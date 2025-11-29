#!/usr/bin/env python3
"""
pdf-ecdsa-signer - PDF Digital Signing Tool

Signs PDF documents using ECDSA P-256 with PKCS#12 credentials.
Supports PAdES and CMS signature formats with optional RFC 3161 timestamping.
"""

import argparse
import glob
import json
import os
import shutil
import sys
import tempfile
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from getpass import getpass
from typing import Any, Dict, List, Optional, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign import fields, signers, timestamps
from pyhanko.sign.fields import SigSeedSubFilter
from pyhanko.sign.validation import validate_pdf_signature
from pyhanko_certvalidator import ValidationContext

# Constants
MIN_PASSPHRASE_LENGTH: int = 8
DEFAULT_CONFIG_FILE: str = "signer_config.json"
DEFAULT_PKCS12_FILE: str = "signer.p12"


@dataclass
class SigningResult:
    """Result of a signing operation."""

    input_file: str
    output_file: str
    success: bool
    message: str


@dataclass
class VerificationResult:
    """Result of a verification operation."""

    file: str
    success: bool
    message: str


class ConfigNotFoundError(Exception):
    """Raised when configuration file is not found."""

    pass


class PassphraseError(Exception):
    """Raised when passphrase validation fails."""

    pass


class SigningError(Exception):
    """Raised when PDF signing fails."""

    pass


class VerificationError(Exception):
    """Raised when PDF verification fails."""

    pass


def get_passphrase(
    prompt: str = "Enter passphrase: ", confirm: bool = False, allow_empty: bool = False
) -> str:
    """
    Securely get passphrase from user.

    Args:
        prompt: Prompt message to display
        confirm: Whether to require confirmation
        allow_empty: Whether to allow empty passphrase (for loading existing files)

    Returns:
        The entered passphrase

    Raises:
        PassphraseError: If passphrase is invalid or confirmation fails
    """
    try:
        passphrase: str = getpass(prompt)
    except (EOFError, KeyboardInterrupt):
        raise PassphraseError("Passphrase entry cancelled")

    if not allow_empty:
        if len(passphrase) < MIN_PASSPHRASE_LENGTH:
            raise PassphraseError(f"Passphrase must be at least {MIN_PASSPHRASE_LENGTH} characters")

    if confirm:
        try:
            confirmation: str = getpass("Confirm passphrase: ")
        except (EOFError, KeyboardInterrupt):
            raise PassphraseError("Passphrase confirmation cancelled")

        if passphrase != confirmation:
            raise PassphraseError("Passphrases do not match")

    return passphrase


def load_config(config_file: str) -> Dict[str, Any]:
    """
    Load configuration from JSON file.

    Args:
        config_file: Path to configuration file

    Returns:
        Configuration dictionary

    Raises:
        ConfigNotFoundError: If config file does not exist
        json.JSONDecodeError: If config file is malformed
        PermissionError: If config file cannot be read
    """
    if not os.path.exists(config_file):
        raise ConfigNotFoundError(
            f"Configuration file not found: {config_file}\n"
            f"Please create a configuration file from the template."
        )

    print(f"Loading configuration from {config_file}")
    with open(config_file, "r", encoding="utf-8") as f:
        config: Dict[str, Any] = json.load(f)

    # Validate required sections
    required_sections: List[str] = ["certificate", "signature", "timestamp", "files"]
    missing: List[str] = [s for s in required_sections if s not in config]
    if missing:
        raise ConfigNotFoundError(
            f"Configuration file is missing required sections: {', '.join(missing)}"
        )

    return config


def generate_pkcs12(config: Dict[str, Any]) -> bool:
    """
    Generate ECDSA P-256 key pair and certificate, save as PKCS#12.

    Args:
        config: Configuration dictionary

    Returns:
        True if generation succeeded, False otherwise
    """
    pkcs12_file: str = config["files"]["pkcs12"]

    if os.path.exists(pkcs12_file):
        print(f"PKCS#12 file already exists: {pkcs12_file}")
        print("Delete it first if you want to regenerate.")
        return False

    print("Generating new ECDSA P-256 key pair and self-signed certificate...")

    # Get passphrase with confirmation
    try:
        passphrase: str = get_passphrase(
            f"Enter passphrase for PKCS#12 (min {MIN_PASSPHRASE_LENGTH} chars): ",
            confirm=True,
            allow_empty=False,
        )
    except PassphraseError as e:
        print(f"Error: {e}")
        return False

    # Generate ECDSA P-256 key
    private_key: ec.EllipticCurvePrivateKey = ec.generate_private_key(ec.SECP256R1())
    public_key: ec.EllipticCurvePublicKey = private_key.public_key()

    cert_config: Dict[str, Any] = config["certificate"]
    subject: x509.Name = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, cert_config["country"]),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, cert_config["state"]),
            x509.NameAttribute(NameOID.LOCALITY_NAME, cert_config["locality"]),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, cert_config["organization"]),
            x509.NameAttribute(NameOID.COMMON_NAME, cert_config["common_name"]),
        ]
    )
    issuer: x509.Name = subject

    validity_days: int = cert_config.get("validity_days", 3650)
    now: datetime = datetime.now(timezone.utc)

    # Build X.509v3 certificate
    cert: x509.Certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=validity_days))
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=True,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage(
                [
                    ExtendedKeyUsageOID.EMAIL_PROTECTION,
                    ExtendedKeyUsageOID.CODE_SIGNING,
                ]
            ),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
        .sign(private_key, hashes.SHA256())
    )

    # Serialize to PKCS#12 format
    encryption: serialization.KeySerializationEncryption = serialization.BestAvailableEncryption(
        passphrase.encode()
    )
    p12_data: bytes = pkcs12.serialize_key_and_certificates(
        name=cert_config["common_name"].encode(),
        key=private_key,
        cert=cert,
        cas=None,
        encryption_algorithm=encryption,
    )

    with open(pkcs12_file, "wb") as f:
        f.write(p12_data)

    print(f"\nPKCS#12 file saved to {pkcs12_file}")
    print(f"Certificate details:")
    print(f"  Format: PKCS#12 (RFC 7292)")
    print(f"  Algorithm: ECDSA P-256 (secp256r1) with SHA-256")
    print(f"  Common Name: {cert_config['common_name']}")
    print(f"  Valid for: {validity_days} days")
    return True


def load_signer(pkcs12_file: str, passphrase: str) -> signers.SimpleSigner:
    """
    Load signer from PKCS#12 file.

    Args:
        pkcs12_file: Path to PKCS#12 file
        passphrase: Passphrase for the file

    Returns:
        SimpleSigner instance

    Raises:
        FileNotFoundError: If PKCS#12 file doesn't exist
        ValueError: If passphrase is incorrect or file is corrupted
    """
    if not os.path.exists(pkcs12_file):
        raise FileNotFoundError(f"PKCS#12 file not found: {pkcs12_file}")

    passphrase_bytes: Optional[bytes] = passphrase.encode() if passphrase else None
    return signers.SimpleSigner.load_pkcs12(pfx_file=pkcs12_file, passphrase=passphrase_bytes)


def create_timestamper(config: Dict[str, Any]) -> Optional[timestamps.HTTPTimeStamper]:
    """
    Create timestamper if enabled in config.

    Args:
        config: Configuration dictionary

    Returns:
        HTTPTimeStamper instance or None if disabled
    """
    ts_config: Dict[str, Any] = config.get("timestamp", {})
    if not ts_config.get("enabled", False):
        return None

    tsa_url: str = ts_config.get("tsa_url", "http://timestamp.digicert.com")
    return timestamps.HTTPTimeStamper(tsa_url)


def sign_single_pdf(
    input_pdf: str,
    output_pdf: str,
    config: Dict[str, Any],
    signer: signers.SimpleSigner,
    timestamper: Optional[timestamps.HTTPTimeStamper],
) -> SigningResult:
    """
    Sign a single PDF file with atomic write.

    Args:
        input_pdf: Path to input PDF
        output_pdf: Path to output PDF
        config: Configuration dictionary
        signer: SimpleSigner instance
        timestamper: Optional timestamper

    Returns:
        SigningResult with operation details
    """
    if not os.path.exists(input_pdf):
        return SigningResult(input_pdf, output_pdf, False, "Input file not found")

    sig_config: Dict[str, Any] = config.get("signature", {})
    subfilter_choice: str = sig_config.get("subfilter", "pkcs7").lower()

    if subfilter_choice == "pades":
        subfilter: SigSeedSubFilter = SigSeedSubFilter.PADES
        format_name: str = "PAdES"
    else:
        subfilter = SigSeedSubFilter.ADOBE_PKCS7_DETACHED
        format_name = "CMS"

    # Use temporary file for atomic write
    output_dir: str = os.path.dirname(output_pdf) or "."
    temp_fd: Optional[int]
    temp_path: Optional[str]
    temp_fd, temp_path = tempfile.mkstemp(suffix=".pdf", dir=output_dir)

    try:
        with open(input_pdf, "rb") as inf:
            w: IncrementalPdfFileWriter = IncrementalPdfFileWriter(inf)

            sig_field_name: str = f"Signature_{uuid.uuid4().hex[:8]}"
            fields.append_signature_field(
                w, sig_field_spec=fields.SigFieldSpec(sig_field_name, box=(0, 0, 0, 0))
            )

            meta: signers.PdfSignatureMetadata = signers.PdfSignatureMetadata(
                field_name=sig_field_name,
                location=sig_config.get("location", "Python Script"),
                reason=sig_config.get("reason", "Document Authentication"),
                name=config["certificate"]["common_name"],
                md_algorithm="sha256",
                subfilter=subfilter,
            )

            with os.fdopen(temp_fd, "wb") as outf:
                temp_fd = None  # Prevent double-close
                signers.sign_pdf(w, meta, signer=signer, output=outf, timestamper=timestamper)

        # Atomic move to final destination
        shutil.move(temp_path, output_pdf)
        temp_path = None

        ts_info: str = " with timestamp" if timestamper else ""
        return SigningResult(input_pdf, output_pdf, True, f"Signed ({format_name}{ts_info})")

    except IOError as e:
        return SigningResult(input_pdf, output_pdf, False, f"I/O error: {e}")
    except ValueError as e:
        return SigningResult(input_pdf, output_pdf, False, f"Invalid PDF: {e}")
    finally:
        # Clean up temp file on failure
        if temp_fd is not None:
            os.close(temp_fd)
        if temp_path is not None and os.path.exists(temp_path):
            os.unlink(temp_path)


def sign_pdfs(
    input_patterns: List[str], output_dir: Optional[str], config: Dict[str, Any]
) -> List[SigningResult]:
    """
    Sign multiple PDF files matching the given patterns.

    Args:
        input_patterns: List of file paths or glob patterns
        output_dir: Optional output directory (None = same as input)
        config: Configuration dictionary

    Returns:
        List of SigningResult for each file
    """
    pkcs12_file: str = config["files"]["pkcs12"]

    # Expand glob patterns and collect unique files
    input_files: List[str] = []
    for pattern in input_patterns:
        matches: List[str] = glob.glob(pattern)
        if not matches:
            # Treat as literal path if no glob matches
            input_files.append(pattern)
        else:
            input_files.extend(matches)

    # Remove duplicates while preserving order
    input_files = list(dict.fromkeys(input_files))

    if not input_files:
        print("No input files specified")
        return []

    # Filter to PDF files only
    pdf_files: List[str] = [f for f in input_files if f.lower().endswith(".pdf")]
    if len(pdf_files) < len(input_files):
        skipped: int = len(input_files) - len(pdf_files)
        print(f"Skipping {skipped} non-PDF file(s)")

    if not pdf_files:
        print("No PDF files to sign")
        return []

    print(f"Found {len(pdf_files)} PDF file(s) to sign")

    # Get passphrase once for all files
    try:
        passphrase: str = get_passphrase("Enter PKCS#12 passphrase: ", allow_empty=True)
    except PassphraseError as e:
        print(f"Error: {e}")
        return [SigningResult(f, "", False, "Passphrase error") for f in pdf_files]

    # Load signer
    try:
        signer: signers.SimpleSigner = load_signer(pkcs12_file, passphrase)
    except FileNotFoundError as e:
        print(f"Error: {e}")
        print("Run --generate-keys first.")
        return [SigningResult(f, "", False, "No PKCS#12 file") for f in pdf_files]
    except ValueError as e:
        print(f"Error: Failed to load PKCS#12 - {e}")
        return [SigningResult(f, "", False, "Invalid PKCS#12") for f in pdf_files]

    # Create timestamper if enabled
    timestamper: Optional[timestamps.HTTPTimeStamper] = create_timestamper(config)
    if timestamper:
        print(f"Timestamping enabled: {config['timestamp']['tsa_url']}")

    # Process files
    results: List[SigningResult] = []
    for i, input_pdf in enumerate(pdf_files, 1):
        # Generate output path
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
            base_name: str = os.path.basename(input_pdf)
            name: str
            ext: str
            name, ext = os.path.splitext(base_name)
            output_pdf: str = os.path.join(output_dir, f"{name}_signed{ext}")
        else:
            base: str
            base, ext = os.path.splitext(input_pdf)
            output_pdf = f"{base}_signed{ext}"

        print(f"[{i}/{len(pdf_files)}] Signing {input_pdf}...", end=" ")
        result: SigningResult = sign_single_pdf(input_pdf, output_pdf, config, signer, timestamper)
        results.append(result)

        if result.success:
            print(f"{result.message}")
        else:
            print(f"{result.message}")

    return results


def verify_single_pdf(pdf_file: str) -> VerificationResult:
    """
    Verify signatures on a single PDF file.

    Args:
        pdf_file: Path to PDF file

    Returns:
        VerificationResult with operation details
    """
    if not os.path.exists(pdf_file):
        return VerificationResult(pdf_file, False, "File not found")

    try:
        with open(pdf_file, "rb") as f:
            reader: PdfFileReader = PdfFileReader(f)
            sigs: List[Any] = list(reader.embedded_signatures)

            if not sigs:
                return VerificationResult(pdf_file, False, "No signatures found")

            all_valid: bool = True
            details: List[str] = []

            for i, sig in enumerate(sigs, 1):
                sig_info: str = f"Signature {i} ({sig.field_name})"

                # Get signer info
                cert: Optional[Any] = sig.signer_cert
                if cert:
                    sig_info += f" by {cert.subject.human_friendly}"

                # Validate with self-signed cert as trust root
                try:
                    vc: ValidationContext = ValidationContext(
                        allow_fetching=False, trust_roots=[cert] if cert else []
                    )
                    status: Any = validate_pdf_signature(sig, vc)

                    if status.intact and status.valid:
                        details.append(f"{sig_info}: Valid")
                    else:
                        details.append(f"{sig_info}: INVALID")
                        all_valid = False

                except Exception as e:
                    details.append(f"{sig_info}: Error - {e}")
                    all_valid = False

            message: str = "; ".join(details)
            return VerificationResult(pdf_file, all_valid, message)

    except Exception as e:
        return VerificationResult(pdf_file, False, f"Error reading PDF: {e}")


def verify_pdfs(input_patterns: List[str]) -> List[VerificationResult]:
    """
    Verify signatures on multiple PDF files matching the given patterns.

    Args:
        input_patterns: List of file paths or glob patterns

    Returns:
        List of VerificationResult for each file
    """
    # Expand glob patterns and collect unique files
    input_files: List[str] = []
    for pattern in input_patterns:
        matches: List[str] = glob.glob(pattern)
        if not matches:
            # Treat as literal path if no glob matches
            input_files.append(pattern)
        else:
            input_files.extend(matches)

    # Remove duplicates while preserving order
    input_files = list(dict.fromkeys(input_files))

    if not input_files:
        print("No input files specified")
        return []

    # Filter to PDF files only
    pdf_files: List[str] = [f for f in input_files if f.lower().endswith(".pdf")]
    if len(pdf_files) < len(input_files):
        skipped: int = len(input_files) - len(pdf_files)
        print(f"Skipping {skipped} non-PDF file(s)")

    if not pdf_files:
        print("No PDF files to verify")
        return []

    print(f"Found {len(pdf_files)} PDF file(s) to verify")

    # Process files
    results: List[VerificationResult] = []
    for i, pdf_file in enumerate(pdf_files, 1):
        print(f"[{i}/{len(pdf_files)}] Verifying {pdf_file}...", end=" ")
        result: VerificationResult = verify_single_pdf(pdf_file)
        results.append(result)

        if result.success:
            print(f"OK - {result.message}")
        else:
            print(f"FAILED - {result.message}")

    return results


def print_signing_summary(results: List[SigningResult]) -> None:
    """Print summary of batch signing results."""
    if not results:
        return

    success_count: int = sum(1 for r in results if r.success)
    fail_count: int = len(results) - success_count

    print(f"\n{'=' * 60}")
    print(f"Signing Summary: {success_count} succeeded, {fail_count} failed")

    if fail_count > 0:
        print("\nFailed files:")
        for r in results:
            if not r.success:
                print(f"  {r.input_file}: {r.message}")


def print_verification_summary(results: List[VerificationResult]) -> None:
    """Print summary of batch verification results."""
    if not results:
        return

    success_count: int = sum(1 for r in results if r.success)
    fail_count: int = len(results) - success_count

    print(f"\n{'=' * 60}")
    print(f"Verification Summary: {success_count} valid, {fail_count} failed")

    if fail_count > 0:
        print("\nFailed files:")
        for r in results:
            if not r.success:
                print(f"  {r.file}: {r.message}")


def main() -> None:
    parser: argparse.ArgumentParser = argparse.ArgumentParser(
        prog="pdf-ecdsa-signer",
        description="PDF Digital Signing Tool - ECDSA P-256 with PKCS#12",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --generate-keys
  %(prog)s -i document.pdf
  %(prog)s -i "*.pdf"
  %(prog)s -i doc1.pdf doc2.pdf -o signed_docs/
  %(prog)s --verify signed_document.pdf
  %(prog)s --verify "./signed_documents/*.pdf"
        """,
    )
    parser.add_argument(
        "-i",
        "--input",
        nargs="+",
        metavar="FILE",
        help="Input PDF file(s) or glob pattern(s) to sign",
    )
    parser.add_argument(
        "-o",
        "--output",
        metavar="DIR",
        help="Output directory for signed PDFs (default: same as input)",
    )
    parser.add_argument(
        "-c",
        "--config",
        default=DEFAULT_CONFIG_FILE,
        help=f"Configuration file (default: {DEFAULT_CONFIG_FILE})",
    )
    parser.add_argument(
        "--generate-keys", action="store_true", help="Generate new PKCS#12 credential file"
    )
    parser.add_argument(
        "--verify",
        nargs="+",
        metavar="FILE",
        help="Verify signature on PDF file(s) or glob pattern(s)",
    )

    args: argparse.Namespace = parser.parse_args()

    print("=" * 60)
    print("pdf-ecdsa-signer - ECDSA P-256 / PKCS#12 / CMS")
    print("=" * 60)

    try:
        config: Dict[str, Any] = load_config(args.config)
    except ConfigNotFoundError as e:
        print(f"Error: {e}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid config file - {e}")
        sys.exit(1)
    except PermissionError as e:
        print(f"Error: Cannot access config file - {e}")
        sys.exit(1)

    if args.generate_keys:
        success: bool = generate_pkcs12(config)
        sys.exit(0 if success else 1)

    elif args.verify:
        results: List[VerificationResult] = verify_pdfs(args.verify)
        print_verification_summary(results)
        success = all(r.success for r in results)
        sys.exit(0 if success else 1)

    elif args.input:
        # Check if PKCS#12 exists
        if not os.path.exists(config["files"]["pkcs12"]):
            print(f"Error: PKCS#12 file not found: {config['files']['pkcs12']}")
            print("Run --generate-keys first.")
            sys.exit(1)

        results_sign: List[SigningResult] = sign_pdfs(args.input, args.output, config)
        print_signing_summary(results_sign)

        # Exit with error if any failed
        success = all(r.success for r in results_sign)
        sys.exit(0 if success else 1)

    else:
        parser.print_help()
        sys.exit(0)


if __name__ == "__main__":
    main()
