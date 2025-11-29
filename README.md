# pdf-ecdsa-signer

A command-line tool for digitally signing PDF documents using ECDSA P-256 with PKCS#12 credentials. Supports PAdES and CMS signature formats with optional RFC 3161 timestamping.

## Features

- ECDSA P-256 (secp256r1) signatures with SHA-256
- Self-signed X.509 certificates stored in PKCS#12 format
- PAdES and CMS (adbe.pkcs7.detached) signature formats
- RFC 3161 timestamp support
- Batch signing with glob patterns
- Signature verification

## Quick Start

```bash
# Install dependencies
uv sync

# Copy the template config file
cp signer_config.json.template signer_config.json

# Generate signing credentials (you'll be prompted for a passphrase)
uv run pdf-ecdsa-signer.py --generate-keys

# Sign a PDF
uv run pdf-ecdsa-signer.py -i document.pdf

# Verify a signed PDF
uv run pdf-ecdsa-signer.py --verify document_signed.pdf
```

## Usage

```
uv run pdf-ecdsa-signer.py [OPTIONS]

Options:
  -i, --input FILE [FILE ...]   Input PDF file(s) or glob pattern(s)
  -o, --output DIR              Output directory for signed PDFs
  -c, --config FILE             Config file (default: signer_config.json)
  --generate-keys               Generate new PKCS#12 credentials
  --verify PDF_FILE             Verify signature on a PDF
  -h, --help                    Show help message
```

### Examples

```bash
# Sign a single file
uv run pdf-ecdsa-signer.py -i report.pdf

# Sign multiple files
uv run pdf-ecdsa-signer.py -i doc1.pdf doc2.pdf doc3.pdf

# Sign all PDFs in current directory
uv run pdf-ecdsa-signer.py -i "*.pdf"

# Sign and save to a specific directory
uv run pdf-ecdsa-signer.py -i "*.pdf" -o ./signed_documents/

# Verify all PDF files in a specific directory
uv run pdf-ecdsa-signer.py --verify "./signed_documents/*.pdf"
```

## Configuration

On first run, a `signer_config.json` file is created with default settings:

```json
{
    "certificate": {
        "country": "US",
        "state": "California",
        "locality": "San Francisco",
        "organization": "My Company",
        "common_name": "Kaiser Zheng",
        "validity_days": 3650
    },
    "signature": {
        "location": "Python Script",
        "reason": "Document Authentication",
        "subfilter": "PAdES"
    },
    "timestamp": {
        "enabled": false,
        "tsa_url": "http://timestamp.digicert.com"
    },
    "files": {
        "pkcs12": "signer.p12"
    }
}
```

### Signature Formats

Set `signature.subfilter` to:
- `pades` — PAdES format (ETSI standard)
- `pkcs7` — CMS format (better Adobe Reader compatibility)

### Timestamping

To enable RFC 3161 timestamps, set `timestamp.enabled` to `true`. The default TSA is DigiCert, but you can use any compliant timestamp authority.

## Output

Signed files are saved with a `_signed` suffix by default:
- `document.pdf` → `document_signed.pdf`

Use `-o` to specify an output directory instead.
