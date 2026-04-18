# pdf-signer

A CLI tool for creating **PAdES-LT** (PDF Advanced Electronic Signatures — Long Term) digital signatures on PDF documents.

It implements a 4-step signing workflow designed for external signing services (e.g., smart cards, HSMs, remote signing APIs): prepare a signature placeholder, embed an externally-produced CMS signature, finalize with long-term validation data, and verify.

## Requirements

- Go 1.23+

## Build

```bash
make build          # builds bin/pdf-signer for the current platform
make build-linux    # cross-compile for linux/amd64
make build-darwin   # cross-compile for darwin/arm64
make clean          # remove build artifacts
```

## Usage

```
pdf-signer <command> [options]
```

### Commands

#### `prepare` — Add a signature placeholder

Parses the input PDF, adds a signature field with a visual stamp and a CMS placeholder, computes the hash over the byte ranges that will be signed, and writes the prepared PDF.

```bash
pdf-signer prepare \
  --input=document.pdf \
  --output=prepared.pdf \
  --signer-name="John Doe" \
  --signer-nic="12345678"  \
  --signing-method=cmd \
  --signature-position="1,100,100,200,50"
```

| Flag | Required | Description |
|------|----------|-------------|
| `--input` | yes | Path to the input PDF file |
| `--output` | yes | Path for the prepared output PDF |
| `--signer-name` | yes | Name of the signer (shown in the visual stamp) |
| `--signer-nic` | no | Signer NIC identifier |
| `--signing-method` | no | Signing method: `cmd` or `cc` (default: `cmd`) |
| `--signature-position` | no | Position as `page,x,y,width,height` (default: auto) |

Outputs JSON with the hash to be signed externally:

```json
{
  "hash": "base64-encoded-sha256-hash",
  "field_name": "Signature1"
}
```

#### `embed` — Embed an external CMS signature

Takes the prepared PDF and a DER-encoded CMS signature blob produced by your external signing service, and embeds the signature into the placeholder.

```bash
pdf-signer embed \
  --input=prepared.pdf \
  --output=signed.pdf \
  --cms=signature.der
```

| Flag | Required | Description |
|------|----------|-------------|
| `--input` | yes | Path to the prepared PDF |
| `--output` | yes | Path for the signed output PDF |
| `--cms` | yes | Path to the DER-encoded CMS signature file |
| `--field-name` | no | Signature field name (for compatibility) |

#### `finalize` — Add long-term validation (LTV) data

Fetches OCSP responses and CRLs for the signer's certificate chain, builds a Document Security Store (DSS), and optionally adds an RFC 3161 document-level timestamp.

```bash
pdf-signer finalize \
  --input=signed.pdf \
  --output=final.pdf \
  --tsa-url=http://timestamp.example.com
```

| Flag | Required | Description |
|------|----------|-------------|
| `--input` | yes | Path to the signed PDF |
| `--output` | yes | Path for the finalized output PDF |
| `--tsa-url` | no | RFC 3161 Time Stamping Authority URL |

#### `verify` — Verify PDF signatures

Parses the PDF, extracts all signature fields, validates each CMS signature against the signed byte ranges, and reports the results.

```bash
pdf-signer verify --input=final.pdf
```

| Flag | Required | Description |
|------|----------|-------------|
| `--input` | yes | Path to the PDF file to verify |

#### `version`

Prints the tool version.

```bash
pdf-signer version
```

## Signing Workflow

The typical end-to-end workflow looks like this:

```
                 +-----------+
                 |  Original |
                 |    PDF    |
                 +-----+-----+
                       |
                 1. prepare
                       |
                 +-----v-----+
                 |  Prepared  |----> hash (JSON stdout)
                 |    PDF     |
                 +-----+-----+
                       |           +------------------+
                       |           | External Signing |
                       |           |  Service / HSM   |
                       |           +--------+---------+
                       |                    |
                       |              CMS signature
                       |                    |
                 2. embed <-----------------+
                       |
                 +-----v-----+
                 |   Signed   |
                 |    PDF     |
                 +-----+-----+
                       |
                 3. finalize (OCSP + CRL + optional TSA)
                       |
                 +-----v-----+
                 |   Final    |
                 |  PAdES-LT  |
                 +-----+-----+
                       |
                 4. verify
                       |
                    Result JSON
```

1. **Prepare**: Add a signature placeholder and get the hash to sign.
2. **Sign externally**: Send the hash to your signing service (smart card, HSM, remote API) and get back a CMS (PKCS#7) signature.
3. **Embed**: Inject the CMS signature into the prepared PDF.
4. **Finalize**: Fetch revocation data (OCSP/CRL) and optionally timestamp the document for PAdES-LT compliance.
5. **Verify**: Validate all signatures in the final PDF.

## Output Format

All commands produce JSON output on stdout. Errors are written to stderr as JSON:

```json
{
  "error": "ERROR_CODE",
  "message": "Human-readable description"
}
```

## Testing

```bash
make test
```

## Project Structure

```
cmd/pdf-signer/        CLI entry point
internal/
  cli/                 Command handlers and JSON output
  pades/               PAdES signing workflow (prepare, embed, finalize, verify)
  pdf/                 Low-level PDF parsing and incremental-update writing
  crypto/              Certificate chain building, OCSP, and CRL fetching
  appearance/          Visual signature stamp generation
  certs/               Root certificate store
```

## Dependencies

| Module | Purpose |
|--------|---------|
| `golang.org/x/crypto` | Cryptographic primitives (OCSP) |

All builds use `CGO_ENABLED=0` for fully static, portable binaries.

## License

See [LICENSE](LICENSE) for details.
