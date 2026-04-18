# Signer trust anchors (Portuguese state)

Vendored PEMs here seed `certs.SignerRoots()` — the pool used to validate
signer (and chain) certificates in CMS signatures.

Contents must be sourced from the **Portuguese Trusted List** (ETSI TS 119 612)
as published via the EU LOTL (`https://ec.europa.eu/tools/lotl/eu-lotl.xml`).
See `cmd/refresh-tsl/` for the automated fetch path.

Do not hand-copy PEMs from ad-hoc sources — the expiry guard will still pass
but the pool will drift from the authoritative TSL.

Suggested filename convention: `<CN-of-root>.pem`, one cert per file.
