# TSA trust anchors (RFC 3161)

Vendored PEMs here seed `certs.TSARoots()` — the pool used to validate the
issuer chain of RFC 3161 timestamp tokens (signature timestamps per PAdES
B-T and DocTimeStamps per PAdES B-LTA).

The default AMA TSA is `http://ts.cartaodecidadao.pt/tsa/v2`. Its issuer
chain must be rooted here. Cross-check against the Portuguese TSL's
`TSPServiceInformation` entries with serviceTypeIdentifier
`http://uri.etsi.org/TrstSvc/Svctype/TSA/QTST`.

Keeping this pool separate from `signer/` is mandated by R-3.1.5 — a TSA
root must never validate a signer cert and vice-versa.
