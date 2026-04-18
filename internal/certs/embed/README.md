# Portuguese state root CAs

Drop PEM files (`*.pem`) for the Portuguese state CA roots in this directory:

- `ECRaizEstado.pem` — top-level Portuguese state root
- `Multicert.pem` — commercial cross-issuer

`PortugueseRoots()` walks this directory at startup and seeds an `x509.CertPool`
with every PEM block it finds. If no PEMs are vendored, it falls back to the
host system pool with a warning (see `roots.go`).
