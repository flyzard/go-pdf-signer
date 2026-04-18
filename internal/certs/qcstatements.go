package certs

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
)

// QCStatements extension OID (RFC 3739 §3.2.6).
var oidQCStatements = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 3}

// ETSI qcStatements identifiers per ETSI EN 319 412-5.
var (
	oidQcCompliance = asn1.ObjectIdentifier{0, 4, 0, 1862, 1, 1}     // QcCompliance — qualified
	oidQcSSCD       = asn1.ObjectIdentifier{0, 4, 0, 1862, 1, 4}     // QcSSCD — key on qualified device
	oidQcType       = asn1.ObjectIdentifier{0, 4, 0, 1862, 1, 6}     // QcType — signature/seal/ssl role
	oidQcTypeESign  = asn1.ObjectIdentifier{0, 4, 0, 1862, 1, 6, 1}  // esign — natural-person signature
	oidQcTypeESeal  = asn1.ObjectIdentifier{0, 4, 0, 1862, 1, 6, 2}  // eseal — legal-person seal
	oidQcTypeEWeb   = asn1.ObjectIdentifier{0, 4, 0, 1862, 1, 6, 3}  // eweb — TLS/web identity
)

// QCProfile summarises the ETSI qualified-signature indicators carried in
// a cert's qcStatements extension. Absence of the extension means a
// non-qualified cert; downstream code distinguishes via the Qualified bit.
type QCProfile struct {
	// Qualified is true when QcCompliance is asserted (i.e. the cert is
	// issued under a qualified certificate profile).
	Qualified bool
	// QSCD is true when QcSSCD is asserted — the key is held on a qualified
	// signature creation device.
	QSCD bool
	// Type is the QcType role when present. Empty string when QcType is
	// absent; most qualified signer certs issued before ~2018 omit it.
	Type string // "esign" | "eseal" | "eweb" | ""
}

// QCType role constants used as string-typed values on QCProfile.Type.
const (
	QCTypeESign = "esign"
	QCTypeESeal = "eseal"
	QCTypeEWeb  = "eweb"
)

// ParseQCProfile extracts the ETSI QC indicators from cert. Returns an
// empty QCProfile (no error) when the qcStatements extension is absent —
// non-qualified certs are a legitimate input for some callers (e.g.
// CA/browser CC certs used in test environments).
func ParseQCProfile(cert *x509.Certificate) (QCProfile, error) {
	var prof QCProfile
	if cert == nil {
		return prof, fmt.Errorf("qc: nil cert")
	}
	ext, ok := findExtension(cert, oidQCStatements)
	if !ok {
		return prof, nil
	}

	// QCStatements ::= SEQUENCE OF QCStatement. Unmarshal into a sequence
	// of RawValue so each entry can be parsed individually — entry shape
	// depends on the statement OID.
	var stmts []asn1.RawValue
	if _, err := asn1.Unmarshal(ext.Value, &stmts); err != nil {
		return prof, fmt.Errorf("qc: decode qcStatements: %w", err)
	}
	for _, stmtRaw := range stmts {
		oid, info, err := splitQCStatement(stmtRaw)
		if err != nil {
			return prof, fmt.Errorf("qc: split statement: %w", err)
		}
		switch {
		case oid.Equal(oidQcCompliance):
			prof.Qualified = true
		case oid.Equal(oidQcSSCD):
			prof.QSCD = true
		case oid.Equal(oidQcType):
			if t, err := parseQcType(info); err == nil {
				prof.Type = t
			}
		}
	}
	return prof, nil
}

// splitQCStatement decodes one QCStatement ::= SEQUENCE { OID, ANY? }.
// Returns (oid, raw statementInfo bytes) — info may be empty when the
// statement carries only the identifier.
func splitQCStatement(raw asn1.RawValue) (asn1.ObjectIdentifier, []byte, error) {
	if raw.Class != asn1.ClassUniversal || raw.Tag != asn1.TagSequence {
		return nil, nil, fmt.Errorf("QCStatement must be a SEQUENCE (class=%d tag=%d)", raw.Class, raw.Tag)
	}
	body := raw.Bytes
	var oid asn1.ObjectIdentifier
	rest, err := asn1.Unmarshal(body, &oid)
	if err != nil {
		return nil, nil, err
	}
	return oid, rest, nil
}

// parseQcType pulls the first qcType OID out of its statementInfo (which is
// SEQUENCE OF OBJECT IDENTIFIER) and maps it to a role string. Ignores any
// further entries — a cert declaring multiple roles is unusual; the first
// entry in the sequence is authoritative in ETSI EN 319 412-5.
func parseQcType(info []byte) (string, error) {
	var oids []asn1.ObjectIdentifier
	if _, err := asn1.Unmarshal(info, &oids); err != nil {
		return "", err
	}
	if len(oids) == 0 {
		return "", fmt.Errorf("QcType: empty OID set")
	}
	switch {
	case oids[0].Equal(oidQcTypeESign):
		return QCTypeESign, nil
	case oids[0].Equal(oidQcTypeESeal):
		return QCTypeESeal, nil
	case oids[0].Equal(oidQcTypeEWeb):
		return QCTypeEWeb, nil
	}
	return "", fmt.Errorf("unknown QcType OID %v", oids[0])
}

// findExtension is a small helper avoiding a linear-search rewrite at
// every call site. cert.Extensions is small (rarely > 20 entries) so the
// scan is fine.
func findExtension(cert *x509.Certificate, oid asn1.ObjectIdentifier) (pkix.Extension, bool) {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oid) {
			return ext, true
		}
	}
	return pkix.Extension{}, false
}
