package certs

import (
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"math/big"
	"strings"
)

// Identity is the cert-derived data the stamp + CMS builder consume. A
// single source-of-truth struct stops the caller from having to juggle
// Subject.* fields across multiple files — every code path that asks
// "what's the signer's name?" should route through here.
type Identity struct {
	// CN is the signer/legal-entity common name, stripped of AMA suffixes
	// like " (Assinatura Qualificada)" that bloat the visible stamp.
	CN string
	// NIC is the Portuguese civil identifier taken from Subject.serialNumber.
	// For legal-entity (seal) certs it is the NIPC/NIF.
	NIC string
	// IssuerCN is the DN Common Name of the immediate issuer — surfaced on
	// the stamp per R-5.2.6 and in verify output.
	IssuerCN string
	// Serial is cert.SerialNumber; kept raw so callers decide how to render
	// (full vs last-16-hex per R-5.2.7).
	Serial *big.Int
	// OrganisationName / OrganisationIdentifier populate the appearance
	// seal branch (R-5.1.3). Empty for natural-person certs.
	OrganisationName       string
	OrganisationIdentifier string
	// QCProfile carries the ETSI qualification indicators (Qualified /
	// QSCD / Type). Empty / zero values mean the cert does not assert any
	// ETSI QC profile — still legal for test deployments but rendered
	// without the "Assinatura Qualificada" heading.
	QCProfile QCProfile
}

// amaCNSuffixes strips known adornments AMA and other Portuguese issuers
// append to the CommonName. Removing them keeps the visible stamp from
// showing a redundant qualifier — the "Assinatura Qualificada" heading
// conveys the same information once, not twice.
var amaCNSuffixes = []string{
	" (Assinatura Qualificada)",
	" (Autenticacao)",
	" (Autenticação)",
}

// oidOrganizationIdentifier is the X.520 organizationIdentifier attribute
// used by QSealC certs per eIDAS Art. 35+. Go's x509 does not surface it
// via pkix.Name struct fields; we walk Subject.Names directly.
var oidOrganizationIdentifier = asn1.ObjectIdentifier{2, 5, 4, 97}

// ExtractIdentity parses the fields needed by the appearance layer and the
// verify output from cert. QCProfile parsing is best-effort — a parse
// error demotes QCProfile to empty rather than failing the whole identity
// extraction, so that a cert with a malformed qcStatements extension
// still produces a usable stamp.
func ExtractIdentity(cert *x509.Certificate) (Identity, error) {
	if cert == nil {
		return Identity{}, fmt.Errorf("identity: cert is nil")
	}
	id := Identity{
		CN:       normaliseCN(cert.Subject.CommonName),
		NIC:      cert.Subject.SerialNumber,
		IssuerCN: cert.Issuer.CommonName,
		Serial:   cert.SerialNumber,
	}
	if len(cert.Subject.Organization) > 0 {
		id.OrganisationName = cert.Subject.Organization[0]
	}
	id.OrganisationIdentifier = extractOrganisationIdentifier(cert)

	if prof, err := ParseQCProfile(cert); err == nil {
		id.QCProfile = prof
	}
	return id, nil
}

// normaliseCN strips AMA adornments and collapses surrounding whitespace so
// the stamp renders cleanly.
func normaliseCN(cn string) string {
	if cn == "" {
		return ""
	}
	for _, suffix := range amaCNSuffixes {
		if strings.HasSuffix(cn, suffix) {
			cn = strings.TrimSuffix(cn, suffix)
			break
		}
	}
	return strings.TrimSpace(cn)
}

// extractOrganisationIdentifier walks Subject.Names for the X.520
// organizationIdentifier attribute (OID 2.5.4.97) and returns its string
// value. Returns empty when absent — the CN/NIC path is used for natural-
// person signatures; this branch feeds the QSealC seal stamp.
func extractOrganisationIdentifier(cert *x509.Certificate) string {
	for _, atv := range cert.Subject.Names {
		if atv.Type.Equal(oidOrganizationIdentifier) {
			if s, ok := atv.Value.(string); ok {
				return s
			}
		}
	}
	return ""
}
