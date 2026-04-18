package certs

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"
)

func mustMakeCert(t *testing.T, subj pkix.Name, extraExts []pkix.Extension) *x509.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("key gen: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:    big.NewInt(1),
		Subject:         subj,
		Issuer:          pkix.Name{CommonName: "Test Issuer"},
		NotBefore:       time.Now().Add(-time.Hour),
		NotAfter:        time.Now().Add(24 * time.Hour),
		KeyUsage:        x509.KeyUsageDigitalSignature,
		ExtraExtensions: extraExts,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return cert
}

func TestExtractIdentityStripsAMASuffix(t *testing.T) {
	cert := mustMakeCert(t, pkix.Name{
		CommonName:   "João Silva (Assinatura Qualificada)",
		SerialNumber: "BI123456789",
	}, nil)
	id, err := ExtractIdentity(cert)
	if err != nil {
		t.Fatalf("ExtractIdentity: %v", err)
	}
	if id.CN != "João Silva" {
		t.Errorf("CN = %q, want stripped %q", id.CN, "João Silva")
	}
	if id.NIC != "BI123456789" {
		t.Errorf("NIC = %q, want from Subject.serialNumber", id.NIC)
	}
}

func TestParseQCProfileDetectsQualifiedEsign(t *testing.T) {
	// Build qcStatements: SEQUENCE OF QCStatement.
	qcCompliance, _ := asn1.Marshal([]asn1.ObjectIdentifier{oidQcCompliance})
	qcSSCD, _ := asn1.Marshal([]asn1.ObjectIdentifier{oidQcSSCD})
	// QcType statement: QCStatement { OID QcType, SEQUENCE OF OID { esign } }
	esignOID, _ := asn1.Marshal([]asn1.ObjectIdentifier{oidQcTypeESign})
	qcTypeStmt, _ := asn1.Marshal(struct {
		ID   asn1.ObjectIdentifier
		Info asn1.RawValue
	}{oidQcType, asn1.RawValue{FullBytes: esignOID}})

	// QcCompliance + QcSSCD statements are identifier-only.
	complianceStmt, _ := asn1.Marshal(struct {
		ID asn1.ObjectIdentifier
	}{oidQcCompliance})
	sscdStmt, _ := asn1.Marshal(struct {
		ID asn1.ObjectIdentifier
	}{oidQcSSCD})
	_ = qcCompliance
	_ = qcSSCD

	statements := append(complianceStmt, sscdStmt...)
	statements = append(statements, qcTypeStmt...)
	qcSeq, _ := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: statements,
	})

	cert := mustMakeCert(t, pkix.Name{CommonName: "Qualified Signer"}, []pkix.Extension{
		{Id: oidQCStatements, Value: qcSeq},
	})
	prof, err := ParseQCProfile(cert)
	if err != nil {
		t.Fatalf("ParseQCProfile: %v", err)
	}
	if !prof.Qualified {
		t.Error("Qualified must be true for QcCompliance")
	}
	if !prof.QSCD {
		t.Error("QSCD must be true for QcSSCD")
	}
	if prof.Type != QCTypeESign {
		t.Errorf("Type = %q, want esign", prof.Type)
	}
}

func TestParseQCProfileAbsentExtension(t *testing.T) {
	cert := mustMakeCert(t, pkix.Name{CommonName: "Plain Signer"}, nil)
	prof, err := ParseQCProfile(cert)
	if err != nil {
		t.Fatalf("ParseQCProfile: %v", err)
	}
	if prof.Qualified || prof.QSCD || prof.Type != "" {
		t.Errorf("empty extension should yield zero profile, got %+v", prof)
	}
}
