package crypto

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
)

// Minimum key sizes per ETSI TS 119 312. Any cert below these is refused
// at sign-start and verify time.
const (
	MinRSABits = 2048
)

// CertPolicyError is the typed error returned by ValidateSignerCert.
// Callers (CLI) switch on Code to map to exit codes / error strings —
// "CERT_WEAK_KEY" / "CERT_CA_LEAF" / etc. Keeping the code textual (not a
// numeric enum) lets the CLI forward it straight into the JSON envelope.
type CertPolicyError struct {
	Code string
	Msg  string
}

func (e *CertPolicyError) Error() string { return e.Code + ": " + e.Msg }

// ValidateSignerCert enforces the signing-profile gates from requirements
// §6.2 (KeyUsage, key size, CA-leaf refusal, digest-agility) before any
// CMS assembly runs. The cert MUST have been freshly parsed — we read
// KeyUsage, BasicConstraints, and PublicKey directly off the struct.
//
// Callers routing through sign-start or sign-local apply this gate on
// entry; verify applies it against the embedded signer cert.
func ValidateSignerCert(cert *x509.Certificate) error {
	if cert == nil {
		return &CertPolicyError{Code: "CERT_NIL", Msg: "nil certificate"}
	}
	if err := checkNotCALeaf(cert); err != nil {
		return err
	}
	if err := checkKeyUsage(cert); err != nil {
		return err
	}
	if err := checkPublicKeyStrength(cert.PublicKey); err != nil {
		return err
	}
	if err := checkSignatureAlgorithm(cert.SignatureAlgorithm); err != nil {
		return err
	}
	return nil
}

func checkNotCALeaf(cert *x509.Certificate) error {
	if cert.IsCA {
		return &CertPolicyError{Code: "CERT_CA_LEAF",
			Msg: "signer certificate has BasicConstraints.CA=true; CA certs cannot sign PAdES content"}
	}
	return nil
}

func checkKeyUsage(cert *x509.Certificate) error {
	// Per RFC 5280 § 4.2.1.3 + ETSI profiles: a qualified signing cert
	// must assert at least one of digitalSignature or nonRepudiation
	// (contentCommitment). A KeyUsage extension absent entirely is still
	// accepted here because some legacy certs omit it; those certs also
	// lack QcCompliance so the qualified-profile gate catches them.
	if cert.KeyUsage == 0 {
		return nil
	}
	const needed = x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment
	if cert.KeyUsage&needed == 0 {
		return &CertPolicyError{Code: "CERT_KEYUSAGE_REJECTED",
			Msg: fmt.Sprintf("KeyUsage=0x%x lacks digitalSignature and contentCommitment", int(cert.KeyUsage))}
	}
	return nil
}

func checkPublicKeyStrength(pub any) error {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		if k.N.BitLen() < MinRSABits {
			return &CertPolicyError{Code: "CERT_WEAK_KEY",
				Msg: fmt.Sprintf("RSA key %d bits below minimum %d", k.N.BitLen(), MinRSABits)}
		}
	case *ecdsa.PublicKey:
		if k.Curve == nil {
			return &CertPolicyError{Code: "CERT_WEAK_KEY", Msg: "ECDSA key missing curve"}
		}
		switch k.Curve {
		case elliptic.P256(), elliptic.P384(), elliptic.P521():
			return nil
		}
		return &CertPolicyError{Code: "CERT_WEAK_KEY",
			Msg: fmt.Sprintf("ECDSA curve %s not accepted (need P-256+)", k.Curve.Params().Name)}
	case ed25519.PublicKey:
		if len(k) != ed25519.PublicKeySize {
			return &CertPolicyError{Code: "CERT_WEAK_KEY",
				Msg: fmt.Sprintf("Ed25519 key length %d", len(k))}
		}
	default:
		return &CertPolicyError{Code: "CERT_UNSUPPORTED_KEY",
			Msg: fmt.Sprintf("unsupported public key type %T", pub)}
	}
	return nil
}

// checkSignatureAlgorithm rejects SHA-1-rooted cert-signing algorithms —
// even when the signer cert itself is RSA-2048+, being signed by a
// SHA-1 issuer makes the chain uncredentiable under eIDAS.
func checkSignatureAlgorithm(alg x509.SignatureAlgorithm) error {
	switch alg {
	case x509.MD2WithRSA, x509.MD5WithRSA, x509.SHA1WithRSA, x509.DSAWithSHA1, x509.ECDSAWithSHA1:
		return &CertPolicyError{Code: "CERT_FORBIDDEN_DIGEST",
			Msg: fmt.Sprintf("cert is signed with %v (SHA-1/MD5-class algorithms forbidden)", alg)}
	}
	return nil
}

