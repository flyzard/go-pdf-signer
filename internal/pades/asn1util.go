package pades

import "encoding/asn1"

// derSEQ wraps body as the contents of a DER universal SEQUENCE.
func derSEQ(body []byte) ([]byte, error) {
	return asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      body,
	})
}

// derSET wraps body as the contents of a DER universal SET.
func derSET(body []byte) ([]byte, error) {
	return asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSet,
		IsCompound: true,
		Bytes:      body,
	})
}

// derContextTag wraps body under a context-specific [tag] IMPLICIT/EXPLICIT
// constructed element. Both shapes are encoded identically at the byte
// level once the caller has produced body; the IMPLICIT/EXPLICIT label
// lives in the type definition, not the wire encoding.
func derContextTag(tag int, body []byte) ([]byte, error) {
	return asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        tag,
		IsCompound: true,
		Bytes:      body,
	})
}
