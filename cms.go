// Package cms verifies and produces detached CMS/PKCS#7 SignedData signatures
// (RFC 5652) using only the Go standard library. It is a deliberately small,
// audited subset — detached SignedData over externally supplied content, with
// signed attributes — enough to verify vendor-signed artifacts such as IANA's
// root-anchors.xml/.p7s, signed feeds/RPZ bundles, and refs resources, and to
// produce the same for netstar-labs's own signed data.
//
// It does NOT implement encryption, enveloped/authenticated-enveloped data,
// timestamping, or attribute certificates.
package cms

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"time"
)

// Object identifiers (RFC 5652 §11, RFC 5758, NIST).
var (
	oidSignedData    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidData          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidContentType   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidMessageDigest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	oidSigningTime   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}

	oidSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSHA384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidSHA512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}

	oidRSAEncryption = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidECPublicKey   = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
)

var (
	// ErrNotSignedData is returned for a ContentInfo that is not SignedData.
	ErrNotSignedData = errors.New("cms: not a SignedData content type")
	// ErrNoSigners is returned when SignedData carries no SignerInfo.
	ErrNoSigners = errors.New("cms: no signers")
	// ErrVerify is returned when no signer verifies against the content+roots.
	ErrVerify = errors.New("cms: signature verification failed")
)

// ---- ASN.1 shapes (RFC 5652) ---------------------------------------------

type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"optional,tag:0"` // [0] EXPLICIT; inner is .Bytes
}

type signedData struct {
	Version          int
	DigestAlgorithms asn1.RawValue
	EncapContentInfo encapContentInfo
	Certificates     asn1.RawValue `asn1:"optional,tag:0"`
	CRLs             asn1.RawValue `asn1:"optional,tag:1"`
	SignerInfos      []signerInfo  `asn1:"set"`
}

type encapContentInfo struct {
	EContentType asn1.ObjectIdentifier
	EContent     asn1.RawValue `asn1:"explicit,optional,tag:0"`
}

type signerInfo struct {
	Version            int
	SID                asn1.RawValue
	DigestAlgorithm    pkix.AlgorithmIdentifier
	SignedAttrs        asn1.RawValue `asn1:"optional,tag:0"`
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          []byte
	UnsignedAttrs      asn1.RawValue `asn1:"optional,tag:1"`
}

type issuerAndSerial struct {
	Issuer       asn1.RawValue
	SerialNumber *big.Int
}

type attribute struct {
	Type   asn1.ObjectIdentifier
	Values asn1.RawValue `asn1:"set"`
}

// ---- verification ---------------------------------------------------------

// Verify checks that sig (DER-encoded, detached CMS SignedData) authenticates
// content: at least one signer must have a valid signature over the content, a
// certificate chaining to roots, and validity at now. It returns the verified
// signer certificates.
func Verify(content, sig []byte, roots *x509.CertPool, now time.Time) ([]*x509.Certificate, error) {
	var ci contentInfo
	if _, err := asn1.Unmarshal(sig, &ci); err != nil {
		return nil, fmt.Errorf("cms: parse ContentInfo: %w", err)
	}
	if !ci.ContentType.Equal(oidSignedData) {
		return nil, ErrNotSignedData
	}
	var sd signedData
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		return nil, fmt.Errorf("cms: parse SignedData: %w", err)
	}
	if len(sd.SignerInfos) == 0 {
		return nil, ErrNoSigners
	}
	certs, err := parseCertificates(sd.Certificates.Bytes)
	if err != nil {
		return nil, err
	}

	var verified []*x509.Certificate
	var lastErr error = ErrVerify
	for _, si := range sd.SignerInfos {
		cert, err := verifySigner(si, content, certs, roots, now)
		if err != nil {
			lastErr = err
			continue
		}
		verified = append(verified, cert)
	}
	if len(verified) == 0 {
		return nil, lastErr
	}
	return verified, nil
}

func verifySigner(si signerInfo, content []byte, certs []*x509.Certificate, roots *x509.CertPool, now time.Time) (*x509.Certificate, error) {
	cert := findCert(certs, si.SID)
	if cert == nil {
		return nil, errors.New("cms: signer certificate not found")
	}
	h, ok := hashForOID(si.DigestAlgorithm.Algorithm)
	if !ok {
		return nil, fmt.Errorf("cms: unsupported digest algorithm %v", si.DigestAlgorithm.Algorithm)
	}

	// Determine the bytes actually signed. With signed attributes present (the
	// normal case, and what IANA uses), the signature is over the DER of the
	// SET OF attributes, and the messageDigest attribute must equal the digest
	// of the external content.
	var signed []byte
	if len(si.SignedAttrs.FullBytes) > 0 {
		md, err := signedAttrMessageDigest(si.SignedAttrs)
		if err != nil {
			return nil, err
		}
		if !bytesEqual(md, digest(h, content)) {
			return nil, errors.New("cms: messageDigest attribute mismatch")
		}
		signed = reencodeAsSet(si.SignedAttrs.FullBytes)
	} else {
		signed = content
	}

	if err := verifySignature(cert, h, digest(h, signed), si.Signature); err != nil {
		return nil, err
	}
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:       roots,
		CurrentTime: now,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return nil, fmt.Errorf("cms: chain: %w", err)
	}
	return cert, nil
}

func verifySignature(cert *x509.Certificate, h crypto.Hash, dgst, sig []byte) error {
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return rsa.VerifyPKCS1v15(pub, h, dgst, sig)
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(pub, dgst, sig) {
			return ErrVerify
		}
		return nil
	default:
		return fmt.Errorf("cms: unsupported public key %T", pub)
	}
}

func signedAttrMessageDigest(attrs asn1.RawValue) ([]byte, error) {
	rest := attrs.Bytes
	var found []byte
	var haveContentType bool
	for len(rest) > 0 {
		var a attribute
		var err error
		rest, err = asn1.Unmarshal(rest, &a)
		if err != nil {
			return nil, fmt.Errorf("cms: parse signed attribute: %w", err)
		}
		switch {
		case a.Type.Equal(oidMessageDigest):
			var octets []byte
			if _, err := asn1.Unmarshal(a.Values.Bytes, &octets); err != nil {
				return nil, fmt.Errorf("cms: messageDigest value: %w", err)
			}
			found = octets
		case a.Type.Equal(oidContentType):
			haveContentType = true
		}
	}
	if found == nil {
		return nil, errors.New("cms: messageDigest attribute absent")
	}
	if !haveContentType {
		return nil, errors.New("cms: contentType attribute absent")
	}
	return found, nil
}

// reencodeAsSet returns the DER of a SET OF from an implicit [0] tagged value by
// swapping the leading context tag (0xA0) for the universal SET tag (0x31); the
// length octets are unchanged (IMPLICIT tagging only replaces the tag).
func reencodeAsSet(implicit []byte) []byte {
	out := make([]byte, len(implicit))
	copy(out, implicit)
	if len(out) > 0 {
		out[0] = 0x31
	}
	return out
}

func parseCertificates(der []byte) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	for len(der) > 0 {
		var raw asn1.RawValue
		rest, err := asn1.Unmarshal(der, &raw)
		if err != nil {
			return nil, fmt.Errorf("cms: parse certificate: %w", err)
		}
		c, err := x509.ParseCertificate(raw.FullBytes)
		if err != nil {
			return nil, fmt.Errorf("cms: certificate: %w", err)
		}
		out = append(out, c)
		der = rest
	}
	return out, nil
}

func findCert(certs []*x509.Certificate, sid asn1.RawValue) *x509.Certificate {
	// SubjectKeyIdentifier form is [0] IMPLICIT OCTET STRING.
	if sid.Class == asn1.ClassContextSpecific && sid.Tag == 0 {
		for _, c := range certs {
			if bytesEqual(c.SubjectKeyId, sid.Bytes) {
				return c
			}
		}
		return nil
	}
	// IssuerAndSerialNumber form.
	var is issuerAndSerial
	if _, err := asn1.Unmarshal(sid.FullBytes, &is); err != nil {
		return nil
	}
	for _, c := range certs {
		if c.SerialNumber.Cmp(is.SerialNumber) == 0 && bytesEqual(c.RawIssuer, is.Issuer.FullBytes) {
			return c
		}
	}
	return nil
}

func hashForOID(oid asn1.ObjectIdentifier) (crypto.Hash, bool) {
	switch {
	case oid.Equal(oidSHA256):
		return crypto.SHA256, true
	case oid.Equal(oidSHA384):
		return crypto.SHA384, true
	case oid.Equal(oidSHA512):
		return crypto.SHA512, true
	}
	return 0, false
}

func digest(h crypto.Hash, b []byte) []byte {
	hh := h.New()
	hh.Write(b)
	return hh.Sum(nil)
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// ---- signing --------------------------------------------------------------

// SignOptions configures Sign.
type SignOptions struct {
	Hash        crypto.Hash // default SHA-256
	SigningTime time.Time   // default: omitted
}

// Sign produces a detached CMS SignedData over content, signed by cert/key with
// signed attributes (contentType=id-data, messageDigest, optional signingTime).
// The signer certificate is embedded so Verify can build the chain.
func Sign(content []byte, cert *x509.Certificate, key crypto.Signer, opts SignOptions) ([]byte, error) {
	h := opts.Hash
	if h == 0 {
		h = crypto.SHA256
	}
	digOID, ok := oidForHash(h)
	if !ok {
		return nil, fmt.Errorf("cms: unsupported hash %v", h)
	}

	attrs := []attribute{
		{Type: oidContentType, Values: mustSetOf(mustMarshal(oidData))},
		{Type: oidMessageDigest, Values: mustSetOf(mustMarshal(digest(h, content)))},
	}
	if !opts.SigningTime.IsZero() {
		attrs = append(attrs, attribute{Type: oidSigningTime, Values: mustSetOf(mustMarshal(opts.SigningTime.UTC()))})
	}

	signedAttrsDER, err := marshalAttributeSet(attrs)
	if err != nil {
		return nil, err
	}
	sig, err := key.Sign(rand.Reader, digest(h, signedAttrsDER), h)
	if err != nil {
		return nil, fmt.Errorf("cms: sign: %w", err)
	}

	si := signerInfo{
		Version:            1,
		SID:                sidFromCert(cert),
		DigestAlgorithm:    pkix.AlgorithmIdentifier{Algorithm: digOID},
		SignedAttrs:        asn1.RawValue{FullBytes: implicitTag(signedAttrsDER)},
		SignatureAlgorithm: pkix.AlgorithmIdentifier{Algorithm: sigOIDForKey(key)},
		Signature:          sig,
	}

	sd := signedData{
		Version:          1,
		DigestAlgorithms: asn1.RawValue{FullBytes: mustMarshal(digestAlgSet(digOID))},
		EncapContentInfo: encapContentInfo{EContentType: oidData}, // detached: no EContent
		Certificates:     asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: cert.Raw},
		SignerInfos:      []signerInfo{si},
	}
	sdDER, err := asn1.Marshal(sd)
	if err != nil {
		return nil, fmt.Errorf("cms: marshal SignedData: %w", err)
	}
	ci := contentInfo{
		ContentType: oidSignedData,
		Content:     asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: sdDER},
	}
	return asn1.Marshal(ci)
}

func marshalAttributeSet(attrs []attribute) ([]byte, error) {
	// SET OF DER requires elements sorted by their encoding.
	var encoded [][]byte
	for _, a := range attrs {
		b, err := asn1.Marshal(a)
		if err != nil {
			return nil, err
		}
		encoded = append(encoded, b)
	}
	sortByteSlices(encoded)
	var body []byte
	for _, e := range encoded {
		body = append(body, e...)
	}
	return append(tlvHeader(0x31, len(body)), body...), nil
}

// implicitTag rewrites a universal SET (0x31…) as an implicit [0] (0xA0…).
func implicitTag(setDER []byte) []byte {
	out := make([]byte, len(setDER))
	copy(out, setDER)
	if len(out) > 0 {
		out[0] = 0xA0
	}
	return out
}

func digestAlgSet(oid asn1.ObjectIdentifier) []byte {
	alg := mustMarshal(pkix.AlgorithmIdentifier{Algorithm: oid})
	return append(tlvHeader(0x31, len(alg)), alg...)
}

func sidFromCert(cert *x509.Certificate) asn1.RawValue {
	b := mustMarshal(issuerAndSerial{
		Issuer:       asn1.RawValue{FullBytes: cert.RawIssuer},
		SerialNumber: cert.SerialNumber,
	})
	return asn1.RawValue{FullBytes: b}
}

func sigOIDForKey(key crypto.Signer) asn1.ObjectIdentifier {
	switch key.Public().(type) {
	case *ecdsa.PublicKey:
		return oidECPublicKey
	default:
		return oidRSAEncryption
	}
}

func oidForHash(h crypto.Hash) (asn1.ObjectIdentifier, bool) {
	switch h {
	case crypto.SHA256:
		return oidSHA256, true
	case crypto.SHA384:
		return oidSHA384, true
	case crypto.SHA512:
		return oidSHA512, true
	}
	return nil, false
}

// ---- small DER helpers ----------------------------------------------------

func mustMarshal(v any) []byte {
	b, err := asn1.Marshal(v)
	if err != nil {
		panic("cms: marshal: " + err.Error())
	}
	return b
}

// mustSetOf wraps one already-encoded value in a SET (for an Attribute's values).
func mustSetOf(elem []byte) asn1.RawValue {
	return asn1.RawValue{FullBytes: append(tlvHeader(0x31, len(elem)), elem...)}
}

func tlvHeader(tag byte, length int) []byte {
	if length < 0x80 {
		return []byte{tag, byte(length)}
	}
	var lb []byte
	for length > 0 {
		lb = append([]byte{byte(length & 0xff)}, lb...)
		length >>= 8
	}
	return append([]byte{tag, byte(0x80 | len(lb))}, lb...)
}

func sortByteSlices(s [][]byte) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && less(s[j], s[j-1]); j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

func less(a, b []byte) bool {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return len(a) < len(b)
}
