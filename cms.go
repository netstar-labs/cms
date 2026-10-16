// Package cms verifies and produces detached CMS/PKCS#7 SignedData signatures
// (RFC 5652) using only the Go standard library. It is a deliberately small,
// audited subset — detached SignedData over externally supplied content, with
// signed attributes — enough to verify vendor-signed artifacts such as IANA's
// root-anchors.xml/.p7s, signed feeds/RPZ bundles, and data resources, and to
// produce the same for netstar-labs's own signed data.
//
// It does NOT implement encryption, enveloped/authenticated-enveloped data,
// timestamping, or attribute certificates.
package cms

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"slices"
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

	oidRSAEncryption   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidECDSAWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidECDSAWithSHA384 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	oidECDSAWithSHA512 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}
	oidEd25519         = asn1.ObjectIdentifier{1, 3, 101, 112} // RFC 8410; its CMS use is RFC 8419
)

var (
	// ErrNotSignedData is returned for a ContentInfo that is not SignedData.
	ErrNotSignedData = errors.New("cms: not a SignedData content type")
	// ErrNoSigners is returned when SignedData carries no SignerInfo.
	ErrNoSigners = errors.New("cms: no signers")
	// ErrVerify is returned, or wrapped, when the signature parsed, carries signers, and none
	// of them verified: a digest or signature mismatch, an untrusted or expired certificate, a
	// certificate not in the bundle or not allowed to sign, or a SignerInfo this package refuses
	// (no signed attributes, or a malformed, repeated or multi-valued one). The wrapped error says
	// which check failed, and with several signers it is the last signer's.
	//
	// It is NOT returned for input that could not be read as a signature this package accepts: a
	// ContentInfo, SignedData or SignerInfo that does not parse, trailing data, ErrNotSignedData, ErrNoSigners, more than eight SignerInfos, an
	// encapsulated content type other than id-data, a malformed certificate in the (attacker-chosen)
	// bundle, or a nil root pool. Whatever the error, non-nil means the signature is not authentic;
	// use ErrVerify only to tell "verification ran and failed" from "could not read the signature".
	ErrVerify = errors.New("cms: signature verification failed")
)

// Limits on the work one signature can demand. SignerInfos are decoded one at a time, so a
// signature listing thousands is refused without decoding them; each distinct signer certificate
// costs a chain build, which Go bounds per build but not per signature.
const (
	maxSigners    = 8          // SignerInfos in one SignedData
	maxCandidates = 4          // bundle certificates tried for one SignerInfo's identifier
	maxChains     = maxSigners // distinct (certificate, time) chain builds in one call
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

// signedDataShape is signedData with the SignerInfos left encoded, so they can be counted as they
// are decoded.
type signedDataShape struct {
	Version          int
	DigestAlgorithms asn1.RawValue
	EncapContentInfo encapContentInfo
	Certificates     asn1.RawValue `asn1:"optional,tag:0"`
	CRLs             asn1.RawValue `asn1:"optional,tag:1"`
	SignerInfos      asn1.RawValue
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
//
// Verify does not check certificate revocation (Go's x509.VerifyOptions has no
// revocation facility). For a revocation policy, use VerifyWith to control the
// chain build and then check the returned signer certificate against a CRL or
// OCSP responder — see the security notes and example/revoke.
func Verify(content, sig []byte, roots *x509.CertPool, now time.Time) ([]*x509.Certificate, error) {
	return VerifyWith(content, sig, x509.VerifyOptions{Roots: roots, CurrentTime: now})
}

// VerifyWith is Verify with caller-controlled chain verification. The signer
// certificate is validated with opts (Roots, CurrentTime, KeyUsages,
// Intermediates, …); any certificates carried in the SignedData are added as
// intermediates when opts.Intermediates is nil, so leaf→intermediate→root chains
// verify. Revocation remains a caller responsibility on the returned certs.
func VerifyWith(content, sig []byte, opts x509.VerifyOptions) ([]*x509.Certificate, error) {
	return verifyWith(newVerifyState(content), sig, opts, false)
}

// verifyWith is VerifyWith over a caller-supplied state, so tests can observe the work done. With
// asSigned, each signer's chain is checked at its own signed time (VerifyAsSigned).
func verifyWith(st *verifyState, sig []byte, opts x509.VerifyOptions, asSigned bool) ([]*x509.Certificate, error) {
	if opts.Roots == nil {
		// x509 reads a nil Roots as the system trust store; a pool that failed to load must not
		// silently become "trust every public CA".
		return nil, errors.New("cms: no root pool; pass x509.SystemCertPool() to trust the system store")
	}
	sd, err := parseSignedData(sig)
	if err != nil {
		return nil, err
	}
	certs, err := parseCertificates(sd.Certificates.Bytes)
	if err != nil {
		return nil, err
	}

	// Use the bundle's certificates as intermediates unless the caller supplied
	// their own, and default KeyUsages to Any (CMS signer certs rarely carry the
	// ServerAuth EKU that x509 assumes by default).
	if opts.Intermediates == nil && len(certs) > 0 {
		inter := x509.NewCertPool()
		for _, c := range certs {
			inter.AddCert(c)
		}
		opts.Intermediates = inter
	}
	if len(opts.KeyUsages) == 0 {
		opts.KeyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageAny}
	}

	// One verification, however many SignerInfos the (attacker-supplied) signature repeats: the
	// content is hashed once per digest algorithm and each certificate's chain is built once.
	var verified []*x509.Certificate
	var lastErr error = ErrVerify
	for _, si := range sd.SignerInfos {
		cert, err := verifySigner(si, st, certs, opts, asSigned)
		if err != nil {
			lastErr = err
			continue
		}
		// A certificate verified under several SignerInfos is reported once, so a caller counting
		// signers for an M-of-N policy counts certificates, not copies.
		if !slices.ContainsFunc(verified, cert.Equal) {
			verified = append(verified, cert)
		}
	}
	if len(verified) == 0 {
		if lastErr != ErrVerify {
			// Still wrap the cause: callers can match ErrVerify for "not authentic" and read
			// the specific reason (digest mismatch, chain failure, …) from the message.
			lastErr = fmt.Errorf("%w: %w", ErrVerify, lastErr)
		}
		return nil, lastErr
	}
	return verified, nil
}

// SigningTime returns the signed signingTime attribute of sig's first signer, or
// ok=false when the signature carries none. It parses without verifying, so the
// value is trustworthy only once Verify/VerifyWith/VerifyAsSigned has succeeded
// over the same signature and content. It reads with Verify's rules, so it returns
// an error for a signature Verify could not read and for signed attributes Verify
// refuses (contentType or messageDigest missing, an attribute repeated or multi-valued).
func SigningTime(sig []byte) (t time.Time, ok bool, err error) {
	_, si, err := parseFirstSigner(sig)
	if err != nil {
		return time.Time{}, false, err
	}
	if len(si.SignedAttrs.FullBytes) == 0 {
		return time.Time{}, false, nil
	}
	a, err := parseSignedAttrs(si.SignedAttrs)
	if err != nil {
		return time.Time{}, false, err
	}
	return a.signingTime, a.hasSigningTime, nil
}

// VerifyAsSigned verifies sig over content but checks each signer's certificate chain at
// that signer's signed signingTime — or, when it has none, at its certificate's NotBefore —
// instead of the current wall clock. Digest match, chain to roots, and signature checks are
// otherwise identical to Verify.
//
// Use it for write-once resources whose signer certificate may have expired since signing: a
// detached signature over immutable bytes is a timeless fact, so an otherwise-valid resource must
// not become unverifiable merely because a short signing leaf has since expired.
//
// The time is read from each signer's own signed attributes, and only after that signer's
// signature over them has verified, so no other SignerInfo, and nobody without the signer's key,
// can choose it. It is still asserted by the signer, not attested by a time authority: a holder of
// the key, including an expired or compromised one, can sign new content claiming any time inside
// the certificate's validity window, or omit signingTime to anchor at NotBefore. So VerifyAsSigned
// shows that a key valid at the claimed time signed the bytes, not that signing happened then. It
// does NOT check revocation (see VerifyWith); pair it with a revocation or known-good-floor policy
// if a compromised-then-expired leaf is in scope.
func VerifyAsSigned(content, sig []byte, roots *x509.CertPool) ([]*x509.Certificate, error) {
	return verifyWith(newVerifyState(content), sig, x509.VerifyOptions{Roots: roots}, true)
}

// parseSignedData decodes a ContentInfo carrying SignedData with at least one SignerInfo.
// It refuses trailing data, which would let one signature take many encodings, an encapsulated
// content type other than id-data, and more than maxSigners SignerInfos.
func parseSignedData(sig []byte) (signedData, error) {
	var ci contentInfo
	rest, err := asn1.Unmarshal(sig, &ci)
	if err != nil {
		return signedData{}, fmt.Errorf("cms: parse ContentInfo: %w", err)
	}
	if len(rest) > 0 {
		return signedData{}, errors.New("cms: trailing data after ContentInfo")
	}
	if !ci.ContentType.Equal(oidSignedData) {
		return signedData{}, ErrNotSignedData
	}
	var raw signedDataShape
	if rest, err = asn1.Unmarshal(ci.Content.Bytes, &raw); err != nil {
		return signedData{}, fmt.Errorf("cms: parse SignedData: %w", err)
	}
	if len(rest) > 0 {
		return signedData{}, errors.New("cms: trailing data after SignedData")
	}
	if !raw.EncapContentInfo.EContentType.Equal(oidData) {
		return signedData{}, fmt.Errorf("cms: content type %v, only id-data is supported", raw.EncapContentInfo.EContentType)
	}
	if raw.SignerInfos.Class != asn1.ClassUniversal || raw.SignerInfos.Tag != asn1.TagSet || !raw.SignerInfos.IsCompound {
		return signedData{}, errors.New("cms: parse SignedData: signerInfos is not a SET")
	}
	sd := signedData{Version: raw.Version, DigestAlgorithms: raw.DigestAlgorithms,
		EncapContentInfo: raw.EncapContentInfo, Certificates: raw.Certificates, CRLs: raw.CRLs}
	for rest := raw.SignerInfos.Bytes; len(rest) > 0; {
		if len(sd.SignerInfos) == maxSigners {
			return signedData{}, fmt.Errorf("cms: more than %d SignerInfos", maxSigners)
		}
		var si signerInfo
		if rest, err = asn1.Unmarshal(rest, &si); err != nil {
			return signedData{}, fmt.Errorf("cms: parse SignerInfo: %w", err)
		}
		sd.SignerInfos = append(sd.SignerInfos, si)
	}
	if len(sd.SignerInfos) == 0 {
		return signedData{}, ErrNoSigners
	}
	return sd, nil
}

// parseFirstSigner is parseSignedData with its first SignerInfo, for the signingTime helpers.
func parseFirstSigner(sig []byte) (signedData, signerInfo, error) {
	sd, err := parseSignedData(sig)
	if err != nil {
		return signedData{}, signerInfo{}, err
	}
	return sd, sd.SignerInfos[0], nil
}

// verifyState memoizes the two expensive, signer-independent steps of one Verify call. The chain
// cache is keyed by certificate pointer and verification time: findCerts hands back the same
// pointer for SignerInfos that name the same certificate, two distinct certificates never share a
// pointer, and the options other than the time are fixed for the call, so a hit can only be the
// identical certificate verified under the identical options.
type verifyState struct {
	content []byte
	digests map[crypto.Hash][]byte
	chains  map[chainKey]error

	// hashed and chained count the computations actually performed, as opposed to answered from
	// the caches; the tests assert them, which is how the memoisation is pinned without timing.
	hashed, chained int
}

func newVerifyState(content []byte) *verifyState {
	return &verifyState{content: content, digests: map[crypto.Hash][]byte{}, chains: map[chainKey]error{}}
}

type chainKey struct {
	cert *x509.Certificate
	at   time.Time
}

func (st *verifyState) digest(h crypto.Hash) []byte {
	d, ok := st.digests[h]
	if !ok {
		d = digest(h, st.content)
		st.digests[h] = d
		st.hashed++
	}
	return d
}

func (st *verifyState) chain(cert *x509.Certificate, opts x509.VerifyOptions) error {
	k := chainKey{cert, opts.CurrentTime}
	err, ok := st.chains[k]
	if !ok {
		if st.chained == maxChains {
			return fmt.Errorf("cms: more than %d certificate chains to build", maxChains)
		}
		_, err = cert.Verify(opts)
		st.chains[k] = err
		st.chained++
	}
	return err
}

func verifySigner(si signerInfo, st *verifyState, certs []*x509.Certificate, opts x509.VerifyOptions, asSigned bool) (*x509.Certificate, error) {
	h, ok := hashForOID(si.DigestAlgorithm.Algorithm)
	if !ok {
		return nil, fmt.Errorf("cms: unsupported digest algorithm %v", si.DigestAlgorithm.Algorithm)
	}

	// The signature must cover signed attributes that bind the content's digest and type (RFC 5652
	// §5.4). RFC 5652 lets id-data omit them, but then a signature made over attributes verifies as
	// a signature over the attribute bytes themselves, and Ed25519 verifies over the whole content
	// once per SignerInfo.
	if len(si.SignedAttrs.FullBytes) == 0 {
		return nil, errors.New("cms: SignerInfo has no signed attributes")
	}
	attrs, err := parseSignedAttrs(si.SignedAttrs)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(attrs.messageDigest, st.digest(h)) {
		return nil, errors.New("cms: messageDigest attribute mismatch")
	}
	if !attrs.contentType.Equal(oidData) { // parseSignedData admits only id-data
		return nil, errors.New("cms: contentType attribute mismatch")
	}
	signed := reencodeAsSet(si.SignedAttrs.FullBytes)

	candidates := findCerts(certs, si.SID)
	if len(candidates) == 0 {
		return nil, errors.New("cms: signer certificate not found")
	}
	for _, cert := range candidates[:min(len(candidates), maxCandidates)] {
		if err = verifyAs(cert, h, signed, si.Signature, attrs, st, opts, asSigned); err == nil {
			return cert, nil
		}
	}
	return nil, err
}

// verifyAs checks one candidate signer certificate: that it may sign, the signature under its key,
// and its chain, at opts.CurrentTime or, when asSigned, at the signer's own signed time.
func verifyAs(cert *x509.Certificate, h crypto.Hash, signed, sig []byte, attrs signedAttrs, st *verifyState, opts x509.VerifyOptions, asSigned bool) error {
	// RFC 5280 §4.2.1.3: a certificate that lists key usages must list one for signing.
	if cert.KeyUsage != 0 && cert.KeyUsage&(x509.KeyUsageDigitalSignature|x509.KeyUsageContentCommitment) == 0 {
		return errors.New("cms: signer certificate's key usage does not allow signatures")
	}
	if err := verifySignature(cert, h, signed, sig); err != nil {
		return err
	}
	if asSigned {
		// Read only now that this signer's signature over its attributes has verified.
		opts.CurrentTime = cert.NotBefore
		if attrs.hasSigningTime {
			opts.CurrentTime = attrs.signingTime
		}
		if opts.CurrentTime.IsZero() { // x509 would read the zero time as now
			return errors.New("cms: signing time is the zero time")
		}
	}
	if err := st.chain(cert, opts); err != nil {
		return fmt.Errorf("cms: chain: %w", err)
	}
	return nil
}

// verifySignature checks sig over the signed bytes. RSA and ECDSA sign a digest of them; Ed25519
// signs the bytes themselves (PureEdDSA), and RFC 8419 §3.1 requires its digest algorithm to be
// SHA-512.
func verifySignature(cert *x509.Certificate, h crypto.Hash, signed, sig []byte) error {
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return rsa.VerifyPKCS1v15(pub, h, digest(h, signed), sig)
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(pub, digest(h, signed), sig) {
			return ErrVerify
		}
		return nil
	case ed25519.PublicKey:
		if h != crypto.SHA512 {
			return fmt.Errorf("cms: Ed25519 signer with digest algorithm %v, RFC 8419 requires SHA-512", h)
		}
		if !ed25519.Verify(pub, signed, sig) {
			return ErrVerify
		}
		return nil
	default:
		return fmt.Errorf("cms: unsupported public key %T", pub)
	}
}

// signedAttrs are the signed attributes Verify reads.
type signedAttrs struct {
	messageDigest  []byte
	contentType    asn1.ObjectIdentifier
	signingTime    time.Time
	hasSigningTime bool
}

// parseSignedAttrs reads contentType and messageDigest, which are mandatory, and signingTime
// (RFC 5652 §5.3). RFC 5652 §11 allows each of the three once, with exactly one value.
func parseSignedAttrs(raw asn1.RawValue) (signedAttrs, error) {
	var out signedAttrs
	var seen [3]bool // messageDigest, contentType, signingTime
	for rest := raw.Bytes; len(rest) > 0; {
		var a attribute
		var err error
		if rest, err = asn1.Unmarshal(rest, &a); err != nil {
			return signedAttrs{}, fmt.Errorf("cms: parse signed attribute: %w", err)
		}
		var v any
		var i int
		switch {
		case a.Type.Equal(oidMessageDigest):
			v, i = &out.messageDigest, 0
		case a.Type.Equal(oidContentType):
			v, i = &out.contentType, 1
		case a.Type.Equal(oidSigningTime):
			v, i, out.hasSigningTime = &out.signingTime, 2, true
		default:
			continue
		}
		if seen[i] {
			return signedAttrs{}, fmt.Errorf("cms: signed attribute %v appears twice", a.Type)
		}
		seen[i] = true
		extra, err := asn1.Unmarshal(a.Values.Bytes, v)
		if err != nil {
			return signedAttrs{}, fmt.Errorf("cms: signed attribute %v value: %w", a.Type, err)
		}
		if len(extra) > 0 {
			return signedAttrs{}, fmt.Errorf("cms: signed attribute %v has more than one value", a.Type)
		}
	}
	if out.messageDigest == nil {
		return signedAttrs{}, errors.New("cms: messageDigest attribute absent")
	}
	if out.contentType == nil {
		return signedAttrs{}, errors.New("cms: contentType attribute absent")
	}
	out.signingTime = out.signingTime.UTC()
	return out, nil
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
		// The other CertificateChoices (RFC 5652 §10.2.2: attribute and "other" certificates) are
		// context-tagged; skip them rather than refuse a bundle that carries one.
		if raw.Class == asn1.ClassContextSpecific {
			der = rest
			continue
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

// findCerts returns the bundle certificates sid names. There can be several, such as a renewed
// certificate for the same key and SubjectKeyIdentifier, so the caller tries each.
func findCerts(certs []*x509.Certificate, sid asn1.RawValue) []*x509.Certificate {
	var match func(*x509.Certificate) bool
	if sid.Class == asn1.ClassContextSpecific && sid.Tag == 0 { // [0] SubjectKeyIdentifier
		if len(sid.Bytes) == 0 {
			return nil // would match every certificate that has no SubjectKeyIdentifier
		}
		match = func(c *x509.Certificate) bool { return bytes.Equal(c.SubjectKeyId, sid.Bytes) }
	} else {
		var is issuerAndSerial
		if _, err := asn1.Unmarshal(sid.FullBytes, &is); err != nil {
			return nil
		}
		match = func(c *x509.Certificate) bool {
			return c.SerialNumber.Cmp(is.SerialNumber) == 0 && bytes.Equal(c.RawIssuer, is.Issuer.FullBytes)
		}
	}
	var out []*x509.Certificate
	for _, c := range certs {
		if match(c) {
			out = append(out, c)
		}
	}
	return out
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

// ---- signing --------------------------------------------------------------

// SignOptions configures Sign.
type SignOptions struct {
	Hash        crypto.Hash // default SHA-256; SHA-512 for an Ed25519 key, which accepts no other (RFC 8419)
	SigningTime time.Time   // default: omitted
}

// Sign produces a detached CMS SignedData over content, signed by cert/key with
// signed attributes (contentType=id-data, messageDigest, optional signingTime).
// The signer certificate is embedded so Verify can build the chain. An Ed25519
// key signs by RFC 8419: SHA-512 for the messageDigest, PureEdDSA over the
// signed attributes.
//
// Sign returns an error, and does not panic, for a nil or unparsed certificate, a nil key, a
// certificate whose public key is not the key's, or a SigningTime outside years 0 to 9999. "Is
// the key's" means cert.PublicKey.Equal(key.Public()): the standard library's keys qualify, but a
// hand-built Certificate with no PublicKey, or a Signer whose Public returns an RSA or ECDSA key
// by value rather than by pointer, is refused. A typed-nil key still panics.
func Sign(content []byte, cert *x509.Certificate, key crypto.Signer, opts SignOptions) ([]byte, error) {
	if cert == nil || len(cert.Raw) == 0 || cert.SerialNumber == nil {
		return nil, errors.New("cms: Sign needs a parsed certificate")
	}
	if key == nil {
		return nil, errors.New("cms: Sign needs a signing key")
	}
	// A certificate that is not the key's would produce a signature that can never verify, and
	// nothing at signing time would say so.
	if pub, ok := cert.PublicKey.(interface{ Equal(crypto.PublicKey) bool }); !ok || !pub.Equal(key.Public()) {
		return nil, errors.New("cms: the certificate's public key is not the signing key's")
	}
	_, isEd25519 := key.Public().(ed25519.PublicKey)
	h := opts.Hash
	switch {
	case isEd25519 && h != 0 && h != crypto.SHA512:
		return nil, fmt.Errorf("cms: Ed25519 signs with SHA-512 only (RFC 8419), not %v", h)
	case isEd25519:
		h = crypto.SHA512
	case h == 0:
		h = crypto.SHA256
	}
	digOID, ok := oidForHash(h)
	if !ok {
		return nil, fmt.Errorf("cms: unsupported hash %v", h)
	}

	attrs := []attribute{
		{Type: oidContentType, Values: setOf(mustMarshal(oidData))},
		{Type: oidMessageDigest, Values: setOf(mustMarshal(digest(h, content)))},
	}
	if !opts.SigningTime.IsZero() {
		// Not mustMarshal: the time is the caller's, and years outside 0..9999 cannot be encoded.
		st, err := asn1.Marshal(opts.SigningTime.UTC())
		if err != nil {
			return nil, fmt.Errorf("cms: signingTime: %w", err)
		}
		attrs = append(attrs, attribute{Type: oidSigningTime, Values: setOf(st)})
	}

	signedAttrsDER, err := marshalAttributeSet(attrs)
	if err != nil {
		return nil, err
	}
	var sig []byte
	if isEd25519 {
		sig, err = key.Sign(rand.Reader, signedAttrsDER, crypto.Hash(0)) // PureEdDSA: the message, not a digest
	} else {
		sig, err = key.Sign(rand.Reader, digest(h, signedAttrsDER), h)
	}
	if err != nil {
		return nil, fmt.Errorf("cms: sign: %w", err)
	}

	si := signerInfo{
		Version:            1,
		SID:                sidFromCert(cert),
		DigestAlgorithm:    pkix.AlgorithmIdentifier{Algorithm: digOID},
		SignedAttrs:        asn1.RawValue{FullBytes: implicitTag(signedAttrsDER)},
		SignatureAlgorithm: sigAlgFor(key, h),
		Signature:          sig,
	}

	sd := signedData{
		Version:          1,
		DigestAlgorithms: asn1.RawValue{FullBytes: digestAlgSet(digOID)},
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
	slices.SortFunc(encoded, bytes.Compare)
	return asn1.Marshal(setOf(bytes.Join(encoded, nil)))
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
	return mustMarshal(setOf(mustMarshal(pkix.AlgorithmIdentifier{Algorithm: oid})))
}

func sidFromCert(cert *x509.Certificate) asn1.RawValue {
	b := mustMarshal(issuerAndSerial{
		Issuer:       asn1.RawValue{FullBytes: cert.RawIssuer},
		SerialNumber: cert.SerialNumber,
	})
	return asn1.RawValue{FullBytes: b}
}

// sigAlgFor is the signatureAlgorithm for key signing with h: rsaEncryption with NULL parameters
// (RFC 3370 §3.2), ecdsa-with-SHA* without parameters (RFC 5753 §2.1.1), id-Ed25519 without
// parameters (RFC 8419 §3.1). These are what OpenSSL writes.
func sigAlgFor(key crypto.Signer, h crypto.Hash) pkix.AlgorithmIdentifier {
	switch key.Public().(type) {
	case *ecdsa.PublicKey:
		oid := oidECDSAWithSHA256 // Sign has already refused hashes other than SHA-256/384/512
		switch h {
		case crypto.SHA384:
			oid = oidECDSAWithSHA384
		case crypto.SHA512:
			oid = oidECDSAWithSHA512
		}
		return pkix.AlgorithmIdentifier{Algorithm: oid}
	case ed25519.PublicKey:
		return pkix.AlgorithmIdentifier{Algorithm: oidEd25519}
	default:
		return pkix.AlgorithmIdentifier{Algorithm: oidRSAEncryption, Parameters: asn1.NullRawValue}
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

// setOf is a SET whose contents are the already-encoded, already-ordered elements in body.
// encoding/asn1 writes the header, so the value cannot be wrapped twice by accident.
func setOf(body []byte) asn1.RawValue {
	return asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true, Bytes: body}
}
