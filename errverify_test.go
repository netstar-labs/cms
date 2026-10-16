package cms

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"testing"
	"time"
)

// TestErrVerifyContract: errors.Is(err, ErrVerify) means "the signature parsed, had signers, and
// verification ran and failed". It must hold for every such failure whatever the signer's key type
// or the reason, and must NOT hold for input that could not be read as a signature. It used to be
// true only for an ECDSA or Ed25519 signature mismatch. (Non-nil of either kind means not authentic.)
func TestErrVerifyContract(t *testing.T) {
	now := time.Now()
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	for _, k := range []struct {
		name string
		key  crypto.Signer
	}{{"rsa", mustRSA(t)}, {"ecdsa", ec}, {"ed25519", mustEd25519(t)}} {
		cert, roots := selfSigned(t, k.key)
		content := []byte("content")
		sig, err := Sign(content, cert, k.key, SignOptions{})
		if err != nil {
			t.Fatal(err)
		}
		flipped := append([]byte(nil), sig...)
		flipped[len(flipped)-1] ^= 1 // inside the signature value
		otherCert, _ := selfSigned(t, mustRSA(t))
		untrusting := x509.NewCertPool()
		untrusting.AddCert(otherCert)

		for name, run := range map[string]func() error{
			"tampered content":  func() error { _, err := Verify([]byte("other"), sig, roots, now); return err },
			"flipped signature": func() error { _, err := Verify(content, flipped, roots, now); return err },
			"untrusted root":    func() error { _, err := Verify(content, sig, untrusting, now); return err },
			"expired":           func() error { _, err := Verify(content, sig, roots, now.Add(72*time.Hour)); return err },
		} {
			if err := run(); !errors.Is(err, ErrVerify) {
				t.Errorf("%s / %s: errors.Is(err, ErrVerify) = false for %v", k.name, name, err)
			}
		}
	}

	// Not a signature at all: a parse error, not an authenticity failure.
	_, err := Verify([]byte("x"), []byte("not DER"), x509.NewCertPool(), now)
	if err == nil || errors.Is(err, ErrVerify) {
		t.Errorf("garbage input: err = %v, want a parse error that is not ErrVerify", err)
	}

	// Readable up to the verification step but not past it: a junk element in the (attacker-chosen)
	// certificate bundle fails to parse before any signer is checked, so it is not ErrVerify.
	{
		k := mustEd25519(t)
		c, r := selfSigned(t, k)
		s, _ := Sign([]byte("x"), c, k, SignOptions{})
		bad := mutateSigner(t, s, func(sd *signedData, _ *signerInfo) {
			sd.Certificates = asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true,
				Bytes: append(append([]byte(nil), sd.Certificates.Bytes...), 0x30, 0x03, 0x02, 0x01, 0x00)}
		})
		if _, err := Verify([]byte("x"), bad, r, now); err == nil || errors.Is(err, ErrVerify) {
			t.Errorf("malformed certificate in the bundle: err = %v, want a parse error that is not ErrVerify", err)
		}
	}

	// The cause stays visible: wrapping must not hide which check failed.
	key := mustRSA(t)
	cert, roots := selfSigned(t, key)
	sig, _ := Sign([]byte("a"), cert, key, SignOptions{})
	_, err = Verify([]byte("b"), sig, roots, now)
	if err == nil || !errors.Is(err, ErrVerify) || err.Error() == ErrVerify.Error() {
		t.Errorf("digest mismatch: %v: want ErrVerify wrapping the specific cause", err)
	}
}

// TestSentinelErrors: the two exported sentinels for readable input that is not a signature here.
func TestSentinelErrors(t *testing.T) {
	key := mustEd25519(t)
	cert, roots := selfSigned(t, key)
	sig, err := Sign([]byte("x"), cert, key, SignOptions{})
	if err != nil {
		t.Fatal(err)
	}
	data := mustMarshal(contentInfo{ContentType: oidData,
		Content: asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: mustMarshal([]byte("x"))}})
	if _, err := Verify([]byte("x"), data, roots, time.Now()); !errors.Is(err, ErrNotSignedData) {
		t.Errorf("id-data ContentInfo: err = %v, want ErrNotSignedData", err)
	}
	if _, err := Verify([]byte("x"), signersInOrder(t, sig, nil), roots, time.Now()); !errors.Is(err, ErrNoSigners) {
		t.Errorf("no SignerInfos: err = %v, want ErrNoSigners", err)
	}
}
