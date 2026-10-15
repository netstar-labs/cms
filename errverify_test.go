package cms

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"testing"
	"time"
)

// TestErrVerifyContract: a caller who asks errors.Is(err, ErrVerify) is asking "was this
// authentic?". It must be true whenever SignerInfos were present and none verified, whatever the
// signer's key type or the reason, and false for input that is not a signature at all. It used to
// be true only for an ECDSA or Ed25519 signature mismatch.
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

	// The cause stays visible: wrapping must not hide which check failed.
	key := mustRSA(t)
	cert, roots := selfSigned(t, key)
	sig, _ := Sign([]byte("a"), cert, key, SignOptions{})
	_, err = Verify([]byte("b"), sig, roots, now)
	if err == nil || !errors.Is(err, ErrVerify) || err.Error() == ErrVerify.Error() {
		t.Errorf("digest mismatch: %v: want ErrVerify wrapping the specific cause", err)
	}
}
