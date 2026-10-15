package cms

import (
	"crypto/x509"
	"testing"
	"time"
)

// TestSignRejectsBadInput: Sign takes caller-supplied values and must answer a bad one with an
// error, never a panic, and must refuse a certificate that does not belong to the key — such a
// signature can never verify, and nothing at signing time said so.
func TestSignRejectsBadInput(t *testing.T) {
	content := []byte("content")
	edKey, rsaKey, rsaKey2 := mustEd25519(t), mustRSA(t), mustRSA(t)
	edCert, _ := selfSigned(t, edKey)
	rsaCert, _ := selfSigned(t, rsaKey)
	at := func(year int) SignOptions {
		return SignOptions{SigningTime: time.Date(year, 1, 1, 0, 0, 0, 0, time.UTC)}
	}

	for name, call := range map[string]func() ([]byte, error){
		"signingTime year 10000": func() ([]byte, error) { return Sign(content, edCert, edKey, at(10000)) },
		"signingTime year -1":    func() ([]byte, error) { return Sign(content, edCert, edKey, at(-1)) },
		"nil certificate":        func() ([]byte, error) { return Sign(content, nil, edKey, SignOptions{}) },
		"nil key":                func() ([]byte, error) { return Sign(content, edCert, nil, SignOptions{}) },
		"certificate without DER": func() ([]byte, error) {
			return Sign(content, &x509.Certificate{}, edKey, SignOptions{})
		},
		"certificate without a serial number": func() ([]byte, error) {
			return Sign(content, &x509.Certificate{Raw: edCert.Raw, PublicKey: edCert.PublicKey}, edKey, SignOptions{})
		},
		"certificate without a public key": func() ([]byte, error) {
			return Sign(content, &x509.Certificate{Raw: edCert.Raw, SerialNumber: edCert.SerialNumber}, edKey, SignOptions{})
		},
		"rsa certificate, other rsa key": func() ([]byte, error) { return Sign(content, rsaCert, rsaKey2, SignOptions{}) },
		"rsa certificate, ed25519 key":   func() ([]byte, error) { return Sign(content, rsaCert, edKey, SignOptions{}) },
		"ed25519 certificate, rsa key":   func() ([]byte, error) { return Sign(content, edCert, rsaKey, SignOptions{}) },
	} {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("Sign panicked: %v", r)
				}
			}()
			if sig, err := call(); err == nil {
				t.Fatalf("Sign accepted bad input and returned %d bytes", len(sig))
			}
		})
	}

	// The extremes that ARE representable must still sign and verify.
	for _, year := range []int{1950, 2049, 2050, 9999} {
		cert, roots := selfSigned(t, edKey)
		sig, err := Sign(content, cert, edKey, at(year))
		if err != nil {
			t.Fatalf("year %d: %v", year, err)
		}
		if _, err := Verify(content, sig, roots, time.Now()); err != nil {
			t.Fatalf("year %d: Verify: %v", year, err)
		}
	}
}
