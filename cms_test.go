package cms

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

// selfSigned returns a self-signed CA certificate and its signer, plus a pool
// trusting it — enough to exercise detached Sign→Verify end to end.
func selfSigned(t *testing.T, key crypto.Signer) (*x509.Certificate, *x509.CertPool) {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(42),
		Subject:               pkix.Name{CommonName: "netstar-labs test signer"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return cert, pool
}

func roundTrip(t *testing.T, key crypto.Signer) {
	t.Helper()
	cert, roots := selfSigned(t, key)
	content := []byte("root-anchors.xml or any vendor-signed blob\n")

	sig, err := Sign(content, cert, key, SignOptions{SigningTime: time.Now()})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	signers, err := Verify(content, sig, roots, time.Now())
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if len(signers) != 1 || signers[0].Subject.CommonName != "netstar-labs test signer" {
		t.Fatalf("unexpected signer set: %+v", signers)
	}

	// Tampered content must fail.
	if _, err := Verify([]byte("tampered"), sig, roots, time.Now()); err == nil {
		t.Fatal("tampered content verified")
	}

	// A pool that does not trust the signer must fail the chain.
	other, _ := selfSigned(t, mustRSA(t))
	empty := x509.NewCertPool()
	empty.AddCert(other)
	if _, err := Verify(content, sig, empty, time.Now()); err == nil {
		t.Fatal("verified against an untrusting root pool")
	}
}

func TestRoundTripRSA(t *testing.T) { roundTrip(t, mustRSA(t)) }

func TestRoundTripECDSA(t *testing.T) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	roundTrip(t, k)
}

func TestExpiredCertRejected(t *testing.T) {
	key := mustRSA(t)
	cert, roots := selfSigned(t, key)
	content := []byte("x")
	sig, err := Sign(content, cert, key, SignOptions{})
	if err != nil {
		t.Fatal(err)
	}
	// Far-future "now" places verification outside the cert validity window.
	if _, err := Verify(content, sig, roots, time.Now().Add(72*time.Hour)); err == nil {
		t.Fatal("verified past certificate expiry")
	}
}

func TestNotSignedData(t *testing.T) {
	if _, err := Verify([]byte("x"), []byte{0x05, 0x00}, x509.NewCertPool(), time.Now()); err == nil {
		t.Fatal("garbage input verified")
	}
}

func mustRSA(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return k
}
