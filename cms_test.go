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

// TestVerifyWithIntermediateChain builds root CA → intermediate CA → leaf signer
// and confirms VerifyWith chains through the bundle's intermediate to a root pool
// that trusts only the root.
func TestVerifyWithIntermediateChain(t *testing.T) {
	now := time.Now()
	mkCert := func(cn string, serial int64, pub any, parent *x509.Certificate, parentKey crypto.Signer, isCA bool) *x509.Certificate {
		tmpl := &x509.Certificate{
			SerialNumber:          big.NewInt(serial),
			Subject:               pkix.Name{CommonName: cn},
			NotBefore:             now.Add(-time.Hour),
			NotAfter:              now.Add(24 * time.Hour),
			KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
			BasicConstraintsValid: true,
			IsCA:                  isCA,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, parentKey)
		if err != nil {
			t.Fatal(err)
		}
		c, _ := x509.ParseCertificate(der)
		return c
	}

	rootKey := mustRSA(t)
	rootTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "root"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true,
	}
	rootDER, _ := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	root, _ := x509.ParseCertificate(rootDER)

	interKey := mustRSA(t)
	inter := mkCert("intermediate", 2, &interKey.PublicKey, root, rootKey, true)

	leafKey := mustRSA(t)
	leaf := mkCert("leaf signer", 3, &leafKey.PublicKey, inter, interKey, false)

	content := []byte("chain test")
	sig, err := Sign(content, leaf, leafKey, SignOptions{})
	if err != nil {
		t.Fatal(err)
	}
	// The SignedData embeds only the leaf; add the intermediate via opts.
	inters := x509.NewCertPool()
	inters.AddCert(inter)
	roots := x509.NewCertPool()
	roots.AddCert(root)

	if _, err := VerifyWith(content, sig, x509.VerifyOptions{
		Roots: roots, Intermediates: inters, CurrentTime: now,
	}); err != nil {
		t.Fatalf("intermediate chain should verify: %v", err)
	}
	// Without the intermediate and without it in the bundle, the chain breaks.
	if _, err := VerifyWith(content, sig, x509.VerifyOptions{
		Roots: roots, Intermediates: x509.NewCertPool(), CurrentTime: now,
	}); err == nil {
		t.Fatal("chain verified without the intermediate")
	}
}
