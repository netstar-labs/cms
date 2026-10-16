package cms

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"testing"
	"time"
)

// fixture is a signer, the roots that trust it, and a valid signature over content.
type fixture struct {
	name    string
	roots   *x509.CertPool
	content []byte
	sig     []byte
}

func fixtures(tb testing.TB, now time.Time) []fixture {
	tb.Helper()
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatal(err)
	}
	_, ed, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		tb.Fatal(err)
	}
	keys := []struct {
		name string
		key  crypto.Signer
	}{{"rsa", mustRSA(tb)}, {"ecdsa", ec}, {"ed25519", ed}}

	var out []fixture
	content := []byte("the signed artifact\n")
	for _, k := range keys {
		cert, roots := selfSigned(tb, k.key)
		for _, st := range []time.Time{{}, now} { // without and with signingTime
			name := k.name
			if !st.IsZero() {
				name += "+signingTime"
			}
			sig, err := Sign(content, cert, k.key, SignOptions{SigningTime: st})
			if err != nil {
				tb.Fatalf("%s: Sign: %v", k.name, err)
			}
			out = append(out, fixture{name, roots, content, sig})
		}
	}
	return out
}

// FuzzVerify feeds arbitrary signature and content bytes to the verifier, which parses
// attacker-controlled DER. Invariants: it never panics or hangs, and — the security property —
// a verification can only succeed over the ORIGINAL content: a mutated signature must never
// authenticate different bytes. "No forgery found" here is evidence about parsing and gating,
// not a proof of the property.
func FuzzVerify(f *testing.F) {
	now := time.Now()
	fx := fixtures(f, now)
	for i, x := range fx {
		f.Add(i, x.content, x.sig)
		f.Add(i, x.content, x.sig[:len(x.sig)/2]) // truncated
		f.Add(i, []byte("other"), x.sig)          // wrong content
	}
	f.Fuzz(func(t *testing.T, which int, content, sig []byte) {
		x := fx[uint(which)%uint(len(fx))]
		for _, verify := range []func() ([]*x509.Certificate, error){
			func() ([]*x509.Certificate, error) { return Verify(content, sig, x.roots, now) },
			func() ([]*x509.Certificate, error) { return VerifyAsSigned(content, sig, x.roots) },
		} {
			signers, err := verify()
			if err == nil && !bytes.Equal(content, x.content) {
				t.Fatalf("FORGERY: %s signature verified different content %q (%d signers)", x.name, content, len(signers))
			}
		}
		SigningTime(sig) // must not panic
	})
}

func BenchmarkVerify(b *testing.B) {
	now := time.Now()
	for _, x := range fixtures(b, now) {
		b.Run(x.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if _, err := Verify(x.content, x.sig, x.roots, now); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkSign(b *testing.B) {
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_, ed, _ := ed25519.GenerateKey(rand.Reader)
	rsaKey := mustRSA(b)
	content := bytes.Repeat([]byte("x"), 64<<10)
	for _, k := range []struct {
		name string
		key  crypto.Signer
	}{{"rsa2048", rsaKey}, {"ecdsa-p256", ec}, {"ed25519", ed}} {
		cert, _ := selfSigned(b, k.key)
		b.Run(k.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if _, err := Sign(content, cert, k.key, SignOptions{}); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkParseHostile measures the cost of rejecting input that is not a signature at all, the
// price an attacker can impose per call with bytes they control.
func BenchmarkParseHostile(b *testing.B) {
	roots := x509.NewCertPool()
	for _, n := range []int{1 << 10, 1 << 20} {
		junk := bytes.Repeat([]byte{0x30, 0x80}, n/2) // nested indefinite-length openers
		b.Run(fmt.Sprintf("%dKiB", n>>10), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				Verify([]byte("x"), junk, roots, time.Now())
			}
		})
	}
}
