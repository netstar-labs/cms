//go:build interop

// The interop test checks cms against the openssl cms command in both directions: openssl verifies what
// Sign writes, and Verify accepts what openssl signs. Run it with go test -tags interop.
//
// Ed25519 needs an openssl whose cms command supports EdDSA (RFC 8419). OpenSSL 3.5.0 does and passes;
// OpenSSL 3.0.15 loads the key but fails in cms ("invalid digest"), and LibreSSL 3.3.6 cannot load an
// Ed25519 key at all. The Ed25519 case therefore skips unless this openssl can itself sign an Ed25519
// CMS message; it never fails because of the openssl it found.
package cms

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestOpenSSLInterop(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("no openssl on PATH")
	}
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for name, key := range map[string]crypto.Signer{"rsa": mustRSA(t), "ecdsa": ec, "ed25519": mustEd25519(t)} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			path := func(f string) string { return filepath.Join(dir, f) }
			cert, roots := selfSigned(t, key)
			pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
			if err != nil {
				t.Fatal(err)
			}
			content := []byte("interop content\n")
			write(t, path("key.pem"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}))
			write(t, path("cert.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
			write(t, path("content"), content)
			write(t, path("tampered"), []byte("tampered\n"))
			if out, err := openssl("pkey", "-in", path("key.pem"), "-noout"); err != nil {
				t.Skipf("this openssl cannot load a %s key: %s", name, out)
			}

			// openssl signs first: for Ed25519 that is also the probe for whether this openssl can do
			// CMS EdDSA at all. Ed25519 takes SHA-512 (RFC 8419); older openssl signs ECDSA with SHA-1,
			// which cms refuses, so the others ask for SHA-256.
			md := "sha256"
			if name == "ed25519" {
				md = "sha512"
			}
			args := []string{"cms", "-sign", "-binary", "-outform", "DER", "-in", path("content"),
				"-signer", path("cert.pem"), "-inkey", path("key.pem"), "-md", md, "-out", path("openssl.p7s")}
			if out, err := openssl(args...); err != nil {
				// Only the failures that mean "no EdDSA in this openssl's cms" skip; any other
				// failure is a real problem and must be seen.
				if name == "ed25519" && (bytes.Contains(out, []byte("invalid digest")) || bytes.Contains(out, []byte("no default digest")) ||
					bytes.Contains(out, []byte("unsupported"))) {
					t.Skipf("this openssl cannot sign an Ed25519 CMS message: %s", out)
				}
				t.Fatalf("openssl cms -sign: %v\n%s", err, out)
			}

			sig, err := Sign(content, cert, key, SignOptions{SigningTime: time.Now()})
			if err != nil {
				t.Fatal(err)
			}
			write(t, path("go.p7s"), sig)
			verify := func(sig, content string) ([]byte, error) {
				return openssl("cms", "-verify", "-binary", "-inform", "DER", "-in", sig, "-content", content,
					"-CAfile", path("cert.pem"), "-out", os.DevNull)
			}
			if out, err := verify(path("go.p7s"), path("content")); err != nil {
				t.Errorf("openssl rejected Sign's output: %v\n%s", err, out)
			}
			if _, err := verify(path("go.p7s"), path("tampered")); err == nil {
				t.Error("openssl accepted Sign's output over tampered content")
			}

			sig, err = os.ReadFile(path("openssl.p7s"))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Verify(content, sig, roots, time.Now()); err != nil {
				t.Errorf("Verify rejected openssl's signature: %v", err)
			}
			if _, err := Verify([]byte("tampered\n"), sig, roots, time.Now()); err == nil {
				t.Error("Verify accepted openssl's signature over tampered content")
			}
		})
	}
}

func openssl(args ...string) ([]byte, error) {
	return exec.Command("openssl", args...).CombinedOutput()
}

func write(t *testing.T, name string, b []byte) {
	t.Helper()
	if err := os.WriteFile(name, b, 0o600); err != nil {
		t.Fatal(err)
	}
}
