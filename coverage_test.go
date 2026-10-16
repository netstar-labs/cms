package cms

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"slices"
	"testing"
	"time"
)

// mutateSigner re-marshals sig with fn applied to its first SignerInfo (and the SignedData around it).
func mutateSigner(t testing.TB, sig []byte, fn func(*signedData, *signerInfo)) []byte {
	t.Helper()
	var ci contentInfo
	if _, err := asn1.Unmarshal(sig, &ci); err != nil {
		t.Fatal(err)
	}
	sd, si, err := parseFirstSigner(sig)
	if err != nil {
		t.Fatal(err)
	}
	fn(&sd, &si)
	sd.SignerInfos = []signerInfo{si}
	sdDER, err := asn1.Marshal(sd)
	if err != nil {
		t.Fatal(err)
	}
	ci.Content = asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: sdDER}
	out, err := asn1.Marshal(ci)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func allKeys(t testing.TB) map[string]crypto.Signer {
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return map[string]crypto.Signer{"rsa": mustRSA(t), "ecdsa": ec, "ed25519": mustEd25519(t)}
}

// TestHashMatrix: the docs say RSA and ECDSA sign with SHA-256, SHA-384 and SHA-512 and that other
// hashes are refused; Ed25519 takes SHA-512 only. Until now no test set a Hash other than the default.
func TestHashMatrix(t *testing.T) {
	now := time.Now()
	content := []byte("content")
	for name, key := range allKeys(t) {
		cert, roots := selfSigned(t, key)
		for _, h := range []crypto.Hash{crypto.SHA256, crypto.SHA384, crypto.SHA512, crypto.SHA1, crypto.MD5, crypto.SHA3_256, crypto.Hash(99)} {
			sig, err := Sign(content, cert, key, SignOptions{Hash: h})
			supported := h == crypto.SHA256 || h == crypto.SHA384 || h == crypto.SHA512
			if name == "ed25519" {
				supported = h == crypto.SHA512
			}
			if !supported {
				if err == nil {
					t.Errorf("%s: Sign accepted hash %v", name, h)
				}
				continue
			}
			if err != nil {
				t.Errorf("%s/%v: Sign: %v", name, h, err)
				continue
			}
			if _, err := Verify(content, sig, roots, now); err != nil {
				t.Errorf("%s/%v: Verify: %v", name, h, err)
			}
		}
	}
}

// TestDigestAlgorithmsIsASet pins the wire form fixed in ec4f686 for every key type, without going
// through the helper that builds it: SignedData.digestAlgorithms is a universal constructed SET
// holding one AlgorithmIdentifier — not an OCTET STRING wrapping one, which openssl rejects.
func TestDigestAlgorithmsIsASet(t *testing.T) {
	for name, key := range allKeys(t) {
		cert, _ := selfSigned(t, key)
		sig, err := Sign([]byte("x"), cert, key, SignOptions{})
		if err != nil {
			t.Fatal(err)
		}
		sd, si, err := parseFirstSigner(sig)
		if err != nil {
			t.Fatal(err)
		}
		d := sd.DigestAlgorithms
		if d.Class != asn1.ClassUniversal || d.Tag != asn1.TagSet || !d.IsCompound {
			t.Errorf("%s: digestAlgorithms is class %d tag %d compound=%v, want a universal constructed SET", name, d.Class, d.Tag, d.IsCompound)
			continue
		}
		var alg struct{ Algorithm asn1.ObjectIdentifier }
		rest, err := asn1.Unmarshal(d.Bytes, &alg)
		if err != nil || len(rest) != 0 || !alg.Algorithm.Equal(si.DigestAlgorithm.Algorithm) {
			t.Errorf("%s: digestAlgorithms holds %x, want exactly the signer's digest algorithm %v (err %v)", name, d.Bytes, si.DigestAlgorithm.Algorithm, err)
		}
	}
}

// TestSubjectKeyIdentifierSID: openssl's -keyid names the signer by [0] SubjectKeyIdentifier rather
// than by issuer and serial; findCert had no test for that form.
func TestSubjectKeyIdentifierSID(t *testing.T) {
	now := time.Now()
	for name, key := range allKeys(t) {
		cert, roots := selfSigned(t, key)
		if len(cert.SubjectKeyId) == 0 {
			t.Fatalf("%s: test certificate has no SubjectKeyId", name)
		}
		sig, err := Sign([]byte("x"), cert, key, SignOptions{})
		if err != nil {
			t.Fatal(err)
		}
		ski := append([]byte{0x80, byte(len(cert.SubjectKeyId))}, cert.SubjectKeyId...)
		bySKI := mutateSigner(t, sig, func(_ *signedData, si *signerInfo) {
			si.SID = asn1.RawValue{FullBytes: ski}
			si.Version = 3 // RFC 5652 §5.3: version 3 when the signer is identified by SKI
		})
		if _, err := Verify([]byte("x"), bySKI, roots, now); err != nil {
			t.Errorf("%s: SKI-identified signer rejected: %v", name, err)
		}
		unknown := mutateSigner(t, sig, func(_ *signedData, si *signerInfo) {
			si.SID = asn1.RawValue{FullBytes: append([]byte{0x80, 3}, 1, 2, 3)}
		})
		if _, err := Verify([]byte("x"), unknown, roots, now); err == nil {
			t.Errorf("%s: signer with an unknown SKI verified", name)
		}
	}
}

// TestMultipleSigners: at least one signer must verify; none verifying is ErrVerify.
func TestMultipleSigners(t *testing.T) {
	now := time.Now()
	content := []byte("two signers")
	k1, k2 := mustEd25519(t), mustRSA(t)
	c1, r1 := selfSigned(t, k1)
	c2 := newCert(t, k2, 99, "second signer")
	roots := x509.NewCertPool()
	roots.AddCert(c2)
	_ = r1
	s1, err := Sign(content, c1, k1, SignOptions{})
	if err != nil {
		t.Fatal(err)
	}
	s2, err := Sign(content, c2, k2, SignOptions{})
	if err != nil {
		t.Fatal(err)
	}
	both := func(a, b []byte) []byte {
		var ci contentInfo
		asn1.Unmarshal(a, &ci)
		sdA, siA, _ := parseFirstSigner(a)
		sdB, siB, _ := parseFirstSigner(b)
		// a parsed RawValue re-marshals from FullBytes, so build a fresh [0] holding both bundles
		sdA.Certificates = asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true,
			Bytes: slices.Concat(sdA.Certificates.Bytes, sdB.Certificates.Bytes)}
		sdA.SignerInfos = []signerInfo{siA, siB}
		der, err := asn1.Marshal(sdA)
		if err != nil {
			t.Fatal(err)
		}
		ci.Content = asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: der}
		out, _ := asn1.Marshal(ci)
		return out
	}
	// c1 is not in the pool (untrusted); c2 is. One good signer is enough, in either order, and the
	// work is shared per digest algorithm and per certificate: SHA-512 (Ed25519) and SHA-256 (RSA),
	// two certificates.
	for name, sig := range map[string][]byte{"untrusted first": both(s1, s2), "trusted first": both(s2, s1)} {
		st := newVerifyState(content)
		signers, err := verifyWith(st, sig, verifyOpts(roots, now), false)
		if err != nil || len(signers) != 1 || signers[0].SerialNumber.Int64() != 99 {
			t.Fatalf("%s: %d signers, err %v", name, len(signers), err)
		}
		if st.hashed != 2 || st.chained != 2 {
			t.Errorf("%s: content hashed %d times and %d chains built, want 2 and 2", name, st.hashed, st.chained)
		}
		if _, err := Verify([]byte("tampered"), sig, roots, now); !errors.Is(err, ErrVerify) {
			t.Errorf("%s: none valid for the content: err = %v, want ErrVerify", name, err)
		}
	}
}

func newCert(t testing.TB, key crypto.Signer, serial int64, cn string) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}
