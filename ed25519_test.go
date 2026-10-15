package cms

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/asn1"
	"errors"
	"testing"
	"time"
)

func mustEd25519(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, k, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestRoundTripEd25519(t *testing.T) { roundTrip(t, mustEd25519(t)) }

// TestEd25519Encoding checks the RFC 8419 §3.1 wire form: id-sha512 as the digest algorithm, in the signer
// and in SignedData's set, and id-Ed25519 as the signature algorithm, both with parameters absent.
func TestEd25519Encoding(t *testing.T) {
	key := mustEd25519(t)
	cert, _ := selfSigned(t, key)
	sig, err := Sign([]byte("x"), cert, key, SignOptions{})
	if err != nil {
		t.Fatal(err)
	}
	sd, si, err := parseFirstSigner(sig)
	if err != nil {
		t.Fatal(err)
	}
	switch {
	case !si.DigestAlgorithm.Algorithm.Equal(oidSHA512) || len(si.DigestAlgorithm.Parameters.FullBytes) != 0:
		t.Errorf("digest algorithm %v %x, want id-sha512 without parameters", si.DigestAlgorithm.Algorithm, si.DigestAlgorithm.Parameters.FullBytes)
	case !si.SignatureAlgorithm.Algorithm.Equal(asn1.ObjectIdentifier{1, 3, 101, 112}) || len(si.SignatureAlgorithm.Parameters.FullBytes) != 0:
		t.Errorf("signature algorithm %v %x, want id-Ed25519 without parameters", si.SignatureAlgorithm.Algorithm, si.SignatureAlgorithm.Parameters.FullBytes)
	case string(sd.DigestAlgorithms.FullBytes) != string(digestAlgSet(oidSHA512)):
		t.Errorf("SignedData digest algorithms %x, want the id-sha512 set", sd.DigestAlgorithms.FullBytes)
	case len(si.Signature) != ed25519.SignatureSize:
		t.Errorf("signature is %d bytes, want %d", len(si.Signature), ed25519.SignatureSize)
	}
}

func TestEd25519RejectsOtherHashes(t *testing.T) {
	key := mustEd25519(t)
	cert, roots := selfSigned(t, key)
	for _, h := range []crypto.Hash{crypto.SHA256, crypto.SHA384} {
		if _, err := Sign([]byte("x"), cert, key, SignOptions{Hash: h}); err == nil {
			t.Errorf("Sign accepted Ed25519 with %v", h)
		}
	}
	sig, err := Sign([]byte("x"), cert, key, SignOptions{Hash: crypto.SHA512})
	if err != nil {
		t.Fatalf("Sign with an explicit SHA-512: %v", err)
	}
	if _, err := Verify([]byte("x"), sig, roots, time.Now()); err != nil {
		t.Fatal(err)
	}

	// A signer that signed SHA-256 attributes with a valid Ed25519 signature is still refused: RFC 8419
	// fixes the digest algorithm, and accepting another would let a weaker messageDigest stand.
	content := []byte("x")
	sig = resignEd25519(t, sig, key, crypto.SHA256, content)
	if _, err := Verify(content, sig, roots, time.Now()); err == nil {
		t.Fatal("verified an Ed25519 signer whose digest algorithm is SHA-256")
	}
}

func TestEd25519TamperedSignature(t *testing.T) {
	key := mustEd25519(t)
	cert, roots := selfSigned(t, key)
	sig, err := Sign([]byte("x"), cert, key, SignOptions{})
	if err != nil {
		t.Fatal(err)
	}
	_, si, err := parseFirstSigner(sig)
	if err != nil {
		t.Fatal(err)
	}
	// The signature is the last field of the only signer, so its last byte is the encoding's last byte.
	if si.Signature[len(si.Signature)-1] != sig[len(sig)-1] {
		t.Fatal("the encoding does not end with the signature")
	}
	sig[len(sig)-1] ^= 1
	if _, err := Verify([]byte("x"), sig, roots, time.Now()); !errors.Is(err, ErrVerify) {
		t.Fatalf("tampered signature: got %v, want ErrVerify", err)
	}
}

// resignEd25519 rewrites sig's only signer to use digest algorithm h, with a messageDigest of content and a
// fresh, valid Ed25519 signature over the new attributes.
func resignEd25519(t *testing.T, sig []byte, key ed25519.PrivateKey, h crypto.Hash, content []byte) []byte {
	t.Helper()
	sd, si, err := parseFirstSigner(sig)
	if err != nil {
		t.Fatal(err)
	}
	oid, _ := oidForHash(h)
	attrs, err := marshalAttributeSet([]attribute{
		{Type: oidContentType, Values: mustSetOf(mustMarshal(oidData))},
		{Type: oidMessageDigest, Values: mustSetOf(mustMarshal(digest(h, content)))},
	})
	if err != nil {
		t.Fatal(err)
	}
	si.DigestAlgorithm.Algorithm = oid
	si.SignedAttrs = asn1.RawValue{FullBytes: implicitTag(attrs)}
	si.Signature = ed25519.Sign(key, attrs)
	sd.DigestAlgorithms = asn1.RawValue{FullBytes: digestAlgSet(oid)}
	sd.SignerInfos = []signerInfo{si}
	return mustMarshal(contentInfo{
		ContentType: oidSignedData,
		Content:     asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: mustMarshal(sd)},
	})
}
