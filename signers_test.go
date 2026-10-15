package cms

import (
	"bytes"
	"encoding/asn1"
	"slices"
	"testing"
	"time"
)

// withSigners rebuilds sig's SignedData with its first SignerInfo repeated n times. DER sorts the
// SET but keeps duplicates, so all n survive (checked by the caller by re-parsing).
func withSigners(t testing.TB, sig []byte, n int) []byte {
	t.Helper()
	var ci contentInfo
	if _, err := asn1.Unmarshal(sig, &ci); err != nil {
		t.Fatal(err)
	}
	sd, si, err := parseFirstSigner(sig)
	if err != nil {
		t.Fatal(err)
	}
	sd.SignerInfos = slices.Repeat([]signerInfo{si}, n)
	sdDER, err := asn1.Marshal(sd)
	if err != nil {
		t.Fatal(err)
	}
	ci.Content = asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: sdDER}
	out, err := asn1.Marshal(ci)
	if err != nil {
		t.Fatal(err)
	}
	if got, _, _ := parseFirstSigner(out); len(got.SignerInfos) != n {
		t.Fatalf("built %d SignerInfos, want %d", len(got.SignerInfos), n)
	}
	return out
}

// TestManySignersBoundedWork: a signature that repeats one SignerInfo n times must cost about what
// one costs, not n times as much. Verify used to hash the whole content, and rebuild the certificate
// chain, once per SignerInfo, so a few hundred bytes per copy bought the attacker seconds of CPU.
func TestManySignersBoundedWork(t *testing.T) {
	now := time.Now()
	content := bytes.Repeat([]byte("x"), 8<<20)
	key := mustEd25519(t)
	cert, roots := selfSigned(t, key)
	sig, err := Sign(content, cert, key, SignOptions{})
	if err != nil {
		t.Fatal(err)
	}
	many := withSigners(t, sig, 64)

	best := func(sig []byte) time.Duration {
		d := time.Hour
		for i := 0; i < 5; i++ {
			start := time.Now()
			if _, err := Verify(content, sig, roots, now); err != nil {
				t.Fatal(err)
			}
			d = min(d, time.Since(start))
		}
		return d
	}
	one, sixtyFour := best(sig), best(many)
	// Unfixed this is about 60x; fixed it is about 1x plus 63 cheap signature checks.
	if sixtyFour > 8*one {
		t.Fatalf("64 repeated SignerInfos took %v, one took %v: work scales with the signer count", sixtyFour, one)
	}
}
