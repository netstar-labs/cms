package cms

import (
	"crypto/x509"
	"encoding/asn1"
	"errors"
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

// verifyOpts are the options Verify builds, for tests that drive verifyWith directly.
func verifyOpts(roots *x509.CertPool, now time.Time) x509.VerifyOptions {
	return x509.VerifyOptions{Roots: roots, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}
}

// TestManySignersBoundedWork: a signature that repeats one SignerInfo n times must cost what one
// costs in the two expensive, signer-independent steps. Verify used to hash the whole content, and
// rebuild the certificate chain, once per SignerInfo, so a few hundred bytes per copy bought an
// attacker seconds of CPU. The work is counted, not timed: a timing ratio flakes under -race and
// load, a count does not, and it also fails if the chain cache is silently disabled.
func TestManySignersBoundedWork(t *testing.T) {
	now := time.Now()
	content := []byte("content")
	key := mustEd25519(t)
	cert, roots := selfSigned(t, key)
	sig, err := Sign(content, cert, key, SignOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []int{1, 2, 64} {
		st := newVerifyState(content)
		signers, err := verifyWith(st, withSigners(t, sig, n), verifyOpts(roots, now))
		if err != nil || len(signers) == 0 {
			t.Fatalf("n=%d: %d signers, err %v", n, len(signers), err)
		}
		if st.hashed != 1 || st.chained != 1 {
			t.Errorf("n=%d: content hashed %d times and the chain built %d times, want once each", n, st.hashed, st.chained)
		}
	}
}

// TestRepeatedBadSignerRejected: a cached chain FAILURE must be replayed. If the cache ignored a
// stored error (or answered a repeat with success), a signature repeating an untrusted or expired
// signer would verify on its second copy while the first copy alone is rejected.
func TestRepeatedBadSignerRejected(t *testing.T) {
	now := time.Now()
	content := []byte("content")
	key := mustEd25519(t)
	cert, roots := selfSigned(t, key)
	other, _ := selfSigned(t, mustRSA(t))
	untrusting := x509.NewCertPool()
	untrusting.AddCert(other)
	sig, err := Sign(content, cert, key, SignOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		roots *x509.CertPool
		at    time.Time
	}{
		"untrusted root": {untrusting, now},
		"expired":        {roots, now.Add(72 * time.Hour)},
	} {
		for _, n := range []int{1, 2, 3, 16} {
			st := newVerifyState(content)
			signers, err := verifyWith(st, withSigners(t, sig, n), verifyOpts(c.roots, c.at))
			if err == nil || len(signers) != 0 || !errors.Is(err, ErrVerify) {
				t.Errorf("%s, %d copies: %d signers accepted, err %v; want rejection with ErrVerify", name, n, len(signers), err)
			}
			if st.chained != 1 {
				t.Errorf("%s, %d copies: chain built %d times, want 1", name, n, st.chained)
			}
		}
	}
}
