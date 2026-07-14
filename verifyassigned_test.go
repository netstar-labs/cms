// Copyright (C) 2026 zxdev
// SPDX-License-Identifier: GPL-3.0-or-later

package cms

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

// selfSignedWindow mints a self-signed CA with an explicit validity window, so a
// test can produce a certificate that is already expired at the current wall
// clock while still having been valid at an earlier signing instant.
func selfSignedWindow(t *testing.T, key crypto.Signer, notBefore, notAfter time.Time) (*x509.Certificate, *x509.CertPool) {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(7),
		Subject:               pkix.Name{CommonName: "netstar-labs windowed signer"},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
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

// TestVerifyAsSignedOutlivesLeaf is the load-bearing case: a leaf that is expired
// at wall-clock now, signed while it was valid, must fail Verify(now) yet pass
// VerifyAsSigned (anchored to the signed signingTime).
func TestVerifyAsSignedOutlivesLeaf(t *testing.T) {
	key := mustRSA(t)
	now := time.Now()
	// Cert valid [now-72h, now-24h] — expired 24h ago.
	cert, roots := selfSignedWindow(t, key, now.Add(-72*time.Hour), now.Add(-24*time.Hour))
	content := []byte("a static resource signed long ago\n")
	signedAt := now.Add(-48 * time.Hour) // inside the window

	sig, err := Sign(content, cert, key, SignOptions{SigningTime: signedAt})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// Verify at wall-clock now must fail: the leaf expired 24h ago.
	if _, err := Verify(content, sig, roots, now); err == nil {
		t.Fatal("Verify(now) accepted an expired leaf")
	}

	// VerifyAsSigned anchors to the signingTime and must pass.
	signers, err := VerifyAsSigned(content, sig, roots)
	if err != nil {
		t.Fatalf("VerifyAsSigned: %v", err)
	}
	if len(signers) != 1 || signers[0].Subject.CommonName != "netstar-labs windowed signer" {
		t.Fatalf("unexpected signer set: %+v", signers)
	}

	// SigningTime must round-trip the signed value.
	got, ok, err := SigningTime(sig)
	if err != nil || !ok {
		t.Fatalf("SigningTime: (%v,%v,%v)", got, ok, err)
	}
	if !got.Equal(signedAt.UTC().Truncate(time.Second)) { // UTCTime has 1s resolution
		t.Fatalf("SigningTime = %s, want %s", got, signedAt.UTC().Truncate(time.Second))
	}

	// Even anchored to signingTime, tampered content and an untrusting pool fail.
	if _, err := VerifyAsSigned([]byte("tampered"), sig, roots); err == nil {
		t.Fatal("VerifyAsSigned accepted tampered content")
	}
	other, _ := selfSigned(t, mustRSA(t))
	empty := x509.NewCertPool()
	empty.AddCert(other)
	if _, err := VerifyAsSigned(content, sig, empty); err == nil {
		t.Fatal("VerifyAsSigned accepted an untrusting root pool")
	}
}

// TestVerifyAsSignedNoSigningTimeFallsBackToNotBefore: with no signingTime, the
// anchor is the signer's NotBefore, so an expired-since leaf still verifies.
func TestVerifyAsSignedNoSigningTimeFallsBackToNotBefore(t *testing.T) {
	key := mustRSA(t)
	now := time.Now()
	cert, roots := selfSignedWindow(t, key, now.Add(-72*time.Hour), now.Add(-24*time.Hour))
	content := []byte("no signingTime here\n")

	sig, err := Sign(content, cert, key, SignOptions{}) // no SigningTime
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if _, err := Verify(content, sig, roots, now); err == nil {
		t.Fatal("Verify(now) accepted an expired leaf")
	}
	if _, err := VerifyAsSigned(content, sig, roots); err != nil {
		t.Fatalf("VerifyAsSigned (NotBefore fallback): %v", err)
	}
	if _, ok, err := SigningTime(sig); err != nil || ok {
		t.Fatalf("SigningTime with none present: ok=%v err=%v, want ok=false", ok, err)
	}
}
