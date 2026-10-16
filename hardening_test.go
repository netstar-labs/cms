package cms

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"runtime"
	"slices"
	"testing"
	"time"
)

// The tests in this file pin the fixes for docs/audits/audit-findings.md D-1 to D-14. Each builds
// a signature the audit showed was accepted, or wrongly rejected, and checks the new answer.

// contentAttrs are the signed attributes Sign writes for content under h, without signingTime.
func contentAttrs(h crypto.Hash, content []byte) []attribute {
	return []attribute{
		{Type: oidContentType, Values: setOf(mustMarshal(oidData))},
		{Type: oidMessageDigest, Values: setOf(mustMarshal(digest(h, content)))},
	}
}

// signedWith rebuilds sig's only signer with attrs as its signed attributes and a fresh, valid
// signature over them by key. fn, when not nil, adjusts the SignedData and SignerInfo first.
func signedWith(t testing.TB, sig []byte, key crypto.Signer, attrs []attribute, fn func(*signedData, *signerInfo)) []byte {
	t.Helper()
	return mutateSigner(t, sig, func(sd *signedData, si *signerInfo) {
		if fn != nil {
			fn(sd, si)
		}
		set, err := marshalAttributeSet(attrs)
		if err != nil {
			t.Fatal(err)
		}
		si.SignedAttrs = asn1.RawValue{FullBytes: implicitTag(set)}
		h, _ := hashForOID(si.DigestAlgorithm.Algorithm)
		if _, ok := key.(interface{ Seed() []byte }); ok { // ed25519.PrivateKey
			si.Signature, err = key.Sign(rand.Reader, set, crypto.Hash(0))
		} else {
			si.Signature, err = key.Sign(rand.Reader, digest(h, set), h)
		}
		if err != nil {
			t.Fatal(err)
		}
	})
}

// D-1: a SignerInfo without signed attributes is refused. The audit's attack: strip the attributes
// from a genuine signature, and what remains is a valid signature over the attribute bytes.
func TestNoSignedAttributesRejected(t *testing.T) {
	now := time.Now()
	content := []byte("signed content")
	for name, key := range allKeys(t) {
		cert, roots := selfSigned(t, key)
		sig, err := Sign(content, cert, key, SignOptions{})
		if err != nil {
			t.Fatal(err)
		}
		_, orig, _ := parseFirstSigner(sig)
		attrsDER := reencodeAsSet(orig.SignedAttrs.FullBytes)
		stripped := mutateSigner(t, sig, func(_ *signedData, si *signerInfo) { si.SignedAttrs = asn1.RawValue{} })
		if _, err := Verify(attrsDER, stripped, roots, now); !errors.Is(err, ErrVerify) {
			t.Errorf("%s: stripped signature over the attribute bytes: err = %v, want ErrVerify", name, err)
		}
		if _, err := Verify(content, sig, roots, now); err != nil {
			t.Errorf("%s: the genuine signature: %v", name, err)
		}
	}
}

// D-2, D-2d: more than maxSigners SignerInfos is refused before they are decoded, so a large
// signature of minimal SignerInfos costs neither time nor memory in proportion to its size.
func TestSignerLimit(t *testing.T) {
	now := time.Now()
	content := []byte("content")
	key := mustEd25519(t)
	cert, roots := selfSigned(t, key)
	sig, err := Sign(content, cert, key, SignOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(content, withSigners(t, sig, maxSigners), roots, now); err != nil {
		t.Errorf("%d SignerInfos: %v", maxSigners, err)
	}
	if _, err := Verify(content, withSigners(t, sig, maxSigners+1), roots, now); err == nil || errors.Is(err, ErrVerify) {
		t.Errorf("%d SignerInfos: err = %v, want a refusal that is not ErrVerify", maxSigners+1, err)
	}

	huge := withSigners(t, sig, 40000)
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	_, err = Verify(content, huge, roots, now)
	runtime.ReadMemStats(&after)
	if err == nil {
		t.Fatal("40,000 SignerInfos verified")
	}
	if alloc := after.TotalAlloc - before.TotalAlloc; alloc > uint64(len(huge))/4 {
		t.Errorf("refusing a %d-byte signature of 40,000 SignerInfos allocated %d bytes", len(huge), alloc)
	}
}

// D-2c: distinct chain builds per call are capped, whatever the certificates.
func TestChainBudget(t *testing.T) {
	st := newVerifyState(nil)
	opts := verifyOpts(x509.NewCertPool(), time.Now())
	key := mustEd25519(t)
	for i := range maxChains + 1 {
		err := st.chain(newCert(t, key, int64(i+1), "chain budget"), opts)
		if i < maxChains && err == nil {
			t.Fatalf("certificate %d chained to an empty pool", i)
		}
		if i == maxChains && (err == nil || st.chained != maxChains) {
			t.Fatalf("certificate %d: err %v after %d builds, want the budget refusal after %d", i, err, st.chained, maxChains)
		}
	}
}

// D-3: VerifyAsSigned takes each signer's time from its own verified attributes. A keyless party
// prepending a SignerInfo with a backdated signingTime used to make an expired signer verify.
func TestVerifyAsSignedAnchorPerSigner(t *testing.T) {
	now := time.Now()
	key := mustEd25519(t)
	cert, roots := selfSignedWindow(t, key, now.Add(-72*time.Hour), now.Add(-24*time.Hour))
	content := []byte("content")
	late, err := Sign(content, cert, key, SignOptions{SigningTime: now}) // after the certificate expired
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyAsSigned(content, late, roots); err == nil {
		t.Fatal("a signature dated after expiry verified")
	}
	backdated := append(contentAttrs(crypto.SHA512, content),
		attribute{Type: oidSigningTime, Values: setOf(mustMarshal(now.Add(-48 * time.Hour).UTC()))})
	_, real, _ := parseFirstSigner(late)
	junk := mutateSigner(t, late, func(sd *signedData, si *signerInfo) {
		set, _ := marshalAttributeSet(backdated)
		si.SignedAttrs = asn1.RawValue{FullBytes: implicitTag(set)} // the signature no longer matches
	})
	_, junkSI, _ := parseFirstSigner(junk)
	for _, order := range [][]signerInfo{{junkSI, real}, {real, junkSI}} {
		both := mutateSigners(t, late, order)
		if _, err := VerifyAsSigned(content, both, roots); err == nil {
			t.Error("a junk SignerInfo's backdated signingTime let an expired signer verify")
		}
	}

	// The zero time is refused rather than read by x509 as "now".
	fresh, freshRoots := selfSigned(t, key)
	zero := append(contentAttrs(crypto.SHA512, content), attribute{Type: oidSigningTime, Values: setOf(mustMarshal(time.Time{}))})
	sig, err := Sign(content, fresh, key, SignOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyAsSigned(content, signedWith(t, sig, key, zero, nil), freshRoots); err == nil {
		t.Error("a signingTime of the zero time verified")
	}
}

// mutateSigners re-marshals sig with sis as its SignerInfos.
func mutateSigners(t testing.TB, sig []byte, sis []signerInfo) []byte {
	t.Helper()
	return mutateSignedData(t, sig, func(sd *signedData) { sd.SignerInfos = sis })
}

func mutateSignedData(t testing.TB, sig []byte, fn func(*signedData)) []byte {
	t.Helper()
	var ci contentInfo
	if _, err := asn1.Unmarshal(sig, &ci); err != nil {
		t.Fatal(err)
	}
	sd, err := parseSignedData(sig)
	if err != nil {
		t.Fatal(err)
	}
	fn(&sd)
	ci.Content = asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: mustMarshal(sd)}
	return mustMarshal(ci)
}

// D-4: a nil root pool is refused instead of meaning the system trust store.
func TestNilRootsRefused(t *testing.T) {
	key := mustEd25519(t)
	cert, _ := selfSigned(t, key)
	sig, err := Sign([]byte("x"), cert, key, SignOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for name, run := range map[string]func() error{
		"Verify":         func() error { _, err := Verify([]byte("x"), sig, nil, time.Now()); return err },
		"VerifyWith":     func() error { _, err := VerifyWith([]byte("x"), sig, x509.VerifyOptions{}); return err },
		"VerifyAsSigned": func() error { _, err := VerifyAsSigned([]byte("x"), sig, nil); return err },
	} {
		if err := run(); err == nil || errors.Is(err, ErrVerify) {
			t.Errorf("%s with nil roots: err = %v, want a refusal that is not ErrVerify", name, err)
		}
	}
}

// D-5: a certificate whose key usage does not include signing cannot sign; one without the
// extension, or with contentCommitment, can.
func TestSignerKeyUsage(t *testing.T) {
	now := time.Now()
	key := mustRSA(t)
	for usage, ok := range map[x509.KeyUsage]bool{
		0:                              true,
		x509.KeyUsageDigitalSignature:  true,
		x509.KeyUsageContentCommitment: true,
		x509.KeyUsageKeyEncipherment:   false,
		x509.KeyUsageCertSign:          false,
		x509.KeyUsageCertSign | x509.KeyUsageCRLSign: false,
	} {
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(5), Subject: pkix.Name{CommonName: "key usage"},
			NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: usage,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
		if err != nil {
			t.Fatal(err)
		}
		cert, _ := x509.ParseCertificate(der)
		roots := x509.NewCertPool()
		roots.AddCert(cert)
		sig, err := Sign([]byte("x"), cert, key, SignOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Verify([]byte("x"), sig, roots, now); (err == nil) != ok {
			t.Errorf("key usage %b: err = %v, want accepted = %v", usage, err, ok)
		}
	}
}

// D-6: one certificate verified under several SignerInfos is reported once.
func TestRepeatedSignerReportedOnce(t *testing.T) {
	key := mustEd25519(t)
	cert, roots := selfSigned(t, key)
	sig, err := Sign([]byte("x"), cert, key, SignOptions{})
	if err != nil {
		t.Fatal(err)
	}
	signers, err := Verify([]byte("x"), withSigners(t, sig, 3), roots, time.Now())
	if err != nil || len(signers) != 1 {
		t.Fatalf("3 copies of one signer: %d certificates, err %v; want 1", len(signers), err)
	}
}

// D-7: an attribute certificate or other context-tagged CertificateChoices in the bundle is skipped.
func TestBundleSkipsOtherCertificateChoices(t *testing.T) {
	key := mustEd25519(t)
	cert, roots := selfSigned(t, key)
	sig, err := Sign([]byte("x"), cert, key, SignOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, tag := range []int{1, 2, 3} {
		other := mustMarshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: tag, IsCompound: true, Bytes: mustMarshal(42)})
		withOther := mutateSignedData(t, sig, func(sd *signedData) {
			sd.Certificates = asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true,
				Bytes: slices.Concat(other, sd.Certificates.Bytes)}
		})
		if _, err := Verify([]byte("x"), withOther, roots, time.Now()); err != nil {
			t.Errorf("[%d] element in the bundle: %v", tag, err)
		}
	}
}

// D-8: every certificate the identifier names is tried, so an expired copy of the signer's
// certificate earlier in the bundle does not hide the current one; an empty SKI names nothing.
func TestSignerCandidates(t *testing.T) {
	now := time.Now()
	key := mustEd25519(t)
	mk := func(notAfter time.Time) *x509.Certificate {
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(9), Subject: pkix.Name{CommonName: "renewed"}, SubjectKeyId: []byte{1, 2, 3, 4},
			NotBefore: now.Add(-48 * time.Hour), NotAfter: notAfter, KeyUsage: x509.KeyUsageDigitalSignature,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
		if err != nil {
			t.Fatal(err)
		}
		c, _ := x509.ParseCertificate(der)
		return c
	}
	expired, current := mk(now.Add(-24*time.Hour)), mk(now.Add(24*time.Hour))
	roots := x509.NewCertPool()
	roots.AddCert(expired)
	roots.AddCert(current)
	sig, err := Sign([]byte("x"), current, key, SignOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, sid := range []string{"issuerAndSerial", "subjectKeyIdentifier"} {
		for _, order := range [][]*x509.Certificate{{expired, current}, {current, expired}} {
			s := mutateSigner(t, sig, func(sd *signedData, si *signerInfo) {
				sd.Certificates = asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true,
					Bytes: slices.Concat(order[0].Raw, order[1].Raw)}
				if sid == "subjectKeyIdentifier" {
					si.SID, si.Version = asn1.RawValue{FullBytes: []byte{0x80, 4, 1, 2, 3, 4}}, 3
				}
			})
			if _, err := Verify([]byte("x"), s, roots, now); err != nil {
				t.Errorf("%s, %s first: %v", sid, order[0].NotAfter.Format(time.DateOnly), err)
			}
		}
	}

	// An empty SKI would match any certificate without one.
	noSKI := newCert(t, key, 11, "no SKI")
	noSKI.SubjectKeyId = nil
	if got := findCerts([]*x509.Certificate{noSKI}, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0}); len(got) != 0 {
		t.Errorf("an empty SubjectKeyIdentifier matched %d certificates", len(got))
	}
}

// D-10: bytes after the ContentInfo, or after the SignedData inside it, are refused.
func TestTrailingDataRefused(t *testing.T) {
	key := mustEd25519(t)
	cert, roots := selfSigned(t, key)
	sig, err := Sign([]byte("x"), cert, key, SignOptions{})
	if err != nil {
		t.Fatal(err)
	}
	var ci contentInfo
	if _, err := asn1.Unmarshal(sig, &ci); err != nil {
		t.Fatal(err)
	}
	ci.Content = asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true,
		Bytes: append(bytes.Clone(ci.Content.Bytes), 0x05, 0x00)}
	for name, s := range map[string][]byte{
		"after ContentInfo": append(bytes.Clone(sig), 0x05, 0x00),
		"after SignedData":  mustMarshal(ci),
	} {
		if _, err := Verify([]byte("x"), s, roots, time.Now()); err == nil || errors.Is(err, ErrVerify) {
			t.Errorf("trailing data %s: err = %v, want a refusal that is not ErrVerify", name, err)
		}
	}
}

// D-11: contentType, messageDigest and signingTime appear once each, with one value.
func TestSignedAttributesOnceEach(t *testing.T) {
	key := mustEd25519(t)
	cert, roots := selfSigned(t, key)
	content := []byte("x")
	sig, err := Sign(content, cert, key, SignOptions{})
	if err != nil {
		t.Fatal(err)
	}
	base := contentAttrs(crypto.SHA512, content)
	st := attribute{Type: oidSigningTime, Values: setOf(mustMarshal(time.Now().UTC().Truncate(time.Second)))}
	if _, err := Verify(content, signedWith(t, sig, key, append(slices.Clone(base), st), nil), roots, time.Now()); err != nil {
		t.Fatalf("well-formed attributes: %v", err)
	}
	md := mustMarshal(digest(crypto.SHA512, content))
	for name, attrs := range map[string][]attribute{
		"messageDigest twice":           append(slices.Clone(base), base[1]),
		"contentType twice":             append(slices.Clone(base), base[0]),
		"signingTime twice":             append(slices.Clone(base), st, st),
		"messageDigest with two values": {base[0], {Type: oidMessageDigest, Values: setOf(slices.Concat(md, md))}},
	} {
		if _, err := Verify(content, signedWith(t, sig, key, attrs, nil), roots, time.Now()); !errors.Is(err, ErrVerify) {
			t.Errorf("%s: err = %v, want ErrVerify", name, err)
		}
	}
}

// D-14: only id-data is signed content; another encapsulated type, even with a matching contentType
// attribute and a valid signature, is refused.
func TestOnlyIDData(t *testing.T) {
	key := mustEd25519(t)
	cert, roots := selfSigned(t, key)
	content := []byte("x")
	sig, err := Sign(content, cert, key, SignOptions{})
	if err != nil {
		t.Fatal(err)
	}
	tstInfo := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}
	attrs := []attribute{
		{Type: oidContentType, Values: setOf(mustMarshal(tstInfo))},
		{Type: oidMessageDigest, Values: setOf(mustMarshal(digest(crypto.SHA512, content)))},
	}
	other := signedWith(t, sig, key, attrs, func(sd *signedData, _ *signerInfo) { sd.EncapContentInfo.EContentType = tstInfo })
	if _, err := Verify(content, other, roots, time.Now()); err == nil || errors.Is(err, ErrVerify) {
		t.Errorf("id-ct-TSTInfo content: err = %v, want a refusal that is not ErrVerify", err)
	}
}

// D-9: Sign's signatureAlgorithm is the one RFC 3370, RFC 5753 and RFC 8419 name, matching what
// OpenSSL writes: rsaEncryption with NULL parameters, ecdsa-with-SHA* and id-Ed25519 without.
func TestSignatureAlgorithmEncoding(t *testing.T) {
	null := []byte{0x05, 0x00}
	want := map[string]map[crypto.Hash]struct {
		oid    asn1.ObjectIdentifier
		params []byte
	}{
		"rsa":     {crypto.SHA256: {oidRSAEncryption, null}, crypto.SHA384: {oidRSAEncryption, null}, crypto.SHA512: {oidRSAEncryption, null}},
		"ecdsa":   {crypto.SHA256: {oidECDSAWithSHA256, nil}, crypto.SHA384: {oidECDSAWithSHA384, nil}, crypto.SHA512: {oidECDSAWithSHA512, nil}},
		"ed25519": {crypto.SHA512: {oidEd25519, nil}},
	}
	for name, key := range allKeys(t) {
		cert, roots := selfSigned(t, key)
		for h, w := range want[name] {
			sig, err := Sign([]byte("x"), cert, key, SignOptions{Hash: h})
			if err != nil {
				t.Fatal(err)
			}
			_, si, err := parseFirstSigner(sig)
			if err != nil {
				t.Fatal(err)
			}
			if got := si.SignatureAlgorithm; !got.Algorithm.Equal(w.oid) || !bytes.Equal(got.Parameters.FullBytes, w.params) {
				t.Errorf("%s/%v: signatureAlgorithm %v %x, want %v %x", name, h, got.Algorithm, got.Parameters.FullBytes, w.oid, w.params)
			}
			if _, err := Verify([]byte("x"), sig, roots, time.Now()); err != nil {
				t.Errorf("%s/%v: %v", name, h, err)
			}
		}
	}
}
