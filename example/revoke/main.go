// Command revoke demonstrates revocation checking on top of cms.Verify.
//
// Go's x509.VerifyOptions has no revocation facility, so revocation is a step
// the caller performs on the verified signer certificate: parse a CRL (or query
// OCSP), confirm the CRL's authenticity against its issuer, then reject the
// signature if the signer's serial is listed. This program builds a CA, a signer
// leaf, and a CRL entirely in-process, signs content, and runs both the
// not-revoked and revoked cases.
//
//	go run ./example/revoke
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/netstar-labs/cms"
)

func main() {
	now := time.Now()

	// --- a CA and a signer leaf it issues -----------------------------------
	caKey := mustRSA()
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "netstar-labs demo CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caCert := selfSign(caTmpl, caKey)

	leafKey := mustRSA()
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1001),
		Subject:      pkix.Name{CommonName: "release signer"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	leafCert := issue(leafTmpl, leafKey.Public(), caCert, caKey)

	// --- sign some content with the leaf ------------------------------------
	content := []byte("core-bundle-2026-07-12.tgz manifest\n")
	sig, err := cms.Sign(content, leafCert, leafKey, cms.SignOptions{SigningTime: now})
	check(err, "sign")

	// Roots trust the CA; the bundle carries the leaf, added as an intermediate
	// automatically by VerifyWith.
	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	opts := x509.VerifyOptions{Roots: roots, CurrentTime: now}

	// --- case 1: signer NOT revoked -----------------------------------------
	emptyCRL := makeCRL(caCert, caKey, nil, now) // no revoked serials
	fmt.Printf("not-revoked: %s\n", verifyAndCheckCRL(content, sig, opts, emptyCRL, caCert))

	// --- case 2: signer revoked ---------------------------------------------
	revokedCRL := makeCRL(caCert, caKey, []*big.Int{leafCert.SerialNumber}, now)
	result := verifyAndCheckCRL(content, sig, opts, revokedCRL, caCert)
	fmt.Printf("revoked:     %s\n", result)
	if result == "accepted" {
		os.Exit(1) // a revoked signer must be rejected
	}
}

// verifyAndCheckCRL runs the two-step pattern: authenticate the CMS signature,
// then enforce revocation on the verified signer against a trusted CRL.
func verifyAndCheckCRL(content, sig []byte, opts x509.VerifyOptions, crl *x509.RevocationList, crlIssuer *x509.Certificate) string {
	signers, err := cms.VerifyWith(content, sig, opts)
	if err != nil {
		return "rejected (signature: " + err.Error() + ")"
	}
	// The CRL must itself be authentic before we trust its contents.
	if err := crl.CheckSignatureFrom(crlIssuer); err != nil {
		return "rejected (untrusted CRL)"
	}
	for _, signer := range signers {
		for _, e := range crl.RevokedCertificateEntries {
			if e.SerialNumber.Cmp(signer.SerialNumber) == 0 {
				return "rejected (signer certificate revoked)"
			}
		}
	}
	return "accepted"
}

func makeCRL(issuer *x509.Certificate, key *rsa.PrivateKey, revoked []*big.Int, now time.Time) *x509.RevocationList {
	tmpl := &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: now.Add(-time.Minute),
		NextUpdate: now.Add(time.Hour),
	}
	for _, sn := range revoked {
		tmpl.RevokedCertificateEntries = append(tmpl.RevokedCertificateEntries,
			x509.RevocationListEntry{SerialNumber: sn, RevocationTime: now})
	}
	der, err := x509.CreateRevocationList(rand.Reader, tmpl, issuer, key)
	check(err, "create CRL")
	crl, err := x509.ParseRevocationList(der)
	check(err, "parse CRL")
	return crl
}

// ---- tiny cert helpers ----------------------------------------------------

func mustRSA() *rsa.PrivateKey {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	check(err, "rsa")
	return k
}

func selfSign(tmpl *x509.Certificate, key *rsa.PrivateKey) *x509.Certificate {
	return issue(tmpl, key.Public(), tmpl, key)
}

func issue(tmpl *x509.Certificate, pub any, parent *x509.Certificate, parentKey *rsa.PrivateKey) *x509.Certificate {
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, parentKey)
	check(err, "create cert")
	c, err := x509.ParseCertificate(der)
	check(err, "parse cert")
	return c
}

func check(err error, what string) {
	if err != nil {
		fmt.Fprintln(os.Stderr, what+":", err)
		os.Exit(2)
	}
}
