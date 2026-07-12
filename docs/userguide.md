# User guide

## Install / import

```go
import "github.com/netstar-labs/cms"
```

Standard library only; no build tags or CGo.

## Verify a detached signature

```go
content, _ := os.ReadFile("root-anchors.xml")
sig, _ := os.ReadFile("root-anchors.p7s")   // detached CMS SignedData (DER)

roots := x509.NewCertPool()
roots.AddCert(icannRootCert)                // trusted out of band

signers, err := cms.Verify(content, sig, roots, time.Now())
if err != nil {
    // signature invalid, chain untrusted, or expired — do not trust content
}
// signers[0] is the verified signer certificate
```

`Verify` returns an error unless at least one signer:
- has a signature that verifies over `content`,
- whose `messageDigest` signed attribute equals `H(content)`,
- and whose certificate chains to `roots` and is valid at the supplied time.

## Produce a detached signature

```go
sig, err := cms.Sign(content, signerCert, signerKey, cms.SignOptions{
    Hash:        crypto.SHA256,   // default when zero
    SigningTime: time.Now(),      // omitted when zero
})
_ = os.WriteFile("content.p7s", sig, 0o644)
```

`signerKey` is any `crypto.Signer` (RSA or ECDSA). The signer certificate is
embedded so a verifier can build the chain.

## Formats

- **Signature:** DER-encoded CMS `ContentInfo` wrapping detached `SignedData`
  (`.p7s` convention). PEM is not handled — decode PEM (`encoding/pem`) to DER
  first if needed.
- **Content:** raw bytes, supplied out of band (detached).
- **Roots:** a `*x509.CertPool` the caller assembles from a trusted source.

## Supported algorithms

| Kind | Supported |
|---|---|
| Signature | RSA PKCS#1 v1.5, ECDSA |
| Digest | SHA-256, SHA-384, SHA-512 |
| Signer id | IssuerAndSerialNumber, SubjectKeyIdentifier |

## Operational notes

- **Trusted roots are your responsibility.** Ship the expected root certificate
  with the binary (or pin it); do not fetch it over the same channel as the
  signed content.
- **Revocation** is not checked, and `x509.VerifyOptions` has no revocation
  facility. If you need it, use `VerifyWith` to drive the chain build, then check
  the returned signer certificate against a CRL (`x509.ParseRevocationList`) or an
  OCSP responder and reject if revoked. See the README §Revocation and
  `example/revoke`.
- **Clock.** `Verify` enforces certificate validity at the `now` you pass — use a
  trustworthy (NTP-synced) clock; a wrong clock can accept an expired chain or
  reject a valid one.
- **Size.** Content and signature are held in memory; intended for small signed
  artifacts (anchors, manifests, feed headers), not multi-gigabyte payloads.
