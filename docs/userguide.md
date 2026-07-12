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

## Supplying the trust roots

`Verify` takes a `*x509.CertPool` you assemble — `cms` never fetches or implies a
root. **The bootstrap trust always originates out of band: `cms` moves the trust
root, it does not remove the need for one.** How that root reaches the binary is
the crux of the whole trust model; pick one of three delivery models.

**1. Embed in the binary** (recommended for a fixed, known issuer). `go:embed` the
PEM and parse it. The root's authenticity is then exactly the binary's — no
separate distribution or verification step, and it works offline / air-gapped.
Rotate by shipping a new binary when the root changes (rare — e.g. the ICANN Root
CA is valid to 2029); embed the *next* root alongside the current one for a
seamless rollover. (This is how `aegis` ships the ICANN Root CA for the DNSSEC
anchor bootstrap.)

```go
//go:embed roots/icannbundle.pem
var rootPEM []byte

pool := x509.NewCertPool()
pool.AppendCertsFromPEM(rootPEM)
signers, err := cms.Verify(content, sig, pool, time.Now())
```

**2. Install from a trusted channel** (config path / signed package). Place the
PEM at a known path via your provisioning system — configuration management, a
**signed** OS package, or an immutable image — and load it at startup. Trust then
comes from the channel that placed it: make the path root-owned and read-only, and
never let the artifact and its signed content arrive over the *same*
unauthenticated channel. Good when the root varies per deployment or tenant.

```go
pem, err := os.ReadFile("/etc/netstar/roots.pem") // placed by provisioning
pool := x509.NewCertPool()
pool.AppendCertsFromPEM(pem)
```

**3. OS trust store** (`x509.SystemCertPool()`). Use the system pool when the
signer chains to a publicly-trusted CA already in the OS store — e.g. a vendor
signing with a WebPKI / code-signing chain. Broadest and zero-config, but you
inherit the OS store's entire trust set, so constrain it: pass restrictive
`KeyUsages` via `VerifyWith` and/or check the returned signer's name/EKU when the
issuer should be a specific one. **Not** appropriate for a private or self-issued
signer — it won't be in the store.

```go
pool, _ := x509.SystemCertPool()
signers, err := cms.VerifyWith(content, sig, x509.VerifyOptions{
    Roots: pool, CurrentTime: time.Now(),
    KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}, // constrain the store
})
```

Whichever model, enforce certificate validity at a trustworthy (NTP-synced) clock
(next note).

## Operational notes

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
