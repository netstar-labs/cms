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
- has a signature that verifies over the signed attributes (or, when it carries none, over
  `content` directly),
- whose `messageDigest` signed attribute, when present, equals `H(content)`,
- and whose certificate chains to `roots` and is valid at the supplied time.

When the signature parsed, carried signers and none verified, the error satisfies
`errors.Is(err, cms.ErrVerify)` and wraps the specific cause. Unreadable input (a parse error,
`ErrNotSignedData`, `ErrNoSigners`, a malformed certificate in the bundle) does not match it;
any non-nil error still means the signature is not authentic. Pass a non-nil `roots` pool: a
nil one means the operating system's trust store.

## Verify a write-once resource (as signed)

For a resource written once and pulled long after signing — possibly after a short
signing leaf has expired — verify **as of the signing instant** rather than now:

```go
signers, err := cms.VerifyAsSigned(content, sig, roots)
```

`VerifyAsSigned` anchors certificate-chain validity to the signed `signingTime`
attribute (or, when absent, the signer certificate's `NotBefore`) instead of the
wall clock. A detached signature over immutable bytes is a timeless fact, so an
otherwise-valid resource does not become unverifiable merely because its leaf has
since expired. Digest, chain, and signature checks are otherwise identical to
`Verify`; use plain `Verify(…, now)` when you *want* expiry to bite (fresh-pull
resources). Note what it does not prove: the `signingTime` is asserted by the signer, so
a holder of an expired or compromised key can mint a new signature claiming a time in the
certificate's validity window. Pair it with a revocation or known-good-floor policy. Do not use it on a signature that an untrusted party could have
altered: the anchor is the *first* SignerInfo's signingTime, read before any signer is verified,
so a keyless attacker can prepend a junk SignerInfo with a backdated time and make an expired
signer verify (the result lists only the verified signer). Use `Verify` at the current time
there; see README Security notes and audit-findings D-3. Read the signed time with:

```go
t, ok, err := cms.SigningTime(sig) // ok=false when the attribute is absent
```

The value is trustworthy only after `Verify`/`VerifyAsSigned` succeeds over the
same signature.

## Produce a detached signature

```go
sig, err := cms.Sign(content, signerCert, signerKey, cms.SignOptions{
    Hash:        crypto.SHA256,   // default when zero; Ed25519 uses SHA-512 and refuses others
    SigningTime: time.Now(),      // omitted when zero
})
_ = os.WriteFile("content.p7s", sig, 0o644)
```

`signerKey` is any `crypto.Signer` (RSA, ECDSA or Ed25519). The signer certificate is
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
| Signature | RSA PKCS#1 v1.5, ECDSA, Ed25519 (RFC 8419) |
| Digest | SHA-256, SHA-384, SHA-512; SHA-512 only with Ed25519 |
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
seamless rollover. (This is the model for shipping the ICANN Root CA for the
DNSSEC anchor bootstrap.)

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
