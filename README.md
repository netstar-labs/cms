# cms — detached CMS/PKCS#7 SignedData, standard library only

`cms` verifies and produces **detached CMS SignedData** signatures (RFC 5652)
using only the Go standard library — no CGo, no third-party crypto. It is a
deliberately small, auditable subset: detached SignedData over externally
supplied content, with signed attributes.

That is exactly what is needed to verify vendor-signed artifacts and to produce
netstar-labs's own — signed feed/RPZ bundles, `refs` resources, `scribe`
archives, `core` bundles and patches, and update manifests. The canonical
example is authenticating IANA's `root-anchors.xml` against its detached
`.p7s` signature (the RFC 5011 / RFC 9718 DNSSEC trust-anchor bootstrap): a
common data-signing shape that the Go standard library could not otherwise
verify.

```
content ─┐
         ├─▶  Verify(content, sig, roots, now) ─▶  []*x509.Certificate (verified signers)
sig ─────┘        │ parse ContentInfo→SignedData · resolve signer cert · check
                  │ messageDigest == H(content) · verify sig over signed attrs · chain to roots
Sign(content, cert, key, opts) ─▶ detached SignedData DER
```

## Documentation

**Start here**
- [Introduction](docs/introduction.md) — what `cms` is, in one page
- [Executive summary](docs/executive-summary.md) — what it is and why, leadership-readable

**Deep dive**
- [Architecture](docs/architecture.md) — the CMS subset, verify/sign flow, trade-offs

**Operations**
- [User guide](docs/userguide.md) — API, wire/file formats, day-2 operations

**Examples**
- [example/README](example/README.md) — verify a detached signature, then enforce revocation

## API

```go
// Verify checks that sig (DER, detached CMS SignedData) authenticates content:
// some signer must verify over the content, chain to roots, and be valid at now.
func Verify(content, sig []byte, roots *x509.CertPool, now time.Time) ([]*x509.Certificate, error)

// VerifyWith is Verify with caller-controlled chain verification. Certificates
// carried in the SignedData are added as intermediates when opts.Intermediates
// is nil. Use it to set KeyUsages/Intermediates and to drive a revocation policy
// on the returned signer (see Revocation below).
func VerifyWith(content, sig []byte, opts x509.VerifyOptions) ([]*x509.Certificate, error)

// Sign produces a detached CMS SignedData over content, signed by cert/key with
// signed attributes (contentType, messageDigest, optional signingTime).
func Sign(content []byte, cert *x509.Certificate, key crypto.Signer, opts SignOptions) ([]byte, error)
```

## Layout

| Path | Purpose |
|---|---|
| `cms.go` | The library: `Verify`, `VerifyWith`, `Sign`, the RFC 5652 ASN.1 shapes, OIDs, DER helpers |
| `cms_test.go` | Self-signed Sign→Verify round-trips (RSA + ECDSA), tamper / wrong-root / expiry negatives |

## Scope

**In:** detached SignedData verification and signing; signed attributes
(`contentType`, `messageDigest`, `signingTime`); RSA (PKCS#1 v1.5) and ECDSA
signatures; SHA-256/384/512; issuer-and-serial and subject-key-identifier signer
resolution; X.509 chain verification to a caller-supplied root pool.

**Out (by design):** encryption, enveloped / authenticated-enveloped data,
timestamping tokens, attribute certificates, CRL/OCSP revocation checking (the
caller's `x509.VerifyOptions` governs the chain). Bring these in only with a
clear need and a matching test corpus.

## Standards

RFC 5652 (CMS), RFC 5758 (SHA-2 signature algorithms), RFC 3370 (CMS algorithms),
RFC 5280 (X.509 path validation, via `crypto/x509`). Consumers: RFC 9718 / RFC
5011 (IANA root-anchors.xml distribution and trust-anchor updates).

## Testing & interoperability

Beyond the unit tests (`go test ./...` — self round-trip Sign→Verify for RSA and
ECDSA, plus tamper / wrong-root / expiry / garbage negatives), the verifier is
**smoke-tested against a reference implementation**: detached CMS SignedData
produced by OpenSSL/LibreSSL (`openssl cms -sign -binary … -outform DER`) is
verified by this package, confirming spec interoperability rather than only
self-consistency.

Verified so far:

- **OpenSSL/LibreSSL RSA** detached signatures, SHA-256 and SHA-384 → accepted;
  tampered content and an untrusting root pool → rejected.
- **Self round-trip** RSA and ECDSA (P-256), SHA-256/384/512 → accepted.
- **End to end**: signing and re-parsing a real KSK-2017 `root-anchors.xml`
  through `Verify` yields the published trust-anchor digest (the DNSSEC bootstrap
  use case, exercised by a consumer).

(OpenSSL *ECDSA* signing was not exercised here only because the local LibreSSL
`req`/`ecparam` CLI hung when generating the EC test cert — an environment quirk,
not a `cms` limitation; ECDSA verification is covered by the self round-trip.)

## Security notes

- Bootstrap trust still originates out-of-band: the root pool passed to `Verify`
  must arrive through a trusted channel (shipped with the binary or the OS store).
  CMS moves the trust root; it does not remove it.
- Signed attributes are required for the verified path: `messageDigest` is checked
  against `H(content)`, the `contentType` attribute must match the encapsulated
  content type, and the signature is verified over the DER `SET OF` attributes
  (RFC 5652 §5.4), not over the content directly.

### Revocation

`Verify` does **not** check certificate revocation — and note that Go's
`x509.VerifyOptions` has no revocation facility either (it governs roots,
intermediates, key usages, and the validity clock, not CRL/OCSP). Revocation is
therefore a step the caller performs **on the returned signer certificate**: use
`VerifyWith` to control the chain build, then reject the result if the signer is
revoked. See [example/revoke](example/revoke/) for a runnable end-to-end demo.

```go
signers, err := cms.VerifyWith(content, sig, x509.VerifyOptions{
    Roots:       roots,
    CurrentTime: now,
    // KeyUsages / Intermediates as your policy requires; the bundle's own
    // certificates are added as intermediates automatically.
})
if err != nil { /* not authentic */ }

// Revocation is a separate, caller-owned check on the verified signer.
crl, _ := x509.ParseRevocationList(crlDER)
if crl.CheckSignatureFrom(caCert) == nil { // trust the CRL first
    for _, s := range signers {
        for _, e := range crl.RevokedCertificateEntries {
            if e.SerialNumber.Cmp(s.SerialNumber) == 0 {
                // signer revoked — reject
            }
        }
    }
}
```

(For OCSP instead of CRLs, query the responder for the returned signer certificate
and reject on a `Revoked` status; OCSP lives in `golang.org/x/crypto/ocsp`, so
adopt it only if you accept that `x/` dependency.)

## License

Copyright (C) 2026 zxdev. Licensed under the GNU General Public License v3.0 or
later — see [LICENSE](LICENSE).
