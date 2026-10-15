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
         └─▶  VerifyAsSigned(content, sig, roots) ─▶ same, anchored to the signed signingTime
                  │ (write-once resources stay verifiable after a short leaf expires)
Sign(content, cert, key, opts) ─▶ detached SignedData DER  (opts.SigningTime binds the instant)
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
// signed attributes (contentType, messageDigest, optional signingTime). An
// Ed25519 key signs by RFC 8419: SHA-512 digest, PureEdDSA over the attributes.
func Sign(content []byte, cert *x509.Certificate, key crypto.Signer, opts SignOptions) ([]byte, error)

// VerifyAsSigned is Verify anchored to the signed signingTime (or the signer's
// NotBefore when absent) instead of the wall clock, so a write-once resource stays
// verifiable after a short signing leaf has expired. Digest/chain/signature checks
// are otherwise identical to Verify.
func VerifyAsSigned(content, sig []byte, roots *x509.CertPool) ([]*x509.Certificate, error)

// SigningTime returns the signed signingTime attribute (ok=false if absent). The
// value is trustworthy only once Verify/VerifyAsSigned has succeeded over the sig.
func SigningTime(sig []byte) (t time.Time, ok bool, err error)
```

## Layout

| Path | Purpose |
|---|---|
| `cms.go` | The library: `Verify`, `VerifyWith`, `VerifyAsSigned`, `SigningTime`, `Sign`, the RFC 5652 ASN.1 shapes, OIDs, DER helpers |
| `cms_test.go` | Self-signed Sign→Verify round-trips (RSA + ECDSA), tamper / wrong-root / expiry negatives |
| `ed25519_test.go` | Ed25519 round-trip, the RFC 8419 encoding, refusal of any digest but SHA-512, tampered signature |
| `interop_test.go` | `-tags interop`: `openssl cms` verifies `Sign`'s output and `Verify` accepts `openssl cms -sign`'s, per key type |
| `verifyassigned_test.go` | `VerifyAsSigned` over an expired-since leaf; `NotBefore` fallback; `SigningTime` round-trip |

## Scope

**In:** detached SignedData verification and signing; signed attributes
(`contentType`, `messageDigest`, `signingTime`); verify-as-signed (anchor chain
validity to the signing instant for write-once resources); RSA (PKCS#1 v1.5),
ECDSA and Ed25519 (RFC 8419) signatures; SHA-256/384/512; issuer-and-serial and subject-key-identifier
signer resolution; X.509 chain verification to a caller-supplied root pool.

**Out (by design):** encryption, enveloped / authenticated-enveloped data,
timestamping tokens, attribute certificates, CRL/OCSP revocation checking (the
caller's `x509.VerifyOptions` governs the chain). Bring these in only with a
clear need and a matching test corpus.

## Standards

RFC 5652 (CMS), RFC 5758 (SHA-2 identifiers), RFC 3370 (CMS algorithms),
RFC 8419 (EdDSA in CMS) with RFC 8410 (Ed25519 identifiers),
RFC 5280 (X.509 path validation, via `crypto/x509`). Consumers: RFC 9718 / RFC
5011 (IANA root-anchors.xml distribution and trust-anchor updates).

Known deviation: for RSA and ECDSA, `Sign` writes `rsaEncryption` without the NULL
parameters RFC 3370 §3.2 requires, and `id-ecPublicKey` where RFC 5753 §2.1.1 calls for
`ecdsa-with-SHA256/384/512` as the `signatureAlgorithm`. OpenSSL 3.5.0, OpenSSL 3.0.15 and
LibreSSL 3.3.6 accept the output anyway, and `Verify` never reads that field (the
certificate's key type decides). The Ed25519 identifiers follow RFC 8419 §3.1. See
`docs/audits/audit-findings.md` (C3).

## Testing & interoperability

`go test ./...` runs the self round-trips (RSA, ECDSA, Ed25519), the RFC 8419
encoding checks and the tamper / wrong-root / expiry / garbage negatives.
`go test -tags interop -run OpenSSLInterop .` checks both directions against the
`openssl` on `PATH`, for each key type: `openssl cms -verify` must accept what
`Sign` writes and reject it over tampered content, and `Verify` must accept what
`openssl cms -sign -binary -outform DER` writes (`-md sha512` for Ed25519, `-md sha256`
otherwise). The Ed25519 case needs an `openssl` whose `cms` command supports EdDSA; it
skips, rather than fails, when this one cannot sign an Ed25519 CMS message.

Verified so far (each run, with `-race` where it applies):

- **OpenSSL 3.5.0, both directions, RSA, ECDSA (P-256) and Ed25519**: the interop test
  passes, including rejection of tampered content on both sides.
- **OpenSSL 3.0.15**: RSA and ECDSA pass; Ed25519 skips (its own `cms -sign` fails on an
  Ed25519 key, so there is nothing to compare). **LibreSSL 3.3.6**: RSA and
  ECDSA pass; Ed25519 skips (it cannot load an Ed25519 key). Not tested: OpenSSL 3.1 to 3.4,
  and verifiers other than OpenSSL/LibreSSL.
- **Self round-trip** RSA and ECDSA (P-256) with SHA-256, SHA-384 and SHA-512, and
  Ed25519 with SHA-512 (`TestHashMatrix`); SHA-1, MD5 and other hashes are refused.
- **Ed25519 output, independently decoded** (a manual check; the script is not in this
  repo): a separate DER decoder with the pyca Ed25519 verifier accepts `Sign`'s output —
  SHA-512 digest algorithms with parameters absent, id-Ed25519, and a valid PureEdDSA
  signature over the signed attributes — and rejects tampered content and a flipped bit.
- **Fuzzing**: `FuzzVerify` (arbitrary bytes into `Verify`, `VerifyAsSigned` and
  `SigningTime`; a mutated signature must never verify different content) ran 13.6M
  executions in 60 s with no panic, hang or forgery.
- **End to end**: signing and re-parsing a real KSK-2017 `root-anchors.xml` through
  `Verify` yields the published trust-anchor digest (reported by a downstream consumer's
  tests; not reproduced in this repo).

LibreSSL 3.3.6's `openssl cms -sign` signs ECDSA with SHA-1 when `-md` is not given, and
`Verify` refuses SHA-1, so pass `-md sha256`. Other OpenSSL/LibreSSL releases were not tested.

Up to and including v0.1.2 (v0.1.0, v0.1.1 and v0.1.2 all carry it), `Sign` encoded
`SignedData.digestAlgorithms` as an OCTET STRING around the SET, so every RSA and ECDSA
signature it wrote was rejected by OpenSSL 3.5.0, OpenSSL 3.0.15 and LibreSSL 3.3.6
(`Field=digestAlgorithms … wrong tag`, tested for each); `Verify` does not read that field,
which is why the round-trips missed it. Re-sign anything produced with v0.1.0–v0.1.2 that
must verify outside this package — every key type and hash was affected.

## Security notes

- Bootstrap trust still originates out-of-band: the root pool passed to `Verify`
  must arrive through a trusted channel (shipped with the binary or the OS store).
  CMS moves the trust root; it does not remove it.
- Signed attributes are checked when present: `messageDigest` must equal `H(content)`,
  the `contentType` attribute must match the encapsulated content type, and the signature
  is verified over the DER `SET OF` attributes (RFC 5652 §5.4). A SignerInfo with **no**
  signed attributes is also accepted — RFC 5652 §5.3 allows it for id-data — and its
  signature is then verified directly over the content (Ed25519) or its digest (RSA and
  ECDSA), with neither attribute checked. A signature made with attributes can therefore
  be turned into a valid no-attributes signature over the attribute bytes themselves, so
  do not accept arbitrary bytes as content from an untrusted party.
- `Verify` returns `ErrVerify` (possibly wrapping the specific cause, with `errors.Is`)
  whenever signers were present and none verified; treat any non-nil error as "not
  authentic". With several signers the cause wrapped is the last signer's.
- Pass a **non-nil** roots pool. A nil `x509.VerifyOptions.Roots` means the operating
  system's trust store, so a caller whose pool failed to load would silently trust every
  public CA. The default key usage is `ExtKeyUsageAny` and the `digitalSignature` key-usage
  bit is not checked: any certificate under your roots can sign. Constrain it through
  `VerifyWith` (for example `ExtKeyUsageCodeSigning`) when the roots issue other kinds.
- `Verify` returns one entry per verified SignerInfo, so a signature that repeats one
  SignerInfo returns the same certificate repeatedly; count distinct certificates, not
  `len(signers)`.
- A hostile signature can still cost CPU. The content is hashed once per digest algorithm
  and each certificate chain is built once per call, but signatures are checked per
  SignerInfo, and an Ed25519 signer without signed attributes verifies over the whole
  content each time (about 11 ms per 16 MiB). Bound `len(sig)` before verifying untrusted
  input.
- Only DER is accepted (not indefinite-length BER), and trailing bytes after the
  `ContentInfo` are ignored.

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

Licensed under the Apache License, Version 2.0 — see [LICENSE](LICENSE).
