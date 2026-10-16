# cms — detached CMS/PKCS#7 SignedData, standard library only

`cms` verifies and produces **detached CMS SignedData** signatures (RFC 5652)
using only the Go standard library — no CGo, no third-party crypto. It is a
deliberately small, auditable subset: detached SignedData over externally
supplied content, with signed attributes.

That is exactly what is needed to verify vendor-signed artifacts and to produce
netstar-labs's own — signed feed/RPZ bundles, data resources, archives,
software bundles and patches, and update manifests. The canonical
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
// roots must not be nil.
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

// VerifyAsSigned is Verify with each signer's chain checked at that signer's own
// signed signingTime (or its NotBefore when absent) instead of the wall clock, so a
// write-once resource stays verifiable after a short signing leaf has expired.
// Digest/chain/signature checks are otherwise identical to Verify.
func VerifyAsSigned(content, sig []byte, roots *x509.CertPool) ([]*x509.Certificate, error)

// SigningTime returns the first signer's signed signingTime attribute (ok=false if
// absent). The value is trustworthy only once Verify/VerifyAsSigned has succeeded
// over the sig. It reads with Verify's rules, so it errors on a signature Verify
// could not read and on signed attributes Verify refuses.
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
| `sign_input_test.go` | `Sign` returns errors, not panics, and refuses a certificate that is not the key's |
| `signers_test.go` | repeated SignerInfos cost one hash and one chain build; a repeated bad signer stays rejected (work is counted, not timed) |
| `errverify_test.go` | the `ErrVerify` contract across key types, and what is not `ErrVerify` |
| `coverage_test.go` | hash matrix, the `digestAlgorithms` SET form, SKI signer ids, several signers |
| `hardening_test.go` | one test per audit fix D-1 to D-14: required signed attributes, signer and chain caps, per-signer `VerifyAsSigned` time, nil roots, key usage, trailing data, repeated attributes, id-data only, `signatureAlgorithm` encoding |
| `fuzz_test.go` | `FuzzVerify` and the `Sign` / `Verify` / hostile-input benchmarks |
| `concurrent_test.go` | `Sign` and `Verify` from many goroutines over one root pool, clean under `-race` |

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

`Sign` writes the `signatureAlgorithm` these RFCs name, as `openssl cms -sign` does:
`rsaEncryption` with NULL parameters (RFC 3370 §3.2), `ecdsa-with-SHA256/384/512` (RFC 5753
§2.1.1) and `id-Ed25519` (RFC 8419 §3.1). Releases up to v0.1.2 wrote `rsaEncryption` without
parameters and `id-ecPublicKey`; `Verify` never reads the field (the certificate's key type
decides), so such signatures still verify here.

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
  `SigningTime`; a mutated signature must not verify different content) ran 13.6M
  executions in 60 s before the audit fixes and 10.5M in 45 s after them, with no panic,
  hang or such verification.
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
- Signed attributes are required (RFC 5652 lets id-data omit them; `Verify` does not):
  `messageDigest` must equal `H(content)`, `contentType` must be `id-data`, each of these and
  `signingTime` may appear once with one value, and the signature is verified over the DER
  `SET OF` attributes (RFC 5652 §5.4). Without this rule, stripping the attributes from a
  genuine signature left a valid signature over the attribute bytes themselves.
- Only `id-data` content is accepted, as the encapsulated type and as the `contentType`
  attribute.
- Treat **any non-nil error** from `Verify` as "not authentic". `errors.Is(err, ErrVerify)`
  additionally says that the signature parsed and had signers and that verification ran and
  failed (the wrapped cause says which check, and with several signers it is the last signer's):
  a digest or signature mismatch, an untrusted or expired certificate, a signer identifier that
  names no bundle certificate, a certificate not allowed to sign, an unsupported digest
  algorithm, a refused SignerInfo (no signed attributes, or a malformed, repeated or
  multi-valued one), or the per-call cap on chain builds. It is not set for input that could not
  be read as a signature this package accepts: a ContentInfo, SignedData or SignerInfo that does
  not parse, trailing data, `ErrNotSignedData`, `ErrNoSigners`, more than eight SignerInfos,
  content that is not `id-data`, a malformed certificate in the bundle, more than 32
  certificates in it or an RSA key over 8192 bits, or a nil root pool.
- `VerifyAsSigned` checks each signer's chain at that signer's own `signingTime` (or its
  certificate's `NotBefore`), read only after that signer's signature has verified, so no other
  SignerInfo can move it. A zero time is refused. The time is still the signer's claim, not a
  time authority's: a key holder, including one whose key has expired or been compromised, can
  sign new content claiming any time inside the certificate's validity window. Pair it with a
  revocation or known-good-floor policy.
- The root pool must be **non-nil**: a nil pool is refused, where `x509.VerifyOptions` would
  read it as the operating system's trust store. To trust the system store, pass
  `x509.SystemCertPool()`.
- A signer certificate that lists key usages must list `digitalSignature` or
  `contentCommitment`. One without the extension may sign, as RFC 5280 allows, and so may one
  whose extension sets no bits (RFC 5280 forbids that encoding; Go cannot tell it from absence). The extended key usage defaults to `ExtKeyUsageAny`, so any certificate
  under your roots with a suitable key usage can sign; constrain it through `VerifyWith` (for
  example `ExtKeyUsageCodeSigning`) when the roots issue other kinds.
- `Verify` returns each verified signing key once (the first certificate it verified under),
  however many SignerInfos or certificates name it, so an M-of-N policy can count the result.
- **Work per signature is capped.** The bundle may hold at most 32 certificates, and none with
  an RSA key over 8192 bits (`crypto/tls`'s limit, for the same reason: RSA verification cost
  grows with the square of the modulus). At most eight SignerInfos, refused before they are
  decoded; at most four bundle certificates tried per signer identifier; at most eight distinct
  chain builds per call; the content is hashed once per digest algorithm. Measured worst cases
  on an Apple M2 Pro: a full bundle of decoy intermediates with 8192-bit RSA keys and eight
  signers, 0.28 s (with P-521 decoys, 0.23 s); eight signers × four 8192-bit candidates, 66 ms.
  Before the bundle limits, oversized RSA keys made a 920 KB signature cost 71 s. A deadline is
  still sensible for untrusted input at volume. Memory is linear in the signature's size: a
  signed-attribute set of many tiny unknown attributes allocates about 13 bytes per input byte.
- A legitimate signer whose identifier matches five or more certificates in one bundle (for
  example, repeated renewals under one issuer and serial) is checked against only the first
  four.
- Input is parsed as DER-ish, not validated as canonical DER: indefinite-length BER and
  trailing data after the `ContentInfo` or the `SignedData` are rejected, but a `.p7s` file can
  still be altered without breaking its verification: extra trailing elements inside the
  `ContentInfo`, `SignedData` and `SignerInfo` sequences, a `SET OF` in non-DER order, unsigned
  fields (versions, `digestAlgorithms`, the `signatureAlgorithm` OID) and the tag form of the
  signed-attributes field are tolerated. Do not use the signature's bytes as an identity.

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
