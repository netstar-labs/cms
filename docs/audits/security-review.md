# Security review — `cms` @ feat/ed25519 (A3)

Report-only review by an independent reviewer, with PoCs run against a copy; findings were then put to separate skeptics.
Findings, verdicts and dispositions live in [audit-findings.md](audit-findings.md); this file is the model and the per-boundary
answers. Labels: **V** verified (run), **R** reported (source or RFC text read), **I** inferred.

**Verdict: no CRITICAL.** No way was found to make `Verify` succeed without a signature by a key whose certificate chains to the
supplied roots (V: exhaustive single-byte mutation sweep of a 662-byte signature, 2.4M-iteration mutation fuzz, 20–24M-execution
`FuzzVerify` runs, and the targeted attacks below). The Ed25519 delta is sound.

## 0. Model

**Assets:** the trust decision ("these bytes came from a signer chaining to a root *I* supplied"); the roots pool; the signing key
and the integrity of what `Sign` signs; verifier CPU and memory.
**Adversaries:** (A) a remote party supplying a forged or malformed `.p7s` and possibly the content; (B) the holder of a legitimately
issued leaf key that has expired or been compromised; (C) supply chain (out of scope — stdlib only, zero dependencies); (D) a caller
passing bad input.

```
ATTACKER-CONTROLLED                    LIBRARY                            CONSUMER-TRUSTED
 sig (.p7s) bytes ─B1─► asn1.Unmarshal(ContentInfo → SignedData)
   (certs, SignerInfos,                 parseCertificates                  roots *x509.CertPool ─B3─┐
    signedAttrs, digestAlg,             per SignerInfo: findCert(SID)                              │
    sigAlg, unsigned fields)              hash(content) with h from the sig                        ▼
 content bytes ─B2─►                      messageDigest / contentType check ─► cert.Verify(opts) ◄─ opts, now
   (also attacker-supplied)               verifySignature: key type from the CERT, not sigAlg    B4/B5
 Sign: content, SigningTime, cert, crypto.Signer ─B6/B7─► Sign
```

B1/B2 input; B3 the trust anchor (the caller's); B4 `VerifyOptions` passed through to x509; B5 the clock, including
`VerifyAsSigned`'s signed-time anchor; B6/B7 the `Sign` inputs.

## 1. Per-boundary answers

As found by the review, before the owner-approved fixes; function names are as they were then (`findCert` is now `findCerts`).
§5 gives the answers after the fixes.

| Boundary | Question | Answer |
|---|---|---|
| B1 tampering | Is the signature gated before anything is trusted? | **Yes.** `verifySignature` and `cert.Verify` both short-circuit (`cms.go` `verifySigner`). Signed bytes are the received `FullBytes` with only the tag byte swapped (V). |
| B1 algorithm confusion | Can the attacker pick a weaker algorithm? | **No.** The key type comes from the certificate; the digest algorithm is attacker-chosen among SHA-256/384/512 but the messageDigest value and length must match, and RSA's DigestInfo OID is hash-bound. Ed25519 requires SHA-512 and that check precedes `ed25519.Verify` (V, `TestEd25519RejectsOtherHashes`). |
| B1 signer selection | Can SKI/serial selection pick the wrong cert? | Selection can be **wrong** (D-8) but never yields a forgery: the chosen certificate must hold the signing key and chain to the roots (V). |
| B1/B2 DoS | Unbounded work from untrusted input? | **Yes, and `len(sig)` does not bound it (D-2).** F-3 removed the per-signer content hash and the chain rebuild for *repeated* signers. Residual: (b) Ed25519 without signed attributes, 1.08 s per 100 copies at 16 MiB; (c) each *distinct* signer certificate gets its own chain build, ~110 ms with 100 decoy intermediates and no content (20 signers: 2.24 s for 59 KB; reproduced twice, linear). A certificate flood with one signer is cheap (8 ms per MB), which is why it was first marked clean; that was wrong once signers multiply. |
| B1 parsing | Panics, hangs, huge allocations? | None found: 20–24M `FuzzVerify` executions, a 2.4M-iteration mutation fuzz, a claimed 4 GiB length rejected in 7.5 µs, indefinite lengths rejected (V). |
| B1 malleability | Can the signature file be altered and still verify? | **Yes, trivially (D-10):** trailing bytes, non-DER `SET OF` order and a couple of dozen positions of unsigned fields. Not a forgery. |
| B1 attribute handling | Strip or reuse signed attributes? | **D-1.** An attribute-less SignerInfo is accepted; a with-attributes signature can be turned into a valid signature over the attribute bytes (V, three key types). Impact needs a consumer that accepts attacker-shaped bytes as content, or a key that also signs raw data elsewhere. |
| B3 trust anchor | What if the pool is wrong? | A **nil** pool means the OS trust store (D-4; mechanism V, wrong accept not reproduced). An empty pool fails closed (V). |
| B4 policy | Who may sign under a root? | Anyone with *any* certificate under it: default `ExtKeyUsageAny`, key-usage bit unchecked (D-5, V). |
| B5 clock | Can the time anchor be abused? | **D-3 (HIGH):** a keyless attacker re-anchors an expired signer by prepending a junk SignerInfo, and the result hides it (V, three reproductions). **D-3b:** a key holder can claim any time in the validity window (V, inherent). The code comment and README now warn against using `VerifyAsSigned` on tamperable input; the fix is awaiting a decision. |
| B6/B7 Sign | Panics, mismatched cert/key, key lifecycle? | Fixed (F-2). `Sign` uses `crypto/rand`; no secret is logged or written; the interop test writes keys to `t.TempDir()` mode 0600 (R). |
| Repudiation / disclosure | Logging, error oracles? | The library logs nothing. Error precedence returns the last signer's error; nothing in it is secret. |

## 2. Findings (see audit-findings.md for evidence)

| Rank | ID | One line | Status |
|---|---|---|---|
| HIGH | D-2 (b, c) | CPU DoS from a small signature: Ed25519 without attributes; distinct signer certificates × decoy intermediates | **fixed**: F-3, D-1, caps of 8 SignerInfos / 4 candidates / 8 chain builds |
| HIGH | D-3 / D-3b | `VerifyAsSigned` anchor from an unverified first signer; key-holder backdating | D-3 **fixed** (per-signer anchor after verification); D-3b documented, inherent |
| MED | D-1 | attribute-less signers accepted; attribute-strip | **fixed**: signed attributes required |
| MED | D-4 | nil roots → OS trust store | **fixed**: refused |
| MED | D-5 | any cert under the root can sign (`ExtKeyUsageAny`) | **fixed** for the key-usage bit; EKU default kept, documented |
| MED | D-6 | duplicate signer certificates returned | **fixed** |
| LOW | D-7…D-12, D-14 | non-X.509 cert choices; SKI selection; sigAlg OIDs; trailing data; duplicate attributes; typed-nil; contentType not required to be id-data | **fixed** except D-12 (recorded limit) and D-10's `SET OF` order / unsigned fields |

**Scope was confirmed by the owner on 2026-10-16** and the recommended option for each of D-1 to D-11 and D-14 was applied
(`51b5b9d`, `2e81a74`, `0aff25a`); see §5 for the boundary answers after the fixes and the
[disposition table](audit-findings.md#dispositions) for each test.

## 3. Checked and clean

Verification is gated; the Ed25519 path is PureEdDSA over the signed bytes with SHA-512 required; `Sign` passes `crypto.Hash(0)`
for PureEdDSA; the signed-attribute set is DER-sorted and retagged `[0] IMPLICIT`; no mutable package state (`-race` clean, including
`TestConcurrentSignVerify`); no dependencies; no home-rolled primitives.

## 4. Caveats

Ed25519 interop was run on OpenSSL 3.5.0 and 3.0.15 only. D-4's wrong accept is unreproduced. The CPU figures at 1 MB of signature
are extrapolated from measured linear scaling.

## 5. After the owner-approved fixes (`2e81a74`, `0aff25a`)

| Boundary | Answer now |
|---|---|
| B1/B2 DoS | Bounded: at most 8 SignerInfos (decoded one at a time, so a 40,000-signer signature is refused without allocating it, V `TestSignerLimit`), 4 candidate certificates per signer, 8 distinct chain builds per call (V `TestChainBudget`). With the audit's ~110 ms per hostile chain build, the chain-build worst case is about 0.9 s (I, from that measurement). Attribute-less Ed25519 is gone with D-1. |
| B1 malleability | Trailing data refused (V). Non-DER `SET OF` order and unsigned fields still tolerated: not a forgery. |
| B1 attribute handling | Signed attributes required; contentType, messageDigest, signingTime once each with one value; id-data only (V). |
| B1 signer selection | Every matching certificate, up to 4, is tried; an empty SKI matches nothing (V). |
| B3 trust anchor | A nil pool is refused (V). |
| B4 policy | A certificate whose key usage is present must allow signing (V); the EKU default stays `ExtKeyUsageAny` (documented). |
| B5 clock | `VerifyAsSigned` anchors each signer at its own signed time, read after its signature verifies; a prepended SignerInfo cannot move it; zero time refused (V `TestVerifyAsSignedAnchorPerSigner`). D-3b unchanged and inherent. |
