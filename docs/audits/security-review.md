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

| Boundary | Question | Answer |
|---|---|---|
| B1 tampering | Is the signature gated before anything is trusted? | **Yes.** `verifySignature` and `cert.Verify` both short-circuit (`cms.go` `verifySigner`). Signed bytes are the received `FullBytes` with only the tag byte swapped (V). |
| B1 algorithm confusion | Can the attacker pick a weaker algorithm? | **No.** The key type comes from the certificate; the digest algorithm is attacker-chosen among SHA-256/384/512 but the messageDigest value and length must match, and RSA's DigestInfo OID is hash-bound. Ed25519 requires SHA-512 and that check precedes `ed25519.Verify` (V, `TestEd25519RejectsOtherHashes`). |
| B1 signer selection | Can SKI/serial selection pick the wrong cert? | Selection can be **wrong** (D-8) but never yields a forgery: the chosen certificate must hold the signing key and chain to the roots (V). |
| B1/B2 DoS | Unbounded work from untrusted input? | **Yes, bounded only by the caller (D-2).** Cost per SignerInfo is a signature check; F-3 removed the per-signer content hash and chain build. Residual: Ed25519 without signed attributes (1.08 s per 100 copies at 16 MiB). Certificate floods are cheap (8 ms per MB of certificates; Go caps chain-building signature checks) (V). |
| B1 parsing | Panics, hangs, huge allocations? | None found: 20–24M `FuzzVerify` executions, a 2.4M-iteration mutation fuzz, a claimed 4 GiB length rejected in 7.5 µs, indefinite lengths rejected (V). |
| B1 malleability | Can the signature file be altered and still verify? | **Yes, trivially (D-10):** trailing bytes and 27 positions of unsigned fields. Not a forgery. |
| B1 attribute handling | Strip or reuse signed attributes? | **D-1.** An attribute-less SignerInfo is accepted; a with-attributes signature can be turned into a valid signature over the attribute bytes (V, three key types). Impact needs a consumer that accepts attacker-shaped bytes as content, or a key that also signs raw data elsewhere. |
| B3 trust anchor | What if the pool is wrong? | A **nil** pool means the OS trust store (D-4; mechanism V, wrong accept not reproduced). An empty pool fails closed (V). |
| B4 policy | Who may sign under a root? | Anyone with *any* certificate under it: default `ExtKeyUsageAny`, key-usage bit unchecked (D-5, V). |
| B5 clock | Can the time anchor be abused? | **D-3 (HIGH):** a keyless attacker re-anchors an expired signer by prepending a junk SignerInfo (V). **D-3b:** a key holder can claim any time in the validity window (V, inherent). Documented honestly now. |
| B6/B7 Sign | Panics, mismatched cert/key, key lifecycle? | Fixed (F-2). `Sign` uses `crypto/rand`; no secret is logged or written; the interop test writes keys to `t.TempDir()` mode 0600 (R). |
| Repudiation / disclosure | Logging, error oracles? | The library logs nothing. Error precedence returns the last signer's error; nothing in it is secret. |

## 2. Findings (see audit-findings.md for evidence)

| Rank | ID | One line | Status |
|---|---|---|---|
| HIGH | D-2 | CPU DoS from a small signature | partly fixed (F-3); cap = decision |
| HIGH | D-3 / D-3b | `VerifyAsSigned` anchor from an unverified first signer; key-holder backdating | decision / documented |
| MED | D-1 | attribute-less signers accepted; attribute-strip | decision |
| MED | D-4 | nil roots → OS trust store | decision; documented |
| MED | D-5 | any cert under the root can sign (`ExtKeyUsageAny`) | decision; documented |
| MED | D-6 | duplicate signer certificates returned | decision; documented |
| LOW | D-7…D-12 | non-X.509 cert choices; SKI selection; sigAlg OIDs; trailing data; duplicate attributes; typed-nil | see ledger |

**Confirm scope before applying any of D-1 to D-11**: each narrows or widens what `Verify` accepts or changes the bytes `Sign`
writes (A3 §5). None has been applied.

## 3. Checked and clean

Verification is gated; the Ed25519 path is PureEdDSA over the signed bytes with SHA-512 required; `Sign` passes `crypto.Hash(0)`
for PureEdDSA; the signed-attribute set is DER-sorted and retagged `[0] IMPLICIT`; no mutable package state (`-race` clean, including
`TestConcurrentSignVerify`); no dependencies; no home-rolled primitives.

## 4. Caveats

Ed25519 interop was run on OpenSSL 3.5.0 and 3.0.15 only. D-4's wrong accept is unreproduced. The CPU figures at 1 MB of signature
are extrapolated from measured linear scaling.
