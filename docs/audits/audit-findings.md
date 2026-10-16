# Audit findings — `feat/ed25519` (ec4f686, 97914b9)

Scope: the whole library (`cms.go`, tests, docs, examples) with the two unpushed commits as the priority.
Method: the A1 torture chamber — four report-only auditors (simplify + dedup, correctness + RFC conformance,
doc drift, and an A3 security review), then **independent skeptics told to refute each finding** (default
"refuted" when unsure), then fixes with regression tests, then a re-validation gate. Findings are tagged
**CONFIRMED** (a skeptic reproduced it by running code), **PARTLY** (reproduced, with a correction), or
**PLAUSIBLE** (survives argument; not skeptic-reproduced). Dispositions: **FIXED**, **DECISION** (changes what
`Verify` accepts or the bytes `Sign` writes, so it needs the owner's call — A1 §3, A3 §5), **DOC**, **DEFERRED**.

Baseline before any change: `go build`, `go vet`, `gofmt`, `staticcheck 2026.2.2`, `deadcode -test` and
`go test -race` all clean; coverage 80.3%; no fuzz targets, no benchmarks.

## Summary

| | |
|---|---|
| Verdict on the delta | The Ed25519 signer and verifier are **sound**: Go's output verifies under OpenSSL 3.5.0 and OpenSSL 3.5.0's `-md sha512` output verifies under Go, both directions, with tamper negatives. The digestAlgorithms fix is **correct**: OpenSSL 3.5.0, OpenSSL 3.0.15 and LibreSSL 3.3.6 each reject the old encoding and accept the new. |
| Defects in the delta | One: the new interop test was wrong (F-1). No defect in the Ed25519 production code. |
| Fixed in this pass | F-1 to F-6 (code, tests, docs). the commits on top of 97914b9, from 4914672 on; the last two correct the earlier ones after sign-off review. |
| Owner decisions | D-1 to D-11 and D-14, all pre-existing behaviour. **Approved by the owner on 2026-10-16 and applied** in `51b5b9d` (Verify) and `2e81a74` (D-9, Sign), with S1 and D1 in `9be6a7c`; see the disposition table. D-3b, D-12 and D-13 remain recorded limits. |
| No CRITICAL | No way was found to make `Verify` succeed without a signature by a key chaining to the supplied roots. |

## Fixed in this pass

| ID | Finding | Verdict | Where | Fix |
|---|---|---|---|---|
| **F-1** | The Ed25519 interop test ran `openssl cms -sign` without `-md`: on OpenSSL 3.5.0 it fails (`no default digest`); on 3.0.15 it fails instead of skipping; its header "needs OpenSSL 3 or later" was wrong. **In delta.** | CONFIRMED (skeptic ran 3.5.0, 3.0.15, LibreSSL) | `interop_test.go` | `-md sha512`; openssl signs first as the probe; skip unless this openssl can sign Ed25519 CMS. Re-run on all three builds: 3.5.0 passes all three key types, 3.0.15 and LibreSSL skip Ed25519. |
| **F-2** | `Sign` panicked on caller input (`SigningTime` outside years 0–9999, nil cert, nil key, cert without DER) and accepted a certificate that is not the key's, returning a signature that cannot verify. Ed25519 key + non-Ed25519 cert is **in delta**. | CONFIRMED (PARTLY on wording: the Ed25519-key/ECDSA-cert output carries a valid Ed25519 signature, it just does not match the embedded certificate). Typed-nil keys still panic (unfixed, see D-12). | `cms.go` `Sign` | Errors, not panics; public-key equality check. `TestSignRejectsBadInput` (failed with 5 panics + 3 silent accepts before). **Declared deviation:** the check is `cert.PublicKey.Equal(key.Public())`, so a Signer whose `Public()` returns an RSA/ECDSA key *by value*, and a hand-built `Certificate` with no `PublicKey`, are now refused although they signed before (found by a sign-off skeptic; now in `Sign`'s doc comment). Bytes for accepted inputs are unchanged. |
| **F-3** | CPU amplification: `Verify` hashed the whole content and rebuilt the chain once **per SignerInfo**. 1,000 copies of a ~220-byte SignerInfo over 16 MiB took ~6.6 s; 1,600 valid copies took 27 s; linear in n. | CONFIRMED (measured by two auditors and a skeptic) | `cms.go` `verifySigner` | `verifyState`: hash once per algorithm, verify each *distinct* certificate once. Before the fix 64 repeated signers over 8 MiB took 347 ms against 6.7 ms for one; a skeptic measured the same approach at 1,000 copies: 6.6 s → 64 ms. The first guard was a timing ratio; a sign-off skeptic showed it flakes under `-race` and load (7 of 20 runs under 3× CPU oversubscription, 8 of 30 under `-race`) and does not notice a disabled chain cache or a cache that ignores a stored failure. It was replaced by counts of the work actually done (`TestManySignersBoundedWork`, `TestRepeatedBadSignerRejected`, `TestMultipleSigners`), each mutation-checked; 20 of 20 pass under `-race` with 30 CPU spinners. Old vs new identical on 6,044 mutated/duplicated/reordered/mixed cases (accept/reject, certs, error text modulo the `ErrVerify` prefix); a sign-off skeptic's larger differential (~320,000 cases) found 0 disagreements. **Residual: D-2b and D-2c.** |
| **F-4** | `ErrVerify` doc was false: `errors.Is(err, ErrVerify)` was true only for ECDSA/Ed25519 signature mismatches; false for tampered content, RSA failures, chain failures, and order-dependent with several signers. | CONFIRMED (two skeptics, two auditors) | `cms.go` | Wrap the cause with `ErrVerify` when signers were present, parsed, and none verified; bare `ErrVerify` unchanged. `TestErrVerifyContract`. **Scope, as corrected by a sign-off skeptic:** it is *not* set for unreadable input — a parse error, `ErrNotSignedData`, `ErrNoSigners`, a malformed certificate in the attacker-chosen bundle, or `VerifyAsSigned` failing before verification (first signer's certificate absent, malformed signingTime). The commit subject ("every failed verification…") overstates this; the doc comment, README and the test comment now state the precise rule, and the test pins the parse-error side. |
| **F-5** | Documentation drift (below). | CONFIRMED | README, `docs/*`, `cms.go` doc comments | Corrected. |
| **F-6** | Coverage gaps: no test for any RSA/ECDSA hash other than SHA-256 (docs claimed "tested"), SKI-form signers, multi-signer, attribute-less signers; the ec4f686 regression was guarded only for Ed25519; no fuzz, no benchmarks. | CONFIRMED | tests | `TestHashMatrix`, `TestDigestAlgorithmsIsASet` (fails with the original bug for all three key types), `TestSubjectKeyIdentifierSID`, `TestMultipleSigners`, `TestNoSignedAttributes`, `FuzzVerify`, benchmarks, `TestConcurrentSignVerify`. Coverage 80.3% → 88.6%. |

### Doc drift fixed (F-5)

| ID | Claim | Verdict |
|---|---|---|
| DD-1 | `ErrVerify` doc comment | CONFIRMED → rewritten with F-4 |
| DD-2 | README: "Signed attributes are required for the verified path" — the code accepts no signedAttrs | CONFIRMED → reworded (the behaviour itself is D-1) |
| DD-3 | `introduction.md`: "signs the digest with any crypto.Signer" — Ed25519 signs the attributes; only RSA/ECDSA/Ed25519 | CONFIRMED |
| DD-4 | README v0.1.x re-sign note | PARTLY → now "v0.1.0–v0.1.2, every key type and hash", with OpenSSL 3.5.0, 3.0.15 and LibreSSL each tested |
| DD-5 | `VerifyAsSigned`: "a forged or backdated value cannot pass" | CONFIRMED → reworded in code comment, architecture, user guide |
| DD-6 | RSA/ECDSA SHA-256/384/512 "tested" | CONFIRMED → test added |
| DD-7 | "Older openssl signs ECDSA with SHA-1" | CONFIRMED over-general → LibreSSL 3.3.6 only |
| DD-8 | "Ed25519 needs OpenSSL 3 or later" / "not yet run on OpenSSL 3" | refuted by run → 3.5.0 verified, 3.0.15 cannot |
| DD-9 | `RFC 5758`/`3370` listed as followed | PARTLY → deviation stated (D-9) |
| DD-10 | commit ec4f686: "OpenSSL and LibreSSL reject…(md_algs: wrong tag)" | TRUE. `cms -verify` prints `Field=digestAlgorithms … wrong tag`, and `openssl smime -verify` and `openssl pkcs7 -print` print `Field=md_algs … wrong tag`, on all three builds (a sign-off skeptic reproduced both). An earlier pass of this audit called the quoted string wrong; it is right for the PKCS7 parsers. No change needed. |
| DD-11 | commit subject 6e08dc6 "every failed verification satisfies errors.Is(err, ErrVerify)" | OVERSTATED (see F-4). Not rewritten: unpushed history, and the doc comment is the authority. Worth rewording in the PR description. |
| DD-12 | README "Only DER is accepted" | PARTLY FALSE → reworded: indefinite-length BER is rejected, but non-DER `SET OF` order, unsigned fields and trailing bytes are tolerated. |
| DD-13 | README layout table omitted six test files | CONFIRMED → added. |
| — | `example/revoke` and `example/verify`: run, behave as documented | CLEAN |
| — | KSK-2017 end-to-end claim | unverified here (attributed to a downstream consumer); reworded as reported |
| — | pyca Ed25519 decode claim | reproduced by the auditor; script not in the repo; reworded as a manual check |

## Owner decisions (all pre-existing; none was in the delta)

Each changes what `Verify` accepts or the bytes `Sign` writes. The owner approved the recommended option for each on 2026-10-16;
the [disposition table](#dispositions) below records what was applied and the test that fails without it. The "Options ·
recommendation" column is kept as the audit wrote it.

| ID | Sev | Finding | Verdict | Options · recommendation |
|---|---|---|---|---|
| **D-1** | MED | A SignerInfo with **no signedAttrs** is accepted (RFC 5652 §5.3 allows it for id-data). A signature made *with* attributes over D can be converted, by stripping them, into a valid signature over the attribute bytes themselves, so `Verify(attrsDER, stripped)` succeeds for RSA, ECDSA and Ed25519. The README said attributes were required. | CONFIRMED (3 independent reproductions) | **Require signed attributes** (recommended: matches the README, and also closes D-2b); or an explicit opt-in field; or keep + docs (done). Requiring them rejects legitimate `-noattr` signatures from other tools. |
| **D-2** | **HIGH** | CPU denial of service from a small signature. F-3 removed the content-hash and chain-build multipliers for *repeated* signers. **Residual (D-2b):** signatures are still checked per SignerInfo, and an **Ed25519 signer with no signed attributes** verifies over the whole content each time — measured 100 copies of a 14 KB signature over 16 MiB: 1.08 s (ECDSA no-attrs collapsed to 13 ms). **(D-2c, found by a sign-off skeptic; worse per byte):** each *distinct* signer certificate gets its own chain build, and a bundle of 100 same-subject P-521 intermediates makes each cost ~110 ms with **no content at all**: 20 leaf signers → 2.24 s for a 59 KB signature (reproduced independently by a skeptic at 50 and 200 leaves and by the author at 1, 5 and 20; linear). Go's cap of 100 signature checks per build bounds *each* chain, not the total. | CONFIRMED (2 independent reproductions of D-2c) | **Cap SignerInfos / distinct signer certificates** (e.g. 16); and/or D-1. **`len(sig)` bounds neither D-2b nor D-2c**, so the earlier advice to bound it was wrong; the README now says to verify untrusted signatures in a resource-limited worker. |
| **D-3** | **HIGH** (design) | `VerifyAsSigned`: the time anchor is taken from the **first** SignerInfo before any signer is verified and applied to all. A keyless attacker prepends a junk SignerInfo with a backdated signingTime and an **expired signer verifies** (`Verify(now)` still rejects); the result lists only the verified signer, so the extra SignerInfo is invisible. "Use single-signer signatures" is not something a consumer of attacker-supplied files can do, so the code comment and the README now say plainly: **do not use `VerifyAsSigned` on a signature untrusted parties could have altered.** | CONFIRMED (three independent reproductions: `[junk, B]` → accepted; `[B, junk]` → rejected) | **Anchor per signer, after that signer's own signature verifies** (recommended; only rejects more). Also reject a zero anchor (a signingTime of year 1 silently degrades to `Verify(now)`: harmless, fails closed). |
| **D-3b** | HIGH (design) | `VerifyAsSigned`: a holder of an expired or compromised leaf key can sign new content claiming any time in the validity window, or omit signingTime (anchor = NotBefore), and it verifies forever. Inherent; the code comment already warned about revocation but the architecture doc claimed it "cannot pass". | CONFIRMED | Doc corrected. Options: a caller-supplied floor / timestamp authority, or default consumers to `Verify(now)`. |
| **D-4** | MED | `nil` roots → `x509.VerifyOptions.Roots == nil` means the **system trust store**; a caller whose pool failed to load silently trusts every public CA, under `ExtKeyUsageAny`. | PARTLY — mechanism confirmed (Go source; a real public TLS leaf passes the chain stage with a nil pool and fails with an empty one); a full wrong accept **not reproduced** (needs a publicly trusted key). | Reject `Roots == nil`. Documented now. |
| **D-5** | MED | Default `ExtKeyUsageAny`, and the `digitalSignature` key-usage bit is never checked: any certificate under the supplied root can sign, including a TLS-only or `keyEncipherment`-only leaf; `KeyUsages: CodeSigning` still ignores the bit. | CONFIRMED | Check the bit (reject `KeyUsage != 0` without digitalSignature/contentCommitment); document or change the EKU default. |
| **D-6** | MED (consumer-conditional) | One valid SignerInfo repeated n times returns the same certificate n times; an M-of-N policy counting `len(signers)` is bypassed. No in-repo caller counts. | CONFIRMED | Dedupe returned certificates by `Raw`. Documented. |
| **D-7** | LOW | A non-X.509 CertificateChoices element (`[2]`/`[3]`) in `certificates` makes `Verify` fail although the signer cert is present (RFC 5652 §10.2.2 allows them; OpenSSL 3.5.0 verifies such a bundle). A junk SEQUENCE correctly fails on both. | PARTLY (non-SEQUENCE elements are a real wrong-reject; the junk case is correct) | Skip non-SEQUENCE elements. |
| **D-8** | LOW | Signer selection by SubjectKeyIdentifier takes the **first** match: `[expired, current]` with one key/SKI is rejected, `[current, expired]` accepted; an **empty** SKI matches a certificate that has none. Not a forgery (the signature must verify under that cert's key and chain to the roots). | CONFIRMED | Try every candidate; reject an empty SKI. |
| **D-9** | LOW | `Sign`'s `signatureAlgorithm` is non-conformant: ECDSA writes `id-ecPublicKey` (RFC 5753 §2.1.1 wants `ecdsa-with-SHA256/384/512`); RSA writes `rsaEncryption` without NULL parameters (RFC 3370 §3.2 wants NULL). OpenSSL 3.5.0, 3.0.15 and LibreSSL accept it; `Verify` ignores the field. Ed25519 matches RFC 8419. | PARTLY (non-conformance confirmed against the RFC text; "other verifiers reject it" is **reported from memory, not reproduced**) | **Bytes-changing.** Recommended: fix it in this release — signatures from v0.1.0–v0.1.2 must be re-signed anyway because of ec4f686, so one re-sign covers both. |
| **D-10** | LOW | Trailing bytes after the ContentInfo and after the SignedData are ignored (signature malleability, not forgery); a `SET OF` in non-DER order is accepted. | CONFIRMED | Reject trailing data. Single-byte sweeps found a couple of dozen positions in unsigned fields (versions, digestAlgorithms, the signatureAlgorithm OID, the constructed bit) where a mutation is still accepted (27 in one 662-byte signature, 19 in another). |
| **D-11** | LOW | Duplicate or multi-valued `contentType`/`messageDigest`/`signingTime` attributes are accepted (RFC 5652 §11 requires one). | CONFIRMED by an auditor probe (not skeptic-rerun) | Reject duplicates. |
| D-2d | MED | Memory amplification: a 1.48 MB signature of 40,000 minimal SignerInfos allocated 67 MB (~48× per input byte) and took 72 ms to reject (one skeptic's measurement, not re-run by me). Same class as D-2. | REPORTED (1 measurement) | Cap SignerInfos; resource-limited worker. |
| D-14 | LOW | `Verify` never requires the `contentType` attribute, or the encapsulated content type, to be `id-data`: a signature whose signed content type is another OID (e.g. `id-ct-TSTInfo`) verifies. Found by a sign-off skeptic. | CONFIRMED (one reproduction) | Require `id-data` (or a caller-supplied expected type). |
| D-12 | LOW | A typed-nil `crypto.Signer` (e.g. `(*rsa.PrivateKey)(nil)`) still panics in `Sign`; a plain nil is now an error. | CONFIRMED | Left: checking it needs `reflect`, for a caller bug. |
| D-13 | INFO | BER indefinite-length input (`openssl cms -sign -stream`) is rejected. | CONFIRMED | By contract (the user guide says DER). No change. |

### Dispositions

Each regression test is in `hardening_test.go` unless named otherwise. "Red before" means it was run against `9be6a7c`, the commit
before the fixes, and failed for the reason in the finding; all pass on `2e81a74`.

| ID | Applied | Commit | Regression test (red before) |
|---|---|---|---|
| D-1 | signed attributes required | `51b5b9d` | `TestNoSignedAttributesRejected` (the attribute-strip signature verified, 3 key types); replaces `TestNoSignedAttributes` |
| D-2, D-2b, D-2d | at most 8 SignerInfos, decoded one at a time; at most 4 candidate certificates per signer identifier; D-1 removes the attribute-less Ed25519 path. The README's earlier advice to use a resource-limited worker is replaced by the documented caps | `51b5b9d` | `TestSignerLimit` (9 and 40,000 SignerInfos verified; allocation bound); `TestCandidateLimit` (added after skeptic review; red with the cap removed) |
| D-2c | at most 8 distinct (certificate, time) chain builds per call | `51b5b9d` | `TestChainBudget` (a 9th build ran) |
| D-3 | `VerifyAsSigned` anchors each signer at its own signed time, read after its signature verifies; zero time refused | `51b5b9d` | `TestVerifyAsSignedAnchorPerSigner` (the junk-first order verified; the zero time verified) |
| D-3b | not applicable: inherent to a signer-asserted time; documented | — | — |
| D-4 | nil root pool refused | `51b5b9d` | `TestNilRootsRefused` (all three entry points went on to the system store) |
| D-5 | key-usage bit checked (`digitalSignature` or `contentCommitment` when any key usage is listed, the audit's `KeyUsage != 0` rule, extended by SK-4 to an extension with no bits `x509` names, which is refused); `ExtKeyUsageAny` default kept and documented | `51b5b9d` | `TestSignerKeyUsage` (keyEncipherment-only and certSign-only certificates signed) |
| D-6 | each verified certificate returned once | `51b5b9d` | `TestRepeatedSignerReportedOnce` (3 copies returned 3 certificates) |
| D-7 | context-tagged CertificateChoices skipped | `51b5b9d` | `TestBundleSkipsOtherCertificateChoices` ([1]–[3] elements failed the parse) |
| D-8 | up to 4 matching certificates tried in order; empty SKI matches nothing | `51b5b9d` | `TestSignerCandidates` (expired-first rejected; empty SKI matched) |
| D-9 | `rsaEncryption` + NULL, `ecdsa-with-SHA*` | `2e81a74` | `TestSignatureAlgorithmEncoding` (mutation: old encoding fails 6 of 6 RSA/ECDSA cases); Ed25519 output byte-identical, RSA output differs only by the NULL |
| D-10 | trailing data after ContentInfo and SignedData refused; non-DER `SET OF` order and unsigned-field malleability remain (documented) | `51b5b9d` | `TestTrailingDataRefused` (both accepted) |
| D-11 | contentType, messageDigest, signingTime once each, one value each | `51b5b9d` | `TestSignedAttributesOnceEach` (4 cases accepted) |
| D-14 | id-data only, as eContentType and contentType attribute | `51b5b9d` | `TestOnlyIDData` (id-ct-TSTInfo accepted); its contentType-attribute-only case was added after skeptic review (red with that check removed) |
| D-12, D-13 | unchanged: recorded limits | — | — |

### Skeptic review of the fixes

Two independent skeptics reviewed `ea1d5fa`, one for security and one for claims and least-code, each in its own clone. **No
forgery was found** (12.5M `FuzzVerify` executions, targeted bypasses of every fix, LibreSSL interop including `-keyid`, two
signers and an intermediate chain; all 16 v0.1.2 RSA/ECDSA signatures still verify). Their findings, all verified by running code,
and what was done:

| ID | Sev | Finding | Disposition |
|---|---|---|---|
| SK-1 | **HIGH** | The DoS bound was refuted. `crypto/x509` parses RSA moduli of any size, verification cost grows with its square, and the caps did not count bundle certificates: decoy intermediates with 65536-bit keys made a 920 KB signature cost 71.5 s, and a 262144-bit leaf key cost 45 s with no chain build. The "about 0.9 s" in the README held only for P-521 decoys (measured 0.92 s). | **Fixed**: bundle certificates capped at 32 and RSA keys at 8192 bits (`crypto/tls`'s limit). Re-measured with the skeptic's harness: 920 KB case refused in 20 µs; worst case 0.28 s. `TestBundleLimits`, mutation-checked for both caps. |
| SK-2 | MED | The D-8 candidate loop multiplies signature checks by up to 4 per SignerInfo (0.71 s → 2.85 s on a 65536-bit input). | Bounded by SK-1: 8 × 4 checks of at most 8192 bits, 66 ms measured. |
| SK-3 | MED | D-6 deduplicated by certificate bytes, so one key under two certificates (a renewal) counted twice for M-of-N. | **Fixed**: one result per public key. `TestRepeatedSignerReportedOnce`, mutation-checked. |
| SK-4 | LOW | A key-usage extension with no bits, or only bit 9, parses as `KeyUsage == 0` and passed the D-5 check. | **Fixed**: the extension's presence is checked as well as the bits. `TestSignerKeyUsage`, mutation-checked. |
| SK-5 | LOW | DER malleability beyond D-10: trailing elements inside the ContentInfo, SignedData and SignerInfo sequences, a primitive retag of the signed attributes, attribute values that are not a SET, unsorted attribute SETs. Not a forgery. | Documented precisely in the README (the earlier "trailing data rejected" overstated); left, like D-10's remainder. |
| SK-6 | LOW | The `ErrVerify` contract did not list the unsupported-digest, unreadable-SID and chain-cap cases (all `ErrVerify`). | **Fixed** in the doc comment and README. |
| SK-7 | LOW | A signed-attribute set of many tiny unknown attributes allocates about 13 B per input byte (16 MB → 208 MB); the claims skeptic measured up to 17 B per byte with one-byte OIDs. Pre-existing, linear. | Documented; left. |
| SK-8 | INFO | A legitimate signer behind four same-identifier certificates in one bundle is not tried. | Documented. |
| — | INFO | LibreSSL's `cms -resign` writes the added signer without a contentType attribute, which `Verify` refuses (as v0.1.2 did). | Recorded; RFC 5652 §11.1 requires the attribute. |

**Sign-off.** A fresh reviewer signed off on the limits at `55761e8`: regressions none (the LibreSSL fixtures, fresh `openssl cms
-sign` output including `-keyid` and two signers, all 16 v0.1.2 RSA/ECDSA signatures); every limit enforced at its boundary
(context-tagged elements count toward the 32; 8192-bit RSA accepted, 8193 refused, at e = 65537 and 2^31−1); worst cases re-measured
at 0.27 s (8192-bit decoys), 0.22 s (P-521) and 46–52 ms (8 × 4 candidates), nothing within the limits above 0.3 s. The claims
skeptic signed off on the documentation at `b05d41b` after two rounds. The first security skeptic's own sign-off pass was halted
before it ran anything and is not counted.

The claims skeptic found six wrong or unpinned claims; they were fixed in `76ce398` (two unpinned checks now tested, an order loop
that tested one order twice, the coverage and allocation figures, the key-usage wording, and stale ledger text).

## Simplification and dedup (auditor A/B)

The unpushed delta needed none. Older code could shrink by ~90 lines of `cms.go` with byte-identical `Sign` output
(72 cases) and identical `Verify` accept/reject over 60,000 mutations, proven by the auditor in a scratch copy. **PLAUSIBLE**
(auditor-verified equivalence, not re-run by a skeptic). **S1 and D1 applied** in `9be6a7c`, before the security fixes and as
their own commit: `Sign` output is byte-identical over 36 fixed RSA and Ed25519 cases (every hash, with and without signingTime,
three content sizes). The rest are left: taste, and not worth the review burden on a security branch.

| ID | Change | Est. LOC | Note |
|---|---|---|---|
| S1 | Use `asn1.MarshalWithParams(…,"set")` and `RawValue{Class,Tag,Bytes}` instead of the hand-written `tlvHeader`/`marshalAttributeSet`/`mustSetOf` | −27 | **Applied** (`9be6a7c`, as `setOf`). The class of code that produced the ec4f686 bug; a `RawValue` built from parts cannot be double-wrapped. |
| S2 | `x509.ParseCertificates` for `parseCertificates` | −10 | error text changes |
| D1 | One `parseSignedData` for `VerifyWith` and `parseFirstSigner` | −3…−10 | **Applied** (`9be6a7c`); it is where the D-2, D-10 and D-14 checks now live |
| S3, S4, S6, S7 | `retag` helper; drop two redundant guards and the repeated `KeyUsages` default; `AppendCertsFromPEM` in the example | −6, −6, −2, −13 | taste |
| D2–D4, S5 | test cert helpers, `mustSign`, hash↔OID map | −38, −10, −12, −4 | taste |

Load-bearing code that looks reducible (kept): the copy in `implicitTag`/`reencodeAsSet`; `reencodeAsSet` must not re-marshal (the
signature covers the received bytes); `digest()` relies on `crypto/x509` linking SHA-2; `signedData.DigestAlgorithms` stays a `RawValue`
(typing it would reject odd-but-valid inputs: behaviour-changing).

## Refuted by the auditors (checked, not defects)

UTCTime century handling (`49→2049`, `50→1950`); a single-signer certificate flood (11 ms for 2,001 intermediates — but see D-2c: with many signers carrying
distinct certificates the cost multiplies, so this was refuted too early); the `0xA0→0x31` tag swap; `marshalAttributeSet` ordering vs X.690 §11.6; `tlvHeader` long-form lengths (the SHA-512
attribute set exceeds 127 bytes and OpenSSL 3.5.0 accepts it); an unsigned `DigestAlgorithm` downgrade (the messageDigest value and
length must match and RSA's DigestInfo OID is hash-bound); an RSA/ECDSA key treated as Ed25519 or the reverse (`verifySignature`
switches on the certificate's key); Ed25519 verified with another digest (SHA-512 is required); a panic on an unregistered hash;
huge/deep input (a claimed 4 GiB length is rejected in 7.5 µs); forgery via an empty or shared SKI (the selected certificate must
still hold the signing key and chain to the roots); data races (no mutable package state; `-race` clean).

## Not verified here

- Ed25519 CMS on OpenSSL 3.1–3.4, and on verifiers other than OpenSSL/LibreSSL.
- That a strict third-party verifier rejects D-9's `signatureAlgorithm` (reported from memory only).
- A full wrong accept for D-4.
- The KSK-2017 `root-anchors.xml` end-to-end claim (attributed to a downstream consumer).
- Fuzzing is time-bounded (60–90 s, 13–24M executions) and used an empty/own root pool, so chain-validation paths past the
  signature check had limited coverage.

## Issues to file (not created: nothing has been pushed, and filing them is the owner's call)

The D-items are fixed on this branch, so they need no issues. Still open: D-3b (a time-authority or floor option for
`VerifyAsSigned`), D-12 (typed-nil key), the remaining malleability in D-10 (non-DER `SET OF` order, unsigned fields), an umbrella
"audit cleanup sweep" (`type:chore`) for S2–S7/D2–D4, and `type:test` issues for the entries in `untestable-without-x.md`.
