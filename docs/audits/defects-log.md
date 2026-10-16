# Defects log — found, root-caused, fixed, regression-tested

| ID | Defect | Root cause | Fix | Regression test | Commit |
|---|---|---|---|---|---|
| F-2 | `Sign` panicked (year outside 0–9999, nil cert/key, cert without DER) and accepted a certificate that is not the key's | `mustMarshal` on caller-supplied time; no input validation; no key/cert comparison | validate inputs; `asn1.Marshal` with an error for the time; compare `cert.PublicKey` with `key.Public()` (declared: refuses by-value RSA/ECDSA `Public()` and certificates without a `PublicKey`) | `TestSignRejectsBadInput` (red: 5 panics + 3 silent accepts) | `4914672` |
| F-3 | CPU amplification: content hashed and chain rebuilt per SignerInfo | the signer loop recomputed two signer-independent results | `verifyState`: digest per algorithm, chain per certificate pointer | `TestManySignersBoundedWork` (originally a timing ratio, red: 347 ms vs 6.7 ms; replaced by work counts after it proved flaky and blind to chain-cache bugs, `16862de`, with `TestRepeatedBadSignerRejected`); differential equivalence over 6,044 cases | `62ed738`, `16862de` |
| F-4 | `errors.Is(err, ErrVerify)` true only for ECDSA/Ed25519 mismatches | `VerifyWith` returned the last signer's own error | wrap the cause with `ErrVerify` when signers were parsed and none verified (not for unreadable input; the commit subject overstates this) | `TestErrVerifyContract` (red: 10 failures) | `6e08dc6` |
| F-1 | Ed25519 interop test failed on OpenSSL 3.0.x/3.5.0 and claimed "3 or later" | the test omitted `-md sha512` and its skip guard checked only key loading | `-md sha512`; openssl signs first as the probe; skip unless this openssl can sign Ed25519 CMS | re-run on 3.5.0 (pass), 3.0.15 (skip), LibreSSL (skip) | `15c0c9c` |
| F-6 | the ec4f686 regression was guarded only for Ed25519, via the builder it tests | the check compared against `digestAlgSet` | structural check of the wire tag for every key type | `TestDigestAlgorithmsIsASet` (red with the bug reintroduced) | `15c0c9c` |
| F-5 | ten documentation claims that did not match the code | see audit-findings DD-1…DD-10 | rewritten | n/a (checked by running each) | `29afdb4` |

| S1, D1 | hand-written SET header (the code that let ec4f686 through); two copies of the SignedData parse | `tlvHeader` built tags and lengths by hand | `setOf` builds a `RawValue` from parts for `encoding/asn1`; one `parseSignedData` | `Sign` output byte-identical over 36 fixed RSA/Ed25519 cases; full suite unchanged | `9be6a7c` |
| D-1…D-14 | the pre-existing `Verify` acceptance defects in [audit-findings.md](audit-findings.md), approved for fixing by the owner on 2026-10-16 | see the findings | see the [disposition table](audit-findings.md#dispositions) | one test each in `hardening_test.go`, every one red against `9be6a7c` | `51b5b9d`, `0aff25a` |
| D-9 | `Sign` wrote `id-ecPublicKey` and parameterless `rsaEncryption` | identifier chosen from the key alone | `sigAlgFor`: `ecdsa-with-SHA*`, `rsaEncryption` + NULL | `TestSignatureAlgorithmEncoding` (mutation-checked: 6 of 6 RSA/ECDSA cases fail on the old encoding) | `2e81a74` |

No production code was weakened to make a test pass. Two tests changed because the behaviour they pinned was fixed:
`TestNoSignedAttributes` (pinned D-1, replaced by `TestNoSignedAttributesRejected`) and the signer-count tests, whose 16 and 64
SignerInfos now exceed the cap of 8. D-3b, D-12 and D-13 remain recorded limits.
