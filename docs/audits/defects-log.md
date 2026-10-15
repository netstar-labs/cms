# Defects log — found, root-caused, fixed, regression-tested

| ID | Defect | Root cause | Fix | Regression test | Commit |
|---|---|---|---|---|---|
| F-2 | `Sign` panicked (year outside 0–9999, nil cert/key, cert without DER) and accepted a certificate that is not the key's | `mustMarshal` on caller-supplied time; no input validation; no key/cert comparison | validate inputs; `asn1.Marshal` with an error for the time; compare `cert.PublicKey` with `key.Public()` | `TestSignRejectsBadInput` (red: 5 panics + 3 silent accepts) | `4914672` |
| F-3 | CPU amplification: content hashed and chain rebuilt per SignerInfo | the signer loop recomputed two signer-independent results | `verifyState`: digest per algorithm, chain per certificate pointer | `TestManySignersBoundedWork` (red: 347 ms vs 6.7 ms); differential equivalence over 6,044 cases | `62ed738` |
| F-4 | `errors.Is(err, ErrVerify)` true only for ECDSA/Ed25519 mismatches | `VerifyWith` returned the last signer's own error | wrap the cause with `ErrVerify` when signers were present and none verified | `TestErrVerifyContract` (red: 10 failures) | `6e08dc6` |
| F-1 | Ed25519 interop test failed on OpenSSL 3.0.x/3.5.0 and claimed "3 or later" | the test omitted `-md sha512` and its skip guard checked only key loading | `-md sha512`; openssl signs first as the probe; skip unless this openssl can sign Ed25519 CMS | re-run on 3.5.0 (pass), 3.0.15 (skip), LibreSSL (skip) | `15c0c9c` |
| F-6 | the ec4f686 regression was guarded only for Ed25519, via the builder it tests | the check compared against `digestAlgSet` | structural check of the wire tag for every key type | `TestDigestAlgorithmsIsASet` (red with the bug reintroduced) | `15c0c9c` |
| F-5 | ten documentation claims that did not match the code | see audit-findings DD-1…DD-10 | rewritten | n/a (checked by running each) | `29afdb4` |

No production code was weakened to make a test pass. Pre-existing defects that need the owner's decision are in
[audit-findings.md](audit-findings.md) (D-1…D-13) and are not fixed.
