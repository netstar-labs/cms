# Test ledger — `cms` (L2)

Statement coverage `go test -coverprofile`: **80.3% → 88.6%** after the first fix pass, **91.6%** after the owner-approved fixes
(`0aff25a`). Classification: `unit | harness | integration | fuzz | bench | n/a`; status: covered / partial / uncovered.

## Per function (at `0aff25a`)

| Symbol | Coverage | Class | Notes |
|---|---|---|---|
| `Verify`, `VerifyWith`, `verifyWith`, `VerifyAsSigned` | 100% | unit, fuzz, bench | |
| `SigningTime` | 77.8% | unit, fuzz | uncovered: parse-error returns |
| `parseSignedData` | 82.1% | unit, fuzz | uncovered: a `signerInfos` that is not a SET, a malformed SignerInfo (fuzz reaches them) |
| `parseFirstSigner` | 100% | unit | |
| `verifySigner` / `verifyAs` | 90.0% / 100% | unit, fuzz | uncovered: unsupported digest algorithm |
| `verifySignature` | 90.9% | unit | unsupported-key default unreachable with stdlib certificates |
| `parseSignedAttrs` | 81.5% | unit | uncovered: attribute value parse errors, absent contentType |
| `parseCertificates`, `findCerts`, `hashForOID` | 93.3 / 93.8 / 80% | unit | |
| `verifyState.digest`, `.chain` | 100% | unit | the chain budget by `TestChainBudget` |
| `Sign`, `marshalAttributeSet`, `mustMarshal` | 91.9 / 87.5 / 75% | unit | `mustMarshal`'s panic arm is unreachable from valid inputs |
| `sigAlgFor`, `setOf`, `oidForHash`, `reencodeAsSet`, `implicitTag`, `digestAlgSet`, `sidFromCert`, `digest` | 100% | unit | |

## Tests added

| Test | Guards | Fails before the fix? |
|---|---|---|
| `TestSignRejectsBadInput` | `Sign` errors, not panics; refuses a mismatched certificate | yes: 5 panics + 3 silent accepts |
| `TestManySignersBoundedWork` | one content hash and one chain build however many SignerInfos repeat a signer (counted, not timed) | mutation-checked: disabled chain cache, disabled digest cache. (The first, timing-based version failed 7 of 20 runs under load and was replaced.) |
| `TestRepeatedBadSignerRejected` | a repeated untrusted or expired signer stays rejected: cached chain failures are replayed | mutation-checked: a cache hit that returns success |
| `TestErrVerifyContract` | `errors.Is(err, ErrVerify)` for every verification failure kind × key type; cause still visible; **not** set for unreadable input (garbage, a malformed bundle certificate) | yes: 10 failures |
| `TestDigestAlgorithmsIsASet` | ec4f686 wire form for RSA, ECDSA, Ed25519, independent of the builder | yes: tag 0x04 for all three |
| `TestHashMatrix` | RSA/ECDSA with SHA-256/384/512; refusals; Ed25519 SHA-512 only | coverage |
| `TestNoSignedAttributes` | pinned the attribute-less behaviour pending D-1; **removed** when D-1 was fixed (`51b5b9d`) | characterization |
| `hardening_test.go` (13 tests) | one per owner-approved fix, D-1 to D-14: see the [disposition table](audit-findings.md#dispositions) | yes: each red against `9be6a7c`; D-9 by mutation |
| `TestSubjectKeyIdentifierSID`, `TestMultipleSigners` | SKI-form signer; one-good-signer-is-enough in either order with one hash per algorithm and one chain per certificate; none-valid is `ErrVerify` | mutation-checked: digest cache keyed by a constant |
| `TestConcurrentSignVerify` | no shared mutable state | `-race` |
| `FuzzVerify` | no panic/hang; a mutated signature never verifies different content | fuzz |
| `BenchmarkVerify`, `BenchmarkSign`, `BenchmarkParseHostile` | baselines | bench |
| `TestOpenSSLInterop` (`-tags interop`) | both directions per key type | fixed (F-1) |

## Still uncovered

`parseSignedAttrs` attribute-value error returns and the absent-contentType return; `parseSignedData`'s non-SET `signerInfos` and
malformed-SignerInfo returns, and `SigningTime`'s parse-error returns (reached by fuzz, not asserted); `mustMarshal`'s panic arm;
the unsupported-public-key default in `verifySignature`; the unsupported-digest return in `verifySigner`.
