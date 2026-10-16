# Test ledger — `cms` (L2)

Statement coverage `go test -coverprofile`: **80.3% → 88.6%** after the first fix pass, **92.8%** after the owner-approved fixes
and the skeptic follow-ups (91.6% at `2e81a74`, 91.7% at `0aff25a`). Classification: `unit | harness | integration | fuzz | bench | n/a`;
status: covered / partial / uncovered.

## Per function (after the skeptic follow-ups)

| Symbol | Coverage | Class | Notes |
|---|---|---|---|
| `Verify`, `VerifyWith`, `verifyWith`, `VerifyAsSigned`, `parseFirstSigner`, `verifyAs` | 100% | unit, fuzz, bench | |
| `SigningTime` | 77.8% | unit, fuzz | uncovered: no-attributes and attribute-error returns |
| `parseSignedData` | 89.3% | unit, fuzz | uncovered: SignedData, non-SET `signerInfos` and SignerInfo parse errors (fuzz reaches them) |
| `verifySigner` | 95.0% | unit, fuzz | uncovered: unsupported digest algorithm |
| `verifySignature` | 90.9% | unit | unsupported-key default unreachable with stdlib certificates |
| `parseSignedAttrs` | 82.1% | unit | uncovered: attribute and value parse errors, absent messageDigest or contentType; the unknown-attribute skip |
| `parseCertificates`, `findCerts`, `hashForOID` | 93.3 / 93.8 / 80% | unit | uncovered: a bundle element that does not parse, a malformed issuerAndSerial, an unknown digest OID |
| `verifyState.digest`, `.chain` | 100% | unit | the chain budget by `TestChainBudget` |
| `Sign`, `marshalAttributeSet`, `mustMarshal` | 91.9 / 87.5 / 75% | unit | uncovered: errors from `key.Sign` and from marshalling, `mustMarshal`'s panic arm (unreachable from valid inputs) |
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
| `hardening_test.go` (14 tests) | one per owner-approved fix, D-1 to D-14, plus `TestCandidateLimit`: see the [disposition table](audit-findings.md#dispositions) | yes: 13 red against `9be6a7c`; D-9, `TestCandidateLimit` and the D-14 attribute case by mutation |
| `TestSentinelErrors` | `ErrNotSignedData` and `ErrNoSigners` are returned and matchable | coverage (they had no test) |
| `TestSubjectKeyIdentifierSID`, `TestMultipleSigners` | SKI-form signer; one-good-signer-is-enough in either order with one hash per algorithm and one chain per certificate; none-valid is `ErrVerify` | mutation-checked: digest cache keyed by a constant |
| `TestConcurrentSignVerify` | no shared mutable state | `-race` |
| `FuzzVerify` | no panic/hang; a mutated signature never verifies different content | fuzz |
| `BenchmarkVerify`, `BenchmarkSign`, `BenchmarkParseHostile` | baselines | bench |
| `TestOpenSSLInterop` (`-tags interop`) | both directions per key type | fixed (F-1) |

## Still uncovered

From the coverage profile (every count-0 block): `SigningTime`'s no-attributes and attribute-error returns; `parseSignedData`'s
SignedData, non-SET `signerInfos` and SignerInfo parse errors; `verifySigner`'s unsupported digest; `verifySignature`'s
unsupported-key default; `parseSignedAttrs`'s attribute and value parse errors, absent messageDigest/contentType and unknown-attribute
skip; `parseCertificates`' element parse error; `findCerts`' malformed issuerAndSerial; `hashForOID`'s unknown OID; `Sign`'s `key.Sign`,
marshal and attribute-set errors; `mustMarshal`'s panic arm. The parse errors are reached by `FuzzVerify` but not asserted.
