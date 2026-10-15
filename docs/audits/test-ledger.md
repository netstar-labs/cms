# Test ledger — `cms` (L2)

Statement coverage `go test -coverprofile`: **80.3% → 87.7%** (the `-tags interop` run reports the same 87.7%, since the interop test drives
the same paths from a second angle). Classification: `unit | harness | integration | fuzz | bench | n/a`; status: covered / partial / uncovered.

## Per function (after)

| Symbol | Before | After | Class | Notes |
|---|---|---|---|---|
| `Verify` | 100% | 100% | unit, fuzz, bench | |
| `VerifyWith` | 87.1% | 88.2% | unit, fuzz | the wrap-with-`ErrVerify` branch is covered by `TestErrVerifyContract` |
| `VerifyAsSigned` | 76.5% | 82.4% | unit, fuzz | uncovered: parse-error returns |
| `SigningTime` | 66.7% | 83.3% | unit, fuzz | |
| `parseFirstSigner` | 63.6% | 72.7% | unit | uncovered: malformed-input returns (fuzz reaches them) |
| `signingTimeFromAttrs` | 83.3% | 83.3% | unit | uncovered: malformed attribute |
| `verifySigner` | 77.3% | 88.9% | unit, fuzz | no-signedAttrs path now covered |
| `verifySignature` | 81.8% | 90.9% | unit | unsupported-key default unreachable with stdlib certs |
| `parseSignedAttrs` | 68.8% | 68.8% | unit | uncovered: attribute value parse errors, absent-attribute errors (partial) |
| `parseCertificates`, `findCert`, `hashForOID` | 83.3 / 50 / 60% | 83.3 / 83.3 / 80% | unit | SKI form and unknown SKI now covered |
| `Sign` | 85.7% | 91.9% | unit | error branches covered by `TestSignRejectsBadInput` |
| `marshalAttributeSet`, `mustMarshal`, `oidForHash` | 90.9 / 75 / 60% | 90.9 / 75 / 100% | unit | `mustMarshal`'s panic arm is unreachable from valid inputs |
| `verifyState.digest`, `.chain` (new) | — | 100% | unit | |
| the rest (`reencodeAsSet`, `implicitTag`, `digestAlgSet`, `sidFromCert`, `sigOIDForKey`, `digest`, `mustSetOf`, `tlvHeader`) | 100% | 100% | unit | |

## Tests added

| Test | Guards | Fails before the fix? |
|---|---|---|
| `TestSignRejectsBadInput` | `Sign` errors, not panics; refuses a mismatched certificate | yes: 5 panics + 3 silent accepts |
| `TestManySignersBoundedWork` | repeated SignerInfos cost ≈ one | yes: 347 ms vs 6.7 ms |
| `TestErrVerifyContract` | `errors.Is(err, ErrVerify)` for every failure kind × key type; cause still visible | yes: 10 failures |
| `TestDigestAlgorithmsIsASet` | ec4f686 wire form for RSA, ECDSA, Ed25519, independent of the builder | yes: tag 0x04 for all three |
| `TestHashMatrix` | RSA/ECDSA with SHA-256/384/512; refusals; Ed25519 SHA-512 only | coverage |
| `TestNoSignedAttributes` | pins the current attribute-less behaviour **pending decision D-1** (flip it if D-1 is accepted) | characterization |
| `TestSubjectKeyIdentifierSID`, `TestMultipleSigners` | SKI-form signer; one-good-signer-is-enough; none-valid is `ErrVerify` | coverage |
| `TestConcurrentSignVerify` | no shared mutable state | `-race` |
| `FuzzVerify` | no panic/hang; a mutated signature never verifies different content | fuzz |
| `BenchmarkVerify`, `BenchmarkSign`, `BenchmarkParseHostile` | baselines | bench |
| `TestOpenSSLInterop` (`-tags interop`) | both directions per key type | fixed (F-1) |

## Still uncovered

`parseSignedAttrs` attribute-value error returns; `signingTimeFromAttrs` malformed attribute; `VerifyAsSigned`/`parseFirstSigner` parse-error returns
(reached by fuzz, not asserted); `mustMarshal`'s panic arm; the unsupported-public-key default in `verifySignature`.
