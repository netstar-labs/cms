# Harness inventory — `cms` (L2)

| Harness | Where | Simulates | Cannot simulate |
|---|---|---|---|
| `selfSigned`, `newCert`, `mustRSA`, `mustEd25519`, `allKeys` | `cms_test.go`, `ed25519_test.go`, `coverage_test.go` | self-signed signer certificates and trust pools for RSA, ECDSA, Ed25519 (now `testing.TB`, so fuzz and benchmarks reuse them) | a CA hierarchy beyond `TestVerifyWithIntermediateChain`'s hand-built one |
| `fixtures` | `fuzz_test.go` | a valid signature per key type, with and without signingTime, plus its roots | |
| `mutateSigner`, `withSigners` | `coverage_test.go`, `signers_test.go` | re-marshalling a SignedData with an edited or repeated SignerInfo (note: a parsed `RawValue` re-marshals from `FullBytes`) | non-DER encodings |
| `resignEd25519` | `ed25519_test.go` | a valid Ed25519 signature over chosen attributes | |
| `openssl`, `write` | `interop_test.go` (`-tags interop`) | a second implementation in both directions | needs an openssl on `PATH`; Ed25519 needs one whose `cms` supports EdDSA |
| `FuzzVerify` | `fuzz_test.go` | arbitrary bytes into the parsers | chain-validation paths with an attacker-chosen *trusted* pool (the fuzz roots are the signer's own) |

The single highest-leverage harness that does not exist: a **second verifier for the Ed25519 case that is not OpenSSL** (a strict RFC 8419 implementation),
which would also settle D-9's "strict verifiers reject the signatureAlgorithm" claim.
