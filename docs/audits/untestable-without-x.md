# Untestable without X — `cms` (L2)

| Item | Why it was not run | Artifact needed | Suggested issue |
|---|---|---|---|
| Ed25519 CMS interop on OpenSSL 3.1–3.4 | only 3.0.15, 3.5.0 and LibreSSL 3.3.6 were available; 3.0.15 cannot do EdDSA in `cms` | those OpenSSL builds on a CI runner | `type:test` |
| Interop with a verifier that is not OpenSSL/LibreSSL (strict `signatureAlgorithm` handling, D-9) | none available | e.g. a BouncyCastle or `asn1crypto`-based CMS checker in a nested module | `type:test` |
| A full wrong accept for a nil roots pool (D-4) | needs a signature by a publicly trusted key | a throwaway public-CA-issued certificate the project owns | `type:test` |
| The real KSK-2017 `root-anchors.xml` end-to-end claim | the file and its consumer test live in a downstream consumer's repository | run that consumer's anchor test against this branch | `type:test` |
| Long fuzzing (hours) and chain-validation fuzzing with an attacker-chosen pool | a 60–90 s budget was used; the fuzz roots were the signer's own | CI fuzz budget; a second fuzz target with a hostile pool | `type:test` |
| BER (indefinite-length) input | rejected by contract (D-13) | a decision to support it, then a corpus from `openssl cms -stream` | none unless in scope |
| Typed-nil `crypto.Signer` (D-12) | would need `reflect` to detect | a decision | none |
