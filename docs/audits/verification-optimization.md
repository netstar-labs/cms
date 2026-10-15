# Verification & optimization — `cms` @ feat/ed25519 (L1)

Consumes the A1 audit ([audit-findings.md](audit-findings.md)) rather than re-deriving dead code, duplication and doc drift.
Toolchain: go1.27.2 darwin/arm64 (go.mod `go 1.26`), Apple M2 Pro; every command run with `GOWORK=off`.

## Executive summary

The library does what its documentation says once the documentation is corrected. The branch's two commits are sound: the
digestAlgorithms fix is verified against three openssl builds, and Ed25519 interoperates with OpenSSL 3.5.0 in both directions.
One defect in the delta (the interop test itself) and four pre-existing defects were fixed; the pre-existing items that change
what `Verify` accepts or what `Sign` writes (D-1…D-11, D-14) are left for the owner's decision. Performance is dominated by signature and chain
verification; nothing needed optimizing except a per-signer rehash that was a denial-of-service vector (fixed for repeated signers; distinct-certificate amplification remains, D-2c).

## 1. Code verification against documentation

| Check | Result |
|---|---|
| Doc comments and docs vs code | 10 drifts found and fixed ([audit-findings.md](audit-findings.md) DD-1…DD-10); `example/revoke` and `example/verify` run as documented (CLEAN) |
| Dead code | `deadcode -test ./...` reports nothing; `go vet` clean |
| Static analysis | `staticcheck 2026.2.2` clean. The installed v0.8.1 cannot load Go 1.27's export data (it built with an older Go), so 2026.2.2 was built from source; the repo's gate pins v0.8.1, which works under the CI's Go 1.24 |
| Duplication | ~90 removable lines in `cms.go` (S1–S7, D1–D4), none in the delta. Not applied (see ledger); `least-code` rung "need" answered: the delta needs nothing removed |
| `// Deprecated` / TODO markers | none present |

## 2. Operational validation (each run this session)

| Suite | Command | Result |
|---|---|---|
| Unit | `go test -race -count=1 ./...` | pass, 88.6% statement coverage (was 80.3%) |
| Interop (OpenSSL 3.5.0) | `PATH=<3.5.0>:$PATH go test -tags interop -run OpenSSLInterop -v .` | rsa, ecdsa, **ed25519** pass; both directions; tamper negatives |
| Interop (OpenSSL 3.0.15) | same | rsa, ecdsa pass; ed25519 **skips** (its `cms -sign` fails on Ed25519) |
| Interop (LibreSSL 3.3.6) | same | rsa, ecdsa pass; ed25519 **skips** (cannot load the key) |
| Old-encoding rejection | sign with the original one-line bug, `openssl cms -verify` on each build | rc=2, `Field=digestAlgorithms … wrong tag` on 3.5.0, 3.0.15 and LibreSSL 3.3.6 for RSA and ECDSA |
| Fuzz | `go test -run=XXX -fuzz=FuzzVerify -fuzztime=60s` | 13.6M executions, no panic, hang or forgery (a 90 s run on the earlier code: 23.6M) |
| Concurrency | `TestConcurrentSignVerify`, 16 goroutines, shared pool | clean under `-race` |
| Flake check | the memoisation tests as a `-race` binary, 20 runs, with 30 CPU-spinning processes on 10 CPUs | 20 of 20 pass (the timing test they replaced failed 7 of 20 here) |
| Old-vs-new equivalence | differential harness over mutated/duplicated/reordered/mixed signatures | 6,044 cases identical (accept/reject, returned certificates, error text modulo the intended `ErrVerify` prefix) |

## 3. Hardening validation

| Area | Finding |
|---|---|
| Input boundaries | Parsers reject indefinite and non-minimal lengths; a claimed 4 GiB length fails in 7.5 µs; fuzz and a 2.4M-iteration mutation run found no panic. Trailing bytes and unsigned fields are malleable (D-10). |
| Error handling | `Sign` panicked on caller input → fixed (F-2). `Verify` returns `ErrVerify`-matchable errors → fixed (F-4). Typed-nil key still panics (D-12). |
| Concurrency | No mutable package state; the package-level OID slices are read-only; `-race` clean. |
| Resource limits | Verification cost scales with the number of SignerInfos and distinct signer certificates and is **not** bounded by `len(sig)` (D-2b, D-2c). The content is not copied (7.5 KB/op flat from 1 KiB to 64 MiB). |
| Integer conversions | `tlvHeader` long-form lengths checked at and above 0x80 (the SHA-512 attribute set crosses it; OpenSSL 3.5.0 accepts it). No attacker-sized conversions found. |
| Denial of service | D-2 (b, c), see the security review. Not closed: needs a cap on SignerInfos / signer certificates. |

## 4. Performance

Baselines and before/after: [benchmark-baselines.md](benchmark-baselines.md). Cost is signature and chain verification; parsing is
about 7–12% of `Verify` (4.5 µs of 35–65 µs). The `VerifyAsSigned` double parse costs about 4 µs (+10% on RSA); not worth changing.

## 5. Optimization plan

| Candidate | Impact | Status |
|---|---|---|
| Hash content once per algorithm; verify each distinct certificate once | 100× on repeated-signer input; single-signer path within noise | **Done** (F-3) |
| Cap SignerInfos and distinct signer certificates | closes D-2b and D-2c (~110 ms per signer certificate with decoy intermediates) | **Decision** (D-2) |
| Avoid the `VerifyAsSigned` double parse | ~4 µs | not worth it |
| Hot-path allocations | none flagged; `Verify` makes 4 more allocations since F-3 (two small maps) | accepted |

## 6. Success metrics

Statement coverage 80.3% → 88.6%; fuzz targets 0 → 1; benchmarks 0 → 4 families; confirmed doc drifts 10 → 0 open; panics reachable
from `Sign` caller input 5 → 0; repeated-signer verification cost linear → near-constant for signed-attribute signers.

## Self-check

Every "passes" above maps to a command run this session. Not run: OpenSSL 3.1–3.4, non-OpenSSL verifiers, the real KSK-2017 file,
fuzzing beyond 90 s. Unexecuted checks are listed in `untestable-without-x.md`.
