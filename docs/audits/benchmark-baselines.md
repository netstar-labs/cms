# Benchmark baselines — `cms` (L2)

Apple M2 Pro, darwin/arm64, go1.27.2, `go test -run=XXX -bench=. -benchmem -count=6`; medians, 64 KiB content for `Sign`, the tiny
fixture content for `Verify`. "Before" is the unchanged branch head (97914b9); "after" is the fixed branch. Spreads were ≤6%.

| Benchmark | before ns/op | after ns/op | Δ | allocs before → after |
|---|---|---|---|---|
| Verify/rsa | 35,179 | 34,576 | −1.7% | 93 → 97 |
| Verify/rsa+signingTime | 35,444 | 34,722 | −2.0% | 95 → 99 |
| Verify/ecdsa | 61,864 | 60,794 | −1.7% | 98 → 102 |
| Verify/ecdsa+signingTime | 63,152 | 60,990 | −3.4% | 100 → 104 |
| Verify/ed25519 | 46,108 | 45,116 | −2.2% | 80 → 84 |
| Verify/ed25519+signingTime | 46,252 | 44,870 | −3.0% | 82 → 86 |
| Sign/rsa2048 | 890,599 | 871,194 | −2.2% | 138 → 140 |
| Sign/ecdsa-p256 | 57,344 | 55,164 | −3.8% | 194 → 198 |
| Sign/ed25519 | 68,300 | 67,536 | −1.1% | 139 → 141 |
| ParseHostile (junk input) | ~187 | ~182 | −3% | 6 → 6 |

No regression, and no claimed speed-up: the before/after differences (−1% to −4%) are inside run-to-run noise (a second reviewer, on a heavily loaded machine, saw ±4% and spreads up to 18%); the allocation counts are exact. The +4 allocations per `Verify` are the two per-call maps. The `Sign` cost for Ed25519 includes SHA-512 over the 64 KiB content.

**Repeated-signer verification (16 MiB content, one SignerInfo repeated n times), the F-3 case:**

| n | before | after |
|---|---|---|
| 100 | 654 ms | 12 ms (skeptic's equivalent fix) |
| 1,000 | 6.57 s | 64 ms (same) |

Residual, not fixed (decision D-2): an Ed25519 signer **without** signed attributes, 100 copies over 16 MiB: **1.08 s** (≈11 ms per signer — pure EdDSA
hashes the whole message in every verification). The same input for ECDSA collapses to 13 ms.
