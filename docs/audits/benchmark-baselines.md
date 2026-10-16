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

Residual at the time (decision D-2): an Ed25519 signer **without** signed attributes, 100 copies over 16 MiB: **1.08 s** (≈11 ms per signer — pure EdDSA
hashes the whole message in every verification). The same input for ECDSA collapses to 13 ms. Both inputs are now refused: D-1
requires signed attributes and D-2 caps SignerInfos at 8.

## After the owner-approved fixes (`9be6a7c` → `0aff25a`)

Same machine and toolchain, `go test -run='^$' -bench='Verify|Sign|ParseHostile' -benchmem -count=6`, compared with `benchstat`.
"Before" is `9be6a7c` (the refactor, before any behaviour change); "after" is `0aff25a` for `Verify` and `2e81a74` for `Sign` and
`ParseHostile` (the last commit does not touch them).

| Benchmark | before | after | time Δ (benchstat) | B/op | allocs |
|---|---|---|---|---|---|
| Verify/rsa | 34.6 µs | 34.5 µs | ~ (p=0.94) | 8,824 → 9,536 | 97 → 96 |
| Verify/rsa+signingTime | 34.3 µs | 35.0 µs | +1.9% (p=0.002) | 9,032 → 9,880 | 99 → 103 |
| Verify/ecdsa | 61.4 µs | 61.4 µs | ~ | 7,864 → 8,592 | 102 → 101 |
| Verify/ecdsa+signingTime | 61.7 µs | 62.1 µs | ~ (p=0.09) | 8,072 → 8,936 | 104 → 108 |
| Verify/ed25519 | 44.6 µs | 44.7 µs | ~ | 6,800 → 7,512 | 84 → 83 |
| Verify/ed25519+signingTime | 45.3 µs | 45.7 µs | +1.0% (p=0.04) | 7,008 → 7,856 | 86 → 90 |
| Sign/rsa2048 | 859 µs | 859 µs | ~ | 9,656 → 9,728 (the NULL) | 145 → 147 |
| Sign/ecdsa-p256 | 55.5 µs | 56.9 µs | +2.4% (p=0.03, spread 4%) | unchanged | unchanged |
| Sign/ed25519 | 68.4 µs | 68.4 µs | ~ | unchanged | unchanged |
| ParseHostile 1 KiB / 1 MiB | 251 / 259 ns | 250 / 260 ns | ~ | unchanged | unchanged |

Time is within 2.5% everywhere, and the changes that benchstat calls significant are within the spreads seen on this machine. `Verify`
allocates about 0.7–0.9 KiB more: the SignerInfo shape, the candidate list and the parsed attributes. With signingTime it makes 4
more allocations, because every signer's signingTime is now decoded to enforce D-11. Without signingTime it makes one fewer.
