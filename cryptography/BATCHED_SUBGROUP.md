# Batched G1 subgroup checks: strategy comparison

Findings from implementing and measuring two randomized strategies for checking
that a batch of BLS12-381 G1 points lies in the prime-order subgroup, to decide
the approach forward. The shipping implementation is
`bls12381::primitives::subgroup::batch_in_g1` (single-RLC, below); a naive
bucketing prototype is preserved on `gv/subgroup-bucketed-prototype`.

All timings in this document are from an 18-core Apple Silicon machine.

## The problem

A decoded curve point can lie outside the prime-order subgroup; using it in a
pairing or scalar multiplication enables small-subgroup attacks. blst's exact
per-point check (Scott, [2021/1130](https://eprint.iacr.org/2021/1130), the
endomorphism test) costs **~22 µs per point**, so a 6000-point batch costs
~133 ms checked one at a time.

Every point splits as `P = G + T` with `G` in-subgroup and `T` a "cofactor
part" in the group of order

```
h = 3 · (11 · 10177 · 859267 · 52437899)²   (odd; smallest prime factor 3)
```

`P ∈ G1` iff `T = 0`. Both strategies form random combinations of the points
and check those; a combination is in G1 iff its combined cofactor parts cancel.
Rounds are repeated until the cheating probability is below `2^-security`.

## Strategy A — single random linear combination (shipping)

Per round: draw `c_i ∈ {0,1,2}` uniformly per point, check the single point
`Q = Σ c_i·P_i` (one 2-bit Pippenger MSM, one subgroup check).

**Soundness (`1/3` per round).** `h` is odd, so every nonzero cofactor part `T`
has order ≥ 3, making `0·T`, `1·T`, `2·T` distinct. Fix any bad `P_j` and
condition on all other coefficients: `c_j·T_j` must hit one fixed value, and it
ranges over three distinct values, so at most one choice of `c_j` works —
probability ≤ 1/3, for any number of bad points and any cofactor group
structure. The bound is tight (a lone bad point escapes exactly when `c_j = 0`),
so larger coefficients cannot improve a single combination — only more
combinations per round can (Strategy B).

Two footguns verified during review:

- **Round count.** 81 rounds = `81·log₂3 = 128.38` bits. 80 rounds = 126.8
  bits — insufficient. The code divides by a strict lower bound on `log₂3` so
  it never under-counts.
- **Coefficient uniformity.** The margin is 0.38 bits. A biased `byte % 3`
  (max probability 86/256) yields 127.5 bits — **below target**. The
  implementation rejection-samples (bytes < 243 → five exact trits), which is
  load-bearing, not pedantry.
- **Odd cofactor required.** An order-2 part `T` has `2T = 0`: escape
  probability 2/3 per round. BLS12-377 G1 (`2^92 | h`) cannot use this scheme
  as-is.

## Strategy B — random bucketing (celo/zexe PR #4)

Per round: assign each point a uniform bucket in `{0,…,B−1}`, sum each bucket,
subgroup-check **each** bucket sum.

**Soundness (`1/B` per round).** A single bad point is always caught (nothing
cancels it inside its bucket). The worst case is a cancelling pair (`T`, `−T`),
which escapes only by colliding in the same bucket — probability `1/B`. So
`rounds = ⌈security / log₂B⌉`: B=16 → 32 rounds, B=256 → 16 rounds.

Bucketing *separates* a cancelling pair unless they collide, so each round
extracts `log₂B` bits instead of `log₂3 ≈ 1.58`. Fewer rounds means fewer
summation passes over the `n` points — the entire appeal.

**There is no cheap hybrid.** Combining the `B` bucket sums into one RLC check
per round re-merges the cancelling pair and collapses soundness back to 1/3.
The `B` separate checks are load-bearing.

## Cost accounting (128-bit security, B=16 for bucketing)

The subgroup check (~22 µs) costs more than a summation pass, so totals are
dominated by inversions + checks, not round count:

| quantity          | A: single-RLC | B: naive buckets | B: shared-inversion buckets |
|-------------------|:-------------:|:----------------:|:---------------------------:|
| rounds            | 81            | 32               | 32                          |
| field inversions  | ~81           | **512** (32×16)  | **~32**                     |
| subgroup checks   | **81**        | 512 (32×16)      | 512 (32×16)                 |
| summation passes  | 81            | 32               | 32                          |

- **A** gets ~1 inversion/round free: Pippenger's bucket accumulation shares one
  Montgomery batch inversion across its internal buckets.
- **B (naive)** pays one inversion per bucket per round (`blst_p1s_add` per
  bucket) — 512 total. The fewer-rounds saving is eaten by the extra inversions.
- **B (shared-inversion)** — zexe's `batch_bucketed_add` — accumulates *all*
  buckets through one batch inversion per addition pass, dropping inversions
  below A while keeping the round advantage. This is the only variant that can
  actually win.
- Every B variant carries a fixed `rounds × B` **check floor**: 512 × 22 µs ≈
  **11.3 ms serial**, independent of `n` (vs A's 1.8 ms). In parallel the floor
  spreads across cores; serially it is a hard tax and pushes the per-point
  fallback threshold up to `rounds × B` points.

## Measured results

Baseline (committed criterion bench, single-RLC vs per-point):

| n    | per-point | A serial       | A parallel      |
|------|-----------|----------------|-----------------|
| 100  | 2.20 ms   | 2.18 ms        | 2.19 ms (auto-tuned serial) |
| 1000 | 21.8 ms   | 12.1 ms (1.8×) | 1.59 ms (13.7×) |
| 6000 | 132.7 ms  | 63.1 ms (2.1×) | 6.9 ms (19.2×)  |

Naive bucketing prototype (best B per size, tuned over B ∈ {8…256}):

| n    | mode     | A (shipping) | B naive (B=8) | outcome           |
|------|----------|:------------:|:-------------:|-------------------|
| 1000 | serial   | **12.1 ms**  | 15.9 ms       | B loses 1.3×      |
| 1000 | parallel | **1.59 ms**  | 2.09 ms       | B loses 1.3×      |
| 6000 | serial   | 63 ms        | **46 ms**     | B wins 1.37×      |
| 6000 | parallel | 6.9 ms       | **5.17 ms**   | B wins 1.33×      |

Larger B is strictly worse in the naive form (B=256 at n=6000: 111 ms serial —
nearly per-point speed) because the check floor grows as `rounds × B`.

External reference: zexe's own batched check (shared-inversion, arkworks field
arithmetic, pre-2021 `[r]P` per-bucket check) measured on this machine at
n=8192: 207 ms naive → 30.7 ms batched parallel. Our A beats it at every level
via blst + the endomorphism check.

## Decision

**Current state: ship A (single-RLC).** Fewest inversions, fewest checks,
simplest soundness argument, smallest review surface; already delivers 2×
serial / 13–19× parallel over per-point.

**Candidate follow-up: B with shared-inversion accumulation.** The cost table
says it is the one variant with a real shot: ~32 inversions (vs A's 81) and 32
summation passes (vs 81), against a 512-check floor that parallelizes well.
Honest projection: **~1.5–3× over A at n=6000, roughly parity at n=1000** (the
check floor dominates there). Costs to get it:

- A hand-rolled unsafe batch-affine accumulator (blst does not expose bucket
  sums — its Pippenger combines them internally), plus the required miri pass.
- A higher per-point fallback threshold (`rounds × B` ≈ 512 points), so small
  batches see no benefit at all.
- The naive prototype's counting sort, `buckets_in_g1` shape, and large-batch
  soundness tests carry over from `gv/subgroup-bucketed-prototype`.

**The decision hinges on workload**: if typical batches are ≳ 4–6k points and
the extra serial-path latency floor is acceptable, shared-inversion bucketing is
worth building; if batches cluster near ~1k, A is already at the optimum and the
added unsafe surface buys nothing.
