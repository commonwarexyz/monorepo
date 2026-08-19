# Batched G1 subgroup checks: strategy comparison

Findings from implementing and measuring three randomized strategies for
checking that a batch of BLS12-381 G1 points lies in the prime-order subgroup.
The shipping implementation is `bls12381::primitives::subgroup::batch_in_g1`
(Strategy C below); a naive-bucketing prototype (Strategy B) is preserved on
`gv/subgroup-bucketed-prototype`.

All timings in this document are from an 18-core Apple Silicon machine.

## The problem

A decoded curve point can lie outside the prime-order subgroup; using it in a
pairing or scalar multiplication enables small-subgroup attacks. blst's exact
per-point check (Scott, [2021/1130](https://eprint.iacr.org/2021/1130), the
endomorphism test) costs **~22 µs per point**, so a 6000-point batch costs
~127 ms checked one at a time.

Every point splits as `P = G + T` with `G` in-subgroup and `T` a "cofactor
part" in the group of order

```
h = 3 · (11 · 10177 · 859267 · 52437899)²   (odd; smallest prime factor 3)
```

`P ∈ G1` iff `T = 0`. Every strategy below forms random combinations of the
points and applies the exact check to those; a combination is in G1 iff its
combined cofactor parts cancel. Rounds repeat until the cheating probability is
below `2^-security`.

## The soundness building block (shared by A and C)

A single combination `Q = Σ c_i·P_i` with `c_i` uniform iid over `{0,1,2}`:
`h` is odd, so every nonzero cofactor part `T` has order ≥ 3, making `0·T`,
`1·T`, `2·T` distinct. Fix any bad `P_j` and condition on all other
coefficients: `c_j·T_j` must hit one fixed value, and it ranges over three
distinct values — at most one works, so the combination vanishes with
probability ≤ 1/3, for any number of bad points and any cofactor group
structure. The bound is tight (a lone bad point escapes exactly when
`c_j = 0`), so a *single* combination cannot beat `log₂3 ≈ 1.58` bits per
evaluation; only more combinations can. `t = ⌈security/log₂3⌉ = 81`
combinations give 128-bit soundness.

Verified footguns:

- **Combination count.** 81 combinations = 128.38 bits; 80 = 126.8 —
  insufficient. The code divides by a strict lower bound on `log₂3`.
- **Coefficient uniformity.** The margin is 0.38 bits. A biased `byte % 3`
  (max probability 86/256) yields 127.5 bits — below target. The implementation
  rejection-samples (bytes < 243 → five exact trits); this is load-bearing.
- **Odd cofactor required.** An order-2 part `T` has `2T = 0`: escape
  probability 2/3 per combination. BLS12-377 G1 (`2^92 | h`) cannot use this
  scheme as-is.

## Strategy A — one combination per round (previous implementation)

Per round: draw `c_i ∈ {0,1,2}` per point, evaluate `Q = Σ c_i·P_i` as one
2-bit Pippenger MSM (blst), check `Q`. Needs 81 rounds — i.e. **81 full
accumulation passes over the `n` points**, one check each.

## Strategy B — random bucketing, per-bucket checks (celo/zexe PR #4)

Per round: assign each point a uniform bucket in `{0,…,B−1}`, sum each bucket,
check **each** bucket sum. A cancelling pair escapes a round only by colliding
in one bucket → `1/B` per round → `⌈security/log₂B⌉` rounds (32 at B=16).

Fewer accumulation passes, but a fixed `rounds × B` check floor (512 × 22 µs ≈
11.3 ms serial at B=16) plus — implemented naively with one `blst_p1s_add` per
bucket — one field-inversion chain per bucket per round. **Measured: loses to A
at n=1000 (15.9 vs 12.1 ms serial) and wins only ~1.35× at n=6000 (46 vs
63 ms).** Rejected; prototype preserved for reference.

## Strategy C — m parallel combinations per round (shipping)

Per round, draw for every point a coefficient *vector* in `{0,1,2}^m` (m iid
trits = a base-3 bucket id in `[0, 3^m)`), and evaluate all m combinations
`Q_j = Σ_i c_{j,i}·P_i` from one shared accumulation:

1. **Bucket by vector.** Points with the same coefficient vector are summed
   together — `3^m` buckets, but still only `n` point additions total (each
   point lands in exactly one bucket). This is the key: *one accumulation pass
   serves m combinations.*
2. **Batch-affine accumulation (the inversion trick).** Each pass pairs up the
   remaining points of every bucket and completes all pairs with a single
   shared field inversion (Montgomery's trick): ~6 field multiplications per
   addition instead of an inversion (~150 ns/point measured, flat in bucket
   count). Hand-rolled over `blst_fp`; blst's Pippenger does not expose bucket
   sums.
3. **Combine deterministically.** `Q_j = Σ_{v_j=1} S_v + 2·Σ_{v_j=2} S_v`,
   where `v_j` is the j-th base-3 digit of the bucket index. The weights are
   deterministic digits — all randomness is in the vector assignment — so this
   evaluates exactly the m combinations (it is *not* the unsound re-randomized
   sum over bucket sums, which would collapse back to one combination).
4. **Check the m outputs.** Soundness per round = `3^-m` (product of m
   independent 1/3 bounds); `r = ⌈81/m⌉` rounds at 128-bit.

`m` (and whether to batch at all) is chosen per batch by a cost model;
soundness holds for every choice, so the model's constants only affect
performance. In practice: n=1000 → m=3 (27 rounds), n=6000 → m=4 (21 rounds);
n ≲ 120 falls back to per-point checks (run through the strategy, so they
still parallelize).

### Why C dominates B

At equal per-round soundness (`B = 3^m` buckets), B checks all `3^m` bucket
sums where C checks only `m` combinations — C's total check count stays at
`r·m ≈ 81–85` for any m (the same as A), while B's grows as `rounds × B`. And
C's shared-inversion accumulation removes B's per-bucket inversion chains.

## Cost accounting (128-bit security)

| quantity                    | A (one RLC) | B naive (B=16) | C (m=4, shipping) |
|-----------------------------|:-----------:|:--------------:|:-----------------:|
| accumulation passes over n  | 81          | 32             | **21**            |
| subgroup checks             | 81          | **512**        | 84                |
| shared-inversion adds       | yes (blst)  | no             | yes (hand-rolled) |

## Measured results (criterion medians, same machine)

| n    | per-point | A serial | A parallel | C serial          | C parallel         |
|------|-----------|----------|------------|-------------------|--------------------|
| 100  | 2.14 ms   | 2.18 ms* | 2.19 ms*   | 2.13 ms (fallback)| **0.31 ms (7×)**   |
| 1000 | 21.4 ms   | 12.1 ms  | 1.59 ms    | **6.50 ms (3.3×)**| **1.16 ms (18.5×)**|
| 6000 | 126.6 ms  | 63.1 ms  | 6.9 ms     | **22.6 ms (5.6×)**| **4.10 ms (30.9×)**|

Speedups in parentheses are vs per-point serial. (*) A's n=100 numbers predate
routing the per-point fallback through the parallel strategy; C's 0.31 ms at
n=100 comes from that routing, not from batching.

Isolated accumulator throughput: 146–178 ns/point, flat across 27–243 buckets
(confirming accumulation cost is independent of bucket count).

External reference: zexe's own batched check (Strategy B with shared
inversions, arkworks field arithmetic, pre-2021 `[r]P` per-bucket check)
measured on this machine at n=8192: 207 ms naive → 30.7 ms batched parallel.

## Status

Strategy C is implemented in `subgroup::batch_in_g1` with:

- soundness-bearing details in the module docs (odd-cofactor proof, exact-trit
  requirement, deterministic-combine clarification);
- an accumulator oracle test (fuzz vs naive G1 addition over mixed
  good/bad/identity/negated/duplicated points) plus deterministic tests for
  every special-case branch (cancelling pairs, doubling chains, identity
  inputs, odd leftovers, empty buckets);
- adversarial batch tests (cancelling bad pair, repeated bad point);
- `cargo miri` cannot run the module (blst FFI is unsupported by miri); the
  unsafe surface is thin per-call FFI wrappers, with all pass-scheduling logic
  in safe Rust under the oracle tests.
