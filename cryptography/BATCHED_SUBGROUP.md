# Batched G1 subgroup checks: strategy comparison

Findings from implementing and measuring three randomized strategies for
checking that a batch of BLS12-381 G1 points lies in the prime-order subgroup.
The shipping implementation is `bls12381::primitives::subgroup::batch_in_g1`
(Strategy C below); a naive-bucketing prototype (Strategy B) is preserved on
`gv/subgroup-bucketed-prototype`.

Timings come from two machines: the original implementation was measured on
an 18-core Apple Silicon machine; the reworked single-threaded implementation
(see "Single-threaded engineering" below) on a 4-core Intel Cascade Lake
server VM. Each table names its machine; cross-machine ratios are not
comparable (the VM's exact check costs ~50 µs vs ~22 µs).

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
   remaining points of every bucket and completes all pairs with shared field
   inversions (Montgomery's trick): 5M+1S field multiplications per addition
   instead of an inversion, flat in bucket count. Hand-rolled over `blst_fp`;
   blst's Pippenger does not expose bucket sums.
3. **Combine deterministically.** `Q_j = Σ_{v_j=1} S_v + 2·Σ_{v_j=2} S_v`,
   where `v_j` is the j-th base-3 digit of the bucket index. The weights are
   deterministic digits — all randomness is in the vector assignment — so this
   evaluates exactly the m combinations (it is *not* the unsound re-randomized
   sum over bucket sums, which would collapse back to one combination). All
   `2m` digit sums are extracted together by a marginal-merge tree over the
   bucket array (~`2·3^m` batched additions total), not by scanning the
   buckets per output.
4. **Check the m outputs.** Soundness per round = `3^-m` (product of m
   independent 1/3 bounds); round widths sum to exactly 81 at 128-bit
   (`⌈81/m⌉` rounds, the last one narrower).

`m` (and whether to batch at all) is chosen per batch by a cost model;
soundness holds for every choice, so the model's constants only affect
performance. In practice: n=1000 → m=5 (17 rounds), n=6000 → m=7 (12 rounds),
n=100k and n=1M → m=9 (9 rounds); n ≲ 115 falls back to per-point checks (run
through the strategy, so they still parallelize).

### Why C dominates B

At equal per-round soundness (`B = 3^m` buckets), B checks all `3^m` bucket
sums where C checks only `m` combinations — C's total check count stays at
`r·m ≈ 81–85` for any m (the same as A), while B's grows as `rounds × B`. And
C's shared-inversion accumulation removes B's per-bucket inversion chains.

## Single-threaded engineering

A dedicated optimization round rebuilt the implementation around the serial
cost anatomy. At 128-bit security the accumulation passes dominate, so the
lever with the largest exponent is width: passes = `⌈81/m⌉`, and each pass
costs `n - nonempty(3^m)` batch-affine additions regardless of `m`. The round
consisted of:

- **Width cap 5 → 10** (`u16` bucket ids): a 100k-point batch runs 9 passes
  instead of 17, with a short final round making the widths sum to exactly 81.
- **Marginal-merge tree combine.** The per-output combine scan
  (`2m·3^(m-1)` Jacobian mixed additions) would have erased the wider rounds'
  gains; merging one digit at a time computes all `2m` digit sums in
  `~2·3^m` batch-affine additions (records `[total, ones_0, twos_0, ...]`
  over shrinking bucket ranges, two batched additions per field per merge).
- **Fused batch-affine engine.** Operations read a source buffer and write a
  disjoint destination (ping-pong halving), so completion order is free:
  results are produced inside the backward walk of the shared-inversion
  chain, whose forward half is built during classification. Operands are
  referenced by `u32` index (the previous engine copied 208-byte operand
  records), inversions are chunked so a chunk's operands stay cache-resident
  between classification and completion, an odd bucket carries its first
  element instead of re-pairing, and the identity test is an inline limb
  compare instead of per-operand FFI.
- **Tiled accumulation.** Batches beyond 2^17 points are summed tile by tile
  into the same bucket space, each tile's surviving bucket sums re-entering
  as points keyed by their bucket. This reassociates the additions without
  adding any, and keeps every buffer within cache instead of streaming
  hundreds of megabytes per pass; scratch buffers are reused across tiles.
- **Cheaper exact-uniform ids.** Bucket ids come from Lemire's multiply-shift
  with rejection on 32-bit words (still *exactly* uniform — the soundness
  margin requires it) instead of per-trit extraction from rejection-sampled
  bytes.
- **Decoded-point fast path.** `G1::batch_to_affine` recognizes `z = 1`
  inputs (what `read_unchecked` produces, i.e. the motivating workload) and
  copies coordinates instead of running the Montgomery-trick conversion.
  Benchmarks feed decoded-form points for the same reason.

Per point at n=100k this leaves ~10.8 batch-affine additions
(9 passes × (1 − nonempty/n + 2·3^9/n)), i.e. ~65 field multiplications,
against ~1130 multiplications for one exact check — a machine-independent
ceiling of ~15-17× once per-pass bookkeeping is amortized, approached as n
grows (the additions per point fall toward 9 and the bookkeeping amortizes).
The measured gap to that ceiling is per-addition overhead (memory system and
scheduling), which is why large batches on cache-rich machines get closest.

## Cost accounting (128-bit security)

| quantity                    | A (one RLC) | B naive (B=16) | C (m=9, n≥100k)   |
|-----------------------------|:-----------:|:--------------:|:-----------------:|
| accumulation passes over n  | 81          | 32             | **9**             |
| subgroup checks             | 81          | **512**        | 81                |
| shared-inversion adds       | yes (blst)  | no             | yes (hand-rolled) |

## Measured results

Reworked implementation (see "Single-threaded engineering"), single-shot
timings on a 4-core Intel Cascade Lake server VM (exact check ~50.6 µs there;
points in decoded form, z = 1):

| n    | per-point | C serial            | C parallel (4 cores) | old C serial |
|------|-----------|---------------------|----------------------|--------------|
| 1000 | 50.9 ms   | **13.4 ms (3.8×)**  | 4.3 ms (11.8×)       | 24.0 ms      |
| 6000 | 309 ms    | **47.3 ms (6.5×)**  | 14.6 ms (21×)        | 62.9 ms      |
| 100k | 5.03 s    | **464 ms (10.9×)**  | 175 ms (28.8×)       | 1.15 s       |
| 1M   | 51.6 s    | **4.19 s (12.3×)**  | 1.57 s (33×)         | 5.96 s*      |

Speedups in parentheses are vs per-point serial; "old C serial" is the
pre-rework implementation on the same VM. (*) old implementation with the
rework's tiling only (the untiled original was not measured at n=1M).

Original implementation, criterion medians on an 18-core Apple Silicon
machine (exact check ~22 µs; points from scalar multiplication):

| n    | per-point | A serial | A parallel | C serial          | C parallel         |
|------|-----------|----------|------------|-------------------|--------------------|
| 100  | 2.14 ms   | 2.18 ms* | 2.19 ms*   | 2.13 ms (fallback)| **0.31 ms (7×)**   |
| 1000 | 21.4 ms   | 12.1 ms  | 1.59 ms    | **6.50 ms (3.3×)**| **1.16 ms (18.5×)**|
| 6000 | 126.6 ms  | 63.1 ms  | 6.9 ms     | **22.6 ms (5.6×)**| **4.10 ms (30.9×)**|

(*) A's n=100 numbers predate routing the per-point fallback through the
parallel strategy; C's 0.31 ms at n=100 comes from that routing, not from
batching.

Isolated accumulator throughput: 146–178 ns/point on the Apple machine
(original engine, 27–243 buckets); ~330 ns/point synthetic and ~390 ns/point
in-scheme on the Cascade Lake VM (reworked engine, 243–19683 buckets, whose
field multiplication is ~44 ns vs ~1130 multiplications per exact check) —
flat in bucket count on both, confirming accumulation cost is independent of
bucket count.

Same-engine strategy comparison (`measure_strategies` harness, single-shot; A
and B are emulated on the shipped accumulation engine so the comparison
isolates the strategy — blst's MSM engine runs A's passes ~15% faster):

| n       | per-point | A (81 passes)   | B (best of 16/64/256) | C (shipping)          |
|---------|-----------|-----------------|-----------------------|-----------------------|
| 1 000   | 21.4 ms   | 15.5 / 2.38 ms  | 15.9 / 2.40 (B=16)    | **6.6 / 1.13 ms**     |
| 6 000   | 126.5 ms  | 74.9 / 8.86 ms  | 40.1 / 4.49 (B=16)    | **22.4 / 3.62 ms**    |
| 100 000 | 2 126 ms  | 1 249 / 138 ms  | 353 / 47.8 (B=256)    | **298 / 49.6 ms**     |

Same comparison on the reworked engine (Cascade Lake VM, single-shot; A and B
emulated on the shipped accumulation engine as before):

| n       | per-point | A (81 passes)   | B (best of 16/64/256) | C (shipping)          |
|---------|-----------|-----------------|-----------------------|-----------------------|
| 1 000   | 54.4 ms   | 34.9 / 9.27 ms  | 37.2 / 12.1 (B=16)    | **12.7 / 3.85 ms**    |
| 6 000   | 311.9 ms  | 171.9 / 46.6 ms | 91.5 / 23.6 (B=16)    | **41.9 / 13.6 ms**    |
| 100 000 | 5 159 ms  | 3 027 / 805 ms  | 862 / 239 (B=256)     | **492 / 177 ms**      |

(serial / parallel per cell; original implementation, Apple machine.) C wins
serially at every size — 7.1× over per-point and 4.2× over A at n=100 000
(42.8× parallel), with B=256 tying C at n=100 000 parallel because the old
width cap (`m ≤ 5`, u8 bucket ids) bound there. The rework lifted the cap to
`m ≤ 10`; at n=100 000 the plan now runs m=9 (9 passes), which is what breaks
the tie (see the tables above).

External reference: zexe's own batched check (Strategy B with shared
inversions, arkworks field arithmetic, pre-2021 `[r]P` per-bucket check)
measured on this machine at n=8192: 207 ms naive → 30.7 ms batched parallel.

## Related work

The current state of the art in the literature is Koshelev–El Housni–Fotiadis,
"Batch subgroup membership testing on pairing-friendly curves"
([eprint 2025/1311](https://eprint.iacr.org/2025/1311), gnark-crypto-based Go
implementation). Their construction is a two-step procedure: a per-point
Tate-pairing/power-residue prefilter removes the small-torsion components
(3- and 11-torsion on BLS12-381), after which the smallest remaining cofactor
prime is 10177 and a few rounds of a 13-bit-coefficient RLC (one full MSM per
round) reach the target. Points of comparison, from the paper itself:

- They state the same barrier (soundness of one combination ≤ `1/p` for the
  smallest cofactor prime `p`, i.e. 1/3 on BLS12-381) and the same multi-round
  escape (`n = ⌈µ/log₂ m⌉` rounds of small coefficients), but their cost model
  charges **one full MSM per round**, which is why they judge the multi-round
  route impractical and reach for the prefilter instead.
- **On BLS12-381 their end-to-end method is slower than naive per-point
  checking on valid inputs** (their words: the first-stage Tate/residue checks
  dominate; Step 2 alone would be 9.6–47× but is unsound without Step 1). Their
  remedy is generating new curves (BLS12-376, a new BLS12-377) where the
  prefilter shrinks — gaining 1.1–1.5× end-to-end, single-threaded, at a
  2⁻⁶⁰ target (vs 2⁻¹²⁸ here).
- Their multi-round variant (old BLS12-377, 60 rounds of `{0,1}` coefficients)
  uses running-sum mixed additions; they name affine additions with
  Montgomery batch inversion as *future work*. The cross-round vector-bucketing
  used here — one accumulation pass serving all `m` combinations — does not
  appear in the paper.

Strategy C therefore fills exactly the gap their cost model assumes away: it
makes the no-prefilter multi-combination route cost `⌈81/m⌉` passes instead of
81 MSMs, which is what turns batch SMT on **unmodified BLS12-381** from "slower
than naive" (their result) into 10.9× serial at n=10⁵ and 12.3× at n=10⁶
(28.8× / 33× on four cores), at a stronger 2⁻¹²⁸ target — approaching the
~15-17× serial ceiling set by ~65 field multiplications per point against
~1130 per exact check. Their binary-coefficient variant also shows how C
extends to even-cofactor curves (e.g. BLS12-377): use `{0,1}` coefficient
vectors (2^m buckets, 1 bit per combination, 128 total) instead of trits.

## Status

Strategy C is implemented in `subgroup::batch_in_g1`, reworked for
single-threaded throughput as described above (wider rounds, marginal-merge
tree, fused ping-pong engine, tiled accumulation, Lemire id sampling, decoded
fast-path conversion), with:

- soundness-bearing details in the module docs (odd-cofactor proof, exact-trit
  requirement, deterministic-combine clarification);
- an accumulator oracle test (fuzz vs naive G1 addition over mixed
  good/bad/identity/negated/duplicated points) plus deterministic tests for
  every special-case branch (cancelling pairs, doubling chains, identity
  inputs, odd leftovers, empty buckets), a marginal-tree oracle test against
  naive per-digit sums, and a tile-boundary oracle test;
- adversarial batch tests (cancelling bad pair, repeated bad point);
- `cargo miri` cannot run the module (blst FFI is unsupported by miri); the
  unsafe surface is thin per-call FFI wrappers, with all pass-scheduling logic
  in safe Rust under the oracle tests.
