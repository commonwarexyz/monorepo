# Batched G1 subgroup checks: strategy comparison

Findings from implementing and measuring three randomized strategies for
checking that a batch of BLS12-381 G1 points lies in the prime-order subgroup.
The shipping implementation is `bls12381::primitives::subgroup::batch_in_g1`
(Strategy C below); a naive-bucketing prototype (Strategy B) is preserved on
`gv/subgroup-bucketed-prototype`.

Timings come from two machines: the first-generation measurements (Strategies
A/B/C as originally shipped) from an 18-core Apple Silicon machine, and the
wide-round revision from a 4-core Intel Xeon @ 2.80 GHz (1 MiB L2/core) —
each table says which. Ratios against per-point checking are the portable
signal; absolute times are not comparable across the two machines (blst's
field multiplication is roughly twice as fast on the Apple Silicon parts).

## The problem

A decoded curve point can lie outside the prime-order subgroup; using it in a
pairing or scalar multiplication enables small-subgroup attacks. blst's exact
per-point check (Scott, [2021/1130](https://eprint.iacr.org/2021/1130), the
endomorphism test) costs **~22 µs per point** on the Apple Silicon machine
(~52 µs on the Xeon), so a 6000-point batch costs ~127 ms (~305 ms) checked
one at a time.

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
  (max probability 86/256) yields 127.5 bits — below target. Rejection
  sampling is load-bearing: the first-generation sampler rejected bytes at or
  above 243 (five exact trits per accepted byte); the shipping sampler draws
  whole bucket ids by Lemire rejection on 16-bit values (exactly
  `floor(2^16 / 3^m)` inputs per id, verified exhaustively in a test).
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
2. **Batch-affine accumulation (the inversion trick).** Additions are
   completed in shared-inversion batches (Montgomery's trick): ~6 field
   multiplications per addition instead of an inversion. Hand-rolled over
   `blst_fp`; blst's Pippenger does not expose bucket sums. (The
   first-generation engine counting-sorted points into per-bucket runs and
   halved each bucket pass by pass, ~150 ns/point on Apple Silicon, flat in
   bucket count; the shipping engine streams points through a slot table —
   see "Widening the rounds" below.)
3. **Combine deterministically.** `Q_j = Σ_{v_j=1} S_v + 2·Σ_{v_j=2} S_v`,
   where `v_j` is the j-th base-3 digit of the bucket index. The weights are
   deterministic digits — all randomness is in the vector assignment — so this
   evaluates exactly the m combinations (it is *not* the unsound re-randomized
   sum over bucket sums, which would collapse back to one combination).
4. **Check the m outputs.** Soundness per round = `3^-m` (product of m
   independent 1/3 bounds); `r = ⌈81/m⌉` rounds at 128-bit.

`m` (and whether to batch at all) is chosen per batch by a cost model;
soundness holds for every choice, so the model's constants only affect
performance. In practice (wide-round engine): n=1000 → m=5 (17 rounds),
n=6000 → m=6 (14 rounds), n=100 000 → m=9 (9 rounds); n ≲ 120 falls back to
per-point checks (run through the strategy, so they still parallelize).

### Why C dominates B

At equal per-round soundness (`B = 3^m` buckets), B checks all `3^m` bucket
sums where C checks only `m` combinations — C's total check count stays at
`r·m ≈ 81–85` for any m (the same as A), while B's grows as `rounds × B`. And
C's shared-inversion accumulation removes B's per-bucket inversion chains.

## Widening the rounds (second-generation engine)

Strategy C's economics improve with `m` (passes fall as `ceil(81/m)`), but the
first-generation engine capped `m` at 5: bucket ids were a `u8`, and the
combine read all `3^m` bucket sums once per combination (`m * 3^m` mixed
additions), which the cost model priced out of wide rounds. Three changes
lift the cap to `m = 10` (`u16` ids) and make wide rounds pay:

1. **Slot accumulation.** Instead of counting-sorting the points into
   per-bucket runs and halving each bucket pass by pass, a round streams the
   points once through a table of `3^m` slots: a point landing on an empty
   slot parks there, a point landing on an occupied slot pairs with the
   parked one (the slot empties until the pair's sum re-enters), and pending
   pairs are completed 1024 at a time with one shared inversion. The
   addition count is at most `n` minus the number of nonempty buckets (fewer
   when identities or cancellations resolve without arithmetic) — it
   *shrinks* as buckets multiply — and the working set is the slot table,
   not the full point buffer. Slots for upcoming points are software-
   prefetched (their ids are already drawn), which matters once the table
   outgrows L2.
2. **Digit-peeling combine.** Splitting the `3^m` sums by their top base-3
   digit gives three contiguous thirds `T0 | T1 | T2`: the top digit's
   combination inputs are `sum(T1)` and `sum(T2)`, and the element-wise sum
   `T0 + T1 + T2` is a `3^(m-1)`-entry table with the same remaining digits —
   recurse, and scan directly once the table is at most 243 entries. This is
   a pure reassociation of the same per-digit sums (soundness untouched) and
   costs about `2 * 3^m` batch-affine additions instead of `m * 3^m` mixed
   ones, which is what makes `m = 8..10` economical.
3. **Exact-uniform bulk ids.** Coefficient vectors are drawn as whole bucket
   ids by Lemire rejection on 16-bit values — exactly `floor(2^16 / 3^m)`
   inputs map to every id (verified exhaustively in a test), replacing the
   per-trit rejection sampler. Exactness is still load-bearing; see the
   module docs.

The cost model picks `m` per batch from `rounds * (n * point_cost +
(n - E[nonempty buckets]) * add_cost + 3^m * bucket_cost + m * check_cost)`,
with `E[nonempty]` computed in integer fixed point. At n = 100 000 it picks
m = 9 — nine rounds (81 = 9 x 9 exactly), each ~0.8 additions per point —
against seventeen rounds for the first-generation cap.

## Cost accounting (128-bit security)

| quantity                    | A (one RLC) | B naive (B=16) | C gen-1 (m=4) | C wide (m=9, n=100k) |
|-----------------------------|:-----------:|:--------------:|:-------------:|:--------------------:|
| accumulation passes over n  | 81          | 32             | 21            | **9**                |
| additions per point per pass| 1           | 1              | ~1            | **~0.8**             |
| subgroup checks             | 81          | **512**        | 84            | 81                   |
| shared-inversion adds       | yes (blst)  | no             | yes           | yes                  |

## Measured results — wide rounds (criterion medians, 4-core Xeon)

| n       | per-point | plan (m, rounds) | C serial            | C parallel           |
|---------|-----------|:----------------:|---------------------|----------------------|
| 100     | 5.25 ms   | fallback         | 5.19 ms (1.0×)      | **1.53 ms (3.4×)**   |
| 1000    | 51.5 ms   | (5, 17)          | **18.5 ms (2.8×)**  | **6.37 ms (8.1×)**   |
| 6000    | 305.5 ms  | (6, 14)          | **50.9 ms (6.0×)**  | **17.2 ms (17.8×)**  |
| 100 000 | 5 225 ms  | (9, 9)           | **497.6 ms (10.5×)**| **197.4 ms (26.5×)** |

Speedups in parentheses are vs per-point serial on the same machine. For
scale: the first-generation engine measured on this same machine reaches only
4.2× serial at n = 100 000 (1 237 ms) — the wide rounds are a 2.5× improvement
of the batch path itself. Small batches are check-bound (the ~81 exact checks
on combination outputs are a fixed ~4.4 ms serial floor here), so the ratio
climbs with n.

Where the time goes at n = 100 000 / m = 9 (serial, single-shot): ~325 ms
accumulating (9 rounds x 100 000 points x ~360 ns), ~140 ms combining
(9 x ~39 000 additions), ~7 ms drawing ids, ~4.4 ms on the 81 exact checks,
plus the one-time batch conversion of the inputs to affine. A batch-affine
addition (six field multiplications plus shares of an inversion) costs
~400–450 ns on this machine, so the batch path runs within ~25% of its
field-multiplication floor.

## Measured results — first generation (criterion medians, Apple Silicon)

| n    | per-point | A serial | A parallel | C serial          | C parallel         |
|------|-----------|----------|------------|-------------------|--------------------|
| 100  | 2.14 ms   | 2.18 ms* | 2.19 ms*   | 2.13 ms (fallback)| **0.31 ms (7×)**   |
| 1000 | 21.4 ms   | 12.1 ms  | 1.59 ms    | **6.50 ms (3.3×)**| **1.16 ms (18.5×)**|
| 6000 | 126.6 ms  | 63.1 ms  | 6.9 ms     | **22.6 ms (5.6×)**| **4.10 ms (30.9×)**|

Speedups in parentheses are vs per-point serial. (*) A's n=100 numbers predate
routing the per-point fallback through the parallel strategy; C's 0.31 ms at
n=100 comes from that routing, not from batching.

First-generation isolated accumulator throughput (Apple Silicon): 146–178
ns/point, flat across 27–243 buckets and n up to 100 000. The slot
accumulator on the Xeon runs 364–412 ns/point at n = 100 000 across 243–19 683
buckets (the same engine at 19 683 buckets is where the per-pass addition
count starts falling below one per point).

Same-engine strategy comparison (first-generation engine, Apple Silicon;
`measure_strategies` harness, single-shot; A and B are emulated on the shipped
accumulation engine so the comparison isolates the strategy — blst's MSM
engine runs A's passes ~15% faster):

| n       | per-point | A (81 passes)   | B (best of 16/64/256) | C (shipping)          |
|---------|-----------|-----------------|-----------------------|-----------------------|
| 1 000   | 21.4 ms   | 15.5 / 2.38 ms  | 15.9 / 2.40 (B=16)    | **6.6 / 1.13 ms**     |
| 6 000   | 126.5 ms  | 74.9 / 8.86 ms  | 40.1 / 4.49 (B=16)    | **22.4 / 3.62 ms**    |
| 100 000 | 2 126 ms  | 1 249 / 138 ms  | 353 / 47.8 (B=256)    | **298 / 49.6 ms**     |

(serial / parallel per cell.) C wins serially at every size — 7.1× over
per-point and 4.2× over A at n=100 000 (42.8× parallel). The one caveat in
these first-generation numbers — at n=100 000 parallel, B=256 tied C within
noise, because C's width cap (`m ≤ 5`, u8 bucket ids) bound exactly where B's
optimal bucket count kept growing — is resolved by the wide-round engine
above (`m ≤ 10`, u16 ids), which C's plan exploits at that size (m=9) while B
would still pay `rounds × B` exact checks.

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
81 MSMs — each pass under one addition per point — which is what turns batch
SMT on **unmodified BLS12-381** from "slower than naive" (their result) into
6.0–10.5× serial and up to 26.5× parallel on a 4-core x86 machine with the
wide-round engine (first generation: 3.2–7.1× serial and 18–43× parallel on
an 18-core Apple Silicon machine), at a stronger 2⁻¹²⁸ target. Their binary-coefficient variant also shows how C
extends to even-cofactor curves (e.g. BLS12-377): use `{0,1}` coefficient
vectors (2^m buckets, 1 bit per combination, 128 total) instead of trits.

## Status

Strategy C with the wide-round engine is implemented in
`subgroup::batch_in_g1` with:

- soundness-bearing details in the module docs (odd-cofactor proof,
  exact-uniformity requirement on coefficient ids, and why the digit-peeling
  combine is a soundness-neutral reassociation of the same combinations);
- an accumulator oracle test (fuzz vs naive G1 addition over mixed
  good/bad/identity/negated/duplicated points, bucket counts 1 through
  19 683) plus deterministic tests for every special-case branch (cancelling
  pairs, doubling chains, identity inputs, mid-stream chunk drains, stale
  displaced slots);
- a combine oracle test (digit-peeling vs direct scan, every width 1..=9,
  tables with identities, duplicates, and cancelling pairs) and a wiring test
  that a single bad point at bucket `d * 3^j` is rejected for every digit
  position and value at m = 9;
- an exhaustive id-uniformity test (all 2^16 sampler inputs, every width:
  each id produced exactly `floor(2^16 / 3^m)` times) plus a stream-pinning
  test that `draw_ids` is exactly that sampler over whole RNG buffers;
- mutation-hardening tests for the two soundness properties no black-box
  accept/reject test can observe (found by adversarial review): the batched
  path executes every planned round (an RNG-fill-counting wrapper), and every
  round's verdict gates acceptance (a scripted RNG builds one accepting round
  followed by deterministically rejecting ones, separating `all` from `any`);
- a check that the order-3 points `(0, ±2)` — the only on-curve points
  sharing the empty-slot sentinel's `x = 0` — flow through parking, doubling,
  cancellation, and the combine exactly;
- adversarial batch tests (cancelling bad pair, repeated bad point, one bad
  point in wide batches);
- `cargo miri` cannot run the module (blst FFI is unsupported by miri); the
  unsafe surface is thin per-call FFI wrappers plus an x86 cache prefetch
  hint, with all scheduling logic in safe Rust under the oracle tests.
