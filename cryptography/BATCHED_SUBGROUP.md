# Batched G1 subgroup checks: strategy comparison

Findings from implementing and measuring three randomized strategies for
checking that a batch of BLS12-381 G1 points lies in the prime-order subgroup.
The shipping implementation is `bls12381::primitives::subgroup::batch_in_g1`
(Strategy C below); a naive-bucketing prototype (Strategy B) is preserved on
`gv/subgroup-bucketed-prototype`.

Unless stated otherwise, timings in this document come from a 4-core Intel
Xeon (Cascade Lake, 2.8 GHz, 1 MiB L2 per core, 33 MiB L3) and are single-shot
best-of-three medians from the manual harnesses in `subgroup.rs`. On that
machine one exact per-point check costs ~52 µs, one field multiplication
~43 ns, and one batch-affine point addition ~344 ns, so a check is worth about
150 point additions — the ratio that decides every number below.

## The problem

A decoded curve point can lie outside the prime-order subgroup; using it in a
pairing or scalar multiplication enables small-subgroup attacks. blst's exact
per-point check (Scott, [2021/1130](https://eprint.iacr.org/2021/1130), the
endomorphism test) costs a ~128-bit scalar multiplication — about 1200 field
multiplications, or ~52 µs here — so a 100 000-point batch costs 5.2 s checked
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
  (max probability 86/256) yields 127.5 bits — below target. The implementation
  rejection-samples (words < 3²⁰ → twenty exact trits); this is load-bearing.
- **Odd cofactor required.** An order-2 part `T` has `2T = 0`: escape
  probability 2/3 per combination. BLS12-377 G1 (`2^92 | h`) cannot use this
  scheme as-is.

## Strategy A — one combination per round (first implementation)

Per round: draw `c_i ∈ {0,1,2}` per point, evaluate `Q = Σ c_i·P_i` as one
2-bit Pippenger MSM (blst), check `Q`. Needs 81 rounds — i.e. **81 full
accumulation passes over the `n` points**, one check each.

## Strategy B — random bucketing, per-bucket checks (celo/zexe PR #4)

Per round: assign each point a uniform bucket in `{0,…,B−1}`, sum each bucket,
check **each** bucket sum. A cancelling pair escapes a round only by colliding
in one bucket → `1/B` per round → `⌈security/log₂B⌉` rounds.

Fewer accumulation passes, but a fixed `rounds × B` check floor that dwarfs
everything else: at 128-bit security the round count falls only as `1/log₂B`
while the check count grows as `B`. Rejected; prototype preserved for
reference.

## Strategy C — m parallel combinations per round (shipping)

Per round, draw for every point a coefficient *vector* in `{0,1,2}^m` (m iid
trits = a base-3 bucket id in `[0, 3^m)`), and evaluate all m combinations
`Q_j = Σ_i c_{j,i}·P_i` from one shared accumulation:

1. **Bucket by vector.** Points with the same coefficient vector are summed
   together — `3^m` buckets, but still only `n` point additions total (each
   point lands in exactly one bucket). This is the key: *one accumulation pass
   serves m combinations.*
2. **Combine deterministically.** `Q_j = Σ_{v_j=1} S_v + 2·Σ_{v_j=2} S_v`,
   where `v_j` is the j-th base-3 digit of the bucket index. The weights are
   deterministic digits — all randomness is in the vector assignment — so this
   evaluates exactly the m combinations (it is *not* the unsound re-randomized
   sum over bucket sums, which would collapse back to one combination).
3. **Check the m outputs.** Soundness per round = `3^-m` (product of m
   independent 1/3 bounds); `r ≈ 81/m` rounds at 128-bit.

`m` (and whether to batch at all) is chosen per batch by a cost model;
soundness holds for every choice, so the model's constants only affect
performance.

### Why C dominates B

At equal per-round soundness (`B = 3^m` buckets), B checks all `3^m` bucket
sums where C checks only `m` combinations — C's total check count stays at
`r·m ≈ 81` for any m (the same as A), while B's grows as `rounds × B`.

## What the cost actually is

A pass over the points buys at most `log₂(3^m)` bits of soundness, whatever
the round does with its bucket sums: a lone bad point escapes whenever its
coefficient vector is the zero vector, which has probability `3^-m`. So the
additions per point are

```
adds/point ≈ (128 / log₂B) · (1 + B/n),     B = 3^m
```

— one addition per point per pass for the accumulation, plus about two per
occupied bucket for the combine. Minimizing over `B` gives ~10.8 additions per
point at n = 100 000 and ~9.2 at n = 10⁶; the floor is 9 passes, because
`⌈81/m⌉ = 9` for every width the cost model will accept. At six field
multiplications per batch-affine addition, that is 55–65 multiplications per
point against ~1200 for an exact check — a ceiling of 18–21×, which the
implementation reaches to within about 15%.

This is why the speedup grows with the batch and then flattens: the `B/n` term
and the fixed costs (converting to affine, drawing coefficients) amortize away,
but nine passes do not.

## The engine

Three implementation choices carry most of the constant:

- **Streaming accumulation with shared inversions.** A bucket's slot holds its
  running sum; additions are queued, and a chunk of 1024 of them shares one
  field inversion (Montgomery's trick), about six field multiplications per
  addition. A bucket with a queued addition is closed until its chunk
  completes, and a point arriving meanwhile is carried to the next pass — with
  uniform bucket ids only ~5% of points ever are. A point is therefore read
  once, added once, and never copied to a work list. Slots are touched in
  random order, so the accumulator prefetches the slot each point will land in
  a couple of dozen iterations ahead.
- **A shared collapse for the combine.** Recovering the `m` combinations one at
  a time touches `2·3^(m-1)` bucket sums each, which caps `m` where the combine
  costs more than the accumulation it saves. Summing away one digit at a time
  instead (level `j+1` is level `j` with its lowest remaining digit collapsed)
  yields every digit's marginals for about two additions per bucket in total,
  and the marginals of all levels reduce together so a handful of inversions
  cover the whole combine. This is what makes `m = 9` affordable — and `m = 9`
  is what turns 17 passes into 9.
- **Field arithmetic without ceremony.** `blst_fp_add`/`blst_fp_sub` are
  replaced by inlined carry chains (the call and the mandatory zeroing of the
  out-parameter cost more than the arithmetic), multiplications write into
  `MaybeUninit` rather than a zeroed temporary, and each addition consumes its
  inverse where the inversion's backward walk produces it, so no inverse is
  ever written to memory.

A round's bucket slots are the accumulator's working set, so the cost model
caps the width at what fits a 2 MiB budget (`3^9` slots). Measured one step
past it, cost per addition rises 20% at `m = 10` and 34% at `m = 11` — more
than the extra combinations repay.

## Measured results

Serial (single-threaded) and parallel (4 threads), against per-point checking:

| n         | per-point | C serial          | C parallel         |
|-----------|-----------|-------------------|--------------------|
| 200       | 10.5 ms   | 7.2 ms (1.5×)     | 3.2 ms (3.3×)      |
| 1 000     | 54.0 ms   | 12.7 ms (4.2×)    | 5.4 ms (10.0×)     |
| 6 000     | 318 ms    | 39.2 ms (8.1×)    | 19.3 ms (16.5×)    |
| 100 000   | 5.21 s    | 430 ms (12.1×)    | 174 ms (29.9×)     |
| 300 000   | 15.6 s    | 1.11 s (14.1×)    | 465 ms (33.6×)     |
| 1 000 000 | 53.0 s    | **3.52 s (15.1×)**| 1.56 s (34.0×)     |
| 3 000 000 | 157 s     | 10.8 s (14.5×)    | 4.42 s (35.6×)     |

Run-to-run spread on this (shared, virtualized) machine is ±5% — the large
sizes have measured anywhere from 14.5× to 15.3× serial across runs — so read
them as "about 15× serial", not as a sharp figure. The `n = 200` row sits just
above the per-point fallback threshold: below it the cost model declines to
batch at all.

For reference, the previous implementation of this same strategy measured
4.7× serial at n = 100 000 on this machine (1.15 s), against 430 ms now.

Chosen plans: 14 rounds of width 6/5 at n = 200, 13 rounds of width 7/6 at
n = 6 000, 9 rounds of width 9 from n = 100 000 up.

Phase breakdown at n = 10⁶ (3.5 s total): 3.2 s in the nine rounds, 0.38 s
converting the batch to affine, 0.04 s drawing coefficients. The conversion is
7 field multiplications per point against 54 for the rounds, and it disappears
entirely for callers whose points arrive already affine (as decoded points do).

## Same-engine strategy comparison

All three strategies run on the shipped accumulation engine (`measure_strategies`,
single-shot), so the comparison isolates the strategy rather than the engine:

| n       | per-point | A (81 passes) | B, best width      | C (shipping)      |
|---------|-----------|---------------|--------------------|-------------------|
| 6 000   | 315 ms    | ~167 ms*      | 144 ms (B=81, r=21)| **38.7 ms**       |
| 100 000 | 5.16 s    | ~2.79 s*      | 1.02 s (B=81, r=21)| **0.41 s**        |

(*) A's row is projected, not measured: `81 · n` additions at the engine's
measured 344 ns. Running A on this engine literally (`m = 1`) measures 13.4 s at
n = 100 000, because three buckets leave at most three additions in flight and
the shared inversion has nothing to amortize over — a batch-affine engine is
simply the wrong engine for a one-combination round, which is why the original
Strategy A used blst's Jacobian MSM. Either way A needs 81 passes where C needs
9.

B was measured at `B ∈ {9, 81, 729}` with `rounds = ⌈81/log₃B⌉`; 81 is its best
width at both sizes, and its check floor (`rounds × B` exact checks — 1701
checks at B=81, r=21) is what keeps it 2.5× behind C.

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
makes the no-prefilter multi-combination route cost `≈81/m` passes instead of
81 MSMs, which is what turns batch SMT on **unmodified BLS12-381** from "slower
than naive" (their result) into 8–15× serial and 19–37× parallel (ours, at a
stronger 2⁻¹²⁸ target). Their binary-coefficient variant also shows how C
extends to even-cofactor curves (e.g. BLS12-377): use `{0,1}` coefficient
vectors (2^m buckets, 1 bit per combination, 128 total) instead of trits.

Note that a faster field multiplication would *lower* these ratios, not raise
them: the exact check is almost pure multiplication while the batched path is
part multiplication and part memory traffic. The multiplication-count ceiling
above (18–21×) is the machine-independent statement.

## Status

Strategy C is implemented in `subgroup::batch_in_g1` with:

- soundness-bearing details in the module docs (odd-cofactor proof, exact-trit
  requirement, deterministic-combine clarification, and why a pass cannot beat
  `3^-m`);
- an accumulator oracle test (fuzz vs naive G1 addition over mixed
  good/bad/identity/negated/duplicated points) plus deterministic tests for
  every special-case branch (cancelling pairs, doubling chains, identity
  inputs, wide plans, empty buckets);
- an oracle test for the inlined field arithmetic against `blst_fp_add` /
  `blst_fp_sub`, and for the affine conversion against `blst_p1s_to_affine`;
- adversarial batch tests (cancelling bad pair, repeated bad point, identity
  padding);
- `cargo miri` cannot run the module (blst FFI is unsupported by miri); the
  unsafe surface is thin per-call FFI wrappers plus prefetch hints, with all
  pass-scheduling logic in safe Rust under the oracle tests.
