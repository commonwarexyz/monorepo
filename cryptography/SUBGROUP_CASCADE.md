# Certifying the whole subgroup-checking circuit

Research against `63a7a9bad`, 2026-09-08. All implementations are test-only in
`src/bls12381/primitives/subgroup/research/`. Production verification is unchanged.
The derivations and implementations received skeptical agent review, not
external cryptographic review or formal verification.

For recurring 100,000-point batches, the subsequent
[precomputation experiment](SUBGROUP_PRECOMPUTATION.md) separates advance setup
from online verification and evaluates a fused graph accumulator.

Soundness assumes inputs are already validated as on-curve and the batch is
fixed before sampling fresh private randomness. This is a subgroup check,
not a replacement for point decoding or on-curve validation.

## Result

Recursive compression becomes substantially cheaper when its certificate
examines the effective coefficients of the WHOLE inner circuit. It can then
exclude all one- and two-input errors exactly, while preserving an ordinary
probability bound for larger errors. This allows a much smaller recursive
graph and less work in the final random combinations.

Same-session end-to-end medians, in milliseconds:

| Points | Original target128 | Previous two-pass | Plain q31 recursion | Certified q19 recursion | Truncated outer + certified q19 |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 100,000 | 133.78 | 175.92 | 175.85 | 102.02 | 100.10 |
| 1,000,000 | 1123.11 | 495.91 | 443.18 | 360.31 | 358.38 |
| 3,000,000 | 3021.72 | 1046.62 | 990.26 | 907.71 | 904.47 |

The final column takes 13.6% less time than the previous two-pass prototype at
three million points, 27.7% less at one million, and 43.1% less at 100,000. It is
3.34x, 3.13x, and 1.34x faster than the original checker at those respective
sizes. Unlike the previous two-pass candidate, it beats the original at the
measured 100,000-point size. Smaller crossover sizes have not been established.
The same-session three-pass exact-exception median at three million points is
1522.14 ms, so the new candidate takes 40.6% less time.

Most of this gain comes from certifying the recursive circuit. The outer
truncation improves the three-million-point median by only 3.24 ms, or 0.36%,
relative to using the full q47 graph with the same certified recursion. Four
manual samples do not establish a reliable gain that small; the full-graph
variant is also a useful candidate with a simpler outer proof.

At three million points, the truncated variant's median phase times are about
14.6 ms affine conversion, 24.4 ms assignment/sign generation, 762.6 ms original
input compression, and 102.6 ms complete inner verification. The previous
two-pass checker spends about 245.6 ms in inner verification. The new inner
time includes its own graph assignments, two recursive accumulations, full
effective-column certificate, exact exceptions, and final random combinations.

The final recursive graph outputs at most 13,718 points per outer side, or 27,436
across both calls, rather than sending up to 207,646 outer bucket sums directly
to the random-combination checker. This is a change to the computation and its
soundness argument, not a change to the underlying curve arithmetic.

## Measurement method and scope

The ignored `measure_cascade` test uses four seeds, `TestRng::new(0..4)`, and
reverses the complete algorithm order on alternate repetitions. Every algorithm
starts from the same seed in a repetition. Inputs are distinct consecutive
generator multiples normalized before timing; generation is excluded. Timings
include conversion, allocation, all randomness, certificates, compression, and
final checks. Runs are single-threaded on the same local Apple ARM machine in
release mode with rustc 1.97.1. These are manual measurements, not Criterion
confidence intervals or a claim about other platforms.

The final truncated three-million-point samples are 903.448, 903.796, 905.134,
and 907.129 ms. Corresponding full-graph certified samples are 904.605, 904.643,
910.768, and 911.318 ms. The original's samples are 3014.352, 3020.684, 3022.748,
and 3033.220 ms. Measurements from earlier reports were different sessions;
the table above uses only this final same-session comparison.

This comparison's algorithm IDs were 0=original, 1=three-pass exact exceptions,
3=previous two-pass split111, 6=q31 recursion with split99, 7=truncated outer with
ordinary pair-certified96, 8=full outer with effective-certified q19, and 9=the
same effective-certified recursion under the truncated outer. Variant 7 has a
three-million-point median of 1000.34 ms. Simpler variants retained in the source
include the original joint129 check, q31 recursion with joint114, and a full
outer graph with ordinary pair-certified96; these were exploratory comparisons.

The `measure_cascade` driver selects `[0, 1, 3, 6, 7, 8, 9]`, reversing that
order on odd repetitions. Separate drivers retain the original two-pass
comparison and the [descent experiment](SUBGROUP_DESCENT.md), which includes an
explicitly incomplete order-three-only filter.

## First step: a stronger graph support bound

Start with the [two-pass graph construction](SUBGROUP_TWO_PASS.md): a fixed
simple girth-eight graph, a fresh private uniform injection of input indices
into edges, and independent signs at the two endpoints of every input. A bad
input means a point with a nonzero cofactor component. A support whose bucket
sums can all vanish has minimum degree at least two.

For such a support with k edges, v occupied vertices and bipartition sizes a,b,
count nonbacktracking length-three paths oriented from left to right. Girth at
least eight gives at most one path per endpoint pair; adjacent endpoints cannot
have one, since that would make a four-cycle. Therefore

```
S = sum_edges (d_u-1)(d_v-1) <= a*b-k <= v^2/4-k.
```

Minimum degree two gives `(d_u-1)(d_v-1)>=d_u+d_v-3`. Cauchy-Schwarz then gives

```
S >= sum_vertices d_v^2-3k >= 4k^2/v-3k,
v^3+8kv >= 16k^2.
```

Let f(k) be the smallest integer satisfying the last inequality. At k=12 this
forces at least 11 occupied vertices, strengthening the previous eight-vertex
bound by three bits. With c=floor(k/8), replace the previous intermediate bound
by

```
c*choose(k-1,c-1)*M^c*L^(k-c)
    / (2^max(8c,f(k))*choose(M,k)),   L=8(D-1).
```

This remains conservative for every component count j<=c: the additional
factor `2^-max(f(k)-8c,0)` is justified by each support's vertex bound. The
original connected-set counting and monotonicity arguments otherwise remain
unchanged.

This alone permits a q31 recursive graph, with 29,791 buckets per side. Its
worst compression bound is 113.173282767731 bits at k=12. Adding a joint
target114 check, which uses 72 trits, gives 112.569416957045 bits, stronger than
the previous inner allowance `3^-71`. Separate target99 checks on its two sides
give 112.747172349703 bits instead. `cascade_bound.py` verifies both complete
outer compositions. This was the first measured improvement, before the
effective-circuit certificate below.

## Exact treatment of sparse inner errors

An ordinary inner random-trit checker assigns each input a complete coefficient
column in `{-1,0,1}^m`. Mark zero columns and EVERY copy of a column repeated up
to one global sign, and subgroup-check every marked input exactly. Retain all
original columns and inputs in the original random combinations.

Acceptance is a subset of the unmodified checker's acceptance, so the error
bound `3^-m` remains valid without conditioning or a retry penalty. Additionally,
one- and two-input errors become impossible: an unmarked nonzero column cannot
kill one nonzero odd-order cofactor element. For two elements to cancel in every
row, their nonzero columns must agree up to the same global sign, which would
have marked both copies. This is implemented in `pair.rs`.

At the outer level, batches with at most two bad inputs now reject exactly.
For every larger support a stronger marginal bound becomes available. For any
three fixed nonzero elements of an odd-order abelian group, independently put
each with a random sign into a uniform one of B>=2 buckets. Every output atom
has probability at most `K3=3/(4B^2)`. Classify a target by its nonzero coordinates:

- Zero: all three inputs must occupy one bucket; fixing two signs leaves at
  most one valid remaining sign, for at most `1/(2B^2)`.
- One: either all three occupy that bucket, or a singleton occupies it and a
  pair cancels elsewhere. This gives at most
  `1/(2B^3)+3(B-1)/(4B^3) <=3/(4B^2)`.
- Two: at most six bucket assignments, each with sign probability at most 1/4,
  give `3/(2B^3)<=3/(4B^2)`.
- Three: at most six assignments, each with sign probability at most 1/8,
  give `3/(4B^3)`. Larger target supports are impossible.

For injective graph assignments with k>=3 bad inputs, condition only the other
k-3 BAD inputs' edges and signs. Three independent draws from the FULL M-edge
graph have uniform bucket marginals. Restricting these draws to distinct edges
avoiding the conditioned bad edges multiplies a probability bound by at most
`M^3/((M-k+3)(M-k+2)(M-k+1))`. Good-input placements remain unconditioned.

For k>=34D, use the direct side-sign bound `2^-34` instead. Consequently

```
A3 = max(K3*M^3/((M-34D+4)(M-34D+3)(M-34D+2)), 2^-34)
```

bounds either side's zero probability uniformly for k>=3. At q47 it provides
33.741155675819 bits. With fresh independent inner randomness and endpoint signs
conditional on the injection, the composition bound is

```
P_accept <= P_compression + 2*epsilon*A3 + epsilon^2.
```

Taking `epsilon=3^-61`, ordinary pair-certified target96 gives 128.272229256651
bits for the full outer graph. `triple_bound.py` also enumerates every mixed
three-input multiset in Z3, Z5, Z9, and Z3 x Z3, with two through four buckets,
checking every output atom. Those finite tests supplement, not replace, the
general counting argument.

## Breakthrough: certify the effective recursive circuit

Compress an inner batch on another graph, then check the compressed sums using
63 fresh random-trit combinations. For an ORIGINAL inner input P_i, the effective
coefficient in final row j is

```
a_(j,i) = alpha_i*c_(j,L_i) + beta_i*c_(j,R_i), in {-2,-1,0,1,2}.
```

Here alpha,beta are its endpoint signs and c are the final coefficients on its
two buckets. Compute the COMPLETE effective columns modulo three. Mark every
zero column and every copy of a column repeated up to global sign. Exact-check
those original inner inputs, keeping the whole sampled graph and final circuit
unchanged. Two disjoint u64 bitplanes encode the 63 coefficients modulo three;
F3 vector addition combines both endpoint columns without curve operations.

The one- and two-error guarantee now relies on the specific BLS12-381 cofactor

```
h = 3*(11*10177*859267*52437899)^2
  = 0x396c8c005555e1568c00aaab0000aaab.
```

One unmarked column has a coefficient of absolute value one or two, invertible
on the cofactor group. Two unmarked columns are independent over F3, so some
two-by-two INTEGER minor is nonzero modulo three. Its absolute value is at most
eight. Every such determinant is coprime to h, because h has no factors two,
five, or seven. Applying the adjugate to the two row equations forces both bad
cofactor elements to zero. Cyclicity is not required. The proof would fail for
arbitrary odd cofactors containing five or seven, or for an additional graph
layer that increased the coefficient bound without a new argument.

A bucket whose actual curve sum is the identity may be omitted and assigned a
zero final coefficient column. This changes the effective matrix but leaves
every final curve combination unchanged. The position map in `effective.rs`
preserves original input indices and translates live buckets to final columns.
Data-dependent omissions do not invalidate the subset-of-acceptance bound.

If the final planner chooses exact checks instead of random combinations, the
graph alone already guarantees exact rejection of one- and two-input errors.
Both paths therefore satisfy the sparse-error requirement of the outer proof.

## Making q19 sufficient: classify twelve-edge supports

The recursive graph now has q19, 6,859 buckets per side and 130,321 edges. Its
generic support bound was too loose at k=12. A twelve-edge stopping support must
be either a twelve-cycle or three internally disjoint length-four paths between
the same endpoints, denoted theta(4,4,4).

Two edge-disjoint cycles need at least sixteen edges. Otherwise a non-cycle
minimum-degree-two component contains a theta: three paths between two vertices.
Each pair of paths forms a cycle of length at least eight. Summing the three
cycle lengths shows the theta needs at least twelve edges, with equality only
for lengths 4,4,4. No other edges remain. Disconnected stopping supports also
need at least sixteen edges.

Counting nonbacktracking length-eleven paths with a forced closing edge gives
`C12<=M(D-1)^10/12`. For any pair of endpoints there are at most D distinct
length-four paths. Write their count as m. Summing `choose(m,2)` over roots and
endpoints counts each eight-cycle eight times; summing `choose(m,3)` counts each
theta twice. Since `choose(m,3)=(m-2)*choose(m,2)/3`,

```
Theta444 <= 4*(D-2)*C8/3 <= M*(D-1)^4*(D-2)/6,
P12 <= (C12/2^12 + Theta444/2^11) / choose(M,12).
```

`effective_bound.py` checks the remaining finite range with exact integers:

| q19 support case | Derived bits |
| --- | ---: |
| k=8 | 97.962752377386 |
| k=10 | 111.096359276141 |
| k=12 | 131.958334296845 |
| k=13 through 1253 | 97.324662163278, worst at 13 |
| k>=1254 | at least 132 |
| Compression plus 63-trit final check | 97.093989606749 |

The last bound is stronger than `3^-61`, which is 96.682712543991 bits. Effective
certification cannot increase this error and guarantees exact rejection of
supports one and two. Thus this recursive checker can replace the ordinary
pair-certified target96 checker in the outer composition.

## Smaller outer graph and support-dependent composition

Restrict the q47 graph's u and t coordinates to 0 through 42, keeping its other
coordinates in F47. It has 94,987 vertices per side, degree 43 and 4,084,441 edges.
It is a subgraph of the original graph, so retains simplicity and girth at
least eight. Field arithmetic remains modulo 47, not 43; the edge code is
`((u*47+v)*47+w)*43+t`.

Its exact eight-cycle count is 1,263,308,051,793. Two independently structured
integer enumerators in `cycles.rs` agree on this count and the full q3/q5 cases.
The first histograms length-four path endpoints from roots `(u,0,0)`, pairs
paths reaching the same endpoint, multiplies by 47^2 for translations, and
divides by four left roots per cycle. The second enumerates the coordinate
cycle equations `sum (u_(i+1)-u_i)*t_i=0` and
`sum (u_(i+1)-u_i)*t_i^2=0`, then divides by eight starting-point/orientation
choices. Four distinct t values give a nonsingular linear system; two distinct
values must alternate; three distinct values are excluded by the Vandermonde
argument. This finite count is security-critical, not a statistical estimate.

The eight-input compression bound is 128.194096178451 bits. Every intermediate
support from 12 through 2837 has at least 131.427809143352 bits, worst at 12; larger
supports have at least 132 bits. An undifferentiated inner-error bound wastes
too much margin here, but the original support size is fixed, so split cases.

For k<=2 the complete checker rejects exactly. For 3<=k<=7, outer compression
cannot vanish, giving `2*epsilon*A3+epsilon^2`. For k>=8, use the previously
proved [sixth-moment atom bound](SUBGROUP_RESEARCH.md):

```
K6(B) = 15/(8B^3)-35/(16B^4)+21/(32B^5).
```

Condition all but six BAD inputs and transfer from independent full-graph draws
as before. With `(x)_6` denoting six descending factors, a uniform side bound is

```
A6 = max(K6(B)*M^6/(M-49D+7)_6, 2^-49).
```

The direct sign bound supplies the second term for k>=49D. The complete error is

```
max(2*epsilon*A3+epsilon^2,
    P_compression+2*epsilon*A6+epsilon^2).
```

The two cases are alternatives, not errors to sum. Using the conservative
`epsilon=3^-61` gives 128.194076795566 bits for the symmetric truncated graph,
verified by `truncated_bound.py`. This covers both ordinary pair-certified96
and the stronger effective-certified q19 checker. The two sides' bucket
placements are never assumed independent; only their endpoint signs and fresh
inner randomness are independent after conditioning on the injection.

## Validation, limits, and next work

The new tests compare both cycle enumerators, exhaust every q19/q31/q47/q53
edge's endpoint bounds and degrees, and check every truncated edge against the
original endpoint map. A full curve-group oracle forces a genuinely cancelled
bucket, cofactor pollution, signed endpoints, and two final rounds; it verifies
the effective coefficients modulo three and exact integer curve combinations,
including coefficients of magnitude two. Forced certificate regressions ensure
that polluted duplicate copies and zero columns trigger exact checks of the
ORIGINAL inputs. Adversarial end-to-end tests cover both full and truncated
outer graphs and both recursive constructions.

The skeptical reviewer checked the cofactor/minor argument, all probability
compositions, finite parameter bounds, sampling, coefficient packing, identity
maps, and the final oracle. A latent unsupported truncated joint129 configuration
was guarded out. Production logic, public APIs, dependencies, encodings, and
unsafe code are unchanged. The supplied proof scripts use floating point only
to display approximate bit counts; security comparisons use exact arithmetic.

All 68 focused subgroup tests passed in release mode with one test thread.
Release Clippy passed, as did all four exact-arithmetic proof scripts below.

Reproduce the checks and manual benchmark with:

```sh
just test -p commonware-cryptography --release --features bls12381 subgroup:: --test-threads 1
just clippy -p commonware-cryptography --release --features bls12381
python3 cryptography/src/bls12381/primitives/subgroup/research/cascade_bound.py
python3 cryptography/src/bls12381/primitives/subgroup/research/triple_bound.py
python3 cryptography/src/bls12381/primitives/subgroup/research/effective_bound.py
python3 cryptography/src/bls12381/primitives/subgroup/research/truncated_bound.py
just test -p commonware-cryptography --release --features bls12381 measure_cascade --run-ignored only --no-capture
```

q19 accepts at most 130,321 inner inputs, sufficient for either implemented q47
outer graph but not a full q53 side. The full outer graph accepts at most 4,879,681
original inputs; the truncated graph accepts 4,084,441. Fixed chunks with an
all-chunks-accept predicate can preserve the per-chunk error bound for larger
batches, but chunking is not implemented or benchmarked here.

Parallel execution, other machines, arbitrary projective inputs, peak memory,
and input-driven exception/tail-latency behavior remain unmeasured. In particular,
exact-check exceptions can add work on unusual inputs; they are a correctness
mechanism, not a worst-case latency guarantee. WASM validation remains blocked
by the missing `wasm32-unknown-unknown` target. Independent cryptographic review
and production-quality benchmarks are still required before integration.

Original-input compression now dominates runtime. The next algorithmic target
is that accumulation structure, not another small reduction in the final
checker. Neither the two-pass count nor the current graph size is asserted to
be a universal lower bound.
