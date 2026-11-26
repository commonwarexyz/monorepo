# Beyond independent vector bucketing

Research against `63a7a9bad`, 2026-09-08. The experiment is in
`src/bls12381/primitives/subgroup/research.rs`, compiled only for tests.
Production `batch_in_g1` is unchanged. A skeptical subagent reviewed the
derivation and implementation and supplied independent finite checks. This
is not external cryptographic review or a machine-checked proof.

## Latest result: certified recursive compression

The [effective-circuit certificate](SUBGROUP_CASCADE.md) makes a much smaller
recursive graph sound by rejecting all one- and two-input errors exactly.
In a new same-session comparison, the best prototype takes 904.47 ms at three
million points, versus 1046.62 ms for the previous two-pass prototype and
3021.72 ms for the original checker. It also beats the original at 100,000
points. The report contains the new derivation, exact bound checks, critical
review, and benchmark limitations. Everything remains test-only.

## Previous result: two passes

The [two-pass graph experiment](SUBGROUP_TWO_PASS.md) supersedes the three-pass
result below for the measured large batches. A fixed girth-eight graph excludes
the dangerous small cancellation patterns structurally; a fresh uniform input
injection and independent endpoint signs preserve the adversarial-input bound.
Separate inner checks at target 111 give a derived total false-acceptance bound
below `2^-128`. This remains test-only, with production logic unchanged.

In that earlier same-session comparison at three million points, median runtime
is 1047.94 ms, versus 1527.10 ms for three-pass exact exceptions and 3028.37 ms
for the original checker: 31.4% less time than three passes and 2.89x faster than
the original. At one million points the respective times are 500.42, 560.75,
and 1130.07 ms. At 100,000 points the original still wins. See the linked report
for the construction, full derivation, exact finite bound checker, benchmark
methodology, validation, and limitations. The rest of this document retains
the earlier four- and three-pass research and measurements.

## Three-pass result

Remove the rare sparse cancellation patterns before relying on a stronger
concentration bound. The first experiment does this by rejecting duplicate
unsigned bucket signatures. The improved experiment finds a small set of
inputs intersecting every dangerous assignment pattern and subgroup-checks
those inputs exactly. Both use the current accumulator without changing the
curve, encoding, or field arithmetic.

The improved experiment needs only three compression passes. At three
million inputs its bucket counts are `(131072, 16384, 16384)`, and each pass's
sums are checked with inner target 100. Its derived overall soundness bound
is at least 131.11 bits. Unlike assignment rejection, exact exceptions keep
the original independent assignment distribution and require no retries.

Earlier three-pass end-to-end medians, in milliseconds:

| Points | Current, target 128 | Four passes | Three, rejection | Three, exact exceptions | Speedup over current |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 1,000,000 | 1176.4 | 778.9 | 583.5 | 580.0 | 2.03x |
| 3,000,000 | 3136.8 | 1904.7 | 1580.7 | 1582.5 | 1.98x |

The exact-exception variant takes 25.5% and 16.9% less time than the
four-pass experiment at these sizes. Both three-pass variants are similar
on the sampled assignments: none required a retry or an exact exception.
The retry elimination and expectation bound are structural/proof results,
not measured tail-latency improvements in these samples.

The updated manual harness uses four seeds, `TestRng::new(0..4)`, reversing
algorithm order on alternate repetitions. Each algorithm starts from the
same seed within a repetition, so the two three-pass variants see the
same initial assignment. The input is distinct consecutive generator
multiples normalized before timing, as in the original measurements.
Times include conversion, all randomness, canonical sorting, graph checks,
compression, and inner verification. Measurements are single-threaded on
the same local Apple ARM machine with rustc 1.97.1 in release mode.

For three-pass exact exceptions at three million inputs, the median phase
times are about 15 ms conversion, 177 ms assignment/certificate, 1200 ms
compression, and 190 ms inner verification. The zero-exception code path
was measured; forced regression tests cover nonzero exceptions separately.
These are four manual runs, not a Criterion confidence interval. Other
platforms, parallel execution, small-batch crossover points for three
passes, and peak memory remain unmeasured. The benchmark is retained as
an ignored research test; a production benchmark should use Criterion and
the contributor guide's benchmark registration convention.

## Initial four-pass measurements

With four passes, 65,536 buckets per pass, and an 80-bit invocation of the
existing checker on each pass's sums, the derived overall soundness bound is
at least 129.66 bits for batches of at most three million points. The 80-bit
inner target is intentional; the proof concerns the composition of all four
passes, including assignment rejection.

Measured end to end, single-threaded on this checkout's local Apple ARM
machine, medians of three runs:

| Points | Current checker, 128-bit target | Four-pass experiment | Speedup |
| ---: | ---: | ---: | ---: |
| 100,000 | 136.1 ms | 224.4 ms | 0.61x |
| 1,000,000 | 1,149.6 ms | 755.1 ms | 1.52x |
| 3,000,000 | 3,058.1 ms | 1,843.8 ms | 1.66x |

The input consists of distinct consecutive generator multiples, normalized
before timing to match decoded points. Generation is excluded for both
algorithms. Timings include conversion, randomness, sorting to check
signature uniqueness, all accumulation, and verification of the compressed
sums. They are manual harness measurements, not a Criterion study. Arbitrary
projective inputs, other machines, and parallel execution were not measured.

At three million points, approximately 1.54 s is compression, 238 ms is inner
verification, 48 ms is assignment generation including duplicate detection,
and 15 ms is affine conversion. The fixed compressed-batch cost makes this a
large-batch technique; the existing checker wins at 100,000 points.

## Construction

Let `B = 2^16` and `d = 4`.

1. Draw an independent uniform 64-bit value for every input. Its four 16-bit
   limbs are the bucket indices for the four passes.
2. Sort a copy. If any values coincide, discard the entire assignment and
   draw again. Only unsigned bucket indices participate in this check.
3. Draw an independent random sign for every point in every pass.
4. In pass `j`, compute `S[j,b] = sum_{i: h[j,i]=b} sign[j,i] P[i]`.
   Every input contributes exactly once, including bucket zero.
5. Verify each pass's at most `B` sums using `batch_in_g1` with target 80
   and fresh randomness. Accept only if all four calls accept.

The prototype handles the same already-on-curve input as `batch_in_g1` and
drops identity inputs before assigning signatures. Its entry points assert
the three-million-point limit used below. It is not an API or an adaptive
replacement for the shipping planner.

## Why the old floor does not apply

The cancelling-pair lower bound for a single pass remains true. What does
not follow is a lower bound obtained by multiplying those probabilities
across passes after conditioning their assignments on uniqueness.

If only two points have nonzero cofactor parts, at least one pass puts them
in distinct buckets. Both resulting singleton buckets remain bad, whatever
their signs. Three bad points also cannot vanish in every pass: a pass can
have no singleton only if all three land in one bucket, which in every pass
would make their unsigned signatures identical.

Thus one, two, and three bad points cannot disappear during compression.
For four or more bad points, a stronger concentration bound applies. The
scheme deliberately removes the worst sparse cases before using that bound.
Ordinary independent bucketing does not have this property.

This is also why merely forbidding the zero coefficient vector, increasing
bucket widths, or rechecking a shared sum does not give the same result.

## Four-input concentration lemma

Work in the finite abelian cofactor group `H`, of odd order. For any nonzero
`T` in `H`, let `mu_T` be the distribution in `H^B` obtained by putting `+T`
or `-T` in one uniformly chosen bucket. Its `2B` outcomes are distinct and
equiprobable.

The probability that four independent samples from `mu_T` sum to zero is

```
K = (6 B + 24 choose(B,2)) / (2 B)^4
  = 3/(4 B^2) - 3/(8 B^3).
```

The first term counts four entries in one bucket with two signs of each
kind. The second counts two cancelling pairs in different buckets. Odd
order excludes every other possibility: the nonzero even coefficients
available here are only `+/-2` and `+/-4`.

For four possibly different nonzero inputs, Fourier inversion and Holder's
inequality bound every atom of their sum by `K`:

```
Pr[X1 + X2 + X3 + X4 = z]
  <= product_i (average_chi |hat(mu_Ti)(chi)|^4)^(1/4)
  = K.
```

The character average is normalized by `|H^B|`. Symmetry of `mu_T` makes
each fourth character moment exactly the return probability above.
Convolution with further independent inputs cannot increase the largest
atom. Therefore, for any fixed batch containing at least four bad points,
one unconditioned signed bucket pass produces entirely valid sums with
probability at most `K`. This argument does not assume cyclic cofactor
torsion or independent/adversary-random input points.

Similarly, Cauchy-Schwarz bounds the largest atom after two inputs by
`a = 1/(2B)`, since each input distribution has squared L2 norm `1/(2B)`.
This remains an upper bound after adding a third input.

## Soundness of the complete experiment

Fix all adversarial inputs before drawing randomness. Let `G` be the event
that the unsigned signatures are distinct. A union bound gives

```
Pr[G] >= g = 1 - n(n-1)/(2 B^4).
```

At `n = 3,000,000`, `g > 0.999999756`. Whole-assignment rejection samples
exactly the independent assignment distribution conditioned on `G`.
Consequently an unconditioned upper bound can be divided by `g`; independence
between passes is used before conditioning, not asserted afterward.

The inner target 80 requires at least 51 trit combinations, so use
`epsilon = 3^-51` for each inner check. An exact-check fallback has zero
error and also satisfies this bound.

For at least four bad inputs, each unconditioned pass accepts with
probability at most `K + epsilon`. The passes and their inner randomness
are independent before conditioning, yielding

```
Pr[accept | G] <= (K + epsilon)^4 / g < 2^-129.66.
```

For two or three bad inputs, event `G` guarantees at least one nonzero
compressed batch. Acceptance must therefore include at least one false
acceptance by an inner check. Union over which pass supplies that false
acceptance; each other unconditioned pass accepts with probability at most
`a + epsilon`:

```
Pr[accept | G] <= 4 epsilon (a + epsilon)^3 / g < 2^-129.83.
```

One bad input leaves all four passes bad and has error at most
`epsilon^4`. These cases exhaust all invalid batches. Their bounds are
alternatives according to the number of bad inputs, not errors to add.

The proof requires independent signs for each edge and fresh private
randomness for each batch and inner check. Reusing public bucket signatures
lets an attacker target the compression kernel and invalidates the argument.
Checking only signed-signature uniqueness is insufficient: opposite signs
can conceal equal unsigned signatures.

## A simpler composition, and why it is slower

An initial version concatenates all four bucket arrays and invokes the
existing checker once with target 129 (at least 82 trit combinations).
Its error bound is

```
K^4/g + 3^-82 < 2^-128.805
```

for the same size limit. Its measured median is 846 ms at one million and
1,951 ms at three million. The per-pass composition above reduces the inner
verification work and improves these to 755 ms and 1,844 ms. Both variants
are retained in the experiment to make this distinction reproducible.

## Three passes with a stronger assignment certificate

The same reasoning suggests excluding every stopping set of size below six,
using three signed bucket passes with `B = 2^15`. A stopping set here means
a set of input columns that creates no singleton bucket in any pass. This
is a property of bucket indices, independent of point values or signs.

For three-part columns, distinctness excludes size two and three. Excluding
size four also excludes size five: a size-five stopping set has at most two
buckets per part, so its distinct columns are a five-element subset of the
eight binary triples. Each such stopping set contains a size-four stopping
set. The experiment exhaustively checks this finite combinatorial claim.

The sixth-moment analogue of the lemma, maximized by order-three torsion, is

```
K6 = 15/(8 B^3) - 35/(16 B^4) + 21/(32 B^5).
```

It bounds every atom of six or more independently signed and bucketed bad
inputs. The additional order-three contribution comes from bucket
occupancies `3+3` and six equal-signed inputs in one bucket.

Reject assignments with duplicate columns or size-four stopping sets. A
union bound on their occurrence gives

```
g3 = 1 - choose(n,2)/B^3
       - choose(n,4) (3/B^2 - 2/B^3)^3.
```

At three million inputs `g3 > 0.7984`. With inner target 100, hence
`epsilon3 = 3^-64`, the analogous bounds are

```
small bad sets: 3 epsilon3 (1/(2B) + epsilon3)^2 / g3
large bad sets: (K6 + epsilon3)^3 / g3.
```

Numerically these give at least 131.52 and 131.95 bits respectively for the
same size limit. This three-pass verifier is implemented in
`src/bls12381/primitives/subgroup/research/three.rs` alongside a stronger
variant that handles exceptions exactly instead of rejecting assignments.

For completeness, the favorable sixth-moment assignment count is

```
22B + 220B(B-1) + 120B(B-1)(B-2), divided by (2B)^6.
```

The terms count bucket occupancies 6, 4+2 and 3+3, and 2+2+2. For an
order-three input, six signs in one bucket sum to zero in 22 ways; four
signs return in 6 ways; three in 2 ways; and two in 2 ways. Larger odd
orders cannot contribute additional returns. The Fourier/Holder argument
then bounds every atom for six arbitrary nonzero cofactor inputs, not just
six identical order-three inputs.

The hard part is certifying the assignment cheaply. A straightforward exact
certificate enumerates every pair of columns sharing their first bucket.
It encodes the symmetric differences of their other two bucket coordinates
as an exact 60-bit key and sorts those keys. Given distinct columns, a
duplicate key identifies a size-four stopping set.

The manual certificate benchmark measured:

| Inputs | Pair keys | Key storage | Draw + build + sort |
| ---: | ---: | ---: | ---: |
| 1,000,000 | 15,257,200 | 122 MB | 191 ms |
| 3,000,000 | 137,329,592 | 1,099 MB | 1,757 ms |

Both sampled assignments passed, so these numbers exclude retries. At three
million inputs, this certificate alone almost costs the whole four-pass
verifier. The next two changes address that algorithmic obstacle.

## Certify the graph without materializing all pair keys

Write each unsigned column as `(a,b,c)`. Build an exact relation mapping
`(b,c)` to its first coordinates `a`, then enumerate pairs sharing `a`.
For a pair `(a,b,c),(a,b',c')`, a matching pair can use the original two
`(b,c)` cells with a shared other first coordinate, or the crossed cells
`(b,c'),(b',c)` with any shared first coordinate. These are exact queries
against an open-addressing table containing full column values.

This rule alone is WRONG when `b=b'` or `c=c'`. Equal coordinates disappear
from the pair's incidence difference, so their values need not agree with
those of a matching pair. Maintain two separate global lists instead:
equal-b pairs are keyed only by their unordered c pair; equal-c pairs only
by their unordered b pair. A repeated key in either list is a stopping
set. The reviewer caught this omission in the initial join proposal with
the four columns `(0,0,0),(0,0,1),(1,1,0),(1,1,1)`. The Rust exhaustive
test failed before the repair and passes after it.

Two conservative membership filters fold b and c to 13 bits each. They
rule out most impossible joins before hash-table lookup. A filter can have
false positives but no false negatives, and every positive candidate is
confirmed exactly. Filters therefore do not change the certificate or its
probability distribution. The implementation sorts a copy to identify
duplicate columns before building the canonical relation.

This replaces the large pair-key array and its sort with a relation of
linear size plus two small expected-size degenerate-key lists. It still
enumerates `choose(n,2)/B_first` pairs in expectation: at fixed bucket
counts the pair-generation work is quadratic, not linear. The relation
uses 64 MiB at three million inputs and the two filters use 16 MiB;
canonical/grouped arrays, offsets, original assignments, and curve storage
are additional. Peak process memory has not been measured.

## Unequal bucket counts reduce certificate work

The proof does not require equal bucket counts. For three passes with
counts `B_j`, define `a_j=1/(2B_j)`, `K_j=K6(B_j)`, and `epsilon=3^-64`.
Under whole-assignment rejection, the same bounds become

```
g = 1 - choose(n,2)/product_j B_j
      - choose(n,4) product_j (3/B_j^2 - 2/B_j^3)
small = sum_j epsilon product_{k != j}(a_k + epsilon) / g
large = product_j(K_j + epsilon) / g.
```

Changing `(2^15,2^15,2^15)` to `(2^17,2^14,2^14)` preserves the product
of bucket counts but divides first-coordinate pair enumeration by four:
about 34.3 million instead of 137.3 million pairs at three million inputs.
It increases the total number of bucket sums, so inner verification becomes
more expensive. The measured tradeoff favors equal buckets at one million
and unequal buckets at three million; this is a manual choice, not a
finished planner. The larger first pass needs accumulator width 12 because
131072 exceeds `folded(11)=88574`.

At three million inputs, the unequal-shape rejection construction has
`g >= 0.7984986732762581`, with small/large-support bounds of 130.7910 and
131.9549 bits. The exact-exception variant below removes division by g.

## Exact exceptions preserve independence and eliminate retries

Draw all original unsigned columns independently ONCE. Mark every duplicate
column value and find a hitting set of the four-column stopping sets among
the distinct canonical columns: a hitting set contains at least one member
of every such set. The join implementation marks both endpoints of every
pair confirmed to participate in a stopping set. For degenerate-key
collisions it marks the endpoints of all pairs carrying that key. It scans
the full assignment, rather than stopping after the first match.

Exactly subgroup-check EVERY original input carrying a marked column value,
not just a representative of a duplicate column. Reject if any is invalid.
Otherwise draw independent signs and compress ALL original inputs using
their original columns, including the exact-checked inputs. Do not redraw
columns, repair individual columns, or remove selected inputs from the
compressed sums: the proof below uses those original independent sums.

Fix an invalid input batch before drawing randomness, and let k be its
number of nonzero cofactor parts. If all exact checks pass, every marked
input has zero cofactor part. For k from two through five, the remaining
bad columns are distinct and contain no four-column stopping set. They
therefore cannot vanish in every pass. Acceptance must contain at least
one inner false acceptance. Dropping the exact-check restrictions and
union-bounding over which pass falsely accepts gives

```
small = sum_j epsilon product_{l != j}(a_l + epsilon).
```

Independence is applied to the original, unconditioned assignments; there
is no conditioning denominator. With at least six bad original inputs,
acceptance is a subset of all three original compression passes accepting,
so `large = product_j(K_j + epsilon)`. With one bad input all three passes
remain bad and the error is at most `epsilon^3`. Fresh signs and inner
randomness can be regarded as sampled upfront even though the implementation
draws them after exact checks succeed.

| Shape | Small-support bound | Large-support bound |
| --- | ---: | ---: |
| `(2^15,2^15,2^15)` | 131.8526 bits | 132.2795 bits |
| `(2^17,2^14,2^14)` | 131.1157 bits | 132.2795 bits |

These alternative cases are not errors to add. The proof no longer depends
on a batch-size limit, although the prototype retains its three-million
input assertion for the measured allocation/performance scope. A union
bound on the implemented number of exact-checked original inputs is

```
E[checks] <= 2 choose(n,2)/product_j B_j
            + 4 choose(n,4) product_j (3/B_j^2 - 2/B_j^3).
```

This is below 0.551 at three million inputs for either shape. The first
term includes ALL copies of a duplicated code. It is an expectation over
the verifier's private random assignments, not a worst-case bound.

## Skeptical review and regressions

The independent subagent found no correctness blocker in the original
four-pass construction. It recomputed the finite-size probability bounds
using exact rational arithmetic, checked the rejection-conditioning and
inner-check composition arguments, and inspected the production sampler
and accumulator used by the prototype. It also caught the high-severity
false-negative case in the subsequently proposed join shortcut described
above. No defective certificate was wired into production.

After repair, the reviewer independently compared the join rule with direct
enumeration on all 17550 four-column and 80730 five-column subsets of the
ternary cube, plus unequal-coordinate universes. Integrated Rust tests
exhaust all ternary-cube four-sets and exercise hitting sets on seeded
multisets, including duplicates and unequal coordinate widths. Separate
tests force folded-filter collisions and demonstrate that candidates are
still checked exactly.

The reviewer added integer-convolution tests that enumerate every nonzero
input multiset of sizes four and six in `Z3` and the noncyclic group
`Z3 x Z3`. They check every output atom and attain the claimed two-bucket
maxima, `36/256` and `484/4096`. The four tests cover 5, 7, 330, and 1716
multisets. This supplements the original cyclic-group enumeration.

Two forced-path regressions address cases ordinary random tests almost
never reach. A valid canonical duplicate cannot conceal a later polluted
copy: checking rejects at the second exact check. The degenerate four-point
counterexample, polluted with `T,-T,-T,T` for an order-three point T, has
valid unsigned bucket sums in every pass, yet exact exceptions reject it.
Both tests verify rejection occurs before any signs are sampled. The
reviewer inspected the final helper and reran both tests successfully.
Another regression forces whole-vector rejection in the four-pass sampler.

No remaining material correctness concern was found by this agent review.
Finite tests cannot establish a cryptographic probability guarantee; the
derivation still requires independent expert review before promotion.

## Context and validation

[Spielman's linear-time encodable codes](https://www.cs.yale.edu/homes/spielman/PAPERS/linearTimeIT.pdf)
motivate looking outside independent combinations toward sparse encodings.
The construction above uses a much weaker certificate than a full
constant-distance code. A claim that a random code is typically good is
insufficient here: its bad-code probability must fit the cryptographic error
budget or be excluded by a checked certificate.

[Koshelev, El Housni, and Fotiadis](https://eprint.iacr.org/2025/1311)
study a different two-stage construction involving Tate tests and
endomorphisms. These experiments establish neither publication novelty nor
external cryptographic review of the proposed proof.

Run the focused correctness checks and manual measurements with:

```sh
just test -p commonware-cryptography --release --features bls12381 research::
just test -p commonware-cryptography --release --features bls12381 subgroup:: --test-threads 1
just clippy -p commonware-cryptography --release --features bls12381
just test -p commonware-cryptography --release --features bls12381 measure_sparse_compression --run-ignored only --no-capture
just test -p commonware-cryptography --release --features bls12381 measure_small_stopping_certificate --run-ignored only --no-capture
just test -p commonware-cryptography --release --features bls12381 measure_three_pass --run-ignored only --no-capture
```

Checks cover compression against direct group sums, cancellation and
doubling, order-three pollution in otherwise valid batches, the five-column
stopping-set lemma, and exhaustive four-input concentration in cyclic groups
of orders 3, 5, 9, and 11 with two buckets. These finite checks support the
derivation; they cannot empirically establish a 128-bit probability bound.

Final validation: all 49 subgroup tests passed, including 15 research tests;
release-mode crate Clippy passed; the final four-seed manual comparison
completed. The parallel test run reported two passing tests as leaky; the
complete serial rerun passed all 49 without that report. New research files
pass rustfmt, and `git diff --check` passes. Formatting the parent
`subgroup.rs` reports unrelated differences also present in HEAD; those were
left untouched.

The WASM build was attempted during the initial experiment but could not
compile because `wasm32-unknown-unknown` is not installed locally. No public
API, dependency, or unsafe code was added. Production subgroup-checking
logic is unchanged; its documentation now scopes the pass-count discussion
to independent combinations instead of claiming a universal nine-pass floor.
