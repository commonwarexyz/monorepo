# Two-pass subgroup compression on a fixed girth-eight graph

Research derivation, 2026-09-08. Implemented only in the test-only module
`src/bls12381/primitives/subgroup/research/two.rs`.
The argument and finite bounds were developed and independently checked by
agents. It has not received external cryptographic review or formal verification.
Production subgroup-checking logic is unchanged.

Follow-up: [certifying the recursive circuit](SUBGROUP_CASCADE.md) reduces
three-million-point runtime by another 13.6% in a new same-session comparison.
The construction and baseline proof below remain relevant; the measurements
here are historical and should not be mixed with the follow-up's timings.

## Measured result

The q=47 prototype replaces the three-pass experiment's assignment certificate
and three input accumulations with a uniform injection into a fixed graph and
two accumulations. Checking the two output arrays separately with inner target
111 is slightly faster than checking their concatenation at target 129. Both
compositions have a derived false-acceptance bound below `2^-128`.

Same-session end-to-end medians in milliseconds:

| Points | Original, target 128 | Three, exact exceptions | Two, joint 129 | Two, split 111 | Original / split |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 100,000 | 133.11 | 148.01 | 183.40 | 173.32 | 0.77x |
| 1,000,000 | 1130.07 | 560.75 | 520.28 | 500.42 | 2.26x |
| 3,000,000 | 3028.37 | 1527.10 | 1069.46 | 1047.94 | 2.89x |

At three million points, the split variant takes 31.4% less time than three
passes and 2.0% less than the joint two-pass check. Its four samples range from
1043.42 to 1052.59 ms. Median phase times are approximately 14.6 ms conversion,
26.1 ms assignment/sign generation, 762.0 ms compression, and 244.9 ms inner
verification. The important improvement is the outer construction; splitting
the inner check is a smaller additional gain. At one million points, the split
variant takes 10.8% less time than three passes. At 100,000 points the original
checker still wins.

The ignored `measure_two_pass` test uses four seeds, `TestRng::new(0..4)`, and
reverses algorithm order on alternate repetitions. Each algorithm starts from
the same seed within a repetition. Inputs are distinct consecutive generator
multiples normalized before timing; generation is excluded. All conversion,
allocation, randomness, accumulation, and inner verification are included.
Measurements are single-threaded on the local Apple ARM machine with rustc
1.97.1 in release mode. These are manual measurements, not Criterion confidence
intervals; use the contributor guide's benchmark registration convention for
a production benchmark.

```sh
just test -p commonware-cryptography --release --features bls12381 measure_two_pass --run-ignored only --no-capture
```

## Construction

Fix an odd prime q and work in F_q. The bipartite graph has q^3 vertices on each
side. Its edges are indexed by quadruples `(u,v,w,t)` and connect

```
(u,v,w)  --  (t, u*t-v, u*t*t-w), with arithmetic modulo q.
```

Thus the graph is simple, has M=q^4 edges, and is D=q regular. Each point has
exactly one neighbor for each t; each line has exactly one neighbor for each u.
This is the monomial graph G_q(xy,xy^2) described in Section 1 of
[Kronenthal, Monomial Graphs and Generalized Quadrangles](https://faculty.kutztown.edu/kronenthal/Research/MGGQ.pdf).
The elementary argument below supplies the girth property used here; no
embedding into a full generalized quadrangle is required.

For an input batch of n<=M already-on-curve points, sample a uniform injective
assignment of input indices to graph edges. The graph may be public and fixed;
the injection must be fresh private randomness. Draw TWO independent signs for
each input, one at each endpoint. Add the signed input to its left bucket and
its independently signed copy to its right bucket. This costs two point
contributions per input. The initial variant checks the concatenation of both
bucket arrays with the existing checker at target 129, using fresh randomness.
The faster variant checks each side separately at target 111 with independent
fresh inner randomness, accepting only if both checks pass. Its composition is
proved below; it does not assume independent left and right bucket placements.

Inputs are fixed adversarially before the injection is drawn. Their cofactor
parts lie in the same odd-order finite abelian group as in the existing proofs.
Removing identity inputs before sampling is harmless. Removing a subset chosen
after inspecting random assignments would require rechecking the argument.

## Why the graph has no four- or six-cycles

Two distinct points sharing a line must have different u coordinates; if u were
equal, the incidence equations force their other coordinates to agree. Dually,
two distinct lines through a point have different t coordinates.

In a four-cycle, subtracting the incidence equations gives
`(u1-u2)*(t1-t2)=0`, contradicting both differences being nonzero.

For a six-cycle, let the successive point first coordinates be u1,u2,u3 and
the successive line first coordinates t1,t2,t3. All three t values are distinct.
Set `delta_i=u_i-u_{i+1}`, cyclically. Summing the incidence equations around the
cycle gives

```
sum delta_i = sum delta_i*t_i = sum delta_i*t_i^2 = 0.
```

The three-by-three Vandermonde matrix on the distinct t values is invertible,
forcing every delta to zero, a contradiction. The graph is bipartite and simple,
so it has girth at least eight, which is all this proof needs.

## Fixed-support sign bound

Let k be the fixed number of nonzero cofactor inputs. Their assigned edges form
a uniform k-element subset of the M edges, independently of how many good input
points were also assigned. Conditional on that subset and the assignment of
cofactor values to its edges, a singleton occupied vertex cannot sum to zero.

At any occupied vertex, condition on all but one incident endpoint sign. The
remaining sign selects between two distinct values, since its cofactor input is
nonzero and has odd order. The vertex sum vanishes with probability at most 1/2.
Different vertices use disjoint endpoint-sign variables, giving conditional
probability at most `2^-v` for all v occupied vertices to vanish simultaneously.
This independence requires separate signs at BOTH endpoints of each edge.

A support that can vanish must therefore have minimum degree at least two.
Every connected component then contains a cycle, hence at least eight edges and
eight occupied vertices. Also `v>=ceil(2k/D)`, by the degree bound.

## Supports below twelve edges

For k=1 through 7 there is no support of minimum degree two. For k=8 it must be
an eight-cycle. For k=10 it must be a ten-cycle. The k=9 and k=11 cases are
impossible.

To justify the last assertions, two distinct cycles C1,C2 have at least eight
edges each; their nonempty symmetric difference is an even-degree subgraph
containing a cycle, hence also has at least eight edges. Therefore

```
|C1 union C2| = (|C1|+|C2|+|C1 symmetric_difference C2|)/2 >= 12.
```

A connected minimum-degree-two graph with at most eleven edges must consequently
be a single cycle. Bipartiteness excludes odd cycles. Disconnected supports
would require at least sixteen edges.

For any simple D-regular girth-at-least-eight graph with M edges,

```
C8 <= M*(D-1)^4/8.
```

Proof: a fixed root has D*(D-1)^3 nonbacktracking length-four paths, all simple.
For any endpoint there are at most D such paths, since fixing the first neighbor
leaves at most one length-three continuation to the endpoint; two would create
a cycle of length at most six. If m paths reach an endpoint, their unordered
pairs number at most `(D-1)*m/2`. Distinct paths to that endpoint are internally
disjoint, again by the girth bound, so each pair forms an eight-cycle. Sum over
the 2M/D roots and divide by eight roots per cycle.

A general simple-graph nonbacktracking path count also gives

```
C10 <= M*(D-1)^8/10.
```

There are at most `2M*(D-1)^8` oriented length-nine nonbacktracking paths. Their
closing edge, if present, is forced. Each ten-cycle appears twenty times.

The compression-failure bounds for these supports are therefore

```
P8  <= M*(D-1)^4 / (8*choose(M,8)*2^8)
P10 <= M*(D-1)^8 / (10*choose(M,10)*2^10).
```

## Intermediate supports: elementary line-graph counting

The line graph has M vertices and maximum degree Delta=2*(D-1). Let
`L=4*Delta=8*(D-1)`. The number of connected sets of s graph edges is at most

```
M*L^(s-1).
```

To see this, encode a rooted plane spanning tree of the corresponding connected
vertex set in the line graph. There are M root choices, at most `4^(s-1)` plane
tree shapes, and at most `Delta^(s-1)` choices for its child-neighbor edges.
Choose a deterministic spanning tree for each set; these encodings cover all
sets, while noninjective embeddings and multiple roots only overcount.

For a vanishing k-edge support with j components, every component has at least
eight edges and eight vertices. Overcount its ordered component sizes by all
positive compositions of k into j parts, of which there are `choose(k-1,j-1)`.
Multiplying the connected-set bounds, ignoring disjointness and the possible
division by j!, and applying the vertex-sign bound gives

```
P_k <= sum_{j=1}^{floor(k/8)}
       choose(k-1,j-1)*M^j*L^(k-j) / (256^j*choose(M,k)).
```

Let `c=floor(k/8)`. For the parameters below, `M/(256L)>1`; both the geometric
factor and `choose(k-1,j-1)` increase through j=c. Consequently the particularly
simple bound checked by the companion script is

```
P_k <= c*choose(k-1,c-1)*M^c*L^(k-c) / (256^c*choose(M,k)).
```

These bounds are uniform over the adversarial cofactor values; they depend only
on the number of bad inputs. The assignment of those values within the random
edge set need not be analyzed further.

## Exact finite verification and composition

Run the standard-library-only companion check:

```sh
python3 cryptography/src/bls12381/primitives/subgroup/research/two_bound.py
```

It compares rational probabilities using exact integers; floating point is used
only to print approximate bit counts. For each q it checks every integer k from
12 through `66D-1`. For k>=66D, the conditional vertex-sign bound is at most
`2^-132`, since at least 132 vertices are occupied.

| Parameter/result | q=47 | q=53 |
| --- | ---: | ---: |
| Buckets per side | 103823 | 148877 |
| M, maximum inputs | 4879681 | 7890481 |
| D | 47 | 53 |
| Eight-input bound, bits | 129.135023726055 | 133.280800717298 |
| Ten-input bound, bits | 147.307556687691 | 152.132477371516 |
| Intermediate range checked | 12 through 3101 | 12 through 3497 |
| Weakest intermediate bound, bits | 129.807253209963 at k=12 | 135.488195799712 at k=12 |
| Sign-only bound beyond that range | 132 bits | 132 bits |
| Total after joint inner target 129, bits | 128.491824750398 | 129.651551568887 |

The cases are alternatives according to k, not errors to sum. A single fresh
inner target 129 uses at least 82 trits, with error `epsilon=3^-82` uniformly for
every compressed batch. Total false acceptance is therefore bounded by

```
max(P8, P10, max_intermediate P_k, 2^-132) + 3^-82.
```

The script proves this is below `2^-128` by exact comparison for both parameters.
At q=47 the derived bound is approximately 128.4918 bits. This establishes the
mathematical bound for two original-input compression passes; the measurements
and implementation checks are separate evidence.

## Lower-cost composition: separate inner checks

Conditional on the unsigned injection, let p_L and p_R be the probabilities,
over their respective endpoint signs, that all cofactor sums on that side are
zero. To bound their expectations, condition on the assigned edges and endpoint
signs of every bad input except one. That last bad input is uniform over M-k+1
remaining edges. At most D of them touch any specified bucket, and its two
signed contributions are distinct because its cofactor part is nonzero and has
odd order. Every possible contribution vector therefore has probability at most

```
D / (2*(M-k+1)).
```

This bounds either side's probability of canceling the fixed contributions of
the other bad inputs. The conditioning is only on OTHER BAD INPUTS. Conditioning
on all good-input assignments would incorrectly replace k by n; their zero
cofactor contributions let their placements remain unconditioned.

For large k, each side has at least `ceil(k/D)` occupied vertices, and independent
endpoint signs give `p_side <= 2^-ceil(k/D)` for every injection. Split the cases
at k=tD. For k<tD use the preceding concentration bound, and otherwise use the
sign bound. A uniform upper bound for both E[p_L] and E[p_R] is

```
A = max(D/(2*(M-tD+2)), 2^-t).
```

Given the injection, left and right endpoint signs and the two fresh inner
random streams are independent. If each inner invocation has error at most
epsilon for every fixed invalid compressed batch, then

```
Pr[accept | injection] <= (p_L + epsilon)*(p_R + epsilon)
Pr[accept] <= E[p_L*p_R] + epsilon*E[p_L+p_R] + epsilon^2
           <= P_compression + 2*epsilon*A + epsilon^2.
```

The first term uses the joint graph compression bound already proved above,
not a product of marginal placement probabilities. Sequential evaluation and
early rejection preserve the argument: independent unused random streams can
be coupled to an execution that evaluates both sides. The implementation draws
the complete injection and both endpoint-sign arrays before invoking either
inner check.

Both target-111 calls use at least 71 trits each, so `epsilon=3^-71` suffices.
The companion script verifies the complete expression using exact rational
arithmetic, including every intermediate support size.

| Parameter/result | q=47 | q=53 |
| --- | ---: | ---: |
| t | 18 | 19 |
| Uniform one-side bound A | 47/9757674 | 53/15778952 |
| Inner target on each side | 111 | 111 |
| Derived total bound, bits | 128.165118548981 | 129.446504198433 |

These are composition bounds, not permission to use a 111-bit checker as a
standalone replacement for a 128-bit check.

## Implementation, validation, and limitations

The prototype uses exactly uniform partial Fisher-Yates sampling without
replacement, separate endpoint signs, the stated graph coordinates, all original
nonidentity inputs in both sums, and fresh inner randomness. Sampling independent
edge IDs with replacement would invalidate the small-support proof unless
collisions receive an additional sound treatment. The existing accumulator is
reused without changing production field or group arithmetic.

Eight new tests cover exact rejection sampling, all small partial-shuffle
injections, independent endpoint sign bits, exhaustive small-graph girth, all
edges' bounds/simplicity/regularity at q=47 and q=53, the exact `2^-8` cancellation
probability on an eight-cycle, direct group-sum agreement, and end-to-end checks
on adversarial order-three cofactor inputs. The last test exercises both graph
parameters and both inner-check compositions, with identities and cancellation
pairs included. Randomized regression tests do not establish a cryptographic
failure probability; the derivation and exact finite inequalities supply that
part of the evidence.

A skeptical subagent independently checked the combinatorial bound, the split
composition, and the implemented sampling and accumulation path. It found no
remaining implementation/proof discrepancy. Validation passed:

```sh
just test -p commonware-cryptography --release --features bls12381 subgroup:: --test-threads 1
just clippy -p commonware-cryptography --release --features bls12381
python3 cryptography/src/bls12381/primitives/subgroup/research/two_bound.py
```

All 57 selected tests passed. WASM validation remains unavailable because the
`wasm32-unknown-unknown` target is not installed. No public API, dependency,
namespace, encoded format, or production verification path changed.

The two passes output up to 207646 sums at q=47, so inner verification has more
work than in the three-pass prototype. The shuffle allocates a full q^4-element
u32 pool (about 19.5 MB at q=47), in addition to input, bucket, and ID storage;
total peak memory is unmeasured. The q=47 implementation accepts at most 4879681
input points, and q=53 at most 7890481. Larger batches can use another proved
parameter set or fixed chunks at the same per-chunk security target, accepting
only if every chunk accepts. Any invalid batch has a fixed invalid chunk, and
accepting the whole batch implies falsely accepting that chunk, so this
all-accept predicate needs no union-bound penalty. Chunking is not implemented
or benchmarked here.

Other platforms, parallel execution, arbitrary projective inputs, adversarial
latency distributions, and crossover thresholds remain unmeasured. Production
integration needs size-based selection retaining the original small-batch path,
independent expert review, and broader performance validation. The next research
targets are reducing the fixed inner-verification cost and the bucket working
set, without weakening the outer compression bound. Neither two passes nor the
current graph size is claimed as a universal lower bound.
