# Preparing recurring 100,000-point subgroup checks

Test-only research against `f0c02cb92`, 2026-09-08. Production verification is
unchanged. The workload is recurring batches of about 100,000 points, with
input-independent work permitted before a batch arrives.

## Result

Precomputation reduces online latency, but the fused block accumulator does
not improve this workload. The best measured candidate keeps the generic
outer accumulator and prepares both recursive verification circuits in advance.

Eight-sample medians in milliseconds, from one comparison session:

| Variant | Preparation | Online | Total |
| --- | ---: | ---: | ---: |
| Current complete graph checker | 0 | 98.18 | 98.18 |
| Fused blocks, outer preparation only | 1.90 | 99.64 | 101.57 |
| Fused blocks, complete preparation | 18.36 | 83.92 | 102.40 |
| Generic accumulator, complete preparation | 18.56 | 81.30 | 99.92 |

The last row has 17.2% lower online latency, with slightly MORE total work.
This is not a throughput improvement on one continuously busy core. It is
useful when preparation fits before arrival, or can run on separate resources;
concurrent preparation and verification have not been benchmarked.

A second experiment actually prepares the circuit BEFORE constructing each
new input batch. Its medians are 98.08 ms for the baseline and 81.31 ms online
for the prepared checker, with 18.60 ms preparation and 99.90 ms total. Input
generation is excluded from both timings. The first preparation in this run
takes 33.71 ms; it is retained in the samples, not silently discarded.

The second experiment's prepared online samples, in seed order, are 81.639,
81.628, 81.519, 81.565, 81.110, 81.055, 80.658, and 80.910 ms. Baseline samples
are 101.143, 98.259, 98.075, 98.025, 98.218, 98.081, 97.767, and 97.325 ms.

## Fused block prototype

The q47 graph maps `(u,v,w,t)` to the two vertices

```
left  = (u, v, w)
right = (t, u*t-v, u*t*t-w), with field arithmetic modulo 47.
```

For fixed `(u,t)`, varying `(v,w)` visits each vertex of the two respective
slabs exactly once. This is a matching: no two edges write the same output.
Each slab contains 47^2 affine points, so the two slabs contain 424,128 bytes
of point data. This count excludes inputs, schedules, and inversion buffers.

There is also a direct coloring. For degree D, color a block by `(u+t) mod D`.
Within one color, each u and each t occurs exactly once. All blocks of that
color therefore have disjoint outputs on BOTH sides. The prototype groups
indices by color and then u, sharing inversion batches across blocks and
flushing at color boundaries. Flushing at every small block was slower.

`two::blocks::Accumulator` updates both sides while visiting an input index.
It reuses the existing field arithmetic and shared-inversion implementation,
including doubling and cancellation handling, but needs no collision retry
lists. It allocates exactly two graph-side slot arrays: 18.24 MB for the
truncated graph, versus the generic outer round's 38.26 MB of affine slots.
These are buffer-size calculations, not measured peak resident memory.

The schedule is built AFTER the uniform injection and endpoint signs are
drawn. It changes neither the assignment nor either sign. Reordering preserves
each signed curve sum, including identities. Fusing execution still performs
two algebraic accumulations; it does not halve the number of curve additions.

Despite the smaller scratch and collision-free schedule, it loses at 100K.
The current measurement does not isolate the contributions of scattered input
reads, scheduling, and arithmetic. No larger-batch speedup is established here.
The prototype remains as a reproducible comparison, not a replacement default.

## What can be prepared

The one-shot preparation contains the outer assignment and signs, both q19
inner graph assignments, the final 63-trit coefficient matrices, exact-exception
indices, and initially allocated scratch. Curve sums and actual subgroup tests
cannot be evaluated until the points arrive.

The key change is to give every possible inner output bucket a fixed position
in the final coefficient matrix. An empty or cancelled bucket still has its
sampled column; its POINT is the identity. This makes the complete effective
matrix independent of point data, so its zero and duplicate-up-to-sign columns
can be detected during preparation.

Online execution compacts nonidentity inputs and graph outputs, retaining their
original dense indices. It selects coefficients at those original indices;
it does not renumber the prepared matrix. Original inputs marked by the
certificate are checked exactly. Marked identity slots are already valid.
The prepared path also passes affine outer slots directly to the inner checker,
avoiding a projective wrapper followed by another affine copy.

The generic control deliberately retains `Round` and its larger scratch. This
separates the effect of preparing the circuit from the effect of changing the
accumulator. Its remaining inner verification costs about 69.5 ms in the
arrival experiment; outer accumulation costs about 11.5 ms.

## Soundness and one-shot use

Precomputation requires the batch to be independent of the prepared challenge.
The assignment, coefficients, and all derived challenge information must remain
private until the input batch is fixed. Sampling earlier is compatible with
the probability argument only under that independence condition. This is NOT
permission to publish challenges or reuse them for later adaptive batches.
Each prototype's `check` consumes its preparation and draws no new randomness
for the fully prepared path. Preparation types are private research types with
no cloning API; this is not a production secret-storage or zeroization design.

Preparing for n points and subsequently dropping identities uses the first m
assigned edges for the m surviving points. Restricting a uniform injection to
a fixed prefix is still uniform. The batch determines m independently of the
private assignment. Both implementations enforce the prepared input length.

Each inner graph is now sampled for all 94,987 outer bucket positions, even
when some positions will hold identities. This is below the q19 capacity of
130,321. The graph's stopping-support bounds concern nonzero cofactor inputs,
so adding identity positions does not invalidate them. Keeping all final
columns also leaves the final distribution at 63 independent random trits.

The effective integer coefficients remain in [-2,2]. Therefore the same
[BLS12-381 minor argument](SUBGROUP_CASCADE.md#breakthrough-certify-the-effective-recursive-circuit)
excludes one- and two-input errors whenever exact exceptions pass. Identity
compaction does not alter these integer coefficients: multiplying a retained
coefficient by the identity contributes zero to the same full circuit.

The unmodified q19 bound remains below `3^-61`, and the truncated outer
composition retains its derived 128.194076795566-bit bound. No security
parameter or graph size is reduced. The existing exact-arithmetic scripts
reproduce these inequalities. This is an extension of the research argument,
not independent cryptographic review or formal verification.

## Validation and reproduction

All 79 focused subgroup tests, release Clippy, and the two exact-arithmetic
bound scripts below passed. WASM validation remains blocked by the missing
`wasm32-unknown-unknown` target. No production logic, public API, dependency,
encoding, or unsafe code was changed.

New tests exhaust the block matching property for q19 and both q47 graphs,
check schedule permutations and disjoint outputs, and compare fused sums with
both direct group addition and the generic accumulator. Dense blocks exercise
multiple full inversion queues, signs, repeated points, doubling, and complete
cancellation. End-to-end tests include order-three and order-eleven pollution,
single and paired errors, empty batches, and interleaved identities.

The prepared-circuit oracle forces cancelled inner buckets and an absent
original input, compares all dense graph sums, then compares every final curve
combination against an independent ternary-digit calculation. Forced zero and
duplicate columns verify exact checking of original dense input indices.

The benchmarks use eight seeds, `TestRng::new(0..8)`, reversing algorithm order
on alternate repetitions. Inputs are distinct consecutive generator multiples,
normalized before verification. All preparation, allocation, verification,
and destruction of the consumed preparation are included in their respective
timed calls. Component medians need not add to the median total.

Measurements are single-threaded release runs on the local Apple ARM machine,
with rustc 1.97.1. These manual samples are not confidence intervals. They do
not establish projective-input performance, adversarial tail latency, peak
memory, other-platform performance, or concurrent pipeline throughput.

```sh
just test -p commonware-cryptography --release --features bls12381 subgroup:: --test-threads 1
just clippy -p commonware-cryptography --release --features bls12381
python3 cryptography/src/bls12381/primitives/subgroup/research/effective_bound.py
python3 cryptography/src/bls12381/primitives/subgroup/research/truncated_bound.py
just test -p commonware-cryptography --release --features bls12381 measure_blocks --run-ignored only --no-capture
just test -p commonware-cryptography --release --features bls12381 measure_prepared_arrival --run-ignored only --no-capture
```
