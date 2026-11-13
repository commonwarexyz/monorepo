# Splitting off the order-three component

Research against `63a7a9bad`, 2026-09-08. This experiment does NOT improve the
complete G1 subgroup checker yet. Production verification is unchanged.
The new test-only `research/primary.rs` checks just the order-three component;
points with other cofactor components deliberately pass it.

## Result and scope

BLS12-381 admits a homomorphism that replaces curve additions with field
multiplications when checking its order-three component. The prototype takes
292.07 ms at three million points, versus 922.24 ms for the current complete
graph/certificate checker in the same session. These implement DIFFERENT
predicates, so this is not a 3.16x subgroup-checking speedup.

The potential architecture is a cheap order-three check plus a different
check for the remaining cofactor. A straightforward additive cost comparison
leaves approximately 630 ms for that residual check at three million points.
Shared preprocessing could change this estimate. No sufficiently cheap
complete residual check has been derived or implemented here.

The partial checker has a derived false-acceptance bound below `2^-128` only
when some input has a nonzero order-three component. An explicit order-eleven
fixture proves that this statement cannot be read as G1 subgroup soundness.
Inputs must already be on-curve and fixed before fresh private verifier
randomness is sampled.

## The map

For the curve `y^2=x^3+4`, let `T=(0,2)`, which has order three. Define alpha
with values in the nonzero field elements modulo cubes:

```
alpha(O) = 1,
alpha(T) = 1/4,
alpha(x,y) = y-2 otherwise.
```

The general descent map appears in Definition 1.3 and Proposition 1.4 of
[Cohen and Pazuki, Elementary 3-Descent with a 3-Isogeny](https://arxiv.org/html/0903.4963).
The critical reviewer read that source in full. Its setting is elliptic curves
over number fields and rank estimation, not BLS verification. The finite-field
argument below is a direct derivation, not an application of its rank formulas.

If three nonexceptional points lie on `y=m*x+c`, substituting the line into
the curve yields the monic polynomial

```
x^3-m^2*x^2-2*m*c*x+4-c^2.
```

Evaluating at `(2-c)/m` shows that the product of their three `y-2` values is
`(c-2)^3`; the horizontal case is immediate. Their curve sum is the identity,
so this is the required multiplicative relation modulo cubes. For a vertical
line, `alpha(P)*alpha(-P)=-x^3`, also a cube.

For a line through T, write `y=m*x+2`. Its other two intersection coordinates
satisfy `x_P*x_R=-4*m`, so their representatives multiply to `-4*m^3`.
Multiplying by `alpha(T)=1/4` gives a cube. Tangencies are covered by repeated
roots. The remaining exceptional relations follow from
`(1/4)^2/(-4)=-1/64` and `(1/4)*(-4)=-1`. Thus alpha is a homomorphism.

For ordinary points, `(y-2)(y+2)=x^3`, so `y+2` represents the inverse class
without a field inversion. The vanishing representative at T, or the inverse
representative at -T, must be replaced: 16 works because `16/(1/4)=4^3`.
Using zero would be incorrect. Identity inputs are removed by the existing
affine conversion before the prototype evaluates representatives.

## Exactly which errors are visible

With p the BLS base-field modulus, define

```
chi(P) = alpha(P)^((p-1)/3).
```

This maps into the three cube roots of unity. Exact arithmetic gives

```
chi(T) = 0x5f19672fdf76ce51ba69c6076a0f77eaddb3a93be6f89688de17d813620a00022e01fffffffefffe.
```

It is a nonidentity cube root, so chi is onto. The curve order is `r*h`, with
`h=3*(11*10177*859267*52437899)^2` and exactly one factor of three. Therefore
multiplication by three has a three-element kernel, its image has index three,
and

```
ker(chi) = [3]E(Fp).
```

In other words, chi sees exactly the order-three component, while all other
cofactor components are invisible. The remaining cofactor is
`h/3=25443201128072175343902036600697491001`.

The exact-arithmetic diagnostic constructs `Q=(4,sqrt(68))` and verifies that
`P=[3]Q` has `chi(P)=1` but `[r]P!=O`. It also constructs a nonzero point of
exact order eleven. The Rust fixture decodes that point and independently
checks its order; adding it to subgroup points still passes the partial filter
but fails the complete effective-certificate checker.

## Multiplicative batching

The partial checker uses the full q47 graph from the
[two-pass construction](SUBGROUP_TWO_PASS.md): 4,879,681 possible edges,
103,823 buckets per side, a fresh uniform injection, and two independent
endpoint signs per input. A bucket now multiplies `y-2` or `y+2` representatives
instead of adding signed curve points. Its character is exactly the character
of the original signed curve sum.

Each side is then checked with 71 fresh random-trit combinations, corresponding
to inner target 111. The fixed width schedule is seven width-nine rounds and
one width-eight round. The folded-ternary circuit also works multiplicatively:
products replace sums, and squaring replaces negation MODULO CUBES. Squaring
is not inversion in the full multiplicative field group. The circuit's
intermediate field representatives need not equal a literal inverse-based
calculation; their characters must agree.

For example the collapse is

```
L[a] = S[a] * S[H+a] * S[H-a]^2 modulo cubes.
```

Each recovered combination gets one cube-character exponentiation. The
ordinary inner bound is `3^-71`; the original full-graph split composition
therefore applies unchanged to this order-three quotient. `two_bound.py`
reproduces a total bound of 128.165118548981 bits. No assertion about the
remaining cofactor follows from this bound.

## Same-session measurements

End-to-end medians in milliseconds, four seeds, on the same local Apple ARM
machine with rustc 1.97.1, release mode, one thread:

| Points | Original complete checker | Current complete graph checker | Order-three-only filter |
| ---: | ---: | ---: | ---: |
| 100,000 | 137.23 | 100.71 | 68.39 |
| 1,000,000 | 1154.77 | 366.64 | 139.57 |
| 3,000,000 | 3091.34 | 922.24 | 292.07 |

The final column is intentionally incomplete. Its four three-million-point
samples are 293.143, 291.093, 293.050, and 288.985 ms, in seed order. Approximate
median phase times are 14.9 ms conversion, 26.4 ms assignment/sign generation,
192.4 ms field-product compression, and 58.8 ms inner verification.

The harness uses distinct consecutive generator multiples normalized before
timing, excluding input generation. Conversion, allocations, all randomness,
compression, and final checks are timed. Algorithm order is reversed on odd
repetitions. These are manual measurements, not confidence intervals; timings
from earlier reports belong to different sessions and are not compared here.
The `measure_order_three` driver selects IDs `[0,9,20]`, with 20 explicitly
labeled `component=order_three_only`. Complete-only comparisons have separate
drivers, so the partial predicate cannot be mistaken for their replacement.

## Why this is not yet a complete speedup

A complete per-point criterion is `chi(P)=1` together with `[3]P` in G1.
Tripling removes the order-three part and is invertible on the remaining
cofactor. A residual batch verifier can triple only its final linear
combinations, not every original point. But running the existing graph
algorithm this way does not make its input accumulations cheaper.

More decisively, the dominant eight-cycle cancellation is not peculiar to
order three. Put eight identical nonzero order-eleven errors on a cycle.
At each vertex the two signs must differ, giving exactly `2^-8` probability
that all eight sums vanish. The diagnostic enumerates all 65,536 endpoint-sign
assignments and finds 256 acceptances. Every input has trivial cubic character,
so the partial filter cannot improve this residual failure probability.

I also tested three accumulation reorganizations: whole-batch stable radix
partitioning, 65,536-point windowed partitioning, and copy-free filtered scans.
They preserve the signed sums, but none established a useful gain. At three
million points the best whole-batch median was 918.43 ms versus its 891.27 ms
baseline; the best windowed median was 913.88 ms versus 896.29 ms. Copy-free
scanning ranged from 927.21 to 1319.53 ms versus 923.94 ms, with noticeable
session drift and no convincing win. Each comparison used four seeds and
reversed order. These timings come from separate sessions. The slower code
was removed from the branch; a temporary archive retains the experiment.

## Validation and next question

All 73 focused subgroup tests passed in release mode with one test thread.
Release Clippy and both exact-arithmetic diagnostics listed below passed.

The critical agent reviewed the finite-field map, exceptional representatives,
exponent constant, multiplicative collapse, randomness, and composition.
Tests verify `3*CUBE_EXPONENT+1=p`, signed torsion and group-law cases, an
independent coefficient oracle including actual widths eight/nine, malicious
order-three batches, and deliberate order-eleven false positives. Additional
regressions verify that both complete outer graph variants reject order-eleven
pollution, including single and paired errors.

The diagnostic exhausts all curve-point pairs for ten small primes and checks
the BLS constants and counterexamples with exact arithmetic. It also exhibits
other curves where the equality `ker(chi)=[3]E` fails, preventing an unwarranted
generalization of the BLS-specific kernel argument.

```sh
just test -p commonware-cryptography --release --features bls12381 subgroup:: --test-threads 1
just clippy -p commonware-cryptography --release --features bls12381
python3 cryptography/src/bls12381/primitives/subgroup/research/descent_bound.py
python3 cryptography/src/bls12381/primitives/subgroup/research/two_bound.py
just test -p commonware-cryptography --release --features bls12381 measure_order_three --run-ignored only --no-capture
```

This remains agent-reviewed research, not external cryptographic review or
formal verification. No public API, dependency, encoding, namespace, unsafe
code, or production verifier was changed. WASM validation requires the missing
`wasm32-unknown-unknown` target. Other platforms, arbitrary projective-input
performance, and adversarial latency have not been measured.

The next structural question is whether the residual cofactor can be checked
substantially more cheaply than another pair of full curve accumulations.
This work establishes a measured, correct partial building block, a concrete
counterexample to treating it as a complete subgroup check, and an obstruction
to shrinking the residual graph merely by removing order-three errors. It
does not establish a new lower bound or a faster complete checker.
