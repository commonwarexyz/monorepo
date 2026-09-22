# Joint G1 decoding and interleaved root extraction

The test-only prototype in
[`decompression.rs`](src/bls12381/primitives/subgroup/research/decompression.rs)
reduces measured serial decoding plus 128-bit subgroup checking by **54% at
100,000 points (2.17x faster)** without increasing the encoded size. The latest
three-point representation saves another 22% over the interleaved pair decoder.
Decoding alone is 2.78x faster than standard compression. It changes the batch
encoding; it cannot accelerate already serialized standard compressed points.
No production codec or public API is changed.

## Algorithm

Use Koshelev's [joint compression for curves of j-invariant
0](https://eprint.iacr.org/2020/010.pdf), specialized to BLS12-381 G1. For a
generic pair, encode `X = x0/x1` and `Y = y0/y1`. Recover

```text
u = 4(1 - Y^2)/(Y^2 - X^3) = x1^3
v = u + 4                 = y1^2
Z = u^2 v^3              = (x1 y1)^6
```

One sixth root `z` of `Z` yields `x1 = uv/z^2` and `y1 = z/x1`;
multiply by the ratios to recover the other point. Three selector bits identify
the desired member of the six-element automorphism orbit. An extra mode bit
handles pairs in the same orbit using one full point and the relative
automorphism. Two 381-bit field elements plus four bits fit in 96 bytes.

The generic pair therefore needs one field exponentiation instead of two.
The prototype batches denominator inversions and normalizes Jacobian
`(uv, uv^2, z)` coordinates with the existing batch-affine helper. An odd final
point uses the existing 48-byte compressed encoding.

## Root extraction in this prototype

Write `p - 1 = 18m`. For this modulus, `m = 5 mod 6`, so the integer
`e = (p + 17)/108` satisfies `6e = m + 1`. Compute `r = Z^e`. If `Z` is a
sixth power, then `r^6/Z = Z^m` is a cube root of unity. Trying
`r`, `r*zeta`, and `r*zeta^2`, where `zeta` has order nine, finds a root.
Every candidate is checked by computing its sixth power. Failure rejects the
input; a product of unrelated radicands is never used to certify individual
points.

The fixed sliding-window schedule costs 371 squarings and 75 multiplications
before the root checks: 370 scheduled squarings after the initial power,
one precomputation squaring, 15 table multiplications, and 60 window
multiplications. A unit test verifies the integer identity `108e = p + 17`.
Field tests cover sixth powers, nonsquares, and non-sixth-power squares.

## Batching the sixth roots

The optional interleaved path, `decode_pairs_with::<true>`, uses
[`batch.rs`](src/bls12381/primitives/subgroup/research/decompression/batch.rs).
It executes each exponentiation step on four independent inputs before moving
to the next step. The exponentiation's arithmetic count is unchanged, but
independent chains let the CPU overlap field operations rather than wait on
one chain's result.
This is single-core instruction overlap, not a thread pool or a shared root
of the product. Four lanes keep the power table small; more lanes gave little
additional improvement on this machine.

The correction also computes `r^6` only once. Replacing `r` by `r*zeta`
updates its sixth power with one multiplication by the precomputed `zeta^6`.
Each individual result still passes an exact sixth-power check before it is
used as a curve point. The tests compare both decoding paths on mixed orbit
cases, short final chunks, malformed inputs, and subgroup nonmembers.

For 20,000 sixth powers, medians of seven runs with rotated method order:

| Method | Root extraction |
| --- | ---: |
| Original independent roots | 179.403 ms |
| One lane, cheaper correction | 177.639 ms |
| Two lanes | 129.190 ms |
| Four lanes | 128.419 ms |
| Eight lanes | 128.467 ms |
| Sixteen lanes | 127.546 ms |

Four lanes improve root extraction by **1.40x**. The correction alone is a
small part of this improvement. Reproduce with:

```sh
just test -p commonware-cryptography --release \
  decompression::batch::measure_root_batching --run-ignored only --no-capture
```

Montgomery's product trick does not directly give the individual roots. For
example, `zeta` and `zeta^-1` are not sixth powers, although their product is
one. A regression test rejects both even though the product has a root.
Knowing a product of roots also does not provide the factors needed to recover
each one, unlike inversion where the original inputs are those factors.

## Three points per sixth root

[`triple.rs`](src/bls12381/primitives/subgroup/research/decompression/triple.rs)
implements Koshelev's later
[batch-compression construction](https://eprint.iacr.org/2021/1446.pdf)
specialized to BLS12-381 G1. A rational change of coordinates represents the
first two points by two fields `z0, z1` and a cube-root selector. Store the third
point's `x2` as the third field. Recover

```text
t  = (z1^2 - 4)/z0^2 = x0/x1
y0 = z1 - 2(z0 - z1)t - z0 t^2
y1 = z1 - 2z0 + (2z1 - z0)/t
A  = x2^3 + 4       = y2^2
B  = y1^2 - 4       = x1^3
R  = A^3 B^2        = (y2 x1)^6
```

One sixth root `r` gives `x1 = AB/r^2` and `y2 = r^3/(AB)`, then `x0 = tx1`.
Three selector bits choose the cube-root rank of `x1` and the sign of `y2`.
Generic triples occupy exactly 144 bytes and use one exponentiation, with four
independent roots interleaved. Both inversion stages use batch inversion.

Exceptional first pairs (`y0^2 = y1^2`, or the forward map's `z0` numerator is
zero) use the pair format plus one standard compressed point, also 144 bytes.
Bit 7 of the second field marks this fallback. The decoder only accepts this
mode for exceptional pairs and rejects generic encodings of same-orbit pairs,
preventing alternate representations. Tests include both exceptional conics,
all six same-orbit cases, mixtures, incomplete triples, and deliberate aliases.
One or two trailing points use the pair format. Every decoded point passes its
curve equation before subgroup checking.

The same five-run methodology, comparing all three formats in one run:

| Points | Standard decode + check | Pair decode + check | Triple decode + check | Triple speedup over standard |
| ---: | ---: | ---: | ---: | ---: |
| 1,000 | 12.667 ms | 9.132 ms | 7.861 ms | 1.61x |
| 6,000 | 59.156 ms | 37.448 ms | 30.378 ms | 1.95x |
| 100,000 | 866.752 ms | 512.035 ms | 399.257 ms | 2.17x |

At 100,000 points, decoding alone takes 730.491 ms with standard compression,
376.390 ms with pairs, and 262.711 ms with triples. Triples save 30.2% of pair
decoding time and 22.0% of pair decoding plus subgroup-check time.

```sh
just test -p commonware-cryptography --release \
  decompression::triple::measure_triple_decoding --run-ignored only --no-capture
```

## Earlier pair measurements

Local arm64 macOS, Rust 1.97.1, optimized release build. Times are medians of
five serial runs, with method order rotated each repetition. Point generation
and encoding are excluded; parsing, allocations, curve validation, and the
existing `batch_in_g1(..., 128, ...)` are included. Both formats encode the same
distinct consecutive generator multiples; encoding and decoding are checked
against the original points before timing.

Combined decoding and 128-bit subgroup checking:

| Points | Standard encoding | Joint, independent roots | Joint, four root lanes | Speedup over standard |
| ---: | ---: | ---: | ---: | ---: |
| 1,000 | 12.175 ms | 9.959 ms | 8.602 ms | 1.42x |
| 6,000 | 57.528 ms | 44.562 ms | 36.526 ms | 1.57x |
| 100,000 | 866.463 ms | 641.458 ms | 509.869 ms | 1.70x |

The 100,000-point decoding-only times from the same run:

| Method | Decode only |
| --- | ---: |
| Standard encoding | 725.788 ms |
| Joint encoding, independent roots | 506.106 ms |
| Joint encoding, four root lanes | 374.760 ms |

Interleaving reduces joint decoding time by 26.0% and combined time by 20.5%.
Against the standard encoding, decoding is 1.94x faster. This Rust prototype
invokes blst's public field operations for each exponentiation step; the
existing square-root implementation uses a specialized assembly squaring
chain. Fewer exponentiations and independent instruction chains both matter.
These results do not measure parallel decoding, sender cost, or network latency.

Reproduce with:

```sh
just test -p commonware-cryptography --release decompression::
just test -p commonware-cryptography --release \
  decompression::measure_joint_decoding --run-ignored only --no-capture
```

## Validation and integration limits

The prototype rejects noncanonical field elements, invalid selector bits,
reserved flags, invalid lengths, zero denominators, invalid root candidates,
infinity, and off-curve points. Tests cover all six same-orbit cases, odd
tails, mutations, and order-eleven nonmembers, including a nonmember mixed into
a 1,000-point batch. Accepted mutated encodings must re-encode identically.

Validation on this machine: all 758 tests selected by the crate's default
nextest profile passed (56 skipped), including twelve focused decoding/root
tests. Clippy and formatting checks passed. The initial prototype's Miri run
passed the integer exponent test but could not execute field/group tests
because blst's foreign functions and generator static are unsupported. The
WASM build was attempted with the installed nightly WASM target, but the local
C compiler cannot compile blst for `wasm32-unknown-unknown`. These environment
limitations remain; the interleaved and triple paths introduce no additional
unsafe code.

Decoding alone establishes curve membership. The full subgroup check still
follows it, with its existing soundness bound. Production use would require
fresh private randomness; fixed seeds here are only for reproducible tests and
benchmarks.

Adoption requires a separately identified batch format and enclosing message
length limits. Individual point bytes differ from the standard codec, and
random access requires decoding the containing pair or triple. The current G1 codec
remains unchanged. New public encoded types would also need codec conformance
fixtures and the appropriate stability annotation.

If the existing bytes must remain compatible, this algorithm does not apply.
Montgomery inversion batching alone does not recover independent square roots.
The current blst square root already uses a fixed addition chain; further
compatible work would need to target its arithmetic implementation, instruction
overlap across points, or repeated-point reuse. The measured algorithmic gain
above comes specifically from changing the joint representation.
