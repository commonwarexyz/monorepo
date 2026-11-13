# commonware-cryptography-bls12381

[![Crates.io](https://img.shields.io/crates/v/commonware-cryptography-bls12381.svg)](https://crates.io/crates/commonware-cryptography-bls12381)
[![Docs.rs](https://docs.rs/commonware-cryptography-bls12381/badge.svg)](https://docs.rs/commonware-cryptography-bls12381)

BLS12-381 cryptography: the groups [`G1`] and [`G2`], their scalar field [`Scalar`], and the pairing into the target group [`GT`], with SIMD arithmetic selected for the host CPU at run time.

## Status

Stability varies by primitive. See [README](https://github.com/commonwarexyz/monorepo#stability) for details.

## Usage

Operators need no imports and take their right operand by reference: `a + &b`, `a - &b`, and `-a` in [`G1`], [`G2`], and [`Scalar`]; `p * &k` for an element `p` of [`G1`] or [`G2`] and a [`Scalar`] `k`; `a * &b` in [`Scalar`] and [`GT`]; and `==`. The other operations are methods of the algebra traits of [commonware-math](https://docs.rs/commonware-math); import the traits whose methods you call:

- [`G1`] and [`G2`]: [`CryptoGroup::generator`], [`Additive::zero`], [`Additive::double`], [`Additive::scale`], and [`Space::msm`].
- [`Scalar`]: [`Field::inv`], [`Ring::exp`], [`Multiplicative::square`], [`FieldNTT`] for roots of unity, and [`Random::random`] for sampling. The inherent [`Scalar::from_bytes`] and [`Scalar::to_bytes`] convert the canonical big-endian encoding, as do the traits of [commonware-codec](https://docs.rs/commonware-codec).
- [`GT`]: [`Multiplicative::square`]. [`GT::ONE`] is the identity.

Operations over slices cost less per element than the same operation repeated on single elements, so prefer them when the inputs are available together:

- [`G1::sum`] and [`G2::sum`] add many elements, as when aggregating keys or signatures.
- [`G1::mul_each`] and [`G2::mul_each`] multiply each element by its own scalar.
- [`Space::msm`] returns the sum of the elements times their scalars, as in threshold recovery or batch verification.

Each takes a strategy of [commonware-parallel](https://docs.rs/commonware-parallel). [`Sequential`] runs the operation on the calling thread. `Rayon`, which needs the `std` feature of commonware-parallel, decides at each call whether to split the operation into batches that run on several threads.

Three functions compute pairings, and the two over several pairs take a strategy as well:

- [`multi_pairing`] returns the product of the pairings of several pairs with one final exponentiation, so it costs less than multiplying separate pairings. Use it for verification equations: check `e(a, b) = e(c, d)` as `multi_pairing(&[(a, b), (-c, d)], &Sequential)` equal to [`GT::ONE`].
- [`pairings`] computes the pairings of independent pairs, as when verifying many signatures separately, at less cost per pair than [`pairing`].
- [`pairing`] returns a single pairing.

## Guarantees

Elements of [`G1`], [`G2`], and [`GT`] arise only from the generators through the group operations and pairings, so every element lies in the subgroup of prime order `r`. The crate does not decode elements of [`G1`] or [`G2`] from bytes.

Multiplication of an element by a scalar (`*`, [`Additive::scale`], and `mul_each`) runs in time independent of the scalar's value, as does arithmetic in [`Scalar`] except [`Ring::exp`] and [`Additive::scale`] on a [`Scalar`], whose running time depends on the exponent or multiplier. [`Space::msm`] runs in variable time: its running time and memory accesses depend on the scalars, which must therefore be public, as Lagrange coefficients in threshold recovery and random weights in batch verification are. The pairing functions skip pairs that contain an identity element, so their running time depends on which inputs are the identity.

## Example

```rust
use commonware_cryptography_bls12381::{G1, G2, GT, Scalar, multi_pairing, pairing};
use commonware_math::algebra::{CryptoGroup, Space};
use commonware_parallel::Sequential;

// A public key in G1 and a signature in G2 on a message point `h`.
let secret = Scalar::from_u64(42);
let public = G1::generator() * &secret;
let h = G2::generator() * &Scalar::from_u64(7);
let signature = h * &secret;

// Check e(public, h) = e(generator, signature) with one product of pairings.
assert_eq!(
    multi_pairing(&[(public, h), (-G1::generator(), signature)], &Sequential),
    GT::ONE
);
assert_eq!(pairing(&public, &h), pairing(&G1::generator(), &signature));

// 2 G + 3 public = (2 + 3 * 42) G.
let points = [G1::generator(), public];
let scalars = [Scalar::from_u64(2), Scalar::from_u64(3)];
assert_eq!(
    G1::msm(&points, &scalars, &Sequential),
    G1::generator() * &Scalar::from_u64(2 + 3 * 42)
);
```

## Features

- `std` (default): links the standard library; without it the crate is `no_std`.
- `fuzz`: exposes the module `fuzz` of fuzzing operations.

## Benchmarks

Times of this crate on one thread, with its speedup over [blst](https://github.com/supranational/blst) 0.3.16 on the same inputs and its speedup under a `Rayon` strategy of 8 and of 16 workers, measured on 2026-11-13.

The speedup over blst is blst's time divided by this crate's, so blst is faster where it is below 1. Both libraries take projective points. blst's sums, multi-scalar multiplications, and pairings take affine points, so its times for them include the conversion. The speedup with workers is the time on one thread divided by the time with that many workers. The operations on single elements take no strategy.

### Zen 5

AMD EPYC 9R45 (AWS c8a.4xlarge, 16 cores), rustc 1.99.1. The crate uses the residue number system over AVX-512 IFMA.

| Operation | Time | Speedup over blst | Speedup with 8 workers | Speedup with 16 workers |
| --- | --- | --- | --- | --- |
| G1 addition | 354 ns | 1.29x | - | - |
| G1 doubling | 274 ns | 0.73x | - | - |
| G1 multiplication by a scalar | 23.3 us | 2.39x | - | - |
| G1 multiplication of 128 elements by their own scalars | 1.83 ms | 3.90x | 7.6x | 13.9x |
| G1 sum of 1024 elements | 123 us | 2.96x | 4.4x | 4.9x |
| G1 multi-scalar multiplication, 8 elements | 84.1 us | 3.04x | 2.8x | 3.0x |
| G1 multi-scalar multiplication, 128 elements | 853 us | 2.39x | 5.0x | 8.2x |
| G1 multi-scalar multiplication, 2048 elements | 8.54 ms | 2.17x | 5.6x | 9.7x |
| G2 addition | 791 ns | 1.59x | - | - |
| G2 doubling | 599 ns | 0.76x | - | - |
| G2 multiplication by a scalar | 31.1 us | 3.69x | - | - |
| G2 multiplication of 128 elements by their own scalars | 4.59 ms | 3.20x | 7.7x | 14.8x |
| G2 sum of 1024 elements | 315 us | 3.23x | 5.9x | 6.5x |
| G2 multi-scalar multiplication, 8 elements | 162 us | 4.07x | 2.9x | 4.1x |
| G2 multi-scalar multiplication, 128 elements | 1.55 ms | 3.82x | 5.0x | 8.3x |
| G2 multi-scalar multiplication, 2048 elements | 16.3 ms | 3.28x | 5.6x | 9.6x |
| Pairing | 108 us | 3.92x | - | - |
| 16 independent pairings | 1.66 ms | 4.08x | 7.4x | 13.1x |
| Product of 2 pairings | 136 us | 3.99x | 1.1x | 1.1x |
| Product of 16 pairings | 535 us | 4.09x | 3.0x | 3.5x |
| Product of 128 pairings | 3.79 ms | 4.16x | 6.8x | 9.6x |

### M4 Max

Apple M4 Max (10 performance cores and 4 efficiency cores), rustc 1.98.1. The crate uses 28-bit limbs over NEON.

| Operation | Time | Speedup over blst | Speedup with 8 workers | Speedup with 16 workers |
| --- | --- | --- | --- | --- |
| G1 addition | 1.71 us | 0.22x | - | - |
| G1 doubling | 1.13 us | 0.15x | - | - |
| G1 multiplication by a scalar | 170 us | 0.27x | - | - |
| G1 multiplication of 128 elements by their own scalars | 5.50 ms | 1.05x | 7.0x | 6.7x |
| G1 sum of 1024 elements | 319 us | 0.96x | 3.7x | 2.3x |
| G1 multi-scalar multiplication, 8 elements | 239 us | 0.94x | 1.2x | 1.1x |
| G1 multi-scalar multiplication, 128 elements | 2.12 ms | 0.78x | 4.4x | 3.4x |
| G1 multi-scalar multiplication, 2048 elements | 19.8 ms | 0.72x | 5.1x | 4.2x |
| G2 addition | 5.72 us | 0.17x | - | - |
| G2 doubling | 3.32 us | 0.11x | - | - |
| G2 multiplication by a scalar | 452 us | 0.19x | - | - |
| G2 multiplication of 128 elements by their own scalars | 14.5 ms | 0.77x | 7.2x | 7.3x |
| G2 sum of 1024 elements | 1.17 ms | 0.68x | 4.7x | 3.4x |
| G2 multi-scalar multiplication, 8 elements | 788 us | 0.70x | 1.5x | 1.5x |
| G2 multi-scalar multiplication, 128 elements | 7.33 ms | 0.59x | 4.5x | 4.1x |
| G2 multi-scalar multiplication, 2048 elements | 73.9 ms | 0.54x | 5.3x | 4.8x |
| Pairing | 1.68 ms | 0.21x | - | - |
| 16 independent pairings | 6.59 ms | 0.80x | 3.8x | 3.7x |
| Product of 2 pairings | 1.68 ms | 0.24x | 1.0x | 1.0x |
| Product of 16 pairings | 3.10 ms | 0.51x | 1.7x | 1.7x |
| Product of 128 pairings | 17.2 ms | 0.67x | 5.0x | 4.5x |

Several effects keep the speedups below the count of workers:

- A strategy cuts batches of whole groups of lanes. A group holds four elements on the M4 Max, so 16 pairs make at most four batches there.
- A product of pairings runs its final exponentiation on one thread.
- Each batch of a multi-scalar multiplication repeats the doublings and bucket sums that one thread does once.
- A sum of 1024 elements of G1 takes 123 us on the Zen 5 and 319 us on the M4 Max, so the time to hand its batches to eight workers holds its speedup to 4.4x and 3.7x.
- Sixteen workers outnumber the 14 cores of the M4 Max.

Run the benchmarks of this crate with `cargo bench -p commonware-cryptography-bls12381`. The operations over slices run under 1 and 8 workers, and under 1, 2, 4, 8, and 16 with `COMMONWARE_BENCH_FULL=1`.

## Parameters

On x86-64 CPUs with the x86v4c instruction profile of [commonware-simd](https://docs.rs/commonware-simd) (AVX-512 with AVX-512IFMA, GFNI, and SHA), base field arithmetic uses a residue number system whose tables a script generates. Regenerate or check them from the workspace root:

```sh
python3 cryptography/bls12381/scripts/parameters.py
python3 cryptography/bls12381/scripts/parameters.py --check
```

The generator checks the tables against a model of the arithmetic and checks accumulator, rounding, and representation bounds with integer arithmetic.

## Test Vectors

The known answers for multiples of the generators and for the pairing of the generators are generated from their definitions with integer arithmetic. Regenerate or check them from the workspace root:

```sh
python3 cryptography/bls12381/scripts/vectors.py
python3 cryptography/bls12381/scripts/vectors.py --check
```

## References

- [VROOM](https://eprint.iacr.org/2026/393), the residue arithmetic design.

See [NOTICE](https://github.com/commonwarexyz/monorepo/blob/main/cryptography/bls12381/NOTICE) for source attribution.

[`G1`]: https://docs.rs/commonware-cryptography-bls12381/latest/commonware_cryptography_bls12381/struct.G1.html
[`G2`]: https://docs.rs/commonware-cryptography-bls12381/latest/commonware_cryptography_bls12381/struct.G2.html
[`GT`]: https://docs.rs/commonware-cryptography-bls12381/latest/commonware_cryptography_bls12381/struct.GT.html
[`Scalar`]: https://docs.rs/commonware-cryptography-bls12381/latest/commonware_cryptography_bls12381/struct.Scalar.html
[`G1::sum`]: https://docs.rs/commonware-cryptography-bls12381/latest/commonware_cryptography_bls12381/struct.G1.html#method.sum
[`G2::sum`]: https://docs.rs/commonware-cryptography-bls12381/latest/commonware_cryptography_bls12381/struct.G2.html#method.sum
[`G1::mul_each`]: https://docs.rs/commonware-cryptography-bls12381/latest/commonware_cryptography_bls12381/struct.G1.html#method.mul_each
[`G2::mul_each`]: https://docs.rs/commonware-cryptography-bls12381/latest/commonware_cryptography_bls12381/struct.G2.html#method.mul_each
[`GT::ONE`]: https://docs.rs/commonware-cryptography-bls12381/latest/commonware_cryptography_bls12381/struct.GT.html#associatedconstant.ONE
[`Scalar::from_bytes`]: https://docs.rs/commonware-cryptography-bls12381/latest/commonware_cryptography_bls12381/struct.Scalar.html#method.from_bytes
[`Scalar::to_bytes`]: https://docs.rs/commonware-cryptography-bls12381/latest/commonware_cryptography_bls12381/struct.Scalar.html#method.to_bytes
[`multi_pairing`]: https://docs.rs/commonware-cryptography-bls12381/latest/commonware_cryptography_bls12381/fn.multi_pairing.html
[`pairing`]: https://docs.rs/commonware-cryptography-bls12381/latest/commonware_cryptography_bls12381/fn.pairing.html
[`pairings`]: https://docs.rs/commonware-cryptography-bls12381/latest/commonware_cryptography_bls12381/fn.pairings.html
[`Additive::zero`]: https://docs.rs/commonware-math/latest/commonware_math/algebra/trait.Additive.html
[`Additive::double`]: https://docs.rs/commonware-math/latest/commonware_math/algebra/trait.Additive.html
[`Additive::scale`]: https://docs.rs/commonware-math/latest/commonware_math/algebra/trait.Additive.html
[`CryptoGroup::generator`]: https://docs.rs/commonware-math/latest/commonware_math/algebra/trait.CryptoGroup.html
[`Field::inv`]: https://docs.rs/commonware-math/latest/commonware_math/algebra/trait.Field.html
[`FieldNTT`]: https://docs.rs/commonware-math/latest/commonware_math/algebra/trait.FieldNTT.html
[`Multiplicative::square`]: https://docs.rs/commonware-math/latest/commonware_math/algebra/trait.Multiplicative.html
[`Random::random`]: https://docs.rs/commonware-math/latest/commonware_math/algebra/trait.Random.html
[`Ring::exp`]: https://docs.rs/commonware-math/latest/commonware_math/algebra/trait.Ring.html
[`Space::msm`]: https://docs.rs/commonware-math/latest/commonware_math/algebra/trait.Space.html
[`Sequential`]: https://docs.rs/commonware-parallel/latest/commonware_parallel/struct.Sequential.html
