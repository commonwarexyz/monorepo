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
- [`Space::msm`] returns the sum of the elements times their scalars, as in threshold recovery or batch verification. Its strategy decides whether it runs on the calling thread ([`Sequential`]) or splits the work into batches of at least 256 elements that run in parallel (`Rayon`, with the `std` feature of [commonware-parallel](https://docs.rs/commonware-parallel)).

Three functions compute pairings:

- [`multi_pairing`] returns the product of the pairings of several pairs with one final exponentiation, so it costs less than multiplying separate pairings. Use it for verification equations: check `e(a, b) = e(c, d)` as `multi_pairing(&[(a, b), (-c, d)])` equal to [`GT::ONE`].
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
    multi_pairing(&[(public, h), (-G1::generator(), signature)]),
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

Times of this crate and of [blst](https://github.com/supranational/blst) 0.3.16 on the same inputs, on one thread, measured on 2026-11-12:

- Zen 5: AMD EPYC 9R45 (AWS c8a.4xlarge), rustc 1.99.1. The crate uses the residue number system over AVX-512 IFMA.
- M4 Max: Apple M4 Max, rustc 1.98.1. The crate uses 28-bit limbs over NEON.

The speedup is blst's time divided by this crate's, so blst is faster where it is below 1. Both libraries take projective points. blst's sums, multi-scalar multiplications, and pairings take affine points, so its times for them include the conversion.

| Operation | Zen 5: commonware | Zen 5: blst | Zen 5: speedup | M4 Max: commonware | M4 Max: blst | M4 Max: speedup |
| --- | --- | --- | --- | --- | --- | --- |
| G1 addition | 321 ns | 458 ns | 1.43x | 1.63 us | 348 ns | 0.21x |
| G1 doubling | 273 ns | 202 ns | 0.74x | 1.10 us | 156 ns | 0.14x |
| G1 multiplication by a scalar | 23.5 us | 56.1 us | 2.39x | 167 us | 45.3 us | 0.27x |
| G1 multiplication of 128 elements by their own scalars | 1.85 ms | 7.17 ms | 3.88x | 5.45 ms | 5.79 ms | 1.06x |
| G1 sum of 1024 elements | 123 us | 364 us | 2.96x | 323 us | 300 us | 0.93x |
| G1 multi-scalar multiplication, 8 elements | 90.9 us | 258 us | 2.84x | 240 us | 208 us | 0.87x |
| G1 multi-scalar multiplication, 128 elements | 885 us | 2.06 ms | 2.33x | 2.08 ms | 1.56 ms | 0.75x |
| G1 multi-scalar multiplication, 2048 elements | 8.94 ms | 18.6 ms | 2.08x | 19.5 ms | 14.3 ms | 0.73x |
| G2 addition | 739 ns | 1.26 us | 1.71x | 5.50 us | 927 ns | 0.17x |
| G2 doubling | 615 ns | 459 ns | 0.75x | 3.24 us | 408 ns | 0.13x |
| G2 multiplication by a scalar | 31.4 us | 116 us | 3.68x | 449 us | 87.8 us | 0.20x |
| G2 multiplication of 128 elements by their own scalars | 4.62 ms | 14.8 ms | 3.20x | 14.5 ms | 11.2 ms | 0.78x |
| G2 sum of 1024 elements | 319 us | 1.03 ms | 3.23x | 1.20 ms | 796 us | 0.67x |
| G2 multi-scalar multiplication, 8 elements | 164 us | 658 us | 4.02x | 788 us | 498 us | 0.63x |
| G2 multi-scalar multiplication, 128 elements | 1.60 ms | 5.84 ms | 3.66x | 7.19 ms | 4.30 ms | 0.60x |
| G2 multi-scalar multiplication, 2048 elements | 17.5 ms | 54.1 ms | 3.10x | 72.4 ms | 39.4 ms | 0.54x |
| Pairing | 109 us | 427 us | 3.92x | 1.67 ms | 318 us | 0.19x |
| 16 independent pairings | 1.68 ms | 6.83 ms | 4.07x | 6.45 ms | 5.15 ms | 0.80x |
| Product of 2 pairings | 137 us | 543 us | 3.97x | 1.67 ms | 396 us | 0.24x |
| Product of 16 pairings | 535 us | 2.19 ms | 4.10x | 3.09 ms | 1.59 ms | 0.51x |
| Product of 128 pairings | 3.80 ms | 15.8 ms | 4.16x | 17.0 ms | 11.4 ms | 0.67x |

Run the benchmarks of this crate with `cargo bench -p commonware-cryptography-bls12381`.

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
