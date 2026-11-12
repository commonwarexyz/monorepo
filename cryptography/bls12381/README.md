# commonware-cryptography-bls12381

[![Crates.io](https://img.shields.io/crates/v/commonware-cryptography-bls12381.svg)](https://crates.io/crates/commonware-cryptography-bls12381)
[![Docs.rs](https://docs.rs/commonware-cryptography-bls12381/badge.svg)](https://docs.rs/commonware-cryptography-bls12381)

BLS12-381 cryptography: the groups G1 and G2, their scalar field, and the pairing into the target group GT, with SIMD arithmetic selected for the host CPU at run time.

The groups and the scalar field implement the algebra traits of [commonware-math](https://docs.rs/commonware-math), so code written against those traits works with them. Operations over slices (sums, multiplications of many elements by their own scalars, multi-scalar multiplications, optionally in parallel, and pairings of many pairs) cost less per element than repeating the single operation. A product of pairings costs less than the pairings it multiplies. Multiplication by a scalar runs in constant time; multi-scalar multiplication runs in variable time and takes public scalars only. See the [crate documentation](https://docs.rs/commonware-cryptography-bls12381) for usage and an example.

## Status

Stability varies by primitive. See [README](https://github.com/commonwarexyz/monorepo#stability) for details.

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

See [NOTICE](NOTICE) for source attribution.
