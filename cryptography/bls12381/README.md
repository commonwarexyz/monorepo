# commonware-cryptography-bls12381

[![Crates.io](https://img.shields.io/crates/v/commonware-cryptography-bls12381.svg)](https://crates.io/crates/commonware-cryptography-bls12381)
[![Docs.rs](https://docs.rs/commonware-cryptography-bls12381/badge.svg)](https://docs.rs/commonware-cryptography-bls12381)

BLS12-381 cryptography.

## Status

Stability varies by primitive. See [README](https://github.com/commonwarexyz/monorepo#stability) for details.

## Parameters

On x86v4c, base field arithmetic uses a residue number system whose tables are generated. Regenerate or check them from the workspace root:

```sh
python3 cryptography/bls12381/scripts/parameters.py
python3 cryptography/bls12381/scripts/parameters.py --check
```

The generator checks the tables against a model of the arithmetic and checks accumulator, rounding, and representation bounds with integer arithmetic.

## References

- [VROOM](https://eprint.iacr.org/2026/393), the residue arithmetic design.

See [NOTICE](NOTICE) for source attribution.
