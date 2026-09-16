# commonware-cryptography-vroom

[![Crates.io](https://img.shields.io/crates/v/commonware-cryptography-vroom.svg)](https://crates.io/crates/commonware-cryptography-vroom)
[![Docs.rs](https://docs.rs/commonware-cryptography-vroom/badge.svg)](https://docs.rs/commonware-cryptography-vroom)

Perform vectorized prime-field arithmetic using VROOM's residue number system.

Sealed modulus types provide validated parameters for the BLS12-381 coordinate and scalar fields, Bandersnatch scalar field, and Curve25519 coordinate field. The `rns` module provides bounded arithmetic with delayed reduction and expansion through portable and AVX-512 IFMA kernels.

## Status

Stability varies by primitive. See [README](https://github.com/commonwarexyz/monorepo#stability) for details.

## Parameters

Regenerate or check the sealed parameter tables from the workspace root:

```sh
python3 cryptography/vroom/scripts/parameters.py
python3 cryptography/vroom/scripts/parameters.py --check
```

The generator checks accumulator and rounding bounds with integer arithmetic.

## References

- [VROOM](https://eprint.iacr.org/2026/393), the residue arithmetic design.
- [blst](https://github.com/supranational/blst), the basis for modular inversion and a differential test oracle.

See [NOTICE](NOTICE) for source attribution.
