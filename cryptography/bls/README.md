# commonware-cryptography-bls

[![Crates.io](https://img.shields.io/crates/v/commonware-cryptography-bls.svg)](https://crates.io/crates/commonware-cryptography-bls)
[![Docs.rs](https://docs.rs/commonware-cryptography-bls/badge.svg)](https://docs.rs/commonware-cryptography-bls)

Perform BLS12-381 and Banderwagon arithmetic, pairings, and BLS signatures.

The curve families share [VROOM field arithmetic](../vroom), with portable and AVX-512 IFMA kernels. The `bls12381` module provides G1/G2, pairings, and MinPk/MinSig signing; `banderwagon` provides the quotient group and its scalar field.

## Status

Stability varies by primitive. See [README](https://github.com/commonwarexyz/monorepo#stability) for details.

## Batch subgroup checks

The [batch subgroup soundness note](src/bls12381/group/subgroup.md) explains the G1/G2 construction and its per-call error bound. Check its exact parameter inequalities from the workspace root:

```sh
python3 cryptography/bls/scripts/subgroup.py
```

The private [joint G1 decoding experiments](BATCH_DECODE.md) combine pair/triple
wire encodings with this checker and benchmark the complete receiver pipeline.

## References

- [VROOM](https://eprint.iacr.org/2026/393), the residue arithmetic design.
- [blst](https://github.com/supranational/blst), the basis for the curve and pairing formulas and the differential test oracle.

See [NOTICE](NOTICE) for source attribution.
