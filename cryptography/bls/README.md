# commonware-cryptography-bls

[![Crates.io](https://img.shields.io/crates/v/commonware-cryptography-bls.svg)](https://crates.io/crates/commonware-cryptography-bls)
[![Docs.rs](https://docs.rs/commonware-cryptography-bls/badge.svg)](https://docs.rs/commonware-cryptography-bls)

Perform BLS12-381 and Banderwagon arithmetic, pairings, and BLS signatures.

The curve families share [VROOM field arithmetic](../vroom), with portable, ARM NEON, and AVX-512 IFMA kernels. The `bls12381` module provides G1/G2, pairings, and MinPk/MinSig signing; `banderwagon` provides the quotient group and its scalar field.

On little-endian 64-bit Linux AArch64, BLS12-381 points use six-limb Montgomery coordinates for group arithmetic, scalar multiplication, MSM, and pairings. Recovery coefficient construction and reciprocal roots in hash-to-curve use the same backend; the remaining hash-to-curve field arithmetic uses VROOM residues.

## Status

Stability varies by primitive. See [README](https://github.com/commonwarexyz/monorepo#stability) for details.

## References

- [VROOM](https://eprint.iacr.org/2026/393), the residue arithmetic design.
- [blst](https://github.com/supranational/blst), the basis for the curve and pairing formulas and the differential test oracle.

See [NOTICE](NOTICE) for source attribution.
