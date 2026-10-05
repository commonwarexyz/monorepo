# commonware-simd

[![Crates.io](https://img.shields.io/crates/v/commonware-simd.svg)](https://crates.io/crates/commonware-simd)
[![Docs.rs](https://docs.rs/commonware-simd/badge.svg)](https://docs.rs/commonware-simd)

Abstract over SIMD operations.

## Backends

Native and array-backed emulated providers implement the same instruction contracts:

| Provider | Byte/u32/u64 lanes | Required instructions |
| --- | --- | --- |
| Scalar | 1/1/1 | None |
| NEON | 16/4/2 | Baseline AArch64 NEON |
| Armv9 | 16/4/2 | NEON, SVE, and SVE2; fixed 128-bit logical vectors |
| Ice Lake | 64/16/8 | AVX-512F, AVX-512BW, GFNI, and AVX-512IFMA |

The default `std` feature enables runtime detection. Without `std`, native
providers require the instruction bundle to be enabled at compile time.
Dispatch selects a supported native provider or falls back to scalar.

## Testing

Shared fuzz plans enter through `Dispatch` to check composition and compare the
selected native backend directly with its matching emulator on real hardware. Run
the fuzzer on each target platform to validate that platform's compiled instructions.
Emulator-specific unit
tests live in that backend's module and run independently of CPU support.
Operation variants can be compared separately with `check_consistent`.

Hardware coverage belongs in this crate so consumers using the modeled interface
can check their algorithms with emulation rather than repeat the hardware matrix.

Run `just test -p commonware-simd` for unit tests and bounded fuzz checks. The
`simd/fuzz` target uses the same plans for continuous fuzzing.

## Status

Stability varies by primitive. See [README](https://github.com/commonwarexyz/monorepo#stability) for details.
