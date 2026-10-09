#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://commonware.xyz/imgs/rustdoc_logo.svg",
    html_favicon_url = "https://commonware.xyz/favicon.ico"
)]
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(test)]
extern crate std;

// Consumer primitive inventory.
// Ocelot reference: PR #4823, commit b6b08b0f7aa59805a38a12e98108010f993a7877:
// https://github.com/commonwarexyz/monorepo/blob/b6b08b0f7aa59805a38a12e98108010f993a7877/coding/src/ocelot/kernel/avx512.rs
// Curve references: cryptography/curve25519/src/curve/{avx512,neon}.rs.
// A dash means the operation is unused by that kernel, not unsupported by the architecture.
//
// | Operation | Ocelot AVX-512 | curve25519 AVX-512 | curve25519 NEON |
// | --- | --- | --- | --- |
// | Full unaligned load/store | 64 byte lanes | 8 u64 lanes | 2 u64 lanes |
// | Zero-filled partial load / partial store | Masked epi32 memory operations; 4-byte prefix granularity | - | - |
// | Zero and scalar broadcast | Repeated byte constants | Zero and repeated u64 constants | Zero and repeated u64 constants |
// | Bitwise XOR | Field addition and accumulation | - | - |
// | Horizontal byte XOR | Checksum reduction; currently store then fold | - | - |
// | Bitwise AND | - | Limb masks | Limb and digit masks |
// | Bitwise OR | - | - | Recombine reduced digits |
// | Wrapping u64 add/subtract | - | Field arithmetic and carries | Field arithmetic and carries |
// | Immediate logical u64 shifts | - | Carries, scaling, product reconstruction | Carries, digit splitting, scaling |
// | Wrapping u32 addition and immediate left shift | - | - | Scale multiplication digits |
// | GF(256) byte multiplication | gf2p8mul_epi8; vector and broadcast-constant operands | - | - |
// | IFMA52 low/high multiply-accumulate | - | madd52lo_epu64, madd52hi_epu64 | - |
// | Truncating u64 -> u32 narrowing | - | - | vmovn_u64; also shift-then-narrow |
// | Unsigned widening u32 * u32 -> u64 | - | - | vmull_u32; scalar-constant variant |
// | Widening multiply-accumulate into u64 | - | - | vmlal_u32 |
// | Selection | - | Whole-u64-lane mask blend | Bitwise select, currently whole-lane masks |
// | Lane insertion/extraction | - | - | Pack/unpack two field elements at boundaries |
//
// Ocelot uses the AES polynomial basis (modulus 0x11b), matching GFNI multiplication directly.
// Its GF16 algorithms compose GF8 multiplication and XOR over two byte planes; they do not
// require integer widening or GFNI affine transforms. The current PR has portable and AVX-512
// kernels only. An Ocelot NEON instruction schedule remains to be chosen.
//
// IFMA multiplies the low 52 bits of each source, selects the low or high 52-bit product half,
// and adds into the full wrapping u64 accumulator. NEON widening consumes two u32 lanes and
// produces two u64 lanes; narrowing truncates rather than saturating. Model lane-mask blending
// separately from bitwise selection with arbitrary partial masks.
//
// Ocelot currently requires AVX-512F + GFNI, and curve25519 requires AVX-512F + IFMA. Ocelot's
// dword-masked memory operations avoid requiring AVX-512BW. Check any additional feature
// requirements when introducing new instructions. Field reduction, GF16 multiplication,
// butterflies, and curve formulas remain algorithms built from these primitives. Scaling by
// 19 can use shifts and additions, with native code generation checked against existing kernels.

commonware_macros::stability_scope!(ALPHA {
    #[cfg(test)]
    mod operation_tests;
    mod consistency;
    pub use consistency::check_consistent;
    mod core;
    pub use core::{ArmV9, IceLake, Neon, Operation, Simd};
    mod dispatch;
    pub use dispatch::{dispatch, test_dispatch};
    pub mod emulated;
    pub mod native;
    #[cfg(any(test, feature = "fuzz"))]
    pub mod fuzz;
});
