//! aarch64 NEON and SHA2 reference models (DESIGN.md §9.2, initial coverage).
//!
//! **Vector representation (§9.2).** A NEON typed vector is an array of its
//! lanes with lane 0 at the lowest address, exactly what `vld1q_*` loads from
//! memory on a little-endian target:
//!
//! | stdarch type   | model type       | core type            |
//! | -------------- | ---------------- | -------------------- |
//! | `uint8x16_t`   | [`Uint8x16`]     | `Array(U8, 16)`      |
//! | `uint8x8_t`    | [`Uint8x8`]      | `Array(U8, 8)`       |
//! | `uint32x4_t`   | [`Uint32x4`]     | `Array(U32, 4)`      |
//! | `uint16x8_t`   | [`Uint16x8`]     | `Array(U16, 8)`      |
//! | `uint64x2_t`   | [`Uint64x2`]     | `Array(U64, 2)`      |
//! | `uint32x2_t`   | [`Uint32x2`]     | `Array(U32, 2)`      |
//!
//! Arm pseudocode's `Elem[V, e, esize]` is lane `e`; `V<32e+31:32e>` of a
//! 128-bit register is lane `e` of the `u32` view. Byte order between the
//! `u8` and `u32` views is little-endian (`vreinterpretq_u32_u8`), which is the
//! only supported configuration: variants are gated on
//! `target_endian = "little"` (§9.2 out of scope: big-endian).
//!
//! **Immediates** (stdarch `const N: i32` generics) are ordinary `i32`
//! arguments. rustc rejects out-of-range immediates at compile time; the models
//! panic on them (in the kernel such an application is ill-typed/stuck).
//!
//! **Loads and stores** are modeled on typed arrays, matching the generated
//! load/store helpers of §9.2 (`load_u8x16(a: &[u8; 16])`): a load returns
//! the array's elements as lanes and a store returns the array to be written.
//!
//! [`neon`] holds the data-movement and integer lane operations, [`sha2`]
//! the SHA-256 instructions (SHA256H, SHA256H2, SHA256SU0, SHA256SU1),
//! [`neon2`] the byte/halfword/doubleword lane operations of plan O10
//! (compares, table lookup, narrowing shifts, reductions, 64-bit and
//! widening arithmetic) and [`sha3`] the FEAT_SHA3/FEAT_SHA512 instructions.
#![forbid(unsafe_code)]

pub mod neon;
pub mod neon2;
pub mod sha2;
pub mod sha3;

pub use neon::*;
pub use neon2::*;
pub use sha2::*;
pub use sha3::*;

/// `uint8x16_t`: sixteen `u8` lanes, lane 0 at the lowest address.
pub type Uint8x16 = [u8; 16];

/// `uint8x8_t`: eight `u8` lanes (a 64-bit D register), lane 0 lowest.
pub type Uint8x8 = [u8; 8];

/// `uint32x4_t`: four `u32` lanes, lane 0 at the lowest address.
pub type Uint32x4 = [u32; 4];

/// `uint16x8_t`: eight `u16` lanes, lane 0 lowest (bytes `2i, 2i+1`, little-endian).
pub type Uint16x8 = [u16; 8];

/// `uint64x2_t`: two `u64` lanes, lane 0 lowest (bytes `8i..8i+8`, little-endian).
pub type Uint64x2 = [u64; 2];

/// `uint32x2_t`: two `u32` lanes (a 64-bit D register), lane 0 lowest.
pub type Uint32x2 = [u32; 2];
