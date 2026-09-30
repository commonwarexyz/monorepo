//! Real aarch64 NEON / SHA2 intrinsics on the model representation, the
//! SHA-256 compression built from them, and the differential campaigns
//! (DESIGN.md §9.2 "Validation": aarch64 NEON/SHA2 validated natively).
//!
//! Every wrapper has the signature of the model of the same name in
//! [`crate::aarch64`], so a campaign is `diff(model::f, hw::f)`. Wrappers are
//! safe `#[target_feature]` functions (rustc 1.98 requires the attribute even
//! though `neon`/`sha2` are static on `aarch64-apple-darwin`); callers outside
//! a feature context use `unsafe` after run-time detection, as the generated
//! dispatch glue of §9.3 does.

//!
//! # Safety
//!
//! The wrappers are safe `#[target_feature]` functions: calling one from code
//! without the feature enabled is `unsafe`, and the caller must ensure the
//! running CPU has the feature (`run_model` checks with run-time detection
//! before every call). Clippy's `missing_safety_doc` is allowed for that
//! reason: this section is the safety documentation of every wrapper.
#![allow(clippy::missing_safety_doc)]

use crate::aarch64 as model;
use crate::diff::{self, Config, Outcome};
use crate::registry::{self, Arch};
use core::arch::aarch64 as arch;
use core::arch::aarch64::{uint8x8_t, uint8x16_t, uint16x8_t, uint32x2_t, uint32x4_t, uint64x2_t};
use core::mem::transmute;

use super::imm_table;

// SAFETY (all four conversions): the NEON vector types and the arrays have
// the same size, every bit pattern is valid for both, and on little-endian
// aarch64 lane i is element i (the §9.2 representation).
#[inline(always)]
fn q8(a: [u8; 16]) -> uint8x16_t {
    unsafe { transmute(a) }
}
#[inline(always)]
fn from_q8(v: uint8x16_t) -> [u8; 16] {
    unsafe { transmute(v) }
}
#[inline(always)]
fn q32(a: [u32; 4]) -> uint32x4_t {
    unsafe { transmute(a) }
}
#[inline(always)]
fn from_q32(v: uint32x4_t) -> [u32; 4] {
    unsafe { transmute(v) }
}
#[inline(always)]
fn from_d8(v: uint8x8_t) -> [u8; 8] {
    unsafe { transmute(v) }
}

#[inline(always)]
fn d8(a: [u8; 8]) -> uint8x8_t {
    unsafe { transmute(a) }
}
#[inline(always)]
fn q16(a: [u16; 8]) -> uint16x8_t {
    unsafe { transmute(a) }
}
#[inline(always)]
fn from_q16(v: uint16x8_t) -> [u16; 8] {
    unsafe { transmute(v) }
}
#[inline(always)]
fn q64(a: [u64; 2]) -> uint64x2_t {
    unsafe { transmute(a) }
}
#[inline(always)]
fn from_q64(v: uint64x2_t) -> [u64; 2] {
    unsafe { transmute(v) }
}
#[inline(always)]
fn d32(a: [u32; 2]) -> uint32x2_t {
    unsafe { transmute(a) }
}
#[inline(always)]
fn from_d32(v: uint32x2_t) -> [u32; 2] {
    unsafe { transmute(v) }
}

/// Byte written around stores to detect writes outside the stored lanes.
const SENTINEL: u8 = 0xa5;

/// `vld1q_u8` reading the 16 bytes of `mem`.
#[target_feature(enable = "neon")]
pub fn vld1q_u8(mem: &[u8; 16]) -> [u8; 16] {
    // SAFETY: `mem` is valid for reading 16 bytes; LD1 has no alignment requirement.
    from_q8(unsafe { arch::vld1q_u8(mem.as_ptr()) })
}

/// `vld1q_u32` reading the four words of `mem`.
#[target_feature(enable = "neon")]
pub fn vld1q_u32(mem: &[u32; 4]) -> [u32; 4] {
    // SAFETY: `mem` is valid for reading 16 bytes.
    from_q32(unsafe { arch::vld1q_u32(mem.as_ptr()) })
}

/// `vld1_u8` reading the 8 bytes of `mem`.
#[target_feature(enable = "neon")]
pub fn vld1_u8(mem: &[u8; 8]) -> [u8; 8] {
    // SAFETY: `mem` is valid for reading 8 bytes.
    from_d8(unsafe { arch::vld1_u8(mem.as_ptr()) })
}

/// `vst1q_u8` into an unaligned slot of a sentinel-filled buffer; returns the
/// 16 bytes written and panics if any byte outside them changed.
#[target_feature(enable = "neon")]
pub fn vst1q_u8(a: [u8; 16]) -> [u8; 16] {
    let mut buf = [SENTINEL; 48];
    // SAFETY: `buf[17..33]` is in bounds and writable; ST1 has no alignment requirement.
    unsafe { arch::vst1q_u8(buf.as_mut_ptr().add(17), q8(a)) };
    assert!(
        buf[..17].iter().chain(&buf[33..]).all(|&b| b == SENTINEL),
        "vst1q_u8 wrote outside its 16 bytes"
    );
    buf[17..33].try_into().expect("16 bytes")
}

/// `vst1q_u32` into a sentinel-filled buffer; returns the four words written
/// and panics if any word outside them changed.
#[target_feature(enable = "neon")]
pub fn vst1q_u32(a: [u32; 4]) -> [u32; 4] {
    let s = u32::from_ne_bytes([SENTINEL; 4]);
    let mut buf = [s; 12];
    // SAFETY: `buf[4..8]` is in bounds, writable and 4-byte aligned.
    unsafe { arch::vst1q_u32(buf.as_mut_ptr().add(4), q32(a)) };
    assert!(
        buf[..4].iter().chain(&buf[8..]).all(|&w| w == s),
        "vst1q_u32 wrote outside its 4 words"
    );
    buf[4..8].try_into().expect("4 words")
}

/// `vrev32q_u8`.
#[target_feature(enable = "neon")]
pub fn vrev32q_u8(a: [u8; 16]) -> [u8; 16] {
    from_q8(arch::vrev32q_u8(q8(a)))
}

/// `vreinterpretq_u32_u8`.
#[target_feature(enable = "neon")]
pub fn vreinterpretq_u32_u8(a: [u8; 16]) -> [u32; 4] {
    from_q32(arch::vreinterpretq_u32_u8(q8(a)))
}

/// `vreinterpretq_u8_u32`.
#[target_feature(enable = "neon")]
pub fn vreinterpretq_u8_u32(a: [u32; 4]) -> [u8; 16] {
    from_q8(arch::vreinterpretq_u8_u32(q32(a)))
}

/// `vaddq_u32`.
#[target_feature(enable = "neon")]
pub fn vaddq_u32(a: [u32; 4], b: [u32; 4]) -> [u32; 4] {
    from_q32(arch::vaddq_u32(q32(a), q32(b)))
}

/// `veorq_u32`.
#[target_feature(enable = "neon")]
pub fn veorq_u32(a: [u32; 4], b: [u32; 4]) -> [u32; 4] {
    from_q32(arch::veorq_u32(q32(a), q32(b)))
}

/// `vandq_u32`.
#[target_feature(enable = "neon")]
pub fn vandq_u32(a: [u32; 4], b: [u32; 4]) -> [u32; 4] {
    from_q32(arch::vandq_u32(q32(a), q32(b)))
}

/// `vorrq_u32`.
#[target_feature(enable = "neon")]
pub fn vorrq_u32(a: [u32; 4], b: [u32; 4]) -> [u32; 4] {
    from_q32(arch::vorrq_u32(q32(a), q32(b)))
}

/// `vdupq_n_u32`.
#[target_feature(enable = "neon")]
pub fn vdupq_n_u32(value: u32) -> [u32; 4] {
    from_q32(arch::vdupq_n_u32(value))
}

// ---------------------------------------------------------------------------
// Plan O10: NEON byte/halfword/doubleword lane operations (src/aarch64/neon2.rs).

/// `vld1q_u64` reading the two words of `mem`.
#[target_feature(enable = "neon")]
pub fn vld1q_u64(mem: &[u64; 2]) -> [u64; 2] {
    // SAFETY: `mem` is valid for reading 16 bytes; LD1 has no alignment requirement.
    from_q64(unsafe { arch::vld1q_u64(mem.as_ptr()) })
}

/// `vst1q_u64` into a sentinel-filled buffer; returns the two words written
/// and panics if any word outside them changed.
#[target_feature(enable = "neon")]
pub fn vst1q_u64(a: [u64; 2]) -> [u64; 2] {
    let s = u64::from_ne_bytes([SENTINEL; 8]);
    let mut buf = [s; 6];
    // SAFETY: `buf[2..4]` is in bounds and writable.
    unsafe { arch::vst1q_u64(buf.as_mut_ptr().add(2), q64(a)) };
    assert!(buf[..2].iter().chain(&buf[4..]).all(|&w| w == s), "vst1q_u64 wrote outside its 2 words");
    buf[2..4].try_into().expect("2 words")
}

macro_rules! bin8 {
    ($($name:ident)*) => {$(
        #[doc = concat!("`", stringify!($name), "`.")]
        #[target_feature(enable = "neon")]
        pub fn $name(a: [u8; 16], b: [u8; 16]) -> [u8; 16] {
            from_q8(arch::$name(q8(a), q8(b)))
        }
    )*};
}
bin8!(veorq_u8 vandq_u8 vorrq_u8 vcltq_u8 vcgeq_u8 vceqq_u8 vqtbl1q_u8);

/// `vdupq_n_u8`.
#[target_feature(enable = "neon")]
pub fn vdupq_n_u8(value: u8) -> [u8; 16] {
    from_q8(arch::vdupq_n_u8(value))
}

/// `vcntq_u8`.
#[target_feature(enable = "neon")]
pub fn vcntq_u8(a: [u8; 16]) -> [u8; 16] {
    from_q8(arch::vcntq_u8(q8(a)))
}

/// `vaddvq_u8`.
#[target_feature(enable = "neon")]
pub fn vaddvq_u8(a: [u8; 16]) -> u8 {
    arch::vaddvq_u8(q8(a))
}

/// `vmaxvq_u8`.
#[target_feature(enable = "neon")]
pub fn vmaxvq_u8(a: [u8; 16]) -> u8 {
    arch::vmaxvq_u8(q8(a))
}

/// `vreinterpretq_u16_u8`.
#[target_feature(enable = "neon")]
pub fn vreinterpretq_u16_u8(a: [u8; 16]) -> [u16; 8] {
    from_q16(arch::vreinterpretq_u16_u8(q8(a)))
}

/// `vreinterpretq_u64_u8`.
#[target_feature(enable = "neon")]
pub fn vreinterpretq_u64_u8(a: [u8; 16]) -> [u64; 2] {
    from_q64(arch::vreinterpretq_u64_u8(q8(a)))
}

/// `vcombine_u8`.
#[target_feature(enable = "neon")]
pub fn vcombine_u8(low: [u8; 8], high: [u8; 8]) -> [u8; 16] {
    from_q8(arch::vcombine_u8(d8(low), d8(high)))
}

/// `vmovn_u64`.
#[target_feature(enable = "neon")]
pub fn vmovn_u64(a: [u64; 2]) -> [u32; 2] {
    from_d32(arch::vmovn_u64(q64(a)))
}

/// `vaddq_u64`.
#[target_feature(enable = "neon")]
pub fn vaddq_u64(a: [u64; 2], b: [u64; 2]) -> [u64; 2] {
    from_q64(arch::vaddq_u64(q64(a), q64(b)))
}

/// `vbslq_u64(mask, b, c)`.
#[target_feature(enable = "neon")]
pub fn vbslq_u64(a: [u64; 2], b: [u64; 2], c: [u64; 2]) -> [u64; 2] {
    from_q64(arch::vbslq_u64(q64(a), q64(b), q64(c)))
}

/// `vbslq_u32(mask, b, c)`.
#[target_feature(enable = "neon")]
pub fn vbslq_u32(a: [u32; 4], b: [u32; 4], c: [u32; 4]) -> [u32; 4] {
    from_q32(arch::vbslq_u32(q32(a), q32(b), q32(c)))
}

/// `vmull_u32`.
#[target_feature(enable = "neon")]
pub fn vmull_u32(a: [u32; 2], b: [u32; 2]) -> [u64; 2] {
    from_q64(arch::vmull_u32(d32(a), d32(b)))
}

/// `vmlal_u32(acc, b, c)`.
#[target_feature(enable = "neon")]
pub fn vmlal_u32(a: [u64; 2], b: [u32; 2], c: [u32; 2]) -> [u64; 2] {
    from_q64(arch::vmlal_u32(q64(a), d32(b), d32(c)))
}

// FEAT_SHA3 / FEAT_SHA512 (src/aarch64/sha3.rs).

/// `veor3q_u8`.
#[target_feature(enable = "sha3")]
pub fn veor3q_u8(a: [u8; 16], b: [u8; 16], c: [u8; 16]) -> [u8; 16] {
    from_q8(arch::veor3q_u8(q8(a), q8(b), q8(c)))
}

/// `vbcaxq_u8`.
#[target_feature(enable = "sha3")]
pub fn vbcaxq_u8(a: [u8; 16], b: [u8; 16], c: [u8; 16]) -> [u8; 16] {
    from_q8(arch::vbcaxq_u8(q8(a), q8(b), q8(c)))
}

/// `vrax1q_u64`.
#[target_feature(enable = "sha3")]
pub fn vrax1q_u64(a: [u64; 2], b: [u64; 2]) -> [u64; 2] {
    from_q64(arch::vrax1q_u64(q64(a), q64(b)))
}

/// `vsha512hq_u64(hash_ed, hash_gf, kwh_kwh2)` — arguments in position order.
#[target_feature(enable = "sha3")]
pub fn vsha512hq_u64(a: [u64; 2], b: [u64; 2], c: [u64; 2]) -> [u64; 2] {
    from_q64(arch::vsha512hq_u64(q64(a), q64(b), q64(c)))
}

/// `vsha512h2q_u64(sum_ab, hash_c_, hash_ab)` — arguments in position order.
#[target_feature(enable = "sha3")]
pub fn vsha512h2q_u64(a: [u64; 2], b: [u64; 2], c: [u64; 2]) -> [u64; 2] {
    from_q64(arch::vsha512h2q_u64(q64(a), q64(b), q64(c)))
}

/// `vsha512su0q_u64(w0_1, w2_)`.
#[target_feature(enable = "sha3")]
pub fn vsha512su0q_u64(a: [u64; 2], b: [u64; 2]) -> [u64; 2] {
    from_q64(arch::vsha512su0q_u64(q64(a), q64(b)))
}

/// `vsha512su1q_u64(s01_s02, w14_15, w9_10)`.
#[target_feature(enable = "sha3")]
pub fn vsha512su1q_u64(a: [u64; 2], b: [u64; 2], c: [u64; 2]) -> [u64; 2] {
    from_q64(arch::vsha512su1q_u64(q64(a), q64(b), q64(c)))
}

// Immediate forms of the O10 models.

type U8x16ImmFn = unsafe fn([u8; 16]) -> [u8; 16];
type GetLane64Fn = unsafe fn([u64; 2]) -> u64;
type Shrn16Fn = unsafe fn([u16; 8]) -> [u8; 8];
type Shrn64Fn = unsafe fn([u64; 2]) -> [u32; 2];
type U64x2x2Fn = unsafe fn([u64; 2], [u64; 2]) -> [u64; 2];

#[target_feature(enable = "neon")]
fn shr8_n<const N: i32>(a: [u8; 16]) -> [u8; 16] {
    from_q8(arch::vshrq_n_u8::<N>(q8(a)))
}
#[target_feature(enable = "neon")]
fn get_lane64<const L: i32>(v: [u64; 2]) -> u64 {
    arch::vgetq_lane_u64::<L>(q64(v))
}
#[target_feature(enable = "neon")]
fn shrn16<const N: i32>(a: [u16; 8]) -> [u8; 8] {
    from_d8(arch::vshrn_n_u16::<N>(q16(a)))
}
#[target_feature(enable = "neon")]
fn shrn64<const N: i32>(a: [u64; 2]) -> [u32; 2] {
    from_d32(arch::vshrn_n_u64::<N>(q64(a)))
}
#[target_feature(enable = "neon")]
fn sra64<const N: i32>(a: [u64; 2], b: [u64; 2]) -> [u64; 2] {
    from_q64(arch::vsraq_n_u64::<N>(q64(a), q64(b)))
}
#[target_feature(enable = "sha3")]
fn xar64<const N: i32>(a: [u64; 2], b: [u64; 2]) -> [u64; 2] {
    from_q64(arch::vxarq_u64::<N>(q64(a), q64(b)))
}

static SHR8: [U8x16ImmFn; 8] = imm_table!(shr8_n, U8x16ImmFn; 1 2 3 4 5 6 7 8);
static GET_LANE64: [GetLane64Fn; 2] = imm_table!(get_lane64, GetLane64Fn; 0 1);
static SHRN16: [Shrn16Fn; 8] = imm_table!(shrn16, Shrn16Fn; 1 2 3 4 5 6 7 8);
static SHRN64: [Shrn64Fn; 32] = imm_table!(shrn64, Shrn64Fn;
    1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32);
static SRA64: [U64x2x2Fn; 64] = imm_table!(sra64, U64x2x2Fn;
    1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32
    33 34 35 36 37 38 39 40 41 42 43 44 45 46 47 48 49 50 51 52 53 54 55 56 57 58 59 60 61 62 63 64);
static XAR64: [U64x2x2Fn; 64] = imm_table!(xar64, U64x2x2Fn;
    0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31
    32 33 34 35 36 37 38 39 40 41 42 43 44 45 46 47 48 49 50 51 52 53 54 55 56 57 58 59 60 61 62 63);

/// `vshrq_n_u8::<N>` with `N` (1..=8) as an argument.
#[target_feature(enable = "neon")]
pub fn vshrq_n_u8(a: [u8; 16], n: i32) -> [u8; 16] {
    // SAFETY: the table entries require `neon`, which this function has.
    unsafe { SHR8[slot(n, 1, 8, "vshrq_n_u8")](a) }
}

/// `vgetq_lane_u64::<LANE>` with `LANE` (0..=1) as an argument.
#[target_feature(enable = "neon")]
pub fn vgetq_lane_u64(v: [u64; 2], lane: i32) -> u64 {
    // SAFETY: as above.
    unsafe { GET_LANE64[slot(lane, 0, 2, "vgetq_lane_u64")](v) }
}

/// `vshrn_n_u16::<N>` with `N` (1..=8) as an argument.
#[target_feature(enable = "neon")]
pub fn vshrn_n_u16(a: [u16; 8], n: i32) -> [u8; 8] {
    // SAFETY: as above.
    unsafe { SHRN16[slot(n, 1, 8, "vshrn_n_u16")](a) }
}

/// `vshrn_n_u64::<N>` with `N` (1..=32) as an argument.
#[target_feature(enable = "neon")]
pub fn vshrn_n_u64(a: [u64; 2], n: i32) -> [u32; 2] {
    // SAFETY: as above.
    unsafe { SHRN64[slot(n, 1, 32, "vshrn_n_u64")](a) }
}

/// `vsraq_n_u64::<N>` with `N` (1..=64) as an argument.
#[target_feature(enable = "neon")]
pub fn vsraq_n_u64(a: [u64; 2], b: [u64; 2], n: i32) -> [u64; 2] {
    // SAFETY: as above.
    unsafe { SRA64[slot(n, 1, 64, "vsraq_n_u64")](a, b) }
}

/// `vxarq_u64::<IMM6>` with `IMM6` (0..=63) as an argument.
#[target_feature(enable = "sha3")]
pub fn vxarq_u64(a: [u64; 2], b: [u64; 2], imm6: i32) -> [u64; 2] {
    // SAFETY: the table entries require `sha3`, which this function has.
    unsafe { XAR64[slot(imm6, 0, 64, "vxarq_u64")](a, b) }
}

// ---------------------------------------------------------------------------
// Immediate forms: one monomorphization per immediate, dispatched by table.

type U32x4Fn = unsafe fn([u32; 4]) -> [u32; 4];
type U32x4x2Fn = unsafe fn([u32; 4], [u32; 4]) -> [u32; 4];
type GetLaneFn = unsafe fn([u32; 4]) -> u32;
type SetLane32Fn = unsafe fn(u32, [u32; 4]) -> [u32; 4];
type SetLane8Fn = unsafe fn(u8, [u8; 16]) -> [u8; 16];

#[target_feature(enable = "neon")]
fn shl_n<const N: i32>(a: [u32; 4]) -> [u32; 4] {
    from_q32(arch::vshlq_n_u32::<N>(q32(a)))
}
#[target_feature(enable = "neon")]
fn shr_n<const N: i32>(a: [u32; 4]) -> [u32; 4] {
    from_q32(arch::vshrq_n_u32::<N>(q32(a)))
}
#[target_feature(enable = "neon")]
fn ext<const N: i32>(a: [u32; 4], b: [u32; 4]) -> [u32; 4] {
    from_q32(arch::vextq_u32::<N>(q32(a), q32(b)))
}
#[target_feature(enable = "neon")]
fn get_lane<const L: i32>(v: [u32; 4]) -> u32 {
    arch::vgetq_lane_u32::<L>(q32(v))
}
#[target_feature(enable = "neon")]
fn set_lane32<const L: i32>(a: u32, b: [u32; 4]) -> [u32; 4] {
    from_q32(arch::vsetq_lane_u32::<L>(a, q32(b)))
}
#[target_feature(enable = "neon")]
fn set_lane8<const L: i32>(a: u8, b: [u8; 16]) -> [u8; 16] {
    from_q8(arch::vsetq_lane_u8::<L>(a, q8(b)))
}

static SHL: [U32x4Fn; 32] = imm_table!(shl_n, U32x4Fn;
    0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31);
static SHR: [U32x4Fn; 32] = imm_table!(shr_n, U32x4Fn;
    1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32);
static EXT: [U32x4x2Fn; 4] = imm_table!(ext, U32x4x2Fn; 0 1 2 3);
static GET_LANE: [GetLaneFn; 4] = imm_table!(get_lane, GetLaneFn; 0 1 2 3);
static SET_LANE32: [SetLane32Fn; 4] = imm_table!(set_lane32, SetLane32Fn; 0 1 2 3);
static SET_LANE8: [SetLane8Fn; 16] =
    imm_table!(set_lane8, SetLane8Fn; 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15);

fn slot(imm: i32, lo: i32, len: usize, what: &str) -> usize {
    let i = imm
        .checked_sub(lo)
        .and_then(|i| usize::try_from(i).ok())
        .filter(|&i| i < len);
    i.unwrap_or_else(|| panic!("{what}: immediate {imm} out of range"))
}

/// `vshlq_n_u32::<N>` with `N` (0..=31) as an argument.
#[target_feature(enable = "neon")]
pub fn vshlq_n_u32(a: [u32; 4], n: i32) -> [u32; 4] {
    // SAFETY: the table entries require `neon`, which this function has.
    unsafe { SHL[slot(n, 0, 32, "vshlq_n_u32")](a) }
}

/// `vshrq_n_u32::<N>` with `N` (1..=32) as an argument.
#[target_feature(enable = "neon")]
pub fn vshrq_n_u32(a: [u32; 4], n: i32) -> [u32; 4] {
    // SAFETY: as above.
    unsafe { SHR[slot(n, 1, 32, "vshrq_n_u32")](a) }
}

/// `vextq_u32::<N>` with `N` (0..=3) as an argument.
#[target_feature(enable = "neon")]
pub fn vextq_u32(a: [u32; 4], b: [u32; 4], n: i32) -> [u32; 4] {
    // SAFETY: as above.
    unsafe { EXT[slot(n, 0, 4, "vextq_u32")](a, b) }
}

/// `vgetq_lane_u32::<LANE>` with `LANE` (0..=3) as an argument.
#[target_feature(enable = "neon")]
pub fn vgetq_lane_u32(v: [u32; 4], lane: i32) -> u32 {
    // SAFETY: as above.
    unsafe { GET_LANE[slot(lane, 0, 4, "vgetq_lane_u32")](v) }
}

/// `vsetq_lane_u32::<LANE>` with `LANE` (0..=3) as an argument.
#[target_feature(enable = "neon")]
pub fn vsetq_lane_u32(a: u32, b: [u32; 4], lane: i32) -> [u32; 4] {
    // SAFETY: as above.
    unsafe { SET_LANE32[slot(lane, 0, 4, "vsetq_lane_u32")](a, b) }
}

/// `vsetq_lane_u8::<LANE>` with `LANE` (0..=15) as an argument.
#[target_feature(enable = "neon")]
pub fn vsetq_lane_u8(a: u8, b: [u8; 16], lane: i32) -> [u8; 16] {
    // SAFETY: as above.
    unsafe { SET_LANE8[slot(lane, 0, 16, "vsetq_lane_u8")](a, b) }
}

// ---------------------------------------------------------------------------
// SHA2

/// `vsha256hq_u32(hash_abcd, hash_efgh, wk)`.
#[target_feature(enable = "sha2")]
pub fn vsha256hq_u32(hash_abcd: [u32; 4], hash_efgh: [u32; 4], wk: [u32; 4]) -> [u32; 4] {
    from_q32(arch::vsha256hq_u32(q32(hash_abcd), q32(hash_efgh), q32(wk)))
}

/// `vsha256h2q_u32(hash_efgh, hash_abcd, wk)` — arguments passed in position
/// order (stdarch's parameter *names* are swapped relative to ACLE; the
/// first operand is the tied `Vd` = `efgh`).
#[target_feature(enable = "sha2")]
pub fn vsha256h2q_u32(hash_efgh: [u32; 4], hash_abcd: [u32; 4], wk: [u32; 4]) -> [u32; 4] {
    from_q32(arch::vsha256h2q_u32(
        q32(hash_efgh),
        q32(hash_abcd),
        q32(wk),
    ))
}

/// `vsha256su0q_u32(w0_3, w4_7)`.
#[target_feature(enable = "sha2")]
pub fn vsha256su0q_u32(w0_3: [u32; 4], w4_7: [u32; 4]) -> [u32; 4] {
    from_q32(arch::vsha256su0q_u32(q32(w0_3), q32(w4_7)))
}

/// `vsha256su1q_u32(tw0_3, w8_11, w12_15)`.
#[target_feature(enable = "sha2")]
pub fn vsha256su1q_u32(tw0_3: [u32; 4], w8_11: [u32; 4], w12_15: [u32; 4]) -> [u32; 4] {
    from_q32(arch::vsha256su1q_u32(q32(tw0_3), q32(w8_11), q32(w12_15)))
}

/// SHA-256 compression of one block with the real SHA2 intrinsics, statement
/// for statement the `sha2` crate's `aarch64_sha2::compress` (one block).
#[target_feature(enable = "sha2")]
pub fn compress_sha2(state: [u32; 8], block: &[u8; 64]) -> [u32; 8] {
    use crate::fips::K;
    // SAFETY (loads/stores below): every pointer is to 16 in-bounds bytes of
    // `state`, `block`, `K` or `out`; LD1/ST1 have no alignment requirement.
    let mut abcd = unsafe { arch::vld1q_u32(state[0..4].as_ptr()) };
    let mut efgh = unsafe { arch::vld1q_u32(state[4..8].as_ptr()) };
    let abcd_orig = abcd;
    let efgh_orig = efgh;

    let load = |i: usize| unsafe { arch::vld1q_u8(block[16 * i..16 * i + 16].as_ptr()) };
    let mut s0 = arch::vreinterpretq_u32_u8(arch::vrev32q_u8(load(0)));
    let mut s1 = arch::vreinterpretq_u32_u8(arch::vrev32q_u8(load(1)));
    let mut s2 = arch::vreinterpretq_u32_u8(arch::vrev32q_u8(load(2)));
    let mut s3 = arch::vreinterpretq_u32_u8(arch::vrev32q_u8(load(3)));

    macro_rules! rounds4 {
        ($s:expr, $t:expr) => {{
            let tmp = arch::vaddq_u32($s, unsafe { arch::vld1q_u32(K[$t..$t + 4].as_ptr()) });
            let abcd_prev = abcd;
            abcd = arch::vsha256hq_u32(abcd_prev, efgh, tmp);
            efgh = arch::vsha256h2q_u32(efgh, abcd_prev, tmp);
        }};
    }

    rounds4!(s0, 0);
    rounds4!(s1, 4);
    rounds4!(s2, 8);
    rounds4!(s3, 12);
    for t in (16..64).step_by(16) {
        s0 = arch::vsha256su1q_u32(arch::vsha256su0q_u32(s0, s1), s2, s3);
        rounds4!(s0, t);
        s1 = arch::vsha256su1q_u32(arch::vsha256su0q_u32(s1, s2), s3, s0);
        rounds4!(s1, t + 4);
        s2 = arch::vsha256su1q_u32(arch::vsha256su0q_u32(s2, s3), s0, s1);
        rounds4!(s2, t + 8);
        s3 = arch::vsha256su1q_u32(arch::vsha256su0q_u32(s3, s0), s1, s2);
        rounds4!(s3, t + 12);
    }
    abcd = arch::vaddq_u32(abcd, abcd_orig);
    efgh = arch::vaddq_u32(efgh, efgh_orig);

    let mut out = [0u32; 8];
    unsafe {
        arch::vst1q_u32(out[0..4].as_mut_ptr(), abcd);
        arch::vst1q_u32(out[4..8].as_mut_ptr(), efgh);
    }
    out
}

// ---------------------------------------------------------------------------
// Campaigns

/// Whether the running CPU has target feature `f` (the names used in the
/// registry).
pub fn feature_detected(f: &str) -> bool {
    match f {
        "neon" => std::arch::is_aarch64_feature_detected!("neon"),
        "sha2" => std::arch::is_aarch64_feature_detected!("sha2"),
        "aes" => std::arch::is_aarch64_feature_detected!("aes"),
        "sha3" => std::arch::is_aarch64_feature_detected!("sha3"),
        _ => false,
    }
}

/// Run-time feature detection results recorded in the evidence.
pub fn detected_features() -> Vec<(String, bool)> {
    ["neon", "aes", "sha2", "sha3"]
        .iter()
        .map(|f| (f.to_string(), feature_detected(f)))
        .collect()
}

/// The differential campaign of one model against its intrinsic, or `None`
/// if `name` is not an aarch64 model. Skipped (with the reason) if the CPU
/// lacks a required feature.
pub fn run_model(name: &str, cfg: &Config) -> Option<Outcome> {
    let m = registry::find(Arch::Aarch64, name)?;
    if let Some(f) = m.features.iter().find(|f| !feature_detected(f)) {
        return Some(Outcome::skipped(name, format!("CPU lacks `{f}`")));
    }
    let n = cfg.random_per_model;
    let s = cfg.seed_for(name);
    let imms = || m.immediates.clone().expect("immediate model");
    // SAFETY (every `unsafe` block below): it calls a `#[target_feature]`
    // wrapper whose features were detected on this CPU just above.
    let o = match name {
        "vld1q_u8" => diff::diff1(
            name,
            n,
            s,
            |a: [u8; 16]| model::vld1q_u8(&a),
            |a: [u8; 16]| unsafe { vld1q_u8(&a) },
        ),
        "vld1q_u32" => diff::diff1(
            name,
            n,
            s,
            |a: [u32; 4]| model::vld1q_u32(&a),
            |a: [u32; 4]| unsafe { vld1q_u32(&a) },
        ),
        "vld1_u8" => diff::diff1(
            name,
            n,
            s,
            |a: [u8; 8]| model::vld1_u8(&a),
            |a: [u8; 8]| unsafe { vld1_u8(&a) },
        ),
        "vst1q_u8" => diff::diff1(name, n, s, model::vst1q_u8, |a| unsafe { vst1q_u8(a) }),
        "vst1q_u32" => diff::diff1(name, n, s, model::vst1q_u32, |a| unsafe { vst1q_u32(a) }),
        "vrev32q_u8" => diff::diff1(name, n, s, model::vrev32q_u8, |a| unsafe { vrev32q_u8(a) }),
        "vreinterpretq_u32_u8" => {
            diff::diff1(name, n, s, model::vreinterpretq_u32_u8, |a| unsafe {
                vreinterpretq_u32_u8(a)
            })
        }
        "vreinterpretq_u8_u32" => {
            diff::diff1(name, n, s, model::vreinterpretq_u8_u32, |a| unsafe {
                vreinterpretq_u8_u32(a)
            })
        }
        "vaddq_u32" => diff::diff2(name, n, s, model::vaddq_u32, |a, b| unsafe {
            vaddq_u32(a, b)
        }),
        "veorq_u32" => diff::diff2(name, n, s, model::veorq_u32, |a, b| unsafe {
            veorq_u32(a, b)
        }),
        "vandq_u32" => diff::diff2(name, n, s, model::vandq_u32, |a, b| unsafe {
            vandq_u32(a, b)
        }),
        "vorrq_u32" => diff::diff2(name, n, s, model::vorrq_u32, |a, b| unsafe {
            vorrq_u32(a, b)
        }),
        "vshlq_n_u32" => diff::diff_imm1(name, imms(), n, s, model::vshlq_n_u32, |a, i| unsafe {
            vshlq_n_u32(a, i)
        }),
        "vshrq_n_u32" => diff::diff_imm1(name, imms(), n, s, model::vshrq_n_u32, |a, i| unsafe {
            vshrq_n_u32(a, i)
        }),
        "vextq_u32" => diff::diff_imm2(name, imms(), n, s, model::vextq_u32, |a, b, i| unsafe {
            vextq_u32(a, b, i)
        }),
        "vdupq_n_u32" => diff::diff1(name, n, s, model::vdupq_n_u32, |x| unsafe {
            vdupq_n_u32(x)
        }),
        "vgetq_lane_u32" => {
            diff::diff_imm1(name, imms(), n, s, model::vgetq_lane_u32, |v, i| unsafe {
                vgetq_lane_u32(v, i)
            })
        }
        "vsetq_lane_u32" => diff::diff_imm2(
            name,
            imms(),
            n,
            s,
            model::vsetq_lane_u32,
            |a, b, i| unsafe { vsetq_lane_u32(a, b, i) },
        ),
        "vsetq_lane_u8" => {
            diff::diff_imm2(name, imms(), n, s, model::vsetq_lane_u8, |a, b, i| unsafe {
                vsetq_lane_u8(a, b, i)
            })
        }
        "vsha256hq_u32" => diff::diff3(name, n, s, model::vsha256hq_u32, |a, b, c| unsafe {
            vsha256hq_u32(a, b, c)
        }),
        "vsha256h2q_u32" => diff::diff3(name, n, s, model::vsha256h2q_u32, |a, b, c| unsafe {
            vsha256h2q_u32(a, b, c)
        }),
        "vsha256su0q_u32" => diff::diff2(name, n, s, model::vsha256su0q_u32, |a, b| unsafe {
            vsha256su0q_u32(a, b)
        }),
        "vsha256su1q_u32" => diff::diff3(name, n, s, model::vsha256su1q_u32, |a, b, c| unsafe {
            vsha256su1q_u32(a, b, c)
        }),
        // ---- plan O10 ----
        "vld1q_u64" => diff::diff1(name, n, s, |a: [u64; 2]| model::vld1q_u64(&a), |a: [u64; 2]| unsafe { vld1q_u64(&a) }),
        "vst1q_u64" => diff::diff1(name, n, s, model::vst1q_u64, |a| unsafe { vst1q_u64(a) }),
        "veorq_u8" => diff::diff2(name, n, s, model::veorq_u8, |a, b| unsafe { veorq_u8(a, b) }),
        "vandq_u8" => diff::diff2(name, n, s, model::vandq_u8, |a, b| unsafe { vandq_u8(a, b) }),
        "vorrq_u8" => diff::diff2(name, n, s, model::vorrq_u8, |a, b| unsafe { vorrq_u8(a, b) }),
        "vdupq_n_u8" => diff::diff1(name, n, s, model::vdupq_n_u8, |x| unsafe { vdupq_n_u8(x) }),
        "vshrq_n_u8" => diff::diff_imm1(name, imms(), n, s, model::vshrq_n_u8, |a, i| unsafe { vshrq_n_u8(a, i) }),
        "vcltq_u8" => diff::diff2(name, n, s, model::vcltq_u8, |a, b| unsafe { vcltq_u8(a, b) }),
        "vcgeq_u8" => diff::diff2(name, n, s, model::vcgeq_u8, |a, b| unsafe { vcgeq_u8(a, b) }),
        "vceqq_u8" => diff::diff2(name, n, s, model::vceqq_u8, |a, b| unsafe { vceqq_u8(a, b) }),
        "vqtbl1q_u8" => diff::diff2(name, n, s, model::vqtbl1q_u8, |a, b| unsafe { vqtbl1q_u8(a, b) }),
        "vcntq_u8" => diff::diff1(name, n, s, model::vcntq_u8, |a| unsafe { vcntq_u8(a) }),
        "vaddvq_u8" => diff::diff1(name, n, s, model::vaddvq_u8, |a| unsafe { vaddvq_u8(a) }),
        "vmaxvq_u8" => diff::diff1(name, n, s, model::vmaxvq_u8, |a| unsafe { vmaxvq_u8(a) }),
        "vreinterpretq_u16_u8" => diff::diff1(name, n, s, model::vreinterpretq_u16_u8, |a| unsafe { vreinterpretq_u16_u8(a) }),
        "vreinterpretq_u64_u8" => diff::diff1(name, n, s, model::vreinterpretq_u64_u8, |a| unsafe { vreinterpretq_u64_u8(a) }),
        "vcombine_u8" => diff::diff2(name, n, s, model::vcombine_u8, |a, b| unsafe { vcombine_u8(a, b) }),
        "vgetq_lane_u64" => diff::diff_imm1(name, imms(), n, s, model::vgetq_lane_u64, |v, i| unsafe { vgetq_lane_u64(v, i) }),
        "vshrn_n_u16" => diff::diff_imm1(name, imms(), n, s, model::vshrn_n_u16, |a, i| unsafe { vshrn_n_u16(a, i) }),
        "vshrn_n_u64" => diff::diff_imm1(name, imms(), n, s, model::vshrn_n_u64, |a, i| unsafe { vshrn_n_u64(a, i) }),
        "vmovn_u64" => diff::diff1(name, n, s, model::vmovn_u64, |a| unsafe { vmovn_u64(a) }),
        "vaddq_u64" => diff::diff2(name, n, s, model::vaddq_u64, |a, b| unsafe { vaddq_u64(a, b) }),
        "vsraq_n_u64" => diff::diff_imm2(name, imms(), n, s, model::vsraq_n_u64, |a, b, i| unsafe { vsraq_n_u64(a, b, i) }),
        "vbslq_u64" => diff::diff3(name, n, s, model::vbslq_u64, |a, b, c| unsafe { vbslq_u64(a, b, c) }),
        "vbslq_u32" => diff::diff3(name, n, s, model::vbslq_u32, |a, b, c| unsafe { vbslq_u32(a, b, c) }),
        "vmull_u32" => diff::diff2(name, n, s, model::vmull_u32, |a, b| unsafe { vmull_u32(a, b) }),
        "vmlal_u32" => diff::diff3(name, n, s, model::vmlal_u32, |a, b, c| unsafe { vmlal_u32(a, b, c) }),
        "veor3q_u8" => diff::diff3(name, n, s, model::veor3q_u8, |a, b, c| unsafe { veor3q_u8(a, b, c) }),
        "vbcaxq_u8" => diff::diff3(name, n, s, model::vbcaxq_u8, |a, b, c| unsafe { vbcaxq_u8(a, b, c) }),
        "vrax1q_u64" => diff::diff2(name, n, s, model::vrax1q_u64, |a, b| unsafe { vrax1q_u64(a, b) }),
        "vxarq_u64" => diff::diff_imm2(name, imms(), n, s, model::vxarq_u64, |a, b, i| unsafe { vxarq_u64(a, b, i) }),
        "vsha512hq_u64" => diff::diff3(name, n, s, model::vsha512hq_u64, |a, b, c| unsafe { vsha512hq_u64(a, b, c) }),
        "vsha512h2q_u64" => diff::diff3(name, n, s, model::vsha512h2q_u64, |a, b, c| unsafe { vsha512h2q_u64(a, b, c) }),
        "vsha512su0q_u64" => diff::diff2(name, n, s, model::vsha512su0q_u64, |a, b| unsafe { vsha512su0q_u64(a, b) }),
        "vsha512su1q_u64" => diff::diff3(name, n, s, model::vsha512su1q_u64, |a, b, c| unsafe { vsha512su1q_u64(a, b, c) }),
        _ => return None,
    };
    Some(o)
}

/// Every model's campaign, in registry order, run in parallel.
pub fn run_all(cfg: &Config) -> Vec<Outcome> {
    let names: Vec<&str> = registry::AARCH64.iter().map(|m| m.name).collect();
    super::run_parallel(&names, |name| {
        run_model(name, cfg).unwrap_or_else(|| panic!("no campaign for model {name}"))
    })
}

/// Whole-kernel hardware checks: the SHA-256 compression from the real
/// intrinsics against FIPS 180-4 and against the compression from the models
/// (budget: a tenth of the per-model budget).
pub fn run_compositions(cfg: &Config) -> Vec<Outcome> {
    let n = (cfg.random_per_model / 10).max(1);
    if !feature_detected("sha2") {
        return vec![
            Outcome::skipped("compress_sha2_intrinsics_vs_fips", "CPU lacks `sha2`"),
            Outcome::skipped("compress_sha2_intrinsics_vs_models", "CPU lacks `sha2`"),
        ];
    }
    // SAFETY: `sha2` was detected just above.
    vec![
        diff::diff2(
            "compress_sha2_intrinsics_vs_fips",
            n,
            cfg.seed_for("compress_sha2_intrinsics_vs_fips"),
            |st: [u32; 8], b: [u8; 64]| unsafe { compress_sha2(st, &b) },
            |st: [u32; 8], b: [u8; 64]| crate::fips::compress(st, &b),
        ),
        diff::diff2(
            "compress_sha2_intrinsics_vs_models",
            n,
            cfg.seed_for("compress_sha2_intrinsics_vs_models"),
            |st: [u32; 8], b: [u8; 64]| unsafe { compress_sha2(st, &b) },
            |st: [u32; 8], b: [u8; 64]| crate::compress::compress_aarch64_models(st, &b),
        ),
    ]
}
