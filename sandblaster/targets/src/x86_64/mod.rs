//! x86_64 SSE2/SSSE3/SSE4.1 and SHA-NI reference models (DESIGN.md §9.2).
//!
//! **Vector representation (§9.2).** `__m128i` has no element type, so it is
//! canonically [`M128i`] = `[u8; 16]`, byte 0 = bits `7:0` (lowest address,
//! little-endian). Typed views read lanes little-endian:
//!
//! * `view_u16(v)[i] = from_le_bytes(v[2i..2i+2])` (SDM `word i` = bits `16i+15:16i`),
//! * `view_u32(v)[i] = from_le_bytes(v[4i..4i+4])` (SDM `dword i` = bits `32i+31:32i`),
//! * `view_u64(v)[i] = from_le_bytes(v[8i..8i+8])` (SDM `qword i`),
//!
//! and the constructors `from_u16x8`, `from_u32x4`, `from_u64x2` are their
//! inverses (`from_u32x4` is the prelude constructor `m128i_from_u32x4` of
//! §9.2). In the kernel the §5.7 byte simplifications
//! (`from_le_bytes([cast_u8(x), cast_u8(x>>8), ..]) → x`) make a chain of
//! `epi32` operations collapse to clean `u32` terms.
//!
//! **Immediates** (`const IMM8: i32`) are ordinary `i32` arguments; the models
//! panic outside the range rustc accepts (`0..=255` for all imm8 forms here).
//!
//! **Loads/stores** are modeled on `&[u8; 16]` like the generated helpers of
//! §9.2: `_mm_loadu_si128` returns the bytes, `_mm_storeu_si128` returns the
//! bytes to be written. Only unaligned forms exist.
//!
//! **Signed scalars.** `_mm_set_epi32`/`_mm_set_epi64x` take `i32`/`i64` as in
//! stdarch; the model converts with two's complement (`as u32`/`as u64`). DSL
//! code uses the unsigned constructors instead (§9.2).
//!
//! [`sse`] holds the SSE2/SSSE3/SSE4.1 operations, [`sha`] the SHA-NI
//! instructions (SHA256RNDS2, SHA256MSG1, SHA256MSG2).
//!
//! **256/512-bit vectors and opmasks** ([`wide`], MODELS.md §10): `__m256i`
//! = `[u8; 32]`, `__m512i` = `[u8; 64]` in the same byte order, `__mmaskN` =
//! `uN`. [`vec`] models the VEX/EVEX integer instructions once per SDM
//! instruction page, generic over the vector width; the intrinsic models are
//! in [`avx512`] (AVX-512F/BW/VL/DQ), [`avx2`] (AVX/AVX2), [`ifma`]
//! (AVX512IFMA), [`gfni`] (GFNI, all widths) and [`vbmi`] (VBMI, VBMI2,
//! VPOPCNTDQ, BITALG).
#![forbid(unsafe_code)]

pub mod avx2;
pub mod avx512;
pub mod gfni;
pub mod ifma;
pub mod sha;
pub mod sse;
pub mod vbmi;
pub mod vec;
pub mod wide;

pub use avx2::*;
pub use avx512::*;
pub use gfni::{
    _mm_gf2p8affine_epi64_epi8, _mm_gf2p8affineinv_epi64_epi8, _mm_gf2p8mul_epi8, _mm256_gf2p8affine_epi64_epi8,
    _mm256_gf2p8affineinv_epi64_epi8, _mm256_gf2p8mul_epi8, _mm512_gf2p8affine_epi64_epi8,
    _mm512_gf2p8affineinv_epi64_epi8, _mm512_gf2p8mul_epi8,
};
pub use ifma::{_mm256_madd52hi_epu64, _mm256_madd52lo_epu64, _mm512_madd52hi_epu64, _mm512_madd52lo_epu64};
pub use sha::*;
pub use sse::*;
pub use vbmi::{
    _mm512_multishift_epi64_epi8, _mm512_permutex2var_epi8, _mm512_permutexvar_epi8, _mm512_popcnt_epi8,
    _mm512_popcnt_epi16, _mm512_popcnt_epi32, _mm512_popcnt_epi64, _mm512_shldi_epi32, _mm512_shldi_epi64,
    _mm512_shldv_epi32, _mm512_shldv_epi64, _mm512_shrdv_epi32, _mm512_shrdv_epi64,
};
pub use wide::{M256i, M512i, Mmask8, Mmask16, Mmask32, Mmask64};

/// `__m128i`: sixteen bytes, byte 0 = bits `7:0` (little-endian).
pub type M128i = [u8; 16];

/// The `u32` view: `view_u32(v)[i] = from_le_bytes(v[4i..4i+4])`.
pub fn view_u32(v: M128i) -> [u32; 4] {
    let mut r = [0u32; 4];
    for i in 0..4 {
        r[i] = u32::from_le_bytes([v[4 * i], v[4 * i + 1], v[4 * i + 2], v[4 * i + 3]]);
    }
    r
}

/// Inverse of [`view_u32`] (the prelude constructor `m128i_from_u32x4`).
pub fn from_u32x4(lanes: [u32; 4]) -> M128i {
    let mut v = [0u8; 16];
    for i in 0..4 {
        let b = lanes[i].to_le_bytes();
        for j in 0..4 {
            v[4 * i + j] = b[j];
        }
    }
    v
}

/// The `u16` view: `view_u16(v)[i] = from_le_bytes(v[2i..2i+2])`.
pub fn view_u16(v: M128i) -> [u16; 8] {
    let mut r = [0u16; 8];
    for i in 0..8 {
        r[i] = u16::from_le_bytes([v[2 * i], v[2 * i + 1]]);
    }
    r
}

/// Inverse of [`view_u16`].
pub fn from_u16x8(lanes: [u16; 8]) -> M128i {
    let mut v = [0u8; 16];
    for i in 0..8 {
        let b = lanes[i].to_le_bytes();
        v[2 * i] = b[0];
        v[2 * i + 1] = b[1];
    }
    v
}

/// The `u64` view: `view_u64(v)[i] = from_le_bytes(v[8i..8i+8])`.
pub fn view_u64(v: M128i) -> [u64; 2] {
    let mut r = [0u64; 2];
    for i in 0..2 {
        let mut b = [0u8; 8];
        for j in 0..8 {
            b[j] = v[8 * i + j];
        }
        r[i] = u64::from_le_bytes(b);
    }
    r
}

/// Inverse of [`view_u64`] (the prelude constructor `m128i_from_u64x2`).
pub fn from_u64x2(lanes: [u64; 2]) -> M128i {
    let mut v = [0u8; 16];
    for i in 0..2 {
        let b = lanes[i].to_le_bytes();
        for j in 0..8 {
            v[8 * i + j] = b[j];
        }
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn views_round_trip() {
        let v: M128i = core::array::from_fn(|i| (i as u8).wrapping_mul(37).wrapping_add(11));
        assert_eq!(from_u32x4(view_u32(v)), v);
        assert_eq!(from_u16x8(view_u16(v)), v);
        assert_eq!(from_u64x2(view_u64(v)), v);
        assert_eq!(view_u32(from_u32x4([1, 2, 3, 4])), [1, 2, 3, 4]);
        assert_eq!(
            view_u32([1, 0, 0, 0, 0, 0, 0, 0x80, 0, 0, 0, 0, 0, 0, 0, 0])[0],
            1
        );
        assert_eq!(
            view_u32([1, 0, 0, 0, 0, 0, 0, 0x80, 0, 0, 0, 0, 0, 0, 0, 0])[1],
            0x8000_0000
        );
    }
}
