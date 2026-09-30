//! AVX / AVX2 256-bit integer intrinsics (Intel SDM transcriptions), for
//! x86 CPUs without AVX-512.
//!
//! Each model is the stdarch intrinsic of the same name on `__m256i` =
//! [`M256i`] (`[u8; 32]`, little-endian) and delegates to the VL-generic
//! instruction model of [`super::vec`] (instantiated at 256 bits), whose doc
//! comment quotes the SDM pseudocode (the VEX.256 form computes the same
//! function as the EVEX.256 form there). Immediates are `i32` arguments in
//! `0..=255`.
#![forbid(unsafe_code)]

use super::vec::{
    vmovdqu, vpaddd, vpaddq, vpalignr256, vpandd, vpblendd, vpbroadcastd, vpbroadcastq, vpermd, vpord, vpshufb,
    vpslld_imm, vpsllq_imm, vpsrld_imm, vpsrlq_imm, vpxord,
};
use super::wide::M256i;

/// `_mm256_loadu_si256` — `VMOVDQU ymm1, m256` (avx): `DEST[255:0] :=
/// SRC[255:0]` ([`vmovdqu`]), on `&[u8; 32]`: `r[i] = mem[i]`.
pub fn _mm256_loadu_si256(mem: &[u8; 32]) -> M256i {
    vmovdqu(mem)
}

/// `_mm256_storeu_si256` — `VMOVDQU m256, ymm1` (avx), returning the 32
/// bytes written ([`vmovdqu`]).
pub fn _mm256_storeu_si256(a: M256i) -> [u8; 32] {
    vmovdqu(&a)
}

/// `_mm256_add_epi32(a, b)` — `VPADDD ymm1, ymm2, ymm3` (avx2) ([`vpaddd`]).
pub fn _mm256_add_epi32(a: M256i, b: M256i) -> M256i {
    vpaddd(a, b)
}

/// `_mm256_add_epi64(a, b)` — `VPADDQ ymm1, ymm2, ymm3` (avx2) ([`vpaddq`]).
pub fn _mm256_add_epi64(a: M256i, b: M256i) -> M256i {
    vpaddq(a, b)
}

/// `_mm256_xor_si256(a, b)` — `VPXOR ymm1, ymm2, ymm3` (avx2): `DEST :=
/// SRC1 XOR SRC2` ([`vpxord`], bitwise).
pub fn _mm256_xor_si256(a: M256i, b: M256i) -> M256i {
    vpxord(a, b)
}

/// `_mm256_and_si256(a, b)` — `VPAND ymm1, ymm2, ymm3` (avx2) ([`vpandd`]).
pub fn _mm256_and_si256(a: M256i, b: M256i) -> M256i {
    vpandd(a, b)
}

/// `_mm256_or_si256(a, b)` — `VPOR ymm1, ymm2, ymm3` (avx2) ([`vpord`]).
pub fn _mm256_or_si256(a: M256i, b: M256i) -> M256i {
    vpord(a, b)
}

/// `_mm256_shuffle_epi8(a, b)` — `VPSHUFB ymm1, ymm2, ymm3` (avx2), `SRC1 = a`
/// (table), `SRC2 = b` (control), per 128-bit lane ([`vpshufb`]).
pub fn _mm256_shuffle_epi8(a: M256i, b: M256i) -> M256i {
    vpshufb(a, b)
}

/// `_mm256_permutevar8x32_epi32(a, idx)` — `VPERMD ymm1, ymm2, ymm3` (avx2)
/// with `SRC1 = idx` (ymm2) and `SRC2 = a`: `r[j] = a[idx[j] & 7]`. **The
/// table is the first argument** of the intrinsic but the second source of
/// the instruction ([`vpermd`]).
pub fn _mm256_permutevar8x32_epi32(a: M256i, idx: M256i) -> M256i {
    vpermd(idx, a)
}

/// `_mm256_slli_epi32::<IMM8>(a)` — `VPSLLD ymm1, ymm2, imm8` (avx2), a count
/// above 31 gives 0 ([`vpslld_imm`]).
pub fn _mm256_slli_epi32(a: M256i, imm8: i32) -> M256i {
    vpslld_imm(a, imm8)
}

/// `_mm256_srli_epi32::<IMM8>(a)` — `VPSRLD ymm1, ymm2, imm8` (avx2)
/// ([`vpsrld_imm`]).
pub fn _mm256_srli_epi32(a: M256i, imm8: i32) -> M256i {
    vpsrld_imm(a, imm8)
}

/// `_mm256_slli_epi64::<IMM8>(a)` — `VPSLLQ ymm1, ymm2, imm8` (avx2), a count
/// above 63 gives 0 ([`vpsllq_imm`]).
pub fn _mm256_slli_epi64(a: M256i, imm8: i32) -> M256i {
    vpsllq_imm(a, imm8)
}

/// `_mm256_srli_epi64::<IMM8>(a)` — `VPSRLQ ymm1, ymm2, imm8` (avx2)
/// ([`vpsrlq_imm`]).
pub fn _mm256_srli_epi64(a: M256i, imm8: i32) -> M256i {
    vpsrlq_imm(a, imm8)
}

/// `_mm256_blend_epi32::<IMM8>(a, b)` — `VPBLENDD ymm1, ymm2, ymm3, imm8`
/// (avx2), `SRC1 = a`, `SRC2 = b`: dword `j` from `b` iff `IMM8[j]`
/// ([`vpblendd`]).
pub fn _mm256_blend_epi32(a: M256i, b: M256i, imm8: i32) -> M256i {
    vpblendd(a, b, imm8)
}

/// `_mm256_alignr_epi8::<IMM8>(a, b)` — `VPALIGNR ymm1, ymm2, ymm3, imm8`
/// (avx2), `SRC1 = a` (high), `SRC2 = b` (low), per 128-bit lane
/// ([`vpalignr256`]).
pub fn _mm256_alignr_epi8(a: M256i, b: M256i, imm8: i32) -> M256i {
    vpalignr256(a, b, imm8)
}

/// `_mm256_set1_epi32(a)` — composite (`VPBROADCASTD ymm`, avx): every dword
/// is `a` (two's complement) ([`vpbroadcastd`]).
pub fn _mm256_set1_epi32(a: i32) -> M256i {
    vpbroadcastd(a as u32)
}

/// `_mm256_set1_epi64x(a)` — composite (`VPBROADCASTQ ymm`, avx): every qword
/// is `a` ([`vpbroadcastq`]).
pub fn _mm256_set1_epi64x(a: i64) -> M256i {
    vpbroadcastq(a as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::x86_64::wide::dword;

    #[test]
    fn known_answers() {
        let a: M256i = core::array::from_fn(|i| i as u8);
        let b: M256i = core::array::from_fn(|i| 0x80 | i as u8);
        // VPALIGNR works per 128-bit lane (unlike a 256-bit byte shift).
        let r = _mm256_alignr_epi8(a, b, 4);
        assert_eq!(&r[..12], &b[4..16]);
        assert_eq!(&r[12..16], &a[0..4]);
        assert_eq!(&r[16..28], &b[20..32]);
        assert_eq!(&r[28..32], &a[16..20]);
        assert_eq!(_mm256_alignr_epi8(a, b, 32), [0; 32]);
        // VPBLENDD 0xAA: odd dwords from b.
        let r = _mm256_blend_epi32(a, b, 0xaa);
        for j in 0..8 {
            assert_eq!(dword(&r, j), dword(if j % 2 == 1 { &b } else { &a }, j));
        }
        // VPERMD with the table first: reverse the dwords.
        let mut idx = [0u8; 32];
        for j in 0..8 {
            crate::x86_64::wide::set_dword(&mut idx, j, 7 - j as u32);
        }
        let r = _mm256_permutevar8x32_epi32(a, idx);
        for j in 0..8 {
            assert_eq!(dword(&r, j), dword(&a, 7 - j));
        }
        assert_eq!(_mm256_set1_epi32(-2), core::array::from_fn(|i| if i % 4 == 0 { 0xfe } else { 0xff }));
    }
}
