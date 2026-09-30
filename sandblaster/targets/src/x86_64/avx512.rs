//! AVX-512F / BW / VL / DQ integer intrinsics (Intel SDM transcriptions).
//!
//! Each model is the stdarch intrinsic of the same name on the byte
//! representation of [`crate::x86_64::wide`] (`__m512i` = [`M512i`],
//! `__m256i` = [`M256i`], `__mmaskN` = `uN`), and delegates to the
//! VL-generic model of the instruction it compiles to in [`super::vec`],
//! whose doc comment quotes the SDM `Operation` section. The doc comment of
//! each intrinsic names the instruction and which argument is which operand.
//! Immediates (`const IMM8`, `const MASK`) are `i32` arguments in
//! `0..=255`, the range rustc accepts; the models panic outside it.
//! `_mm256_*` models here are the EVEX.256 (AVX512VL) forms.
#![forbid(unsafe_code)]

use super::vec::{
    vmovdqa32_masked, vmovdqa64_masked, vmovdqu, vpaddd, vpaddq, vpandd, vpandnd, vpblendmd, vpblendmq, vpbroadcastd,
    vpbroadcastq, vpcmpeqd, vpcmpeqq, vpcmpuq_lt, vpermd, vpermi2q, vpermq, vpmullq, vpmuludq, vpord, vprold, vprolq,
    vprolvd, vprolvq, vprord, vprorq, vprorvd, vprorvq, vpshufb, vpslld_imm, vpsllq_imm, vpsllvq, vpsrld_imm,
    vpsrlq_imm, vpsrlvq, vpsubd, vpsubq, vpternlogd, vpternlogq, vpunpckhdq, vpunpckhqdq, vpunpckldq, vpunpcklqdq,
    vpxord, vshufi32x4, vshufi64x2,
};
use super::wide::{M256i, M512i, Mmask8, Mmask16};

/// `_mm512_loadu_si512` — `VMOVDQU32 zmm1, m512` (avx512f): `DEST[511:0] :=
/// SRC[511:0]` ([`vmovdqu`]), modelled on `&[u8; 64]` like the generated load
/// helpers: `r[i] = mem[i]`.
pub fn _mm512_loadu_si512(mem: &[u8; 64]) -> M512i {
    vmovdqu(mem)
}

/// `_mm512_storeu_si512` — `VMOVDQU32 m512, zmm1` (avx512f), as a pure
/// function returning the 64 bytes written ([`vmovdqu`]).
pub fn _mm512_storeu_si512(a: M512i) -> [u8; 64] {
    vmovdqu(&a)
}

/// `_mm512_add_epi32(a, b)` — `VPADDD zmm1, zmm2, zmm3` (avx512f), `SRC1 = a`,
/// `SRC2 = b` ([`vpaddd`]).
pub fn _mm512_add_epi32(a: M512i, b: M512i) -> M512i {
    vpaddd(a, b)
}

/// `_mm512_add_epi64(a, b)` — `VPADDQ zmm1, zmm2, zmm3` (avx512f) ([`vpaddq`]).
pub fn _mm512_add_epi64(a: M512i, b: M512i) -> M512i {
    vpaddq(a, b)
}

/// `_mm512_sub_epi32(a, b)` — `VPSUBD zmm1, zmm2, zmm3` (avx512f): `a - b` per
/// dword ([`vpsubd`]).
pub fn _mm512_sub_epi32(a: M512i, b: M512i) -> M512i {
    vpsubd(a, b)
}

/// `_mm512_sub_epi64(a, b)` — `VPSUBQ zmm1, zmm2, zmm3` (avx512f): `a - b` per
/// qword ([`vpsubq`]).
pub fn _mm512_sub_epi64(a: M512i, b: M512i) -> M512i {
    vpsubq(a, b)
}

/// `_mm512_xor_si512(a, b)` — `VPXORD`/`VPXORQ zmm` (avx512f; bitwise, so the
/// element size is immaterial) ([`vpxord`]).
pub fn _mm512_xor_si512(a: M512i, b: M512i) -> M512i {
    vpxord(a, b)
}

/// `_mm512_and_si512(a, b)` — `VPANDD`/`VPANDQ zmm` (avx512f) ([`vpandd`]).
pub fn _mm512_and_si512(a: M512i, b: M512i) -> M512i {
    vpandd(a, b)
}

/// `_mm512_or_si512(a, b)` — `VPORD`/`VPORQ zmm` (avx512f) ([`vpord`]).
pub fn _mm512_or_si512(a: M512i, b: M512i) -> M512i {
    vpord(a, b)
}

/// `_mm512_andnot_si512(a, b)` — `VPANDND`/`VPANDNQ zmm` (avx512f), `SRC1 = a`
/// (inverted), `SRC2 = b`: `!a & b` ([`vpandnd`]).
pub fn _mm512_andnot_si512(a: M512i, b: M512i) -> M512i {
    vpandnd(a, b)
}

/// `_mm512_ternarylogic_epi32::<IMM8>(a, b, c)` — `VPTERNLOGD zmm1, zmm2,
/// zmm3, imm8` (avx512f), `DEST = a`, `SRC1 = b`, `SRC2 = c`, `0 ≤ IMM8 ≤ 255`:
/// result bit = `IMM8[(a << 2) | (b << 1) | c]` ([`vpternlogd`]).
pub fn _mm512_ternarylogic_epi32(a: M512i, b: M512i, c: M512i, imm8: i32) -> M512i {
    vpternlogd(a, b, c, imm8)
}

/// `_mm512_ternarylogic_epi64::<IMM8>(a, b, c)` — `VPTERNLOGQ zmm1, zmm2,
/// zmm3, imm8` (avx512f), operands as for the `epi32` form ([`vpternlogq`]).
pub fn _mm512_ternarylogic_epi64(a: M512i, b: M512i, c: M512i, imm8: i32) -> M512i {
    vpternlogq(a, b, c, imm8)
}

/// `_mm512_rol_epi32::<IMM8>(a)` — `VPROLD zmm1, zmm2, imm8` (avx512f),
/// `0 ≤ IMM8 ≤ 255`, rotate count `IMM8 mod 32` ([`vprold`]).
pub fn _mm512_rol_epi32(a: M512i, imm8: i32) -> M512i {
    vprold(a, imm8)
}

/// `_mm512_ror_epi32::<IMM8>(a)` — `VPRORD zmm1, zmm2, imm8` (avx512f),
/// count `IMM8 mod 32` ([`vprord`]).
pub fn _mm512_ror_epi32(a: M512i, imm8: i32) -> M512i {
    vprord(a, imm8)
}

/// `_mm512_rol_epi64::<IMM8>(a)` — `VPROLQ zmm1, zmm2, imm8` (avx512f),
/// count `IMM8 mod 64` ([`vprolq`]).
pub fn _mm512_rol_epi64(a: M512i, imm8: i32) -> M512i {
    vprolq(a, imm8)
}

/// `_mm512_ror_epi64::<IMM8>(a)` — `VPRORQ zmm1, zmm2, imm8` (avx512f),
/// count `IMM8 mod 64` ([`vprorq`]).
pub fn _mm512_ror_epi64(a: M512i, imm8: i32) -> M512i {
    vprorq(a, imm8)
}

/// `_mm512_rolv_epi32(a, b)` — `VPROLVD zmm1, zmm2, zmm3` (avx512f): dword `j`
/// of `a` rotated left by `b[j] mod 32` ([`vprolvd`]).
pub fn _mm512_rolv_epi32(a: M512i, b: M512i) -> M512i {
    vprolvd(a, b)
}

/// `_mm512_rorv_epi32(a, b)` — `VPRORVD zmm1, zmm2, zmm3` (avx512f)
/// ([`vprorvd`]).
pub fn _mm512_rorv_epi32(a: M512i, b: M512i) -> M512i {
    vprorvd(a, b)
}

/// `_mm512_rolv_epi64(a, b)` — `VPROLVQ zmm1, zmm2, zmm3` (avx512f): count
/// `b[j] mod 64` ([`vprolvq`]).
pub fn _mm512_rolv_epi64(a: M512i, b: M512i) -> M512i {
    vprolvq(a, b)
}

/// `_mm512_rorv_epi64(a, b)` — `VPRORVQ zmm1, zmm2, zmm3` (avx512f)
/// ([`vprorvq`]).
pub fn _mm512_rorv_epi64(a: M512i, b: M512i) -> M512i {
    vprorvq(a, b)
}

/// `_mm512_slli_epi32::<IMM8>(a)` — `VPSLLD zmm1, zmm2, imm8` (avx512f),
/// `0 ≤ IMM8 ≤ 255` (stdarch `const IMM8: u32`); a count above 31 gives 0
/// ([`vpslld_imm`]).
pub fn _mm512_slli_epi32(a: M512i, imm8: i32) -> M512i {
    vpslld_imm(a, imm8)
}

/// `_mm512_srli_epi32::<IMM8>(a)` — `VPSRLD zmm1, zmm2, imm8` (avx512f)
/// ([`vpsrld_imm`]).
pub fn _mm512_srli_epi32(a: M512i, imm8: i32) -> M512i {
    vpsrld_imm(a, imm8)
}

/// `_mm512_slli_epi64::<IMM8>(a)` — `VPSLLQ zmm1, zmm2, imm8` (avx512f); a
/// count above 63 gives 0 ([`vpsllq_imm`]).
pub fn _mm512_slli_epi64(a: M512i, imm8: i32) -> M512i {
    vpsllq_imm(a, imm8)
}

/// `_mm512_srli_epi64::<IMM8>(a)` — `VPSRLQ zmm1, zmm2, imm8` (avx512f)
/// ([`vpsrlq_imm`]).
pub fn _mm512_srli_epi64(a: M512i, imm8: i32) -> M512i {
    vpsrlq_imm(a, imm8)
}

/// `_mm512_sllv_epi64(a, count)` — `VPSLLVQ zmm1, zmm2, zmm3` (avx512f), a
/// 64-bit count of 64 or more gives 0 ([`vpsllvq`]).
pub fn _mm512_sllv_epi64(a: M512i, count: M512i) -> M512i {
    vpsllvq(a, count)
}

/// `_mm512_srlv_epi64(a, count)` — `VPSRLVQ zmm1, zmm2, zmm3` (avx512f)
/// ([`vpsrlvq`]).
pub fn _mm512_srlv_epi64(a: M512i, count: M512i) -> M512i {
    vpsrlvq(a, count)
}

/// `_mm512_shuffle_epi8(a, b)` — `VPSHUFB zmm1, zmm2, zmm3` (avx512bw),
/// `SRC1 = a` (table), `SRC2 = b` (control): per 128-bit lane
/// ([`vpshufb`]).
pub fn _mm512_shuffle_epi8(a: M512i, b: M512i) -> M512i {
    vpshufb(a, b)
}

/// `_mm512_permutexvar_epi32(idx, a)` — `VPERMD zmm1, zmm2, zmm3` (avx512f),
/// `SRC1 = idx`, `SRC2 = a`: `r[j] = a[idx[j] & 15]` ([`vpermd`]).
pub fn _mm512_permutexvar_epi32(idx: M512i, a: M512i) -> M512i {
    vpermd(idx, a)
}

/// `_mm512_permutexvar_epi64(idx, a)` — `VPERMQ zmm1, zmm2, zmm3` (avx512f),
/// `SRC1 = idx`, `SRC2 = a`: `r[j] = a[idx[j] & 7]` ([`vpermq`]).
pub fn _mm512_permutexvar_epi64(idx: M512i, a: M512i) -> M512i {
    vpermq(idx, a)
}

/// `_mm512_permutex2var_epi64(a, idx, b)` — `VPERMI2Q`/`VPERMT2Q zmm`
/// (avx512f), indices `idx`, first table `a`, second table `b`:
/// `r[j] = (idx[j] & 8 ≠ 0 ? b : a)[idx[j] & 7]` ([`vpermi2q`]).
pub fn _mm512_permutex2var_epi64(a: M512i, idx: M512i, b: M512i) -> M512i {
    vpermi2q(idx, a, b)
}

/// `_mm512_shuffle_i32x4::<MASK>(a, b)` — `VSHUFI32X4 zmm1, zmm2, zmm3, imm8`
/// (avx512f), `SRC1 = a`, `SRC2 = b`, `0 ≤ MASK ≤ 255` ([`vshufi32x4`]).
pub fn _mm512_shuffle_i32x4(a: M512i, b: M512i, imm8: i32) -> M512i {
    vshufi32x4(a, b, imm8)
}

/// `_mm512_shuffle_i64x2::<MASK>(a, b)` — `VSHUFI64X2 zmm1, zmm2, zmm3, imm8`
/// (avx512f), `SRC1 = a`, `SRC2 = b`, `0 ≤ MASK ≤ 255` ([`vshufi64x2`]).
pub fn _mm512_shuffle_i64x2(a: M512i, b: M512i, imm8: i32) -> M512i {
    vshufi64x2(a, b, imm8)
}

/// `_mm512_unpacklo_epi32(a, b)` — `VPUNPCKLDQ zmm1, zmm2, zmm3` (avx512f)
/// ([`vpunpckldq`]).
pub fn _mm512_unpacklo_epi32(a: M512i, b: M512i) -> M512i {
    vpunpckldq(a, b)
}

/// `_mm512_unpackhi_epi32(a, b)` — `VPUNPCKHDQ zmm1, zmm2, zmm3` (avx512f)
/// ([`vpunpckhdq`]).
pub fn _mm512_unpackhi_epi32(a: M512i, b: M512i) -> M512i {
    vpunpckhdq(a, b)
}

/// `_mm512_unpacklo_epi64(a, b)` — `VPUNPCKLQDQ zmm1, zmm2, zmm3` (avx512f)
/// ([`vpunpcklqdq`]).
pub fn _mm512_unpacklo_epi64(a: M512i, b: M512i) -> M512i {
    vpunpcklqdq(a, b)
}

/// `_mm512_unpackhi_epi64(a, b)` — `VPUNPCKHQDQ zmm1, zmm2, zmm3` (avx512f)
/// ([`vpunpckhqdq`]).
pub fn _mm512_unpackhi_epi64(a: M512i, b: M512i) -> M512i {
    vpunpckhqdq(a, b)
}

/// `_mm512_set1_epi32(a)` — composite (`VPBROADCASTD zmm1, r32`, avx512f):
/// every dword is `a` (two's complement) ([`vpbroadcastd`]).
pub fn _mm512_set1_epi32(a: i32) -> M512i {
    vpbroadcastd(a as u32)
}

/// `_mm512_set1_epi64(a)` — composite (`VPBROADCASTQ zmm1, r64`, avx512f)
/// ([`vpbroadcastq`]).
pub fn _mm512_set1_epi64(a: i64) -> M512i {
    vpbroadcastq(a as u64)
}

/// `_mm512_mask_blend_epi32(k, a, b)` — `VPBLENDMD zmm1 {k1}, zmm2, zmm3`
/// (avx512f), `SRC1 = a`, `SRC2 = b`: `r[j] = k[j] ? b[j] : a[j]`
/// ([`vpblendmd`]).
pub fn _mm512_mask_blend_epi32(k: Mmask16, a: M512i, b: M512i) -> M512i {
    vpblendmd(u64::from(k), a, b)
}

/// `_mm512_mask_blend_epi64(k, a, b)` — `VPBLENDMQ zmm1 {k1}, zmm2, zmm3`
/// (avx512f) ([`vpblendmq`]).
pub fn _mm512_mask_blend_epi64(k: Mmask8, a: M512i, b: M512i) -> M512i {
    vpblendmq(u64::from(k), a, b)
}

/// `_mm512_cmplt_epu64_mask(a, b)` — `VPCMPUQ k1, zmm1, zmm2, 1` (avx512f):
/// bit `j` = `a[j] < b[j]` unsigned ([`vpcmpuq_lt`]).
pub fn _mm512_cmplt_epu64_mask(a: M512i, b: M512i) -> Mmask8 {
    vpcmpuq_lt(a, b) as Mmask8
}

/// `_mm512_cmpeq_epi64_mask(a, b)` — `VPCMPEQQ k1, zmm1, zmm2` (avx512f)
/// ([`vpcmpeqq`]).
pub fn _mm512_cmpeq_epi64_mask(a: M512i, b: M512i) -> Mmask8 {
    vpcmpeqq(a, b) as Mmask8
}

/// `_mm512_cmpeq_epi32_mask(a, b)` — `VPCMPEQD k1, zmm1, zmm2` (avx512f)
/// ([`vpcmpeqd`]).
pub fn _mm512_cmpeq_epi32_mask(a: M512i, b: M512i) -> Mmask16 {
    vpcmpeqd(a, b) as Mmask16
}

/// `_mm512_maskz_mov_epi32(k, a)` — `VMOVDQA32 zmm1 {k1}{z}, zmm2` (avx512f):
/// `r[j] = k[j] ? a[j] : 0` ([`vmovdqa32_masked`], zeroing).
pub fn _mm512_maskz_mov_epi32(k: Mmask16, a: M512i) -> M512i {
    vmovdqa32_masked(None, u64::from(k), a)
}

/// `_mm512_mask_mov_epi32(src, k, a)` — `VMOVDQA32 zmm1 {k1}, zmm2`
/// (avx512f), `DEST` initially `src`: `r[j] = k[j] ? a[j] : src[j]`
/// ([`vmovdqa32_masked`], merging).
pub fn _mm512_mask_mov_epi32(src: M512i, k: Mmask16, a: M512i) -> M512i {
    vmovdqa32_masked(Some(src), u64::from(k), a)
}

/// `_mm512_maskz_mov_epi64(k, a)` — `VMOVDQA64 zmm1 {k1}{z}, zmm2` (avx512f)
/// ([`vmovdqa64_masked`], zeroing).
pub fn _mm512_maskz_mov_epi64(k: Mmask8, a: M512i) -> M512i {
    vmovdqa64_masked(None, u64::from(k), a)
}

/// `_mm512_mask_mov_epi64(src, k, a)` — `VMOVDQA64 zmm1 {k1}, zmm2`
/// (avx512f) ([`vmovdqa64_masked`], merging).
pub fn _mm512_mask_mov_epi64(src: M512i, k: Mmask8, a: M512i) -> M512i {
    vmovdqa64_masked(Some(src), u64::from(k), a)
}

/// `_mm512_mullo_epi64(a, b)` — `VPMULLQ zmm1, zmm2, zmm3` (avx512dq): the low
/// 64 bits of each product ([`vpmullq`]).
pub fn _mm512_mullo_epi64(a: M512i, b: M512i) -> M512i {
    vpmullq(a, b)
}

/// `_mm512_mul_epu32(a, b)` — `VPMULUDQ zmm1, zmm2, zmm3` (avx512f): the full
/// product of the low dwords of each qword ([`vpmuludq`]).
pub fn _mm512_mul_epu32(a: M512i, b: M512i) -> M512i {
    vpmuludq(a, b)
}

/// `_mm256_ternarylogic_epi32::<IMM8>(a, b, c)` — `VPTERNLOGD ymm1, ymm2,
/// ymm3, imm8` (avx512f + avx512vl), operands as the 512-bit form
/// ([`vpternlogd`]).
pub fn _mm256_ternarylogic_epi32(a: M256i, b: M256i, c: M256i, imm8: i32) -> M256i {
    vpternlogd(a, b, c, imm8)
}

/// `_mm256_ternarylogic_epi64::<IMM8>(a, b, c)` — `VPTERNLOGQ ymm1, ymm2,
/// ymm3, imm8` (avx512f + avx512vl) ([`vpternlogq`]).
pub fn _mm256_ternarylogic_epi64(a: M256i, b: M256i, c: M256i, imm8: i32) -> M256i {
    vpternlogq(a, b, c, imm8)
}

/// `_mm256_rol_epi32::<IMM8>(a)` — `VPROLD ymm1, ymm2, imm8` (avx512f +
/// avx512vl) ([`vprold`]).
pub fn _mm256_rol_epi32(a: M256i, imm8: i32) -> M256i {
    vprold(a, imm8)
}

/// `_mm256_ror_epi32::<IMM8>(a)` — `VPRORD ymm1, ymm2, imm8` (avx512f +
/// avx512vl) ([`vprord`]).
pub fn _mm256_ror_epi32(a: M256i, imm8: i32) -> M256i {
    vprord(a, imm8)
}

/// `_mm256_rol_epi64::<IMM8>(a)` — `VPROLQ ymm1, ymm2, imm8` (avx512f +
/// avx512vl) ([`vprolq`]).
pub fn _mm256_rol_epi64(a: M256i, imm8: i32) -> M256i {
    vprolq(a, imm8)
}

/// `_mm256_ror_epi64::<IMM8>(a)` — `VPRORQ ymm1, ymm2, imm8` (avx512f +
/// avx512vl) ([`vprorq`]).
pub fn _mm256_ror_epi64(a: M256i, imm8: i32) -> M256i {
    vprorq(a, imm8)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::x86_64::wide::{dword, qword};

    fn iota(base: u8) -> M512i {
        core::array::from_fn(|i| base.wrapping_add(i as u8))
    }

    #[test]
    fn known_answers() {
        let a = iota(0);
        let b = iota(0x40);
        // unpack: per 128-bit lane.
        let lo = _mm512_unpacklo_epi32(a, b);
        assert_eq!([dword(&lo, 0), dword(&lo, 1), dword(&lo, 2), dword(&lo, 3)], [dword(&a, 0), dword(&b, 0), dword(&a, 1), dword(&b, 1)]);
        assert_eq!(dword(&lo, 4), dword(&a, 4));
        let hi = _mm512_unpackhi_epi64(a, b);
        assert_eq!([qword(&hi, 0), qword(&hi, 1), qword(&hi, 6), qword(&hi, 7)], [qword(&a, 1), qword(&b, 1), qword(&a, 7), qword(&b, 7)]);
        // blend / masked moves / compares.
        let r = _mm512_mask_blend_epi32(0x00ff, a, b);
        assert_eq!((dword(&r, 0), dword(&r, 8)), (dword(&b, 0), dword(&a, 8)));
        assert_eq!(_mm512_maskz_mov_epi64(0, a), [0; 64]);
        assert_eq!(_mm512_mask_mov_epi32(b, 0xffff, a), a);
        assert_eq!(_mm512_cmpeq_epi32_mask(a, a), 0xffff);
        assert_eq!(_mm512_cmpeq_epi64_mask(a, b), 0);
        assert_eq!(_mm512_cmplt_epu64_mask(a, b), 0xff);
        assert_eq!(_mm512_cmplt_epu64_mask(b, a), 0);
        // set1, mul, andnot.
        let s = _mm512_set1_epi64(-1);
        assert_eq!(s, [0xff; 64]);
        assert_eq!(_mm512_andnot_si512(s, a), [0; 64]);
        let m = _mm512_mul_epu32(s, s);
        assert_eq!(qword(&m, 3), 0xffff_fffe_0000_0001);
        assert_eq!(qword(&_mm512_mullo_epi64(s, s), 5), 1);
        // shifts past the width give zero, rotates wrap.
        assert_eq!(_mm512_slli_epi32(s, 32), [0; 64]);
        assert_eq!(_mm512_srli_epi64(s, 64), [0; 64]);
        assert_eq!(_mm512_rol_epi32(a, 32), a);
        assert_eq!(_mm512_ror_epi64(a, 64 + 8), core::array::from_fn(|i| a[(i & !7) | ((i + 1) & 7)]));
        // shuffle_i32x4 0x4e: lanes (a2, a3, b0, b1).
        let sh = _mm512_shuffle_i32x4(a, b, 0x4e);
        assert_eq!((sh[0], sh[16], sh[32], sh[48]), (32, 48, 0x40, 0x50));
    }
}
