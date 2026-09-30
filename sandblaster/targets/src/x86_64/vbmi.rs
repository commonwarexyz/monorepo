//! AVX-512 VBMI (`VPERMB`, `VPERMI2B`/`VPERMT2B`, `VPMULTISHIFTQB`), VBMI2
//! funnel shifts (`VPSHLDV*`, `VPSHRDV*`, `VPSHLD*`), VPOPCNTDQ
//! (`VPOPCNTD/Q`) and BITALG (`VPOPCNTB/W`) (Intel SDM transcriptions).
#![forbid(unsafe_code)]
// Element loops mirror the pseudocode.
#![allow(clippy::needless_range_loop)]

use super::wide::{M512i, dword, qword, set_dword, set_qword, set_word, word};

/// `VPERMB` (`SRC1` holds the indices, `SRC2` the table):
///
/// ```text
/// (KL, VL) = (16, 128), (32, 256), (64, 512)
/// IF VL = 128: n := 3;
/// ELSE IF VL = 256: n := 4;
/// ELSE IF VL = 512: n := 5;
/// FI;
/// FOR j := 0 TO KL-1:
///     id := SRC1[j*8 + n : j*8] ; // location of the source byte
///     DEST[j*8 + 7: j*8] := SRC2[id*8 +7: id*8];
/// ```
pub fn vpermb<const N: usize>(src1: [u8; N], src2: [u8; N]) -> [u8; N] {
    let mut dest = [0u8; N];
    for j in 0..N {
        let id = src1[j] as usize & (N - 1);
        dest[j] = src2[id];
    }
    dest
}

/// `VPERMI2B` / `VPERMT2B` (two-table byte permute; `index` holds the
/// indices, `src1` the first table, `src2` the second):
///
/// ```text
/// (KL, VL) = (16, 128), (32, 256), (64, 512)
/// IF VL = 128: id := 3;
/// ELSE IF VL = 256: id := 4;
/// ELSE IF VL = 512: id := 5;
/// FI;
/// TMP_DEST[VL-1:0] := DEST[VL-1:0];        -- the indices
/// FOR j := 0 TO KL-1
///     off := 8*TMP_DEST[j*8 + id: j*8] ;
///     DEST[j*8 + 7: j*8] := TMP_DEST[j*8+id+1]? SRC2[off+7:off] : SRC1[off+7:off];
/// ```
pub fn vpermi2b<const N: usize>(index: [u8; N], src1: [u8; N], src2: [u8; N]) -> [u8; N] {
    let mut dest = [0u8; N];
    for j in 0..N {
        let ix = index[j] as usize;
        let off = ix & (N - 1);
        dest[j] = if ix & N != 0 { src2[off] } else { src1[off] };
    }
    dest
}

/// `VPMULTISHIFTQB DEST, SRC1, SRC2` (`SRC1` holds the controls, `SRC2` the
/// data qwords):
///
/// ```text
/// (KL, VL) = (2, 128),(4, 256), (8, 512)
/// FOR i := 0 TO KL-1
///     tcur := src2.qword[i];
///     FOR j := 0 to 7
///         ctrl := src1.qword[i].byte[j] & 63;
///         FOR k := 0 to 7
///             res.bit[k] := tcur.bit[ (ctrl+k) mod 64 ];
///         ENDFOR
///         DEST.qword[i].byte[j] := res;
///     ENDFOR
/// ENDFOR
/// ```
pub fn vpmultishiftqb<const N: usize>(src1: [u8; N], src2: [u8; N]) -> [u8; N] {
    let mut dest = [0u8; N];
    for i in 0..N / 8 {
        let tcur = qword(&src2, i);
        for j in 0..8 {
            let ctrl = (src1[8 * i + j] & 63) as u64;
            let mut res = 0u8;
            for k in 0..8u64 {
                res |= (((tcur >> ((ctrl + k) % 64)) & 1) as u8) << k;
            }
            dest[8 * i + j] = res;
        }
    }
    dest
}

/// SDM `concat(a, b)` of the VBMI2 shifts for qwords: `a[63:0] << 64 |
/// b[63:0]` (`a` high).
pub fn concat_qwords(a: u64, b: u64) -> u128 {
    ((a as u128) << 64) | (b as u128)
}

/// SDM `concat(a, b)` for dwords: `a[31:0] << 32 | b[31:0]`.
pub fn concat_dwords(a: u32, b: u32) -> u64 {
    ((a as u64) << 32) | (b as u64)
}

/// `VPSHLDVQ DEST, SRC2, SRC3`:
///
/// ```text
/// (KL, VL) = (2, 128), (4, 256), (8, 512)
/// FOR j := 0 TO KL-1:
///     tsrc3 := SRC3.qword[j]
///     tmp := concat(DEST.qword[j], SRC2.qword[j]) << (tsrc3 & 63)
///     DEST.qword[j] := tmp.qword[1]
/// ```
pub fn vpshldvq<const N: usize>(dest: [u8; N], src2: [u8; N], src3: [u8; N]) -> [u8; N] {
    let mut out = [0u8; N];
    for j in 0..N / 8 {
        let tsrc3 = qword(&src3, j);
        let tmp = concat_qwords(qword(&dest, j), qword(&src2, j)) << (tsrc3 & 63);
        set_qword(&mut out, j, (tmp >> 64) as u64);
    }
    out
}

/// `VPSHRDVQ DEST, SRC2, SRC3`: `tmp := concat(SRC2.qword[j], DEST.qword[j]) >>
/// (tsrc3 & 63); DEST.qword[j] := tmp.qword[0]` (`SRC2` is the **high** half).
pub fn vpshrdvq<const N: usize>(dest: [u8; N], src2: [u8; N], src3: [u8; N]) -> [u8; N] {
    let mut out = [0u8; N];
    for j in 0..N / 8 {
        let tsrc3 = qword(&src3, j);
        let tmp = concat_qwords(qword(&src2, j), qword(&dest, j)) >> (tsrc3 & 63);
        set_qword(&mut out, j, tmp as u64);
    }
    out
}

/// `VPSHLDVD DEST, SRC2, SRC3`: `(KL, VL) = (4, 128), (8, 256), (16, 512)`;
/// `tmp := concat(DEST.dword[j], SRC2.dword[j]) << (tsrc3 & 31); DEST.dword[j]
/// := tmp.dword[1]`.
pub fn vpshldvd<const N: usize>(dest: [u8; N], src2: [u8; N], src3: [u8; N]) -> [u8; N] {
    let mut out = [0u8; N];
    for j in 0..N / 4 {
        let tsrc3 = dword(&src3, j);
        let tmp = concat_dwords(dword(&dest, j), dword(&src2, j)) << (tsrc3 & 31);
        set_dword(&mut out, j, (tmp >> 32) as u32);
    }
    out
}

/// `VPSHRDVD DEST, SRC2, SRC3`: `tmp := concat(SRC2.dword[j], DEST.dword[j]) >>
/// (tsrc3 & 31); DEST.dword[j] := tmp.dword[0]`.
pub fn vpshrdvd<const N: usize>(dest: [u8; N], src2: [u8; N], src3: [u8; N]) -> [u8; N] {
    let mut out = [0u8; N];
    for j in 0..N / 4 {
        let tsrc3 = dword(&src3, j);
        let tmp = concat_dwords(dword(&src2, j), dword(&dest, j)) >> (tsrc3 & 31);
        set_dword(&mut out, j, tmp as u32);
    }
    out
}

/// `VPSHLDQ DEST, SRC2, SRC3, imm8`, `0 ≤ imm8 ≤ 255`:
///
/// ```text
/// FOR j := 0 TO KL-1:
///     tsrc3 := SRC3.qword[j]
///     tmp := concat(SRC2.qword[j], tsrc3) << (imm8 & 63)
///     DEST.qword[j] := tmp.qword[1]
/// ```
pub fn vpshldq_imm<const N: usize>(src2: [u8; N], src3: [u8; N], imm8: i32) -> [u8; N] {
    assert!((0..=255).contains(&imm8), "vpshldq: immediate {imm8} out of range 0..=255");
    let mut dest = [0u8; N];
    for j in 0..N / 8 {
        let tsrc3 = qword(&src3, j);
        let tmp = concat_qwords(qword(&src2, j), tsrc3) << (imm8 & 63);
        set_qword(&mut dest, j, (tmp >> 64) as u64);
    }
    dest
}

/// `VPSHLDD DEST, SRC2, SRC3, imm8`, `0 ≤ imm8 ≤ 255`: `tmp :=
/// concat(SRC2.dword[j], tsrc3) << (imm8 & 31); DEST.dword[j] := tmp.dword[1]`.
pub fn vpshldd_imm<const N: usize>(src2: [u8; N], src3: [u8; N], imm8: i32) -> [u8; N] {
    assert!((0..=255).contains(&imm8), "vpshldd: immediate {imm8} out of range 0..=255");
    let mut dest = [0u8; N];
    for j in 0..N / 4 {
        let tsrc3 = dword(&src3, j);
        let tmp = concat_dwords(dword(&src2, j), tsrc3) << (imm8 & 31);
        set_dword(&mut dest, j, (tmp >> 32) as u32);
    }
    dest
}

/// `VPOPCNTQ`: `(KL, VL) = (2, 128), (4, 256), (8, 512)`; `FOR j := 0 TO KL-1:
/// t := SRC.qword[j]; DEST.qword[j] := POPCNT(t)` (the number of set bits).
pub fn vpopcntq<const N: usize>(src: [u8; N]) -> [u8; N] {
    let mut dest = [0u8; N];
    for j in 0..N / 8 {
        set_qword(&mut dest, j, qword(&src, j).count_ones() as u64);
    }
    dest
}

/// `VPOPCNTD`: `FOR j := 0 TO KL-1: t := SRC.dword[j]; DEST.dword[j] :=
/// POPCNT(t)`.
pub fn vpopcntd<const N: usize>(src: [u8; N]) -> [u8; N] {
    let mut dest = [0u8; N];
    for j in 0..N / 4 {
        set_dword(&mut dest, j, dword(&src, j).count_ones());
    }
    dest
}

/// `VPOPCNTB` (BITALG): `(KL, VL) = (16, 128), (32, 256), (64, 512)`; `FOR j :=
/// 0 TO KL-1: DEST.byte[j] := POPCNT(SRC.byte[j])`.
pub fn vpopcntb<const N: usize>(src: [u8; N]) -> [u8; N] {
    let mut dest = [0u8; N];
    for j in 0..N {
        dest[j] = src[j].count_ones() as u8;
    }
    dest
}

/// `VPOPCNTW` (BITALG): `FOR j := 0 TO KL-1: DEST.word[j] :=
/// POPCNT(SRC.word[j])`.
pub fn vpopcntw<const N: usize>(src: [u8; N]) -> [u8; N] {
    let mut dest = [0u8; N];
    for j in 0..N / 2 {
        set_word(&mut dest, j, word(&src, j).count_ones() as u16);
    }
    dest
}

/// `_mm512_permutexvar_epi8(idx, a)` — `VPERMB zmm1, zmm2, zmm3`
/// (avx512vbmi), `SRC1 = idx`, `SRC2 = a`: `r[j] = a[idx[j] & 63]`
/// ([`vpermb`]).
pub fn _mm512_permutexvar_epi8(idx: M512i, a: M512i) -> M512i {
    vpermb(idx, a)
}

/// `_mm512_permutex2var_epi8(a, idx, b)` — `VPERMI2B`/`VPERMT2B zmm`
/// (avx512vbmi): `r[j] = (idx[j] & 64 ≠ 0 ? b : a)[idx[j] & 63]`
/// ([`vpermi2b`]).
pub fn _mm512_permutex2var_epi8(a: M512i, idx: M512i, b: M512i) -> M512i {
    vpermi2b(idx, a, b)
}

/// `_mm512_multishift_epi64_epi8(a, b)` — `VPMULTISHIFTQB zmm1, zmm2, zmm3`
/// (avx512vbmi), `SRC1 = a` (controls), `SRC2 = b` (data): byte `j` of qword
/// `i` is the 8 bits of `b.qword[i]` starting at bit `a.qword[i].byte[j] & 63`,
/// wrapping ([`vpmultishiftqb`]).
pub fn _mm512_multishift_epi64_epi8(a: M512i, b: M512i) -> M512i {
    vpmultishiftqb(a, b)
}

/// `_mm512_shldv_epi64(a, b, c)` — `VPSHLDVQ zmm1, zmm2, zmm3` (avx512vbmi2),
/// `DEST = a` (high), `SRC2 = b` (low), `SRC3 = c` (counts) ([`vpshldvq`]).
pub fn _mm512_shldv_epi64(a: M512i, b: M512i, c: M512i) -> M512i {
    vpshldvq(a, b, c)
}

/// `_mm512_shrdv_epi64(a, b, c)` — `VPSHRDVQ zmm1, zmm2, zmm3` (avx512vbmi2),
/// `DEST = a` (**low**), `SRC2 = b` (high), `SRC3 = c` ([`vpshrdvq`]).
pub fn _mm512_shrdv_epi64(a: M512i, b: M512i, c: M512i) -> M512i {
    vpshrdvq(a, b, c)
}

/// `_mm512_shldv_epi32(a, b, c)` — `VPSHLDVD zmm1, zmm2, zmm3` (avx512vbmi2)
/// ([`vpshldvd`]).
pub fn _mm512_shldv_epi32(a: M512i, b: M512i, c: M512i) -> M512i {
    vpshldvd(a, b, c)
}

/// `_mm512_shrdv_epi32(a, b, c)` — `VPSHRDVD zmm1, zmm2, zmm3` (avx512vbmi2)
/// ([`vpshrdvd`]).
pub fn _mm512_shrdv_epi32(a: M512i, b: M512i, c: M512i) -> M512i {
    vpshrdvd(a, b, c)
}

/// `_mm512_shldi_epi64::<IMM8>(a, b)` — `VPSHLDQ zmm1, zmm2, zmm3, imm8`
/// (avx512vbmi2), `SRC2 = a` (high), `SRC3 = b` (low), `0 ≤ IMM8 ≤ 255`,
/// count `IMM8 & 63` ([`vpshldq_imm`]).
pub fn _mm512_shldi_epi64(a: M512i, b: M512i, imm8: i32) -> M512i {
    vpshldq_imm(a, b, imm8)
}

/// `_mm512_shldi_epi32::<IMM8>(a, b)` — `VPSHLDD zmm1, zmm2, zmm3, imm8`
/// (avx512vbmi2), count `IMM8 & 31` ([`vpshldd_imm`]).
pub fn _mm512_shldi_epi32(a: M512i, b: M512i, imm8: i32) -> M512i {
    vpshldd_imm(a, b, imm8)
}

/// `_mm512_popcnt_epi64(a)` — `VPOPCNTQ zmm1, zmm2` (avx512vpopcntdq)
/// ([`vpopcntq`]).
pub fn _mm512_popcnt_epi64(a: M512i) -> M512i {
    vpopcntq(a)
}

/// `_mm512_popcnt_epi32(a)` — `VPOPCNTD zmm1, zmm2` (avx512vpopcntdq)
/// ([`vpopcntd`]).
pub fn _mm512_popcnt_epi32(a: M512i) -> M512i {
    vpopcntd(a)
}

/// `_mm512_popcnt_epi8(a)` — `VPOPCNTB zmm1, zmm2` (avx512bitalg)
/// ([`vpopcntb`]).
pub fn _mm512_popcnt_epi8(a: M512i) -> M512i {
    vpopcntb(a)
}

/// `_mm512_popcnt_epi16(a)` — `VPOPCNTW zmm1, zmm2` (avx512bitalg)
/// ([`vpopcntw`]).
pub fn _mm512_popcnt_epi16(a: M512i) -> M512i {
    vpopcntw(a)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::x86_64::wide::qword;

    #[test]
    fn known_answers() {
        let t: M512i = core::array::from_fn(|i| i as u8);
        // VPERMB: indices use 6 bits; bit 6 (and 7) ignored.
        let idx: M512i = core::array::from_fn(|j| (63 - j as u8) | 0xc0);
        assert_eq!(_mm512_permutexvar_epi8(idx, t), core::array::from_fn(|j| 63 - j as u8));
        // VPERMI2B: bit 6 selects the second table.
        let t2: M512i = core::array::from_fn(|i| 0x80 | i as u8);
        let idx: M512i = core::array::from_fn(|j| (j as u8) | if j % 2 == 1 { 0x40 } else { 0 });
        assert_eq!(_mm512_permutex2var_epi8(t, idx, t2), core::array::from_fn(|j| if j % 2 == 1 { t2[j] } else { t[j] }));
        // VPMULTISHIFTQB with controls 8j extracts byte j; control 60 wraps.
        let ctl: M512i = core::array::from_fn(|i| ((i % 8) * 8) as u8);
        assert_eq!(_mm512_multishift_epi64_epi8(ctl, t2), t2);
        let mut wrap = [0u8; 64];
        wrap[0] = 60;
        let data: M512i = core::array::from_fn(|i| if i == 7 { 0xab } else if i == 0 { 0xcd } else { 0 });
        // bits 60..63 of qword 0 are 0xa (high nibble of 0xab), bits 0..3 are 0xd.
        assert_eq!(_mm512_multishift_epi64_epi8(wrap, data)[0], 0xda);
        // Funnel shifts: count 0 returns DEST, the other half enters.
        let ones = [0xffu8; 64];
        let zero = [0u8; 64];
        assert_eq!(_mm512_shldv_epi64(zero, ones, zero), zero);
        let mut c = [0u8; 64];
        crate::x86_64::wide::set_qword(&mut c, 0, 4 + 64);
        assert_eq!(qword(&_mm512_shldv_epi64(zero, ones, c), 0), 0xf);
        assert_eq!(qword(&_mm512_shrdv_epi64(zero, ones, c), 0), 0xf << 60);
        assert_eq!(qword(&_mm512_shldi_epi64(ones, zero, 64 + 60), 0), u64::MAX << 60);
        assert_eq!(qword(&_mm512_shldi_epi32(zero, ones, 31), 0), 0x7fff_ffff_7fff_ffff);
        // Population counts.
        assert_eq!(qword(&_mm512_popcnt_epi64(ones), 2), 64);
        assert_eq!(_mm512_popcnt_epi8(t)[7], 3);
        assert_eq!(crate::x86_64::wide::word(&_mm512_popcnt_epi16(ones), 9), 16);
        assert_eq!(crate::x86_64::wide::dword(&_mm512_popcnt_epi32(t), 0), 0x03020100u32.count_ones());
    }
}
