//! AVX-512 IFMA (52-bit integer fused multiply-add): `VPMADD52LUQ`,
//! `VPMADD52HUQ` (Intel SDM transcriptions), 512- and 256-bit forms.
//!
//! The intrinsics `_mm*_madd52{lo,hi}_epu64(a, b, c)` take the accumulator
//! first: `a` is the `DEST` (srcdest) operand, `b = SRC1`, `c = SRC2`. Only
//! bits 51:0 of `b` and `c` enter the 104-bit product; bits 63:52 are ignored.
//! The accumulation is modulo 2^64.
#![forbid(unsafe_code)]

use super::wide::{M256i, M512i, qword, set_qword};

/// `VPMADD52LUQ srcdest, src1, src2`:
///
/// ```text
/// (KL, VL) = (2, 128), (4, 256), (8, 512)
/// FOR j := 0 TO KL-1
///     i := j * 64;
///     tsrc2[63:0] := ZeroExtend64(src2[i+51:i]);
///     Temp128[127:0] := ZeroExtend64(src1[i+51:i]) * tsrc2[63:0];
///     Temp2[63:0] := DEST[i+63:i] + ZeroExtend64(temp128[51:0]) ;
///     DEST[i+63:i] := Temp2[63:0];
/// ENDFOR
/// ```
pub fn vpmadd52luq<const N: usize>(dest: [u8; N], src1: [u8; N], src2: [u8; N]) -> [u8; N] {
    let low52 = (1u64 << 52) - 1; // bits 51:0
    let mut out = [0u8; N];
    for j in 0..N / 8 {
        let tsrc2 = qword(&src2, j) & low52;
        let temp128 = ((qword(&src1, j) & low52) as u128) * (tsrc2 as u128);
        let temp2 = qword(&dest, j).wrapping_add((temp128 as u64) & low52);
        set_qword(&mut out, j, temp2);
    }
    out
}

/// `VPMADD52HUQ srcdest, src1, src2`: as [`vpmadd52luq`] with
/// `Temp2[63:0] := DEST[i+63:i] + ZeroExtend64(temp128[103:52]) ;`.
pub fn vpmadd52huq<const N: usize>(dest: [u8; N], src1: [u8; N], src2: [u8; N]) -> [u8; N] {
    let low52 = (1u64 << 52) - 1; // bits 51:0
    let mut out = [0u8; N];
    for j in 0..N / 8 {
        let tsrc2 = qword(&src2, j) & low52;
        let temp128 = ((qword(&src1, j) & low52) as u128) * (tsrc2 as u128);
        let temp2 = qword(&dest, j).wrapping_add(((temp128 >> 52) as u64) & low52);
        set_qword(&mut out, j, temp2);
    }
    out
}

/// `_mm512_madd52lo_epu64(a, b, c)` — `VPMADD52LUQ zmm1, zmm2, zmm3`
/// (avx512ifma), `DEST = a`, `SRC1 = b`, `SRC2 = c` ([`vpmadd52luq`]).
pub fn _mm512_madd52lo_epu64(a: M512i, b: M512i, c: M512i) -> M512i {
    vpmadd52luq(a, b, c)
}

/// `_mm512_madd52hi_epu64(a, b, c)` — `VPMADD52HUQ zmm1, zmm2, zmm3`
/// (avx512ifma) ([`vpmadd52huq`]).
pub fn _mm512_madd52hi_epu64(a: M512i, b: M512i, c: M512i) -> M512i {
    vpmadd52huq(a, b, c)
}

/// `_mm256_madd52lo_epu64(a, b, c)` — `VPMADD52LUQ ymm1, ymm2, ymm3`
/// (avx512ifma + avx512vl) ([`vpmadd52luq`]).
pub fn _mm256_madd52lo_epu64(a: M256i, b: M256i, c: M256i) -> M256i {
    vpmadd52luq(a, b, c)
}

/// `_mm256_madd52hi_epu64(a, b, c)` — `VPMADD52HUQ ymm1, ymm2, ymm3`
/// (avx512ifma + avx512vl) ([`vpmadd52huq`]).
pub fn _mm256_madd52hi_epu64(a: M256i, b: M256i, c: M256i) -> M256i {
    vpmadd52huq(a, b, c)
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOW52: u64 = (1 << 52) - 1;

    fn splat(x: u64) -> M512i {
        let mut v = [0u8; 64];
        for j in 0..8 {
            set_qword(&mut v, j, x);
        }
        v
    }

    #[test]
    fn known_answers() {
        // (2^52 - 1)^2 = 2^104 - 2^53 + 1: low 52 bits 1, high 52 bits 2^52 - 2.
        let m = splat(LOW52);
        assert_eq!(qword(&_mm512_madd52lo_epu64(splat(0), m, m), 0), 1);
        assert_eq!(qword(&_mm512_madd52hi_epu64(splat(0), m, m), 7), LOW52 - 1);
        // Bits 63:52 of the multiplicands are ignored.
        let hi_junk = splat(u64::MAX);
        assert_eq!(_mm512_madd52lo_epu64(splat(5), hi_junk, splat(1)), splat(5 + LOW52));
        // The accumulator wraps modulo 2^64.
        assert_eq!(qword(&_mm512_madd52lo_epu64(splat(u64::MAX), splat(1), splat(1)), 3), 0);
        // 2^51 * 2^51 = 2^102: low 0, high 2^50.
        let p = splat(1 << 51);
        assert_eq!(qword(&_mm512_madd52lo_epu64(splat(0), p, p), 1), 0);
        assert_eq!(qword(&_mm512_madd52hi_epu64(splat(0), p, p), 1), 1 << 50);
    }
}
