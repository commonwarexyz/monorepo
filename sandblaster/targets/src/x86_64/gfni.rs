//! GFNI: `GF2P8MULB`, `GF2P8AFFINEQB`, `GF2P8AFFINEINVQB` (Intel SDM
//! transcriptions), 128-bit (legacy SSE encoding), 256-bit (VEX) and
//! 512-bit (EVEX) forms.
//!
//! The field is GF(2^8) with the AES reduction polynomial
//! `x^8 + x^4 + x^3 + x + 1` (`0x11B`). The affine forms treat each qword of
//! the second source as an 8×8 bit matrix: result bit `i` of a byte is the
//! parity of `matrix.byte[7-i] AND byte` XOR `imm8[i]`. The parity is the SDM's
//! xor of bit extractions (not a population count), which makes the model
//! syntactically GF(2)-linear in the data byte (design §9.2).
#![forbid(unsafe_code)]
// Bit loops mirror the pseudocode's `FOR i := 0 to 7`.
#![allow(clippy::needless_range_loop)]

use super::M128i;
use super::wide::{M256i, M512i, qword};

/// SDM `gf2p8mul_byte(src1byte, src2byte)`:
///
/// ```text
/// define gf2p8mul_byte(src1byte, src2byte):
///     tword := 0
///     FOR i := 0 to 7:
///         IF src2byte.bit[i]:
///             tword := tword XOR (src1byte<< i)
///     * carry out polynomial reduction by the characteristic polynomial p*
///     FOR i := 14 downto 8:
///         p := 0x11B << (i-8) *0x11B = 0000_0001_0001_1011 in binary*
///         IF tword.bit[i]:
///             tword := tword XOR p
///     return tword.byte[0]
/// ```
pub fn gf2p8mul_byte(src1byte: u8, src2byte: u8) -> u8 {
    let mut tword: u16 = 0;
    for i in 0..8 {
        if (src2byte >> i) & 1 == 1 {
            tword ^= (src1byte as u16) << i;
        }
    }
    for i in (8..=14).rev() {
        let p: u16 = 0x11b << (i - 8);
        if (tword >> i) & 1 == 1 {
            tword ^= p;
        }
    }
    tword as u8
}

/// SDM `parity(x)` of the affine instructions:
///
/// ```text
/// define parity(x):
///     t := 0 // single bit
///     FOR i := 0 to 7:
///         t = t xor x.bit[i]
///     return t
/// ```
pub fn parity(x: u8) -> u8 {
    let mut t = 0u8;
    for i in 0..8 {
        t ^= (x >> i) & 1;
    }
    t
}

/// SDM `affine_byte(tsrc2qw, src1byte, imm)`:
///
/// ```text
/// define affine_byte(tsrc2qw, src1byte, imm):
///     FOR i := 0 to 7:
///         * parity(x) = 1 if x has an odd number of 1s in it, and 0 otherwise.*
///         retbyte.bit[i] := parity(tsrc2qw.byte[7-i] AND src1byte) XOR imm8.bit[i]
///     return retbyte
/// ```
pub fn affine_byte(tsrc2qw: u64, src1byte: u8, imm: u32) -> u8 {
    let mut retbyte = 0u8;
    for i in 0..8 {
        let row = (tsrc2qw >> (8 * (7 - i))) as u8;
        let bit = parity(row & src1byte) ^ ((imm >> i) & 1) as u8;
        retbyte |= bit << i;
    }
    retbyte
}

/// SDM `inverse(x)` (table "Inverse Byte Listings" of GF2P8AFFINEINVQB): the
/// multiplicative inverse of `x` in GF(2^8) mod `0x11B`, with `inverse(0) =
/// 0`. Computed as `x^254` with [`gf2p8mul_byte`]: `x^255 = 1` for `x ≠ 0`
/// (the multiplicative group has order 255) and `0^254 = 0`, so this is the
/// table; the unit tests check it against rows of the table, a brute-force
/// search and the AES S-box. `x^254 = x^2·x^4·x^8·x^16·x^32·x^64·x^128`.
pub fn inverse(x: u8) -> u8 {
    let mut sq = x;
    let mut acc = 1u8;
    for _ in 0..7 {
        sq = gf2p8mul_byte(sq, sq);
        acc = gf2p8mul_byte(acc, sq);
    }
    acc
}

/// SDM `affine_inverse_byte(tsrc2qw, src1byte, imm)`:
///
/// ```text
/// define affine_inverse_byte(tsrc2qw, src1byte, imm):
///     FOR i := 0 to 7:
///         * parity(x) = 1 if x has an odd number of 1s in it, and 0 otherwise.*
///         * inverse(x) is defined in the table above *
///         retbyte.bit[i] := parity(tsrc2qw.byte[7-i] AND inverse(src1byte)) XOR imm8.bit[i]
///     return retbyte
/// ```
pub fn affine_inverse_byte(tsrc2qw: u64, src1byte: u8, imm: u32) -> u8 {
    let inv = inverse(src1byte);
    let mut retbyte = 0u8;
    for i in 0..8 {
        let row = (tsrc2qw >> (8 * (7 - i))) as u8;
        let bit = parity(row & inv) ^ ((imm >> i) & 1) as u8;
        retbyte |= bit << i;
    }
    retbyte
}

/// `GF2P8MULB` / `VGF2P8MULB`:
///
/// ```text
/// (KL, VL) = (16, 128), (32, 256), (64, 512)
/// FOR j := 0 TO KL-1:
///     DEST.byte[j] := gf2p8mul_byte(SRC1.byte[j], SRC2.byte[j])
/// ```
///
/// (legacy SSE: `DEST.byte[j] := gf2p8mul_byte(DEST.byte[j], SRC.byte[j])`).
pub fn vgf2p8mulb<const N: usize>(src1: [u8; N], src2: [u8; N]) -> [u8; N] {
    let mut dest = [0u8; N];
    for j in 0..N {
        dest[j] = gf2p8mul_byte(src1[j], src2[j]);
    }
    dest
}

/// `GF2P8AFFINEQB` / `VGF2P8AFFINEQB dest, src1, src2, imm8`, `0 ≤ imm8 ≤ 255`:
///
/// ```text
/// (KL, VL) = (2, 128), (4, 256), (8, 512)
/// FOR j := 0 TO KL-1:
///     tsrc2 := SRC2.qword[j]
///     FOR b := 0 to 7:
///         DEST.qword[j].byte[b] := affine_byte(tsrc2, SRC1.qword[j].byte[b], imm8)
/// ```
pub fn vgf2p8affineqb<const N: usize>(src1: [u8; N], src2: [u8; N], imm8: i32) -> [u8; N] {
    assert!((0..=255).contains(&imm8), "vgf2p8affineqb: immediate {imm8} out of range 0..=255");
    let mut dest = [0u8; N];
    for j in 0..N / 8 {
        let tsrc2 = qword(&src2, j);
        for b in 0..8 {
            dest[8 * j + b] = affine_byte(tsrc2, src1[8 * j + b], imm8 as u32);
        }
    }
    dest
}

/// `GF2P8AFFINEINVQB` / `VGF2P8AFFINEINVQB dest, src1, src2, imm8`,
/// `0 ≤ imm8 ≤ 255`: as [`vgf2p8affineqb`] with `affine_inverse_byte`:
/// `DEST.qword[j].byte[b] := affine_inverse_byte(tsrc2, SRC1.qword[j].byte[b],
/// imm8)`.
pub fn vgf2p8affineinvqb<const N: usize>(src1: [u8; N], src2: [u8; N], imm8: i32) -> [u8; N] {
    assert!((0..=255).contains(&imm8), "vgf2p8affineinvqb: immediate {imm8} out of range 0..=255");
    let mut dest = [0u8; N];
    for j in 0..N / 8 {
        let tsrc2 = qword(&src2, j);
        for b in 0..8 {
            dest[8 * j + b] = affine_inverse_byte(tsrc2, src1[8 * j + b], imm8 as u32);
        }
    }
    dest
}

/// `_mm512_gf2p8mul_epi8(a, b)` — `VGF2P8MULB zmm1, zmm2, zmm3` (gfni +
/// avx512f), `SRC1 = a`, `SRC2 = b` ([`vgf2p8mulb`]).
pub fn _mm512_gf2p8mul_epi8(a: M512i, b: M512i) -> M512i {
    vgf2p8mulb(a, b)
}

/// `_mm256_gf2p8mul_epi8(a, b)` — `VGF2P8MULB ymm1, ymm2, ymm3` (gfni + avx)
/// ([`vgf2p8mulb`]).
pub fn _mm256_gf2p8mul_epi8(a: M256i, b: M256i) -> M256i {
    vgf2p8mulb(a, b)
}

/// `_mm_gf2p8mul_epi8(a, b)` — `GF2P8MULB xmm1, xmm2` (gfni), `DEST = a`,
/// `SRC = b` ([`vgf2p8mulb`]).
pub fn _mm_gf2p8mul_epi8(a: M128i, b: M128i) -> M128i {
    vgf2p8mulb(a, b)
}

/// `_mm512_gf2p8affine_epi64_epi8::<B>(x, a)` — `VGF2P8AFFINEQB zmm1, zmm2,
/// zmm3, imm8` (gfni + avx512f), `SRC1 = x` (data bytes), `SRC2 = a` (one
/// 8×8 bit matrix per qword), `imm8 = B`, `0 ≤ B ≤ 255` ([`vgf2p8affineqb`]).
pub fn _mm512_gf2p8affine_epi64_epi8(x: M512i, a: M512i, b: i32) -> M512i {
    vgf2p8affineqb(x, a, b)
}

/// `_mm256_gf2p8affine_epi64_epi8::<B>(x, a)` — `VGF2P8AFFINEQB ymm1, ymm2,
/// ymm3, imm8` (gfni + avx) ([`vgf2p8affineqb`]).
pub fn _mm256_gf2p8affine_epi64_epi8(x: M256i, a: M256i, b: i32) -> M256i {
    vgf2p8affineqb(x, a, b)
}

/// `_mm_gf2p8affine_epi64_epi8::<B>(x, a)` — `GF2P8AFFINEQB xmm1, xmm2, imm8`
/// (gfni) ([`vgf2p8affineqb`]).
pub fn _mm_gf2p8affine_epi64_epi8(x: M128i, a: M128i, b: i32) -> M128i {
    vgf2p8affineqb(x, a, b)
}

/// `_mm512_gf2p8affineinv_epi64_epi8::<B>(x, a)` — `VGF2P8AFFINEINVQB zmm1,
/// zmm2, zmm3, imm8` (gfni + avx512f) ([`vgf2p8affineinvqb`]).
pub fn _mm512_gf2p8affineinv_epi64_epi8(x: M512i, a: M512i, b: i32) -> M512i {
    vgf2p8affineinvqb(x, a, b)
}

/// `_mm256_gf2p8affineinv_epi64_epi8::<B>(x, a)` — `VGF2P8AFFINEINVQB ymm1,
/// ymm2, ymm3, imm8` (gfni + avx) ([`vgf2p8affineinvqb`]).
pub fn _mm256_gf2p8affineinv_epi64_epi8(x: M256i, a: M256i, b: i32) -> M256i {
    vgf2p8affineinvqb(x, a, b)
}

/// `_mm_gf2p8affineinv_epi64_epi8::<B>(x, a)` — `GF2P8AFFINEINVQB xmm1, xmm2,
/// imm8` (gfni) ([`vgf2p8affineinvqb`]).
pub fn _mm_gf2p8affineinv_epi64_epi8(x: M128i, a: M128i, b: i32) -> M128i {
    vgf2p8affineinvqb(x, a, b)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The AES S-box through GF2P8AFFINEINVQB (the matrix `0xF1E3C78F1F3E7CF8`
    /// and constant `0x63` of FIPS-197 §5.1.1): a well-known use of the
    /// instruction that exercises inverse, matrix orientation and imm8 bits.
    #[test]
    fn aes_sbox_known_answers() {
        let m = 0xf1e3_c78f_1f3e_7cf8u64;
        for (x, s) in [(0x00u8, 0x63u8), (0x01, 0x7c), (0x02, 0x77), (0x53, 0xed), (0x10, 0xca), (0xff, 0x16), (0x6e, 0x9f), (0xc9, 0xdd)] {
            assert_eq!(affine_inverse_byte(m, x, 0x63), s, "S({x:#04x})");
        }
        let mut src2 = [0u8; 16];
        src2[..8].copy_from_slice(&m.to_le_bytes());
        src2[8..].copy_from_slice(&m.to_le_bytes());
        let x: M128i = core::array::from_fn(|i| [0x00, 0x01, 0x53, 0xff][i % 4]);
        let r = _mm_gf2p8affineinv_epi64_epi8(x, src2, 0x63);
        assert_eq!(&r[..4], &[0x63, 0x7c, 0xed, 0x16]);
    }

    /// First row of the SDM's inverse table, `{53}·{CA} = {01}` (FIPS-197
    /// §4.2), and a brute-force check of every byte.
    #[test]
    fn inverse_table() {
        let row0 = [0x00u8, 0x01, 0x8d, 0xf6, 0xcb, 0x52, 0x7b, 0xd1, 0xe8, 0x4f, 0x29, 0xc0, 0xb0, 0xe1, 0xe5, 0xc7];
        for (x, inv) in row0.iter().enumerate() {
            assert_eq!(inverse(x as u8), *inv, "inverse({x:#04x})");
        }
        assert_eq!(gf2p8mul_byte(0x53, 0xca), 0x01);
        assert_eq!(inverse(0x53), 0xca);
        for x in 1..=255u8 {
            let brute = (1..=255u8).find(|&y| gf2p8mul_byte(x, y) == 1).unwrap();
            assert_eq!(inverse(x), brute);
        }
    }

    #[test]
    fn multiply_and_affine_known_answers() {
        // FIPS-197 §4.2: {57}·{83} = {c1}, {57}·{13} = {fe}.
        assert_eq!(gf2p8mul_byte(0x57, 0x83), 0xc1);
        assert_eq!(gf2p8mul_byte(0x57, 0x13), 0xfe);
        assert_eq!(gf2p8mul_byte(0x80, 0x02), 0x1b);
        // The identity matrix (byte 7-i = 1 << i) and the zero matrix.
        let id = 0x0102_0408_1020_4080u64;
        for x in [0u8, 1, 0x80, 0x5a, 0xff] {
            assert_eq!(affine_byte(id, x, 0), x);
            assert_eq!(affine_byte(id, x, 0xff), !x);
            assert_eq!(affine_byte(0, x, 0x3c), 0x3c);
        }
        assert_eq!(parity(0b1011_0001), 0);
        assert_eq!(parity(0b1011_0011), 1);
    }
}
