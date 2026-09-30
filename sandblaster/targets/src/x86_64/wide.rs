//! 256- and 512-bit vectors and AVX-512 opmask registers (DESIGN.md §9.2,
//! MODELS.md §10).
//!
//! **Vectors.** `__m256i` and `__m512i` have no element type, so, like
//! [`M128i`](super::M128i), they are canonically byte arrays in memory order:
//! [`M256i`] = `[u8; 32]`, [`M512i`] = `[u8; 64]`, byte `i` = bits `8i+7:8i`
//! (little-endian). The SDM names elements by bit slices; the accessors
//! below are those slices on the byte representation, for any vector width
//! `N` (bytes):
//!
//! * [`word`] / [`set_word`]: `SRC[16j+15:16j]` = bytes `2j, 2j+1`,
//! * [`dword`] / [`set_dword`]: `SRC[32j+31:32j]` = bytes `4j..4j+4`,
//! * [`qword`] / [`set_qword`]: `SRC[64j+63:64j]` = bytes `8j..8j+8`,
//!
//! all little-endian (`dword(v, j) = u32::from_le_bytes(v[4j..4j+4])`), so
//! `dword(v, j)` on an `M128i` is `view_u32(v)[j]` of [`crate::x86_64`]. The
//! models of the VEX/EVEX instructions are written once per instruction,
//! generic over `N` (the SDM's `(KL, VL)` table: `KL = N / element size`),
//! and each intrinsic instantiates them at its width.
//!
//! **Opmasks.** `__mmask8`, `__mmask16`, `__mmask32`, `__mmask64` are
//! `u8`, `u16`, `u32`, `u64` ([`Mmask8`] … [`Mmask64`]); bit `j` of the mask
//! (SDM `k1[j]`) belongs to element `j` ([`mask_bit`]).
#![forbid(unsafe_code)]
// Element loops mirror the SDM's `FOR j := 0 TO KL-1`.
#![allow(clippy::needless_range_loop)]

/// `__m256i`: 32 bytes, byte 0 = bits `7:0` (little-endian).
pub type M256i = [u8; 32];

/// `__m512i`: 64 bytes, byte 0 = bits `7:0` (little-endian).
pub type M512i = [u8; 64];

/// `__mmask8`: bit `j` is the mask bit of element `j`.
pub type Mmask8 = u8;

/// `__mmask16`.
pub type Mmask16 = u16;

/// `__mmask32`.
pub type Mmask32 = u32;

/// `__mmask64`.
pub type Mmask64 = u64;

/// SDM `SRC[16j+15:16j]`: word `j` of a vector of `N` bytes (bytes `2j`, `2j+1`).
pub fn word<const N: usize>(v: &[u8; N], j: usize) -> u16 {
    u16::from_le_bytes([v[2 * j], v[2 * j + 1]])
}

/// `DEST[16j+15:16j] := x`.
pub fn set_word<const N: usize>(v: &mut [u8; N], j: usize, x: u16) {
    let b = x.to_le_bytes();
    v[2 * j] = b[0];
    v[2 * j + 1] = b[1];
}

/// SDM `SRC[32j+31:32j]`: dword `j` of a vector of `N` bytes (bytes `4j..4j+4`).
pub fn dword<const N: usize>(v: &[u8; N], j: usize) -> u32 {
    u32::from_le_bytes([v[4 * j], v[4 * j + 1], v[4 * j + 2], v[4 * j + 3]])
}

/// `DEST[32j+31:32j] := x`.
pub fn set_dword<const N: usize>(v: &mut [u8; N], j: usize, x: u32) {
    let b = x.to_le_bytes();
    for k in 0..4 {
        v[4 * j + k] = b[k];
    }
}

/// SDM `SRC[64j+63:64j]`: qword `j` of a vector of `N` bytes (bytes `8j..8j+8`).
pub fn qword<const N: usize>(v: &[u8; N], j: usize) -> u64 {
    let mut b = [0u8; 8];
    for k in 0..8 {
        b[k] = v[8 * j + k];
    }
    u64::from_le_bytes(b)
}

/// `DEST[64j+63:64j] := x`.
pub fn set_qword<const N: usize>(v: &mut [u8; N], j: usize, x: u64) {
    let b = x.to_le_bytes();
    for k in 0..8 {
        v[8 * j + k] = b[k];
    }
}

/// SDM `k1[j]`: bit `j` of an opmask (any of `__mmask8..64`, widened to `u64`).
pub fn mask_bit(k: u64, j: usize) -> bool {
    (k >> j) & 1 == 1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accessors_are_little_endian_slices() {
        let v: M512i = core::array::from_fn(|i| i as u8);
        assert_eq!(word(&v, 0), 0x0100);
        assert_eq!(word(&v, 31), 0x3f3e);
        assert_eq!(dword(&v, 1), 0x0706_0504);
        assert_eq!(dword(&v, 15), 0x3f3e_3d3c);
        assert_eq!(qword(&v, 7), 0x3f3e_3d3c_3b3a_3938);
        let mut w = [0u8; 32];
        set_dword(&mut w, 7, 0xa1b2_c3d4);
        assert_eq!(&w[28..], &[0xd4, 0xc3, 0xb2, 0xa1]);
        set_qword(&mut w, 0, 0x0102_0304_0506_0708);
        assert_eq!(&w[..8], &[8, 7, 6, 5, 4, 3, 2, 1]);
        set_word(&mut w, 5, 0xbeef);
        assert_eq!(&w[10..12], &[0xef, 0xbe]);
        // On an M128i the accessors are the typed views of `crate::x86_64`.
        let x: super::super::M128i = core::array::from_fn(|i| (i * 37) as u8);
        let v32 = super::super::view_u32(x);
        let v64 = super::super::view_u64(x);
        for j in 0..4 {
            assert_eq!(dword(&x, j), v32[j]);
        }
        for j in 0..2 {
            assert_eq!(qword(&x, j), v64[j]);
        }
        assert!(mask_bit(0b100, 2) && !mask_bit(0b100, 1) && mask_bit(u64::MAX, 63));
    }
}
