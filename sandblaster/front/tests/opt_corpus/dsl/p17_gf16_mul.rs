//! P17: GF(2^16) multiplication by a constant over 64-byte lo/hi blocks
//! (docs/optimizer-plan.md O1; design §9.2). The layout of Commonware's
//! Reed–Solomon engine (`SHARD_CHUNK_BYTES` = 64): the 32 low bytes of 32
//! field elements, then their 32 high bytes. Written the natural way, one
//! shift-and-add product per element. Multiplication by a constant is
//! GF(2)-linear in the element's bits, so it lowers to 4 nibble tables
//! (NEON TBL, SSSE3 PSHUFB) or one GFNI affine transform per byte plane.
use sandblaster::prelude::*;

/// The field polynomial x^16 + x^5 + x^3 + x^2 + 1 (Commonware's
/// `GF_POLYNOMIAL`), without the x^16 term.
pub const GF16_POLY_LOW: u32 = 0x002D;

/// `x · a` in GF(2^16): shift left, reduce by the polynomial.
pub fn gf16_double(a: u16) -> u16 {
    let x = (a as u32) << 1u32;
    let r = if x >= 0x1_0000 { (x - 0x1_0000) ^ GF16_POLY_LOW } else { x };
    r as u16
}

/// `a · b` in GF(2^16), polynomial basis: 16 shift-and-add steps.
pub fn gf16_mul(a: u16, b: u16) -> u16 {
    let mut acc: u16 = 0;
    let mut x: u16 = a;
    for i in 0..16u32 {
        if (b >> i) & 1 == 1 {
            acc = acc ^ x;
        }
        x = gf16_double(x);
    }
    acc
}

/// Multiplies the 32 field elements of a lo/hi block by `c`.
pub fn gf16_mul_block(c: u16, block: &[u8; 64]) -> [u8; 64] {
    let mut out = [0u8; 64];
    for i in 0..32usize {
        let v = (block[i] as u16) | ((block[i + 32] as u16) << 8u32);
        let p = gf16_mul(v, c);
        out[i] = (p & 0xff) as u8;
        out[i + 32] = (p >> 8u32) as u8;
    }
    out
}
