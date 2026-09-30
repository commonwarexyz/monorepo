//! P20: sparse / constant-operand multiplication (docs/optimizer-plan.md O1;
//! design §6.5 polyvariant call-site specialization; the pattern of BLS
//! "line" multiplication, where a generic product is called with an operand
//! whose coefficients are known zeros and ones). A generic product of two
//! degree-2 polynomials over GF(2^64) (carry-less products, low 64 bits),
//! called with the sparse operand `(1, c, 0)`: specialized at the call
//! site, 4 of its 6 carry-less products are known (`clmul(x, 0) = 0`,
//! `clmul(x, 1) = x`).
use sandblaster::prelude::*;

/// Carry-less product of `a` and `b`, low 64 bits (GF(2)[x] mod x^64).
pub fn clmul_lo(a: u64, b: u64) -> u64 {
    let mut acc: u64 = 0;
    for i in 0..64u32 {
        if (b >> i) & 1 == 1 {
            acc = acc ^ a.wrapping_shl(i);
        }
    }
    acc
}

/// `a · b` for polynomials of degree ≤ 2 over GF(2^64), mod y^3.
pub fn poly3_mul(a: &[u64; 3], b: &[u64; 3]) -> [u64; 3] {
    [
        clmul_lo(a[0], b[0]),
        clmul_lo(a[0], b[1]) ^ clmul_lo(a[1], b[0]),
        clmul_lo(a[0], b[2]) ^ clmul_lo(a[1], b[1]) ^ clmul_lo(a[2], b[0]),
    ]
}

/// Multiplication by the sparse element `1 + c·y` (a "line").
pub fn line_mul(a: &[u64; 3], c: u64) -> [u64; 3] {
    poly3_mul(a, &[1, c, 0])
}
