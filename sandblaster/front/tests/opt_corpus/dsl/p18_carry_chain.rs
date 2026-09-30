//! P18: u64 carry chain (docs/optimizer-plan.md O1; design §11.5, E0). A
//! multi-limb product in radix 2^28 with carry propagation whose
//! multiplications are plain (checked) operations proven not to overflow
//! from the limbs' bounds (a precondition): the shape of an unsaturated field
//! multiplication (curve25519's `F::mul`, measured 1.9x faster once proven
//! operations are printed as wrapping helpers). Printed as checked operators,
//! every `*` pays an overflow check under `overflow-checks = true`
//! (Commonware's release profile), and a checked 64-bit multiplication needs
//! the high half of the product.
use sandblaster::prelude::*;

/// 2^28 − 1.
pub const MASK28: u64 = 268435455;

/// The 8-limb product of the 4-limb numbers `a` and `b` whose limbs are
/// < 2^28 (the representation's invariant, a precondition), carried: every
/// output limb < 2^28. The 16 partial products are checked multiplications,
/// proven from the precondition (which the generated code's host compiler
/// cannot see: it keeps the overflow checks); each is split at bit 28 at
/// once, and column `k` sums the low halves of the products of weight `k`
/// and the high halves of those of weight `k − 1` (sums below 2^31, written
/// wrapping so the proof stays linear).
#[requires(a[0] <= MASK28 && a[1] <= MASK28 && a[2] <= MASK28 && a[3] <= MASK28)]
#[requires(b[0] <= MASK28 && b[1] <= MASK28 && b[2] <= MASK28 && b[3] <= MASK28)]
pub(crate) fn mul_carry_limbs(a: &[u64; 4], b: &[u64; 4]) -> [u64; 8] {
    let a0 = a[0];
    let a1 = a[1];
    let a2 = a[2];
    let a3 = a[3];
    let b0 = b[0];
    let b1 = b[1];
    let b2 = b[2];
    let b3 = b[3];
    let p00 = a0 * b0;
    let p01 = a0 * b1;
    let p02 = a0 * b2;
    let p03 = a0 * b3;
    let p10 = a1 * b0;
    let p11 = a1 * b1;
    let p12 = a1 * b2;
    let p13 = a1 * b3;
    let p20 = a2 * b0;
    let p21 = a2 * b1;
    let p22 = a2 * b2;
    let p23 = a2 * b3;
    let p30 = a3 * b0;
    let p31 = a3 * b1;
    let p32 = a3 * b2;
    let p33 = a3 * b3;
    let s1 = (p01 & MASK28).wrapping_add(p10 & MASK28).wrapping_add(p00 >> 28u32);
    let s2 = (p02 & MASK28).wrapping_add(p11 & MASK28).wrapping_add(p20 & MASK28).wrapping_add(p01 >> 28u32).wrapping_add(p10 >> 28u32);
    let s3 = (p03 & MASK28).wrapping_add(p12 & MASK28).wrapping_add(p21 & MASK28).wrapping_add(p30 & MASK28).wrapping_add(p02 >> 28u32).wrapping_add(p11 >> 28u32).wrapping_add(p20 >> 28u32);
    let s4 = (p13 & MASK28).wrapping_add(p22 & MASK28).wrapping_add(p31 & MASK28).wrapping_add(p03 >> 28u32).wrapping_add(p12 >> 28u32).wrapping_add(p21 >> 28u32).wrapping_add(p30 >> 28u32);
    let s5 = (p23 & MASK28).wrapping_add(p32 & MASK28).wrapping_add(p13 >> 28u32).wrapping_add(p22 >> 28u32).wrapping_add(p31 >> 28u32);
    let s6 = (p33 & MASK28).wrapping_add(p23 >> 28u32).wrapping_add(p32 >> 28u32);
    let t2 = s2.wrapping_add(s1 >> 28u32);
    let t3 = s3.wrapping_add(t2 >> 28u32);
    let t4 = s4.wrapping_add(t3 >> 28u32);
    let t5 = s5.wrapping_add(t4 >> 28u32);
    let t6 = s6.wrapping_add(t5 >> 28u32);
    let t7 = (p33 >> 28u32).wrapping_add(t6 >> 28u32);
    [p00 & MASK28, s1 & MASK28, t2 & MASK28, t3 & MASK28, t4 & MASK28, t5 & MASK28, t6 & MASK28, t7]
}

/// The product of the 28-bit parts of the limbs of `a` and `b`
/// ([`mul_carry_limbs`] on the masked limbs).
pub fn mul_carry(a: &[u64; 4], b: &[u64; 4]) -> [u64; 8] {
    mul_carry_limbs(&[a[0] & MASK28, a[1] & MASK28, a[2] & MASK28, a[3] & MASK28], &[b[0] & MASK28, b[1] & MASK28, b[2] & MASK28, b[3] & MASK28])
}
