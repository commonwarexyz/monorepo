//! The Arm NEON backend: two lanes of an [`super::FVec`] limb row per 128-bit register.
//!
//! The generic field kernels stay entirely in NEON. A scalar-plus-NEON design only becomes useful
//! when independent operations are scheduled across a complete point formula; dividing one
//! [`super::FVec`] operation between both domains adds setup and synchronization costs on Apple
//! M-series CPUs. Products split radix-`2^51` limbs into alternating 26/25-bit digits only while
//! multiplying, keeping the surrounding group formulas in their compact five-limb representation.

use super::{BIAS_16P as SUB_BIAS, F, FBackend, FVec, GAffineVec, GBackend, GVec, LANES, MASK_51};
use core::arch::aarch64::*;

/// `2d` in every lane, for the `C = 2d*T1*T2` term of point addition.
const EDWARDS_D2: FVec = FVec::splat(F::EDWARDS_D2);

/// Number of packed `u64` lanes in a NEON register.
const WIDTH: usize = 2;

/// Number of register tiles needed to cover all backend lanes.
const TILES: usize = LANES / WIDTH;

/// Five radix-`2^51` limbs for two independent field elements.
type Regs = [uint64x2_t; 5];

/// The NEON backend token.
///
/// NEON is part of the AArch64 baseline, so the token needs no runtime feature check.
#[derive(Clone, Copy)]
pub(super) struct Backend;

impl Backend {
    pub(super) const fn new() -> Self {
        Self
    }
}

/// Loads one two-lane tile from each of the five limb rows.
#[inline(always)]
fn load(limbs: &[[u64; LANES]; 5], tile: usize) -> Regs {
    assert!(tile < TILES);
    let offset = tile * WIDTH;
    core::array::from_fn(|i| {
        // SAFETY: the tile assertion ensures that `offset..offset + WIDTH` is within the row,
        // and AArch64 targets provide NEON.
        unsafe { vld1q_u64(limbs[i].as_ptr().add(offset)) }
    })
}

/// Stores one two-lane tile into each of the five limb rows.
#[inline(always)]
fn store(regs: Regs, limbs: &mut [[u64; LANES]; 5], tile: usize) {
    assert!(tile < TILES);
    let offset = tile * WIDTH;
    for (row, reg) in limbs.iter_mut().zip(regs) {
        // SAFETY: the tile assertion ensures that `offset..offset + WIDTH` is within the row,
        // and AArch64 targets provide NEON.
        unsafe { vst1q_u64(row.as_mut_ptr().add(offset), reg) };
    }
}

/// `19*z` via `(z << 4) + (z << 1) + z`.
///
/// # Correctness
///
/// `z` must be less than `2^59` per lane so the shifts do not discard significant bits.
///
/// The explicit instruction sequence prevents LLVM from recognizing a packed `u64` multiplication
/// and scalarizing it through general-purpose registers. NEON has no packed `u64` multiply, while
/// these shifts and additions stay in vector registers and measured better on Apple M-series CPUs.
#[inline(always)]
fn mul19(z: uint64x2_t) -> uint64x2_t {
    #[cfg(miri)]
    {
        // Miri cannot execute inline assembly, so use equivalent intrinsics for semantic coverage.
        // SAFETY: AArch64 targets provide NEON.
        unsafe { vaddq_u64(vaddq_u64(vshlq_n_u64(z, 4), vshlq_n_u64(z, 1)), z) }
    }
    #[cfg(not(miri))]
    {
        let result;
        // SAFETY: AArch64 targets provide NEON. The instructions only read their register input,
        // write their register outputs, and preserve the bounds documented above.
        unsafe {
            core::arch::asm!(
                "shl {doubled:v}.2d, {z:v}.2d, #1",
                "shl {times16:v}.2d, {z:v}.2d, #4",
                "add {doubled:v}.2d, {doubled:v}.2d, {times16:v}.2d",
                "add {result:v}.2d, {doubled:v}.2d, {z:v}.2d",
                z = in(vreg) z,
                doubled = out(vreg) _,
                times16 = out(vreg) _,
                result = lateout(vreg) result,
                options(pure, nomem, nostack),
            );
        }
        result
    }
}

#[derive(Clone, Copy)]
struct Pair {
    lo: uint32x2_t,
    hi: uint32x2_t,
}

#[inline(always)]
fn split_pairs(a: Regs) -> [Pair; 5] {
    // SAFETY: AArch64 targets provide NEON.
    unsafe {
        let mask = vdupq_n_u64((1 << 26) - 1);
        [
            Pair {
                lo: vmovn_u64(vandq_u64(a[0], mask)),
                hi: vshrn_n_u64(a[0], 26),
            },
            Pair {
                lo: vmovn_u64(vandq_u64(a[1], mask)),
                hi: vshrn_n_u64(a[1], 26),
            },
            Pair {
                lo: vmovn_u64(vandq_u64(a[2], mask)),
                hi: vshrn_n_u64(a[2], 26),
            },
            Pair {
                lo: vmovn_u64(vandq_u64(a[3], mask)),
                hi: vshrn_n_u64(a[3], 26),
            },
            Pair {
                lo: vmovn_u64(vandq_u64(a[4], mask)),
                hi: vshrn_n_u64(a[4], 26),
            },
        ]
    }
}

#[inline(always)]
fn digit_times2(value: uint32x2_t) -> uint32x2_t {
    // SAFETY: AArch64 targets provide NEON, and the doubled component fits in `u32`.
    unsafe { vshl_n_u32(value, 1) }
}

#[inline(always)]
fn digit_times19(value: uint32x2_t) -> uint32x2_t {
    // SAFETY: AArch64 targets provide NEON, and the scaled component fits in `u32`.
    unsafe { vadd_u32(vadd_u32(vshl_n_u32(value, 4), vshl_n_u32(value, 1)), value) }
}

#[inline(always)]
fn digit_mac(accumulator: uint64x2_t, a: uint32x2_t, b: uint32x2_t) -> uint64x2_t {
    // SAFETY: AArch64 targets provide NEON, and the accumulated column fits in `u64`.
    unsafe { vmlal_u32(accumulator, a, b) }
}

#[inline(always)]
fn digit_product(a: uint32x2_t, b: uint32x2_t) -> uint64x2_t {
    // SAFETY: AArch64 targets provide NEON.
    unsafe { vmull_u32(a, b) }
}

#[inline(always)]
fn reduce_columns(mut c: [uint64x2_t; 10]) -> Regs {
    // SAFETY: AArch64 targets provide NEON. All accumulators and carry additions fit in `u64`.
    unsafe {
        let mask26 = vdupq_n_u64((1 << 26) - 1);
        let mask25 = vdupq_n_u64((1 << 25) - 1);
        c[1] = vaddq_u64(c[1], vshrq_n_u64(c[0], 26));
        c[0] = vandq_u64(c[0], mask26);
        c[2] = vaddq_u64(c[2], vshrq_n_u64(c[1], 25));
        c[1] = vandq_u64(c[1], mask25);
        c[3] = vaddq_u64(c[3], vshrq_n_u64(c[2], 26));
        c[2] = vandq_u64(c[2], mask26);
        c[4] = vaddq_u64(c[4], vshrq_n_u64(c[3], 25));
        c[3] = vandq_u64(c[3], mask25);
        c[5] = vaddq_u64(c[5], vshrq_n_u64(c[4], 26));
        c[4] = vandq_u64(c[4], mask26);
        c[6] = vaddq_u64(c[6], vshrq_n_u64(c[5], 25));
        c[5] = vandq_u64(c[5], mask25);
        c[7] = vaddq_u64(c[7], vshrq_n_u64(c[6], 26));
        c[6] = vandq_u64(c[6], mask26);
        c[8] = vaddq_u64(c[8], vshrq_n_u64(c[7], 25));
        c[7] = vandq_u64(c[7], mask25);
        c[9] = vaddq_u64(c[9], vshrq_n_u64(c[8], 26));
        c[8] = vandq_u64(c[8], mask26);
        // Narrowing this carry is lossless, which needs a tighter bound than the worst-case
        // column (`267 * (2^26 - 1)^2 < 2^61`): column 9 is where terms fold *from*, never
        // *into*, so it accumulates at most ten unscaled products plus column 8's carry,
        // `c[9] < 10 * (2^26 - 1)^2 + 2^32 < 2^56`, making the carry `c[9] >> 25` less than
        // `2^31`. Narrowing enables one widening multiply instead of the longer packed-u64
        // shift/add sequence.
        let top = vmovn_u64(vshrq_n_u64(c[9], 25));
        c[0] = vaddq_u64(c[0], vmull_n_u32(top, 19));
        c[9] = vandq_u64(c[9], mask25);
        c[1] = vaddq_u64(c[1], vshrq_n_u64(c[0], 26));
        c[0] = vandq_u64(c[0], mask26);
        [
            vorrq_u64(c[0], vshlq_n_u64(c[1], 26)),
            vorrq_u64(c[2], vshlq_n_u64(c[3], 26)),
            vorrq_u64(c[4], vshlq_n_u64(c[5], 26)),
            vorrq_u64(c[6], vshlq_n_u64(c[7], 26)),
            vorrq_u64(c[8], vshlq_n_u64(c[9], 26)),
        ]
    }
}

#[inline(always)]
fn mul_regs(a: Regs, b: Regs) -> Regs {
    let a = split_pairs(a);
    let b = split_pairs(b);
    let a0 = a[0].lo;
    let a1 = a[0].hi;
    let a2 = a[1].lo;
    let a3 = a[1].hi;
    let a4 = a[2].lo;
    let a5 = a[2].hi;
    let a6 = a[3].lo;
    let a7 = a[3].hi;
    let a8 = a[4].lo;
    let a9 = a[4].hi;
    let b0 = b[0].lo;
    let b1 = b[0].hi;
    let b2 = b[1].lo;
    let b3 = b[1].hi;
    let b4 = b[2].lo;
    let b5 = b[2].hi;
    let b6 = b[3].lo;
    let b7 = b[3].hi;
    let b8 = b[4].lo;
    let b9 = b[4].hi;
    let mut c0 = digit_product(a0, b0);
    c0 = digit_mac(c0, digit_times2(a1), digit_times19(b9));
    c0 = digit_mac(c0, a2, digit_times19(b8));
    c0 = digit_mac(c0, digit_times2(a3), digit_times19(b7));
    c0 = digit_mac(c0, a4, digit_times19(b6));
    c0 = digit_mac(c0, digit_times2(a5), digit_times19(b5));
    c0 = digit_mac(c0, a6, digit_times19(b4));
    c0 = digit_mac(c0, digit_times2(a7), digit_times19(b3));
    c0 = digit_mac(c0, a8, digit_times19(b2));
    c0 = digit_mac(c0, digit_times2(a9), digit_times19(b1));
    let mut c1 = digit_product(a0, b1);
    c1 = digit_mac(c1, a1, b0);
    c1 = digit_mac(c1, a2, digit_times19(b9));
    c1 = digit_mac(c1, a3, digit_times19(b8));
    c1 = digit_mac(c1, a4, digit_times19(b7));
    c1 = digit_mac(c1, a5, digit_times19(b6));
    c1 = digit_mac(c1, a6, digit_times19(b5));
    c1 = digit_mac(c1, a7, digit_times19(b4));
    c1 = digit_mac(c1, a8, digit_times19(b3));
    c1 = digit_mac(c1, a9, digit_times19(b2));
    let mut c2 = digit_product(a0, b2);
    c2 = digit_mac(c2, digit_times2(a1), b1);
    c2 = digit_mac(c2, a2, b0);
    c2 = digit_mac(c2, digit_times2(a3), digit_times19(b9));
    c2 = digit_mac(c2, a4, digit_times19(b8));
    c2 = digit_mac(c2, digit_times2(a5), digit_times19(b7));
    c2 = digit_mac(c2, a6, digit_times19(b6));
    c2 = digit_mac(c2, digit_times2(a7), digit_times19(b5));
    c2 = digit_mac(c2, a8, digit_times19(b4));
    c2 = digit_mac(c2, digit_times2(a9), digit_times19(b3));
    let mut c3 = digit_product(a0, b3);
    c3 = digit_mac(c3, a1, b2);
    c3 = digit_mac(c3, a2, b1);
    c3 = digit_mac(c3, a3, b0);
    c3 = digit_mac(c3, a4, digit_times19(b9));
    c3 = digit_mac(c3, a5, digit_times19(b8));
    c3 = digit_mac(c3, a6, digit_times19(b7));
    c3 = digit_mac(c3, a7, digit_times19(b6));
    c3 = digit_mac(c3, a8, digit_times19(b5));
    c3 = digit_mac(c3, a9, digit_times19(b4));
    let mut c4 = digit_product(a0, b4);
    c4 = digit_mac(c4, digit_times2(a1), b3);
    c4 = digit_mac(c4, a2, b2);
    c4 = digit_mac(c4, digit_times2(a3), b1);
    c4 = digit_mac(c4, a4, b0);
    c4 = digit_mac(c4, digit_times2(a5), digit_times19(b9));
    c4 = digit_mac(c4, a6, digit_times19(b8));
    c4 = digit_mac(c4, digit_times2(a7), digit_times19(b7));
    c4 = digit_mac(c4, a8, digit_times19(b6));
    c4 = digit_mac(c4, digit_times2(a9), digit_times19(b5));
    let mut c5 = digit_product(a0, b5);
    c5 = digit_mac(c5, a1, b4);
    c5 = digit_mac(c5, a2, b3);
    c5 = digit_mac(c5, a3, b2);
    c5 = digit_mac(c5, a4, b1);
    c5 = digit_mac(c5, a5, b0);
    c5 = digit_mac(c5, a6, digit_times19(b9));
    c5 = digit_mac(c5, a7, digit_times19(b8));
    c5 = digit_mac(c5, a8, digit_times19(b7));
    c5 = digit_mac(c5, a9, digit_times19(b6));
    let mut c6 = digit_product(a0, b6);
    c6 = digit_mac(c6, digit_times2(a1), b5);
    c6 = digit_mac(c6, a2, b4);
    c6 = digit_mac(c6, digit_times2(a3), b3);
    c6 = digit_mac(c6, a4, b2);
    c6 = digit_mac(c6, digit_times2(a5), b1);
    c6 = digit_mac(c6, a6, b0);
    c6 = digit_mac(c6, digit_times2(a7), digit_times19(b9));
    c6 = digit_mac(c6, a8, digit_times19(b8));
    c6 = digit_mac(c6, digit_times2(a9), digit_times19(b7));
    let mut c7 = digit_product(a0, b7);
    c7 = digit_mac(c7, a1, b6);
    c7 = digit_mac(c7, a2, b5);
    c7 = digit_mac(c7, a3, b4);
    c7 = digit_mac(c7, a4, b3);
    c7 = digit_mac(c7, a5, b2);
    c7 = digit_mac(c7, a6, b1);
    c7 = digit_mac(c7, a7, b0);
    c7 = digit_mac(c7, a8, digit_times19(b9));
    c7 = digit_mac(c7, a9, digit_times19(b8));
    let mut c8 = digit_product(a0, b8);
    c8 = digit_mac(c8, digit_times2(a1), b7);
    c8 = digit_mac(c8, a2, b6);
    c8 = digit_mac(c8, digit_times2(a3), b5);
    c8 = digit_mac(c8, a4, b4);
    c8 = digit_mac(c8, digit_times2(a5), b3);
    c8 = digit_mac(c8, a6, b2);
    c8 = digit_mac(c8, digit_times2(a7), b1);
    c8 = digit_mac(c8, a8, b0);
    c8 = digit_mac(c8, digit_times2(a9), digit_times19(b9));
    let mut c9 = digit_product(a0, b9);
    c9 = digit_mac(c9, a1, b8);
    c9 = digit_mac(c9, a2, b7);
    c9 = digit_mac(c9, a3, b6);
    c9 = digit_mac(c9, a4, b5);
    c9 = digit_mac(c9, a5, b4);
    c9 = digit_mac(c9, a6, b3);
    c9 = digit_mac(c9, a7, b2);
    c9 = digit_mac(c9, a8, b1);
    c9 = digit_mac(c9, a9, b0);
    reduce_columns([c0, c1, c2, c3, c4, c5, c6, c7, c8, c9])
}

/// Accumulates one term of a direct ten-digit square.
#[inline(always)]
fn square_column_mac<const COLUMN: usize, const SCALE: u32, const DOUBLE: bool>(
    c: &mut [uint64x2_t; 10],
    a: uint32x2_t,
    b: uint32x2_t,
) {
    // SAFETY: AArch64 targets provide NEON. Every call uses a column below ten and a scale in
    // {1, 2, 4, 19, 38}. A 26-bit digit scaled by at most 38 fits in `u32`; the doubled products
    // and accumulated columns fit under the bounds documented by `square_regs`.
    unsafe {
        let b = match SCALE {
            1 => b,
            2 => vshl_n_u32(b, 1),
            4 => vshl_n_u32(b, 2),
            19 => digit_times19(b),
            38 => vshl_n_u32(digit_times19(b), 1),
            _ => unreachable!(),
        };
        let mut product = vmull_u32(a, b);
        if DOUBLE {
            product = vshlq_n_u64(product, 1);
        }
        c[COLUMN] = vaddq_u64(c[COLUMN], product);
    }
}

/// Squares directly in the alternating 26/25-bit digit basis.
///
/// The coefficient of each distinct pair is doubled. A pair of odd-numbered digits gains another
/// factor of two because their radix exponents sum one bit above the corresponding even digit,
/// and terms beyond digit nine fold by `2^255 = 19`. Scales of 76 are represented as a 38-scaled
/// `u32` operand followed by a doubled `u64` product. Every column is bounded by the corresponding
/// general-multiplication column, at worst `267 * (2^26 - 1)^2 < 2^61`.
///
/// Keeping the 55 products explicit is deliberate: coefficients are applied while digits are
/// still `u32`, avoiding packed-`u64` constant multiplications that LLVM scalarizes on Apple
/// targets, while the independent columns expose enough instruction-level parallelism.
#[inline(always)]
fn square_regs(a: Regs) -> Regs {
    let pairs = split_pairs(a);
    let x = [
        pairs[0].lo,
        pairs[0].hi,
        pairs[1].lo,
        pairs[1].hi,
        pairs[2].lo,
        pairs[2].hi,
        pairs[3].lo,
        pairs[3].hi,
        pairs[4].lo,
        pairs[4].hi,
    ];
    // SAFETY: AArch64 targets provide NEON.
    let zero = unsafe { vdupq_n_u64(0) };
    let mut c = [zero; 10];

    square_column_mac::<0, 1, false>(&mut c, x[0], x[0]);
    square_column_mac::<1, 2, false>(&mut c, x[0], x[1]);
    square_column_mac::<2, 2, false>(&mut c, x[0], x[2]);
    square_column_mac::<3, 2, false>(&mut c, x[0], x[3]);
    square_column_mac::<4, 2, false>(&mut c, x[0], x[4]);
    square_column_mac::<5, 2, false>(&mut c, x[0], x[5]);
    square_column_mac::<6, 2, false>(&mut c, x[0], x[6]);
    square_column_mac::<7, 2, false>(&mut c, x[0], x[7]);
    square_column_mac::<8, 2, false>(&mut c, x[0], x[8]);
    square_column_mac::<9, 2, false>(&mut c, x[0], x[9]);
    square_column_mac::<2, 2, false>(&mut c, x[1], x[1]);
    square_column_mac::<3, 2, false>(&mut c, x[1], x[2]);
    square_column_mac::<4, 4, false>(&mut c, x[1], x[3]);
    square_column_mac::<5, 2, false>(&mut c, x[1], x[4]);
    square_column_mac::<6, 4, false>(&mut c, x[1], x[5]);
    square_column_mac::<7, 2, false>(&mut c, x[1], x[6]);
    square_column_mac::<8, 4, false>(&mut c, x[1], x[7]);
    square_column_mac::<9, 2, false>(&mut c, x[1], x[8]);
    square_column_mac::<0, 38, true>(&mut c, x[1], x[9]);
    square_column_mac::<4, 1, false>(&mut c, x[2], x[2]);
    square_column_mac::<5, 2, false>(&mut c, x[2], x[3]);
    square_column_mac::<6, 2, false>(&mut c, x[2], x[4]);
    square_column_mac::<7, 2, false>(&mut c, x[2], x[5]);
    square_column_mac::<8, 2, false>(&mut c, x[2], x[6]);
    square_column_mac::<9, 2, false>(&mut c, x[2], x[7]);
    square_column_mac::<0, 38, false>(&mut c, x[2], x[8]);
    square_column_mac::<1, 38, false>(&mut c, x[2], x[9]);
    square_column_mac::<6, 2, false>(&mut c, x[3], x[3]);
    square_column_mac::<7, 2, false>(&mut c, x[3], x[4]);
    square_column_mac::<8, 4, false>(&mut c, x[3], x[5]);
    square_column_mac::<9, 2, false>(&mut c, x[3], x[6]);
    square_column_mac::<0, 38, true>(&mut c, x[3], x[7]);
    square_column_mac::<1, 38, false>(&mut c, x[3], x[8]);
    square_column_mac::<2, 38, true>(&mut c, x[3], x[9]);
    square_column_mac::<8, 1, false>(&mut c, x[4], x[4]);
    square_column_mac::<9, 2, false>(&mut c, x[4], x[5]);
    square_column_mac::<0, 38, false>(&mut c, x[4], x[6]);
    square_column_mac::<1, 38, false>(&mut c, x[4], x[7]);
    square_column_mac::<2, 38, false>(&mut c, x[4], x[8]);
    square_column_mac::<3, 38, false>(&mut c, x[4], x[9]);
    square_column_mac::<0, 38, false>(&mut c, x[5], x[5]);
    square_column_mac::<1, 38, false>(&mut c, x[5], x[6]);
    square_column_mac::<2, 38, true>(&mut c, x[5], x[7]);
    square_column_mac::<3, 38, false>(&mut c, x[5], x[8]);
    square_column_mac::<4, 38, true>(&mut c, x[5], x[9]);
    square_column_mac::<2, 19, false>(&mut c, x[6], x[6]);
    square_column_mac::<3, 38, false>(&mut c, x[6], x[7]);
    square_column_mac::<4, 38, false>(&mut c, x[6], x[8]);
    square_column_mac::<5, 38, false>(&mut c, x[6], x[9]);
    square_column_mac::<4, 38, false>(&mut c, x[7], x[7]);
    square_column_mac::<5, 38, false>(&mut c, x[7], x[8]);
    square_column_mac::<6, 38, true>(&mut c, x[7], x[9]);
    square_column_mac::<6, 19, false>(&mut c, x[8], x[8]);
    square_column_mac::<7, 38, false>(&mut c, x[8], x[9]);
    square_column_mac::<8, 38, false>(&mut c, x[9], x[9]);

    reduce_columns(c)
}

/// Reduces each radix-`2^51` lane with one parallel carry pass.
///
/// # Correctness
///
/// Inputs must have limbs below `2^63`. Outputs then have limbs below `2^52`.
#[inline(always)]
fn reduce_regs(l: Regs) -> Regs {
    // SAFETY: AArch64 targets provide NEON.
    unsafe {
        let mask = vdupq_n_u64(MASK_51);
        let c: Regs = core::array::from_fn(|i| vshrq_n_u64(l[i], 51));
        [
            vaddq_u64(vandq_u64(l[0], mask), mul19(c[4])),
            vaddq_u64(vandq_u64(l[1], mask), c[0]),
            vaddq_u64(vandq_u64(l[2], mask), c[1]),
            vaddq_u64(vandq_u64(l[3], mask), c[2]),
            vaddq_u64(vandq_u64(l[4], mask), c[3]),
        ]
    }
}

/// Elementwise addition without a carry pass.
///
/// # Correctness
///
/// The sum must not wrap around `u64` if it is to represent integer addition.
#[inline(always)]
fn add_raw(a: Regs, b: Regs) -> Regs {
    // SAFETY: AArch64 targets provide NEON.
    unsafe { core::array::from_fn(|i| vaddq_u64(a[i], b[i])) }
}

/// Elementwise subtraction as `a + 16p - b`, without a carry pass.
///
/// # Correctness
///
/// Every limb of `b` must be less than `2^52`, and the biased sum must not wrap around `u64`.
#[inline(always)]
fn sub_raw(a: Regs, b: Regs) -> Regs {
    // SAFETY: AArch64 targets provide NEON.
    unsafe {
        core::array::from_fn(|i| {
            let biased = vaddq_u64(a[i], vdupq_n_u64(SUB_BIAS[i]));
            vsubq_u64(biased, b[i])
        })
    }
}

/// Applies a register operation to each two-lane tile.
#[inline(always)]
fn map_f(a: FVec, operation: impl Fn(Regs) -> Regs) -> FVec {
    let mut result = FVec::splat(F::ZERO);
    for tile in 0..TILES {
        store(operation(load(&a.limbs, tile)), &mut result.limbs, tile);
    }
    result
}

/// Applies a binary register operation to each pair of two-lane tiles.
#[inline(always)]
fn map2_f(a: FVec, b: FVec, operation: impl Fn(Regs, Regs) -> Regs) -> FVec {
    let mut result = FVec::splat(F::ZERO);
    for tile in 0..TILES {
        store(
            operation(load(&a.limbs, tile), load(&b.limbs, tile)),
            &mut result.limbs,
            tile,
        );
    }
    result
}

/// Every input must satisfy [`FVec`]'s limb bound. That bound keeps raw field arithmetic and all
/// wide accumulators within their documented ranges.
impl FBackend for Backend {
    #[inline(always)]
    fn add(self, a: FVec, b: FVec) -> FVec {
        map2_f(a, b, |a, b| reduce_regs(add_raw(a, b)))
    }

    #[inline(always)]
    fn neg(self, a: FVec) -> FVec {
        // SAFETY: AArch64 targets provide NEON.
        let zero = unsafe { [vdupq_n_u64(0); 5] };
        map_f(a, |a| reduce_regs(sub_raw(zero, a)))
    }

    #[inline(always)]
    fn sub(self, a: FVec, b: FVec) -> FVec {
        map2_f(a, b, |a, b| reduce_regs(sub_raw(a, b)))
    }

    #[inline(always)]
    fn mul(self, a: FVec, b: FVec) -> FVec {
        map2_f(a, b, mul_regs)
    }

    #[inline(always)]
    fn square(self, a: FVec) -> FVec {
        map_f(a, square_regs)
    }
}

/// Returns an all-zero point used as fully overwritten output storage.
#[inline(always)]
const fn empty_gvec() -> GVec {
    let zero = FVec::splat(F::ZERO);
    GVec {
        x: zero,
        y: zero,
        t: zero,
        z: zero,
    }
}

impl GBackend for Backend {
    /// Fused point addition, processed two lanes at a time to keep the working set in registers.
    #[inline(always)]
    fn g_add(self, p: GVec, q: GVec) -> GVec {
        let mut result = empty_gvec();
        for tile in 0..TILES {
            // Unified extended-coordinates addition (Hisil-Wong-Carter-Dawson):
            //
            //   A = (Y1 - X1) * (Y2 - X2)        E = B - A        X3 = E*F
            //   B = (Y1 + X1) * (Y2 + X2)        F = D - C        Y3 = G*H
            //   C = 2d * T1 * T2                 G = D + C        Z3 = F*G
            //   D = 2 * Z1 * Z2                  H = B + A        T3 = E*H
            let x1 = load(&p.x.limbs, tile);
            let y1 = load(&p.y.limbs, tile);
            let x2 = load(&q.x.limbs, tile);
            let y2 = load(&q.y.limbs, tile);
            let a = mul_regs(reduce_regs(sub_raw(y1, x1)), reduce_regs(sub_raw(y2, x2)));
            let b = mul_regs(reduce_regs(add_raw(y1, x1)), reduce_regs(add_raw(y2, x2)));
            let c = mul_regs(
                mul_regs(load(&p.t.limbs, tile), load(&q.t.limbs, tile)),
                load(&EDWARDS_D2.limbs, tile),
            );
            let zz = mul_regs(load(&p.z.limbs, tile), load(&q.z.limbs, tile));
            let d = reduce_regs(add_raw(zz, zz));
            let e = reduce_regs(sub_raw(b, a));
            let f = reduce_regs(sub_raw(d, c));
            let g = reduce_regs(add_raw(d, c));
            let h = reduce_regs(add_raw(b, a));

            store(mul_regs(e, f), &mut result.x.limbs, tile);
            store(mul_regs(g, h), &mut result.y.limbs, tile);
            store(mul_regs(e, h), &mut result.t.limbs, tile);
            store(mul_regs(f, g), &mut result.z.limbs, tile);
        }
        result
    }

    /// Fused mixed point addition, processed two lanes at a time.
    #[inline(always)]
    fn g_add_mixed(self, p: GVec, q: GAffineVec) -> GVec {
        let mut result = empty_gvec();
        for tile in 0..TILES {
            let x1 = load(&p.x.limbs, tile);
            let y1 = load(&p.y.limbs, tile);
            let x2 = load(&q.x.limbs, tile);
            let y2 = load(&q.y.limbs, tile);
            let a = mul_regs(reduce_regs(sub_raw(y1, x1)), reduce_regs(sub_raw(y2, x2)));
            let b = mul_regs(reduce_regs(add_raw(y1, x1)), reduce_regs(add_raw(y2, x2)));
            let c = mul_regs(load(&p.t.limbs, tile), load(&q.t2d.limbs, tile));
            let z1 = load(&p.z.limbs, tile);
            let d = reduce_regs(add_raw(z1, z1));
            let e = reduce_regs(sub_raw(b, a));
            let f = reduce_regs(sub_raw(d, c));
            let g = reduce_regs(add_raw(d, c));
            let h = reduce_regs(add_raw(b, a));

            store(mul_regs(e, f), &mut result.x.limbs, tile);
            store(mul_regs(g, h), &mut result.y.limbs, tile);
            store(mul_regs(e, h), &mut result.t.limbs, tile);
            store(mul_regs(f, g), &mut result.z.limbs, tile);
        }
        result
    }

    /// Fused point doubling using the dedicated `dbl-2008-hwcd` formula.
    #[inline(always)]
    fn g_double(self, p: GVec) -> GVec {
        let mut result = empty_gvec();
        for tile in 0..TILES {
            let x = load(&p.x.limbs, tile);
            let y = load(&p.y.limbs, tile);
            let z = load(&p.z.limbs, tile);

            let a = square_regs(x);
            let b = square_regs(y);
            let c0 = square_regs(z);
            let c = reduce_regs(add_raw(c0, c0));
            let xy2 = square_regs(reduce_regs(add_raw(x, y)));
            let e = reduce_regs(sub_raw(sub_raw(xy2, a), b));
            let g = reduce_regs(sub_raw(b, a));
            let f = reduce_regs(sub_raw(g, c));
            // SAFETY: AArch64 targets provide NEON.
            let zero = unsafe { [vdupq_n_u64(0); 5] };
            let h = reduce_regs(sub_raw(sub_raw(zero, a), b));

            store(mul_regs(e, f), &mut result.x.limbs, tile);
            store(mul_regs(g, h), &mut result.y.limbs, tile);
            store(mul_regs(e, h), &mut result.t.limbs, tile);
            store(mul_regs(f, g), &mut result.z.limbs, tile);
        }
        result
    }
}

impl super::Backend for Backend {}
