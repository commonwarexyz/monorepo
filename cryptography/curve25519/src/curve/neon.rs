//! The Arm NEON backend: two lanes of an [`super::FVec`] limb row per 128-bit register.
//!
//! The generic field kernels stay entirely in NEON. A scalar-plus-NEON design only becomes useful
//! when independent operations are scheduled across a complete point formula; dividing one
//! [`super::FVec`] operation between both domains adds setup and synchronization costs on Apple
//! M-series CPUs. Products split radix-`2^51` limbs into digits at alternating 26/25-bit offsets
//! only while multiplying. Loose input digits can each occupy 26 bits. The surrounding group
//! formulas keep their compact five-limb representation.

use super::{
    BIAS_16P as SUB_BIAS, F, FBackend, FVec, G, GAffine, GAffineVec, GBackend, GVec, LANES,
    MASK_51, msm,
};
#[cfg(not(feature = "std"))]
use alloc::vec;
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
/// `z` must be less than `2^59` per lane so `19*z` fits in `u64`.
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

/// Reduces ten alternating 26/25-bit product columns into five loose radix-`2^51` limbs.
///
/// With `M = 2^26 - 1`, column bounds are `M^2` times
/// `[267, 154, 213, 118, 159, 82, 105, 46, 51, 10]`.
/// Each pair satisfies `c[2*i] + 2^26*c[2*i + 1] = low[i] + 2^51*carry[i]`, with
/// `low[i] < 2^51`. Carries move to the next limb, wrapping the top carry by `2^255 = 19 (mod p)`.
#[inline(always)]
fn reduce_columns(c: [uint64x2_t; 10]) -> Regs {
    // SAFETY: AArch64 targets provide NEON. Paired columns and carry additions fit in u64.
    unsafe {
        let mask26 = vdupq_n_u64((1 << 26) - 1);
        let mask25 = vdupq_n_u64((1 << 25) - 1);
        let paired: Regs =
            core::array::from_fn(|i| vaddq_u64(c[2 * i + 1], vshrq_n_u64(c[2 * i], 26)));
        let mut out: Regs = core::array::from_fn(|i| {
            vorrq_u64(
                vandq_u64(c[2 * i], mask26),
                vshlq_n_u64(vandq_u64(paired[i], mask25), 26),
            )
        });

        // Column 8 is at most 51*M^2 and column 9 at most 10*M^2, so the top carry fits
        // below 2^31 and can narrow losslessly. Its 19-fold and every other carry are
        // below 2^35, leaving each output below 2^51 + 2^35 < 2^52 without another pass.
        let top = vmovn_u64(vshrq_n_u64(paired[4], 25));
        out[0] = vaddq_u64(out[0], vmull_n_u32(top, 19));
        for i in 1..5 {
            out[i] = vaddq_u64(out[i], vshrq_n_u64(paired[i - 1], 25));
        }
        out
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

/// Packs two independent field elements into register lanes.
#[inline(always)]
fn pack_pair(values: [F; 2]) -> Regs {
    // SAFETY: AArch64 targets provide NEON, and the selected lane is within the two-lane register.
    unsafe {
        core::array::from_fn(|i| vsetq_lane_u64(values[1].0[i], vdupq_n_u64(values[0].0[i]), 1))
    }
}

/// Unpacks both register lanes into independent field elements.
#[inline(always)]
fn unpack_pair(regs: Regs) -> [F; 2] {
    // SAFETY: AArch64 targets provide NEON, and both lane indices are within the register.
    unsafe {
        [
            F(regs.map(|reg| vgetq_lane_u64(reg, 0))),
            F(regs.map(|reg| vgetq_lane_u64(reg, 1))),
        ]
    }
}

/// Applies the complete mixed-addition formula to two independent register lanes.
///
/// Extended inputs and outputs use `[x, y, t, z]`. Affine inputs use `[x, y, t2d]`.
#[inline(always)]
fn add_mixed_regs(p: [Regs; 4], q: [Regs; 3]) -> [Regs; 4] {
    let [x1, y1, t1, z1] = p;
    let [x2, y2, t2d] = q;
    let a = mul_regs(reduce_regs(sub_raw(y1, x1)), reduce_regs(sub_raw(y2, x2)));
    let b = mul_regs(reduce_regs(add_raw(y1, x1)), reduce_regs(add_raw(y2, x2)));
    let c = mul_regs(t1, t2d);
    let d = add_raw(z1, z1);
    let e = reduce_regs(sub_raw(b, a));
    let f = reduce_regs(sub_raw(d, c));
    let g = reduce_regs(add_raw(d, c));
    let h = reduce_regs(add_raw(b, a));
    [
        mul_regs(e, f),
        mul_regs(g, h),
        mul_regs(e, h),
        mul_regs(f, g),
    ]
}

impl GBackend for Backend {
    /// Fused point addition, processed two lanes at a time to keep the working set in registers.
    #[inline(always)]
    fn g_add(self, mut p: GVec, q: GVec) -> GVec {
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
            let d = add_raw(zz, zz);
            let e = reduce_regs(sub_raw(b, a));
            let f = reduce_regs(sub_raw(d, c));
            let g = reduce_regs(add_raw(d, c));
            let h = reduce_regs(add_raw(b, a));

            store(mul_regs(e, f), &mut p.x.limbs, tile);
            store(mul_regs(g, h), &mut p.y.limbs, tile);
            store(mul_regs(e, h), &mut p.t.limbs, tile);
            store(mul_regs(f, g), &mut p.z.limbs, tile);
        }
        p
    }

    /// Fused mixed point addition, processed two lanes at a time.
    #[inline(always)]
    fn g_add_mixed(self, mut p: GVec, q: GAffineVec) -> GVec {
        for tile in 0..TILES {
            let [x, y, t, z] = add_mixed_regs(
                [
                    load(&p.x.limbs, tile),
                    load(&p.y.limbs, tile),
                    load(&p.t.limbs, tile),
                    load(&p.z.limbs, tile),
                ],
                [
                    load(&q.x.limbs, tile),
                    load(&q.y.limbs, tile),
                    load(&q.t2d.limbs, tile),
                ],
            );
            store(x, &mut p.x.limbs, tile);
            store(y, &mut p.y.limbs, tile);
            store(t, &mut p.t.limbs, tile);
            store(z, &mut p.z.limbs, tile);
        }
        p
    }

    /// Fused point doubling using the dedicated `dbl-2008-hwcd` formula.
    #[inline(always)]
    fn g_double(self, mut p: GVec) -> GVec {
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

            store(mul_regs(e, f), &mut p.x.limbs, tile);
            store(mul_regs(g, h), &mut p.y.limbs, tile);
            store(mul_regs(e, h), &mut p.t.limbs, tile);
            store(mul_regs(f, g), &mut p.z.limbs, tile);
        }
        p
    }
}

impl super::Backend for Backend {}

/// Adds a signed affine point to each of two extended points.
///
/// Each result is `p[i] + q[i]` or `p[i] - q[i]` according to `negative[i]`.
/// Variable-time, so the signs must be public.
#[inline(always)]
fn g_add_mixed_pair(p: [G; 2], q: [GAffine; 2], negative: [bool; 2]) -> [G; 2] {
    let mut x2 = pack_pair(q.map(|point| point.x));
    let mut t2d = pack_pair(q.map(|point| point.t2d));
    if negative.iter().any(|&sign| sign) {
        // SAFETY: AArch64 targets provide NEON, and the mask array has two complete lanes.
        unsafe {
            let masks = negative.map(|sign| 0u64.wrapping_sub(u64::from(sign)));
            let mask = vld1q_u64(masks.as_ptr());
            let zero = [vdupq_n_u64(0); 5];
            let neg_x = reduce_regs(sub_raw(zero, x2));
            let neg_t2d = reduce_regs(sub_raw(zero, t2d));
            x2 = core::array::from_fn(|i| vbslq_u64(mask, neg_x[i], x2[i]));
            t2d = core::array::from_fn(|i| vbslq_u64(mask, neg_t2d[i], t2d[i]));
        }
    }
    let [x, y, t, z] = add_mixed_regs(
        [
            pack_pair(p.map(|point| point.x)),
            pack_pair(p.map(|point| point.y)),
            pack_pair(p.map(|point| point.t)),
            pack_pair(p.map(|point| point.z)),
        ],
        [x2, pack_pair(q.map(|point| point.y)), t2d],
    );
    let x = unpack_pair(x);
    let y = unpack_pair(y);
    let t = unpack_pair(t);
    let z = unpack_pair(z);
    core::array::from_fn(|i| G {
        x: x[i],
        y: y[i],
        t: t[i],
        z: z[i],
    })
}

impl Backend {
    /// Returns lanes whose sum is the weighted sum of all bucket stripes.
    ///
    /// Let `B[k, lane]` sum the stripes at bucket index `k*LANES + lane`. The descending pass
    /// builds `sum[lane] = sum_k B[k, lane]` and `rows[lane] = sum_k k*B[k, lane]`.
    /// Final weighting gives `LANES*rows[lane] + (lane + 1)*sum[lane]`, assigning each bucket
    /// its index-plus-one weight. The lane count is a power of two.
    fn fold_buckets_lanes(self, buckets: &[G], nb: usize, used: usize) -> GVec {
        // A single used bucket has weight one, so return the stripes without weighting.
        if used == 1 {
            return GVec::transpose(core::array::from_fn(|lane| {
                if lane < <Self as msm::Backend>::STRIPES {
                    buckets[lane * nb]
                } else {
                    G::IDENTITY
                }
            }));
        }
        let mut sum = GVec::identity();
        let mut rows = GVec::identity();
        for block in (0..used.div_ceil(LANES)).rev() {
            let gather = |stripe: usize| {
                GVec::transpose(core::array::from_fn(|lane| {
                    let digit = block * LANES + lane;
                    if digit < used {
                        buckets[stripe * nb + digit]
                    } else {
                        G::IDENTITY
                    }
                }))
            };
            let mut combined = gather(0);
            for stripe in 1..<Self as msm::Backend>::STRIPES {
                combined = self.g_add(combined, gather(stripe));
            }
            rows = self.g_add(rows, sum);
            sum = self.g_add(sum, combined);
        }

        // Seed the row weight and the high bit of lane + 1. Doubling shifts both together.
        let lanes = sum.untranspose();
        let mut weighted = self.g_add(
            rows,
            GVec::transpose(core::array::from_fn(|lane| {
                if lane == LANES - 1 {
                    lanes[lane]
                } else {
                    G::IDENTITY
                }
            })),
        );
        for bit in (0..LANES.ilog2()).rev() {
            weighted = self.g_double(weighted);
            let selected = core::array::from_fn(|lane| {
                if (lane + 1) & (1 << bit) != 0 {
                    lanes[lane]
                } else {
                    G::IDENTITY
                }
            });
            weighted = self.g_add(weighted, GVec::transpose(selected));
        }
        weighted
    }
}

impl msm::Backend for Backend {
    // One stripe per physical mixed-addition lane keeps wave updates independent. Folds retain
    // LANES independent bucket indices.
    const STRIPES: usize = WIDTH;

    fn fill_buckets<T>(
        self,
        buckets: &mut [G],
        nb: usize,
        terms: &[T],
        term: impl Fn(&T) -> (GAffine, i16),
    ) {
        msm::fill_buckets(g_add_mixed_pair, buckets, nb, terms, term);
    }

    #[inline(always)]
    fn fold_buckets(self, buckets: &[G], nb: usize, used: usize) -> G {
        self.fold_buckets_lanes(buckets, nb, used).sum_lanes(self)
    }

    /// Scalar recombination computes each point once, avoiding duplicate SIMD lanes.
    fn combine_windows(
        self,
        partials: impl IntoIterator<Item = (usize, G)>,
        windows: usize,
        width: u32,
    ) -> G {
        let mut window_sums = vec![G::IDENTITY; windows];
        for (window, partial) in partials {
            window_sums[window] = window_sums[window].add(partial);
        }
        let mut result = G::IDENTITY;
        for window in window_sums.iter().rev() {
            for _ in 0..width {
                result = result.double();
            }
            result = result.add(*window);
        }
        result
    }
}

#[test]
fn mixed_pair_matches_full_width() {
    let reference = super::portable::Backend::new();
    let torsion = GAffine::decompress(&[0; 32]).unwrap();
    let mixed = GAffine::decompress(
        &GAffine::BASEPOINT
            .to_extended()
            .add(torsion.to_extended())
            .to_bytes(),
    )
    .unwrap();
    let points = [GAffine::IDENTITY, GAffine::BASEPOINT, torsion, mixed];
    let max = F([super::test::MASK_52; 5]);
    let loose = G {
        x: max,
        y: max,
        t: max,
        z: max,
    };
    let loose_affine = GAffine {
        x: max,
        y: max,
        t2d: max,
    };
    for i in 0..points.len() {
        for j in 0..points.len() {
            let current = [points[i].to_extended(), points[j].to_extended()];
            let current = core::array::from_fn(|lane| {
                let factor = F([lane as u64 + 2, 0, 0, 0, 0]);
                G {
                    x: current[lane].x.mul(factor),
                    y: current[lane].y.mul(factor),
                    t: current[lane].t.mul(factor),
                    z: current[lane].z.mul(factor),
                }
            });
            let incoming = [points[j], points[(i + 1) % points.len()]];
            for (current, incoming) in [
                (current, incoming),
                ([loose, current[1]], [loose_affine, incoming[1]]),
            ] {
                for negative in [[false, false], [false, true], [true, false], [true, true]] {
                    let mut packed_current = [G::IDENTITY; LANES];
                    let mut packed_incoming = [GAffine::IDENTITY; LANES];
                    let mut packed_negative = [false; LANES];
                    packed_current[..WIDTH].copy_from_slice(&current);
                    packed_incoming[..WIDTH].copy_from_slice(&incoming);
                    packed_negative[..WIDTH].copy_from_slice(&negative);
                    let expected = reference
                        .g_add_mixed(
                            GVec::transpose(packed_current),
                            GAffineVec::from_signed_lanes(
                                reference,
                                &packed_incoming,
                                &packed_negative,
                            ),
                        )
                        .untranspose();
                    let actual = g_add_mixed_pair(current, incoming, negative);
                    for lane in 0..2 {
                        for (actual, expected) in [
                            (actual[lane].x, expected[lane].x),
                            (actual[lane].y, expected[lane].y),
                            (actual[lane].t, expected[lane].t),
                            (actual[lane].z, expected[lane].z),
                        ] {
                            super::test::assert_f_eq(
                                FVec::splat(actual),
                                FVec::splat(expected),
                                "mixed pair coordinate",
                            );
                        }
                    }
                }
            }
        }
    }
}
