//! Unsaturated radix-`2^28` Montgomery arithmetic on several base field elements at once, using
//! 32-bit lane values.
//!
//! An [`Unsat28`] is a matrix with [`LIMBS`] rows and `S::U32_LANES` columns: row `i` holds limb
//! `i` of every element. Elements use radix `2^28` in Montgomery form with `R = 2^392`. Limbs
//! occupy 32-bit lanes and products accumulate in 64-bit lanes: `u32_widen_mul_first` and
//! `u32_widen_mul_second` split each row of products between two 64-bit vectors (UMULL and UMULL2
//! on NEON, VPMULUDQ on even and odd lanes on AVX-512), and `u64_narrow_pair` packs limbs back.
//!
//! # Usage
//!
//! Elements cross the boundary as [`BYTES`]-byte big-endian integers below `2^384`, which loads
//! interpret modulo `p` and stores return canonically.
//!
//! Loads, splats, products, and [`Unsat28::carry`] return carried values, whose limbs are below
//! `2^28`; additions, subtractions, negations, and doublings return uncarried ones. A
//! multiplication accepts limbs below `2^30`, so it multiplies sums of up to [`SLACK`] carried
//! values without carrying them. [`Unsat28::ready`] prepares a multiplicand from a static bound on
//! its limbs, carrying only when that bound exceeds [`SLACK`]. A subtraction or negation removes
//! values whose limbs are at most twice those of a carried value. Limbs must also fit their 32-bit
//! lanes, so a value holds at most [`LIMB_LIMIT`] carried values' worth of limbs: longer chains of
//! additions carry along the way.
//!
//! Carrying preserves the represented integer; multiplication is what reduces modulo `p`, and
//! [`Unsat28::store`] returns canonical elements from any value. A subtraction or negation bias
//! `K` must exceed the bound of the value it removes.
//!
//! # Bounds
//!
//! Each value carries two debug-only bound counters: an integer bound in units of `p`, and a
//! limb bound in units of `2^28`. For integer bounds `A` and `B` and limb bounds `L` and `M`:
//!
//! | Operation | Requires | Integer bound | Limb bound |
//! |---|---|---|---|
//! | load, splat | | `2` | `1` |
//! | `a + b` | | `A + B` | `L + M` |
//! | `a - b` with bias `K` | `M <= 2`, `B < K` | `A + K` | `L + 3` |
//! | `-a` with bias `K` | `L <= 2`, `A < K` | `K` | `3` |
//! | carry | | `A` | `1` |
//! | `a * b` | `L, M <= SLACK` | `ceil(A * B / LIMIT) + 1` | `1` |
//! | tight reduction | | `2` | `1` |
//!
//! Every integer bound is at most [`LIMIT`], so values fit carried limbs because `p < 2^381`.
//! Every limb bound is at most [`LIMB_LIMIT`], so limbs stay below `15 * 2^28` and still fit their
//! lanes after receiving a carry, which is at most `15`. Multiplication returns below
//! `a * b / 2^392 + p`, and `p / 2^392 < 1 / LIMIT`. A tight reduction subtracts an estimate of
//! the multiple of `p` that the top limb covers and carries, which returns below `1.03 p`. Debug
//! builds check these rules; release builds do not, and results are unspecified when a formula
//! violates them.

use super::{
    super::arithmetic::Field, BYTES, MODULUS, WORDS, bytes_from_words, power_of_two,
    words_from_bytes,
};
use crate::{core::debug_counter::DebugCounter, montgomery::negated_inverse};
use commonware_simd::{Neon, Operation, Simd};
use core::hint::black_box;

/// Number of limbs in a field element.
pub const LIMBS: usize = 14;

/// Largest number of elements in a value, the widest backend's `S::U32_LANES`.
pub const MAX_LANES: usize = 16;

/// Bits per carried limb.
const LIMB_BITS: u32 = 28;

/// The low [`LIMB_BITS`] bits of a limb.
const MASK: u32 = (1 << LIMB_BITS) - 1;

/// Largest integer bound of any value, in units of `p`.
///
/// Because `p < 2^381`, `LIMIT * p < 2^392` and `p / 2^392 < 1 / LIMIT`.
pub const LIMIT: u64 = {
    assert!(MODULUS[WORDS - 1] < 1 << 61);
    1 << (LIMBS as u32 * LIMB_BITS - 381)
};

/// Largest limb bound of a multiplicand, in units of `2^28`.
///
/// The multiplier accepts any 32-bit limbs, but a product column must stay below `2^64`: it sums
/// at most [`LIMBS`] products of multiplicand limbs below `SLACK * 2^28`, [`LIMBS`] reduction
/// products of 28-bit factors, and a carry below `2^36`.
pub const SLACK: u64 = {
    let slack: u64 = 4;
    assert!(slack <= LIMB_LIMIT);
    let products = (slack * slack + 1) as u128 * LIMBS as u128;
    assert!((products << (2 * LIMB_BITS)) + (1 << (64 - LIMB_BITS)) <= u64::MAX as u128);
    slack
};

/// Largest limb bound of any value, in units of `2^28`.
///
/// Limbs stay below `15 * 2^28`, so each still fits its 32-bit lane after receiving a carry,
/// which is at most `15`.
pub const LIMB_LIMIT: u64 = (1 << (32 - LIMB_BITS)) - 1;

/// The modulus `p` in limbs.
const P: [u32; LIMBS] = limbs_from_words(MODULUS);

/// The limbs of `p`, four per vector, which NEON multiplies by vector lane.
const P_LANES: [[u32; 4]; 4] = {
    let mut lanes = [[0; 4]; 4];
    let mut i = 0;
    while i < LIMBS {
        lanes[i / 4][i % 4] = P[i];
        i += 1;
    }
    lanes
};

/// `-p^(-1) mod 2^28`, the Montgomery reduction constant.
const INV: u32 = negated_inverse(MODULUS[0]) as u32 & MASK;

/// Bits of the fixed-point reciprocal of [`Unsat28::fold`].
const FOLD_SHIFT: u32 = 48;

/// `floor(2^48 / (t + 1))` for the top limb `t` of `p`, so that a top limb `h` gives the
/// multiple `floor(h * FOLD_RECIPROCAL / 2^48)` of `p`, at most `h / (t + 1)` and more than
/// `h / (t + 1) - 2`.
const FOLD_RECIPROCAL: u32 = {
    let reciprocal = (1u64 << FOLD_SHIFT) / (P[LIMBS - 1] as u64 + 1);
    assert!(reciprocal <= u32::MAX as u64);
    reciprocal as u32
};

/// Offset that [`Unsat28::fold`] adds to every limb but the top one and removes, as `2^12` units,
/// from the limb above, so that no limb difference goes negative.
const FOLD_OFFSET: u64 = {
    // A multiple of p below 2^11 times a 28-bit limb of p stays below the offset.
    assert!((LIMIT as u128 * MASK as u128) < (1 << 40) - (1 << 12));
    1 << 40
};

/// `R^2 mod p` for `R = 2^392`. A Montgomery multiplication by it maps `a` to `a * R`.
const TO_LANES: [u32; LIMBS] = limbs_from_words(power_of_two(2 * LIMBS as u32 * LIMB_BITS));

/// One. A Montgomery multiplication by it maps `a * R` back to `a`.
const FROM_LANES: [u32; LIMBS] = {
    let mut limbs = [0; LIMBS];
    limbs[0] = 1;
    limbs
};

/// Narrows limbs that are below `2^32`.
const fn narrow(wide: [u64; LIMBS]) -> [u32; LIMBS] {
    let mut limbs = [0; LIMBS];
    let mut i = 0;
    while i < LIMBS {
        assert!(wide[i] <= u32::MAX as u64);
        limbs[i] = wide[i] as u32;
        i += 1;
    }
    limbs
}

/// Splits a little-endian 64-bit integer below `2^384` into 28-bit limbs.
const fn limbs_from_words(words: [u64; WORDS]) -> [u32; LIMBS] {
    narrow(super::limbs_from_words::<LIMBS, LIMB_BITS>(words))
}

/// Joins carried 28-bit limbs of a value below `2^384` into little-endian 64-bit words.
const fn words_from_limbs(limbs: [u32; LIMBS]) -> [u64; WORDS] {
    let mut wide = [0; LIMBS];
    let mut i = 0;
    while i < LIMBS {
        wide[i] = limbs[i] as u64;
        i += 1;
    }
    super::words_from_limbs::<LIMBS, LIMB_BITS>(wide)
}

/// Returns `k * p` with twice `2^28` moved from each limb into the one below it, so that it can
/// absorb the subtraction of a value below `(k - 1) * p` whose limbs are at most twice those of a
/// carried value.
const fn bias(k: u64) -> [u32; LIMBS] {
    narrow(super::bias::<LIMBS, LIMB_BITS>(k))
}

/// `S::U32_LANES` base field elements in radix `2^28` Montgomery form, one per lane.
///
/// See the [module documentation](self) for the layout and the bounds every value satisfies.
pub struct Unsat28<S: Simd> {
    limbs: [S::U32; LIMBS],
    bound: DebugCounter,
    limb_bound: DebugCounter,
}

impl<S: Simd> Clone for Unsat28<S> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<S: Simd> Copy for Unsat28<S> {}

impl<S: Simd> Unsat28<S> {
    /// Number of 64-bit vectors that the products of one row of limbs fill.
    const HALVES: usize = {
        assert!(S::U32_LANES <= MAX_LANES);
        assert!(S::U32_LANES <= 2 * S::U64_LANES);
        if S::U32_LANES > S::U64_LANES { 2 } else { 1 }
    };

    /// Loads up to `S::U32_LANES` elements, one per lane, filling the remaining lanes with `fill`.
    #[inline(always)]
    pub fn load(simd: S, elements: &[[u8; BYTES]], fill: &[u8; BYTES]) -> Self {
        let fill = limbs_from_words(words_from_bytes(fill));
        let mut lanes = [[0; LIMBS]; MAX_LANES];
        for (i, lane) in lanes.iter_mut().enumerate().take(S::U32_LANES) {
            *lane = elements
                .get(i)
                .map_or(fill, |element| limbs_from_words(words_from_bytes(element)));
        }
        // Integers below 2^384 are below 10p.
        Self::raw(simd, &lanes, 10).to_lanes(simd)
    }

    /// Stores the canonical value of each lane into `elements`, dropping lanes beyond its length.
    #[inline(always)]
    pub fn store(self, simd: S, elements: &mut [[u8; BYTES]]) {
        let canonical = self
            .carry(simd)
            .mul(simd, Self::constant(simd, &FROM_LANES, 1))
            .subtract_modulus(simd);
        let rows = canonical.to_rows(simd);
        for (lane, element) in elements.iter_mut().enumerate().take(S::U32_LANES) {
            let limbs = core::array::from_fn(|i| rows[i][lane]);
            *element = bytes_from_words(&words_from_limbs(limbs));
        }
    }

    /// Transposes the carried limbs of the first `S::U32_LANES` lanes, bounded by `bound * p`,
    /// into limb rows.
    #[inline(always)]
    fn raw(simd: S, lanes: &[[u32; LIMBS]; MAX_LANES], bound: u64) -> Self {
        const { assert!(Self::HALVES > 0) };
        let mut limbs = [simd.u32_splat(0); LIMBS];
        for (i, limb) in limbs.iter_mut().enumerate() {
            let mut row = [0; MAX_LANES];
            for (value, lane) in row.iter_mut().zip(lanes).take(S::U32_LANES) {
                *value = lane[i];
            }
            *limb = simd.u32_load(&row);
        }
        Self {
            limbs,
            bound: DebugCounter::new(bound),
            limb_bound: DebugCounter::new(1),
        }
    }

    /// Returns every lane set to the carried `limbs`, bounded by `bound * p`.
    #[inline(always)]
    fn constant(simd: S, limbs: &[u32; LIMBS], bound: u64) -> Self {
        let mut rows = [simd.u32_splat(0); LIMBS];
        for (row, limb) in rows.iter_mut().zip(limbs) {
            *row = simd.u32_splat(*limb);
        }
        Self {
            limbs: rows,
            bound: DebugCounter::new(bound),
            limb_bound: DebugCounter::new(1),
        }
    }

    /// Returns the limb rows, without any conversion. Lanes beyond `S::U32_LANES` are zero.
    #[inline(always)]
    fn to_rows(self, simd: S) -> [[u32; MAX_LANES]; LIMBS] {
        let mut rows = [[0; MAX_LANES]; LIMBS];
        for (row, limb) in rows.iter_mut().zip(self.limbs) {
            simd.u32_store(limb, row);
        }
        rows
    }

    /// Converts an integer `a` into this module's Montgomery form `a * 2^392`.
    #[inline(always)]
    fn to_lanes(self, simd: S) -> Self {
        self.mul(simd, Self::constant(simd, &TO_LANES, 1))
    }

    /// Returns `self + rhs`, without carrying.
    #[inline(always)]
    pub fn add(mut self, simd: S, rhs: Self) -> Self {
        self.bound.add(rhs.bound);
        self.bound.assert_le(LIMIT);
        self.limb_bound.add(rhs.limb_bound);
        self.limb_bound.assert_le(LIMB_LIMIT);
        for (limb, rhs) in self.limbs.iter_mut().zip(rhs.limbs) {
            *limb = simd.u32_add(*limb, rhs);
        }
        self
    }

    /// Returns `self + K * p - rhs`, which is `self - rhs`, without carrying.
    #[inline(always)]
    pub fn sub<const K: u64>(mut self, simd: S, rhs: Self) -> Self {
        rhs.limb_bound.assert_le(2);
        // The subtrahend must be below (K - 1) * p; see bias.
        self.bound.sub_with_bias(rhs.bound, K - 1);
        self.bound.add(DebugCounter::new(1));
        self.bound.assert_le(LIMIT);
        self.limb_bound.add(DebugCounter::new(3));
        self.limb_bound.assert_le(LIMB_LIMIT);
        let bias = const { bias(K) };
        for ((limb, rhs), bias) in self.limbs.iter_mut().zip(rhs.limbs).zip(bias) {
            *limb = simd.u32_sub(simd.u32_add(*limb, simd.u32_splat(bias)), rhs);
        }
        self
    }

    /// Returns `K * p - self`, which is `-self`, without carrying.
    #[inline(always)]
    pub fn neg<const K: u64>(mut self, simd: S) -> Self {
        self.limb_bound.assert_le(2);
        let mut bound = DebugCounter::new(1);
        bound.sub_with_bias(self.bound, K - 1);
        bound.assert_le(LIMIT);
        let bias = const { bias(K) };
        for (limb, bias) in self.limbs.iter_mut().zip(bias) {
            *limb = simd.u32_sub(simd.u32_splat(bias), *limb);
        }
        self.bound = bound;
        self.limb_bound = DebugCounter::new(3);
        self
    }

    /// Propagates carries so every limb is below `2^28`, without reducing modulo `p`.
    #[inline(always)]
    pub fn carry(mut self, simd: S) -> Self {
        let mask = simd.u32_splat(MASK);
        for i in 0..LIMBS - 1 {
            let carry = simd.u32_shr::<LIMB_BITS>(self.limbs[i]);
            self.limbs[i + 1] = simd.u32_add(self.limbs[i + 1], carry);
            self.limbs[i] = simd.u32_and(self.limbs[i], mask);
        }
        // The value is below 2^392, so the top limb is now below 2^28 as well.
        self.limb_bound = DebugCounter::new(1);
        self
    }

    /// Returns `self` as a multiplicand, given that its limb bound is at most `U`.
    ///
    /// Carries only when `U` exceeds [`SLACK`], so the decision is made at compile time.
    #[inline(always)]
    pub fn ready<const U: u64>(self, simd: S) -> Self {
        self.limb_bound.assert_le(U);
        if U > SLACK { self.carry(simd) } else { self }
    }

    /// Returns `self * rhs`.
    ///
    /// Runs as its own kernel, so formulas call one copy rather than inlining it at every use.
    #[inline(always)]
    pub fn mul(self, simd: S, rhs: Self) -> Self {
        /// The product as an operation, so that NEON multiplies by the limbs of `p` by vector lane.
        struct Multiply<S: Simd>(Unsat28<S>, Unsat28<S>);

        impl<S: Simd> Operation<S> for Multiply<S> {
            type Output = Unsat28<S>;

            #[inline(always)]
            fn portable(self, simd: S) -> Unsat28<S> {
                self.0.multiply(simd, self.1, Splat)
            }

            #[inline(always)]
            fn neon(self, simd: S) -> Unsat28<S>
            where
                S: Neon,
            {
                self.0.multiply(simd, self.1, Lanes::new(simd))
            }
        }

        simd.execute(Multiply(self, rhs))
    }

    /// Body of [`Self::mul`], inlined into the calling kernel.
    ///
    /// `modulus` multiplies quotient limbs by the limbs of `p`.
    #[inline(always)]
    fn multiply<M: Modulus<S>>(self, simd: S, rhs: Self, modulus: M) -> Self {
        self.limb_bound.assert_le(SLACK);
        rhs.limb_bound.assert_le(SLACK);
        let mut bound = self.bound;
        bound.mul(rhs.bound);
        bound.div_ceil(LIMIT);
        bound.add(DebugCounter::new(1));
        bound.assert_le(LIMIT);

        // Product scanning: column k sums a_i b_j and q_i p_j with i + j = k, so only one
        // column's accumulators are live. Each column is split into the 64-bit halves of the
        // widening multiplication, and SLACK bounds every column below 2^64.
        let (a, b) = (self.limbs, rhs.limbs);
        let mut q = [simd.u32_splat(0); LIMBS];
        let mut limbs = [simd.u32_splat(0); LIMBS];
        let mut carry = [simd.u64_splat(0); 2];
        // Each column is a separate inlined call with a constant index, so every loop unrolls.
        macro_rules! columns {
            ($($k:literal)*) => {$(
                Self::column(simd, $k, &a, &b, &mut q, &mut limbs, &mut carry, modulus);
            )*};
        }
        columns!(0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26);
        // The result is below 2^392, so the last carry is the top limb.
        limbs[LIMBS - 1] = simd.u64_narrow_pair(carry[0], carry[1]);
        Self {
            limbs,
            bound,
            limb_bound: DebugCounter::new(1),
        }
    }

    /// Returns the 64-bit products of half `h` of the lanes of `a` and `b`.
    #[inline(always)]
    fn widen(simd: S, h: usize, a: S::U32, b: S::U32) -> S::U64 {
        if h == 0 {
            simd.u32_widen_mul_first(a, b)
        } else {
            simd.u32_widen_mul_second(a, b)
        }
    }

    /// Accumulates and reduces column `k` of [`Self::mul`].
    #[inline(always)]
    #[allow(clippy::too_many_arguments)]
    fn column<M: Modulus<S>>(
        simd: S,
        k: usize,
        a: &[S::U32; LIMBS],
        b: &[S::U32; LIMBS],
        q: &mut [S::U32; LIMBS],
        limbs: &mut [S::U32; LIMBS],
        carry: &mut [S::U64; 2],
        modulus: M,
    ) {
        // Products and reduction terms share one accumulator per half: on NEON, separate
        // accumulators cost an addition and an unfused multiplication each and measured slower.
        // Index arithmetic wraps rather than checks: release builds enable overflow checks, which
        // change how the unrolled kernel compiles even though no check survives constant folding.
        let zero = simd.u64_splat(0);
        let mut column = *carry;
        for (h, column) in column.iter_mut().enumerate().take(Self::HALVES) {
            let mut products = zero;
            for (i, a) in a.iter().enumerate() {
                let j = k.wrapping_sub(i);
                if i <= k && j < LIMBS {
                    products = simd.u64_add(products, Self::widen(simd, h, *a, b[j]));
                }
            }
            for (i, q) in q.iter().enumerate().take(k.min(LIMBS)) {
                let j = k.wrapping_sub(i);
                if j < LIMBS {
                    products = simd.u64_add(products, modulus.widen(simd, h, *q, j));
                }
            }
            *column = simd.u64_add(products, *column);
        }
        if k < LIMBS {
            // Choose q_k below 2^28 to cancel the low 28 bits of this column, which only depend on
            // its low 32 bits, then carry the rest.
            let low = simd.u64_narrow_pair(column[0], column[1]);
            let multiplier = simd.u32_mul_lo(low, simd.u32_splat(INV));
            let multiplier = simd.u32_and(multiplier, simd.u32_splat(MASK));
            for (h, column) in column.iter_mut().enumerate().take(Self::HALVES) {
                *column = simd.u64_add(*column, modulus.widen(simd, h, multiplier, 0));
            }
            q[k] = multiplier;
        } else {
            let low = simd.u64_narrow_pair(column[0], column[1]);
            limbs[k.wrapping_sub(LIMBS)] = simd.u32_and(low, simd.u32_splat(MASK));
        }
        for (carry, column) in carry.iter_mut().zip(column).take(Self::HALVES) {
            *carry = simd.u64_shr::<LIMB_BITS>(column);
        }
    }

    /// Returns `self - k p` for the multiple `k` of `p` that the top limb covers, carried and
    /// with integer bound `2`.
    ///
    /// Requires integer bound at most [`LIMIT`], so the top limb `h` is below `2^28` and
    /// `k < LIMIT`, and any valid limbs. With `t` the top limb of `p`, `k` is at most
    /// `h / (t + 1)` and more than `h / (t + 1) - 2`. Since `t * 2^364 <= p < (t + 1) 2^364` and
    /// the lower limbs sum below `16 * 2^364`, the result is nonnegative and below
    /// `2^364 (16 + h / (t + 1)) + p (1 + h / 2^48)`, which is below `1.03 p`.
    #[inline(always)]
    fn fold(self, simd: S) -> Self {
        self.bound.assert_le(LIMIT);
        self.limb_bound.assert_le(LIMB_LIMIT);
        let zero = simd.u64_splat(0);
        let reciprocal = simd.u32_splat(FOLD_RECIPROCAL);
        let mut estimate = [zero; 2];
        for (h, estimate) in estimate.iter_mut().enumerate().take(Self::HALVES) {
            let product = Self::widen(simd, h, self.limbs[LIMBS - 1], reciprocal);
            *estimate = simd.u64_shr::<FOLD_SHIFT>(product);
        }
        let k = simd.u64_narrow_pair(estimate[0], estimate[1]);
        // Limb j of self - k p, plus the offset for j below the top and less 2^12 units of it
        // for j above the bottom, so the offsets cancel and every difference stays nonnegative.
        // Each takes the carry out of the one below, which leaves the top limb of the result.
        let one = simd.u32_splat(1);
        let mask = simd.u32_splat(MASK);
        let mut limbs = self.limbs;
        let mut previous = [zero; 2];
        for (j, limb) in limbs.iter_mut().enumerate() {
            // The top limb's offset is negative and wraps; its difference is the result's limb.
            let offset = if j + 1 < LIMBS { FOLD_OFFSET } else { 0 };
            let offset = offset.wrapping_sub(if j > 0 { FOLD_OFFSET >> LIMB_BITS } else { 0 });
            let offset = simd.u64_splat(offset);
            let p = simd.u32_splat(P[j]);
            let mut column = [zero; 2];
            for (h, (column, previous)) in column
                .iter_mut()
                .zip(&mut previous)
                .enumerate()
                .take(Self::HALVES)
            {
                let value = simd.u64_add(Self::widen(simd, h, *limb, one), offset);
                let difference = simd.u64_sub(value, Self::widen(simd, h, k, p));
                *column = simd.u64_add(difference, simd.u64_shr::<LIMB_BITS>(*previous));
                *previous = *column;
            }
            *limb = simd.u64_narrow_pair(column[0], column[1]);
            if j + 1 < LIMBS {
                *limb = simd.u32_and(*limb, mask);
            }
        }
        Self {
            limbs,
            bound: DebugCounter::new(2),
            limb_bound: DebugCounter::new(1),
        }
    }

    /// Returns `self - p` in lanes where `self >= p`, for a carried value below `2p`.
    #[inline(always)]
    fn subtract_modulus(self, simd: S) -> Self {
        self.limb_bound.assert_le(1);
        self.bound.assert_le(2);
        let mask = simd.u32_splat(MASK);
        let mut reduced = self.limbs;
        let mut borrow = simd.u32_splat(0);
        for (i, reduced) in reduced.iter_mut().enumerate() {
            let difference =
                simd.u32_sub(simd.u32_sub(self.limbs[i], simd.u32_splat(P[i])), borrow);
            *reduced = simd.u32_and(difference, mask);
            borrow = simd.u32_shr::<31>(difference);
        }
        // A final borrow means the lane was already below p.
        let keep = simd.u32_sub(simd.u32_splat(0), borrow);
        for (limb, original) in reduced.iter_mut().zip(self.limbs) {
            *limb = simd.u32_select(keep, original, *limb);
        }
        Self {
            limbs: reduced,
            bound: DebugCounter::new(1),
            limb_bound: self.limb_bound,
        }
    }
}

/// Multiplies quotient limbs by the limbs of `p` in [`Unsat28::mul`].
trait Modulus<S: Simd>: Copy {
    /// Returns the 64-bit products of half `h` of the lanes of `q` and limb `j` of `p`, split as
    /// [`Simd::u32_widen_mul_first`] and [`Simd::u32_widen_mul_second`].
    fn widen(self, simd: S, h: usize, q: S::U32, j: usize) -> S::U64;
}

/// Splats each limb of `p` across a vector.
#[derive(Clone, Copy)]
struct Splat;

impl<S: Simd> Modulus<S> for Splat {
    #[inline(always)]
    fn widen(self, simd: S, h: usize, q: S::U32, j: usize) -> S::U64 {
        Unsat28::<S>::widen(simd, h, q, simd.u32_splat(P[j]))
    }
}

/// The limbs of `p`, four per vector, multiplied by vector lane.
///
/// Four vectors hold every limb, which leaves registers for the factors and quotient limbs that
/// fourteen splats would spill. The vectors pass through [`black_box`] because the optimizer
/// otherwise folds each constant lane back into a splat.
#[derive(Clone, Copy)]
struct Lanes<S: Simd>([S::U32; 4]);

impl<S: Neon> Lanes<S> {
    #[inline(always)]
    fn new(simd: S) -> Self {
        let mut lanes = [simd.u32_splat(0); 4];
        for (lane, limbs) in lanes.iter_mut().zip(&P_LANES) {
            *lane = simd.u32_load(limbs);
        }
        Self(black_box(lanes))
    }
}

impl<S: Neon> Modulus<S> for Lanes<S> {
    #[inline(always)]
    fn widen(self, simd: S, h: usize, q: S::U32, j: usize) -> S::U64 {
        let limbs = self.0[j / 4];
        match (h, j % 4) {
            (0, 0) => simd.u32_widen_mul_first_lane::<0>(q, limbs),
            (0, 1) => simd.u32_widen_mul_first_lane::<1>(q, limbs),
            (0, 2) => simd.u32_widen_mul_first_lane::<2>(q, limbs),
            (0, _) => simd.u32_widen_mul_first_lane::<3>(q, limbs),
            (_, 0) => simd.u32_widen_mul_second_lane::<0>(q, limbs),
            (_, 1) => simd.u32_widen_mul_second_lane::<1>(q, limbs),
            (_, 2) => simd.u32_widen_mul_second_lane::<2>(q, limbs),
            (_, _) => simd.u32_widen_mul_second_lane::<3>(q, limbs),
        }
    }
}

impl<S: Simd> Field<S> for Unsat28<S> {
    const LANES: usize = S::U32_LANES;
    type Product = Self;
    const PRODUCTS: usize = 8;

    #[inline(always)]
    fn load(simd: S, elements: &[[u8; BYTES]], fill: &[u8; BYTES]) -> Self {
        Self::load(simd, elements, fill)
    }

    #[inline(always)]
    fn store(self, simd: S, elements: &mut [[u8; BYTES]]) {
        self.store(simd, elements);
    }

    type Raw = [u32; LIMBS];

    #[inline(always)]
    fn store_raw<const A: u64>(self, simd: S, lanes: &mut [[u32; LIMBS]]) {
        self.bound.assert_le(A);
        self.limb_bound.assert_le(1);
        let rows = self.to_rows(simd);
        for (lane, limbs) in lanes.iter_mut().enumerate().take(S::U32_LANES) {
            for (limb, row) in limbs.iter_mut().zip(&rows) {
                *limb = row[lane];
            }
        }
    }

    #[inline(always)]
    fn load_raw<const A: u64>(simd: S, lanes: &[&[u32; LIMBS]]) -> Self {
        const { assert!(A <= LIMIT) };
        debug_assert!(lanes.len() >= S::U32_LANES);
        let mut limbs = [simd.u32_splat(0); LIMBS];
        for (i, limb) in limbs.iter_mut().enumerate() {
            let mut row = [0; MAX_LANES];
            for (value, lane) in row.iter_mut().zip(lanes).take(S::U32_LANES) {
                *value = lane[i];
            }
            *limb = simd.u32_load(&row);
        }
        Self {
            limbs,
            bound: DebugCounter::new(A),
            limb_bound: DebugCounter::new(1),
        }
    }

    #[inline(always)]
    fn add(self, simd: S, rhs: Self) -> Self {
        self.add(simd, rhs)
    }

    #[inline(always)]
    fn sub<const K: u64>(self, simd: S, rhs: Self) -> Self {
        self.sub::<K>(simd, rhs)
    }

    #[inline(always)]
    fn neg<const K: u64>(self, simd: S) -> Self {
        self.neg::<K>(simd)
    }

    #[inline(always)]
    fn select(mut self, simd: S, rhs: Self, lanes: u64) -> Self {
        let lanes = black_box(lanes);
        let mut masks = [0u32; MAX_LANES];
        for (lane, mask) in masks.iter_mut().enumerate() {
            *mask = 0u32.wrapping_sub(((lanes >> lane) & 1) as u32);
        }
        let mask = simd.u32_load(&masks);
        for (limb, other) in self.limbs.iter_mut().zip(rhs.limbs) {
            *limb = simd.u32_select(mask, other, *limb);
        }
        self.bound.max(rhs.bound);
        self.limb_bound.max(rhs.limb_bound);
        self
    }

    #[inline(always)]
    fn carry(self, simd: S) -> Self {
        self.carry(simd)
    }

    #[inline(always)]
    fn ready<const U: u64>(self, simd: S) -> Self {
        self.ready::<U>(simd)
    }

    #[inline(always)]
    fn product(self, simd: S, rhs: Self) -> Self::Product {
        self.mul(simd, rhs)
    }

    #[inline(always)]
    fn accumulate(simd: S, a: Self::Product, b: Self::Product) -> Self::Product {
        a.add(simd, b)
    }

    #[inline(always)]
    fn product_sub<const K: u64>(simd: S, a: Self::Product, b: Self::Product) -> Self::Product {
        // The subtrahend must be below Kp; carrying covers limb borrows.
        a.sub::<K>(simd, b.carry(simd))
    }

    #[inline(always)]
    fn lift(self, _simd: S) -> Self::Product {
        self
    }

    #[inline(always)]
    fn reduce(simd: S, product: Self::Product) -> Self {
        product.carry(simd)
    }

    #[inline(always)]
    fn carry_product(simd: S, product: Self::Product) -> Self::Product {
        product.carry(simd)
    }

    /// Folds the multiple of `p` that the top limb covers, carrying as it goes.
    #[inline(always)]
    fn reduce_tight(simd: S, product: Self::Product) -> Self {
        product.fold(simd)
    }
}

/// Checks of [`Unsat28`] values with any bounds against the reference arithmetic.
#[cfg(any(test, feature = "fuzz"))]
pub mod fuzz {
    use super::{
        super::{
            reference::Element,
            testing::{self, Family, Formulas, Positional},
        },
        *,
    };
    use arbitrary::{Arbitrary, Unstructured};

    impl<S: Simd> Positional<S> for Unsat28<S> {
        const LIMIT: u64 = LIMIT;
        const SLACK: u64 = SLACK;
        const LIMB_LIMIT: u64 = LIMB_LIMIT;

        fn lifted(element: Element, bound: u64) -> [u32; LIMBS] {
            narrow(testing::lift::<LIMBS, LIMB_BITS>(element, bound))
        }

        fn from_raw(simd: S, lanes: &[[u32; LIMBS]], bound: u64) -> Self {
            let mut all = [[0; LIMBS]; MAX_LANES];
            for (lane, limbs) in all.iter_mut().zip(lanes) {
                *lane = *limbs;
            }
            Self::raw(simd, &all, bound)
        }

        fn widest(bound: u64) -> Element {
            testing::widest::<LIMBS, LIMB_BITS>(bound)
        }

        fn is_tight(raw: &[u32; LIMBS]) -> bool {
            testing::is_tight::<LIMBS, LIMB_BITS>(raw.map(u64::from))
        }
    }

    /// Selects [`Unsat28`] on every backend.
    struct Representation;

    impl Family for Representation {
        type Value<S: Simd> = Unsat28<S>;
    }

    /// A formula over [`Unsat28`] values lifted to bounds drawn from the input, with distinct
    /// elements in every lane, on an emulated backend drawn from the input.
    #[derive(Clone, Copy, Debug, Arbitrary)]
    pub enum Plan {
        /// Checks additions, subtractions and negations with every bias, doublings, and stores, up
        /// to the integer limit.
        Linear,
        /// Checks products of values up to the integer limit, of sums of [`SLACK`] values, of
        /// values readied from static limb bounds, and of doublings carried at the limb limit.
        Products,
        /// Checks that tight reductions of sums up to the limb limit fold to carried values below
        /// `2p`.
        Tight,
    }

    impl Plan {
        /// Runs the operation using the remaining input.
        pub fn run(self, u: &mut Unstructured<'_>) -> arbitrary::Result<()> {
            let formulas = match self {
                Self::Linear => Formulas::Linear,
                Self::Products => Formulas::Products,
                Self::Tight => Formulas::Tight,
            };
            testing::run_formulas::<Representation>(formulas, u)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::{
            super::super::{power_of_two, reference},
            *,
        };
        use commonware_invariants::minifuzz;
        use commonware_simd::{
            Operation, check_consistent, emulated::EmulatedScalar, test_dispatch,
        };
        use std::vec::Vec;

        #[test]
        fn minifuzz_linear() {
            minifuzz::test(|u| Plan::Linear.run(u));
        }

        #[test]
        fn minifuzz_products() {
            minifuzz::test(|u| Plan::Products.run(u));
        }

        #[test]
        fn minifuzz_tight() {
            minifuzz::test(|u| Plan::Tight.run(u));
        }

        #[test]
        fn rejects_values_beyond_the_limits() {
            testing::check_limits::<_, Unsat28<_>>(EmulatedScalar);
        }

        /// Returns the elements of every lane lifted to integer bound `bound` with the widest
        /// carried limbs below it.
        fn widest<S: Simd>(simd: S, bound: u64) -> Unsat28<S> {
            let element = <Unsat28<S> as Positional<S>>::widest(bound);
            testing::loose(simd, &[element; MAX_LANES], bound)
        }

        #[test]
        fn widest_columns_fit_the_lanes() {
            /// Multiplies sums of `SLACK` values with the widest carried limbs, so that product
            /// columns reach their largest sums.
            struct Widest;

            impl<S: Simd> Operation<S> for Widest {
                type Output = [u8; BYTES];

                fn portable(self, simd: S) -> [u8; BYTES] {
                    let sum = |bound| {
                        let value = widest(simd, bound);
                        (1..SLACK).fold(value, |sum, _| sum.add(simd, value))
                    };
                    let mut output = [[0; BYTES]; MAX_LANES];
                    sum(LIMIT / SLACK)
                        .mul(simd, sum((LIMIT - 1) / SLACK))
                        .store(simd, &mut output);
                    output[0]
                }
            }

            let times = |bound| {
                let element = testing::widest::<LIMBS, LIMB_BITS>(bound);
                reference::mul(element, [SLACK, 0, 0, 0, 0, 0])
            };
            let expected = reference::mul(times(LIMIT / SLACK), times((LIMIT - 1) / SLACK));
            assert_eq!(test_dispatch(Widest), reference::to_bytes(expected));
            check_consistent(|| Widest);
        }

        /// Returns the largest top limb below `(LIMIT - 1) p`, with zero low limbs, and the
        /// element it represents. A multiple estimated from the top limb of `p` alone exceeds
        /// the value it covers.
        fn largest_top() -> ([u32; LIMBS], Element) {
            let top = super::super::super::multiple::<LIMBS, LIMB_BITS>(LIMIT - 1)[LIMBS - 1] - 1;
            let mut limbs = [0; LIMBS];
            limbs[LIMBS - 1] = top as u32;
            let shift = LIMB_BITS * (LIMBS as u32 - 1);
            let value = reference::mul([top, 0, 0, 0, 0, 0], power_of_two(shift));
            (limbs, testing::from_montgomery(value))
        }

        #[test]
        fn tight_reductions_fold_below_twice_the_modulus() {
            /// Tightly reduces values at the integer limit, carried with the widest low limbs or
            /// summed up to the limb limit, and a value just below a multiple of `p` with zero
            /// low limbs. Checks that every result is carried and below `2p`.
            struct Fold;

            impl<S: Simd> Operation<S> for Fold {
                type Output = Vec<[u8; BYTES]>;

                fn portable(self, simd: S) -> Vec<[u8; BYTES]> {
                    let mut outputs = Vec::new();
                    let mut fold = |value: Unsat28<S>| {
                        let folded = <Unsat28<S> as Field<S>>::reduce_tight(simd, value);
                        let mut raw = [[0; LIMBS]; MAX_LANES];
                        folded.store_raw::<2>(simd, &mut raw);
                        for raw in &raw[..S::U32_LANES] {
                            assert!(<Unsat28<S> as Positional<S>>::is_tight(raw));
                        }
                        let mut output = [[0; BYTES]];
                        folded.store(simd, &mut output);
                        outputs.push(output[0]);
                    };
                    fold(widest(simd, LIMIT));
                    let value = widest(simd, LIMIT / LIMB_LIMIT);
                    fold((1..LIMB_LIMIT).fold(value, |sum, _| sum.add(simd, value)));
                    let limbs = largest_top().0;
                    fold(Unsat28::raw(simd, &[limbs; MAX_LANES], LIMIT - 1));
                    outputs
                }
            }

            let sum = reference::mul(
                testing::widest::<LIMBS, LIMB_BITS>(LIMIT / LIMB_LIMIT),
                [LIMB_LIMIT, 0, 0, 0, 0, 0],
            );
            let expected = [
                testing::widest::<LIMBS, LIMB_BITS>(LIMIT),
                sum,
                largest_top().1,
            ]
            .map(reference::to_bytes);
            assert_eq!(test_dispatch(Fold), expected);
            check_consistent(|| Fold);
        }
    }
}
