//! Unsaturated radix-`2^49` Montgomery arithmetic on several base field elements at once, using
//! 64-bit lane values.
//!
//! An [`Unsat49`] is a matrix with [`LIMBS`] rows and `S::U64_LANES` columns: row `i` holds limb
//! `i` of every element. Elements use radix `2^49` in Montgomery form with `R = 2^392`. Products
//! accumulate with `u64_madd52lo` and `u64_madd52hi`, which AVX-512 IFMA provides natively and
//! other backends emulate. They split each product at bit 52, so each column of high halves is
//! shifted left by three bits before joining its column.
//!
//! # Usage
//!
//! Elements cross the boundary as [`BYTES`]-byte big-endian integers below `2^384`, which loads
//! interpret modulo `p` and stores return canonically.
//!
//! Loads, splats, products, and [`Unsat49::carry`] return carried values, whose limbs are below
//! `2^49`; additions, subtractions, negations, and doublings return uncarried ones. A
//! multiplication accepts limbs below `2^52`, so it multiplies sums of up to [`SLACK`] carried
//! values without carrying them. [`Unsat49::ready`] prepares a multiplicand from a static bound on
//! its limbs, carrying only when that bound exceeds [`SLACK`]. A subtraction or negation removes
//! values whose limbs are at most twice those of a carried value.
//!
//! Carrying preserves the represented integer; multiplication is what reduces modulo `p`, and
//! [`Unsat49::store`] returns canonical elements from any value. A subtraction or negation bias
//! `K` must exceed the bound of the value it removes.
//!
//! # Bounds
//!
//! Each value carries two debug-only bound counters: an integer bound in units of `p`, and a
//! limb bound in units of `2^49`. For integer bounds `A` and `B` and limb bounds `L` and `M`:
//!
//! | Operation | Requires | Integer bound | Limb bound |
//! |---|---|---|---|
//! | load, splat | | `2` | `1` |
//! | `a + b` | | `A + B` | `L + M` |
//! | `a - b` with bias `K` | `M <= 2`, `B < K` | `A + K` | `L + 3` |
//! | `-a` with bias `K` | `L <= 2`, `A < K` | `K` | `3` |
//! | carry | | `A` | `1` |
//! | `a * b` | `L, M <= SLACK` | `ceil(A * B / LIMIT) + 1` | `1` |
//!
//! Every integer bound is at most [`LIMIT`], so values fit carried limbs because `p < 2^381`.
//! Every limb bound is below `2^15`, so carries fit the 64-bit lanes. Multiplication returns below
//! `a * b / 2^392 + p`, and `p / 2^392 < 1 / LIMIT`. Debug builds check these rules; release
//! builds do not, and results are unspecified when a formula violates them.

use super::{
    super::arithmetic::Field, BYTES, MAX_LANES, MODULUS, WORDS, bytes_from_words, power_of_two,
    words_from_bytes,
};
use crate::{core::debug_counter::DebugCounter, montgomery::negated_inverse};
use commonware_simd::Simd;
use core::hint::black_box;

/// Number of limbs in a field element.
pub const LIMBS: usize = 8;

/// Bits per carried limb.
const LIMB_BITS: u32 = 49;

/// The low [`LIMB_BITS`] bits of a limb.
const MASK: u64 = (1 << LIMB_BITS) - 1;

/// Largest integer bound of any value, in units of `p`.
///
/// Because `p < 2^381`, `LIMIT * p < 2^392` and `p / 2^392 < 1 / LIMIT`.
pub const LIMIT: u64 = {
    assert!(MODULUS[WORDS - 1] < 1 << 61);
    1 << (8 * LIMB_BITS - 381)
};

/// Largest limb bound of a multiplicand, in units of `2^49`: the 52-bit multipliers accept limbs
/// below `2^52`.
pub const SLACK: u64 = 1 << (52 - LIMB_BITS);

/// Largest limb bound of any value, in units of `2^49`, so that carries fit the lanes.
const LIMB_LIMIT: u64 = (1 << (64 - LIMB_BITS)) - 1;

/// The modulus `p` in limbs.
const P: [u64; LIMBS] = limbs_from_words(MODULUS);

/// `-p^(-1) mod 2^49`, the Montgomery reduction constant.
const INV: u64 = negated_inverse(MODULUS[0]) & MASK;

/// `R^2 mod p` for `R = 2^392`. A Montgomery multiplication by it maps `a` to `a * R`.
const TO_LANES: [u64; LIMBS] = limbs_from_words(power_of_two(2 * 8 * LIMB_BITS));

/// `R mod p`, one in Montgomery form. A Montgomery multiplication by it preserves the value.
const ONE: [u64; LIMBS] = limbs_from_words(power_of_two(8 * LIMB_BITS));

/// One. A Montgomery multiplication by it maps `a * R` back to `a`.
const FROM_LANES: [u64; LIMBS] = {
    let mut limbs = [0; LIMBS];
    limbs[0] = 1;
    limbs
};

/// Splits a little-endian 64-bit integer below `2^384` into 49-bit limbs.
const fn limbs_from_words(words: [u64; WORDS]) -> [u64; LIMBS] {
    super::limbs_from_words::<LIMBS, LIMB_BITS>(words)
}

/// Joins carried 49-bit limbs of a value below `2^384` into little-endian 64-bit words.
const fn words_from_limbs(limbs: [u64; LIMBS]) -> [u64; WORDS] {
    super::words_from_limbs::<LIMBS, LIMB_BITS>(limbs)
}

/// Returns `k * p` with twice `2^49` moved from each limb into the one below it, so that it can
/// absorb the subtraction of a value below `(k - 1) * p` whose limbs are at most twice those of a
/// carried value.
const fn bias(k: u64) -> [u64; LIMBS] {
    super::bias::<LIMBS, LIMB_BITS>(k)
}

/// `S::U64_LANES` base field elements in radix `2^49` Montgomery form, one per lane.
///
/// See the [module documentation](self) for the layout and the bounds every value satisfies.
pub struct Unsat49<S: Simd> {
    limbs: [S::U64; LIMBS],
    bound: DebugCounter,
    limb_bound: DebugCounter,
}

impl<S: Simd> Clone for Unsat49<S> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<S: Simd> Copy for Unsat49<S> {}

impl<S: Simd> Unsat49<S> {
    /// Loads up to `S::U64_LANES` elements, one per lane, filling the remaining lanes with `fill`.
    #[inline(always)]
    pub fn load(simd: S, elements: &[[u8; BYTES]], fill: &[u8; BYTES]) -> Self {
        let mut lanes = [limbs_from_words(words_from_bytes(fill)); MAX_LANES];
        for (lane, element) in lanes.iter_mut().zip(elements) {
            *lane = limbs_from_words(words_from_bytes(element));
        }
        // Integers below 2^384 are below 10p.
        Self::raw(simd, &lanes, 10).to_lanes(simd)
    }

    /// Stores the canonical value of each lane into `elements`, dropping lanes beyond its length.
    #[inline(always)]
    pub fn store(self, simd: S, elements: &mut [[u8; BYTES]]) {
        let canonical = self
            .carry(simd)
            .mul(simd, Self::raw(simd, &[FROM_LANES; MAX_LANES], 1))
            .subtract_modulus(simd);
        let lanes = canonical.lane_limbs(simd);
        for (element, limbs) in elements.iter_mut().zip(lanes).take(S::U64_LANES) {
            *element = bytes_from_words(&words_from_limbs(limbs));
        }
    }

    /// Transposes carried per-lane limbs, bounded by `bound * p`, into limb rows.
    #[inline(always)]
    fn raw(simd: S, lanes: &[[u64; LIMBS]; MAX_LANES], bound: u64) -> Self {
        const { assert!(S::U64_LANES <= MAX_LANES) };
        let mut rows = [[0; MAX_LANES]; LIMBS];
        for (lane, limbs) in lanes.iter().enumerate() {
            for (row, limb) in rows.iter_mut().zip(limbs) {
                row[lane] = *limb;
            }
        }
        let mut limbs = [simd.u64_splat(0); LIMBS];
        for (limb, row) in limbs.iter_mut().zip(&rows) {
            *limb = simd.u64_load(row);
        }
        Self {
            limbs,
            bound: DebugCounter::new(bound),
            limb_bound: DebugCounter::new(1),
        }
    }

    /// Returns each lane's limbs, without any conversion.
    #[inline(always)]
    fn lane_limbs(self, simd: S) -> [[u64; LIMBS]; MAX_LANES] {
        let mut lanes = [[0; LIMBS]; MAX_LANES];
        for (i, row) in self.limbs.into_iter().enumerate() {
            let mut values = [0; MAX_LANES];
            simd.u64_store(row, &mut values);
            for (lane, value) in lanes.iter_mut().zip(values) {
                lane[i] = value;
            }
        }
        lanes
    }

    /// Converts an integer `a` into this module's Montgomery form `a * 2^392`.
    #[inline(always)]
    fn to_lanes(self, simd: S) -> Self {
        self.mul(simd, Self::raw(simd, &[TO_LANES; MAX_LANES], 1))
    }

    /// Returns `self + rhs`, without carrying.
    #[inline(always)]
    pub fn add(mut self, simd: S, rhs: Self) -> Self {
        self.bound.add(rhs.bound);
        self.bound.assert_le(LIMIT);
        self.limb_bound.add(rhs.limb_bound);
        self.limb_bound.assert_le(LIMB_LIMIT);
        for (limb, rhs) in self.limbs.iter_mut().zip(rhs.limbs) {
            *limb = simd.u64_add(*limb, rhs);
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
            *limb = simd.u64_sub(simd.u64_add(*limb, simd.u64_splat(bias)), rhs);
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
            *limb = simd.u64_sub(simd.u64_splat(bias), *limb);
        }
        self.bound = bound;
        self.limb_bound = DebugCounter::new(3);
        self
    }

    /// Propagates carries so every limb is below `2^49`, without reducing modulo `p`.
    #[inline(always)]
    pub fn carry(mut self, simd: S) -> Self {
        let mask = simd.u64_splat(MASK);
        for i in 0..LIMBS - 1 {
            let carry = simd.u64_shr::<LIMB_BITS>(self.limbs[i]);
            self.limbs[i + 1] = simd.u64_add(self.limbs[i + 1], carry);
            self.limbs[i] = simd.u64_and(self.limbs[i], mask);
        }
        // The value is below 2^392, so the top limb is now below 2^49 as well.
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
        simd.execute(
            #[inline(always)]
            move |simd: S| self.multiply(simd, rhs),
        )
    }

    /// Body of [`Self::mul`], inlined into the calling kernel.
    #[inline(always)]
    fn multiply(self, simd: S, rhs: Self) -> Self {
        self.limb_bound.assert_le(SLACK);
        rhs.limb_bound.assert_le(SLACK);
        let mut bound = self.bound;
        bound.mul(rhs.bound);
        bound.div_ceil(LIMIT);
        bound.add(DebugCounter::new(1));
        bound.assert_le(LIMIT);

        // Product scanning: column k sums the low halves of a_i b_j and q_i p_j with i + j = k
        // and the high halves with i + j = k - 1, so only one column's accumulators are live.
        // High halves have weight 2^52 = 2^3 * 2^49, so they are shifted once per column. A
        // column receives at most 32 terms below 2^52 plus a carry, so nothing overflows.
        let (a, b) = (self.limbs, rhs.limbs);
        let zero = simd.u64_splat(0);
        let mut q = [zero; LIMBS];
        let mut limbs = [zero; LIMBS];
        let mut carry = zero;
        // Each column is a separate inlined call with a constant index, so every loop unrolls.
        macro_rules! columns {
            ($($k:literal)*) => {$(
                Self::column(simd, $k, &a, &b, &mut q, &mut limbs, &mut carry);
            )*};
        }
        columns!(0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15);
        Self {
            limbs,
            bound,
            limb_bound: DebugCounter::new(1),
        }
    }

    /// Accumulates and reduces column `k` of [`Self::mul`].
    #[inline(always)]
    #[allow(clippy::too_many_arguments)]
    fn column(
        simd: S,
        k: usize,
        a: &[S::U64; LIMBS],
        b: &[S::U64; LIMBS],
        q: &mut [S::U64; LIMBS],
        limbs: &mut [S::U64; LIMBS],
        carry: &mut S::U64,
    ) {
        let zero = simd.u64_splat(0);
        let mut low = zero;
        let mut high = zero;
        for i in 0..LIMBS {
            if i <= k && k - i < LIMBS {
                low = simd.u64_madd52lo(low, a[i], b[k - i]);
            }
            if i < k && k - 1 - i < LIMBS {
                high = simd.u64_madd52hi(high, a[i], b[k - 1 - i]);
            }
        }
        for (i, q) in q.iter().enumerate().take(k.min(LIMBS)) {
            if k - i < LIMBS {
                let modulus = simd.u64_splat(P[k - i]);
                low = simd.u64_madd52lo(low, *q, modulus);
            }
            if k - 1 - i < LIMBS {
                let modulus = simd.u64_splat(P[k - 1 - i]);
                high = simd.u64_madd52hi(high, *q, modulus);
            }
        }
        let column = simd.u64_add(low, *carry);
        let mut column = simd.u64_add(column, simd.u64_shl::<3>(high));
        if k < LIMBS {
            // Choose q_k below 2^49 to cancel the low 49 bits of this column, then carry the
            // rest.
            let multiplier = simd.u64_madd52lo(zero, column, simd.u64_splat(INV));
            let multiplier = simd.u64_and(multiplier, simd.u64_splat(MASK));
            column = simd.u64_madd52lo(column, multiplier, simd.u64_splat(P[0]));
            q[k] = multiplier;
            *carry = simd.u64_shr::<LIMB_BITS>(column);
        } else if k < 2 * LIMBS - 1 {
            limbs[k - LIMBS] = simd.u64_and(column, simd.u64_splat(MASK));
            *carry = simd.u64_shr::<LIMB_BITS>(column);
        } else {
            // The result is below 2^392, so the top column needs no carry.
            limbs[LIMBS - 1] = column;
        }
    }

    /// Returns `self - p` in lanes where `self >= p`, for a carried value below `2p`.
    #[inline(always)]
    fn subtract_modulus(self, simd: S) -> Self {
        self.limb_bound.assert_le(1);
        self.bound.assert_le(2);
        let mask = simd.u64_splat(MASK);
        let mut reduced = self.limbs;
        let mut borrow = simd.u64_splat(0);
        for (i, reduced) in reduced.iter_mut().enumerate() {
            let difference =
                simd.u64_sub(simd.u64_sub(self.limbs[i], simd.u64_splat(P[i])), borrow);
            *reduced = simd.u64_and(difference, mask);
            borrow = simd.u64_shr::<63>(difference);
        }
        // A final borrow means the lane was already below p.
        let keep = simd.u64_sub(simd.u64_splat(0), borrow);
        for (limb, reduced) in reduced.iter_mut().zip(self.limbs) {
            *limb = simd.u64_select(keep, reduced, *limb);
        }
        Self {
            limbs: reduced,
            bound: DebugCounter::new(1),
            limb_bound: self.limb_bound,
        }
    }
}

impl<S: Simd> Field<S> for Unsat49<S> {
    const LANES: usize = S::U64_LANES;
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

    type Raw = [u64; LIMBS];

    #[inline(always)]
    fn store_raw<const A: u64>(self, simd: S, lanes: &mut [[u64; LIMBS]]) {
        self.bound.assert_le(A);
        self.limb_bound.assert_le(1);
        for (lane, limbs) in lanes
            .iter_mut()
            .zip(self.lane_limbs(simd))
            .take(S::U64_LANES)
        {
            *lane = limbs;
        }
    }

    #[inline(always)]
    fn load_raw<const A: u64>(simd: S, lanes: &[&[u64; LIMBS]]) -> Self {
        const { assert!(A <= LIMIT) };
        debug_assert!(lanes.len() >= S::U64_LANES);
        let mut limbs = [simd.u64_splat(0); LIMBS];
        for (i, limb) in limbs.iter_mut().enumerate() {
            let mut row = [0; MAX_LANES];
            for (value, lane) in row.iter_mut().zip(lanes).take(S::U64_LANES) {
                *value = lane[i];
            }
            *limb = simd.u64_load(&row);
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
        let mut masks = [0u64; MAX_LANES];
        for (lane, mask) in masks.iter_mut().enumerate() {
            *mask = 0u64.wrapping_sub((lanes >> lane) & 1);
        }
        let mask = simd.u64_load(&masks);
        for (limb, other) in self.limbs.iter_mut().zip(rhs.limbs) {
            *limb = simd.u64_select(mask, other, *limb);
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

    /// Carries, then multiplies by one in Montgomery form, which is below `p`.
    #[inline(always)]
    fn reduce_tight(simd: S, product: Self::Product) -> Self {
        product
            .carry(simd)
            .mul(simd, Self::raw(simd, &[ONE; MAX_LANES], 1))
    }
}

/// Checks of [`Unsat49`] values with any bounds against the reference arithmetic.
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

    impl<S: Simd> Positional<S> for Unsat49<S> {
        const LIMIT: u64 = LIMIT;
        const SLACK: u64 = SLACK;
        const LIMB_LIMIT: u64 = LIMB_LIMIT;

        fn lifted(element: Element, bound: u64) -> [u64; LIMBS] {
            testing::lift::<LIMBS, LIMB_BITS>(element, bound)
        }

        fn from_raw(simd: S, lanes: &[[u64; LIMBS]], bound: u64) -> Self {
            let mut all = [[0; LIMBS]; MAX_LANES];
            for (lane, limbs) in all.iter_mut().zip(lanes) {
                *lane = *limbs;
            }
            Self::raw(simd, &all, bound)
        }

        fn widest(bound: u64) -> Element {
            testing::widest::<LIMBS, LIMB_BITS>(bound)
        }

        fn is_tight(raw: &[u64; LIMBS]) -> bool {
            testing::is_tight::<LIMBS, LIMB_BITS>(*raw)
        }
    }

    /// Selects [`Unsat49`] on every backend.
    struct Representation;

    impl Family for Representation {
        type Value<S: Simd> = Unsat49<S>;
    }

    /// A formula over [`Unsat49`] values lifted to bounds drawn from the input, with distinct
    /// elements in every lane, on an emulated backend drawn from the input.
    #[derive(Clone, Copy, Debug, Arbitrary)]
    pub enum Plan {
        /// Checks additions, subtractions and negations with every bias, doublings, and stores, up
        /// to the integer limit.
        Linear,
        /// Checks products of values up to the integer limit, of sums of [`SLACK`] values, of
        /// values readied from static limb bounds, and of repeated doublings.
        Products,
        /// Checks that tight reductions of sums return carried values below `2p`.
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
        use super::*;
        use commonware_invariants::minifuzz;
        use commonware_simd::emulated::EmulatedScalar;

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
            testing::check_limits::<_, Unsat49<_>>(EmulatedScalar);
        }
    }
}
