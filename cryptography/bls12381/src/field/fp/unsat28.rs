//! Unsaturated radix-`2^28` Montgomery arithmetic on several base field elements at once, using
//! 32-bit lane values.
//!
//! An [`Unsat28`] is a matrix with [`LIMBS`] rows and `S::U64_LANES` columns: row `i` holds limb
//! `i` of every element. Elements use radix `2^28` in Montgomery form with `R = 2^392`. Products
//! use `u64_mul32`, which multiplies the low 32 bits of two lanes into a 64-bit product: VPMULUDQ
//! on AVX-512 and UMULL on NEON. Limbs occupy 64-bit lanes so that a column of products can be
//! summed in place.
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
//! values whose limbs are at most twice those of a carried value.
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
//!
//! Every integer bound is at most [`LIMIT`], so values fit carried limbs because `p < 2^381`.
//! Every limb bound is at most `2^35`, so limbs stay below `2^63` and a carried-in value below
//! `2^36` still fits the 64-bit lanes. Multiplication returns below `a * b / 2^392 + p`, and
//! `p / 2^392 < 1 / LIMIT`. Debug builds check these rules; release builds do not, and results
//! are unspecified when a formula violates them.

use super::{BYTES, MAX_LANES, MODULUS, WORDS, bytes_from_words, power_of_two, words_from_bytes};
use crate::{debug_counter::DebugCounter, montgomery::negated_inverse};
use commonware_simd::Simd;

/// Number of limbs in a field element.
pub const LIMBS: usize = 14;

/// Bits per carried limb.
const LIMB_BITS: u32 = 28;

/// The low [`LIMB_BITS`] bits of a limb.
const MASK: u64 = (1 << LIMB_BITS) - 1;

/// Largest integer bound of any value, in units of `p`.
///
/// Because `p < 2^381`, `LIMIT * p < 2^392` and `p / 2^392 < 1 / LIMIT`.
pub const LIMIT: u64 = {
    assert!(MODULUS[WORDS - 1] < 1 << 61);
    1 << (LIMBS as u32 * LIMB_BITS - 381)
};

/// Largest limb bound of a multiplicand, in units of `2^28`.
///
/// Multiplicand limbs below `SLACK * 2^28 = 2^30` fit the 32-bit multiplier. The multiplier would
/// accept wider limbs, but a product column must stay below `2^64`: it sums at most [`LIMBS`]
/// products of multiplicand limbs, [`LIMBS`] reduction products of 28-bit factors, and a carry
/// below `2^36`.
pub const SLACK: u64 = {
    let slack: u64 = 4;
    assert!(slack << LIMB_BITS <= 1 << 32);
    let products = (slack * slack + 1) as u128 * LIMBS as u128;
    assert!((products << (2 * LIMB_BITS)) + (1 << (64 - LIMB_BITS)) <= u64::MAX as u128);
    slack
};

/// Largest limb bound of any value, in units of `2^28`.
///
/// Limbs stay below `2^63`, so each still fits the 64-bit lanes after receiving a carry, which is
/// below `2^36`.
const LIMB_LIMIT: u64 = 1 << (63 - LIMB_BITS);

/// The modulus `p` in limbs.
const P: [u64; LIMBS] = limbs_from_words(MODULUS);

/// `-p^(-1) mod 2^28`, the Montgomery reduction constant.
const INV: u64 = negated_inverse(MODULUS[0]) & MASK;

/// `R^2 mod p` for `R = 2^392`. A Montgomery multiplication by it maps `a` to `a * R`.
const TO_LANES: [u64; LIMBS] = limbs_from_words(power_of_two(2 * LIMBS as u32 * LIMB_BITS));

/// One. A Montgomery multiplication by it maps `a * R` back to `a`.
const FROM_LANES: [u64; LIMBS] = {
    let mut limbs = [0; LIMBS];
    limbs[0] = 1;
    limbs
};

/// Splits a little-endian 64-bit integer below `2^384` into 28-bit limbs.
const fn limbs_from_words(words: [u64; WORDS]) -> [u64; LIMBS] {
    super::limbs_from_words::<LIMBS, LIMB_BITS>(words)
}

/// Joins carried 28-bit limbs of a value below `2^384` into little-endian 64-bit words.
const fn words_from_limbs(limbs: [u64; LIMBS]) -> [u64; WORDS] {
    super::words_from_limbs::<LIMBS, LIMB_BITS>(limbs)
}

/// Returns `k * p` with twice `2^28` moved from each limb into the one below it, so that it can
/// absorb the subtraction of a value below `(k - 1) * p` whose limbs are at most twice those of a
/// carried value.
const fn bias(k: u64) -> [u64; LIMBS] {
    super::bias::<LIMBS, LIMB_BITS>(k)
}

/// `S::U64_LANES` base field elements in radix `2^28` Montgomery form, one per lane.
///
/// See the [module documentation](self) for the layout and the bounds every value satisfies.
pub struct Unsat28<S: Simd> {
    limbs: [S::U64; LIMBS],
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
    /// Returns every lane set to `element`.
    #[inline(always)]
    pub fn splat(simd: S, element: &[u8; BYTES]) -> Self {
        let limbs = limbs_from_words(words_from_bytes(element));
        Self::raw(simd, &[limbs; MAX_LANES], 10).to_lanes(simd)
    }

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
        let lanes = canonical.store_raw(simd);
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
    fn store_raw(self, simd: S) -> [[u64; LIMBS]; MAX_LANES] {
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

    /// Loads per-lane limbs in this module's representation, bounded by `bound * p`.
    ///
    /// The limbs must be carried, as returned by [`Self::to_limbs`] after [`Self::carry`].
    #[inline(always)]
    pub fn from_limbs(simd: S, lanes: &[[u64; LIMBS]; MAX_LANES], bound: u64) -> Self {
        Self::raw(simd, lanes, bound)
    }

    /// Returns each lane's carried limbs in this module's representation, without any
    /// conversion, for a value bounded by `bound * p`.
    #[inline(always)]
    pub fn to_limbs(self, simd: S, bound: u64) -> [[u64; LIMBS]; MAX_LANES] {
        self.limb_bound.assert_le(1);
        self.bound.assert_le(bound);
        self.store_raw(simd)
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

    /// Returns `2 * self`, without carrying.
    #[inline(always)]
    pub fn double(self, simd: S) -> Self {
        self.add(simd, self)
    }

    /// Propagates carries so every limb is below `2^28`, without reducing modulo `p`.
    #[inline(always)]
    pub fn carry(mut self, simd: S) -> Self {
        let mask = simd.u64_splat(MASK);
        for i in 0..LIMBS - 1 {
            let carry = simd.u64_shr::<LIMB_BITS>(self.limbs[i]);
            self.limbs[i + 1] = simd.u64_add(self.limbs[i + 1], carry);
            self.limbs[i] = simd.u64_and(self.limbs[i], mask);
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
    /// Debug builds keep this a call so that deeply inlined formulas fit in a stack frame.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn mul(self, simd: S, rhs: Self) -> Self {
        self.limb_bound.assert_le(SLACK);
        rhs.limb_bound.assert_le(SLACK);
        let mut bound = self.bound;
        bound.mul(rhs.bound);
        bound.div_ceil(LIMIT);
        bound.add(DebugCounter::new(1));
        bound.assert_le(LIMIT);

        // Product scanning: column k sums a_i b_j and q_i p_j with i + j = k, so only one
        // column's accumulators are live. SLACK bounds every column below 2^64.
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
        columns!(0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26);
        // The result is below 2^392, so the last carry is the top limb.
        limbs[LIMBS - 1] = carry;
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
        // Products and reduction terms accumulate separately, so the two chains of additions can
        // proceed in parallel.
        let zero = simd.u64_splat(0);
        let mut products = zero;
        for i in 0..LIMBS {
            if i <= k && k - i < LIMBS {
                products = simd.u64_add(products, simd.u64_mul32(a[i], b[k - i]));
            }
        }
        let mut reduction = zero;
        for (i, q) in q.iter().enumerate().take(k.min(LIMBS)) {
            if k - i < LIMBS {
                let modulus = simd.u64_splat(P[k - i]);
                reduction = simd.u64_add(reduction, simd.u64_mul32(*q, modulus));
            }
        }
        let mut column = simd.u64_add(simd.u64_add(products, reduction), *carry);
        if k < LIMBS {
            // Choose q_k below 2^28 to cancel the low 28 bits of this column, then carry the
            // rest.
            let multiplier = simd.u64_mul32(column, simd.u64_splat(INV));
            let multiplier = simd.u64_and(multiplier, simd.u64_splat(MASK));
            column = simd.u64_add(column, simd.u64_mul32(multiplier, simd.u64_splat(P[0])));
            q[k] = multiplier;
        } else {
            limbs[k - LIMBS] = simd.u64_and(column, simd.u64_splat(MASK));
        }
        *carry = simd.u64_shr::<LIMB_BITS>(column);
    }

    /// Returns `self * self`.
    #[inline(always)]
    pub fn square(self, simd: S) -> Self {
        self.mul(simd, self)
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

#[cfg(test)]
mod tests {
    use super::{super::tests as reference, *};
    use arbitrary::Unstructured;
    use commonware_invariants::minifuzz;
    use commonware_simd::{Operation, check_consistent, emulated::EmulatedScalar, test_dispatch};
    use reference::Element;
    use std::{panic::catch_unwind, vec::Vec};

    /// Returns `k * p` in carried limbs.
    fn multiple(k: u64) -> [u64; LIMBS] {
        super::super::multiple::<LIMBS, LIMB_BITS>(k)
    }

    /// A formula evaluated on one pair of elements per lane.
    #[derive(Clone, Copy, Debug)]
    enum Formula {
        Add,
        Sub,
        Neg,
        Double,
        Mul,
        Square,
        /// `(a + a + a) * (b - a) - b`: linear operations chained around a product.
        Chain,
        /// `(a + b) * (2 * (a + b) + a)`: an uncarried sum times one that `ready` carries.
        Ready,
        /// Addition up to the integer limit.
        LooseAdd,
        /// Doublings without carrying, then a product.
        LooseDoubling,
        /// Subtraction with a larger bias, then a square.
        LooseSub,
        /// Multiplication of inputs with large integer bounds.
        LooseMul,
        /// Storing a value at the integer limit.
        LooseStore,
        /// Loading the elements as bytes, then multiplying.
        Load,
    }

    const FORMULAS: [Formula; 14] = [
        Formula::Add,
        Formula::Sub,
        Formula::Neg,
        Formula::Double,
        Formula::Mul,
        Formula::Square,
        Formula::Chain,
        Formula::Ready,
        Formula::LooseAdd,
        Formula::LooseDoubling,
        Formula::LooseSub,
        Formula::LooseMul,
        Formula::LooseStore,
        Formula::Load,
    ];

    impl Formula {
        /// Returns the integer bounds of the inputs, in units of `p`.
        fn bounds(self) -> (u64, u64) {
            match self {
                Self::LooseAdd => (LIMIT / 2, LIMIT / 2),
                Self::LooseMul => (LIMIT, LIMIT - 1),
                Self::LooseStore => (LIMIT, 1),
                _ => (2, 2),
            }
        }

        /// Returns how many times `LooseDoubling` doubles, staying within the integer limit.
        fn doublings() -> u32 {
            (LIMIT.ilog2() - 1).min(11)
        }

        fn scalar(self, a: Element, b: Element) -> Element {
            match self {
                Self::Add | Self::LooseAdd => reference::add(a, b),
                Self::Sub => reference::sub(a, b),
                Self::Neg => reference::neg(a),
                Self::Double => reference::add(a, a),
                Self::Mul | Self::LooseMul | Self::Load => reference::mul(a, b),
                Self::Square => reference::mul(a, a),
                Self::Chain => {
                    let three = reference::add(reference::add(a, a), a);
                    reference::sub(reference::mul(three, reference::sub(b, a)), b)
                }
                Self::Ready => {
                    let sum = reference::add(a, b);
                    let wide = reference::add(reference::add(sum, sum), a);
                    reference::mul(sum, wide)
                }
                Self::LooseDoubling => {
                    let doubled = (0..Self::doublings()).fold(a, |a, _| reference::add(a, a));
                    reference::mul(doubled, b)
                }
                Self::LooseSub => {
                    let difference = reference::sub(a, b);
                    reference::mul(difference, difference)
                }
                Self::LooseStore => a,
            }
        }

        #[inline(always)]
        fn lanes<S: Simd>(self, simd: S, a: Unsat28<S>, b: Unsat28<S>) -> Unsat28<S> {
            match self {
                Self::Add | Self::LooseAdd => a.add(simd, b),
                Self::Sub => a.sub::<3>(simd, b),
                Self::Neg => a.neg::<3>(simd),
                Self::Double => a.double(simd),
                Self::Mul | Self::LooseMul | Self::Load => a.mul(simd, b),
                Self::Square => a.square(simd),
                Self::Chain => {
                    let three = a.double(simd).add(simd, a).ready::<3>(simd);
                    let difference = b.sub::<3>(simd, a).ready::<4>(simd);
                    three.mul(simd, difference).sub::<3>(simd, b)
                }
                Self::Ready => {
                    let sum = a.add(simd, b);
                    let wide = sum.double(simd).add(simd, a).ready::<5>(simd);
                    sum.ready::<2>(simd).mul(simd, wide)
                }
                Self::LooseDoubling => {
                    let mut a = a;
                    for _ in 0..Self::doublings() {
                        a = a.double(simd);
                    }
                    a.carry(simd).mul(simd, b)
                }
                Self::LooseSub => a.sub::<5>(simd, b).carry(simd).square(simd),
                Self::LooseStore => a,
            }
        }
    }

    /// Returns the representative `a * 2^392 mod p` of an element, in limbs.
    fn to_lanes_form(element: Element) -> [u64; LIMBS] {
        limbs_from_words(reference::mul(
            element,
            power_of_two(LIMBS as u32 * LIMB_BITS),
        ))
    }

    /// Returns the element whose representative is `limbs`, a carried value below `p`.
    fn from_lanes_form(limbs: [u64; LIMBS]) -> Element {
        let inverse = reference::invert(power_of_two(LIMBS as u32 * LIMB_BITS));
        reference::mul(words_from_limbs(limbs), inverse)
    }

    /// Returns the representative of `element` plus `(bound - 1) * p`, in carried limbs.
    fn lift(element: Element, bound: u64) -> [u64; LIMBS] {
        let (value, offset) = (to_lanes_form(element), multiple(bound - 1));
        let mut limbs = [0; LIMBS];
        let mut carry = 0;
        for (i, limb) in limbs.iter_mut().enumerate() {
            let sum = value[i] + offset[i] + carry;
            *limb = sum & MASK;
            carry = sum >> LIMB_BITS;
        }
        assert_eq!(carry, 0);
        limbs
    }

    /// Loads one element per lane, each lifted by `(bound - 1) * p`.
    fn loose<S: Simd>(simd: S, elements: &[Element], bound: u64) -> Unsat28<S> {
        let mut lanes = [[0; LIMBS]; MAX_LANES];
        for (lane, element) in lanes.iter_mut().zip(elements) {
            *lane = lift(*element, bound);
        }
        Unsat28::from_limbs(simd, &lanes, bound)
    }

    /// Returns the element whose representative is `p - 1`, which lifts to `bound * p - 1`.
    fn largest() -> Element {
        let mut limbs = multiple(1);
        limbs[0] -= 1;
        from_lanes_form(limbs)
    }

    /// Evaluates a formula on every pair of elements, a lane-sized chunk at a time.
    struct Evaluate<'a> {
        formula: Formula,
        a: &'a [Element; MAX_LANES],
        b: &'a [Element; MAX_LANES],
    }

    impl<S: Simd> Operation<S> for Evaluate<'_> {
        type Output = [[u8; BYTES]; MAX_LANES];

        fn portable(self, simd: S) -> [[u8; BYTES]; MAX_LANES] {
            let mut output = [[0; BYTES]; MAX_LANES];
            let (a_bound, b_bound) = self.formula.bounds();
            let bytes = self.a.map(reference::to_bytes);
            simd.execute(
                #[inline(always)]
                |simd: S| {
                    for start in (0..MAX_LANES).step_by(S::U64_LANES) {
                        let a = match self.formula {
                            Formula::Load => Unsat28::load(simd, &bytes[start..], &[0; BYTES]),
                            _ => loose(simd, &self.a[start..], a_bound),
                        };
                        let b = loose(simd, &self.b[start..], b_bound);
                        self.formula
                            .lanes(simd, a, b)
                            .store(simd, &mut output[start..]);
                    }
                },
            );
            output
        }
    }

    fn elements(
        u: &mut Unstructured<'_>,
        largest: Element,
    ) -> arbitrary::Result<[Element; MAX_LANES]> {
        let mut elements = [reference::ZERO; MAX_LANES];
        for element in &mut elements {
            *element = match u.int_in_range(0..=9)? {
                0 => reference::ZERO,
                1 => reference::ONE,
                2 => reference::neg(reference::ONE),
                3 => largest,
                _ => reference::canonical(u)?,
            };
        }
        Ok(elements)
    }

    #[test]
    fn representatives_round_trip() {
        let mut limbs = multiple(1);
        limbs[0] -= 1;
        assert_eq!(to_lanes_form(largest()), limbs);
        let element = reference::neg(reference::ONE);
        assert_eq!(from_lanes_form(to_lanes_form(element)), element);
    }

    #[test]
    fn matches_reference() {
        let largest = largest();
        minifuzz::test(|u| {
            let a = elements(u, largest)?;
            let b = elements(u, largest)?;
            for formula in FORMULAS {
                let expected: Vec<[u8; BYTES]> = a
                    .iter()
                    .zip(&b)
                    .map(|(a, b)| reference::to_bytes(formula.scalar(*a, *b)))
                    .collect();
                let evaluate = || Evaluate {
                    formula,
                    a: &a,
                    b: &b,
                };
                let actual = test_dispatch(evaluate());
                assert_eq!(actual, expected[..actual.len()], "{formula:?}");
                check_consistent(evaluate);
            }
            Ok(())
        });
    }

    /// Loads and stores every lane.
    struct RoundTrip<'a>(&'a [[u8; BYTES]; MAX_LANES]);

    impl<S: Simd> Operation<S> for RoundTrip<'_> {
        type Output = [[u8; BYTES]; MAX_LANES];

        fn portable(self, simd: S) -> [[u8; BYTES]; MAX_LANES] {
            let mut output = [[0; BYTES]; MAX_LANES];
            for start in (0..MAX_LANES).step_by(S::U64_LANES) {
                Unsat28::<S>::load(simd, &self.0[start..], &[0; BYTES])
                    .store(simd, &mut output[start..]);
            }
            output
        }
    }

    #[test]
    fn round_trip_reduces_bytes() {
        let largest = largest();
        minifuzz::test(|u| {
            let a = elements(u, largest)?.map(reference::to_bytes);
            assert_eq!(test_dispatch(RoundTrip(&a)), a);
            check_consistent(|| RoundTrip(&a));
            // Integers at or above p load as their residues.
            let raw: [[u8; BYTES]; MAX_LANES] = u.arbitrary()?;
            let reduced = raw.map(|bytes| reference::to_bytes(reference::reduce(&bytes)));
            assert_eq!(test_dispatch(RoundTrip(&raw)), reduced);
            Ok(())
        });
    }

    /// Splats an element into every lane.
    struct Splat([u8; BYTES]);

    impl<S: Simd> Operation<S> for Splat {
        type Output = [[u8; BYTES]; MAX_LANES];

        fn portable(self, simd: S) -> [[u8; BYTES]; MAX_LANES] {
            let mut output = [[0; BYTES]; MAX_LANES];
            for start in (0..MAX_LANES).step_by(S::U64_LANES) {
                Unsat28::<S>::splat(simd, &self.0).store(simd, &mut output[start..]);
            }
            output
        }
    }

    #[test]
    fn splat_fills_every_lane() {
        minifuzz::test(|u| {
            let element = reference::to_bytes(reference::canonical(u)?);
            assert_eq!(test_dispatch(Splat(element)), [element; MAX_LANES]);
            check_consistent(|| Splat(element));
            Ok(())
        });
    }

    #[test]
    fn rejects_values_beyond_the_limits() {
        if !DebugCounter::live() {
            return;
        }
        let simd = EmulatedScalar;
        let largest = largest();
        let at = |bound| loose(simd, &[largest], bound);
        assert!(catch_unwind(|| at(LIMIT).add(simd, at(1))).is_err());
        assert!(catch_unwind(|| at(2).sub::<3>(simd, at(2))).is_ok());
        assert!(catch_unwind(|| at(2).sub::<3>(simd, at(3))).is_err());
        assert!(catch_unwind(|| at(1).sub::<5>(simd, at(1).double(simd))).is_ok());
        assert!(catch_unwind(|| at(1).sub::<9>(simd, at(1).double(simd).double(simd))).is_err());
        assert!(catch_unwind(|| at(LIMIT).sub::<3>(simd, at(1))).is_err());
        assert!(catch_unwind(|| at(3).neg::<3>(simd)).is_err());
        assert!(catch_unwind(|| at(LIMIT).mul(simd, at(LIMIT))).is_err());
        // A multiplicand may hold the sum of SLACK carried values, but no more.
        let sum = |count: u64| (1..count).fold(at(1), |sum, _| sum.add(simd, at(1)));
        assert!(catch_unwind(|| sum(SLACK).mul(simd, at(1))).is_ok());
        assert!(catch_unwind(|| sum(SLACK + 1).mul(simd, at(1))).is_err());
    }
    /// Returns carried limbs below `bound * p` whose low limbs all hold their largest value, and
    /// the element they represent.
    fn widest(bound: u64) -> ([u64; LIMBS], Element) {
        let shift = LIMB_BITS * (LIMBS as u32 - 1);
        let top = bound * (MODULUS[WORDS - 1] >> (shift - 320)) - 1;
        assert!(top <= MASK);
        let mut limbs = [MASK; LIMBS];
        limbs[LIMBS - 1] = top;
        // The limbs hold top * 2^shift + 2^shift - 1, and 2^shift is below p.
        let low = reference::sub(power_of_two(shift), reference::ONE);
        let high = reference::mul([top, 0, 0, 0, 0, 0], power_of_two(shift));
        let inverse = reference::invert(power_of_two(LIMBS as u32 * LIMB_BITS));
        let element = reference::mul(reference::add(high, low), inverse);
        (limbs, element)
    }

    /// Multiplies sums of `SLACK` values with the widest carried limbs, so that product columns
    /// reach their largest sums.
    struct Widest;

    impl<S: Simd> Operation<S> for Widest {
        type Output = [u8; BYTES];

        fn portable(self, simd: S) -> [u8; BYTES] {
            let sum = |bound| {
                let value = Unsat28::<S>::from_limbs(simd, &[widest(bound).0; MAX_LANES], bound);
                (1..SLACK).fold(value, |sum, _| sum.add(simd, value))
            };
            let mut output = [[0; BYTES]; MAX_LANES];
            sum(LIMIT / SLACK)
                .mul(simd, sum((LIMIT - 1) / SLACK))
                .store(simd, &mut output);
            output[0]
        }
    }

    #[test]
    fn widest_columns_fit_the_lanes() {
        let times = |element| reference::mul(element, [SLACK, 0, 0, 0, 0, 0]);
        let a = times(widest(LIMIT / SLACK).1);
        let b = times(widest((LIMIT - 1) / SLACK).1);
        assert_eq!(
            test_dispatch(Widest),
            reference::to_bytes(reference::mul(a, b))
        );
        check_consistent(|| Widest);
    }
}
