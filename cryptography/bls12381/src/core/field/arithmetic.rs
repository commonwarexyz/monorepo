//! Representation-neutral base field arithmetic.
//!
//! Representations choose when factors need carrying and whether products reduce eagerly or
//! accumulate before a shared reduction. SIMD operation profiles choose the representation;
//! this trait shares arithmetic without selecting a backend.
//!
//! # Bounds
//!
//! A bound is a conservative limit derived from a formula, not from inspecting a field value.
//! There are three distinct kinds:
//!
//! - An integer bound `A` means the nonnegative integer encoding a value is below `A * p`.
//!   This bounds the representation's integer, not the canonical field residue. It determines
//!   which subtraction biases cover the value and which reductions accept it.
//! - A positional limb bound `L` means every limb is below `L * radix`. Carried limbs have bound
//!   `1`. Limb bounds determine whether additions fit their lanes and factors fit the multiplier.
//! - A product accumulator has an integer bound in units of `p` for eager products, or `p^2` for
//!   wide products. Wide accumulators also have a term bound that protects their machine words.
//!
//! These bounds are independent. Carrying restores positional limb bound `1` but preserves the
//! represented integer and its integer bound. A multiplication or wide reduction can shrink the
//! integer bound; canonicalization returns an integer below `p`.
//!
//! A formula must establish each operation's input bounds and keep its outputs within the limits
//! below. A valid value is not necessarily a valid operand for every operation. Bounds are static
//! usage rules: debug counters verify them, but never choose where to carry or reduce. With debug
//! assertions disabled, the counters and checks disappear; the arithmetic requirements remain.
//!
//! # Representation limits
//!
//! | Property | [`Unsat49`] | [`Unsat28`] | [`Rns`] |
//! |---|---|---|---|
//! | Radix | `2^49` | `2^28` | Residues, each at most twice its modulus |
//! | Maximum value integer bound | `2048` | `2048` | `2048` |
//! | Maximum limb bound | `32767` | `15` | Not positional |
//! | Multiplier limb slack | `8` | `4` | Residues are always ready |
//! | [`Field::Product`] | `Self`, eagerly reduced | `Self`, eagerly reduced | [`Wide`] |
//! | [`Field::PRODUCTS`] | `8` | `8` | `256` |
//!
//! The product count does not replace integer, limb, or accumulator limits. Subtraction biases
//! consume integer headroom, and lifted values retain their input bounds.
//!
//! # Operation rules
//!
//! In the tables below, input values have integer bounds `A`, `B` and positional limb bounds `L`,
//! `M`. Define `E(A, B) = ceil(A * B / 2048) + 1`. Every value's integer and limb bounds must
//! remain within its representation's limits.
//!
//! | Operation | Positional integer and limb bounds | RNS integer bound |
//! |---|---|---|
//! | [`load`](Field::load) | `(2, 1)` | `2` |
//! | [`store_raw::<A>`](Field::store_raw) | Requires `(A, 1)` | Requires `A` |
//! | [`load_raw::<A>`](Field::load_raw) | `(A, 1)` | `A` |
//! | [`add`](Field::add) | `(A + B, L + M)` | `A + B` |
//! | [`double`](Field::double) | `(2A, 2L)` | `2A` |
//! | [`mul_small::<C>`](Field::mul_small) | `(C * A, C * L)` | `C * A` |
//! | [`sub::<K>`](Field::sub) | Requires `B < K`, `M <= 2`; returns `(A + K, L + 3)` | Requires `B <= K`; returns `A + K` |
//! | [`neg::<K>`](Field::neg) | Requires `A < K`, `L <= 2`; returns `(K, 3)` | Requires `A <= K`; returns `K` |
//! | [`carry`](Field::carry) | Preserves `A`, carries to limb bound `1` | No-op |
//! | [`ready::<U>`](Field::ready) | Requires `L <= U`; preserves `A`, carries to limb bound `1` only when `U` exceeds multiplier slack | No-op |
//! | [`product`](Field::product) | Requires ready limbs; returns `(E(A, B), 1)` | Wide integer bound `A * B`, one term |
//! | [`mul`](Field::mul) | Same bounds as `product` | Requires `A * B <= 645173`; returns `ceil(A * B / 645173) + 16 <= 17` |
//!
//! For example, adding values with limb bounds `4` and `2` gives limb bound `6`.
//! `ready::<6>` leaves that sum uncarried for [`Unsat49`], carries it for [`Unsat28`], and does
//! nothing for [`Rns`]. The choice depends on the constant `U`, never on a debug counter.
//!
//! For product accumulators, let `C`, `D` be integer bounds in the accumulator's units. For
//! [`Wide`], let `T`, `V` be term bounds. Every wide accumulator must have at most `1024` terms;
//! its integer bound must be at most `645173` when reduced.
//!
//! | Operation | Eager products, in units of `p` | Wide products, in units of `p^2` |
//! |---|---|---|
//! | [`accumulate`](Field::accumulate) | Integer and limb bounds add | Bound `C + D`, terms `T + V` |
//! | [`product_sub::<K>`](Field::product_sub) | Requires `D < K`; carries the subtrahend; returns integer bound `C + K`, minuend limb bound plus `3` | Ignores `K`; requires `D <= 295936` and `V <= 384`; returns bound `C + 295936`, terms `T + 385` |
//! | [`lift`](Field::lift) | Preserves the value's integer and limb bounds | Integer bound `A`, one term |
//! | [`carry_product`](Field::carry_product) | Preserves integer bound `C`, carries to limb bound `1` | No-op |
//! | [`reduce`](Field::reduce) | Preserves integer bound `C`, carries to limb bound `1` | Returns value bound `ceil(C / 645173) + 16 <= 17` |
//! | [`reduce_tight`](Field::reduce_tight) | Requires `C <= 2048`; returns value bound `2` | Same as [`reduce`](Field::reduce) |
//!
//! # Tight reductions
//!
//! An eager product is already reduced, so a sum of them keeps the sum of their integer bounds and
//! [`Field::reduce`] only carries it. Long sums, such as the coefficients of products in the higher
//! extensions, would then return values whose integer bounds grow with every chained multiplication.
//! [`Field::reduce_tight`] returns integer bound at most [`TIGHT`] in every representation, whatever
//! the sum's bound: [`Unsat49`] pays one more product, by one, [`Unsat28`] subtracts the multiple
//! of `p` that its top limb covers, and wide products reduce as usual.
//! Between products of such sums, [`Field::carry_product`] restores the limb bound of eager sums, so
//! they keep accumulating; wide sums need no carrying and keep their term bounds.
//!
//! # Signed sums
//!
//! A [`Signed`] sum holds the products to add and the products to subtract separately, so
//! subtracting one signed sum from another only accumulates. [`Field::reduce_signed`] subtracts
//! once, through [`Field::product_sub`] with the same bias `K`: the negative sum must satisfy its
//! subtrahend bound, and the positive sum plus its bias must satisfy [`Field::reduce`]. Without a
//! negative sum, it reduces the positive sum directly.
//!
//! The bias `K` applies only to eager products. A formula picks the smallest bias that covers each
//! negative sum, since the bias adds to the integer bound of the reduced value. Wide products
//! always subtract with their fixed bias, which their reduction removes.
//!
//! The default [`Field::cross`] uses Karatsuba. Each input pair must sum to a factor with limb
//! bound at most `2`. Its eager positive sum has integer bound `E(A0 + A1, B0 + B1)` and limb
//! bound `1`, and its negative sum is the two known products, with their bounds added.
//! [`Rns`] overrides it with two products and an accumulation, giving a positive wide integer
//! bound `A0 * B1 + A1 * B0` with two terms and no negative sum.
//!
//! Generic formulas must account for all of these bounds, including between calls. For repeated
//! point operations, a coordinate contract can bound the inputs and show that the outputs satisfy
//! the same contract. This does not require canonical coordinates between operations.
//!
//! # Several reductions
//!
//! [`Field::reduce_each`], [`Field::reduce_each_signed`], and [`Field::reduce_each_signed_tight`]
//! reduce `N` sums that a closure forms by index, each under the rules of [`Field::reduce`],
//! [`Field::reduce_signed`], or [`Field::reduce_signed_tight`]. The defaults reduce each sum right
//! after forming it. [`Rns`] reductions are long dependency chains, so it runs each step of the
//! reduction for several sums before the next, which overlaps their chains; formulas pass it up to
//! [`Field::INTERLEAVE`] sums at once.
//!
//! [`Unsat49`]: super::fp::unsat49::Unsat49
//! [`Unsat28`]: super::fp::unsat28::Unsat28
//! [`Rns`]: super::fp::rns::Rns
//! [`Wide`]: super::fp::rns::Wide

use super::fp::{BYTES, MODULUS, WORDS};
use commonware_simd::{Operation, Simd};

/// Largest integer bound of a value returned by [`Field::reduce_tight`] in any representation, in
/// units of `p`.
pub const TIGHT: u64 = 17;

/// Most indices [`unroll`] calls: the components of an `Fp12` value.
pub(crate) const UNROLLED: usize = 12;

/// Calls `f` with each index below `N`, in order.
///
/// The calls are straight-line code rather than a loop, so every call sees a constant index:
/// arrays indexed by it stay in registers, and a closure that matches on it runs one arm, however
/// large the inlined body of `f`.
#[inline(always)]
pub(crate) fn unroll<const N: usize>(mut f: impl FnMut(usize)) {
    const { assert!(N <= UNROLLED) };
    macro_rules! calls {
        ($($i:literal)*) => {$(
            if $i < N {
                f($i);
            }
        )*};
    }
    calls!(0 1 2 3 4 5 6 7 8 9 10 11);
}

/// A sum of products less another, subtracted only when reduced.
///
/// Subtracting signed sums swaps their parts, so subtraction biases never stack. See the
/// [module documentation](self) for the bounds of a reduction.
#[derive(Clone, Copy)]
pub struct Signed<P> {
    /// The products to add.
    pub pos: P,
    /// The products to subtract, if any.
    pub neg: Option<P>,
}

impl<P> Signed<P> {
    /// Returns a sum with no products to subtract.
    #[inline(always)]
    pub const fn positive(pos: P) -> Self {
        Self { pos, neg: None }
    }
}

/// Base field arithmetic on [`Self::LANES`] elements, shared by every representation.
///
/// Operands must satisfy the integer, limb, and product accumulator bounds in the
/// [module documentation](self). These are caller obligations even when debug checks are disabled.
pub trait Field<S: Simd>: Copy {
    /// Number of elements in a value.
    const LANES: usize;

    /// A sum of products, held unreduced when the representation supports lazy reduction.
    type Product: Copy;

    /// Most products one [`Self::Product`] may accumulate before [`Self::reduce`].
    ///
    /// Integer and limb bounds also constrain accumulation, including subtraction biases.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "Documents the accumulation contract, which the tests check."
        )
    )]
    const PRODUCTS: usize;

    /// Most sums whose reductions one call of [`Self::reduce_each`] or its variants interleaves,
    /// at most [`UNROLLED`].
    ///
    /// The defaults reduce one sum after another. Extension formulas reduce every coefficient of a
    /// result in one call only when this covers all their components, and otherwise reduce each
    /// coefficient in its own kernel.
    const INTERLEAVE: usize = 1;

    /// Loads up to [`Self::LANES`] big-endian integers, filling the remaining lanes with `fill`.
    ///
    /// Interprets each [`BYTES`]-byte integer modulo `p` and returns the initial value bounds.
    fn load(simd: S, elements: &[[u8; BYTES]], fill: &[u8; BYTES]) -> Self;

    /// Stores the canonical value of each lane, dropping lanes beyond `elements`.
    ///
    /// Requires valid value bounds. Entries beyond [`Self::LANES`] are unchanged.
    fn store(self, simd: S, elements: &mut [[u8; BYTES]]);

    /// Runs an operation of base field, quadratic, or sextic extension size, such as a reduction
    /// or an [`Fp2`] or [`Fp6`] product, as its own kernel when the representation's
    /// multiplication is large enough to be worth outlining, so that formulas call one copy;
    /// representations whose operations are small run it inline.
    ///
    /// [`Fp2`]: super::fp2::Fp2
    /// [`Fp6`]: super::fp6::Fp6
    #[inline(always)]
    fn kernel<O: Operation<S>>(simd: S, operation: O) -> O::Output {
        simd.execute(operation)
    }

    /// One lane of a value in the representation's own form, as [`Self::store_raw`] stores it.
    type Raw: Copy + Default;

    /// Stores each lane in the representation's own form, dropping lanes beyond `lanes`.
    ///
    /// Requires positional limb bound `1` and integer bound at most `A`, so that
    /// [`Self::load_raw`] with the same `A` returns a valid value. Costs no conversion. Entries
    /// beyond [`Self::LANES`] are unchanged.
    fn store_raw<const A: u64>(self, simd: S, lanes: &mut [Self::Raw]);

    /// Loads lane `i` from `lanes[i]`, as [`Self::store_raw`] stored it with the same `A`.
    ///
    /// Requires at least [`Self::LANES`] entries and ignores the rest. Returns integer bound `A`
    /// and positional limb bound `1`. Costs no conversion.
    fn load_raw<const A: u64>(simd: S, lanes: &[&Self::Raw]) -> Self;

    /// Returns `self + rhs`, without reducing.
    ///
    /// Integer and positional limb bounds add; the result must fit the value limits.
    fn add(self, simd: S, rhs: Self) -> Self;

    /// Returns `self + self`, without reducing.
    ///
    /// Integer and positional limb bounds double; the result must fit the value limits.
    #[inline(always)]
    fn double(self, simd: S) -> Self {
        self.add(simd, self)
    }

    /// Returns `C * self` for a small positive constant `C`, without reducing.
    ///
    /// Integer and positional limb bounds multiply by `C`, as for `C` additions of `self`, and
    /// every intermediate stays within them; the result must fit the value limits. The default
    /// doubles and adds along the bits of `C`, costing no multiplication.
    #[inline(always)]
    fn mul_small<const C: u64>(self, simd: S) -> Self {
        const { assert!(C > 0) };
        let mut result = self;
        let mut bit = 63 - C.leading_zeros();
        while bit > 0 {
            bit -= 1;
            result = result.double(simd);
            if (C >> bit) & 1 == 1 {
                result = result.add(simd, self);
            }
        }
        result
    }

    /// Returns `self + K * p - rhs`, without reducing.
    ///
    /// The bias must cover `rhs` under the representation's subtraction rules, including its
    /// positional limb restriction. The result's integer bound is the input bound plus `K`.
    fn sub<const K: u64>(self, simd: S, rhs: Self) -> Self;

    /// Returns `K * p - self`, without reducing.
    ///
    /// The bias must cover `self` under the subtraction rules, including its positional limb
    /// restriction. The result's integer bound is `K`.
    fn neg<const K: u64>(self, simd: S) -> Self;

    /// Returns `rhs` in every lane whose bit is set in `lanes`, and `self` in the others.
    ///
    /// Bit `i` of `lanes` selects lane `i`; bits at or beyond [`Self::LANES`] are ignored. The
    /// selection does not branch on `lanes`. Each bound of the result is the larger of the inputs'.
    fn select(self, simd: S, rhs: Self, lanes: u64) -> Self;

    /// Carries every positional limb to limb bound `1`, without reducing.
    ///
    /// Preserves the represented integer and its integer bound. Representations without positional
    /// limbs return the value unchanged.
    fn carry(self, simd: S) -> Self;

    /// Prepares a value for multiplication using a static positional limb bound `U`.
    ///
    /// Each positional limb must be below `U` times the radix. Carries only when `U` exceeds
    /// multiplier slack; otherwise the limbs remain loose. Preserves the represented integer and
    /// its integer bound. Representations without positional limbs do not need carrying.
    fn ready<const U: u64>(self, simd: S) -> Self;

    /// Forms a product. Both factors must be ready; eager representations reduce immediately.
    ///
    /// Each factor must satisfy the multiplier's limb limits and the value integer limit. The
    /// result must fit the product accumulator limits and any subsequent reduction's budget.
    fn product(self, simd: S, rhs: Self) -> Self::Product;

    /// Returns `a + b`.
    ///
    /// Product integer, limb, and term bounds add where applicable. The accumulator must fit;
    /// the product count alone does not establish this.
    fn accumulate(simd: S, a: Self::Product, b: Self::Product) -> Self::Product;

    /// Returns `a - b` plus `K * p` for eager products, or a representation-specific fixed
    /// multiple of `p^2` for wide products.
    ///
    /// The subtrahend must fit the subtraction bias, and the result must fit its integer, limb, and
    /// term bounds. The bias increases the integer bound even when the mathematical difference is
    /// small. Representations with wide products ignore `K`.
    fn product_sub<const K: u64>(simd: S, a: Self::Product, b: Self::Product) -> Self::Product;

    /// Lifts a value into the product representation without changing its field value.
    ///
    /// Requires valid value bounds. Includes the input integer bound in the accumulator's bound;
    /// lifting does not canonicalize the input.
    fn lift(self, simd: S) -> Self::Product;

    /// Reduces a sum of at most [`Self::PRODUCTS`] products and prepares its limbs for reuse.
    ///
    /// The input must satisfy the integer and machine-accumulator limits for reduction. The
    /// output has the documented value integer bound and ready limbs; it need not be canonical.
    /// Reduction does not guarantee a smaller integer bound for an already eager product.
    fn reduce(simd: S, product: Self::Product) -> Self;

    /// Carries every positional limb of an eager sum of products to limb bound `1`, without
    /// reducing.
    ///
    /// Preserves the sum's integer bound. A carried eager sum counts as one product toward
    /// [`Self::PRODUCTS`], so it may accumulate as many products again. Wide sums have no
    /// positional limbs and return unchanged, keeping their count and term bounds.
    fn carry_product(simd: S, product: Self::Product) -> Self::Product;

    /// Reduces a sum of products to integer bound at most [`TIGHT`], whatever the sum's integer
    /// bound, and prepares its limbs for reuse.
    ///
    /// The input must satisfy the limits of [`Self::reduce`]. Eager sums take one more step, which
    /// costs at most one product; wide sums reduce exactly as for [`Self::reduce`].
    fn reduce_tight(simd: S, product: Self::Product) -> Self;

    /// Returns `self * rhs`.
    ///
    /// Both factors must be ready, and their product must fit the reduction budget. Returns the
    /// documented multiplication integer bound and ready limbs.
    #[inline(always)]
    fn mul(self, simd: S, rhs: Self) -> Self {
        Self::reduce(simd, self.product(simd, rhs))
    }

    /// Returns `a[0] * b[1] + a[1] * b[0]` as a product, given `p0 = a[0] * b[0]` and
    /// `p1 = a[1] * b[1]`.
    ///
    /// The default uses Karatsuba: one product of the sums `a[0] + a[1]` and `b[0] + b[1]`, less the
    /// two known products, which form the negative sum. A representation whose products cost less
    /// than those additions and the subtraction overrides it with the two products.
    ///
    /// Inputs must be ready and their pairwise sums must satisfy `ready::<2>`. The known products
    /// must accumulate within their accumulator.
    #[inline(always)]
    fn cross(
        simd: S,
        a: [Self; 2],
        b: [Self; 2],
        p0: Self::Product,
        p1: Self::Product,
    ) -> Signed<Self::Product> {
        let a = a[0].add(simd, a[1]).ready::<2>(simd);
        let b = b[0].add(simd, b[1]).ready::<2>(simd);
        Signed {
            pos: a.product(simd, b),
            neg: Some(Self::accumulate(simd, p0, p1)),
        }
    }

    /// Reduces a signed sum, subtracting its negative sum once with the bias `K`.
    ///
    /// The negative sum must satisfy [`Self::product_sub`]'s subtrahend bound for `K`, and the
    /// difference must satisfy [`Self::reduce`].
    #[inline(always)]
    fn reduce_signed<const K: u64>(simd: S, sum: Signed<Self::Product>) -> Self {
        let Some(neg) = sum.neg else {
            return Self::reduce(simd, sum.pos);
        };
        Self::reduce(simd, Self::product_sub::<K>(simd, sum.pos, neg))
    }

    /// Reduces a signed sum as [`Self::reduce_signed`] does, to integer bound at most [`TIGHT`]
    /// as for [`Self::reduce_tight`].
    #[inline(always)]
    fn reduce_signed_tight<const K: u64>(simd: S, sum: Signed<Self::Product>) -> Self {
        let Some(neg) = sum.neg else {
            return Self::reduce_tight(simd, sum.pos);
        };
        Self::reduce_tight(simd, Self::product_sub::<K>(simd, sum.pos, neg))
    }

    /// Returns `sums(0)`, ..., `sums(N - 1)`, each reduced as [`Self::reduce`] does.
    ///
    /// Calls `sums` once for each index, in increasing order, so that it may form the sums as
    /// they are requested. The default reduces each sum right after forming it; representations
    /// whose reductions are long dependency chains form several sums first and interleave their
    /// reductions, as [`Self::INTERLEAVE`] documents.
    #[inline(always)]
    fn reduce_each<const N: usize>(
        simd: S,
        mut sums: impl FnMut(usize) -> Self::Product,
    ) -> [Self; N] {
        const { assert!(N > 0) };
        let mut reduced = [Self::reduce(simd, sums(0)); N];
        unroll::<N>(
            #[inline(always)]
            |i| {
                if i > 0 {
                    reduced[i] = Self::reduce(simd, sums(i));
                }
            },
        );
        reduced
    }

    /// Returns `sums(0)`, ..., `sums(N - 1)`, each reduced as [`Self::reduce_signed`] does with the
    /// bias `K`.
    ///
    /// Calls `sums` as [`Self::reduce_each`] does.
    #[inline(always)]
    fn reduce_each_signed<const N: usize, const K: u64>(
        simd: S,
        mut sums: impl FnMut(usize) -> Signed<Self::Product>,
    ) -> [Self; N] {
        const { assert!(N > 0) };
        let mut reduced = [Self::reduce_signed::<K>(simd, sums(0)); N];
        unroll::<N>(
            #[inline(always)]
            |i| {
                if i > 0 {
                    reduced[i] = Self::reduce_signed::<K>(simd, sums(i));
                }
            },
        );
        reduced
    }

    /// Returns `sums(0)`, ..., `sums(N - 1)`, each reduced as [`Self::reduce_signed_tight`] does
    /// with the bias `K`.
    ///
    /// Calls `sums` as [`Self::reduce_each`] does.
    #[inline(always)]
    fn reduce_each_signed_tight<const N: usize, const K: u64>(
        simd: S,
        mut sums: impl FnMut(usize) -> Signed<Self::Product>,
    ) -> [Self; N] {
        const { assert!(N > 0) };
        let mut reduced = [Self::reduce_signed_tight::<K>(simd, sums(0)); N];
        unroll::<N>(
            #[inline(always)]
            |i| {
                if i > 0 {
                    reduced[i] = Self::reduce_signed_tight::<K>(simd, sums(i));
                }
            },
        );
        reduced
    }

    /// Returns `self^(p - 2)`, the inverse of a nonzero element, or zero for zero.
    ///
    /// Requires a ready value with integer bound at most [`TIGHT`], so that every power stays
    /// within the limits of [`Self::mul`]. Returns the documented multiplication bounds.
    /// Exponentiates with fixed four-bit windows, at the cost of about `380` squarings and `110`
    /// multiplications, and runs as its own kernel.
    #[inline(always)]
    fn invert(self, simd: S) -> Self {
        simd.execute(
            #[inline(always)]
            move |simd: S| {
                // Window k holds self^k; every power is a product, so all share one bound.
                let mut window = [self.mul(simd, self); 16];
                window[1] = self;
                for k in 3..16 {
                    window[k] = window[k - 1].mul(simd, self);
                }
                let exponent = INVERSE_EXPONENT;
                // The top nibble of p - 2 is nonzero, so the result starts from its window.
                let top = (exponent[WORDS - 1] >> 60) as usize;
                let mut result = window[top];
                for nibble in (0..WORDS * 16 - 1).rev() {
                    for _ in 0..4 {
                        result = result.mul(simd, result);
                    }
                    let digit = (exponent[nibble / 16] >> (4 * (nibble % 16))) & 0xf;
                    if digit != 0 {
                        result = result.mul(simd, window[digit as usize]);
                    }
                }
                result
            },
        )
    }
}

/// `p - 2`, little-endian, the exponent of [`Field::invert`].
const INVERSE_EXPONENT: [u64; WORDS] = {
    let mut exponent = MODULUS;
    exponent[0] -= 2;
    assert!(exponent[WORDS - 1] >> 60 != 0);
    exponent
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::field::fp::{
        rns::Rns, tests as reference, unsat28::Unsat28, unsat49::Unsat49,
    };
    use commonware_invariants::minifuzz;
    use commonware_simd::{
        Operation, X86V4C, check_consistent,
        emulated::{EmulatedNeon, EmulatedScalar, EmulatedX86V4C},
        test_dispatch,
    };

    fn check<S: Simd, F: Field<S>>(simd: S, inputs: &[[u8; BYTES]; 4]) {
        let mut lanes = vec![[0; BYTES]; F::LANES + 1];
        F::load(simd, &inputs[..1], &inputs[1]).store(simd, &mut lanes);
        assert_eq!(lanes[0], reference::to_bytes(reference::reduce(&inputs[0])));
        for lane in &lanes[1..F::LANES] {
            assert_eq!(*lane, reference::to_bytes(reference::reduce(&inputs[1])));
        }
        assert_eq!(lanes[F::LANES], [0; BYTES]);
        F::load(simd, inputs, &inputs[0]).store(simd, &mut []);
        let [a, b, c, d] = inputs.map(|bytes| F::load(simd, &[], &bytes));
        let [ra, rb, rc, rd] = inputs.map(|bytes| reference::reduce(&bytes));
        let assert_value = |value: F, expected| {
            let mut output = [[0; BYTES]];
            value.store(simd, &mut output);
            assert_eq!(output[0], reference::to_bytes(expected));
        };
        let ab = a.product(simd, b);
        let cd = c.product(simd, d);
        assert_value(F::reduce(simd, ab), reference::mul(ra, rb));
        assert_value(F::mul(a, simd, b), reference::mul(ra, rb));
        assert_value(a.add(simd, b), reference::add(ra, rb));
        assert_value(a.double(simd), reference::add(ra, ra));
        assert_value(a.mul_small::<1>(simd), ra);
        assert_value(
            a.mul_small::<3>(simd),
            reference::mul(ra, [3, 0, 0, 0, 0, 0]),
        );
        let scaled = a.mul_small::<12>(simd);
        assert_value(scaled, reference::mul(ra, [12, 0, 0, 0, 0, 0]));
        // A carried multiple is a valid subtrahend and factor.
        let scaled = scaled.carry(simd);
        assert_value(
            b.sub::<{ 12 * 17 }>(simd, scaled),
            reference::sub(rb, reference::mul(ra, [12, 0, 0, 0, 0, 0])),
        );
        assert_value(
            F::mul(scaled, simd, b),
            reference::mul(reference::mul(ra, [12, 0, 0, 0, 0, 0]), rb),
        );
        assert_value(a.sub::<3>(simd, b), reference::sub(ra, rb));
        assert_value(a.neg::<3>(simd), reference::neg(ra));
        assert_value(F::reduce(simd, F::lift(a, simd)), ra);
        assert_value(
            F::reduce(simd, F::accumulate(simd, ab, cd)),
            reference::add(reference::mul(ra, rb), reference::mul(rc, rd)),
        );
        assert_value(
            F::reduce(simd, F::product_sub::<64>(simd, ab, cd)),
            reference::sub(reference::mul(ra, rb), reference::mul(rc, rd)),
        );
        assert_value(
            F::reduce_signed::<64>(simd, F::cross(simd, [a, c], [b, d], ab, cd)),
            reference::add(reference::mul(ra, rd), reference::mul(rc, rb)),
        );
        let mut sum = ab;
        let mut expected = reference::mul(ra, rb);
        for _ in 1..F::PRODUCTS {
            sum = F::accumulate(simd, sum, ab);
            expected = reference::add(expected, reference::mul(ra, rb));
        }
        assert_value(
            F::reduce(simd, F::product_sub::<64>(simd, ab, sum)),
            reference::sub(reference::mul(ra, rb), expected),
        );
        let reduced = F::reduce(simd, sum);
        assert_value(reduced, expected);
        // A carried sum of eight products, the fewest any representation accepts, accumulates
        // seven more, and a tight reduction bounds the result whatever the sum's bound.
        let mut long = ab;
        let mut long_expected = reference::mul(ra, rb);
        for _ in 1..8 {
            long = F::accumulate(simd, long, ab);
            long_expected = reference::add(long_expected, reference::mul(ra, rb));
        }
        long = F::carry_product(simd, long);
        for _ in 1..8 {
            long = F::accumulate(simd, long, ab);
            long_expected = reference::add(long_expected, reference::mul(ra, rb));
        }
        let tight = F::reduce_tight(simd, long);
        assert_value(tight, long_expected);
        tight.neg::<{ TIGHT + 1 }>(simd);
        let tight = F::reduce_signed_tight::<64>(
            simd,
            Signed {
                pos: long,
                neg: Some(cd),
            },
        );
        assert_value(tight, reference::sub(long_expected, reference::mul(rc, rd)));
        tight.neg::<{ TIGHT + 1 }>(simd);
        assert_value(
            F::reduce_signed_tight::<64>(simd, Signed::positive(ab)),
            reference::mul(ra, rb),
        );
        assert_value(
            F::mul(reduced.ready::<1>(simd), simd, a),
            reference::mul(expected, ra),
        );
        let mut factor = a;
        let mut scalar_factor = ra;
        for _ in 1..16 {
            factor = factor.add(simd, a);
            scalar_factor = reference::add(scalar_factor, ra);
            // Keep additions within the representation's limb limits.
            factor = factor.ready::<16>(simd);
        }
        assert_value(
            F::mul(factor.ready::<16>(simd), simd, b),
            reference::mul(scalar_factor, rb),
        );
        let sum = a.add(simd, b).ready::<2>(simd);
        assert_value(
            F::mul(sum, simd, c),
            reference::mul(reference::add(ra, rb), rc),
        );
        // Selection picks each lane independently and keeps the larger bounds.
        assert_value(a.select(simd, b, 0), ra);
        assert_value(a.select(simd, b, u64::MAX), rb);
        let mut selected = vec![[0; BYTES]; F::LANES];
        a.select(simd, scaled, 0x5555).store(simd, &mut selected);
        let scaled_value = reference::mul(ra, [12, 0, 0, 0, 0, 0]);
        for (lane, value) in selected.iter().enumerate() {
            let expected = if lane % 2 == 0 { scaled_value } else { ra };
            assert_eq!(*value, reference::to_bytes(expected));
        }
        // Raw forms round-trip without conversion and load as valid operands.
        let mut raw = vec![F::Raw::default(); F::LANES];
        F::mul(a, simd, b).store_raw::<TIGHT>(simd, &mut raw);
        let lanes: Vec<&F::Raw> = raw.iter().collect();
        let loaded = F::load_raw::<TIGHT>(simd, &lanes);
        assert_value(loaded, reference::mul(ra, rb));
        assert_value(
            F::mul(loaded, simd, c),
            reference::mul(reference::mul(ra, rb), rc),
        );
        // Each lane loads its own entry.
        F::load(simd, &inputs[..1], &inputs[1]).store_raw::<2>(simd, &mut raw);
        let reversed: Vec<&F::Raw> = raw.iter().rev().collect();
        let mut stored = vec![[0; BYTES]; F::LANES];
        F::load_raw::<2>(simd, &reversed).store(simd, &mut stored);
        for (lane, value) in stored.iter().enumerate() {
            let expected = if lane + 1 == F::LANES { ra } else { rb };
            assert_eq!(*value, reference::to_bytes(expected));
        }
        assert!(F::LANES > 0);
    }

    struct Evaluate([[u8; BYTES]; 4]);

    impl<S: Simd> Operation<S> for Evaluate {
        type Output = ();

        fn portable(self, simd: S) {
            simd.execute(|simd: S| {
                check::<S, Unsat49<S>>(simd, &self.0);
                check::<S, Unsat28<S>>(simd, &self.0);
            });
        }

        // Residues require x86v4c.
        fn x86_v4c(self, simd: S)
        where
            S: X86V4C,
        {
            let inputs = self.0;
            self.portable(simd);
            simd.execute(|simd: S| check::<S, Rns<S>>(simd, &inputs));
        }
    }

    #[test]
    fn representations_match_reference() {
        for value in [
            reference::ZERO,
            reference::ONE,
            reference::neg(reference::ONE),
        ] {
            let inputs = [reference::to_bytes(value); 4];
            check_consistent(|| Evaluate(inputs));
        }
        minifuzz::test(|u| {
            let inputs = [
                u.arbitrary()?,
                u.arbitrary()?,
                u.arbitrary()?,
                u.arbitrary()?,
            ];
            test_dispatch(Evaluate(inputs));
            check_consistent(|| Evaluate(inputs));
            // Run every representation and vector width even on hosts without native SIMD.
            Evaluate(inputs).portable(EmulatedScalar);
            Evaluate(inputs).portable(EmulatedNeon);
            EmulatedX86V4C.execute(Evaluate(inputs));
            Ok(())
        });
    }

    fn check_inverse<S: Simd, F: Field<S>>(simd: S, input: &[u8; BYTES]) {
        let a = F::load(simd, &[], input);
        let ra = reference::reduce(input);
        let inverse = a.invert(simd);
        let mut output = [[0; BYTES]; 2];
        inverse.store(simd, &mut output[..1]);
        F::mul(inverse, simd, a).store(simd, &mut output[1..]);
        assert_eq!(output[0], reference::to_bytes(reference::invert(ra)));
        let one = if ra == reference::ZERO {
            reference::ZERO
        } else {
            reference::ONE
        };
        assert_eq!(output[1], reference::to_bytes(one));
    }

    struct Invert([u8; BYTES]);

    impl<S: Simd> Operation<S> for Invert {
        type Output = ();

        fn portable(self, simd: S) {
            simd.execute(|simd: S| {
                check_inverse::<S, Unsat49<S>>(simd, &self.0);
                check_inverse::<S, Unsat28<S>>(simd, &self.0);
            });
        }

        // Residues require x86v4c.
        fn x86_v4c(self, simd: S)
        where
            S: X86V4C,
        {
            let input = self.0;
            self.portable(simd);
            simd.execute(|simd: S| check_inverse::<S, Rns<S>>(simd, &input));
        }
    }

    #[test]
    fn inverses_match_reference() {
        let mut u = arbitrary::Unstructured::new(&[0xa5; 64]);
        for value in [
            reference::ZERO,
            reference::ONE,
            reference::neg(reference::ONE),
            reference::canonical(&mut u).unwrap(),
        ] {
            let input = reference::to_bytes(value);
            test_dispatch(Invert(input));
            Invert(input).portable(EmulatedNeon);
            EmulatedX86V4C.execute(Invert(input));
        }
    }
}
