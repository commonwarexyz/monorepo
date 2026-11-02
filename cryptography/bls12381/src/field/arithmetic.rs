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
//! | [`product_sub`](Field::product_sub) | Requires `D <= 63`; carries the subtrahend; returns integer bound `C + 64`, minuend limb bound plus `3` | Requires `D <= 295936`; returns bound `C + 295936`, terms `T + 3` |
//! | [`lift`](Field::lift) | Preserves the value's integer and limb bounds | Integer bound `A`, one term |
//! | [`reduce`](Field::reduce) | Preserves integer bound `C`, carries to limb bound `1` | Returns value bound `ceil(C / 645173) + 16 <= 17` |
//!
//! # Signed sums
//!
//! A [`Signed`] sum holds the products to add and the products to subtract separately, so
//! subtracting one signed sum from another only accumulates. [`Field::reduce_signed`] subtracts
//! once, through [`Field::product_sub`]: the negative sum must satisfy its subtrahend bound, and the
//! positive sum plus its bias must satisfy [`Field::reduce`]. Without a negative sum, it reduces
//! the positive sum directly.
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
//! [`Unsat49`]: super::fp::unsat49::Unsat49
//! [`Unsat28`]: super::fp::unsat28::Unsat28
//! [`Rns`]: super::fp::rns::Rns
//! [`Wide`]: super::fp::rns::Wide

use super::fp::BYTES;
use commonware_simd::Simd;

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
    const PRODUCTS: usize;

    /// Loads up to [`Self::LANES`] big-endian integers, filling the remaining lanes with `fill`.
    ///
    /// Interprets each [`BYTES`]-byte integer modulo `p` and returns the initial value bounds.
    fn load(simd: S, elements: &[[u8; BYTES]], fill: &[u8; BYTES]) -> Self;

    /// Stores the canonical value of each lane, dropping lanes beyond `elements`.
    ///
    /// Requires valid value bounds. Entries beyond [`Self::LANES`] are unchanged.
    fn store(self, simd: S, elements: &mut [[u8; BYTES]]);

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

    /// Returns `a - b` plus a representation-specific fixed multiple of `p` (or `p^2`).
    ///
    /// The subtrahend must fit the representation's subtraction bias, and the result must fit
    /// its integer, limb, and term bounds. The bias increases the integer bound even when the
    /// mathematical difference is small.
    fn product_sub(simd: S, a: Self::Product, b: Self::Product) -> Self::Product;

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

    /// Reduces a signed sum, subtracting its negative sum once.
    ///
    /// The negative sum must satisfy [`Self::product_sub`]'s subtrahend bound, and the difference
    /// must satisfy [`Self::reduce`].
    #[inline(always)]
    fn reduce_signed(simd: S, sum: Signed<Self::Product>) -> Self {
        let Some(neg) = sum.neg else {
            return Self::reduce(simd, sum.pos);
        };
        Self::reduce(simd, Self::product_sub(simd, sum.pos, neg))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::fp::{rns::Rns, tests as reference, unsat28::Unsat28, unsat49::Unsat49};
    use commonware_invariants::minifuzz;
    use commonware_simd::{
        Operation, check_consistent,
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
            F::reduce(simd, F::product_sub(simd, ab, cd)),
            reference::sub(reference::mul(ra, rb), reference::mul(rc, rd)),
        );
        assert_value(
            F::reduce_signed(simd, F::cross(simd, [a, c], [b, d], ab, cd)),
            reference::add(reference::mul(ra, rd), reference::mul(rc, rb)),
        );
        let mut sum = ab;
        let mut expected = reference::mul(ra, rb);
        for _ in 1..F::PRODUCTS {
            sum = F::accumulate(simd, sum, ab);
            expected = reference::add(expected, reference::mul(ra, rb));
        }
        assert_value(
            F::reduce(simd, F::product_sub(simd, ab, sum)),
            reference::sub(reference::mul(ra, rb), expected),
        );
        let reduced = F::reduce(simd, sum);
        assert_value(reduced, expected);
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
        assert!(F::LANES > 0);
    }

    struct Evaluate([[u8; BYTES]; 4]);

    impl<S: Simd> Operation<S> for Evaluate {
        type Output = ();

        fn portable(self, simd: S) {
            simd.execute(|simd: S| {
                check::<S, Unsat49<S>>(simd, &self.0);
                check::<S, Unsat28<S>>(simd, &self.0);
                check::<S, Rns<S>>(simd, &self.0);
            });
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
            Evaluate(inputs).portable(EmulatedX86V4C);
            Ok(())
        });
    }
}
