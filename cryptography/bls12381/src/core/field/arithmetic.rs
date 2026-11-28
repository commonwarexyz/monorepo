//! The [`Field`] trait: base field arithmetic on several elements at once, which the extension
//! fields, curve formulas, and kernels are written over once for every representation.
//!
//! The kernels choose a representation for each SIMD backend: [`Unsat49`], [`Unsat28`], or
//! [`Rns`]. A formula forms products with [`Field::product`], adds them with
//! [`Field::accumulate`] or [`Field::accumulate_product`], and reduces each sum once with
//! [`Field::reduce`] or one of its variants. Positional representations reduce every product
//! eagerly; [`Rns`] holds sums of products unreduced. A [`Signed`] sum defers a subtraction of
//! products to its reduction.
//! Representations differ in when values need carrying, so a formula is correct for all of them
//! only if it keeps every operand within the bounds below.
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
//! below. A valid value is not necessarily a valid operand for every operation. Generic formulas
//! must account for these bounds between calls as well. For repeated point operations, a
//! coordinate contract can bound the inputs and show that the outputs satisfy the same contract;
//! coordinates need not be canonical between operations.
//!
//! Debug builds check the bounds with counters, which never decide where to carry or reduce.
//! Release builds do not check them, and results are unspecified when a formula violates them.
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
//! An eager product is already reduced, so [`Field::reduce`] only carries a sum of them, and the
//! result keeps the sum of their integer bounds. Chained multiplications of long sums, such as the
//! coefficients of products in the higher extensions, would grow that bound at every step.
//! [`Field::reduce_tight`] returns integer bound at most [`TIGHT`] in every representation,
//! whatever the sum's bound. Between products of such sums, [`Field::carry_product`] restores the
//! limb bound of eager sums so that they can keep accumulating; wide sums need no carrying and
//! keep their term bounds.
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
//! [`Field::cross`] requires each input pair to sum to a factor with limb bound at most `2`. For
//! eager products, its positive sum has integer bound `E(A0 + A1, B0 + B1)` and limb bound `1`,
//! and its negative sum is the two known products, with their bounds added. For [`Rns`], its
//! positive sum has wide integer bound `A0 * B1 + A1 * B0` with two terms, and it has no negative
//! sum.
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
pub const UNROLLED: usize = 12;

/// Calls `f` with each index below `N`, in order.
///
/// The calls are straight-line code rather than a loop, so every call sees a constant index:
/// arrays indexed by it stay in registers, and a closure that matches on it runs one arm, however
/// large the inlined body of `f`.
#[inline(always)]
pub fn unroll<const N: usize>(mut f: impl FnMut(usize)) {
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

    /// Returns `self + rhs`, adding the positive sums and the negative sums.
    #[inline(always)]
    pub fn add<S: Simd, F: Field<S, Product = P>>(self, simd: S, rhs: Self) -> Self {
        Self {
            pos: F::accumulate(simd, self.pos, rhs.pos),
            neg: join::<S, F>(simd, self.neg, rhs.neg),
        }
    }

    /// Returns `self - rhs`, adding the negative sum of `rhs` to the positive sum and its positive
    /// sum to the negative sum, so no bias is needed.
    #[inline(always)]
    pub fn sub<S: Simd, F: Field<S, Product = P>>(self, simd: S, rhs: Self) -> Self {
        let mut pos = self.pos;
        if let Some(neg) = rhs.neg {
            pos = F::accumulate(simd, pos, neg);
        }
        Self {
            pos,
            neg: join::<S, F>(simd, self.neg, Some(rhs.pos)),
        }
    }

    /// Carries both sums, as for [`Field::carry_product`].
    #[inline(always)]
    pub fn carry<S: Simd, F: Field<S, Product = P>>(self, simd: S) -> Self {
        Self {
            pos: F::carry_product(simd, self.pos),
            neg: self.neg.map(|neg| F::carry_product(simd, neg)),
        }
    }

    /// Returns the difference of the sums as one sum of products, subtracting the negative sum
    /// once with the bias `K` as [`Field::reduce_signed`] does before reducing, or the positive
    /// sum alone when there is no negative sum.
    #[inline(always)]
    pub fn difference<S: Simd, F: Field<S, Product = P>, const K: u64>(self, simd: S) -> P {
        let Some(neg) = self.neg else {
            return self.pos;
        };
        F::product_sub::<K>(simd, self.pos, neg)
    }
}

/// Returns the sum of two optional sums of products.
#[inline(always)]
fn join<S: Simd, F: Field<S>>(
    simd: S,
    a: Option<F::Product>,
    b: Option<F::Product>,
) -> Option<F::Product> {
    match (a, b) {
        (Some(a), Some(b)) => Some(F::accumulate(simd, a, b)),
        (a, None) => a,
        (None, b) => b,
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
        not(any(test, feature = "fuzz")),
        expect(
            dead_code,
            reason = "Documents the accumulation contract, which the tests check."
        )
    )]
    const PRODUCTS: usize;

    /// Most sums whose reductions one call of [`Self::reduce_each`] or its variants overlaps, at
    /// most [`UNROLLED`].
    ///
    /// Extension formulas reduce every coefficient of a result in one call only when this covers
    /// all of them, and otherwise reduce each coefficient in its own kernel.
    const INTERLEAVE: usize = 1;

    /// Whether formulas over the higher extensions multiply every pair of coefficients and
    /// accumulate each product into the sum it belongs to, through
    /// [`Self::accumulate_quadratic`], rather than form Karatsuba's fewer products of sums and
    /// combine them with more additions.
    ///
    /// Set where [`Self::accumulate_product`] costs no more than [`Self::product`], so that the
    /// additions disappear.
    const SCHOOLBOOK: bool = false;

    /// Loads up to [`Self::LANES`] big-endian integers, filling the remaining lanes with `fill`.
    ///
    /// Interprets each [`BYTES`]-byte integer modulo `p`. Returns integer bound `2` and
    /// positional limb bound `1`.
    fn load(simd: S, elements: &[[u8; BYTES]], fill: &[u8; BYTES]) -> Self;

    /// Stores the canonical value of each lane, dropping lanes beyond `elements`.
    ///
    /// Requires valid value bounds. Entries beyond [`Self::LANES`] are unchanged.
    fn store(self, simd: S, elements: &mut [[u8; BYTES]]);

    /// Runs an operation of base field, [`Fp2`], or [`Fp6`] size, such as a reduction or a
    /// product, either as its own kernel or inline, as the representation chooses.
    ///
    /// [`Fp2`]: super::fp2::Fp2
    /// [`Fp6`]: super::fp6::Fp6
    #[inline(always)]
    fn kernel<O: Operation<S>>(simd: S, operation: O) -> O::Output {
        // A separate kernel lets every formula call one copy of the operation.
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
    /// every intermediate stays within them; the result must fit the value limits.
    #[inline(always)]
    fn mul_small<const C: u64>(self, simd: S) -> Self {
        const { assert!(C > 0) };
        // Doubles and adds along the bits of C, costing no multiplication.
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

    /// Returns `self * rhs` as a sum of one product. Both factors must be ready.
    ///
    /// Each factor must satisfy the multiplier's limb limits and the value integer limit. The
    /// result must fit the product accumulator limits and those of the reduction that consumes it.
    fn product(self, simd: S, rhs: Self) -> Self::Product;

    /// Returns `a + b`.
    ///
    /// Product integer, limb, and term bounds add where applicable. The accumulator must fit;
    /// the product count alone does not establish this.
    fn accumulate(simd: S, a: Self::Product, b: Self::Product) -> Self::Product;

    /// Returns `sum + a * b`, under the requirements of [`Self::product`] for the factors and of
    /// [`Self::accumulate`] for the sum.
    ///
    /// Formulas accumulate every product they do not reuse this way, since it may cost less than
    /// [`Self::product`] followed by [`Self::accumulate`].
    #[inline(always)]
    fn accumulate_product(simd: S, sum: Self::Product, a: Self, b: Self) -> Self::Product {
        Self::accumulate(simd, sum, a.product(simd, b))
    }

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

    /// Returns `sum + value`, lifting the value as [`Self::lift`] does and accumulating it as
    /// [`Self::accumulate`] does.
    #[inline(always)]
    fn accumulate_lift(simd: S, sum: Self::Product, value: Self) -> Self::Product {
        Self::accumulate(simd, sum, value.lift(simd))
    }

    /// Reduces a sum of at most [`Self::PRODUCTS`] products to a value with positional limb
    /// bound `1`.
    ///
    /// The input must satisfy the integer and term bounds for reduction. The output has the
    /// documented value integer bound and ready limbs; it need not be canonical.
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
    /// bound, and positional limb bound `1`.
    ///
    /// The input must satisfy the limits of [`Self::reduce`]. Costs at most one product more than
    /// [`Self::reduce`].
    fn reduce_tight(simd: S, product: Self::Product) -> Self;

    /// Returns `self * rhs`.
    ///
    /// Both factors must be ready, and their product must satisfy [`Self::reduce`]. Returns the
    /// documented multiplication integer bound and ready limbs.
    #[inline(always)]
    fn mul(self, simd: S, rhs: Self) -> Self {
        Self::reduce(simd, self.product(simd, rhs))
    }

    /// Returns `a[0] * b[1] + a[1] * b[0]` as a product, given `p0 = a[0] * b[0]` and
    /// `p1 = a[1] * b[1]`.
    ///
    /// Inputs must be ready and their pairwise sums must satisfy `ready::<2>`. The known products
    /// must accumulate within their accumulator. The [module documentation](self#signed-sums)
    /// gives the bounds of the result.
    #[inline(always)]
    fn cross(
        simd: S,
        a: [Self; 2],
        b: [Self; 2],
        p0: Self::Product,
        p1: Self::Product,
    ) -> Signed<Self::Product> {
        // Karatsuba: one product of the sums a[0] + a[1] and b[0] + b[1], less the two known
        // products, which form the negative sum.
        let a = a[0].add(simd, a[1]).ready::<2>(simd);
        let b = b[0].add(simd, b[1]).ready::<2>(simd);
        Signed {
            pos: a.product(simd, b),
            neg: Some(Self::accumulate(simd, p0, p1)),
        }
    }

    /// Returns the product of `a[0] + a[1] i` and `b[0] + b[1] i`, where `i^2 = -1`, as the
    /// signed sums of its real and imaginary components.
    ///
    /// The real component is `a[0] b[0]` less `a[1] b[1]`, and the imaginary component is
    /// [`Self::cross`] of the factors given those two products, under its requirements.
    #[inline(always)]
    fn quadratic(simd: S, a: [Self; 2], b: [Self; 2]) -> [Signed<Self::Product>; 2] {
        let p0 = a[0].product(simd, b[0]);
        let p1 = a[1].product(simd, b[1]);
        [
            Signed {
                pos: p0,
                neg: Some(p1),
            },
            Self::cross(simd, a, b, p0, p1),
        ]
    }

    /// Returns `sum` plus the product of `a[0] + a[1] i` and `b[0] + b[1] i`, component by
    /// component, under the requirements of [`Self::quadratic`] and of [`Self::accumulate`] for
    /// each sum.
    #[inline(always)]
    fn accumulate_quadratic(
        simd: S,
        sum: [Signed<Self::Product>; 2],
        a: [Self; 2],
        b: [Self; 2],
    ) -> [Signed<Self::Product>; 2] {
        // Forms the product and adds it as Signed::add does.
        let [c0, c1] = Self::quadratic(simd, a, b);
        [
            sum[0].add::<S, Self>(simd, c0),
            sum[1].add::<S, Self>(simd, c1),
        ]
    }

    /// Returns `sum` less the product of `a[0] + a[1] i` and `b[0] + b[1] i`, component by
    /// component and without a bias, under the requirements of [`Self::quadratic`] and of
    /// [`Self::accumulate`] for each sum.
    #[inline(always)]
    fn subtract_quadratic(
        simd: S,
        sum: [Signed<Self::Product>; 2],
        a: [Self; 2],
        b: [Self; 2],
    ) -> [Signed<Self::Product>; 2] {
        // Forms the product and subtracts it as Signed::sub does.
        let [c0, c1] = Self::quadratic(simd, a, b);
        [
            sum[0].sub::<S, Self>(simd, c0),
            sum[1].sub::<S, Self>(simd, c1),
        ]
    }

    /// Reduces a signed sum, subtracting its negative sum once with the bias `K`.
    ///
    /// The negative sum must satisfy [`Self::product_sub`]'s subtrahend bound for `K`, and the
    /// difference must satisfy [`Self::reduce`].
    #[inline(always)]
    fn reduce_signed<const K: u64>(simd: S, sum: Signed<Self::Product>) -> Self {
        Self::reduce(simd, sum.difference::<S, Self, K>(simd))
    }

    /// Reduces a signed sum as [`Self::reduce_signed`] does, to integer bound at most [`TIGHT`]
    /// as for [`Self::reduce_tight`].
    #[inline(always)]
    fn reduce_signed_tight<const K: u64>(simd: S, sum: Signed<Self::Product>) -> Self {
        Self::reduce_tight(simd, sum.difference::<S, Self, K>(simd))
    }

    /// Returns `sums(0)`, ..., `sums(N - 1)`, each reduced as [`Self::reduce`] does.
    ///
    /// Calls `sums` once for each index, in increasing order, so that it may form the sums as
    /// they are requested. A representation may form several sums before reducing them and
    /// overlap their reductions, up to [`Self::INTERLEAVE`] sums.
    #[inline(always)]
    fn reduce_each<const N: usize>(
        simd: S,
        mut sums: impl FnMut(usize) -> Self::Product,
    ) -> [Self; N] {
        const { assert!(N > 0) };
        // Reduces each sum right after forming it.
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
    #[inline(always)]
    fn invert(self, simd: S) -> Self {
        // Runs as its own kernel and exponentiates with fixed four-bit windows: about 380
        // squarings and 110 multiplications over every lane at once.
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

/// Checks of the arithmetic of every representation against the reference arithmetic.
#[cfg(any(test, feature = "fuzz"))]
pub mod fuzz {
    use super::*;
    use crate::core::field::fp::{
        reference::{self, Element, small},
        testing::{self, Check},
    };
    use arbitrary::{Arbitrary, Unstructured};
    use core::any::type_name;
    use std::{vec, vec::Vec};

    /// A check of every [`Field`] operation in a representation and on an emulated backend drawn
    /// from the input, with distinct elements in every lane.
    #[derive(Clone, Copy, Debug, Arbitrary)]
    pub enum Plan {
        /// Checks loads and stores with fills, selections, and raw forms.
        LoadStore,
        /// Checks sums, multiples, differences, negations, carries, and products of values,
        /// including readied sums.
        Values,
        /// Checks reduced products and their sums, differences, cross terms, and quadratic forms.
        Products,
        /// Checks sums of [`Field::PRODUCTS`] products and tight reductions of longer sums.
        Accumulation,
        /// Checks inversion against the reference, mapping zero to zero.
        Inverse,
    }

    impl Plan {
        /// Runs the check on the remaining input.
        pub fn run(self, u: &mut Unstructured<'_>) -> arbitrary::Result<()> {
            testing::check_any(u, self)
        }
    }

    impl Check for Plan {
        fn check<S: Simd, F: Field<S>>(
            self,
            simd: S,
            u: &mut Unstructured<'_>,
        ) -> arbitrary::Result<()> {
            match self {
                Self::LoadStore => load_store::<S, F>(simd, u),
                Self::Values => values::<S, F>(simd, u),
                Self::Products => products::<S, F>(simd, u),
                Self::Accumulation => accumulation::<S, F>(simd, u),
                Self::Inverse => inverse::<S, F>(simd, u),
            }
        }
    }

    /// Draws one integer per lane and loads them, or draws one and loads it into every lane
    /// through the fill, returning the value and its lanes' residues.
    fn draw<S: Simd, F: Field<S>>(
        simd: S,
        u: &mut Unstructured<'_>,
    ) -> arbitrary::Result<(F, Vec<Element>)> {
        if u.int_in_range(0..=3)? == 1 {
            let fill = testing::bytes(u)?;
            let residues = vec![reference::decode(&fill); F::LANES];
            return Ok((F::load(simd, &[], &fill), residues));
        }
        let mut lanes = Vec::with_capacity(F::LANES);
        for _ in 0..F::LANES {
            lanes.push(testing::bytes(u)?);
        }
        let residues = lanes.iter().map(reference::decode).collect();
        Ok((F::load(simd, &lanes, &[0; BYTES]), residues))
    }

    /// Asserts that lane `i` of `value` is `expected(i)`.
    fn assert_lanes<S: Simd, F: Field<S>>(
        simd: S,
        value: F,
        label: &str,
        expected: impl Fn(usize) -> Element,
    ) {
        let mut output = vec![[0; BYTES]; F::LANES];
        value.store(simd, &mut output);
        for (lane, output) in output.iter().enumerate() {
            assert_eq!(
                *output,
                reference::encode(expected(lane)),
                "{label} on {}, lane {lane}",
                type_name::<F>()
            );
        }
    }

    fn load_store<S: Simd, F: Field<S>>(
        simd: S,
        u: &mut Unstructured<'_>,
    ) -> arbitrary::Result<()> {
        // Loads fill the lanes beyond the given elements and ignore elements beyond the lanes;
        // stores leave entries beyond the lanes unchanged.
        let lanes = F::LANES;
        let mut elements = Vec::with_capacity(lanes + 1);
        for _ in 0..=lanes {
            elements.push(testing::bytes(u)?);
        }
        let fill = testing::bytes(u)?;
        let count = lanes + 1 - u.int_in_range(0..=lanes + 1)?;
        let length = lanes + 1 - u.int_in_range(0..=lanes + 1)?;
        // Above p, so never a stored element.
        let sentinel = [0xff; BYTES];
        let mut stored = vec![sentinel; length];
        F::load(simd, &elements[..count], &fill).store(simd, &mut stored);
        for (lane, stored) in stored.iter().enumerate() {
            let expected = match lane {
                lane if lane >= lanes => sentinel,
                lane if lane < count => reference::encode(reference::decode(&elements[lane])),
                _ => reference::encode(reference::decode(&fill)),
            };
            assert_eq!(
                *stored,
                expected,
                "load {count} and store {length} on {}, lane {lane}",
                type_name::<F>()
            );
        }

        let (a, ra) = draw::<S, F>(simd, u)?;
        let (b, rb) = draw::<S, F>(simd, u)?;
        let (c, rc) = draw::<S, F>(simd, u)?;
        let rab = |i: usize| reference::mul(ra[i], rb[i]);
        // Selection picks each lane independently and keeps the larger bounds.
        let scaled = a.mul_small::<12>(simd).carry(simd);
        let mask = match u.int_in_range(0..=2)? {
            0 => u.arbitrary()?,
            1 => 0,
            _ => u64::MAX,
        };
        assert_lanes(simd, a.select(simd, scaled, mask), "select", |i| {
            if (mask >> i) & 1 == 1 {
                reference::mul(ra[i], small(12))
            } else {
                ra[i]
            }
        });
        // Raw forms load each lane from its own entry without conversion, as valid operands.
        let mut raw = vec![F::Raw::default(); lanes];
        a.store_raw::<2>(simd, &mut raw);
        let reversed: Vec<&F::Raw> = raw.iter().rev().collect();
        assert_lanes(
            simd,
            F::load_raw::<2>(simd, &reversed),
            "reversed raw a",
            |i| ra[lanes - 1 - i],
        );
        F::mul(a, simd, b).store_raw::<TIGHT>(simd, &mut raw);
        let ordered: Vec<&F::Raw> = raw.iter().collect();
        let loaded = F::load_raw::<TIGHT>(simd, &ordered);
        assert_lanes(simd, loaded, "raw ab", rab);
        assert_lanes(simd, F::mul(loaded, simd, c), "raw ab * c", |i| {
            reference::mul(rab(i), rc[i])
        });
        Ok(())
    }

    fn values<S: Simd, F: Field<S>>(simd: S, u: &mut Unstructured<'_>) -> arbitrary::Result<()> {
        let (a, ra) = draw::<S, F>(simd, u)?;
        let (b, rb) = draw::<S, F>(simd, u)?;
        let (c, rc) = draw::<S, F>(simd, u)?;
        assert_lanes(simd, F::mul(a, simd, b), "a * b", |i| {
            reference::mul(ra[i], rb[i])
        });
        assert_lanes(simd, a.add(simd, b), "a + b", |i| {
            reference::add(ra[i], rb[i])
        });
        assert_lanes(simd, a.double(simd), "2a", |i| reference::add(ra[i], ra[i]));
        assert_lanes(simd, a.mul_small::<1>(simd), "1a", |i| ra[i]);
        assert_lanes(simd, a.mul_small::<3>(simd), "3a", |i| {
            reference::mul(ra[i], small(3))
        });
        let r12 = |i: usize| reference::mul(ra[i], small(12));
        let scaled = a.mul_small::<12>(simd);
        assert_lanes(simd, scaled, "12a", r12);
        // A carried multiple is a valid subtrahend and factor.
        let scaled = scaled.carry(simd);
        assert_lanes(simd, b.sub::<{ 12 * 17 }>(simd, scaled), "b - 12a", |i| {
            reference::sub(rb[i], r12(i))
        });
        assert_lanes(simd, F::mul(scaled, simd, b), "12a * b", |i| {
            reference::mul(r12(i), rb[i])
        });
        assert_lanes(simd, a.sub::<3>(simd, b), "a - b", |i| {
            reference::sub(ra[i], rb[i])
        });
        assert_lanes(simd, a.neg::<3>(simd), "-a", |i| reference::neg(ra[i]));
        // Sums of up to sixteen values multiply once readied.
        let mut factor = a;
        for _ in 1..16 {
            // Keep additions within the representation's limb limits.
            factor = factor.add(simd, a).ready::<16>(simd);
        }
        assert_lanes(
            simd,
            F::mul(factor.ready::<16>(simd), simd, b),
            "16a * b",
            |i| reference::mul(reference::mul(ra[i], small(16)), rb[i]),
        );
        let sum_ab = a.add(simd, b).ready::<2>(simd);
        assert_lanes(simd, F::mul(sum_ab, simd, c), "(a + b) * c", |i| {
            reference::mul(reference::add(ra[i], rb[i]), rc[i])
        });
        Ok(())
    }

    fn products<S: Simd, F: Field<S>>(simd: S, u: &mut Unstructured<'_>) -> arbitrary::Result<()> {
        let (a, ra) = draw::<S, F>(simd, u)?;
        let (b, rb) = draw::<S, F>(simd, u)?;
        let (c, rc) = draw::<S, F>(simd, u)?;
        let (d, rd) = draw::<S, F>(simd, u)?;
        let mul = |x: &[Element], y: &[Element], i: usize| reference::mul(x[i], y[i]);
        let rab = |i| mul(&ra, &rb, i);
        let rcd = |i| mul(&rc, &rd, i);
        let ab = a.product(simd, b);
        let cd = c.product(simd, d);
        assert_lanes(simd, F::reduce(simd, ab), "reduce(a * b)", rab);
        assert_lanes(simd, F::reduce(simd, F::lift(a, simd)), "lift(a)", |i| {
            ra[i]
        });
        let sum = |i| reference::add(rab(i), rcd(i));
        let difference = |i| reference::sub(rab(i), rcd(i));
        let cross = |i| reference::add(mul(&ra, &rd, i), mul(&rc, &rb, i));
        assert_lanes(
            simd,
            F::reduce(simd, F::accumulate(simd, ab, cd)),
            "ab + cd",
            sum,
        );
        assert_lanes(
            simd,
            F::reduce(simd, F::product_sub::<64>(simd, ab, cd)),
            "ab - cd",
            difference,
        );
        assert_lanes(
            simd,
            F::reduce_signed::<64>(simd, F::cross(simd, [a, c], [b, d], ab, cd)),
            "cross",
            cross,
        );
        assert_lanes(
            simd,
            F::reduce(simd, F::accumulate_product(simd, ab, c, d)),
            "ab + c * d",
            sum,
        );
        // (a + c i)(b + d i) = ab - cd + (ad + cb) i, accumulated into itself and subtracted
        // from the double.
        let quadratic = F::quadratic(simd, [a, c], [b, d]);
        assert_lanes(
            simd,
            F::reduce_signed::<64>(simd, quadratic[0]),
            "real",
            difference,
        );
        assert_lanes(
            simd,
            F::reduce_signed::<64>(simd, quadratic[1]),
            "imaginary",
            cross,
        );
        let doubled = F::accumulate_quadratic(simd, quadratic, [a, c], [b, d]);
        assert_lanes(
            simd,
            F::reduce_signed::<64>(simd, doubled[0]),
            "2 real",
            |i| reference::add(difference(i), difference(i)),
        );
        assert_lanes(
            simd,
            F::reduce_signed::<64>(simd, doubled[1]),
            "2 imaginary",
            |i| reference::add(cross(i), cross(i)),
        );
        let single = F::subtract_quadratic(simd, doubled, [a, c], [b, d]);
        assert_lanes(
            simd,
            F::reduce_signed::<64>(simd, single[0]),
            "real again",
            difference,
        );
        assert_lanes(
            simd,
            F::reduce_signed::<64>(simd, single[1]),
            "imaginary again",
            cross,
        );
        Ok(())
    }

    fn accumulation<S: Simd, F: Field<S>>(
        simd: S,
        u: &mut Unstructured<'_>,
    ) -> arbitrary::Result<()> {
        let (a, ra) = draw::<S, F>(simd, u)?;
        let (b, rb) = draw::<S, F>(simd, u)?;
        let (c, rc) = draw::<S, F>(simd, u)?;
        let (d, rd) = draw::<S, F>(simd, u)?;
        let rab = |i: usize| reference::mul(ra[i], rb[i]);
        let rcd = |i: usize| reference::mul(rc[i], rd[i]);
        let ab = a.product(simd, b);
        let cd = c.product(simd, d);
        // A sum of PRODUCTS products reduces, and is a valid subtrahend.
        let times = |n: usize, i| reference::mul(rab(i), small(n as u64));
        let mut full = ab;
        for _ in 1..F::PRODUCTS {
            full = F::accumulate(simd, full, ab);
        }
        assert_lanes(
            simd,
            F::reduce(simd, F::product_sub::<64>(simd, ab, full)),
            "ab - PRODUCTS ab",
            |i| reference::sub(rab(i), times(F::PRODUCTS, i)),
        );
        let reduced = F::reduce(simd, full);
        assert_lanes(simd, reduced, "PRODUCTS ab", |i| times(F::PRODUCTS, i));
        assert_lanes(
            simd,
            F::mul(reduced.ready::<1>(simd), simd, a),
            "PRODUCTS ab * a",
            |i| reference::mul(times(F::PRODUCTS, i), ra[i]),
        );
        // A carried sum of eight products, the fewest any representation accepts, accumulates
        // seven more, and a tight reduction bounds the result whatever the sum's bound.
        let mut long = ab;
        for _ in 1..8 {
            long = F::accumulate(simd, long, ab);
        }
        long = F::carry_product(simd, long);
        for _ in 1..8 {
            long = F::accumulate(simd, long, ab);
        }
        let tight = F::reduce_tight(simd, long);
        assert_lanes(simd, tight, "tight 15 ab", |i| times(15, i));
        // Debug counters reject a tight result whose bound exceeds TIGHT.
        let _ = tight.neg::<{ TIGHT + 1 }>(simd);
        let tight = F::reduce_signed_tight::<64>(
            simd,
            Signed {
                pos: long,
                neg: Some(cd),
            },
        );
        assert_lanes(simd, tight, "tight 15 ab - cd", |i| {
            reference::sub(times(15, i), rcd(i))
        });
        // Debug counters reject a tight result whose bound exceeds TIGHT.
        let _ = tight.neg::<{ TIGHT + 1 }>(simd);
        assert_lanes(
            simd,
            F::reduce_signed_tight::<64>(simd, Signed::positive(ab)),
            "tight ab",
            rab,
        );
        Ok(())
    }

    fn inverse<S: Simd, F: Field<S>>(simd: S, u: &mut Unstructured<'_>) -> arbitrary::Result<()> {
        let (a, ra) = draw::<S, F>(simd, u)?;
        let inverse = a.invert(simd);
        let inverses: Vec<Element> = ra.iter().map(|a| reference::invert(*a)).collect();
        assert_lanes(simd, inverse, "1 / a", |i| inverses[i]);
        assert_lanes(simd, F::mul(inverse, simd, a), "a / a", |i| {
            if ra[i] == reference::ZERO {
                reference::ZERO
            } else {
                reference::ONE
            }
        });
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use commonware_invariants::minifuzz;

        #[test]
        fn minifuzz_load_store() {
            minifuzz::test(|u| Plan::LoadStore.run(u));
        }

        #[test]
        fn minifuzz_values() {
            minifuzz::test(|u| Plan::Values.run(u));
        }

        #[test]
        fn minifuzz_products() {
            minifuzz::test(|u| Plan::Products.run(u));
        }

        #[test]
        fn minifuzz_accumulation() {
            minifuzz::test(|u| Plan::Accumulation.run(u));
        }

        #[test]
        fn minifuzz_inverse() {
            minifuzz::test(|u| Plan::Inverse.run(u));
        }
    }
}
