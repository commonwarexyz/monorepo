//! The quadratic extension `Fp2 = Fp[i] / (i^2 + 1)`, over any base field representation.
//!
//! An [`Fp2`] holds two base field values, so it holds as many extension elements as its base
//! field values hold elements, one per lane. Its arithmetic runs once over every representation of
//! the [base field arithmetic](super::arithmetic). A [`Product`] holds a [`Signed`] sum of base
//! field products in each component, so sums and differences of extension products share
//! reductions, and subtracting one never adds a bias until it is reduced.
//!
//! # Bounds
//!
//! Each component keeps its own integer and limb bounds under the rules of the
//! [base field arithmetic](super::arithmetic), and every operation's requirements apply to the
//! components it uses. Value operations ([`add`](Fp2::add), [`double`](Fp2::double),
//! [`mul_small`](Fp2::mul_small), [`sub`](Fp2::sub), [`neg`](Fp2::neg), [`carry`](Fp2::carry),
//! and [`ready`](Fp2::ready)) apply the base rule to each component. The others combine
//! components as follows, for factors with component integer bounds `A0`, `A1` and `B0`, `B1`,
//! and `E(A, B) = ceil(A * B / 2048) + 1` as in the base field:
//!
//! | Operation | Requirements | Positional integer and limb bounds | RNS integer bounds |
//! |---|---|---|---|
//! | [`conjugate::<K>`](Fp2::conjugate) | `neg::<K>` of `c1` | `c0` unchanged, `c1` is `(K, 3)` | `c0` unchanged, `c1` is `K` |
//! | [`mul_by_nonresidue::<K>`](Fp2::mul_by_nonresidue) | `c0.sub::<K>(c1)` | `(A0 + K, L0 + 3)`, `(A0 + A1, L0 + L1)` | `A0 + K`, `A0 + A1` |
//! | [`product`](Fp2::product) | Component limb bounds `1` | `c0`: `E(A0, B0)` less `E(A1, B1)`; `c1`: `E(A0 + A1, B0 + B1)` less `E(A0, B0) + E(A1, B1)` | `c0`: `A0 * B0` less `A1 * B1`; `c1`: `A0 * B1 + A1 * B0` |
//! | [`product_schoolbook`](Fp2::product_schoolbook) | [`Field::product`] of each pair of components | `c0`: `E(A0, B0)` less `E(A1, B1)`; `c1`: `E(A0, B1) + E(A1, B0)` | Same as [`product`](Fp2::product) |
//! | [`square_product::<K>`](Fp2::square_product) | Component limb bounds `1`; `c0.sub::<K>(c1)` | `E(A0 + A1, A0 + K)`, `E(2 * A0, A1)` | `(A0 + A1) * (A0 + K)`, `2 * A0 * A1` |
//! | [`product_base`](Fp2::product_base) | [`Field::product`] of each component | `E(A0, B)`, `E(A1, B)` | `A0 * B`, `A1 * B` |
//!
//! Products list positive sums, less any negative sums; eager products have limb bound `1` per
//! term and wide products one term per product. [`accumulate`](Fp2::accumulate) adds the positive
//! sums and the negative sums of each component. [`product_sub`](Fp2::product_sub) adds the
//! subtrahend's negative sums to the positive sums and its positive sums to the negative sums,
//! and [`product_mul_by_nonresidue`](Fp2::product_mul_by_nonresidue) rearranges them the same way,
//! so neither adds a bias. [`accumulate_product`](Fp2::accumulate_product) and
//! [`subtract_product`](Fp2::subtract_product) add a product of two elements to a sum, or
//! subtract it, with the bounds of [`product`](Fp2::product) followed by
//! [`accumulate`](Fp2::accumulate) or [`product_sub`](Fp2::product_sub); residues multiply-add
//! into the sums without forming the product. [`lift`](Fp2::lift) gives positive sums with the
//! value's bounds.
//!
//! [`reduce::<K>`](Fp2::reduce) applies [`Field::reduce_signed`] with the bias `K` to each
//! component. A positional negative sum must be below `K`, and the component returns the positive
//! sum's integer bound plus `K` with limb bound `1`. A wide negative sum must be at most `295936`,
//! and the positive sum plus `295936` at most `645173`; the component reduces to at most `17`.
//! Components without negative sums reduce without the bias. [`mul::<K>`](Fp2::mul) reduces a
//! product with the bias `K`, and [`square`](Fp2::square) and [`mul_base`](Fp2::mul_base) reduce
//! products without negative sums.
//! [`reduce_tight::<K>`](Fp2::reduce_tight) applies [`Field::reduce_signed_tight`] instead, so the
//! same requirements return components with integer bound at most [`TIGHT`], and
//! [`carry_product`](Fp2::carry_product) carries every sum as for [`Field::carry_product`].
//! [`invert`](Fp2::invert) accepts components with limb bound `1` and integer bound at most `TIGHT`
//! and returns tight components.
//!
//! For example, components with limb bound `1` and integer bound at most `77` multiply with the
//! bias `64` to components with integer bound at most `77` in every representation, so
//! multiplications chain without carrying between them.
//!
//! Debug builds keep products and reductions as calls so that chained arithmetic fits in a stack
//! frame.

use super::{
    arithmetic::{Field, Signed, TIGHT, unroll},
    fp::{self, BYTES as FP_BYTES, WORDS},
};
use commonware_simd::Simd;

/// Number of bytes in an element's big-endian encoding: `c1` followed by `c0`.
pub const BYTES: usize = 2 * FP_BYTES;

/// Returns the encoding of `c0 + c1 i` for little-endian words.
pub(crate) const fn encode(c0: [u64; WORDS], c1: [u64; WORDS]) -> [u8; BYTES] {
    let (c0, c1) = (fp::encode(c0), fp::encode(c1));
    let mut bytes = [0; BYTES];
    let mut i = 0;
    while i < FP_BYTES {
        bytes[i] = c1[i];
        bytes[FP_BYTES + i] = c0[i];
        i += 1;
    }
    bytes
}

/// Signed sums of products of elements in the representation `F` on backend `S`.
pub type Product<F, S> = Fp2<Signed<<F as Field<S>>::Product>>;

/// Largest number of elements in a value, the widest representation's lane count.
const MAX_LANES: usize = 16;

/// Elements `c0 + c1 * i`, one per lane of the components.
///
/// Components are base field values or, for sums of products, base field products. See the
/// [module documentation](self) for the bounds each operation requires.
#[derive(Clone, Copy)]
pub struct Fp2<T> {
    /// The real components.
    pub c0: T,
    /// The imaginary components.
    pub c1: T,
}

impl<F> Fp2<F> {
    /// Loads up to one element per lane, filling the remaining lanes with `fill`.
    ///
    /// Interprets each component modulo `p` and returns the base field's initial bounds.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn load<S: Simd>(simd: S, elements: &[[u8; BYTES]], fill: &[u8; BYTES]) -> Self
    where
        F: Field<S>,
    {
        const { assert!(F::LANES <= MAX_LANES) };
        let mut components = [[[0; FP_BYTES]; MAX_LANES]; 2];
        let lanes = elements.len().min(F::LANES);
        for (lane, element) in elements[..lanes].iter().enumerate() {
            let (c1, c0) = split(element);
            components[0][lane] = *c0;
            components[1][lane] = *c1;
        }
        let (fill1, fill0) = split(fill);
        Self {
            c0: F::load(simd, &components[0][..lanes], fill0),
            c1: F::load(simd, &components[1][..lanes], fill1),
        }
    }

    /// Stores the canonical value of each lane, dropping lanes beyond `elements`.
    ///
    /// Requires valid value bounds. Entries beyond [`Field::LANES`] are unchanged.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn store<S: Simd>(self, simd: S, elements: &mut [[u8; BYTES]])
    where
        F: Field<S>,
    {
        const { assert!(F::LANES <= MAX_LANES) };
        let mut components = [[[0; FP_BYTES]; MAX_LANES]; 2];
        let lanes = elements.len().min(F::LANES);
        self.c0.store(simd, &mut components[0][..lanes]);
        self.c1.store(simd, &mut components[1][..lanes]);
        for (lane, element) in elements[..lanes].iter_mut().enumerate() {
            let (c1, c0) = element.split_at_mut(FP_BYTES);
            c0.copy_from_slice(&components[0][lane]);
            c1.copy_from_slice(&components[1][lane]);
        }
    }

    /// Returns `self + rhs`, without reducing.
    #[inline(always)]
    pub fn add<S: Simd>(self, simd: S, rhs: Self) -> Self
    where
        F: Field<S>,
    {
        Self {
            c0: self.c0.add(simd, rhs.c0),
            c1: self.c1.add(simd, rhs.c1),
        }
    }

    /// Stores each lane's components in the representation's own form, as for
    /// [`Field::store_raw`], dropping lanes beyond `elements`.
    #[inline(always)]
    pub fn store_raw<const A: u64, S: Simd>(self, simd: S, elements: &mut [[F::Raw; 2]])
    where
        F: Field<S>,
    {
        const { assert!(F::LANES <= MAX_LANES) };
        let mut components = [[F::Raw::default(); MAX_LANES]; 2];
        let lanes = elements.len().min(F::LANES);
        self.c0.store_raw::<A>(simd, &mut components[0][..lanes]);
        self.c1.store_raw::<A>(simd, &mut components[1][..lanes]);
        for (lane, element) in elements[..lanes].iter_mut().enumerate() {
            *element = [components[0][lane], components[1][lane]];
        }
    }

    /// Loads lane `i` from `elements[i]`, as [`Self::store_raw`] stored it, for at least
    /// [`Field::LANES`] entries.
    #[inline(always)]
    pub fn load_raw<const A: u64, S: Simd>(simd: S, elements: &[&[F::Raw; 2]]) -> Self
    where
        F: Field<S>,
    {
        const { assert!(F::LANES <= MAX_LANES) };
        let component = |i: usize| {
            let mut lanes = [&elements[0][i]; MAX_LANES];
            for (lane, element) in lanes.iter_mut().zip(elements).take(F::LANES) {
                *lane = &element[i];
            }
            F::load_raw::<A>(simd, &lanes)
        };
        Self {
            c0: component(0),
            c1: component(1),
        }
    }

    /// Returns `self + self`, without reducing.
    #[inline(always)]
    pub fn double<S: Simd>(self, simd: S) -> Self
    where
        F: Field<S>,
    {
        Self {
            c0: self.c0.double(simd),
            c1: self.c1.double(simd),
        }
    }

    /// Returns `C * self` for a small positive constant `C`, without reducing.
    #[inline(always)]
    pub fn mul_small<const C: u64, S: Simd>(self, simd: S) -> Self
    where
        F: Field<S>,
    {
        Self {
            c0: self.c0.mul_small::<C>(simd),
            c1: self.c1.mul_small::<C>(simd),
        }
    }

    /// Returns `self + K * p - rhs` in each component, without reducing.
    #[inline(always)]
    pub fn sub<const K: u64, S: Simd>(self, simd: S, rhs: Self) -> Self
    where
        F: Field<S>,
    {
        Self {
            c0: self.c0.sub::<K>(simd, rhs.c0),
            c1: self.c1.sub::<K>(simd, rhs.c1),
        }
    }

    /// Returns `K * p - self` in each component, without reducing.
    #[inline(always)]
    pub fn neg<const K: u64, S: Simd>(self, simd: S) -> Self
    where
        F: Field<S>,
    {
        Self {
            c0: self.c0.neg::<K>(simd),
            c1: self.c1.neg::<K>(simd),
        }
    }

    /// Returns the conjugate `c0 - c1 * i`, without reducing.
    ///
    /// The bias `K` must cover `c1` as for [`Field::neg`].
    #[inline(always)]
    pub fn conjugate<const K: u64, S: Simd>(self, simd: S) -> Self
    where
        F: Field<S>,
    {
        Self {
            c0: self.c0,
            c1: self.c1.neg::<K>(simd),
        }
    }

    /// Returns `self * (1 + i)`, the non-residue that defines the higher extensions, without
    /// reducing.
    ///
    /// The bias `K` must cover `c1` as for [`Field::sub`].
    #[inline(always)]
    pub fn mul_by_nonresidue<const K: u64, S: Simd>(self, simd: S) -> Self
    where
        F: Field<S>,
    {
        Self {
            c0: self.c0.sub::<K>(simd, self.c1),
            c1: self.c0.add(simd, self.c1),
        }
    }

    /// Returns `rhs` in every lane whose bit is set in `lanes`, and `self` in the others, as
    /// [`Field::select`] does for each component.
    #[inline(always)]
    pub fn select<S: Simd>(self, simd: S, rhs: Self, lanes: u64) -> Self
    where
        F: Field<S>,
    {
        Self {
            c0: self.c0.select(simd, rhs.c0, lanes),
            c1: self.c1.select(simd, rhs.c1, lanes),
        }
    }

    /// Carries every positional limb of both components to limb bound `1`, without reducing.
    #[inline(always)]
    pub fn carry<S: Simd>(self, simd: S) -> Self
    where
        F: Field<S>,
    {
        Self {
            c0: self.c0.carry(simd),
            c1: self.c1.carry(simd),
        }
    }

    /// Prepares both components for multiplication using a static positional limb bound `U`.
    ///
    /// [`Self::product`] and [`Self::square_product`] require limb bound `1`, so prepare their
    /// operands with `U = 1` or [`Self::carry`]. [`Self::product_base`] accepts any ready limbs.
    #[inline(always)]
    pub fn ready<const U: u64, S: Simd>(self, simd: S) -> Self
    where
        F: Field<S>,
    {
        Self {
            c0: self.c0.ready::<U>(simd),
            c1: self.c1.ready::<U>(simd),
        }
    }

    /// Forms the product `self * rhs`.
    ///
    /// This is [`Field::quadratic`]: the real component is `a0 b0` less `a1 b1`, and the imaginary
    /// component comes from [`Field::cross`], which reuses both known products. Both factors'
    /// components must have limb bound `1`.
    /// Runs through [`Field::kernel`], as its own kernel unless the representation inlines it.
    #[inline(always)]
    pub fn product<S: Simd>(self, simd: S, rhs: Self) -> Product<F, S>
    where
        F: Field<S>,
    {
        F::kernel(
            simd,
            #[inline(always)]
            move |simd: S| {
                let [c0, c1] = F::quadratic(simd, [self.c0, self.c1], [rhs.c0, rhs.c1]);
                Fp2 { c0, c1 }
            },
        )
    }

    /// Returns `sum + a * b`, as [`Field::accumulate_quadratic`] does: the product of
    /// [`Self::product`] accumulated into each component of `sum`.
    #[inline(always)]
    pub fn accumulate_product<S: Simd>(
        simd: S,
        sum: Product<F, S>,
        a: Self,
        b: Self,
    ) -> Product<F, S>
    where
        F: Field<S>,
    {
        let [c0, c1] = F::accumulate_quadratic(simd, [sum.c0, sum.c1], [a.c0, a.c1], [b.c0, b.c1]);
        Fp2 { c0, c1 }
    }

    /// Returns `sum - a * b`, as [`Field::subtract_quadratic`] does: the product of
    /// [`Self::product`] subtracted from each component of `sum` without a bias.
    #[inline(always)]
    pub fn subtract_product<S: Simd>(simd: S, sum: Product<F, S>, a: Self, b: Self) -> Product<F, S>
    where
        F: Field<S>,
    {
        let [c0, c1] = F::subtract_quadratic(simd, [sum.c0, sum.c1], [a.c0, a.c1], [b.c0, b.c1]);
        Fp2 { c0, c1 }
    }

    /// Returns `self * rhs`, under the requirements of [`Self::product`] and [`Self::reduce`] with
    /// the bias `K`.
    #[inline(always)]
    pub fn mul<const K: u64, S: Simd>(self, simd: S, rhs: Self) -> Self
    where
        F: Field<S>,
    {
        Self::reduce::<K, S>(simd, self.product(simd, rhs))
    }

    /// Forms the product `self * rhs` with four base field products.
    ///
    /// The real component is `a0 b0` less `a1 b1`, and the imaginary component is
    /// `a0 b1 + a1 b0`, accumulated as it forms. Unlike [`Self::product`], no product takes a sum
    /// of components, so large factors keep smaller positional bounds at the cost of one more
    /// positional product; residues form the same products either way. Every factor must be
    /// ready, as for [`Field::product`].
    /// Runs through [`Field::kernel`], as its own kernel unless the representation inlines it.
    #[inline(always)]
    pub fn product_schoolbook<S: Simd>(self, simd: S, rhs: Self) -> Product<F, S>
    where
        F: Field<S>,
    {
        F::kernel(
            simd,
            #[inline(always)]
            move |simd: S| self.product_schoolbook_body(simd, rhs),
        )
    }

    /// Body of [`Self::product_schoolbook`].
    #[inline(always)]
    fn product_schoolbook_body<S: Simd>(self, simd: S, rhs: Self) -> Product<F, S>
    where
        F: Field<S>,
    {
        Fp2 {
            c0: Signed {
                pos: self.c0.product(simd, rhs.c0),
                neg: Some(self.c1.product(simd, rhs.c1)),
            },
            c1: Signed::positive(F::accumulate_product(
                simd,
                self.c0.product(simd, rhs.c1),
                self.c1,
                rhs.c0,
            )),
        }
    }

    /// Forms the product `self * self` with two base field products.
    ///
    /// The real component is `(c0 + c1)(c0 - c1)` and the imaginary component is `(2 c0) c1`.
    /// Both components must have limb bound `1`, and the bias `K` must cover `c1` as for
    /// [`Field::sub`].
    /// Runs through [`Field::kernel`], as its own kernel unless the representation inlines it.
    #[inline(always)]
    pub fn square_product<const K: u64, S: Simd>(self, simd: S) -> Product<F, S>
    where
        F: Field<S>,
    {
        F::kernel(
            simd,
            #[inline(always)]
            move |simd: S| self.square_product_body::<K, S>(simd),
        )
    }

    /// Body of [`Self::square_product`].
    #[inline(always)]
    fn square_product_body<const K: u64, S: Simd>(self, simd: S) -> Product<F, S>
    where
        F: Field<S>,
    {
        let sum = self.c0.add(simd, self.c1).ready::<2>(simd);
        let difference = self.c0.sub::<K>(simd, self.c1).ready::<4>(simd);
        let c0 = self.c0.double(simd).ready::<2>(simd);
        Fp2 {
            c0: Signed::positive(sum.product(simd, difference)),
            c1: Signed::positive(c0.product(simd, self.c1)),
        }
    }

    /// Returns `self * self`, under the requirements of [`Self::square_product`].
    #[cfg_attr(
        not(any(test, feature = "fuzz")),
        expect(
            dead_code,
            reason = "Completes the documented arithmetic, which the tests check."
        )
    )]
    #[inline(always)]
    pub fn square<const K: u64, S: Simd>(self, simd: S) -> Self
    where
        F: Field<S>,
    {
        Self::reduce_positive(simd, self.square_product::<K, S>(simd))
    }

    /// Forms the product of `self` and a base field value.
    ///
    /// Every factor must be ready, as for [`Field::product`].
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn product_base<S: Simd>(self, simd: S, rhs: F) -> Product<F, S>
    where
        F: Field<S>,
    {
        Fp2 {
            c0: Signed::positive(self.c0.product(simd, rhs)),
            c1: Signed::positive(self.c1.product(simd, rhs)),
        }
    }

    /// Returns the product of `self` and a base field value, under the requirements of
    /// [`Self::product_base`].
    #[inline(always)]
    pub fn mul_base<S: Simd>(self, simd: S, rhs: F) -> Self
    where
        F: Field<S>,
    {
        Self::reduce_positive(simd, self.product_base(simd, rhs))
    }

    /// Returns `a + b` for products.
    ///
    /// Adds the positive sums and the negative sums of each component.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn accumulate<S: Simd>(simd: S, a: Product<F, S>, b: Product<F, S>) -> Product<F, S>
    where
        F: Field<S>,
    {
        Fp2 {
            c0: a.c0.add::<S, F>(simd, b.c0),
            c1: a.c1.add::<S, F>(simd, b.c1),
        }
    }

    /// Returns `a - b` for products, without a bias.
    ///
    /// Adds the negative sums of `b` to the positive sums of `a`, and the positive sums of `b`
    /// to the negative sums of `a`.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn product_sub<S: Simd>(simd: S, a: Product<F, S>, b: Product<F, S>) -> Product<F, S>
    where
        F: Field<S>,
    {
        Fp2 {
            c0: a.c0.sub::<S, F>(simd, b.c0),
            c1: a.c1.sub::<S, F>(simd, b.c1),
        }
    }

    /// Returns `product * (1 + i)`, without a bias.
    ///
    /// The real component is `c0 - c1` and the imaginary component `c0 + c1`, each formed as in
    /// [`Self::product_sub`] and [`Self::accumulate`].
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn product_mul_by_nonresidue<S: Simd>(simd: S, product: Product<F, S>) -> Product<F, S>
    where
        F: Field<S>,
    {
        Fp2 {
            c0: product.c0.sub::<S, F>(simd, product.c1),
            c1: product.c0.add::<S, F>(simd, product.c1),
        }
    }

    /// Lifts `self` into the product representation without changing its value.
    #[inline(always)]
    pub fn lift<S: Simd>(self, simd: S) -> Product<F, S>
    where
        F: Field<S>,
    {
        Fp2 {
            c0: Signed::positive(self.c0.lift(simd)),
            c1: Signed::positive(self.c1.lift(simd)),
        }
    }

    /// Returns `sum + value`, lifting each component of the value into the positive sum of the
    /// matching component, as [`Field::accumulate_lift`] does.
    #[inline(always)]
    pub fn accumulate_lift<S: Simd>(simd: S, sum: Product<F, S>, value: Self) -> Product<F, S>
    where
        F: Field<S>,
    {
        Fp2 {
            c0: Signed {
                pos: F::accumulate_lift(simd, sum.c0.pos, value.c0),
                neg: sum.c0.neg,
            },
            c1: Signed {
                pos: F::accumulate_lift(simd, sum.c1.pos, value.c1),
                neg: sum.c1.neg,
            },
        }
    }

    /// Reduces both components of a product, as for [`Field::reduce_signed`] with the bias `K`.
    /// Runs through [`Field::kernel`], as its own kernel unless the representation inlines it.
    #[inline(always)]
    pub fn reduce<const K: u64, S: Simd>(simd: S, product: Product<F, S>) -> Self
    where
        F: Field<S>,
    {
        F::kernel(
            simd,
            #[inline(always)]
            move |simd: S| Self::reduce_body::<K, S>(simd, product),
        )
    }

    /// Body of [`Self::reduce`].
    #[inline(always)]
    fn reduce_body<const K: u64, S: Simd>(simd: S, product: Product<F, S>) -> Self
    where
        F: Field<S>,
    {
        let sums = [product.c0, product.c1];
        let [c0, c1] = F::reduce_each_signed::<2, K>(
            simd,
            #[inline(always)]
            |i| sums[i],
        );
        Self { c0, c1 }
    }

    /// Reduces both components of a product without negative sums.
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn reduce_positive<S: Simd>(simd: S, product: Product<F, S>) -> Self
    where
        F: Field<S>,
    {
        debug_assert!(product.c0.neg.is_none() && product.c1.neg.is_none());
        let sums = [product.c0.pos, product.c1.pos];
        let [c0, c1] = F::reduce_each::<2>(
            simd,
            #[inline(always)]
            |i| sums[i],
        );
        Self { c0, c1 }
    }

    /// Carries every sum of a product, as for [`Field::carry_product`].
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn carry_product<S: Simd>(simd: S, product: Product<F, S>) -> Product<F, S>
    where
        F: Field<S>,
    {
        Fp2 {
            c0: product.c0.carry::<S, F>(simd),
            c1: product.c1.carry::<S, F>(simd),
        }
    }

    /// Reduces both components of a product to integer bound at most [`TIGHT`], as for
    /// [`Field::reduce_signed_tight`] with the bias `K`.
    /// Runs through [`Field::kernel`], as its own kernel unless the representation inlines it.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn reduce_tight<const K: u64, S: Simd>(simd: S, product: Product<F, S>) -> Self
    where
        F: Field<S>,
    {
        F::kernel(
            simd,
            #[inline(always)]
            move |simd: S| {
                let sums = [product.c0, product.c1];
                let [c0, c1] = F::reduce_each_signed_tight::<2, K>(
                    simd,
                    #[inline(always)]
                    |i| sums[i],
                );
                Self { c0, c1 }
            },
        )
    }

    /// Returns `product(0)`, ..., `product(N - 1)`, each reduced as [`Self::reduce_tight`] does
    /// with the bias `K`, for their `C = 2 * N` components.
    ///
    /// Forms each product once, in order. When [`Field::INTERLEAVE`] covers the `C` components,
    /// they reduce in one call of [`Field::reduce_each_signed_tight`]; otherwise each product
    /// reduces right after it is formed.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub(super) fn reduce_each_tight<const N: usize, const C: usize, const K: u64, S: Simd>(
        simd: S,
        mut product: impl FnMut(usize) -> Product<F, S>,
    ) -> [Self; N]
    where
        F: Field<S>,
    {
        const { assert!(N > 0 && C == 2 * N) };
        if C > F::INTERLEAVE {
            let mut reduced = [Self::reduce_tight::<K, S>(simd, product(0)); N];
            unroll::<N>(
                #[inline(always)]
                |k| {
                    if k > 0 {
                        reduced[k] = Self::reduce_tight::<K, S>(simd, product(k));
                    }
                },
            );
            return reduced;
        }
        // Components are requested in order, so each product forms with its real component and
        // holds its imaginary component for the next request.
        let mut imaginary = None;
        let components = F::reduce_each_signed_tight::<C, K>(
            simd,
            #[inline(always)]
            |i| {
                if i % 2 == 0 {
                    let Fp2 { c0, c1 } = product(i / 2);
                    imaginary = Some(c1);
                    c0
                } else {
                    imaginary.take().expect("the real component comes first")
                }
            },
        );
        let mut reduced = [Self {
            c0: components[0],
            c1: components[1],
        }; N];
        unroll::<N>(
            #[inline(always)]
            |k| {
                reduced[k] = Self {
                    c0: components[2 * k],
                    c1: components[2 * k + 1],
                };
            },
        );
        reduced
    }

    /// Returns the difference of each component's signed sums, as one sum of products per
    /// component, subtracting the negative sums once with the bias `K` as
    /// [`Signed::difference`] does: reducing the result as [`Field::reduce`] does is
    /// [`Self::reduce`] with the bias `K`.
    #[inline(always)]
    pub fn difference<const K: u64, S: Simd>(simd: S, product: Product<F, S>) -> Fp2<F::Product>
    where
        F: Field<S>,
    {
        Fp2 {
            c0: product.c0.difference::<S, F, K>(simd),
            c1: product.c1.difference::<S, F, K>(simd),
        }
    }

    /// Returns `sum(0)`, ..., `sum(N - 1)`, each a difference from [`Self::difference`] reduced
    /// as [`Field::reduce`] does, for their `C = 2 * N` components.
    ///
    /// Forms each sum once, in order. When [`Field::INTERLEAVE`] covers the `C` components, they
    /// reduce in one call of [`Field::reduce_each`], so formulas reduce every independent value
    /// of a stage at once, each with its own bias; otherwise each sum reduces right after it is
    /// formed.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn reduce_each<const N: usize, const C: usize, S: Simd>(
        simd: S,
        mut sum: impl FnMut(usize) -> Fp2<F::Product>,
    ) -> [Self; N]
    where
        F: Field<S>,
    {
        const { assert!(N > 0 && C == 2 * N) };
        if C > F::INTERLEAVE {
            let reduce = |sum: Fp2<F::Product>| Self {
                c0: F::reduce(simd, sum.c0),
                c1: F::reduce(simd, sum.c1),
            };
            let mut reduced = [reduce(sum(0)); N];
            unroll::<N>(
                #[inline(always)]
                |k| {
                    if k > 0 {
                        reduced[k] = reduce(sum(k));
                    }
                },
            );
            return reduced;
        }
        // Components are requested in order, so each sum forms with its real component and
        // holds its imaginary component for the next request.
        let mut imaginary = None;
        let components = F::reduce_each::<C>(
            simd,
            #[inline(always)]
            |i| {
                if i % 2 == 0 {
                    let Fp2 { c0, c1 } = sum(i / 2);
                    imaginary = Some(c1);
                    c0
                } else {
                    imaginary.take().expect("the real component comes first")
                }
            },
        );
        let mut reduced = [Self {
            c0: components[0],
            c1: components[1],
        }; N];
        unroll::<N>(
            #[inline(always)]
            |k| {
                reduced[k] = Self {
                    c0: components[2 * k],
                    c1: components[2 * k + 1],
                };
            },
        );
        reduced
    }

    /// Returns the inverse `(c0 - c1 i) / (c0^2 + c1^2)`, or zero for zero.
    ///
    /// Both components must have limb bound `1` and integer bound at most [`TIGHT`]; so do the
    /// result's. Inverts in the base field with [`Field::invert`].
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn invert<S: Simd>(self, simd: S) -> Self
    where
        F: Field<S>,
    {
        let norm = F::accumulate_product(simd, self.c0.product(simd, self.c0), self.c1, self.c1);
        let inverse = F::reduce_tight(simd, norm).invert(simd);
        let conjugate = self.conjugate::<{ TIGHT + 1 }, S>(simd).carry(simd);
        Self::reduce_tight::<1, S>(simd, conjugate.product_base(simd, inverse))
    }
}

/// Splits an element's encoding into its `c1` and `c0` encodings.
#[inline(always)]
fn split(element: &[u8; BYTES]) -> (&[u8; FP_BYTES], &[u8; FP_BYTES]) {
    let (c1, c0) = element
        .split_first_chunk::<FP_BYTES>()
        .expect("two components");
    (c1, c0.try_into().expect("two components"))
}

/// Reference arithmetic on elements with canonical components, for testing formulas.
#[cfg(any(test, feature = "fuzz"))]
pub(crate) mod reference {
    use super::{BYTES, FP_BYTES};
    use crate::core::field::fp::reference as fp;
    use arbitrary::Unstructured;

    /// An element `c0 + c1 i` as `(c0, c1)`, with canonical components.
    pub(crate) type Element = (fp::Element, fp::Element);

    /// Zero.
    pub(crate) const ZERO: Element = (fp::ZERO, fp::ZERO);

    /// One.
    pub(crate) const ONE: Element = (fp::ONE, fp::ZERO);

    /// `1 + i`, the nonresidue that defines the cubic extension.
    pub(crate) const NONRESIDUE: Element = (fp::ONE, fp::ONE);

    /// Returns the element of the base field with the integer value `n`.
    pub(crate) const fn small(n: u64) -> Element {
        ([n, 0, 0, 0, 0, 0], fp::ZERO)
    }

    /// Returns `a + b`.
    pub(crate) const fn add((a0, a1): Element, (b0, b1): Element) -> Element {
        (fp::add(a0, b0), fp::add(a1, b1))
    }

    /// Returns `-a`.
    pub(crate) const fn neg((a0, a1): Element) -> Element {
        (fp::neg(a0), fp::neg(a1))
    }

    /// Returns `a - b`.
    pub(crate) const fn sub((a0, a1): Element, (b0, b1): Element) -> Element {
        (fp::sub(a0, b0), fp::sub(a1, b1))
    }

    /// Returns `a * b`.
    pub(crate) const fn mul((a0, a1): Element, (b0, b1): Element) -> Element {
        (
            fp::sub(fp::mul(a0, b0), fp::mul(a1, b1)),
            fp::add(fp::mul(a0, b1), fp::mul(a1, b0)),
        )
    }

    /// Returns the conjugate `c0 - c1 i`.
    pub(crate) const fn conjugate((a0, a1): Element) -> Element {
        (a0, fp::neg(a1))
    }

    /// Returns the inverse of a nonzero `a`: its conjugate over its norm.
    pub(crate) fn invert((a0, a1): Element) -> Element {
        let norm = fp::add(fp::mul(a0, a0), fp::mul(a1, a1));
        let inverse = fp::invert(norm);
        (fp::mul(a0, inverse), fp::mul(fp::neg(a1), inverse))
    }

    /// Returns the residues of an encoding's components.
    pub(crate) fn decode(bytes: &[u8; BYTES]) -> Element {
        let (c1, c0) = super::split(bytes);
        (fp::reduce(c0), fp::reduce(c1))
    }

    /// Returns the encoding of an element, the imaginary component first.
    pub(crate) fn encode((c0, c1): Element) -> [u8; BYTES] {
        let mut bytes = [0; BYTES];
        bytes[..FP_BYTES].copy_from_slice(&fp::to_bytes(c1));
        bytes[FP_BYTES..].copy_from_slice(&fp::to_bytes(c0));
        bytes
    }

    /// Draws an element with canonical components, as [`fp::canonical`] draws each.
    pub(crate) fn canonical(u: &mut Unstructured<'_>) -> arbitrary::Result<Element> {
        Ok((fp::canonical(u)?, fp::canonical(u)?))
    }
}

/// Checks of [`Fp2`] arithmetic in every representation against the reference arithmetic.
#[cfg(any(test, feature = "fuzz"))]
pub mod fuzz {
    use super::{
        reference::{self, Element},
        *,
    };
    use crate::core::field::fp::testing::{self, Check};
    use arbitrary::{Arbitrary, Unstructured};
    use core::any::type_name;
    use std::vec;

    /// Largest component integer bound that multiplications preserve, in units of `p`.
    const BOUND: u64 = 77;

    /// Positional bias of every reduction, which covers the negative sums of these checks.
    const BIAS: u64 = 64;

    /// Multiplications in the chain of [`Plan::Chain`].
    const ROUNDS: usize = 8;

    /// A check of [`Fp2`] operations over a base field representation and on an emulated backend
    /// drawn from the input.
    #[derive(Clone, Copy, Debug, Arbitrary)]
    pub enum Plan {
        /// Checks loading, storing, and every value operation, including reduced products.
        Values,
        /// Checks sums and differences of products, which never stack subtraction biases.
        Products,
        /// Chains multiplications through the bound they preserve, mixing in the operations whose
        /// outputs exceed it before squaring them back down.
        Chain,
    }

    impl Plan {
        /// Runs the operation using the remaining input.
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
            let mut inputs = [[0; BYTES]; 4];
            for input in &mut inputs {
                // Components biased toward zero, one, and -1, so edge elements such as 0, 1, i,
                // and -1 - i appear.
                input[..FP_BYTES].copy_from_slice(&testing::bytes(u)?);
                input[FP_BYTES..].copy_from_slice(&testing::bytes(u)?);
            }
            match self {
                Self::Values => check_values::<S, F>(simd, &inputs),
                Self::Products => check_products::<S, F>(simd, &inputs),
                Self::Chain => check_chain::<S, F>(simd, &inputs),
            }
            Ok(())
        }
    }

    /// Asserts that the lane-0 value of `value` is `expected`.
    fn assert_value<S: Simd, F: Field<S>>(simd: S, value: Fp2<F>, label: &str, expected: Element) {
        let mut output = [[0; BYTES]];
        value.store(simd, &mut output);
        assert_eq!(
            output[0],
            reference::encode(expected),
            "{label} on {}",
            type_name::<F>()
        );
    }

    fn check_values<S: Simd, F: Field<S>>(simd: S, inputs: &[[u8; BYTES]; 4]) {
        let mut lanes = vec![[0; BYTES]; F::LANES + 1];
        Fp2::<F>::load(simd, &inputs[..1], &inputs[1]).store(simd, &mut lanes);
        let decoded = |input: &[u8; BYTES]| reference::encode(reference::decode(input));
        assert_eq!(
            lanes[0],
            decoded(&inputs[0]),
            "load on {}",
            type_name::<F>()
        );
        for lane in &lanes[1..F::LANES] {
            assert_eq!(*lane, decoded(&inputs[1]), "fill on {}", type_name::<F>());
        }
        assert_eq!(
            lanes[F::LANES],
            [0; BYTES],
            "store beyond lanes on {}",
            type_name::<F>()
        );
        let [a, b, ..] = inputs.map(|bytes| Fp2::<F>::load(simd, &[], &bytes));
        let [ra, rb, ..] = inputs.map(|bytes| reference::decode(&bytes));
        let i = (fp::reference::ZERO, fp::reference::ONE);
        assert_value(simd, a.add(simd, b), "a + b", reference::add(ra, rb));
        assert_value(simd, a.double(simd), "2a", reference::add(ra, ra));
        assert_value(
            simd,
            a.mul_small::<5, S>(simd),
            "5a",
            reference::mul(ra, reference::small(5)),
        );
        assert_value(
            simd,
            a.sub::<3, S>(simd, b),
            "a - b",
            reference::sub(ra, rb),
        );
        assert_value(simd, a.neg::<3, S>(simd), "-a", reference::neg(ra));
        assert_value(
            simd,
            a.conjugate::<3, S>(simd),
            "conjugate",
            reference::conjugate(ra),
        );
        assert_value(
            simd,
            a.mul_by_nonresidue::<3, S>(simd),
            "a (1 + i)",
            reference::mul(ra, reference::NONRESIDUE),
        );
        assert_value(
            simd,
            a.mul::<BIAS, S>(simd, b),
            "a * b",
            reference::mul(ra, rb),
        );
        assert_value(
            simd,
            Fp2::<F>::reduce::<BIAS, S>(simd, a.product_schoolbook(simd, b)),
            "schoolbook a * b",
            reference::mul(ra, rb),
        );
        let unit = Fp2::<F>::load(simd, &[], &reference::encode(i));
        assert_value(
            simd,
            unit.mul::<BIAS, S>(simd, a),
            "i * a",
            reference::mul(i, ra),
        );
        assert_value(simd, a.square::<3, S>(simd), "a^2", reference::mul(ra, ra));
        assert_value(
            simd,
            a.mul_base(simd, b.c0),
            "a * b.c0",
            reference::mul(ra, (rb.0, fp::reference::ZERO)),
        );
        assert_value(
            simd,
            Fp2::<F>::reduce::<BIAS, S>(simd, a.lift(simd)),
            "lift(a)",
            ra,
        );
    }

    fn check_products<S: Simd, F: Field<S>>(simd: S, inputs: &[[u8; BYTES]; 4]) {
        let [a, b, c, d] = inputs.map(|bytes| Fp2::<F>::load(simd, &[], &bytes));
        let [ra, rb, rc, rd] = inputs.map(|bytes| reference::decode(&bytes));
        let (ab, cd) = (a.product(simd, b), c.product(simd, d));
        let (rab, rcd) = (reference::mul(ra, rb), reference::mul(rc, rd));
        let reduce = |product| Fp2::<F>::reduce::<BIAS, S>(simd, product);
        assert_value(
            simd,
            reduce(Fp2::<F>::accumulate(simd, ab, cd)),
            "ab + cd",
            reference::add(rab, rcd),
        );
        assert_value(
            simd,
            reduce(Fp2::<F>::product_sub(simd, ab, c.lift(simd))),
            "ab - c",
            reference::sub(rab, rc),
        );
        assert_value(
            simd,
            reduce(Fp2::<F>::product_sub(simd, ab, c.product_base(simd, d.c0))),
            "ab - c * d.c0",
            reference::sub(rab, reference::mul(rc, (rd.0, fp::reference::ZERO))),
        );
        assert_value(
            simd,
            reduce(Fp2::<F>::product_sub(simd, ab, cd)),
            "ab - cd",
            reference::sub(rab, rcd),
        );
        // Products accumulate into sums as they form, and subtract from them.
        assert_value(
            simd,
            reduce(Fp2::<F>::accumulate_product(simd, ab, c, d)),
            "ab + c * d",
            reference::add(rab, rcd),
        );
        assert_value(
            simd,
            reduce(Fp2::<F>::subtract_product(simd, ab, c, d)),
            "ab - c * d",
            reference::sub(rab, rcd),
        );
        let accumulated = Fp2::<F>::accumulate_product(simd, cd, a, b);
        let accumulated = Fp2::<F>::subtract_product(simd, accumulated, c, d);
        let accumulated = Fp2::<F>::accumulate_product(simd, accumulated, a, b);
        assert_value(
            simd,
            reduce(accumulated),
            "cd + ab - cd + ab",
            reference::add(rab, rab),
        );
        // (ab - cd)(1 + i) - (ab + cd) - b^2, as formulas over extensions combine products.
        let difference = Fp2::<F>::product_sub(simd, ab, cd);
        let rotated = Fp2::<F>::product_mul_by_nonresidue(simd, difference);
        let sum = Fp2::<F>::accumulate(simd, ab, cd);
        let combined = Fp2::<F>::product_sub(simd, rotated, sum);
        let combined = Fp2::<F>::product_sub(simd, combined, b.square_product::<3, S>(simd));
        let rotated = reference::mul(reference::sub(rab, rcd), reference::NONRESIDUE);
        let expected = reference::sub(
            reference::sub(rotated, reference::add(rab, rcd)),
            reference::mul(rb, rb),
        );
        assert_value(simd, reduce(combined), "combined products", expected);
    }

    fn check_chain<S: Simd, F: Field<S>>(simd: S, inputs: &[[u8; BYTES]; 4]) {
        let [a, b, ..] = inputs.map(|bytes| Fp2::<F>::load(simd, &[], &bytes));
        let [ra, rb, ..] = inputs.map(|bytes| reference::decode(&bytes));
        let mut value = a;
        let mut expected = ra;
        for _ in 0..ROUNDS {
            value = value.mul::<BIAS, S>(simd, b);
            expected = reference::mul(expected, rb);
            // Components below BOUND + 1 and 2 * BOUND, carried to limb bound 1.
            value = value
                .mul_by_nonresidue::<{ BOUND + 1 }, S>(simd)
                .carry(simd);
            expected = reference::mul(expected, reference::NONRESIDUE);
            value = value.square::<{ 2 * BOUND + 1 }, S>(simd);
            expected = reference::mul(expected, expected);
            value = value.conjugate::<{ BOUND + 1 }, S>(simd).carry(simd);
            expected = reference::conjugate(expected);
            value = value.mul::<BIAS, S>(simd, value);
            expected = reference::mul(expected, expected);
        }
        assert_value(simd, value, "chain", expected);
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use commonware_invariants::minifuzz;

        #[test]
        fn minifuzz_values() {
            minifuzz::test(|u| Plan::Values.run(u));
        }

        #[test]
        fn minifuzz_products() {
            minifuzz::test(|u| Plan::Products.run(u));
        }

        #[test]
        fn minifuzz_chain() {
            minifuzz::test(|u| Plan::Chain.run(u));
        }
    }
}
