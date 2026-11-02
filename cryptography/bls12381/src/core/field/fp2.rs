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
//! so neither adds a bias. [`lift`](Fp2::lift) gives positive sums with the value's bounds.
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
    arithmetic::{Field, Signed, TIGHT},
    fp::BYTES as FP_BYTES,
};
use commonware_simd::Simd;

/// Number of bytes in an element's big-endian encoding: `c1` followed by `c0`.
pub const BYTES: usize = 2 * FP_BYTES;

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
    /// The real component is `a0 b0` less `a1 b1`, and the imaginary component comes from
    /// [`Field::cross`], which reuses both known products. Both factors' components must have limb
    /// bound `1`.
    /// Runs as its own kernel, so callers share one copy.
    #[inline(always)]
    pub fn product<S: Simd>(self, simd: S, rhs: Self) -> Product<F, S>
    where
        F: Field<S>,
    {
        simd.execute(
            #[inline(always)]
            move |simd: S| self.product_body(simd, rhs),
        )
    }

    /// Body of [`Self::product`].
    #[inline(always)]
    fn product_body<S: Simd>(self, simd: S, rhs: Self) -> Product<F, S>
    where
        F: Field<S>,
    {
        let a = [self.c0, self.c1];
        let b = [rhs.c0, rhs.c1];
        let p0 = self.c0.product(simd, rhs.c0);
        let p1 = self.c1.product(simd, rhs.c1);
        Fp2 {
            c0: Signed {
                pos: p0,
                neg: Some(p1),
            },
            c1: F::cross(simd, a, b, p0, p1),
        }
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
    /// `a0 b1 + a1 b0`. Unlike [`Self::product`], no product takes a sum of components, so large
    /// factors keep smaller positional bounds at the cost of one more positional product; residues
    /// form the same products either way. Every factor must be ready, as for [`Field::product`].
    /// Runs as its own kernel, so callers share one copy.
    #[inline(always)]
    pub fn product_schoolbook<S: Simd>(self, simd: S, rhs: Self) -> Product<F, S>
    where
        F: Field<S>,
    {
        simd.execute(
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
            c1: Signed::positive(F::accumulate(
                simd,
                self.c0.product(simd, rhs.c1),
                self.c1.product(simd, rhs.c0),
            )),
        }
    }

    /// Forms the product `self * self` with two base field products.
    ///
    /// The real component is `(c0 + c1)(c0 - c1)` and the imaginary component is `(2 c0) c1`.
    /// Both components must have limb bound `1`, and the bias `K` must cover `c1` as for
    /// [`Field::sub`].
    /// Runs as its own kernel, so callers share one copy.
    #[inline(always)]
    pub fn square_product<const K: u64, S: Simd>(self, simd: S) -> Product<F, S>
    where
        F: Field<S>,
    {
        simd.execute(
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
            c0: add::<S, F>(simd, a.c0, b.c0),
            c1: add::<S, F>(simd, a.c1, b.c1),
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
            c0: sub::<S, F>(simd, a.c0, b.c0),
            c1: sub::<S, F>(simd, a.c1, b.c1),
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
            c0: sub::<S, F>(simd, product.c0, product.c1),
            c1: add::<S, F>(simd, product.c0, product.c1),
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

    /// Reduces both components of a product, as for [`Field::reduce_signed`] with the bias `K`.
    /// Runs as its own kernel, so callers share one copy.
    #[inline(always)]
    pub fn reduce<const K: u64, S: Simd>(simd: S, product: Product<F, S>) -> Self
    where
        F: Field<S>,
    {
        simd.execute(
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
        Self {
            c0: F::reduce_signed::<K>(simd, product.c0),
            c1: F::reduce_signed::<K>(simd, product.c1),
        }
    }

    /// Reduces both components of a product without negative sums.
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn reduce_positive<S: Simd>(simd: S, product: Product<F, S>) -> Self
    where
        F: Field<S>,
    {
        debug_assert!(product.c0.neg.is_none() && product.c1.neg.is_none());
        Self {
            c0: F::reduce(simd, product.c0.pos),
            c1: F::reduce(simd, product.c1.pos),
        }
    }

    /// Carries every sum of a product, as for [`Field::carry_product`].
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn carry_product<S: Simd>(simd: S, product: Product<F, S>) -> Product<F, S>
    where
        F: Field<S>,
    {
        Fp2 {
            c0: carry::<S, F>(simd, product.c0),
            c1: carry::<S, F>(simd, product.c1),
        }
    }

    /// Reduces both components of a product to integer bound at most [`TIGHT`], as for
    /// [`Field::reduce_signed_tight`] with the bias `K`.
    /// Runs as its own kernel, so callers share one copy.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn reduce_tight<const K: u64, S: Simd>(simd: S, product: Product<F, S>) -> Self
    where
        F: Field<S>,
    {
        simd.execute(
            #[inline(always)]
            move |simd: S| Self {
                c0: F::reduce_signed_tight::<K>(simd, product.c0),
                c1: F::reduce_signed_tight::<K>(simd, product.c1),
            },
        )
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
        let norm = F::accumulate(
            simd,
            self.c0.product(simd, self.c0),
            self.c1.product(simd, self.c1),
        );
        let inverse = F::reduce_tight(simd, norm).invert(simd);
        let conjugate = self.conjugate::<{ TIGHT + 1 }, S>(simd).carry(simd);
        Self::reduce_tight::<1, S>(simd, conjugate.product_base(simd, inverse))
    }
}

/// Returns the sum of two optional products.
#[cfg_attr(not(debug_assertions), inline(always))]
fn join<S: Simd, F: Field<S>>(simd: S, a: Option<F::Product>, b: Option<F::Product>) -> Option<F::Product> {
    match (a, b) {
        (Some(a), Some(b)) => Some(F::accumulate(simd, a, b)),
        (a, None) => a,
        (None, b) => b,
    }
}

/// Returns `a + b` for signed sums.
#[cfg_attr(not(debug_assertions), inline(always))]
fn add<S: Simd, F: Field<S>>(simd: S, a: Signed<F::Product>, b: Signed<F::Product>) -> Signed<F::Product> {
    Signed {
        pos: F::accumulate(simd, a.pos, b.pos),
        neg: join::<S, F>(simd, a.neg, b.neg),
    }
}

/// Returns `a - b` for signed sums, swapping the parts of `b`.
#[cfg_attr(not(debug_assertions), inline(always))]
fn sub<S: Simd, F: Field<S>>(simd: S, a: Signed<F::Product>, b: Signed<F::Product>) -> Signed<F::Product> {
    let mut pos = a.pos;
    if let Some(neg) = b.neg {
        pos = F::accumulate(simd, pos, neg);
    }
    Signed {
        pos,
        neg: join::<S, F>(simd, a.neg, Some(b.pos)),
    }
}

/// Carries both parts of a signed sum.
#[cfg_attr(not(debug_assertions), inline(always))]
fn carry<S: Simd, F: Field<S>>(simd: S, sum: Signed<F::Product>) -> Signed<F::Product> {
    Signed {
        pos: F::carry_product(simd, sum.pos),
        neg: sum.neg.map(|neg| F::carry_product(simd, neg)),
    }
}

/// Splits an element's encoding into its `c1` and `c0` encodings.
#[inline(always)]
fn split(element: &[u8; BYTES]) -> (&[u8; FP_BYTES], &[u8; FP_BYTES]) {
    let (c1, c0) = element.split_first_chunk::<FP_BYTES>().expect("two components");
    (c1, c0.try_into().expect("two components"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::field::fp::{
        rns::Rns,
        tests::{self as reference, Element},
        unsat28::Unsat28,
        unsat49::Unsat49,
    };
    use commonware_invariants::minifuzz;
    use commonware_simd::{
        Operation, check_consistent,
        emulated::{EmulatedNeon, EmulatedScalar, EmulatedX86V4C},
        test_dispatch,
    };
    use std::vec;

    /// A reference element `(c0, c1)` with canonical components.
    type Reference = (Element, Element);

    /// Largest component integer bound that multiplications preserve, in units of `p`.
    const BOUND: u64 = 77;

    /// Positional bias of every reduction, which covers the negative sums of these checks.
    const BIAS: u64 = 64;

    /// Multiplications in the chain of [`check`].
    const ROUNDS: usize = 8;

    fn add((a0, a1): Reference, (b0, b1): Reference) -> Reference {
        (reference::add(a0, b0), reference::add(a1, b1))
    }

    fn sub((a0, a1): Reference, (b0, b1): Reference) -> Reference {
        (reference::sub(a0, b0), reference::sub(a1, b1))
    }

    fn mul((a0, a1): Reference, (b0, b1): Reference) -> Reference {
        (
            reference::sub(reference::mul(a0, b0), reference::mul(a1, b1)),
            reference::add(reference::mul(a0, b1), reference::mul(a1, b0)),
        )
    }

    fn decode(bytes: &[u8; BYTES]) -> Reference {
        let (c1, c0) = split(bytes);
        (reference::reduce(c0), reference::reduce(c1))
    }

    fn encode((c0, c1): Reference) -> [u8; BYTES] {
        let mut bytes = [0; BYTES];
        bytes[..FP_BYTES].copy_from_slice(&reference::to_bytes(c1));
        bytes[FP_BYTES..].copy_from_slice(&reference::to_bytes(c0));
        bytes
    }

    /// Asserts that the lane-0 value of `value` is `expected`.
    fn assert_value<S: Simd, F: Field<S>>(simd: S, value: Fp2<F>, expected: Reference) {
        let mut output = [[0; BYTES]];
        value.store(simd, &mut output);
        assert_eq!(output[0], encode(expected));
    }

    /// Checks loading, storing, and every value operation, including reduced products.
    fn check_values<S: Simd, F: Field<S>>(simd: S, inputs: &[[u8; BYTES]; 4]) {
        let mut lanes = vec![[0; BYTES]; F::LANES + 1];
        Fp2::<F>::load(simd, &inputs[..1], &inputs[1]).store(simd, &mut lanes);
        assert_eq!(lanes[0], encode(decode(&inputs[0])));
        for lane in &lanes[1..F::LANES] {
            assert_eq!(*lane, encode(decode(&inputs[1])));
        }
        assert_eq!(lanes[F::LANES], [0; BYTES]);
        let [a, b, ..] = inputs.map(|bytes| Fp2::<F>::load(simd, &[], &bytes));
        let [ra, rb, ..] = inputs.map(|bytes| decode(&bytes));
        let (zero, one) = (reference::ZERO, reference::ONE);
        let i = (zero, one);
        assert_value(simd, a.add(simd, b), add(ra, rb));
        assert_value(simd, a.double(simd), add(ra, ra));
        assert_value(
            simd,
            a.mul_small::<5, S>(simd),
            mul(ra, ([5, 0, 0, 0, 0, 0], zero)),
        );
        assert_value(simd, a.sub::<3, S>(simd, b), sub(ra, rb));
        assert_value(simd, a.neg::<3, S>(simd), sub((zero, zero), ra));
        assert_value(
            simd,
            a.conjugate::<3, S>(simd),
            (ra.0, reference::neg(ra.1)),
        );
        assert_value(simd, a.mul_by_nonresidue::<3, S>(simd), mul(ra, (one, one)));
        assert_value(simd, a.mul::<BIAS, S>(simd, b), mul(ra, rb));
        assert_value(
            simd,
            Fp2::<F>::reduce::<BIAS, S>(simd, a.product_schoolbook(simd, b)),
            mul(ra, rb),
        );
        let unit = Fp2::<F>::load(simd, &[], &encode(i));
        assert_value(simd, unit.mul::<BIAS, S>(simd, a), mul(i, ra));
        assert_value(simd, a.square::<3, S>(simd), mul(ra, ra));
        assert_value(simd, a.mul_base(simd, b.c0), mul(ra, (rb.0, zero)));
        assert_value(simd, Fp2::<F>::reduce::<BIAS, S>(simd, a.lift(simd)), ra);
    }

    /// Checks sums and differences of products, which never stack subtraction biases.
    fn check_products<S: Simd, F: Field<S>>(simd: S, inputs: &[[u8; BYTES]; 4]) {
        let [a, b, c, d] = inputs.map(|bytes| Fp2::<F>::load(simd, &[], &bytes));
        let [ra, rb, rc, rd] = inputs.map(|bytes| decode(&bytes));
        let (zero, one) = (reference::ZERO, reference::ONE);
        let (ab, cd) = (a.product(simd, b), c.product(simd, d));
        let (rab, rcd) = (mul(ra, rb), mul(rc, rd));
        assert_value(
            simd,
            Fp2::<F>::reduce::<BIAS, S>(simd, Fp2::<F>::accumulate(simd, ab, cd)),
            add(rab, rcd),
        );
        assert_value(
            simd,
            Fp2::<F>::reduce::<BIAS, S>(simd, Fp2::<F>::product_sub(simd, ab, c.lift(simd))),
            sub(rab, rc),
        );
        assert_value(
            simd,
            Fp2::<F>::reduce::<BIAS, S>(
                simd,
                Fp2::<F>::product_sub(simd, ab, c.product_base(simd, d.c0)),
            ),
            sub(rab, mul(rc, (rd.0, zero))),
        );
        assert_value(
            simd,
            Fp2::<F>::reduce::<BIAS, S>(simd, Fp2::<F>::product_sub(simd, ab, cd)),
            sub(rab, rcd),
        );
        // (ab - cd)(1 + i) - (ab + cd) - b^2, as formulas over extensions combine products.
        let difference = Fp2::<F>::product_sub(simd, ab, cd);
        let rotated = Fp2::<F>::product_mul_by_nonresidue(simd, difference);
        let sum = Fp2::<F>::accumulate(simd, ab, cd);
        let combined = Fp2::<F>::product_sub(simd, rotated, sum);
        let combined = Fp2::<F>::product_sub(simd, combined, b.square_product::<3, S>(simd));
        let expected = sub(
            sub(mul(sub(rab, rcd), (one, one)), add(rab, rcd)),
            mul(rb, rb),
        );
        assert_value(simd, Fp2::<F>::reduce::<BIAS, S>(simd, combined), expected);
    }

    /// Chains multiplications through the bound they preserve, mixing in the operations whose
    /// outputs exceed it before squaring them back down.
    fn check_chain<S: Simd, F: Field<S>>(simd: S, inputs: &[[u8; BYTES]; 4]) {
        let [a, b, ..] = inputs.map(|bytes| Fp2::<F>::load(simd, &[], &bytes));
        let [ra, rb, ..] = inputs.map(|bytes| decode(&bytes));
        let one = reference::ONE;
        let mut value = a;
        let mut expected = ra;
        for _ in 0..ROUNDS {
            value = value.mul::<BIAS, S>(simd, b);
            expected = mul(expected, rb);
            // Components below BOUND + 1 and 2 * BOUND, carried to limb bound 1.
            value = value.mul_by_nonresidue::<{ BOUND + 1 }, S>(simd).carry(simd);
            expected = mul(expected, (one, one));
            value = value.square::<{ 2 * BOUND + 1 }, S>(simd);
            expected = mul(expected, expected);
            value = value.conjugate::<{ BOUND + 1 }, S>(simd).carry(simd);
            expected = (expected.0, reference::neg(expected.1));
            value = value.mul::<BIAS, S>(simd, value);
            expected = mul(expected, expected);
        }
        assert_value(simd, value, expected);
    }

    /// Runs every check in one representation.
    fn check<S: Simd, F: Field<S>>(simd: S, inputs: &[[u8; BYTES]; 4]) {
        check_values::<S, F>(simd, inputs);
        check_products::<S, F>(simd, inputs);
        check_chain::<S, F>(simd, inputs);
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
        let one = reference::ONE;
        let minus_one = reference::neg(one);
        for value in [
            (reference::ZERO, reference::ZERO),
            (one, reference::ZERO),
            (reference::ZERO, one),
            (minus_one, minus_one),
        ] {
            let inputs = [encode(value); 4];
            check_consistent(|| Evaluate(inputs));
        }
        minifuzz::test(|u| {
            let mut inputs = [[0; BYTES]; 4];
            for input in &mut inputs {
                *input = u.arbitrary()?;
            }
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
