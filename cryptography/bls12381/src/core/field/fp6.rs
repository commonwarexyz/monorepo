//! The cubic extension `Fp6 = Fp2[v] / (v^3 - (1 + i))`, over any base field representation.
//!
//! An [`Fp6`] holds three [`Fp2`] coefficients, so it holds as many extension elements as its base
//! field values hold elements, one per lane. A [`Product`] holds an [extension product](fp2::Product)
//! in each coefficient, so sums and differences of products share reductions, and multiplying a
//! product by `v` only rearranges its signed sums.
//!
//! # Bounds
//!
//! Value operations apply the [`Fp2`] rule to each coefficient. Products take no subtraction bias:
//!
//! - [`product`](Fp6::product) forms Karatsuba's six extension products: those of the
//!   coefficients, and those of the three sums of two coefficients, which it carries. Every
//!   component of both factors must have limb bound `1`, and sums of two components must fit the
//!   value limits.
//! - [`square_product`](Fp6::square_product) forms the same six products with
//!   [`Fp2::square_product`]. Every component must have limb bound `1` and integer bound at most
//!   [`SQUARE_BOUND`].
//! - [`product_by_01`](Fp6::product_by_01) and [`product_by_1`](Fp6::product_by_1) multiply by
//!   sparse elements, with five and three extension products, under the requirements of
//!   [`product`](Fp6::product).
//!
//! Every coefficient of a product is a signed sum of at most nine extension products' sums, so
//! for eager representations each positive and each negative sum has limb bound at most `9`.
//! Products of products accumulate them, after [`carry_product`](Fp6::carry_product) where the sums
//! would exceed the limb limits. [`reduce_tight::<K>`](Fp6::reduce_tight) reduces each
//! coefficient as [`Fp2::reduce_tight`] does, under the same requirements on each component's
//! sums.
//! [`invert`](Fp6::invert) accepts components with limb bound `1` and integer bound at most
//! [`TIGHT`] and returns tight components.

use super::{
    arithmetic::{Field, Signed, TIGHT},
    fp2::{self, BYTES as FP2_BYTES, Fp2},
};
use commonware_simd::Simd;

/// Number of bytes in an element's big-endian encoding: `c2`, `c1`, then `c0`.
pub const BYTES: usize = 3 * FP2_BYTES;

/// Largest component integer bound of a [`Fp6::square_product`] factor, in units of `p`: the sum
/// of two tightly reduced values.
pub const SQUARE_BOUND: u64 = 2 * TIGHT;

/// Positional bias of the tight reductions in this module, in units of `p`.
///
/// Covers every negative sum of the tight reductions of factors within [`TIGHT`], and leaves room
/// below the value limit for their positive sums.
const BIAS: u64 = 512;

/// Signed sums of products of elements in the representation `F` on backend `S`.
pub type Product<F, S> = Fp6<Signed<<F as Field<S>>::Product>>;

/// Largest number of elements in a value, the widest representation's lane count.
const MAX_LANES: usize = 16;

/// Elements `c0 + c1 * v + c2 * v^2`, one per lane of the coefficients.
///
/// Components are base field values or, for sums of products, base field products. See the
/// [module documentation](self) for the bounds each operation requires.
#[derive(Clone, Copy)]
pub struct Fp6<T> {
    /// The coefficients of `1`.
    pub c0: Fp2<T>,
    /// The coefficients of `v`.
    pub c1: Fp2<T>,
    /// The coefficients of `v^2`.
    pub c2: Fp2<T>,
}

impl<F> Fp6<F> {
    /// Loads up to one element per lane, filling the remaining lanes with `fill`.
    ///
    /// Interprets each component modulo `p` and returns the base field's initial bounds.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn load<S: Simd>(simd: S, elements: &[[u8; BYTES]], fill: &[u8; BYTES]) -> Self
    where
        F: Field<S>,
    {
        const { assert!(F::LANES <= MAX_LANES) };
        let mut coefficients = [[[0; FP2_BYTES]; MAX_LANES]; 3];
        let lanes = elements.len().min(F::LANES);
        for (lane, element) in elements[..lanes].iter().enumerate() {
            for (coefficient, bytes) in coefficients.iter_mut().zip(split(element)) {
                coefficient[lane] = *bytes;
            }
        }
        let [fill0, fill1, fill2] = split(fill);
        Self {
            c0: Fp2::load(simd, &coefficients[0][..lanes], fill0),
            c1: Fp2::load(simd, &coefficients[1][..lanes], fill1),
            c2: Fp2::load(simd, &coefficients[2][..lanes], fill2),
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
        let mut coefficients = [[[0; FP2_BYTES]; MAX_LANES]; 3];
        let lanes = elements.len().min(F::LANES);
        self.c0.store(simd, &mut coefficients[0][..lanes]);
        self.c1.store(simd, &mut coefficients[1][..lanes]);
        self.c2.store(simd, &mut coefficients[2][..lanes]);
        for (lane, element) in elements[..lanes].iter_mut().enumerate() {
            let (c2, rest) = element.split_at_mut(FP2_BYTES);
            let (c1, c0) = rest.split_at_mut(FP2_BYTES);
            c0.copy_from_slice(&coefficients[0][lane]);
            c1.copy_from_slice(&coefficients[1][lane]);
            c2.copy_from_slice(&coefficients[2][lane]);
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
            c2: self.c2.add(simd, rhs.c2),
        }
    }

    /// Returns `K * p - self` in each component, without reducing.
    #[inline(always)]
    pub fn neg<const K: u64, S: Simd>(self, simd: S) -> Self
    where
        F: Field<S>,
    {
        Self {
            c0: self.c0.neg::<K, S>(simd),
            c1: self.c1.neg::<K, S>(simd),
            c2: self.c2.neg::<K, S>(simd),
        }
    }

    /// Carries every positional limb of every component to limb bound `1`, without reducing.
    #[inline(always)]
    pub fn carry<S: Simd>(self, simd: S) -> Self
    where
        F: Field<S>,
    {
        Self {
            c0: self.c0.carry(simd),
            c1: self.c1.carry(simd),
            c2: self.c2.carry(simd),
        }
    }

    /// Forms the product `self * rhs` with Karatsuba's six extension products.
    ///
    /// Every component of both factors must have limb bound `1`.
    /// Runs as its own kernel, so callers share one copy.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn product<S: Simd>(&self, simd: S, rhs: &Self) -> Product<F, S>
    where
        F: Field<S>,
    {
        simd.execute(
            #[inline(always)]
            move |simd: S| {
                let (a, b) = (self, rhs);
                let v = [
                    a.c0.product(simd, b.c0),
                    a.c1.product(simd, b.c1),
                    a.c2.product(simd, b.c2),
                ];
                let sums = [
                    sum(simd, a.c0, a.c1).product(simd, sum(simd, b.c0, b.c1)),
                    sum(simd, a.c0, a.c2).product(simd, sum(simd, b.c0, b.c2)),
                    sum(simd, a.c1, a.c2).product(simd, sum(simd, b.c1, b.c2)),
                ];
                combine::<S, F>(simd, v, sums)
            },
        )
    }

    /// Forms the product `self * self` with six extension squarings.
    ///
    /// Every component must have limb bound `1` and integer bound at most [`SQUARE_BOUND`].
    /// Runs as its own kernel, so callers share one copy.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn square_product<S: Simd>(&self, simd: S) -> Product<F, S>
    where
        F: Field<S>,
    {
        simd.execute(
            #[inline(always)]
            move |simd: S| {
                // Components within SQUARE_BOUND, and sums of two of them.
                const K: u64 = SQUARE_BOUND + 1;
                const SUM_K: u64 = 2 * SQUARE_BOUND + 1;
                let a = self;
                let v = [
                    a.c0.square_product::<K, S>(simd),
                    a.c1.square_product::<K, S>(simd),
                    a.c2.square_product::<K, S>(simd),
                ];
                let sums = [
                    sum(simd, a.c0, a.c1).square_product::<SUM_K, S>(simd),
                    sum(simd, a.c0, a.c2).square_product::<SUM_K, S>(simd),
                    sum(simd, a.c1, a.c2).square_product::<SUM_K, S>(simd),
                ];
                combine::<S, F>(simd, v, sums)
            },
        )
    }

    /// Forms the product of `self` and the sparse element `y0 + y1 * v` with five extension
    /// products.
    ///
    /// Every component of the factors must have limb bound `1`.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn product_by_01<S: Simd>(self, simd: S, y0: Fp2<F>, y1: Fp2<F>) -> Product<F, S>
    where
        F: Field<S>,
    {
        let v0 = self.c0.product(simd, y0);
        let v1 = self.c1.product(simd, y1);
        // (x0 + x1)(y0 + y1) - x0 y0 - x1 y1.
        let cross = sum(simd, self.c0, self.c1).product(simd, sum(simd, y0, y1));
        let c1 = Fp2::<F>::product_sub(simd, Fp2::<F>::product_sub(simd, cross, v0), v1);
        Fp6 {
            c0: Fp2::<F>::accumulate(
                simd,
                v0,
                Fp2::<F>::product_mul_by_nonresidue(simd, self.c2.product(simd, y1)),
            ),
            c1,
            c2: Fp2::<F>::accumulate(simd, self.c2.product(simd, y0), v1),
        }
    }

    /// Forms the product of `self` and the sparse element `y1 * v` with three extension products.
    ///
    /// Every component of the factors must have limb bound `1`.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn product_by_1<S: Simd>(self, simd: S, y1: Fp2<F>) -> Product<F, S>
    where
        F: Field<S>,
    {
        Fp6 {
            c0: Fp2::<F>::product_mul_by_nonresidue(simd, self.c2.product(simd, y1)),
            c1: self.c0.product(simd, y1),
            c2: self.c1.product(simd, y1),
        }
    }

    /// Lifts `self` into the product representation without changing its value.
    #[inline(always)]
    pub fn lift<S: Simd>(self, simd: S) -> Product<F, S>
    where
        F: Field<S>,
    {
        Fp6 {
            c0: self.c0.lift(simd),
            c1: self.c1.lift(simd),
            c2: self.c2.lift(simd),
        }
    }

    /// Returns `a + b` for products, accumulating each coefficient as [`Fp2::accumulate`] does.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn accumulate<S: Simd>(simd: S, a: Product<F, S>, b: Product<F, S>) -> Product<F, S>
    where
        F: Field<S>,
    {
        Fp6 {
            c0: Fp2::<F>::accumulate(simd, a.c0, b.c0),
            c1: Fp2::<F>::accumulate(simd, a.c1, b.c1),
            c2: Fp2::<F>::accumulate(simd, a.c2, b.c2),
        }
    }

    /// Returns `a - b` for products, without a bias, as [`Fp2::product_sub`] does.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn product_sub<S: Simd>(simd: S, a: Product<F, S>, b: Product<F, S>) -> Product<F, S>
    where
        F: Field<S>,
    {
        Fp6 {
            c0: Fp2::<F>::product_sub(simd, a.c0, b.c0),
            c1: Fp2::<F>::product_sub(simd, a.c1, b.c1),
            c2: Fp2::<F>::product_sub(simd, a.c2, b.c2),
        }
    }

    /// Returns `product * v`, without a bias: `v^3 = 1 + i` moves the coefficient of `v^2` to `1`
    /// through [`Fp2::product_mul_by_nonresidue`].
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn product_mul_by_nonresidue<S: Simd>(simd: S, product: Product<F, S>) -> Product<F, S>
    where
        F: Field<S>,
    {
        Fp6 {
            c0: Fp2::<F>::product_mul_by_nonresidue(simd, product.c2),
            c1: product.c0,
            c2: product.c1,
        }
    }

    /// Carries every sum of a product, as for [`Field::carry_product`].
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn carry_product<S: Simd>(simd: S, product: Product<F, S>) -> Product<F, S>
    where
        F: Field<S>,
    {
        Fp6 {
            c0: Fp2::<F>::carry_product(simd, product.c0),
            c1: Fp2::<F>::carry_product(simd, product.c1),
            c2: Fp2::<F>::carry_product(simd, product.c2),
        }
    }

    /// Reduces every coefficient of a product to integer bound at most [`TIGHT`], as
    /// [`Fp2::reduce_tight`] does with the bias `K`.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn reduce_tight<const K: u64, S: Simd>(simd: S, product: Product<F, S>) -> Self
    where
        F: Field<S>,
    {
        Self {
            c0: Fp2::<F>::reduce_tight::<K, S>(simd, product.c0),
            c1: Fp2::<F>::reduce_tight::<K, S>(simd, product.c1),
            c2: Fp2::<F>::reduce_tight::<K, S>(simd, product.c2),
        }
    }

    /// Returns the inverse, or zero for zero.
    ///
    /// The adjugate `c` satisfies `self * c = d` for `d` in `Fp2`, which [`Fp2::invert`] inverts.
    /// Every component must have limb bound `1` and integer bound at most [`TIGHT`]; so does every
    /// component of the result.
    /// Runs as its own kernel, so callers share one copy.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn invert<S: Simd>(self, simd: S) -> Self
    where
        F: Field<S>,
    {
        simd.execute(
            #[inline(always)]
            move |simd: S| {
                const K: u64 = TIGHT + 1;
                let Self { c0, c1, c2 } = self;
                // a0 = c0^2 - (1 + i) c1 c2, a1 = (1 + i) c2^2 - c0 c1, and a2 = c1^2 - c0 c2.
                let a0 = Fp2::<F>::product_sub(
                    simd,
                    c0.square_product::<K, S>(simd),
                    Fp2::<F>::product_mul_by_nonresidue(simd, c1.product(simd, c2)),
                );
                let a1 = Fp2::<F>::product_sub(
                    simd,
                    Fp2::<F>::product_mul_by_nonresidue(simd, c2.square_product::<K, S>(simd)),
                    c0.product(simd, c1),
                );
                let a2 = Fp2::<F>::product_sub(
                    simd,
                    c1.square_product::<K, S>(simd),
                    c0.product(simd, c2),
                );
                let a0 = Fp2::<F>::reduce_tight::<BIAS, S>(simd, a0);
                let a1 = Fp2::<F>::reduce_tight::<BIAS, S>(simd, a1);
                let a2 = Fp2::<F>::reduce_tight::<BIAS, S>(simd, a2);
                // d = c0 a0 + (1 + i) (c2 a1 + c1 a2).
                let d = Fp2::<F>::accumulate(
                    simd,
                    c0.product(simd, a0),
                    Fp2::<F>::product_mul_by_nonresidue(
                        simd,
                        Fp2::<F>::accumulate(simd, c2.product(simd, a1), c1.product(simd, a2)),
                    ),
                );
                let inverse = Fp2::<F>::reduce_tight::<BIAS, S>(simd, d).invert(simd);
                Self {
                    c0: Fp2::<F>::reduce_tight::<BIAS, S>(simd, a0.product(simd, inverse)),
                    c1: Fp2::<F>::reduce_tight::<BIAS, S>(simd, a1.product(simd, inverse)),
                    c2: Fp2::<F>::reduce_tight::<BIAS, S>(simd, a2.product(simd, inverse)),
                }
            },
        )
    }
}

/// Combines Karatsuba's products into a product: `v` holds the products of the coefficients and
/// `sums` those of the sums of coefficients `0` and `1`, `0` and `2`, and `1` and `2`.
#[cfg_attr(not(debug_assertions), inline(always))]
fn combine<S: Simd, F: Field<S>>(
    simd: S,
    v: [fp2::Product<F, S>; 3],
    sums: [fp2::Product<F, S>; 3],
) -> Product<F, S> {
    // The cross terms a0 b1 + a1 b0, a0 b2 + a2 b0, and a1 b2 + a2 b1.
    let c01 = difference::<S, F>(simd, sums[0], v[0], v[1]);
    let c02 = difference::<S, F>(simd, sums[1], v[0], v[2]);
    let c12 = difference::<S, F>(simd, sums[2], v[1], v[2]);
    Fp6 {
        c0: Fp2::<F>::accumulate(simd, v[0], Fp2::<F>::product_mul_by_nonresidue(simd, c12)),
        c1: Fp2::<F>::accumulate(simd, c01, Fp2::<F>::product_mul_by_nonresidue(simd, v[2])),
        c2: Fp2::<F>::accumulate(simd, c02, v[1]),
    }
}

/// Returns `sum - a - b` for products, without a bias.
#[cfg_attr(not(debug_assertions), inline(always))]
fn difference<S: Simd, F: Field<S>>(
    simd: S,
    sum: fp2::Product<F, S>,
    a: fp2::Product<F, S>,
    b: fp2::Product<F, S>,
) -> fp2::Product<F, S> {
    Fp2::<F>::product_sub(simd, Fp2::<F>::product_sub(simd, sum, a), b)
}

/// Returns `a + b`, carried for multiplication.
#[cfg_attr(not(debug_assertions), inline(always))]
fn sum<S: Simd, F: Field<S>>(simd: S, a: Fp2<F>, b: Fp2<F>) -> Fp2<F> {
    a.add(simd, b).carry(simd)
}

/// Splits an element's encoding into its `c0`, `c1`, and `c2` encodings.
#[inline(always)]
const fn split(element: &[u8; BYTES]) -> [&[u8; FP2_BYTES]; 3] {
    let (chunks, _) = element.as_chunks::<FP2_BYTES>();
    [&chunks[2], &chunks[1], &chunks[0]]
}
