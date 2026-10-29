//! A sketch of representation-neutral field arithmetic; nothing implements it yet.
//!
//! Formulas for the extension fields, curves, and pairings should be written once and run on every
//! base field representation ([`Unsat49`], [`Unsat28`], [`Rns`]), with each representation deciding
//! for itself where to carry and where to reduce. Profile methods of [`Operation`] choose the
//! representation per backend and workload; this trait only lets formulas share code and is not a
//! selection layer.
//!
//! # Where representations differ
//!
//! Three choices determine the cost of a formula, and each depends only on static information about
//! the formula and on the representation's rules:
//!
//! 1. Readiness of factors. A factor is often a sum of reduced values, such as `a0 + a1`. Positional
//!    representations carry such a sum once it exceeds their multiplier's slack; residues stay
//!    reduced, so [`Rns`] never needs to.
//! 2. Where products reduce. A product is an unreduced, double-width value, and the products that
//!    feed one output can share a single reduction (lazy reduction). In a residue number system the
//!    reduction dominates (about 44 IFMA against 4 per product on x86v4c), so sharing it is what makes
//!    [`Rns`] pay off. Positional representations may reduce every product instead.
//! 3. How bilinear terms are formed. Karatsuba trades a product for additions, which suits
//!    representations whose products are expensive.
//!
//! A product must be reduced before it is multiplied again, so reductions never move across
//! multiplications. Every choice is therefore local and no global scheduler is needed: once a
//! formula states which values are summed and which products feed each output, the
//! representation's rules settle all three.
//!
//! # Representation side
//!
//! Each base field representation implements [`Field`]:
//!
//! - Values keep the representation's own looseness: an integer bound in units of `p`, plus limb
//!   bounds for positional representations. Additions, subtractions, and negations never reduce.
//! - [`Field::Product`] is an unreduced sum of products. Representations that reduce every product
//!   set it to `Self`, with [`Field::product`] multiplying, [`Field::accumulate`] adding, and
//!   [`Field::reduce`] doing nothing, so shared formulas compile to the code they would write by
//!   hand. [`Rns`] uses the `(high, low)` accumulators of both bases, and its reduction is the second
//!   half of [`Rns::mul`]: the quotient, the diagonal conversion, and the extension.
//! - Budgets are static rules stated by each representation: how many products a sum may hold
//!   ([`Field::PRODUCTS`]), and integer bounds in units of `p` for values and `p^2` for products.
//!   Debug counters verify them in tests; they never decide where code carries or reduces.
//!
//! # Formula side
//!
//! Formulas never call [`Field::ready`] or [`Field::reduce`] directly. Helpers built on [`Field`]
//! state each output as a signed sum of products of small sums, with term counts known at compile
//! time, and apply the representation's rules:
//!
//! - A `dot` helper sums `K` signed products: it readies each factor from its static shape, takes
//!   the products, accumulates them, and reduces once, splitting sums longer than
//!   [`Field::PRODUCTS`].
//! - Extension levels implement the same operations over a base [`Field`], with products that are
//!   pairs or triples of lower-level products. An Fp6 multiplication then accumulates Fp2 products
//!   and reduces once per coefficient, as blst's `mul_fp6x2` does by hand, and an Fp12
//!   multiplication does the same over Fp6. Upper levels use the default [`Field::cross`].
//!
//! For example, an Fp2 multiplication over any representation, with `u^2 = -1`:
//!
//! ```ignore
//! let p0 = a.c0.product(simd, b.c0);
//! let p1 = a.c1.product(simd, b.c1);
//! let c1 = F::cross(simd, [a.c0, a.c1], [b.c0, b.c1], p0, p1);
//! let c0 = F::product_sub(simd, p0, p1);
//! Fp2 { c0: F::reduce(simd, c0), c1: F::reduce(simd, c1) }
//! ```
//!
//! # Open questions
//!
//! - [`Field::product_sub`] needs a bias covering its subtrahend: `K * p` for representations whose
//!   products are values, and a multiple of `p^2` scaled into each basis for [`Rns`]. How the bias
//!   is chosen statically is open: a const generic, or the representation's budget.
//! - Whether [`Field::lift`] is worth offering, or reduced terms should only join after
//!   [`Field::reduce`]. For [`Rns`] a lift is one product with a constant.
//! - How `dot` learns the shape of each factor at compile time, for example from fixed-length
//!   arrays, while staying readable.
//! - Whether [`Field::cross`] needs a cost model rather than an override per representation. With
//!   lazy reduction Karatsuba adds no reductions, so the choice only trades products for additions;
//!   it matters mainly for [`Rns`] at the base level and should follow measurements.
//! - Formula variants beyond the bilinear algorithm, such as different point addition formulas,
//!   need a choice per formula, or later an expression representation built on the same products.
//!
//! # Validation
//!
//! Implement the trait for Fp2 and Fp6 with lazily reduced [`Rns`] and eager [`Unsat49`], and
//! compare both with hand-written versions on x86v4c and NEON. That also gives the first comparison
//! of the representations on formulas with several products per reduction.
//!
//! [`Operation`]: commonware_simd::Operation
//! [`Rns`]: super::fp::rns::Rns
//! [`Rns::mul`]: super::fp::rns::Rns::mul
//! [`Unsat28`]: super::fp::unsat28::Unsat28
//! [`Unsat49`]: super::fp::unsat49::Unsat49

#![expect(
    dead_code,
    reason = "A design sketch; no representation implements it yet."
)]

use super::fp::BYTES;
use commonware_simd::Simd;

/// Base field arithmetic on [`Self::LANES`] elements, shared by every representation.
///
/// See the [module documentation](self) for the design.
pub(crate) trait Field<S: Simd>: Copy {
    /// Number of elements in a value.
    const LANES: usize;

    /// An unreduced sum of products. Representations that reduce every product use `Self`.
    type Product: Copy;

    /// Most products one [`Self::Product`] may accumulate before [`Self::reduce`].
    const PRODUCTS: usize;

    /// Loads up to [`Self::LANES`] big-endian integers, filling the remaining lanes with `fill`.
    fn load(simd: S, elements: &[[u8; BYTES]], fill: &[u8; BYTES]) -> Self;

    /// Stores the canonical value of each lane, dropping lanes beyond `elements`.
    fn store(self, simd: S, elements: &mut [[u8; BYTES]]);

    /// Returns `self + rhs`, without reducing.
    fn add(self, simd: S, rhs: Self) -> Self;

    /// Returns `self + K * p - rhs`, without reducing.
    fn sub<const K: u64>(self, simd: S, rhs: Self) -> Self;

    /// Returns `K * p - self`, without reducing.
    fn neg<const K: u64>(self, simd: S) -> Self;

    /// Prepares a sum of at most `U` reduced values as a factor, carrying only when the
    /// representation's multiplier requires it.
    fn ready<const U: u64>(self, simd: S) -> Self;

    /// Returns `self * rhs` without reducing. Both factors must be ready.
    fn product(self, simd: S, rhs: Self) -> Self::Product;

    /// Returns `a + b`.
    fn accumulate(simd: S, a: Self::Product, b: Self::Product) -> Self::Product;

    /// Returns `a - b` plus a multiple of `p` (or `p^2`) large enough to cover `b`.
    fn product_sub(simd: S, a: Self::Product, b: Self::Product) -> Self::Product;

    /// Returns a reduced value as a product, so it can join a sum of products.
    fn lift(self, simd: S) -> Self::Product;

    /// Reduces a sum of at most [`Self::PRODUCTS`] products.
    fn reduce(simd: S, product: Self::Product) -> Self;

    /// Returns `self * rhs`.
    fn mul(self, simd: S, rhs: Self) -> Self {
        Self::reduce(simd, self.product(simd, rhs))
    }

    /// Returns `a[0] * b[1] + a[1] * b[0]` without reducing, given the products `p0 = a[0] * b[0]`
    /// and `p1 = a[1] * b[1]` of reduced values.
    ///
    /// The default uses Karatsuba: one product of the sums `a[0] + a[1]` and `b[0] + b[1]`, less the
    /// two known products. A representation whose products cost less than those additions and
    /// subtractions overrides it with the two products.
    fn cross(
        simd: S,
        a: [Self; 2],
        b: [Self; 2],
        p0: Self::Product,
        p1: Self::Product,
    ) -> Self::Product {
        let a = a[0].add(simd, a[1]).ready::<2>(simd);
        let b = b[0].add(simd, b[1]).ready::<2>(simd);
        let sum = a.product(simd, b);
        Self::product_sub(simd, Self::product_sub(simd, sum, p0), p1)
    }
}
