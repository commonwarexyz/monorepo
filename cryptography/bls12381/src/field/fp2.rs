//! The quadratic extension `Fp2 = Fp[i] / (i^2 + 1)`, over any base field representation.
//!
//! An [`Fp2`] holds two base field values, so it holds as many extension elements as its base
//! field values hold elements, one per lane. Its arithmetic runs once over every representation of
//! the [base field arithmetic](super::arithmetic). [`Fp2<F::Product>`](Fp2) holds products, so
//! sums of extension products can share reductions.
//!
//! # Bounds
//!
//! Each component keeps its own integer and limb bounds under the rules of the
//! [base field arithmetic](super::arithmetic), and every operation's requirements apply to the
//! components it uses. Componentwise operations ([`add`](Fp2::add), [`double`](Fp2::double),
//! [`mul_small`](Fp2::mul_small), [`sub`](Fp2::sub), [`neg`](Fp2::neg), [`carry`](Fp2::carry),
//! [`ready`](Fp2::ready), [`accumulate`](Fp2::accumulate), [`product_sub`](Fp2::product_sub),
//! [`lift`](Fp2::lift), and [`reduce`](Fp2::reduce)) apply the base rule to each component.
//! The others combine components as follows, for factors with component integer bounds `A0`, `A1`
//! and `B0`, `B1`, and `E(A, B) = ceil(A * B / 2048) + 1` as in the base field:
//!
//! | Operation | Requirements | Positional integer and limb bounds | RNS integer bounds |
//! |---|---|---|---|
//! | [`conjugate::<K>`](Fp2::conjugate) | `neg::<K>` of `c1` | `c0` unchanged, `c1` is `(K, 3)` | `c0` unchanged, `c1` is `K` |
//! | [`mul_by_nonresidue::<K>`](Fp2::mul_by_nonresidue) | `c0.sub::<K>(c1)` | `(A0 + K, L0 + 3)`, `(A0 + A1, L0 + L1)` | `A0 + K`, `A0 + A1` |
//! | [`product`](Fp2::product) | Component limb bounds `1`; `E(A0, B0)`, `E(A1, B1) <= 16` | `(E(A0, B0) + 17, 4)`, `(E(A0 + A1, B0 + B1) + 34, 7)` | Wide `A0 * B0 + 295936` with four terms, `A0 * B1 + A1 * B0` with two |
//! | [`square_product::<K>`](Fp2::square_product) | Component limb bounds `1`; `c0.sub::<K>(c1)` | `(E(A0 + A1, A0 + K), 1)`, `(E(2 * A0, A1), 1)` | Wide `(A0 + A1) * (A0 + K)`, `2 * A0 * A1`, one term each |
//! | [`product_base`](Fp2::product_base) | [`Field::product`] of each component | `(E(A0, B), 1)`, `(E(A1, B), 1)` | Wide `A0 * B`, `A1 * B`, one term each |
//!
//! [`mul`](Fp2::mul), [`square`](Fp2::square), and [`mul_base`](Fp2::mul_base) reduce the
//! corresponding products: positional components keep their integer bounds with limb bound `1`,
//! and residues reduce to at most `17` when the wide bound is at most `645173`.
//!
//! For example, components with limb bound `1` and integer bound at most `38` multiply to
//! components with integer bound at most `38` in every representation, so multiplications chain
//! without carrying between them.

use super::{arithmetic::Field, fp::BYTES as FP_BYTES};
use commonware_simd::Simd;

/// Number of bytes in an element's big-endian encoding: `c1` followed by `c0`.
pub const BYTES: usize = 2 * FP_BYTES;

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
    #[inline(always)]
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
    #[inline(always)]
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
    /// The real component is `a0 b0 - a1 b1` and the imaginary component comes from
    /// [`Field::cross`], which reuses both known products. Both factors' components must have limb
    /// bound `1`.
    #[inline(always)]
    pub fn product<S: Simd>(self, simd: S, rhs: Self) -> Fp2<F::Product>
    where
        F: Field<S>,
    {
        let a = [self.c0, self.c1];
        let b = [rhs.c0, rhs.c1];
        let p0 = self.c0.product(simd, rhs.c0);
        let p1 = self.c1.product(simd, rhs.c1);
        Fp2 {
            c0: F::product_sub(simd, p0, p1),
            c1: F::cross(simd, a, b, p0, p1),
        }
    }

    /// Returns `self * rhs`, under the requirements of [`Self::product`].
    #[inline(always)]
    pub fn mul<S: Simd>(self, simd: S, rhs: Self) -> Self
    where
        F: Field<S>,
    {
        Self::reduce(simd, self.product(simd, rhs))
    }

    /// Forms the product `self * self` with two base field products.
    ///
    /// The real component is `(c0 + c1)(c0 - c1)` and the imaginary component is `(2 c0) c1`.
    /// Both components must have limb bound `1`, and the bias `K` must cover `c1` as for
    /// [`Field::sub`].
    #[inline(always)]
    pub fn square_product<const K: u64, S: Simd>(self, simd: S) -> Fp2<F::Product>
    where
        F: Field<S>,
    {
        let sum = self.c0.add(simd, self.c1).ready::<2>(simd);
        let difference = self.c0.sub::<K>(simd, self.c1).ready::<4>(simd);
        let c0 = self.c0.double(simd).ready::<2>(simd);
        Fp2 {
            c0: sum.product(simd, difference),
            c1: c0.product(simd, self.c1),
        }
    }

    /// Returns `self * self`, under the requirements of [`Self::square_product`].
    #[inline(always)]
    pub fn square<const K: u64, S: Simd>(self, simd: S) -> Self
    where
        F: Field<S>,
    {
        Self::reduce(simd, self.square_product::<K, S>(simd))
    }

    /// Forms the product of `self` and a base field value.
    ///
    /// Every factor must be ready, as for [`Field::product`].
    #[inline(always)]
    pub fn product_base<S: Simd>(self, simd: S, rhs: F) -> Fp2<F::Product>
    where
        F: Field<S>,
    {
        Fp2 {
            c0: self.c0.product(simd, rhs),
            c1: self.c1.product(simd, rhs),
        }
    }

    /// Returns the product of `self` and a base field value, under the requirements of
    /// [`Self::product_base`].
    #[inline(always)]
    pub fn mul_base<S: Simd>(self, simd: S, rhs: F) -> Self
    where
        F: Field<S>,
    {
        Self::reduce(simd, self.product_base(simd, rhs))
    }

    /// Returns `a + b` for products.
    #[inline(always)]
    pub fn accumulate<S: Simd>(simd: S, a: Fp2<F::Product>, b: Fp2<F::Product>) -> Fp2<F::Product>
    where
        F: Field<S>,
    {
        Fp2 {
            c0: F::accumulate(simd, a.c0, b.c0),
            c1: F::accumulate(simd, a.c1, b.c1),
        }
    }

    /// Returns `a - b` for products, plus the base field's fixed product subtraction bias in each
    /// component.
    ///
    /// Each component of `b` must fit [`Field::product_sub`]'s subtrahend limit. The real component
    /// of a [`Self::product`] already includes that bias and exceeds the limit, so subtract lifted
    /// values, [`Self::square_product`]s, or [`Self::product_base`]s instead.
    #[inline(always)]
    pub fn product_sub<S: Simd>(simd: S, a: Fp2<F::Product>, b: Fp2<F::Product>) -> Fp2<F::Product>
    where
        F: Field<S>,
    {
        Fp2 {
            c0: F::product_sub(simd, a.c0, b.c0),
            c1: F::product_sub(simd, a.c1, b.c1),
        }
    }

    /// Lifts `self` into the product representation without changing its value.
    #[inline(always)]
    pub fn lift<S: Simd>(self, simd: S) -> Fp2<F::Product>
    where
        F: Field<S>,
    {
        Fp2 {
            c0: self.c0.lift(simd),
            c1: self.c1.lift(simd),
        }
    }

    /// Reduces both components of a sum of products, as for [`Field::reduce`].
    #[inline(always)]
    pub fn reduce<S: Simd>(simd: S, product: Fp2<F::Product>) -> Self
    where
        F: Field<S>,
    {
        Self {
            c0: F::reduce(simd, product.c0),
            c1: F::reduce(simd, product.c1),
        }
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
    use crate::field::fp::{
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
    const BOUND: u64 = 38;

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

    fn check<S: Simd, F: Field<S>>(simd: S, inputs: &[[u8; BYTES]; 4]) {
        let mut lanes = vec![[0; BYTES]; F::LANES + 1];
        Fp2::<F>::load(simd, &inputs[..1], &inputs[1]).store(simd, &mut lanes);
        assert_eq!(lanes[0], encode(decode(&inputs[0])));
        for lane in &lanes[1..F::LANES] {
            assert_eq!(*lane, encode(decode(&inputs[1])));
        }
        assert_eq!(lanes[F::LANES], [0; BYTES]);
        let [a, b, c, d] = inputs.map(|bytes| Fp2::<F>::load(simd, &[], &bytes));
        let [ra, rb, rc, rd] = inputs.map(|bytes| decode(&bytes));
        let assert_value = |value: Fp2<F>, expected: Reference| {
            let mut output = [[0; BYTES]];
            value.store(simd, &mut output);
            assert_eq!(output[0], encode(expected));
        };
        let zero = reference::ZERO;
        let one = reference::ONE;
        let i = (zero, one);
        assert_value(a.add(simd, b), add(ra, rb));
        assert_value(a.double(simd), add(ra, ra));
        assert_value(a.mul_small::<5, S>(simd), mul(ra, ([5, 0, 0, 0, 0, 0], zero)));
        assert_value(a.sub::<3, S>(simd, b), sub(ra, rb));
        assert_value(a.neg::<3, S>(simd), sub((zero, zero), ra));
        assert_value(a.conjugate::<3, S>(simd), (ra.0, reference::neg(ra.1)));
        assert_value(a.mul_by_nonresidue::<3, S>(simd), mul(ra, (one, one)));
        assert_value(a.mul(simd, b), mul(ra, rb));
        assert_value(Fp2::<F>::load(simd, &[], &encode(i)).mul(simd, a), mul(i, ra));
        assert_value(a.square::<3, S>(simd), mul(ra, ra));
        assert_value(a.mul_base(simd, b.c0), mul(ra, (rb.0, zero)));
        assert_value(Fp2::reduce(simd, a.lift(simd)), ra);
        let (ab, cd) = (a.product(simd, b), c.product(simd, d));
        assert_value(
            Fp2::reduce(simd, Fp2::<F>::accumulate(simd, ab, cd)),
            add(mul(ra, rb), mul(rc, rd)),
        );
        assert_value(
            Fp2::reduce(simd, Fp2::<F>::product_sub(simd, ab, c.lift(simd))),
            sub(mul(ra, rb), rc),
        );
        assert_value(
            Fp2::reduce(simd, Fp2::<F>::product_sub(simd, ab, c.product_base(simd, d.c0))),
            sub(mul(ra, rb), mul(rc, (rd.0, zero))),
        );
        // Chain multiplications through the bound they preserve, mixing in the operations whose
        // outputs exceed it before squaring them back down.
        let mut value = a;
        let mut expected = ra;
        for _ in 0..ROUNDS {
            value = value.mul(simd, b);
            expected = mul(expected, rb);
            // Components below BOUND + 1 and 2 * BOUND, carried to limb bound 1.
            value = value.mul_by_nonresidue::<{ BOUND + 1 }, S>(simd).carry(simd);
            expected = mul(expected, (one, one));
            value = value.square::<{ 2 * BOUND + 1 }, S>(simd);
            expected = mul(expected, expected);
            value = value.conjugate::<{ BOUND + 1 }, S>(simd).carry(simd);
            expected = (expected.0, reference::neg(expected.1));
            value = value.mul(simd, value);
            expected = mul(expected, expected);
        }
        assert_value(value, expected);
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
