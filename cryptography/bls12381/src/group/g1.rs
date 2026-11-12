//! The group G1.

use super::{
    Scalar, fmt_coordinates,
    kernel::{Add, Double, Group, Kernel, MAX_COMPONENTS, Multiply, MultiplyEach, Sum},
    msm,
};
use crate::core::{
    curve::g1::{Coordinates, GENERATOR, IDENTITY, Point},
    field::{
        MAX_LANES,
        arithmetic::Field,
        fp::{self, BYTES},
    },
};
use commonware_math::algebra::{Additive, CryptoGroup, Object, Space};
use commonware_parallel::Strategy;
use commonware_simd::Simd;
use core::{
    fmt,
    ops::{self, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};

/// An element of G1, the subgroup of prime order `r` of the curve `y^2 = x^3 + 4` over the base
/// field.
///
/// `Debug` prints the projective coordinates, which depend on the operations that produced the
/// element and not only on its value: compare elements with `==`, not through their `Debug`
/// output. The coordinates of a multiple by a secret scalar can reveal information about the
/// scalar, so do not log such an element through `Debug`.
#[derive(Clone, Copy)]
pub struct G1(Coordinates);

impl Group for G1 {
    type Coordinates = Coordinates;
    type Points<S: Simd, F: Field<S>> = Point<F>;

    const IDENTITY: Coordinates = IDENTITY;

    // Up to these counts, residues, which hold one element at a time, finish sooner than Unsat49:
    // a pass of Unsat49 costs the same however many of its lanes hold elements, and its sum ends
    // with additions across the lanes.
    const SUM_BATCH: Option<usize> = Some(MAX_LANES);
    const MULTIPLY_BATCH: Option<usize> = Some(8);

    // Scalars split into two halves of 128 bits: k = a + b x^2 for the eigenvalue -x^2 of the
    // endomorphism.
    const COMPONENTS: usize = 2;
    const COMPONENT_BITS: u32 = 129;

    fn components(scalar: &Scalar) -> [[u64; 2]; MAX_COMPONENTS] {
        let [a, b] = scalar.split();
        [a, b, [0; 2], [0; 2]]
    }

    fn coordinates(&self) -> &Coordinates {
        &self.0
    }

    fn from_coordinates(coordinates: Coordinates) -> Self {
        Self(coordinates)
    }
}

impl fmt::Debug for G1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt_coordinates("G1", &self.0, f)
    }
}

impl PartialEq for G1 {
    fn eq(&self, other: &Self) -> bool {
        Add(*self, -*other).dispatch().is_identity()
    }
}

impl Eq for G1 {}

impl Object for G1 {}

impl<'a> AddAssign<&'a Self> for G1 {
    fn add_assign(&mut self, rhs: &'a Self) {
        *self = Add(*self, *rhs).dispatch();
    }
}

impl<'a> ops::Add<&'a Self> for G1 {
    type Output = Self;

    fn add(mut self, rhs: &'a Self) -> Self {
        self += rhs;
        self
    }
}

impl<'a> SubAssign<&'a Self> for G1 {
    fn sub_assign(&mut self, rhs: &'a Self) {
        *self += &-*rhs;
    }
}

impl<'a> Sub<&'a Self> for G1 {
    type Output = Self;

    fn sub(mut self, rhs: &'a Self) -> Self {
        self -= rhs;
        self
    }
}

impl Neg for G1 {
    type Output = Self;

    fn neg(self) -> Self {
        let [x, y, z] = self.0;
        Self([x, fp::neg(&y), z])
    }
}

impl Additive for G1 {
    fn zero() -> Self {
        Self(IDENTITY)
    }

    fn double(&mut self) {
        *self = Double(*self).dispatch();
    }

    /// Multiplies by the little-endian integer `bits_le` of any length, in time independent of
    /// its value.
    fn scale(&self, bits_le: &[u64]) -> Self {
        Multiply {
            element: *self,
            scalar: Scalar::from_words_wide(bits_le),
        }
        .dispatch()
    }
}

impl<'a> MulAssign<&'a Scalar> for G1 {
    fn mul_assign(&mut self, rhs: &'a Scalar) {
        *self = Multiply {
            element: *self,
            scalar: *rhs,
        }
        .dispatch();
    }
}

impl<'a> Mul<&'a Scalar> for G1 {
    type Output = Self;

    fn mul(mut self, rhs: &'a Scalar) -> Self {
        self *= rhs;
        self
    }
}

impl Space<Scalar> for G1 {
    /// Returns the sum of the points times their scalars, in variable time.
    ///
    /// The scalars must be public, as Lagrange coefficients and batch-verification weights are:
    /// the running time and memory accesses depend on them. A parallel strategy may split the
    /// points into batches of at least 256, so fewer than 512 points always run on the calling
    /// thread.
    fn msm(points: &[Self], scalars: &[Scalar], strategy: &impl Strategy) -> Self {
        msm::batched(points, scalars, strategy)
    }
}

impl CryptoGroup for G1 {
    type Scalar = Scalar;

    fn generator() -> Self {
        Self(GENERATOR)
    }
}

impl G1 {
    /// Returns whether this is the identity.
    pub(crate) fn is_identity(&self) -> bool {
        self.0[2] == [0; BYTES]
    }

    /// Returns the sum of the elements, as when aggregating keys or signatures.
    ///
    /// Costs less per element than adding the elements one at a time with `+`.
    pub fn sum(elements: &[Self]) -> Self {
        Sum(elements).dispatch()
    }

    /// Multiplies each element by the scalar at the same index, in place, in time independent of
    /// the scalars' values.
    ///
    /// Elements beyond the scalars are unchanged, and scalars beyond the elements are ignored.
    /// Costs less per element than multiplying the elements one at a time with `*`.
    pub fn mul_each(elements: &mut [Self], scalars: &[Scalar]) {
        MultiplyEach { elements, scalars }.dispatch();
    }
}

/// Fuzzing support for this group.
#[cfg(any(test, feature = "fuzz"))]
mod fuzz {
    use super::*;
    use crate::group::fuzz::{self as shared, Element};
    use arbitrary::{Arbitrary, Unstructured};
    use std::{sync::LazyLock, vec::Vec};

    /// The small multiples of the generator.
    static MULTIPLES: LazyLock<Vec<G1>> = LazyLock::new(shared::table);

    impl<'a> Arbitrary<'a> for G1 {
        fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
            Ok(shared::element(u)?.0)
        }
    }

    impl Element for G1 {
        fn eigenvalue() -> Scalar {
            // -x^2 for the curve parameter x.
            let [low, high] = crate::group::scalar::X_SQUARED;
            -Scalar::from_words([low, high, 0, 0]).expect("below the order")
        }

        fn multiples() -> &'static [Self] {
            &MULTIPLES
        }

        fn sum(elements: &[Self]) -> Self {
            Self::sum(elements)
        }

        fn mul_each(elements: &mut [Self], scalars: &[Scalar]) {
            Self::mul_each(elements, scalars);
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::{core::field::fp::reference, group::vectors::G1_MULTIPLES};

        /// Returns the affine coordinates of an element other than the identity.
        fn affine(element: &G1) -> [[u8; BYTES]; 2] {
            let [x, y, z] = element.0.map(|coordinate| reference::decode(&coordinate));
            let inverse = reference::invert(z);
            [x, y].map(|coordinate| reference::encode(reference::mul(coordinate, inverse)))
        }

        #[test]
        fn multiples_match_known_answers() {
            for (scalar, expected) in G1_MULTIPLES {
                let scalar = Scalar::from_bytes(&scalar).expect("below the order");
                assert_eq!(affine(&(G1::generator() * &scalar)), expected);
            }
        }
    }
}
