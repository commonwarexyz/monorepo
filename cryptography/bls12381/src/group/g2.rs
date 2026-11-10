//! The group G2.

use super::{
    MSM_BATCH, Scalar,
    kernel::{Add, Double, Group, Kernel, MAX_COMPONENTS, Msm, Multiply, MultiplyEach, Sum},
};
use crate::core::{
    curve::g2::{Coordinates, GENERATOR, IDENTITY, Point},
    field::{
        arithmetic::Field,
        fp::{self, BYTES as FP_BYTES},
        fp2::BYTES,
    },
};
use commonware_formatting::Hex;
use commonware_math::algebra::{Additive, CryptoGroup, Object, Space};
use commonware_parallel::Strategy;
use commonware_simd::Simd;
use core::{
    fmt,
    ops::{self, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};

/// An element of G2, the subgroup of prime order `r` of the curve `y^2 = x^3 + 4 (1 + i)` over
/// the quadratic extension.
#[derive(Clone, Copy)]
pub struct G2(Coordinates);

impl Group for G2 {
    type Coordinates = Coordinates;
    type Points<S: Simd, F: Field<S>> = Point<F>;

    const IDENTITY: Coordinates = IDENTITY;

    // Products in the quadratic extension take fewer multiplies in residues than in the lanes.
    const SUM_BATCH: Option<usize> = None;
    const MULTIPLY_BATCH: Option<usize> = None;

    // Scalars split into four quarters of 64 bits: k = a0 + a1 |x| + a2 |x|^2 + a3 |x|^3 for
    // the eigenvalue x = -|x| of the endomorphism.
    const COMPONENTS: usize = 4;
    const COMPONENT_BITS: u32 = 65;

    fn components(scalar: &Scalar) -> [u128; MAX_COMPONENTS] {
        scalar.split_quarters().map(u128::from)
    }

    fn coordinates(&self) -> &Coordinates {
        &self.0
    }

    fn from_coordinates(coordinates: Coordinates) -> Self {
        Self(coordinates)
    }

    fn negate(&self) -> Self {
        let [x, mut y, z] = self.0;
        for component in y.as_chunks_mut::<FP_BYTES>().0 {
            *component = fp::neg(component);
        }
        Self([x, y, z])
    }

    fn is_identity(&self) -> bool {
        self.0[2] == [0; BYTES]
    }
}

impl fmt::Debug for G2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [x, y, z] = &self.0;
        f.debug_struct("G2")
            .field("x", &Hex(x))
            .field("y", &Hex(y))
            .field("z", &Hex(z))
            .finish()
    }
}

impl PartialEq for G2 {
    fn eq(&self, other: &Self) -> bool {
        Add(*self, other.negate()).dispatch().is_identity()
    }
}

impl Eq for G2 {}

impl Object for G2 {}

impl<'a> AddAssign<&'a Self> for G2 {
    fn add_assign(&mut self, rhs: &'a Self) {
        *self = Add(*self, *rhs).dispatch();
    }
}

impl<'a> ops::Add<&'a Self> for G2 {
    type Output = Self;

    fn add(mut self, rhs: &'a Self) -> Self {
        self += rhs;
        self
    }
}

impl<'a> SubAssign<&'a Self> for G2 {
    fn sub_assign(&mut self, rhs: &'a Self) {
        *self += &rhs.negate();
    }
}

impl<'a> Sub<&'a Self> for G2 {
    type Output = Self;

    fn sub(mut self, rhs: &'a Self) -> Self {
        self -= rhs;
        self
    }
}

impl Neg for G2 {
    type Output = Self;

    fn neg(self) -> Self {
        self.negate()
    }
}

impl Additive for G2 {
    fn zero() -> Self {
        Self(IDENTITY)
    }

    fn double(&mut self) {
        *self = Double(*self).dispatch();
    }

    /// Multiplies by an integer of any length without branching on its value.
    fn scale(&self, bits_le: &[u64]) -> Self {
        Multiply {
            element: *self,
            scalar: Scalar::from_words_wide(bits_le),
        }
        .dispatch()
    }
}

impl<'a> MulAssign<&'a Scalar> for G2 {
    fn mul_assign(&mut self, rhs: &'a Scalar) {
        *self = Multiply {
            element: *self,
            scalar: *rhs,
        }
        .dispatch();
    }
}

impl<'a> Mul<&'a Scalar> for G2 {
    type Output = Self;

    fn mul(mut self, rhs: &'a Scalar) -> Self {
        self *= rhs;
        self
    }
}

impl Space<Scalar> for G2 {
    /// Returns the sum of the points times their scalars, in variable time.
    ///
    /// The scalars must be public, as Lagrange coefficients and batch-verification weights are:
    /// the running time and memory accesses depend on them. A sequential strategy runs one kernel
    /// over all points, and a parallel one splits them into batches of at least 256 points.
    fn msm(points: &[Self], scalars: &[Scalar], strategy: &impl Strategy) -> Self {
        let count = points.len().min(scalars.len());
        let (points, scalars) = (&points[..count], &scalars[..count]);
        strategy.run_batches(count, MSM_BATCH, 1, |batches| {
            batches
                .map_collect_vec(
                    |ranges| ranges,
                    |range| {
                        Msm {
                            elements: &points[range.clone()],
                            scalars: &scalars[range],
                            plan: None,
                        }
                        .dispatch()
                    },
                )
                .iter()
                .fold(Self::zero(), |sum, batch| sum + batch)
        })
    }
}

impl CryptoGroup for G2 {
    type Scalar = Scalar;

    fn generator() -> Self {
        Self(GENERATOR)
    }
}

impl G2 {
    /// Returns the sum of the elements, as when aggregating keys or signatures.
    ///
    /// Adds one element per lane, so it costs far less than adding them one at a time.
    pub fn sum(elements: &[Self]) -> Self {
        Sum(elements).dispatch()
    }

    /// Multiplies each element by the scalar at the same index, in place, without branching on
    /// the scalars.
    ///
    /// Multiplies one element per lane. Elements beyond the scalars are unchanged, and scalars
    /// beyond the elements are ignored.
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
    static MULTIPLES: LazyLock<Vec<G2>> = LazyLock::new(shared::table);

    impl<'a> Arbitrary<'a> for G2 {
        fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
            Ok(shared::element(u)?.0)
        }
    }

    impl Element for G2 {
        fn eigenvalue() -> Scalar {
            // The curve parameter x, which is negative.
            -Scalar::from_u64(crate::group::scalar::X_ABS)
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
        use crate::{core::field::fp2::reference, group::vectors::G2_MULTIPLES};

        shared::tests!(G2);

        /// Returns the affine coordinates of an element other than the identity.
        fn affine(element: &G2) -> [[u8; BYTES]; 2] {
            let [x, y, z] = element.0.map(|coordinate| reference::decode(&coordinate));
            let inverse = reference::invert(z);
            [x, y].map(|coordinate| reference::encode(reference::mul(coordinate, inverse)))
        }

        #[test]
        fn multiples_match_known_answers() {
            let [x, y, _] = GENERATOR;
            assert_eq!(affine(&G2::generator()), [x, y]);
            for (scalar, expected) in G2_MULTIPLES {
                let scalar = Scalar::from_bytes(&scalar).expect("below the order");
                assert_eq!(affine(&(G2::generator() * &scalar)), expected);
            }
        }
    }
}
