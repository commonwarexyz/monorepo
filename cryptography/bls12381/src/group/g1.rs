//! The group G1.

use super::{
    Hex, MSM_BATCH, Scalar,
    kernel::{
        Add, Double, Group, MAX_COMPONENTS, MAX_LANES, Msm, Multiply, MultiplyEach, Sum, dispatch,
    },
};
use crate::core::{
    curve::g1::{Coordinates, IDENTITY, Point},
    field::{
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

/// The generator in projective coordinates, with `Z = 1`.
const GENERATOR: Coordinates = [
    super::hex(
        "17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
    ),
    super::hex(
        "08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1",
    ),
    {
        let mut one = [0; BYTES];
        one[BYTES - 1] = 1;
        one
    },
];

/// An element of G1, the subgroup of prime order `r` of the curve `y^2 = x^3 + 4` over the base
/// field.
#[derive(Clone, Copy)]
pub struct G1(Coordinates);

impl Group for G1 {
    type Coordinates = Coordinates;
    type Points<S: Simd, F: Field<S>> = Point<F>;

    const IDENTITY: Coordinates = IDENTITY;

    // The lanes' sums cost additions of their own, and their pass over every lane costs as much
    // whether the lanes are full or not, so a few elements finish sooner one at a time.
    const SUM_BATCH: Option<usize> = Some(MAX_LANES);
    const MULTIPLY_BATCH: Option<usize> = Some(8);

    // Scalars split into two halves of 128 bits: k = a + b x^2 for the eigenvalue -x^2 of the
    // endomorphism.
    const COMPONENTS: usize = 2;
    const COMPONENT_BITS: u32 = 129;

    fn components(scalar: &Scalar) -> [u128; MAX_COMPONENTS] {
        let [a, b] = scalar.split();
        [a, b, 0, 0]
    }

    fn coordinates(&self) -> &Coordinates {
        &self.0
    }

    fn from_coordinates(coordinates: Coordinates) -> Self {
        Self(coordinates)
    }

    fn negate(&self) -> Self {
        let [x, y, z] = self.0;
        Self([x, fp::neg(&y), z])
    }

    fn is_identity(&self) -> bool {
        self.0[2] == [0; BYTES]
    }
}

impl fmt::Debug for G1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [x, y, z] = &self.0;
        f.debug_struct("G1")
            .field("x", &Hex(x))
            .field("y", &Hex(y))
            .field("z", &Hex(z))
            .finish()
    }
}

impl PartialEq for G1 {
    fn eq(&self, other: &Self) -> bool {
        dispatch(Add(*self, other.negate())).is_identity()
    }
}

impl Eq for G1 {}

impl Object for G1 {}

impl<'a> AddAssign<&'a Self> for G1 {
    fn add_assign(&mut self, rhs: &'a Self) {
        *self = dispatch(Add(*self, *rhs));
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
        *self += &rhs.negate();
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
        self.negate()
    }
}

impl Additive for G1 {
    fn zero() -> Self {
        Self(IDENTITY)
    }

    fn double(&mut self) {
        *self = dispatch(Double(*self));
    }

    /// Multiplies by an integer of any length without branching on its value.
    fn scale(&self, bits_le: &[u64]) -> Self {
        dispatch(Multiply {
            element: *self,
            scalar: Scalar::from_words_wide(bits_le),
        })
    }
}

impl<'a> MulAssign<&'a Scalar> for G1 {
    fn mul_assign(&mut self, rhs: &'a Scalar) {
        *self = dispatch(Multiply {
            element: *self,
            scalar: *rhs,
        });
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
                        dispatch(Msm {
                            elements: &points[range.clone()],
                            scalars: &scalars[range],
                            plan: None,
                        })
                    },
                )
                .iter()
                .fold(Self::zero(), |sum, batch| sum + batch)
        })
    }
}

impl CryptoGroup for G1 {
    type Scalar = Scalar;

    fn generator() -> Self {
        Self(GENERATOR)
    }
}

impl G1 {
    /// Returns the sum of the elements, as when aggregating keys or signatures.
    ///
    /// Adds one element per lane, so it costs far less than adding them one at a time.
    pub fn sum(elements: &[Self]) -> Self {
        dispatch(Sum(elements))
    }

    /// Multiplies each element by the scalar at the same index, in place, without branching on
    /// the scalars.
    ///
    /// Multiplies one element per lane. Elements beyond the scalars are unchanged, and scalars
    /// beyond the elements are ignored.
    pub fn mul_each(elements: &mut [Self], scalars: &[Scalar]) {
        dispatch(MultiplyEach { elements, scalars });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::group::{Scalar, tests as shared};
    use arbitrary::{Arbitrary, Unstructured};
    use commonware_invariants::minifuzz;
    use commonware_math::algebra::{CryptoGroup, test_suites};

    impl<'a> Arbitrary<'a> for G1 {
        fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
            Ok(Self::generator() * &Scalar::arbitrary(u)?)
        }
    }

    /// Returns `scalar` times the generator, computed by blst, with `Z = 1` unless it is the
    /// identity.
    fn reference(scalar: &Scalar) -> G1 {
        let mut bytes = [0u8; 32];
        for (chunk, word) in bytes
            .as_chunks_mut::<8>()
            .0
            .iter_mut()
            .zip(scalar.to_words())
        {
            *chunk = word.to_le_bytes();
        }
        let mut point = blst::blst_p1::default();
        let mut affine = blst::blst_p1_affine::default();
        let mut coordinates = GENERATOR;
        // SAFETY: every pointer references a valid value of the expected type, the scalar holds
        // 256 bits, and each output buffer holds a base field element.
        unsafe {
            blst::blst_p1_mult(&mut point, blst::blst_p1_generator(), bytes.as_ptr(), 256);
            if blst::blst_p1_is_inf(&point) {
                return G1(IDENTITY);
            }
            blst::blst_p1_to_affine(&mut affine, &point);
            blst::blst_bendian_from_fp(coordinates[0].as_mut_ptr(), &affine.x);
            blst::blst_bendian_from_fp(coordinates[1].as_mut_ptr(), &affine.y);
        }
        G1(coordinates)
    }

    #[test]
    fn generator_matches_blst() {
        assert_eq!(G1::generator().0, reference(&Scalar::ONE).0);
    }

    #[test]
    fn operations_match_blst() {
        shared::check_operations(reference);
    }

    #[test]
    fn msm_matches_multiplications() {
        shared::check_msm::<G1>();
    }

    #[test]
    fn sum_matches_additions() {
        shared::check_sum::<G1>(G1::sum);
    }

    #[test]
    fn mul_each_matches_multiplications() {
        shared::check_mul_each::<G1>(G1::mul_each);
    }

    #[test]
    fn representations_agree() {
        shared::check_representations::<G1>();
    }

    #[test]
    fn endomorphism_multiplies_by_eigenvalue() {
        // -x^2 for the curve parameter x.
        let [low, high] = crate::group::scalar::X_SQUARED;
        shared::check_endomorphism::<G1>(-Scalar::from_words([low, high, 0, 0]).unwrap());
    }

    #[test]
    fn satisfies_space_laws() {
        // Each case multiplies several times, so a few cases keep debug builds fast.
        minifuzz::Builder::default()
            .with_search_limit(8)
            .test(test_suites::fuzz_space_ring::<Scalar, G1>);
    }
}
