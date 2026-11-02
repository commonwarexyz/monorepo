//! The group G1.

use super::kernel::Group;
use crate::core::{
    curve::g1::{Coordinates, IDENTITY, Point},
    field::{
        arithmetic::Field,
        fp::{self, BYTES},
    },
};
use commonware_simd::Simd;

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

super::group_traits!(G1);

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
    fn representations_agree() {
        shared::check_representations::<G1>();
    }

    #[test]
    fn satisfies_space_laws() {
        // Each case multiplies several times, so a few cases keep debug builds fast.
        minifuzz::Builder::default()
            .with_search_limit(8)
            .test(test_suites::fuzz_space_ring::<Scalar, G1>);
    }
}
