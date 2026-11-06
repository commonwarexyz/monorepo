//! The group G2.

use super::kernel::Group;
use crate::core::{
    curve::g2::{Coordinates, IDENTITY, Point},
    field::{
        arithmetic::Field,
        fp::{self, BYTES as FP_BYTES},
        fp2::BYTES,
    },
};
use commonware_simd::Simd;

/// The generator in projective coordinates, with `Z = 1`. Each coordinate is `c1` followed by
/// `c0`.
const GENERATOR: Coordinates = [
    super::hex(concat!(
        "13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e",
        "024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8",
    )),
    super::hex(concat!(
        "0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be",
        "0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801",
    )),
    {
        let mut one = [0; BYTES];
        one[BYTES - 1] = 1;
        one
    },
];

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

super::group_traits!(G2);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::group::{Scalar, tests as shared};
    use arbitrary::{Arbitrary, Unstructured};
    use commonware_invariants::minifuzz;
    use commonware_math::algebra::{CryptoGroup, test_suites};

    impl<'a> Arbitrary<'a> for G2 {
        fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
            Ok(Self::generator() * &Scalar::arbitrary(u)?)
        }
    }

    /// Returns `scalar` times the generator, computed by blst, with `Z = 1` unless it is the
    /// identity.
    fn reference(scalar: &Scalar) -> G2 {
        let mut bytes = [0u8; 32];
        for (chunk, word) in bytes
            .as_chunks_mut::<8>()
            .0
            .iter_mut()
            .zip(scalar.to_words())
        {
            *chunk = word.to_le_bytes();
        }
        let mut point = blst::blst_p2::default();
        let mut affine = blst::blst_p2_affine::default();
        let mut coordinates = GENERATOR;
        // SAFETY: every pointer references a valid value of the expected type, the scalar holds
        // 256 bits, and each output buffer holds a base field element: `c1` in the first half of
        // an extension encoding and `c0` in the second.
        unsafe {
            blst::blst_p2_mult(&mut point, blst::blst_p2_generator(), bytes.as_ptr(), 256);
            if blst::blst_p2_is_inf(&point) {
                return G2(IDENTITY);
            }
            blst::blst_p2_to_affine(&mut affine, &point);
            for (coordinate, value) in coordinates.iter_mut().zip([affine.x, affine.y]) {
                blst::blst_bendian_from_fp(coordinate.as_mut_ptr(), &value.fp[1]);
                blst::blst_bendian_from_fp(coordinate[FP_BYTES..].as_mut_ptr(), &value.fp[0]);
            }
        }
        G2(coordinates)
    }

    #[test]
    fn generator_matches_blst() {
        assert_eq!(G2::generator().0, reference(&Scalar::ONE).0);
    }

    #[test]
    fn operations_match_blst() {
        shared::check_operations(reference);
    }

    #[test]
    fn msm_matches_multiplications() {
        shared::check_msm::<G2>();
    }

    #[test]
    fn sum_matches_additions() {
        shared::check_sum::<G2>(G2::sum);
    }

    #[test]
    fn mul_each_matches_multiplications() {
        shared::check_mul_each::<G2>(G2::mul_each);
    }

    #[test]
    fn representations_agree() {
        shared::check_representations::<G2>();
    }

    #[test]
    fn satisfies_space_laws() {
        // Each case multiplies several times, so a few cases keep debug builds fast.
        minifuzz::Builder::default()
            .with_search_limit(4)
            .test(test_suites::fuzz_space_ring::<Scalar, G2>);
    }
}
