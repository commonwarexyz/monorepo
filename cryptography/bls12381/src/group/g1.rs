//! The group G1.

use super::{
    Scalar,
    kernel::{Group, MAX_COMPONENTS},
};
use crate::core::{
    curve::g1::{Coordinates, GENERATOR, IDENTITY, Point},
    field::{MAX_LANES, arithmetic::Field, fp},
};
use commonware_simd::Simd;
use core::ops::Neg;

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

impl Neg for G1 {
    type Output = Self;

    fn neg(self) -> Self {
        let [x, y, z] = self.0;
        Self([x, fp::neg(&y), z])
    }
}

impl_group!(
    G1,
    generator: GENERATOR,
    // -x^2 for the curve parameter x.
    eigenvalue: {
        let [low, high] = crate::group::scalar::X_SQUARED;
        -Scalar::from_words([low, high, 0, 0]).expect("below the order")
    },
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        core::field::fp::{BYTES, reference},
        group::vectors::G1_MULTIPLES,
    };
    use commonware_math::algebra::CryptoGroup;

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
