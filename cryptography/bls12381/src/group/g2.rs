//! The group G2.

use super::{
    Scalar,
    kernel::{Group, Kernel, MAX_COMPONENTS, MultiplyEach, Sum},
    msm::Msm,
};
use crate::core::{
    curve::g2::{Coordinates, GENERATOR, IDENTITY, Point},
    field::{
        arithmetic::Field,
        fp::{self, BYTES as FP_BYTES},
    },
};
use commonware_simd::Simd;
use core::ops::Neg;

/// An element of G2, the subgroup of prime order `r` of the curve `y^2 = x^3 + 4 (1 + i)` over
/// the quadratic extension.
///
/// `Debug` prints the projective coordinates, which depend on the operations that produced the
/// element and not only on its value: compare elements with `==`, not through their `Debug`
/// output. The coordinates of a multiple by a secret scalar can reveal information about the
/// scalar, so do not log such an element through `Debug`.
#[derive(Clone, Copy)]
pub struct G2(Coordinates);

impl Group for G2 {
    type Coordinates = Coordinates;
    type Points<S: Simd, F: Field<S>> = Point<F>;

    const IDENTITY: Coordinates = IDENTITY;

    // An addition of G2 multiplies in the quadratic extension, where each product takes three or
    // four products in the base field.
    const WORK: usize = 4;

    // Residues finish every count sooner than Unsat49: a product in the quadratic extension takes
    // fewer multiply instructions in residues than in the lanes of Unsat49.
    const SUM_BATCH: Option<usize> = None;
    const MULTIPLY_BATCH: Option<usize> = None;

    // Scalars split into four quarters of 64 bits: k = a0 + a1 |x| + a2 |x|^2 + a3 |x|^3 for
    // the eigenvalue x = -|x| of the endomorphism.
    const COMPONENTS: usize = 4;
    const COMPONENT_BITS: u32 = 65;

    fn components(scalar: &Scalar) -> [[u64; 2]; MAX_COMPONENTS] {
        scalar.split_quarters().map(|quarter| [quarter, 0])
    }

    // The three functions below have no type parameters, so the kernels compile once, in this
    // crate, and not for every strategy and crate that reaches them through
    // Batch::dispatch_batches.

    fn dispatch_sum(kernel: Sum<'_, Self>) -> Self {
        kernel.dispatch()
    }

    fn dispatch_multiply_each(kernel: MultiplyEach<'_, Self>) {
        kernel.dispatch();
    }

    fn dispatch_msm(kernel: Msm<'_, Self>) -> Self {
        kernel.dispatch()
    }

    fn coordinates(&self) -> &Coordinates {
        &self.0
    }

    fn from_coordinates(coordinates: Coordinates) -> Self {
        Self(coordinates)
    }
}

impl Neg for G2 {
    type Output = Self;

    fn neg(self) -> Self {
        let [x, mut y, z] = self.0;
        for component in y.as_chunks_mut::<FP_BYTES>().0 {
            *component = fp::neg(component);
        }
        Self([x, y, z])
    }
}

impl_group!(
    G2,
    generator: GENERATOR,
    // The curve parameter x, which is negative.
    eigenvalue: -Scalar::from_u64(crate::core::curve::X_ABS),
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        core::field::fp2::{BYTES, reference},
        group::vectors::G2_MULTIPLES,
    };
    use commonware_math::algebra::CryptoGroup;

    /// Returns the affine coordinates of an element other than the identity.
    fn affine(element: &G2) -> [[u8; BYTES]; 2] {
        let [x, y, z] = element.0.map(|coordinate| reference::decode(&coordinate));
        let inverse = reference::invert(z);
        [x, y].map(|coordinate| reference::encode(reference::mul(coordinate, inverse)))
    }

    #[test]
    fn multiples_match_known_answers() {
        for (scalar, expected) in G2_MULTIPLES {
            let scalar = Scalar::from_bytes(&scalar).expect("below the order");
            assert_eq!(affine(&(G2::generator() * &scalar)), expected);
        }
    }
}
