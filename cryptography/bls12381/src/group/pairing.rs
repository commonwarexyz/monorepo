//! The pairing of G1 and G2 into the target group.

use super::{
    G1, G2, Hex,
    kernel::{self, Group, Kernel, MAX_LANES},
};
use crate::core::{
    curve::{g1, g2},
    field::{
        arithmetic::Field,
        fp::BYTES as FP_BYTES,
        fp2::{BYTES as FP2_BYTES, Fp2},
        fp12::{self, BYTES, Fp12},
    },
    pairing::{G1Affine, G2Affine, Pair, final_exponentiation, miller_loop},
};
use commonware_math::algebra::{Multiplicative, Object};
use commonware_simd::Simd;
use core::{
    array,
    fmt::{self, Debug, Formatter},
    ops::{Mul, MulAssign},
};

/// Most prepared pairs, one per lane, whose Miller loops share squarings.
const SHARED: usize = 4;

/// An element of GT, the subgroup of prime order `r` of the multiplicative group of the degree-12
/// extension, which the pairing maps into.
///
/// Elements arise only from pairings and their products, so every element lies in the subgroup.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct GT([u8; BYTES]);

impl GT {
    /// The identity, `e(P, 0)` for any `P`.
    pub const ONE: Self = Self(fp12::ONE);

    /// Returns the canonical encoding, a big-endian element of the degree-12 extension.
    pub const fn to_bytes(&self) -> [u8; BYTES] {
        self.0
    }
}

impl Debug for GT {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_tuple("GT").field(&Hex(&self.0)).finish()
    }
}

impl Object for GT {}

impl<'a> MulAssign<&'a Self> for GT {
    fn mul_assign(&mut self, rhs: &'a Self) {
        *self = kernel::dispatch(Product(*self, *rhs));
    }
}

impl<'a> Mul<&'a Self> for GT {
    type Output = Self;

    fn mul(mut self, rhs: &'a Self) -> Self {
        self *= rhs;
        self
    }
}

impl Multiplicative for GT {}

/// Returns the pairing `e(p, q)`.
pub fn pairing(p: &G1, q: &G2) -> GT {
    multi_pairing(&[(*p, *q)])
}

/// Returns the product of the pairings of `pairs`, with one shared final exponentiation, or
/// [`GT::ONE`] for no pairs.
///
/// A product of pairings is cheaper than the pairings it multiplies, so checks such as
/// `e(a, b) = e(c, d)` should compare `multi_pairing(&[(a, b), (-c, d)])` with [`GT::ONE`].
pub fn multi_pairing(pairs: &[(G1, G2)]) -> GT {
    kernel::dispatch(Pairings(pairs))
}

/// Multiplies two elements of GT.
#[derive(Clone, Copy)]
struct Product(GT, GT);

impl Kernel for Product {
    type Output = GT;

    #[inline(always)]
    fn run<S: Simd, F: Field<S>>(self, simd: S) -> GT {
        let a = Fp12::<F>::load(simd, &[], &self.0.0);
        let b = Fp12::<F>::load(simd, &[], &self.1.0);
        let mut output = [fp12::ONE];
        a.mul(simd, b).store(simd, &mut output);
        GT(output[0])
    }
}

/// Multiplies the pairings of pairs of elements.
#[derive(Clone, Copy)]
struct Pairings<'a>(&'a [(G1, G2)]);

impl Kernel for Pairings<'_> {
    type Output = GT;

    fn batch(&self) -> bool {
        self.0.len() > SHARED
    }

    // Debug builds keep this a call so that each representation's frame stays separate.
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn run<S: Simd, F: Field<S>>(self, simd: S) -> GT {
        const { assert!(F::LANES <= MAX_LANES) };
        // Pairs with an identity contribute one, so only the others are prepared. Unused lanes
        // hold a pair whose G1 coordinates are zero, which the final exponentiation maps to one.
        let generator = <G2 as commonware_math::algebra::CryptoGroup>::generator();
        let [x, y, _] = *generator.coordinates();
        let fill: (G1Affine, G2Affine) = ([[0; FP_BYTES]; 2], [x, y]);
        let mut pairs = self
            .0
            .iter()
            .filter(|(p, q)| !p.is_identity() && !q.is_identity())
            .peekable();
        let mut prepared = [Pair::<F>::load(simd, &[], &fill); SHARED];
        let mut count = 0;
        let mut product: Option<Fp12<F>> = None;
        while pairs.peek().is_some() {
            let mut points = [(g1::IDENTITY, g2::IDENTITY); MAX_LANES];
            let mut lanes = 0;
            for (p, q) in pairs.by_ref().take(F::LANES) {
                points[lanes] = (*p.coordinates(), *q.coordinates());
                lanes += 1;
            }
            let affine = to_affine::<S, F>(simd, &points[..lanes]);
            prepared[count] = Pair::load(simd, &affine[..lanes], &fill);
            count += 1;
            if count == SHARED || pairs.peek().is_none() {
                let lines = miller_loop(simd, &prepared[..count]);
                product = Some(product.map_or(lines, |product| product.mul(simd, lines)));
                count = 0;
            }
        }
        let Some(product) = product else {
            return GT::ONE;
        };
        let mut output = [fp12::ONE];
        final_exponentiation(simd, product.product_of_lanes(simd)).store(simd, &mut output);
        GT(output[0])
    }
}

/// Returns the affine coordinates of each lane's pair of points, none of which may be the
/// identity.
#[cfg_attr(not(debug_assertions), inline(always))]
fn to_affine<S: Simd, F: Field<S>>(
    simd: S,
    points: &[(g1::Coordinates, g2::Coordinates)],
) -> [(G1Affine, G2Affine); MAX_LANES] {
    let mut g1 = [g1::IDENTITY; MAX_LANES];
    let mut g2 = [g2::IDENTITY; MAX_LANES];
    for (lane, (p, q)) in points.iter().enumerate() {
        g1[lane] = *p;
        g2[lane] = *q;
    }
    let p = g1::Point::<F>::load(simd, &g1[..points.len()], &g1::IDENTITY);
    let q = g2::Point::<F>::load(simd, &g2[..points.len()], &g2::IDENTITY);
    // Loaded coordinates are tight with limb bound one, as inversion requires, and multiplying
    // them by tight inverses stays within every product bound.
    let p_inverse = p.z.invert(simd);
    let q_inverse = q.z.invert(simd);
    let mut px = [[0; FP_BYTES]; MAX_LANES];
    let mut py = [[0; FP_BYTES]; MAX_LANES];
    let mut qx = [[0; FP2_BYTES]; MAX_LANES];
    let mut qy = [[0; FP2_BYTES]; MAX_LANES];
    p.x.mul(simd, p_inverse).store(simd, &mut px);
    p.y.mul(simd, p_inverse).store(simd, &mut py);
    Fp2::mul::<64, S>(q.x, simd, q_inverse).store(simd, &mut qx);
    Fp2::mul::<64, S>(q.y, simd, q_inverse).store(simd, &mut qy);
    array::from_fn(|lane| ([px[lane], py[lane]], [qx[lane], qy[lane]]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{core::field::fp12::tests::from_blst, group::Scalar};
    use commonware_math::algebra::{Additive, CryptoGroup};
    use std::vec::Vec;

    /// Returns `e(a G1, b G2)` computed by blst.
    fn reference(a: u64, b: u64) -> GT {
        let scalar = |value: u64| {
            let mut bytes = [0u8; 32];
            bytes[..8].copy_from_slice(&value.to_le_bytes());
            bytes
        };
        let (a, b) = (scalar(a), scalar(b));
        let mut p = blst::blst_p1::default();
        let mut q = blst::blst_p2::default();
        let mut p_affine = blst::blst_p1_affine::default();
        let mut q_affine = blst::blst_p2_affine::default();
        let mut result = blst::blst_fp12::default();
        // SAFETY: every pointer references a valid value of the expected type, each scalar holds
        // 64 bits, and blst's final exponentiation accepts the same input and output.
        unsafe {
            blst::blst_p1_mult(&mut p, blst::blst_p1_generator(), a.as_ptr(), 64);
            blst::blst_p2_mult(&mut q, blst::blst_p2_generator(), b.as_ptr(), 64);
            blst::blst_p1_to_affine(&mut p_affine, &p);
            blst::blst_p2_to_affine(&mut q_affine, &q);
            blst::blst_miller_loop(&mut result, &q_affine, &p_affine);
            let pointer = &raw mut result;
            blst::blst_final_exp(pointer, pointer);
        }
        GT(from_blst(&result))
    }

    fn multiple<G: CryptoGroup<Scalar = Scalar>>(k: u64) -> G {
        G::generator() * &Scalar::from_u64(k)
    }

    #[test]
    fn pairings_match_blst() {
        for (a, b) in [(1, 1), (3, 5), (0xdead_beef, 7)] {
            assert_eq!(pairing(&multiple(a), &multiple(b)), reference(a, b));
        }
    }

    #[test]
    fn identities_pair_to_one() {
        assert_eq!(multi_pairing(&[]), GT::ONE);
        assert_eq!(pairing(&G1::zero(), &multiple(3)), GT::ONE);
        assert_eq!(pairing(&multiple(3), &G2::zero()), GT::ONE);
        let (p, q) = (multiple::<G1>(5), multiple::<G2>(7));
        assert_eq!(
            multi_pairing(&[(G1::zero(), q), (p, q), (p, G2::zero())]),
            pairing(&p, &q)
        );
    }

    #[test]
    fn products_match_separate_pairings() {
        // More pairs than share squarings in every lane of the widest representation.
        let ks = 1..=(SHARED * MAX_LANES) as u64 + 3;
        let pairs: Vec<(G1, G2)> = ks
            .clone()
            .map(|k| (multiple(k), multiple(k + 11)))
            .collect();
        // By bilinearity, the product is e(G1, G2) to the sum of k (k + 11).
        let exponent = ks.map(|k| k * (k + 11)).sum();
        let expected = pairing(&G1::generator(), &multiple(exponent));
        assert_eq!(multi_pairing(&pairs), expected);
        let (first, second) = pairs.split_at(7);
        assert_eq!(multi_pairing(first) * &multi_pairing(second), expected);
    }

    #[test]
    fn checks_are_bilinear() {
        let (p, q) = (multiple::<G1>(6), multiple::<G2>(35));
        let (r, s) = (multiple::<G1>(14), multiple::<G2>(15));
        assert_eq!(multi_pairing(&[(p, q), (-r, s)]), GT::ONE);
        assert_ne!(multi_pairing(&[(p, q), (r, s)]), GT::ONE);
    }

    /// Runs the pairing kernel in every representation, checking that they agree.
    struct Representations<'a>(Pairings<'a>);

    impl<S: Simd> commonware_simd::Operation<S> for Representations<'_> {
        type Output = GT;

        fn portable(self, simd: S) -> GT {
            use crate::core::field::fp::{rns::Rns, unsat28::Unsat28, unsat49::Unsat49};
            simd.execute(|simd: S| {
                let expected = self.0.run::<S, Unsat49<S>>(simd);
                assert_eq!(self.0.run::<S, Unsat28<S>>(simd), expected);
                assert_eq!(self.0.run::<S, Rns<S>>(simd), expected);
                expected
            })
        }
    }

    #[test]
    fn representations_agree() {
        let pairs = [
            (multiple::<G1>(3), multiple::<G2>(4)),
            (multiple::<G1>(5), G2::zero()),
            (multiple::<G1>(6), multiple::<G2>(7)),
        ];
        commonware_simd::check_consistent(|| Representations(Pairings(&pairs)));
    }
}
