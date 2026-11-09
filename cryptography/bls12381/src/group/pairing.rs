//! The pairing of G1 and G2 into the target group.

use super::{
    G1, G2,
    kernel::{Group, Kernel, MAX_LANES},
};
use crate::core::{
    curve::{Points, g1, g2},
    field::{
        arithmetic::{Field, TIGHT},
        fp::BYTES as FP_BYTES,
        fp2::{BYTES as FP2_BYTES, Fp2},
        fp12::{self, BYTES, Fp12},
    },
    pairing::{G1Affine, G2Affine, Pair, SHARED, final_exponentiation, miller_loop},
};
use commonware_formatting::Hex;
use commonware_math::algebra::{Multiplicative, Object};
use alloc::{vec, vec::Vec};
use commonware_simd::Simd;
use core::{
    fmt::{self, Debug, Formatter},
    ops::{Mul, MulAssign},
};

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
        *self = Product(*self, *rhs).dispatch();
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

/// Computes the pairing of each pair into the output at the same index, as when verifying many
/// signatures separately.
///
/// Pairs one pair per lane. Outputs beyond the pairs are unchanged, and pairs beyond the outputs
/// are ignored.
pub fn pairings(pairs: &[(G1, G2)], outputs: &mut [GT]) {
    Each(pairs, outputs).dispatch();
}

/// Returns the product of the pairings of `pairs`, with one shared final exponentiation, or
/// [`GT::ONE`] for no pairs.
///
/// A product of pairings is cheaper than the pairings it multiplies, so checks such as
/// `e(a, b) = e(c, d)` should compare `multi_pairing(&[(a, b), (-c, d)])` with [`GT::ONE`].
pub fn multi_pairing(pairs: &[(G1, G2)]) -> GT {
    Pairings(pairs).dispatch()
}

/// Multiplies two elements of GT.
#[derive(Clone, Copy)]
struct Product(GT, GT);

impl Kernel for Product {
    type Output = GT;

    #[inline(always)]
    fn run<S: Simd, F: Field<S>>(self, simd: S) -> GT {
        let mut a = Fp12::<F>::load(simd, &[], &self.0.0);
        let b = Fp12::<F>::load(simd, &[], &self.1.0);
        let mut output = [fp12::ONE];
        a.mul(simd, &b);
        a.store(simd, &mut output);
        GT(output[0])
    }
}

/// Multiplies the pairings of pairs of elements.
#[derive(Clone, Copy)]
struct Pairings<'a>(&'a [(G1, G2)]);

impl Pairings<'_> {
    /// Returns the product of the Miller loops of the pairs without an identity, as its canonical
    /// encoding, or `None` when there are none.
    ///
    /// Up to [`SHARED`] lanes of pairs share their squarings, and the lanes of their product
    /// multiply into one element.
    // Debug builds keep this a call so that each representation's frame stays separate.
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn miller_loops<S: Simd, F: Field<S>>(self, simd: S) -> Option<[u8; BYTES]> {
        const { assert!(F::LANES <= MAX_LANES) };
        // Pairs with an identity contribute one, so only the others are prepared. Unused lanes
        // hold the fill pair.
        let fill = fill();
        let points: Vec<_> = self
            .0
            .iter()
            .filter(|(p, q)| !p.is_identity() && !q.is_identity())
            .map(|(p, q)| (*p.coordinates(), *q.coordinates()))
            .collect();
        let affine = to_affine::<S, F>(simd, &points);
        let mut prepared = [Pair::<F>::load(simd, &[], &fill); SHARED];
        let mut count = 0;
        let mut product: Option<Fp12<F>> = None;
        let mut groups = affine.chunks(F::LANES).peekable();
        while let Some(group) = groups.next() {
            prepared[count] = Pair::load(simd, group, &fill);
            count += 1;
            if count == SHARED || groups.peek().is_none() {
                let lines = miller_loop(simd, &prepared[..count]);
                match &mut product {
                    Some(product) => product.mul(simd, &lines),
                    None => product = Some(lines),
                }
                count = 0;
            }
        }
        let mut output = [fp12::ONE];
        product?.product_of_lanes(simd).store(simd, &mut output);
        Some(output[0])
    }

    /// Returns the final exponentiation of the product of Miller loops.
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn exponentiate<S: Simd, F: Field<S>>(simd: S, product: &[u8; BYTES]) -> GT {
        let mut output = [fp12::ONE];
        final_exponentiation(simd, Fp12::<F>::load(simd, &[], product)).store(simd, &mut output);
        GT(output[0])
    }
}

/// Returns a pair that pairs to one and fills unused lanes: its G1 coordinates are zero, which
/// the final exponentiation maps to one, and its G2 point is the generator, whose lines have
/// nonzero constant terms.
fn fill() -> (G1Affine, G2Affine) {
    let generator = <G2 as commonware_math::algebra::CryptoGroup>::generator();
    let [x, y, _] = *generator.coordinates();
    ([[0; FP_BYTES]; 2], [x, y])
}

impl Kernel for Pairings<'_> {
    type Output = GT;

    #[inline(always)]
    fn run<S: Simd, F: Field<S>>(self, simd: S) -> GT {
        self.miller_loops::<S, F>(simd).map_or(GT::ONE, |product| {
            Self::exponentiate::<S, F>(simd, &product)
        })
    }
}

/// Computes the pairing of each pair, one pair per lane.
struct Each<'a>(&'a [(G1, G2)], &'a mut [GT]);

impl Kernel for Each<'_> {
    type Output = ();

    // Debug builds keep this a call so that each representation's frame stays separate.
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn run<S: Simd, F: Field<S>>(self, simd: S) {
        const { assert!(F::LANES <= MAX_LANES) };
        let fill = fill();
        // The fill pair in projective coordinates, which convert to its affine coordinates.
        let mut filler = (g1::IDENTITY, g2::IDENTITY);
        filler.0[2][FP_BYTES - 1] = 1;
        filler.1 = *<G2 as commonware_math::algebra::CryptoGroup>::generator().coordinates();
        let count = self.0.len().min(self.1.len());
        // Pairs with an identity pair to one, so their lanes hold the fill pair, which the
        // conversion to affine coordinates accepts.
        let points: Vec<_> = self.0[..count]
            .iter()
            .map(|(p, q)| {
                if p.is_identity() || q.is_identity() {
                    filler
                } else {
                    (*p.coordinates(), *q.coordinates())
                }
            })
            .collect();
        let affine = to_affine::<S, F>(simd, &points);
        for ((pairs, affine), outputs) in self.0[..count]
            .chunks(F::LANES)
            .zip(affine.chunks(F::LANES))
            .zip(self.1[..count].chunks_mut(F::LANES))
        {
            let prepared = Pair::<F>::load(simd, affine, &fill);
            let lines = miller_loop(simd, &[prepared]);
            let mut results = [fp12::ONE; MAX_LANES];
            final_exponentiation(simd, lines).store(simd, &mut results[..pairs.len()]);
            for ((output, (p, q)), result) in outputs.iter_mut().zip(pairs).zip(results) {
                *output = if p.is_identity() || q.is_identity() {
                    GT::ONE
                } else {
                    GT(result)
                };
            }
        }
    }
}

/// Returns the affine coordinates of each pair of points, none of which may be the identity.
///
/// One inversion serves every pair, as Montgomery's trick: the G1 denominators and the norms of
/// the G2 denominators multiply up in turn, the total inverts, and each inverse unwinds from the
/// total with the running products. Runs as its own kernel, so that the conversions have the
/// backend's instructions.
#[cfg_attr(not(debug_assertions), inline(always))]
fn to_affine<S: Simd, F: Field<S>>(
    simd: S,
    points: &[(g1::Coordinates, g2::Coordinates)],
) -> Vec<(G1Affine, G2Affine)> {
    const { assert!(F::LANES <= MAX_LANES) };
    if points.is_empty() {
        return Vec::new();
    }
    // Unused lanes hold points with denominator one, which leave the products unchanged.
    let mut p_fill = g1::IDENTITY;
    p_fill[2][FP_BYTES - 1] = 1;
    let mut q_fill = g2::IDENTITY;
    q_fill[2][FP2_BYTES - 1] = 1;
    simd.execute(
        #[inline(always)]
        move |simd: S| {
            let groups = points.len().div_ceil(F::LANES);
            let mut loaded = Vec::with_capacity(groups);
            // The G1 denominator and the norm of the G2 denominator of each group, tight with
            // limb bound one, as inversion requires.
            let mut denominators = Vec::with_capacity(2 * groups);
            for group in points.chunks(F::LANES) {
                let mut g1 = [p_fill; MAX_LANES];
                let mut g2 = [q_fill; MAX_LANES];
                for (lane, (p, q)) in group.iter().enumerate() {
                    g1[lane] = *p;
                    g2[lane] = *q;
                }
                let p = g1::Point::<F>::load(simd, &g1[..group.len()], &p_fill);
                let q = g2::Point::<F>::load(simd, &g2[..group.len()], &q_fill);
                let norm = F::accumulate_product(simd, q.z.c0.product(simd, q.z.c0), q.z.c1, q.z.c1);
                denominators.push(p.z);
                denominators.push(F::reduce_tight(simd, norm));
                loaded.push((p, q));
            }
            let mut running = Vec::with_capacity(denominators.len());
            let mut total = denominators[0];
            running.push(total);
            for &denominator in &denominators[1..] {
                total = F::reduce_tight(simd, total.product(simd, denominator));
                running.push(total);
            }
            let mut inverse = total.invert(simd);
            let mut inverses = vec![inverse; denominators.len()];
            for i in (1..denominators.len()).rev() {
                inverses[i] = F::reduce_tight(simd, inverse.product(simd, running[i - 1]));
                inverse = F::reduce_tight(simd, inverse.product(simd, denominators[i]));
            }
            inverses[0] = inverse;

            let mut affine = Vec::with_capacity(points.len());
            for (group, (p, q)) in loaded.into_iter().enumerate() {
                let lanes = (points.len() - group * F::LANES).min(F::LANES);
                let (p_inverse, norm_inverse) = (inverses[2 * group], inverses[2 * group + 1]);
                // The inverse of the G2 denominator is its conjugate over its norm.
                let conjugate = q.z.conjugate::<{ TIGHT + 1 }, S>(simd).carry(simd);
                let q_inverse = Fp2::reduce_tight::<1, S>(simd, conjugate.product_base(simd, norm_inverse));
                // Multiplying tight coordinates by tight inverses stays within every product
                // bound.
                let mut px = [[0; FP_BYTES]; MAX_LANES];
                let mut py = [[0; FP_BYTES]; MAX_LANES];
                let mut qx = [[0; FP2_BYTES]; MAX_LANES];
                let mut qy = [[0; FP2_BYTES]; MAX_LANES];
                p.x.mul(simd, p_inverse).store(simd, &mut px);
                p.y.mul(simd, p_inverse).store(simd, &mut py);
                Fp2::mul::<64, S>(q.x, simd, q_inverse).store(simd, &mut qx);
                Fp2::mul::<64, S>(q.y, simd, q_inverse).store(simd, &mut qy);
                for lane in 0..lanes {
                    affine.push(([px[lane], py[lane]], [qx[lane], qy[lane]]));
                }
            }
            affine
        },
    )
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
    fn pairings_match_separate_pairings() {
        // More pairs than the lanes of the widest representation, with identities among them.
        let mut pairs: Vec<(G1, G2)> = (1..=MAX_LANES as u64 + 3)
            .map(|k| (multiple(k), multiple(k + 5)))
            .collect();
        pairs[1].0 = G1::zero();
        pairs[MAX_LANES].1 = G2::zero();
        let expected: Vec<GT> = pairs.iter().map(|(p, q)| pairing(p, q)).collect();
        assert_eq!(expected[1], GT::ONE);
        assert_eq!(expected[MAX_LANES], GT::ONE);
        let unchanged = pairing(&multiple(2), &multiple(3));
        let mut outputs = vec![GT::ONE; pairs.len() + 1];
        outputs[pairs.len()] = unchanged;
        pairings(&pairs, &mut outputs);
        assert_eq!(outputs[..pairs.len()], expected);
        assert_eq!(outputs[pairs.len()], unchanged);
        // The longer input is truncated.
        let mut outputs = vec![GT::ONE; 3];
        pairings(&pairs, &mut outputs);
        assert_eq!(outputs, expected[..3]);
        let mut outputs = vec![unchanged; 3];
        pairings(&pairs[..2], &mut outputs);
        assert_eq!(outputs, [expected[0], expected[1], unchanged]);
        pairings(&[], &mut []);
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

    #[test]
    fn representations_agree() {
        /// Runs the kernel of [`pairings`] in every representation, checking that they agree.
        struct EachRepresentations<'a>(&'a [(G1, G2)]);

        impl<S: Simd> commonware_simd::Operation<S> for EachRepresentations<'_> {
            type Output = Vec<GT>;

            fn portable(self, simd: S) -> Vec<GT> {
                use crate::core::field::fp::{unsat28::Unsat28, unsat49::Unsat49};
                simd.execute(|simd: S| {
                    let mut expected = vec![GT::ONE; self.0.len()];
                    Each(self.0, &mut expected).run::<S, Unsat49<S>>(simd);
                    let mut outputs = vec![GT::ONE; self.0.len()];
                    Each(self.0, &mut outputs).run::<S, Unsat28<S>>(simd);
                    assert_eq!(outputs, expected);
                    expected
                })
            }

            // Residues require x86v4c.
            fn x86_v4c(self, simd: S) -> Vec<GT>
            where
                S: commonware_simd::X86V4C,
            {
                use crate::core::field::fp::rns::Rns;
                let pairs = self.0;
                let expected = self.portable(simd);
                simd.execute(|simd: S| {
                    let mut outputs = vec![GT::ONE; pairs.len()];
                    Each(pairs, &mut outputs).run::<S, Rns<S>>(simd);
                    assert_eq!(outputs, expected);
                });
                expected
            }
        }

        /// Runs the pairing kernel in every representation, checking that they agree.
        struct Representations<'a>(Pairings<'a>);

        impl<S: Simd> commonware_simd::Operation<S> for Representations<'_> {
            type Output = GT;

            fn portable(self, simd: S) -> GT {
                use crate::core::field::fp::{unsat28::Unsat28, unsat49::Unsat49};
                simd.execute(|simd: S| {
                    let expected = self.0.run::<S, Unsat49<S>>(simd);
                    assert_eq!(self.0.run::<S, Unsat28<S>>(simd), expected);
                    expected
                })
            }

            // Residues require x86v4c.
            fn x86_v4c(self, simd: S) -> GT
            where
                S: commonware_simd::X86V4C,
            {
                use crate::core::field::fp::rns::Rns;
                let kernel = self.0;
                let expected = self.portable(simd);
                simd.execute(|simd: S| assert_eq!(kernel.run::<S, Rns<S>>(simd), expected));
                expected
            }
        }

        let pairs = [
            (multiple::<G1>(3), multiple::<G2>(4)),
            (multiple::<G1>(5), G2::zero()),
            (multiple::<G1>(6), multiple::<G2>(7)),
        ];
        commonware_simd::check_consistent(|| Representations(Pairings(&pairs)));
        commonware_simd::check_consistent(|| EachRepresentations(&pairs));
    }
}
