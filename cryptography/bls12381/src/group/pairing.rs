//! The pairing of G1 and G2 into the target group.

use super::{
    G1, G2,
    kernel::{Group, Kernel},
};
use crate::core::{
    curve::{Points, g1, g2},
    field::{
        MAX_LANES,
        arithmetic::{Field, TIGHT},
        fp::{self, BYTES as FP_BYTES},
        fp2::{self, BYTES as FP2_BYTES, Fp2},
        fp12::{self, BYTES, Fp12},
    },
    pairing::{G1Affine, G2Affine, Pair, SHARED, final_exponentiation, miller_loop},
};
use alloc::{vec, vec::Vec};
use commonware_formatting::Hex;
use commonware_math::algebra::{Multiplicative, Object};
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
    Pairings(pairs, outputs).dispatch();
}

/// Returns the product of the pairings of `pairs`, with one shared final exponentiation, or
/// [`GT::ONE`] for no pairs.
///
/// A product of pairings is cheaper than the pairings it multiplies, so checks such as
/// `e(a, b) = e(c, d)` should compare `multi_pairing(&[(a, b), (-c, d)])` with [`GT::ONE`].
pub fn multi_pairing(pairs: &[(G1, G2)]) -> GT {
    MultiPairing(pairs).dispatch()
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
struct MultiPairing<'a>(&'a [(G1, G2)]);

impl MultiPairing<'_> {
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
        let points: Vec<_> = self
            .0
            .iter()
            .filter(|(p, q)| !p.is_identity() && !q.is_identity())
            .map(|(p, q)| (*p.coordinates(), *q.coordinates()))
            .collect();
        let affine = to_affine::<S, F>(simd, &points);
        let mut prepared = [Pair::<F>::load(simd, &[], &FILL); SHARED];
        let mut product: Option<Fp12<F>> = None;
        for batch in affine.chunks(SHARED * F::LANES) {
            let groups = batch.chunks(F::LANES);
            let count = groups.len();
            for (prepared, group) in prepared.iter_mut().zip(groups) {
                *prepared = Pair::load(simd, group, &FILL);
            }
            let lines = miller_loop(simd, &prepared[..count]);
            match &mut product {
                Some(product) => product.mul(simd, &lines),
                None => product = Some(lines),
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

/// A pair that pairs to one and fills unused lanes: its G1 coordinates are zero, which the final
/// exponentiation maps to one, and its G2 point is the generator, whose lines have nonzero
/// constant terms.
const FILL: (G1Affine, G2Affine) = ([[0; FP_BYTES]; 2], [g2::GENERATOR[0], g2::GENERATOR[1]]);

/// The G1 point `(0 : 1 : 1)`, whose denominator is one.
const P_FILL: g1::Coordinates = {
    let mut fill = g1::IDENTITY;
    fill[2] = fp::ONE;
    fill
};

/// The G2 point `(0 : 1 : 1)`, whose denominator is one.
const Q_FILL: g2::Coordinates = {
    let mut fill = g2::IDENTITY;
    fill[2] = fp2::ONE;
    fill
};

impl Kernel for MultiPairing<'_> {
    type Output = GT;

    #[inline(always)]
    fn run<S: Simd, F: Field<S>>(self, simd: S) -> GT {
        self.miller_loops::<S, F>(simd).map_or(GT::ONE, |product| {
            Self::exponentiate::<S, F>(simd, &product)
        })
    }
}

/// Computes the pairing of each pair, one pair per lane.
struct Pairings<'a>(&'a [(G1, G2)], &'a mut [GT]);

impl Kernel for Pairings<'_> {
    type Output = ();

    // Debug builds keep this a call so that each representation's frame stays separate.
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn run<S: Simd, F: Field<S>>(self, simd: S) {
        const { assert!(F::LANES <= MAX_LANES) };
        // Pairs with an identity hold points with denominator one, which the conversion to
        // affine coordinates accepts; their outputs are replaced by one.
        let filler = (P_FILL, g2::GENERATOR);
        let count = self.0.len().min(self.1.len());
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
            let prepared = Pair::<F>::load(simd, affine, &FILL);
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
    simd.execute(
        #[inline(always)]
        move |simd: S| {
            let groups = points.len().div_ceil(F::LANES);
            let mut loaded = Vec::with_capacity(groups);
            // The G1 denominator and the norm of the G2 denominator of each group, tight with
            // limb bound one, as inversion requires.
            let mut denominators = Vec::with_capacity(2 * groups);
            for group in points.chunks(F::LANES) {
                // Unused lanes hold points with denominator one, which leave the products
                // unchanged.
                let mut g1 = [P_FILL; MAX_LANES];
                let mut g2 = [Q_FILL; MAX_LANES];
                for (lane, (p, q)) in group.iter().enumerate() {
                    g1[lane] = *p;
                    g2[lane] = *q;
                }
                let p = g1::Point::<F>::load(simd, &g1[..group.len()], &P_FILL);
                let q = g2::Point::<F>::load(simd, &g2[..group.len()], &Q_FILL);
                let norm =
                    F::accumulate_product(simd, q.z.c0.product(simd, q.z.c0), q.z.c1, q.z.c1);
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
                let q_inverse =
                    Fp2::reduce_tight::<1, S>(simd, conjugate.product_base(simd, norm_inverse));
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

/// Fuzzing operations for the pairing.
#[cfg(any(test, feature = "fuzz"))]
pub mod fuzz {
    use super::*;
    use crate::group::{
        Scalar,
        fuzz::{check_representations, dot, elements},
    };
    use arbitrary::{Arbitrary, Unstructured};
    use commonware_math::algebra::{CryptoGroup, test_suites};
    use std::sync::LazyLock;

    /// The pairing of the generators, which generates the target group.
    static GENERATOR: LazyLock<GT> = LazyLock::new(|| pairing(&G1::generator(), &G2::generator()));

    impl<'a> Arbitrary<'a> for GT {
        fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
            // A small power of the generator, which costs a few multiplications.
            let exponent: u8 = u.arbitrary()?;
            let mut power = Self::ONE;
            for bit in (0..u8::BITS).rev() {
                power = power * &power;
                if (exponent >> bit) & 1 == 1 {
                    power *= &GENERATOR;
                }
            }
            Ok(power)
        }
    }

    /// Draws pairs of elements with the discrete logarithm of the product of their pairings to
    /// the pairing of the generators: by bilinearity, the sum of the products of the discrete
    /// logarithms of each pair.
    fn pairs(u: &mut Unstructured<'_>, count: usize) -> arbitrary::Result<(Vec<(G1, G2)>, Scalar)> {
        let (p, a) = elements::<G1>(u, count)?;
        let (q, b) = elements::<G2>(u, count)?;
        Ok((p.into_iter().zip(q).collect(), dot(&a, &b)))
    }

    /// Returns the power of the pairing of the generators by a scalar, multiplying either
    /// generator by it.
    fn power(u: &mut Unstructured<'_>, logarithm: &Scalar) -> arbitrary::Result<GT> {
        Ok(if u.arbitrary()? {
            pairing(&G1::generator(), &(G2::generator() * logarithm))
        } else {
            pairing(&(G1::generator() * logarithm), &G2::generator())
        })
    }

    /// Computes the pairing of each pair, returning the pairings.
    #[derive(Clone, Copy)]
    struct Separate<'a>(&'a [(G1, G2)]);

    impl Kernel for Separate<'_> {
        type Output = Vec<GT>;

        fn run<S: Simd, F: Field<S>>(self, simd: S) -> Vec<GT> {
            let mut outputs = vec![GT::ONE; self.0.len()];
            Pairings(self.0, &mut outputs).run::<S, F>(simd);
            outputs
        }
    }

    /// A kernel whose representations [`Plan::Representations`] compares.
    #[derive(Clone, Copy, Debug, Arbitrary)]
    enum PairingKernel {
        MultiPairing,
        Separate,
        Product,
    }

    /// A pairing fuzzing operation.
    #[derive(Clone, Copy, Debug, Arbitrary)]
    pub enum Plan {
        /// Checks the laws of multiplication in the target group.
        Multiplicative,
        /// Checks that a product of pairings, whole or in two parts, is the power of the pairing
        /// of the generators that bilinearity gives.
        Product,
        /// Checks the pairings of a slice against one pairing at a time.
        Each,
        /// Checks that every representation and backend computes what each kernel's dispatch
        /// does.
        Representations,
    }

    impl Plan {
        /// Runs the operation using the remaining input.
        pub fn run(self, u: &mut Unstructured<'_>) -> arbitrary::Result<()> {
            match self {
                Self::Multiplicative => {
                    test_suites::fuzz_multiplicative::<GT>(u)?;
                    let a = GT::arbitrary(u)?;
                    assert_eq!(a * &GT::ONE, a);
                }
                Self::Product => {
                    // More pairs than share their squarings on one lane.
                    let count = SHARED + 1 - u.int_in_range(0..=SHARED + 1)?;
                    let (pairs, logarithm) = pairs(u, count)?;
                    let expected = power(u, &logarithm)?;
                    assert_eq!(multi_pairing(&pairs), expected);
                    let (first, second) = pairs.split_at(u.int_in_range(0..=count)?);
                    assert_eq!(multi_pairing(first) * &multi_pairing(second), expected);
                }
                Self::Each => {
                    // Outputs beyond the pairs are unchanged, and pairs beyond the outputs are
                    // ignored. A few pairs suffice, since each costs a pairing:
                    // Representations covers the lane counts of every representation.
                    const LONGEST: usize = 6;
                    let count = LONGEST - u.int_in_range(0..=LONGEST)?;
                    let (pairs, _) = pairs(u, count)?;
                    let unchanged = GT::arbitrary(u)?;
                    let mut outputs = vec![unchanged; LONGEST - u.int_in_range(0..=LONGEST)?];
                    pairings(&pairs, &mut outputs);
                    for (i, output) in outputs.iter().enumerate() {
                        let expected = pairs.get(i).map_or(unchanged, |(p, q)| pairing(p, q));
                        assert_eq!(*output, expected, "output {i}");
                    }
                }
                Self::Representations => {
                    let kernel = PairingKernel::arbitrary(u)?;
                    // More pairs than share their squarings on one lane, or than the lanes of
                    // the widest representation.
                    let longest = match kernel {
                        PairingKernel::Separate => MAX_LANES,
                        PairingKernel::MultiPairing | PairingKernel::Product => SHARED,
                    } + 1;
                    let count = longest - u.int_in_range(0..=longest)?;
                    let (pairs, _) = pairs(u, count)?;
                    match kernel {
                        PairingKernel::MultiPairing => {
                            check_representations(u, MultiPairing(&pairs))?
                        }
                        PairingKernel::Separate => check_representations(u, Separate(&pairs))?,
                        PairingKernel::Product => {
                            let product = Product(GT::arbitrary(u)?, GT::arbitrary(u)?);
                            check_representations(u, product)?;
                        }
                    }
                }
            }
            Ok(())
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::group::vectors::PAIRING;
        use commonware_invariants::minifuzz;
        use commonware_math::algebra::Additive;

        #[test]
        fn minifuzz_multiplicative() {
            minifuzz::Builder::default()
                .with_min_iterations(32)
                .test(|u| Plan::Multiplicative.run(u));
        }

        // The remaining cases compute several pairings, so debug builds run few of them.

        #[test]
        fn minifuzz_product() {
            minifuzz::Builder::default()
                .with_min_iterations(2)
                .test(|u| Plan::Product.run(u));
        }

        #[test]
        fn minifuzz_each() {
            minifuzz::Builder::default()
                .with_min_iterations(2)
                .test(|u| Plan::Each.run(u));
        }

        #[test]
        fn minifuzz_representations() {
            minifuzz::Builder::default()
                .with_min_iterations(2)
                .test(|u| Plan::Representations.run(u));
        }

        #[test]
        fn generators_pair_to_known_answer() {
            assert_eq!(GENERATOR.to_bytes(), PAIRING);
        }

        #[test]
        fn identities_pair_to_one() {
            assert_eq!(multi_pairing(&[]), GT::ONE);
            assert_eq!(pairing(&G1::zero(), &G2::generator()), GT::ONE);
            assert_eq!(pairing(&G1::generator(), &G2::zero()), GT::ONE);
        }
    }
}
