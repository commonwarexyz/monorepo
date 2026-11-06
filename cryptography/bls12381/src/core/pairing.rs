//! The optimal ate pairing on BLS12-381, on several pairs at once, one per lane.
//!
//! [`miller_loop`] maps pairs of a G1 point and a G2 point to elements of `Fp12`, and
//! [`final_exponentiation`] maps those to the target group, so their composition is the pairing.
//! Products of pairings share one final exponentiation, which is how signatures are verified: a
//! pairing check asks whether such a product is one. A lane's Miller loop over several pairs
//! shares its squarings among them, and [`Fp12::product_of_lanes`] multiplies the lanes.
//!
//! The Miller loop runs on the twist `y^2 = x^3 + 4 (1 + i)` of G2 in the projective coordinates of
//! [`Point`], with affine inputs, and evaluates each line as the sparse element
//! `l0 + l2 w^2 + l3 w^3` of `Fp12`. Lines are scaled by factors in `Fp2` that the final exponentiation
//! removes. The final exponentiation splits into the easy part `(p^6 - 1) (p^2 + 1)`, which lands in
//! the cyclotomic subgroup, and the hard part, an addition chain over the curve parameter
//! `z = -0xd201000000010000` (see "Faster Squaring in the Cyclotomic Subgroup of Sixth Degree
//! Extensions", Granger and Scott, 2010, and the chain of the zkcrypto `pairing` crate).
//!
//! # Inputs
//!
//! Points are affine and must lie in the prime-order subgroups, other than the identity, which has
//! no affine coordinates: callers handle pairs with an identity, which contribute one. A pair whose
//! G1 coordinates are both zero is not a pair of points, but its lines have no terms in `w`, so its
//! Miller loop is an element of `Fp2`, which the final exponentiation maps to one. Such a pair fills
//! a lane's unused slots, given a G2 point, such as the generator, whose lines have nonzero
//! constant terms.
//!
//! # Bounds
//!
//! The points of the Miller loop satisfy the [coordinate bounds of G2](crate::core::curve::g2), and its
//! lines the bounds of [`Fp12::mul_by_line`]: every line component has limb bound `1` and integer
//! bound at most `61`, below [`LINE_BOUND`](crate::core::field::fp12::LINE_BOUND). Every element of
//! `Fp12` satisfies the [element bounds](crate::core::field::fp12).

use crate::core::{
    curve::g2::{self, Addition, Point},
    field::{
        arithmetic::Field,
        fp::BYTES as FP_BYTES,
        fp2::{BYTES as FP2_BYTES, Fp2},
        fp12::Fp12,
    },
};
use commonware_simd::Simd;

/// Affine coordinates `[x, y]` of a G1 point as big-endian integers.
pub type G1Affine = [[u8; FP_BYTES]; 2];

/// Affine coordinates `[x, y]` of a G2 point as big-endian extension elements.
pub type G2Affine = [[u8; FP2_BYTES]; 2];

/// `|z|`, the absolute value of the curve parameter.
const Z: u64 = 0xd201_0000_0001_0000;

/// `|z| / 2`.
const HALF_Z: u64 = Z / 2;

/// Most pairs whose Miller loops share squarings, which bounds the points held at once.
pub const SHARED: usize = 8;

/// Largest number of pairs in a value, the widest representation's lane count.
const MAX_LANES: usize = 16;

/// Pairs of affine points, one per lane, prepared for the Miller loop.
#[derive(Clone, Copy)]
pub struct Pair<F> {
    /// The `x` coordinates of the G1 points.
    x: F,
    /// The negated `y` coordinates of the G1 points.
    negated_y: F,
    /// The G2 points, with `Z = 1`.
    q: Point<F>,
}

impl<F> Pair<F> {
    /// Loads up to one pair per lane, filling the remaining lanes with `fill`.
    ///
    /// See the [module documentation](self) for the points the pairs must hold.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn load<S: Simd>(
        simd: S,
        pairs: &[(G1Affine, G2Affine)],
        fill: &(G1Affine, G2Affine),
    ) -> Self
    where
        F: Field<S>,
    {
        const { assert!(F::LANES <= MAX_LANES) };
        let lanes = pairs.len().min(F::LANES);
        let mut p = [[[0; FP_BYTES]; MAX_LANES]; 2];
        let mut q = [[[0; FP2_BYTES]; MAX_LANES]; 2];
        for (lane, (g1, g2)) in pairs[..lanes].iter().enumerate() {
            for k in 0..2 {
                p[k][lane] = g1[k];
                q[k][lane] = g2[k];
            }
        }
        let (g1, g2) = fill;
        let mut one = [0; FP2_BYTES];
        one[FP2_BYTES - 1] = 1;
        let y = F::load(simd, &p[1][..lanes], &g1[1]);
        Self {
            x: F::load(simd, &p[0][..lanes], &g1[0]),
            // Loaded values are below 2p.
            negated_y: y.neg::<3>(simd).carry(simd),
            q: Point {
                x: Fp2::load(simd, &q[0][..lanes], &g2[0]),
                y: Fp2::load(simd, &q[1][..lanes], &g2[1]),
                z: Fp2::load(simd, &[], &one),
            },
        }
    }
}

/// Returns, in each lane, the product of the Miller loops of that lane's pairs, or one for no
/// pairs.
///
/// Every group of up to [`SHARED`] pairs shares its squarings. The result is only defined up to the
/// factors that [`final_exponentiation`] removes.
pub fn miller_loop<S: Simd, F: Field<S>>(simd: S, pairs: &[Pair<F>]) -> Fp12<F> {
    let mut chunks = pairs.chunks(SHARED);
    let Some(first) = chunks.next() else {
        return Fp12::one(simd);
    };
    let mut product = shared_miller_loop(simd, first);
    for chunk in chunks {
        product.mul(simd, &shared_miller_loop(simd, chunk));
    }
    product
}

/// Returns the product of the Miller loops of up to [`SHARED`] pairs, which share their squarings.
///
/// This is the Miller function of `|z|`, conjugated because `z` is negative.
fn shared_miller_loop<S: Simd, F: Field<S>>(simd: S, pairs: &[Pair<F>]) -> Fp12<F> {
    debug_assert!(!pairs.is_empty() && pairs.len() <= SHARED);
    let mut points = [pairs[0].q; SHARED];
    for (point, pair) in points.iter_mut().zip(pairs) {
        *point = pair.q;
    }
    let mut f = Fp12::one(simd);
    // The bits of |z| below the leading one. The first square of one is skipped.
    for bit in (0..63).rev() {
        if bit != 62 {
            f.square(simd);
        }
        for (point, pair) in points.iter_mut().zip(pairs) {
            let line = double_step(simd, point, pair);
            f.mul_by_line(simd, &line);
        }
        if (Z >> bit) & 1 == 1 {
            for (point, pair) in points.iter_mut().zip(pairs) {
                let line = add_step(simd, point, pair);
                f.mul_by_line(simd, &line);
            }
        }
    }
    f.conjugate(simd)
}

/// Doubles `t` in place and returns the line tangent at it, evaluated at the pair's G1 point.
///
/// With the curve equation, `3 x^3 - 2 y^2 z` becomes `z (y^2 - 3b z^2)`, and scaling the tangent by
/// `-2 y z^2 / z` leaves `[3b z^2 - y^2, 3 x^2 xp, -2 y z yp]`. The point is [`Point::double`]'s,
/// whose stages the line's values join: `x^2` reduces with the first stage and the last two
/// coefficients with the coordinates.
/// Runs as its own kernel, so callers share one copy, and replaces the point in place, so that
/// the loop copies nothing.
#[cfg_attr(not(debug_assertions), inline(always))]
fn double_step<S: Simd, F: Field<S>>(simd: S, t: &mut Point<F>, pair: &Pair<F>) -> [Fp2<F>; 3] {
    simd.execute(
        #[inline(always)]
        move |simd: S| {
            let [yy, xy, yz, b3zz, xx] = Fp2::<F>::reduce_each::<5, 10, S>(
                simd,
                #[cfg_attr(not(debug_assertions), inline(always))]
                |k| {
                    if k < 4 {
                        return t.doubling(simd, k);
                    }
                    let x = t.x.ready::<1, S>(simd);
                    let square = x.square_product::<{ g2::BOUND + 1 }, S>(simd);
                    Fp2::<F>::difference::<1, S>(simd, square)
                },
            );
            let doubling = [yy, xy, yz, b3zz];
            let xx3 = xx.mul_small::<3, S>(simd).carry(simd);
            // y^2 is below 18p in every representation.
            let l0 = b3zz.sub::<18, S>(simd, yy).carry(simd);
            let yz2 = yz.double(simd).carry(simd);
            let [x, y, z, l2, l3] = Fp2::<F>::reduce_each::<5, 10, S>(
                simd,
                #[cfg_attr(not(debug_assertions), inline(always))]
                |k| match k {
                    0..=2 => Point::doubled(simd, &doubling, k),
                    3 => Fp2::<F>::difference::<1, S>(simd, xx3.product_base(simd, pair.x)),
                    _ => {
                        let product = yz2.product_base(simd, pair.negated_y);
                        Fp2::<F>::difference::<1, S>(simd, product)
                    }
                },
            );
            *t = Point { x, y, z };
            [l0, l2, l3]
        },
    )
}

/// Adds the pair's G2 point to `t` in place and returns the line through them, evaluated at the
/// pair's G1 point.
///
/// The line is `[qx y - qy x, (qy z - y) xp, -(qx z - x) yp]` and the point is [`Point::add`]'s,
/// whose second stage the line's first products join.
/// Runs as its own kernel, so callers share one copy, and replaces the point in place.
#[cfg_attr(not(debug_assertions), inline(always))]
fn add_step<S: Simd, F: Field<S>>(simd: S, t: &mut Point<F>, pair: &Pair<F>) -> [Fp2<F>; 3] {
    simd.execute(
        #[inline(always)]
        move |simd: S| {
            let (x, y, z) = (
                t.x.ready::<1, S>(simd),
                t.y.ready::<1, S>(simd),
                t.z.ready::<1, S>(simd),
            );
            let (qx, qy) = (pair.q.x, pair.q.y);
            let first = Addition::new(simd, *t, pair.q);
            let first = Fp2::<F>::reduce_each::<6, 12, S>(
                simd,
                #[cfg_attr(not(debug_assertions), inline(always))]
                |k| first.sum(simd, k),
            );
            let [sx, sy, sz, l0, qyz, qxz] = Fp2::<F>::reduce_each::<6, 12, S>(
                simd,
                #[cfg_attr(not(debug_assertions), inline(always))]
                |k| match k {
                    0..=2 => Addition::coordinate(simd, &first, k),
                    3 => Fp2::<F>::difference::<7, S>(
                        simd,
                        Fp2::<F>::subtract_product(simd, qx.product(simd, y), qy, x),
                    ),
                    4 => Fp2::<F>::difference::<5, S>(simd, qy.product(simd, z)),
                    _ => Fp2::<F>::difference::<5, S>(simd, qx.product(simd, z)),
                },
            );
            let [l2, l3] = Fp2::<F>::reduce_each::<2, 4, S>(
                simd,
                #[cfg_attr(not(debug_assertions), inline(always))]
                |k| {
                    let (value, point, scale) = if k == 0 {
                        (qyz, y, pair.x)
                    } else {
                        (qxz, x, pair.negated_y)
                    };
                    let factor = value.sub::<{ g2::BOUND + 1 }, S>(simd, point).carry(simd);
                    Fp2::<F>::difference::<1, S>(simd, factor.product_base(simd, scale))
                },
            );
            *t = Point { x: sx, y: sy, z: sz };
            [l0, l2, l3]
        },
    )
}

/// Returns `f^((p^12 - 1) / r)` in each lane, up to the fixed power that the addition chain computes,
/// or zero for zero.
///
/// This is the second half of a pairing: the final exponentiation of [`miller_loop`] of one pair is
/// its pairing. The result is the same as blst's.
pub fn final_exponentiation<S: Simd, F: Field<S>>(simd: S, f: Fp12<F>) -> Fp12<F> {
    let coefficients = Fp12::<F>::frobenius_coefficients(simd);
    // The easy part: f^((p^6 - 1) (p^2 + 1)) lies in the cyclotomic subgroup.
    let mut inverse = f.conjugate(simd);
    inverse.mul(simd, &f.invert(simd));
    let mut easy = inverse
        .frobenius(simd, &coefficients)
        .frobenius(simd, &coefficients);
    easy.mul(simd, &inverse);

    let mut y0 = easy;
    y0.cyclotomic_square(simd);
    let mut y1 = raise_to_z(simd, y0);
    let y2 = raise_to_half_z(simd, y1);
    y1.mul(simd, &easy.conjugate(simd));
    let mut y1 = y1.conjugate(simd);
    y1.mul(simd, &y2);
    let y2 = raise_to_z(simd, y1);
    let mut y3 = raise_to_z(simd, y2);
    y3.mul(simd, &y1.conjugate(simd));
    let mut y1 = y1
        .frobenius(simd, &coefficients)
        .frobenius(simd, &coefficients)
        .frobenius(simd, &coefficients);
    let y2 = y2
        .frobenius(simd, &coefficients)
        .frobenius(simd, &coefficients);
    y1.mul(simd, &y2);
    let mut y2 = raise_to_z(simd, y3);
    y2.mul(simd, &y0);
    y2.mul(simd, &easy);
    y1.mul(simd, &y2);
    y1.mul(simd, &y3.frobenius(simd, &coefficients));
    y1
}

/// Returns `a^(z / 2)` for `a` in the cyclotomic subgroup.
fn raise_to_half_z<S: Simd, F: Field<S>>(simd: S, a: Fp12<F>) -> Fp12<F> {
    // Square and multiply over the bits of |z| / 2 below its leading one, then conjugate for the
    // sign of z.
    let mut result = a;
    for bit in (0..62).rev() {
        result.cyclotomic_square(simd);
        if (HALF_Z >> bit) & 1 == 1 {
            result.mul(simd, &a);
        }
    }
    result.conjugate(simd)
}

/// Returns `a^z` for `a` in the cyclotomic subgroup.
fn raise_to_z<S: Simd, F: Field<S>>(simd: S, a: Fp12<F>) -> Fp12<F> {
    let mut result = raise_to_half_z(simd, a);
    result.cyclotomic_square(simd);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::field::{
        fp::{rns::Rns, unsat28::Unsat28, unsat49::Unsat49},
        fp12::{
            BYTES, LINE_BOUND, ONE,
            tests::{element, from_blst, to_blst},
        },
    };
    use arbitrary::Unstructured;
    use commonware_simd::{
        Operation, X86V4C,
        emulated::{EmulatedNeon, EmulatedScalar, EmulatedX86V4C},
        test_dispatch,
    };
    use std::{vec, vec::Vec};

    /// Pairs in each lane of the multi-pairing checks, more than share their squarings.
    const PAIRS: usize = SHARED + 1;

    /// Returns `[k] G1` for a nonzero scalar of 32 seeded bytes, in affine coordinates and in blst's.
    fn g1(seed: u8) -> (G1Affine, blst::blst_p1_affine) {
        let scalar = [seed.wrapping_mul(29).wrapping_add(3) | 1; 32];
        let mut point = blst::blst_p1::default();
        let mut affine = blst::blst_p1_affine::default();
        let mut coordinates = [[0; FP_BYTES]; 2];
        // SAFETY: every pointer references a valid value of the expected type, the scalar holds
        // 256 bits, and each output buffer holds a base field element.
        unsafe {
            blst::blst_p1_mult(&mut point, blst::blst_p1_generator(), scalar.as_ptr(), 256);
            blst::blst_p1_to_affine(&mut affine, &point);
            blst::blst_bendian_from_fp(coordinates[0].as_mut_ptr(), &affine.x);
            blst::blst_bendian_from_fp(coordinates[1].as_mut_ptr(), &affine.y);
        }
        (coordinates, affine)
    }

    /// Returns `[k] G2` for a nonzero scalar of 32 seeded bytes, or the generator for no seed, in
    /// affine coordinates and in blst's.
    fn g2(seed: Option<u8>) -> (G2Affine, blst::blst_p2_affine) {
        let mut point = blst::blst_p2::default();
        let mut affine = blst::blst_p2_affine::default();
        let mut coordinates = [[0; FP2_BYTES]; 2];
        // SAFETY: every pointer references a valid value of the expected type, the scalar holds
        // 256 bits, and each output buffer holds a base field element.
        unsafe {
            match seed {
                Some(seed) => {
                    let scalar = [seed.wrapping_mul(53).wrapping_add(7) | 1; 32];
                    blst::blst_p2_mult(&mut point, blst::blst_p2_generator(), scalar.as_ptr(), 256);
                }
                None => point = *blst::blst_p2_generator(),
            }
            blst::blst_p2_to_affine(&mut affine, &point);
            // Extension elements encode the imaginary component first.
            for (coordinate, value) in coordinates.iter_mut().zip([&affine.x, &affine.y]) {
                blst::blst_bendian_from_fp(coordinate.as_mut_ptr(), &value.fp[1]);
                blst::blst_bendian_from_fp(coordinate[FP_BYTES..].as_mut_ptr(), &value.fp[0]);
            }
        }
        (coordinates, affine)
    }

    /// Returns blst's pairing of affine points.
    fn blst_pairing(p: &blst::blst_p1_affine, q: &blst::blst_p2_affine) -> blst::blst_fp12 {
        let mut miller = blst::blst_fp12::default();
        let mut out = blst::blst_fp12::default();
        // SAFETY: all pointers reference valid, initialized structures.
        unsafe {
            blst::blst_miller_loop(&mut miller, q, p);
            blst::blst_final_exp(&mut out, &miller);
        }
        out
    }

    fn blst_mul(a: &blst::blst_fp12, b: &blst::blst_fp12) -> blst::blst_fp12 {
        let mut out = blst::blst_fp12::default();
        // SAFETY: the pointers reference valid field elements.
        unsafe { blst::blst_fp12_mul(&mut out, a, b) };
        out
    }

    /// The pairs of one lane, with blst's product of their pairings.
    #[derive(Clone)]
    struct Lane {
        pairs: Vec<(G1Affine, G2Affine)>,
        expected: [u8; BYTES],
    }

    /// Returns a lane of `count` pairs, the last of which is the neutral pair when `neutral` is set.
    fn lane(seed: u8, count: usize, neutral: bool) -> Lane {
        let mut pairs = Vec::new();
        let mut expected = None;
        for k in 0..count {
            let seed = seed.wrapping_mul(17).wrapping_add(k as u8);
            if neutral && k + 1 == count {
                pairs.push(([[0; FP_BYTES]; 2], g2(None).0));
                continue;
            }
            let ((p, p_blst), (q, q_blst)) = (g1(seed), g2(Some(seed)));
            pairs.push((p, q));
            let pairing = blst_pairing(&p_blst, &q_blst);
            expected = Some(expected.map_or(pairing, |product| blst_mul(&product, &pairing)));
        }
        Lane {
            pairs,
            expected: from_blst(&expected.expect("a pair")),
        }
    }

    /// Returns the pairing products of lanes, one pair slot per call of [`Pair::load`].
    fn pairings<S: Simd, F: Field<S>>(simd: S, lanes: &[Lane]) -> Vec<[u8; BYTES]> {
        let mut output = vec![[0; BYTES]; lanes.len()];
        let fill = (g1(0).0, g2(None).0);
        for start in (0..lanes.len()).step_by(F::LANES) {
            let chunk = &lanes[start..lanes.len().min(start + F::LANES)];
            let mut pairs = Vec::new();
            for k in 0..chunk[0].pairs.len() {
                let slot: Vec<_> = chunk.iter().map(|lane| lane.pairs[k]).collect();
                pairs.push(Pair::<F>::load(simd, &slot, &fill));
            }
            let f = final_exponentiation(simd, miller_loop(simd, &pairs));
            f.store(simd, &mut output[start..]);
        }
        output
    }

    /// Runs [`pairings`] in every representation, on fewer lanes for residues, which hold one.
    struct Pairings<'a>(&'a [Lane], usize);

    impl<S: Simd> Operation<S> for Pairings<'_> {
        type Output = [Vec<[u8; BYTES]>; 2];

        fn portable(self, simd: S) -> Self::Output {
            simd.execute(|simd: S| {
                [
                    pairings::<S, Unsat49<S>>(simd, self.0),
                    pairings::<S, Unsat28<S>>(simd, self.0),
                ]
            })
        }

        // Residues require x86v4c and must match the other representations.
        fn x86_v4c(self, simd: S) -> Self::Output
        where
            S: X86V4C,
        {
            let lanes = &self.0[..self.1];
            let outputs = self.portable(simd);
            let residues = simd.execute(|simd: S| pairings::<S, Rns<S>>(simd, lanes));
            assert!(residues == outputs[0][..lanes.len()], "residues differ");
            outputs
        }
    }

    fn check(lanes: &[Lane], outputs: [Vec<[u8; BYTES]>; 2]) {
        for (representation, output) in outputs.iter().enumerate() {
            for (k, (output, lane)) in output.iter().zip(lanes).enumerate() {
                assert!(
                    *output == lane.expected,
                    "representation {representation}, lane {k}"
                );
            }
        }
    }

    #[test]
    fn pairings_match_blst() {
        let lanes: Vec<_> = (0..MAX_LANES as u8)
            .map(|seed| lane(seed, 1, false))
            .collect();
        check(&lanes, test_dispatch(Pairings(&lanes, 2)));
        // Run every representation and vector width even on hosts without native SIMD.
        check(&lanes, Pairings(&lanes, 1).portable(EmulatedNeon));
        check(&lanes, EmulatedX86V4C.execute(Pairings(&lanes, 2)));
    }

    #[test]
    fn multi_pairings_match_blst() {
        // More pairs than share squarings, the last of them neutral.
        let lanes: Vec<_> = (0..MAX_LANES as u8)
            .map(|seed| lane(seed, PAIRS, true))
            .collect();
        check(&lanes, test_dispatch(Pairings(&lanes, 1)));
        check(&lanes, EmulatedX86V4C.execute(Pairings(&lanes, 1)));
    }

    /// Checks that `e(a P, Q) e(-P, a Q)` is one across the lanes, and that a perturbed product is not.
    fn check_lanes<S: Simd, F: Field<S>>(simd: S) {
        let (p, q) = (g1(5), g2(Some(6)));
        let mut pairs = Vec::new();
        for lane in 0..F::LANES {
            // Lanes alternate between e(2 P, Q) and e(-P, 2 Q), a neutral pair filling an odd count.
            let mut point = blst::blst_p1::default();
            let mut affine = blst::blst_p1_affine::default();
            let mut q2 = blst::blst_p2::default();
            let mut q2_affine = blst::blst_p2_affine::default();
            // SAFETY: every pointer references a valid value of the expected type.
            let pair = unsafe {
                blst::blst_p1_from_affine(&mut point, &p.1);
                blst::blst_p2_from_affine(&mut q2, &q.1);
                if lane % 2 == 0 {
                    blst::blst_p1_double(&mut point, &point);
                    blst::blst_p1_to_affine(&mut affine, &point);
                    q2_affine = q.1;
                } else {
                    blst::blst_p1_cneg(&mut point, true);
                    blst::blst_p1_to_affine(&mut affine, &point);
                    blst::blst_p2_double(&mut q2, &q2);
                    blst::blst_p2_to_affine(&mut q2_affine, &q2);
                }
                (affine, q2_affine)
            };
            let mut coordinates = ([[0; FP_BYTES]; 2], [[0; FP2_BYTES]; 2]);
            // SAFETY: each output buffer holds a base field element.
            unsafe {
                blst::blst_bendian_from_fp(coordinates.0[0].as_mut_ptr(), &pair.0.x);
                blst::blst_bendian_from_fp(coordinates.0[1].as_mut_ptr(), &pair.0.y);
                for (coordinate, value) in coordinates.1.iter_mut().zip([&pair.1.x, &pair.1.y]) {
                    blst::blst_bendian_from_fp(coordinate.as_mut_ptr(), &value.fp[1]);
                    blst::blst_bendian_from_fp(coordinate[FP_BYTES..].as_mut_ptr(), &value.fp[0]);
                }
            }
            let last = lane + 1 == F::LANES && F::LANES % 2 == 1;
            pairs.push(if last {
                ([[0; FP_BYTES]; 2], g2(None).0)
            } else {
                coordinates
            });
        }
        let pair = Pair::<F>::load(simd, &pairs, &pairs[0]);
        let product = miller_loop(simd, &[pair]).product_of_lanes(simd);
        let mut output = [[0; BYTES]; MAX_LANES];
        final_exponentiation(simd, product).store(simd, &mut output);
        for lane in &output[..F::LANES] {
            assert!(*lane == ONE);
        }
        // Without the last lane's pair, an even count leaves one e(-P, 2 Q).
        if F::LANES > 1 && F::LANES % 2 == 0 {
            let pair = Pair::<F>::load(
                simd,
                &pairs[..F::LANES - 1],
                &([[0; FP_BYTES]; 2], g2(None).0),
            );
            let product = miller_loop(simd, &[pair]).product_of_lanes(simd);
            final_exponentiation(simd, product).store(simd, &mut output);
            assert!(output[0] != ONE);
        }
    }

    #[test]
    fn pairing_checks_multiply_lanes() {
        EmulatedX86V4C.execute(|simd: EmulatedX86V4C| {
            check_lanes::<_, Unsat49<_>>(simd);
            check_lanes::<_, Unsat28<_>>(simd);
            check_lanes::<_, Rns<_>>(simd);
        });
        EmulatedNeon.execute(|simd: EmulatedNeon| check_lanes::<_, Unsat28<_>>(simd));
    }

    /// Returns the final exponentiation of elements, one per lane.
    fn exponentiate<S: Simd, F: Field<S>>(simd: S, elements: &[[u8; BYTES]]) -> Vec<[u8; BYTES]> {
        let mut output = vec![[0; BYTES]; elements.len()];
        for start in (0..elements.len()).step_by(F::LANES) {
            let f = Fp12::<F>::load(simd, &elements[start..], &ONE);
            final_exponentiation(simd, f).store(simd, &mut output[start..]);
        }
        output
    }

    #[test]
    fn final_exponentiations_match_blst() {
        let mut elements = vec![[0; BYTES]; 4];
        for (k, value) in elements.iter_mut().enumerate().skip(1) {
            let seed = [(k as u8).wrapping_mul(71).wrapping_add(5); 1024];
            *value = element(&mut Unstructured::new(&seed)).unwrap();
        }
        let expected: Vec<_> = elements
            .iter()
            .map(|element| {
                let mut out = blst::blst_fp12::default();
                // SAFETY: the pointers reference valid field elements.
                unsafe { blst::blst_final_exp(&mut out, &to_blst(element)) };
                from_blst(&out)
            })
            .collect();
        // Zero maps to zero.
        assert_eq!(expected[0], [0; BYTES]);
        EmulatedScalar.execute(|simd: EmulatedScalar| {
            assert!(exponentiate::<_, Unsat49<_>>(simd, &elements) == expected);
            assert!(exponentiate::<_, Unsat28<_>>(simd, &elements) == expected);
        });
        EmulatedX86V4C.execute(|simd: EmulatedX86V4C| {
            assert!(exponentiate::<_, Rns<_>>(simd, &elements) == expected);
        });
    }

    /// Checks, in debug builds, that steps from points at the coordinate bounds return points within
    /// them and lines within the documented bounds.
    fn check_steps<S: Simd, F: Field<S>>(simd: S) {
        let zero = Fp2::<F>::load(simd, &[], &[0; FP2_BYTES]);
        let widen = |value: Fp2<F>| value.sub::<{ g2::BOUND - 2 }, S>(simd, zero).carry(simd);
        let pair = Pair::<F>::load(simd, &[], &(g1(1).0, g2(Some(2)).0));
        let t = Point {
            x: widen(pair.q.x),
            y: widen(pair.q.y),
            z: widen(pair.q.z),
        };
        let (mut doubled, mut sum) = (t, t);
        let steps = [
            (double_step(simd, &mut doubled, &pair), doubled),
            (add_step(simd, &mut sum, &pair), sum),
        ];
        for (line, point) in steps {
            for coordinate in [point.x, point.y, point.z] {
                coordinate.neg::<{ g2::BOUND + 1 }, S>(simd);
            }
            line[0].neg::<62, S>(simd);
            line[1].neg::<{ LINE_BOUND + 1 }, S>(simd);
            line[2].neg::<{ LINE_BOUND + 1 }, S>(simd);
        }
    }

    #[test]
    fn steps_satisfy_their_bounds() {
        EmulatedScalar.execute(|simd: EmulatedScalar| {
            check_steps::<_, Unsat49<_>>(simd);
            check_steps::<_, Unsat28<_>>(simd);
        });
        EmulatedX86V4C.execute(|simd: EmulatedX86V4C| check_steps::<_, Rns<_>>(simd));
    }
}
