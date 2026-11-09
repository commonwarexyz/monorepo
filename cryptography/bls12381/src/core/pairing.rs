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
/// `-2 y z^2 / z` leaves `[3b z^2 - y^2, 3 x^2 xp, -2 y z yp]`. The point is
/// [`Points::double`](crate::core::curve::Points::double)'s, whose stages the line's values join:
/// `x^2` reduces with the first stage and the last two coefficients with the coordinates.
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
/// The line is `[qx y - qy x, (qy z - y) xp, -(qx z - x) yp]` and the point is
/// [`Points::add`](crate::core::curve::Points::add)'s, whose second stage the line's first products
/// join.
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
            *t = Point {
                x: sx,
                y: sy,
                z: sz,
            };
            [l0, l2, l3]
        },
    )
}

/// Returns `f^((p^12 - 1) / r)` in each lane, up to the fixed power that the addition chain computes,
/// or zero for zero.
///
/// This is the second half of a pairing: the final exponentiation of [`miller_loop`] of one pair is
/// its pairing.
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

/// Fuzzing of the final exponentiation, and the bounds of the Miller loop's steps.
#[cfg(any(test, feature = "fuzz"))]
pub mod fuzz {
    use super::*;
    use crate::core::field::fp12::{
        BYTES, ONE,
        fuzz::{Kernel, Target, element},
        reference::{self, Element},
    };
    use arbitrary::{Arbitrary, Unstructured};
    use std::{vec, vec::Vec};

    /// A fuzzing operation on the pairing.
    #[derive(Clone, Copy, Debug, Arbitrary)]
    pub enum Plan {
        /// Check that the final exponentiation of any elements is multiplicative, maps zero to
        /// zero and the subfield `Fp6` (so every line scaling factor) to one, and maps nonzero
        /// elements into the cyclotomic subgroup, where the Frobenius map raises to the power
        /// `z`, as it does on the target group since `p = z mod r`.
        FinalExponentiation,
    }

    impl Plan {
        /// Runs the operation using the remaining input.
        pub fn run(self, u: &mut Unstructured<'_>) -> arbitrary::Result<()> {
            match self {
                Self::FinalExponentiation => final_exponentiations(u),
            }
        }
    }

    /// Returns the final exponentiations of elements, one per lane of as few values as hold them.
    struct Exponentiate<'a>(&'a [[u8; BYTES]]);

    impl Kernel for Exponentiate<'_> {
        type Output = Vec<[u8; BYTES]>;

        fn run<S: Simd, F: Field<S>>(&self, simd: S) -> Self::Output {
            let mut output = vec![[0; BYTES]; self.0.len()];
            for (elements, output) in self.0.chunks(F::LANES).zip(output.chunks_mut(F::LANES)) {
                let f = Fp12::<F>::load(simd, elements, &ONE);
                final_exponentiation(simd, f).store(simd, output);
            }
            output
        }
    }

    /// Returns whether an element lies in `Fp6`: its coefficients of odd degree in `w` are zero.
    fn in_subfield(a: &Element) -> bool {
        a.iter()
            .skip(1)
            .step_by(2)
            .all(|c| *c == reference::ZERO[0])
    }

    /// Runs [`Plan::FinalExponentiation`].
    fn final_exponentiations(u: &mut Unstructured<'_>) -> arbitrary::Result<()> {
        let target = Target::draw(u)?;
        // Elements and the products of neighbors fill the lanes of one value where it holds two
        // or more.
        let count = target.lanes().div_ceil(2);
        let count = count - u.int_in_range(0..=count - 1)?;
        let a = (0..count)
            .map(|_| element(u))
            .collect::<arbitrary::Result<Vec<_>>>()?;
        let mut elements: Vec<_> = a.iter().map(reference::encode).collect();
        for (k, x) in a.iter().enumerate() {
            elements.push(reference::encode(&reference::mul(x, &a[(k + 1) % count])));
        }
        let outputs = target.run(&Exponentiate(&elements));
        let (images, products) = outputs.split_at(count);
        for lane in 0..count {
            let label = std::format!("{target:?}, element {lane} of {count}");
            let x = reference::decode(&images[lane]);
            let y = reference::decode(&images[(lane + 1) % count]);
            assert!(
                products[lane] == reference::encode(&reference::mul(&x, &y)),
                "multiplicative, {label}"
            );
            if a[lane] == reference::ZERO {
                assert!(x == reference::ZERO, "zero, {label}");
                continue;
            }
            if in_subfield(&a[lane]) {
                assert!(x == reference::ONE, "subfield, {label}");
            }
            assert!(
                reference::mul(&reference::conjugate(&x), &x) == reference::ONE,
                "cyclotomic, {label}"
            );
            // z is negative, and conjugation inverts in the cyclotomic subgroup.
            assert!(
                reference::frobenius(&x) == reference::conjugate(&reference::power(&x, &[Z])),
                "frobenius is z, {label}"
            );
        }
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::core::{
            curve::g1,
            field::{
                fp::{rns::Rns, unsat28::Unsat28, unsat49::Unsat49},
                fp12::LINE_BOUND,
            },
        };
        use commonware_invariants::minifuzz;
        use commonware_simd::emulated::{EmulatedScalar, EmulatedX86V4C};

        #[test]
        fn minifuzz_final_exponentiation() {
            minifuzz::Builder::default()
                .with_min_iterations(MIN_ITERATIONS)
                .test(|u| Plan::FinalExponentiation.run(u));
        }

        /// Cases of [`minifuzz_final_exponentiation`] that run however long they take.
        const MIN_ITERATIONS: u64 = 10;

        /// Checks, in debug builds, that steps from points at the coordinate bounds return points
        /// within them and lines within the documented bounds.
        fn check_steps<S: Simd, F: Field<S>>(simd: S) {
            let zero = Fp2::<F>::load(simd, &[], &[0; FP2_BYTES]);
            let widen = |value: Fp2<F>| value.sub::<{ g2::BOUND - 2 }, S>(simd, zero).carry(simd);
            let p = [g1::GENERATOR[0], g1::GENERATOR[1]];
            let q = [g2::GENERATOR[0], g2::GENERATOR[1]];
            let pair = Pair::<F>::load(simd, &[], &(p, q));
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
}
