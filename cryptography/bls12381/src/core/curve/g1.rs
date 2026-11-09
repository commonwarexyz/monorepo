//! Arithmetic on points of G1, the curve `y^2 = x^3 + 4` over the base field.
//!
//! A [`Point`] holds as many projective points as its field values hold elements, one per lane,
//! and its formulas run once over every base field representation.
//!
//! # Coordinate bounds
//!
//! Every coordinate a formula accepts or returns has positional limb bound `1` and integer bound at
//! most [`BOUND`], as defined by the [base field arithmetic](crate::core::field::arithmetic): the
//! positional representations return at most `73` from the subtraction in [`Point::add`]'s `X`
//! coordinate, and residues reduce to at most `17`. Loaded coordinates and every formula's outputs
//! satisfy this, so points chain through any number of operations without carrying or
//! canonicalizing between them.
//!
//! Raw coordinates hold each lane of a point in the representation's own form, through
//! [`Field::store_raw`] with bound [`BOUND`], so storing and loading them costs no conversion and
//! loaded raw coordinates satisfy the coordinate bounds.
//!
//! Subtractions remove small multiples of reduced products of coordinates. Such a product is
//! bounded by `4p` in the positional representations and by `17p` in residues, so a multiple
//! `C` of it is covered by a bias of `17C` in every representation. Inside a
//! formula, the positional representations reach integer bounds of at most `912` and limb bounds
//! of at most `12`; residues reach integer bounds of at most `629`.

use crate::core::field::{
    arithmetic::Field,
    fp::{BYTES, MINUS_ONE, ONE, encode},
};
use commonware_simd::Simd;

/// Projective coordinates `[X, Y, Z]` as big-endian integers.
pub type Coordinates = [[u8; BYTES]; 3];

/// Largest integer bound of a coordinate, in units of `p`.
pub const BOUND: u64 = 73;

/// The identity `(0 : 1 : 0)` as projective coordinates.
pub const IDENTITY: Coordinates = {
    let mut identity = [[0; BYTES]; 3];
    identity[1][BYTES - 1] = 1;
    identity
};

/// Largest integer bound of a reduced value in residues, in units of `p`.
///
/// Positional products of coordinates are bounded by `4p`, so multiples of this cover a
/// subtrahend in every representation.
const REDUCED: u64 = 17;

/// Positional bias of every subtraction of products, in units of `p`.
///
/// Covers each negative sum of products, which stays below `64p` in the positional
/// representations.
const PRODUCT_BIAS: u64 = 64;

/// Largest number of points in a value, the widest representation's lane count.
const MAX_LANES: usize = 16;

/// A cube root of unity `beta` such that `(x, y) -> (beta x, y)` multiplies every point of the
/// prime-order subgroup by `-x^2`, for the curve parameter `x`: a cube root of unity modulo the
/// subgroup order `r = x^4 - x^2 + 1`.
const BETA: [u8; BYTES] = encode([
    0x2e01_ffff_fffe_fffe,
    0xde17_d813_620a_0002,
    0xddb3_a93b_e6f8_9688,
    0xba69_c607_6a0f_77ea,
    0x5f19_672f_df76_ce51,
    0,
]);

/// Projective points, one per lane of the field values.
///
/// See the [module documentation](self) for the bounds every coordinate satisfies.
#[derive(Clone, Copy)]
pub struct Point<F> {
    /// The `X` coordinates.
    pub x: F,
    /// The `Y` coordinates.
    pub y: F,
    /// The `Z` coordinates.
    pub z: F,
}

impl<F> Point<F> {
    /// Loads up to one projective point per lane, filling the remaining lanes with `fill`.
    #[inline(always)]
    pub fn load<S: Simd>(simd: S, points: &[Coordinates], fill: &Coordinates) -> Self
    where
        F: Field<S>,
    {
        const { assert!(F::LANES <= MAX_LANES) };
        let mut coordinates = [[[0; BYTES]; MAX_LANES]; 3];
        let lanes = points.len().min(F::LANES);
        for (i, coordinate) in coordinates.iter_mut().enumerate() {
            for (lane, point) in coordinate.iter_mut().zip(&points[..lanes]) {
                *lane = point[i];
            }
        }
        Self {
            x: F::load(simd, &coordinates[0][..lanes], &fill[0]),
            y: F::load(simd, &coordinates[1][..lanes], &fill[1]),
            z: F::load(simd, &coordinates[2][..lanes], &fill[2]),
        }
    }

    /// Stores each lane's canonical projective coordinates, dropping lanes beyond `points`.
    #[inline(always)]
    pub fn store<S: Simd>(self, simd: S, points: &mut [Coordinates])
    where
        F: Field<S>,
    {
        const { assert!(F::LANES <= MAX_LANES) };
        let mut coordinates = [[[0; BYTES]; MAX_LANES]; 3];
        let lanes = points.len().min(F::LANES);
        self.x.store(simd, &mut coordinates[0][..lanes]);
        self.y.store(simd, &mut coordinates[1][..lanes]);
        self.z.store(simd, &mut coordinates[2][..lanes]);
        for (lane, point) in points[..lanes].iter_mut().enumerate() {
            *point = [
                coordinates[0][lane],
                coordinates[1][lane],
                coordinates[2][lane],
            ];
        }
    }

    /// Returns `rhs` in every lane whose bit is set in `lanes`, and `self` in the others.
    ///
    /// Bit `i` of `lanes` selects lane `i`, without branching on `lanes`.
    #[inline(always)]
    pub fn select<S: Simd>(self, simd: S, rhs: Self, lanes: u64) -> Self
    where
        F: Field<S>,
    {
        Self {
            x: self.x.select(simd, rhs.x, lanes),
            y: self.y.select(simd, rhs.y, lanes),
            z: self.z.select(simd, rhs.z, lanes),
        }
    }

    /// Stores each lane's raw coordinates, dropping lanes beyond `points`.
    #[inline(always)]
    pub fn store_raw<S: Simd>(self, simd: S, points: &mut [[F::Raw; 3]])
    where
        F: Field<S>,
    {
        const { assert!(F::LANES <= MAX_LANES) };
        let mut coordinates = [[F::Raw::default(); MAX_LANES]; 3];
        let lanes = points.len().min(F::LANES);
        self.x
            .store_raw::<BOUND>(simd, &mut coordinates[0][..lanes]);
        self.y
            .store_raw::<BOUND>(simd, &mut coordinates[1][..lanes]);
        self.z
            .store_raw::<BOUND>(simd, &mut coordinates[2][..lanes]);
        for (lane, point) in points[..lanes].iter_mut().enumerate() {
            *point = [
                coordinates[0][lane],
                coordinates[1][lane],
                coordinates[2][lane],
            ];
        }
    }

    /// Loads lane `i` from the raw coordinates `points[i]`, for at least `F::LANES` entries.
    #[inline(always)]
    pub fn load_raw<S: Simd>(simd: S, points: &[&[F::Raw; 3]]) -> Self
    where
        F: Field<S>,
    {
        const { assert!(F::LANES <= MAX_LANES) };
        let coordinate = |i: usize| {
            let mut lanes = [&points[0][i]; MAX_LANES];
            for (lane, point) in lanes.iter_mut().zip(points).take(F::LANES) {
                *lane = &point[i];
            }
            F::load_raw::<BOUND>(simd, &lanes)
        };
        Self {
            x: coordinate(0),
            y: coordinate(1),
            z: coordinate(2),
        }
    }

    /// Returns `-self`.
    ///
    /// Multiplies `Y` by `-1` rather than subtracting it, so the coordinates keep their bounds.
    #[inline(always)]
    pub fn neg<S: Simd>(self, simd: S) -> Self
    where
        F: Field<S>,
    {
        let minus_one = F::load(simd, &[], &MINUS_ONE);
        Self {
            y: self.y.ready::<1>(simd).mul(simd, minus_one),
            ..self
        }
    }

    /// Returns `-self` in every lane whose bit is set in `lanes`, and `self` in the others.
    ///
    /// Multiplies `Y` by `1` or `-1`, selected without branching on `lanes`.
    #[inline(always)]
    pub fn negate_lanes<S: Simd>(self, simd: S, lanes: u64) -> Self
    where
        F: Field<S>,
    {
        let sign = F::load(simd, &[], &ONE).select(simd, F::load(simd, &[], &MINUS_ONE), lanes);
        Self {
            y: self.y.ready::<1>(simd).mul(simd, sign),
            ..self
        }
    }

    /// Returns the image of every lane under the endomorphism `(x, y) -> (beta x, y)`, which
    /// multiplies points of the prime-order subgroup by `-x^2` for the curve parameter `x`.
    #[inline(always)]
    pub fn endomorphism<S: Simd>(self, simd: S) -> Self
    where
        F: Field<S>,
    {
        let beta = F::load(simd, &[], &BETA);
        Self {
            x: self.x.ready::<1>(simd).mul(simd, beta),
            ..self
        }
    }

    /// Returns `self + rhs`.
    ///
    /// This is Algorithm 7 of Renes, Costello, and Batina, "Complete addition formulas for prime
    /// order elliptic curves" (2016), which accepts any pair of points, including the identity and
    /// equal points. Each output coordinate is a sum of two products with a single reduction, and
    /// each cross term reuses the two known products through [`Field::cross`]. Multiplications by
    /// `3b = 12` use [`Field::mul_small`], leaving twelve products.
    ///
    /// Debug builds keep this a call so that chained formulas fit in a stack frame.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn add<S: Simd>(self, simd: S, rhs: Self) -> Self
    where
        F: Field<S>,
    {
        let (x1, y1, z1) = (
            self.x.ready::<1>(simd),
            self.y.ready::<1>(simd),
            self.z.ready::<1>(simd),
        );
        let (x2, y2, z2) = (
            rhs.x.ready::<1>(simd),
            rhs.y.ready::<1>(simd),
            rhs.z.ready::<1>(simd),
        );
        let xx = x1.product(simd, x2);
        let yy = y1.product(simd, y2);
        let zz = z1.product(simd, z2);
        // x1 y2 + y1 x2, y1 z2 + z1 y2, and x1 z2 + z1 x2.
        let xy = F::reduce_signed::<PRODUCT_BIAS>(simd, F::cross(simd, [x1, y1], [x2, y2], xx, yy));
        let yz = F::reduce_signed::<PRODUCT_BIAS>(simd, F::cross(simd, [y1, z1], [y2, z2], yy, zz));
        let xz = F::reduce_signed::<PRODUCT_BIAS>(simd, F::cross(simd, [x1, z1], [x2, z2], xx, zz));
        let xx = F::reduce(simd, xx);
        let yy = F::reduce(simd, yy);
        let zz = F::reduce(simd, zz);
        let xx3 = xx.mul_small::<3>(simd).ready::<3>(simd);
        let b3zz = zz.mul_small::<12>(simd).carry(simd);
        let b3xz = xz.mul_small::<12>(simd).ready::<12>(simd);
        let sum = yy.add(simd, b3zz).ready::<2>(simd);
        let difference = yy.sub::<{ 12 * REDUCED }>(simd, b3zz).ready::<4>(simd);
        let x = F::product_sub::<PRODUCT_BIAS>(simd, xy.product(simd, difference), yz.product(simd, b3xz));
        let y = F::accumulate(simd, b3xz.product(simd, xx3), difference.product(simd, sum));
        let z = F::accumulate(simd, sum.product(simd, yz), xx3.product(simd, xy));
        Self {
            x: F::reduce(simd, x),
            y: F::reduce(simd, y),
            z: F::reduce(simd, z),
        }
    }

    /// Returns `2 * self`.
    ///
    /// This is Algorithm 9 of Renes, Costello, and Batina, which accepts any point, including the
    /// identity. It returns the same point as [`Self::add`] of `self` with itself, with eight
    /// products.
    ///
    /// Debug builds keep this a call so that chained formulas fit in a stack frame.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn double<S: Simd>(self, simd: S) -> Self
    where
        F: Field<S>,
    {
        let (x, y, z) = (
            self.x.ready::<1>(simd),
            self.y.ready::<1>(simd),
            self.z.ready::<1>(simd),
        );
        let yy = y.mul(simd, y);
        let xy = x.mul(simd, y);
        let yz = y.mul(simd, z);
        // 3b z^2 and 9b z^2.
        let b3zz = z.mul(simd, z).mul_small::<12>(simd).carry(simd);
        let b9zz = b3zz.mul_small::<3>(simd).carry(simd);
        let yy8 = yy.mul_small::<8>(simd).ready::<8>(simd);
        // y^2 - 9b z^2 and y^2 + 3b z^2.
        let difference = yy.sub::<{ 36 * REDUCED }>(simd, b9zz).ready::<4>(simd);
        let sum = yy.add(simd, b3zz).ready::<2>(simd);
        let xy2 = xy.double(simd).ready::<2>(simd);
        let y = F::accumulate(simd, difference.product(simd, sum), b3zz.product(simd, yy8));
        Self {
            x: F::reduce(simd, difference.product(simd, xy2)),
            y: F::reduce(simd, y),
            z: F::reduce(simd, yy8.product(simd, yz)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::field::fp::{
        rns::Rns,
        tests::{self as reference, Element},
        unsat28::Unsat28,
        unsat49::Unsat49,
    };
    use commonware_simd::{
        Operation, X86V4C, check_consistent,
        emulated::{EmulatedNeon, EmulatedScalar, EmulatedX86V4C},
        test_dispatch,
    };
    use std::{vec, vec::Vec};

    /// Number of points summed into each lane.
    const ROUNDS: usize = 12;

    /// The standard G1 generator in affine coordinates.
    const GENERATOR: (Element, Element) = (
        [
            0xfb3a_f00a_db22_c6bb,
            0x6c55_e83f_f97a_1aef,
            0xa14e_3a3f_171b_ac58,
            0xc368_8c4f_9774_b905,
            0x2695_638c_4fa9_ac0f,
            0x17f1_d3a7_3197_d794,
        ],
        [
            0x0caa_2329_46c5_e7e1,
            0xd03c_c744_a288_8ae4,
            0x00db_18cb_2c04_b3ed,
            0xfcf5_e095_d5d0_0af6,
            0xa09e_30ed_741d_8ae4,
            0x08b3_f481_e3aa_a0f1,
        ],
    );

    /// An affine point, or `None` for the identity.
    type Affine = Option<(Element, Element)>;

    /// Returns `p + q` with the affine chord-and-tangent formulas.
    fn affine_add(p: Affine, q: Affine) -> Affine {
        let (Some((x1, y1)), Some((x2, y2))) = (p, q) else {
            return p.or(q);
        };
        let slope = if x1 == x2 {
            if reference::add(y1, y2) == reference::ZERO {
                return None;
            }
            let numerator = reference::mul([3, 0, 0, 0, 0, 0], reference::mul(x1, x1));
            reference::mul(numerator, reference::invert(reference::add(y1, y1)))
        } else {
            reference::mul(
                reference::sub(y2, y1),
                reference::invert(reference::sub(x2, x1)),
            )
        };
        let x3 = reference::sub(reference::sub(reference::mul(slope, slope), x1), x2);
        let y3 = reference::sub(reference::mul(slope, reference::sub(x1, x3)), y1);
        Some((x3, y3))
    }

    /// Returns projective coordinates as bytes, scaling affine points by `z`.
    fn coordinates(point: Affine, z: Element) -> Coordinates {
        match point {
            Some((x, y)) => {
                [reference::mul(x, z), reference::mul(y, z), z].map(reference::to_bytes)
            }
            None => [reference::ZERO, z, reference::ZERO].map(reference::to_bytes),
        }
    }

    /// Returns the affine point of projective coordinates.
    fn affine(coordinates: &Coordinates) -> Affine {
        let [x, y, z] = coordinates.map(|bytes| reference::reduce(&bytes));
        if z == reference::ZERO {
            return None;
        }
        let inverse = reference::invert(z);
        Some((reference::mul(x, inverse), reference::mul(y, inverse)))
    }

    /// For each lane, sums `ROUNDS` points and doubles the sum, returning both.
    fn sum_and_double<S: Simd, F: Field<S>>(simd: S, points: &[Coordinates]) -> Vec<Coordinates> {
        let lanes = points.len() / ROUNDS;
        let mut output = vec![IDENTITY; 2 * lanes];
        for start in (0..lanes).step_by(F::LANES) {
            let mut sum = Point::<F>::load(simd, &[], &IDENTITY);
            for round in 0..ROUNDS {
                let addend = &points[round * lanes + start..(round + 1) * lanes];
                sum = sum.add(simd, Point::load(simd, addend, &IDENTITY));
                // Chain some sums through doublings and round-trip others through bytes or raw
                // coordinates.
                match round % 3 {
                    0 => sum = sum.add(simd, sum).add(simd, sum.double(simd).double(simd)),
                    1 => {
                        let mut stored = [IDENTITY; MAX_LANES];
                        sum.store(simd, &mut stored);
                        sum = Point::load(simd, &stored, &IDENTITY);
                    }
                    // Negate through -s + 2s, and round-trip through raw coordinates.
                    _ => {
                        sum = sum.neg(simd).add(simd, sum.double(simd));
                        let mut raw = [[F::Raw::default(); 3]; MAX_LANES];
                        sum.store_raw(simd, &mut raw);
                        let lanes: Vec<_> = raw.iter().collect();
                        sum = Point::load_raw(simd, &lanes);
                    }
                }
            }
            sum.store(simd, &mut output[start..lanes]);
            sum.double(simd).store(simd, &mut output[lanes + start..]);
        }
        output
    }

    #[test]
    fn sums_and_doublings_match_reference() {
        /// Runs [`sum_and_double`] in every representation, returning the positional ones' outputs.
        struct Evaluate<'a>(&'a [Coordinates]);

        impl<S: Simd> Operation<S> for Evaluate<'_> {
            type Output = [Vec<Coordinates>; 2];

            fn portable(self, simd: S) -> [Vec<Coordinates>; 2] {
                simd.execute(
                    #[inline(always)]
                    |simd: S| {
                        [
                            sum_and_double::<S, Unsat49<S>>(simd, self.0),
                            sum_and_double::<S, Unsat28<S>>(simd, self.0),
                        ]
                    },
                )
            }

            // Residues require x86v4c and must match the other representations.
            fn x86_v4c(self, simd: S) -> [Vec<Coordinates>; 2]
            where
                S: X86V4C,
            {
                let points = self.0;
                let outputs = self.portable(simd);
                let residues = simd.execute(
                    #[inline(always)]
                    |simd: S| sum_and_double::<S, Rns<S>>(simd, points),
                );
                assert!(residues == outputs[0], "residues differ");
                outputs
            }
        }

        let (x, y) = GENERATOR;
        let four = [4, 0, 0, 0, 0, 0];
        assert_eq!(
            reference::mul(y, y),
            reference::add(reference::mul(x, reference::mul(x, x)), four),
            "the generator is on the curve"
        );
        // Multiples of the generator, with repeats, negations, and identities to exercise
        // doubling, cancellation, and the identity cases, in varied projective scalings.
        let mut points = Vec::new();
        let mut inputs = Vec::new();
        let mut point = Some(GENERATOR);
        for i in 0..ROUNDS * MAX_LANES {
            let addend = match i % 7 {
                3 => None,
                5 => point.map(|(x, y)| (x, reference::neg(y))),
                _ => point,
            };
            points.push(addend);
            let z = [i as u64 + 1, 0, 0, 0, 0, 0];
            inputs.push(coordinates(
                addend,
                if i % 2 == 0 { reference::ONE } else { z },
            ));
            if i % 5 != 0 {
                point = affine_add(point, Some(GENERATOR));
            }
        }
        let mut expected = Vec::new();
        for lane in 0..MAX_LANES {
            let mut sum = None;
            for round in 0..ROUNDS {
                sum = affine_add(sum, points[round * MAX_LANES + lane]);
                if round % 3 == 0 {
                    // sum + sum + 4 sum.
                    let double = affine_add(sum, sum);
                    sum = affine_add(double, affine_add(double, double));
                }
            }
            expected.push(sum);
        }
        let check = |outputs: [Vec<Coordinates>; 2]| {
            for (representation, output) in outputs.iter().enumerate() {
                for lane in 0..MAX_LANES {
                    assert_eq!(
                        affine(&output[lane]),
                        expected[lane],
                        "sum {representation} {lane}"
                    );
                    assert_eq!(
                        affine(&output[MAX_LANES + lane]),
                        affine_add(expected[lane], expected[lane]),
                        "double {representation} {lane}"
                    );
                }
            }
        };
        check(test_dispatch(Evaluate(&inputs)));
        check_consistent(|| Evaluate(&inputs));
        // Run every representation and vector width even on hosts without native SIMD.
        check(Evaluate(&inputs).portable(EmulatedScalar));
        check(Evaluate(&inputs).portable(EmulatedNeon));
        check(EmulatedX86V4C.execute(Evaluate(&inputs)));
    }
}
