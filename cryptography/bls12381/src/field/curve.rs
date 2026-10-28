//! Complete projective addition on G1 over [`Unsat49`] values.
//!
//! The formula is Algorithm 7 of Renes, Costello, and Batina, "Complete addition formulas for
//! prime order elliptic curves" (2016), for `y^2 = x^3 + 4`: twelve multiplications, two
//! multiplications by `3b = 12`, and nineteen additions or subtractions. It accepts any pair of
//! points, including the identity `(0 : 1 : 0)` and equal points.
//!
//! Every multiplicand is prepared with [`Unsat49::ready`] from a static bound on its limbs, which
//! never exceeds the multipliers' spare bits, so the formula never carries. Inputs and outputs have
//! integer bounds of at most `5` for `x` and `4` for `y` and `z`, in units of `p`, and limb
//! bounds of at most `4` for `x` and `2` for `y` and `z`, in units of a carried limb.

use crate::field::fp::{
    BYTES, MAX_LANES,
    unsat49::{LIMBS, Unsat49},
};
use commonware_simd::Simd;

/// `S::U64_LANES` projective points, one per lane.
pub struct Point<S: Simd> {
    /// The `X` coordinates.
    pub x: Unsat49<S>,
    /// The `Y` coordinates.
    pub y: Unsat49<S>,
    /// The `Z` coordinates.
    pub z: Unsat49<S>,
}

impl<S: Simd> Clone for Point<S> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<S: Simd> Copy for Point<S> {}

/// Projective coordinates `[X, Y, Z]` as big-endian integers.
pub type Coordinates = [[u8; BYTES]; 3];

/// `S::U64_LANES` projective points in the per-lane limb form of [`Unsat49::to_limbs`].
pub type Limbs = [[[u64; LIMBS]; MAX_LANES]; 3];

impl<S: Simd> Point<S> {
    /// Loads up to `S::U64_LANES` projective points, one per lane, filling the remaining lanes
    /// with `fill`.
    #[inline(always)]
    pub fn load(simd: S, points: &[Coordinates], fill: &Coordinates) -> Self {
        let mut coordinates = [[[0; BYTES]; MAX_LANES]; 3];
        for (i, coordinate) in coordinates.iter_mut().enumerate() {
            coordinate.fill(fill[i]);
            for (lane, point) in coordinate.iter_mut().zip(points) {
                *lane = point[i];
            }
        }
        Self {
            x: Unsat49::load(simd, &coordinates[0], &fill[0]),
            y: Unsat49::load(simd, &coordinates[1], &fill[1]),
            z: Unsat49::load(simd, &coordinates[2], &fill[2]),
        }
    }

    /// Stores each lane's canonical projective coordinates, dropping lanes beyond `points`.
    #[inline(always)]
    pub fn store(self, simd: S, points: &mut [Coordinates]) {
        let mut coordinates = [[[0; BYTES]; MAX_LANES]; 3];
        self.x.store(simd, &mut coordinates[0]);
        self.y.store(simd, &mut coordinates[1]);
        self.z.store(simd, &mut coordinates[2]);
        for (lane, point) in points.iter_mut().enumerate().take(S::U64_LANES) {
            *point = [coordinates[0][lane], coordinates[1][lane], coordinates[2][lane]];
        }
    }

    /// Loads points stored by [`Self::to_limbs`], without any conversion.
    #[inline(always)]
    pub fn from_limbs(simd: S, limbs: &Limbs) -> Self {
        Self {
            x: Unsat49::from_limbs(simd, &limbs[0], 5),
            y: Unsat49::from_limbs(simd, &limbs[1], 4),
            z: Unsat49::from_limbs(simd, &limbs[2], 4),
        }
    }

    /// Returns the points' carried limbs, without any conversion.
    #[inline(always)]
    pub fn to_limbs(self, simd: S) -> Limbs {
        [
            self.x.carry(simd).to_limbs(simd, 5),
            self.y.carry(simd).to_limbs(simd, 4),
            self.z.carry(simd).to_limbs(simd, 4),
        ]
    }

    /// Returns `self + rhs`, where `b3` holds `3b = 12` in every lane.
    #[inline(always)]
    pub fn add(self, simd: S, rhs: Self, b3: Unsat49<S>) -> Self {
        let (x1, y1, z1) = (self.x, self.y, self.z);
        let (x2, y2, z2) = (rhs.x, rhs.y, rhs.z);
        let t0 = x1.ready::<4>(simd).mul(simd, x2.ready::<4>(simd));
        let t1 = y1.ready::<2>(simd).mul(simd, y2.ready::<2>(simd));
        let t2 = z1.ready::<2>(simd).mul(simd, z2.ready::<2>(simd));
        let t3 = x1.add(simd, y1).ready::<6>(simd);
        let t4 = x2.add(simd, y2).ready::<6>(simd);
        let t3 = t3.mul(simd, t4);
        let t4 = t0.add(simd, t1);
        let t3 = t3.sub::<5>(simd, t4);
        let t4 = y1.add(simd, z1).ready::<4>(simd);
        let x3 = y2.add(simd, z2).ready::<4>(simd);
        let t4 = t4.mul(simd, x3);
        let x3 = t1.add(simd, t2);
        let t4 = t4.sub::<5>(simd, x3);
        let x3 = x1.add(simd, z1).ready::<6>(simd);
        let y3 = x2.add(simd, z2).ready::<6>(simd);
        let x3 = x3.mul(simd, y3);
        let y3 = t0.add(simd, t2);
        let y3 = x3.sub::<5>(simd, y3);
        let x3 = t0.double(simd);
        let t0 = x3.add(simd, t0);
        let t2 = b3.mul(simd, t2);
        let z3 = t1.add(simd, t2);
        let t1 = t1.sub::<3>(simd, t2);
        let y3 = b3.mul(simd, y3.ready::<4>(simd));
        let x3 = t4.ready::<4>(simd).mul(simd, y3);
        let t2 = t3.ready::<4>(simd).mul(simd, t1.ready::<4>(simd));
        let x3 = t2.sub::<3>(simd, x3);
        let t0 = t0.ready::<3>(simd);
        let y3 = y3.mul(simd, t0);
        let t1 = t1.ready::<4>(simd).mul(simd, z3.ready::<2>(simd));
        let y3 = t1.add(simd, y3);
        let t0 = t0.mul(simd, t3.ready::<4>(simd));
        let z3 = z3.ready::<2>(simd).mul(simd, t4.ready::<4>(simd));
        let z3 = z3.add(simd, t0);
        Self {
            x: x3,
            y: y3,
            z: z3,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::fp::tests::{self as reference, Element};
    use commonware_simd::{Operation, check_consistent, test_dispatch};
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
            reference::mul(reference::sub(y2, y1), reference::invert(reference::sub(x2, x1)))
        };
        let x3 = reference::sub(reference::sub(reference::mul(slope, slope), x1), x2);
        let y3 = reference::sub(reference::mul(slope, reference::sub(x1, x3)), y1);
        Some((x3, y3))
    }

    /// Returns projective coordinates as bytes.
    fn coordinates(point: Affine) -> Coordinates {
        match point {
            Some((x, y)) => [x, y, reference::ONE].map(reference::to_bytes),
            None => [reference::ZERO, reference::ONE, reference::ZERO].map(reference::to_bytes),
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

    /// Sums `ROUNDS` points into each lane, loading each addend from bytes.
    struct Sum<'a>(&'a [Coordinates]);

    impl<S: Simd> Operation<S> for Sum<'_> {
        type Output = Vec<Coordinates>;

        fn portable(self, simd: S) -> Vec<Coordinates> {
            let mut output = vec![[[0; BYTES]; 3]; MAX_LANES];
            let identity = coordinates(None);
            let twelve = reference::to_bytes([12, 0, 0, 0, 0, 0]);
            simd.execute(
                #[inline(always)]
                |simd: S| {
                    let b3 = Unsat49::<S>::splat(simd, &twelve);
                    for start in (0..MAX_LANES).step_by(S::U64_LANES) {
                        let mut sum = Point::<S>::load(simd, &[], &identity);
                        for round in 0..ROUNDS {
                            let points = &self.0[round * MAX_LANES + start..];
                            let addend = Point::load(simd, &points[..S::U64_LANES], &identity);
                            sum = sum.add(simd, addend, b3);
                            // Round-trip some sums through limbs, as stored accumulators would,
                            // and chain the others directly.
                            if round % 2 == 1 {
                                sum = Point::from_limbs(simd, &sum.to_limbs(simd));
                            }
                        }
                        sum.store(simd, &mut output[start..]);
                    }
                },
            );
            output
        }
    }

    #[test]
    fn sums_match_reference() {
        let (x, y) = GENERATOR;
        let four = [4, 0, 0, 0, 0, 0];
        assert_eq!(
            reference::mul(y, y),
            reference::add(reference::mul(x, reference::mul(x, x)), four),
            "the generator is on the curve"
        );
        // Multiples of the generator, with repeats and identities to exercise doubling and the
        // identity cases.
        let mut points = Vec::new();
        let mut point = Some(GENERATOR);
        for i in 0..ROUNDS * MAX_LANES {
            points.push(if i % 7 == 3 { None } else { point });
            if i % 5 != 0 {
                point = affine_add(point, Some(GENERATOR));
            }
        }
        let inputs: Vec<Coordinates> = points.iter().map(|point| coordinates(*point)).collect();
        let actual = test_dispatch(Sum(&inputs));
        check_consistent(|| Sum(&inputs));
        for (lane, actual) in actual.iter().enumerate() {
            let mut expected = None;
            for round in 0..ROUNDS {
                expected = affine_add(expected, points[round * MAX_LANES + lane]);
            }
            assert_eq!(affine(actual), expected, "lane {lane}");
        }
    }
}
