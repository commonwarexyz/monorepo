//! Complete projective addition on G1 over [`Unsat49`] values, for comparing field
//! representations.
//!
//! The formula is Algorithm 7 of Renes, Costello, and Batina, "Complete addition formulas for
//! prime order elliptic curves" (2016), for `y^2 = x^3 + 4`: twelve multiplications, two
//! multiplications by `3b = 12`, and nineteen additions or subtractions. It accepts any pair of
//! points, including the identity `(0 : 1 : 0)` and equal points.
//!
//! Every multiplicand is prepared with [`Unsat49::ready`] from a static bound on its limbs, so
//! radices with spare multiplier bits skip the carries that radix `2^52` needs. Inputs and outputs
//! have integer bounds of at most `5` for `x` and `4` for `y` and `z`, in units of `p`, and limb
//! bounds of at most `4` for `x` and `2` for `y` and `z`, in units of a carried limb.

use crate::{
    field::fp::unsat49::{LIMBS, Unsat49},
    fp::{Fp, lanes::MAX_LANES},
};
use commonware_simd::Simd;

/// `S::U64_LANES` projective points, one per lane.
pub struct Point<S: Simd, const BITS: u32 = 49> {
    /// The `X` coordinates.
    pub x: Unsat49<S, BITS>,
    /// The `Y` coordinates.
    pub y: Unsat49<S, BITS>,
    /// The `Z` coordinates.
    pub z: Unsat49<S, BITS>,
}

impl<S: Simd, const BITS: u32> Clone for Point<S, BITS> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<S: Simd, const BITS: u32> Copy for Point<S, BITS> {}

/// `S::U64_LANES` projective points in the per-lane limb form of [`Unsat49::to_limbs`].
pub type Limbs = [[[u64; LIMBS]; MAX_LANES]; 3];

impl<S: Simd, const BITS: u32> Point<S, BITS> {
    /// Loads up to `S::U64_LANES` projective points `[X, Y, Z]`, one per lane, filling the
    /// remaining lanes with `fill`.
    #[inline(always)]
    pub fn load(simd: S, points: &[[Fp; 3]], fill: [Fp; 3]) -> Self {
        let mut coordinates = [[Fp::ZERO; MAX_LANES]; 3];
        for (i, coordinate) in coordinates.iter_mut().enumerate() {
            coordinate.fill(fill[i]);
            for (lane, point) in coordinate.iter_mut().zip(points) {
                *lane = point[i];
            }
        }
        Self {
            x: Unsat49::load(simd, &coordinates[0], fill[0]),
            y: Unsat49::load(simd, &coordinates[1], fill[1]),
            z: Unsat49::load(simd, &coordinates[2], fill[2]),
        }
    }

    /// Stores each lane's canonical projective coordinates, dropping lanes beyond `points`.
    #[inline(always)]
    pub fn store(self, simd: S, points: &mut [[Fp; 3]]) {
        let mut coordinates = [[Fp::ZERO; MAX_LANES]; 3];
        self.x.store(simd, &mut coordinates[0]);
        self.y.store(simd, &mut coordinates[1]);
        self.z.store(simd, &mut coordinates[2]);
        for (lane, point) in points.iter_mut().enumerate().take(MAX_LANES) {
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
    pub fn add(self, simd: S, rhs: Self, b3: Unsat49<S, BITS>) -> Self {
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
    use crate::g1::G1;
    use commonware_simd::{Operation, check_consistent, test_dispatch};
    use std::vec::Vec;

    /// Number of points summed into each lane.
    const ROUNDS: usize = 12;

    /// Sums `ROUNDS` points into each lane, loading each addend as scalar coordinates.
    struct Sum<'a, const BITS: u32>(&'a [[Fp; 3]]);

    impl<S: Simd, const BITS: u32> Operation<S> for Sum<'_, BITS> {
        type Output = Vec<[Fp; 3]>;

        fn portable(self, simd: S) -> Vec<[Fp; 3]> {
            let mut output = vec![[Fp::ZERO; 3]; MAX_LANES];
            let fill = [Fp::ZERO, Fp::ONE, Fp::ZERO];
            simd.execute(
                #[inline(always)]
                |simd: S| {
                    let b3 = Unsat49::<S, BITS>::splat(simd, Fp::from_u64(12));
                    for start in (0..MAX_LANES).step_by(S::U64_LANES) {
                        let mut sum = Point::<S, BITS>::load(simd, &[], fill);
                        for round in 0..ROUNDS {
                            let points = &self.0[round * MAX_LANES + start..];
                            let addend = Point::load(simd, &points[..S::U64_LANES], fill);
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

    /// Returns affine coordinates, or `None` for the identity.
    fn affine([x, y, z]: [Fp; 3]) -> Option<(Fp, Fp)> {
        if z == Fp::ZERO {
            return None;
        }
        let inverse = z.invert();
        Some((x.mul(inverse), y.mul(inverse)))
    }

    fn sums_match_g1<const BITS: u32>() {
        // Distinct multiples of the generator, with repeats to exercise doubling and identities.
        let mut points = Vec::new();
        let mut point = G1::GENERATOR;
        for i in 0..ROUNDS * MAX_LANES {
            points.push(if i % 7 == 3 { G1::IDENTITY } else { point });
            if i % 5 != 0 {
                point += &G1::GENERATOR;
            }
        }
        let scalar: Vec<[Fp; 3]> = points
            .iter()
            .map(|point| match point.to_affine() {
                Some((x, y)) => [x, y, Fp::ONE],
                None => [Fp::ZERO, Fp::ONE, Fp::ZERO],
            })
            .collect();
        let actual = test_dispatch(Sum::<BITS>(&scalar));
        check_consistent(|| Sum::<BITS>(&scalar));
        for (lane, actual) in actual.iter().enumerate() {
            let mut expected = G1::IDENTITY;
            for round in 0..ROUNDS {
                expected += &points[round * MAX_LANES + lane];
            }
            assert_eq!(affine(*actual), expected.to_affine(), "lane {lane}");
        }
    }

    #[test]
    fn sums_match_g1_radix52() {
        sums_match_g1::<52>();
    }

    #[test]
    fn sums_match_g1_radix51() {
        sums_match_g1::<51>();
    }

    #[test]
    fn sums_match_g1_radix50() {
        sums_match_g1::<50>();
    }

    #[test]
    fn sums_match_g1_radix49() {
        sums_match_g1::<49>();
    }
}
