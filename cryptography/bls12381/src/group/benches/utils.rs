//! Inputs shared by the group benchmarks.

use commonware_cryptography_bls12381::{G1, G2, Scalar};
use commonware_math::algebra::{CryptoGroup, Random};
use commonware_utils::TestRng;

/// Returns `count` deterministic scalars, uniform over the scalar field.
pub fn scalars(count: usize, seed: u64) -> Vec<Scalar> {
    let mut rng = TestRng::new(seed);
    (0..count).map(|_| Scalar::random(&mut rng)).collect()
}

/// A group of the public API.
pub trait Curve: CryptoGroup<Scalar = Scalar> + Copy {
    /// The group's name in benchmark labels.
    const NAME: &'static str;

    /// Returns the sum of the points.
    fn sum(points: &[Self]) -> Self;

    /// Multiplies each point by the scalar at the same index, in place.
    fn mul_each(points: &mut [Self], scalars: &[Scalar]);

    /// Returns `count` distinct points.
    fn points(count: usize, seed: u64) -> Vec<Self> {
        // The points step from one multiple of the generator by another, so that preparing many
        // costs additions rather than multiplications.
        let scalars = scalars(2, seed);
        let mut point = Self::generator() * &scalars[0];
        let step = Self::generator() * &scalars[1];
        let mut points = Vec::with_capacity(count);
        for _ in 0..count {
            points.push(point);
            point += &step;
        }
        points
    }
}

impl Curve for G1 {
    const NAME: &'static str = "g1";

    fn sum(points: &[Self]) -> Self {
        Self::sum(points)
    }

    fn mul_each(points: &mut [Self], scalars: &[Scalar]) {
        Self::mul_each(points, scalars);
    }
}

impl Curve for G2 {
    const NAME: &'static str = "g2";

    fn sum(points: &[Self]) -> Self {
        Self::sum(points)
    }

    fn mul_each(points: &mut [Self], scalars: &[Scalar]) {
        Self::mul_each(points, scalars);
    }
}

/// Returns `count` pairs of points.
pub fn pairs(count: usize) -> Vec<(G1, G2)> {
    G1::points(count, 1)
        .into_iter()
        .zip(G2::points(count, 2))
        .collect()
}
