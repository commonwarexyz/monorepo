//! Inputs shared by the group benchmarks.

use commonware_bench::Inputs;
use commonware_cryptography_bls12381::{G1, G2, Scalar};
use commonware_math::algebra::{CryptoGroup, Random};
use commonware_parallel::{Rayon, Strategy, rayon::ThreadPoolBuilder};
use commonware_utils::TestRng;
use std::num::NonZeroUsize;

/// Returns `count` deterministic scalars, uniform over the scalar field.
pub fn scalars(count: usize, seed: u64) -> Vec<Scalar> {
    let mut rng = TestRng::new(seed);
    (0..count).map(|_| Scalar::random(&mut rng)).collect()
}

/// Returns the strategies that the operations over slices run under, each with its count of
/// workers. One worker measures the calling thread alone.
pub fn strategies() -> Vec<(usize, Rayon)> {
    let workers: &[usize] = match Inputs::current() {
        Inputs::Smoke => &[1, 2],
        Inputs::Standard => &[1, 8],
        Inputs::Full => &[1, 2, 4, 8, 16],
    };
    workers
        .iter()
        .map(|&workers| {
            let count = NonZeroUsize::new(workers).expect("at least one worker");
            let strategy = Rayon::new(ThreadPoolBuilder::new(count)).expect("the pool must build");
            (workers, strategy)
        })
        .collect()
}

/// A group of the public API.
pub trait Curve: CryptoGroup<Scalar = Scalar> + Copy {
    /// The group's name in benchmark labels.
    const NAME: &'static str;

    /// Returns the sum of the points.
    fn sum(points: &[Self], strategy: &impl Strategy) -> Self;

    /// Multiplies each point by the scalar at the same index, in place.
    fn mul_each(points: &mut [Self], scalars: &[Scalar], strategy: &impl Strategy);

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

    fn sum(points: &[Self], strategy: &impl Strategy) -> Self {
        Self::sum(points, strategy)
    }

    fn mul_each(points: &mut [Self], scalars: &[Scalar], strategy: &impl Strategy) {
        Self::mul_each(points, scalars, strategy);
    }
}

impl Curve for G2 {
    const NAME: &'static str = "g2";

    fn sum(points: &[Self], strategy: &impl Strategy) -> Self {
        Self::sum(points, strategy)
    }

    fn mul_each(points: &mut [Self], scalars: &[Scalar], strategy: &impl Strategy) {
        Self::mul_each(points, scalars, strategy);
    }
}

/// Returns `count` pairs of points.
pub fn pairs(count: usize) -> Vec<(G1, G2)> {
    G1::points(count, 1)
        .into_iter()
        .zip(G2::points(count, 2))
        .collect()
}
