//! Sums of G1 points, as a representative formula.
//!
//! Each lane sums every eighth point with complete projective additions, leaving eight partial
//! sums; combining them would add a small, fixed cost.

use super::utils::{LANES, points};
use commonware_cryptography_bls12381::{
    curve::g1::{B3, Coordinates, IDENTITY, Point},
    field::fp::unsat49::{LIMBS, Unsat49},
};
use commonware_simd::{Operation, Simd, dispatch};
use criterion::{Criterion, Throughput, criterion_group};
use std::hint::black_box;

/// Largest `S::U64_LANES` of any backend.
const MAX_LANES: usize = 8;

/// `S::U64_LANES` projective points in the per-lane limb form of [`Unsat49::to_limbs`].
type Limbs = [[[u64; LIMBS]; MAX_LANES]; 3];

/// Integer bound of loaded coordinates, in units of `p`.
const LOADED: u64 = 2;

/// Sums points loaded from bytes, converting each addend.
struct SumBytes<'a>(&'a [Coordinates]);

impl<S: Simd> Operation<S> for SumBytes<'_> {
    type Output = [Coordinates; LANES];

    fn portable(self, simd: S) -> [Coordinates; LANES] {
        let mut output = [IDENTITY; LANES];
        simd.execute(
            #[inline(always)]
            |simd: S| {
                let b3 = Unsat49::<S>::splat(simd, &B3);
                let rounds = self.0.len() / LANES;
                for start in (0..LANES).step_by(S::U64_LANES) {
                    let mut sum = Point::<Unsat49<S>>::load(simd, &self.0[start..], &IDENTITY);
                    for round in 1..rounds {
                        let base = round * LANES + start;
                        let points = &self.0[base..base + S::U64_LANES];
                        sum = sum.add(simd, Point::load(simd, points, &IDENTITY), b3);
                    }
                    sum.store(simd, &mut output[start..]);
                }
            },
        );
        output
    }
}

/// Converts points into per-lane limbs, one entry per round and lane chunk.
struct Prepare<'a>(&'a [Coordinates]);

impl<S: Simd> Operation<S> for Prepare<'_> {
    type Output = Vec<Limbs>;

    fn portable(self, simd: S) -> Vec<Limbs> {
        let mut output = Vec::new();
        for round in 0..self.0.len() / LANES {
            for start in (0..LANES).step_by(S::U64_LANES) {
                let base = round * LANES + start;
                let points = &self.0[base..base + S::U64_LANES];
                let point = Point::<Unsat49<S>>::load(simd, points, &IDENTITY);
                output.push(
                    [point.x, point.y, point.z].map(|coordinate| coordinate.to_limbs(simd, LOADED)),
                );
            }
        }
        output
    }
}

/// Loads points stored by [`Prepare`], without any conversion.
#[inline(always)]
fn from_limbs<S: Simd>(simd: S, limbs: &Limbs) -> Point<Unsat49<S>> {
    Point {
        x: Unsat49::from_limbs(simd, &limbs[0], LOADED),
        y: Unsat49::from_limbs(simd, &limbs[1], LOADED),
        z: Unsat49::from_limbs(simd, &limbs[2], LOADED),
    }
}

/// Sums points already in this representation's limb form.
struct SumLimbs<'a>(&'a [Limbs]);

impl<S: Simd> Operation<S> for SumLimbs<'_> {
    type Output = [Coordinates; LANES];

    fn portable(self, simd: S) -> [Coordinates; LANES] {
        let mut output = [IDENTITY; LANES];
        simd.execute(
            #[inline(always)]
            |simd: S| {
                let b3 = Unsat49::<S>::splat(simd, &B3);
                let chunks = LANES / S::U64_LANES;
                let rounds = self.0.len() / chunks;
                for (chunk, start) in (0..LANES).step_by(S::U64_LANES).enumerate() {
                    let mut sum = from_limbs(simd, &self.0[chunk]);
                    for round in 1..rounds {
                        let addend = from_limbs(simd, &self.0[round * chunks + chunk]);
                        sum = sum.add(simd, addend, b3);
                    }
                    sum.store(simd, &mut output[start..]);
                }
            },
        );
        output
    }
}

fn bench_sum(c: &mut Criterion) {
    let mut group = c.benchmark_group(module_path!());
    for n in [128, 1024] {
        let (coordinates, blst_points) = points(n);
        group.throughput(Throughput::Elements(n as u64));
        group.bench_function(format!("repr=unsat49 input=bytes n={n}"), |b| {
            b.iter(|| black_box(dispatch(SumBytes(black_box(&coordinates)))));
        });
        let limbs = dispatch(Prepare(&coordinates));
        group.bench_function(format!("repr=unsat49 input=limbs n={n}"), |b| {
            b.iter(|| black_box(dispatch(SumLimbs(black_box(&limbs)))));
        });
        group.bench_function(format!("repr=blst n={n}"), |b| {
            b.iter(|| {
                let mut acc = blst::blst_p1::default();
                for point in &blst_points {
                    // SAFETY: valid pointers to point structures.
                    unsafe { blst::blst_p1_add_or_double(&mut acc, &acc, point) };
                }
                black_box(acc)
            });
        });
    }
    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(20);
    targets = bench_sum
}
