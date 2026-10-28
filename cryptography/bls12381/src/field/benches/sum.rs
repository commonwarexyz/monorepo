//! Sums of G1 points, as a representative formula for comparing radices.
//!
//! Each lane sums every eighth point with complete projective additions, leaving eight partial
//! sums; combining them is the same small cost in every representation.

use super::utils::{IDENTITY, LANES, points, projective, to_blst};
use commonware_cryptography_bls12381::{
    field::{
        curve::{Limbs, Point},
        fp::unsat49::Unsat49,
    },
    fp::{Fp, lanes::FpVec},
    g1::G1,
};
use commonware_simd::{Operation, Simd, dispatch};
use criterion::{Criterion, Throughput, criterion_group};
use std::hint::black_box;

/// Sums points loaded from scalar coordinates, converting each addend.
struct SumFp<'a, const BITS: u32>(&'a [[Fp; 3]]);

impl<S: Simd, const BITS: u32> Operation<S> for SumFp<'_, BITS> {
    type Output = [[Fp; 3]; LANES];

    fn portable(self, simd: S) -> [[Fp; 3]; LANES] {
        let mut output = [IDENTITY; LANES];
        simd.execute(
            #[inline(always)]
            |simd: S| {
                let b3 = Unsat49::<S, BITS>::splat(simd, Fp::from_u64(12));
                let rounds = self.0.len() / LANES;
                for start in (0..LANES).step_by(S::U64_LANES) {
                    let mut sum = Point::<S, BITS>::load(simd, &self.0[start..], IDENTITY);
                    for round in 1..rounds {
                        let base = round * LANES + start;
                        let addend =
                            Point::load(simd, &self.0[base..base + S::U64_LANES], IDENTITY);
                        sum = sum.add(simd, addend, b3);
                    }
                    sum.store(simd, &mut output[start..]);
                }
            },
        );
        output
    }
}

/// Converts points into per-lane limbs, one entry per round and lane chunk.
struct Prepare<'a, const BITS: u32>(&'a [[Fp; 3]]);

impl<S: Simd, const BITS: u32> Operation<S> for Prepare<'_, BITS> {
    type Output = Vec<Limbs>;

    fn portable(self, simd: S) -> Vec<Limbs> {
        let mut output = Vec::new();
        for round in 0..self.0.len() / LANES {
            for start in (0..LANES).step_by(S::U64_LANES) {
                let base = round * LANES + start;
                let point =
                    Point::<S, BITS>::load(simd, &self.0[base..base + S::U64_LANES], IDENTITY);
                output.push(point.to_limbs(simd));
            }
        }
        output
    }
}

/// Sums points already in this representation's limb form.
struct SumLimbs<'a, const BITS: u32>(&'a [Limbs]);

impl<S: Simd, const BITS: u32> Operation<S> for SumLimbs<'_, BITS> {
    type Output = [[Fp; 3]; LANES];

    fn portable(self, simd: S) -> [[Fp; 3]; LANES] {
        let mut output = [IDENTITY; LANES];
        simd.execute(
            #[inline(always)]
            |simd: S| {
                let b3 = Unsat49::<S, BITS>::splat(simd, Fp::from_u64(12));
                let chunks = LANES / S::U64_LANES;
                let rounds = self.0.len() / chunks;
                for (chunk, start) in (0..LANES).step_by(S::U64_LANES).enumerate() {
                    let mut sum = Point::<S, BITS>::from_limbs(simd, &self.0[chunk]);
                    for round in 1..rounds {
                        let addend = Point::from_limbs(simd, &self.0[round * chunks + chunk]);
                        sum = sum.add(simd, addend, b3);
                    }
                    sum.store(simd, &mut output[start..]);
                }
            },
        );
        output
    }
}

/// Complete projective addition with the existing eagerly carried radix `2^52` lanes.
#[inline(always)]
fn add_fpvec<S: Simd>(simd: S, p: [FpVec<S>; 3], q: [FpVec<S>; 3], b3: FpVec<S>) -> [FpVec<S>; 3] {
    let ([x1, y1, z1], [x2, y2, z2]) = (p, q);
    let t0 = x1.mul(simd, x2);
    let t1 = y1.mul(simd, y2);
    let t2 = z1.mul(simd, z2);
    let t3 = x1.add(simd, y1);
    let t4 = x2.add(simd, y2);
    let t3 = t3.mul(simd, t4);
    let t4 = t0.add(simd, t1);
    let t3 = t3.sub(simd, t4);
    let t4 = y1.add(simd, z1);
    let x3 = y2.add(simd, z2);
    let t4 = t4.mul(simd, x3);
    let x3 = t1.add(simd, t2);
    let t4 = t4.sub(simd, x3);
    let x3 = x1.add(simd, z1);
    let y3 = x2.add(simd, z2);
    let x3 = x3.mul(simd, y3);
    let y3 = t0.add(simd, t2);
    let y3 = x3.sub(simd, y3);
    let x3 = t0.double(simd);
    let t0 = x3.add(simd, t0);
    let t2 = b3.mul(simd, t2);
    let z3 = t1.add(simd, t2);
    let t1 = t1.sub(simd, t2);
    let y3 = b3.mul(simd, y3);
    let x3 = t4.mul(simd, y3);
    let t2 = t3.mul(simd, t1);
    let x3 = t2.sub(simd, x3);
    let y3 = y3.mul(simd, t0);
    let t1 = t1.mul(simd, z3);
    let y3 = t1.add(simd, y3);
    let t0 = t0.mul(simd, t3);
    let z3 = z3.mul(simd, t4);
    let z3 = z3.add(simd, t0);
    [x3, y3, z3]
}

/// Loads one projective point per lane into the existing eagerly carried lanes.
#[inline(always)]
fn load_fpvec<S: Simd>(simd: S, points: &[[Fp; 3]]) -> [FpVec<S>; 3] {
    let mut coordinates = [[Fp::ZERO; LANES]; 3];
    for (i, coordinate) in coordinates.iter_mut().enumerate() {
        for (lane, point) in coordinate.iter_mut().zip(points) {
            *lane = point[i];
        }
    }
    [
        FpVec::load(simd, &coordinates[0], IDENTITY[0]),
        FpVec::load(simd, &coordinates[1], IDENTITY[1]),
        FpVec::load(simd, &coordinates[2], IDENTITY[2]),
    ]
}

/// [`SumFp`] with the existing eagerly carried radix `2^52` lanes.
struct SumFpVec<'a>(&'a [[Fp; 3]]);

impl<S: Simd> Operation<S> for SumFpVec<'_> {
    type Output = [[Fp; 3]; LANES];

    fn portable(self, simd: S) -> [[Fp; 3]; LANES] {
        let mut output = [IDENTITY; LANES];
        simd.execute(
            #[inline(always)]
            |simd: S| {
                let b3 = FpVec::splat(simd, Fp::from_u64(12));
                let rounds = self.0.len() / LANES;
                for start in (0..LANES).step_by(S::U64_LANES) {
                    let mut sum = load_fpvec(simd, &self.0[start..start + S::U64_LANES]);
                    for round in 1..rounds {
                        let base = round * LANES + start;
                        let addend = load_fpvec(simd, &self.0[base..base + S::U64_LANES]);
                        sum = add_fpvec(simd, sum, addend, b3);
                    }
                    let mut coordinates = [[Fp::ZERO; LANES]; 3];
                    for (value, coordinate) in sum.into_iter().zip(&mut coordinates) {
                        value.store(simd, coordinate);
                    }
                    for (lane, point) in output[start..start + S::U64_LANES].iter_mut().enumerate()
                    {
                        *point = [
                            coordinates[0][lane],
                            coordinates[1][lane],
                            coordinates[2][lane],
                        ];
                    }
                }
            },
        );
        output
    }
}

fn bench_sum(c: &mut Criterion) {
    let mut group = c.benchmark_group(module_path!());
    for n in [128, 1024] {
        let points = points(n);
        let scalar: Vec<[Fp; 3]> = points.iter().map(projective).collect();
        group.throughput(Throughput::Elements(n as u64));
        macro_rules! radix {
            ($($bits:literal),*) => {$(
                group.bench_function(format!("repr=unsat49 radix={} input=fp n={n}", $bits), |b| {
                    b.iter(|| black_box(dispatch(SumFp::<$bits>(black_box(&scalar)))));
                });
                let limbs = dispatch(Prepare::<$bits>(&scalar));
                group.bench_function(format!("repr=unsat49 radix={} input=limbs n={n}", $bits), |b| {
                    b.iter(|| black_box(dispatch(SumLimbs::<$bits>(black_box(&limbs)))));
                });
            )*};
        }
        radix!(52, 51, 50, 49);
        group.bench_function(format!("repr=fpvec radix=52 input=fp n={n}"), |b| {
            b.iter(|| black_box(dispatch(SumFpVec(black_box(&scalar)))));
        });
        group.bench_function(format!("repr=g1 n={n}"), |b| {
            b.iter(|| black_box(G1::sum(black_box(&points))));
        });
        let blst_points: Vec<_> = points.iter().map(to_blst).collect();
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
    config = criterion::Criterion::default().sample_size(20);
    targets = bench_sum
}
