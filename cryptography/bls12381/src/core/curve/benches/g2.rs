//! G2 point operations in every base field representation, compared with blst.
//!
//! Each operation runs on `POINTS` independent points, one per lane, so every representation
//! fills whole vectors. blst runs the same operations one point at a time.

use super::utils::{Radix28, Radix49, Representation, Residues, g2_points};
use commonware_cryptography_bls12381::core::{
    curve::g2::{Coordinates, IDENTITY, Point},
    field::arithmetic::Field,
};
use commonware_simd::{Operation, Simd, dispatch};
use criterion::{BenchmarkGroup, Criterion, Throughput, criterion_group, measurement::WallTime};
use std::{hint::black_box, marker::PhantomData};

/// Independent points per operation, a multiple of every representation's lane count.
const POINTS: usize = 16;

/// Dependent operations on each point.
const ROUNDS: usize = 64;

/// Point sizes of the sums.
const SIZES: [usize; 2] = [128, 1024];

/// The operation each lane repeats.
#[derive(Clone, Copy)]
enum Step {
    /// Adds a fixed point to the accumulator.
    Add,
    /// Doubles the accumulator.
    Double,
}

/// Repeats a step `ROUNDS` times on each of `POINTS` accumulators, loaded with their addends.
struct Chain<'a, R>(Step, &'a [Coordinates], PhantomData<R>);

impl<S: Simd, R: Representation> Operation<S> for Chain<'_, R> {
    type Output = [Coordinates; POINTS];

    fn portable(self, simd: S) -> [Coordinates; POINTS] {
        let mut output = [IDENTITY; POINTS];
        simd.execute(
            #[inline(always)]
            |simd: S| {
                for start in (0..POINTS).step_by(R::Field::<S>::LANES) {
                    let mut sum = Point::<R::Field<S>>::load(simd, &self.1[start..], &IDENTITY);
                    let addend = Point::load(simd, &self.1[POINTS + start..], &IDENTITY);
                    match self.0 {
                        Step::Add => {
                            for _ in 0..ROUNDS {
                                sum = sum.add(simd, addend);
                            }
                        }
                        Step::Double => {
                            for _ in 0..ROUNDS {
                                sum = sum.double(simd);
                            }
                        }
                    }
                    sum.store(simd, &mut output[start..]);
                }
            },
        );
        output
    }
}

/// Sums points loaded from bytes into `POINTS` partial sums, converting each addend.
struct Sum<'a, R>(&'a [Coordinates], PhantomData<R>);

impl<S: Simd, R: Representation> Operation<S> for Sum<'_, R> {
    type Output = [Coordinates; POINTS];

    fn portable(self, simd: S) -> [Coordinates; POINTS] {
        let mut output = [IDENTITY; POINTS];
        simd.execute(
            #[inline(always)]
            |simd: S| {
                let rounds = self.0.len() / POINTS;
                for start in (0..POINTS).step_by(R::Field::<S>::LANES) {
                    let mut sum = Point::<R::Field<S>>::load(simd, &self.0[start..], &IDENTITY);
                    for round in 1..rounds {
                        let points = &self.0[round * POINTS + start..];
                        sum = sum.add(simd, Point::load(simd, points, &IDENTITY));
                    }
                    sum.store(simd, &mut output[start..]);
                }
            },
        );
        output
    }
}

fn bench_chain(c: &mut Criterion) {
    let mut group = c.benchmark_group(module_path!());
    let (coordinates, blst_points) = g2_points(2 * POINTS);
    group.throughput(Throughput::Elements((POINTS * ROUNDS) as u64));
    for (step, name) in [(Step::Add, "add"), (Step::Double, "double")] {
        chain_representation::<Radix28>(&mut group, step, name, &coordinates);
        chain_representation::<Radix49>(&mut group, step, name, &coordinates);
        chain_representation::<Residues>(&mut group, step, name, &coordinates);
        group.bench_function(format!("op={name} repr=blst"), |b| {
            b.iter(|| {
                let (sums, addends) = black_box(&blst_points).split_at(POINTS);
                let mut output = [blst::blst_p2::default(); POINTS];
                for ((output, sum), addend) in output.iter_mut().zip(sums).zip(addends) {
                    *output = *sum;
                    for _ in 0..ROUNDS {
                        // SAFETY: valid pointers to point structures; blst allows aliasing the
                        // output with an input.
                        unsafe {
                            match step {
                                Step::Add => blst::blst_p2_add_or_double(output, output, addend),
                                Step::Double => blst::blst_p2_double(output, output),
                            }
                        }
                    }
                }
                black_box(output)
            });
        });
    }
    group.finish();
}

fn chain_representation<R: Representation>(
    group: &mut BenchmarkGroup<'_, WallTime>,
    step: Step,
    name: &str,
    coordinates: &[Coordinates],
) {
    group.bench_function(format!("op={name} repr={}", R::NAME), |b| {
        b.iter(|| {
            black_box(dispatch(Chain::<R>(
                step,
                black_box(coordinates),
                PhantomData,
            )))
        });
    });
}

fn bench_sum(c: &mut Criterion) {
    let mut group = c.benchmark_group(module_path!());
    for n in SIZES {
        let (coordinates, blst_points) = g2_points(n);
        group.throughput(Throughput::Elements(n as u64));
        sum_representation::<Radix28>(&mut group, n, &coordinates);
        sum_representation::<Radix49>(&mut group, n, &coordinates);
        sum_representation::<Residues>(&mut group, n, &coordinates);
        group.bench_function(format!("op=sum repr=blst n={n}"), |b| {
            b.iter(|| {
                let mut sum = blst::blst_p2::default();
                for point in black_box(&blst_points) {
                    // SAFETY: valid pointers to point structures; blst allows aliasing the output
                    // with an input.
                    unsafe { blst::blst_p2_add_or_double(&mut sum, &sum, point) };
                }
                black_box(sum)
            });
        });
    }
    group.finish();
}

fn sum_representation<R: Representation>(
    group: &mut BenchmarkGroup<'_, WallTime>,
    n: usize,
    coordinates: &[Coordinates],
) {
    group.bench_function(format!("op=sum repr={} n={n}", R::NAME), |b| {
        b.iter(|| black_box(dispatch(Sum::<R>(black_box(coordinates), PhantomData))));
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(20);
    targets = bench_chain, bench_sum
}
