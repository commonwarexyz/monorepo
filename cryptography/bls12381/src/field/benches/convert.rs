//! Throughput of converting elements into and out of lanes.

use super::utils::{Field, Radix28, Radix49, Representation, elements};
use commonware_cryptography_bls12381::field::fp::BYTES;
use commonware_simd::{Operation, Simd, dispatch};
use criterion::{BenchmarkGroup, Criterion, Throughput, criterion_group, measurement::WallTime};
use std::{hint::black_box, marker::PhantomData};

/// Elements converted per iteration.
const COUNT: usize = 1024;

/// Loads every element into lanes and stores it back.
struct RoundTrip<'a, R>(&'a [[u8; BYTES]], PhantomData<R>);

impl<S: Simd, R: Representation> Operation<S> for RoundTrip<'_, R> {
    type Output = Vec<[u8; BYTES]>;

    fn portable(self, simd: S) -> Vec<[u8; BYTES]> {
        let mut output = vec![[0; BYTES]; self.0.len()];
        simd.execute(
            #[inline(always)]
            |simd: S| {
                for start in (0..self.0.len()).step_by(R::Field::<S>::LANES) {
                    R::Field::<S>::load(simd, &self.0[start..], &[0; BYTES])
                        .store(simd, &mut output[start..]);
                }
            },
        );
        output
    }
}

fn bench_convert(c: &mut Criterion) {
    let mut group = c.benchmark_group(module_path!());
    let inputs = elements(COUNT);
    group.throughput(Throughput::Elements(COUNT as u64));
    bench_representation::<Radix28>(&mut group, &inputs);
    bench_representation::<Radix49>(&mut group, &inputs);
    group.finish();
}

fn bench_representation<R: Representation>(
    group: &mut BenchmarkGroup<'_, WallTime>,
    inputs: &[[u8; BYTES]],
) {
    group.bench_function(format!("repr={}", R::NAME), |b| {
        b.iter(|| black_box(dispatch(RoundTrip::<R>(black_box(inputs), PhantomData))));
    });
}

criterion_group!(benches, bench_convert);
