//! Throughput of lane multiplications.

use super::utils::{Field, LANES, ONE, Radix28, Radix49, Representation, elements};
use commonware_cryptography_bls12381::field::fp::BYTES;
use commonware_simd::{Operation, Simd, dispatch};
use criterion::{BenchmarkGroup, Criterion, Throughput, criterion_group, measurement::WallTime};
use std::{hint::black_box, marker::PhantomData};

/// Independent multiplication chains per lane, so consecutive products can overlap.
const CHAINS: usize = 4;

/// Multiplications in each chain.
const ROUNDS: usize = 64;

/// Multiplies each of `CHAINS` accumulators by a factor `ROUNDS` times, per lane.
struct Chains<'a, R>(&'a [[u8; BYTES]], PhantomData<R>);

impl<S: Simd, R: Representation> Operation<S> for Chains<'_, R> {
    type Output = [[u8; BYTES]; LANES];

    fn portable(self, simd: S) -> [[u8; BYTES]; LANES] {
        let mut output = [[0; BYTES]; LANES];
        simd.execute(
            #[inline(always)]
            |simd: S| {
                for start in (0..LANES).step_by(S::U64_LANES) {
                    let factor = R::Field::<S>::load(simd, &self.0[start..], &ONE);
                    let mut chains = [factor; CHAINS];
                    for (i, chain) in chains.iter_mut().enumerate() {
                        *chain = R::Field::load(simd, &self.0[LANES * (i + 1) + start..], &ONE);
                    }
                    for _ in 0..ROUNDS {
                        for chain in &mut chains {
                            *chain = chain.mul(simd, factor);
                        }
                    }
                    let mut sum = chains[0];
                    for chain in &chains[1..] {
                        sum = sum.add(simd, *chain);
                    }
                    sum.store(simd, &mut output[start..]);
                }
            },
        );
        output
    }
}

fn bench_mul(c: &mut Criterion) {
    let mut group = c.benchmark_group(module_path!());
    let inputs = elements(LANES * (CHAINS + 1));
    group.throughput(Throughput::Elements((LANES * CHAINS * ROUNDS) as u64));
    bench_representation::<Radix28>(&mut group, &inputs);
    bench_representation::<Radix49>(&mut group, &inputs);
    group.finish();
}

fn bench_representation<R: Representation>(
    group: &mut BenchmarkGroup<'_, WallTime>,
    inputs: &[[u8; BYTES]],
) {
    group.bench_function(format!("repr={}", R::NAME), |b| {
        b.iter(|| black_box(dispatch(Chains::<R>(black_box(inputs), PhantomData))));
    });
}

criterion_group!(benches, bench_mul);
