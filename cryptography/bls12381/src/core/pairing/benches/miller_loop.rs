//! Independent Miller loops, one pair per lane, compared with blst.

use super::utils::{
    POINTS, Radix28, Radix49, Representation, Residues, blst_miller_loop, encodings, pairs,
};
use commonware_cryptography_bls12381::core::{
    field::{arithmetic::Field, fp12::BYTES},
    pairing::{G1Affine, G2Affine, Pair, miller_loop},
};
use commonware_simd::{Operation, Simd, dispatch};
use criterion::{BenchmarkGroup, Criterion, Throughput, criterion_group, measurement::WallTime};
use std::{hint::black_box, marker::PhantomData, slice};

/// Runs the Miller loop of each of the first POINTS pairs.
struct MillerLoops<'a, R>(&'a [(G1Affine, G2Affine)], PhantomData<R>);

impl<S: Simd, R: Representation> Operation<S> for MillerLoops<'_, R> {
    type Output = [[u8; BYTES]; POINTS];

    fn portable(self, simd: S) -> [[u8; BYTES]; POINTS] {
        let mut output = [[0; BYTES]; POINTS];
        simd.execute(|simd: S| {
            for start in (0..POINTS).step_by(R::Field::<S>::LANES) {
                let pair = Pair::<R::Field<S>>::load(simd, &self.0[start..], &self.0[0]);
                miller_loop(simd, &[pair]).store(simd, &mut output[start..]);
            }
        });
        output
    }
}

fn representation<R: Representation>(
    group: &mut BenchmarkGroup<'_, WallTime>,
    pairs: &[(G1Affine, G2Affine)],
) {
    group.bench_function(format!("repr={}", R::NAME), |b| {
        b.iter(|| black_box(dispatch(MillerLoops::<R>(black_box(pairs), PhantomData))));
    });
}

fn bench_miller_loop(c: &mut Criterion) {
    let mut group = c.benchmark_group(module_path!());
    let pairs = pairs(POINTS);
    let encoded = encodings(&pairs);
    group.throughput(Throughput::Elements(POINTS as u64));
    representation::<Radix28>(&mut group, &encoded);
    representation::<Radix49>(&mut group, &encoded);
    representation::<Residues>(&mut group, &encoded);
    group.bench_function("repr=blst", |b| {
        b.iter(|| {
            let mut output = [blst::blst_fp12::default(); POINTS];
            for (output, (_, pair)) in output.iter_mut().zip(black_box(&pairs)) {
                *output = blst_miller_loop(slice::from_ref(pair));
            }
            black_box(output)
        });
    });
    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_miller_loop
}
