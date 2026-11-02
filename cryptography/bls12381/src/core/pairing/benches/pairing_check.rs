//! Pairing-product checks, a multi-Miller loop followed by one final exponentiation, compared with
//! blst.
//!
//! A batch of POINTS independent checks gives each lane one check, whose pairs share their
//! squarings. A single check spreads its pairs across the lanes, multiplies the lanes, and
//! exponentiates once.

use super::utils::{
    NEUTRAL, POINTS, Radix28, Radix49, Representation, Residues, blst_final_exponentiation,
    blst_miller_loop, encodings, pairs,
};
use commonware_cryptography_bls12381::core::{
    field::{arithmetic::Field, fp12::BYTES},
    pairing::{G1Affine, G2Affine, Pair, final_exponentiation, miller_loop},
};
use commonware_simd::{Operation, Simd, dispatch};
use criterion::{BenchmarkGroup, Criterion, Throughput, criterion_group, measurement::WallTime};
use std::{hint::black_box, marker::PhantomData};

/// Pairs per check in a batch of independent checks.
const BATCH_SIZES: [usize; 2] = [2, 8];

/// Pairs in a single check.
const SINGLE_SIZES: [usize; 3] = [2, 16, 128];

/// Runs POINTS independent checks of n pairs each, held consecutively, one check per lane.
struct Batch<'a, R>(&'a [(G1Affine, G2Affine)], usize, PhantomData<R>);

impl<S: Simd, R: Representation> Operation<S> for Batch<'_, R> {
    type Output = [[u8; BYTES]; POINTS];

    fn portable(self, simd: S) -> [[u8; BYTES]; POINTS] {
        let Self(pairs, n, _) = self;
        let mut output = [[0; BYTES]; POINTS];
        simd.execute(|simd: S| {
            let lanes = R::Field::<S>::LANES;
            let mut slot = vec![pairs[0]; lanes];
            let mut prepared = Vec::with_capacity(n);
            for start in (0..POINTS).step_by(lanes) {
                prepared.clear();
                for k in 0..n {
                    for (lane, pair) in slot.iter_mut().enumerate() {
                        *pair = pairs[(start + lane) * n + k];
                    }
                    prepared.push(Pair::<R::Field<S>>::load(simd, &slot, &pairs[0]));
                }
                let f = miller_loop(simd, &prepared);
                final_exponentiation(simd, f).store(simd, &mut output[start..]);
            }
        });
        output
    }
}

/// Runs one check of all the pairs, spread across the lanes.
struct Single<'a, R>(&'a [(G1Affine, G2Affine)], PhantomData<R>);

impl<S: Simd, R: Representation> Operation<S> for Single<'_, R> {
    type Output = [u8; BYTES];

    fn portable(self, simd: S) -> [u8; BYTES] {
        let mut output = [[0; BYTES]; 1];
        simd.execute(|simd: S| {
            let fill = (NEUTRAL, self.0[0].1);
            let prepared: Vec<_> = self
                .0
                .chunks(R::Field::<S>::LANES)
                .map(|slot| Pair::<R::Field<S>>::load(simd, slot, &fill))
                .collect();
            let f = miller_loop(simd, &prepared).product_of_lanes(simd);
            final_exponentiation(simd, f).store(simd, &mut output);
        });
        output[0]
    }
}

fn batch<R: Representation>(
    group: &mut BenchmarkGroup<'_, WallTime>,
    pairs: &[(G1Affine, G2Affine)],
    n: usize,
) {
    group.bench_function(format!("repr={} batch={POINTS} n={n}", R::NAME), |b| {
        b.iter(|| black_box(dispatch(Batch::<R>(black_box(pairs), n, PhantomData))));
    });
}

fn single<R: Representation>(
    group: &mut BenchmarkGroup<'_, WallTime>,
    pairs: &[(G1Affine, G2Affine)],
) {
    group.bench_function(format!("repr={} batch=1 n={}", R::NAME, pairs.len()), |b| {
        b.iter(|| black_box(dispatch(Single::<R>(black_box(pairs), PhantomData))));
    });
}

fn bench_pairing_check(c: &mut Criterion) {
    let mut group = c.benchmark_group(module_path!());
    for n in BATCH_SIZES {
        let pairs = pairs(POINTS * n);
        let encoded = encodings(&pairs);
        let blst_pairs: Vec<_> = pairs.iter().map(|(_, pair)| *pair).collect();
        group.throughput(Throughput::Elements(POINTS as u64));
        batch::<Radix28>(&mut group, &encoded, n);
        batch::<Radix49>(&mut group, &encoded, n);
        batch::<Residues>(&mut group, &encoded, n);
        group.bench_function(format!("repr=blst batch={POINTS} n={n}"), |b| {
            b.iter(|| {
                let mut output = [blst::blst_fp12::default(); POINTS];
                for (output, check) in output.iter_mut().zip(black_box(&blst_pairs).chunks(n)) {
                    *output = blst_final_exponentiation(&blst_miller_loop(check));
                }
                black_box(output)
            });
        });
    }
    for n in SINGLE_SIZES {
        let pairs = pairs(n);
        let encoded = encodings(&pairs);
        let blst_pairs: Vec<_> = pairs.iter().map(|(_, pair)| *pair).collect();
        group.throughput(Throughput::Elements(1));
        single::<Radix28>(&mut group, &encoded);
        single::<Radix49>(&mut group, &encoded);
        single::<Residues>(&mut group, &encoded);
        group.bench_function(format!("repr=blst batch=1 n={n}"), |b| {
            b.iter(|| {
                let f = blst_miller_loop(black_box(&blst_pairs));
                black_box(blst_final_exponentiation(&f))
            });
        });
    }
    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_pairing_check
}
