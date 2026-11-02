//! Independent final exponentiations, one element per lane, compared with blst.

use super::utils::{
    POINTS, Radix28, Radix49, Representation, Residues, blst_final_exponentiation,
    blst_miller_loop, from_blst, pairs,
};
use commonware_cryptography_bls12381::core::{
    field::{
        arithmetic::Field,
        fp12::{BYTES, Fp12, ONE},
    },
    pairing::final_exponentiation,
};
use commonware_simd::{Operation, Simd, dispatch};
use criterion::{BenchmarkGroup, Criterion, Throughput, criterion_group, measurement::WallTime};
use std::{hint::black_box, marker::PhantomData, slice};

/// Runs the final exponentiation of each of POINTS elements.
struct FinalExponentiations<'a, R>(&'a [[u8; BYTES]], PhantomData<R>);

impl<S: Simd, R: Representation> Operation<S> for FinalExponentiations<'_, R> {
    type Output = [[u8; BYTES]; POINTS];

    fn portable(self, simd: S) -> [[u8; BYTES]; POINTS] {
        let mut output = [[0; BYTES]; POINTS];
        simd.execute(|simd: S| {
            for start in (0..POINTS).step_by(R::Field::<S>::LANES) {
                let f = Fp12::<R::Field<S>>::load(simd, &self.0[start..], &ONE);
                final_exponentiation(simd, f).store(simd, &mut output[start..]);
            }
        });
        output
    }
}

fn representation<R: Representation>(
    group: &mut BenchmarkGroup<'_, WallTime>,
    elements: &[[u8; BYTES]],
) {
    group.bench_function(format!("repr={}", R::NAME), |b| {
        b.iter(|| {
            black_box(dispatch(FinalExponentiations::<R>(
                black_box(elements),
                PhantomData,
            )))
        });
    });
}

fn bench_final_exponentiation(c: &mut Criterion) {
    let mut group = c.benchmark_group(module_path!());
    // Miller loop outputs, as a pairing exponentiates.
    let miller: Vec<_> = pairs(POINTS)
        .iter()
        .map(|(_, pair)| blst_miller_loop(slice::from_ref(pair)))
        .collect();
    let elements: Vec<_> = miller.iter().map(from_blst).collect();
    group.throughput(Throughput::Elements(POINTS as u64));
    representation::<Radix28>(&mut group, &elements);
    representation::<Radix49>(&mut group, &elements);
    representation::<Residues>(&mut group, &elements);
    group.bench_function("repr=blst", |b| {
        b.iter(|| {
            let mut output = [blst::blst_fp12::default(); POINTS];
            for (output, f) in output.iter_mut().zip(black_box(&miller)) {
                *output = blst_final_exponentiation(f);
            }
            black_box(output)
        });
    });
    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_final_exponentiation
}
