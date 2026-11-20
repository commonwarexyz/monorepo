use commonware_codec::{Encode, FixedSize, ReadExt};
use commonware_cryptography::bls12381::primitives::{
    group::{G1, Scalar},
    subgroup::batch_in_g1,
};
use commonware_math::algebra::{CryptoGroup, Random};
use commonware_parallel::{Rayon, Sequential};
use commonware_utils::test_rng;
use criterion::{Criterion, criterion_group};
use rayon::prelude::*;
use std::{hint::black_box, num::NonZeroUsize, thread::available_parallelism};

/// Compare end-to-end deserialization of many G1 points: per-point checked
/// decoding against unchecked decoding followed by one batched subgroup check.
///
/// `decode_only` and `in_g1_only` split the per-point cost into its two parts,
/// bounding what batching the subgroup check alone can gain.
fn bench_deserialize(c: &mut Criterion) {
    let threads = available_parallelism().unwrap_or(NonZeroUsize::new(1).unwrap());
    let rayon = Rayon::new(threads).unwrap();
    for n in [100usize, 1000, 6000, 100_000] {
        let mut rng = test_rng();
        let points: Vec<G1> = (0..n)
            .map(|_| G1::generator() * &Scalar::random(&mut rng))
            .collect();
        let bytes: Vec<u8> = points.iter().flat_map(|p| p.encode()).collect();

        let name = |method: &str| format!("{}/method={method} n={n}", module_path!());

        c.bench_function(&name("decode_only"), |b| {
            b.iter(|| {
                let decoded: Vec<G1> = bytes
                    .chunks_exact(G1::SIZE)
                    .map(|mut chunk| G1::read_unchecked(&mut chunk).unwrap())
                    .collect();
                black_box(decoded)
            });
        });

        c.bench_function(&name("in_g1_only"), |b| {
            b.iter(|| black_box(points.iter().all(G1::in_subgroup)));
        });

        c.bench_function(&name("per_point_serial"), |b| {
            b.iter(|| {
                let decoded: Vec<G1> = bytes
                    .chunks_exact(G1::SIZE)
                    .map(|mut chunk| G1::read(&mut chunk).unwrap())
                    .collect();
                black_box(decoded)
            });
        });

        c.bench_function(&name("batch_serial"), |b| {
            b.iter(|| {
                let decoded: Vec<G1> = bytes
                    .chunks_exact(G1::SIZE)
                    .map(|mut chunk| G1::read_unchecked(&mut chunk).unwrap())
                    .collect();
                assert!(batch_in_g1(&decoded, 128, &Sequential, &mut test_rng()));
                black_box(decoded)
            });
        });

        c.bench_function(&name("per_point_parallel"), |b| {
            b.iter(|| {
                let decoded: Vec<G1> = bytes
                    .par_chunks_exact(G1::SIZE)
                    .map(|mut chunk| G1::read(&mut chunk).unwrap())
                    .collect();
                black_box(decoded)
            });
        });

        c.bench_function(&name("batch_parallel"), |b| {
            b.iter(|| {
                let decoded: Vec<G1> = bytes
                    .par_chunks_exact(G1::SIZE)
                    .map(|mut chunk| G1::read_unchecked(&mut chunk).unwrap())
                    .collect();
                assert!(batch_in_g1(&decoded, 128, &rayon, &mut test_rng()));
                black_box(decoded)
            });
        });
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_deserialize
}
