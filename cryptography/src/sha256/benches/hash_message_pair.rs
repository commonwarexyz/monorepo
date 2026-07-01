use commonware_cryptography::{Hasher, Sha256};
use commonware_parallel::{Rayon, Strategy};
use criterion::{criterion_group, Criterion};
use rand::{rngs::StdRng, RngCore, SeedableRng};
use std::{hint::black_box, num::NonZeroUsize};

const SIZES: [usize; 5] = [64, 72, 256, 1024, 32768];

fn messages(size: usize, sampler: &mut StdRng) -> (Vec<u8>, Vec<u8>) {
    let mut left = vec![0u8; size];
    let mut right = vec![0u8; size];
    sampler.fill_bytes(&mut left);
    sampler.fill_bytes(&mut right);
    (left, right)
}

fn bench_hash_pair(c: &mut Criterion) {
    let mut sampler = StdRng::seed_from_u64(0);
    let strategy = Rayon::new(NonZeroUsize::new(2).unwrap()).unwrap();
    let hasher = Sha256::new();

    for size in SIZES {
        let (left, right) = messages(size, &mut sampler);
        let left = left.as_slice();
        let right = right.as_slice();

        c.bench_function(
            &format!("{}/size={size} mode=serial", module_path!()),
            |b| {
                b.iter(|| {
                    let left = Sha256::hash(black_box(left));
                    let right = Sha256::hash(black_box(right));
                    black_box((left, right));
                });
            },
        );

        c.bench_function(
            &format!("{}/size={size} mode=hash_pair", module_path!()),
            |b| {
                b.iter(|| {
                    black_box(hasher.hash_pair(black_box(left), black_box(right)));
                });
            },
        );

        c.bench_function(
            &format!("{}/size={size} mode=parallel_threads", module_path!()),
            |b| {
                b.iter(|| {
                    let digests =
                        strategy.map_collect_vec([black_box(left), black_box(right)], Sha256::hash);
                    black_box(digests);
                });
            },
        );
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_hash_pair
}
