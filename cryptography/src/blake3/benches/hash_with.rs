use commonware_cryptography::{Hasher, blake3::Blake3};
use commonware_parallel::Rayon;
use commonware_utils::{NZUsize, test_rng};
use criterion::{Criterion, criterion_group};
use rand::Rng;
use std::hint::black_box;

fn bench_hash_with(c: &mut Criterion) {
    let mut sampler = test_rng();
    let mut group = c.benchmark_group(module_path!());
    group.sample_size(20);
    for len in [262_144, 1_048_576, 4_194_304, 16_777_216] {
        let mut message = vec![0u8; len];
        sampler.fill_bytes(&mut message);
        for threads in [1, 2, 4, 8, 16] {
            let strategy = Rayon::new(NZUsize!(threads)).unwrap();
            group.bench_function(format!("len={len} threads={threads}"), |b| {
                b.iter(|| Blake3::hash_with(&strategy, &[black_box(&message)]))
            });
        }
    }
    group.finish();
}

criterion_group!(benches, bench_hash_with);
