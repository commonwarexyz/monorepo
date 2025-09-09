use commonware_cryptography::{sha256, Digest as _, Sha256};
use commonware_storage::mmr::{mem::Mmr, StandardHasher};
use criterion::{criterion_group, Criterion};
use futures::executor::block_on;
use rand::{rngs::StdRng, SeedableRng};

fn bench_append(c: &mut Criterion) {
    for n in [10_000, 100_000, 1_000_000, 5_000_000, 10_000_000] {
        // Generate random elements
        let mut elements = Vec::with_capacity(n);
        let mut sampler = StdRng::seed_from_u64(0);
        for _ in 0..n {
            let element = sha256::Digest::random(&mut sampler);
            elements.push(element);
        }

        // Append elements to MMR
        c.bench_function(&format!("{}/n={}", module_path!(), n), |b| {
            b.iter(|| {
                block_on(async {
                    let mut h = StandardHasher::new();
                    let mut mmr = Mmr::<Sha256>::new();
                    for digest in &elements {
                        mmr.add(&mut h, digest);
                    }
                })
            });
        });
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_append
}
