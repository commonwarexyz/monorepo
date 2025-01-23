use commonware_cryptography::{Digest, Hasher, Sha256};
use commonware_storage::mmr::mem::Mmr;
use criterion::{criterion_group, Criterion};
use rand::{rngs::StdRng, RngCore, SeedableRng};

fn bench_build(c: &mut Criterion) {
    for n in [10_000, 100_000, 1_000_000, 5_000_000, 10_000_000] {
        c.bench_function(&format!("{}/n={}", module_path!(), n), |b| {
            b.iter_batched(
                || {
                    let mut elements = Vec::with_capacity(n);
                    let mut sampler = StdRng::seed_from_u64(0);
                    for _ in 0..n {
                        let mut digest = vec![0u8; Sha256::len()];
                        sampler.fill_bytes(&mut digest);
                        let element = Digest::from(digest);
                        elements.push(element);
                    }
                    elements
                },
                |digests| {
                    let mut mmr = Mmr::<Sha256>::new();
                    for digest in digests {
                        mmr.add(&digest);
                    }
                },
                criterion::BatchSize::SmallInput,
            )
        });
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_build
}
