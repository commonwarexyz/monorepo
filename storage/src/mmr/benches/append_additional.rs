use commonware_cryptography::{Hasher, Sha256};
use commonware_storage::mmr::{hasher::Standard, mem::Mmr};
use criterion::{criterion_group, Criterion};
use futures::executor::block_on;
use rand::{rngs::StdRng, SeedableRng};

fn bench_append_additional(c: &mut Criterion) {
    for n in [10_000, 100_000, 1_000_000, 5_000_000, 10_000_000] {
        // Generate random elements
        let mut elements = Vec::with_capacity(n);
        let mut sampler = StdRng::seed_from_u64(0);
        for _ in 0..n {
            let element = Sha256::random(&mut sampler);
            elements.push(element);
        }

        // Generate additional elements and append them to MMR
        for a in [100, 1_000, 10_000, 50_000] {
            let mut additional = Vec::with_capacity(a);
            for _ in 0..a {
                let element = Sha256::random(&mut sampler);
                additional.push(element);
            }
            c.bench_function(&format!("{}/start={} add={}", module_path!(), n, a), |b| {
                b.iter_batched(
                    || {
                        let mut h = Sha256::new();
                        let mut h = Standard::new(&mut h);
                        let mut mmr = Mmr::<Sha256>::new();
                        block_on(async {
                            for digest in &elements {
                                mmr.add(&mut h, digest).await.unwrap();
                            }
                        });
                        mmr
                    },
                    |mut mmr| {
                        let mut h = Sha256::new();
                        let mut h = Standard::new(&mut h);
                        block_on(async {
                            for digest in &additional {
                                mmr.add(&mut h, digest).await.unwrap();
                            }
                        });
                    },
                    criterion::BatchSize::SmallInput,
                )
            });
        }
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_append_additional
}
