use commonware_cryptography::{Digest, Sha256};
use commonware_storage::mmr::mem::Mmr;
use criterion::{criterion_group, Criterion};
use rand::{rngs::StdRng, Rng, SeedableRng};

fn bench_build_additional(c: &mut Criterion) {
    for n in [10_000, 100_000, 1_000_000, 5_000_000, 10_000_000] {
        for a in [100, 1_000, 10_000, 50_000] {
            c.bench_function(&format!("{}/base={} new={}", module_path!(), n, a), |b| {
                b.iter_batched(
                    || {
                        let mut mmr = Mmr::<Sha256>::new();
                        let mut sampler = StdRng::seed_from_u64(0);
                        for _ in 0..n {
                            let digest: [u8; 32] = sampler.gen();
                            let element = Digest::from(digest.to_vec());
                            mmr.add(&element);
                        }
                        let mut additional = Vec::with_capacity(a);
                        for _ in 0..a {
                            let digest: [u8; 32] = sampler.gen();
                            let element = Digest::from(digest.to_vec());
                            additional.push(element);
                        }
                        (mmr, additional)
                    },
                    |(mut mmr, additional)| {
                        for digest in additional {
                            mmr.add(&digest);
                        }
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
    targets = bench_build_additional
}
