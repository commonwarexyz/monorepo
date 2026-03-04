use commonware_cryptography::{sha256, Sha256};
use commonware_math::algebra::Random as _;
use commonware_storage::mmr::{mem::DirtyMmr, StandardHasher};
use criterion::{criterion_group, Criterion};
use futures::executor::block_on;
use rand::{rngs::StdRng, SeedableRng};

#[cfg(not(full_bench))]
const N_LEAVES: [usize; 2] = [10_000, 100_000];
#[cfg(full_bench)]
const N_LEAVES: [usize; 5] = [10_000, 100_000, 1_000_000, 5_000_000, 10_000_000];

fn bench_append_additional(c: &mut Criterion) {
    for n in N_LEAVES {
        // Generate random elements
        let mut elements = Vec::with_capacity(n);
        let mut sampler = StdRng::seed_from_u64(0);
        for _ in 0..n {
            let element = sha256::Digest::random(&mut sampler);
            elements.push(element);
        }

        // Generate additional elements and append them to MMR
        for a in [100, 1_000, 10_000, 50_000] {
            let mut additional = Vec::with_capacity(a);
            for _ in 0..a {
                let element = sha256::Digest::random(&mut sampler);
                additional.push(element);
            }
            c.bench_function(&format!("{}/start={} add={}", module_path!(), n, a), |b| {
                b.iter_batched(
                    || {
                        let mut h = StandardHasher::<Sha256>::new();
                        let mut mmr = DirtyMmr::new();
                        block_on(async {
                            for digest in &elements {
                                mmr.add(&mut h, digest);
                            }
                        });
                        mmr.merkleize(&mut h, None)
                    },
                    |mmr| {
                        let mut h = StandardHasher::<Sha256>::new();
                        let mut mmr = mmr.into_dirty();
                        block_on(async {
                            for digest in &additional {
                                mmr.add(&mut h, digest);
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
