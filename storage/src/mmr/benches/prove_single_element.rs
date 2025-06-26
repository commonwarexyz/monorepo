use commonware_cryptography::{sha256, Digest as _, Sha256};
use commonware_storage::mmr::{hasher::Standard, mem::Mmr};
use criterion::{criterion_group, Criterion};
use futures::executor::block_on;
use rand::{rngs::StdRng, seq::SliceRandom, SeedableRng};

const SAMPLE_SIZE: usize = 100;

fn bench_prove_single_element(c: &mut Criterion) {
    for n in [10_000, 100_000, 1_000_000, 5_000_000, 10_000_000] {
        // Populate MMR
        let mut mmr = Mmr::<Sha256>::new();
        let mut elements = Vec::with_capacity(n);
        let mut sampler = StdRng::seed_from_u64(0);
        let mut hasher = Standard::new();
        block_on(async {
            for _ in 0..n {
                let element = sha256::Digest::random(&mut sampler);
                let pos = mmr.add(&mut hasher, &element);
                elements.push((pos, element));
            }
        });
        let root_digest = mmr.root(&mut hasher);

        // Select SAMPLE_SIZE random elements without replacement and create/verify proofs
        c.bench_function(
            &format!("{}/n={} samples={}", module_path!(), n, SAMPLE_SIZE),
            |b| {
                b.iter_batched(
                    || {
                        let samples = elements
                            .choose_multiple(&mut sampler, SAMPLE_SIZE)
                            .cloned()
                            .collect::<Vec<_>>();
                        samples
                    },
                    |samples| {
                        block_on(async {
                            let mut hasher = Standard::<Sha256>::new();
                            for (pos, element) in samples {
                                let proof = mmr.proof(pos).await.unwrap();
                                assert!(proof
                                    .verify_element_inclusion(
                                        &mut hasher,
                                        &element,
                                        pos,
                                        &root_digest,
                                    )
                                    .unwrap());
                            }
                        });
                    },
                    criterion::BatchSize::SmallInput,
                )
            },
        );
    }
}
criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_prove_single_element
}
