use commonware_cryptography::{sha256, Digest as _, Sha256};
use commonware_storage::mmr::{mem::Mmr, StandardHasher};
use criterion::{criterion_group, Criterion};
use futures::executor::block_on;
use rand::{rngs::StdRng, seq::SliceRandom, SeedableRng};

const SAMPLE_SIZE: usize = 100;

#[cfg(test)]
const N_LEAVES: [usize; 2] = [10_000, 100_000];
#[cfg(not(test))]
const N_LEAVES: [usize; 5] = [10_000, 100_000, 1_000_000, 5_000_000, 10_000_000];

fn bench_prove_single_element(c: &mut Criterion) {
    for n in N_LEAVES {
        // Populate MMR
        let mut mmr = Mmr::<Sha256>::new();
        let mut elements = Vec::with_capacity(n);
        let mut sampler = StdRng::seed_from_u64(0);
        let mut hasher = StandardHasher::new();
        block_on(async {
            for _ in 0..n {
                let element = sha256::Digest::random(&mut sampler);
                let pos = mmr.add(&mut hasher, &element);
                elements.push((pos, element));
            }
        });
        let root = mmr.root(&mut hasher);

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
                            let mut hasher = StandardHasher::<Sha256>::new();
                            for (pos, element) in samples {
                                let proof = mmr.proof(pos).unwrap();
                                assert!(proof.verify_element_inclusion(
                                    &mut hasher,
                                    &element,
                                    pos,
                                    &root,
                                ));
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
