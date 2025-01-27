use commonware_cryptography::{Hasher, Sha256};
use commonware_storage::mmr::mem::Mmr;
use criterion::{criterion_group, Criterion};
use rand::{rngs::StdRng, seq::SliceRandom, SeedableRng};

const SAMPLE_SIZE: usize = 100;

fn bench_prove_single_element(c: &mut Criterion) {
    for n in [10_000, 100_000, 1_000_000, 5_000_000, 10_000_000] {
        // Populate MMR
        let mut mmr = Mmr::<Sha256>::new();
        let mut elements = Vec::with_capacity(n);
        let mut sampler = StdRng::seed_from_u64(0);
        for _ in 0..n {
            let element = Sha256::random(&mut sampler);
            let pos = mmr.add(&element);
            elements.push((pos, element));
        }
        let root_hash = mmr.root_hash();

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
                        let mut hasher = Sha256::new();
                        for (pos, element) in samples {
                            let proof = mmr.proof(pos).unwrap();
                            assert!(proof.verify_element_inclusion(
                                &mut hasher,
                                &element,
                                pos,
                                &root_hash,
                            ));
                        }
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
