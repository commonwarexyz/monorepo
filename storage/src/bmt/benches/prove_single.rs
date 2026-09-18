use commonware_cryptography::{Sha256, sha256};
use commonware_math::algebra::Random as _;
use commonware_storage::bmt::Builder;
use commonware_utils::test_rng;
use criterion::{Criterion, criterion_group};
use rand::seq::IndexedRandom;

const SAMPLE_SIZE: usize = 100;

fn bench_prove_single(c: &mut Criterion) {
    for n in [250, 1_000, 5_000, 10_000, 25_000, 50_000, 100_000] {
        // Populate Binary Merkle Tree
        let mut builder = Builder::<Sha256>::new(n);
        let mut queries = Vec::with_capacity(n);
        let mut sampler = test_rng();
        for pos in 0..n {
            let element = sha256::Digest::random(&mut sampler);
            builder.add(&element);
            queries.push((pos as u32, element));
        }
        let tree = builder.build();
        let root = tree.root();

        // Select SAMPLE_SIZE random elements without replacement and create/verify proofs
        c.bench_function(
            &format!("{}/n={} items={}", module_path!(), n, SAMPLE_SIZE),
            |b| {
                b.iter_batched(
                    || {
                        queries
                            .sample(&mut sampler, SAMPLE_SIZE)
                            .cloned()
                            .collect::<Vec<_>>()
                    },
                    |samples| {
                        for (pos, element) in samples {
                            let proof = tree.proof(pos).unwrap();
                            assert!(
                                proof
                                    .verify_element_inclusion::<Sha256>(&element, pos, &root)
                                    .is_ok()
                            );
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
    targets = bench_prove_single
}
