use commonware_cryptography::{Sha256, sha256};
use commonware_math::algebra::Random as _;
use commonware_storage::bmt::Builder;
use commonware_utils::test_rng;
use criterion::{Criterion, criterion_group};
use rand::seq::IndexedRandom;

const SAMPLE_SIZE: usize = 100;

/// Times multi-proof verification, with the proof generated in setup.
fn bench_verify_multi(c: &mut Criterion) {
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

        // Select SAMPLE_SIZE random elements without replacement in ascending
        // position order, prove them in setup, and verify the multi-proof
        c.bench_function(
            &format!("{}/n={} items={}", module_path!(), n, SAMPLE_SIZE),
            |b| {
                // Borrow the inputs so they are freed after timing stops
                b.iter_batched_ref(
                    || {
                        let mut samples: Vec<_> =
                            queries.sample(&mut sampler, SAMPLE_SIZE).cloned().collect();
                        samples.sort_unstable_by_key(|(pos, _)| *pos);
                        let positions: Vec<u32> = samples.iter().map(|(pos, _)| *pos).collect();
                        let proof = tree.multi_proof(&positions).unwrap();
                        let elements: Vec<_> =
                            samples.iter().map(|(pos, elem)| (*elem, *pos)).collect();
                        (elements, proof)
                    },
                    |(elements, proof)| {
                        assert!(
                            proof
                                .verify_multi_inclusion::<Sha256>(elements, &root)
                                .is_ok()
                        );
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
    targets = bench_verify_multi
}
