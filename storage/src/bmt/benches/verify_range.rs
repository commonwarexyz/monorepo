use commonware_cryptography::{Sha256, sha256};
use commonware_math::algebra::Random as _;
use commonware_storage::bmt::Builder;
use commonware_utils::test_rng;
use criterion::{Criterion, criterion_group};
use rand::RngExt as _;

const SAMPLE_SIZE: usize = 100;

/// Times range proof verification, with the proof generated in setup.
fn bench_verify_range(c: &mut Criterion) {
    for n in [250, 1_000, 5_000, 10_000, 25_000, 50_000, 100_000] {
        // Populate Binary Merkle Tree
        let mut builder = Builder::<Sha256>::new(n);
        let mut elements = Vec::with_capacity(n);
        let mut sampler = test_rng();
        for _ in 0..n {
            let element = sha256::Digest::random(&mut sampler);
            builder.add(&element);
            elements.push(element);
        }
        let tree = builder.build();
        let root = tree.root();

        // Prove a range at a random start in setup and verify it
        c.bench_function(
            &format!("{}/n={} items={}", module_path!(), n, SAMPLE_SIZE),
            |b| {
                // Borrow the inputs so the proof is freed after timing stops
                b.iter_batched_ref(
                    || {
                        let start = sampler.random_range(0..=(n - SAMPLE_SIZE));
                        let end = start + SAMPLE_SIZE - 1;
                        (
                            start as u32,
                            &elements[start..=end],
                            tree.range_proof(start as u32, end as u32).unwrap(),
                        )
                    },
                    |(start, leaves, proof)| {
                        assert!(
                            proof
                                .verify_range_inclusion::<Sha256>(*start, leaves, &root)
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
    targets = bench_verify_range
}
