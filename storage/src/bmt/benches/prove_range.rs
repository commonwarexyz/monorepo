use commonware_cryptography::{Hasher, Sha256, sha256};
use commonware_math::algebra::Random as _;
use commonware_storage::bmt::Builder;
use commonware_utils::test_rng;
use criterion::{Criterion, criterion_group};
use rand::RngExt as _;

const SAMPLE_SIZE: usize = 100;

fn bench_prove_range(c: &mut Criterion) {
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

        // Prove range of proofs for random starting positions
        c.bench_function(
            &format!("{}/n={} items={}", module_path!(), n, SAMPLE_SIZE),
            |b| {
                b.iter_batched(
                    || {
                        let start = sampler.random_range(0..(n - SAMPLE_SIZE));
                        let end = start + SAMPLE_SIZE;
                        (
                            start,
                            end,
                            tree.range_proof(start as u32, end as u32).unwrap(),
                        )
                    },
                    |(start, end, proof)| {
                        let mut hasher = Sha256::new();
                        let range_leaves = &elements[start..=end];
                        assert!(
                            proof
                                .verify_range_inclusion(
                                    &mut hasher,
                                    start as u32,
                                    range_leaves,
                                    &root
                                )
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
    targets = bench_prove_range
}
