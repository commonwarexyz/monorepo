use commonware_cryptography::{sha256, Digest as _, Hasher, Sha256};
use commonware_storage::bmt::Builder;
use criterion::{criterion_group, Criterion};
use rand::{rngs::StdRng, Rng, SeedableRng};

const SAMPLE_SIZE: usize = 100;

fn bench_prove_range(c: &mut Criterion) {
    for n in [100, 1_000, 5_000, 10_000, 25_000, 50_000, 100_000] {
        for range_size in [10, 50, 100, 500] {
            // Skip if range size is larger than tree size
            if range_size > n {
                continue;
            }

            // Populate Binary Merkle Tree
            let mut builder = Builder::<Sha256>::new(n);
            let mut elements = Vec::with_capacity(n);
            let mut sampler = StdRng::seed_from_u64(0);
            for _ in 0..n {
                let element = sha256::Digest::random(&mut sampler);
                builder.add(&element);
                elements.push(element);
            }
            let tree = builder.build();
            let root = tree.root();

            // Benchmark range proof generation and verification
            c.bench_function(
                &format!(
                    "{}/n={} range_size={} samples={}",
                    module_path!(),
                    n,
                    range_size,
                    SAMPLE_SIZE
                ),
                |b| {
                    b.iter_batched(
                        || {
                            // Generate random starting positions for range proofs
                            let mut positions = Vec::with_capacity(SAMPLE_SIZE);
                            for _ in 0..SAMPLE_SIZE {
                                let start = sampler.gen_range(0..=(n - range_size));
                                positions.push(start);
                            }
                            positions
                        },
                        |positions| {
                            let mut hasher = Sha256::new();
                            for start in positions {
                                // Generate range proof
                                let proof =
                                    tree.range_proof(start as u32, range_size as u32).unwrap();

                                // Verify range proof
                                let range_leaves = &elements[start..start + range_size];
                                assert!(proof
                                    .verify(&mut hasher, start as u32, range_leaves, &root)
                                    .is_ok());
                            }
                        },
                        criterion::BatchSize::SmallInput,
                    )
                },
            );
        }
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_prove_range
}
