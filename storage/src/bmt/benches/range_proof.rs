use commonware_cryptography::{Hasher as _, Sha256};
use commonware_storage::bmt::Builder;
use criterion::{Criterion, criterion_group};
use std::hint::black_box;

/// Number of leaves covered by each range proof.
const SAMPLE_SIZE: usize = 100;

/// Times range proof generation without verification.
fn bench_range_proof(c: &mut Criterion) {
    for n in [250, 1_000, 100_000] {
        // Populate Binary Merkle Tree
        let mut builder = Builder::<Sha256>::new(n);
        for i in 0..n {
            builder.add(&Sha256::hash(&[&i.to_le_bytes()]));
        }
        let tree = builder.build();

        // Prove a range away from the edges of the tree
        let start = (n / 3) as u32;
        let end = start + SAMPLE_SIZE as u32 - 1;
        c.bench_function(
            &format!("{}/n={} items={}", module_path!(), n, SAMPLE_SIZE),
            |b| b.iter(|| black_box(tree.range_proof(black_box(start), black_box(end)).unwrap())),
        );
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(30);
    targets = bench_range_proof
}
