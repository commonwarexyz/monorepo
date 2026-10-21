use commonware_cryptography::{Hasher as _, Sha256};
use commonware_storage::bmt::Builder;
use criterion::{Criterion, criterion_group};
use std::hint::black_box;

/// Times single-leaf proof generation without verification.
fn bench_proof(c: &mut Criterion) {
    for n in [250, 1_000, 100_000] {
        // Populate Binary Merkle Tree
        let mut builder = Builder::<Sha256>::new(n);
        for i in 0..n {
            builder.add(&Sha256::hash(&[&i.to_le_bytes()]));
        }
        let tree = builder.build();

        // Prove one leaf away from the edges of the tree
        let position = (n / 3) as u32;
        c.bench_function(&format!("{}/n={}", module_path!(), n), |b| {
            b.iter(|| black_box(tree.proof(black_box(position)).unwrap()))
        });
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(30);
    targets = bench_proof
}
