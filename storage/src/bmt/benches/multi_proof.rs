use commonware_cryptography::{Hasher as _, Sha256};
use commonware_storage::bmt::Builder;
use commonware_utils::test_rng;
use criterion::{Criterion, criterion_group};
use rand::seq::index;
use std::hint::black_box;

/// Number of positions proven by each multi-proof.
const SAMPLE_SIZE: usize = 100;

/// Times multi-proof generation without verification.
fn bench_multi_proof(c: &mut Criterion) {
    for n in [250, 1_000, 100_000] {
        // Populate Binary Merkle Tree
        let mut builder = Builder::<Sha256>::new(n);
        for i in 0..n {
            builder.add(&Sha256::hash(&[&i.to_le_bytes()]));
        }
        let tree = builder.build();

        // Sample SAMPLE_SIZE distinct positions in ascending order
        let mut positions: Vec<u32> = index::sample(&mut test_rng(), n, SAMPLE_SIZE)
            .into_iter()
            .map(|position| position as u32)
            .collect();
        positions.sort_unstable();
        c.bench_function(
            &format!("{}/n={} items={}", module_path!(), n, SAMPLE_SIZE),
            |b| b.iter(|| black_box(tree.multi_proof(black_box(&positions)).unwrap())),
        );
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(30);
    targets = bench_multi_proof
}
