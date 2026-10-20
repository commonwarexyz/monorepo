use commonware_cryptography::{Hasher as _, Sha256};
use commonware_storage::bmt::Builder;
use commonware_utils::test_rng;
use criterion::{Criterion, criterion_group};
use rand::seq::index;
use std::hint::black_box;

/// Number of positions proven by each multi-proof.
const MULTI_POSITIONS: usize = 100;

/// Times proof generation alone, without verification.
fn bench_generate_proof(c: &mut Criterion) {
    for n in [250, 1_000, 100_000] {
        // Populate Binary Merkle Tree
        let mut builder = Builder::<Sha256>::new(n);
        for i in 0..n {
            builder.add(&Sha256::hash(&[&i.to_le_bytes()]));
        }
        let tree = builder.build();

        // Distinct positions in random order
        let positions: Vec<u32> = index::sample(&mut test_rng(), n, MULTI_POSITIONS)
            .into_iter()
            .map(|position| position as u32)
            .collect();
        let single = (n / 3) as u32;
        let (start, end) = ((n / 3) as u32, (n / 2) as u32);

        c.bench_function(&format!("{}/kind=single n={}", module_path!(), n), |b| {
            b.iter(|| black_box(tree.proof(black_box(single)).unwrap()))
        });
        c.bench_function(&format!("{}/kind=multi n={}", module_path!(), n), |b| {
            b.iter(|| black_box(tree.multi_proof(black_box(&positions)).unwrap()))
        });
        c.bench_function(&format!("{}/kind=range n={}", module_path!(), n), |b| {
            b.iter(|| black_box(tree.range_proof(black_box(start), black_box(end)).unwrap()))
        });
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(30);
    targets = bench_generate_proof
}
