use commonware_cryptography::{Hasher, Sha256};
use commonware_storage::binary::Tree;
use criterion::{black_box, criterion_group, Criterion};
use rand::{rngs::StdRng, SeedableRng};

fn bench_new(c: &mut Criterion) {
    for n in [100, 1_000, 5_000, 10_000, 25_000, 50_000, 100_000] {
        // Generate random elements
        let mut elements = Vec::with_capacity(n);
        let mut sampler = StdRng::seed_from_u64(0);
        for _ in 0..n {
            let element = Sha256::random(&mut sampler);
            elements.push(element);
        }

        // Generate Binary Merkle Tree
        c.bench_function(&format!("{}/n={}", module_path!(), n), |b| {
            b.iter_batched(
                || elements.clone(),
                |elements| {
                    let mut hasher = Sha256::new();
                    black_box(Tree::<Sha256>::new(&mut hasher, elements));
                },
                criterion::BatchSize::SmallInput,
            )
        });
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_new
}
