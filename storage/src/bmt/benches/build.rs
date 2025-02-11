use commonware_cryptography::{Hasher, Sha256};
use commonware_storage::bmt::Builder;
use criterion::{criterion_group, Criterion};
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
            b.iter(|| {
                let mut builder = Builder::<Sha256>::new(elements.len());
                for element in &elements {
                    builder.add(element);
                }
                builder.build();
            })
        });
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_new
}
