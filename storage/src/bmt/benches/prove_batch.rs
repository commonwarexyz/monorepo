use commonware_cryptography::{sha256, Digest as _, Sha256};
use commonware_storage::bmt::Builder;
use criterion::{criterion_group, Criterion};
use rand::{rngs::StdRng, SeedableRng};

fn bench_prove_batch(c: &mut Criterion) {
    for n in [100, 250, 1_000, 5_000, 10_000, 25_000, 50_000, 100_000] {
        // Populate Binary Merkle Tree
        let mut builder = Builder::<Sha256>::new(n);
        let mut sampler = StdRng::seed_from_u64(0);
        for _ in 0..n {
            let element = sha256::Digest::random(&mut sampler);
            builder.add(&element);
        }
        let tree = builder.build();

        // Benchmark batch proof generation
        c.bench_function(&format!("{}/n={}", module_path!(), n), |b| {
            b.iter(|| {
                let proofs = tree.proofs();
                assert_eq!(proofs.len(), n);
            })
        });
    }
}

fn bench_prove_batch_vs_individual(c: &mut Criterion) {
    for n in [100, 250, 1_000] {
        // Populate Binary Merkle Tree
        let mut builder = Builder::<Sha256>::new(n);
        let mut sampler = StdRng::seed_from_u64(0);
        for _ in 0..n {
            let element = sha256::Digest::random(&mut sampler);
            builder.add(&element);
        }
        let tree = builder.build();

        // Benchmark batch proof generation
        c.bench_function(&format!("{}/batch/n={}", module_path!(), n), |b| {
            b.iter(|| tree.proofs())
        });

        // Benchmark individual proof generation (for comparison)
        c.bench_function(&format!("{}/individual/n={}", module_path!(), n), |b| {
            b.iter(|| {
                let mut proofs = Vec::with_capacity(n);
                for i in 0..n {
                    proofs.push(tree.proof(i as u32).unwrap());
                }
                proofs
            })
        });
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_prove_batch, bench_prove_batch_vs_individual
}
