use commonware_cryptography::bls12381::{dkg, primitives};
use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use std::hint::black_box;

fn benchmark_signature_aggregation(c: &mut Criterion) {
    let msg = b"hello";
    for &n in &[5, 10, 20, 50, 100, 250, 500] {
        let t = dkg::utils::threshold(n).unwrap();
        c.bench_function(&format!("n={} t={}", n, t), |b| {
            b.iter_batched(
                || {
                    let (_, shares) = dkg::ops::generate_shares(None, n, t);
                    shares
                        .iter()
                        .map(|s| primitives::ops::partial_sign(s, &msg[..]))
                        .collect::<Vec<_>>()
                },
                |partials| {
                    black_box(primitives::ops::aggregate(t, partials).unwrap());
                },
                BatchSize::SmallInput,
            );
        });
    }
}

criterion_group!(benches, benchmark_signature_aggregation);
criterion_main!(benches);
