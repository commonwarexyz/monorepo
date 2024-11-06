use commonware_cryptography::bls12381::{dkg, primitives};
use commonware_utils::quorum;
use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use std::hint::black_box;

fn benchmark_partial_signature_aggregation(c: &mut Criterion) {
    let namespace = b"benchmark";
    let msg = b"hello";
    for &n in &[5, 10, 20, 50, 100, 250, 500] {
        let t = quorum(n).unwrap();
        c.bench_function(&format!("n={} t={}", n, t), |b| {
            b.iter_batched(
                || {
                    let (_, shares) = dkg::ops::generate_shares(None, n, t);
                    shares
                        .iter()
                        .map(|s| primitives::ops::partial_sign(s, namespace, msg))
                        .collect::<Vec<_>>()
                },
                |partials| {
                    black_box(primitives::ops::partial_aggregate(t, partials).unwrap());
                },
                BatchSize::SmallInput,
            );
        });
    }
}

criterion_group!(benches, benchmark_partial_signature_aggregation);
criterion_main!(benches);
