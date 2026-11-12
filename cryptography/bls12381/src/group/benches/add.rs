//! Adding two elements.
//!
//! One addition uses one lane, so this measures latency; [`sum`](super::sum) measures the
//! throughput of additions.

use super::utils::{Curve, scalars};
use commonware_cryptography_bls12381::{G1, G2};
use criterion::{Criterion, Throughput, criterion_group};
use std::hint::black_box;

fn bench<C: Curve>(c: &mut Criterion) {
    let mut group = c.benchmark_group(module_path!());
    let scalars = scalars(2, 3);
    let (a, b) = (C::generator() * &scalars[0], C::generator() * &scalars[1]);
    group.throughput(Throughput::Elements(1));
    group.bench_function(format!("curve={} n=1", C::NAME), |bencher| {
        bencher.iter(|| black_box(black_box(a) + black_box(&b)))
    });
    group.finish();
}

fn bench_add(c: &mut Criterion) {
    bench::<G1>(c);
    bench::<G2>(c);
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_add
}
