use criterion::{criterion_group, Criterion};

fn bench_connect(c: &mut Criterion) {
    c.bench_function(module_path!(), |b| b.iter(|| super::connect().unwrap()));
}

criterion_group!(benches, bench_connect);
