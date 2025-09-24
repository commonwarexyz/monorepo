use criterion::{criterion_group, Criterion};

fn bench_transport(c: &mut Criterion) {
    let (mut send, mut recv) = super::connect().unwrap();
    for n in [1 << 12, 1 << 16, 1 << 20] {
        let data = vec![0; n];
        c.bench_function(&format!("{}/n={}", module_path!(), n), |b| {
            b.iter(|| recv.recv(&send.send(&data).unwrap()).unwrap())
        });
    }
}

criterion_group!(benches, bench_transport);
