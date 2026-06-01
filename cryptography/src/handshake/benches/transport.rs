use criterion::{criterion_group, BatchSize, Criterion};
use std::hint::black_box;

fn bench_transport(c: &mut Criterion) {
    let (mut send, mut recv) = super::connect().unwrap();
    for n in [1 << 12, 1 << 16, 1 << 20, 1 << 22] {
        let data = vec![0; n];
        c.bench_function(&format!("{}/n={}", module_path!(), n), |b| {
            b.iter(|| recv.recv(&send.send(&data).unwrap()).unwrap())
        });
    }
}

fn bench_authenticated_transport(c: &mut Criterion) {
    let (mut send, mut recv) = super::connect().unwrap();
    for n in [1 << 12, 1 << 16, 1 << 20, 1 << 22] {
        let data = vec![0; n];
        c.bench_function(
            &format!("{}/n={} mode=authenticated", module_path!(), n),
            |b| {
                b.iter(|| {
                    let tag = send.authenticate(black_box(&data)).unwrap();
                    recv.verify(black_box(&data), black_box(&tag)).unwrap();
                })
            },
        );
    }
}

fn bench_receive_transport(c: &mut Criterion) {
    let n = 1 << 22;
    let data = vec![0; n];
    c.bench_function(&format!("{}/n={} mode=decrypt", module_path!(), n), |b| {
        b.iter_batched(
            || {
                let (mut send, recv) = super::connect().unwrap();
                let ciphertext = send.send(&data).unwrap();
                (recv, ciphertext)
            },
            |(mut recv, ciphertext)| recv.recv(&ciphertext).unwrap(),
            BatchSize::SmallInput,
        )
    });
    c.bench_function(&format!("{}/n={} mode=verify", module_path!(), n), |b| {
        b.iter_batched(
            || {
                let (mut send, recv) = super::connect().unwrap();
                let tag = send.authenticate(&data).unwrap();
                (recv, tag)
            },
            |(mut recv, tag)| recv.verify(black_box(&data), black_box(&tag)).unwrap(),
            BatchSize::SmallInput,
        )
    });
}

criterion_group!(
    benches,
    bench_transport,
    bench_authenticated_transport,
    bench_receive_transport
);
