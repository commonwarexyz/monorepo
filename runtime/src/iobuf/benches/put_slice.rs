use bytes::BufMut as _;
use commonware_runtime::{IoBufMut, IoBufsMut};
use criterion::{BatchSize, Criterion};
use std::hint::black_box;

pub fn bench(c: &mut Criterion) {
    let data = vec![7; 4096];
    for chunks in [1, 4, 16, 256] {
        c.bench_function(
            &format!("{}/chunks={chunks} size=4096", module_path!()),
            |b| {
                b.iter_batched(
                    || {
                        IoBufsMut::from(
                            (0..chunks)
                                .map(|_| IoBufMut::with_capacity(data.len() / chunks))
                                .collect::<Vec<_>>(),
                        )
                    },
                    |mut bufs| {
                        bufs.put_slice(black_box(&data));
                        bufs
                    },
                    BatchSize::SmallInput,
                );
            },
        );
    }
}
