use bytes::Buf as _;
use commonware_runtime::{IoBuf, IoBufs};
use criterion::{BatchSize, Criterion};
use std::hint::black_box;

pub fn bench(c: &mut Criterion) {
    for chunks in [1, 4, 16, 256] {
        let source = IoBufs::from(vec![IoBuf::from(b"abcdefgh"); chunks]);
        c.bench_function(&format!("{}/chunks={chunks}", module_path!()), |b| {
            b.iter_batched(
                || source.clone(),
                |mut bufs| {
                    while bufs.has_remaining() {
                        let len = bufs.chunk().len();
                        black_box(bufs.split_to(len));
                    }
                },
                BatchSize::SmallInput,
            );
        });
    }
}
