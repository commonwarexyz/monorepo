use bytes::BytesMut;
use commonware_codec::{EncodeSize, Write};
use commonware_utils::bitmap::BitMap;
use criterion::{criterion_group, Criterion};
use std::hint::black_box;

fn bench_write<const CHUNK_SIZE: usize>(c: &mut Criterion, size: u64) {
    let bitmap = BitMap::<CHUNK_SIZE>::ones(size);
    let encoded_size = bitmap.encode_size();
    let mut buf = BytesMut::with_capacity(encoded_size);

    c.bench_function(
        &format!("{}/size={size} chunk_size={CHUNK_SIZE}", module_path!()),
        |b| {
            b.iter(|| {
                buf.clear();
                black_box(&bitmap).write(&mut buf);
                black_box(buf.len());
            });
        },
    );
}

fn benchmark_write(c: &mut Criterion) {
    for size in [64, 1 << 10, 1 << 14, 1 << 18, 1 << 22, 1 << 26] {
        bench_write::<4>(c, size);
        bench_write::<8>(c, size);
        bench_write::<16>(c, size);
        bench_write::<32>(c, size);
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = benchmark_write,
}
