use bytes::BytesMut;
use commonware_codec::{EncodeSize, Write};
use commonware_utils::bitmap::roaring::Bitmap;
use criterion::{criterion_group, Criterion};
use std::hint::black_box;

fn alternating_bitmap(containers: u64) -> Bitmap {
    let mut bitmap = Bitmap::new();
    for key in 0..containers {
        let base = key << 16;
        for i in 0..5000 {
            bitmap.insert(base + i * 2);
        }
    }
    bitmap
}

fn benchmark_write(c: &mut Criterion) {
    let mut group = c.benchmark_group(module_path!());
    for containers in [1, 16, 64] {
        let bitmap = alternating_bitmap(containers);
        let encoded_size = bitmap.encode_size();
        let mut buf = BytesMut::with_capacity(encoded_size);

        group.bench_function(format!("containers={containers} shape=bitmap"), |b| {
            b.iter(|| {
                buf.clear();
                black_box(&bitmap).write(&mut buf);
                black_box(buf.len());
            });
        });
    }
    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(50);
    targets = benchmark_write,
}
