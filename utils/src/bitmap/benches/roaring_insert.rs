use commonware_utils::bitmap::roaring::Bitmap;
use criterion::{criterion_group, Criterion};
use roaring::RoaringTreemap;
use std::hint::black_box;

fn benchmark_insert(c: &mut Criterion) {
    let mut group = c.benchmark_group(module_path!());
    for count in [100, 1000, 10000] {
        group.bench_function(format!("count={count} impl=ours"), |b| {
            b.iter(|| {
                let mut bitmap = Bitmap::new();
                for i in 0..count {
                    bitmap.insert(i * 7);
                }
                black_box(bitmap)
            });
        });

        group.bench_function(format!("count={count} impl=roaring-rs"), |b| {
            b.iter(|| {
                let mut bitmap = RoaringTreemap::new();
                for i in 0..count {
                    bitmap.insert(i * 7);
                }
                black_box(bitmap)
            });
        });
    }
    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(50);
    targets = benchmark_insert,
}
