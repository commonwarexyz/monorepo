use commonware_utils::bitmap::roaring::container::Bitmap;
use criterion::{criterion_group, Criterion};
use std::hint::black_box;

fn benchmark_bitmap_or(c: &mut Criterion) {
    let count: u16 = 10000;
    let mut bitmap_a = Bitmap::new();
    let mut bitmap_b = Bitmap::new();
    for i in 0..count {
        bitmap_a.insert(i * 2);
        bitmap_b.insert(i * 3);
    }

    c.bench_function(&format!("{}/count={count}", module_path!()), |b| {
        b.iter(|| black_box(Bitmap::or_new(&bitmap_a, &bitmap_b)));
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(50);
    targets = benchmark_bitmap_or,
}
