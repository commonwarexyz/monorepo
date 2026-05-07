use commonware_utils::bitmap::roaring::Bitmap;
use criterion::{criterion_group, Criterion};
use roaring::RoaringTreemap;
use std::hint::black_box;

fn benchmark_iteration(c: &mut Criterion) {
    let mut group = c.benchmark_group(module_path!());
    for count in [1000, 10000, 100000] {
        let mut ours = Bitmap::new();
        let mut theirs = RoaringTreemap::new();
        for i in 0..count {
            ours.insert(i * 7);
            theirs.insert(i * 7);
        }

        group.bench_function(format!("count={count} impl=ours"), |b| {
            b.iter(|| black_box(ours.iter().count()));
        });

        group.bench_function(format!("count={count} impl=roaring-rs"), |b| {
            b.iter(|| black_box(theirs.iter().count()));
        });
    }
    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(50);
    targets = benchmark_iteration,
}
