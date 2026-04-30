use commonware_utils::bitmap::roaring::{union, Bitmap};
use criterion::{criterion_group, Criterion};
use roaring::RoaringTreemap;
use std::hint::black_box;

fn benchmark_union(c: &mut Criterion) {
    let mut group = c.benchmark_group(module_path!());
    for count in [1000, 10000] {
        let mut ours_a = Bitmap::new();
        let mut ours_b = Bitmap::new();
        let mut theirs_a = RoaringTreemap::new();
        let mut theirs_b = RoaringTreemap::new();

        for i in 0..count {
            ours_a.insert(i * 2);
            ours_b.insert(i * 3);
            theirs_a.insert(i * 2);
            theirs_b.insert(i * 3);
        }

        group.bench_function(format!("count={count} impl=ours"), |b| {
            b.iter(|| black_box(union(&ours_a, &ours_b, u64::MAX)));
        });

        group.bench_function(format!("count={count} impl=roaring-rs"), |b| {
            b.iter(|| black_box(&theirs_a | &theirs_b));
        });
    }
    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(50);
    targets = benchmark_union,
}
