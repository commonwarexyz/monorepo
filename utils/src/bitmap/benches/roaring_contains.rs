use commonware_utils::bitmap::roaring::Bitmap;
use criterion::{criterion_group, Criterion};
use roaring::RoaringTreemap;
use std::hint::black_box;

fn benchmark_contains(c: &mut Criterion) {
    let mut group = c.benchmark_group(module_path!());
    for count in [1000, 10000, 100000] {
        let mut ours = Bitmap::new();
        let mut theirs = RoaringTreemap::new();
        for i in 0..count {
            ours.insert(i * 3);
            theirs.insert(i * 3);
        }

        group.bench_function(format!("count={count} impl=ours"), |b| {
            b.iter(|| {
                let mut found = 0u64;
                for i in 0..count {
                    if ours.contains(i * 3) {
                        found += 1;
                    }
                }
                black_box(found)
            });
        });

        group.bench_function(format!("count={count} impl=roaring-rs"), |b| {
            b.iter(|| {
                let mut found = 0u64;
                for i in 0..count {
                    if theirs.contains(i * 3) {
                        found += 1;
                    }
                }
                black_box(found)
            });
        });
    }
    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(50);
    targets = benchmark_contains,
}
