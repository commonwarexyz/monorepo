use commonware_utils::bitmap::roaring::{difference, intersection, union, Bitmap, RoaringBitmap};
use criterion::{criterion_group, BenchmarkId, Criterion};
use roaring::RoaringTreemap;

fn benchmark_insert(c: &mut Criterion) {
    let mut group = c.benchmark_group("roaring/insert");

    for count in [100, 1000, 10000] {
        group.bench_with_input(BenchmarkId::new("ours", count), &count, |b, &count| {
            b.iter(|| {
                let mut bitmap = RoaringBitmap::new();
                for i in 0..count {
                    bitmap.insert(i * 7);
                }
                bitmap
            });
        });

        group.bench_with_input(
            BenchmarkId::new("roaring-rs", count),
            &count,
            |b, &count| {
                b.iter(|| {
                    let mut bitmap = RoaringTreemap::new();
                    for i in 0..count {
                        bitmap.insert(i * 7);
                    }
                    bitmap
                });
            },
        );
    }

    group.finish();
}

fn benchmark_insert_range(c: &mut Criterion) {
    let mut group = c.benchmark_group("roaring/insert_range");

    for count in [1000, 10000, 100000] {
        group.bench_with_input(BenchmarkId::new("ours", count), &count, |b, &count| {
            b.iter(|| {
                let mut bitmap = RoaringBitmap::new();
                bitmap.insert_range(0, count);
                bitmap
            });
        });

        group.bench_with_input(
            BenchmarkId::new("roaring-rs", count),
            &count,
            |b, &count| {
                b.iter(|| {
                    let mut bitmap = RoaringTreemap::new();
                    bitmap.insert_range(0..count);
                    bitmap
                });
            },
        );
    }

    group.finish();
}

fn benchmark_contains(c: &mut Criterion) {
    let mut group = c.benchmark_group("roaring/contains");

    for count in [1000, 10000, 100000] {
        let mut ours = RoaringBitmap::new();
        let mut theirs = RoaringTreemap::new();
        for i in 0..count {
            ours.insert(i * 3);
            theirs.insert(i * 3);
        }

        group.bench_with_input(BenchmarkId::new("ours", count), &count, |b, &count| {
            b.iter(|| {
                let mut found = 0u64;
                for i in 0..count {
                    if ours.contains(i * 3) {
                        found += 1;
                    }
                }
                found
            });
        });

        group.bench_with_input(
            BenchmarkId::new("roaring-rs", count),
            &count,
            |b, &count| {
                b.iter(|| {
                    let mut found = 0u64;
                    for i in 0..count {
                        if theirs.contains(i * 3) {
                            found += 1;
                        }
                    }
                    found
                });
            },
        );
    }

    group.finish();
}

fn benchmark_union(c: &mut Criterion) {
    let mut group = c.benchmark_group("roaring/union");

    for count in [1000, 10000] {
        let mut ours_a = RoaringBitmap::new();
        let mut ours_b = RoaringBitmap::new();
        let mut theirs_a = RoaringTreemap::new();
        let mut theirs_b = RoaringTreemap::new();

        for i in 0..count {
            ours_a.insert(i * 2);
            ours_b.insert(i * 3);
            theirs_a.insert(i * 2);
            theirs_b.insert(i * 3);
        }

        group.bench_with_input(BenchmarkId::new("ours", count), &count, |b, _| {
            b.iter(|| union(&ours_a, &ours_b, u64::MAX));
        });

        group.bench_with_input(BenchmarkId::new("roaring-rs", count), &count, |b, _| {
            b.iter(|| &theirs_a | &theirs_b);
        });
    }

    group.finish();
}

fn benchmark_bitmap_or(c: &mut Criterion) {
    let mut group = c.benchmark_group("roaring/bitmap_or");

    let mut bitmap_a = Bitmap::new();
    let mut bitmap_b = Bitmap::new();

    for i in 0u16..10000 {
        bitmap_a.insert(i * 2);
        bitmap_b.insert(i * 3);
    }

    group.bench_function("ours", |b| {
        b.iter(|| Bitmap::or_new(&bitmap_a, &bitmap_b));
    });

    group.finish();
}

fn benchmark_intersection(c: &mut Criterion) {
    let mut group = c.benchmark_group("roaring/intersection");

    for count in [1000, 10000] {
        let mut ours_a = RoaringBitmap::new();
        let mut ours_b = RoaringBitmap::new();
        let mut theirs_a = RoaringTreemap::new();
        let mut theirs_b = RoaringTreemap::new();

        for i in 0..count {
            ours_a.insert(i * 2);
            ours_b.insert(i * 3);
            theirs_a.insert(i * 2);
            theirs_b.insert(i * 3);
        }

        group.bench_with_input(BenchmarkId::new("ours", count), &count, |b, _| {
            b.iter(|| intersection(&ours_a, &ours_b, u64::MAX));
        });

        group.bench_with_input(BenchmarkId::new("roaring-rs", count), &count, |b, _| {
            b.iter(|| &theirs_a & &theirs_b);
        });
    }

    group.finish();
}

fn benchmark_difference(c: &mut Criterion) {
    let mut group = c.benchmark_group("roaring/difference");

    for count in [1000, 10000] {
        let mut ours_a = RoaringBitmap::new();
        let mut ours_b = RoaringBitmap::new();
        let mut theirs_a = RoaringTreemap::new();
        let mut theirs_b = RoaringTreemap::new();

        for i in 0..count {
            ours_a.insert(i * 2);
            ours_b.insert(i * 3);
            theirs_a.insert(i * 2);
            theirs_b.insert(i * 3);
        }

        group.bench_with_input(BenchmarkId::new("ours", count), &count, |b, _| {
            b.iter(|| difference(&ours_a, &ours_b, u64::MAX));
        });

        group.bench_with_input(BenchmarkId::new("roaring-rs", count), &count, |b, _| {
            b.iter(|| &theirs_a - &theirs_b);
        });
    }

    group.finish();
}

fn benchmark_iteration(c: &mut Criterion) {
    let mut group = c.benchmark_group("roaring/iteration");

    for count in [1000, 10000, 100000] {
        let mut ours = RoaringBitmap::new();
        let mut theirs = RoaringTreemap::new();
        for i in 0..count {
            ours.insert(i * 7);
            theirs.insert(i * 7);
        }

        group.bench_with_input(BenchmarkId::new("ours", count), &count, |b, _| {
            b.iter(|| ours.iter().count());
        });

        group.bench_with_input(BenchmarkId::new("roaring-rs", count), &count, |b, _| {
            b.iter(|| theirs.iter().count());
        });
    }

    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(50);
    targets =
        benchmark_insert,
        benchmark_insert_range,
        benchmark_contains,
        benchmark_union,
        benchmark_bitmap_or,
        benchmark_intersection,
        benchmark_difference,
        benchmark_iteration,
}
