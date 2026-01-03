use commonware_codec::Read as _;
use commonware_utils::bitmap::RoaringBitmap as OurBitmap;
use criterion::{criterion_group, BenchmarkId, Criterion, Throughput};
use rand::{rngs::StdRng, Rng, SeedableRng};
use roaring::RoaringBitmap as ExtBitmap;
use std::hint::black_box;

const SEED: u64 = 12345;

fn benchmark_insert_sequential(c: &mut Criterion) {
    let mut group = c.benchmark_group("roaring/insert_sequential");

    for count in [1_000, 10_000, 100_000] {
        group.throughput(Throughput::Elements(count as u64));

        group.bench_with_input(BenchmarkId::new("ours", count), &count, |b, &count| {
            b.iter(|| {
                let mut bitmap = OurBitmap::new();
                for i in 0..count {
                    bitmap.insert(i as u64);
                }
                black_box(bitmap)
            });
        });

        group.bench_with_input(BenchmarkId::new("roaring-rs", count), &count, |b, &count| {
            b.iter(|| {
                let mut bitmap = ExtBitmap::new();
                for i in 0..count {
                    bitmap.insert(i as u32);
                }
                black_box(bitmap)
            });
        });
    }
    group.finish();
}

fn benchmark_insert_random(c: &mut Criterion) {
    let mut group = c.benchmark_group("roaring/insert_random");

    for count in [1_000, 10_000, 100_000] {
        // Pre-generate random values
        let mut rng = StdRng::seed_from_u64(SEED);
        let values: Vec<u32> = (0..count).map(|_| rng.gen_range(0..1_000_000)).collect();

        group.throughput(Throughput::Elements(count as u64));

        group.bench_with_input(BenchmarkId::new("ours", count), &values, |b, values| {
            b.iter(|| {
                let mut bitmap = OurBitmap::new();
                for &v in values {
                    bitmap.insert(v as u64);
                }
                black_box(bitmap)
            });
        });

        group.bench_with_input(BenchmarkId::new("roaring-rs", count), &values, |b, values| {
            b.iter(|| {
                let mut bitmap = ExtBitmap::new();
                for &v in values {
                    bitmap.insert(v);
                }
                black_box(bitmap)
            });
        });
    }
    group.finish();
}

fn benchmark_insert_range(c: &mut Criterion) {
    let mut group = c.benchmark_group("roaring/insert_range");

    for count in [10_000u64, 100_000, 1_000_000] {
        group.throughput(Throughput::Elements(count));

        group.bench_with_input(BenchmarkId::new("ours", count), &count, |b, &count| {
            b.iter(|| {
                let mut bitmap = OurBitmap::new();
                bitmap.insert_range(0..count);
                black_box(bitmap)
            });
        });

        group.bench_with_input(BenchmarkId::new("roaring-rs", count), &count, |b, &count| {
            b.iter(|| {
                let mut bitmap = ExtBitmap::new();
                bitmap.insert_range(0..count as u32);
                black_box(bitmap)
            });
        });
    }
    group.finish();
}

fn benchmark_contains(c: &mut Criterion) {
    let mut group = c.benchmark_group("roaring/contains");

    for count in [10_000, 100_000] {
        // Build bitmaps with random values
        let mut rng = StdRng::seed_from_u64(SEED);
        let values: Vec<u32> = (0..count).map(|_| rng.gen_range(0..1_000_000)).collect();

        let mut our_bitmap = OurBitmap::new();
        let mut ext_bitmap = ExtBitmap::new();
        for &v in &values {
            our_bitmap.insert(v as u64);
            ext_bitmap.insert(v);
        }

        // Generate lookup values (mix of hits and misses)
        let lookups: Vec<u32> = (0..1000).map(|_| rng.gen_range(0..1_000_000)).collect();

        group.throughput(Throughput::Elements(1000));

        group.bench_with_input(
            BenchmarkId::new("ours", count),
            &(&our_bitmap, &lookups),
            |b, &(bitmap, lookups)| {
                b.iter(|| {
                    let mut found = 0u32;
                    for &v in lookups {
                        if bitmap.contains(v as u64) {
                            found += 1;
                        }
                    }
                    black_box(found)
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("roaring-rs", count),
            &(&ext_bitmap, &lookups),
            |b, &(bitmap, lookups)| {
                b.iter(|| {
                    let mut found = 0u32;
                    for &v in lookups {
                        if bitmap.contains(v) {
                            found += 1;
                        }
                    }
                    black_box(found)
                });
            },
        );
    }
    group.finish();
}

fn benchmark_iteration(c: &mut Criterion) {
    let mut group = c.benchmark_group("roaring/iteration");

    for count in [10_000u64, 100_000] {
        // Bitmap with contiguous range (uses run containers)
        let mut our_bitmap = OurBitmap::new();
        our_bitmap.insert_range(0..count);

        let mut ext_bitmap = ExtBitmap::new();
        ext_bitmap.insert_range(0..count as u32);

        group.throughput(Throughput::Elements(count));

        group.bench_with_input(
            BenchmarkId::new("ours", count),
            &our_bitmap,
            |b, bitmap: &OurBitmap| {
                b.iter(|| {
                    let sum: u64 = bitmap.iter().sum();
                    black_box(sum)
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("roaring-rs", count),
            &ext_bitmap,
            |b, bitmap: &ExtBitmap| {
                b.iter(|| {
                    let sum: u64 = bitmap.iter().map(|x| x as u64).sum();
                    black_box(sum)
                });
            },
        );
    }
    group.finish();
}

fn benchmark_union(c: &mut Criterion) {
    let mut group = c.benchmark_group("roaring/union");

    for count in [10_000, 100_000] {
        let mut rng = StdRng::seed_from_u64(SEED);

        // Create two bitmaps with overlapping values
        let values_a: Vec<u32> = (0..count).map(|_| rng.gen_range(0..500_000)).collect();
        let values_b: Vec<u32> = (0..count).map(|_| rng.gen_range(250_000..750_000)).collect();

        let mut our_a = OurBitmap::new();
        let mut our_b = OurBitmap::new();
        let mut ext_a = ExtBitmap::new();
        let mut ext_b = ExtBitmap::new();

        for &v in &values_a {
            our_a.insert(v as u64);
            ext_a.insert(v);
        }
        for &v in &values_b {
            our_b.insert(v as u64);
            ext_b.insert(v);
        }

        group.bench_with_input(
            BenchmarkId::new("ours", count),
            &(&our_a, &our_b),
            |b, &(a, b_map)| {
                b.iter(|| {
                    let result = a.union(b_map);
                    black_box(result)
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("roaring-rs", count),
            &(&ext_a, &ext_b),
            |b, &(a, b_map)| {
                b.iter(|| {
                    let result = a | b_map;
                    black_box(result)
                });
            },
        );
    }
    group.finish();
}

fn benchmark_intersection(c: &mut Criterion) {
    let mut group = c.benchmark_group("roaring/intersection");

    for count in [10_000, 100_000] {
        let mut rng = StdRng::seed_from_u64(SEED);

        let values_a: Vec<u32> = (0..count).map(|_| rng.gen_range(0..500_000)).collect();
        let values_b: Vec<u32> = (0..count).map(|_| rng.gen_range(250_000..750_000)).collect();

        let mut our_a = OurBitmap::new();
        let mut our_b = OurBitmap::new();
        let mut ext_a = ExtBitmap::new();
        let mut ext_b = ExtBitmap::new();

        for &v in &values_a {
            our_a.insert(v as u64);
            ext_a.insert(v);
        }
        for &v in &values_b {
            our_b.insert(v as u64);
            ext_b.insert(v);
        }

        group.bench_with_input(
            BenchmarkId::new("ours", count),
            &(&our_a, &our_b),
            |b, &(a, b_map)| {
                b.iter(|| {
                    let result = a.intersection(b_map);
                    black_box(result)
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("roaring-rs", count),
            &(&ext_a, &ext_b),
            |b, &(a, b_map)| {
                b.iter(|| {
                    let result = a & b_map;
                    black_box(result)
                });
            },
        );
    }
    group.finish();
}

fn benchmark_serialization(c: &mut Criterion) {
    use commonware_codec::{Encode, EncodeSize};

    let mut group = c.benchmark_group("roaring/serialize");

    for count in [10_000u64, 100_000, 1_000_000] {
        // Contiguous range (benefits from run containers)
        let mut our_bitmap = OurBitmap::new();
        our_bitmap.insert_range(0..count);

        let mut ext_bitmap = ExtBitmap::new();
        ext_bitmap.insert_range(0..count as u32);

        group.bench_with_input(
            BenchmarkId::new("ours", count),
            &our_bitmap,
            |b, bitmap: &OurBitmap| {
                b.iter(|| {
                    let encoded = bitmap.encode();
                    black_box(encoded)
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("roaring-rs", count),
            &ext_bitmap,
            |b, bitmap: &ExtBitmap| {
                b.iter(|| {
                    let mut buf = Vec::with_capacity(bitmap.serialized_size());
                    bitmap.serialize_into(&mut buf).unwrap();
                    black_box(buf)
                });
            },
        );

        // Report sizes
        let our_size = our_bitmap.encode_size();
        let ext_size = ext_bitmap.serialized_size();
        println!(
            "Serialized size for {} elements: ours={} bytes, roaring-rs={} bytes",
            count, our_size, ext_size
        );
    }
    group.finish();
}

fn benchmark_deserialization(c: &mut Criterion) {
    use commonware_codec::Encode;

    let mut group = c.benchmark_group("roaring/deserialize");

    for count in [10_000u64, 100_000] {
        let mut our_bitmap = OurBitmap::new();
        our_bitmap.insert_range(0..count);
        let our_encoded = our_bitmap.encode();

        let mut ext_bitmap = ExtBitmap::new();
        ext_bitmap.insert_range(0..count as u32);
        let mut ext_encoded = Vec::new();
        ext_bitmap.serialize_into(&mut ext_encoded).unwrap();

        group.bench_with_input(
            BenchmarkId::new("ours", count),
            &our_encoded,
            |b, encoded: &bytes::BytesMut| {
                b.iter(|| {
                    let decoded = OurBitmap::read_cfg(&mut encoded.clone(), &1000).unwrap();
                    black_box(decoded)
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("roaring-rs", count),
            &ext_encoded,
            |b, encoded: &Vec<u8>| {
                b.iter(|| {
                    let decoded = ExtBitmap::deserialize_from(encoded.as_slice()).unwrap();
                    black_box(decoded)
                });
            },
        );
    }
    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(50);
    targets =
        benchmark_insert_sequential,
        benchmark_insert_random,
        benchmark_insert_range,
        benchmark_contains,
        benchmark_iteration,
        benchmark_union,
        benchmark_intersection,
        benchmark_serialization,
        benchmark_deserialization,
}
