use commonware_cryptography::lthash::LtHash;
use commonware_cryptography::{Blake3, Sha256};
use criterion::{black_box, BatchSize, Criterion};

pub fn bench_lthash_add(c: &mut Criterion) {
    let mut group = c.benchmark_group("lthash_add");

    // Benchmark with different data sizes
    for size in [32, 256, 1024, 4096] {
        group.bench_function(format!("blake3_{size}_bytes"), |b| {
            let data = vec![0u8; size];
            b.iter_batched(
                LtHash::<Blake3>::new,
                |mut lthash| {
                    lthash.add(black_box(&data));
                },
                BatchSize::SmallInput,
            );
        });

        group.bench_function(format!("sha256_{size}_bytes"), |b| {
            let data = vec![0u8; size];
            b.iter_batched(
                LtHash::<Sha256>::new,
                |mut lthash| {
                    lthash.add(black_box(&data));
                },
                BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

pub fn bench_lthash_subtract(c: &mut Criterion) {
    let mut group = c.benchmark_group("lthash_subtract");

    // Benchmark with different data sizes
    for size in [32, 256, 1024] {
        group.bench_function(format!("blake3_{size}_bytes"), |b| {
            let data = vec![0u8; size];
            b.iter_batched(
                || {
                    let mut lthash = LtHash::<Blake3>::new();
                    lthash.add(&data);
                    lthash
                },
                |mut lthash| {
                    lthash.subtract(black_box(&data));
                },
                BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

pub fn bench_lthash_combine(c: &mut Criterion) {
    let mut group = c.benchmark_group("lthash_combine");

    group.bench_function("blake3", |b| {
        b.iter_batched(
            || {
                let mut lthash1 = LtHash::<Blake3>::new();
                let mut lthash2 = LtHash::<Blake3>::new();
                lthash1.add(b"data1");
                lthash2.add(b"data2");
                (lthash1, lthash2)
            },
            |(mut lthash1, lthash2)| {
                lthash1.combine(black_box(&lthash2));
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

pub fn bench_lthash_finalize(c: &mut Criterion) {
    let mut group = c.benchmark_group("lthash_finalize");

    group.bench_function("blake3", |b| {
        let mut lthash = LtHash::<Blake3>::new();
        for i in 0..100u32 {
            lthash.add(&i.to_le_bytes());
        }
        b.iter(|| {
            black_box(lthash.finalize());
        });
    });

    group.bench_function("sha256", |b| {
        let mut lthash = LtHash::<Sha256>::new();
        for i in 0..100u32 {
            lthash.add(&i.to_le_bytes());
        }
        b.iter(|| {
            black_box(lthash.finalize());
        });
    });

    group.finish();
}

pub fn bench_lthash_operations_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("lthash_operations_comparison");

    // Compare incremental update vs full recomputation
    group.bench_function("incremental_update", |b| {
        let initial_data: Vec<Vec<u8>> = (0..100).map(|i: u32| i.to_le_bytes().to_vec()).collect();
        let update_data = b"update";

        b.iter_batched(
            || {
                let mut lthash = LtHash::<Blake3>::new();
                for data in &initial_data {
                    lthash.add(data);
                }
                lthash
            },
            |mut lthash| {
                lthash.add(black_box(update_data));
                black_box(lthash.finalize());
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("full_recomputation", |b| {
        let initial_data: Vec<Vec<u8>> = (0..100).map(|i: u32| i.to_le_bytes().to_vec()).collect();
        let update_data = b"update";

        b.iter(|| {
            let mut lthash = LtHash::<Blake3>::new();
            for data in &initial_data {
                lthash.add(data);
            }
            lthash.add(black_box(update_data));
            black_box(lthash.finalize());
        });
    });

    // Benchmark many small updates vs few large updates
    group.bench_function("many_small_updates", |b| {
        let small_data = vec![0u8; 32];
        b.iter_batched(
            LtHash::<Blake3>::new,
            |mut lthash| {
                for _ in 0..100 {
                    lthash.add(&small_data);
                }
                black_box(lthash.finalize());
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("few_large_updates", |b| {
        let large_data = vec![0u8; 3200];
        b.iter_batched(
            LtHash::<Blake3>::new,
            |mut lthash| {
                lthash.add(&large_data);
                black_box(lthash.finalize());
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}
