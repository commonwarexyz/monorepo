use commonware_cryptography::lthash::LtHash;
use criterion::{criterion_group, BatchSize, Criterion};

fn benchmark_incremental_vs_full(c: &mut Criterion) {
    let initial_data: Vec<Vec<u8>> = (0..100u32)
        .map(|i| i.to_le_bytes().to_vec())
        .collect();
    let update_data = b"update";

    // Benchmark incremental update
    c.bench_function(&format!("{}/incremental_update", module_path!()), |b| {
        b.iter_batched(
            || {
                let mut lthash = LtHash::new();
                for data in &initial_data {
                    lthash.add(data);
                }
                lthash
            },
            |mut lthash| {
                lthash.add(update_data);
                lthash.finalize()
            },
            BatchSize::SmallInput,
        );
    });

    // Benchmark full recomputation
    c.bench_function(&format!("{}/full_recomputation", module_path!()), |b| {
        b.iter(|| {
            let mut lthash = LtHash::new();
            for data in &initial_data {
                lthash.add(data);
            }
            lthash.add(update_data);
            lthash.finalize()
        });
    });

    // Benchmark many small updates vs few large updates
    c.bench_function(&format!("{}/many_small_updates", module_path!()), |b| {
        let small_data = vec![0u8; 32];
        b.iter_batched(
            LtHash::new,
            |mut lthash| {
                for _ in 0..100 {
                    lthash.add(&small_data);
                }
                lthash.finalize()
            },
            BatchSize::SmallInput,
        );
    });

    c.bench_function(&format!("{}/few_large_updates", module_path!()), |b| {
        let large_data = vec![0u8; 3200];
        b.iter_batched(
            LtHash::new,
            |mut lthash| {
                lthash.add(&large_data);
                lthash.finalize()
            },
            BatchSize::SmallInput,
        );
    });
}

criterion_group!(benches, benchmark_incremental_vs_full);