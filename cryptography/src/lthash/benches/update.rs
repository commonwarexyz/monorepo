use commonware_cryptography::lthash::LtHash;
use criterion::{criterion_group, BatchSize, Criterion};

fn benchmark_update(c: &mut Criterion) {
    let initial_data: Vec<Vec<u8>> = (0..10_000u32).map(|i| i.to_le_bytes().to_vec()).collect();
    let update_data = b"update";

    // Benchmark incremental update
    c.bench_function(&format!("{}/incremental", module_path!()), |b| {
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
                lthash.checksum()
            },
            BatchSize::SmallInput,
        );
    });

    // Benchmark full recomputation
    c.bench_function(&format!("{}/full", module_path!()), |b| {
        b.iter(|| {
            let mut lthash = LtHash::new();
            for data in &initial_data {
                lthash.add(data);
            }
            lthash.add(update_data);
            lthash.checksum()
        });
    });
}

criterion_group!(benches, benchmark_update);
