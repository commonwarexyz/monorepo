use commonware_utils::{bitmap::BitMap, TestRng};
use criterion::{criterion_group, Criterion};
use rand::RngExt as _;
use std::hint::black_box;

fn bench_count_ones<const CHUNK_SIZE: usize>(c: &mut Criterion, size: u64) {
    let mut rng = TestRng::new(size);
    let mut bitmap = BitMap::<CHUNK_SIZE>::with_capacity(size);
    for _ in 0..size {
        bitmap.push(rng.random::<bool>());
    }
    c.bench_function(
        &format!("{}/size={size} chunk_size={CHUNK_SIZE}", module_path!()),
        |b| {
            b.iter(|| black_box(&bitmap).count_ones());
        },
    );
}

fn benchmark_count_ones(c: &mut Criterion) {
    for size in [64, 1 << 10, 1 << 14, 1 << 18, 1 << 22, 1 << 28] {
        bench_count_ones::<4>(c, size);
        bench_count_ones::<8>(c, size);
        bench_count_ones::<16>(c, size);
        bench_count_ones::<32>(c, size);
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = benchmark_count_ones,
}
