use commonware_utils::bitmap::BitMap;
use criterion::{criterion_group, Criterion};
use rand::{rngs::StdRng, Rng, SeedableRng};
use std::hint::black_box;

fn count_ones<const CHUNK_SIZE: usize>(c: &mut Criterion, size: u64) {
    let mut rng = StdRng::seed_from_u64(size);
    let mut bitmap = BitMap::<CHUNK_SIZE>::with_capacity(size);
    for _ in 0..size {
        bitmap.push(rng.gen::<bool>());
    }
    c.bench_function(
        &format!(
            "{}/fn=count_ones size={size} chunk_size={CHUNK_SIZE}",
            module_path!()
        ),
        |b| {
            b.iter(|| black_box(&bitmap).count_ones());
        },
    );
}

fn bench_count_ones(c: &mut Criterion) {
    for size in [64, 1 << 10, 1 << 14, 1 << 18, 1 << 22, 1 << 28] {
        count_ones::<4>(c, size);
        count_ones::<8>(c, size);
        count_ones::<16>(c, size);
        count_ones::<32>(c, size);
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_count_ones,
}
