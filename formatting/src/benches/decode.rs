//! Benchmark: `from_hex()` decoding.

use criterion::{criterion_group, Criterion};
use rand::{rngs::StdRng, RngCore, SeedableRng};
use std::hint::black_box;

fn bench_decode(c: &mut Criterion) {
    for size in [16usize, 32, 64, 256, 1024, 16 * 1024] {
        let mut rng = StdRng::seed_from_u64(size as u64);
        let mut buf = vec![0u8; size];
        rng.fill_bytes(&mut buf);
        let encoded = commonware_formatting::hex(&buf);

        c.bench_function(&format!("{}/size={size}", module_path!()), |b| {
            b.iter(|| black_box(commonware_formatting::from_hex(black_box(&encoded))));
        });
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(50);
    targets = bench_decode,
}
