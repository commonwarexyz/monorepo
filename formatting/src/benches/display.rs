//! Benchmark: `Hex` newtype's `Display` impl (stack-allocated, no `String`).

use commonware_formatting::Hex;
use criterion::{criterion_group, Criterion};
use rand::{rngs::StdRng, RngCore, SeedableRng};
use std::{fmt::Write as _, hint::black_box};

fn bench_display(c: &mut Criterion) {
    for size in [16usize, 32, 64, 256, 1024, 16 * 1024] {
        let mut rng = StdRng::seed_from_u64(size as u64);
        let mut buf = vec![0u8; size];
        rng.fill_bytes(&mut buf);

        // Reuse one `String` across iterations so we measure the formatter,
        // not the allocator.
        let mut out = String::with_capacity(size * 2);

        c.bench_function(&format!("{}/size={size}", module_path!()), |b| {
            b.iter(|| {
                out.clear();
                write!(out, "{}", Hex(black_box(&buf))).unwrap();
                black_box(&out);
            });
        });
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(50);
    targets = bench_display,
}
