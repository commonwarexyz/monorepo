//! Benchmark: `from_hex_formatted()`.
//!
//! Two cases per size: pristine input (no whitespace, no `0x`) and "ugly"
//! input (mixed whitespace plus `0x` prefix).

use criterion::{criterion_group, Criterion};
use rand::{rngs::StdRng, RngCore, SeedableRng};
use std::hint::black_box;

/// Inject whitespace at every 8th character, plus a `0x` prefix.
fn ugly(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + s.len() / 8 + 2);
    out.push_str("0x");
    for (i, ch) in s.chars().enumerate() {
        if i > 0 && i.is_multiple_of(8) {
            out.push(' ');
        }
        out.push(ch);
    }
    out
}

fn bench_decode_formatted(c: &mut Criterion) {
    for size in [16usize, 32, 64, 256, 1024, 16 * 1024] {
        let mut rng = StdRng::seed_from_u64(size as u64);
        let mut buf = vec![0u8; size];
        rng.fill_bytes(&mut buf);
        let pristine = commonware_formatting::hex(&buf);
        let ugly = ugly(&pristine);

        c.bench_function(
            &format!("{}/input=pristine size={size}", module_path!()),
            |b| {
                b.iter(|| {
                    black_box(commonware_formatting::from_hex_formatted(black_box(
                        &pristine,
                    )))
                });
            },
        );
        c.bench_function(&format!("{}/input=ugly size={size}", module_path!()), |b| {
            b.iter(|| black_box(commonware_formatting::from_hex_formatted(black_box(&ugly))));
        });
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(50);
    targets = bench_decode_formatted,
}
