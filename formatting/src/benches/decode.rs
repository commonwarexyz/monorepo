//! Benchmark: `from_hex()`.
//!
//! Two cases per size: pristine input (no whitespace, no prefix) and "ugly"
//! input (mixed whitespace plus a `0x`/`0X` prefix; iterations alternate
//! between the two prefix variants to exercise both stripping paths roughly
//! 50/50).

use criterion::{criterion_group, Criterion};
use rand::{rngs::StdRng, RngCore, SeedableRng};
use std::hint::black_box;

/// Inject whitespace at every 8th character, plus a `prefix` at the start.
fn ugly(s: &str, prefix: &str) -> String {
    let mut out = String::with_capacity(s.len() + s.len() / 8 + prefix.len());
    out.push_str(prefix);
    for (i, ch) in s.chars().enumerate() {
        if i > 0 && i.is_multiple_of(8) {
            out.push(' ');
        }
        out.push(ch);
    }
    out
}

fn bench_decode(c: &mut Criterion) {
    for size in [16usize, 32, 64, 256, 1024, 16 * 1024] {
        let mut rng = StdRng::seed_from_u64(size as u64);
        let mut buf = vec![0u8; size];
        rng.fill_bytes(&mut buf);
        let pristine = commonware_formatting::hex(&buf);
        let ugly_lower = ugly(&pristine, "0x");
        let ugly_upper = ugly(&pristine, "0X");

        c.bench_function(
            &format!("{}/input=pristine size={size}", module_path!()),
            |b| {
                b.iter(|| black_box(commonware_formatting::from_hex(black_box(&pristine))));
            },
        );
        c.bench_function(&format!("{}/input=ugly size={size}", module_path!()), |b| {
            let inputs: [&str; 2] = [&ugly_lower, &ugly_upper];
            let mut idx = 0usize;
            b.iter(|| {
                let s = inputs[idx];
                idx ^= 1;
                black_box(commonware_formatting::from_hex(black_box(s)))
            });
        });
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(50);
    targets = bench_decode,
}
