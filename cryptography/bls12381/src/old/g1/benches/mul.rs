use super::utils::{points, scalar, to_blst};
use criterion::{Criterion, criterion_group};
use std::hint::black_box;

fn bench_mul(c: &mut Criterion) {
    let point = points(1)[0];
    let scalar = scalar(7);
    c.bench_function(&format!("{}/impl=bls12381", module_path!()), |b| {
        b.iter(|| black_box(point.mul(&scalar)));
    });
    let p = to_blst(&point);
    let bytes = scalar.to_words().map(u64::to_le_bytes).concat();
    c.bench_function(&format!("{}/impl=blst", module_path!()), |b| {
        b.iter(|| {
            let mut out = blst::blst_p1::default();
            // SAFETY: valid pointers; the scalar buffer holds 256 bits.
            unsafe { blst::blst_p1_mult(&mut out, &p, bytes.as_ptr(), 255) };
            black_box(out)
        });
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_mul
}
