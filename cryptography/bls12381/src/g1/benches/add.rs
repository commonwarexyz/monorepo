use super::utils::{points, to_blst};
use criterion::{Criterion, criterion_group};
use std::hint::black_box;

fn bench_add(c: &mut Criterion) {
    let points = points(2);
    c.bench_function(&format!("{}/impl=bls12381", module_path!()), |b| {
        b.iter(|| black_box(points[0].add(&points[1])));
    });
    let (p, q) = (to_blst(&points[0]), to_blst(&points[1]));
    c.bench_function(&format!("{}/impl=blst", module_path!()), |b| {
        b.iter(|| {
            let mut out = blst::blst_p1::default();
            // SAFETY: valid pointers to point structures.
            unsafe { blst::blst_p1_add_or_double(&mut out, &p, &q) };
            black_box(out)
        });
    });
}

fn bench_double(c: &mut Criterion) {
    let points = points(1);
    c.bench_function(&format!("{}_double/impl=bls12381", module_path!()), |b| {
        b.iter(|| black_box(points[0].double()));
    });
    let p = to_blst(&points[0]);
    c.bench_function(&format!("{}_double/impl=blst", module_path!()), |b| {
        b.iter(|| {
            let mut out = blst::blst_p1::default();
            // SAFETY: valid pointers to point structures.
            unsafe { blst::blst_p1_double(&mut out, &p) };
            black_box(out)
        });
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_add, bench_double
}
