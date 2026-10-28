use super::utils::{blst_miller_loop, pairs, to_blst};
use commonware_cryptography_bls12381::old::pairing::miller_loop;
use criterion::{Criterion, criterion_group};
use std::hint::black_box;

fn bench_miller_loop(c: &mut Criterion) {
    let pairs = pairs(1);
    c.bench_function(&format!("{}/impl=bls12381", module_path!()), |b| {
        b.iter(|| black_box(miller_loop(&pairs)));
    });
    let (p, q) = to_blst(&pairs);
    c.bench_function(&format!("{}/impl=blst", module_path!()), |b| {
        b.iter(|| black_box(blst_miller_loop(&p, &q)));
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_miller_loop
}
