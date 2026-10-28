use super::utils::{blst_final_exp, blst_miller_loop, pairs, to_blst};
use commonware_cryptography_bls12381::old::pairing::{final_exponentiation, miller_loop};
use criterion::{Criterion, criterion_group};
use std::hint::black_box;

fn bench_final_exponentiation(c: &mut Criterion) {
    let pairs = pairs(1);
    let f = miller_loop(&pairs);
    c.bench_function(&format!("{}/impl=bls12381", module_path!()), |b| {
        b.iter(|| black_box(final_exponentiation(&f)));
    });
    let (p, q) = to_blst(&pairs);
    let f = blst_miller_loop(&p, &q);
    c.bench_function(&format!("{}/impl=blst", module_path!()), |b| {
        b.iter(|| black_box(blst_final_exp(&f)));
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_final_exponentiation
}
