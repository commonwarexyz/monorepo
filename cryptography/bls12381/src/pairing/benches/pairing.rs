use super::utils::{blst_final_exp, blst_miller_loop, pairs, to_blst};
use commonware_cryptography_bls12381::pairing::pairing;
use criterion::{Criterion, criterion_group};
use std::hint::black_box;

fn bench_pairing(c: &mut Criterion) {
    let pairs = pairs(1);
    let (p, q) = pairs[0];
    c.bench_function(&format!("{}/impl=bls12381", module_path!()), |b| {
        b.iter(|| black_box(pairing(&p, &q)));
    });
    let (p, q) = to_blst(&pairs);
    c.bench_function(&format!("{}/impl=blst", module_path!()), |b| {
        b.iter(|| black_box(blst_final_exp(&blst_miller_loop(&p, &q))));
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_pairing
}
