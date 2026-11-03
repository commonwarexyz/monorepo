//! One pairing, compared with blst.

use super::utils::{blst_multi_pairing, pairs};
use commonware_cryptography_bls12381::group::pairing;
use criterion::{Criterion, criterion_group};
use std::{hint::black_box, slice};

fn bench_pairing(c: &mut Criterion) {
    let (pairs, blst_pairs) = pairs(1);
    let ((p, q), blst_pair) = (pairs[0], blst_pairs[0]);
    c.bench_function(&format!("{}/impl=commonware", module_path!()), |bencher| {
        bencher.iter(|| black_box(pairing(black_box(&p), black_box(&q))))
    });
    c.bench_function(&format!("{}/impl=blst", module_path!()), |bencher| {
        bencher.iter(|| black_box(blst_multi_pairing(slice::from_ref(black_box(&blst_pair)))))
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_pairing
}
