//! Multiplying an element by a secret scalar, compared with blst.

use super::utils::{Curve, scalars};
use commonware_cryptography_bls12381::group::{G1, G2};
use criterion::{Criterion, criterion_group};
use std::hint::black_box;

fn bench<C: Curve>(c: &mut Criterion) {
    let scalars = scalars(2, 5);
    let (a, blst_a) = C::multiple(&scalars[0]);
    let scalar = scalars[1];
    c.bench_function(
        &format!("{}/curve={} impl=commonware", module_path!(), C::NAME),
        |bencher| bencher.iter(|| black_box(black_box(a) * black_box(&scalar))),
    );
    c.bench_function(
        &format!("{}/curve={} impl=blst", module_path!(), C::NAME),
        |bencher| bencher.iter(|| black_box(C::blst_mul(black_box(&blst_a), black_box(&scalar)))),
    );
}

fn bench_mul(c: &mut Criterion) {
    bench::<G1>(c);
    bench::<G2>(c);
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_mul
}
