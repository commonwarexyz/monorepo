//! Doubling an element, compared with blst.

use super::utils::{Curve, scalars};
use commonware_cryptography_bls12381::group::{G1, G2};
use criterion::{Criterion, criterion_group};
use std::hint::black_box;

fn bench<C: Curve>(c: &mut Criterion) {
    let (a, blst_a) = C::multiple(&scalars(1, 4)[0]);
    c.bench_function(
        &format!("{}/curve={} impl=commonware", module_path!(), C::NAME),
        |bencher| {
            bencher.iter(|| {
                let mut doubled = black_box(a);
                doubled.double();
                black_box(doubled)
            })
        },
    );
    c.bench_function(
        &format!("{}/curve={} impl=blst", module_path!(), C::NAME),
        |bencher| bencher.iter(|| black_box(C::blst_double(black_box(&blst_a)))),
    );
}

fn bench_double(c: &mut Criterion) {
    bench::<G1>(c);
    bench::<G2>(c);
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_double
}
