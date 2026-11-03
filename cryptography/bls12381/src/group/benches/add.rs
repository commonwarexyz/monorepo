//! Adding two elements, compared with blst.

use super::utils::{Curve, scalars};
use commonware_cryptography_bls12381::group::{G1, G2};
use criterion::{Criterion, criterion_group};
use std::hint::black_box;

fn bench<C: Curve>(c: &mut Criterion) {
    let scalars = scalars(2, 3);
    let (a, b) = (C::multiple(&scalars[0]), C::multiple(&scalars[1]));
    c.bench_function(
        &format!("{}/curve={} impl=commonware", module_path!(), C::NAME),
        |bencher| bencher.iter(|| black_box(black_box(a.0) + black_box(&b.0))),
    );
    c.bench_function(
        &format!("{}/curve={} impl=blst", module_path!(), C::NAME),
        |bencher| bencher.iter(|| black_box(C::blst_add(black_box(&a.1), black_box(&b.1)))),
    );
}

fn bench_add(c: &mut Criterion) {
    bench::<G1>(c);
    bench::<G2>(c);
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_add
}
