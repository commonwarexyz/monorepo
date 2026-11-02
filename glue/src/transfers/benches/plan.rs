use crate::{CONCURRENCY, for_each_batch};
use commonware_glue::transfers::{Plan, Transfer};
use commonware_parallel::{Rayon, Sequential};
use commonware_utils::NZUsize;
use criterion::{Criterion, criterion_group};

/// Plans `batch` on one thread and on `pool`.
fn bench_batch<T: Transfer + Sync>(c: &mut Criterion, pool: &Rayon, params: &str, batch: &[T]) {
    c.bench_function(&format!("{}/{params} conc=1", module_path!()), |b| {
        b.iter(|| Plan::new(batch, &Sequential).unwrap())
    });
    c.bench_function(
        &format!("{}/{params} conc={CONCURRENCY}", module_path!()),
        |b| b.iter(|| Plan::new(batch, pool).unwrap()),
    );
}

fn bench_plan(c: &mut Criterion) {
    let pool = Rayon::new(NZUsize!(CONCURRENCY)).unwrap();
    for_each_batch(|params, payments, signed| {
        bench_batch(c, &pool, &format!("{params} effects=none"), payments);
        bench_batch(c, &pool, &format!("{params} effects=nonce"), signed);
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_plan,
}
