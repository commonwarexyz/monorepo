use crate::{BALANCE, Balance, CONCURRENCY, Nonced, for_each_batch};
use commonware_glue::transfers::{Plan, Transfer};
use commonware_parallel::{Rayon, Sequential};
use commonware_utils::NZUsize;
use criterion::{Criterion, criterion_group};

/// Settles the plan of `batch` on one thread and on `pool`, with every key starting at `start`.
fn bench_batch<T: Transfer + Sync>(
    c: &mut Criterion,
    pool: &Rayon,
    params: &str,
    batch: &[T],
    start: T::Account,
) {
    let plan = Plan::new(batch, &Sequential).unwrap();
    let reads = vec![Some(start); plan.len()];
    c.bench_function(&format!("{}/{params} conc=1", module_path!()), |b| {
        b.iter(|| plan.settle(&reads, &Sequential).unwrap())
    });
    c.bench_function(
        &format!("{}/{params} conc={CONCURRENCY}", module_path!()),
        |b| b.iter(|| plan.settle(&reads, pool).unwrap()),
    );
}

fn bench_settle(c: &mut Criterion) {
    let pool = Rayon::new(NZUsize!(CONCURRENCY)).unwrap();
    for_each_batch(|params, payments, signed| {
        bench_batch(
            c,
            &pool,
            &format!("{params} effects=none"),
            payments,
            Balance(BALANCE),
        );
        bench_batch(
            c,
            &pool,
            &format!("{params} effects=nonce"),
            signed,
            Nonced::START,
        );
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_settle,
}
