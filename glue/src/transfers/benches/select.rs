use crate::{BALANCE, Balance, CONCURRENCY, Nonced, for_each_batch};
use commonware_glue::transfers::{Selection, Transfer};
use commonware_parallel::{Rayon, Sequential, Strategy};
use commonware_storage::qmdb::any::batch::Slot;
use commonware_utils::NZUsize;
use criterion::{Criterion, criterion_group};

/// Selects every transfer of `batch` in one round from keys that all start at `start` and accept
/// every transfer. Returns whether each was accepted and the slot of every key.
fn select<T: Transfer>(
    batch: &[T],
    start: &T::Account,
    strategy: &impl Strategy,
) -> (Vec<bool>, Vec<Slot<T::Account>>) {
    let mut selection = Selection::new();
    let touched = selection.touch(batch);
    selection.register(vec![Some(start.clone()); touched.len()]);
    let accepted = selection.apply(batch);
    (accepted, selection.settle(strategy))
}

/// Selects `batch` and settles the selection on one thread and on `pool`.
fn bench_batch<T: Transfer>(
    c: &mut Criterion,
    pool: &Rayon,
    params: &str,
    batch: &[T],
    start: T::Account,
) {
    c.bench_function(&format!("{}/{params} conc=1", module_path!()), |b| {
        b.iter(|| select(batch, &start, &Sequential))
    });
    c.bench_function(
        &format!("{}/{params} conc={CONCURRENCY}", module_path!()),
        |b| b.iter(|| select(batch, &start, pool)),
    );
}

fn bench_select(c: &mut Criterion) {
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
    targets = bench_select,
}
