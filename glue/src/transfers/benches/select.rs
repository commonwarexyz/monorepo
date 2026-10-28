use crate::{BALANCE, Balance, CONCURRENCY, Payment, TRANSFERS, payments};
use commonware_glue::transfers::Selection;
use commonware_parallel::{Rayon, Sequential, Strategy};
use commonware_storage::qmdb::any::batch::Slot;
use commonware_utils::NZUsize;
use criterion::{Criterion, criterion_group};

/// Selects every payment in one round against accounts that afford them all, returning whether
/// each was accepted and the slot of every key.
fn select(payments: &[Payment], strategy: &impl Strategy) -> (Vec<bool>, Vec<Slot<Balance>>) {
    let mut selection = Selection::new();
    let touched = selection.touch(payments);
    selection.register(vec![Some(Balance(BALANCE)); touched.len()]);
    let accepted = selection.apply(payments);
    (accepted, selection.settle(strategy))
}

fn bench_select(c: &mut Criterion) {
    let pool = Rayon::new(NZUsize!(CONCURRENCY)).unwrap();
    for transfers in TRANSFERS {
        let payments = payments(transfers);
        c.bench_function(
            &format!("{}/transfers={transfers} conc=1", module_path!()),
            |b| b.iter(|| select(&payments, &Sequential)),
        );
        c.bench_function(
            &format!(
                "{}/transfers={transfers} conc={CONCURRENCY}",
                module_path!()
            ),
            |b| b.iter(|| select(&payments, &pool)),
        );
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_select,
}
