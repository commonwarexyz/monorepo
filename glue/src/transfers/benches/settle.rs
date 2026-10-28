use crate::{BALANCE, Balance, CONCURRENCY, TRANSFERS, payments};
use commonware_glue::transfers::Plan;
use commonware_parallel::{Rayon, Sequential};
use commonware_utils::NZUsize;
use criterion::{Criterion, criterion_group};

fn bench_settle(c: &mut Criterion) {
    let pool = Rayon::new(NZUsize!(CONCURRENCY)).unwrap();
    for transfers in TRANSFERS {
        let plan = Plan::new(&payments(transfers), &Sequential).unwrap();
        let reads = vec![Some(Balance(BALANCE)); plan.len()];
        c.bench_function(
            &format!("{}/transfers={transfers} conc=1", module_path!()),
            |b| b.iter(|| plan.settle(&reads, &Sequential).unwrap()),
        );
        c.bench_function(
            &format!(
                "{}/transfers={transfers} conc={CONCURRENCY}",
                module_path!()
            ),
            |b| b.iter(|| plan.settle(&reads, &pool).unwrap()),
        );
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_settle,
}
