//! Journal append and replay on a real store.

use commonware_consensus::multimmit::test_utils::benchmarks::{JournalScenario, run_journal};
use commonware_runtime::{
    benchmarks::{context, tokio},
    tokio::Context as TokioContext,
};
use criterion::{Criterion, criterion_group};
use std::time::Duration;

fn bench_journal(c: &mut Criterion) {
    let runner = tokio::Runner::default();
    for scenario in JournalScenario::ALL {
        c.bench_function(&format!("{}::{scenario}", module_path!()), |b| {
            b.to_async(&runner).iter_custom(|iterations| async move {
                // The runner stores one context per measurement and `get` takes it, so every
                // iteration shares the one taken here.
                let ctx = context::get::<TokioContext>();
                let mut elapsed = Duration::ZERO;
                for _ in 0..iterations {
                    elapsed += run_journal(&ctx, scenario).await;
                }
                elapsed
            });
        });
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_journal
}
