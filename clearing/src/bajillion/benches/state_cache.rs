use super::fixtures::{STATE_CACHE_SIZES, TestStateCache, state_leaves};
use commonware_cryptography::Sha256;
use criterion::{BatchSize, Criterion, criterion_group};
use std::hint::black_box;

fn bench_state_cache(c: &mut Criterion) {
    for &live_accounts in STATE_CACHE_SIZES {
        let leaves = state_leaves(live_accounts);
        c.bench_function(
            &format!("{}/live_accounts={live_accounts}", module_path!()),
            |b| {
                b.iter_batched(
                    || leaves.clone(),
                    |leaves| {
                        black_box(
                            TestStateCache::new::<Sha256>(leaves)
                                .expect("benchmark state is canonical"),
                        )
                    },
                    BatchSize::LargeInput,
                );
            },
        );
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_state_cache,
}
