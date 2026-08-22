use super::fixtures::{WORKERS, active_close_fixture, selected_active_profiles, strategy};
use commonware_clearing::bajillion::transition::prepare_close_with_strategy;
use commonware_cryptography::Sha256;
use criterion::{BatchSize, Criterion, criterion_group};
use std::hint::black_box;

fn bench_prepare(c: &mut Criterion) {
    for (_, profile) in selected_active_profiles() {
        let fixture = active_close_fixture(profile);
        let live_accounts = profile.live_accounts;
        let changed = profile.changed_accounts;
        let credited = profile.credited_accounts;
        let shards = profile.receive_shards_per_credited;
        c.bench_function(
            &format!(
                "{}/N={live_accounts} A={changed} B={credited} h={shards} workers={WORKERS}",
                module_path!()
            ),
            |b| {
                b.iter_batched(
                    || (fixture.rows.clone(), fixture.shard_sets.clone()),
                    |(rows, shard_sets)| {
                        black_box(
                            prepare_close_with_strategy::<Sha256, _, _>(
                                &fixture.cache,
                                &fixture.context,
                                &fixture.deposits,
                                &fixture.withdrawals,
                                rows,
                                shard_sets,
                                strategy(),
                            )
                            .expect("benchmark preparation is valid"),
                        )
                    },
                    BatchSize::PerIteration,
                );
            },
        );
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_prepare,
}
