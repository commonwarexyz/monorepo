use super::fixtures::{active_close_fixture, selected_active_profiles};
use commonware_clearing::bajillion::transition::build_close;
use commonware_cryptography::Sha256;
use criterion::{BatchSize, Criterion, criterion_group};
use std::hint::black_box;

fn bench_build_close(c: &mut Criterion) {
    for (_, profile) in selected_active_profiles() {
        // The complete opening tree is persistent epoch state and is outside active-close timing.
        // `build_close` performs full validation before returning; the validation bench isolates
        // the cost of checking an already-constructed corpus.
        let fixture = active_close_fixture(profile);
        let registry = profile.registry;
        let changed = profile.changed_accounts;
        let credited = profile.credited_accounts;
        let shards = profile.receive_shards_per_credited;
        c.bench_function(
            &format!(
                "{}/N={registry} A={changed} B={credited} h={shards}",
                module_path!()
            ),
            |b| {
                b.iter_batched(
                    || (fixture.rows.clone(), fixture.shard_sets.clone()),
                    |(rows, shard_sets)| {
                        black_box(
                            build_close::<Sha256, _, _>(
                                &fixture.cache,
                                &fixture.context,
                                &fixture.deposits,
                                &fixture.withdrawals,
                                rows,
                                shard_sets,
                            )
                            .expect("benchmark close is valid"),
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
    targets = bench_build_close,
}
