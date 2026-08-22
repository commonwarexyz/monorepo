use super::{
    admission_fixtures::{SLICE_BITS, SLICES},
    fixtures::{WORKERS, active_close_fixture, selected_active_profiles, strategy},
};
use criterion::{BatchSize, Criterion, criterion_group};
use std::{hint::black_box, time::Duration};

fn bench_deal(c: &mut Criterion) {
    for (_, profile) in selected_active_profiles() {
        let fixture = active_close_fixture(profile);
        assert_eq!(fixture.context.assignment().slice_bits(), SLICE_BITS);
        let live_accounts = profile.live_accounts;
        let changed = profile.changed_accounts;
        let credited = profile.credited_accounts;
        let shards = profile.receive_shards_per_credited;
        c.bench_function(
            &format!(
                "{}/N={live_accounts} A={changed} B={credited} h={shards} slices={SLICES} workers={WORKERS}",
                module_path!()
            ),
            |b| {
                b.iter_batched(
                    || (),
                    |()| {
                        black_box(
                            fixture
                                .prepared
                                .assemble_slices(black_box(&fixture.cache), strategy())
                                .expect("benchmark dealing is valid"),
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
    config = Criterion::default()
        .sample_size(10)
        .warm_up_time(Duration::from_secs(10))
        .measurement_time(Duration::from_secs(20));
    targets = bench_deal,
}
