use super::{
    admission_fixtures::{SLICE_BITS, SLICES},
    fixtures::{WORKERS, active_close_fixture, selected_active_profiles, strategy},
};
use commonware_clearing::bajillion::transition::{assemble_slices, validate_close};
use commonware_cryptography::Sha256;
use criterion::{BatchSize, Criterion, criterion_group};
use std::{hint::black_box, time::Duration};

fn bench_assemble_slices(c: &mut Criterion) {
    for (_, profile) in selected_active_profiles() {
        let fixture = active_close_fixture(profile);
        assert_eq!(fixture.context.assignment().slice_bits(), SLICE_BITS);
        let registry = profile.registry;
        let changed = profile.changed_accounts;
        let credited = profile.credited_accounts;
        let shards = profile.receive_shards_per_credited;
        validate_close::<Sha256, _, _>(
            &fixture.context,
            &fixture.deposits,
            &fixture.withdrawals,
            fixture.prepared.close(),
        )
        .expect("benchmark close is publicly valid");
        c.bench_function(
            &format!(
                "{}/N={registry} A={changed} B={credited} h={shards} slices={SLICES} workers={WORKERS}",
                module_path!()
            ),
            |b| {
                b.iter_batched(
                    || (),
                    |()| {
                        black_box(
                            assemble_slices::<Sha256, _, _>(
                                black_box(&fixture.cache),
                                black_box(&fixture.context),
                                black_box(&fixture.deposits),
                                black_box(&fixture.withdrawals),
                                black_box(fixture.prepared.close()),
                                strategy(),
                            )
                            .expect("benchmark slices are valid"),
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
    targets = bench_assemble_slices,
}
