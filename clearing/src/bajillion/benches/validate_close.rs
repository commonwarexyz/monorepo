use super::fixtures::{active_close_fixture, selected_active_profiles};
use commonware_clearing::bajillion::transition::validate_close;
use commonware_cryptography::Sha256;
use criterion::{Criterion, criterion_group};
use std::hint::black_box;

fn bench_validate_close(c: &mut Criterion) {
    for (_, profile) in selected_active_profiles() {
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
                b.iter(|| {
                    black_box(validate_close::<Sha256, _, _>(
                        black_box(&fixture.context),
                        black_box(&fixture.deposits),
                        black_box(&fixture.withdrawals),
                        black_box(fixture.prepared.close()),
                    ))
                    .expect("benchmark close is valid")
                });
            },
        );
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_validate_close,
}
