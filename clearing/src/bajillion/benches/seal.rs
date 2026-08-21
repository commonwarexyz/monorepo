use super::{
    admission_fixtures::{QUORUM, SLICES, VALIDATORS, validator_fixture},
    fixtures::{WORKERS, selected_active_profiles, strategy},
};
use commonware_clearing::bajillion::admission::seal;
use commonware_cryptography::Sha256;
use commonware_cryptography_curve25519::signing::BatchVerifier as PaymentBatchVerifier;
use commonware_utils::TestRng;
use criterion::{Criterion, criterion_group};
use std::{
    hint::black_box,
    time::{Duration, Instant},
};

fn bench_seal(c: &mut Criterion) {
    for (_, profile) in selected_active_profiles() {
        let fixture = validator_fixture(profile);
        let assigned_slices = fixture.slices.len();
        let scheme = fixture.validators.signer(fixture.validator);
        let registry = profile.registry;
        let changed = profile.changed_accounts;
        let credited = profile.credited_accounts;
        let shards = profile.receive_shards_per_credited;
        eprintln!(
            "clearing benchmark corpus: N={registry} A={changed} B={credited} h={shards} close_bytes={} slice_corpus_bytes={} validator={} assignment_bytes={} assigned_slices={} workers={WORKERS}",
            fixture.public_corpus_bytes,
            fixture.slice_corpus_bytes,
            usize::from(fixture.validator),
            fixture.assignment_bytes,
            assigned_slices,
        );

        c.bench_function(
            &format!(
                "{}/N={registry} A={changed} B={credited} h={shards} n={VALIDATORS} q={QUORUM} slices={SLICES} assigned={assigned_slices} workers={WORKERS}",
                module_path!()
            ),
            |b| {
                let mut slices = Some(fixture.slices.clone());
                let mut rng = TestRng::new(0);
                b.iter_custom(|iterations| {
                    let mut elapsed = Duration::ZERO;
                    for _ in 0..iterations {
                        let input = slices.take().expect("benchmark assignment is available");
                        let start = Instant::now();
                        let (vote, retained) =
                            seal::<Sha256, _, _, PaymentBatchVerifier, _>(
                                black_box(&scheme),
                                black_box(&fixture.close.context),
                                black_box(&fixture.close.deposits),
                                black_box(&fixture.close.withdrawals),
                                black_box(&fixture.close.prepared.close().header),
                                black_box(&fixture.close.prepared.close().roots),
                                input,
                                &mut rng,
                                strategy(),
                            )
                            .expect("benchmark assignment is valid");
                        elapsed += start.elapsed();
                        black_box(vote);
                        slices = Some(retained.into_slices());
                    }
                    elapsed
                });
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
    targets = bench_seal,
}
