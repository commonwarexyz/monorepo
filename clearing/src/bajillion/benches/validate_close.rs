use super::fixtures::{
    WORKERS, active_close_fixture, profile_key, selected_active_profiles, strategy,
};
use commonware_clearing::bajillion::{posted, transition::validate_close_with_strategy};
use commonware_cryptography::Sha256;
use commonware_cryptography_curve25519::signing::BatchVerifier;
use commonware_runtime::Runner as _;
use commonware_utils::TestRng;
use criterion::{Criterion, criterion_group};
use std::{
    hint::black_box,
    time::{Duration, Instant},
};

fn bench_validate_close(c: &mut Criterion) {
    for (_, profile) in selected_active_profiles() {
        c.bench_function(
            &format!(
                "{}/{} E={} workers={WORKERS}",
                module_path!(),
                profile_key(profile),
                profile.edges()
            ),
            |b| {
                b.iter_custom(|iterations| {
                    super::fixtures::runner().start(|runtime| async move {
                        let fixture = active_close_fixture(runtime, profile).await;
                        let mut rng = TestRng::new(0);
                        let mut elapsed = Duration::ZERO;
                        for _ in 0..iterations {
                            let dealing = posted::decode(
                                fixture.prepared.encoded().clone(),
                                &fixture.context,
                            )
                            .expect("decode outside validation timing");
                            let start = Instant::now();
                            let prepared = validate_close_with_strategy::<
                                Sha256,
                                _,
                                _,
                                _,
                                _,
                                BatchVerifier,
                                _,
                            >(
                                &fixture.state,
                                &fixture.context,
                                &fixture.operator_bls,
                                &fixture.deposits,
                                &fixture.withdrawals,
                                dealing,
                                &mut rng,
                                strategy(),
                            )
                            .await
                            .expect("validate close");
                            elapsed += start.elapsed();
                            assert_eq!(prepared.close().header, fixture.prepared.close().header);
                            black_box(prepared);
                        }
                        elapsed
                    })
                });
            },
        );
    }
}
criterion_group! {name = benches; config = Criterion::default().sample_size(10); targets = bench_validate_close,}
