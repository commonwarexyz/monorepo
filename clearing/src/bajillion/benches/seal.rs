use super::{
    admission_fixtures::Validators,
    fixtures::{WORKERS, active_close_fixture, profile_key, selected_active_profiles, strategy},
};
use commonware_clearing::bajillion::admission::seal;
use commonware_cryptography::Sha256;
use commonware_cryptography_curve25519::signing::BatchVerifier;
use commonware_runtime::Runner as _;
use commonware_utils::{Participant, TestRng};
use criterion::{Criterion, criterion_group};
use std::{
    hint::black_box,
    time::{Duration, Instant},
};

fn bench_seal(c: &mut Criterion) {
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
                        let signer = Validators::new().signer(Participant::new(0));
                        let mut rng = TestRng::new(0);
                        let mut elapsed = Duration::ZERO;
                        for _ in 0..iterations {
                            let wire = fixture.prepared.encoded().clone();
                            let start = Instant::now();
                            let (vote, prepared) = seal::<Sha256, _, _, _, _, BatchVerifier, _>(
                                &signer,
                                &fixture.state,
                                &fixture.context,
                                &fixture.operator_bls,
                                &fixture.deposits,
                                &fixture.withdrawals,
                                wire,
                                &mut rng,
                                strategy(),
                            )
                            .await
                            .expect("decode validate and sign");
                            elapsed += start.elapsed();
                            assert_eq!(prepared.close().header, fixture.prepared.close().header);
                            black_box((vote, prepared));
                        }
                        elapsed
                    })
                });
            },
        );
    }
}
criterion_group! {name = benches; config = Criterion::default().sample_size(10); targets = bench_seal,}
