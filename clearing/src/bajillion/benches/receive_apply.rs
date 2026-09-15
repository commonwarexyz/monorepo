use super::{
    admission_fixtures::{VALIDATORS, Validators},
    fixtures::{
        CloseFixture, EPOCH, WORKERS, active_close_fixture, epoch_context, profile_key,
        selected_active_profiles, strategy, terminal_material,
    },
};
use commonware_clearing::bajillion::{
    admission::seal, qmdb::account_key, transition::prepare_dealing,
};
use commonware_cryptography::Sha256;
use commonware_cryptography_curve25519::signing::BatchVerifier;
use commonware_runtime::Runner as _;
use commonware_utils::{Participant, TestRng};
use criterion::{Criterion, criterion_group};
use std::{
    hint::black_box,
    time::{Duration, Instant},
};

// Each Criterion batch advances a sequence from one genesis. Only terminal inputs are
// regenerated between closes; the live database remains incremental.
fn bench_receive_apply(c: &mut Criterion) {
    for (_, profile) in selected_active_profiles() {
        c.bench_function(
            &format!(
                "{}/{} E={} workers={WORKERS} sequence=consecutive",
                module_path!(),
                profile_key(profile),
                profile.edges()
            ),
            |b| {
                b.iter_custom(|iterations| {
                    super::fixtures::runner().start(|runtime| async {
                        let CloseFixture {
                            mut state,
                            accounts,
                            operator,
                            operator_bls,
                            deposits,
                            withdrawals,
                            prepared,
                            ..
                        } = active_close_fixture(runtime, profile).await;
                        drop(prepared);
                        let validators = Validators::new(VALIDATORS);
                        let committee = validators.committee().commitment::<Sha256>();
                        let signer = validators.signer(Participant::new(0));
                        let mut rng = TestRng::new(0);
                        let mut elapsed = Duration::ZERO;
                        let mut first = None;

                        for iteration in 0..iterations.max(2) {
                            let measured = iteration < iterations;
                            let context = epoch_context(
                                &state,
                                EPOCH + iteration,
                                committee,
                                &operator,
                                &deposits,
                                &withdrawals,
                            );
                            let (terminals, _) =
                                terminal_material(profile, &accounts, &context, &operator);
                            let encoded = prepare_dealing::<Sha256, _, _>(
                                context.epoch_context(),
                                &deposits,
                                &withdrawals,
                                terminals,
                            )
                            .expect("operator wire")
                            .encoded()
                            .clone();
                            let (advanced, close) = {
                                let start = Instant::now();
                                let (vote, validated) =
                                    seal::<Sha256, _, _, _, _, BatchVerifier, _>(
                                        &signer,
                                        &state,
                                        &context,
                                        &operator_bls,
                                        &deposits,
                                        &withdrawals,
                                        encoded,
                                        &mut rng,
                                        strategy(),
                                    )
                                    .await
                                    .expect("receive validate sign");
                                let result = Box::pin(validated.apply(state))
                                    .await
                                    .expect("advance validator state");
                                let duration = start.elapsed();
                                if measured {
                                    elapsed += duration;
                                }
                                black_box(vote);
                                result
                            };
                            assert_eq!(advanced.state().root(), close.roots.successor);
                            assert_eq!(
                                advanced.state().liability(),
                                profile.live_accounts as u64 * super::fixtures::OPENING_BALANCE
                            );
                            black_box((&advanced, &close));
                            state = advanced;

                            if first.is_none() {
                                first = Some((close, state.state().head().operations()));
                            }
                        }
                        // The retained first close remains queryable after later applications. Historical
                        // view reconstruction/proof generation is checked here and is not an advancement timing.
                        if let Some((first, operations)) = first {
                            let key = account_key(&accounts[0].0).expect("key");
                            let head = state.state().root();
                            let proof = state
                                .state()
                                .lookup_at(first.roots.successor, operations, &key)
                                .await
                                .expect("retained state proof");
                            assert_eq!(
                                proof
                                    .resolve::<Sha256>(&first.roots.successor, &key)
                                    .expect("verify retained proof")
                                    .map(|b| b.get()),
                                Some(first.rows[0].successor)
                            );
                            assert_eq!(state.state().root(), head);
                            black_box((first, proof, state));
                        }
                        elapsed
                    })
                });
            },
        );
    }
}

criterion_group! {name = benches; config = Criterion::default().sample_size(10); targets = bench_receive_apply,}
