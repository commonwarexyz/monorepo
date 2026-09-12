use super::{
    admission_fixtures::{VALIDATORS, Validators},
    fixtures::{
        CloseFixture, EPOCH, WORKERS, active_close_fixture, epoch_context, profile_key,
        selected_active_profiles, strategy, terminal_material,
    },
};
use commonware_clearing::bajillion::{
    admission::seal, qmdb::account_key, transition::prepare_close_with_strategy,
};
use commonware_cryptography::Sha256;
use commonware_cryptography_curve25519::signing::BatchVerifier;
use commonware_runtime::Runner as _;
use commonware_utils::{Participant, TestRng};
use criterion::Criterion;
use std::{
    hint::black_box,
    time::{Duration, Instant},
};

pub(crate) enum Operation {
    Prepare,
    Receive,
}

// Each Criterion batch advances a sequence from one genesis. Only terminal inputs are
// regenerated between closes; the live database remains incremental.
pub(crate) fn benches(c: &mut Criterion, name: &str, operation: Operation) {
    for (_, profile) in selected_active_profiles() {
        c.bench_function(
            &format!(
                "{name}/{} E={} workers={WORKERS} sequence=consecutive",
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
                        let validators = Validators::new();
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
                            )
                            .await;
                            let (terminals, _) =
                                terminal_material(profile, &accounts, &context, &operator);
                            let (advanced, close) = match operation {
                                Operation::Prepare => {
                                    let start = Instant::now();
                                    let prepared =
                                        prepare_close_with_strategy::<Sha256, _, _, _, _>(
                                            &state,
                                            &context,
                                            &deposits,
                                            &withdrawals,
                                            terminals.clone(),
                                            strategy(),
                                        )
                                        .await
                                        .expect("prepare");
                                    let packets = (0..VALIDATORS)
                                        .map(|_| prepared.encoded().clone())
                                        .collect::<Vec<_>>();
                                    let result = prepared
                                        .apply(state)
                                        .await
                                        .expect("advance operator state");
                                    let duration = start.elapsed();
                                    if measured {
                                        elapsed += duration;
                                    }
                                    black_box(packets);
                                    result
                                }
                                Operation::Receive => {
                                    let encoded =
                                        prepare_close_with_strategy::<Sha256, _, _, _, _>(
                                            &state,
                                            &context,
                                            &deposits,
                                            &withdrawals,
                                            terminals,
                                            strategy(),
                                        )
                                        .await
                                        .expect("operator wire")
                                        .encoded()
                                        .clone();
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
                                    let result = validated
                                        .apply(state)
                                        .await
                                        .expect("advance validator state");
                                    let duration = start.elapsed();
                                    if measured {
                                        elapsed += duration;
                                    }
                                    black_box(vote);
                                    result
                                }
                            };
                            assert_eq!(advanced.root(), close.roots.successor);
                            assert_eq!(
                                advanced.liability(),
                                profile.live_accounts as u64 * super::fixtures::OPENING_BALANCE
                            );
                            black_box((&advanced, &close));
                            state = advanced;
                            if first.is_none() {
                                first = Some((close, state.head().operations()));
                            }
                        }
                        // The retained first close remains queryable after later applications. Historical
                        // view reconstruction/proof generation is checked here and is not an advancement timing.
                        if let Some((first, operations)) = first {
                            let key = account_key(&accounts[0].0).expect("key");
                            let head = state.root();
                            let proof = state
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
                            assert_eq!(state.root(), head);
                            black_box((first, proof, state));
                        }
                        elapsed
                    })
                });
            },
        );
    }
}
