use super::{
    admission_fixtures::{VALIDATORS, Validators},
    fixtures, native_fixtures,
};
use bytes::Bytes;
use commonware_clearing::bajillion::{
    boundary::{DepositBatch, SignedWithdrawal, WithdrawalAction, WithdrawalBatch},
    posted,
    transition::{
        CloseContext, OperatorKey, OperatorVariant, PreparedClose, Terminal,
        prepare_close_with_strategy, validate_close_with_strategy,
    },
    vector::OutEntry,
};
use commonware_codec::Encode as _;
use commonware_cryptography::{
    Sha256, Signer as _,
    bls12381::primitives::{
        group::{Private, Scalar},
        ops::compute_public,
    },
    sha256::Digest,
};
use commonware_cryptography_curve25519::signing::{
    BatchVerifier, SigningKey, StrictVerifyingKey as VerifyingKey,
};
use commonware_parallel::Rayon;
use commonware_runtime::{Runner as _, deterministic};
use commonware_utils::TestRng;
use criterion::{Criterion, criterion_group};
use std::{
    hint::black_box,
    time::{Duration, Instant},
};

#[derive(Clone, Copy)]
struct Workload {
    accounts: usize,
    history: usize,
    rows: usize,
    payouts: usize,
}

impl Workload {
    fn label(self) -> String {
        format!(
            "N={} H={} payment_rows={} activity_rows={} W={} action=close workers={} storage=deterministic_memory replay=fixed_predecessor",
            self.accounts,
            self.history,
            self.rows,
            self.rows.max(self.payouts),
            self.payouts,
            fixtures::WORKERS
        )
    }
}

struct Input {
    state: fixtures::BenchState,
    context: CloseContext<VerifyingKey, Digest>,
    deposits: DepositBatch<VerifyingKey>,
    withdrawals: WithdrawalBatch<VerifyingKey, Digest>,
    operator: OperatorKey,
    expected: PreparedClose<VerifyingKey, Digest, Rayon>,
}

fn terminals(
    keys: &[(VerifyingKey, SigningKey)],
    count: usize,
    context: &CloseContext<VerifyingKey, Digest>,
    operator: &SigningKey,
) -> Vec<Terminal<VerifyingKey, Digest>> {
    keys[..count]
        .iter()
        .map(|key| {
            fixtures::terminal_for_entries(
                key,
                context,
                operator,
                1,
                vec![OutEntry {
                    recipient: key.0.clone(),
                    cumulative: 1,
                    count: 1,
                }],
            )
            .0
        })
        .collect()
}

#[commonware_macros::boxed]
async fn input(runtime: deterministic::Context, workload: Workload) -> Input {
    assert!(workload.rows <= workload.accounts);
    let keys = fixtures::accounts(workload.accounts);
    let mut state = fixtures::new_state(runtime, &keys).await;
    let operator = SigningKey::from_seed(1);
    let committee = Validators::new(VALIDATORS)
        .committee()
        .commitment::<Sha256>();
    let deposits = DepositBatch::empty();
    let empty_withdrawals = WithdrawalBatch::empty();
    let mut epoch = fixtures::EPOCH;
    let mut remaining = workload.history;

    while remaining > 0 {
        let rows = remaining.min(workload.accounts);
        let context = fixtures::epoch_context(
            &state,
            workload.accounts,
            epoch,
            committee,
            &operator,
            &deposits,
            &empty_withdrawals,
        );
        let batch = prepare_close_with_strategy::<Sha256, _, _, _, _>(
            &state,
            &context,
            &deposits,
            &empty_withdrawals,
            terminals(&keys, rows, &context, &operator),
            fixtures::strategy(),
        )
        .await
        .unwrap();
        assert_eq!(batch.close().rows.len(), rows);

        state = Box::pin(batch.apply(state)).await.unwrap().0;
        remaining -= rows;
        epoch += 1;
    }
    state = Box::pin(state.sync()).await.unwrap();

    // Signed full-exit requests exercise balance deletions and payout Appends when W=N.
    let deployment = *fixtures::epoch_context(
        &state,
        workload.accounts,
        epoch,
        committee,
        &operator,
        &deposits,
        &empty_withdrawals,
    )
    .deployment();
    let withdrawals = WithdrawalBatch::new(
        keys[..workload.payouts]
            .iter()
            .map(|(_, signer)| {
                SignedWithdrawal::sign(
                    deployment,
                    state.state().root().digest,
                    Bytes::from_static(b"exit-destination"),
                    WithdrawalAction::Close,
                    99,
                    signer,
                )
            })
            .collect(),
    )
    .unwrap();
    let context = fixtures::epoch_context(
        &state,
        workload.accounts,
        epoch,
        committee,
        &operator,
        &deposits,
        &withdrawals,
    );
    let material = terminals(&keys, workload.rows, &context, &operator);
    let expected = prepare_close_with_strategy::<Sha256, _, _, _, _>(
        &state,
        &context,
        &deposits,
        &withdrawals,
        material,
        fixtures::strategy(),
    )
    .await
    .unwrap();
    assert_eq!(
        expected.close().rows.len(),
        workload.rows.max(workload.payouts)
    );
    let range = expected.close().roots.activity_range(&context).unwrap();
    assert_eq!(
        range.end - range.start,
        workload.rows.max(workload.payouts) as u64
    );
    assert_eq!(
        expected.close().withdrawal_outputs().len(),
        workload.payouts
    );
    assert_eq!(
        expected.close().withdrawal_total,
        workload.payouts as u64 * fixtures::OPENING_BALANCE
    );
    let operator = compute_public::<OperatorVariant>(&Private::new(Scalar::from(1u64)));
    Input {
        state,
        context,
        deposits,
        withdrawals,
        operator,
        expected,
    }
}

#[derive(Clone, Copy)]
enum Phase {
    NativePrepare,
    Decode,
    ValidatePrepare,
    Apply,
    Commit,
    ReceiveApply,
    ReceiveCommit,
}

impl Phase {
    const ALL: [Self; 7] = [
        Self::NativePrepare,
        Self::Decode,
        Self::ValidatePrepare,
        Self::Apply,
        Self::Commit,
        Self::ReceiveApply,
        Self::ReceiveCommit,
    ];
    const fn name(self) -> &'static str {
        match self {
            Self::NativePrepare => "native_prepare_state_logs",
            Self::Decode => "decode",
            Self::ValidatePrepare => "validate_prepare_state_logs",
            Self::Apply => "apply_state_logs",
            Self::Commit => "commit_state_logs_memory",
            Self::ReceiveApply => "decode_validate_apply",
            Self::ReceiveCommit => "decode_validate_apply_commit_memory",
        }
    }
}

#[commonware_macros::boxed]
async fn measure(
    runtime: deterministic::Context,
    workload: Workload,
    phase: Phase,
    iterations: u64,
    report: bool,
) -> Duration {
    let Input {
        mut state,
        context,
        deposits,
        withdrawals,
        operator,
        expected,
    } = input(runtime, workload).await;
    let baseline = state.head();
    let expected_head = expected.replica().head();
    let encoded = expected.encoded().clone();
    let mutations = expected.state().mutations().to_vec();
    let activity = expected.close().activity_input::<Sha256>();
    let outputs = expected.close().withdrawal_outputs().to_vec();
    let mut elapsed = Duration::ZERO;
    let mut rng = TestRng::new(0);
    for iteration in 0..iterations {
        if iteration > 0 {
            state = Box::pin(state.rewind(&baseline)).await.unwrap();
            assert_eq!(state.head(), baseline);
        }
        if matches!(phase, Phase::NativePrepare) {
            let mutations = mutations.clone();
            let activity = activity.clone();
            let outputs = outputs.clone();
            let start = Instant::now();
            let batch = state
                .prepare(&baseline, mutations, activity, outputs, context.floors())
                .await
                .unwrap();
            elapsed += start.elapsed();
            assert_eq!(batch.head(), expected_head);
            state = state.apply(batch).await.unwrap();
        } else {
            let bytes = encoded.clone();
            let receive = Instant::now();
            let decoded = posted::decode(bytes, &context).unwrap();
            let decode = receive.elapsed();
            let start = Instant::now();
            let validated = validate_close_with_strategy::<Sha256, _, _, _, _, BatchVerifier, _>(
                &state,
                &context,
                &operator,
                &deposits,
                &withdrawals,
                decoded,
                &mut rng,
                fixtures::strategy(),
            )
            .await
            .unwrap();
            let validate = start.elapsed();
            let start = Instant::now();
            let (advanced, close) = Box::pin(validated.apply(state)).await.unwrap();
            let apply = start.elapsed();
            let receive_apply = receive.elapsed();
            let start = Instant::now();
            state = Box::pin(advanced.commit()).await.unwrap();
            let commit = start.elapsed();
            let receive_commit = receive.elapsed();
            elapsed += match phase {
                Phase::Decode => decode,
                Phase::ValidatePrepare => validate,
                Phase::Apply => apply,
                Phase::Commit => commit,
                Phase::ReceiveApply => receive_apply,
                Phase::ReceiveCommit => receive_commit,
                Phase::NativePrepare => unreachable!(),
            };
            assert_eq!(close.header, expected.close().header);
            black_box(close);
        }
        assert_eq!(state.head(), expected_head);
        assert_eq!(
            state.state().head().live_accounts(),
            (workload.accounts - workload.payouts) as u64
        );
        black_box(&state);
    }
    if report {
        let (_, activity_operations) = expected.replica().logs().activity_operations();
        let (activity_append_operations, activity_append_bytes) = activity_operations
            .iter()
            .filter(|operation| {
                matches!(
                    operation,
                    commonware_clearing::bajillion::logs::ActivityOperation::Append(_)
                )
            })
            .fold((0, 0), |(count, bytes), operation| {
                (count + 1, bytes + operation.encode().len())
            });
        let (_, payout_operations) = expected.replica().logs().payout_operations();
        let (payout_output_operations, payout_output_bytes) = payout_operations
            .iter()
            .filter(|operation| {
                matches!(
                    operation,
                    commonware_clearing::bajillion::logs::PayoutOperation::Append(_)
                )
            })
            .fold((0, 0), |(count, bytes), operation| {
                (count + 1, bytes + operation.encode().len())
            });
        println!(
            "native_transition {} dealing_bytes={} roots_bytes={} descriptor_bytes={} context_bytes={} row_count={} activity_append_operations={} activity_append_bytes={} activity_commit_bytes={} payout_output_operations={} payout_output_bytes={} payout_commit_bytes={} predecessor_state_operations={} predecessor_activity_operations={} predecessor_payout_operations={} successor_state_operations={} successor_activity_operations={} successor_payout_operations={} history_epochs={}",
            workload.label(),
            encoded.len(),
            expected.close().roots.encode().len(),
            expected.close().roots.encode().len() + 8,
            context.encode().len(),
            expected.close().roots.row_count,
            activity_append_operations,
            activity_append_bytes,
            activity_operations.last().unwrap().encode().len(),
            payout_output_operations,
            payout_output_bytes,
            payout_operations.last().unwrap().encode().len(),
            baseline.state.operations(),
            baseline.logs.activity.operations,
            baseline.logs.payouts.operations,
            expected_head.state.operations(),
            expected_head.logs.activity.operations,
            expected_head.logs.payouts.operations,
            workload.history.div_ceil(workload.accounts)
        );
    }
    elapsed
}

fn workloads() -> Vec<Workload> {
    let accounts = native_fixtures::accounts();
    let mut workloads = Vec::new();
    for history in native_fixtures::histories() {
        for rows in native_fixtures::rows() {
            assert!(rows <= accounts, "payment rows cannot exceed live accounts");
            for payouts in native_fixtures::payouts(accounts) {
                workloads.push(Workload {
                    accounts,
                    history,
                    rows,
                    payouts,
                });
            }
        }
    }
    workloads
}

pub(crate) fn check() {
    for workload in workloads() {
        for phase in [Phase::NativePrepare, Phase::ReceiveCommit] {
            fixtures::runner().start(|runtime| {
                measure(
                    runtime,
                    workload,
                    phase,
                    2,
                    matches!(phase, Phase::ReceiveCommit),
                )
            });
        }
    }
}

fn bench_transition(c: &mut Criterion) {
    for workload in workloads() {
        for phase in Phase::ALL {
            c.bench_function(
                &format!("{}::{}/{}", module_path!(), phase.name(), workload.label()),
                |b| {
                    b.iter_custom(|iterations| {
                        fixtures::runner()
                            .start(|runtime| measure(runtime, workload, phase, iterations, false))
                    });
                },
            );
        }
    }
}

criterion_group! { name = benches; config = Criterion::default().sample_size(10); targets = bench_transition, }
