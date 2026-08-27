use super::{
    certification, challenge as challenge_model,
    settlement::{
        Account, AccountState, Batch, BatchStatus, ChallengeKind, Deployment, DepositId,
        Destination, Fault, ForkRelation, RegistrationId, Root, SettlementAction, SettlementEdge,
        SettlementModel, SettlementState, Terminal, WithdrawalAction, WithdrawalId,
    },
};

fn step(model: SettlementModel, state: &mut SettlementState, action: SettlementAction) {
    *state = model
        .apply(state, action)
        .unwrap_or_else(|| panic!("expected action to succeed: {action:?}\nstate: {state:#?}"));
}

fn rejected(model: SettlementModel, state: &SettlementState, action: SettlementAction) {
    assert!(
        model.apply(state, action).is_none(),
        "expected action to be rejected: {action:?}\nstate: {state:#?}"
    );
}

fn rejected_unchanged(model: SettlementModel, state: &SettlementState, action: SettlementAction) {
    let snapshot = state.clone();
    rejected(model, state, action);
    assert_eq!(state, &snapshot);
}

fn register_and_admit(model: SettlementModel, state: &mut SettlementState, batch: Batch) {
    step(
        model,
        state,
        SettlementAction::Register(batch.registration()),
    );
    step(model, state, admission(batch));
}

fn admission(batch: Batch) -> SettlementAction {
    let certified = certification::certify_close(batch.registration(), batch)
        .expect("the fixture candidate matches its registration");
    SettlementAction::Admit(certified)
}

fn proven_challenge(batch: Batch, kind: ChallengeKind) -> SettlementAction {
    let proven = challenge_model::adjudicated_proven_challenges(batch)
        .into_iter()
        .find(|proven| proven.kind() == kind)
        .expect("the finite challenge model proves this endpoint");
    SettlementAction::Challenge(proven)
}

fn queue_withdrawal(model: SettlementModel, state: &mut SettlementState, id: WithdrawalId) {
    let attempt = SettlementModel::withdrawal_attempt(state, id);
    step(model, state, SettlementAction::QueueWithdrawal(attempt));
}

const fn withdrawal_claim(batch: Batch) -> SettlementAction {
    let position = batch
        .candidate()
        .withdrawal_output
        .expect("the fixture has a withdrawal output")
        .position;
    SettlementAction::ClaimWithdrawal {
        batch,
        source: batch,
        position,
    }
}

const fn payout_claim(batch: Batch) -> SettlementAction {
    let position = batch
        .candidate()
        .payout_output
        .expect("the fixture has a payout output")
        .position;
    SettlementAction::ClaimPayout {
        batch,
        source: batch,
        position,
    }
}

#[test]
fn rejected_candidate_preserves_the_exact_live_registration() {
    let model = SettlementModel::default();
    let mut state = SettlementState::default();
    step(
        model,
        &mut state,
        SettlementAction::RecordDeposit(DepositId::BobTwo),
    );
    step(
        model,
        &mut state,
        SettlementAction::Register(RegistrationId::B0),
    );

    let registered = state.clone();
    rejected(model, &state, admission(Batch::Offset));
    assert_eq!(state, registered);

    step(model, &mut state, admission(Batch::B0));
    assert_eq!(state.registered, None);
    assert_eq!(state.pipeline, vec![Batch::B0]);
}

#[test]
fn invalid_withdrawal_authorization_dimensions_do_not_mutate_state() {
    let model = SettlementModel::default();
    let state = SettlementState::default();
    let valid = SettlementModel::withdrawal_attempt(&state, WithdrawalId::CloseAfterFault);

    // Signed request and destination predicates fail before intake state changes.
    let mut invalid_signature = valid;
    invalid_signature.request.signature_valid = false;
    rejected_unchanged(
        model,
        &state,
        SettlementAction::QueueWithdrawal(invalid_signature),
    );

    let mut wrong_deployment = valid;
    wrong_deployment.request.deployment = Deployment::Other;
    wrong_deployment.replay_key = wrong_deployment.request.replay_key();
    rejected_unchanged(
        model,
        &state,
        SettlementAction::QueueWithdrawal(wrong_deployment),
    );

    let mut wrong_context = valid;
    wrong_context.request.context_root = Root::R1;
    wrong_context.replay_key = wrong_context.request.replay_key();
    rejected_unchanged(
        model,
        &state,
        SettlementAction::QueueWithdrawal(wrong_context),
    );

    let mut oversized_destination = valid;
    oversized_destination.request.destination = Destination::TooLong;
    oversized_destination.replay_key = oversized_destination.request.replay_key();
    rejected_unchanged(
        model,
        &state,
        SettlementAction::QueueWithdrawal(oversized_destination),
    );

    let mut ineligible_destination = valid;
    ineligible_destination.destination_eligible = false;
    rejected_unchanged(
        model,
        &state,
        SettlementAction::QueueWithdrawal(ineligible_destination),
    );

    // Every safety root requires one authenticated opening for the exact account and state.
    let mut wrong_count = valid;
    wrong_count.safety_openings[0] = None;
    rejected_unchanged(
        model,
        &state,
        SettlementAction::QueueWithdrawal(wrong_count),
    );

    let mut extra_opening = valid;
    extra_opening.safety_openings[1] = extra_opening.safety_openings[0];
    rejected_unchanged(
        model,
        &state,
        SettlementAction::QueueWithdrawal(extra_opening),
    );

    let mut unauthenticated = valid;
    unauthenticated.safety_openings[0]
        .as_mut()
        .unwrap()
        .authenticated_state = false;
    rejected_unchanged(
        model,
        &state,
        SettlementAction::QueueWithdrawal(unauthenticated),
    );

    let mut wrong_account = valid;
    wrong_account.safety_openings[0].as_mut().unwrap().account = Account::Bob;
    rejected_unchanged(
        model,
        &state,
        SettlementAction::QueueWithdrawal(wrong_account),
    );

    let mut wrong_root = valid;
    wrong_root.safety_openings[0].as_mut().unwrap().root = Root::R1;
    rejected_unchanged(model, &state, SettlementAction::QueueWithdrawal(wrong_root));

    let mut wrong_state = valid;
    wrong_state.safety_openings[0].as_mut().unwrap().state = AccountState {
        active: false,
        balance: 0,
    };
    rejected_unchanged(
        model,
        &state,
        SettlementAction::QueueWithdrawal(wrong_state),
    );

    // Replay identity binds the full body, whose action must be affordable at every safety root.
    let mut mismatched_replay_key = valid;
    mismatched_replay_key.request.action = WithdrawalAction::Amount(1);
    rejected_unchanged(
        model,
        &state,
        SettlementAction::QueueWithdrawal(mismatched_replay_key),
    );

    let mut unaffordable_current = valid;
    unaffordable_current.request.action = WithdrawalAction::Amount(11);
    unaffordable_current.replay_key = unaffordable_current.request.replay_key();
    rejected_unchanged(
        model,
        &state,
        SettlementAction::QueueWithdrawal(unaffordable_current),
    );

    let mut zero_amount = valid;
    zero_amount.request.action = WithdrawalAction::Amount(0);
    zero_amount.replay_key = zero_amount.request.replay_key();
    rejected_unchanged(
        model,
        &state,
        SettlementAction::QueueWithdrawal(zero_amount),
    );

    let mut too_soon = valid;
    too_soon.request.deadline = 1;
    too_soon.replay_key = too_soon.request.replay_key();
    rejected_unchanged(model, &state, SettlementAction::QueueWithdrawal(too_soon));

    let mut too_late = valid;
    too_late.request.deadline = 13;
    too_late.replay_key = too_late.request.replay_key();
    rejected_unchanged(model, &state, SettlementAction::QueueWithdrawal(too_late));

    let mut with_successor = SettlementState::default();
    step(
        model,
        &mut with_successor,
        SettlementAction::RecordDeposit(DepositId::BobTwo),
    );
    register_and_admit(model, &mut with_successor, Batch::B0);
    let mut unaffordable_successor =
        SettlementModel::withdrawal_attempt(&with_successor, WithdrawalId::CloseAfterFault);
    unaffordable_successor.request.action = WithdrawalAction::Amount(9);
    unaffordable_successor.replay_key = unaffordable_successor.request.replay_key();
    rejected_unchanged(
        model,
        &with_successor,
        SettlementAction::QueueWithdrawal(unaffordable_successor),
    );

    register_and_admit(model, &mut with_successor, Batch::B1);
    let mut unaffordable_tail =
        SettlementModel::withdrawal_attempt(&with_successor, WithdrawalId::CloseAfterFault);
    unaffordable_tail.request.action = WithdrawalAction::Amount(8);
    unaffordable_tail.replay_key = unaffordable_tail.request.replay_key();
    rejected_unchanged(
        model,
        &with_successor,
        SettlementAction::QueueWithdrawal(unaffordable_tail),
    );

    let mut accepted = state;
    step(
        model,
        &mut accepted,
        SettlementAction::QueueWithdrawal(valid),
    );
    rejected_unchanged(model, &accepted, SettlementAction::QueueWithdrawal(valid));
}

fn admit_first_three(model: SettlementModel) -> SettlementState {
    let mut state = SettlementState::default();
    step(
        model,
        &mut state,
        SettlementAction::RecordDeposit(DepositId::BobTwo),
    );
    register_and_admit(model, &mut state, Batch::B0);
    register_and_admit(model, &mut state, Batch::B1);
    queue_withdrawal(model, &mut state, WithdrawalId::Amount);
    register_and_admit(model, &mut state, Batch::B2);
    state
}

fn finalize_b0(model: SettlementModel, state: &mut SettlementState) {
    if state.now < 5 {
        step(model, state, SettlementAction::Observe(5));
    }
    step(model, state, SettlementAction::Finalize);
    assert_eq!(state.last, SettlementEdge::Finalize(Batch::B0));
}

fn drain_terminal(model: SettlementModel, state: &mut SettlementState) {
    if state.terminal == Terminal::Dormant {
        step(model, state, SettlementAction::BeginTerminal);
        let initialized = state.clone();
        step(model, state, SettlementAction::BeginTerminal);
        assert_eq!(state, &initialized);
    }
    for account in [Account::Alice, Account::Bob, Account::Carol] {
        if let Some(next) = model.apply(state, SettlementAction::ClaimDeposit(account)) {
            *state = next;
        }
        if let Some(next) = model.apply(state, SettlementAction::ClaimState(account)) {
            *state = next;
        }
    }
    assert_eq!(state.terminal, Terminal::Settled);
    assert_eq!(state.custody, 0);
}

#[test]
fn skipped_registration_and_out_of_order_settlement_are_rejected() {
    let model = SettlementModel::default();
    let mut state = SettlementState::default();
    rejected(
        model,
        &state,
        SettlementAction::Register(RegistrationId::B1),
    );
    step(
        model,
        &mut state,
        SettlementAction::RecordDeposit(DepositId::BobTwo),
    );
    register_and_admit(model, &mut state, Batch::B0);
    rejected(
        model,
        &state,
        SettlementAction::Register(RegistrationId::B2),
    );
    register_and_admit(model, &mut state, Batch::B1);

    step(model, &mut state, SettlementAction::Observe(6));
    step(model, &mut state, SettlementAction::Finalize);
    assert_eq!(state.expected_epoch, 1);
    assert_eq!(state.current_root, Batch::B0.candidate().successor);
    step(model, &mut state, SettlementAction::Finalize);
    assert_eq!(state.expected_epoch, 2);
    assert_eq!(state.current_root, Batch::B1.candidate().successor);
}

#[test]
fn admission_and_challenge_boundaries_are_inclusive() {
    let model = SettlementModel::default();
    let mut registered = SettlementState::default();
    step(model, &mut registered, SettlementAction::Observe(1));
    step(
        model,
        &mut registered,
        SettlementAction::RecordDeposit(DepositId::BobTwo),
    );
    step(model, &mut registered, SettlementAction::Observe(2));
    step(
        model,
        &mut registered,
        SettlementAction::Register(RegistrationId::B0),
    );

    let mut admitted = registered.clone();
    step(model, &mut admitted, admission(Batch::B0));
    assert_eq!(admitted.last, SettlementEdge::Admit(Batch::B0));
    step(model, &mut admitted, SettlementAction::Observe(4));
    step(
        model,
        &mut admitted,
        proven_challenge(
            Batch::B0,
            ChallengeKind::ReceiptFork(ForkRelation::SameIndex),
        ),
    );

    let (late, admitted_late) = model.call_at(&registered, 3, admission(Batch::B0));
    assert!(!admitted_late);
    assert!(matches!(
        late.fault,
        Fault::ExpiredRegistration {
            registration: RegistrationId::B0,
            expired_at: 2,
            ..
        }
    ));
    assert_eq!(late.registered, None);

    let mut clean = SettlementState::default();
    step(
        model,
        &mut clean,
        SettlementAction::RecordDeposit(DepositId::BobTwo),
    );
    register_and_admit(model, &mut clean, Batch::B0);
    step(model, &mut clean, SettlementAction::Observe(4));
    rejected(model, &clean, SettlementAction::Finalize);
    step(model, &mut clean, SettlementAction::Observe(5));
    step(model, &mut clean, SettlementAction::Finalize);
}

#[test]
fn configured_pipeline_capacity_is_a_hard_admission_bound() {
    let model = SettlementModel::with_max_pending(2);
    let mut state = SettlementState::default();
    step(
        model,
        &mut state,
        SettlementAction::RecordDeposit(DepositId::BobTwo),
    );
    register_and_admit(model, &mut state, Batch::B0);
    register_and_admit(model, &mut state, Batch::B1);
    queue_withdrawal(model, &mut state, WithdrawalId::Amount);
    rejected(
        model,
        &state,
        SettlementAction::Register(RegistrationId::B2),
    );
    assert_eq!(state.pipeline, vec![Batch::B0, Batch::B1]);
}

#[test]
fn open_registration_slot_has_no_heartbeat() {
    let model = SettlementModel::default();
    let mut state = SettlementState::default();
    step(model, &mut state, SettlementAction::Observe(12));
    assert_eq!(state.fault, Fault::Healthy);
    assert_eq!(state.registered, None);

    rejected(
        model,
        &state,
        SettlementAction::Register(RegistrationId::B1),
    );
    assert_eq!(state.fault, Fault::Healthy);
    assert_eq!(state.registered, None);
}

#[test]
fn expired_registration_is_permanent_and_recovers_every_sender_bucket() {
    let model = SettlementModel::default();
    let mut state = SettlementState::default();
    step(
        model,
        &mut state,
        SettlementAction::RecordDeposit(DepositId::BobTwo),
    );
    queue_withdrawal(model, &mut state, WithdrawalId::Offset);
    step(
        model,
        &mut state,
        SettlementAction::Register(RegistrationId::Offset),
    );
    step(model, &mut state, SettlementAction::Observe(2));
    assert!(matches!(
        state.fault,
        Fault::ExpiredRegistration {
            registration: RegistrationId::Offset,
            expired_at: 1,
            ..
        }
    ));
    assert_eq!(state.admission_fence_epoch, Some(0));
    rejected(
        model,
        &state,
        SettlementAction::Register(RegistrationId::Offset),
    );
    rejected(model, &state, admission(Batch::Offset));

    step(
        model,
        &mut state,
        SettlementAction::ClaimDeposit(Account::Bob),
    );
    assert_eq!(state.refunded_deposits[Account::Bob as usize], 2);
    step(model, &mut state, SettlementAction::BeginTerminal);
    step(
        model,
        &mut state,
        SettlementAction::ClaimState(Account::Alice),
    );
    step(
        model,
        &mut state,
        SettlementAction::ClaimState(Account::Bob),
    );
    assert_eq!(state.terminal_withdrawals[Account::Bob as usize], 2);
    assert_eq!(state.terminal_residuals[Account::Bob as usize], 3);
    assert_eq!(state.recovered_state[Account::Alice as usize], 10);
    assert_eq!(state.recovered_state[Account::Bob as usize], 5);
    assert_eq!(state.released, state.total_in);
    assert_eq!(state.terminal, Terminal::Settled);
    rejected(model, &state, SettlementAction::ClaimState(Account::Bob));
}

#[test]
fn simultaneous_faults_use_registration_then_withdrawal_then_deposit_priority() {
    let model = SettlementModel::default();

    // Registration wins when all three obligations first expire together, even if observed late.
    let mut all_three = SettlementState::default();
    step(
        model,
        &mut all_three,
        SettlementAction::RecordDeposit(DepositId::BobTwo),
    );
    queue_withdrawal(model, &mut all_three, WithdrawalId::Offset);
    step(
        model,
        &mut all_three,
        SettlementAction::Register(RegistrationId::Offset),
    );
    step(model, &mut all_three, SettlementAction::Observe(12));
    assert!(matches!(
        all_three.fault,
        Fault::ExpiredRegistration {
            registration: RegistrationId::Offset,
            expired_at: 1,
            ..
        }
    ));

    // Registration also wins the exact two-way tie with a deposit.
    let mut registration_deposit = SettlementState::default();
    step(
        model,
        &mut registration_deposit,
        SettlementAction::Observe(1),
    );
    step(
        model,
        &mut registration_deposit,
        SettlementAction::RecordDeposit(DepositId::BobTwo),
    );
    step(
        model,
        &mut registration_deposit,
        SettlementAction::Register(RegistrationId::B0),
    );
    step(
        model,
        &mut registration_deposit,
        SettlementAction::Observe(12),
    );
    assert!(matches!(
        registration_deposit.fault,
        Fault::ExpiredRegistration {
            registration: RegistrationId::B0,
            expired_at: 2,
            ..
        }
    ));

    // Without a registration, withdrawal attribution wins a withdrawal/deposit tie.
    let mut withdrawal = SettlementState::default();
    step(
        model,
        &mut withdrawal,
        SettlementAction::RecordDeposit(DepositId::BobTwo),
    );
    queue_withdrawal(model, &mut withdrawal, WithdrawalId::Offset);
    step(model, &mut withdrawal, SettlementAction::Observe(12));
    assert_eq!(
        withdrawal.fault,
        Fault::ExpiredWithdrawal {
            account: Account::Bob,
            expired_at: 2,
        }
    );

    let mut deposit = SettlementState::default();
    step(
        model,
        &mut deposit,
        SettlementAction::RecordDeposit(DepositId::AliceOne),
    );
    step(model, &mut deposit, SettlementAction::Observe(12));
    assert_eq!(
        deposit.fault,
        Fault::ExpiredDeposit {
            account: Account::Alice,
            expired_at: 2,
        }
    );
}

#[test]
fn every_receipt_contradiction_releases_the_frozen_sender() {
    let model = SettlementModel::default();
    for kind in ChallengeKind::ALL {
        let mut state = SettlementState::default();
        step(
            model,
            &mut state,
            SettlementAction::RecordDeposit(DepositId::BobTwo),
        );
        register_and_admit(model, &mut state, Batch::B0);
        register_and_admit(model, &mut state, Batch::B1);
        finalize_b0(model, &mut state);
        step(model, &mut state, proven_challenge(Batch::B1, kind));
        drain_terminal(model, &mut state);
        assert_eq!(
            state.recovered_state[Account::Alice as usize],
            8,
            "{kind:?}"
        );
        assert_eq!(state.recovered_state[Account::Bob as usize], 9, "{kind:?}");
        assert_eq!(state.claimable, 0, "{kind:?}");
        assert_eq!(state.released, state.total_in, "{kind:?}");
    }
}

#[test]
fn front_fault_restores_the_sender_and_refunds_the_admitted_deposit() {
    let model = SettlementModel::default();
    let mut state = admit_first_three(model);
    step(
        model,
        &mut state,
        proven_challenge(Batch::B0, ChallengeKind::LatestAcknowledgedSend),
    );
    assert_eq!(state.clean_prefix_len, 0);
    assert_eq!(
        state.status[Batch::B1.index()],
        BatchStatus::Invalidated(Batch::B0)
    );
    assert_eq!(
        state.status[Batch::B2.index()],
        BatchStatus::Invalidated(Batch::B0)
    );
    drain_terminal(model, &mut state);
    assert_eq!(state.recovered_state[Account::Alice as usize], 10);
    assert_eq!(state.recovered_state[Account::Bob as usize], 5);
    assert_eq!(state.refunded_deposits[Account::Bob as usize], 2);
    assert_eq!(state.terminal_withdrawals[Account::Bob as usize], 2);
    assert_eq!(state.released, state.total_in);
}

#[test]
fn amountless_close_sweeps_the_frozen_epoch_tail_after_operator_failure() {
    let model = SettlementModel::default();
    let mut state = SettlementState::default();
    queue_withdrawal(model, &mut state, WithdrawalId::CloseAfterFault);
    step(model, &mut state, SettlementAction::Observe(11));
    assert_eq!(
        state.fault,
        Fault::ExpiredWithdrawal {
            account: Account::Alice,
            expired_at: 11,
        }
    );
    drain_terminal(model, &mut state);
    assert_eq!(state.terminal_withdrawals[Account::Alice as usize], 10);
    assert_eq!(state.terminal_residuals[Account::Alice as usize], 0);
    assert_eq!(state.terminal_residuals[Account::Bob as usize], 5);
    assert_eq!(state.released, state.total_in);
}

#[test]
fn wrong_batch_and_expired_challenge_do_not_change_status() {
    let model = SettlementModel::default();
    let mut state = SettlementState::default();
    step(
        model,
        &mut state,
        SettlementAction::RecordDeposit(DepositId::BobTwo),
    );
    register_and_admit(model, &mut state, Batch::B0);
    let snapshot = state.clone();
    rejected(
        model,
        &state,
        proven_challenge(Batch::B1, ChallengeKind::LatestAcknowledgedSend),
    );
    assert_eq!(state, snapshot);

    step(model, &mut state, SettlementAction::Observe(5));
    let snapshot = state.clone();
    rejected(
        model,
        &state,
        proven_challenge(Batch::B0, ChallengeKind::LatestAcknowledgedSend),
    );
    assert_eq!(state, snapshot);
}

#[test]
fn middle_fault_preserves_only_the_clean_fifo_prefix() {
    let model = SettlementModel::default();
    let mut state = admit_first_three(model);
    step(model, &mut state, SettlementAction::Observe(4));
    step(
        model,
        &mut state,
        proven_challenge(
            Batch::B1,
            ChallengeKind::ReceiptFork(ForkRelation::SameSend),
        ),
    );
    assert_eq!(state.status[Batch::B0.index()], BatchStatus::Pending);
    assert!(matches!(
        state.status[Batch::B1.index()],
        BatchStatus::Challenged(_)
    ));
    assert_eq!(
        state.status[Batch::B2.index()],
        BatchStatus::Invalidated(Batch::B1)
    );
    rejected(model, &state, SettlementAction::BeginTerminal);
    finalize_b0(model, &mut state);
    drain_terminal(model, &mut state);
    assert_eq!(state.recovered_state[Account::Alice as usize], 8);
    assert_eq!(state.recovered_state[Account::Bob as usize], 9);
    assert_eq!(state.terminal_withdrawals[Account::Bob as usize], 2);
    assert_eq!(state.terminal_residuals[Account::Bob as usize], 7);
    assert_eq!(state.released, state.total_in);
}

#[test]
fn tail_fault_precedes_and_drains_its_two_batch_clean_prefix() {
    let model = SettlementModel::default();
    let mut state = admit_first_three(model);

    // Fault the tail while both clean predecessors remain pending.
    step(
        model,
        &mut state,
        proven_challenge(Batch::B2, ChallengeKind::HigherShardTip),
    );
    assert_eq!(state.clean_prefix_len, 2);
    assert_eq!(state.status[Batch::B0.index()], BatchStatus::Pending);
    assert_eq!(state.status[Batch::B1.index()], BatchStatus::Pending);

    // The permanent fence still permits the two clean epochs to finalize in FIFO order.
    step(model, &mut state, SettlementAction::Observe(5));
    step(model, &mut state, SettlementAction::Finalize);
    step(model, &mut state, SettlementAction::Observe(6));
    step(model, &mut state, SettlementAction::Finalize);
    assert_eq!(state.finalized_batches & 0b11, 0b11);

    drain_terminal(model, &mut state);
    step(model, &mut state, payout_claim(Batch::B1));
    assert_eq!(state.released, state.total_in);
}

#[test]
fn registration_expiry_drains_its_earlier_two_batch_prefix() {
    let model = SettlementModel::default();
    let mut state = SettlementState::default();
    step(
        model,
        &mut state,
        SettlementAction::RecordDeposit(DepositId::BobTwo),
    );
    register_and_admit(model, &mut state, Batch::B0);
    register_and_admit(model, &mut state, Batch::B1);
    queue_withdrawal(model, &mut state, WithdrawalId::Amount);
    step(
        model,
        &mut state,
        SettlementAction::Register(RegistrationId::B2),
    );

    // Expiry fences the registered successor without invalidating its earlier pending prefix.
    step(model, &mut state, SettlementAction::Observe(5));
    assert!(matches!(
        state.fault,
        Fault::ExpiredRegistration {
            registration: RegistrationId::B2,
            expired_at: 4,
            ..
        }
    ));
    assert_eq!(state.clean_prefix_len, 2);
    step(model, &mut state, SettlementAction::Finalize);
    step(model, &mut state, SettlementAction::Observe(6));
    step(model, &mut state, SettlementAction::Finalize);

    drain_terminal(model, &mut state);
    step(model, &mut state, payout_claim(Batch::B1));
    assert_eq!(state.released, state.total_in);
}

#[test]
fn finalized_reserve_survives_descendant_fault_and_claims_independently() {
    let model = SettlementModel::default();
    let mut state = admit_first_three(model);
    step(model, &mut state, SettlementAction::Observe(6));
    step(model, &mut state, SettlementAction::Finalize);
    step(model, &mut state, SettlementAction::Finalize);
    assert_eq!(state.payout_reserve[Batch::B1.index()], 1);
    step(
        model,
        &mut state,
        proven_challenge(Batch::B2, ChallengeKind::HigherShardTip),
    );
    drain_terminal(model, &mut state);
    assert_eq!(state.claimable, 1);
    step(model, &mut state, payout_claim(Batch::B1));
    assert_eq!(state.claimable, 0);
    assert_eq!(state.released, state.total_in);
    rejected(model, &state, payout_claim(Batch::B1));
}

#[test]
fn finalized_withdrawal_reserve_survives_a_later_malicious_close() {
    let model = SettlementModel::default();
    let mut state = admit_first_three(model);
    finalize_b0(model, &mut state);
    queue_withdrawal(model, &mut state, WithdrawalId::Close);
    register_and_admit(model, &mut state, Batch::B3);
    step(model, &mut state, SettlementAction::Observe(7));
    step(model, &mut state, SettlementAction::Finalize);
    step(model, &mut state, SettlementAction::Finalize);
    assert_eq!(state.withdrawal_reserve[Batch::B2.index()], 2);
    step(
        model,
        &mut state,
        proven_challenge(
            Batch::B3,
            ChallengeKind::ReceiptFork(ForkRelation::SameIndex),
        ),
    );
    drain_terminal(model, &mut state);
    assert_eq!(state.withdrawal_reserve[Batch::B2.index()], 2);
    step(model, &mut state, withdrawal_claim(Batch::B2));
    step(model, &mut state, payout_claim(Batch::B1));
    assert_eq!(state.released, state.total_in);
}

#[test]
fn clean_claims_require_exact_positions_and_batch_scoped_routes() {
    let model = SettlementModel::default();
    let mut state = admit_first_three(model);
    finalize_b0(model, &mut state);
    queue_withdrawal(model, &mut state, WithdrawalId::Close);
    register_and_admit(model, &mut state, Batch::B3);
    step(model, &mut state, SettlementAction::Observe(7));
    step(model, &mut state, SettlementAction::Finalize);
    step(model, &mut state, SettlementAction::Finalize);
    step(model, &mut state, SettlementAction::Observe(9));
    step(model, &mut state, SettlementAction::Finalize);

    // Wrong positions, proof roots, and claim namespaces stutter without consuming reserves.
    rejected_unchanged(
        model,
        &state,
        SettlementAction::ClaimWithdrawal {
            batch: Batch::B2,
            source: Batch::B2,
            position: 1,
        },
    );
    rejected_unchanged(
        model,
        &state,
        SettlementAction::ClaimWithdrawal {
            batch: Batch::B2,
            source: Batch::Offset,
            position: 0,
        },
    );
    rejected_unchanged(
        model,
        &state,
        SettlementAction::ClaimWithdrawal {
            batch: Batch::B2,
            source: Batch::B3,
            position: 0,
        },
    );
    rejected_unchanged(
        model,
        &state,
        SettlementAction::ClaimWithdrawal {
            batch: Batch::B1,
            source: Batch::B1,
            position: 1,
        },
    );
    rejected_unchanged(
        model,
        &state,
        SettlementAction::ClaimPayout {
            batch: Batch::B2,
            source: Batch::B2,
            position: 0,
        },
    );

    // Each exact positioned output consumes only its own batch-scoped reserve.
    step(model, &mut state, withdrawal_claim(Batch::B2));
    rejected_unchanged(model, &state, withdrawal_claim(Batch::B2));
    step(model, &mut state, withdrawal_claim(Batch::B3));
    step(model, &mut state, payout_claim(Batch::B1));
    assert_eq!(state.withdrawal_reserve, [0; 5]);
    assert_eq!(state.payout_reserve, [0; 5]);
    assert_eq!(state.clean_claim_paid, 10);
}

#[test]
fn admitted_withdrawal_expiry_supports_challenge_and_clean_finalization() {
    let model = SettlementModel::default();
    let mut admitted = SettlementState::default();
    step(
        model,
        &mut admitted,
        SettlementAction::RecordDeposit(DepositId::BobTwo),
    );
    queue_withdrawal(model, &mut admitted, WithdrawalId::Offset);
    register_and_admit(model, &mut admitted, Batch::Offset);
    step(model, &mut admitted, SettlementAction::Observe(2));
    assert_eq!(
        admitted.fault,
        Fault::ExpiredWithdrawal {
            account: Account::Bob,
            expired_at: 2,
        }
    );

    let mut challenged = admitted.clone();
    step(
        model,
        &mut challenged,
        proven_challenge(Batch::Offset, ChallengeKind::InconsistentReceiptRange),
    );
    drain_terminal(model, &mut challenged);
    assert_eq!(challenged.released, challenged.total_in);

    let mut clean = admitted;
    step(model, &mut clean, SettlementAction::Observe(4));
    step(model, &mut clean, SettlementAction::Finalize);
    assert_eq!(clean.withdrawal_reserve[Batch::Offset.index()], 2);
    drain_terminal(model, &mut clean);
    step(model, &mut clean, withdrawal_claim(Batch::Offset));
    assert_eq!(clean.released, clean.total_in);
}

#[test]
fn withdrawal_replay_ids_prune_at_the_exact_deadline_and_recheck_context_on_reuse() {
    let model = SettlementModel::default();
    let mut finalized = admit_first_three(model);
    step(model, &mut finalized, SettlementAction::Observe(7));
    step(model, &mut finalized, SettlementAction::Finalize);
    step(model, &mut finalized, SettlementAction::Finalize);
    step(model, &mut finalized, SettlementAction::Finalize);
    assert_eq!(
        finalized.withdrawal_replay_expiries[WithdrawalId::Amount.index()],
        Some(10)
    );

    // Finalization clears the obligation but retains replay protection through its deadline.
    step(model, &mut finalized, SettlementAction::Observe(9));
    let before_deadline = SettlementModel::withdrawal_attempt(&finalized, WithdrawalId::Amount);
    rejected_unchanged(
        model,
        &finalized,
        SettlementAction::QueueWithdrawal(before_deadline),
    );
    assert_eq!(
        finalized.withdrawal_replay_expiries[WithdrawalId::Amount.index()],
        Some(10)
    );

    // Exact-boundary observation prunes the ID, while the old signed context remains unusable.
    step(model, &mut finalized, SettlementAction::Observe(10));
    assert_eq!(finalized.fault, Fault::Healthy);
    assert_eq!(
        finalized.withdrawal_replay_expiries[WithdrawalId::Amount.index()],
        None
    );
    let stale_context = SettlementModel::withdrawal_attempt(&finalized, WithdrawalId::Amount);
    rejected_unchanged(
        model,
        &finalized,
        SettlementAction::QueueWithdrawal(stale_context),
    );

    // An outstanding request faults and prunes its replay ID in the same deadline observation.
    let mut expired = SettlementState::default();
    queue_withdrawal(model, &mut expired, WithdrawalId::Offset);
    assert_eq!(
        expired.withdrawal_replay_expiries[WithdrawalId::Offset.index()],
        Some(2)
    );
    step(model, &mut expired, SettlementAction::Observe(2));
    assert_eq!(
        expired.withdrawal_replay_expiries[WithdrawalId::Offset.index()],
        None
    );
    assert_eq!(
        expired.fault,
        Fault::ExpiredWithdrawal {
            account: Account::Bob,
            expired_at: 2,
        }
    );
}

#[test]
fn same_account_deposits_keep_the_earliest_deadline_and_refund_exactly() {
    let model = SettlementModel::default();
    let mut state = SettlementState::default();
    step(
        model,
        &mut state,
        SettlementAction::RecordDeposit(DepositId::BobTwo),
    );
    step(model, &mut state, SettlementAction::Observe(1));
    step(
        model,
        &mut state,
        SettlementAction::RecordDeposit(DepositId::BobOne),
    );
    assert_eq!(state.deposit_deadlines[Account::Bob as usize], Some(2));
    step(model, &mut state, SettlementAction::Observe(2));
    assert_eq!(
        state.fault,
        Fault::ExpiredDeposit {
            account: Account::Bob,
            expired_at: 2,
        }
    );
    step(
        model,
        &mut state,
        SettlementAction::ClaimDeposit(Account::Bob),
    );
    assert_eq!(state.refunded_deposits[Account::Bob as usize], 3);
    rejected(model, &state, SettlementAction::ClaimDeposit(Account::Bob));
    drain_terminal(model, &mut state);
    assert_eq!(state.released, state.total_in);
}
