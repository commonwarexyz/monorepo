use super::*;
use crate::protocol::{Protocol, wallets};
use bytes::Bytes;
use commonware_clearing::bajillion::{
    boundary::DepositRecord,
    challenge::{Challenge, ChallengeKind},
    credit::ShardSet,
    payment::{Payment, SignedReceipt, SignedSend},
    settlement::HardFaultReason,
    state::{AccountRow, Prefix, SettlementOutput},
};
use commonware_codec::Encode;
use commonware_cryptography::{Hasher, Sha256};
use commonware_utils::TestRng;
use std::num::NonZeroU64;

fn empty_root() -> VectorRoot<Digest> {
    DepositBatch::<Key>::empty().root::<Sha256>().unwrap()
}

fn admission_fixture() -> (
    Settlement,
    SettlementSubmission,
    SettlementResult,
    StateCache<Key, Digest>,
    Protocol,
    DepositEvent,
) {
    let mut settlement = Settlement::new().unwrap();
    let protocol = Protocol::new(NonZeroUsize::MIN).unwrap();
    let mut predecessor = identities()
        .into_iter()
        .map(|identity| StateLeaf {
            account: identity.key,
            state: AccountState {
                balance: INITIAL_BALANCE,
                active: true,
                ..AccountState::default()
            },
        })
        .collect::<Vec<_>>();
    predecessor.sort_unstable_by(|left, right| left.account.cmp(&right.account));
    let state = StateCache::new::<Sha256>(predecessor.clone()).unwrap();
    let account = predecessor[0].account.clone();
    let deposit = DepositEvent {
        id: Sha256::hash(&[b"admission-fixture-deposit"]),
        account: account.clone(),
        amount: 1,
    };
    settlement.deposit(deposit.clone()).unwrap();
    let deposits =
        DepositBatch::new(vec![DepositRecord::new(account.clone(), 1).unwrap()]).unwrap();
    settlement
        .register_epoch(
            0,
            400,
            deposits.root::<Sha256>().unwrap(),
            deposits.root::<Sha256>().unwrap(),
            WithdrawalBatch::empty(),
            &[],
        )
        .unwrap();

    let predecessor_state = predecessor[0].state;
    let successor_state = AccountState {
        balance: predecessor_state.balance + 1,
        ..predecessor_state
    };
    let row = AccountRow {
        account: account.clone(),
        predecessor: predecessor_state,
        successor: successor_state,
        outgoing: None,
        output: SettlementOutput::None,
        prefix: Prefix {
            deposit: 1,
            ..Prefix::default()
        },
    };
    let mut successor = predecessor;
    successor[0].state = successor_state;
    let registration = protocol
        .registration(0, deposits, WithdrawalBatch::empty(), 400)
        .unwrap();
    let prepared = protocol
        .prepare(
            registration,
            vec![deposit.clone()],
            state.leaves().to_vec(),
            vec![row],
            vec![ShardSet::empty(0, account)],
            successor,
        )
        .unwrap();
    let result = protocol.complete(prepared, &mut TestRng::new(91)).unwrap();
    let submission = SettlementSubmission::from(&result);
    (settlement, submission, result, state, protocol, deposit)
}

fn receipt_fork(result: &SettlementResult, protocol: &Protocol) -> Challenge<Key, Digest> {
    let wallets = wallets();
    let recipient = wallets[2].public_key();
    let payment = |payer: usize, amount| {
        let send = SignedSend::sign_next(
            &result.payment_context,
            wallets[payer].signer(),
            recipient.clone(),
            amount,
            0,
        )
        .unwrap();
        let receipt = SignedReceipt::issue_next::<Sha256, _>(
            &result.payment_context,
            &send,
            &recipient,
            0,
            0,
            0,
            protocol.operator(),
        )
        .unwrap();
        Payment::new::<Sha256>(&result.payment_context, send, receipt).unwrap()
    };
    Challenge::receipt_fork(&payment(0, 2), &payment(1, 3))
}

#[test]
fn replay_cache_evicts_only_its_oldest_acknowledgement() {
    let mut cache = ReplayCache::new(NonZeroUsize::new(2).unwrap());
    cache.insert(1, "one");
    cache.insert(2, "two");
    cache.insert(3, "three");

    assert_eq!(cache.get(&1), None);
    assert_eq!(cache.get(&2), Some(&"two"));
    assert_eq!(cache.get(&3), Some(&"three"));
}

#[test]
fn admission_stays_pending_through_the_inclusive_deadline() {
    let (mut settlement, submission, result, _, _, _) = admission_fixture();
    let challenge_deadline = result.epoch_context.challenge_deadline();

    assert_eq!(
        settlement.admit_submission(submission.clone()).unwrap(),
        AdmissionOutcome::Pending
    );
    assert_eq!(settlement.status().unwrap().now, challenge_deadline);
    assert_eq!(
        settlement.admit_submission(submission.clone()).unwrap(),
        AdmissionOutcome::Pending
    );

    settlement.advance_logical_time(1).unwrap();
    let finalized = match settlement.admit_submission(submission.clone()).unwrap() {
        AdmissionOutcome::Pending => panic!("admission remained pending after its deadline"),
        AdmissionOutcome::Finalized(finalized) => finalized,
    };
    assert_eq!(finalized.batch_id, result.finalized.batch_id);
    assert_eq!(
        settlement.admit_submission(submission.clone()).unwrap(),
        AdmissionOutcome::Finalized(finalized)
    );

    // Finalization retains the batch's claim roots forever, keyed by its identity.
    assert_eq!(
        settlement.claim_roots(finalized.batch_id).unwrap(),
        Some(ClaimRoots {
            withdrawal_outputs: result.roots.withdrawal_outputs,
            change: result.roots.change,
        })
    );
    assert_eq!(
        settlement
            .claim_roots(BatchId::new(Sha256::hash(&[b"unknown-claim-batch"])))
            .unwrap(),
        None
    );

    let mut conflicting = submission;
    conflicting.predecessor_liability -= 1;
    assert!(settlement.admit_submission(conflicting).is_err());
}

#[test]
fn admitted_close_finalizes_after_its_deadline_without_operator_retry() {
    let (mut settlement, submission, result, _, _, _) = admission_fixture();

    assert_eq!(
        settlement.admit_submission(submission.clone()).unwrap(),
        AdmissionOutcome::Pending
    );
    settlement.advance_logical_time(1).unwrap();

    let status = settlement.status().unwrap();
    assert_eq!(status.state_root, result.finalized.successor_root);
    assert_eq!(
        settlement.admit_submission(submission).unwrap(),
        AdmissionOutcome::Finalized(result.finalized)
    );
}

#[test]
fn proven_challenge_replays_only_for_exact_evidence_while_pending() {
    let (mut settlement, submission, result, _, protocol, _) = admission_fixture();
    let batch_id = result.finalized.batch_id;
    assert_eq!(
        settlement.admit_submission(submission).unwrap(),
        AdmissionOutcome::Pending
    );
    let evidence = receipt_fork(&result, &protocol).encode();

    let verdict = settlement
        .challenge_encoded(batch_id, evidence.clone(), evidence.len())
        .unwrap();
    assert_eq!(verdict, Verdict::Proven(ChallengeKind::ReceiptFork));
    assert_eq!(
        settlement
            .challenge_encoded(batch_id, evidence.clone(), evidence.len())
            .unwrap(),
        verdict
    );
    let mut conflicting = evidence.to_vec();
    conflicting.push(0);
    assert!(
        settlement
            .challenge_encoded(batch_id, Bytes::from(conflicting), evidence.len() + 1)
            .is_err()
    );
    assert!(settlement.status().unwrap().hard_faulted);
}

#[test]
fn hard_fault_begin_claim_and_refund_replay_after_full_settlement() {
    let (mut settlement, submission, result, state, protocol, deposit) = admission_fixture();
    let batch_id = result.finalized.batch_id;
    assert_eq!(
        settlement.admit_submission(submission).unwrap(),
        AdmissionOutcome::Pending
    );
    let evidence = receipt_fork(&result, &protocol).encode();
    assert!(matches!(
        settlement
            .challenge_encoded(batch_id, evidence.clone(), evidence.len())
            .unwrap(),
        Verdict::Proven(ChallengeKind::ReceiptFork)
    ));

    let snapshot = settlement.begin_hard_fault_settlement().unwrap();
    assert_eq!(snapshot.state_liability, 400);
    assert_eq!(snapshot.unfinalized_deposit_total, 1);
    assert_eq!(settlement.begin_hard_fault_settlement().unwrap(), snapshot);

    let openings = state
        .leaves()
        .iter()
        .map(|leaf| state.opening(&leaf.account).unwrap())
        .collect::<Vec<_>>();
    let first = settlement.claim_hard_fault(&openings[0]).unwrap();
    assert_eq!(first.released_custody, INITIAL_BALANCE);
    assert_eq!(settlement.claim_hard_fault(&openings[0]).unwrap(), first);
    let mut conflicting = openings[0].clone();
    conflicting.leaf.state.balance -= 1;
    assert!(settlement.claim_hard_fault(&conflicting).is_err());
    for opening in &openings[1..] {
        settlement.claim_hard_fault(opening).unwrap();
    }

    let refund = settlement.claim_pending_deposit(&deposit.account).unwrap();
    assert_eq!(refund.amount, deposit.amount);
    assert_eq!(settlement.status().unwrap().custody_balance, 0);
    assert_eq!(
        settlement
            .challenge_encoded(batch_id, evidence.clone(), evidence.len())
            .unwrap(),
        Verdict::Proven(ChallengeKind::ReceiptFork)
    );
    assert_eq!(settlement.begin_hard_fault_settlement().unwrap(), snapshot);
    assert_eq!(settlement.claim_hard_fault(&openings[0]).unwrap(), first);
    assert_eq!(
        settlement.claim_pending_deposit(&deposit.account).unwrap(),
        refund
    );
}

#[test]
fn deposit_ids_are_idempotent_but_bound_to_one_event() {
    let mut settlement = Settlement::new().unwrap();
    let account = identities()[0].key.clone();
    let event = DepositEvent {
        id: Sha256::hash(&[b"deposit-id"]),
        account,
        amount: 7,
    };
    settlement.deposit(event.clone()).unwrap();
    settlement.deposit(event.clone()).unwrap();
    assert_eq!(
        settlement.confirm_deposit(&event).unwrap(),
        DepositPresence::Recorded
    );

    let conflicting = DepositEvent { amount: 8, ..event };
    assert!(settlement.deposit(conflicting.clone()).is_err());
    assert!(settlement.confirm_deposit(&conflicting).is_err());
    assert_eq!(settlement.status().unwrap().custody_balance, 407);
}

#[test]
fn deposit_rejects_values_outside_the_operator_storage_domain() {
    let mut settlement = Settlement::new().unwrap();
    let before = settlement.status().unwrap();
    let event = DepositEvent {
        id: Sha256::hash(&[b"oversized-deposit"]),
        account: identities()[0].key.clone(),
        amount: i64::MAX as u64,
    };

    assert!(settlement.deposit(event.clone()).is_err());
    assert_eq!(
        settlement.confirm_deposit(&event).unwrap(),
        DepositPresence::Unknown
    );
    assert_eq!(
        settlement.status().unwrap().custody_balance,
        before.custody_balance
    );
}

#[test]
fn epoch_registration_is_idempotent_and_rejects_late_custody_events() {
    let mut settlement = Settlement::new().unwrap();
    settlement
        .register_epoch(
            0,
            400,
            empty_root(),
            empty_root(),
            WithdrawalBatch::empty(),
            &[],
        )
        .unwrap();
    settlement
        .register_epoch(
            0,
            400,
            empty_root(),
            empty_root(),
            WithdrawalBatch::empty(),
            &[],
        )
        .unwrap();
    let event = DepositEvent {
        id: Sha256::hash(&[b"late-deposit"]),
        account: identities()[0].key.clone(),
        amount: 1,
    };
    assert!(settlement.deposit(event).is_err());
}

#[test]
fn epoch_registration_activates_its_exact_payment_anchor() {
    let mut settlement = Settlement::new().unwrap();
    let deposits = DepositBatch::empty();
    let withdrawals = WithdrawalBatch::empty();
    let context = epoch_context(0, &deposits, &withdrawals, 400).unwrap();
    let anchor = *context.payment().anchor();
    let admission_deadline = context.admission_deadline();

    settlement
        .register_epoch(0, 400, empty_root(), empty_root(), withdrawals, &[])
        .unwrap();

    assert_eq!(
        settlement
            .chain
            .fault_expired(admission_deadline + 1)
            .unwrap(),
        HardFaultReason::ExpiredRegistration {
            anchor,
            epoch: 0,
            expired_at: admission_deadline,
        }
    );
}

#[test]
fn registration_query_is_exact_retryable_and_rejects_fault() {
    let mut settlement = Settlement::new().unwrap();
    let predecessor_state_root = settlement.status().unwrap().state_root;
    let deposits = DepositBatch::empty();
    let withdrawals = WithdrawalBatch::empty();
    let context = epoch_context(0, &deposits, &withdrawals, 400).unwrap();
    let anchor = *context.payment().anchor();

    assert!(
        settlement
            .confirm_registration(0, &anchor, &predecessor_state_root)
            .is_err()
    );
    settlement
        .register_epoch(0, 400, empty_root(), empty_root(), withdrawals, &[])
        .unwrap();
    for _ in 0..2 {
        settlement
            .confirm_registration(0, &anchor, &predecessor_state_root)
            .unwrap();
    }
    assert!(
        settlement
            .confirm_registration(1, &anchor, &predecessor_state_root)
            .is_err()
    );
    assert!(
        settlement
            .confirm_registration(
                0,
                &Sha256::hash(&[b"another-payment-anchor"]),
                &predecessor_state_root,
            )
            .is_err()
    );
    assert!(
        settlement
            .confirm_registration(
                0,
                &anchor,
                &VectorRoot {
                    digest: Sha256::hash(&[b"another-predecessor-state-root"]),
                },
            )
            .is_err()
    );

    settlement
        .advance_logical_time(context.admission_deadline() + 1)
        .unwrap();
    assert!(settlement.status().unwrap().hard_faulted);
    assert!(
        settlement
            .confirm_registration(0, &anchor, &predecessor_state_root)
            .is_err()
    );
}

#[test]
fn registration_query_is_live_through_admission_only() {
    let (mut settlement, submission, result, _, _, _) = admission_fixture();
    let epoch = result.payment_context.epoch();
    let anchor = *result.payment_context.anchor();

    settlement
        .confirm_registration(epoch, &anchor, &result.predecessor_root)
        .unwrap();
    assert_eq!(
        settlement.admit_submission(submission).unwrap(),
        AdmissionOutcome::Pending
    );
    settlement
        .confirm_registration(epoch, &anchor, &result.predecessor_root)
        .unwrap();

    // Finalization retires the live slot. A send resolved after the cut concludes
    // commitment from the finalized root instead of this query.
    settlement.advance_logical_time(1).unwrap();
    assert!(settlement.registered.is_none());
    assert!(
        settlement
            .confirm_registration(epoch, &anchor, &result.predecessor_root)
            .is_err()
    );
    assert_eq!(settlement.status().unwrap().last_finalized, Some(epoch));
}

#[test]
fn idle_open_slot_has_no_logical_clock_obligation() {
    let mut settlement = Settlement::new().unwrap();

    settlement.advance_logical_time(u64::MAX).unwrap();

    let status = settlement.status().unwrap();
    assert_eq!(status.now, 0);
    assert!(!status.hard_faulted);
}

#[test]
fn delayed_registration_remains_available_while_deposit_is_live() {
    let mut settlement = Settlement::new().unwrap();
    settlement
        .deposit(DepositEvent {
            id: Sha256::hash(&[b"delayed-registration-deposit"]),
            account: identities()[0].key.clone(),
            amount: 7,
        })
        .unwrap();

    settlement.advance_logical_time(2).unwrap();
    let status = settlement.status().unwrap();
    assert_eq!(status.now, 2);
    assert!(!status.hard_faulted);

    let deposits_root = settlement
        .chain
        .pending_deposits()
        .root::<Sha256>()
        .unwrap();
    settlement
        .register_epoch(
            0,
            400,
            deposits_root,
            deposits_root,
            WithdrawalBatch::empty(),
            &[],
        )
        .unwrap();
    assert_eq!(settlement.registered.as_ref().unwrap().epoch, 0);
}

#[test]
fn delayed_registration_remains_available_while_withdrawal_is_live() {
    let mut settlement = Settlement::new().unwrap();
    let wallet = crate::protocol::wallets().remove(0);
    let mut leaves = identities()
        .into_iter()
        .map(|identity| StateLeaf {
            account: identity.key,
            state: AccountState {
                balance: INITIAL_BALANCE,
                active: true,
                ..AccountState::default()
            },
        })
        .collect::<Vec<_>>();
    leaves.sort_unstable_by(|left, right| left.account.cmp(&right.account));
    let cache = StateCache::new::<Sha256>(leaves).unwrap();
    let account = wallet.public_key();
    let request = SignedWithdrawal::sign(
        deployment(),
        cache.root().digest,
        Bytes::from_static(b"delayed-withdrawal"),
        WithdrawalAction::Amount(NonZeroU64::new(7).unwrap()),
        50,
        wallet.signer(),
    );
    let opening = cache.opening(&account).unwrap();
    settlement.queue_withdrawal(request, vec![opening]).unwrap();

    settlement.advance_logical_time(2).unwrap();
    let status = settlement.status().unwrap();
    assert_eq!(status.now, 2);
    assert!(!status.hard_faulted);

    let withdrawals = settlement.chain.pending_withdrawals();
    settlement
        .register_epoch(0, 400, empty_root(), empty_root(), withdrawals, &[])
        .unwrap();
    assert_eq!(settlement.registered.as_ref().unwrap().epoch, 0);
}

#[test]
fn divergent_deposit_boundary_is_rejected_without_consuming_the_slot() {
    let mut settlement = Settlement::new().unwrap();
    let event = DepositEvent {
        id: Sha256::hash(&[b"lost-apply-window-deposit"]),
        account: identities()[0].key.clone(),
        amount: 7,
    };
    settlement.deposit(event).unwrap();

    // An operator whose credit was lost still believes the boundary is empty. The
    // divergent commitment fails cleanly and keeps the slot open.
    let error = settlement
        .register_epoch(
            0,
            400,
            empty_root(),
            empty_root(),
            WithdrawalBatch::empty(),
            &[],
        )
        .unwrap_err();
    assert!(
        format!("{error:#}").contains("operator staged deposits differ from settlement"),
        "unexpected error: {error:#}"
    );
    assert!(settlement.registered.is_none());

    // After the operator applies the deposit, its healed view registers the epoch.
    let deposits_root = settlement
        .chain
        .pending_deposits()
        .root::<Sha256>()
        .unwrap();
    settlement
        .register_epoch(
            0,
            400,
            deposits_root,
            deposits_root,
            WithdrawalBatch::empty(),
            &[],
        )
        .unwrap();
    assert_eq!(settlement.registered.as_ref().unwrap().epoch, 0);
}

#[test]
fn carried_offset_withdrawal_defers_the_staged_deposit_and_registers() {
    let mut settlement = Settlement::new().unwrap();
    let signers = wallets();
    let account = signers[0].public_key();
    settlement
        .deposit(DepositEvent {
            id: Sha256::hash(&[b"carried-offset-deposit"]),
            account: account.clone(),
            amount: 7,
        })
        .unwrap();

    let mut leaves = identities()
        .into_iter()
        .map(|identity| StateLeaf {
            account: identity.key,
            state: AccountState {
                balance: INITIAL_BALANCE,
                active: true,
                ..AccountState::default()
            },
        })
        .collect::<Vec<_>>();
    leaves.sort_unstable_by(|left, right| left.account.cmp(&right.account));
    let cache = StateCache::new::<Sha256>(leaves).unwrap();

    // A carried extra exactly offsetting the staged deposit reaches the chain at
    // registration. The chain defers the deposit to a successor epoch, and the
    // boundary this epoch registers is empty.
    let carried = SignedWithdrawal::sign(
        deployment(),
        cache.root().digest,
        Bytes::from_static(b"carried-offset-withdrawal"),
        WithdrawalAction::Amount(NonZeroU64::new(7).unwrap()),
        50,
        signers[0].signer(),
    );
    let withdrawals = WithdrawalBatch::new(vec![carried]).unwrap();
    assert_eq!(
        settlement
            .chain
            .boundary_deposits(&withdrawals)
            .root::<Sha256>()
            .unwrap(),
        empty_root()
    );
    let staged_root = settlement
        .chain
        .boundary_deposits(&WithdrawalBatch::empty())
        .root::<Sha256>()
        .unwrap();
    settlement
        .register_epoch(
            0,
            400,
            empty_root(),
            staged_root,
            withdrawals,
            &[cache.opening(&account).unwrap()],
        )
        .unwrap();
    assert_eq!(settlement.registered.as_ref().unwrap().epoch, 0);
    assert_eq!(settlement.chain.pending_deposits().amount_for(&account), 7);
}

#[test]
fn register_epoch_carries_extras_but_requires_every_queued_withdrawal() {
    let mut settlement = Settlement::new().unwrap();
    let signers = wallets();
    let mut leaves = identities()
        .into_iter()
        .map(|identity| StateLeaf {
            account: identity.key,
            state: AccountState {
                balance: INITIAL_BALANCE,
                active: true,
                ..AccountState::default()
            },
        })
        .collect::<Vec<_>>();
    leaves.sort_unstable_by(|left, right| left.account.cmp(&right.account));
    let cache = StateCache::new::<Sha256>(leaves).unwrap();
    let queued_account = signers[0].public_key();
    let queued = SignedWithdrawal::sign(
        deployment(),
        cache.root().digest,
        Bytes::from_static(b"queued-withdrawal"),
        WithdrawalAction::Amount(NonZeroU64::new(7).unwrap()),
        50,
        signers[0].signer(),
    );
    let opening = cache.opening(&queued_account).unwrap();
    settlement
        .queue_withdrawal(queued.clone(), vec![opening])
        .unwrap();

    let error = settlement
        .register_epoch(
            0,
            400,
            empty_root(),
            empty_root(),
            WithdrawalBatch::empty(),
            &[],
        )
        .unwrap_err();
    assert!(
        format!("{error:#}").contains("omits a queued settlement withdrawal"),
        "unexpected error: {error:#}"
    );

    let carried_account = signers[1].public_key();
    let carried = SignedWithdrawal::sign(
        deployment(),
        cache.root().digest,
        Bytes::from_static(b"carried-withdrawal"),
        WithdrawalAction::Amount(NonZeroU64::new(9).unwrap()),
        50,
        signers[1].signer(),
    );
    let withdrawals = WithdrawalBatch::new(vec![queued.clone(), carried]).unwrap();

    // The carried extra registers only with a predecessor-root opening proving it
    // certifiable. The queued request needs none.
    let error = settlement
        .register_epoch(0, 400, empty_root(), empty_root(), withdrawals.clone(), &[])
        .unwrap_err();
    assert!(
        format!("{error:#}").contains("missing an opening"),
        "unexpected error: {error:#}"
    );
    settlement
        .register_epoch(
            0,
            400,
            empty_root(),
            empty_root(),
            withdrawals,
            &[cache.opening(&carried_account).unwrap()],
        )
        .unwrap();
    assert_eq!(settlement.registered.as_ref().unwrap().epoch, 0);

    // Only the queued request occupies the chain's pending set. The carried extra was
    // admitted at registration and never touches the queue.
    let pending = settlement.chain.pending_withdrawals();
    assert_eq!(pending.requests(), [queued]);
}

#[test]
fn registered_epoch_expires_after_its_inclusive_window_and_refunds_deposits() {
    let mut settlement = Settlement::new().unwrap();
    let account = identities()[0].key.clone();
    let event = DepositEvent {
        id: Sha256::hash(&[b"registered-expiry-refund"]),
        account: account.clone(),
        amount: 7,
    };
    settlement.deposit(event).unwrap();
    let deposits = settlement.chain.pending_deposits();
    let withdrawals = WithdrawalBatch::empty();
    let admission_deadline = epoch_context(0, &deposits, &withdrawals, 400)
        .unwrap()
        .admission_deadline();
    settlement
        .register_epoch(
            0,
            400,
            deposits.root::<Sha256>().unwrap(),
            deposits.root::<Sha256>().unwrap(),
            withdrawals,
            &[],
        )
        .unwrap();

    settlement.advance_logical_time(admission_deadline).unwrap();
    assert!(!settlement.status().unwrap().hard_faulted);
    settlement
        .advance_logical_time(admission_deadline + 1)
        .unwrap();
    let status = settlement.status().unwrap();
    assert_eq!(status.now, admission_deadline + 1);
    assert!(status.hard_faulted);
    assert!(settlement.registered.is_none());
    let refund = settlement.chain.claim_pending_deposit(2, &account).unwrap();
    assert_eq!(refund.account, account);
    assert_eq!(refund.amount, 7);
}

#[test]
fn a_successor_context_opens_only_after_its_predecessor_finalizes() {
    let (mut settlement, submission, result, _, _, deposit) = admission_fixture();
    let successor_liability = result
        .epoch_context
        .predecessor_liability()
        .checked_add(deposit.amount)
        .unwrap();

    assert!(
        settlement
            .register_epoch(
                1,
                successor_liability,
                empty_root(),
                empty_root(),
                WithdrawalBatch::empty(),
                &[],
            )
            .is_err()
    );
    assert_eq!(
        settlement.admit_submission(submission).unwrap(),
        AdmissionOutcome::Pending
    );
    assert_eq!(
        settlement.status().unwrap().now,
        result.epoch_context.challenge_deadline()
    );
    assert!(
        settlement
            .register_epoch(
                1,
                successor_liability,
                empty_root(),
                empty_root(),
                WithdrawalBatch::empty(),
                &[],
            )
            .is_err()
    );

    settlement.advance_logical_time(1).unwrap();
    settlement
        .register_epoch(
            1,
            successor_liability,
            empty_root(),
            empty_root(),
            WithdrawalBatch::empty(),
            &[],
        )
        .unwrap();
}

#[test]
fn intake_stops_before_the_terminal_clock_exhausts() {
    let terminal_epoch = crate::protocol::TERMINAL_EPOCH;
    let event = DepositEvent {
        id: Sha256::hash(&[b"terminal-clock-deposit"]),
        account: identities()[0].key.clone(),
        amount: 1,
    };

    let mut deposit = Settlement::at_epoch(terminal_epoch).unwrap();
    let before = deposit.status().unwrap();
    assert!(deposit.deposit(event.clone()).is_err());
    assert_eq!(
        deposit.confirm_deposit(&event).unwrap(),
        DepositPresence::Unknown
    );
    assert_eq!(
        deposit.status().unwrap().custody_balance,
        before.custody_balance
    );

    let mut registration = Settlement::at_epoch(terminal_epoch).unwrap();
    assert!(
        registration
            .register_epoch(
                terminal_epoch,
                400,
                empty_root(),
                empty_root(),
                WithdrawalBatch::empty(),
                &[],
            )
            .is_err()
    );
    assert!(registration.registered.is_none());
}

#[test]
fn deposit_intake_stops_while_the_epoch_context_remains_representable() {
    let terminal_epoch = crate::protocol::TERMINAL_EPOCH;
    let epoch = terminal_epoch - 2;
    let event = DepositEvent {
        id: Sha256::hash(&[b"post-inclusion-exit-clock-deposit"]),
        account: identities()[0].key.clone(),
        amount: 1,
    };
    let mut settlement = Settlement::at_epoch(epoch).unwrap();

    let before = settlement.status().unwrap();
    assert!(settlement.deposit(event.clone()).is_err());
    assert_eq!(
        settlement.confirm_deposit(&event).unwrap(),
        DepositPresence::Unknown
    );
    assert_eq!(
        settlement.status().unwrap().custody_balance,
        before.custody_balance
    );
    assert!(
        epoch_context(
            epoch,
            &DepositBatch::empty(),
            &WithdrawalBatch::empty(),
            400,
        )
        .is_ok()
    );
}
