use super::*;
use commonware_clearing::bajillion::payment::Entry;
use commonware_utils::TestRng;
use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

static TEMP_DATABASE_ID: AtomicU64 = AtomicU64::new(0);

struct TempDatabase {
    directory: PathBuf,
    path: PathBuf,
}

impl TempDatabase {
    fn new() -> Self {
        let id = TEMP_DATABASE_ID.fetch_add(1, Ordering::Relaxed);
        let directory =
            std::env::temp_dir().join(format!("commonware-terminal-{}-{id}", std::process::id()));
        fs::create_dir(&directory).unwrap();
        let path = directory.join("operator.sqlite");
        Self { directory, path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDatabase {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

fn operator() -> Operator {
    Operator::in_memory(NonZeroUsize::new(2).unwrap()).unwrap()
}

fn released<T: std::fmt::Debug>(outcome: crate::settlement::ClaimOutcome<T>) -> T {
    match outcome {
        crate::settlement::ClaimOutcome::Released(value) => value,
        other => panic!("claim was not released: {other:?}"),
    }
}

fn amount(value: u64) -> WithdrawalAction {
    WithdrawalAction::Amount(NonZeroU64::new(value).unwrap())
}

fn start_current_close(operator: &mut Operator) -> Result<CloseStarted> {
    let epoch = operator.registration.context.payment().epoch();
    operator.start_close(epoch)
}

fn rotate_epoch(operator: &mut Operator, epoch: u64) {
    let successor = operator
        .protocol
        .registration(
            epoch.checked_add(1).unwrap(),
            operator.registration.deferred.clone(),
            WithdrawalBatch::empty(),
            operator.store.successor_liability().unwrap(),
        )
        .unwrap();
    operator
        .store
        .rotate_epoch(
            epoch,
            operator.registration.context.payment(),
            &successor.context,
        )
        .unwrap();
    operator.registration = successor;
    operator.reload_predecessor().unwrap();
}

#[test]
fn payment_is_atomic_and_rejects_overspend() {
    let mut operator = operator();
    let accepted = operator.pay(0, 1, 25).unwrap();
    assert_eq!(accepted.epoch, 0);
    assert!(operator.pay(0, 1, 76).is_err());
    let snapshot = operator.snapshot().unwrap();
    assert_eq!(snapshot.payments.len(), 1);
    assert_eq!(
        snapshot
            .accounts
            .iter()
            .find(|account| account.name == "Alice")
            .unwrap()
            .balance,
        75
    );
}

#[test]
fn accepted_batch_reads_across_the_operating_fence() {
    let mut operator = operator();
    let payer = operator.wallets[0].public_key();
    let quote = operator.payment_quote(&payer).unwrap();
    let send = SignedSend::sign_next(
        &quote.context,
        operator.wallets[0].signer(),
        operator.wallets[1].public_key(),
        25,
        quote.state.cumulative_debit,
    )
    .unwrap();
    let committed = operator.accept_send(send.clone()).unwrap();

    // Sign a second send that is never accepted, before any fence blocks quoting.
    let quote = operator
        .payment_quote(&operator.wallets[3].public_key())
        .unwrap();
    let uncommitted = SignedSend::sign_next(
        &quote.context,
        operator.wallets[3].signer(),
        operator.wallets[2].public_key(),
        1,
        quote.state.cumulative_debit,
    )
    .unwrap();

    // A close fence blocks admitting new state but leaves the committed rows readable.
    operator.close_fault = Some("fenced after a failed predecessor close".to_string());
    assert!(operator.accept_send(send.clone()).is_err());
    let resolved = operator
        .accepted_batch(&send)
        .unwrap()
        .expect("a fenced operator failed to read a committed batch");
    assert_eq!(resolved.acceptance, committed.acceptance);
    assert!(operator.accepted_batch(&uncommitted).unwrap().is_none());

    // A storage fault is fatal to the instance until it restarts, so the read refuses
    // to answer instead of reporting a false absence.
    operator.store_fault = Some("the SQLite connection is unusable".to_string());
    assert!(operator.accepted_batch(&send).is_err());
    assert!(operator.accepted_batch(&uncommitted).is_err());
}

#[test]
fn arbitrary_unregistered_recipient_is_rejected_without_a_debit() {
    let mut operator = operator();
    let payer = operator.wallets[0].public_key();
    let quote = operator.payment_quote(&payer).unwrap();
    let recipient = Wallet::from_seed("Mallory", 9_999).public_key();
    let send = SignedSend::sign_next(
        &quote.context,
        operator.wallets[0].signer(),
        recipient,
        25,
        quote.state.cumulative_debit,
    )
    .unwrap();

    assert!(operator.accept_send(send).is_err());
    let snapshot = operator.snapshot().unwrap();
    assert!(snapshot.payments.is_empty());
    assert_eq!(
        snapshot
            .accounts
            .iter()
            .find(|account| account.name == "Alice")
            .unwrap()
            .balance,
        INITIAL_BALANCE
    );
}

#[test]
fn compact_status_does_not_materialize_epoch_artifacts() {
    let database = TempDatabase::new();
    let mut operator = Operator::open(database.path(), NonZeroUsize::MIN).unwrap();
    operator.pay(0, 1, 1).unwrap();
    let connection = rusqlite::Connection::open(database.path()).unwrap();
    connection
        .execute("UPDATE payments SET encoded = zeroblob(256)", [])
        .unwrap();

    let status = operator.status().unwrap();
    assert_eq!(status.accounts, 4);
    assert_eq!(status.present_accounts, 4);
    assert_eq!(status.recent_payments, 1);
}

#[test]
fn payment_quote_serves_the_retained_predecessor_cache() {
    let database = TempDatabase::new();
    let mut operator = Operator::open(database.path(), NonZeroUsize::new(2).unwrap()).unwrap();
    let payer = operator.wallets[0].public_key();
    let before = operator.payment_quote(&payer).unwrap();
    for amount in [3, 4, 5] {
        operator.pay(0, 1, amount).unwrap();
    }

    // The predecessor commitment is constant across the epoch. Only the live account
    // state moves with accepted payments.
    let after = operator.payment_quote(&payer).unwrap();
    assert_eq!(after.root, before.root);
    assert_eq!(after.opening, before.opening);
    assert_eq!(after.state.balance, before.state.balance - 12);
    assert_eq!(
        after.state.cumulative_debit,
        before.state.cumulative_debit + 12
    );

    // Quotes serve the retained cache and never replay the payment log: tampering
    // with a stored row is invisible here. Startup replays and verifies every row,
    // so the reopened operator must reject the same database loudly.
    let connection = rusqlite::Connection::open(database.path()).unwrap();
    let mut tampered: Vec<u8> = connection
        .query_row(
            "SELECT encoded FROM payments WHERE sequence = 1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    *tampered.last_mut().unwrap() ^= 1;
    connection
        .execute(
            "UPDATE payments SET encoded = ?1 WHERE sequence = 1",
            [tampered.as_slice()],
        )
        .unwrap();
    let quoted = operator.payment_quote(&payer).unwrap();
    assert_eq!(quoted.root, after.root);
    assert_eq!(quoted.state, after.state);
    assert_eq!(quoted.opening, after.opening);
    drop(operator);
    drop(connection);

    let error = match Operator::open(database.path(), NonZeroUsize::new(2).unwrap()) {
        Ok(_) => panic!("tampered payment log reopened cleanly"),
        Err(error) => error,
    };
    assert!(format!("{error:#}").contains("verify stored payment"));
}

#[test]
fn payment_retry_returns_the_original_receipt_without_a_second_debit() {
    let mut operator = operator();
    let payer = operator.wallets[0].public_key();
    let recipient = operator.wallets[1].public_key();
    let quote = operator.payment_quote(&payer).unwrap();
    let send = SignedSend::sign_next(
        &quote.context,
        operator.wallets[0].signer(),
        recipient,
        25,
        quote.state.cumulative_debit,
    )
    .unwrap();

    let first = operator.accept_send(send.clone()).unwrap();
    let retry = operator.accept_send(send).unwrap();
    assert_eq!(retry.sequence, first.sequence);
    assert_eq!(retry.acceptance, first.acceptance);

    let snapshot = operator.snapshot().unwrap();
    assert_eq!(snapshot.payments.len(), 1);
    assert_eq!(
        snapshot
            .accounts
            .iter()
            .find(|account| account.name == "Alice")
            .unwrap()
            .balance,
        75
    );
}

#[test]
fn payment_retry_survives_epoch_cutover() {
    let mut operator = operator();
    let payer = operator.wallets[0].public_key();
    let recipient = operator.wallets[1].public_key();
    let quote = operator.payment_quote(&payer).unwrap();
    let send = SignedSend::sign_next(
        &quote.context,
        operator.wallets[0].signer(),
        recipient,
        25,
        quote.state.cumulative_debit,
    )
    .unwrap();

    let first = operator.accept_send(send.clone()).unwrap();
    rotate_epoch(&mut operator, 0);
    assert!(!operator.send_requires_epoch_registration(&send).unwrap());
    let retry = operator.accept_send(send).unwrap();

    assert_eq!(retry.epoch, first.epoch);
    assert_eq!(retry.sequence, first.sequence);
    assert_eq!(retry.acceptance, first.acceptance);
    assert_eq!(operator.snapshot().unwrap().payments.len(), 0);
}

#[test]
fn completed_close_event_is_replayable() {
    let mut operator = operator();
    operator.pay(0, 1, 1).unwrap();
    let epoch = start_current_close(&mut operator).unwrap().epoch;
    let first = loop {
        if let Some(event) = operator.poll_close(epoch).unwrap() {
            break event;
        }
        thread::sleep(Duration::from_millis(5));
    };
    assert!(matches!(first, CloseEvent::Finished(ref close) if close.epoch == epoch));

    let replay = operator.poll_close(epoch).unwrap();
    assert!(matches!(replay, Some(CloseEvent::Finished(close)) if close.epoch == epoch));
}

#[test]
fn batched_send_survives_retry_and_closes() {
    let mut operator = operator();
    let quote = operator
        .payment_quote(&operator.wallets[0].public_key())
        .unwrap();
    let send = SignedSend::sign_next_batch(
        &quote.context,
        operator.wallets[0].signer(),
        vec![
            Entry::new(operator.wallets[1].public_key(), 2).unwrap(),
            Entry::new(operator.wallets[2].public_key(), 3).unwrap(),
            Entry::new(operator.external.key.clone(), 1).unwrap(),
        ],
        quote.state.cumulative_debit,
    )
    .unwrap();

    let first = operator.accept_send(send.clone()).unwrap();
    assert_eq!(first.total, 6);
    assert_eq!(first.acceptance.receipts.len(), 3);
    let tx_id = send.tx_id::<Sha256>();
    assert!(
        first
            .acceptance
            .receipts
            .iter()
            .all(|receipt| receipt.body().tx_id() == &tx_id)
    );
    let retry = operator.accept_send(send).unwrap();
    assert_eq!(retry.sequence, first.sequence);
    assert_eq!(retry.acceptance, first.acceptance);

    let snapshot = operator.snapshot().unwrap();
    assert_eq!(snapshot.payments.len(), 3);
    let balance = |name: &str| {
        snapshot
            .accounts
            .iter()
            .find(|account| account.name == name)
            .unwrap()
            .balance
    };
    assert_eq!(balance("Alice"), INITIAL_BALANCE - 6);
    assert_eq!(balance("Bob"), INITIAL_BALANCE + 2);
    assert_eq!(balance("Carol"), INITIAL_BALANCE + 3);

    // The close replay walks the payer's endpoint once per batch and each entry's shard step.
    let epoch = start_current_close(&mut operator).unwrap().epoch;
    let event = loop {
        if let Some(event) = operator.poll_close(epoch).unwrap() {
            break event;
        }
        thread::sleep(Duration::from_millis(5));
    };
    assert!(matches!(event, CloseEvent::Finished(ref close) if close.epoch == epoch));
}

#[test]
fn completed_close_event_survives_operator_restart() {
    let database = TempDatabase::new();
    let epoch = {
        let mut operator = Operator::open(database.path(), NonZeroUsize::new(2).unwrap()).unwrap();
        operator.pay(0, 1, 1).unwrap();
        let epoch = start_current_close(&mut operator).unwrap().epoch;
        operator.wait_for_closes().unwrap();
        epoch
    };

    let mut recovered = Operator::open(database.path(), NonZeroUsize::new(2).unwrap()).unwrap();
    assert!(matches!(
        recovered.poll_close(epoch).unwrap(),
        Some(CloseEvent::Finished(close)) if close.epoch == epoch
    ));
}

#[test]
fn exact_close_retry_does_not_cut_the_successor_epoch() {
    let mut operator = operator();
    operator.pay(0, 1, 10).unwrap();
    let (started, release) = operator.pause_next_close();
    let first = start_current_close(&mut operator).unwrap();
    started.recv_timeout(Duration::from_secs(1)).unwrap();

    operator.pay(2, 3, 7).unwrap();
    let retry = operator.start_close(first.epoch).unwrap();
    release.send(()).unwrap();
    operator.wait_for_closes().unwrap();

    assert_eq!(retry.epoch, first.epoch);
    assert_eq!(operator.store.epoch().unwrap(), first.epoch + 1);
}

#[test]
fn close_retry_survives_operator_restart() {
    let database = TempDatabase::new();
    {
        let mut operator = Operator::open(database.path(), NonZeroUsize::new(2).unwrap()).unwrap();
        operator.pay(0, 1, 10).unwrap();
        rotate_epoch(&mut operator, 0);
        operator.pay(2, 3, 7).unwrap();
    }

    let mut recovered = Operator::open(database.path(), NonZeroUsize::new(2).unwrap()).unwrap();
    let replay = recovered.start_close(0).unwrap();
    assert_eq!(replay.epoch, 0);
    assert_eq!(recovered.store.epoch().unwrap(), 1);
    recovered.wait_for_closes().unwrap();
}

#[test]
fn close_request_rejects_an_unstarted_noncurrent_epoch() {
    let mut operator = operator();
    operator.pay(0, 1, 10).unwrap();

    assert!(operator.start_close(1).is_err());
    assert_eq!(operator.store.epoch().unwrap(), 0);
    assert!(!operator.store.has_close_job(1).unwrap());
}

#[test]
fn intake_stops_before_the_terminal_clock_exhausts() {
    let mut operator = operator();
    operator.pay(0, 1, 1).unwrap();
    let terminal_epoch = crate::protocol::TERMINAL_EPOCH;
    operator.registration = operator
        .protocol
        .registration(
            terminal_epoch,
            DepositBatch::empty(),
            WithdrawalBatch::empty(),
            operator.store.current_liability().unwrap(),
        )
        .unwrap();

    assert!(
        operator
            .payment_quote(&operator.wallets[0].public_key())
            .is_err()
    );
    assert!(operator.validate_close_start(terminal_epoch).is_err());
    assert!(operator.settlement_registration().is_err());
    assert_eq!(operator.snapshot().unwrap().payments.len(), 1);
}

#[test]
fn balance_intake_stops_while_the_current_epoch_can_still_close() {
    let mut operator = operator();
    operator.pay(0, 1, 1).unwrap();
    let terminal_epoch = crate::protocol::TERMINAL_EPOCH;
    let epoch = terminal_epoch - 2;
    operator.registration = operator
        .protocol
        .registration(
            epoch,
            DepositBatch::empty(),
            WithdrawalBatch::empty(),
            operator.store.current_liability().unwrap(),
        )
        .unwrap();

    assert!(
        operator
            .payment_quote(&operator.wallets[0].public_key())
            .is_err()
    );
    operator.validate_close_start(epoch).unwrap();
    assert_eq!(operator.settlement_registration().unwrap().epoch, epoch);
    assert_eq!(operator.snapshot().unwrap().payments.len(), 1);
}

#[test]
fn amountless_close_outlives_amount_intake_at_the_clock_horizon() {
    let mut operator = operator();
    operator.pay(0, 1, 1).unwrap();
    let terminal_epoch = crate::protocol::TERMINAL_EPOCH;
    let epoch = terminal_epoch - 1;
    operator.registration = operator
        .protocol
        .registration(
            epoch,
            DepositBatch::empty(),
            WithdrawalBatch::empty(),
            operator.store.current_liability().unwrap(),
        )
        .unwrap();

    assert!(
        operator
            .ensure_withdrawal_intake_horizon(&amount(1))
            .is_err()
    );
    operator
        .ensure_withdrawal_intake_horizon(&WithdrawalAction::Close)
        .unwrap();
    operator.validate_close_start(epoch).unwrap();
    assert_eq!(operator.settlement_registration().unwrap().epoch, epoch);
}

#[test]
fn unknown_settlement_admission_is_retried() {
    let mut attempts = 0;
    let value = admit_until_known(
        || {
            attempts += 1;
            if attempts == 1 {
                Err(settlement_rpc::AdmitError::Unknown(anyhow::anyhow!(
                    "response was lost"
                )))
            } else {
                Ok(7)
            }
        },
        Duration::ZERO,
    )
    .unwrap();

    assert_eq!(value, 7);
    assert_eq!(attempts, 2);

    attempts = 0;
    let error = admit_until_known::<u8>(
        || {
            attempts += 1;
            Err(settlement_rpc::AdmitError::Rejected(
                "invalid certificate".to_string(),
            ))
        },
        Duration::ZERO,
    )
    .unwrap_err();
    assert!(format!("{error:#}").contains("invalid certificate"));
    assert_eq!(attempts, 1);
}

#[test]
fn withdrawal_retry_survives_epoch_cutover() {
    let mut operator = operator();
    let first = operator.withdraw(0, amount(25)).unwrap();
    let request = operator.store.load_current().unwrap().withdrawals[0]
        .request
        .clone();
    rotate_epoch(&mut operator, 0);

    let retry = operator.apply_withdrawal(request).unwrap();
    assert_eq!(retry.epoch, first.epoch);
    assert_eq!(retry.account, first.account);
    assert_eq!(retry.action, first.action);
}

#[test]
fn close_authorization_response_loss_retries_after_cutover_and_restart() {
    let database = TempDatabase::new();
    let mut operator = Operator::open(database.path(), NonZeroUsize::new(2).unwrap()).unwrap();
    let first = operator.withdraw(0, WithdrawalAction::Close).unwrap();
    let request = operator.store.load_current().unwrap().withdrawals[0]
        .request
        .clone();
    rotate_epoch(&mut operator, 0);
    drop(operator);

    let mut recovered = Operator::open(database.path(), NonZeroUsize::new(2).unwrap()).unwrap();
    recovered.wait_for_closes().unwrap();
    let retry = recovered.apply_withdrawal(request).unwrap();
    assert_eq!(retry.epoch, first.epoch);
    assert_eq!(retry.account, first.account);
    assert_eq!(retry.action, WithdrawalAction::Close);
    assert_eq!(recovered.status().unwrap().epoch, 1);
}

#[test]
fn staged_close_keeps_incoming_and_outgoing_activity_live_until_cutover() {
    let mut operator = operator();
    operator.withdraw(1, WithdrawalAction::Close).unwrap();
    assert_eq!(operator.store.current_liability().unwrap(), 400);
    assert_eq!(
        operator
            .payment_quote(&operator.wallets[1].public_key())
            .unwrap()
            .state
            .balance,
        100
    );

    let payer = operator.wallets[0].public_key();
    let recipient = operator.wallets[1].public_key();
    let quote = operator.payment_quote(&payer).unwrap();
    let incoming = SignedSend::sign_next(
        &quote.context,
        operator.wallets[0].signer(),
        recipient.clone(),
        7,
        quote.state.cumulative_debit,
    )
    .unwrap();
    assert!(
        operator
            .send_requires_epoch_registration(&incoming)
            .unwrap()
    );
    operator.accept_send(incoming).unwrap();

    let quote = operator.payment_quote(&recipient).unwrap();
    let outgoing = SignedSend::sign_next(
        &quote.context,
        operator.wallets[1].signer(),
        operator.wallets[2].public_key(),
        12,
        quote.state.cumulative_debit,
    )
    .unwrap();
    operator.accept_send(outgoing).unwrap();

    let data = operator.store.load_current().unwrap();
    let bob = data
        .accounts
        .iter()
        .find(|account| account.key == recipient)
        .unwrap();
    assert_eq!(bob.current.balance, 95);
    assert_eq!(bob.current.cumulative_debit, 12);
    assert_eq!(bob.current.cumulative_credit, 7);
    assert_eq!(bob.current.receipt_count, 1);
    let prepared = prepare_epoch(&operator.protocol, data, operator.registration.clone()).unwrap();

    rotate_epoch(&mut operator, 0);
    assert_eq!(operator.store.current_liability().unwrap(), 305);
    assert!(
        operator
            .store
            .current_account(&recipient)
            .unwrap()
            .is_none()
    );
    let frozen = operator.store.epoch_reader().load(0).unwrap();
    let bob = frozen
        .accounts
        .iter()
        .find(|account| account.key == recipient)
        .unwrap();
    assert_eq!(bob.current.balance, 0);
    assert_eq!(bob.current.cumulative_debit, 12);
    assert_eq!(bob.current.cumulative_credit, 7);
    assert_eq!(bob.current.receipt_count, 1);
    assert_eq!(frozen.withdrawals[0].applied_amount, Some(95));

    let result = operator
        .protocol
        .complete(prepared, &mut TestRng::new(44))
        .unwrap();
    assert_eq!(result.finalized.withdrawal_total, 95);
    assert_eq!(
        result.withdrawal_claims[0]
            .verify::<Sha256>(&result.roots.withdrawal_outputs)
            .unwrap()
            .amount(),
        95
    );
    operator
        .store
        .finish_close(&result, operator.genesis_root)
        .unwrap();
}

#[test]
fn close_can_spend_to_zero_without_creating_withdrawal_payout_work() {
    let mut operator = operator();
    let account = operator.wallets[0].public_key();
    operator.withdraw(0, WithdrawalAction::Close).unwrap();
    operator.pay(0, 1, 100).unwrap();

    let data = operator.store.load_current().unwrap();
    let prepared = prepare_epoch(&operator.protocol, data, operator.registration.clone()).unwrap();
    rotate_epoch(&mut operator, 0);
    assert_eq!(operator.store.current_liability().unwrap(), 400);

    let result = operator
        .protocol
        .complete(prepared, &mut TestRng::new(45))
        .unwrap();
    assert_eq!(result.finalized.withdrawal_total, 0);
    assert_eq!(
        result.withdrawal_claims[0]
            .verify::<Sha256>(&result.roots.withdrawal_outputs)
            .unwrap()
            .amount(),
        0
    );
    operator
        .store
        .finish_close(&result, operator.genesis_root)
        .unwrap();
    assert!(operator.store.withdrawal_evidence(&account).is_err());
}

#[test]
fn payment_to_a_closed_configured_identity_becomes_an_external_claim() {
    let mut operator = operator();
    let closed = operator.wallets[1].public_key();
    operator.withdraw(1, WithdrawalAction::Close).unwrap();
    start_current_close(&mut operator).unwrap();
    operator.wait_for_closes().unwrap();
    assert!(operator.store.current_account(&closed).unwrap().is_none());

    let accepted = operator.pay(0, 1, 7).unwrap();
    assert_eq!(accepted.epoch, 1);
    assert!(operator.store.load_current().unwrap().payments[0].external);
    operator.pay(2, operator.wallet_count(), 5).unwrap();
    assert_eq!(operator.store.current_liability().unwrap(), 288);

    start_current_close(&mut operator).unwrap();
    operator.wait_for_closes().unwrap();
    let closed_evidence = operator.external_payout_evidence(&closed).unwrap();
    let eve_evidence = operator
        .external_payout_evidence(&external_identity().key)
        .unwrap();
    assert_eq!(closed_evidence.claim.recipient(), &closed);
    assert_eq!(eve_evidence.claim.recipient(), &external_identity().key);
    assert_ne!(
        closed_evidence.claim.position(),
        eve_evidence.claim.position()
    );
    assert_eq!(operator.snapshot().unwrap().reserved_payout_value, 12);
}

#[test]
fn invalid_requests_are_rejected_before_epoch_registration() {
    let operator = operator();
    let payer = operator.wallets[0].public_key();
    let quote = operator.payment_quote(&payer).unwrap();
    let invalid = SignedSend::sign_next(
        &quote.context,
        operator.wallets[0].signer(),
        operator.wallets[1].public_key(),
        101,
        quote.state.cumulative_debit,
    )
    .unwrap();

    assert!(operator.send_requires_epoch_registration(&invalid).is_err());
    assert!(operator.validate_close_start(0).is_err());
}

#[test]
fn unknown_payment_commit_fences_the_connection() {
    let mut operator = operator();
    operator.store.fail_next_payment_commit();
    let error = match operator.pay(0, 1, 10) {
        Ok(_) => panic!("unknown payment commit was acknowledged"),
        Err(error) => error,
    };
    assert!(format!("{error:#}").contains("payment commit outcome is unknown"));
    assert!(operator.fault().is_some());
    assert!(operator.pay(0, 1, 1).is_err());
    assert!(operator.snapshot().is_err());
    assert!(operator.poll_close(0).is_err());
}

#[test]
fn payment_write_failure_fences_the_connection_and_rolls_back() {
    let database = TempDatabase::new();
    let mut operator = Operator::open(database.path(), NonZeroUsize::new(2).unwrap()).unwrap();
    operator.store.fail_next_payment_write();

    let error = match operator.pay(0, 1, 10) {
        Ok(_) => panic!("failed payment write was acknowledged"),
        Err(error) => error,
    };
    assert!(!format!("{error:#}").is_empty());
    assert!(operator.fault().is_some());
    assert!(operator.snapshot().is_err());
    drop(operator);

    let recovered = Operator::open(database.path(), NonZeroUsize::new(2).unwrap()).unwrap();
    let snapshot = recovered.snapshot().unwrap();
    assert!(snapshot.payments.is_empty());
    assert!(
        snapshot
            .accounts
            .iter()
            .all(|account| account.balance == 100)
    );
}

#[test]
fn poisoned_connection_rejects_withdrawal_preflight() {
    let mut operator = operator();
    operator.withdraw(0, amount(1)).unwrap();
    let request = operator.store.load_current().unwrap().withdrawals[0]
        .request
        .clone();
    operator.store.fail_next_payment_write();
    assert!(operator.pay(1, 2, 1).is_err());

    let error = match operator.staged_withdrawal(&request) {
        Ok(_) => panic!("withdrawal preflight queried a poisoned connection"),
        Err(error) => error,
    };
    assert!(format!("{error:#}").contains("SQLite connection is unusable"));
}

#[test]
fn rejected_payment_keeps_the_connection_usable() {
    let mut operator = operator();

    assert!(operator.pay(0, 1, 101).is_err());
    assert!(operator.fault().is_none());
    operator.pay(0, 1, 1).unwrap();
}

#[test]
fn unknown_deposit_commit_fences_the_connection() {
    let mut operator = operator();
    operator.store.fail_next_deposit_commit();
    let error = match operator.deposit(0, 10) {
        Ok(_) => panic!("unknown deposit commit was acknowledged"),
        Err(error) => error,
    };
    assert!(format!("{error:#}").contains("deposit commit outcome is unknown"));
    assert!(operator.fault().is_some());
    assert!(operator.deposit(0, 1).is_err());
    assert!(operator.snapshot().is_err());
    assert!(operator.poll_close(0).is_err());
}

#[test]
fn unknown_cutover_commit_fences_the_connection_before_claim() {
    let mut operator = operator();
    operator.pay(0, operator.wallet_count(), 100).unwrap();
    let data = operator.store.load_current().unwrap();
    let prepared = prepare_epoch(&operator.protocol, data, operator.registration.clone()).unwrap();
    let epoch = prepared.epoch();
    rotate_epoch(&mut operator, epoch);
    operator
        .finish_prepared(prepared, &mut TestRng::new(24))
        .unwrap();

    operator.pay(1, 2, 1).unwrap();
    operator.store.fail_next_cutover_commit();
    let error = match start_current_close(&mut operator) {
        Ok(_) => panic!("unknown cutover commit was acknowledged"),
        Err(error) => error,
    };
    assert!(format!("{error:#}").contains("epoch cutover commit outcome is unknown"));
    assert!(operator.store_fault.is_some());
    assert!(
        operator
            .external_payout_evidence(&operator.external.key)
            .is_err()
    );
    assert!(operator.snapshot().is_err());
}

#[test]
fn cutover_reuses_the_incrementally_maintained_liability() {
    let mut operator = operator();
    assert_eq!(operator.registration.context.predecessor_liability(), 400);
    assert_eq!(operator.store.current_liability().unwrap(), 400);

    operator.deposit(0, 10).unwrap();
    assert_eq!(operator.registration.context.predecessor_liability(), 400);
    assert_eq!(operator.store.current_liability().unwrap(), 410);
    operator.pay(0, 1, 5).unwrap();
    assert_eq!(operator.store.current_liability().unwrap(), 410);
    operator.pay(2, operator.wallet_count(), 25).unwrap();
    assert_eq!(operator.store.current_liability().unwrap(), 385);

    rotate_epoch(&mut operator, 0);
    assert_eq!(operator.registration.context.predecessor_liability(), 385);
}

#[test]
fn cutover_does_not_materialize_account_state() {
    let mut operator = operator();
    operator.pay(0, 1, 10).unwrap();
    let rows = operator.store.account_version_count().unwrap();
    let changes = operator.store.total_changes();
    let plan = operator
        .store
        .account_lookup_plan(&operator.wallets[0].public_key())
        .unwrap();
    assert!(
        plan.iter()
            .any(|step| step.contains("account_states_key_epoch")),
        "point lookup did not use the account-history index: {plan:?}"
    );
    assert!(
        plan.iter().all(|step| !step.contains("SCAN state")),
        "point lookup scanned account history: {plan:?}"
    );

    rotate_epoch(&mut operator, 0);

    assert_eq!(operator.store.total_changes() - changes, 2);
    assert_eq!(operator.store.account_version_count().unwrap(), rows);
    operator.pay(1, 0, 5).unwrap();
    assert_eq!(operator.store.account_version_count().unwrap(), rows + 2);
}

#[test]
fn finalization_prunes_obsolete_balance_versions() {
    let mut operator = operator();

    operator.pay(1, 2, 1).unwrap();
    let data = operator.store.load_current().unwrap();
    let prepared = prepare_epoch(&operator.protocol, data, operator.registration.clone()).unwrap();
    rotate_epoch(&mut operator, prepared.epoch());
    operator
        .finish_prepared(prepared, &mut TestRng::new(40))
        .unwrap();
    assert_eq!(operator.store.account_version_count().unwrap(), 4);

    operator
        .pay(0, operator.wallet_count(), INITIAL_BALANCE)
        .unwrap();
    operator.pay(1, 2, 10).unwrap();
    let data = operator.store.load_current().unwrap();
    let prepared = prepare_epoch(&operator.protocol, data, operator.registration.clone()).unwrap();
    rotate_epoch(&mut operator, prepared.epoch());

    assert_eq!(operator.store.account_version_count().unwrap(), 7);
    let frozen = operator.store.epoch_reader().load(1).unwrap();
    assert!(frozen.accounts.iter().any(|account| {
        account.name == operator.wallets[0].name && account.current.balance == 0
    }));

    operator
        .finish_prepared(prepared, &mut TestRng::new(41))
        .unwrap();
    assert_eq!(operator.store.account_version_count().unwrap(), 3);
    assert!(
        operator
            .store
            .load_current()
            .unwrap()
            .accounts
            .iter()
            .all(|account| account.name != operator.wallets[0].name)
    );
}

#[test]
fn pruning_ignores_unfinalized_successor_versions() {
    let mut operator = operator();

    operator.pay(1, 2, 1).unwrap();
    let data = operator.store.load_current().unwrap();
    let first = prepare_epoch(&operator.protocol, data, operator.registration.clone()).unwrap();
    rotate_epoch(&mut operator, first.epoch());

    operator
        .pay(0, operator.wallet_count(), INITIAL_BALANCE)
        .unwrap();
    let second_registration = operator.registration.clone();
    rotate_epoch(&mut operator, second_registration.context.payment().epoch());
    operator.deposit(0, 5).unwrap();
    assert_eq!(operator.store.account_version_count().unwrap(), 6);

    operator
        .finish_prepared(first, &mut TestRng::new(42))
        .unwrap();
    assert_eq!(operator.store.account_version_count().unwrap(), 6);

    let frozen = operator.store.epoch_reader().load(1).unwrap();
    assert!(frozen.accounts.iter().any(|account| {
        account.name == operator.wallets[0].name && account.current.balance == 0
    }));
    let second = prepare_epoch(&operator.protocol, frozen, second_registration).unwrap();
    operator
        .finish_prepared(second, &mut TestRng::new(43))
        .unwrap();

    assert_eq!(operator.store.account_version_count().unwrap(), 4);
    let recreated = operator
        .store
        .current_account(&operator.wallets[0].public_key())
        .unwrap()
        .unwrap();
    assert_eq!(recreated.current.balance, 5);
}

#[test]
fn frozen_epoch_scan_does_not_walk_account_history() {
    let operator = operator();
    let plan = operator.store.epoch_account_plan(0).unwrap();
    assert!(
        plan.iter().any(|step| step.contains("SCAN identity")),
        "epoch reconstruction is not driven by account identities: {plan:?}"
    );
    assert!(
        plan.iter().all(|step| !step.contains("SCAN state")),
        "epoch reconstruction walks historical account versions: {plan:?}"
    );
}

#[test]
fn ephemeral_terminal_database_uses_wal() {
    let operator = operator();
    assert_eq!(operator.store.journal_mode().unwrap(), "wal");
}

#[test]
fn non_wal_sqlite_sources_are_rejected() {
    let id = TEMP_DATABASE_ID.fetch_add(1, Ordering::Relaxed);
    let path = PathBuf::from(format!(
        "file:commonware-terminal-{}-{id}?mode=memory&cache=shared",
        std::process::id()
    ));
    let error = match Operator::open(&path, NonZeroUsize::new(2).unwrap()) {
        Ok(_) => panic!("non-WAL database was accepted"),
        Err(error) => error,
    };
    assert!(format!("{error:#}").contains("WAL"));
}

#[test]
fn ephemeral_database_lives_until_the_last_reader_owner() {
    let operator = operator();
    let path = operator.store.database_path();
    let reader = operator.store.epoch_reader();
    assert!(path.exists());

    drop(operator);
    assert!(path.exists());

    drop(reader);
    assert!(!path.exists());
}

#[test]
fn zero_balance_registration_expires_at_cutover() {
    let mut operator = operator();
    operator.pay(0, operator.wallet_count(), 100).unwrap();

    // An account drained during E remains registered until E closes.
    operator.pay(1, 0, 10).unwrap();
    assert!(!operator.snapshot().unwrap().payments[0].external);
    operator.pay(0, operator.wallet_count(), 10).unwrap();

    rotate_epoch(&mut operator, 0);

    // Its zero E state is absent in E+1, so a transfer to the same identity is a payout.
    operator.pay(1, 0, 5).unwrap();
    assert!(operator.snapshot().unwrap().payments[0].external);
}

#[test]
fn empty_close_rejection_keeps_the_operator_live() {
    let mut operator = operator();
    let error = match start_current_close(&mut operator) {
        Ok(_) => panic!("empty epoch was closed"),
        Err(error) => error,
    };
    assert!(format!("{error:#}").contains("nothing to close"));
    assert!(operator.fault().is_none());
    assert_eq!(operator.pay(0, 1, 1).unwrap().epoch, 0);
}

#[test]
fn rejected_deposit_does_not_change_the_epoch_anchor() {
    let mut operator = operator();
    let large = i64::MAX as u64 - 400;
    operator.deposit(0, large).unwrap();

    let error = match operator.deposit(1, 1) {
        Ok(_) => panic!("overflowing deposit was accepted"),
        Err(error) => error,
    };
    assert!(format!("{error:#}").contains("live liability"));
    assert!(operator.fault().is_none());
    let snapshot = operator.snapshot().unwrap();
    assert_eq!(
        snapshot
            .accounts
            .iter()
            .find(|account| account.name == "Bob")
            .unwrap()
            .balance,
        100
    );
}

#[test]
fn stale_same_epoch_anchor_is_rejected_without_mutation() {
    let mut operator = operator();
    let stale = operator.registration.context.payment().clone();
    operator.deposit(0, 10).unwrap();
    let payer = &operator.wallets[1];
    let recipient = &operator.wallets[2];
    let send = SignedSend::sign_next(&stale, payer.signer(), recipient.public_key(), 1, 0).unwrap();

    let error = match operator
        .store
        .accept_send(&stale, operator.protocol.operator(), send, 0)
    {
        Ok(_) => panic!("stale payment anchor was accepted"),
        Err(error) => error,
    };
    assert!(format!("{error:#}").contains("payment anchor is stale"));
    let snapshot = operator.snapshot().unwrap();
    assert!(snapshot.payments.is_empty());
    assert_eq!(
        snapshot
            .accounts
            .iter()
            .find(|account| account.name == payer.name)
            .unwrap()
            .balance,
        100
    );
}

#[test]
fn cutover_accepts_successor_payment_before_predecessor_root_preparation() {
    let mut operator = operator();
    operator.pay(0, 1, 10).unwrap();
    let (started, release) = operator.pause_next_close();
    let close = start_current_close(&mut operator).unwrap();
    started.recv_timeout(Duration::from_secs(1)).unwrap();

    let successor = operator.pay(1, 0, 5).unwrap();
    assert_eq!(successor.epoch, 1);
    assert!(operator.close_in_progress());
    release.send(()).unwrap();
    let events = operator.wait_for_closes().unwrap();
    assert!(matches!(
        events.as_slice(),
        [CloseEvent::Finished(finished)] if finished.epoch == close.epoch
    ));
    let snapshot = operator.snapshot().unwrap();
    assert_eq!(snapshot.payments.len(), 1);
    assert_eq!(
        snapshot
            .accounts
            .iter()
            .find(|account| account.name == "Alice")
            .unwrap()
            .balance,
        95
    );
}

#[test]
fn close_backlog_is_bounded_before_cutover() {
    let mut operator = operator();
    let (started, release) = operator.pause_next_close();
    for epoch in 0..MAX_PENDING_CLOSES {
        operator.pay(epoch % 2, (epoch + 1) % 2, 1).unwrap();
        let close = start_current_close(&mut operator).unwrap();
        assert_eq!(close.epoch, epoch as u64);
        if epoch == 0 {
            started.recv_timeout(Duration::from_secs(1)).unwrap();
        } else {
            assert!(close.queued);
        }
    }
    operator.pay(0, 1, 1).unwrap();
    let epoch = operator.snapshot().unwrap().epoch;
    let error = match start_current_close(&mut operator) {
        Ok(_) => panic!("close backlog exceeded its bound"),
        Err(error) => error,
    };
    assert!(format!("{error:#}").contains("backlog"));
    assert_eq!(operator.snapshot().unwrap().epoch, epoch);
    assert!(operator.fault().is_none());

    release.send(()).unwrap();
    assert_eq!(
        operator.wait_for_closes().unwrap().len(),
        MAX_PENDING_CLOSES
    );
}

#[test]
fn close_scheduler_uses_the_status_epoch_index() {
    let operator = operator();
    let plan = operator.store.close_job_status_query_plan().unwrap();
    assert!(
        plan.iter()
            .any(|step| step.contains("close_jobs_status_epoch")),
        "unexpected query plan: {plan:?}"
    );
}

#[test]
fn committed_cutover_fences_a_worker_start_failure() {
    let mut operator = operator();
    operator.pay(0, 1, 10).unwrap();
    operator.fail_next_close_spawn();

    let error = match start_current_close(&mut operator) {
        Ok(_) => panic!("injected worker failure was accepted"),
        Err(error) => error,
    };
    assert!(format!("{error:#}").contains("operator fenced"));
    assert!(operator.fault().is_some());
    assert!(operator.pay(2, 3, 1).is_err());
    assert_eq!(operator.store.next_closing_epoch().unwrap(), None);
}

#[test]
fn worker_panic_fences_the_successor_epoch() {
    let mut operator = operator();
    operator.pay(0, 1, 10).unwrap();
    operator.panic_next_close_worker();
    start_current_close(&mut operator).unwrap();

    let events = operator.wait_for_closes().unwrap();
    assert!(matches!(
        events.as_slice(),
        [CloseEvent::Failed { epoch: 0, .. }]
    ));
    assert!(operator.fault().is_some());
    assert!(operator.pay(2, 3, 1).is_err());
}

#[test]
fn finalization_write_failure_fences_the_successor_epoch() {
    let mut operator = operator();
    operator.pay(0, 1, 10).unwrap();
    let (started, release) = operator.pause_next_close();
    let close = start_current_close(&mut operator).unwrap();
    started.recv_timeout(Duration::from_secs(1)).unwrap();
    operator
        .store
        .fail_close(close.epoch, "injected finalization failure")
        .unwrap();
    release.send(()).unwrap();

    assert!(operator.wait_for_closes().is_err());
    assert!(operator.fault().is_some());
    assert!(operator.pay(2, 3, 1).is_err());
}

#[test]
fn queued_worker_start_failure_fences_after_predecessor_finalization() {
    let mut operator = operator();
    operator.pay(0, 1, 10).unwrap();
    let (started, release) = operator.pause_next_close();
    start_current_close(&mut operator).unwrap();
    started.recv_timeout(Duration::from_secs(1)).unwrap();

    operator.pay(2, 3, 7).unwrap();
    assert!(start_current_close(&mut operator).unwrap().queued);
    operator.fail_next_close_spawn();
    release.send(()).unwrap();

    assert!(operator.wait_for_closes().is_err());
    assert!(operator.fault().is_some());
    assert!(operator.pay(0, 1, 1).is_err());
    assert!(
        operator
            .store
            .failed_close()
            .unwrap()
            .unwrap()
            .starts_with("epoch 1:")
    );
}

#[test]
fn older_finalization_preserves_a_descendant_fault() {
    let mut operator = operator();
    operator.pay(0, 1, 10).unwrap();
    let (started, release) = operator.pause_next_close();
    start_current_close(&mut operator).unwrap();
    started.recv_timeout(Duration::from_secs(1)).unwrap();

    operator.pay(2, 3, 7).unwrap();
    assert!(start_current_close(&mut operator).unwrap().queued);
    let descendant_fault = "injected descendant fault".to_string();
    operator.store.fail_close(1, &descendant_fault).unwrap();
    operator.close_fault = Some(descendant_fault.clone());
    release.send(()).unwrap();

    loop {
        if let Some(event) = operator.poll_close(0).unwrap() {
            assert!(matches!(event, CloseEvent::Finished(finished) if finished.epoch == 0));
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(operator.fault(), Some(descendant_fault.as_str()));
    assert!(!operator.close_in_progress());
    assert!(operator.pay(0, 1, 1).is_err());
}

#[test]
fn recovery_finishes_an_unfailed_ancestor_below_a_descendant_fault() {
    let database = TempDatabase::new();
    {
        let mut operator = Operator::open(database.path(), NonZeroUsize::new(2).unwrap()).unwrap();
        operator.pay(0, 1, 10).unwrap();
        let (started, release) = operator.pause_next_close();
        start_current_close(&mut operator).unwrap();
        started.recv_timeout(Duration::from_secs(1)).unwrap();
        operator.pay(2, 3, 7).unwrap();
        assert!(start_current_close(&mut operator).unwrap().queued);
        operator.pay(0, 1, 3).unwrap();
        assert!(start_current_close(&mut operator).unwrap().queued);
        operator
            .store
            .fail_close(2, "injected descendant fault")
            .unwrap();
        drop(release);
    }

    let mut recovered = Operator::open(database.path(), NonZeroUsize::new(2).unwrap()).unwrap();
    assert!(recovered.fault().is_some());
    assert!(recovered.close_in_progress());
    let events = recovered.wait_for_closes().unwrap();
    assert!(matches!(
        events.as_slice(),
        [CloseEvent::Finished(first), CloseEvent::Finished(second)]
            if first.epoch == 0 && second.epoch == 1
    ));
    assert!(recovered.fault().is_some());
    assert!(recovered.pay(0, 1, 1).is_err());
}

#[test]
fn cut_and_successor_payment_recover_before_predecessor_preparation() {
    let database = TempDatabase::new();
    {
        let mut operator = Operator::open(database.path(), NonZeroUsize::new(2).unwrap()).unwrap();
        operator.pay(0, 1, 10).unwrap();
        rotate_epoch(&mut operator, 0);
        let successor = operator.pay(2, 3, 7).unwrap();
        assert_eq!(successor.epoch, 1);
    }

    let mut recovered = Operator::open(database.path(), NonZeroUsize::new(2).unwrap()).unwrap();
    assert!(recovered.close_in_progress());
    assert_eq!(recovered.snapshot().unwrap().payments.len(), 1);
    assert!(recovered.pay(0, 1, 1).is_err());
    let events = recovered.wait_for_closes().unwrap();
    assert!(matches!(
        events.as_slice(),
        [CloseEvent::Finished(finished)] if finished.epoch == 0
    ));
    assert_eq!(recovered.snapshot().unwrap().epoch, 1);
    assert_eq!(recovered.pay(0, 1, 1).unwrap().epoch, 1);
}

#[test]
fn recovery_rejects_unreplayed_current_state() {
    let database = TempDatabase::new();
    {
        let _operator = Operator::open(database.path(), NonZeroUsize::new(2).unwrap()).unwrap();
    }
    let connection = rusqlite::Connection::open(database.path()).unwrap();
    connection
        .execute(
            "UPDATE account_states SET current_balance = 99, current_debit = 1
             WHERE epoch = 0 AND public_key = (
                 SELECT public_key FROM account_identities WHERE name = 'Alice'
             )",
            [],
        )
        .unwrap();
    drop(connection);

    let error = match Operator::open(database.path(), NonZeroUsize::new(2).unwrap()) {
        Ok(_) => panic!("corrupt operator state was accepted"),
        Err(error) => error,
    };
    assert!(format!("{error:#}").contains("SQLite balance drift"));
}

#[test]
fn recovery_rejects_same_liability_state_substitution() {
    let database = TempDatabase::new();
    {
        let mut operator = Operator::open(database.path(), NonZeroUsize::new(2).unwrap()).unwrap();
        operator.pay(0, 1, 10).unwrap();
        start_current_close(&mut operator).unwrap();
        operator.wait_for_closes().unwrap();
    }
    let connection = rusqlite::Connection::open(database.path()).unwrap();
    connection
        .execute(
            "UPDATE account_states
             SET current_balance = current_balance + CASE
                 WHEN public_key = (
                     SELECT public_key FROM account_identities WHERE name = 'Alice'
                 ) THEN -1 ELSE 1 END
             WHERE epoch = 0 AND public_key IN (
                 SELECT public_key FROM account_identities WHERE name IN ('Alice', 'Bob')
             )",
            [],
        )
        .unwrap();
    drop(connection);

    let error = match Operator::open(database.path(), NonZeroUsize::new(2).unwrap()) {
        Ok(_) => panic!("same-liability predecessor substitution was accepted"),
        Err(error) => error,
    };
    assert!(format!("{error:#}").contains("predecessor root"));
}

#[test]
fn pending_genesis_close_rejects_same_liability_predecessor_substitution() {
    let database = TempDatabase::new();
    {
        let mut operator = Operator::open(database.path(), NonZeroUsize::new(2).unwrap()).unwrap();
        operator.pay(0, 1, 10).unwrap();
        rotate_epoch(&mut operator, 0);
    }
    let connection = rusqlite::Connection::open(database.path()).unwrap();
    connection
        .execute(
            "UPDATE account_states
             SET predecessor_balance = predecessor_balance + CASE
                     WHEN public_key = (
                         SELECT public_key FROM account_identities WHERE name = 'Alice'
                     ) THEN -1 ELSE 1 END,
                 current_balance = current_balance + CASE
                     WHEN public_key = (
                         SELECT public_key FROM account_identities WHERE name = 'Alice'
                     ) THEN -1 ELSE 1 END
             WHERE epoch = 0 AND public_key IN (
                 SELECT public_key FROM account_identities WHERE name IN ('Alice', 'Bob')
             )",
            [],
        )
        .unwrap();
    drop(connection);

    let mut recovered = Operator::open(database.path(), NonZeroUsize::new(2).unwrap()).unwrap();
    assert!(recovered.wait_for_closes().is_err());
    assert!(recovered.store.failed_close().unwrap().is_some());
}

#[test]
fn predecessor_root_rejection_is_durable() {
    let database = TempDatabase::new();
    {
        let mut operator = Operator::open(database.path(), NonZeroUsize::new(2).unwrap()).unwrap();
        operator.pay(0, 1, 10).unwrap();
        start_current_close(&mut operator).unwrap();
        operator.wait_for_closes().unwrap();
        operator.pay(0, 1, 5).unwrap();
        rotate_epoch(&mut operator, 1);
    }
    let connection = rusqlite::Connection::open(database.path()).unwrap();
    connection
        .execute(
            "UPDATE account_states
             SET predecessor_balance = predecessor_balance + CASE
                     WHEN public_key = (
                         SELECT public_key FROM account_identities WHERE name = 'Alice'
                     ) THEN -1 ELSE 1 END,
                 current_balance = current_balance + CASE
                     WHEN public_key = (
                         SELECT public_key FROM account_identities WHERE name = 'Alice'
                     ) THEN -1 ELSE 1 END
             WHERE epoch = 1 AND public_key IN (
                 SELECT public_key FROM account_identities WHERE name IN ('Alice', 'Bob')
             )",
            [],
        )
        .unwrap();
    drop(connection);

    let mut recovered = Operator::open(database.path(), NonZeroUsize::new(2).unwrap()).unwrap();
    assert!(recovered.wait_for_closes().is_err());
    drop(recovered);

    let mut reopened = Operator::open(database.path(), NonZeroUsize::new(2).unwrap()).unwrap();
    assert!(reopened.fault().is_some());
    assert!(reopened.pay(0, 1, 1).is_err());
}

#[test]
fn malformed_predecessor_roots_persist_a_close_fence() {
    let database = TempDatabase::new();
    {
        let mut operator = Operator::open(database.path(), NonZeroUsize::new(2).unwrap()).unwrap();
        operator.pay(0, 1, 10).unwrap();
        start_current_close(&mut operator).unwrap();
        operator.wait_for_closes().unwrap();
        operator.pay(0, 1, 5).unwrap();
        rotate_epoch(&mut operator, 1);
    }
    let connection = rusqlite::Connection::open(database.path()).unwrap();
    connection
        .execute(
            "UPDATE settlements SET roots = zeroblob(1) WHERE epoch = 0",
            [],
        )
        .unwrap();
    drop(connection);

    let mut recovered = Operator::open(database.path(), NonZeroUsize::new(2).unwrap()).unwrap();
    assert!(recovered.wait_for_closes().is_err());
    drop(recovered);

    let reopened = Operator::open(database.path(), NonZeroUsize::new(2).unwrap()).unwrap();
    assert!(reopened.store.failed_close().unwrap().is_some());
    assert!(!reopened.close_in_progress());
}

#[test]
fn recovery_bounds_close_error_before_materializing_text() {
    let database = TempDatabase::new();
    {
        let mut operator = Operator::open(database.path(), NonZeroUsize::new(2).unwrap()).unwrap();
        operator.pay(0, 1, 1).unwrap();
        rotate_epoch(&mut operator, 0);
    }
    let connection = rusqlite::Connection::open(database.path()).unwrap();
    connection
        .execute_batch("PRAGMA ignore_check_constraints = ON")
        .unwrap();
    connection
        .execute(
            "UPDATE close_jobs
             SET status = 'failed', error = CAST(zeroblob(1048576) AS TEXT)
             WHERE epoch = 0",
            [],
        )
        .unwrap();
    drop(connection);

    let error = match Operator::open(database.path(), NonZeroUsize::new(2).unwrap()) {
        Ok(_) => panic!("oversized close error was materialized"),
        Err(error) => error,
    };
    assert!(format!("{error:#}").contains("persisted byte bound"));
}

#[test]
fn recovery_bounds_payment_blobs_before_decoding() {
    let database = TempDatabase::new();
    {
        let mut operator = Operator::open(database.path(), NonZeroUsize::new(2).unwrap()).unwrap();
        operator.pay(0, 1, 10).unwrap();
    }
    let connection = rusqlite::Connection::open(database.path()).unwrap();
    connection
        .execute_batch("PRAGMA ignore_check_constraints = ON")
        .unwrap();
    connection
        .execute("UPDATE payments SET encoded = zeroblob(1048576)", [])
        .unwrap();
    drop(connection);

    let error = match Operator::open(database.path(), NonZeroUsize::new(2).unwrap()) {
        Ok(_) => panic!("oversized payment blob was accepted"),
        Err(error) => error,
    };
    assert!(format!("{error:#}").contains("invalid encoded payment length"));
}

#[test]
fn recovery_bounds_account_keys_before_decoding() {
    let database = TempDatabase::new();
    let key = {
        let operator = Operator::open(database.path(), NonZeroUsize::new(2).unwrap()).unwrap();
        operator.wallets[0].public_key()
    };
    let connection = rusqlite::Connection::open(database.path()).unwrap();
    connection
        .execute_batch(
            "PRAGMA foreign_keys = OFF;
             PRAGMA ignore_check_constraints = ON;",
        )
        .unwrap();
    connection
        .execute(
            "UPDATE account_states SET public_key = zeroblob(1048576)
             WHERE public_key = ?1",
            [key.as_ref()],
        )
        .unwrap();
    connection
        .execute(
            "UPDATE account_identities SET public_key = zeroblob(1048576)
             WHERE public_key = ?1",
            [key.as_ref()],
        )
        .unwrap();
    drop(connection);

    let error = match Operator::open(database.path(), NonZeroUsize::new(2).unwrap()) {
        Ok(_) => panic!("oversized account key was accepted"),
        Err(error) => error,
    };
    assert!(format!("{error:#}").contains("invalid account key length"));
}

#[test]
fn external_payout_removes_zero_balance_account() {
    let mut operator = operator();
    operator.pay(0, operator.wallet_count(), 100).unwrap();
    let data = operator.store.load_current().unwrap();
    let mut settlement = crate::settlement::Settlement::new().unwrap();
    let registration = operator.settlement_registration().unwrap();
    settlement
        .register_epoch(
            registration.epoch,
            registration.predecessor_liability,
            registration.deposits_root,
            registration.staged_root,
            registration.withdrawals,
            &registration.openings,
        )
        .unwrap();
    let prepared = prepare_epoch(&operator.protocol, data, operator.registration.clone()).unwrap();
    let epoch = prepared.epoch();
    rotate_epoch(&mut operator, epoch);
    let result = operator
        .protocol
        .complete(prepared, &mut TestRng::new(8))
        .unwrap();
    assert_eq!(result.finalized.payout_total, 100);
    let finalized = settlement
        .admit(SettlementSubmission::from(&result))
        .unwrap();
    let claim = result.external_claims.first().unwrap();
    let payout = released(
        settlement
            .claim_external_payout(finalized.batch_id, claim)
            .unwrap(),
    );
    assert_eq!(payout.recipient, external_identity().key);
    assert_eq!(payout.amount, 100);
    assert_eq!(
        released(
            settlement
                .claim_external_payout(finalized.batch_id, claim)
                .unwrap(),
        ),
        payout
    );
    operator
        .store
        .finish_close(&result, operator.genesis_root)
        .unwrap();
    let snapshot = operator.snapshot().unwrap();
    let alice = snapshot
        .accounts
        .iter()
        .find(|account| account.name == "Alice")
        .unwrap();
    assert!(!alice.present);
    assert_eq!(snapshot.reserved_payout_value, 100);
    let evidence = operator
        .external_payout_evidence(&external_identity().key)
        .unwrap();
    assert_eq!(evidence.batch_id, finalized.batch_id);
    operator
        .acknowledge_external_payout_claim(evidence.batch_id, &evidence.claim)
        .unwrap();
    assert_eq!(operator.snapshot().unwrap().reserved_payout_value, 0);
    assert!(
        operator
            .external_payout_evidence(&external_identity().key)
            .is_err()
    );
}

#[test]
fn unclaimed_batch_does_not_block_later_finalization() {
    let mut operator = operator();
    let mut settlement = crate::settlement::Settlement::new().unwrap();

    operator.pay(0, operator.wallet_count(), 100).unwrap();
    let data = operator.store.load_current().unwrap();
    let registration = operator.settlement_registration().unwrap();
    settlement
        .register_epoch(
            registration.epoch,
            registration.predecessor_liability,
            registration.deposits_root,
            registration.staged_root,
            registration.withdrawals,
            &registration.openings,
        )
        .unwrap();
    let prepared = prepare_epoch(&operator.protocol, data, operator.registration.clone()).unwrap();
    let epoch = prepared.epoch();
    rotate_epoch(&mut operator, epoch);
    let first = operator
        .protocol
        .complete(prepared, &mut TestRng::new(31))
        .unwrap();
    let first_finalized = settlement
        .admit(SettlementSubmission::from(&first))
        .unwrap();
    operator
        .store
        .finish_close(&first, operator.genesis_root)
        .unwrap();

    operator.pay(1, operator.wallet_count(), 100).unwrap();
    let data = operator.store.load_current().unwrap();
    let registration = operator.settlement_registration().unwrap();
    settlement
        .register_epoch(
            registration.epoch,
            registration.predecessor_liability,
            registration.deposits_root,
            registration.staged_root,
            registration.withdrawals,
            &registration.openings,
        )
        .unwrap();
    let prepared = prepare_epoch(&operator.protocol, data, operator.registration.clone()).unwrap();
    let epoch = prepared.epoch();
    rotate_epoch(&mut operator, epoch);
    let second = operator
        .protocol
        .complete(prepared, &mut TestRng::new(32))
        .unwrap();
    let submission = SettlementSubmission::from(&second);
    let second_finalized = settlement.admit(submission).unwrap();
    assert_eq!(second_finalized.batch_id, second.finalized.batch_id);
    assert_eq!(settlement.status().unwrap().claimable_balance, 200);

    let first_claim = first.external_claims.first().unwrap();
    assert_eq!(first_claim.position(), 0);
    let second_claim = second.external_claims.first().unwrap();
    assert_eq!(second_claim.position(), 0);
    assert_ne!(second_finalized.batch_id, first_finalized.batch_id);

    // An unknown batch is an availability signal, never a verdict on the claim.
    assert_eq!(
        settlement
            .claim_external_payout(
                BatchId::new(Sha256::hash(&[b"unknown-payout-batch"])),
                first_claim,
            )
            .unwrap(),
        crate::settlement::ClaimOutcome::Unavailable
    );

    // A claim adjudicated against the wrong finalized batch is definitively invalid.
    assert_eq!(
        settlement
            .claim_external_payout(first_finalized.batch_id, second_claim)
            .unwrap(),
        crate::settlement::ClaimOutcome::Invalid
    );
    let first_payout = released(
        settlement
            .claim_external_payout(first_finalized.batch_id, first_claim)
            .unwrap(),
    );
    let second_payout = released(
        settlement
            .claim_external_payout(second_finalized.batch_id, second_claim)
            .unwrap(),
    );
    assert_eq!(
        released(
            settlement
                .claim_external_payout(second_finalized.batch_id, second_claim)
                .unwrap(),
        ),
        second_payout
    );

    // A consumed position replays only for the exact recorded claim.
    assert_eq!(
        settlement
            .claim_external_payout(first_finalized.batch_id, second_claim)
            .unwrap(),
        crate::settlement::ClaimOutcome::Invalid
    );
    assert_eq!(
        released(
            settlement
                .claim_external_payout(first_finalized.batch_id, first_claim)
                .unwrap(),
        ),
        first_payout
    );
    assert_eq!(settlement.status().unwrap().claimable_balance, 0);
}

#[test]
fn finalized_withdrawal_replays_after_a_later_claim() {
    let mut operator = operator();
    let mut settlement = crate::settlement::Settlement::new().unwrap();

    operator.withdraw(0, amount(25)).unwrap();
    let first_account = operator.wallets[0].public_key();
    let first_opening = operator.withdrawal_opening(&first_account).unwrap();
    let data = operator.store.load_current().unwrap();
    settlement
        .queue_withdrawal(
            data.withdrawals[0].request.clone(),
            vec![first_opening.opening],
        )
        .unwrap();
    let registration = operator.settlement_registration().unwrap();
    settlement
        .register_epoch(
            registration.epoch,
            registration.predecessor_liability,
            registration.deposits_root,
            registration.staged_root,
            registration.withdrawals,
            &registration.openings,
        )
        .unwrap();
    let prepared = prepare_epoch(&operator.protocol, data, operator.registration.clone()).unwrap();
    let epoch = prepared.epoch();
    rotate_epoch(&mut operator, epoch);
    let first = operator
        .protocol
        .complete(prepared, &mut TestRng::new(33))
        .unwrap();
    let first_finalized = settlement
        .admit(SettlementSubmission::from(&first))
        .unwrap();
    operator
        .store
        .finish_close(&first, operator.genesis_root)
        .unwrap();

    let first_claim = first.withdrawal_claims.first().unwrap();
    assert_eq!(first_claim.position(), 0);

    // An unknown batch is an availability signal, never a verdict on the claim.
    assert_eq!(
        settlement
            .claim_withdrawal(
                BatchId::new(Sha256::hash(&[b"unknown-withdrawal-batch"])),
                first_claim,
            )
            .unwrap(),
        crate::settlement::ClaimOutcome::Unavailable
    );
    let first_output = released(
        settlement
            .claim_withdrawal(first_finalized.batch_id, first_claim)
            .unwrap(),
    );

    operator.withdraw(1, amount(30)).unwrap();
    let second_account = operator.wallets[1].public_key();
    let second_opening = operator.withdrawal_opening(&second_account).unwrap();
    let data = operator.store.load_current().unwrap();
    settlement
        .queue_withdrawal(
            data.withdrawals[0].request.clone(),
            vec![second_opening.opening],
        )
        .unwrap();
    let registration = operator.settlement_registration().unwrap();
    settlement
        .register_epoch(
            registration.epoch,
            registration.predecessor_liability,
            registration.deposits_root,
            registration.staged_root,
            registration.withdrawals,
            &registration.openings,
        )
        .unwrap();
    let prepared = prepare_epoch(&operator.protocol, data, operator.registration.clone()).unwrap();
    let epoch = prepared.epoch();
    rotate_epoch(&mut operator, epoch);
    let second = operator
        .protocol
        .complete(prepared, &mut TestRng::new(34))
        .unwrap();
    let second_finalized = settlement
        .admit(SettlementSubmission::from(&second))
        .unwrap();

    let second_claim = second.withdrawal_claims.first().unwrap();
    assert_eq!(second_claim.position(), 0);
    assert_ne!(second_finalized.batch_id, first_finalized.batch_id);
    let second_output = released(
        settlement
            .claim_withdrawal(second_finalized.batch_id, second_claim)
            .unwrap(),
    );
    assert_eq!(
        released(
            settlement
                .claim_withdrawal(second_finalized.batch_id, second_claim)
                .unwrap(),
        ),
        second_output
    );

    // A consumed position replays only for the exact recorded claim.
    assert_eq!(
        settlement
            .claim_withdrawal(first_finalized.batch_id, second_claim)
            .unwrap(),
        crate::settlement::ClaimOutcome::Invalid
    );
    assert_eq!(
        released(
            settlement
                .claim_withdrawal(first_finalized.batch_id, first_claim)
                .unwrap(),
        ),
        first_output
    );
    assert_eq!(settlement.status().unwrap().claimable_balance, 0);
}

#[test]
fn external_payout_claim_survives_restart_and_stays_consumed() {
    let database = TempDatabase::new();
    let mut operator = Operator::open(database.path(), NonZeroUsize::new(2).unwrap()).unwrap();
    operator.pay(0, operator.wallet_count(), 100).unwrap();
    let data = operator.store.load_current().unwrap();
    let prepared = prepare_epoch(&operator.protocol, data, operator.registration.clone()).unwrap();
    let epoch = prepared.epoch();
    rotate_epoch(&mut operator, epoch);
    operator
        .finish_prepared(prepared, &mut TestRng::new(18))
        .unwrap();
    drop(operator);

    let mut recovered = Operator::open(database.path(), NonZeroUsize::new(2).unwrap()).unwrap();
    assert_eq!(recovered.snapshot().unwrap().reserved_payout_value, 100);
    let evidence = recovered
        .external_payout_evidence(&external_identity().key)
        .unwrap();
    recovered
        .acknowledge_external_payout_claim(evidence.batch_id, &evidence.claim)
        .unwrap();
    drop(recovered);

    let recovered = Operator::open(database.path(), NonZeroUsize::new(2).unwrap()).unwrap();
    assert_eq!(recovered.snapshot().unwrap().reserved_payout_value, 0);
    assert!(
        recovered
            .external_payout_evidence(&external_identity().key)
            .is_err()
    );
}

#[test]
fn external_payout_evidence_replays_until_acknowledged() {
    let mut operator = operator();
    let recipient = external_identity().key;
    operator.pay(0, operator.wallet_count(), 10).unwrap();
    let data = operator.store.load_current().unwrap();
    let prepared = prepare_epoch(&operator.protocol, data, operator.registration.clone()).unwrap();
    let epoch = prepared.epoch();
    rotate_epoch(&mut operator, epoch);
    operator
        .finish_prepared(prepared, &mut TestRng::new(19))
        .unwrap();

    let first = operator.external_payout_evidence(&recipient).unwrap();
    let retry = operator.external_payout_evidence(&recipient).unwrap();
    assert_eq!(retry.batch_id, first.batch_id);
    assert_eq!(retry.claim, first.claim);

    operator
        .acknowledge_external_payout_claim(first.batch_id, &first.claim)
        .unwrap();
    assert!(operator.external_payout_evidence(&recipient).is_err());
}

#[test]
fn ordinary_withdrawal_is_included_and_claimable() {
    let mut operator = operator();
    let staged = operator.withdraw(0, amount(25)).unwrap();
    assert_eq!(staged.epoch, 0);
    assert_eq!(staged.action, amount(25));
    let snapshot = operator.snapshot().unwrap();
    let alice = snapshot
        .accounts
        .iter()
        .find(|account| account.name == "Alice")
        .unwrap();
    assert_eq!(alice.balance, 75);

    let data = operator.store.load_current().unwrap();
    let request = data.withdrawals[0].request.clone();
    let account = operator.wallets[0].public_key();
    let opening = operator.withdrawal_opening(&account).unwrap();
    let mut settlement = crate::settlement::Settlement::new().unwrap();
    settlement
        .queue_withdrawal(request, vec![opening.opening])
        .unwrap();
    let registration = operator.settlement_registration().unwrap();
    settlement
        .register_epoch(
            registration.epoch,
            registration.predecessor_liability,
            registration.deposits_root,
            registration.staged_root,
            registration.withdrawals,
            &registration.openings,
        )
        .unwrap();
    let prepared = prepare_epoch(&operator.protocol, data, operator.registration.clone()).unwrap();
    let epoch = prepared.epoch();
    rotate_epoch(&mut operator, epoch);
    let result = operator
        .protocol
        .complete(prepared, &mut TestRng::new(21))
        .unwrap();
    let batch_id = result.finalized.batch_id;
    operator
        .store
        .finish_close(&result, operator.genesis_root)
        .unwrap();

    let evidence = operator
        .store
        .withdrawal_evidence(&operator.wallets[0].public_key())
        .unwrap();
    assert_eq!(evidence.account, operator.wallets[0].public_key());
    assert_eq!(evidence.claim.output().amount(), 25);
    assert_eq!(evidence.claim.output().destination().as_ref(), b"Alice");
    assert_eq!(evidence.batch_id, batch_id);
    let finalized = settlement
        .admit(SettlementSubmission::from(&result))
        .unwrap();
    assert_eq!(finalized.batch_id, batch_id);
    let release = released(
        settlement
            .claim_withdrawal(evidence.batch_id, &evidence.claim)
            .unwrap(),
    );
    assert_eq!(release.amount(), 25);
    assert_eq!(release.destination().as_ref(), b"Alice");
    assert_eq!(&release, evidence.claim.output());
    assert_eq!(
        released(
            settlement
                .claim_withdrawal(evidence.batch_id, &evidence.claim)
                .unwrap(),
        ),
        release
    );
}

#[test]
fn exact_offset_deposit_defers_and_settles_in_the_next_epoch() {
    let mut operator = operator();
    let mut settlement = crate::settlement::Settlement::new().unwrap();
    let account = operator.wallets[0].public_key();
    let deposit_deadline = crate::protocol::settlement_config()
        .deposit_inclusion_timeout
        .get();
    let event = |label: &'static [u8], amount: u64| DepositEvent {
        id: Sha256::hash(&[label]),
        account: account.clone(),
        amount,
    };

    // The verified honest sequence: deposit 3, carried withdrawal Amount(7), then
    // deposit 4. Settlement takes custody first, so the operator must credit every
    // recorded event without refusing any shape.
    let first = event(b"honest-offset-deposit-3", 3);
    settlement.deposit(first.clone()).unwrap();
    operator.apply_deposit(first).unwrap();
    operator.withdraw(0, amount(7)).unwrap();
    let second = event(b"honest-offset-deposit-4", 4);
    settlement.deposit(second.clone()).unwrap();
    let staged = operator.apply_deposit(second).unwrap();
    assert_eq!(staged.epoch, 1);

    // The deferring aggregate is unspendable during the deferring epoch: this close's
    // row for the account carries no deposit.
    assert_eq!(operator.payment_quote(&account).unwrap().state.balance, 93);
    assert!(operator.pay(0, 1, 94).is_err());
    operator.pay(0, 1, 5).unwrap();

    // Registration succeeds with the whole aggregate deferred: the committed boundary
    // is empty and the staged view matches settlement's custody record.
    let registration = operator.settlement_registration().unwrap();
    assert_eq!(
        registration.deposits_root,
        DepositBatch::<Key>::empty().root::<Sha256>().unwrap()
    );
    settlement
        .register_epoch(
            registration.epoch,
            registration.predecessor_liability,
            registration.deposits_root,
            registration.staged_root,
            registration.withdrawals,
            &registration.openings,
        )
        .unwrap();
    rotate_epoch(&mut operator, 0);

    // The close worker loads the frozen epoch after cutover, so the deferral must
    // re-derive from the parked rows alone.
    let frozen = operator.store.epoch_reader().load(0).unwrap();
    let recovered = registration_for(&operator.protocol, &frozen).unwrap();
    let prepared = prepare_epoch(&operator.protocol, frozen, recovered).unwrap();
    let first_close = operator
        .protocol
        .complete(prepared, &mut TestRng::new(51))
        .unwrap();
    let first_finalized = settlement
        .admit(SettlementSubmission::from(&first_close))
        .unwrap();

    // The rehearsal staged the deferred aggregate too, so it reproduces the
    // authoritative finalization exactly, custody included.
    assert_eq!(first_finalized, first_close.finalized);
    operator
        .store
        .finish_close(&first_close, operator.genesis_root)
        .unwrap();
    let release = released(
        settlement
            .claim_withdrawal(first_finalized.batch_id, &first_close.withdrawal_claims[0])
            .unwrap(),
    );
    assert_eq!(release.amount(), 7);

    // The deferred aggregate lands staged and spendable in the successor epoch.
    assert_eq!(operator.payment_quote(&account).unwrap().state.balance, 95);
    let registration = operator.settlement_registration().unwrap();
    assert_eq!(registration.epoch, 1);
    settlement
        .register_epoch(
            registration.epoch,
            registration.predecessor_liability,
            registration.deposits_root,
            registration.staged_root,
            registration.withdrawals,
            &registration.openings,
        )
        .unwrap();
    let data = operator.store.load_current().unwrap();
    let prepared = prepare_epoch(&operator.protocol, data, operator.registration.clone()).unwrap();
    rotate_epoch(&mut operator, 1);
    let second_close = operator
        .protocol
        .complete(prepared, &mut TestRng::new(52))
        .unwrap();
    let second_finalized = settlement
        .admit(SettlementSubmission::from(&second_close))
        .unwrap();
    assert_eq!(second_finalized, second_close.finalized);
    operator
        .store
        .finish_close(&second_close, operator.genesis_root)
        .unwrap();

    // The deferral consumed one close of deadline headroom and the demo geometry
    // still lands the deposit well before its inclusion deadline.
    let status = settlement.status().unwrap();
    assert!(!status.hard_faulted);
    assert!(status.now < deposit_deadline);
}

#[test]
fn exact_offset_withdrawal_defers_at_intake() {
    let mut operator = operator();
    let account = operator.wallets[0].public_key();
    operator.deposit(0, 7).unwrap();
    assert_eq!(operator.payment_quote(&account).unwrap().state.balance, 107);

    operator.withdraw(0, amount(7)).unwrap();
    assert_eq!(operator.payment_quote(&account).unwrap().state.balance, 93);
    assert_eq!(operator.registration.deposits.amount_for(&account), 0);
    assert_eq!(operator.registration.deferred.amount_for(&account), 7);
}

#[test]
fn growing_aggregate_returns_a_parked_deposit_to_its_epoch() {
    let mut operator = operator();
    let account = operator.wallets[0].public_key();
    operator.deposit(0, 7).unwrap();
    operator.withdraw(0, amount(7)).unwrap();
    assert_eq!(operator.payment_quote(&account).unwrap().state.balance, 93);

    // The grown aggregate no longer offsets the withdrawal exactly, so the whole
    // aggregate returns to this epoch's boundary with its credit.
    operator.deposit(0, 5).unwrap();
    assert_eq!(operator.payment_quote(&account).unwrap().state.balance, 105);
    assert_eq!(operator.registration.deposits.amount_for(&account), 12);
    assert!(operator.registration.deferred.is_empty());
}

#[test]
fn growing_aggregate_returns_a_re_parked_carried_deposit() {
    let mut operator = operator();
    let account = operator.wallets[0].public_key();
    operator.deposit(0, 7).unwrap();
    operator.withdraw(0, amount(7)).unwrap();
    let data = operator.store.load_current().unwrap();
    let prepared = prepare_epoch(&operator.protocol, data, operator.registration.clone()).unwrap();
    rotate_epoch(&mut operator, 0);
    operator
        .finish_prepared(prepared, &mut TestRng::new(57))
        .unwrap();
    assert_eq!(operator.payment_quote(&account).unwrap().state.balance, 100);

    // A carried exact offset parks the carried-in aggregate again, and a later
    // deposit that breaks the offset returns it whole with its origin intact.
    operator.withdraw(0, amount(7)).unwrap();
    assert_eq!(operator.payment_quote(&account).unwrap().state.balance, 86);
    assert_eq!(operator.registration.deferred.amount_for(&account), 7);
    operator.deposit(0, 5).unwrap();
    assert_eq!(operator.payment_quote(&account).unwrap().state.balance, 98);
    assert_eq!(operator.registration.deposits.amount_for(&account), 12);
    assert!(operator.registration.deferred.is_empty());
}

#[test]
fn parked_deposit_survives_operator_restart() {
    let database = TempDatabase::new();
    let account = wallets()[0].public_key();
    {
        let mut operator = Operator::open(database.path(), NonZeroUsize::new(2).unwrap()).unwrap();
        operator.deposit(0, 7).unwrap();
        operator.withdraw(0, amount(7)).unwrap();
    }

    let operator = Operator::open(database.path(), NonZeroUsize::new(2).unwrap()).unwrap();
    assert_eq!(operator.registration.deferred.amount_for(&account), 7);
    assert_eq!(operator.payment_quote(&account).unwrap().state.balance, 93);
}

#[test]
fn offsetable_withdrawal_must_be_coverable_without_the_aggregate() {
    let mut operator = operator();
    let account = operator.wallets[0].public_key();
    operator.deposit(0, 5).unwrap();

    // A later deposit could grow the aggregate into an exact offset, deferring it
    // whole, so the amount must stay coverable without the aggregate.
    let error = operator
        .withdraw(0, amount(101))
        .err()
        .expect("an offsetable underfunded withdrawal must be refused");
    assert!(
        format!("{error:#}").contains("without its deposit aggregate"),
        "unexpected error: {error:#}"
    );
    assert_eq!(operator.payment_quote(&account).unwrap().state.balance, 105);
    operator.withdraw(0, amount(100)).unwrap();
    assert_eq!(operator.payment_quote(&account).unwrap().state.balance, 5);
}

#[test]
fn queued_exact_offset_re_defers_the_carried_aggregate() {
    let mut operator = operator();
    let mut settlement = crate::settlement::Settlement::new().unwrap();
    let account = operator.wallets[0].public_key();
    let deposit_deadline = crate::protocol::settlement_config()
        .deposit_inclusion_timeout
        .get();
    let register = |settlement: &mut crate::settlement::Settlement, operator: &mut Operator| {
        let registration = operator.settlement_registration().unwrap();
        settlement
            .register_epoch(
                registration.epoch,
                registration.predecessor_liability,
                registration.deposits_root,
                registration.staged_root,
                registration.withdrawals,
                &registration.openings,
            )
            .unwrap();
    };
    let close = |settlement: &mut crate::settlement::Settlement,
                 operator: &mut Operator,
                 epoch: u64,
                 seed: u64| {
        rotate_epoch(operator, epoch);
        let frozen = operator.store.epoch_reader().load(epoch).unwrap();
        let recovered = registration_for(&operator.protocol, &frozen).unwrap();
        let prepared = prepare_epoch(&operator.protocol, frozen, recovered).unwrap();
        let result = operator
            .protocol
            .complete(prepared, &mut TestRng::new(seed))
            .unwrap();
        let finalized = settlement
            .admit(SettlementSubmission::from(&result))
            .unwrap();
        assert_eq!(finalized, result.finalized);
        operator
            .store
            .finish_close(&result, operator.genesis_root)
            .unwrap();
        result
    };

    // The deposit parks under a carried exact-offset withdrawal and lands in the
    // successor epoch.
    let event = DepositEvent {
        id: Sha256::hash(&[b"re-deferral-deposit"]),
        account: account.clone(),
        amount: 7,
    };
    settlement.deposit(event.clone()).unwrap();
    operator.apply_deposit(event).unwrap();
    operator.withdraw(0, amount(7)).unwrap();
    register(&mut settlement, &mut operator);
    let first_close = close(&mut settlement, &mut operator, 0, 54);
    assert_eq!(operator.payment_quote(&account).unwrap().state.balance, 100);

    // A QUEUED withdrawal exactly offsets the carried-in aggregate in its landing
    // epoch. The chain accepts and defers again, so the operator must represent the
    // shape, and the aggregate parks onward instead of wedging the registration.
    let opening = operator.withdrawal_opening(&account).unwrap();
    let queued = SignedWithdrawal::sign(
        operator.protocol.deployment(),
        opening.root.digest,
        Bytes::from_static(b"Alice"),
        amount(7),
        50,
        operator.wallets[0].signer(),
    );
    settlement
        .queue_withdrawal(queued.clone(), vec![opening.opening])
        .unwrap();
    operator.apply_withdrawal(queued).unwrap();
    assert_eq!(operator.payment_quote(&account).unwrap().state.balance, 86);
    assert_eq!(operator.registration.deferred.amount_for(&account), 7);
    register(&mut settlement, &mut operator);
    let second_close = close(&mut settlement, &mut operator, 1, 55);

    // The twice-deferred deposit lands spendable two epochs after intake and is
    // included well before its inclusion deadline in the demo geometry.
    assert_eq!(operator.payment_quote(&account).unwrap().state.balance, 93);
    assert_eq!(operator.registration.deposits.amount_for(&account), 7);
    register(&mut settlement, &mut operator);
    close(&mut settlement, &mut operator, 2, 56);
    let status = settlement.status().unwrap();
    assert!(!status.hard_faulted);
    assert!(status.now < deposit_deadline);

    // Both withdrawal reserves release.
    for result in [&first_close, &second_close] {
        let release = released(
            settlement
                .claim_withdrawal(result.finalized.batch_id, &result.withdrawal_claims[0])
                .unwrap(),
        );
        assert_eq!(release.amount(), 7);
    }
}

#[test]
fn hidden_staged_divergence_is_rejected_at_registration_until_the_credit_heals() {
    let mut operator = operator();
    let mut settlement = crate::settlement::Settlement::new().unwrap();
    let account = operator.wallets[0].public_key();

    // Settlement records custody the operator never credited, and the carried
    // withdrawal exactly offsets the unseen aggregate: both derived boundaries
    // exclude the account, so only the staged view can expose the divergence.
    let event = DepositEvent {
        id: Sha256::hash(&[b"hidden-divergence-deposit"]),
        account,
        amount: 7,
    };
    settlement.deposit(event.clone()).unwrap();
    operator.withdraw(0, amount(7)).unwrap();
    let registration = operator.settlement_registration().unwrap();
    assert_eq!(
        registration.deposits_root,
        DepositBatch::<Key>::empty().root::<Sha256>().unwrap()
    );
    let error = settlement
        .register_epoch(
            registration.epoch,
            registration.predecessor_liability,
            registration.deposits_root,
            registration.staged_root,
            registration.withdrawals,
            &registration.openings,
        )
        .unwrap_err();
    assert!(
        format!("{error:#}").contains("operator staged deposits differ from settlement"),
        "unexpected error: {error:#}"
    );

    // The wallet's credit retry heals the view and registration proceeds with the
    // aggregate deferred on both sides.
    operator.apply_deposit(event).unwrap();
    let registration = operator.settlement_registration().unwrap();
    settlement
        .register_epoch(
            registration.epoch,
            registration.predecessor_liability,
            registration.deposits_root,
            registration.staged_root,
            registration.withdrawals,
            &registration.openings,
        )
        .unwrap();
}

#[test]
fn acknowledged_withdrawal_evidence_advances_to_the_next_epoch() {
    let mut operator = operator();
    operator.withdraw(0, amount(25)).unwrap();
    let data = operator.store.load_current().unwrap();
    let prepared = prepare_epoch(&operator.protocol, data, operator.registration.clone()).unwrap();
    let epoch = prepared.epoch();
    rotate_epoch(&mut operator, epoch);
    operator
        .finish_prepared(prepared, &mut TestRng::new(26))
        .unwrap();
    let first = operator
        .withdrawal_evidence(&operator.wallets[0].public_key())
        .unwrap();

    operator.withdraw(0, amount(10)).unwrap();
    let data = operator.store.load_current().unwrap();
    let prepared = prepare_epoch(&operator.protocol, data, operator.registration.clone()).unwrap();
    let epoch = prepared.epoch();
    rotate_epoch(&mut operator, epoch);
    operator
        .finish_prepared(prepared, &mut TestRng::new(27))
        .unwrap();
    assert_eq!(
        operator
            .withdrawal_evidence(&operator.wallets[0].public_key())
            .unwrap()
            .batch_id,
        first.batch_id
    );

    let wrong_batch = BatchId::new(Sha256::hash(&[b"wrong-withdrawal-batch"]));
    assert!(
        operator
            .acknowledge_withdrawal_claim(wrong_batch, &first.account, &first.claim)
            .is_err()
    );
    let wrong_account = operator.wallets[1].public_key();
    assert!(
        operator
            .acknowledge_withdrawal_claim(first.batch_id, &wrong_account, &first.claim)
            .is_err()
    );
    let retry = operator
        .withdrawal_evidence(&operator.wallets[0].public_key())
        .unwrap();
    assert_eq!(retry.batch_id, first.batch_id);
    assert_eq!(retry.claim, first.claim);

    operator
        .acknowledge_withdrawal_claim(first.batch_id, &first.account, &first.claim)
        .unwrap();
    operator
        .acknowledge_withdrawal_claim(first.batch_id, &first.account, &first.claim)
        .unwrap();
    let second = operator
        .withdrawal_evidence(&operator.wallets[0].public_key())
        .unwrap();
    assert_ne!(second.batch_id, first.batch_id);
    assert_eq!(second.account, operator.wallets[0].public_key());
    assert_eq!(second.claim.output().amount(), 10);
}

#[test]
fn malformed_admission_does_not_poison_valid_retry() {
    let mut operator = operator();
    operator.pay(0, 1, 1).unwrap();
    let data = operator.store.load_current().unwrap();
    let mut settlement = crate::settlement::Settlement::new().unwrap();
    let registration = operator.settlement_registration().unwrap();
    settlement
        .register_epoch(
            registration.epoch,
            registration.predecessor_liability,
            registration.deposits_root,
            registration.staged_root,
            registration.withdrawals,
            &registration.openings,
        )
        .unwrap();
    let prepared = prepare_epoch(&operator.protocol, data, operator.registration.clone()).unwrap();
    let result = operator
        .protocol
        .complete(prepared, &mut TestRng::new(25))
        .unwrap();
    let valid = SettlementSubmission::from(&result);
    let mut malformed = valid.clone();
    malformed.roots.change.digest = Sha256::hash(&[b"malformed-change-root"]);

    assert!(settlement.admit(malformed).is_err());
    assert_eq!(
        settlement.admit(valid).unwrap().batch_id,
        result.finalized.batch_id
    );
}

#[test]
fn close_removes_the_account_and_claims_the_final_tail() {
    let mut operator = operator();
    let staged = operator.withdraw(0, WithdrawalAction::Close).unwrap();
    assert_eq!(staged.action, WithdrawalAction::Close);
    let data = operator.store.load_current().unwrap();
    let prepared = prepare_epoch(&operator.protocol, data, operator.registration.clone()).unwrap();
    let epoch = prepared.epoch();
    rotate_epoch(&mut operator, epoch);
    operator
        .finish_prepared(prepared, &mut TestRng::new(22))
        .unwrap();

    let alice = operator
        .snapshot()
        .unwrap()
        .accounts
        .into_iter()
        .find(|account| account.name == "Alice")
        .unwrap();
    assert!(!alice.present);
    let evidence = operator
        .store
        .withdrawal_evidence(&operator.wallets[0].public_key())
        .unwrap();
    assert_eq!(evidence.account, operator.wallets[0].public_key());
    assert_eq!(evidence.claim.output().amount(), INITIAL_BALANCE);
    assert_eq!(evidence.claim.output().destination().as_ref(), b"Alice");
}

#[test]
fn deposit_recreates_an_absent_account() {
    let mut operator = operator();
    operator.pay(0, operator.wallet_count(), 100).unwrap();
    let data = operator.store.load_current().unwrap();
    let prepared = prepare_epoch(&operator.protocol, data, operator.registration.clone()).unwrap();
    let epoch = prepared.epoch();
    rotate_epoch(&mut operator, epoch);
    operator
        .finish_prepared(prepared, &mut TestRng::new(9))
        .unwrap();
    operator.deposit(0, 30).unwrap();
    let snapshot = operator.snapshot().unwrap();
    let alice = snapshot
        .accounts
        .iter()
        .find(|account| account.name == "Alice")
        .unwrap();
    assert!(alice.present);
    assert_eq!(alice.balance, 30);
}

#[test]
fn deposit_event_capacity_is_rejected_before_mutation() {
    let mut operator = operator();
    for index in 0..1_024 {
        operator
            .deposit(index % operator.wallet_count(), 1)
            .unwrap();
    }
    let epoch = operator.snapshot().unwrap().epoch;
    let liability = operator.store.current_liability().unwrap();
    let error = match operator.deposit(0, 1) {
        Ok(_) => panic!("deposit event capacity was exceeded"),
        Err(error) => error,
    };
    assert!(format!("{error:#}").contains("deposit event capacity"));
    assert_eq!(operator.snapshot().unwrap().epoch, epoch);
    assert_eq!(operator.store.current_liability().unwrap(), liability);
}
