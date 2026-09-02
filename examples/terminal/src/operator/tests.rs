use super::*;
use crate::{
    chain::{
        harness,
        state::{
            ExternalPayoutResponse, Record, RegistrationRecord, StatusRecord, WithdrawalResponse,
            admitted_key, deposit_key, payout_release_key, registration_key, status_key,
            withdrawal_key, withdrawal_release_key,
        },
        tx::{
            AdmitRequest, ExternalPayoutClaimRequest, QueueWithdrawalRequest, SettlementTx,
            WithdrawalClaimRequest,
        },
    },
    protocol::deployment,
};
use commonware_clearing::bajillion::{challenge::StateOpening, transition::WithdrawalClaim};
use commonware_runtime::{Runner as _, deterministic};
use commonware_utils::TestRng;
use std::{
    fs,
    net::SocketAddr,
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

/// Unwraps one claim resolution: the release record proving exactly this
/// claim consumed its position.
fn released<T: std::fmt::Debug>(outcome: Option<T>) -> T {
    outcome.expect("the claim released nothing")
}

/// The settlement chain these tests co-simulate with the operator: a harness
/// chain driven at the transaction level, with every verdict read from
/// executed state.
struct Chain {
    control: harness::Control,
}

impl Chain {
    async fn new(context: &deterministic::Context) -> Self {
        let control =
            harness::start(context, SocketAddr::from(([127, 0, 0, 1], 9_800)), "chain").await;
        Self { control }
    }

    async fn deposit(&self, event: DepositEvent) {
        self.control
            .submit(SettlementTx::Deposit(crate::chain::tx::DepositRequest {
                deployment: deployment(),
                event: event.clone(),
            }))
            .await;
        assert!(matches!(
            self.control.record(deposit_key(&deployment(), &event.id)).await,
            Some(Record::Deposit(recorded)) if recorded == event
        ));
    }

    async fn queue_withdrawal(
        &self,
        request: SignedWithdrawal<Key, Digest>,
        openings: Vec<StateOpening<Key, Digest>>,
    ) {
        let account = request.account().clone();
        self.control
            .submit(SettlementTx::QueueWithdrawal(QueueWithdrawalRequest {
                request: request.clone(),
                openings,
            }))
            .await;
        assert!(matches!(
            self.control.record(withdrawal_key(&deployment(), &account)).await,
            Some(Record::Withdrawal(recorded)) if recorded == request
        ));
    }

    /// Submits the operator's boundary-only signed registration, returning
    /// the registration record it landed, or `None` when the registration
    /// left no effect.
    async fn try_register(&self, operator: &mut Operator) -> Option<RegistrationRecord> {
        let register = operator.signed_registration().unwrap();
        let epoch = register.epoch;
        self.control
            .submit(SettlementTx::RegisterEpoch(register))
            .await;
        match self.control.record(registration_key(&deployment())).await {
            Some(Record::Registration(record)) if record.epoch == epoch => Some(record),
            _ => None,
        }
    }

    /// Registers the operator's live epoch and adopts the chain-assigned
    /// deadlines and anchor from the certified registration record.
    async fn register(&self, operator: &mut Operator) {
        let record = self
            .try_register(operator)
            .await
            .expect("the registration earned no record");
        operator.adopt_registration(&record).unwrap();
    }

    /// Admits `result`'s close and drives the chain to its certified
    /// finalization, asserting the finalized records match the operator's
    /// local rehearsal.
    async fn admit(&self, result: &SettlementResult) {
        self.control
            .submit(SettlementTx::Admit(AdmitRequest::from(result)))
            .await;
        let deadline = result.epoch_context.challenge_deadline();
        let height = self.control.advance(0).await;
        if height <= deadline {
            self.control.advance(deadline - height + 1).await;
        }
        match self
            .control
            .record(admitted_key(&deployment(), result.epoch))
            .await
        {
            Some(Record::Admitted(admitted)) => {
                assert_eq!(admitted.batch_id, result.finalized.batch_id);
                assert_eq!(admitted.change, result.roots.change);
                assert!(admitted.finalized);
            }
            record => panic!("expected an admitted record, found {record:?}"),
        }
        let status = self.status().await;
        assert!(
            status
                .last_finalized
                .is_some_and(|last| last >= result.epoch)
        );
        if status.last_finalized == Some(result.epoch) {
            assert_eq!(status.state_root, result.finalized.successor_root);
            assert_eq!(status.custody, result.finalized.custody_balance);
        }
    }

    async fn status(&self) -> StatusRecord {
        match self.control.record(status_key(&deployment())).await {
            Some(Record::Status(status)) => status,
            record => panic!("expected the status record, found {record:?}"),
        }
    }

    /// Submits one withdrawal claim and resolves it by its effect record:
    /// `Some` when the release record proves exactly this claim consumed the
    /// position, `None` when these bytes released nothing (an unavailable
    /// batch, an adjudicated rejection, or a position consumed by other
    /// bytes are all effect-free for them).
    async fn claim_withdrawal(
        &self,
        batch_id: BatchId<Digest>,
        claim: &WithdrawalClaim<Digest>,
    ) -> Option<WithdrawalResponse> {
        let tx = SettlementTx::ClaimWithdrawal(WithdrawalClaimRequest {
            batch_id,
            claim: claim.clone(),
        });
        self.control.submit(tx).await;
        match self
            .control
            .record(withdrawal_release_key(
                &deployment(),
                &batch_id,
                claim.position(),
            ))
            .await
        {
            Some(Record::WithdrawalRelease(release))
                if release.claim == Sha256::hash(&[&claim.encode()]) =>
            {
                Some(release.released)
            }
            _ => None,
        }
    }

    /// Submits one external-payout claim and resolves it by its effect
    /// record, under the same contract as [`Self::claim_withdrawal`].
    async fn claim_external_payout(
        &self,
        batch_id: BatchId<Digest>,
        claim: &ExternalPayoutClaim<Key, Digest>,
    ) -> Option<ExternalPayoutResponse> {
        let tx = SettlementTx::ClaimExternalPayout(ExternalPayoutClaimRequest {
            batch_id,
            claim: claim.clone(),
        });
        self.control.submit(tx).await;
        match self
            .control
            .record(payout_release_key(
                &deployment(),
                &batch_id,
                claim.position(),
            ))
            .await
        {
            Some(Record::PayoutRelease(release))
                if release.claim == Sha256::hash(&[&claim.encode()]) =>
            {
                Some(release.released)
            }
            _ => None,
        }
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
    let (send, entries) = operator
        .sign_send(0, &[(operator.wallets[1].public_key(), 25)])
        .unwrap();
    let committed = operator
        .accept_send(send.clone(), entries.clone())
        .unwrap()
        .into_accepted();

    // Sign a second send that is never accepted, before any fence blocks quoting.
    let (uncommitted, uncommitted_entries) = operator
        .sign_send(3, &[(operator.wallets[2].public_key(), 1)])
        .unwrap();

    // A close fence blocks admitting new state but leaves the committed rows readable.
    operator.close_fault = Some("fenced after a failed predecessor close".to_string());
    assert!(operator.accept_send(send.clone(), entries.clone()).is_err());
    let resolved = operator
        .accepted_batch(&send, &entries)
        .unwrap()
        .expect("a fenced operator failed to read a committed batch");
    assert_eq!(resolved.acceptance, committed.acceptance);
    assert!(
        operator
            .accepted_batch(&uncommitted, &uncommitted_entries)
            .unwrap()
            .is_none()
    );

    // A storage fault is fatal to the instance until it restarts, so the read refuses
    // to answer instead of reporting a false absence.
    operator.store_fault = Some("the SQLite connection is unusable".to_string());
    assert!(operator.accepted_batch(&send, &entries).is_err());
    assert!(
        operator
            .accepted_batch(&uncommitted, &uncommitted_entries)
            .is_err()
    );
}

#[test]
fn arbitrary_unregistered_receiver_is_rejected_without_a_debit() {
    let mut operator = operator();
    let receiver = Wallet::from_seed("Mallory", 9_999).public_key();
    let (send, entries) = operator.sign_send(0, &[(receiver, 25)]).unwrap();

    assert!(operator.accept_send(send, entries).is_err());
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
        .execute("UPDATE accepted_entries SET opening = zeroblob(256)", [])
        .unwrap();

    let status = operator.status().unwrap();
    assert_eq!(status.accounts, 4);
    assert_eq!(status.present_accounts, 4);
    assert_eq!(status.recent_payments, 1);
}

#[test]
fn payment_head_serves_the_retained_predecessor_cache() {
    let database = TempDatabase::new();
    let mut operator = Operator::open(database.path(), NonZeroUsize::new(2).unwrap()).unwrap();
    let payer = operator.wallets[0].public_key();
    let before = operator.payment_head(&payer).unwrap();
    for amount in [3, 4, 5] {
        operator.pay(0, 1, amount).unwrap();
    }

    // The predecessor commitment is constant across the epoch. Only the live account
    // state moves with accepted payments.
    let after = operator.payment_head(&payer).unwrap();
    assert_eq!(after.root, before.root);
    assert_eq!(after.opening, before.opening);
    assert_eq!(after.state.balance, before.state.balance - 12);
    assert_eq!(
        after.state.cumulative_debit,
        before.state.cumulative_debit + 12
    );

    // Head reads serve the retained cache and never replay the acknowledgment log:
    // tampering with a stored row is invisible here. Startup replays and verifies every
    // row, so the reopened operator must reject the same database loudly.
    let connection = rusqlite::Connection::open(database.path()).unwrap();
    let mut tampered: Vec<u8> = connection
        .query_row("SELECT ack FROM acks WHERE seq = 1", [], |row| row.get(0))
        .unwrap();
    *tampered.last_mut().unwrap() ^= 1;
    connection
        .execute(
            "UPDATE acks SET ack = ?1 WHERE seq = 1",
            [tampered.as_slice()],
        )
        .unwrap();
    let reread = operator.payment_head(&payer).unwrap();
    assert_eq!(reread.root, after.root);
    assert_eq!(reread.state, after.state);
    assert_eq!(reread.opening, after.opening);
    drop(operator);
    drop(connection);

    let error = match Operator::open(database.path(), NonZeroUsize::new(2).unwrap()) {
        Ok(_) => panic!("tampered acknowledgment log reopened cleanly"),
        Err(error) => error,
    };
    assert!(format!("{error:#}").contains("verify stored acknowledgment"));
}

#[test]
fn payment_retry_returns_the_original_receipt_without_a_second_debit() {
    let mut operator = operator();
    let receiver = operator.wallets[1].public_key();
    let (send, entries) = operator.sign_send(0, &[(receiver, 25)]).unwrap();

    let first = operator
        .accept_send(send.clone(), entries.clone())
        .unwrap()
        .into_accepted();
    let retry = operator.accept_send(send, entries).unwrap().into_accepted();
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
    let receiver = operator.wallets[1].public_key();
    let (send, entries) = operator.sign_send(0, &[(receiver, 25)]).unwrap();

    let first = operator
        .accept_send(send.clone(), entries.clone())
        .unwrap()
        .into_accepted();
    rotate_epoch(&mut operator, 0);
    assert!(
        !operator
            .send_requires_epoch_registration(&send, &entries)
            .unwrap()
    );
    let retry = operator.accept_send(send, entries).unwrap().into_accepted();

    assert_eq!(retry.epoch, first.epoch);
    assert_eq!(retry.sequence, first.sequence);
    assert_eq!(retry.acceptance, first.acceptance);
    assert_eq!(operator.snapshot().unwrap().payments.len(), 0);
}

/// Pins the endpoint exclusivity that makes the wallet's corrective retry safe: an
/// old-context send and its re-signed successor authorize the same cumulative debit
/// interval, so offering both to closes commits at most one of them.
#[test]
fn corrective_retry_and_kept_send_commit_at_most_once() {
    // The Byzantine keep: the operator accepts the old-context send it claimed to
    // reject and cuts the epoch, so that close commits the endpoint. The corrective
    // retry at the same endpoint then has a zero delta against the committed debit and
    // is infeasible in every later close.
    let mut byzantine = operator();
    let payer = byzantine.wallets[0].public_key();
    let receiver = byzantine.wallets[1].public_key();
    let (kept, kept_entries) = byzantine.sign_send(0, &[(receiver.clone(), 7)]).unwrap();
    byzantine
        .accept_send(kept, kept_entries)
        .unwrap()
        .into_accepted();
    rotate_epoch(&mut byzantine, 0);
    let successor = byzantine.registration.context.payment().clone();
    let (retry, retry_entries) = sign_send_at(
        &successor,
        &byzantine.wallets[0],
        &Endpoint {
            cumulative_debit: 0,
            seq: 0,
            entries: Vec::new(),
        },
        &[(receiver.clone(), 7)],
    )
    .unwrap();
    match byzantine.accept_send(retry, retry_entries).unwrap() {
        SendOutcome::Stale {
            cumulative_debit,
            seq,
            entries,
            ..
        } => {
            assert_eq!(cumulative_debit, 7);
            assert_eq!(seq, 0);
            assert!(entries.is_empty());
        }
        SendOutcome::Accepted(_) => panic!("a zero-delta corrective retry was accepted"),
    }
    assert_eq!(
        byzantine
            .payment_head(&payer)
            .unwrap()
            .state
            .cumulative_debit,
        7
    );

    // The honest roll: the old-context send was never accepted and its epoch is cut,
    // so only the retry commits. The dead bytes afterward earn the typed corrective
    // rejection carrying the live context and the committed endpoint, never a debit.
    let mut honest = operator();
    let (dead, dead_entries) = honest.sign_send(0, &[(receiver.clone(), 7)]).unwrap();

    // An unrelated payment gives the epoch content to close. The payer's send was
    // never accepted, so the cut commits nothing of it.
    honest.pay(2, 3, 5).unwrap();
    rotate_epoch(&mut honest, 0);
    let (retry, retry_entries) = honest.sign_send(0, &[(receiver.clone(), 7)]).unwrap();
    let committed = honest
        .accept_send(retry, retry_entries)
        .unwrap()
        .into_accepted();
    assert_eq!(committed.total, 7);
    match honest.accept_send(dead, dead_entries).unwrap() {
        SendOutcome::Stale {
            context,
            cumulative_debit,
            seq,
            entries,
        } => {
            assert_eq!(&context, honest.registration.context.payment());
            assert_eq!(cumulative_debit, 7);
            assert_eq!(seq, 1);
            assert_eq!(
                entries,
                vec![OutEntry {
                    recipient: receiver,
                    cumulative: 7,
                    count: 1,
                }]
            );
        }
        SendOutcome::Accepted(_) => panic!("a dead-context send was accepted"),
    }
    assert_eq!(
        honest.payment_head(&payer).unwrap().state.cumulative_debit,
        7
    );
}

/// A re-signed different body at an already accepted sequence is wallet equivocation
/// against its own endpoint chain, so acceptance fails closed instead of correcting.
#[test]
fn conflicting_body_at_an_accepted_sequence_is_refused() {
    let mut operator = operator();
    let payer = operator.wallets[0].public_key();
    let receiver = operator.wallets[2].public_key();
    operator.pay(0, 1, 7).unwrap();

    // Sequence one is committed crediting wallet one. Re-sign it crediting wallet two
    // with the same endpoint arithmetic.
    let context = operator.registration.context.payment().clone();
    let (conflict, conflict_entries) = sign_send_at(
        &context,
        &operator.wallets[0],
        &Endpoint {
            cumulative_debit: 0,
            seq: 0,
            entries: Vec::new(),
        },
        &[(receiver, 7)],
    )
    .unwrap();
    let error = match operator.accept_send(conflict, conflict_entries) {
        Ok(_) => panic!("a conflicting body at an accepted sequence was admitted"),
        Err(error) => error,
    };
    assert!(format!("{error:#}").contains("bound to another accepted endpoint"));
    assert_eq!(
        operator
            .payment_head(&payer)
            .unwrap()
            .state
            .cumulative_debit,
        7
    );
    assert_eq!(operator.snapshot().unwrap().payments.len(), 1);
}

#[test]
fn incoming_entries_serve_verifiable_receipts_in_cursor_order() {
    let mut operator = operator();
    let receiver = operator.wallets[1].public_key();
    operator.pay(0, 1, 2).unwrap();
    operator.pay(2, 1, 3).unwrap();
    let context = operator.registration.context.payment().clone();

    let first = operator.incoming_payments(&receiver, 0, 10).unwrap();
    assert_eq!(first.len(), 2);
    for incoming in &first {
        assert_eq!(incoming.receipt.recipient, receiver);
        incoming.receipt.verify::<Sha256>(&context).unwrap();
    }
    let after = operator
        .incoming_payments(&receiver, first[0].sequence, 10)
        .unwrap();
    assert_eq!(after.len(), 1);
    assert_eq!(after[0].sequence, first[1].sequence);

    // A second batch from the same payer advances the same edge cumulatively.
    operator.pay(0, 1, 5).unwrap();
    let all = operator.incoming_payments(&receiver, 0, 10).unwrap();
    assert_eq!(all.len(), 3);
    assert_eq!(all[2].receipt.cumulative, 7);
    assert_eq!(all[2].receipt.count, 2);
    all[2].receipt.verify::<Sha256>(&context).unwrap();
}

#[test]
fn committed_entry_serves_the_retained_close() {
    let mut operator = operator();
    let payer = operator.wallets[0].public_key();
    let receiver = operator.wallets[1].public_key();
    operator.pay(0, 1, 7).unwrap();
    let epoch = start_current_close(&mut operator).unwrap().epoch;
    operator.wait_for_closes().unwrap();

    // The credited edge resolves to its committed terminal entry.
    let evidence = operator.committed_entry(&payer, &receiver, epoch).unwrap();
    let change_root = evidence.change_root;
    assert_eq!(
        evidence
            .lookup
            .resolve::<Sha256>(&evidence.change_root, &payer, &receiver)
            .unwrap(),
        (7, 1)
    );

    // A changed credit-only row resolves the reverse edge through its empty vector, and
    // a payer outside the close resolves through ordered change-vector absence: both
    // land on the canonical zero entry.
    let evidence = operator.committed_entry(&receiver, &payer, epoch).unwrap();
    assert_eq!(
        evidence
            .lookup
            .resolve::<Sha256>(&evidence.change_root, &receiver, &payer)
            .unwrap(),
        (0, 0)
    );
    let idle = operator.wallets[3].public_key();
    let evidence = operator.committed_entry(&idle, &receiver, epoch).unwrap();
    assert_eq!(
        evidence
            .lookup
            .resolve::<Sha256>(&evidence.change_root, &idle, &receiver)
            .unwrap(),
        (0, 0)
    );

    // The successor's finalization must not take the evidence with it: the payer keeps
    // moving in every later epoch, yet the close reconstructs exactly until RETAINED_EPOCHS
    // further epochs have finalized, and only then do the pruned versions refuse it.
    let close_successor = |operator: &mut Operator| {
        operator.pay(0, 2, 1).unwrap();
        start_current_close(operator).unwrap();
        operator.wait_for_closes().unwrap();
    };
    let served = |operator: &Operator| {
        let evidence = operator.committed_entry(&payer, &receiver, epoch).unwrap();
        assert_eq!(evidence.change_root, change_root);
        assert_eq!(
            evidence
                .lookup
                .resolve::<Sha256>(&evidence.change_root, &payer, &receiver)
                .unwrap(),
            (7, 1)
        );
    };
    close_successor(&mut operator);
    served(&operator);
    for _ in 1..RETAINED_EPOCHS {
        close_successor(&mut operator);
        served(&operator);
    }
    close_successor(&mut operator);
    assert!(operator.committed_entry(&payer, &receiver, epoch).is_err());
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
    let context = operator.registration.context.payment().clone();
    let (send, entries) = operator
        .sign_send(
            0,
            &[
                (operator.wallets[1].public_key(), 2),
                (operator.wallets[2].public_key(), 3),
                (operator.external.key.clone(), 1),
            ],
        )
        .unwrap();

    let first = operator
        .accept_send(send.clone(), entries.clone())
        .unwrap()
        .into_accepted();
    assert_eq!(first.total, 6);
    assert_eq!(first.acceptance.entries.len(), 3);
    first.acceptance.verify(&context).unwrap();
    assert!(
        first
            .acceptance
            .receipts()
            .all(|receipt| receipt.ack == first.acceptance.ack)
    );
    let retry = operator.accept_send(send, entries).unwrap().into_accepted();
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

    // The close replay walks the payer's endpoint once per batch and each entry's edge step.
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

/// The restart hard-fault arc: an epoch is registered and adopted, the
/// operator dies before cutting, and the admission runway keeps expiring
/// while it is down. Startup must resume the cut itself (no agent RPC is
/// owed) and the close must still admit inside the driven window.
#[test]
fn registered_epoch_restart_resumes_the_cut_and_admits() {
    deterministic::Runner::default().start(|context| async move {
        let database = TempDatabase::new();
        let chain = Chain::new(&context).await;
        let record = {
            let mut operator =
                Operator::open(database.path(), NonZeroUsize::new(2).unwrap()).unwrap();

            // A fresh operator has nothing to resume.
            assert!(operator.resume_registered_close().unwrap().is_none());

            // The first send triggers the registration before it is accepted,
            // so adopt the assigned deadlines and then take the payment.
            let record = chain
                .try_register(&mut operator)
                .await
                .expect("the registration earned no record");
            operator.adopt_registration(&record).unwrap();

            // An adopted registration without work is not resumable: there is
            // nothing to close.
            assert!(operator.resume_registered_close().unwrap().is_none());
            operator.pay(0, 1, 25).unwrap();

            // Killed here: the epoch is registered and adopted, the cut is not.
            record
        };

        // Most of the admission runway passes while the operator is down.
        let height = chain.control.advance(0).await;
        assert!(height + 3 <= record.admission_deadline);
        chain
            .control
            .advance(record.admission_deadline - 3 - height)
            .await;

        // Startup resumes the cut from the adopted registration alone.
        let mut recovered = Operator::open(database.path(), NonZeroUsize::new(2).unwrap()).unwrap();
        let started = recovered
            .resume_registered_close()
            .unwrap()
            .expect("the adopted registration resumes its cut");
        assert_eq!(started.epoch, 0);
        assert!(!started.queued);
        assert_eq!(recovered.store.epoch().unwrap(), 1);

        // The cut is durable and the successor is unregistered, so a second
        // resume finds nothing to do.
        assert!(recovered.resume_registered_close().unwrap().is_none());
        assert!(matches!(
            recovered.wait_for_closes().unwrap().as_slice(),
            [CloseEvent::Finished(close)] if close.epoch == 0
        ));

        // The resumed worker is seeded by its epoch, so its exact certified
        // result rebuilds here and admits inside the driven window.
        let data = recovered.store.epoch_reader().load(0).unwrap();
        let registration = registration_for(&recovered.protocol, &data).unwrap();
        let prepared = prepare_epoch(&recovered.protocol, data, registration).unwrap();
        let result = recovered
            .protocol
            .complete(prepared, &mut TestRng::new(0))
            .unwrap();
        chain.admit(&result).await;
    });
}

/// The close rehearsal must derive its intake horizons from the deadlines it
/// rehearses. Under a genesis challenge duration past the fixed constants it
/// once reused, the rehearsal broke twice on a perfectly finalizable close:
/// its notice window rejected the carried withdrawal outright ("withdrawal
/// deadline exceeds the maximum notice"), and a deferred deposit (recorded
/// by the rehearsal but consumed by no boundary) expired before the finalize
/// tick, silently hard-faulting the rehearsal chain.
#[test]
fn close_rehearsal_survives_a_long_genesis_challenge_window() {
    let mut operator = operator();

    // A staged deposit exactly offset by the account's withdrawal defers
    // whole to the successor boundary, so the rehearsal records it without
    // admitting it: it stays pending through the finalize tick.
    operator
        .observe(&[DepositEvent {
            id: Sha256::hash(&[b"long-window-deferred-deposit"]),
            account: wallets()[0].public_key(),
            amount: 5,
        }])
        .unwrap();
    let wallet = wallets().remove(0);
    let request = SignedWithdrawal::sign(
        deployment(),
        operator.predecessor.root().digest,
        Bytes::copy_from_slice(wallet.name.as_bytes()),
        amount(5),
        500,
        wallet.signer(),
    );
    operator.apply_withdrawal(request).unwrap();

    // Adopt chain-shaped deadlines whose challenge window outgrows the fixed
    // deposit timeout a rehearsal would otherwise reuse.
    let admission_deadline = 40;
    let challenge_deadline = admission_deadline + 420;
    let replacement = operator
        .protocol
        .registration_at(
            0,
            staged_deposits(&operator.registration).unwrap(),
            operator.registration.withdrawals.clone(),
            operator.registration.context.predecessor_liability(),
            admission_deadline,
            challenge_deadline,
        )
        .unwrap();
    let deposits_root = replacement.deposits.root::<Sha256>().unwrap();
    operator
        .adopt_registration(&RegistrationRecord {
            epoch: 0,
            predecessor_liability: operator.registration.context.predecessor_liability(),
            anchor: *replacement.context.payment().anchor(),
            admission_deadline,
            challenge_deadline,
            deposits_root,
            staged_root: deposits_root,
            withdrawals_root: replacement.withdrawals.root::<Sha256>().unwrap(),
            admitted: None,
        })
        .unwrap();

    let result = operator.complete_close(45).unwrap();
    assert_eq!(result.epoch, 0);

    // The deferred deposit rode through as the successor's parked aggregate:
    // it was never in this close's boundary and never expired.
    assert_eq!(result.deposits.total(), 0);
    assert_eq!(result.finalized.withdrawal_total, 5);
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
            .payment_head(&operator.wallets[0].public_key())
            .is_err()
    );
    assert!(operator.validate_close_start(terminal_epoch).is_err());
    assert!(operator.signed_registration().is_err());
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
            .payment_head(&operator.wallets[0].public_key())
            .is_err()
    );
    operator.validate_close_start(epoch).unwrap();
    assert_eq!(operator.signed_registration().unwrap().epoch, epoch);
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
    assert_eq!(operator.signed_registration().unwrap().epoch, epoch);
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
            .payment_head(&operator.wallets[1].public_key())
            .unwrap()
            .state
            .balance,
        100
    );

    let receiver = operator.wallets[1].public_key();
    let (incoming, incoming_entries) = operator.sign_send(0, &[(receiver.clone(), 7)]).unwrap();
    assert!(
        operator
            .send_requires_epoch_registration(&incoming, &incoming_entries)
            .unwrap()
    );
    operator
        .accept_send(incoming, incoming_entries)
        .unwrap()
        .into_accepted();

    let (outgoing, outgoing_entries) = operator
        .sign_send(1, &[(operator.wallets[2].public_key(), 12)])
        .unwrap();
    operator
        .accept_send(outgoing, outgoing_entries)
        .unwrap()
        .into_accepted();

    let data = operator.store.load_current().unwrap();
    let bob = data
        .accounts
        .iter()
        .find(|account| account.key == receiver)
        .unwrap();
    assert_eq!(bob.current.balance, 95);
    assert_eq!(bob.current.cumulative_debit, 12);
    assert_eq!(bob.current.cumulative_credit, 7);
    assert_eq!(bob.current.receipt_count, 1);
    let prepared = prepare_epoch(&operator.protocol, data, operator.registration.clone()).unwrap();

    rotate_epoch(&mut operator, 0);
    assert_eq!(operator.store.current_liability().unwrap(), 305);
    assert!(operator.store.current_account(&receiver).unwrap().is_none());
    let frozen = operator.store.epoch_reader().load(0).unwrap();
    let bob = frozen
        .accounts
        .iter()
        .find(|account| account.key == receiver)
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
    assert!(operator.store.load_current().unwrap().entries[0].external);
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
    let (invalid, invalid_entries) = operator
        .sign_send(0, &[(operator.wallets[1].public_key(), 101)])
        .unwrap();

    assert!(
        operator
            .send_requires_epoch_registration(&invalid, &invalid_entries)
            .is_err()
    );
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

    // Inside the retention window nothing is pruned: the drained account is already gone
    // from the live epoch, while its finalized zero version still reconstructs epoch 1.
    assert_eq!(operator.store.account_version_count().unwrap(), 7);
    let drained = operator.wallets[0].name;
    let gone = |data: EpochData| data.accounts.iter().all(|account| account.name != drained);
    assert!(gone(operator.store.load_current().unwrap()));
    assert!(!gone(operator.store.epoch_reader().load(1).unwrap()));

    // Finalizing RETAINED_EPOCHS further epochs retires epoch 1's obsolete versions, the
    // three epoch-0 versions its payers shadow plus the drained account's epoch-1 zero,
    // while every epoch still inside the window keeps its versions.
    for epoch in 2..=RETAINED_EPOCHS + 1 {
        operator.pay(1, 2, 1).unwrap();
        let data = operator.store.load_current().unwrap();
        let prepared =
            prepare_epoch(&operator.protocol, data, operator.registration.clone()).unwrap();
        assert_eq!(prepared.epoch(), epoch);
        rotate_epoch(&mut operator, epoch);
        operator
            .finish_prepared(prepared, &mut TestRng::new(40 + epoch))
            .unwrap();
    }
    assert_eq!(
        operator.store.account_version_count().unwrap(),
        7 + 2 * RETAINED_EPOCHS - 4
    );
    assert!(gone(operator.store.epoch_reader().load(1).unwrap()));
    assert!(gone(operator.store.load_current().unwrap()));
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

    // Finalizing epoch 1 inside the retention window prunes nothing, and the unfinalized
    // epoch-2 deposit version stays the live one.
    assert_eq!(operator.store.account_version_count().unwrap(), 6);
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
    let receiver = operator.wallets[2].public_key();
    let (send, entries) = sign_send_at(
        &stale,
        &operator.wallets[1],
        &Endpoint {
            cumulative_debit: 0,
            seq: 0,
            entries: Vec::new(),
        },
        &[(receiver, 1)],
    )
    .unwrap();

    let error = match operator
        .store
        .accept_send(&stale, &operator.protocol, send, &entries)
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
            .find(|account| account.name == operator.wallets[1].name)
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
fn recovery_bounds_entry_blobs_before_decoding() {
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
        .execute(
            "UPDATE accepted_entries SET opening = zeroblob(1048576)",
            [],
        )
        .unwrap();
    drop(connection);

    let error = match Operator::open(database.path(), NonZeroUsize::new(2).unwrap()) {
        Ok(_) => panic!("oversized entry opening was accepted"),
        Err(error) => error,
    };
    assert!(format!("{error:#}").contains("invalid entry opening length"));
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
    deterministic::Runner::default().start(|context| async move {
        let chain = Chain::new(&context).await;
        let mut operator = operator();

        // Registration precedes the epoch's first receipt, as the service
        // orders it: adopting the chain-assigned deadlines moves the anchor.
        chain.register(&mut operator).await;
        operator.pay(0, operator.wallet_count(), 100).unwrap();
        let data = operator.store.load_current().unwrap();
        let prepared =
            prepare_epoch(&operator.protocol, data, operator.registration.clone()).unwrap();
        let epoch = prepared.epoch();
        rotate_epoch(&mut operator, epoch);
        let result = operator
            .protocol
            .complete(prepared, &mut TestRng::new(8))
            .unwrap();
        assert_eq!(result.finalized.payout_total, 100);
        chain.admit(&result).await;
        let batch_id = result.finalized.batch_id;
        let claim = result.external_claims.first().unwrap();
        let payout = released(chain.claim_external_payout(batch_id, claim).await);
        assert_eq!(payout.receiver, external_identity().key);
        assert_eq!(payout.amount, 100);
        assert_eq!(
            released(chain.claim_external_payout(batch_id, claim).await),
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
        assert_eq!(evidence.batch_id, batch_id);
        operator
            .acknowledge_external_payout_claim(evidence.batch_id, &evidence.claim)
            .unwrap();
        assert_eq!(operator.snapshot().unwrap().reserved_payout_value, 0);
        assert!(
            operator
                .external_payout_evidence(&external_identity().key)
                .is_err()
        );
    });
}

#[test]
fn unclaimed_batch_does_not_block_later_finalization() {
    deterministic::Runner::default().start(|context| async move {
        let chain = Chain::new(&context).await;
        let mut operator = operator();

        chain.register(&mut operator).await;
        operator.pay(0, operator.wallet_count(), 100).unwrap();
        let data = operator.store.load_current().unwrap();
        let prepared =
            prepare_epoch(&operator.protocol, data, operator.registration.clone()).unwrap();
        let epoch = prepared.epoch();
        rotate_epoch(&mut operator, epoch);
        let first = operator
            .protocol
            .complete(prepared, &mut TestRng::new(31))
            .unwrap();
        chain.admit(&first).await;
        operator
            .store
            .finish_close(&first, operator.genesis_root)
            .unwrap();

        chain.register(&mut operator).await;
        operator.pay(1, operator.wallet_count(), 100).unwrap();
        let data = operator.store.load_current().unwrap();
        let prepared =
            prepare_epoch(&operator.protocol, data, operator.registration.clone()).unwrap();
        let epoch = prepared.epoch();
        rotate_epoch(&mut operator, epoch);
        let second = operator
            .protocol
            .complete(prepared, &mut TestRng::new(32))
            .unwrap();
        chain.admit(&second).await;
        assert_eq!(chain.status().await.claimable, 200);

        let first_batch = first.finalized.batch_id;
        let second_batch = second.finalized.batch_id;
        let first_claim = first.external_claims.first().unwrap();
        assert_eq!(first_claim.position(), 0);
        let second_claim = second.external_claims.first().unwrap();
        assert_eq!(second_claim.position(), 0);
        assert_ne!(second_batch, first_batch);

        // An unknown batch is an availability signal, never a verdict on the claim.
        assert_eq!(
            chain
                .claim_external_payout(
                    BatchId::new(Sha256::hash(&[b"unknown-payout-batch"])),
                    first_claim,
                )
                .await,
            None
        );

        // A claim adjudicated against the wrong finalized batch is definitively invalid.
        assert_eq!(
            chain.claim_external_payout(first_batch, second_claim).await,
            None
        );
        let first_payout = released(chain.claim_external_payout(first_batch, first_claim).await);
        let second_payout = released(
            chain
                .claim_external_payout(second_batch, second_claim)
                .await,
        );
        assert_eq!(
            released(
                chain
                    .claim_external_payout(second_batch, second_claim)
                    .await
            ),
            second_payout
        );

        // A consumed position replays only for the exact recorded claim: the
        // exact bytes stay provably released through the release record,
        // while a foreign claim against the drained batch releases nothing
        // and never can.
        assert_eq!(
            chain.claim_external_payout(first_batch, second_claim).await,
            None
        );
        assert_eq!(
            released(chain.claim_external_payout(first_batch, first_claim).await),
            first_payout
        );
        assert_eq!(chain.status().await.claimable, 0);
    });
}

#[test]
fn finalized_withdrawal_replays_after_a_later_claim() {
    deterministic::Runner::default().start(|context| async move {
        let chain = Chain::new(&context).await;
        let mut operator = operator();

        operator.withdraw(0, amount(25)).unwrap();
        let first_account = operator.wallets[0].public_key();
        let first_opening = operator.withdrawal_opening(&first_account).unwrap();
        let data = operator.store.load_current().unwrap();
        chain
            .queue_withdrawal(
                data.withdrawals[0].request.clone(),
                vec![first_opening.opening],
            )
            .await;
        chain.register(&mut operator).await;
        let data = operator.store.load_current().unwrap();
        let prepared =
            prepare_epoch(&operator.protocol, data, operator.registration.clone()).unwrap();
        let epoch = prepared.epoch();
        rotate_epoch(&mut operator, epoch);
        let first = operator
            .protocol
            .complete(prepared, &mut TestRng::new(33))
            .unwrap();
        chain.admit(&first).await;
        operator
            .store
            .finish_close(&first, operator.genesis_root)
            .unwrap();

        let first_batch = first.finalized.batch_id;
        let first_claim = first.withdrawal_claims.first().unwrap();
        assert_eq!(first_claim.position(), 0);

        // An unknown batch is an availability signal, never a verdict on the claim.
        assert_eq!(
            chain
                .claim_withdrawal(
                    BatchId::new(Sha256::hash(&[b"unknown-withdrawal-batch"])),
                    first_claim,
                )
                .await,
            None
        );
        let first_output = released(chain.claim_withdrawal(first_batch, first_claim).await);

        operator.withdraw(1, amount(30)).unwrap();
        let second_account = operator.wallets[1].public_key();
        let second_opening = operator.withdrawal_opening(&second_account).unwrap();
        let data = operator.store.load_current().unwrap();
        chain
            .queue_withdrawal(
                data.withdrawals[0].request.clone(),
                vec![second_opening.opening],
            )
            .await;
        chain.register(&mut operator).await;
        let data = operator.store.load_current().unwrap();
        let prepared =
            prepare_epoch(&operator.protocol, data, operator.registration.clone()).unwrap();
        let epoch = prepared.epoch();
        rotate_epoch(&mut operator, epoch);
        let second = operator
            .protocol
            .complete(prepared, &mut TestRng::new(34))
            .unwrap();
        chain.admit(&second).await;

        let second_batch = second.finalized.batch_id;
        let second_claim = second.withdrawal_claims.first().unwrap();
        assert_eq!(second_claim.position(), 0);
        assert_ne!(second_batch, first_batch);
        let second_output = released(chain.claim_withdrawal(second_batch, second_claim).await);
        assert_eq!(
            released(chain.claim_withdrawal(second_batch, second_claim).await),
            second_output
        );

        // A consumed position replays only for the exact recorded claim: the
        // exact bytes stay provably released through the release record,
        // while a foreign claim against the drained batch releases nothing
        // and never can.
        assert_eq!(
            chain.claim_withdrawal(first_batch, second_claim).await,
            None
        );
        assert_eq!(
            released(chain.claim_withdrawal(first_batch, first_claim).await),
            first_output
        );
        assert_eq!(chain.status().await.claimable, 0);
    });
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
    let receiver = external_identity().key;
    operator.pay(0, operator.wallet_count(), 10).unwrap();
    let data = operator.store.load_current().unwrap();
    let prepared = prepare_epoch(&operator.protocol, data, operator.registration.clone()).unwrap();
    let epoch = prepared.epoch();
    rotate_epoch(&mut operator, epoch);
    operator
        .finish_prepared(prepared, &mut TestRng::new(19))
        .unwrap();

    let first = operator.external_payout_evidence(&receiver).unwrap();
    let retry = operator.external_payout_evidence(&receiver).unwrap();
    assert_eq!(retry.batch_id, first.batch_id);
    assert_eq!(retry.claim, first.claim);

    operator
        .acknowledge_external_payout_claim(first.batch_id, &first.claim)
        .unwrap();
    assert!(operator.external_payout_evidence(&receiver).is_err());
}

#[test]
fn ordinary_withdrawal_is_included_and_claimable() {
    deterministic::Runner::default().start(|context| async move {
        let chain = Chain::new(&context).await;
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
        chain.queue_withdrawal(request, vec![opening.opening]).await;
        chain.register(&mut operator).await;
        let data = operator.store.load_current().unwrap();
        let prepared =
            prepare_epoch(&operator.protocol, data, operator.registration.clone()).unwrap();
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
        chain.admit(&result).await;
        let release = released(
            chain
                .claim_withdrawal(evidence.batch_id, &evidence.claim)
                .await,
        );
        assert_eq!(release.amount, 25);
        assert_eq!(release.destination.as_ref(), b"Alice");
        assert_eq!(release.amount, evidence.claim.output().amount());
        assert_eq!(&release.destination, evidence.claim.output().destination());
        assert_eq!(
            released(
                chain
                    .claim_withdrawal(evidence.batch_id, &evidence.claim)
                    .await,
            ),
            release
        );
    });
}

#[test]
fn exact_offset_deposit_defers_and_settles_in_the_next_epoch() {
    deterministic::Runner::default().start(|context| async move {
        let chain = Chain::new(&context).await;
        let mut operator = operator();
        let account = operator.wallets[0].public_key();
        let event = |label: &'static [u8], amount: u64| DepositEvent {
            id: Sha256::hash(&[label]),
            account: account.clone(),
            amount,
        };

        // The verified honest sequence: deposit 3, carried withdrawal Amount(7), then
        // deposit 4. The chain takes custody first, so the operator must credit every
        // recorded event without refusing any shape.
        let first = event(b"honest-offset-deposit-3", 3);
        chain.deposit(first.clone()).await;
        let deposit_recorded = chain.status().await.height;
        operator.observe(&[first]).unwrap();
        operator.withdraw(0, amount(7)).unwrap();
        let second = event(b"honest-offset-deposit-4", 4);
        chain.deposit(second.clone()).await;
        let staged = operator.observe(&[second]).unwrap().remove(0);
        assert_eq!(staged.epoch, 1);

        // Registration succeeds with the whole aggregate deferred: the committed boundary
        // is empty and the staged view matches the chain's custody record. It runs
        // before the epoch's first receipt, as the service orders it.
        assert_eq!(
            operator.signed_registration().unwrap().deposits_root,
            DepositBatch::<Key>::empty().root::<Sha256>().unwrap()
        );
        chain.register(&mut operator).await;

        // The deferring aggregate is unspendable during the deferring epoch: this close's
        // row for the account carries no deposit.
        assert_eq!(operator.payment_head(&account).unwrap().state.balance, 93);
        assert!(operator.pay(0, 1, 94).is_err());
        operator.pay(0, 1, 5).unwrap();
        rotate_epoch(&mut operator, 0);

        // The close worker loads the frozen epoch after cutover, so the deferral must
        // re-derive from the parked rows alone, under the persisted chain deadlines.
        let frozen = operator.store.epoch_reader().load(0).unwrap();
        let recovered = registration_for(&operator.protocol, &frozen).unwrap();
        let prepared = prepare_epoch(&operator.protocol, frozen, recovered).unwrap();
        let first_close = operator
            .protocol
            .complete(prepared, &mut TestRng::new(51))
            .unwrap();

        // The rehearsal staged the deferred aggregate too, so the chain's certified
        // finalization reproduces it exactly, custody included.
        chain.admit(&first_close).await;
        operator
            .store
            .finish_close(&first_close, operator.genesis_root)
            .unwrap();
        let release = released(
            chain
                .claim_withdrawal(
                    first_close.finalized.batch_id,
                    &first_close.withdrawal_claims[0],
                )
                .await,
        );
        assert_eq!(release.amount, 7);

        // The deferred aggregate lands staged and spendable in the successor epoch.
        assert_eq!(operator.payment_head(&account).unwrap().state.balance, 95);
        assert_eq!(operator.signed_registration().unwrap().epoch, 1);
        chain.register(&mut operator).await;
        let data = operator.store.load_current().unwrap();
        let prepared =
            prepare_epoch(&operator.protocol, data, operator.registration.clone()).unwrap();
        rotate_epoch(&mut operator, 1);
        let second_close = operator
            .protocol
            .complete(prepared, &mut TestRng::new(52))
            .unwrap();
        chain.admit(&second_close).await;
        operator
            .store
            .finish_close(&second_close, operator.genesis_root)
            .unwrap();

        // The deferral consumed one close of deadline headroom and the demo geometry
        // still includes the deposit well before its inclusion deadline.
        let status = chain.status().await;
        assert!(!status.hard_faulted);
        let deposit_deadline = deposit_recorded
            + crate::protocol::settlement_config(&crate::protocol::Timing::DEFAULT)
                .deposit_inclusion_timeout
                .get();
        assert!(status.height < deposit_deadline);
    });
}

#[test]
fn exact_offset_withdrawal_defers_at_intake() {
    let mut operator = operator();
    let account = operator.wallets[0].public_key();
    operator.deposit(0, 7).unwrap();
    assert_eq!(operator.payment_head(&account).unwrap().state.balance, 107);

    operator.withdraw(0, amount(7)).unwrap();
    assert_eq!(operator.payment_head(&account).unwrap().state.balance, 93);
    assert_eq!(operator.registration.deposits.amount_for(&account), 0);
    assert_eq!(operator.registration.deferred.amount_for(&account), 7);
}

#[test]
fn growing_aggregate_returns_a_parked_deposit_to_its_epoch() {
    let mut operator = operator();
    let account = operator.wallets[0].public_key();
    operator.deposit(0, 7).unwrap();
    operator.withdraw(0, amount(7)).unwrap();
    assert_eq!(operator.payment_head(&account).unwrap().state.balance, 93);

    // The grown aggregate no longer offsets the withdrawal exactly, so the whole
    // aggregate returns to this epoch's boundary with its credit.
    operator.deposit(0, 5).unwrap();
    assert_eq!(operator.payment_head(&account).unwrap().state.balance, 105);
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
    assert_eq!(operator.payment_head(&account).unwrap().state.balance, 100);

    // A carried exact offset parks the carried-in aggregate again, and a later
    // deposit that breaks the offset returns it whole with its origin intact.
    operator.withdraw(0, amount(7)).unwrap();
    assert_eq!(operator.payment_head(&account).unwrap().state.balance, 86);
    assert_eq!(operator.registration.deferred.amount_for(&account), 7);
    operator.deposit(0, 5).unwrap();
    assert_eq!(operator.payment_head(&account).unwrap().state.balance, 98);
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
    assert_eq!(operator.payment_head(&account).unwrap().state.balance, 93);
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
    assert_eq!(operator.payment_head(&account).unwrap().state.balance, 105);
    operator.withdraw(0, amount(100)).unwrap();
    assert_eq!(operator.payment_head(&account).unwrap().state.balance, 5);
}

#[test]
fn queued_exact_offset_re_defers_the_carried_aggregate() {
    deterministic::Runner::default().start(|context| async move {
        let chain = Chain::new(&context).await;
        let mut operator = operator();
        let account = operator.wallets[0].public_key();
        async fn close(
            chain: &Chain,
            operator: &mut Operator,
            epoch: u64,
            seed: u64,
        ) -> SettlementResult {
            rotate_epoch(operator, epoch);
            let frozen = operator.store.epoch_reader().load(epoch).unwrap();
            let recovered = registration_for(&operator.protocol, &frozen).unwrap();
            let prepared = prepare_epoch(&operator.protocol, frozen, recovered).unwrap();
            let result = operator
                .protocol
                .complete(prepared, &mut TestRng::new(seed))
                .unwrap();
            chain.admit(&result).await;
            operator
                .store
                .finish_close(&result, operator.genesis_root)
                .unwrap();
            result
        }

        // The deposit parks under a carried exact-offset withdrawal and lands in the
        // successor epoch.
        let event = DepositEvent {
            id: Sha256::hash(&[b"re-deferral-deposit"]),
            account: account.clone(),
            amount: 7,
        };
        chain.deposit(event.clone()).await;
        let deposit_recorded = chain.status().await.height;
        operator.observe(&[event]).unwrap();
        operator.withdraw(0, amount(7)).unwrap();
        chain.register(&mut operator).await;
        let first_close = close(&chain, &mut operator, 0, 54).await;
        assert_eq!(operator.payment_head(&account).unwrap().state.balance, 100);

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
        chain
            .queue_withdrawal(queued.clone(), vec![opening.opening])
            .await;
        operator.apply_withdrawal(queued).unwrap();
        assert_eq!(operator.payment_head(&account).unwrap().state.balance, 86);
        assert_eq!(operator.registration.deferred.amount_for(&account), 7);
        chain.register(&mut operator).await;
        let second_close = close(&chain, &mut operator, 1, 55).await;

        // The twice-deferred deposit lands spendable two epochs after intake and is
        // included well before its inclusion deadline in the demo geometry.
        assert_eq!(operator.payment_head(&account).unwrap().state.balance, 93);
        assert_eq!(operator.registration.deposits.amount_for(&account), 7);
        chain.register(&mut operator).await;
        close(&chain, &mut operator, 2, 56).await;
        let status = chain.status().await;
        assert!(!status.hard_faulted);
        let deposit_deadline = deposit_recorded
            + crate::protocol::settlement_config(&crate::protocol::Timing::DEFAULT)
                .deposit_inclusion_timeout
                .get();
        assert!(status.height < deposit_deadline);

        // Both withdrawal reserves release.
        for result in [&first_close, &second_close] {
            let release = released(
                chain
                    .claim_withdrawal(result.finalized.batch_id, &result.withdrawal_claims[0])
                    .await,
            );
            assert_eq!(release.amount, 7);
        }
    });
}

#[test]
fn hidden_staged_divergence_is_rejected_at_registration_until_the_credit_heals() {
    deterministic::Runner::default().start(|context| async move {
        let chain = Chain::new(&context).await;
        let mut operator = operator();
        let account = operator.wallets[0].public_key();

        // The chain records custody the operator never credited, and the carried
        // withdrawal exactly offsets the unseen aggregate: both derived boundaries
        // exclude the account, so only the staged view can expose the divergence.
        let event = DepositEvent {
            id: Sha256::hash(&[b"hidden-divergence-deposit"]),
            account,
            amount: 7,
        };
        chain.deposit(event.clone()).await;
        operator.withdraw(0, amount(7)).unwrap();
        assert_eq!(
            operator.signed_registration().unwrap().deposits_root,
            DepositBatch::<Key>::empty().root::<Sha256>().unwrap()
        );
        assert_eq!(chain.try_register(&mut operator).await, None);

        // The wallet's credit retry heals the view and registration proceeds with the
        // aggregate deferred on both sides.
        operator.observe(&[event]).unwrap();
        chain.register(&mut operator).await;
    });
}

#[test]
fn divergent_deposit_boundary_is_rejected_without_consuming_the_slot() {
    deterministic::Runner::default().start(|context| async move {
        let chain = Chain::new(&context).await;
        let mut operator = operator();

        // A signer that agrees on the staged view but commits a boundary the
        // chain cannot derive is rejected on the boundary check alone.
        let mut register = operator.signed_registration().unwrap();
        let record = DepositRecord::new(operator.wallets[0].public_key(), 7).unwrap();
        let divergent = DepositBatch::new(vec![record])
            .unwrap()
            .root::<Sha256>()
            .unwrap();
        register.deposits_root = divergent;
        register.signature = operator.protocol.sign_chain_registration(
            register.epoch,
            register.predecessor_liability,
            &register.deposits_root,
            &register.staged_root,
            &register.withdrawals,
        );
        chain
            .control
            .submit(SettlementTx::RegisterEpoch(register))
            .await;
        assert_eq!(
            chain.control.record(registration_key(&deployment())).await,
            None
        );

        // The effect-free rejection leaves the epoch slot open: the honest
        // bytes register the same epoch.
        chain.register(&mut operator).await;
    });
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
    deterministic::Runner::default().start(|context| async move {
        let chain = Chain::new(&context).await;
        let mut operator = operator();
        chain.register(&mut operator).await;
        operator.pay(0, 1, 1).unwrap();
        let data = operator.store.load_current().unwrap();
        let prepared =
            prepare_epoch(&operator.protocol, data, operator.registration.clone()).unwrap();
        let result = operator
            .protocol
            .complete(prepared, &mut TestRng::new(25))
            .unwrap();
        let mut malformed = AdmitRequest::from(&result);
        malformed.roots.change.digest = Sha256::hash(&[b"malformed-change-root"]);
        let epoch = malformed.epoch;

        // A rejected admission is effect-free and must not consume or fence
        // the registration slot.
        chain.control.submit(SettlementTx::Admit(malformed)).await;
        assert_eq!(
            chain
                .control
                .record(admitted_key(&deployment(), epoch))
                .await,
            None
        );
        chain.admit(&result).await;
    });
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
