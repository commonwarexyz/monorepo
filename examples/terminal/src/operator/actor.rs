//! Application orchestration across wallets, SQLite, and the clearing protocol.

use super::store::{
    AcceptedBatch, CloseRejected, EpochData, ExternalPayoutEvidence, IncomingPayment,
    MutationFailed, StagedDeposit, StagedWithdrawal, Store, StoreStatus, StoredCloseOutcome,
    WithdrawalEvidence,
};
#[cfg(test)]
use super::store::{AccountView, StoreSnapshot};
#[cfg(test)]
use crate::protocol::{MAX_DESTINATION_BYTES, Wallet, wallets};
use crate::{
    protocol::{
        AccountCache, AccountIdentity, DepositEvent, EpochRegistration, INITIAL_BALANCE, Key,
        Payment, PreparedEpoch, Protocol, SettlementResult, ensure_amount_withdrawal_horizon,
        ensure_balance_intake_horizon, ensure_close_horizon, external_identity, identities,
        openable_epoch_after, short_digest,
    },
    settlement::{SettlementSubmission, rpc as settlement_rpc},
    store::CommitUnknown,
};
use anyhow::{Context, Result, ensure};
#[cfg(test)]
use bytes::Bytes;
use commonware_clearing::bajillion::{
    boundary::{DepositBatch, DepositRecord, SignedWithdrawal, WithdrawalAction, WithdrawalBatch},
    challenge::{HigherShardTipLookup, StateOpening},
    commitment::VectorRoot,
    credit::{ShardHead, ShardSet},
    payment::{PaymentContext, SignedSend, TxId, verify_receipt_step},
    state::{AccountRow, AccountState, Prefix, SettlementOutput, StateLeaf},
    transition::{BatchId, ChallengeIndex, ExternalPayoutClaim, WithdrawalClaim},
};
#[cfg(test)]
use commonware_codec::EncodeSize as _;
#[cfg(test)]
use commonware_cryptography::Hasher;
use commonware_cryptography::{Sha256, sha256::Digest};
#[cfg(test)]
use std::num::NonZeroU64;
#[cfg(test)]
use std::sync::mpsc::SyncSender;
use std::{
    collections::{BTreeMap, BTreeSet},
    net::SocketAddr,
    num::NonZeroUsize,
    path::Path,
    sync::{
        Arc,
        mpsc::{self, Receiver, TryRecvError},
    },
    thread::{self, JoinHandle},
    time::Duration,
};

pub(crate) const DEFAULT_AMOUNT: u64 = 5;
const MAX_PENDING_CLOSES: usize = 4;
#[cfg(test)]
const DEPOSIT_ID_NAMESPACE: &[u8] = b"_COMMONWARE_EXAMPLES_TERMINAL_DEPOSIT";

pub(crate) struct CloseStarted {
    pub(crate) epoch: u64,
    pub(crate) queued: bool,
}

pub(crate) struct PaymentQuote {
    pub(crate) context: PaymentContext<Key, Digest>,
    pub(crate) state: AccountState,
    pub(crate) root: VectorRoot<Digest>,
    pub(crate) opening: StateOpening<Key, Digest>,
}

pub(crate) struct WithdrawalOpening {
    pub(crate) root: VectorRoot<Digest>,
    pub(crate) opening: StateOpening<Key, Digest>,
}

/// Committed-side receive-shard evidence for one recipient, reconstructed from retained
/// epoch data. A recipient resolves the lookup against `change_root` to read the close's
/// public credit tip for its shard, then challenges when a held receipt exceeds it.
pub(crate) struct CommittedShardTip {
    pub(crate) batch_id: BatchId<Digest>,
    pub(crate) change_root: VectorRoot<Digest>,
    pub(crate) lookup: HigherShardTipLookup<Key, Digest>,
}

#[derive(Clone)]
pub(crate) struct SettlementRegistration {
    pub(crate) epoch: u64,
    pub(crate) predecessor_liability: u64,
    pub(crate) deposits_root: VectorRoot<Digest>,
    /// Root of the full staged deposit set, deferred aggregates included. Settlement
    /// checks it against its own custody record, because a deferral hides its account
    /// from both derived boundaries and the boundary roots alone cannot see a deposit the
    /// operator never credited.
    pub(crate) staged_root: VectorRoot<Digest>,
    pub(crate) withdrawals: WithdrawalBatch<Key, Digest>,
    /// One predecessor-root opening per withdrawal in batch order. Settlement uses them to
    /// prove each operator-carried request certifiable before it registers the close.
    pub(crate) openings: Vec<StateOpening<Key, Digest>>,
    pub(crate) signature: commonware_cryptography_curve25519::signing::Signature,
}

pub(crate) struct CloseFinished {
    pub(crate) epoch: u64,
    pub(crate) header_digest: String,
    pub(crate) rows: usize,
    pub(crate) slices: usize,
    pub(crate) payout_total: u64,
    pub(crate) header_bytes: usize,
    pub(crate) certificate_bytes: usize,
    pub(crate) prepare_micros: u128,
    pub(crate) deal_micros: u128,
    pub(crate) seal_micros: u128,
}

pub(crate) enum CloseEvent {
    Finished(CloseFinished),
    Failed { epoch: u64, error: String },
}

struct ActiveClose {
    epoch: u64,
    receiver: Receiver<Result<SettlementResult>>,
    thread: JoinHandle<()>,
}

#[cfg(test)]
struct CloseGate {
    started: SyncSender<()>,
    release: Receiver<()>,
}

/// Complete local operator. Only public state and signed artifacts enter SQLite.
pub(crate) struct Operator {
    store: Store,
    protocol: Arc<Protocol>,
    identities: Vec<AccountIdentity>,
    #[cfg(test)]
    wallets: Vec<Wallet>,
    external: AccountIdentity,
    settlement_address: Option<SocketAddr>,
    genesis_root: VectorRoot<Digest>,
    registration: EpochRegistration,
    /// Predecessor state commitment retained for the current epoch.
    ///
    /// Payments, deposits, and withdrawals mutate only `current_*` account state, so the
    /// predecessor set is immutable between rotations. Quotes, openings, and registration
    /// openings serve this cache instead of replaying the epoch from SQLite.
    predecessor: AccountCache,
    active_close: Option<ActiveClose>,
    recovery_predecessor_root: Option<VectorRoot<Digest>>,
    store_fault: Option<String>,
    close_fault: Option<String>,
    #[cfg(test)]
    close_gate: Option<CloseGate>,
    #[cfg(test)]
    fail_close_spawn: bool,
    #[cfg(test)]
    panic_close_worker: bool,
}

impl Operator {
    #[cfg(test)]
    pub(crate) fn open(path: &Path, workers: NonZeroUsize) -> Result<Self> {
        let identities = identities();
        let store = Store::open(path, &identities)?;
        Self::from_store(store, identities, workers, None)
    }

    pub(crate) fn open_remote(
        path: &Path,
        workers: NonZeroUsize,
        settlement_address: SocketAddr,
    ) -> Result<Self> {
        let identities = identities();
        let store = Store::open(path, &identities)?;
        Self::from_store(store, identities, workers, Some(settlement_address))
    }

    #[cfg(test)]
    fn in_memory(workers: NonZeroUsize) -> Result<Self> {
        let identities = identities();
        let store = Store::in_memory(&identities)?;
        Self::from_store(store, identities, workers, None)
    }

    fn from_store(
        mut store: Store,
        identities: Vec<AccountIdentity>,
        workers: NonZeroUsize,
        settlement_address: Option<SocketAddr>,
    ) -> Result<Self> {
        let protocol = Arc::new(Protocol::new(workers)?);
        let configured_genesis_root = genesis_root(&protocol, &identities)?;
        let current = store.load_current()?;
        let registration = registration_for(&protocol, &current)?;
        store.ensure_current_context(registration.context.payment())?;
        let predecessor = validate_epoch_data(&protocol, &current, &registration)
            .context("validate current SQLite epoch")?;
        let current_predecessor_root = predecessor.root();
        ensure!(
            projected_liability(&current)? == store.current_liability()?,
            "stored live liability differs from the projected account state"
        );
        ensure!(
            current.deposits.len() == store.current_deposit_events()?,
            "stored deposit event count differs from the current epoch log"
        );
        let close_fault = store.failed_close()?;
        let pending_close_count = store.pending_close_count()?;
        ensure!(
            pending_close_count <= MAX_PENDING_CLOSES,
            "stored close backlog exceeds its {MAX_PENDING_CLOSES}-epoch bound"
        );
        let pending_close = pending_close_count != 0;
        let recovery_predecessor_root = if close_fault.is_none() && pending_close {
            Some(current_predecessor_root)
        } else {
            None
        };
        if close_fault.is_none() && !pending_close {
            let (expected_epoch, expected_root) = match store.latest_finalized_root()? {
                Some((epoch, root)) => (
                    epoch.checked_add(1).context("settlement epoch overflow")?,
                    root,
                ),
                None => (0, configured_genesis_root),
            };
            ensure!(
                current.epoch == expected_epoch,
                "current epoch does not extend the finalized settlement tip"
            );
            ensure!(
                current_predecessor_root == expected_root,
                "current predecessor root does not extend the finalized settlement tip"
            );
        }
        let mut operator = Self {
            store,
            protocol,
            identities,
            #[cfg(test)]
            wallets: wallets(),
            external: external_identity(),
            settlement_address,
            genesis_root: configured_genesis_root,
            registration,
            predecessor,
            active_close: None,
            recovery_predecessor_root,
            store_fault: None,
            close_fault,
            #[cfg(test)]
            close_gate: None,
            #[cfg(test)]
            fail_close_spawn: false,
            #[cfg(test)]
            panic_close_worker: false,
        };
        operator.start_next_persisted_close()?;
        Ok(operator)
    }

    #[cfg(test)]
    pub(crate) const fn wallet_count(&self) -> usize {
        self.wallets.len()
    }

    #[cfg(test)]
    pub(crate) const fn recipient_count(&self) -> usize {
        self.wallets.len() + 1
    }

    #[cfg(test)]
    pub(crate) fn pay(
        &mut self,
        payer: usize,
        recipient: usize,
        amount: u64,
    ) -> Result<AcceptedBatch> {
        self.ensure_operating()?;
        ensure!(amount > 0, "payment amount must be positive");
        let payer = &self.wallets[payer % self.wallets.len()];
        let recipient_index = recipient % self.recipient_count();
        let recipient = if recipient_index == self.wallets.len() {
            self.external.key.clone()
        } else {
            self.wallets[recipient_index].public_key()
        };
        let quote = self.payment_quote(&payer.public_key())?;
        ensure!(quote.state.balance > 0, "selected payer has no balance");
        let send = SignedSend::sign_next(
            &quote.context,
            payer.signer(),
            recipient,
            amount,
            quote.state.cumulative_debit,
        )
        .context("sign payment request")?;
        self.accept_send(send)
    }

    pub(crate) fn payment_quote(&self, account: &Key) -> Result<PaymentQuote> {
        self.ensure_operating()?;
        self.ensure_balance_intake_horizon()?;
        let state = self
            .store
            .current_account(account)?
            .context("payer is not in the current live state")?;
        ensure!(
            state.current.active,
            "payer is not in the current live state"
        );
        let payer_opening = self
            .predecessor
            .opening(account)
            .context("open payer recovery state")?;
        Ok(PaymentQuote {
            context: self.registration.context.payment().clone(),
            state: state.current,
            root: self.predecessor.root(),
            opening: payer_opening,
        })
    }

    /// Reads the committed batch for one send, a plain durable lookup by transaction id.
    ///
    /// This is an optional receipts fetch for a wallet that already decided commitment from
    /// a finalized settlement root. It carries no verdict, so it stays readable across the
    /// operating fence (a failed predecessor close leaves committed rows intact) but still
    /// refuses to read past a storage fault, which is fatal until the operator restarts.
    pub(crate) fn accepted_batch(
        &self,
        send: &SignedSend<Key, Digest>,
    ) -> Result<Option<AcceptedBatch>> {
        ensure!(
            self.store_fault.is_none(),
            "a storage fault blocks committed-batch reads until the operator restarts"
        );
        self.store.accepted_batch(send)
    }

    /// Serves accepted linked pairs crediting `recipient` after the caller's durable cursor.
    ///
    /// This is a plain durable read of committed payment rows, so it stays readable across the
    /// operating fence and refuses only past a storage fault.
    pub(crate) fn incoming_payments(
        &self,
        recipient: &Key,
        after: u64,
        limit: usize,
    ) -> Result<Vec<IncomingPayment>> {
        self.ensure_store_usable()?;
        self.store.incoming_payments(recipient, after, limit)
    }

    /// Reconstructs one recipient's committed receive-shard evidence for a retained epoch.
    ///
    /// The close is rebuilt from the retained payment log with the same lookup constructor the
    /// operator uses for withdrawal openings, so the served [`HigherShardTipLookup`] opens
    /// against the reconstructed close's own change root. Retention is honest: once a finalized
    /// epoch's account-state versions are pruned it may no longer reconstruct, which a recipient
    /// treats as an availability signal and retries.
    pub(crate) fn committed_shard_tip(
        &self,
        recipient: &Key,
        shard: u64,
        epoch: u64,
    ) -> Result<CommittedShardTip> {
        self.ensure_store_usable()?;
        let data = self.store.load_at(epoch)?;
        let registration = registration_for(&self.protocol, &data)?;
        let prepared = prepare_epoch(&self.protocol, data, registration)
            .context("reconstruct committed close for shard-tip evidence")?;
        let close = prepared.close();
        let index = ChallengeIndex::new::<Sha256>(prepared.close_context(), close)
            .context("index committed close for shard-tip evidence")?;

        // A recipient that received credit has a changed row and terminal shard set. An absent
        // recipient has neither, and the lookup constructor requires the matching pairing.
        let shards = close
            .rows
            .iter()
            .position(|row| &row.account == recipient)
            .map(|position| &close.shard_sets[position]);
        let lookup = index
            .higher_shard_tip_lookup::<Sha256>(recipient, shards, shard)
            .context("compose committed shard-tip lookup")?;
        Ok(CommittedShardTip {
            batch_id: close.header.batch_id::<Sha256>(),
            change_root: close.roots.change,
            lookup,
        })
    }

    pub(crate) fn accept_send(&mut self, send: SignedSend<Key, Digest>) -> Result<AcceptedBatch> {
        self.ensure_operating()?;
        self.validate_recipients(&send)?;

        // A replay lookup is the only pre-mutation probe: the store transaction fully
        // validates a new send before any mutation, so validating here too would repeat
        // the same signature checks on every accepted payment.
        if let Some(accepted) = self.store.accepted_batch(&send)? {
            return Ok(accepted);
        }
        self.ensure_balance_intake_horizon()?;
        let result = self.store.accept_send(
            self.registration.context.payment(),
            self.protocol.operator(),
            send,
            0,
        );
        self.guard_store(result)
    }

    /// Reports whether accepting this send must first register the epoch with settlement.
    ///
    /// This probe keeps the full validation of a new send: registering an epoch starts
    /// settlement's liveness clock, so only a payer-authorized send may trigger it.
    pub(crate) fn send_requires_epoch_registration(
        &self,
        send: &SignedSend<Key, Digest>,
    ) -> Result<bool> {
        self.ensure_operating()?;
        self.validate_recipients(send)?;
        let required = self.store.payment_requires_epoch_registration(
            self.registration.context.payment(),
            send,
            0,
        )?;
        if required {
            self.ensure_balance_intake_horizon()?;
        }
        Ok(required)
    }

    #[cfg(test)]
    pub(crate) fn deposit(&mut self, wallet: usize, amount: u64) -> Result<StagedDeposit> {
        self.ensure_operating()?;
        let wallet = &self.wallets[wallet % self.wallets.len()];
        let identity = AccountIdentity {
            name: wallet.name,
            key: wallet.public_key(),
        };

        let sequence = self
            .store
            .current_deposit_events()?
            .checked_add(1)
            .context("deposit sequence overflow")?;
        let event = DepositEvent {
            id: Sha256::hash(&[
                DEPOSIT_ID_NAMESPACE,
                &self.registration.context.payment().epoch().to_be_bytes(),
                &sequence.to_be_bytes(),
                identity.key.as_ref(),
                &amount.to_be_bytes(),
            ]),
            account: identity.key.clone(),
            amount,
        };
        self.apply_deposit(event)
    }

    pub(crate) fn apply_deposit(&mut self, event: DepositEvent) -> Result<StagedDeposit> {
        self.ensure_operating()?;
        if let Some(staged) = self.store.staged_deposit(&event.id)? {
            ensure!(
                staged.account == event.account && staged.amount == event.amount,
                "deposit id is bound to another event"
            );
            return Ok(staged);
        }
        self.ensure_balance_intake_horizon()?;
        let identity = self
            .identities
            .iter()
            .find(|identity| identity.key == event.account)
            .context("deposit account is not a configured operator identity")?;

        // Settlement already holds custody for this event, so no shape may be refused
        // here: an aggregate exactly offsetting the carried withdrawal defers to the
        // successor epoch instead, mirroring the chain's boundary rule.
        let replacement = registration_with_deposit(
            &self.protocol,
            &self.registration,
            identity.key.clone(),
            event.amount,
        )
        .context("prospective deposit does not fit the epoch anchor")?;
        let result = self.store.stage_deposit(
            identity,
            &event,
            self.registration.context.payment(),
            replacement.context.payment(),
        );
        let staged = self.guard_store(result)?;
        self.registration = replacement;
        Ok(staged)
    }

    #[cfg(test)]
    pub(crate) fn withdraw(
        &mut self,
        wallet: usize,
        action: WithdrawalAction,
    ) -> Result<StagedWithdrawal> {
        self.ensure_operating()?;
        let wallet = &self.wallets[wallet % self.wallets.len()];
        let deadline = crate::protocol::epoch_start(self.registration.context.payment().epoch())?
            .checked_add(50)
            .context("withdrawal deadline overflow")?;
        let destination = Bytes::copy_from_slice(wallet.name.as_bytes());
        ensure!(
            destination.len() <= MAX_DESTINATION_BYTES,
            "operator destination exceeds its bound"
        );
        let request = SignedWithdrawal::sign(
            self.protocol.deployment(),
            self.predecessor.root().digest,
            destination,
            action,
            deadline,
            wallet.signer(),
        );
        self.apply_withdrawal(request)
    }

    pub(crate) fn withdrawal_opening(&self, account: &Key) -> Result<WithdrawalOpening> {
        self.ensure_operating()?;
        self.ensure_close_horizon()?;
        Ok(WithdrawalOpening {
            root: self.predecessor.root(),
            opening: self
                .predecessor
                .opening(account)
                .context("open withdrawing account")?,
        })
    }

    pub(crate) fn apply_withdrawal(
        &mut self,
        request: SignedWithdrawal<Key, Digest>,
    ) -> Result<StagedWithdrawal> {
        self.ensure_operating()?;
        if let Some(staged) = self.staged_withdrawal(&request)? {
            return Ok(staged);
        }
        self.ensure_withdrawal_intake_horizon(request.body().action())?;
        let quote = self.withdrawal_opening(request.account())?;
        request
            .verify_context(&self.protocol.deployment(), &quote.root.digest)
            .context("verify withdrawal context")?;

        // An amount exactly offsetting the staged aggregate defers it to the successor
        // epoch inside the store, which also gates certifiability: the amount must stay
        // coverable without any aggregate a later deposit could turn into an exact offset.
        let replacement =
            registration_with_withdrawal(&self.protocol, &self.registration, request.clone())
                .context("prospective withdrawal does not fit the epoch anchor")?;
        let result = self.store.stage_withdrawal(
            &request,
            self.registration.context.payment(),
            replacement.context.payment(),
        );
        let staged = self.guard_store(result)?;
        self.registration = replacement;
        Ok(staged)
    }

    pub(crate) fn staged_withdrawal(
        &self,
        request: &SignedWithdrawal<Key, Digest>,
    ) -> Result<Option<StagedWithdrawal>> {
        self.ensure_store_usable()?;
        if let Some(staged) = self.store.staged_withdrawal_request(request)? {
            return Ok(Some(staged));
        }
        let Some((stored, staged)) = self.store.staged_withdrawal(request.account())? else {
            return Ok(None);
        };
        ensure!(
            stored == *request,
            "account already staged another withdrawal"
        );
        Ok(Some(staged))
    }

    pub(crate) fn external_payout_evidence(
        &self,
        recipient: &Key,
    ) -> Result<ExternalPayoutEvidence> {
        self.ensure_store_usable()?;
        self.store.external_payout_evidence(recipient)
    }

    pub(crate) fn acknowledge_external_payout_claim(
        &mut self,
        batch_id: BatchId<Digest>,
        claim: &ExternalPayoutClaim<Key, Digest>,
    ) -> Result<()> {
        self.ensure_store_usable()?;
        let result = self
            .store
            .acknowledge_external_payout_claim(batch_id, claim);
        self.guard_store(result)
    }

    /// Cuts the registered epoch, opens its successor, and schedules close construction.
    pub(crate) fn start_close(&mut self, expected_epoch: u64) -> Result<CloseStarted> {
        if self.close_already_started(expected_epoch)? {
            return Ok(CloseStarted {
                epoch: expected_epoch,
                queued: true,
            });
        }
        self.validate_close_start(expected_epoch)?;
        let epoch = expected_epoch;
        let payment_context = self.registration.context.payment().clone();
        let next_epoch = self.next_openable_epoch()?;

        // Deferred aggregates already live as the successor's parked rows, so the
        // successor context opens with them staged.
        let successor = self.protocol.registration(
            next_epoch,
            self.registration.deferred.clone(),
            WithdrawalBatch::empty(),
            self.store.successor_liability()?,
        )?;
        let cutover = self.store.rotate_epoch(
            epoch,
            self.registration.context.payment(),
            &successor.context,
        );
        if let Err(error) = self.guard_store(cutover) {
            if self.store_fault.is_some() {
                return Err(error);
            }
            let message = format!("epoch {epoch} cutover failed: {error:#}");
            self.close_fault = Some(message.clone());
            return Err(error.context(format!("operator fenced: {message}")));
        }

        // SQLite owns the cut and the root-independent successor context. The RPC service registers
        // that exact context with settlement before it releases the successor's first receipt.
        let scheduling: Result<bool> = (|| {
            self.registration = successor;
            self.reload_predecessor()?;
            let queued = self.active_close.is_some();
            if !queued {
                self.spawn_close(payment_context)?;
            }
            Ok(queued)
        })();
        let queued = match scheduling {
            Ok(queued) => queued,
            Err(error) => {
                let message = format!("epoch {epoch} could not be scheduled: {error:#}");
                self.close_fault = Some(message.clone());
                let persisted = self.store.fail_close(epoch, &message);
                if let Err(persist_error) = self.guard_store(persisted) {
                    return Err(anyhow::anyhow!(
                        "operator fenced after {message}; persisting the fence also failed: {persist_error:#}"
                    ));
                }
                return Err(error.context(format!("operator fenced: {message}")));
            }
        };
        Ok(CloseStarted { epoch, queued })
    }

    pub(crate) fn close_already_started(&self, epoch: u64) -> Result<bool> {
        self.ensure_store_usable()?;
        self.store.has_close_job(epoch)
    }

    pub(crate) fn validate_close_start(&self, expected_epoch: u64) -> Result<()> {
        self.ensure_operating()?;
        ensure!(
            self.registration.context.payment().epoch() == expected_epoch,
            "close request does not match the active epoch"
        );
        self.next_openable_epoch()?;
        ensure!(self.store.has_current_work()?, "there is nothing to close");
        ensure!(
            self.store.pending_close_count()? < MAX_PENDING_CLOSES,
            "close backlog reached its {MAX_PENDING_CLOSES}-epoch bound"
        );
        Ok(())
    }

    pub(crate) fn poll_close(&mut self, epoch: u64) -> Result<Option<CloseEvent>> {
        self.ensure_store_usable()?;
        self.advance_close()?;
        match self.store.close_outcome(epoch)? {
            StoredCloseOutcome::Pending => Ok(None),
            StoredCloseOutcome::Finished(close) => Ok(Some(CloseEvent::Finished(CloseFinished {
                epoch,
                header_digest: short_digest(close.header.digest()),
                rows: close.rows,
                slices: close.slices,
                payout_total: close.payout_total,
                header_bytes: close.header_bytes,
                certificate_bytes: close.certificate_bytes,
                prepare_micros: close.prepare_micros,
                deal_micros: close.deal_micros,
                seal_micros: close.seal_micros,
            }))),
            StoredCloseOutcome::Failed(error) => Ok(Some(CloseEvent::Failed { epoch, error })),
        }
    }

    fn advance_close(&mut self) -> Result<()> {
        let Some(active) = self.active_close.as_ref() else {
            return Ok(());
        };
        let result = match active.receiver.try_recv() {
            Ok(result) => result,
            Err(TryRecvError::Empty) => return Ok(()),
            Err(TryRecvError::Disconnected) => Err(anyhow::anyhow!(
                "close worker disconnected without a result"
            )),
        };
        let active = self
            .active_close
            .take()
            .expect("active close was checked above");
        let epoch = active.epoch;
        if active.thread.join().is_err() {
            self.record_failed_close(epoch, "close worker panicked".to_string())?;
            return Ok(());
        }

        match result {
            Ok(result) => {
                if let Err(error) = self.store.finish_close(&result, self.genesis_root) {
                    let message = format!("epoch {epoch} finalization was not durable: {error:#}");
                    if error.downcast_ref::<CloseRejected>().is_some() {
                        self.record_failed_close(epoch, message.clone())?;
                    } else {
                        self.store_fault =
                            Some(format!("{message}; restart the operator before continuing"));
                    }
                    return Err(error.context(format!("operator fenced: {message}")));
                }
                if let Err(error) = self.start_next_persisted_close() {
                    let message = format!("next close could not be scheduled: {error:#}");
                    self.close_fault = Some(message.clone());
                    if let Ok(Some(pending_epoch)) = self.store.next_closing_epoch() {
                        let persisted = self.store.fail_close(pending_epoch, &message);
                        if let Err(persist_error) = self.guard_store(persisted) {
                            return Err(anyhow::anyhow!(
                                "operator fenced after {message}; persisting the fence also failed: {persist_error:#}"
                            ));
                        }
                    }
                    return Err(error.context(format!("operator fenced: {message}")));
                }
                self.verify_recovered_predecessor()?;
            }
            Err(error) => {
                self.record_failed_close(epoch, format!("{error:#}"))?;
            }
        }
        Ok(())
    }

    pub(crate) const fn close_in_progress(&self) -> bool {
        self.active_close.is_some()
    }

    pub(crate) fn fault(&self) -> Option<&str> {
        self.store_fault
            .as_deref()
            .or(self.close_fault.as_deref())
            .or(self
                .recovery_predecessor_root
                .is_some()
                .then_some("authenticating recovered settlement ancestry"))
    }

    pub(crate) fn status(&self) -> Result<StoreStatus> {
        self.ensure_store_usable()?;
        self.store.status()
    }

    #[cfg(test)]
    pub(crate) fn settlement_roots(
        &self,
        epoch: u64,
    ) -> Result<commonware_clearing::bajillion::transition::RootBundle<Digest>> {
        self.ensure_store_usable()?;
        self.store.settlement_roots(epoch)
    }

    #[cfg(test)]
    pub(crate) fn snapshot(&self) -> Result<StoreSnapshot> {
        self.ensure_store_usable()?;
        let mut snapshot = self.store.snapshot()?;
        for identity in &self.identities {
            if !snapshot
                .accounts
                .iter()
                .any(|account| account.name == identity.name)
            {
                snapshot.accounts.push(AccountView {
                    name: identity.name.to_string(),
                    balance: 0,
                    present: false,
                });
            }
        }
        snapshot
            .accounts
            .sort_unstable_by(|left, right| left.name.cmp(&right.name));
        Ok(snapshot)
    }

    pub(crate) fn settlement_registration(&self) -> Result<SettlementRegistration> {
        self.ensure_operating()?;
        self.next_openable_epoch()?;
        let epoch = self.registration.context.payment().epoch();
        let predecessor_liability = self.registration.context.predecessor_liability();
        let withdrawals = self.registration.withdrawals.clone();
        let openings = withdrawals
            .requests()
            .iter()
            .map(|request| {
                self.predecessor
                    .opening(request.account())
                    .context("open carried withdrawal account")
            })
            .collect::<Result<Vec<_>>>()?;

        // The committed boundary is derived through the chain's own deferral rule, so the
        // roots agree by construction whenever the deposit sets agree. The staged root
        // carries the full set alongside so settlement can also see set divergence a
        // deferral would hide from both boundaries.
        let deposits_root = self
            .registration
            .deposits
            .root::<Sha256>()
            .context("commit registration deposit boundary")?;
        let staged_root = staged_deposits(&self.registration)?
            .root::<Sha256>()
            .context("commit registration staged deposits")?;
        let signature = self.protocol.sign_registration(
            epoch,
            predecessor_liability,
            &deposits_root,
            &staged_root,
            &withdrawals,
        );
        Ok(SettlementRegistration {
            epoch,
            predecessor_liability,
            deposits_root,
            staged_root,
            withdrawals,
            openings,
            signature,
        })
    }

    /// Rebuilds the retained predecessor commitment after the durable epoch advanced.
    fn reload_predecessor(&mut self) -> Result<()> {
        let current = self.store.load_current()?;
        self.predecessor = validate_epoch_data(&self.protocol, &current, &self.registration)
            .context("validate rotated SQLite epoch")?;
        Ok(())
    }

    fn next_openable_epoch(&self) -> Result<u64> {
        openable_epoch_after(self.registration.context.payment().epoch())
    }

    fn ensure_balance_intake_horizon(&self) -> Result<()> {
        ensure_balance_intake_horizon(self.registration.context.payment().epoch())
    }

    fn ensure_withdrawal_intake_horizon(&self, action: &WithdrawalAction) -> Result<()> {
        match action {
            WithdrawalAction::Amount(_) => {
                ensure_amount_withdrawal_horizon(self.registration.context.payment().epoch())
            }
            WithdrawalAction::Close => {
                ensure_close_horizon(self.registration.context.payment().epoch())
            }
        }
    }

    fn ensure_close_horizon(&self) -> Result<()> {
        ensure_close_horizon(self.registration.context.payment().epoch())
    }

    fn validate_recipients(&self, send: &SignedSend<Key, Digest>) -> Result<()> {
        for entry in send.body().entries() {
            let recipient = entry.recipient();
            ensure!(
                recipient == &self.external.key
                    || self
                        .identities
                        .iter()
                        .any(|identity| &identity.key == recipient),
                "payment recipient is neither a registered account nor the configured external recipient"
            );
        }
        Ok(())
    }

    pub(crate) fn withdrawal_evidence(&self, account: &Key) -> Result<WithdrawalEvidence> {
        self.ensure_store_usable()?;
        self.store.withdrawal_evidence(account)
    }

    pub(crate) fn acknowledge_withdrawal_claim(
        &mut self,
        batch_id: BatchId<Digest>,
        account: &Key,
        claim: &WithdrawalClaim<Digest>,
    ) -> Result<()> {
        self.ensure_store_usable()?;
        let result = self
            .store
            .acknowledge_withdrawal_claim(batch_id, account, claim);
        self.guard_store(result)
    }

    #[cfg(test)]
    pub(crate) fn wait_for_closes(&mut self) -> Result<Vec<CloseEvent>> {
        let mut events = Vec::new();
        loop {
            let epoch = self
                .active_close
                .as_ref()
                .map(|active| active.epoch)
                .or(self.store.next_closing_epoch()?);
            let Some(epoch) = epoch else {
                break;
            };
            if let Some(event) = self.poll_close(epoch)? {
                events.push(event);
                continue;
            }
            if self.active_close.is_none() {
                break;
            }
            thread::sleep(Duration::from_millis(5));
        }
        Ok(events)
    }

    fn spawn_close(&mut self, payment_context: PaymentContext<Key, Digest>) -> Result<()> {
        #[cfg(test)]
        if std::mem::take(&mut self.fail_close_spawn) {
            anyhow::bail!("injected close worker start failure");
        }

        let epoch = payment_context.epoch();
        let protocol = Arc::clone(&self.protocol);
        let reader = self.store.epoch_reader();
        let settlement_address = self.settlement_address;
        #[cfg(test)]
        let close_gate = self.close_gate.take();
        #[cfg(test)]
        let panic_close_worker = std::mem::take(&mut self.panic_close_worker);
        let (sender, receiver) = mpsc::sync_channel(1);
        let thread = thread::Builder::new()
            .name(format!("terminal-close-{epoch}"))
            .spawn(move || {
                #[cfg(test)]
                if let Some(gate) = close_gate {
                    let _ = gate.started.send(());
                    if gate.release.recv().is_err() {
                        return;
                    }
                }

                #[cfg(test)]
                assert!(!panic_close_worker, "injected close worker panic");

                let prepared = reader.load(epoch).and_then(|data| {
                    let registration = registration_for(&protocol, &data)?;
                    ensure!(
                        payment_context == *registration.context.payment(),
                        "frozen epoch context differs from its durable close job"
                    );
                    prepare_epoch(&protocol, data, registration)
                });
                #[cfg(test)]
                let mut rng = commonware_utils::TestRng::new(epoch);
                #[cfg(not(test))]
                let mut rng = rand::rng();
                let result = prepared
                    .and_then(|prepared| protocol.complete(prepared, &mut rng))
                    .and_then(|result| {
                        let Some(address) = settlement_address else {
                            return Ok(result);
                        };
                        let submission = SettlementSubmission::from(&result);
                        let finalized = admit_until_known(
                            || settlement_rpc::admit_blocking(address, &submission),
                            Duration::from_millis(100),
                        )?;
                        ensure!(
                            finalized.batch_id == result.finalized.batch_id
                                && finalized.epoch == result.finalized.epoch
                                && finalized.successor_root == result.finalized.successor_root
                                && finalized.withdrawal_total == result.finalized.withdrawal_total
                                && finalized.payout_total == result.finalized.payout_total
                                && finalized.custody_balance == result.finalized.custody_balance,
                            "settlement finalized a different close"
                        );
                        Ok(result)
                    })
                    .map(|mut result| {
                        result.release_dealings();
                        result
                    });
                let _ = sender.send(result);
            })
            .context("spawn asynchronous close worker")?;
        self.active_close = Some(ActiveClose {
            epoch,
            receiver,
            thread,
        });
        Ok(())
    }

    #[cfg(test)]
    fn pause_next_close(&mut self) -> (Receiver<()>, SyncSender<()>) {
        let (started_sender, started_receiver) = mpsc::sync_channel(1);
        let (release_sender, release_receiver) = mpsc::sync_channel(1);
        self.close_gate = Some(CloseGate {
            started: started_sender,
            release: release_receiver,
        });
        (started_receiver, release_sender)
    }

    #[cfg(test)]
    const fn fail_next_close_spawn(&mut self) {
        self.fail_close_spawn = true;
    }

    #[cfg(test)]
    const fn panic_next_close_worker(&mut self) {
        self.panic_close_worker = true;
    }

    fn start_next_persisted_close(&mut self) -> Result<()> {
        if self.active_close.is_some() {
            return Ok(());
        }

        // A failed close invalidates its suffix but must not strand older custody-bearing closes.
        let failed_epoch = self.store.first_failed_epoch()?;
        let payment_context = if let Some(epoch) = self.store.next_closing_epoch()? {
            if failed_epoch.is_some_and(|failed| epoch >= failed) {
                return Ok(());
            }
            Some(self.store.closing_context(epoch)?)
        } else {
            None
        };
        if let Some(payment_context) = payment_context {
            self.spawn_close(payment_context)?;
        }
        Ok(())
    }

    fn ensure_operating(&self) -> Result<()> {
        self.ensure_store_usable()?;
        ensure!(
            self.close_fault.is_none(),
            "the operator is fenced after a failed predecessor close"
        );
        ensure!(
            self.recovery_predecessor_root.is_none(),
            "the operator is authenticating recovered settlement ancestry"
        );
        Ok(())
    }

    fn ensure_store_usable(&self) -> Result<()> {
        if let Some(fault) = &self.store_fault {
            anyhow::bail!("the SQLite connection is unusable: {fault}");
        }
        Ok(())
    }

    fn guard_store<T>(&mut self, result: Result<T>) -> Result<T> {
        match result {
            Err(error)
                if error.downcast_ref::<CommitUnknown>().is_some()
                    || error.downcast_ref::<MutationFailed>().is_some() =>
            {
                let message = format!("{error:#}; restart the operator before continuing");
                self.store_fault = Some(message.clone());
                Err(error.context(format!("operator fenced: {message}")))
            }
            result => result,
        }
    }

    fn record_failed_close(&mut self, epoch: u64, message: String) -> Result<()> {
        self.close_fault = Some(message.clone());
        if let Err(error) = self.store.fail_close(epoch, &message) {
            let fault = format!(
                "persisting the epoch {epoch} close fence failed: {error:#}; restart the operator"
            );
            self.store_fault = Some(fault.clone());
            return Err(error.context(fault));
        }
        Ok(())
    }

    fn verify_recovered_predecessor(&mut self) -> Result<()> {
        let Some(expected) = self.recovery_predecessor_root else {
            return Ok(());
        };
        if self.close_fault.is_some()
            || self.active_close.is_some()
            || self.store.next_closing_epoch()?.is_some()
        {
            return Ok(());
        }
        let (epoch, actual) = self
            .store
            .latest_finalized_root()?
            .context("recovered close chain has no finalized state root")?;
        let current_epoch = self.registration.context.payment().epoch();
        let expected_epoch = epoch.checked_add(1).context("settlement epoch overflow")?;
        if current_epoch != expected_epoch || actual != expected {
            let message =
                "recovered current predecessor root does not extend the finalized settlement tip";
            self.close_fault = Some(message.to_string());
            anyhow::bail!(message);
        }
        self.recovery_predecessor_root = None;
        Ok(())
    }

    #[cfg(test)]
    fn finish_prepared<R: rand_core::CryptoRng>(
        &mut self,
        prepared: PreparedEpoch,
        rng: &mut R,
    ) -> Result<CloseFinished> {
        let result = self.protocol.complete(prepared, rng)?;
        self.store.finish_close(&result, self.genesis_root)?;
        Ok(CloseFinished {
            epoch: result.epoch,
            header_digest: short_digest(result.header.digest()),
            rows: result.rows,
            slices: result.slices,
            payout_total: result.finalized.payout_total,
            header_bytes: result.header.encode_size(),
            certificate_bytes: result.certificate.encode_size(),
            prepare_micros: result.prepare_micros,
            deal_micros: result.deal_micros,
            seal_micros: result.seal_micros,
        })
    }
}

fn admit_until_known<T>(
    mut attempt: impl FnMut() -> std::result::Result<T, settlement_rpc::AdmitError>,
    retry_delay: Duration,
) -> Result<T> {
    loop {
        match attempt() {
            Ok(value) => return Ok(value),
            Err(settlement_rpc::AdmitError::Rejected(error)) => {
                anyhow::bail!("settlement rejected admission: {error}")
            }
            Err(settlement_rpc::AdmitError::Pending | settlement_rpc::AdmitError::Unknown(_)) => {
                thread::sleep(retry_delay)
            }
        }
    }
}

fn genesis_root(protocol: &Protocol, identities: &[AccountIdentity]) -> Result<VectorRoot<Digest>> {
    let mut leaves = identities
        .iter()
        .map(|identity| StateLeaf {
            account: identity.key.clone(),
            state: AccountState {
                balance: INITIAL_BALANCE,
                active: true,
                ..AccountState::default()
            },
        })
        .collect::<Vec<_>>();
    leaves.sort_unstable_by(|left, right| left.account.cmp(&right.account));
    Ok(
        AccountCache::new_with_strategy::<Sha256>(leaves, protocol.strategy())
            .context("commit configured genesis state")?
            .root(),
    )
}

/// Folds deposit events into their canonical per-account aggregate batch.
fn deposit_batch<'a>(
    events: impl IntoIterator<Item = &'a DepositEvent>,
) -> Result<DepositBatch<Key>> {
    let mut aggregates = BTreeMap::<Key, u64>::new();
    for event in events {
        let amount = aggregates.entry(event.account.clone()).or_default();
        *amount = amount
            .checked_add(event.amount)
            .context("deposit total overflow")?;
    }
    Ok(DepositBatch::new(
        aggregates
            .into_iter()
            .map(|(account, amount)| DepositRecord::new(account, amount))
            .collect::<Result<Vec<_>, _>>()?,
    )?)
}

/// Returns a registration's full staged aggregates, included and deferred together.
fn staged_deposits(registration: &EpochRegistration) -> Result<DepositBatch<Key>> {
    Ok(DepositBatch::new(
        registration
            .deposits
            .records()
            .iter()
            .chain(registration.deferred.records())
            .cloned()
            .collect(),
    )?)
}

fn registration_for(protocol: &Protocol, data: &EpochData) -> Result<EpochRegistration> {
    let included = deposit_batch(&data.deposits)?;
    let carried = deposit_batch(&data.carried)?;
    let staged = deposit_batch(data.deposits.iter().chain(&data.carried))?;
    let withdrawals = WithdrawalBatch::new(
        data.withdrawals
            .iter()
            .map(|stored| stored.request.clone())
            .collect(),
    )?;
    let registration = protocol.registration(
        data.epoch,
        staged,
        withdrawals,
        predecessor_liability(data)?,
    )?;

    // Storage keeps every epoch normalized: its rows and account state carry exactly its
    // boundary-included deposits, and deferred aggregates live as parked rows. The
    // derived split must reproduce that partition exactly.
    ensure!(
        registration.deposits == included && registration.deferred == carried,
        "stored deposit partition differs from the derived boundary"
    );
    Ok(registration)
}

fn registration_with_deposit(
    protocol: &Protocol,
    current: &EpochRegistration,
    account: Key,
    amount: u64,
) -> Result<EpochRegistration> {
    ensure!(amount > 0, "deposit amount must be positive");
    let mut aggregates = staged_deposits(current)?
        .records()
        .iter()
        .map(|record| (record.account().clone(), record.amount()))
        .collect::<BTreeMap<_, _>>();
    let total = aggregates.entry(account).or_default();
    *total = total
        .checked_add(amount)
        .context("deposit total overflow")?;
    let staged = DepositBatch::new(
        aggregates
            .into_iter()
            .map(|(account, amount)| DepositRecord::new(account, amount))
            .collect::<Result<Vec<_>, _>>()?,
    )?;
    protocol.registration(
        current.context.payment().epoch(),
        staged,
        current.withdrawals.clone(),
        current.context.predecessor_liability(),
    )
}

fn registration_with_withdrawal(
    protocol: &Protocol,
    current: &EpochRegistration,
    request: SignedWithdrawal<Key, Digest>,
) -> Result<EpochRegistration> {
    let mut requests = current.withdrawals.requests().to_vec();
    requests.push(request);
    let withdrawals = WithdrawalBatch::new(requests)?;
    protocol.registration(
        current.context.payment().epoch(),
        staged_deposits(current)?,
        withdrawals,
        current.context.predecessor_liability(),
    )
}

fn predecessor_liability(data: &EpochData) -> Result<u64> {
    data.accounts
        .iter()
        .filter(|account| account.predecessor.active)
        .try_fold(0_u64, |total, account| {
            total
                .checked_add(account.predecessor.balance)
                .context("predecessor liability overflow")
        })
}

fn projected_liability(data: &EpochData) -> Result<u64> {
    data.accounts.iter().try_fold(0_u64, |total, account| {
        total
            .checked_add(account.current.balance)
            .context("projected liability overflow")
    })
}

#[derive(Clone, Default)]
struct AccountActivity {
    debit: u64,
    credit: u64,
    receipts: u64,
}

struct EpochAssembly {
    predecessor: Vec<StateLeaf<Key>>,
    rows: Vec<AccountRow<Key, Digest>>,
    shard_sets: Vec<ShardSet<Key, Digest>>,
    successor: Vec<StateLeaf<Key>>,
}

fn close_tail(predecessor: u64, deposit: u64, credit: u64, debit: u64) -> Result<u64> {
    let available = u128::from(predecessor) + u128::from(deposit) + u128::from(credit);
    let tail = available
        .checked_sub(u128::from(debit))
        .context("Close debit exceeds available balance")?;
    u64::try_from(tail).context("Close tail exceeds u64")
}

fn prepare_epoch(
    protocol: &Protocol,
    data: EpochData,
    registration: EpochRegistration,
) -> Result<PreparedEpoch> {
    ensure!(
        !data.payments.is_empty() || !data.deposits.is_empty() || !data.withdrawals.is_empty(),
        "there are no payments, deposits, or withdrawals to close"
    );
    let assembled = assemble_epoch(protocol, &data, &registration)?;

    // The completion rehearsal must stage the full deposit set, deferred aggregates
    // included, to reproduce the authoritative chain's boundary and custody exactly.
    let mut events = data.deposits;
    events.extend(data.carried);
    protocol.prepare(
        registration,
        events,
        assembled.predecessor,
        assembled.rows,
        assembled.shard_sets,
        assembled.successor,
    )
}

/// Replays and validates one stored epoch, returning its committed predecessor state.
fn validate_epoch_data(
    protocol: &Protocol,
    data: &EpochData,
    registration: &EpochRegistration,
) -> Result<AccountCache> {
    let assembled = assemble_epoch(protocol, data, registration)?;
    AccountCache::new_with_strategy::<Sha256>(assembled.predecessor, protocol.strategy())
        .context("commit recovered predecessor state")
}

fn assemble_epoch(
    protocol: &Protocol,
    data: &EpochData,
    registration: &EpochRegistration,
) -> Result<EpochAssembly> {
    ensure!(
        data.epoch == registration.context.payment().epoch(),
        "registration does not match SQLite epoch"
    );
    let accounts = data
        .accounts
        .iter()
        .map(|account| (account.key.clone(), account))
        .collect::<BTreeMap<_, _>>();
    let stored_withdrawals = data
        .withdrawals
        .iter()
        .map(|stored| (stored.request.account().clone(), stored))
        .collect::<BTreeMap<_, _>>();
    ensure!(
        stored_withdrawals.len() == data.withdrawals.len(),
        "SQLite contains duplicate account withdrawals"
    );
    // Replay signed endpoints in canonical database order. These checks bind every mutable cache
    // field back to the immutable payment log before any recovered operator action is allowed.
    let mut activity = BTreeMap::<Key, AccountActivity>::new();
    let mut payer_endpoints = accounts
        .iter()
        .map(|(key, account)| (key.clone(), account.predecessor.cumulative_debit))
        .collect::<BTreeMap<_, _>>();
    let mut payer_batches = BTreeMap::<Key, (TxId<Digest>, SignedSend<Key, Digest>)>::new();
    let mut receipt_endpoints = BTreeMap::<(Key, u64), (u64, u64)>::new();
    let mut outgoing = BTreeMap::<Key, Payment>::new();
    let mut heads = BTreeMap::<Key, BTreeMap<u64, Payment>>::new();

    for stored in &data.payments {
        let payment = &stored.payment;
        let payer = payment.payer().clone();

        // Rows of one batched send carry byte-identical copies of one send. The batch's
        // first row verifies that send and binds the stored transaction id, so a later row
        // proves only that it carries the same send, that its receipt is operator signed,
        // and that the receipt links to one exact entry of that verified send.
        let head_tx_id = match payer_batches
            .get(&payer)
            .filter(|(tx_id, _)| tx_id.into_digest() == stored.tx_id)
        {
            Some((batch_tx_id, batch_send)) => {
                ensure!(
                    payment.send() == batch_send,
                    "stored batch entry does not carry its verified send"
                );
                payment
                    .receipt()
                    .verify(registration.context.payment())
                    .with_context(|| format!("verify stored payment {}", stored.sequence))?;
                ensure!(
                    payment.receipt().links(batch_send.body(), batch_tx_id),
                    "stored batch entry is not linked to its send"
                );
                None
            }
            None => {
                let tx_id = payment.send().tx_id::<Sha256>();
                ensure!(
                    stored.tx_id == tx_id.into_digest(),
                    "stored transaction id does not match its payment"
                );
                payment
                    .verify_linked_with_strategy::<Sha256>(
                        registration.context.payment(),
                        protocol.strategy(),
                    )
                    .with_context(|| format!("verify stored payment {}", stored.sequence))?;
                Some(tx_id)
            }
        };
        let recipient = payment.recipient().clone();
        let payer_account = accounts
            .get(&payer)
            .context("stored payment payer is not registered")?;
        ensure!(
            payer_account.name == stored.payer_name,
            "stored payer label does not match its key"
        );
        let recipient_account = accounts.get(&recipient);
        ensure!(
            stored.external == recipient_account.is_none(),
            "stored recipient classification is inconsistent"
        );
        if let Some(account) = recipient_account {
            ensure!(
                account.name == stored.recipient_name,
                "stored recipient label does not match its key"
            );
        }

        let previous_debit = payer_endpoints
            .get(&payer)
            .copied()
            .context("payer endpoint is missing")?;
        if let Some(tx_id) = head_tx_id {
            payment
                .send()
                .verify_next(registration.context.payment(), previous_debit)
                .context("stored payer endpoint is not consecutive")?;
            payer_endpoints.insert(payer.clone(), payment.send().body().cumulative_debit());
            payer_batches.insert(payer.clone(), (tx_id, payment.send().clone()));
        } else {
            // Later entries of one batched send share the endpoint its first entry advanced.
            ensure!(
                payment.send().body().cumulative_debit() == previous_debit,
                "stored batch entry endpoint is inconsistent"
            );
        }

        let shard = payment.receipt().body().shard();
        let endpoint = receipt_endpoints
            .entry((recipient.clone(), shard))
            .or_insert((0, 0));
        verify_receipt_step(endpoint.0, endpoint.1, payment)
            .context("stored receipt endpoint is not consecutive")?;
        *endpoint = (
            payment.receipt().body().cumulative_shard_credit(),
            payment.receipt().body().index(),
        );

        let payer_activity = activity.entry(payer.clone()).or_default();
        payer_activity.debit = payer_activity
            .debit
            .checked_add(payment.amount())
            .context("payer debit overflow")?;
        let recipient_activity = activity.entry(recipient.clone()).or_default();
        recipient_activity.credit = recipient_activity
            .credit
            .checked_add(payment.amount())
            .context("recipient credit overflow")?;
        recipient_activity.receipts = recipient_activity
            .receipts
            .checked_add(1)
            .context("recipient receipt count overflow")?;
        outgoing.insert(payer, payment.clone());
        heads
            .entry(recipient)
            .or_default()
            .insert(shard, payment.clone());
    }

    // The receive-shard table is a cache used on the online payment path. Exact comparison keeps a
    // corrupt cache from issuing a receipt that the immutable payment log cannot justify.
    ensure!(
        data.receive_shards.len() == receipt_endpoints.len(),
        "stored receive-shard endpoint count is inconsistent"
    );
    for (stored, ((recipient, shard), (credit, index))) in
        data.receive_shards.iter().zip(&receipt_endpoints)
    {
        ensure!(
            &stored.recipient == recipient
                && stored.shard == *shard
                && stored.cumulative_credit == *credit
                && stored.receipt_index == *index,
            "stored receive-shard endpoint is inconsistent"
        );
    }

    // Reconcile the materialized account table with the replayed payments and staged deposits.
    for account in accounts.values() {
        if account.predecessor.active {
            ensure!(
                account.predecessor.balance > 0,
                "predecessor live account has zero balance"
            );
        } else {
            ensure!(
                account.predecessor == AccountState::default(),
                "absent predecessor account is not canonical"
            );
        }
        let totals = activity.get(&account.key).cloned().unwrap_or_default();
        let deposit = registration.deposits.amount_for(&account.key);
        let withdrawal = registration.withdrawals.request_for(&account.key);
        let stored_withdrawal = stored_withdrawals.get(&account.key).copied();
        ensure!(
            withdrawal == stored_withdrawal.map(|stored| &stored.request),
            "registration withdrawal differs from SQLite"
        );
        let available = u128::from(account.predecessor.balance)
            + u128::from(deposit)
            + u128::from(totals.credit);
        let expected_balance = match withdrawal.map(|request| request.body().action()) {
            Some(WithdrawalAction::Amount(amount)) => available
                .checked_sub(u128::from(amount.get()))
                .and_then(|value| value.checked_sub(u128::from(totals.debit)))
                .and_then(|value| u64::try_from(value).ok())
                .context("account withdrawal exceeds available balance")?,
            Some(WithdrawalAction::Close) => {
                let tail = close_tail(
                    account.predecessor.balance,
                    deposit,
                    totals.credit,
                    totals.debit,
                )?;
                match stored_withdrawal.and_then(|stored| stored.applied_amount) {
                    Some(applied) => {
                        ensure!(applied == tail, "stored Close tail is inconsistent");
                        0
                    }
                    None => tail,
                }
            }
            None => available
                .checked_sub(u128::from(totals.debit))
                .and_then(|value| u64::try_from(value).ok())
                .context("account debit exceeds available balance")?,
        };
        ensure!(
            account.current.balance == expected_balance,
            "SQLite balance drift"
        );
        ensure!(
            account.current.cumulative_debit
                == account
                    .predecessor
                    .cumulative_debit
                    .checked_add(totals.debit)
                    .context("account debit counter overflow")?,
            "SQLite debit counter drift"
        );
        ensure!(
            account.current.cumulative_credit
                == account
                    .predecessor
                    .cumulative_credit
                    .checked_add(totals.credit)
                    .context("account credit counter overflow")?,
            "SQLite credit counter drift"
        );
        ensure!(
            account.current.receipt_count
                == account
                    .predecessor
                    .receipt_count
                    .checked_add(totals.receipts)
                    .context("account receipt counter overflow")?,
            "SQLite receipt counter drift"
        );
    }

    let mut changed = BTreeSet::<Key>::new();
    for account in accounts.values() {
        if account.predecessor != account.current
            || registration.deposits.amount_for(&account.key) != 0
            || registration.withdrawals.request_for(&account.key).is_some()
        {
            changed.insert(account.key.clone());
        }
    }
    changed.extend(
        activity
            .keys()
            .filter(|key| !accounts.contains_key(*key))
            .cloned(),
    );

    // The same replay produces the canonical changed rows, shard heads, and cumulative prefixes
    // consumed by root preparation and validator dealings.
    let mut prefix = Prefix::default();
    let mut rows = Vec::with_capacity(changed.len());
    let mut shard_sets = Vec::with_capacity(changed.len());
    for account in changed {
        let stored = accounts.get(&account).copied();
        let predecessor = stored.map_or(AccountState::default(), |stored| stored.predecessor);
        let totals = activity.get(&account).cloned().unwrap_or_default();
        let successor = stored.map_or(
            AccountState {
                cumulative_credit: totals.credit,
                receipt_count: totals.receipts,
                ..AccountState::default()
            },
            |stored| stored.current,
        );
        let terminal_heads = heads
            .remove(&account)
            .unwrap_or_default()
            .into_iter()
            .map(|(shard, payment)| ShardHead::new(shard, payment))
            .collect::<Vec<_>>();
        let shards = if terminal_heads.is_empty() {
            ShardSet::empty(data.epoch, account.clone())
        } else {
            ShardSet::new(data.epoch, account.clone(), terminal_heads)
                .context("construct terminal receive shards")?
        };
        let deposit = registration.deposits.amount_for(&account);
        let withdrawal = registration.withdrawals.request_for(&account);
        let withdrawal_amount = match withdrawal.map(|request| request.body().action()) {
            Some(WithdrawalAction::Amount(amount)) => amount.get(),
            Some(WithdrawalAction::Close) => {
                close_tail(predecessor.balance, deposit, totals.credit, totals.debit)?
            }
            None => 0,
        };
        let successor = if matches!(
            withdrawal.map(|request| request.body().action()),
            Some(WithdrawalAction::Close)
        ) {
            AccountState {
                balance: 0,
                active: false,
                ..successor
            }
        } else {
            successor
        };
        let registered = predecessor.active || deposit != 0;
        let payout = if registered { 0 } else { totals.credit };
        let output = match withdrawal {
            Some(_) => SettlementOutput::Withdrawal(withdrawal_amount),
            None if payout != 0 => SettlementOutput::ExternalPayout(payout),
            None => SettlementOutput::None,
        };
        prefix = prefix
            .checked_extend(Prefix {
                debit: totals.debit,
                credit: totals.credit,
                payout,
                deposit,
                withdrawal: withdrawal_amount,
                withdrawal_count: u64::from(withdrawal.is_some()),
                shard_count: u64::try_from(shards.heads().len())
                    .context("shard count does not fit u64")?,
            })
            .context("close prefix overflow")?;
        rows.push(AccountRow {
            account: account.clone(),
            predecessor,
            successor,
            outgoing: outgoing.remove(&account),
            output,
            prefix,
        });
        shard_sets.push(shards);
    }

    let predecessor = data
        .accounts
        .iter()
        .filter(|account| account.predecessor.active)
        .map(|account| StateLeaf {
            account: account.key.clone(),
            state: account.predecessor,
        })
        .collect::<Vec<_>>();
    let successor = data
        .accounts
        .iter()
        .filter(|account| {
            account.current.balance > 0
                && !matches!(
                    registration
                        .withdrawals
                        .request_for(&account.key)
                        .map(|request| request.body().action()),
                    Some(WithdrawalAction::Close)
                )
        })
        .map(|stored| StateLeaf {
            account: stored.key.clone(),
            state: stored.current,
        })
        .collect::<Vec<_>>();
    Ok(EpochAssembly {
        predecessor,
        rows,
        shard_sets,
        successor,
    })
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
