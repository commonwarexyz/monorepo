//! Application orchestration across wallets, SQLite, and the clearing protocol.

use crate::{
    protocol::{
        AccountCache, AccountIdentity, DepositEvent, EpochRegistration, INITIAL_BALANCE, Key,
        Payment, PreparedEpoch, Protocol, SettlementResult, ensure_amount_withdrawal_horizon,
        ensure_balance_intake_horizon, ensure_close_horizon, external_identity, identities,
        openable_epoch_after, short_digest,
    },
    settlement::SettlementSubmission,
    settlement_rpc,
    store::{
        AcceptedBatch, CloseRejected, CommitUnknown, EpochData, ExternalPayoutEvidence,
        MutationFailed, StagedDeposit, StagedWithdrawal, Store, StoreStatus, StoredCloseOutcome,
        WithdrawalEvidence,
    },
};
#[cfg(test)]
use crate::{
    protocol::{Wallet, wallets},
    store::{AccountView, MAX_DESTINATION_BYTES, StoreSnapshot},
};
use anyhow::{Context, Result, ensure};
#[cfg(test)]
use bytes::Bytes;
use commonware_clearing::bajillion::{
    boundary::{DepositBatch, DepositRecord, SignedWithdrawal, WithdrawalAction, WithdrawalBatch},
    challenge::StateOpening,
    commitment::VectorRoot,
    credit::{ShardHead, ShardSet},
    payment::{PaymentContext, SignedSend, verify_receipt_step},
    state::{AccountRow, AccountState, Prefix, SettlementOutput, StateLeaf},
    transition::{BatchId, ExternalPayoutClaim, WithdrawalClaim},
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

#[derive(Clone)]
pub(crate) struct SettlementRegistration {
    pub(crate) epoch: u64,
    pub(crate) predecessor_liability: u64,
    pub(crate) deposits: DepositBatch<Key>,
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
        let current_predecessor_root = validate_epoch_data(&protocol, &current, &registration)
            .context("validate current SQLite epoch")?;
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
        let current = self.store.load_current()?;
        let assembled = assemble_epoch(&self.protocol, &current, &self.registration)?;
        let predecessor = AccountCache::new_with_strategy::<Sha256>(
            assembled.predecessor,
            self.protocol.strategy(),
        )
        .context("commit payment recovery state")?;
        let state = current
            .accounts
            .iter()
            .find(|stored| &stored.key == account)
            .context("payer is not in the current live state")?;
        ensure!(
            state.current.active,
            "payer is not in the current live state"
        );
        let payer_opening = predecessor
            .opening(account)
            .context("open payer recovery state")?;
        Ok(PaymentQuote {
            context: self.registration.context.payment().clone(),
            state: state.current,
            root: predecessor.root(),
            opening: payer_opening,
        })
    }

    pub(crate) fn accept_send(&mut self, send: SignedSend<Key, Digest>) -> Result<AcceptedBatch> {
        self.ensure_operating()?;
        self.validate_recipients(&send)?;
        if self.store.payment_requires_epoch_registration(
            self.registration.context.payment(),
            &send,
            0,
        )? {
            self.ensure_balance_intake_horizon()?;
        }
        let result = self.store.accept_send(
            self.registration.context.payment(),
            self.protocol.operator(),
            send,
            0,
        );
        self.guard_store(result)
    }

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
        let current = self.store.load_current()?;
        let assembled = assemble_epoch(&self.protocol, &current, &self.registration)?;
        let predecessor = AccountCache::new_with_strategy::<Sha256>(
            assembled.predecessor,
            self.protocol.strategy(),
        )
        .context("commit withdrawal safety state")?;
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
            predecessor.root().digest,
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
        let current = self.store.load_current()?;
        let assembled = assemble_epoch(&self.protocol, &current, &self.registration)?;
        let predecessor = AccountCache::new_with_strategy::<Sha256>(
            assembled.predecessor,
            self.protocol.strategy(),
        )
        .context("commit withdrawal safety state")?;
        Ok(WithdrawalOpening {
            root: predecessor.root(),
            opening: predecessor
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

        // Settlement refuses to register a carried amount that exactly offsets the close's
        // staged deposit (that shape must defer the deposit through the queue), so fail it
        // here instead of wedging the epoch at registration.
        if let WithdrawalAction::Amount(amount) = request.body().action() {
            let deposited = self.registration.deposits.amount_for(request.account());
            ensure!(
                deposited == 0 || amount.get() != deposited,
                "a carried withdrawal cannot exactly offset the staged deposit"
            );
        }
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
        let successor = self.protocol.registration(
            next_epoch,
            DepositBatch::empty(),
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
        let deposits = self.registration.deposits.clone();
        let withdrawals = self.registration.withdrawals.clone();
        let openings = if withdrawals.requests().is_empty() {
            Vec::new()
        } else {
            let current = self.store.load_current()?;
            let assembled = assemble_epoch(&self.protocol, &current, &self.registration)?;
            let predecessor = AccountCache::new_with_strategy::<Sha256>(
                assembled.predecessor,
                self.protocol.strategy(),
            )
            .context("commit registration predecessor state")?;
            withdrawals
                .requests()
                .iter()
                .map(|request| {
                    predecessor
                        .opening(request.account())
                        .context("open carried withdrawal account")
                })
                .collect::<Result<Vec<_>>>()?
        };
        let signature =
            self.protocol
                .sign_registration(epoch, predecessor_liability, &deposits, &withdrawals);
        Ok(SettlementRegistration {
            epoch,
            predecessor_liability,
            deposits,
            withdrawals,
            openings,
            signature,
        })
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

fn registration_for(protocol: &Protocol, data: &EpochData) -> Result<EpochRegistration> {
    let mut deposits = BTreeMap::<Key, u64>::new();
    for stored in &data.deposits {
        let amount = deposits.entry(stored.account.clone()).or_default();
        *amount = amount
            .checked_add(stored.amount)
            .context("deposit total overflow")?;
    }
    let deposits = DepositBatch::new(
        deposits
            .into_iter()
            .map(|(account, amount)| DepositRecord::new(account, amount))
            .collect::<Result<Vec<_>, _>>()?,
    )?;
    let withdrawals = WithdrawalBatch::new(
        data.withdrawals
            .iter()
            .map(|stored| stored.request.clone())
            .collect(),
    )?;
    protocol.registration(
        data.epoch,
        deposits,
        withdrawals,
        predecessor_liability(data)?,
    )
}

fn registration_with_deposit(
    protocol: &Protocol,
    current: &EpochRegistration,
    account: Key,
    amount: u64,
) -> Result<EpochRegistration> {
    ensure!(amount > 0, "deposit amount must be positive");
    let mut deposits = current
        .deposits
        .records()
        .iter()
        .map(|record| (record.account().clone(), record.amount()))
        .collect::<BTreeMap<_, _>>();
    let total = deposits.entry(account).or_default();
    *total = total
        .checked_add(amount)
        .context("deposit total overflow")?;
    let deposits = DepositBatch::new(
        deposits
            .into_iter()
            .map(|(account, amount)| DepositRecord::new(account, amount))
            .collect::<Result<Vec<_>, _>>()?,
    )?;
    protocol.registration(
        current.context.payment().epoch(),
        deposits,
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
        current.deposits.clone(),
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
    protocol.prepare(
        registration,
        data.deposits,
        assembled.predecessor,
        assembled.rows,
        assembled.shard_sets,
        assembled.successor,
    )
}

fn validate_epoch_data(
    protocol: &Protocol,
    data: &EpochData,
    registration: &EpochRegistration,
) -> Result<VectorRoot<Digest>> {
    let assembled = assemble_epoch(protocol, data, registration)?;
    Ok(
        AccountCache::new_with_strategy::<Sha256>(assembled.predecessor, protocol.strategy())
            .context("commit recovered predecessor state")?
            .root(),
    )
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
    let mut payer_batches = BTreeMap::<Key, Digest>::new();
    let mut receipt_endpoints = BTreeMap::<(Key, u64), (u64, u64)>::new();
    let mut outgoing = BTreeMap::<Key, Payment>::new();
    let mut heads = BTreeMap::<Key, BTreeMap<u64, Payment>>::new();

    for stored in &data.payments {
        let payment = &stored.payment;
        ensure!(
            stored.tx_id == payment.send().tx_id::<Sha256>().into_digest(),
            "stored transaction id does not match its payment"
        );
        payment
            .verify_linked_with_strategy::<Sha256>(
                registration.context.payment(),
                protocol.strategy(),
            )
            .with_context(|| format!("verify stored payment {}", stored.sequence))?;
        let payer = payment.payer().clone();
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
        if payer_batches.get(&payer) == Some(&stored.tx_id) {
            // Later entries of one batched send share the endpoint its first entry advanced.
            ensure!(
                payment.send().body().cumulative_debit() == previous_debit,
                "stored batch entry endpoint is inconsistent"
            );
        } else {
            payment
                .send()
                .verify_next(registration.context.payment(), previous_debit)
                .context("stored payer endpoint is not consecutive")?;
            payer_endpoints.insert(payer.clone(), payment.send().body().cumulative_debit());
            payer_batches.insert(payer.clone(), stored.tx_id);
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
mod tests {
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
            let directory = std::env::temp_dir()
                .join(format!("commonware-terminal-{}-{id}", std::process::id()));
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
                DepositBatch::empty(),
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
            let mut operator =
                Operator::open(database.path(), NonZeroUsize::new(2).unwrap()).unwrap();
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
            let mut operator =
                Operator::open(database.path(), NonZeroUsize::new(2).unwrap()).unwrap();
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
        let prepared =
            prepare_epoch(&operator.protocol, data, operator.registration.clone()).unwrap();

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
        let prepared =
            prepare_epoch(&operator.protocol, data, operator.registration.clone()).unwrap();
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
        let prepared =
            prepare_epoch(&operator.protocol, data, operator.registration.clone()).unwrap();
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
        let prepared =
            prepare_epoch(&operator.protocol, data, operator.registration.clone()).unwrap();
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
        let prepared =
            prepare_epoch(&operator.protocol, data, operator.registration.clone()).unwrap();
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
        let send =
            SignedSend::sign_next(&stale, payer.signer(), recipient.public_key(), 1, 0).unwrap();

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
            let mut operator =
                Operator::open(database.path(), NonZeroUsize::new(2).unwrap()).unwrap();
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
            let mut operator =
                Operator::open(database.path(), NonZeroUsize::new(2).unwrap()).unwrap();
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
            let mut operator =
                Operator::open(database.path(), NonZeroUsize::new(2).unwrap()).unwrap();
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
            let mut operator =
                Operator::open(database.path(), NonZeroUsize::new(2).unwrap()).unwrap();
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
            let mut operator =
                Operator::open(database.path(), NonZeroUsize::new(2).unwrap()).unwrap();
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
            let mut operator =
                Operator::open(database.path(), NonZeroUsize::new(2).unwrap()).unwrap();
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
            let mut operator =
                Operator::open(database.path(), NonZeroUsize::new(2).unwrap()).unwrap();
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
            let mut operator =
                Operator::open(database.path(), NonZeroUsize::new(2).unwrap()).unwrap();
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
        settlement
            .register_epoch(
                data.epoch,
                operator.registration.context.predecessor_liability(),
                operator.registration.deposits.clone(),
                operator.registration.withdrawals.clone(),
                &operator.settlement_registration().unwrap().openings,
            )
            .unwrap();
        let prepared =
            prepare_epoch(&operator.protocol, data, operator.registration.clone()).unwrap();
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
        let payout = settlement
            .claim_external_payout(finalized.batch_id, claim)
            .unwrap();
        assert_eq!(payout.recipient, external_identity().key);
        assert_eq!(payout.amount, 100);
        assert_eq!(
            settlement
                .claim_external_payout(finalized.batch_id, claim)
                .unwrap(),
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
        settlement
            .register_epoch(
                data.epoch,
                operator.registration.context.predecessor_liability(),
                operator.registration.deposits.clone(),
                operator.registration.withdrawals.clone(),
                &operator.settlement_registration().unwrap().openings,
            )
            .unwrap();
        let prepared =
            prepare_epoch(&operator.protocol, data, operator.registration.clone()).unwrap();
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
        settlement
            .register_epoch(
                data.epoch,
                operator.registration.context.predecessor_liability(),
                operator.registration.deposits.clone(),
                operator.registration.withdrawals.clone(),
                &operator.settlement_registration().unwrap().openings,
            )
            .unwrap();
        let prepared =
            prepare_epoch(&operator.protocol, data, operator.registration.clone()).unwrap();
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
        let first_payout = settlement
            .claim_external_payout(first_finalized.batch_id, first_claim)
            .unwrap();
        let second_claim = second.external_claims.first().unwrap();
        assert_eq!(second_claim.position(), 0);
        assert_ne!(second_finalized.batch_id, first_finalized.batch_id);
        let second_payout = settlement
            .claim_external_payout(second_finalized.batch_id, second_claim)
            .unwrap();
        assert_eq!(
            settlement
                .claim_external_payout(second_finalized.batch_id, second_claim)
                .unwrap(),
            second_payout
        );
        assert!(
            settlement
                .claim_external_payout(first_finalized.batch_id, second_claim)
                .is_err()
        );
        assert_eq!(
            settlement
                .claim_external_payout(first_finalized.batch_id, first_claim)
                .unwrap(),
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
        settlement
            .register_epoch(
                data.epoch,
                operator.registration.context.predecessor_liability(),
                operator.registration.deposits.clone(),
                operator.registration.withdrawals.clone(),
                &operator.settlement_registration().unwrap().openings,
            )
            .unwrap();
        let prepared =
            prepare_epoch(&operator.protocol, data, operator.registration.clone()).unwrap();
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
        let first_output = settlement
            .claim_withdrawal(first_finalized.batch_id, first_claim)
            .unwrap();

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
        settlement
            .register_epoch(
                data.epoch,
                operator.registration.context.predecessor_liability(),
                operator.registration.deposits.clone(),
                operator.registration.withdrawals.clone(),
                &operator.settlement_registration().unwrap().openings,
            )
            .unwrap();
        let prepared =
            prepare_epoch(&operator.protocol, data, operator.registration.clone()).unwrap();
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
        let second_output = settlement
            .claim_withdrawal(second_finalized.batch_id, second_claim)
            .unwrap();
        assert_eq!(
            settlement
                .claim_withdrawal(second_finalized.batch_id, second_claim)
                .unwrap(),
            second_output
        );
        assert!(
            settlement
                .claim_withdrawal(first_finalized.batch_id, second_claim)
                .is_err()
        );
        assert_eq!(
            settlement
                .claim_withdrawal(first_finalized.batch_id, first_claim)
                .unwrap(),
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
        let prepared =
            prepare_epoch(&operator.protocol, data, operator.registration.clone()).unwrap();
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
        let prepared =
            prepare_epoch(&operator.protocol, data, operator.registration.clone()).unwrap();
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
        settlement
            .register_epoch(
                data.epoch,
                operator.registration.context.predecessor_liability(),
                operator.registration.deposits.clone(),
                operator.registration.withdrawals.clone(),
                &operator.settlement_registration().unwrap().openings,
            )
            .unwrap();
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
        let finalized = settlement
            .admit(SettlementSubmission::from(&result))
            .unwrap();
        assert_eq!(finalized.batch_id, batch_id);
        let release = settlement
            .claim_withdrawal(evidence.batch_id, &evidence.claim)
            .unwrap();
        assert_eq!(release.amount(), 25);
        assert_eq!(release.destination().as_ref(), b"Alice");
        assert_eq!(&release, evidence.claim.output());
        assert_eq!(
            settlement
                .claim_withdrawal(evidence.batch_id, &evidence.claim)
                .unwrap(),
            release
        );
    }

    #[test]
    fn exact_offset_is_rejected_at_staging_and_queueing_but_close_composes() {
        let mut first_operator = operator();
        let staged = first_operator.deposit(0, 10).unwrap();
        let event = DepositEvent {
            id: staged.id,
            account: staged.account,
            amount: staged.amount,
        };
        let mut settlement = crate::settlement::Settlement::new().unwrap();
        settlement.deposit(event).unwrap();

        // The operator refuses to carry the offset shape, and the settlement queue
        // refuses to defer it, so neither intake can wedge a registration.
        let error = first_operator
            .withdraw(0, amount(10))
            .err()
            .expect("exact-offset staging must be refused");
        assert!(format!("{error:#}").contains("exactly offset"));
        let offset = SignedWithdrawal::sign(
            first_operator.protocol.deployment(),
            settlement.status().unwrap().state_root.digest,
            Bytes::from_static(b"Alice"),
            amount(10),
            50,
            first_operator.wallets[0].signer(),
        );
        let error = settlement.queue_withdrawal(offset, Vec::new()).unwrap_err();
        assert!(format!("{error:#}").contains("exactly offset"));

        let mut second_operator = operator();
        let account = second_operator.wallets[0].public_key();
        let opening = second_operator.withdrawal_opening(&account).unwrap();
        second_operator
            .withdraw(0, WithdrawalAction::Close)
            .unwrap();
        let staged = second_operator.deposit(0, 1).unwrap();
        let request = second_operator.store.load_current().unwrap().withdrawals[0]
            .request
            .clone();
        let mut settlement = crate::settlement::Settlement::new().unwrap();
        settlement
            .queue_withdrawal(request, vec![opening.opening])
            .unwrap();
        let event = DepositEvent {
            id: staged.id,
            account: staged.account,
            amount: staged.amount,
        };
        settlement.deposit(event.clone()).unwrap();
        settlement.confirm_deposit(&event).unwrap();

        let mut third_operator = operator();
        let staged = third_operator.deposit(0, 1).unwrap();
        let event = DepositEvent {
            id: staged.id,
            account: staged.account,
            amount: staged.amount,
        };
        let opening = third_operator.withdrawal_opening(&account).unwrap();
        third_operator.withdraw(0, WithdrawalAction::Close).unwrap();
        let request = third_operator.store.load_current().unwrap().withdrawals[0]
            .request
            .clone();
        let mut settlement = crate::settlement::Settlement::new().unwrap();
        settlement.deposit(event).unwrap();
        settlement
            .queue_withdrawal(request, vec![opening.opening])
            .unwrap();
    }

    #[test]
    fn acknowledged_withdrawal_evidence_advances_to_the_next_epoch() {
        let mut operator = operator();
        operator.withdraw(0, amount(25)).unwrap();
        let data = operator.store.load_current().unwrap();
        let prepared =
            prepare_epoch(&operator.protocol, data, operator.registration.clone()).unwrap();
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
        let prepared =
            prepare_epoch(&operator.protocol, data, operator.registration.clone()).unwrap();
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
        settlement
            .register_epoch(
                data.epoch,
                operator.registration.context.predecessor_liability(),
                operator.registration.deposits.clone(),
                operator.registration.withdrawals.clone(),
                &operator.settlement_registration().unwrap().openings,
            )
            .unwrap();
        let prepared =
            prepare_epoch(&operator.protocol, data, operator.registration.clone()).unwrap();
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
        let prepared =
            prepare_epoch(&operator.protocol, data, operator.registration.clone()).unwrap();
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
        let prepared =
            prepare_epoch(&operator.protocol, data, operator.registration.clone()).unwrap();
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
}
