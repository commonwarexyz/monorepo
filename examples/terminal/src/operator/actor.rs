//! Application orchestration across wallets, SQLite, and the clearing protocol.

use super::store::{
    AcceptedBatch, CloseRejected, EpochData, ExternalPayoutEvidence, IncomingPayment,
    MutationFailed, RETAINED_EPOCHS, SendVerdict, StagedDeposit, StagedWithdrawal, Staging, Store,
    StoreStatus, StoredCloseOutcome, WithdrawalEvidence,
};
#[cfg(test)]
use super::store::{AccountView, Endpoint, StoreSnapshot};
#[cfg(test)]
use crate::protocol::{MAX_DESTINATION_BYTES, Wallet, wallets};
use crate::{
    chain::{
        node::Pipeline,
        state::RegistrationRecord,
        tx::{AdmitRequest, RegisterEpochRequest},
    },
    protocol::{
        AccountCache, AccountIdentity, Ack, DepositEvent, Entry, EpochRegistration,
        INITIAL_BALANCE, Key, PreparedEpoch, Protocol, SettlementResult,
        ensure_amount_withdrawal_horizon, ensure_balance_intake_horizon, ensure_close_horizon,
        external_identity, identities, openable_epoch_after, short_digest,
    },
    store::CommitUnknown,
};
use anyhow::{Context, Result, ensure};
#[cfg(test)]
use bytes::Bytes;
use commonware_clearing::bajillion::{
    boundary::{DepositBatch, DepositRecord, SignedWithdrawal, WithdrawalAction, WithdrawalBatch},
    challenge::{HigherEntryLookup, StateOpening, higher_entry_lookup},
    commitment::{VectorKind, VectorRoot},
    payment::{PaymentContext, SendAuthorization, VECTOR_ACK_AGGREGATE_NAMESPACE, VectorSendBody},
    state::{AccountRow, AccountState, Prefix, SettlementOutput, StateLeaf},
    transition::{
        BatchId, ChallengeIndex, ExternalPayoutClaim, OperatorSignature, OperatorVariant,
        WithdrawalClaim,
    },
    vector::{OutEntry, OutVector, TransposeEntry},
};
use commonware_codec::Encode as _;
#[cfg(test)]
use commonware_codec::EncodeSize as _;
#[cfg(test)]
use commonware_cryptography::Hasher;
use commonware_cryptography::{Sha256, bls12381::primitives::ops::verify_message, sha256::Digest};
#[cfg(test)]
use std::num::NonZeroU64;
#[cfg(test)]
use std::sync::mpsc::SyncSender;
#[cfg(test)]
use std::time::Duration;
use std::{
    collections::{BTreeMap, BTreeSet},
    num::NonZeroUsize,
    path::Path,
    sync::{
        Arc,
        mpsc::{self, Receiver, TryRecvError},
    },
    thread::{self, JoinHandle},
    time::Instant,
};

pub(crate) const DEFAULT_AMOUNT: u64 = 5;
const MAX_PENDING_CLOSES: usize = 4;
#[cfg(test)]
const DEPOSIT_ID_NAMESPACE: &[u8] = b"_COMMONWARE_EXAMPLES_TERMINAL_DEPOSIT";

pub(crate) struct CloseStarted {
    pub(crate) epoch: u64,
    pub(crate) queued: bool,
}

pub(crate) struct PaymentHead {
    pub(crate) context: PaymentContext<Key, Digest>,
    pub(crate) state: AccountState,
    pub(crate) root: VectorRoot<Digest>,
    pub(crate) opening: StateOpening<Key, Digest>,
}

/// The operator's verdict on one submitted send.
pub(crate) enum SendOutcome {
    /// The send, or its exact replay, is committed with its acceptance.
    Accepted(AcceptedBatch),
    /// Corrective rejection: the send binds a payment context this operator has moved
    /// past, or an endpoint that does not extend the payer's accepted state, so its
    /// exact bytes can never be accepted. The verdict carries the live context and the
    /// payer's accepted endpoint as this operator sees it: its cumulative debit, its
    /// epoch-local batch sequence, and its cumulative out vector, so the payer can
    /// adopt, merge, re-sign, and retry locally instead of re-reading the head. The
    /// claim is unauthenticated by design: a payer signs cumulative debit endpoints,
    /// and two sends at one endpoint under different contexts can never both debit, so
    /// adopting a false endpoint only produces a send that never commits.
    Stale {
        context: PaymentContext<Key, Digest>,
        cumulative_debit: u64,
        seq: u64,
        entries: Vec<OutEntry<Key>>,
    },
}

#[cfg(test)]
impl SendOutcome {
    /// Unwraps the accepted batch, panicking on a corrective rejection.
    pub(crate) fn into_accepted(self) -> AcceptedBatch {
        match self {
            Self::Accepted(accepted) => accepted,
            Self::Stale { .. } => panic!("the send was rejected with a corrective context"),
        }
    }
}

pub(crate) struct WithdrawalOpening {
    pub(crate) root: VectorRoot<Digest>,
    pub(crate) opening: StateOpening<Key, Digest>,
}

/// Committed-side terminal-entry evidence for one (payer, recipient) edge, reconstructed
/// from retained epoch data. A receiver resolves the lookup against `change_root` to read
/// the close's public terminal entry for the edge, then challenges when a held receipt
/// exceeds it.
pub(crate) struct CommittedEntry {
    pub(crate) batch_id: BatchId<Digest>,
    pub(crate) change_root: VectorRoot<Digest>,
    pub(crate) lookup: HigherEntryLookup<Key, Digest>,
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
    /// Close pipeline over the operator node's DA channel and local chain
    /// backend. `None` runs the in-process harness certification instead.
    pipeline: Option<Pipeline>,
    genesis_root: VectorRoot<Digest>,
    registration: EpochRegistration,
    /// Predecessor state commitment retained for the current epoch.
    ///
    /// Payments, deposits, and withdrawals mutate only `current_*` account state, so the
    /// predecessor set is immutable between rotations. Head reads, openings, and registration
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
        Self::from_store(store, identities, Protocol::new(workers)?, None)
    }

    /// Opens the operator over its follower node's close `pipeline`, signing
    /// as `clearing` with `ack` as its aggregable-acknowledgment BLS key: the
    /// deployment this operator runs derives from that clearing identity.
    pub(crate) fn open_remote(
        path: &Path,
        workers: NonZeroUsize,
        pipeline: Pipeline,
        clearing: commonware_cryptography_curve25519::signing::SigningKey,
        ack: commonware_cryptography::bls12381::primitives::group::Private,
    ) -> Result<Self> {
        let identities = identities();
        let store = Store::open(path, &identities)?;
        Self::from_store(
            store,
            identities,
            Protocol::with_signer(workers, clearing, ack)?,
            Some(pipeline),
        )
    }

    #[cfg(test)]
    fn in_memory(workers: NonZeroUsize) -> Result<Self> {
        let identities = identities();
        let store = Store::in_memory(&identities)?;
        Self::from_store(store, identities, Protocol::new(workers)?, None)
    }

    fn from_store(
        mut store: Store,
        identities: Vec<AccountIdentity>,
        protocol: Protocol,
        pipeline: Option<Pipeline>,
    ) -> Result<Self> {
        let protocol = Arc::new(protocol);
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
            pipeline,
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
    pub(crate) const fn receiver_count(&self) -> usize {
        self.wallets.len() + 1
    }

    #[cfg(test)]
    pub(crate) fn pay(
        &mut self,
        payer: usize,
        receiver: usize,
        amount: u64,
    ) -> Result<AcceptedBatch> {
        self.ensure_operating()?;
        ensure!(amount > 0, "payment amount must be positive");
        let payer = payer % self.wallets.len();
        let receiver_index = receiver % self.receiver_count();
        let receiver = if receiver_index == self.wallets.len() {
            self.external.key.clone()
        } else {
            self.wallets[receiver_index].public_key()
        };
        let head = self.payment_head(&self.wallets[payer].public_key())?;
        ensure!(head.state.balance > 0, "selected payer has no balance");
        let (authorization, entries) = self.sign_send(payer, &[(receiver, amount)])?;
        match self.accept_send(authorization, entries)? {
            SendOutcome::Accepted(accepted) => Ok(accepted),

            // Mutations are serialized on `&mut self`, so the endpoint cannot move
            // between the signing above and this acceptance.
            SendOutcome::Stale { .. } => unreachable!("the live endpoint moved under one borrow"),
        }
    }

    /// Signs `deltas` from wallet `payer` at its live accepted endpoint.
    #[cfg(test)]
    pub(crate) fn sign_send(
        &self,
        payer: usize,
        deltas: &[(Key, u64)],
    ) -> Result<(SendAuthorization<Key, Digest>, Vec<Entry>)> {
        let wallet = &self.wallets[payer % self.wallets.len()];
        let endpoint = self.store.payer_endpoint(&wallet.public_key())?;
        sign_send_at(
            self.registration.context.payment(),
            wallet,
            &endpoint,
            deltas,
        )
    }

    pub(crate) fn payment_head(&self, account: &Key) -> Result<PaymentHead> {
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
        Ok(PaymentHead {
            context: self.registration.context.payment().clone(),
            state: state.current,
            root: self.predecessor.root(),
            opening: payer_opening,
        })
    }

    /// Reads the committed batch for one authorization, a plain durable lookup by its
    /// signed endpoint.
    ///
    /// This is an optional receipts fetch for a wallet that already decided commitment from
    /// a finalized settlement root. It carries no verdict, so it stays readable across the
    /// operating fence (a failed predecessor close leaves committed rows intact) but still
    /// refuses to read past a storage fault, which is fatal until the operator restarts.
    pub(crate) fn accepted_batch(
        &self,
        authorization: &SendAuthorization<Key, Digest>,
        entries: &[Entry],
    ) -> Result<Option<AcceptedBatch>> {
        ensure!(
            self.store_fault.is_none(),
            "a storage fault blocks committed-batch reads until the operator restarts"
        );
        self.store.accepted_batch(authorization, entries)
    }

    /// Serves accepted entry receipts crediting `receiver` after the caller's durable cursor.
    ///
    /// This is a plain durable read of committed serving-log rows, so it stays readable across
    /// the operating fence and refuses only past a storage fault.
    pub(crate) fn incoming_payments(
        &self,
        receiver: &Key,
        after: u64,
        limit: usize,
    ) -> Result<Vec<IncomingPayment>> {
        self.ensure_store_usable()?;
        self.store.incoming_payments(receiver, after, limit)
    }

    /// Finalized epochs whose closes [`Self::committed_entry`] still reconstructs exactly,
    /// counted back from the latest finalized epoch: the receiver reconciliation contract.
    pub(crate) const RETAINED_EPOCHS: u64 = RETAINED_EPOCHS;

    /// Reconstructs the committed public terminal entry for one (payer, recipient) edge of
    /// a retained epoch.
    ///
    /// The close is rebuilt from the retained acknowledgment log with the same lookup
    /// constructor the challenge tests use, so the served [`HigherEntryLookup`] opens
    /// against the reconstructed close's own change root. Retention is bounded: a finalized
    /// epoch reconstructs exactly until [`Self::RETAINED_EPOCHS`] further epochs finalize and
    /// may not afterwards, which a receiver reports as unavailability rather than
    /// withholding.
    pub(crate) fn committed_entry(
        &self,
        payer: &Key,
        recipient: &Key,
        epoch: u64,
    ) -> Result<CommittedEntry> {
        self.ensure_store_usable()?;
        let data = self.store.load_at(epoch)?;
        let registration = registration_for(&self.protocol, &data)?;
        let prepared = prepare_epoch(&self.protocol, data, registration)
            .context("reconstruct committed close for entry evidence")?;
        let close = prepared.close();
        let index = ChallengeIndex::new::<Sha256>(prepared.close_context(), close)
            .context("index committed close for entry evidence")?;

        // A changed payer has a row and an aligned out vector (empty for a credit-only
        // row). An absent payer has neither, and the lookup constructor requires the
        // matching pairing.
        let vector = close
            .rows
            .binary_search_by(|row| row.account.cmp(payer))
            .ok()
            .map(|position| &close.out_vectors[position]);
        let lookup = higher_entry_lookup::<Sha256, _, _>(&index, payer, vector, recipient)
            .context("compose committed entry lookup")?;
        Ok(CommittedEntry {
            batch_id: close.header.batch_id::<Sha256>(),
            change_root: close.roots.change,
            lookup,
        })
    }

    pub(crate) fn accept_send(
        &mut self,
        authorization: SendAuthorization<Key, Digest>,
        entries: Vec<Entry>,
    ) -> Result<SendOutcome> {
        self.ensure_operating()?;
        self.validate_recipients(&entries)?;

        // A replay lookup is the only pre-mutation probe: the store transaction fully
        // validates a new batch before any mutation, so validating here too would repeat
        // the same signature checks on every accepted payment.
        if let Some(accepted) = self.store.accepted_batch(&authorization, &entries)? {
            return Ok(SendOutcome::Accepted(accepted));
        }

        // A send bound to a context this operator moved past can never be accepted, so
        // it earns the corrective rejection instead of an opaque error: the live context
        // and the payer's endpoint let an optimistic payer merge, re-sign, and retry
        // from its local state instead of re-reading the head.
        let context = self.registration.context.payment().clone();
        let body = authorization.body();
        let rebound = VectorSendBody::new(
            &context,
            body.payer().clone(),
            body.seq(),
            body.cumulative_debit(),
            body.send_root(),
        );
        if rebound != *body {
            let endpoint = self.store.payer_endpoint(body.payer())?;
            return Ok(SendOutcome::Stale {
                context,
                cumulative_debit: endpoint.cumulative_debit,
                seq: endpoint.seq,
                entries: endpoint.entries,
            });
        }
        self.ensure_balance_intake_horizon()?;
        let result = self.store.accept_send(
            self.registration.context.payment(),
            &self.protocol,
            authorization,
            &entries,
        );
        match self.guard_store(result)? {
            SendVerdict::Accepted(accepted) => Ok(SendOutcome::Accepted(*accepted)),
            SendVerdict::Stale(endpoint) => Ok(SendOutcome::Stale {
                context,
                cumulative_debit: endpoint.cumulative_debit,
                seq: endpoint.seq,
                entries: endpoint.entries,
            }),
        }
    }

    /// Reports whether accepting this send must first register the epoch with settlement.
    ///
    /// This probe keeps the full validation of a new live-context send: registering an
    /// epoch starts settlement's liveness clock, so only a payer-authorized send may
    /// trigger it. A stale send short-circuits to `false` instead, because acceptance
    /// answers it with the corrective rejection and admits nothing.
    pub(crate) fn send_requires_epoch_registration(
        &self,
        authorization: &SendAuthorization<Key, Digest>,
        entries: &[Entry],
    ) -> Result<bool> {
        self.ensure_operating()?;
        self.validate_recipients(entries)?;
        let context = self.registration.context.payment();
        let body = authorization.body();
        let rebound = VectorSendBody::new(
            context,
            body.payer().clone(),
            body.seq(),
            body.cumulative_debit(),
            body.send_root(),
        );
        if rebound != *body {
            return Ok(false);
        }
        let required =
            self.store
                .payment_requires_epoch_registration(context, authorization, entries)?;
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
        let mut staged = self.observe(std::slice::from_ref(&event))?;
        Ok(staged.pop().expect("one observed event stages one credit"))
    }

    /// Stages chain-confirmed deposit events observed from one finalized
    /// block, the operator's only deposit intake.
    ///
    /// The staged row keyed by deposit id is the idempotence key, so the
    /// at-least-once observation stream (marshal re-delivers any block whose
    /// acknowledgement was not durable) never double-credits: an event whose
    /// id is already staged is verified against its row and skipped. Every
    /// new event of the block commits in one transaction together with the
    /// boundary context the events chain to, so a crash stages either the
    /// whole block or none of it. Settlement already holds custody for each
    /// event, so no shape may be refused here: an aggregate exactly
    /// offsetting the carried withdrawal defers to the successor epoch
    /// instead, mirroring the chain's boundary rule. Returns the newly
    /// staged credits in event order.
    pub(crate) fn observe(&mut self, events: &[DepositEvent]) -> Result<Vec<StagedDeposit>> {
        self.ensure_operating()?;
        let mut registration = self.registration.clone();
        let mut batch = Vec::new();
        for event in events {
            if let Some(staged) = self.store.staged_deposit(&event.id)? {
                ensure!(
                    staged.account == event.account && staged.amount == event.amount,
                    "deposit id is bound to another event"
                );
                continue;
            }
            let identity = self
                .identities
                .iter()
                .find(|identity| identity.key == event.account)
                .context("deposit account is not a configured operator identity")?
                .clone();
            let replacement = registration_with_deposit(
                &self.protocol,
                &registration,
                identity.key.clone(),
                event.amount,
            )
            .context("prospective deposit does not fit the epoch anchor")?;
            batch.push(Staging {
                identity,
                event: event.clone(),
                replacement: replacement.context.payment().clone(),
            });
            registration = replacement;
        }
        if batch.is_empty() {
            return Ok(Vec::new());
        }
        self.ensure_balance_intake_horizon()?;
        let result = self
            .store
            .stage_deposits(self.registration.context.payment(), &batch);
        let staged = self.guard_store(result)?;
        self.registration = registration;
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
        let head = self.withdrawal_opening(request.account())?;
        request
            .verify_context(&self.protocol.deployment(), &head.root.digest)
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
        receiver: &Key,
    ) -> Result<ExternalPayoutEvidence> {
        self.ensure_store_usable()?;
        self.store.external_payout_evidence(receiver)
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

    /// The oldest cut epoch whose close has not durably finished.
    pub(crate) fn next_closing_epoch(&self) -> Result<Option<u64>> {
        self.ensure_store_usable()?;
        self.store.next_closing_epoch()
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

    /// Builds the signed chain registration for the live epoch, without
    /// mutating anything. The signature covers exactly the boundary material
    /// (execution assigns the deadlines at inclusion), so retries resubmit
    /// these exact bytes and a lost response replays into the permanent
    /// applied outcome.
    pub(crate) fn signed_registration(&self) -> Result<RegisterEpochRequest> {
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
        let signature = self.protocol.sign_chain_registration(
            epoch,
            predecessor_liability,
            &deposits_root,
            &staged_root,
            &withdrawals,
        );
        Ok(RegisterEpochRequest {
            deployment: self.protocol.deployment(),
            epoch,
            predecessor_liability,
            deposits_root,
            staged_root,
            withdrawals,
            openings,
            signature,
        })
    }

    /// Adopts the chain-assigned registration for the live epoch from its
    /// certified record: rebuilds the epoch context at the assigned deadlines
    /// (moving the payment anchor with it), persists them with the context
    /// transition, and swaps the live registration. Payers signed under the
    /// placeholder context learn the move from the corrective rejection.
    ///
    /// Idempotent for a record already adopted, so a restart between the
    /// registration's submission and this read-back recovers by re-reading
    /// the same certified record.
    pub(crate) fn adopt_registration(&mut self, record: &RegistrationRecord) -> Result<()> {
        self.ensure_operating()?;
        let epoch = self.registration.context.payment().epoch();
        ensure!(
            record.epoch == epoch,
            "the certified registration record is not the live epoch"
        );
        if let Some(adopted) = self.store.chain_deadlines(epoch)? {
            ensure!(
                adopted == (record.admission_deadline, record.challenge_deadline),
                "the adopted deadlines diverged from the certified registration"
            );
            ensure!(
                self.registration.context.payment().anchor() == &record.anchor,
                "the adopted context diverged from the certified registration"
            );
            return Ok(());
        }
        let replacement = self.protocol.registration_at(
            epoch,
            staged_deposits(&self.registration)?,
            self.registration.withdrawals.clone(),
            self.registration.context.predecessor_liability(),
            record.admission_deadline,
            record.challenge_deadline,
        )?;
        ensure!(
            replacement.context.payment().anchor() == &record.anchor,
            "the rebuilt context does not match the certified registration"
        );
        let adopted = self.store.adopt_deadlines(
            epoch,
            self.registration.context.payment(),
            replacement.context.payment(),
            record.admission_deadline,
            record.challenge_deadline,
        );
        self.guard_store(adopted)?;
        self.registration = replacement;
        Ok(())
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

    fn validate_recipients(&self, entries: &[Entry]) -> Result<()> {
        for entry in entries {
            ensure!(
                entry.recipient == self.external.key
                    || self
                        .identities
                        .iter()
                        .any(|identity| identity.key == entry.recipient),
                "payment receiver is neither a registered account nor the configured external receiver"
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
        let pipeline = self.pipeline.clone();
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
                    .and_then(|prepared| {
                        // Without a pipeline (the test and harness path) the
                        // close certifies through the in-process simulation
                        // and completes locally.
                        let Some(pipeline) = &pipeline else {
                            return protocol.complete(prepared, &mut rng);
                        };

                        // Distributed certification: assemble and disseminate
                        // the per-validator dealings over the DA channel,
                        // assemble the exact-quorum certificate from the
                        // returned votes, then submit the certified close and
                        // complete once the local certified state finalized
                        // the exact batch.
                        let deal_start = Instant::now();
                        let slices = protocol.slices(&prepared)?;
                        let dealings = protocol.dealings(&prepared, &slices)?;
                        let deal_micros = deal_start.elapsed().as_micros();
                        let seal_start = Instant::now();
                        let dealing_slices = dealings.iter().map(Vec::len).sum();
                        let header = prepared.close().header;
                        let roots = prepared.close().roots;
                        let certificate = pipeline.certify(epoch, header, roots, dealings)?;
                        let seal_micros = seal_start.elapsed().as_micros();
                        let result = protocol.certify(
                            prepared,
                            slices.len(),
                            dealing_slices,
                            certificate,
                            deal_micros,
                            seal_micros,
                        )?;
                        pipeline.admit(
                            AdmitRequest::from(&result),
                            result.finalized,
                            result.roots.change,
                        )?;
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

    /// Resumes the registered-but-uncut live epoch after a restart, returning
    /// the started close when the cut resumed.
    ///
    /// A certified registration's admission deadline keeps running while the
    /// operator is down, and only its admitted close consumes it. Once the
    /// chain-assigned deadlines are adopted the cut is fully determined, so
    /// startup starts the close itself instead of waiting for an agent RPC
    /// that may come after the runway expired. A fenced or recovering
    /// operator skips the resume: it cannot cut, and its fault already
    /// surfaces on every close-facing call.
    pub(crate) fn resume_registered_close(&mut self) -> Result<Option<CloseStarted>> {
        self.ensure_store_usable()?;
        if self.ensure_operating().is_err() {
            return Ok(None);
        }
        let epoch = self.registration.context.payment().epoch();
        if self.store.chain_deadlines(epoch)?.is_none()
            || !self.store.has_current_work()?
            || self.close_already_started(epoch)?
        {
            return Ok(None);
        }
        self.validate_close_start(epoch)?;
        self.start_close(epoch).map(Some)
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

    /// Test-only synchronous close pipeline: prepares the live epoch's close,
    /// rotates to the successor, completes and records the close, and returns
    /// the result for chain admission by the caller.
    #[cfg(test)]
    pub(crate) fn complete_close(&mut self, seed: u64) -> Result<SettlementResult> {
        let epoch = self.registration.context.payment().epoch();
        let data = self.store.load_current()?;
        let prepared = prepare_epoch(&self.protocol, data, self.registration.clone())?;
        let next_epoch = self.next_openable_epoch()?;
        let successor = self.protocol.registration(
            next_epoch,
            self.registration.deferred.clone(),
            WithdrawalBatch::empty(),
            self.store.successor_liability()?,
        )?;
        self.store.rotate_epoch(
            epoch,
            self.registration.context.payment(),
            &successor.context,
        )?;
        self.registration = successor;
        self.reload_predecessor()?;
        let result = self
            .protocol
            .complete(prepared, &mut commonware_utils::TestRng::new(seed))?;
        self.store.finish_close(&result, self.genesis_root)?;
        Ok(result)
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

    // An epoch that registered on the chain rebuilds under the chain-assigned
    // absolute deadlines it adopted from the certified registration record.
    // An epoch that never registered rebuilds under the deterministic
    // placeholder deadlines its contexts were staged with.
    let liability = predecessor_liability(data)?;
    let registration = match data.deadlines {
        Some((admission_deadline, challenge_deadline)) => protocol.registration_at(
            data.epoch,
            staged,
            withdrawals,
            liability,
            admission_deadline,
            challenge_deadline,
        )?,
        None => protocol.registration(data.epoch, staged, withdrawals, liability)?,
    };

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

    // Boundary moves preserve the context's deadlines: only the chain
    // assigns them, at the registration's inclusion height.
    protocol.registration_at(
        current.context.payment().epoch(),
        staged,
        current.withdrawals.clone(),
        current.context.predecessor_liability(),
        current.context.admission_deadline(),
        current.context.challenge_deadline(),
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

    // Boundary moves preserve the context's deadlines: only the chain
    // assigns them, at the registration's inclusion height.
    protocol.registration_at(
        current.context.payment().epoch(),
        staged_deposits(current)?,
        withdrawals,
        current.context.predecessor_liability(),
        current.context.admission_deadline(),
        current.context.challenge_deadline(),
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
    /// Out vectors aligned one-for-one with `rows`.
    vectors: Vec<OutVector<Key>>,
    /// Aggregable operator countersignatures aligned one-for-one with `rows`.
    signatures: Vec<Option<OperatorSignature>>,
    /// The global recipient-major transpose.
    transpose: Vec<TransposeEntry<Key>>,
    successor: Vec<StateLeaf<Key>>,
}

/// Signs `deltas` from `wallet` against `endpoint`, merging them into its cumulative
/// out vector under `context`.
#[cfg(test)]
pub(crate) fn sign_send_at(
    context: &PaymentContext<Key, Digest>,
    wallet: &Wallet,
    endpoint: &Endpoint,
    deltas: &[(Key, u64)],
) -> Result<(SendAuthorization<Key, Digest>, Vec<Entry>)> {
    let mut merged = endpoint.entries.clone();
    let mut entries = Vec::with_capacity(deltas.len());
    let mut total = 0_u64;
    for (recipient, amount) in deltas.iter().cloned() {
        total = total.checked_add(amount).context("delta total overflow")?;
        match merged.binary_search_by(|edge| edge.recipient.cmp(&recipient)) {
            Ok(position) => {
                merged[position].cumulative = merged[position]
                    .cumulative
                    .checked_add(amount)
                    .context("edge cumulative overflow")?;
                merged[position].count = merged[position]
                    .count
                    .checked_add(1)
                    .context("edge count overflow")?;
            }
            Err(position) => merged.insert(
                position,
                OutEntry {
                    recipient: recipient.clone(),
                    cumulative: amount,
                    count: 1,
                },
            ),
        }
        entries.push(Entry { recipient, amount });
    }
    entries.sort_unstable_by(|left, right| left.recipient.cmp(&right.recipient));
    let vector = OutVector::new(context.epoch(), wallet.public_key(), merged)
        .context("assemble signed out vector")?;
    let body = VectorSendBody::new(
        context,
        wallet.public_key(),
        endpoint.seq.checked_add(1).context("sequence overflow")?,
        endpoint
            .cumulative_debit
            .checked_add(total)
            .context("endpoint overflow")?,
        vector
            .root::<Sha256, Digest>()
            .context("commit signed out vector")?,
    );
    Ok((SendAuthorization::sign(body, wallet.signer()), entries))
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
        !data.acks.is_empty() || !data.deposits.is_empty() || !data.withdrawals.is_empty(),
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
        assembled.vectors,
        assembled.signatures,
        assembled.transpose,
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
    let context = registration.context.payment();
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

    // Replay the acknowledgment chain in canonical database order: contiguous epoch-local
    // sequences per payer, a strictly advancing lifetime debit endpoint, and both
    // countersignatures on every accepted body. These checks bind every mutable cache
    // field back to the immutable acknowledgment log before any recovered operator action
    // is allowed.
    let mut terminals = BTreeMap::<Key, (Ack, OperatorSignature)>::new();
    let mut endpoints = BTreeMap::<Key, (u64, u64)>::new();
    let mut batches = BTreeMap::<(Key, u64), (VectorRoot<Digest>, u64)>::new();
    for stored in &data.acks {
        let body = stored.ack.body();
        let payer = body.payer().clone();
        let account = accounts
            .get(&payer)
            .context("stored acknowledgment payer is not registered")?;
        stored
            .ack
            .verify(context)
            .context("verify stored acknowledgment")?;
        verify_message::<OperatorVariant>(
            protocol.operator_ack_key(),
            VECTOR_ACK_AGGREGATE_NAMESPACE,
            body.encode().as_ref(),
            &stored.aggregate,
        )
        .map_err(|_| anyhow::anyhow!("stored aggregate countersignature is invalid"))?;
        let (prior_seq, prior_debit) = endpoints
            .get(&payer)
            .copied()
            .unwrap_or((0, account.predecessor.cumulative_debit));
        let expected_seq = prior_seq
            .checked_add(1)
            .context("batch sequence overflow")?;
        ensure!(
            body.seq() == expected_seq,
            "stored acknowledgment sequence is not consecutive"
        );
        let delta = body
            .cumulative_debit()
            .checked_sub(prior_debit)
            .filter(|delta| *delta > 0)
            .context("stored acknowledgment endpoint did not advance")?;
        batches.insert((payer.clone(), body.seq()), (body.send_root(), delta));
        endpoints.insert(payer.clone(), (body.seq(), body.cumulative_debit()));
        terminals.insert(payer, (stored.ack.clone(), stored.aggregate));
    }

    // Replay the serving log against the acknowledged batches: every entry advances its
    // edge by exactly its delta, opens under its batch's acknowledged root, and each
    // batch's deltas sum to its endpoint advance.
    let mut edges = BTreeMap::<(Key, Key), (u64, u64)>::new();
    let mut credited = BTreeMap::<(Key, u64), u64>::new();
    let mut cursor = 0_u64;
    for stored in &data.entries {
        ensure!(
            stored.sequence > cursor,
            "stored entry cursor is not increasing"
        );
        cursor = stored.sequence;
        let key = (stored.payer.clone(), stored.seq);
        let (send_root, _) = batches
            .get(&key)
            .context("stored entry has no acknowledged batch")?;
        ensure!(
            stored.recipient != stored.payer,
            "stored entry credits its own payer"
        );
        ensure!(
            stored.external == !accounts.contains_key(&stored.recipient),
            "stored receiver classification is inconsistent"
        );
        let edge = edges
            .entry((stored.payer.clone(), stored.recipient.clone()))
            .or_insert((0, 0));
        ensure!(
            stored.amount > 0
                && Some(stored.cumulative) == edge.0.checked_add(stored.amount)
                && Some(stored.count) == edge.1.checked_add(1),
            "stored entry endpoint is not consecutive"
        );
        let entry = OutEntry {
            recipient: stored.recipient.clone(),
            cumulative: stored.cumulative,
            count: stored.count,
        };
        stored
            .opening
            .verify::<Sha256>(VectorKind::OutEntry, send_root, entry.encode().as_ref())
            .map_err(|_| anyhow::anyhow!("stored entry opening does not authenticate"))?;
        *edge = (stored.cumulative, stored.count);
        let sum = credited.entry(key).or_insert(0);
        *sum = sum
            .checked_add(stored.amount)
            .context("batch credit overflow")?;
    }
    for (key, (_, delta)) in &batches {
        ensure!(
            credited.get(key) == Some(delta),
            "stored batch entries do not sum to its endpoint advance"
        );
    }

    // The edge table is a cache used on the online payment path. Exact comparison keeps a
    // corrupt cache from acknowledging a vector the immutable serving log cannot justify.
    ensure!(
        data.edges.len() == edges.len(),
        "stored edge count is inconsistent"
    );
    for (stored, ((payer, recipient), (cumulative, count))) in data.edges.iter().zip(&edges) {
        ensure!(
            &stored.payer == payer
                && &stored.entry.recipient == recipient
                && stored.entry.cumulative == *cumulative
                && stored.entry.count == *count,
            "stored edge endpoint is inconsistent"
        );
    }

    // Collate per-account activity, per-payer outgoing vectors, and per-recipient
    // transpose groups from the replayed edges. Payer-major iteration keeps every
    // outgoing vector recipient-sorted and every incoming group payer-sorted.
    let mut activity = BTreeMap::<Key, AccountActivity>::new();
    let mut outgoing = BTreeMap::<Key, Vec<OutEntry<Key>>>::new();
    let mut incoming = BTreeMap::<Key, Vec<TransposeEntry<Key>>>::new();
    for ((payer, recipient), (cumulative, count)) in &edges {
        let payer_activity = activity.entry(payer.clone()).or_default();
        payer_activity.debit = payer_activity
            .debit
            .checked_add(*cumulative)
            .context("payer debit overflow")?;
        let receiver_activity = activity.entry(recipient.clone()).or_default();
        receiver_activity.credit = receiver_activity
            .credit
            .checked_add(*cumulative)
            .context("receiver credit overflow")?;
        receiver_activity.receipts = receiver_activity
            .receipts
            .checked_add(*count)
            .context("receiver receipt count overflow")?;
        outgoing.entry(payer.clone()).or_default().push(OutEntry {
            recipient: recipient.clone(),
            cumulative: *cumulative,
            count: *count,
        });
        incoming
            .entry(recipient.clone())
            .or_default()
            .push(TransposeEntry {
                recipient: recipient.clone(),
                payer: payer.clone(),
                cumulative: *cumulative,
                count: *count,
            });
    }

    // Every terminal endpoint must equal its replayed edge total, and every debiting
    // account must hold a terminal acknowledgment.
    for (payer, (_, debit)) in &endpoints {
        let advance = activity.get(payer).map_or(0, |totals| totals.debit);
        let account = accounts
            .get(payer)
            .context("stored acknowledgment payer is not registered")?;
        ensure!(
            Some(*debit) == account.predecessor.cumulative_debit.checked_add(advance),
            "stored acknowledgment endpoint differs from its edges"
        );
    }
    for (account, totals) in &activity {
        if totals.debit > 0 {
            ensure!(
                endpoints.contains_key(account),
                "stored edges have no acknowledged sender"
            );
        }
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

    // The same replay produces the canonical changed rows, aligned out vectors, aggregable
    // countersignatures, transpose, and cumulative prefixes consumed by root preparation
    // and validator dealings.
    let mut prefix = Prefix::default();
    let mut rows = Vec::with_capacity(changed.len());
    let mut vectors = Vec::with_capacity(changed.len());
    let mut signatures = Vec::with_capacity(changed.len());
    let mut transpose = Vec::new();
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
        let out = outgoing.remove(&account).unwrap_or_default();
        let (vector, outgoing_send, signature) = match terminals.get(&account) {
            Some((ack, aggregate)) => {
                let vector = OutVector::new(data.epoch, account.clone(), out)
                    .context("assemble stored out vector")?;
                let root = vector
                    .root::<Sha256, Digest>()
                    .context("commit stored out vector")?;
                ensure!(
                    root == ack.body().send_root(),
                    "stored out vector does not match its acknowledged root"
                );
                let send = SendAuthorization::from_raw_unchecked(
                    ack.body().clone(),
                    ack.payer_signature().clone(),
                );
                (vector, Some(send), Some(*aggregate))
            }
            None => (OutVector::empty(data.epoch, account.clone()), None, None),
        };
        let group = incoming.remove(&account).unwrap_or_default();
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
                out_count: u64::try_from(vector.entries().len())
                    .context("out-entry count does not fit u64")?,
                in_count: u64::try_from(group.len())
                    .context("transpose entry count does not fit u64")?,
            })
            .context("close prefix overflow")?;
        rows.push(AccountRow {
            account: account.clone(),
            predecessor,
            successor,
            outgoing: outgoing_send,
            output,
            prefix,
        });
        vectors.push(vector);
        signatures.push(signature);
        transpose.extend(group);
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
        vectors,
        signatures,
        transpose,
        successor,
    })
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
