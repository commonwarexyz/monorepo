//! The wallet core: identity, durable state, verified head reads, and close control.

use super::{
    custody::initial_deposit_nonce,
    evidence::{Holders, unusable_head},
    pay::operator_head,
    store::{ContextCache, IncomingSummary, PendingPayment, PendingWithdrawalClaim, State, Store},
};
use crate::{
    chain::{
        client::{Chain, Client, Env},
        state::{AdmittedRootsResponse, FaultRecord, HardFaultReasonResponse, StatusRecord},
    },
    operator::rpc as operator_rpc,
    protocol::{AccountIdentity, Key, Wallet, eve_identity, eve_wallet, identities, wallets},
};
use anyhow::{Context, Result, ensure};
use commonware_clearing::bajillion::{
    boundary::SignedWithdrawal, custody::Source, payment::PaymentContext, qmdb::StateOpening,
};
use commonware_cryptography::sha256::Digest;
use commonware_runtime::{Clock, Network};
use std::{collections::BTreeSet, net::SocketAddr, path::Path};

/// An agent owns one payer key and retains the receipts returned by the operator.
///
/// Durable state follows one discipline. It holds only what this wallet alone can
/// produce: its signed sends, its signed withdrawal requests, and its deposit identities.
/// The exceptions are proofs that must survive counterparty death, namely the frozen-root
/// recovery openings, cached claim evidence, and the receiver's held incoming receipts. A
/// held incoming receipt is a self-verified dual-signed entry crediting this wallet: like
/// the recovery openings it is irreplaceable once the operator is gone, so it is retained,
/// never an overwritable cache. Everything the counterparty can reproduce is a cache and
/// never gates progress.
///
/// Cached contexts and verified balance floors keep successful payments local until submission.
/// Accepted debit, sequence, and vector state belong to their exact epoch and anchor.
/// A corrective reply cannot replace an ambiguous authorization; settlement resolves it first.
///
/// Frozen-root recovery requires an opening at the last finalized root, which advances
/// with every finalization by anyone. Openings refresh on every head read or balance
/// poll; a passive wallet fetches the frozen root through the validators' retained state.
///
/// The operator is the fast path for every read and the only path for accepting a send or
/// applying a withdrawal. Every enforcement flow completes without it: heads, floors, and
/// balances come from Current proofs at certified state roots, while payment outcomes,
/// committed entries, and claims come from authenticated epoch activity. The signing
/// context comes from the chain's own registration. Every proof binds its certified root.
///
/// Incoming credit requires a durably held receipt acquired while its preconfirmation
/// remains live, or verified coverage in its finalized close. Live preconfirmations depend
/// on the holder obtaining evidence and including a challenge within the native window.
/// Reconciliation retains that obligation for previously held receipts.
pub(crate) struct Agent {
    pub(super) wallet: Wallet,
    /// The clearing key authenticated by this deployment's registry entry.
    pub(super) operator: Key,
    /// The deployment this agent transacts on: every settlement expectation
    /// (status deployment, payment-context operator, deposit naming) is
    /// checked against it.
    pub(super) deployment: Digest,
    pub(super) store: Store,
    pub(super) receivers: Vec<AccountIdentity>,
    pub(super) deposit_nonce: u64,
    /// Durable optimistic signing state: the cached operator-served context and its
    /// verified affordability floor. Absent for a fresh wallet and after invalidation.
    pub(super) cache: Option<ContextCache>,
    pub(super) pending_payment: Option<PendingPayment>,
    pub(super) pending_deposit: Option<crate::chain::tx::DepositRequest>,
    pub(super) pending_transfer: Option<crate::chain::tx::NativeTransferRequest>,
    pub(super) pending_withdrawal: Option<SignedWithdrawal<Key, Digest>>,
    pub(super) pending_withdrawal_claim: Option<PendingWithdrawalClaim>,
    pub(super) pending_close_epoch: Option<u64>,
    pub(super) receipt_count: u64,
    /// Receiver intake ledger summary and durable fetch cursor.
    pub(super) incoming: IncomingSummary,
    /// Highest epoch whose held credits reconciled cleanly against the committed close.
    pub(super) last_reconciled_epoch: Option<u64>,
    /// Finalized epochs whose committed evidence the operator is currently withholding, latched
    /// so the alarm is reported once per stretch of withholding.
    pub(super) withheld: BTreeSet<u64>,
    /// The wallet's route to validator-served evidence: the validators each
    /// enforcement flow falls back to when the operator is unreachable or refuses.
    pub(super) holders: Holders,
}

impl Agent {
    /// An in-memory agent bound to the compiled default deployment.
    #[cfg(test)]
    pub(crate) fn new(identity: usize) -> Result<Self> {
        Self::new_for(
            identity,
            crate::protocol::deployment(),
            crate::protocol::operator_key(),
        )
    }

    /// An in-memory agent bound to this deployment and its authenticated operator.
    #[cfg(test)]
    pub(crate) fn new_for(identity: usize, deployment: Digest, operator: Key) -> Result<Self> {
        let (wallet, receivers) = Self::identity(identity)?;
        let account = wallet.public_key();
        let (store, state) = Store::in_memory(&account, &deployment, &operator)?;
        Ok(Self::from_state(
            wallet,
            operator,
            deployment,
            receivers,
            store,
            state,
            initial_deposit_nonce(),
        ))
    }

    /// A durable agent bound to the compiled default deployment.
    #[cfg(test)]
    pub(crate) fn open(path: &Path, identity: usize) -> Result<Self> {
        Self::open_for(
            path,
            identity,
            crate::protocol::deployment(),
            crate::protocol::operator_key(),
        )
    }

    /// A durable agent bound to this deployment and its authenticated operator.
    /// The store rejects reopening under a different binding.
    pub(crate) fn open_for(
        path: &Path,
        identity: usize,
        deployment: Digest,
        operator: Key,
    ) -> Result<Self> {
        let (wallet, receivers) = Self::identity(identity)?;
        let account = wallet.public_key();
        let (store, state) = Store::open(path, &account, &deployment, &operator)?;
        Ok(Self::from_state(
            wallet,
            operator,
            deployment,
            receivers,
            store,
            state,
            initial_deposit_nonce(),
        ))
    }

    fn identity(identity: usize) -> Result<(Wallet, Vec<AccountIdentity>)> {
        let mut wallets = wallets();
        ensure!(identity <= wallets.len(), "agent identity is out of range");
        let wallet = if identity == wallets.len() {
            eve_wallet()
        } else {
            wallets.remove(identity)
        };
        let mut receivers = identities();
        receivers.push(eve_identity());
        Ok((wallet, receivers))
    }

    fn from_state(
        wallet: Wallet,
        operator: Key,
        deployment: Digest,
        receivers: Vec<AccountIdentity>,
        store: Store,
        state: State,
        deposit_nonce: u64,
    ) -> Self {
        Self {
            wallet,
            operator,
            deployment,
            store,
            receivers,
            deposit_nonce,
            cache: state.cache,
            pending_payment: state.pending_payment,
            pending_deposit: state.pending_deposit,
            pending_transfer: state.pending_transfer,
            pending_withdrawal: state.pending_withdrawal,
            pending_withdrawal_claim: state.pending_withdrawal_claim,
            pending_close_epoch: None,
            receipt_count: state.receipt_count,
            incoming: state.incoming,
            last_reconciled_epoch: state.last_reconciled_epoch,
            withheld: BTreeSet::new(),
            holders: Holders::default(),
        }
    }

    pub(crate) const fn name(&self) -> &'static str {
        self.wallet.name
    }

    pub(crate) fn account(&self) -> Key {
        self.wallet.public_key()
    }

    /// The clearing key of the operator this agent is bound to.
    pub(crate) fn operator(&self) -> Key {
        self.operator.clone()
    }

    /// Whether a withdrawal-claim intent from an interrupted run is still open.
    pub(crate) const fn has_pending_withdrawal_claim(&self) -> bool {
        self.pending_withdrawal_claim.is_some()
    }

    pub(crate) const fn receiver_count(&self) -> usize {
        self.receivers.len()
    }

    /// Returns the first selectable receiver that is not this wallet.
    pub(crate) fn default_receiver(&self) -> usize {
        let account = self.account();
        self.receivers
            .iter()
            .position(|identity| identity.key != account)
            .expect("the demo receiver list is larger than one wallet")
    }

    pub(crate) fn receiver_name(&self, index: usize) -> &'static str {
        self.receivers[index % self.receivers.len()].name
    }

    pub(crate) const fn receipt_count(&self) -> u64 {
        self.receipt_count
    }

    /// Rejects further work after a failed wallet storage mutation.
    pub(crate) fn ensure_store_usable(&self) -> Result<()> {
        self.store.ensure_usable()
    }

    /// Returns the receiver's verified incoming ledger summary.
    pub(crate) const fn incoming(&self) -> IncomingSummary {
        self.incoming
    }

    /// Returns the highest epoch whose held credits reconciled with the committed close.
    pub(crate) const fn last_reconciled_epoch(&self) -> Option<u64> {
        self.last_reconciled_epoch
    }

    /// Whether this wallet durably holds the exact verified, anchored receipt.
    pub(crate) fn has_receipt(&self, payer: &Key, id: &Digest) -> Result<bool> {
        self.store.has_receipt(payer, id)
    }

    /// The exact unresolved send survives restarts and can only be retried or resolved.
    pub(crate) const fn has_pending_payment(&self) -> bool {
        self.pending_payment.is_some()
    }

    pub(crate) async fn operator_status<E: Network + Clock>(
        &self,
        network: &E,
        operator: SocketAddr,
    ) -> Result<operator_rpc::StatusResponse> {
        operator_rpc::status(network, operator).await
    }

    /// Reads the account head against its finalized or admitted predecessor root.
    ///
    /// The operator's head is the fast path: it carries the live balance and the
    /// signing context to re-cache. When the operator is unreachable or its head fails
    /// verification, the validators open the wallet's leaf at the certified head
    /// instead and the finalized balance is reported, so the poll never depends on the
    /// operator.
    ///
    /// Polling doubles as the passive wallet's retention heartbeat: the verified head
    /// opening is retained through [`Self::verify_head`] or [`Self::retain_head`], so a
    /// wallet that only watches its balance still refreshes its frozen-root recovery
    /// evidence and, from an operator head, re-anchors its optimistic signing state.
    /// Payments use the cached context. A corrective rejection triggers authenticated
    /// resolution of the exact pending intent before a new context can be used.
    pub(crate) async fn balance<E: Env>(
        &mut self,
        ctx: &E,
        chain: &mut Client,
        operator: SocketAddr,
    ) -> Result<u64> {
        let operator_error =
            match operator_head(ctx, operator, self.account(), &self.operator).await {
                Ok(head) => {
                    let status = settlement_status(ctx, chain, self.deployment)
                        .await
                        .context("read settlement balance head")?;
                    match self.verify_head(ctx, chain, &head, &status).await {
                        Ok(()) => return Ok(head.balance),
                        Err(error) => error,
                    }
                }
                Err(error) => error,
            };
        let (_, opening) = self
            .validator_head(ctx, chain)
            .await
            .map_err(|error| unusable_head(operator_error, error))?;
        Ok(opening.map_or(0, |opening| opening.balance.get()))
    }

    /// Returns the operator-served account opening verified against the certified
    /// finalized root, together with the status that authenticates that root.
    pub(crate) async fn finalized_head<E: Env>(
        &mut self,
        ctx: &E,
        chain: &mut Client,
        operator: SocketAddr,
    ) -> Result<(StatusRecord, StateOpening<Key, Digest>)> {
        let head = operator_head(ctx, operator, self.account(), &self.operator).await?;
        let status = settlement_status(ctx, chain, self.deployment).await?;
        ensure!(
            status.state_root == head.root,
            "payer opening is not the exact finalized head"
        );
        self.verify_head(ctx, chain, &head, &status).await?;
        Ok((status, head.opening))
    }

    /// This wallet's leaf at the certified head, opened by the validators,
    /// verified against the status root, and retained: the head read that
    /// needs no operator.
    pub(super) async fn validator_head<E: Env>(
        &mut self,
        ctx: &E,
        chain: &mut Client,
    ) -> Result<(StatusRecord, Option<StateOpening<Key, Digest>>)> {
        let status = settlement_status(ctx, chain, self.deployment)
            .await
            .context("read settlement head")?;
        let account = self.account();
        let opening = self
            .holders
            .validator_balance(ctx, chain, &account, &status)
            .await?;
        if let Some(opening) = &opening {
            self.retain_head(&status.state_root, opening)?;
        }
        Ok((status, opening))
    }

    pub(crate) async fn start_close<E: Network + Clock>(
        &mut self,
        network: &E,
        operator: SocketAddr,
    ) -> Result<operator_rpc::StartCloseResponse> {
        let expected_epoch = match self.pending_close_epoch {
            Some(epoch) => epoch,
            None => {
                let epoch = operator_rpc::status(network, operator).await?.epoch;
                self.pending_close_epoch = Some(epoch);
                epoch
            }
        };
        let started = operator_rpc::start_close(network, operator, expected_epoch).await?;
        ensure!(
            started.epoch == expected_epoch,
            "operator started another close epoch"
        );
        self.pending_close_epoch = None;
        Ok(started)
    }

    pub(crate) async fn poll_close<E: Network + Clock>(
        &mut self,
        network: &E,
        operator: SocketAddr,
        epoch: u64,
    ) -> Result<operator_rpc::PollCloseResponse> {
        operator_rpc::poll_close(network, operator, epoch).await
    }
}

/// The certified status singleton, checked to name `deployment`, the one the
/// wallet is bound to.
pub(super) async fn settlement_status<E: Env>(
    ctx: &E,
    chain: &mut Client,
    deployment: Digest,
) -> Result<StatusRecord> {
    let status = chain.status(ctx).await?;
    ensure!(
        status.deployment == deployment,
        "settlement status has an unexpected deployment"
    );
    Ok(status)
}

/// Certified settlement permissions for acquiring a receipt under one payment context.
pub(super) enum ReceiptEpoch {
    /// Registration or admission is not visible enough to decide; retain the exact intent.
    Unresolved,
    /// The native challenge window remains live, with an optional immutable admitted close.
    Live(Option<AdmittedRootsResponse>),
    /// Coverage must be verified under this source authenticated at paired finalized heads.
    Finalized(Box<Source<Key, Digest>>),
    /// The published fault does not establish whether this nonfinal admitted close survives.
    Faulted(AdmittedRootsResponse),
    /// The context can never settle: its anchor conflicts, it never admitted, or it was invalidated.
    Invalidated,
}

/// Classifies new receipt reliance using monotonic certified reads of native settlement.
pub(super) async fn receipt_epoch<E: Env>(
    ctx: &E,
    chain: &mut Client,
    deployment: Digest,
    context: &PaymentContext<Key, Digest>,
) -> Result<ReceiptEpoch> {
    ensure!(
        chain.deployment() == deployment,
        "settlement client has an unexpected deployment"
    );
    let epoch = context.epoch();
    let anchor = match chain.anchor(ctx, epoch).await {
        Ok(anchor) => anchor,
        Err(anchor_error) => {
            return match finalized_receipt_source(ctx, chain, deployment, context).await {
                Ok(Some(verdict)) => Ok(verdict),
                Ok(None) => Err(anchor_error),
                Err(source_error) => Err(source_error
                    .context(format!("receipt anchor is unavailable ({anchor_error:#})"))),
            };
        }
    };
    match anchor {
        Some(anchor) if anchor != *context.anchor() => return Ok(ReceiptEpoch::Invalidated),
        None => {
            let status = chain.recent_status(ctx).await?;
            let registration = chain.registration(ctx).await?;
            if status.hard_faulted
                || status.last_finalized.is_some_and(|last| last >= epoch)
                || registration.is_some_and(|registered| registered.epoch > epoch)
            {
                // The absence must follow the permanent boundary, since a registration
                // can become visible between the initial anchor and boundary reads.
                if let Some(verdict) =
                    finalized_receipt_source(ctx, chain, deployment, context).await?
                {
                    return Ok(verdict);
                }
                return Ok(match chain.anchor(ctx, epoch).await? {
                    Some(anchor) if anchor == *context.anchor() => ReceiptEpoch::Unresolved,
                    _ => ReceiptEpoch::Invalidated,
                });
            }
            return Ok(ReceiptEpoch::Unresolved);
        }
        Some(_) => {}
    }

    let admitted = chain.admitted(ctx, epoch).await?;
    if let Some(record) = admitted
        && record.finalized
    {
        return finalized_receipt_source(ctx, chain, deployment, context)
            .await?
            .context("finalized source is not visible yet");
    }
    let registration = if admitted.is_none() {
        chain.registration(ctx).await?
    } else {
        None
    };
    let status = chain.recent_status(ctx).await?;
    if status.hard_faulted {
        let fault = chain
            .fault(ctx)
            .await?
            .context("settlement fault is not visible yet")?;

        // Admission absence after the permanent fault proves the context never can admit.
        // An earlier absence could have preceded a successful admission and must be retried.
        let Some(record) = chain.admitted(ctx, epoch).await? else {
            return Ok(ReceiptEpoch::Invalidated);
        };
        if record.finalized {
            return finalized_receipt_source(ctx, chain, deployment, context)
                .await?
                .context("finalized source is not visible yet");
        }
        if invalidated_epoch(ctx, chain, epoch, &status, &fault).await? {
            return Ok(ReceiptEpoch::Invalidated);
        }
        return Ok(ReceiptEpoch::Faulted(record));
    }
    if status.last_finalized.is_some_and(|last| last >= epoch) {
        return finalized_receipt_source(ctx, chain, deployment, context)
            .await?
            .context("finalized source is not visible yet");
    }

    // Native admission deadlines strictly increase, challenge duration is fixed, and each
    // sequential block finalizes the ready front. A healthy nonfinal admitted close
    // therefore still has a live challenge window, even after its successor registers.
    if admitted.is_some() {
        return Ok(ReceiptEpoch::Live(admitted));
    }
    if registration.is_some_and(|registered| {
        registered.epoch == epoch
            && registered.anchor == *context.anchor()
            && registered.admitted.is_none()
            && status.height <= registered.admission_deadline
    }) {
        return Ok(ReceiptEpoch::Live(None));
    }
    Ok(ReceiptEpoch::Unresolved)
}

/// Resolves finalized receipt authority directly from one paired native checkpoint.
async fn finalized_receipt_source<E: Env>(
    ctx: &E,
    chain: &mut Client,
    deployment: Digest,
    context: &PaymentContext<Key, Digest>,
) -> Result<Option<ReceiptEpoch>> {
    let (status, tip) = chain.payout_checkpoint(ctx).await?;
    ensure!(
        status.deployment == deployment && status.last_finalized == tip.finalized,
        "receipt checkpoint has another deployment or finalization boundary"
    );
    if !tip.finalized.is_some_and(|last| context.epoch() <= last) {
        return Ok(None);
    }
    let source = chain.source(ctx, context.epoch(), tip).await?;
    if source.context().payment() != context {
        return Ok(Some(ReceiptEpoch::Invalidated));
    }
    Ok(Some(ReceiptEpoch::Finalized(Box::new(source))))
}

/// Whether the published fault boundary permanently invalidates this nonfinal admitted epoch.
pub(super) async fn invalidated_epoch<E: Env>(
    ctx: &E,
    chain: &mut Client,
    epoch: u64,
    status: &StatusRecord,
    fault: &FaultRecord,
) -> Result<bool> {
    let batch_id = match fault {
        // Terminal settlement starts only after every surviving prefix close finalizes.
        FaultRecord::Settling(_) => return Ok(true),
        FaultRecord::Faulted(HardFaultReasonResponse::ProvenChallenge { batch_id, .. }) => {
            *batch_id
        }
        FaultRecord::Faulted(_) => return Ok(false),
    };
    let first = status
        .last_finalized
        .map_or(Some(0), |last| last.checked_add(1))
        .context("receipt epoch overflow")?;
    for candidate in first..=epoch {
        let record = chain
            .admitted(ctx, candidate)
            .await?
            .context("fault ancestry is not visible yet")?;
        if record.batch_id == batch_id {
            return Ok(true);
        }
    }
    Ok(false)
}
