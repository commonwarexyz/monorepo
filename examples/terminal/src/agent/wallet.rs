//! The wallet core: identity, durable state, verified head reads, and close control.

use super::{
    custody::initial_deposit_nonce,
    store::{
        ContextCache, IncomingCredit, IncomingSummary, PendingPayment, PendingPayoutClaim,
        PendingWithdrawalClaim, State, Store,
    },
};
use crate::{
    chain::client::{Chain, Client, Env},
    operator::rpc as operator_rpc,
    protocol::{
        AccountIdentity, DepositEvent, Key, Wallet, deployment_of, external_identity,
        external_wallet, identities, wallets,
    },
};
use anyhow::{Context, Result, ensure};
use commonware_clearing::bajillion::boundary::SignedWithdrawal;
use commonware_cryptography::sha256::Digest;
use commonware_runtime::Network;
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
/// The cached signing context follows the cache rule and exists precisely so that
/// ordinary payments need nothing beyond local SQL. The wallet's own durable cumulative
/// debit is the authoritative signing endpoint, the cached `(epoch, anchor)` is the
/// claimed context to bind, and the cached verified floor lower-bounds affordability.
/// When the operator has moved to a new context, the wallet learns it from the typed
/// corrective rejection its next send earns, never from a routine head read. The cache
/// steers only what gets signed: settlement's registration confirmation after
/// acceptance remains the trust anchor before anything is recorded.
///
/// Frozen-root recovery requires an opening retained at or refreshed to the last
/// finalized root, which advances with every finalization by anyone. Openings refresh on
/// every head read or balance poll, so only a wallet passive across the final finalization
/// holds none, and it then depends on the operator's survival to serve one.
///
/// As a receiver, this wallet may rely on a payment exactly when its verified receipt is
/// durably held. A balance that moved in the operator's head is an observation, not
/// reliance-grade: the enforceable preconfirmation is the held operator receipt, and
/// reconciliation later proves every finalized credit was backed by one.
pub(crate) struct Agent {
    pub(super) wallet: Wallet,
    /// The clearing key of the one operator this agent is bound to. The
    /// bound deployment digest derives from it.
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
    pub(super) pending_deposit: Option<DepositEvent>,
    pub(super) pending_withdrawal: Option<SignedWithdrawal<Key, Digest>>,
    pub(super) pending_withdrawal_claim: Option<PendingWithdrawalClaim>,
    pub(super) pending_payout_claim: Option<PendingPayoutClaim>,
    pub(super) pending_close_epoch: Option<u64>,
    pub(super) cumulative_debit: u64,
    pub(super) receipt_count: u64,
    /// Receiver intake ledger summary and durable fetch cursor.
    pub(super) incoming: IncomingSummary,
    /// Highest epoch whose held credits reconciled cleanly against the committed close.
    pub(super) last_reconciled_epoch: Option<u64>,
    /// Finalized epochs whose committed evidence the operator is currently withholding, latched
    /// so the alarm is reported once per stretch of withholding.
    pub(super) withheld: BTreeSet<u64>,
}

impl Agent {
    /// An in-memory agent bound to the compiled default deployment.
    #[cfg(test)]
    pub(crate) fn new(identity: usize) -> Result<Self> {
        Self::new_for(identity, crate::protocol::operator_key())
    }

    /// An in-memory agent bound to `operator`'s deployment.
    pub(crate) fn new_for(identity: usize, operator: Key) -> Result<Self> {
        let (wallet, receivers) = Self::identity(identity)?;
        let account = wallet.public_key();
        let deployment = deployment_of(&operator);
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
        Self::open_for(path, identity, crate::protocol::operator_key())
    }

    /// A durable agent bound to `operator`'s deployment. The store pins the
    /// binding, so reopening under another operator fails.
    pub(crate) fn open_for(path: &Path, identity: usize, operator: Key) -> Result<Self> {
        let (wallet, receivers) = Self::identity(identity)?;
        let account = wallet.public_key();
        let deployment = deployment_of(&operator);
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
            external_wallet()
        } else {
            wallets.remove(identity)
        };
        let mut receivers = identities();
        receivers.push(external_identity());
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
            pending_withdrawal: None,
            pending_withdrawal_claim: state.pending_withdrawal_claim,
            pending_payout_claim: state.pending_payout_claim,
            pending_close_epoch: None,
            cumulative_debit: state.cumulative_debit,
            receipt_count: state.receipt_count,
            incoming: state.incoming,
            last_reconciled_epoch: state.last_reconciled_epoch,
            withheld: BTreeSet::new(),
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
            .expect("the receiver roster is larger than one wallet")
    }

    pub(crate) fn receiver_name(&self, index: usize) -> &'static str {
        self.receivers[index % self.receivers.len()].name
    }

    pub(crate) const fn receipt_count(&self) -> u64 {
        self.receipt_count
    }

    /// Returns the receiver's verified incoming ledger summary.
    pub(crate) const fn incoming(&self) -> IncomingSummary {
        self.incoming
    }

    /// Returns the highest epoch whose held credits reconciled with the committed close.
    pub(crate) const fn last_reconciled_epoch(&self) -> Option<u64> {
        self.last_reconciled_epoch
    }

    /// Answers the receiver's service-accounting question: has `payer` paid this wallet under
    /// the batch identified by `id`, and for how much? The id is the digest of the
    /// payer-signed acknowledgment body, so it is the natural invoice reference. A hit means
    /// the credit's verified receipt is durably held, which is exactly the condition under
    /// which a receiver may rely on it.
    pub(crate) fn paid(&self, payer: &Key, id: &Digest) -> Result<Option<IncomingCredit>> {
        self.store.paid(payer, id)
    }

    pub(crate) async fn operator_status<E: Network>(
        &self,
        network: &E,
        operator: SocketAddr,
    ) -> Result<operator_rpc::StatusResponse> {
        operator_rpc::status(network, operator).await
    }

    /// Reads the live account head and verifies it against the certified state root.
    ///
    /// Polling doubles as the passive wallet's retention heartbeat: the verified head
    /// opening is retained through [`Self::verify_head`], so a wallet that only
    /// watches its balance still refreshes its frozen-root recovery evidence and
    /// re-anchors its optimistic signing state. This read is off the payment hot path:
    /// payments sign from the cached context and learn a moved context from the
    /// operator's corrective rejection instead.
    pub(crate) async fn balance<E: Env>(
        &mut self,
        ctx: &E,
        chain: &mut Client,
        operator: SocketAddr,
    ) -> Result<u64> {
        let head = operator_rpc::payment_head(
            ctx,
            operator,
            operator_rpc::PaymentHeadRequest {
                account: self.account(),
            },
        )
        .await
        .context("read payer state")?;
        ensure!(
            head.context.operator() == &self.operator,
            "payment context has an unexpected operator"
        );
        let status = chain
            .status(ctx)
            .await
            .context("read settlement balance head")?;
        ensure!(
            status.deployment == self.deployment,
            "settlement status has an unexpected deployment"
        );
        self.verify_head(&head, &status)?;
        Ok(head.state.balance)
    }

    pub(crate) async fn start_close<E: Network>(
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

    pub(crate) async fn poll_close<E: Network>(
        &mut self,
        network: &E,
        operator: SocketAddr,
        epoch: u64,
    ) -> Result<operator_rpc::PollCloseResponse> {
        operator_rpc::poll_close(network, operator, epoch).await
    }
}
