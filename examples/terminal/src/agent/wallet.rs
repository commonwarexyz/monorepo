//! The wallet core: identity, durable state, verified head reads, and close control.

use super::{
    custody::initial_deposit_nonce,
    store::{
        IncomingCredit, IncomingSummary, PendingPayment, PendingPayoutClaim,
        PendingWithdrawalClaim, State, Store,
    },
};
use crate::{
    operator::rpc as operator_rpc,
    protocol::{
        AccountIdentity, DepositEvent, Key, Wallet, deployment, external_identity, external_wallet,
        identities, operator_key, wallets,
    },
    settlement::rpc as settlement_rpc,
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
/// recovery openings, cached claim evidence, and the provider's held incoming pairs. A held
/// incoming pair is a self-verified (send, receipt) crediting this wallet: like the recovery
/// openings it is irreplaceable once the operator is gone, so it is retained, never an
/// overwritable cache. Everything the counterparty can reproduce is a cache and never gates
/// progress.
///
/// Frozen-root recovery requires an opening retained at or refreshed to the last
/// finalized root, which advances with every finalization by anyone. Openings refresh on
/// every quote or balance poll, so only a wallet passive across the final finalization
/// holds none, and it then depends on the operator's survival to serve one.
///
/// As a service provider, this wallet may rely on a payment exactly when its verified pair is
/// durably held. A quote balance that moved is an observation, not reliance-grade: the
/// enforceable preconfirmation is the held operator receipt, and reconciliation later proves
/// every finalized credit was backed by one.
pub(crate) struct Agent {
    pub(super) wallet: Wallet,
    pub(super) store: Store,
    pub(super) recipients: Vec<AccountIdentity>,
    pub(super) deposit_nonce: u64,
    pub(super) pending_payment: Option<PendingPayment>,
    pub(super) pending_deposit: Option<DepositEvent>,
    pub(super) pending_withdrawal: Option<SignedWithdrawal<Key, Digest>>,
    pub(super) pending_withdrawal_claim: Option<PendingWithdrawalClaim>,
    pub(super) pending_payout_claim: Option<PendingPayoutClaim>,
    pub(super) pending_close_epoch: Option<u64>,
    pub(super) cumulative_debit: u64,
    pub(super) receipt_count: u64,
    /// Provider intake ledger summary and durable fetch cursor.
    pub(super) incoming: IncomingSummary,
    /// Highest epoch whose held credits reconciled cleanly against the committed close.
    pub(super) last_reconciled_epoch: Option<u64>,
    /// Finalized epochs whose committed evidence the operator is currently withholding, latched
    /// so the alarm is reported once per stretch of withholding.
    pub(super) withheld: BTreeSet<u64>,
}

impl Agent {
    pub(crate) fn new(identity: usize) -> Result<Self> {
        let (wallet, recipients) = Self::identity(identity)?;
        let account = wallet.public_key();
        let (store, state) = Store::in_memory(&account, &deployment(), &operator_key())?;
        Ok(Self::from_state(
            wallet,
            recipients,
            store,
            state,
            initial_deposit_nonce(),
        ))
    }

    pub(crate) fn open(path: &Path, identity: usize) -> Result<Self> {
        let (wallet, recipients) = Self::identity(identity)?;
        let account = wallet.public_key();
        let (store, state) = Store::open(path, &account, &deployment(), &operator_key())?;
        Ok(Self::from_state(
            wallet,
            recipients,
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
        let mut recipients = identities();
        recipients.push(external_identity());
        Ok((wallet, recipients))
    }

    fn from_state(
        wallet: Wallet,
        recipients: Vec<AccountIdentity>,
        store: Store,
        state: State,
        deposit_nonce: u64,
    ) -> Self {
        Self {
            wallet,
            store,
            recipients,
            deposit_nonce,
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

    pub(crate) const fn recipient_count(&self) -> usize {
        self.recipients.len()
    }

    /// Returns the first selectable recipient that is not this wallet.
    pub(crate) fn default_recipient(&self) -> usize {
        let account = self.account();
        self.recipients
            .iter()
            .position(|identity| identity.key != account)
            .expect("the recipient roster is larger than one wallet")
    }

    pub(crate) fn recipient_name(&self, index: usize) -> &'static str {
        self.recipients[index % self.recipients.len()].name
    }

    pub(crate) const fn receipt_count(&self) -> u64 {
        self.receipt_count
    }

    /// Returns the provider's verified incoming ledger summary.
    pub(crate) const fn incoming(&self) -> IncomingSummary {
        self.incoming
    }

    /// Returns the highest epoch whose held credits reconciled with the committed close.
    pub(crate) const fn last_reconciled_epoch(&self) -> Option<u64> {
        self.last_reconciled_epoch
    }

    /// Answers the provider's service-accounting question: has `payer` paid this wallet under
    /// transaction `tx_id`, and for how much? The payer chooses the transaction id by signing
    /// its send, so it is the natural invoice reference. A hit means the credit's verified pair
    /// is durably held, which is exactly the condition under which a provider may rely on it.
    pub(crate) fn paid(&self, payer: &Key, tx_id: &Digest) -> Result<Option<IncomingCredit>> {
        self.store.paid(payer, tx_id)
    }

    pub(crate) async fn operator_status<E: Network>(
        &self,
        network: &E,
        operator: SocketAddr,
    ) -> Result<operator_rpc::StatusResponse> {
        operator_rpc::status(network, operator).await
    }

    pub(crate) async fn settlement_status<E: Network>(
        &self,
        network: &E,
        settlement: SocketAddr,
    ) -> Result<settlement_rpc::StatusResponse> {
        settlement_rpc::status(network, settlement).await
    }

    /// Reads the live balance quote and verifies it against settlement's exact head.
    ///
    /// Polling doubles as the passive wallet's retention heartbeat: the verified head
    /// opening is retained through [`Self::verify_quoted_head`], so a wallet that only
    /// watches its balance still refreshes its frozen-root recovery evidence.
    pub(crate) async fn balance<E: Network>(
        &mut self,
        network: &E,
        settlement: SocketAddr,
        operator: SocketAddr,
    ) -> Result<u64> {
        let quote = operator_rpc::payment_quote(
            network,
            operator,
            operator_rpc::PaymentQuoteRequest {
                account: self.account(),
            },
        )
        .await
        .context("read payer state")?;
        let settlement_status = settlement_rpc::status(network, settlement)
            .await
            .context("read settlement balance head")?;
        ensure!(
            settlement_status.deployment == deployment(),
            "settlement status has an unexpected deployment"
        );
        self.verify_quoted_head(&quote, &settlement_status)?;
        Ok(quote.state.balance)
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
        &self,
        network: &E,
        operator: SocketAddr,
        epoch: u64,
    ) -> Result<operator_rpc::PollCloseResponse> {
        operator_rpc::poll_close(network, operator, epoch).await
    }
}
