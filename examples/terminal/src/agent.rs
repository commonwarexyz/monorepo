//! One-wallet client workflows for the clearing terminal.

use crate::{
    operator_rpc,
    protocol::{
        AccountIdentity, DepositEvent, Key, Payment, Wallet, external_identity, external_wallet,
        identities, wallets,
    },
    settlement_rpc,
};
use anyhow::{Context, Result, ensure};
use bytes::Bytes;
use commonware_clearing::bajillion::{
    boundary::{SignedWithdrawal, WithdrawalAction},
    payment::{PaymentContext, SignedSend},
};
use commonware_cryptography::{Hasher, Sha256, sha256::Digest};
use commonware_runtime::Network;
#[cfg(not(test))]
use rand::RngExt as _;
use std::{collections::VecDeque, net::SocketAddr};

const DEPOSIT_ID_NAMESPACE: &[u8] = b"_COMMONWARE_EXAMPLES_TERMINAL_AGENT_DEPOSIT";
const MAX_RETAINED_RECEIPTS: usize = 256;

struct PendingPayment {
    recipient: Key,
    amount: u64,
    context: PaymentContext<Key, Digest>,
    send: SignedSend<Key, Digest>,
}

struct PendingWithdrawal {
    queue: settlement_rpc::QueueWithdrawalRequest,
    queued: bool,
}

/// An agent owns one payer key and retains the receipts returned by the operator.
pub(crate) struct Agent {
    wallet: Wallet,
    recipients: Vec<AccountIdentity>,
    deposit_nonce: u64,
    pending_payment: Option<PendingPayment>,
    pending_deposit: Option<DepositEvent>,
    pending_withdrawal: Option<PendingWithdrawal>,
    pending_claim: Option<operator_rpc::WithdrawalEvidenceResponse>,
    pending_payout: Option<operator_rpc::ExternalPayoutEvidenceResponse>,
    pending_close_epoch: Option<u64>,
    receipts: VecDeque<Payment>,
}

impl Agent {
    pub(crate) fn new(identity: usize) -> Result<Self> {
        let mut wallets = wallets();
        ensure!(identity <= wallets.len(), "agent identity is out of range");
        let wallet = if identity == wallets.len() {
            external_wallet()
        } else {
            wallets.remove(identity)
        };
        let mut recipients = identities();
        recipients.push(external_identity());
        #[cfg(test)]
        let deposit_nonce = 0;
        #[cfg(not(test))]
        let deposit_nonce = rand::rng().random();
        Ok(Self {
            wallet,
            recipients,
            deposit_nonce,
            pending_payment: None,
            pending_deposit: None,
            pending_withdrawal: None,
            pending_claim: None,
            pending_payout: None,
            pending_close_epoch: None,
            receipts: VecDeque::new(),
        })
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

    pub(crate) fn recipient_name(&self, index: usize) -> &'static str {
        self.recipients[index % self.recipients.len()].name
    }

    pub(crate) fn receipt_count(&self) -> usize {
        self.receipts.len()
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

    pub(crate) async fn balance<E: Network>(
        &self,
        network: &E,
        operator: SocketAddr,
    ) -> Result<u64> {
        Ok(operator_rpc::payment_quote(
            network,
            operator,
            operator_rpc::PaymentQuoteRequest {
                account: self.account(),
            },
        )
        .await?
        .state
        .balance)
    }

    pub(crate) async fn pay<E: Network>(
        &mut self,
        network: &E,
        operator: SocketAddr,
        recipient: usize,
        amount: u64,
    ) -> Result<operator_rpc::AcceptedPaymentResponse> {
        ensure!(amount > 0, "payment amount must be positive");
        let recipient = self.recipients[recipient % self.recipients.len()]
            .key
            .clone();
        let (context, send) = match &self.pending_payment {
            Some(pending) => {
                ensure!(
                    pending.recipient == recipient && pending.amount == amount,
                    "another payment retry is pending"
                );
                (pending.context.clone(), pending.send.clone())
            }
            None => {
                let quote = operator_rpc::payment_quote(
                    network,
                    operator,
                    operator_rpc::PaymentQuoteRequest {
                        account: self.account(),
                    },
                )
                .await
                .context("read payer state")?;
                let send = SignedSend::sign_next(
                    &quote.context,
                    self.wallet.signer(),
                    recipient.clone(),
                    amount,
                    quote.state.cumulative_debit,
                )
                .context("sign payment")?;
                self.pending_payment = Some(PendingPayment {
                    recipient,
                    amount,
                    context: quote.context.clone(),
                    send: send.clone(),
                });
                (quote.context, send)
            }
        };
        let accepted = operator_rpc::accept_send(
            network,
            operator,
            operator_rpc::AcceptSendRequest { send: send.clone() },
        )
        .await
        .context("submit payment")?;
        ensure!(
            accepted.payment.send() == &send
                && accepted.amount == amount
                && accepted.epoch == context.epoch(),
            "operator returned another payment"
        );
        accepted
            .payment
            .verify_linked::<Sha256>(&context)
            .context("verify operator receipt")?;
        self.pending_payment = None;
        self.receipts.push_back(accepted.payment.clone());
        while self.receipts.len() > MAX_RETAINED_RECEIPTS {
            self.receipts.pop_front();
        }
        Ok(accepted)
    }

    pub(crate) async fn deposit<E: Network>(
        &mut self,
        network: &E,
        settlement: SocketAddr,
        operator: SocketAddr,
        amount: u64,
    ) -> Result<operator_rpc::AppliedDepositResponse> {
        ensure!(amount > 0, "deposit amount must be positive");
        let event = match &self.pending_deposit {
            Some(event) => {
                ensure!(event.amount == amount, "another deposit retry is pending");
                event.clone()
            }
            None => {
                let account = self.account();
                let event = DepositEvent {
                    id: Sha256::hash(&[
                        DEPOSIT_ID_NAMESPACE,
                        account.as_ref(),
                        &self.deposit_nonce.to_be_bytes(),
                        &amount.to_be_bytes(),
                    ]),
                    account,
                    amount,
                };
                self.pending_deposit = Some(event.clone());
                event
            }
        };
        settlement_rpc::deposit(
            network,
            settlement,
            settlement_rpc::DepositRequest {
                id: event.id,
                account: event.account.clone(),
                amount: event.amount,
            },
        )
        .await
        .context("record settlement deposit")?;
        let applied = operator_rpc::apply_deposit(
            network,
            operator,
            operator_rpc::ApplyDepositRequest {
                id: event.id,
                account: event.account,
                amount: event.amount,
            },
        )
        .await
        .context("credit operator deposit")?;
        self.pending_deposit = None;
        self.deposit_nonce = self
            .deposit_nonce
            .checked_add(1)
            .context("deposit nonce overflow")?;
        Ok(applied)
    }

    pub(crate) async fn withdraw<E: Network>(
        &mut self,
        network: &E,
        settlement: SocketAddr,
        operator: SocketAddr,
        action: WithdrawalAction,
    ) -> Result<operator_rpc::AppliedWithdrawalResponse> {
        let (queue, queued) = match &self.pending_withdrawal {
            Some(pending) => {
                ensure!(
                    pending.queue.request.body().action() == &action,
                    "another withdrawal retry is pending"
                );
                (pending.queue.clone(), pending.queued)
            }
            None => {
                let opening = operator_rpc::withdrawal_opening(
                    network,
                    operator,
                    operator_rpc::WithdrawalOpeningRequest {
                        account: self.account(),
                    },
                )
                .await
                .context("read withdrawal opening")?;
                let settlement_status = settlement_rpc::status(network, settlement).await?;
                ensure!(
                    settlement_status.state_root == opening.root,
                    "operator opening is not the settlement head"
                );
                let deadline = settlement_status
                    .now
                    .checked_add(50)
                    .context("withdrawal deadline overflow")?;
                let request = SignedWithdrawal::sign(
                    settlement_status.deployment,
                    opening.root.digest,
                    Bytes::copy_from_slice(self.wallet.name.as_bytes()),
                    action,
                    deadline,
                    self.wallet.signer(),
                );
                let queue = settlement_rpc::QueueWithdrawalRequest {
                    request,
                    openings: vec![opening.opening],
                };
                self.pending_withdrawal = Some(PendingWithdrawal {
                    queue: queue.clone(),
                    queued: false,
                });
                (queue, false)
            }
        };
        if !queued {
            settlement_rpc::queue_withdrawal(network, settlement, queue.clone())
                .await
                .context("queue settlement withdrawal")?;
            self.pending_withdrawal
                .as_mut()
                .expect("the exact withdrawal retry was retained")
                .queued = true;
        }
        let account = queue.request.account().clone();
        let action = *queue.request.body().action();
        let applied = operator_rpc::apply_withdrawal(
            network,
            operator,
            operator_rpc::ApplyWithdrawalRequest {
                request: queue.request,
            },
        )
        .await
        .context("apply operator withdrawal")?;
        ensure!(
            applied.account == account && applied.action == action,
            "operator staged another withdrawal"
        );
        self.pending_withdrawal = None;
        Ok(applied)
    }

    pub(crate) async fn claim_withdrawal<E: Network>(
        &mut self,
        network: &E,
        settlement: SocketAddr,
        operator: SocketAddr,
    ) -> Result<settlement_rpc::WithdrawalResponse> {
        let evidence = match &self.pending_claim {
            Some(evidence) => evidence.clone(),
            None => {
                let evidence = operator_rpc::withdrawal_evidence(
                    network,
                    operator,
                    operator_rpc::WithdrawalEvidenceRequest {
                        account: self.account(),
                    },
                )
                .await
                .context("fetch withdrawal evidence")?;
                self.pending_claim = Some(evidence.clone());
                evidence
            }
        };
        let release = settlement_rpc::claim_withdrawal(
            network,
            settlement,
            settlement_rpc::WithdrawalClaimRequest {
                batch_id: evidence.batch_id,
                claim: evidence.claim.clone(),
            },
        )
        .await
        .context("claim settlement withdrawal")?;
        operator_rpc::acknowledge_withdrawal(
            network,
            operator,
            operator_rpc::AcknowledgeWithdrawalRequest {
                batch_id: evidence.batch_id,
                claim: evidence.claim,
            },
        )
        .await
        .context("acknowledge claimed withdrawal")?;
        self.pending_claim = None;
        Ok(release)
    }

    pub(crate) async fn claim_external_payout<E: Network>(
        &mut self,
        network: &E,
        settlement: SocketAddr,
        operator: SocketAddr,
    ) -> Result<settlement_rpc::ExternalPayoutResponse> {
        let evidence = match &self.pending_payout {
            Some(evidence) => evidence.clone(),
            None => {
                let evidence = operator_rpc::external_payout_evidence(
                    network,
                    operator,
                    operator_rpc::ExternalPayoutEvidenceRequest {
                        account: self.account(),
                    },
                )
                .await
                .context("fetch external payout evidence")?;
                self.pending_payout = Some(evidence.clone());
                evidence
            }
        };
        let payout = settlement_rpc::claim_external_payout(
            network,
            settlement,
            settlement_rpc::ExternalPayoutClaimRequest {
                batch_id: evidence.batch_id,
                claim: evidence.claim.clone(),
            },
        )
        .await
        .context("claim settlement external payout")?;
        ensure!(
            payout.recipient == self.account(),
            "settlement returned another external payout"
        );
        operator_rpc::acknowledge_external_payout(
            network,
            operator,
            operator_rpc::AcknowledgeExternalPayoutRequest {
                batch_id: evidence.batch_id,
                claim: evidence.claim,
            },
        )
        .await
        .context("acknowledge claimed external payout")?;
        self.pending_payout = None;
        Ok(payout)
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
