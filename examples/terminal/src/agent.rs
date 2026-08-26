//! One-wallet client workflows for the clearing terminal.

use crate::{
    agent_store::{AgentState, AgentStore},
    operator_rpc,
    protocol::{
        AccountIdentity, DepositEvent, Key, Wallet, deployment, external_identity, external_wallet,
        identities, operator_key, wallets,
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
use std::{net::SocketAddr, path::Path};

const DEPOSIT_ID_NAMESPACE: &[u8] = b"_COMMONWARE_EXAMPLES_TERMINAL_AGENT_DEPOSIT";

struct PendingWithdrawal {
    queue: settlement_rpc::QueueWithdrawalRequest,
    queued: bool,
}

/// An agent owns one payer key and retains the receipts returned by the operator.
pub(crate) struct Agent {
    wallet: Wallet,
    store: AgentStore,
    recipients: Vec<AccountIdentity>,
    deposit_nonce: u64,
    pending_payment: Option<SignedSend<Key, Digest>>,
    pending_deposit: Option<DepositEvent>,
    pending_withdrawal: Option<PendingWithdrawal>,
    pending_claim: Option<operator_rpc::WithdrawalEvidenceResponse>,
    pending_payout: Option<operator_rpc::ExternalPayoutEvidenceResponse>,
    pending_close_epoch: Option<u64>,
    cumulative_debit: u64,
    receipt_count: u64,
}

const fn withdrawal_deadline(now: u64) -> u64 {
    now.saturating_add(50)
}

#[cfg(test)]
const fn initial_deposit_nonce() -> u64 {
    0
}

#[cfg(not(test))]
fn initial_deposit_nonce() -> u64 {
    rand::rng().random()
}

impl Agent {
    pub(crate) fn new(identity: usize) -> Result<Self> {
        let (wallet, recipients) = Self::identity(identity)?;
        let account = wallet.public_key();
        let (store, state) = AgentStore::in_memory(&account, &deployment(), &operator_key())?;
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
        let (store, state) = AgentStore::open(path, &account, &deployment(), &operator_key())?;
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

    const fn from_state(
        wallet: Wallet,
        recipients: Vec<AccountIdentity>,
        store: AgentStore,
        state: AgentState,
        deposit_nonce: u64,
    ) -> Self {
        Self {
            wallet,
            store,
            recipients,
            deposit_nonce,
            pending_payment: state.pending_send,
            pending_deposit: None,
            pending_withdrawal: None,
            pending_claim: None,
            pending_payout: None,
            pending_close_epoch: None,
            cumulative_debit: state.cumulative_debit,
            receipt_count: state.receipt_count,
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

    pub(crate) fn recipient_name(&self, index: usize) -> &'static str {
        self.recipients[index % self.recipients.len()].name
    }

    pub(crate) const fn receipt_count(&self) -> u64 {
        self.receipt_count
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
            Some(send) => {
                ensure!(
                    send.body().recipient() == &recipient && send.body().amount() == amount,
                    "another payment retry is pending"
                );
                (
                    PaymentContext::new(*send.body().anchor(), send.body().epoch(), operator_key()),
                    send.clone(),
                )
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
                ensure!(
                    quote.context.operator() == &operator_key(),
                    "payment context has an unexpected operator"
                );
                let send = SignedSend::sign_next(
                    &quote.context,
                    self.wallet.signer(),
                    recipient.clone(),
                    amount,
                    self.cumulative_debit,
                )
                .context("sign payment")?;
                self.store
                    .stage_payment(&send, self.cumulative_debit)
                    .context("durably stage payment")?;
                self.pending_payment = Some(send.clone());
                (quote.context, send)
            }
        };
        ensure!(
            context.operator() == &operator_key(),
            "payment context has an unexpected operator"
        );
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
        let receipt_count = self
            .store
            .commit_payment(&accepted.payment, self.cumulative_debit, self.receipt_count)
            .context("commit accepted receipt")?;
        self.cumulative_debit = send.body().cumulative_debit();
        self.pending_payment = None;
        self.receipt_count = receipt_count;
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
                let deadline = withdrawal_deadline(settlement_status.now);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpc;
    use commonware_clearing::bajillion::{
        payment::{Payment, SignedReceipt},
        state::AccountState,
    };
    use commonware_codec::Encode;
    use commonware_runtime::{
        Listener as _, Runner as _, Spawner as _, Supervisor as _, deterministic,
    };
    use std::{
        fs,
        path::{Path, PathBuf},
        sync::atomic::{AtomicU64, Ordering},
    };

    static TEMP_DATABASE_ID: AtomicU64 = AtomicU64::new(0);

    struct TempDatabase {
        directory: PathBuf,
        path: PathBuf,
    }

    impl TempDatabase {
        fn new() -> Self {
            let id = TEMP_DATABASE_ID.fetch_add(1, Ordering::Relaxed);
            let directory = std::env::temp_dir().join(format!(
                "commonware-terminal-agent-{}-{id}",
                std::process::id()
            ));
            fs::create_dir(&directory).unwrap();
            let path = directory.join("agent.sqlite");
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

    async fn respond<L: commonware_runtime::Listener>(
        listener: &mut L,
        handle: impl FnOnce(operator_rpc::OperatorRequest) -> rpc::Response,
    ) {
        let (_, mut sink, mut stream) = listener.accept().await.unwrap();
        let request = rpc::recv_request(&mut stream).await.unwrap();
        let response = handle(operator_rpc::decode_request(request).unwrap());
        rpc::send_response(&mut sink, &response).await.unwrap();
    }

    #[test]
    fn payment_debit_is_local_and_advances_only_after_a_verified_receipt() {
        deterministic::Runner::default().start(|context| async move {
            let operator = Wallet::from_seed("operator", 1);
            let impostor = Wallet::from_seed("impostor", 1_001);
            let payment_context = PaymentContext::new(
                Sha256::hash(&[b"agent-payment-counter"]),
                7,
                operator.public_key(),
            );
            let mut listener = context
                .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
                .await
                .unwrap();
            let operator_address = listener.local_addr().unwrap();
            let operator_server = context.child("operator").spawn(move |_| async move {
                respond(&mut listener, |request| {
                    assert!(matches!(
                        request,
                        operator_rpc::OperatorRequest::PaymentQuote(_)
                    ));
                    rpc::Response::Success {
                        body: operator_rpc::PaymentQuoteResponse {
                            context: payment_context.clone(),
                            state: AccountState {
                                balance: 100,
                                cumulative_debit: 10_000,
                                ..AccountState::default()
                            },
                        }
                        .encode(),
                    }
                })
                .await;

                let mut first_payment = None;
                respond(&mut listener, |request| {
                    let operator_rpc::OperatorRequest::AcceptSend(request) = request else {
                        panic!("payment retry unexpectedly requested another quote");
                    };
                    assert_eq!(request.send.body().cumulative_debit(), 7);
                    let receipt = SignedReceipt::issue_next::<Sha256, _>(
                        &payment_context,
                        &request.send,
                        0,
                        0,
                        0,
                        operator.signer(),
                    )
                    .unwrap();
                    first_payment = Some(
                        Payment::new::<Sha256>(
                            &payment_context,
                            request.send.clone(),
                            receipt.clone(),
                        )
                        .unwrap(),
                    );
                    let forged = SignedReceipt::sign_body_by_authority(
                        receipt.body().clone(),
                        impostor.signer(),
                    );
                    rpc::Response::Success {
                        body: operator_rpc::AcceptedPaymentResponse {
                            epoch: payment_context.epoch(),
                            sequence: 0,
                            amount: 7,
                            payment: Payment::from_parts_unchecked(request.send, forged),
                        }
                        .encode(),
                    }
                })
                .await;
                let first_payment = first_payment.unwrap();

                respond(&mut listener, |request| {
                    let operator_rpc::OperatorRequest::AcceptSend(request) = request else {
                        panic!("payment retry unexpectedly requested another quote");
                    };
                    assert_eq!(request.send, *first_payment.send());
                    rpc::Response::Success {
                        body: operator_rpc::AcceptedPaymentResponse {
                            epoch: payment_context.epoch(),
                            sequence: 0,
                            amount: 7,
                            payment: first_payment.clone(),
                        }
                        .encode(),
                    }
                })
                .await;

                respond(&mut listener, |request| {
                    assert!(matches!(
                        request,
                        operator_rpc::OperatorRequest::PaymentQuote(_)
                    ));
                    rpc::Response::Success {
                        body: operator_rpc::PaymentQuoteResponse {
                            context: payment_context.clone(),
                            state: AccountState {
                                balance: 93,
                                cumulative_debit: 20_000,
                                ..AccountState::default()
                            },
                        }
                        .encode(),
                    }
                })
                .await;

                respond(&mut listener, |request| {
                    let operator_rpc::OperatorRequest::AcceptSend(request) = request else {
                        panic!("expected the second signed send");
                    };
                    assert_eq!(request.send.body().cumulative_debit(), 10);
                    let receipt = SignedReceipt::issue_next::<Sha256, _>(
                        &payment_context,
                        &request.send,
                        0,
                        7,
                        1,
                        operator.signer(),
                    )
                    .unwrap();
                    let payment =
                        Payment::new::<Sha256>(&payment_context, request.send, receipt).unwrap();
                    rpc::Response::Success {
                        body: operator_rpc::AcceptedPaymentResponse {
                            epoch: payment_context.epoch(),
                            sequence: 1,
                            amount: 3,
                            payment,
                        }
                        .encode(),
                    }
                })
                .await;
            });

            let mut agent = Agent::new(0).unwrap();
            let rejected = agent
                .pay(&context, operator_address, 1, 7)
                .await
                .unwrap_err();
            assert!(format!("{rejected:#}").contains("verify operator receipt"));
            assert_eq!(agent.receipt_count(), 0);

            let accepted = agent.pay(&context, operator_address, 1, 7).await.unwrap();
            assert_eq!(accepted.payment.amount(), 7);
            assert_eq!(agent.receipt_count(), 1);

            let accepted = agent.pay(&context, operator_address, 1, 3).await.unwrap();
            assert_eq!(accepted.payment.amount(), 3);
            assert_eq!(agent.receipt_count(), 2);
            operator_server.await.unwrap();
        });
    }

    #[test]
    fn withdrawal_deadline_caps_at_the_clock_horizon() {
        assert_eq!(withdrawal_deadline(7), 57);
        assert_eq!(withdrawal_deadline(u64::MAX - 20), u64::MAX);
    }

    #[test]
    fn forged_quote_operator_is_rejected_before_staging() {
        deterministic::Runner::default().start(|context| async move {
            let database = TempDatabase::new();
            let impostor = Wallet::from_seed("impostor", 1_001);
            let payment_context = PaymentContext::new(
                Sha256::hash(&[b"forged-quote-operator"]),
                7,
                impostor.public_key(),
            );
            let mut listener = context
                .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
                .await
                .unwrap();
            let operator_address = listener.local_addr().unwrap();
            let operator_server = context.child("operator").spawn(move |_| async move {
                respond(&mut listener, |request| {
                    assert!(matches!(
                        request,
                        operator_rpc::OperatorRequest::PaymentQuote(_)
                    ));
                    rpc::Response::Success {
                        body: operator_rpc::PaymentQuoteResponse {
                            context: payment_context,
                            state: AccountState {
                                balance: 100,
                                cumulative_debit: 50_000,
                                ..AccountState::default()
                            },
                        }
                        .encode(),
                    }
                })
                .await;
            });

            let mut agent = Agent::open(database.path(), 0).unwrap();
            let error = agent
                .pay(&context, operator_address, 1, 7)
                .await
                .unwrap_err();
            assert!(format!("{error:#}").contains("unexpected operator"));
            drop(agent);

            let recovered = Agent::open(database.path(), 0).unwrap();
            assert_eq!(recovered.cumulative_debit, 0);
            assert!(recovered.pending_payment.is_none());
            operator_server.await.unwrap();
        });
    }

    #[test]
    fn response_loss_restart_retries_byte_identical_pending_send() {
        deterministic::Runner::default().start(|context| async move {
            let database = TempDatabase::new();
            let operator = Wallet::from_seed("operator", 1);
            let payment_context = PaymentContext::new(
                Sha256::hash(&[b"response-loss-restart"]),
                7,
                operator.public_key(),
            );
            let mut listener = context
                .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
                .await
                .unwrap();
            let operator_address = listener.local_addr().unwrap();
            let operator_server = context.child("operator").spawn(move |_| async move {
                respond(&mut listener, |request| {
                    assert!(matches!(
                        request,
                        operator_rpc::OperatorRequest::PaymentQuote(_)
                    ));
                    rpc::Response::Success {
                        body: operator_rpc::PaymentQuoteResponse {
                            context: payment_context.clone(),
                            state: AccountState {
                                balance: 100,
                                cumulative_debit: 50_000,
                                ..AccountState::default()
                            },
                        }
                        .encode(),
                    }
                })
                .await;

                let accepted;
                let first_send;
                {
                    let (_, _sink, mut stream) = listener.accept().await.unwrap();
                    let request = rpc::recv_request(&mut stream).await.unwrap();
                    let operator_rpc::OperatorRequest::AcceptSend(request) =
                        operator_rpc::decode_request(request).unwrap()
                    else {
                        panic!("expected the initially staged send");
                    };
                    assert_eq!(request.send.body().cumulative_debit(), 7);
                    first_send = request.send;
                    let receipt = SignedReceipt::issue_next::<Sha256, _>(
                        &payment_context,
                        &first_send,
                        0,
                        0,
                        0,
                        operator.signer(),
                    )
                    .unwrap();
                    accepted =
                        Payment::new::<Sha256>(&payment_context, first_send.clone(), receipt)
                            .unwrap();
                }

                respond(&mut listener, |request| {
                    let operator_rpc::OperatorRequest::AcceptSend(request) = request else {
                        panic!("restart unexpectedly requested another quote");
                    };
                    assert_eq!(request.send.encode(), first_send.encode());
                    rpc::Response::Success {
                        body: operator_rpc::AcceptedPaymentResponse {
                            epoch: payment_context.epoch(),
                            sequence: 0,
                            amount: 7,
                            payment: accepted,
                        }
                        .encode(),
                    }
                })
                .await;
            });

            let mut agent = Agent::open(database.path(), 0).unwrap();
            let error = agent
                .pay(&context, operator_address, 1, 7)
                .await
                .unwrap_err();
            assert!(format!("{error:#}").contains("submit payment"));
            assert!(agent.pending_payment.is_some());
            drop(agent);

            let mut recovered = Agent::open(database.path(), 0).unwrap();
            assert!(recovered.pending_payment.is_some());
            let accepted = recovered
                .pay(&context, operator_address, 1, 7)
                .await
                .unwrap();
            assert_eq!(accepted.payment.amount(), 7);
            assert_eq!(recovered.cumulative_debit, 7);
            assert_eq!(recovered.receipt_count(), 1);
            assert!(recovered.pending_payment.is_none());
            drop(recovered);

            let recovered = Agent::open(database.path(), 0).unwrap();
            assert!(recovered.pending_payment.is_none());
            assert_eq!(recovered.receipt_count(), 1);
            operator_server.await.unwrap();
        });
    }

    #[test]
    fn successful_receipt_commit_survives_restart_and_advances_next_debit() {
        deterministic::Runner::default().start(|context| async move {
            let database = TempDatabase::new();
            let operator = Wallet::from_seed("operator", 1);
            let payment_context = PaymentContext::new(
                Sha256::hash(&[b"successful-payment-restart"]),
                7,
                operator.public_key(),
            );
            let mut listener = context
                .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
                .await
                .unwrap();
            let operator_address = listener.local_addr().unwrap();
            let operator_server = context.child("operator").spawn(move |_| async move {
                respond(&mut listener, |request| {
                    assert!(matches!(
                        request,
                        operator_rpc::OperatorRequest::PaymentQuote(_)
                    ));
                    rpc::Response::Success {
                        body: operator_rpc::PaymentQuoteResponse {
                            context: payment_context.clone(),
                            state: AccountState {
                                balance: 100,
                                cumulative_debit: 10_000,
                                ..AccountState::default()
                            },
                        }
                        .encode(),
                    }
                })
                .await;
                respond(&mut listener, |request| {
                    let operator_rpc::OperatorRequest::AcceptSend(request) = request else {
                        panic!("expected the first signed send");
                    };
                    assert_eq!(request.send.body().cumulative_debit(), 7);
                    let receipt = SignedReceipt::issue_next::<Sha256, _>(
                        &payment_context,
                        &request.send,
                        0,
                        0,
                        0,
                        operator.signer(),
                    )
                    .unwrap();
                    let payment =
                        Payment::new::<Sha256>(&payment_context, request.send, receipt).unwrap();
                    rpc::Response::Success {
                        body: operator_rpc::AcceptedPaymentResponse {
                            epoch: payment_context.epoch(),
                            sequence: 0,
                            amount: 7,
                            payment,
                        }
                        .encode(),
                    }
                })
                .await;
                respond(&mut listener, |request| {
                    assert!(matches!(
                        request,
                        operator_rpc::OperatorRequest::PaymentQuote(_)
                    ));
                    rpc::Response::Success {
                        body: operator_rpc::PaymentQuoteResponse {
                            context: payment_context.clone(),
                            state: AccountState {
                                balance: 93,
                                cumulative_debit: 20_000,
                                ..AccountState::default()
                            },
                        }
                        .encode(),
                    }
                })
                .await;
                respond(&mut listener, |request| {
                    let operator_rpc::OperatorRequest::AcceptSend(request) = request else {
                        panic!("expected the second signed send");
                    };
                    assert_eq!(request.send.body().cumulative_debit(), 10);
                    let receipt = SignedReceipt::issue_next::<Sha256, _>(
                        &payment_context,
                        &request.send,
                        0,
                        7,
                        1,
                        operator.signer(),
                    )
                    .unwrap();
                    let payment =
                        Payment::new::<Sha256>(&payment_context, request.send, receipt).unwrap();
                    rpc::Response::Success {
                        body: operator_rpc::AcceptedPaymentResponse {
                            epoch: payment_context.epoch(),
                            sequence: 1,
                            amount: 3,
                            payment,
                        }
                        .encode(),
                    }
                })
                .await;
            });

            let mut agent = Agent::open(database.path(), 0).unwrap();
            agent.pay(&context, operator_address, 1, 7).await.unwrap();
            drop(agent);

            let mut recovered = Agent::open(database.path(), 0).unwrap();
            assert_eq!(recovered.cumulative_debit, 7);
            assert_eq!(recovered.receipt_count(), 1);
            recovered
                .pay(&context, operator_address, 1, 3)
                .await
                .unwrap();
            drop(recovered);

            let recovered = Agent::open(database.path(), 0).unwrap();
            assert_eq!(recovered.cumulative_debit, 10);
            assert_eq!(recovered.receipt_count(), 2);
            operator_server.await.unwrap();
        });
    }
}
