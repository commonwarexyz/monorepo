//! One-wallet client workflows for the clearing terminal.

use crate::{
    agent_store::{
        AgentState, AgentStore, PendingPayment, PendingPayoutClaim, PendingWithdrawalClaim,
    },
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
    commitment::VectorKind,
    payment::{Entry, PaymentContext, SignedSend},
};
use commonware_codec::Encode as _;
use commonware_cryptography::{Hasher, Sha256};
use commonware_runtime::Network;
#[cfg(not(test))]
use rand::RngExt as _;
use std::{net::SocketAddr, path::Path};

const DEPOSIT_ID_NAMESPACE: &[u8] = b"_COMMONWARE_EXAMPLES_TERMINAL_AGENT_DEPOSIT";

struct PendingWithdrawal {
    queue: settlement_rpc::QueueWithdrawalRequest,
    queued: bool,
}

#[derive(Debug)]
pub(crate) enum DepositOutcome {
    Applied {
        epoch: u64,
        event: DepositEvent,
    },
    Recorded {
        event: DepositEvent,
        error: anyhow::Error,
    },
}

#[derive(Debug)]
pub(crate) enum WithdrawalOutcome {
    Applied {
        epoch: u64,
        request: SignedWithdrawal<Key, commonware_cryptography::sha256::Digest>,
    },
    Queued {
        request: SignedWithdrawal<Key, commonware_cryptography::sha256::Digest>,
        error: anyhow::Error,
    },
}

/// An agent owns one payer key and retains the receipts returned by the operator.
pub(crate) struct Agent {
    wallet: Wallet,
    store: AgentStore,
    recipients: Vec<AccountIdentity>,
    deposit_nonce: u64,
    pending_payment: Option<PendingPayment>,
    pending_deposit: Option<DepositEvent>,
    pending_withdrawal: Option<PendingWithdrawal>,
    pending_withdrawal_claim: Option<PendingWithdrawalClaim>,
    pending_payout_claim: Option<PendingPayoutClaim>,
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

    fn from_state(
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
            pending_payment: state.pending_payment,
            pending_deposit: None,
            pending_withdrawal: None,
            pending_withdrawal_claim: state.pending_withdrawal_claim,
            pending_payout_claim: state.pending_payout_claim,
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

    /// Pays every `(recipient index, amount)` entry with one batched send.
    pub(crate) async fn pay<E: Network>(
        &mut self,
        network: &E,
        settlement: SocketAddr,
        operator: SocketAddr,
        entries: &[(usize, u64)],
    ) -> Result<operator_rpc::AcceptedBatchResponse> {
        let mut requested = Vec::with_capacity(entries.len());
        for (recipient, amount) in entries {
            let recipient = self.recipients[recipient % self.recipients.len()]
                .key
                .clone();
            requested.push(Entry::new(recipient, *amount).context("stage payment entry")?);
        }
        requested.sort_unstable_by(|left, right| left.recipient().cmp(right.recipient()));
        let (context, send, predecessor_state_root) = match &self.pending_payment {
            Some(pending) => {
                ensure!(
                    pending.send.body().entries() == requested,
                    "another payment retry is pending"
                );
                self.store
                    .recovery_opening(&pending.recovery_root)?
                    .context("pending payment recovery opening is missing")?;
                (
                    PaymentContext::new(
                        *pending.send.body().anchor(),
                        pending.send.body().epoch(),
                        operator_key(),
                    ),
                    pending.send.clone(),
                    pending.recovery_root,
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
                let settlement_status = settlement_rpc::status(network, settlement)
                    .await
                    .context("read settlement payment head")?;
                ensure!(
                    settlement_status.deployment == deployment(),
                    "settlement status has an unexpected deployment"
                );
                ensure!(
                    !settlement_status.hard_faulted,
                    "settlement is permanently hard-faulted"
                );
                ensure!(
                    settlement_status.state_root == quote.root,
                    "payer opening is not the exact settlement head"
                );
                ensure!(
                    quote.opening.leaf.account == self.account(),
                    "payer opening belongs to another account"
                );
                ensure!(
                    quote.opening.leaf.state.active && quote.opening.leaf.state.balance > 0,
                    "payer opening is not live"
                );
                quote
                    .opening
                    .proof
                    .verify::<Sha256>(
                        VectorKind::State,
                        &quote.root,
                        quote.opening.leaf.encode().as_ref(),
                    )
                    .context("verify payer state opening")?;
                self.store
                    .retain_recovery_opening(&quote.root, &quote.opening)
                    .context("durably retain payer state opening")?;
                let send = SignedSend::sign_next_batch(
                    &quote.context,
                    self.wallet.signer(),
                    requested.clone(),
                    self.cumulative_debit,
                )
                .context("sign payment")?;
                self.store
                    .stage_payment(&send, &quote.root, self.cumulative_debit)
                    .context("durably stage payment")?;
                self.pending_payment = Some(PendingPayment {
                    send: send.clone(),
                    recovery_root: quote.root,
                });
                (quote.context, send, quote.root)
            }
        };
        let accepted = operator_rpc::accept_send(
            network,
            operator,
            operator_rpc::AcceptSendRequest { send: send.clone() },
        )
        .await
        .context("submit payment")?;
        let total = send
            .body()
            .total()
            .context("staged payment total is checked")?;
        ensure!(
            accepted.epoch == context.epoch()
                && accepted.total == total
                && accepted.acceptance.send == send,
            "operator returned another payment"
        );
        accepted
            .acceptance
            .verify(&context)
            .context("verify operator receipts")?;
        settlement_rpc::confirm_registration(
            network,
            settlement,
            settlement_rpc::RegistrationQuery {
                epoch: context.epoch(),
                anchor: *context.anchor(),
                state_root: predecessor_state_root,
            },
        )
        .await
        .context("confirm payment registration")?;
        let receipt_count = self
            .store
            .commit_payment(
                &accepted.acceptance,
                self.cumulative_debit,
                self.receipt_count,
            )
            .context("commit accepted receipts")?;
        self.cumulative_debit = send.body().cumulative_debit();
        self.pending_payment = None;
        self.receipt_count = receipt_count;
        Ok(accepted)
    }

    pub(crate) async fn recover_hard_fault<E: Network>(
        &self,
        network: &E,
        settlement: SocketAddr,
    ) -> Result<settlement_rpc::ClaimHardFaultResponse> {
        let hard_fault = settlement_rpc::begin_hard_fault_settlement(network, settlement)
            .await
            .context("begin hard-fault settlement")?;
        let opening = self
            .store
            .recovery_opening(&hard_fault.frozen_state_root)?
            .context("no payer opening is retained for the frozen state root")?;
        let expected_custody = opening.leaf.state.balance;
        let release = settlement_rpc::claim_hard_fault(
            network,
            settlement,
            settlement_rpc::ClaimHardFaultRequest { opening },
        )
        .await
        .context("claim hard-fault payer state")?;
        ensure!(
            release.account == self.account(),
            "settlement released another account"
        );
        ensure!(
            release.released_custody == expected_custody,
            "settlement released the wrong payer custody"
        );
        let withdrawal = release
            .withdrawal
            .as_ref()
            .map_or(0, |output| output.amount());
        ensure!(
            withdrawal.checked_add(release.residual) == Some(release.released_custody),
            "settlement release does not decompose into withdrawal and residual"
        );
        Ok(release)
    }

    pub(crate) async fn recover_pending_deposit<E: Network>(
        &self,
        network: &E,
        settlement: SocketAddr,
    ) -> Result<settlement_rpc::ClaimPendingDepositResponse> {
        let account = self.account();
        let refund = settlement_rpc::claim_pending_deposit(
            network,
            settlement,
            settlement_rpc::ClaimPendingDepositRequest {
                account: account.clone(),
            },
        )
        .await
        .context("claim pending settlement deposit")?;
        ensure!(
            refund.account == account,
            "settlement refunded another account"
        );
        ensure!(
            refund.amount > 0,
            "settlement returned a zero deposit refund"
        );
        Ok(refund)
    }

    pub(crate) async fn deposit<E: Network>(
        &mut self,
        network: &E,
        settlement: SocketAddr,
        operator: SocketAddr,
        amount: u64,
    ) -> Result<DepositOutcome> {
        ensure!(amount > 0, "deposit amount must be positive");
        let next_deposit_nonce = self
            .deposit_nonce
            .checked_add(1)
            .context("deposit nonce overflow")?;
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
        let applied = match operator_rpc::apply_deposit(
            network,
            operator,
            operator_rpc::ApplyDepositRequest {
                id: event.id,
                account: event.account.clone(),
                amount: event.amount,
            },
        )
        .await
        {
            Ok(applied) => applied,
            Err(error) => {
                return Ok(DepositOutcome::Recorded {
                    event,
                    error: error.context("credit operator deposit"),
                });
            }
        };
        if applied.id != event.id
            || applied.account != event.account
            || applied.amount != event.amount
        {
            return Ok(DepositOutcome::Recorded {
                event,
                error: anyhow::anyhow!("operator acknowledged another deposit"),
            });
        }
        self.pending_deposit = None;
        self.deposit_nonce = next_deposit_nonce;
        Ok(DepositOutcome::Applied {
            epoch: applied.epoch,
            event,
        })
    }

    pub(crate) async fn withdraw<E: Network>(
        &mut self,
        network: &E,
        settlement: SocketAddr,
        operator: SocketAddr,
        action: WithdrawalAction,
    ) -> Result<WithdrawalOutcome> {
        let (queue, queued) = match &self.pending_withdrawal {
            Some(pending) => {
                ensure!(
                    pending.queue.request.body().action() == &action,
                    "another withdrawal retry is pending"
                );
                (pending.queue.clone(), pending.queued)
            }
            None => {
                let settlement_status = settlement_rpc::status(network, settlement)
                    .await
                    .context("read settlement withdrawal head")?;
                ensure!(
                    settlement_status.deployment == deployment(),
                    "settlement status has an unexpected deployment"
                );
                ensure!(
                    !settlement_status.hard_faulted,
                    "settlement is permanently hard-faulted"
                );
                let opening = match self
                    .store
                    .recovery_opening(&settlement_status.state_root)
                    .context("read retained withdrawal opening")?
                {
                    Some(opening) => opening,
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
                        ensure!(
                            settlement_status.state_root == opening.root,
                            "operator opening is not the settlement head"
                        );
                        self.store
                            .retain_recovery_opening(&opening.root, &opening.opening)
                            .context("durably retain withdrawal opening")?;
                        opening.opening
                    }
                };
                let deadline = withdrawal_deadline(settlement_status.now);
                let request = SignedWithdrawal::sign(
                    settlement_status.deployment,
                    settlement_status.state_root.digest,
                    Bytes::copy_from_slice(self.wallet.name.as_bytes()),
                    action,
                    deadline,
                    self.wallet.signer(),
                );
                let queue = settlement_rpc::QueueWithdrawalRequest {
                    request,
                    openings: vec![opening],
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
        let digest = operator_rpc::withdrawal_digest(&queue.request);
        let applied = match operator_rpc::apply_withdrawal(
            network,
            operator,
            operator_rpc::ApplyWithdrawalRequest {
                request: queue.request.clone(),
            },
        )
        .await
        {
            Ok(applied) => applied,
            Err(error) => {
                return Ok(WithdrawalOutcome::Queued {
                    request: queue.request,
                    error: error.context("apply operator withdrawal"),
                });
            }
        };
        if applied.digest != digest {
            return Ok(WithdrawalOutcome::Queued {
                request: queue.request,
                error: anyhow::anyhow!("operator acknowledged another withdrawal"),
            });
        }
        self.pending_withdrawal = None;
        Ok(WithdrawalOutcome::Applied {
            epoch: applied.epoch,
            request: queue.request,
        })
    }

    pub(crate) async fn claim_withdrawal<E: Network>(
        &mut self,
        network: &E,
        settlement: SocketAddr,
        operator: SocketAddr,
    ) -> Result<settlement_rpc::WithdrawalResponse> {
        let pending = match &self.pending_withdrawal_claim {
            Some(pending) => pending.clone(),
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
                ensure!(
                    evidence.account == self.account(),
                    "operator returned withdrawal evidence for another account"
                );
                self.store
                    .stage_withdrawal_claim(&evidence)
                    .context("persist withdrawal evidence")?;
                let pending = PendingWithdrawalClaim {
                    evidence,
                    result: None,
                };
                self.pending_withdrawal_claim = Some(pending.clone());
                pending
            }
        };
        let release = settlement_rpc::claim_withdrawal(
            network,
            settlement,
            settlement_rpc::WithdrawalClaimRequest {
                batch_id: pending.evidence.batch_id,
                claim: pending.evidence.claim.clone(),
            },
        )
        .await
        .context("claim settlement withdrawal")?;
        ensure!(
            release.destination == *pending.evidence.claim.output().destination()
                && release.amount == pending.evidence.claim.output().amount(),
            "settlement returned another withdrawal output"
        );
        if let Some(expected) = &pending.result {
            ensure!(
                &release == expected,
                "settlement replay returned another withdrawal output"
            );
        } else {
            self.store
                .record_withdrawal_result(&pending.evidence, &release)
                .context("persist withdrawal result")?;
            self.pending_withdrawal_claim
                .as_mut()
                .expect("withdrawal evidence was retained before settlement")
                .result = Some(release.clone());
        }
        operator_rpc::acknowledge_withdrawal(
            network,
            operator,
            operator_rpc::AcknowledgeWithdrawalRequest {
                batch_id: pending.evidence.batch_id,
                account: pending.evidence.account.clone(),
                claim: pending.evidence.claim.clone(),
            },
        )
        .await
        .context("acknowledge claimed withdrawal")?;
        self.store
            .complete_withdrawal_claim(&pending.evidence, &release)
            .context("complete withdrawal claim")?;
        self.pending_withdrawal_claim = None;
        Ok(release)
    }

    pub(crate) async fn claim_external_payout<E: Network>(
        &mut self,
        network: &E,
        settlement: SocketAddr,
        operator: SocketAddr,
    ) -> Result<settlement_rpc::ExternalPayoutResponse> {
        let pending = match &self.pending_payout_claim {
            Some(pending) => pending.clone(),
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
                ensure!(
                    evidence.claim.recipient() == &self.account(),
                    "operator returned external-payout evidence for another account"
                );
                self.store
                    .stage_payout_claim(&evidence)
                    .context("persist external-payout evidence")?;
                let pending = PendingPayoutClaim {
                    evidence,
                    result: None,
                };
                self.pending_payout_claim = Some(pending.clone());
                pending
            }
        };
        let payout = settlement_rpc::claim_external_payout(
            network,
            settlement,
            settlement_rpc::ExternalPayoutClaimRequest {
                batch_id: pending.evidence.batch_id,
                claim: pending.evidence.claim.clone(),
            },
        )
        .await
        .context("claim settlement external payout")?;
        ensure!(
            payout.recipient == self.account(),
            "settlement returned another external payout"
        );
        if let Some(expected) = &pending.result {
            ensure!(
                &payout == expected,
                "settlement replay returned another external payout"
            );
        } else {
            self.store
                .record_payout_result(&pending.evidence, &payout)
                .context("persist external payout")?;
            self.pending_payout_claim
                .as_mut()
                .expect("external-payout evidence was retained before settlement")
                .result = Some(payout.clone());
        }
        operator_rpc::acknowledge_external_payout(
            network,
            operator,
            operator_rpc::AcknowledgeExternalPayoutRequest {
                batch_id: pending.evidence.batch_id,
                claim: pending.evidence.claim.clone(),
            },
        )
        .await
        .context("acknowledge claimed external payout")?;
        self.store
            .complete_payout_claim(&pending.evidence, &payout)
            .context("complete external payout")?;
        self.pending_payout_claim = None;
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
    use crate::{
        operator::Operator,
        protocol::{Acceptance, AccountCache},
        rpc,
        settlement::Settlement,
    };
    use commonware_clearing::bajillion::{
        boundary::{DepositBatch, WithdrawalBatch},
        payment::{Payment, SignedReceipt},
        state::{AccountState, StateLeaf},
    };
    use commonware_codec::{DecodeExt as _, Encode};
    use commonware_runtime::{
        Listener as _, Runner as _, Spawner as _, Supervisor as _, deterministic,
    };
    use std::{
        fs,
        num::{NonZeroU64, NonZeroUsize},
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

    async fn respond_rpc<L: commonware_runtime::Listener>(
        listener: &mut L,
        handle: impl FnOnce(rpc::Request) -> rpc::Response,
    ) {
        let (_, mut sink, mut stream) = listener.accept().await.unwrap();
        let request = rpc::recv_request(&mut stream).await.unwrap();
        let response = handle(request);
        rpc::send_response(&mut sink, &response).await.unwrap();
    }

    async fn respond<L: commonware_runtime::Listener>(
        listener: &mut L,
        handle: impl FnOnce(operator_rpc::OperatorRequest) -> rpc::Response,
    ) {
        respond_rpc(listener, |request| {
            handle(operator_rpc::decode_request(request).unwrap())
        })
        .await;
    }

    async fn respond_registration<L: commonware_runtime::Listener>(
        listener: &mut L,
        context: &PaymentContext<Key, commonware_cryptography::sha256::Digest>,
    ) {
        respond_rpc(listener, |request| {
            assert_eq!(request.method, settlement_rpc::METHOD_CONFIRM_REGISTRATION);
            assert_eq!(
                settlement_rpc::RegistrationQuery::decode(request.body).unwrap(),
                settlement_rpc::RegistrationQuery {
                    epoch: context.epoch(),
                    anchor: *context.anchor(),
                    state_root: settlement_status_response().state_root,
                }
            );
            rpc::Response::Success { body: Bytes::new() }
        })
        .await;
    }

    fn payment_quote_response(
        context: PaymentContext<Key, commonware_cryptography::sha256::Digest>,
        state: AccountState,
    ) -> operator_rpc::PaymentQuoteResponse {
        let account = wallets()[0].public_key();
        let opening = AccountCache::new::<Sha256>(vec![StateLeaf {
            account: account.clone(),
            state: AccountState {
                balance: 100,
                active: true,
                ..AccountState::default()
            },
        }])
        .unwrap();
        operator_rpc::PaymentQuoteResponse {
            context,
            state,
            root: opening.root(),
            opening: opening.opening(&account).unwrap(),
        }
    }

    fn settlement_status_response() -> settlement_rpc::StatusResponse {
        let quote = payment_quote_response(
            PaymentContext::new(Sha256::hash(&[b"status-root"]), 0, operator_key()),
            AccountState::default(),
        );
        settlement_rpc::StatusResponse {
            now: 0,
            deployment: deployment(),
            state_root: quote.root,
            custody_balance: 400,
            claimable_balance: 0,
            hard_faulted: false,
        }
    }

    #[derive(Clone, Copy, Debug)]
    enum PaymentQuoteGateCase {
        WrongDeployment,
        HardFaulted,
        MismatchedStateRoot,
        WrongAccount,
        InactivePayer,
        ZeroBalance,
        InvalidProof,
    }

    impl PaymentQuoteGateCase {
        const ALL: [Self; 7] = [
            Self::WrongDeployment,
            Self::HardFaulted,
            Self::MismatchedStateRoot,
            Self::WrongAccount,
            Self::InactivePayer,
            Self::ZeroBalance,
            Self::InvalidProof,
        ];

        const fn actor(self) -> &'static str {
            match self {
                Self::WrongDeployment => "wrong_deployment",
                Self::HardFaulted => "hard_faulted",
                Self::MismatchedStateRoot => "mismatched_state_root",
                Self::WrongAccount => "wrong_account",
                Self::InactivePayer => "inactive_payer",
                Self::ZeroBalance => "zero_balance",
                Self::InvalidProof => "invalid_proof",
            }
        }

        const fn expected_error(self) -> &'static str {
            match self {
                Self::WrongDeployment => "settlement status has an unexpected deployment",
                Self::HardFaulted => "settlement is permanently hard-faulted",
                Self::MismatchedStateRoot => "payer opening is not the exact settlement head",
                Self::WrongAccount => "payer opening belongs to another account",
                Self::InactivePayer | Self::ZeroBalance => "payer opening is not live",
                Self::InvalidProof => "verify payer state opening",
            }
        }

        fn corrupt(
            self,
            quote: &mut operator_rpc::PaymentQuoteResponse,
            status: &mut settlement_rpc::StatusResponse,
        ) {
            match self {
                Self::WrongDeployment => {
                    status.deployment = Sha256::hash(&[b"wrong-settlement-deployment"]);
                }
                Self::HardFaulted => status.hard_faulted = true,
                Self::MismatchedStateRoot => {
                    status.state_root.digest = Sha256::hash(&[b"different-state-root"]);
                }
                Self::WrongAccount => {
                    let account = wallets()[2].public_key();
                    let opening = AccountCache::new::<Sha256>(vec![StateLeaf {
                        account: account.clone(),
                        state: quote.opening.leaf.state,
                    }])
                    .unwrap();
                    quote.root = opening.root();
                    quote.opening = opening.opening(&account).unwrap();
                    status.state_root = quote.root;
                }
                Self::InactivePayer => quote.opening.leaf.state.active = false,
                Self::ZeroBalance => quote.opening.leaf.state.balance = 0,
                Self::InvalidProof => {
                    quote.opening.proof.proof.leaf_count = 2;
                    quote
                        .opening
                        .proof
                        .proof
                        .siblings
                        .push(Sha256::hash(&[b"invalid-payer-opening"]));
                }
            }
        }
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
                        body: payment_quote_response(
                            payment_context.clone(),
                            AccountState {
                                balance: 100,
                                cumulative_debit: 10_000,
                                ..AccountState::default()
                            },
                        )
                        .encode(),
                    }
                })
                .await;
                respond(&mut listener, |request| {
                    assert!(matches!(request, operator_rpc::OperatorRequest::Status));
                    rpc::Response::Success {
                        body: settlement_status_response().encode(),
                    }
                })
                .await;

                let mut first_payment = None;
                respond(&mut listener, |request| {
                    let operator_rpc::OperatorRequest::AcceptSend(request) = request else {
                        panic!("payment retry unexpectedly requested another quote");
                    };
                    assert_eq!(request.send.body().cumulative_debit(), 7);
                    let recipient = request.send.body().entries()[0].recipient().clone();
                    let receipt = SignedReceipt::issue_next::<Sha256, _>(
                        &payment_context,
                        &request.send,
                        &recipient,
                        0,
                        0,
                        0,
                        operator.signer(),
                    )
                    .unwrap();
                    let linked =
                        Payment::new::<Sha256>(&payment_context, request.send.clone(), receipt)
                            .unwrap();
                    let (send, receipt) = linked.into_parts();
                    first_payment = Some(Acceptance {
                        send,
                        receipts: vec![receipt],
                    });
                    let forged = SignedReceipt::sign_body_by_authority(
                        first_payment.as_ref().unwrap().receipts[0].body().clone(),
                        impostor.signer(),
                    );
                    rpc::Response::Success {
                        body: operator_rpc::AcceptedBatchResponse {
                            epoch: payment_context.epoch(),
                            sequence: 0,
                            total: 7,
                            acceptance: Acceptance {
                                send: request.send,
                                receipts: vec![forged],
                            },
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
                    assert_eq!(request.send, first_payment.send);
                    rpc::Response::Success {
                        body: operator_rpc::AcceptedBatchResponse {
                            epoch: payment_context.epoch(),
                            sequence: 0,
                            total: 7,
                            acceptance: first_payment.clone(),
                        }
                        .encode(),
                    }
                })
                .await;
                respond_registration(&mut listener, &payment_context).await;

                respond(&mut listener, |request| {
                    assert!(matches!(
                        request,
                        operator_rpc::OperatorRequest::PaymentQuote(_)
                    ));
                    rpc::Response::Success {
                        body: payment_quote_response(
                            payment_context.clone(),
                            AccountState {
                                balance: 93,
                                cumulative_debit: 20_000,
                                ..AccountState::default()
                            },
                        )
                        .encode(),
                    }
                })
                .await;
                respond(&mut listener, |request| {
                    assert!(matches!(request, operator_rpc::OperatorRequest::Status));
                    rpc::Response::Success {
                        body: settlement_status_response().encode(),
                    }
                })
                .await;

                respond(&mut listener, |request| {
                    let operator_rpc::OperatorRequest::AcceptSend(request) = request else {
                        panic!("expected the second signed send");
                    };
                    assert_eq!(request.send.body().cumulative_debit(), 10);
                    let recipient = request.send.body().entries()[0].recipient().clone();
                    let receipt = SignedReceipt::issue_next::<Sha256, _>(
                        &payment_context,
                        &request.send,
                        &recipient,
                        0,
                        7,
                        1,
                        operator.signer(),
                    )
                    .unwrap();
                    let (send, receipt) =
                        Payment::new::<Sha256>(&payment_context, request.send, receipt)
                            .unwrap()
                            .into_parts();
                    let payment = Acceptance {
                        send,
                        receipts: vec![receipt],
                    };
                    rpc::Response::Success {
                        body: operator_rpc::AcceptedBatchResponse {
                            epoch: payment_context.epoch(),
                            sequence: 1,
                            total: 3,
                            acceptance: payment,
                        }
                        .encode(),
                    }
                })
                .await;
                respond_registration(&mut listener, &payment_context).await;
            });

            let mut agent = Agent::new(0).unwrap();
            let rejected = agent
                .pay(&context, operator_address, operator_address, &[(1, 7)])
                .await
                .unwrap_err();
            assert!(format!("{rejected:#}").contains("verify operator receipt"));
            assert_eq!(agent.receipt_count(), 0);

            let accepted = agent
                .pay(&context, operator_address, operator_address, &[(1, 7)])
                .await
                .unwrap();
            assert_eq!(accepted.acceptance.receipts[0].body().amount(), 7);
            assert_eq!(agent.receipt_count(), 1);

            let accepted = agent
                .pay(&context, operator_address, operator_address, &[(1, 3)])
                .await
                .unwrap();
            assert_eq!(accepted.acceptance.receipts[0].body().amount(), 3);
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
    fn pending_deposit_recovery_validates_the_settlement_refund() {
        deterministic::Runner::default().start(|context| async move {
            let agent = Agent::new(0).unwrap();
            let account = agent.account();
            let mut settlement_listener = context
                .bind(SocketAddr::from(([127, 0, 0, 1], 1)))
                .await
                .unwrap();
            let settlement_address = settlement_listener.local_addr().unwrap();
            let expected_account = account.clone();
            let settlement_server = context.child("settlement").spawn(move |_| async move {
                respond_rpc(&mut settlement_listener, |request| {
                    assert_eq!(request.method, settlement_rpc::METHOD_CLAIM_PENDING_DEPOSIT);
                    let claim =
                        settlement_rpc::ClaimPendingDepositRequest::decode(request.body).unwrap();
                    assert_eq!(claim.account, expected_account);
                    rpc::Response::Success {
                        body: settlement_rpc::ClaimPendingDepositResponse {
                            account: wallets()[1].public_key(),
                            amount: 7,
                        }
                        .encode(),
                    }
                })
                .await;
                respond_rpc(&mut settlement_listener, |request| {
                    assert_eq!(request.method, settlement_rpc::METHOD_CLAIM_PENDING_DEPOSIT);
                    let claim =
                        settlement_rpc::ClaimPendingDepositRequest::decode(request.body).unwrap();
                    assert_eq!(claim.account, expected_account);
                    rpc::Response::Success {
                        body: settlement_rpc::ClaimPendingDepositResponse {
                            account: expected_account,
                            amount: 0,
                        }
                        .encode(),
                    }
                })
                .await;
            });

            let error = agent
                .recover_pending_deposit(&context, settlement_address)
                .await
                .unwrap_err();
            assert!(format!("{error:#}").contains("refunded another account"));
            let error = agent
                .recover_pending_deposit(&context, settlement_address)
                .await
                .unwrap_err();
            assert!(format!("{error:#}").contains("zero deposit refund"));
            settlement_server.await.unwrap();
        });
    }

    #[test]
    fn deposit_response_loss_preserves_exact_retry_until_acknowledged() {
        deterministic::Runner::default().start(|context| async move {
            let mut settlement = Settlement::new().unwrap();
            let mut settlement_listener = context
                .bind(SocketAddr::from(([127, 0, 0, 1], 1)))
                .await
                .unwrap();
            let settlement_address = settlement_listener.local_addr().unwrap();
            let settlement_server = context.child("settlement").spawn(move |_| async move {
                for _ in 0..2 {
                    respond_rpc(&mut settlement_listener, |request| {
                        assert_eq!(request.method, settlement_rpc::METHOD_DEPOSIT);
                        settlement_rpc::handle(&mut settlement, request)
                    })
                    .await;
                }
                settlement.status().unwrap().custody_balance
            });

            let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
            let mut operator_listener = context
                .bind(SocketAddr::from(([127, 0, 0, 1], 2)))
                .await
                .unwrap();
            let operator_address = operator_listener.local_addr().unwrap();
            let operator_server = context.child("operator").spawn(move |_| async move {
                let (_, sink, mut stream) = operator_listener.accept().await.unwrap();
                let first = rpc::recv_request(&mut stream).await.unwrap();
                assert_eq!(first.method, operator_rpc::METHOD_APPLY_DEPOSIT);
                let first_body = first.body.clone();
                let first = operator_rpc::decode_request(first).unwrap();
                assert!(matches!(
                    operator_rpc::handle_decoded(&mut operator, first),
                    rpc::Response::Success { .. }
                ));
                drop(sink);

                respond_rpc(&mut operator_listener, |request| {
                    assert_eq!(request.method, operator_rpc::METHOD_APPLY_DEPOSIT);
                    assert_eq!(request.body, first_body);
                    let request = operator_rpc::decode_request(request).unwrap();
                    operator_rpc::handle_decoded(&mut operator, request)
                })
                .await;
            });

            let mut agent = Agent::new(0).unwrap();
            let first = agent
                .deposit(&context, settlement_address, operator_address, 7)
                .await
                .unwrap();
            let DepositOutcome::Recorded { event, error } = first else {
                panic!("lost operator response unexpectedly applied deposit");
            };
            assert!(format!("{error:#}").contains("credit operator deposit"));
            assert_eq!(agent.pending_deposit.as_ref(), Some(&event));
            assert_eq!(agent.deposit_nonce, 0);

            let retry = agent
                .deposit(&context, settlement_address, operator_address, 7)
                .await
                .unwrap();
            let DepositOutcome::Applied {
                epoch,
                event: applied,
            } = retry
            else {
                panic!("exact deposit retry was not acknowledged");
            };
            assert_eq!(epoch, 0);
            assert_eq!(applied, event);
            assert!(agent.pending_deposit.is_none());
            assert_eq!(agent.deposit_nonce, 1);
            assert_eq!(settlement_server.await.unwrap(), 407);
            operator_server.await.unwrap();
        });
    }

    #[test]
    fn deposit_nonce_overflow_precedes_custody() {
        deterministic::Runner::default().start(|context| async move {
            let mut agent = Agent::new(0).unwrap();
            agent.deposit_nonce = u64::MAX;
            let error = agent
                .deposit(
                    &context,
                    SocketAddr::from(([127, 0, 0, 1], 1)),
                    SocketAddr::from(([127, 0, 0, 1], 2)),
                    7,
                )
                .await
                .unwrap_err();
            assert!(format!("{error:#}").contains("deposit nonce overflow"));
            assert!(agent.pending_deposit.is_none());
        });
    }

    #[test]
    fn conflicting_deposit_acks_preserve_pending_custody() {
        deterministic::Runner::default().start(|context| async move {
            for case in 0..4 {
                let mut settlement_listener = context
                    .bind(SocketAddr::from(([127, 0, 0, 1], 10 + case * 2)))
                    .await
                    .unwrap();
                let settlement_address = settlement_listener.local_addr().unwrap();
                let settlement_server = context.child("settlement").spawn(move |_| async move {
                    respond_rpc(&mut settlement_listener, |request| {
                        assert_eq!(request.method, settlement_rpc::METHOD_DEPOSIT);
                        rpc::Response::Success { body: Bytes::new() }
                    })
                    .await;
                });

                let mut operator_listener = context
                    .bind(SocketAddr::from(([127, 0, 0, 1], 11 + case * 2)))
                    .await
                    .unwrap();
                let operator_address = operator_listener.local_addr().unwrap();
                let operator_server = context.child("operator").spawn(move |_| async move {
                    respond_rpc(&mut operator_listener, |request| {
                        assert_eq!(request.method, operator_rpc::METHOD_APPLY_DEPOSIT);
                        let operator_rpc::OperatorRequest::ApplyDeposit(request) =
                            operator_rpc::decode_request(request).unwrap()
                        else {
                            panic!("expected a deposit request");
                        };
                        if case == 3 {
                            return rpc::Response::Success {
                                body: Bytes::from_static(&[0]),
                            };
                        }
                        let mut ack = operator_rpc::DepositAck {
                            epoch: 0,
                            id: request.id,
                            account: request.account,
                            amount: request.amount,
                        };
                        match case {
                            0 => ack.id = Sha256::hash(&[b"another-deposit-id"]),
                            1 => ack.account = wallets()[1].public_key(),
                            2 => ack.amount += 1,
                            _ => unreachable!(),
                        }
                        rpc::Response::Success { body: ack.encode() }
                    })
                    .await;
                });

                let mut agent = Agent::new(0).unwrap();
                let outcome = agent
                    .deposit(&context, settlement_address, operator_address, 7)
                    .await
                    .unwrap();
                let DepositOutcome::Recorded { event, .. } = outcome else {
                    panic!("conflicting operator response cleared pending custody");
                };
                assert_eq!(agent.pending_deposit.as_ref(), Some(&event));
                assert_eq!(agent.deposit_nonce, 0);
                settlement_server.await.unwrap();
                operator_server.await.unwrap();
            }
        });
    }

    #[test]
    fn withdrawal_response_loss_and_wrong_ack_preserve_one_exact_queue() {
        deterministic::Runner::default().start(|context| async move {
            let mut settlement = Settlement::new().unwrap();
            let mut settlement_listener = context
                .bind(SocketAddr::from(([127, 0, 0, 1], 1)))
                .await
                .unwrap();
            let settlement_address = settlement_listener.local_addr().unwrap();
            let settlement_server = context.child("settlement").spawn(move |_| async move {
                for expected in [
                    settlement_rpc::METHOD_STATUS,
                    settlement_rpc::METHOD_QUEUE_WITHDRAWAL,
                ] {
                    respond_rpc(&mut settlement_listener, |request| {
                        assert_eq!(request.method, expected);
                        settlement_rpc::handle(&mut settlement, request)
                    })
                    .await;
                }
            });

            let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
            let mut operator_listener = context
                .bind(SocketAddr::from(([127, 0, 0, 1], 2)))
                .await
                .unwrap();
            let operator_address = operator_listener.local_addr().unwrap();
            let operator_server = context.child("operator").spawn(move |_| async move {
                respond_rpc(&mut operator_listener, |request| {
                    assert_eq!(request.method, operator_rpc::METHOD_WITHDRAWAL_OPENING);
                    let request = operator_rpc::decode_request(request).unwrap();
                    operator_rpc::handle_decoded(&mut operator, request)
                })
                .await;

                let (_, sink, mut stream) = operator_listener.accept().await.unwrap();
                let first = rpc::recv_request(&mut stream).await.unwrap();
                assert_eq!(first.method, operator_rpc::METHOD_APPLY_WITHDRAWAL);
                let first_body = first.body.clone();
                let first = operator_rpc::decode_request(first).unwrap();
                assert!(matches!(
                    operator_rpc::handle_decoded(&mut operator, first),
                    rpc::Response::Success { .. }
                ));
                drop(sink);

                respond_rpc(&mut operator_listener, |request| {
                    assert_eq!(request.method, operator_rpc::METHOD_APPLY_WITHDRAWAL);
                    assert_eq!(request.body, first_body);
                    let request = operator_rpc::decode_request(request).unwrap();
                    assert!(matches!(
                        operator_rpc::handle_decoded(&mut operator, request),
                        rpc::Response::Success { .. }
                    ));
                    rpc::Response::Success {
                        body: operator_rpc::WithdrawalAck {
                            epoch: 0,
                            digest: Sha256::hash(&[b"another-withdrawal"]),
                        }
                        .encode(),
                    }
                })
                .await;

                respond_rpc(&mut operator_listener, |request| {
                    assert_eq!(request.method, operator_rpc::METHOD_APPLY_WITHDRAWAL);
                    assert_eq!(request.body, first_body);
                    let request = operator_rpc::decode_request(request).unwrap();
                    operator_rpc::handle_decoded(&mut operator, request)
                })
                .await;
            });

            let action = WithdrawalAction::Amount(NonZeroU64::new(7).unwrap());
            let mut agent = Agent::new(0).unwrap();
            let first = agent
                .withdraw(&context, settlement_address, operator_address, action)
                .await
                .unwrap();
            let WithdrawalOutcome::Queued { request, error } = first else {
                panic!("lost operator response unexpectedly applied withdrawal");
            };
            assert!(format!("{error:#}").contains("apply operator withdrawal"));
            assert!(agent.pending_withdrawal.as_ref().unwrap().queued);

            let wrong_ack = agent
                .withdraw(&context, settlement_address, operator_address, action)
                .await
                .unwrap();
            let WithdrawalOutcome::Queued {
                request: retained,
                error,
            } = wrong_ack
            else {
                panic!("wrong operator acknowledgement cleared withdrawal");
            };
            assert_eq!(retained, request);
            assert!(format!("{error:#}").contains("another withdrawal"));
            assert!(agent.pending_withdrawal.as_ref().unwrap().queued);

            let retry = agent
                .withdraw(&context, settlement_address, operator_address, action)
                .await
                .unwrap();
            let WithdrawalOutcome::Applied {
                epoch,
                request: applied,
            } = retry
            else {
                panic!("exact withdrawal retry was not acknowledged");
            };
            assert_eq!(epoch, 0);
            assert_eq!(applied, request);
            assert!(agent.pending_withdrawal.is_none());
            settlement_server.await.unwrap();
            operator_server.await.unwrap();
        });
    }

    #[test]
    fn withdrawal_uses_only_the_exact_retained_head_when_the_operator_is_unreachable() {
        deterministic::Runner::default().start(|context| async move {
            let account = wallets()[0].public_key();
            let current = AccountCache::new::<Sha256>(vec![StateLeaf {
                account: account.clone(),
                state: AccountState {
                    balance: 100,
                    active: true,
                    ..AccountState::default()
                },
            }])
            .unwrap();
            let stale = AccountCache::new::<Sha256>(vec![StateLeaf {
                account: account.clone(),
                state: AccountState {
                    balance: 99,
                    active: true,
                    ..AccountState::default()
                },
            }])
            .unwrap();
            let current_root = current.root();
            let current_opening = current.opening(&account).unwrap();
            let stale_root = stale.root();
            let stale_opening = stale.opening(&account).unwrap();
            assert_ne!(current_root, stale_root);

            let mut agent = Agent::new(0).unwrap();
            agent
                .store
                .retain_recovery_opening(&current_root, &current_opening)
                .unwrap();
            agent
                .store
                .retain_recovery_opening(&stale_root, &stale_opening)
                .unwrap();

            let mut settlement_listener = context
                .bind(SocketAddr::from(([127, 0, 0, 1], 1)))
                .await
                .unwrap();
            let settlement_address = settlement_listener.local_addr().unwrap();
            let expected_opening = current_opening.clone();
            let settlement_server = context.child("settlement").spawn(move |_| async move {
                respond_rpc(&mut settlement_listener, |request| {
                    assert_eq!(request.method, settlement_rpc::METHOD_STATUS);
                    let mut status = settlement_status_response();
                    status.state_root = current_root;
                    rpc::Response::Success {
                        body: status.encode(),
                    }
                })
                .await;
                respond_rpc(&mut settlement_listener, |request| {
                    assert_eq!(request.method, settlement_rpc::METHOD_QUEUE_WITHDRAWAL);
                    let queued =
                        settlement_rpc::QueueWithdrawalRequest::decode(request.body).unwrap();
                    assert_eq!(queued.request.body().state_root(), &current_root.digest);
                    assert_eq!(queued.openings, [expected_opening]);
                    rpc::Response::Success { body: Bytes::new() }
                })
                .await;
            });

            let outcome = agent
                .withdraw(
                    &context,
                    settlement_address,
                    SocketAddr::from(([127, 0, 0, 1], 2)),
                    WithdrawalAction::Amount(NonZeroU64::new(7).unwrap()),
                )
                .await
                .unwrap();
            let WithdrawalOutcome::Queued { request, error } = outcome else {
                panic!("unreachable operator unexpectedly applied withdrawal");
            };
            assert_eq!(
                request.body().action(),
                &WithdrawalAction::Amount(NonZeroU64::new(7).unwrap())
            );
            assert!(format!("{error:#}").contains("apply operator withdrawal"));
            let pending = agent.pending_withdrawal.as_ref().unwrap();
            assert!(pending.queued);
            assert_eq!(pending.queue.openings, [current_opening]);
            settlement_server.await.unwrap();

            let mut wrong_only = Agent::new(0).unwrap();
            wrong_only
                .store
                .retain_recovery_opening(&stale_root, &stale_opening)
                .unwrap();
            let mut settlement_listener = context
                .bind(SocketAddr::from(([127, 0, 0, 1], 3)))
                .await
                .unwrap();
            let settlement_address = settlement_listener.local_addr().unwrap();
            let settlement_server =
                context
                    .child("wrong_only_settlement")
                    .spawn(move |_| async move {
                        respond_rpc(&mut settlement_listener, |request| {
                            assert_eq!(request.method, settlement_rpc::METHOD_STATUS);
                            let mut status = settlement_status_response();
                            status.state_root = current_root;
                            rpc::Response::Success {
                                body: status.encode(),
                            }
                        })
                        .await;
                    });

            let error = wrong_only
                .withdraw(
                    &context,
                    settlement_address,
                    SocketAddr::from(([127, 0, 0, 1], 4)),
                    WithdrawalAction::Close,
                )
                .await
                .unwrap_err();
            assert!(format!("{error:#}").contains("read withdrawal opening"));
            assert!(wrong_only.pending_withdrawal.is_none());
            settlement_server.await.unwrap();
        });
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
                        body: payment_quote_response(
                            payment_context,
                            AccountState {
                                balance: 100,
                                cumulative_debit: 50_000,
                                ..AccountState::default()
                            },
                        )
                        .encode(),
                    }
                })
                .await;
            });

            let mut agent = Agent::open(database.path(), 0).unwrap();
            let error = agent
                .pay(&context, operator_address, operator_address, &[(1, 7)])
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
    fn adversarial_payment_quotes_are_rejected_before_send_or_persistence() {
        deterministic::Runner::default().start(|context| async move {
            for (case_index, case) in PaymentQuoteGateCase::ALL.into_iter().enumerate() {
                let database = TempDatabase::new();
                let payment_context = PaymentContext::new(
                    Sha256::hash(&[b"adversarial-payment-quote"]),
                    7,
                    operator_key(),
                );
                let mut quote = payment_quote_response(
                    payment_context,
                    AccountState {
                        balance: 100,
                        ..AccountState::default()
                    },
                );
                let mut status = settlement_status_response();
                status.state_root = quote.root;
                case.corrupt(&mut quote, &mut status);
                let rejected_root = quote.root;
                let base_port = u16::try_from(case_index).unwrap() * 2;

                let mut operator_listener = context
                    .bind(SocketAddr::from(([127, 0, 0, 1], base_port + 1)))
                    .await
                    .unwrap();
                let operator_address = operator_listener.local_addr().unwrap();
                let mut settlement_listener = context
                    .bind(SocketAddr::from(([127, 0, 0, 1], base_port + 2)))
                    .await
                    .unwrap();
                let settlement_address = settlement_listener.local_addr().unwrap();
                let server = context.child(case.actor()).spawn(move |_| async move {
                    respond(&mut operator_listener, |request| {
                        let operator_rpc::OperatorRequest::PaymentQuote(request) = request else {
                            panic!("expected one payment quote request");
                        };
                        assert_eq!(request.account, wallets()[0].public_key());
                        rpc::Response::Success {
                            body: quote.encode(),
                        }
                    })
                    .await;
                    respond_rpc(&mut settlement_listener, |request| {
                        assert_eq!(request.method, settlement_rpc::METHOD_STATUS);
                        assert_eq!(request.body, settlement_rpc::StatusRequest.encode());
                        rpc::Response::Success {
                            body: status.encode(),
                        }
                    })
                    .await;
                });

                let mut agent = Agent::open(database.path(), 0).unwrap();
                let error = agent
                    .pay(&context, settlement_address, operator_address, &[(1, 7)])
                    .await
                    .unwrap_err();
                let error = format!("{error:#}");
                assert!(
                    error.contains(case.expected_error()),
                    "{case:?} returned an unexpected error: {error}"
                );
                drop(agent);
                server.await.unwrap();

                let recovered = Agent::open(database.path(), 0).unwrap();
                assert_eq!(recovered.cumulative_debit, 0, "{case:?}");
                assert!(recovered.pending_payment.is_none(), "{case:?}");
                assert_eq!(recovered.receipt_count(), 0, "{case:?}");
                assert!(
                    recovered
                        .store
                        .recovery_opening(&rejected_root)
                        .unwrap()
                        .is_none(),
                    "{case:?} retained an unauthenticated payer opening"
                );
            }
        });
    }

    #[test]
    fn unregistered_valid_payment_context_does_not_commit() {
        deterministic::Runner::default().start(|context| async move {
            let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();

            let mut operator_listener = context
                .bind(SocketAddr::from(([127, 0, 0, 1], 1)))
                .await
                .unwrap();
            let operator_address = operator_listener.local_addr().unwrap();
            let operator_server = context.child("operator").spawn(move |_| async move {
                let mut first_send = None;
                for expected in [
                    operator_rpc::METHOD_PAYMENT_QUOTE,
                    operator_rpc::METHOD_ACCEPT_SEND,
                    operator_rpc::METHOD_ACCEPT_SEND,
                ] {
                    respond_rpc(&mut operator_listener, |request| {
                        assert_eq!(request.method, expected);
                        let request = operator_rpc::decode_request(request).unwrap();
                        if let operator_rpc::OperatorRequest::AcceptSend(request) = &request {
                            if let Some(first) = &first_send {
                                assert_eq!(&request.send, first);
                            } else {
                                first_send = Some(request.send.clone());
                            }
                        }
                        operator_rpc::handle_decoded(&mut operator, request)
                    })
                    .await;
                }
            });

            let mut settlement = Settlement::new().unwrap();
            let mut settlement_listener = context
                .bind(SocketAddr::from(([127, 0, 0, 1], 2)))
                .await
                .unwrap();
            let settlement_address = settlement_listener.local_addr().unwrap();
            let settlement_server = context.child("settlement").spawn(move |_| async move {
                for expected in [
                    settlement_rpc::METHOD_STATUS,
                    settlement_rpc::METHOD_CONFIRM_REGISTRATION,
                ] {
                    respond_rpc(&mut settlement_listener, |request| {
                        assert_eq!(request.method, expected);
                        settlement_rpc::handle(&mut settlement, request)
                    })
                    .await;
                }
                settlement
                    .register_epoch(0, 400, DepositBatch::empty(), WithdrawalBatch::empty())
                    .unwrap();
                respond_rpc(&mut settlement_listener, |request| {
                    assert_eq!(request.method, settlement_rpc::METHOD_CONFIRM_REGISTRATION);
                    settlement_rpc::handle(&mut settlement, request)
                })
                .await;
            });

            let mut agent = Agent::new(0).unwrap();
            let error = agent
                .pay(&context, settlement_address, operator_address, &[(1, 7)])
                .await
                .unwrap_err();
            let error = format!("{error:#}");
            assert!(error.contains("confirm payment registration"));
            assert!(error.contains("payment registration is no longer live"));
            assert_eq!(agent.cumulative_debit, 0);
            assert_eq!(agent.receipt_count(), 0);
            let pending = agent.pending_payment.as_ref().unwrap();
            assert!(
                agent
                    .store
                    .recovery_opening(&pending.recovery_root)
                    .unwrap()
                    .is_some()
            );

            let accepted = agent
                .pay(&context, settlement_address, operator_address, &[(1, 7)])
                .await
                .unwrap();
            assert_eq!(accepted.acceptance.receipts[0].body().amount(), 7);
            assert_eq!(agent.cumulative_debit, 7);
            assert_eq!(agent.receipt_count(), 1);
            assert!(agent.pending_payment.is_none());
            operator_server.await.unwrap();
            settlement_server.await.unwrap();
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
                        body: payment_quote_response(
                            payment_context.clone(),
                            AccountState {
                                balance: 100,
                                cumulative_debit: 50_000,
                                ..AccountState::default()
                            },
                        )
                        .encode(),
                    }
                })
                .await;
                respond(&mut listener, |request| {
                    assert!(matches!(request, operator_rpc::OperatorRequest::Status));
                    rpc::Response::Success {
                        body: settlement_status_response().encode(),
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
                    let recipient = first_send.body().entries()[0].recipient().clone();
                    let receipt = SignedReceipt::issue_next::<Sha256, _>(
                        &payment_context,
                        &first_send,
                        &recipient,
                        0,
                        0,
                        0,
                        operator.signer(),
                    )
                    .unwrap();
                    let (send, receipt) =
                        Payment::new::<Sha256>(&payment_context, first_send.clone(), receipt)
                            .unwrap()
                            .into_parts();
                    accepted = Acceptance {
                        send,
                        receipts: vec![receipt],
                    };
                }

                respond(&mut listener, |request| {
                    let operator_rpc::OperatorRequest::AcceptSend(request) = request else {
                        panic!("restart unexpectedly requested another quote");
                    };
                    assert_eq!(request.send.encode(), first_send.encode());
                    rpc::Response::Success {
                        body: operator_rpc::AcceptedBatchResponse {
                            epoch: payment_context.epoch(),
                            sequence: 0,
                            total: 7,
                            acceptance: accepted,
                        }
                        .encode(),
                    }
                })
                .await;
                respond_registration(&mut listener, &payment_context).await;
            });

            let mut agent = Agent::open(database.path(), 0).unwrap();
            let error = agent
                .pay(&context, operator_address, operator_address, &[(1, 7)])
                .await
                .unwrap_err();
            assert!(format!("{error:#}").contains("submit payment"));
            assert!(agent.pending_payment.is_some());
            drop(agent);

            let mut recovered = Agent::open(database.path(), 0).unwrap();
            assert!(recovered.pending_payment.is_some());
            let accepted = recovered
                .pay(&context, operator_address, operator_address, &[(1, 7)])
                .await
                .unwrap();
            assert_eq!(accepted.acceptance.receipts[0].body().amount(), 7);
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
                        body: payment_quote_response(
                            payment_context.clone(),
                            AccountState {
                                balance: 100,
                                cumulative_debit: 10_000,
                                ..AccountState::default()
                            },
                        )
                        .encode(),
                    }
                })
                .await;
                respond(&mut listener, |request| {
                    assert!(matches!(request, operator_rpc::OperatorRequest::Status));
                    rpc::Response::Success {
                        body: settlement_status_response().encode(),
                    }
                })
                .await;
                respond(&mut listener, |request| {
                    let operator_rpc::OperatorRequest::AcceptSend(request) = request else {
                        panic!("expected the first signed send");
                    };
                    assert_eq!(request.send.body().cumulative_debit(), 7);
                    let recipient = request.send.body().entries()[0].recipient().clone();
                    let receipt = SignedReceipt::issue_next::<Sha256, _>(
                        &payment_context,
                        &request.send,
                        &recipient,
                        0,
                        0,
                        0,
                        operator.signer(),
                    )
                    .unwrap();
                    let (send, receipt) =
                        Payment::new::<Sha256>(&payment_context, request.send, receipt)
                            .unwrap()
                            .into_parts();
                    let payment = Acceptance {
                        send,
                        receipts: vec![receipt],
                    };
                    rpc::Response::Success {
                        body: operator_rpc::AcceptedBatchResponse {
                            epoch: payment_context.epoch(),
                            sequence: 0,
                            total: 7,
                            acceptance: payment,
                        }
                        .encode(),
                    }
                })
                .await;
                respond_registration(&mut listener, &payment_context).await;
                respond(&mut listener, |request| {
                    assert!(matches!(
                        request,
                        operator_rpc::OperatorRequest::PaymentQuote(_)
                    ));
                    rpc::Response::Success {
                        body: payment_quote_response(
                            payment_context.clone(),
                            AccountState {
                                balance: 93,
                                cumulative_debit: 20_000,
                                ..AccountState::default()
                            },
                        )
                        .encode(),
                    }
                })
                .await;
                respond(&mut listener, |request| {
                    assert!(matches!(request, operator_rpc::OperatorRequest::Status));
                    rpc::Response::Success {
                        body: settlement_status_response().encode(),
                    }
                })
                .await;
                respond(&mut listener, |request| {
                    let operator_rpc::OperatorRequest::AcceptSend(request) = request else {
                        panic!("expected the second signed send");
                    };
                    assert_eq!(request.send.body().cumulative_debit(), 10);
                    let recipient = request.send.body().entries()[0].recipient().clone();
                    let receipt = SignedReceipt::issue_next::<Sha256, _>(
                        &payment_context,
                        &request.send,
                        &recipient,
                        0,
                        7,
                        1,
                        operator.signer(),
                    )
                    .unwrap();
                    let (send, receipt) =
                        Payment::new::<Sha256>(&payment_context, request.send, receipt)
                            .unwrap()
                            .into_parts();
                    let payment = Acceptance {
                        send,
                        receipts: vec![receipt],
                    };
                    rpc::Response::Success {
                        body: operator_rpc::AcceptedBatchResponse {
                            epoch: payment_context.epoch(),
                            sequence: 1,
                            total: 3,
                            acceptance: payment,
                        }
                        .encode(),
                    }
                })
                .await;
                respond_registration(&mut listener, &payment_context).await;
            });

            let mut agent = Agent::open(database.path(), 0).unwrap();
            agent
                .pay(&context, operator_address, operator_address, &[(1, 7)])
                .await
                .unwrap();
            drop(agent);

            let mut recovered = Agent::open(database.path(), 0).unwrap();
            assert_eq!(recovered.cumulative_debit, 7);
            assert_eq!(recovered.receipt_count(), 1);
            recovered
                .pay(&context, operator_address, operator_address, &[(1, 3)])
                .await
                .unwrap();
            drop(recovered);

            let recovered = Agent::open(database.path(), 0).unwrap();
            assert_eq!(recovered.cumulative_debit, 10);
            assert_eq!(recovered.receipt_count(), 2);
            operator_server.await.unwrap();
        });
    }

    #[test]
    fn withdrawal_claim_ack_loss_recovers_after_agent_restart() {
        deterministic::Runner::default().start(|context| async move {
            let database = TempDatabase::new();
            let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
            operator
                .withdraw(0, WithdrawalAction::Amount(NonZeroU64::new(25).unwrap()))
                .unwrap();
            operator.start_close(0).unwrap();
            operator.wait_for_closes().unwrap();

            let account = wallets()[0].public_key();
            let evidence = operator.withdrawal_evidence(&account).unwrap();
            let evidence = operator_rpc::WithdrawalEvidenceResponse {
                batch_id: evidence.batch_id,
                account: evidence.account,
                claim: evidence.claim,
            };
            let release = settlement_rpc::WithdrawalResponse {
                amount: evidence.claim.output().amount(),
                destination: evidence.claim.output().destination().clone(),
            };

            let mut settlement_listener = context
                .bind(SocketAddr::from(([127, 0, 0, 1], 1)))
                .await
                .unwrap();
            let settlement_address = settlement_listener.local_addr().unwrap();
            let settlement_evidence = evidence.clone();
            let settlement_release = release.clone();
            let settlement_server = context.child("settlement").spawn(move |_| async move {
                for _ in 0..2 {
                    respond_rpc(&mut settlement_listener, |request| {
                        assert_eq!(request.method, settlement_rpc::METHOD_CLAIM_WITHDRAWAL);
                        let request =
                            settlement_rpc::WithdrawalClaimRequest::decode(request.body).unwrap();
                        assert_eq!(request.batch_id, settlement_evidence.batch_id);
                        assert_eq!(request.claim, settlement_evidence.claim);
                        rpc::Response::Success {
                            body: settlement_release.encode(),
                        }
                    })
                    .await;
                }
            });

            let mut operator_listener = context
                .bind(SocketAddr::from(([127, 0, 0, 1], 2)))
                .await
                .unwrap();
            let operator_address = operator_listener.local_addr().unwrap();
            let operator_evidence = evidence.clone();
            let operator_server = context.child("operator").spawn(move |_| async move {
                respond(&mut operator_listener, |request| {
                    let operator_rpc::OperatorRequest::WithdrawalEvidence(request) = request else {
                        panic!("expected withdrawal evidence request");
                    };
                    assert_eq!(request.account, operator_evidence.account);
                    rpc::Response::Success {
                        body: operator_rpc::WithdrawalEvidenceResponse {
                            batch_id: operator_evidence.batch_id,
                            account: operator_evidence.account.clone(),
                            claim: operator_evidence.claim.clone(),
                        }
                        .encode(),
                    }
                })
                .await;

                let (_, sink, mut stream) = operator_listener.accept().await.unwrap();
                let request =
                    operator_rpc::decode_request(rpc::recv_request(&mut stream).await.unwrap())
                        .unwrap();
                let operator_rpc::OperatorRequest::AcknowledgeWithdrawal(request) = request else {
                    panic!("expected withdrawal acknowledgement");
                };
                assert_eq!(request.as_ref(), &operator_evidence);
                assert!(matches!(
                    operator_rpc::acknowledge_withdrawal_confirmed(&mut operator, &request),
                    rpc::Response::Success { .. }
                ));
                drop(sink);

                respond(&mut operator_listener, |request| {
                    let operator_rpc::OperatorRequest::AcknowledgeWithdrawal(request) = request
                    else {
                        panic!("restart requested withdrawal evidence again");
                    };
                    assert_eq!(request.as_ref(), &operator_evidence);
                    operator_rpc::acknowledge_withdrawal_confirmed(&mut operator, &request)
                })
                .await;
            });

            let mut agent = Agent::open(database.path(), 0).unwrap();
            let lost = agent
                .claim_withdrawal(&context, settlement_address, operator_address)
                .await
                .unwrap_err();
            assert!(format!("{lost:#}").contains("acknowledge claimed withdrawal"));
            drop(agent);

            let mut recovered = Agent::open(database.path(), 0).unwrap();
            assert!(recovered.pending_withdrawal_claim.is_some());
            assert_eq!(
                recovered
                    .claim_withdrawal(&context, settlement_address, operator_address)
                    .await
                    .unwrap(),
                release
            );
            assert!(recovered.pending_withdrawal_claim.is_none());
            drop(recovered);

            let recovered = Agent::open(database.path(), 0).unwrap();
            assert!(recovered.pending_withdrawal_claim.is_none());
            operator_server.await.unwrap();
            settlement_server.await.unwrap();
        });
    }

    #[test]
    fn external_payout_ack_loss_recovers_after_agent_restart() {
        deterministic::Runner::default().start(|context| async move {
            let database = TempDatabase::new();
            let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
            operator.pay(0, operator.wallet_count(), 100).unwrap();
            operator.start_close(0).unwrap();
            operator.wait_for_closes().unwrap();

            let identity = wallets().len();
            let account = external_identity().key;
            let evidence = operator.external_payout_evidence(&account).unwrap();
            let evidence = operator_rpc::ExternalPayoutEvidenceResponse {
                batch_id: evidence.batch_id,
                claim: evidence.claim,
            };
            let payout = settlement_rpc::ExternalPayoutResponse {
                recipient: account.clone(),
                amount: 100,
            };

            let mut settlement_listener = context
                .bind(SocketAddr::from(([127, 0, 0, 1], 3)))
                .await
                .unwrap();
            let settlement_address = settlement_listener.local_addr().unwrap();
            let settlement_evidence = evidence.clone();
            let settlement_payout = payout.clone();
            let settlement_server = context.child("settlement").spawn(move |_| async move {
                for _ in 0..2 {
                    respond_rpc(&mut settlement_listener, |request| {
                        assert_eq!(request.method, settlement_rpc::METHOD_CLAIM_EXTERNAL_PAYOUT);
                        let request =
                            settlement_rpc::ExternalPayoutClaimRequest::decode(request.body)
                                .unwrap();
                        assert_eq!(request.batch_id, settlement_evidence.batch_id);
                        assert_eq!(request.claim, settlement_evidence.claim);
                        rpc::Response::Success {
                            body: settlement_payout.encode(),
                        }
                    })
                    .await;
                }
            });

            let mut operator_listener = context
                .bind(SocketAddr::from(([127, 0, 0, 1], 4)))
                .await
                .unwrap();
            let operator_address = operator_listener.local_addr().unwrap();
            let operator_evidence = evidence.clone();
            let operator_server = context.child("operator").spawn(move |_| async move {
                respond(&mut operator_listener, |request| {
                    let operator_rpc::OperatorRequest::ExternalPayoutEvidence(request) = request
                    else {
                        panic!("expected external-payout evidence request");
                    };
                    assert_eq!(request.account, account);
                    rpc::Response::Success {
                        body: operator_rpc::ExternalPayoutEvidenceResponse {
                            batch_id: operator_evidence.batch_id,
                            claim: operator_evidence.claim.clone(),
                        }
                        .encode(),
                    }
                })
                .await;

                let (_, sink, mut stream) = operator_listener.accept().await.unwrap();
                let request =
                    operator_rpc::decode_request(rpc::recv_request(&mut stream).await.unwrap())
                        .unwrap();
                let operator_rpc::OperatorRequest::AcknowledgeExternalPayout(request) = request
                else {
                    panic!("expected external-payout acknowledgement");
                };
                assert_eq!(request.as_ref(), &operator_evidence);
                assert!(matches!(
                    operator_rpc::acknowledge_external_payout_confirmed(&mut operator, &request),
                    rpc::Response::Success { .. }
                ));
                drop(sink);

                respond(&mut operator_listener, |request| {
                    let operator_rpc::OperatorRequest::AcknowledgeExternalPayout(request) = request
                    else {
                        panic!("restart requested external-payout evidence again");
                    };
                    assert_eq!(request.as_ref(), &operator_evidence);
                    operator_rpc::acknowledge_external_payout_confirmed(&mut operator, &request)
                })
                .await;
            });

            let mut agent = Agent::open(database.path(), identity).unwrap();
            let lost = agent
                .claim_external_payout(&context, settlement_address, operator_address)
                .await
                .unwrap_err();
            assert!(format!("{lost:#}").contains("acknowledge claimed external payout"));
            drop(agent);

            let mut recovered = Agent::open(database.path(), identity).unwrap();
            assert!(recovered.pending_payout_claim.is_some());
            assert_eq!(
                recovered
                    .claim_external_payout(&context, settlement_address, operator_address)
                    .await
                    .unwrap(),
                payout
            );
            assert!(recovered.pending_payout_claim.is_none());
            drop(recovered);

            let recovered = Agent::open(database.path(), identity).unwrap();
            assert!(recovered.pending_payout_claim.is_none());
            operator_server.await.unwrap();
            settlement_server.await.unwrap();
        });
    }
}
