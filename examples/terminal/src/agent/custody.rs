//! Custody flows: deposits, withdrawal authorization and escalation, and recovery.

use super::{
    Agent, evidence::unusable_head, store::PendingWithdrawalClaim, wallet::settlement_status,
};
use crate::{
    chain::{
        client::{Chain, Client, EFFECT_ATTEMPTS, Env, POLL},
        query::Lookup,
        state::{ClaimHardFaultResponse, ClaimPendingDepositResponse, FaultRecord, Record},
        tx::{
            BeginHardFaultSettlementRequest, ClaimHardFaultRequest, ClaimPendingDepositRequest,
            DepositRequest, NativeTransferRequest, QueueWithdrawalRequest, SettlementTx,
        },
    },
    operator::rpc as operator_rpc,
    protocol::{DepositEvent, Key, settlement_config},
};
use anyhow::{Context, Result, ensure};
use commonware_clearing::bajillion::{
    boundary::{SignedWithdrawal, WithdrawalAction},
    qmdb::StateRoot,
};
use commonware_codec::Encode as _;
use commonware_cryptography::{Hasher, Sha256, sha256::Digest};
#[cfg(not(test))]
use rand::RngExt as _;
use std::net::SocketAddr;

pub(super) const DEPOSIT_ID_NAMESPACE: &[u8] = b"_COMMONWARE_EXAMPLES_TERMINAL_AGENT_DEPOSIT";

#[derive(Debug)]
pub(crate) enum WithdrawalOutcome {
    Applied {
        epoch: u64,
        request: SignedWithdrawal<Key, Digest>,
    },
    Signed {
        request: SignedWithdrawal<Key, Digest>,
        error: anyhow::Error,
    },
}

pub(super) fn withdrawal_deadline(now: u64, timing: &crate::protocol::Timing) -> Result<u64> {
    Ok(now.saturating_add(settlement_config(timing)?.maximum_withdrawal_notice.get()))
}

#[cfg(test)]
pub(super) const fn initial_deposit_nonce() -> u64 {
    0
}

#[cfg(not(test))]
pub(super) fn initial_deposit_nonce() -> u64 {
    rand::rng().random()
}

impl Agent {
    /// The saved authorization remains the retry authority until its claim completes.
    pub(crate) fn pending_withdrawal_action(&self) -> Option<WithdrawalAction> {
        self.pending_withdrawal
            .as_ref()
            .map(|request| *request.body().action())
    }

    /// Transfers shared native funds and completes on the exact certified receipt.
    pub(crate) async fn transfer_native<E: Env>(
        &mut self,
        ctx: &E,
        chain: &mut Client,
        to: Key,
        amount: u64,
    ) -> Result<NativeTransferRequest> {
        ensure!(amount > 0, "native transfer amount must be positive");
        let chain_id = chain.genesis().native.chain_id();
        let next_nonce = self
            .deposit_nonce
            .checked_add(1)
            .context("wallet nonce overflow")?;
        let request = match &self.pending_transfer {
            Some(request) => {
                ensure!(
                    request.chain_id == chain_id && request.to == to && request.amount == amount,
                    "another native transfer retry is pending"
                );
                request.clone()
            }
            None => {
                let nonce = initial_deposit_nonce();
                let id = Sha256::hash(&[
                    b"_COMMONWARE_EXAMPLES_TERMINAL_AGENT_TRANSFER",
                    chain_id.as_ref(),
                    self.deployment.as_ref(),
                    self.account().as_ref(),
                    &nonce.to_be_bytes(),
                    &self.deposit_nonce.to_be_bytes(),
                    to.as_ref(),
                    &amount.to_be_bytes(),
                ]);
                let request =
                    NativeTransferRequest::sign(chain_id, id, to, amount, self.wallet.signer());
                self.store
                    .stage_transfer(&request)
                    .context("durably stage native transfer")?;
                self.pending_transfer = Some(request.clone());
                request
            }
        };
        for attempt in 0..EFFECT_ATTEMPTS {
            if let Ok(Some(record)) = chain
                .native_transfer(ctx, chain_id, request.from.clone(), request.id)
                .await
            {
                ensure!(
                    record == request,
                    "native transfer id is bound to another request"
                );
                self.store.complete_transfer(&request)?;
                self.pending_transfer = None;
                self.deposit_nonce = next_nonce;
                return Ok(request);
            }
            if attempt == 0 {
                chain
                    .deliver(ctx, &SettlementTx::NativeTransfer(request.clone()))
                    .await
                    .context("submit native transfer")?;
            }
            ctx.sleep(POLL).await;
        }
        anyhow::bail!("native transfer was not certified in time; exact signed retry retained")
    }

    /// Returns no release when the account is absent from the authenticated frozen state.
    /// Finalized withdrawal reserves remain independently claimable.
    pub(crate) async fn recover_hard_fault<E: Env>(
        &mut self,
        ctx: &E,
        chain: &mut Client,
    ) -> Result<Option<ClaimHardFaultResponse>> {
        // Terminal settlement begins as a transaction whose effect is the
        // certified Settling fault record: a lost response resubmits the
        // same bytes and completes on the same frozen snapshot.
        let begin = SettlementTx::BeginHardFaultSettlement(BeginHardFaultSettlementRequest {
            deployment: self.deployment,
        });
        chain
            .deliver(ctx, &begin)
            .await
            .context("begin hard-fault settlement")?;
        // A read error (an unavailable snapshot, a briefly stale validator)
        // clears with time, so every effect poll keeps polling through it.
        let mut settling = None;
        for _ in 0..EFFECT_ATTEMPTS {
            if let Ok(Some(FaultRecord::Settling(settlement))) = chain.fault(ctx).await {
                settling = Some(settlement);
                break;
            }
            ctx.sleep(POLL).await;
        }
        let hard_fault = settling.context("terminal settlement never certifiably began")?;

        // Only the frozen root owns recoverable state. A retained opening or a
        // validator's authenticated membership or absence resolves that state.
        let opening = match self.store.recovery_opening(&hard_fault.frozen_state_root)? {
            Some(opening) => opening,
            None => {
                let status = chain
                    .status(ctx)
                    .await
                    .context("read the frozen settlement head")?;
                ensure!(
                    status.deployment == self.deployment
                        && status.state_root == hard_fault.frozen_state_root,
                    "the settlement head is not the frozen state root"
                );
                let opening = self
                    .holders
                    .validator_balance(ctx, chain, &self.account(), &status)
                    .await
                    .context(
                        "no payer opening is retained for the frozen state root and the \
                         validators opened none",
                    )?;
                let Some(opening) = opening else {
                    // State absence says nothing about a finalized withdrawal reserve. Only
                    // complete finalized history can retire an uncached authorization.
                    if self
                        .pending_withdrawal_claim
                        .as_ref()
                        .is_some_and(|claim| claim.evidence.is_none())
                        && let Some(request) = self.pending_withdrawal.clone()
                        && self
                            .carried_withdrawal_epoch(ctx, chain, &request, status.last_finalized)
                            .await?
                            .is_none()
                    {
                        self.store.discard_unused_withdrawal(&request)?;
                        self.pending_withdrawal = None;
                        self.pending_withdrawal_claim = None;
                    }
                    return Ok(None);
                };
                opening
            }
        };
        let expected_custody = opening.balance.get();
        let claim = SettlementTx::ClaimHardFault(ClaimHardFaultRequest {
            deployment: self.deployment,
            opening,
        });
        chain
            .deliver(ctx, &claim)
            .await
            .context("claim hard-fault payer state")?;
        let mut released = None;
        for _ in 0..EFFECT_ATTEMPTS {
            if let Ok(Some(record)) = chain.hard_fault(ctx, self.account()).await {
                released = Some(record);
                break;
            }
            ctx.sleep(POLL).await;
        }
        let record = released.context("the hard-fault claim earned no certified release")?;
        ensure!(
            record.root == hard_fault.frozen_state_root,
            "the hard-fault release belongs to another frozen root"
        );
        let release = record.released;
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
        Ok(Some(release))
    }

    pub(crate) async fn recover_pending_deposit<E: Env>(
        &self,
        ctx: &E,
        chain: &mut Client,
    ) -> Result<ClaimPendingDepositResponse> {
        let account = self.account();
        let request = chain.request(Lookup::Fault);
        let terminal = match chain.recent(ctx, &request).await?.record {
            Some(Record::Fault(FaultRecord::Faulted(_))) => false,
            Some(Record::Fault(FaultRecord::Settling(_))) => true,
            _ => anyhow::bail!("deposit recovery requires a certified deployment fault"),
        };
        let claim = SettlementTx::ClaimPendingDeposit(ClaimPendingDepositRequest {
            deployment: self.deployment,
            account: account.clone(),
            terminal,
        });
        chain
            .deliver(ctx, &claim)
            .await
            .context("claim pending settlement deposit")?;
        let mut released = None;
        for _ in 0..EFFECT_ATTEMPTS {
            if let Ok(Some(record)) = chain.refund(ctx, account.clone(), terminal).await {
                released = Some(record);
                break;
            }
            ctx.sleep(POLL).await;
        }
        let refund = released.context("the refund claim earned no certified release")?;
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

    /// Places one deposit at settlement and completes on the certified
    /// custody record.
    ///
    /// The wallet never reports the deposit to the operator: deposits are
    /// chain state, so the operator observes the finalized record on its own
    /// follower and stages the credit itself. The credit shows on a later
    /// verified balance poll, which is the wallet's existing observation
    /// path.
    pub(crate) async fn deposit<E: Env>(
        &mut self,
        ctx: &E,
        chain: &mut Client,
        amount: u64,
    ) -> Result<DepositEvent> {
        ensure!(
            chain.deployment() == self.deployment,
            "deposit client belongs to another deployment"
        );
        ensure!(amount > 0, "deposit amount must be positive");
        let next_deposit_nonce = self
            .deposit_nonce
            .checked_add(1)
            .context("deposit nonce overflow")?;
        let event = match &self.pending_deposit {
            Some(event) => {
                ensure!(
                    event.chain_id == chain.genesis().native.chain_id(),
                    "pending deposit belongs to another chain"
                );
                ensure!(
                    event.event.amount == amount,
                    "another deposit retry is pending"
                );
                event.clone()
            }
            None => {
                let account = self.account();
                let configured = match chain
                    .genesis()
                    .native
                    .deployments
                    .iter()
                    .find(|entry| entry.deployment.digest() == &self.deployment)
                    .cloned()
                {
                    Some(entry) => entry,
                    None => chain
                        .registered(ctx)
                        .await
                        .context("read deposit deployment")?,
                };
                ensure!(
                    configured.deployment.operator == self.operator,
                    "deposit deployment belongs to another operator"
                );

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

                let event = DepositRequest::sign(
                    chain.genesis().native.chain_id(),
                    self.deployment,
                    event,
                    self.wallet.signer(),
                );

                // The id above derives from a volatile nonce and custody moves once the
                // transaction applies. Stage the event durably first so a crash in that
                // window cannot orphan the recorded deposit: a restarted wallet retries the
                // exact id, which the chain and the operator both deduplicate.
                self.store
                    .stage_deposit(&event)
                    .context("durably stage deposit")?;
                self.pending_deposit = Some(event.clone());
                event
            }
        };
        chain
            .deliver(ctx, &SettlementTx::Deposit(event.clone()))
            .await
            .context("record settlement deposit")?;
        let mut recorded = None;
        for _ in 0..EFFECT_ATTEMPTS {
            if let Ok(Some(record)) = chain.deposit(ctx, event.event.id).await {
                recorded = Some(record);
                break;
            }
            ctx.sleep(POLL).await;
        }
        match recorded {
            Some(record) if record == event.event => {}
            Some(_) => {
                // A conflicting certified event makes these staged bytes unrecordable.
                // Advance the nonce so a fresh intent cannot reuse that consumed ID.
                self.store
                    .discard_deposit(&event)
                    .context("discard unrecordable deposit")?;
                self.pending_deposit = None;
                self.deposit_nonce = next_deposit_nonce;
                anyhow::bail!("the deposit id is certifiably bound to another event");
            }
            None => {
                // An effect-free rejection is indistinguishable from
                // not-yet-included, so the staged event survives for an
                // exact retry.
                anyhow::bail!("record settlement deposit: custody was not certified in time");
            }
        }
        self.store
            .complete_deposit(&event)
            .context("complete staged deposit")?;
        self.pending_deposit = None;
        self.deposit_nonce = next_deposit_nonce;
        Ok(event.event)
    }

    pub(crate) async fn withdraw<E: Env>(
        &mut self,
        ctx: &E,
        chain: &mut Client,
        operator: SocketAddr,
        action: WithdrawalAction,
    ) -> Result<WithdrawalOutcome> {
        ensure!(
            self.pending_withdrawal_claim.is_none() || self.pending_withdrawal.is_some(),
            "the pending withdrawal claim must complete before a new withdrawal"
        );
        if let Some(request) = self.pending_withdrawal.clone() {
            ensure!(
                request.body().action() == &action,
                "the pending withdrawal claim must complete before a different withdrawal"
            );
            let status = chain.recent_status(ctx).await?;
            ensure!(
                status.deployment == self.deployment,
                "unexpected withdrawal deployment"
            );
            if status.height >= request.body().deadline() {
                ensure!(
                    !status.hard_faulted,
                    "expired withdrawal requires hard-fault recovery"
                );
                // A healthy post-deadline state excludes every outstanding obligation.
                // Finalized boundaries distinguish completed carriage from a request never used.
                if let Some(epoch) = self
                    .carried_withdrawal_epoch(ctx, chain, &request, status.last_finalized)
                    .await?
                {
                    return Ok(WithdrawalOutcome::Applied { epoch, request });
                }
                self.store.discard_unused_withdrawal(&request)?;
                self.pending_withdrawal = None;
                self.pending_withdrawal_claim = None;
            }
        }
        let request = match &self.pending_withdrawal {
            Some(pending) => pending.clone(),
            None => {
                // The signed deadline is an absolute block height, so it is
                // chosen from a recency-bounded status read: a certified tip
                // whose timestamp is within the recency threshold of the
                // local clock.
                let status = chain
                    .recent_status(ctx)
                    .await
                    .context("read settlement withdrawal head")?;
                ensure!(
                    status.deployment == self.deployment,
                    "settlement status has an unexpected deployment"
                );
                ensure!(
                    !status.hard_faulted,
                    "settlement is permanently hard-faulted"
                );

                // Retain a head opening before signing. It is not sent anywhere: if the
                // deployment later hard-faults while frozen at this root, recovery needs it.
                // The operator serves it first, and the validators when it does not.
                if self
                    .store
                    .recovery_opening(&status.state_root)
                    .context("read retained withdrawal opening")?
                    .is_none()
                {
                    let served = operator_rpc::withdrawal_opening(
                        ctx,
                        operator,
                        operator_rpc::WithdrawalOpeningRequest {
                            account: self.account(),
                        },
                    )
                    .await
                    .and_then(|opening| {
                        ensure!(
                            status.state_root == opening.root,
                            "operator opening is not the settlement head"
                        );
                        Ok(opening.opening)
                    });
                    let opening = match served {
                        Ok(opening) => opening,
                        Err(operator_error) => self
                            .holders
                            .validator_opening(ctx, chain, &self.account(), &status)
                            .await
                            .map_err(|error| unusable_head(operator_error, error))
                            .context("read withdrawal opening")?,
                    };
                    self.store
                        .retain_recovery_opening(&status.state_root, &opening)
                        .context("durably retain withdrawal opening")?;
                }

                let deadline = withdrawal_deadline(status.height, &chain.genesis().timing())?;
                let request = SignedWithdrawal::sign(
                    status.deployment,
                    status.state_root.digest,
                    self.account().encode(),
                    action,
                    deadline,
                    self.wallet.signer(),
                );
                self.store
                    .stage_withdrawal(&request)
                    .context("persist signed withdrawal")?;
                self.cache = None;
                self.pending_withdrawal_claim = Some(PendingWithdrawalClaim { evidence: None });
                self.pending_withdrawal = Some(request.clone());
                request
            }
        };
        let digest = operator_rpc::withdrawal_digest(&request);
        let applied = match operator_rpc::apply_withdrawal(
            ctx,
            operator,
            operator_rpc::ApplyWithdrawalRequest {
                request: request.clone(),
            },
        )
        .await
        {
            Ok(applied) => applied,
            Err(error) => {
                return Ok(WithdrawalOutcome::Signed {
                    request,
                    error: error.context("apply operator withdrawal"),
                });
            }
        };
        if applied.digest != digest {
            return Ok(WithdrawalOutcome::Signed {
                request,
                error: anyhow::anyhow!("operator acknowledged another withdrawal"),
            });
        }

        Ok(WithdrawalOutcome::Applied {
            epoch: applied.epoch,
            request,
        })
    }

    /// Searches every finalized boundary before declaring a saved request uncarried.
    async fn carried_withdrawal_epoch<E: Env>(
        &mut self,
        ctx: &E,
        chain: &mut Client,
        request: &SignedWithdrawal<Key, Digest>,
        last_finalized: Option<u64>,
    ) -> Result<Option<u64>> {
        if let Some(last) = last_finalized {
            for epoch in 0..=last {
                let admitted = chain
                    .admitted(ctx, epoch)
                    .await?
                    .filter(|record| record.finalized)
                    .context("finalized withdrawal history is unavailable")?;
                if self
                    .holders
                    .carried_withdrawal(ctx, chain, epoch, &admitted, request)
                    .await?
                {
                    return Ok(Some(epoch));
                }
            }
        }
        Ok(None)
    }

    /// Escalates a signed withdrawal the operator would not carry directly to the chain.
    ///
    /// This is the censorship-fallback exit. When [`Self::withdraw`] returns
    /// [`WithdrawalOutcome::Signed`] because the operator is unreachable, the wallet queues the
    /// exact retained request and its head opening on the chain, where its deadline becomes an
    /// on-chain obligation that expires into hard-fault recovery. Execution deduplicates the
    /// account's queued request (a replay lands on the queue-slot guard), so a lost response
    /// resubmits unchanged and completes on the certified queued record, and the retained
    /// opening remains the durable evidence hard-fault recovery later releases against.
    ///
    /// A `Signed` outcome does not prove the operator skipped the request: it may have applied
    /// it and lost only the response, in which case the next registered close must carry the
    /// queued request verbatim and finalizes an operator-carried claim. The wallet therefore
    /// opens the claim slot exactly like the applied path, so that claim stays recoverable. The
    /// two payout paths are exclusive: a carried request finalizes a claimable reserve and no
    /// fault occurs, while an expired obligation faults the deployment and hard-fault recovery
    /// pays out, leaving the idle claim intent permanently unavailable and harmless.
    pub(crate) async fn escalate_withdrawal<E: Env>(
        &mut self,
        ctx: &E,
        chain: &mut Client,
    ) -> Result<SignedWithdrawal<Key, Digest>> {
        let request = self
            .pending_withdrawal
            .clone()
            .context("no signed withdrawal awaits escalation")?;
        let root = StateRoot {
            digest: *request.body().state_root(),
        };
        let opening = self
            .store
            .recovery_opening(&root)?
            .context("no retained head opening for the signed withdrawal")?;
        let status = settlement_status(ctx, chain, self.deployment).await?;
        ensure!(
            status.state_root == root,
            "the signed withdrawal reference root is no longer finalized"
        );
        let tx = SettlementTx::QueueWithdrawal(QueueWithdrawalRequest {
            request: request.clone(),
            opening,
        });
        chain
            .deliver(ctx, &tx)
            .await
            .context("queue signed withdrawal at settlement")?;

        // The effect is the certified queue-slot record holding exactly the
        // escalated request. A stale record from an earlier serviced
        // withdrawal is not a verdict, so only the exact match completes.
        let mut queued = false;
        for _ in 0..EFFECT_ATTEMPTS {
            if let Ok(Some(recorded)) = chain.withdrawal(ctx, request.account().clone()).await
                && recorded == request
            {
                queued = true;
                break;
            }
            ctx.sleep(POLL).await;
        }
        ensure!(queued, "the queued withdrawal was not certified in time");

        Ok(request)
    }
}
