//! Custody flows: deposits, withdrawal authorization and escalation, and recovery.

use super::{Agent, store::PendingWithdrawalClaim};
use crate::{
    chain::{
        client::{Chain, Client, EFFECT_ATTEMPTS, Env, POLL},
        state::{ClaimHardFaultResponse, ClaimPendingDepositResponse, FaultRecord},
        tx::{
            BeginHardFaultSettlementRequest, ClaimHardFaultRequest, ClaimPendingDepositRequest,
            DepositRequest, QueueWithdrawalRequest, SettlementTx,
        },
    },
    operator::rpc as operator_rpc,
    protocol::{DepositEvent, Key, identities},
};
use anyhow::{Context, Result, ensure};
use bytes::Bytes;
use commonware_clearing::bajillion::{
    boundary::{SignedWithdrawal, WithdrawalAction},
    commitment::VectorRoot,
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

pub(super) const fn withdrawal_deadline(now: u64) -> u64 {
    now.saturating_add(crate::protocol::WITHDRAWAL_HORIZON)
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
    pub(crate) async fn recover_hard_fault<E: Env>(
        &self,
        ctx: &E,
        chain: &mut Client,
    ) -> Result<ClaimHardFaultResponse> {
        // Terminal settlement begins as a transaction whose effect is the
        // certified Settling fault record: a lost response resubmits the
        // same bytes and completes on the same frozen snapshot.
        let begin = SettlementTx::BeginHardFaultSettlement(BeginHardFaultSettlementRequest {
            deployment: self.deployment,
        });
        let advice = chain
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
        let hard_fault = settling.with_context(|| {
            format!("terminal settlement never certifiably began (dry-run advice: {advice:?})")
        })?;

        // Recovery at a frozen root requires an opening retained at or refreshed to that
        // root. Openings refresh on every head read or balance poll, so this fails only for a
        // wallet passive across the final finalization, which then depends on the
        // operator's survival to serve one.
        let opening = self
            .store
            .recovery_opening(&hard_fault.frozen_state_root)?
            .context(
                "no payer opening is retained for the frozen state root: the wallet was \
                 passive across the final finalization and needs the operator to serve one",
            )?;
        let expected_custody = opening.leaf.state.balance;
        let opening_digest = Sha256::hash(&[&opening.encode()]);
        let claim = SettlementTx::ClaimHardFault(ClaimHardFaultRequest {
            deployment: self.deployment,
            opening,
        });
        let advice = chain
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
        let record = released.with_context(|| {
            format!("the hard-fault claim earned no certified release (dry-run advice: {advice:?})")
        })?;
        ensure!(
            record.opening == opening_digest,
            "the hard-fault release consumed another opening"
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
        Ok(release)
    }

    pub(crate) async fn recover_pending_deposit<E: Env>(
        &self,
        ctx: &E,
        chain: &mut Client,
    ) -> Result<ClaimPendingDepositResponse> {
        let account = self.account();
        let claim = SettlementTx::ClaimPendingDeposit(ClaimPendingDepositRequest {
            deployment: self.deployment,
            account: account.clone(),
        });
        let advice = chain
            .deliver(ctx, &claim)
            .await
            .context("claim pending settlement deposit")?;
        let mut released = None;
        for _ in 0..EFFECT_ATTEMPTS {
            if let Ok(Some(record)) = chain.refund(ctx, account.clone()).await {
                released = Some(record);
                break;
            }
            ctx.sleep(POLL).await;
        }
        let refund = released.with_context(|| {
            format!("the refund claim earned no certified release (dry-run advice: {advice:?})")
        })?;
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

                // Settlement takes custody only for configured identities, so any other
                // account would deterministically wedge as staged forever.
                ensure!(
                    identities().iter().any(|identity| identity.key == account),
                    "deposits are limited to configured terminal agents"
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
        let advice = chain
            .deliver(
                ctx,
                &SettlementTx::Deposit(DepositRequest {
                    deployment: self.deployment,
                    event: event.clone(),
                }),
            )
            .await
            .context("record settlement deposit")?;
        let mut recorded = None;
        for _ in 0..EFFECT_ATTEMPTS {
            if let Ok(Some(record)) = chain.deposit(ctx, event.id).await {
                recorded = Some(record);
                break;
            }
            ctx.sleep(POLL).await;
        }
        match recorded {
            Some(record) if record == event => {}
            Some(_) => {
                // The id is certifiably consumed by another event, so the
                // staged bytes can never take custody: this is the one
                // discard evidence can justify. The id derives from this
                // wallet's own nonce namespace, so the arm is unreachable
                // without a local id-derivation bug.
                self.store
                    .discard_deposit(&event)
                    .context("discard unrecordable deposit")?;
                self.pending_deposit = None;
                anyhow::bail!("the deposit id is certifiably bound to another event");
            }
            None => {
                // An effect-free rejection is indistinguishable from
                // not-yet-included, so the staged event survives for an
                // exact retry and the advisory dry-run answer is the only
                // typed diagnosis available.
                anyhow::bail!(
                    "record settlement deposit: custody was not certified in time \
                     (dry-run advice: {advice:?})"
                );
            }
        }
        self.store
            .complete_deposit(&event)
            .context("complete staged deposit")?;
        self.pending_deposit = None;
        self.deposit_nonce = next_deposit_nonce;
        Ok(event)
    }

    pub(crate) async fn withdraw<E: Env>(
        &mut self,
        ctx: &E,
        chain: &mut Client,
        operator: SocketAddr,
        action: WithdrawalAction,
    ) -> Result<WithdrawalOutcome> {
        // One withdrawal claim intent exists per wallet, and a recorded release pins its
        // evidence until the operator acknowledgement completes it. A new withdrawal must
        // wait: silently skipping the open would drop the new reserve's intent instead.
        ensure!(
            self.pending_withdrawal_claim.is_none(),
            "the pending withdrawal claim must complete before a new withdrawal"
        );
        let request = match &self.pending_withdrawal {
            Some(pending) => {
                ensure!(
                    pending.body().action() == &action,
                    "another withdrawal retry is pending"
                );
                pending.clone()
            }
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
                if self
                    .store
                    .recovery_opening(&status.state_root)
                    .context("read retained withdrawal opening")?
                    .is_none()
                {
                    let opening = operator_rpc::withdrawal_opening(
                        ctx,
                        operator,
                        operator_rpc::WithdrawalOpeningRequest {
                            account: self.account(),
                        },
                    )
                    .await
                    .context("read withdrawal opening")?;
                    ensure!(
                        status.state_root == opening.root,
                        "operator opening is not the settlement head"
                    );
                    self.store
                        .retain_recovery_opening(&opening.root, &opening.opening)
                        .context("durably retain withdrawal opening")?;
                }

                // A withdrawal reduces the live balance mid-epoch, ahead of any
                // predecessor root an affordability floor could be read from.
                // Invalidate the cached signing state durably before the request can
                // reach the operator: verified head reads re-cache only once no
                // withdrawal is in flight, so the optimistic payment precheck never
                // overstates spendable balance.
                self.store
                    .clear_context()
                    .context("invalidate cached signing context")?;
                self.cache = None;
                let deadline = withdrawal_deadline(status.height);
                let request = SignedWithdrawal::sign(
                    status.deployment,
                    status.state_root.digest,
                    Bytes::copy_from_slice(self.wallet.name.as_bytes()),
                    action,
                    deadline,
                    self.wallet.signer(),
                );
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

        // The acknowledged epoch is display only and never trusted: the claim intent
        // carries no epoch, and the claim binds to its finalized batch only when fetched
        // evidence verifies locally against that batch's own claim roots.
        self.store
            .open_withdrawal_claim()
            .context("open withdrawal claim")?;
        self.pending_withdrawal_claim = Some(PendingWithdrawalClaim {
            evidence: None,
            result: None,
        });
        self.pending_withdrawal = None;
        Ok(WithdrawalOutcome::Applied {
            epoch: applied.epoch,
            request,
        })
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
        let root = VectorRoot {
            digest: *request.body().state_root(),
        };
        let opening = self
            .store
            .recovery_opening(&root)?
            .context("no retained head opening for the signed withdrawal")?;
        let tx = SettlementTx::QueueWithdrawal(QueueWithdrawalRequest {
            request: request.clone(),
            openings: vec![opening],
        });
        let advice = chain
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
        ensure!(
            queued,
            "the queued withdrawal was not certified in time (dry-run advice: {advice:?})"
        );

        // The request is now a chain obligation. Open the claim slot in case the operator
        // already applied the request and only the response was lost: a close that carries it
        // finalizes an operator-carried claim this slot recovers, while a true non-carriage
        // expires into hard-fault recovery against the retained opening.
        self.store
            .open_withdrawal_claim()
            .context("open withdrawal claim")?;
        self.pending_withdrawal_claim = Some(PendingWithdrawalClaim {
            evidence: None,
            result: None,
        });
        self.pending_withdrawal = None;
        Ok(request)
    }
}
