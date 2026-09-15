//! Permissionless claims for wallet-owned outputs in the finalized payout MMR.

use super::{Agent, evidence::verify_payout_proof, store::PendingWithdrawalClaim};
use crate::{
    chain::{
        client::{Chain, Client, EFFECT_ATTEMPTS, Env, POLL},
        state::WithdrawalResponse,
        tx::{SettlementTx, WithdrawalClaimRequest},
    },
    operator::rpc as operator_rpc,
};
use anyhow::{Context, Result, ensure};
use commonware_clearing::bajillion::logs::PayoutOperation;
use std::net::SocketAddr;

impl Agent {
    /// Retains an authenticated payout identity and retries refreshable proof bytes until the
    /// append-only certified payout log proves that globally positioned output spent.
    pub(crate) async fn claim_withdrawal<E: Env>(
        &mut self,
        ctx: &E,
        chain: &mut Client,
        operator: SocketAddr,
    ) -> Result<WithdrawalResponse> {
        ensure!(
            chain.deployment() == self.deployment,
            "withdrawal client is bound to another deployment"
        );
        let mut candidate = match self.pending_withdrawal_claim.clone() {
            Some(candidate) => candidate,
            None => {
                let candidate = self.withdrawal_source(ctx, chain).await?;
                self.store
                    .cache_withdrawal_claim(&candidate)
                    .context("cache discovered withdrawal proof")?;
                self.pending_withdrawal_claim = Some(candidate.clone());
                candidate
            }
        };
        let index = candidate.claim.position();
        let output = candidate.claim.output().clone();
        let mut last_submission = None;

        for _ in 0..EFFECT_ATTEMPTS {
            // The cached candidate was authenticated at a finalized payout head. Payout positions
            // are append-only, so a newer certified count beyond this index proves that the same
            // identity was issued even when its current interval is absent.
            let status = chain
                .payout_status(ctx, index)
                .await
                .context("read coherent payout status")?;
            ensure!(
                index < status.head.operations,
                "current payout head predates the cached candidate"
            );
            let Some(interval) = status.interval else {
                self.store
                    .complete_withdrawal_claim(index)
                    .context("record delivered payout candidate")?;
                self.pending_withdrawal_claim = None;
                return Ok(WithdrawalResponse {
                    destination: output.destination().clone(),
                    amount: output.amount(),
                });
            };
            let claim = match &candidate {
                cached if cached.head == status.head => cached.claim.clone(),
                _ => match operator_rpc::payout_proof(
                    ctx,
                    operator,
                    operator_rpc::PayoutProofRequest {
                        head: status.head,
                        index,
                    },
                )
                .await
                .and_then(|claim| verify_payout_proof(&status.head, index, &output, claim))
                {
                    Ok(claim) => claim,
                    Err(_) => chain
                        .payout_proof(ctx, status.head, index)
                        .await
                        .and_then(|claim| verify_payout_proof(&status.head, index, &output, claim))
                        .context("refresh payout proof from configured custodians")?,
                },
            };
            ensure!(
                interval.start <= index && index < interval.end,
                "certified interval does not contain the payout index"
            );
            if candidate.head != status.head {
                candidate = PendingWithdrawalClaim {
                    head: status.head,
                    claim: claim.clone(),
                };
                self.store
                    .cache_withdrawal_claim(&candidate)
                    .context("cache current withdrawal proof")?;
                self.pending_withdrawal_claim = Some(candidate.clone());
            }

            let tx = SettlementTx::ClaimWithdrawal(WithdrawalClaimRequest {
                deployment: self.deployment,
                start: interval.start,
                claim,
            });
            if let Err(error) = chain.deliver(ctx, &tx).await {
                last_submission = Some(error);
            }
            ctx.sleep(POLL).await;
        }

        let error = anyhow::anyhow!(
            "the withdrawal remains unclaimed; payout identity and current proof are retained"
        );
        match last_submission {
            Some(source) => Err(error.context(source)),
            None => Err(error),
        }
    }

    /// Discovers one unspent wallet-owned output in the finalized native payout log.
    ///
    /// The destination match is advisory discovery. The point opening and coherent current
    /// unclaimed interval authenticate the candidate before it becomes durable.
    async fn withdrawal_source<E: Env>(
        &mut self,
        ctx: &E,
        chain: &mut Client,
    ) -> Result<PendingWithdrawalClaim> {
        let tip = chain
            .payout_checkpoint(ctx)
            .await
            .context("read withdrawal payout checkpoint")?;
        ensure!(tip.finalized.is_some(), "no withdrawal epoch is finalized");
        let head = tip.payouts;
        let mut cursor = 0;
        while cursor < head.operations {
            let (start, operations) = chain
                .payout_operations(ctx, head, cursor)
                .await
                .context("discover finalized wallet payouts")?;
            ensure!(
                cursor <= start && start < head.operations && !operations.is_empty(),
                "payout discovery returned an invalid cursor"
            );
            for (offset, operation) in operations.iter().enumerate() {
                let PayoutOperation::Append(output) = operation else {
                    continue;
                };
                if output.destination().as_ref() != self.account().as_ref() {
                    continue;
                }
                let position = start
                    .checked_add(u64::try_from(offset).context("payout offset overflow")?)
                    .context("payout position overflow")?;
                let Ok(status) = chain.payout_status(ctx, position).await else {
                    continue;
                };
                if position >= status.head.operations {
                    continue;
                }
                if let Some(interval) = status.interval {
                    if !(interval.start <= position && position < interval.end) {
                        continue;
                    }
                    let Ok(claim) = chain.payout_proof(ctx, status.head, position).await else {
                        continue;
                    };
                    let Ok(claim) = verify_payout_proof(&status.head, position, output, claim)
                    else {
                        continue;
                    };
                    return Ok(PendingWithdrawalClaim {
                        head: status.head,
                        claim,
                    });
                }
            }
            cursor = start
                .checked_add(
                    u64::try_from(operations.len()).context("payout page length overflow")?,
                )
                .context("payout cursor overflow")?;
        }
        anyhow::bail!("no unspent wallet-owned payout is available")
    }
}
