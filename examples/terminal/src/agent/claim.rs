//! Finalized withdrawal claims bound to the wallet's retained authorization.

use super::{
    Agent,
    evidence::verify_payout_proof,
    store::{PendingWithdrawalClaim, RefreshedWithdrawalClaim, WithdrawalSource},
};
use crate::{
    chain::{
        client::{Chain, Client, EFFECT_ATTEMPTS, Env, POLL},
        state::WithdrawalResponse,
        tx::{SettlementTx, WithdrawalClaimRequest},
    },
    operator::rpc as operator_rpc,
};
use anyhow::{Context, Result, ensure};
use std::net::SocketAddr;

impl Agent {
    /// Retains immutable source evidence and retries refreshable proof/hint bytes until the
    /// globally positioned output is proven spent in the same certified payout snapshot.
    pub(crate) async fn claim_withdrawal<E: Env>(
        &mut self,
        ctx: &E,
        chain: &mut Client,
        operator: SocketAddr,
    ) -> Result<WithdrawalResponse> {
        let pending = self
            .pending_withdrawal_claim
            .clone()
            .context("no withdrawal claim is pending")?;
        let source = match pending.source {
            // SQLite contains this identity only after a finalized SourceProof bound the exact
            // request and output. Current payout inclusion below re-establishes issuance without
            // depending on source retention after restart.
            Some(source) => source,
            None => {
                let source = self.withdrawal_source(ctx, chain).await?;
                self.store
                    .cache_withdrawal_source(&source)
                    .context("cache immutable withdrawal source")?;
                self.pending_withdrawal_claim = Some(PendingWithdrawalClaim {
                    source: Some(source.clone()),
                    refreshed: None,
                });
                source
            }
        };

        let index = source.position;
        let output = source.output.clone();
        let mut cached = self
            .pending_withdrawal_claim
            .as_ref()
            .and_then(|pending| pending.refreshed.clone());
        let mut last_submission = None;

        for _ in 0..EFFECT_ATTEMPTS {
            // Head and interval are authenticated under one chain root. Only after current-head
            // inclusion verifies can interval absence mean that this issued output was spent.
            let status = chain
                .payout_status(ctx, index)
                .await
                .context("read coherent payout status")?;
            let claim = match cached.as_ref() {
                Some(refreshed)
                    if refreshed.head == status.head
                        && refreshed.claim.position() == index
                        && refreshed.claim.output() == &output =>
                {
                    refreshed.claim.clone()
                }
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

            let Some(interval) = status.interval else {
                self.store
                    .complete_withdrawal_claim(&source)
                    .context("complete spent withdrawal claim")?;
                self.pending_withdrawal_claim = None;
                self.pending_withdrawal = None;
                let release = WithdrawalResponse {
                    destination: output.destination().clone(),
                    amount: output.amount(),
                };

                return Ok(release);
            };

            ensure!(
                interval.start <= index && index < interval.end,
                "certified interval does not contain the payout index"
            );
            let refreshed = RefreshedWithdrawalClaim {
                head: status.head,
                start: interval.start,
                claim: claim.clone(),
            };
            self.store
                .cache_withdrawal_refresh(&source, &refreshed)
                .context("cache current withdrawal proof")?;
            cached = Some(refreshed.clone());
            self.pending_withdrawal_claim = Some(PendingWithdrawalClaim {
                source: Some(source.clone()),
                refreshed: Some(refreshed),
            });

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
            "the withdrawal remains unclaimed; immutable source and current proof are retained"
        );
        match last_submission {
            Some(source) => Err(error.context(source)),
            None => Err(error),
        }
    }

    /// Obtains an exact finalized source identity from the bounded native-custody window.
    async fn withdrawal_source<E: Env>(
        &mut self,
        ctx: &E,
        chain: &mut Client,
    ) -> Result<WithdrawalSource> {
        let request = self
            .pending_withdrawal
            .clone()
            .context("no immutable withdrawal request is available for source discovery")?;
        self.withdrawal_source_in_notice_window(ctx, chain, &request)
            .await
            .context("search native custody for the withdrawal source")?
            .context("the bounded custody window contains no exact withdrawal source")
    }
}
