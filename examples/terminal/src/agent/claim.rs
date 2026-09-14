//! Finalized withdrawal claims bound to the wallet's retained authorization.

use super::{Agent, store::PendingWithdrawalClaim};
use crate::{
    chain::{
        client::{Chain, Client, EFFECT_ATTEMPTS, Env, POLL},
        state::{ClaimRootsResponse, WithdrawalResponse},
        tx::{SettlementTx, WithdrawalClaimRequest},
    },
    operator::rpc as operator_rpc,
};
use anyhow::{Context, Result, ensure};
use commonware_codec::Encode as _;
use commonware_cryptography::{Hasher as _, Sha256};
use std::net::SocketAddr;

impl Agent {
    /// Retains verified evidence until its exact certified release completes the saved intent.
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
        let evidence = match pending.evidence {
            Some(evidence) => evidence,
            None => {
                let (fresh, roots) = match self.historical_withdrawal(ctx, chain).await? {
                    Some(fetched) => fetched,
                    None => {
                        let fresh = operator_rpc::withdrawal_evidence(
                            ctx,
                            operator,
                            operator_rpc::WithdrawalEvidenceRequest {
                                account: self.account(),
                            },
                        )
                        .await
                        .context("fetch withdrawal evidence")?;
                        let roots = chain
                            .claim_roots(ctx, fresh.batch_id())
                            .await
                            .context("look up the withdrawal claim batch")?
                            .context("the withdrawal batch has not finalized, so its evidence is not yet cacheable")?;
                        (fresh, roots)
                    }
                };
                self.bind_withdrawal(&fresh, &roots)?;
                self.store
                    .cache_withdrawal_claim(&fresh)
                    .context("cache withdrawal evidence")?;
                self.pending_withdrawal_claim = Some(PendingWithdrawalClaim {
                    evidence: Some(fresh.clone()),
                });
                fresh
            }
        };

        ensure!(
            chain
                .claim_roots(ctx, evidence.batch_id())
                .await
                .context("look up the withdrawal claim batch")?
                .is_some(),
            "the withdrawal batch has not finalized, so the cached evidence waits for finalization"
        );
        let output = evidence.witness.claim.output();
        let release = if output.amount() == 0 {
            WithdrawalResponse {
                destination: output.destination().clone(),
                amount: 0,
            }
        } else if let Ok(Some(release)) = Self::withdrawal_release(ctx, chain, &evidence).await {
            release
        } else {
            let tx = SettlementTx::ClaimWithdrawal(WithdrawalClaimRequest {
                deployment: self.deployment,
                batch_id: evidence.batch_id(),
                claim: evidence.witness.claim.clone(),
            });
            chain
                .deliver(ctx, &tx)
                .await
                .context("claim settlement withdrawal")?;
            let mut released = None;
            for _ in 0..EFFECT_ATTEMPTS {
                if let Ok(Some(release)) = Self::withdrawal_release(ctx, chain, &evidence).await {
                    released = Some(release);
                    break;
                }
                ctx.sleep(POLL).await;
            }
            released.context(
                "the withdrawal claim earned no certified release yet; the exact claim retries",
            )?
        };
        ensure!(
            release.destination == *output.destination() && release.amount == output.amount(),
            "settlement returned another withdrawal output"
        );
        self.store
            .complete_withdrawal_claim(&evidence, &release)
            .context("complete withdrawal claim")?;
        self.pending_withdrawal_claim = None;
        self.pending_withdrawal = None;

        // The certified release retires the intent before optional operator bookkeeping.
        let _ = operator_rpc::acknowledge_withdrawal(
            ctx,
            operator,
            operator_rpc::AcknowledgeWithdrawalRequest::from(&evidence),
        )
        .await;
        Ok(release)
    }

    /// Binds the request and output to this wallet and the certified batch descriptor.
    fn bind_withdrawal(
        &self,
        evidence: &operator_rpc::WithdrawalEvidenceResponse,
        roots: &ClaimRootsResponse,
    ) -> Result<()> {
        ensure!(
            self.pending_withdrawal
                .as_ref()
                .is_none_or(|request| evidence.witness.request == *request),
            "withdrawal evidence names another request"
        );
        let batch = evidence.witness.verify(
            &evidence.roots,
            &self.deployment,
            &self.account(),
            self.account().as_ref(),
        )?;
        ensure!(
            batch == roots.batch_id
                && evidence.roots.withdrawal_outputs == roots.withdrawal_outputs,
            "withdrawal descriptor differs from its finalized batch"
        );
        ensure!(
            !self
                .store
                .withdrawal_claim_completed(batch, evidence.witness.claim.position())?,
            "operator re-served evidence for an already-completed withdrawal claim"
        );
        Ok(())
    }

    /// Finds a current obligation, including one another holder already delivered.
    async fn historical_withdrawal<E: Env>(
        &mut self,
        ctx: &E,
        chain: &mut Client,
    ) -> Result<Option<(operator_rpc::WithdrawalEvidenceResponse, ClaimRootsResponse)>> {
        let status = chain
            .status(ctx)
            .await
            .context("read the withdrawal claim head")?;
        ensure!(
            status.deployment == self.deployment,
            "settlement status has an unexpected deployment"
        );
        let registration = chain
            .registration(ctx)
            .await
            .context("read the registered close")?;
        let Some(last) = status.last_finalized.max(registration.map(|r| r.epoch)) else {
            return Ok(None);
        };
        for epoch in 0..=last {
            let Some(admitted) = chain.admitted(ctx, epoch).await? else {
                continue;
            };
            let account = self.account();
            let Ok(witness) = self
                .holders
                .withdrawal_evidence(ctx, chain, &admitted, &account, account.as_ref())
                .await
            else {
                continue;
            };
            let evidence = operator_rpc::WithdrawalEvidenceResponse {
                roots: admitted.roots,
                witness,
            };
            if self.store.withdrawal_claim_completed(
                evidence.batch_id(),
                evidence.witness.claim.position(),
            )? || (self.pending_withdrawal.as_ref() != Some(&evidence.witness.request)
                && Self::withdrawal_release(ctx, chain, &evidence)
                    .await?
                    .is_some())
            {
                continue;
            }
            let roots = ClaimRootsResponse {
                batch_id: admitted.batch_id,
                withdrawal_outputs: admitted.roots.withdrawal_outputs,
            };
            if self.bind_withdrawal(&evidence, &roots).is_err() {
                continue;
            }
            return Ok(Some((evidence, roots)));
        }
        Ok(None)
    }

    /// A certified release must consume the exact output opening retained by the wallet.
    async fn withdrawal_release<E: Env>(
        ctx: &E,
        chain: &mut Client,
        evidence: &operator_rpc::WithdrawalEvidenceResponse,
    ) -> Result<Option<WithdrawalResponse>> {
        let Some(record) = chain
            .withdrawal_release(ctx, evidence.batch_id(), evidence.witness.claim.position())
            .await?
        else {
            return Ok(None);
        };
        ensure!(
            record.claim == Sha256::hash(&[&evidence.witness.claim.encode()]),
            "the released withdrawal position consumed other evidence"
        );
        Ok(Some(record.released))
    }
}
