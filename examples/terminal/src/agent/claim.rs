//! The shared claim driver for finalized withdrawal and external-payout reserves.

use super::{
    Agent,
    evidence::Holders,
    store::{PendingClaim, PendingPayoutClaim, PendingWithdrawalClaim, Store},
};
use crate::{
    chain::{
        client::{Chain, Client, EFFECT_ATTEMPTS, Env, POLL},
        state::{
            AdmittedRootsResponse, ClaimRootsResponse, ExternalPayoutResponse, WithdrawalResponse,
        },
        tx::{ExternalPayoutClaimRequest, SettlementTx, WithdrawalClaimRequest},
    },
    operator::rpc as operator_rpc,
    protocol::{Key, Wallet},
};
use anyhow::{Context, Result, ensure};
use commonware_clearing::bajillion::transition::BatchId;
use commonware_codec::Encode as _;
use commonware_cryptography::{Hasher as _, Sha256, sha256::Digest};
use std::net::SocketAddr;

/// One claim kind's wiring for the shared claim driver.
trait ClaimChannel {
    type Evidence: Clone;
    type Release;

    /// Claim noun used by the driver's errors and contexts.
    const NOUN: &'static str;

    fn pending(agent: &Agent) -> &Option<PendingClaim<Self::Evidence>>;
    fn pending_mut(agent: &mut Agent) -> &mut Option<PendingClaim<Self::Evidence>>;

    /// Returns the finalized batch the evidence names.
    fn batch(evidence: &Self::Evidence) -> BatchId<Digest>;

    /// Binds operator-supplied evidence to this wallet by full local verification against
    /// the claim roots of the finalized batch the evidence names, before it may be cached.
    /// Evidence naming an already-completed (batch, position) is refused: its release is
    /// spent, so binding it would close the open intent against an old obligation.
    fn bind(agent: &Agent, evidence: &Self::Evidence, roots: &ClaimRootsResponse) -> Result<()>;

    /// Confirms a settlement release pays what the bound evidence certifies.
    fn verify_release(
        agent: &Agent,
        evidence: &Self::Evidence,
        release: &Self::Release,
    ) -> Result<()>;

    /// Fetches this wallet's evidence from the operator's reconstruction of the
    /// finalized close it names.
    async fn fetch<E: Env>(account: Key, ctx: &E, operator: SocketAddr) -> Result<Self::Evidence>;

    /// Fetches `wallet`'s evidence for the admitted close from its validators,
    /// verified against the admitted roots.
    async fn fetch_admitted<E: Env>(
        holders: &Holders,
        ctx: &E,
        chain: &Client,
        admitted: &AdmittedRootsResponse,
        wallet: &Wallet,
    ) -> Result<Self::Evidence>;

    /// A finalized zero output completes without an asset transfer.
    fn zero_release(_: &Self::Evidence) -> Option<Self::Release> {
        None
    }

    /// The claim transaction for `evidence`.
    fn tx(deployment: Digest, evidence: &Self::Evidence) -> SettlementTx;

    /// Reads the certified release the applied claim produced, verifying it
    /// consumed exactly this evidence.
    async fn release<E: Env>(
        ctx: &E,
        chain: &mut Client,
        evidence: &Self::Evidence,
    ) -> Result<Option<Self::Release>>;

    async fn acknowledge<E: Env>(
        ctx: &E,
        operator: SocketAddr,
        evidence: &Self::Evidence,
    ) -> Result<()>;

    fn cache(store: &mut Store, evidence: &Self::Evidence) -> Result<()>;
    fn completed(store: &Store, evidence: &Self::Evidence) -> Result<bool>;
    /// A saved authorization can complete from a release delivered by another holder.
    fn matches_intent(_: &Agent, _: &Self::Evidence) -> bool {
        false
    }

    fn complete(
        agent: &mut Agent,
        evidence: &Self::Evidence,
        release: &Self::Release,
    ) -> Result<()>;
}

struct WithdrawalChannel;

impl ClaimChannel for WithdrawalChannel {
    type Evidence = operator_rpc::WithdrawalEvidenceResponse;
    type Release = WithdrawalResponse;

    const NOUN: &'static str = "withdrawal";

    fn pending(agent: &Agent) -> &Option<PendingWithdrawalClaim> {
        &agent.pending_withdrawal_claim
    }

    fn pending_mut(agent: &mut Agent) -> &mut Option<PendingWithdrawalClaim> {
        &mut agent.pending_withdrawal_claim
    }

    fn batch(evidence: &Self::Evidence) -> BatchId<Digest> {
        evidence.batch_id()
    }

    fn bind(agent: &Agent, evidence: &Self::Evidence, roots: &ClaimRootsResponse) -> Result<()> {
        ensure!(
            agent
                .pending_withdrawal
                .as_ref()
                .is_none_or(|request| evidence.witness.request == *request),
            "withdrawal evidence names another request"
        );
        let batch_id = evidence.witness.verify(
            &evidence.roots,
            &agent.deployment,
            &agent.account(),
            agent.account().as_ref(),
        )?;
        ensure!(
            evidence.roots.withdrawal_outputs == roots.withdrawal_outputs
                && evidence.roots.change == roots.change,
            "withdrawal descriptor differs from its finalized batch"
        );
        ensure!(
            !agent
                .store
                .withdrawal_claim_completed(batch_id, evidence.witness.claim.position())?,
            "operator re-served evidence for an already-completed withdrawal claim"
        );
        Ok(())
    }

    fn matches_intent(agent: &Agent, evidence: &Self::Evidence) -> bool {
        agent.pending_withdrawal.as_ref() == Some(&evidence.witness.request)
    }

    fn verify_release(_: &Agent, evidence: &Self::Evidence, release: &Self::Release) -> Result<()> {
        ensure!(
            release.destination == *evidence.witness.claim.output().destination()
                && release.amount == evidence.witness.claim.output().amount(),
            "settlement returned another withdrawal output"
        );
        Ok(())
    }

    async fn fetch<E: Env>(account: Key, ctx: &E, operator: SocketAddr) -> Result<Self::Evidence> {
        operator_rpc::withdrawal_evidence(
            ctx,
            operator,
            operator_rpc::WithdrawalEvidenceRequest { account },
        )
        .await
    }

    async fn fetch_admitted<E: Env>(
        holders: &Holders,
        ctx: &E,
        chain: &Client,
        admitted: &AdmittedRootsResponse,
        wallet: &Wallet,
    ) -> Result<Self::Evidence> {
        let account = wallet.public_key();
        let witness = holders
            .withdrawal_evidence(ctx, chain, admitted, &account, account.as_ref())
            .await?;
        Ok(operator_rpc::WithdrawalEvidenceResponse {
            roots: admitted.roots,
            witness,
        })
    }

    fn zero_release(evidence: &Self::Evidence) -> Option<Self::Release> {
        let output = evidence.witness.claim.output();
        (output.amount() == 0).then(|| WithdrawalResponse {
            destination: output.destination().clone(),
            amount: 0,
        })
    }

    fn tx(deployment: Digest, evidence: &Self::Evidence) -> SettlementTx {
        SettlementTx::ClaimWithdrawal(WithdrawalClaimRequest {
            deployment,
            batch_id: evidence.batch_id(),
            claim: evidence.witness.claim.clone(),
        })
    }

    async fn release<E: Env>(
        ctx: &E,
        chain: &mut Client,
        evidence: &Self::Evidence,
    ) -> Result<Option<Self::Release>> {
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

    async fn acknowledge<E: Env>(
        ctx: &E,
        operator: SocketAddr,
        evidence: &Self::Evidence,
    ) -> Result<()> {
        operator_rpc::acknowledge_withdrawal(
            ctx,
            operator,
            operator_rpc::AcknowledgeWithdrawalRequest::from(evidence),
        )
        .await
    }

    fn cache(store: &mut Store, evidence: &Self::Evidence) -> Result<()> {
        store.cache_withdrawal_claim(evidence)
    }

    fn completed(store: &Store, evidence: &Self::Evidence) -> Result<bool> {
        store.withdrawal_claim_completed(evidence.batch_id(), evidence.witness.claim.position())
    }

    fn complete(
        agent: &mut Agent,
        evidence: &Self::Evidence,
        release: &Self::Release,
    ) -> Result<()> {
        agent.store.complete_withdrawal_claim(evidence, release)?;
        agent.pending_withdrawal_claim = None;
        agent.pending_withdrawal = None;
        Ok(())
    }
}

struct PayoutChannel;

impl ClaimChannel for PayoutChannel {
    type Evidence = operator_rpc::ExternalPayoutEvidenceResponse;
    type Release = ExternalPayoutResponse;

    const NOUN: &'static str = "external payout";

    fn pending(agent: &Agent) -> &Option<PendingPayoutClaim> {
        &agent.pending_payout_claim
    }

    fn pending_mut(agent: &mut Agent) -> &mut Option<PendingPayoutClaim> {
        &mut agent.pending_payout_claim
    }

    fn batch(evidence: &Self::Evidence) -> BatchId<Digest> {
        evidence.batch_id
    }

    /// Binding is full local verification: the claim must open against the finalized
    /// batch's own change root and certify this wallet as the receiver settlement pays.
    fn bind(agent: &Agent, evidence: &Self::Evidence, roots: &ClaimRootsResponse) -> Result<()> {
        let payout = evidence
            .claim
            .verify::<Sha256>(&roots.change)
            .context("verify external payout claim against its finalized batch")?;
        ensure!(
            payout.recipient == agent.account(),
            "operator returned external-payout evidence for another account"
        );

        // A completed (batch, position) is refused under the same rule as the withdrawal
        // channel: its release is spent, and the open intent must wait for fresh evidence.
        ensure!(
            !agent
                .store
                .payout_claim_completed(evidence.batch_id, evidence.claim.position())?,
            "operator re-served evidence for an already-completed external-payout claim"
        );
        Ok(())
    }

    fn verify_release(agent: &Agent, _: &Self::Evidence, release: &Self::Release) -> Result<()> {
        ensure!(
            release.receiver == agent.account(),
            "settlement returned another external payout"
        );
        Ok(())
    }

    async fn fetch<E: Env>(account: Key, ctx: &E, operator: SocketAddr) -> Result<Self::Evidence> {
        operator_rpc::external_payout_evidence(
            ctx,
            operator,
            operator_rpc::ExternalPayoutEvidenceRequest { account },
        )
        .await
    }

    async fn fetch_admitted<E: Env>(
        holders: &Holders,
        ctx: &E,
        chain: &Client,
        admitted: &AdmittedRootsResponse,
        wallet: &Wallet,
    ) -> Result<Self::Evidence> {
        ensure!(admitted.finalized, "external payout has not finalized");
        let claim = holders
            .external_payout_claim(ctx, chain, admitted, &wallet.public_key())
            .await?;
        Ok(operator_rpc::ExternalPayoutEvidenceResponse {
            batch_id: admitted.batch_id,
            claim,
        })
    }

    fn tx(deployment: Digest, evidence: &Self::Evidence) -> SettlementTx {
        SettlementTx::ClaimExternalPayout(ExternalPayoutClaimRequest {
            deployment,
            batch_id: evidence.batch_id,
            claim: evidence.claim.clone(),
        })
    }

    async fn release<E: Env>(
        ctx: &E,
        chain: &mut Client,
        evidence: &Self::Evidence,
    ) -> Result<Option<Self::Release>> {
        let Some(record) = chain
            .payout_release(ctx, evidence.batch_id, evidence.claim.position())
            .await?
        else {
            return Ok(None);
        };
        ensure!(
            record.claim == Sha256::hash(&[&evidence.claim.encode()]),
            "the released payout position consumed other evidence"
        );
        Ok(Some(record.released))
    }

    async fn acknowledge<E: Env>(
        ctx: &E,
        operator: SocketAddr,
        evidence: &Self::Evidence,
    ) -> Result<()> {
        operator_rpc::acknowledge_external_payout(
            ctx,
            operator,
            operator_rpc::AcknowledgeExternalPayoutRequest {
                batch_id: evidence.batch_id,
                claim: evidence.claim.clone(),
            },
        )
        .await
    }

    fn cache(store: &mut Store, evidence: &Self::Evidence) -> Result<()> {
        store.cache_payout_claim(evidence)
    }

    fn completed(store: &Store, evidence: &Self::Evidence) -> Result<bool> {
        store.payout_claim_completed(evidence.batch_id, evidence.claim.position())
    }

    fn complete(
        agent: &mut Agent,
        evidence: &Self::Evidence,
        release: &Self::Release,
    ) -> Result<()> {
        agent.store.complete_payout_claim(evidence, release)?;
        agent.pending_payout_claim = None;
        Ok(())
    }
}

impl Agent {
    /// Retains verified claim evidence until its exact certified release completes
    /// the durable intent. Operator acknowledgment is optional bookkeeping.
    async fn drive_claim<C: ClaimChannel, E: Env>(
        &mut self,
        ctx: &E,
        chain: &mut Client,
        operator: SocketAddr,
    ) -> Result<C::Release> {
        let pending = C::pending(self)
            .clone()
            .with_context(|| format!("no {} claim is pending", C::NOUN))?;
        let evidence = match pending.evidence {
            Some(evidence) => evidence,
            None => {
                let (fresh, roots) = match self.historical_evidence::<C, E>(ctx, chain).await? {
                    Some(fetched) => fetched,
                    None => {
                        let fresh = C::fetch(self.account(), ctx, operator)
                            .await
                            .with_context(|| format!("fetch {} evidence", C::NOUN))?;

                        // A proven-absent batch is an availability signal, never a
                        // verdict: the batch may simply not have finalized yet, so
                        // nothing is cached and the exact claim retries later.
                        let roots = chain
                            .claim_roots(ctx, C::batch(&fresh))
                            .await
                            .with_context(|| format!("look up the {} claim batch", C::NOUN))?
                            .with_context(|| {
                                format!(
                                    "the {} batch has not finalized, so its evidence is not \
                                     yet cacheable",
                                    C::NOUN
                                )
                            })?;
                        (fresh, roots)
                    }
                };
                C::bind(self, &fresh, &roots)?;
                C::cache(&mut self.store, &fresh)
                    .with_context(|| format!("cache {} evidence", C::NOUN))?;
                *C::pending_mut(self) = Some(PendingClaim {
                    evidence: Some(fresh.clone()),
                });
                fresh
            }
        };

        // Settlement adjudicates claims against finalized batches only, so a claim whose
        // batch is still inside its window waits with its verified evidence cached.
        ensure!(
            chain
                .claim_roots(ctx, C::batch(&evidence))
                .await
                .with_context(|| format!("look up the {} claim batch", C::NOUN))?
                .is_some(),
            "the {} batch has not finalized, so the cached evidence waits for finalization",
            C::NOUN
        );
        let release = if let Some(zero) = C::zero_release(&evidence) {
            zero
        } else if let Ok(Some(release)) = C::release(ctx, chain, &evidence).await {
            release
        } else {
            chain
                .deliver(ctx, &C::tx(self.deployment, &evidence))
                .await
                .with_context(|| format!("claim settlement {}", C::NOUN))?;
            // A read error (an unavailable snapshot, a briefly stale validator)
            // clears with time, so the effect poll keeps polling through it. A
            // release record consumed by other bytes fails inside C::release and
            // is likewise retried until the budget ends: it can only appear
            // through evidence this wallet did not submit.
            let mut released = None;
            for _ in 0..EFFECT_ATTEMPTS {
                if let Ok(Some(release)) = C::release(ctx, chain, &evidence).await {
                    released = Some(release);
                    break;
                }
                ctx.sleep(POLL).await;
            }
            let Some(release) = released else {
                // Not claimable yet, not included yet, or rejected without an
                // effect: indistinguishable by design, so nothing is dropped and
                // the exact claim retries later.
                anyhow::bail!(
                    "the {} claim earned no certified release yet; the exact claim retries",
                    C::NOUN
                )
            };
            release
        };
        C::verify_release(self, &evidence, &release)?;
        C::complete(self, &evidence, &release)
            .with_context(|| format!("complete {} claim", C::NOUN))?;

        // Completion retires the durable intent before optional operator bookkeeping.
        let _ = C::acknowledge(ctx, operator, &evidence).await;
        Ok(release)
    }

    /// Finds an unspent claim or the certified release of an exact saved authorization.
    async fn historical_evidence<C: ClaimChannel, E: Env>(
        &mut self,
        ctx: &E,
        chain: &mut Client,
    ) -> Result<Option<(C::Evidence, ClaimRootsResponse)>> {
        let status = chain
            .status(ctx)
            .await
            .with_context(|| format!("read the {} claim head", C::NOUN))?;
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
            if let Ok(evidence) =
                C::fetch_admitted(&self.holders, ctx, chain, &admitted, &self.wallet).await
            {
                if C::completed(&self.store, &evidence)?
                    || (!C::matches_intent(self, &evidence)
                        && C::release(ctx, chain, &evidence).await?.is_some())
                {
                    continue;
                }
                let roots = ClaimRootsResponse {
                    withdrawal_outputs: admitted.roots.withdrawal_outputs,
                    change: admitted.roots.change,
                };
                if C::bind(self, &evidence, &roots).is_err() {
                    continue;
                }
                return Ok(Some((evidence, roots)));
            }
        }
        Ok(None)
    }

    pub(crate) async fn claim_withdrawal<E: Env>(
        &mut self,
        ctx: &E,
        chain: &mut Client,
        operator: SocketAddr,
    ) -> Result<WithdrawalResponse> {
        self.drive_claim::<WithdrawalChannel, E>(ctx, chain, operator)
            .await
    }

    /// Claims this wallet's external payout.
    ///
    /// The receiver needs no out-of-band provenance: fetched evidence names its batch
    /// and is verified locally against that batch's own claim roots.
    pub(crate) async fn claim_external_payout<E: Env>(
        &mut self,
        ctx: &E,
        chain: &mut Client,
        operator: SocketAddr,
    ) -> Result<ExternalPayoutResponse> {
        if self.pending_payout_claim.is_none() {
            self.store
                .open_payout_claim()
                .context("open external payout claim")?;
            self.pending_payout_claim = Some(PendingPayoutClaim { evidence: None });
        }
        self.drive_claim::<PayoutChannel, E>(ctx, chain, operator)
            .await
    }
}
