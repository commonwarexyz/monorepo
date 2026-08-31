//! The shared claim driver for finalized withdrawal and external-payout reserves.

use super::{
    Agent,
    store::{PendingClaim, PendingPayoutClaim, PendingWithdrawalClaim, Store},
};
use crate::{
    chain::{
        client::{Chain, Client, EFFECT_ATTEMPTS, Env, POLL},
        state::{ClaimRootsResponse, ExternalPayoutResponse, WithdrawalResponse},
        tx::{ExternalPayoutClaimRequest, SettlementTx, WithdrawalClaimRequest},
    },
    operator::rpc as operator_rpc,
    protocol::Key,
};
use anyhow::{Context, Result, ensure};
use commonware_clearing::bajillion::transition::BatchId;
use commonware_codec::Encode as _;
use commonware_cryptography::{Hasher as _, Sha256, sha256::Digest};
use std::net::SocketAddr;

/// One claim kind's wiring for the shared claim driver.
trait ClaimChannel {
    type Evidence: Clone + PartialEq;
    type Release: Clone + PartialEq;

    /// Claim noun used by the driver's errors and contexts.
    const NOUN: &'static str;

    fn pending(agent: &Agent) -> &Option<PendingClaim<Self::Evidence, Self::Release>>;
    fn pending_mut(agent: &mut Agent) -> &mut Option<PendingClaim<Self::Evidence, Self::Release>>;

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

    async fn fetch<E: Env>(account: Key, ctx: &E, operator: SocketAddr) -> Result<Self::Evidence>;

    /// The claim transaction for `evidence`.
    fn tx(evidence: &Self::Evidence) -> SettlementTx;

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
    fn record(store: &mut Store, evidence: &Self::Evidence, release: &Self::Release) -> Result<()>;
    fn complete(
        store: &mut Store,
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
        evidence.batch_id
    }

    /// Binding is full local verification: the claim must open against the finalized
    /// batch's own withdrawal-outputs root, belong to this wallet's account, and pay the
    /// destination this wallet signs into every withdrawal. The output amount is
    /// deliberately unchecked: the batch may have finalized the withdrawal degraded to a
    /// zero release, and it is still the one batch that settles this claim.
    fn bind(agent: &Agent, evidence: &Self::Evidence, roots: &ClaimRootsResponse) -> Result<()> {
        let output = evidence
            .claim
            .verify::<Sha256>(&roots.withdrawal_outputs)
            .context("verify withdrawal claim against its finalized batch")?;
        ensure!(
            evidence.account == agent.account(),
            "operator returned withdrawal evidence for another account"
        );
        ensure!(
            output.destination().as_ref() == agent.wallet.name.as_bytes(),
            "operator returned withdrawal evidence for another destination"
        );

        // An old batch's still-present claim roots verify its evidence forever, so a
        // completed (batch, position) must be refused here: rebinding it would close the
        // open intent against a spent release and strand the new reserve. Like an
        // unfinalized batch this is an availability verdict, not a completion: nothing is
        // cached and the exact claim retries on fresh evidence.
        ensure!(
            !agent
                .store
                .withdrawal_claim_completed(evidence.batch_id, evidence.claim.position())?,
            "operator re-served evidence for an already-completed withdrawal claim"
        );
        Ok(())
    }

    fn verify_release(_: &Agent, evidence: &Self::Evidence, release: &Self::Release) -> Result<()> {
        ensure!(
            release.destination == *evidence.claim.output().destination()
                && release.amount == evidence.claim.output().amount(),
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

    fn tx(evidence: &Self::Evidence) -> SettlementTx {
        SettlementTx::ClaimWithdrawal(WithdrawalClaimRequest {
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
            .withdrawal_release(ctx, evidence.batch_id, evidence.claim.position())
            .await?
        else {
            return Ok(None);
        };
        ensure!(
            record.claim == Sha256::hash(&[&evidence.claim.encode()]),
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
            operator_rpc::AcknowledgeWithdrawalRequest {
                batch_id: evidence.batch_id,
                account: evidence.account.clone(),
                claim: evidence.claim.clone(),
            },
        )
        .await
    }

    fn cache(store: &mut Store, evidence: &Self::Evidence) -> Result<()> {
        store.cache_withdrawal_claim(evidence)
    }

    fn record(store: &mut Store, evidence: &Self::Evidence, release: &Self::Release) -> Result<()> {
        store.record_withdrawal_result(evidence, release)
    }

    fn complete(
        store: &mut Store,
        evidence: &Self::Evidence,
        release: &Self::Release,
    ) -> Result<()> {
        store.complete_withdrawal_claim(evidence, release)
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

    fn tx(evidence: &Self::Evidence) -> SettlementTx {
        SettlementTx::ClaimExternalPayout(ExternalPayoutClaimRequest {
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

    fn record(store: &mut Store, evidence: &Self::Evidence, release: &Self::Release) -> Result<()> {
        store.record_payout_result(evidence, release)
    }

    fn complete(
        store: &mut Store,
        evidence: &Self::Evidence,
        release: &Self::Release,
    ) -> Result<()> {
        store.complete_payout_claim(evidence, release)
    }
}

impl Agent {
    /// Resolves this wallet's open claim of `C`'s kind through the shared claim driver.
    ///
    /// A held copy always gets its submission before any replacement, and the cache exists
    /// to protect a finalized reserve against the operator vanishing after finalization.
    /// Only self-verified evidence ever enters it: each attempt without a held copy
    /// fetches fresh evidence, looks up the claim roots of the finalized batch that
    /// evidence names through a certified read, and verifies the claim locally against
    /// those roots before caching. Every cached copy is therefore releasable, so
    /// poisoning and epoch lies are structurally impossible. Bind also refuses evidence
    /// naming a (batch, position) this wallet already completed, so a re-served old
    /// batch's spent claim can never close a newer intent: the attempt fails like an
    /// unavailable batch and the exact claim retries on fresh evidence.
    ///
    /// Claims complete on the certified release record at the claim's (batch,
    /// position), which must have consumed exactly this evidence: that record is the
    /// transaction's effect and the only authoritative answer. A missing release is
    /// not a verdict (the batch may not be claimable yet, the claim may not be
    /// included yet, and a rejection is effect-free), so the exact claim retries
    /// later with the last advisory dry-run answer surfaced for diagnosis. Local
    /// verification at bind means a cached copy is always releasable against its
    /// finalized batch.
    async fn drive_claim<C: ClaimChannel, E: Env>(
        &mut self,
        ctx: &E,
        chain: &mut Client,
        operator: SocketAddr,
    ) -> Result<C::Release> {
        let pending = C::pending(self)
            .clone()
            .with_context(|| format!("no {} claim is pending", C::NOUN))?;
        let recorded = pending.result.clone();
        let evidence = match pending.evidence.clone() {
            Some(evidence) => evidence,
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
                            "the {} batch has not finalized, so its evidence is not yet cacheable",
                            C::NOUN
                        )
                    })?;
                C::bind(self, &fresh, &roots)?;
                C::cache(&mut self.store, &fresh)
                    .with_context(|| format!("cache {} evidence", C::NOUN))?;
                *C::pending_mut(self) = Some(PendingClaim {
                    evidence: Some(fresh.clone()),
                    result: None,
                });
                fresh
            }
        };
        let advice = chain
            .deliver(ctx, &C::tx(&evidence))
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
                "the {} claim earned no certified release yet; the exact claim retries \
                 (dry-run advice: {advice:?})",
                C::NOUN
            )
        };
        C::verify_release(self, &evidence, &release)?;
        if let Some(expected) = &recorded {
            ensure!(
                &release == expected,
                "settlement replayed another {} release",
                C::NOUN
            );
        } else {
            C::record(&mut self.store, &evidence, &release)
                .with_context(|| format!("persist {} release", C::NOUN))?;
            *C::pending_mut(self) = Some(PendingClaim {
                evidence: Some(evidence.clone()),
                result: Some(release.clone()),
            });
        }
        C::acknowledge(ctx, operator, &evidence)
            .await
            .with_context(|| format!("acknowledge claimed {}", C::NOUN))?;
        C::complete(&mut self.store, &evidence, &release)
            .with_context(|| format!("complete {} claim", C::NOUN))?;
        *C::pending_mut(self) = None;
        Ok(release)
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
            self.pending_payout_claim = Some(PendingPayoutClaim {
                evidence: None,
                result: None,
            });
        }
        self.drive_claim::<PayoutChannel, E>(ctx, chain, operator)
            .await
    }
}
