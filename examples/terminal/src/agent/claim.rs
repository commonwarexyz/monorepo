//! The shared claim driver for finalized withdrawal and external-payout reserves.

use super::{
    Agent,
    store::{PendingClaim, PendingPayoutClaim, PendingWithdrawalClaim, Store},
};
use crate::{operator::rpc as operator_rpc, settlement::rpc as settlement_rpc};
use anyhow::{Context, Result, ensure};
use commonware_clearing::bajillion::transition::BatchId;
use commonware_cryptography::{Sha256, sha256::Digest};
use commonware_runtime::Network;
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
    fn bind(
        agent: &Agent,
        evidence: &Self::Evidence,
        roots: &settlement_rpc::ClaimRootsResponse,
    ) -> Result<()>;

    /// Confirms a settlement release pays what the bound evidence certifies.
    fn verify_release(
        agent: &Agent,
        evidence: &Self::Evidence,
        release: &Self::Release,
    ) -> Result<()>;

    async fn fetch<E: Network>(
        agent: &Agent,
        network: &E,
        operator: SocketAddr,
    ) -> Result<Self::Evidence>;

    async fn submit<E: Network>(
        network: &E,
        settlement: SocketAddr,
        evidence: &Self::Evidence,
    ) -> Result<settlement_rpc::ClaimResponse<Self::Release>>;

    async fn acknowledge<E: Network>(
        network: &E,
        operator: SocketAddr,
        evidence: &Self::Evidence,
    ) -> Result<()>;

    fn cache(store: &mut Store, evidence: &Self::Evidence) -> Result<()>;
    fn drop_evidence(store: &mut Store, evidence: &Self::Evidence) -> Result<()>;
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
    type Release = settlement_rpc::WithdrawalResponse;

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
    fn bind(
        agent: &Agent,
        evidence: &Self::Evidence,
        roots: &settlement_rpc::ClaimRootsResponse,
    ) -> Result<()> {
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

    async fn fetch<E: Network>(
        agent: &Agent,
        network: &E,
        operator: SocketAddr,
    ) -> Result<Self::Evidence> {
        operator_rpc::withdrawal_evidence(
            network,
            operator,
            operator_rpc::WithdrawalEvidenceRequest {
                account: agent.account(),
            },
        )
        .await
    }

    async fn submit<E: Network>(
        network: &E,
        settlement: SocketAddr,
        evidence: &Self::Evidence,
    ) -> Result<settlement_rpc::ClaimResponse<Self::Release>> {
        settlement_rpc::claim_withdrawal(
            network,
            settlement,
            settlement_rpc::WithdrawalClaimRequest {
                batch_id: evidence.batch_id,
                claim: evidence.claim.clone(),
            },
        )
        .await
    }

    async fn acknowledge<E: Network>(
        network: &E,
        operator: SocketAddr,
        evidence: &Self::Evidence,
    ) -> Result<()> {
        operator_rpc::acknowledge_withdrawal(
            network,
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

    fn drop_evidence(store: &mut Store, evidence: &Self::Evidence) -> Result<()> {
        store.drop_withdrawal_claim_evidence(evidence)
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
    type Release = settlement_rpc::ExternalPayoutResponse;

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
    fn bind(
        agent: &Agent,
        evidence: &Self::Evidence,
        roots: &settlement_rpc::ClaimRootsResponse,
    ) -> Result<()> {
        let payout = evidence
            .claim
            .verify::<Sha256>(&roots.change)
            .context("verify external payout claim against its finalized batch")?;
        ensure!(
            payout.recipient == agent.account(),
            "operator returned external-payout evidence for another account"
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

    async fn fetch<E: Network>(
        agent: &Agent,
        network: &E,
        operator: SocketAddr,
    ) -> Result<Self::Evidence> {
        operator_rpc::external_payout_evidence(
            network,
            operator,
            operator_rpc::ExternalPayoutEvidenceRequest {
                account: agent.account(),
            },
        )
        .await
    }

    async fn submit<E: Network>(
        network: &E,
        settlement: SocketAddr,
        evidence: &Self::Evidence,
    ) -> Result<settlement_rpc::ClaimResponse<Self::Release>> {
        settlement_rpc::claim_external_payout(
            network,
            settlement,
            settlement_rpc::ExternalPayoutClaimRequest {
                batch_id: evidence.batch_id,
                claim: evidence.claim.clone(),
            },
        )
        .await
    }

    async fn acknowledge<E: Network>(
        network: &E,
        operator: SocketAddr,
        evidence: &Self::Evidence,
    ) -> Result<()> {
        operator_rpc::acknowledge_external_payout(
            network,
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

    fn drop_evidence(store: &mut Store, evidence: &Self::Evidence) -> Result<()> {
        store.drop_payout_claim_evidence(evidence)
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
    /// evidence names, and verifies the claim locally against those roots before caching.
    /// Every cached copy is therefore releasable, so poisoning and epoch lies are
    /// structurally impossible.
    async fn drive_claim<C: ClaimChannel, E: Network>(
        &mut self,
        network: &E,
        settlement: SocketAddr,
        operator: SocketAddr,
    ) -> Result<C::Release> {
        let pending = C::pending(self)
            .clone()
            .with_context(|| format!("no {} claim is pending", C::NOUN))?;
        let recorded = pending.result.clone();
        let evidence = match pending.evidence.clone() {
            Some(evidence) => evidence,
            None => {
                let fresh = C::fetch(self, network, operator)
                    .await
                    .with_context(|| format!("fetch {} evidence", C::NOUN))?;

                // An unknown batch is an availability signal, never a verdict: the batch
                // may simply not have finalized yet, so nothing is cached and the exact
                // claim retries later.
                let roots = settlement_rpc::claim_roots(network, settlement, C::batch(&fresh))
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
        let release = match C::submit(network, settlement, &evidence)
            .await
            .with_context(|| format!("claim settlement {}", C::NOUN))?
        {
            settlement_rpc::ClaimResponse::Released(release) => release,
            settlement_rpc::ClaimResponse::Unavailable => {
                // The batch may not be claimable at this instant. Nothing is dropped: the
                // exact claim retries later.
                anyhow::bail!("{} batch is not claimable yet", C::NOUN)
            }
            settlement_rpc::ClaimResponse::Invalid => {
                // Adjudicated against an immutable finalized batch, so this exact copy can
                // never succeed. Local verification at bind makes this arm unreachable for
                // cached copies, but it stays as the honest fallback: drop only the cache
                // and keep the intent open. Evidence with a recorded release is never
                // dropped: settlement already paid it and only the operator
                // acknowledgement is outstanding.
                ensure!(
                    recorded.is_none(),
                    "settlement rejected a {} claim it already released",
                    C::NOUN
                );
                C::drop_evidence(&mut self.store, &evidence)
                    .with_context(|| format!("drop rejected {} evidence", C::NOUN))?;
                *C::pending_mut(self) = Some(PendingClaim {
                    evidence: None,
                    result: None,
                });
                anyhow::bail!("settlement rejected the cached {} evidence", C::NOUN)
            }
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
        C::acknowledge(network, operator, &evidence)
            .await
            .with_context(|| format!("acknowledge claimed {}", C::NOUN))?;
        C::complete(&mut self.store, &evidence, &release)
            .with_context(|| format!("complete {} claim", C::NOUN))?;
        *C::pending_mut(self) = None;
        Ok(release)
    }

    pub(crate) async fn claim_withdrawal<E: Network>(
        &mut self,
        network: &E,
        settlement: SocketAddr,
        operator: SocketAddr,
    ) -> Result<settlement_rpc::WithdrawalResponse> {
        self.drive_claim::<WithdrawalChannel, E>(network, settlement, operator)
            .await
    }

    /// Claims this wallet's external payout.
    ///
    /// The receiver needs no out-of-band provenance: fetched evidence names its batch
    /// and is verified locally against that batch's own claim roots.
    pub(crate) async fn claim_external_payout<E: Network>(
        &mut self,
        network: &E,
        settlement: SocketAddr,
        operator: SocketAddr,
    ) -> Result<settlement_rpc::ExternalPayoutResponse> {
        if self.pending_payout_claim.is_none() {
            self.store
                .open_payout_claim()
                .context("open external payout claim")?;
            self.pending_payout_claim = Some(PendingPayoutClaim {
                evidence: None,
                result: None,
            });
        }
        self.drive_claim::<PayoutChannel, E>(network, settlement, operator)
            .await
    }
}
