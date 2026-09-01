//! Admission of observed artifacts and their prechecks.

use super::{
    machine::Machine,
    store::{ArtifactEntry, ArtifactState, vote_slot_key},
};
use crate::{
    Epochable, Viewable,
    multimmit::{
        machine::{
            artifact::{Dependency, IdentifiedArtifact},
            capability::{Capabilities, Capability},
            input::{ObservationResult, ObservationStatus, Rejection, Step, StepError, StepStatus},
            job::Issued,
            verification::{JobId, Observation, VerificationItem, VerificationTicket, VerifyJob},
        },
        types::{Anchor, Artifact, ArtifactId, ChainId},
    },
    types::{Attributable, Height},
};
use commonware_cryptography::{Hasher, bls12381::primitives::variant::Variant};
use std::sync::Arc;

/// Holds back one slot of `limit` for view-critical work while at least two slots exist.
const fn reserve_one(limit: usize) -> usize {
    if limit >= 2 { limit - 1 } else { limit }
}

impl<H: Hasher, V: Variant> Machine<H, V> {
    pub(super) fn observe_artifacts(
        &mut self,
        artifacts: impl ExactSizeIterator<Item = IdentifiedArtifact<V, H::Digest>>,
    ) -> Result<Step<V, H::Digest>, StepError> {
        let artifact_count = artifacts.len();
        let cohort = self.store.next_cohort;
        self.store.next_cohort = self
            .store
            .next_cohort
            .checked_add(1)
            .ok_or(StepError::IdentifierExhausted)?;

        let resources = self.profile.resources();
        if artifact_count > resources.max_verification_batch()
            || u32::try_from(artifact_count).is_err()
        {
            return Ok(Step::from(StepStatus::CohortRejected {
                count: artifact_count,
                rejection: Rejection::VerificationBatchTooLarge,
            }));
        }

        let job = JobId::new(self.completions.next_job);
        let local_artifact_reservations = self.local_artifact_reservations();
        let mut results = Vec::with_capacity(artifact_count);
        let mut items = None;

        for (index, identified) in artifacts.enumerate() {
            let IdentifiedArtifact {
                id,
                artifact,
                provisions,
            } = identified;
            let observation = Observation::new(cohort, index as u32);
            if let Some(rejection) = self.precheck_unidentified(&artifact) {
                results.push(ObservationResult {
                    id: None,
                    status: ObservationStatus::Rejected(rejection),
                });
                continue;
            }

            // Identifiers arrive precomputed from the same-process batcher, and every retained
            // index keys off them. A mismatch would poison the artifact cache, so it is checked
            // wherever the extra hash is affordable.
            debug_assert_eq!(
                id,
                artifact.id::<H>(),
                "artifact identifier matches content"
            );
            let mut status = self.precheck_identified(&artifact, id, local_artifact_reservations);
            let dependency_slot =
                status == ObservationStatus::Scheduled && self.needs_dependency_slot(&artifact);
            if dependency_slot
                && self.dependencies.slots >= self.profile.resources().max_dependency_waiters()
            {
                status = ObservationStatus::Rejected(Rejection::DependencyWaitersFull);
            }

            if status == ObservationStatus::Scheduled
                && let Artifact::DaCertificate(certificate) = &artifact
                && !self
                    .chain
                    .da
                    .claim_certificate::<H>(id, observation, certificate)?
            {
                status = ObservationStatus::Duplicate;
            }

            if status != ObservationStatus::Scheduled {
                results.push(ObservationResult {
                    id: Some(id),
                    status,
                });
                continue;
            }

            let future = artifact
                .view()
                .is_some_and(|view| view > self.durable.state.view);
            if artifact.self_certifying_view() {
                self.make_room_for_view_proof(future)?;
            }
            let artifact = Arc::new(artifact);
            let ticket = VerificationTicket::new(job, id, observation);
            self.insert_pending(
                ticket,
                observation,
                &artifact,
                provisions,
                future,
                dependency_slot,
            )?;
            let known = self.known_constituents(id, &artifact);
            items
                .get_or_insert_with(|| Vec::with_capacity(artifact_count))
                .push(VerificationItem::new(ticket, artifact, known));
            results.push(ObservationResult {
                id: Some(id),
                status,
            });
        }

        let mut capabilities = if let Some(items) = items {
            self.completions.next_job = self
                .completions
                .next_job
                .checked_add(1)
                .ok_or(StepError::IdentifierExhausted)?;
            let tickets = items.iter().map(VerificationItem::ticket).collect();
            self.completions.verification_jobs.insert(job, tickets);
            vec![Capability::Verify(VerifyJob::new(
                Issued::new(job, self.durable.state.generation),
                items,
            ))]
        } else {
            Capabilities::new()
        };
        capabilities.extend(self.chain.take_capabilities());

        Ok(Step::new(StepStatus::Observed(results), capabilities))
    }

    /// Evicts refetchable future gossip until an admitted view proof fits its bounds; see
    /// [`Self::evict_future_gossip`].
    fn make_room_for_view_proof(&mut self, future: bool) -> Result<(), StepError> {
        let resources = self.profile.resources();
        while (future && self.store.future.len() >= resources.max_future_artifacts())
            || self.store.artifacts.len() + self.local_artifact_reservations()
                >= resources.max_cached_artifacts()
        {
            if !self.evict_future_gossip()? {
                break;
            }
        }
        Ok(())
    }

    /// Retains an artifact awaiting the verification `ticket`, with its claims and indexes.
    fn insert_pending(
        &mut self,
        ticket: VerificationTicket<H::Digest>,
        observation: Observation,
        artifact: &Arc<Artifact<V, H::Digest>>,
        provisions: Vec<Dependency<H::Digest>>,
        future: bool,
        dependency_slot: bool,
    ) -> Result<(), StepError> {
        let id = ticket.artifact();
        // A proposal is actionable only with its parent certificate. Keeping an unresolved
        // proposal as a transition claim would order later V-QCs and nullifications behind a
        // dependency that the view owner cannot discharge.
        let deferred_proposal =
            dependency_slot && matches!(artifact.as_ref(), Artifact::LeaderBlock(_));
        if !deferred_proposal {
            self.views.claim(id, observation, artifact);
        }
        self.claim_finality(id, observation, Arc::clone(artifact))?;
        debug_assert_eq!(provisions, artifact.provisions::<H>());
        let provisions = Arc::<[_]>::from(provisions);
        self.dependencies.add_provider(id, &provisions);
        let position = self.floor_position(artifact);
        self.retain_entry(
            id,
            ArtifactEntry {
                artifact: Arc::clone(artifact),
                provisions,
                observation,
                state: ArtifactState::Pending(ticket),
                dependency_protected: false,
                future,
                view_observed: false,
                dependency_slot,
            },
            position,
        );
        if let Artifact::DaVote(vote) = artifact.as_ref()
            && self.above_durable_tip(vote.header().chain(), vote.header().height())
        {
            self.store.claim_vote_slot(vote_slot_key(vote), id);
        }
        Ok(())
    }

    /// Returns already verified artifacts that let the executor discharge terms of `artifact`'s
    /// verification without pairings.
    ///
    /// A certificate over messages this node already verified needs no pairings: the executor
    /// discharges every transcript term a known signature reproduces. A leader block anchors
    /// every chain on a data-availability certificate; the ones this node already holds are
    /// attached so only unseen anchors cost a pairing. A late DA vote, at or below the durable
    /// certified tip, is attached to this signer's earlier vote for another block at the same
    /// height. Above the tip a vote is admitted only into an empty slot, so no earlier vote
    /// exists.
    fn known_constituents(
        &self,
        id: ArtifactId<H::Digest>,
        artifact: &Artifact<V, H::Digest>,
    ) -> Vec<Arc<Artifact<V, H::Digest>>> {
        match artifact {
            Artifact::Vqc(certificate) => self.views.verified_messages(certificate.view()),
            Artifact::Lqc(certificate) => self.views.verified_messages(certificate.view()),
            Artifact::LeaderBlock(block) => block
                .block()
                .proposals()
                .iter()
                .filter_map(|proposal| match proposal.anchor() {
                    Anchor::Certificate(certificate) => self
                        .chain
                        .da
                        .held_certificate(certificate.block_ref::<H>())
                        .filter(|held| *held == certificate)
                        .map(|held| Arc::new(Artifact::DaCertificate(held.clone()))),
                    Anchor::Tip(_) => None,
                })
                .collect(),
            Artifact::DaVote(vote)
                if self.above_durable_tip(vote.header().chain(), vote.header().height()) =>
            {
                Vec::new()
            }
            Artifact::DaVote(vote) => self
                .store
                .by_position
                .get(&(vote.header().chain(), vote.header().height()))
                .into_iter()
                .flatten()
                .filter(|candidate| **candidate != id)
                .filter_map(|candidate| {
                    let entry = self.store.artifacts.get(candidate)?;
                    match entry.artifact.as_ref() {
                        Artifact::DaVote(prior)
                            if prior.signer() == vote.signer()
                                && prior.header() != vote.header() =>
                        {
                            Some(Arc::clone(&entry.artifact))
                        }
                        _ => None,
                    }
                })
                .collect(),
            _ => Vec::new(),
        }
    }

    fn precheck_unidentified(&self, artifact: &Artifact<V, H::Digest>) -> Option<Rejection> {
        let resources = self.profile.resources();
        let protocol = self.profile.protocol();
        if artifact.epoch() != protocol.epoch() {
            return Some(Rejection::Context);
        }
        if artifact.signer().is_some_and(|participant| {
            participant.get() as usize >= protocol.codec_config().participants()
        }) {
            return Some(Rejection::Participant);
        }
        let chain = match artifact {
            Artifact::TransactionBlock(block) => Some(block.header().chain()),
            Artifact::DaVote(vote) => Some(vote.header().chain()),
            Artifact::DaCertificate(certificate) => Some(certificate.header().chain()),
            _ => None,
        };
        if chain.is_some_and(|chain| chain.get() as usize >= protocol.codec_config().chains()) {
            return Some(Rejection::Context);
        }
        if let Artifact::TransactionBlock(block) = artifact
            && protocol.producer(block.header().chain()) != Some(block.signer())
        {
            return Some(Rejection::Participant);
        }
        if artifact.encoded_len() > resources.max_artifact_bytes() {
            return Some(Rejection::ArtifactTooLarge);
        }
        if let Some(view) = artifact.view()
            && view > self.durable.state.view
            && !artifact.self_certifying_view()
            && view.get().saturating_sub(self.durable.state.view.get())
                > resources.max_future_view_distance()
        {
            return Some(Rejection::FutureView);
        }
        // Only a chain's producer recovers certificates from its data-availability votes.
        if let Artifact::DaVote(vote) = artifact
            && !self.chain.produces(vote.header().chain())
        {
            return Some(Rejection::Unsolicited);
        }
        if let Artifact::TransactionBlock(_) | Artifact::DaVote(_) = artifact
            && let Some((chain, height)) = artifact.chain_position()
            && height
                .get()
                .saturating_sub(self.certified_frontier(chain).get())
                > self.profile.height_window()
        {
            return Some(Rejection::FutureHeight);
        }
        None
    }

    /// Returns the greatest height `chain` is known certified at: its durable certified tip or a
    /// DA certificate this node holds.
    fn certified_frontier(&self, chain: ChainId) -> Height {
        self.durable
            .state
            .certified_height(chain)
            .unwrap_or_default()
            .max(self.chain.da.certified_anchor(chain).height())
    }

    /// Returns whether `height` sits above `chain`'s durable certified tip.
    fn above_durable_tip(&self, chain: ChainId, height: Height) -> bool {
        self.durable
            .state
            .certified_height(chain)
            .is_none_or(|tip| height > tip)
    }

    /// Checks the bound one chain position places on `artifact`.
    ///
    /// A position retains at most
    /// [`VERIFIED_BLOCKS_PER_HEIGHT`](crate::multimmit::config::VERIFIED_BLOCKS_PER_HEIGHT)
    /// verified producer blocks. On the chain this node produces, a position above the durable
    /// certified tip retains one data-availability vote per signer, for a header this node holds
    /// a verified block for. Votes at or below the tip are late and retire as soon as they are
    /// ready.
    fn precheck_position(&self, artifact: &Artifact<V, H::Digest>) -> Option<Rejection> {
        match artifact {
            Artifact::TransactionBlock(block) => self
                .store
                .verified_blocks_full((block.header().chain(), block.header().height()))
                .then_some(Rejection::PositionFull),
            Artifact::DaVote(vote) => {
                let header = vote.header();
                if !self.above_durable_tip(header.chain(), header.height()) {
                    None
                } else if !self.store.holds_verified_header(header) {
                    Some(Rejection::Unsolicited)
                } else {
                    self.store
                        .vote_slots
                        .contains_key(&vote_slot_key(vote))
                        .then_some(Rejection::PositionFull)
                }
            }
            _ => None,
        }
    }

    fn precheck_identified(
        &self,
        artifact: &Artifact<V, H::Digest>,
        id: ArtifactId<H::Digest>,
        local_artifact_reservations: usize,
    ) -> ObservationStatus {
        if let Some(existing) = self.store.artifacts.get(&id) {
            // An identifier hashes the exact encoding, so a hit names the same artifact under
            // the collision resistance the journal and resolution already stand on. Comparing
            // the values instead would force the arriving copy's lazy signature decodes, and
            // gossip echoes make that the machine's dominant arrival cost.
            debug_assert!(
                existing.artifact.as_ref() == artifact,
                "two artifacts encode to one identifier"
            );
            return ObservationStatus::Duplicate;
        }
        if let Some(rejection) = self.precheck_position(artifact) {
            return ObservationStatus::Rejected(rejection);
        }

        let resources = self.profile.resources();
        // Remote non-proof ingress leaves cache room for the atomic timeout choice and one
        // self-certifying view proof. Verification separately keeps one job slot for that proof.
        // Producer ingress leaves one slot for view messages in each non-proof partition
        // with at least two slots.
        let anchor = artifact.self_certifying_view();
        if !anchor
            && let Some(view) = artifact.view()
            && view > self.durable.state.view
            && self.store.future.len() >= resources.max_future_artifacts()
        {
            return ObservationStatus::Rejected(Rejection::FutureArtifactsFull);
        }
        let cache_occupancy = self.store.artifacts.len() + local_artifact_reservations;
        let mut cache_limit = if anchor {
            resources.max_cached_artifacts()
        } else {
            resources.remote_artifact_capacity()
        };
        if !artifact.view_critical() {
            cache_limit = reserve_one(cache_limit);
        }
        if cache_occupancy >= cache_limit {
            // Occupancy outside the remote-ingress partition belongs to current-view work or
            // local protocol reservations and cannot be discarded here.
            if !anchor || self.store.future.is_empty() {
                return ObservationStatus::Rejected(Rejection::ArtifactCacheFull);
            }
        }
        let mut verification_limit = resources
            .max_inflight_verifications()
            .saturating_sub(usize::from(!anchor));
        if !artifact.view_critical() {
            verification_limit = reserve_one(verification_limit);
        }
        if self.completions.verification_jobs.len() >= verification_limit {
            return ObservationStatus::Rejected(Rejection::VerificationJobsFull);
        }

        ObservationStatus::Scheduled
    }
}
