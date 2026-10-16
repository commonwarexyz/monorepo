//! Admission of observed artifacts, their verification, and dependency waits.
//!
//! An observed artifact passes the generic bounds below and its component's protocol precheck,
//! then waits in the store for its verification verdict. A valid artifact waits on the first
//! dependency its component names, fetched through the resolver, and is handed to the component
//! once every dependency is held. An artifact that becomes ready provides its retrieval keys,
//! which wakes every artifact waiting on one of them.
//!
//! A vote update whose signed content cannot be rebuilt yet is parked unverified on its sender's
//! vote of the tag it extends; reading an update of that vote wakes it, and it is checked again
//! then: verified once it rebuilds, dropped once the read update supersedes it.

use super::{
    components::Precheck,
    machine::Machine,
    store::{ArtifactEntry, ArtifactState},
};
use crate::{
    Epochable as _,
    multimmit::{
        machine::{
            artifact::IdentifiedArtifact,
            capability::{Capabilities, Capability, ResolverCommand},
            input::{
                Now, ObservationResult, ObservationStatus, Rejection, Step, StepError, StepStatus,
            },
            job::Issued,
            resolution::{ResolutionJob, RetrievalKey},
            verification::{
                JobId, Observation, VerificationCompletion, VerificationItem, VerificationTicket,
                VerifyJob,
            },
        },
        types::{Artifact, ArtifactId, VoteContent},
    },
    types::Attributable as _,
};
use commonware_cryptography::{Digest, Hasher, bls12381::primitives::variant::Variant};
use std::{collections::VecDeque, ops::RangeInclusive, sync::Arc};

impl<H: Hasher, V: Variant> Machine<H, V> {
    /// Classifies one cohort of observed artifacts and issues one verification job for the
    /// artifacts it schedules, admitted at `now`.
    pub(super) fn observe_artifacts(
        &mut self,
        artifacts: impl ExactSizeIterator<Item = IdentifiedArtifact<V, H::Digest>>,
        now: Now,
    ) -> Result<Step<V, H::Digest>, StepError> {
        let count = artifacts.len();
        if count > self.profile.resources().max_verification_batch() {
            return Ok(Step::from(StepStatus::CohortRejected {
                count,
                rejection: Rejection::VerificationBatchTooLarge,
            }));
        }
        let cohort = self.store.next_cohort;
        self.store.next_cohort = cohort
            .checked_add(1)
            .ok_or(StepError::IdentifierExhausted)?;
        let job = JobId::new(self.completions.next_job);
        let mut results = Vec::with_capacity(count);
        let mut items = Vec::new();
        let mut capabilities = Capabilities::new();
        for (index, identified) in (0u32..).zip(artifacts) {
            let IdentifiedArtifact {
                id,
                artifact,
                provisions,
                received,
            } = identified;
            if let Some(rejection) = self.precheck_unidentified(&artifact) {
                if rejection == Rejection::TagWindow {
                    let ticket = VerificationTicket::new(job, id, Observation::new(cohort, index));
                    items.extend(self.probe_ahead(ticket, artifact));
                }
                results.push(ObservationResult {
                    id: None,
                    status: ObservationStatus::Rejected(rejection),
                });
                continue;
            }
            // Ingress identifies artifacts off the voter loop, and every index keys off the
            // identifier, so a mismatch would poison the store.
            debug_assert_eq!(
                id,
                artifact.id::<H>(),
                "artifact identifier matches content"
            );
            let precheck = self.precheck_identified(&artifact, &id).and_then(|()| {
                self.precheck_protocol(&artifact, false)
                    .map_err(ObservationStatus::Rejected)
            });
            let precheck = match precheck {
                Ok(precheck) => precheck,
                Err(status) => {
                    results.push(ObservationResult {
                        id: Some(id),
                        status,
                    });
                    continue;
                }
            };
            let observation = Observation::new(cohort, index);
            let artifact = Arc::new(artifact);
            let (content, state) = match precheck {
                Precheck::Verify(content) => {
                    let ticket = VerificationTicket::new(job, id, observation);
                    items.push(verification_item(ticket, &artifact, content.as_ref()));
                    (content, ArtifactState::Pending(ticket))
                }
                Precheck::Park(key) => {
                    capabilities.extend(self.request(key)?);
                    (None, ArtifactState::Parked(key))
                }
            };
            self.store.insert(
                id,
                ArtifactEntry {
                    artifact,
                    provisions: provisions.into(),
                    observation,
                    received: received.map_or(now, |received| received.min(now)),
                    content,
                    state,
                },
                self.durable.state.view,
            );
            results.push(ObservationResult {
                id: Some(id),
                status: ObservationStatus::Scheduled,
            });
        }
        capabilities.extend(self.issue_verification(job, items)?);
        Ok(Step::new(StepStatus::Observed(results), capabilities))
    }

    /// Issues the verification job `job` for `items`, whose tickets name it, unless there are
    /// none.
    fn issue_verification(
        &mut self,
        job: JobId,
        items: Vec<VerificationItem<V, H::Digest>>,
    ) -> Result<Option<Capability<V, H::Digest>>, StepError> {
        if items.is_empty() {
            return Ok(None);
        }
        self.completions.next_job = self
            .completions
            .next_job
            .checked_add(1)
            .ok_or(StepError::IdentifierExhausted)?;
        let tickets = items.iter().map(VerificationItem::ticket).collect();
        self.completions.verification_jobs.insert(job, tickets);
        Ok(Some(Capability::Verify(VerifyJob::new(
            Issued::new(job, self.durable.state.generation),
            items,
        ))))
    }

    /// Checks the bounds that need no identifier: context, committee membership, size, and the
    /// window of views retained state can serve.
    ///
    /// A floor is admitted however far ahead it lies: anchoring on it is how a node far behind
    /// catches up, and its protocol precheck bounds it from below.
    fn precheck_unidentified(&self, artifact: &Artifact<V, H::Digest>) -> Option<Rejection> {
        let protocol = self.profile.protocol();
        let resources = self.profile.resources();
        if artifact.epoch() != protocol.epoch() {
            return Some(Rejection::Context);
        }
        if artifact
            .signer()
            .is_some_and(|signer| usize::from(signer) >= self.profile.codec().participants())
        {
            return Some(Rejection::Participant);
        }
        if let Artifact::TransactionBlock(block) = artifact {
            let chain = block.header().chain();
            if chain.index() >= self.profile.codec().chains() {
                return Some(Rejection::Context);
            }
            if protocol.producer(chain) != Some(block.signer()) {
                return Some(Rejection::Participant);
            }
        }
        if artifact.encoded_len() > resources.max_artifact_bytes() {
            return Some(Rejection::ArtifactTooLarge);
        }
        let state = &self.durable.state;
        let bounded = !matches!(artifact, Artifact::Floor(_));
        if artifact.view().is_some_and(|view| {
            view <= state.retired_view
                || bounded
                    && view.get().saturating_sub(state.view.get())
                        > resources.max_future_view_distance()
        }) {
            return Some(Rejection::TagWindow);
        }
        None
    }

    /// Checks duplicates and the bounds on retained and in-flight work.
    fn precheck_identified(
        &self,
        artifact: &Artifact<V, H::Digest>,
        id: &ArtifactId<H::Digest>,
    ) -> Result<(), ObservationStatus> {
        if self.store.get(id).is_some() || self.durable.references(id) {
            return Err(ObservationStatus::Duplicate);
        }
        let resources = self.profile.resources();
        let rejected = |rejection| Err(ObservationStatus::Rejected(rejection));
        if artifact
            .view()
            .is_some_and(|view| view > self.durable.state.view)
            && self.store.future_len() >= resources.max_future_artifacts()
        {
            return rejected(Rejection::FutureArtifactsFull);
        }
        if self.store.len() + self.durable.occupancy() >= resources.max_cached_artifacts() {
            return rejected(Rejection::ArtifactCacheFull);
        }
        if self.completions.verification_jobs.len() >= resources.max_inflight_verifications() {
            return rejected(Rejection::VerificationJobsFull);
        }
        Ok(())
    }

    /// Applies one verification completion: one verdict per ticket of its job, in order.
    pub(super) fn complete_verification(
        &mut self,
        completion: VerificationCompletion<H::Digest>,
        now: Now,
    ) -> Result<Step<V, H::Digest>, StepError> {
        let issued = completion.issued();
        if !self.is_current(issued) {
            return Ok(Step::stale());
        }
        let Some(tickets) = self.completions.verification_jobs.get(&issued.id()) else {
            return Ok(Step::stale());
        };
        let verdicts = completion.verdicts();
        if tickets.len() != verdicts.len()
            || tickets
                .iter()
                .zip(verdicts)
                .any(|(ticket, verdict)| *ticket != verdict.ticket())
        {
            return Err(StepError::CompletionMismatch);
        }
        self.completions.verification_jobs.remove(&issued.id());
        let (mut valid, mut invalid) = (0, 0);
        let mut capabilities = Capabilities::new();
        for verdict in verdicts {
            let ticket = verdict.ticket();
            let id = ticket.artifact();
            if self.settle_probe(ticket, verdict.valid(), &mut capabilities)? {
                continue;
            }
            // Retention may have retired the artifact while its job was in flight.
            if self
                .store
                .get(&id)
                .is_none_or(|entry| entry.state != ArtifactState::Pending(ticket))
            {
                continue;
            }
            if verdict.valid() {
                valid += 1;
                capabilities.extend(self.settle([id], now)?);
            } else {
                invalid += 1;
                self.store.remove(&id);
                capabilities.extend(self.reject_retrieved(id)?);
            }
        }
        // The completion freed a job slot: artifacts that woke while every slot was taken get
        // another check.
        let deferred = core::mem::take(&mut self.completions.awaiting_job)
            .into_iter()
            .filter(|id| {
                self.store
                    .get(id)
                    .is_some_and(|entry| matches!(entry.state, ArtifactState::Parked(_)))
            })
            .collect::<Vec<_>>();
        capabilities.extend(self.settle(deferred, now)?);
        Ok(Step::new(
            StepStatus::Verified { valid, invalid },
            capabilities,
        ))
    }

    /// Moves authenticated artifacts to their next state: waiting on their first missing
    /// dependency, or ready and handed to their component. A ready artifact releases the waiters
    /// of every key it provides, which settle in turn.
    ///
    /// A parked artifact among the waiters is checked again: it is verified once its content can
    /// be rebuilt, parked on the next key otherwise, and dropped when its check now fails. Its
    /// verification shares one job with the others it woke with. When that job would exceed the
    /// verification job bound, the artifact stays parked until a verification completes.
    pub(super) fn settle(
        &mut self,
        ids: impl IntoIterator<Item = ArtifactId<H::Digest>>,
        now: Now,
    ) -> Result<Capabilities<V, H::Digest>, StepError> {
        let mut capabilities = Capabilities::new();
        let job = JobId::new(self.completions.next_job);
        let mut unparked = Vec::new();
        let mut queue = VecDeque::from_iter(ids);
        while let Some(id) = queue.pop_front() {
            let Some(entry) = self.store.get(&id) else {
                continue;
            };
            let entry = entry.clone();
            if matches!(entry.state, ArtifactState::Parked(_)) {
                if unparked.is_empty()
                    && self.completions.verification_jobs.len()
                        >= self.profile.resources().max_inflight_verifications()
                {
                    self.completions.awaiting_job.insert(id);
                    continue;
                }
                match self.precheck_protocol(&entry.artifact, true) {
                    Ok(Precheck::Verify(content)) => {
                        let ticket = VerificationTicket::new(job, id, entry.observation);
                        unparked.push(verification_item(ticket, &entry.artifact, content.as_ref()));
                        self.store.unpark(&id, content, ticket);
                    }
                    Ok(Precheck::Park(key)) => {
                        self.store.set_state(&id, ArtifactState::Parked(key));
                        capabilities.extend(self.request(key)?);
                    }
                    Err(_) => {
                        self.store.remove(&id);
                    }
                }
                continue;
            }
            if let Some(key) = self.dependency(&entry) {
                let waiting = matches!(entry.state, ArtifactState::Waiting(_));
                if !waiting
                    && self.store.waiting_len() >= self.profile.resources().max_dependency_waiters()
                {
                    self.store.remove(&id);
                    continue;
                }
                self.store.set_state(&id, ArtifactState::Waiting(key));
                capabilities.extend(self.request(key)?);
                continue;
            }
            self.store.set_state(&id, ArtifactState::Ready);
            capabilities.extend(self.admit_ready(id, &entry, now)?);
            for key in entry.provisions.iter() {
                if let Some(job) = self.resolution.resolved(*key) {
                    capabilities.push(Capability::Resolver(ResolverCommand::Cancel(job)));
                }
                queue.extend(self.store.waiters(key));
            }
        }
        capabilities.extend(self.issue_verification(job, unparked)?);
        Ok(capabilities)
    }

    /// Settles the artifacts parked or waiting on a key within `keys`, which a component made
    /// available other than by admitting the artifact the key names.
    pub(in crate::multimmit::machine) fn settle_waiters(
        &mut self,
        keys: RangeInclusive<RetrievalKey<H::Digest>>,
        now: Now,
    ) -> Result<Capabilities<V, H::Digest>, StepError> {
        let waiters = self.store.waiters_within(keys);
        self.settle(waiters, now)
    }

    /// Requests the artifact `key` names unless a request for it is outstanding.
    pub(in crate::multimmit::machine) fn request(
        &mut self,
        key: RetrievalKey<H::Digest>,
    ) -> Result<Option<Capability<V, H::Digest>>, StepError> {
        let job = self
            .resolution
            .request(
                self.durable.state.generation,
                key,
                self.profile.resources().max_dependency_waiters(),
            )
            .map_err(|_| StepError::IdentifierExhausted)?;
        Ok(job.map(|job| Capability::Resolver(ResolverCommand::Resolve(job))))
    }

    /// Requests the keys stored artifacts wait on without a request, once a request table that
    /// refused one has room again.
    pub(super) fn request_starved(&mut self) -> Result<Capabilities<V, H::Digest>, StepError> {
        let mut capabilities = Capabilities::new();
        if !self
            .resolution
            .take_starved(self.profile.resources().max_dependency_waiters())
        {
            return Ok(capabilities);
        }
        let keys = self
            .store
            .waited_keys()
            .filter(|key| !self.resolution.contains(key))
            .copied()
            .collect::<Vec<_>>();
        for key in keys {
            capabilities.extend(self.request(key)?);
        }
        Ok(capabilities)
    }

    /// Ends the failed retrieval `job`, whose record is gone, with the resolver through
    /// `command`, and requests its key again while an artifact still waits on it.
    pub(super) fn retry_retrieval(
        &mut self,
        job: ResolutionJob<H::Digest>,
        command: ResolverCommand<H::Digest>,
    ) -> Result<Capabilities<V, H::Digest>, StepError> {
        let mut capabilities = vec![Capability::Resolver(command)];
        if self.store.has_waiters(&job.key()) {
            capabilities.extend(self.request(job.key())?);
        }
        Ok(capabilities)
    }

    /// Rejects the retrievals that returned the invalid artifact `id` and requests their keys
    /// again while an artifact still waits on them.
    fn reject_retrieved(
        &mut self,
        id: ArtifactId<H::Digest>,
    ) -> Result<Capabilities<V, H::Digest>, StepError> {
        let mut capabilities = Capabilities::new();
        for job in self.resolution.verification_failed(id) {
            capabilities.extend(self.retry_retrieval(job, ResolverCommand::Reject(job))?);
        }
        Ok(capabilities)
    }
}

/// Returns the verification item of `artifact` under `ticket`, covering a vote update's rebuilt
/// `content`.
fn verification_item<V: Variant, D: Digest>(
    ticket: VerificationTicket<D>,
    artifact: &Arc<Artifact<V, D>>,
    content: Option<&Arc<VoteContent<D>>>,
) -> VerificationItem<V, D> {
    content.map_or_else(
        || VerificationItem::new(ticket, Arc::clone(artifact)),
        |content| VerificationItem::update(ticket, Arc::clone(artifact), Arc::clone(content)),
    )
}
