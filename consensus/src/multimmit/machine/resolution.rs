//! Retrieval keys and the bounded requests the machine issues to the resolver.
//!
//! The machine asks the resolver for an artifact it needs but has not received: a sender's vote of
//! a view tag an update is encoded against, a header a tip or path names, a parent V-QC, a view's
//! V-QC, a view's leader block, an L-QC, or a peer's newest finalization certificate. At most one
//! request is outstanding per key, and it is cancelled once the machine no longer needs the
//! artifact, however it arrived.

use super::{
    artifact::IdentifiedArtifact,
    job::{Generation, IdSequence, Issued, SequenceId},
};
use crate::{
    multimmit::types::{ArtifactId, CertificateId, ChainId},
    types::{Participant, View},
};
use commonware_cryptography::{Digest, bls12381::primitives::variant::Variant};
use std::collections::BTreeMap;

/// Names one artifact a peer can serve.
///
/// A key also names what an admitted artifact provides, so arrival through ingress or through a
/// retrieval satisfies the same waiters.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub(crate) enum RetrievalKey<D: Digest> {
    /// A vote update of `signer` for `view`.
    ///
    /// The key names the sender's vote of the tag, not one update: a peer answers with the
    /// sender's latest update of the tag naming every chain, which needs no predecessor and
    /// supersedes every earlier update of the tag. Every update of the tag provides the key, so
    /// reading any of them wakes the updates waiting on the tag.
    Update {
        /// The update's signer.
        signer: Participant,
        /// The view tagging the update.
        view: View,
    },
    /// The signed header with `digest` on `chain`.
    Header {
        /// The header's producer chain.
        chain: ChainId,
        /// The header digest.
        digest: D,
    },
    /// The V-QC with this identifier.
    Vqc(CertificateId<D>),
    /// Any V-QC for this view.
    VqcView(View),
    /// The leader block of this view.
    LeaderBlock(View),
    /// The L-QC with this identifier.
    Lqc(CertificateId<D>),
    /// The peer's newest finalization certificate with its opening.
    ///
    /// The answer depends on the peer and changes as it finalizes views, so it is always fetched
    /// from peers, never served from this node's own custody.
    LatestFloor,
}

impl<D: Digest> RetrievalKey<D> {
    /// Returns the view the key is scoped to, if it is view-scoped.
    pub(crate) const fn view(&self) -> Option<View> {
        match self {
            Self::Update { view, .. } | Self::VqcView(view) | Self::LeaderBlock(view) => {
                Some(*view)
            }
            Self::Header { .. } | Self::Vqc(_) | Self::Lqc(_) | Self::LatestFloor => None,
        }
    }

    /// Returns whether the key names a vote update or a header, which only stored artifacts
    /// waiting on them request.
    const fn requested_by_waiters(&self) -> bool {
        matches!(self, Self::Update { .. } | Self::Header { .. })
    }
}

/// Identifies one volatile retrieval within a process generation.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct ResolutionId(u64);

impl ResolutionId {
    /// Returns the generation-local sequence.
    pub(crate) const fn get(self) -> u64 {
        self.0
    }
}

impl SequenceId for ResolutionId {
    fn at(sequence: u64) -> Self {
        Self(sequence)
    }
}

/// One deduplicated retrieval of the artifact a key names.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct ResolutionJob<D: Digest> {
    issued: Issued<ResolutionId>,
    key: RetrievalKey<D>,
}

impl<D: Digest> ResolutionJob<D> {
    /// Creates a job. Production jobs are issued only by [`ResolutionState::request`].
    pub(crate) const fn new(issued: Issued<ResolutionId>, key: RetrievalKey<D>) -> Self {
        Self { issued, key }
    }

    /// Returns the request's identity and issuing generation.
    pub(crate) const fn issued(self) -> Issued<ResolutionId> {
        self.issued
    }

    /// Returns the retrieved key.
    pub(crate) const fn key(self) -> RetrievalKey<D> {
        self.key
    }
}

#[cfg(test)]
impl<D: Digest> ResolutionJob<D> {
    /// Returns job `id` of `generation` retrieving `key`, for tests outside the machine.
    pub(crate) const fn for_test(id: u64, generation: Generation, key: RetrievalKey<D>) -> Self {
        Self::new(Issued::new(ResolutionId(id), generation), key)
    }
}

/// A retrieved artifact correlated to its request.
///
/// The resolver identifies the artifact on its own task, as ingress does, and the machine admits
/// it through the same checks as an observed artifact.
#[derive(Clone, Debug)]
pub(crate) struct ResolutionCompletion<V: Variant, D: Digest> {
    job: ResolutionJob<D>,
    artifact: Box<IdentifiedArtifact<V, D>>,
}

impl<V: Variant, D: Digest> ResolutionCompletion<V, D> {
    /// Creates the completion of `job`.
    pub(crate) fn new(job: ResolutionJob<D>, artifact: IdentifiedArtifact<V, D>) -> Self {
        Self {
            job,
            artifact: Box::new(artifact),
        }
    }

    /// Returns the request this completes.
    pub(crate) const fn job(&self) -> ResolutionJob<D> {
        self.job
    }

    /// Returns the retrieved artifact.
    pub(crate) const fn artifact(&self) -> &IdentifiedArtifact<V, D> {
        &self.artifact
    }

    /// Returns the retrieved artifact, consuming the completion.
    pub(crate) fn into_artifact(self) -> IdentifiedArtifact<V, D> {
        *self.artifact
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum ResolutionStatus<D: Digest> {
    InFlight,
    Verifying(ArtifactId<D>),
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
struct ResolutionRecord<D: Digest> {
    job: ResolutionJob<D>,
    status: ResolutionStatus<D>,
}

/// A retrieval the machine could not issue.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum ResolutionError {
    /// The generation-local request identifier overflowed.
    #[error("resolution identifier exhausted")]
    IdentifierExhausted,
}

/// Machine-wide ownership of bounded retrievals.
///
/// A request stays keyed while an attempt is in flight or its returned artifact is undergoing
/// ordinary verification. Removing a failed attempt lets the same key be retried with a fresh
/// identifier in the same process generation.
///
/// The table bound counts only requests for vote updates and headers, which peers' vote traffic
/// can demand in bulk: a node behind its peers holds many updates encoded against earlier ones it
/// never saw. Requests for certificates and leader blocks are always issued, so that traffic never
/// starves the parent V-QCs through which such a node catches up; the stored artifacts that wait on
/// them, the views, and the durable certificates bound those instead. A request refused because the
/// table is full marks the state starved, so the machine requests the keys still waited on once a
/// request is released.
pub(crate) struct ResolutionState<D: Digest> {
    records: BTreeMap<RetrievalKey<D>, ResolutionRecord<D>>,
    /// The number of keys in `records` the table bound counts.
    bounded: usize,
    ids: IdSequence<ResolutionId>,
    starved: bool,
}

impl<D: Digest> Default for ResolutionState<D> {
    fn default() -> Self {
        Self::new()
    }
}

impl<D: Digest> ResolutionState<D> {
    /// Creates state with no outstanding requests.
    pub(crate) const fn new() -> Self {
        Self {
            records: BTreeMap::new(),
            bounded: 0,
            ids: IdSequence::new(),
            starved: false,
        }
    }

    /// Issues one deduplicated job, holding at most `limit` outstanding requests for vote updates
    /// and headers.
    pub(crate) fn request(
        &mut self,
        generation: Generation,
        key: RetrievalKey<D>,
        limit: usize,
    ) -> Result<Option<ResolutionJob<D>>, ResolutionError> {
        if self.records.contains_key(&key) {
            return Ok(None);
        }
        let counted = key.requested_by_waiters();
        if counted && self.bounded >= limit {
            self.starved = true;
            return Ok(None);
        }
        let id = self
            .ids
            .issue()
            .ok_or(ResolutionError::IdentifierExhausted)?;
        let job = ResolutionJob::new(Issued::new(id, generation), key);
        self.records.insert(
            key,
            ResolutionRecord {
                job,
                status: ResolutionStatus::InFlight,
            },
        );
        self.bounded += usize::from(counted);
        Ok(Some(job))
    }

    /// Returns whether a request was refused for a full table since the last call that returned
    /// `true`, now that fewer than `limit` bounded requests are outstanding.
    pub(crate) fn take_starved(&mut self, limit: usize) -> bool {
        self.bounded < limit && core::mem::take(&mut self.starved)
    }

    /// Returns whether a request for `key` is outstanding.
    pub(crate) fn contains(&self, key: &RetrievalKey<D>) -> bool {
        self.records.contains_key(key)
    }

    /// Returns whether `job` is the in-flight request for its key.
    pub(crate) fn matches(&self, job: ResolutionJob<D>) -> bool {
        self.records
            .get(&job.key())
            .is_some_and(|record| record.status == ResolutionStatus::InFlight && record.job == job)
    }

    /// Marks the request for `key` as waiting on verification of the returned `artifact`.
    pub(crate) fn begin_verification(&mut self, key: RetrievalKey<D>, artifact: ArtifactId<D>) {
        if let Some(record) = self.records.get_mut(&key) {
            record.status = ResolutionStatus::Verifying(artifact);
        }
    }

    /// Removes and returns the requests whose returned `artifact` failed verification, so their
    /// keys can be requested again.
    pub(crate) fn verification_failed(&mut self, artifact: ArtifactId<D>) -> Vec<ResolutionJob<D>> {
        let mut failed = Vec::new();
        let bounded = &mut self.bounded;
        self.records.retain(|key, record| {
            let matched = record.status == ResolutionStatus::Verifying(artifact);
            if matched {
                *bounded -= usize::from(key.requested_by_waiters());
                failed.push(record.job);
            }
            !matched
        });
        failed
    }

    /// Removes and returns the request for `key`.
    pub(crate) fn resolved(&mut self, key: RetrievalKey<D>) -> Option<ResolutionJob<D>> {
        let record = self.records.remove(&key)?;
        self.bounded -= usize::from(key.requested_by_waiters());
        Some(record.job)
    }

    /// Forgets the requests for view-scoped keys at or below `view`, which the resolver prunes
    /// itself.
    pub(crate) fn prune(&mut self, view: View) {
        let bounded = &mut self.bounded;
        self.records.retain(|key, _| {
            let kept = key.view().is_none_or(|scoped| scoped > view);
            if !kept {
                *bounded -= usize::from(key.requested_by_waiters());
            }
            kept
        });
    }

    /// Removes and returns every outstanding request.
    pub(crate) fn take_all(&mut self) -> Vec<ResolutionJob<D>> {
        self.starved = false;
        self.bounded = 0;
        core::mem::take(&mut self.records)
            .into_values()
            .map(|record| record.job)
            .collect()
    }

    /// Returns the number of outstanding requests.
    pub(crate) fn len(&self) -> usize {
        self.records.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::{Hasher as _, Sha256, sha256::Digest as Sha256Digest};

    fn digest(label: &[u8]) -> Sha256Digest {
        Sha256::hash(&[label])
    }

    /// Checks that the bounded-request count matches the table.
    fn assert_counted(state: &ResolutionState<Sha256Digest>) {
        let counted = state
            .records
            .keys()
            .filter(|key| key.requested_by_waiters())
            .count();
        assert_eq!(state.bounded, counted);
    }

    #[test]
    fn requests_deduplicate_retry_and_prune_by_view() {
        let generation = Generation::new(1);
        let mut state = ResolutionState::<Sha256Digest>::new();
        let update = RetrievalKey::Update {
            signer: Participant::new(2),
            view: View::new(4),
        };
        let header = RetrievalKey::Header {
            chain: ChainId::new(1),
            digest: digest(b"header"),
        };
        let job = state.request(generation, update, 2).unwrap().unwrap();
        assert!(state.matches(job));
        assert_eq!(state.request(generation, update, 2).unwrap(), None);
        state.request(generation, header, 2).unwrap().unwrap();
        assert_eq!(
            state
                .request(
                    generation,
                    RetrievalKey::Header {
                        chain: ChainId::new(2),
                        digest: digest(b"other"),
                    },
                    2
                )
                .unwrap(),
            None,
            "the request bound holds"
        );
        let leader = state
            .request(generation, RetrievalKey::LeaderBlock(View::new(9)), 2)
            .unwrap()
            .expect("the bound leaves leader blocks and certificates out");
        assert!(state.matches(leader));
        assert!(state.resolved(leader.key()).is_some());
        assert_counted(&state);

        let artifact = ArtifactId::new(digest(b"artifact"));
        state.begin_verification(update, artifact);
        assert!(!state.matches(job));
        assert_eq!(state.verification_failed(artifact), vec![job]);
        assert_counted(&state);
        let retry = state.request(generation, update, 2).unwrap().unwrap();
        assert_ne!(retry.issued(), job.issued());

        state.prune(View::new(3));
        assert!(state.matches(retry));
        state.prune(View::new(4));
        assert!(!state.matches(retry));
        assert_counted(&state);
        assert!(state.resolved(header).is_some());
        assert_counted(&state);
        assert_eq!(state.len(), 0);

        state.request(generation, update, 2).unwrap().unwrap();
        state.request(generation, header, 2).unwrap().unwrap();
        assert_eq!(state.take_all().len(), 2);
        assert_counted(&state);
    }
}
