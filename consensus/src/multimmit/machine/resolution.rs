//! Bounded view-proof requests and completions.
//!
//! The machine asks the resolver for a view proof (a V-QC, nullification, or covering L-QC) when
//! it needs one it has not received. At most one request is outstanding per view, and it is
//! cancelled once the machine no longer needs the proof, however the proof arrived.

use super::{
    capability::Capabilities,
    job::{Generation, IdSequence, Issued, SequenceId},
};
use crate::{
    multimmit::types::{ArtifactId, ViewProof},
    types::View,
};
use commonware_cryptography::{Digest, bls12381::primitives::variant::Variant};
use core::mem::take;
use std::collections::BTreeMap;

/// A completion correlated to one resolution request.
#[derive(Clone, Debug)]
pub(crate) struct ResolutionCompletion<V: Variant, D: Digest> {
    issued: Issued<ResolutionId>,
    view: View,
    proof: ViewProof<V, D>,
}

impl<V: Variant, D: Digest> ResolutionCompletion<V, D> {
    /// Creates a completion for one machine-issued request.
    pub(crate) const fn new(
        issued: Issued<ResolutionId>,
        view: View,
        proof: ViewProof<V, D>,
    ) -> Self {
        Self {
            issued,
            view,
            proof,
        }
    }

    /// Returns the request this completes.
    pub(crate) const fn issued(&self) -> Issued<ResolutionId> {
        self.issued
    }

    /// Returns the requested view.
    pub(crate) const fn view(&self) -> View {
        self.view
    }

    /// Returns the decoded proof.
    pub(crate) const fn proof(&self) -> &ViewProof<V, D> {
        &self.proof
    }

    /// Returns the decoded proof, consuming the completion.
    pub(crate) fn into_proof(self) -> ViewProof<V, D> {
        self.proof
    }
}

/// Identifies one volatile resolution request within a process generation.
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

/// A bounded, deduplicated want for a view proof: a V-QC, nullification, or covering L-QC for
/// one view.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct ResolutionJob {
    issued: Issued<ResolutionId>,
    view: View,
}

impl ResolutionJob {
    /// Creates a job. Production jobs are issued only by [`ResolutionState::request`].
    pub(crate) const fn new(issued: Issued<ResolutionId>, view: View) -> Self {
        Self { issued, view }
    }

    /// Creates a job at `sequence` issued by `generation`.
    #[cfg(test)]
    pub(crate) const fn issue(sequence: u64, generation: Generation, view: View) -> Self {
        Self::new(Issued::new(ResolutionId(sequence), generation), view)
    }

    /// Returns the request's identity and issuing generation.
    pub(crate) const fn issued(self) -> Issued<ResolutionId> {
        self.issued
    }

    /// Returns the view to resolve.
    pub(crate) const fn view(self) -> View {
        self.view
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum ResolutionStatus<D: Digest> {
    InFlight,
    Verifying(ArtifactId<D>),
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
struct ResolutionRecord<D: Digest> {
    job: ResolutionJob,
    status: ResolutionStatus<D>,
}

/// A view-proof request the machine could not issue.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum ResolutionError {
    /// The generation-local request identifier overflowed.
    #[error("resolution identifier exhausted")]
    IdentifierExhausted,
}

/// Machine-wide ownership of bounded view-proof requests.
///
/// Jobs remain keyed by view while an attempt is in flight or its decoded artifact is undergoing
/// ordinary verification. Removing a failed attempt permits the same view to be
/// retried with a fresh identifier while retaining the process generation.
pub(crate) struct ResolutionState<V: Variant, D: Digest> {
    records: BTreeMap<View, ResolutionRecord<D>>,
    ids: IdSequence<ResolutionId>,
    /// Resolver capabilities waiting to be emitted.
    pub(super) capabilities: Capabilities<V, D>,
    /// Current view in which finality-floor recovery was last probed.
    pub(super) floor_probe_view: View,
}

impl<V: Variant, D: Digest> ResolutionState<V, D> {
    /// Creates state with no outstanding requests.
    pub(super) const fn new() -> Self {
        Self {
            records: BTreeMap::new(),
            ids: IdSequence::new(),
            capabilities: Capabilities::new(),
            floor_probe_view: View::zero(),
        }
    }

    /// Issues one deduplicated job without exceeding the shared dependency-work bound.
    pub(crate) fn request(
        &mut self,
        generation: Generation,
        view: View,
        limit: usize,
    ) -> Result<Option<ResolutionJob>, ResolutionError> {
        if self.records.contains_key(&view) || self.records.len() >= limit {
            return Ok(None);
        }
        let id = self
            .ids
            .issue()
            .ok_or(ResolutionError::IdentifierExhausted)?;
        let job = ResolutionJob::new(Issued::new(id, generation), view);
        self.records.insert(
            view,
            ResolutionRecord {
                job,
                status: ResolutionStatus::InFlight,
            },
        );
        Ok(Some(job))
    }

    /// Returns whether `completion` answers the in-flight request for its view.
    pub(crate) fn matches(&self, completion: &ResolutionCompletion<V, D>) -> bool {
        self.records.get(&completion.view()).is_some_and(|record| {
            record.status == ResolutionStatus::InFlight
                && record.job.issued() == completion.issued()
        })
    }

    /// Marks the request for `view` as waiting on verification of the returned `artifact`.
    pub(crate) fn begin_verification(&mut self, view: View, artifact: ArtifactId<D>) {
        if let Some(record) = self.records.get_mut(&view) {
            record.status = ResolutionStatus::Verifying(artifact);
        }
    }

    /// Returns the views whose returned proof is `artifact`, now verified.
    pub(crate) fn verification_ready(&mut self, artifact: ArtifactId<D>) -> Vec<View> {
        self.records
            .iter()
            .filter_map(|(key, record)| {
                matches!(record.status, ResolutionStatus::Verifying(verifying) if verifying == artifact)
                    .then_some(*key)
            })
            .collect()
    }

    /// Removes and returns the requests whose returned proof `artifact` failed verification, so
    /// their views can be requested again.
    pub(crate) fn verification_failed(&mut self, artifact: ArtifactId<D>) -> Vec<ResolutionJob> {
        let failed = self
            .records
            .iter()
            .filter_map(|(key, record)| match record.status {
                ResolutionStatus::Verifying(verifying) if verifying == artifact => {
                    Some((*key, record.job))
                }
                ResolutionStatus::InFlight | ResolutionStatus::Verifying(_) => None,
            })
            .collect::<Vec<_>>();
        for (key, _) in &failed {
            self.records.remove(key);
        }
        failed.into_iter().map(|(_, job)| job).collect()
    }

    /// Removes and returns the request for `view`.
    pub(crate) fn resolved(&mut self, view: View) -> Option<ResolutionJob> {
        self.records.remove(&view).map(|record| record.job)
    }

    /// Returns the views with an outstanding request.
    pub(crate) fn keys(&self) -> impl Iterator<Item = View> + '_ {
        self.records.keys().copied()
    }

    /// Returns the number of outstanding requests.
    pub(crate) fn len(&self) -> usize {
        self.records.len()
    }

    /// Takes the resolver capabilities issued since the last call.
    pub(crate) fn take_capabilities(&mut self) -> Capabilities<V, D> {
        take(&mut self.capabilities)
    }
}
