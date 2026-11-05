//! Bounded view-proof and DA-certificate requests and completions.
//!
//! The machine asks the resolver for a view proof (a V-QC, nullification, or covering L-QC) when
//! it needs one it has not received. At most one request is outstanding per view, and it is
//! cancelled once the machine no longer needs the proof, however the proof arrived.
//!
//! It also asks for a DA certificate when a chain whose placement implies a certificate (no
//! pipeline and no extensions) is placed above every certificate it holds: messages before GST
//! may be lost, and once peers place a block they no longer send its certificate. At most one
//! such request is outstanding per chain.

use super::{
    capability::Capabilities,
    job::{Generation, IdSequence, Issued, SequenceId},
};
use crate::{
    multimmit::{
        scheme::Scheme,
        types::{ArtifactId, ChainId, DaCertificate, ViewProof},
    },
    types::{Height, View},
};
use commonware_cryptography::Digest;
use core::mem::take;
use std::collections::BTreeMap;

/// A completion correlated to one resolution request.
#[derive(Clone, Debug)]
pub(crate) struct ResolutionCompletion<S: Scheme, D: Digest> {
    issued: Issued<ResolutionId>,
    view: View,
    proof: ViewProof<S, D>,
}

impl<S: Scheme, D: Digest> ResolutionCompletion<S, D> {
    /// Creates a completion for one machine-issued request.
    pub(crate) const fn new(
        issued: Issued<ResolutionId>,
        view: View,
        proof: ViewProof<S, D>,
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
    pub(crate) const fn proof(&self) -> &ViewProof<S, D> {
        &self.proof
    }

    /// Returns the decoded proof, consuming the completion.
    pub(crate) fn into_proof(self) -> ViewProof<S, D> {
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

/// A completion correlated to one DA-certificate request.
#[derive(Clone, Debug)]
pub(crate) struct CertificateCompletion<S: Scheme, D: Digest> {
    job: CertificateJob,
    certificate: DaCertificate<S, D>,
}

impl<S: Scheme, D: Digest> CertificateCompletion<S, D> {
    /// Creates a completion for one machine-issued request.
    pub(crate) const fn new(job: CertificateJob, certificate: DaCertificate<S, D>) -> Self {
        Self { job, certificate }
    }

    /// Returns the request this completes.
    pub(crate) const fn job(&self) -> CertificateJob {
        self.job
    }

    /// Returns the decoded certificate.
    pub(crate) const fn certificate(&self) -> &DaCertificate<S, D> {
        &self.certificate
    }

    /// Returns the decoded certificate, consuming the completion.
    pub(crate) fn into_certificate(self) -> DaCertificate<S, D> {
        self.certificate
    }
}

/// A bounded want for a DA certificate on one chain above a height.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct CertificateJob {
    issued: Issued<ResolutionId>,
    chain: ChainId,
    after: Height,
}

impl CertificateJob {
    /// Creates a job. Production jobs are issued only by [`ResolutionState::request_certificate`].
    pub(crate) const fn new(issued: Issued<ResolutionId>, chain: ChainId, after: Height) -> Self {
        Self {
            issued,
            chain,
            after,
        }
    }

    /// Creates a job at `sequence` issued by `generation`.
    #[cfg(test)]
    pub(crate) const fn issue(
        sequence: u64,
        generation: Generation,
        chain: ChainId,
        after: Height,
    ) -> Self {
        Self::new(Issued::new(ResolutionId(sequence), generation), chain, after)
    }

    /// Returns the request's identity and issuing generation.
    pub(crate) const fn issued(self) -> Issued<ResolutionId> {
        self.issued
    }

    /// Returns the chain whose certificate is requested.
    pub(crate) const fn chain(self) -> ChainId {
        self.chain
    }

    /// Returns the height the certificate must be above.
    pub(crate) const fn after(self) -> Height {
        self.after
    }
}

/// Where one DA-certificate request stands.
#[derive(Clone, Debug)]
enum CertificateStatus<S: Scheme, D: Digest> {
    /// Waiting for a peer to answer.
    InFlight,
    /// The returned certificate is being verified.
    Verifying(ArtifactId<D>),
    /// The returned certificate waits for local admission capacity.
    Held(DaCertificate<S, D>),
}

#[derive(Clone, Debug)]
struct CertificateRecord<S: Scheme, D: Digest> {
    job: CertificateJob,
    status: CertificateStatus<S, D>,
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
pub(crate) struct ResolutionState<S: Scheme, D: Digest> {
    records: BTreeMap<View, ResolutionRecord<D>>,
    /// DA-certificate requests, at most one per chain.
    certificates: BTreeMap<ChainId, CertificateRecord<S, D>>,
    /// The view in which each chain was first seen placed above every certificate this node
    /// holds. A request waits one view, so a certificate already arriving with the placing leader
    /// block is not fetched again.
    pub(super) lagging: BTreeMap<ChainId, View>,
    /// The highest DA certificate per chain carried by an authenticated proof (a V-QC or L-QC
    /// embeds its leader block), waiting to be admitted and verified like any certificate.
    pub(super) carried: BTreeMap<ChainId, DaCertificate<S, D>>,
    ids: IdSequence<ResolutionId>,
    /// Resolver capabilities waiting to be emitted.
    pub(super) capabilities: Capabilities<S, D>,
    /// Current view in which finality-floor recovery was last probed.
    pub(super) floor_probe_view: View,
}

impl<S: Scheme, D: Digest> ResolutionState<S, D> {
    /// Creates state with no outstanding requests.
    pub(super) const fn new() -> Self {
        Self {
            records: BTreeMap::new(),
            certificates: BTreeMap::new(),
            lagging: BTreeMap::new(),
            carried: BTreeMap::new(),
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
    pub(crate) fn matches(&self, completion: &ResolutionCompletion<S, D>) -> bool {
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

    /// Issues the DA-certificate request for `chain` above `after`, unless one is outstanding.
    pub(crate) fn request_certificate(
        &mut self,
        generation: Generation,
        chain: ChainId,
        after: Height,
    ) -> Result<Option<CertificateJob>, ResolutionError> {
        if self.certificates.contains_key(&chain) {
            return Ok(None);
        }
        let id = self
            .ids
            .issue()
            .ok_or(ResolutionError::IdentifierExhausted)?;
        let job = CertificateJob::new(Issued::new(id, generation), chain, after);
        self.certificates.insert(
            chain,
            CertificateRecord {
                job,
                status: CertificateStatus::InFlight,
            },
        );
        Ok(Some(job))
    }

    /// Returns the chains with an outstanding DA-certificate request.
    pub(crate) fn certificate_chains(&self) -> impl Iterator<Item = ChainId> + '_ {
        self.certificates.keys().copied()
    }

    /// Returns the outstanding DA-certificate request for `chain`.
    pub(crate) fn certificate_job(&self, chain: ChainId) -> Option<CertificateJob> {
        self.certificates.get(&chain).map(|record| record.job)
    }

    /// Returns whether `completion` answers the in-flight request for its chain.
    pub(crate) fn certificate_matches(&self, completion: &CertificateCompletion<S, D>) -> bool {
        self.certificates
            .get(&completion.job().chain())
            .is_some_and(|record| {
                matches!(record.status, CertificateStatus::InFlight)
                    && record.job == completion.job()
            })
    }

    /// Marks the request for `chain` as waiting on verification of the returned `artifact`.
    pub(crate) fn begin_certificate_verification(&mut self, chain: ChainId, artifact: ArtifactId<D>) {
        if let Some(record) = self.certificates.get_mut(&chain) {
            record.status = CertificateStatus::Verifying(artifact);
        }
    }

    /// Keeps the returned `certificate` for `chain` until local admission has room for it.
    pub(crate) fn hold_certificate(&mut self, chain: ChainId, certificate: DaCertificate<S, D>) {
        if let Some(record) = self.certificates.get_mut(&chain) {
            record.status = CertificateStatus::Held(certificate);
        }
    }

    /// Takes the held certificates to admit again, marking their requests in flight.
    pub(crate) fn take_held_certificates(&mut self) -> Vec<(ChainId, DaCertificate<S, D>)> {
        let mut held = Vec::new();
        for (chain, record) in &mut self.certificates {
            if matches!(record.status, CertificateStatus::Held(_)) {
                let CertificateStatus::Held(certificate) =
                    core::mem::replace(&mut record.status, CertificateStatus::InFlight)
                else {
                    unreachable!("matched above");
                };
                held.push((*chain, certificate));
            }
        }
        held
    }

    /// Returns the chains whose returned certificate is `artifact`, now verified.
    pub(crate) fn certificate_verification_ready(&self, artifact: ArtifactId<D>) -> Vec<ChainId> {
        self.certificates
            .iter()
            .filter_map(|(chain, record)| {
                matches!(record.status, CertificateStatus::Verifying(verifying) if verifying == artifact)
                    .then_some(*chain)
            })
            .collect()
    }

    /// Removes and returns the requests whose returned certificate `artifact` failed
    /// verification, so they can be requested again.
    pub(crate) fn certificate_verification_failed(
        &mut self,
        artifact: ArtifactId<D>,
    ) -> Vec<CertificateJob> {
        let failed = self
            .certificates
            .iter()
            .filter_map(|(chain, record)| match record.status {
                CertificateStatus::Verifying(verifying) if verifying == artifact => {
                    Some((*chain, record.job))
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        for (chain, _) in &failed {
            self.certificates.remove(chain);
        }
        failed.into_iter().map(|(_, job)| job).collect()
    }

    /// Removes and returns the DA-certificate request for `chain`.
    pub(crate) fn resolved_certificate(&mut self, chain: ChainId) -> Option<CertificateJob> {
        self.certificates.remove(&chain).map(|record| record.job)
    }

    /// Takes the resolver capabilities issued since the last call.
    pub(crate) fn take_capabilities(&mut self) -> Capabilities<S, D> {
        take(&mut self.capabilities)
    }
}
