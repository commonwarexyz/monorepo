//! Batch verification jobs and the tickets and verdicts that correlate their completions.

use super::job::Issued;
use crate::multimmit::types::{Artifact, ArtifactId, VoteContent};
use commonware_cryptography::{Digest, bls12381::primitives::variant::Variant};
use std::sync::Arc;

/// Deterministic ingress order assigned before verification is scheduled.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct Observation {
    cohort: u64,
    index: u32,
}

impl Observation {
    /// Creates the observation of the `index`-th artifact of input `cohort`.
    pub(crate) const fn new(cohort: u64, index: u32) -> Self {
        Self { cohort, index }
    }
}

/// Identifies an immutable verification job within one machine generation.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct JobId(u64);

impl JobId {
    /// Wraps a job identifier.
    pub(crate) const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the generation-local sequence.
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Correlates one retained artifact with its verification verdict.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct VerificationTicket<D: Digest> {
    job: JobId,
    artifact: ArtifactId<D>,
    observation: Observation,
}

impl<D: Digest> VerificationTicket<D> {
    /// Creates the ticket of `artifact`, observed at `observation`, in verification `job`.
    pub(crate) const fn new(job: JobId, artifact: ArtifactId<D>, observation: Observation) -> Self {
        Self {
            job,
            artifact,
            observation,
        }
    }

    /// Returns the artifact identifier.
    pub(crate) const fn artifact(self) -> ArtifactId<D> {
        self.artifact
    }
}

/// One retained artifact in an immutable verification request.
///
/// A vote update's signature covers its full content, which the update carries only as changes
/// against the sender's earlier updates. The machine rebuilds that content before it schedules the
/// update, and the item carries it so the verifier checks the signature over exactly what the
/// machine will count.
#[derive(Clone, Debug)]
pub(crate) struct VerificationItem<V: Variant, D: Digest> {
    ticket: VerificationTicket<D>,
    artifact: Arc<Artifact<V, D>>,
    content: Option<Arc<VoteContent<D>>>,
}

impl<V: Variant, D: Digest> VerificationItem<V, D> {
    /// Creates an item verifying an artifact whose signed subject is the artifact itself.
    pub(crate) const fn new(ticket: VerificationTicket<D>, artifact: Arc<Artifact<V, D>>) -> Self {
        Self {
            ticket,
            artifact,
            content: None,
        }
    }

    /// Creates an item verifying a vote update's signature over its rebuilt `content`.
    pub(crate) const fn update(
        ticket: VerificationTicket<D>,
        artifact: Arc<Artifact<V, D>>,
        content: Arc<VoteContent<D>>,
    ) -> Self {
        Self {
            ticket,
            artifact,
            content: Some(content),
        }
    }

    /// Returns the correlation ticket.
    pub(crate) const fn ticket(&self) -> VerificationTicket<D> {
        self.ticket
    }

    /// Returns the retained decoded artifact.
    pub(crate) fn artifact(&self) -> &Artifact<V, D> {
        &self.artifact
    }

    /// Returns the rebuilt content of a vote update, or `None` for any other artifact.
    pub(crate) fn content(&self) -> Option<&VoteContent<D>> {
        self.content.as_deref()
    }
}

/// A batch of artifact verification work issued by the machine.
#[derive(Clone, Debug)]
pub(crate) struct VerifyJob<V: Variant, D: Digest> {
    issued: Issued<JobId>,
    items: Vec<VerificationItem<V, D>>,
}

impl<V: Variant, D: Digest> VerifyJob<V, D> {
    /// Creates the job issued as `issued` over `items`.
    pub(crate) const fn new(issued: Issued<JobId>, items: Vec<VerificationItem<V, D>>) -> Self {
        Self { issued, items }
    }

    /// Returns the job's identity and issuing generation.
    pub(crate) const fn issued(&self) -> Issued<JobId> {
        self.issued
    }

    /// Returns the retained items in observation order.
    pub(crate) fn items(&self) -> &[VerificationItem<V, D>] {
        &self.items
    }

    /// Returns whether any item carries view progress.
    ///
    /// The view waits on these verdicts, so a job holding one is scheduled ahead of bulk header
    /// work and runs on the view-critical execution pool.
    pub(crate) fn view_critical(&self) -> bool {
        self.items
            .iter()
            .any(|item| item.artifact().view_critical())
    }
}

/// The cryptographic verdict for one verification ticket.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) struct Verdict<D: Digest> {
    ticket: VerificationTicket<D>,
    valid: bool,
}

impl<D: Digest> Verdict<D> {
    /// Creates a verdict for a machine-issued ticket.
    pub(crate) const fn new(ticket: VerificationTicket<D>, valid: bool) -> Self {
        Self { ticket, valid }
    }

    /// Returns the machine-issued ticket.
    pub(crate) const fn ticket(self) -> VerificationTicket<D> {
        self.ticket
    }

    /// Returns the artifact-verification result.
    pub(crate) const fn valid(self) -> bool {
        self.valid
    }
}

/// Completion of one verification job: one verdict per item, in item order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct VerificationCompletion<D: Digest> {
    issued: Issued<JobId>,
    verdicts: Vec<Verdict<D>>,
}

impl<D: Digest> VerificationCompletion<D> {
    /// Creates the completion of job `issued`.
    pub(crate) const fn new(issued: Issued<JobId>, verdicts: Vec<Verdict<D>>) -> Self {
        Self { issued, verdicts }
    }

    /// Returns the job this completes.
    pub(crate) const fn issued(&self) -> Issued<JobId> {
        self.issued
    }

    /// Returns per-item verdicts in request order.
    pub(crate) fn verdicts(&self) -> &[Verdict<D>] {
        &self.verdicts
    }

    /// Returns the bytes the completion holds, or `None` on overflow.
    pub(crate) fn resident_bytes(&self) -> Option<usize> {
        self.verdicts
            .capacity()
            .checked_mul(size_of::<Verdict<D>>())?
            .checked_add(size_of_val(self))
    }
}
