//! Batch verification jobs and the tickets and verdicts that correlate their completions.

use super::job::Issued;
use crate::{
    Viewable as _,
    multimmit::{
        algebra::{ValidatedLqc, ValidatedVqc},
        types::{Artifact, ArtifactId},
    },
    types::{Participant, View},
};
use commonware_cryptography::{Digest, bls12381::primitives::variant::Variant};
use std::sync::Arc;

type ValidatedVqcs<D> = Vec<(usize, ValidatedVqc<D>)>;
type ValidatedLqcs<V, D> = Vec<(usize, ValidatedLqc<V, D>)>;
type DaEquivocators = Vec<(usize, Participant)>;

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

    /// Returns the input cohort.
    pub(crate) const fn cohort(self) -> u64 {
        self.cohort
    }

    /// Returns the artifact's index within its cohort.
    #[cfg(any(test, feature = "mocks"))]
    pub(crate) const fn index(self) -> u32 {
        self.index
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

    /// Returns the issuing job.
    #[cfg(any(test, feature = "mocks"))]
    pub(crate) const fn job(self) -> JobId {
        self.job
    }

    /// Returns the artifact identifier.
    pub(crate) const fn artifact(self) -> ArtifactId<D> {
        self.artifact
    }

    /// Returns the pre-verification observation order.
    #[cfg(any(test, feature = "mocks"))]
    pub(crate) const fn observation(self) -> Observation {
        self.observation
    }
}

/// One retained artifact in an immutable verification request.
#[derive(Clone, Debug)]
pub(crate) struct VerificationItem<V: Variant, D: Digest> {
    ticket: VerificationTicket<D>,
    artifact: Arc<Artifact<V, D>>,
    /// Locally authenticated claims that can discharge verification or prove equivocation.
    known: Vec<Arc<Artifact<V, D>>>,
}

impl<V: Variant, D: Digest> VerificationItem<V, D> {
    /// Creates an item verifying `artifact` with the `known` claims that may discharge it.
    pub(crate) const fn new(
        ticket: VerificationTicket<D>,
        artifact: Arc<Artifact<V, D>>,
        known: Vec<Arc<Artifact<V, D>>>,
    ) -> Self {
        Self {
            ticket,
            artifact,
            known,
        }
    }

    /// Returns locally authenticated claims attached to this item.
    pub(crate) fn known(&self) -> &[Arc<Artifact<V, D>>] {
        &self.known
    }

    /// Returns the retained decoded artifact behind its shared pointer.
    pub(crate) const fn shared_artifact(&self) -> &Arc<Artifact<V, D>> {
        &self.artifact
    }

    /// Returns the correlation ticket.
    pub(crate) const fn ticket(&self) -> VerificationTicket<D> {
        self.ticket
    }

    /// Returns the retained decoded artifact.
    pub(crate) fn artifact(&self) -> &Artifact<V, D> {
        &self.artifact
    }
}

/// A batch of artifact verification work issued by the machine.
///
/// The items are fixed at issue. Before verifying, the voter may add known messages to
/// certificate items with [`Self::extend_known`].
#[derive(Clone, Debug)]
pub(crate) struct VerifyJob<V: Variant, D: Digest> {
    issued: Issued<JobId>,
    items: Vec<VerificationItem<V, D>>,
}

impl<V: Variant, D: Digest> VerifyJob<V, D> {
    /// Extends every certificate item's known messages with `lookup(view)`, so a verifier can
    /// discharge transcripts with votes it verified after the machine issued this job.
    pub(crate) fn extend_known(
        &mut self,
        mut lookup: impl FnMut(View) -> Vec<Arc<Artifact<V, D>>>,
    ) {
        for item in &mut self.items {
            let view = match item.artifact.as_ref() {
                Artifact::Vqc(certificate) => certificate.view(),
                Artifact::Lqc(certificate) => certificate.view(),
                _ => continue,
            };
            item.known.extend(lookup(view));
        }
    }

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
    /// The round waits on these verdicts, so a job holding one is scheduled ahead of bulk header
    /// and availability work and runs on the view-critical execution pool.
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

/// Completion of one verification job.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct VerificationCompletion<V: Variant, D: Digest> {
    issued: Issued<JobId>,
    verdicts: Vec<Verdict<D>>,
    validated_vqcs: ValidatedVqcs<D>,
    validated_lqcs: ValidatedLqcs<V, D>,
    da_equivocators: DaEquivocators,
}

impl<V: Variant, D: Digest> VerificationCompletion<V, D> {
    /// Creates a completion for a machine-issued verification request.
    ///
    /// Production completions are built by the verifier, which attaches reusable certificate
    /// validations and DA equivocators; this constructor serves tests and benchmarks.
    #[cfg(any(test, feature = "mocks"))]
    pub(crate) const fn new(issued: Issued<JobId>, verdicts: Vec<Verdict<D>>) -> Self {
        Self {
            issued,
            verdicts,
            validated_vqcs: Vec::new(),
            validated_lqcs: Vec::new(),
            da_equivocators: Vec::new(),
        }
    }

    /// Creates a completion carrying the derivations the verifier produced for items by index.
    pub(crate) fn with_validated(
        issued: Issued<JobId>,
        verdicts: Vec<Verdict<D>>,
        validated_vqcs: ValidatedVqcs<D>,
        validated_lqcs: ValidatedLqcs<V, D>,
        da_equivocators: DaEquivocators,
    ) -> Self {
        debug_assert!(
            validated_vqcs
                .iter()
                .all(|(index, _)| *index < verdicts.len())
        );
        debug_assert!(
            validated_lqcs
                .iter()
                .all(|(index, _)| *index < verdicts.len())
        );
        debug_assert!(validated_vqcs.windows(2).all(|pair| pair[0].0 < pair[1].0));
        debug_assert!(validated_lqcs.windows(2).all(|pair| pair[0].0 < pair[1].0));
        Self {
            issued,
            verdicts,
            validated_vqcs,
            validated_lqcs,
            da_equivocators,
        }
    }

    /// Returns the job this completes.
    pub(crate) const fn issued(&self) -> Issued<JobId> {
        self.issued
    }

    /// Returns per-item verdicts in request order.
    pub(crate) fn verdicts(&self) -> &[Verdict<D>] {
        &self.verdicts
    }

    /// Takes the V-QC validation the verifier derived for item `index`, if any.
    pub(crate) fn take_validated_vqc(&mut self, index: usize) -> Option<ValidatedVqc<D>> {
        let position = self
            .validated_vqcs
            .iter()
            .position(|(candidate, _)| *candidate == index)?;
        Some(self.validated_vqcs.swap_remove(position).1)
    }

    /// Takes the L-QC validation the verifier derived for item `index`, if any.
    pub(crate) fn take_validated_lqc(&mut self, index: usize) -> Option<ValidatedLqc<V, D>> {
        let position = self
            .validated_lqcs
            .iter()
            .position(|(candidate, _)| *candidate == index)?;
        Some(self.validated_lqcs.swap_remove(position).1)
    }

    /// Takes the participant item `index` proved to equivocate on DA shares, if any.
    pub(crate) fn take_da_equivocator(&mut self, index: usize) -> Option<Participant> {
        let position = self
            .da_equivocators
            .iter()
            .position(|(candidate, _)| *candidate == index)?;
        Some(self.da_equivocators.swap_remove(position).1)
    }

    /// Returns the bytes the completion holds, or `None` on overflow.
    pub(crate) fn resident_bytes(&self) -> Option<usize> {
        let verdicts = self
            .verdicts
            .capacity()
            .checked_mul(size_of::<Verdict<D>>())?;
        let derivations = self
            .validated_vqcs
            .capacity()
            .checked_mul(size_of::<(usize, ValidatedVqc<D>)>())?
            .checked_add(
                self.validated_lqcs
                    .capacity()
                    .checked_mul(size_of::<(usize, ValidatedLqc<V, D>)>())?,
            )?;
        let equivocations = self
            .da_equivocators
            .capacity()
            .checked_mul(size_of::<(usize, Participant)>())?;
        let total = self.validated_vqcs.iter().try_fold(
            size_of_val(self)
                .checked_add(verdicts)?
                .checked_add(derivations)?
                .checked_add(equivocations)?,
            |total, (_, validated)| total.checked_add(validated.owned_bytes()?),
        )?;
        self.validated_lqcs
            .iter()
            .try_fold(total, |total, (_, validated)| {
                total.checked_add(validated.owned_bytes()?)
            })
    }
}

#[cfg(test)]
impl<V: Variant, D: Digest> VerificationCompletion<V, D> {
    /// Returns the V-QC validation derived for item `index`, if any.
    pub(crate) fn validated_vqc(&self, index: usize) -> Option<&ValidatedVqc<D>> {
        self.validated_vqcs
            .iter()
            .find_map(|(candidate, validated)| (*candidate == index).then_some(validated))
    }

    /// Returns the L-QC validation derived for item `index`, if any.
    pub(crate) fn validated_lqc(&self, index: usize) -> Option<&ValidatedLqc<V, D>> {
        self.validated_lqcs
            .iter()
            .find_map(|(candidate, validated)| (*candidate == index).then_some(validated))
    }
}
