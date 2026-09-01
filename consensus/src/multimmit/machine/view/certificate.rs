//! View certificate assembly: scans of retained messages and shares, and the aggregation jobs.

use super::{
    forward::{ExitKey, ExitKind, set_member},
    state::{ViewError, ViewState},
    store::{LeaderRecord, MessageRef, ParentProof, ViewMessageKind, VqcEligibility},
};
use crate::{
    Viewable,
    multimmit::{
        algebra::{DerivedVqc, ValidatedVqc, validate_vqc_votes, validate_vqc_with_votes},
        machine::{
            artifact::Held,
            capability::{Capabilities, Capability, CryptoJob},
            job::{Admit, Generation, Issued, SequenceId},
            util::Drive,
            verification::Observation,
        },
        scheme::bls12381_threshold::{CertificateVotes, Error as SchemeError},
        types::{
            Artifact, ArtifactId, CodecConfig, LeaderBlock, Nullification, Nullify, ViewMessage,
            VoteBody, Vqc,
        },
    },
    types::{Attributable, Participant, View},
};
use commonware_cryptography::{Digest, Hasher, bls12381::primitives::variant::Variant};
use std::{
    collections::{BTreeMap, BinaryHeap},
    ops::Bound::{Excluded, Unbounded},
    sync::Arc,
};

/// Identifies one view-certificate construction request.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct ViewCertificateId(u64);

impl ViewCertificateId {
    /// Returns the generation-local sequence.
    pub(crate) const fn get(self) -> u64 {
        self.0
    }
}

impl SequenceId for ViewCertificateId {
    fn at(sequence: u64) -> Self {
        Self(sequence)
    }
}

/// Verified shares selected for one nullification.
#[derive(Clone, Debug)]
pub(crate) struct NullificationRecoveryJob<V: Variant> {
    issued: Issued<ViewCertificateId>,
    pub(super) view: View,
    shares: Arc<[Nullify<V>]>,
}

impl<V: Variant> NullificationRecoveryJob<V> {
    /// Returns the job's identity and issuing generation.
    pub(crate) const fn issued(&self) -> Issued<ViewCertificateId> {
        self.issued
    }

    /// Returns the canonical signer subset in participant order.
    pub(crate) fn shares(&self) -> &[Nullify<V>] {
        &self.shares
    }
}

/// Completion of one nullification recovery request.
#[derive(Clone, Debug)]
pub(crate) struct NullificationRecoveryCompletion<V: Variant> {
    issued: Issued<ViewCertificateId>,
    certificate: Nullification<V>,
}

impl<V: Variant> NullificationRecoveryCompletion<V> {
    /// Creates a matched recovery completion.
    pub(crate) const fn new(
        issued: Issued<ViewCertificateId>,
        certificate: Nullification<V>,
    ) -> Self {
        Self {
            issued,
            certificate,
        }
    }

    /// Returns the job this completes.
    pub(crate) const fn issued(&self) -> Issued<ViewCertificateId> {
        self.issued
    }
}

/// Verified view messages selected for one V-QC.
#[derive(Clone, Debug)]
pub(crate) struct VqcAggregateJob<V: Variant, D: Digest> {
    issued: Issued<ViewCertificateId>,
    leader: LeaderBlock<V, D>,
    messages: Arc<[Held<ViewMessageKind, V, D>]>,
    transcript: VqcTranscript<D>,
}

impl<V: Variant, D: Digest> VqcAggregateJob<V, D> {
    /// Returns the job's identity and issuing generation.
    pub(crate) const fn issued(&self) -> Issued<ViewCertificateId> {
        self.issued
    }

    /// Returns the designated unsigned leader block.
    pub(crate) const fn leader(&self) -> &LeaderBlock<V, D> {
        &self.leader
    }

    /// Reconstructs the canonical message subset in participant order.
    ///
    /// The job retains shared canonical artifacts. Consumers materialize owned protocol messages
    /// only while executing the aggregation.
    pub(crate) fn messages(&self) -> impl ExactSizeIterator<Item = ViewMessage<V, D>> + '_ {
        self.messages.iter().map(|message| match message.get() {
            MessageRef::Vote(vote) => ViewMessage::Vote(vote.clone()),
            MessageRef::NoVote(vote) => ViewMessage::NoVote(vote.clone()),
        })
    }

    /// Returns whether `certificate` aggregates exactly this job's leader and messages.
    fn matches<H: Hasher<Digest = D>>(&self, certificate: &Vqc<V, D>, config: CodecConfig) -> bool {
        vqc_transcript_matches::<H, V, D>(certificate, &self.leader, &self.messages, config)
    }
}

/// Completion of one V-QC aggregation request.
#[derive(Clone, Debug)]
pub(crate) struct VqcAggregateCompletion<V: Variant, D: Digest> {
    issued: Issued<ViewCertificateId>,
    // Only the view owner constructs job transcripts. Clones retain this allocation, so its
    // identity binds the worker's checked certificate to the still-pending request.
    messages: Arc<[Held<ViewMessageKind, V, D>]>,
    /// Taken once the certificate is admitted, so admission moves the validation it carries.
    derived: Option<DerivedVqc<V, D>>,
}

impl<V: Variant, D: Digest> VqcAggregateCompletion<V, D> {
    /// Checks the selected transcript and derives certificate projections in the worker.
    pub(crate) fn prepare<H: Hasher<Digest = D>>(
        job: &VqcAggregateJob<V, D>,
        certificate: Vqc<V, D>,
        config: CodecConfig,
    ) -> Result<Self, SchemeError> {
        if !job.matches::<H>(&certificate, config) {
            return Err(SchemeError::Transcript);
        }
        let leader = certificate.leader().digest::<H>();
        let mut votes = CertificateVotes {
            leader,
            designated: Vec::new(),
            conflicting: Vec::new(),
        };
        for message in job.messages.iter() {
            if let MessageRef::Vote(vote) = message.get() {
                let target = if vote.body().leader() == leader {
                    &mut votes.designated
                } else {
                    &mut votes.conflicting
                };
                target.push((vote.signer(), vote.body().clone()));
            }
        }
        let validated = validate_vqc_with_votes::<H, V, D>(&certificate, config, votes)
            .map_err(|_| SchemeError::Transcript)?;
        let derived =
            DerivedVqc::new::<H>(certificate, validated).map_err(|_| SchemeError::Transcript)?;
        Ok(Self {
            issued: job.issued,
            messages: Arc::clone(&job.messages),
            derived: Some(derived),
        })
    }

    /// Returns the certificate and the projections the worker derived from it.
    pub(crate) const fn derived(&self) -> &DerivedVqc<V, D> {
        self.derived
            .as_ref()
            .expect("the derivation is taken only when the certificate is admitted")
    }

    /// Takes the validation the worker derived, once the certificate is admitted.
    pub(crate) fn take_validated(&mut self) -> ValidatedVqc<D> {
        self.derived
            .take()
            .expect("the derivation is taken only when the certificate is admitted")
            .validated
    }

    /// Returns the job this completes.
    pub(crate) const fn issued(&self) -> Issued<ViewCertificateId> {
        self.issued
    }

    /// Returns the aggregated certificate.
    pub(crate) fn certificate(&self) -> &Vqc<V, D> {
        self.derived().artifact.get()
    }
}

/// A bounded prefix of certificate assembly.
pub(crate) type CertificateDrive = Drive<()>;

/// An issued certificate job with the observation its certificate is admitted at.
#[derive(Clone, Debug)]
pub(super) enum ViewCertificateJob<V: Variant, D: Digest> {
    Nullification {
        job: NullificationRecoveryJob<V>,
        observation: Observation,
    },
    Vqc {
        job: VqcAggregateJob<V, D>,
        observation: Observation,
    },
}

impl<V: Variant, D: Digest> ViewCertificateJob<V, D> {
    /// Returns the view the job exits.
    pub(super) fn view(&self) -> View {
        match self {
            Self::Nullification { job, .. } => job.view,
            Self::Vqc { job, .. } => job.leader.view(),
        }
    }

    /// Returns the observation the assembled certificate is admitted at.
    const fn observation(&self) -> Observation {
        match self {
            Self::Nullification { observation, .. } | Self::Vqc { observation, .. } => *observation,
        }
    }
}

/// A locally assembled certificate ready for admission at its job's observation.
pub(crate) struct PreparedArtifact<V: Variant, D: Digest> {
    pub(crate) artifact: Arc<Artifact<V, D>>,
    pub(crate) observation: Observation,
}

/// The view messages a V-QC for one target aggregates, in participant order.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct VqcTranscript<D: Digest> {
    view: View,
    pub(super) target: D,
    pub(super) messages: Vec<ArtifactId<D>>,
}

/// A V-QC transcript and the observation at which its last message settled.
#[derive(Clone, Debug)]
pub(super) struct VqcCandidate<D: Digest> {
    pub(super) observation: Observation,
    pub(super) transcript: VqcTranscript<D>,
}

/// A V-QC candidate with the messages it aggregates.
#[derive(Clone, Debug)]
pub(super) struct PreparedVqc<V: Variant, D: Digest> {
    pub(super) candidate: VqcCandidate<D>,
    messages: Arc<[Held<ViewMessageKind, V, D>]>,
}

/// A nullification share set with the observation at which its last share arrived.
#[derive(Clone, Debug)]
pub(super) struct PreparedNullification<V: Variant> {
    pub(super) observation: Observation,
    shares: Arc<[Nullify<V>]>,
}

enum PreparedCertificate<V: Variant, D: Digest> {
    Vqc(PreparedVqc<V, D>),
    Nullification(PreparedNullification<V>),
}

/// A resumable scan of one view's settled messages and nullify shares for the best V-QC
/// candidate and a nullification share set.
#[derive(Clone, Debug)]
pub(super) struct CertificateScan<V: Variant, D: Digest> {
    pub(super) view: View,
    pending_messages: Option<u64>,
    pending_nullifies: Option<u64>,
    support: BTreeMap<D, usize>,
    pub(super) best_vqc: Option<PreparedVqc<V, D>>,
    pub(super) nullification: Option<PreparedNullification<V>>,
    phase: CertificateScanPhase<V, D>,
}

impl<V: Variant, D: Digest> CertificateScan<V, D> {
    const fn complete(&self) -> bool {
        matches!(self.phase, CertificateScanPhase::Complete)
    }

    /// Returns whether a retained record observed in `cohort` predates every pending message
    /// claim, so verification still in flight cannot precede it.
    fn message_settled(&self, cohort: u64) -> bool {
        self.pending_messages.is_none_or(|pending| cohort < pending)
    }

    /// Returns whether a retained nullify share observed in `cohort` predates every pending
    /// nullify claim.
    fn nullify_settled(&self, cohort: u64) -> bool {
        self.pending_nullifies
            .is_none_or(|pending| cohort < pending)
    }
}

/// What one scan step did, with the phase the scan continues in.
#[derive(Debug)]
enum ScanStep<V: Variant, D: Digest> {
    /// The step visited one retained participant or target, which costs one unit of budget.
    Advanced(CertificateScanPhase<V, D>),
    /// The step only moved to the next phase.
    Moved(CertificateScanPhase<V, D>),
}

#[derive(Clone, Debug)]
enum CertificateScanPhase<V: Variant, D: Digest> {
    CountSupport(CountSupport),
    FindTarget(FindTarget<D>),
    EvaluateTarget(EvaluateTarget<D>),
    SelectTarget(SelectTarget<V, D>),
    CountNullifications(CountNullifications),
    SelectNullifications(SelectNullifications<V>),
    Complete,
}

/// Counts settled votes per designated leader digest.
#[derive(Clone, Debug)]
struct CountSupport {
    cursor: Option<Participant>,
}

/// Finds the next leader digest with a designation quorum of support and a held leader.
#[derive(Clone, Debug)]
struct FindTarget<D: Digest> {
    cursor: Option<D>,
}

/// Counts messages eligible for a V-QC on `target` and the cohorts a quorum needs.
#[derive(Clone, Debug)]
struct EvaluateTarget<D: Digest> {
    target: D,
    cursor: Option<Participant>,
    eligible: usize,
    targets: usize,
    message_cohorts: BinaryHeap<u64>,
    target_cohorts: BinaryHeap<u64>,
}

/// Selects the earliest messages that still complete a V-QC on `target`.
#[derive(Clone, Debug)]
struct SelectTarget<V: Variant, D: Digest> {
    target: D,
    cohort: u64,
    limit: usize,
    cursor: Option<Participant>,
    eligible: usize,
    remaining_targets: usize,
    visited: usize,
    target_count: usize,
    observation: Observation,
    messages: Vec<Held<ViewMessageKind, V, D>>,
    ids: Vec<ArtifactId<D>>,
}

impl<V: Variant, D: Digest> SelectTarget<V, D> {
    /// Returns whether the next eligible message can join the selection while enough eligible
    /// messages and designated votes remain to fill it to a quorum.
    ///
    /// Callers only step a selection with room left.
    fn admit(&self, is_target: bool, designation_quorum: usize) -> bool {
        let slots_after = self.limit - self.messages.len() - 1;
        let enough_entries = self.eligible - self.visited > slots_after;
        let enough_targets =
            self.target_count + usize::from(is_target) + self.remaining_targets.min(slots_after)
                >= designation_quorum;
        enough_entries && enough_targets
    }
}

/// Counts settled nullify shares and the cohorts a quorum needs.
#[derive(Clone, Debug)]
struct CountNullifications {
    cursor: Option<Participant>,
    cohorts: BinaryHeap<u64>,
}

/// Selects the earliest nullify shares for a nullification.
#[derive(Clone, Debug)]
struct SelectNullifications<V: Variant> {
    cohort: u64,
    cursor: Option<Participant>,
    observation: Option<Observation>,
    shares: Vec<Nullify<V>>,
}

/// Returns the first entry after `cursor`, or the first entry without one.
fn next_after<K: Copy + Ord, T>(entries: &BTreeMap<K, T>, cursor: Option<K>) -> Option<(K, &T)> {
    cursor
        .map_or_else(
            || entries.first_key_value(),
            |cursor| entries.range((Excluded(cursor), Unbounded)).next(),
        )
        .map(|(key, value)| (*key, value))
}

fn retain_smallest(values: &mut BinaryHeap<u64>, value: u64, limit: usize) {
    values.push(value);
    if values.len() > limit {
        values.pop();
    }
}

/// Returns whether `certificate` aggregates exactly `messages` for `leader`.
fn vqc_transcript_matches<H, V, D>(
    certificate: &Vqc<V, D>,
    leader: &LeaderBlock<V, D>,
    messages: &[Held<ViewMessageKind, V, D>],
    config: CodecConfig,
) -> bool
where
    H: Hasher<Digest = D>,
    V: Variant,
    D: Digest,
{
    if certificate.leader() != leader
        || certificate.signature().is_none()
        || certificate.validate(config).is_err()
    {
        return false;
    }
    enum MessageBody<D: Digest> {
        Vote(VoteBody<D>),
        NoVote,
    }
    let (Ok(designated), Ok(conflicting)) = (
        certificate.expand_votes(leader.digest::<H>(), config),
        certificate.conflicting_bodies(),
    ) else {
        return false;
    };
    let mut actual = BTreeMap::<Participant, MessageBody<D>>::new();
    for (signer, body) in designated {
        actual.insert(signer, MessageBody::Vote(body));
    }
    for signer in certificate.novoters().iter() {
        actual.insert(signer, MessageBody::NoVote);
    }
    for (signer, body) in conflicting {
        actual.insert(signer, MessageBody::Vote(body));
    }
    if actual.len() != messages.len() {
        return false;
    }
    messages.iter().all(|expected| match expected.get() {
        MessageRef::Vote(vote) => {
            matches!(actual.get(&vote.signer()), Some(MessageBody::Vote(body)) if vote.body() == body)
        }
        MessageRef::NoVote(vote) => {
            matches!(actual.get(&vote.signer()), Some(MessageBody::NoVote))
        }
    })
}

impl<V: Variant, D: Digest> ViewState<V, D> {
    /// Returns the leader record a certificate scan selected as `target` in `view`.
    fn scanned_leader(&self, view: View, target: D) -> &LeaderRecord<V, D> {
        self.entry(view)
            .and_then(|entry| entry.leaders.get(&target))
            .expect("a scanned target's leader is retained")
    }

    /// Returns the observation of the assembly job in flight for `kind` in `view`.
    pub(super) fn pending_observation(&self, view: View, kind: ExitKind) -> Option<Observation> {
        let entry = self.entry(view)?;
        match kind {
            ExitKind::Vqc => entry.vqc.pending,
            ExitKind::Nullification => entry.nullification.pending,
        }
    }

    /// Returns the lowest view other than `current` that is ready for certificate work.
    pub(crate) fn deferred_certificate_view(&self, current: View) -> Option<View> {
        self.ready_certificate_views
            .iter()
            .copied()
            .find(|view| *view != current)
    }

    /// Drives certificate assembly for `view`, finishing a scan already in progress for another
    /// view first.
    pub(crate) fn drive_view_certificates<H: Hasher<Digest = D>>(
        &mut self,
        generation: Generation,
        view: View,
        job_slots: usize,
        budget: usize,
    ) -> Result<CertificateDrive, ViewError> {
        if job_slots == 0 || budget == 0 {
            return Ok(if job_slots == 0 {
                Drive::done(0, ())
            } else {
                Drive::yielded(0, ())
            });
        }
        let mut processed = 0;
        // A scan already in progress for another view finishes first. Discarding it would let
        // the current view and a deferred ready view reset each other's partial scans on
        // alternating drives, which never terminates once one pass exceeds a service budget.
        if let Some(mut other) = self.certificate_scan.take_if(|scan| scan.view != view) {
            if !self.run_scan(&mut other, &mut processed, budget) {
                self.certificate_scan = Some(other);
                return Ok(Drive::yielded(processed, ()));
            }
            self.finish_certificate_scan::<H>(generation, other)?;
            if processed >= budget {
                return Ok(Drive::yielded(processed, ()));
            }
        }
        let mut scan = self
            .certificate_scan
            .take()
            .unwrap_or_else(|| self.start_certificate_scan(view));
        if !self.run_scan(&mut scan, &mut processed, budget) {
            self.certificate_scan = Some(scan);
            return Ok(Drive::yielded(processed, ()));
        }

        self.finish_certificate_scan::<H>(generation, scan)?;
        Ok(Drive::done(processed, ()))
    }

    fn start_certificate_scan(&self, view: View) -> CertificateScan<V, D> {
        CertificateScan {
            view,
            pending_messages: self.claims.first_message_cohort(view),
            pending_nullifies: self.claims.first_nullify_cohort(view),
            support: BTreeMap::new(),
            best_vqc: None,
            nullification: None,
            phase: CertificateScanPhase::CountSupport(CountSupport { cursor: None }),
        }
    }

    /// Runs a full certificate scan of `view` without a budget.
    pub(super) fn complete_certificate_scan(&self, view: View) -> CertificateScan<V, D> {
        let mut scan = self.start_certificate_scan(view);
        let mut processed = 0;
        self.run_scan(&mut scan, &mut processed, usize::MAX);
        scan
    }

    /// Advances `scan` until it completes or `processed` reaches `budget`, and returns whether
    /// it completed.
    fn run_scan(
        &self,
        scan: &mut CertificateScan<V, D>,
        processed: &mut usize,
        budget: usize,
    ) -> bool {
        while *processed < budget && !scan.complete() {
            if self.advance_certificate_scan(scan) {
                *processed += 1;
            }
        }
        scan.complete()
    }

    /// Advances exactly one retained participant or target boundary and returns whether the
    /// step cost one unit of budget.
    fn advance_certificate_scan(&self, scan: &mut CertificateScan<V, D>) -> bool {
        let step = match core::mem::replace(&mut scan.phase, CertificateScanPhase::Complete) {
            CertificateScanPhase::CountSupport(phase) => self.count_support(scan, phase),
            CertificateScanPhase::FindTarget(phase) => self.find_target(scan, phase),
            CertificateScanPhase::EvaluateTarget(phase) => self.evaluate_target(scan, phase),
            CertificateScanPhase::SelectTarget(phase) => self.select_target(scan, phase),
            CertificateScanPhase::CountNullifications(phase) => {
                self.count_nullifications(scan, phase)
            }
            CertificateScanPhase::SelectNullifications(phase) => {
                self.select_nullifications(scan, phase)
            }
            CertificateScanPhase::Complete => ScanStep::Advanced(CertificateScanPhase::Complete),
        };
        let (advanced, phase) = match step {
            ScanStep::Advanced(phase) => (true, phase),
            ScanStep::Moved(phase) => (false, phase),
        };
        scan.phase = phase;
        advanced
    }

    fn count_support(
        &self,
        scan: &mut CertificateScan<V, D>,
        CountSupport { cursor }: CountSupport,
    ) -> ScanStep<V, D> {
        let Some((participant, (_, record))) = self
            .entry(scan.view)
            .and_then(|entry| next_after(&entry.sticky, cursor))
        else {
            return ScanStep::Moved(CertificateScanPhase::FindTarget(FindTarget {
                cursor: None,
            }));
        };
        if scan.message_settled(record.observation.cohort())
            && let MessageRef::Vote(vote) = record.value.get()
        {
            *scan.support.entry(vote.body().leader()).or_default() += 1;
        }
        ScanStep::Advanced(CertificateScanPhase::CountSupport(CountSupport {
            cursor: Some(participant),
        }))
    }

    fn find_target(
        &self,
        scan: &CertificateScan<V, D>,
        FindTarget { cursor }: FindTarget<D>,
    ) -> ScanStep<V, D> {
        let Some((target, support)) = next_after(&scan.support, cursor) else {
            return ScanStep::Moved(CertificateScanPhase::CountNullifications(
                CountNullifications {
                    cursor: None,
                    cohorts: BinaryHeap::new(),
                },
            ));
        };
        let usable = *support >= self.config.designation_quorum()
            && self
                .entry(scan.view)
                .is_some_and(|entry| entry.leaders.contains_key(&target));
        let phase = if usable {
            CertificateScanPhase::EvaluateTarget(EvaluateTarget {
                target,
                cursor: None,
                eligible: 0,
                targets: 0,
                message_cohorts: BinaryHeap::new(),
                target_cohorts: BinaryHeap::new(),
            })
        } else {
            CertificateScanPhase::FindTarget(FindTarget {
                cursor: Some(target),
            })
        };
        ScanStep::Advanced(phase)
    }

    fn evaluate_target(
        &self,
        scan: &CertificateScan<V, D>,
        mut phase: EvaluateTarget<D>,
    ) -> ScanStep<V, D> {
        let Some((participant, (_, record))) = self
            .entry(scan.view)
            .and_then(|entry| next_after(&entry.sticky, phase.cursor))
        else {
            if phase.eligible < self.config.view_quorum()
                || phase.targets < self.config.designation_quorum()
            {
                return ScanStep::Moved(CertificateScanPhase::FindTarget(FindTarget {
                    cursor: Some(phase.target),
                }));
            }
            let cohort = *phase
                .message_cohorts
                .peek()
                .expect("a quorum fills the message cohort heap")
                .max(
                    phase
                        .target_cohorts
                        .peek()
                        .expect("a designation quorum fills the target cohort heap"),
                )
                .max(
                    &self
                        .scanned_leader(scan.view, phase.target)
                        .observation
                        .cohort(),
                );
            let limit = if self
                .entry(scan.view)
                .is_some_and(|entry| entry.vqc.assembled.contains_key(&phase.target))
            {
                phase.eligible
            } else {
                self.config.view_quorum()
            };
            return ScanStep::Moved(CertificateScanPhase::SelectTarget(SelectTarget {
                target: phase.target,
                cohort: if limit == phase.eligible {
                    u64::MAX
                } else {
                    cohort
                },
                limit,
                cursor: None,
                eligible: phase.eligible,
                remaining_targets: phase.targets,
                visited: 0,
                target_count: 0,
                observation: self.scanned_leader(scan.view, phase.target).observation,
                messages: Vec::with_capacity(limit),
                ids: Vec::with_capacity(limit),
            }));
        };
        if scan.message_settled(record.observation.cohort())
            && let Some(kind) = record.value.vqc_eligibility(
                phase.target,
                self.scanned_leader(scan.view, phase.target).value.get(),
            )
        {
            phase.eligible += 1;
            retain_smallest(
                &mut phase.message_cohorts,
                record.observation.cohort(),
                self.config.view_quorum(),
            );
            if matches!(kind, VqcEligibility::Target) {
                phase.targets += 1;
                retain_smallest(
                    &mut phase.target_cohorts,
                    record.observation.cohort(),
                    self.config.designation_quorum(),
                );
            }
        }
        phase.cursor = Some(participant);
        ScanStep::Advanced(CertificateScanPhase::EvaluateTarget(phase))
    }

    fn select_target(
        &self,
        scan: &mut CertificateScan<V, D>,
        mut phase: SelectTarget<V, D>,
    ) -> ScanStep<V, D> {
        let next = (phase.messages.len() < phase.limit)
            .then(|| {
                self.entry(scan.view)
                    .and_then(|entry| next_after(&entry.sticky, phase.cursor))
            })
            .flatten();
        let Some((participant, (id, record))) = next else {
            if phase.messages.len() == phase.limit
                && phase.target_count >= self.config.designation_quorum()
            {
                let prepared = PreparedVqc {
                    candidate: VqcCandidate {
                        observation: phase.observation,
                        transcript: VqcTranscript {
                            view: scan.view,
                            target: phase.target,
                            messages: phase.ids,
                        },
                    },
                    messages: phase.messages.into(),
                };
                if self.vqc_transcript_is_new(&prepared.candidate.transcript)
                    && scan.best_vqc.as_ref().is_none_or(|best| {
                        (
                            prepared.candidate.observation,
                            prepared.candidate.transcript.target,
                        ) < (best.candidate.observation, best.candidate.transcript.target)
                    })
                {
                    scan.best_vqc = Some(prepared);
                }
            }
            return ScanStep::Moved(CertificateScanPhase::FindTarget(FindTarget {
                cursor: Some(phase.target),
            }));
        };
        let cohort = record.observation.cohort();
        let kind = (cohort <= phase.cohort && scan.message_settled(cohort))
            .then(|| {
                record.value.vqc_eligibility(
                    phase.target,
                    self.scanned_leader(scan.view, phase.target).value.get(),
                )
            })
            .flatten();
        if let Some(kind) = kind {
            let is_target = matches!(kind, VqcEligibility::Target);
            phase.remaining_targets -= usize::from(is_target);
            if phase.admit(is_target, self.config.designation_quorum()) {
                phase.messages.push(record.value.clone());
                phase.ids.push(*id);
                phase.target_count += usize::from(is_target);
                phase.observation = phase.observation.max(record.observation);
            }
            phase.visited += 1;
        }
        phase.cursor = Some(participant);
        ScanStep::Advanced(CertificateScanPhase::SelectTarget(phase))
    }

    fn count_nullifications(
        &self,
        scan: &CertificateScan<V, D>,
        mut phase: CountNullifications,
    ) -> ScanStep<V, D> {
        let Some((participant, record)) = self
            .entry(scan.view)
            .and_then(|entry| next_after(&entry.nullifies, phase.cursor))
        else {
            let quorum = self.config.nullification_quorum();
            let next = match phase.cohorts.peek() {
                Some(cohort) if phase.cohorts.len() >= quorum => {
                    CertificateScanPhase::SelectNullifications(SelectNullifications {
                        cohort: *cohort,
                        cursor: None,
                        observation: None,
                        shares: Vec::with_capacity(quorum),
                    })
                }
                _ => CertificateScanPhase::Complete,
            };
            return ScanStep::Moved(next);
        };
        if scan.nullify_settled(record.observation.cohort()) {
            retain_smallest(
                &mut phase.cohorts,
                record.observation.cohort(),
                self.config.nullification_quorum(),
            );
        }
        phase.cursor = Some(participant);
        ScanStep::Advanced(CertificateScanPhase::CountNullifications(phase))
    }

    fn select_nullifications(
        &self,
        scan: &mut CertificateScan<V, D>,
        mut phase: SelectNullifications<V>,
    ) -> ScanStep<V, D> {
        let Some((participant, record)) = self
            .entry(scan.view)
            .and_then(|entry| next_after(&entry.nullifies, phase.cursor))
        else {
            if phase.shares.len() == self.config.nullification_quorum() {
                scan.nullification = Some(PreparedNullification {
                    observation: phase
                        .observation
                        .expect("selected shares have an observation"),
                    shares: phase.shares.into(),
                });
            }
            return ScanStep::Moved(CertificateScanPhase::Complete);
        };
        let cohort = record.observation.cohort();
        if phase.shares.len() < self.config.nullification_quorum()
            && cohort <= phase.cohort
            && scan.nullify_settled(cohort)
        {
            phase.shares.push(record.value.get().clone());
            phase.observation = Some(phase.observation.map_or(record.observation, |current| {
                current.max(record.observation)
            }));
        }
        phase.cursor = Some(participant);
        ScanStep::Advanced(CertificateScanPhase::SelectNullifications(phase))
    }

    fn finish_certificate_scan<H: Hasher<Digest = D>>(
        &mut self,
        generation: Generation,
        scan: CertificateScan<V, D>,
    ) -> Result<(), ViewError> {
        let view = scan.view;
        let mut rescan = false;
        match self.select_prepared(scan) {
            Some(PreparedCertificate::Vqc(prepared)) => {
                let candidate = prepared.candidate;
                let leader = self
                    .scanned_leader(view, candidate.transcript.target)
                    .value
                    .get()
                    .clone();
                let exit_covered = self.vqc_forwarded(view) || self.nullification_forwarded(view);
                let valid = validate_vqc_votes::<H, V, D>(
                    &leader,
                    prepared.messages.iter().filter_map(|message| {
                        let MessageRef::Vote(vote) = message.get() else {
                            return None;
                        };
                        (vote.body().leader() == candidate.transcript.target)
                            .then_some((vote.signer(), vote.body()))
                    }),
                    self.config,
                )
                .is_ok();
                let materialized =
                    self.vqc_transcript_materialized::<H>(&leader, &prepared.messages, self.config);
                if !valid || exit_covered && materialized {
                    self.entry_mut(candidate.transcript.view)
                        .vqc
                        .assembled
                        .insert(candidate.transcript.target, candidate.transcript.messages);
                    rescan = materialized;
                } else {
                    let job = VqcAggregateJob {
                        issued: Issued::new(self.next_certificate_id()?, generation),
                        leader,
                        messages: prepared.messages,
                        transcript: candidate.transcript,
                    };
                    self.issue(ViewCertificateJob::Vqc {
                        job,
                        observation: candidate.observation,
                    });
                }
            }
            Some(PreparedCertificate::Nullification(prepared)) => {
                let job = NullificationRecoveryJob {
                    issued: Issued::new(self.next_certificate_id()?, generation),
                    view,
                    shares: prepared.shares,
                };
                self.issue(ViewCertificateJob::Nullification {
                    job,
                    observation: prepared.observation,
                });
            }
            None => {}
        }
        self.ready_certificate_views.remove(&view);
        if rescan {
            self.refresh_view(view);
        }
        Ok(())
    }

    /// Returns the certificate a completed scan may assemble next: the earliest candidate exit
    /// that no unresolved or held exit precedes and that is not already pending or assembled.
    fn select_prepared(&self, scan: CertificateScan<V, D>) -> Option<PreparedCertificate<V, D>> {
        let view = scan.view;
        let vqc_forwarded = self.vqc_forwarded(view);
        let nullification_forwarded = self.nullification_forwarded(view);
        let unresolved = self.unresolved_exit(view, !vqc_forwarded, !nullification_forwarded);
        let held = self.held_exit(view, vqc_forwarded, nullification_forwarded);
        let allowed = |key: ExitKey| {
            unresolved.is_none_or(|unresolved| key < unresolved)
                && held.is_none_or(|held| key <= held)
        };

        let vqc = scan.best_vqc.filter(|prepared| {
            self.pending_observation(view, ExitKind::Vqc).is_none()
                && allowed(ExitKey::vqc(prepared.candidate.observation.cohort()))
        });
        let nullification = scan.nullification.filter(|prepared| {
            !nullification_forwarded
                && self
                    .pending_observation(view, ExitKind::Nullification)
                    .is_none()
                && !self
                    .entry(view)
                    .is_some_and(|entry| entry.nullification.assembled)
                && !self
                    .entry(view)
                    .and_then(|entry| entry.nullification.records.first())
                    .is_some_and(|(_, record)| {
                        record.observation.cohort() < prepared.observation.cohort()
                    })
                && allowed(ExitKey::nullification(prepared.observation.cohort()))
        });
        match (vqc, nullification) {
            (Some(vqc), Some(nullification)) => Some(
                if ExitKey::vqc(vqc.candidate.observation.cohort())
                    <= ExitKey::nullification(nullification.observation.cohort())
                {
                    PreparedCertificate::Vqc(vqc)
                } else {
                    PreparedCertificate::Nullification(nullification)
                },
            ),
            (Some(vqc), None) => Some(PreparedCertificate::Vqc(vqc)),
            (None, Some(nullification)) => Some(PreparedCertificate::Nullification(nullification)),
            (None, None) => None,
        }
    }

    /// Records an issued certificate job, marks its view pending, and releases its effect.
    fn issue(&mut self, job: ViewCertificateJob<V, D>) {
        let observation = job.observation();
        let issued = match &job {
            ViewCertificateJob::Nullification { job, .. } => {
                self.entry_mut(job.view).nullification.pending = Some(observation);
                self.capabilities
                    .push(Capability::Crypto(CryptoJob::RecoverNullification(
                        job.clone(),
                    )));
                job.issued
            }
            ViewCertificateJob::Vqc { job, .. } => {
                self.entry_mut(job.leader.view()).vqc.pending = Some(observation);
                self.capabilities
                    .push(Capability::Crypto(CryptoJob::AggregateVqc(job.clone())));
                job.issued
            }
        };
        self.certificate_jobs.insert(issued, job);
    }

    /// Invalidates any scan of `view` and re-derives whether the view is ready for certificate
    /// work and which of its certificates can be forwarded.
    pub(super) fn refresh_view(&mut self, view: View) {
        if self
            .certificate_scan
            .as_ref()
            .is_some_and(|scan| scan.view == view)
        {
            self.certificate_scan = None;
        }
        let (messages, nullifies) = self
            .entry(view)
            .map_or((0, 0), |entry| (entry.sticky.len(), entry.nullifies.len()));
        let ready = messages >= self.config.view_quorum()
            || nullifies >= self.config.nullification_quorum();
        set_member(&mut self.ready_certificate_views, view, ready);

        // Only live views have a first-forwarding duty. Certificates resolved for retired
        // views supply finality evidence and proposal parents.
        let live = view > self.retired_transitions;
        let candidates = live.then(|| self.forward_candidates(view));
        let vqc = candidates
            .as_ref()
            .is_some_and(|candidates| candidates.vqc.is_some());
        let nullification = candidates
            .as_ref()
            .is_some_and(|candidates| candidates.nullification.is_some());
        set_member(&mut self.forwardable_vqcs, view, vqc);
        set_member(&mut self.forwardable_nullifications, view, nullification);
    }

    /// Takes the certificate work issued since the last call.
    pub(crate) fn take_capabilities(&mut self) -> Capabilities<V, D> {
        std::mem::take(&mut self.capabilities)
    }

    /// Returns the number of certificate jobs in flight.
    pub(crate) fn certificate_reservations(&self) -> usize {
        self.certificate_jobs.len()
    }

    /// Prepares a nullification recovery completion, or consumes a stale completion.
    ///
    /// Returning `None` releases a matching job whose dispatch generation is no longer current
    /// and re-derives the view's readiness, so a completion that cannot commit can never strand
    /// the view behind a pending marker.
    pub(crate) fn prepare_nullification(
        &mut self,
        completion: &NullificationRecoveryCompletion<V>,
        generation: Generation,
    ) -> Result<Option<PreparedArtifact<V, D>>, ViewError> {
        let (job, observation) = match self.certificate_jobs.admit(completion.issued, generation) {
            Admit::Current(ViewCertificateJob::Nullification { job, observation }) => {
                (job, *observation)
            }
            Admit::Current(ViewCertificateJob::Vqc { .. }) | Admit::Stale => return Ok(None),
            Admit::Abandoned(job) => {
                self.release_certificate_job(job);
                return Ok(None);
            }
        };
        let certificate = &completion.certificate;
        let Some(first) = job.shares.first() else {
            return Err(ViewError::CompletionMismatch);
        };
        if certificate.round() != first.round() || certificate.certificate().get().is_none() {
            return Err(ViewError::CompletionMismatch);
        }
        Ok(Some(PreparedArtifact {
            artifact: Arc::new(Artifact::Nullification(certificate.clone())),
            observation,
        }))
    }

    /// Releases a committed nullification job and marks its view's nullification assembled.
    pub(crate) fn finish_nullification(&mut self, id: ViewCertificateId) {
        let Some(ViewCertificateJob::Nullification { job, .. }) = self.certificate_jobs.remove(id)
        else {
            return;
        };
        let track = &mut self.entry_mut(job.view).nullification;
        track.pending = None;
        track.assembled = true;
        self.refresh_view(job.view);
    }

    /// Prepares a V-QC aggregation completion, or consumes a stale completion.
    ///
    /// Returning `None` releases a matching job whose dispatch generation is no longer current
    /// and re-derives the view's readiness, so a completion that cannot commit can never strand
    /// the view behind a pending marker.
    pub(crate) fn prepare_vqc(
        &mut self,
        completion: &VqcAggregateCompletion<V, D>,
        generation: Generation,
    ) -> Result<Option<PreparedArtifact<V, D>>, ViewError> {
        let (job, observation) = match self.certificate_jobs.admit(completion.issued, generation) {
            Admit::Current(ViewCertificateJob::Vqc { job, observation }) => (job, *observation),
            Admit::Current(ViewCertificateJob::Nullification { .. }) | Admit::Stale => {
                return Ok(None);
            }
            Admit::Abandoned(job) => {
                self.release_certificate_job(job);
                return Ok(None);
            }
        };
        if !Arc::ptr_eq(&job.messages, &completion.messages) {
            return Err(ViewError::CompletionMismatch);
        }
        Ok(Some(PreparedArtifact {
            artifact: Arc::clone(completion.derived().artifact.arc()),
            observation,
        }))
    }

    /// Releases a committed V-QC job and records its transcript as assembled.
    pub(crate) fn finish_vqc(&mut self, id: ViewCertificateId) {
        let Some(ViewCertificateJob::Vqc { job, .. }) = self.certificate_jobs.remove(id) else {
            return;
        };
        let view = job.leader.view();
        if let Some(entry) = self.views.get_mut(&view) {
            entry.vqc.pending = None;
        }
        self.entry_mut(job.transcript.view)
            .vqc
            .assembled
            .insert(job.transcript.target, job.transcript.messages);
        self.refresh_view(view);
    }

    /// Releases a certificate job without an assembled certificate and re-derives readiness.
    ///
    /// The retained shares survive the job, so the view re-enters the ready set on the same
    /// call when its quorum still holds, instead of waiting behind a pending marker whose
    /// completion was consumed.
    fn release_certificate_job(&mut self, job: ViewCertificateJob<V, D>) {
        match job {
            ViewCertificateJob::Nullification { job, .. } => {
                if let Some(entry) = self.views.get_mut(&job.view) {
                    entry.nullification.pending = None;
                }
                self.refresh_view(job.view);
            }
            ViewCertificateJob::Vqc { job, .. } => {
                let view = job.leader.view();
                if let Some(entry) = self.views.get_mut(&view) {
                    entry.vqc.pending = None;
                }
                self.refresh_view(view);
            }
        }
    }

    fn vqc_transcript_is_new(&self, candidate: &VqcTranscript<D>) -> bool {
        let Some(previous) = self
            .entry(candidate.view)
            .and_then(|entry| entry.vqc.assembled.get(&candidate.target))
        else {
            return true;
        };
        candidate.messages.len() > previous.len()
            && previous
                .iter()
                .all(|message| candidate.messages.contains(message))
    }

    fn vqc_transcript_materialized<H: Hasher<Digest = D>>(
        &self,
        leader: &LeaderBlock<V, D>,
        messages: &[Held<ViewMessageKind, V, D>],
        config: CodecConfig,
    ) -> bool {
        self.parents_by_view
            .get(&leader.view())
            .into_iter()
            .flatten()
            .filter_map(|id| match &self.parents.get(id)?.proof {
                ParentProof::Genesis => None,
                ParentProof::Vqc(certificate) => Some(certificate),
            })
            .any(|certificate| {
                vqc_transcript_matches::<H, V, D>(certificate.get(), leader, messages, config)
            })
    }

    fn next_certificate_id(&mut self) -> Result<ViewCertificateId, ViewError> {
        self.certificate_ids
            .issue()
            .ok_or(ViewError::IdentifierExhausted)
    }
}
