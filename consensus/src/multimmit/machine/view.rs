//! Proposal selection, view-message collection, and deterministic view exits.

use super::{
    Artifact, ArtifactId, ChainProposalPass, ChainProposalProgress, ChainState, Observation,
    Profile, ProposalRequest, Role, SignRequest, ViewNullification, ViewSnapshot, ViewStance,
    ViewTransition, VoteBodyPass, VoteBodyProgress, VoteRequest,
    algebra::{Tips, VqcExtraction, validate_vqc_votes},
};
use crate::{
    Epochable, Viewable,
    multimmit::{
        config::CodecConfig,
        types::{
            Anchor, CertificateId, LeaderBlock, Nullification, Nullify, ProposalParent,
            SignedLeaderBlock, TipRecord, ViewMessage, Vote, VoteBody, Vqc, genesis_history,
        },
    },
    types::{Attributable, Participant, Round, View},
};
use bytes::Bytes;
use commonware_codec::Encode;
use commonware_cryptography::{Digest, Hasher, bls12381::primitives::variant::Variant};
use core::iter::once;
use std::{
    collections::{BTreeMap, BTreeSet, BinaryHeap},
    ops::Bound::{Excluded, Unbounded},
    sync::Arc,
};

#[derive(Clone, Debug)]
struct ProposalRecord<V: Variant, D: Digest> {
    observation: Observation,
    artifact: Arc<Artifact<V, D>>,
}

#[derive(Clone, Debug)]
struct TransitionLeader<V: Variant, D: Digest> {
    observation: Observation,
    artifact: Arc<Artifact<V, D>>,
}

enum RegularSignPass<V: Variant, D: Digest> {
    Vote {
        view: View,
        pass: VoteBodyPass<V, D>,
    },
    Proposal {
        view: View,
        parent: ParentRecord<V, D>,
        attach_parent: bool,
        next_chain: usize,
        current: Option<ChainProposalPass<V, D>>,
        proposals: Vec<crate::multimmit::types::ChainProposal<V, D>>,
    },
}

pub(crate) struct RegularSignDrive<V: Variant, D: Digest> {
    pub(crate) processed: usize,
    pub(crate) complete: bool,
    pub(crate) request: Option<SignRequest<V, D>>,
}

pub(super) struct LeaderRecord<V: Variant, D: Digest> {
    transition: Option<TransitionLeader<V, D>>,
}

#[derive(Clone, Debug)]
struct ParentRecord<V: Variant, D: Digest> {
    id: CertificateId<D>,
    view: View,
    history: D,
    canonical: Bytes,
    certificate: Option<Arc<Artifact<V, D>>>,
    tips: Tips<D>,
    messages: usize,
}

#[derive(Clone, Debug)]
struct MessageRecord<V: Variant, D: Digest> {
    id: ArtifactId<D>,
    observation: Observation,
    artifact: Arc<Artifact<V, D>>,
}

type FinalityProofs<V, D> = BTreeMap<(View, ArtifactId<D>), Arc<Artifact<V, D>>>;

#[derive(Clone, Debug)]
struct NullifyRecord<V: Variant, D: Digest> {
    observation: Observation,
    artifact: Arc<Artifact<V, D>>,
}

#[derive(Clone, Debug)]
struct NullificationRecord<V: Variant, D: Digest> {
    id: ArtifactId<D>,
    observation: Observation,
    artifact: Arc<Artifact<V, D>>,
}

#[derive(Clone, Debug)]
struct VqcRecord<V: Variant, D: Digest> {
    artifact_id: ArtifactId<D>,
    id: CertificateId<D>,
    observation: Observation,
    artifact: Arc<Artifact<V, D>>,
}

impl<V: Variant, D: Digest> ProposalRecord<V, D> {
    fn block(&self) -> &SignedLeaderBlock<V, D> {
        let Artifact::LeaderBlock(block) = self.artifact.as_ref() else {
            unreachable!("proposal records contain leader blocks");
        };
        block
    }
}

enum MessageRef<'a, V: Variant, D: Digest> {
    Vote(&'a Vote<V, D>),
    NoVote,
}

#[derive(Copy, Clone)]
enum VqcEligibility {
    Target,
    Other,
}

impl<V: Variant, D: Digest> LeaderRecord<V, D> {
    fn block(&self) -> &LeaderBlock<V, D> {
        let transition = self
            .transition
            .as_ref()
            .expect("view rules only inspect retained transition leaders");
        match transition.artifact.as_ref() {
            Artifact::LeaderBlock(block) => block.block(),
            Artifact::Vqc(certificate) => certificate.leader(),
            _ => unreachable!("leader records contain proposals or V-QCs"),
        }
    }

    const fn observation(&self) -> Observation {
        self.transition
            .as_ref()
            .expect("view rules only inspect retained transition leaders")
            .observation
    }

    fn set_transition(&mut self, observation: Observation, artifact: &Arc<Artifact<V, D>>) {
        let Some(transition) = self.transition.as_mut() else {
            self.transition = Some(TransitionLeader {
                observation,
                artifact: Arc::clone(artifact),
            });
            return;
        };
        if transition.observation <= observation {
            return;
        }
        transition.observation = observation;
        transition.artifact = Arc::clone(artifact);
    }

    const fn retain_transition(&self) -> bool {
        self.transition.is_some()
    }
}

impl<V: Variant, D: Digest> MessageRecord<V, D> {
    fn message(&self) -> MessageRef<'_, V, D> {
        match self.artifact.as_ref() {
            Artifact::Vote(vote) => MessageRef::Vote(vote),
            Artifact::NoVote(_) => MessageRef::NoVote,
            _ => unreachable!("view-message records contain votes or novotes"),
        }
    }

    fn vqc_eligibility(&self, target: D, leader: &LeaderBlock<V, D>) -> Option<VqcEligibility> {
        match self.message() {
            MessageRef::Vote(vote) if vote.body().leader() == target => vote
                .body()
                .valid_for_digest(leader, target)
                .then_some(VqcEligibility::Target),
            MessageRef::Vote(_) | MessageRef::NoVote => Some(VqcEligibility::Other),
        }
    }
}

impl<V: Variant, D: Digest> NullifyRecord<V, D> {
    fn share(&self) -> &Nullify<V> {
        let Artifact::Nullify(share) = self.artifact.as_ref() else {
            unreachable!("nullify records contain nullify shares");
        };
        share
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Claim {
    Proposal(View),
    ViewMessage(View, Participant),
    Nullify(View, Participant),
    Nullification(View),
    Vqc(View),
}

impl Claim {
    const fn certificate_view(self) -> View {
        match self {
            Self::Proposal(view)
            | Self::ViewMessage(view, _)
            | Self::Nullify(view, _)
            | Self::Nullification(view)
            | Self::Vqc(view) => view,
        }
    }
}

/// Identifies one exact view-certificate construction request.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct ViewCertificateId(u64);

impl ViewCertificateId {
    /// Returns the generation-local sequence.
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Exact verified shares selected for one nullification.
#[derive(Clone, Debug)]
pub(crate) struct NullificationRecoveryJob<V: Variant> {
    id: ViewCertificateId,
    generation: u64,
    shares: Arc<[Nullify<V>]>,
}

impl<V: Variant> NullificationRecoveryJob<V> {
    /// Returns the job identifier.
    pub const fn id(&self) -> ViewCertificateId {
        self.id
    }

    /// Returns the process generation issuing the job.
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns the exact canonical signer subset in participant order.
    pub fn shares(&self) -> &[Nullify<V>] {
        &self.shares
    }
}

/// Completion of one exact nullification recovery request.
#[derive(Clone, Debug)]
pub(crate) struct NullificationRecoveryCompletion<V: Variant> {
    id: ViewCertificateId,
    generation: u64,
    certificate: Nullification<V>,
}

impl<V: Variant> NullificationRecoveryCompletion<V> {
    /// Creates a matched recovery completion.
    pub const fn new(
        id: ViewCertificateId,
        generation: u64,
        certificate: Nullification<V>,
    ) -> Self {
        Self {
            id,
            generation,
            certificate,
        }
    }

    /// Returns the completed job identifier.
    pub const fn id(&self) -> ViewCertificateId {
        self.id
    }
}

/// Exact verified view messages selected for one V-QC.
#[derive(Clone, Debug)]
pub(crate) struct VqcAggregateJob<V: Variant, D: Digest> {
    id: ViewCertificateId,
    generation: u64,
    leader: LeaderBlock<V, D>,
    messages: Arc<[Arc<Artifact<V, D>>]>,
    transcript: VqcTranscript<D>,
}

impl<V: Variant, D: Digest> VqcAggregateJob<V, D> {
    /// Returns the job identifier.
    pub const fn id(&self) -> ViewCertificateId {
        self.id
    }

    /// Returns the process generation issuing the job.
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns the designated unsigned leader block.
    pub const fn leader(&self) -> &LeaderBlock<V, D> {
        &self.leader
    }

    /// Reconstructs the exact canonical message subset in participant order.
    ///
    /// The job retains shared canonical artifacts. Consumers materialize owned protocol messages
    /// only while executing the aggregation.
    pub fn messages(&self) -> impl ExactSizeIterator<Item = ViewMessage<V, D>> + '_ {
        self.messages
            .iter()
            .map(|artifact| match artifact.as_ref() {
                Artifact::Vote(vote) => ViewMessage::Vote(vote.clone()),
                Artifact::NoVote(vote) => ViewMessage::NoVote(vote.clone()),
                _ => unreachable!("V-QC jobs contain votes or novotes"),
            })
    }
}

/// Completion of one exact V-QC aggregation request.
#[derive(Clone, Debug)]
pub(crate) struct VqcAggregateCompletion<V: Variant, D: Digest> {
    id: ViewCertificateId,
    generation: u64,
    certificate: Vqc<V, D>,
}

impl<V: Variant, D: Digest> VqcAggregateCompletion<V, D> {
    /// Creates a matched aggregation completion.
    pub const fn new(id: ViewCertificateId, generation: u64, certificate: Vqc<V, D>) -> Self {
        Self {
            id,
            generation,
            certificate,
        }
    }

    /// Returns the completed job identifier.
    pub const fn id(&self) -> ViewCertificateId {
        self.id
    }
}

#[derive(Clone, Debug)]
pub(crate) enum ViewEffect<V: Variant, D: Digest> {
    RecoverNullification(NullificationRecoveryJob<V>),
    AggregateVqc(VqcAggregateJob<V, D>),
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) struct CertificateDrive {
    pub processed: usize,
    pub complete: bool,
}

#[derive(Clone, Debug)]
pub(crate) struct Exit<V: Variant, D: Digest> {
    pub proof: Arc<Artifact<V, D>>,
    pub rescue: Option<LeaderBlock<V, D>>,
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
enum TransitionState {
    #[default]
    Active,
    Exited,
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
enum StanceState {
    #[default]
    Unchosen,
    Voted,
    NoVoted,
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
enum NullificationState {
    #[default]
    Unsigned,
    Signed,
}

/// One explicit input to the per-view product machine.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum ViewSlotInput {
    Propose,
    Vote,
    NoVote,
    Nullify,
    Exit,
}

/// The state dimension changed by one accepted per-view input.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum ViewSlotOutput {
    Proposed,
    Voted,
    NoVoted,
    Nullified,
    Exited,
    Unchanged,
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
struct ViewProductState {
    transition: TransitionState,
    stance: StanceState,
    nullification: NullificationState,
    proposed: bool,
}

impl ViewProductState {
    fn apply(&mut self, input: ViewSlotInput) -> Option<ViewSlotOutput> {
        use ViewSlotInput::{Exit, NoVote, Nullify, Propose, Vote};

        match input {
            Propose if self.transition == TransitionState::Active && !self.proposed => {
                self.proposed = true;
                Some(ViewSlotOutput::Proposed)
            }
            Propose if self.proposed => Some(ViewSlotOutput::Unchanged),
            Vote if self.transition == TransitionState::Active
                && self.stance == StanceState::Unchosen
                && self.nullification == NullificationState::Unsigned =>
            {
                self.stance = StanceState::Voted;
                Some(ViewSlotOutput::Voted)
            }
            Vote if self.stance == StanceState::Voted => Some(ViewSlotOutput::Unchanged),
            NoVote
                if self.transition == TransitionState::Active
                    && self.stance == StanceState::Unchosen =>
            {
                self.stance = StanceState::NoVoted;
                Some(ViewSlotOutput::NoVoted)
            }
            NoVote if self.stance == StanceState::NoVoted => Some(ViewSlotOutput::Unchanged),
            Nullify if self.transition == TransitionState::Active => {
                let output = if self.nullification == NullificationState::Signed {
                    ViewSlotOutput::Unchanged
                } else {
                    self.nullification = NullificationState::Signed;
                    ViewSlotOutput::Nullified
                };
                Some(output)
            }
            Exit if self.transition == TransitionState::Active => {
                self.transition = TransitionState::Exited;
                Some(ViewSlotOutput::Exited)
            }
            Exit => Some(ViewSlotOutput::Unchanged),
            Propose | Vote | NoVote | Nullify => None,
        }
    }

    const fn can_vote(self) -> bool {
        matches!(self.transition, TransitionState::Active)
            && matches!(self.stance, StanceState::Unchosen)
            && matches!(self.nullification, NullificationState::Unsigned)
    }

    const fn has_voted(self) -> bool {
        matches!(self.stance, StanceState::Voted)
    }

    const fn nullified(self) -> bool {
        matches!(self.nullification, NullificationState::Signed)
    }
}

#[derive(Clone, Debug)]
struct ViewSlot<V: Variant, D: Digest> {
    state: ViewProductState,
    proposal: Option<LeaderBlock<V, D>>,
    vote: Option<VoteBody<D>>,
    exit: Option<ArtifactId<D>>,
}

impl<V: Variant, D: Digest> Default for ViewSlot<V, D> {
    fn default() -> Self {
        Self {
            state: ViewProductState::default(),
            proposal: None,
            vote: None,
            exit: None,
        }
    }
}

impl<V: Variant, D: Digest> ViewSlot<V, D> {
    fn observe_proposal(&mut self, block: LeaderBlock<V, D>) -> Result<(), ViewError> {
        if let Some(existing) = &self.proposal {
            return (existing == &block)
                .then_some(())
                .ok_or(ViewError::ProposalConflict);
        }
        self.state
            .apply(ViewSlotInput::Propose)
            .ok_or(ViewError::ProposalConflict)?;
        self.proposal = Some(block);
        Ok(())
    }

    fn observe_vote(&mut self, body: VoteBody<D>) -> Result<(), ViewError> {
        if let Some(existing) = &self.vote {
            return (existing == &body)
                .then_some(())
                .ok_or(ViewError::VoteConflict);
        }
        self.state
            .apply(ViewSlotInput::Vote)
            .ok_or(ViewError::VoteNoVoteConflict)?;
        self.vote = Some(body);
        Ok(())
    }

    fn observe_novote(&mut self) -> Result<(), ViewError> {
        self.state
            .apply(ViewSlotInput::NoVote)
            .ok_or(ViewError::VoteNoVoteConflict)?;
        Ok(())
    }

    fn observe_nullify(&mut self) {
        let _ = self.state.apply(ViewSlotInput::Nullify);
    }

    fn observe_exit(&mut self, proof: ArtifactId<D>) {
        if self.state.apply(ViewSlotInput::Exit).is_some() {
            self.exit.get_or_insert(proof);
        }
    }
}

/// Consensus-layer facts and local safety choices for one epoch.
pub(crate) struct ViewState<V: Variant, D: Digest> {
    pub(super) config: CodecConfig,
    retired_transitions: View,
    proposal_anchor_view: View,
    proposal_nullified_through: View,
    parents: BTreeMap<CertificateId<D>, ParentRecord<V, D>>,
    parents_by_view: BTreeMap<View, Vec<CertificateId<D>>>,
    pub(super) leaders: BTreeMap<(View, D), LeaderRecord<V, D>>,
    proposals: BTreeMap<View, Vec<ProposalRecord<V, D>>>,
    messages: BTreeMap<View, BTreeMap<Participant, Vec<MessageRecord<V, D>>>>,
    message_locations: BTreeMap<ArtifactId<D>, (View, Participant, Observation)>,
    sticky_messages: BTreeMap<View, BTreeMap<Participant, MessageRecord<V, D>>>,
    nullify_shares: BTreeMap<View, BTreeMap<Participant, NullifyRecord<V, D>>>,
    nullifications: BTreeMap<View, Vec<NullificationRecord<V, D>>>,
    vqcs: BTreeMap<View, Vec<VqcRecord<V, D>>>,
    claims: BTreeMap<Claim, BTreeMap<ArtifactId<D>, Observation>>,
    claim_cohorts: BTreeMap<Claim, BTreeMap<u64, usize>>,
    message_claim_cohorts: BTreeMap<View, BTreeMap<u64, usize>>,
    nullify_claim_cohorts: BTreeMap<View, BTreeMap<u64, usize>>,
    slots: BTreeMap<View, ViewSlot<V, D>>,
    post_vote_evidence: BTreeMap<View, BTreeSet<Participant>>,
    timeout_cutoffs: BTreeMap<View, TimeoutCutoff<D>>,
    certificate_jobs: BTreeMap<ViewCertificateId, ViewCertificateJob<V, D>>,
    pending_nullifications: BTreeMap<View, Observation>,
    pending_vqcs: BTreeMap<View, Observation>,
    assembled_nullifications: BTreeSet<View>,
    assembled_vqcs: BTreeSet<VqcTranscript<D>>,
    forwarded_nullifications: BTreeSet<View>,
    forwarded_vqcs: BTreeMap<View, CertificateId<D>>,
    forwardable_nullifications: BTreeSet<View>,
    forwardable_vqcs: BTreeSet<View>,
    ready_certificate_views: BTreeSet<View>,
    certificate_scan: Option<CertificateScan<V, D>>,
    regular_sign_pass: Option<RegularSignPass<V, D>>,
    next_certificate: u64,
    capabilities: Vec<ViewEffect<V, D>>,
    /// Admitted L-QCs not yet consumed by the durable signing floor.
    ///
    /// This index owns each proof because finality evidence can outlive its general ready-artifact
    /// cache entry. The identifier remains in the key only to order same-view proofs
    /// deterministically.
    finality_proofs: FinalityProofs<V, D>,
}

#[derive(Clone, Debug)]
enum ViewCertificateJob<V: Variant, D: Digest> {
    Nullification {
        job: NullificationRecoveryJob<V>,
        observation: Observation,
    },
    Vqc {
        job: VqcAggregateJob<V, D>,
        observation: Observation,
    },
}

#[derive(Clone, Debug)]
enum TimeoutCutoff<D: Digest> {
    Vote(VoteRequest<D>),
    Timeout,
}

pub(crate) struct PreparedArtifact<V: Variant, D: Digest> {
    pub artifact: Arc<Artifact<V, D>>,
    pub observation: Observation,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct VqcTranscript<D: Digest> {
    view: View,
    target: D,
    messages: Vec<ArtifactId<D>>,
}

#[derive(Clone, Debug)]
struct VqcCandidate<D: Digest> {
    target: D,
    observation: Observation,
    transcript: VqcTranscript<D>,
}

#[derive(Clone, Debug)]
struct PreparedVqc<V: Variant, D: Digest> {
    candidate: VqcCandidate<D>,
    messages: Arc<[Arc<Artifact<V, D>>]>,
}

#[derive(Clone, Debug)]
struct PreparedNullification<V: Variant> {
    observation: Observation,
    shares: Arc<[Nullify<V>]>,
}

enum PreparedCertificate<V: Variant, D: Digest> {
    Vqc(PreparedVqc<V, D>),
    Nullification(PreparedNullification<V>),
}

#[derive(Clone, Debug)]
struct CertificateScan<V: Variant, D: Digest> {
    view: View,
    pending_messages: Option<u64>,
    pending_nullifies: Option<u64>,
    support: BTreeMap<D, usize>,
    best_vqc: Option<PreparedVqc<V, D>>,
    nullification: Option<PreparedNullification<V>>,
    phase: CertificateScanPhase<V, D>,
}

#[derive(Clone, Debug)]
enum CertificateScanPhase<V: Variant, D: Digest> {
    CountSupport {
        cursor: Option<Participant>,
    },
    FindTarget {
        cursor: Option<D>,
    },
    EvaluateTarget {
        target: D,
        cursor: Option<Participant>,
        eligible: usize,
        targets: usize,
        message_cohorts: BinaryHeap<u64>,
        target_cohorts: BinaryHeap<u64>,
    },
    SelectTarget {
        target: D,
        cohort: u64,
        limit: usize,
        cursor: Option<Participant>,
        eligible: usize,
        remaining_targets: usize,
        visited: usize,
        target_count: usize,
        observation: Option<Observation>,
        messages: Vec<Arc<Artifact<V, D>>>,
        ids: Vec<ArtifactId<D>>,
    },
    CountNullifications {
        cursor: Option<Participant>,
        cohorts: BinaryHeap<u64>,
    },
    SelectNullifications {
        cohort: u64,
        cursor: Option<Participant>,
        observation: Option<Observation>,
        shares: Vec<Nullify<V>>,
    },
    Complete,
}

impl<V: Variant, D: Digest> ViewState<V, D> {
    pub(crate) fn new<H: Hasher<Digest = D>>(profile: &Profile<H, V>) -> Self {
        let genesis = profile.protocol().genesis();
        let tips = Tips::new(genesis.tips().to_vec())
            .expect("validated genesis has one tip per canonical chain");
        let parent = ParentRecord {
            id: genesis.vqc(),
            view: View::zero(),
            history: genesis_history::<H>(genesis),
            canonical: Bytes::new(),
            certificate: None,
            tips,
            messages: 0,
        };
        Self {
            config: profile.protocol().codec_config(),
            retired_transitions: View::zero(),
            proposal_anchor_view: View::zero(),
            proposal_nullified_through: View::zero(),
            parents: BTreeMap::from([(genesis.vqc(), parent)]),
            parents_by_view: BTreeMap::from([(View::zero(), vec![genesis.vqc()])]),
            leaders: BTreeMap::new(),
            proposals: BTreeMap::new(),
            messages: BTreeMap::new(),
            message_locations: BTreeMap::new(),
            sticky_messages: BTreeMap::new(),
            nullify_shares: BTreeMap::new(),
            nullifications: BTreeMap::new(),
            vqcs: BTreeMap::new(),
            claims: BTreeMap::new(),
            claim_cohorts: BTreeMap::new(),
            message_claim_cohorts: BTreeMap::new(),
            nullify_claim_cohorts: BTreeMap::new(),
            slots: BTreeMap::new(),
            post_vote_evidence: BTreeMap::new(),
            timeout_cutoffs: BTreeMap::new(),
            certificate_jobs: BTreeMap::new(),
            pending_nullifications: BTreeMap::new(),
            pending_vqcs: BTreeMap::new(),
            assembled_nullifications: BTreeSet::new(),
            assembled_vqcs: BTreeSet::new(),
            forwarded_nullifications: BTreeSet::new(),
            forwarded_vqcs: BTreeMap::new(),
            forwardable_nullifications: BTreeSet::new(),
            forwardable_vqcs: BTreeSet::new(),
            ready_certificate_views: BTreeSet::new(),
            certificate_scan: None,
            regular_sign_pass: None,
            next_certificate: 0,
            capabilities: Vec::new(),
            finality_proofs: BTreeMap::new(),
        }
    }

    /// Applies E3 after Finality admits a full L-QC.
    pub(crate) fn observe_finality(
        &mut self,
        artifact_id: ArtifactId<D>,
        artifact: &Arc<Artifact<V, D>>,
    ) -> Result<bool, ViewError> {
        let Artifact::Lqc(certificate) = artifact.as_ref() else {
            return Err(ViewError::Certificate);
        };
        if self
            .finality_proofs
            .last_key_value()
            .is_some_and(|((view, _), _)| *view >= certificate.view())
        {
            return Ok(false);
        }
        self.finality_proofs.clear();
        self.finality_proofs
            .insert((certificate.view(), artifact_id), Arc::clone(artifact));
        Ok(true)
    }

    /// Returns the highest admitted L-QC above the durable signing floor.
    ///
    /// The candidate is deliberately independent of the current view: an L-QC whose
    /// aggregation completes after its view exits is still portable finality evidence, and the
    /// floor it raises retires the same signing authority whether or not it also advances the
    /// view. Requiring the candidate to cover the current view would make floor progress a
    /// race against the ordinary exit, which the aggregation loses whenever it is not inline.
    pub(crate) fn signing_floor_candidate(&self, floor: View) -> Option<Arc<Artifact<V, D>>> {
        self.finality_proofs
            .iter()
            .next_back()
            .and_then(|((view, _), proof)| (*view > floor).then(|| Arc::clone(proof)))
    }

    pub(crate) fn retire_finality_proofs_through(&mut self, floor: View) {
        while self
            .finality_proofs
            .first_key_value()
            .is_some_and(|((view, _), _)| *view <= floor)
        {
            self.finality_proofs.pop_first();
        }
    }

    #[cfg(test)]
    pub(crate) fn retained_finality_proofs(&self) -> usize {
        self.finality_proofs.len()
    }

    #[cfg(test)]
    pub(crate) fn retained_exit_proofs(&self) -> BTreeMap<View, ArtifactId<D>> {
        self.slots
            .iter()
            .filter_map(|(view, slot)| slot.exit.map(|proof| (*view, proof)))
            .collect()
    }

    fn slot_state(&self, view: View) -> ViewProductState {
        self.slots
            .get(&view)
            .map_or_else(ViewProductState::default, |slot| slot.state)
    }

    fn slot_mut(&mut self, view: View) -> &mut ViewSlot<V, D> {
        self.slots.entry(view).or_default()
    }

    pub(crate) fn retire_transitions_through(&mut self, floor: View) {
        if floor <= self.retired_transitions {
            return;
        }
        self.retired_transitions = floor;
        let retained = |view: &View| *view > floor;

        self.leaders.retain(|(view, _), _| retained(view));
        self.proposals.retain(|view, _| retained(view));
        self.messages.retain(|view, _| retained(view));
        self.message_locations
            .retain(|_, (view, _, _)| retained(view));
        self.sticky_messages.retain(|view, _| retained(view));
        self.nullify_shares.retain(|view, _| retained(view));
        self.nullifications.retain(|view, _| retained(view));
        self.vqcs.retain(|view, _| retained(view));
        self.claims
            .retain(|claim, _| retained(&claim.certificate_view()));
        self.claim_cohorts
            .retain(|claim, _| retained(&claim.certificate_view()));
        self.message_claim_cohorts.retain(|view, _| retained(view));
        self.nullify_claim_cohorts.retain(|view, _| retained(view));
        self.slots.retain(|view, _| retained(view));
        self.post_vote_evidence.retain(|view, _| retained(view));
        self.timeout_cutoffs.retain(|view, _| retained(view));
        self.certificate_jobs.retain(|_, job| match job {
            ViewCertificateJob::Nullification { job, .. } => job
                .shares()
                .first()
                .is_some_and(|share| retained(&share.view())),
            ViewCertificateJob::Vqc { job, .. } => retained(&job.leader().view()),
        });
        self.pending_nullifications.retain(|view, _| retained(view));
        self.pending_vqcs.retain(|view, _| retained(view));
        self.assembled_nullifications.retain(retained);
        self.assembled_vqcs
            .retain(|transcript| retained(&transcript.view));
        self.forwardable_nullifications.retain(retained);
        self.forwardable_vqcs.retain(retained);
        self.ready_certificate_views.retain(retained);
        if self
            .certificate_scan
            .as_ref()
            .is_some_and(|scan| !retained(&scan.view))
        {
            self.certificate_scan = None;
        }
        self.capabilities.retain(|effect| match effect {
            ViewEffect::RecoverNullification(job) => job
                .shares()
                .first()
                .is_some_and(|share| retained(&share.view())),
            ViewEffect::AggregateVqc(job) => retained(&job.leader().view()),
        });
    }

    /// Drops the first-forwarding facts for views the machine no longer retains.
    ///
    /// Nothing below the floor can be forwarded again: its candidates and messages are already
    /// retired, so the fact has no rule left to enforce.
    pub(crate) fn retire_forwarded_through(&mut self, floor: View) {
        self.forwarded_vqcs.retain(|view, _| *view > floor);
        self.forwarded_nullifications.retain(|view| *view > floor);
    }

    pub(crate) fn retire_parents_through(
        &mut self,
        floor: View,
        anchor: Option<CertificateId<D>>,
    ) -> Vec<CertificateId<D>> {
        let removed = self
            .parents
            .iter()
            .filter_map(|(id, parent)| {
                (!parent.view.is_zero() && parent.view < floor && Some(*id) != anchor)
                    .then_some(*id)
            })
            .collect::<Vec<_>>();
        self.parents.retain(|id, parent| {
            parent.view.is_zero() || parent.view >= floor || Some(*id) == anchor
        });
        let parents = &self.parents;
        self.parents_by_view.retain(|view, ids| {
            ids.retain(|id| parents.contains_key(id));
            view.is_zero() || *view >= floor || !ids.is_empty()
        });
        removed
    }

    pub(crate) const fn restore_proposal_frontier(
        &mut self,
        anchor: View,
        nullified_through: View,
    ) {
        self.proposal_anchor_view = anchor;
        self.proposal_nullified_through = nullified_through;
    }

    pub(crate) fn restore_snapshot(&mut self, snapshot: &ViewSnapshot<V, D>) {
        self.slots = snapshot
            .slots
            .iter()
            .map(|(view, saved)| {
                let transition = match saved.transition {
                    ViewTransition::Active => TransitionState::Active,
                    ViewTransition::Exited(_) => TransitionState::Exited,
                };
                let stance = match &saved.stance {
                    ViewStance::Unchosen => StanceState::Unchosen,
                    ViewStance::Voted(_) => StanceState::Voted,
                    ViewStance::NoVoted => StanceState::NoVoted,
                };
                let nullification = match saved.nullification {
                    ViewNullification::Unsigned => NullificationState::Unsigned,
                    ViewNullification::Signed => NullificationState::Signed,
                };
                let exit = match saved.transition {
                    ViewTransition::Active => None,
                    ViewTransition::Exited(proof) => Some(proof),
                };
                let slot = ViewSlot {
                    state: ViewProductState {
                        transition,
                        stance,
                        nullification,
                        proposed: saved.proposal.is_some(),
                    },
                    proposal: saved.proposal.clone(),
                    vote: match &saved.stance {
                        ViewStance::Voted(body) => Some(body.clone()),
                        ViewStance::Unchosen | ViewStance::NoVoted => None,
                    },
                    exit,
                };
                (*view, slot)
            })
            .collect();
    }

    /// Records the exact proof whose durable transition exited `view`.
    pub(crate) fn observe_exit(&mut self, view: View, proof: ArtifactId<D>) {
        self.slot_mut(view).observe_exit(proof);
    }

    fn vqc_forwarded(&self, view: View) -> bool {
        self.forwarded_vqcs.contains_key(&view)
    }

    fn nullification_forwarded(&self, view: View) -> bool {
        self.forwarded_nullifications.contains(&view)
    }

    pub(crate) fn claim(
        &mut self,
        id: ArtifactId<D>,
        observation: Observation,
        artifact: &Artifact<V, D>,
    ) {
        let Some(claim) = Self::claim_for(artifact) else {
            return;
        };
        let previous = self
            .claims
            .entry(claim)
            .or_default()
            .insert(id, observation);
        if let Some(previous) = previous {
            self.remove_claim_cohort(claim, previous.cohort());
        }
        self.insert_claim_cohort(claim, observation.cohort());
        {
            let view = claim.certificate_view();
            self.refresh_view(view);
        }
    }

    pub(crate) fn reject(&mut self, id: ArtifactId<D>, artifact: &Artifact<V, D>) {
        let Some(claim) = Self::claim_for(artifact) else {
            return;
        };
        self.remove_claim(claim, id);
        if let Claim::ViewMessage(view, participant) = claim {
            self.remove_message(id, view, participant);
            self.settle_message(view, participant);
            if self.slot_state(view).has_voted() {
                self.rebuild_post_vote_evidence(view);
            }
        }
        {
            let view = claim.certificate_view();
            self.refresh_view(view);
        }
    }

    pub(crate) fn observe<H: Hasher<Digest = D>>(
        &mut self,
        id: ArtifactId<D>,
        observation: Observation,
        artifact: &Arc<Artifact<V, D>>,
        profile: &Profile<H, V>,
    ) -> Result<(), ViewError> {
        let certificate_view = Self::claim_for(artifact).map(Claim::certificate_view);
        if let Some(claim) = Self::claim_for(artifact) {
            self.remove_claim(claim, id);
        }
        if artifact
            .view()
            .is_some_and(|view| view <= self.retired_transitions)
        {
            match artifact.as_ref() {
                Artifact::Vqc(certificate) => {
                    self.observe_vqc::<H>(id, observation, artifact, profile)?;
                    self.refresh_view(certificate.view());
                    return Ok(());
                }
                Artifact::Nullification(certificate)
                    if !self.nullification_forwarded(certificate.view()) =>
                {
                    self.observe_nullification(id, observation, Arc::clone(artifact));
                    self.refresh_view(certificate.view());
                    return Ok(());
                }
                Artifact::Nullification(_) => return Ok(()),
                _ if artifact
                    .view()
                    .is_some_and(|view| view < self.retired_transitions) =>
                {
                    return Ok(());
                }
                _ => {}
            }
        }
        match artifact.as_ref() {
            Artifact::LeaderBlock(_) => {
                self.observe_proposal::<H>(observation, artifact)?;
            }
            Artifact::Vote(vote) => {
                self.observe_message(id, observation, Arc::clone(artifact));
                self.settle_message(vote.view(), vote.signer());
            }
            Artifact::NoVote(novote) => {
                self.observe_message(id, observation, Arc::clone(artifact));
                self.settle_message(novote.view(), novote.signer());
            }
            Artifact::Nullify(_) => {
                self.observe_nullify(observation, Arc::clone(artifact));
            }
            Artifact::Nullification(_) => {
                self.observe_nullification(id, observation, Arc::clone(artifact));
            }
            Artifact::Vqc(_) => {
                self.observe_vqc::<H>(id, observation, artifact, profile)?;
            }
            Artifact::TransactionBlock(_)
            | Artifact::DaVote(_)
            | Artifact::DaCertificate(_)
            | Artifact::Lqc(_) => {}
        }
        if let Some(view) = certificate_view {
            self.refresh_view(view);
        }
        Ok(())
    }

    pub(crate) fn observe_sign_request(
        &mut self,
        request: &SignRequest<V, D>,
    ) -> Result<(), ViewError> {
        match request {
            SignRequest::LeaderBlock(request) => {
                self.observe_local_proposal(request.block().clone())
            }
            SignRequest::Vote(request) => self.observe_local_vote(request.body().clone()),
            SignRequest::NoVote { round, .. } => self.observe_local_novote(round.view()),
            SignRequest::Nullify { round, .. } => {
                self.slot_mut(round.view()).observe_nullify();
                Ok(())
            }
            SignRequest::TransactionBlock(_) | SignRequest::DaVote(_) => Ok(()),
        }
    }

    pub(crate) fn observe_durable_artifact(
        &mut self,
        artifact: &Artifact<V, D>,
        role: Role,
    ) -> Result<(), ViewError> {
        match artifact {
            Artifact::LeaderBlock(block) if role == Role::Validator(block.signer()) => {
                self.observe_local_proposal(block.block().clone())
            }
            Artifact::Vote(vote) if role == Role::Validator(vote.signer()) => {
                self.observe_local_vote(vote.body().clone())
            }
            Artifact::NoVote(vote) if role == Role::Validator(vote.signer()) => {
                self.observe_local_novote(vote.view())
            }
            Artifact::Nullify(share) if role == Role::Validator(share.signer()) => {
                self.slot_mut(share.view()).observe_nullify();
                Ok(())
            }
            Artifact::Nullification(certificate) => {
                self.assembled_nullifications.insert(certificate.view());
                self.refresh_view(certificate.view());
                Ok(())
            }
            Artifact::Vqc(certificate) => {
                self.refresh_view(certificate.view());
                Ok(())
            }
            _ => Ok(()),
        }
    }

    pub(crate) fn observe_forwarded<H: Hasher<Digest = D>>(&mut self, artifact: &Artifact<V, D>) {
        let view = match artifact {
            Artifact::Vqc(certificate) => {
                self.forwarded_vqcs
                    .insert(certificate.view(), certificate.id::<H>());
                if certificate.view() <= self.retired_transitions {
                    self.vqcs.remove(&certificate.view());
                    self.forwardable_vqcs.remove(&certificate.view());
                }
                certificate.view()
            }
            Artifact::Nullification(certificate) => {
                self.forwarded_nullifications.insert(certificate.view());
                if certificate.view() <= self.retired_transitions {
                    self.nullifications.remove(&certificate.view());
                    self.forwardable_nullifications.remove(&certificate.view());
                }
                certificate.view()
            }
            _ => return,
        };
        self.refresh_view(view);
    }

    pub(crate) fn drive_regular_sign_request<H: Hasher<Digest = D>>(
        &mut self,
        profile: &Profile<H, V>,
        view: View,
        chain: &ChainState<V, D>,
        budget: usize,
    ) -> Result<RegularSignDrive<V, D>, ViewError> {
        if !matches!(profile.role(), Role::Validator(_)) || !self.slot_state(view).can_vote() {
            self.regular_sign_pass = None;
            return Ok(RegularSignDrive {
                processed: 0,
                complete: true,
                request: None,
            });
        }
        let stale = self
            .regular_sign_pass
            .as_ref()
            .is_some_and(|pass| match pass {
                RegularSignPass::Vote { view: pass, .. }
                | RegularSignPass::Proposal { view: pass, .. } => *pass != view,
            });
        if stale {
            self.regular_sign_pass = None;
        }
        if self.regular_sign_pass.is_none() {
            self.regular_sign_pass = self.begin_regular_sign_pass::<H>(profile, view, chain)?;
        }
        if self.regular_sign_pass.is_none() {
            return Ok(RegularSignDrive {
                processed: 0,
                complete: true,
                request: None,
            });
        }

        let mut processed = 0;
        while processed < budget {
            processed += 1;
            let progress = match self
                .regular_sign_pass
                .as_mut()
                .expect("the regular signing pass was initialized")
            {
                RegularSignPass::Vote { pass, .. } => {
                    match chain
                        .resume_vote_body_pass::<H>(profile, pass)
                        .map_err(|_| ViewError::Chain)?
                    {
                        VoteBodyProgress::Pending => None,
                        VoteBodyProgress::Complete(body) => {
                            Some(SignRequest::Vote(VoteRequest::new(body)))
                        }
                    }
                }
                RegularSignPass::Proposal {
                    view,
                    parent,
                    attach_parent,
                    next_chain,
                    current,
                    proposals,
                } => {
                    if current.is_none() {
                        if let Some(tip) = parent.tips.blocks().get(*next_chain).copied() {
                            *current = Some(
                                chain
                                    .begin_proposal_pass::<H>(profile, tip)
                                    .map_err(|_| ViewError::Chain)?,
                            );
                            None
                        } else {
                            Some(Self::finish_proposal_request::<H>(
                                profile,
                                *view,
                                parent,
                                *attach_parent,
                                proposals,
                            )?)
                        }
                    } else {
                        match chain
                            .resume_proposal_pass::<H>(
                                current
                                    .as_mut()
                                    .expect("the current proposal pass was checked above"),
                            )
                            .map_err(|_| ViewError::Chain)?
                        {
                            ChainProposalProgress::Pending => None,
                            ChainProposalProgress::Complete(proposal) => {
                                proposals.push(proposal);
                                *next_chain += 1;
                                *current = None;
                                None
                            }
                        }
                    }
                }
            };
            if let Some(request) = progress {
                self.regular_sign_pass = None;
                return Ok(RegularSignDrive {
                    processed,
                    complete: true,
                    request: Some(request),
                });
            }
        }

        Ok(RegularSignDrive {
            processed,
            complete: false,
            request: None,
        })
    }

    fn begin_regular_sign_pass<H: Hasher<Digest = D>>(
        &self,
        profile: &Profile<H, V>,
        view: View,
        chain: &ChainState<V, D>,
    ) -> Result<Option<RegularSignPass<V, D>>, ViewError> {
        let Role::Validator(me) = profile.role() else {
            return Ok(None);
        };
        if let Some(proposal) = self.valid_proposal::<H>(profile, view)? {
            let leader = proposal.block().clone();
            let pass = chain.begin_vote_body_pass(profile, leader);
            return Ok(Some(RegularSignPass::Vote { view, pass }));
        }

        let leader = profile.protocol().leader(view);
        if me != leader
            || self
                .slots
                .get(&view)
                .is_some_and(|slot| slot.proposal.is_some())
        {
            return Ok(None);
        }
        let parent = self
            .select_anchor(view)
            .cloned()
            .ok_or(ViewError::MissingParent)?;
        if !self.gap_is_nullified(parent.view, view) {
            return Ok(None);
        }
        let attach_parent = parent.certificate.is_some()
            && self.forwarded_vqcs.get(&parent.view) != Some(&parent.id);
        Ok(Some(RegularSignPass::Proposal {
            view,
            parent,
            attach_parent,
            next_chain: 0,
            current: None,
            proposals: Vec::with_capacity(self.config.chains()),
        }))
    }

    fn finish_proposal_request<H: Hasher<Digest = D>>(
        profile: &Profile<H, V>,
        view: View,
        parent: &ParentRecord<V, D>,
        attach_parent: bool,
        proposals: &[crate::multimmit::types::ChainProposal<V, D>],
    ) -> Result<SignRequest<V, D>, ViewError> {
        let parent_proof = match parent.certificate.as_deref() {
            None if parent.id == profile.protocol().genesis().vqc()
                && parent.view == View::zero() =>
            {
                ProposalParent::Genesis
            }
            None => unreachable!("only the genesis anchor lacks a V-QC"),
            Some(Artifact::Vqc(certificate)) => {
                ProposalParent::Exact(Arc::new(certificate.clone()))
            }
            Some(_) => unreachable!("non-genesis parent records contain V-QCs"),
        };
        let block = LeaderBlock::new(
            Round::new(profile.protocol().epoch(), view),
            parent.id,
            TipRecord::new(parent.history, parent.tips.blocks().to_vec())
                .map_err(|_| ViewError::Proposal)?
                .commitment::<H>(),
            proposals.to_vec(),
            profile.protocol().codec_config(),
        )
        .map_err(|_| ViewError::Proposal)?;
        Ok(SignRequest::LeaderBlock(ProposalRequest::new(
            block,
            parent_proof,
            attach_parent,
        )))
    }

    pub(crate) fn timeout_requests<H: Hasher<Digest = D>>(
        &self,
        profile: &Profile<H, V>,
        view: View,
    ) -> Option<Arc<[SignRequest<V, D>]>> {
        let Role::Validator(_) = profile.role() else {
            return None;
        };
        if !matches!(
            self.timeout_cutoffs.get(&view),
            Some(TimeoutCutoff::Timeout)
        ) || !self.slot_state(view).can_vote()
        {
            return None;
        }
        let round = Round::new(profile.protocol().epoch(), view);
        Some(Arc::from([
            SignRequest::NoVote { round },
            SignRequest::Nullify { round },
        ]))
    }

    pub(crate) fn cutoff_vote(&self, view: View) -> Option<SignRequest<V, D>> {
        if !self.slot_state(view).can_vote() {
            return None;
        }
        let TimeoutCutoff::Vote(request) = self.timeout_cutoffs.get(&view)? else {
            return None;
        };
        Some(SignRequest::Vote(request.clone()))
    }

    pub(crate) fn exit<H: Hasher<Digest = D>>(
        &self,
        profile: &Profile<H, V>,
        view: View,
        proof: Arc<Artifact<V, D>>,
    ) -> Option<Exit<V, D>> {
        if proof.view() != Some(view) {
            return None;
        }
        let rescue = match (profile.role(), proof.as_ref()) {
            (Role::Validator(_), Artifact::Vqc(certificate))
                if self.slot_state(view).can_vote() =>
            {
                Some(certificate.leader().clone())
            }
            _ => None,
        };
        Some(Exit { proof, rescue })
    }

    pub(crate) fn rescue_vote<H: Hasher<Digest = D>>(
        &self,
        profile: &Profile<H, V>,
        chain: &ChainState<V, D>,
        leader: &LeaderBlock<V, D>,
    ) -> Result<SignRequest<V, D>, ViewError> {
        chain
            .vote_body::<H>(profile, leader)
            .map(VoteRequest::new)
            .map(SignRequest::Vote)
            .map_err(|_| ViewError::Chain)
    }

    pub(crate) fn post_vote_nullify<H: Hasher<Digest = D>>(
        &self,
        profile: &Profile<H, V>,
        view: View,
    ) -> Option<SignRequest<V, D>> {
        let Role::Validator(_) = profile.role() else {
            return None;
        };
        if !self.slot_state(view).has_voted() || self.slot_state(view).nullified() {
            return None;
        }
        if self.post_vote_evidence.get(&view).map_or(0, BTreeSet::len)
            < profile.protocol().codec_config().designation_quorum()
        {
            return None;
        }
        Some(SignRequest::Nullify {
            round: Round::new(profile.protocol().epoch(), view),
        })
    }

    pub(crate) fn fire_timer<H: Hasher<Digest = D>>(
        &mut self,
        profile: &Profile<H, V>,
        view: View,
        chain: &ChainState<V, D>,
    ) -> Result<(), ViewError> {
        if self.timeout_cutoffs.contains_key(&view) || !self.slot_state(view).can_vote() {
            return Ok(());
        }
        let cutoff = match (profile.role(), self.valid_proposal::<H>(profile, view)?) {
            (Role::Validator(_), Some(proposal)) if self.slot_state(view).can_vote() => {
                let SignRequest::Vote(request) =
                    self.vote_request::<H>(profile, chain, proposal.block())?
                else {
                    unreachable!("vote request helper returns a vote")
                };
                TimeoutCutoff::Vote(request)
            }
            _ => TimeoutCutoff::Timeout,
        };
        self.timeout_cutoffs.insert(view, cutoff);
        Ok(())
    }

    pub(crate) fn next_forward(&self) -> Option<Arc<Artifact<V, D>>> {
        let vqc = self.forwardable_vqcs.first().and_then(|view| {
            self.forward_vqc(self.config, *view, !self.nullification_forwarded(*view))
        });
        let nullification = self.forwardable_nullifications.first().and_then(|view| {
            self.forward_nullification(self.config, *view, !self.vqc_forwarded(*view))
        });
        match (vqc, nullification) {
            (Some((left_observation, left)), Some((right_observation, right))) => {
                Some(if left_observation.cohort() <= right_observation.cohort() {
                    left
                } else {
                    right
                })
            }
            (Some((_, artifact)), None) | (None, Some((_, artifact))) => Some(artifact),
            (None, None) => None,
        }
    }

    pub(crate) fn drive_certificates<H: Hasher<Digest = D>>(
        &mut self,
        profile: &Profile<H, V>,
        generation: u64,
        current: View,
        slots: usize,
        budget: usize,
    ) -> Result<CertificateDrive, ViewError> {
        self.drive_view_certificates(profile, generation, current, slots, budget)
    }

    pub(crate) fn deferred_certificate_view(&self, current: View) -> Option<View> {
        self.ready_certificate_views
            .iter()
            .copied()
            .find(|view| *view != current)
    }

    pub(crate) fn drive_deferred_certificate<H: Hasher<Digest = D>>(
        &mut self,
        profile: &Profile<H, V>,
        generation: u64,
        view: View,
        slots: usize,
        budget: usize,
    ) -> Result<CertificateDrive, ViewError> {
        self.drive_view_certificates(profile, generation, view, slots, budget)
    }

    fn drive_view_certificates<H: Hasher<Digest = D>>(
        &mut self,
        profile: &Profile<H, V>,
        generation: u64,
        view: View,
        slots: usize,
        budget: usize,
    ) -> Result<CertificateDrive, ViewError> {
        if slots == 0 || budget == 0 {
            return Ok(CertificateDrive {
                processed: 0,
                complete: slots == 0,
            });
        }
        if self
            .certificate_scan
            .as_ref()
            .is_some_and(|scan| scan.view != view)
        {
            self.certificate_scan = None;
        }
        let mut scan = self
            .certificate_scan
            .take()
            .unwrap_or_else(|| self.start_certificate_scan(view));
        let mut processed = 0;
        while processed < budget && !matches!(scan.phase, CertificateScanPhase::Complete) {
            processed += usize::from(self.advance_certificate_scan(&mut scan));
        }
        if !matches!(scan.phase, CertificateScanPhase::Complete) {
            self.certificate_scan = Some(scan);
            return Ok(CertificateDrive {
                processed,
                complete: false,
            });
        }

        self.finish_certificate_scan::<H>(profile, generation, scan)?;
        Ok(CertificateDrive {
            processed,
            complete: true,
        })
    }

    fn start_certificate_scan(&self, view: View) -> CertificateScan<V, D> {
        CertificateScan {
            view,
            pending_messages: self
                .message_claim_cohorts
                .get(&view)
                .and_then(BTreeMap::first_key_value)
                .map(|(cohort, _)| *cohort),
            pending_nullifies: self
                .nullify_claim_cohorts
                .get(&view)
                .and_then(BTreeMap::first_key_value)
                .map(|(cohort, _)| *cohort),
            support: BTreeMap::new(),
            best_vqc: None,
            nullification: None,
            phase: CertificateScanPhase::CountSupport { cursor: None },
        }
    }

    /// Advances exactly one retained participant or target boundary.
    fn advance_certificate_scan(&self, scan: &mut CertificateScan<V, D>) -> bool {
        let phase = core::mem::replace(&mut scan.phase, CertificateScanPhase::Complete);
        scan.phase = match phase {
            CertificateScanPhase::CountSupport { cursor } => {
                let Some((participant, record)) = self.next_sticky_message(scan.view, cursor)
                else {
                    return {
                        scan.phase = CertificateScanPhase::FindTarget { cursor: None };
                        false
                    };
                };
                if scan
                    .pending_messages
                    .is_none_or(|pending| record.observation.cohort() < pending)
                    && let MessageRef::Vote(vote) = record.message()
                {
                    *scan.support.entry(vote.body().leader()).or_default() += 1;
                }
                CertificateScanPhase::CountSupport {
                    cursor: Some(participant),
                }
            }
            CertificateScanPhase::FindTarget { cursor } => {
                let Some((target, support)) = next_map_entry(&scan.support, cursor) else {
                    return {
                        scan.phase = CertificateScanPhase::CountNullifications {
                            cursor: None,
                            cohorts: BinaryHeap::new(),
                        };
                        false
                    };
                };
                let usable = *support >= self.config.designation_quorum()
                    && self
                        .leaders
                        .get(&(scan.view, target))
                        .is_some_and(LeaderRecord::retain_transition);
                if usable {
                    CertificateScanPhase::EvaluateTarget {
                        target,
                        cursor: None,
                        eligible: 0,
                        targets: 0,
                        message_cohorts: BinaryHeap::new(),
                        target_cohorts: BinaryHeap::new(),
                    }
                } else {
                    CertificateScanPhase::FindTarget {
                        cursor: Some(target),
                    }
                }
            }
            CertificateScanPhase::EvaluateTarget {
                target,
                cursor,
                mut eligible,
                mut targets,
                mut message_cohorts,
                mut target_cohorts,
            } => {
                let Some((participant, record)) = self.next_sticky_message(scan.view, cursor)
                else {
                    if eligible < self.config.view_quorum()
                        || targets < self.config.designation_quorum()
                    {
                        return {
                            scan.phase = CertificateScanPhase::FindTarget {
                                cursor: Some(target),
                            };
                            false
                        };
                    }
                    let cohort = *message_cohorts
                        .peek()
                        .expect("a quorum fills the message cohort heap")
                        .max(
                            target_cohorts
                                .peek()
                                .expect("a designation quorum fills the target cohort heap"),
                        )
                        .max(&self.leaders[&(scan.view, target)].observation().cohort());
                    let limit = if self.longest_assembled_vqc(scan.view, target).is_some() {
                        eligible
                    } else {
                        self.config.view_quorum()
                    };
                    return {
                        scan.phase = CertificateScanPhase::SelectTarget {
                            target,
                            cohort: if limit == eligible { u64::MAX } else { cohort },
                            limit,
                            cursor: None,
                            eligible,
                            remaining_targets: targets,
                            visited: 0,
                            target_count: 0,
                            observation: Some(self.leaders[&(scan.view, target)].observation()),
                            messages: Vec::with_capacity(limit),
                            ids: Vec::with_capacity(limit),
                        };
                        false
                    };
                };
                if scan
                    .pending_messages
                    .is_none_or(|pending| record.observation.cohort() < pending)
                    && let Some(kind) =
                        record.vqc_eligibility(target, self.leaders[&(scan.view, target)].block())
                {
                    eligible += 1;
                    retain_smallest(
                        &mut message_cohorts,
                        record.observation.cohort(),
                        self.config.view_quorum(),
                    );
                    if matches!(kind, VqcEligibility::Target) {
                        targets += 1;
                        retain_smallest(
                            &mut target_cohorts,
                            record.observation.cohort(),
                            self.config.designation_quorum(),
                        );
                    }
                }
                CertificateScanPhase::EvaluateTarget {
                    target,
                    cursor: Some(participant),
                    eligible,
                    targets,
                    message_cohorts,
                    target_cohorts,
                }
            }
            CertificateScanPhase::SelectTarget {
                target,
                cohort,
                limit,
                cursor,
                eligible,
                mut remaining_targets,
                mut visited,
                mut target_count,
                mut observation,
                mut messages,
                mut ids,
            } => {
                let next = (messages.len() < limit)
                    .then(|| self.next_sticky_message(scan.view, cursor))
                    .flatten();
                let Some((participant, record)) = next else {
                    if messages.len() == limit && target_count >= self.config.designation_quorum() {
                        let observation = observation.expect("leader supplies an observation");
                        let candidate = VqcCandidate {
                            target,
                            observation,
                            transcript: VqcTranscript {
                                view: scan.view,
                                target,
                                messages: ids,
                            },
                        };
                        let prepared = PreparedVqc {
                            candidate,
                            messages: messages.into(),
                        };
                        if self.vqc_transcript_is_new(&prepared.candidate.transcript)
                            && scan.best_vqc.as_ref().is_none_or(|best| {
                                (prepared.candidate.observation, prepared.candidate.target)
                                    < (best.candidate.observation, best.candidate.target)
                            })
                        {
                            scan.best_vqc = Some(prepared);
                        }
                    }
                    return {
                        scan.phase = CertificateScanPhase::FindTarget {
                            cursor: Some(target),
                        };
                        false
                    };
                };
                let kind = (record.observation.cohort() <= cohort
                    && scan
                        .pending_messages
                        .is_none_or(|pending| record.observation.cohort() < pending))
                .then(|| record.vqc_eligibility(target, self.leaders[&(scan.view, target)].block()))
                .flatten();
                if let Some(kind) = kind {
                    let is_target = matches!(kind, VqcEligibility::Target);
                    remaining_targets -= usize::from(is_target);
                    let slots_after = limit - messages.len() - 1;
                    let enough_entries = eligible - visited > slots_after;
                    let enough_targets =
                        target_count + usize::from(is_target) + remaining_targets.min(slots_after)
                            >= self.config.designation_quorum();
                    if messages.len() < limit && enough_entries && enough_targets {
                        messages.push(Arc::clone(&record.artifact));
                        ids.push(record.id);
                        target_count += usize::from(is_target);
                        observation = Some(observation.map_or(record.observation, |current| {
                            current.max(record.observation)
                        }));
                    }
                    visited += 1;
                }
                CertificateScanPhase::SelectTarget {
                    target,
                    cohort,
                    limit,
                    cursor: Some(participant),
                    eligible,
                    remaining_targets,
                    visited,
                    target_count,
                    observation,
                    messages,
                    ids,
                }
            }
            CertificateScanPhase::CountNullifications {
                cursor,
                mut cohorts,
            } => {
                let Some((participant, record)) = self.next_nullify(scan.view, cursor) else {
                    scan.phase = if cohorts.len() < self.config.nullification_quorum() {
                        CertificateScanPhase::Complete
                    } else {
                        CertificateScanPhase::SelectNullifications {
                            cohort: *cohorts
                                .peek()
                                .expect("a quorum fills the nullification heap"),
                            cursor: None,
                            observation: None,
                            shares: Vec::with_capacity(self.config.nullification_quorum()),
                        }
                    };
                    return false;
                };
                if scan
                    .pending_nullifies
                    .is_none_or(|pending| record.observation.cohort() < pending)
                {
                    retain_smallest(
                        &mut cohorts,
                        record.observation.cohort(),
                        self.config.nullification_quorum(),
                    );
                }
                CertificateScanPhase::CountNullifications {
                    cursor: Some(participant),
                    cohorts,
                }
            }
            CertificateScanPhase::SelectNullifications {
                cohort,
                cursor,
                mut observation,
                mut shares,
            } => {
                let Some((participant, record)) = self.next_nullify(scan.view, cursor) else {
                    if shares.len() == self.config.nullification_quorum() {
                        scan.nullification = Some(PreparedNullification {
                            observation: observation.expect("selected shares have an observation"),
                            shares: shares.into(),
                        });
                    }
                    return {
                        scan.phase = CertificateScanPhase::Complete;
                        false
                    };
                };
                if shares.len() < self.config.nullification_quorum()
                    && record.observation.cohort() <= cohort
                    && scan
                        .pending_nullifies
                        .is_none_or(|pending| record.observation.cohort() < pending)
                {
                    shares.push(record.share().clone());
                    observation = Some(observation.map_or(record.observation, |current| {
                        current.max(record.observation)
                    }));
                }
                CertificateScanPhase::SelectNullifications {
                    cohort,
                    cursor: Some(participant),
                    observation,
                    shares,
                }
            }
            CertificateScanPhase::Complete => CertificateScanPhase::Complete,
        };
        true
    }

    fn next_sticky_message(
        &self,
        view: View,
        cursor: Option<Participant>,
    ) -> Option<(Participant, &MessageRecord<V, D>)> {
        let messages = self.sticky_messages.get(&view)?;
        cursor.map_or_else(
            || {
                messages
                    .first_key_value()
                    .map(|(participant, record)| (*participant, record))
            },
            |cursor| {
                messages
                    .range((Excluded(cursor), Unbounded))
                    .next()
                    .map(|(participant, record)| (*participant, record))
            },
        )
    }

    fn next_nullify(
        &self,
        view: View,
        cursor: Option<Participant>,
    ) -> Option<(Participant, &NullifyRecord<V, D>)> {
        let shares = self.nullify_shares.get(&view)?;
        cursor.map_or_else(
            || {
                shares
                    .first_key_value()
                    .map(|(participant, record)| (*participant, record))
            },
            |cursor| {
                shares
                    .range((Excluded(cursor), Unbounded))
                    .next()
                    .map(|(participant, record)| (*participant, record))
            },
        )
    }

    fn finish_certificate_scan<H: Hasher<Digest = D>>(
        &mut self,
        profile: &Profile<H, V>,
        generation: u64,
        scan: CertificateScan<V, D>,
    ) -> Result<(), ViewError> {
        let view = scan.view;
        let vqc_forwarded = self.vqc_forwarded(view);
        let nullification_forwarded = self.nullification_forwarded(view);
        let unresolved = self.unresolved_exit_key(view, vqc_forwarded, nullification_forwarded);
        let held = self.held_exit_key(view, vqc_forwarded, nullification_forwarded);
        let allowed = |key: (u64, u8)| {
            unresolved.is_none_or(|unresolved| key < unresolved)
                && held.is_none_or(|held| key <= held)
        };

        let vqc = scan.best_vqc.filter(|prepared| {
            !self.pending_vqcs.contains_key(&view)
                && allowed((prepared.candidate.observation.cohort(), 0))
        });
        let nullification = scan.nullification.filter(|prepared| {
            !nullification_forwarded
                && !self.pending_nullifications.contains_key(&view)
                && !self.assembled_nullifications.contains(&view)
                && !self
                    .nullifications
                    .get(&view)
                    .and_then(|records| records.first())
                    .is_some_and(|record| {
                        record.observation.cohort() < prepared.observation.cohort()
                    })
                && allowed((prepared.observation.cohort(), 1))
        });
        let prepared = match (vqc, nullification) {
            (Some(vqc), Some(nullification)) => {
                if (vqc.candidate.observation.cohort(), 0)
                    <= (nullification.observation.cohort(), 1)
                {
                    Some(PreparedCertificate::Vqc(vqc))
                } else {
                    Some(PreparedCertificate::Nullification(nullification))
                }
            }
            (Some(vqc), None) => Some(PreparedCertificate::Vqc(vqc)),
            (None, Some(nullification)) => Some(PreparedCertificate::Nullification(nullification)),
            (None, None) => None,
        };
        let mut rescan = false;

        match prepared {
            Some(PreparedCertificate::Vqc(prepared)) => {
                let candidate = prepared.candidate;
                let leader = self.leaders[&(view, candidate.target)].block().clone();
                let exit_covered = vqc_forwarded || nullification_forwarded;
                let config = profile.protocol().codec_config();
                let valid = validate_vqc_votes::<H, V, D>(
                    &leader,
                    prepared.messages.iter().filter_map(|artifact| {
                        let Artifact::Vote(vote) = artifact.as_ref() else {
                            return None;
                        };
                        (vote.body().leader() == candidate.target)
                            .then_some((vote.signer(), vote.body()))
                    }),
                    config,
                )
                .is_ok();
                let materialized =
                    self.vqc_transcript_materialized::<H>(&leader, &prepared.messages, config);
                if !valid || exit_covered && materialized {
                    self.assembled_vqcs.insert(candidate.transcript);
                    rescan = materialized;
                } else {
                    let id = self.next_certificate_id()?;
                    let job = VqcAggregateJob {
                        id,
                        generation,
                        leader,
                        messages: prepared.messages,
                        transcript: candidate.transcript,
                    };
                    self.certificate_jobs.insert(
                        id,
                        ViewCertificateJob::Vqc {
                            job: job.clone(),
                            observation: candidate.observation,
                        },
                    );
                    self.pending_vqcs.insert(view, candidate.observation);
                    self.capabilities.push(ViewEffect::AggregateVqc(job));
                }
            }
            Some(PreparedCertificate::Nullification(prepared)) => {
                let id = self.next_certificate_id()?;
                let job = NullificationRecoveryJob {
                    id,
                    generation,
                    shares: prepared.shares,
                };
                self.certificate_jobs.insert(
                    id,
                    ViewCertificateJob::Nullification {
                        job: job.clone(),
                        observation: prepared.observation,
                    },
                );
                self.pending_nullifications
                    .insert(view, prepared.observation);
                self.capabilities
                    .push(ViewEffect::RecoverNullification(job));
            }
            None => {}
        }
        self.ready_certificate_views.remove(&view);
        if rescan {
            self.refresh_view(view);
        }
        Ok(())
    }

    fn refresh_view(&mut self, view: View) {
        if self
            .certificate_scan
            .as_ref()
            .is_some_and(|scan| scan.view == view)
        {
            self.certificate_scan = None;
        }
        let messages = self.sticky_messages.get(&view).map_or(0, BTreeMap::len);
        let nullifies = self.nullify_shares.get(&view).map_or(0, BTreeMap::len);
        if messages >= self.config.view_quorum() || nullifies >= self.config.nullification_quorum()
        {
            self.ready_certificate_views.insert(view);
        } else {
            self.ready_certificate_views.remove(&view);
        }

        // First forwarding is a per-view rule, and a retired view no longer keeps the fact that
        // enforces it. A certificate resolved for such a view is finality input only.
        let live = view > self.retired_transitions;
        let vqc = live
            && !self.vqc_forwarded(view)
            && self
                .forward_vqc(self.config, view, !self.nullification_forwarded(view))
                .is_some();
        if vqc {
            self.forwardable_vqcs.insert(view);
        } else {
            self.forwardable_vqcs.remove(&view);
        }

        let nullification = live
            && !self.nullification_forwarded(view)
            && self
                .forward_nullification(self.config, view, !self.vqc_forwarded(view))
                .is_some();
        if nullification {
            self.forwardable_nullifications.insert(view);
        } else {
            self.forwardable_nullifications.remove(&view);
        }
    }

    pub(crate) fn take_effects(&mut self) -> Vec<ViewEffect<V, D>> {
        self.capabilities.drain(..).collect()
    }

    pub(crate) fn certificate_reservations(&self) -> usize {
        self.certificate_jobs.len()
    }

    #[cfg(test)]
    pub(crate) fn retained_parents(&self) -> usize {
        self.parents.len()
    }

    /// Prepares a nullification recovery completion, or consumes a stale completion.
    ///
    /// Returning `None` releases a matching job whose dispatch generation is no longer current
    /// and re-derives the view's readiness, so a completion that cannot commit can never strand
    /// the view behind a pending marker.
    pub(crate) fn prepare_nullification(
        &mut self,
        completion: &NullificationRecoveryCompletion<V>,
        generation: u64,
    ) -> Result<Option<PreparedArtifact<V, D>>, ViewError> {
        if matches!(
            self.certificate_jobs.get(&completion.id),
            Some(ViewCertificateJob::Nullification { job, .. }) if job.generation != generation
        ) {
            self.abandon_certificate_job(completion.id);
            return Ok(None);
        }
        if completion.generation != generation {
            return Ok(None);
        }
        let Some(ViewCertificateJob::Nullification { job, observation }) =
            self.certificate_jobs.get(&completion.id)
        else {
            return Ok(None);
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
            observation: *observation,
        }))
    }

    pub(crate) fn finish_nullification(&mut self, id: ViewCertificateId) {
        let Some(ViewCertificateJob::Nullification { job, .. }) = self.certificate_jobs.remove(&id)
        else {
            return;
        };
        if let Some(first) = job.shares.first() {
            self.pending_nullifications.remove(&first.view());
            self.assembled_nullifications.insert(first.view());
            self.refresh_view(first.view());
        }
    }

    /// Prepares a V-QC aggregation completion, or consumes a stale completion.
    ///
    /// Returning `None` releases a matching job whose dispatch generation is no longer current
    /// and re-derives the view's readiness, so a completion that cannot commit can never strand
    /// the view behind a pending marker.
    pub(crate) fn prepare_vqc<H: Hasher<Digest = D>>(
        &mut self,
        profile: &Profile<H, V>,
        completion: &VqcAggregateCompletion<V, D>,
        generation: u64,
    ) -> Result<Option<PreparedArtifact<V, D>>, ViewError> {
        if matches!(
            self.certificate_jobs.get(&completion.id),
            Some(ViewCertificateJob::Vqc { job, .. }) if job.generation != generation
        ) {
            self.abandon_certificate_job(completion.id);
            return Ok(None);
        }
        if completion.generation != generation {
            return Ok(None);
        }
        let Some(ViewCertificateJob::Vqc { job, observation }) =
            self.certificate_jobs.get(&completion.id)
        else {
            return Ok(None);
        };
        if job.generation != completion.generation
            || !vqc_matches_job::<H, V, D>(
                &completion.certificate,
                &job.leader,
                &job.messages,
                profile.protocol().codec_config(),
            )
        {
            return Err(ViewError::CompletionMismatch);
        }
        Ok(Some(PreparedArtifact {
            artifact: Arc::new(Artifact::Vqc(completion.certificate.clone())),
            observation: *observation,
        }))
    }

    pub(crate) fn finish_vqc(&mut self, id: ViewCertificateId) {
        let Some(ViewCertificateJob::Vqc { job, .. }) = self.certificate_jobs.remove(&id) else {
            return;
        };
        let view = job.leader.view();
        self.pending_vqcs.remove(&view);
        self.assembled_vqcs.insert(job.transcript);
        self.refresh_view(view);
    }

    /// Reports whether a certificate assembly is marked in flight for the view.
    #[cfg(test)]
    pub(crate) fn certificate_pending(&self, view: View) -> bool {
        self.pending_vqcs.contains_key(&view) || self.pending_nullifications.contains_key(&view)
    }

    /// Reports whether the view re-derived as ready for certificate work.
    #[cfg(test)]
    pub(crate) fn certificate_ready(&self, view: View) -> bool {
        self.ready_certificate_views.contains(&view)
    }

    /// Releases a certificate job without an assembled certificate and re-derives readiness.
    ///
    /// The retained shares survive the job, so the view re-enters the ready set on the same
    /// call when its quorum still holds, instead of waiting behind a pending marker whose
    /// completion was consumed.
    fn abandon_certificate_job(&mut self, id: ViewCertificateId) {
        match self.certificate_jobs.remove(&id) {
            Some(ViewCertificateJob::Nullification { job, .. }) => {
                if let Some(first) = job.shares.first() {
                    let view = first.view();
                    self.pending_nullifications.remove(&view);
                    self.refresh_view(view);
                }
            }
            Some(ViewCertificateJob::Vqc { job, .. }) => {
                let view = job.leader.view();
                self.pending_vqcs.remove(&view);
                self.refresh_view(view);
            }
            None => {}
        }
    }

    fn claim_for(artifact: &Artifact<V, D>) -> Option<Claim> {
        match artifact {
            Artifact::LeaderBlock(block) => Some(Claim::Proposal(block.view())),
            Artifact::Vote(vote) => Some(Claim::ViewMessage(vote.view(), vote.signer())),
            Artifact::NoVote(vote) => Some(Claim::ViewMessage(vote.view(), vote.signer())),
            Artifact::Nullify(share) => Some(Claim::Nullify(share.view(), share.signer())),
            Artifact::Nullification(certificate) => Some(Claim::Nullification(certificate.view())),
            Artifact::Vqc(certificate) => Some(Claim::Vqc(certificate.view())),
            Artifact::TransactionBlock(_)
            | Artifact::DaVote(_)
            | Artifact::DaCertificate(_)
            | Artifact::Lqc(_) => None,
        }
    }

    fn remove_claim(&mut self, claim: Claim, id: ArtifactId<D>) {
        let Some(claims) = self.claims.get_mut(&claim) else {
            return;
        };
        let Some(observation) = claims.remove(&id) else {
            return;
        };
        if claims.is_empty() {
            self.claims.remove(&claim);
        }
        self.remove_claim_cohort(claim, observation.cohort());
    }

    fn insert_claim_cohort(&mut self, claim: Claim, cohort: u64) {
        *self
            .claim_cohorts
            .entry(claim)
            .or_default()
            .entry(cohort)
            .or_default() += 1;
        let aggregate = match claim {
            Claim::ViewMessage(view, _) => self.message_claim_cohorts.entry(view).or_default(),
            Claim::Nullify(view, _) => self.nullify_claim_cohorts.entry(view).or_default(),
            Claim::Proposal(_) | Claim::Nullification(_) | Claim::Vqc(_) => return,
        };
        *aggregate.entry(cohort).or_default() += 1;
    }

    fn remove_claim_cohort(&mut self, claim: Claim, cohort: u64) {
        remove_cohort(&mut self.claim_cohorts, claim, cohort);
        match claim {
            Claim::ViewMessage(view, _) => {
                remove_cohort(&mut self.message_claim_cohorts, view, cohort);
            }
            Claim::Nullify(view, _) => {
                remove_cohort(&mut self.nullify_claim_cohorts, view, cohort);
            }
            Claim::Proposal(_) | Claim::Nullification(_) | Claim::Vqc(_) => {}
        }
    }

    fn observe_proposal<H: Hasher<Digest = D>>(
        &mut self,
        observation: Observation,
        artifact: &Arc<Artifact<V, D>>,
    ) -> Result<(), ViewError> {
        let Artifact::LeaderBlock(block) = artifact.as_ref() else {
            unreachable!("proposal observation contains a leader block");
        };
        self.record_leader::<H>(observation, artifact);
        let records = self.proposals.entry(block.view()).or_default();
        if let Some(record) = records
            .iter_mut()
            .find(|record| record.artifact.as_ref() == artifact.as_ref())
        {
            record.observation = record.observation.min(observation);
            records.sort_unstable_by_key(|record| record.observation);
            return Ok(());
        }
        let index = records.partition_point(|record| record.observation < observation);
        records.insert(
            index,
            ProposalRecord {
                observation,
                artifact: Arc::clone(artifact),
            },
        );
        Ok(())
    }

    fn record_leader<H: Hasher<Digest = D>>(
        &mut self,
        observation: Observation,
        artifact: &Arc<Artifact<V, D>>,
    ) {
        let leader = match artifact.as_ref() {
            Artifact::LeaderBlock(block) => block.block(),
            Artifact::Vqc(certificate) => certificate.leader(),
            _ => unreachable!("leader sources are proposals or V-QCs"),
        };
        let key = (leader.view(), leader.digest::<H>());
        let record = self
            .leaders
            .entry(key)
            .or_insert(LeaderRecord { transition: None });
        record.set_transition(observation, artifact);
    }

    fn observe_message(
        &mut self,
        id: ArtifactId<D>,
        observation: Observation,
        artifact: Arc<Artifact<V, D>>,
    ) {
        let (view, signer) = match artifact.as_ref() {
            Artifact::Vote(vote) => (vote.view(), vote.signer()),
            Artifact::NoVote(vote) => (vote.view(), vote.signer()),
            _ => unreachable!("view-message observation contains a vote or novote"),
        };
        if let Some((existing_view, existing_signer, existing_observation)) =
            self.message_locations.get(&id).copied()
        {
            debug_assert_eq!((existing_view, existing_signer), (view, signer));
            if observation >= existing_observation {
                return;
            }
            let records = self
                .messages
                .get_mut(&view)
                .expect("indexed view exists")
                .get_mut(&signer)
                .expect("indexed signer exists");
            let index = records
                .binary_search_by_key(&existing_observation, |record| record.observation)
                .expect("indexed observation exists");
            let mut record = records.remove(index);
            debug_assert_eq!(record.id, id);
            debug_assert_eq!(record.artifact.as_ref(), artifact.as_ref());
            record.observation = observation;
            let index = records.partition_point(|record| record.observation < observation);
            records.insert(index, record);
            self.message_locations
                .insert(id, (view, signer, observation));
            return;
        }

        let opposes_local_vote = self
            .slots
            .get(&view)
            .and_then(|slot| slot.vote.as_ref())
            .is_some_and(|voted| {
                let message = match artifact.as_ref() {
                    Artifact::Vote(vote) => MessageRef::Vote(vote),
                    Artifact::NoVote(_) => MessageRef::NoVote,
                    _ => unreachable!("view-message observation contains a vote or novote"),
                };
                message_opposes(message, voted)
            });
        let records = self
            .messages
            .entry(view)
            .or_default()
            .entry(signer)
            .or_default();
        let record = MessageRecord {
            id,
            observation,
            artifact,
        };
        if records
            .last()
            .is_none_or(|existing| existing.observation < observation)
        {
            records.push(record);
        } else {
            let index = records.partition_point(|record| record.observation < observation);
            records.insert(index, record);
        }
        self.message_locations
            .insert(id, (view, signer, observation));
        if opposes_local_vote {
            self.post_vote_evidence
                .entry(view)
                .or_default()
                .insert(signer);
        }
    }

    fn remove_message(&mut self, id: ArtifactId<D>, view: View, signer: Participant) {
        let Some((recorded_view, recorded_signer, _)) = self.message_locations.remove(&id) else {
            return;
        };
        debug_assert_eq!((recorded_view, recorded_signer), (view, signer));

        let remove_view = self.messages.get_mut(&view).is_some_and(|messages| {
            let remove_signer = messages.get_mut(&signer).is_some_and(|records| {
                records.retain(|record| record.id != id);
                records.is_empty()
            });
            if remove_signer {
                messages.remove(&signer);
            }
            messages.is_empty()
        });
        if remove_view {
            self.messages.remove(&view);
        }

        let remove_sticky_view = self.sticky_messages.get_mut(&view).is_some_and(|messages| {
            if messages.get(&signer).is_some_and(|record| record.id == id) {
                messages.remove(&signer);
            }
            messages.is_empty()
        });
        if remove_sticky_view {
            self.sticky_messages.remove(&view);
        }
    }

    fn settle_message(&mut self, view: View, participant: Participant) {
        if self
            .sticky_messages
            .get(&view)
            .is_some_and(|messages| messages.contains_key(&participant))
        {
            return;
        }
        let Some(record) = self
            .messages
            .get(&view)
            .and_then(|messages| messages.get(&participant))
            .and_then(|records| records.first())
            .cloned()
        else {
            return;
        };
        if self
            .first_claim_cohort(Claim::ViewMessage(view, participant))
            .is_some_and(|cohort| cohort <= record.observation.cohort())
        {
            return;
        }
        self.sticky_messages
            .entry(view)
            .or_default()
            .insert(participant, record);
    }

    fn observe_nullify(&mut self, observation: Observation, artifact: Arc<Artifact<V, D>>) {
        let Artifact::Nullify(share) = artifact.as_ref() else {
            unreachable!("nullify observation contains a nullify share");
        };
        let view = share.view();
        let signer = share.signer();
        let records = self.nullify_shares.entry(view).or_default();
        match records.get(&signer) {
            Some(existing) if existing.observation <= observation => {}
            _ => {
                records.insert(
                    signer,
                    NullifyRecord {
                        observation,
                        artifact,
                    },
                );
            }
        }
        if self.slot_state(view).has_voted() {
            self.post_vote_evidence
                .entry(view)
                .or_default()
                .insert(signer);
        }
    }

    fn observe_nullification(
        &mut self,
        id: ArtifactId<D>,
        observation: Observation,
        artifact: Arc<Artifact<V, D>>,
    ) {
        let Artifact::Nullification(certificate) = artifact.as_ref() else {
            unreachable!("nullification observation contains a nullification");
        };
        let records = self.nullifications.entry(certificate.view()).or_default();
        if let Some(record) = records.iter_mut().find(|record| record.id == id) {
            record.observation = record.observation.min(observation);
            records.sort_unstable_by_key(|record| (record.observation, record.id));
            return;
        }
        records.push(NullificationRecord {
            id,
            observation,
            artifact,
        });
        records.sort_unstable_by_key(|record| (record.observation, record.id));
    }

    fn observe_vqc<H: Hasher<Digest = D>>(
        &mut self,
        artifact_id: ArtifactId<D>,
        observation: Observation,
        artifact: &Arc<Artifact<V, D>>,
        profile: &Profile<H, V>,
    ) -> Result<(), ViewError> {
        let Artifact::Vqc(certificate) = artifact.as_ref() else {
            unreachable!("V-QC observation contains a V-QC");
        };
        let id = self.retain_vqc_parent::<H>(artifact, profile)?;
        if certificate.view() <= self.retired_transitions && self.vqc_forwarded(certificate.view())
        {
            return Ok(());
        }
        self.record_leader::<H>(observation, artifact);
        let records = self.vqcs.entry(certificate.view()).or_default();
        if let Some(record) = records
            .iter_mut()
            .find(|record| record.artifact_id == artifact_id)
        {
            record.observation = record.observation.min(observation);
            records.sort_unstable_by_key(|record| (record.observation, record.id));
            return Ok(());
        }
        records.push(VqcRecord {
            artifact_id,
            id,
            observation,
            artifact: Arc::clone(artifact),
        });
        records.sort_unstable_by_key(|record| (record.observation, record.id));
        Ok(())
    }

    /// Retains a V-QC as a proposal parent without scheduling standalone forwarding.
    pub(crate) fn retain_vqc_parent<H: Hasher<Digest = D>>(
        &mut self,
        artifact: &Arc<Artifact<V, D>>,
        profile: &Profile<H, V>,
    ) -> Result<CertificateId<D>, ViewError> {
        let Artifact::Vqc(certificate) = artifact.as_ref() else {
            return Err(ViewError::Certificate);
        };
        let id = certificate.id::<H>();
        let record = ParentRecord {
            id,
            view: certificate.view(),
            history: certificate.leader().history(),
            canonical: certificate.encode(),
            certificate: Some(Arc::clone(artifact)),
            tips: VqcExtraction::new::<H, V>(certificate, profile.protocol().codec_config())
                .map_err(|_| ViewError::Certificate)?
                .into_parts()
                .0,
            messages: certificate.tally().signers().count()
                + certificate.novoters().len()
                + certificate.conflicting_votes().len(),
        };
        if let Some(existing) = self.parents.get(&id) {
            return (existing.canonical == record.canonical)
                .then_some(id)
                .ok_or(ViewError::Certificate);
        }

        self.parents.insert(id, record);
        let ids = self.parents_by_view.entry(certificate.view()).or_default();
        let index = ids.binary_search(&id).unwrap_or_else(|index| index);
        ids.insert(index, id);
        Ok(id)
    }

    fn observe_local_proposal(&mut self, block: LeaderBlock<V, D>) -> Result<(), ViewError> {
        self.slot_mut(block.view()).observe_proposal(block)
    }

    fn observe_local_vote(&mut self, body: VoteBody<D>) -> Result<(), ViewError> {
        let view = body.view();
        self.slot_mut(view).observe_vote(body)?;
        self.rebuild_post_vote_evidence(view);
        Ok(())
    }

    fn observe_local_novote(&mut self, view: View) -> Result<(), ViewError> {
        self.slot_mut(view).observe_novote()
    }

    fn valid_proposal<H: Hasher<Digest = D>>(
        &self,
        profile: &Profile<H, V>,
        view: View,
    ) -> Result<Option<&SignedLeaderBlock<V, D>>, ViewError> {
        let records = self
            .proposals
            .get(&view)
            .map(Vec::as_slice)
            .unwrap_or_default();
        let Some(record) = records.first() else {
            return Ok(None);
        };
        // Observation linearizes receipt into the paper's State. Verification may complete out
        // of order, but an unresolved proposal could still authenticate as an equivocation and
        // invalidate the direct-vote route's precisely-one-proposal precondition.
        if self.first_claim_cohort(Claim::Proposal(view)).is_some() {
            return Ok(None);
        }
        if records.get(1).is_some() {
            return Ok(None);
        }
        let block = record.block().block();
        let Some(parent) = self.parents.get(&block.parent()) else {
            return Ok(None);
        };
        if parent.view >= view
            || !self.gap_is_nullified(parent.view, view)
            || !self.proposal_extends(profile, block, parent)?
        {
            return Ok(None);
        }
        Ok(Some(record.block()))
    }

    fn proposal_extends<H: Hasher<Digest = D>>(
        &self,
        profile: &Profile<H, V>,
        block: &LeaderBlock<V, D>,
        parent: &ParentRecord<V, D>,
    ) -> Result<bool, ViewError> {
        if block.proposals().len() != parent.tips.blocks().len() {
            return Ok(false);
        }
        let history = TipRecord::new(parent.history, parent.tips.blocks().to_vec())
            .map_err(|_| ViewError::Proposal)?;
        if history.commitment::<H>() != block.history() {
            return Ok(false);
        }
        for (proposal, tip) in block.proposals().iter().zip(parent.tips.blocks()) {
            match proposal.anchor() {
                Anchor::Tip(actual) if actual == tip => {}
                Anchor::Certificate(certificate)
                    if certificate.header().chain() == tip.chain()
                        && certificate.header().height() > tip.height()
                        && certificate.epoch() == profile.protocol().epoch() => {}
                _ => return Ok(false),
            }
        }
        Ok(true)
    }

    fn vote_request<H: Hasher<Digest = D>>(
        &self,
        profile: &Profile<H, V>,
        chain: &ChainState<V, D>,
        leader: &LeaderBlock<V, D>,
    ) -> Result<SignRequest<V, D>, ViewError> {
        let body = chain
            .vote_body::<H>(profile, leader)
            .map_err(|_| ViewError::Chain)?;
        Ok(SignRequest::Vote(VoteRequest::new(body)))
    }

    /// Returns whether every view strictly between `parent` and `child` was nullified.
    ///
    /// A proposal may only skip views that provably could not have finalized. Retirement drops the
    /// live nullification records, so a retired view is answered by the forwarded set instead: a
    /// machine may only leave a view whose exit proof it durably forwarded, which makes that set a
    /// complete witness for every view this node has passed.
    pub(crate) fn gap_is_nullified(&self, parent: View, child: View) -> bool {
        self.first_missing_nullification(parent, child).is_none()
    }

    pub(crate) fn has_nullification(&self, view: View) -> bool {
        view > self.proposal_anchor_view && view <= self.proposal_nullified_through
            || self.nullifications.contains_key(&view)
            || self.forwarded_nullifications.contains(&view)
    }

    /// Returns the lowest unresolved skipped view required by an exact proposal parent.
    ///
    /// Incoming proposals always participate. The selected local anchor participates only when the
    /// caller can propose in this view, which avoids speculative resolver work on followers.
    pub(crate) fn missing_nullification(
        &self,
        child: View,
        include_local_anchor: bool,
    ) -> Option<View> {
        let proposal = self
            .proposals
            .get(&child)
            .into_iter()
            .flatten()
            .filter_map(|record| self.parents.get(&record.block().block().parent()))
            .filter(|parent| parent.certificate.is_some())
            .filter_map(|parent| self.first_missing_nullification(parent.view, child))
            .min();
        let local = include_local_anchor
            .then(|| self.select_anchor(child))
            .flatten()
            .filter(|parent| parent.certificate.is_some())
            .and_then(|parent| self.first_missing_nullification(parent.view, child));
        proposal.into_iter().chain(local).min()
    }

    fn first_missing_nullification(&self, parent: View, child: View) -> Option<View> {
        let Some(mut view) = parent.get().checked_add(1) else {
            return Some(parent);
        };
        while view < child.get() {
            let gap = View::new(view);
            if !self.has_nullification(gap) {
                return Some(gap);
            }
            let Some(next) = view.checked_add(1) else {
                return Some(gap);
            };
            view = next;
        }
        None
    }

    fn select_anchor(&self, view: View) -> Option<&ParentRecord<V, D>> {
        let (_, ids) = self.parents_by_view.range(..view).next_back()?;
        ids.iter()
            .filter_map(|id| self.parents.get(id))
            .min_by(|left, right| {
                right.messages.cmp(&left.messages).then_with(|| {
                    left.canonical
                        .cmp(&right.canonical)
                        .then_with(|| left.id.cmp(&right.id))
                })
            })
    }

    fn vqc_candidate(&self, config: CodecConfig, view: View) -> Option<VqcCandidate<D>> {
        let pool = self.sticky_messages.get(&view)?;
        let pending = self
            .message_claim_cohorts
            .get(&view)
            .and_then(|cohorts| cohorts.first_key_value())
            .map(|(cohort, _)| *cohort);
        let mut support = BTreeMap::<D, usize>::new();
        for record in pool.values() {
            if pending.is_some_and(|pending| record.observation.cohort() >= pending) {
                continue;
            }
            if let MessageRef::Vote(vote) = record.message() {
                *support.entry(vote.body().leader()).or_default() += 1;
            }
        }
        support
            .into_iter()
            .filter(|(_, count)| *count >= config.designation_quorum())
            .filter_map(|(target, _)| {
                let leader = self.leaders.get(&(view, target))?;
                if !leader.retain_transition() {
                    return None;
                }
                self.vqc_candidate_for(pool, pending, target, leader, config)
            })
            .min_by_key(|candidate| (candidate.observation, candidate.target))
    }

    fn vqc_candidate_for(
        &self,
        pool: &BTreeMap<Participant, MessageRecord<V, D>>,
        pending: Option<u64>,
        target: D,
        leader: &LeaderRecord<V, D>,
        config: CodecConfig,
    ) -> Option<VqcCandidate<D>> {
        let mut message_cohorts = Vec::with_capacity(pool.len());
        let mut target_cohorts = Vec::with_capacity(config.designation_quorum());
        for record in pool.values() {
            if pending.is_some_and(|pending| record.observation.cohort() >= pending) {
                continue;
            }
            let Some(eligibility) = record.vqc_eligibility(target, leader.block()) else {
                continue;
            };
            message_cohorts.push(record.observation.cohort());
            if matches!(eligibility, VqcEligibility::Target) {
                target_cohorts.push(record.observation.cohort());
            }
        }
        if message_cohorts.len() < config.view_quorum()
            || target_cohorts.len() < config.designation_quorum()
        {
            return None;
        }
        message_cohorts.select_nth_unstable(config.view_quorum() - 1);
        target_cohorts.select_nth_unstable(config.designation_quorum() - 1);
        let cohort = message_cohorts[config.view_quorum() - 1]
            .max(target_cohorts[config.designation_quorum() - 1])
            .max(leader.observation().cohort());
        let limit = if self
            .longest_assembled_vqc(leader.block().view(), target)
            .is_some()
        {
            message_cohorts.len()
        } else {
            config.view_quorum()
        };
        let selected = select_vqc_messages(
            pool,
            target,
            leader.block(),
            if limit == message_cohorts.len() {
                u64::MAX
            } else {
                cohort
            },
            pending,
            config,
            limit,
        )?;
        let observation = selected
            .iter()
            .map(|record| record.observation)
            .chain(once(leader.observation()))
            .max()?;
        let transcript = VqcTranscript {
            view: leader.block().view(),
            target,
            messages: selected.iter().map(|record| record.id).collect(),
        };
        if !self.vqc_transcript_is_new(&transcript) {
            return None;
        }
        Some(VqcCandidate {
            target,
            observation,
            transcript,
        })
    }

    fn longest_assembled_vqc(&self, view: View, target: D) -> Option<&VqcTranscript<D>> {
        self.assembled_vqcs
            .iter()
            .filter(|transcript| transcript.view == view && transcript.target == target)
            .max_by_key(|transcript| transcript.messages.len())
    }

    fn vqc_transcript_is_new(&self, candidate: &VqcTranscript<D>) -> bool {
        let Some(previous) = self.longest_assembled_vqc(candidate.view, candidate.target) else {
            return true;
        };
        candidate.messages.len() > previous.messages.len()
            && previous
                .messages
                .iter()
                .all(|message| candidate.messages.contains(message))
    }

    fn vqc_transcript_materialized<H: Hasher<Digest = D>>(
        &self,
        leader: &LeaderBlock<V, D>,
        messages: &[Arc<Artifact<V, D>>],
        config: CodecConfig,
    ) -> bool {
        self.parents_by_view
            .get(&leader.view())
            .into_iter()
            .flatten()
            .filter_map(|id| self.parents.get(id)?.certificate.as_deref())
            .any(|artifact| {
                let Artifact::Vqc(certificate) = artifact else {
                    unreachable!("proposal parents contain V-QCs");
                };
                vqc_matches_job::<H, V, D>(certificate, leader, messages, config)
            })
    }

    fn nullification_candidate(&self, view: View, quorum: usize) -> Option<Observation> {
        let shares = self.nullify_shares.get(&view)?;
        let pending = self
            .nullify_claim_cohorts
            .get(&view)
            .and_then(|cohorts| cohorts.first_key_value())
            .map(|(cohort, _)| *cohort);
        let mut cohorts = shares
            .values()
            .filter(|record| pending.is_none_or(|pending| record.observation.cohort() < pending))
            .map(|record| record.observation.cohort())
            .collect::<Vec<_>>();
        if cohorts.len() < quorum {
            return None;
        }
        cohorts.select_nth_unstable(quorum - 1);
        let cohort = cohorts[quorum - 1];
        self.select_nullification_shares(view, quorum, cohort)?
            .into_iter()
            .map(|record| record.observation)
            .max()
    }

    fn select_nullification_shares(
        &self,
        view: View,
        quorum: usize,
        cohort: u64,
    ) -> Option<Vec<&NullifyRecord<V, D>>> {
        let selected = self
            .nullify_shares
            .get(&view)?
            .values()
            .filter(|record| record.observation.cohort() <= cohort)
            .take(quorum)
            .collect::<Vec<_>>();
        (selected.len() == quorum).then_some(selected)
    }

    fn forward_vqc(
        &self,
        config: CodecConfig,
        view: View,
        wait_for_nullification: bool,
    ) -> Option<(Observation, Arc<Artifact<V, D>>)> {
        let records = self.vqcs.get(&view)?;
        let earliest = records.first()?.observation.cohort();
        if self.exit_frontier_blocks(config, view, (earliest, 0), true, wait_for_nullification) {
            return None;
        }
        let record = records
            .iter()
            .filter(|record| record.observation.cohort() == earliest)
            .min_by_key(|record| record.id)?;
        Some((record.observation, Arc::clone(&record.artifact)))
    }

    fn forward_nullification(
        &self,
        config: CodecConfig,
        view: View,
        wait_for_vqc: bool,
    ) -> Option<(Observation, Arc<Artifact<V, D>>)> {
        let records = self.nullifications.get(&view)?;
        let earliest = records.first()?.observation.cohort();
        if self.exit_frontier_blocks(config, view, (earliest, 1), wait_for_vqc, true) {
            return None;
        }
        let record = records
            .iter()
            .filter(|record| record.observation.cohort() == earliest)
            .min_by_key(|record| record.id)?;
        Some((record.observation, Arc::clone(&record.artifact)))
    }

    fn exit_frontier_blocks(
        &self,
        config: CodecConfig,
        view: View,
        candidate: (u64, u8),
        wait_for_vqc: bool,
        wait_for_nullification: bool,
    ) -> bool {
        if wait_for_vqc
            && (self.claim_at_or_before(Claim::Vqc(view), candidate, 0)
                || self.claim_at_or_before(Claim::Proposal(view), candidate, 0)
                || self.cohort_at_or_before(&self.message_claim_cohorts, view, candidate, 0)
                || self
                    .pending_vqcs
                    .get(&view)
                    .is_some_and(|observation| (observation.cohort(), 0) <= candidate)
                || (!self.pending_vqcs.contains_key(&view)
                    && self.vqc_candidate(config, view).is_some_and(|local| {
                        !self.assembled_vqcs.contains(&local.transcript)
                            && (local.observation.cohort(), 0) <= candidate
                    })))
        {
            return true;
        }
        wait_for_nullification
            && (self.claim_at_or_before(Claim::Nullification(view), candidate, 1)
                || self.cohort_at_or_before(&self.nullify_claim_cohorts, view, candidate, 1)
                || self
                    .pending_nullifications
                    .get(&view)
                    .is_some_and(|observation| (observation.cohort(), 1) <= candidate)
                || (!self.assembled_nullifications.contains(&view)
                    && !self.pending_nullifications.contains_key(&view)
                    && self
                        .nullification_candidate(view, config.nullification_quorum())
                        .is_some_and(|local| (local.cohort(), 1) <= candidate)))
    }

    fn claim_at_or_before(&self, claim: Claim, candidate: (u64, u8), priority: u8) -> bool {
        self.first_claim_cohort(claim)
            .is_some_and(|cohort| (cohort, priority) <= candidate)
    }

    fn first_claim_cohort(&self, claim: Claim) -> Option<u64> {
        self.claim_cohorts
            .get(&claim)
            .and_then(BTreeMap::first_key_value)
            .map(|(cohort, _)| *cohort)
    }

    fn cohort_at_or_before(
        &self,
        index: &BTreeMap<View, BTreeMap<u64, usize>>,
        view: View,
        candidate: (u64, u8),
        priority: u8,
    ) -> bool {
        index
            .get(&view)
            .and_then(|cohorts| cohorts.first_key_value())
            .is_some_and(|(cohort, _)| (*cohort, priority) <= candidate)
    }

    fn held_exit_key(
        &self,
        view: View,
        vqc_forwarded: bool,
        nullification_forwarded: bool,
    ) -> Option<(u64, u8)> {
        let vqc = (!vqc_forwarded)
            .then(|| {
                self.vqcs
                    .get(&view)
                    .and_then(|records| records.first())
                    .map(|record| (record.observation.cohort(), 0))
            })
            .flatten();
        let nullification = (!nullification_forwarded)
            .then(|| {
                self.nullifications
                    .get(&view)
                    .and_then(|records| records.first())
                    .map(|record| (record.observation.cohort(), 1))
            })
            .flatten();
        match (vqc, nullification) {
            (Some(left), Some(right)) => Some(left.min(right)),
            (Some(key), None) | (None, Some(key)) => Some(key),
            (None, None) => None,
        }
    }

    fn unresolved_exit_key(
        &self,
        view: View,
        vqc_forwarded: bool,
        nullification_forwarded: bool,
    ) -> Option<(u64, u8)> {
        let vqc = if vqc_forwarded {
            None
        } else {
            self.first_claim_cohort(Claim::Vqc(view))
                .map(|cohort| (cohort, 0))
                .into_iter()
                .chain(
                    self.first_claim_cohort(Claim::Proposal(view))
                        .map(|cohort| (cohort, 0)),
                )
                .chain(
                    self.message_claim_cohorts
                        .get(&view)
                        .and_then(BTreeMap::first_key_value)
                        .map(|(cohort, _)| (*cohort, 0)),
                )
                .chain(
                    self.pending_vqcs
                        .get(&view)
                        .map(|observation| (observation.cohort(), 0)),
                )
                .min()
        };
        let nullification = if nullification_forwarded {
            None
        } else {
            self.first_claim_cohort(Claim::Nullification(view))
                .map(|cohort| (cohort, 1))
                .into_iter()
                .chain(
                    self.nullify_claim_cohorts
                        .get(&view)
                        .and_then(BTreeMap::first_key_value)
                        .map(|(cohort, _)| (*cohort, 1)),
                )
                .chain(
                    self.pending_nullifications
                        .get(&view)
                        .map(|observation| (observation.cohort(), 1)),
                )
                .min()
        };
        match (vqc, nullification) {
            (Some(left), Some(right)) => Some(left.min(right)),
            (Some(key), None) | (None, Some(key)) => Some(key),
            (None, None) => None,
        }
    }

    fn rebuild_post_vote_evidence(&mut self, view: View) {
        let Some(voted) = self.slots.get(&view).and_then(|slot| slot.vote.as_ref()) else {
            return;
        };
        let mut evidence = self
            .nullify_shares
            .get(&view)
            .map(|shares| shares.keys().copied().collect::<BTreeSet<_>>())
            .unwrap_or_default();
        if let Some(messages) = self.messages.get(&view) {
            for (participant, records) in messages {
                if records
                    .iter()
                    .any(|record| message_opposes(record.message(), voted))
                {
                    evidence.insert(*participant);
                }
            }
        }
        self.post_vote_evidence.insert(view, evidence);
    }

    fn next_certificate_id(&mut self) -> Result<ViewCertificateId, ViewError> {
        let id = ViewCertificateId(self.next_certificate);
        self.next_certificate = self
            .next_certificate
            .checked_add(1)
            .ok_or(ViewError::IdentifierExhausted)?;
        Ok(id)
    }
}

fn message_opposes<V: Variant, D: Digest>(
    message: MessageRef<'_, V, D>,
    voted: &VoteBody<D>,
) -> bool {
    match message {
        MessageRef::NoVote => true,
        MessageRef::Vote(vote) => vote.body().leader() != voted.leader(),
    }
}

fn remove_cohort<K: Copy + Ord>(
    index: &mut BTreeMap<K, BTreeMap<u64, usize>>,
    key: K,
    cohort: u64,
) {
    let Some(cohorts) = index.get_mut(&key) else {
        return;
    };
    let Some(count) = cohorts.get_mut(&cohort) else {
        return;
    };
    *count -= 1;
    if *count == 0 {
        cohorts.remove(&cohort);
    }
    if cohorts.is_empty() {
        index.remove(&key);
    }
}

fn select_vqc_messages<'a, V: Variant, D: Digest>(
    pool: &'a BTreeMap<Participant, MessageRecord<V, D>>,
    target: D,
    leader: &LeaderBlock<V, D>,
    cohort: u64,
    pending: Option<u64>,
    config: CodecConfig,
    limit: usize,
) -> Option<Vec<&'a MessageRecord<V, D>>> {
    let eligible = pool.values().filter(|message| {
        message.observation.cohort() <= cohort
            && pending.is_none_or(|pending| message.observation.cohort() < pending)
            && message.vqc_eligibility(target, leader).is_some()
    });
    let eligible_len = eligible.clone().count();
    if eligible_len < config.view_quorum() {
        return None;
    }
    if limit < config.view_quorum() || limit > eligible_len {
        return None;
    }
    let mut selected = Vec::with_capacity(limit);
    let mut target_count = 0usize;
    let mut remaining_targets = eligible
        .clone()
        .filter(|message| {
            matches!(
                message.vqc_eligibility(target, leader),
                Some(VqcEligibility::Target)
            )
        })
        .count();
    for (index, message) in eligible.enumerate() {
        if selected.len() == limit {
            break;
        }
        let is_target = matches!(
            message.vqc_eligibility(target, leader),
            Some(VqcEligibility::Target)
        );
        remaining_targets -= usize::from(is_target);
        let slots_after = limit - selected.len() - 1;
        let enough_entries = eligible_len - index > slots_after;
        let enough_targets =
            target_count + usize::from(is_target) + remaining_targets.min(slots_after)
                >= config.designation_quorum();
        if enough_entries && enough_targets {
            selected.push(message);
            target_count += usize::from(is_target);
        }
    }
    (selected.len() == limit && target_count >= config.designation_quorum()).then_some(selected)
}

fn next_map_entry<D: Digest>(
    entries: &BTreeMap<D, usize>,
    cursor: Option<D>,
) -> Option<(D, &usize)> {
    cursor.map_or_else(
        || entries.first_key_value().map(|(key, value)| (*key, value)),
        |cursor| {
            entries
                .range((Excluded(cursor), Unbounded))
                .next()
                .map(|(key, value)| (*key, value))
        },
    )
}

fn retain_smallest(values: &mut BinaryHeap<u64>, value: u64, limit: usize) {
    values.push(value);
    if values.len() > limit {
        values.pop();
    }
}

fn vqc_matches_job<H, V, D>(
    certificate: &Vqc<V, D>,
    leader: &LeaderBlock<V, D>,
    messages: &[Arc<Artifact<V, D>>],
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
    let mut actual = BTreeMap::<Participant, MessageBody<D>>::new();
    for signer in certificate.tally().signers().iter() {
        let Ok(body) = certificate.tally().vote::<V, H>(leader, signer, config) else {
            return false;
        };
        actual.insert(signer, MessageBody::Vote(body));
    }
    for signer in certificate.novoters().iter() {
        actual.insert(signer, MessageBody::NoVote);
    }
    for conflict in certificate.conflicting_votes() {
        let Ok(body) = conflict.vote_body(leader.round(), config) else {
            return false;
        };
        actual.insert(conflict.signer(), MessageBody::Vote(body));
    }
    if actual.len() != messages.len() {
        return false;
    }
    messages.iter().all(|expected| match expected.as_ref() {
        Artifact::Vote(vote) => {
            matches!(actual.get(&vote.signer()), Some(MessageBody::Vote(body)) if vote.body() == body)
        }
        Artifact::NoVote(vote) => {
            matches!(actual.get(&vote.signer()), Some(MessageBody::NoVote))
        }
        _ => false,
    })
}

#[cfg(test)]
mod tests {
    use super::{
        NullificationState, StanceState, TransitionState, ViewProductState, ViewSlotInput,
        ViewSlotOutput,
    };

    #[test]
    fn product_state_table_is_exhaustive() {
        let transitions = [TransitionState::Active, TransitionState::Exited];
        let stances = [
            StanceState::Unchosen,
            StanceState::Voted,
            StanceState::NoVoted,
        ];
        let nullifications = [NullificationState::Unsigned, NullificationState::Signed];
        let inputs = [
            ViewSlotInput::Propose,
            ViewSlotInput::Vote,
            ViewSlotInput::NoVote,
            ViewSlotInput::Nullify,
            ViewSlotInput::Exit,
        ];

        let mut cases = 0;
        for transition in transitions {
            for stance in stances {
                for nullification in nullifications {
                    for proposed in [false, true] {
                        for input in inputs {
                            let before = ViewProductState {
                                transition,
                                stance,
                                nullification,
                                proposed,
                            };
                            let mut actual = before;
                            let output = actual.apply(input);

                            match (input, output) {
                                (ViewSlotInput::Propose, Some(ViewSlotOutput::Proposed)) => {
                                    assert_eq!(transition, TransitionState::Active);
                                    assert!(!proposed);
                                    assert!(actual.proposed);
                                }
                                (ViewSlotInput::Propose, Some(ViewSlotOutput::Unchanged)) => {
                                    assert!(proposed);
                                    assert_eq!(actual, before);
                                }
                                (ViewSlotInput::Vote, Some(ViewSlotOutput::Voted)) => {
                                    assert_eq!(transition, TransitionState::Active);
                                    assert_eq!(stance, StanceState::Unchosen);
                                    assert_eq!(nullification, NullificationState::Unsigned);
                                    assert_eq!(actual.stance, StanceState::Voted);
                                }
                                (ViewSlotInput::Vote, Some(ViewSlotOutput::Unchanged)) => {
                                    assert_eq!(stance, StanceState::Voted);
                                    assert_eq!(actual, before);
                                }
                                (ViewSlotInput::NoVote, Some(ViewSlotOutput::NoVoted)) => {
                                    assert_eq!(transition, TransitionState::Active);
                                    assert_eq!(stance, StanceState::Unchosen);
                                    assert_eq!(actual.stance, StanceState::NoVoted);
                                }
                                (ViewSlotInput::NoVote, Some(ViewSlotOutput::Unchanged)) => {
                                    assert_eq!(stance, StanceState::NoVoted);
                                    assert_eq!(actual, before);
                                }
                                (ViewSlotInput::Nullify, Some(ViewSlotOutput::Nullified)) => {
                                    assert_eq!(transition, TransitionState::Active);
                                    assert_eq!(nullification, NullificationState::Unsigned);
                                    assert_eq!(actual.nullification, NullificationState::Signed);
                                }
                                (ViewSlotInput::Nullify, Some(ViewSlotOutput::Unchanged)) => {
                                    assert_eq!(transition, TransitionState::Active);
                                    assert_eq!(nullification, NullificationState::Signed);
                                    assert_eq!(actual, before);
                                }
                                (ViewSlotInput::Exit, Some(ViewSlotOutput::Exited)) => {
                                    assert_eq!(transition, TransitionState::Active);
                                    assert_eq!(actual.transition, TransitionState::Exited);
                                }
                                (ViewSlotInput::Exit, Some(ViewSlotOutput::Unchanged)) => {
                                    assert_eq!(transition, TransitionState::Exited);
                                    assert_eq!(actual, before);
                                }
                                (_, None) => assert_eq!(actual, before),
                                pair => panic!("unexpected product transition: {pair:?}"),
                            }
                            cases += 1;
                        }
                    }
                }
            }
        }
        assert_eq!(cases, 120);
    }

    #[test]
    fn timer_and_post_vote_nullification_are_orthogonal() {
        let mut state = ViewProductState::default();
        assert!(state.can_vote());
        assert_eq!(
            state.apply(ViewSlotInput::Vote),
            Some(ViewSlotOutput::Voted)
        );
        assert!(!state.can_vote());
        assert_eq!(
            state.apply(ViewSlotInput::Nullify),
            Some(ViewSlotOutput::Nullified)
        );
        assert!(state.has_voted());
        assert!(state.nullified());

        let mut nullified_first = ViewProductState::default();
        assert_eq!(
            nullified_first.apply(ViewSlotInput::Nullify),
            Some(ViewSlotOutput::Nullified)
        );
        assert_eq!(nullified_first.apply(ViewSlotInput::Vote), None);
    }
}

/// A contradictory authenticated view fact or malformed derived transition.
#[derive(Copy, Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum ViewError {
    #[error("a local leader proposal conflicts with an earlier durable choice")]
    ProposalConflict,
    #[error("a local vote conflicts with an earlier durable choice")]
    VoteConflict,
    #[error("a local vote conflicts with a durable novote choice")]
    VoteNoVoteConflict,
    #[error("the selected proposal is malformed")]
    Proposal,
    #[error("the selected parent certificate is malformed")]
    Certificate,
    #[error("the selected proposal parent is unavailable")]
    MissingParent,
    #[error("a producer-chain fact required by the view transition is malformed")]
    Chain,
    #[error("a view-certificate completion does not match its issued transcript")]
    CompletionMismatch,
    #[error("a view-certificate identifier overflowed")]
    IdentifierExhausted,
}
