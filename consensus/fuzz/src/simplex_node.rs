use crate::{
    simplex,
    strategy::{SmallScope, Strategy},
    utils::Partition,
    FuzzInput, PublicKeyOf, StrategyChoice, MAX_REQUIRED_CONTAINERS, N4F3C1,
};
use arbitrary::Arbitrary;
use bytes::Bytes;
use commonware_codec::{Encode, Read, ReadExt};
use commonware_consensus::{
    simplex::{
        elector::{Config as ElectorConfig, Elector},
        scheme::Scheme as SimplexScheme,
        types::{
            Certificate, Finalization, Finalize, Notarization, Notarize, Nullification, Nullify,
            Proposal, Vote,
        },
        ForwardingPolicy,
    },
    types::{Epoch, Round, View},
    Monitor, Viewable,
};
use commonware_cryptography::{certificate::Scheme as _, sha256::Digest as Sha256Digest};
use commonware_p2p::{simulated, Receiver as _, Recipients, Sender as _};
use commonware_parallel::Sequential;
use commonware_runtime::{deterministic, Clock, Runner, Supervisor};
use commonware_utils::{channel::mpsc::Receiver, NZUsize};
use futures::FutureExt;
use rand::Rng;
use std::{
    collections::{HashMap, HashSet, VecDeque},
    time::Duration,
};

const MIN_EVENTS: usize = 10;
const MAX_EVENTS: usize = 100;
const MAX_SAFE_VIEW: u64 = u64::MAX - 2;
const PROPOSAL_CACHE_LIMIT: usize = 64;

/// Number of Byzantine nodes in the N4F3C1 configuration.
pub(crate) const BYZANTINE_COUNT: usize = 3;
/// Index of the single honest node in the N4F3C1 configuration.
pub(crate) const HONEST_ID: usize = BYZANTINE_COUNT;
/// All Byzantine signer indices, used to build quorum certificates.
const BYZANTINE_IDS: [usize; BYZANTINE_COUNT] = [0, 1, 2];

#[derive(Debug, Clone, Copy, Arbitrary)]
pub enum Event {
    OnProposalBroadcast,
    OnProposalBroadcastThenNotarize,
    OnNotarize,
    OnNullify,
    OnFinalize,
    OnNotarization,
    OnNullification,
    OnFinalization,
}

#[derive(Debug, Clone, Copy, Arbitrary)]
pub struct NodeEvent {
    pub from_node_idx: u8,
    pub event: Event,
}

#[derive(Debug, Clone)]
pub struct NodeFuzzInput {
    pub raw_bytes: Vec<u8>,
    pub events: Vec<NodeEvent>,
    pub forwarding: ForwardingPolicy,
    pub certify: crate::CertifyChoice,
}

impl Arbitrary<'_> for NodeFuzzInput {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let event_count = u.int_in_range(MIN_EVENTS..=MAX_EVENTS)?;

        let mut events = Vec::with_capacity(event_count);
        for _ in 0..event_count {
            events.push(NodeEvent::arbitrary(u)?);
        }

        let forwarding = match u.int_in_range(0..=2)? {
            0 => ForwardingPolicy::Disabled,
            1 => ForwardingPolicy::SilentVoters,
            _ => ForwardingPolicy::SilentLeader,
        };

        // Single-target certify variants are not sampled: the node-fuzz
        // harness runs only one honest engine, so disabling its certifier
        // halts liveness.
        let certify = crate::CertifyChoice::Always;

        let remaining = u.len().min(crate::MAX_RAW_BYTES);
        let raw_bytes = if remaining == 0 {
            vec![0]
        } else {
            u.bytes(remaining)?.to_vec()
        };

        Ok(Self {
            raw_bytes,
            events,
            forwarding,
            certify,
        })
    }
}

/// Selector for which single-node fuzz path [`crate::fuzz_node`] dispatches to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeMode {
    WithoutRecovery,
    WithRecovery,
}

/// Zero-sized type implemented by every single-node fuzz mode;
/// [`crate::fuzz_node::<P, M>`] picks the run path via `M::MODE`.
///
/// Separate from [`crate::FuzzMode`] (the multi-node trait) so the type system
/// prevents passing single-node modes to multi-node entry points and vice versa.
pub trait NodeFuzzMode {
    const MODE: NodeMode;
}

/// **WithoutRecovery mode** - single-node fuzzing without unclean-shutdown recovery.
///
/// Used only by [`crate::fuzz_node`] to drive `simplex_node::run` against a
/// scripted [`NodeEvent`] sequence. The runtime starts, the events fire, the
/// run ends - no checkpoint / restart cycle.
pub struct WithoutRecovery;
impl NodeFuzzMode for WithoutRecovery {
    const MODE: NodeMode = NodeMode::WithoutRecovery;
}

/// **WithRecovery mode** - single-node fuzzing through an unclean-shutdown cycle.
///
/// Used only by [`crate::fuzz_node`]. The runtime drives `simplex_node::run`
/// to completion, captures a [`Checkpoint`](commonware_runtime::deterministic::Checkpoint),
/// then re-runs `simplex_node::run_recovery` from that checkpoint to verify
/// the node restarts cleanly into a consistent state.
pub struct WithRecovery;
impl NodeFuzzMode for WithRecovery {
    const MODE: NodeMode = NodeMode::WithRecovery;
}

#[derive(Clone, Copy)]
enum ProgressBranch {
    NullificationCertificate,
    NullifyVotes,
    NotarizationCertificateAndFinalizationCertificate,
    NotarizationCertificateAndFinalizeVotes,
    NotarizeVotesAndFinalizationCertificate,
    NotarizeVotesAndFinalizeVotes,
}

#[derive(Clone, Copy)]
enum RequestedCertificateMode {
    Notarization,
    Finalization,
    Nullification,
    ValidFallback,
}

#[derive(Clone, Copy)]
enum ValidCertificateKind {
    Notarization,
    Finalization,
    Nullification,
}

#[derive(Clone, Copy)]
enum EpochFlavor {
    Current,
    WrongEpoch,
}

#[derive(Clone, Copy)]
enum ResolverResponseBranch {
    DefaultResponse,
    Certificate,
    MutatedCertificate,
}

#[derive(Clone, Copy)]
enum VotePreference {
    PreferHonest,
    ByzantineOnly,
}

#[derive(Clone, Copy)]
enum NotarizeVotePolicy {
    Valid,
    Malformed,
    WrongEpoch,
}

#[derive(Clone, Copy)]
enum BroadcastAndNotarizeBranch {
    TryValidPath,
    FuzzedPath,
}

#[derive(Clone, Copy)]
enum NotarizationCertificateBranch {
    Normal,
    Malformed,
    WrongEpochNullification,
    InvalidNotarization,
}

#[derive(Clone, Copy)]
enum NullificationCertificateBranch {
    Normal,
    TriggerLocalFloor,
    Malformed,
    WrongEpoch,
    InvalidNullification,
}

#[derive(Clone, Copy)]
enum FinalizationCertificateBranch {
    Normal,
    InvalidFinalization,
}

struct NodeDriver<S, E>
where
    S: SimplexScheme<Sha256Digest>,
    E: Elector<S>,
    S::PublicKey: Send,
{
    context: deterministic::Context,
    honest: S::PublicKey,
    relay: std::sync::Arc<
        commonware_consensus::simplex::mocks::relay::Relay<Sha256Digest, S::PublicKey>,
    >,
    byzantine_participants: Vec<S::PublicKey>,
    schemes: Vec<S>,
    vote_senders: Vec<simulated::Sender<S::PublicKey, deterministic::Context>>,
    certificate_senders: Vec<simulated::Sender<S::PublicKey, deterministic::Context>>,
    resolver_senders: Vec<simulated::Sender<S::PublicKey, deterministic::Context>>,
    vote_receivers: Vec<simulated::Receiver<S::PublicKey>>,
    certificate_receivers: Vec<simulated::Receiver<S::PublicKey>>,
    resolver_receivers: Vec<simulated::Receiver<S::PublicKey>>,
    strategy: SmallScope,
    elector: E,

    last_vote_view: u64,
    last_finalized_view: u64,
    last_notarized_view: u64,
    last_nullified_view: u64,

    latest_proposals: VecDeque<Proposal<Sha256Digest>>,
    proposal_by_view: HashMap<u64, Proposal<Sha256Digest>>,

    honest_notarize_votes: HashMap<Proposal<Sha256Digest>, Notarize<S, Sha256Digest>>,
    honest_finalize_votes: HashMap<Proposal<Sha256Digest>, Finalize<S, Sha256Digest>>,
    injected_finalize_views: HashSet<u64>,

    notarized_by_view: HashMap<u64, Sha256Digest>,
    finalized_by_view: HashMap<u64, Sha256Digest>,
    leader_certificate_by_view: HashMap<u64, S::Certificate>,
}

impl<S, E> NodeDriver<S, E>
where
    S: SimplexScheme<Sha256Digest>,
    E: Elector<S>,
    S::PublicKey: Send,
{
    #[allow(clippy::too_many_arguments)]
    fn new(
        context: deterministic::Context,
        honest: S::PublicKey,
        relay: std::sync::Arc<
            commonware_consensus::simplex::mocks::relay::Relay<Sha256Digest, S::PublicKey>,
        >,
        byzantine_participants: Vec<S::PublicKey>,
        schemes: Vec<S>,
        vote_senders: Vec<simulated::Sender<S::PublicKey, deterministic::Context>>,
        certificate_senders: Vec<simulated::Sender<S::PublicKey, deterministic::Context>>,
        resolver_senders: Vec<simulated::Sender<S::PublicKey, deterministic::Context>>,
        vote_receivers: Vec<simulated::Receiver<S::PublicKey>>,
        certificate_receivers: Vec<simulated::Receiver<S::PublicKey>>,
        resolver_receivers: Vec<simulated::Receiver<S::PublicKey>>,
        elector: E,
    ) -> Self {
        Self {
            context,
            honest,
            relay,
            byzantine_participants,
            schemes,
            vote_senders,
            certificate_senders,
            resolver_senders,
            vote_receivers,
            certificate_receivers,
            resolver_receivers,
            strategy: SmallScope {
                fault_rounds: 1,
                fault_rounds_bound: 1,
            },
            elector,
            last_vote_view: 1,
            last_finalized_view: 0,
            last_notarized_view: 0,
            last_nullified_view: 0,
            latest_proposals: VecDeque::new(),
            proposal_by_view: HashMap::new(),
            honest_notarize_votes: HashMap::new(),
            honest_finalize_votes: HashMap::new(),
            injected_finalize_views: HashSet::new(),
            notarized_by_view: HashMap::new(),
            finalized_by_view: HashMap::new(),
            leader_certificate_by_view: HashMap::new(),
        }
    }

    fn signer_index(&self, node_idx: u8) -> usize {
        usize::from(node_idx) % self.schemes.len()
    }

    fn leader_for_view(&self, view: u64) -> Option<usize> {
        if view == 0 {
            return None;
        }
        let round = Round::new(Epoch::new(crate::EPOCH), View::new(view));
        let certificate = if view == 1 {
            None
        } else {
            Some(self.leader_certificate_by_view.get(&(view - 1))?)
        };
        Some(usize::from(self.elector.elect(round, certificate)))
    }

    fn is_elected_leader(&self, participant_idx: usize, view: u64) -> bool {
        self.leader_for_view(view) == Some(participant_idx)
    }

    fn is_elected_honest_leader(&self, view: u64) -> bool {
        self.is_elected_leader(self.byzantine_participants.len(), view)
    }

    fn track_certificate(&mut self, certificate: &Certificate<S, Sha256Digest>) {
        match certificate {
            Certificate::Notarization(notarization) => {
                self.leader_certificate_by_view
                    .insert(notarization.view().get(), notarization.certificate.clone());
            }
            Certificate::Nullification(nullification) => {
                self.leader_certificate_by_view.insert(
                    nullification.view().get(),
                    nullification.certificate.clone(),
                );
            }
            Certificate::Finalization(finalization) => {
                self.leader_certificate_by_view
                    .insert(finalization.view().get(), finalization.certificate.clone());
            }
        }
    }

    fn choose_progress_branch(&mut self) -> ProgressBranch {
        match self.context.gen_range(0..100u8) {
            0..=9 => ProgressBranch::NullificationCertificate,
            10..=19 => ProgressBranch::NullifyVotes,
            20..=39 => ProgressBranch::NotarizationCertificateAndFinalizationCertificate,
            40..=59 => ProgressBranch::NotarizationCertificateAndFinalizeVotes,
            60..=79 => ProgressBranch::NotarizeVotesAndFinalizationCertificate,
            80..=99 => ProgressBranch::NotarizeVotesAndFinalizeVotes,
            _ => unreachable!(),
        }
    }

    fn choose_requested_certificate_mode(&mut self) -> RequestedCertificateMode {
        match self.context.gen_range(0..=3u8) {
            0 => RequestedCertificateMode::Notarization,
            1 => RequestedCertificateMode::Finalization,
            2 => RequestedCertificateMode::Nullification,
            _ => RequestedCertificateMode::ValidFallback,
        }
    }

    fn choose_valid_certificate_kind(&mut self) -> ValidCertificateKind {
        match self.context.gen_range(0..3usize) {
            0 => ValidCertificateKind::Notarization,
            1 => ValidCertificateKind::Finalization,
            _ => ValidCertificateKind::Nullification,
        }
    }

    fn choose_epoch_flavor(&mut self) -> EpochFlavor {
        match self.context.gen_range(0..100u8) {
            0..=79 => EpochFlavor::Current,
            80..=99 => EpochFlavor::WrongEpoch,
            _ => unreachable!(),
        }
    }

    fn choose_resolver_response_branch(&mut self) -> ResolverResponseBranch {
        match self.context.gen_range(0..100u8) {
            0..=63 => ResolverResponseBranch::Certificate,
            64..=79 => ResolverResponseBranch::MutatedCertificate,
            80..=99 => ResolverResponseBranch::DefaultResponse,
            _ => unreachable!(),
        }
    }

    fn choose_vote_preference(&mut self) -> VotePreference {
        match self.context.gen_range(0..2u8) {
            0 => VotePreference::PreferHonest,
            1 => VotePreference::ByzantineOnly,
            _ => unreachable!(),
        }
    }

    fn choose_notarize_vote_policy(&mut self) -> NotarizeVotePolicy {
        match self.context.gen_range(0..100u8) {
            0..=93 => NotarizeVotePolicy::Valid,
            94..=96 => NotarizeVotePolicy::Malformed,
            97..=99 => NotarizeVotePolicy::WrongEpoch,
            _ => unreachable!(),
        }
    }

    fn choose_broadcast_and_notarize_branch(&mut self) -> BroadcastAndNotarizeBranch {
        match self.context.gen_range(0..100u8) {
            0..=2 => BroadcastAndNotarizeBranch::TryValidPath,
            3..=99 => BroadcastAndNotarizeBranch::FuzzedPath,
            _ => unreachable!(),
        }
    }

    fn choose_notarization_certificate_branch(&mut self) -> NotarizationCertificateBranch {
        match self.context.gen_range(0..100u8) {
            0..=89 => NotarizationCertificateBranch::Normal,
            90..=93 => NotarizationCertificateBranch::Malformed,
            94..=96 => NotarizationCertificateBranch::WrongEpochNullification,
            97..=99 => NotarizationCertificateBranch::InvalidNotarization,
            _ => unreachable!(),
        }
    }

    fn choose_nullification_certificate_branch(&mut self) -> NullificationCertificateBranch {
        match self.context.gen_range(0..100u8) {
            0..=86 => NullificationCertificateBranch::Normal,
            87..=89 => NullificationCertificateBranch::TriggerLocalFloor,
            90..=93 => NullificationCertificateBranch::Malformed,
            94..=96 => NullificationCertificateBranch::WrongEpoch,
            97..=99 => NullificationCertificateBranch::InvalidNullification,
            _ => unreachable!(),
        }
    }

    fn choose_finalization_certificate_branch(&mut self) -> FinalizationCertificateBranch {
        match self.context.gen_range(0..100u8) {
            0..=95 => FinalizationCertificateBranch::Normal,
            96..=99 => FinalizationCertificateBranch::InvalidFinalization,
            _ => unreachable!(),
        }
    }

    fn next_sender(&mut self) -> usize {
        debug_assert!(
            !self.certificate_senders.is_empty(),
            "expected certificate senders"
        );
        self.context.gen_range(0..self.certificate_senders.len())
    }

    // Picks a proposal for the next fuzz event. It may reuse a recent proposal
    // or mutate one to create nearby variants.
    fn select_event_proposal(&mut self) -> Proposal<Sha256Digest> {
        let base = self
            .strategy
            .repeated_proposal_index(&mut self.context, self.latest_proposals.len())
            .and_then(|idx| self.latest_proposals.get(idx).cloned())
            .unwrap_or_else(|| {
                self.strategy.random_proposal(
                    &mut self.context,
                    self.last_vote_view,
                    self.last_finalized_view,
                    self.last_notarized_view,
                    self.last_nullified_view,
                )
            });

        let proposal = self.strategy.mutate_proposal(
            &mut self.context,
            &base,
            self.last_vote_view,
            self.last_finalized_view,
            self.last_notarized_view,
            self.last_nullified_view,
        );

        self.proposal_by_view
            .insert(proposal.view().get(), proposal.clone());
        self.latest_proposals.push_back(proposal.clone());
        while self.latest_proposals.len() > PROPOSAL_CACHE_LIMIT {
            self.latest_proposals.pop_front();
        }

        proposal
    }

    // Returns a proposal anchored to a specific view, reusing the existing one
    // for that view when present.
    fn get_or_build_proposal_for_view(&mut self, view: u64) -> Proposal<Sha256Digest> {
        if let Some(existing) = self.proposal_by_view.get(&view) {
            return existing.clone();
        }

        let proposal = self.strategy.random_proposal(
            &mut self.context,
            view,
            self.last_finalized_view,
            self.last_notarized_view,
            self.last_nullified_view,
        );

        self.proposal_by_view.insert(view, proposal.clone());
        self.latest_proposals.push_back(proposal.clone());
        while self.latest_proposals.len() > PROPOSAL_CACHE_LIMIT {
            self.latest_proposals.pop_front();
        }

        proposal
    }

    fn build_notarization_from_byz(
        &self,
        proposal: &Proposal<Sha256Digest>,
        signers: &[usize],
    ) -> Option<Notarization<S, Sha256Digest>> {
        let votes: Vec<_> = signers
            .iter()
            .map(|idx| Notarize::sign(&self.schemes[*idx], proposal.clone()))
            .collect::<Option<Vec<_>>>()?;
        Notarization::from_notarizes(&self.schemes[signers[0]], &votes, &Sequential)
    }

    fn build_nullification_from_byz(
        &self,
        round: Round,
        signers: &[usize],
    ) -> Option<Nullification<S>> {
        let votes: Vec<_> = signers
            .iter()
            .map(|idx| Nullify::<S>::sign::<Sha256Digest>(&self.schemes[*idx], round))
            .collect::<Option<Vec<_>>>()?;
        Nullification::from_nullifies(&self.schemes[signers[0]], &votes, &Sequential)
    }

    fn build_finalization_from_byz(
        &self,
        proposal: &Proposal<Sha256Digest>,
        signers: &[usize],
    ) -> Option<Finalization<S, Sha256Digest>> {
        let votes: Vec<_> = signers
            .iter()
            .map(|idx| Finalize::sign(&self.schemes[*idx], proposal.clone()))
            .collect::<Option<Vec<_>>>()?;
        Finalization::from_finalizes(&self.schemes[signers[0]], &votes, &Sequential)
    }

    fn notarization_with_optional_honest_vote(
        &mut self,
        proposal: &Proposal<Sha256Digest>,
        prefer_honest_vote: bool,
    ) -> Option<(Notarization<S, Sha256Digest>, bool)> {
        if prefer_honest_vote {
            if let Some(honest_vote) = self.honest_notarize_votes.get(proposal).cloned() {
                let byz_vote_0 = Notarize::sign(&self.schemes[0], proposal.clone())?;
                let byz_vote_1 = Notarize::sign(&self.schemes[1], proposal.clone())?;
                let votes = vec![honest_vote, byz_vote_0, byz_vote_1];
                let cert = Notarization::from_notarizes(&self.schemes[0], &votes, &Sequential)?;
                return Some((cert, true));
            }
        }

        let cert = self.build_notarization_from_byz(proposal, &BYZANTINE_IDS)?;
        Some((cert, false))
    }

    fn finalization_with_optional_honest_vote(
        &mut self,
        proposal: &Proposal<Sha256Digest>,
        prefer_honest_vote: bool,
    ) -> Option<(Finalization<S, Sha256Digest>, bool)> {
        if prefer_honest_vote {
            if let Some(honest_vote) = self.honest_finalize_votes.get(proposal).cloned() {
                let byz_vote_0 = Finalize::sign(&self.schemes[0], proposal.clone())?;
                let byz_vote_1 = Finalize::sign(&self.schemes[1], proposal.clone())?;
                let votes = vec![honest_vote, byz_vote_0, byz_vote_1];
                let cert = Finalization::from_finalizes(&self.schemes[0], &votes, &Sequential)?;
                return Some((cert, true));
            }
        }

        let cert = self.build_finalization_from_byz(proposal, &BYZANTINE_IDS)?;
        Some((cert, false))
    }

    fn build_invalid_notarization_for_view(
        &mut self,
        view: u64,
    ) -> Option<Notarization<S, Sha256Digest>> {
        let base = self.get_or_build_proposal_for_view(view);
        let mut conflicting = self.strategy.mutate_proposal(
            &mut self.context,
            &base,
            self.last_vote_view,
            self.last_finalized_view,
            self.last_notarized_view,
            self.last_nullified_view,
        );
        conflicting = self
            .strategy
            .proposal_with_view(&conflicting, base.view().get());
        if conflicting.payload == base.payload {
            conflicting = Proposal::new(
                conflicting.round,
                conflicting.parent,
                self.strategy.random_payload(&mut self.context),
            );
        }

        let votes = [
            Notarize::sign(&self.schemes[0], base.clone())?,
            Notarize::sign(&self.schemes[1], base.clone())?,
            Notarize::sign(&self.schemes[2], conflicting)?,
        ];
        Notarization::from_notarizes(&self.schemes[0], votes.iter(), &Sequential)
    }

    fn build_invalid_nullification_for_view(&mut self, view: u64) -> Option<Nullification<S>> {
        let mut conflicting_view = self.strategy.mutate_nullify_view(
            &mut self.context,
            view,
            self.last_finalized_view,
            self.last_notarized_view,
            self.last_nullified_view,
        );
        conflicting_view = conflicting_view.clamp(1, MAX_SAFE_VIEW);
        if conflicting_view == view {
            conflicting_view = view.saturating_add(1).min(MAX_SAFE_VIEW);
            if conflicting_view == view {
                conflicting_view = view.saturating_sub(1).max(1);
            }
        }

        let base_round = Round::new(Epoch::new(crate::EPOCH), View::new(view));
        let conflicting_round = Round::new(Epoch::new(crate::EPOCH), View::new(conflicting_view));
        let votes = [
            Nullify::<S>::sign::<Sha256Digest>(&self.schemes[0], base_round)?,
            Nullify::<S>::sign::<Sha256Digest>(&self.schemes[1], base_round)?,
            Nullify::<S>::sign::<Sha256Digest>(&self.schemes[2], conflicting_round)?,
        ];
        Nullification::from_nullifies(&self.schemes[0], votes.iter(), &Sequential)
    }

    fn decode_resolver_request(msg: &[u8]) -> Option<(u64, u64)> {
        if msg.len() < 17 {
            return None;
        }
        let id = u64::from_be_bytes(msg.get(0..8)?.try_into().ok()?);
        if msg[8] != 0 {
            return None;
        }
        let requested_view = u64::from_be_bytes(msg.get(9..17)?.try_into().ok()?);
        Some((id, requested_view))
    }

    fn encode_resolver_response(id: u64, data: Vec<u8>) -> Vec<u8> {
        let mut out = Vec::with_capacity(9 + data.len() + 2);
        out.extend_from_slice(&id.to_be_bytes());
        out.push(1); // response payload
        out.extend_from_slice(&data.encode()); // length-prefixed bytes
        out
    }

    fn certificate_for_requested_view(
        &mut self,
        view: u64,
    ) -> Option<Certificate<S, Sha256Digest>> {
        let wrong_epoch = Epoch::new(crate::EPOCH.saturating_add(1));
        let base = self.get_or_build_proposal_for_view(view);

        match self.choose_requested_certificate_mode() {
            RequestedCertificateMode::Notarization => {
                let cert = match self.choose_epoch_flavor() {
                    EpochFlavor::Current => {
                        self.build_notarization_from_byz(&base, &BYZANTINE_IDS)?
                    }
                    EpochFlavor::WrongEpoch => {
                        let wrong = Proposal::new(
                            Round::new(wrong_epoch, base.view()),
                            base.parent,
                            base.payload,
                        );
                        self.build_notarization_from_byz(&wrong, &BYZANTINE_IDS)?
                    }
                };
                Some(Certificate::Notarization(cert))
            }
            RequestedCertificateMode::Finalization => {
                let proposal = self.strategy.proposal_with_parent_view(
                    &self.strategy.proposal_with_view(&base, view),
                    view.saturating_sub(1),
                );
                let cert = match self.choose_epoch_flavor() {
                    EpochFlavor::Current => {
                        self.build_finalization_from_byz(&proposal, &BYZANTINE_IDS)?
                    }
                    EpochFlavor::WrongEpoch => {
                        let wrong = Proposal::new(
                            Round::new(wrong_epoch, proposal.view()),
                            proposal.parent,
                            proposal.payload,
                        );
                        self.build_finalization_from_byz(&wrong, &BYZANTINE_IDS)?
                    }
                };
                Some(Certificate::Finalization(cert))
            }
            RequestedCertificateMode::Nullification => {
                let view = self.strategy.mutate_nullify_view(
                    &mut self.context,
                    view,
                    self.last_finalized_view,
                    self.last_notarized_view,
                    self.last_nullified_view,
                );
                let round = match self.choose_epoch_flavor() {
                    EpochFlavor::Current => Round::new(Epoch::new(crate::EPOCH), View::new(view)),
                    EpochFlavor::WrongEpoch => Round::new(wrong_epoch, View::new(view.max(1))),
                };
                let cert = self.build_nullification_from_byz(round, &BYZANTINE_IDS)?;
                Some(Certificate::Nullification(cert))
            }
            RequestedCertificateMode::ValidFallback => match self.choose_valid_certificate_kind() {
                ValidCertificateKind::Notarization => {
                    let cert = self.build_notarization_from_byz(&base, &BYZANTINE_IDS)?;
                    Some(Certificate::Notarization(cert))
                }
                ValidCertificateKind::Finalization => {
                    let cert = self.build_finalization_from_byz(&base, &BYZANTINE_IDS)?;
                    Some(Certificate::Finalization(cert))
                }
                ValidCertificateKind::Nullification => {
                    let round = Round::new(Epoch::new(crate::EPOCH), View::new(base.view().get()));
                    let cert = self.build_nullification_from_byz(round, &BYZANTINE_IDS)?;
                    Some(Certificate::Nullification(cert))
                }
            },
        }
    }

    fn handle_honest_votes(&mut self, sender: &S::PublicKey, bytes: Vec<u8>) {
        if sender != &self.honest {
            return;
        }
        let Ok(vote) = Vote::<S, Sha256Digest>::read(&mut bytes.as_slice()) else {
            return;
        };

        self.last_vote_view = self.last_vote_view.max(vote.view().get());

        match vote {
            Vote::Notarize(notarize) => {
                let view = notarize.view().get();
                self.honest_notarize_votes
                    .insert(notarize.proposal.clone(), notarize.clone());
                self.proposal_by_view
                    .insert(view, notarize.proposal.clone());
                self.latest_proposals.push_back(notarize.proposal);
            }
            Vote::Nullify(nullify) => {
                self.last_nullified_view = self.last_nullified_view.max(nullify.view().get());
            }
            Vote::Finalize(finalize) => {
                let view = finalize.view().get();
                self.honest_finalize_votes
                    .insert(finalize.proposal.clone(), finalize.clone());
                self.proposal_by_view
                    .insert(view, finalize.proposal.clone());
                self.latest_proposals.push_back(finalize.proposal);
            }
        }

        while self.latest_proposals.len() > PROPOSAL_CACHE_LIMIT {
            self.latest_proposals.pop_front();
        }
    }

    async fn handle_honest_resolvers(
        &mut self,
        sender: &S::PublicKey,
        receiver_idx: usize,
        bytes: Vec<u8>,
    ) {
        if sender != &self.honest {
            return;
        }
        let default_response = self
            .strategy
            .mutate_resolver_bytes(&mut self.context, &bytes);
        let response = if let Some((id, requested_view)) = Self::decode_resolver_request(&bytes) {
            match self.choose_resolver_response_branch() {
                ResolverResponseBranch::DefaultResponse => default_response,
                ResolverResponseBranch::Certificate => {
                    if let Some(certificate) = self.certificate_for_requested_view(requested_view) {
                        Self::encode_resolver_response(id, certificate.encode().to_vec())
                    } else {
                        default_response
                    }
                }
                ResolverResponseBranch::MutatedCertificate => {
                    if let Some(certificate) = self.certificate_for_requested_view(requested_view) {
                        let cert_bytes = self
                            .strategy
                            .mutate_certificate_bytes(&mut self.context, &certificate.encode());
                        Self::encode_resolver_response(id, cert_bytes)
                    } else {
                        default_response
                    }
                }
            }
        } else {
            default_response
        };
        let _ = self.resolver_senders[receiver_idx]
            .send(Recipients::One(self.honest.clone()), response, true)
            .await;
    }

    fn handle_honest_certificates(&mut self, sender: &S::PublicKey, bytes: Vec<u8>) {
        if sender != &self.honest {
            return;
        }
        let cfg = self.schemes[0].certificate_codec_config();
        let Ok(certificate) = Certificate::<S, Sha256Digest>::read_cfg(&mut bytes.as_slice(), &cfg)
        else {
            return;
        };

        match certificate {
            Certificate::Notarization(notarization) => {
                self.leader_certificate_by_view
                    .insert(notarization.view().get(), notarization.certificate.clone());
                let view = notarization.view().get();
                self.last_vote_view = self.last_vote_view.max(view);
                self.last_notarized_view = self.last_notarized_view.max(view);
                self.notarized_by_view
                    .insert(view, notarization.proposal.payload);
                self.proposal_by_view
                    .insert(view, notarization.proposal.clone());
                self.latest_proposals.push_back(notarization.proposal);
            }
            Certificate::Nullification(nullification) => {
                self.leader_certificate_by_view.insert(
                    nullification.view().get(),
                    nullification.certificate.clone(),
                );
                let view = nullification.view().get();
                self.last_nullified_view = self.last_nullified_view.max(view);
                self.last_vote_view = self.last_vote_view.max(view);
            }
            Certificate::Finalization(finalization) => {
                self.leader_certificate_by_view
                    .insert(finalization.view().get(), finalization.certificate.clone());
                let view = finalization.view().get();
                self.last_vote_view = self.last_vote_view.max(view);
                self.last_finalized_view = self.last_finalized_view.max(view);
                self.finalized_by_view
                    .insert(view, finalization.proposal.payload);
                self.proposal_by_view
                    .insert(view, finalization.proposal.clone());
                self.latest_proposals.push_back(finalization.proposal);
            }
        }

        while self.latest_proposals.len() > PROPOSAL_CACHE_LIMIT {
            self.latest_proposals.pop_front();
        }
    }

    async fn handle_receivers(&mut self) {
        for idx in 0..self.vote_receivers.len() {
            while let Some(Ok((sender, msg))) = self.vote_receivers[idx].recv().now_or_never() {
                let bytes: Vec<u8> = msg.into();
                self.handle_honest_votes(&sender, bytes);
            }
        }

        for idx in 0..self.certificate_receivers.len() {
            while let Some(Ok((sender, msg))) =
                self.certificate_receivers[idx].recv().now_or_never()
            {
                let bytes: Vec<u8> = msg.into();
                self.handle_honest_certificates(&sender, bytes);
            }
        }

        for idx in 0..self.resolver_receivers.len() {
            while let Some(Ok((sender, msg))) = self.resolver_receivers[idx].recv().now_or_never() {
                let bytes: Vec<u8> = msg.into();
                self.handle_honest_resolvers(&sender, idx, bytes).await;
            }
        }
    }

    fn check_finalization(&mut self, latest: &mut View, monitor: &mut Receiver<View>) -> bool {
        let mut progressed = false;
        while let Ok(update) = monitor.try_recv() {
            if update.get() > latest.get() {
                *latest = update;
                self.last_finalized_view = self.last_finalized_view.max(update.get());
                progressed = true;
            }
        }
        progressed
    }

    async fn apply_event(&mut self, event: NodeEvent) {
        let signer_idx = self.signer_index(event.from_node_idx);
        match event.event {
            Event::OnProposalBroadcast => self.broadcast_payload(signer_idx).await,
            Event::OnProposalBroadcastThenNotarize => {
                self.send_broadcast_and_notarize(signer_idx).await
            }
            Event::OnNotarize => self.send_notarize_vote(signer_idx).await,
            Event::OnNullify => self.send_nullify_vote(signer_idx).await,
            Event::OnFinalize => self.send_finalize_vote(signer_idx).await,
            Event::OnNotarization => self.send_notarization_certificate().await,
            Event::OnNullification => self.send_nullification_certificate().await,
            Event::OnFinalization => self.send_finalization_certificate().await,
        }
    }

    async fn broadcast_payload(&mut self, signer_idx: usize) {
        let proposal = self.select_event_proposal();
        let view = proposal.view().get();
        if !self.is_elected_leader(signer_idx, view) {
            return;
        }
        self.broadcast_payload_for_verify(signer_idx, &proposal)
            .await;
    }

    async fn broadcast_payload_for_verify(
        &mut self,
        signer_idx: usize,
        proposal: &Proposal<Sha256Digest>,
    ) {
        let Some(sender) = self.byzantine_participants.get(signer_idx).cloned() else {
            return;
        };
        // Mirror equivocator behavior: make payload bytes available to the mock app so
        // verify requests can resolve through relay delivery.
        let contents = self
            .strategy
            .mutate_resolver_bytes(&mut self.context, &[0u8]);
        self.relay
            .broadcast(&sender, (proposal.payload, contents.into()))
    }

    async fn send_notarize_vote(&mut self, signer_idx: usize) {
        let proposal = self.select_event_proposal();
        self.send_notarize_vote_with_policy(signer_idx, proposal)
            .await;
    }

    async fn send_notarize_vote_with_policy(
        &mut self,
        signer_idx: usize,
        proposal: Proposal<Sha256Digest>,
    ) {
        match self.choose_notarize_vote_policy() {
            NotarizeVotePolicy::Valid => {
                self.send_notarize_vote_for_proposal(signer_idx, proposal)
                    .await;
            }
            NotarizeVotePolicy::Malformed => {
                self.send_malformed_vote(signer_idx).await;
            }
            NotarizeVotePolicy::WrongEpoch => {
                self.send_wrong_epoch_notarize_vote_for_proposal(signer_idx, proposal)
                    .await;
            }
        }
    }

    async fn send_broadcast_and_notarize(&mut self, signer_idx: usize) {
        // create a valid verify path so the honest node can complete peer verification
        // and perform `verify` flow.
        match self.choose_broadcast_and_notarize_branch() {
            BroadcastAndNotarizeBranch::TryValidPath => {
                if self.send_valid_broadcast_and_notarize(signer_idx).await {
                    return;
                }
            }
            BroadcastAndNotarizeBranch::FuzzedPath => {}
        }

        let proposal = self.select_event_proposal();
        let view = proposal.view().get();
        if self.is_elected_leader(signer_idx, view) {
            self.broadcast_payload_for_verify(signer_idx, &proposal)
                .await;
        }
        self.send_notarize_vote_with_policy(signer_idx, proposal)
            .await;
    }

    async fn send_valid_broadcast_and_notarize(&mut self, signer_idx: usize) -> bool {
        let mut view = self.last_vote_view.clamp(1, MAX_SAFE_VIEW);
        if !self.is_elected_leader(signer_idx, view) {
            let next = view.saturating_add(1).min(MAX_SAFE_VIEW);
            if !self.is_elected_leader(signer_idx, next) {
                return false;
            }
            view = next;
        }

        let parent_view = self
            .finalized_by_view
            .keys()
            .copied()
            .filter(|v| *v > 0 && *v < view)
            .max();
        let Some(parent_view) = parent_view else {
            return false;
        };
        let Some(parent_payload) = self.finalized_by_view.get(&parent_view).copied() else {
            return false;
        };

        let mut proposal = self.get_or_build_proposal_for_view(view);
        proposal = self.strategy.proposal_with_view(&proposal, view);
        proposal.parent = View::new(parent_view);
        self.proposal_by_view.insert(view, proposal.clone());
        self.latest_proposals.push_back(proposal.clone());
        while self.latest_proposals.len() > PROPOSAL_CACHE_LIMIT {
            self.latest_proposals.pop_front();
        }

        let Some(sender) = self.byzantine_participants.get(signer_idx).cloned() else {
            return false;
        };
        let rand = self.context.gen::<u64>();
        let contents = (proposal.round, parent_payload, rand).encode();
        self.relay.broadcast(&sender, (proposal.payload, contents));

        self.send_notarize_vote_for_proposal(signer_idx, proposal)
            .await;
        true
    }

    async fn send_notarize_vote_for_proposal(
        &mut self,
        signer_idx: usize,
        proposal: Proposal<Sha256Digest>,
    ) {
        let Some(vote) = Notarize::sign(&self.schemes[signer_idx], proposal) else {
            return;
        };
        let msg = Vote::<S, Sha256Digest>::Notarize(vote).encode();
        self.send_vote_bytes(signer_idx, msg).await;
    }

    async fn send_notarize_quorum_votes(&mut self, proposal: Proposal<Sha256Digest>) {
        for signer_idx in 0..self.schemes.len() {
            self.send_notarize_vote_for_proposal(signer_idx, proposal.clone())
                .await;
        }
    }

    async fn send_nullify_vote(&mut self, signer_idx: usize) {
        let view = self.strategy.mutate_nullify_view(
            &mut self.context,
            self.last_vote_view,
            self.last_finalized_view,
            self.last_notarized_view,
            self.last_nullified_view,
        );
        self.send_nullify_vote_for_view(signer_idx, view).await;
    }

    async fn send_nullify_vote_for_view(&mut self, signer_idx: usize, view: u64) {
        let round = Round::new(Epoch::new(crate::EPOCH), View::new(view));
        let Some(vote) = Nullify::<S>::sign::<Sha256Digest>(&self.schemes[signer_idx], round)
        else {
            return;
        };

        let msg = Vote::<S, Sha256Digest>::Nullify(vote).encode();
        self.send_vote_bytes(signer_idx, msg).await;
    }

    async fn send_nullify_quorum_votes(&mut self, view: u64) {
        for signer_idx in 0..self.schemes.len() {
            self.send_nullify_vote_for_view(signer_idx, view).await;
        }
    }

    async fn send_finalize_vote(&mut self, signer_idx: usize) {
        let proposal = self.select_event_proposal();
        self.send_finalize_vote_for_proposal(signer_idx, proposal)
            .await;
    }

    async fn send_finalize_vote_for_proposal(
        &mut self,
        signer_idx: usize,
        proposal: Proposal<Sha256Digest>,
    ) {
        let Some(vote) = Finalize::sign(&self.schemes[signer_idx], proposal) else {
            return;
        };

        let msg = Vote::<S, Sha256Digest>::Finalize(vote).encode();
        self.send_vote_bytes(signer_idx, msg).await;
    }

    async fn send_finalize_quorum_votes(&mut self, proposal: Proposal<Sha256Digest>) {
        for signer_idx in 0..self.schemes.len() {
            self.send_finalize_vote_for_proposal(signer_idx, proposal.clone())
                .await;
        }
    }

    async fn send_vote_bytes(&mut self, signer_idx: usize, msg: Bytes) {
        let _ = self.vote_senders[signer_idx]
            .send(Recipients::One(self.honest.clone()), msg, true)
            .await;
    }

    async fn send_malformed_vote(&mut self, signer_idx: usize) {
        let msg = self
            .strategy
            .mutate_resolver_bytes(&mut self.context, &[0u8]);
        self.send_vote_bytes(signer_idx, msg.into()).await;
    }

    async fn send_wrong_epoch_notarize_vote_for_proposal(
        &mut self,
        signer_idx: usize,
        proposal: Proposal<Sha256Digest>,
    ) {
        let wrong_epoch = Epoch::new(crate::EPOCH.saturating_add(1));
        let wrong_proposal = Proposal::new(
            Round::new(wrong_epoch, proposal.view()),
            proposal.parent,
            proposal.payload,
        );
        let Some(vote) = Notarize::sign(&self.schemes[signer_idx], wrong_proposal) else {
            return;
        };
        let msg = Vote::<S, Sha256Digest>::Notarize(vote).encode();
        self.send_vote_bytes(signer_idx, msg).await;
    }

    async fn send_certificate_bytes(&mut self, msg: Bytes) {
        let sender_idx = self.next_sender();
        let _ = self.certificate_senders[sender_idx]
            .send(Recipients::One(self.honest.clone()), msg, true)
            .await;
    }

    async fn send_malformed_certificate(&mut self) {
        let msg = self
            .strategy
            .mutate_certificate_bytes(&mut self.context, &[0u8]);
        self.send_certificate_bytes(msg.into()).await;
    }

    async fn send_wrong_epoch_nullification_certificate(&mut self) {
        let view = self.last_vote_view.clamp(1, MAX_SAFE_VIEW);
        let wrong_epoch = Epoch::new(crate::EPOCH.saturating_add(1));
        let round = Round::new(wrong_epoch, View::new(view));
        let Some(cert) = self.build_nullification_from_byz(round, &BYZANTINE_IDS) else {
            return;
        };

        let msg = Certificate::<S, Sha256Digest>::Nullification(cert).encode();
        self.send_certificate_bytes(msg).await;
    }

    async fn send_invalid_notarization_certificate(&mut self) {
        let view = self
            .last_vote_view
            .max(self.last_notarized_view)
            .max(self.last_finalized_view)
            .clamp(1, MAX_SAFE_VIEW);
        let Some(cert) = self.build_invalid_notarization_for_view(view) else {
            return;
        };

        let msg = Certificate::<S, Sha256Digest>::Notarization(cert).encode();
        self.send_certificate_bytes(msg).await;
    }

    async fn send_invalid_nullification_certificate(&mut self) {
        let view = self
            .last_vote_view
            .max(self.last_nullified_view)
            .max(self.last_finalized_view)
            .clamp(1, MAX_SAFE_VIEW);
        let Some(cert) = self.build_invalid_nullification_for_view(view) else {
            return;
        };

        let msg = Certificate::<S, Sha256Digest>::Nullification(cert).encode();
        self.send_certificate_bytes(msg).await;
    }

    // After an honest notarize, inject one Byzantine progress branch for that view:
    // either notarize+finalize/notarization+finalization evidence, or nullification evidence.
    async fn drive_progress(&mut self) {
        let notarized: Vec<_> = self
            .honest_notarize_votes
            .iter()
            .filter(|(proposal, _)| {
                !self
                    .injected_finalize_views
                    .contains(&proposal.view().get())
            })
            .map(|(proposal, _)| (proposal.view().get(), proposal.clone()))
            .collect();

        if notarized.is_empty() {
            return;
        }

        for (view, proposal) in notarized {
            // Intuition: once the honest node notarizes a proposal, either help it complete
            // the notarize/finalize path or force the nullification path, but never both.
            match self.choose_progress_branch() {
                ProgressBranch::NullificationCertificate => {
                    self.send_nullification_certificate_for_view(view).await;
                }
                ProgressBranch::NullifyVotes => {
                    self.send_nullify_quorum_votes(view).await;
                }
                ProgressBranch::NotarizationCertificateAndFinalizationCertificate => {
                    self.send_notarization_certificate_for_proposal(proposal.clone(), true)
                        .await;
                    self.send_finalization_certificate_for_proposal(proposal.clone())
                        .await;
                }
                ProgressBranch::NotarizationCertificateAndFinalizeVotes => {
                    self.send_notarization_certificate_for_proposal(proposal.clone(), true)
                        .await;
                    self.send_finalize_quorum_votes(proposal.clone()).await;
                }
                ProgressBranch::NotarizeVotesAndFinalizationCertificate => {
                    self.send_notarize_quorum_votes(proposal.clone()).await;
                    self.send_finalization_certificate_for_proposal(proposal.clone())
                        .await;
                }
                ProgressBranch::NotarizeVotesAndFinalizeVotes => {
                    self.send_notarize_quorum_votes(proposal.clone()).await;
                    self.send_finalize_quorum_votes(proposal.clone()).await;
                }
            }

            // Keep existing one-shot-per-view behavior.
            self.injected_finalize_views.insert(view);
        }
    }

    async fn send_notarization_certificate_for_proposal(
        &mut self,
        proposal: Proposal<Sha256Digest>,
        prefer_honest_vote: bool,
    ) {
        let view = proposal.view().get();
        let payload = proposal.payload;

        let cert = self.notarization_with_optional_honest_vote(&proposal, prefer_honest_vote);

        let Some((certificate, _)) = cert else {
            return;
        };

        self.notarized_by_view.insert(view, payload);
        self.last_notarized_view = self.last_notarized_view.max(view);

        self.track_certificate(&Certificate::Notarization(certificate.clone()));
        let msg = Certificate::<S, Sha256Digest>::Notarization(certificate).encode();
        self.send_certificate_bytes(msg).await;
    }

    async fn send_notarization_certificate(&mut self) {
        let proposal = self.select_event_proposal();
        let prefer_honest_vote =
            matches!(self.choose_vote_preference(), VotePreference::PreferHonest);

        match self.choose_notarization_certificate_branch() {
            NotarizationCertificateBranch::Normal => {
                self.send_notarization_certificate_for_proposal(proposal, prefer_honest_vote)
                    .await;
            }
            NotarizationCertificateBranch::Malformed => {
                self.send_malformed_certificate().await;
            }
            NotarizationCertificateBranch::WrongEpochNullification => {
                self.send_wrong_epoch_nullification_certificate().await;
            }
            NotarizationCertificateBranch::InvalidNotarization => {
                self.send_invalid_notarization_certificate().await;
            }
        }
    }

    async fn send_nullification_certificate_for_view(&mut self, view: u64) {
        let view = view.max(1);

        let round = Round::new(Epoch::new(crate::EPOCH), View::new(view));
        let cert = self
            .build_nullification_from_byz(round, &BYZANTINE_IDS)
            .expect("byzantine nullification should build");

        self.last_nullified_view = self.last_nullified_view.max(view);

        self.track_certificate(&Certificate::Nullification(cert.clone()));
        let msg = Certificate::<S, Sha256Digest>::Nullification(cert).encode();
        self.send_certificate_bytes(msg).await;
    }

    // Force the honest node to assemble and broadcast a local nullification for
    // an honest-led view so voter::actor can emit the floor certificate branch.
    async fn try_trigger_local_nullification_floor(&mut self) {
        let Some(proposal) = self
            .honest_notarize_votes
            .keys()
            .filter(|proposal| {
                let view = proposal.view().get();
                self.is_elected_honest_leader(view) && proposal.parent.get() > 0
            })
            .max_by_key(|proposal| proposal.view().get())
            .cloned()
        else {
            return;
        };

        let view = proposal.view().get();
        let parent_view = proposal.parent.get();

        if !self.notarized_by_view.contains_key(&parent_view)
            && !self.finalized_by_view.contains_key(&parent_view)
        {
            let Some(parent_proposal) = self.proposal_by_view.get(&parent_view).cloned() else {
                return;
            };
            self.send_notarization_certificate_for_proposal(parent_proposal, true)
                .await;
        }

        self.send_nullify_quorum_votes(view).await;
    }

    async fn send_nullification_certificate(&mut self) {
        let view = self.strategy.mutate_nullify_view(
            &mut self.context,
            self.last_vote_view,
            self.last_finalized_view,
            self.last_notarized_view,
            self.last_nullified_view,
        );

        match self.choose_nullification_certificate_branch() {
            NullificationCertificateBranch::Normal => {
                self.send_nullification_certificate_for_view(view).await;
            }
            NullificationCertificateBranch::TriggerLocalFloor => {
                self.try_trigger_local_nullification_floor().await;
            }
            NullificationCertificateBranch::Malformed => {
                self.send_malformed_certificate().await;
            }
            NullificationCertificateBranch::WrongEpoch => {
                self.send_wrong_epoch_nullification_certificate().await;
            }
            NullificationCertificateBranch::InvalidNullification => {
                self.send_invalid_nullification_certificate().await;
            }
        }
    }

    async fn send_finalization_certificate_for_proposal(
        &mut self,
        proposal: Proposal<Sha256Digest>,
    ) {
        let view = proposal.view().get();
        let payload = proposal.payload;

        if self
            .notarized_by_view
            .get(&view)
            .is_none_or(|d| *d != payload)
        {
            self.send_notarization_certificate_for_proposal(proposal.clone(), true)
                .await;
        }

        let prefer_honest_vote =
            matches!(self.choose_vote_preference(), VotePreference::PreferHonest);
        let cert = self.finalization_with_optional_honest_vote(&proposal, prefer_honest_vote);

        let Some((certificate, _)) = cert else {
            return;
        };

        self.finalized_by_view.insert(view, payload);
        self.last_finalized_view = self.last_finalized_view.max(view);

        self.track_certificate(&Certificate::Finalization(certificate.clone()));
        let msg = Certificate::<S, Sha256Digest>::Finalization(certificate).encode();
        self.send_certificate_bytes(msg).await;
    }

    fn build_invalid_finalization_for_view(
        &mut self,
        view: u64,
    ) -> Option<Finalization<S, Sha256Digest>> {
        let base = self.get_or_build_proposal_for_view(view);
        let valid = self.build_finalization_from_byz(&base, &BYZANTINE_IDS)?;

        let mut conflicting = self.strategy.mutate_proposal(
            &mut self.context,
            &base,
            self.last_vote_view,
            self.last_finalized_view,
            self.last_notarized_view,
            self.last_nullified_view,
        );
        conflicting = self
            .strategy
            .proposal_with_view(&conflicting, base.view().get());
        if conflicting == base {
            conflicting = Proposal::new(
                conflicting.round,
                conflicting.parent,
                self.strategy.random_payload(&mut self.context),
            );
        }
        Some(Finalization {
            proposal: conflicting,
            certificate: valid.certificate,
        })
    }

    async fn send_invalid_finalization_certificate(&mut self) {
        let view = self
            .last_vote_view
            .max(self.last_notarized_view)
            .max(self.last_finalized_view);
        let Some(cert) = self.build_invalid_finalization_for_view(view) else {
            return;
        };

        let msg = Certificate::<S, Sha256Digest>::Finalization(cert).encode();
        self.send_certificate_bytes(msg).await;
    }

    async fn send_finalization_certificate(&mut self) {
        let proposal = self.select_event_proposal();

        match self.choose_finalization_certificate_branch() {
            FinalizationCertificateBranch::Normal => {
                self.send_finalization_certificate_for_proposal(proposal)
                    .await;
            }
            FinalizationCertificateBranch::InvalidFinalization => {
                self.send_invalid_finalization_certificate().await;
            }
        }
    }
}

pub(crate) async fn run<P: simplex::Simplex>(
    context: &mut deterministic::Context,
    input: &NodeFuzzInput,
) -> (Vec<PublicKeyOf<P>>, Vec<P::Scheme>)
where
    PublicKeyOf<P>: Send,
{
    let base = FuzzInput {
        raw_bytes: input.raw_bytes.clone(),
        required_containers: MAX_REQUIRED_CONTAINERS,
        degraded_network: false,
        configuration: N4F3C1,
        partition: Partition::Connected,
        strategy: StrategyChoice::SmallScope {
            fault_rounds: 1,
            fault_rounds_bound: 1,
        },
        messaging_faults: Vec::new(),
        forwarding: input.forwarding,
        certify: input.certify,
    };

    let (oracle, participants, schemes, mut registrations) =
        crate::setup_network::<P>(context, &base).await;

    let (fuzzer_schemes, honest_schemes) = schemes.split_at(BYZANTINE_COUNT);
    let honest_scheme = honest_schemes[0].clone();

    let relay = std::sync::Arc::new(commonware_consensus::simplex::mocks::relay::Relay::new());
    let byzantine_participants: Vec<_> =
        participants.iter().take(BYZANTINE_COUNT).cloned().collect();

    let mut vote_senders = Vec::new();
    let mut certificate_senders = Vec::new();
    let mut resolver_senders = Vec::new();
    let mut vote_receivers = Vec::new();
    let mut certificate_receivers = Vec::new();
    let mut resolver_receivers = Vec::new();

    for byz in participants.iter().take(BYZANTINE_COUNT) {
        let (
            (vote_sender, vote_receiver),
            (cert_sender, cert_receiver),
            (resolver_sender, resolver_receiver),
        ) = registrations
            .remove(byz)
            .expect("byzantine participant must exist");

        vote_senders.push(vote_sender);
        certificate_senders.push(cert_sender);
        resolver_senders.push(resolver_sender);
        vote_receivers.push(vote_receiver);
        certificate_receivers.push(cert_receiver);
        resolver_receivers.push(resolver_receiver);
    }

    let honest = participants[HONEST_ID].clone();
    let honest_channels = registrations
        .remove(&honest)
        .expect("honest participant must exist");
    let (pending, recovered, resolver) = honest_channels;
    let mut reporter = crate::spawn_honest_validator::<P, _, _, _, _, _, _, _>(
        context.child("honest_validator"),
        &oracle,
        &participants,
        honest_scheme,
        honest.clone(),
        <P::Elector as Default>::default(),
        relay.clone(),
        Duration::from_secs(1),
        Duration::from_secs(2),
        base.forwarding,
        pending,
        recovered,
        resolver,
        base.certify,
    );
    let (mut latest, mut monitor): (View, Receiver<View>) = reporter.subscribe().await;
    let elector = <P::Elector as Default>::default().build(fuzzer_schemes[0].participants());

    let mut driver = NodeDriver::<P::Scheme, _>::new(
        context.child("simplex_node_driver"),
        honest,
        relay,
        byzantine_participants,
        fuzzer_schemes.to_vec(),
        vote_senders,
        certificate_senders,
        resolver_senders,
        vote_receivers,
        certificate_receivers,
        resolver_receivers,
        elector,
    );

    for event in input.events.iter() {
        driver.check_finalization(&mut latest, &mut monitor);
        driver.handle_receivers().await;
        driver.drive_progress().await;
        driver.apply_event(*event).await;
    }

    (participants, schemes)
}

pub(crate) fn run_recovery<P: simplex::Simplex>(
    checkpoint: deterministic::Checkpoint,
    participants: Vec<PublicKeyOf<P>>,
    schemes: Vec<P::Scheme>,
    forwarding: ForwardingPolicy,
    certify: crate::CertifyChoice,
) where
    PublicKeyOf<P>: Send,
{
    deterministic::Runner::from(checkpoint).start(|context: deterministic::Context| async move {
        let (network, mut oracle) = simulated::Network::new(
            context.child("network_recovery"),
            simulated::Config {
                max_size: 1024 * 1024,
                disconnect_on_block: false,
                tracked_peer_sets: NZUsize!(1),
            },
        );
        network.start();

        let relay = std::sync::Arc::new(commonware_consensus::simplex::mocks::relay::Relay::new());
        let honest = participants[HONEST_ID].clone();
        let mut registrations =
            crate::utils::register(&mut oracle, std::slice::from_ref(&honest)).await;
        let honest_channels = registrations
            .remove(&honest)
            .expect("honest participant must exist in recovery");
        let (pending, recovered, resolver) = honest_channels;
        let mut reporter = crate::spawn_honest_validator::<P, _, _, _, _, _, _, _>(
            context.child("honest_validator_recovery"),
            &oracle,
            &participants,
            schemes[HONEST_ID].clone(),
            honest,
            <P::Elector as Default>::default(),
            relay,
            Duration::from_secs(1),
            Duration::from_secs(2),
            forwarding,
            pending,
            recovered,
            resolver,
            certify,
        );

        let _ = reporter.subscribe().await;
        context.sleep(std::time::Duration::from_millis(50)).await;
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fuzz_node;
    use commonware_macros::test_group;

    #[test_group("slow")]
    #[test]
    fn test_simplex_node_smoke() {
        let input = NodeFuzzInput {
            raw_bytes: vec![1, 2, 3, 4, 5],
            events: vec![
                NodeEvent {
                    from_node_idx: 0,
                    event: Event::OnNotarize,
                },
                NodeEvent {
                    from_node_idx: 1,
                    event: Event::OnNotarization,
                },
                NodeEvent {
                    from_node_idx: 2,
                    event: Event::OnFinalization,
                },
            ],
            forwarding: ForwardingPolicy::Disabled,
            certify: crate::CertifyChoice::Always,
        };
        fuzz_node::<simplex::SimplexEd25519, WithoutRecovery>(input);
    }

    #[test_group("slow")]
    #[test]
    fn test_simplex_node_recovery_smoke() {
        let input = NodeFuzzInput {
            raw_bytes: vec![9, 8, 7, 6, 5],
            events: vec![
                NodeEvent {
                    from_node_idx: 0,
                    event: Event::OnProposalBroadcastThenNotarize,
                },
                NodeEvent {
                    from_node_idx: 1,
                    event: Event::OnNotarization,
                },
                NodeEvent {
                    from_node_idx: 2,
                    event: Event::OnFinalization,
                },
            ],
            forwarding: ForwardingPolicy::Disabled,
            certify: crate::CertifyChoice::Always,
        };
        fuzz_node::<simplex::SimplexEd25519, WithRecovery>(input);
    }
}
