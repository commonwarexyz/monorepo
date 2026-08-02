//! Durable events, stable outbox actions, snapshots, and replay validation.

pub use super::contracts::obligations::{
    BlockPublication, CertificatePublication, ExitPublication, OwnMessagePublication,
    VotePublication,
};
use super::{Artifact, ArtifactBatch, ArtifactId, ArtifactKind, Profile, Role, ViewProof};
use crate::{
    Epochable, Viewable,
    multimmit::{
        config::Config,
        types::{
            BlockRef, Height, LeaderBlock, ProposalParent, SignedLeaderBlock,
            SignedTransactionBlock, TransactionBlockHeader, VoteBody, Vqc,
        },
    },
    types::{Attributable, Epoch, Participant, Round, View},
};
use commonware_codec::{Encode, EncodeSize};
use commonware_cryptography::{Digest, Hasher, bls12381::primitives::variant::Variant};
use core::{marker::PhantomData, time::Duration};
use std::{collections::BTreeMap, ops::Deref, sync::Arc};

mod codec;
pub use codec::{DomainEventCodecConfig, SnapshotCodecConfig};

/// Durable event and snapshot schema version.
///
/// This version is independent of the network wire version.
pub const DURABILITY_SCHEMA_VERSION: u8 = 0;

// Section versions describe the initial format and leave room for fail-closed schema evolution.
const PUBLICATION_OUTBOX_VERSION: u8 = 0;
const ORDERING_SNAPSHOT_VERSION: u8 = 0;
const SIGNING_RESERVATIONS_VERSION: u8 = 0;
const VIEW_SNAPSHOT_VERSION: u8 = 0;
const OBLIGATIONS_VERSION: u8 = 0;
const JOURNAL_PREFIX_VERSION: u8 = 0;
const COMPONENT_EVENT_VERSION: u8 = 0;

/// The last acknowledged journal position.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Cursor(u64);

impl Cursor {
    /// Returns the empty-journal cursor.
    pub const fn zero() -> Self {
        Self(0)
    }

    /// Returns the journal position.
    pub const fn get(self) -> u64 {
        self.0
    }

    pub(crate) const fn new(value: u64) -> Self {
        Self(value)
    }

    pub(crate) const fn next(self) -> Option<Self> {
        match self.0.checked_add(1) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }
}

/// Stable idempotency identifier for one durable external action.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EffectId(u64);

impl EffectId {
    pub(crate) const fn from_cursor(cursor: Cursor) -> Self {
        Self(cursor.0)
    }

    /// Returns the stable epoch-local sequence.
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Stable family-typed identity for one item in a durable publication.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ObligationId<F> {
    effect: EffectId,
    item: u32,
    marker: PhantomData<fn() -> F>,
}

impl<F> ObligationId<F> {
    pub(crate) const fn new(effect: EffectId, item: u32) -> Self {
        Self {
            effect,
            item,
            marker: PhantomData,
        }
    }

    /// Returns the stable publication effect identity.
    pub const fn effect(self) -> EffectId {
        self.effect
    }

    /// Returns the stable item ordinal within the publication.
    pub const fn item(self) -> u32 {
        self.item
    }
}

/// The network-publication shapes in the durable outbox.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PublicationKind {
    /// One broadcast artifact.
    Broadcast,
    /// One atomic broadcast batch.
    BroadcastBatch,
    /// One leader proposal with its exact parent.
    Propose,
    /// One point-to-point artifact.
    Send,
    /// One atomic point-to-point batch.
    SendBatch,
}

/// A family-typed durable end condition for one publication item.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PublicationDischarge {
    /// A certificate at or above the block height substitutes for the window fact.
    BlockCertifiedAtLeast {
        /// Stable family identity.
        id: ObligationId<BlockPublication>,
        /// Producer chain.
        chain: crate::multimmit::types::ChainId,
        /// Published block height.
        height: Height,
    },
    /// A certificate at or above the vote height makes the share redundant.
    VoteCertifiedAtLeast {
        /// Stable family identity.
        id: ObligationId<VotePublication>,
        /// Producer chain.
        chain: crate::multimmit::types::ChainId,
        /// Voted height.
        height: Height,
    },
    /// Only a strictly higher certificate supersedes a certificate publication.
    CertificateSupersededAbove {
        /// Stable family identity.
        id: ObligationId<CertificatePublication>,
        /// Producer chain.
        chain: crate::multimmit::types::ChainId,
        /// Published certificate height.
        height: Height,
    },
    /// A newer durable exit obligation ends an older push obligation.
    ExitReplacedAfter {
        /// Stable family identity.
        id: ObligationId<ExitPublication>,
        /// Published exit view.
        view: View,
    },
    /// The acknowledged retention floor ends an own-message obligation.
    ViewRetired {
        /// Stable family identity.
        id: ObligationId<OwnMessagePublication>,
        /// Published message view.
        view: View,
    },
}

impl PublicationDischarge {
    /// Returns the containing publication effect.
    pub const fn effect(self) -> EffectId {
        match self {
            Self::BlockCertifiedAtLeast { id, .. } => id.effect(),
            Self::VoteCertifiedAtLeast { id, .. } => id.effect(),
            Self::CertificateSupersededAbove { id, .. } => id.effect(),
            Self::ExitReplacedAfter { id, .. } => id.effect(),
            Self::ViewRetired { id, .. } => id.effect(),
        }
    }

    /// Returns the stable item ordinal.
    pub const fn item(self) -> u32 {
        match self {
            Self::BlockCertifiedAtLeast { id, .. } => id.item(),
            Self::VoteCertifiedAtLeast { id, .. } => id.item(),
            Self::CertificateSupersededAbove { id, .. } => id.item(),
            Self::ExitReplacedAfter { id, .. } => id.item(),
            Self::ViewRetired { id, .. } => id.item(),
        }
    }
}

/// Durable typed publication metadata paired with the outbox's immutable payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicationObligation {
    effect: EffectId,
    kind: PublicationKind,
    discharges: Arc<[PublicationDischarge]>,
}

impl PublicationObligation {
    pub(crate) fn new(
        effect: EffectId,
        kind: PublicationKind,
        discharges: Vec<PublicationDischarge>,
    ) -> Self {
        Self {
            effect,
            kind,
            discharges: discharges.into(),
        }
    }

    /// Returns the stable outbox identity.
    pub const fn effect(&self) -> EffectId {
        self.effect
    }

    /// Returns the exact legacy publication shape.
    #[cfg(test)]
    pub const fn kind(&self) -> PublicationKind {
        self.kind
    }

    /// Returns every family-typed item end condition.
    pub fn discharges(&self) -> &[PublicationDischarge] {
        &self.discharges
    }

    fn payload_artifact<V: Variant, D: Digest>(
        discharge: PublicationDischarge,
        effect: &DurableEffect<V, D>,
    ) -> Option<&Artifact<V, D>> {
        let item = usize::try_from(discharge.item()).ok()?;
        match effect {
            DurableEffect::Broadcast(artifact) if item == 0 => Some(artifact),
            DurableEffect::BroadcastBatch(artifacts) => artifacts.get(item).map(Arc::as_ref),
            DurableEffect::Send(request) if item == 0 => Some(request.artifact()),
            DurableEffect::SendBatch(requests) => requests
                .get(item)
                .map(|request| request.artifact().as_ref()),
            DurableEffect::Sign(_)
            | DurableEffect::SignBatch(_)
            | DurableEffect::Propose(_)
            | DurableEffect::Broadcast(_)
            | DurableEffect::Send(_) => None,
        }
    }

    fn discharge_matches_artifact<V: Variant, D: Digest>(
        discharge: PublicationDischarge,
        artifact: &Artifact<V, D>,
    ) -> bool {
        match (discharge, artifact) {
            (
                PublicationDischarge::BlockCertifiedAtLeast { chain, height, .. },
                Artifact::TransactionBlock(block),
            ) => block.header().chain() == chain && block.header().height() == height,
            (
                PublicationDischarge::VoteCertifiedAtLeast { chain, height, .. },
                Artifact::DaVote(vote),
            ) => vote.header().chain() == chain && vote.header().height() == height,
            (
                PublicationDischarge::CertificateSupersededAbove { chain, height, .. },
                Artifact::DaCertificate(certificate),
            ) => certificate.header().chain() == chain && certificate.header().height() == height,
            (PublicationDischarge::ExitReplacedAfter { view, .. }, Artifact::Vqc(certificate)) => {
                certificate.view() == view
            }
            (
                PublicationDischarge::ExitReplacedAfter { view, .. },
                Artifact::Nullification(certificate),
            ) => certificate.view() == view,
            (PublicationDischarge::ViewRetired { view, .. }, Artifact::LeaderBlock(message)) => {
                message.view() == view
            }
            (PublicationDischarge::ViewRetired { view, .. }, Artifact::Vote(message)) => {
                message.view() == view
            }
            (PublicationDischarge::ViewRetired { view, .. }, Artifact::NoVote(message)) => {
                message.view() == view
            }
            (PublicationDischarge::ViewRetired { view, .. }, Artifact::Nullify(message)) => {
                message.view() == view
            }
            (PublicationDischarge::ViewRetired { view, .. }, Artifact::Lqc(message)) => {
                message.view() == view
            }
            _ => false,
        }
    }

    pub(crate) fn matches_payload<V: Variant, D: Digest>(
        &self,
        effect: &DurableEffect<V, D>,
    ) -> bool {
        let kind_matches = matches!(
            (self.kind, effect),
            (PublicationKind::Broadcast, DurableEffect::Broadcast(_))
                | (
                    PublicationKind::BroadcastBatch,
                    DurableEffect::BroadcastBatch(_)
                )
                | (PublicationKind::Propose, DurableEffect::Propose(_))
                | (PublicationKind::Send, DurableEffect::Send(_))
                | (PublicationKind::SendBatch, DurableEffect::SendBatch(_))
        );
        if !kind_matches {
            return false;
        }

        self.discharges.iter().copied().all(|discharge| {
            if let DurableEffect::Propose(proposal) = effect {
                return discharge.item() == 0
                    && matches!(discharge, PublicationDischarge::ViewRetired { view, .. }
                        if proposal.block().view() == view);
            }
            Self::payload_artifact(discharge, effect)
                .is_some_and(|artifact| Self::discharge_matches_artifact(discharge, artifact))
        })
    }
}

/// Identifies one exact persistence barrier within a process generation.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BarrierId(u64);

impl BarrierId {
    pub(crate) const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the generation-local sequence.
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// An exact typed subject the local scheme may sign.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SignRequest<V: Variant, D: Digest> {
    /// Authorize one producer-chain header.
    TransactionBlock(TransactionBlockHeader<D>),
    /// Authorize one data-availability share after local eligibility is durable.
    DaVote(DaVoteRequest<V, D>),
    /// Authorize one scheduled leader proposal and retain its exact parent certificate.
    LeaderBlock(ProposalRequest<V, D>),
    /// Authorize one ordinary signature over a complete vote body.
    Vote(VoteRequest<D>),
    /// Authorize an abstention for one round.
    NoVote {
        /// The exact round.
        round: Round,
    },
    /// Authorize a nullification share for one round.
    Nullify {
        /// The exact round.
        round: Round,
    },
}

impl<V: Variant, D: Digest> SignRequest<V, D> {
    pub(crate) fn consensus_view(&self) -> Option<View> {
        match self {
            Self::TransactionBlock(_) | Self::DaVote(_) => None,
            Self::LeaderBlock(request) => Some(request.block().view()),
            Self::Vote(request) => Some(request.body().view()),
            Self::NoVote { round } | Self::Nullify { round } => Some(round.view()),
        }
    }

    pub(crate) fn matches_context(&self, epoch: Epoch) -> bool {
        match self {
            Self::TransactionBlock(header) => header.epoch() == epoch,
            Self::DaVote(request) => request.header().epoch() == epoch,
            Self::LeaderBlock(request) => request.block().epoch() == epoch,
            Self::Vote(request) => request.body().epoch() == epoch,
            Self::NoVote { round } | Self::Nullify { round } => round.epoch() == epoch,
        }
    }

    pub(crate) fn matches(&self, signer: Participant, artifact: &Artifact<V, D>) -> bool {
        if artifact.signer() != Some(signer) {
            return false;
        }
        match (self, artifact) {
            (Self::TransactionBlock(expected), Artifact::TransactionBlock(actual)) => {
                expected == actual.header()
            }
            (Self::DaVote(expected), Artifact::DaVote(actual)) => {
                expected.header() == actual.header()
            }
            (Self::LeaderBlock(expected), Artifact::LeaderBlock(actual)) => {
                expected.block() == actual.block()
            }
            (Self::Vote(expected), Artifact::Vote(actual)) => expected.body() == actual.body(),
            (Self::NoVote { round, .. }, Artifact::NoVote(actual)) => *round == actual.round(),
            (Self::Nullify { round, .. }, Artifact::Nullify(actual)) => *round == actual.round(),
            _ => false,
        }
    }
}

/// A DA-vote subject and the exact authenticated block whose availability it promises.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DaVoteRequest<V: Variant, D: Digest> {
    block: Arc<SignedTransactionBlock<V, D>>,
}

impl<V: Variant, D: Digest> DaVoteRequest<V, D> {
    pub(crate) const fn new(block: Arc<SignedTransactionBlock<V, D>>) -> Self {
        Self { block }
    }

    /// Returns the header authorized by this request.
    pub fn header(&self) -> &TransactionBlockHeader<D> {
        self.block.header()
    }

    /// Returns the authenticated subject of the durable DA-vote authorization.
    pub const fn block(&self) -> &Arc<SignedTransactionBlock<V, D>> {
        &self.block
    }
}

/// One exact vote body authorized for signing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VoteRequest<D: Digest> {
    body: VoteBody<D>,
}

impl<D: Digest> VoteRequest<D> {
    pub(crate) const fn new(body: VoteBody<D>) -> Self {
        Self { body }
    }

    /// Returns the exact body to sign.
    pub const fn body(&self) -> &VoteBody<D> {
        &self.body
    }
}

/// An exact leader block, its parent V-QC, and the durable choice to transmit that parent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProposalRequest<V: Variant, D: Digest> {
    block: LeaderBlock<V, D>,
    parent: ProposalParent<Arc<Vqc<V, D>>>,
    attach_parent: bool,
}

impl<V: Variant, D: Digest> ProposalRequest<V, D> {
    pub(crate) const fn new(
        block: LeaderBlock<V, D>,
        parent: ProposalParent<Arc<Vqc<V, D>>>,
        attach_parent: bool,
    ) -> Self {
        Self {
            block,
            parent,
            attach_parent,
        }
    }

    /// Returns the exact unsigned block to sign.
    pub const fn block(&self) -> &LeaderBlock<V, D> {
        &self.block
    }

    /// Returns the exact non-genesis parent referenced by the signed block.
    pub const fn parent(&self) -> &ProposalParent<Arc<Vqc<V, D>>> {
        &self.parent
    }

    /// Returns whether the exact parent must accompany the proposal.
    pub const fn attach_parent(&self) -> bool {
        self.attach_parent
    }
}

/// One exact proposal publication with its durable parent-transmission choice.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProposalPublication<V: Variant, D: Digest> {
    block: Arc<SignedLeaderBlock<V, D>>,
    parent: ProposalParent<Arc<Vqc<V, D>>>,
    attach_parent: bool,
}

impl<V: Variant, D: Digest> ProposalPublication<V, D> {
    pub(crate) const fn new(
        block: Arc<SignedLeaderBlock<V, D>>,
        parent: ProposalParent<Arc<Vqc<V, D>>>,
        attach_parent: bool,
    ) -> Self {
        Self {
            block,
            parent,
            attach_parent,
        }
    }

    /// Returns the signed leader block.
    pub const fn block(&self) -> &Arc<SignedLeaderBlock<V, D>> {
        &self.block
    }

    /// Returns the exact proposal parent.
    pub const fn parent(&self) -> &ProposalParent<Arc<Vqc<V, D>>> {
        &self.parent
    }

    /// Returns whether the exact parent must accompany the proposal.
    pub const fn attach_parent(&self) -> bool {
        self.attach_parent
    }
}

/// One exact point-to-point protocol publication.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SendRequest<V: Variant, D: Digest> {
    recipient: Participant,
    artifact: Arc<Artifact<V, D>>,
}

impl<V: Variant, D: Digest> SendRequest<V, D> {
    pub(crate) const fn new(recipient: Participant, artifact: Arc<Artifact<V, D>>) -> Self {
        Self {
            recipient,
            artifact,
        }
    }

    /// Returns the sole intended recipient.
    pub const fn recipient(&self) -> Participant {
        self.recipient
    }

    /// Returns the exact canonical artifact to send.
    pub const fn artifact(&self) -> &Arc<Artifact<V, D>> {
        &self.artifact
    }
}

/// An external action whose authorization and stable ID survive recovery.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DurableEffect<V: Variant, D: Digest> {
    /// Sign an exact typed subject.
    Sign(SignRequest<V, D>),
    /// Atomically sign a set of subjects that must be published together.
    SignBatch(Arc<[SignRequest<V, D>]>),
    /// Broadcast an exact canonical protocol artifact.
    Broadcast(Arc<Artifact<V, D>>),
    /// Atomically broadcast artifacts created by one signing choice.
    BroadcastBatch(ArtifactBatch<V, D>),
    /// Publish a signed proposal with its exact referenced non-genesis V-QC.
    Propose(ProposalPublication<V, D>),
    /// Send an exact canonical protocol artifact to one participant.
    Send(SendRequest<V, D>),
    /// Atomically send artifacts created by one signing choice, each to its own recipient.
    SendBatch(Arc<[SendRequest<V, D>]>),
}

impl<V: Variant, D: Digest> DurableEffect<V, D> {
    pub(crate) const fn is_signing(&self) -> bool {
        matches!(self, Self::Sign(_) | Self::SignBatch(_))
    }

    pub(crate) const fn is_network_publication(&self) -> bool {
        matches!(
            self,
            Self::Broadcast(_)
                | Self::BroadcastBatch(_)
                | Self::Propose(_)
                | Self::Send(_)
                | Self::SendBatch(_)
        )
    }

    /// Returns every artifact this effect carries.
    pub fn artifacts(&self) -> Vec<&Arc<Artifact<V, D>>> {
        match self {
            Self::Broadcast(artifact) => vec![artifact],
            Self::BroadcastBatch(artifacts) => artifacts.iter().collect(),
            Self::Send(request) => vec![request.artifact()],
            Self::SendBatch(requests) => requests.iter().map(SendRequest::artifact).collect(),
            Self::Sign(_) | Self::SignBatch(_) | Self::Propose(_) => Vec::new(),
        }
    }

    /// Returns whether releasing this effect could externalize one of `me`'s signatures.
    ///
    /// Individually attributed artifacts expose exactly their signer; certificates aggregate
    /// unattributed shares, so any aggregate may embed one of `me`'s votes and counts as a
    /// reference. Signing requests carry no signature: only the publication of their result
    /// does. Capabilities with no such reference are safe to release before their record is
    /// durable, because every message they carry is independently verifiable and could have
    /// been sent by any peer.
    pub(crate) fn references_own_signature(&self, me: Option<Participant>) -> bool {
        // An aggregate certificate (no single signer) may embed one of our shares.
        let references = |artifact: &Arc<Artifact<V, D>>| {
            artifact.signer().is_none_or(|signer| Some(signer) == me)
        };
        match self {
            Self::Sign(_) | Self::SignBatch(_) => false,
            Self::Broadcast(artifact) => references(artifact),
            Self::BroadcastBatch(artifacts) => artifacts.iter().any(references),
            Self::Propose(_) => true,
            Self::Send(request) => references(request.artifact()),
            Self::SendBatch(requests) => requests
                .iter()
                .any(|request| references(request.artifact())),
        }
    }

    pub(crate) fn publication(
        artifact: Arc<Artifact<V, D>>,
        request: Option<&SignRequest<V, D>>,
        protocol: &Config<D>,
    ) -> Option<Self> {
        if let (Artifact::LeaderBlock(block), Some(SignRequest::LeaderBlock(proposal))) =
            (artifact.as_ref(), request)
        {
            return Some(Self::Propose(ProposalPublication::new(
                Arc::new(block.clone()),
                proposal.parent().clone(),
                proposal.attach_parent(),
            )));
        }
        match artifact.as_ref() {
            Artifact::LeaderBlock(_) => None,
            Artifact::DaVote(vote) => protocol
                .producer(vote.header().chain())
                .map(|producer| Self::Send(SendRequest::new(producer, artifact))),
            _ => Some(Self::Broadcast(artifact)),
        }
    }

    pub(crate) fn publication_batch(
        artifacts: ArtifactBatch<V, D>,
        protocol: &Config<D>,
    ) -> Option<Self> {
        if artifacts.is_empty() {
            return None;
        }
        if artifacts
            .iter()
            .all(|artifact| matches!(artifact.as_ref(), Artifact::DaVote(_)))
        {
            let requests = artifacts
                .iter()
                .map(|artifact| {
                    let Artifact::DaVote(vote) = artifact.as_ref() else {
                        unreachable!("the batch holds only data-availability votes");
                    };
                    protocol
                        .producer(vote.header().chain())
                        .map(|producer| SendRequest::new(producer, Arc::clone(artifact)))
                })
                .collect::<Option<Vec<_>>>()?;
            return Some(Self::SendBatch(requests.into()));
        }
        artifacts
            .iter()
            .all(|artifact| {
                !matches!(
                    artifact.as_ref(),
                    Artifact::LeaderBlock(_) | Artifact::DaVote(_)
                )
            })
            .then_some(Self::BroadcastBatch(artifacts))
    }

    pub(crate) fn authorized<H: Hasher<Digest = D>>(&self, profile: &Profile<H, V>) -> bool {
        let protocol = profile.protocol();
        match self {
            Self::Sign(request) => {
                let Role::Validator(participant) = profile.role() else {
                    return false;
                };
                request.matches_context(protocol.epoch())
                    && match request {
                        SignRequest::TransactionBlock(header) => {
                            protocol.producer(header.chain()) == Some(participant)
                        }
                        SignRequest::DaVote(request) => {
                            (request.header().chain().get() as usize)
                                < protocol.codec_config().chains()
                        }
                        SignRequest::LeaderBlock(request) => {
                            proposal_parent_valid::<H, V, D>(
                                request.block(),
                                request.parent(),
                                profile,
                            ) && (!request.attach_parent() || request.parent().exact().is_some())
                        }
                        _ => true,
                    }
            }
            Self::SignBatch(requests) => {
                let Role::Validator(_) = profile.role() else {
                    return false;
                };
                if requests.is_empty()
                    || !requests
                        .iter()
                        .all(|request| request.matches_context(protocol.epoch()))
                {
                    return false;
                }
                let timeout_pair = requests.len() == 2
                    && matches!(
                        (&requests[0], &requests[1]),
                        (
                            SignRequest::NoVote { round: left },
                            SignRequest::Nullify { round: right }
                        ) if left == right
                    );
                // One data-availability vote per producer chain may share a signing barrier:
                // the requests are independent attestations whose only coupling is the sync
                // that makes them safe to sign.
                let mut chains = std::collections::BTreeSet::new();
                let da_votes = requests.iter().all(|request| {
                    matches!(request, SignRequest::DaVote(request)
                        if (request.header().chain().get() as usize)
                            < protocol.codec_config().chains()
                            && chains.insert(request.header().chain()))
                });
                timeout_pair || da_votes
            }
            Self::Broadcast(artifact) => {
                !matches!(artifact.as_ref(), Artifact::DaVote(_))
                    && artifact.encoded_len() <= profile.resources().max_artifact_bytes()
                    && artifact.epoch() == protocol.epoch()
                    && artifact.signer().is_none_or(|participant| {
                        (participant.get() as usize) < protocol.codec_config().participants()
                    })
            }
            Self::BroadcastBatch(artifacts) => {
                let timeout = match (profile.role(), artifacts.as_ref()) {
                    (Role::Validator(signer), [novote_artifact, nullify_artifact]) => {
                        match (novote_artifact.as_ref(), nullify_artifact.as_ref()) {
                            (Artifact::NoVote(novote), Artifact::Nullify(nullify)) => {
                                novote.signer() == signer
                                    && nullify.signer() == signer
                                    && novote.round() == nullify.round()
                            }
                            _ => false,
                        }
                    }
                    _ => false,
                };
                timeout
                    && artifacts.iter().all(|artifact| {
                        artifact.encoded_len() <= profile.resources().max_artifact_bytes()
                            && artifact.epoch() == protocol.epoch()
                    })
            }
            Self::Propose(publication) => {
                let block = publication.block();
                let expected = protocol.leader(block.view());
                block.signer() == expected
                    && block.epoch() == protocol.epoch()
                    && block.encode_size() <= profile.resources().max_artifact_bytes()
                    && (!publication.attach_parent() || publication.parent().exact().is_some())
                    && proposal_parent_valid::<H, V, D>(
                        block.block(),
                        publication.parent(),
                        profile,
                    )
            }
            Self::Send(request) => {
                matches!((profile.role(), request.artifact().as_ref()),
                    (Role::Validator(sender), Artifact::DaVote(vote))
                        if protocol.producer(vote.header().chain()) == Some(request.recipient())
                            && vote.signer() == sender)
                    && (request.recipient().get() as usize) < protocol.codec_config().participants()
                    && request.artifact().encoded_len() <= profile.resources().max_artifact_bytes()
                    && request.artifact().epoch() == protocol.epoch()
                    && request.artifact().signer().is_none_or(|participant| {
                        (participant.get() as usize) < protocol.codec_config().participants()
                    })
            }
            Self::SendBatch(requests) => {
                !requests.is_empty()
                    && requests.iter().all(|request| {
                        matches!((profile.role(), request.artifact().as_ref()),
                            (Role::Validator(sender), Artifact::DaVote(vote))
                                if protocol.producer(vote.header().chain()) == Some(request.recipient())
                                    && vote.signer() == sender)
                            && (request.recipient().get() as usize)
                                < protocol.codec_config().participants()
                            && request.artifact().encoded_len()
                                <= profile.resources().max_artifact_bytes()
                            && request.artifact().epoch() == protocol.epoch()
                    })
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SigningReservations<V: Variant, D: Digest> {
    entries: BTreeMap<EffectId, DurableEffect<V, D>>,
}

impl<V: Variant, D: Digest> Default for SigningReservations<V, D> {
    fn default() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }
}

impl<V: Variant, D: Digest> SigningReservations<V, D> {
    pub(crate) fn from_entries(entries: BTreeMap<EffectId, DurableEffect<V, D>>) -> Option<Self> {
        entries
            .values()
            .all(DurableEffect::is_signing)
            .then_some(Self { entries })
    }

    pub(crate) fn insert(
        &mut self,
        id: EffectId,
        effect: DurableEffect<V, D>,
    ) -> Option<DurableEffect<V, D>> {
        assert!(
            effect.is_signing(),
            "SigningReservations only accepts Sign and SignBatch effects"
        );
        self.entries.insert(id, effect)
    }

    pub(crate) fn remove(&mut self, id: &EffectId) -> Option<DurableEffect<V, D>> {
        self.entries.remove(id)
    }

    pub(crate) fn valid(&self) -> bool {
        self.entries.values().all(DurableEffect::is_signing)
    }
}

impl<V: Variant, D: Digest> Deref for SigningReservations<V, D> {
    type Target = BTreeMap<EffectId, DurableEffect<V, D>>;

    fn deref(&self) -> &Self::Target {
        &self.entries
    }
}

impl<'a, V: Variant, D: Digest> IntoIterator for &'a SigningReservations<V, D> {
    type Item = (&'a EffectId, &'a DurableEffect<V, D>);
    type IntoIter = std::collections::btree_map::Iter<'a, EffectId, DurableEffect<V, D>>;

    fn into_iter(self) -> Self::IntoIter {
        self.entries.iter()
    }
}

/// The durable transition dimension for one retained view.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub(crate) enum ViewTransition<D: Digest> {
    #[default]
    Active,
    Exited(ArtifactId<D>),
}

/// The durable local voting choice for one retained view.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) enum ViewStance<D: Digest> {
    #[default]
    Unchosen,
    Voted(VoteBody<D>),
    NoVoted,
}

/// Whether this node durably authorized a nullification share for one retained view.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub(crate) enum ViewNullification {
    #[default]
    Unsigned,
    Signed,
}

/// The exact stable product state for one retained view.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ViewSlotSnapshot<V: Variant, D: Digest> {
    pub(crate) transition: ViewTransition<D>,
    pub(crate) stance: ViewStance<D>,
    pub(crate) nullification: ViewNullification,
    pub(crate) proposal: Option<LeaderBlock<V, D>>,
}

impl<V: Variant, D: Digest> Default for ViewSlotSnapshot<V, D> {
    fn default() -> Self {
        Self {
            transition: ViewTransition::Active,
            stance: ViewStance::Unchosen,
            nullification: ViewNullification::Unsigned,
            proposal: None,
        }
    }
}

impl<V: Variant, D: Digest> ViewSlotSnapshot<V, D> {
    fn observe_proposal(&mut self, block: LeaderBlock<V, D>) -> Result<(), ReplayError> {
        if let Some(existing) = &self.proposal {
            return (existing == &block)
                .then_some(())
                .ok_or(ReplayError::Transition);
        }
        self.proposal = Some(block);
        Ok(())
    }

    fn observe_vote(&mut self, body: VoteBody<D>) -> Result<(), ReplayError> {
        match &self.stance {
            ViewStance::Unchosen => self.stance = ViewStance::Voted(body),
            ViewStance::Voted(existing) if existing == &body => {}
            ViewStance::Voted(_) | ViewStance::NoVoted => return Err(ReplayError::Transition),
        }
        Ok(())
    }

    fn observe_novote(&mut self) -> Result<(), ReplayError> {
        match self.stance {
            ViewStance::Unchosen => self.stance = ViewStance::NoVoted,
            ViewStance::NoVoted => {}
            ViewStance::Voted(_) => return Err(ReplayError::Transition),
        }
        Ok(())
    }

    const fn observe_nullify(&mut self) {
        self.nullification = ViewNullification::Signed;
    }

    fn observe_exit(&mut self, proof: ArtifactId<D>) -> Result<(), ReplayError> {
        match self.transition {
            ViewTransition::Active => self.transition = ViewTransition::Exited(proof),
            ViewTransition::Exited(existing) if existing == proof => {}
            ViewTransition::Exited(_) => return Err(ReplayError::Transition),
        }
        Ok(())
    }

    const fn stable(&self) -> bool {
        !matches!(
            (&self.stance, self.nullification),
            (ViewStance::Unchosen, ViewNullification::Signed)
                | (ViewStance::NoVoted, ViewNullification::Unsigned)
        )
    }
}

/// Canonical stable View state at one acknowledged checkpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ViewSnapshot<V: Variant, D: Digest> {
    pub(crate) slots: BTreeMap<View, ViewSlotSnapshot<V, D>>,
}

impl<V: Variant, D: Digest> Default for ViewSnapshot<V, D> {
    fn default() -> Self {
        Self {
            slots: BTreeMap::new(),
        }
    }
}

/// Versioned owner of durable network-publication effects.
///
/// Signing reservations own signing effects; this outbox permanently owns the network
/// publication forms until their typed obligations are discharged.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicationOutbox<V: Variant, D: Digest> {
    version: u8,
    entries: BTreeMap<EffectId, DurableEffect<V, D>>,
}

impl<V: Variant, D: Digest> Default for PublicationOutbox<V, D> {
    fn default() -> Self {
        Self {
            version: PUBLICATION_OUTBOX_VERSION,
            entries: BTreeMap::new(),
        }
    }
}

impl<V: Variant, D: Digest> PublicationOutbox<V, D> {
    /// Returns the publication-outbox schema version.
    pub const fn version(&self) -> u8 {
        self.version
    }

    /// Returns every outstanding publication in stable identifier order.
    pub const fn entries(&self) -> &BTreeMap<EffectId, DurableEffect<V, D>> {
        &self.entries
    }

    pub(crate) fn from_entries(entries: BTreeMap<EffectId, DurableEffect<V, D>>) -> Option<Self> {
        entries
            .values()
            .all(DurableEffect::is_network_publication)
            .then_some(Self {
                version: PUBLICATION_OUTBOX_VERSION,
                entries,
            })
    }

    pub(crate) fn insert(
        &mut self,
        id: EffectId,
        effect: DurableEffect<V, D>,
    ) -> Option<DurableEffect<V, D>> {
        assert!(
            effect.is_network_publication(),
            "PublicationOutbox only accepts network-publication effects"
        );
        self.entries.insert(id, effect)
    }

    pub(crate) fn remove(&mut self, id: &EffectId) -> Option<DurableEffect<V, D>> {
        self.entries.remove(id)
    }

    pub(crate) fn valid(&self) -> bool {
        self.entries
            .values()
            .all(DurableEffect::is_network_publication)
    }
}

impl<V: Variant, D: Digest> Deref for PublicationOutbox<V, D> {
    type Target = BTreeMap<EffectId, DurableEffect<V, D>>;

    fn deref(&self) -> &Self::Target {
        &self.entries
    }
}

impl<'a, V: Variant, D: Digest> IntoIterator for &'a PublicationOutbox<V, D> {
    type Item = (&'a EffectId, &'a DurableEffect<V, D>);
    type IntoIter = std::collections::btree_map::Iter<'a, EffectId, DurableEffect<V, D>>;

    fn into_iter(self) -> Self::IntoIter {
        self.entries.iter()
    }
}

fn proposal_parent_valid<H, V, D>(
    block: &LeaderBlock<V, D>,
    parent: &ProposalParent<Arc<Vqc<V, D>>>,
    profile: &Profile<H, V>,
) -> bool
where
    H: Hasher<Digest = D>,
    V: Variant,
    D: Digest,
{
    let protocol = profile.protocol();
    match parent {
        ProposalParent::Genesis => block.parent() == protocol.genesis().vqc(),
        ProposalParent::Exact(parent) => {
            block.parent() != protocol.genesis().vqc()
                && parent.epoch() == protocol.epoch()
                && parent.view() < block.view()
                && parent.encode_size() <= profile.resources().max_artifact_bytes()
                && block.parent() == parent.id::<H>()
        }
    }
}

/// One stable outbox action released only after its journal event is durable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DurableJob<T> {
    id: EffectId,
    generation: u64,
    request: T,
}

impl<T> DurableJob<T> {
    pub(crate) const fn new(id: EffectId, generation: u64, request: T) -> Self {
        Self {
            id,
            generation,
            request,
        }
    }

    /// Returns the stable idempotency identifier.
    #[cfg(any(test, feature = "test-utils"))]
    pub const fn id(&self) -> EffectId {
        self.id
    }

    /// Returns the process generation issuing this attempt.
    #[cfg(any(test, feature = "test-utils"))]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns the exact immutable action.
    #[cfg(any(test, feature = "test-utils"))]
    pub const fn request(&self) -> &T {
        &self.request
    }

    /// Consumes the job and returns its stable identity and exact action.
    pub fn into_parts(self) -> (EffectId, u64, T) {
        (self.id, self.generation, self.request)
    }
}

/// A logical timer interpreted by an attached runtime.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Timer {
    generation: u64,
    round: Round,
    delay: Duration,
}

impl Timer {
    pub(crate) const fn new(generation: u64, round: Round, delay: Duration) -> Self {
        Self {
            generation,
            round,
            delay,
        }
    }

    /// Returns the process generation owning this timer.
    pub const fn generation(self) -> u64 {
        self.generation
    }

    /// Returns the exact round whose timeout this timer represents.
    pub const fn round(self) -> Round {
        self.round
    }

    /// Returns the logical delay requested from the runtime.
    pub const fn delay(self) -> Duration {
        self.delay
    }
}

/// One versioned state transition written to the safety journal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DomainEvent<V: Variant, D: Digest> {
    epoch: Epoch,
    cursor: Cursor,
    change: Change<V, D>,
}

impl<V: Variant, D: Digest> DomainEvent<V, D> {
    pub(crate) const fn new(epoch: Epoch, cursor: Cursor, change: Change<V, D>) -> Self {
        Self {
            epoch,
            cursor,
            change,
        }
    }

    /// Returns the bound epoch.
    pub const fn epoch(&self) -> Epoch {
        self.epoch
    }

    /// Returns the exact journal position.
    pub const fn cursor(&self) -> Cursor {
        self.cursor
    }

    /// Returns the typed durable state change.
    pub const fn change(&self) -> &Change<V, D> {
        &self.change
    }

    /// Returns the permanent owner tag encoded by the outer event envelope.
    pub const fn component(&self) -> DurableComponent {
        self.change.component()
    }
}

/// A durable machine state change.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Change<V: Variant, D: Digest> {
    /// Starts a new process generation after startup or recovery.
    GenerationAdvanced(u64),
    /// Adds one stable external action to the durable outbox.
    OutboxQueued {
        /// Stable action identifier.
        id: EffectId,
        /// Exact immutable action.
        effect: Box<DurableEffect<V, D>>,
    },
    /// Atomically retains one locally signed artifact and replaces its signing job with publication.
    SignedArtifact {
        /// Completed signing action.
        sign: EffectId,
        /// Stable publication action created by this transition.
        publication: EffectId,
        /// Exact locally signed artifact retained across publication attempts.
        artifact: Arc<Artifact<V, D>>,
    },
    /// Atomically retains locally signed artifacts and replaces their batch-signing job.
    SignedArtifactBatch {
        /// Completed batch-signing action.
        sign: EffectId,
        /// Stable atomic publication created by this transition.
        publication: EffectId,
        /// Exact locally signed artifacts retained across publication attempts.
        artifacts: ArtifactBatch<V, D>,
    },
    /// Atomically retains one locally constructed artifact and publishes it.
    ArtifactCreated {
        /// Stable publication action created by this transition.
        publication: EffectId,
        /// Exact locally constructed artifact retained across publication attempts.
        artifact: Arc<Artifact<V, D>>,
    },
    /// Advances one chain's durable DA floor and atomically retires its obsolete live work.
    DaCertificateAdvanced {
        /// Publication installed for a locally assembled certificate.
        publication: Option<EffectId>,
        /// Publications made obsolete by this certificate.
        retired: Vec<EffectId>,
        /// Highest accepted certificate for the chain.
        artifact: Arc<Artifact<V, D>>,
    },
    /// Retains one locally assembled view certificate before representative selection.
    ViewCertificateCreated {
        /// Exact locally assembled V-QC or nullification.
        artifact: Arc<Artifact<V, D>>,
    },
    /// Durably marks and broadcasts the selected first certificate for one view.
    ArtifactForwarded {
        /// Stable publication action created by this transition.
        publication: EffectId,
        /// Older exit push obligations discharged by this durable successor.
        retired: Vec<EffectId>,
        /// Exact authenticated certificate selected by observation order.
        artifact: Arc<Artifact<V, D>>,
    },
    /// Advances exactly one view using an authenticated current-view exit proof.
    ViewAdvanced {
        /// Identifier of the retained V-QC or nullification authorizing the transition.
        proof: ArtifactId<D>,
        /// Own-message obligations ended by the new retention floor.
        retired: Vec<EffectId>,
    },
    /// Raises the signing view through an independently authenticated finalization.
    FinalityFloorAdvanced {
        /// Exact L-QC proving finality at the skipped-through view.
        proof: Arc<Artifact<V, D>>,
        /// Obsolete consensus signing requests retired by the floor.
        retired: Vec<EffectId>,
        /// Own-message obligations ended by the new retention floor.
        publication_retired: Vec<EffectId>,
    },
}

/// Exact append-and-sync work for one safety-journal barrier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PersistJob<V: Variant, D: Digest> {
    id: BarrierId,
    generation: u64,
    previous: Cursor,
    events: Arc<Vec<DomainEvent<V, D>>>,
    urgent: bool,
}

impl<V: Variant, D: Digest> PersistJob<V, D> {
    /// Returns whether an external release is gated on this exact barrier's durability.
    ///
    /// The machine marks a barrier urgent when one of its events records a fresh local
    /// signature (its publication must not leave before the record is durable) or starts a
    /// generation (the recovered outbox re-releases at its acknowledgement). Non-urgent
    /// barriers may defer their sync to a later covering barrier.
    pub const fn urgent(&self) -> bool {
        self.urgent
    }

    pub(crate) fn new(
        id: BarrierId,
        generation: u64,
        previous: Cursor,
        events: Vec<DomainEvent<V, D>>,
        urgent: bool,
    ) -> Self {
        Self {
            id,
            generation,
            previous,
            events: Arc::new(events),
            urgent,
        }
    }

    /// Returns the exact barrier identifier.
    pub const fn id(&self) -> BarrierId {
        self.id
    }

    /// Returns the process generation that issued the write.
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns the cursor that must precede this batch.
    pub const fn previous(&self) -> Cursor {
        self.previous
    }

    /// Extends this batch by one contiguous event.
    pub(crate) fn push_event(&mut self, event: DomainEvent<V, D>, urgent: bool) {
        Arc::make_mut(&mut self.events).push(event);
        self.urgent |= urgent;
    }

    pub(crate) fn shared_events(&self) -> Arc<Vec<DomainEvent<V, D>>> {
        Arc::clone(&self.events)
    }

    /// Returns the exact ordered journal entries.
    pub fn events(&self) -> &[DomainEvent<V, D>] {
        self.events.as_slice()
    }

    /// Returns the final cursor established by this barrier.
    pub fn last_cursor(&self) -> Cursor {
        self.events
            .last()
            .map_or(self.previous, DomainEvent::cursor)
    }
}

/// One machine-issued journal barrier and work fenced by its admission.
///
/// After the journal accepts the barrier, resolver custody is installed before the paired
/// independently verifiable publications are released. The optional effect pair associates a
/// completed local sign with the publication whose persistence latency it measures.
#[derive(Clone, Debug)]
pub(crate) struct PersistDirective<V: Variant, D: Digest> {
    job: PersistJob<V, D>,
    staged_retention: Vec<Arc<Artifact<V, D>>>,
    release_after_enqueue: Vec<DurableJob<DurableEffect<V, D>>>,
    signed_publication: Option<(EffectId, EffectId)>,
}

type PersistDirectiveParts<V, D> = (
    PersistJob<V, D>,
    Vec<Arc<Artifact<V, D>>>,
    Vec<DurableJob<DurableEffect<V, D>>>,
    Option<(EffectId, EffectId)>,
);

impl<V: Variant, D: Digest> PersistDirective<V, D> {
    pub(crate) const fn new(
        job: PersistJob<V, D>,
        staged_retention: Vec<Arc<Artifact<V, D>>>,
        release_after_enqueue: Vec<DurableJob<DurableEffect<V, D>>>,
        signed_publication: Option<(EffectId, EffectId)>,
    ) -> Self {
        Self {
            job,
            staged_retention,
            release_after_enqueue,
            signed_publication,
        }
    }

    #[cfg(any(test, feature = "test-utils"))]
    pub(crate) const fn job(&self) -> &PersistJob<V, D> {
        &self.job
    }

    pub(crate) fn into_parts(self) -> PersistDirectiveParts<V, D> {
        (
            self.job,
            self.staged_retention,
            self.release_after_enqueue,
            self.signed_publication,
        )
    }
}

impl<V: Variant, D: Digest> Deref for PersistDirective<V, D> {
    type Target = PersistJob<V, D>;

    fn deref(&self) -> &Self::Target {
        &self.job
    }
}

/// Acknowledgement of one exact persistence barrier and covered journal prefix.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct BarrierAck {
    barrier: BarrierId,
    generation: u64,
    cursor: Cursor,
}

impl BarrierAck {
    /// Creates an acknowledgement for an exact machine-issued persistence job.
    pub const fn new(barrier: BarrierId, generation: u64, cursor: Cursor) -> Self {
        Self {
            barrier,
            generation,
            cursor,
        }
    }

    /// Returns the completed barrier.
    pub const fn barrier(self) -> BarrierId {
        self.barrier
    }

    /// Returns the issuing process generation.
    pub const fn generation(self) -> u64 {
        self.generation
    }

    /// Returns the cursor made durable by the barrier.
    pub const fn cursor(self) -> Cursor {
        self.cursor
    }
}

/// Semantic domain named by a durable event.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DurableComponent {
    /// Producer-chain and data-availability state.
    Da,
    /// Per-view transition state.
    View,
    /// Finality pools and authenticated checkpoint state.
    Ordering,
    /// Shared durability lifecycle state.
    Durability,
    /// Durable network-publication effects.
    PublicationOutbox,
}

/// A versioned canonical snapshot section.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ComponentPayload {
    version: u8,
    bytes: Arc<[u8]>,
}

impl ComponentPayload {
    /// Creates a payload under its component-local schema version.
    pub fn new(version: u8, bytes: impl Into<Arc<[u8]>>) -> Self {
        Self {
            version,
            bytes: bytes.into(),
        }
    }

    /// Returns the canonical component bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Exact acknowledged journal prefix and pending boundary sequence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JournalPrefix {
    version: u8,
    generation: u64,
    acknowledged: Cursor,
    pending: Vec<BarrierAck>,
}

impl JournalPrefix {
    const fn acknowledged(generation: u64, cursor: Cursor) -> Self {
        Self {
            version: JOURNAL_PREFIX_VERSION,
            generation,
            acknowledged: cursor,
            pending: Vec::new(),
        }
    }

    fn restore(
        version: u8,
        generation: u64,
        acknowledged: Cursor,
        pending: Vec<BarrierAck>,
    ) -> Result<Self, ()> {
        let prefix = Self {
            version,
            generation,
            acknowledged,
            pending,
        };
        if prefix.version != JOURNAL_PREFIX_VERSION
            || prefix.pending.iter().any(|boundary| {
                boundary.generation() != generation || boundary.cursor() <= acknowledged
            })
            || prefix.pending.windows(2).any(|pair| {
                pair[0].barrier().get().checked_add(1) != Some(pair[1].barrier().get())
                    || pair[0].cursor() >= pair[1].cursor()
            })
        {
            return Err(());
        }
        Ok(prefix)
    }

    /// Returns the process generation that issued the boundaries.
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns the last acknowledged journal cursor.
    pub const fn acknowledged_cursor(&self) -> Cursor {
        self.acknowledged
    }

    /// Returns pending boundaries in the only legal acknowledgement order.
    pub fn pending(&self) -> &[BarrierAck] {
        &self.pending
    }
}

/// Completion of one stable outbox action.
#[derive(Clone, Debug)]
pub(crate) enum EffectCompletion<V: Variant, D: Digest> {
    /// An exact signed artifact was produced.
    Signed {
        /// Stable signing action identifier.
        id: EffectId,
        /// Issuing process generation.
        generation: u64,
        /// The exact completed artifact.
        artifact: Arc<Artifact<V, D>>,
    },
    /// An exact atomic signing batch was produced.
    SignedBatch {
        /// Stable signing action identifier.
        id: EffectId,
        /// Issuing process generation.
        generation: u64,
        /// Exact artifacts in request order.
        artifacts: Vec<Artifact<V, D>>,
    },
    /// One publication attempt was accepted by the attached transport.
    ///
    /// This is volatile feedback and does not retire the durable publication. Only an authenticated
    /// protocol successor can do that.
    Delivered {
        /// Stable action identifier.
        id: EffectId,
        /// Issuing process generation.
        generation: u64,
    },
}

impl<V: Variant, D: Digest> EffectCompletion<V, D> {
    /// Returns the stable action identifier.
    pub const fn id(&self) -> EffectId {
        match self {
            Self::Signed { id, .. } | Self::SignedBatch { id, .. } | Self::Delivered { id, .. } => {
                *id
            }
        }
    }

    /// Returns the issuing process generation.
    pub const fn generation(&self) -> u64 {
        match self {
            Self::Signed { generation, .. }
            | Self::SignedBatch { generation, .. }
            | Self::Delivered { generation, .. } => *generation,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DurableState<V: Variant, D: Digest> {
    pub view: View,
    pub produced_blocks: u64,
    pub produced_height: Height,
    pub generation: u64,
    pub cursor: Cursor,
    pub certified_tips: Vec<BlockRef<D>>,
    pub da_safety_heights: Vec<Height>,
    pub retired_view: View,
    pub signing_floor: Option<Arc<Artifact<V, D>>>,
    pub proposal_anchor: Option<Arc<Artifact<V, D>>>,
    pub proposal_nullified_through: View,
    pub local: BTreeMap<ArtifactId<D>, Arc<Artifact<V, D>>>,
    pub signing_reservations: SigningReservations<V, D>,
    pub outbox: PublicationOutbox<V, D>,
    pub obligations: BTreeMap<EffectId, PublicationObligation>,
    pub forwarded_vqcs: BTreeMap<View, Arc<Artifact<V, D>>>,
    pub forwarded_nullifications: BTreeMap<View, Arc<Artifact<V, D>>>,
    pub exits: BTreeMap<View, Arc<Artifact<V, D>>>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct ObligationsSnapshot {
    obligations: BTreeMap<EffectId, PublicationObligation>,
}

impl<V: Variant, D: Digest> DurableState<V, D> {
    pub(crate) fn new(certified_tips: Vec<BlockRef<D>>, produced_height: Height) -> Self {
        let da_safety_heights = certified_tips.iter().map(BlockRef::height).collect();
        Self {
            view: View::new(1),
            produced_blocks: 0,
            produced_height,
            generation: 0,
            cursor: Cursor::zero(),
            certified_tips,
            da_safety_heights,
            retired_view: View::zero(),
            signing_floor: None,
            proposal_anchor: None,
            proposal_nullified_through: View::zero(),
            local: BTreeMap::new(),
            signing_reservations: SigningReservations::default(),
            outbox: PublicationOutbox::default(),
            obligations: BTreeMap::new(),
            forwarded_vqcs: BTreeMap::new(),
            forwarded_nullifications: BTreeMap::new(),
            exits: BTreeMap::new(),
        }
    }

    fn retained_artifacts(&self) -> impl Iterator<Item = Arc<Artifact<V, D>>> + '_ {
        self.local
            .values()
            .chain(self.signing_floor.iter())
            .chain(self.proposal_anchor.iter())
            .chain(self.forwarded_vqcs.values())
            .chain(self.forwarded_nullifications.values())
            .chain(self.exits.values())
            .chain(self.outbox.values().flat_map(DurableEffect::artifacts))
            .cloned()
            .chain(self.signing_reservations.values().flat_map(|effect| {
                let requests: Vec<_> = match effect {
                    DurableEffect::Sign(request) => vec![request],
                    DurableEffect::SignBatch(requests) => requests.iter().collect(),
                    _ => Vec::new(),
                };
                requests.into_iter().filter_map(|request| match request {
                    SignRequest::DaVote(request) => Some(Arc::new(Artifact::TransactionBlock(
                        request.block().as_ref().clone(),
                    ))),
                    SignRequest::LeaderBlock(request) => request
                        .parent()
                        .exact()
                        .map(|parent| Arc::new(Artifact::Vqc(parent.as_ref().clone()))),
                    SignRequest::TransactionBlock(_)
                    | SignRequest::Vote(_)
                    | SignRequest::NoVote { .. }
                    | SignRequest::Nullify { .. } => None,
                })
            }))
    }

    /// Projects resolver evidence directly from durable custody.
    pub(crate) fn resolver_proofs(&self) -> impl Iterator<Item = ViewProof<V, D>> + '_ {
        self.retained_artifacts()
            .filter_map(|artifact| match artifact.as_ref() {
                Artifact::Nullification(proof) => {
                    Some(ViewProof::Nullification(Box::new(proof.clone())))
                }
                Artifact::Vqc(proof) => Some(ViewProof::Vqc(Box::new(proof.clone()))),
                Artifact::Lqc(proof) => Some(ViewProof::Lqc(Box::new(proof.clone()))),
                _ => None,
            })
    }

    pub(crate) fn vqc_forwarded(&self, view: View) -> bool {
        self.forwarded_vqcs.contains_key(&view)
    }

    pub(crate) fn nullification_forwarded(&self, view: View) -> bool {
        self.forwarded_nullifications.contains_key(&view)
    }

    pub(crate) fn artifact_references<H: Hasher<Digest = D>>(
        &self,
    ) -> BTreeMap<ArtifactId<D>, usize> {
        let mut references = BTreeMap::new();
        for id in self.local.keys().copied() {
            *references.entry(id).or_default() += 1;
        }
        for effect in self.outbox.values() {
            Self::visit_effect_artifacts::<H>(effect, |id| {
                *references.entry(id).or_default() += 1;
            });
        }
        for reservation in self.signing_reservations.values() {
            Self::visit_effect_artifacts::<H>(reservation, |id| {
                *references.entry(id).or_default() += 1;
            });
        }
        for artifact in self
            .forwarded_vqcs
            .values()
            .chain(self.forwarded_nullifications.values())
            .chain(self.signing_floor.iter())
            .chain(self.proposal_anchor.iter())
        {
            *references.entry(artifact.id::<H>()).or_default() += 1;
        }
        references
    }

    pub(crate) fn artifact_occupancy<H: Hasher<Digest = D>>(&self) -> usize {
        self.artifact_references::<H>().len() + self.signing_reservations()
    }

    pub(crate) fn signing_reservations(&self) -> usize {
        self.signing_reservations
            .values()
            .map(Self::effect_reservations)
            .sum()
    }

    pub(crate) fn effect(&self, id: &EffectId) -> Option<DurableEffect<V, D>> {
        self.signing_reservations
            .get(id)
            .cloned()
            .or_else(|| self.outbox.get(id).cloned())
    }

    pub(crate) fn contains_effect(&self, id: &EffectId) -> bool {
        self.signing_reservations.contains_key(id) || self.outbox.contains_key(id)
    }

    pub(crate) fn effect_count(&self) -> usize {
        self.signing_reservations.len() + self.outbox.len()
    }

    pub(crate) fn effect_ids(&self) -> impl Iterator<Item = EffectId> + '_ {
        self.signing_reservations
            .keys()
            .chain(self.outbox.keys())
            .copied()
    }

    pub(crate) fn effect_reservations(effect: &DurableEffect<V, D>) -> usize {
        match effect {
            DurableEffect::Sign(_) => 1,
            DurableEffect::SignBatch(requests) => requests.len(),
            DurableEffect::Broadcast(_)
            | DurableEffect::BroadcastBatch(_)
            | DurableEffect::Propose(_)
            | DurableEffect::Send(_)
            | DurableEffect::SendBatch(_) => 0,
        }
    }

    pub(crate) fn visit_effect_artifacts<H: Hasher<Digest = D>>(
        effect: &DurableEffect<V, D>,
        mut visit: impl FnMut(ArtifactId<D>),
    ) {
        match effect {
            DurableEffect::Broadcast(artifact) => {
                visit(artifact.id::<H>());
            }
            DurableEffect::BroadcastBatch(artifacts) => {
                for artifact in artifacts.iter() {
                    visit(artifact.id::<H>());
                }
            }
            DurableEffect::Propose(publication) => {
                visit(Artifact::LeaderBlock(publication.block().as_ref().clone()).id::<H>());
                if let Some(parent) = publication.parent().exact() {
                    visit(Artifact::Vqc(parent.as_ref().clone()).id::<H>());
                }
            }
            DurableEffect::Send(request) => {
                visit(request.artifact().id::<H>());
            }
            DurableEffect::SendBatch(requests) => {
                for request in requests.iter() {
                    visit(request.artifact().id::<H>());
                }
            }
            DurableEffect::Sign(SignRequest::LeaderBlock(request)) => {
                if let Some(parent) = request.parent().exact() {
                    visit(Artifact::Vqc(parent.as_ref().clone()).id::<H>());
                }
            }
            DurableEffect::Sign(_) | DurableEffect::SignBatch(_) => {}
        }
    }
}

impl<V: Variant, D: Digest> ViewSnapshot<V, D> {
    fn structurally_valid(&self, epoch: Epoch) -> bool {
        self.slots.iter().all(|(view, slot)| {
            !view.is_zero()
                && slot.stable()
                && slot
                    .proposal
                    .as_ref()
                    .is_none_or(|block| block.epoch() == epoch && block.view() == *view)
                && !matches!(&slot.stance, ViewStance::Voted(body)
                    if body.epoch() != epoch || body.view() != *view)
        })
    }

    fn slot_mut(&mut self, view: View) -> Result<&mut ViewSlotSnapshot<V, D>, ReplayError> {
        if view.is_zero() {
            return Err(ReplayError::Transition);
        }
        Ok(self.slots.entry(view).or_default())
    }

    fn observe_request(
        &mut self,
        request: &SignRequest<V, D>,
        retired: View,
    ) -> Result<(), ReplayError> {
        let Some(view) = request.consensus_view() else {
            return Ok(());
        };
        if view <= retired {
            return Err(ReplayError::Transition);
        }
        let slot = self.slot_mut(view)?;
        match request {
            SignRequest::LeaderBlock(request) => {
                slot.observe_proposal(request.block().clone())?;
            }
            SignRequest::Vote(request) => slot.observe_vote(request.body().clone())?,
            SignRequest::NoVote { .. } => slot.observe_novote()?,
            SignRequest::Nullify { .. } => slot.observe_nullify(),
            SignRequest::TransactionBlock(_) | SignRequest::DaVote(_) => {}
        }
        Ok(())
    }

    fn observe_artifact(
        &mut self,
        artifact: &Artifact<V, D>,
        role: Role,
        retired: View,
    ) -> Result<(), ReplayError> {
        let Role::Validator(me) = role else {
            return Ok(());
        };
        if artifact.signer() != Some(me) {
            return Ok(());
        }
        let Some(view) = artifact.view() else {
            return Ok(());
        };
        if view <= retired {
            return Err(ReplayError::Transition);
        }
        let slot = self.slot_mut(view)?;
        match artifact {
            Artifact::LeaderBlock(block) => slot.observe_proposal(block.block().clone())?,
            Artifact::Vote(vote) => slot.observe_vote(vote.body().clone())?,
            Artifact::NoVote(_) => slot.observe_novote()?,
            Artifact::Nullify(_) => slot.observe_nullify(),
            Artifact::TransactionBlock(_)
            | Artifact::DaVote(_)
            | Artifact::DaCertificate(_)
            | Artifact::Nullification(_)
            | Artifact::Vqc(_)
            | Artifact::Lqc(_) => {}
        }
        Ok(())
    }

    fn from_durable<H: Hasher<Digest = D>>(
        epoch: Epoch,
        role: Role,
        state: &DurableState<V, D>,
    ) -> Result<Self, ReplayError> {
        let mut snapshot = Self::default();
        for effect in state.signing_reservations.values() {
            let requests = match effect {
                DurableEffect::Sign(request) => core::slice::from_ref(request),
                DurableEffect::SignBatch(requests) => requests,
                _ => return Err(ReplayError::Transition),
            };
            for request in requests {
                snapshot.observe_request(request, state.retired_view)?;
            }
        }
        for artifact in state.local.values() {
            snapshot.observe_artifact(artifact, role, state.retired_view)?;
        }
        for (view, proof) in &state.exits {
            if *view <= state.retired_view || *view >= state.view {
                return Err(ReplayError::Transition);
            }
            snapshot.slot_mut(*view)?.observe_exit(proof.id::<H>())?;
        }
        if !snapshot.structurally_valid(epoch)
            || snapshot.slots.iter().any(|(view, slot)| {
                matches!(slot.transition, ViewTransition::Active) && *view < state.view
            })
        {
            return Err(ReplayError::Transition);
        }
        Ok(snapshot)
    }
}

/// Canonical projections needed to restore the synchronous protocol state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnapshotEnvelope {
    ordering: ComponentPayload,
    signing_reservations: ComponentPayload,
    view: ComponentPayload,
    obligations: ComponentPayload,
    journal: JournalPrefix,
}

impl SnapshotEnvelope {
    fn current<V: Variant, D: Digest>(
        state: &DurableState<V, D>,
        view: &ViewSnapshot<V, D>,
    ) -> Self {
        Self {
            ordering: ordering_snapshot_payload(),
            signing_reservations: signing_reservations_payload(state),
            view: view_snapshot_payload(view),
            obligations: obligations_snapshot_payload(state),
            journal: JournalPrefix::acknowledged(state.generation, state.cursor),
        }
    }

    /// Returns the leader-chain view projection.
    #[cfg(test)]
    pub const fn view(&self) -> &ComponentPayload {
        &self.view
    }
}

fn view_snapshot_payload<V: Variant, D: Digest>(view: &ViewSnapshot<V, D>) -> ComponentPayload {
    let bytes = view.encode();
    ComponentPayload::new(VIEW_SNAPSHOT_VERSION, Arc::<[u8]>::from(bytes.as_ref()))
}

fn signing_reservations_payload<V: Variant, D: Digest>(
    state: &DurableState<V, D>,
) -> ComponentPayload {
    let bytes = state.signing_reservations.encode();
    ComponentPayload::new(
        SIGNING_RESERVATIONS_VERSION,
        Arc::<[u8]>::from(bytes.as_ref()),
    )
}

fn obligations_snapshot_payload<V: Variant, D: Digest>(
    state: &DurableState<V, D>,
) -> ComponentPayload {
    let snapshot = ObligationsSnapshot {
        obligations: state.obligations.clone(),
    };
    let bytes = snapshot.encode();
    ComponentPayload::new(OBLIGATIONS_VERSION, Arc::<[u8]>::from(bytes.as_ref()))
}

fn ordering_snapshot_payload() -> ComponentPayload {
    ComponentPayload::new(ORDERING_SNAPSHOT_VERSION, Arc::<[u8]>::from([]))
}

/// A projection of the last acknowledged durable cursor.
///
/// Verification jobs, unsynced reservations, and other volatile work are intentionally absent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snapshot<V: Variant, D: Digest> {
    epoch: Epoch,
    role: Role,
    state: DurableState<V, D>,
    view: ViewSnapshot<V, D>,
    envelope: SnapshotEnvelope,
}

impl<V: Variant, D: Digest> Change<V, D> {
    pub(crate) const fn component(&self) -> DurableComponent {
        match self {
            Self::GenerationAdvanced(_) => DurableComponent::Durability,
            Self::FinalityFloorAdvanced { .. } => DurableComponent::Ordering,
            Self::DaCertificateAdvanced { .. } => DurableComponent::Da,
            Self::ViewCertificateCreated { .. }
            | Self::ArtifactForwarded { .. }
            | Self::ViewAdvanced { .. } => DurableComponent::View,
            Self::OutboxQueued { .. }
            | Self::SignedArtifact { .. }
            | Self::SignedArtifactBatch { .. }
            | Self::ArtifactCreated { .. } => DurableComponent::PublicationOutbox,
        }
    }

    /// Returns the outbox effect this change queues, if any.
    pub(crate) const fn queued_effect(&self) -> Option<EffectId> {
        match self {
            Self::OutboxQueued { id, .. } => Some(*id),
            Self::SignedArtifact { publication, .. }
            | Self::SignedArtifactBatch { publication, .. }
            | Self::ArtifactCreated { publication, .. }
            | Self::ArtifactForwarded { publication, .. } => Some(*publication),
            Self::DaCertificateAdvanced { publication, .. } => *publication,
            Self::GenerationAdvanced(_)
            | Self::ViewAdvanced { .. }
            | Self::FinalityFloorAdvanced { .. }
            | Self::ViewCertificateCreated { .. } => None,
        }
    }

    /// Returns whether this change records a fresh local signature.
    ///
    /// The publication such a change queues must not leave the process before the record is
    /// durable: a crash that forgets a released signature could re-sign a conflicting subject
    /// for the same slot, and that equivocation is exactly what the journal exists to prevent.
    pub(crate) const fn records_local_signature(&self) -> bool {
        matches!(
            self,
            Self::SignedArtifact { .. } | Self::SignedArtifactBatch { .. }
        )
    }

    pub(crate) const fn kind(&self) -> &'static str {
        match self {
            Self::GenerationAdvanced(_) => "generation advanced",
            Self::OutboxQueued { .. } => "outbox queued",
            Self::SignedArtifact { .. } => "signed artifact",
            Self::SignedArtifactBatch { .. } => "signed artifact batch",
            Self::ArtifactCreated { .. } => "artifact created",
            Self::ViewCertificateCreated { .. } => "view certificate created",
            Self::DaCertificateAdvanced { .. } => "DA certificate advanced",
            Self::ArtifactForwarded { .. } => "artifact forwarded",
            Self::ViewAdvanced { .. } => "view advanced",
            Self::FinalityFloorAdvanced { .. } => "finality floor advanced",
        }
    }
}

impl<V: Variant, D: Digest> Snapshot<V, D> {
    pub(crate) fn new<H: Hasher<Digest = D>>(
        epoch: Epoch,
        role: Role,
        state: DurableState<V, D>,
    ) -> Self {
        let view = ViewSnapshot::from_durable::<H>(epoch, role, &state)
            .expect("live durable state has a valid View projection");
        let envelope = SnapshotEnvelope::current(&state, &view);
        Self {
            epoch,
            role,
            state,
            view,
            envelope,
        }
    }

    #[cfg(test)]
    pub(crate) fn from_state_for_test<H: Hasher<Digest = D>>(
        epoch: Epoch,
        role: Role,
        state: DurableState<V, D>,
    ) -> Self {
        let view = ViewSnapshot::from_durable::<H>(epoch, role, &state).unwrap_or_default();
        let envelope = SnapshotEnvelope::current(&state, &view);
        Self {
            epoch,
            role,
            state,
            view,
            envelope,
        }
    }

    /// Returns the acknowledged journal cursor.
    pub const fn cursor(&self) -> Cursor {
        self.state.cursor
    }

    pub(crate) const fn epoch(&self) -> Epoch {
        self.epoch
    }

    /// Returns the permanent component snapshot envelope.
    #[cfg(test)]
    pub const fn envelope(&self) -> &SnapshotEnvelope {
        &self.envelope
    }

    /// Returns the greatest genesis or witnessed DA certificate on every producer chain.
    #[cfg(test)]
    pub fn certified_tips(&self) -> &[BlockRef<D>] {
        &self.state.certified_tips
    }

    /// Returns each chain's durable frontier for future DA votes.
    ///
    /// A validator advances a frontier by committing a vote or accepting a higher certificate.
    /// Observers mirror their certified heights because they never vote.
    #[cfg(test)]
    pub fn da_safety_heights(&self) -> &[Height] {
        &self.state.da_safety_heights
    }

    /// Returns network publications that remain durably outstanding.
    #[cfg(any(test, feature = "test-utils"))]
    pub const fn outbox(&self) -> &BTreeMap<EffectId, DurableEffect<V, D>> {
        self.state.outbox.entries()
    }

    /// Returns local signing requests that remain durably authorized.
    #[cfg(test)]
    pub fn signing_reservations(&self) -> &BTreeMap<EffectId, DurableEffect<V, D>> {
        &self.state.signing_reservations
    }

    /// Returns active family-typed publication obligations.
    #[cfg(any(test, feature = "test-utils"))]
    pub const fn obligations(&self) -> &BTreeMap<EffectId, PublicationObligation> {
        &self.state.obligations
    }

    /// Returns locally created artifacts retained independently of publication lifetime.
    #[cfg(test)]
    pub const fn local_artifacts(&self) -> &BTreeMap<ArtifactId<D>, Arc<Artifact<V, D>>> {
        &self.state.local
    }

    /// Returns every artifact durably retained by this snapshot.
    ///
    /// Locally created artifacts are only part of the set: certificates this node forwarded, the
    /// proofs it exited views with, and the artifacts named by its outbox are equally relevant to
    /// recovery validation.
    pub fn retained_artifacts(&self) -> impl Iterator<Item = Arc<Artifact<V, D>>> + '_ {
        self.state.retained_artifacts()
    }

    pub(crate) const fn state(&self) -> &DurableState<V, D> {
        &self.state
    }

    pub(crate) const fn view_snapshot(&self) -> &ViewSnapshot<V, D> {
        &self.view
    }

    #[cfg(test)]
    pub(crate) fn replace_view_payload(&mut self, bytes: impl Into<Arc<[u8]>>) {
        self.envelope.view = ComponentPayload::new(VIEW_SNAPSHOT_VERSION, bytes);
    }

    #[cfg(test)]
    pub(crate) fn clear_view_snapshot(&mut self) {
        self.view = ViewSnapshot::default();
        self.envelope.view = view_snapshot_payload(&self.view);
    }

    /// Returns a codec-valid fixture at the requested acknowledged cursor.
    #[cfg(test)]
    pub(crate) fn at_cursor_for_test(mut self, cursor: Cursor) -> Self {
        self.state.cursor = cursor;
        self.envelope.journal = JournalPrefix::acknowledged(self.state.generation, cursor);
        self
    }
}

/// An invalid snapshot, journal event, or replay lifecycle operation.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ReplayError {
    /// Snapshot or event belongs to another epoch or role.
    #[error("recovery context does not match the machine profile")]
    Context,
    /// A journal entry is not the exact next cursor.
    #[error("journal cursor is not contiguous")]
    Cursor,
    /// A durable state change violates its transition invariant.
    #[error("invalid durable state transition")]
    Transition,
    /// Replay was attempted after live processing began.
    #[error("journal replay is only allowed during recovery")]
    Lifecycle,
}

impl<V: Variant, D: Digest> Snapshot<V, D> {
    pub(crate) fn validate<H: Hasher<Digest = D>>(
        &self,
        profile: &Profile<H, V>,
    ) -> Result<(), ReplayError> {
        if self.epoch != profile.protocol().epoch() || self.role != profile.role() {
            return Err(ReplayError::Context);
        }
        if self.envelope.ordering != ordering_snapshot_payload()
            || self.envelope.signing_reservations != signing_reservations_payload(&self.state)
            || self.envelope.view != view_snapshot_payload(&self.view)
            || self.envelope.obligations != obligations_snapshot_payload(&self.state)
            || self.envelope.journal.generation() != self.state.generation
            || self.envelope.journal.acknowledged_cursor() != self.state.cursor
            || !self.envelope.journal.pending().is_empty()
        {
            return Err(ReplayError::Transition);
        }
        if ViewSnapshot::from_durable::<H>(self.epoch, self.role, &self.state)? != self.view {
            return Err(ReplayError::Transition);
        }
        let resources = profile.resources();
        let chains = profile.protocol().codec_config().chains();
        let initial_produced_height = match self.role {
            Role::Validator(participant) => profile
                .protocol()
                .producer_chain(participant)
                .map_or_else(Height::zero, |chain| {
                    profile.protocol().genesis().tips()[chain.get() as usize].height()
                }),
            Role::Observer => Height::zero(),
        };
        if self.state.local.len() > resources.max_cached_artifacts()
            || self.state.effect_count() > resources.max_outbox_effects()
            || !self.state.signing_reservations.valid()
            || !self.state.outbox.valid()
            || self
                .state
                .signing_reservations
                .keys()
                .any(|id| self.state.outbox.contains_key(id))
            || self.state.artifact_occupancy::<H>() > resources.max_cached_artifacts()
            || self.state.produced_height < initial_produced_height
            || matches!(self.role, Role::Observer) && !self.state.produced_height.is_zero()
            || self.state.certified_tips.len() != profile.protocol().codec_config().chains()
            || self.state.da_safety_heights.len() != profile.protocol().codec_config().chains()
            || self
                .state
                .certified_tips
                .iter()
                .zip(profile.protocol().genesis().tips())
                .enumerate()
                .any(|(chain, (certified, genesis))| {
                    certified.chain().get() as usize != chain
                        || certified.height() < genesis.height()
                        || certified.height() == genesis.height() && certified != genesis
                })
            || self
                .state
                .da_safety_heights
                .iter()
                .zip(&self.state.certified_tips)
                .any(|(safe, certified)| {
                    matches!(profile.role(), Role::Validator(_))
                        && (*safe < certified.height()
                            || safe.get().saturating_sub(certified.height().get())
                                > profile.protocol().codec_config().pipeline_depth() as u64)
                })
            || matches!(profile.role(), Role::Observer)
                && self
                    .state
                    .da_safety_heights
                    .iter()
                    .zip(&self.state.certified_tips)
                    .any(|(safe, certified)| *safe != certified.height())
        {
            return Err(ReplayError::Transition);
        }

        for (id, artifact) in &self.state.local {
            let locally_constructible = match (profile.role(), artifact.as_ref()) {
                (Role::Validator(_) | Role::Observer, Artifact::DaCertificate(certificate)) => self
                    .state
                    .certified_tips
                    .get(certificate.header().chain().get() as usize)
                    .is_some_and(|tip| certificate.block_ref::<H>() == *tip),
                (
                    Role::Validator(_) | Role::Observer,
                    Artifact::Nullification(_) | Artifact::Vqc(_) | Artifact::Lqc(_),
                ) => true,
                (Role::Validator(signer), _) => artifact.signer() == Some(signer),
                (Role::Observer, _) => false,
            };
            // A locally constructed transaction block is bound to its producer's own chain, the
            // same way the network path binds it. Without this, a tampered checkpoint could carry
            // an out-of-range chain into the per-chain tables.
            if let Artifact::TransactionBlock(block) = artifact.as_ref()
                && (block.header().chain().get() as usize >= chains
                    || profile.protocol().producer(block.header().chain()) != artifact.signer())
            {
                return Err(ReplayError::Transition);
            }
            if artifact.encoded_len() > resources.max_artifact_bytes()
                || artifact.epoch() != self.epoch
                || !locally_constructible
                || artifact.id::<H>() != *id
                || matches!(artifact.as_ref(), Artifact::DaVote(vote)
                    if self.state
                        .da_safety_heights
                        .get(vote.header().chain().get() as usize)
                        .is_none_or(|height| vote.header().height() > *height))
            {
                return Err(ReplayError::Transition);
            }
        }
        for (chain, (certified, genesis)) in self
            .state
            .certified_tips
            .iter()
            .zip(profile.protocol().genesis().tips())
            .enumerate()
        {
            if certified == genesis {
                continue;
            }
            let retained = self.state.local.values().filter(|artifact| {
                matches!(artifact.as_ref(), Artifact::DaCertificate(certificate)
                    if certificate.header().chain().get() as usize == chain
                        && certificate.block_ref::<H>() == *certified)
            });
            if retained.count() != 1 {
                return Err(ReplayError::Transition);
            }
        }
        for (id, effect) in self
            .state
            .signing_reservations
            .iter()
            .chain(self.state.outbox.iter())
        {
            if id.get() == 0
                || id.get() > self.state.cursor.get()
                || !effect.authorized(profile)
                || matches!(effect, DurableEffect::Sign(SignRequest::DaVote(request))
                    if self.state
                        .da_safety_heights
                        .get(request.header().chain().get() as usize)
                        .is_none_or(|height| request.header().height() > *height))
            {
                return Err(ReplayError::Transition);
            }
        }
        for (id, obligation) in &self.state.obligations {
            let Some(effect) = self.state.outbox.get(id) else {
                return Err(ReplayError::Transition);
            };
            if obligation.effect() != *id
                || !obligation.matches_payload(effect)
                || obligation.discharges().is_empty()
                || obligation
                    .discharges()
                    .windows(2)
                    .any(|pair| pair[0].item() >= pair[1].item())
                || obligation
                    .discharges()
                    .iter()
                    .any(|discharge| discharge.effect() != *id)
            {
                return Err(ReplayError::Transition);
            }
        }
        if self
            .state
            .outbox
            .keys()
            .any(|id| !self.state.obligations.contains_key(id))
        {
            return Err(ReplayError::Transition);
        }
        let forwarded_maps = [
            (&self.state.forwarded_vqcs, ArtifactKind::Vqc),
            (
                &self.state.forwarded_nullifications,
                ArtifactKind::Nullification,
            ),
        ];
        for (forwarded_map, expected_kind) in forwarded_maps {
            for (view, artifact) in forwarded_map {
                // A certificate observed for a view below the retention floor can still be
                // forwarded once, so the fact outlives that view until the next compaction.
                if view.is_zero() {
                    return Err(ReplayError::Transition);
                }
                if artifact.view() != Some(*view)
                    || artifact.kind() != expected_kind
                    || artifact.epoch() != self.epoch
                    || artifact.encoded_len() > resources.max_artifact_bytes()
                {
                    return Err(ReplayError::Transition);
                }
            }
        }
        if self.state.retired_view >= self.state.view {
            return Err(ReplayError::Transition);
        }
        let signing_floor_view = match self.state.signing_floor.as_deref() {
            Some(artifact @ Artifact::Lqc(floor))
                if !floor.view().is_zero()
                    && floor.view() <= self.state.retired_view
                    && floor.view() < self.state.view
                    && artifact.epoch() == self.epoch
                    && artifact.encoded_len() <= resources.max_artifact_bytes() =>
            {
                floor.view()
            }
            Some(_) => return Err(ReplayError::Transition),
            None => View::zero(),
        };
        let anchor_view = match self.state.proposal_anchor.as_deref() {
            Some(artifact @ Artifact::Vqc(anchor))
                if !anchor.view().is_zero()
                    && artifact.epoch() == self.epoch
                    && artifact.encoded_len() <= resources.max_artifact_bytes() =>
            {
                anchor.view()
            }
            Some(_) => return Err(ReplayError::Transition),
            None => View::zero(),
        };
        if anchor_view < signing_floor_view
            || self.state.proposal_nullified_through < anchor_view
            || self.state.proposal_nullified_through > self.state.view
            || self.state.proposal_nullified_through == self.state.view
                && anchor_view != self.state.view
        {
            return Err(ReplayError::Transition);
        }
        if signing_floor_view == anchor_view
            && let (Some(Artifact::Lqc(floor)), Some(Artifact::Vqc(anchor))) = (
                self.state.signing_floor.as_deref(),
                self.state.proposal_anchor.as_deref(),
            )
            && !floor.equivalent_vqc(anchor)
        {
            return Err(ReplayError::Transition);
        }
        if self.state.forwarded_vqcs.len() + self.state.forwarded_nullifications.len()
            > resources.max_forwarded_certificates()
        {
            return Err(ReplayError::Transition);
        }
        let Some(mut expected_exit) = self.state.retired_view.get().checked_add(1) else {
            return Err(ReplayError::Transition);
        };
        let contiguous_exits = !self.state.view.is_zero()
            && self.state.exits.keys().all(|view| {
                if view.get() != expected_exit {
                    return false;
                }
                let Some(next) = expected_exit.checked_add(1) else {
                    return false;
                };
                expected_exit = next;
                true
            })
            && expected_exit == self.state.view.get();
        if !contiguous_exits
            || self.state.exits.iter().any(|(view, proof)| {
                proof.view() != Some(*view)
                    || !matches!(
                        proof.as_ref(),
                        Artifact::Vqc(_) | Artifact::Nullification(_)
                    )
                    || self
                        .state
                        .forwarded_vqcs
                        .get(view)
                        .into_iter()
                        .chain(self.state.forwarded_nullifications.get(view))
                        .all(|forwarded| forwarded.as_ref() != proof.as_ref())
            })
        {
            return Err(ReplayError::Transition);
        }
        Ok(())
    }
}

/// Result of replaying one durable journal event.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Replayed {
    cursor: Cursor,
}

impl Replayed {
    pub(crate) const fn new(cursor: Cursor) -> Self {
        Self { cursor }
    }
}

/// A normalized identifier and kind for one authenticated local completion.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SelfAdmission<D: Digest> {
    id: ArtifactId<D>,
}

impl<D: Digest> SelfAdmission<D> {
    pub(crate) const fn new(id: ArtifactId<D>) -> Self {
        Self { id }
    }
}
