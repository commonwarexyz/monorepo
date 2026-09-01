//! Durable external actions: signing requests, publications, and their authorization.

use super::EffectId;
use crate::{
    Epochable, Viewable,
    multimmit::{
        config::{Profile, Protocol, Role},
        machine::job::Issued,
        scheme::bls12381_threshold::{Error as SchemeError, Scheme},
        types::{
            Artifact, ArtifactBatch, ArtifactId, ArtifactKind, LeaderBlock, SignedLeaderBlock,
            SignedTransactionBlock, TransactionBlockHeader, ViewProof, VoteBody, Vqc,
        },
    },
    types::{Attributable, Epoch, Participant, Round, View},
};
use commonware_codec::EncodeSize;
use commonware_cryptography::{Digest, Hasher, PublicKey, bls12381::primitives::variant::Variant};
use std::{collections::BTreeMap, sync::Arc};

/// A typed subject the local scheme may sign.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum SignRequest<V: Variant, D: Digest> {
    /// Authorize one producer-chain header.
    TransactionBlock(TransactionBlockHeader<D>),
    /// Authorize one data-availability share for the authenticated block whose availability it
    /// promises, after local eligibility is durable.
    DaVote(Arc<SignedTransactionBlock<V, D>>),
    /// Authorize one scheduled leader proposal and retain its parent certificate.
    LeaderBlock(ProposalRequest<V, D>),
    /// Authorize one ordinary signature over a complete vote body.
    Vote(VoteBody<D>),
    /// Authorize an abstention for one round.
    NoVote {
        /// The round.
        round: Round,
    },
    /// Authorize a nullification share for one round.
    Nullify {
        /// The round.
        round: Round,
    },
}

impl<V: Variant, D: Digest> SignRequest<V, D> {
    /// Returns the stable operation label recorded on signing spans.
    pub(crate) const fn label(&self) -> &'static str {
        match self {
            Self::TransactionBlock(_) => "transaction_block",
            Self::DaVote(_) => "da_vote",
            Self::LeaderBlock(_) => "leader_block",
            Self::Vote(_) => "vote",
            Self::NoVote { .. } => "no_vote",
            Self::Nullify { .. } => "nullify",
        }
    }

    /// Signs this subject with the local key material in `scheme`.
    pub(crate) fn sign<P: PublicKey>(
        &self,
        scheme: &Scheme<P, V>,
    ) -> Result<Artifact<V, D>, SchemeError> {
        let artifact = match self {
            Self::TransactionBlock(header) => {
                Artifact::TransactionBlock(scheme.sign_transaction_block(header.clone())?)
            }
            Self::DaVote(block) => Artifact::DaVote(scheme.sign_da_vote(block.header().clone())?),
            Self::LeaderBlock(request) => {
                Artifact::LeaderBlock(scheme.sign_leader_block(request.block().clone())?)
            }
            Self::Vote(body) => Artifact::Vote(scheme.sign_vote(body.clone())?),
            Self::NoVote { round } => Artifact::NoVote(scheme.sign_novote(*round)?),
            Self::Nullify { round } => Artifact::Nullify(scheme.sign_nullify(*round)?),
        };
        Ok(artifact)
    }

    fn visit_retained(&self, visit: &mut impl FnMut(Retained<'_, V, D>)) {
        match self {
            Self::DaVote(block) => visit(Retained::DaVoteBlock(block)),
            Self::LeaderBlock(request) => {
                if let Some(parent) = request.parent().exact() {
                    visit(Retained::Vqc(parent));
                }
            }
            Self::TransactionBlock(_)
            | Self::Vote(_)
            | Self::NoVote { .. }
            | Self::Nullify { .. } => {}
        }
    }

    pub(crate) fn consensus_view(&self) -> Option<View> {
        match self {
            Self::TransactionBlock(_) | Self::DaVote(_) => None,
            Self::LeaderBlock(request) => Some(request.block().view()),
            Self::Vote(body) => Some(body.view()),
            Self::NoVote { round } | Self::Nullify { round } => Some(round.view()),
        }
    }

    pub(crate) fn matches_context(&self, epoch: Epoch) -> bool {
        match self {
            Self::TransactionBlock(header) => header.epoch() == epoch,
            Self::DaVote(block) => block.header().epoch() == epoch,
            Self::LeaderBlock(request) => request.block().epoch() == epoch,
            Self::Vote(body) => body.epoch() == epoch,
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
            (Self::Vote(expected), Artifact::Vote(actual)) => expected == actual.body(),
            (Self::NoVote { round }, Artifact::NoVote(actual)) => *round == actual.round(),
            (Self::Nullify { round }, Artifact::Nullify(actual)) => *round == actual.round(),
            _ => false,
        }
    }
}

/// The certificate attached to a leader proposal.
///
/// The genesis variant names the configured synthetic certificate. Every other proposal names and
/// carries one view quorum certificate.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) enum ProposalParent<Q> {
    /// The configured synthetic genesis certificate.
    Genesis,
    /// The view quorum certificate referenced by the leader block.
    Exact(Q),
}

impl<Q> ProposalParent<Q> {
    /// Returns the parent certificate, if this is a live parent.
    pub(crate) const fn exact(&self) -> Option<&Q> {
        match self {
            Self::Genesis => None,
            Self::Exact(parent) => Some(parent),
        }
    }
}

/// A leader block, its parent V-QC, and the durable choice to transmit that parent.
///
/// A signing request holds the unsigned block and its publication holds the signed block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Proposal<V: Variant, D: Digest, B> {
    pub(super) block: B,
    pub(super) parent: ProposalParent<Arc<Vqc<V, D>>>,
    pub(super) attach_parent: bool,
}

/// A scheduled leader block to sign.
pub(crate) type ProposalRequest<V, D> = Proposal<V, D, LeaderBlock<V, D>>;

/// A signed leader block to publish.
pub(crate) type ProposalPublication<V, D> = Proposal<V, D, Arc<SignedLeaderBlock<V, D>>>;

impl<V: Variant, D: Digest, B> Proposal<V, D, B> {
    pub(crate) const fn new(
        block: B,
        parent: ProposalParent<Arc<Vqc<V, D>>>,
        attach_parent: bool,
    ) -> Self {
        Self {
            block,
            parent,
            attach_parent,
        }
    }

    /// Returns the block.
    pub(crate) const fn block(&self) -> &B {
        &self.block
    }

    /// Returns the non-genesis parent referenced by the block.
    pub(crate) const fn parent(&self) -> &ProposalParent<Arc<Vqc<V, D>>> {
        &self.parent
    }

    /// Returns whether the parent must accompany the proposal.
    pub(crate) const fn attach_parent(&self) -> bool {
        self.attach_parent
    }
}

impl<V: Variant, D: Digest> ProposalRequest<V, D> {
    /// Returns the publication of this request once signed as `block`.
    fn signed(&self, block: Arc<SignedLeaderBlock<V, D>>) -> ProposalPublication<V, D> {
        Proposal::new(block, self.parent.clone(), self.attach_parent)
    }
}

/// One point-to-point protocol publication.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SendRequest<V: Variant, D: Digest> {
    pub(super) recipient: Participant,
    pub(super) artifact: Arc<Artifact<V, D>>,
}

impl<V: Variant, D: Digest> SendRequest<V, D> {
    pub(crate) const fn new(recipient: Participant, artifact: Arc<Artifact<V, D>>) -> Self {
        Self {
            recipient,
            artifact,
        }
    }

    /// Returns the sole intended recipient.
    pub(crate) const fn recipient(&self) -> Participant {
        self.recipient
    }

    /// Returns the canonical artifact to send.
    pub(crate) const fn artifact(&self) -> &Arc<Artifact<V, D>> {
        &self.artifact
    }
}
/// An artifact, or artifact part, retained by durable state.
pub(crate) enum Retained<'a, V: Variant, D: Digest> {
    /// A complete artifact.
    Artifact(&'a Arc<Artifact<V, D>>),
    /// The signed block of a proposal publication.
    LeaderBlock(&'a Arc<SignedLeaderBlock<V, D>>),
    /// The parent of a proposal publication or leader-block signing request.
    Vqc(&'a Arc<Vqc<V, D>>),
    /// The block a data-availability signing request votes for.
    DaVoteBlock(&'a Arc<SignedTransactionBlock<V, D>>),
}

impl<V: Variant, D: Digest> Retained<'_, V, D> {
    /// Returns the identifier of the artifact this item is or encodes as.
    pub(crate) fn id<H: Hasher<Digest = D>>(&self) -> ArtifactId<D> {
        match self {
            Self::Artifact(artifact) => artifact.id::<H>(),
            Self::LeaderBlock(block) => {
                Artifact::<V, D>::id_of::<H, _>(ArtifactKind::LeaderBlock, block.as_ref())
            }
            Self::Vqc(certificate) => {
                Artifact::<V, D>::id_of::<H, _>(ArtifactKind::Vqc, certificate.as_ref())
            }
            Self::DaVoteBlock(block) => {
                Artifact::<V, D>::id_of::<H, _>(ArtifactKind::TransactionBlock, block.as_ref())
            }
        }
    }

    /// Returns the item as an artifact, cloning an artifact part into its own artifact.
    pub(crate) fn to_artifact(&self) -> Arc<Artifact<V, D>> {
        match self {
            Self::Artifact(artifact) => Arc::clone(artifact),
            Self::LeaderBlock(block) => Arc::new(Artifact::LeaderBlock(block.as_ref().clone())),
            Self::Vqc(certificate) => Arc::new(Artifact::Vqc(certificate.as_ref().clone())),
            Self::DaVoteBlock(block) => {
                Arc::new(Artifact::TransactionBlock(block.as_ref().clone()))
            }
        }
    }

    /// Returns the item as a view proof, if it is one.
    pub(crate) fn view_proof(&self) -> Option<ViewProof<V, D>> {
        match self {
            Self::Artifact(artifact) => match artifact.as_ref() {
                Artifact::Nullification(proof) => {
                    Some(ViewProof::Nullification(Box::new(proof.clone())))
                }
                Artifact::Vqc(proof) => Some(ViewProof::Vqc(Box::new(proof.clone()))),
                Artifact::Lqc(proof) => Some(ViewProof::Lqc(Box::new(proof.clone()))),
                _ => None,
            },
            Self::Vqc(proof) => Some(ViewProof::Vqc(Box::new(proof.as_ref().clone()))),
            Self::LeaderBlock(_) | Self::DaVoteBlock(_) => None,
        }
    }
}
/// Signing requests authorized together, whose results are published together.
///
/// A signing choice is one request, a timeout pair (an abstention then a nullify share for one
/// round), or data-availability votes over runs of consecutive heights on several chains.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SignEffect<V: Variant, D: Digest> {
    pub(super) requests: Arc<[SignRequest<V, D>]>,
}

impl<V: Variant, D: Digest> SignEffect<V, D> {
    pub(crate) const fn new(requests: Arc<[SignRequest<V, D>]>) -> Self {
        Self { requests }
    }

    /// Returns a signing choice of one request.
    pub(crate) fn one(request: SignRequest<V, D>) -> Self {
        Self::new(Arc::from([request]))
    }

    /// Returns the requests in signing and publication order.
    pub(crate) fn requests(&self) -> &[SignRequest<V, D>] {
        &self.requests
    }

    /// Returns the shared request list, whose identity names this authorization.
    pub(crate) const fn shared(&self) -> &Arc<[SignRequest<V, D>]> {
        &self.requests
    }

    /// Visits every artifact part the requests retain.
    pub(crate) fn visit_retained(&self, mut visit: impl FnMut(Retained<'_, V, D>)) {
        for request in self.requests.iter() {
            request.visit_retained(&mut visit);
        }
    }

    pub(crate) fn authorized<H: Hasher<Digest = D>>(&self, profile: &Profile<H::Digest>) -> bool {
        let Role::Validator(participant) = profile.role() else {
            return false;
        };
        let protocol = profile.protocol();
        if !self
            .requests
            .iter()
            .all(|request| request.matches_context(protocol.epoch()))
        {
            return false;
        }
        match self.requests.as_ref() {
            [] => false,
            [request] => match request {
                SignRequest::TransactionBlock(header) => {
                    protocol.producer(header.chain()) == Some(participant)
                }
                SignRequest::DaVote(request) => {
                    request.header().chain().index() < protocol.codec_config().chains()
                }
                SignRequest::LeaderBlock(request) => {
                    proposal_parent_valid::<H, V, D>(request.block(), request.parent(), profile)
                        && (!request.attach_parent() || request.parent().exact().is_some())
                }
                SignRequest::Vote(_) | SignRequest::NoVote { .. } | SignRequest::Nullify { .. } => {
                    true
                }
            },
            [
                SignRequest::NoVote { round: left },
                SignRequest::Nullify { round: right },
            ] if left == right => true,
            // Data-availability votes may share a signing barrier: several producer chains, and
            // per chain one run of strictly consecutive heights, where each vote counts as sent
            // for the next one's eligibility within the same authorization.
            requests => {
                let mut runs = BTreeMap::new();
                requests.iter().all(|request| {
                    matches!(request, SignRequest::DaVote(request)
                    if {
                        let header = request.header();
                        header.chain().index() < protocol.codec_config().chains()
                            && runs
                                .insert(header.chain(), header.height())
                                .is_none_or(|last| header.height() == last.next())
                    })
                })
            }
        }
    }
}

/// A durable network publication.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Publication<V: Variant, D: Digest> {
    /// Atomically broadcast the artifacts created by one signing choice.
    Broadcast(ArtifactBatch<V, D>),
    /// Publish a signed proposal with its referenced non-genesis V-QC.
    Propose(ProposalPublication<V, D>),
    /// Atomically send the artifacts created by one signing choice, each to its own recipient.
    Send(Arc<[SendRequest<V, D>]>),
}

impl<V: Variant, D: Digest> Publication<V, D> {
    /// Returns a broadcast of one artifact.
    pub(crate) fn broadcast(artifact: Arc<Artifact<V, D>>) -> Self {
        Self::Broadcast(Arc::from([artifact]))
    }

    /// Returns the artifacts published as their own messages, in item order.
    ///
    /// A proposal publishes its block and parent in one proposal message and returns none.
    pub(crate) fn artifacts(&self) -> impl Iterator<Item = &Arc<Artifact<V, D>>> {
        let broadcast = match self {
            Self::Broadcast(artifacts) => artifacts.as_ref(),
            Self::Propose(_) | Self::Send(_) => &[],
        };
        let send = match self {
            Self::Send(requests) => requests.as_ref(),
            Self::Broadcast(_) | Self::Propose(_) => &[],
        };
        broadcast
            .iter()
            .chain(send.iter().map(SendRequest::artifact))
    }

    /// Returns the artifact published as item `item`, if the publication has one.
    pub(crate) fn artifact(&self, item: usize) -> Option<&Arc<Artifact<V, D>>> {
        match self {
            Self::Broadcast(artifacts) => artifacts.get(item),
            Self::Send(requests) => requests.get(item).map(SendRequest::artifact),
            Self::Propose(_) => None,
        }
    }

    /// Visits every artifact, or artifact part, the publication retains.
    pub(crate) fn visit_retained(&self, mut visit: impl FnMut(Retained<'_, V, D>)) {
        match self {
            Self::Propose(publication) => {
                visit(Retained::LeaderBlock(publication.block()));
                if let Some(parent) = publication.parent().exact() {
                    visit(Retained::Vqc(parent));
                }
            }
            Self::Broadcast(_) | Self::Send(_) => {
                for artifact in self.artifacts() {
                    visit(Retained::Artifact(artifact));
                }
            }
        }
    }

    /// Returns whether releasing this publication could externalize one of `me`'s signatures.
    ///
    /// Individually attributed artifacts expose exactly their signer; certificates aggregate
    /// unattributed shares, so any aggregate may embed one of `me`'s votes and counts as a
    /// reference. A publication with no such reference is safe to release before its record is
    /// durable, because every message it carries is independently verifiable and could have
    /// been sent by any peer. Signing requests carry no signature: only the publication of their
    /// result does.
    pub(crate) fn references_own_signature(&self, me: Option<Participant>) -> bool {
        match self {
            Self::Propose(_) => true,
            Self::Broadcast(_) | Self::Send(_) => self
                .artifacts()
                .any(|artifact| artifact.signer().is_none_or(|signer| Some(signer) == me)),
        }
    }

    /// Returns the publication of `artifacts`, freshly signed for `requests` in order.
    pub(crate) fn signed(
        requests: &[SignRequest<V, D>],
        artifacts: &ArtifactBatch<V, D>,
        protocol: &Protocol<D>,
    ) -> Option<Self> {
        if let ([SignRequest::LeaderBlock(proposal)], [artifact]) = (requests, artifacts.as_ref())
            && let Artifact::LeaderBlock(block) = artifact.as_ref()
        {
            return Some(Self::Propose(proposal.signed(Arc::new(block.clone()))));
        }
        if artifacts.is_empty() {
            return None;
        }
        // Data-availability votes go to their producers; any other kind is broadcast.
        let mut sends = Vec::new();
        for artifact in artifacts.iter() {
            let Artifact::DaVote(vote) = artifact.as_ref() else {
                break;
            };
            let producer = protocol.producer(vote.header().chain())?;
            sends.push(SendRequest::new(producer, Arc::clone(artifact)));
        }
        if sends.len() == artifacts.len() {
            return Some(Self::Send(sends.into()));
        }
        artifacts
            .iter()
            .all(|artifact| {
                !matches!(
                    artifact.as_ref(),
                    Artifact::LeaderBlock(_) | Artifact::DaVote(_)
                )
            })
            .then(|| Self::Broadcast(Arc::clone(artifacts)))
    }

    pub(crate) fn authorized<H: Hasher<Digest = D>>(&self, profile: &Profile<H::Digest>) -> bool {
        let protocol = profile.protocol();
        match self {
            Self::Broadcast(artifacts) => match (profile.role(), artifacts.as_ref()) {
                (role, [artifact]) => {
                    let authorized = match artifact.as_ref() {
                        Artifact::DaVote(_) => false,
                        Artifact::DaCertificate(certificate) => matches!(
                            role,
                            Role::Validator(participant)
                                if protocol.producer(certificate.header().chain())
                                    == Some(participant)
                        ),
                        _ => true,
                    };
                    authorized && artifact_in_bounds(artifact, profile)
                }
                (Role::Validator(signer), [novote, nullify]) => {
                    let timeout = match (novote.as_ref(), nullify.as_ref()) {
                        (Artifact::NoVote(novote), Artifact::Nullify(nullify)) => {
                            novote.signer() == signer
                                && nullify.signer() == signer
                                && novote.round() == nullify.round()
                        }
                        _ => false,
                    };
                    timeout
                        && artifacts
                            .iter()
                            .all(|artifact| artifact_in_bounds(artifact, profile))
                }
                _ => false,
            },
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
            Self::Send(requests) => {
                !requests.is_empty()
                    && requests
                        .iter()
                        .all(|request| send_authorized(request, profile))
            }
        }
    }
}

/// Returns whether `artifact` fits the epoch, the artifact size bound and the committee.
fn artifact_in_bounds<V: Variant, D: Digest>(
    artifact: &Artifact<V, D>,
    profile: &Profile<D>,
) -> bool {
    let protocol = profile.protocol();
    artifact.encoded_len() <= profile.resources().max_artifact_bytes()
        && artifact.epoch() == protocol.epoch()
        && artifact.signer().is_none_or(|participant| {
            usize::from(participant) < protocol.codec_config().participants()
        })
}

/// Returns whether `request` sends this validator's DA vote to the vote's producer.
fn send_authorized<V: Variant, D: Digest>(
    request: &SendRequest<V, D>,
    profile: &Profile<D>,
) -> bool {
    let protocol = profile.protocol();
    matches!((profile.role(), request.artifact().as_ref()),
        (Role::Validator(sender), Artifact::DaVote(vote))
            if protocol.producer(vote.header().chain()) == Some(request.recipient())
                && vote.signer() == sender)
        && usize::from(request.recipient()) < protocol.codec_config().participants()
        && artifact_in_bounds(request.artifact(), profile)
}

/// An external action whose authorization and stable ID survive recovery.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum DurableEffect<V: Variant, D: Digest> {
    /// Sign subjects whose results are published together.
    Sign(SignEffect<V, D>),
    /// Publish artifacts to peers.
    Publish(Publication<V, D>),
}

impl<V: Variant, D: Digest> DurableEffect<V, D> {
    /// Returns an effect signing one request.
    pub(crate) fn sign(request: SignRequest<V, D>) -> Self {
        Self::Sign(SignEffect::one(request))
    }

    /// Returns an effect broadcasting one artifact.
    pub(crate) fn broadcast(artifact: Arc<Artifact<V, D>>) -> Self {
        Self::Publish(Publication::broadcast(artifact))
    }

    /// Returns the signing requests, if this effect signs.
    pub(crate) fn sign_requests(&self) -> Option<&[SignRequest<V, D>]> {
        match self {
            Self::Sign(effect) => Some(effect.requests()),
            Self::Publish(_) => None,
        }
    }

    /// Returns the publication, if this effect publishes.
    pub(crate) const fn publication(&self) -> Option<&Publication<V, D>> {
        match self {
            Self::Sign(_) => None,
            Self::Publish(publication) => Some(publication),
        }
    }

    /// Returns how many artifact cache slots the effect reserves for its signing results.
    pub(crate) fn reservations(&self) -> usize {
        self.sign_requests().map_or(0, <[_]>::len)
    }

    /// Visits every artifact, or artifact part, this effect retains.
    pub(crate) fn visit_retained(&self, visit: impl FnMut(Retained<'_, V, D>)) {
        match self {
            Self::Sign(effect) => effect.visit_retained(visit),
            Self::Publish(publication) => publication.visit_retained(visit),
        }
    }

    /// Visits the identifiers of the artifacts this effect holds a cache reference to.
    ///
    /// A block awaiting a data-availability vote is charged as a signing reservation instead.
    pub(crate) fn visit_references<H: Hasher<Digest = D>>(
        &self,
        mut visit: impl FnMut(ArtifactId<D>),
    ) {
        self.visit_retained(|retained| {
            if !matches!(retained, Retained::DaVoteBlock(_)) {
                visit(retained.id::<H>());
            }
        });
    }

    pub(crate) fn authorized<H: Hasher<Digest = D>>(&self, profile: &Profile<D>) -> bool {
        match self {
            Self::Sign(effect) => effect.authorized::<H>(profile),
            Self::Publish(publication) => publication.authorized::<H>(profile),
        }
    }
}

/// Returns whether `parent` is the exact certificate `block` names as its parent, from this
/// epoch and an earlier view, within the artifact size bound.
fn proposal_parent_valid<H, V, D>(
    block: &LeaderBlock<V, D>,
    parent: &ProposalParent<Arc<Vqc<V, D>>>,
    profile: &Profile<H::Digest>,
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
pub(crate) struct DurableJob<V: Variant, D: Digest> {
    issued: Issued<EffectId>,
    request: DurableEffect<V, D>,
}

impl<V: Variant, D: Digest> DurableJob<V, D> {
    pub(crate) const fn new(issued: Issued<EffectId>, request: DurableEffect<V, D>) -> Self {
        Self { issued, request }
    }

    /// Returns the stable idempotency identifier and the generation issuing this attempt.
    #[cfg(any(test, feature = "mocks"))]
    pub(crate) const fn issued(&self) -> Issued<EffectId> {
        self.issued
    }

    /// Returns the immutable action.
    #[cfg(any(test, feature = "mocks"))]
    pub(crate) const fn request(&self) -> &DurableEffect<V, D> {
        &self.request
    }

    /// Consumes the job and returns its stable identity and action.
    pub(crate) fn into_parts(self) -> (Issued<EffectId>, DurableEffect<V, D>) {
        (self.issued, self.request)
    }
}

/// Completion of one stable outbox action.
#[derive(Clone, Debug)]
pub(crate) struct EffectCompletion<V: Variant, D: Digest> {
    /// The completed action.
    pub(crate) issued: Issued<EffectId>,
    /// What the action produced.
    pub(crate) result: EffectResult<V, D>,
}

impl<V: Variant, D: Digest> EffectCompletion<V, D> {
    /// Returns a completion carrying the artifacts of one signing choice, in request order.
    pub(crate) const fn signed(
        issued: Issued<EffectId>,
        artifacts: Vec<Arc<Artifact<V, D>>>,
    ) -> Self {
        Self {
            issued,
            result: EffectResult::Signed(artifacts),
        }
    }

    /// Returns a completion reporting one accepted publication attempt.
    pub(crate) const fn delivered(issued: Issued<EffectId>) -> Self {
        Self {
            issued,
            result: EffectResult::Delivered,
        }
    }
}

/// What one stable outbox action produced.
#[derive(Clone, Debug)]
pub(crate) enum EffectResult<V: Variant, D: Digest> {
    /// The artifacts of one signing choice, in request order.
    Signed(Vec<Arc<Artifact<V, D>>>),
    /// The attached transport accepted one publication attempt.
    ///
    /// This is volatile feedback and does not retire the durable publication. Only an authenticated
    /// protocol successor can do that.
    Delivered,
}
