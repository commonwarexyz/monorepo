//! Durable external actions: signing requests, publications, and their authorization.

use super::EffectId;
use crate::{
    Epochable, Viewable,
    multimmit::{
        config::{Profile, Role},
        machine::job::Issued,
        scheme::bls12381::{Error as SchemeError, Scheme},
        types::{
            Artifact, ArtifactBatch, ArtifactId, ArtifactKind, ChainChange, LeaderBlock,
            SignedLeaderBlock, SignedTransactionBlock, TransactionBlockHeader, ViewProof,
            VoteContent, VoteUpdate, Vqc,
        },
    },
    types::{Attributable, Epoch, Participant, View},
};
use commonware_codec::EncodeSize;
use commonware_cryptography::{Digest, Hasher, PublicKey, bls12381::primitives::variant::Variant};
use std::sync::Arc;

/// One vote update to sign: the full content the signature covers, and the sequence number and
/// changed chains the published update carries.
///
/// The changes name the chains whose tips differ from the update the reader rebuilds against,
/// with payload hashes that let a reader rebuild headers it lacks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct UpdateRequest<D: Digest> {
    pub(super) content: VoteContent<D>,
    pub(super) seq: u32,
    pub(super) changes: Vec<ChainChange<D>>,
}

impl<D: Digest> UpdateRequest<D> {
    pub(crate) const fn new(
        content: VoteContent<D>,
        seq: u32,
        changes: Vec<ChainChange<D>>,
    ) -> Self {
        Self {
            content,
            seq,
            changes,
        }
    }

    /// Returns the signed content.
    pub(crate) const fn content(&self) -> &VoteContent<D> {
        &self.content
    }

    /// Returns the update's sequence number within its view tag.
    pub(crate) const fn seq(&self) -> u32 {
        self.seq
    }

    /// Returns the changed chains in ascending order.
    pub(crate) fn changes(&self) -> &[ChainChange<D>] {
        &self.changes
    }

    /// Returns whether `update` publishes exactly this request.
    fn matches<V: Variant>(&self, update: &VoteUpdate<V, D>) -> bool {
        update.round() == self.content.round()
            && update.leader() == self.content.leader()
            && update.is_final() == self.content.is_final()
            && update.declared() == self.content.declared()
            && update.seq() == self.seq
            && update.changes() == self.changes.as_slice()
    }

    /// Returns whether every change names its chain's tip in the content.
    fn consistent(&self) -> bool {
        self.seq != 0
            && self
                .changes
                .windows(2)
                .all(|pair| pair[0].chain() < pair[1].chain())
            && self.changes.iter().all(|change| {
                self.content
                    .tips()
                    .get(change.chain().index())
                    .is_some_and(|tip| *tip == change.tip())
            })
    }
}

/// A typed subject the local scheme may sign.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum SignRequest<V: Variant, D: Digest> {
    /// Authorize one own-chain header whose body is in custody.
    TransactionBlock(TransactionBlockHeader<D>),
    /// Authorize one scheduled leader proposal and retain its parent certificate.
    LeaderBlock(ProposalRequest<V, D>),
    /// Authorize one vote update.
    Update(UpdateRequest<D>),
}

impl<V: Variant, D: Digest> SignRequest<V, D> {
    /// Returns the stable operation label recorded on signing spans.
    pub(crate) const fn label(&self) -> &'static str {
        match self {
            Self::TransactionBlock(_) => "transaction_block",
            Self::LeaderBlock(_) => "leader_block",
            Self::Update(_) => "update",
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
            Self::LeaderBlock(request) => {
                Artifact::LeaderBlock(scheme.sign_leader_block(request.block().clone())?)
            }
            Self::Update(request) => {
                let content = request.content();
                let attestation = scheme.sign_vote(content)?;
                Artifact::Update(VoteUpdate::new(
                    content.round(),
                    content.leader(),
                    content.is_final(),
                    content.declared().clone(),
                    request.seq(),
                    request.changes().to_vec(),
                    attestation,
                    scheme.codec_config(),
                )?)
            }
        };
        Ok(artifact)
    }

    fn visit_retained(&self, visit: &mut impl FnMut(Retained<'_, V, D>)) {
        if let Self::LeaderBlock(request) = self
            && let Some(parent) = request.parent().exact()
        {
            visit(Retained::Vqc(parent));
        }
    }

    /// Returns the view a consensus request is tagged with, or `None` for a header.
    pub(crate) fn consensus_view(&self) -> Option<View> {
        match self {
            Self::TransactionBlock(_) => None,
            Self::LeaderBlock(request) => Some(request.block().view()),
            Self::Update(request) => Some(request.content().view()),
        }
    }

    pub(crate) fn matches_context(&self, epoch: Epoch) -> bool {
        match self {
            Self::TransactionBlock(header) => header.epoch() == epoch,
            Self::LeaderBlock(request) => request.block().epoch() == epoch,
            Self::Update(request) => request.content().epoch() == epoch,
        }
    }

    /// Returns whether `artifact` is `signer`'s signature over exactly this request.
    pub(crate) fn matches(&self, signer: Participant, artifact: &Artifact<V, D>) -> bool {
        if artifact.signer() != Some(signer) {
            return false;
        }
        match (self, artifact) {
            (Self::TransactionBlock(expected), Artifact::TransactionBlock(actual)) => {
                expected == actual.header()
            }
            (Self::LeaderBlock(expected), Artifact::LeaderBlock(actual)) => {
                expected.block() == actual.block()
            }
            (Self::Update(expected), Artifact::Update(actual)) => expected.matches(actual),
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
pub(crate) type ProposalRequest<V, D> = Proposal<V, D, LeaderBlock<D>>;

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

    /// Returns the parent referenced by the block.
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

/// An artifact, or artifact part, retained by durable state.
pub(crate) enum Retained<'a, V: Variant, D: Digest> {
    /// A complete artifact.
    Artifact(&'a Arc<Artifact<V, D>>),
    /// An accepted header.
    Header(&'a Arc<SignedTransactionBlock<V, D>>),
    /// The signed block of a proposal publication.
    LeaderBlock(&'a Arc<SignedLeaderBlock<V, D>>),
    /// The parent of a proposal publication or leader-block signing request.
    Vqc(&'a Arc<Vqc<V, D>>),
}

impl<V: Variant, D: Digest> Retained<'_, V, D> {
    /// Returns the identifier of the artifact this item is or encodes as.
    pub(crate) fn id<H: Hasher<Digest = D>>(&self) -> ArtifactId<D> {
        match self {
            Self::Artifact(artifact) => artifact.id::<H>(),
            Self::Header(header) => {
                Artifact::<V, D>::id_of::<H, _>(ArtifactKind::TransactionBlock, header.as_ref())
            }
            Self::LeaderBlock(block) => {
                Artifact::<V, D>::id_of::<H, _>(ArtifactKind::LeaderBlock, block.as_ref())
            }
            Self::Vqc(certificate) => {
                Artifact::<V, D>::id_of::<H, _>(ArtifactKind::Vqc, certificate.as_ref())
            }
        }
    }

    /// Returns the item as an artifact, cloning an artifact part into its own artifact.
    pub(crate) fn to_artifact(&self) -> Arc<Artifact<V, D>> {
        match self {
            Self::Artifact(artifact) => Arc::clone(artifact),
            Self::Header(header) => Arc::new(Artifact::TransactionBlock(header.as_ref().clone())),
            Self::LeaderBlock(block) => Arc::new(Artifact::LeaderBlock(block.as_ref().clone())),
            Self::Vqc(certificate) => Arc::new(Artifact::Vqc(certificate.as_ref().clone())),
        }
    }

    /// Returns the item as a view proof, if it is one.
    pub(crate) fn view_proof(&self) -> Option<ViewProof<V, D>> {
        match self {
            Self::Artifact(artifact) => ViewProof::from_artifact(artifact),
            Self::Vqc(proof) => Some(ViewProof::Vqc(Box::new(proof.as_ref().clone()))),
            Self::Header(_) | Self::LeaderBlock(_) => None,
        }
    }
}

/// Signing requests authorized together, whose results are published together.
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

    /// Returns the requests in signing and publication order, consuming the effect.
    pub(crate) fn into_requests(self) -> Arc<[SignRequest<V, D>]> {
        self.requests
    }

    /// Visits every artifact part the requests retain.
    pub(crate) fn visit_retained(&self, mut visit: impl FnMut(Retained<'_, V, D>)) {
        for request in self.requests.iter() {
            request.visit_retained(&mut visit);
        }
    }

    /// Returns whether `profile`'s validator may sign this choice: exactly one request of the
    /// local epoch, for a header of its own chain, a proposal it leads, or a well-formed update.
    pub(crate) fn authorized<H: Hasher<Digest = D>>(&self, profile: &Profile<H::Digest>) -> bool {
        let Role::Validator(participant) = profile.role() else {
            return false;
        };
        let protocol = profile.protocol();
        let [request] = self.requests.as_ref() else {
            return false;
        };
        if !request.matches_context(protocol.epoch()) {
            return false;
        }
        match request {
            SignRequest::TransactionBlock(header) => {
                protocol.producer(header.chain()) == Some(participant)
            }
            SignRequest::LeaderBlock(request) => {
                protocol.leader(request.block().view()) == participant
                    && proposal_parent_valid::<H, V, D>(request.block(), request.parent(), profile)
                    && (!request.attach_parent() || request.parent().exact().is_some())
            }
            SignRequest::Update(request) => request.consistent(),
        }
    }
}

/// A durable network publication.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Publication<V: Variant, D: Digest> {
    /// Atomically broadcast a batch of artifacts.
    Broadcast(ArtifactBatch<V, D>),
    /// Publish a signed proposal with its referenced non-genesis V-QC.
    Propose(ProposalPublication<V, D>),
}

impl<V: Variant, D: Digest> Publication<V, D> {
    /// Returns a broadcast of one artifact.
    pub(crate) fn broadcast(artifact: Arc<Artifact<V, D>>) -> Self {
        Self::Broadcast(Arc::from([artifact]))
    }

    /// Returns the artifacts published as their own messages, in item order.
    ///
    /// A proposal publishes its block and parent in one proposal message and returns none.
    pub(crate) fn artifacts(&self) -> &[Arc<Artifact<V, D>>] {
        match self {
            Self::Broadcast(artifacts) => artifacts,
            Self::Propose(_) => &[],
        }
    }

    /// Returns the number of items whose publication can be discharged separately.
    pub(crate) fn items(&self) -> usize {
        match self {
            Self::Broadcast(artifacts) => artifacts.len(),
            Self::Propose(_) => 1,
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
            Self::Broadcast(artifacts) => {
                for artifact in artifacts.iter() {
                    visit(Retained::Artifact(artifact));
                }
            }
        }
    }

    /// Returns whether releasing this publication could externalize one of `me`'s signatures.
    ///
    /// Individually attributed artifacts expose exactly their signer; certificates aggregate
    /// unattributed signatures, so any certificate may embed one of `me`'s votes. A publication
    /// with no such reference is safe to release before its record is durable, because every
    /// message it carries is independently verifiable and could have been sent by any peer.
    pub(crate) fn references_own_signature(&self, me: Option<Participant>) -> bool {
        match self {
            Self::Propose(_) => true,
            Self::Broadcast(artifacts) => artifacts
                .iter()
                .any(|artifact| artifact.signer().is_none_or(|signer| Some(signer) == me)),
        }
    }

    /// Returns the publication of `artifacts`, freshly signed for `requests` in order.
    pub(crate) fn signed(
        requests: &[SignRequest<V, D>],
        artifacts: &ArtifactBatch<V, D>,
    ) -> Option<Self> {
        if let ([SignRequest::LeaderBlock(proposal)], [artifact]) = (requests, artifacts.as_ref())
            && let Artifact::LeaderBlock(block) = artifact.as_ref()
        {
            return Some(Self::Propose(proposal.signed(Arc::new(block.clone()))));
        }
        (!artifacts.is_empty()
            && artifacts
                .iter()
                .all(|artifact| !matches!(artifact.as_ref(), Artifact::LeaderBlock(_))))
        .then(|| Self::Broadcast(Arc::clone(artifacts)))
    }

    /// Returns whether `profile` may publish this: every broadcast artifact is in bounds, is not
    /// a bare leader block, and is either a certificate or signed by the local validator; a
    /// proposal is signed by its view's leader and names a valid parent.
    pub(crate) fn authorized<H: Hasher<Digest = D>>(&self, profile: &Profile<H::Digest>) -> bool {
        let protocol = profile.protocol();
        match self {
            Self::Broadcast(artifacts) => {
                let me = match profile.role() {
                    Role::Validator(participant) => Some(participant),
                    Role::Observer => None,
                };
                !artifacts.is_empty()
                    && artifacts.iter().all(|artifact| {
                        !matches!(artifact.as_ref(), Artifact::LeaderBlock(_))
                            && artifact.signer().is_none_or(|signer| Some(signer) == me)
                            && artifact_in_bounds(artifact, profile)
                    })
            }
            Self::Propose(publication) => {
                let block = publication.block();
                block.signer() == protocol.leader(block.view())
                    && block.epoch() == protocol.epoch()
                    && block.encode_size() <= profile.resources().max_artifact_bytes()
                    && (!publication.attach_parent() || publication.parent().exact().is_some())
                    && proposal_parent_valid::<H, V, D>(
                        block.block(),
                        publication.parent(),
                        profile,
                    )
            }
        }
    }
}

/// Returns whether `artifact` fits the epoch, the artifact size bound, and the committee.
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
    #[cfg(test)]
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
    block: &LeaderBlock<D>,
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
    /// This is volatile feedback and does not retire the durable publication. Only an
    /// authenticated protocol successor can do that.
    Delivered,
}
