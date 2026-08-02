//! Producer-chain and leader-chain protocol objects.

use super::{
    Attestation, BlockRef, CertificateId, ChainId, Error, Height, ThresholdShare,
    certificate::DaCertificate,
};
use crate::{
    Block, Epochable, Heightable, Viewable,
    multimmit::config::CodecConfig,
    types::{Attributable, Epoch, Participant, Round, View},
};
use bytes::{Buf, BufMut};
use commonware_codec::{
    Codec, Encode, EncodeSize, Error as CodecError, RangeCfg, Read, ReadExt, Write,
};
use commonware_cryptography::{Digest, Digestible, Hasher, bls12381::primitives::variant::Variant};
use core::{
    fmt,
    hash::{Hash, Hasher as CoreHasher},
    marker::PhantomData,
};
use std::sync::Arc;

/// The certificate attached to a leader proposal.
///
/// The genesis variant names the configured synthetic certificate. Every other proposal names and
/// carries one exact view quorum certificate.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum ProposalParent<Q> {
    /// The configured synthetic genesis certificate.
    Genesis,
    /// The exact view quorum certificate referenced by the leader block.
    Exact(Q),
}

impl<Q> ProposalParent<Q> {
    /// Returns whether this parent is the synthetic genesis certificate.
    pub const fn is_genesis(&self) -> bool {
        matches!(self, Self::Genesis)
    }

    /// Returns the exact parent certificate, if this is a live parent.
    pub const fn exact(&self) -> Option<&Q> {
        match self {
            Self::Genesis => None,
            Self::Exact(parent) => Some(parent),
        }
    }
}

/// Consensus metadata associated with one application payload.
///
/// The same value is supplied when a producer builds a payload and when another validator checks
/// it. Every field is reconstructible from the signed transaction-block header; transient mempool
/// state and payload-storage details are deliberately excluded.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct Context<D: Digest> {
    epoch: Epoch,
    chain: ChainId,
    height: Height,
    parent: D,
}

impl<D: Digest> Context<D> {
    /// Creates application context for one producer-chain position.
    pub const fn new(
        epoch: Epoch,
        chain: ChainId,
        height: Height,
        parent: D,
    ) -> Result<Self, Error> {
        if height.is_zero() {
            return Err(Error::GenesisHeight);
        }
        Ok(Self {
            epoch,
            chain,
            height,
            parent,
        })
    }

    /// Returns the producer chain.
    pub const fn chain(self) -> ChainId {
        self.chain
    }

    /// Returns the canonical identity of the parent producer-block header.
    pub const fn parent(self) -> D {
        self.parent
    }
}

impl<D: Digest> Epochable for Context<D> {
    fn epoch(&self) -> Epoch {
        self.epoch
    }
}

impl<D: Digest> Heightable for Context<D> {
    fn height(&self) -> Height {
        self.height
    }
}

impl<D: Digest> From<&TransactionBlockHeader<D>> for Context<D> {
    fn from(header: &TransactionBlockHeader<D>) -> Self {
        Self {
            epoch: header.epoch,
            chain: header.chain,
            height: header.height,
            parent: header.parent,
        }
    }
}

/// The protocol metadata that identifies one application block.
///
/// Multimmit leaves the application block body and its encoding to the attached application. This
/// header binds the chain coordinates, canonical parent identity, and the digest of that
/// external body. The block's protocol identity is the digest of the complete header.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TransactionBlockHeader<D: Digest> {
    epoch: Epoch,
    chain: ChainId,
    height: Height,
    parent: D,
    body_digest: D,
}

impl<D: Digest> TransactionBlockHeader<D> {
    /// Creates a live producer-chain header.
    ///
    /// Height zero is reserved for the synthetic genesis block of each producer chain.
    pub const fn new(
        epoch: Epoch,
        chain: ChainId,
        height: Height,
        parent: D,
        body_digest: D,
    ) -> Result<Self, Error> {
        if height.is_zero() {
            return Err(Error::GenesisHeight);
        }

        Ok(Self {
            epoch,
            chain,
            height,
            parent,
            body_digest,
        })
    }

    /// Returns the producer chain.
    pub const fn chain(&self) -> ChainId {
        self.chain
    }

    /// Returns the chain-local height.
    pub const fn height(&self) -> Height {
        self.height
    }

    /// Returns the canonical identity of the parent producer-block header.
    pub const fn parent(&self) -> D {
        self.parent
    }

    /// Returns the canonical digest of the opaque application body.
    pub const fn body_digest(&self) -> D {
        self.body_digest
    }

    /// Returns the digest of this canonical header.
    pub fn digest<H: Hasher<Digest = D>>(&self) -> D {
        H::hash(&[self.encode().as_ref()])
    }

    /// Returns this producer block's canonical protocol identity.
    pub fn block_ref<H: Hasher<Digest = D>>(&self) -> BlockRef<D> {
        BlockRef::new(self.chain, self.height, self.digest::<H>())
    }
}

impl<D: Digest> Epochable for TransactionBlockHeader<D> {
    fn epoch(&self) -> Epoch {
        self.epoch
    }
}

impl<D: Digest> Heightable for TransactionBlockHeader<D> {
    fn height(&self) -> Height {
        self.height
    }
}

impl<D: Digest> Write for TransactionBlockHeader<D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.epoch.write(buf);
        self.chain.write(buf);
        self.height.write(buf);
        self.parent.write(buf);
        self.body_digest.write(buf);
    }
}

impl<D: Digest> Read for TransactionBlockHeader<D> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        Self::new(
            Epoch::read(buf)?,
            ChainId::read(buf)?,
            Height::read(buf)?,
            D::read(buf)?,
            D::read(buf)?,
        )
        .map_err(|_| CodecError::Invalid("TransactionBlockHeader", "height zero is synthetic"))
    }
}

impl<D: Digest> EncodeSize for TransactionBlockHeader<D> {
    fn encode_size(&self) -> usize {
        self.epoch.encode_size()
            + self.chain.encode_size()
            + self.height.encode_size()
            + self.parent.encode_size()
            + self.body_digest.encode_size()
    }
}

/// A complete producer-chain block.
///
/// The header carries all protocol metadata and commits to the opaque application body. The
/// block's canonical consensus identity is the digest of that header; the body's digest is used
/// only to verify the body digest when the two are paired or decoded.
pub struct TransactionBlock<H, B>
where
    H: Hasher,
    B: Codec + Digestible<Digest = H::Digest>,
{
    header: TransactionBlockHeader<H::Digest>,
    body: Arc<B>,
    _hasher: PhantomData<H>,
}

impl<H, B> TransactionBlock<H, B>
where
    H: Hasher,
    B: Codec + Digestible<Digest = H::Digest>,
{
    /// Constructs a block from application context and an owned body.
    pub fn from_context(context: Context<H::Digest>, body: B) -> Self {
        Self::from_shared_context(context, Arc::new(body))
    }

    /// Constructs a block from application context and an already shared body.
    pub fn from_shared_context(context: Context<H::Digest>, body: Arc<B>) -> Self {
        let header = TransactionBlockHeader::new(
            context.epoch(),
            context.chain(),
            context.height(),
            context.parent(),
            body.digest(),
        )
        .expect("application context always names a live producer height");
        Self {
            header,
            body,
            _hasher: PhantomData,
        }
    }

    /// Pairs a canonical producer header with an owned application body.
    pub fn new(header: TransactionBlockHeader<H::Digest>, body: B) -> Result<Self, Error> {
        Self::from_shared(header, Arc::new(body))
    }

    /// Pairs a canonical producer header with an already shared application body.
    pub fn from_shared(
        header: TransactionBlockHeader<H::Digest>,
        body: Arc<B>,
    ) -> Result<Self, Error> {
        if header.body_digest() != body.digest() {
            return Err(Error::Commitment);
        }
        Ok(Self {
            header,
            body,
            _hasher: PhantomData,
        })
    }

    /// Returns the canonical producer header.
    pub const fn header(&self) -> &TransactionBlockHeader<H::Digest> {
        &self.header
    }

    /// Returns the opaque application body.
    pub fn body(&self) -> &B {
        self.body.as_ref()
    }

    /// Returns a shared handle to the opaque application body.
    pub fn body_shared(&self) -> Arc<B> {
        Arc::clone(&self.body)
    }

    /// Returns the canonical producer-chain reference.
    pub fn reference(&self) -> BlockRef<H::Digest> {
        self.header.block_ref::<H>()
    }

    /// Discards the producer header and returns the shared application body.
    pub fn into_body(self) -> Arc<B> {
        self.body
    }
}

impl<H, B> Clone for TransactionBlock<H, B>
where
    H: Hasher,
    B: Codec + Digestible<Digest = H::Digest>,
{
    fn clone(&self) -> Self {
        Self {
            header: self.header.clone(),
            body: Arc::clone(&self.body),
            _hasher: PhantomData,
        }
    }
}

impl<H, B> fmt::Debug for TransactionBlock<H, B>
where
    H: Hasher,
    B: Codec + Digestible<Digest = H::Digest> + fmt::Debug,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TransactionBlock")
            .field("header", &self.header)
            .field("body", &self.body)
            .finish()
    }
}

impl<H, B> PartialEq for TransactionBlock<H, B>
where
    H: Hasher,
    B: Codec + Digestible<Digest = H::Digest> + PartialEq,
{
    fn eq(&self, other: &Self) -> bool {
        self.header == other.header && self.body == other.body
    }
}

impl<H, B> Eq for TransactionBlock<H, B>
where
    H: Hasher,
    B: Codec + Digestible<Digest = H::Digest> + Eq,
{
}

impl<H, B> Write for TransactionBlock<H, B>
where
    H: Hasher,
    B: Codec + Digestible<Digest = H::Digest>,
{
    fn write(&self, buf: &mut impl BufMut) {
        self.header.write(buf);
        self.body.write(buf);
    }
}

impl<H, B> Read for TransactionBlock<H, B>
where
    H: Hasher,
    B: Codec + Digestible<Digest = H::Digest>,
{
    type Cfg = B::Cfg;

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        let header = TransactionBlockHeader::read(buf)?;
        let body = B::read_cfg(buf, cfg)?;
        Self::new(header, body).map_err(|_| {
            CodecError::Invalid("TransactionBlock", "body does not match the header digest")
        })
    }
}

impl<H, B> EncodeSize for TransactionBlock<H, B>
where
    H: Hasher,
    B: Codec + Digestible<Digest = H::Digest>,
{
    fn encode_size(&self) -> usize {
        self.header.encode_size() + self.body.encode_size()
    }
}

impl<H, B> Digestible for TransactionBlock<H, B>
where
    H: Hasher,
    B: Codec + Digestible<Digest = H::Digest>,
{
    type Digest = H::Digest;

    fn digest(&self) -> Self::Digest {
        self.header.digest::<H>()
    }
}

impl<H, B> Block for TransactionBlock<H, B>
where
    H: Hasher,
    B: Codec + Digestible<Digest = H::Digest>,
{
    fn parent(&self) -> Self::Digest {
        self.header.parent()
    }
}

impl<H, B> Heightable for TransactionBlock<H, B>
where
    H: Hasher,
    B: Codec + Digestible<Digest = H::Digest>,
{
    fn height(&self) -> Height {
        self.header.height()
    }
}

impl<H, B> Epochable for TransactionBlock<H, B>
where
    H: Hasher,
    B: Codec + Digestible<Digest = H::Digest>,
{
    fn epoch(&self) -> Epoch {
        self.header.epoch()
    }
}

/// A producer-authenticated application-block header.
#[derive(Clone, Debug)]
pub struct SignedTransactionBlock<V: Variant, D: Digest> {
    header: TransactionBlockHeader<D>,
    attestation: Attestation<V>,
}

impl<V: Variant, D: Digest> SignedTransactionBlock<V, D> {
    /// Creates an attributed producer signature over `header`.
    ///
    /// This constructor does not verify the signature or that its signer owns the named chain.
    pub const fn new(header: TransactionBlockHeader<D>, attestation: Attestation<V>) -> Self {
        Self {
            header,
            attestation,
        }
    }

    /// Returns the signed protocol header.
    pub const fn header(&self) -> &TransactionBlockHeader<D> {
        &self.header
    }

    /// Returns the producer attestation.
    pub const fn attestation(&self) -> &Attestation<V> {
        &self.attestation
    }
}

impl<V: Variant, D: Digest> PartialEq for SignedTransactionBlock<V, D> {
    fn eq(&self, other: &Self) -> bool {
        self.header == other.header && self.attestation == other.attestation
    }
}

impl<V: Variant, D: Digest> Eq for SignedTransactionBlock<V, D> {}

impl<V: Variant, D: Digest> Hash for SignedTransactionBlock<V, D> {
    fn hash<H: CoreHasher>(&self, state: &mut H) {
        self.header.hash(state);
        self.attestation.hash(state);
    }
}

impl<V: Variant, D: Digest> Epochable for SignedTransactionBlock<V, D> {
    fn epoch(&self) -> Epoch {
        self.header.epoch()
    }
}

impl<V: Variant, D: Digest> Heightable for SignedTransactionBlock<V, D> {
    fn height(&self) -> Height {
        self.header.height()
    }
}

impl<V: Variant, D: Digest> Attributable for SignedTransactionBlock<V, D> {
    fn signer(&self) -> Participant {
        self.attestation.signer()
    }
}

impl<V: Variant, D: Digest> Write for SignedTransactionBlock<V, D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.header.write(buf);
        self.attestation.write(buf);
    }
}

impl<V: Variant, D: Digest> Read for SignedTransactionBlock<V, D> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        Ok(Self::new(
            TransactionBlockHeader::read(buf)?,
            Attestation::read(buf)?,
        ))
    }
}

impl<V: Variant, D: Digest> EncodeSize for SignedTransactionBlock<V, D> {
    fn encode_size(&self) -> usize {
        self.header.encode_size() + self.attestation.encode_size()
    }
}

/// One attributed data-availability vote over a complete transaction-block header.
#[derive(Clone, Debug)]
pub struct DaVote<V: Variant, D: Digest> {
    header: TransactionBlockHeader<D>,
    share: ThresholdShare<V>,
}

impl<V: Variant, D: Digest> DaVote<V, D> {
    /// Creates an attributed data-availability vote.
    ///
    /// This constructor does not verify the signature or the voter's eligibility.
    pub const fn new(header: TransactionBlockHeader<D>, share: ThresholdShare<V>) -> Self {
        Self { header, share }
    }

    /// Returns the complete voted header.
    pub const fn header(&self) -> &TransactionBlockHeader<D> {
        &self.header
    }

    /// Returns the voter's threshold share.
    pub const fn share(&self) -> &ThresholdShare<V> {
        &self.share
    }
}

impl<V: Variant, D: Digest> PartialEq for DaVote<V, D> {
    fn eq(&self, other: &Self) -> bool {
        self.header == other.header && self.share == other.share
    }
}

impl<V: Variant, D: Digest> Eq for DaVote<V, D> {}

impl<V: Variant, D: Digest> Hash for DaVote<V, D> {
    fn hash<H: CoreHasher>(&self, state: &mut H) {
        self.header.hash(state);
        self.share.hash(state);
    }
}

impl<V: Variant, D: Digest> Epochable for DaVote<V, D> {
    fn epoch(&self) -> Epoch {
        self.header.epoch()
    }
}

impl<V: Variant, D: Digest> Heightable for DaVote<V, D> {
    fn height(&self) -> Height {
        self.header.height()
    }
}

impl<V: Variant, D: Digest> Attributable for DaVote<V, D> {
    fn signer(&self) -> Participant {
        self.share.signer()
    }
}

impl<V: Variant, D: Digest> Write for DaVote<V, D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.header.write(buf);
        self.share.write(buf);
    }
}

impl<V: Variant, D: Digest> Read for DaVote<V, D> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        Ok(Self::new(
            TransactionBlockHeader::read(buf)?,
            ThresholdShare::read(buf)?,
        ))
    }
}

impl<V: Variant, D: Digest> EncodeSize for DaVote<V, D> {
    fn encode_size(&self) -> usize {
        self.header.encode_size() + self.share.encode_size()
    }
}

/// The base of one producer-chain proposal.
///
/// A certificate variant carries a recovered DA signature. Constructing or decoding an anchor does
/// not cryptographically verify it.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Anchor<V: Variant, D: Digest> {
    /// An explicit safe-tip reference inherited from the parent V-QC.
    Tip(BlockRef<D>),
    /// A higher data-availability certificate carried with the proposal.
    Certificate(DaCertificate<V, D>),
}

impl<V: Variant, D: Digest> Anchor<V, D> {
    /// Returns the anchor's producer chain.
    pub const fn chain(&self) -> ChainId {
        match self {
            Self::Tip(reference) => reference.chain(),
            Self::Certificate(certificate) => certificate.header().chain(),
        }
    }

    /// Returns the anchor's chain-local height.
    pub const fn height(&self) -> Height {
        match self {
            Self::Tip(reference) => reference.height(),
            Self::Certificate(certificate) => certificate.header().height(),
        }
    }

    /// Returns the block reference named by this anchor.
    pub fn block_ref<H: Hasher<Digest = D>>(&self) -> BlockRef<D> {
        match self {
            Self::Tip(reference) => *reference,
            Self::Certificate(certificate) => certificate.header().block_ref::<H>(),
        }
    }
}

impl<V: Variant, D: Digest> Write for Anchor<V, D> {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::Tip(reference) => {
                0u8.write(buf);
                reference.write(buf);
            }
            Self::Certificate(certificate) => {
                1u8.write(buf);
                certificate.write(buf);
            }
        }
    }
}

impl<V: Variant, D: Digest> Read for Anchor<V, D> {
    type Cfg = CodecConfig;

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        match u8::read(buf)? {
            0 => Ok(Self::Tip(BlockRef::read(buf)?)),
            1 => Ok(Self::Certificate(DaCertificate::read(buf)?)),
            tag => Err(CodecError::InvalidEnum(tag)),
        }
    }
}

impl<V: Variant, D: Digest> EncodeSize for Anchor<V, D> {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Tip(reference) => reference.encode_size(),
            Self::Certificate(certificate) => certificate.encode_size(),
        }
    }
}

/// One producer-chain coordinate in a leader proposal.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct ChainProposal<V: Variant, D: Digest> {
    anchor: Anchor<V, D>,
    payloads: Vec<D>,
}

impl<V: Variant, D: Digest> fmt::Debug for ChainProposal<V, D> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ChainProposal")
            .field("anchor", &self.anchor)
            .field("payload_count", &self.payloads.len())
            .finish()
    }
}

impl<V: Variant, D: Digest> ChainProposal<V, D> {
    /// Creates a bounded proposal path for `chain` above `anchor`.
    pub fn new(
        chain: ChainId,
        anchor: Anchor<V, D>,
        payloads: Vec<D>,
        pipeline_depth: usize,
    ) -> Result<Self, Error> {
        if anchor.chain() != chain {
            return Err(Error::Chain);
        }
        if payloads.len() > pipeline_depth {
            return Err(Error::Length("proposal payloads"));
        }
        if anchor
            .height()
            .get()
            .checked_add(payloads.len() as u64)
            .is_none()
        {
            return Err(Error::HeightOverflow);
        }

        Ok(Self { anchor, payloads })
    }

    /// Returns the explicit or certified proposal base.
    pub const fn anchor(&self) -> &Anchor<V, D> {
        &self.anchor
    }

    /// Returns the proposed application commitments above the base.
    pub fn payloads(&self) -> &[D] {
        &self.payloads
    }

    /// Returns the number of proposed blocks above the base.
    pub const fn len(&self) -> usize {
        self.payloads.len()
    }

    /// Returns whether the proposal adds no blocks above its anchor.
    pub const fn is_empty(&self) -> bool {
        self.payloads.is_empty()
    }
}

impl<V: Variant, D: Digest> Write for ChainProposal<V, D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.anchor.write(buf);
        self.payloads.write(buf);
    }
}

impl<V: Variant, D: Digest> Read for ChainProposal<V, D> {
    type Cfg = (ChainId, CodecConfig);

    fn read_cfg(buf: &mut impl Buf, (chain, config): &Self::Cfg) -> Result<Self, CodecError> {
        let anchor = Anchor::read_cfg(buf, config)?;
        let payloads = Vec::<D>::read_cfg(buf, &(RangeCfg::from(0..=config.pipeline_depth()), ()))?;

        Self::new(*chain, anchor, payloads, config.pipeline_depth())
            .map_err(|_| CodecError::Invalid("ChainProposal", "invalid chain proposal"))
    }
}

impl<V: Variant, D: Digest> EncodeSize for ChainProposal<V, D> {
    fn encode_size(&self) -> usize {
        self.anchor.encode_size() + self.payloads.encode_size()
    }
}

/// A transaction-free leader block spanning every producer chain.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct LeaderBlock<V: Variant, D: Digest> {
    round: Round,
    parent: CertificateId<D>,
    history: D,
    proposals: Vec<ChainProposal<V, D>>,
}

impl<V: Variant, D: Digest> LeaderBlock<V, D> {
    /// Creates a live-view leader block with exactly one proposal per chain.
    pub fn new(
        round: Round,
        parent: CertificateId<D>,
        history: D,
        proposals: Vec<ChainProposal<V, D>>,
        limits: CodecConfig,
    ) -> Result<Self, Error> {
        let block = Self {
            round,
            parent,
            history,
            proposals,
        };
        block.validate(limits)?;
        Ok(block)
    }

    pub(crate) fn validate(&self, limits: CodecConfig) -> Result<(), Error> {
        if self.round.view().is_zero() {
            return Err(Error::GenesisView);
        }
        if self.proposals.len() != limits.chains() {
            return Err(Error::Length("chain proposals"));
        }

        for (index, proposal) in self.proposals.iter().enumerate() {
            let expected = ChainId::new(index as u32);
            if proposal.anchor().chain() != expected {
                return Err(Error::Chain);
            }
            if proposal.len() > limits.pipeline_depth() {
                return Err(Error::Length("proposal payloads"));
            }
            if proposal
                .anchor()
                .height()
                .get()
                .checked_add(proposal.len() as u64)
                .is_none()
            {
                return Err(Error::HeightOverflow);
            }
            if let Anchor::Certificate(certificate) = proposal.anchor()
                && certificate.epoch() != self.round.epoch()
            {
                return Err(Error::Context);
            }
        }
        Ok(())
    }

    /// Returns the block's round.
    pub const fn round(&self) -> Round {
        self.round
    }

    /// Returns the referenced parent V-QC identifier.
    pub const fn parent(&self) -> CertificateId<D> {
        self.parent
    }

    /// Returns the commitment to the safe-tip history through the parent V-QC.
    pub const fn history(&self) -> D {
        self.history
    }

    /// Returns proposals in ascending chain order.
    pub fn proposals(&self) -> &[ChainProposal<V, D>] {
        &self.proposals
    }

    /// Returns the digest of this canonical leader block.
    pub fn digest<H: Hasher<Digest = D>>(&self) -> D {
        H::hash(&[self.encode().as_ref()])
    }
}

impl<V: Variant, D: Digest> Epochable for LeaderBlock<V, D> {
    fn epoch(&self) -> Epoch {
        self.round.epoch()
    }
}

impl<V: Variant, D: Digest> Viewable for LeaderBlock<V, D> {
    fn view(&self) -> View {
        self.round.view()
    }
}

impl<V: Variant, D: Digest> Write for LeaderBlock<V, D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.round.epoch().write(buf);
        self.round.view().write(buf);
        self.parent.write(buf);
        self.history.write(buf);
        self.proposals.write(buf);
    }
}

impl<V: Variant, D: Digest> Read for LeaderBlock<V, D> {
    type Cfg = CodecConfig;

    fn read_cfg(buf: &mut impl Buf, limits: &Self::Cfg) -> Result<Self, CodecError> {
        let epoch = Epoch::read(buf)?;
        let view = View::read(buf)?;
        let parent = CertificateId::read(buf)?;
        let history = D::read(buf)?;
        let exact_chains = RangeCfg::from(limits.chains()..=limits.chains());
        let proposal_count = usize::read_cfg(buf, &exact_chains)?;
        let mut proposals = Vec::with_capacity(proposal_count.min(buf.remaining()));

        for index in 0..proposal_count {
            let chain = ChainId::new(index as u32);
            proposals.push(ChainProposal::read_cfg(buf, &(chain, *limits))?);
        }

        Self::new(Round::new(epoch, view), parent, history, proposals, *limits)
            .map_err(|_| CodecError::Invalid("LeaderBlock", "invalid leader block"))
    }
}

impl<V: Variant, D: Digest> EncodeSize for LeaderBlock<V, D> {
    fn encode_size(&self) -> usize {
        self.round.epoch().encode_size()
            + self.round.view().encode_size()
            + self.parent.encode_size()
            + self.history.encode_size()
            + self.proposals.encode_size()
    }
}

/// A leader-authenticated leader block used during proposal ingress.
#[derive(Clone, Debug)]
pub struct SignedLeaderBlock<V: Variant, D: Digest> {
    block: LeaderBlock<V, D>,
    attestation: Attestation<V>,
}

impl<V: Variant, D: Digest> SignedLeaderBlock<V, D> {
    /// Creates an attributed leader signature over `block`.
    ///
    /// This constructor does not verify the signature or the round-robin leader assignment.
    pub const fn new(block: LeaderBlock<V, D>, attestation: Attestation<V>) -> Self {
        Self { block, attestation }
    }

    /// Returns the complete leader block.
    pub const fn block(&self) -> &LeaderBlock<V, D> {
        &self.block
    }

    /// Returns the leader attestation.
    pub const fn attestation(&self) -> &Attestation<V> {
        &self.attestation
    }
}

impl<V: Variant, D: Digest> PartialEq for SignedLeaderBlock<V, D> {
    fn eq(&self, other: &Self) -> bool {
        self.block == other.block && self.attestation == other.attestation
    }
}

impl<V: Variant, D: Digest> Eq for SignedLeaderBlock<V, D> {}

impl<V: Variant, D: Digest> Hash for SignedLeaderBlock<V, D> {
    fn hash<H: CoreHasher>(&self, state: &mut H) {
        self.block.hash(state);
        self.attestation.hash(state);
    }
}

impl<V: Variant, D: Digest> Epochable for SignedLeaderBlock<V, D> {
    fn epoch(&self) -> Epoch {
        self.block.epoch()
    }
}

impl<V: Variant, D: Digest> Attributable for SignedLeaderBlock<V, D> {
    fn signer(&self) -> Participant {
        self.attestation.signer()
    }
}

impl<V: Variant, D: Digest> Viewable for SignedLeaderBlock<V, D> {
    fn view(&self) -> View {
        self.block.view()
    }
}

impl<V: Variant, D: Digest> Write for SignedLeaderBlock<V, D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.block.write(buf);
        self.attestation.write(buf);
    }
}

impl<V: Variant, D: Digest> Read for SignedLeaderBlock<V, D> {
    type Cfg = CodecConfig;

    fn read_cfg(buf: &mut impl Buf, limits: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self::new(
            LeaderBlock::read_cfg(buf, limits)?,
            Attestation::read(buf)?,
        ))
    }
}

impl<V: Variant, D: Digest> EncodeSize for SignedLeaderBlock<V, D> {
    fn encode_size(&self) -> usize {
        self.block.encode_size() + self.attestation.encode_size()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::multimmit::config::Limits;
    use commonware_codec::{Decode, DecodeExt, Encode};
    use commonware_cryptography::{Sha256, bls12381::primitives::variant::MinSig, sha256};

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct TestBody(u64);

    impl Write for TestBody {
        fn write(&self, buf: &mut impl BufMut) {
            self.0.write(buf);
        }
    }

    impl Read for TestBody {
        type Cfg = ();

        fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
            Ok(Self(u64::read(buf)?))
        }
    }

    impl EncodeSize for TestBody {
        fn encode_size(&self) -> usize {
            self.0.encode_size()
        }
    }

    impl Digestible for TestBody {
        type Digest = sha256::Digest;

        fn digest(&self) -> Self::Digest {
            Sha256::hash(&[&self.0.to_be_bytes()])
        }
    }

    fn digest(label: &[u8]) -> sha256::Digest {
        Sha256::hash(&[label])
    }

    fn codec_config() -> CodecConfig {
        CodecConfig::new(2, 2, Limits::new(2, 1).unwrap()).unwrap()
    }

    fn proposal(chain: u32, payloads: usize) -> ChainProposal<MinSig, sha256::Digest> {
        let chain = ChainId::new(chain);
        let anchor = Anchor::Tip(BlockRef::new(chain, Height::zero(), digest(b"anchor")));
        let payloads = (0..payloads)
            .map(|index| digest(&index.to_be_bytes()))
            .collect();
        ChainProposal::new(chain, anchor, payloads, codec_config().pipeline_depth()).unwrap()
    }

    #[test]
    fn transaction_header_rejects_genesis_height() {
        let result = TransactionBlockHeader::new(
            Epoch::new(7),
            ChainId::new(0),
            Height::zero(),
            digest(b"parent"),
            digest(b"payload"),
        );

        assert_eq!(result.unwrap_err(), Error::GenesisHeight);
    }

    #[test]
    fn transaction_header_identity_binds_complete_ancestry() {
        let commitment = digest(b"application block");
        let left = TransactionBlockHeader::new(
            Epoch::new(7),
            ChainId::new(1),
            Height::new(3),
            digest(b"left parent"),
            commitment,
        )
        .unwrap();
        let right = TransactionBlockHeader::new(
            Epoch::new(7),
            ChainId::new(1),
            Height::new(3),
            digest(b"right parent"),
            commitment,
        )
        .unwrap();

        let left_ref = left.block_ref::<Sha256>();
        let right_ref = right.block_ref::<Sha256>();
        assert_ne!(left_ref, right_ref);
        assert_eq!(left_ref.digest(), left.digest::<Sha256>());
        assert_eq!(right_ref.digest(), right.digest::<Sha256>());

        let left_child = TransactionBlockHeader::new(
            Epoch::new(7),
            ChainId::new(1),
            Height::new(4),
            left_ref.digest(),
            digest(b"shared child payload"),
        )
        .unwrap();
        let right_child = TransactionBlockHeader::new(
            Epoch::new(7),
            ChainId::new(1),
            Height::new(4),
            right_ref.digest(),
            digest(b"shared child payload"),
        )
        .unwrap();
        assert_ne!(left_child, right_child);
        assert_ne!(
            left_child.digest::<Sha256>(),
            right_child.digest::<Sha256>()
        );
    }

    #[test]
    fn transaction_block_uses_header_identity_and_coordinates() {
        let body = TestBody(11);
        let parent = digest(b"parent");
        let header = TransactionBlockHeader::new(
            Epoch::new(7),
            ChainId::new(1),
            Height::new(3),
            parent,
            body.digest(),
        )
        .unwrap();
        let expected_digest = header.digest::<Sha256>();
        let block = TransactionBlock::<Sha256, _>::new(header, body).unwrap();

        assert_eq!(block.digest(), expected_digest);
        assert_eq!(block.reference().digest(), expected_digest);
        assert_eq!(block.parent(), parent);
        assert_eq!(block.height(), Height::new(3));
        assert_eq!(block.epoch(), Epoch::new(7));
        assert_eq!(block.header().body_digest(), block.body().digest());

        let shared = block.body_shared();
        let body = block.into_body();
        assert!(Arc::ptr_eq(&shared, &body));
    }

    #[test]
    fn transaction_block_codec_is_header_then_body() {
        let body = TestBody(12);
        let header = TransactionBlockHeader::new(
            Epoch::new(7),
            ChainId::new(1),
            Height::new(3),
            digest(b"parent"),
            body.digest(),
        )
        .unwrap();
        let mut expected = header.encode().to_vec();
        body.write(&mut expected);
        let block = TransactionBlock::<Sha256, _>::new(header, body).unwrap();

        assert_eq!(block.encode().as_ref(), expected);
        assert_eq!(
            TransactionBlock::<Sha256, TestBody>::decode(expected.as_slice()).unwrap(),
            block
        );
    }

    #[test]
    fn transaction_block_rejects_mismatched_body() {
        let committed = TestBody(13);
        let header = TransactionBlockHeader::new(
            Epoch::new(7),
            ChainId::new(1),
            Height::new(3),
            digest(b"parent"),
            committed.digest(),
        )
        .unwrap();

        assert_eq!(
            TransactionBlock::<Sha256, _>::new(header.clone(), TestBody(14)),
            Err(Error::Commitment)
        );

        let mut encoded = header.encode().to_vec();
        TestBody(14).write(&mut encoded);
        assert!(TransactionBlock::<Sha256, TestBody>::decode(encoded.as_slice()).is_err());
    }

    #[test]
    fn chain_proposal_checks_chain_and_pipeline_depth() {
        let chain = ChainId::new(0);
        let anchor =
            Anchor::<MinSig, _>::Tip(BlockRef::new(chain, Height::zero(), digest(b"anchor")));

        assert_eq!(
            ChainProposal::new(ChainId::new(1), anchor.clone(), Vec::new(), 2).unwrap_err(),
            Error::Chain
        );
        assert_eq!(
            ChainProposal::new(chain, anchor, vec![digest(b"1"), digest(b"2")], 1).unwrap_err(),
            Error::Length("proposal payloads")
        );

        let overflow = Anchor::<MinSig, _>::Tip(BlockRef::new(
            chain,
            Height::new(u64::MAX),
            digest(b"overflow"),
        ));
        assert_eq!(
            ChainProposal::new(chain, overflow, vec![digest(b"1")], 1).unwrap_err(),
            Error::HeightOverflow
        );
    }

    #[test]
    fn leader_block_codec_preserves_chain_order() {
        let limits = codec_config();
        let leader = LeaderBlock::new(
            Round::new(Epoch::new(7), View::new(1)),
            CertificateId::new(digest(b"parent")),
            digest(b"history"),
            vec![proposal(0, 2), proposal(1, 1)],
            limits,
        )
        .unwrap();

        let decoded =
            LeaderBlock::<MinSig, sha256::Digest>::decode_cfg(leader.encode(), &limits).unwrap();
        assert_eq!(decoded, leader);
    }
}
