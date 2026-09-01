//! Producer-chain and leader-chain protocol objects.

use super::{
    Attestation, BlockRef, CertificateId, ChainId, Error, ThresholdShare,
    bounds::{
        MAX_U64_VARINT_SIZE, checked_product, checked_sum, encoded_index_sum, encoded_len,
        encoded_vec, max_index_width,
    },
    canonical_digest,
    certificate::DaCertificate,
};
use crate::{
    Block, Epochable, Heightable, Viewable,
    multimmit::types::CodecConfig,
    types::{Attributable, Epoch, Height, Participant, Round, View},
};
use bytes::BufMut;
use commonware_codec::{
    Buf, BufsMut, Codec, EncodeSize, Error as CodecError, FixedSize as _, RangeCfg, Read, ReadExt,
    Write,
};
use commonware_cryptography::{Digest, Digestible, Hasher, bls12381::primitives::variant::Variant};
use core::{fmt, marker::PhantomData};
use std::sync::Arc;

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

    /// Returns the header committing to `body_digest` at this position.
    pub const fn header(self, body_digest: D) -> TransactionBlockHeader<D> {
        TransactionBlockHeader::from_context(self, body_digest)
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
        header.context
    }
}

/// The protocol metadata that identifies one application block.
///
/// Multimmit leaves the application block body and its encoding to the attached application. This
/// header binds the chain coordinates, canonical parent identity, and the digest of that
/// external body. The block's protocol identity is the digest of the complete header.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TransactionBlockHeader<D: Digest> {
    context: Context<D>,
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
        match Context::new(epoch, chain, height, parent) {
            Ok(context) => Ok(Self::from_context(context, body_digest)),
            Err(error) => Err(error),
        }
    }

    /// Creates the header committing to `body_digest` at `context`'s position.
    pub const fn from_context(context: Context<D>, body_digest: D) -> Self {
        Self {
            context,
            body_digest,
        }
    }

    /// Encoded size of [`Self::write_fixed`].
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) const FIXED_SIZE: usize = u64::SIZE + u32::SIZE + u64::SIZE + D::SIZE * 2;

    /// Writes the header with every integer at full width, for fixed-size storage records.
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) fn write_fixed(&self, buf: &mut impl BufMut) {
        self.context.epoch.get().write(buf);
        self.context.chain.get().write(buf);
        self.context.height.get().write(buf);
        self.context.parent.write(buf);
        self.body_digest.write(buf);
    }

    /// Reads a header written by [`Self::write_fixed`], validating it as [`Self::new`] does.
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) fn read_fixed(buf: &mut impl Buf) -> Result<Self, CodecError> {
        Self::new(
            Epoch::new(u64::read(buf)?),
            ChainId::new(u32::read(buf)?),
            Height::new(u64::read(buf)?),
            D::read(buf)?,
            D::read(buf)?,
        )
        .map_err(|error| CodecError::Wrapped("TransactionBlockHeader", error.into()))
    }

    /// Returns the application context this header names.
    pub const fn context(&self) -> Context<D> {
        self.context
    }

    /// Returns the producer chain.
    pub const fn chain(&self) -> ChainId {
        self.context.chain
    }

    /// Returns the chain-local height.
    pub const fn height(&self) -> Height {
        self.context.height
    }

    /// Returns the canonical identity of the parent producer-block header.
    pub const fn parent(&self) -> D {
        self.context.parent
    }

    /// Returns the canonical digest of the opaque application body.
    pub const fn body_digest(&self) -> D {
        self.body_digest
    }

    /// Returns the digest of this canonical header.
    pub fn digest<H: Hasher<Digest = D>>(&self) -> D {
        canonical_digest::<H>(self)
    }

    /// Returns this producer block's canonical protocol identity.
    pub fn block_ref<H: Hasher<Digest = D>>(&self) -> BlockRef<D> {
        BlockRef::new(self.chain(), self.height(), self.digest::<H>())
    }

    /// Returns the reference of this header's parent, one height below it on the same chain.
    pub fn parent_ref(&self) -> BlockRef<D> {
        let height = self
            .height()
            .previous()
            .expect("live producer headers are above the genesis height");
        BlockRef::new(self.chain(), height, self.parent())
    }

    /// Returns the largest encoding of a header without its chain identifier, whose width varies
    /// by chain.
    pub(super) fn max_encode_size_without_chain() -> Option<usize> {
        checked_sum(&[
            checked_product(2, MAX_U64_VARINT_SIZE)?,
            checked_product(2, D::SIZE)?,
        ])
    }

    /// Returns the largest encoding of a header under `codec`.
    pub(super) fn max_encode_size(codec: CodecConfig) -> Option<usize> {
        checked_sum(&[
            Self::max_encode_size_without_chain()?,
            max_index_width(codec.chains())?,
        ])
    }
}

impl<D: Digest> Epochable for TransactionBlockHeader<D> {
    fn epoch(&self) -> Epoch {
        self.context.epoch
    }
}

impl<D: Digest> Heightable for TransactionBlockHeader<D> {
    fn height(&self) -> Height {
        self.context.height
    }
}

impl<D: Digest> Write for TransactionBlockHeader<D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.context.epoch.write(buf);
        self.context.chain.write(buf);
        self.context.height.write(buf);
        self.context.parent.write(buf);
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
        .map_err(|error| CodecError::Wrapped("TransactionBlockHeader", error.into()))
    }
}

impl<D: Digest> EncodeSize for TransactionBlockHeader<D> {
    fn encode_size(&self) -> usize {
        self.context.epoch.encode_size()
            + self.context.chain.encode_size()
            + self.context.height.encode_size()
            + self.context.parent.encode_size()
            + self.body_digest.encode_size()
    }
}

/// An application block body: canonically encoded and identified by a digest from `H`.
pub trait Body<H: Hasher>: Codec + Digestible<Digest = H::Digest> {}

impl<H: Hasher, T: Codec + Digestible<Digest = H::Digest>> Body<H> for T {}

/// A complete producer-chain block.
///
/// The header carries all protocol metadata and commits to the opaque application body. The
/// block's canonical consensus identity is the digest of that header; the header's `body_digest`
/// is checked against the body when the two are paired or decoded.
pub struct TransactionBlock<H: Hasher, B> {
    header: TransactionBlockHeader<H::Digest>,
    body: Arc<B>,
    _hasher: PhantomData<H>,
}

impl<H, B> TransactionBlock<H, B>
where
    H: Hasher,
    B: Body<H>,
{
    /// Constructs a block from application context and its body.
    pub fn from_context(context: Context<H::Digest>, body: impl Into<Arc<B>>) -> Self {
        let body = body.into();
        Self {
            header: TransactionBlockHeader::from_context(context, body.digest()),
            body,
            _hasher: PhantomData,
        }
    }

    /// Pairs a canonical producer header with its application body.
    pub fn new(
        header: TransactionBlockHeader<H::Digest>,
        body: impl Into<Arc<B>>,
    ) -> Result<Self, Error> {
        let body = body.into();
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

    /// Returns the canonical producer-chain reference.
    pub fn reference(&self) -> BlockRef<H::Digest> {
        self.header.block_ref::<H>()
    }
}

impl<H, B> Clone for TransactionBlock<H, B>
where
    H: Hasher,
    B: Body<H>,
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
    B: Body<H> + fmt::Debug,
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
    B: Body<H> + PartialEq,
{
    fn eq(&self, other: &Self) -> bool {
        self.header == other.header && self.body == other.body
    }
}

impl<H, B> Eq for TransactionBlock<H, B>
where
    H: Hasher,
    B: Body<H> + Eq,
{
}

impl<H, B> Write for TransactionBlock<H, B>
where
    H: Hasher,
    B: Body<H>,
{
    fn write(&self, buf: &mut impl BufMut) {
        self.header.write(buf);
        self.body.write(buf);
    }

    fn write_bufs(&self, buf: &mut impl BufsMut) {
        self.header.write_bufs(buf);
        self.body.write_bufs(buf);
    }
}

impl<H, B> Read for TransactionBlock<H, B>
where
    H: Hasher,
    B: Body<H>,
{
    type Cfg = B::Cfg;

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        let header = TransactionBlockHeader::read(buf)?;
        let body = B::read_cfg(buf, cfg)?;
        Self::new(header, body)
            .map_err(|error| CodecError::Wrapped("TransactionBlock", error.into()))
    }
}

impl<H, B> EncodeSize for TransactionBlock<H, B>
where
    H: Hasher,
    B: Body<H>,
{
    fn encode_size(&self) -> usize {
        self.header.encode_size() + self.body.encode_size()
    }

    fn encode_inline_size(&self) -> usize {
        self.header.encode_inline_size() + self.body.encode_inline_size()
    }
}

impl<H, B> Digestible for TransactionBlock<H, B>
where
    H: Hasher,
    B: Body<H>,
{
    type Digest = H::Digest;

    fn digest(&self) -> Self::Digest {
        self.header.digest::<H>()
    }
}

impl<H, B> Block for TransactionBlock<H, B>
where
    H: Hasher,
    B: Body<H>,
{
    fn parent(&self) -> Self::Digest {
        self.header.parent()
    }
}

impl<H, B> Heightable for TransactionBlock<H, B>
where
    H: Hasher,
    B: Body<H>,
{
    fn height(&self) -> Height {
        self.header.height()
    }
}

impl<H, B> Epochable for TransactionBlock<H, B>
where
    H: Hasher,
    B: Body<H>,
{
    fn epoch(&self) -> Epoch {
        self.header.epoch()
    }
}

/// A producer-authenticated application-block header.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
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

    /// Returns the largest encoding of a signed header under `codec`.
    pub(super) fn max_encode_size(codec: CodecConfig) -> Option<usize> {
        checked_sum(&[
            TransactionBlockHeader::<D>::max_encode_size(codec)?,
            max_index_width(codec.participants())?,
            V::Signature::SIZE,
        ])
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
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
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

    /// Returns the largest encoding of a data-availability vote under `codec`.
    pub(super) fn max_encode_size(codec: CodecConfig) -> Option<usize> {
        checked_sum(&[
            TransactionBlockHeader::<D>::max_encode_size(codec)?,
            max_index_width(codec.participants())?,
            V::Signature::SIZE,
        ])
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
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
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
        let proposal = Self { anchor, payloads };
        proposal.validate(chain, pipeline_depth)?;
        Ok(proposal)
    }

    /// Checks that the proposal is anchored on `chain`, fits `pipeline_depth`, and does not
    /// overflow the chain height.
    fn validate(&self, chain: ChainId, pipeline_depth: usize) -> Result<(), Error> {
        if self.anchor.chain() != chain {
            return Err(Error::Chain);
        }
        if self.payloads.len() > pipeline_depth {
            return Err(Error::ProposalLength);
        }
        if self
            .anchor
            .height()
            .get()
            .checked_add(self.payloads.len() as u64)
            .is_none()
        {
            return Err(Error::HeightOverflow);
        }
        Ok(())
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

    /// Returns the largest encoding of a proposal under `codec` without the chain identifier in
    /// its anchor, whose width varies by chain.
    ///
    /// A certificate anchor is larger than a tip anchor.
    pub(super) fn max_encode_size_without_chain(codec: CodecConfig) -> Option<usize> {
        checked_sum(&[
            1,
            TransactionBlockHeader::<D>::max_encode_size_without_chain()?,
            V::Signature::SIZE,
            encoded_vec(codec.pipeline_depth(), D::SIZE)?,
        ])
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
        let anchor = Anchor::read(buf)?;
        let payloads = Vec::<D>::read_cfg(buf, &(RangeCfg::from(0..=config.pipeline_depth()), ()))?;

        Self::new(*chain, anchor, payloads, config.pipeline_depth())
            .map_err(|error| CodecError::Wrapped("ChainProposal", error.into()))
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
            return Err(Error::ChainCount);
        }

        for (index, proposal) in self.proposals.iter().enumerate() {
            proposal.validate(ChainId::new(index as u32), limits.pipeline_depth())?;
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

    /// Returns each chain's proposed tip height: the anchor plus the payloads above it.
    pub fn proposed_heights(&self) -> Vec<Height> {
        self.proposals
            .iter()
            .map(|proposal| Height::new(proposal.anchor().height().get() + proposal.len() as u64))
            .collect()
    }

    /// Returns the digest of this canonical leader block.
    pub fn digest<H: Hasher<Digest = D>>(&self) -> D {
        canonical_digest::<H>(self)
    }

    /// Returns the largest encoding of a leader block under `codec`.
    pub(super) fn max_encode_size(codec: CodecConfig) -> Option<usize> {
        let chains = codec.chains();
        let proposals = checked_sum(&[
            encoded_len(chains)?,
            checked_product(
                chains,
                ChainProposal::<V, D>::max_encode_size_without_chain(codec)?,
            )?,
            encoded_index_sum(chains)?,
        ])?;
        checked_sum(&[
            checked_product(2, MAX_U64_VARINT_SIZE)?,
            checked_product(2, D::SIZE)?,
            proposals,
        ])
    }
}

/// A leader block paired with its digest, so leader-relative checks hash the block once.
pub struct DigestedLeader<'a, V: Variant, D: Digest> {
    block: &'a LeaderBlock<V, D>,
    digest: D,
}

impl<'a, V: Variant, D: Digest> DigestedLeader<'a, V, D> {
    /// Pairs `block` with its digest under `H`.
    pub fn new<H: Hasher<Digest = D>>(block: &'a LeaderBlock<V, D>) -> Self {
        Self {
            block,
            digest: block.digest::<H>(),
        }
    }

    /// Pairs `block` with a digest the caller already computed for it.
    ///
    /// `digest` must equal `block.digest::<H>()` under the hasher the caller verifies with.
    /// Nothing checks this, and a mismatched digest makes every vote check against the pair
    /// judge the wrong block.
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) const fn with_digest(block: &'a LeaderBlock<V, D>, digest: D) -> Self {
        Self { block, digest }
    }

    /// Returns the leader block.
    pub const fn block(&self) -> &'a LeaderBlock<V, D> {
        self.block
    }

    /// Returns the leader block's digest.
    pub const fn digest(&self) -> D {
        self.digest
    }
}

impl<V: Variant, D: Digest> Clone for DigestedLeader<'_, V, D> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<V: Variant, D: Digest> Copy for DigestedLeader<'_, V, D> {}

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
        self.round.write(buf);
        self.parent.write(buf);
        self.history.write(buf);
        self.proposals.write(buf);
    }
}

impl<V: Variant, D: Digest> Read for LeaderBlock<V, D> {
    type Cfg = CodecConfig;

    fn read_cfg(buf: &mut impl Buf, limits: &Self::Cfg) -> Result<Self, CodecError> {
        let round = Round::read(buf)?;
        let parent = CertificateId::read(buf)?;
        let history = D::read(buf)?;
        let exact_chains = RangeCfg::from(limits.chains()..=limits.chains());
        let proposal_count = usize::read_cfg(buf, &exact_chains)?;
        let mut proposals = Vec::with_capacity(proposal_count.min(buf.remaining()));

        for index in 0..proposal_count {
            let chain = ChainId::new(index as u32);
            proposals.push(ChainProposal::read_cfg(buf, &(chain, *limits))?);
        }

        Self::new(round, parent, history, proposals, *limits)
            .map_err(|error| CodecError::Wrapped("LeaderBlock", error.into()))
    }
}

impl<V: Variant, D: Digest> EncodeSize for LeaderBlock<V, D> {
    fn encode_size(&self) -> usize {
        self.round.encode_size()
            + self.parent.encode_size()
            + self.history.encode_size()
            + self.proposals.encode_size()
    }
}

/// A leader block signed by its scheduled leader.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SignedLeaderBlock<V: Variant, D: Digest> {
    block: LeaderBlock<V, D>,
    attestation: Attestation<V>,
}

impl<V: Variant, D: Digest> SignedLeaderBlock<V, D> {
    /// Creates an attributed leader signature over `block`.
    ///
    /// This constructor does not verify the signature or the scheduled leader assignment.
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

    /// Returns the largest encoding of a signed leader block under `codec`.
    pub(super) fn max_encode_size(codec: CodecConfig) -> Option<usize> {
        checked_sum(&[
            LeaderBlock::<V, D>::max_encode_size(codec)?,
            max_index_width(codec.participants())?,
            V::Signature::SIZE,
        ])
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
    use crate::multimmit::{mocks::MockBody, types::PathLimits};
    use commonware_codec::{Decode, DecodeExt, Encode};
    use commonware_cryptography::{Sha256, bls12381::primitives::variant::MinSig, sha256};

    fn digest(label: &[u8]) -> sha256::Digest {
        Sha256::hash(&[label])
    }

    fn codec_config() -> CodecConfig {
        CodecConfig::new(2, 2, PathLimits::new(2, 1).unwrap()).unwrap()
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
    fn context_header_matches_the_explicit_constructor() {
        let context = Context::new(
            Epoch::new(7),
            ChainId::new(1),
            Height::new(3),
            digest(b"parent"),
        )
        .unwrap();
        assert_eq!(
            context.header(digest(b"body")),
            TransactionBlockHeader::new(
                Epoch::new(7),
                ChainId::new(1),
                Height::new(3),
                digest(b"parent"),
                digest(b"body"),
            )
            .unwrap()
        );
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
    fn transaction_header_parent_ref_names_the_parent_block() {
        let first = TransactionBlockHeader::new(
            Epoch::new(7),
            ChainId::new(1),
            Height::new(1),
            digest(b"genesis"),
            digest(b"first payload"),
        )
        .unwrap();
        assert_eq!(
            first.parent_ref(),
            BlockRef::new(ChainId::new(1), Height::zero(), digest(b"genesis"))
        );

        let second = TransactionBlockHeader::new(
            Epoch::new(7),
            ChainId::new(1),
            Height::new(2),
            first.digest::<Sha256>(),
            digest(b"second payload"),
        )
        .unwrap();
        assert_eq!(second.parent_ref(), first.block_ref::<Sha256>());
    }

    #[test]
    fn transaction_block_uses_header_identity_and_coordinates() {
        let body = MockBody(11);
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
        assert_eq!(
            TransactionBlock::<Sha256, _>::from_context(
                Context::from(block.header()),
                Arc::new(MockBody(11))
            ),
            block
        );
    }

    #[test]
    fn transaction_block_codec_is_header_then_body() {
        let body = MockBody(12);
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
            TransactionBlock::<Sha256, MockBody>::decode(expected).unwrap(),
            block
        );
    }

    #[test]
    fn transaction_block_rejects_mismatched_body() {
        let committed = MockBody(13);
        let header = TransactionBlockHeader::new(
            Epoch::new(7),
            ChainId::new(1),
            Height::new(3),
            digest(b"parent"),
            committed.digest(),
        )
        .unwrap();

        assert_eq!(
            TransactionBlock::<Sha256, _>::new(header.clone(), MockBody(14)),
            Err(Error::Commitment)
        );

        let mut encoded = header.encode().to_vec();
        MockBody(14).write(&mut encoded);
        assert!(TransactionBlock::<Sha256, MockBody>::decode(encoded).is_err());
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
            Error::ProposalLength
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
    fn leader_block_checks_each_proposal() {
        let limits = codec_config();
        let round = Round::new(Epoch::new(7), View::new(1));
        let parent = CertificateId::new(digest(b"parent"));
        let build = |proposals| {
            LeaderBlock::<MinSig, _>::new(round, parent, digest(b"history"), proposals, limits)
        };

        assert_eq!(build(vec![proposal(0, 1)]).unwrap_err(), Error::ChainCount);
        assert_eq!(
            build(vec![proposal(1, 1), proposal(0, 1)]).unwrap_err(),
            Error::Chain
        );
        let mut long = proposal(1, limits.pipeline_depth());
        long.payloads.push(digest(b"beyond the pipeline"));
        assert_eq!(
            build(vec![proposal(0, 1), long]).unwrap_err(),
            Error::ProposalLength
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
