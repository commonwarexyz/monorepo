//! Producer-chain and leader-chain protocol objects.

use super::{
    Attestation, BlockRef, CertificateId, ChainId, Error,
    bounds::{MAX_U64_VARINT_SIZE, checked_sum, max_index_width},
    canonical_digest,
};
use crate::{
    Block, Epochable, Heightable, Viewable,
    multimmit::types::CodecConfig,
    types::{Attributable, Epoch, Height, Participant, Round, View},
};
use bytes::BufMut;
use commonware_codec::{
    Buf, BufsMut, Codec, EncodeSize, Error as CodecError, FixedSize as _, Read, ReadExt, Write,
};
use commonware_cryptography::{Digest, Digestible, Hasher, bls12381::primitives::variant::Variant};
use core::{fmt, marker::PhantomData};
use std::sync::Arc;

const HEADER_NAMESPACE: &[u8] = b"_COMMONWARE_CONSENSUS_MULTIMMIT_HEADER";
const LEADER_BLOCK_NAMESPACE: &[u8] = b"_COMMONWARE_CONSENSUS_MULTIMMIT_LEADER_BLOCK";

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
    /// Creates application context for one producer-chain coordinate.
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

    /// Returns the header committing to `body_digest` at this coordinate.
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

    /// Creates the header committing to `body_digest` at `context`'s coordinate.
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
        canonical_digest::<H>(HEADER_NAMESPACE, self)
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

    /// Returns the largest encoding of a header under `codec`.
    pub(super) fn max_encode_size(codec: CodecConfig) -> Option<usize> {
        checked_sum(&[
            2 * MAX_U64_VARINT_SIZE,
            2 * D::SIZE,
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

/// A scheduled leader's proposal for one view.
///
/// The leader names the V-QC of the previous view it forwarded (`parent`) and the tips-history
/// commitment of that V-QC's chain (`history`, see [`HistoryRecord`](super::HistoryRecord)).
/// Voters accept the proposal only while holding the parent with its whole parent chain and
/// recomputing the same commitment, so `n - f` votes for a leader block pin the tips of every
/// view below it.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct LeaderBlock<D: Digest> {
    round: Round,
    parent: CertificateId<D>,
    history: D,
}

impl<D: Digest> LeaderBlock<D> {
    /// Creates a live-view leader block.
    pub const fn new(round: Round, parent: CertificateId<D>, history: D) -> Result<Self, Error> {
        if round.view().is_zero() {
            return Err(Error::GenesisView);
        }
        Ok(Self {
            round,
            parent,
            history,
        })
    }

    /// Returns the block's round.
    pub const fn round(&self) -> Round {
        self.round
    }

    /// Returns the referenced parent V-QC identifier.
    pub const fn parent(&self) -> CertificateId<D> {
        self.parent
    }

    /// Returns the tips-history commitment of the parent V-QC's chain.
    pub const fn history(&self) -> D {
        self.history
    }

    /// Returns the digest of this canonical leader block.
    pub fn digest<H: Hasher<Digest = D>>(&self) -> D {
        canonical_digest::<H>(LEADER_BLOCK_NAMESPACE, self)
    }

    /// Returns the largest encoding of a leader block.
    pub(super) fn max_encode_size() -> Option<usize> {
        checked_sum(&[2 * MAX_U64_VARINT_SIZE, 2 * D::SIZE])
    }
}

impl<D: Digest> Epochable for LeaderBlock<D> {
    fn epoch(&self) -> Epoch {
        self.round.epoch()
    }
}

impl<D: Digest> Viewable for LeaderBlock<D> {
    fn view(&self) -> View {
        self.round.view()
    }
}

impl<D: Digest> Write for LeaderBlock<D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.round.write(buf);
        self.parent.write(buf);
        self.history.write(buf);
    }
}

impl<D: Digest> Read for LeaderBlock<D> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        Self::new(Round::read(buf)?, CertificateId::read(buf)?, D::read(buf)?)
            .map_err(|error| CodecError::Wrapped("LeaderBlock", error.into()))
    }
}

impl<D: Digest> EncodeSize for LeaderBlock<D> {
    fn encode_size(&self) -> usize {
        self.round.encode_size() + self.parent.encode_size() + self.history.encode_size()
    }
}

/// A leader block signed by its scheduled leader.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SignedLeaderBlock<V: Variant, D: Digest> {
    block: LeaderBlock<D>,
    attestation: Attestation<V>,
}

impl<V: Variant, D: Digest> SignedLeaderBlock<V, D> {
    /// Creates an attributed leader signature over `block`.
    ///
    /// This constructor does not verify the signature or the scheduled leader assignment.
    pub const fn new(block: LeaderBlock<D>, attestation: Attestation<V>) -> Self {
        Self { block, attestation }
    }

    /// Returns the complete leader block.
    pub const fn block(&self) -> &LeaderBlock<D> {
        &self.block
    }

    /// Returns the leader attestation.
    pub const fn attestation(&self) -> &Attestation<V> {
        &self.attestation
    }

    /// Returns the largest encoding of a signed leader block under `codec`.
    pub(super) fn max_encode_size(codec: CodecConfig) -> Option<usize> {
        checked_sum(&[
            LeaderBlock::<D>::max_encode_size()?,
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
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        Ok(Self::new(LeaderBlock::read(buf)?, Attestation::read(buf)?))
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
    use crate::multimmit::mocks::MockBody;
    use commonware_codec::{DecodeExt, Encode};
    use commonware_cryptography::{Sha256, sha256};

    fn digest(label: &[u8]) -> sha256::Digest {
        Sha256::hash(&[label])
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
    fn leader_block_rejects_genesis_view_and_round_trips() {
        let parent = CertificateId::new(digest(b"parent"));
        assert_eq!(
            LeaderBlock::new(
                Round::new(Epoch::new(7), View::zero()),
                parent,
                digest(b"history")
            )
            .unwrap_err(),
            Error::GenesisView
        );
        let leader = LeaderBlock::new(
            Round::new(Epoch::new(7), View::new(3)),
            parent,
            digest(b"history"),
        )
        .unwrap();
        let encoded = leader.encode();
        assert!(encoded.len() <= LeaderBlock::<sha256::Digest>::max_encode_size().unwrap());
        assert_eq!(
            LeaderBlock::<sha256::Digest>::decode(encoded).unwrap(),
            leader
        );
        assert_ne!(
            leader.digest::<Sha256>(),
            LeaderBlock::new(leader.round(), parent, digest(b"other"))
                .unwrap()
                .digest::<Sha256>()
        );

        let mut zero = Round::new(Epoch::new(7), View::zero()).encode().to_vec();
        parent.write(&mut zero);
        digest(b"history").write(&mut zero);
        assert!(LeaderBlock::<sha256::Digest>::decode(zero).is_err());
    }
}
