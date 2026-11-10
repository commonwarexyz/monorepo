//! Types for erasure coding.

use crate::{
    Block, CertifiableBlock, Heightable,
    marshal::core::ExpectedCommitment,
    types::{Height, Round, coding::Commitment},
};
use bytes::{Buf, BufMut, Bytes};
use commonware_codec::{
    BufsMut, Codec, EncodeSize, Error as CodecError, FixedSize, MaxEncodeSize, RangeCfg, Read,
    ReadExt, Write,
};
use commonware_coding::{Config as CodingConfig, Scheme, Segmentable};
use commonware_cryptography::{Committable, Digested, Digestible, Hasher};
use commonware_parallel::Strategy;
use commonware_utils::{Faults, N3f1, NZU16};
use std::{
    future::Future,
    sync::{Arc, OnceLock},
};

/// The byte layout erasure coded for a block.
///
/// The canonical [`Codec`] encoding is authoritative for storage, backfill and digests. The
/// coded layout orders the same information so that the body, the bytes that are final before
/// the block is sealed, comes first and can be coded while the rest of the block is still being
/// computed. The coded payload is
///
/// ```text
/// write_body || write_tail || body_len (u32 little endian) || coding config
/// ```
///
/// so a decoder reads the config and the body length from the end. A block that keeps the
/// defaults codes as its canonical encoding with an empty body.
///
/// ```text
/// canonical encoding    [ header ][ count ][ tx ][ tx ] ... [ tx ]
/// (storage, digest)        ^ carries commitments to the executed state, known only after it exists
///
/// coded layout          [ tx ][ tx ] ... [ tx ][ header ][ count ][ body_len ][ config ]
/// (what is coded)        \______ body ______/\______ tail ______/\__ trailer __/
///                        final before the      final when the block
///                        block is sealed       is sealed
/// ```
///
/// # Requirements
///
/// The body and tail together must be exactly as long as the canonical encoding. This bounds the
/// payload by the block's encoded size plus the trailer and lets the streaming encoder derive the
/// body's length from the tail's.
///
/// The body and tail must depend only on the canonical encoding, and [`Self::read_coded`] must
/// accept no other pair for the block. A node holds a block without its shards after
/// reconstruction, a certified backfill or a restart. It codes the block again to send it and must
/// reach the same coding root.
///
/// # Verification
///
/// A commitment holds the block's digest and the coding root of its payload. A validator checks the
/// shards it decodes against the root, and the block it reads from them against the digest.
///
/// ```text
/// leader       block --write_body, write_tail--> payload --code--> shards
///                |                                                   |
///                v                                                   v
/// commitment   digest                                           coding root
///                |                                                   |
///              checks                                              checks
///                v                                                   v
/// validator    block <--------read_coded-------- payload <-decode- shards
/// ```
///
/// A block fetched under a certified commitment is checked against the digest and not the root, so
/// bytes the digest does not cover are the decoder's to check. When the digest is a hash of the
/// block's header, the block's decoder must reject transactions that do not match the roots in that
/// header.
pub trait CodedLayout: Codec + Sized {
    /// Writes the bytes that are final before the block is sealed (for example its
    /// transactions).
    fn write_body(&self, _buf: &mut impl BufMut) {}

    /// Writes everything the body does not carry.
    fn write_tail(&self, buf: &mut impl BufMut) {
        self.write(buf);
    }

    /// Reads a block from its body and tail.
    ///
    /// It must be the strict inverse of [`Self::write_body`] and [`Self::write_tail`], so every
    /// block has exactly one accepted `(body, tail)` pair. It must also reject every block the
    /// canonical decoder rejects under `cfg`, since storage and backfill read blocks with that
    /// decoder.
    fn read_coded(body: Bytes, tail: Bytes, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        if !body.is_empty() {
            return Err(CodecError::Invalid("CodedLayout", "unexpected body"));
        }
        Self::decode_cfg(tail, cfg)
    }
}

/// The size of the trailer that follows a block's coded layout: its body length and the coding
/// config.
const CODED_TRAILER: usize = u32::SIZE + CodingConfig::SIZE;

/// Writes the trailer that ends a coded payload whose body is `body_len` bytes.
pub(crate) fn write_coded_trailer(body_len: usize, config: CodingConfig, buf: &mut impl BufMut) {
    let body_len = u32::try_from(body_len).expect("a block body must fit in a u32 length");
    buf.put_slice(&body_len.to_le_bytes());
    config.write(buf);
}

/// Returns the coded payload of `block` under `config` and the length of its body.
pub(crate) fn coded_payload<B: CodedLayout>(block: &B, config: CodingConfig) -> (Vec<u8>, usize) {
    let mut buf = Vec::with_capacity(block.encode_size() + CODED_TRAILER);
    block.write_body(&mut buf);
    let body_len = buf.len();
    block.write_tail(&mut buf);
    write_coded_trailer(body_len, config, &mut buf);
    (buf, body_len)
}

/// Reads a block and the coding config from a coded payload.
pub(crate) fn read_coded_payload<B: CodedLayout>(
    payload: Vec<u8>,
    cfg: &B::Cfg,
) -> Result<(B, CodingConfig), CodecError> {
    let Some(layout_len) = payload.len().checked_sub(CODED_TRAILER) else {
        return Err(CodecError::EndOfBuffer);
    };
    let mut payload = Bytes::from(payload);
    let mut trailer = payload.split_off(layout_len);
    let body_len = trailer.get_u32_le() as usize;
    let config = CodingConfig::read(&mut trailer)?;
    if body_len > layout_len {
        return Err(CodecError::Invalid(
            "CodedLayout",
            "body length exceeds payload",
        ));
    }
    let tail = payload.split_off(body_len);
    Ok((B::read_coded(payload, tail, cfg)?, config))
}

/// A broadcastable shard of erasure coded data, including the coding commitment and
/// the configuration used to code the data.
pub struct Shard<B: Digestible, C: Scheme, H: Hasher> {
    /// The coding commitment
    pub(crate) commitment: Commitment<B, C, H>,
    /// The index of this shard within the commitment.
    pub(crate) index: u16,
    /// An individual shard within the commitment.
    pub(crate) inner: C::Shard,
}

impl<B: Digestible, C: Scheme, H: Hasher> Shard<B, C, H> {
    /// Returns the largest encoded size of a shard whose inner shard encodes to at most `shard`
    /// bytes.
    pub const fn max_encode_size(shard: usize) -> usize {
        shard + Commitment::<B, C, H>::SIZE + u16::SIZE
    }

    pub const fn new(commitment: Commitment<B, C, H>, index: u16, inner: C::Shard) -> Self {
        Self {
            commitment,
            index,
            inner,
        }
    }

    /// Returns the index of this shard within the commitment.
    pub const fn index(&self) -> u16 {
        self.index
    }

    /// Returns the [`Commitment`] for this shard.
    pub const fn commitment(&self) -> Commitment<B, C, H> {
        self.commitment
    }

    /// Takes the inner shard.
    pub fn into_inner(self) -> C::Shard {
        self.inner
    }
}

impl<B: Digestible, C: Scheme, H: Hasher> Clone for Shard<B, C, H> {
    fn clone(&self) -> Self {
        Self {
            commitment: self.commitment,
            index: self.index,
            inner: self.inner.clone(),
        }
    }
}

impl<B: Digestible, C: Scheme, H: Hasher> Committable for Shard<B, C, H> {
    type Commitment = Commitment<B, C, H>;

    fn commitment(&self) -> Self::Commitment {
        self.commitment
    }
}

impl<B: Digestible, C: Scheme, H: Hasher> Write for Shard<B, C, H> {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.commitment.write(buf);
        self.index.write(buf);
        self.inner.write(buf);
    }

    fn write_bufs(&self, buf: &mut impl BufsMut) {
        self.commitment.write(buf);
        self.index.write(buf);
        self.inner.write_bufs(buf);
    }
}

impl<B: Digestible, C: Scheme, H: Hasher> EncodeSize for Shard<B, C, H> {
    fn encode_size(&self) -> usize {
        self.commitment.encode_size() + self.index.encode_size() + self.inner.encode_size()
    }

    fn encode_inline_size(&self) -> usize {
        self.commitment.encode_size() + self.index.encode_size() + self.inner.encode_inline_size()
    }
}

impl<B: Digestible, C: Scheme, H: Hasher> Read for Shard<B, C, H> {
    /// An upper bound on the encoded size of an application block.
    type Cfg = usize;

    fn read_cfg(
        buf: &mut impl commonware_codec::Buf,
        max_block_size: &Self::Cfg,
    ) -> Result<Self, commonware_codec::Error> {
        let commitment = Commitment::<B, C, H>::read(buf)?;
        let index = u16::read(buf)?;

        // A coded payload is the block's coded layout followed by its trailer. The claimed config
        // is untrusted until consensus confirms the commitment, so the data width it admits may be
        // the scheme's widest for a payload at this bound.
        let maximum = max_block_size.saturating_add(CODED_TRAILER);
        let inner = C::Shard::read_cfg(buf, &(commitment.config(), maximum))?;

        Ok(Self {
            commitment,
            index,
            inner,
        })
    }
}

impl<B: Digestible, C: Scheme, H: Hasher> PartialEq for Shard<B, C, H> {
    fn eq(&self, other: &Self) -> bool {
        self.commitment == other.commitment
            && self.index == other.index
            && self.inner == other.inner
    }
}

impl<B: Digestible, C: Scheme, H: Hasher> Eq for Shard<B, C, H> {}

#[cfg(feature = "arbitrary")]
impl<B: Digestible, C: Scheme, H: Hasher> arbitrary::Arbitrary<'_> for Shard<B, C, H>
where
    Commitment<B, C, H>: for<'a> arbitrary::Arbitrary<'a>,
    C::Shard: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            commitment: u.arbitrary()?,
            index: u.arbitrary()?,
            inner: u.arbitrary()?,
        })
    }
}

/// One segment's chunk of a shard.
///
/// A proposer sends each chunk as soon as its segment is coded. That can be before the block is
/// sealed and its commitment exists.
///
/// The leader sends each recipient its chunk, and a participant relays the chunk of its own index
/// unchanged. A recipient checks the chunk against `root`, and [`StreamRoots`] binds every root
/// to the commitment.
pub struct StreamChunk<C: Segmentable> {
    /// The coding config the chunk was coded with.
    pub(crate) config: CodingConfig,
    /// The round in which the block is proposed.
    pub(crate) round: Round,
    /// The index of the shard this chunk belongs to.
    pub(crate) index: u16,
    /// The segment this chunk codes.
    pub(crate) segment: u16,
    /// The root of the segment.
    pub(crate) root: C::Commitment,
    /// The chunk of shard `index` for `segment`.
    pub(crate) chunk: C::Chunk,
}

impl<C: Segmentable> Clone for StreamChunk<C> {
    fn clone(&self) -> Self {
        Self {
            config: self.config,
            round: self.round,
            index: self.index,
            segment: self.segment,
            root: self.root,
            chunk: self.chunk.clone(),
        }
    }
}

impl<C: Segmentable> PartialEq for StreamChunk<C> {
    fn eq(&self, other: &Self) -> bool {
        self.config == other.config
            && self.round == other.round
            && self.index == other.index
            && self.segment == other.segment
            && self.root == other.root
            && self.chunk == other.chunk
    }
}

impl<C: Segmentable> Eq for StreamChunk<C> {}

/// The segment roots of a block whose chunks were streamed. The leader sends them once the block
/// is sealed, and each participant that binds them relays them. They must hash to the
/// commitment's coding root.
pub struct StreamRoots<B: Digestible, C: Segmentable, H: Hasher> {
    /// The coding commitment.
    pub(crate) commitment: Commitment<B, C, H>,
    /// The round in which the block is proposed.
    pub(crate) round: Round,
    /// The root of every segment, in segment order.
    pub(crate) roots: Vec<C::Commitment>,
}

impl<B: Digestible, C: Segmentable, H: Hasher> Clone for StreamRoots<B, C, H> {
    fn clone(&self) -> Self {
        Self {
            commitment: self.commitment,
            round: self.round,
            roots: self.roots.clone(),
        }
    }
}

impl<B: Digestible, C: Segmentable, H: Hasher> PartialEq for StreamRoots<B, C, H> {
    fn eq(&self, other: &Self) -> bool {
        self.commitment == other.commitment
            && self.round == other.round
            && self.roots == other.roots
    }
}

impl<B: Digestible, C: Segmentable, H: Hasher> Eq for StreamRoots<B, C, H> {}

/// A message of the shards engine.
///
/// Every message starts with a one byte tag that selects the variant:
///
/// ```text
/// Stream: 0 || coding config || round || index || segment || root || chunk
/// Roots:  1 || commitment || round || roots
/// ```
///
/// Each variant claims a coding config in the field after the tag. A stream message's config is
/// that field, and a roots message's commitment ends with its config, so a receiver can classify
/// a message with [`Self::claimed_config`] before decoding the rest.
pub enum ShardMessage<B: Digestible, C: Segmentable, H: Hasher> {
    /// One segment's chunk of a shard.
    Stream(StreamChunk<C>),
    /// The segment roots of a block whose chunks were streamed.
    Roots(StreamRoots<B, C, H>),
}

impl<B: Digestible, C: Segmentable, H: Hasher> ShardMessage<B, C, H> {
    const STREAM: u8 = 0;
    const ROOTS: u8 = 1;

    /// Returns the largest encoded size of a message whose chunk encodes to at most `chunk`
    /// bytes, for a block of at most `segments` segments.
    pub fn max_encode_size(chunk: usize, segments: u16) -> usize {
        let stream = CodingConfig::SIZE
            + Round::MAX_ENCODE_SIZE
            + 2 * u16::SIZE
            + C::Commitment::SIZE
            + chunk;
        let roots = Commitment::<B, C, H>::SIZE
            + Round::MAX_ENCODE_SIZE
            + usize::from(segments).encode_size()
            + usize::from(segments) * C::Commitment::SIZE;
        u8::SIZE + stream.max(roots)
    }

    /// Returns the coding config the encoded message `bytes` claims, reading only its tag and
    /// the config or commitment that follows.
    pub fn claimed_config(bytes: &[u8]) -> Result<CodingConfig, CodecError> {
        let mut buf = commonware_codec::Copying(bytes);
        match u8::read(&mut buf)? {
            Self::STREAM => CodingConfig::read(&mut buf),
            Self::ROOTS => Ok(Commitment::<B, C, H>::read(&mut buf)?.config()),
            tag => Err(CodecError::InvalidEnum(tag)),
        }
    }

    /// Returns the round the message belongs to.
    pub const fn round(&self) -> Round {
        match self {
            Self::Stream(chunk) => chunk.round,
            Self::Roots(roots) => roots.round,
        }
    }

    /// Writes every field but the variable-width chunk data.
    fn write_header(&self, buf: &mut impl BufMut) {
        match self {
            Self::Stream(chunk) => {
                Self::STREAM.write(buf);
                chunk.config.write(buf);
                chunk.round.write(buf);
                chunk.index.write(buf);
                chunk.segment.write(buf);
                chunk.root.write(buf);
            }
            Self::Roots(roots) => {
                Self::ROOTS.write(buf);
                roots.commitment.write(buf);
                roots.round.write(buf);
                roots.roots.write(buf);
            }
        }
    }

    /// Returns the encoded size of every field but the chunk data.
    fn header_size(&self) -> usize {
        u8::SIZE
            + match self {
                Self::Stream(chunk) => {
                    CodingConfig::SIZE
                        + chunk.round.encode_size()
                        + chunk.index.encode_size()
                        + chunk.segment.encode_size()
                        + chunk.root.encode_size()
                }
                Self::Roots(roots) => {
                    Commitment::<B, C, H>::SIZE
                        + roots.round.encode_size()
                        + roots.roots.encode_size()
                }
            }
    }
}

impl<B: Digestible, C: Segmentable, H: Hasher> From<StreamChunk<C>> for ShardMessage<B, C, H> {
    fn from(chunk: StreamChunk<C>) -> Self {
        Self::Stream(chunk)
    }
}

impl<B: Digestible, C: Segmentable, H: Hasher> From<StreamRoots<B, C, H>>
    for ShardMessage<B, C, H>
{
    fn from(roots: StreamRoots<B, C, H>) -> Self {
        Self::Roots(roots)
    }
}

impl<B: Digestible, C: Segmentable, H: Hasher> Clone for ShardMessage<B, C, H> {
    fn clone(&self) -> Self {
        match self {
            Self::Stream(chunk) => Self::Stream(chunk.clone()),
            Self::Roots(roots) => Self::Roots(roots.clone()),
        }
    }
}

impl<B: Digestible, C: Segmentable, H: Hasher> Write for ShardMessage<B, C, H> {
    fn write(&self, buf: &mut impl BufMut) {
        self.write_header(buf);
        if let Self::Stream(chunk) = self {
            chunk.chunk.write(buf);
        }
    }

    fn write_bufs(&self, buf: &mut impl BufsMut) {
        self.write_header(buf);
        if let Self::Stream(chunk) = self {
            chunk.chunk.write_bufs(buf);
        }
    }
}

impl<B: Digestible, C: Segmentable, H: Hasher> EncodeSize for ShardMessage<B, C, H> {
    fn encode_size(&self) -> usize {
        self.header_size()
            + match self {
                Self::Stream(chunk) => chunk.chunk.encode_size(),
                Self::Roots(_) => 0,
            }
    }

    fn encode_inline_size(&self) -> usize {
        self.header_size()
            + match self {
                Self::Stream(chunk) => chunk.chunk.encode_inline_size(),
                Self::Roots(_) => 0,
            }
    }
}

impl<B: Digestible, C: Segmentable, H: Hasher> Read for ShardMessage<B, C, H> {
    /// An upper bound on the encoded size of an application block.
    type Cfg = usize;

    fn read_cfg(
        buf: &mut impl commonware_codec::Buf,
        max_block_size: &Self::Cfg,
    ) -> Result<Self, CodecError> {
        // The claimed config is untrusted until roots bound to a named commitment cover the chunk,
        // so chunk data may reach the scheme's widest for a payload at this bound. A payload at
        // the bound also has the most segments.
        let maximum = max_block_size.saturating_add(CODED_TRAILER);
        match u8::read(buf)? {
            Self::STREAM => {
                let config = CodingConfig::read(buf)?;
                let round = Round::read(buf)?;
                let index = u16::read(buf)?;
                let segment = u16::read(buf)?;
                let root = C::Commitment::read(buf)?;
                let chunk = C::Chunk::read_cfg(buf, &(config, maximum))?;
                Ok(Self::Stream(StreamChunk {
                    config,
                    round,
                    index,
                    segment,
                    root,
                    chunk,
                }))
            }
            Self::ROOTS => {
                let segments = usize::from(C::segments(maximum));
                let commitment = Commitment::<B, C, H>::read(buf)?;
                let round = Round::read(buf)?;
                let roots =
                    Vec::<C::Commitment>::read_cfg(buf, &(RangeCfg::new(1..=segments), ()))?;
                Ok(Self::Roots(StreamRoots {
                    commitment,
                    round,
                    roots,
                }))
            }
            tag => Err(CodecError::InvalidEnum(tag)),
        }
    }
}

impl<B: Digestible, C: Segmentable, H: Hasher> PartialEq for ShardMessage<B, C, H> {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Stream(a), Self::Stream(b)) => a == b,
            (Self::Roots(a), Self::Roots(b)) => a == b,
            _ => false,
        }
    }
}

impl<B: Digestible, C: Segmentable, H: Hasher> Eq for ShardMessage<B, C, H> {}

#[cfg(feature = "arbitrary")]
impl<B: Digestible, C: Segmentable, H: Hasher> arbitrary::Arbitrary<'_> for ShardMessage<B, C, H>
where
    Commitment<B, C, H>: for<'a> arbitrary::Arbitrary<'a>,
    C::Commitment: for<'a> arbitrary::Arbitrary<'a>,
    C::Chunk: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        if u.arbitrary()? {
            Ok(Self::Stream(StreamChunk {
                config: u.arbitrary()?,
                round: u.arbitrary()?,
                index: u.arbitrary()?,
                segment: u.arbitrary()?,
                root: u.arbitrary()?,
                chunk: u.arbitrary()?,
            }))
        } else {
            Ok(Self::Roots(StreamRoots {
                commitment: u.arbitrary()?,
                round: u.arbitrary()?,
                roots: u.arbitrary()?,
            }))
        }
    }
}

/// An envelope type for an erasure coded [`Block`].
///
/// The consensus commitment is fixed when the block is built, decoded, or restored, so reading
/// the commitment or the inner block's digest never hashes or erasure codes.
#[derive(Debug)]
pub struct CodedBlock<B: Block, C: Scheme, H: Hasher> {
    /// The inner block type.
    inner: Arc<B>,
    /// The consensus commitment, binding the inner block's digest, the coding root, the digest
    /// of the consensus context, and the coding configuration.
    commitment: Commitment<B, C, H>,
    /// The coded shards.
    ///
    /// These shards are lazily-constructed when [`CodedBlock`] is formed without erasure coding,
    /// by [`Self::precomputed`], a trusted decode, or restoration from storage.
    shards: OnceLock<Arc<[C::Shard]>>,
}

impl<B: Block, C: Scheme, H: Hasher> CodedBlock<B, C, H> {
    /// Returns the largest encoded size of a coded block whose application block encodes to at
    /// most `application` bytes.
    pub const fn max_encode_size(application: usize) -> usize {
        application + CodingConfig::SIZE
    }

    /// Returns the largest coded payload of a block whose application block encodes to at most
    /// `application` bytes.
    pub const fn max_coded_size(application: usize) -> usize {
        application + CODED_TRAILER
    }

    /// Creates a [`CodedBlock`] from a [`Block`] and its precomputed [`Commitment`].
    ///
    /// `commitment` must encode `inner`. [`Self::shards`] generates shards on
    /// demand and panics if the coding root does not match.
    ///
    /// Panics if `commitment` does not commit to the block's digest.
    pub fn precomputed(inner: Digested<B>, commitment: Commitment<B, C, H>) -> Self {
        assert_eq!(
            inner.digest(),
            commitment.block(),
            "commitment does not commit to block"
        );
        Self {
            inner: inner.into(),
            commitment,
            shards: OnceLock::new(),
        }
    }

    /// Returns the coding configuration for the data committed.
    pub fn config(&self) -> CodingConfig {
        self.commitment.config()
    }

    /// Returns a [`Shard`] at the given index, if the index is valid.
    pub fn shard(&self, index: u16) -> Option<Shard<B, C, H>> {
        Some(Shard::new(
            self.commitment,
            index,
            self.shards.get()?.get(usize::from(index))?.clone(),
        ))
    }

    /// Returns a reference to the inner [`Block`].
    pub fn inner(&self) -> &B {
        &self.inner
    }

    /// Returns a shared reference to the inner [`Block`].
    pub fn inner_shared(&self) -> Arc<B> {
        Arc::clone(&self.inner)
    }

    /// Returns the inner [`Block`] with its digest, which the commitment binds.
    pub fn inner_digested(&self) -> Digested<B> {
        Digested::precomputed(Arc::clone(&self.inner), self.commitment.block())
    }
}

impl<B: CertifiableBlock + CodedLayout, C: Scheme, H: Hasher> CodedBlock<B, C, H> {
    /// Erasure codes the block's coded layout.
    #[allow(clippy::type_complexity)]
    fn encode_shards(
        inner: &B,
        config: CodingConfig,
        strategy: &impl Strategy,
    ) -> Result<(C::Commitment, Vec<C::Shard>), C::Error> {
        let (payload, _) = coded_payload(inner, config);
        C::encode(&config, payload.as_slice(), strategy)
    }

    /// Returns a reference to the shards in this coded block.
    ///
    /// If the shards have not yet been generated, they will be created via [`Scheme::encode`].
    pub fn shards(&self, strategy: &impl Strategy) -> &[C::Shard] {
        self.shards.get_or_init(|| {
            let (root, shards) = Self::encode_shards(&self.inner, self.config(), strategy)
                .expect("must encode block successfully");

            // A mismatch means a commitment trusted at construction does not
            // encode this block, which is a contract violation or a consensus
            // safety failure. Never serve shards under a different root.
            assert_eq!(
                root,
                self.commitment.root(),
                "coded block constructed with trusted commitment does not match commitment"
            );

            shards.into()
        })
    }

    /// Builds a [`CodedBlock`] from shards already coded under `root` and `config`, for example
    /// segment by segment while the block was built.
    ///
    /// `shards` and `root` must be the coding of the block's coded layout under `config`, as
    /// [`Self::encode`] would produce them.
    pub fn from_shards(
        inner: Digested<B>,
        config: CodingConfig,
        root: C::Commitment,
        shards: Vec<C::Shard>,
    ) -> Self {
        Self {
            commitment: Self::commit(&inner, root, config),
            inner: inner.into(),
            shards: OnceLock::from(Arc::<[C::Shard]>::from(shards)),
        }
    }

    /// Builds the consensus commitment of `inner` from its coding `root` and `config`.
    fn commit(
        inner: &Digested<B>,
        root: C::Commitment,
        config: CodingConfig,
    ) -> Commitment<B, C, H> {
        Commitment::from((
            inner.digest(),
            root,
            hash_context::<H, _>(&inner.context()),
            config,
        ))
    }

    /// Erasure codes `inner` with `config` as a job on `strategy`, producing a [`CodedBlock`] that
    /// holds its shards.
    #[track_caller]
    pub fn encode(
        inner: Digested<B>,
        config: CodingConfig,
        strategy: &impl Strategy,
    ) -> impl Future<Output = Self> + Send + 'static {
        strategy.spawn(inner.encode_size(), move |strategy| {
            let (root, shards) = Self::encode_shards(inner.inner(), config, &strategy)
                .expect("must encode block successfully");
            Self {
                commitment: Self::commit(&inner, root, config),
                inner: inner.into(),
                shards: OnceLock::from(Arc::<[C::Shard]>::from(shards)),
            }
        })
    }

    /// Builds a [`CodedBlock`] from a decoded block and coding configuration, failing unless the
    /// result's commitment equals the one in `expected`.
    ///
    /// The block's digest and, for [`ExpectedCommitment::Untrusted`], its coding root are computed
    /// as jobs on `strategy`.
    pub(crate) fn from_decoded(
        inner: B,
        config: CodingConfig,
        expected: ExpectedCommitment<Commitment<B, C, H>>,
        strategy: &impl Strategy,
    ) -> impl Future<Output = Result<Self, commonware_codec::Error>> + Send {
        let (ExpectedCommitment::Trusted(commitment) | ExpectedCommitment::Untrusted(commitment)) =
            expected;
        let strategy = strategy.clone();
        async move {
            // Erasure coding is bounded by the expected config and skipped for a block that
            // cannot match, so both are checked before it.
            if config != commitment.config() {
                return Err(commonware_codec::Error::Invalid(
                    "CodedBlock",
                    "config mismatch",
                ));
            }
            let inner = Digested::compute(inner, &strategy).await;
            if inner.digest() != commitment.block() {
                return Err(commonware_codec::Error::Invalid(
                    "CodedBlock",
                    "block digest mismatch",
                ));
            }

            // A certified commitment already fixes the coding root of these bytes,
            // so recomputing it would only re-derive the root already in `expected`.
            let (root, shards) = match expected {
                ExpectedCommitment::Trusted(_) => (commitment.root(), None),
                ExpectedCommitment::Untrusted(_) => {
                    let encoding = inner.clone();
                    let (root, shards) = strategy
                        .spawn(inner.encode_size(), move |strategy| {
                            Self::encode_shards(encoding.inner(), config, &strategy)
                        })
                        .await
                        .map_err(|_| {
                            commonware_codec::Error::Invalid(
                                "CodedBlock",
                                "Failed to re-commit to block",
                            )
                        })?;
                    (root, Some(shards))
                }
            };

            // Binds the components not checked above, which are the root and the context digest.
            let computed = Self::commit(&inner, root, config);
            if computed != commitment {
                return Err(commonware_codec::Error::Invalid(
                    "CodedBlock",
                    "commitment mismatch",
                ));
            }
            Ok(Self {
                inner: inner.into(),
                commitment: computed,
                shards: shards.map_or_else(OnceLock::new, |shards| {
                    OnceLock::from(Arc::<[C::Shard]>::from(shards))
                }),
            })
        }
    }
}

impl<B: Block, C: Scheme, H: Hasher> From<CodedBlock<B, C, H>> for StoredCodedBlock<B, C, H> {
    fn from(block: CodedBlock<B, C, H>) -> Self {
        Self::new(block)
    }
}

/// Shares the inner block of a [`CodedBlock`] for archival.
impl<B: Block, C: Scheme, H: Hasher> From<Arc<CodedBlock<B, C, H>>> for StoredCodedBlock<B, C, H> {
    fn from(block: Arc<CodedBlock<B, C, H>>) -> Self {
        Self {
            commitment: block.commitment,
            inner: block.inner_shared(),
        }
    }
}

impl<B: Block, C: Scheme, H: Hasher> Clone for CodedBlock<B, C, H> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            commitment: self.commitment,
            shards: self.shards.clone(),
        }
    }
}

impl<B: Block, C: Scheme, H: Hasher> Committable for CodedBlock<B, C, H> {
    type Commitment = Commitment<B, C, H>;

    fn commitment(&self) -> Self::Commitment {
        self.commitment
    }
}

impl<B: Block, C: Scheme, H: Hasher> Digestible for CodedBlock<B, C, H> {
    type Digest = B::Digest;

    fn digest(&self) -> Self::Digest {
        self.commitment.block()
    }
}

impl<B: Block, C: Scheme, H: Hasher> Write for CodedBlock<B, C, H> {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.inner.write(buf);
        self.config().write(buf);
    }
}

impl<B: Block, C: Scheme, H: Hasher> EncodeSize for CodedBlock<B, C, H> {
    fn encode_size(&self) -> usize {
        self.inner.encode_size() + self.config().encode_size()
    }
}

impl<B: Block, C: Scheme, H: Hasher> Block for CodedBlock<B, C, H> {
    fn parent(&self) -> Self::Digest {
        self.inner.parent()
    }
}

impl<B: Block, C: Scheme, H: Hasher> Heightable for CodedBlock<B, C, H> {
    fn height(&self) -> Height {
        self.inner.height()
    }
}

impl<B: CertifiableBlock, C: Scheme, H: Hasher> CertifiableBlock for CodedBlock<B, C, H> {
    type Context = B::Context;

    fn context(&self) -> Self::Context {
        self.inner.context()
    }
}

/// Hashes a consensus context for inclusion in a [`Commitment`].
pub fn hash_context<H: Hasher, C: EncodeSize + Write>(context: &C) -> H::Digest {
    let mut buf = Vec::with_capacity(context.encode_size());
    context.write(&mut buf);
    H::hash(&[&buf])
}

impl<B: Block + PartialEq, C: Scheme, H: Hasher> PartialEq for CodedBlock<B, C, H> {
    fn eq(&self, other: &Self) -> bool {
        self.inner == other.inner
            && self.commitment == other.commitment
            && self.shards == other.shards
    }
}

impl<B: Block + Eq, C: Scheme, H: Hasher> Eq for CodedBlock<B, C, H> {}

/// A [`CodedBlock`] paired with its [`Commitment`] for efficient storage and retrieval.
///
/// This type should be preferred for storing verified [`CodedBlock`]s on disk, and it
/// should never be sent over the network. Use [`CodedBlock`] for network transmission.
///
/// When reading from storage, we don't need to re-encode or hash the block to compute
/// the commitment, because we stored it alongside the block when we first verified it.
/// This avoids expensive erasure coding operations on the read path.
pub struct StoredCodedBlock<B: Block, C: Scheme, H: Hasher> {
    inner: Arc<B>,
    commitment: Commitment<B, C, H>,
}

impl<B: Block, C: Scheme, H: Hasher> StoredCodedBlock<B, C, H> {
    /// Create a [`StoredCodedBlock`] from a verified [`CodedBlock`].
    ///
    /// The caller must ensure the [`CodedBlock`] has been properly verified
    /// (i.e., its commitment was computed or validated against a trusted source).
    pub fn new(block: CodedBlock<B, C, H>) -> Self {
        Self {
            commitment: block.commitment,
            inner: block.inner,
        }
    }

    /// Convert back to a [`CodedBlock`] using the trusted commitment.
    ///
    /// The returned [`CodedBlock`] generates shards lazily if they are needed.
    pub fn into_coded_block(self) -> CodedBlock<B, C, H> {
        CodedBlock {
            inner: self.inner,
            commitment: self.commitment,
            shards: OnceLock::new(),
        }
    }

    /// Returns a reference to the inner block.
    pub fn inner(&self) -> &B {
        &self.inner
    }
}

/// Converts a [`StoredCodedBlock`] back to a [`CodedBlock`].
impl<B: Block, C: Scheme, H: Hasher> From<StoredCodedBlock<B, C, H>> for CodedBlock<B, C, H> {
    fn from(stored: StoredCodedBlock<B, C, H>) -> Self {
        stored.into_coded_block()
    }
}

/// Restores a shared [`CodedBlock`] from its stored form.
impl<B: Block, C: Scheme, H: Hasher> From<StoredCodedBlock<B, C, H>> for Arc<CodedBlock<B, C, H>> {
    fn from(stored: StoredCodedBlock<B, C, H>) -> Self {
        Self::new(stored.into())
    }
}

impl<B: Block, C: Scheme, H: Hasher> Clone for StoredCodedBlock<B, C, H> {
    fn clone(&self) -> Self {
        Self {
            commitment: self.commitment,
            inner: Arc::clone(&self.inner),
        }
    }
}

impl<B: Block, C: Scheme, H: Hasher> Committable for StoredCodedBlock<B, C, H> {
    type Commitment = Commitment<B, C, H>;

    fn commitment(&self) -> Self::Commitment {
        self.commitment
    }
}

impl<B: Block, C: Scheme, H: Hasher> Digestible for StoredCodedBlock<B, C, H> {
    type Digest = B::Digest;

    fn digest(&self) -> Self::Digest {
        self.commitment.block()
    }
}

impl<B: Block, C: Scheme, H: Hasher> Write for StoredCodedBlock<B, C, H> {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.inner.write(buf);
        self.commitment.write(buf);
    }
}

impl<B: Block, C: Scheme, H: Hasher> EncodeSize for StoredCodedBlock<B, C, H> {
    fn encode_size(&self) -> usize {
        self.inner.encode_size() + self.commitment.encode_size()
    }
}

impl<B: Block + Read, C: Scheme, H: Hasher> Read for StoredCodedBlock<B, C, H> {
    type Cfg = B::Cfg;

    fn read_cfg(
        buf: &mut impl commonware_codec::Buf,
        block_cfg: &Self::Cfg,
    ) -> Result<Self, commonware_codec::Error> {
        let inner = B::read_cfg(buf, block_cfg)?;
        let commitment = Commitment::<B, C, H>::read(buf)?;
        Ok(Self {
            commitment,
            inner: Arc::new(inner),
        })
    }
}

impl<B: Block, C: Scheme, H: Hasher> Block for StoredCodedBlock<B, C, H> {
    fn parent(&self) -> Self::Digest {
        self.inner.parent()
    }
}

impl<B: CertifiableBlock, C: Scheme, H: Hasher> CertifiableBlock for StoredCodedBlock<B, C, H> {
    type Context = B::Context;

    fn context(&self) -> Self::Context {
        self.inner.context()
    }
}

impl<B: Block, C: Scheme, H: Hasher> Heightable for StoredCodedBlock<B, C, H> {
    fn height(&self) -> Height {
        self.inner.height()
    }
}

impl<B: Block + PartialEq, C: Scheme, H: Hasher> PartialEq for StoredCodedBlock<B, C, H> {
    fn eq(&self, other: &Self) -> bool {
        self.commitment == other.commitment && self.inner == other.inner
    }
}

impl<B: Block + Eq, C: Scheme, H: Hasher> Eq for StoredCodedBlock<B, C, H> {}

/// Compute the [`CodingConfig`] for a given number of participants.
///
/// Panics if `n_participants < 4`.
pub fn coding_config_for_participants(n_participants: u16) -> CodingConfig {
    let max_faults = N3f1::max_faults(n_participants);
    assert!(
        max_faults >= 1,
        "Need at least 4 participants to maintain fault tolerance"
    );
    let max_faults = u16::try_from(max_faults).expect("max_faults must fit in u16");
    let minimum_shards = NZU16!(max_faults + 1);
    CodingConfig {
        minimum_shards,
        extra_shards: NZU16!(n_participants - minimum_shards.get()),
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::marshal::mocks::block::{EmptyBlock, encode_block};
    use commonware_codec::{Decode, Encode, Error, Input};
    use commonware_coding::ReedSolomon;
    use commonware_cryptography::{Digest, Sha256, sha256::Digest as Sha256Digest};
    use commonware_parallel::Sequential;
    use commonware_runtime::iobuf::EncodeExt;

    const MAX_BLOCK_SIZE: usize = 1024 * 1024;

    type H = Sha256;
    type RS = ReedSolomon<H>;
    type TestBlock = EmptyBlock<H>;
    type RShard = Shard<TestBlock, RS, H>;

    /// Decodes a coded block's wire bytes against `expected` the way the coding variant does.
    fn decode(
        encoded: impl Input,
        expected: ExpectedCommitment<Commitment<TestBlock, RS, H>>,
    ) -> Result<CodedBlock<TestBlock, RS, H>, Error> {
        let (inner, config) = <(TestBlock, CodingConfig)>::decode_cfg(encoded, &((), ()))?;
        Sequential.block_on(CodedBlock::from_decoded(
            inner,
            config,
            expected,
            &Sequential,
        ))
    }

    /// A shard decodes only when it is no wider than a block of the maximum size produces under
    /// the coding config its commitment claims.
    #[test]
    fn test_shard_width_bounded_by_commitment_config() {
        const MAX: usize = 1000;
        const CONFIG: CodingConfig = CodingConfig {
            minimum_shards: NZU16!(2),
            extra_shards: NZU16!(2),
        };
        let encode = |len: usize, claimed: CodingConfig| {
            let (root, shards) =
                RS::encode(&CONFIG, vec![0u8; len].as_slice(), &Sequential).unwrap();
            let commitment =
                Commitment::from((Sha256Digest::EMPTY, root, Sha256Digest::EMPTY, claimed));
            RShard::new(commitment, 0, shards[0].clone()).encode()
        };

        // A maximum block and the trailer of its coded payload produce the widest admitted shard.
        let widest = MAX + CODED_TRAILER;
        assert!(RShard::decode_cfg(encode(widest, CONFIG), &MAX).is_ok());

        // One more byte widens the shard past the bound.
        assert!(RShard::decode_cfg(encode(widest + 1, CONFIG), &MAX).is_err());

        // A commitment claiming more minimum shards narrows the bound.
        let claimed = CodingConfig {
            minimum_shards: NZU16!(4),
            extra_shards: NZU16!(2),
        };
        assert!(RShard::decode_cfg(encode(widest, claimed), &MAX).is_err());
    }

    /// A shard of a block whose encoding is exactly at the bound decodes.
    #[test]
    fn test_shard_of_block_at_bound_decodes() {
        const CONFIG: CodingConfig = CodingConfig {
            minimum_shards: NZU16!(1),
            extra_shards: NZU16!(2),
        };

        let block = TestBlock::new(Sha256::hash(&[b"parent"]), Height::new(42), 1_234_567);
        let bound = block.encode_size();
        let coded = encode_block::<TestBlock, RS, H>(block, CONFIG);
        let shard = coded.shard(0).unwrap();
        assert!(RShard::decode_cfg(shard.encode(), &bound).is_ok());
    }

    #[test]
    fn test_shard_wrapper_codec_roundtrip() {
        const MOCK_BLOCK_DATA: &[u8] = b"commonware shape rotator club";
        const CONFIG: CodingConfig = CodingConfig {
            minimum_shards: NZU16!(1),
            extra_shards: NZU16!(2),
        };

        let (commitment, shards) = RS::encode(&CONFIG, MOCK_BLOCK_DATA, &Sequential).unwrap();
        let raw_shard = shards.first().cloned().unwrap();

        let commitment =
            Commitment::from((Sha256Digest::EMPTY, commitment, Sha256Digest::EMPTY, CONFIG));
        let shard = RShard::new(commitment, 0, raw_shard);
        let encoded = shard.encode();
        let decoded = RShard::decode_cfg(encoded, &MAX_BLOCK_SIZE).unwrap();
        assert!(shard == decoded);
    }

    #[test]
    fn test_shard_decode_truncated_returns_error() {
        let decode = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let buf = commonware_codec::Copying(&[]);
            RShard::decode_cfg(buf, &MAX_BLOCK_SIZE)
        }));
        assert!(decode.is_ok(), "decode must not panic on truncated input");
        assert!(decode.unwrap().is_err());
    }

    /// Every message variant starts with its tag, claims its coding config in the field after it,
    /// round-trips, and fits the bound for its chunk width and segment count. A roots message
    /// carrying more roots than a payload at the bound has segments is rejected.
    #[test]
    fn test_shard_message_codec_roundtrip() {
        // A chunk and the roots of a two-segment payload, one message of each variant.
        type SC = commonware_coding::Segmented<H, 64>;
        const CONFIG: CodingConfig = CodingConfig {
            minimum_shards: NZU16!(2),
            extra_shards: NZU16!(2),
        };
        let data = [7u8; 100];
        let (root, shards) = SC::encode(&CONFIG, data.as_slice(), &Sequential).unwrap();
        let (roots, chunks) = SC::split(&shards[1]);
        let commitment = Commitment::from((Sha256Digest::EMPTY, root, Sha256Digest::EMPTY, CONFIG));
        let round = Round::new(crate::types::Epoch::new(3), crate::types::View::new(7));
        let stream = StreamChunk::<SC> {
            config: CONFIG,
            round,
            index: 1,
            segment: 1,
            root: roots[1],
            chunk: chunks[1].clone(),
        };
        let sealed = StreamRoots {
            commitment,
            round,
            roots,
        };

        // Each message starts with its tag, fits the bound, claims the config, and round-trips.
        let bound = ShardMessage::<TestBlock, SC, H>::max_encode_size(
            SC::max_chunk_size(&CONFIG, data.len()),
            SC::segments(data.len()),
        );
        for (tag, message) in [(0, stream.into()), (1, sealed.clone().into())] {
            let message: ShardMessage<TestBlock, SC, H> = message;
            let encoded = message.encode();
            assert_eq!(encoded[0], tag);
            assert!(encoded.len() <= bound);
            assert_eq!(
                ShardMessage::<TestBlock, SC, H>::claimed_config(encoded.as_ref()).unwrap(),
                CONFIG
            );
            let decoded =
                ShardMessage::<TestBlock, SC, H>::decode_cfg(encoded, &MAX_BLOCK_SIZE).unwrap();
            assert!(decoded == message);
        }

        // A message with no tag or an unknown tag claims no config.
        assert!(ShardMessage::<TestBlock, SC, H>::claimed_config(&[]).is_err());
        assert!(ShardMessage::<TestBlock, SC, H>::claimed_config(&[2]).is_err());

        // A payload at a 64 byte block bound spans two segments, so a third root is rejected.
        let mut wide = sealed;
        wide.roots.push(root);
        let encoded = ShardMessage::Roots(wide).encode();
        assert!(ShardMessage::<TestBlock, SC, H>::decode_cfg(encoded, &64).is_err());
    }

    /// The coded layout of a block that keeps the defaults is its canonical encoding with an
    /// empty body, and the payload decodes back to the block and config. A trailer naming a body
    /// longer than the payload is rejected.
    #[test]
    fn test_coded_payload_roundtrip() {
        // A block that keeps the defaults codes as its canonical encoding, a zero body length,
        // and the config.
        let block = TestBlock::new(Sha256Digest::EMPTY, Height::new(3), 9);
        let config = coding_config_for_participants(4);
        let (payload, body_len) = coded_payload(&block, config);
        assert_eq!(body_len, 0);
        let mut expected = block.encode().to_vec();
        expected.extend_from_slice(&0u32.to_le_bytes());
        expected.extend_from_slice(&config.encode());
        assert_eq!(payload, expected);

        // The payload decodes back to the block and its config.
        let (decoded, decoded_config) = read_coded_payload::<TestBlock>(payload, &()).unwrap();
        assert!(decoded == block);
        assert_eq!(decoded_config, config);

        // A trailer naming a body longer than the payload is rejected.
        let (mut payload, _) = coded_payload(&block, config);
        let at = payload.len() - CODED_TRAILER;
        payload[at..at + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(read_coded_payload::<TestBlock>(payload, &()).is_err());
    }

    /// A block whose digest is the hash of its header. The header commits to the transactions by
    /// their hash, and the coded layout puts them ahead of it.
    #[derive(Clone, Debug, PartialEq, Eq)]
    struct HeaderBlock {
        parent: Sha256Digest,
        root: Sha256Digest,
        txs: Vec<u64>,
    }

    impl HeaderBlock {
        fn new(parent: Sha256Digest, txs: Vec<u64>) -> Self {
            Self {
                parent,
                root: Sha256::hash(&[txs.encode().as_ref()]),
                txs,
            }
        }
    }

    impl Write for HeaderBlock {
        fn write(&self, buf: &mut impl BufMut) {
            self.parent.write(buf);
            self.root.write(buf);
            self.txs.write(buf);
        }
    }

    impl EncodeSize for HeaderBlock {
        fn encode_size(&self) -> usize {
            self.parent.encode_size() + self.root.encode_size() + self.txs.encode_size()
        }
    }

    impl Read for HeaderBlock {
        type Cfg = ();

        fn read_cfg(buf: &mut impl commonware_codec::Buf, _: &Self::Cfg) -> Result<Self, Error> {
            let parent = Sha256Digest::read(buf)?;
            let root = Sha256Digest::read(buf)?;
            let txs = Vec::read_cfg(buf, &(RangeCfg::new(..), ()))?;
            let block = Self::new(parent, txs);
            if block.root != root {
                return Err(Error::Invalid(
                    "HeaderBlock",
                    "transactions do not match the header",
                ));
            }
            Ok(block)
        }
    }

    impl Digestible for HeaderBlock {
        type Digest = Sha256Digest;

        fn digest(&self) -> Self::Digest {
            Sha256::hash(&[self.parent.as_ref(), self.root.as_ref()])
        }
    }

    impl CodedLayout for HeaderBlock {
        fn write_body(&self, buf: &mut impl BufMut) {
            for tx in &self.txs {
                tx.write(buf);
            }
        }

        fn write_tail(&self, buf: &mut impl BufMut) {
            self.parent.write(buf);
            self.root.write(buf);
            self.txs.len().write(buf);
        }

        fn read_coded(body: Bytes, tail: Bytes, cfg: &Self::Cfg) -> Result<Self, Error> {
            // The tail followed by the body is the canonical encoding. Its decoder checks the
            // transactions against the header.
            let block = Self::decode_cfg([tail.as_ref(), body.as_ref()].concat(), cfg)?;

            // Every cut of the encoding concatenates back to it, so only a body of exactly the
            // transactions is the layout.
            if body.len() != block.txs.len() * u64::SIZE {
                return Err(Error::Invalid(
                    "HeaderBlock",
                    "body is not the transactions",
                ));
            }
            Ok(block)
        }
    }

    /// A block whose digest covers only its header codes as a reordering of its canonical encoding,
    /// and no other cut of that encoding reads back. Its decoder rejects transactions the header
    /// does not commit to, since the digest cannot tell them apart.
    #[test]
    fn test_coded_payload_reordered_roundtrip() {
        let block = HeaderBlock::new(Sha256::hash(&[b"parent"]), vec![1, 2, 3]);
        let config = coding_config_for_participants(4);

        // The transactions move ahead of the header and the count, and no byte is added.
        let canonical = block.encode();
        let (payload, body_len) = coded_payload(&block, config);
        let layout_len = payload.len() - CODED_TRAILER;
        assert_eq!(layout_len, canonical.len());
        assert_eq!(body_len, 3 * u64::SIZE);
        let header_len = canonical.len() - body_len;
        assert_eq!(payload[..body_len], canonical[header_len..]);
        assert_eq!(payload[body_len..layout_len], canonical[..header_len]);

        // A block decoded from the canonical encoding codes to the same payload, and the payload
        // reads back as the block.
        let decoded = HeaderBlock::decode_cfg(canonical.clone(), &()).unwrap();
        assert_eq!(coded_payload(&decoded, config).0, payload);
        let (read, read_config) = read_coded_payload::<HeaderBlock>(payload, &()).unwrap();
        assert_eq!(read, block);
        assert_eq!(read_config, config);

        // The canonical encoding cut anywhere else holds the same bytes, but it must not read back.
        for split in (0..=canonical.len()).filter(|split| *split != body_len) {
            let cut = canonical.len() - split;
            let mut payload = [&canonical[cut..], &canonical[..cut]].concat();
            write_coded_trailer(split, config, &mut payload);
            assert!(matches!(
                read_coded_payload::<HeaderBlock>(payload, &()),
                Err(Error::Invalid(
                    "HeaderBlock",
                    "body is not the transactions"
                ))
            ));
        }

        // Other transactions under the same header keep the digest, and its root rejects them.
        let forged = HeaderBlock {
            txs: vec![1, 2, 4],
            ..block
        };
        assert_eq!(forged.digest(), block.digest());
        let (payload, _) = coded_payload(&forged, config);
        assert!(matches!(
            read_coded_payload::<HeaderBlock>(payload, &()),
            Err(Error::Invalid(
                "HeaderBlock",
                "transactions do not match the header"
            ))
        ));
    }

    #[test]
    fn test_coding_config_for_participants_valid_for_minimum_set() {
        let config = coding_config_for_participants(4);
        assert_eq!(config.minimum_shards.get(), 2);
        assert_eq!(config.extra_shards.get(), 2);
    }

    #[test]
    #[should_panic(expected = "Need at least 4 participants to maintain fault tolerance")]
    fn test_coding_config_for_participants_panics_for_small_sets() {
        let _ = coding_config_for_participants(3);
    }

    #[test]
    fn test_shard_codec_roundtrip() {
        const MOCK_BLOCK_DATA: &[u8] = b"deadc0de";
        const CONFIG: CodingConfig = CodingConfig {
            minimum_shards: NZU16!(1),
            extra_shards: NZU16!(2),
        };

        let (commitment, shards) = RS::encode(&CONFIG, MOCK_BLOCK_DATA, &Sequential).unwrap();
        let raw_shard = shards.first().cloned().unwrap();

        let commitment =
            Commitment::from((Sha256Digest::EMPTY, commitment, Sha256Digest::EMPTY, CONFIG));
        let shard = RShard::new(commitment, 0, raw_shard);
        let encoded = shard.encode();
        let decoded = RShard::decode_cfg(encoded, &MAX_BLOCK_SIZE).unwrap();
        assert!(shard == decoded);
    }

    #[test]
    fn test_coded_block_codec_roundtrip() {
        const CONFIG: CodingConfig = CodingConfig {
            minimum_shards: NZU16!(1),
            extra_shards: NZU16!(2),
        };

        let block = TestBlock::new(Sha256::hash(&[b"parent"]), Height::new(42), 1_234_567);
        let coded_block = encode_block::<TestBlock, RS, H>(block, CONFIG);

        let encoded = coded_block.encode();
        let decoded = decode(
            encoded,
            ExpectedCommitment::Trusted(coded_block.commitment()),
        )
        .unwrap();
        assert_eq!(decoded.commitment(), coded_block.commitment());
        assert_eq!(decoded.shards(&Sequential), coded_block.shards(&Sequential));
        assert!(coded_block == decoded);

        // Binding the same bytes to an untrusted commitment recomputes the same block.
        let decoded = decode(
            coded_block.encode(),
            ExpectedCommitment::Untrusted(coded_block.commitment()),
        )
        .unwrap();
        assert!(coded_block == decoded);
    }

    #[test]
    fn test_coded_block_decode_rejects_config_mismatch() {
        const EXPECTED_CONFIG: CodingConfig = CodingConfig {
            minimum_shards: NZU16!(1),
            extra_shards: NZU16!(3),
        };
        const EMBEDDED_CONFIG: CodingConfig = CodingConfig {
            minimum_shards: NZU16!(2),
            extra_shards: NZU16!(2),
        };

        let block = TestBlock::new(Sha256::hash(&[b"parent"]), Height::new(42), 1_234_567);
        let expected =
            encode_block::<TestBlock, RS, H>(block.clone(), EXPECTED_CONFIG).commitment();
        let encoded = (block, EMBEDDED_CONFIG).encode();

        let Err(err) = decode(encoded, ExpectedCommitment::Untrusted(expected)) else {
            panic!("config mismatch should be rejected");
        };

        assert!(
            matches!(err, Error::Invalid("CodedBlock", "config mismatch")),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn test_coded_block_decode_rejects_coding_root_mismatch() {
        const CONFIG: CodingConfig = CodingConfig {
            minimum_shards: NZU16!(1),
            extra_shards: NZU16!(2),
        };

        // Build an expected commitment that differs only in its coding root.
        let block = TestBlock::new(Sha256::hash(&[b"parent"]), Height::new(42), 1_234_567);
        let coded = encode_block::<TestBlock, RS, H>(block, CONFIG);
        let commitment = coded.commitment();
        let wrong_root = Sha256::hash(&[b"wrong root"]);
        assert_ne!(wrong_root, commitment.root());
        let expected = Commitment::<TestBlock, RS, H>::from((
            commitment.block(),
            wrong_root,
            commitment.context(),
            commitment.config(),
        ));

        // Decoding must reject bytes that do not satisfy the exact expected
        // commitment.
        let Err(err) = decode(coded.encode(), ExpectedCommitment::Untrusted(expected)) else {
            panic!("coding root mismatch should be rejected");
        };

        assert!(
            matches!(err, Error::Invalid("CodedBlock", "commitment mismatch")),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn test_coded_block_decode_trusted_is_lazy() {
        const CONFIG: CodingConfig = CodingConfig {
            minimum_shards: NZU16!(1),
            extra_shards: NZU16!(2),
        };

        let block = TestBlock::new(Sha256::hash(&[b"parent"]), Height::new(42), 1_234_567);
        let coded = encode_block::<TestBlock, RS, H>(block, CONFIG);
        let decoded = decode(
            coded.encode(),
            ExpectedCommitment::Trusted(coded.commitment()),
        )
        .unwrap();

        // The root comes from the commitment and shards are generated on demand.
        assert_eq!(decoded.commitment(), coded.commitment());
        assert!(decoded.shard(0).is_none());
        assert_eq!(decoded.shards(&Sequential), coded.shards(&Sequential));
    }

    #[test]
    fn test_coded_block_decode_trusted_rejects_config_mismatch() {
        const EXPECTED_CONFIG: CodingConfig = CodingConfig {
            minimum_shards: NZU16!(1),
            extra_shards: NZU16!(3),
        };
        const EMBEDDED_CONFIG: CodingConfig = CodingConfig {
            minimum_shards: NZU16!(2),
            extra_shards: NZU16!(2),
        };

        let block = TestBlock::new(Sha256::hash(&[b"parent"]), Height::new(42), 1_234_567);
        let expected =
            encode_block::<TestBlock, RS, H>(block.clone(), EXPECTED_CONFIG).commitment();
        let encoded = (block, EMBEDDED_CONFIG).encode();

        let Err(err) = decode(encoded, ExpectedCommitment::Trusted(expected)) else {
            panic!("config mismatch should be rejected");
        };
        assert!(
            matches!(err, Error::Invalid("CodedBlock", "config mismatch")),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn test_coded_block_decode_trusted_rejects_block_digest_mismatch() {
        const CONFIG: CodingConfig = CodingConfig {
            minimum_shards: NZU16!(1),
            extra_shards: NZU16!(2),
        };

        let block = TestBlock::new(Sha256::hash(&[b"parent"]), Height::new(42), 1_234_567);
        let other = TestBlock::new(Sha256::hash(&[b"parent"]), Height::new(43), 1_234_567);
        let expected = encode_block::<TestBlock, RS, H>(block, CONFIG).commitment();
        assert_ne!(other.digest(), expected.block());
        let encoded = (other, CONFIG).encode();

        let Err(err) = decode(encoded, ExpectedCommitment::Trusted(expected)) else {
            panic!("block digest mismatch should be rejected");
        };

        assert!(
            matches!(err, Error::Invalid("CodedBlock", "block digest mismatch")),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    #[should_panic(expected = "does not match commitment")]
    fn test_coded_block_trusted_wrong_root_panics_on_shards() {
        const CONFIG: CodingConfig = CodingConfig {
            minimum_shards: NZU16!(1),
            extra_shards: NZU16!(2),
        };

        // A trusted commitment is not re-encoded at decode, so a root that does
        // not encode the block is only caught when shards are generated.
        let block = TestBlock::new(Sha256::hash(&[b"parent"]), Height::new(42), 1_234_567);
        let coded = encode_block::<TestBlock, RS, H>(block, CONFIG);
        let commitment = coded.commitment();
        let expected = Commitment::<TestBlock, RS, H>::from((
            commitment.block(),
            Sha256::hash(&[b"wrong root"]),
            commitment.context(),
            commitment.config(),
        ));
        let decoded = decode(coded.encode(), ExpectedCommitment::Trusted(expected)).unwrap();

        decoded.shards(&Sequential);
    }

    #[test]
    fn test_coded_block_clone_shares_shards() {
        const CONFIG: CodingConfig = CodingConfig {
            minimum_shards: NZU16!(1),
            extra_shards: NZU16!(2),
        };

        let block = TestBlock::new(Sha256::hash(&[b"parent"]), Height::new(42), 1_234_567);
        let coded_block = encode_block::<TestBlock, RS, H>(block, CONFIG);
        let cloned = coded_block.clone();

        assert!(Arc::ptr_eq(&coded_block.inner, &cloned.inner));
        assert!(Arc::ptr_eq(
            coded_block.shards.get().unwrap(),
            cloned.shards.get().unwrap()
        ));
    }

    #[test]
    fn test_stored_coded_block_codec_roundtrip() {
        const CONFIG: CodingConfig = CodingConfig {
            minimum_shards: NZU16!(1),
            extra_shards: NZU16!(2),
        };

        let block = TestBlock::new(Sha256::hash(&[b"parent"]), Height::new(42), 1_234_567);
        let coded_block = encode_block::<TestBlock, RS, H>(block, CONFIG);
        let stored = StoredCodedBlock::<TestBlock, RS, H>::new(coded_block.clone());

        assert_eq!(stored.commitment(), coded_block.commitment());
        assert_eq!(stored.digest(), coded_block.digest());
        assert_eq!(stored.height(), coded_block.height());
        assert_eq!(stored.parent(), coded_block.parent());

        let encoded = stored.encode();
        let decoded = StoredCodedBlock::<TestBlock, RS, H>::decode_cfg(encoded, &()).unwrap();

        assert!(stored == decoded);
        assert_eq!(decoded.commitment(), coded_block.commitment());
        assert_eq!(decoded.digest(), coded_block.digest());
    }

    #[test]
    fn test_stored_coded_block_into_coded_block() {
        const CONFIG: CodingConfig = CodingConfig {
            minimum_shards: NZU16!(1),
            extra_shards: NZU16!(2),
        };

        let block = TestBlock::new(Sha256::hash(&[b"parent"]), Height::new(42), 1_234_567);
        let coded_block = encode_block::<TestBlock, RS, H>(block, CONFIG);
        let original_commitment = coded_block.commitment();
        let original_digest = coded_block.digest();

        let stored = StoredCodedBlock::<TestBlock, RS, H>::new(coded_block);
        let encoded = stored.encode();
        let decoded = StoredCodedBlock::<TestBlock, RS, H>::decode_cfg(encoded, &()).unwrap();
        let restored = decoded.into_coded_block();

        assert_eq!(restored.commitment(), original_commitment);
        assert_eq!(restored.digest(), original_digest);
    }

    #[test]
    fn test_shard_encode_iobufs_matches_encode() {
        const CONFIG: CodingConfig = CodingConfig {
            minimum_shards: NZU16!(1),
            extra_shards: NZU16!(2),
        };

        let (commitment, shards) =
            RS::encode(&CONFIG, b"iobufs encoding test".as_slice(), &Sequential).unwrap();
        let commitment =
            Commitment::from((Sha256Digest::EMPTY, commitment, Sha256Digest::EMPTY, CONFIG));
        let shard = RShard::new(commitment, 0, shards.into_iter().next().unwrap());

        let encoded = shard.encode();
        let mut encoded_iobufs = shard.encode_iobufs();
        let mut encoded_iobufs_bytes = vec![0u8; encoded_iobufs.remaining()];
        encoded_iobufs.copy_to_slice(&mut encoded_iobufs_bytes);
        assert_eq!(encoded_iobufs_bytes, encoded.as_ref());
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::*;
        use commonware_codec::conformance::CodecConformance;
        use commonware_coding::Segmented;

        commonware_conformance::conformance_tests! {
            CodecConformance<Shard<TestBlock, ReedSolomon<Sha256>, Sha256>>,
            CodecConformance<ShardMessage<TestBlock, Segmented<Sha256, 64>, Sha256>>,
        }
    }
}
