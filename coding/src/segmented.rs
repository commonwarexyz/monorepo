//! Erasure coding applied to fixed-size segments of the data.
//!
//! [Segmented] splits the data into consecutive segments of `L` bytes and codes each segment with
//! [ReedSolomon] on its own. Participant `i` receives the `i`-th chunk of every segment, so it can
//! check and forward each chunk as soon as that chunk arrives, without waiting for its whole shard.
//! The commitment hashes the ordered list of segment roots, so a chunk is provable against its
//! segment root while the remaining segments are still being coded.
//!
//! ```text
//!            segment 0        segment 1        segment 2     ...   last segment (1..=L bytes)
//! data      [...L bytes...][...L bytes...][...L bytes...]  ...  [....]
//!                 |                |                |                  |
//!                 | ReedSolomon    | ReedSolomon    | ReedSolomon      | ReedSolomon
//!                 v                v                v                  v
//! chunks     c0,0 .. c0,n-1   c1,0 .. c1,n-1   c2,0 .. c2,n-1    ...  cS-1,0 .. cS-1,n-1
//!                 |                |                |                  |
//! roots         root_0           root_1           root_2       ...    root_S-1
//!                 +----------------+----------------+---------- ... ---+
//!                                           |
//!                 commitment = H(namespace || L || S || root_0 || ... || root_S-1)
//!
//! shard i = [c0,i][c1,i][c2,i] ... [cS-1,i]    one proof per chunk, each against its segment root
//! ```
//!
//! [SegmentEncoder] codes bytes as they are pushed, emitting each segment when it fills. Pushing
//! a payload in any pieces and finishing produces the commitment, roots, and shards that
//! [Scheme::encode] produces for the whole payload, so a receiver cannot tell streamed coding
//! from one-shot coding.
//!
//! ```text
//! push(a) push(b) push(c) ...... finish()        encode(a || b || c || ...)
//!   |       |       |              |                     |
//!   seg 0   -       seg 1, seg 2   seg S-1, commitment   seg 0 .. seg S-1, commitment
//!                                                        (identical roots, chunks and commitment)
//! ```
//!
//! [Segmentable] exposes the chunk-level and streaming operations a dissemination engine needs.

use crate::{
    Config, ReedSolomon, Scheme,
    reed_solomon::{CheckedChunk, Chunk, Error as RsError},
};
use bytes::{BufMut, Bytes};
use commonware_codec::{
    Buf, BufsMut, Codec, EncodeSize, FixedSize, RangeCfg, Read, Write, util::max_items_size,
};
use commonware_cryptography::{Digest, Hasher};
use commonware_parallel::{Sequential, Strategy};
use std::{fmt::Debug, marker::PhantomData};
use thiserror::Error;

/// Domain separator for the commitment over segment roots.
const NAMESPACE: &[u8] = b"_COMMONWARE_CODING_SEGMENTED_COMMITMENT";

/// Errors that can occur when interacting with the segmented coder.
#[derive(Error, Debug)]
pub enum Error {
    #[error("reed-solomon error: {0}")]
    ReedSolomon(#[from] RsError),
    #[error("segment roots do not match the commitment")]
    CommitmentMismatch,
    #[error("shard has {roots} segment roots but {chunks} chunks")]
    ShapeMismatch { roots: usize, chunks: usize },
    #[error("invalid segment count: {0}")]
    InvalidSegmentCount(usize),
    #[error("invalid segment: {0}")]
    InvalidSegment(u16),
    #[error("missing segment: {0}")]
    MissingSegment(u16),
    #[error("non-canonical segment length {len} at segment {segment}")]
    NonCanonicalSegment { segment: u16, len: usize },
}

/// Hashes `roots` under the segmented domain, binding the segment size and the segment count.
///
/// Every field has a fixed width, so distinct `(segment_size, roots)` inputs hash distinct byte
/// strings.
fn commit_roots<H: Hasher>(segment_size: usize, roots: &[H::Digest]) -> H::Digest {
    let mut hasher = H::default();
    hasher.update(NAMESPACE);
    hasher.update(&(segment_size as u64).to_be_bytes());
    hasher.update(&(roots.len() as u64).to_be_bytes());
    for root in roots {
        hasher.update(root.as_ref());
    }
    hasher.finalize().1
}

/// Chunk-level operations used to code, send, verify, forward, and decode data one segment at a
/// time.
///
/// A shard is the list of segment roots plus one chunk per segment, in segment order. Each chunk
/// can be checked against its segment root independently, and the roots are bound to the
/// commitment by [`Segmentable::commit`]. Pushing a payload through an encoder in any number of
/// pieces and finishing produces the commitment, roots, and shards [`Scheme::encode`] produces
/// for the whole payload.
pub trait Segmentable: Scheme {
    /// The part of a shard that belongs to one segment.
    ///
    /// Chunks decode with a [`Config`] and the maximum number of input data bytes, the same
    /// configuration as [`Scheme::Shard`].
    type Chunk: Clone + Debug + Eq + Codec<Cfg = (Config, usize)> + Send + Sync + 'static;

    /// A chunk that has been checked against its segment root.
    type CheckedChunk: Clone + Send + Sync;

    /// The state of an encoding in progress.
    type Encoder: Send + 'static;

    /// Returns the number of segments the encoding of `data` bytes produces (at least one).
    fn segments(data: usize) -> u16;

    /// Returns an upper bound on the encoded size of any chunk [`Scheme::encode`] produces under
    /// `config` from at most `data` bytes.
    fn max_chunk_size(config: &Config, data: usize) -> usize;

    /// Returns the segment roots and the chunks of a shard, in segment order.
    fn split(shard: &Self::Shard) -> (Vec<Self::Commitment>, Vec<Self::Chunk>);

    /// Builds a shard from its segment roots and its chunk of every segment, in segment order.
    ///
    /// This is the inverse of [`Segmentable::split`].
    fn assemble(roots: Vec<Self::Commitment>, chunks: Vec<Self::Chunk>) -> Self::Shard;

    /// Returns the commitment over the segment roots, as [`Scheme::encode`] returns it.
    fn commit(roots: &[Self::Commitment]) -> Self::Commitment;

    /// Checks one chunk of shard `index` against the root of segment `segment`.
    fn check_chunk(
        config: &Config,
        root: &Self::Commitment,
        index: u16,
        segment: u16,
        chunk: &Self::Chunk,
    ) -> Result<Self::CheckedChunk, Self::Error>;

    /// Decodes the data from checked chunks.
    ///
    /// Any `config.minimum_shards` distinct indices per segment suffice, and they may differ
    /// between segments. `roots` must hash to `commitment`, and every chunk must have been
    /// checked against the root of its segment in `roots`. As with [`Scheme::decode`], the
    /// result is the same data or a failure regardless of which chunks are supplied.
    fn decode_chunks<'a>(
        config: &Config,
        commitment: &Self::Commitment,
        roots: &[Self::Commitment],
        chunks: impl Iterator<Item = &'a Self::CheckedChunk>,
        strategy: &impl Strategy,
    ) -> Result<Vec<u8>, Self::Error>;

    /// Returns an encoder that codes every segment under `config`.
    fn encoder(config: Config) -> Self::Encoder;

    /// Appends `bytes` to the payload `encoder` codes and returns every segment they complete,
    /// in segment order.
    #[allow(clippy::type_complexity)]
    fn push(
        encoder: &mut Self::Encoder,
        bytes: &[u8],
        strategy: &impl Strategy,
    ) -> Result<Vec<EncodedSegment<Self::Commitment, Self::Chunk>>, Self::Error>;

    /// Codes the remaining bytes and returns the commitment, every segment root in order, and
    /// the final segment if pushes did not already return it.
    #[allow(clippy::type_complexity)]
    fn finish(
        encoder: Self::Encoder,
        strategy: &impl Strategy,
    ) -> Result<FinishedEncoding<Self::Commitment, Self::Chunk>, Self::Error>;

    /// Builds every shard from coded segments, so that streamed output equals [`Scheme::encode`].
    ///
    /// `roots` holds the root of every segment in order, and `segments` holds every coded
    /// segment in the same order. Shard `i` receives chunk `i` of each segment.
    ///
    /// # Panics
    ///
    /// Panics if `segments` is empty, if its length differs from `roots`, if a segment is out
    /// of order or disagrees with its root, or if segments hold different numbers of chunks.
    fn assemble_shards(
        roots: Vec<Self::Commitment>,
        segments: Vec<EncodedSegment<Self::Commitment, Self::Chunk>>,
    ) -> Vec<Self::Shard>;
}

/// One segment's chunk of a [`SegmentedShard`]: the coded bytes and a proof against the segment
/// root.
///
/// `L` is the segment size of the [`Segmented`] scheme that produced it. It bounds the width a
/// chunk may have when read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SegmentChunk<D: Digest, const L: usize>(Chunk<D>);

impl<D: Digest, const L: usize> Write for SegmentChunk<D, L> {
    fn write(&self, buf: &mut impl BufMut) {
        self.0.write(buf);
    }

    fn write_bufs(&self, buf: &mut impl BufsMut) {
        self.0.write_bufs(buf);
    }
}

impl<D: Digest, const L: usize> Read for SegmentChunk<D, L> {
    /// The coding config and the maximum number of data bytes across all segments.
    ///
    /// A chunk decodes only if it is no wider than coding a segment of `min(maximum, L)` bytes
    /// under the config would produce.
    type Cfg = (Config, usize);

    fn read_cfg(
        buf: &mut impl Buf,
        (config, maximum): &Self::Cfg,
    ) -> Result<Self, commonware_codec::Error> {
        Chunk::read_cfg(buf, &(*config, (*maximum).min(L))).map(Self)
    }
}

impl<D: Digest, const L: usize> EncodeSize for SegmentChunk<D, L> {
    fn encode_size(&self) -> usize {
        self.0.encode_size()
    }

    fn encode_inline_size(&self) -> usize {
        self.0.encode_inline_size()
    }
}

#[cfg(feature = "arbitrary")]
impl<D: Digest, const L: usize> arbitrary::Arbitrary<'_> for SegmentChunk<D, L>
where
    D: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self(u.arbitrary()?))
    }
}

/// A participant's shard of [`Segmented`] data: every segment root, and this participant's
/// chunk of every segment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SegmentedShard<D: Digest, const L: usize> {
    /// The root of every segment, in segment order.
    pub roots: Vec<D>,
    /// The chunk of segment `s` at position `s`.
    pub chunks: Vec<SegmentChunk<D, L>>,
}

impl<D: Digest, const L: usize> Write for SegmentedShard<D, L> {
    fn write(&self, buf: &mut impl BufMut) {
        self.roots.write(buf);
        self.chunks.write(buf);
    }

    fn write_bufs(&self, buf: &mut impl BufsMut) {
        self.roots.write_bufs(buf);
        self.chunks.write_bufs(buf);
    }
}

impl<D: Digest, const L: usize> Read for SegmentedShard<D, L> {
    /// The coding config and the maximum number of data bytes.
    ///
    /// A shard decodes only if it has one chunk per root and no more segments than encoding
    /// that many bytes produces, and each chunk satisfies the [`SegmentChunk`] width bound.
    type Cfg = (Config, usize);

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        let segments = segment_count::<L>(cfg.1).map_or(usize::from(u16::MAX), usize::from);
        let roots = Vec::<D>::read_cfg(buf, &(RangeCfg::new(1..=segments), ()))?;
        let chunks =
            Vec::<SegmentChunk<D, L>>::read_cfg(buf, &(RangeCfg::exact(roots.len()), *cfg))?;
        Ok(Self { roots, chunks })
    }
}

impl<D: Digest, const L: usize> EncodeSize for SegmentedShard<D, L> {
    fn encode_size(&self) -> usize {
        self.roots.encode_size() + self.chunks.encode_size()
    }

    fn encode_inline_size(&self) -> usize {
        self.roots.encode_inline_size() + self.chunks.encode_inline_size()
    }
}

#[cfg(feature = "arbitrary")]
impl<D: Digest, const L: usize> arbitrary::Arbitrary<'_> for SegmentedShard<D, L>
where
    D: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            roots: u.arbitrary()?,
            chunks: u.arbitrary()?,
        })
    }
}

/// A [`SegmentChunk`] that has been checked against the root of its segment.
///
/// It records the segment root it was checked against so decoding can reject chunks from a
/// different commitment. Like [`ReedSolomon`]'s checked shards, it is parameterized by the
/// hasher that computed its cached digest.
pub struct CheckedSegmentChunk<H: Hasher> {
    root: H::Digest,
    index: u16,
    segment: u16,
    chunk: CheckedChunk<H>,
}

impl<H: Hasher> CheckedSegmentChunk<H> {
    /// Returns the shard index the chunk was checked at.
    pub const fn index(&self) -> u16 {
        self.index
    }

    /// Returns the segment the chunk was checked for.
    pub const fn segment(&self) -> u16 {
        self.segment
    }

    /// Returns the segment root the chunk was checked against.
    pub const fn root(&self) -> &H::Digest {
        &self.root
    }
}

impl<H: Hasher> Clone for CheckedSegmentChunk<H> {
    fn clone(&self) -> Self {
        Self {
            root: self.root,
            index: self.index,
            segment: self.segment,
            chunk: self.chunk.clone(),
        }
    }
}

impl<H: Hasher> Debug for CheckedSegmentChunk<H> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CheckedSegmentChunk")
            .field("root", &self.root)
            .field("index", &self.index)
            .field("segment", &self.segment)
            .field("chunk", &self.chunk)
            .finish()
    }
}

impl<H: Hasher> PartialEq for CheckedSegmentChunk<H> {
    fn eq(&self, other: &Self) -> bool {
        self.root == other.root
            && self.index == other.index
            && self.segment == other.segment
            && self.chunk == other.chunk
    }
}

impl<H: Hasher> Eq for CheckedSegmentChunk<H> {}

/// Returns the number of `L`-byte segments that hold `len` bytes, at least one, or `None`
/// if the count does not fit a `u16` segment index.
fn segment_count<const L: usize>(len: usize) -> Option<u16> {
    u16::try_from(len.div_ceil(L).max(1)).ok()
}

/// One coded segment: its root and the chunk of every shard index, in index order.
///
/// Chunk `i` belongs to shard `i` and is checked against `root` at segment `segment`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodedSegment<D, K> {
    /// The position of the segment in the data.
    pub segment: u16,
    /// The root every chunk of the segment is checked against.
    pub root: D,
    /// The chunk of every shard index, in index order.
    pub chunks: Vec<K>,
}

/// A segment [`Segmented`] codes with segment size `L`.
type Segment<D, const L: usize> = EncodedSegment<D, SegmentChunk<D, L>>;

/// Codes the bytes of segment `segment` with [ReedSolomon].
fn encode_segment<H: Hasher, const L: usize>(
    config: &Config,
    segment: u16,
    data: Bytes,
    strategy: &impl Strategy,
) -> Result<Segment<H::Digest, L>, Error> {
    let (root, chunks) = ReedSolomon::<H>::encode(config, data, strategy)?;
    Ok(EncodedSegment {
        segment,
        root,
        chunks: chunks.into_iter().map(SegmentChunk).collect(),
    })
}

/// What finishing an encoding returns: the commitment, every segment root in order, and the
/// final segment if pushes did not already return it.
type FinishedEncoding<D, K> = (D, Vec<D>, Option<EncodedSegment<D, K>>);

/// Codes data segment by segment as its bytes become available.
///
/// Pushing the bytes of a payload in any number of pieces and then calling
/// [`SegmentEncoder::finish`] yields the commitment, segment roots, and chunks that
/// [`Segmented::encode`] produces for the concatenated bytes. A segment is coded as soon as
/// `L` bytes of it are buffered, so a producer can disseminate each segment's chunks while the
/// rest of the payload is still being computed.
pub struct SegmentEncoder<H: Hasher, const L: usize> {
    /// The coding config shared by every segment.
    config: Config,
    /// Bytes of the segment being filled, fewer than `L` between calls.
    buffer: Vec<u8>,
    /// The root of every segment coded so far, in segment order.
    roots: Vec<H::Digest>,
    /// The number of payload bytes pushed so far, including buffered ones.
    pushed: usize,
}

impl<H: Hasher, const L: usize> SegmentEncoder<H, L> {
    /// Creates an encoder that codes every segment under `config`.
    pub const fn new(config: Config) -> Self {
        let () = Segmented::<H, L>::VALID_SEGMENT_SIZE;
        Self {
            config,
            buffer: Vec::new(),
            roots: Vec::new(),
            pushed: 0,
        }
    }

    /// Appends `bytes` and returns every segment they complete, in segment order.
    ///
    /// A segment completes when `L` bytes of it are buffered, so a payload whose length is a
    /// multiple of `L` has all of its segments returned by pushes and none by
    /// [`SegmentEncoder::finish`]. The segments of one push are coded in parallel on `strategy`.
    ///
    /// Returns [`Error::InvalidSegmentCount`] if the payload would need more segments than a
    /// `u16` segment index can address. Nothing is consumed in that case.
    pub fn push(
        &mut self,
        bytes: &[u8],
        strategy: &impl Strategy,
    ) -> Result<Vec<Segment<H::Digest, L>>, Error> {
        let total = self.pushed.saturating_add(bytes.len());
        if segment_count::<L>(total).is_none() {
            return Err(Error::InvalidSegmentCount(total));
        }

        // Complete the partially filled segment first, then copy out each whole segment of the
        // input and buffer the remainder for the next push.
        let mut inputs = Vec::new();
        let mut rest = bytes;
        if !self.buffer.is_empty() {
            let take = (L - self.buffer.len()).min(rest.len());
            self.buffer.extend_from_slice(&rest[..take]);
            rest = &rest[take..];
            if self.buffer.len() == L {
                inputs.push(Bytes::from(std::mem::take(&mut self.buffer)));
            }
        }
        while rest.len() >= L {
            let (segment, tail) = rest.split_at(L);
            inputs.push(Bytes::copy_from_slice(segment));
            rest = tail;
        }
        if !rest.is_empty() {
            self.buffer.reserve_exact(L);
            self.buffer.extend_from_slice(rest);
        }
        self.pushed = total;

        // Code the completed segments in parallel, numbered after the segments already coded.
        let first = self.roots.len();
        let config = self.config;
        let encoded =
            strategy.try_map_collect_vec(inputs.into_iter().enumerate(), |(offset, segment)| {
                encode_segment::<H, L>(&config, (first + offset) as u16, segment, strategy)
            })?;
        self.roots
            .extend(encoded.iter().map(|segment| segment.root));
        Ok(encoded)
    }

    /// Codes the final segment and returns the commitment, every segment root in order, and the
    /// final segment.
    ///
    /// The final segment holds the bytes [`SegmentEncoder::push`] left buffered, always fewer than
    /// `L`. It is `None` when pushes already returned every segment, and empty data yields a
    /// single empty segment.
    pub fn finish(
        mut self,
        strategy: &impl Strategy,
    ) -> Result<FinishedEncoding<H::Digest, SegmentChunk<H::Digest, L>>, Error> {
        let last = if self.buffer.is_empty() && !self.roots.is_empty() {
            None
        } else {
            let data = Bytes::from(std::mem::take(&mut self.buffer));
            let segment =
                encode_segment::<H, L>(&self.config, self.roots.len() as u16, data, strategy)?;
            self.roots.push(segment.root);
            Some(segment)
        };
        let commitment = Segmented::<H, L>::commit(&self.roots);
        Ok((commitment, self.roots, last))
    }
}

/// Erasure coding applied to fixed-size segments of the data, so that each segment's chunk of a
/// shard can be checked, forwarded, and decoded independently.
///
/// # Format
///
/// The data is split into consecutive segments of `L` bytes, where the last segment holds
/// between one and `L` bytes. Empty data is a single empty segment. Each segment is coded with
/// [`ReedSolomon`] under the same [`Config`], and shard `i` holds every segment root and the
/// `i`-th chunk of every segment.
///
/// The commitment is `H(namespace || L || S || root_0 || ... || root_{S-1})`, where the
/// namespace is `_COMMONWARE_CODING_SEGMENTED_COMMITMENT` and `L` and the segment count `S` are
/// big-endian `u64`s.
///
/// Changing `L` changes every commitment, so it is a protocol constant. It must be positive and
/// fit in a `u32`.
///
/// # Canonical Decoding
///
/// Each segment decodes under its own root with the [`ReedSolomon`] rules, and the decoded
/// segments must have the shape encoding produces. Every segment but the last holds exactly `L`
/// bytes, and the last holds one to `L` bytes (or none, when it is the only segment). A
/// commitment therefore decodes only to the data whose encoding produced it.
///
/// # Resource Usage
///
/// Each segment costs what [`ReedSolomon`] costs for `L` bytes. Reading a shard bounds the
/// segment count and each chunk's width by the maximum payload length, so callers that accept
/// shards from an untrusted source must bound that maximum and the shard counts as for
/// [`ReedSolomon`].
pub struct Segmented<H, const L: usize> {
    _marker: PhantomData<H>,
}

impl<H, const L: usize> Clone for Segmented<H, L> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<H, const L: usize> Copy for Segmented<H, L> {}

impl<H, const L: usize> Debug for Segmented<H, L> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Segmented")
            .field("segment_size", &L)
            .finish()
    }
}

impl<H: Hasher, const L: usize> Segmented<H, L> {
    /// Fails at compile time for segment sizes the format cannot represent.
    const VALID_SEGMENT_SIZE: () = assert!(
        L > 0 && L <= u32::MAX as usize,
        "segment size must be positive and fit in a u32"
    );

    /// Checks that a decoded segment has the length encoding gives segment `segment` of
    /// `count` segments.
    const fn check_shape(segment: usize, count: usize, len: usize) -> Result<(), Error> {
        let canonical = if segment + 1 < count {
            len == L
        } else {
            len <= L && (len > 0 || count == 1)
        };
        if canonical {
            Ok(())
        } else {
            Err(Error::NonCanonicalSegment {
                segment: segment as u16,
                len,
            })
        }
    }
}

impl<H: Hasher, const L: usize> Scheme for Segmented<H, L> {
    type Commitment = H::Digest;
    type Shard = SegmentedShard<H::Digest, L>;
    type CheckedShard = Vec<CheckedSegmentChunk<H>>;
    type Error = Error;

    /// Returns an upper bound on the encoded size of any shard [`Scheme::encode`] produces under
    /// `config` from at most `data` bytes.
    ///
    /// # Panics
    ///
    /// Panics if `data` bytes need more than `u16::MAX` segments, or if [`ReedSolomon`] cannot
    /// code a segment of `min(data, L)` bytes under `config`.
    fn max_shard_size(config: &Config, data: usize) -> usize {
        let segments = usize::from(Self::segments(data));
        max_items_size(segments, H::Digest::SIZE)
            + max_items_size(segments, Self::max_chunk_size(config, data))
    }

    fn encode(
        config: &Config,
        mut data: impl bytes::Buf,
        strategy: &impl Strategy,
    ) -> Result<(Self::Commitment, Vec<Self::Shard>), Self::Error> {
        let () = Self::VALID_SEGMENT_SIZE;
        let len = data.remaining();
        let count = usize::from(segment_count::<L>(len).ok_or(Error::InvalidSegmentCount(len))?);

        // Code every segment on its own, reusing the payload's storage for the segment views.
        let data = data.copy_to_bytes(len);
        let segments: Vec<Bytes> = (0..count)
            .map(|s| data.slice(s * L..((s + 1) * L).min(len)))
            .collect();
        let encoded = strategy
            .try_map_collect_vec(segments.into_iter().enumerate(), |(segment, data)| {
                encode_segment::<H, L>(config, segment as u16, data, strategy)
            })?;

        let roots: Vec<H::Digest> = encoded.iter().map(|segment| segment.root).collect();
        let shards = Self::assemble_shards(roots.clone(), encoded);
        Ok((Self::commit(&roots), shards))
    }

    fn check(
        config: &Config,
        commitment: &Self::Commitment,
        index: u16,
        shard: &Self::Shard,
        strategy: &impl Strategy,
    ) -> Result<Self::CheckedShard, Self::Error> {
        let (roots, chunks) = (&shard.roots, &shard.chunks);
        if roots.len() != chunks.len() {
            return Err(Error::ShapeMismatch {
                roots: roots.len(),
                chunks: chunks.len(),
            });
        }
        if roots.is_empty() || roots.len() > usize::from(u16::MAX) {
            return Err(Error::InvalidSegmentCount(roots.len()));
        }
        if Self::commit(roots) != *commitment {
            return Err(Error::CommitmentMismatch);
        }
        strategy.try_map_collect_vec(
            roots.iter().zip(chunks).enumerate(),
            |(segment, (root, chunk))| {
                Self::check_chunk(config, root, index, segment as u16, chunk)
            },
        )
    }

    /// Decodes the data from checked shards.
    ///
    /// The segment roots come from the checked chunks themselves, so the supplied shards must
    /// cover every segment and agree on each segment's root.
    fn decode<'a>(
        config: &Config,
        commitment: &Self::Commitment,
        shards: impl Iterator<Item = &'a Self::CheckedShard>,
        strategy: &impl Strategy,
    ) -> Result<Vec<u8>, Self::Error> {
        let chunks: Vec<&CheckedSegmentChunk<H>> = shards.flatten().collect();
        let mut roots: Vec<Option<H::Digest>> = Vec::new();
        for chunk in &chunks {
            let segment = usize::from(chunk.segment);
            if roots.len() <= segment {
                roots.resize(segment + 1, None);
            }
            match &roots[segment] {
                None => roots[segment] = Some(chunk.root),
                Some(root) if *root == chunk.root => {}
                Some(_) => return Err(Error::CommitmentMismatch),
            }
        }
        if roots.is_empty() {
            return Err(Error::ReedSolomon(RsError::NotEnoughChunks));
        }
        let roots = roots
            .into_iter()
            .enumerate()
            .map(|(segment, root)| root.ok_or(Error::MissingSegment(segment as u16)))
            .collect::<Result<Vec<_>, _>>()?;
        Self::decode_chunks(config, commitment, &roots, chunks.into_iter(), strategy)
    }
}

impl<H: Hasher, const L: usize> Segmentable for Segmented<H, L> {
    type Chunk = SegmentChunk<H::Digest, L>;
    type CheckedChunk = CheckedSegmentChunk<H>;
    type Encoder = SegmentEncoder<H, L>;

    /// # Panics
    ///
    /// Panics if `data` bytes need more than `u16::MAX` segments.
    fn segments(data: usize) -> u16 {
        let () = Self::VALID_SEGMENT_SIZE;
        segment_count::<L>(data).expect("segment count must fit in u16")
    }

    /// # Panics
    ///
    /// Panics if [`ReedSolomon`] cannot code a segment of `min(data, L)` bytes under `config`.
    fn max_chunk_size(config: &Config, data: usize) -> usize {
        let () = Self::VALID_SEGMENT_SIZE;
        ReedSolomon::<H>::max_shard_size(config, data.min(L))
    }

    fn split(shard: &Self::Shard) -> (Vec<Self::Commitment>, Vec<Self::Chunk>) {
        (shard.roots.clone(), shard.chunks.clone())
    }

    fn assemble(roots: Vec<Self::Commitment>, chunks: Vec<Self::Chunk>) -> Self::Shard {
        SegmentedShard { roots, chunks }
    }

    fn commit(roots: &[Self::Commitment]) -> Self::Commitment {
        let () = Self::VALID_SEGMENT_SIZE;
        commit_roots::<H>(L, roots)
    }

    fn check_chunk(
        config: &Config,
        root: &Self::Commitment,
        index: u16,
        segment: u16,
        chunk: &Self::Chunk,
    ) -> Result<Self::CheckedChunk, Self::Error> {
        let checked = ReedSolomon::<H>::check(config, root, index, &chunk.0, &Sequential)?;
        Ok(CheckedSegmentChunk {
            root: *root,
            index,
            segment,
            chunk: checked,
        })
    }

    fn decode_chunks<'a>(
        config: &Config,
        commitment: &Self::Commitment,
        roots: &[Self::Commitment],
        chunks: impl Iterator<Item = &'a Self::CheckedChunk>,
        strategy: &impl Strategy,
    ) -> Result<Vec<u8>, Self::Error> {
        let count = roots.len();
        if count == 0 || count > usize::from(u16::MAX) {
            return Err(Error::InvalidSegmentCount(count));
        }
        if Self::commit(roots) != *commitment {
            return Err(Error::CommitmentMismatch);
        }

        // Group chunks by segment, rejecting any chunk checked against a root other than its
        // segment's root in the commitment.
        let mut groups: Vec<Vec<&CheckedChunk<H>>> = vec![Vec::new(); count];
        for chunk in chunks {
            let segment = usize::from(chunk.segment);
            let group = groups
                .get_mut(segment)
                .ok_or(Error::InvalidSegment(chunk.segment))?;
            if chunk.root != roots[segment] {
                return Err(Error::CommitmentMismatch);
            }
            group.push(&chunk.chunk);
        }

        // Each segment decodes under its own root, then must have its canonical length.
        let segments = strategy.try_map_collect_vec(
            groups.into_iter().zip(roots).enumerate(),
            |(segment, (group, root))| {
                let data = ReedSolomon::<H>::decode(config, root, group.into_iter(), strategy)?;
                Self::check_shape(segment, count, data.len())?;
                Ok::<_, Error>(data)
            },
        )?;
        Ok(segments.concat())
    }

    fn encoder(config: Config) -> Self::Encoder {
        SegmentEncoder::new(config)
    }

    fn push(
        encoder: &mut Self::Encoder,
        bytes: &[u8],
        strategy: &impl Strategy,
    ) -> Result<Vec<EncodedSegment<Self::Commitment, Self::Chunk>>, Self::Error> {
        encoder.push(bytes, strategy)
    }

    fn finish(
        encoder: Self::Encoder,
        strategy: &impl Strategy,
    ) -> Result<FinishedEncoding<Self::Commitment, Self::Chunk>, Self::Error> {
        encoder.finish(strategy)
    }

    fn assemble_shards(
        roots: Vec<Self::Commitment>,
        segments: Vec<EncodedSegment<Self::Commitment, Self::Chunk>>,
    ) -> Vec<Self::Shard> {
        assert!(!segments.is_empty(), "at least one segment must be given");
        assert_eq!(
            roots.len(),
            segments.len(),
            "there must be one root per segment"
        );
        let total = segments[0].chunks.len();
        let mut columns: Vec<Vec<Self::Chunk>> = (0..total)
            .map(|_| Vec::with_capacity(segments.len()))
            .collect();
        for (position, segment) in segments.into_iter().enumerate() {
            assert_eq!(
                usize::from(segment.segment),
                position,
                "segments must be in order"
            );
            assert_eq!(
                segment.root, roots[position],
                "each segment must match its root"
            );
            assert_eq!(
                segment.chunks.len(),
                total,
                "every segment must hold the same number of chunks"
            );
            for (column, chunk) in columns.iter_mut().zip(segment.chunks) {
                column.push(chunk);
            }
        }
        columns
            .into_iter()
            .map(|chunks| SegmentedShard {
                roots: roots.clone(),
                chunks,
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::{Decode as _, Encode as _};
    use commonware_cryptography::Sha256;
    use commonware_invariants::minifuzz;
    use commonware_utils::NZU16;

    const L: usize = 64;
    type Seg = Segmented<Sha256, L>;
    type RS = ReedSolomon<Sha256>;
    type Digest = <Sha256 as Hasher>::Digest;

    /// Seven shards, any three of which decode.
    fn config() -> Config {
        Config {
            minimum_shards: NZU16!(3),
            extra_shards: NZU16!(4),
        }
    }

    /// A deterministic `len`-byte payload.
    fn data(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i * 31 + 7) as u8).collect()
    }

    /// Pushes `payload` in pieces of the given sizes, then the remainder as one last piece, and
    /// finishes. Returns the segment count of each push, the commitment, the segment roots, and
    /// every segment the encoder produced, in order.
    fn stream(
        payload: &[u8],
        pieces: &[usize],
    ) -> (Vec<usize>, Digest, Vec<Digest>, Vec<Segment<Digest, L>>) {
        // Push each piece and then the remainder, recording how many segments each push emits.
        let mut encoder = SegmentEncoder::<Sha256, L>::new(config());
        let mut segments = Vec::new();
        let mut counts = Vec::new();
        let mut offset = 0usize;
        for piece in pieces.iter().copied().chain([usize::MAX]) {
            let end = offset.saturating_add(piece).min(payload.len());
            let emitted = encoder.push(&payload[offset..end], &Sequential).unwrap();
            offset = end;
            counts.push(emitted.len());
            segments.extend(emitted);
        }

        // Finishing codes the final segment if pushes left bytes over or emitted nothing.
        let (commitment, roots, last) = encoder.finish(&Sequential).unwrap();
        segments.extend(last);
        (counts, commitment, roots, segments)
    }

    /// Asserts that streaming `payload` in `pieces` equals encoding it in one go.
    fn assert_streams_like_encode(payload: &[u8], pieces: &[usize]) {
        // Encode the payload in one go and by streaming.
        let (commitment, shards) = Seg::encode(&config(), payload, &Sequential).unwrap();
        let (_, streamed_commitment, roots, segments) = stream(payload, pieces);

        // Both produce the same commitment and segment roots.
        assert_eq!(streamed_commitment, commitment);
        assert_eq!(roots, shards[0].roots);
        assert_eq!(segments.len(), roots.len());

        // Each streamed segment is in order and carries the chunk every shard holds for it.
        for (position, segment) in segments.iter().enumerate() {
            assert_eq!(usize::from(segment.segment), position);
            assert_eq!(segment.root, roots[position]);
            for (chunk, shard) in segment.chunks.iter().zip(&shards) {
                assert_eq!(*chunk, shard.chunks[position]);
            }
        }

        // Assembling the streamed segments rebuilds the one-shot shards.
        assert_eq!(Seg::assemble_shards(roots, segments), shards);
    }

    /// Checks every shard at its own index.
    fn check_all(
        commitment: &Digest,
        shards: &[SegmentedShard<Digest, L>],
    ) -> Vec<Vec<CheckedSegmentChunk<Sha256>>> {
        shards
            .iter()
            .enumerate()
            .map(|(i, shard)| {
                Seg::check(&config(), commitment, i as u16, shard, &Sequential).unwrap()
            })
            .collect()
    }

    /// Codes each piece as its own segment, bypassing the canonical split of [`Segmented::encode`].
    fn forge(pieces: &[&[u8]]) -> (Digest, Vec<SegmentedShard<Digest, L>>) {
        let encoded: Vec<_> = pieces
            .iter()
            .map(|piece| RS::encode(&config(), *piece, &Sequential).unwrap())
            .collect();
        let roots: Vec<Digest> = encoded.iter().map(|(root, _)| *root).collect();
        let total = config().total_shards() as usize;
        let shards = (0..total)
            .map(|i| SegmentedShard {
                roots: roots.clone(),
                chunks: encoded
                    .iter()
                    .map(|(_, chunks)| SegmentChunk(chunks[i].clone()))
                    .collect(),
            })
            .collect();
        (Seg::commit(&roots), shards)
    }

    /// Encoding produces one segment per started `L` bytes, and one segment for empty data.
    #[test]
    fn segment_counts() {
        // Every shard of each length holds one root and one chunk per expected segment.
        for (len, expected) in [(0, 1), (1, 1), (L - 1, 1), (L, 1), (L + 1, 2), (3 * L, 3)] {
            assert_eq!(Seg::segments(len), expected, "len {len}");
            let (_, shards) = Seg::encode(&config(), data(len).as_slice(), &Sequential).unwrap();
            assert_eq!(shards.len(), config().total_shards() as usize);
            for shard in &shards {
                assert_eq!(shard.roots.len(), usize::from(expected));
                assert_eq!(shard.chunks.len(), usize::from(expected));
            }
        }
    }

    /// Each segment decodes from its own set of shard indices.
    #[test]
    fn decode_chunks_from_different_indices_per_segment() {
        // Encode a payload spanning six segments.
        let payload = data(5 * L + 10);
        let (commitment, shards) = Seg::encode(&config(), payload.as_slice(), &Sequential).unwrap();
        let (roots, _) = Seg::split(&shards[0]);
        assert_eq!(roots.len(), 6);

        // Segment s takes indices s, s + 2, and s + 5 (mod 7), so no index covers every segment.
        let total = config().total_shards() as usize;
        let mut checked = Vec::new();
        for (segment, root) in roots.iter().enumerate() {
            for offset in [0, 2, 5] {
                let index = (segment + offset) % total;
                let (_, chunks) = Seg::split(&shards[index]);
                checked.push(
                    Seg::check_chunk(
                        &config(),
                        root,
                        index as u16,
                        segment as u16,
                        &chunks[segment],
                    )
                    .unwrap(),
                );
            }
        }

        // The chunks decode against the segment roots, even in reverse order.
        let decoded = Seg::decode_chunks(
            &config(),
            &commitment,
            &roots,
            checked.iter().rev(),
            &Sequential,
        )
        .unwrap();
        assert_eq!(decoded, payload);

        // The same chunks also decode as one checked shard.
        let decoded = Seg::decode(&config(), &commitment, [checked].iter(), &Sequential).unwrap();
        assert_eq!(decoded, payload);
    }

    /// Decoding fails when a segment has no chunks.
    #[test]
    fn decode_chunks_rejects_missing_segment() {
        // Encode and check a three-segment payload.
        let (commitment, shards) =
            Seg::encode(&config(), data(3 * L).as_slice(), &Sequential).unwrap();
        let checked = check_all(&commitment, &shards);
        let (roots, _) = Seg::split(&shards[0]);

        // Without any chunk of segment 1, that segment cannot decode.
        let chunks = checked[..3]
            .iter()
            .flatten()
            .filter(|chunk| chunk.segment() != 1);
        assert!(matches!(
            Seg::decode_chunks(&config(), &commitment, &roots, chunks, &Sequential),
            Err(Error::ReedSolomon(RsError::NotEnoughChunks))
        ));

        // Without any chunk of the last segment, the roots derived from the chunks do not match
        // the commitment.
        let partial: Vec<Vec<_>> = checked[..3]
            .iter()
            .map(|shard| shard[..2].to_vec())
            .collect();
        assert!(matches!(
            Seg::decode(&config(), &commitment, partial.iter(), &Sequential),
            Err(Error::CommitmentMismatch)
        ));
    }

    /// A chunk counts only for the segment whose root it was checked against.
    #[test]
    fn chunk_checked_against_other_segment_is_rejected() {
        // Take shard 2 of a payload with distinct segment roots.
        let (commitment, shards) =
            Seg::encode(&config(), data(3 * L).as_slice(), &Sequential).unwrap();
        let (roots, chunks) = Seg::split(&shards[2]);
        assert_ne!(roots[0], roots[1]);

        // The proof of segment 0's chunk does not verify against segment 1's root.
        assert!(matches!(
            Seg::check_chunk(&config(), &roots[1], 2, 1, &chunks[0]),
            Err(Error::ReedSolomon(RsError::InvalidProof))
        ));

        // A chunk checked against segment 0's root but labeled with segment 1 fails decoding, as
        // does one labeled with a segment the commitment does not have.
        let checked = check_all(&commitment, &shards);
        let decode_with = |segment: u16| {
            let mislabeled =
                Seg::check_chunk(&config(), &roots[0], 2, segment, &chunks[0]).unwrap();
            let chunks = checked[3..6]
                .iter()
                .flatten()
                .chain(core::iter::once(&mislabeled));
            Seg::decode_chunks(&config(), &commitment, &roots, chunks, &Sequential)
        };
        assert!(matches!(decode_with(1), Err(Error::CommitmentMismatch)));
        assert!(matches!(decode_with(5), Err(Error::InvalidSegment(5))));
    }

    /// Shards and root lists with the wrong number of segments are rejected when checking,
    /// decoding, and reading.
    #[test]
    fn wrong_segment_count_is_rejected() {
        // Encode, check, and split a three-segment payload.
        let payload = data(3 * L);
        let (commitment, shards) = Seg::encode(&config(), payload.as_slice(), &Sequential).unwrap();
        let checked = check_all(&commitment, &shards);
        let (roots, chunks) = Seg::split(&shards[0]);

        // Dropping or duplicating a segment changes the commitment.
        let truncated = SegmentedShard {
            roots: roots[..2].to_vec(),
            chunks: chunks[..2].to_vec(),
        };
        let mut extended = shards[0].clone();
        extended.roots.push(roots[2]);
        extended.chunks.push(chunks[2].clone());
        for shard in [&truncated, &extended] {
            assert!(matches!(
                Seg::check(&config(), &commitment, 0, shard, &Sequential),
                Err(Error::CommitmentMismatch)
            ));
        }

        // Checking requires one chunk per root and at least one segment.
        let uneven = SegmentedShard {
            roots: roots.clone(),
            chunks: chunks[..2].to_vec(),
        };
        assert!(matches!(
            Seg::check(&config(), &commitment, 0, &uneven, &Sequential),
            Err(Error::ShapeMismatch {
                roots: 3,
                chunks: 2
            })
        ));
        let empty = SegmentedShard {
            roots: Vec::new(),
            chunks: Vec::new(),
        };
        assert!(matches!(
            Seg::check(&config(), &Seg::commit(&[]), 0, &empty, &Sequential),
            Err(Error::InvalidSegmentCount(0))
        ));

        // Decoding with a root list other than the committed one fails before any chunk is used.
        for roots in [&roots[..2], &[roots[0], roots[1], roots[2], roots[2]][..]] {
            assert!(matches!(
                Seg::decode_chunks(
                    &config(),
                    &commitment,
                    roots,
                    checked.iter().flatten(),
                    &Sequential
                ),
                Err(Error::CommitmentMismatch)
            ));
        }
        assert!(matches!(
            Seg::decode_chunks(
                &config(),
                &commitment,
                &[],
                checked.iter().flatten(),
                &Sequential
            ),
            Err(Error::InvalidSegmentCount(0))
        ));

        // Reading requires one chunk per root, at least one segment, and no more segments than
        // the maximum payload length needs.
        let cfg = (config(), payload.len());
        assert!(SegmentedShard::<Digest, L>::decode_cfg(extended.encode(), &cfg).is_err());
        assert!(SegmentedShard::<Digest, L>::decode_cfg(empty.encode(), &cfg).is_err());
        assert!(SegmentedShard::<Digest, L>::decode_cfg(uneven.encode(), &cfg).is_err());
        assert_eq!(
            SegmentedShard::<Digest, L>::decode_cfg(shards[0].encode(), &cfg).unwrap(),
            shards[0]
        );
        assert!(
            SegmentedShard::<Digest, L>::decode_cfg(shards[0].encode(), &(config(), 2 * L))
                .is_err()
        );
    }

    /// A commitment over segments that encoding would not produce checks but never decodes.
    #[test]
    fn non_canonical_segment_shape_is_rejected() {
        // Forging the canonical split reproduces the encoded commitment, for empty data too.
        let payload = data(L + 36);
        let (canonical, _) = forge(&[&payload[..L], &payload[L..]]);
        let (commitment, _) = Seg::encode(&config(), payload.as_slice(), &Sequential).unwrap();
        assert_eq!(canonical, commitment);
        let (empty, _) = forge(&[&[]]);
        let (commitment, _) = Seg::encode(&config(), &[][..], &Sequential).unwrap();
        assert_eq!(empty, commitment);

        // A short inner segment, an empty last segment, or an oversized last segment each pass
        // checking but fail decoding at that segment.
        let long = data(L + 1);
        let cases: [(&[&[u8]], u16); 4] = [
            (&[&payload[..32], &payload[32..]], 0),
            (&[&payload[..L], &[]], 1),
            (&[&payload[..L], &long], 1),
            (&[&long], 0),
        ];
        for (pieces, segment) in cases {
            let (commitment, shards) = forge(pieces);
            let checked = check_all(&commitment, &shards);
            let result = Seg::decode(&config(), &commitment, checked.iter(), &Sequential);
            assert!(
                matches!(result, Err(Error::NonCanonicalSegment { segment: s, .. }) if s == segment),
                "{result:?}"
            );
        }
    }

    /// Splitting a shard and assembling its parts returns the shard.
    #[test]
    fn split_assemble_roundtrip() {
        // Every shard splits into its own roots and chunks and reassembles unchanged.
        let (_, shards) = Seg::encode(&config(), data(2 * L + 5).as_slice(), &Sequential).unwrap();
        for shard in &shards {
            let (roots, chunks) = Seg::split(shard);
            assert_eq!(roots, shard.roots);
            assert_eq!(chunks, shard.chunks);
            assert_eq!(&Seg::assemble(roots, chunks), shard);
        }
    }

    /// The size bounds cover every encoded shard and chunk, and reading caps a chunk at the width
    /// of a coded `L`-byte segment.
    #[test]
    fn size_bounds_cover_encoded_shards_and_chunks() {
        // Every shard and chunk fits the bounds for its own length and for a larger maximum, and
        // each chunk reads back under that maximum.
        for len in [0, 1, L - 1, L, L + 1, 4 * L, 4 * L + 3] {
            let (_, shards) = Seg::encode(&config(), data(len).as_slice(), &Sequential).unwrap();
            for max in [len, len + 2 * L] {
                let shard_bound = Seg::max_shard_size(&config(), max);
                let chunk_bound = Seg::max_chunk_size(&config(), max);
                for shard in &shards {
                    assert!(
                        shard.encode_size() <= shard_bound,
                        "a shard of {len} bytes must fit the bound for {max} bytes"
                    );
                    for chunk in &shard.chunks {
                        assert!(
                            chunk.encode_size() <= chunk_bound,
                            "a chunk of {len} bytes must fit the bound for {max} bytes"
                        );
                        let decoded =
                            SegmentChunk::<Digest, L>::decode_cfg(chunk.encode(), &(config(), max))
                                .unwrap();
                        assert_eq!(decoded, *chunk);
                    }
                }
            }
        }

        // A chunk wider than a coded L-byte segment does not read, however large the payload.
        let (_, wide) = RS::encode(&config(), data(4 * L).as_slice(), &Sequential).unwrap();
        let wide = SegmentChunk::<Digest, L>(wide[0].clone());
        assert!(
            SegmentChunk::<Digest, L>::decode_cfg(wide.encode(), &(config(), 100 * L)).is_err()
        );
    }

    /// The commitment differs between segment sizes even when the segment roots match.
    #[test]
    fn commitment_binds_segment_size() {
        // Ten bytes fill one segment under either size, so only the hashed segment size differs.
        let payload = data(10);
        let (small, small_shards) =
            Segmented::<Sha256, L>::encode(&config(), payload.as_slice(), &Sequential).unwrap();
        let (large, large_shards) =
            Segmented::<Sha256, { 2 * L }>::encode(&config(), payload.as_slice(), &Sequential)
                .unwrap();
        assert_eq!(small_shards[0].roots, large_shards[0].roots);
        assert_ne!(small, large);
    }

    /// Streaming matches one-shot encoding for lengths around segment boundaries.
    #[test]
    fn streaming_matches_one_shot_at_segment_boundaries() {
        // Each length streams as one piece, with up to `3 * L` one-byte pushes followed by the
        // remainder, with empty pushes, and in pieces that cross segment boundaries.
        for len in [
            0,
            1,
            L - 1,
            L,
            L + 1,
            2 * L - 1,
            2 * L,
            2 * L + 1,
            5 * L + 9,
        ] {
            let payload = data(len);
            assert_streams_like_encode(&payload, &[]);
            assert_streams_like_encode(&payload, &[1; 3 * L]);
            assert_streams_like_encode(&payload, &[0, L, 0, 1]);
            assert_streams_like_encode(&payload, &[L - 1, 2, L]);
        }
    }

    /// Streaming matches one-shot encoding for random payloads split into random pieces.
    #[test]
    fn streaming_matches_one_shot_for_random_pushes() {
        minifuzz::test(|u| {
            // Draw a payload of up to six segments and up to 16 pieces, each shorter than three
            // segments.
            let len = usize::from(u.arbitrary::<u16>()?) % (6 * L + 1);
            let payload = u.bytes(len)?.to_vec();
            let mut pieces = Vec::new();
            while u.arbitrary::<bool>()? && pieces.len() < 16 {
                pieces.push(usize::from(u.arbitrary::<u8>()?) % (3 * L));
            }
            assert_streams_like_encode(&payload, &pieces);
            Ok(())
        });
    }

    /// A push returns exactly the segments its bytes complete.
    #[test]
    fn segments_are_emitted_when_complete() {
        // Pushes that complete no segment return none, and the rest return exactly the segments
        // they complete, in order.
        let payload = data(3 * L + 5);
        let mut encoder = SegmentEncoder::<Sha256, L>::new(config());
        let mut push = |range: std::ops::Range<usize>| {
            let emitted = encoder.push(&payload[range], &Sequential).unwrap();
            emitted.iter().map(|s| s.segment).collect::<Vec<_>>()
        };
        assert_eq!(push(0..0), Vec::<u16>::new());
        assert_eq!(push(0..L - 1), Vec::<u16>::new());
        assert_eq!(push(L - 1..L), vec![0]);
        assert_eq!(push(L..L + 1), Vec::<u16>::new());
        assert_eq!(push(L + 1..3 * L + 1), vec![1, 2]);
        assert_eq!(push(3 * L + 1..3 * L + 5), Vec::<u16>::new());

        // The partial last segment is only coded on finish.
        let (_, roots, last) = encoder.finish(&Sequential).unwrap();
        assert_eq!(roots.len(), 4);
        let last = last.unwrap();
        assert_eq!(last.segment, 3);
        assert_eq!(last.root, roots[3]);
    }

    /// Finishing codes a final segment only for leftover bytes or empty data.
    #[test]
    fn finish_codes_a_final_segment_only_when_bytes_remain() {
        // No bytes at all is one empty segment.
        let (counts, _, roots, segments) = stream(&[], &[]);
        assert_eq!(counts, [0]);
        assert_eq!((roots.len(), segments.len()), (1, 1));

        // Exactly L bytes are emitted by the push, leaving nothing to finish.
        let mut encoder = SegmentEncoder::<Sha256, L>::new(config());
        assert_eq!(encoder.push(&data(L), &Sequential).unwrap().len(), 1);
        let (_, roots, last) = encoder.finish(&Sequential).unwrap();
        assert_eq!(roots.len(), 1);
        assert!(last.is_none());

        // One byte more leaves a one-byte final segment.
        let mut encoder = SegmentEncoder::<Sha256, L>::new(config());
        assert_eq!(encoder.push(&data(L + 1), &Sequential).unwrap().len(), 1);
        let (_, roots, last) = encoder.finish(&Sequential).unwrap();
        assert_eq!(roots.len(), 2);
        assert_eq!(last.unwrap().segment, 1);
    }

    /// Shards assembled from streamed segments decode.
    #[test]
    fn streamed_shards_decode() {
        // Stream a payload, assemble its shards, and decode from shards 2, 3, and 4.
        let payload = data(4 * L + 17);
        let (_, commitment, roots, segments) = stream(&payload, &[L / 2, 3 * L]);
        let shards = Seg::assemble_shards(roots, segments);
        let checked: Vec<_> = check_all(&commitment, &shards)
            .into_iter()
            .skip(2)
            .collect();
        let decoded = Seg::decode(&config(), &commitment, checked.iter().take(3), &Sequential);
        assert_eq!(decoded.unwrap(), payload);
    }

    /// A push that would need more than `u16::MAX` segments fails without consuming its bytes.
    #[test]
    fn push_rejects_more_segments_than_addressable() {
        // One byte past the addressable limit fails.
        let mut encoder = SegmentEncoder::<Sha256, L>::new(config());
        let limit = usize::from(u16::MAX) * L;
        assert!(matches!(
            encoder.push(&vec![0; limit + 1], &Sequential),
            Err(Error::InvalidSegmentCount(len)) if len == limit + 1
        ));

        // Nothing was consumed, so the next segment is still the first.
        let emitted = encoder.push(&data(L), &Sequential).unwrap();
        assert_eq!(emitted.len(), 1);
        assert_eq!(emitted[0].segment, 0);
    }

    /// Assembling segments that hold different numbers of chunks panics.
    #[test]
    #[should_panic(expected = "every segment must hold the same number of chunks")]
    fn assemble_shards_rejects_ragged_segments() {
        // Dropping a chunk from the second segment makes assembly panic.
        let (_, _, roots, mut segments) = stream(&data(2 * L), &[]);
        segments[1].chunks.pop();
        let _ = Seg::assemble_shards(roots, segments);
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::*;
        use commonware_codec::conformance::CodecConformance;

        commonware_conformance::conformance_tests! {
            CodecConformance<SegmentChunk<Digest, L>>,
            CodecConformance<SegmentedShard<Digest, L>>,
        }
    }
}
