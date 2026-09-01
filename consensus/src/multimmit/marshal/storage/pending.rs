//! Shared temporary custody for producer blocks from every chain.
//!
//! Blocks and their compact metadata use aligned local positions within independently reclaimable
//! segments. The segment identifier and local position form one global append coordinate. A
//! durable manifest preserves that coordinate and each chain's logical prune floor across crashes.
//! Segment capacity bounds each journal's size; the journals do not need internal blob rotation.

use super::{
    archive::Shared,
    blocks::{BlockMeta, validated_reference},
};
use crate::{
    multimmit::{
        marshal::config::ArchiveConfig,
        types::{BlockRef, ChainId, Height, TransactionBlock, TransactionBlockHeader},
    },
    types::Epoch,
};
use bytes::BufMut;
use commonware_codec::{
    Buf, Codec, EncodeSize, Error as CodecError, FixedSize as _, RangeCfg, Read, ReadExt as _,
    Write, varint::MAX_U32_VARINT_SIZE,
};
use commonware_cryptography::{Digest, Digestible, Hasher, crc32};
use commonware_runtime::{Handle, ReadOptions};
use commonware_storage::{
    Context,
    journal::{
        self,
        contiguous::{Contiguous, Many, variable},
    },
    metadata::{self, Metadata},
    translator::Translator,
};
use commonware_utils::sequence::Unit;
use futures::{StreamExt as _, future::BoxFuture};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    future::Future,
    marker::PhantomData,
    num::{NonZeroU64, NonZeroUsize},
    sync::Arc,
};

type StoredBody<H, B> = Shared<TransactionBlock<H, B>>;
type BodyJournal<E, H, B> = variable::Journal<E, StoredBody<H, B>>;
type BodySnapshot<E, H, B> = variable::Reader<'static, E, StoredBody<H, B>>;
type MetadataJournal<E, H> = variable::Journal<E, BlockMeta<<H as Hasher>::Digest>>;

const STATE_VERSION: u8 = 2;
/// Bounds file descriptors and filesystem operations used by one segment I/O wave.
pub(in crate::multimmit::marshal) const BODY_READ_CONCURRENCY: usize = 16;

#[derive(Clone)]
struct PendingState {
    segment_capacity: u64,
    floors: Vec<Height>,
    segments: Vec<u64>,
}

#[derive(Clone, Copy)]
struct PendingStateCfg {
    chains: usize,
    max_segments: usize,
}

impl Read for PendingState {
    type Cfg = PendingStateCfg;

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        if u8::read(buf)? != STATE_VERSION {
            return Err(CodecError::Invalid("PendingState", "unsupported version"));
        }
        Ok(Self {
            segment_capacity: u64::read(buf)?,
            floors: Vec::<Height>::read_cfg(buf, &(RangeCfg::exact(cfg.chains), ()))?,
            segments: Vec::<u64>::read_cfg(buf, &(RangeCfg::from(0..=cfg.max_segments), ()))?,
        })
    }
}

impl Write for PendingState {
    fn write(&self, buf: &mut impl BufMut) {
        STATE_VERSION.write(buf);
        self.segment_capacity.write(buf);
        self.floors.write(buf);
        self.segments.write(buf);
    }
}

impl EncodeSize for PendingState {
    fn encode_size(&self) -> usize {
        STATE_VERSION.encode_size()
            + self.segment_capacity.encode_size()
            + self.floors.encode_size()
            + self.segments.encode_size()
    }
}

fn state_blob_size(state: &PendingState) -> Option<usize> {
    u64::SIZE
        .checked_add(Unit::SIZE)?
        .checked_add(state.encode_size())?
        .checked_add(crc32::Digest::SIZE)
}

struct Segment<E, H, B>
where
    E: Context,
    H: Hasher,
    B: Codec + Digestible<Digest = H::Digest>,
{
    bodies: BodyJournal<E, H, B>,
    metadata: MetadataJournal<E, H>,
}

/// Completed journal writes awaiting publication into the catalog's custody indexes.
pub(in crate::multimmit::marshal) struct Append<E, H, B>
where
    E: Context,
    H: Hasher,
    B: Codec + Digestible<Digest = H::Digest>,
{
    position: u64,
    rows: Vec<BlockMeta<H::Digest>>,
    segment: Segment<E, H, B>,
}

impl<E, H, B> Segment<E, H, B>
where
    E: Context,
    H: Hasher,
    B: Codec + Digestible<Digest = H::Digest>,
{
    /// Truncate an asymmetric crash tail and make the common local range authoritative before
    /// the segment can accept another append.
    async fn reconcile(self, capacity: u64) -> Result<(Self, u64), Error> {
        let body_bounds = self.bodies.bounds();
        let metadata_bounds = self.metadata.bounds();
        if body_bounds.start != 0 || metadata_bounds.start != 0 {
            return Err(Error::Inconsistent("pending segment was partially pruned"));
        }
        if body_bounds.end > capacity || metadata_bounds.end > capacity {
            return Err(Error::Inconsistent("pending segment exceeds its capacity"));
        }
        let common = body_bounds.end.min(metadata_bounds.end);
        if body_bounds.end == metadata_bounds.end {
            return Ok((self, common));
        }

        let Self { bodies, metadata } = self;
        let (bodies, metadata) = futures::try_join!(
            async move { bodies.rewind(common).await.map_err(Error::from) },
            async move { metadata.rewind(common).await.map_err(Error::from) },
        )?;
        let (bodies, metadata) = futures::try_join!(
            async move { bodies.sync().await.map_err(Error::from) },
            async move { metadata.sync().await.map_err(Error::from) },
        )?;
        Ok((Self { bodies, metadata }, common))
    }

    /// Starts one paired durability cut and freezes its body range for readers.
    async fn start_sync(self) -> Result<(Self, Vec<Handle<()>>, BodySnapshot<E, H, B>), Error> {
        let Self { bodies, metadata } = self;
        let ((bodies, body_handle), (metadata, metadata_handle)) = futures::try_join!(
            async move { bodies.start_sync().await.map_err(Error::from) },
            async move { metadata.start_sync().await.map_err(Error::from) },
        )?;
        let (bodies, reader) = bodies.snapshot().await?;
        Ok((
            Self { bodies, metadata },
            vec![body_handle, metadata_handle],
            reader,
        ))
    }

    /// Persists both journals' final recovery checkpoints and closes them. Must only run after
    /// the segment's final durability cut completed: the completed data syncs are reused, so
    /// only the checkpoint markers are written, and reopening then replays no frames.
    async fn retire(self) -> Result<(), Error> {
        let Self { bodies, metadata } = self;
        futures::try_join!(
            async move { bodies.sync().await.map_err(Error::from) },
            async move { metadata.sync().await.map_err(Error::from) },
        )?;
        Ok(())
    }
}

/// A pending block store failed or recovered inconsistent data.
#[derive(Debug, thiserror::Error)]
pub(in crate::multimmit::marshal) enum Error {
    /// An underlying journal operation failed.
    #[error(transparent)]
    Storage(#[from] journal::Error),
    /// Durable custody state could not be read or written.
    #[error(transparent)]
    State(#[from] metadata::Error),
    /// Durable indexes disagree about a block's identity.
    #[error("pending block store is inconsistent: {0}")]
    Inconsistent(&'static str),
}

#[derive(Clone)]
struct Entry<D: Digest> {
    position: u64,
    reference: BlockRef<D>,
    meta: BlockMeta<D>,
}

#[derive(Clone, Copy)]
pub(in crate::multimmit::marshal) struct BodyLocator<D: Digest> {
    position: u64,
    reference: BlockRef<D>,
    encoded_len: u64,
}

/// The inputs needed to open one shared snapshot for a segment without a resident reader.
pub(in crate::multimmit::marshal) struct ColdSource<E, H, B>
where
    E: Context,
    H: Hasher,
    B: Codec + Digestible<Digest = H::Digest>,
{
    context: E,
    config: variable::Config<B::Cfg>,
    segment: u64,
    segment_capacity: u64,
    _marker: PhantomData<H>,
}

impl<E, H, B> ColdSource<E, H, B>
where
    E: Context,
    H: Hasher,
    B: Codec + Digestible<Digest = H::Digest>,
    B::Cfg: Clone,
{
    /// Opens the segment's body journal through ordinary recovery and snapshots it. A retired
    /// segment's checkpoint covers its whole range, so opening replays no frames; crash residue
    /// replays only its unproven suffix and heals its checkpoint for the next open. The segment
    /// accepts no further appends, so the snapshot is immutable.
    pub(in crate::multimmit::marshal) async fn open(self) -> Result<BodyReader<E, H, B>, Error> {
        let journal = BodyJournal::init(self.context, self.config).await?;
        let bounds = journal.bounds();
        if bounds.start != 0 || bounds.end > self.segment_capacity {
            return Err(Error::Inconsistent(
                "pending body segment bounds are invalid",
            ));
        }
        let (journal, reader) = journal.snapshot().await?;
        drop(journal);
        Ok(BodyReader::new(
            self.segment,
            self.segment_capacity,
            reader,
            true,
        ))
    }
}

/// An immutable segment source. Ready sources borrow the catalog's frozen snapshot; cold sources
/// open one shared snapshot on demand.
pub(in crate::multimmit::marshal) enum BodySource<E, H, B>
where
    E: Context,
    H: Hasher,
    B: Codec + Digestible<Digest = H::Digest>,
{
    Ready(BodyReader<E, H, B>),
    Cold(ColdSource<E, H, B>),
}

impl<E, H, B> BodySource<E, H, B>
where
    E: Context,
    H: Hasher,
    B: Codec + Digestible<Digest = H::Digest>,
    B::Cfg: Clone,
{
    #[cfg(test)]
    pub(in crate::multimmit::marshal) async fn open(self) -> Result<BodyReader<E, H, B>, Error> {
        match self {
            Self::Ready(reader) => Ok(reader),
            Self::Cold(source) => source.open().await,
        }
    }
}

pub(in crate::multimmit::marshal) struct BodyReader<E, H, B>
where
    E: Context,
    H: Hasher,
    B: Codec + Digestible<Digest = H::Digest>,
{
    segment: u64,
    segment_capacity: u64,
    reader: Arc<BodySnapshot<E, H, B>>,
    /// Whether the segment's journals can no longer change: it is full or no longer current, so
    /// no append, rewind, or namespace reuse can touch the bytes this snapshot covers. Such
    /// segments are read through sequential replay rather than the page cache.
    immutable: bool,
}

impl<E, H, B> Clone for BodyReader<E, H, B>
where
    E: Context,
    H: Hasher,
    B: Codec + Digestible<Digest = H::Digest>,
{
    fn clone(&self) -> Self {
        Self {
            segment: self.segment,
            segment_capacity: self.segment_capacity,
            reader: Arc::clone(&self.reader),
            immutable: self.immutable,
        }
    }
}

impl<E, H, B> BodyReader<E, H, B>
where
    E: Context,
    H: Hasher,
    B: Codec + Digestible<Digest = H::Digest>,
{
    fn new(
        segment: u64,
        segment_capacity: u64,
        reader: BodySnapshot<E, H, B>,
        immutable: bool,
    ) -> Self {
        Self {
            segment,
            segment_capacity,
            reader: Arc::new(reader),
            immutable,
        }
    }

    pub(in crate::multimmit::marshal) const fn segment(&self) -> u64 {
        self.segment
    }

    /// Reads adjacent runs of strictly increasing local `positions` through one sequential
    /// replay each, so a run costs one batched physical read per `prefetch` budget instead of
    /// one page fault per cached page, and no page enters the software cache. Holes between
    /// runs are never decoded. `lengths` are the encoded body lengths at those positions.
    async fn replay_runs(
        &self,
        positions: &[u64],
        lengths: &[u64],
        prefetch: Prefetch,
    ) -> Result<Vec<StoredBody<H, B>>, Error> {
        let mut stored = Vec::with_capacity(positions.len());
        let mut start = 0;
        while start < positions.len() {
            let mut end = start + 1;
            while end < positions.len() && positions[end] == positions[end - 1] + 1 {
                end += 1;
            }
            let bytes = lengths[start..end].iter().fold(0u64, |total, len| {
                total
                    .saturating_add(*len)
                    .saturating_add(MAX_U32_VARINT_SIZE as u64)
            });
            let range = positions[start]..positions[end - 1] + 1;
            let items = self
                .reader
                .replay_range(
                    range.clone(),
                    prefetch.buffer(bytes),
                    ReadOptions::default(),
                )
                .await?;
            futures::pin_mut!(items);
            let mut expected = range.start;
            while let Some(item) = items.next().await {
                let (position, item) = item?;
                if position != expected {
                    return Err(Error::Inconsistent(
                        "pending body replay skipped a position",
                    ));
                }
                expected += 1;
                stored.push(item);
            }
            if expected != range.end {
                return Err(Error::Inconsistent("pending body replay ended early"));
            }
            start = end;
        }
        Ok(stored)
    }

    const fn local_position(&self, position: u64) -> Result<u64, Error> {
        let segment = position / self.segment_capacity;
        if segment != self.segment {
            return Err(Error::Inconsistent(
                "pending body locator names another segment",
            ));
        }
        Ok(position % self.segment_capacity)
    }

    fn contains(&self, position: u64) -> bool {
        self.local_position(position)
            .is_ok_and(|local| self.reader.bounds().contains(&local))
    }

    #[cfg(test)]
    pub(in crate::multimmit::marshal) async fn read(
        &self,
        locator: BodyLocator<H::Digest>,
    ) -> Result<Arc<TransactionBlock<H, B>>, Error> {
        let local = self.local_position(locator.position)?;
        let block = self.reader.read(local).await?.into_inner();
        validate_body(&block, locator)?;
        Ok(block)
    }
}

/// Physical read budget for one sequential replay of an immutable segment.
#[derive(Clone, Copy)]
struct Prefetch {
    /// Largest physical read for one replay fill.
    buffer: NonZeroUsize,
    /// Page size of the journal's blobs.
    page: u64,
}

impl Prefetch {
    /// Sizes the replay buffer for a run of `bytes`: the run is split into equal fills of at
    /// most `buffer` bytes, so each fill is one physical read and the last one prefetches at
    /// most two pages past the run.
    fn buffer(self, bytes: u64) -> NonZeroUsize {
        let fills = bytes.div_ceil(self.buffer.get() as u64).max(1);
        let fill = bytes.div_ceil(fills).saturating_add(2 * self.page);
        NonZeroUsize::new(usize::try_from(fill).unwrap_or(usize::MAX)).unwrap_or(self.buffer)
    }
}

/// One owned, single-segment materialization job. Entries retain their requested output indexes
/// and are sorted by storage position for one deduplicated batched journal read.
pub(in crate::multimmit::marshal) struct BodyReadGroup<E, H, B>
where
    E: Context,
    H: Hasher,
    B: Codec + Digestible<Digest = H::Digest>,
{
    source: BodySource<E, H, B>,
    entries: Vec<(usize, BodyLocator<H::Digest>)>,
    encoded_bytes: u64,
    prefetch: Prefetch,
}

impl<E, H, B> BodyReadGroup<E, H, B>
where
    E: Context,
    H: Hasher,
    B: Codec + Digestible<Digest = H::Digest>,
    B::Cfg: Clone,
{
    fn new(
        source: BodySource<E, H, B>,
        entries: Vec<(usize, BodyLocator<H::Digest>)>,
        prefetch: Prefetch,
    ) -> Result<Self, Error> {
        let encoded_bytes = Self::total_encoded_bytes(&entries)?;
        Ok(Self {
            source,
            entries,
            encoded_bytes,
            prefetch,
        })
    }

    pub(in crate::multimmit::marshal) const fn segment(&self) -> u64 {
        match &self.source {
            BodySource::Ready(reader) => reader.segment,
            BodySource::Cold(source) => source.segment,
        }
    }

    pub(in crate::multimmit::marshal) fn references(
        &self,
    ) -> impl Iterator<Item = BlockRef<H::Digest>> + '_ {
        self.entries.iter().map(|(_, locator)| locator.reference)
    }

    pub(in crate::multimmit::marshal) fn retain_references(
        &mut self,
        references: &BTreeSet<BlockRef<H::Digest>>,
    ) -> Result<bool, Error> {
        self.entries
            .retain(|(_, locator)| references.contains(&locator.reference));
        self.encoded_bytes = Self::total_encoded_bytes(&self.entries)?;
        Ok(!self.entries.is_empty())
    }

    fn total_encoded_bytes(entries: &[(usize, BodyLocator<H::Digest>)]) -> Result<u64, Error> {
        entries.iter().try_fold(0u64, |total, (_, locator)| {
            total
                .checked_add(locator.encoded_len)
                .ok_or(Error::Inconsistent("pending body read bytes overflow"))
        })
    }

    #[cfg(test)]
    pub(in crate::multimmit::marshal) async fn read(
        self,
    ) -> Result<Vec<(usize, Arc<TransactionBlock<H, B>>)>, Error> {
        let (source, read) = self.into_parts();
        read.read(source.open().await?).await
    }

    pub(in crate::multimmit::marshal) fn into_parts(self) -> (BodySource<E, H, B>, BodyRead<H>) {
        let segment = self.segment();
        (
            self.source,
            BodyRead {
                segment,
                entries: self.entries,
                encoded_bytes: self.encoded_bytes,
                prefetch: self.prefetch,
            },
        )
    }
}

/// An immutable batch that can share a segment reader with other batches.
pub(in crate::multimmit::marshal) struct BodyRead<H>
where
    H: Hasher,
{
    segment: u64,
    entries: Vec<(usize, BodyLocator<H::Digest>)>,
    encoded_bytes: u64,
    prefetch: Prefetch,
}

impl<H> BodyRead<H>
where
    H: Hasher,
{
    pub(in crate::multimmit::marshal) const fn encoded_bytes(&self) -> u64 {
        self.encoded_bytes
    }

    pub(in crate::multimmit::marshal) const fn segment(&self) -> u64 {
        self.segment
    }

    pub(in crate::multimmit::marshal) async fn read<E, B>(
        self,
        reader: BodyReader<E, H, B>,
    ) -> Result<Vec<(usize, Arc<TransactionBlock<H, B>>)>, Error>
    where
        E: Context,
        B: Codec + Digestible<Digest = H::Digest>,
    {
        let requests = self
            .entries
            .chunk_by(|(_, left), (_, right)| left.position == right.position);
        let positions = requests
            .clone()
            .map(|requests| reader.local_position(requests[0].1.position))
            .collect::<Result<Vec<_>, _>>()?;
        // An active snapshot's recent pages are hot in the page cache and its tail page may
        // still be rewritten beneath a raw replay, so only immutable segments replay.
        let stored = if reader.immutable {
            let lengths = requests
                .clone()
                .map(|requests| requests[0].1.encoded_len)
                .collect::<Vec<_>>();
            reader
                .replay_runs(&positions, &lengths, self.prefetch)
                .await?
        } else {
            reader.reader.read_many(&positions).await?
        };
        let mut results = Vec::new();
        for (requests, stored) in requests.zip(stored) {
            let block = stored.into_inner();
            for (output, locator) in requests {
                validate_body(&block, *locator)?;
                results.push((*output, Arc::clone(&block)));
            }
        }
        results.sort_unstable_by_key(|(output, _)| *output);
        Ok(results)
    }
}

/// Collects one segment's replayed compact-metadata rows.
async fn replay_rows<H: Hasher>(
    metadata: &impl Contiguous<Item = BlockMeta<H::Digest>>,
    buffer: NonZeroUsize,
) -> Result<Vec<(u64, BlockMeta<H::Digest>)>, journal::Error> {
    let rows = metadata.replay(0, buffer, ReadOptions::default()).await?;
    futures::pin_mut!(rows);
    let mut collected = Vec::new();
    while let Some(item) = rows.next().await {
        collected.push(item?);
    }
    Ok(collected)
}

fn validate_body<H, B>(
    block: &TransactionBlock<H, B>,
    locator: BodyLocator<H::Digest>,
) -> Result<(), Error>
where
    H: Hasher,
    B: Codec + Digestible<Digest = H::Digest>,
{
    let encoded_len = u64::try_from(block.encode_size())
        .map_err(|_| Error::Inconsistent("encoded block length exceeds u64"))?;
    if block.reference() != locator.reference || encoded_len != locator.encoded_len {
        return Err(Error::Inconsistent(
            "pending body does not match its locator",
        ));
    }
    Ok(())
}

/// Catalog-owned pending producer blocks from every chain.
pub(in crate::multimmit::marshal) struct PendingBlocks<T, E, H, B>
where
    T: Translator,
    E: Context,
    H: Hasher,
    B: Codec + Digestible<Digest = H::Digest>,
{
    context: E,
    archive: ArchiveConfig<T>,
    prefix: String,
    body_codec_config: B::Cfg,
    state: Option<Metadata<E, Unit, PendingState>>,
    state_dirty: bool,
    segments: BTreeSet<u64>,
    /// An occupied empty entry lends both journals to an append; absent entries are cold.
    open_segments: BTreeMap<u64, Option<Segment<E, H, B>>>,
    active_readers: BTreeMap<u64, BodyReader<E, H, B>>,
    dirty_segments: BTreeSet<u64>,
    /// Full segments whose lent-out journals are writing their final checkpoints. Their readers
    /// stay retained (so no cold open can race the write) and reclamation skips them until the
    /// retirement completes.
    retiring: BTreeSet<u64>,
    by_digest: HashMap<H::Digest, Entry<H::Digest>>,
    by_position: BTreeMap<u64, H::Digest>,
    by_chain: Vec<BTreeMap<Height, Vec<H::Digest>>>,
    next_position: u64,
    floors: Vec<Height>,
    segment_capacity: u64,
    max_state_bytes: NonZeroUsize,
    epoch: Epoch,
}

impl<T, E, H, B> PendingBlocks<T, E, H, B>
where
    T: Translator,
    E: Context,
    H: Hasher,
    B: Codec + Digestible<Digest = H::Digest>,
    B::Cfg: Clone,
{
    /// Opens aligned body and metadata journals and reconstructs indexes from metadata alone.
    #[allow(clippy::too_many_arguments)]
    pub(in crate::multimmit::marshal) async fn init(
        context: E,
        archive: ArchiveConfig<T>,
        prefix: String,
        body_codec_config: B::Cfg,
        epoch: Epoch,
        chains: usize,
        segment_capacity: NonZeroU64,
        max_state_bytes: NonZeroUsize,
    ) -> Result<Self, Error> {
        let state_cfg = PendingStateCfg {
            chains,
            max_segments: max_state_bytes.get() / u64::SIZE,
        };
        let mut state = Metadata::init(
            context.child("state"),
            metadata::Config {
                partition: format!("{prefix}_state"),
                codec_config: state_cfg,
            },
        )
        .await?;
        if state.get(&Unit).is_none() {
            state = state
                .put_sync(
                    Unit,
                    PendingState {
                        segment_capacity: segment_capacity.get(),
                        floors: vec![Height::zero(); chains],
                        segments: Vec::new(),
                    },
                )
                .await?;
        }
        let persisted = state
            .get(&Unit)
            .expect("pending state was initialized")
            .clone();
        if persisted.segment_capacity != segment_capacity.get() {
            return Err(Error::Inconsistent(
                "pending segment capacity differs from storage",
            ));
        }
        if persisted.segments.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(Error::Inconsistent(
                "pending segment manifest is not strictly ordered",
            ));
        }
        let mut store = Self {
            context,
            archive,
            prefix,
            body_codec_config,
            state: Some(state),
            state_dirty: false,
            segments: persisted.segments.iter().copied().collect(),
            open_segments: BTreeMap::new(),
            active_readers: BTreeMap::new(),
            dirty_segments: BTreeSet::new(),
            retiring: BTreeSet::new(),
            by_digest: HashMap::new(),
            by_position: BTreeMap::new(),
            by_chain: vec![BTreeMap::new(); chains],
            next_position: 0,
            floors: persisted.floors,
            segment_capacity: segment_capacity.get(),
            max_state_bytes,
            epoch,
        };

        let current = persisted.segments.last().copied();
        store.next_position = 0;
        for segment_id in persisted.segments {
            let segment_start = segment_id
                .checked_mul(store.segment_capacity)
                .ok_or(Error::Inconsistent("pending segment coordinate overflow"))?;

            // Every segment reopens through ordinary recovery. A retired segment's checkpoints
            // cover its whole range, so opening reads index metadata and no body bytes; the
            // current tail and crash residue replay only their unproven suffix and heal their
            // checkpoints for the next restart. Metadata is the sole recovery index: the
            // paired-size reconciliation proves that every replayed row has one body at the
            // same local position. Journals of non-current segments close once indexed.
            let segment = store.open_segment(segment_id).await?;
            let (segment, common_size) = segment.reconcile(store.segment_capacity).await?;
            let rows = replay_rows::<H>(&segment.metadata, store.archive.replay_buffer).await?;
            store.remember_rows(segment_start, rows, common_size)?;

            if Some(segment_id) == current {
                let Segment { bodies, metadata } = segment;
                let (bodies, reader) = bodies.snapshot().await?;
                store.active_readers.insert(
                    segment_id,
                    BodyReader::new(
                        segment_id,
                        store.segment_capacity,
                        reader,
                        common_size == store.segment_capacity,
                    ),
                );
                store.next_position = segment_start
                    .checked_add(common_size)
                    .ok_or(Error::Inconsistent("pending position overflow"))?;
                store
                    .open_segments
                    .insert(segment_id, Some(Segment { bodies, metadata }));
            }
        }
        let empty = store
            .segments
            .iter()
            .copied()
            .filter(|segment| Some(*segment) != current && !store.segment_has_live_blocks(*segment))
            .collect::<Vec<_>>();
        store.reclaim_segments(&empty).await?;
        if current.is_none() {
            store.ensure_segment(0).await?;
            store.persist_state().await?;
        }
        Ok(store)
    }

    const fn segment_id(&self, position: u64) -> u64 {
        position / self.segment_capacity
    }

    fn segment_has_live_blocks(&self, segment: u64) -> bool {
        let Some(start) = segment.checked_mul(self.segment_capacity) else {
            return false;
        };
        let end = start.saturating_add(self.segment_capacity - 1);
        self.by_position.range(start..=end).next().is_some()
    }

    fn segment_prefix(&self, family: &str, segment: u64) -> String {
        format!("{}_{family}_{segment}", self.prefix)
    }

    fn body_config(&self, segment: u64) -> variable::Config<B::Cfg> {
        variable::Config {
            partition: self.segment_prefix("bodies", segment),
            items_per_section: NonZeroU64::MAX,
            compression: None,
            codec_config: self.body_codec_config.clone(),
            page_cache: self.archive.page_cache.clone(),
            write_buffer: self.archive.value_write_buffer,
            replay_buffer: self.archive.replay_buffer,
        }
    }

    fn body_context(&self, segment: u64) -> E {
        self.context
            .child("bodies")
            .with_attribute("segment", segment)
    }

    fn metadata_context(&self, segment: u64) -> E {
        self.context
            .child("metadata")
            .with_attribute("segment", segment)
    }

    fn metadata_config(&self, segment: u64) -> variable::Config<()> {
        variable::Config {
            partition: self.segment_prefix("metadata", segment),
            items_per_section: NonZeroU64::MAX,
            compression: None,
            codec_config: (),
            page_cache: self.archive.page_cache.clone(),
            write_buffer: self.archive.key_write_buffer,
            replay_buffer: self.archive.replay_buffer,
        }
    }

    /// Absent manifest coordinates remove both journals' partitions before reuse, so residue from
    /// an interrupted destruction, however damaged, never enters recovery. Existing coordinates
    /// use authoritative recovery.
    fn open_segment(
        &self,
        segment: u64,
    ) -> impl Future<Output = Result<Segment<E, H, B>, Error>> + Send + use<T, E, H, B> {
        let body_context = self.body_context(segment);
        let body_config = self.body_config(segment);
        let metadata_context = self.metadata_context(segment);
        let metadata_config = self.metadata_config(segment);
        let exists = self.segments.contains(&segment);
        async move {
            let (bodies, metadata) = futures::try_join!(
                async move {
                    if !exists {
                        BodyJournal::<E, H, B>::destroy_partition(
                            &body_context,
                            &body_config.partition,
                        )
                        .await?;
                    }
                    BodyJournal::init(body_context, body_config).await
                },
                async move {
                    if !exists {
                        MetadataJournal::<E, H>::destroy_partition(
                            &metadata_context,
                            &metadata_config.partition,
                        )
                        .await?;
                    }
                    MetadataJournal::<E, H>::init(metadata_context, metadata_config).await
                },
            )?;
            Ok(Segment { bodies, metadata })
        }
    }

    fn state_snapshot(&self) -> Result<PendingState, Error> {
        let state = PendingState {
            segment_capacity: self.segment_capacity,
            floors: self.floors.clone(),
            segments: self.segments.iter().copied().collect(),
        };
        if state_blob_size(&state).is_none_or(|size| size > self.max_state_bytes.get()) {
            return Err(Error::Inconsistent(
                "pending state exceeds configured bound",
            ));
        }
        Ok(state)
    }

    fn stage_state(&mut self) -> Result<(), Error> {
        let state = self.state_snapshot()?;
        self.state
            .as_mut()
            .expect("catalog owns pending state")
            .put(Unit, state);
        self.state_dirty = true;
        Ok(())
    }

    async fn persist_state(&mut self) -> Result<(), Error> {
        let state = self.state_snapshot()?;
        let metadata = self.state.take().expect("catalog owns pending state");
        self.state = Some(metadata.put_sync(Unit, state).await?);
        self.state_dirty = false;
        Ok(())
    }

    async fn ensure_segment(&mut self, segment: u64) -> Result<(), Error> {
        if self.open_segments.contains_key(&segment) {
            return Ok(());
        }
        let exists = self.segments.contains(&segment);
        let opened = self.open_segment(segment).await?;
        self.open_segments.insert(segment, Some(opened));
        if exists {
            Ok(())
        } else {
            self.segments.insert(segment);
            self.stage_state()
        }
    }

    async fn reclaim_segments(&mut self, segments: &[u64]) -> Result<Vec<u64>, Error> {
        let current = self.segments.last().copied();
        let segments = segments
            .iter()
            .copied()
            .filter(|segment| Some(*segment) != current)
            .collect::<Vec<_>>();
        if segments.is_empty() {
            return Ok(segments);
        }
        if segments
            .iter()
            .any(|segment| !self.segments.contains(segment))
        {
            return Err(Error::Inconsistent("pending segment manifest changed"));
        }
        for segment in &segments {
            self.open_segments.remove(segment);
            self.active_readers.remove(segment);
            self.segments.remove(segment);
        }
        // The manifest stops naming each segment before physical destruction, so a crash during
        // destruction leaves only unreachable residue, which reuse removes. Retired contents
        // are removed by name: they are never reopened or replayed.
        self.persist_state().await?;
        for batch in segments.chunks(BODY_READ_CONCURRENCY) {
            futures::future::try_join_all(batch.iter().map(|&segment| {
                let context = &self.context;
                let bodies = self.segment_prefix("bodies", segment);
                let metadata = self.segment_prefix("metadata", segment);
                async move {
                    futures::try_join!(
                        BodyJournal::<E, H, B>::destroy_partition(context, &bodies),
                        MetadataJournal::<E, H>::destroy_partition(context, &metadata),
                    )?;
                    Ok::<_, Error>(())
                }
            }))
            .await?;
        }
        Ok(segments)
    }

    fn remember(&mut self, position: u64, meta: BlockMeta<H::Digest>) -> Result<(), Error> {
        let digest = meta.header().digest::<H>();
        let reference = validated_reference::<H>(&meta, digest, self.epoch, self.by_chain.len())
            .ok_or(Error::Inconsistent(
                "block metadata has an invalid identity",
            ))?;
        let chain = reference.chain().get() as usize;
        if reference.height() < self.floors[chain] {
            return Ok(());
        }
        if let Some(existing) = self.by_digest.get(&digest) {
            if existing.position != position
                || existing.reference != reference
                || existing.meta != meta
            {
                return Err(Error::Inconsistent(
                    "one digest names multiple pending blocks",
                ));
            }
            return Ok(());
        }
        if self.by_position.insert(position, digest).is_some() {
            return Err(Error::Inconsistent(
                "one pending position names multiple blocks",
            ));
        }
        self.by_chain[chain]
            .entry(reference.height())
            .or_default()
            .push(digest);
        self.by_digest.insert(
            digest,
            Entry {
                position,
                reference,
                meta,
            },
        );
        Ok(())
    }

    /// Rebuilds the in-memory indexes from one segment's replayed compact-metadata rows.
    fn remember_rows(
        &mut self,
        segment_start: u64,
        rows: Vec<(u64, BlockMeta<H::Digest>)>,
        bound: u64,
    ) -> Result<(), Error> {
        for (local, meta) in rows {
            if local >= bound {
                return Err(Error::Inconsistent(
                    "pending metadata exceeds the common segment range",
                ));
            }
            let position = segment_start
                .checked_add(local)
                .ok_or(Error::Inconsistent("pending position overflow"))?;
            self.remember(position, meta)?;
        }
        Ok(())
    }

    fn advance_floors(&mut self, floors: &[Option<Height>]) -> Result<bool, Error> {
        if floors.len() != self.by_chain.len() {
            return Err(Error::Inconsistent("pending prune chain count differs"));
        }
        let mut changed = false;
        for (chain, floor) in floors.iter().enumerate() {
            let Some(floor) = floor else { continue };
            let floor = (*floor).max(self.floors[chain]);
            if floor == self.floors[chain] {
                continue;
            }
            changed = true;
            self.floors[chain] = floor;
            let retained = self.by_chain[chain].split_off(&floor);
            let removed = std::mem::replace(&mut self.by_chain[chain], retained);
            for digest in removed.into_values().flatten() {
                if let Some(entry) = self.by_digest.remove(&digest) {
                    self.by_position.remove(&entry.position);
                }
            }
        }
        Ok(changed)
    }

    /// Returns the configured producer-chain count.
    pub(in crate::multimmit::marshal) const fn chain_count(&self) -> usize {
        self.by_chain.len()
    }

    /// Returns whether this reference remains eligible for temporary custody.
    pub(in crate::multimmit::marshal) fn admits(&self, reference: BlockRef<H::Digest>) -> bool {
        self.floors
            .get(reference.chain().get() as usize)
            .is_some_and(|floor| reference.height() >= *floor)
    }

    /// Buffers a complete block at one globally unique archive position.
    #[cfg(test)]
    pub(in crate::multimmit::marshal) async fn put(
        &mut self,
        reference: BlockRef<H::Digest>,
        block: Arc<TransactionBlock<H, B>>,
    ) -> Result<(), Error> {
        if let Some(append) = self.start_put(&mut [(reference, block)].into_iter())? {
            let append = append.await?;
            self.finish_put(append)?;
        }
        Ok(())
    }

    /// Consumes blocks through one segment boundary and lends its paired journals.
    /// Exact duplicates consume no positions; completed rows retain input order.
    ///
    /// Only immutable body reads may run until `finish_put` returns the journals. The occupied
    /// segment slot keeps an appendable segment from being mistaken for a cold immutable one.
    #[allow(clippy::type_complexity)]
    pub(in crate::multimmit::marshal) fn start_put(
        &mut self,
        blocks: &mut dyn Iterator<Item = (BlockRef<H::Digest>, Arc<TransactionBlock<H, B>>)>,
    ) -> Result<
        Option<impl Future<Output = Result<Append<E, H, B>, Error>> + Send + use<T, E, H, B>>,
        Error,
    > {
        let position = self.next_position;
        let segment_id = self.segment_id(position);
        let local = position % self.segment_capacity;
        let mut bodies = Vec::new();
        let mut rows = Vec::new();
        let mut seen = HashMap::new();
        while (rows.len() as u64) < self.segment_capacity - local {
            let Some((reference, block)) = blocks.next() else {
                break;
            };
            if !self.admits(reference) {
                return Err(Error::Inconsistent(
                    "pending block is outside the custody floor",
                ));
            }
            let digest = reference.digest();
            let meta = BlockMeta::new(
                block.header().clone(),
                u64::try_from(block.encode_size())
                    .map_err(|_| Error::Inconsistent("encoded block length exceeds u64"))?,
            );
            if block.reference() != reference
                || validated_reference::<H>(&meta, digest, self.epoch, self.by_chain.len())
                    != Some(reference)
            {
                return Err(Error::Inconsistent("pending block identity is invalid"));
            }
            if let Some(entry) = self.by_digest.get(&digest) {
                if entry.reference != reference || entry.meta != meta {
                    return Err(Error::Inconsistent("pending digest identity changed"));
                }
                continue;
            }
            if let Some(&index) = seen.get(&digest) {
                if rows[index] != meta {
                    return Err(Error::Inconsistent("pending digest identity changed"));
                }
                continue;
            }
            seen.insert(digest, rows.len());
            rows.push(meta);
            bodies.push(Shared::new(block));
        }
        if rows.is_empty() {
            return Ok(None);
        }
        let count = u64::try_from(rows.len())
            .map_err(|_| Error::Inconsistent("pending position overflow"))?;
        position
            .checked_add(count)
            .ok_or(Error::Inconsistent("pending position overflow"))?;
        let last = local + count - 1;
        let segment = self.open_segments.insert(segment_id, None);
        let opening = segment.is_none().then(|| self.open_segment(segment_id));
        Ok(Some(async move {
            let segment = match segment {
                Some(segment) => segment.expect("append owns pending segment"),
                None => opening.expect("a missing segment has open inputs").await?,
            };
            if segment.bodies.size() != local || segment.metadata.size() != local {
                return Err(Error::Inconsistent(
                    "pending journals do not match the append coordinate",
                ));
            }
            let Segment {
                bodies: body_journal,
                metadata,
            } = segment;
            let (bodies, metadata) = futures::try_join!(
                async {
                    body_journal
                        .append_many(Many::Flat(&bodies))
                        .await
                        .map_err(Error::from)
                },
                async {
                    metadata
                        .append_many(Many::Flat(&rows))
                        .await
                        .map_err(Error::from)
                },
            )?;
            if bodies.1 != last || metadata.1 != last {
                return Err(Error::Inconsistent(
                    "pending journals assigned different local positions",
                ));
            }
            Ok(Append {
                position,
                rows,
                segment: Segment {
                    bodies: bodies.0,
                    metadata: metadata.0,
                },
            })
        }))
    }

    /// Publishes one completed append; no other mutable operation may have intervened.
    pub(in crate::multimmit::marshal) fn finish_put(
        &mut self,
        append: Append<E, H, B>,
    ) -> Result<(), Error> {
        let Append {
            position,
            rows,
            segment,
        } = append;
        assert_eq!(position, self.next_position, "appends complete in order");
        let segment_id = self.segment_id(position);
        self.open_segments.insert(segment_id, Some(segment));
        if self.segments.insert(segment_id) {
            self.stage_state()?;
        }
        self.dirty_segments.insert(segment_id);
        for meta in rows {
            self.remember(self.next_position, meta)?;
            self.next_position += 1;
        }
        Ok(())
    }

    /// Starts one shared durability cut for every buffered producer block.
    pub(in crate::multimmit::marshal) async fn start_sync(
        &mut self,
    ) -> Result<Vec<Handle<()>>, Error> {
        let dirty = std::mem::take(&mut self.dirty_segments);
        let current = self.segments.last().copied();
        // Catalog starts a new admission cut only after the prior cut completes. Readers for its
        // full segments can now be dropped, except while a retirement is writing checkpoints (the
        // retained reader keeps every read off the journals the write still touches); externally
        // issued Arc snapshots remain valid.
        let retiring = &self.retiring;
        self.active_readers
            .retain(|segment, _| Some(*segment) == current || retiring.contains(segment));
        let mut cuts = Vec::with_capacity(dirty.len());
        for segment_id in dirty {
            let segment = self
                .open_segments
                .remove(&segment_id)
                .ok_or(Error::Inconsistent("dirty pending segment is missing"))?
                .expect("catalog owns pending segment");
            cuts.push(async move {
                let (segment, handles, reader) = segment.start_sync().await?;
                Ok::<_, Error>((segment_id, segment, handles, reader))
            });
        }

        let dirty_state = self.state_dirty;
        let state = dirty_state.then(|| self.state.take().expect("catalog owns pending state"));
        let (cuts, state) = futures::try_join!(futures::future::try_join_all(cuts), async move {
            let Some(state) = state else {
                return Ok::<_, Error>(None);
            };
            let (state, handle) = state.start_sync().await?;
            Ok(Some((state, handle)))
        },)?;

        let mut handles =
            Vec::with_capacity(cuts.len().saturating_mul(2) + usize::from(dirty_state));
        for (segment_id, segment, segment_handles, reader) in cuts {
            self.open_segments.insert(segment_id, Some(segment));
            handles.extend(segment_handles);
            let immutable = reader.bounds().end == self.segment_capacity;
            self.active_readers.insert(
                segment_id,
                BodyReader::new(segment_id, self.segment_capacity, reader, immutable),
            );
        }
        // A full segment's final cut is in flight: keep its journals until the cut completes so
        // start_retire can persist their final checkpoints.
        let capacity = self.segment_capacity;
        self.open_segments.retain(|segment, journals| {
            Some(*segment) == current
                || journals
                    .as_ref()
                    .expect("catalog owns pending segment")
                    .bodies
                    .size()
                    == capacity
        });
        if let Some((state, handle)) = state {
            self.state = Some(state);
            handles.push(handle);
        }
        self.state_dirty = false;
        Ok(handles)
    }

    /// Lends out the journals of full segments whose final admission cut completed so they can
    /// be retired off the admission path. Returns the retiring segments and one future per
    /// segment that persists its final checkpoints and closes it; the caller must hand the
    /// segments back through [`Self::finish_retire`] once every future completes.
    ///
    /// A dirty full segment holds appends its next cut has not yet covered, so it stays open
    /// and retires after that cut completes. Retirement is an optimization only: a crash before
    /// it completes leaves a segment whose next open replays its final cut and then heals its
    /// checkpoints itself.
    #[allow(clippy::type_complexity)]
    pub(in crate::multimmit::marshal) fn start_retire(
        &mut self,
    ) -> (Vec<u64>, Vec<BoxFuture<'static, Result<(), Error>>>) {
        let full = self
            .open_segments
            .iter()
            .filter(|(segment, journals)| {
                journals
                    .as_ref()
                    .expect("catalog owns pending segment")
                    .bodies
                    .size()
                    == self.segment_capacity
                    && !self.dirty_segments.contains(segment)
                    && !self.retiring.contains(segment)
            })
            .map(|(&segment, _)| segment)
            .collect::<Vec<_>>();
        let retirements = full
            .iter()
            .map(|segment_id| {
                let segment = self
                    .open_segments
                    .remove(segment_id)
                    .expect("full pending segment was just observed")
                    .expect("catalog owns pending segment");
                self.retiring.insert(*segment_id);
                Box::pin(segment.retire()) as BoxFuture<'static, Result<(), Error>>
            })
            .collect();
        (full, retirements)
    }

    /// Releases segments whose retirement completed: later opens replay nothing, so their
    /// retained readers drop and reclamation may destroy them once empty. Segments a
    /// concurrent prune skipped while retiring are reclaimed here (unless a cut is in flight,
    /// which defers them to the next reclamation), and the destroyed set is returned.
    pub(in crate::multimmit::marshal) async fn finish_retire(
        &mut self,
        segments: Vec<u64>,
        pinned: &BTreeSet<u64>,
    ) -> Result<Vec<u64>, Error> {
        let current = self.segments.last().copied();
        for segment in segments {
            self.retiring.remove(&segment);
            if Some(segment) != current {
                self.active_readers.remove(&segment);
            }
        }
        if !self.dirty_segments.is_empty() || self.state_dirty {
            return Ok(Vec::new());
        }
        self.reclaim_unpinned(pinned).await
    }

    /// Clones snapshots whose segments cannot accept another append.
    pub(in crate::multimmit::marshal) fn immutable_body_readers(&self) -> Vec<BodyReader<E, H, B>> {
        self.active_readers
            .values()
            .filter(|reader| reader.immutable)
            .cloned()
            .collect()
    }

    fn prefetch(&self) -> Prefetch {
        Prefetch {
            buffer: self.archive.replay_buffer,
            page: u64::from(self.archive.page_cache.page_size().get()),
        }
    }

    const fn locator(entry: &Entry<H::Digest>) -> BodyLocator<H::Digest> {
        BodyLocator {
            position: entry.position,
            reference: entry.reference,
            encoded_len: entry.meta.encoded_len(),
        }
    }

    fn body_source(&self, segment: u64) -> BodySource<E, H, B> {
        self.active_readers.get(&segment).map_or_else(
            || {
                BodySource::Cold(ColdSource {
                    context: self.body_context(segment),
                    config: self.body_config(segment),
                    segment,
                    segment_capacity: self.segment_capacity,
                    _marker: PhantomData,
                })
            },
            |reader| BodySource::Ready(reader.clone()),
        )
    }

    /// Plans bounded, immutable reads for exact locally stored references.
    ///
    /// Positions beyond the latest snapshot remain unavailable until their admission cut starts.
    /// Non-current segments are safe to open independently because they can no longer be
    /// appended. Each group contains positions from one segment in ascending order. Byte-safe groups are
    /// split to expose up to `max_groups` jobs. Groups do not exceed an equal share of `max_bytes`,
    /// except that one individually oversized block is admitted alone so reads can make progress.
    /// A block is never split.
    pub(in crate::multimmit::marshal) fn body_read_groups(
        &self,
        references: impl IntoIterator<Item = (usize, BlockRef<H::Digest>)>,
        max_bytes: u64,
        max_groups: usize,
    ) -> Result<Vec<BodyReadGroup<E, H, B>>, Error> {
        debug_assert!(max_bytes > 0);
        debug_assert!(max_groups > 0);
        let mut by_segment = BTreeMap::<u64, Vec<_>>::new();
        let mut total_entries = 0usize;
        for (output, reference) in references {
            let Some(entry) = self.by_digest.get(&reference.digest()) else {
                continue;
            };
            if entry.reference != reference {
                continue;
            }
            let segment = self.segment_id(entry.position);
            let readable = self
                .active_readers
                .get(&segment)
                .is_some_and(|reader| reader.contains(entry.position))
                || !self.open_segments.contains_key(&segment);
            if readable {
                total_entries = total_entries
                    .checked_add(1)
                    .ok_or(Error::Inconsistent("pending body read count overflow"))?;
                by_segment
                    .entry(segment)
                    .or_default()
                    .push((output, Self::locator(entry)));
            }
        }

        let budget_group_bytes = max_bytes
            .checked_div(u64::try_from(max_groups).unwrap_or(u64::MAX))
            .unwrap_or(0)
            .max(1);
        let mut byte_groups = Vec::new();
        for (segment, mut entries) in by_segment {
            entries.sort_unstable_by_key(|(_, locator)| locator.position);
            let mut chunk = Vec::new();
            let mut chunk_bytes = 0u64;
            for entry @ (_, locator) in entries {
                let next_bytes = chunk_bytes.checked_add(locator.encoded_len);
                if !chunk.is_empty() && next_bytes.is_none_or(|bytes| bytes > budget_group_bytes) {
                    byte_groups.push((segment, chunk_bytes, std::mem::take(&mut chunk)));
                    chunk_bytes = 0;
                }
                chunk_bytes = chunk_bytes
                    .checked_add(locator.encoded_len)
                    .ok_or(Error::Inconsistent("pending body read bytes overflow"))?;
                chunk.push(entry);
            }
            if !chunk.is_empty() {
                byte_groups.push((segment, chunk_bytes, chunk));
            }
        }

        let target_groups = max_groups.min(total_entries).max(byte_groups.len());
        let mut allocations = vec![1usize; byte_groups.len()];
        for _ in byte_groups.len()..target_groups {
            let index = (0..byte_groups.len())
                .filter(|&index| allocations[index] < byte_groups[index].2.len())
                .max_by_key(|&index| {
                    byte_groups[index]
                        .1
                        .div_ceil(u64::try_from(allocations[index]).unwrap_or(u64::MAX))
                })
                .expect("a body read group can be split toward its job target");
            allocations[index] += 1;
        }

        let mut groups = Vec::with_capacity(target_groups);
        for ((segment, mut remaining_bytes, entries), mut remaining_groups) in
            byte_groups.into_iter().zip(allocations)
        {
            let mut entries = entries.into_iter().peekable();
            let mut remaining_entries = entries.len();
            while remaining_groups > 0 {
                let target_bytes =
                    remaining_bytes.div_ceil(u64::try_from(remaining_groups).unwrap_or(u64::MAX));
                let mut chunk = Vec::new();
                let mut chunk_bytes = 0u64;
                while remaining_entries > remaining_groups - 1 {
                    let locator = &entries.peek().expect("a planned body entry exists").1;
                    let next_bytes = chunk_bytes.checked_add(locator.encoded_len);
                    if !chunk.is_empty() && next_bytes.is_none_or(|bytes| bytes > target_bytes) {
                        break;
                    }
                    chunk_bytes = next_bytes
                        .expect("a byte-safe body group cannot overflow its encoded length");
                    remaining_bytes = remaining_bytes
                        .checked_sub(locator.encoded_len)
                        .expect("a byte group covers its planned entries");
                    remaining_entries -= 1;
                    chunk.push(entries.next().expect("a peeked body read entry exists"));
                }
                groups.push(BodyReadGroup::new(
                    self.body_source(segment),
                    chunk,
                    self.prefetch(),
                )?);
                remaining_groups -= 1;
            }
        }
        Ok(groups)
    }

    /// Returns the exact pending reference named by a chain and header digest.
    pub(in crate::multimmit::marshal) fn reference_by_digest(
        &self,
        chain: ChainId,
        digest: H::Digest,
    ) -> Option<BlockRef<H::Digest>> {
        self.by_digest
            .get(&digest)
            .map(|entry| entry.reference)
            .filter(|reference| reference.chain() == chain)
    }

    #[cfg(test)]
    async fn read_live_body(
        &self,
        segment: u64,
        locator: BodyLocator<H::Digest>,
    ) -> Result<Arc<TransactionBlock<H, B>>, Error> {
        let local = locator.position % self.segment_capacity;
        let block = self
            .open_segments
            .get(&segment)
            .ok_or(Error::Inconsistent("active pending segment is missing"))?
            .as_ref()
            .expect("catalog owns pending segment")
            .bodies
            .read(local)
            .await?
            .into_inner();
        validate_body(&block, locator)?;
        Ok(block)
    }

    /// Returns a complete block only when its body survived storage recovery.
    #[cfg(test)]
    pub(in crate::multimmit::marshal) async fn block(
        &self,
        reference: BlockRef<H::Digest>,
    ) -> Result<Option<Arc<TransactionBlock<H, B>>>, Error> {
        let Some(entry) = self.by_digest.get(&reference.digest()) else {
            return Ok(None);
        };
        if entry.reference != reference {
            return Ok(None);
        }
        let segment = self.segment_id(entry.position);
        let locator = Self::locator(entry);
        if self
            .active_readers
            .get(&segment)
            .is_some_and(|reader| reader.contains(entry.position))
        {
            let reader = self.body_source(segment).open().await?;
            return reader.read(locator).await.map(Some);
        }
        if self.open_segments.contains_key(&segment) {
            return self.read_live_body(segment, locator).await.map(Some);
        }
        let reader = self.body_source(segment).open().await?;
        reader.read(locator).await.map(Some)
    }

    #[cfg(test)]
    async fn blocks(
        &self,
        references: &[BlockRef<H::Digest>],
    ) -> Result<Vec<Option<Arc<TransactionBlock<H, B>>>>, Error> {
        let groups = self.body_read_groups(references.iter().copied().enumerate(), u64::MAX, 1)?;
        let mut blocks = vec![None; references.len()];
        for (output, block) in
            futures::future::try_join_all(groups.into_iter().map(BodyReadGroup::read))
                .await?
                .into_iter()
                .flatten()
        {
            blocks[output] = Some(block);
        }
        Ok(blocks)
    }

    /// Returns compact metadata for a complete stored body.
    pub(in crate::multimmit::marshal) fn custody_meta(
        &self,
        reference: BlockRef<H::Digest>,
    ) -> Option<BlockMeta<H::Digest>> {
        self.by_digest
            .get(&reference.digest())
            .filter(|entry| entry.reference == reference)
            .map(|entry| entry.meta.clone())
    }

    /// Returns a recovered header from the common complete body/metadata range.
    pub(in crate::multimmit::marshal) fn header(
        &self,
        reference: BlockRef<H::Digest>,
    ) -> Option<TransactionBlockHeader<H::Digest>> {
        self.by_digest
            .get(&reference.digest())
            .filter(|entry| entry.reference == reference)
            .map(|entry| entry.meta.header().clone())
    }

    async fn reclaim_unpinned(&mut self, pinned: &BTreeSet<u64>) -> Result<Vec<u64>, Error> {
        let empty = self
            .segments
            .iter()
            .copied()
            .filter(|segment| {
                !pinned.contains(segment)
                    && !self.retiring.contains(segment)
                    && !self.segment_has_live_blocks(*segment)
            })
            .collect::<Vec<_>>();
        self.reclaim_segments(&empty).await
    }

    /// Reclaims chain-local heights below each supplied floor and returns destroyed segments.
    pub(in crate::multimmit::marshal) async fn prune(
        &mut self,
        floors: &[Option<Height>],
        pinned: &BTreeSet<u64>,
    ) -> Result<Vec<u64>, Error> {
        if !self.dirty_segments.is_empty() || self.state_dirty {
            return Err(Error::Inconsistent(
                "pending prune crossed a durability cut",
            ));
        }
        let changed = self.advance_floors(floors)?;

        // Floors become authoritative before reclamation, so recovery can filter dead metadata
        // after a crash. Only whole non-current segments are destroyed; local positions never
        // move, and the retained current journal continues to own the append cursor.
        if changed {
            self.persist_state().await?;
        }
        self.reclaim_unpinned(pinned).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{marshal::mocks::block::EmptyBlock, multimmit::marshal::config::ArchiveConfig};
    use commonware_cryptography::{Sha256, sha256::Digest as Sha256Digest};
    use commonware_runtime::{
        Metrics as _, Runner as _, Storage as _, Supervisor as _,
        buffer::paged::CacheRef,
        deterministic::{self, Context as DeterministicContext},
    };
    use commonware_storage::translator::TwoCap;
    use commonware_utils::{NZU16, NZU64, NZUsize};
    use rstest::rstest;

    type TestBody = EmptyBlock<Sha256>;
    type InnerTestStore = PendingBlocks<TwoCap, DeterministicContext, Sha256, TestBody>;

    struct TestStore(InnerTestStore);

    impl std::ops::Deref for TestStore {
        type Target = InnerTestStore;

        fn deref(&self) -> &Self::Target {
            &self.0
        }
    }

    impl std::ops::DerefMut for TestStore {
        fn deref_mut(&mut self) -> &mut Self::Target {
            &mut self.0
        }
    }

    impl TestStore {
        async fn put(
            &mut self,
            reference: BlockRef<Sha256Digest>,
            block: Arc<TransactionBlock<Sha256, TestBody>>,
        ) -> Result<(), Error> {
            Box::pin(self.0.put(reference, block)).await
        }

        async fn put_many(&mut self, blocks: &[Arc<TransactionBlock<Sha256, TestBody>>]) {
            Box::pin(async {
                let mut blocks = blocks
                    .iter()
                    .map(|block| (block.reference(), block.clone()))
                    .peekable();
                while blocks.peek().is_some() {
                    if let Some(append) = self.0.start_put(&mut blocks).unwrap() {
                        let append = Box::pin(append).await.unwrap();
                        self.0.finish_put(append).unwrap();
                    }
                }
            })
            .await
        }

        fn locator(entry: &Entry<Sha256Digest>) -> BodyLocator<Sha256Digest> {
            InnerTestStore::locator(entry)
        }
    }

    async fn open_with_capacity(
        context: &DeterministicContext,
        label: &'static str,
        prefix: &str,
        segment_capacity: NonZeroU64,
    ) -> TestStore {
        let config = ArchiveConfig::new(
            TwoCap,
            CacheRef::from_pooler(context, NZU16!(1024), NZUsize!(10)),
        );
        TestStore(
            Box::pin(InnerTestStore::init(
                context.child(label),
                config,
                prefix.to_string(),
                (),
                Epoch::new(7),
                2,
                segment_capacity,
                NZUsize!(1024 * 1024),
            ))
            .await
            .unwrap(),
        )
    }

    async fn open(context: &DeterministicContext, label: &'static str, prefix: &str) -> TestStore {
        open_with_capacity(context, label, prefix, NZU64!(2)).await
    }

    fn block(chain: u32, height: u64, nonce: u64) -> Arc<TransactionBlock<Sha256, TestBody>> {
        let body = TestBody::new(
            Sha256::hash(&[b"application parent"]),
            Height::new(height),
            nonce,
        );
        let header = TransactionBlockHeader::new(
            Epoch::new(7),
            ChainId::new(chain),
            Height::new(height),
            Sha256Digest::from([chain as u8; 32]),
            body.digest(),
        )
        .unwrap();
        Arc::new(TransactionBlock::new(header, body).unwrap())
    }

    /// One production-shaped durability round: the admission cut, then the retirements the
    /// catalog starts once the cut completes and releases once they finish.
    async fn sync(store: &mut TestStore) {
        futures::future::try_join_all(store.start_sync().await.unwrap())
            .await
            .unwrap();
        let (retiring, retirements) = store.start_retire();
        futures::future::try_join_all(retirements).await.unwrap();
        store
            .finish_retire(retiring, &BTreeSet::new())
            .await
            .unwrap();
    }

    /// Storage bytes read, writes, and syncs recorded so far.
    fn storage_io(context: &DeterministicContext) -> (u64, u64, u64) {
        let encoded = context.encode();
        (
            counter(&encoded, "storage_read_bytes"),
            counter(&encoded, "storage_writes"),
            counter(&encoded, "storage_syncs"),
        )
    }

    #[test]
    fn append_read_and_exact_idempotence() {
        deterministic::Runner::default().start(|context| async move {
            let block = block(0, 1, 1);
            let reference = block.reference();
            let mut store = open(&context, "store", "pending_append_read").await;
            store.put(reference, Arc::clone(&block)).await.unwrap();
            store.put(reference, Arc::clone(&block)).await.unwrap();
            assert_eq!(store.next_position, 1);
            let segment = store.open_segments.get(&0).unwrap().as_ref().unwrap();
            assert_eq!(segment.bodies.size(), 1);
            assert_eq!(segment.metadata.size(), 1);
            sync(&mut store).await;

            assert_eq!(
                store.block(reference).await.unwrap().as_deref(),
                Some(block.as_ref())
            );
            let blocks = store.blocks(&[reference, reference]).await.unwrap();
            assert_eq!(blocks[0].as_deref(), Some(block.as_ref()));
            assert_eq!(blocks[1].as_deref(), Some(block.as_ref()));

            let entry = store.by_digest.get(&reference.digest()).unwrap();
            let mut locator = TestStore::locator(entry);
            locator.encoded_len += 1;
            let reader = store.active_readers.get(&0).unwrap();
            assert!(reader.read(locator).await.is_err());
        });
    }

    #[test]
    fn batched_appends_match_single_rows_across_segments_and_reopen() {
        deterministic::Runner::default().start(|context| async move {
            let mut single =
                open_with_capacity(&context, "single", "pending_single", NZU64!(3)).await;
            let mut batch = open_with_capacity(&context, "batch", "pending_batch", NZU64!(3)).await;
            let blocks = (0..7)
                .map(|i| block((i % 2) as u32, i + 1, i))
                .collect::<Vec<_>>();
            for store in [&mut single, &mut batch] {
                store
                    .put(blocks[0].reference(), blocks[0].clone())
                    .await
                    .unwrap();
            }
            let input = [0, 1, 1, 2, 3, 3, 4, 5, 6, 6].map(|i| blocks[i].clone());
            for block in &input {
                single.put(block.reference(), block.clone()).await.unwrap();
            }
            batch.put_many(&[]).await;
            batch.put_many(&input).await;
            batch.put_many(&input).await;
            for store in [&mut single, &mut batch] {
                assert_eq!(store.next_position, blocks.len() as u64);
                for (&id, segment) in &store.open_segments {
                    let segment = segment.as_ref().unwrap();
                    let expected = (blocks.len() as u64 - id * 3).min(3);
                    assert_eq!(segment.bodies.size(), expected);
                    assert_eq!(segment.metadata.size(), expected);
                }
                sync(store).await;
            }
            let refs = blocks
                .iter()
                .map(|block| block.reference())
                .collect::<Vec<_>>();
            for reopened in [false, true] {
                if reopened {
                    drop(single);
                    drop(batch);
                    single =
                        open_with_capacity(&context, "single_reopen", "pending_single", NZU64!(3))
                            .await;
                    batch =
                        open_with_capacity(&context, "batch_reopen", "pending_batch", NZU64!(3))
                            .await;
                }
                assert_eq!(single.next_position, batch.next_position);
                assert_eq!(single.segments, batch.segments);
                for reference in &refs {
                    assert_eq!(single.header(*reference), batch.header(*reference));
                    assert_eq!(
                        single.by_digest[&reference.digest()].position,
                        batch.by_digest[&reference.digest()].position
                    );
                }
                let expected = blocks.iter().cloned().map(Some).collect::<Vec<_>>();
                assert_eq!(single.blocks(&refs).await.unwrap(), expected);
                assert_eq!(batch.blocks(&refs).await.unwrap(), expected);
            }
        });
    }

    #[test]
    fn owned_append_preserves_snapshot_and_publishes_only_on_completion() {
        deterministic::Runner::default().start(|context| async move {
            let mut store =
                open_with_capacity(&context, "store", "pending_owned_append", NZU64!(4)).await;
            let first = block(0, 1, 1);
            let second = block(0, 2, 2);
            let third = block(1, 1, 3);
            store.put(first.reference(), first.clone()).await.unwrap();
            sync(&mut store).await;

            let append = store
                .start_put(
                    &mut [&second, &second, &third]
                        .into_iter()
                        .map(|block| (block.reference(), block.clone())),
                )
                .unwrap()
                .unwrap();
            assert!(matches!(store.open_segments.get(&0), Some(None)));
            let refs = [
                (0, first.reference()),
                (1, second.reference()),
                (2, third.reference()),
            ];
            let mut groups = store.body_read_groups(refs, u64::MAX, 1).unwrap();
            assert_eq!(groups.len(), 1);
            assert_eq!(
                groups.pop().unwrap().read().await.unwrap(),
                vec![(0, first.clone())]
            );
            assert_eq!(store.next_position, 1);
            for block in [&second, &third] {
                assert!(!store.by_digest.contains_key(&block.reference().digest()));
            }

            let append = Box::pin(append).await.unwrap();
            for block in [&second, &third] {
                assert!(!store.by_digest.contains_key(&block.reference().digest()));
            }
            store.finish_put(append).unwrap();
            assert!(matches!(store.open_segments.get(&0), Some(Some(_))));
            assert_eq!(store.next_position, 3);
            for block in [&second, &third] {
                assert!(store.by_digest.contains_key(&block.reference().digest()));
            }
            assert!(
                store
                    .body_read_groups(
                        [(0, second.reference()), (1, third.reference())],
                        u64::MAX,
                        1
                    )
                    .unwrap()
                    .is_empty()
            );
            sync(&mut store).await;
            let values = store
                .blocks(&[first.reference(), second.reference(), third.reference()])
                .await
                .unwrap();
            assert_eq!(values, vec![Some(first), Some(second), Some(third)]);
        });
    }

    #[test]
    fn segment_rollover_does_not_rotate_inner_journals() {
        deterministic::Runner::default().start(|context| async move {
            let prefix = "pending_single_blob_segments";
            let mut store = open(&context, "store", prefix).await;
            let references = fill_first_segment(&mut store).await;

            for segment in 0..=1 {
                for family in ["bodies", "metadata"] {
                    for suffix in ["data", "offsets-blobs"] {
                        let partition = format!("{prefix}_{family}_{segment}_{suffix}");
                        assert_eq!(
                            context.scan(&partition).await.unwrap(),
                            vec![0u64.to_be_bytes().to_vec()],
                            "pending segments bound their journals: {partition}"
                        );
                    }
                }
            }

            drop(store);
            let mut store = open(&context, "reopened", prefix).await;
            for reference in references {
                assert_eq!(
                    store.block(reference).await.unwrap().unwrap().reference(),
                    reference
                );
            }
            let next = block(1, 2, 4);
            let reference = next.reference();
            store.put(reference, next).await.unwrap();
            sync(&mut store).await;
            assert_eq!(store.next_position, 4);
            assert_eq!(
                store.block(reference).await.unwrap().unwrap().reference(),
                reference
            );
        });
    }

    #[test]
    fn only_full_snapshots_are_exposed_as_immutable() {
        deterministic::Runner::default().start(|context| async move {
            let mut store = open(&context, "store", "pending_snapshot_bound").await;
            for height in 1..=5 {
                let block = block(0, height, height);
                store.put(block.reference(), block).await.unwrap();
            }

            // The completed cut is the catalog's offer point: every cut segment has a frozen
            // reader, and only the full ones are exposed as immutable.
            futures::future::try_join_all(store.start_sync().await.unwrap())
                .await
                .unwrap();
            assert_eq!(
                store.active_readers.keys().copied().collect::<Vec<_>>(),
                vec![0, 1, 2]
            );
            assert_eq!(
                store
                    .immutable_body_readers()
                    .iter()
                    .map(BodyReader::segment)
                    .collect::<Vec<_>>(),
                vec![0, 1]
            );

            // Readers stay retained while retirements are in flight, and drop once they finish.
            // Retirement reuses the completed cut's data syncs and writes only checkpoints.
            let (retiring, retirements) = store.start_retire();
            assert_eq!(retiring, vec![0, 1]);
            assert_eq!(
                store.active_readers.keys().copied().collect::<Vec<_>>(),
                vec![0, 1, 2]
            );
            assert_eq!(
                store.open_segments.keys().copied().collect::<Vec<_>>(),
                vec![2]
            );
            let (_, writes, syncs) = storage_io(&context);
            futures::future::try_join_all(retirements).await.unwrap();
            let (_, writes_after, syncs_after) = storage_io(&context);
            assert_eq!(
                writes_after - writes,
                4,
                "one checkpoint per retired journal"
            );
            assert_eq!(
                syncs_after - syncs,
                4,
                "no data fsync beyond the checkpoints"
            );
            store
                .finish_retire(retiring, &BTreeSet::new())
                .await
                .unwrap();
            assert_eq!(
                store.active_readers.keys().copied().collect::<Vec<_>>(),
                vec![2]
            );

            sync(&mut store).await;
            assert_eq!(
                store.active_readers.keys().copied().collect::<Vec<_>>(),
                vec![2]
            );
            assert!(store.immutable_body_readers().is_empty());
        });
    }

    #[test]
    fn retiring_segments_defer_reclamation_until_they_finish() {
        deterministic::Runner::default().start(|context| async move {
            let mut store = open(&context, "store", "pending_retiring_reclaim").await;
            for height in 1..=5 {
                let block = block(0, height, height);
                store.put(block.reference(), block).await.unwrap();
            }
            futures::future::try_join_all(store.start_sync().await.unwrap())
                .await
                .unwrap();
            let (retiring, retirements) = store.start_retire();
            assert_eq!(retiring, vec![0, 1]);

            // Pruning past every block must not destroy a segment whose checkpoints are still
            // being written; the retirement finishing reclaims the deferred segments itself.
            let reclaimed = store
                .prune(&[Some(Height::new(6)), None], &BTreeSet::new())
                .await
                .unwrap();
            assert!(reclaimed.is_empty());
            futures::future::try_join_all(retirements).await.unwrap();
            let reclaimed = store
                .finish_retire(retiring, &BTreeSet::new())
                .await
                .unwrap();
            assert_eq!(reclaimed, vec![0, 1]);
        });
    }

    #[test]
    fn asymmetric_prune_survives_reopen() {
        deterministic::Runner::default().start(|context| async move {
            let retained = block(0, 1, 1);
            let pruned = block(1, 1, 2);
            let also_pruned = block(1, 2, 3);
            let mut store = open(&context, "first", "pending_asymmetric").await;
            store
                .put(retained.reference(), Arc::clone(&retained))
                .await
                .unwrap();
            store
                .put(pruned.reference(), Arc::clone(&pruned))
                .await
                .unwrap();
            store
                .put(also_pruned.reference(), Arc::clone(&also_pruned))
                .await
                .unwrap();
            sync(&mut store).await;
            store
                .prune(&[None, Some(Height::new(3))], &BTreeSet::new())
                .await
                .unwrap();
            assert!(store.block(retained.reference()).await.unwrap().is_some());
            assert!(store.block(pruned.reference()).await.unwrap().is_none());
            assert!(
                store
                    .block(also_pruned.reference())
                    .await
                    .unwrap()
                    .is_none()
            );
            assert_eq!(
                store.segments.iter().copied().collect::<Vec<_>>(),
                vec![0, 1]
            );
            drop(store);

            let store = open(&context, "reopen", "pending_asymmetric").await;
            assert!(store.block(retained.reference()).await.unwrap().is_some());
            assert!(store.block(pruned.reference()).await.unwrap().is_none());
            assert!(
                store
                    .block(also_pruned.reference())
                    .await
                    .unwrap()
                    .is_none()
            );
            assert_eq!(
                store.segments.iter().copied().collect::<Vec<_>>(),
                vec![0, 1]
            );
        });
    }

    #[test]
    fn fully_pruned_store_keeps_its_append_coordinate() {
        deterministic::Runner::default().start(|context| async move {
            let first = block(0, 1, 1);
            let second = block(0, 2, 2);
            let mut store = open(&context, "first", "pending_empty").await;
            store
                .put(first.reference(), Arc::clone(&first))
                .await
                .unwrap();
            sync(&mut store).await;
            store
                .prune(&[Some(Height::new(2)), None], &BTreeSet::new())
                .await
                .unwrap();
            drop(store);

            let mut store = open(&context, "reopen", "pending_empty").await;
            assert_eq!(store.next_position, 1);
            store
                .put(second.reference(), Arc::clone(&second))
                .await
                .unwrap();
            sync(&mut store).await;
            drop(store);

            let store = open(&context, "second_reopen", "pending_empty").await;
            assert!(store.block(second.reference()).await.unwrap().is_some());
        });
    }

    #[test]
    fn durable_floor_precedes_physical_reclamation() {
        deterministic::Runner::default().start(|context| async move {
            let retained = block(0, 1, 1);
            let pruned = block(1, 1, 2);
            let mut store = open(&context, "first", "pending_prune_cut").await;
            store
                .put(retained.reference(), Arc::clone(&retained))
                .await
                .unwrap();
            store
                .put(pruned.reference(), Arc::clone(&pruned))
                .await
                .unwrap();
            sync(&mut store).await;

            assert!(store.advance_floors(&[None, Some(Height::new(2))]).unwrap());
            store.persist_state().await.unwrap();
            drop(store);

            let store = open(&context, "reopen", "pending_prune_cut").await;
            assert!(store.block(retained.reference()).await.unwrap().is_some());
            assert!(store.block(pruned.reference()).await.unwrap().is_none());
        });
    }

    #[test]
    fn snapshot_survives_prune_and_segment_destruction() {
        deterministic::Runner::default().start(|context| async move {
            let first = block(0, 1, 1);
            let second = block(0, 2, 2);
            let current = block(1, 1, 3);
            let first_ref = first.reference();
            let current_ref = current.reference();
            let mut store = open(&context, "store", "pending_snapshot_prune").await;
            store.put(first_ref, Arc::clone(&first)).await.unwrap();
            store.put(second.reference(), second).await.unwrap();
            sync(&mut store).await;
            let reader = store.active_readers.get(&0).unwrap().clone();
            let locator = TestStore::locator(store.by_digest.get(&first_ref.digest()).unwrap());

            store.put(current_ref, current).await.unwrap();
            sync(&mut store).await;
            let reclaimed = store
                .prune(&[Some(Height::new(3)), None], &BTreeSet::new())
                .await
                .unwrap();
            assert_eq!(reclaimed, vec![0]);
            assert!(!store.segments.contains(&0));
            assert_eq!(reader.read(locator).await.unwrap().reference(), first_ref);
            drop(store);

            let store = open(&context, "reopen", "pending_snapshot_prune").await;
            assert!(store.block(first_ref).await.unwrap().is_none());
            assert!(store.block(current_ref).await.unwrap().is_some());
        });
    }

    #[test]
    fn planned_cold_read_pins_segment_until_materialized() {
        deterministic::Runner::default().start(|context| async move {
            let first = block(0, 1, 1);
            let second = block(0, 2, 2);
            let current = block(1, 1, 3);
            let first_ref = first.reference();
            let mut store = open(&context, "store", "pending_pinned_read").await;
            store.put(first_ref, first).await.unwrap();
            store.put(second.reference(), second).await.unwrap();
            sync(&mut store).await;
            store.put(current.reference(), current).await.unwrap();
            sync(&mut store).await;

            let group = store
                .body_read_groups([(0, first_ref)], u64::MAX, 1)
                .unwrap()
                .pop()
                .unwrap();
            assert_eq!(group.segment(), 0);
            let reclaimed = store
                .prune(&[Some(Height::new(3)), None], &BTreeSet::from([0]))
                .await
                .unwrap();
            assert!(reclaimed.is_empty());
            assert!(store.segments.contains(&0));
            assert_eq!(group.read().await.unwrap()[0].1.reference(), first_ref);

            let reclaimed = store
                .prune(&[Some(Height::new(3)), None], &BTreeSet::new())
                .await
                .unwrap();
            assert_eq!(reclaimed, vec![0]);
            assert!(!store.segments.contains(&0));
        });
    }

    #[test]
    fn body_reads_fan_out_duplicate_positions_and_validate_each_locator() {
        deterministic::Runner::default().start(|context| async move {
            let mut store = open(&context, "store", "pending_duplicate_reads").await;
            let first = block(0, 1, 1);
            let second = block(0, 2, 2);
            for block in [&first, &second] {
                store
                    .put(block.reference(), Arc::clone(block))
                    .await
                    .unwrap();
            }
            sync(&mut store).await;

            let mut groups = store
                .body_read_groups(
                    [
                        (2, first.reference()),
                        (0, second.reference()),
                        (1, first.reference()),
                    ],
                    u64::MAX,
                    1,
                )
                .unwrap();
            assert_eq!(groups.len(), 1);
            assert_eq!(
                groups.pop().unwrap().read().await.unwrap(),
                vec![
                    (0, second),
                    (1, Arc::clone(&first)),
                    (2, Arc::clone(&first))
                ],
            );

            let mut group = store
                .body_read_groups(
                    [(0, first.reference()), (1, first.reference())],
                    u64::MAX,
                    1,
                )
                .unwrap()
                .pop()
                .unwrap();
            group.entries[1].1.encoded_len += 1;
            assert!(matches!(group.read().await, Err(Error::Inconsistent(_))));
        });
    }

    #[test]
    fn body_read_groups_preserve_contiguous_segment_run() {
        deterministic::Runner::default().start(|context| async move {
            let mut store =
                open_with_capacity(&context, "store", "pending_position_locality", NZU64!(8)).await;
            let blocks = (1..=6)
                .map(|height| block(0, height, height))
                .collect::<Vec<_>>();
            for block in &blocks {
                store
                    .put(block.reference(), Arc::clone(block))
                    .await
                    .unwrap();
            }
            sync(&mut store).await;

            let request_order = [0, 3, 1, 4, 2, 5];
            let groups = store
                .body_read_groups(
                    request_order
                        .into_iter()
                        .enumerate()
                        .map(|(output, block)| (output, blocks[block].reference())),
                    u64::MAX,
                    1,
                )
                .unwrap();
            let positions = groups
                .into_iter()
                .map(|group| {
                    group
                        .into_parts()
                        .1
                        .entries
                        .into_iter()
                        .map(|(_, locator)| locator.position)
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>();
            assert_eq!(positions, vec![vec![0, 1, 2, 3, 4, 5]]);
        });
    }

    #[test]
    fn body_read_groups_split_at_byte_and_segment_boundaries() {
        deterministic::Runner::default().start(|context| async move {
            let mut store =
                open_with_capacity(&context, "store", "pending_group_boundaries", NZU64!(3)).await;
            let blocks = (1..=7)
                .map(|height| block(0, height, height))
                .collect::<Vec<_>>();
            for block in &blocks {
                store
                    .put(block.reference(), Arc::clone(block))
                    .await
                    .unwrap();
            }
            sync(&mut store).await;

            let block_bytes = u64::try_from(blocks[0].encode_size()).unwrap();
            let max_bytes = block_bytes.checked_mul(2).unwrap();
            let request_order = [6, 2, 4, 1, 5, 0, 3];
            let groups = store
                .body_read_groups(
                    request_order
                        .into_iter()
                        .enumerate()
                        .map(|(output, block)| (output, blocks[block].reference())),
                    max_bytes,
                    1,
                )
                .unwrap();
            let groups = groups
                .into_iter()
                .map(|group| {
                    let (_, read) = group.into_parts();
                    (
                        read.segment(),
                        read.encoded_bytes(),
                        read.entries
                            .into_iter()
                            .map(|(_, locator)| locator.position)
                            .collect::<Vec<_>>(),
                    )
                })
                .collect::<Vec<_>>();
            assert_eq!(
                groups,
                vec![
                    (0, max_bytes, vec![0, 1]),
                    (0, block_bytes, vec![2]),
                    (1, max_bytes, vec![3, 4]),
                    (1, block_bytes, vec![5]),
                    (2, block_bytes, vec![6]),
                ]
            );
        });
    }

    #[test]
    fn body_read_groups_do_not_exceed_request_job_target() {
        deterministic::Runner::default().start(|context| async move {
            const MAX_GROUPS: usize = 16;
            let mut store =
                open_with_capacity(&context, "store", "pending_group_target", NZU64!(64)).await;
            let blocks = (1..=31)
                .map(|height| block(0, height, height))
                .collect::<Vec<_>>();
            for block in &blocks {
                store
                    .put(block.reference(), Arc::clone(block))
                    .await
                    .unwrap();
            }
            sync(&mut store).await;

            let block_bytes = u64::try_from(blocks[0].encode_size()).unwrap();
            let max_bytes = block_bytes
                .checked_mul(u64::try_from(MAX_GROUPS * 2).unwrap())
                .unwrap();
            let max_group_bytes = max_bytes / u64::try_from(MAX_GROUPS).unwrap();
            let groups = store
                .body_read_groups(
                    blocks
                        .iter()
                        .enumerate()
                        .map(|(output, block)| (output, block.reference())),
                    max_bytes,
                    MAX_GROUPS,
                )
                .unwrap();

            assert_eq!(groups.len(), MAX_GROUPS);
            assert!(
                groups
                    .iter()
                    .all(|group| group.encoded_bytes <= max_group_bytes)
            );
            assert_eq!(
                groups
                    .iter()
                    .map(|group| group.entries.len())
                    .collect::<Vec<_>>(),
                [vec![2; MAX_GROUPS - 1], vec![1]].concat()
            );
        });
    }

    #[test]
    fn body_read_groups_fill_byte_capacity_before_exceeding_job_target() {
        deterministic::Runner::default().start(|context| async move {
            const MAX_GROUPS: usize = 16;
            let mut store =
                open_with_capacity(&context, "store", "pending_variable_groups", NZU64!(64)).await;
            let blocks = (1..=48)
                .map(|height| block(0, height, height))
                .collect::<Vec<_>>();
            for block in &blocks {
                store
                    .put(block.reference(), Arc::clone(block))
                    .await
                    .unwrap();
            }
            sync(&mut store).await;

            for (index, block) in blocks.iter().enumerate() {
                let entry = store
                    .by_digest
                    .get_mut(&block.reference().digest())
                    .unwrap();
                entry.meta =
                    BlockMeta::new(entry.meta.header().clone(), if index < 46 { 1 } else { 5 });
            }
            let max_bytes = 160;
            let max_group_bytes = max_bytes / u64::try_from(MAX_GROUPS).unwrap();
            let groups = store
                .body_read_groups(
                    blocks
                        .iter()
                        .enumerate()
                        .map(|(output, block)| (output, block.reference())),
                    max_bytes,
                    MAX_GROUPS,
                )
                .unwrap();

            assert_eq!(groups.len(), MAX_GROUPS);
            assert!(
                groups
                    .iter()
                    .all(|group| group.encoded_bytes <= max_group_bytes)
            );
            assert_eq!(
                groups
                    .iter()
                    .map(|group| group.entries.len())
                    .sum::<usize>(),
                blocks.len()
            );
        });
    }

    #[test]
    fn body_read_groups_allow_one_oversized_body() {
        deterministic::Runner::default().start(|context| async move {
            let mut store = open(&context, "store", "pending_oversized_group").await;
            let block = block(0, 1, 1);
            let block_bytes = u64::try_from(block.encode_size()).unwrap();
            store
                .put(block.reference(), Arc::clone(&block))
                .await
                .unwrap();
            sync(&mut store).await;

            let groups = store
                .body_read_groups(
                    [(0, block.reference())],
                    block_bytes.checked_sub(1).unwrap(),
                    1,
                )
                .unwrap();
            assert_eq!(groups.len(), 1);
            let (_, read) = groups.into_iter().next().unwrap().into_parts();
            assert_eq!(read.encoded_bytes(), block_bytes);
            assert_eq!(read.entries.len(), 1);
        });
    }

    async fn partial_tail(
        context: &DeterministicContext,
        label: &'static str,
        prefix: &str,
        metadata_only: bool,
    ) {
        let retained = block(0, 1, 1);
        let retained_reference = retained.reference();
        let tail = [block(0, 2, 2), block(1, 1, 3)];
        let mut store = open_with_capacity(context, label, prefix, NZU64!(4)).await;
        store
            .put(retained_reference, Arc::clone(&retained))
            .await
            .unwrap();
        sync(&mut store).await;
        let mut segment = store.open_segments.get_mut(&0).unwrap().take().unwrap();
        if metadata_only {
            let metadata = segment.metadata;
            let rows = tail
                .iter()
                .map(|block| {
                    BlockMeta::new(
                        block.header().clone(),
                        u64::try_from(block.encode_size()).unwrap(),
                    )
                })
                .collect::<Vec<_>>();
            let (metadata, position) = metadata.append_many(Many::Flat(&rows)).await.unwrap();
            assert_eq!(position, 2);
            segment.metadata = metadata.sync().await.unwrap();
        } else {
            let bodies = segment.bodies;
            let rows = tail.iter().cloned().map(Shared::new).collect::<Vec<_>>();
            let (bodies, position) = bodies.append_many(Many::Flat(&rows)).await.unwrap();
            assert_eq!(position, 2);
            segment.bodies = bodies.sync().await.unwrap();
        }
        store.open_segments.insert(0, Some(segment));
        drop(store);

        let mut store = open_with_capacity(context, "partial_reopen", prefix, NZU64!(4)).await;
        assert_eq!(store.next_position, 1);
        assert_eq!(
            store.block(retained_reference).await.unwrap().as_deref(),
            Some(retained.as_ref())
        );
        for block in &tail {
            assert_eq!(store.header(block.reference()), None);
            assert!(store.block(block.reference()).await.unwrap().is_none());
        }
        let current = store.open_segments.get(&0).unwrap().as_ref().unwrap();
        assert_eq!(current.bodies.size(), 1);
        assert_eq!(current.metadata.size(), 1);
        store.put_many(&tail).await;
        sync(&mut store).await;
        for block in &tail {
            assert_eq!(
                store.block(block.reference()).await.unwrap().as_deref(),
                Some(block.as_ref())
            );
        }
    }

    #[test]
    fn asymmetric_partial_cuts_rewind_to_the_common_range() {
        deterministic::Runner::default().start(|context| async move {
            partial_tail(&context, "metadata_first", "pending_metadata_tail", true).await;
            partial_tail(&context, "body_first", "pending_body_tail", false).await;
        });
    }

    /// Durable journals for a segment the manifest never named are residue: reuse removes them
    /// by name first, so even residue recovery could not open does not block the store.
    #[rstest]
    fn unpublished_segment_is_reset_before_reuse(#[values(false, true)] corrupt: bool) {
        deterministic::Runner::default().start(|context| async move {
            let first = block(0, 1, 1);
            let second = block(0, 2, 2);
            let third = block(0, 3, 3);
            let mut store = open(&context, "first", "pending_unpublished_segment").await;
            for block in [&first, &second] {
                store
                    .put(block.reference(), Arc::clone(block))
                    .await
                    .unwrap();
            }
            sync(&mut store).await;
            store
                .put(third.reference(), Arc::clone(&third))
                .await
                .unwrap();
            let Segment { bodies, metadata } =
                store.open_segments.get_mut(&1).unwrap().take().unwrap();
            let (bodies, metadata) = futures::try_join!(bodies.sync(), metadata.sync()).unwrap();
            store
                .open_segments
                .insert(1, Some(Segment { bodies, metadata }));
            let partition = store.body_config(1).partition + "_data";
            drop(store);
            if corrupt {
                drop(context.open(&partition, b"invalid").await.unwrap());
            }

            let mut store = open(&context, "reopen", "pending_unpublished_segment").await;
            assert_eq!(store.segments.iter().copied().collect::<Vec<_>>(), vec![0]);
            assert_eq!(store.next_position, 2);
            assert_eq!(
                store.block(first.reference()).await.unwrap().as_deref(),
                Some(first.as_ref())
            );
            assert_eq!(
                store.block(second.reference()).await.unwrap().as_deref(),
                Some(second.as_ref())
            );
            assert!(store.block(third.reference()).await.unwrap().is_none());
            store
                .put(third.reference(), Arc::clone(&third))
                .await
                .unwrap();
            sync(&mut store).await;
            drop(store);

            let store = open(&context, "final", "pending_unpublished_segment").await;
            assert_eq!(
                store.block(third.reference()).await.unwrap().as_deref(),
                Some(third.as_ref())
            );
        });
    }

    #[test]
    fn below_floor_admission_is_rejected() {
        deterministic::Runner::default().start(|context| async move {
            let stale = block(0, 1, 1);
            let mut store = open(&context, "store", "pending_below_floor").await;
            store
                .prune(&[Some(Height::new(2)), None], &BTreeSet::new())
                .await
                .unwrap();

            assert!(store.put(stale.reference(), stale).await.is_err());
        });
    }

    /// Extract a metric counter's value from encoded metrics output.
    fn counter(buffer: &str, name: &str) -> u64 {
        buffer
            .lines()
            .find(|line| line.contains(name) && !line.starts_with('#'))
            .and_then(|line| line.split_whitespace().last())
            .and_then(|value| value.parse().ok())
            .expect("counter missing")
    }

    /// Buffers blocks that fill segment 0 and roll into segment 1.
    async fn put_first_segment(store: &mut TestStore) -> Vec<BlockRef<Sha256Digest>> {
        let blocks = [block(0, 1, 1), block(0, 2, 2), block(1, 1, 3)];
        let references = blocks.iter().map(|block| block.reference()).collect();
        for block in blocks {
            store.put(block.reference(), block).await.unwrap();
        }
        references
    }

    /// Fills segment 0, rolls into segment 1, and runs production-shaped durability rounds.
    async fn fill_first_segment(store: &mut TestStore) -> Vec<BlockRef<Sha256Digest>> {
        let references = put_first_segment(store).await;
        sync(store).await;
        // The next cut drops segment 0's admission-time reader, so later reads are cold.
        sync(store).await;
        references
    }

    /// Opens segment 0 cold and asserts the open wrote and synced nothing.
    async fn cold_open_without_writes(
        context: &DeterministicContext,
        store: &TestStore,
    ) -> BodyReader<DeterministicContext, Sha256, TestBody> {
        let (_, writes, syncs) = storage_io(context);
        let reader = store.body_source(0).open().await.unwrap();
        let (_, writes_after, syncs_after) = storage_io(context);
        assert_eq!(writes_after, writes, "a retired cold open must not write");
        assert_eq!(syncs_after, syncs, "a retired cold open must not sync");
        reader
    }

    #[test]
    fn retired_segment_cold_opens_without_replay_or_writes() {
        deterministic::Runner::default().start(|context| async move {
            let mut store = open(&context, "store", "pending_retired_cold").await;
            let references = fill_first_segment(&mut store).await;

            // The retired checkpoints cover the whole segment, so the open reads index
            // metadata only: no body replay, no rebuilt offsets, no checkpoint writes.
            let (read, _, _) = storage_io(&context);
            let reader = cold_open_without_writes(&context, &store).await;
            let (read_after, _, _) = storage_io(&context);
            let locator = TestStore::locator(store.by_digest.get(&references[0].digest()).unwrap());
            let body = locator.encoded_len;
            assert!(
                read_after - read < 2 * body + 6 * 1024,
                "cold open read {} bytes of index metadata for a {body}-byte body segment",
                read_after - read
            );
            assert_eq!(
                reader.read(locator).await.unwrap().reference(),
                references[0]
            );
        });
    }

    #[test]
    fn missing_checkpoint_recovers_and_heals_on_cold_open() {
        deterministic::Runner::default().start(|context| async move {
            let mut store = open(&context, "store", "pending_missing_checkpoint").await;
            let references = fill_first_segment(&mut store).await;

            // Destroy segment 0's body checkpoint (the offsets journal's recovery record).
            context
                .remove("pending_missing_checkpoint_bodies_0_offsets-metadata", None)
                .await
                .unwrap();

            // The cold open recovers authoritatively, serves exact bodies, and rewrites the
            // checkpoint, so the next open is write-free again.
            let reader = store.body_source(0).open().await.unwrap();
            let locator = TestStore::locator(store.by_digest.get(&references[1].digest()).unwrap());
            assert_eq!(
                reader.read(locator).await.unwrap().reference(),
                references[1]
            );
            drop(reader);
            cold_open_without_writes(&context, &store).await;
        });
    }

    #[test]
    fn dirty_full_segment_defers_its_retirement_to_the_covering_cut() {
        deterministic::Runner::default().start(|context| async move {
            let mut store = open(&context, "store", "pending_dirty_retire").await;
            let first = block(0, 1, 1);
            let filler = block(0, 2, 2);
            let next = block(1, 1, 3);
            let filler_reference = filler.reference();
            store.put(first.reference(), first).await.unwrap();
            let cut = store.start_sync().await.unwrap();
            // The segment fills while its first cut is still in flight, so its tail is not
            // covered by that cut.
            store.put(filler_reference, filler).await.unwrap();
            store.put(next.reference(), next).await.unwrap();
            futures::future::try_join_all(cut).await.unwrap();

            // The catalog retires on cut completion; the dirty tail defers this segment's
            // retirement and keeps its journals appendable for the covering cut.
            assert!(store.start_retire().0.is_empty());
            sync(&mut store).await;
            sync(&mut store).await;

            let reader = cold_open_without_writes(&context, &store).await;
            let locator =
                TestStore::locator(store.by_digest.get(&filler_reference.digest()).unwrap());
            assert_eq!(
                reader.read(locator).await.unwrap().reference(),
                filler_reference
            );
        });
    }

    #[test]
    fn unretired_full_segment_self_heals_on_reopen() {
        deterministic::Runner::default().start(|context| async move {
            let mut store = open(&context, "first", "pending_unretired_reopen").await;
            let references = put_first_segment(&mut store).await;
            // Crash window: the admission cut completes but the retirement never runs.
            futures::future::try_join_all(store.start_sync().await.unwrap())
                .await
                .unwrap();
            drop(store);

            // Startup replays the segment's unproven suffix and records its final checkpoints,
            // so the next cold open reads index metadata alone.
            let store = open(&context, "reopen", "pending_unretired_reopen").await;
            for reference in &references {
                assert!(store.block(*reference).await.unwrap().is_some());
            }
            cold_open_without_writes(&context, &store).await;
        });
    }

    #[test]
    fn immutable_segment_reads_replay_adjacent_runs() {
        deterministic::Runner::default().start(|context| async move {
            let mut store =
                open_with_capacity(&context, "store", "pending_replay_runs", NZU64!(4)).await;
            let blocks = (0..5)
                .map(|height| block(0, height + 1, height))
                .collect::<Vec<_>>();
            store.put_many(&blocks).await;
            sync(&mut store).await;
            sync(&mut store).await;
            assert!(!store.active_readers.contains_key(&0));

            // Positions 0, 1, and 3 of the retired segment: two adjacent runs, one hole. Each
            // run is one sequential replay, so the reads stay bounded by runs, not by pages.
            let reader = store.body_source(0).open().await.unwrap();
            assert!(reader.immutable);
            let requests = [
                blocks[3].reference(),
                blocks[0].reference(),
                blocks[1].reference(),
            ];
            let groups = store
                .body_read_groups(requests.iter().copied().enumerate(), u64::MAX, 1)
                .unwrap();
            assert_eq!(groups.len(), 1);
            let (_, read) = groups.into_iter().next().unwrap().into_parts();
            let reads = counter(&context.encode(), "storage_reads");
            let mut results = read.read(reader).await.unwrap();
            assert!(
                counter(&context.encode(), "storage_reads") - reads <= 4,
                "two runs must cost at most one index and one data read each"
            );
            results.sort_by_key(|(output, _)| *output);
            assert_eq!(results.len(), 3);
            for (output, block) in results {
                assert_eq!(block.reference(), requests[output]);
            }

            // The current segment stays on the cached snapshot path.
            let current = store.active_readers.get(&1).unwrap();
            assert!(!current.immutable);
            assert_eq!(
                store.block(blocks[4].reference()).await.unwrap().as_deref(),
                Some(blocks[4].as_ref())
            );
        });
    }

    #[test]
    fn reclaimed_segments_are_removed_by_name_without_reads() {
        deterministic::Runner::default().start(|context| async move {
            let mut store = open(&context, "store", "pending_reclaim_by_name").await;
            let references = fill_first_segment(&mut store).await;

            // Retired contents need not be recoverable, including malformed blob names.
            let partition = store.body_config(0).partition + "_data";
            drop(context.open(&partition, b"invalid").await.unwrap());
            let reads = counter(&context.encode(), "storage_reads");
            let reclaimed = store
                .prune(&[Some(Height::new(3)), None], &BTreeSet::new())
                .await
                .unwrap();
            assert_eq!(reclaimed, vec![0]);
            assert_eq!(counter(&context.encode(), "storage_reads"), reads);
            assert!(matches!(
                context.scan(&partition).await,
                Err(commonware_runtime::Error::PartitionMissing(_))
            ));
            drop(store);

            let store = open(&context, "reopen", "pending_reclaim_by_name").await;
            assert!(store.block(references[0]).await.unwrap().is_none());
            assert_eq!(
                store
                    .block(references[2])
                    .await
                    .unwrap()
                    .unwrap()
                    .reference(),
                references[2]
            );
        });
    }

    #[test]
    fn cold_segments_close_between_cuts() {
        deterministic::Runner::default().start(|context| async move {
            let first = block(0, 1, 1);
            let second = block(0, 2, 2);
            let third = block(1, 1, 3);
            let fourth = block(1, 2, 4);
            let fifth = block(0, 3, 5);
            let first_ref = first.reference();
            let second_ref = second.reference();
            let third_ref = third.reference();
            let mut store = open(&context, "store", "pending_cold_segments").await;

            store
                .put(first.reference(), Arc::clone(&first))
                .await
                .unwrap();
            store.put(second.reference(), second).await.unwrap();
            sync(&mut store).await;
            store.put(third.reference(), third).await.unwrap();
            store.put(fourth.reference(), fourth).await.unwrap();
            sync(&mut store).await;
            store.put(fifth.reference(), fifth).await.unwrap();
            sync(&mut store).await;

            assert_eq!(
                store.open_segments.keys().copied().collect::<Vec<_>>(),
                vec![2]
            );
            store.put(first_ref, Arc::clone(&first)).await.unwrap();
            assert_eq!(
                store.open_segments.keys().copied().collect::<Vec<_>>(),
                vec![2]
            );

            let blocks = store
                .blocks(&[first_ref, second_ref, third_ref])
                .await
                .unwrap();
            assert!(blocks.iter().all(Option::is_some));
            assert_eq!(
                store.open_segments.keys().copied().collect::<Vec<_>>(),
                vec![2]
            );

            store
                .prune(&[Some(Height::new(2)), None], &BTreeSet::new())
                .await
                .unwrap();
            assert!(store.block(first_ref).await.unwrap().is_none());
            assert!(store.block(second_ref).await.unwrap().is_some());
            assert_eq!(
                store.open_segments.keys().copied().collect::<Vec<_>>(),
                vec![2]
            );
        });
    }
}
