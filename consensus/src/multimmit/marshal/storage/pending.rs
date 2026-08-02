//! Shared temporary custody for producer blocks from every chain.
//!
//! Blocks and their compact metadata use aligned local positions within independently reclaimable
//! segments. The segment identifier and local position form one global append coordinate. A
//! durable manifest preserves that coordinate and each chain's logical prune floor across crashes.

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
use bytes::{Buf, BufMut};
use commonware_codec::{
    Codec, EncodeSize, Error as CodecError, FixedSize as _, RangeCfg, Read, ReadExt as _, Write,
};
use commonware_cryptography::{Digest, Digestible, Hasher, crc32};
use commonware_runtime::{Handle, telemetry::metrics::EncodeLabelValue};
use commonware_storage::{
    Context,
    journal::{
        self,
        contiguous::{Contiguous, variable},
    },
    metadata::{self, Metadata},
    translator::Translator,
};
use commonware_utils::sequence::Unit;
use futures::StreamExt as _;
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    marker::PhantomData,
    num::{NonZeroU64, NonZeroUsize},
    sync::Arc,
};
use tracing::debug;

type StoredBody<H, B> = Shared<TransactionBlock<H, B>>;
type BodyJournal<E, H, B> = variable::Journal<E, StoredBody<H, B>>;
type BodySnapshot<E, H, B> = variable::Reader<'static, E, StoredBody<H, B>>;
type MetadataJournal<E, H> = variable::Journal<E, BlockMeta<<H as Hasher>::Digest>>;
type MetadataSnapshot<E, H> = variable::Reader<'static, E, BlockMeta<<H as Hasher>::Digest>>;

const STATE_VERSION: u8 = 1;
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
    bodies: Option<BodyJournal<E, H, B>>,
    metadata: Option<MetadataJournal<E, H>>,
}

impl<E, H, B> Segment<E, H, B>
where
    E: Context,
    H: Hasher,
    B: Codec + Digestible<Digest = H::Digest>,
{
    const fn bodies(&self) -> &BodyJournal<E, H, B> {
        self.bodies.as_ref().expect("catalog owns pending bodies")
    }

    const fn metadata(&self) -> &MetadataJournal<E, H> {
        self.metadata
            .as_ref()
            .expect("catalog owns pending block metadata")
    }

    /// Truncate an asymmetric crash tail and make the common local range authoritative before
    /// the segment can accept another append.
    async fn reconcile(mut self, capacity: u64) -> Result<(Self, u64), Error> {
        let body_bounds = self.bodies().bounds();
        let metadata_bounds = self.metadata().bounds();
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

        let bodies = self.bodies.take().expect("catalog owns pending bodies");
        let metadata = self
            .metadata
            .take()
            .expect("catalog owns pending block metadata");
        let (bodies, metadata) = futures::try_join!(
            async move { bodies.rewind(common).await.map_err(Error::from) },
            async move { metadata.rewind(common).await.map_err(Error::from) },
        )?;
        let (bodies, metadata) = futures::try_join!(
            async move { bodies.sync().await.map_err(Error::from) },
            async move { metadata.sync().await.map_err(Error::from) },
        )?;
        self.bodies = Some(bodies);
        self.metadata = Some(metadata);
        Ok((self, common))
    }

    /// Starts one paired durability cut and freezes its body range for readers.
    async fn start_sync(mut self) -> Result<(Self, Vec<Handle<()>>, BodySnapshot<E, H, B>), Error> {
        let bodies = self.bodies.take().expect("catalog owns pending bodies");
        let metadata = self
            .metadata
            .take()
            .expect("catalog owns pending block metadata");
        let ((bodies, body_handle), (metadata, metadata_handle)) = futures::try_join!(
            async move { bodies.start_sync().await.map_err(Error::from) },
            async move { metadata.start_sync().await.map_err(Error::from) },
        )?;
        let (bodies, reader) = bodies.snapshot().await?;
        self.bodies = Some(bodies);
        self.metadata = Some(metadata);
        Ok((self, vec![body_handle, metadata_handle], reader))
    }

    /// Starts the paired durable seal proof (each journal's recovery watermark at the full
    /// segment size). Must only run after the segment's final durability cut completed.
    async fn start_seal(mut self) -> Result<(Self, Vec<Handle<()>>), Error> {
        let bodies = self.bodies.take().expect("catalog owns pending bodies");
        let metadata = self
            .metadata
            .take()
            .expect("catalog owns pending block metadata");
        let ((bodies, body_handle), (metadata, metadata_handle)) = futures::try_join!(
            async move { bodies.start_seal().await.map_err(Error::from) },
            async move { metadata.start_seal().await.map_err(Error::from) },
        )?;
        self.bodies = Some(bodies);
        self.metadata = Some(metadata);
        Ok((self, vec![body_handle, metadata_handle]))
    }

    async fn destroy(mut self) -> Result<(), Error> {
        let bodies = self.bodies.take().expect("catalog owns pending bodies");
        let metadata = self
            .metadata
            .take()
            .expect("catalog owns pending block metadata");
        futures::try_join!(
            async move { bodies.destroy().await.map_err(Error::from) },
            async move { metadata.destroy().await.map_err(Error::from) },
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

/// How a cold segment reader was produced. Doubles as the acquisition metric label.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, EncodeLabelValue)]
pub(in crate::multimmit::marshal) enum ColdOpen {
    /// The segment's durable sealed proof held, so opening read only index metadata.
    Sealed,
    /// The proof did not hold; one authoritative mutable recovery re-established it.
    Recovered,
}

/// The inputs needed to open one shared snapshot for a segment without a resident reader.
pub(in crate::multimmit::marshal) struct ColdSource<E, H, B>
where
    E: Context,
    H: Hasher,
    B: Codec + Digestible<Digest = H::Digest>,
{
    context: E,
    /// An equivalent context for the recovery fallback; contexts are not cloneable, and
    /// re-registering the same metric keys returns the existing handles.
    recovery_context: E,
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
    /// Opens the segment sealed-first: a sealed segment proves its exact durable size, so its
    /// reader opens from index metadata alone. A failed proof (a crash before the seal
    /// watermark landed, or a partially filled crash-residue segment) falls back to one
    /// authoritative recovery, which re-establishes the proof for the next open.
    pub(in crate::multimmit::marshal) async fn open(
        self,
    ) -> Result<(BodyReader<E, H, B>, ColdOpen), Error> {
        match BodyJournal::<E, H, B>::init_sealed(
            self.context,
            self.config.clone(),
            self.segment_capacity,
        )
        .await
        {
            Ok(reader) => {
                return Ok((
                    BodyReader::new(self.segment, self.segment_capacity, reader),
                    ColdOpen::Sealed,
                ));
            }
            Err(journal::Error::Unsealed(reason)) => {
                debug!(
                    segment = self.segment,
                    reason, "pending segment is not provably sealed"
                );
            }
            Err(error) => return Err(error.into()),
        }
        let journal = BodyJournal::init(self.recovery_context, self.config).await?;
        let bounds = journal.bounds();
        if bounds.start != 0 || bounds.end > self.segment_capacity {
            return Err(Error::Inconsistent(
                "pending body segment bounds are invalid",
            ));
        }
        let (journal, reader) = journal.snapshot().await?;
        drop(journal);
        Ok((
            BodyReader::new(self.segment, self.segment_capacity, reader),
            ColdOpen::Recovered,
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
    pub(in crate::multimmit::marshal) async fn open(
        self,
    ) -> Result<(BodyReader<E, H, B>, Option<ColdOpen>), Error> {
        match self {
            Self::Ready(reader) => Ok((reader, None)),
            Self::Cold(source) => {
                let (reader, cold) = source.open().await?;
                Ok((reader, Some(cold)))
            }
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
        }
    }
}

impl<E, H, B> BodyReader<E, H, B>
where
    E: Context,
    H: Hasher,
    B: Codec + Digestible<Digest = H::Digest>,
{
    fn new(segment: u64, segment_capacity: u64, reader: BodySnapshot<E, H, B>) -> Self {
        Self {
            segment,
            segment_capacity,
            reader: Arc::new(reader),
        }
    }

    pub(in crate::multimmit::marshal) const fn segment(&self) -> u64 {
        self.segment
    }

    fn is_sealed(&self) -> bool {
        self.reader.bounds() == (0..self.segment_capacity)
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

/// One owned, single-segment materialization job. Entries remain in requested output order while
/// storage positions are deduplicated into one batched journal read.
pub(in crate::multimmit::marshal) struct BodyReadGroup<E, H, B>
where
    E: Context,
    H: Hasher,
    B: Codec + Digestible<Digest = H::Digest>,
{
    source: BodySource<E, H, B>,
    entries: Vec<(usize, BodyLocator<H::Digest>)>,
    encoded_bytes: u64,
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
    ) -> Result<Self, Error> {
        let encoded_bytes = Self::total_encoded_bytes(&entries)?;
        Ok(Self {
            source,
            entries,
            encoded_bytes,
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
        let (reader, _) = source.open().await?;
        read.read(reader).await
    }

    pub(in crate::multimmit::marshal) fn into_parts(
        self,
    ) -> (BodySource<E, H, B>, BodyRead<H>) {
        let segment = self.segment();
        (
            self.source,
            BodyRead {
                segment,
                entries: self.entries,
                encoded_bytes: self.encoded_bytes,
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
        let mut by_local = BTreeMap::<u64, Vec<_>>::new();
        for (output, locator) in self.entries {
            by_local
                .entry(reader.local_position(locator.position)?)
                .or_default()
                .push((output, locator));
        }
        let positions = by_local.keys().copied().collect::<Vec<_>>();
        let stored = reader.reader.read_many(&positions).await?;
        let mut results = Vec::new();
        for ((_, requests), stored) in by_local.into_iter().zip(stored) {
            let block = stored.into_inner();
            for (output, locator) in requests {
                validate_body(&block, locator)?;
                results.push((output, Arc::clone(&block)));
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
    let rows = metadata.replay(0, buffer).await?;
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
    open_segments: BTreeMap<u64, Segment<E, H, B>>,
    active_readers: BTreeMap<u64, BodyReader<E, H, B>>,
    dirty_segments: BTreeSet<u64>,
    /// Segments whose durable seal proof is still being written. Their readers stay retained
    /// (so no cold open can race the write) and reclamation skips them until the proof lands.
    sealing: BTreeSet<u64>,
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
        let mut state = Metadata::init_bounded(
            context.child("state"),
            metadata::Config {
                partition: format!("{prefix}_state"),
                codec_config: state_cfg,
            },
            max_state_bytes,
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
            sealing: BTreeSet::new(),
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

            // Sealed segments prove their exact durable size, so their indexes rebuild from
            // read-only compact-metadata snapshots without opening mutable recovery or reading
            // any body bytes. Only the current tail and segments whose proof does not hold (a
            // crash before their seal landed) take the authoritative recovery path below, which
            // re-establishes the proof for the next restart.
            if Some(segment_id) != current {
                match store.open_sealed(segment_id).await {
                    Ok(metadata) => {
                        let rows = replay_rows::<H>(&metadata, store.archive.replay_buffer).await?;
                        store.remember_rows(segment_start, rows, store.segment_capacity)?;
                        continue;
                    }
                    Err(journal::Error::Unsealed(reason)) => {
                        debug!(
                            segment = segment_id,
                            reason, "recovering pending segment without a sealed proof"
                        );
                    }
                    Err(error) => return Err(error.into()),
                }
            }

            let segment = store.open_segment(segment_id).await?;
            let (mut segment, common_size) = segment.reconcile(store.segment_capacity).await?;

            // Metadata is the sole recovery index. The paired-size reconciliation proves that
            // every replayed row has one body at the same local position.
            let rows = replay_rows::<H>(segment.metadata(), store.archive.replay_buffer).await?;
            store.remember_rows(segment_start, rows, common_size)?;

            if Some(segment_id) == current {
                let bodies = segment.bodies.take().expect("catalog owns pending bodies");
                let (bodies, reader) = bodies.snapshot().await?;
                segment.bodies = Some(bodies);
                store.active_readers.insert(
                    segment_id,
                    BodyReader::new(segment_id, store.segment_capacity, reader),
                );
                store.next_position = segment_start
                    .checked_add(common_size)
                    .ok_or(Error::Inconsistent("pending position overflow"))?;
                store.open_segments.insert(segment_id, segment);
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
            items_per_section: NonZeroU64::new(self.segment_capacity)
                .expect("segment capacity is nonzero"),
            compression: None,
            codec_config: self.body_codec_config.clone(),
            page_cache: self.archive.page_cache.clone(),
            write_buffer: self.archive.value_write_buffer,
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

    async fn open_bodies(&self, segment: u64) -> Result<BodyJournal<E, H, B>, Error> {
        BodyJournal::init(self.body_context(segment), self.body_config(segment))
            .await
            .map_err(Error::from)
    }

    fn metadata_config(&self, segment: u64) -> variable::Config<()> {
        variable::Config {
            partition: self.segment_prefix("metadata", segment),
            items_per_section: NonZeroU64::new(self.segment_capacity)
                .expect("segment capacity is nonzero"),
            compression: None,
            codec_config: (),
            page_cache: self.archive.page_cache.clone(),
            write_buffer: self.archive.key_write_buffer,
        }
    }

    async fn open_segment(&self, segment: u64) -> Result<Segment<E, H, B>, Error> {
        let metadata = MetadataJournal::<E, H>::init(
            self.metadata_context(segment),
            self.metadata_config(segment),
        );
        let (bodies, metadata) = futures::try_join!(self.open_bodies(segment), async move {
            metadata.await.map_err(Error::from)
        })?;
        Ok(Segment {
            bodies: Some(bodies),
            metadata: Some(metadata),
        })
    }

    /// Opens a sealed segment's compact-metadata snapshot after proving both of its journals
    /// hold exactly one full segment durably. Fails with [`journal::Error::Unsealed`] when
    /// either proof does not hold, without repairing anything.
    async fn open_sealed(&self, segment: u64) -> Result<MetadataSnapshot<E, H>, journal::Error> {
        let bodies = BodyJournal::<E, H, B>::init_sealed(
            self.body_context(segment),
            self.body_config(segment),
            self.segment_capacity,
        );
        let metadata = MetadataJournal::<E, H>::init_sealed(
            self.metadata_context(segment),
            self.metadata_config(segment),
            self.segment_capacity,
        );
        let (_, metadata) = futures::try_join!(bodies, metadata)?;
        Ok(metadata)
    }

    /// Reset both journals together before an absent manifest coordinate is reused. This is the
    /// recovery path for residue left by an interrupted post-manifest segment destruction.
    async fn open_new_segment(&self, segment: u64) -> Result<Segment<E, H, B>, Error> {
        let bodies =
            BodyJournal::init_at_size(self.body_context(segment), self.body_config(segment), 0);
        let metadata = MetadataJournal::<E, H>::init_at_size(
            self.metadata_context(segment),
            self.metadata_config(segment),
            0,
        );
        let (bodies, metadata) = futures::try_join!(
            async move { bodies.await.map_err(Error::from) },
            async move { metadata.await.map_err(Error::from) },
        )?;
        Ok(Segment {
            bodies: Some(bodies),
            metadata: Some(metadata),
        })
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
        let opened = if exists {
            self.open_segment(segment).await?
        } else {
            self.open_new_segment(segment).await?
        };
        self.open_segments.insert(segment, opened);
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
        // The manifest stops naming each segment before physical destruction. A crash during
        // destroy can therefore leave only unreachable residue, which reuse resets to empty.
        self.persist_state().await?;
        for batch in segments.chunks(BODY_READ_CONCURRENCY) {
            futures::future::try_join_all(batch.iter().map(|&segment| {
                let bodies =
                    BodyJournal::init(self.body_context(segment), self.body_config(segment));
                let metadata = MetadataJournal::<E, H>::init(
                    self.metadata_context(segment),
                    self.metadata_config(segment),
                );
                async move {
                    let (bodies, metadata) = futures::try_join!(
                        async move { bodies.await.map_err(Error::from) },
                        async move { metadata.await.map_err(Error::from) },
                    )?;
                    Segment::<E, H, B> {
                        bodies: Some(bodies),
                        metadata: Some(metadata),
                    }
                    .destroy()
                    .await
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
    pub(in crate::multimmit::marshal) async fn put(
        &mut self,
        reference: BlockRef<H::Digest>,
        block: Arc<TransactionBlock<H, B>>,
    ) -> Result<(), Error> {
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
        match self.by_digest.get(&digest) {
            Some(entry) if entry.reference == reference && entry.meta == meta => return Ok(()),
            Some(_) => return Err(Error::Inconsistent("pending digest identity changed")),
            None => {}
        }

        let position = self.next_position;
        let segment_id = self.segment_id(position);
        let local = position % self.segment_capacity;
        self.ensure_segment(segment_id).await?;
        let segment = self
            .open_segments
            .get_mut(&segment_id)
            .expect("pending segment was ensured");
        if segment.bodies().size() != local || segment.metadata().size() != local {
            return Err(Error::Inconsistent(
                "pending journals do not match the append coordinate",
            ));
        }
        let bodies = segment.bodies.take().expect("catalog owns pending bodies");
        let metadata = segment
            .metadata
            .take()
            .expect("catalog owns pending block metadata");
        let stored_body = Shared::new(block);
        let (bodies, metadata) = futures::try_join!(
            async move { bodies.append(&stored_body).await.map_err(Error::from) },
            async { metadata.append(&meta).await.map_err(Error::from) },
        )?;
        if bodies.1 != local || metadata.1 != local {
            return Err(Error::Inconsistent(
                "pending journals assigned different local positions",
            ));
        }
        segment.bodies = Some(bodies.0);
        segment.metadata = Some(metadata.0);
        self.next_position = position
            .checked_add(1)
            .ok_or(Error::Inconsistent("pending position overflow"))?;
        self.dirty_segments.insert(segment_id);
        self.remember(position, meta)
    }

    /// Starts one shared durability cut for every buffered producer block.
    pub(in crate::multimmit::marshal) async fn start_sync(
        &mut self,
    ) -> Result<Vec<Handle<()>>, Error> {
        let dirty = std::mem::take(&mut self.dirty_segments);
        let current = self.segments.last().copied();
        // Catalog starts a new admission cut only after the prior cut completes. Readers for its
        // sealed segments can now be dropped, except while a seal proof is being written (the
        // retained reader keeps every read off the journals the write still touches); externally
        // issued Arc snapshots remain valid.
        let sealing = &self.sealing;
        self.active_readers
            .retain(|segment, _| Some(*segment) == current || sealing.contains(segment));
        let mut cuts = Vec::with_capacity(dirty.len());
        for segment_id in dirty {
            let segment = self
                .open_segments
                .remove(&segment_id)
                .ok_or(Error::Inconsistent("dirty pending segment is missing"))?;
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
            self.open_segments.insert(segment_id, segment);
            handles.extend(segment_handles);
            self.active_readers.insert(
                segment_id,
                BodyReader::new(segment_id, self.segment_capacity, reader),
            );
        }
        // A full segment's final cut is in flight: keep its journals until the cut completes so
        // start_seals can prove it sealed on disk.
        let capacity = self.segment_capacity;
        self.open_segments.retain(|segment, journals| {
            Some(*segment) == current || journals.bodies().size() == capacity
        });
        if let Some((state, handle)) = state {
            self.state = Some(state);
            handles.push(handle);
        }
        self.state_dirty = false;
        Ok(handles)
    }

    /// Starts durable seal proofs for full segments whose final admission cut completed, then
    /// releases their journals. Returns the sealing segments and their proof handles; the
    /// caller must hand the segments back through [`Self::finish_seals`] once every handle
    /// completes.
    ///
    /// A dirty full segment holds appends its next cut has not yet covered, so it stays open
    /// and seals after that cut completes. Sealing is an optimization only: a crash before a
    /// seal lands falls back to one authoritative recovery that re-establishes the proof. A
    /// full segment that is still current keeps its journals and re-proves idempotently until
    /// it rolls over.
    pub(in crate::multimmit::marshal) async fn start_seals(
        &mut self,
    ) -> Result<(Vec<u64>, Vec<Handle<()>>), Error> {
        let current = self.segments.last().copied();
        let full = self
            .open_segments
            .iter()
            .filter(|(segment, journals)| {
                journals.bodies().size() == self.segment_capacity
                    && !self.dirty_segments.contains(segment)
                    && !self.sealing.contains(segment)
            })
            .map(|(&segment, _)| segment)
            .collect::<Vec<_>>();
        let mut handles = Vec::new();
        for &segment_id in &full {
            let segment = self
                .open_segments
                .remove(&segment_id)
                .expect("full pending segment was just observed");
            let (segment, seal_handles) = segment.start_seal().await?;
            handles.extend(seal_handles);
            self.sealing.insert(segment_id);
            if Some(segment_id) == current {
                self.open_segments.insert(segment_id, segment);
            }
        }
        Ok((full, handles))
    }

    /// Releases segments whose durable seal proof landed: later opens use the proof, so their
    /// retained readers drop and reclamation may destroy them once empty. Segments a
    /// concurrent prune skipped while sealing are reclaimed here (unless a cut is in flight,
    /// which defers them to the next reclamation), and the destroyed set is returned.
    pub(in crate::multimmit::marshal) async fn finish_seals(
        &mut self,
        segments: Vec<u64>,
        pinned: &BTreeSet<u64>,
    ) -> Result<Vec<u64>, Error> {
        let current = self.segments.last().copied();
        for segment in segments {
            self.sealing.remove(&segment);
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
    pub(in crate::multimmit::marshal) fn sealed_body_readers(
        &self,
    ) -> Vec<BodyReader<E, H, B>> {
        self.active_readers
            .values()
            .filter(|reader| reader.is_sealed())
            .cloned()
            .collect()
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
            || BodySource::Cold(ColdSource {
                context: self.body_context(segment),
                recovery_context: self.body_context(segment),
                config: self.body_config(segment),
                segment,
                segment_capacity: self.segment_capacity,
                _marker: PhantomData,
            }),
            |reader| BodySource::Ready(reader.clone()),
        )
    }

    /// Plans bounded, immutable reads for exact locally stored references.
    ///
    /// Positions beyond the latest snapshot remain unavailable until their admission cut starts.
    /// Sealed segments are safe to open independently because they can no longer be appended.
    /// Exact encoded bytes are balanced toward `target_groups`, while `max_bytes` remains the
    /// batching ceiling. A block is never split, and segment boundaries may produce additional
    /// groups.
    pub(in crate::multimmit::marshal) fn body_read_groups(
        &self,
        references: impl IntoIterator<Item = (usize, BlockRef<H::Digest>)>,
        max_bytes: u64,
        target_groups: NonZeroUsize,
    ) -> Result<Vec<BodyReadGroup<E, H, B>>, Error> {
        debug_assert!(max_bytes > 0);
        let mut by_segment = BTreeMap::<u64, Vec<_>>::new();
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
                by_segment
                    .entry(segment)
                    .or_default()
                    .push((output, Self::locator(entry)));
            }
        }

        let total_bytes = by_segment
            .values()
            .flatten()
            .try_fold(0u64, |total, (_, locator)| {
                total
                    .checked_add(locator.encoded_len)
                    .ok_or(Error::Inconsistent("pending body read bytes overflow"))
            })?;
        let target_groups = u64::try_from(target_groups.get()).unwrap_or(u64::MAX);
        let max_bytes = max_bytes.min(total_bytes.div_ceil(target_groups).max(1));
        let mut groups = Vec::new();
        for (segment, mut entries) in by_segment {
            entries.sort_unstable_by_key(|(_, locator)| locator.position);
            let mut chunk = Vec::new();
            let mut chunk_bytes = 0u64;
            for entry @ (_, locator) in entries {
                if !chunk.is_empty()
                    && chunk_bytes
                        .checked_add(locator.encoded_len)
                        .is_none_or(|bytes| bytes > max_bytes)
                {
                    groups.push(BodyReadGroup::new(
                        self.body_source(segment),
                        std::mem::take(&mut chunk),
                    )?);
                    chunk_bytes = 0;
                }
                chunk_bytes = chunk_bytes
                    .checked_add(locator.encoded_len)
                    .ok_or(Error::Inconsistent("pending body read bytes overflow"))?;
                chunk.push(entry);
            }
            if !chunk.is_empty() {
                groups.push(BodyReadGroup::new(self.body_source(segment), chunk)?);
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
            .bodies()
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
            let (reader, _) = self.body_source(segment).open().await?;
            return reader.read(locator).await.map(Some);
        }
        if self.open_segments.contains_key(&segment) {
            return self.read_live_body(segment, locator).await.map(Some);
        }
        let (reader, _) = self.body_source(segment).open().await?;
        reader.read(locator).await.map(Some)
    }

    #[cfg(test)]
    async fn blocks(
        &self,
        references: &[BlockRef<H::Digest>],
    ) -> Result<Vec<Option<Arc<TransactionBlock<H, B>>>>, Error> {
        let groups = self.body_read_groups(
            references.iter().copied().enumerate(),
            u64::MAX,
            NonZeroUsize::MIN,
        )?;
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
                    && !self.sealing.contains(segment)
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

    type TestBody = EmptyBlock<Sha256>;
    type TestStore = PendingBlocks<TwoCap, DeterministicContext, Sha256, TestBody>;

    async fn open(context: &DeterministicContext, label: &'static str, prefix: &str) -> TestStore {
        let config = ArchiveConfig::new(
            TwoCap,
            CacheRef::from_pooler(context, NZU16!(1024), NZUsize!(10)),
        );
        TestStore::init(
            context.child(label),
            config,
            prefix.to_string(),
            (),
            Epoch::new(7),
            2,
            NZU64!(2),
            NZUsize!(1024 * 1024),
        )
        .await
        .unwrap()
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

    /// One production-shaped durability round: the admission cut, then the seal proofs the
    /// catalog starts once the cut completes and releases once they land.
    async fn sync(store: &mut TestStore) {
        futures::future::try_join_all(store.start_sync().await.unwrap())
            .await
            .unwrap();
        let (sealed, handles) = store.start_seals().await.unwrap();
        futures::future::try_join_all(handles).await.unwrap();
        store.finish_seals(sealed, &BTreeSet::new()).await.unwrap();
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
            let segment = store.open_segments.get(&0).unwrap();
            assert_eq!(segment.bodies().size(), 1);
            assert_eq!(segment.metadata().size(), 1);
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
    fn only_full_snapshots_are_exposed_as_sealed() {
        deterministic::Runner::default().start(|context| async move {
            let mut store = open(&context, "store", "pending_snapshot_bound").await;
            for height in 1..=5 {
                let block = block(0, height, height);
                store.put(block.reference(), block).await.unwrap();
            }

            // The completed cut is the catalog's offer point: every cut segment has a frozen
            // reader, and only the full ones are exposed as sealed.
            futures::future::try_join_all(store.start_sync().await.unwrap())
                .await
                .unwrap();
            assert_eq!(
                store.active_readers.keys().copied().collect::<Vec<_>>(),
                vec![0, 1, 2]
            );
            assert_eq!(
                store
                    .sealed_body_readers()
                    .iter()
                    .map(BodyReader::segment)
                    .collect::<Vec<_>>(),
                vec![0, 1]
            );

            // Readers stay retained while seal proofs are in flight, and drop once they land.
            let (sealed, handles) = store.start_seals().await.unwrap();
            assert_eq!(sealed, vec![0, 1]);
            assert_eq!(
                store.active_readers.keys().copied().collect::<Vec<_>>(),
                vec![0, 1, 2]
            );
            assert_eq!(
                store.open_segments.keys().copied().collect::<Vec<_>>(),
                vec![2]
            );
            futures::future::try_join_all(handles).await.unwrap();
            store.finish_seals(sealed, &BTreeSet::new()).await.unwrap();
            assert_eq!(
                store.active_readers.keys().copied().collect::<Vec<_>>(),
                vec![2]
            );

            sync(&mut store).await;
            assert_eq!(
                store.active_readers.keys().copied().collect::<Vec<_>>(),
                vec![2]
            );
            assert!(store.sealed_body_readers().is_empty());
        });
    }

    #[test]
    fn sealing_segments_defer_reclamation_until_their_proof_lands() {
        deterministic::Runner::default().start(|context| async move {
            let mut store = open(&context, "store", "pending_sealing_reclaim").await;
            for height in 1..=5 {
                let block = block(0, height, height);
                store.put(block.reference(), block).await.unwrap();
            }
            futures::future::try_join_all(store.start_sync().await.unwrap())
                .await
                .unwrap();
            let (sealed, handles) = store.start_seals().await.unwrap();
            assert_eq!(sealed, vec![0, 1]);

            // Pruning past every block must not destroy a segment whose seal proof is still
            // being written; the proof landing reclaims the deferred segments itself.
            let reclaimed = store
                .prune(&[Some(Height::new(6)), None], &BTreeSet::new())
                .await
                .unwrap();
            assert!(reclaimed.is_empty());
            futures::future::try_join_all(handles).await.unwrap();
            let reclaimed = store
                .finish_seals(sealed, &BTreeSet::new())
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
                .body_read_groups([(0, first_ref)], u64::MAX, NonZeroUsize::MIN)
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
    fn body_read_groups_preserve_position_locality() {
        deterministic::Runner::default().start(|context| async move {
            let config = ArchiveConfig::new(
                TwoCap,
                CacheRef::from_pooler(&context, NZU16!(1024), NZUsize!(10)),
            );
            let mut store = TestStore::init(
                context.child("store"),
                config,
                "pending_position_locality".to_string(),
                (),
                Epoch::new(7),
                2,
                NZU64!(8),
                NZUsize!(1024 * 1024),
            )
            .await
            .unwrap();
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
                    NZUsize!(3),
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
            assert_eq!(positions, vec![vec![0, 1], vec![2, 3], vec![4, 5]]);
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
        let tail = block(0, 2, 2);
        let tail_reference = tail.reference();
        let mut store = open(context, label, prefix).await;
        store
            .put(retained_reference, Arc::clone(&retained))
            .await
            .unwrap();
        sync(&mut store).await;
        let segment = store.open_segments.get_mut(&0).unwrap();
        if metadata_only {
            let metadata = segment.metadata.take().unwrap();
            let meta = BlockMeta::new(
                tail.header().clone(),
                u64::try_from(tail.encode_size()).unwrap(),
            );
            let (metadata, position) = metadata.append(&meta).await.unwrap();
            assert_eq!(position, 1);
            segment.metadata = Some(metadata.sync().await.unwrap());
        } else {
            let bodies = segment.bodies.take().unwrap();
            let body = Shared::new(Arc::clone(&tail));
            let (bodies, position) = bodies.append(&body).await.unwrap();
            assert_eq!(position, 1);
            segment.bodies = Some(bodies.sync().await.unwrap());
        }
        drop(store);

        let mut store = open(context, "partial_reopen", prefix).await;
        assert_eq!(store.next_position, 1);
        assert_eq!(
            store.block(retained_reference).await.unwrap().as_deref(),
            Some(retained.as_ref())
        );
        assert_eq!(store.header(tail_reference), None);
        assert!(store.block(tail_reference).await.unwrap().is_none());
        let current = store.open_segments.get(&0).unwrap();
        assert_eq!(current.bodies().size(), 1);
        assert_eq!(current.metadata().size(), 1);
        store.put(tail_reference, Arc::clone(&tail)).await.unwrap();
        sync(&mut store).await;
        assert_eq!(
            store.block(tail_reference).await.unwrap().as_deref(),
            Some(tail.as_ref())
        );
    }

    #[test]
    fn asymmetric_partial_cuts_rewind_to_the_common_range() {
        deterministic::Runner::default().start(|context| async move {
            partial_tail(&context, "metadata_first", "pending_metadata_tail", true).await;
            partial_tail(&context, "body_first", "pending_body_tail", false).await;
        });
    }

    #[test]
    fn unpublished_segment_is_reset_before_reuse() {
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
            let segment = store.open_segments.get_mut(&1).unwrap();
            let bodies = segment.bodies.take().unwrap();
            let metadata = segment.metadata.take().unwrap();
            let (bodies, metadata) = futures::try_join!(bodies.sync(), metadata.sync()).unwrap();
            segment.bodies = Some(bodies);
            segment.metadata = Some(metadata);
            drop(store);

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

    #[test]
    fn sealed_segment_cold_opens_without_recovery_or_writes() {
        deterministic::Runner::default().start(|context| async move {
            let mut store = open(&context, "store", "pending_sealed_cold").await;
            let references = fill_first_segment(&mut store).await;

            // The sealed proof opens the segment from index metadata alone: no repair, no
            // rebuilt offsets, no watermark writes. Recovery would show up as storage writes.
            let before = context.encode();
            let (reader, cold) = store.body_source(0).open().await.unwrap();
            let after = context.encode();
            assert_eq!(cold, Some(ColdOpen::Sealed));
            assert_eq!(
                counter(&after, "storage_writes"),
                counter(&before, "storage_writes"),
                "sealed cold open must not write"
            );
            assert_eq!(
                counter(&after, "storage_syncs"),
                counter(&before, "storage_syncs"),
                "sealed cold open must not sync"
            );
            let locator = TestStore::locator(store.by_digest.get(&references[0].digest()).unwrap());
            assert_eq!(reader.read(locator).await.unwrap().reference(), references[0]);
        });
    }

    #[test]
    fn broken_seal_proof_falls_back_to_authoritative_recovery() {
        deterministic::Runner::default().start(|context| async move {
            let mut store = open(&context, "store", "pending_broken_seal").await;
            let references = fill_first_segment(&mut store).await;

            // Destroy segment 0's durable seal proof (the offsets journal checkpoint).
            context
                .remove("pending_broken_seal_bodies_0_offsets-metadata", None)
                .await
                .unwrap();

            // The cold open falls back to one authoritative recovery, which serves exact
            // bodies and re-establishes the proof for the next open.
            let (reader, cold) = store.body_source(0).open().await.unwrap();
            assert_eq!(cold, Some(ColdOpen::Recovered));
            let locator = TestStore::locator(store.by_digest.get(&references[1].digest()).unwrap());
            assert_eq!(reader.read(locator).await.unwrap().reference(), references[1]);
            drop(reader);
            let (_, cold) = store.body_source(0).open().await.unwrap();
            assert_eq!(cold, Some(ColdOpen::Sealed));
        });
    }

    #[test]
    fn dirty_full_segment_defers_its_seal_to_the_covering_cut() {
        deterministic::Runner::default().start(|context| async move {
            let mut store = open(&context, "store", "pending_dirty_seal").await;
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

            // The catalog seals on cut completion; the dirty tail defers this segment's seal
            // and keeps its journals appendable for the covering cut.
            assert!(store.start_seals().await.unwrap().0.is_empty());
            sync(&mut store).await;
            sync(&mut store).await;

            let (reader, cold) = store.body_source(0).open().await.unwrap();
            assert_eq!(cold, Some(ColdOpen::Sealed));
            let locator =
                TestStore::locator(store.by_digest.get(&filler_reference.digest()).unwrap());
            assert_eq!(
                reader.read(locator).await.unwrap().reference(),
                filler_reference
            );
        });
    }

    #[test]
    fn unsealed_full_segment_self_heals_on_reopen() {
        deterministic::Runner::default().start(|context| async move {
            let mut store = open(&context, "first", "pending_unsealed_reopen").await;
            let references = put_first_segment(&mut store).await;
            // Crash window: the admission cut completes but the seal proof never lands.
            futures::future::try_join_all(store.start_sync().await.unwrap())
                .await
                .unwrap();
            drop(store);

            // Startup recovers the unproven segment authoritatively, which also re-establishes
            // its seal proof, so the next cold open reads index metadata alone.
            let store = open(&context, "reopen", "pending_unsealed_reopen").await;
            for reference in &references {
                assert!(store.block(*reference).await.unwrap().is_some());
            }
            let (_, cold) = store.body_source(0).open().await.unwrap();
            assert_eq!(cold, Some(ColdOpen::Sealed));
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
