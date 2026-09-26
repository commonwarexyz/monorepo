//! The pending custody store: segment journals, custody indexes, and the manifest.

use super::{
    manifest::{PendingState, PendingStateCfg},
    plan::plan_groups,
    read::{BodyLocator, BodyRead, BodyReadGroup, BodyReader, BodySource, ColdSource},
    record::PendingRecord,
};
use crate::{
    multimmit::{
        marshal::storage::{Error, blocks::BlockMeta, record::DurableRecord},
        types::{BlockRef, Body, ChainId, Frontier, TransactionBlock, TransactionBlockHeader},
    },
    types::{Epoch, Height},
};
use commonware_codec::{EncodeSize as _, FixedSize as _};
use commonware_cryptography::{Digest, Hasher};
use commonware_runtime::{Handle, ReadOptions, buffer::paged::CacheRef};
use commonware_storage::{
    Context,
    journal::{
        self,
        segmented::{
            glob,
            oversized::{self, Oversized},
        },
    },
};
use commonware_utils::NZUsize;
use futures::{
    FutureExt as _,
    future::{BoxFuture, try_join_all},
};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    marker::PhantomData,
    mem,
    num::{NonZeroU64, NonZeroUsize},
    sync::Arc,
};

type Segment<E, H, B> =
    Oversized<E, PendingRecord<<H as Hasher>::Digest>, Arc<TransactionBlock<H, B>>>;

/// An unplaced index record and the body it locates.
type AppendEntry<H, B> = (
    PendingRecord<<H as Hasher>::Digest>,
    Arc<TransactionBlock<H, B>>,
);

/// Bounds file descriptors and filesystem operations used by one segment read wave.
pub(crate) const BODY_READ_CONCURRENCY: NonZeroUsize = NZUsize!(16);

/// Segments whose partitions are removed concurrently while reclaiming.
const IO_BATCH: usize = 16;

/// Partition family holding a segment's body frames.
const BODIES: &str = "bodies";
/// Partition family holding a segment's fixed-width index records.
const METADATA: &str = "metadata";
/// Partition family holding a segment's recovery markers.
const MARKERS: &str = "markers";

/// Journal buffers and page cache shared by every pending segment.
#[derive(Clone)]
pub(crate) struct JournalBuffers {
    /// Cache for index journal pages.
    pub(crate) page_cache: CacheRef,
    /// Bytes buffered by index journals.
    pub(crate) key_write_buffer: NonZeroUsize,
    /// Bytes buffered by value journals.
    pub(crate) value_write_buffer: NonZeroUsize,
    /// Bytes buffered while replaying index journals, and the read prefetch for body reads.
    pub(crate) replay_buffer: NonZeroUsize,
}

/// Construction inputs for [`PendingBlocks`].
pub(crate) struct PendingConfig<C> {
    /// Prefix from which every pending partition is derived.
    pub(crate) prefix: String,
    /// Journal buffers and page cache.
    pub(crate) buffers: JournalBuffers,
    /// Bounds used to decode block bodies.
    pub(crate) body_codec_config: C,
    /// Epoch every stored block belongs to.
    pub(crate) epoch: Epoch,
    /// Number of producer chains.
    pub(crate) chains: usize,
    /// Positions in each segment; fixed when the namespace is created.
    pub(crate) segment_capacity: NonZeroU64,
    /// Largest manifest blob.
    pub(crate) max_manifest_bytes: NonZeroUsize,
}

/// A retention floor per producer chain, in chain order. `None` leaves a chain unchanged.
pub(crate) struct ChainFloors(Vec<Option<Height>>);

/// The partitions one segment owns.
pub(super) struct SegmentPartitions {
    bodies: String,
    metadata: String,
    markers: String,
}

/// Who holds an open segment's journals. A closed segment has no slot.
pub(super) enum SegmentSlot<E, H, B>
where
    E: Context,
    H: Hasher,
    B: Body<H>,
{
    /// The store holds the journals.
    Owned(Segment<E, H, B>),
    /// An in-flight append holds the journals. The segment still accepts appends, so it must
    /// not be read as a cold immutable segment; only captured snapshots may read it.
    Lent,
}

/// Custody index entry for one stored block.
#[derive(Clone, PartialEq, Eq)]
pub(super) struct CustodyEntry<D: Digest> {
    pub(super) locator: BodyLocator<D>,
    pub(super) header: TransactionBlockHeader<D>,
}

/// The inputs to open one segment's journals, validating every recovered record.
struct SegmentOpener<E, H, B>
where
    E: Context,
    H: Hasher,
    B: Body<H>,
{
    context: E,
    config: oversized::Config<B::Cfg>,
    partitions: SegmentPartitions,
    /// Whether the manifest already names the segment; an unnamed one is reset before use.
    exists: bool,
    capacity: u64,
    _marker: PhantomData<H>,
}

/// An admitted batch of blocks waiting to be appended to one segment.
pub(crate) struct PendingAppend<E, H, B>
where
    E: Context,
    H: Hasher,
    B: Body<H>,
{
    position: u64,
    local: u64,
    entries: Vec<AppendEntry<H, B>>,
    segment: AppendTarget<E, H, B>,
}

enum AppendTarget<E, H, B>
where
    E: Context,
    H: Hasher,
    B: Body<H>,
{
    Owned(Segment<E, H, B>),
    Closed(SegmentOpener<E, H, B>),
}

/// Completed journal writes awaiting publication into the custody indexes.
pub(crate) struct Append<E, H, B>
where
    E: Context,
    H: Hasher,
    B: Body<H>,
{
    position: u64,
    rows: Vec<PendingRecord<H::Digest>>,
    segment: Segment<E, H, B>,
}

/// Full segments whose recovery markers are being persisted.
pub(crate) struct Retirement {
    /// Segments to return through [`PendingBlocks::finish_retire`] once `sync` completes.
    pub(crate) segments: Vec<u64>,
    /// Completes when every marker is durable.
    pub(crate) sync: BoxFuture<'static, Result<(), Error>>,
}

/// Catalog-owned pending producer blocks from every chain.
pub(crate) struct PendingBlocks<E, H, B>
where
    E: Context,
    H: Hasher,
    B: Body<H>,
{
    pub(super) context: E,
    buffers: JournalBuffers,
    prefix: String,
    body_codec_config: B::Cfg,
    manifest: DurableRecord<E, PendingState>,
    /// Whether the manifest changed since its last durability cut.
    manifest_dirty: bool,
    pub(super) segments: BTreeSet<u64>,
    pub(super) open_segments: BTreeMap<u64, SegmentSlot<E, H, B>>,
    pub(super) active_readers: BTreeMap<u64, BodyReader<E, H, B>>,
    dirty_segments: BTreeSet<u64>,
    /// Full segments publishing recovery markers. Reclamation waits for these writes to finish.
    retiring: BTreeSet<u64>,
    pub(super) by_digest: HashMap<H::Digest, CustodyEntry<H::Digest>>,
    by_position: BTreeMap<u64, H::Digest>,
    by_chain: Vec<BTreeMap<Height, Vec<H::Digest>>>,
    pub(super) next_position: u64,
    pub(super) floors: Vec<Height>,
    pub(super) segment_capacity: u64,
    pub(super) epoch: Epoch,
}

impl ChainFloors {
    /// Returns floors that leave all `chains` unchanged.
    pub(crate) fn unchanged(chains: usize) -> Self {
        Self(vec![None; chains])
    }

    /// Returns floors just above every block of `frontier`.
    pub(crate) fn above<D: Digest>(frontier: &Frontier<D>) -> Self {
        Self(
            frontier
                .references()
                .iter()
                .map(|reference| Some(Height::new(reference.height().get().saturating_add(1))))
                .collect(),
        )
    }

    /// Raises `chain`'s floor to at least `floor`.
    pub(crate) fn raise(&mut self, chain: ChainId, floor: Height) {
        let slot = &mut self.0[chain.get() as usize];
        *slot = Some(slot.map_or(floor, |current| current.max(floor)));
    }
}

impl FromIterator<Option<Height>> for ChainFloors {
    /// Collects one floor per chain, in chain order.
    fn from_iter<I: IntoIterator<Item = Option<Height>>>(floors: I) -> Self {
        Self(floors.into_iter().collect())
    }
}

impl SegmentPartitions {
    pub(super) fn all(self) -> [String; 3] {
        [self.bodies, self.metadata, self.markers]
    }
}

impl<E, H, B> SegmentSlot<E, H, B>
where
    E: Context,
    H: Hasher,
    B: Body<H>,
{
    const fn owned(&self) -> Result<&Segment<E, H, B>, Error> {
        match self {
            Self::Owned(segment) => Ok(segment),
            Self::Lent => Err(Error::Inconsistent("pending segment is lent to an append")),
        }
    }
}

impl<D: Digest> CustodyEntry<D> {
    fn meta(&self) -> BlockMeta<D> {
        BlockMeta::new(self.header.clone(), self.locator.encoded_len)
    }

    fn matches(&self, meta: &BlockMeta<D>) -> bool {
        self.header == *meta.header() && self.locator.encoded_len == meta.encoded_len()
    }
}

impl<E, H, B> SegmentOpener<E, H, B>
where
    E: Context,
    H: Hasher,
    B: Body<H>,
    B::Cfg: Clone,
{
    /// Opens the segment, returning its journals and every validated record in order.
    ///
    /// A manifest coordinate owns its partitions. Reuse removes unreachable residue before
    /// opening writers; recovery validates uncommitted bodies before their records become
    /// custody.
    async fn open(self) -> Result<(Segment<E, H, B>, Vec<PendingRecord<H::Digest>>), Error> {
        let markers = self.partitions.markers.clone();
        if !self.exists {
            remove_partitions(&self.context, self.partitions).await?;
        }
        // Journal metrics keep their `oversized` scope; the marker metadata now registers
        // beneath it because the journal owns its metadata context.
        let mut replay = Segment::<E, H, B>::init_with_metadata(
            self.context.child("oversized"),
            self.config,
            markers,
            ReadOptions::default(),
        )
        .await?;
        let mut rows = Vec::new();
        let mut end = 0u64;
        while let Some(row) = replay.next().await {
            let (section, position, row) = row?;
            if section != 0 || position != rows.len() as u64 || position >= self.capacity {
                return Err(Error::Inconsistent("pending segment bounds are invalid"));
            }
            if row.offset != end {
                return Err(Error::Inconsistent("pending body location is invalid"));
            }
            end = row
                .offset
                .checked_add(u64::from(row.size))
                .ok_or(Error::Inconsistent("pending body location overflows"))?;
            rows.push(row);
        }
        Ok((replay.finish_tracked().await?, rows))
    }
}

impl<E, H, B> PendingAppend<E, H, B>
where
    E: Context,
    H: Hasher,
    B: Body<H>,
    B::Cfg: Clone,
{
    /// Appends the batch and returns the located rows for [`PendingBlocks::finish_put`].
    pub(crate) async fn run(self) -> Result<Append<E, H, B>, Error> {
        let mut segment = match self.segment {
            AppendTarget::Owned(segment) => segment,
            AppendTarget::Closed(opener) => opener.open().await?.0,
        };
        if segment_len::<E, H, B>(&segment)? != self.local {
            return Err(Error::Inconsistent(
                "pending segment does not match the append coordinate",
            ));
        }
        let count = self.entries.len() as u64;
        let last;
        let locations;
        (segment, last, locations) = segment
            .append_many(
                0,
                self.entries.iter().map(|(row, body)| (row.clone(), body)),
            )
            .await?;
        if last != self.local + count - 1 {
            return Err(Error::Inconsistent(
                "pending segment assigned an unexpected position",
            ));
        }
        let rows = self
            .entries
            .into_iter()
            .zip(locations)
            .map(|((row, _), (offset, size))| oversized::Record::with_location(row, offset, size))
            .collect();
        Ok(Append {
            position: self.position,
            rows,
            segment,
        })
    }
}

/// Returns the number of records appended to a segment.
pub(super) fn segment_len<E, H, B>(segment: &Segment<E, H, B>) -> Result<u64, Error>
where
    E: Context,
    H: Hasher,
    B: Body<H>,
{
    match segment.size(0) {
        Ok(size) => Ok(size / PendingRecord::<H::Digest>::SIZE as u64),
        Err(journal::Error::SectionOutOfRange(_)) => Ok(0),
        Err(error) => Err(error.into()),
    }
}

async fn remove_partitions<E: Context>(
    context: &E,
    partitions: SegmentPartitions,
) -> Result<(), Error> {
    for partition in partitions.all() {
        match context.remove(&partition, None).await {
            Ok(()) | Err(commonware_runtime::Error::PartitionMissing(_)) => {}
            Err(error) => return Err(journal::Error::from(error).into()),
        }
    }
    Ok(())
}

impl<E, H, B> PendingBlocks<E, H, B>
where
    E: Context,
    H: Hasher,
    B: Body<H>,
    B::Cfg: Clone,
{
    /// Opens pending custody, recovering each segment before publishing its metadata as custody.
    pub(crate) async fn init(context: E, config: PendingConfig<B::Cfg>) -> Result<Self, Error> {
        let PendingConfig {
            prefix,
            buffers,
            body_codec_config,
            epoch,
            chains,
            segment_capacity,
            max_manifest_bytes,
        } = config;
        let manifest_cfg = PendingStateCfg {
            chains,
            max_segments: max_manifest_bytes.get() / u64::SIZE,
        };
        let mut manifest = DurableRecord::init(
            context.child("state"),
            format!("{prefix}_state"),
            manifest_cfg,
            Some(max_manifest_bytes),
        )
        .await?;
        let persisted = match manifest.get()?.cloned() {
            Some(state) => state,
            None => {
                let state = PendingState {
                    segment_capacity: segment_capacity.get(),
                    floors: vec![Height::zero(); chains],
                    segments: Vec::new(),
                };
                manifest.put_sync(state.clone()).await?;
                state
            }
        };
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
            buffers,
            prefix,
            body_codec_config,
            manifest,
            manifest_dirty: false,
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
            epoch,
        };

        let current = persisted.segments.last().copied();
        for segment_id in persisted.segments {
            let segment_start = segment_id
                .checked_mul(store.segment_capacity)
                .ok_or(Error::Inconsistent("pending segment coordinate overflow"))?;

            let (mut segment, rows) = store.opener(segment_id).open().await?;
            let count = rows.len() as u64;
            for (local, row) in rows.into_iter().enumerate() {
                let position = segment_start
                    .checked_add(local as u64)
                    .ok_or(Error::Inconsistent("pending position overflow"))?;
                store.remember(position, row)?;
            }
            if Some(segment_id) == current {
                if count > 0 {
                    let reader;
                    (segment, reader) = segment.value_snapshot(0).await?;
                    store.active_readers.insert(
                        segment_id,
                        BodyReader::new(
                            segment_id,
                            store.segment_capacity,
                            reader,
                            count == store.segment_capacity,
                        ),
                    );
                }
                store.next_position = segment_start
                    .checked_add(count)
                    .ok_or(Error::Inconsistent("pending position overflow"))?;
                store
                    .open_segments
                    .insert(segment_id, SegmentSlot::Owned(segment));
            } else {
                segment.close().await?;
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
            store.persist_manifest().await?;
        }
        Ok(store)
    }

    /// Returns the configured producer-chain count.
    pub(crate) const fn chain_count(&self) -> usize {
        self.by_chain.len()
    }

    /// Returns whether this reference remains eligible for pending custody.
    pub(crate) fn admits(&self, reference: BlockRef<H::Digest>) -> bool {
        self.floors
            .get(reference.chain().get() as usize)
            .is_some_and(|floor| reference.height() >= *floor)
    }

    /// Admits blocks up to the end of the current segment and lends its writer to the append.
    ///
    /// Exact duplicates consume no positions; appended rows keep input order. Only immutable body
    /// reads may run until [`Self::finish_put`] returns the writer. Returns `None` when every
    /// block is already stored, in which case nothing is lent.
    pub(crate) fn start_put(
        &mut self,
        blocks: impl Iterator<Item = (BlockRef<H::Digest>, Arc<TransactionBlock<H, B>>)>,
    ) -> Result<Option<PendingAppend<E, H, B>>, Error> {
        let position = self.next_position;
        let segment_id = self.segment_id(position);
        let local = position % self.segment_capacity;
        let room = self.segment_capacity - local;
        let mut entries: Vec<AppendEntry<H, B>> = Vec::new();
        let mut seen: HashMap<H::Digest, usize> = HashMap::new();
        for (reference, block) in blocks {
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
                || meta.authenticate::<H>(digest, self.epoch, self.chain_count()) != Some(reference)
            {
                return Err(Error::Inconsistent("pending block identity is invalid"));
            }
            if let Some(entry) = self.by_digest.get(&digest) {
                if entry.locator.reference != reference || !entry.matches(&meta) {
                    return Err(Error::Inconsistent("pending digest identity changed"));
                }
                continue;
            }
            if let Some(&index) = seen.get(&digest) {
                if entries[index].0.meta != meta {
                    return Err(Error::Inconsistent("pending digest identity changed"));
                }
                continue;
            }
            seen.insert(digest, entries.len());
            entries.push((PendingRecord::unplaced(meta), block));
            if entries.len() as u64 == room {
                break;
            }
        }
        if entries.is_empty() {
            return Ok(None);
        }
        position
            .checked_add(entries.len() as u64)
            .ok_or(Error::Inconsistent("pending position overflow"))?;
        let segment = match self.open_segments.insert(segment_id, SegmentSlot::Lent) {
            Some(SegmentSlot::Owned(segment)) => AppendTarget::Owned(segment),
            Some(SegmentSlot::Lent) => {
                return Err(Error::Inconsistent("pending segment is lent to an append"));
            }
            None => AppendTarget::Closed(self.opener(segment_id)),
        };
        Ok(Some(PendingAppend {
            position,
            local,
            entries,
            segment,
        }))
    }

    /// Publishes one completed append; no other mutable operation may have intervened.
    pub(crate) fn finish_put(&mut self, append: Append<E, H, B>) -> Result<(), Error> {
        let Append {
            position,
            rows,
            segment,
        } = append;
        assert_eq!(position, self.next_position, "appends complete in order");
        let segment_id = self.segment_id(position);
        self.open_segments
            .insert(segment_id, SegmentSlot::Owned(segment));
        if self.segments.insert(segment_id) {
            self.stage_manifest()?;
        }
        self.dirty_segments.insert(segment_id);
        for row in rows {
            self.remember(self.next_position, row)?;
            self.next_position += 1;
        }
        Ok(())
    }

    /// Starts one shared durability cut for every buffered producer block.
    pub(crate) async fn start_sync(&mut self) -> Result<Vec<Handle<()>>, Error> {
        let dirty = mem::take(&mut self.dirty_segments);
        let current = self.segments.last().copied();
        // The previous cut completed before this one starts. Its non-current readers can be
        // released; outstanding read plans own their snapshots and cold reads open only values.
        self.active_readers
            .retain(|segment, _| Some(*segment) == current);
        let mut cuts = Vec::with_capacity(dirty.len());
        for segment_id in dirty {
            let segment = match self.open_segments.remove(&segment_id) {
                Some(SegmentSlot::Owned(segment)) => segment,
                Some(SegmentSlot::Lent) | None => {
                    return Err(Error::Inconsistent("dirty pending segment is not owned"));
                }
            };
            cuts.push(async move {
                let count = segment_len::<E, H, B>(&segment)?;
                let (segment, handle) = segment.start_sync(0).await?;
                let reader = segment.capture(0)?;
                Ok::<_, Error>((segment_id, segment, handle, reader, count))
            });
        }

        let manifest_dirty = mem::take(&mut self.manifest_dirty);
        let manifest = &mut self.manifest;
        let (cuts, manifest) = futures::try_join!(try_join_all(cuts), async move {
            if manifest_dirty {
                manifest.start_sync().await.map(Some)
            } else {
                Ok(None)
            }
        })?;

        let mut handles = Vec::with_capacity(cuts.len() + usize::from(manifest.is_some()));
        for (segment_id, segment, handle, reader, count) in cuts {
            self.open_segments
                .insert(segment_id, SegmentSlot::Owned(segment));
            handles.push(handle);
            let immutable = count == self.segment_capacity;
            self.active_readers.insert(
                segment_id,
                BodyReader::new(segment_id, self.segment_capacity, reader, immutable),
            );
        }
        // A full segment's final cut is in flight: keep its journals until the cut completes so
        // start_retire can persist their final checkpoints. Every slot is checked before any is
        // dropped, so a failure leaves the map untouched.
        for slot in self.open_segments.values() {
            segment_len::<E, H, B>(slot.owned()?)?;
        }
        self.open_segments.retain(|&segment, slot| {
            Some(segment) == current
                || slot
                    .owned()
                    .and_then(segment_len::<E, H, B>)
                    .is_ok_and(|len| len == self.segment_capacity)
        });
        handles.extend(manifest);
        Ok(handles)
    }

    /// Closes full segments after their final admission cut, persisting recovery markers.
    ///
    /// The caller must return the retired segments through [`Self::finish_retire`] before they
    /// can be reclaimed. Dirty full segments wait for the cut covering their final appends.
    pub(crate) fn start_retire(&mut self) -> Result<Option<Retirement>, Error> {
        let mut segments = Vec::new();
        for (&segment, slot) in &self.open_segments {
            if !self.dirty_segments.contains(&segment)
                && !self.retiring.contains(&segment)
                && segment_len::<E, H, B>(slot.owned()?)? == self.segment_capacity
            {
                segments.push(segment);
            }
        }
        if segments.is_empty() {
            return Ok(None);
        }
        let mut closes = Vec::with_capacity(segments.len());
        for segment in &segments {
            let Some(SegmentSlot::Owned(journal)) = self.open_segments.remove(segment) else {
                unreachable!("a full pending segment was just observed as owned");
            };
            self.retiring.insert(*segment);
            closes.push(journal.close());
        }
        Ok(Some(Retirement {
            segments,
            sync: async move {
                try_join_all(closes).await?;
                Ok(())
            }
            .boxed(),
        }))
    }

    /// Releases completed marker writers and reclaims any empty, unpinned segments that
    /// pruning deferred while their markers were being persisted.
    pub(crate) async fn finish_retire(
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
        if !self.dirty_segments.is_empty() || self.manifest_dirty {
            return Ok(Vec::new());
        }
        self.reclaim_unpinned(pinned).await
    }

    /// Clones snapshots whose segments cannot accept another append.
    pub(crate) fn immutable_body_readers(&self) -> Vec<BodyReader<E, H, B>> {
        self.active_readers
            .values()
            .filter(|reader| reader.immutable)
            .cloned()
            .collect()
    }

    /// Plans bounded, immutable reads for locally stored references.
    ///
    /// Positions beyond the latest snapshot remain unavailable until their admission cut starts.
    /// Non-current segments are safe to open independently because they can no longer be
    /// appended. Grouping follows [`plan_groups`].
    pub(crate) fn body_read_groups(
        &self,
        references: impl IntoIterator<Item = (usize, BlockRef<H::Digest>)>,
        max_bytes: NonZeroU64,
        max_groups: NonZeroUsize,
    ) -> Result<Vec<BodyReadGroup<E, H, B>>, Error> {
        let mut by_segment = BTreeMap::<u64, Vec<_>>::new();
        for (output, reference) in references {
            let Some(entry) = self.entry(reference) else {
                continue;
            };
            let segment = self.segment_id(entry.locator.position);
            let readable = self
                .active_readers
                .get(&segment)
                .is_some_and(|reader| reader.contains(entry.locator))
                || !self.open_segments.contains_key(&segment);
            if readable {
                by_segment
                    .entry(segment)
                    .or_default()
                    .push((output, entry.locator));
            }
        }
        plan_groups(by_segment, max_bytes, max_groups)?
            .into_iter()
            .map(|group| {
                Ok(BodyReadGroup {
                    source: self.body_source(group.segment),
                    read: BodyRead::new(group.segment, group.entries, self.buffers.replay_buffer)?,
                })
            })
            .collect()
    }

    /// Returns the pending reference named by a chain and header digest.
    pub(crate) fn reference_by_digest(
        &self,
        chain: ChainId,
        digest: H::Digest,
    ) -> Option<BlockRef<H::Digest>> {
        self.by_digest
            .get(&digest)
            .map(|entry| entry.locator.reference)
            .filter(|reference| reference.chain() == chain)
    }

    /// Returns compact metadata for a complete stored body.
    pub(crate) fn custody_meta(
        &self,
        reference: BlockRef<H::Digest>,
    ) -> Option<BlockMeta<H::Digest>> {
        self.entry(reference).map(CustodyEntry::meta)
    }

    /// Returns a header recovered with its corresponding body.
    pub(crate) fn header(
        &self,
        reference: BlockRef<H::Digest>,
    ) -> Option<TransactionBlockHeader<H::Digest>> {
        self.entry(reference).map(|entry| entry.header.clone())
    }

    /// Reclaims chain-local heights below each supplied floor and returns destroyed segments.
    pub(crate) async fn prune(
        &mut self,
        floors: &ChainFloors,
        pinned: &BTreeSet<u64>,
    ) -> Result<Vec<u64>, Error> {
        if !self.dirty_segments.is_empty() || self.manifest_dirty {
            return Err(Error::Inconsistent(
                "pending prune crossed a durability cut",
            ));
        }
        // Floors become authoritative before reclamation, so recovery can filter dead metadata
        // after a crash. Only whole non-current segments are destroyed; local positions never
        // move, and the retained current journal continues to own the append cursor.
        if self.advance_floors(floors)? {
            self.persist_manifest().await?;
        }
        self.reclaim_unpinned(pinned).await
    }

    /// Returns the live custody entry for exactly `reference`.
    pub(super) fn entry(&self, reference: BlockRef<H::Digest>) -> Option<&CustodyEntry<H::Digest>> {
        self.by_digest
            .get(&reference.digest())
            .filter(|entry| entry.locator.reference == reference)
    }

    pub(super) const fn segment_id(&self, position: u64) -> u64 {
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

    pub(super) fn segment_partitions(&self, segment: u64) -> SegmentPartitions {
        SegmentPartitions {
            bodies: self.segment_prefix(BODIES, segment),
            metadata: self.segment_prefix(METADATA, segment),
            markers: self.segment_prefix(MARKERS, segment),
        }
    }

    /// Pending body frames must stay uncompressed: [`PendingRecord`] derives each block's
    /// encoded length from its frame size minus the fixed CRC32 trailer.
    pub(super) fn body_config(&self, segment: u64) -> glob::Config<B::Cfg> {
        glob::Config {
            partition: self.segment_prefix(BODIES, segment),
            compression: None,
            codec_config: self.body_codec_config.clone(),
            write_buffer: self.buffers.value_write_buffer,
        }
    }

    /// Pending body frames must stay uncompressed: [`PendingRecord`] derives each block's
    /// encoded length from its frame size minus the fixed CRC32 trailer.
    pub(super) fn segment_config(&self, segment: u64) -> oversized::Config<B::Cfg> {
        oversized::Config {
            index_partition: self.segment_prefix(METADATA, segment),
            value_partition: self.segment_prefix(BODIES, segment),
            index_page_cache: self.buffers.page_cache.clone(),
            index_write_buffer: self.buffers.key_write_buffer,
            value_write_buffer: self.buffers.value_write_buffer,
            replay_buffer: self.buffers.replay_buffer,
            compression: None,
            codec_config: self.body_codec_config.clone(),
        }
    }

    fn opener(&self, segment: u64) -> SegmentOpener<E, H, B> {
        SegmentOpener {
            context: self
                .context
                .child("segments")
                .with_attribute("segment", segment),
            config: self.segment_config(segment),
            partitions: self.segment_partitions(segment),
            exists: self.segments.contains(&segment),
            capacity: self.segment_capacity,
            _marker: PhantomData,
        }
    }

    pub(super) fn body_source(&self, segment: u64) -> BodySource<E, H, B> {
        self.active_readers.get(&segment).map_or_else(
            || {
                BodySource::Cold(ColdSource {
                    context: self
                        .context
                        .child("bodies")
                        .with_attribute("segment", segment),
                    config: self.body_config(segment),
                    segment,
                    segment_capacity: self.segment_capacity,
                    _marker: PhantomData,
                })
            },
            |reader| BodySource::Ready(reader.clone()),
        )
    }

    fn manifest_snapshot(&self) -> PendingState {
        PendingState {
            segment_capacity: self.segment_capacity,
            floors: self.floors.clone(),
            segments: self.segments.iter().copied().collect(),
        }
    }

    fn stage_manifest(&mut self) -> Result<(), Error> {
        self.manifest.stage(self.manifest_snapshot())?;
        self.manifest_dirty = true;
        Ok(())
    }

    pub(super) async fn persist_manifest(&mut self) -> Result<(), Error> {
        self.manifest.put_sync(self.manifest_snapshot()).await?;
        self.manifest_dirty = false;
        Ok(())
    }

    async fn ensure_segment(&mut self, segment: u64) -> Result<(), Error> {
        if self.open_segments.contains_key(&segment) {
            return Ok(());
        }
        let (opened, _) = self.opener(segment).open().await?;
        self.open_segments
            .insert(segment, SegmentSlot::Owned(opened));
        if self.segments.insert(segment) {
            self.stage_manifest()?;
        }
        Ok(())
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
        self.persist_manifest().await?;
        for batch in segments.chunks(IO_BATCH) {
            try_join_all(batch.iter().map(|&segment| {
                remove_partitions(&self.context, self.segment_partitions(segment))
            }))
            .await?;
        }
        Ok(segments)
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

    fn remember(&mut self, position: u64, row: PendingRecord<H::Digest>) -> Result<(), Error> {
        let PendingRecord { meta, offset, size } = row;
        let digest = meta.header().digest::<H>();
        let reference = meta
            .authenticate::<H>(digest, self.epoch, self.chain_count())
            .ok_or(Error::Inconsistent(
                "block metadata has an invalid identity",
            ))?;
        let chain = reference.chain().get() as usize;
        if reference.height() < self.floors[chain] {
            return Ok(());
        }
        let entry = CustodyEntry {
            locator: BodyLocator {
                position,
                reference,
                encoded_len: meta.encoded_len(),
                offset,
                size,
            },
            header: meta.header().clone(),
        };
        if let Some(existing) = self.by_digest.get(&digest) {
            if *existing != entry {
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
        self.by_digest.insert(digest, entry);
        Ok(())
    }

    pub(super) fn advance_floors(&mut self, floors: &ChainFloors) -> Result<bool, Error> {
        if floors.0.len() != self.chain_count() {
            return Err(Error::Inconsistent("pending prune chain count differs"));
        }
        let mut changed = false;
        for (chain, floor) in floors.0.iter().enumerate() {
            let Some(floor) = floor else { continue };
            let floor = (*floor).max(self.floors[chain]);
            if floor == self.floors[chain] {
                continue;
            }
            changed = true;
            self.floors[chain] = floor;
            let retained = self.by_chain[chain].split_off(&floor);
            let removed = mem::replace(&mut self.by_chain[chain], retained);
            for digest in removed.into_values().flatten() {
                if let Some(entry) = self.by_digest.remove(&digest) {
                    self.by_position.remove(&entry.locator.position);
                }
            }
        }
        Ok(changed)
    }
}
