//! Fixed-size contiguous journal backed by V2 atomic blobs.
//!
//! Each section uses append-only checked pages. Exactly one section - the active tail - stores the
//! journal's absolute start position in its atomic root tag. Moving that marker and rewinding a
//! target section are published in one embedded batch, so recovery sees the complete old journal
//! or the complete new journal without a separate `Metadata` object.
//!
//! Appends write through to the active section but do not become reachable until `sync`. A
//! rollover may durably stage a sealed section with no marker, keeping the eventual decision
//! bounded to the prior authority and current tail. Opening derives bounds from section names,
//! the one movable marker, and committed lengths. It never scans a complete section, but validates
//! at most the final partial checked page of each section.

use super::{
    super::{Contiguous, Many, blob_first_position, position_to_blob},
    MIGRATION_NAME, MutableV2, NO_START_MARKER, decode_start_marker, encode_start_marker,
    finish_migration, fixed_migration_batch_items, legacy_cache, legacy_write_buffer,
    migration_start, partition_has_state, remove_partition, scan_partition, start_migration,
};
use crate::{
    Context,
    journal::{Error, contiguous::fixed as legacy},
};
use commonware_codec::{CodecFixedShared, DecodeExt as _};
use commonware_runtime::{
    AtomicStorage, BatchOperation, BatchStorage, Handle, IoBuf,
    buffer::paged::{ATOMIC_MARKER_LEN, AtomicSnapshot, AtomicWriter},
};
use futures::{Stream, stream};
use std::{
    collections::{BTreeMap, BTreeSet},
    marker::PhantomData,
    num::{NonZeroU16, NonZeroU64, NonZeroUsize},
    ops::Range,
};

const V2_SUFFIX: &str = "-v2";
const NO_MARKER: [u8; ATOMIC_MARKER_LEN] = NO_START_MARKER;

type Blob<E> = <E as AtomicStorage>::AtomicBlob;

/// Configuration for a V2 fixed contiguous journal.
#[derive(Clone, Debug)]
pub struct Config {
    /// Base partition name. V2 sections are stored in `{partition}-v2`.
    pub partition: String,

    /// Maximum number of items in one section.
    pub items_per_blob: NonZeroU64,

    /// Logical bytes protected by one page CRC.
    ///
    /// Use [`commonware_runtime::buffer::paged::atomic_page_size`] to align full physical pages.
    /// When migrating a legacy journal, choose the same physical page size that its `CacheRef`
    /// used (for example, legacy `page_size(4096)` maps to V2 `atomic_page_size(4096)`).
    pub page_size: NonZeroU16,
}

impl Config {
    fn v2_partition(&self) -> String {
        format!("{}{V2_SUFFIX}", self.partition)
    }
}

fn first_in_blob(start: u64, blob: u64, items_per_blob: u64) -> Result<u64, Error> {
    Ok(start.max(blob_first_position(blob, items_per_blob)?))
}

/// Immutable point-in-time view of a V2 fixed journal.
pub struct Reader<B: commonware_runtime::AtomicBlob, A> {
    blobs: BTreeMap<u64, AtomicSnapshot<B>>,
    bounds: Range<u64>,
    items_per_blob: NonZeroU64,
    _item: PhantomData<A>,
}

impl<B: commonware_runtime::AtomicBlob, A> Clone for Reader<B, A> {
    fn clone(&self) -> Self {
        Self {
            blobs: self.blobs.clone(),
            bounds: self.bounds.clone(),
            items_per_blob: self.items_per_blob,
            _item: PhantomData,
        }
    }
}

impl<B: commonware_runtime::AtomicBlob, A: CodecFixedShared> Reader<B, A> {
    fn locate(&self, position: u64) -> Result<(&AtomicSnapshot<B>, u64), Error> {
        if position < self.bounds.start {
            return Err(Error::ItemPruned(position));
        }
        if position >= self.bounds.end {
            return Err(Error::ItemOutOfRange(position));
        }
        let items_per_blob = self.items_per_blob.get();
        let blob = position_to_blob(position, items_per_blob);
        let first = first_in_blob(self.bounds.start, blob, items_per_blob)?;
        let item = position - first;
        let offset = item
            .checked_mul(A::SIZE as u64)
            .ok_or(Error::OffsetOverflow)?;
        let blob = self.blobs.get(&blob).ok_or(Error::MissingBlob(blob))?;
        Ok((blob, offset))
    }
}

fn replay_owned<B, A>(
    reader: Reader<B, A>,
    start_pos: u64,
) -> Result<impl Stream<Item = Result<(u64, A), Error>> + Send, Error>
where
    B: commonware_runtime::AtomicBlob,
    A: CodecFixedShared,
{
    if start_pos < reader.bounds.start {
        return Err(Error::ItemPruned(start_pos));
    }
    if start_pos > reader.bounds.end {
        return Err(Error::ItemOutOfRange(start_pos));
    }
    let end = reader.bounds.end;
    Ok(stream::unfold(
        (reader, start_pos),
        move |(reader, position)| async move {
            if position == end {
                return None;
            }
            let item = reader.read(position).await.map(|item| (position, item));
            Some((item, (reader, position + 1)))
        },
    ))
}

impl<B: commonware_runtime::AtomicBlob, A: CodecFixedShared> Contiguous for Reader<B, A> {
    type Item = A;

    fn bounds(&self) -> Range<u64> {
        self.bounds.clone()
    }

    async fn read(&self, position: u64) -> Result<A, Error> {
        let (blob, offset) = self.locate(position)?;
        let bytes = blob.read_at(offset, A::SIZE).await?.coalesce();
        A::decode(bytes).map_err(Error::Codec)
    }

    async fn read_many(&self, positions: &[u64]) -> Result<Vec<A>, Error> {
        assert!(
            positions.is_sorted_by(|a, b| a < b),
            "positions must be strictly increasing"
        );
        let mut items = Vec::with_capacity(positions.len());
        for &position in positions {
            items.push(self.read(position).await?);
        }
        Ok(items)
    }

    fn try_read_sync(&self, _position: u64) -> Option<A> {
        None
    }

    fn try_read_many_sync(&self, positions: &[u64]) -> Vec<Option<A>> {
        (0..positions.len()).map(|_| None).collect()
    }

    async fn replay(
        &self,
        start_pos: u64,
        _buffer: NonZeroUsize,
    ) -> Result<impl Stream<Item = Result<(u64, A), Error>> + Send, Error> {
        replay_owned(self.clone(), start_pos)
    }
}

/// Fixed-size contiguous journal using append-only V2 sections.
pub struct Journal<E, A>
where
    E: Context + BatchStorage,
    A: CodecFixedShared,
{
    context: E,
    partition: String,
    blobs: BTreeMap<u64, AtomicWriter<Blob<E>>>,
    dirty: BTreeSet<u64>,
    published_tail: u64,
    tail: u64,
    bounds: Range<u64>,
    items_per_blob: NonZeroU64,
    page_size: NonZeroU16,
    active: bool,
    _item: PhantomData<A>,
}

impl<E, A> std::fmt::Debug for Journal<E, A>
where
    E: Context + BatchStorage,
    A: CodecFixedShared,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Journal")
            .field("bounds", &self.bounds)
            .finish_non_exhaustive()
    }
}

impl<E, A> Journal<E, A>
where
    E: Context + BatchStorage,
    A: CodecFixedShared,
{
    fn validate_item_size() -> Result<(), Error> {
        if A::SIZE == 0 {
            return Err(Error::InvalidConfiguration(
                "fixed journal items must be non-empty".into(),
            ));
        }
        Ok(())
    }

    async fn open_blob(
        context: &E,
        partition: &str,
        index: u64,
        page_size: NonZeroU16,
    ) -> Result<AtomicWriter<Blob<E>>, Error> {
        let (blob, physical_size) = context.open_atomic(partition, &index.to_be_bytes()).await?;
        Ok(AtomicWriter::new(blob, physical_size, page_size).await?)
    }

    async fn fresh(
        context: E,
        partition: String,
        items_per_blob: NonZeroU64,
        page_size: NonZeroU16,
        start: u64,
        active: bool,
    ) -> Result<Self, Error> {
        let tail = position_to_blob(start, items_per_blob.get());
        let writer = Self::open_blob(&context, &partition, tail, page_size).await?;
        let marker = if active {
            encode_start_marker(start)?
        } else {
            NO_MARKER
        };
        let writer = writer.set_marker(marker).await?;
        writer.sync().await?;
        Ok(Self {
            context,
            partition,
            blobs: BTreeMap::from([(tail, writer)]),
            dirty: BTreeSet::new(),
            published_tail: tail,
            tail,
            bounds: start..start,
            items_per_blob,
            page_size,
            active,
            _item: PhantomData,
        })
    }

    async fn open_existing(
        context: E,
        cfg: &Config,
        names: Vec<Vec<u8>>,
        staging_start: Option<u64>,
    ) -> Result<Option<Self>, Error> {
        Self::validate_item_size()?;
        let partition = cfg.v2_partition();

        let mut blobs = BTreeMap::new();
        let mut authority = None;
        for name in names.into_iter().filter(|name| name != MIGRATION_NAME) {
            let printable = commonware_formatting::hex(&name);
            let name: [u8; 8] = name
                .try_into()
                .map_err(|_| Error::InvalidBlobName(printable))?;
            let index = u64::from_be_bytes(name);
            let writer = Self::open_blob(&context, &partition, index, cfg.page_size).await?;
            if let Some(start) = decode_start_marker(writer.marker())?
                && authority.replace((index, start)).is_some()
            {
                return Err(Error::Corruption("multiple V2 journal tail markers".into()));
            }
            blobs.insert(index, writer);
        }
        if blobs.is_empty() {
            return Ok(None);
        }

        let (tail, start, active) = match authority {
            Some((tail, start)) => {
                if let Some(staging_start) = staging_start
                    && start != staging_start
                {
                    return Err(Error::Corruption(
                        "activated V2 fixed journal disagrees with migration start".into(),
                    ));
                }
                (tail, start, true)
            }
            None if let Some(start) = staging_start => {
                let oldest = position_to_blob(start, cfg.items_per_blob.get());
                let mut expected = oldest;
                let mut tail = None;
                let indices = blobs.keys().copied().collect::<Vec<_>>();
                for index in indices {
                    if index != expected || tail.is_some() {
                        context
                            .remove(&partition, Some(&index.to_be_bytes()))
                            .await?;
                        blobs.remove(&index);
                        continue;
                    }
                    let writer = blobs.get(&index).expect("staging section exists");
                    if writer.marker() != NO_MARKER || writer.size() % A::SIZE as u64 != 0 {
                        return Err(Error::InvalidBlobSize(index, writer.size()));
                    }
                    let first = first_in_blob(start, index, cfg.items_per_blob.get())?;
                    let natural_start = blob_first_position(index, cfg.items_per_blob.get())?;
                    let capacity = cfg.items_per_blob.get() - (first - natural_start);
                    let count = writer.size() / A::SIZE as u64;
                    if count > capacity {
                        return Err(Error::InvalidBlobSize(index, writer.size()));
                    }
                    if count < capacity {
                        tail = Some(index);
                    } else {
                        expected = index.checked_add(1).ok_or(Error::OffsetOverflow)?;
                    }
                }
                let tail = match tail {
                    Some(tail) => tail,
                    None => {
                        let writer =
                            Self::open_blob(&context, &partition, expected, cfg.page_size).await?;
                        if writer.size() != 0 || writer.marker() != NO_MARKER {
                            return Err(Error::Corruption(
                                "V2 fixed migration tail is not empty".into(),
                            ));
                        }
                        blobs.insert(expected, writer);
                        expected
                    }
                };
                (tail, start, false)
            }
            None => {
                if blobs.values().any(|writer| writer.size() != 0) {
                    return Err(Error::Corruption(
                        "non-empty V2 fixed sections have no tail marker".into(),
                    ));
                }
                for index in blobs.keys().copied().collect::<Vec<_>>() {
                    context
                        .remove(&partition, Some(&index.to_be_bytes()))
                        .await?;
                }
                return Ok(None);
            }
        };
        if !active && blobs.values().any(|writer| writer.marker() != NO_MARKER) {
            return Err(Error::Corruption(
                "V2 fixed migration has an unexpected marker".into(),
            ));
        }

        if active
            && blobs
                .values()
                .filter(|writer| writer.marker() != NO_MARKER)
                .count()
                != 1
        {
            return Err(Error::Corruption(
                "V2 fixed journal has an invalid tail marker".into(),
            ));
        }

        if !active && !blobs.contains_key(&tail) {
            return Err(Error::MissingBlob(tail));
        }

        if !active
            && blobs.keys().next().copied()
                != Some(position_to_blob(start, cfg.items_per_blob.get()))
        {
            return Err(Error::Corruption(
                "V2 fixed migration does not begin at its recorded start".into(),
            ));
        }

        if blobs.is_empty() {
            return Err(Error::Corruption("V2 fixed journal has no sections".into()));
        }

        if active && tail < position_to_blob(start, cfg.items_per_blob.get()) {
            return Err(Error::Corruption(
                "V2 tail marker precedes the journal start".into(),
            ));
        }

        if active {
            for writer in blobs.values() {
                if writer.marker() != NO_MARKER
                    && decode_start_marker(writer.marker())? != Some(start)
                {
                    return Err(Error::Corruption(
                        "V2 fixed tail marker changed during open".into(),
                    ));
                }
            }
        }

        let items_per_blob = cfg.items_per_blob.get();
        let oldest = position_to_blob(start, items_per_blob);
        if tail < oldest {
            return Err(Error::Corruption(
                "V2 tail marker precedes the journal start".into(),
            ));
        }

        let mut expected = oldest;
        for (&index, writer) in blobs.range(oldest..=tail) {
            if index != expected {
                return Err(Error::MissingBlob(expected));
            }
            if writer.size() % A::SIZE as u64 != 0 {
                return Err(Error::InvalidBlobSize(index, writer.size()));
            }
            let first = first_in_blob(start, index, items_per_blob)?;
            let natural_start = blob_first_position(index, items_per_blob)?;
            let capacity = items_per_blob - (first - natural_start);
            let count = writer.size() / A::SIZE as u64;
            if index != tail && count != capacity {
                return Err(Error::InvalidBlobSize(index, writer.size()));
            }
            if index == tail && count >= capacity {
                return Err(Error::InvalidBlobSize(index, writer.size()));
            }
            if index == tail {
                break;
            }
            expected = index.checked_add(1).ok_or(Error::OffsetOverflow)?;
        }

        let tail_writer = blobs.get(&tail).ok_or(Error::MissingBlob(tail))?;
        let tail_first = first_in_blob(start, tail, items_per_blob)?;
        let end = tail_first
            .checked_add(tail_writer.size() / A::SIZE as u64)
            .ok_or(Error::SizeOverflow)?;

        if active {
            for index in blobs
                .keys()
                .copied()
                .filter(|index| *index < oldest || *index > tail)
                .collect::<Vec<_>>()
            {
                context
                    .remove(&partition, Some(&index.to_be_bytes()))
                    .await?;
                blobs.remove(&index);
            }
        }

        Ok(Some(Self {
            context,
            partition,
            blobs,
            dirty: BTreeSet::new(),
            published_tail: tail,
            tail,
            bounds: start..end,
            items_per_blob: cfg.items_per_blob,
            page_size: cfg.page_size,
            active,
            _item: PhantomData,
        }))
    }

    fn legacy_partitions(partition: &str) -> [String; 3] {
        [
            partition.to_owned(),
            format!("{partition}-blobs"),
            format!("{partition}-metadata"),
        ]
    }

    fn legacy_config(context: &E, cfg: &Config) -> Result<legacy::Config, Error> {
        Ok(legacy::Config {
            partition: cfg.partition.clone(),
            items_per_blob: cfg.items_per_blob,
            page_cache: legacy_cache(context, cfg.page_size)?,
            write_buffer: legacy_write_buffer(cfg.page_size)?,
        })
    }

    async fn cleanup_legacy(context: &E, partition: &str) -> Result<(), Error> {
        for partition in Self::legacy_partitions(partition) {
            remove_partition(context, &partition).await?;
        }
        Ok(())
    }

    async fn activate(mut self) -> Result<Self, Error> {
        if self.active {
            return Ok(self);
        }
        let writer = self
            .blobs
            .remove(&self.tail)
            .expect("migration tail exists");
        let writer = writer
            .set_marker(encode_start_marker(self.bounds.start)?)
            .await?;
        self.blobs.insert(self.tail, writer);
        self.dirty.insert(self.tail);
        self.apply_dirty().await?;
        self.published_tail = self.tail;
        self.active = true;
        Ok(self)
    }

    async fn migrate_legacy(
        mut legacy: legacy::Journal<E, A>,
        mut target: Self,
        cfg: &Config,
    ) -> Result<Self, Error> {
        let source = legacy.bounds();
        if target.bounds.start > source.start
            || target.bounds.end < source.start
            || target.bounds.end > source.end
        {
            return Err(Error::Corruption(format!(
                "fixed migration ranges disagree: staged={:?} legacy={source:?}",
                target.bounds
            )));
        }

        while target.bounds.end < source.end {
            let remaining_in_section =
                cfg.items_per_blob.get() - (target.bounds.end % cfg.items_per_blob.get());
            let count = (source.end - target.bounds.end)
                .min(remaining_in_section)
                .min(fixed_migration_batch_items(A::SIZE) as u64);
            let count = usize::try_from(count).map_err(|_| Error::UsizeTooSmall)?;
            let capacity = count.checked_mul(A::SIZE).ok_or(Error::OffsetOverflow)?;
            let mut bytes = Vec::with_capacity(capacity);
            for position in target.bounds.end..target.bounds.end + count as u64 {
                legacy.read(position).await?.write(&mut bytes);
            }
            (target, _) = target.append_encoded(bytes.into(), count).await?;

            if target.bounds.end.is_multiple_of(cfg.items_per_blob.get()) {
                target = target.sync().await?;
                (legacy, _) = legacy.prune(target.bounds.end).await?;
            }
        }

        target = target.sync().await?.activate().await?;
        drop(legacy);
        Self::cleanup_legacy(&target.context, &cfg.partition).await?;
        finish_migration(&target.context, &target.partition).await?;
        Ok(target)
    }

    async fn init_inner(context: E, cfg: Config) -> Result<Self, Error> {
        Self::validate_item_size()?;
        let partition = cfg.v2_partition();
        let names = scan_partition(&context, &partition).await?;
        let witness = migration_start(&context, &partition, &names).await?;
        let staging_start = witness.flatten();
        let existing =
            Self::open_existing(context.child("v2_open"), &cfg, names, staging_start).await?;

        if existing.as_ref().is_some_and(|journal| journal.active) {
            let journal = existing.expect("active journal exists");
            if witness.is_some() {
                Self::cleanup_legacy(&journal.context, &cfg.partition).await?;
                finish_migration(&journal.context, &journal.partition).await?;
            }
            return Ok(journal);
        }

        let legacy_partitions = Self::legacy_partitions(&cfg.partition);
        if !partition_has_state(&context, &legacy_partitions).await? {
            if witness.is_some() {
                return Err(Error::Corruption(
                    "fixed migration witness has neither legacy nor active V2 state".into(),
                ));
            }
            return Self::fresh(
                context,
                partition,
                cfg.items_per_blob,
                cfg.page_size,
                0,
                true,
            )
            .await;
        }

        let legacy = legacy::Journal::<E, A>::init(
            context.child("legacy"),
            Self::legacy_config(&context, &cfg)?,
        )
        .await?;
        let source = legacy.bounds();
        let start = match witness {
            Some(Some(start)) => start,
            Some(None) | None => {
                start_migration(&context, &partition, source.start).await?;
                source.start
            }
        };
        if start != source.start && existing.is_none() {
            return Err(Error::Corruption(
                "fixed migration start no longer matches legacy state".into(),
            ));
        }

        let target = match existing {
            Some(target) => target,
            None => {
                Self::fresh(
                    context.child("v2_migrate"),
                    partition,
                    cfg.items_per_blob,
                    cfg.page_size,
                    start,
                    false,
                )
                .await?
            }
        };
        Self::migrate_legacy(legacy, target, &cfg).await
    }

    /// Open or create a V2 fixed journal, eagerly migrating any recovered legacy journal.
    ///
    /// A successful migration removes the same-base legacy partitions, so selecting V2 is
    /// forward-only for this journal.
    pub async fn init(context: E, cfg: Config) -> Result<Self, Error> {
        Self::init_inner(context, cfg).await
    }

    /// Open the journal and atomically reset it to an empty state at `size`.
    pub async fn init_at_size(context: E, cfg: Config, size: u64) -> Result<Self, Error> {
        if size == u64::MAX {
            return Err(Error::SizeOverflow);
        }
        let journal = Self::init_inner(context, cfg).await?;
        if journal.bounds == (size..size) {
            return Ok(journal);
        }
        journal.clear_to_size(size).await
    }

    /// Return the next append position.
    pub const fn size(&self) -> u64 {
        self.bounds.end
    }

    /// Return an immutable point-in-time reader.
    pub fn snapshot(&self) -> Reader<Blob<E>, A> {
        Reader {
            blobs: self
                .blobs
                .iter()
                .map(|(&index, blob)| (index, blob.snapshot()))
                .collect(),
            bounds: self.bounds.clone(),
            items_per_blob: self.items_per_blob,
            _item: PhantomData,
        }
    }

    async fn rollover(mut self) -> Result<Self, Error> {
        let old_index = self.tail;
        let next = self.tail.checked_add(1).ok_or(Error::SizeOverflow)?;
        let marker = if self.active {
            encode_start_marker(self.bounds.start)?
        } else {
            NO_MARKER
        };
        let old = self.blobs.remove(&self.tail).expect("tail must exist");
        let old = old.set_marker(NO_MARKER).await?;
        let new = Self::open_blob(&self.context, &self.partition, next, self.page_size).await?;
        if new.size() != 0 || new.marker() != NO_MARKER {
            return Err(Error::Corruption(
                "V2 rollover target is not an empty unmarked section".into(),
            ));
        }
        let new = new.set_marker(marker).await?;
        if old_index == self.published_tail {
            self.dirty.insert(old_index);
        } else {
            // This section was created after the last publication, so its committed root is still
            // empty and unmarked. Persisting its final unmarked root cannot make it reachable, but
            // keeps the eventual marker-transfer group bounded to the old and new authorities.
            old.sync().await?;
            self.dirty.remove(&old_index);
        }
        self.blobs.insert(old_index, old);
        self.blobs.insert(next, new);
        self.dirty.insert(next);
        self.tail = next;
        Ok(self)
    }

    fn dirty_operations(&self) -> Vec<BatchOperation<Blob<E>>> {
        self.dirty
            .iter()
            .map(|index| {
                let writer = self.blobs.get(index).expect("dirty section must exist");
                BatchOperation::Publish(writer.blob().clone())
            })
            .collect()
    }

    async fn apply_dirty(&mut self) -> Result<(), Error> {
        match self.dirty.len() {
            0 => return Ok(()),
            1 => {
                let index = *self.dirty.first().expect("one dirty section must exist");
                self.blobs
                    .get(&index)
                    .expect("dirty section must exist")
                    .sync()
                    .await?;
            }
            _ => self.context.apply(self.dirty_operations()).await?,
        }
        self.dirty.clear();
        Ok(())
    }

    async fn append_encoded(mut self, bytes: IoBuf, items: usize) -> Result<(Self, u64), Error> {
        if items == 0 {
            return Err(Error::EmptyAppend);
        }
        self.bounds
            .end
            .checked_add(items as u64)
            .ok_or(Error::SizeOverflow)?;
        let mut written = 0usize;
        while written < items {
            let count = super::super::batch_count_to_blob_boundary(
                self.bounds.end,
                items - written,
                self.items_per_blob.get(),
            );
            let start = written.checked_mul(A::SIZE).ok_or(Error::OffsetOverflow)?;
            let end = start
                .checked_add(count.checked_mul(A::SIZE).ok_or(Error::OffsetOverflow)?)
                .ok_or(Error::OffsetOverflow)?;
            let writer = self.blobs.remove(&self.tail).expect("tail must exist");
            let (writer, _) = writer.append_owned(bytes.slice(start..end)).await?;
            self.blobs.insert(self.tail, writer);
            self.dirty.insert(self.tail);
            self.bounds.end += count as u64;
            written += count;
            if self.bounds.end.is_multiple_of(self.items_per_blob.get()) {
                self = self.rollover().await?;
            }
        }
        let position = self.bounds.end - 1;
        Ok((self, position))
    }

    /// Append one item.
    pub async fn append(self, item: &A) -> Result<(Self, u64), Error> {
        let mut bytes = Vec::with_capacity(A::SIZE);
        item.write(&mut bytes);
        self.append_encoded(bytes.into(), 1).await
    }

    /// Append one or more item slices.
    pub async fn append_many(self, items: Many<'_, A>) -> Result<(Self, u64), Error> {
        let count = items.len();
        let capacity = count.checked_mul(A::SIZE).ok_or(Error::OffsetOverflow)?;
        let mut bytes = Vec::with_capacity(capacity);
        match items {
            Many::Flat(items) => {
                for item in items {
                    item.write(&mut bytes);
                }
            }
            Many::Nested(groups) => {
                for group in groups {
                    for item in *group {
                        item.write(&mut bytes);
                    }
                }
            }
        }
        self.append_encoded(bytes.into(), count).await
    }

    /// Begin publishing all pending bytes and the current root tag.
    pub async fn start_sync(mut self) -> Result<(Self, Handle<()>), Error> {
        let handle = match self.dirty.len() {
            0 => Handle::ready(Ok(())),
            1 => {
                let index = *self.dirty.first().expect("one dirty section must exist");
                self.blobs
                    .get(&index)
                    .expect("dirty section must exist")
                    .start_sync()
                    .await
            }
            _ => {
                let handle = self.context.start_apply(self.dirty_operations()).await?;
                self.published_tail = self.tail;
                handle
            }
        };
        self.dirty.clear();
        Ok((self, handle))
    }

    /// Publish all pending bytes and the current root tag.
    pub async fn sync(self) -> Result<Self, Error> {
        let (journal, completion) = self.start_sync().await?;
        completion.await?;
        Ok(journal)
    }

    /// Prune complete sections strictly before `min_position`.
    pub async fn prune(mut self, min_position: u64) -> Result<(Self, bool), Error> {
        let target = position_to_blob(min_position, self.items_per_blob.get()).min(self.tail);
        let oldest = position_to_blob(self.bounds.start, self.items_per_blob.get());
        if target <= oldest {
            return Ok((self, false));
        }
        let start = blob_first_position(target, self.items_per_blob.get())?;
        let writer = self.blobs.remove(&self.tail).expect("tail must exist");
        let writer = writer.set_marker(encode_start_marker(start)?).await?;
        self.blobs.insert(self.tail, writer);
        self.dirty.insert(self.tail);
        self.apply_dirty().await?;
        self.published_tail = self.tail;
        for index in self
            .blobs
            .keys()
            .copied()
            .filter(|index| *index < target)
            .collect::<Vec<_>>()
        {
            self.context
                .remove(&self.partition, Some(&index.to_be_bytes()))
                .await?;
            self.blobs.remove(&index);
        }
        self.bounds.start = start;
        Ok((self, true))
    }

    /// Rewind to `size`, atomically moving the active-tail marker when needed.
    pub async fn rewind(mut self, size: u64) -> Result<Self, Error> {
        if size > self.bounds.end {
            return Err(Error::InvalidRewind(size));
        }
        if size < self.bounds.start {
            return Err(Error::ItemPruned(size));
        }
        if size == self.bounds.end {
            return Ok(self);
        }
        let target = position_to_blob(size, self.items_per_blob.get());
        let first = first_in_blob(self.bounds.start, target, self.items_per_blob.get())?;
        let logical_size = (size - first)
            .checked_mul(A::SIZE as u64)
            .ok_or(Error::OffsetOverflow)?;
        let marker = encode_start_marker(self.bounds.start)?;
        let stale = self
            .blobs
            .keys()
            .copied()
            .filter(|index| *index > target)
            .collect::<Vec<_>>();

        let target_writer = self
            .blobs
            .remove(&target)
            .ok_or(Error::MissingBlob(target))?;
        let target_writer = target_writer.rewind(logical_size).await?;
        let target_writer = target_writer.set_marker(marker).await?;
        self.blobs.insert(target, target_writer);
        self.dirty.insert(target);
        if target != self.tail {
            let old = self.blobs.remove(&self.tail).expect("tail must exist");
            let old = old.set_marker(NO_MARKER).await?;
            self.blobs.insert(self.tail, old);
            self.dirty.insert(self.tail);
        }
        self.apply_dirty().await?;
        self.published_tail = target;
        for index in stale {
            self.context
                .remove(&self.partition, Some(&index.to_be_bytes()))
                .await?;
            self.blobs.remove(&index);
        }
        self.tail = target;
        self.bounds.end = size;
        Ok(self)
    }

    /// Atomically discard all items and reposition the empty journal at `size`.
    pub async fn clear_to_size(mut self, size: u64) -> Result<Self, Error> {
        if size == u64::MAX {
            return Err(Error::SizeOverflow);
        }
        let target = position_to_blob(size, self.items_per_blob.get());
        if !self.blobs.contains_key(&target) {
            let writer =
                Self::open_blob(&self.context, &self.partition, target, self.page_size).await?;
            if writer.size() != 0 || writer.marker() != NO_MARKER {
                return Err(Error::Corruption(
                    "V2 clear target is not an empty unmarked section".into(),
                ));
            }
            self.blobs.insert(target, writer);
        }
        let stale = self
            .blobs
            .keys()
            .copied()
            .filter(|index| *index != target)
            .collect::<Vec<_>>();
        let writer = self.blobs.remove(&target).expect("target must exist");
        let writer = writer.rewind(0).await?;
        let writer = writer.set_marker(encode_start_marker(size)?).await?;
        self.blobs.insert(target, writer);
        self.dirty.insert(target);
        if target != self.tail {
            let old = self.blobs.remove(&self.tail).expect("tail must exist");
            let old = old.set_marker(NO_MARKER).await?;
            self.blobs.insert(self.tail, old);
            self.dirty.insert(self.tail);
        }
        self.apply_dirty().await?;
        self.published_tail = target;
        for index in stale {
            self.context
                .remove(&self.partition, Some(&index.to_be_bytes()))
                .await?;
            self.blobs.remove(&index);
        }
        self.tail = target;
        self.bounds = size..size;
        Ok(self)
    }

    /// Remove the V2 journal and any same-base legacy partitions.
    pub async fn destroy(self) -> Result<(), Error> {
        let base_partition = self
            .partition
            .strip_suffix(V2_SUFFIX)
            .expect("V2 fixed partition has its suffix");
        Self::cleanup_legacy(&self.context, base_partition).await?;
        self.context.remove(&self.partition, None).await?;
        Ok(())
    }
}

impl<E, A> Contiguous for Journal<E, A>
where
    E: Context + BatchStorage,
    A: CodecFixedShared,
{
    type Item = A;

    fn bounds(&self) -> Range<u64> {
        self.bounds.clone()
    }

    async fn read(&self, position: u64) -> Result<A, Error> {
        self.snapshot().read(position).await
    }

    async fn read_many(&self, positions: &[u64]) -> Result<Vec<A>, Error> {
        self.snapshot().read_many(positions).await
    }

    fn try_read_sync(&self, _position: u64) -> Option<A> {
        None
    }

    fn try_read_many_sync(&self, positions: &[u64]) -> Vec<Option<A>> {
        (0..positions.len()).map(|_| None).collect()
    }

    async fn replay(
        &self,
        start_pos: u64,
        _buffer: NonZeroUsize,
    ) -> Result<impl Stream<Item = Result<(u64, A), Error>> + Send, Error> {
        replay_owned(self.snapshot(), start_pos)
    }
}

impl<E, A> MutableV2 for Journal<E, A>
where
    E: Context + BatchStorage,
    A: CodecFixedShared,
{
    async fn append(self, item: &A) -> Result<(Self, u64), Error> {
        Self::append(self, item).await
    }

    async fn append_many(self, items: Many<'_, A>) -> Result<(Self, u64), Error> {
        Self::append_many(self, items).await
    }

    async fn prune(self, min_position: u64) -> Result<(Self, bool), Error> {
        Self::prune(self, min_position).await
    }

    async fn rewind(self, size: u64) -> Result<Self, Error> {
        Self::rewind(self, size).await
    }

    async fn start_sync(self) -> Result<(Self, Handle<()>), Error> {
        Self::start_sync(self).await
    }

    async fn sync(self) -> Result<Self, Error> {
        Self::sync(self).await
    }

    async fn destroy(self) -> Result<(), Error> {
        Self::destroy(self).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::journal::contiguous::fixed as legacy;
    use commonware_runtime::{
        Runner as _, Storage as _, Supervisor as _,
        buffer::paged::{CacheRef, atomic_page_size, page_size},
        deterministic,
    };
    use commonware_utils::{NZU64, NZUsize, sequence::FixedBytes};
    use futures::StreamExt as _;

    type Item = FixedBytes<8>;

    fn config(partition: &str) -> Config {
        Config {
            partition: partition.into(),
            items_per_blob: NZU64!(3),
            page_size: atomic_page_size(64),
        }
    }

    fn item(value: u8) -> Item {
        FixedBytes::new([value; 8])
    }

    #[test]
    fn migration_batches_are_bounded_by_items_and_bytes() {
        assert_eq!(
            fixed_migration_batch_items(1),
            super::super::MIGRATION_BATCH_ITEMS
        );
        assert_eq!(
            fixed_migration_batch_items(super::super::MIGRATION_BATCH_BYTES / 2),
            2
        );
        assert_eq!(
            fixed_migration_batch_items(super::super::MIGRATION_BATCH_BYTES + 1),
            1
        );
    }

    #[test]
    fn init_migrates_recovered_legacy_sections_and_removes_legacy_state() {
        deterministic::Runner::default().start(|context| async move {
            let cfg = config("v2_fixed_migrate_legacy");
            let legacy_cfg = legacy::Config {
                partition: cfg.partition.clone(),
                items_per_blob: cfg.items_per_blob,
                page_cache: CacheRef::from_pooler(&context, page_size(64), NZUsize!(3)),
                write_buffer: NZUsize!(128),
            };
            let mut legacy = legacy::Journal::init(context.child("legacy"), legacy_cfg)
                .await
                .unwrap();
            for value in 0..8 {
                (legacy, _) = legacy.append(&item(value)).await.unwrap();
            }
            (legacy, _) = legacy.prune(4).await.unwrap();
            legacy = legacy.sync().await.unwrap();
            assert_eq!(legacy.bounds(), 3..8);
            drop(legacy);

            let journal = Journal::<_, Item>::init(context.child("migrate"), cfg.clone())
                .await
                .unwrap();
            assert_eq!(journal.bounds(), 3..8);
            assert_eq!(
                journal.read_many(&[3, 4, 5, 6, 7]).await.unwrap(),
                (3..8).map(item).collect::<Vec<_>>()
            );
            drop(journal);

            for partition in [
                cfg.partition.clone(),
                format!("{}-blobs", cfg.partition),
                format!("{}-metadata", cfg.partition),
            ] {
                assert!(matches!(
                    context.scan(&partition).await,
                    Err(commonware_runtime::Error::PartitionMissing(_))
                ));
            }

            let journal = Journal::<_, Item>::init(context.child("reopen"), cfg)
                .await
                .unwrap();
            assert_eq!(journal.bounds(), 3..8);
            journal.destroy().await.unwrap();
        });
    }

    #[test]
    fn init_resumes_after_a_staged_section_replaced_its_legacy_source() {
        deterministic::Runner::default().start(|context| async move {
            let cfg = config("v2_fixed_resume_migration");
            let legacy_cfg = legacy::Config {
                partition: cfg.partition.clone(),
                items_per_blob: cfg.items_per_blob,
                page_cache: CacheRef::from_pooler(&context, page_size(64), NZUsize!(3)),
                write_buffer: NZUsize!(128),
            };
            let values = (0..8).map(item).collect::<Vec<_>>();
            let legacy = legacy::Journal::init(context.child("legacy"), legacy_cfg)
                .await
                .unwrap();
            let (legacy, _) = legacy.append_many(Many::Flat(&values)).await.unwrap();
            let mut legacy = legacy.sync().await.unwrap();

            let partition = cfg.v2_partition();
            start_migration(&context, &partition, 0).await.unwrap();
            let target = Journal::<_, Item>::fresh(
                context.child("stage"),
                partition,
                cfg.items_per_blob,
                cfg.page_size,
                0,
                false,
            )
            .await
            .unwrap();
            let (target, _) = target.append_many(Many::Flat(&values[..3])).await.unwrap();
            let target = target.sync().await.unwrap();
            (legacy, _) = legacy.prune(3).await.unwrap();
            assert_eq!(target.bounds(), 0..3);
            assert_eq!(legacy.bounds(), 3..8);
            drop(target);
            drop(legacy);

            let journal = Journal::<_, Item>::init(context.child("resume"), cfg)
                .await
                .unwrap();
            assert_eq!(journal.bounds(), 0..8);
            assert_eq!(
                journal.read_many(&[0, 2, 3, 5, 7]).await.unwrap(),
                vec![item(0), item(2), item(3), item(5), item(7),]
            );
            journal.destroy().await.unwrap();
        });
    }

    #[test]
    fn init_migrates_an_empty_legacy_journal_at_a_nonzero_start() {
        deterministic::Runner::default().start(|context| async move {
            let cfg = config("v2_fixed_migrate_empty_at_size");
            let legacy_cfg = legacy::Config {
                partition: cfg.partition.clone(),
                items_per_blob: cfg.items_per_blob,
                page_cache: CacheRef::from_pooler(&context, page_size(64), NZUsize!(3)),
                write_buffer: NZUsize!(128),
            };
            let legacy =
                legacy::Journal::<_, Item>::init_at_size(context.child("legacy"), legacy_cfg, 5)
                    .await
                    .unwrap();
            assert_eq!(legacy.bounds(), 5..5);
            drop(legacy);

            let journal = Journal::<_, Item>::init(context.child("migrate"), cfg)
                .await
                .unwrap();
            assert_eq!(journal.bounds(), 5..5);
            journal.destroy().await.unwrap();
        });
    }

    #[test]
    fn activated_migration_cleans_legacy_without_reopening_it() {
        deterministic::Runner::default().start(|context| async move {
            let cfg = config("v2_fixed_activated_cleanup");
            let legacy_cfg = legacy::Config {
                partition: cfg.partition.clone(),
                items_per_blob: cfg.items_per_blob,
                page_cache: CacheRef::from_pooler(&context, page_size(64), NZUsize!(3)),
                write_buffer: NZUsize!(128),
            };
            let values = [item(0), item(1)];
            let legacy = legacy::Journal::init(context.child("legacy"), legacy_cfg)
                .await
                .unwrap();
            let (legacy, _) = legacy.append_many(Many::Flat(&values)).await.unwrap();
            let legacy = legacy.sync().await.unwrap();

            let partition = cfg.v2_partition();
            start_migration(&context, &partition, 0).await.unwrap();
            let target = Journal::<_, Item>::fresh(
                context.child("stage"),
                partition,
                cfg.items_per_blob,
                cfg.page_size,
                0,
                false,
            )
            .await
            .unwrap();
            let (target, _) = target.append_many(Many::Flat(&values)).await.unwrap();
            let target = target.sync().await.unwrap().activate().await.unwrap();
            drop(target);
            drop(legacy);

            // Normal legacy recovery rejects this name. Once V2 is active, init must skip that
            // recovery and finish idempotent cleanup from V2 authority.
            let (bad, _) = context
                .open(&format!("{}-blobs", cfg.partition), b"bad-name")
                .await
                .unwrap();
            drop(bad);
            let journal = Journal::<_, Item>::init(context.child("cleanup"), cfg)
                .await
                .unwrap();
            assert_eq!(journal.bounds(), 0..2);
            assert_eq!(journal.read_many(&[0, 1]).await.unwrap(), values);
            journal.destroy().await.unwrap();
        });
    }

    #[test]
    fn destroy_prevents_stale_legacy_state_from_reappearing() {
        deterministic::Runner::default().start(|context| async move {
            let cfg = config("v2_fixed_destroy_legacy");
            let legacy_cfg = legacy::Config {
                partition: cfg.partition.clone(),
                items_per_blob: cfg.items_per_blob,
                page_cache: CacheRef::from_pooler(&context, page_size(64), NZUsize!(3)),
                write_buffer: NZUsize!(128),
            };
            let legacy = legacy::Journal::init(context.child("legacy"), legacy_cfg)
                .await
                .unwrap();
            let (legacy, _) = legacy.append(&item(1)).await.unwrap();
            let legacy = legacy.sync().await.unwrap();
            drop(legacy);

            // Simulate V2 state created before transparent migration owned the base namespace.
            let journal = Journal::<_, Item>::fresh(
                context.child("v2"),
                cfg.v2_partition(),
                cfg.items_per_blob,
                cfg.page_size,
                0,
                true,
            )
            .await
            .unwrap();
            let (journal, _) = journal.append(&item(9)).await.unwrap();
            journal.sync().await.unwrap().destroy().await.unwrap();

            let journal = Journal::<_, Item>::init(context.child("reopen"), cfg)
                .await
                .unwrap();
            assert_eq!(journal.bounds(), 0..0);
            journal.destroy().await.unwrap();
        });
    }

    #[test]
    fn lifecycle_reopens_without_metadata() {
        deterministic::Runner::default().start(|context| async move {
            let cfg = config("v2_fixed_lifecycle");
            let mut journal = Journal::init(context.child("initial"), cfg.clone())
                .await
                .unwrap();
            for value in 0..8 {
                (journal, _) = journal.append(&item(value)).await.unwrap();
            }
            assert_eq!(journal.bounds(), 0..8);
            assert_eq!(journal.read(4).await.unwrap(), item(4));
            journal = journal.sync().await.unwrap();

            let replayed = journal
                .replay(2, NonZeroUsize::new(64).unwrap())
                .await
                .unwrap()
                .collect::<Vec<_>>()
                .await;
            assert_eq!(replayed.len(), 6);
            assert_eq!(replayed[0].as_ref().unwrap(), &(2, item(2)));
            drop(journal);

            assert!(matches!(
                context.scan("v2_fixed_lifecycle-metadata").await,
                Err(commonware_runtime::Error::PartitionMissing(_))
            ));
            let mut journal = Journal::init(context.child("reopen"), cfg.clone())
                .await
                .unwrap();
            assert_eq!(journal.bounds(), 0..8);
            assert_eq!(journal.read(7).await.unwrap(), item(7));

            let (next, pruned) = journal.prune(4).await.unwrap();
            journal = next;
            assert!(pruned);
            assert_eq!(journal.bounds(), 3..8);
            journal = journal.rewind(4).await.unwrap();
            assert_eq!(journal.bounds(), 3..4);
            (journal, _) = journal.append(&item(9)).await.unwrap();
            journal = journal.sync().await.unwrap();
            assert_eq!(journal.read(4).await.unwrap(), item(9));

            journal = journal.clear_to_size(2).await.unwrap();
            assert_eq!(journal.bounds(), 2..2);
            drop(journal);
            let journal =
                Journal::<_, Item>::init(context.child("reopen_after_clear"), cfg.clone())
                    .await
                    .unwrap();
            assert_eq!(journal.bounds(), 2..2);

            let journal = Journal::<_, Item>::init_at_size(context.child("reinitialize"), cfg, 7)
                .await
                .unwrap();
            assert_eq!(journal.bounds(), 7..7);
            journal.destroy().await.unwrap();
        });
    }

    #[test]
    fn reopens_when_the_empty_tail_has_the_maximum_section_index() {
        deterministic::Runner::default().start(|context| async move {
            let mut cfg = config("v2_fixed_maximum_tail");
            cfg.items_per_blob = NZU64!(1);
            let journal = Journal::<_, Item>::init_at_size(
                context.child("initial"),
                cfg.clone(),
                u64::MAX - 1,
            )
            .await
            .unwrap();
            let (journal, position) = journal.append(&item(1)).await.unwrap();
            assert_eq!(position, u64::MAX - 1);
            let journal = journal.sync().await.unwrap();
            assert_eq!(journal.tail, u64::MAX);
            drop(journal);

            let journal = Journal::<_, Item>::init(context.child("reopen"), cfg)
                .await
                .unwrap();
            assert_eq!(journal.bounds(), (u64::MAX - 1)..u64::MAX);
            journal.destroy().await.unwrap();
        });
    }

    #[test]
    fn marker_transfer_cleans_unreachable_sections() {
        deterministic::Runner::default().start(|context| async move {
            let cfg = config("v2_fixed_cleanup");
            let mut journal = Journal::init(context.child("initial"), cfg.clone())
                .await
                .unwrap();
            for value in 0..7 {
                (journal, _) = journal.append(&item(value)).await.unwrap();
            }
            journal = journal.sync().await.unwrap();
            assert_eq!(context.scan("v2_fixed_cleanup-v2").await.unwrap().len(), 3);

            journal = journal.rewind(2).await.unwrap();
            assert_eq!(journal.bounds(), 0..2);
            assert_eq!(context.scan("v2_fixed_cleanup-v2").await.unwrap().len(), 1);
            drop(journal);

            let journal = Journal::<_, Item>::init(context.child("reopen"), cfg)
                .await
                .unwrap();
            assert_eq!(journal.bounds(), 0..2);
            assert_eq!(journal.read(1).await.unwrap(), item(1));
        });
    }

    #[test]
    fn unpublished_rollovers_are_unreachable_and_keep_the_decision_bounded() {
        deterministic::Runner::default().start(|context| async move {
            let cfg = config("v2_fixed_unpublished_rollovers");
            let mut journal = Journal::init(context.child("initial"), cfg.clone())
                .await
                .unwrap();
            for value in 0..8 {
                (journal, _) = journal.append(&item(value)).await.unwrap();
            }
            assert_eq!(journal.tail, 2);
            assert_eq!(journal.published_tail, 0);
            assert_eq!(journal.dirty, BTreeSet::from([0, 2]));
            drop(journal);

            let journal = Journal::<_, Item>::init(context.child("reopen"), cfg)
                .await
                .unwrap();
            assert_eq!(journal.bounds(), 0..0);
            assert_eq!(journal.tail, 0);
            assert!(journal.dirty.is_empty());
            journal.destroy().await.unwrap();
        });
    }

    #[test]
    fn append_after_start_sync_belongs_to_the_next_epoch() {
        deterministic::Runner::default().start(|context| async move {
            let cfg = config("v2_fixed_start_sync_epoch");
            let journal = Journal::init(context.child("initial"), cfg.clone())
                .await
                .unwrap();
            let (journal, _) = journal.append(&item(1)).await.unwrap();
            let (journal, completion) = journal.start_sync().await.unwrap();
            let (journal, _) = journal.append(&item(2)).await.unwrap();
            completion.await.unwrap();
            drop(journal);

            let journal = Journal::<_, Item>::init(context.child("reopen"), cfg)
                .await
                .unwrap();
            assert_eq!(journal.bounds(), 0..1);
            assert_eq!(journal.read(0).await.unwrap(), item(1));
            journal.destroy().await.unwrap();
        });
    }

    #[test]
    fn missing_marker_rejects_non_empty_sections_without_deleting_them() {
        deterministic::Runner::default().start(|context| async move {
            let cfg = config("v2_fixed_missing_marker");
            let partition = cfg.v2_partition();
            let mut journal = Journal::init(context.child("initial"), cfg.clone())
                .await
                .unwrap();
            for value in 0..4 {
                (journal, _) = journal.append(&item(value)).await.unwrap();
            }
            journal = journal.sync().await.unwrap();
            let writer = journal.blobs.remove(&journal.tail).unwrap();
            let writer = writer.set_marker(NO_MARKER).await.unwrap();
            journal.blobs.insert(journal.tail, writer);
            journal
                .blobs
                .get(&journal.tail)
                .unwrap()
                .sync()
                .await
                .unwrap();
            drop(journal);

            let mut before = context.scan(&partition).await.unwrap();
            before.sort();
            let reopened = Journal::<_, Item>::init(context.child("reopen"), cfg).await;
            assert!(matches!(reopened, Err(Error::Corruption(_))));
            let mut after = context.scan(&partition).await.unwrap();
            after.sort();
            assert_eq!(after, before);
        });
    }

    #[test]
    fn noncanonical_markers_are_rejected_before_section_cleanup() {
        deterministic::Runner::default().start(|context| async move {
            for (case, mut marker) in [
                ("absent", NO_MARKER),
                ("present", encode_start_marker(0).unwrap()),
            ] {
                marker[8] = 1;
                let base = format!("v2_fixed_noncanonical_marker_{case}");
                let cfg = config(&base);
                let partition = cfg.v2_partition();
                let mut journal = Journal::<_, Item>::init(context.child("initial"), cfg.clone())
                    .await
                    .unwrap();
                let writer = journal.blobs.remove(&journal.tail).unwrap();
                let writer = writer.set_marker(marker).await.unwrap();
                writer.sync().await.unwrap();
                journal.blobs.insert(journal.tail, writer);
                drop(journal);

                let mut before = context.scan(&partition).await.unwrap();
                before.sort();
                let reopened = Journal::<_, Item>::init(context.child("reopen"), cfg).await;
                assert!(matches!(reopened, Err(Error::Corruption(_))), "{case}");
                let mut after = context.scan(&partition).await.unwrap();
                after.sort();
                assert_eq!(after, before, "{case}");
                context.remove(&partition, None).await.unwrap();
            }
        });
    }
}
