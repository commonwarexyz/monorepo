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
    MutableV2,
};
use crate::{Context, journal::Error};
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
const NO_MARKER: [u8; ATOMIC_MARKER_LEN] = [0; ATOMIC_MARKER_LEN];

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
    pub page_size: NonZeroU16,
}

impl Config {
    fn v2_partition(&self) -> String {
        format!("{}{V2_SUFFIX}", self.partition)
    }
}

fn encode_marker(start: u64) -> Result<[u8; ATOMIC_MARKER_LEN], Error> {
    Ok(start
        .checked_add(1)
        .ok_or(Error::SizeOverflow)?
        .to_be_bytes())
}

const fn decode_marker(marker: [u8; ATOMIC_MARKER_LEN]) -> Option<u64> {
    let encoded = u64::from_be_bytes(marker);
    encoded.checked_sub(1)
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

    async fn scan_names(context: &E, partition: &str) -> Result<Vec<Vec<u8>>, Error> {
        match context.scan(partition).await {
            Ok(names) => Ok(names),
            Err(commonware_runtime::Error::PartitionMissing(_)) => Ok(Vec::new()),
            Err(error) => Err(error.into()),
        }
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
    ) -> Result<Self, Error> {
        let tail = position_to_blob(start, items_per_blob.get());
        let writer = Self::open_blob(&context, &partition, tail, page_size).await?;
        let writer = writer.set_marker(encode_marker(start)?).await?;
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
            _item: PhantomData,
        })
    }

    async fn init_inner(context: E, cfg: Config) -> Result<Self, Error> {
        Self::validate_item_size()?;
        let partition = cfg.v2_partition();
        let names = Self::scan_names(&context, &partition).await?;
        if names.is_empty() {
            return Self::fresh(context, partition, cfg.items_per_blob, cfg.page_size, 0).await;
        }

        let mut blobs = BTreeMap::new();
        let mut authority = None;
        for name in names {
            let printable = commonware_formatting::hex(&name);
            let name: [u8; 8] = name
                .try_into()
                .map_err(|_| Error::InvalidBlobName(printable))?;
            let index = u64::from_be_bytes(name);
            let writer = Self::open_blob(&context, &partition, index, cfg.page_size).await?;
            if let Some(start) = decode_marker(writer.marker())
                && authority.replace((index, start)).is_some()
            {
                return Err(Error::Corruption("multiple V2 journal tail markers".into()));
            }
            blobs.insert(index, writer);
        }

        let Some((tail, start)) = authority else {
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
            return Self::fresh(context, partition, cfg.items_per_blob, cfg.page_size, 0).await;
        };
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

        Ok(Self {
            context,
            partition,
            blobs,
            dirty: BTreeSet::new(),
            published_tail: tail,
            tail,
            bounds: start..end,
            items_per_blob: cfg.items_per_blob,
            page_size: cfg.page_size,
            _item: PhantomData,
        })
    }

    /// Open or create a V2 fixed journal.
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
        let marker = encode_marker(self.bounds.start)?;
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
        let writer = writer.set_marker(encode_marker(start)?).await?;
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
        let marker = encode_marker(self.bounds.start)?;
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
        let writer = writer.set_marker(encode_marker(size)?).await?;
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

    /// Remove the V2 journal partition.
    pub async fn destroy(self) -> Result<(), Error> {
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
    use commonware_runtime::{
        Runner as _, Storage as _, Supervisor as _, buffer::paged::atomic_page_size, deterministic,
    };
    use commonware_utils::{NZU64, sequence::FixedBytes};
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
}
