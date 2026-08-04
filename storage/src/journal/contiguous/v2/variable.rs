//! Variable-size contiguous journal backed by paired V2 atomic blobs.
//!
//! Every section has a varint-framed data blob and a fixed-width `u64` offsets blob. Mutations to
//! the pair are published by one [`BatchStorage`] decision, so recovery never has to choose one
//! side as more durable than the other. The active section carries the same movable start marker
//! in both roots. Sealed sections are page-complete and carry a final offset sentinel, allowing
//! reopen to validate roots and the two active partial tails without scanning data frames.
//!
//! Appends write both payload and offsets immediately but remain unreachable until `sync`
//! publishes their roots together. A rollover may durably stage a sealed unmarked pair, keeping
//! the eventual decision bounded to the prior authority and current tail. A crash before `sync`
//! restores both old lengths even if any subset of the new physical writes survived.

use super::{
    super::{Contiguous, Many, blob_first_position, position_to_blob},
    MIGRATION_BATCH_BYTES, MIGRATION_BATCH_ITEMS, MIGRATION_NAME, MutableV2, NO_START_MARKER,
    decode_start_marker, encode_start_marker, finish_migration, legacy_cache, legacy_write_buffer,
    migration_start, partition_has_state, remove_partition, scan_partition, start_migration,
};
use crate::{
    Context,
    journal::{
        Error,
        contiguous::variable as legacy,
        frame::{decode_item, decode_length_prefix, encode_frame_into},
    },
};
use commonware_codec::{Codec, CodecShared, varint::MAX_U32_VARINT_SIZE};
use commonware_runtime::{
    AtomicBlob as _, AtomicStorage, BatchOperation, BatchStorage, Handle, IoBuf,
    buffer::paged::{ATOMIC_MARKER_LEN, AtomicSnapshot, AtomicWriter},
};
use futures::{Stream, stream};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Cursor,
    marker::PhantomData,
    num::{NonZeroU16, NonZeroU64, NonZeroUsize},
    ops::Range,
};

const DATA_SUFFIX: &str = "-v2-data";
const OFFSETS_SUFFIX: &str = "-v2-offsets";
const OFFSET_SIZE: usize = size_of::<u64>();
const NO_MARKER: [u8; ATOMIC_MARKER_LEN] = NO_START_MARKER;

type Blob<E> = <E as AtomicStorage>::AtomicBlob;

/// Items encoded for a deferred append.
pub struct PreparedAppend<V> {
    encoded: Vec<u8>,
    item_starts: Vec<usize>,
    compressed: bool,
    _item: PhantomData<V>,
}

/// Configuration for a V2 variable contiguous journal.
#[derive(Clone, Debug)]
pub struct Config<C> {
    /// Base partition name. Data and offsets use distinct V2-only sub-partitions.
    pub partition: String,

    /// Maximum number of items in one section.
    pub items_per_section: NonZeroU64,

    /// Optional compression level for encoded item payloads.
    pub compression: Option<u8>,

    /// Codec configuration used to encode and decode items.
    pub codec_config: C,

    /// Logical bytes protected by one page CRC.
    ///
    /// Use [`commonware_runtime::buffer::paged::atomic_page_size`] to align full physical pages.
    /// When migrating a legacy journal, choose the same physical page size that its `CacheRef`
    /// used (for example, legacy `page_size(4096)` maps to V2 `atomic_page_size(4096)`).
    pub page_size: NonZeroU16,
}

impl<C> Config<C> {
    fn data_partition(&self) -> String {
        format!("{}{DATA_SUFFIX}", self.partition)
    }

    fn offsets_partition(&self) -> String {
        format!("{}{OFFSETS_SUFFIX}", self.partition)
    }
}

struct RawRoot<B> {
    blob: B,
    physical_size: u64,
    marker: [u8; ATOMIC_MARKER_LEN],
}

struct Section<B: commonware_runtime::AtomicBlob> {
    data: AtomicWriter<B>,
    offsets: AtomicWriter<B>,
}

impl<B: commonware_runtime::AtomicBlob> Section<B> {
    async fn set_marker(mut self, marker: [u8; ATOMIC_MARKER_LEN]) -> Result<Self, Error> {
        self.data = self.data.set_marker(marker).await?;
        self.offsets = self.offsets.set_marker(marker).await?;
        Ok(self)
    }

    async fn rewind(mut self, data_size: u64, offsets_size: u64) -> Result<Self, Error> {
        self.data = self.data.rewind(data_size).await?;
        self.offsets = self.offsets.rewind(offsets_size).await?;
        Ok(self)
    }

    async fn sync(&self) -> Result<(), Error> {
        let data = self.data.start_sync().await;
        let offsets = self.offsets.start_sync().await;
        data.await?;
        offsets.await?;
        Ok(())
    }
}

#[derive(Clone)]
struct SectionSnapshot<B: commonware_runtime::AtomicBlob> {
    data: AtomicSnapshot<B>,
    offsets: AtomicSnapshot<B>,
}

fn first_in_section(start: u64, section: u64, items_per_section: u64) -> Result<u64, Error> {
    Ok(start.max(blob_first_position(section, items_per_section)?))
}

fn section_capacity(start: u64, section: u64, items_per_section: u64) -> Result<u64, Error> {
    let natural_start = blob_first_position(section, items_per_section)?;
    let first = start.max(natural_start);
    let skipped = first
        .checked_sub(natural_start)
        .ok_or(Error::OffsetOverflow)?;
    items_per_section
        .checked_sub(skipped)
        .ok_or(Error::OffsetOverflow)
}

fn offsets_size(items: u64) -> Result<u64, Error> {
    items
        .checked_mul(OFFSET_SIZE as u64)
        .ok_or(Error::OffsetOverflow)
}

fn padded_size(size: u64, page_size: NonZeroU16) -> Result<u64, Error> {
    let page_size = u64::from(page_size.get());
    let remainder = size % page_size;
    if remainder == 0 {
        return Ok(size);
    }
    size.checked_add(page_size - remainder)
        .ok_or(Error::OffsetOverflow)
}

/// Immutable point-in-time view of a V2 variable journal.
pub struct Reader<B: commonware_runtime::AtomicBlob, V: Codec> {
    sections: BTreeMap<u64, SectionSnapshot<B>>,
    tail: u64,
    bounds: Range<u64>,
    items_per_section: NonZeroU64,
    codec_config: V::Cfg,
    compressed: bool,
    _item: PhantomData<V>,
}

impl<B, V> Clone for Reader<B, V>
where
    B: commonware_runtime::AtomicBlob,
    V: CodecShared,
{
    fn clone(&self) -> Self {
        Self {
            sections: self.sections.clone(),
            tail: self.tail,
            bounds: self.bounds.clone(),
            items_per_section: self.items_per_section,
            codec_config: self.codec_config.clone(),
            compressed: self.compressed,
            _item: PhantomData,
        }
    }
}

impl<B, V> Reader<B, V>
where
    B: commonware_runtime::AtomicBlob,
    V: CodecShared,
{
    const fn validate_readable(&self, position: u64) -> Result<(), Error> {
        if position < self.bounds.start {
            return Err(Error::ItemPruned(position));
        }
        if position >= self.bounds.end {
            return Err(Error::ItemOutOfRange(position));
        }
        Ok(())
    }

    fn locate(&self, position: u64) -> Result<(u64, &SectionSnapshot<B>, u64), Error> {
        self.validate_readable(position)?;
        let items_per_section = self.items_per_section.get();
        let section = position_to_blob(position, items_per_section);
        let first = first_in_section(self.bounds.start, section, items_per_section)?;
        let slot = position.checked_sub(first).ok_or(Error::OffsetOverflow)?;
        let section_ref = self
            .sections
            .get(&section)
            .ok_or(Error::MissingBlob(section))?;
        Ok((section, section_ref, slot))
    }

    async fn read_offset(offsets: &AtomicSnapshot<B>, slot: u64) -> Result<u64, Error> {
        let logical_offset = offsets_size(slot)?;
        let bytes = offsets
            .read_at(logical_offset, OFFSET_SIZE)
            .await?
            .coalesce();
        let bytes: [u8; OFFSET_SIZE] = bytes
            .as_ref()
            .try_into()
            .map_err(|_| Error::UnexpectedSize(OFFSET_SIZE as u32, bytes.len() as u32))?;
        Ok(u64::from_be_bytes(bytes))
    }

    async fn extent(&self, position: u64) -> Result<(u64, &AtomicSnapshot<B>, u64, u64), Error> {
        let (section, pair, slot) = self.locate(position)?;
        let start = Self::read_offset(&pair.offsets, slot).await?;
        let end = if section != self.tail || position + 1 < self.bounds.end {
            Self::read_offset(&pair.offsets, slot + 1).await?
        } else {
            pair.data.size()
        };
        if end <= start || end > pair.data.size() {
            return Err(Error::Corruption(format!(
                "invalid V2 frame extent in section {section}: {start}..{end}"
            )));
        }
        Ok((section, &pair.data, start, end))
    }

    async fn decode_at(&self, position: u64) -> Result<V, Error> {
        let (section, data, offset, end) = self.extent(position).await?;
        let span_u64 = end.checked_sub(offset).ok_or(Error::OffsetOverflow)?;
        let span = usize::try_from(span_u64).map_err(|_| Error::UsizeTooSmall)?;
        let header_len = span.min(MAX_U32_VARINT_SIZE);
        let header = data.read_at(offset, header_len).await?.coalesce();
        let mut cursor = Cursor::new(header.as_ref());
        let (payload_len, varint_len) = decode_length_prefix(&mut cursor)?;
        let actual_len = payload_len
            .checked_add(varint_len)
            .ok_or(Error::OffsetOverflow)?;
        if actual_len != span {
            return Err(Error::OffsetDataMismatch {
                section,
                offset,
                expected_len: span,
                actual_len,
            });
        }
        let payload_offset = offset
            .checked_add(varint_len as u64)
            .ok_or(Error::OffsetOverflow)?;
        let payload = data.read_at(payload_offset, payload_len).await?;
        decode_item::<V>(payload, &self.codec_config, self.compressed)
    }
}

fn replay_owned<B, V>(
    reader: Reader<B, V>,
    start_pos: u64,
) -> Result<impl Stream<Item = Result<(u64, V), Error>> + Send, Error>
where
    B: commonware_runtime::AtomicBlob,
    V: CodecShared,
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

impl<B, V> Contiguous for Reader<B, V>
where
    B: commonware_runtime::AtomicBlob,
    V: CodecShared,
{
    type Item = V;

    fn bounds(&self) -> Range<u64> {
        self.bounds.clone()
    }

    async fn read(&self, position: u64) -> Result<V, Error> {
        self.decode_at(position).await
    }

    async fn read_many(&self, positions: &[u64]) -> Result<Vec<V>, Error> {
        assert!(
            positions.is_sorted_by(|a, b| a < b),
            "positions must be strictly increasing"
        );
        let mut items = Vec::with_capacity(positions.len());
        for &position in positions {
            items.push(self.decode_at(position).await?);
        }
        Ok(items)
    }

    fn try_read_sync(&self, _position: u64) -> Option<V> {
        None
    }

    fn try_read_many_sync(&self, positions: &[u64]) -> Vec<Option<V>> {
        (0..positions.len()).map(|_| None).collect()
    }

    async fn replay(
        &self,
        start_pos: u64,
        _buffer: NonZeroUsize,
    ) -> Result<impl Stream<Item = Result<(u64, V), Error>> + Send, Error> {
        replay_owned(self.clone(), start_pos)
    }
}

/// Variable-size contiguous journal using paired append-only V2 sections.
pub struct Journal<E, V>
where
    E: Context + BatchStorage,
    V: CodecShared,
{
    context: E,
    data_partition: String,
    offsets_partition: String,
    sections: BTreeMap<u64, Section<Blob<E>>>,
    dirty: BTreeSet<u64>,
    published_tail: u64,
    tail: u64,
    bounds: Range<u64>,
    items_per_section: NonZeroU64,
    compression: Option<u8>,
    codec_config: V::Cfg,
    page_size: NonZeroU16,
    active: bool,
    _item: PhantomData<V>,
}

impl<E, V> std::fmt::Debug for Journal<E, V>
where
    E: Context + BatchStorage,
    V: CodecShared,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Journal")
            .field("bounds", &self.bounds)
            .finish_non_exhaustive()
    }
}

impl<E, V> Journal<E, V>
where
    E: Context + BatchStorage,
    V: CodecShared,
{
    fn validate_config(cfg: &Config<V::Cfg>) -> Result<(), Error> {
        let entries =
            cfg.items_per_section.get().checked_add(1).ok_or_else(|| {
                Error::InvalidConfiguration("offset section size exceeds u64".into())
            })?;
        let size = offsets_size(entries)
            .map_err(|_| Error::InvalidConfiguration("offset section size exceeds u64".into()))?;
        padded_size(size, cfg.page_size)
            .map_err(|_| Error::InvalidConfiguration("offset section size exceeds u64".into()))?;
        Ok(())
    }

    async fn open_roots(
        context: &E,
        partition: &str,
        names: Vec<Vec<u8>>,
    ) -> Result<BTreeMap<u64, RawRoot<Blob<E>>>, Error> {
        let mut roots = BTreeMap::new();
        for name in names {
            let printable = commonware_formatting::hex(&name);
            let name: [u8; 8] = name
                .try_into()
                .map_err(|_| Error::InvalidBlobName(printable))?;
            let index = u64::from_be_bytes(name);
            let (blob, physical_size) = context.open_atomic(partition, &name).await?;
            let tag = blob.tag().await?;
            let marker = tag[..ATOMIC_MARKER_LEN]
                .try_into()
                .expect("atomic marker length is fixed");
            if roots
                .insert(
                    index,
                    RawRoot {
                        blob,
                        physical_size,
                        marker,
                    },
                )
                .is_some()
            {
                return Err(Error::Corruption(format!(
                    "duplicate V2 section name {index}"
                )));
            }
        }
        Ok(roots)
    }

    fn authority(
        roots: &BTreeMap<u64, RawRoot<Blob<E>>>,
        kind: &str,
    ) -> Result<Option<(u64, u64)>, Error> {
        let mut authority = None;
        for (&index, root) in roots {
            let Some(start) = decode_start_marker(root.marker)? else {
                continue;
            };
            if authority.replace((index, start)).is_some() {
                return Err(Error::Corruption(format!(
                    "multiple V2 variable {kind} tail markers"
                )));
            }
        }
        Ok(authority)
    }

    async fn remove_named(context: &E, partition: &str, indices: &[u64]) -> Result<(), Error> {
        for index in indices {
            context
                .remove(partition, Some(&index.to_be_bytes()))
                .await?;
        }
        Ok(())
    }

    async fn open_writer(
        root: RawRoot<Blob<E>>,
        page_size: NonZeroU16,
    ) -> Result<AtomicWriter<Blob<E>>, Error> {
        Ok(AtomicWriter::new(root.blob, root.physical_size, page_size).await?)
    }

    async fn open_empty_section(
        context: &E,
        data_partition: &str,
        offsets_partition: &str,
        index: u64,
        page_size: NonZeroU16,
    ) -> Result<Section<Blob<E>>, Error> {
        let name = index.to_be_bytes();
        let (data, data_size) = context.open_atomic(data_partition, &name).await?;
        let (offsets, offsets_size) = context.open_atomic(offsets_partition, &name).await?;
        let data = AtomicWriter::new(data, data_size, page_size).await?;
        let offsets = AtomicWriter::new(offsets, offsets_size, page_size).await?;
        if data.size() != 0
            || offsets.size() != 0
            || data.marker() != NO_MARKER
            || offsets.marker() != NO_MARKER
        {
            return Err(Error::Corruption(format!(
                "V2 rollover target {index} is not an empty unmarked pair"
            )));
        }
        Ok(Section { data, offsets })
    }

    fn publish_pair(operations: &mut Vec<BatchOperation<Blob<E>>>, section: &Section<Blob<E>>) {
        operations.push(BatchOperation::Publish(section.data.blob().clone()));
        operations.push(BatchOperation::Publish(section.offsets.blob().clone()));
    }

    async fn fresh(
        context: E,
        cfg: Config<V::Cfg>,
        start: u64,
        active: bool,
    ) -> Result<Self, Error> {
        let data_partition = cfg.data_partition();
        let offsets_partition = cfg.offsets_partition();
        let tail = position_to_blob(start, cfg.items_per_section.get());
        let section = Self::open_empty_section(
            &context,
            &data_partition,
            &offsets_partition,
            tail,
            cfg.page_size,
        )
        .await?;
        let marker = if active {
            encode_start_marker(start)?
        } else {
            NO_MARKER
        };
        let section = section.set_marker(marker).await?;
        let mut operations = Vec::with_capacity(2);
        Self::publish_pair(&mut operations, &section);
        context.apply(operations).await?;
        Ok(Self {
            context,
            data_partition,
            offsets_partition,
            sections: BTreeMap::from([(tail, section)]),
            dirty: BTreeSet::new(),
            published_tail: tail,
            tail,
            bounds: start..start,
            items_per_section: cfg.items_per_section,
            compression: cfg.compression,
            codec_config: cfg.codec_config,
            page_size: cfg.page_size,
            active,
            _item: PhantomData,
        })
    }

    async fn open_existing(
        context: E,
        cfg: &Config<V::Cfg>,
        data_names: Vec<Vec<u8>>,
        offsets_names: Vec<Vec<u8>>,
        staging_start: Option<u64>,
    ) -> Result<Option<Self>, Error> {
        Self::validate_config(cfg)?;
        let data_partition = cfg.data_partition();
        let offsets_partition = cfg.offsets_partition();
        let data_names = data_names
            .into_iter()
            .filter(|name| name != MIGRATION_NAME)
            .collect();
        let mut data = Self::open_roots(&context, &data_partition, data_names).await?;
        let mut offsets = Self::open_roots(&context, &offsets_partition, offsets_names).await?;
        if data.is_empty() && offsets.is_empty() {
            return Ok(None);
        }

        let data_authority = Self::authority(&data, "data")?;
        let offsets_authority = Self::authority(&offsets, "offsets")?;
        let (authority, active) = match (data_authority, offsets_authority) {
            (Some(data), Some(offsets)) if data == offsets => {
                if let Some(staging_start) = staging_start
                    && data.1 != staging_start
                {
                    return Err(Error::Corruption(
                        "activated V2 variable journal disagrees with migration start".into(),
                    ));
                }
                (Some(data), true)
            }
            (None, None) if staging_start.is_some() => (None, false),
            (None, None) => {
                if data.values().any(|root| root.physical_size != 0)
                    || offsets.values().any(|root| root.physical_size != 0)
                {
                    return Err(Error::Corruption(
                        "non-empty V2 variable sections have no tail marker".into(),
                    ));
                }
                let data_indices = data.keys().copied().collect::<Vec<_>>();
                let offsets_indices = offsets.keys().copied().collect::<Vec<_>>();
                Self::remove_named(&context, &data_partition, &data_indices).await?;
                Self::remove_named(&context, &offsets_partition, &offsets_indices).await?;
                return Ok(None);
            }
            _ => {
                return Err(Error::Corruption(
                    "V2 variable data and offsets tail markers disagree".into(),
                ));
            }
        };

        let start = authority
            .map(|(_, start)| start)
            .or(staging_start)
            .expect("active or staging state has a start");
        let items_per_section = cfg.items_per_section.get();
        let oldest = position_to_blob(start, items_per_section);
        let marker = encode_start_marker(start)?;
        let mut sections = BTreeMap::new();

        let (tail, tail_count) = if let Some((tail, _)) = authority {
            if tail < oldest {
                return Err(Error::Corruption(
                    "V2 variable tail marker precedes the journal start".into(),
                ));
            }
            let mut index = oldest;
            let tail_count = loop {
                let data_root = data.remove(&index).ok_or(Error::MissingBlob(index))?;
                let offsets_root = offsets.remove(&index).ok_or(Error::MissingBlob(index))?;
                let data_writer = Self::open_writer(data_root, cfg.page_size).await?;
                let offsets_writer = Self::open_writer(offsets_root, cfg.page_size).await?;
                let capacity = section_capacity(start, index, items_per_section)?;

                if index == tail {
                    if data_writer.marker() != marker || offsets_writer.marker() != marker {
                        return Err(Error::Corruption(
                            "V2 variable active markers changed during open".into(),
                        ));
                    }
                    if offsets_writer.size() % OFFSET_SIZE as u64 != 0 {
                        return Err(Error::InvalidBlobSize(index, offsets_writer.size()));
                    }
                    let count = offsets_writer.size() / OFFSET_SIZE as u64;
                    if count >= capacity {
                        return Err(Error::InvalidBlobSize(index, offsets_writer.size()));
                    }
                    if (count == 0) != (data_writer.size() == 0) {
                        return Err(Error::Corruption(format!(
                            "V2 variable active section {index} has mismatched empty state"
                        )));
                    }
                    sections.insert(
                        index,
                        Section {
                            data: data_writer,
                            offsets: offsets_writer,
                        },
                    );
                    break count;
                }

                if data_writer.marker() != NO_MARKER || offsets_writer.marker() != NO_MARKER {
                    return Err(Error::Corruption(format!(
                        "V2 variable sealed section {index} is marked active"
                    )));
                }
                if data_writer.size() == 0
                    || data_writer.size() % u64::from(cfg.page_size.get()) != 0
                {
                    return Err(Error::InvalidBlobSize(index, data_writer.size()));
                }
                let sealed_entries = capacity.checked_add(1).ok_or(Error::OffsetOverflow)?;
                let expected_offsets = padded_size(offsets_size(sealed_entries)?, cfg.page_size)?;
                if offsets_writer.size() != expected_offsets {
                    return Err(Error::InvalidBlobSize(index, offsets_writer.size()));
                }
                sections.insert(
                    index,
                    Section {
                        data: data_writer,
                        offsets: offsets_writer,
                    },
                );
                index = index.checked_add(1).ok_or(Error::OffsetOverflow)?;
            };
            (tail, tail_count)
        } else {
            let mut index = oldest;
            loop {
                let data_root = data.remove(&index);
                let offsets_root = offsets.remove(&index);
                let (data_writer, offsets_writer) = match (data_root, offsets_root) {
                    (Some(data), Some(offsets)) => (
                        Self::open_writer(data, cfg.page_size).await?,
                        Self::open_writer(offsets, cfg.page_size).await?,
                    ),
                    (data_root, offsets_root) => {
                        if data_root.is_some() {
                            Self::remove_named(&context, &data_partition, &[index]).await?;
                        }
                        if offsets_root.is_some() {
                            Self::remove_named(&context, &offsets_partition, &[index]).await?;
                        }
                        let section = Self::open_empty_section(
                            &context,
                            &data_partition,
                            &offsets_partition,
                            index,
                            cfg.page_size,
                        )
                        .await?;
                        sections.insert(index, section);
                        break (index, 0);
                    }
                };
                if data_writer.marker() != NO_MARKER || offsets_writer.marker() != NO_MARKER {
                    return Err(Error::Corruption(format!(
                        "V2 variable migration section {index} is marked active"
                    )));
                }
                let capacity = section_capacity(start, index, items_per_section)?;
                let sealed_entries = capacity.checked_add(1).ok_or(Error::OffsetOverflow)?;
                let expected_offsets = padded_size(offsets_size(sealed_entries)?, cfg.page_size)?;
                let sealed = data_writer.size() != 0
                    && data_writer.size() % u64::from(cfg.page_size.get()) == 0
                    && offsets_writer.size() == expected_offsets;
                if sealed {
                    sections.insert(
                        index,
                        Section {
                            data: data_writer,
                            offsets: offsets_writer,
                        },
                    );
                    index = index.checked_add(1).ok_or(Error::OffsetOverflow)?;
                    continue;
                }
                if offsets_writer.size() % OFFSET_SIZE as u64 != 0 {
                    return Err(Error::InvalidBlobSize(index, offsets_writer.size()));
                }
                let count = offsets_writer.size() / OFFSET_SIZE as u64;
                if count >= capacity || (count == 0) != (data_writer.size() == 0) {
                    return Err(Error::InvalidBlobSize(index, offsets_writer.size()));
                }
                sections.insert(
                    index,
                    Section {
                        data: data_writer,
                        offsets: offsets_writer,
                    },
                );
                break (index, count);
            }
        };

        let stale_data = data.keys().copied().collect::<Vec<_>>();
        let stale_offsets = offsets.keys().copied().collect::<Vec<_>>();
        Self::remove_named(&context, &data_partition, &stale_data).await?;
        Self::remove_named(&context, &offsets_partition, &stale_offsets).await?;

        let tail_first = first_in_section(start, tail, items_per_section)?;
        let end = tail_first
            .checked_add(tail_count)
            .ok_or(Error::SizeOverflow)?;
        Ok(Some(Self {
            context,
            data_partition,
            offsets_partition,
            sections,
            dirty: BTreeSet::new(),
            published_tail: tail,
            tail,
            bounds: start..end,
            items_per_section: cfg.items_per_section,
            compression: cfg.compression,
            codec_config: cfg.codec_config.clone(),
            page_size: cfg.page_size,
            active,
            _item: PhantomData,
        }))
    }

    fn legacy_partitions(partition: &str) -> [String; 5] {
        [
            format!("{partition}_data"),
            format!("{partition}_data-blobs"),
            format!("{partition}_offsets"),
            format!("{partition}_offsets-blobs"),
            format!("{partition}_offsets-metadata"),
        ]
    }

    fn legacy_config(context: &E, cfg: &Config<V::Cfg>) -> Result<legacy::Config<V::Cfg>, Error> {
        Ok(legacy::Config {
            partition: cfg.partition.clone(),
            items_per_section: cfg.items_per_section,
            compression: cfg.compression,
            codec_config: cfg.codec_config.clone(),
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
        let section = self
            .sections
            .remove(&self.tail)
            .expect("migration tail exists");
        let section = section
            .set_marker(encode_start_marker(self.bounds.start)?)
            .await?;
        self.sections.insert(self.tail, section);
        self.dirty.insert(self.tail);
        self.apply_dirty().await?;
        self.published_tail = self.tail;
        self.active = true;
        Ok(self)
    }

    async fn migrate_legacy(
        mut legacy: legacy::Journal<E, V>,
        mut target: Self,
        cfg: &Config<V::Cfg>,
    ) -> Result<Self, Error> {
        let source = legacy.bounds();
        if target.bounds.start > source.start
            || target.bounds.end < source.start
            || target.bounds.end > source.end
        {
            return Err(Error::Corruption(format!(
                "variable migration ranges disagree: staged={:?} legacy={source:?}",
                target.bounds
            )));
        }

        while target.bounds.end < source.end {
            let remaining_in_section =
                cfg.items_per_section.get() - (target.bounds.end % cfg.items_per_section.get());
            let end = target
                .bounds
                .end
                .checked_add((source.end - target.bounds.end).min(remaining_in_section))
                .ok_or(Error::SizeOverflow)?;
            let prepared =
                Self::prepare_migration_batch(&legacy, target.bounds.end, end, cfg.compression)
                    .await?;
            (target, _) = target.append_prepared(prepared).await?;
            if target
                .bounds
                .end
                .is_multiple_of(cfg.items_per_section.get())
            {
                target = target.sync().await?;
                (legacy, _) = legacy.prune(target.bounds.end).await?;
            }
        }

        target = target.sync().await?.activate().await?;
        drop(legacy);
        Self::cleanup_legacy(&target.context, &cfg.partition).await?;
        finish_migration(&target.context, &target.data_partition).await?;
        Ok(target)
    }

    async fn init_inner(context: E, cfg: Config<V::Cfg>) -> Result<Self, Error> {
        Self::validate_config(&cfg)?;
        let data_partition = cfg.data_partition();
        let offsets_partition = cfg.offsets_partition();
        let data_names = scan_partition(&context, &data_partition).await?;
        let offsets_names = scan_partition(&context, &offsets_partition).await?;
        let witness = migration_start(&context, &data_partition, &data_names).await?;
        let existing = Self::open_existing(
            context.child("v2_open"),
            &cfg,
            data_names,
            offsets_names,
            witness.flatten(),
        )
        .await?;

        if existing.as_ref().is_some_and(|journal| journal.active) {
            let journal = existing.expect("active journal exists");
            if witness.is_some() {
                Self::cleanup_legacy(&journal.context, &cfg.partition).await?;
                finish_migration(&journal.context, &journal.data_partition).await?;
            }
            return Ok(journal);
        }

        let legacy_partitions = Self::legacy_partitions(&cfg.partition);
        if !partition_has_state(&context, &legacy_partitions).await? {
            if witness.is_some() {
                return Err(Error::Corruption(
                    "variable migration witness has neither legacy nor active V2 state".into(),
                ));
            }
            return Self::fresh(context, cfg, 0, true).await;
        }

        let legacy = legacy::Journal::<E, V>::init(
            context.child("legacy"),
            Self::legacy_config(&context, &cfg)?,
        )
        .await?;
        let source = legacy.bounds();
        let start = match witness {
            Some(Some(start)) => start,
            Some(None) | None => {
                start_migration(&context, &data_partition, source.start).await?;
                source.start
            }
        };
        if start != source.start && existing.is_none() {
            return Err(Error::Corruption(
                "variable migration start no longer matches legacy state".into(),
            ));
        }
        let target = match existing {
            Some(target) => target,
            None => Self::fresh(context.child("v2_migrate"), cfg.clone(), start, false).await?,
        };
        Self::migrate_legacy(legacy, target, &cfg).await
    }

    /// Open or create a V2 variable journal, eagerly migrating any recovered legacy journal.
    ///
    /// A successful migration removes the same-base legacy partitions, so selecting V2 is
    /// forward-only for this journal.
    pub async fn init(context: E, cfg: Config<V::Cfg>) -> Result<Self, Error> {
        Self::init_inner(context, cfg).await
    }

    /// Open the journal and atomically reset it to an empty state at `size`.
    pub async fn init_at_size(context: E, cfg: Config<V::Cfg>, size: u64) -> Result<Self, Error> {
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
    pub fn snapshot(&self) -> Reader<Blob<E>, V> {
        Reader {
            sections: self
                .sections
                .iter()
                .map(|(&index, section)| {
                    (
                        index,
                        SectionSnapshot {
                            data: section.data.snapshot(),
                            offsets: section.offsets.snapshot(),
                        },
                    )
                })
                .collect(),
            tail: self.tail,
            bounds: self.bounds.clone(),
            items_per_section: self.items_per_section,
            codec_config: self.codec_config.clone(),
            compressed: self.compression.is_some(),
            _item: PhantomData,
        }
    }

    /// Encode items for a later [`append_prepared`](Self::append_prepared) call.
    pub fn prepare_append(&self, items: Many<'_, V>) -> Result<PreparedAppend<V>, Error> {
        let count = items.len();
        let mut encoded = Vec::new();
        let mut item_starts = Vec::with_capacity(count);
        match items {
            Many::Flat(items) => {
                for item in items {
                    item_starts.push(encoded.len());
                    encode_frame_into(self.compression, item, &mut encoded)?;
                }
            }
            Many::Nested(groups) => {
                for group in groups {
                    for item in *group {
                        item_starts.push(encoded.len());
                        encode_frame_into(self.compression, item, &mut encoded)?;
                    }
                }
            }
        }
        Ok(PreparedAppend {
            encoded,
            item_starts,
            compressed: self.compression.is_some(),
            _item: PhantomData,
        })
    }

    async fn prepare_migration_batch(
        legacy: &legacy::Journal<E, V>,
        start: u64,
        end: u64,
        compression: Option<u8>,
    ) -> Result<PreparedAppend<V>, Error> {
        // Encode as items are read so migration retains a bounded encoded batch rather than a
        // decoded item vector. One item larger than the budget is admitted by itself.
        let mut encoded = Vec::new();
        let mut item_starts = Vec::new();
        for position in start..end {
            if item_starts.len() == MIGRATION_BATCH_ITEMS {
                break;
            }
            let item = legacy.read(position).await?;
            let mut frame = Vec::new();
            encode_frame_into(compression, &item, &mut frame)?;

            if item_starts.is_empty() {
                item_starts.push(0);
                encoded = frame;
            } else {
                let Some(next_size) = encoded.len().checked_add(frame.len()) else {
                    break;
                };
                if next_size > MIGRATION_BATCH_BYTES {
                    break;
                }
                item_starts.push(encoded.len());
                encoded.extend_from_slice(&frame);
            }
            if encoded.len() >= MIGRATION_BATCH_BYTES {
                break;
            }
        }
        debug_assert!(!item_starts.is_empty());
        Ok(PreparedAppend {
            encoded,
            item_starts,
            compressed: compression.is_some(),
            _item: PhantomData,
        })
    }

    async fn pad_writer(
        writer: AtomicWriter<Blob<E>>,
        page_size: NonZeroU16,
    ) -> Result<AtomicWriter<Blob<E>>, Error> {
        let padded = padded_size(writer.size(), page_size)?;
        let padding = usize::try_from(padded - writer.size()).map_err(|_| Error::UsizeTooSmall)?;
        if padding == 0 {
            return Ok(writer);
        }
        let (writer, _) = writer.append_owned(vec![0; padding].into()).await?;
        Ok(writer)
    }

    async fn seal_tail(mut self) -> Result<Self, Error> {
        let old_index = self.tail;
        let next = self.tail.checked_add(1).ok_or(Error::SizeOverflow)?;
        let next_section = Self::open_empty_section(
            &self.context,
            &self.data_partition,
            &self.offsets_partition,
            next,
            self.page_size,
        )
        .await?;
        let marker = if self.active {
            encode_start_marker(self.bounds.start)?
        } else {
            NO_MARKER
        };

        let mut tail = self.sections.remove(&self.tail).expect("tail must exist");
        let data_end = tail.data.size();
        (tail.offsets, _) = tail.offsets.append(&data_end.to_be_bytes()).await?;
        tail.data = Self::pad_writer(tail.data, self.page_size).await?;
        tail.offsets = Self::pad_writer(tail.offsets, self.page_size).await?;
        let tail = tail.set_marker(NO_MARKER).await?;
        let next_section = next_section.set_marker(marker).await?;

        if old_index == self.published_tail {
            self.dirty.insert(old_index);
        } else {
            // This pair is not reachable from the committed marker. Persist its final unmarked
            // roots now so any number of crossed sections still needs only a four-blob decision.
            tail.sync().await?;
            self.dirty.remove(&old_index);
        }
        self.sections.insert(old_index, tail);
        self.sections.insert(next, next_section);
        self.dirty.insert(next);
        self.tail = next;
        Ok(self)
    }

    async fn write_encoded(mut self, prepared: PreparedAppend<V>) -> Result<(Self, u64), Error> {
        let PreparedAppend {
            encoded,
            item_starts,
            compressed,
            ..
        } = prepared;
        let item_count = item_starts.len();
        if item_count == 0 {
            return Err(Error::EmptyAppend);
        }
        if compressed != self.compression.is_some() {
            return Err(Error::InvalidConfiguration(
                "prepared append compression setting does not match journal".into(),
            ));
        }
        let item_count_u64 = u64::try_from(item_count).map_err(|_| Error::SizeOverflow)?;
        self.bounds
            .end
            .checked_add(item_count_u64)
            .ok_or(Error::SizeOverflow)?;
        let encoded = IoBuf::from(encoded);
        let items_per_section = self.items_per_section.get();
        let mut written = 0usize;

        while written < item_count {
            let count = super::super::batch_count_to_blob_boundary(
                self.bounds.end,
                item_count - written,
                items_per_section,
            );
            let batch_start = item_starts[written];
            let batch_end = item_starts
                .get(written + count)
                .copied()
                .unwrap_or(encoded.len());
            let old_end = self.bounds.end;
            let new_end = old_end
                .checked_add(count as u64)
                .ok_or(Error::SizeOverflow)?;

            let tail_first = first_in_section(self.bounds.start, self.tail, items_per_section)?;
            let expected_count = old_end
                .checked_sub(tail_first)
                .ok_or(Error::OffsetOverflow)?;
            let tail = self.sections.get(&self.tail).expect("tail must exist");
            if tail.offsets.size() != offsets_size(expected_count)? {
                return Err(Error::Corruption(
                    "V2 variable active offsets length changed unexpectedly".into(),
                ));
            }
            let mut tail = self.sections.remove(&self.tail).expect("tail must exist");
            let (data, base_offset) = tail
                .data
                .append_owned(encoded.slice(batch_start..batch_end))
                .await?;
            tail.data = data;
            let mut offset_bytes = Vec::with_capacity(
                count
                    .checked_mul(OFFSET_SIZE)
                    .ok_or(Error::OffsetOverflow)?,
            );
            for &relative in &item_starts[written..written + count] {
                let delta =
                    u64::try_from(relative - batch_start).map_err(|_| Error::OffsetOverflow)?;
                let offset = base_offset
                    .checked_add(delta)
                    .ok_or(Error::OffsetOverflow)?;
                offset_bytes.extend_from_slice(&offset.to_be_bytes());
            }
            (tail.offsets, _) = tail.offsets.append_owned(offset_bytes.into()).await?;
            self.sections.insert(self.tail, tail);
            self.dirty.insert(self.tail);

            if new_end.is_multiple_of(items_per_section) {
                self = self.seal_tail().await?;
            }
            self.bounds.end = new_end;
            written += count;
        }
        let position = self.bounds.end - 1;
        Ok((self, position))
    }

    /// Append one item, staging its data and offset for joint publication.
    pub async fn append(self, item: &V) -> Result<(Self, u64), Error> {
        self.append_many(Many::Flat(std::slice::from_ref(item)))
            .await
    }

    /// Append one or more item slices.
    pub async fn append_many(self, items: Many<'_, V>) -> Result<(Self, u64), Error> {
        let prepared = self.prepare_append(items)?;
        self.write_encoded(prepared).await
    }

    /// Append items previously encoded by [`prepare_append`](Self::prepare_append).
    pub async fn append_prepared(self, prepared: PreparedAppend<V>) -> Result<(Self, u64), Error> {
        self.write_encoded(prepared).await
    }

    fn dirty_operations(&self) -> Vec<BatchOperation<Blob<E>>> {
        let mut operations = Vec::with_capacity(self.dirty.len().saturating_mul(2));
        for index in &self.dirty {
            Self::publish_pair(
                &mut operations,
                self.sections.get(index).expect("dirty section must exist"),
            );
        }
        operations
    }

    async fn apply_dirty(&mut self) -> Result<(), Error> {
        if self.dirty.is_empty() {
            return Ok(());
        }
        self.context.apply(self.dirty_operations()).await?;
        self.dirty.clear();
        Ok(())
    }

    /// Begin jointly publishing the current data and offsets roots.
    pub async fn start_sync(mut self) -> Result<(Self, Handle<()>), Error> {
        if self.dirty.is_empty() {
            return Ok((self, Handle::ready(Ok(()))));
        }
        let handle = self.context.start_apply(self.dirty_operations()).await?;
        self.published_tail = self.tail;
        self.dirty.clear();
        Ok((self, handle))
    }

    /// Jointly publish the current data and offsets roots.
    pub async fn sync(self) -> Result<Self, Error> {
        let (journal, completion) = self.start_sync().await?;
        completion.await?;
        Ok(journal)
    }

    /// Prune complete sections strictly before `min_position`.
    pub async fn prune(mut self, min_position: u64) -> Result<(Self, bool), Error> {
        let target = position_to_blob(min_position, self.items_per_section.get()).min(self.tail);
        let oldest = position_to_blob(self.bounds.start, self.items_per_section.get());
        if target <= oldest {
            return Ok((self, false));
        }
        let start = blob_first_position(target, self.items_per_section.get())?;
        let marker = encode_start_marker(start)?;
        let tail = self.sections.remove(&self.tail).expect("tail must exist");
        let tail = tail.set_marker(marker).await?;
        self.sections.insert(self.tail, tail);
        self.dirty.insert(self.tail);
        self.apply_dirty().await?;
        self.published_tail = self.tail;

        let stale = self
            .sections
            .keys()
            .copied()
            .filter(|index| *index < target)
            .collect::<Vec<_>>();
        Self::remove_named(&self.context, &self.data_partition, &stale).await?;
        Self::remove_named(&self.context, &self.offsets_partition, &stale).await?;
        for index in stale {
            self.sections.remove(&index);
        }
        self.bounds.start = start;
        Ok((self, true))
    }

    async fn writer_offset(offsets: &AtomicWriter<Blob<E>>, slot: u64) -> Result<u64, Error> {
        let bytes = offsets
            .read_at(offsets_size(slot)?, OFFSET_SIZE)
            .await?
            .coalesce();
        let bytes: [u8; OFFSET_SIZE] = bytes
            .as_ref()
            .try_into()
            .map_err(|_| Error::UnexpectedSize(OFFSET_SIZE as u32, bytes.len() as u32))?;
        Ok(u64::from_be_bytes(bytes))
    }

    /// Rewind to `size`, publishing both shortened roots and the marker move in one batch.
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

        let target = position_to_blob(size, self.items_per_section.get());
        let first = first_in_section(self.bounds.start, target, self.items_per_section.get())?;
        let retained = size.checked_sub(first).ok_or(Error::OffsetOverflow)?;
        let data_size = if retained == 0 {
            0
        } else {
            let target_section = self
                .sections
                .get(&target)
                .ok_or(Error::MissingBlob(target))?;
            Self::writer_offset(&target_section.offsets, retained).await?
        };
        let marker = encode_start_marker(self.bounds.start)?;
        let stale = self
            .sections
            .keys()
            .copied()
            .filter(|index| *index > target)
            .collect::<Vec<_>>();
        let target_section = self
            .sections
            .remove(&target)
            .ok_or(Error::MissingBlob(target))?;
        let target_section = target_section
            .rewind(data_size, offsets_size(retained)?)
            .await?;
        let target_section = target_section.set_marker(marker).await?;

        self.sections.insert(target, target_section);
        self.dirty.insert(target);
        if target != self.tail {
            let old_tail = self.sections.remove(&self.tail).expect("tail must exist");
            let old_tail = old_tail.set_marker(NO_MARKER).await?;
            self.sections.insert(self.tail, old_tail);
            self.dirty.insert(self.tail);
        }
        self.apply_dirty().await?;
        self.published_tail = target;

        Self::remove_named(&self.context, &self.data_partition, &stale).await?;
        Self::remove_named(&self.context, &self.offsets_partition, &stale).await?;
        for index in stale {
            self.sections.remove(&index);
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
        if self.bounds == (size..size) {
            return Ok(self);
        }
        let target = position_to_blob(size, self.items_per_section.get());
        if !self.sections.contains_key(&target) {
            let section = Self::open_empty_section(
                &self.context,
                &self.data_partition,
                &self.offsets_partition,
                target,
                self.page_size,
            )
            .await?;
            self.sections.insert(target, section);
        }
        let marker = encode_start_marker(size)?;
        let stale = self
            .sections
            .keys()
            .copied()
            .filter(|index| *index != target)
            .collect::<Vec<_>>();
        let target_section = self.sections.remove(&target).expect("target must exist");
        let target_section = target_section.rewind(0, 0).await?;
        let target_section = target_section.set_marker(marker).await?;

        self.sections.insert(target, target_section);
        self.dirty.insert(target);
        if target != self.tail {
            let old_tail = self.sections.remove(&self.tail).expect("tail must exist");
            let old_tail = old_tail.set_marker(NO_MARKER).await?;
            self.sections.insert(self.tail, old_tail);
            self.dirty.insert(self.tail);
        }
        self.apply_dirty().await?;
        self.published_tail = target;

        Self::remove_named(&self.context, &self.data_partition, &stale).await?;
        Self::remove_named(&self.context, &self.offsets_partition, &stale).await?;
        for index in stale {
            self.sections.remove(&index);
        }
        self.tail = target;
        self.bounds = size..size;
        Ok(self)
    }

    /// Remove both V2 journal partitions and any same-base legacy partitions.
    ///
    /// This final teardown is not crash-safe; use [`clear_to_size`](Self::clear_to_size) for a
    /// recoverable reset.
    pub async fn destroy(self) -> Result<(), Error> {
        let base_partition = self
            .data_partition
            .strip_suffix(DATA_SUFFIX)
            .expect("V2 variable data partition has its suffix");
        Self::cleanup_legacy(&self.context, base_partition).await?;
        self.context.remove(&self.data_partition, None).await?;
        self.context.remove(&self.offsets_partition, None).await?;
        Ok(())
    }
}

impl<E, V> Contiguous for Journal<E, V>
where
    E: Context + BatchStorage,
    V: CodecShared,
{
    type Item = V;

    fn bounds(&self) -> Range<u64> {
        self.bounds.clone()
    }

    async fn read(&self, position: u64) -> Result<V, Error> {
        self.snapshot().read(position).await
    }

    async fn read_many(&self, positions: &[u64]) -> Result<Vec<V>, Error> {
        self.snapshot().read_many(positions).await
    }

    fn try_read_sync(&self, _position: u64) -> Option<V> {
        None
    }

    fn try_read_many_sync(&self, positions: &[u64]) -> Vec<Option<V>> {
        (0..positions.len()).map(|_| None).collect()
    }

    async fn replay(
        &self,
        start_pos: u64,
        _buffer: NonZeroUsize,
    ) -> Result<impl Stream<Item = Result<(u64, V), Error>> + Send, Error> {
        replay_owned(self.snapshot(), start_pos)
    }
}

impl<E, V> MutableV2 for Journal<E, V>
where
    E: Context + BatchStorage,
    V: CodecShared,
{
    async fn append(self, item: &V) -> Result<(Self, u64), Error> {
        Self::append(self, item).await
    }

    async fn append_many(self, items: Many<'_, V>) -> Result<(Self, u64), Error> {
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
    use crate::journal::contiguous::variable as legacy;
    use bytes::Bytes;
    use commonware_codec::RangeCfg;
    use commonware_runtime::{
        Runner as _, Storage as _, Supervisor as _,
        buffer::paged::{CacheRef, atomic_page_size, page_size},
        deterministic,
    };
    use commonware_utils::{NZU64, NZUsize};
    use futures::StreamExt as _;

    fn config(partition: &str) -> Config<()> {
        Config {
            partition: partition.into(),
            items_per_section: NZU64!(3),
            compression: None,
            codec_config: (),
            page_size: atomic_page_size(64),
        }
    }

    #[test]
    fn migration_batches_are_bounded_by_encoded_bytes() {
        deterministic::Runner::default().start(|context| async move {
            let item_len = MIGRATION_BATCH_BYTES * 3 / 5;
            let cfg = legacy::Config {
                partition: "v2_variable_migration_batch_bound".into(),
                items_per_section: NZU64!(3),
                compression: None,
                codec_config: RangeCfg::new(0..=MIGRATION_BATCH_BYTES),
                page_cache: CacheRef::from_pooler(&context, page_size(4096), NZUsize!(3)),
                write_buffer: NZUsize!(1024 * 1024),
            };
            let values = [
                Bytes::from(vec![1; item_len]),
                Bytes::from(vec![2; item_len]),
            ];
            let legacy = legacy::Journal::init(context.child("legacy"), cfg)
                .await
                .unwrap();
            let (legacy, _) = legacy.append_many(Many::Flat(&values)).await.unwrap();
            let legacy = legacy.sync().await.unwrap();

            let first =
                Journal::<_, Bytes>::prepare_migration_batch(&legacy, 0, values.len() as u64, None)
                    .await
                    .unwrap();
            assert_eq!(first.item_starts.len(), 1);
            assert!(first.encoded.len() < MIGRATION_BATCH_BYTES);

            let second = Journal::<_, Bytes>::prepare_migration_batch(&legacy, 1, 2, None)
                .await
                .unwrap();
            assert_eq!(second.item_starts.len(), 1);
            legacy.destroy().await.unwrap();
        });
    }

    #[test]
    fn init_migrates_recovered_legacy_pairs_and_removes_legacy_state() {
        deterministic::Runner::default().start(|context| async move {
            let cfg = config("v2_variable_migrate_legacy");
            let legacy_cfg = legacy::Config {
                partition: cfg.partition.clone(),
                items_per_section: cfg.items_per_section,
                compression: cfg.compression,
                codec_config: (),
                page_cache: CacheRef::from_pooler(&context, page_size(64), NZUsize!(3)),
                write_buffer: NZUsize!(128),
            };
            let values = (0..8u64).collect::<Vec<_>>();
            let legacy = legacy::Journal::init(context.child("legacy"), legacy_cfg)
                .await
                .unwrap();
            let (legacy, _) = legacy.append_many(Many::Flat(&values)).await.unwrap();
            let (legacy, _) = legacy.prune(4).await.unwrap();
            let legacy = legacy.sync().await.unwrap();
            assert_eq!(legacy.bounds(), 3..8);
            drop(legacy);

            let journal = Journal::<_, u64>::init(context.child("migrate"), cfg.clone())
                .await
                .unwrap();
            assert_eq!(journal.bounds(), 3..8);
            assert_eq!(
                journal.read_many(&[3, 4, 5, 6, 7]).await.unwrap(),
                vec![3, 4, 5, 6, 7]
            );
            drop(journal);

            for partition in [
                format!("{}_data", cfg.partition),
                format!("{}_data-blobs", cfg.partition),
                format!("{}_offsets", cfg.partition),
                format!("{}_offsets-blobs", cfg.partition),
                format!("{}_offsets-metadata", cfg.partition),
            ] {
                assert!(matches!(
                    context.scan(&partition).await,
                    Err(commonware_runtime::Error::PartitionMissing(_))
                ));
            }

            let journal = Journal::<_, u64>::init(context.child("reopen"), cfg)
                .await
                .unwrap();
            assert_eq!(journal.bounds(), 3..8);
            journal.destroy().await.unwrap();
        });
    }

    #[test]
    fn init_resumes_after_a_staged_pair_replaced_its_legacy_source() {
        deterministic::Runner::default().start(|context| async move {
            let cfg = config("v2_variable_resume_migration");
            let legacy_cfg = legacy::Config {
                partition: cfg.partition.clone(),
                items_per_section: cfg.items_per_section,
                compression: cfg.compression,
                codec_config: (),
                page_cache: CacheRef::from_pooler(&context, page_size(64), NZUsize!(3)),
                write_buffer: NZUsize!(128),
            };
            let values = (0..8u64).collect::<Vec<_>>();
            let legacy = legacy::Journal::init(context.child("legacy"), legacy_cfg)
                .await
                .unwrap();
            let (legacy, _) = legacy.append_many(Many::Flat(&values)).await.unwrap();
            let mut legacy = legacy.sync().await.unwrap();

            let data_partition = cfg.data_partition();
            start_migration(&context, &data_partition, 0).await.unwrap();
            let target = Journal::<_, u64>::fresh(context.child("stage"), cfg.clone(), 0, false)
                .await
                .unwrap();
            let (target, _) = target.append_many(Many::Flat(&values[..3])).await.unwrap();
            let target = target.sync().await.unwrap();
            (legacy, _) = legacy.prune(3).await.unwrap();
            assert_eq!(target.bounds(), 0..3);
            assert_eq!(legacy.bounds(), 3..8);
            drop(target);
            drop(legacy);

            let journal = Journal::<_, u64>::init(context.child("resume"), cfg)
                .await
                .unwrap();
            assert_eq!(journal.bounds(), 0..8);
            assert_eq!(
                journal.read_many(&[0, 2, 3, 5, 7]).await.unwrap(),
                vec![0, 2, 3, 5, 7,]
            );
            journal.destroy().await.unwrap();
        });
    }

    #[test]
    fn init_migrates_an_empty_legacy_journal_at_a_nonzero_start() {
        deterministic::Runner::default().start(|context| async move {
            let cfg = config("v2_variable_migrate_empty_at_size");
            let legacy_cfg = legacy::Config {
                partition: cfg.partition.clone(),
                items_per_section: cfg.items_per_section,
                compression: cfg.compression,
                codec_config: (),
                page_cache: CacheRef::from_pooler(&context, page_size(64), NZUsize!(3)),
                write_buffer: NZUsize!(128),
            };
            let legacy =
                legacy::Journal::<_, u64>::init_at_size(context.child("legacy"), legacy_cfg, 5)
                    .await
                    .unwrap();
            assert_eq!(legacy.bounds(), 5..5);
            drop(legacy);

            let journal = Journal::<_, u64>::init(context.child("migrate"), cfg)
                .await
                .unwrap();
            assert_eq!(journal.bounds(), 5..5);
            journal.destroy().await.unwrap();
        });
    }

    #[test]
    fn activated_migration_cleans_legacy_without_reopening_it() {
        deterministic::Runner::default().start(|context| async move {
            let cfg = config("v2_variable_activated_cleanup");
            let legacy_cfg = legacy::Config {
                partition: cfg.partition.clone(),
                items_per_section: cfg.items_per_section,
                compression: cfg.compression,
                codec_config: (),
                page_cache: CacheRef::from_pooler(&context, page_size(64), NZUsize!(3)),
                write_buffer: NZUsize!(128),
            };
            let values = [10u64, 11];
            let legacy = legacy::Journal::init(context.child("legacy"), legacy_cfg)
                .await
                .unwrap();
            let (legacy, _) = legacy.append_many(Many::Flat(&values)).await.unwrap();
            let legacy = legacy.sync().await.unwrap();

            let data_partition = cfg.data_partition();
            start_migration(&context, &data_partition, 0).await.unwrap();
            let target = Journal::<_, u64>::fresh(context.child("stage"), cfg.clone(), 0, false)
                .await
                .unwrap();
            let (target, _) = target.append_many(Many::Flat(&values)).await.unwrap();
            let target = target.sync().await.unwrap().activate().await.unwrap();
            drop(target);
            drop(legacy);

            let (bad, _) = context
                .open(&format!("{}_data-blobs", cfg.partition), b"bad-name")
                .await
                .unwrap();
            drop(bad);
            let journal = Journal::<_, u64>::init(context.child("cleanup"), cfg)
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
            let cfg = config("v2_variable_destroy_legacy");
            let legacy_cfg = legacy::Config {
                partition: cfg.partition.clone(),
                items_per_section: cfg.items_per_section,
                compression: cfg.compression,
                codec_config: (),
                page_cache: CacheRef::from_pooler(&context, page_size(64), NZUsize!(3)),
                write_buffer: NZUsize!(128),
            };
            let legacy = legacy::Journal::init(context.child("legacy"), legacy_cfg)
                .await
                .unwrap();
            let (legacy, _) = legacy.append(&1u64).await.unwrap();
            let legacy = legacy.sync().await.unwrap();
            drop(legacy);

            // Simulate V2 state created before transparent migration owned the base namespace.
            let journal = Journal::<_, u64>::fresh(context.child("v2"), cfg.clone(), 0, true)
                .await
                .unwrap();
            let (journal, _) = journal.append(&9u64).await.unwrap();
            journal.sync().await.unwrap().destroy().await.unwrap();

            let journal = Journal::<_, u64>::init(context.child("reopen"), cfg)
                .await
                .unwrap();
            assert_eq!(journal.bounds(), 0..0);
            journal.destroy().await.unwrap();
        });
    }

    #[test]
    fn lifecycle_reopen_random_read_and_no_metadata() {
        deterministic::Runner::default().start(|context| async move {
            let cfg = config("v2_variable_lifecycle");
            let values = (0..10u64).collect::<Vec<_>>();
            let journal = Journal::<_, u64>::init(context.child("initial"), cfg.clone())
                .await
                .unwrap();
            let (mut journal, last) = journal.append_many(Many::Flat(&values)).await.unwrap();
            assert_eq!(last, 9);
            assert_eq!(journal.bounds(), 0..10);
            assert_eq!(
                journal.read_many(&[0, 3, 5, 9]).await.unwrap(),
                vec![0, 3, 5, 9]
            );
            let (next, handle) = journal.start_sync().await.unwrap();
            handle.await.unwrap();
            journal = next;

            let replayed = journal
                .replay(7, NZUsize!(32))
                .await
                .unwrap()
                .collect::<Vec<_>>()
                .await
                .into_iter()
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
            assert_eq!(replayed, vec![(7, 7), (8, 8), (9, 9)]);
            drop(journal);

            let mut journal = Journal::<_, u64>::init(context.child("reopen"), cfg.clone())
                .await
                .unwrap();
            assert_eq!(journal.bounds(), 0..10);
            assert_eq!(journal.read(4).await.unwrap(), 4);

            let (next, pruned) = journal.prune(4).await.unwrap();
            journal = next;
            assert!(pruned);
            assert_eq!(journal.bounds(), 3..10);
            journal = journal.rewind(7).await.unwrap();
            assert_eq!(journal.bounds(), 3..7);
            (journal, _) = journal.append(&99).await.unwrap();
            assert_eq!(journal.read_many(&[3, 6, 7]).await.unwrap(), vec![3, 6, 99]);

            journal = journal.clear_to_size(5).await.unwrap();
            (journal, _) = journal.append(&42).await.unwrap();
            journal = journal.sync().await.unwrap();
            assert_eq!(journal.bounds(), 5..6);
            drop(journal);

            let journal = Journal::<_, u64>::init(context.child("reopen_after_clear"), cfg)
                .await
                .unwrap();
            assert_eq!(journal.bounds(), 5..6);
            assert_eq!(journal.read(5).await.unwrap(), 42);

            for partition in [
                "v2_variable_lifecycle-metadata",
                "v2_variable_lifecycle_offsets-metadata",
                "v2_variable_lifecycle-v2-offsets-metadata",
            ] {
                assert!(matches!(
                    context.scan(partition).await,
                    Err(commonware_runtime::Error::PartitionMissing(_))
                ));
            }
            journal.destroy().await.unwrap();
        });
    }

    #[test]
    fn offset_index_remains_logical_across_integrity_footers() {
        deterministic::Runner::default().start(|context| async move {
            let mut cfg = config("v2_variable_small_integrity_pages");
            cfg.items_per_section = NZU64!(8);
            cfg.page_size = atomic_page_size(16);

            let mut journal = Journal::<_, u64>::init(context.child("initial"), cfg.clone())
                .await
                .unwrap();
            for value in 0..6 {
                (journal, _) = journal.append(&value).await.unwrap();
            }
            let tail = journal.sections.get(&0).unwrap();
            assert!(tail.data.physical_size() > tail.data.size());
            assert!(tail.offsets.physical_size() > tail.offsets.size());
            journal = journal.sync().await.unwrap();
            drop(journal);

            let mut journal = Journal::<_, u64>::init(context.child("reopen"), cfg.clone())
                .await
                .unwrap();
            assert_eq!(journal.bounds(), 0..6);
            assert_eq!(
                journal.read_many(&[0, 1, 2, 3, 4, 5]).await.unwrap(),
                vec![0, 1, 2, 3, 4, 5]
            );

            journal = journal.rewind(4).await.unwrap();
            let (journal, position) = journal.append(&99).await.unwrap();
            assert_eq!(position, 4);
            let journal = journal.sync().await.unwrap();
            drop(journal);

            let journal = Journal::<_, u64>::init(context.child("reopen_after_rewind"), cfg)
                .await
                .unwrap();
            assert_eq!(journal.bounds(), 0..5);
            assert_eq!(
                journal.read_many(&[0, 1, 2, 3, 4]).await.unwrap(),
                vec![0, 1, 2, 3, 99]
            );
            journal.destroy().await.unwrap();
        });
    }

    #[test]
    fn unpublished_data_offset_subsets_do_not_advance_reopen() {
        deterministic::Runner::default().start(|context| async move {
            for (case, stage_data, stage_offsets) in [
                ("data", true, false),
                ("offsets", false, true),
                ("both", true, true),
            ] {
                let cfg = config(&format!("v2_variable_unpublished_{case}"));
                let journal = Journal::<_, u64>::init(context.child(case), cfg.clone())
                    .await
                    .unwrap();
                let (journal, _) = journal.append_many(Many::Flat(&[10, 11])).await.unwrap();
                let mut journal = journal.sync().await.unwrap();

                let tail = journal.tail;
                let mut section = journal.sections.remove(&tail).unwrap();
                let offset = section.data.size();
                if stage_data {
                    let mut frame = Vec::new();
                    encode_frame_into(None, &12u64, &mut frame).unwrap();
                    (section.data, _) = section.data.append(&frame).await.unwrap();
                }
                if stage_offsets {
                    (section.offsets, _) =
                        section.offsets.append(&offset.to_be_bytes()).await.unwrap();
                }
                journal.sections.insert(tail, section);
                drop(journal);

                let journal = Journal::<_, u64>::init(context.child("reopen"), cfg)
                    .await
                    .unwrap();
                assert_eq!(journal.bounds(), 0..2);
                assert_eq!(journal.read_many(&[0, 1]).await.unwrap(), vec![10, 11]);
                journal.destroy().await.unwrap();
            }
        });
    }

    #[test]
    fn unpublished_rollovers_are_unreachable_and_keep_the_decision_bounded() {
        deterministic::Runner::default().start(|context| async move {
            let cfg = config("v2_variable_unpublished_rollovers");
            let values = (0..10u64).collect::<Vec<_>>();
            let journal = Journal::<_, u64>::init(context.child("initial"), cfg.clone())
                .await
                .unwrap();
            let (journal, _) = journal.append_many(Many::Flat(&values)).await.unwrap();
            assert_eq!(journal.tail, 3);
            assert_eq!(journal.published_tail, 0);
            assert_eq!(journal.dirty, BTreeSet::from([0, 3]));
            drop(journal);

            let journal = Journal::<_, u64>::init(context.child("reopen"), cfg)
                .await
                .unwrap();
            assert_eq!(journal.bounds(), 0..0);
            assert_eq!(journal.tail, 0);
            assert!(journal.dirty.is_empty());
            journal.destroy().await.unwrap();
        });
    }

    #[test]
    fn noncanonical_markers_are_rejected_before_pair_cleanup() {
        deterministic::Runner::default().start(|context| async move {
            for (case, mut marker) in [
                ("absent", NO_MARKER),
                ("present", encode_start_marker(0).unwrap()),
            ] {
                marker[8] = 1;
                let base = format!("v2_variable_noncanonical_marker_{case}");
                let cfg = config(&base);
                let data_partition = cfg.data_partition();
                let offsets_partition = cfg.offsets_partition();
                let mut journal = Journal::<_, u64>::init(context.child("initial"), cfg.clone())
                    .await
                    .unwrap();
                let section = journal.sections.remove(&journal.tail).unwrap();
                let section = section.set_marker(marker).await.unwrap();
                section.sync().await.unwrap();
                journal.sections.insert(journal.tail, section);
                drop(journal);

                let mut data_before = context.scan(&data_partition).await.unwrap();
                let mut offsets_before = context.scan(&offsets_partition).await.unwrap();
                data_before.sort();
                offsets_before.sort();
                let reopened = Journal::<_, u64>::init(context.child("reopen"), cfg).await;
                assert!(matches!(reopened, Err(Error::Corruption(_))), "{case}");
                let mut data_after = context.scan(&data_partition).await.unwrap();
                let mut offsets_after = context.scan(&offsets_partition).await.unwrap();
                data_after.sort();
                offsets_after.sort();
                assert_eq!(data_after, data_before, "{case}");
                assert_eq!(offsets_after, offsets_before, "{case}");
                context.remove(&data_partition, None).await.unwrap();
                context.remove(&offsets_partition, None).await.unwrap();
            }
        });
    }
}
