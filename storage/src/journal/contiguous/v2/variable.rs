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
    MutableV2,
};
use crate::{
    Context,
    journal::{
        Error,
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
const NO_MARKER: [u8; ATOMIC_MARKER_LEN] = [0; ATOMIC_MARKER_LEN];

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

fn encode_marker(start: u64) -> Result<[u8; ATOMIC_MARKER_LEN], Error> {
    Ok(start
        .checked_add(1)
        .ok_or(Error::SizeOverflow)?
        .to_be_bytes())
}

const fn decode_marker(marker: [u8; ATOMIC_MARKER_LEN]) -> Option<u64> {
    u64::from_be_bytes(marker).checked_sub(1)
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

    async fn scan_names(context: &E, partition: &str) -> Result<Vec<Vec<u8>>, Error> {
        match context.scan(partition).await {
            Ok(names) => Ok(names),
            Err(commonware_runtime::Error::PartitionMissing(_)) => Ok(Vec::new()),
            Err(error) => Err(error.into()),
        }
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
            let Some(start) = decode_marker(root.marker) else {
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

    async fn fresh(context: E, cfg: Config<V::Cfg>, start: u64) -> Result<Self, Error> {
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
        let marker = encode_marker(start)?;
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
            _item: PhantomData,
        })
    }

    async fn init_inner(context: E, cfg: Config<V::Cfg>) -> Result<Self, Error> {
        Self::validate_config(&cfg)?;
        let data_partition = cfg.data_partition();
        let offsets_partition = cfg.offsets_partition();
        let data_names = Self::scan_names(&context, &data_partition).await?;
        let offsets_names = Self::scan_names(&context, &offsets_partition).await?;
        if data_names.is_empty() && offsets_names.is_empty() {
            return Self::fresh(context, cfg, 0).await;
        }

        // Root inspection does not read payload. AtomicWriter is constructed only after the
        // movable markers identify the retained interval.
        let mut data = Self::open_roots(&context, &data_partition, data_names).await?;
        let mut offsets = Self::open_roots(&context, &offsets_partition, offsets_names).await?;
        let data_authority = Self::authority(&data, "data")?;
        let offsets_authority = Self::authority(&offsets, "offsets")?;
        let authority = match (data_authority, offsets_authority) {
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
                return Self::fresh(context, cfg, 0).await;
            }
            (Some(data), Some(offsets)) if data == offsets => data,
            _ => {
                return Err(Error::Corruption(
                    "V2 variable data and offsets tail markers disagree".into(),
                ));
            }
        };

        let (tail, start) = authority;
        let items_per_section = cfg.items_per_section.get();
        let oldest = position_to_blob(start, items_per_section);
        if tail < oldest {
            return Err(Error::Corruption(
                "V2 variable tail marker precedes the journal start".into(),
            ));
        }

        let marker = encode_marker(start)?;
        let mut sections = BTreeMap::new();
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
            if data_writer.size() == 0 || data_writer.size() % u64::from(cfg.page_size.get()) != 0 {
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

        let tail_first = first_in_section(start, tail, items_per_section)?;
        let end = tail_first
            .checked_add(tail_count)
            .ok_or(Error::SizeOverflow)?;

        // Names outside the marker-defined interval are crash artifacts. Removing them cannot
        // change logical state because neither root carries authority.
        let stale_data = data.keys().copied().collect::<Vec<_>>();
        let stale_offsets = offsets.keys().copied().collect::<Vec<_>>();
        Self::remove_named(&context, &data_partition, &stale_data).await?;
        Self::remove_named(&context, &offsets_partition, &stale_offsets).await?;

        Ok(Self {
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
            codec_config: cfg.codec_config,
            page_size: cfg.page_size,
            _item: PhantomData,
        })
    }

    /// Open or create a V2 variable journal.
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
        let marker = encode_marker(self.bounds.start)?;

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
        let marker = encode_marker(start)?;
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
        let marker = encode_marker(self.bounds.start)?;
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
        let marker = encode_marker(size)?;
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

    /// Remove both V2 journal partitions.
    ///
    /// This final teardown is not crash-safe; use [`clear_to_size`](Self::clear_to_size) for a
    /// recoverable reset.
    pub async fn destroy(self) -> Result<(), Error> {
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
    use commonware_runtime::{
        Runner as _, Storage as _, Supervisor as _, buffer::paged::atomic_page_size, deterministic,
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
}
