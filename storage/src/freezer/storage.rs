use super::{Config, Error, Identifier};
use crate::Context;
use commonware_codec::{CodecShared, FixedArray, FixedSize, Read, ReadExt, Write as CodecWrite};
use commonware_cryptography::Crc32;
use commonware_runtime::{
    buffer::{self, paged},
    telemetry::metrics::{Counter, MetricsExt as _},
    Blob, Buf, BufMut, BufferPooler,
};
use commonware_utils::{Array, Span};
use futures::future::try_join;
use std::{marker::PhantomData, num::NonZeroUsize, ops::Deref};
use tracing::debug;
use zstd::{bulk::compress, decode_all};

/// The percentage of table entries that must reach `table_resize_frequency`
/// before a resize is triggered.
const RESIZE_THRESHOLD: u64 = 50;

/// Location of an item in the [Freezer].
///
/// This can be used to directly access the data for a given
/// key-value pair (rather than walking the record chain).
#[derive(Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, FixedArray)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[repr(transparent)]
pub struct Cursor([u8; u64::SIZE + u32::SIZE]);

impl Cursor {
    /// Create a new [Cursor].
    fn new(offset: u64, size: u32) -> Self {
        let mut buf = [0u8; u64::SIZE + u32::SIZE];
        buf[..u64::SIZE].copy_from_slice(&offset.to_be_bytes());
        buf[u64::SIZE..].copy_from_slice(&size.to_be_bytes());
        Self(buf)
    }

    /// Get the byte offset of the value in the value blob.
    fn offset(&self) -> u64 {
        u64::from_be_bytes(self.0[..u64::SIZE].try_into().unwrap())
    }

    /// Get the size of the value.
    fn size(&self) -> u32 {
        u32::from_be_bytes(self.0[u64::SIZE..].try_into().unwrap())
    }
}

impl Read for Cursor {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        <[u8; u64::SIZE + u32::SIZE]>::read(buf).map(Self)
    }
}

impl CodecWrite for Cursor {
    fn write(&self, buf: &mut impl BufMut) {
        self.0.write(buf);
    }
}

impl FixedSize for Cursor {
    const SIZE: usize = u64::SIZE + u32::SIZE;
}

impl Span for Cursor {}

impl Array for Cursor {}

impl Deref for Cursor {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<[u8]> for Cursor {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for Cursor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Cursor(offset={}, size={})", self.offset(), self.size())
    }
}

impl std::fmt::Display for Cursor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Cursor(offset={}, size={})", self.offset(), self.size())
    }
}

/// Name of the table blob.
const TABLE_BLOB_NAME: &[u8] = b"table";

/// Name of the key record blob.
const KEYS_BLOB_NAME: &[u8] = b"keys";

/// Name of the value blob.
const VALUES_BLOB_NAME: &[u8] = b"values";

/// Chain head stored in a table slot.
#[derive(Debug, Clone, PartialEq)]
struct Entry {
    // Position of the chain head in the key record blob
    position: u64,
    // Number of items added to this entry since last resize
    added: u8,
}

impl Entry {
    /// The size of a table slot: an occupancy tag followed by an [Entry].
    ///
    /// The tag distinguishes an empty slot (all zeros, the initial state of every
    /// table range) from a chain head at position 0.
    const SLOT_SIZE: usize = u8::SIZE + u64::SIZE + u8::SIZE;

    /// Parse a table slot, consuming [Self::SLOT_SIZE] bytes from `buf`.
    fn read_slot(buf: &mut impl Buf) -> Result<Option<Self>, Error> {
        let tag = u8::read(buf).map_err(Error::Codec)?;
        match tag {
            0 => {
                buf.advance(Self::SLOT_SIZE - u8::SIZE);
                Ok(None)
            }
            1 => {
                let position = u64::read(buf).map_err(Error::Codec)?;
                let added = u8::read(buf).map_err(Error::Codec)?;
                Ok(Some(Self { position, added }))
            }
            tag => Err(Error::Codec(commonware_codec::Error::InvalidEnum(tag))),
        }
    }

    /// Write a table slot, producing [Self::SLOT_SIZE] bytes into `buf`.
    fn write_slot(buf: &mut impl BufMut, entry: Option<&Self>) {
        match entry {
            Some(entry) => {
                1u8.write(buf);
                entry.position.write(buf);
                entry.added.write(buf);
            }
            None => buf.put_bytes(0, Self::SLOT_SIZE),
        }
    }
}

/// Sentinel value indicating no next record in the collision chain.
const NO_NEXT: u64 = u64::MAX;

/// Key record stored in the key record blob.
///
/// All fields are fixed size, enabling efficient collision chain traversal
/// without reading values.
///
/// The `next` pointer uses the sentinel value `u64::MAX` to indicate "no next
/// record" instead of Option, ensuring fixed-size encoding. Records are
/// append-only and chains grow at the head, so `next` always references a
/// strictly smaller position.
#[derive(Debug, Clone, PartialEq)]
struct Record<K: Array> {
    /// The key for this record.
    key: K,
    /// Position of the next record in the collision chain.
    /// Uses u64::MAX as sentinel for "no next".
    next: u64,
    /// Byte offset of the value in the value blob.
    value_offset: u64,
    /// Size of the value's stored bytes in the value blob.
    value_size: u32,
}

impl<K: Array> Record<K> {
    /// Create a new [Record].
    fn new(key: K, next: Option<u64>, value_offset: u64, value_size: u32) -> Self {
        Self {
            key,
            next: next.unwrap_or(NO_NEXT),
            value_offset,
            value_size,
        }
    }

    /// Get the position of the next record in the collision chain, if any.
    const fn next(&self) -> Option<u64> {
        if self.next == NO_NEXT {
            None
        } else {
            Some(self.next)
        }
    }
}

impl<K: Array> CodecWrite for Record<K> {
    fn write(&self, buf: &mut impl BufMut) {
        self.key.write(buf);
        self.next.write(buf);
        self.value_offset.write(buf);
        self.value_size.write(buf);
    }
}

impl<K: Array> Read for Record<K> {
    type Cfg = ();
    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        let key = K::read(buf)?;
        let next = u64::read(buf)?;
        let value_offset = u64::read(buf)?;
        let value_size = u32::read(buf)?;

        Ok(Self {
            key,
            next,
            value_offset,
            value_size,
        })
    }
}

impl<K: Array> FixedSize for Record<K> {
    // key + next + value_offset + value_size
    const SIZE: usize = K::SIZE + u64::SIZE + u64::SIZE + u32::SIZE;
}

#[cfg(feature = "arbitrary")]
impl<K: Array> arbitrary::Arbitrary<'_> for Record<K>
where
    K: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            key: K::arbitrary(u)?,
            next: u64::arbitrary(u)?,
            value_offset: u64::arbitrary(u)?,
            value_size: u32::arbitrary(u)?,
        })
    }
}

/// Implementation of [Freezer].
pub struct Freezer<E: BufferPooler + Context, K: Array, V: CodecShared> {
    // Context for storage operations
    context: E,

    // Table configuration
    table_partition: String,
    table_size: u32,
    table_resize_threshold: u64,
    table_resize_frequency: u8,
    table_resize_chunk_size: u32,

    // Table blob that maps slots to key record chain heads
    table: E::Blob,

    // Key record blob: one fixed-size record per put, addressed by position
    // (insertion order). Appends buffer in the writer and reads go through
    // the page cache (chain traversal has good locality).
    key_partition: String,
    keys: paged::Writer<E::Blob>,

    // Value blob: encoded values back to back, addressed by (offset, size).
    // Reads go directly to the blob (values should not pollute a page cache).
    value_partition: String,
    values: buffer::Write<E::Blob>,
    value_compression: Option<u8>,
    codec_config: V::Cfg,

    resizable: u32,
    resize_progress: Option<u32>,

    // Metrics
    puts: Counter,
    gets: Counter,
    has: Counter,
    unnecessary_reads: Counter,
    unnecessary_writes: Counter,
    resizes: Counter,

    _key: PhantomData<K>,
}

impl<E: BufferPooler + Context, K: Array, V: CodecShared> Freezer<E, K, V> {
    /// Size of each key record in bytes (as u64).
    const RECORD_SIZE: u64 = Record::<K>::SIZE as u64;

    /// Calculate the byte offset for a table index.
    #[inline]
    const fn table_offset(table_index: u32) -> u64 {
        table_index as u64 * Entry::SLOT_SIZE as u64
    }

    /// Read the chain head from the table blob.
    async fn read_table(blob: &E::Blob, table_index: u32) -> Result<Option<Entry>, Error> {
        let offset = Self::table_offset(table_index);
        let mut read_buf = blob.read_at(offset, Entry::SLOT_SIZE).await?;

        Entry::read_slot(&mut read_buf)
    }

    /// Scan the table, validating every slot and counting resizable entries.
    ///
    /// Committed slots always reference committed key records: [Freezer::sync] and
    /// [Freezer::sync_into] commit the key record blob, the value blob, and the table
    /// in ONE atomic commit. A slot that does not decode, or that references a record
    /// the key record blob does not hold, is therefore corruption or tampering, never
    /// a state a crash can produce.
    ///
    /// Returns the number of entries that can be resized.
    async fn scan_table(
        pooler: &impl BufferPooler,
        blob: &E::Blob,
        key_positions: u64,
        table_size: u32,
        table_resize_frequency: u8,
        table_replay_buffer: NonZeroUsize,
    ) -> Result<u32, Error> {
        // Create a buffered reader for efficient scanning
        let blob_size = Self::table_offset(table_size);
        let mut reader =
            buffer::Read::from_pooler(pooler, blob.clone(), blob_size, table_replay_buffer);

        let mut resizable = 0u32;
        for _ in 0..table_size {
            let mut slot_buf = reader.read(Entry::SLOT_SIZE).await?;
            let Some(entry) = Entry::read_slot(&mut slot_buf)? else {
                continue;
            };

            // Verify the chain head references a record the key record blob holds
            if entry.position >= key_positions {
                return Err(Error::MissingRecord(entry.position));
            }

            // If the entry has reached the resize frequency, increment the resizable entries
            if entry.added >= table_resize_frequency {
                resizable += 1;
            }
        }

        Ok(resizable)
    }

    /// Write a chain head to the table slot at `offset`.
    async fn write_head(
        pooler: &impl BufferPooler,
        table: &E::Blob,
        offset: u64,
        entry: Option<&Entry>,
    ) -> Result<(), Error> {
        let mut buf = pooler.storage_buffer_pool().alloc(Entry::SLOT_SIZE);
        Entry::write_slot(&mut buf, entry);
        table
            .write_at(offset, buf.freeze())
            .await
            .map_err(Error::Runtime)
    }

    /// Initialize table with given size and sync.
    async fn init_table(blob: &E::Blob, table_size: u32) -> Result<(), Error> {
        let table_len = Self::table_offset(table_size);
        blob.resize(table_len).await?;
        blob.sync().await?;
        Ok(())
    }

    /// Initialize a [Freezer] instance, recovering existing data from its own committed
    /// state (see the module's Recovery documentation).
    pub async fn init(context: E, config: Config<V::Cfg>) -> Result<Self, Error> {
        // Validate that initial_table_size is a power of 2
        assert!(
            config.table_initial_size > 0 && config.table_initial_size.is_power_of_two(),
            "table_initial_size must be a power of 2"
        );

        // Open the key record and value blobs
        let (keys_blob, keys_len) = context.open(&config.key_partition, KEYS_BLOB_NAME).await?;
        let (values_blob, values_len) = context
            .open(&config.value_partition, VALUES_BLOB_NAME)
            .await?;

        // Verify the two blobs describe a committed freezer state. The storage backend
        // guarantees per-blob atomic sync (a partial record cannot survive a crash) and
        // both blobs commit in the same batch (see the module's Recovery documentation),
        // so a partial record or any skew between the blobs is corruption or tampering,
        // never a state a crash can produce. Value offsets are appended in monotone
        // order, so checking the last record's value range bounds all earlier ones.
        if !keys_len.is_multiple_of(Self::RECORD_SIZE) {
            return Err(Error::Corruption(format!(
                "key record blob has a partial record: {keys_len} bytes"
            )));
        }
        let key_positions = keys_len / Self::RECORD_SIZE;
        let value_end = if key_positions == 0 {
            0
        } else {
            let mut buf = keys_blob
                .read_at(keys_len - Self::RECORD_SIZE, Record::<K>::SIZE)
                .await?;
            let record = Record::<K>::read(&mut buf)?;
            record
                .value_offset
                .checked_add(u64::from(record.value_size))
                .ok_or_else(|| {
                    Error::Corruption("last key record's value range overflows".into())
                })?
        };
        if value_end != values_len {
            return Err(Error::Corruption(format!(
                "key records reference {value_end} value bytes but {values_len} are committed"
            )));
        }

        // Wrap the blobs for buffered appends
        let keys = paged::Writer::new(
            keys_blob,
            keys_len,
            config.key_write_buffer.get(),
            config.key_page_cache.clone(),
        )
        .await?;
        let values = buffer::Write::from_pooler(
            &context,
            values_blob,
            values_len,
            config.value_write_buffer,
        );

        // Open table blob
        let (table, table_len) = context
            .open(&config.table_partition, TABLE_BLOB_NAME)
            .await?;

        // Recover the table geometry from the blob length. The blob holds `table_size`
        // slots plus one slot per landed resize chunk (the blob grows only as chunks are
        // written, never up front), so the committed size is the largest power of two of
        // slots the blob holds. Length past that boundary is a resize the freezer did not
        // finish: the partially copied upper half is dropped and the resize restarts once
        // triggered again.
        let (table_size, resizable) = if table_len == 0 {
            Self::init_table(&table, config.table_initial_size).await?;
            (config.table_initial_size, 0)
        } else {
            let slots = table_len / Entry::SLOT_SIZE as u64;
            let table_size = slots
                .checked_ilog2()
                .and_then(|bits| u32::try_from(1u64 << bits).ok())
                .ok_or(Error::InvalidTableLength(table_len))?;
            let expected_table_len = Self::table_offset(table_size);
            if table_len != expected_table_len {
                debug!(
                    from = table_len,
                    to = expected_table_len,
                    "dropped interrupted resize"
                );
                table.resize(expected_table_len).await?;
            }
            let resizable = Self::scan_table(
                &context,
                &table,
                key_positions,
                table_size,
                config.table_resize_frequency,
                config.table_replay_buffer,
            )
            .await?;
            (table_size, resizable)
        };

        // Create metrics
        let puts = context.counter("puts", "number of put operations");
        let gets = context.counter("gets", "number of get operations");
        let has = context.counter("has", "number of has operations");
        let unnecessary_reads = context.counter(
            "unnecessary_reads",
            "number of unnecessary reads performed during key lookups",
        );
        let unnecessary_writes = context.counter(
            "unnecessary_writes",
            "number of unnecessary writes performed during resize",
        );
        let resizes = context.counter("resizes", "number of table resizing operations");

        Ok(Self {
            context,
            table_partition: config.table_partition,
            table_size,
            table_resize_threshold: table_size as u64 * RESIZE_THRESHOLD / 100,
            table_resize_frequency: config.table_resize_frequency,
            table_resize_chunk_size: config.table_resize_chunk_size,
            table,
            key_partition: config.key_partition,
            keys,
            value_partition: config.value_partition,
            values,
            value_compression: config.value_compression,
            codec_config: config.codec_config,
            resizable,
            resize_progress: None,
            puts,
            gets,
            has,
            unnecessary_reads,
            unnecessary_writes,
            resizes,
            _key: PhantomData,
        })
    }

    /// Compute the table index for a given key.
    ///
    /// As the table doubles in size during a resize, each existing entry splits into two:
    /// one at the original index and another at a new index (original index + previous table size).
    ///
    /// For example, with an initial table size of 4 (2^2):
    /// - Initially: uses 2 bits of the hash, mapping to entries 0, 1, 2, 3.
    /// - After resizing to 8: uses 3 bits, entry 0 splits into indices 0 and 4.
    /// - After resizing to 16: uses 4 bits, entry 0 splits into indices 0 and 8, and so on.
    ///
    /// To determine the appropriate entry, we AND the key's hash with the current table size.
    fn table_index(&self, key: &K) -> u32 {
        let hash = Crc32::checksum(key.as_ref());
        hash & (self.table_size - 1)
    }

    /// Determine if the table should be resized.
    const fn should_resize(&self) -> bool {
        self.resizable as u64 >= self.table_resize_threshold
    }

    /// Put a key-value pair into the [Freezer].
    /// If the key already exists, the value is updated.
    pub async fn put(&mut self, key: K, value: V) -> Result<Cursor, Error> {
        self.puts.inc();

        // Get head of the chain from table
        let table_index = self.table_index(&key);
        let head = Self::read_table(&self.table, table_index).await?;

        // Encode (and optionally compress) the value, then write it at the tip of the
        // value blob. This will typically write to an in-memory buffer and return
        // quickly (only blocks when the buffer is full).
        let buf = if let Some(level) = self.value_compression {
            let encoded = value.encode();
            compress(&encoded, level as i32).map_err(|_| Error::CompressionFailed)?
        } else {
            // Uncompressed: pre-allocate exact size to avoid copying
            let mut buf = Vec::with_capacity(value.encode_size());
            value.write(&mut buf);
            buf
        };
        let value_size = u32::try_from(buf.len()).map_err(|_| Error::ValueTooLarge(buf.len()))?;
        let value_offset = self.values.size();
        self.values.write_at(value_offset, buf).await?;

        // Append the key record with a pointer to the previous head
        let record = Record::new(
            key,
            head.as_ref().map(|entry| entry.position),
            value_offset,
            value_size,
        );
        let mut record_buf = self.context.storage_buffer_pool().alloc(Record::<K>::SIZE);
        record.write(&mut record_buf);
        let record_offset = self.keys.append_owned(record_buf.freeze()).await?;
        debug_assert!(record_offset.is_multiple_of(Self::RECORD_SIZE));
        let position = record_offset / Self::RECORD_SIZE;

        // Update the number of items added to the entry.
        //
        // We use `saturating_add` to handle overflow (when the table is at max size) gracefully.
        let mut added = head.map(|entry| entry.added).unwrap_or(0);
        added = added.saturating_add(1);

        // If we've reached the threshold for resizing, increment the resizable entries
        if added == self.table_resize_frequency {
            self.resizable += 1;
        }

        // Update the old position
        let new_entry = Entry { position, added };
        Self::write_head(
            &self.context,
            &self.table,
            Self::table_offset(table_index),
            Some(&new_entry),
        )
        .await?;

        // If we're mid-resize and this entry has already been processed, update the new position too
        if let Some(resize_progress) = self.resize_progress {
            if table_index < resize_progress {
                self.unnecessary_writes.inc();

                // If the previous entry crossed the threshold, so did this one
                if added == self.table_resize_frequency {
                    self.resizable += 1;
                }

                // This entry has been processed, so we need to update the new position as well
                let new_table_index = self.table_size + table_index;
                Self::write_head(
                    &self.context,
                    &self.table,
                    Self::table_offset(new_table_index),
                    Some(&new_entry),
                )
                .await?;
            }
        }

        Ok(Cursor::new(value_offset, value_size))
    }

    /// Read the key record at `position`.
    async fn read_record(&self, position: u64) -> Result<Record<K>, Error> {
        // Positions originate from committed table slots (validated at initialization)
        // and this instance's own appends, so an unaddressable position is corruption.
        let offset = position.checked_mul(Self::RECORD_SIZE).ok_or_else(|| {
            Error::Corruption(format!("record position {position} is unaddressable"))
        })?;
        let mut buf = self.keys.read_at(offset, Record::<K>::SIZE).await?;
        Record::<K>::read(&mut buf).map_err(Error::Codec)
    }

    /// Read and decode the value at `offset` with known `size`.
    async fn read_value(&self, offset: u64, size: u32) -> Result<V, Error> {
        let buf = self.values.read_at(offset, size as usize).await?.coalesce();
        if self.value_compression.is_some() {
            let decompressed = decode_all(buf.as_ref()).map_err(|_| Error::DecompressionFailed)?;
            V::decode_cfg(decompressed.as_ref(), &self.codec_config).map_err(Error::Codec)
        } else {
            V::decode_cfg(buf.as_ref(), &self.codec_config).map_err(Error::Codec)
        }
    }

    /// Get the value for a given [Cursor].
    async fn get_cursor(&self, cursor: Cursor) -> Result<V, Error> {
        self.read_value(cursor.offset(), cursor.size()).await
    }

    /// Find the first key record matching `key`.
    ///
    /// Reads key records only, never values.
    async fn find_key(&self, key: &K) -> Result<Option<Record<K>>, Error> {
        // Get head of the chain from table
        let table_index = self.table_index(key);
        let Some(head) = Self::read_table(&self.table, table_index).await? else {
            return Ok(None);
        };
        let mut position = head.position;

        // Follow the linked list chain to find the first matching key
        loop {
            // Get the key record from the key record blob (fixed size, page-cached)
            let record = self.read_record(position).await?;

            // Check if this key matches
            if record.key.as_ref() == key.as_ref() {
                return Ok(Some(record));
            }

            // Increment unnecessary reads
            self.unnecessary_reads.inc();

            // Follow the chain
            let Some(next) = record.next() else {
                break; // End of chain
            };
            position = next;
        }

        Ok(None)
    }

    /// Get the first value for a given key.
    async fn get_key(&self, key: &K) -> Result<Option<V>, Error> {
        self.gets.inc();

        let Some(record) = self.find_key(key).await? else {
            return Ok(None);
        };
        let value = self
            .read_value(record.value_offset, record.value_size)
            .await?;
        Ok(Some(value))
    }

    /// Get the value for a given [Identifier].
    ///
    /// If a [Cursor] is known for the required key, it
    /// is much faster to use it than searching for a `key`.
    pub async fn get<'a>(&'a self, identifier: Identifier<'a, K>) -> Result<Option<V>, Error> {
        match identifier {
            Identifier::Cursor(cursor) => self.get_cursor(cursor).await.map(Some),
            Identifier::Key(key) => self.get_key(key).await,
        }
    }

    /// Check whether a value exists for a given key.
    ///
    /// Walks the same key record chain as [`Self::get`] with [`Identifier::Key`]
    /// but never reads values.
    pub async fn has(&self, key: &K) -> Result<bool, Error> {
        self.has.inc();

        Ok(self.find_key(key).await?.is_some())
    }

    /// Resize the table by doubling its size and split each entry into two.
    ///
    /// The table blob is not extended here: it grows one slot per chunk entry as
    /// [Self::advance_resize] writes the upper half, so the blob length always encodes
    /// how far a resize progressed (see [Self::init]).
    fn start_resize(&mut self) {
        self.resizes.inc();

        // Double the table size (if not already at the max size)
        let old_size = self.table_size;
        let Some(new_size) = old_size.checked_mul(2) else {
            return;
        };

        // Start the resize
        self.resize_progress = Some(0);
        debug!(old = old_size, new = new_size, "table resize started");
    }

    /// Continue a resize operation by processing the next chunk of entries.
    ///
    /// This function processes `table_resize_chunk_size` entries at a time, allowing the resize to
    /// be spread across multiple sync operations to avoid latency spikes.
    async fn advance_resize(&mut self) -> Result<(), Error> {
        // Compute the range to update
        let current_index = self.resize_progress.unwrap();
        let old_size = self.table_size;
        let chunk_end = (current_index + self.table_resize_chunk_size).min(old_size);
        let chunk_size = chunk_end - current_index;

        // Read the entire chunk
        let chunk_bytes = chunk_size as usize * Entry::SLOT_SIZE;
        let read_offset = Self::table_offset(current_index);
        let mut read_buf = self.table.read_at(read_offset, chunk_bytes).await?;

        // Process each entry in the chunk
        let mut writes = self.context.storage_buffer_pool().alloc(chunk_bytes);
        for _ in 0..chunk_size {
            // Get the current head
            let head = Entry::read_slot(&mut read_buf)?;

            // Get the reset entry (may be empty)
            let reset_entry = head.map(|entry| {
                // If the entry was at or over the threshold, decrement the resizable entries.
                if entry.added >= self.table_resize_frequency {
                    self.resizable -= 1;
                }
                Entry { added: 0, ..entry }
            });

            // Rewrite the slot
            Entry::write_slot(&mut writes, reset_entry.as_ref());
        }

        // Put the writes into the table.
        let writes = writes.freeze();
        let old_write = self.table.write_at(read_offset, writes.clone());
        let new_offset = (old_size as usize * Entry::SLOT_SIZE) as u64 + read_offset;
        let new_write = self.table.write_at(new_offset, writes);
        try_join(old_write, new_write).await?;

        // Update progress
        if chunk_end >= old_size {
            // Resize complete
            self.table_size = old_size * 2;
            self.table_resize_threshold = self.table_size as u64 * RESIZE_THRESHOLD / 100;
            self.resize_progress = None;
            debug!(
                old = old_size,
                new = self.table_size,
                "table resize completed"
            );
        } else {
            // More chunks to process
            self.resize_progress = Some(chunk_end);
            debug!(current = current_index, chunk_end, "table resize progress");
        }

        Ok(())
    }

    /// Sync all pending data in [Freezer].
    ///
    /// If the table needs to be resized, the resize will begin during this sync.
    /// The resize operation is performed incrementally across multiple sync calls
    /// to avoid a large latency spike (or unexpected long latency for [Freezer::put]).
    /// Each sync will process up to `table_resize_chunk_size` entries until the resize
    /// is complete.
    //
    // TODO:(<https://github.com/commonwarexyz/monorepo/issues/2910>): Make this non &mut.
    pub async fn sync(&mut self) -> Result<(), Error> {
        // Stage the key/value blobs' syncs and the table write with one batch:
        // ONE atomic commit makes them durable together, so the table can never
        // reference records the key record blob does not hold.
        let mut batch = self.context.batch().await.map_err(Error::Runtime)?;
        self.sync_into(&mut batch).await?;
        commonware_runtime::WriteBatch::apply_sync(batch)
            .await
            .map_err(Error::Runtime)
    }

    /// [Self::sync], staged with `batch` instead of synced directly: the key
    /// record blob, the value blob, and the table become durable when the
    /// batch is applied.
    pub async fn sync_into<T: commonware_runtime::WriteBatch<Blob = E::Blob>>(
        &mut self,
        batch: &mut T,
    ) -> Result<(), Error> {
        // The value blob is staged before the key record blob so a sequentially
        // replayed batch (the test-only mock fallback) never syncs records ahead
        // of the values they reference.
        self.values.sync_into(batch).await?;
        self.keys.sync_into(batch).await?;

        if self.should_resize() && self.resize_progress.is_none() {
            self.start_resize();
        }
        if self.resize_progress.is_some() {
            self.advance_resize().await?;
        }

        // Table entries are written directly to the blob. Stage its
        // durability with the batch.
        batch.sync(&self.table);

        Ok(())
    }

    /// Close the [Freezer], making all pending data durable.
    pub async fn close(mut self) -> Result<(), Error> {
        // If we're mid-resize, complete it
        while self.resize_progress.is_some() {
            self.advance_resize().await?;
        }

        // Sync any pending updates before closing
        self.sync().await
    }

    /// Close and remove any underlying blobs created by the [Freezer], in ONE atomic commit.
    pub async fn destroy(self) -> Result<(), Error> {
        let mut batch = self.context.batch().await.map_err(Error::Runtime)?;
        self.destroy_into(&mut batch);
        commonware_runtime::WriteBatch::apply_sync(batch)
            .await
            .map_err(Error::Runtime)
    }

    /// [Self::destroy], staged with `batch`: every partition removal lands when the
    /// caller applies the batch with `apply_sync`, atomically with everything else it
    /// stages.
    ///
    /// All three partitions exist: their blobs are opened at initialization.
    pub(crate) fn destroy_into<T: commonware_runtime::WriteBatch<Blob = E::Blob>>(
        self,
        batch: &mut T,
    ) {
        drop(self.keys);
        batch.remove(&self.key_partition, None);
        drop(self.values);
        batch.remove(&self.value_partition, None);
        drop(self.table);
        batch.remove(&self.table_partition, None);
    }

    /// Get the current progress of the resize operation.
    ///
    /// Returns `None` if the [Freezer] is not resizing.
    #[cfg(test)]
    pub const fn resizing(&self) -> Option<u32> {
        self.resize_progress
    }

    /// Get the number of resizable entries.
    #[cfg(test)]
    pub const fn resizable(&self) -> u32 {
        self.resizable
    }
}

#[cfg(all(test, feature = "arbitrary"))]
mod conformance {
    use super::*;
    use commonware_codec::conformance::CodecConformance;
    use commonware_utils::sequence::U64;

    commonware_conformance::conformance_tests! {
        CodecConformance<Cursor>,
        CodecConformance<Record<U64>>
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::DecodeExt;
    use commonware_macros::test_traced;
    use commonware_runtime::{
        buffer::paged::CacheRef, deterministic, deterministic::Context, Runner, Storage,
        Supervisor as _,
    };
    use commonware_utils::{
        sequence::{FixedBytes, U64},
        NZUsize, NZU16,
    };

    fn test_key(key: &str) -> FixedBytes<64> {
        let mut buf = [0u8; 64];
        let key = key.as_bytes();
        assert!(key.len() <= buf.len());
        buf[..key.len()].copy_from_slice(key);
        FixedBytes::decode(buf.as_ref()).unwrap()
    }

    /// Generate `count` distinct keys that all map to `table_index` in a table of
    /// `table_size` slots.
    fn test_keys_at_index(table_size: u32, table_index: u32, count: usize) -> Vec<FixedBytes<64>> {
        assert!(table_size.is_power_of_two());
        assert!(table_index < table_size);

        let mut keys = Vec::with_capacity(count);
        for value in 0u64.. {
            let mut buf = [0u8; 64];
            let bytes = value.to_be_bytes();
            buf[..bytes.len()].copy_from_slice(&bytes);
            let key = FixedBytes::new(buf);
            if Crc32::checksum(key.as_ref()) & (table_size - 1) == table_index {
                keys.push(key);
                if keys.len() == count {
                    return keys;
                }
            }
        }

        unreachable!("u64 key space exhausted");
    }

    fn test_key_at_index(table_size: u32, table_index: u32) -> FixedBytes<64> {
        test_keys_at_index(table_size, table_index, 1)
            .pop()
            .unwrap()
    }

    fn test_cfg(
        pooler: &impl BufferPooler,
        table_initial_size: u32,
        table_resize_frequency: u8,
        table_resize_chunk_size: u32,
    ) -> super::super::Config<()> {
        super::super::Config {
            key_partition: "test-key".into(),
            key_write_buffer: NZUsize!(1024),
            key_page_cache: CacheRef::from_pooler(pooler, NZU16!(1024), NZUsize!(10)),
            value_partition: "test-value".into(),
            value_compression: None,
            value_write_buffer: NZUsize!(1024),
            table_partition: "test-table".into(),
            table_initial_size,
            table_resize_frequency,
            table_resize_chunk_size,
            table_replay_buffer: NZUsize!(64 * 1024),
            codec_config: (),
        }
    }

    type TestFreezer = Freezer<Context, U64, u64>;

    fn is_send<T: Send>(_: T) {}

    #[allow(dead_code)]
    fn assert_freezer_futures_are_send(freezer: &mut TestFreezer, key: U64) {
        is_send(freezer.get(Identifier::Key(&key)));
        is_send(freezer.put(key, 0u64));
    }

    #[allow(dead_code)]
    fn assert_freezer_destroy_is_send(freezer: TestFreezer) {
        is_send(freezer.destroy());
    }

    #[test_traced]
    fn issue_2966_regression() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Use 4 entries but only insert to 2, leaving 2 empty
            let cfg = test_cfg(&context, 4, 1, 4);
            let mut freezer =
                Freezer::<_, FixedBytes<64>, i32>::init(context.child("first"), cfg.clone())
                    .await
                    .unwrap();

            // Insert only 2 keys to different entries. With table_size=4, entries 2 and 3
            // should remain empty.
            freezer.put(test_key("key0"), 0).await.unwrap();
            freezer.put(test_key("key2"), 1).await.unwrap();
            freezer.close().await.unwrap();

            let (blob, size) = context.open(&cfg.table_partition, b"table").await.unwrap();
            let mut table_data = blob.read_at(0, size as usize).await.unwrap().coalesce();

            // Verify resize happened (table doubled from 4 to 8)
            let num_entries = size as usize / Entry::SLOT_SIZE;
            assert_eq!(num_entries, 8);

            // Count empty slots. The bug would cause a resize to rewrite empty slots as
            // occupied entries.
            let mut empty_count = 0;
            for _ in 0..num_entries {
                if Entry::read_slot(&mut table_data).unwrap().is_none() {
                    empty_count += 1;
                }
            }
            // 2 keys in 4 entries = 2 empty. After resize to 8, those become 4 empty.
            assert_eq!(empty_count, 4);
        });
    }

    /// A sync that leaves a resize mid-flight commits a table length between two powers
    /// of two. Reopening must drop the partially copied upper half and keep committed
    /// keys reachable.
    #[test_traced]
    fn reopen_truncates_interrupted_resize() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, 2, 1, 1);
            let key = test_key_at_index(4, 3);

            {
                let mut freezer =
                    Freezer::<_, FixedBytes<64>, i32>::init(context.child("first"), cfg.clone())
                        .await
                        .unwrap();
                freezer.put(key.clone(), 42).await.unwrap();
                freezer.sync().await.unwrap();

                assert_eq!(freezer.resizing(), Some(1));
                assert_eq!(freezer.get(Identifier::Key(&key)).await.unwrap(), Some(42));
            }

            let freezer =
                Freezer::<_, FixedBytes<64>, i32>::init(context.child("second"), cfg.clone())
                    .await
                    .unwrap();
            assert_eq!(freezer.table_size, 2);
            assert_eq!(freezer.resizing(), None);
            assert_eq!(freezer.get(Identifier::Key(&key)).await.unwrap(), Some(42));
        });
    }

    #[test_traced]
    fn reopen_recovers_completed_resize() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, 2, 1, 2);
            let key = test_key_at_index(4, 3);

            {
                let mut freezer =
                    Freezer::<_, FixedBytes<64>, i32>::init(context.child("first"), cfg.clone())
                        .await
                        .unwrap();
                freezer.put(key.clone(), 42).await.unwrap();
                freezer.sync().await.unwrap();

                assert_eq!(freezer.table_size, 4);
                assert_eq!(freezer.resizing(), None);
                assert_eq!(freezer.get(Identifier::Key(&key)).await.unwrap(), Some(42));
            }

            let freezer =
                Freezer::<_, FixedBytes<64>, i32>::init(context.child("second"), cfg.clone())
                    .await
                    .unwrap();
            assert_eq!(freezer.table_size, 4);
            assert_eq!(freezer.get(Identifier::Key(&key)).await.unwrap(), Some(42));
        });
    }

    /// A table slot referencing a record the key record blob does not hold cannot be
    /// produced by a crash (the blobs and the table commit atomically), so
    /// initialization must fail loudly instead of repairing it.
    #[test_traced]
    fn dangling_slot_is_loud() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, 4, 64, 4);

            {
                let mut freezer =
                    Freezer::<_, FixedBytes<64>, i32>::init(context.child("first"), cfg.clone())
                        .await
                        .unwrap();
                freezer.put(test_key("key1"), 42).await.unwrap();
                freezer.close().await.unwrap();
            }

            // Point the first slot at a record position the key record blob does not hold
            {
                let (blob, _) = context.open(&cfg.table_partition, b"table").await.unwrap();
                let mut slot = Vec::with_capacity(Entry::SLOT_SIZE);
                Entry::write_slot(
                    &mut slot,
                    Some(&Entry {
                        position: u64::MAX / Record::<FixedBytes<64>>::SIZE as u64,
                        added: 0,
                    }),
                );
                blob.write_at_sync(0, slot).await.unwrap();
            }

            let result =
                Freezer::<_, FixedBytes<64>, i32>::init(context.child("second"), cfg.clone()).await;
            assert!(matches!(result, Err(Error::MissingRecord(_))));
        });
    }

    /// A table blob too short to hold a single slot cannot be produced by a crash, so
    /// initialization must fail loudly.
    #[test_traced]
    fn sub_slot_table_is_loud() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, 2, 1, 1);

            {
                let (blob, _) = context.open(&cfg.table_partition, b"table").await.unwrap();
                blob.write_at_sync(0, vec![0u8; 3]).await.unwrap();
            }

            let result =
                Freezer::<_, FixedBytes<64>, i32>::init(context.child("storage"), cfg.clone())
                    .await;
            assert!(matches!(result, Err(Error::InvalidTableLength(3))));
        });
    }

    /// Records committed by different syncs share a chain: traversal crosses commit
    /// boundaries through monotone positions.
    #[test_traced]
    fn chain_across_commits() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, 4, 64, 4);
            let keys = test_keys_at_index(4, 0, 3);

            {
                let mut freezer =
                    Freezer::<_, FixedBytes<64>, i32>::init(context.child("first"), cfg.clone())
                        .await
                        .unwrap();
                for (i, key) in keys.iter().enumerate() {
                    freezer.put(key.clone(), i as i32).await.unwrap();
                    freezer.sync().await.unwrap();
                }
                freezer.close().await.unwrap();
            }

            let freezer =
                Freezer::<_, FixedBytes<64>, i32>::init(context.child("second"), cfg.clone())
                    .await
                    .unwrap();
            for (i, key) in keys.iter().enumerate() {
                assert_eq!(
                    freezer.get(Identifier::Key(key)).await.unwrap(),
                    Some(i as i32)
                );
            }
        });
    }

    /// A crash erases uncommitted puts atomically: the table slot, the key records, and
    /// the values all revert to the last commit (never one without the others), and the
    /// erased keys can be re-put.
    #[test_traced]
    fn crash_recovers_committed_chain() {
        let executor = deterministic::Runner::default();
        let (_, checkpoint) = executor.start_and_recover(|context| async move {
            let cfg = test_cfg(&context, 4, 64, 4);
            let keys = test_keys_at_index(4, 0, 3);
            let mut freezer =
                Freezer::<_, FixedBytes<64>, i32>::init(context.child("first"), cfg.clone())
                    .await
                    .unwrap();

            // Commit the chain head for keys[0]
            freezer.put(keys[0].clone(), 0).await.unwrap();
            freezer.sync().await.unwrap();

            // Extend the same chain without committing
            freezer.put(keys[1].clone(), 1).await.unwrap();
            freezer.put(keys[2].clone(), 2).await.unwrap();
        });

        deterministic::Runner::from(checkpoint).start(|context| async move {
            let cfg = test_cfg(&context, 4, 64, 4);
            let keys = test_keys_at_index(4, 0, 3);
            let mut freezer =
                Freezer::<_, FixedBytes<64>, i32>::init(context.child("second"), cfg.clone())
                    .await
                    .unwrap();

            // The committed head is intact, the uncommitted chain extensions vanished
            assert_eq!(
                freezer.get(Identifier::Key(&keys[0])).await.unwrap(),
                Some(0)
            );
            assert_eq!(freezer.get(Identifier::Key(&keys[1])).await.unwrap(), None);
            assert_eq!(freezer.get(Identifier::Key(&keys[2])).await.unwrap(), None);

            // The erased keys can be re-put and the whole chain traverses
            freezer.put(keys[1].clone(), 11).await.unwrap();
            freezer.put(keys[2].clone(), 22).await.unwrap();
            freezer.sync().await.unwrap();
            assert_eq!(
                freezer.get(Identifier::Key(&keys[0])).await.unwrap(),
                Some(0)
            );
            assert_eq!(
                freezer.get(Identifier::Key(&keys[1])).await.unwrap(),
                Some(11)
            );
            assert_eq!(
                freezer.get(Identifier::Key(&keys[2])).await.unwrap(),
                Some(22)
            );
        });
    }

    /// Chain traversal across many records in one slot, before and after reopen.
    #[test_traced]
    fn chain_traversal_many_records() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // A resize frequency of u8::MAX keeps the table at its initial size, so every
            // key lands in one chain.
            let cfg = test_cfg(&context, 4, u8::MAX, 4);
            let keys = test_keys_at_index(4, 2, 64);

            let mut cursors = Vec::new();
            {
                let mut freezer =
                    Freezer::<_, FixedBytes<64>, i32>::init(context.child("first"), cfg.clone())
                        .await
                        .unwrap();
                for (i, key) in keys.iter().enumerate() {
                    cursors.push(freezer.put(key.clone(), i as i32).await.unwrap());
                }

                // Every key is reachable before the chain is committed
                for (i, key) in keys.iter().enumerate() {
                    assert_eq!(
                        freezer.get(Identifier::Key(key)).await.unwrap(),
                        Some(i as i32)
                    );
                }
                freezer.close().await.unwrap();
            }

            let freezer =
                Freezer::<_, FixedBytes<64>, i32>::init(context.child("second"), cfg.clone())
                    .await
                    .unwrap();
            for (i, key) in keys.iter().enumerate() {
                assert_eq!(
                    freezer.get(Identifier::Key(key)).await.unwrap(),
                    Some(i as i32)
                );
                assert!(freezer.has(key).await.unwrap());
                assert_eq!(
                    freezer.get(Identifier::Cursor(cursors[i])).await.unwrap(),
                    Some(i as i32)
                );
            }
        });
    }

    /// A value blob truncated behind the last committed record is corruption: both blobs
    /// commit in the same batch, so no crash can produce it.
    #[test_traced]
    fn value_blob_truncated_is_corruption() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, 4, 64, 4);

            {
                let mut freezer =
                    Freezer::<_, FixedBytes<64>, i32>::init(context.child("first"), cfg.clone())
                        .await
                        .unwrap();
                freezer.put(test_key("key1"), 1).await.unwrap();
                freezer.put(test_key("key2"), 2).await.unwrap();
                freezer.close().await.unwrap();
            }

            {
                let (blob, size) = context.open(&cfg.value_partition, b"values").await.unwrap();
                blob.resize(size - 2).await.unwrap();
                blob.sync().await.unwrap();
            }

            let result =
                Freezer::<_, FixedBytes<64>, i32>::init(context.child("second"), cfg.clone()).await;
            assert!(matches!(result, Err(Error::Corruption(_))));
        });
    }

    /// Value bytes past the last committed record's value range are corruption: unsynced
    /// value writes are never made readable by another blob's commit.
    #[test_traced]
    fn value_blob_trailing_bytes_is_corruption() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, 4, 64, 4);

            {
                let mut freezer =
                    Freezer::<_, FixedBytes<64>, i32>::init(context.child("first"), cfg.clone())
                        .await
                        .unwrap();
                freezer.put(test_key("key1"), 1).await.unwrap();
                freezer.close().await.unwrap();
            }

            {
                let (blob, size) = context.open(&cfg.value_partition, b"values").await.unwrap();
                blob.write_at_sync(size, vec![0xDE; 100]).await.unwrap();
            }

            let result =
                Freezer::<_, FixedBytes<64>, i32>::init(context.child("second"), cfg.clone()).await;
            assert!(matches!(result, Err(Error::Corruption(_))));
        });
    }

    /// A partial key record is corruption: the backend's per-blob atomic sync means no
    /// crash can produce one.
    #[test_traced]
    fn partial_key_record_is_corruption() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, 4, 64, 4);

            {
                let mut freezer =
                    Freezer::<_, FixedBytes<64>, i32>::init(context.child("first"), cfg.clone())
                        .await
                        .unwrap();
                freezer.put(test_key("key1"), 1).await.unwrap();
                freezer.close().await.unwrap();
            }

            {
                let (blob, size) = context.open(&cfg.key_partition, b"keys").await.unwrap();
                blob.resize(size - 3).await.unwrap();
                blob.sync().await.unwrap();
            }

            let result =
                Freezer::<_, FixedBytes<64>, i32>::init(context.child("second"), cfg.clone()).await;
            assert!(matches!(result, Err(Error::Corruption(_))));
        });
    }

    /// A key record blob truncated behind the value blob is corruption: both blobs
    /// commit in the same batch, so no crash can produce it.
    #[test_traced]
    fn key_blob_truncated_is_corruption() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, 4, 64, 4);

            {
                let mut freezer =
                    Freezer::<_, FixedBytes<64>, i32>::init(context.child("first"), cfg.clone())
                        .await
                        .unwrap();
                freezer.put(test_key("key1"), 1).await.unwrap();
                freezer.put(test_key("key2"), 2).await.unwrap();
                freezer.close().await.unwrap();
            }

            // Drop the last record but keep its value bytes: the remaining last record's
            // value range no longer ends at the value blob's size.
            {
                let (blob, size) = context.open(&cfg.key_partition, b"keys").await.unwrap();
                blob.resize(size - Record::<FixedBytes<64>>::SIZE as u64)
                    .await
                    .unwrap();
                blob.sync().await.unwrap();
            }

            let result =
                Freezer::<_, FixedBytes<64>, i32>::init(context.child("second"), cfg.clone()).await;
            assert!(matches!(result, Err(Error::Corruption(_))));
        });
    }
}
