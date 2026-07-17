use super::{Config, Error, Identifier};
use crate::{
    journal::segmented::oversized::{
        Config as OversizedConfig, Oversized, Record as OversizedRecord,
    },
    Context,
};
use commonware_codec::{CodecShared, FixedArray, FixedSize, Read, ReadExt, Write as CodecWrite};
use commonware_cryptography::Crc32;
use commonware_runtime::{
    buffer,
    telemetry::metrics::{Counter, MetricsExt as _},
    Blob, Buf, BufMut, BufferPooler,
};
use commonware_utils::{Array, Span};
use futures::future::try_join;
use std::{collections::BTreeSet, num::NonZeroUsize, ops::Deref};
use tracing::debug;

/// The percentage of table entries that must reach `table_resize_frequency`
/// before a resize is triggered.
const RESIZE_THRESHOLD: u64 = 50;

/// Location of an item in the [Freezer].
///
/// This can be used to directly access the data for a given
/// key-value pair (rather than walking the journal chain).
#[derive(Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, FixedArray)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[repr(transparent)]
pub struct Cursor([u8; u64::SIZE + u64::SIZE + u32::SIZE]);

impl Cursor {
    /// Create a new [Cursor].
    fn new(section: u64, offset: u64, size: u32) -> Self {
        let mut buf = [0u8; u64::SIZE + u64::SIZE + u32::SIZE];
        buf[..u64::SIZE].copy_from_slice(&section.to_be_bytes());
        buf[u64::SIZE..u64::SIZE + u64::SIZE].copy_from_slice(&offset.to_be_bytes());
        buf[u64::SIZE + u64::SIZE..].copy_from_slice(&size.to_be_bytes());
        Self(buf)
    }

    /// Get the section of the cursor.
    fn section(&self) -> u64 {
        u64::from_be_bytes(self.0[..u64::SIZE].try_into().unwrap())
    }

    /// Get the offset of the cursor.
    fn offset(&self) -> u64 {
        u64::from_be_bytes(self.0[u64::SIZE..u64::SIZE + u64::SIZE].try_into().unwrap())
    }

    /// Get the size of the value.
    fn size(&self) -> u32 {
        u32::from_be_bytes(self.0[u64::SIZE + u64::SIZE..].try_into().unwrap())
    }
}

impl Read for Cursor {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        <[u8; u64::SIZE + u64::SIZE + u32::SIZE]>::read(buf).map(Self)
    }
}

impl CodecWrite for Cursor {
    fn write(&self, buf: &mut impl BufMut) {
        self.0.write(buf);
    }
}

impl FixedSize for Cursor {
    const SIZE: usize = u64::SIZE + u64::SIZE + u32::SIZE;
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
        write!(
            f,
            "Cursor(section={}, offset={}, size={})",
            self.section(),
            self.offset(),
            self.size()
        )
    }
}

impl std::fmt::Display for Cursor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Cursor(section={}, offset={}, size={})",
            self.section(),
            self.offset(),
            self.size()
        )
    }
}

/// Name of the table blob.
const TABLE_BLOB_NAME: &[u8] = b"table";

/// Chain head stored in a table slot.
#[derive(Debug, Clone, PartialEq)]
struct Entry {
    // Section in which the head was written
    section: u64,
    // Position in the key index for this section
    position: u64,
    // Number of items added to this entry since last resize
    added: u8,
}

impl Entry {
    /// The size of a table slot: an occupancy tag followed by an [Entry].
    ///
    /// The tag distinguishes an empty slot (all zeros, the initial state of every
    /// table range) from a chain head at section 0, position 0.
    const SLOT_SIZE: usize = u8::SIZE + u64::SIZE + u64::SIZE + u8::SIZE;

    /// Parse a table slot, consuming [Self::SLOT_SIZE] bytes from `buf`.
    fn read_slot(buf: &mut impl Buf) -> Result<Option<Self>, Error> {
        let tag = u8::read(buf).map_err(Error::Codec)?;
        match tag {
            0 => {
                buf.advance(Self::SLOT_SIZE - u8::SIZE);
                Ok(None)
            }
            1 => {
                let section = u64::read(buf).map_err(Error::Codec)?;
                let position = u64::read(buf).map_err(Error::Codec)?;
                let added = u8::read(buf).map_err(Error::Codec)?;
                Ok(Some(Self {
                    section,
                    position,
                    added,
                }))
            }
            tag => Err(Error::Codec(commonware_codec::Error::InvalidEnum(tag))),
        }
    }

    /// Write a table slot, producing [Self::SLOT_SIZE] bytes into `buf`.
    fn write_slot(buf: &mut impl BufMut, entry: Option<&Self>) {
        match entry {
            Some(entry) => {
                1u8.write(buf);
                entry.section.write(buf);
                entry.position.write(buf);
                entry.added.write(buf);
            }
            None => buf.put_bytes(0, Self::SLOT_SIZE),
        }
    }
}

/// Sentinel value indicating no next entry in the collision chain.
const NO_NEXT_SECTION: u64 = u64::MAX;
const NO_NEXT_POSITION: u64 = u64::MAX;

/// Key entry stored in the segmented/fixed key index journal.
///
/// All fields are fixed size, enabling efficient collision chain traversal
/// without reading large values.
///
/// The `next` pointer uses sentinel values (u64::MAX, u64::MAX) to indicate
/// "no next entry" instead of Option, ensuring fixed-size encoding.
#[derive(Debug, Clone, PartialEq)]
struct Record<K: Array> {
    /// The key for this entry.
    key: K,
    /// Pointer to next entry in collision chain (section, position in key index).
    /// Uses (u64::MAX, u64::MAX) as sentinel for "no next".
    next_section: u64,
    next_position: u64,
    /// Byte offset in value journal (same section).
    value_offset: u64,
    /// Size of value data in the value journal.
    value_size: u32,
}

impl<K: Array> Record<K> {
    /// Create a new [Record].
    fn new(key: K, next: Option<(u64, u64)>, value_offset: u64, value_size: u32) -> Self {
        let (next_section, next_position) = next.unwrap_or((NO_NEXT_SECTION, NO_NEXT_POSITION));
        Self {
            key,
            next_section,
            next_position,
            value_offset,
            value_size,
        }
    }

    /// Get the next entry in the collision chain, if any.
    const fn next(&self) -> Option<(u64, u64)> {
        if self.next_section == NO_NEXT_SECTION && self.next_position == NO_NEXT_POSITION {
            None
        } else {
            Some((self.next_section, self.next_position))
        }
    }
}

impl<K: Array> CodecWrite for Record<K> {
    fn write(&self, buf: &mut impl BufMut) {
        self.key.write(buf);
        self.next_section.write(buf);
        self.next_position.write(buf);
        self.value_offset.write(buf);
        self.value_size.write(buf);
    }
}

impl<K: Array> Read for Record<K> {
    type Cfg = ();
    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        let key = K::read(buf)?;
        let next_section = u64::read(buf)?;
        let next_position = u64::read(buf)?;
        let value_offset = u64::read(buf)?;
        let value_size = u32::read(buf)?;

        Ok(Self {
            key,
            next_section,
            next_position,
            value_offset,
            value_size,
        })
    }
}

impl<K: Array> FixedSize for Record<K> {
    // key + next_section + next_position + value_offset + value_size
    const SIZE: usize = K::SIZE + u64::SIZE + u64::SIZE + u64::SIZE + u32::SIZE;
}

impl<K: Array> OversizedRecord for Record<K> {
    fn value_location(&self) -> (u64, u32) {
        (self.value_offset, self.value_size)
    }

    fn with_location(mut self, offset: u64, size: u32) -> Self {
        self.value_offset = offset;
        self.value_size = size;
        self
    }
}

#[cfg(feature = "arbitrary")]
impl<K: Array> arbitrary::Arbitrary<'_> for Record<K>
where
    K: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            key: K::arbitrary(u)?,
            next_section: u64::arbitrary(u)?,
            next_position: u64::arbitrary(u)?,
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

    // Table blob that maps slots to key index chain heads
    table: E::Blob,

    // Combined key index + value storage with crash recovery
    oversized: Oversized<E, Record<K>, V>,

    // Target size for value blob sections
    blob_target_size: u64,

    // Current section for new writes
    current_section: u64,

    // Sections with pending table updates to be synced
    modified_sections: BTreeSet<u64>,
    resizable: u32,
    resize_progress: Option<u32>,

    // Metrics
    puts: Counter,
    gets: Counter,
    has: Counter,
    unnecessary_reads: Counter,
    unnecessary_writes: Counter,
    resizes: Counter,
}

impl<E: BufferPooler + Context, K: Array, V: CodecShared> Freezer<E, K, V> {
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
    /// Committed slots always reference committed journal records: [Freezer::sync_into]
    /// commits the journals and the table atomically, and [Freezer::sync] commits the
    /// journals before the table. A slot that does not decode, or that references a
    /// record the journals do not hold, is therefore corruption or tampering, never a
    /// state a crash can produce.
    ///
    /// Returns the number of entries that can be resized.
    async fn scan_table(
        pooler: &impl BufferPooler,
        blob: &E::Blob,
        oversized: &Oversized<E, Record<K>, V>,
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

            // Verify the chain head references a record the journals hold
            let positions = oversized.size(entry.section)? / Record::<K>::SIZE as u64;
            if entry.position >= positions {
                return Err(Error::MissingRecord(entry.section, entry.position));
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

        // Initialize oversized journal (verifies cross-journal consistency)
        let oversized_cfg = OversizedConfig {
            index_partition: config.key_partition.clone(),
            value_partition: config.value_partition.clone(),
            index_page_cache: config.key_page_cache.clone(),
            index_write_buffer: config.key_write_buffer,
            value_write_buffer: config.value_write_buffer,
            compression: config.value_compression,
            codec_config: config.codec_config,
        };
        let oversized: Oversized<E, Record<K>, V> =
            Oversized::init(context.child("oversized"), oversized_cfg).await?;

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
                &oversized,
                table_size,
                config.table_resize_frequency,
                config.table_replay_buffer,
            )
            .await?;
            (table_size, resizable)
        };

        // Resume appends in the newest committed section
        let current_section = oversized.newest_section().unwrap_or(0);

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
            oversized,
            blob_target_size: config.value_target_size,
            current_section,
            modified_sections: BTreeSet::new(),
            resizable,
            resize_progress: None,
            puts,
            gets,
            has,
            unnecessary_reads,
            unnecessary_writes,
            resizes,
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

    /// Determine which blob section to write to based on current blob size.
    async fn update_section(&mut self) -> Result<(), Error> {
        // Get the current value blob section size
        let value_size = self.oversized.value_size(self.current_section).await?;

        // If the current section has reached the target size, create a new section
        if value_size >= self.blob_target_size {
            self.current_section += 1;
            debug!(
                size = value_size,
                section = self.current_section,
                "updated section"
            );
        }

        Ok(())
    }

    /// Put a key-value pair into the [Freezer].
    /// If the key already exists, the value is updated.
    pub async fn put(&mut self, key: K, value: V) -> Result<Cursor, Error> {
        self.puts.inc();

        // Update the section if needed
        self.update_section().await?;

        // Get head of the chain from table
        let table_index = self.table_index(&key);
        let head = Self::read_table(&self.table, table_index).await?;

        // Create key entry with pointer to previous head (value location set by oversized.append)
        let key_entry = Record::new(
            key,
            head.as_ref().map(|entry| (entry.section, entry.position)),
            0,
            0,
        );

        // Write value and key entry (glob first, then index)
        let (position, value_offset, value_size) = self
            .oversized
            .append(self.current_section, key_entry, &value)
            .await?;

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
        self.modified_sections.insert(self.current_section);
        let new_entry = Entry {
            section: self.current_section,
            position,
            added,
        };
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

        Ok(Cursor::new(self.current_section, value_offset, value_size))
    }

    /// Get the value for a given [Cursor].
    async fn get_cursor(&self, cursor: Cursor) -> Result<V, Error> {
        let value = self
            .oversized
            .get_value(cursor.section(), cursor.offset(), cursor.size())
            .await?;

        Ok(value)
    }

    /// Find the first key entry matching `key`, returning it with its section.
    ///
    /// Reads key entries only, never values.
    async fn find_key(&self, key: &K) -> Result<Option<(u64, Record<K>)>, Error> {
        // Get head of the chain from table
        let table_index = self.table_index(key);
        let Some(head) = Self::read_table(&self.table, table_index).await? else {
            return Ok(None);
        };
        let (mut section, mut position) = (head.section, head.position);

        // Follow the linked list chain to find the first matching key
        loop {
            // Get the key entry from the fixed key index (efficient, good cache locality)
            let key_entry = self.oversized.get(section, position).await?;

            // Check if this key matches
            if key_entry.key.as_ref() == key.as_ref() {
                return Ok(Some((section, key_entry)));
            }

            // Increment unnecessary reads
            self.unnecessary_reads.inc();

            // Follow the chain
            let Some(next) = key_entry.next() else {
                break; // End of chain
            };
            section = next.0;
            position = next.1;
        }

        Ok(None)
    }

    /// Get the first value for a given key.
    async fn get_key(&self, key: &K) -> Result<Option<V>, Error> {
        self.gets.inc();

        let Some((section, key_entry)) = self.find_key(key).await? else {
            return Ok(None);
        };
        let value = self
            .oversized
            .get_value(section, key_entry.value_offset, key_entry.value_size)
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
    /// Walks the same key index chain as [`Self::get`] with [`Identifier::Key`]
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
        // Sync all modified sections for oversized journal. The journals must commit
        // before the table: a crash between the two commits then leaves the table
        // referencing only records the journals hold (any newer journal records stay
        // unreferenced, bounded waste rather than a dangling slot).
        self.oversized.sync(&self.modified_sections).await?;
        self.modified_sections.clear();

        // Start a resize (if needed)
        if self.should_resize() && self.resize_progress.is_none() {
            self.start_resize();
        }

        // Continue a resize (if ongoing)
        if self.resize_progress.is_some() {
            self.advance_resize().await?;
        }

        // Sync updated table entries
        self.table.sync().await?;

        Ok(())
    }

    /// [Self::sync], staged with `batch` instead of synced directly: the
    /// oversized journals and the table become durable when the batch is
    /// applied.
    pub async fn sync_into<T: commonware_runtime::WriteBatch<Blob = E::Blob>>(
        &mut self,
        batch: &mut T,
    ) -> Result<(), Error> {
        self.oversized
            .sync_into(&self.modified_sections, batch)
            .await?;
        self.modified_sections.clear();

        if self.should_resize() && self.resize_progress.is_none() {
            self.start_resize();
        }
        if self.resize_progress.is_some() {
            self.advance_resize().await?;
        }

        // Table entries are written directly to the blob; stage its
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
        self.destroy_into(&mut batch).await?;
        commonware_runtime::WriteBatch::apply_sync(batch)
            .await
            .map_err(Error::Runtime)
    }

    /// [Self::destroy], staged with `batch`: every partition removal (both the oversized
    /// journal's and the table's) lands when the caller applies the batch with `apply_sync`,
    /// atomically with everything else it stages.
    ///
    /// The table partition always exists: the table blob is created at initialization.
    pub(crate) async fn destroy_into<T: commonware_runtime::WriteBatch<Blob = E::Blob>>(
        self,
        batch: &mut T,
    ) -> Result<(), Error> {
        // Stage the oversized journal's destruction
        self.oversized.destroy_into(batch).await?;

        // Stage the table's destruction
        drop(self.table);
        batch.remove(&self.table_partition, None);

        Ok(())
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

    fn test_key_at_index(table_size: u32, table_index: u32) -> FixedBytes<64> {
        assert!(table_size.is_power_of_two());
        assert!(table_index < table_size);

        for value in 0u64.. {
            let mut buf = [0u8; 64];
            let bytes = value.to_be_bytes();
            buf[..bytes.len()].copy_from_slice(&bytes);
            let key = FixedBytes::new(buf);
            if Crc32::checksum(key.as_ref()) & (table_size - 1) == table_index {
                return key;
            }
        }

        unreachable!("u64 key space exhausted");
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
            let cfg = super::super::Config {
                key_partition: "test-key-index".into(),
                key_write_buffer: NZUsize!(1024),
                key_page_cache: CacheRef::from_pooler(&context, NZU16!(1024), NZUsize!(10)),
                value_partition: "test-value-journal".into(),
                value_compression: None,
                value_write_buffer: NZUsize!(1024),
                value_target_size: 10 * 1024 * 1024,
                table_partition: "test-table".into(),
                // Use 4 entries but only insert to 2, leaving 2 empty
                table_initial_size: 4,
                table_resize_frequency: 1,
                table_resize_chunk_size: 4,
                table_replay_buffer: NZUsize!(64 * 1024),
                codec_config: (),
            };
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
            let cfg = super::super::Config {
                key_partition: "test-key-index".into(),
                key_write_buffer: NZUsize!(1024),
                key_page_cache: CacheRef::from_pooler(&context, NZU16!(1024), NZUsize!(10)),
                value_partition: "test-value-journal".into(),
                value_compression: None,
                value_write_buffer: NZUsize!(1024),
                value_target_size: 10 * 1024 * 1024,
                table_partition: "test-table".into(),
                table_initial_size: 2,
                table_resize_frequency: 1,
                table_resize_chunk_size: 1,
                table_replay_buffer: NZUsize!(64 * 1024),
                codec_config: (),
            };
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
            let cfg = super::super::Config {
                key_partition: "test-key-index".into(),
                key_write_buffer: NZUsize!(1024),
                key_page_cache: CacheRef::from_pooler(&context, NZU16!(1024), NZUsize!(10)),
                value_partition: "test-value-journal".into(),
                value_compression: None,
                value_write_buffer: NZUsize!(1024),
                value_target_size: 10 * 1024 * 1024,
                table_partition: "test-table".into(),
                table_initial_size: 2,
                table_resize_frequency: 1,
                table_resize_chunk_size: 2,
                table_replay_buffer: NZUsize!(64 * 1024),
                codec_config: (),
            };
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

    /// A table slot referencing a record the journals do not hold cannot be produced by
    /// a crash (the journals commit before or atomically with the table), so
    /// initialization must fail loudly instead of repairing it.
    #[test_traced]
    fn dangling_slot_is_loud() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = super::super::Config {
                key_partition: "test-key-index".into(),
                key_write_buffer: NZUsize!(1024),
                key_page_cache: CacheRef::from_pooler(&context, NZU16!(1024), NZUsize!(10)),
                value_partition: "test-value-journal".into(),
                value_compression: None,
                value_write_buffer: NZUsize!(1024),
                value_target_size: 10 * 1024 * 1024,
                table_partition: "test-table".into(),
                table_initial_size: 4,
                table_resize_frequency: 64,
                table_resize_chunk_size: 4,
                table_replay_buffer: NZUsize!(64 * 1024),
                codec_config: (),
            };

            {
                let mut freezer =
                    Freezer::<_, FixedBytes<64>, i32>::init(context.child("first"), cfg.clone())
                        .await
                        .unwrap();
                freezer.put(test_key("key1"), 42).await.unwrap();
                freezer.close().await.unwrap();
            }

            // Point the first slot at a record position the journals do not hold
            {
                let (blob, _) = context.open(&cfg.table_partition, b"table").await.unwrap();
                let mut slot = Vec::with_capacity(Entry::SLOT_SIZE);
                Entry::write_slot(
                    &mut slot,
                    Some(&Entry {
                        section: 0,
                        position: u64::MAX / Record::<FixedBytes<64>>::SIZE as u64,
                        added: 0,
                    }),
                );
                blob.write_at_sync(0, slot).await.unwrap();
            }

            let result =
                Freezer::<_, FixedBytes<64>, i32>::init(context.child("second"), cfg.clone()).await;
            assert!(matches!(result, Err(Error::MissingRecord(0, _))));
        });
    }

    /// A table blob too short to hold a single slot cannot be produced by a crash, so
    /// initialization must fail loudly.
    #[test_traced]
    fn sub_slot_table_is_loud() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = super::super::Config {
                key_partition: "test-key-index".into(),
                key_write_buffer: NZUsize!(1024),
                key_page_cache: CacheRef::from_pooler(&context, NZU16!(1024), NZUsize!(10)),
                value_partition: "test-value-journal".into(),
                value_compression: None,
                value_write_buffer: NZUsize!(1024),
                value_target_size: 10 * 1024 * 1024,
                table_partition: "test-table".into(),
                table_initial_size: 2,
                table_resize_frequency: 1,
                table_resize_chunk_size: 1,
                table_replay_buffer: NZUsize!(64 * 1024),
                codec_config: (),
            };

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
}
