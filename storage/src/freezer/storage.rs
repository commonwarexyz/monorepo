use super::{Config, Error, Identifier};
use crate::journal::variable::{Config as JournalConfig, Journal};
use bytes::{Buf, BufMut};
use commonware_codec::{Codec, Encode, EncodeSize, FixedSize, Read, ReadExt, Write as CodecWrite};
use commonware_runtime::{buffer, Blob, Clock, Metrics, Storage};
use commonware_utils::{Array, Span};
use futures::future::{try_join, try_join_all};
use prometheus_client::metrics::counter::Counter;
use std::{
    cmp::Ordering, collections::BTreeSet, marker::PhantomData, num::NonZeroUsize, ops::Deref,
};
use tracing::debug;

/// The percentage of table entries that must reach `table_resize_frequency`
/// before a resize is triggered.
const RESIZE_THRESHOLD: u64 = 50;

/// Location of an item in the [Freezer].
///
/// This can be used to directly access the data for a given
/// key-value pair (rather than walking the journal chain).
#[derive(Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
#[repr(transparent)]
pub struct Cursor([u8; u64::SIZE + u32::SIZE]);

impl Cursor {
    /// Create a new [Cursor].
    fn new(section: u64, offset: u32) -> Self {
        let mut buf = [0u8; u64::SIZE + u32::SIZE];
        buf[..u64::SIZE].copy_from_slice(&section.to_be_bytes());
        buf[u64::SIZE..].copy_from_slice(&offset.to_be_bytes());
        Self(buf)
    }

    /// Get the section of the cursor.
    fn section(&self) -> u64 {
        u64::from_be_bytes(self.0[..u64::SIZE].try_into().unwrap())
    }

    /// Get the offset of the cursor.
    fn offset(&self) -> u32 {
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
        write!(
            f,
            "Cursor(section={}, offset={})",
            self.section(),
            self.offset()
        )
    }
}

impl std::fmt::Display for Cursor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Cursor(section={}, offset={})",
            self.section(),
            self.offset()
        )
    }
}

/// Marker of [Freezer] progress.
///
/// This can be used to restore the [Freezer] to a consistent
/// state after shutdown.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Copy)]
pub struct Checkpoint {
    /// The epoch of the last committed operation.
    epoch: u64,
    /// The section of the last committed operation.
    section: u64,
    /// The size of the journal in the last committed section.
    size: u64,
    /// The size of the table.
    table_size: u32,
}

impl Checkpoint {
    /// Initialize a new [Checkpoint].
    fn init(table_size: u32) -> Self {
        Self {
            table_size,
            epoch: 0,
            section: 0,
            size: 0,
        }
    }
}

impl Read for Checkpoint {
    type Cfg = ();
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, commonware_codec::Error> {
        let epoch = u64::read(buf)?;
        let section = u64::read(buf)?;
        let size = u64::read(buf)?;
        let table_size = u32::read(buf)?;
        Ok(Self {
            epoch,
            section,
            size,
            table_size,
        })
    }
}

impl CodecWrite for Checkpoint {
    fn write(&self, buf: &mut impl BufMut) {
        self.epoch.write(buf);
        self.section.write(buf);
        self.size.write(buf);
        self.table_size.write(buf);
    }
}

impl FixedSize for Checkpoint {
    const SIZE: usize = u64::SIZE + u64::SIZE + u64::SIZE + u32::SIZE;
}

/// Name of the table blob.
const TABLE_BLOB_NAME: &[u8] = b"table";

/// Single table entry stored in the table blob.
#[derive(Debug, Clone, PartialEq)]
struct Entry {
    // Epoch in which this slot was written
    epoch: u64,
    // Section in which this slot was written
    section: u64,
    // Offset in the section where this slot was written
    offset: u32,
    // Number of items added to this entry since last resize
    added: u8,
    // CRC of (epoch | section | offset | added)
    crc: u32,
}

impl Entry {
    /// The full size of a table entry (2 slots).
    const FULL_SIZE: usize = Self::SIZE * 2;

    /// Compute a checksum for [Entry].
    fn compute_crc(epoch: u64, section: u64, offset: u32, added: u8) -> u32 {
        let mut hasher = crc32fast::Hasher::new();
        hasher.update(&epoch.to_be_bytes());
        hasher.update(&section.to_be_bytes());
        hasher.update(&offset.to_be_bytes());
        hasher.update(&added.to_be_bytes());
        hasher.finalize()
    }

    /// Create a new [Entry].
    fn new(epoch: u64, section: u64, offset: u32, added: u8) -> Self {
        Self {
            epoch,
            section,
            offset,
            added,
            crc: Self::compute_crc(epoch, section, offset, added),
        }
    }

    /// Check if this entry is empty (all zeros).
    fn is_empty(&self) -> bool {
        self.section == 0 && self.offset == 0 && self.crc == 0
    }

    /// Check if this entry is valid.
    fn is_valid(&self) -> bool {
        Self::compute_crc(self.epoch, self.section, self.offset, self.added) == self.crc
    }
}

impl FixedSize for Entry {
    const SIZE: usize = u64::SIZE + u64::SIZE + u32::SIZE + u8::SIZE + u32::SIZE;
}

impl CodecWrite for Entry {
    fn write(&self, buf: &mut impl BufMut) {
        self.epoch.write(buf);
        self.section.write(buf);
        self.offset.write(buf);
        self.added.write(buf);
        self.crc.write(buf);
    }
}

impl Read for Entry {
    type Cfg = ();
    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        let epoch = u64::read(buf)?;
        let section = u64::read(buf)?;
        let offset = u32::read(buf)?;
        let added = u8::read(buf)?;
        let crc = u32::read(buf)?;

        Ok(Self {
            epoch,
            section,
            offset,
            added,
            crc,
        })
    }
}

/// A key-value pair stored in the [Journal].
struct Record<K: Array, V: Codec> {
    key: K,
    value: V,
    next: Option<(u64, u32)>,
}

impl<K: Array, V: Codec> Record<K, V> {
    /// Create a new [Record].
    fn new(key: K, value: V, next: Option<(u64, u32)>) -> Self {
        Self { key, value, next }
    }
}

impl<K: Array, V: Codec> CodecWrite for Record<K, V> {
    fn write(&self, buf: &mut impl BufMut) {
        self.key.write(buf);
        self.value.write(buf);
        self.next.write(buf);
    }
}

impl<K: Array, V: Codec> Read for Record<K, V> {
    type Cfg = V::Cfg;
    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        let key = K::read(buf)?;
        let value = V::read_cfg(buf, cfg)?;
        let next = Option::<(u64, u32)>::read_cfg(buf, &((), ()))?;

        Ok(Self { key, value, next })
    }
}

impl<K: Array, V: Codec> EncodeSize for Record<K, V> {
    fn encode_size(&self) -> usize {
        K::SIZE + self.value.encode_size() + self.next.encode_size()
    }
}

/// Implementation of [Freezer].
pub struct Freezer<E: Storage + Metrics + Clock, K: Array, V: Codec> {
    // Context for storage operations
    context: E,

    // Table configuration
    table_partition: String,
    table_size: u32,
    table_resize_threshold: u64,
    table_resize_frequency: u8,
    table_resize_chunk_size: u32,

    // Table blob that maps slots to journal chain heads
    table: E::Blob,

    // Variable journal for storing entries
    journal: Journal<E, Record<K, V>>,
    journal_target_size: u64,

    // Current section for new writes
    current_section: u64,
    next_epoch: u64,

    // Sections with pending table updates to be synced
    modified_sections: BTreeSet<u64>,
    resizable: u32,
    resize_progress: Option<u32>,

    // Metrics
    puts: Counter,
    gets: Counter,
    unnecessary_reads: Counter,
    unnecessary_writes: Counter,
    resizes: Counter,

    // Phantom data to satisfy the compiler about generic types
    _phantom: PhantomData<(K, V)>,
}

impl<E: Storage + Metrics + Clock, K: Array, V: Codec> Freezer<E, K, V> {
    /// Calculate the byte offset for a table index.
    #[inline]
    fn table_offset(table_index: u32) -> u64 {
        table_index as u64 * Entry::FULL_SIZE as u64
    }

    /// Parse table entries from a buffer.
    fn parse_entries(buf: &[u8]) -> Result<(Entry, Entry), Error> {
        let mut buf1 = &buf[0..Entry::SIZE];
        let entry1 = Entry::read(&mut buf1)?;
        let mut buf2 = &buf[Entry::SIZE..Entry::FULL_SIZE];
        let entry2 = Entry::read(&mut buf2)?;
        Ok((entry1, entry2))
    }

    /// Read entries from the table blob.
    async fn read_table(blob: &E::Blob, table_index: u32) -> Result<(Entry, Entry), Error> {
        let offset = Self::table_offset(table_index);
        let buf = vec![0u8; Entry::FULL_SIZE];
        let read_buf = blob.read_at(buf, offset).await?;

        Self::parse_entries(read_buf.as_ref())
    }

    /// Recover a single table entry and update tracking.
    async fn recover_entry(
        blob: &E::Blob,
        entry: &mut Entry,
        entry_offset: u64,
        max_valid_epoch: Option<u64>,
        max_epoch: &mut u64,
        max_section: &mut u64,
    ) -> Result<bool, Error> {
        if entry.is_empty() {
            return Ok(false);
        }

        if !entry.is_valid()
            || (max_valid_epoch.is_some() && entry.epoch > max_valid_epoch.unwrap())
        {
            debug!(
                valid_epoch = max_valid_epoch,
                entry_epoch = entry.epoch,
                "found invalid table entry"
            );
            *entry = Entry::new(0, 0, 0, 0);
            let zero_buf = vec![0u8; Entry::SIZE];
            blob.write_at(zero_buf, entry_offset).await?;
            Ok(true)
        } else if max_valid_epoch.is_none() && entry.epoch > *max_epoch {
            // Only track max epoch if we're discovering it (not validating against a known epoch)
            *max_epoch = entry.epoch;
            *max_section = entry.section;
            Ok(false)
        } else {
            Ok(false)
        }
    }

    /// Validate and clean invalid table entries for a given epoch.
    ///
    /// Returns (modified, max_epoch, max_section, resizable) where:
    /// - modified: whether any entries were cleaned
    /// - max_epoch: the maximum valid epoch found
    /// - max_section: the section corresponding to `max_epoch`
    /// - resizable: the number of entries that can be resized
    async fn recover_table(
        blob: &E::Blob,
        table_size: u32,
        table_resize_frequency: u8,
        max_valid_epoch: Option<u64>,
        table_replay_buffer: NonZeroUsize,
    ) -> Result<(bool, u64, u64, u32), Error> {
        // Create a buffered reader for efficient scanning
        let blob_size = Self::table_offset(table_size);
        let mut reader = buffer::Read::new(blob.clone(), blob_size, table_replay_buffer);

        // Iterate over all table entries and overwrite invalid ones
        let mut modified = false;
        let mut max_epoch = 0u64;
        let mut max_section = 0u64;
        let mut resizable = 0u32;
        for table_index in 0..table_size {
            let offset = Self::table_offset(table_index);

            // Read both entries from the buffer
            let mut buf = [0u8; Entry::FULL_SIZE];
            reader.read_exact(&mut buf, Entry::FULL_SIZE).await?;
            let (mut entry1, mut entry2) = Self::parse_entries(&buf)?;

            // Check both entries
            let entry1_cleared = Self::recover_entry(
                blob,
                &mut entry1,
                offset,
                max_valid_epoch,
                &mut max_epoch,
                &mut max_section,
            )
            .await?;
            let entry2_cleared = Self::recover_entry(
                blob,
                &mut entry2,
                offset + Entry::SIZE as u64,
                max_valid_epoch,
                &mut max_epoch,
                &mut max_section,
            )
            .await?;
            modified |= entry1_cleared || entry2_cleared;

            // If the latest entry has reached the resize frequency, increment the resizable entries
            if let Some((_, _, added)) = Self::read_latest_entry(&entry1, &entry2) {
                if added >= table_resize_frequency {
                    resizable += 1;
                }
            }
        }

        Ok((modified, max_epoch, max_section, resizable))
    }

    /// Determine the write offset for a table entry based on current entries and epoch.
    fn compute_write_offset(entry1: &Entry, entry2: &Entry, epoch: u64) -> u64 {
        // If either entry matches the current epoch, overwrite it
        if !entry1.is_empty() && entry1.epoch == epoch {
            return 0;
        }
        if !entry2.is_empty() && entry2.epoch == epoch {
            return Entry::SIZE as u64;
        }

        // Otherwise, write to the older slot (or empty slot)
        match (entry1.is_empty(), entry2.is_empty()) {
            (true, _) => 0,                  // First slot is empty
            (_, true) => Entry::SIZE as u64, // Second slot is empty
            (false, false) => {
                if entry1.epoch < entry2.epoch {
                    0
                } else {
                    Entry::SIZE as u64
                }
            }
        }
    }

    /// Read the latest valid entry from two table slots.
    fn read_latest_entry(entry1: &Entry, entry2: &Entry) -> Option<(u64, u32, u8)> {
        match (
            !entry1.is_empty() && entry1.is_valid(),
            !entry2.is_empty() && entry2.is_valid(),
        ) {
            (true, true) => match entry1.epoch.cmp(&entry2.epoch) {
                Ordering::Greater => Some((entry1.section, entry1.offset, entry1.added)),
                Ordering::Less => Some((entry2.section, entry2.offset, entry2.added)),
                Ordering::Equal => {
                    unreachable!("two valid entries with the same epoch")
                }
            },
            (true, false) => Some((entry1.section, entry1.offset, entry1.added)),
            (false, true) => Some((entry2.section, entry2.offset, entry2.added)),
            (false, false) => None,
        }
    }

    /// Write a table entry to the appropriate slot based on epoch.
    async fn update_head(
        table: &E::Blob,
        table_index: u32,
        entry1: &Entry,
        entry2: &Entry,
        update: Entry,
    ) -> Result<(), Error> {
        // Calculate the base offset for this table index
        let table_offset = Self::table_offset(table_index);

        // Determine which slot to write to based on the provided entries
        let start = Self::compute_write_offset(entry1, entry2, update.epoch);

        // Write the new entry
        table
            .write_at(update.encode(), table_offset + start)
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

    /// Initialize a new [Freezer] instance.
    pub async fn init(context: E, config: Config<V::Cfg>) -> Result<Self, Error> {
        Self::init_with_checkpoint(context, config, None).await
    }

    /// Initialize a new [Freezer] instance with a [Checkpoint].
    // TODO(#1227): Hide this complexity from the caller.
    pub async fn init_with_checkpoint(
        context: E,
        config: Config<V::Cfg>,
        checkpoint: Option<Checkpoint>,
    ) -> Result<Self, Error> {
        // Validate that initial_table_size is a power of 2
        assert!(
            config.table_initial_size > 0 && config.table_initial_size.is_power_of_two(),
            "table_initial_size must be a power of 2"
        );

        // Initialize variable journal with a separate partition
        let journal_config = JournalConfig {
            partition: config.journal_partition,
            compression: config.journal_compression,
            codec_config: config.codec_config,
            write_buffer: config.journal_write_buffer,
            buffer_pool: config.journal_buffer_pool,
        };
        let mut journal = Journal::init(context.clone(), journal_config).await?;

        // Open table blob
        let (table, table_len) = context
            .open(&config.table_partition, TABLE_BLOB_NAME)
            .await?;

        // Determine checkpoint based on initialization scenario
        let (checkpoint, resizable) = match (table_len, checkpoint) {
            // New table with no data
            (0, None) => {
                Self::init_table(&table, config.table_initial_size).await?;
                (Checkpoint::init(config.table_initial_size), 0)
            }

            // New table with explicit checkpoint (must be empty)
            (0, Some(checkpoint)) => {
                assert_eq!(checkpoint.epoch, 0);
                assert_eq!(checkpoint.section, 0);
                assert_eq!(checkpoint.size, 0);
                assert_eq!(checkpoint.table_size, 0);

                Self::init_table(&table, config.table_initial_size).await?;
                (Checkpoint::init(config.table_initial_size), 0)
            }

            // Existing table with checkpoint
            (_, Some(checkpoint)) => {
                assert!(
                    checkpoint.table_size > 0 && checkpoint.table_size.is_power_of_two(),
                    "table_size must be a power of 2"
                );

                // Rewind the journal to the committed section and offset
                journal.rewind(checkpoint.section, checkpoint.size).await?;
                journal.sync(checkpoint.section).await?;

                // Resize table if needed
                let expected_table_len = Self::table_offset(checkpoint.table_size);
                let mut modified = if table_len != expected_table_len {
                    table.resize(expected_table_len).await?;
                    true
                } else {
                    false
                };

                // Validate and clean invalid entries
                let (table_modified, _, _, resizable) = Self::recover_table(
                    &table,
                    checkpoint.table_size,
                    config.table_resize_frequency,
                    Some(checkpoint.epoch),
                    config.table_replay_buffer,
                )
                .await?;
                if table_modified {
                    modified = true;
                }

                // Sync table if needed
                if modified {
                    table.sync().await?;
                }

                (checkpoint, resizable)
            }

            // Existing table without checkpoint
            (_, None) => {
                // Find max epoch/section and clean invalid entries in a single pass
                let table_size = (table_len / Entry::FULL_SIZE as u64) as u32;
                let (modified, max_epoch, max_section, resizable) = Self::recover_table(
                    &table,
                    table_size,
                    config.table_resize_frequency,
                    None,
                    config.table_replay_buffer,
                )
                .await?;

                // Sync table if needed
                if modified {
                    table.sync().await?;
                }

                (
                    Checkpoint {
                        epoch: max_epoch,
                        section: max_section,
                        size: journal.size(max_section).await?,
                        table_size,
                    },
                    resizable,
                )
            }
        };

        // Create metrics
        let puts = Counter::default();
        let gets = Counter::default();
        let unnecessary_reads = Counter::default();
        let unnecessary_writes = Counter::default();
        let resizes = Counter::default();
        context.register("puts", "number of put operations", puts.clone());
        context.register("gets", "number of get operations", gets.clone());
        context.register(
            "unnecessary_reads",
            "number of unnecessary reads performed during key lookups",
            unnecessary_reads.clone(),
        );
        context.register(
            "unnecessary_writes",
            "number of unnecessary writes performed during resize",
            unnecessary_writes.clone(),
        );
        context.register(
            "resizes",
            "number of table resizing operations",
            resizes.clone(),
        );

        Ok(Self {
            context,
            table_partition: config.table_partition,
            table_size: checkpoint.table_size,
            table_resize_threshold: checkpoint.table_size as u64 * RESIZE_THRESHOLD / 100,
            table_resize_frequency: config.table_resize_frequency,
            table_resize_chunk_size: config.table_resize_chunk_size,
            table,
            journal,
            journal_target_size: config.journal_target_size,
            current_section: checkpoint.section,
            next_epoch: checkpoint.epoch.checked_add(1).expect("epoch overflow"),
            modified_sections: BTreeSet::new(),
            resizable,
            resize_progress: None,
            puts,
            gets,
            unnecessary_reads,
            unnecessary_writes,
            resizes,
            _phantom: PhantomData,
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
        let hash = crc32fast::hash(key.as_ref());
        hash & (self.table_size - 1)
    }

    /// Determine if the table should be resized.
    fn should_resize(&self) -> bool {
        self.resizable as u64 >= self.table_resize_threshold
    }

    /// Determine which journal section to write to based on current journal size.
    async fn update_section(&mut self) -> Result<(), Error> {
        // Get the current section size
        let size = self.journal.size(self.current_section).await?;

        // If the current section has reached the target size, create a new section
        if size >= self.journal_target_size {
            self.current_section += 1;
            debug!(size, section = self.current_section, "updated section");
        }

        Ok(())
    }

    /// Put a key-value pair into the [Freezer].
    pub async fn put(&mut self, key: K, value: V) -> Result<Cursor, Error> {
        self.puts.inc();

        // Update the section if needed
        self.update_section().await?;

        // Get head of the chain from table
        let table_index = self.table_index(&key);
        let (entry1, entry2) = Self::read_table(&self.table, table_index).await?;
        let head = Self::read_latest_entry(&entry1, &entry2);

        // Create new head of the chain
        let entry = Record::new(
            key,
            value,
            head.map(|(section, offset, _)| (section, offset)),
        );

        // Append entry to the variable journal
        let (offset, _) = self.journal.append(self.current_section, entry).await?;

        // Update the number of items added to the entry.
        //
        // We use `saturating_add` to handle overflow (when the table is at max size) gracefully.
        let mut added = head.map(|(_, _, added)| added).unwrap_or(0);
        added = added.saturating_add(1);

        // If we've reached the threshold for resizing, increment the resizable entries
        if added == self.table_resize_frequency {
            self.resizable += 1;
        }

        // Update the old position
        self.modified_sections.insert(self.current_section);
        let new_entry = Entry::new(self.next_epoch, self.current_section, offset, added);
        Self::update_head(&self.table, table_index, &entry1, &entry2, new_entry).await?;

        // If we're mid-resize and this entry has already been processed, update the new position too
        if let Some(resize_progress) = self.resize_progress {
            if table_index < resize_progress {
                self.unnecessary_writes.inc();

                // If the previous entry crossed the threshold, so did this one
                if added == self.table_resize_frequency {
                    self.resizable += 1;
                }

                // This entry has been processed, so we need to update the new position as well.
                //
                // The entries are still identical to the old ones, so we don't need to read them again.
                let new_table_index = self.table_size + table_index;
                let new_entry = Entry::new(self.next_epoch, self.current_section, offset, added);
                Self::update_head(&self.table, new_table_index, &entry1, &entry2, new_entry)
                    .await?;
            }
        }

        Ok(Cursor::new(self.current_section, offset))
    }

    /// Get the value for a given [Cursor].
    async fn get_cursor(&self, cursor: Cursor) -> Result<V, Error> {
        let entry = self.journal.get(cursor.section(), cursor.offset()).await?;

        Ok(entry.value)
    }

    /// Get the first value for a given key.
    async fn get_key(&self, key: &K) -> Result<Option<V>, Error> {
        self.gets.inc();

        // Get head of the chain from table
        let table_index = self.table_index(key);
        let (entry1, entry2) = Self::read_table(&self.table, table_index).await?;
        let Some((mut section, mut offset, _)) = Self::read_latest_entry(&entry1, &entry2) else {
            return Ok(None);
        };

        // Follow the linked list chain to find the first matching key
        loop {
            // Get the entry from the variable journal
            let entry = self.journal.get(section, offset).await?;

            // Check if this key matches
            if entry.key.as_ref() == key.as_ref() {
                return Ok(Some(entry.value));
            }

            // Increment unnecessary reads
            self.unnecessary_reads.inc();

            // Follow the chain
            let Some(next) = entry.next else {
                break; // End of chain
            };
            section = next.0;
            offset = next.1;
        }

        Ok(None)
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

    /// Resize the table by doubling its size and split each entry into two.
    async fn start_resize(&mut self) -> Result<(), Error> {
        self.resizes.inc();

        // Double the table size (if not already at the max size)
        let old_size = self.table_size;
        let Some(new_size) = old_size.checked_mul(2) else {
            return Ok(());
        };
        self.table.resize(Self::table_offset(new_size)).await?;

        // Start the resize
        self.resize_progress = Some(0);
        debug!(old = old_size, new = new_size, "table resize started");

        Ok(())
    }

    /// Write a pair of entries to a buffer, replacing one slot with the new entry.
    fn rewrite_entries(buf: &mut Vec<u8>, entry1: &Entry, entry2: &Entry, new_entry: &Entry) {
        if Self::compute_write_offset(entry1, entry2, new_entry.epoch) == 0 {
            buf.extend_from_slice(&new_entry.encode());
            buf.extend_from_slice(&entry2.encode());
        } else {
            buf.extend_from_slice(&entry1.encode());
            buf.extend_from_slice(&new_entry.encode());
        }
    }

    /// Continue a resize operation by processing the next chunk of entries.
    ///
    /// This function processes `table_resize_chunk_size` entries at a time,
    /// allowing the resize to be spread across multiple sync operations to
    /// avoid latency spikes.
    async fn advance_resize(&mut self) -> Result<(), Error> {
        // Compute the range to update
        let current_index = self.resize_progress.unwrap();
        let old_size = self.table_size;
        let chunk_end = (current_index + self.table_resize_chunk_size).min(old_size);
        let chunk_size = chunk_end - current_index;

        // Read the entire chunk
        let chunk_bytes = chunk_size as usize * Entry::FULL_SIZE;
        let read_offset = Self::table_offset(current_index);
        let read_buf = vec![0u8; chunk_bytes];
        let read_buf: Vec<u8> = self.table.read_at(read_buf, read_offset).await?.into();

        // Process each entry in the chunk
        let mut writes = Vec::with_capacity(chunk_bytes);
        for i in 0..chunk_size {
            // Get the entry
            let entry_offset = i as usize * Entry::FULL_SIZE;
            let entry_end = entry_offset + Entry::FULL_SIZE;
            let entry_buf = &read_buf[entry_offset..entry_end];

            // Parse the two slots
            let (entry1, entry2) = Self::parse_entries(entry_buf)?;

            // Get the current head
            let (section, offset, added) =
                Self::read_latest_entry(&entry1, &entry2).unwrap_or((0, 0, 0));

            // If the entry was over the threshold, decrement the resizable entries
            if added >= self.table_resize_frequency {
                self.resizable -= 1;
            }

            // Rewrite the entries
            let reset_entry = Entry::new(self.next_epoch, section, offset, 0);
            Self::rewrite_entries(&mut writes, &entry1, &entry2, &reset_entry);
        }

        // Put the writes into the table
        let old_write = self.table.write_at(writes.clone(), read_offset);
        let new_offset = (old_size as usize * Entry::FULL_SIZE) as u64 + read_offset;
        let new_write = self.table.write_at(writes, new_offset);
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
    pub async fn sync(&mut self) -> Result<Checkpoint, Error> {
        // Sync all modified journal sections
        let mut updates = Vec::with_capacity(self.modified_sections.len());
        for section in &self.modified_sections {
            updates.push(self.journal.sync(*section));
        }
        try_join_all(updates).await?;
        self.modified_sections.clear();

        // Start a resize (if needed)
        if self.should_resize() && self.resize_progress.is_none() {
            self.start_resize().await?;
        }

        // Continue a resize (if ongoing)
        if self.resize_progress.is_some() {
            self.advance_resize().await?;
        }

        // Sync updated table entries
        self.table.sync().await?;
        let stored_epoch = self.next_epoch;
        self.next_epoch = self.next_epoch.checked_add(1).expect("epoch overflow");

        Ok(Checkpoint {
            epoch: stored_epoch,
            section: self.current_section,
            size: self.journal.size(self.current_section).await?,
            table_size: self.table_size,
        })
    }

    /// Close the [Freezer] and return a [Checkpoint] for recovery.
    pub async fn close(mut self) -> Result<Checkpoint, Error> {
        // If we're mid-resize, complete it
        while self.resize_progress.is_some() {
            self.advance_resize().await?;
        }

        // Sync any pending updates before closing
        let checkpoint = self.sync().await?;

        self.journal.close().await?;
        self.table.sync().await?;
        Ok(checkpoint)
    }

    /// Close and remove any underlying blobs created by the [Freezer].
    pub async fn destroy(self) -> Result<(), Error> {
        // Destroy the journal (removes all journal sections)
        self.journal.destroy().await?;

        // Destroy the table
        drop(self.table);
        self.context
            .remove(&self.table_partition, Some(TABLE_BLOB_NAME))
            .await?;
        self.context.remove(&self.table_partition, None).await?;

        Ok(())
    }

    /// Get the current progress of the resize operation.
    ///
    /// Returns `None` if the [Freezer] is not resizing.
    #[cfg(test)]
    pub fn resizing(&self) -> Option<u32> {
        self.resize_progress
    }

    /// Get the number of resizable entries.
    #[cfg(test)]
    pub fn resizable(&self) -> u32 {
        self.resizable
    }
}
