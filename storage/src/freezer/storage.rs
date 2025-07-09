use super::{Config, Error, Identifier};
use crate::journal::variable::{Config as JournalConfig, Journal};
use bytes::{Buf, BufMut};
use commonware_codec::{Codec, Encode, EncodeSize, FixedSize, Read, ReadExt, Write as CodecWrite};
use commonware_runtime::{Blob, Clock, Metrics, Storage};
use commonware_utils::Array;
use futures::future::try_join_all;
use prometheus_client::metrics::counter::Counter;
use std::{cmp::Ordering, collections::BTreeSet, marker::PhantomData, ops::Deref};
use tracing::debug;

/// Cursor for an item in the [Freezer].
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

/// Checkpoint for [Freezer] progress.
///
/// This can be used to restore the [Freezer] to a consistent
/// state after shutdown.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Copy, Default)]
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
    // Number of items added to this bucket since last resize
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
    table_initial_size: u32,
    table_resize_frequency: u8,

    // Table blob that maps slots to journal chain heads
    table: E::Blob,

    // Variable journal for storing entries
    journal: Journal<E, Record<K, V>>,
    journal_target_size: u64,

    // Current section for new writes
    current_section: u64,
    next_epoch: u64,

    // Pending table updates to be written on sync (table_index -> (section, offset))
    modified_sections: BTreeSet<u64>,
    should_resize: bool,

    // Metrics
    puts: Counter,
    gets: Counter,
    useless_reads: Counter,
    resizes: Counter,

    // Phantom data to satisfy the compiler about generic types
    _phantom: PhantomData<(K, V)>,
}

impl<E: Storage + Metrics + Clock, K: Array, V: Codec> Freezer<E, K, V> {
    /// Read a table entry pair at the given index.
    async fn read_table_entry(&self, table_index: u32) -> Result<(Entry, Entry), Error> {
        let offset = table_index as u64 * Entry::FULL_SIZE as u64;
        let buf = vec![0u8; Entry::FULL_SIZE];
        let read_buf = self.table.read_at(buf, offset).await?;

        let mut buf1 = &read_buf.as_ref()[0..Entry::SIZE];
        let entry1 = Entry::read(&mut buf1)?;
        let mut buf2 = &read_buf.as_ref()[Entry::SIZE..Entry::FULL_SIZE];
        let entry2 = Entry::read(&mut buf2)?;

        Ok((entry1, entry2))
    }

    /// Read table entries from a blob at the given index.
    async fn read_table_entries(blob: &E::Blob, table_index: u32) -> Result<(Entry, Entry), Error> {
        let offset = table_index as u64 * Entry::FULL_SIZE as u64;
        let buf = vec![0u8; Entry::FULL_SIZE];
        let read_buf = blob.read_at(buf, offset).await?;

        let mut buf1 = &read_buf.as_ref()[0..Entry::SIZE];
        let entry1 = Entry::read(&mut buf1)?;
        let mut buf2 = &read_buf.as_ref()[Entry::SIZE..Entry::FULL_SIZE];
        let entry2 = Entry::read(&mut buf2)?;

        Ok((entry1, entry2))
    }

    /// Validate and clean invalid table entries for a given epoch.
    ///
    /// Returns (modified, max_epoch, max_section) where:
    /// - modified: whether any entries were cleaned
    /// - max_epoch: the maximum valid epoch found (if max_valid_epoch is None)
    /// - max_section: the section corresponding to max_epoch
    async fn recover_table(
        blob: &E::Blob,
        table_size: u32,
        max_valid_epoch: Option<u64>,
    ) -> Result<(bool, u64, u64), Error> {
        let mut modified = false;
        let mut max_epoch = 0u64;
        let mut max_section = 0u64;
        let zero_buf = vec![0u8; Entry::SIZE];

        for table_index in 0..table_size {
            let offset = table_index as u64 * Entry::FULL_SIZE as u64;
            let (entry1, entry2) = Self::read_table_entries(blob, table_index).await?;

            // Check first entry
            if !entry1.is_empty() {
                if !entry1.is_valid()
                    || (max_valid_epoch.is_some() && entry1.epoch > max_valid_epoch.unwrap())
                {
                    debug!(
                        valid_epoch = max_valid_epoch,
                        entry_epoch = entry1.epoch,
                        "found invalid table entry"
                    );
                    blob.write_at(zero_buf.clone(), offset).await?;
                    modified = true;
                } else if max_valid_epoch.is_none() && entry1.epoch > max_epoch {
                    // Only track max epoch if we're discovering it (not validating against a known epoch)
                    max_epoch = entry1.epoch;
                    max_section = entry1.section;
                }
            }

            // Check second entry
            if !entry2.is_empty() {
                if !entry2.is_valid()
                    || (max_valid_epoch.is_some() && entry2.epoch > max_valid_epoch.unwrap())
                {
                    debug!(
                        valid_epoch = max_valid_epoch,
                        entry_epoch = entry2.epoch,
                        "found invalid table entry"
                    );
                    blob.write_at(zero_buf.clone(), offset + Entry::SIZE as u64)
                        .await?;
                    modified = true;
                } else if max_valid_epoch.is_none() && entry2.epoch > max_epoch {
                    // Only track max epoch if we're discovering it (not validating against a known epoch)
                    max_epoch = entry2.epoch;
                    max_section = entry2.section;
                }
            }
        }

        Ok((modified, max_epoch, max_section))
    }

    /// Determine the write slot for a table entry based on current entries and epoch.
    fn select_write_slot(entry1: &Entry, entry2: &Entry, epoch: u64) -> usize {
        // If either entry matches the current epoch, overwrite it
        if !entry1.is_empty() && entry1.epoch == epoch {
            return 0;
        }
        if !entry2.is_empty() && entry2.epoch == epoch {
            return Entry::SIZE;
        }

        // Otherwise, write to the older slot (or empty slot)
        match (entry1.is_empty(), entry2.is_empty()) {
            (true, _) => 0,           // First slot is empty
            (_, true) => Entry::SIZE, // Second slot is empty
            (false, false) => {
                if entry1.epoch < entry2.epoch {
                    0
                } else {
                    Entry::SIZE
                }
            }
        }
    }

    /// Initialize a new [Freezer] instance.
    pub async fn init(context: E, config: Config<V::Cfg>) -> Result<Self, Error> {
        Self::init_synchronized(context, config, None).await
    }

    /// Initialize a new [Freezer] instance with a [Checkpoint].
    pub async fn init_synchronized(
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
        };
        let mut journal = Journal::init(context.clone(), journal_config).await?;

        // Open table blob (includes header)
        let (table, table_len) = context
            .open(&config.table_partition, TABLE_BLOB_NAME)
            .await?;

        // Determine checkpoint based on initialization scenario
        let checkpoint = match (table_len, checkpoint) {
            // New table with no data
            (0, None) => {
                let table_data_size = config.table_initial_size as u64 * Entry::FULL_SIZE as u64;
                table.resize(table_data_size).await?;
                table.sync().await?;
                Checkpoint {
                    table_size: config.table_initial_size,
                    ..Default::default()
                }
            }

            // New table with explicit checkpoint (must be empty)
            (0, Some(checkpoint)) => {
                assert_eq!(checkpoint.epoch, 0);
                assert_eq!(checkpoint.section, 0);
                assert_eq!(checkpoint.size, 0);
                assert_eq!(checkpoint.table_size, 0);

                let table_data_size = config.table_initial_size as u64 * Entry::FULL_SIZE as u64;
                table.resize(table_data_size).await?;
                table.sync().await?;
                Checkpoint {
                    table_size: config.table_initial_size,
                    ..Default::default()
                }
            }

            // Existing table with checkpoint
            (_, Some(checkpoint)) => {
                assert!(
                    checkpoint.table_size > 0 && checkpoint.table_size.is_power_of_two(),
                    "table_size must be a power of 2"
                );

                // Rewind the journal to the committed section and offset
                journal.rewind(checkpoint.section, checkpoint.size).await?;

                // Resize table if needed
                let table_data_size = checkpoint.table_size as u64 * Entry::FULL_SIZE as u64;
                let mut modified = if table_data_size != table_len {
                    table.resize(table_data_size).await?;
                    true
                } else {
                    false
                };

                // Validate and clean invalid entries
                let (table_modified, _, _) =
                    Self::recover_table(&table, checkpoint.table_size, Some(checkpoint.epoch))
                        .await?;
                if table_modified {
                    modified = true;
                }

                // Sync table if needed
                if modified {
                    table.sync().await?;
                }

                checkpoint
            }

            // Existing table without checkpoint
            (_, None) => {
                // Find max epoch/section and clean invalid entries in a single pass
                let table_size = (table_len / Entry::FULL_SIZE as u64) as u32;
                let (modified, max_epoch, max_section) =
                    Self::recover_table(&table, table_size, None).await?;

                // Sync table if needed
                if modified {
                    table.sync().await?;
                }

                Checkpoint {
                    epoch: max_epoch,
                    section: max_section,
                    size: journal.size(max_section).await?,
                    table_size,
                }
            }
        };

        // Create metrics
        let puts = Counter::default();
        let gets = Counter::default();
        let useless_reads = Counter::default();
        let resizes = Counter::default();
        context.register("puts", "number of put operations", puts.clone());
        context.register("gets", "number of get operations", gets.clone());
        context.register(
            "useless_reads",
            "number of get operations that didn't match the key",
            useless_reads.clone(),
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
            table_initial_size: config.table_initial_size,
            table_resize_frequency: config.table_resize_frequency,
            table,
            journal,
            journal_target_size: config.journal_target_size,
            current_section: checkpoint.section,
            next_epoch: checkpoint.epoch.checked_add(1).expect("epoch overflow"),
            puts,
            gets,
            useless_reads,
            resizes,
            modified_sections: BTreeSet::new(),
            should_resize: false,
            _phantom: PhantomData,
        })
    }

    /// Compute the table index for a given key using bit-based indexing.
    ///
    /// When the table doubles in size, each bucket splits into two: the original
    /// bucket and a new bucket at position (original + old_size).
    ///
    /// For example, with initial size 4 (2^2):
    /// - Initially: use 2 bits, so buckets are 0, 1, 2, 3
    /// - After resize to 8: use 3 bits, bucket 0 splits into 0 and 4
    /// - After resize to 16: use 4 bits, bucket 0 splits into 0 and 8, etc.
    ///
    /// This function maps the hash to the correct bucket by extracting the
    /// lower bits that are used to determine the bucket.
    fn table_index(&self, key: &K) -> u32 {
        let hash = crc32fast::hash(key.as_ref());

        // Calculate the depth (how many times the table has been resized)
        //
        // depth = log2(table_size / table_initial_size)
        let depth = (self.table_size / self.table_initial_size).trailing_zeros();

        // Calculate the number of bits to use
        //
        // initial_bits = log2(table_initial_size)
        let initial_bits = self.table_initial_size.trailing_zeros();
        let total_bits = initial_bits + depth;

        // Extract the lower 'total_bits' bits from the hash
        //
        // This ensures that when the table doubles, entries at position X
        // will either stay at X or move to X + old_size
        let mask = (1u32 << total_bits) - 1;
        hash & mask
    }

    /// Choose the newer valid entry between two table slots.
    fn select_valid_entry(&self, entry1: &Entry, entry2: &Entry) -> Option<(u64, u32, u8)> {
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

    /// Get the head of the journal chain for a given table index, along with its depth.
    async fn get_head(&self, table_index: u32) -> Result<Option<(u64, u32, u8)>, Error> {
        let (entry1, entry2) = self.read_table_entry(table_index).await?;
        Ok(self.select_valid_entry(&entry1, &entry2))
    }

    /// Write a table entry to disk using atomic dual-entry writes.
    async fn update_head(
        &self,
        epoch: u64,
        table_index: u32,
        section: u64,
        offset: u32,
        added: u8,
    ) -> Result<(), Error> {
        // Read current entries to determine which slot to update
        let table_offset = table_index as u64 * Entry::FULL_SIZE as u64;
        let (entry1, entry2) = self.read_table_entry(table_index).await?;

        // Determine where to start writing the new entry
        let start = Self::select_write_slot(&entry1, &entry2, epoch);

        // Build the new entry
        let entry = Entry::new(epoch, section, offset, added);

        // Write the new entry
        self.table
            .write_at(entry.encode(), table_offset + start as u64)
            .await
            .map_err(Error::Runtime)
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

    /// Put a key-value pair into the freezer.
    pub async fn put(&mut self, key: K, value: V) -> Result<Cursor, Error> {
        self.puts.inc();

        // Update the section if needed
        self.update_section().await?;

        // Get head of the chain from table
        let table_index = self.table_index(&key);
        let head = self.get_head(table_index).await?;

        // Create new head of the chain
        let entry = Record::new(
            key,
            value,
            head.map(|(section, offset, _)| (section, offset)),
        );

        // Append entry to the variable journal
        let (offset, _) = self.journal.append(self.current_section, entry).await?;

        // Push table update
        let mut added = head.map(|(_, _, added)| added).unwrap_or(0);

        // Determine if we should resize the table
        if added >= self.table_resize_frequency {
            // We don't need to keep incrementing added because we are already resizing.
            //
            // This prevents an overflow of the added field when there are many operations before resize.
            self.should_resize = true;
        } else {
            added = added.checked_add(1).expect("added overflow");
        }

        self.modified_sections.insert(self.current_section);
        self.update_head(
            self.next_epoch,
            table_index,
            self.current_section,
            offset,
            added,
        )
        .await?;

        Ok(Cursor::new(self.current_section, offset))
    }

    /// Get the value for a given cursor.
    async fn get_cursor(&self, cursor: Cursor) -> Result<Option<V>, Error> {
        let entry = self.journal.get(cursor.section(), cursor.offset()).await?;
        let Some(entry) = entry else {
            return Ok(None);
        };

        Ok(Some(entry.value))
    }

    /// Get the first value for a given key.
    async fn get_key(&self, key: &K) -> Result<Option<V>, Error> {
        self.gets.inc();

        // Get head of the chain from table
        let table_index = self.table_index(key);
        let Some((mut section, mut offset, _)) = self.get_head(table_index).await? else {
            return Ok(None);
        };

        // Follow the linked list chain, collecting values for matching keys
        loop {
            // Get the entry from the variable journal
            let entry = match self.journal.get(section, offset).await? {
                Some(entry) => entry,
                None => unreachable!("missing entry"),
            };

            // Check if this key matches
            if entry.key.as_ref() == key.as_ref() {
                return Ok(Some(entry.value));
            }

            // Increment useless reads
            self.useless_reads.inc();

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
    pub async fn get<'a>(&'a self, identifier: Identifier<'a, K>) -> Result<Option<V>, Error> {
        match identifier {
            Identifier::Cursor(cursor) => self.get_cursor(cursor).await,
            Identifier::Key(key) => self.get_key(key).await,
        }
    }

    /// Resize the table by doubling its size and re-sharding all entries.
    async fn resize(&mut self) -> Result<(), Error> {
        self.resizes.inc();

        // Double the table size
        let old_size = self.table_size;
        let new_size = old_size.checked_mul(2).expect("table size overflow");
        debug!(old = old_size, new = new_size, "resizing table");
        self.table
            .resize(new_size as u64 * Entry::FULL_SIZE as u64)
            .await?;

        // For each bucket in the old table, copy its head to the new position
        let mut updates = Vec::with_capacity(old_size as usize * 2);
        for i in 0..old_size {
            // Get the previous value or default to (0, 0)
            let head = self.get_head(i).await?;
            let (section, offset) = head
                .map(|(section, offset, _)| (section, offset))
                .unwrap_or((0, 0));

            // Write the same head to both i and i + old_size
            updates.push(self.update_head(self.next_epoch, i, section, offset, 0));
            updates.push(self.update_head(self.next_epoch, i + old_size, section, offset, 0));
        }
        try_join_all(updates).await?;

        // Update the table size
        self.table_size = new_size;
        self.should_resize = false;

        Ok(())
    }

    /// Sync all data to the underlying freezer.
    pub async fn sync(&mut self) -> Result<Checkpoint, Error> {
        // Sync all modified journal sections
        let mut updates = Vec::with_capacity(self.modified_sections.len());
        for section in &self.modified_sections {
            updates.push(self.journal.sync(*section));
        }
        try_join_all(updates).await?;
        self.modified_sections.clear();

        // Sync updated table entries
        if self.should_resize {
            self.resize().await?;
        }
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

    /// Close the freezer and underlying journal.
    pub async fn close(mut self) -> Result<Checkpoint, Error> {
        // Sync any pending updates before closing
        let checkpoint = self.sync().await?;

        self.journal.close().await?;
        self.table.close().await?;
        Ok(checkpoint)
    }

    /// Close and remove any underlying blobs created by the freezer.
    pub async fn destroy(self) -> Result<(), Error> {
        // Destroy the journal (removes all journal sections)
        self.journal.destroy().await?;

        // Destroy the table
        self.table.close().await?;
        self.context
            .remove(&self.table_partition, Some(TABLE_BLOB_NAME))
            .await?;
        self.context.remove(&self.table_partition, None).await?;

        Ok(())
    }
}
