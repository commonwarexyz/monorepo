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
#[derive(Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
#[repr(transparent)]
pub struct Cursor([u8; u64::SIZE + u32::SIZE]);

impl Cursor {
    fn new(section: u64, offset: u32) -> Self {
        let mut buf = [0u8; u64::SIZE + u32::SIZE];
        buf[..u64::SIZE].copy_from_slice(&section.to_be_bytes());
        buf[u64::SIZE..].copy_from_slice(&offset.to_be_bytes());
        Self(buf)
    }

    fn section(&self) -> u64 {
        u64::from_be_bytes(self.0[..u64::SIZE].try_into().unwrap())
    }

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
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Copy, Default)]
pub struct Checkpoint {
    epoch: u64,
    section: u64,
    size: u64,
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
struct TableEntry {
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

impl TableEntry {
    /// The full size of a table entry (2 slots).
    const FULL_SIZE: usize = Self::SIZE * 2;

    /// Create a new [TableEntry] with a CRC.
    fn new(epoch: u64, section: u64, offset: u32, added: u8) -> Self {
        let mut hasher = crc32fast::Hasher::new();
        hasher.update(&epoch.to_be_bytes());
        hasher.update(&section.to_be_bytes());
        hasher.update(&offset.to_be_bytes());
        hasher.update(&added.to_be_bytes());

        Self {
            epoch,
            section,
            offset,
            added,
            crc: hasher.finalize(),
        }
    }

    /// Check if this entry is empty (all zeros).
    fn is_empty(&self) -> bool {
        self.section == 0 && self.offset == 0 && self.crc == 0
    }

    /// Check if this entry is valid.
    fn is_valid(&self) -> bool {
        let mut hasher = crc32fast::Hasher::new();
        hasher.update(&self.epoch.to_be_bytes());
        hasher.update(&self.section.to_be_bytes());
        hasher.update(&self.offset.to_be_bytes());
        hasher.update(&self.added.to_be_bytes());
        hasher.finalize() == self.crc
    }
}

impl FixedSize for TableEntry {
    const SIZE: usize = u64::SIZE + u64::SIZE + u32::SIZE + u8::SIZE + u32::SIZE;
}

impl CodecWrite for TableEntry {
    fn write(&self, buf: &mut impl BufMut) {
        self.epoch.write(buf);
        self.section.write(buf);
        self.offset.write(buf);
        self.added.write(buf);
        self.crc.write(buf);
    }
}

impl Read for TableEntry {
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

/// Record stored in the journal for linked list entries.
struct JournalEntry<K: Array, V: Codec> {
    key: K,
    value: V,
    next: Option<(u64, u32)>,
}

impl<K: Array, V: Codec> JournalEntry<K, V> {
    /// Create a new [JournalEntry].
    fn new(key: K, value: V, next: Option<(u64, u32)>) -> Self {
        Self { key, value, next }
    }
}

impl<K: Array, V: Codec> CodecWrite for JournalEntry<K, V> {
    fn write(&self, buf: &mut impl BufMut) {
        self.key.write(buf);
        self.value.write(buf);
        self.next.write(buf);
    }
}

impl<K: Array, V: Codec> Read for JournalEntry<K, V> {
    type Cfg = V::Cfg;

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        let key = K::read(buf)?;
        let value = V::read_cfg(buf, cfg)?;
        let next = Option::<(u64, u32)>::read_cfg(buf, &((), ()))?;

        Ok(Self { key, value, next })
    }
}

impl<K: Array, V: Codec> EncodeSize for JournalEntry<K, V> {
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

    // Table blob that maps hash values to journal locations (journal_id, offset)
    table: E::Blob,

    // Variable journal for storing entries
    journal: Journal<E, JournalEntry<K, V>>,
    journal_target_size: u64,

    // Current section for new writes
    current_section: u64,
    next_epoch: u64,

    // Metrics
    puts: Counter,
    gets: Counter,
    resizes: Counter,

    // Pending table updates to be written on sync (table_index -> (section, offset))
    modified_sections: BTreeSet<u64>,
    should_resize: bool,

    // Phantom data to satisfy the compiler about generic types
    _phantom: PhantomData<(K, V)>,
}

impl<E: Storage + Metrics + Clock, K: Array, V: Codec> Freezer<E, K, V> {
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

        // If the blob is brand new, create header + zeroed buckets.
        let checkpoint = if table_len == 0 {
            // Assert that the checkpoint is valid
            if let Some(checkpoint) = checkpoint {
                assert_eq!(checkpoint.epoch, 0);
                assert_eq!(checkpoint.section, 0);
                assert_eq!(checkpoint.size, 0);
                assert_eq!(checkpoint.table_size, 0);
            }

            // Create the table
            let table_data_size = config.table_initial_size as u64 * TableEntry::FULL_SIZE as u64;
            table.resize(table_data_size).await?;
            table.sync().await?;
            Checkpoint {
                table_size: config.table_initial_size,
                ..Default::default()
            }
        } else if let Some(checkpoint) = checkpoint {
            // Assert that the checkpoint is valid
            assert!(
                checkpoint.table_size > 0 && checkpoint.table_size.is_power_of_two(),
                "table_size must be a power of 2"
            );

            // Rewind the journal to the committed section and offset and drop all values larger
            journal.rewind(checkpoint.section, checkpoint.size).await?;

            // Resize the table
            let mut modified = false;
            let table_data_size = checkpoint.table_size as u64 * TableEntry::FULL_SIZE as u64;
            if table_data_size != table_len {
                table.resize(table_data_size).await?;
                modified = true;
            }

            // Zero out any table entries whose epoch is greater than the committed epoch
            let zero_buf = vec![0u8; TableEntry::SIZE];
            for table_index in 0..checkpoint.table_size {
                let offset = table_index as u64 * TableEntry::FULL_SIZE as u64;
                let result = table
                    .read_at(vec![0u8; TableEntry::FULL_SIZE], offset)
                    .await?;

                let mut buf1 = &result.as_ref()[0..TableEntry::SIZE];
                let entry1 = TableEntry::read(&mut buf1)?;
                if !entry1.is_empty() && (!entry1.is_valid() || entry1.epoch > checkpoint.epoch) {
                    debug!(
                        epoch = checkpoint.epoch,
                        epoch = entry1.epoch,
                        "found invalid table entry"
                    );
                    table.write_at(zero_buf.clone(), offset).await?;
                    modified = true;
                }

                let mut buf2 = &result.as_ref()[TableEntry::SIZE..TableEntry::FULL_SIZE];
                let entry2 = TableEntry::read(&mut buf2)?;
                if !entry2.is_empty() && (!entry2.is_valid() || entry2.epoch > checkpoint.epoch) {
                    debug!(
                        epoch = checkpoint.epoch,
                        epoch = entry2.epoch,
                        "found invalid table entry"
                    );
                    table
                        .write_at(zero_buf.clone(), offset + TableEntry::SIZE as u64)
                        .await?;
                    modified = true;
                }
            }

            // Sync the table if any changes were made
            if modified {
                table.sync().await?;
            }
            checkpoint
        } else {
            // Open the table blob and construct a checkpoint from what is written
            let mut modified = false;
            let mut checkpoint = Checkpoint {
                table_size: (table_len / TableEntry::FULL_SIZE as u64) as u32,
                ..Default::default()
            };
            let zero_buf = vec![0u8; TableEntry::SIZE];
            for table_index in 0..checkpoint.table_size {
                let offset = table_index as u64 * TableEntry::FULL_SIZE as u64;
                let result = table
                    .read_at(vec![0u8; TableEntry::FULL_SIZE], offset)
                    .await?;

                let mut buf1 = &result.as_ref()[0..TableEntry::SIZE];
                let entry1 = TableEntry::read(&mut buf1)?;
                if !entry1.is_empty() {
                    if !entry1.is_valid() {
                        debug!(
                            epoch = checkpoint.epoch,
                            epoch = entry1.epoch,
                            "found invalid table entry"
                        );
                        table.write_at(zero_buf.clone(), offset).await?;
                        modified = true;
                    } else if entry1.epoch > checkpoint.epoch {
                        checkpoint.epoch = entry1.epoch;
                        checkpoint.section = entry1.section;
                    }
                }

                let mut buf2 = &result.as_ref()[TableEntry::SIZE..TableEntry::FULL_SIZE];
                let entry2 = TableEntry::read(&mut buf2)?;
                if !entry2.is_empty() {
                    if !entry2.is_valid() {
                        debug!(
                            epoch = checkpoint.epoch,
                            epoch = entry2.epoch,
                            "found invalid table entry"
                        );
                        table
                            .write_at(zero_buf.clone(), offset + TableEntry::SIZE as u64)
                            .await?;
                        modified = true;
                    } else if entry2.epoch > checkpoint.epoch {
                        checkpoint.epoch = entry2.epoch;
                        checkpoint.section = entry2.section;
                    }
                }
            }
            if modified {
                table.sync().await?;
            }

            // Get the current section size
            let size = journal.size(checkpoint.section).await?;
            checkpoint.size = size;

            checkpoint
        };

        // Create metrics
        let puts = Counter::default();
        let gets = Counter::default();
        let resizes = Counter::default();
        context.register("puts", "number of put operations", puts.clone());
        context.register("gets", "number of get operations", gets.clone());
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
            resizes,
            modified_sections: BTreeSet::new(),
            should_resize: false,
            _phantom: PhantomData,
        })
    }

    /// Compute the table index for a given key using bit-based indexing.
    ///
    /// This method uses a bit-based approach instead of modulo to ensure that
    /// values can be correctly looked up as the table grows. When the table
    /// doubles in size, each bucket splits into two: the original bucket and
    /// a new bucket at position (original + old_size).
    ///
    /// For example, with initial size 4 (2^2):
    /// - Initially: use 2 bits, so buckets are 0, 1, 2, 3
    /// - After resize to 8: use 3 bits, bucket 0 splits into 0 and 4
    /// - After resize to 16: use 4 bits, bucket 0 splits into 0 and 8, etc.
    ///
    /// This ensures that entries inserted before a resize can still be found
    /// after the resize, as they will be in one of the two possible locations.
    fn table_index(&self, key: &K) -> u32 {
        let hash = crc32fast::hash(key.as_ref());

        // Calculate the depth (how many times the table has been resized)
        // depth = log2(table_size / table_initial_size)
        let depth = (self.table_size / self.table_initial_size).trailing_zeros();

        // Calculate the number of bits to use
        // initial_bits = log2(table_initial_size)
        let initial_bits = self.table_initial_size.trailing_zeros();
        let total_bits = initial_bits + depth;

        // Extract the lower 'total_bits' bits from the hash
        // This ensures that when the table doubles, entries at position X
        // will either stay at X or move to X + old_size
        let mask = (1u32 << total_bits) - 1;
        hash & mask
    }

    /// Choose the newer valid entry between two table slots.
    fn select_valid_entry(
        &self,
        entry1: &TableEntry,
        entry2: &TableEntry,
    ) -> Option<(u64, u32, u8)> {
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
        // Read the table entry
        let offset = table_index as u64 * TableEntry::FULL_SIZE as u64;
        let buf = vec![0u8; TableEntry::FULL_SIZE];
        let read_buf = self.table.read_at(buf, offset).await?;
        let mut buf1 = &read_buf.as_ref()[0..TableEntry::SIZE];
        let entry1 = TableEntry::read(&mut buf1)?;
        let mut buf2 = &read_buf.as_ref()[TableEntry::SIZE..TableEntry::FULL_SIZE];
        let entry2 = TableEntry::read(&mut buf2)?;

        // Select the valid entry and return with depth
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
        let table_offset = table_index as u64 * TableEntry::FULL_SIZE as u64;
        let buf = vec![0u8; TableEntry::FULL_SIZE];
        let read_buf = self.table.read_at(buf, table_offset).await?;

        // Parse current entries using codec
        let mut buf1 = &read_buf.as_ref()[0..TableEntry::SIZE];
        let entry1 = TableEntry::read(&mut buf1)?;
        let mut buf2 = &read_buf.as_ref()[TableEntry::SIZE..TableEntry::FULL_SIZE];
        let entry2 = TableEntry::read(&mut buf2)?;

        // Determine where to start writing the new entry
        let start = if !entry1.is_empty() && entry1.epoch == epoch {
            // Overwrite existing entry for this epoch
            0
        } else if !entry2.is_empty() && entry2.epoch == epoch {
            // Overwrite existing entry for this epoch
            TableEntry::SIZE
        } else if entry1.is_empty() || entry1.epoch < entry2.epoch {
            0
        } else if entry2.is_empty() || entry2.epoch < entry1.epoch {
            TableEntry::SIZE
        } else {
            unreachable!("two valid entries with the same epoch");
        };

        // Build the new entry
        let entry = TableEntry::new(epoch, section, offset, added);

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
        let entry = JournalEntry::new(
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

            // Follow the chain
            let Some(next) = entry.next else {
                break; // End of chain
            };
            section = next.0;
            offset = next.1;
        }

        Ok(None)
    }

    pub async fn get<'a>(&'a self, identifier: Identifier<'a, K>) -> Result<Option<V>, Error> {
        match identifier {
            Identifier::Cursor(cursor) => self.get_cursor(cursor).await,
            Identifier::Key(key) => self.get_key(key).await,
        }
    }

    /// Check if a key exists in the freezer.
    pub async fn has(&self, key: &K) -> Result<bool, Error> {
        Ok(self.get(Identifier::Key(key)).await?.is_some())
    }

    /// Resize the table by doubling its size and re-sharding all entries.
    async fn resize(&mut self) -> Result<(), Error> {
        self.resizes.inc();

        // Double the table size
        let old = self.table_size;
        let new = old.checked_mul(2).expect("table size overflow");
        debug!(old, new, "resizing table");
        self.table
            .resize(new as u64 * TableEntry::FULL_SIZE as u64)
            .await?;

        // For each bucket in the old table, copy its head to the new position
        let mut updates = Vec::with_capacity(old as usize * 2);
        for i in 0..old {
            let head = self.get_head(i).await?;
            if let Some((section, offset, _)) = head {
                // Write the same head to both i and i + old_size
                updates.push(self.update_head(self.next_epoch, i, section, offset, 0));
                updates.push(self.update_head(self.next_epoch, i + old, section, offset, 0));
            } else {
                // No chain at this position, write empty entries
                updates.push(self.update_head(self.next_epoch, i, 0, 0, 0));
                updates.push(self.update_head(self.next_epoch, i + old, 0, 0, 0));
            }
        }
        try_join_all(updates).await?;

        // Update the table size
        self.table_size = new;
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
