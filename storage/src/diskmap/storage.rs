use super::{Config, Error};
use crate::journal::variable::{Config as JournalConfig, Journal};
use crate::metadata::{self, Metadata};
use bytes::{Buf, BufMut};
use commonware_codec::{Codec, EncodeSize, FixedSize, Read, ReadExt, Write as CodecWrite};
use commonware_runtime::{Blob, Clock, Metrics, Storage};
use commonware_utils::array::U64;
use commonware_utils::{hex, Array};
use futures::future::try_join_all;
use prometheus_client::metrics::counter::Counter;
use std::collections::{HashMap, HashSet};
use std::marker::PhantomData;
use tracing::trace;

const COMMITTED_EPOCH: u64 = 0;
const COMMITTED_SECTION: u64 = 1;
const COMMITTED_OFFSET: u64 = 2;

// -------------------------------------------------------------------------------------------------
// Table layout
// -------------------------------------------------------------------------------------------------
// Bucket slot (24 bytes):
//   u64 epoch                – epoch in which this slot was written
//   u64 section
//   u32 offset
//   u32 crc                  – CRC of (epoch | section | offset )

/// Two slots per bucket, each slot now 24 bytes.
const TABLE_BLOB_NAME: &[u8] = b"table";
const TABLE_ENTRY_SIZE: usize = 24;
const FULL_TABLE_ENTRY_SIZE: usize = 2 * TABLE_ENTRY_SIZE;

/// Single table entry stored in the table blob.
#[derive(Debug, Clone, PartialEq)]
struct TableEntry {
    epoch: u64,
    section: u64,
    offset: u32,
    crc: u32,
}

impl TableEntry {
    /// Create a new `TableEntry`.
    fn new(epoch: u64, section: u64, offset: u32, crc: u32) -> Self {
        Self {
            epoch,
            section,
            offset,
            crc,
        }
    }

    /// Construct a new `TableEntry` with a CRC.
    fn construct(epoch: u64, section: u64, offset: u32) -> Self {
        let mut hasher = crc32fast::Hasher::new();
        hasher.update(&epoch.to_be_bytes());
        hasher.update(&section.to_be_bytes());
        hasher.update(&offset.to_be_bytes());
        Self {
            epoch,
            section,
            offset,
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
        hasher.finalize() == self.crc
    }
}

impl FixedSize for TableEntry {
    const SIZE: usize = TABLE_ENTRY_SIZE;
}

impl CodecWrite for TableEntry {
    fn write(&self, buf: &mut impl BufMut) {
        self.epoch.write(buf);
        self.section.write(buf);
        self.offset.write(buf);
        self.crc.write(buf);
    }
}

impl Read for TableEntry {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        let epoch = u64::read(buf)?;
        let section = u64::read(buf)?;
        let offset = u32::read(buf)?;
        let crc = u32::read(buf)?;

        Ok(Self {
            epoch,
            section,
            offset,
            crc,
        })
    }
}

/// Record stored in the journal for linked list entries.
struct JournalEntry<K: Array, V: Codec> {
    next_section: u64,
    next_offset: u32,
    key: K,
    value: V,
}

impl<K: Array, V: Codec> JournalEntry<K, V> {
    /// Create a new `JournalEntry`.
    fn new(next_section: u64, next_offset: u32, key: K, value: V) -> Self {
        Self {
            next_section,
            next_offset,
            key,
            value,
        }
    }
}

impl<K: Array, V: Codec> CodecWrite for JournalEntry<K, V> {
    fn write(&self, buf: &mut impl BufMut) {
        self.next_section.write(buf);
        self.next_offset.write(buf);
        self.key.write(buf);
        self.value.write(buf);
    }
}

impl<K: Array, V: Codec> Read for JournalEntry<K, V> {
    type Cfg = V::Cfg;

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        let next_section = u64::read(buf)?;
        let next_offset = u32::read(buf)?;
        let key = K::read(buf)?;
        let value = V::read_cfg(buf, cfg)?;

        Ok(Self {
            next_section,
            next_offset,
            key,
            value,
        })
    }
}

impl<K: Array, V: Codec> EncodeSize for JournalEntry<K, V> {
    fn encode_size(&self) -> usize {
        u64::SIZE + u32::SIZE + K::SIZE + 4 + self.value.encode_size()
    }
}

/// Implementation of `DiskMap` storage.
pub struct DiskMap<E: Storage + Metrics + Clock, K: Array, V: Codec> {
    // Context for storage operations
    context: E,

    // Codec configuration
    codec: V::Cfg,

    // Table size
    table_size: u64,

    // Committed data for the disk map
    metadata: Metadata<E, U64>,

    // Table blob that maps hash values to journal locations (journal_id, offset)
    table: E::Blob,

    // Variable journal for storing entries
    journal: Journal<E, JournalEntry<K, V>>,

    // Current section for new writes
    current_section: u64,

    // Metrics
    puts: Counter,
    gets: Counter,

    // Track modified journal sections
    modified_sections: HashSet<u64>,

    // Pending table updates to be written on sync (table_index -> (epoch, section, offset))
    pending_table_updates: HashMap<
        u64,
        (
            u64, /*epoch*/
            u64, /*section*/
            u32, /*offset*/
        ),
    >,

    // Phantom data to satisfy the compiler about generic types
    _phantom: PhantomData<(K, V)>,
}

impl<E: Storage + Metrics + Clock, K: Array, V: Codec> DiskMap<E, K, V> {
    /// Initialize a new `DiskMap` instance.
    pub async fn init(context: E, config: Config<V::Cfg>) -> Result<Self, Error> {
        // Validate configuration
        assert_ne!(config.table_size, 0, "table size must be non-zero");
        assert!(
            config.table_size.is_power_of_two(),
            "table size must be a power of two"
        );

        // Initialize metadata
        let metadata = Metadata::init(
            context.with_label("metadata"),
            metadata::Config {
                partition: config.metadata_partition,
            },
        )
        .await?;

        // Open table blob (includes header)
        let (table, table_len) = context
            .open(&config.table_partition, TABLE_BLOB_NAME)
            .await?;

        // If the blob is brand new, create header + zeroed buckets.
        if table_len == 0 {
            // buckets
            let table_data_size = config.table_size * FULL_TABLE_ENTRY_SIZE as u64;
            let table_data = vec![0u8; table_data_size as usize];
            table.write_at(table_data, 0).await?;
            table.sync().await?;
        }

        // Load committed data from metadata
        let committed_epoch = metadata
            .get(&COMMITTED_EPOCH.into())
            .and_then(|v| Some(u64::from_be_bytes(v.as_slice().try_into().unwrap())))
            .unwrap_or(0u64);
        let committed_section = metadata
            .get(&COMMITTED_SECTION.into())
            .and_then(|v| Some(u64::from_be_bytes(v.as_slice().try_into().unwrap())))
            .unwrap_or(0u64);
        let committed_offset = metadata
            .get(&COMMITTED_OFFSET.into())
            .and_then(|v| Some(u32::from_be_bytes(v.as_slice().try_into().unwrap())))
            .unwrap_or(0u32);

        // Initialize variable journal with a separate partition
        let journal_config = JournalConfig {
            partition: config.journal_partition,
            compression: config.journal_compression,
            codec_config: config.codec_config.clone(),
            write_buffer: config.write_buffer,
        };
        let journal = Journal::init(context.clone(), journal_config).await?;

        // Create metrics
        let puts = Counter::default();
        let gets = Counter::default();

        context.register("puts", "number of put operations", puts.clone());
        context.register("gets", "number of get operations", gets.clone());

        let mut diskmap = Self {
            context,
            codec: config.codec_config,
            table_size: config.table_size,
            metadata,
            table,
            journal,
            current_section: committed_section,
            puts,
            gets,
            modified_sections: HashSet::new(),
            pending_table_updates: HashMap::new(),
            _phantom: PhantomData,
        };

        // Zero-out any bucket slots that belong to a future epoch (after an unclean shutdown).
        diskmap.clean_table().await?;

        // Scan table entries and truncate journal to latest reachable entry
        diskmap.truncate_to_latest_reachable_entry().await?;

        Ok(diskmap)
    }

    /// Hash a key to a table index.
    fn hash_key(&self, key: &K) -> u64 {
        let hash = crc32fast::hash(key.as_ref()) as u64;
        hash % self.table_size
    }

    /// Get the journal location (journal_id, offset) for a given table index.
    async fn get_table_entry(&self, table_index: u64) -> Result<(u64, u32), Error> {
        self.table_reads.inc();

        // Check if there's a pending update first
        if let Some(&(_epoch, journal_id, journal_offset)) =
            self.pending_table_updates.get(&table_index)
        {
            return Ok((journal_id, journal_offset));
        }

        let offset = TABLE_HEADER_SIZE as u64 + table_index * TABLE_ENTRY_SIZE as u64;
        let buf = vec![0u8; TABLE_ENTRY_SIZE];
        let read_buf = self.table_blob.read_at(buf, offset).await?;

        // Parse both entries using codec
        let mut buf1 = &read_buf.as_ref()[0..SINGLE_ENTRY_SIZE];
        let mut buf2 = &read_buf.as_ref()[SINGLE_ENTRY_SIZE..TABLE_ENTRY_SIZE];

        let entry1 = TableEntry::read(&mut buf1)?;
        let entry2 = TableEntry::read(&mut buf2)?;

        // Validate CRCs *and* epoch ≤ committed_epoch.
        let expected_crc1 =
            self.calculate_entry_crc(entry1.epoch, entry1.journal_id, entry1.journal_offset);
        let expected_crc2 =
            self.calculate_entry_crc(entry2.epoch, entry2.journal_id, entry2.journal_offset);

        let entry1_valid = entry1.epoch <= self.committed_epoch && entry1.crc == expected_crc1;
        let entry2_valid = entry2.epoch <= self.committed_epoch && entry2.crc == expected_crc2;

        match (entry1_valid, entry2_valid) {
            (true, true) => {
                // Both valid - select the one with the higher epoch
                if entry1.epoch > entry2.epoch {
                    // Entry1 is newer
                    Ok((entry1.journal_id, entry1.journal_offset))
                } else if entry2.epoch > entry1.epoch {
                    // Entry2 references entry1, so entry2 is newer
                    Ok((entry2.journal_id, entry2.journal_offset))
                } else {
                    // Both entries are the same epoch - corruption
                    Err(Error::DirectoryCorrupted)
                }
            }
            (true, false) => {
                // Only entry1 is valid
                Ok((entry1.journal_id, entry1.journal_offset))
            }
            (false, true) => {
                // Only entry2 is valid
                Ok((entry2.journal_id, entry2.journal_offset))
            }
            (false, false) => {
                // Both entries are corrupted or empty
                if entry1.is_empty() && entry2.is_empty() {
                    // Empty entry
                    Ok((0, 0))
                } else {
                    // Corrupted
                    Err(Error::DirectoryCorrupted)
                }
            }
        }
    }

    /// Calculate CRC for the data portion of an entry (journal_id + journal_offset)
    fn calculate_entry_crc(&self, epoch: u64, journal_id: u64, journal_offset: u32) -> u32 {
        let mut data = Vec::with_capacity(20);
        data.extend_from_slice(&epoch.to_le_bytes());
        data.extend_from_slice(&journal_id.to_le_bytes());
        data.extend_from_slice(&journal_offset.to_le_bytes());
        crc32fast::hash(&data)
    }

    /// Choose the newer valid entry between two table slots.
    fn select_valid_entry(
        &self,
        entry1: &TableEntry,
        entry2: &TableEntry,
    ) -> Result<(u64, u32), Error> {
        // Expected CRCs
        let expected_crc1 =
            self.calculate_entry_crc(entry1.epoch, entry1.journal_id, entry1.journal_offset);
        let expected_crc2 =
            self.calculate_entry_crc(entry2.epoch, entry2.journal_id, entry2.journal_offset);

        let entry1_valid = entry1.epoch <= self.committed_epoch && entry1.crc == expected_crc1;
        let entry2_valid = entry2.epoch <= self.committed_epoch && entry2.crc == expected_crc2;

        match (entry1_valid, entry2_valid) {
            (true, true) => {
                if entry1.epoch > entry2.epoch {
                    Ok((entry1.journal_id, entry1.journal_offset))
                } else if entry2.epoch > entry1.epoch {
                    Ok((entry2.journal_id, entry2.journal_offset))
                } else {
                    Err(Error::DirectoryCorrupted)
                }
            }
            (true, false) => Ok((entry1.journal_id, entry1.journal_offset)),
            (false, true) => Ok((entry2.journal_id, entry2.journal_offset)),
            (false, false) => {
                if entry1.is_empty() && entry2.is_empty() {
                    Ok((0, 0))
                } else {
                    Err(Error::DirectoryCorrupted)
                }
            }
        }
    }

    /// Set the journal location for a given table index by storing it in memory for later sync.
    fn set_table_entry(
        &mut self,
        table_index: u64,
        journal_id: u64,
        journal_offset: u32,
    ) -> Result<(), Error> {
        // Store the update in memory for later sync
        let epoch = self.committed_epoch + 1;
        self.pending_table_updates
            .insert(table_index, (epoch, journal_id, journal_offset));
        Ok(())
    }

    /// Write a table entry to disk using atomic dual-entry writes.
    async fn write_table_entry_to_disk(
        &self,
        table_index: u64,
        epoch: u64,
        journal_id: u64,
        journal_offset: u32,
    ) -> Result<(), Error> {
        let offset = TABLE_HEADER_SIZE as u64 + table_index * TABLE_ENTRY_SIZE as u64;

        // Read current entries to determine which slot to update
        let buf = vec![0u8; TABLE_ENTRY_SIZE];
        let read_buf = self.table_blob.read_at(buf, offset).await?;

        // Parse current entries using codec
        let mut buf1 = &read_buf.as_ref()[0..SINGLE_ENTRY_SIZE];
        let mut buf2 = &read_buf.as_ref()[SINGLE_ENTRY_SIZE..TABLE_ENTRY_SIZE];

        let entry1 = TableEntry::read(&mut buf1)?;
        let entry2 = TableEntry::read(&mut buf2)?;

        // Calculate CRCs for new entry
        let new_crc = self.calculate_entry_crc(epoch, journal_id, journal_offset);

        // Determine which slot to update (alternate between them)
        let (update_first, _) = match self.select_valid_entry(&entry1, &entry2) {
            Ok((old_journal_id, old_journal_offset)) => {
                // There's a valid current entry - figure out which slot it's in
                let entry1_matches = entry1.journal_id == old_journal_id
                    && entry1.journal_offset == old_journal_offset;

                let (update_first, old_crc) = if entry1_matches {
                    // Current entry is in slot 1, update slot 2
                    (
                        false,
                        self.calculate_entry_crc(
                            entry1.epoch,
                            entry1.journal_id,
                            entry1.journal_offset,
                        ),
                    )
                } else {
                    // Current entry is in slot 2, update slot 1
                    (
                        true,
                        self.calculate_entry_crc(
                            entry2.epoch,
                            entry2.journal_id,
                            entry2.journal_offset,
                        ),
                    )
                };
                (update_first, old_crc)
            }
            Err(_) => {
                // No valid current entry, use slot 1
                (true, 0)
            }
        };

        // Build the new complete table entry
        let mut new_buf = Vec::with_capacity(TABLE_ENTRY_SIZE);

        if update_first {
            // Update first slot, keep second slot
            let new_entry1 = TableEntry::new(epoch, journal_id, journal_offset, new_crc);
            new_entry1.write(&mut new_buf);
            entry2.write(&mut new_buf);
        } else {
            // Keep first slot, update second slot
            entry1.write(&mut new_buf);
            let new_entry2 = TableEntry::new(epoch, journal_id, journal_offset, new_crc);
            new_entry2.write(&mut new_buf);
        }

        // Write the complete entry
        self.table_blob.write_at(new_buf, offset).await?;

        Ok(())
    }

    /// Determine which journal section to write to based on current journal size.
    async fn determine_journal_section(&mut self, _entry_size: usize) -> Result<u64, Error> {
        // If we have an existing journal, check if it has reached the target size
        if self.current_journal_id > 0 {
            let current_size = self.journal.section_size(self.current_journal_id).await?;

            // Continue using current journal if it hasn't reached target size
            if current_size < self.config.target_journal_size {
                return Ok(self.current_journal_id);
            }
        }

        // Need a new journal (either first write or current has reached target size)
        self.current_journal_id += 1;
        Ok(self.current_journal_id)
    }

    /// Insert a key-value pair into a journal using proper linked list chaining.
    async fn insert_into_journal(
        &mut self,
        table_index: u64,
        key: K,
        value: V,
    ) -> Result<(), Error> {
        // Get current head of the chain from table
        let (current_head_journal_id, current_head_offset) =
            self.get_table_entry(table_index).await?;

        // Create journal entry with proper linked list chaining
        let entry = JournalEntry::new(current_head_journal_id, current_head_offset, key, value);

        // Determine which journal section to write to based on entry size
        let target_journal_id = self.determine_journal_section(entry.encode_size()).await?;

        // Append entry to the variable journal
        let (new_entry_offset, _size) = self.journal.append(target_journal_id, entry).await?;

        // Track that this section has been modified
        self.modified_sections.insert(target_journal_id);

        // Update table to point to this new entry as the head
        self.set_table_entry(table_index, target_journal_id, new_entry_offset)?;

        Ok(())
    }

    /// Put a key-value pair into the disk map.
    pub async fn put(&mut self, key: K, value: V) -> Result<(), Error> {
        self.puts.inc();

        // Hash key to table index
        let table_index = self.hash_key(&key);

        // Insert into journal (this will handle the linked list chaining)
        self.insert_into_journal(table_index, key.clone(), value)
            .await?;

        trace!(
            key = hex(key.as_ref()),
            table_index = table_index,
            "inserted key-value pair"
        );

        Ok(())
    }

    /// Get all values for a given key from the disk map.
    pub async fn get(&mut self, key: &K) -> Result<Vec<V>, Error> {
        self.gets.inc();

        // Hash key to table index
        let table_index = self.hash_key(key);

        // Get head of the chain from table
        let (mut journal_id, mut offset) = self.get_table_entry(table_index).await?;

        if journal_id == 0 {
            return Ok(vec![]); // No entries for this key
        }

        // Follow the linked list chain, collecting values for matching keys
        let mut values = Vec::new();

        loop {
            // Get the entry from the variable journal
            let entry = match self.journal.get(journal_id, offset).await? {
                Some(entry) => entry,
                None => break, // Entry not found, end of chain
            };

            // Check if this key matches
            if entry.key.as_ref() == key.as_ref() {
                values.push(entry.value);
            }

            // Follow the chain
            if entry.next_journal_id == 0 {
                break; // End of chain
            }
            journal_id = entry.next_journal_id;
            offset = entry.next_offset;
        }

        trace!(
            key = hex(key.as_ref()),
            values_found = values.len(),
            "retrieved values for key"
        );

        Ok(values)
    }

    /// Check if a key exists in the disk map.
    pub async fn contains_key(&mut self, key: &K) -> Result<bool, Error> {
        let values = self.get(key).await?;
        Ok(!values.is_empty())
    }

    /// Get the number of table entries.
    pub fn table_size(&self) -> u64 {
        self.table_size
    }

    /// Sync all data to the underlying store.
    /// First syncs all journal sections, then flushes pending table updates, and finally syncs the table.
    pub async fn sync(&mut self) -> Result<(), Error> {
        // First sync all modified journal sections
        for &section in &self.modified_sections {
            self.journal.sync(section).await?;
        }

        // Clear the modified sections since they're now synced
        self.modified_sections.clear();

        let mut max_journal = self.committed_journal_id;
        let mut max_offset = self.committed_offset;

        let mut updates = Vec::with_capacity(self.pending_table_updates.len());
        for (&table_index, &(epoch, journal_id, journal_offset)) in &self.pending_table_updates {
            updates.push(self.write_table_entry_to_disk(
                table_index,
                epoch,
                journal_id,
                journal_offset,
            ));

            if journal_id > max_journal
                || (journal_id == max_journal && journal_offset > max_offset)
            {
                max_journal = journal_id;
                max_offset = journal_offset;
            }
        }
        try_join_all(updates).await?;

        // Flush table blob (buckets)
        self.table_blob.sync().await?;

        // ------------------------------------------------------------------
        // Update commit header (epoch advance) – write to alternate slot
        // ------------------------------------------------------------------
        let new_epoch = self.committed_epoch + 1;
        let header_slot = HeaderSlot::new(new_epoch, max_journal, max_offset);
        let mut hdr_buf = Vec::with_capacity(HEADER_SLOT_SIZE);
        header_slot.write(&mut hdr_buf);

        let next_cursor = 1 - self.header_cursor;
        let hdr_offset = (next_cursor * HEADER_SLOT_SIZE) as u64;
        self.table_blob.write_at(hdr_buf, hdr_offset).await?;
        self.table_blob.sync().await?;

        self.committed_epoch = new_epoch;
        self.committed_journal_id = max_journal;
        self.committed_offset = max_offset;
        self.header_cursor = next_cursor;

        self.pending_table_updates.clear();

        Ok(())
    }

    /// Close the disk map and underlying journal.
    pub async fn close(mut self) -> Result<(), Error> {
        // Sync any pending updates before closing
        self.sync().await?;

        self.journal.close().await?;
        self.table_blob.close().await?;
        Ok(())
    }

    /// Truncates journal sections to the last committed high-water mark from the table header.
    async fn truncate_to_latest_reachable_entry(&mut self) -> Result<(), Error> {
        trace!(
            committed_journal_id = self.committed_journal_id,
            committed_offset = self.committed_offset,
            "truncating journal to last committed state via journal::truncate_section"
        );

        // Delegate truncation/rollback logic to the journal itself.
        self.journal
            .truncate_section(self.committed_journal_id, self.committed_offset)
            .await?;

        Ok(())
    }

    /// Validates the integrity of the hash table by checking that all table entries
    /// point to valid journal entries. This is optional and mainly useful for debugging.
    pub async fn validate_table_integrity(&self) -> Result<usize, Error> {
        let mut valid_entries = 0;
        let mut invalid_entries = 0;

        for table_index in 0..self.table_size {
            let (journal_id, journal_offset) = self.get_table_entry(table_index).await?;

            // Skip empty table entries
            if journal_id == 0 && journal_offset == 0 {
                continue;
            }

            // Check if the journal entry exists
            match self.journal.get(journal_id, journal_offset).await {
                Ok(Some(_)) => valid_entries += 1,
                Ok(None) => {
                    invalid_entries += 1;
                    trace!(
                        table_index,
                        journal_id,
                        journal_offset,
                        "table entry points to non-existent journal entry"
                    );
                }
                Err(err) => {
                    invalid_entries += 1;
                    trace!(
                        table_index,
                        journal_id,
                        journal_offset,
                        ?err,
                        "error accessing journal entry from table"
                    );
                }
            }
        }

        trace!(
            valid_entries,
            invalid_entries,
            "table integrity validation complete"
        );

        Ok(valid_entries)
    }

    /// Close and remove any underlying blobs created by the disk map.
    pub async fn destroy(self) -> Result<(), Error> {
        // Destroy the journal (removes all journal sections)
        self.journal.destroy().await?;

        // Close and remove the table blob
        self.table_blob.close().await?;
        self.context
            .remove(&self.config.partition, Some(TABLE_BLOB_NAME))
            .await?;

        // Remove the partition itself
        self.context.remove(&self.config.partition, None).await?;

        Ok(())
    }

    /// Remove bucket slots whose epoch is greater than the committed epoch.
    async fn clean_table(&mut self) -> Result<(), Error> {
        // Determine last allowed epoch
        let committed_epoch = self
            .metadata
            .get(&COMMITTED_EPOCH.into())
            .and_then(|v| Some(u64::from_be_bytes(v.as_slice().try_into().unwrap())))
            .unwrap_or(0u64);

        // Zero out any table entries whose epoch is greater than the committed epoch
        let mut sync = false;
        let zero_buf = vec![0u8; TABLE_ENTRY_SIZE];
        for table_index in 0..self.table_size {
            let offset = table_index * FULL_TABLE_ENTRY_SIZE as u64;
            let result = self
                .table
                .read_at(vec![0u8; TABLE_ENTRY_SIZE], offset)
                .await?;

            let mut buf1 = &result.as_ref()[0..TABLE_ENTRY_SIZE];
            let entry1 = TableEntry::read(&mut buf1)?;
            if entry1.epoch > committed_epoch {
                self.table.write_at(zero_buf.clone(), offset).await?;
                sync = true;
            }

            let mut buf2 = &result.as_ref()[TABLE_ENTRY_SIZE..FULL_TABLE_ENTRY_SIZE];
            let entry2 = TableEntry::read(&mut buf2)?;
            if entry2.epoch > committed_epoch {
                self.table
                    .write_at(zero_buf.clone(), offset + TABLE_ENTRY_SIZE as u64)
                    .await?;
                sync = true;
            }
        }

        // Sync the table if any changes were made
        if sync {
            self.table.sync().await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_runtime::{deterministic, Runner};
    use commonware_utils::array::FixedBytes;

    type TestKey = FixedBytes<8>;
    type TestValue = FixedBytes<16>;

    #[test]
    fn test_diskmap_basic_operations() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let config = Config {
                partition: "test".to_string(),
                directory_size: 256,
                codec_config: (),
                write_buffer: 1024,
                target_journal_size: 64 * 1024 * 1024, // 64MB
            };

            let mut diskmap = DiskMap::<_, TestKey, TestValue>::init(context, config)
                .await
                .unwrap();

            // Test put and get
            let key = TestKey::new(*b"testkey1");
            let value = TestValue::new(*b"testvalue1234567");

            diskmap.put(key.clone(), value.clone()).await.unwrap();
            let values = diskmap.get(&key).await.unwrap();

            assert_eq!(values.len(), 1);
            assert_eq!(values[0], value);

            // Test multiple values for same key
            let value2 = TestValue::new(*b"testvalue7654321");
            diskmap.put(key.clone(), value2.clone()).await.unwrap();
            let values = diskmap.get(&key).await.unwrap();

            assert_eq!(values.len(), 2);
            assert!(values.contains(&value));
            assert!(values.contains(&value2));

            // Test contains_key
            assert!(diskmap.contains_key(&key).await.unwrap());
            let nonexist_key = TestKey::new(*b"nonexist");
            assert!(!diskmap.contains_key(&nonexist_key).await.unwrap());

            // Clean up the diskmap
            diskmap.destroy().await.unwrap();
        });
    }

    #[test]
    fn test_diskmap_type_safety() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let config = Config {
                partition: "test_type_safety".to_string(),
                directory_size: 256,
                codec_config: (),
                write_buffer: 1024,
                target_journal_size: 64 * 1024 * 1024, // 64MB
            };

            let mut diskmap = DiskMap::<_, TestKey, TestValue>::init(context, config)
                .await
                .unwrap();

            // Test basic type safety - this should compile and work
            let key = TestKey::new(*b"testkey1");
            let value = TestValue::new(*b"testvalue1234567");

            diskmap.put(key.clone(), value.clone()).await.unwrap();
            let values = diskmap.get(&key).await.unwrap();

            assert_eq!(values.len(), 1);
            assert_eq!(values[0], value);

            // Clean up the diskmap
            diskmap.destroy().await.unwrap();
        });
    }

    #[test]
    fn test_diskmap_journal_initialization() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // First, create a diskmap and add some data
            {
                let config = Config {
                    partition: "test_restart".to_string(),
                    directory_size: 256,
                    codec_config: (),
                    write_buffer: 1024,
                    target_journal_size: 64 * 1024 * 1024, // 64MB
                };

                let mut diskmap = DiskMap::<_, TestKey, TestValue>::init(context.clone(), config)
                    .await
                    .unwrap();

                // Add some data that should go to journal 1
                let key1 = TestKey::new(*b"testkey1");
                let value1 = TestValue::new(*b"testvalue1234567");
                diskmap.put(key1.clone(), value1.clone()).await.unwrap();

                let key2 = TestKey::new(*b"testkey2");
                let value2 = TestValue::new(*b"testvalue7654321");
                diskmap.put(key2.clone(), value2.clone()).await.unwrap();

                // Verify data is retrievable
                let values1 = diskmap.get(&key1).await.unwrap();
                assert_eq!(values1.len(), 1);
                assert_eq!(values1[0], value1);

                diskmap.close().await.unwrap();
            }

            // Now restart and verify it finds the existing journal
            {
                let config = Config {
                    partition: "test_restart".to_string(),
                    directory_size: 256,
                    codec_config: (),
                    write_buffer: 1024,
                    target_journal_size: 64 * 1024 * 1024, // 64MB
                };

                let mut diskmap = DiskMap::<_, TestKey, TestValue>::init(context.clone(), config)
                    .await
                    .unwrap();

                // Verify existing data is still accessible
                let key1 = TestKey::new(*b"testkey1");
                let value1 = TestValue::new(*b"testvalue1234567");
                let values1 = diskmap.get(&key1).await.unwrap();
                assert_eq!(values1.len(), 1);
                assert_eq!(values1[0], value1);

                // Add more data - should continue in the same journal if there's space
                let key3 = TestKey::new(*b"testkey3");
                let value3 = TestValue::new(*b"testvalue3333333");
                diskmap.put(key3.clone(), value3.clone()).await.unwrap();

                let values3 = diskmap.get(&key3).await.unwrap();
                assert_eq!(values3.len(), 1);
                assert_eq!(values3[0], value3);

                diskmap.close().await.unwrap();
            }
        });
    }

    #[test]
    fn test_diskmap_sync() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let config = Config {
                partition: "test_sync".to_string(),
                directory_size: 256,
                codec_config: (),
                write_buffer: 1024,
                target_journal_size: 64 * 1024 * 1024, // 64MB
            };

            let mut diskmap = DiskMap::<_, TestKey, TestValue>::init(context, config)
                .await
                .unwrap();

            // Add some data
            let key1 = TestKey::new(*b"testkey1");
            let value1 = TestValue::new(*b"testvalue1234567");
            diskmap.put(key1.clone(), value1.clone()).await.unwrap();

            let key2 = TestKey::new(*b"testkey2");
            let value2 = TestValue::new(*b"testvalue7654321");
            diskmap.put(key2.clone(), value2.clone()).await.unwrap();

            // Test sync - should not error and should force data to storage
            diskmap.sync().await.unwrap();

            // Verify data is still retrievable after sync
            let values1 = diskmap.get(&key1).await.unwrap();
            assert_eq!(values1.len(), 1);
            assert_eq!(values1[0], value1);

            let values2 = diskmap.get(&key2).await.unwrap();
            assert_eq!(values2.len(), 1);
            assert_eq!(values2[0], value2);

            // Test that sync can be called multiple times (should be no-op after first sync)
            diskmap.sync().await.unwrap();

            diskmap.close().await.unwrap();
        });
    }

    #[test]
    fn test_diskmap_sync_efficiency() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let config = Config {
                partition: "test_sync_efficiency".to_string(),
                directory_size: 256,
                codec_config: (),
                write_buffer: 1024,
                target_journal_size: 64 * 1024 * 1024, // 64MB
            };

            let mut diskmap = DiskMap::<_, TestKey, TestValue>::init(context, config)
                .await
                .unwrap();

            // Initially, no sections should be modified and no pending table updates
            assert!(diskmap.modified_sections.is_empty());
            assert!(diskmap.pending_table_updates.is_empty());

            // Add some data - should track that a section was modified and a table update is pending
            let key1 = TestKey::new(*b"testkey1");
            let value1 = TestValue::new(*b"testvalue1234567");
            diskmap.put(key1.clone(), value1.clone()).await.unwrap();

            // Should have one modified section and one pending table update now
            assert_eq!(diskmap.modified_sections.len(), 1);
            assert_eq!(diskmap.pending_table_updates.len(), 1);

            // Add more data to same hash bucket - should still be same section but might be more table updates
            let key2 = TestKey::new(*b"testkey2");
            let value2 = TestValue::new(*b"testvalue7654321");
            diskmap.put(key2.clone(), value2.clone()).await.unwrap();

            // Should still have at most one section (might be the same section) and possibly more table updates
            assert!(!diskmap.modified_sections.is_empty());
            assert!(!diskmap.pending_table_updates.is_empty());

            // After sync, modified sections and pending table updates should be cleared
            diskmap.sync().await.unwrap();
            assert!(diskmap.modified_sections.is_empty());
            assert!(diskmap.pending_table_updates.is_empty());

            // Add more data after sync - should track new modifications
            let key3 = TestKey::new(*b"testkey3");
            let value3 = TestValue::new(*b"testvalue3333333");
            diskmap.put(key3.clone(), value3.clone()).await.unwrap();

            // Should have modified sections and pending table updates again
            assert!(!diskmap.modified_sections.is_empty());
            assert!(!diskmap.pending_table_updates.is_empty());

            diskmap.close().await.unwrap();
        });
    }

    #[test]
    fn test_diskmap_initialization_validation() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let config = Config {
                partition: "test_init_validation".to_string(),
                directory_size: 256,
                codec_config: (),
                write_buffer: 1024,
                target_journal_size: 64 * 1024 * 1024, // 64MB
            };

            // Create initial diskmap and add some data
            {
                let mut diskmap =
                    DiskMap::<_, TestKey, TestValue>::init(context.clone(), config.clone())
                        .await
                        .unwrap();

                // Add data that will create linked lists (same hash bucket)
                let key1 = TestKey::new(*b"key00001");
                let value1 = TestValue::new(*b"value00000000001");
                diskmap.put(key1.clone(), value1.clone()).await.unwrap();

                let key2 = TestKey::new(*b"key00002");
                let value2 = TestValue::new(*b"value00000000002");
                diskmap.put(key2.clone(), value2.clone()).await.unwrap();

                // Verify data is accessible
                let values1 = diskmap.get(&key1).await.unwrap();
                assert_eq!(values1.len(), 1);
                assert_eq!(values1[0], value1);

                let values2 = diskmap.get(&key2).await.unwrap();
                assert_eq!(values2.len(), 1);
                assert_eq!(values2[0], value2);

                diskmap.sync().await.unwrap();
                diskmap.close().await.unwrap();
            }

            // Re-initialize and verify the initialization validation works
            {
                let diskmap =
                    DiskMap::<_, TestKey, TestValue>::init(context.clone(), config.clone())
                        .await
                        .unwrap();

                // The initialization should have scanned all table entries and validated reachability
                // If we got here without error, the validation passed

                // Verify the data is still accessible after reinitialization
                let key1 = TestKey::new(*b"key00001");
                let value1 = TestValue::new(*b"value00000000001");
                let mut diskmap = diskmap; // Make mutable for get operations
                let values1 = diskmap.get(&key1).await.unwrap();
                assert_eq!(values1.len(), 1);
                assert_eq!(values1[0], value1);

                let key2 = TestKey::new(*b"key00002");
                let value2 = TestValue::new(*b"value00000000002");
                let values2 = diskmap.get(&key2).await.unwrap();
                assert_eq!(values2.len(), 1);
                assert_eq!(values2[0], value2);

                diskmap.destroy().await.unwrap();
            }
        });
    }
}
