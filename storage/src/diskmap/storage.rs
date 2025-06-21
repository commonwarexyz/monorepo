use super::{Config, Error};
use crate::journal::variable::{Config as JournalConfig, Journal};
use bytes::{Buf, BufMut};
use commonware_codec::{Codec, EncodeSize, FixedSize, Read, ReadExt, Write as CodecWrite};
use commonware_runtime::{Blob, Metrics, Storage};
use commonware_utils::{hex, Array};
use futures::future::try_join_all;
use prometheus_client::metrics::counter::Counter;
use std::collections::{HashMap, HashSet};
use std::marker::PhantomData;
use tracing::trace;

const TABLE_BLOB_NAME: &[u8] = b"table";

// -------------------------------------------------------------------------------------------------
// Table layout
// -------------------------------------------------------------------------------------------------
// The very first bytes of the table blob form a fixed-size header that acts as a durable commit
// pointer.  The rest of the blob contains the actual bucket slots (two per bucket as before).
//
// Header (24 bytes):
//   u64 committed_epoch      – highest epoch that is *fully* flushed to disk
//   u64 max_journal_id       – greatest journal-section id referenced by any bucket of that epoch
//   u32 max_offset           – greatest offset inside that journal section
//   u32 crc                  – CRC32 of the first 20 bytes
//
// Bucket slot (28 bytes):
//   u64 epoch                – epoch in which this slot was written
//   u64 journal_id
//   u32 journal_offset
//   u32 crc                  – CRC of (epoch | journal_id | journal_offset)
//   u32 other_crc            – CRC of the sibling slot (for atomic toggle)

/// Size of a single commit-pointer header slot.
const HEADER_SLOT_SIZE: usize = 24;
/// Total header region (two header slots).
const TABLE_HEADER_SIZE: usize = HEADER_SLOT_SIZE * 2;

/// Two slots per bucket, each slot now 28 bytes.
const SINGLE_ENTRY_SIZE: usize = 28;
const TABLE_ENTRY_SIZE: usize = 2 * SINGLE_ENTRY_SIZE;

// -------------------------------------------------------------------------------------------------
// Commit pointer header (duplicated)
// -------------------------------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
struct HeaderSlot {
    epoch: u64,
    max_journal_id: u64,
    max_offset: u32,
    crc: u32,
}

impl FixedSize for HeaderSlot {
    const SIZE: usize = HEADER_SLOT_SIZE;
}

impl CodecWrite for HeaderSlot {
    fn write(&self, buf: &mut impl BufMut) {
        buf.put_slice(&self.epoch.to_le_bytes());
        buf.put_slice(&self.max_journal_id.to_le_bytes());
        buf.put_slice(&self.max_offset.to_le_bytes());
        buf.put_slice(&self.crc.to_le_bytes());
    }
}

impl Read for HeaderSlot {
    type Cfg = ();
    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        let mut epoch_bytes = [0u8; 8];
        buf.copy_to_slice(&mut epoch_bytes);
        let epoch = u64::from_le_bytes(epoch_bytes);

        let mut jid_bytes = [0u8; 8];
        buf.copy_to_slice(&mut jid_bytes);
        let max_journal_id = u64::from_le_bytes(jid_bytes);

        let mut off_bytes = [0u8; 4];
        buf.copy_to_slice(&mut off_bytes);
        let max_offset = u32::from_le_bytes(off_bytes);

        let mut crc_bytes = [0u8; 4];
        buf.copy_to_slice(&mut crc_bytes);
        let crc = u32::from_le_bytes(crc_bytes);

        Ok(Self {
            epoch,
            max_journal_id,
            max_offset,
            crc,
        })
    }
}

impl HeaderSlot {
    fn calc_crc(epoch: u64, jid: u64, off: u32) -> u32 {
        let mut data = Vec::with_capacity(20);
        data.extend_from_slice(&epoch.to_le_bytes());
        data.extend_from_slice(&jid.to_le_bytes());
        data.extend_from_slice(&off.to_le_bytes());
        crc32fast::hash(&data)
    }

    fn new(epoch: u64, jid: u64, off: u32) -> Self {
        let crc = Self::calc_crc(epoch, jid, off);
        Self {
            epoch,
            max_journal_id: jid,
            max_offset: off,
            crc,
        }
    }

    fn is_valid(&self) -> bool {
        self.crc == Self::calc_crc(self.epoch, self.max_journal_id, self.max_offset)
    }
}

/// Single table entry stored in the table blob.
#[derive(Debug, Clone, PartialEq)]
struct TableEntry {
    epoch: u64,
    journal_id: u64,
    journal_offset: u32,
    crc: u32,
    other_crc: u32,
}

impl TableEntry {
    /// Create a new `TableEntry`.
    fn new(epoch: u64, journal_id: u64, journal_offset: u32, crc: u32, other_crc: u32) -> Self {
        Self {
            epoch,
            journal_id,
            journal_offset,
            crc,
            other_crc,
        }
    }

    /// Check if this entry is empty (all zeros).
    fn is_empty(&self) -> bool {
        self.journal_id == 0 && self.journal_offset == 0 && self.crc == 0 && self.other_crc == 0
    }
}

impl FixedSize for TableEntry {
    const SIZE: usize = SINGLE_ENTRY_SIZE;
}

impl CodecWrite for TableEntry {
    fn write(&self, buf: &mut impl BufMut) {
        buf.put_slice(&self.epoch.to_le_bytes());
        buf.put_slice(&self.journal_id.to_le_bytes());
        buf.put_slice(&self.journal_offset.to_le_bytes());
        buf.put_slice(&self.crc.to_le_bytes());
        buf.put_slice(&self.other_crc.to_le_bytes());
    }
}

impl Read for TableEntry {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _cfg: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        let mut epoch_bytes = [0u8; 8];
        buf.copy_to_slice(&mut epoch_bytes);
        let epoch = u64::from_le_bytes(epoch_bytes);

        let mut journal_id_bytes = [0u8; 8];
        buf.copy_to_slice(&mut journal_id_bytes);
        let journal_id = u64::from_le_bytes(journal_id_bytes);

        let mut journal_offset_bytes = [0u8; 4];
        buf.copy_to_slice(&mut journal_offset_bytes);
        let journal_offset = u32::from_le_bytes(journal_offset_bytes);

        let mut crc_bytes = [0u8; 4];
        buf.copy_to_slice(&mut crc_bytes);
        let crc = u32::from_le_bytes(crc_bytes);

        let mut other_crc_bytes = [0u8; 4];
        buf.copy_to_slice(&mut other_crc_bytes);
        let other_crc = u32::from_le_bytes(other_crc_bytes);

        Ok(Self {
            epoch,
            journal_id,
            journal_offset,
            crc,
            other_crc,
        })
    }
}

/// Record stored in the journal for linked list entries.
struct JournalEntry<K: Array, V: Codec> {
    next_journal_id: u64,
    next_offset: u32, // Changed to u32 to match variable journal offsets
    key: K,
    value: V,
}

impl<K: Array, V: Codec> JournalEntry<K, V> {
    /// Create a new `JournalEntry`.
    fn new(next_journal_id: u64, next_offset: u32, key: K, value: V) -> Self {
        Self {
            next_journal_id,
            next_offset,
            key,
            value,
        }
    }
}

impl<K: Array, V: Codec> CodecWrite for JournalEntry<K, V> {
    fn write(&self, buf: &mut impl BufMut) {
        buf.put_slice(&self.next_journal_id.to_le_bytes());
        buf.put_slice(&self.next_offset.to_le_bytes());
        self.key.write(buf);
        // Write value size first, then the value
        let value_size = self.value.encode_size() as u32;
        buf.put_slice(&value_size.to_le_bytes());
        self.value.write(buf);
    }
}

impl<K: Array, V: Codec> Read for JournalEntry<K, V> {
    type Cfg = V::Cfg;

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        let mut next_journal_id_bytes = [0u8; 8];
        buf.copy_to_slice(&mut next_journal_id_bytes);
        let next_journal_id = u64::from_le_bytes(next_journal_id_bytes);

        let mut next_offset_bytes = [0u8; 4]; // Changed to 4 bytes
        buf.copy_to_slice(&mut next_offset_bytes);
        let next_offset = u32::from_le_bytes(next_offset_bytes);

        let key = K::read(buf)?;

        // Read value size first
        let mut value_size_bytes = [0u8; 4];
        buf.copy_to_slice(&mut value_size_bytes);
        let _value_size = u32::from_le_bytes(value_size_bytes);

        let value = V::read_cfg(buf, cfg)?;

        Ok(Self {
            next_journal_id,
            next_offset,
            key,
            value,
        })
    }
}

impl<K: Array, V: Codec> EncodeSize for JournalEntry<K, V> {
    fn encode_size(&self) -> usize {
        8 + 4 + K::SIZE + 4 + self.value.encode_size() // Changed to 4 bytes for next_offset
    }
}

/// Implementation of `DiskMap` storage.
pub struct DiskMap<E: Storage + Metrics, K: Array, V: Codec> {
    // Context for storage operations
    context: E,

    // Configuration
    config: Config<V::Cfg>,

    // Table blob that maps hash values to journal locations (journal_id, offset)
    table_blob: E::Blob,
    table_size: u64, // Number of table entries

    // Variable journal for storing entries
    journal: Journal<E, JournalEntry<K, V>>,

    // Current journal for new writes
    current_journal_id: u64,

    // Phantom data to satisfy the compiler about generic types
    _phantom: PhantomData<(K, V)>,

    // Metrics
    puts: Counter,
    gets: Counter,
    table_reads: Counter,

    // Track modified journal sections
    modified_sections: HashSet<u64>,

    // Pending table updates to be written on sync (table_index -> (journal_id, journal_offset))
    pending_table_updates: HashMap<
        u64,
        (
            u64, /*epoch*/
            u64, /*journal_id*/
            u32, /*offset*/
        ),
    >,

    // Durability pointer (populated at init and advanced on every sync)
    committed_epoch: u64,
    committed_journal_id: u64,
    committed_offset: u32,

    // which header slot is current (0 or 1)
    header_cursor: usize,
}

impl<E: Storage + Metrics, K: Array, V: Codec> DiskMap<E, K, V> {
    /// Initialize a new `DiskMap` instance.
    pub async fn init(context: E, config: Config<V::Cfg>) -> Result<Self, Error> {
        // Validate configuration
        if config.directory_size == 0 || !config.directory_size.is_power_of_two() {
            return Err(Error::DirectoryCorrupted);
        }

        // Calculate table size based on configuration
        let table_size = config.directory_size;

        // Open table blob (includes header)
        let (table_blob, table_len) = context.open(&config.partition, TABLE_BLOB_NAME).await?;

        // If the blob is brand new, create header + zeroed buckets.
        if table_len == 0 {
            // header
            table_blob.write_at(vec![0u8; TABLE_HEADER_SIZE], 0).await?;
            // buckets
            let table_data_size = table_size * TABLE_ENTRY_SIZE as u64;
            let table_data = vec![0u8; table_data_size as usize];
            table_blob
                .write_at(table_data, TABLE_HEADER_SIZE as u64)
                .await?;
            table_blob.sync().await?;
        }

        // ------------------------------------------------------------------
        // Load commit pointer (two-header scheme)
        // ------------------------------------------------------------------
        let hdr_buf = table_blob.read_at(vec![0u8; TABLE_HEADER_SIZE], 0).await?;

        let mut hdr_slice1 = &hdr_buf.as_ref()[0..HEADER_SLOT_SIZE];
        let mut hdr_slice2 = &hdr_buf.as_ref()[HEADER_SLOT_SIZE..TABLE_HEADER_SIZE];

        let h1 = HeaderSlot::read(&mut hdr_slice1).unwrap();
        let h2 = HeaderSlot::read(&mut hdr_slice2).unwrap();

        let h1_valid = h1.is_valid();
        let h2_valid = h2.is_valid();

        let (committed_epoch, committed_journal_id, committed_offset, header_cursor) =
            match (h1_valid, h2_valid) {
                (true, true) => {
                    if h2.epoch > h1.epoch {
                        (h2.epoch, h2.max_journal_id, h2.max_offset, 1)
                    } else {
                        (h1.epoch, h1.max_journal_id, h1.max_offset, 0)
                    }
                }
                (true, false) => (h1.epoch, h1.max_journal_id, h1.max_offset, 0),
                (false, true) => (h2.epoch, h2.max_journal_id, h2.max_offset, 1),
                (false, false) => {
                    trace!("both header slots invalid – starting at epoch 0");
                    (0, 0, 0, 0)
                }
            };

        // Initialize variable journal with a separate partition
        let journal_partition = format!("{}_journal", config.partition);
        let journal_config = JournalConfig {
            partition: journal_partition,
            compression: None, // Can be configurable if needed
            codec_config: config.codec_config.clone(),
            write_buffer: config.write_buffer,
        };
        let journal = Journal::init(context.clone(), journal_config).await?;

        // Find the current journal ID from existing journals
        let current_journal_id = journal.max_section_id().unwrap_or(0);

        // Create metrics
        let puts = Counter::default();
        let gets = Counter::default();
        let table_reads = Counter::default();

        context.register("puts", "number of put operations", puts.clone());
        context.register("gets", "number of get operations", gets.clone());
        context.register("table_reads", "number of table reads", table_reads.clone());

        // Initialize modified sections set
        let modified_sections = HashSet::new();

        // Initialize pending table updates
        let pending_table_updates = HashMap::new();

        let mut diskmap = Self {
            context,
            config,
            table_blob,
            table_size,
            journal,
            current_journal_id,
            _phantom: PhantomData,
            puts,
            gets,
            table_reads,
            modified_sections,
            pending_table_updates,
            committed_epoch,
            committed_journal_id,
            committed_offset,
            header_cursor,
        };

        // Zero-out any bucket slots that belong to a future epoch (after an unclean shutdown).
        diskmap.clean_future_epochs().await?;

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
                // Both valid - select the one that references the other's CRC
                if entry1.other_crc == expected_crc2 {
                    // Entry1 references entry2, so entry1 is newer
                    Ok((entry1.journal_id, entry1.journal_offset))
                } else if entry2.other_crc == expected_crc1 {
                    // Entry2 references entry1, so entry2 is newer
                    Ok((entry2.journal_id, entry2.journal_offset))
                } else {
                    // Neither references the other correctly - corruption
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
                if entry1.other_crc == expected_crc2 {
                    Ok((entry1.journal_id, entry1.journal_offset))
                } else if entry2.other_crc == expected_crc1 {
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
        let (update_first, old_crc) = match self.select_valid_entry(&entry1, &entry2) {
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
            let new_entry1 = TableEntry::new(epoch, journal_id, journal_offset, new_crc, old_crc);
            new_entry1.write(&mut new_buf);
            entry2.write(&mut new_buf);
        } else {
            // Keep first slot, update second slot
            entry1.write(&mut new_buf);
            let new_entry2 = TableEntry::new(epoch, journal_id, journal_offset, new_crc, old_crc);
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

    /// Returns a stream of all key-value pairs in the disk map.
    ///
    /// This function uses the journal's efficient replay mechanism to stream through
    /// all entries. This is much faster than following linked lists manually as it
    /// uses buffered reading.
    pub async fn replay(
        &self,
        buffer: usize,
    ) -> Result<impl futures::Stream<Item = Result<(K, V), Error>> + '_, Error> {
        use futures::StreamExt;

        trace!("starting diskmap replay using journal replay");

        // Use the journal's efficient replay to get all entries
        let journal_stream = self.journal.replay(buffer).await?;

        // Transform the journal entries to key-value pairs
        Ok(journal_stream.map(|result| match result {
            Ok((_, _, _, entry)) => Ok((entry.key, entry.value)),
            Err(err) => Err(Error::Journal(err)),
        }))
    }

    /// Truncates journal sections to the last committed high-water mark from the table header.
    async fn truncate_to_latest_reachable_entry(&mut self) -> Result<(), Error> {
        trace!(
            committed_journal_id = self.committed_journal_id,
            committed_offset = self.committed_offset,
            "truncating journal to last committed state"
        );

        // If there is no committed section, we are done (nothing to truncate).
        if self.committed_journal_id == 0 {
            return Ok(());
        }

        let section_id = self.committed_journal_id;
        let committed_offset = self.committed_offset;

        // If committed offset is 0, it means no entries are committed in this section.
        // The first entry in a variable journal starts at offset 1 (16 bytes), so truncating
        // to offset 1 effectively clears it to just its header.
        if committed_offset == 0 {
            trace!(
                section_id,
                "truncating journal section with no committed entries to header"
            );
            self.journal.truncate_section(section_id, 1).await?;
            return Ok(());
        }

        // Otherwise, find the end of the last committed entry and truncate after it.
        match self.journal.get(section_id, committed_offset).await {
            Ok(Some(entry)) => {
                let current_size = self.journal.section_size(section_id).await?;

                // Each entry is: size(4) + data(variable) + crc(4), then aligned to 16 bytes.
                let data_size = entry.encode_size() as u64;
                let size_on_disk = 4 + data_size + 4;
                let aligned_size = (size_on_disk + 15) & !15;
                let new_size_in_bytes = (committed_offset as u64 * 16) + aligned_size;

                if new_size_in_bytes < current_size {
                    let new_offset = (new_size_in_bytes / 16) as u32;
                    trace!(
                        section_id,
                        current_size,
                        new_size_in_bytes,
                        "truncating journal section to remove partial writes"
                    );
                    self.journal
                        .truncate_section(section_id, new_offset)
                        .await?;
                }
            }
            Ok(None) => {
                trace!(
                    section_id,
                    committed_offset,
                    "commit pointer refers to non-existent journal entry; truncating section"
                );
                self.journal.truncate_section(section_id, 1).await?;
            }
            Err(e) => {
                trace!(
                    section_id,
                    committed_offset,
                    error = ?e,
                    "error reading committed journal entry; truncating section"
                );
                self.journal.truncate_section(section_id, 1).await?;
            }
        }

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
    async fn clean_future_epochs(&mut self) -> Result<(), Error> {
        let mut zero_buf = vec![0u8; SINGLE_ENTRY_SIZE];
        let buckets = self.table_size;
        for table_index in 0..buckets {
            let offset = TABLE_HEADER_SIZE as u64 + table_index * TABLE_ENTRY_SIZE as u64;
            let buf = self
                .table_blob
                .read_at(vec![0u8; TABLE_ENTRY_SIZE], offset)
                .await?;

            let mut buf1 = &buf.as_ref()[0..SINGLE_ENTRY_SIZE];
            let mut buf2 = &buf.as_ref()[SINGLE_ENTRY_SIZE..TABLE_ENTRY_SIZE];
            let entry1 = TableEntry::read(&mut buf1)?;
            let entry2 = TableEntry::read(&mut buf2)?;

            let mut need_write = false;
            let mut new_buf = Vec::with_capacity(TABLE_ENTRY_SIZE);

            for entry in [&entry1, &entry2] {
                if entry.epoch > self.committed_epoch {
                    new_buf.extend_from_slice(&zero_buf);
                    need_write = true;
                } else {
                    entry.write(&mut new_buf);
                }
            }

            if need_write {
                self.table_blob.write_at(new_buf, offset).await?;
            }
        }
        if buckets > 0 {
            self.table_blob.sync().await?;
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
    fn test_diskmap_replay() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let config = Config {
                partition: "test_replay".to_string(),
                directory_size: 256,
                codec_config: (),
                write_buffer: 1024,
                target_journal_size: 64 * 1024 * 1024, // 64MB
            };

            let mut diskmap =
                DiskMap::<_, TestKey, TestValue>::init(context.clone(), config.clone())
                    .await
                    .unwrap();

            // Add some test data
            let test_data = vec![
                (
                    TestKey::new(*b"key00001"),
                    TestValue::new(*b"value00000000001"),
                ),
                (
                    TestKey::new(*b"key00002"),
                    TestValue::new(*b"value00000000002"),
                ),
                (
                    TestKey::new(*b"key00003"),
                    TestValue::new(*b"value00000000003"),
                ),
            ];

            for (key, value) in &test_data {
                diskmap.put(key.clone(), value.clone()).await.unwrap();
            }

            // Validate table integrity before sync
            let valid_entries = diskmap.validate_table_integrity().await.unwrap();
            assert_eq!(valid_entries, test_data.len());

            // Sync to ensure data is persisted
            diskmap.sync().await.unwrap();
            diskmap.close().await.unwrap();

            // Re-initialize diskmap
            let diskmap = DiskMap::<_, TestKey, TestValue>::init(context, config)
                .await
                .unwrap();

            // Validate table integrity after restart
            let valid_entries = diskmap.validate_table_integrity().await.unwrap();
            assert_eq!(valid_entries, test_data.len());

            // Replay all items using efficient journal replay
            use futures::StreamExt;
            let mut replayed_items = Vec::new();
            {
                let stream = diskmap.replay(1024).await.unwrap();
                let mut stream = Box::pin(stream);

                while let Some(result) = stream.next().await {
                    let (key, value) = result.unwrap();
                    replayed_items.push((key, value));
                }
            } // stream is dropped here

            // Verify we got all the items back (order might be different due to hashing)
            assert_eq!(replayed_items.len(), test_data.len());

            // Check that all test data is present in replayed items
            for (expected_key, expected_value) in &test_data {
                assert!(replayed_items
                    .iter()
                    .any(|(k, v)| k == expected_key && v == expected_value));
            }

            diskmap.destroy().await.unwrap();
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

                // Test replay functionality - should return both entries
                use futures::StreamExt;
                let mut replayed_items = Vec::new();
                {
                    let stream = diskmap.replay(1024).await.unwrap();
                    let mut stream = Box::pin(stream);

                    while let Some(result) = stream.next().await {
                        let (key, value) = result.unwrap();
                        replayed_items.push((key, value));
                    }
                }

                // Should have replayed exactly the entries we can access through the hash table
                assert_eq!(replayed_items.len(), 2);
                assert!(replayed_items
                    .iter()
                    .any(|(k, v)| k == &key1 && v == &value1));
                assert!(replayed_items
                    .iter()
                    .any(|(k, v)| k == &key2 && v == &value2));

                diskmap.destroy().await.unwrap();
            }
        });
    }
}
