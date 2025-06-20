use super::{Config, Error};
use crate::journal::variable::{Config as JournalConfig, Journal};
use bytes::{Buf, BufMut};
use commonware_codec::{Codec, EncodeSize, FixedSize, Read, ReadExt, Write as CodecWrite};
use commonware_runtime::{Blob, Metrics, Storage};
use commonware_utils::{hex, Array};
use prometheus_client::metrics::counter::Counter;
use std::collections::{HashMap, HashSet};
use std::marker::PhantomData;
use tracing::trace;

const TABLE_BLOB_NAME: &[u8] = b"table";
const TABLE_ENTRY_SIZE: usize = 40; // Two entries: 2 * (u64 journal_id + u32 offset + u32 crc + u32 other_crc)
const SINGLE_ENTRY_SIZE: usize = 20; // u64 journal_id + u32 offset + u32 crc + u32 other_crc

/// Single table entry stored in the table blob.
#[derive(Debug, Clone, PartialEq)]
struct TableEntry {
    journal_id: u64,
    journal_offset: u32,
    crc: u32,
    other_crc: u32,
}

impl TableEntry {
    /// Create a new `TableEntry`.
    fn new(journal_id: u64, journal_offset: u32, crc: u32, other_crc: u32) -> Self {
        Self {
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
        buf.put_slice(&self.journal_id.to_le_bytes());
        buf.put_slice(&self.journal_offset.to_le_bytes());
        buf.put_slice(&self.crc.to_le_bytes());
        buf.put_slice(&self.other_crc.to_le_bytes());
    }
}

impl Read for TableEntry {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _cfg: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
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
    pending_table_updates: HashMap<u64, (u64, u32)>,
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

        // Open table blob
        let (table_blob, table_len) = context.open(&config.partition, TABLE_BLOB_NAME).await?;

        // Initialize table if empty
        if table_len == 0 {
            let table_data_size = table_size * TABLE_ENTRY_SIZE as u64;
            let table_data = vec![0u8; table_data_size as usize];
            table_blob.write_at(table_data, 0).await?;
            table_blob.sync().await?;
        }

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

        Ok(Self {
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
        })
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
        if let Some(&(journal_id, journal_offset)) = self.pending_table_updates.get(&table_index) {
            return Ok((journal_id, journal_offset));
        }

        let offset = table_index * TABLE_ENTRY_SIZE as u64;
        let buf = vec![0u8; TABLE_ENTRY_SIZE];
        let read_buf = self.table_blob.read_at(buf, offset).await?;

        // Parse both entries using codec
        let mut buf1 = &read_buf.as_ref()[0..SINGLE_ENTRY_SIZE];
        let mut buf2 = &read_buf.as_ref()[SINGLE_ENTRY_SIZE..TABLE_ENTRY_SIZE];

        let entry1 = TableEntry::read(&mut buf1)?;
        let entry2 = TableEntry::read(&mut buf2)?;

        // Determine which entry is valid
        let (journal_id, journal_offset) = self.select_valid_entry(&entry1, &entry2)?;

        Ok((journal_id, journal_offset))
    }

    /// Calculate CRC for the data portion of an entry (journal_id + journal_offset)
    fn calculate_entry_crc(&self, journal_id: u64, journal_offset: u32) -> u32 {
        let mut data = Vec::with_capacity(12);
        data.extend_from_slice(&journal_id.to_le_bytes());
        data.extend_from_slice(&journal_offset.to_le_bytes());
        crc32fast::hash(&data)
    }

    /// Select the valid entry from two candidates based on CRC validation and cross-references
    fn select_valid_entry(
        &self,
        entry1: &TableEntry,
        entry2: &TableEntry,
    ) -> Result<(u64, u32), Error> {
        // Calculate expected CRCs
        let expected_crc1 = self.calculate_entry_crc(entry1.journal_id, entry1.journal_offset);
        let expected_crc2 = self.calculate_entry_crc(entry2.journal_id, entry2.journal_offset);

        // Check which entries have valid CRCs
        let entry1_valid = entry1.crc == expected_crc1;
        let entry2_valid = entry2.crc == expected_crc2;

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

    /// Set the journal location for a given table index by storing it in memory for later sync.
    fn set_table_entry(
        &mut self,
        table_index: u64,
        journal_id: u64,
        journal_offset: u32,
    ) -> Result<(), Error> {
        // Store the update in memory for later sync
        self.pending_table_updates
            .insert(table_index, (journal_id, journal_offset));
        Ok(())
    }

    /// Write a table entry to disk using atomic dual-entry writes.
    async fn write_table_entry_to_disk(
        &self,
        table_index: u64,
        journal_id: u64,
        journal_offset: u32,
    ) -> Result<(), Error> {
        let offset = table_index * TABLE_ENTRY_SIZE as u64;

        // Read current entries to determine which slot to update
        let buf = vec![0u8; TABLE_ENTRY_SIZE];
        let read_buf = self.table_blob.read_at(buf, offset).await?;

        // Parse current entries using codec
        let mut buf1 = &read_buf.as_ref()[0..SINGLE_ENTRY_SIZE];
        let mut buf2 = &read_buf.as_ref()[SINGLE_ENTRY_SIZE..TABLE_ENTRY_SIZE];

        let entry1 = TableEntry::read(&mut buf1)?;
        let entry2 = TableEntry::read(&mut buf2)?;

        // Calculate CRCs for new entry
        let new_crc = self.calculate_entry_crc(journal_id, journal_offset);

        // Determine which slot to update (alternate between them)
        let (update_first, old_entry) = match self.select_valid_entry(&entry1, &entry2) {
            Ok((old_journal_id, old_journal_offset)) => {
                // There's a valid current entry - figure out which slot it's in
                let old_crc = self.calculate_entry_crc(old_journal_id, old_journal_offset);
                let entry1_crc = self.calculate_entry_crc(entry1.journal_id, entry1.journal_offset);

                if entry1_crc == old_crc {
                    // Current entry is in slot 1, update slot 2
                    (false, (old_journal_id, old_journal_offset))
                } else {
                    // Current entry is in slot 2, update slot 1
                    (true, (old_journal_id, old_journal_offset))
                }
            }
            Err(_) => {
                // No valid current entry, use slot 1
                (true, (0, 0))
            }
        };

        // Calculate the old entry's CRC for cross-reference
        let old_crc = self.calculate_entry_crc(old_entry.0, old_entry.1);

        // Build the new complete table entry
        let mut new_buf = Vec::with_capacity(TABLE_ENTRY_SIZE);

        if update_first {
            // Update first slot, keep second slot
            let new_entry1 = TableEntry::new(journal_id, journal_offset, new_crc, old_crc);
            new_entry1.write(&mut new_buf);
            entry2.write(&mut new_buf);
        } else {
            // Keep first slot, update second slot
            entry1.write(&mut new_buf);
            let new_entry2 = TableEntry::new(journal_id, journal_offset, new_crc, old_crc);
            new_entry2.write(&mut new_buf);
        }

        // Write the complete entry
        self.table_blob.write_at(new_buf, offset).await?;

        Ok(())
    }

    /// Determine which journal section to write to based on current journal size.
    async fn determine_journal_section(&mut self, entry_size: usize) -> Result<u64, Error> {
        // If we have an existing journal, check if it has enough space
        if self.current_journal_id > 0 {
            let current_size = self.journal.section_size(self.current_journal_id).await?;

            // Check if adding this entry would exceed the limit
            if current_size + entry_size as u64 <= self.config.max_journal_size {
                // Current journal has space, continue using it
                return Ok(self.current_journal_id);
            }
        }

        // Need a new journal (either first write or current is full)
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

        // Flush all pending table updates to disk
        for (&table_index, &(journal_id, journal_offset)) in &self.pending_table_updates {
            self.write_table_entry_to_disk(table_index, journal_id, journal_offset)
                .await?;
        }

        // Clear pending updates since they're now written
        self.pending_table_updates.clear();

        // Finally sync the table
        self.table_blob.sync().await?;

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
                max_journal_size: 64 * 1024 * 1024, // 64MB
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
                max_journal_size: 64 * 1024 * 1024, // 64MB
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
                    max_journal_size: 64 * 1024 * 1024, // 64MB
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
                    max_journal_size: 64 * 1024 * 1024, // 64MB
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
                max_journal_size: 64 * 1024 * 1024, // 64MB
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
                max_journal_size: 64 * 1024 * 1024, // 64MB
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
}
