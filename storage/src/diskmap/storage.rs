use super::{Config, Error};
use commonware_runtime::{buffer::Write, Blob, Metrics, Storage};
use commonware_utils::hex;
use prometheus_client::metrics::counter::Counter;
use std::collections::HashMap;
use tracing::trace;

const TABLE_BLOB_NAME: &[u8] = b"table";
const JOURNAL_PREFIX: &str = "journal_";
const TABLE_ENTRY_SIZE: usize = 48; // Two entries: 2 * (u64 journal_id + u64 offset + u32 crc + u32 other_crc)
const SINGLE_ENTRY_SIZE: usize = 24; // u64 journal_id + u64 offset + u32 crc + u32 other_crc

const MAX_JOURNAL_SIZE: u64 = 64 * 1024 * 1024; // 64MB per journal

/// Implementation of `DiskMap` storage.
pub struct DiskMap<E: Storage + Metrics> {
    context: E,
    config: Config,

    // Table blob that maps hash values to journal locations (journal_id, offset)
    table_blob: E::Blob,
    table_size: u64, // Number of table entries

    // Cache of open journal blobs
    journal_cache: HashMap<u64, Write<E::Blob>>,

    // Current journal for new writes
    current_journal_id: u64,

    // Metrics
    puts: Counter,
    gets: Counter,
    journal_hits: Counter,
    journal_misses: Counter,
    table_reads: Counter,
}

impl<E: Storage + Metrics> DiskMap<E> {
    /// Initialize a new `DiskMap` instance.
    pub async fn init(context: E, config: Config) -> Result<Self, Error> {
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

        // Create metrics
        let puts = Counter::default();
        let gets = Counter::default();
        let journal_hits = Counter::default();
        let journal_misses = Counter::default();
        let table_reads = Counter::default();

        context.register("puts", "number of put operations", puts.clone());
        context.register("gets", "number of get operations", gets.clone());
        context.register(
            "journal_hits",
            "number of journal cache hits",
            journal_hits.clone(),
        );
        context.register(
            "journal_misses",
            "number of journal cache misses",
            journal_misses.clone(),
        );
        context.register("table_reads", "number of table reads", table_reads.clone());

        Ok(Self {
            context,
            config,
            table_blob,
            table_size,
            journal_cache: HashMap::new(),
            current_journal_id: 0,
            puts,
            gets,
            journal_hits,
            journal_misses,
            table_reads,
        })
    }

    /// Hash a key to a table index.
    fn hash_key(&self, key: &[u8]) -> u64 {
        let hash = crc32fast::hash(key) as u64;
        hash % self.table_size
    }

    /// Get the journal location (journal_id, offset) for a given table index.
    async fn get_table_entry(&self, table_index: u64) -> Result<(u64, u64), Error> {
        self.table_reads.inc();

        let offset = table_index * TABLE_ENTRY_SIZE as u64;
        let buf = vec![0u8; TABLE_ENTRY_SIZE];
        let read_buf = self.table_blob.read_at(buf, offset).await?;

        // Parse both entries
        let entry1 = self.parse_single_entry(&read_buf.as_ref()[0..SINGLE_ENTRY_SIZE])?;
        let entry2 =
            self.parse_single_entry(&read_buf.as_ref()[SINGLE_ENTRY_SIZE..TABLE_ENTRY_SIZE])?;

        // Determine which entry is valid
        let (journal_id, journal_offset) = self.select_valid_entry(entry1, entry2)?;

        Ok((journal_id, journal_offset))
    }

    /// Parse a single table entry: [journal_id][journal_offset][crc][other_crc]
    fn parse_single_entry(&self, data: &[u8]) -> Result<(u64, u64, u32, u32), Error> {
        if data.len() != SINGLE_ENTRY_SIZE {
            return Err(Error::DirectoryCorrupted);
        }

        let journal_id = u64::from_le_bytes(data[0..8].try_into().unwrap());
        let journal_offset = u64::from_le_bytes(data[8..16].try_into().unwrap());
        let crc = u32::from_le_bytes(data[16..20].try_into().unwrap());
        let other_crc = u32::from_le_bytes(data[20..24].try_into().unwrap());

        Ok((journal_id, journal_offset, crc, other_crc))
    }

    /// Calculate CRC for the data portion of an entry (journal_id + journal_offset)
    fn calculate_entry_crc(&self, journal_id: u64, journal_offset: u64) -> u32 {
        let mut data = Vec::with_capacity(16);
        data.extend_from_slice(&journal_id.to_le_bytes());
        data.extend_from_slice(&journal_offset.to_le_bytes());
        crc32fast::hash(&data)
    }

    /// Select the valid entry from two candidates based on CRC validation and cross-references
    fn select_valid_entry(
        &self,
        entry1: (u64, u64, u32, u32),
        entry2: (u64, u64, u32, u32),
    ) -> Result<(u64, u64), Error> {
        let (journal_id1, journal_offset1, crc1, other_crc1) = entry1;
        let (journal_id2, journal_offset2, crc2, other_crc2) = entry2;

        // Calculate expected CRCs
        let expected_crc1 = self.calculate_entry_crc(journal_id1, journal_offset1);
        let expected_crc2 = self.calculate_entry_crc(journal_id2, journal_offset2);

        // Check which entries have valid CRCs
        let entry1_valid = crc1 == expected_crc1;
        let entry2_valid = crc2 == expected_crc2;

        match (entry1_valid, entry2_valid) {
            (true, true) => {
                // Both valid - select the one that references the other's CRC
                if other_crc1 == expected_crc2 {
                    // Entry1 references entry2, so entry1 is newer
                    Ok((journal_id1, journal_offset1))
                } else if other_crc2 == expected_crc1 {
                    // Entry2 references entry1, so entry2 is newer
                    Ok((journal_id2, journal_offset2))
                } else {
                    // Neither references the other correctly - corruption
                    Err(Error::DirectoryCorrupted)
                }
            }
            (true, false) => {
                // Only entry1 is valid
                Ok((journal_id1, journal_offset1))
            }
            (false, true) => {
                // Only entry2 is valid
                Ok((journal_id2, journal_offset2))
            }
            (false, false) => {
                // Both entries are corrupted or empty
                if journal_id1 == 0
                    && journal_offset1 == 0
                    && journal_id2 == 0
                    && journal_offset2 == 0
                {
                    // Empty entry
                    Ok((0, 0))
                } else {
                    // Corrupted
                    Err(Error::DirectoryCorrupted)
                }
            }
        }
    }

    /// Set the journal location for a given table index using atomic dual-entry writes.
    async fn set_table_entry(
        &self,
        table_index: u64,
        journal_id: u64,
        journal_offset: u64,
    ) -> Result<(), Error> {
        let offset = table_index * TABLE_ENTRY_SIZE as u64;

        // Read current entries to determine which slot to update
        let buf = vec![0u8; TABLE_ENTRY_SIZE];
        let read_buf = self.table_blob.read_at(buf, offset).await?;

        // Parse current entries
        let entry1 = self.parse_single_entry(&read_buf.as_ref()[0..SINGLE_ENTRY_SIZE])?;
        let entry2 =
            self.parse_single_entry(&read_buf.as_ref()[SINGLE_ENTRY_SIZE..TABLE_ENTRY_SIZE])?;

        // Calculate CRCs for new entry
        let new_crc = self.calculate_entry_crc(journal_id, journal_offset);

        // Determine which slot to update (alternate between them)
        let (update_first, old_entry) = match self.select_valid_entry(entry1, entry2) {
            Ok((old_journal_id, old_journal_offset)) => {
                // There's a valid current entry - figure out which slot it's in
                let old_crc = self.calculate_entry_crc(old_journal_id, old_journal_offset);
                let entry1_crc = self.calculate_entry_crc(entry1.0, entry1.1);

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
            new_buf.extend_from_slice(&journal_id.to_le_bytes());
            new_buf.extend_from_slice(&journal_offset.to_le_bytes());
            new_buf.extend_from_slice(&new_crc.to_le_bytes());
            new_buf.extend_from_slice(&old_crc.to_le_bytes()); // Reference to old entry

            // Copy second slot unchanged
            new_buf.extend_from_slice(&read_buf.as_ref()[SINGLE_ENTRY_SIZE..TABLE_ENTRY_SIZE]);
        } else {
            // Keep first slot, update second slot
            new_buf.extend_from_slice(&read_buf.as_ref()[0..SINGLE_ENTRY_SIZE]);

            // Update second slot
            new_buf.extend_from_slice(&journal_id.to_le_bytes());
            new_buf.extend_from_slice(&journal_offset.to_le_bytes());
            new_buf.extend_from_slice(&new_crc.to_le_bytes());
            new_buf.extend_from_slice(&old_crc.to_le_bytes()); // Reference to old entry
        }

        // Write the complete entry atomically
        self.table_blob.write_at(new_buf, offset).await?;
        self.table_blob.sync().await?;

        Ok(())
    }

    /// Get or create a journal blob.
    async fn get_journal(&mut self, journal_id: u64) -> Result<&mut Write<E::Blob>, Error> {
        if !self.journal_cache.contains_key(&journal_id) {
            self.journal_misses.inc();
            let journal_name = format!("{}{}", JOURNAL_PREFIX, journal_id);
            let (journal_blob, journal_len) = self
                .context
                .open(&self.config.partition, journal_name.as_bytes())
                .await?;
            let write_journal = Write::new(journal_blob, journal_len, self.config.write_buffer);
            self.journal_cache.insert(journal_id, write_journal);
        } else {
            self.journal_hits.inc();
        }

        Ok(self.journal_cache.get_mut(&journal_id).unwrap())
    }

    /// Insert a key-value pair into a journal using proper linked list chaining.
    async fn insert_into_journal(
        &mut self,
        table_index: u64,
        key: &[u8],
        value: &[u8],
    ) -> Result<(), Error> {
        let key_length = self.config.key_length;
        let value_length = self.config.value_length;

        // Get current head of the chain from table
        let (current_head_journal_id, current_head_offset) =
            self.get_table_entry(table_index).await?;

        // Determine which journal to write to
        let target_journal_id = if self.current_journal_id == 0 {
            // First write, start with journal 0
            self.current_journal_id = 1;
            1
        } else {
            // Check if current journal is getting too large
            let current_journal = self.get_journal(self.current_journal_id).await?;
            let current_size = current_journal.size().await;

            if current_size > MAX_JOURNAL_SIZE {
                // Start a new journal
                self.current_journal_id += 1;
                self.current_journal_id
            } else {
                self.current_journal_id
            }
        };

        let journal = self.get_journal(target_journal_id).await?;
        let new_entry_offset = journal.size().await;

        // Write the new entry: [next_journal_id][next_offset][key][value]
        // Next pointers point to the previous head of the chain
        journal
            .write_at(
                current_head_journal_id.to_le_bytes().to_vec(),
                new_entry_offset,
            )
            .await?;
        let mut offset = new_entry_offset + 8;

        journal
            .write_at(current_head_offset.to_le_bytes().to_vec(), offset)
            .await?;
        offset += 8;

        journal.write_at(key.to_vec(), offset).await?;
        offset += key_length as u64;

        journal.write_at(value.to_vec(), offset).await?;

        journal.sync().await?;

        // Update table to point to this new entry as the head
        self.set_table_entry(table_index, target_journal_id, new_entry_offset)
            .await?;
        self.table_blob.sync().await?;

        Ok(())
    }

    /// Put a key-value pair into the disk map.
    pub async fn put(&mut self, key: &[u8], value: &[u8]) -> Result<(), Error> {
        self.puts.inc();

        // Validate input lengths
        if key.len() != self.config.key_length {
            return Err(Error::InvalidKeyLength {
                expected: self.config.key_length,
                actual: key.len(),
            });
        }

        if value.len() != self.config.value_length {
            return Err(Error::InvalidValueLength {
                expected: self.config.value_length,
                actual: value.len(),
            });
        }

        // Hash key to table index
        let table_index = self.hash_key(key);

        // Insert into journal (this will handle the linked list chaining)
        self.insert_into_journal(table_index, key, value).await?;

        trace!(
            key = hex(key),
            value = hex(value),
            table_index = table_index,
            "inserted key-value pair"
        );

        Ok(())
    }

    /// Get all values for a given key from the disk map.
    pub async fn get(&mut self, key: &[u8]) -> Result<Vec<Vec<u8>>, Error> {
        self.gets.inc();

        // Validate input length
        if key.len() != self.config.key_length {
            return Err(Error::InvalidKeyLength {
                expected: self.config.key_length,
                actual: key.len(),
            });
        }

        // Hash key to table index
        let table_index = self.hash_key(key);

        // Get head of the chain from table
        let (mut journal_id, mut offset) = self.get_table_entry(table_index).await?;

        if journal_id == 0 {
            return Ok(vec![]); // No entries for this key
        }

        // Follow the linked list chain, collecting values for matching keys
        let key_length = self.config.key_length;
        let value_length = self.config.value_length;
        let mut values = Vec::new();

        loop {
            // Get the journal for this entry
            let journal = self.get_journal(journal_id).await?;

            // Read next pointers first: [next_journal_id][next_offset][key][value]
            let next_journal_buf = vec![0u8; 8];
            let next_journal_buf = journal.read_at(next_journal_buf, offset).await?;
            let next_journal_id = u64::from_le_bytes(next_journal_buf.as_ref().try_into().unwrap());

            let next_offset_buf = vec![0u8; 8];
            let next_offset_buf = journal.read_at(next_offset_buf, offset + 8).await?;
            let next_offset = u64::from_le_bytes(next_offset_buf.as_ref().try_into().unwrap());

            // Read key
            let key_buf = vec![0u8; key_length];
            let key_buf = journal.read_at(key_buf, offset + 16).await?;

            // Read value
            let value_buf = vec![0u8; value_length];
            let value_buf = journal
                .read_at(value_buf, offset + 16 + key_length as u64)
                .await?;

            // Check if this key matches
            if key_buf.as_ref() == key {
                values.push(value_buf.as_ref().to_vec());
            }

            // Follow the chain
            if next_journal_id == 0 {
                break; // End of chain
            }
            journal_id = next_journal_id;
            offset = next_offset;
        }

        trace!(
            key = hex(key),
            values_found = values.len(),
            "retrieved values for key"
        );

        Ok(values)
    }

    /// Check if a key exists in the disk map.
    pub async fn contains_key(&mut self, key: &[u8]) -> Result<bool, Error> {
        let values = self.get(key).await?;
        Ok(!values.is_empty())
    }

    /// Get the number of table entries.
    pub fn table_size(&self) -> u64 {
        self.table_size
    }

    /// Get the configured key length.
    pub fn key_length(&self) -> usize {
        self.config.key_length
    }

    /// Get the configured value length.
    pub fn value_length(&self) -> usize {
        self.config.value_length
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_runtime::{deterministic, Runner};

    #[test]
    fn test_diskmap_basic_operations() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let config = Config {
                partition: "test".to_string(),
                directory_size: 256,
                key_length: 8,
                value_length: 16,
                write_buffer: 1024,
            };

            let mut diskmap = DiskMap::init(context, config).await.unwrap();

            // Test put and get
            let key = b"testkey1";
            let value = b"testvalue1234567";

            diskmap.put(key, value).await.unwrap();
            let values = diskmap.get(key).await.unwrap();

            assert_eq!(values.len(), 1);
            assert_eq!(values[0], value);

            // Test multiple values for same key
            let value2 = b"testvalue7654321";
            diskmap.put(key, value2).await.unwrap();
            let values = diskmap.get(key).await.unwrap();

            assert_eq!(values.len(), 2);
            assert!(values.contains(&value.to_vec()));
            assert!(values.contains(&value2.to_vec()));

            // Test contains_key
            assert!(diskmap.contains_key(key).await.unwrap());
            assert!(!diskmap.contains_key(b"nonexist").await.unwrap());
        });
    }

    #[test]
    fn test_diskmap_invalid_lengths() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let config = Config {
                partition: "test".to_string(),
                directory_size: 256,
                key_length: 8,
                value_length: 16,
                write_buffer: 1024,
            };

            let mut diskmap = DiskMap::init(context, config).await.unwrap();

            // Test invalid key length
            let result = diskmap.put(b"short", b"testvalue1234567").await;
            assert!(matches!(result, Err(Error::InvalidKeyLength { .. })));

            // Test invalid value length
            let result = diskmap.put(b"testkey1", b"short").await;
            assert!(matches!(result, Err(Error::InvalidValueLength { .. })));
        });
    }
}
