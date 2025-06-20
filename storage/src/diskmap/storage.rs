use super::{Config, Error};
use bytes::{Buf, BufMut};
use commonware_codec::{Codec, EncodeSize, Read, ReadExt, Write as CodecWrite};
use commonware_runtime::{buffer::Write, Blob, Metrics, Storage};
use commonware_utils::{hex, Array};
use prometheus_client::metrics::counter::Counter;
use std::collections::HashMap;
use std::marker::PhantomData;
use tracing::trace;

const TABLE_BLOB_NAME: &[u8] = b"table";
const JOURNAL_PREFIX: &str = "journal_";
const TABLE_ENTRY_SIZE: usize = 48; // Two entries: 2 * (u64 journal_id + u64 offset + u32 crc + u32 other_crc)
const SINGLE_ENTRY_SIZE: usize = 24; // u64 journal_id + u64 offset + u32 crc + u32 other_crc

const MAX_JOURNAL_SIZE: u64 = 64 * 1024 * 1024; // 64MB per journal

/// Record stored in the journal for linked list entries.
struct JournalEntry<K: Array, V: Codec> {
    next_journal_id: u64,
    next_offset: u64,
    key: K,
    value: V,
}

impl<K: Array, V: Codec> JournalEntry<K, V> {
    /// Create a new `JournalEntry`.
    fn new(next_journal_id: u64, next_offset: u64, key: K, value: V) -> Self {
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

        let mut next_offset_bytes = [0u8; 8];
        buf.copy_to_slice(&mut next_offset_bytes);
        let next_offset = u64::from_le_bytes(next_offset_bytes);

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
        8 + 8 + K::SIZE + 4 + self.value.encode_size() // Added 4 bytes for value size
    }
}

/// Implementation of `DiskMap` storage.
pub struct DiskMap<E: Storage + Metrics, K: Array, V: Codec> {
    context: E,
    config: Config<V::Cfg>,

    // Table blob that maps hash values to journal locations (journal_id, offset)
    table_blob: E::Blob,
    table_size: u64, // Number of table entries

    // Cache of open journal blobs
    journal_cache: HashMap<u64, Write<E::Blob>>,

    // Current journal for new writes
    current_journal_id: u64,

    // Phantom data to satisfy the compiler about generic types
    _phantom: PhantomData<(K, V)>,

    // Metrics
    puts: Counter,
    gets: Counter,
    journal_hits: Counter,
    journal_misses: Counter,
    table_reads: Counter,
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
            _phantom: PhantomData,
            puts,
            gets,
            journal_hits,
            journal_misses,
            table_reads,
        })
    }

    /// Hash a key to a table index.
    fn hash_key(&self, key: &K) -> u64 {
        let hash = crc32fast::hash(key.as_ref()) as u64;
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
        key: K,
        value: V,
    ) -> Result<(), Error> {
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

        // Create journal entry
        let entry = JournalEntry::new(current_head_journal_id, current_head_offset, key, value);

        // Encode the entry
        let mut buf = Vec::with_capacity(entry.encode_size());
        entry.write(&mut buf);

        // Write the entry to the journal
        journal.write_at(buf, new_entry_offset).await?;
        journal.sync().await?;

        // Update table to point to this new entry as the head
        self.set_table_entry(table_index, target_journal_id, new_entry_offset)
            .await?;

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
            // Get the journal for this entry
            let journal = self.get_journal(journal_id).await?;

            // Read the next pointers first to get the structure
            let next_journal_buf = vec![0u8; 8];
            let next_journal_buf = journal.read_at(next_journal_buf, offset).await?;
            let next_journal_id = u64::from_le_bytes(next_journal_buf.as_ref().try_into().unwrap());

            let next_offset_buf = vec![0u8; 8];
            let next_offset_buf = journal.read_at(next_offset_buf, offset + 8).await?;
            let next_offset = u64::from_le_bytes(next_offset_buf.as_ref().try_into().unwrap());

            // Read the key
            let key_buf = vec![0u8; K::SIZE];
            let key_buf = journal.read_at(key_buf, offset + 16).await?;
            let entry_key =
                K::read(&mut key_buf.as_ref()).map_err(|_| Error::BucketCorrupted(offset))?;

            // Check if this key matches before reading the value
            if entry_key.as_ref() == key.as_ref() {
                // Read the value size first
                let value_size_buf = vec![0u8; 4];
                let value_size_buf = journal
                    .read_at(value_size_buf, offset + 16 + K::SIZE as u64)
                    .await?;
                let value_size =
                    u32::from_le_bytes(value_size_buf.as_ref().try_into().unwrap()) as usize;

                // Now read exactly the amount of data we need for the value
                let value_buf = vec![0u8; value_size];
                let value_buf = journal
                    .read_at(value_buf, offset + 16 + K::SIZE as u64 + 4)
                    .await?;

                let entry_value = V::read_cfg(&mut value_buf.as_ref(), &self.config.codec_config)
                    .map_err(|_| Error::BucketCorrupted(offset))?;

                values.push(entry_value);
            }

            // Follow the chain
            if next_journal_id == 0 {
                break; // End of chain
            }
            journal_id = next_journal_id;
            offset = next_offset;
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
        });
    }

    #[test]
    fn test_diskmap_type_safety() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let config = Config {
                partition: "test".to_string(),
                directory_size: 256,
                codec_config: (),
                write_buffer: 1024,
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
        });
    }
}
