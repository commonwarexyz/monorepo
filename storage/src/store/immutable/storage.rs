use super::{Config, Error};
use crate::{
    journal::variable::{Config as JournalConfig, Journal},
    metadata::{self, Metadata},
};
use bytes::{Buf, BufMut};
use commonware_codec::{Codec, Encode, EncodeSize, FixedSize, Read, ReadExt, Write as CodecWrite};
use commonware_runtime::{Blob, Clock, Metrics, Storage};
use commonware_utils::{array::U64, Array};
use futures::future::try_join_all;
use prometheus_client::metrics::counter::Counter;
use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet},
    marker::PhantomData,
};
use tracing::debug;

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
    /// Create a new [TableEntry] with a CRC.
    fn new(epoch: u64, section: u64, offset: u32) -> Self {
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
    key: K,
    value: V,

    next: Option<(u64, u32)>,
}

impl<K: Array, V: Codec> JournalEntry<K, V> {
    /// Create a new `JournalEntry`.
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

/// Implementation of `Index` storage.
pub struct Store<E: Storage + Metrics + Clock, K: Array, V: Codec> {
    // Context for storage operations
    context: E,

    // Table size
    table_partition: String,
    table_size: u32,

    // Committed data for the disk map
    metadata: Metadata<E, U64>,

    // Table blob that maps hash values to journal locations (journal_id, offset)
    table: E::Blob,

    // Variable journal for storing entries
    journal: Journal<E, JournalEntry<K, V>>,

    // Target size of each journal
    target_journal_size: u64,

    // Current section for new writes
    current_section: u64,

    // Metrics
    puts: Counter,
    gets: Counter,

    // Pending table updates to be written on sync (table_index -> (section, offset))
    modified_sections: BTreeSet<u64>,
    pending: BTreeMap<u32, (u64 /*section*/, u32 /*offset*/)>,

    // Phantom data to satisfy the compiler about generic types
    _phantom: PhantomData<(K, V)>,
}

impl<E: Storage + Metrics + Clock, K: Array, V: Codec> Store<E, K, V> {
    /// Initialize a new `Index` instance.
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

        // Initialize variable journal with a separate partition
        let journal_config = JournalConfig {
            partition: config.journal_partition,
            compression: config.journal_compression,
            codec_config: config.codec_config,
            write_buffer: config.write_buffer,
        };
        let mut journal = Journal::init(context.clone(), journal_config).await?;

        // Open table blob (includes header)
        let (table, table_len) = context
            .open(&config.table_partition, TABLE_BLOB_NAME)
            .await?;

        // If the blob is brand new, create header + zeroed buckets.
        let current_section = if table_len == 0 {
            // buckets
            let table_data_size = config.table_size as u64 * FULL_TABLE_ENTRY_SIZE as u64;
            let table_data = vec![0u8; table_data_size as usize];
            table.write_at(table_data, 0).await?;
            table.sync().await?;
            0
        } else {
            // Load committed data from metadata
            let committed_epoch = metadata
                .get(&COMMITTED_EPOCH.into())
                .map(|v| u64::from_be_bytes(v.as_slice().try_into().unwrap()))
                .unwrap_or(0u64);
            let committed_section = metadata
                .get(&COMMITTED_SECTION.into())
                .map(|v| u64::from_be_bytes(v.as_slice().try_into().unwrap()))
                .unwrap_or(0u64);
            let committed_offset = metadata
                .get(&COMMITTED_OFFSET.into())
                .map(|v| u32::from_be_bytes(v.as_slice().try_into().unwrap()))
                .unwrap_or(0u32);

            // Rewind the journal to the committed section and offset
            journal.rewind(committed_section, committed_offset).await?;

            // Zero out any table entries whose epoch is greater than the committed epoch
            let mut sync = false;
            let zero_buf = vec![0u8; TABLE_ENTRY_SIZE];
            for table_index in 0..config.table_size {
                let offset = table_index as u64 * FULL_TABLE_ENTRY_SIZE as u64;
                let result = table.read_at(vec![0u8; TABLE_ENTRY_SIZE], offset).await?;

                let mut buf1 = &result.as_ref()[0..TABLE_ENTRY_SIZE];
                let entry1 = TableEntry::read(&mut buf1)?;
                if entry1.epoch > committed_epoch {
                    debug!(
                        committed_epoch,
                        epoch = entry1.epoch,
                        "found invalid table entry"
                    );
                    table.write_at(zero_buf.clone(), offset).await?;
                    sync = true;
                }

                let mut buf2 = &result.as_ref()[TABLE_ENTRY_SIZE..FULL_TABLE_ENTRY_SIZE];
                let entry2 = TableEntry::read(&mut buf2)?;
                if entry2.epoch > committed_epoch {
                    debug!(
                        committed_epoch,
                        epoch = entry2.epoch,
                        "found invalid table entry"
                    );
                    table
                        .write_at(zero_buf.clone(), offset + TABLE_ENTRY_SIZE as u64)
                        .await?;
                    sync = true;
                }
            }

            // Sync the table if any changes were made
            if sync {
                table.sync().await?;
            }
            committed_section
        };

        // Create metrics
        let puts = Counter::default();
        let gets = Counter::default();
        context.register("puts", "number of put operations", puts.clone());
        context.register("gets", "number of get operations", gets.clone());

        Ok(Self {
            context,
            table_size: config.table_size,
            metadata,
            table,
            table_partition: config.table_partition,
            journal,
            target_journal_size: config.target_journal_size,
            current_section,
            puts,
            gets,
            modified_sections: BTreeSet::new(),
            pending: BTreeMap::new(),
            _phantom: PhantomData,
        })
    }

    /// Compute the table index for a given key.
    fn table_index(&self, key: &K) -> u32 {
        let hash = crc32fast::hash(key.as_ref());
        hash % self.table_size
    }

    /// Choose the newer valid entry between two table slots.
    fn select_valid_entry(&self, entry1: &TableEntry, entry2: &TableEntry) -> Option<(u64, u32)> {
        match (
            !entry1.is_empty() && entry1.is_valid(),
            !entry2.is_empty() && entry2.is_valid(),
        ) {
            (true, true) => match entry1.epoch.cmp(&entry2.epoch) {
                Ordering::Greater => Some((entry1.section, entry1.offset)),
                Ordering::Less => Some((entry2.section, entry2.offset)),
                Ordering::Equal => {
                    unreachable!("two valid entries with the same epoch")
                }
            },
            (true, false) => Some((entry1.section, entry1.offset)),
            (false, true) => Some((entry2.section, entry2.offset)),
            (false, false) => None,
        }
    }

    /// Get the head of the journal chain for a given table index.
    async fn get_head(&self, table_index: u32) -> Result<Option<(u64, u32)>, Error> {
        // Check if there's a pending update first
        if let Some(&(section, offset)) = self.pending.get(&table_index) {
            return Ok(Some((section, offset)));
        }

        // Read the table entry
        let offset = table_index as u64 * FULL_TABLE_ENTRY_SIZE as u64;
        let buf = vec![0u8; FULL_TABLE_ENTRY_SIZE];
        let read_buf = self.table.read_at(buf, offset).await?;
        let mut buf1 = &read_buf.as_ref()[0..TABLE_ENTRY_SIZE];
        let entry1 = TableEntry::read(&mut buf1)?;
        let mut buf2 = &read_buf.as_ref()[TABLE_ENTRY_SIZE..FULL_TABLE_ENTRY_SIZE];
        let entry2 = TableEntry::read(&mut buf2)?;

        // Select the valid entry
        Ok(self.select_valid_entry(&entry1, &entry2))
    }

    /// Write a table entry to disk using atomic dual-entry writes.
    async fn update_head(
        &self,
        epoch: u64,
        table_index: u32,
        section: u64,
        offset: u32,
    ) -> Result<(), Error> {
        // Read current entries to determine which slot to update
        let table_offset = table_index as u64 * FULL_TABLE_ENTRY_SIZE as u64;
        let buf = vec![0u8; FULL_TABLE_ENTRY_SIZE];
        let read_buf = self.table.read_at(buf, table_offset).await?;

        // Parse current entries using codec
        let mut buf1 = &read_buf.as_ref()[0..TABLE_ENTRY_SIZE];
        let entry1 = TableEntry::read(&mut buf1)?;
        let mut buf2 = &read_buf.as_ref()[TABLE_ENTRY_SIZE..FULL_TABLE_ENTRY_SIZE];
        let entry2 = TableEntry::read(&mut buf2)?;

        // Determine where to start writing the new entry
        let start = if entry1.is_empty() {
            0
        } else if entry2.is_empty() {
            TABLE_ENTRY_SIZE
        } else if entry1.epoch > entry2.epoch {
            0
        } else {
            unreachable!("two valid entries with the same epoch");
        };

        // Build the new entry
        let entry = TableEntry::new(epoch, section, offset);

        // Write the new entry
        self.table
            .write_at(entry.encode(), table_offset + start as u64)
            .await
            .map_err(Error::Runtime)
    }

    /// Determine which journal section to write to based on current journal size.
    async fn update_section(&mut self) -> Result<(), Error> {
        // Get the current section size
        let current_size = self.journal.section_size(self.current_section).await?;

        // If the current section has reached the target size, create a new section
        if current_size >= self.target_journal_size {
            self.current_section += 1;
        }

        Ok(())
    }

    /// Put a key-value pair into the disk map.
    pub async fn put(&mut self, key: K, value: V) -> Result<(), Error> {
        self.puts.inc();

        // Update the section if needed
        self.update_section().await?;

        // Get head of the chain from table
        let table_index = self.table_index(&key);
        let next = self.get_head(table_index).await?;

        // Create new head of the chain
        let entry = JournalEntry::new(key, value, next);

        // Append entry to the variable journal
        let (offset, _) = self.journal.append(self.current_section, entry).await?;

        // Stage table update
        self.modified_sections.insert(self.current_section);
        self.pending
            .insert(table_index, (self.current_section, offset));

        Ok(())
    }

    /// Get the first value for a given key.
    pub async fn get(&self, key: &K) -> Result<Option<V>, Error> {
        self.gets.inc();

        // Get head of the chain from table
        let table_index = self.table_index(key);
        let Some((mut section, mut offset)) = self.get_head(table_index).await? else {
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

    /// Check if a key exists in the disk map.
    pub async fn has(&self, key: &K) -> Result<bool, Error> {
        Ok(self.get(key).await?.is_some())
    }

    /// Sync all data to the underlying store.
    /// First syncs all journal sections, then flushes pending table updates, and finally syncs the table.
    pub async fn sync(&mut self) -> Result<(), Error> {
        // Compute the next epoch, max section, and max offset
        let committed_epoch = self
            .metadata
            .get(&COMMITTED_EPOCH.into())
            .map(|v| u64::from_be_bytes(v.as_slice().try_into().unwrap()))
            .unwrap_or(0);
        let next_epoch = committed_epoch.checked_add(1).expect("epoch overflow");
        let max_section = self.current_section;
        let max_offset = self.journal.section_size(max_section).await?;

        // Sync all modified journal sections
        let mut updates = Vec::with_capacity(self.modified_sections.len());
        for section in &self.modified_sections {
            updates.push(self.journal.sync(*section));
        }
        try_join_all(updates).await?;
        self.modified_sections.clear();

        // Write updated table entries
        let mut updates = Vec::with_capacity(self.pending.len());
        for (&table_index, &(section, offset)) in &self.pending {
            updates.push(self.update_head(next_epoch, table_index, section, offset));
        }
        try_join_all(updates).await?;
        self.table.sync().await?;
        self.pending.clear();

        // Update committed data
        self.metadata
            .put(COMMITTED_EPOCH.into(), next_epoch.to_be_bytes().to_vec());
        self.metadata
            .put(COMMITTED_SECTION.into(), max_section.to_be_bytes().to_vec());
        self.metadata
            .put(COMMITTED_OFFSET.into(), max_offset.to_be_bytes().to_vec());
        self.metadata.sync().await?;

        Ok(())
    }

    /// Close the disk map and underlying journal.
    pub async fn close(mut self) -> Result<(), Error> {
        // Sync any pending updates before closing
        self.sync().await?;

        self.journal.close().await?;
        self.table.close().await?;
        self.metadata.close().await?;
        Ok(())
    }

    /// Close and remove any underlying blobs created by the disk map.
    pub async fn destroy(self) -> Result<(), Error> {
        // Destroy the journal (removes all journal sections)
        self.journal.destroy().await?;

        // Close and remove the table blob
        self.table.close().await?;
        self.context
            .remove(&self.table_partition, Some(TABLE_BLOB_NAME))
            .await?;

        // Remove the metadata blob
        self.metadata.destroy().await?;

        Ok(())
    }
}
