use super::{Config, Error, Identifier};
use crate::{
    journal::segmented::oversized::{
        Config as OversizedConfig, Oversized, Record as OversizedRecord,
    },
    kv, Persistable,
};
use bytes::{Buf, BufMut};
use commonware_codec::{CodecShared, Encode, FixedSize, Read, ReadExt, Write as CodecWrite};
use commonware_cryptography::{crc32, Crc32, Hasher};
use commonware_runtime::{buffer, Blob, Clock, Metrics, Storage};
use commonware_utils::{Array, Span};
use futures::future::{try_join, try_join_all};
use prometheus_client::metrics::counter::Counter;
use std::{cmp::Ordering, collections::BTreeSet, num::NonZeroUsize, ops::Deref};
use tracing::debug;

/// The percentage of table entries that must reach `table_resize_frequency`
/// before a resize is triggered.
const RESIZE_THRESHOLD: u64 = 50;

/// Location of an item in the [Freezer].
///
/// This can be used to directly access the data for a given
/// key-value pair (rather than walking the journal chain).
#[derive(Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
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

/// Marker of [Freezer] progress.
///
/// This can be used to restore the [Freezer] to a consistent
/// state after shutdown.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Copy)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct Checkpoint {
    /// The epoch of the last committed operation.
    epoch: u64,
    /// The section of the last committed operation.
    section: u64,
    /// The size of the oversized index journal in the last committed section.
    oversized_size: u64,
    /// The size of the table.
    table_size: u32,
}

impl Checkpoint {
    /// Initialize a new [Checkpoint].
    const fn init(table_size: u32) -> Self {
        Self {
            table_size,
            epoch: 0,
            section: 0,
            oversized_size: 0,
        }
    }
}

impl Read for Checkpoint {
    type Cfg = ();
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, commonware_codec::Error> {
        let epoch = u64::read(buf)?;
        let section = u64::read(buf)?;
        let oversized_size = u64::read(buf)?;
        let table_size = u32::read(buf)?;
        Ok(Self {
            epoch,
            section,
            oversized_size,
            table_size,
        })
    }
}

impl CodecWrite for Checkpoint {
    fn write(&self, buf: &mut impl BufMut) {
        self.epoch.write(buf);
        self.section.write(buf);
        self.oversized_size.write(buf);
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
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
struct Entry {
    // Epoch in which this slot was written
    epoch: u64,
    // Section in which this slot was written
    section: u64,
    // Position in the key index for this section
    position: u64,
    // Number of items added to this entry since last resize
    added: u8,
    // CRC of (epoch | section | position | added)
    crc: u32,
}

impl Entry {
    /// The full size of a table entry (2 slots).
    const FULL_SIZE: usize = Self::SIZE * 2;

    /// Compute a checksum for [Entry].
    fn compute_crc(epoch: u64, section: u64, position: u64, added: u8) -> u32 {
        let mut hasher = Crc32::new();
        hasher.update(&epoch.to_be_bytes());
        hasher.update(&section.to_be_bytes());
        hasher.update(&position.to_be_bytes());
        hasher.update(&added.to_be_bytes());
        hasher.finalize().as_u32()
    }

    /// Create a new [Entry].
    fn new(epoch: u64, section: u64, position: u64, added: u8) -> Self {
        Self {
            epoch,
            section,
            position,
            added,
            crc: Self::compute_crc(epoch, section, position, added),
        }
    }

    /// Check if this entry is empty (all zeros).
    const fn is_empty(&self) -> bool {
        self.section == 0 && self.position == 0 && self.crc == 0
    }

    /// Check if this entry is valid.
    fn is_valid(&self) -> bool {
        Self::compute_crc(self.epoch, self.section, self.position, self.added) == self.crc
    }
}

impl FixedSize for Entry {
    const SIZE: usize = u64::SIZE + u64::SIZE + u64::SIZE + u8::SIZE + crc32::Digest::SIZE;
}

impl CodecWrite for Entry {
    fn write(&self, buf: &mut impl BufMut) {
        self.epoch.write(buf);
        self.section.write(buf);
        self.position.write(buf);
        self.added.write(buf);
        self.crc.write(buf);
    }
}

impl Read for Entry {
    type Cfg = ();
    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        let epoch = u64::read(buf)?;
        let section = u64::read(buf)?;
        let position = u64::read(buf)?;
        let added = u8::read(buf)?;
        let crc = u32::read(buf)?;

        Ok(Self {
            epoch,
            section,
            position,
            added,
            crc,
        })
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
pub struct Freezer<E: Storage + Metrics + Clock, K: Array, V: CodecShared> {
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
}

impl<E: Storage + Metrics + Clock, K: Array, V: CodecShared> Freezer<E, K, V> {
    /// Calculate the byte offset for a table index.
    #[inline]
    const fn table_offset(table_index: u32) -> u64 {
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
    const fn compute_write_offset(entry1: &Entry, entry2: &Entry, epoch: u64) -> u64 {
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
    fn read_latest_entry(entry1: &Entry, entry2: &Entry) -> Option<(u64, u64, u8)> {
        match (
            !entry1.is_empty() && entry1.is_valid(),
            !entry2.is_empty() && entry2.is_valid(),
        ) {
            (true, true) => match entry1.epoch.cmp(&entry2.epoch) {
                Ordering::Greater => Some((entry1.section, entry1.position, entry1.added)),
                Ordering::Less => Some((entry2.section, entry2.position, entry2.added)),
                Ordering::Equal => {
                    unreachable!("two valid entries with the same epoch")
                }
            },
            (true, false) => Some((entry1.section, entry1.position, entry1.added)),
            (false, true) => Some((entry2.section, entry2.position, entry2.added)),
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
            .write_at(update.encode_mut(), table_offset + start)
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

        // Initialize oversized journal (handles crash recovery)
        let oversized_cfg = OversizedConfig {
            index_partition: config.key_partition.clone(),
            value_partition: config.value_partition.clone(),
            index_buffer_pool: config.key_buffer_pool.clone(),
            index_write_buffer: config.key_write_buffer,
            value_write_buffer: config.value_write_buffer,
            compression: config.value_compression,
            codec_config: config.codec_config,
        };
        let mut oversized: Oversized<E, Record<K>, V> =
            Oversized::init(context.with_label("oversized"), oversized_cfg).await?;

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
                assert_eq!(checkpoint.oversized_size, 0);
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

                // Rewind oversized to the committed section and key size
                oversized
                    .rewind(checkpoint.section, checkpoint.oversized_size)
                    .await?;

                // Sync oversized
                oversized.sync(checkpoint.section).await?;

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

                // Get sizes from oversized (crash recovery already ran during init)
                let oversized_size = oversized.size(max_section).await?;

                (
                    Checkpoint {
                        epoch: max_epoch,
                        section: max_section,
                        oversized_size,
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
            oversized,
            blob_target_size: config.value_target_size,
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
        let (entry1, entry2) = Self::read_table(&self.table, table_index).await?;
        let head = Self::read_latest_entry(&entry1, &entry2);

        // Create key entry with pointer to previous head (value location set by oversized.append)
        let key_entry = Record::new(
            key,
            head.map(|(section, position, _)| (section, position)),
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
        let mut added = head.map(|(_, _, added)| added).unwrap_or(0);
        added = added.saturating_add(1);

        // If we've reached the threshold for resizing, increment the resizable entries
        if added == self.table_resize_frequency {
            self.resizable += 1;
        }

        // Update the old position
        self.modified_sections.insert(self.current_section);
        let new_entry = Entry::new(self.next_epoch, self.current_section, position, added);
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
                let new_entry = Entry::new(self.next_epoch, self.current_section, position, added);
                Self::update_head(&self.table, new_table_index, &entry1, &entry2, new_entry)
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

    /// Get the first value for a given key.
    async fn get_key(&self, key: &K) -> Result<Option<V>, Error> {
        self.gets.inc();

        // Get head of the chain from table
        let table_index = self.table_index(key);
        let (entry1, entry2) = Self::read_table(&self.table, table_index).await?;
        let Some((mut section, mut position, _)) = Self::read_latest_entry(&entry1, &entry2) else {
            return Ok(None);
        };

        // Follow the linked list chain to find the first matching key
        loop {
            // Get the key entry from the fixed key index (efficient, good cache locality)
            let key_entry = self.oversized.get(section, position).await?;

            // Check if this key matches
            if key_entry.key.as_ref() == key.as_ref() {
                let value = self
                    .oversized
                    .get_value(section, key_entry.value_offset, key_entry.value_size)
                    .await?;
                return Ok(Some(value));
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
            let (section, position, added) =
                Self::read_latest_entry(&entry1, &entry2).unwrap_or((0, 0, 0));

            // If the entry was over the threshold, decrement the resizable entries
            if added >= self.table_resize_frequency {
                self.resizable -= 1;
            }

            // Rewrite the entries
            let reset_entry = Entry::new(self.next_epoch, section, position, 0);
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
        // Sync all modified sections for oversized journal
        let syncs: Vec<_> = self
            .modified_sections
            .iter()
            .map(|section| self.oversized.sync(*section))
            .collect();
        try_join_all(syncs).await?;
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

        // Get size from oversized
        let oversized_size = self.oversized.size(self.current_section).await?;

        Ok(Checkpoint {
            epoch: stored_epoch,
            section: self.current_section,
            oversized_size,
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

        Ok(checkpoint)
    }

    /// Close and remove any underlying blobs created by the [Freezer].
    pub async fn destroy(self) -> Result<(), Error> {
        // Destroy oversized journal
        self.oversized.destroy().await?;

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
    pub const fn resizing(&self) -> Option<u32> {
        self.resize_progress
    }

    /// Get the number of resizable entries.
    #[cfg(test)]
    pub const fn resizable(&self) -> u32 {
        self.resizable
    }
}

impl<E: Storage + Metrics + Clock, K: Array, V: CodecShared> kv::Gettable for Freezer<E, K, V> {
    type Key = K;
    type Value = V;
    type Error = Error;

    async fn get(&self, key: &Self::Key) -> Result<Option<Self::Value>, Self::Error> {
        self.get(Identifier::Key(key)).await
    }
}

impl<E: Storage + Metrics + Clock, K: Array, V: CodecShared> kv::Updatable for Freezer<E, K, V> {
    async fn update(&mut self, key: Self::Key, value: Self::Value) -> Result<(), Self::Error> {
        self.put(key, value).await?;
        Ok(())
    }
}

impl<E: Storage + Metrics + Clock, K: Array, V: CodecShared> Persistable for Freezer<E, K, V> {
    type Error = Error;

    async fn commit(&mut self) -> Result<(), Self::Error> {
        self.sync().await?;
        Ok(())
    }

    async fn sync(&mut self) -> Result<(), Self::Error> {
        self.sync().await?;
        Ok(())
    }

    async fn destroy(self) -> Result<(), Self::Error> {
        self.destroy().await?;
        Ok(())
    }
}

#[cfg(all(test, feature = "arbitrary"))]
mod conformance {
    use super::*;
    use commonware_codec::conformance::CodecConformance;
    use commonware_utils::sequence::U64;

    commonware_conformance::conformance_tests! {
        CodecConformance<Cursor>,
        CodecConformance<Checkpoint>,
        CodecConformance<Entry>,
        CodecConformance<Record<U64>>
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kv::tests::{assert_gettable, assert_send, assert_updatable};
    use commonware_runtime::deterministic::Context;
    use commonware_utils::sequence::U64;

    type TestFreezer = Freezer<Context, U64, u64>;

    #[allow(dead_code)]
    fn assert_freezer_futures_are_send(freezer: &mut TestFreezer, key: U64) {
        assert_gettable(freezer, &key);
        assert_updatable(freezer, key, 0u64);
    }

    #[allow(dead_code)]
    fn assert_freezer_destroy_is_send(freezer: TestFreezer) {
        assert_send(freezer.destroy());
    }
}
