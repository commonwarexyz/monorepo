//! Contiguous wrapper for variable-length journals.
//!
//! This wrapper enforces section fullness: all non-final sections are full and synced.
//! On init, only the last section needs to be replayed to determine the exact size.

use super::Contiguous;
use crate::journal::{fixed, variable, Error};
use bytes::{Buf, BufMut};
use commonware_codec::{Codec, FixedSize, Read, Write};
use commonware_runtime::{buffer::PoolRef, Metrics, Storage};
use commonware_utils::NZUsize;
use futures::{stream, Stream, StreamExt as _};
use std::{
    num::{NonZeroU64, NonZeroUsize},
    pin::Pin,
};
use tracing::info;

const REPLAY_BUFFER_SIZE: NonZeroUsize = NZUsize!(1024);

/// Location of an item in the variable journal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Location {
    /// Section number where the item is stored
    section: u64,

    /// Offset within the section (u32, aligned to 16 bytes)
    offset: u32,
}

impl Write for Location {
    fn write(&self, buf: &mut impl BufMut) {
        buf.put_u64(self.section);
        buf.put_u32(self.offset);
    }
}

impl FixedSize for Location {
    const SIZE: usize = u64::SIZE + u32::SIZE;
}

impl Read for Location {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _cfg: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        if buf.remaining() < Self::SIZE {
            return Err(commonware_codec::Error::InvalidLength(buf.remaining()));
        }
        Ok(Self {
            section: buf.get_u64(),
            offset: buf.get_u32(),
        })
    }
}

/// Calculate the section number for a given position.
///
/// # Arguments
///
/// * `position` - The absolute position in the journal (must be >= `oldest_retained_pos`)
/// * `oldest_retained_pos` - The position of the first item after pruning (section-aligned)
/// * `items_per_section` - The number of items stored in each section
///
/// # Returns
///
/// The section number where the item at `position` should be stored.
///
/// # Examples
///
/// ```ignore
/// // With 10 items per section and no pruning:
/// assert_eq!(position_to_section(0, 0, 10), 0);   // position 0 -> section 0
/// assert_eq!(position_to_section(9, 0, 10), 0);   // position 9 -> section 0
/// assert_eq!(position_to_section(10, 0, 10), 1);  // position 10 -> section 1
/// assert_eq!(position_to_section(25, 0, 10), 2);  // position 25 -> section 2
///
/// // After pruning sections 0-1 (oldest_retained_pos = 20):
/// assert_eq!(position_to_section(20, 20, 10), 2); // position 20 -> section 2
/// assert_eq!(position_to_section(25, 20, 10), 2); // position 25 -> section 2
/// assert_eq!(position_to_section(30, 20, 10), 3); // position 30 -> section 3
/// ```
const fn position_to_section(
    position: u64,
    oldest_retained_pos: u64,
    items_per_section: u64,
) -> u64 {
    // Calculate position relative to the oldest retained position
    let relative_position = position - oldest_retained_pos;

    // Determine the section: base section number (from oldest_retained_pos)
    // plus the section offset (from relative_position)
    (relative_position / items_per_section) + (oldest_retained_pos / items_per_section)
}

/// Configuration for a contiguous variable-length journal.
#[derive(Clone)]
pub struct Config<C> {
    /// The storage partition to use for the data journal.
    pub data_partition: String,

    /// The storage partition to use for the locations journal.
    pub locations_partition: String,

    /// The number of items to store in each section.
    ///
    /// Once set, this value cannot be changed across restarts.
    /// All non-final sections will be full and synced.
    pub items_per_section: NonZeroU64,

    /// Optional compression level for stored items.
    pub compression: Option<u8>,

    /// Codec configuration for encoding/decoding items.
    pub codec_config: C,

    /// Buffer pool for caching data.
    pub buffer_pool: PoolRef,

    /// Write buffer size for each section.
    pub write_buffer: NonZeroUsize,
}

/// A contiguous wrapper around [variable::Journal] that implements an append-only log.
///
/// This wrapper manages section assignment automatically, allowing callers to append items
/// sequentially without manually tracking section numbers.
///
/// # Invariants
///
/// ## 1. Section Fullness
///
/// All non-final sections are full (`items_per_section` items) and synced. This ensures
/// that on `init()`, we only need to replay the last section to determine the exact size.
///
/// ## 2. Data Journal is Source of Truth
///
/// The data journal is always the source of truth. The locations journal is an index
/// that may temporarily diverge during crashes. Divergences are automatically
/// repaired during init():
/// * If locations.size() < data.size(): Rebuild missing locations by replaying data.
///   (This can happen if we crash after writing data journal but before writing locations journal)
/// * If locations.size() > data.size(): Rewind locations to match data size.
///   (This can happen if we crash after rewinding data journal but before rewinding locations journal)
/// * If locations.oldest_retained_pos() < data.oldest_retained_pos(): Prune locations to match
///   (This can happen if we crash after pruning data journal but before pruning locations journal)
///
/// Note that we don't recover from the case where locations.oldest_retained_pos() >
/// data.oldest_retained_pos(). This should never occur because we always prune the data journal
/// before the locations journal.
pub struct Variable<E: Storage + Metrics, V: Codec> {
    /// The underlying variable-length data journal.
    data: variable::Journal<E, V>,

    /// Index mapping positions to (section, offset) pairs within the data journal.
    locations: fixed::Journal<E, Location>,

    /// The number of items per section.
    ///
    /// # Invariant
    ///
    /// This value is immutable after initialization and must remain consistent
    /// across restarts. Changing this value will result in data loss or corruption.
    items_per_section: u64,

    /// The next position to be assigned on append (total items appended).
    ///
    /// # Invariant
    ///
    /// Always >= `oldest_retained_pos`. Equal when data journal is empty or fully pruned.
    size: u64,

    /// The position of the first item that remains after pruning.
    ///
    /// # Invariant
    ///
    /// Always section-aligned: `oldest_retained_pos % items_per_section == 0`.
    /// Never decreases (pruning only moves forward).
    oldest_retained_pos: u64,
}

impl<E: Storage + Metrics, V: Codec + Send> Variable<E, V> {
    /// Initialize a contiguous variable journal.
    ///
    /// # Crash Recovery
    ///
    /// The data journal is the source of truth. If the locations index is inconsistent
    /// it will be updated to match the data journal.
    pub async fn init(context: E, cfg: Config<V::Cfg>) -> Result<Self, Error> {
        // Validate that partitions are different to prevent blob name collisions
        if cfg.data_partition == cfg.locations_partition {
            return Err(Error::InvalidConfiguration(format!(
                "partition and locations_partition must be different: both are '{}'",
                cfg.data_partition
            )));
        }

        let items_per_section = cfg.items_per_section.get();

        // Initialize underlying variable data journal
        let mut data = variable::Journal::init(
            context.clone(),
            variable::Config {
                partition: cfg.data_partition,
                compression: cfg.compression,
                codec_config: cfg.codec_config,
                buffer_pool: cfg.buffer_pool.clone(),
                write_buffer: cfg.write_buffer,
            },
        )
        .await?;

        // Initialize locations journal
        let mut locations = fixed::Journal::init(
            context,
            fixed::Config {
                partition: cfg.locations_partition,
                items_per_blob: cfg.items_per_section,
                buffer_pool: cfg.buffer_pool,
                write_buffer: cfg.write_buffer,
            },
        )
        .await?;

        // Validate and repair locations journal to match data journal
        let (oldest_retained_pos, size) =
            Self::repair_journals(&mut data, &mut locations, items_per_section).await?;

        Ok(Self {
            data,
            locations,
            items_per_section,
            size,
            oldest_retained_pos,
        })
    }

    /// Rewind the journal to the given size, discarding items from the end.
    ///
    /// After rewinding to size N, the journal will contain exactly N items,
    /// and the next append will receive position N.
    ///
    /// # Errors
    ///
    /// Returns [Error::InvalidRewind] if size is invalid (too large or points to pruned data).
    /// Returns an error if the underlying storage operation fails.
    ///
    /// Errors may leave the journal in an inconsistent state. The journal should be closed and
    /// reopened to trigger repair in [Variable::init].
    pub async fn rewind(&mut self, size: u64) -> Result<(), Error> {
        // Validate rewind target
        match size.cmp(&self.size) {
            std::cmp::Ordering::Greater => return Err(Error::InvalidRewind(size)),
            std::cmp::Ordering::Equal => return Ok(()), // No-op
            std::cmp::Ordering::Less => {}
        }

        // Rewind never updates oldest_retained_pos.
        if size < self.oldest_retained_pos {
            return Err(Error::InvalidRewind(size));
        }

        // Read the location of the first item to discard (at position 'size').
        let discard_location = self.locations.read(size).await?;

        self.data
            .rewind_to_offset(discard_location.section, discard_location.offset)
            .await?;
        self.locations.rewind(size).await?;

        // Update our size
        self.size = size;

        Ok(())
    }

    /// Append a new item to the journal, returning its position.
    ///
    /// The position returned is a stable, consecutively increasing value starting from 0.
    /// This position is independent of section boundaries and remains constant even after
    /// pruning.
    ///
    /// When a section becomes full, both the data journal and locations journal are synced
    /// to maintain the invariant that all non-final sections are full and consistent.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying storage operation fails or if the item cannot
    /// be encoded.
    ///
    /// Errors may leave the journal in an inconsistent state. The journal should be closed and
    /// reopened to trigger repair in [Variable::init].
    pub async fn append(&mut self, item: V) -> Result<u64, Error> {
        // Calculate which section this position belongs to
        let section = self.current_section();

        // Append to data journal, get offset
        let (offset, _size) = self.data.append(section, item).await?;

        // Append location to locations journal
        let locations_pos = self.locations.append(Location { section, offset }).await?;
        assert_eq!(locations_pos, self.size);

        // Return the current position
        let position = self.size;
        self.size += 1;

        // Maintain invariant that all full sections are synced.
        if self.size.is_multiple_of(self.items_per_section) {
            self.data.sync(section).await?;
            self.locations.sync().await?;
        }

        Ok(position)
    }

    /// Return the total number of items that have been appended to the journal.
    ///
    /// This count is NOT affected by pruning. The next appended item will receive this
    /// position as its value.
    pub async fn size(&self) -> Result<u64, Error> {
        Ok(self.size)
    }

    /// Return the position of the oldest item still retained in the journal.
    ///
    /// Returns `None` if the journal is empty or if all items have been pruned.
    pub async fn oldest_retained_pos(&self) -> Result<Option<u64>, Error> {
        if self.size == self.oldest_retained_pos {
            // No items retained: either never had data or fully pruned
            Ok(None)
        } else {
            Ok(Some(self.oldest_retained_pos))
        }
    }

    /// Prune items at positions strictly less than `min_position`.
    ///
    /// Returns `true` if any data was pruned, `false` otherwise.
    ///
    /// This prunes both the data journal and the locations journal to maintain consistency.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying storage operation fails.
    ///
    /// Errors may leave the journal in an inconsistent state. The journal should be closed and
    /// reopened to trigger repair in [Variable::init].
    pub async fn prune(&mut self, min_position: u64) -> Result<bool, Error> {
        if min_position <= self.oldest_retained_pos {
            return Ok(false);
        }

        // Cap min_position to size to maintain the invariant oldest_retained_pos <= size
        let min_position = min_position.min(self.size);

        // Calculate section number
        let min_section = min_position / self.items_per_section;

        let pruned = self.data.prune(min_section).await?;
        if pruned {
            self.oldest_retained_pos = min_section * self.items_per_section;
            self.locations.prune(self.oldest_retained_pos).await?;
        }
        Ok(pruned)
    }

    /// Return a stream of all items in the journal starting from `start_pos`.
    ///
    /// Each item is yielded as a tuple `(position, item)` where position is the item's
    /// position in the journal.
    ///
    /// # Errors
    ///
    /// Returns an error if `start_pos` exceeds the journal size or if any storage/decoding
    /// errors occur during replay.
    pub async fn replay(
        &self,
        start_pos: u64,
        buffer_size: NonZeroUsize,
    ) -> Result<Pin<Box<dyn Stream<Item = Result<(u64, V), Error>> + Send + '_>>, Error> {
        // Validate start position is within bounds.
        if start_pos < self.oldest_retained_pos {
            return Err(Error::ItemPruned(start_pos));
        }
        if start_pos > self.size {
            return Err(Error::ItemOutOfRange(start_pos));
        }

        // If replaying at exactly size, return empty stream
        if start_pos == self.size {
            return Ok(Box::pin(stream::empty()));
        }

        // Use locations index to find section/offset to start from
        let location = self.locations.read(start_pos).await?;
        let data_stream = self
            .data
            .replay(location.section, location.offset, buffer_size)
            .await?;

        // Transform the stream to include position information
        let transformed = data_stream.enumerate().map(move |(idx, result)| {
            result.map(|(_section, _offset, _size, item)| {
                // Calculate position: start_pos + items read
                let pos = start_pos + idx as u64;
                (pos, item)
            })
        });

        Ok(Box::pin(transformed))
    }

    /// Read the item at the given position.
    ///
    /// # Errors
    ///
    /// - Returns [Error::ItemPruned] if the item at `position` has been pruned.
    /// - Returns [Error::ItemOutOfRange] if `position` is beyond the journal size.
    /// - Returns other errors if storage or decoding fails.
    pub async fn read(&self, position: u64) -> Result<V, Error> {
        // Check bounds
        if position >= self.size {
            return Err(Error::ItemOutOfRange(position));
        }

        if position < self.oldest_retained_pos {
            return Err(Error::ItemPruned(position));
        }

        // Read location from index
        let location = self.locations.read(position).await?;

        // Read item from data journal using the location
        self.data.get(location.section, location.offset).await
    }

    /// Sync only the data journal to storage, without syncing the locations index.
    ///
    /// This is faster than `sync()` and can be used to ensure data durability without
    /// the overhead of syncing the locations index.
    ///
    /// We call `sync` when appending to a section, so the locations journal will eventually be
    /// synced as well, maintaining the invariant that all non-final sections are fully synced.
    /// In other words, the journal will remain in a consistent, recoverable state even if a crash
    /// occurs after calling this method but before calling `sync`.
    pub async fn sync_data(&mut self) -> Result<(), Error> {
        // Sync only the current (final) section of the data journal.
        // All non-final sections are already synced per Invariant #1.
        let section = self.current_section();
        if self.data.blobs.contains_key(&section) {
            self.data.sync(section).await?;
        }
        Ok(())
    }

    /// Sync all pending writes to storage.
    ///
    /// This syncs both the data journal and the locations journal.
    pub async fn sync(&mut self) -> Result<(), Error> {
        // Sync data journal
        self.sync_data().await?;

        // Sync locations journal
        self.locations.sync().await?;

        Ok(())
    }

    /// Close the journal, syncing all pending writes.
    ///
    /// This closes both the data journal and the locations journal.
    pub async fn close(mut self) -> Result<(), Error> {
        self.sync().await?;
        self.data.close().await?;
        self.locations.close().await
    }

    /// Remove any underlying blobs created by the journal.
    ///
    /// This destroys both the data journal and the locations journal.
    pub async fn destroy(self) -> Result<(), Error> {
        self.data.destroy().await?;
        self.locations.destroy().await
    }

    /// Return the section number where the next append will write.
    const fn current_section(&self) -> u64 {
        position_to_section(self.size, self.oldest_retained_pos, self.items_per_section)
    }

    /// Repair the locations journal and data journal to be consistent in case a crash occured
    /// on a previous run and left the journals in an inconsistent state.
    ///
    /// The data journal is the source of truth. This function scans it to determine
    /// what SHOULD be in the locations journal, then fixes any mismatches.
    ///
    /// # Returns
    ///
    /// Returns `(oldest_retained_pos, size)` for the contiguous journal.
    async fn repair_journals(
        data: &mut variable::Journal<E, V>,
        locations: &mut fixed::Journal<E, Location>,
        items_per_section: u64,
    ) -> Result<(u64, u64), Error> {
        // === Handle empty data journal case ===
        let items_in_last_section = match data.blobs.last_key_value() {
            Some((last_section, _)) => {
                let stream = data.replay(*last_section, 0, REPLAY_BUFFER_SIZE).await?;
                futures::pin_mut!(stream);
                let mut count = 0u64;
                while let Some(result) = stream.next().await {
                    result?; // Propagate replay errors (corruption, etc.)
                    count += 1;
                }
                count
            }
            None => 0,
        };

        // Data journal is empty if there are no sections or if there is one section and it has no items.
        // The latter should only occur if a crash occured after opening a data journal blob but
        // before writing to it.
        let data_empty =
            data.blobs.is_empty() || (data.blobs.len() == 1 && items_in_last_section == 0);
        if data_empty {
            let size = locations.size().await?;

            if !data.blobs.is_empty() {
                // A section exists but contains 0 items. This can happen in two cases:
                // 1. Rewind crash: we rewound the data journal but crashed before rewinding locations
                // 2. First append crash: we opened the first section blob but crashed before writing to it
                // In both cases, calculate target position from the first remaining section
                let first_section = *data.blobs.first_key_value().unwrap().0;
                let target_pos = first_section * items_per_section;

                info!("crash repair: rewinding locations from {size} to {target_pos}");
                locations.rewind(target_pos).await?;
                locations.sync().await?;
                return Ok((target_pos, target_pos));
            }

            // data.blobs is empty. This can happen in two cases:
            // 1. Rewind crash: we completely pruned the data journal but crashed before rewinding
            //    the locations journal.
            // 2. The data journal was never opened.
            if let Some(oldest) = locations.oldest_retained_pos().await? {
                if oldest < size {
                    // Locations has unpruned entries but data is gone - repair by pruning
                    info!("crash repair: pruning locations to {size} (prune-all crash)");
                    locations.prune(size).await?;
                    locations.sync().await?;
                }
            }

            return Ok((size, size));
        }

        // === Handle non-empty data journal case ===
        let (data_oldest_pos, data_size) = {
            // Data exists -- count items
            let first_section = *data.blobs.first_key_value().unwrap().0;
            let last_section = *data.blobs.last_key_value().unwrap().0;

            let oldest_pos = first_section * items_per_section;

            // Invariant 1 on `Variable` guarantees that all sections except possibly the last
            // are full. Therefore, the size of the journal is the number of items in the last
            // section plus the number of items in the other sections.
            let size = (last_section * items_per_section) + items_in_last_section;
            (oldest_pos, size)
        };
        assert_ne!(
            data_oldest_pos, data_size,
            "data journal expected to be non-empty"
        );

        // Align pruning state. We always prune the data journal before the locations journal,
        // so we validate that invariant and repair crash faults or detect corruption.
        match locations.oldest_retained_pos().await? {
            Some(oldest_retained_pos) if oldest_retained_pos < data_oldest_pos => {
                // Locations behind on pruning -- prune to catch up
                info!("crash repair: pruning locations journal to {data_oldest_pos}");
                locations.prune(data_oldest_pos).await?;
            }
            Some(oldest_retained_pos) if oldest_retained_pos > data_oldest_pos => {
                return Err(Error::Corruption(format!(
                    "locations oldest pos ({oldest_retained_pos}) > data oldest pos ({data_oldest_pos})"
                )));
            }
            Some(_) => {
                // Both journals are pruned to the same position.
            }
            None if data_oldest_pos > 0 => {
                return Err(Error::Corruption(
                    "locations journal unexpectedly empty".to_string(),
                ));
            }
            None => {
                // Both journals are empty/fully pruned.
            }
        }

        let locations_size = locations.size().await?;
        if locations_size > data_size {
            // We must have crashed after rewinding the journal and writing the rewound data
            // journal but before writing the rewound locations journal.
            info!("crash repair: rewinding locations from {locations_size} to {data_size}");
            locations.rewind(data_size).await?;
        } else if locations_size < data_size {
            // We must have crashed after writing the data journal but before writing the locations
            // journal.
            Self::add_missing_locations(data, locations, locations_size).await?;
        }

        assert_eq!(locations.size().await?, data_size);
        // Oldest retained position is always Some because the data journal is non-empty.
        assert_eq!(
            locations.oldest_retained_pos().await?,
            Some(data_oldest_pos)
        );

        locations.sync().await?;
        Ok((data_oldest_pos, data_size))
    }

    /// Rebuild missing location entries by replaying the data journal and
    /// appending the missing entries to the locations journal.
    ///
    /// The data journal is the source of truth. This function brings the locations
    /// journal up to date by replaying data items and indexing their positions.
    ///
    /// # Invariants
    ///
    /// - `data.blobs` must not be empty (data journal has at least one section)
    /// - `locations_size < data.size()` (locations is behind data)
    async fn add_missing_locations(
        data: &variable::Journal<E, V>,
        locations: &mut fixed::Journal<E, Location>,
        locations_size: u64,
    ) -> Result<(), Error> {
        assert!(
            !data.blobs.is_empty(),
            "rebuild_locations called with empty data journal"
        );

        // Find where to start replaying
        let (start_section, resume_offset, skip_first) =
            if let Some(oldest) = locations.oldest_retained_pos().await? {
                if oldest < locations_size {
                    // Locations has items -- resume from last indexed position
                    let last_loc = locations.read(locations_size - 1).await?;
                    (last_loc.section, last_loc.offset, true)
                } else {
                    // Locations fully pruned but data has items -- start from first data section
                    // SAFETY: data.blobs is non-empty (checked above)
                    let first_section = *data.blobs.first_key_value().unwrap().0;
                    (first_section, 0, false)
                }
            } else {
                // Locations empty -- start from first data section
                // SAFETY: data.blobs is non-empty (checked above)
                let first_section = *data.blobs.first_key_value().unwrap().0;
                (first_section, 0, false)
            };

        // Replay data journal from start position through the end and index all items.
        // The data journal is the source of truth, so we consume the entire stream.
        // (replay streams from start_section onwards through all subsequent sections)
        let stream = data
            .replay(start_section, resume_offset, REPLAY_BUFFER_SIZE)
            .await?;
        futures::pin_mut!(stream);

        let mut skipped_first = false;
        while let Some(result) = stream.next().await {
            let (section, offset, _size, _item) = result?;

            // Skip first item if resuming from last indexed location
            if skip_first && !skipped_first {
                skipped_first = true;
                continue;
            }

            locations.append(Location { section, offset }).await?;
        }

        Ok(())
    }
}

// Implement Contiguous trait for Variable
impl<E: Storage + Metrics, V: Codec + Send + Sync> Contiguous for Variable<E, V> {
    type Item = V;

    async fn append(&mut self, item: Self::Item) -> Result<u64, Error> {
        Variable::append(self, item).await
    }

    async fn size(&self) -> Result<u64, Error> {
        Variable::size(self).await
    }

    async fn oldest_retained_pos(&self) -> Result<Option<u64>, Error> {
        Variable::oldest_retained_pos(self).await
    }

    async fn prune(&mut self, min_position: u64) -> Result<bool, Error> {
        Variable::prune(self, min_position).await
    }

    async fn replay(
        &self,
        start_pos: u64,
        buffer: NonZeroUsize,
    ) -> Result<impl Stream<Item = Result<(u64, Self::Item), Error>> + '_, Error> {
        Variable::replay(self, start_pos, buffer).await
    }

    async fn read(&self, position: u64) -> Result<Self::Item, Error> {
        Variable::read(self, position).await
    }

    async fn sync(&mut self) -> Result<(), Error> {
        Variable::sync(self).await
    }

    async fn close(self) -> Result<(), Error> {
        Variable::close(self).await
    }

    async fn destroy(self) -> Result<(), Error> {
        Variable::destroy(self).await
    }

    async fn rewind(&mut self, size: u64) -> Result<(), Error> {
        Variable::rewind(self, size).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::journal::contiguous::tests::run_contiguous_tests;
    use commonware_macros::test_traced;
    use commonware_runtime::{buffer::PoolRef, deterministic, Runner};
    use commonware_utils::{NZUsize, NZU64};
    use futures::FutureExt as _;
    use test_case::test_case;

    // No pruning cases
    #[test_case(0, 0, 10, 0; "first section start")]
    #[test_case(5, 0, 10, 0; "first section middle")]
    #[test_case(9, 0, 10, 0; "first section end")]
    #[test_case(10, 0, 10, 1; "second section start")]
    #[test_case(15, 0, 10, 1; "second section middle")]
    #[test_case(19, 0, 10, 1; "second section end")]
    #[test_case(20, 0, 10, 2; "third section start")]
    #[test_case(25, 0, 10, 2; "third section middle")]
    #[test_case(29, 0, 10, 2; "third section end")]
    // After pruning one section
    #[test_case(10, 10, 10, 1; "after prune one: section 1 start")]
    #[test_case(15, 10, 10, 1; "after prune one: section 1 middle")]
    #[test_case(19, 10, 10, 1; "after prune one: section 1 end")]
    #[test_case(20, 10, 10, 2; "after prune one: section 2 start")]
    #[test_case(25, 10, 10, 2; "after prune one: section 2 middle")]
    #[test_case(29, 10, 10, 2; "after prune one: section 2 end")]
    // After pruning two sections
    #[test_case(20, 20, 10, 2; "after prune two: section 2 start")]
    #[test_case(25, 20, 10, 2; "after prune two: section 2 middle")]
    #[test_case(29, 20, 10, 2; "after prune two: section 2 end")]
    #[test_case(30, 20, 10, 3; "after prune two: section 3 start")]
    #[test_case(35, 20, 10, 3; "after prune two: section 3 middle")]
    #[test_case(39, 20, 10, 3; "after prune two: section 3 end")]
    // Section boundaries
    #[test_case(0, 0, 10, 0; "boundary: position 0")]
    #[test_case(10, 0, 10, 1; "boundary: position 10")]
    #[test_case(20, 0, 10, 2; "boundary: position 20")]
    #[test_case(30, 0, 10, 3; "boundary: position 30")]
    #[test_case(10, 10, 10, 1; "boundary after prune: base 10")]
    #[test_case(20, 10, 10, 2; "boundary after prune: position 20")]
    #[test_case(30, 10, 10, 3; "boundary after prune: position 30")]
    #[test_case(20, 20, 10, 2; "boundary after prune: base 20")]
    #[test_case(30, 20, 10, 3; "boundary after prune: position 30 base 20")]
    #[test_case(40, 20, 10, 4; "boundary after prune: position 40")]
    // Edge case: 1 item per section
    #[test_case(0, 0, 1, 0; "1 item: position 0")]
    #[test_case(1, 0, 1, 1; "1 item: position 1")]
    #[test_case(2, 0, 1, 2; "1 item: position 2")]
    #[test_case(10, 0, 1, 10; "1 item: position 10")]
    #[test_case(5, 5, 1, 5; "1 item after prune: position 5")]
    #[test_case(6, 5, 1, 6; "1 item after prune: position 6")]
    #[test_case(10, 5, 1, 10; "1 item after prune: position 10")]
    // Position equals oldest_retained_pos
    #[test_case(0, 0, 10, 0; "position equals base: 0")]
    #[test_case(10, 10, 10, 1; "position equals base: 10")]
    #[test_case(20, 20, 10, 2; "position equals base: 20")]
    #[test_case(100, 100, 10, 10; "position equals base: 100")]
    fn test_position_to_section_mapping(
        position: u64,
        oldest_retained_pos: u64,
        items_per_section: u64,
        expected_section: u64,
    ) {
        assert_eq!(
            position_to_section(position, oldest_retained_pos, items_per_section),
            expected_section
        );
    }

    /// Test that complete locations partition loss after pruning is detected as unrecoverable.
    ///
    /// When the locations partition is completely lost and the data has been pruned, we cannot
    /// rebuild the index with correct position alignment (would require creating placeholder blobs).
    /// This is a genuine external failure that should be detected and reported clearly.
    #[test_traced]
    fn test_variable_locations_partition_loss_after_prune_unrecoverable() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                data_partition: "locations_loss_after_prune".to_string(),
                locations_partition: "locations_loss_after_prune_locations".to_string(),
                items_per_section: NZU64!(10),
                compression: None,
                codec_config: (),
                buffer_pool: PoolRef::new(NZUsize!(1024), NZUsize!(10)),
                write_buffer: NZUsize!(1024),
            };

            // === Phase 1: Create journal with data and prune ===
            let mut journal = Variable::<_, u64>::init(context.clone(), cfg.clone())
                .await
                .unwrap();

            // Append 40 items across 4 sections (0-3)
            for i in 0..40u64 {
                journal.append(i * 100).await.unwrap();
            }

            // Prune to position 20 (removes sections 0-1, keeps sections 2-3)
            journal.prune(20).await.unwrap();
            assert_eq!(journal.oldest_retained_pos().await.unwrap(), Some(20));
            assert_eq!(journal.size().await.unwrap(), 40);

            journal.close().await.unwrap();

            // === Phase 2: Simulate complete locations partition loss ===
            context
                .remove(&cfg.locations_partition, None)
                .await
                .expect("Failed to remove locations partition");

            // === Phase 3: Verify this is detected as unrecoverable ===
            let result = Variable::<_, u64>::init(context.clone(), cfg.clone()).await;
            assert!(matches!(result, Err(Error::Corruption(_))));
        });
    }

    /// Test that init repairs state when data is pruned/lost but locations survives.
    ///
    /// This handles both:
    /// 1. Crash during prune-all (data pruned, locations not yet)
    /// 2. External data partition loss
    ///
    /// In both cases, we repair by pruning locations to match.
    #[test_traced]
    fn test_variable_repair_data_locations_mismatch() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                data_partition: "data_loss_test".to_string(),
                locations_partition: "data_loss_test_locations".to_string(),
                items_per_section: NZU64!(10),
                compression: None,
                codec_config: (),
                buffer_pool: PoolRef::new(NZUsize!(1024), NZUsize!(10)),
                write_buffer: NZUsize!(1024),
            };

            // === Setup: Create journal with data ===
            let mut variable = Variable::<_, u64>::init(context.clone(), cfg.clone())
                .await
                .unwrap();

            // Append 20 items across 2 sections
            for i in 0..20u64 {
                variable.append(i * 100).await.unwrap();
            }

            variable.close().await.unwrap();

            // === Simulate data loss: Delete data partition but keep locations ===
            context
                .remove(&cfg.data_partition, None)
                .await
                .expect("Failed to remove data partition");

            // === Verify init repairs the mismatch ===
            let mut journal = Variable::<_, u64>::init(context.clone(), cfg.clone())
                .await
                .expect("Should repair locations to match empty data");

            // Size should be preserved
            assert_eq!(journal.size().await.unwrap(), 20);

            // But no items remain (both journals pruned)
            assert_eq!(journal.oldest_retained_pos().await.unwrap(), None);

            // All reads should fail with ItemPruned
            for i in 0..20 {
                assert!(matches!(
                    journal.read(i).await,
                    Err(crate::journal::Error::ItemPruned(_))
                ));
            }

            // Can append new data starting at position 20
            let pos = journal.append(999).await.unwrap();
            assert_eq!(pos, 20);
            assert_eq!(journal.read(20).await.unwrap(), 999);

            journal.destroy().await.unwrap();
        });
    }

    /// Test that init rejects when partition and locations_partition are the same.
    ///
    /// This prevents blob name collisions between data and locations journals.
    #[test_traced]
    fn test_variable_reject_same_partitions() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                data_partition: "same_partition".to_string(),
                locations_partition: "same_partition".to_string(), // Same as partition!
                items_per_section: NZU64!(10),
                compression: None,
                codec_config: (),
                buffer_pool: PoolRef::new(NZUsize!(1024), NZUsize!(10)),
                write_buffer: NZUsize!(1024),
            };

            let result = Variable::<_, u64>::init(context, cfg).await;
            match result {
                Err(e) => {
                    let err_msg = format!("{e}");
                    assert!(err_msg.contains("partition and locations_partition must be different"));
                }
                Ok(_) => panic!("Should reject identical partitions"),
            }
        });
    }

    #[test_traced]
    fn test_variable_contiguous() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            run_contiguous_tests(move |test_name: String| {
                let context = context.clone();
                async move {
                    Variable::<_, u64>::init(
                        context,
                        Config {
                            data_partition: format!("generic_test_{}", test_name),
                            locations_partition: format!("generic_test_{}_locations", test_name),
                            items_per_section: NZU64!(10),
                            compression: None,
                            codec_config: (),
                            buffer_pool: PoolRef::new(NZUsize!(1024), NZUsize!(10)),
                            write_buffer: NZUsize!(1024),
                        },
                    )
                    .await
                }
                .boxed()
            })
            .await;
        });
    }

    /// Test multiple sequential prunes with Variable-specific guarantees.
    #[test_traced]
    fn test_variable_multiple_sequential_prunes() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                data_partition: "sequential_prunes".to_string(),
                locations_partition: "sequential_prunes_locations".to_string(),
                items_per_section: NZU64!(10),
                compression: None,
                codec_config: (),
                buffer_pool: PoolRef::new(NZUsize!(1024), NZUsize!(10)),
                write_buffer: NZUsize!(1024),
            };

            let mut journal = Variable::<_, u64>::init(context, cfg).await.unwrap();

            // Append items across 4 sections: [0-9], [10-19], [20-29], [30-39]
            for i in 0..40u64 {
                journal.append(i * 100).await.unwrap();
            }

            // Initial state: all items accessible
            assert_eq!(journal.oldest_retained_pos().await.unwrap(), Some(0));
            assert_eq!(journal.size().await.unwrap(), 40);

            // First prune: remove section 0 (positions 0-9)
            let pruned = journal.prune(10).await.unwrap();
            assert!(pruned);

            // Variable-specific guarantee: oldest is EXACTLY at section boundary
            let oldest = journal.oldest_retained_pos().await.unwrap().unwrap();
            assert_eq!(oldest, 10);

            // Items 0-9 should be pruned, 10+ should be accessible
            assert!(matches!(
                journal.read(0).await,
                Err(crate::journal::Error::ItemPruned(_))
            ));
            assert_eq!(journal.read(10).await.unwrap(), 1000);
            assert_eq!(journal.read(19).await.unwrap(), 1900);

            // Second prune: remove section 1 (positions 10-19)
            let pruned = journal.prune(20).await.unwrap();
            assert!(pruned);

            // Variable-specific guarantee: oldest is EXACTLY at section boundary
            let oldest = journal.oldest_retained_pos().await.unwrap().unwrap();
            assert_eq!(oldest, 20);

            // Items 0-19 should be pruned, 20+ should be accessible
            assert!(matches!(
                journal.read(10).await,
                Err(crate::journal::Error::ItemPruned(_))
            ));
            assert!(matches!(
                journal.read(19).await,
                Err(crate::journal::Error::ItemPruned(_))
            ));
            assert_eq!(journal.read(20).await.unwrap(), 2000);
            assert_eq!(journal.read(29).await.unwrap(), 2900);

            // Third prune: remove section 2 (positions 20-29)
            let pruned = journal.prune(30).await.unwrap();
            assert!(pruned);

            // Variable-specific guarantee: oldest is EXACTLY at section boundary
            let oldest = journal.oldest_retained_pos().await.unwrap().unwrap();
            assert_eq!(oldest, 30);

            // Items 0-29 should be pruned, 30+ should be accessible
            assert!(matches!(
                journal.read(20).await,
                Err(crate::journal::Error::ItemPruned(_))
            ));
            assert!(matches!(
                journal.read(29).await,
                Err(crate::journal::Error::ItemPruned(_))
            ));
            assert_eq!(journal.read(30).await.unwrap(), 3000);
            assert_eq!(journal.read(39).await.unwrap(), 3900);

            // Size should still be 40 (pruning doesn't affect size)
            assert_eq!(journal.size().await.unwrap(), 40);

            journal.destroy().await.unwrap();
        });
    }

    /// Test that pruning all data and re-initializing preserves positions.
    #[test_traced]
    fn test_variable_prune_all_then_reinit() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                data_partition: "prune_all_reinit".to_string(),
                locations_partition: "prune_all_reinit_locations".to_string(),
                items_per_section: NZU64!(10),
                compression: None,
                codec_config: (),
                buffer_pool: PoolRef::new(NZUsize!(1024), NZUsize!(10)),
                write_buffer: NZUsize!(1024),
            };

            // === Phase 1: Create journal and append data ===
            let mut journal = Variable::<_, u64>::init(context.clone(), cfg.clone())
                .await
                .unwrap();

            for i in 0..100u64 {
                journal.append(i * 100).await.unwrap();
            }

            assert_eq!(journal.size().await.unwrap(), 100);
            assert_eq!(journal.oldest_retained_pos().await.unwrap(), Some(0));

            // === Phase 2: Prune all data ===
            let pruned = journal.prune(100).await.unwrap();
            assert!(pruned);

            // All data is pruned - no items remain
            assert_eq!(journal.size().await.unwrap(), 100);
            assert_eq!(journal.oldest_retained_pos().await.unwrap(), None);

            // All reads should fail with ItemPruned
            for i in 0..100 {
                assert!(matches!(
                    journal.read(i).await,
                    Err(crate::journal::Error::ItemPruned(_))
                ));
            }

            journal.close().await.unwrap();

            // === Phase 3: Re-init and verify position preserved ===
            let mut journal = Variable::<_, u64>::init(context.clone(), cfg.clone())
                .await
                .unwrap();

            // Size should be preserved, but no items remain
            assert_eq!(journal.size().await.unwrap(), 100);
            assert_eq!(journal.oldest_retained_pos().await.unwrap(), None);

            // All reads should still fail
            for i in 0..100 {
                assert!(matches!(
                    journal.read(i).await,
                    Err(crate::journal::Error::ItemPruned(_))
                ));
            }

            // === Phase 4: Append new data ===
            // Next append should get position 100
            journal.append(10000).await.unwrap();
            assert_eq!(journal.size().await.unwrap(), 101);
            // Now we have one item at position 100
            assert_eq!(journal.oldest_retained_pos().await.unwrap(), Some(100));

            // Can read the new item
            assert_eq!(journal.read(100).await.unwrap(), 10000);

            // Old positions still fail
            assert!(matches!(
                journal.read(99).await,
                Err(crate::journal::Error::ItemPruned(_))
            ));

            journal.destroy().await.unwrap();
        });
    }

    /// Test recovery from crash after data journal pruned but before locations journal.
    #[test_traced]
    fn test_variable_recovery_prune_crash_locations_behind() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // === Setup: Create Variable wrapper with data ===
            let cfg = Config {
                data_partition: "recovery_prune_crash".to_string(),
                locations_partition: "recovery_prune_crash_locations".to_string(),
                items_per_section: NZU64!(10),
                compression: None,
                codec_config: (),
                buffer_pool: PoolRef::new(NZUsize!(1024), NZUsize!(10)),
                write_buffer: NZUsize!(1024),
            };

            let mut variable = Variable::<_, u64>::init(context.clone(), cfg.clone())
                .await
                .unwrap();

            // Append 40 items across 4 sections to both journals
            for i in 0..40u64 {
                variable.append(i * 100).await.unwrap();
            }

            // Prune to position 10 normally (both data and locations journals pruned)
            variable.prune(10).await.unwrap();
            assert_eq!(variable.oldest_retained_pos().await.unwrap(), Some(10));

            // === Simulate crash: Prune data journal but not locations journal ===
            // Manually prune data journal to section 2 (position 20)
            variable.data.prune(2).await.unwrap();
            // Locations journal still has data from position 10-19

            variable.close().await.unwrap();

            // === Verify recovery ===
            let variable = Variable::<_, u64>::init(context.clone(), cfg.clone())
                .await
                .unwrap();

            // Init should auto-repair: locations journal pruned to match data journal
            assert_eq!(variable.oldest_retained_pos().await.unwrap(), Some(20));
            assert_eq!(variable.size().await.unwrap(), 40);

            // Reads before position 20 should fail (pruned from both journals)
            assert!(matches!(
                variable.read(10).await,
                Err(crate::journal::Error::ItemPruned(_))
            ));

            // Reads at position 20+ should succeed
            assert_eq!(variable.read(20).await.unwrap(), 2000);
            assert_eq!(variable.read(39).await.unwrap(), 3900);

            variable.destroy().await.unwrap();
        });
    }

    /// Test recovery detects corruption when locations journal pruned ahead of data journal.
    ///
    /// Simulates an impossible state (locations journal pruned more than data journal) which
    /// should never happen due to write ordering. Verifies that init() returns corruption error.
    #[test_traced]
    fn test_variable_recovery_locations_ahead_corruption() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // === Setup: Create Variable wrapper with data ===
            let cfg = Config {
                data_partition: "recovery_locations_ahead".to_string(),
                locations_partition: "recovery_locations_ahead_locations".to_string(),
                items_per_section: NZU64!(10),
                compression: None,
                codec_config: (),
                buffer_pool: PoolRef::new(NZUsize!(1024), NZUsize!(10)),
                write_buffer: NZUsize!(1024),
            };

            let mut variable = Variable::<_, u64>::init(context.clone(), cfg.clone())
                .await
                .unwrap();

            // Append 40 items across 4 sections to both journals
            for i in 0..40u64 {
                variable.append(i * 100).await.unwrap();
            }

            // Prune locations journal ahead of data journal (impossible state)
            variable.locations.prune(20).await.unwrap(); // Prune to position 20
            variable.data.prune(1).await.unwrap(); // Only prune data journal to section 1 (position 10)

            variable.close().await.unwrap();

            // === Verify corruption detected ===
            let result = Variable::<_, u64>::init(context.clone(), cfg.clone()).await;
            assert!(matches!(result, Err(Error::Corruption(_))));
        });
    }

    /// Test recovery from crash after appending to data journal but before appending to locations journal.
    #[test_traced]
    fn test_variable_recovery_append_crash_locations_behind() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // === Setup: Create Variable wrapper with partial data ===
            let cfg = Config {
                data_partition: "recovery_append_crash".to_string(),
                locations_partition: "recovery_append_crash_locations".to_string(),
                items_per_section: NZU64!(10),
                compression: None,
                codec_config: (),
                buffer_pool: PoolRef::new(NZUsize!(1024), NZUsize!(10)),
                write_buffer: NZUsize!(1024),
            };

            let mut variable = Variable::<_, u64>::init(context.clone(), cfg.clone())
                .await
                .unwrap();

            // Append 15 items to both journals (fills section 0, partial section 1)
            for i in 0..15u64 {
                variable.append(i * 100).await.unwrap();
            }

            assert_eq!(variable.size().await.unwrap(), 15);

            // Manually append 5 more items directly to data journal only
            for i in 15..20u64 {
                variable.data.append(1, i * 100).await.unwrap();
            }
            // Locations journal still has only 15 entries

            variable.close().await.unwrap();

            // === Verify recovery ===
            let variable = Variable::<_, u64>::init(context.clone(), cfg.clone())
                .await
                .unwrap();

            // Init should rebuild locations journal from data journal replay
            assert_eq!(variable.size().await.unwrap(), 20);
            assert_eq!(variable.oldest_retained_pos().await.unwrap(), Some(0));

            // All items should be readable from both journals
            for i in 0..20u64 {
                assert_eq!(variable.read(i).await.unwrap(), i * 100);
            }

            // Locations journal should be fully rebuilt to match data journal
            assert_eq!(variable.locations.size().await.unwrap(), 20);

            variable.destroy().await.unwrap();
        });
    }

    /// Test recovery from multiple prune operations with crash.
    #[test_traced]
    fn test_variable_recovery_multiple_prunes_crash() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // === Setup: Create Variable wrapper with data ===
            let cfg = Config {
                data_partition: "recovery_multiple_prunes".to_string(),
                locations_partition: "recovery_multiple_prunes_locations".to_string(),
                items_per_section: NZU64!(10),
                compression: None,
                codec_config: (),
                buffer_pool: PoolRef::new(NZUsize!(1024), NZUsize!(10)),
                write_buffer: NZUsize!(1024),
            };

            let mut variable = Variable::<_, u64>::init(context.clone(), cfg.clone())
                .await
                .unwrap();

            // Append 50 items across 5 sections to both journals
            for i in 0..50u64 {
                variable.append(i * 100).await.unwrap();
            }

            // Prune to position 10 normally (both data and locations journals pruned)
            variable.prune(10).await.unwrap();
            assert_eq!(variable.oldest_retained_pos().await.unwrap(), Some(10));

            // === Simulate crash: Multiple prunes on data journal, not on locations journal ===
            // Manually prune data journal to section 3 (position 30)
            variable.data.prune(3).await.unwrap();
            // Locations journal still thinks oldest is position 10

            variable.close().await.unwrap();

            // === Verify recovery ===
            let variable = Variable::<_, u64>::init(context.clone(), cfg.clone())
                .await
                .unwrap();

            // Init should auto-repair: locations journal pruned to match data journal
            assert_eq!(variable.oldest_retained_pos().await.unwrap(), Some(30));
            assert_eq!(variable.size().await.unwrap(), 50);

            // Reads before position 30 should fail (pruned from both journals)
            assert!(matches!(
                variable.read(10).await,
                Err(crate::journal::Error::ItemPruned(_))
            ));
            assert!(matches!(
                variable.read(20).await,
                Err(crate::journal::Error::ItemPruned(_))
            ));

            // Reads at position 30+ should succeed
            assert_eq!(variable.read(30).await.unwrap(), 3000);
            assert_eq!(variable.read(49).await.unwrap(), 4900);

            variable.destroy().await.unwrap();
        });
    }

    /// Test recovery from crash during rewind operation.
    ///
    /// Simulates a crash after locations.rewind() completes but before data.rewind() completes.
    /// This creates a situation where locations journal has been rewound but data journal still
    /// contains items across multiple sections. Verifies that init() correctly rebuilds the
    /// locations index across all sections to match the data journal.
    #[test_traced]
    fn test_variable_recovery_rewind_crash_multi_section() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // === Setup: Create Variable wrapper with data across multiple sections ===
            let cfg = Config {
                data_partition: "recovery_rewind_crash".to_string(),
                locations_partition: "recovery_rewind_crash_locations".to_string(),
                items_per_section: NZU64!(10),
                compression: None,
                codec_config: (),
                buffer_pool: PoolRef::new(NZUsize!(1024), NZUsize!(10)),
                write_buffer: NZUsize!(1024),
            };

            let mut variable = Variable::<_, u64>::init(context.clone(), cfg.clone())
                .await
                .unwrap();

            // Append 25 items across 3 sections (section 0: 0-9, section 1: 10-19, section 2: 20-24)
            for i in 0..25u64 {
                variable.append(i * 100).await.unwrap();
            }

            assert_eq!(variable.size().await.unwrap(), 25);

            // === Simulate crash during rewind(5) ===
            // Rewind locations journal to size 5 (keeps positions 0-4)
            variable.locations.rewind(5).await.unwrap();
            // CRASH before data.rewind() completes - data still has all 3 sections

            variable.close().await.unwrap();

            // === Verify recovery ===
            let mut variable = Variable::<_, u64>::init(context.clone(), cfg.clone())
                .await
                .unwrap();

            // Init should rebuild locations[5-24] from data journal across all 3 sections
            assert_eq!(variable.size().await.unwrap(), 25);
            assert_eq!(variable.oldest_retained_pos().await.unwrap(), Some(0));

            // All items should be readable - locations rebuilt correctly across all sections
            for i in 0..25u64 {
                assert_eq!(variable.read(i).await.unwrap(), i * 100);
            }

            // Verify locations journal fully rebuilt
            assert_eq!(variable.locations.size().await.unwrap(), 25);

            // Verify next append gets position 25
            let pos = variable.append(2500).await.unwrap();
            assert_eq!(pos, 25);
            assert_eq!(variable.read(25).await.unwrap(), 2500);

            variable.destroy().await.unwrap();
        });
    }

    /// Test that locations index is rebuilt from data after sync_data + crash.
    #[test_traced]
    fn test_variable_sync_data_recovery() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                data_partition: "sync_data_recovery".to_string(),
                locations_partition: "sync_data_recovery_locations".to_string(),
                items_per_section: NZU64!(10),
                compression: None,
                codec_config: (),
                buffer_pool: PoolRef::new(NZUsize!(1024), NZUsize!(10)),
                write_buffer: NZUsize!(1024),
            };

            let mut journal = Variable::<_, u64>::init(context.clone(), cfg.clone())
                .await
                .unwrap();

            // Append items across a section boundary
            for i in 0..15u64 {
                journal.append(i * 100).await.unwrap();
            }

            // Sync data only (locations lags behind)
            journal.sync_data().await.unwrap();

            // Simulate a crash
            drop(journal);

            let journal = Variable::<_, u64>::init(context.clone(), cfg.clone())
                .await
                .unwrap();

            // Data should be intact and locations rebuilt
            assert_eq!(journal.size().await.unwrap(), 15);
            for i in 0..15u64 {
                assert_eq!(journal.read(i).await.unwrap(), i * 100);
            }

            journal.destroy().await.unwrap();
        });
    }
}
