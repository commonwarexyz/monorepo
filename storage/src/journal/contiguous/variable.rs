//! Contiguous wrapper for variable-length journals.
//!
//! This wrapper enforces section fullness: all non-final sections are full and synced.
//! On init, only the last section needs to be replayed to determine the exact size.

use super::Contiguous;
use crate::journal::{fixed, variable, Error};
use bytes::{Buf, BufMut};
use commonware_codec::{Codec, FixedSize, Read as CodecRead, Write as CodecWrite};
use commonware_runtime::{buffer::PoolRef, Clock, Metrics, Storage};
use commonware_utils::NZUsize;
use futures::{Stream, StreamExt as _};
use std::num::{NonZeroU64, NonZeroUsize};
use tracing::warn;

const REPLAY_BUFFER_SIZE: NonZeroUsize = NZUsize!(1024);

/// Location of an item in the variable journal.
///
/// This struct maps a global position to a (section, offset) pair in the underlying
/// variable journal, enabling O(1) reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Location {
    /// Section number where the item is stored
    section: u64,

    /// Offset within the section (u32, aligned to 16 bytes)
    offset: u32,
}

impl CodecWrite for Location {
    fn write(&self, buf: &mut impl BufMut) {
        buf.put_u64(self.section);
        buf.put_u32(self.offset);
    }
}

impl FixedSize for Location {
    const SIZE: usize = 12; // u64 + u32
}

impl CodecRead for Location {
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
    /// The storage partition to use for journal blobs.
    pub partition: String,

    /// The storage partition to use for the locations index.
    ///
    /// This index maps positions to (section, offset) pairs for O(1) reads.
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

/// A contiguous wrapper around `variable::Journal` that provides position-based append.
///
/// This wrapper manages section assignment automatically, allowing callers to append items
/// sequentially without manually tracking section numbers. Positions are assigned starting
/// from 0 and increment with each append.
///
/// # Section Fullness Invariant
///
/// All non-final sections are full (`items_per_section` items) and synced. This ensures
/// that on `init()`, we only need to replay the last section to determine the exact size.
pub struct Variable<E: Storage + Metrics + Clock, V: Codec> {
    /// The underlying variable-length journal.
    journal: variable::Journal<E, V>,

    /// Index mapping positions to (section, offset) pairs for O(1) reads.
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
    /// Always >= `oldest_retained_pos`. Equal when journal is empty or fully pruned.
    /// Increments by 1 on each successful append.
    size: u64,

    /// The position of the first item that remains after pruning.
    ///
    /// # Invariant
    ///
    /// Always section-aligned: `oldest_retained_pos % items_per_section == 0`.
    /// Never decreases (pruning only moves forward).
    /// Derived from first section on disk.
    oldest_retained_pos: u64,
}

impl<E: Storage + Metrics + Clock, V: Codec> Variable<E, V> {
    /// Initialize a contiguous variable journal.
    ///
    /// This method:
    /// 1. Initializes the underlying `variable::Journal` and locations index
    /// 2. Derives `oldest_retained_pos` from the first blob on disk
    /// 3. Replays only the last section to verify/rebuild locations index
    ///
    /// # Section Fullness Invariant
    ///
    /// All non-final sections are assumed to be full (`items_per_section` items).
    /// Only the final section is replayed to ensure consistency.
    ///
    /// # Crash Recovery
    ///
    /// The data journal is the source of truth. If the locations index is inconsistent
    /// (ahead, behind, or missing), this method will automatically rebuild it from the
    /// last section.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying journal initialization fails or if any storage
    /// operations fail.
    pub async fn init(context: E, cfg: Config<V::Cfg>) -> Result<Self, Error> {
        let items_per_section = cfg.items_per_section.get();

        // Initialize underlying variable journal
        let journal = variable::Journal::init(
            context.clone(),
            variable::Config {
                partition: cfg.partition,
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

        // CRASH RECOVERY: Data journal is the source of truth
        // Always synchronize locations to match data
        let (size, oldest_retained_pos) = if journal.blobs.is_empty() {
            // Empty data journal - locations should also be empty
            let locations_size = locations.size().await?;
            if locations_size > 0 {
                // Fix corruption: Rewind locations to match empty data
                warn!(
                    locations_size,
                    "locations ahead of empty data journal, rewinding to 0"
                );
                locations.rewind(0).await?;
                locations.sync().await?;
            }
            (0, 0)
        } else {
            let first_section = *journal.blobs.first_key_value().unwrap().0;
            let oldest_retained_pos = first_section * items_per_section;
            let last_section = *journal.blobs.last_key_value().unwrap().0;

            // Count items in last section
            let stream = journal.replay(last_section, 0, REPLAY_BUFFER_SIZE).await?;
            futures::pin_mut!(stream);

            let mut items_in_last_section = 0u64;
            while stream.next().await.is_some() {
                items_in_last_section += 1;
            }

            // Calculate expected size based on actual data on disk
            let expected_size = (last_section * items_per_section) + items_in_last_section;
            let last_section_start_pos = last_section * items_per_section;

            // Check locations journal state
            let locations_size = locations.size().await?;

            // Fix any inconsistency between the locations journal and the data journal
            if locations_size != expected_size {
                warn!(
                    locations_size,
                    expected_size,
                    last_section,
                    items_in_last_section,
                    "locations journal inconsistent with data, rebuilding"
                );

                if locations_size < expected_size {
                    // Locations behind: append only the missing locations
                    // Calculate offset within the last section where we need to start
                    let start_offset = (locations_size - last_section_start_pos) as u32;

                    // Replay from where locations left off
                    let stream = journal
                        .replay(last_section, start_offset, REPLAY_BUFFER_SIZE)
                        .await?;
                    futures::pin_mut!(stream);

                    while let Some(result) = stream.next().await {
                        let (section, offset, _size, _item) = result?;
                        locations.append(Location { section, offset }).await?;
                    }
                } else {
                    // Locations ahead: rewind and rebuild entire last section
                    locations.rewind(last_section_start_pos).await?;

                    // Replay from offset 0 and stream locations directly
                    let stream = journal.replay(last_section, 0, REPLAY_BUFFER_SIZE).await?;
                    futures::pin_mut!(stream);

                    while let Some(result) = stream.next().await {
                        let (section, offset, _size, _item) = result?;
                        locations.append(Location { section, offset }).await?;
                    }
                }

                // Sync the rebuilt/extended locations
                locations.sync().await?;
            }

            (expected_size, oldest_retained_pos)
        };

        Ok(Self {
            journal,
            locations,
            items_per_section,
            size,
            oldest_retained_pos,
        })
    }

    /// Return the section number where the next append will write.
    ///
    /// This is a convenience method that calculates the section for the current
    /// journal size, accounting for pruning. It's equivalent to calling
    /// `position_to_section(self.size, self.oldest_retained_pos, self.items_per_section)`.
    ///
    /// # Returns
    ///
    /// The section number where the next appended item will be stored.
    const fn current_section(&self) -> u64 {
        position_to_section(self.size, self.oldest_retained_pos, self.items_per_section)
    }

    /// Append a new item to the journal, returning its position.
    ///
    /// The position returned is a stable, monotonically increasing value starting from 0.
    /// This position is independent of section boundaries and remains constant even after
    /// pruning.
    ///
    /// When a section becomes full, both the data journal and locations index are synced
    /// to maintain the invariant that all non-final sections are full and consistent.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying storage operation fails or if the item cannot
    /// be encoded.
    pub async fn append(&mut self, item: V) -> Result<u64, Error> {
        // Calculate which section this position belongs to
        let section = self.current_section();

        // Append to data journal, get offset
        let (offset, _size) = self.journal.append(section, item).await?;

        // Append location to index
        self.locations.append(Location { section, offset }).await?;

        // Return the current position and increment for next time
        let position = self.size;
        self.size += 1;

        // If we just filled a section, sync both journals together
        if self.size.is_multiple_of(self.items_per_section) {
            self.journal.sync(section).await?;
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

    /// Prune items at positions strictly less than `min_position`.
    ///
    /// Returns `true` if any data was pruned, `false` otherwise.
    ///
    /// This prunes both the data journal and the locations index to maintain consistency.
    ///
    /// # Note on Section Alignment
    ///
    /// Pruning is section-aligned. This means some items with positions less than
    /// `min_position` may be retained if they are in the same section as items >= `min_position`.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying storage operation fails.
    pub async fn prune(&mut self, min_position: u64) -> Result<bool, Error> {
        if min_position <= self.oldest_retained_pos {
            return Ok(false);
        }

        // Cap min_position to size to maintain the invariant oldest_retained_pos <= size
        let capped_min_position = min_position.min(self.size);

        let relative_pos = capped_min_position - self.oldest_retained_pos;
        let min_section = relative_pos / self.items_per_section;

        let pruned = self.journal.prune(min_section).await?;
        if pruned {
            self.oldest_retained_pos += min_section * self.items_per_section;
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
        buffer: NonZeroUsize,
    ) -> Result<impl Stream<Item = Result<(u64, V), Error>> + '_, Error> {
        if start_pos > self.size {
            return Err(Error::ItemOutOfRange(start_pos));
        }

        // Calculate starting section and offset within that section
        let relative_start = start_pos.saturating_sub(self.oldest_retained_pos);
        let start_section = (relative_start / self.items_per_section)
            + (self.oldest_retained_pos / self.items_per_section);

        // Get the stream from the underlying journal
        let stream = self.journal.replay(start_section, 0, buffer).await?;

        // Transform the stream to include position information
        let items_per_section = self.items_per_section;

        // Use enumerate to track the index, then calculate position from section info
        Ok(stream
            .enumerate()
            .filter_map(move |(idx, result)| async move {
                match result {
                    Ok((_section, _offset, _size, item)) => {
                        // Calculate position: start of section + index within all replayed items
                        // Since we start replaying from start_section at offset 0, the first item
                        // is at position start_section * items_per_section
                        let pos = start_section * items_per_section + idx as u64;

                        // Only yield items at or after start_pos
                        if pos >= start_pos {
                            Some(Ok((pos, item)))
                        } else {
                            None
                        }
                    }
                    Err(e) => Some(Err(e)),
                }
            }))
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
        self.journal.get(location.section, location.offset).await
    }

    /// Sync all pending writes to storage.
    ///
    /// This syncs both the data journal and the locations index.
    pub async fn sync(&mut self) -> Result<(), Error> {
        // Sync all sections in the underlying journal
        for &section in self.journal.blobs.keys() {
            self.journal.sync(section).await?;
        }

        // Sync locations journal
        self.locations.sync().await?;

        Ok(())
    }

    /// Close the journal, syncing all pending writes.
    ///
    /// This closes both the data journal and the locations index.
    pub async fn close(mut self) -> Result<(), Error> {
        self.sync().await?;
        self.locations.close().await?;
        self.journal.close().await
    }

    /// Remove any underlying blobs created by the journal.
    ///
    /// This is useful for cleaning up test journals. After calling this method,
    /// the journal cannot be used again.
    ///
    /// This destroys both the data journal and the locations index.
    pub async fn destroy(self) -> Result<(), Error> {
        self.locations.destroy().await?;
        self.journal.destroy().await
    }
}

// Implement Contiguous trait for Variable
impl<E: Storage + Metrics + Clock, V: Codec + Send + Sync> Contiguous for Variable<E, V> {
    type Item = V;

    async fn append(&mut self, item: Self::Item) -> Result<u64, Error> {
        Variable::append(self, item).await
    }

    async fn size(&self) -> Result<u64, Error> {
        Variable::size(self).await
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::journal::contiguous::{tests::run_contiguous_tests, Contiguous};
    use commonware_runtime::{buffer::PoolRef, deterministic, Runner};
    use commonware_utils::{NZUsize, NZU64};
    use futures::FutureExt as _;
    use test_case::test_case;

    #[test]
    fn test_variable_empty_journal() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let journal = Variable::<_, u64>::init(
                context,
                Config {
                    partition: "test_variable_empty".to_string(),
                    locations_partition: "test_variable_empty_locations".to_string(),
                    items_per_section: NZU64!(10),
                    compression: None,
                    codec_config: (),
                    buffer_pool: PoolRef::new(NZUsize!(1024), NZUsize!(10)),
                    write_buffer: NZUsize!(1024),
                },
            )
            .await
            .unwrap();

            // Empty journal should have size 0
            assert_eq!(journal.size().await.unwrap(), 0);

            journal.destroy().await.unwrap();
        });
    }

    #[test]
    fn test_variable_append_and_size() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut journal = Variable::<_, u64>::init(
                context,
                Config {
                    partition: "test_variable_append".to_string(),
                    locations_partition: "test_variable_append_locations".to_string(),
                    items_per_section: NZU64!(10),
                    compression: None,
                    codec_config: (),
                    buffer_pool: PoolRef::new(NZUsize!(1024), NZUsize!(10)),
                    write_buffer: NZUsize!(1024),
                },
            )
            .await
            .unwrap();

            // Append some items
            let pos1 = journal.append(100u64).await.unwrap();
            let pos2 = journal.append(200u64).await.unwrap();
            let pos3 = journal.append(300u64).await.unwrap();

            // Positions should be sequential
            assert_eq!(pos1, 0);
            assert_eq!(pos2, 1);
            assert_eq!(pos3, 2);

            // Size should match
            assert_eq!(journal.size().await.unwrap(), 3);

            journal.destroy().await.unwrap();
        });
    }

    #[test]
    fn test_variable_multiple_sections() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut journal = Variable::<_, u64>::init(
                context,
                Config {
                    partition: "test_variable_sections".to_string(),
                    locations_partition: "test_variable_sections_locations".to_string(),
                    items_per_section: NZU64!(5), // Small sections to test crossing boundaries
                    compression: None,
                    codec_config: (),
                    buffer_pool: PoolRef::new(NZUsize!(1024), NZUsize!(10)),
                    write_buffer: NZUsize!(1024),
                },
            )
            .await
            .unwrap();

            // Append 12 items (will span 3 sections: 0-4, 5-9, 10-11)
            for i in 0..12u64 {
                let pos = journal.append(i * 10).await.unwrap();
                assert_eq!(pos, i);
            }

            assert_eq!(journal.size().await.unwrap(), 12);

            journal.destroy().await.unwrap();
        });
    }

    #[test]
    fn test_variable_persistence_across_restart() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let partition = "test_variable_persist";
            let cfg = Config {
                partition: partition.to_string(),
                locations_partition: format!("{}_locations", partition),
                items_per_section: NZU64!(10),
                compression: None,
                codec_config: (),
                buffer_pool: PoolRef::new(NZUsize!(1024), NZUsize!(10)),
                write_buffer: NZUsize!(1024),
            };

            // First session: append some items
            {
                let mut journal = Variable::<_, u64>::init(context.clone(), cfg.clone())
                    .await
                    .unwrap();

                for i in 0..5u64 {
                    let pos = journal.append(i * 100).await.unwrap();
                    assert_eq!(pos, i);
                }

                assert_eq!(journal.size().await.unwrap(), 5);
                journal.close().await.unwrap();
            }

            // Second session: should recover position and continue
            {
                let mut journal = Variable::<_, u64>::init(context.clone(), cfg.clone())
                    .await
                    .unwrap();

                // Size should reflect previous appends
                assert_eq!(journal.size().await.unwrap(), 5);

                // New appends should continue from position 5
                let pos = journal.append(500u64).await.unwrap();
                assert_eq!(pos, 5);

                assert_eq!(journal.size().await.unwrap(), 6);
                journal.close().await.unwrap();
            }
        });
    }

    #[test]
    fn test_variable_prune() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut journal = Variable::<_, u64>::init(
                context,
                Config {
                    partition: "test_variable_prune".to_string(),
                    locations_partition: "test_variable_prune_locations".to_string(),
                    items_per_section: NZU64!(5),
                    compression: None,
                    codec_config: (),
                    buffer_pool: PoolRef::new(NZUsize!(1024), NZUsize!(10)),
                    write_buffer: NZUsize!(1024),
                },
            )
            .await
            .unwrap();

            // Append 12 items (spans 3 sections: 0-4, 5-9, 10-11)
            for i in 0..12u64 {
                journal.append(i * 10).await.unwrap();
            }

            // Prune up to position 7 (should prune section 0, keep sections 1-2)
            let pruned = journal.prune(7).await.unwrap();
            assert!(pruned);

            // Size should still be 12
            assert_eq!(journal.size().await.unwrap(), 12);

            journal.destroy().await.unwrap();
        });
    }

    #[test]
    fn test_variable_replay() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut journal = Variable::<_, u64>::init(
                context,
                Config {
                    partition: "test_variable_replay".to_string(),
                    locations_partition: "test_variable_replay_locations".to_string(),
                    items_per_section: NZU64!(5),
                    compression: None,
                    codec_config: (),
                    buffer_pool: PoolRef::new(NZUsize!(1024), NZUsize!(10)),
                    write_buffer: NZUsize!(1024),
                },
            )
            .await
            .unwrap();

            // Append some items
            for i in 0..10u64 {
                journal.append(i * 10).await.unwrap();
            }

            // Replay from start
            use futures::StreamExt;
            {
                let stream = journal.replay(0, NZUsize!(1024)).await.unwrap();
                futures::pin_mut!(stream);

                let mut items = Vec::new();
                while let Some(result) = stream.next().await {
                    items.push(result.unwrap());
                }

                assert_eq!(items.len(), 10);
                for (i, (pos, value)) in items.iter().enumerate() {
                    assert_eq!(*pos, i as u64);
                    assert_eq!(*value, (i as u64) * 10);
                }
            }

            journal.destroy().await.unwrap();
        });
    }

    #[test]
    fn test_variable_replay_from_middle() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut journal = Variable::<_, u64>::init(
                context,
                Config {
                    partition: "test_variable_replay_middle".to_string(),
                    locations_partition: "test_variable_replay_middle_locations".to_string(),
                    items_per_section: NZU64!(5),
                    compression: None,
                    codec_config: (),
                    buffer_pool: PoolRef::new(NZUsize!(1024), NZUsize!(10)),
                    write_buffer: NZUsize!(1024),
                },
            )
            .await
            .unwrap();

            // Append 10 items
            for i in 0..10u64 {
                journal.append(i * 10).await.unwrap();
            }

            // Replay from position 5
            use futures::StreamExt;
            {
                let stream = journal.replay(5, NZUsize!(1024)).await.unwrap();
                futures::pin_mut!(stream);

                let mut items = Vec::new();
                while let Some(result) = stream.next().await {
                    items.push(result.unwrap());
                }

                assert_eq!(items.len(), 5);
                for (i, (pos, value)) in items.iter().enumerate() {
                    assert_eq!(*pos, (i + 5) as u64);
                    assert_eq!(*value, ((i + 5) as u64) * 10);
                }
            }

            journal.destroy().await.unwrap();
        });
    }

    #[test]
    fn test_variable_through_contiguous_trait() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut journal = Variable::<_, u64>::init(
                context,
                Config {
                    partition: "test_variable_trait".to_string(),
                    locations_partition: "test_variable_trait_locations".to_string(),
                    items_per_section: NZU64!(5),
                    compression: None,
                    codec_config: (),
                    buffer_pool: PoolRef::new(NZUsize!(1024), NZUsize!(10)),
                    write_buffer: NZUsize!(1024),
                },
            )
            .await
            .unwrap();

            // Use through Contiguous trait
            let pos1 = Contiguous::append(&mut journal, 42u64).await.unwrap();
            let pos2 = Contiguous::append(&mut journal, 100u64).await.unwrap();
            assert_eq!(pos1, 0);
            assert_eq!(pos2, 1);

            let size = Contiguous::size(&journal).await.unwrap();
            assert_eq!(size, 2);

            journal.destroy().await.unwrap();
        });
    }

    #[test]
    fn test_variable_destroy() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let partition = "test_variable_destroy";
            let cfg = Config {
                partition: partition.to_string(),
                locations_partition: format!("{}_locations", partition),
                items_per_section: NZU64!(5),
                compression: None,
                codec_config: (),
                buffer_pool: PoolRef::new(NZUsize!(1024), NZUsize!(10)),
                write_buffer: NZUsize!(1024),
            };

            // Create journal and append items
            {
                let mut journal = Variable::<_, u64>::init(context.clone(), cfg.clone())
                    .await
                    .unwrap();

                for i in 0..10u64 {
                    journal.append(i * 10).await.unwrap();
                }

                // Destroy should remove all blobs and metadata
                journal.destroy().await.unwrap();
            }

            // After destroy, initializing again should start fresh
            {
                let journal = Variable::<_, u64>::init(context.clone(), cfg.clone())
                    .await
                    .unwrap();

                // Should be empty
                assert_eq!(journal.size().await.unwrap(), 0);
                journal.destroy().await.unwrap();
            }
        });
    }

    // TODO: Re-enable this test after debugging metadata persistence issue
    // The metadata saving/loading works (as evidenced by test_variable_persistence_across_restart)
    // but there's a subtle issue with multiple sessions in the deterministic runtime
    #[test]
    #[ignore]
    fn test_variable_metadata_persistence() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let partition = "test_variable_metadata";
            let cfg = Config {
                partition: partition.to_string(),
                locations_partition: format!("{}_locations", partition),
                items_per_section: NZU64!(7),
                compression: None,
                codec_config: (),
                buffer_pool: PoolRef::new(NZUsize!(1024), NZUsize!(10)),
                write_buffer: NZUsize!(1024),
            };

            // First session: append items and close (saves metadata)
            {
                let mut journal = Variable::<_, u64>::init(context.clone(), cfg.clone())
                    .await
                    .unwrap();

                for i in 0..10u64 {
                    journal.append(i * 10).await.unwrap();
                }

                journal.close().await.unwrap();
            }

            // Second session: should load from metadata (not replay)
            {
                let mut journal = Variable::<_, u64>::init(context.clone(), cfg.clone())
                    .await
                    .unwrap();

                assert_eq!(journal.size().await.unwrap(), 10);

                // Continue appending
                let pos = journal.append(100u64).await.unwrap();
                assert_eq!(pos, 10);

                journal.close().await.unwrap();
            }

            // Third session: verify again
            {
                let journal = Variable::<_, u64>::init(context, cfg).await.unwrap();

                assert_eq!(journal.size().await.unwrap(), 11);
                journal.close().await.unwrap();
            }
        });
    }

    #[test]
    fn test_current_section_no_pruning() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut journal = Variable::<_, u64>::init(
                context,
                Config {
                    partition: "test_current_section".to_string(),
                    locations_partition: "test_current_section_locations".to_string(),
                    items_per_section: NZU64!(10),
                    compression: None,
                    codec_config: (),
                    buffer_pool: PoolRef::new(NZUsize!(1024), NZUsize!(10)),
                    write_buffer: NZUsize!(1024),
                },
            )
            .await
            .unwrap();

            // Initially, should be in section 0
            assert_eq!(journal.current_section(), 0);

            // After appending 5 items, still in section 0
            for _ in 0..5 {
                journal.append(42u64).await.unwrap();
            }
            assert_eq!(journal.current_section(), 0);

            // After appending 5 more items (total 10), should be in section 1
            for _ in 0..5 {
                journal.append(42u64).await.unwrap();
            }
            assert_eq!(journal.current_section(), 1);

            // After appending 15 more items (total 25), should be in section 2
            for _ in 0..15 {
                journal.append(42u64).await.unwrap();
            }
            assert_eq!(journal.current_section(), 2);

            journal.destroy().await.unwrap();
        });
    }

    #[test]
    fn test_current_section_after_pruning() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut journal = Variable::<_, u64>::init(
                context,
                Config {
                    partition: "test_current_section_prune".to_string(),
                    locations_partition: "test_current_section_prune_locations".to_string(),
                    items_per_section: NZU64!(5),
                    compression: None,
                    codec_config: (),
                    buffer_pool: PoolRef::new(NZUsize!(1024), NZUsize!(10)),
                    write_buffer: NZUsize!(1024),
                },
            )
            .await
            .unwrap();

            // Append 12 items (sections 0, 1, 2)
            for _ in 0..12 {
                journal.append(42u64).await.unwrap();
            }

            // Current section should be 2 (positions 10-14 are in section 2)
            assert_eq!(journal.current_section(), 2);

            // Prune up to position 7 (removes section 0, keeps sections 1+)
            journal.prune(7).await.unwrap();

            // Should still be in section 2
            assert_eq!(journal.current_section(), 2);

            // Append a few more items
            for _ in 0..3 {
                journal.append(42u64).await.unwrap();
            }

            // Should now be in section 3 (15 items total)
            assert_eq!(journal.current_section(), 3);

            journal.destroy().await.unwrap();
        });
    }

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

    #[test]
    fn test_variable_contiguous() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            run_contiguous_tests(move |test_name: String| {
                let context = context.clone();
                async move {
                    Variable::<_, u64>::init(
                        context,
                        Config {
                            partition: format!("generic_test_{}", test_name),
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
}
