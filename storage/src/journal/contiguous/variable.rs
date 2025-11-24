//! Position-based journal for variable-length items.
//!
//! This journal enforces section fullness: all non-final sections are full and synced.
//! On init, only the last section needs to be replayed to determine the exact size.

use crate::{
    journal::{
        contiguous::{fixed, Contiguous, MutableContiguous, PersistableContiguous},
        segmented::variable,
        Error,
    },
    mmr::Location,
};
use commonware_codec::Codec;
use commonware_runtime::{buffer::PoolRef, Metrics, Storage};
use commonware_utils::NZUsize;
use core::ops::Range;
use futures::{future::Either, stream, Stream, StreamExt as _};
use std::num::{NonZeroU64, NonZeroUsize};
use tracing::{debug, info};

const REPLAY_BUFFER_SIZE: NonZeroUsize = NZUsize!(1024);

/// Suffix appended to the base partition name for the data journal.
const DATA_SUFFIX: &str = "_data";

/// Suffix appended to the base partition name for the offsets journal.
const OFFSETS_SUFFIX: &str = "_offsets";

/// Calculate the section number for a given position.
///
/// # Arguments
///
/// * `position` - The absolute position in the journal
/// * `items_per_section` - The number of items stored in each section
///
/// # Returns
///
/// The section number where the item at `position` should be stored.
///
/// # Examples
///
/// ```ignore
/// // With 10 items per section:
/// assert_eq!(position_to_section(0, 10), 0);   // position 0 -> section 0
/// assert_eq!(position_to_section(9, 10), 0);   // position 9 -> section 0
/// assert_eq!(position_to_section(10, 10), 1);  // position 10 -> section 1
/// assert_eq!(position_to_section(25, 10), 2);  // position 25 -> section 2
/// assert_eq!(position_to_section(30, 10), 3);  // position 30 -> section 3
/// ```
const fn position_to_section(position: u64, items_per_section: u64) -> u64 {
    position / items_per_section
}

/// Configuration for a [Journal].
#[derive(Clone)]
pub struct Config<C> {
    /// Base partition name. Sub-partitions will be created by appending DATA_SUFFIX and OFFSETS_SUFFIX.
    pub partition: String,

    /// The number of items to store in each section.
    ///
    /// Once set, this value cannot be changed across restarts.
    /// All non-final sections will be full and persisted.
    pub items_per_section: NonZeroU64,

    /// Optional compression level for stored items.
    pub compression: Option<u8>,

    /// [Codec] configuration for encoding/decoding items.
    pub codec_config: C,

    /// Buffer pool for caching data.
    pub buffer_pool: PoolRef,

    /// Write buffer size for each section.
    pub write_buffer: NonZeroUsize,
}

impl<C> Config<C> {
    /// Returns the partition name for the data journal.
    fn data_partition(&self) -> String {
        format!("{}{}", self.partition, DATA_SUFFIX)
    }

    /// Returns the partition name for the offsets journal.
    fn offsets_partition(&self) -> String {
        format!("{}{}", self.partition, OFFSETS_SUFFIX)
    }
}

/// A position-based journal for variable-length items.
///
/// This journal manages section assignment automatically, allowing callers to append items
/// sequentially without manually tracking section numbers.
///
/// # Invariants
///
/// ## 1. Section Fullness
///
/// All non-final sections are full (`items_per_section` items) and persisted. This ensures
/// that on `init()`, we only need to replay the last section to determine the exact size.
///
/// ## 2. Data Journal is Source of Truth
///
/// The data journal is always the source of truth. The offsets journal is an index
/// that may temporarily diverge during crashes. Divergences are automatically
/// aligned during init():
/// * If offsets.size() < data.size(): Rebuild missing offsets by replaying data.
///   (This can happen if we crash after writing data journal but before writing offsets journal)
/// * If offsets.size() > data.size(): Rewind offsets to match data size.
///   (This can happen if we crash after rewinding data journal but before rewinding offsets journal)
/// * If offsets.oldest_retained_pos() < data.oldest_retained_pos(): Prune offsets to match
///   (This can happen if we crash after pruning data journal but before pruning offsets journal)
///
/// Note that we don't recover from the case where offsets.oldest_retained_pos() >
/// data.oldest_retained_pos(). This should never occur because we always prune the data journal
/// before the offsets journal.
pub struct Journal<E: Storage + Metrics, V: Codec> {
    /// The underlying variable-length data journal.
    data: variable::Journal<E, V>,

    /// Index mapping positions to byte offsets within the data journal.
    /// The section can be calculated from the position using items_per_section.
    offsets: fixed::Journal<E, u32>,

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

impl<E: Storage + Metrics, V: Codec> Journal<E, V> {
    /// Initialize a contiguous variable journal.
    ///
    /// # Crash Recovery
    ///
    /// The data journal is the source of truth. If the offsets journal is inconsistent
    /// it will be updated to match the data journal.
    pub async fn init(context: E, cfg: Config<V::Cfg>) -> Result<Self, Error> {
        let items_per_section = cfg.items_per_section.get();
        let data_partition = cfg.data_partition();
        let offsets_partition = cfg.offsets_partition();

        // Initialize underlying variable data journal
        let mut data = variable::Journal::init(
            context.clone(),
            variable::Config {
                partition: data_partition,
                compression: cfg.compression,
                codec_config: cfg.codec_config,
                buffer_pool: cfg.buffer_pool.clone(),
                write_buffer: cfg.write_buffer,
            },
        )
        .await?;

        // Initialize offsets journal
        let mut offsets = fixed::Journal::init(
            context,
            fixed::Config {
                partition: offsets_partition,
                items_per_blob: cfg.items_per_section,
                buffer_pool: cfg.buffer_pool,
                write_buffer: cfg.write_buffer,
            },
        )
        .await?;

        // Validate and align offsets journal to match data journal
        let (oldest_retained_pos, size) =
            Self::align_journals(&mut data, &mut offsets, items_per_section).await?;
        assert!(
            oldest_retained_pos.is_multiple_of(items_per_section),
            "oldest_retained_pos is not section-aligned"
        );

        Ok(Self {
            data,
            offsets,
            items_per_section,
            size,
            oldest_retained_pos,
        })
    }

    /// Initialize a [Journal] in a fully pruned state at a specific logical size.
    ///
    /// This creates a journal that reports `size()` as `size` but contains no data.
    /// The `oldest_retained_pos()` will return `None`, indicating all positions before
    /// `size` have been pruned. This is useful for state sync when starting from
    /// a non-zero position without historical data.
    ///
    /// # Arguments
    ///
    /// * `size` - The logical size to initialize at.
    ///
    /// # Post-conditions
    ///
    /// * `size()` returns `size`
    /// * `oldest_retained_pos()` returns `None` (fully pruned)
    /// * Next append receives position `size`
    pub async fn init_at_size(context: E, cfg: Config<V::Cfg>, size: u64) -> Result<Self, Error> {
        // Initialize empty data journal
        let data = variable::Journal::init(
            context.clone(),
            variable::Config {
                partition: cfg.data_partition(),
                compression: cfg.compression,
                codec_config: cfg.codec_config.clone(),
                buffer_pool: cfg.buffer_pool.clone(),
                write_buffer: cfg.write_buffer,
            },
        )
        .await?;

        // Initialize offsets journal at the target size
        let offsets = crate::adb::any::fixed::sync::init_journal_at_size(
            context,
            fixed::Config {
                partition: cfg.offsets_partition(),
                items_per_blob: cfg.items_per_section,
                buffer_pool: cfg.buffer_pool,
                write_buffer: cfg.write_buffer,
            },
            size,
        )
        .await?;

        Ok(Self {
            data,
            offsets,
            items_per_section: cfg.items_per_section.get(),
            size,
            oldest_retained_pos: size,
        })
    }

    /// Initialize a [Journal] for use in state sync.
    ///
    /// The bounds are item locations (not section numbers). This function prepares the
    /// on-disk journal so that subsequent appends go to the correct physical location for the
    /// requested range.
    ///
    /// Behavior by existing on-disk state:
    /// - Fresh (no data): returns an empty journal.
    /// - Stale (all data strictly before `range.start`): destroys existing data and returns an
    ///   empty journal.
    /// - Overlap within [`range.start`, `range.end`]:
    ///   - Prunes to `range.start`
    /// - Unexpected data beyond `range.end`: returns [crate::adb::Error::UnexpectedData].
    ///
    /// # Arguments
    /// - `context`: storage context
    /// - `cfg`: journal configuration
    /// - `range`: range of item locations to retain
    ///
    /// # Returns
    /// A contiguous journal ready for sync operations. The journal's size will be within the range.
    ///
    /// # Errors
    /// Returns [crate::adb::Error::UnexpectedData] if existing data extends beyond `range.end`.
    pub(crate) async fn init_sync(
        context: E,
        cfg: Config<V::Cfg>,
        range: Range<u64>,
    ) -> Result<Journal<E, V>, crate::adb::Error> {
        assert!(!range.is_empty(), "range must not be empty");

        debug!(
            range.start,
            range.end,
            items_per_section = cfg.items_per_section.get(),
            "initializing contiguous variable journal for sync"
        );

        // Initialize contiguous journal
        let mut journal = Journal::init(context.with_label("journal"), cfg.clone()).await?;

        let size = journal.size();

        // No existing data - initialize at the start of the sync range if needed
        if size == 0 {
            if range.start == 0 {
                debug!("no existing journal data, returning empty journal");
                return Ok(journal);
            } else {
                debug!(
                    range.start,
                    "no existing journal data, initializing at sync range start"
                );
                journal.destroy().await?;
                return Ok(Journal::init_at_size(context, cfg, range.start).await?);
            }
        }

        // Check if data exceeds the sync range
        if size > range.end {
            return Err(crate::adb::Error::UnexpectedData(Location::new_unchecked(
                size,
            )));
        }

        // If all existing data is before our sync range, destroy and recreate fresh
        if size <= range.start {
            // All data is stale (ends at or before range.start)
            debug!(
                size,
                range.start, "existing journal data is stale, re-initializing at start position"
            );
            journal.destroy().await?;
            return Ok(Journal::init_at_size(context, cfg, range.start).await?);
        }

        // Prune to lower bound if needed
        let oldest = journal.oldest_retained_pos();
        if let Some(oldest_pos) = oldest {
            if oldest_pos < range.start {
                debug!(
                    oldest_pos,
                    range.start, "pruning journal to sync range start"
                );
                journal.prune(range.start).await?;
            }
        }

        Ok(journal)
    }

    /// Rewind the journal to the given size, discarding items from the end.
    ///
    /// After rewinding to size N, the journal will contain exactly N items, and the next append
    /// will receive position N.
    ///
    /// # Errors
    ///
    /// Returns [Error::InvalidRewind] if size is invalid (too large or points to pruned data).
    ///
    /// # Warning
    ///
    /// - This operation is not guaranteed to survive restarts until `commit` or `sync` is called.
    pub async fn rewind(&mut self, size: u64) -> Result<(), Error> {
        // Validate rewind target
        match size.cmp(&self.size) {
            std::cmp::Ordering::Greater => return Err(Error::InvalidRewind(size)),
            std::cmp::Ordering::Equal => return Ok(()), // No-op
            std::cmp::Ordering::Less => {}
        }

        // Rewind never updates oldest_retained_pos.
        if size < self.oldest_retained_pos {
            return Err(Error::ItemPruned(size));
        }

        // Read the offset of the first item to discard (at position 'size').
        let discard_offset = self.offsets.read(size).await?;
        let discard_section = position_to_section(size, self.items_per_section);

        self.data
            .rewind_to_offset(discard_section, discard_offset)
            .await?;
        self.offsets.rewind(size).await?;

        // Update our size
        self.size = size;

        Ok(())
    }

    /// Append a new item to the journal, returning its position.
    ///
    /// The position returned is a stable, consecutively increasing value starting from 0.
    /// This position remains constant after pruning.
    ///
    /// When a section becomes full, both the data journal and offsets journal are persisted
    /// to maintain the invariant that all non-final sections are full and consistent.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying storage operation fails or if the item cannot
    /// be encoded.
    ///
    /// Errors may leave the journal in an inconsistent state. The journal should be closed and
    /// reopened to trigger alignment in [Journal::init].
    pub async fn append(&mut self, item: V) -> Result<u64, Error> {
        // Calculate which section this position belongs to
        let section = self.current_section();

        // Append to data journal, get offset
        let (offset, _size) = self.data.append(section, item).await?;

        // Append offset to offsets journal
        let offsets_pos = self.offsets.append(offset).await?;
        assert_eq!(offsets_pos, self.size);

        // Return the current position
        let position = self.size;
        self.size += 1;

        // Maintain invariant that all full sections are persisted.
        if self.size.is_multiple_of(self.items_per_section) {
            futures::try_join!(self.data.sync(section), self.offsets.sync())?;
        }

        Ok(position)
    }

    /// Return the total number of items that have been appended to the journal.
    ///
    /// This count is NOT affected by pruning. The next appended item will receive this
    /// position as its value.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Return the position of the oldest item still retained in the journal.
    ///
    /// Returns `None` if the journal is empty or if all items have been pruned.
    pub fn oldest_retained_pos(&self) -> Option<u64> {
        if self.size == self.oldest_retained_pos {
            // No items retained: either never had data or fully pruned
            None
        } else {
            Some(self.oldest_retained_pos)
        }
    }

    /// Returns the location before which all items have been pruned.
    pub fn pruning_boundary(&self) -> u64 {
        self.oldest_retained_pos().unwrap_or(self.size)
    }

    /// Prune items at positions strictly less than `min_position`.
    ///
    /// Returns `true` if any data was pruned, `false` otherwise.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying storage operation fails.
    ///
    /// Errors may leave the journal in an inconsistent state. The journal should be closed and
    /// reopened to trigger alignment in [Journal::init].
    pub async fn prune(&mut self, min_position: u64) -> Result<bool, Error> {
        if min_position <= self.oldest_retained_pos {
            return Ok(false);
        }

        // Cap min_position to size to maintain the invariant oldest_retained_pos <= size
        let min_position = min_position.min(self.size);

        // Calculate section number
        let min_section = position_to_section(min_position, self.items_per_section);

        let pruned = self.data.prune(min_section).await?;
        if pruned {
            self.oldest_retained_pos = min_section * self.items_per_section;
            self.offsets.prune(self.oldest_retained_pos).await?;
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
    ) -> Result<impl Stream<Item = Result<(u64, V), Error>> + '_, Error> {
        // Validate start position is within bounds.
        if start_pos < self.oldest_retained_pos {
            return Err(Error::ItemPruned(start_pos));
        }
        if start_pos > self.size {
            return Err(Error::ItemOutOfRange(start_pos));
        }

        // If replaying at exactly size, return empty stream
        if start_pos == self.size {
            return Ok(Either::Left(stream::empty()));
        }

        // Use offsets index to find offset to start from, calculate section from position
        let start_offset = self.offsets.read(start_pos).await?;
        let start_section = position_to_section(start_pos, self.items_per_section);
        let data_stream = self
            .data
            .replay(start_section, start_offset, buffer_size)
            .await?;

        // Transform the stream to include position information
        let transformed = data_stream.enumerate().map(move |(idx, result)| {
            result.map(|(_section, _offset, _size, item)| {
                // Calculate position: start_pos + items read
                let pos = start_pos + idx as u64;
                (pos, item)
            })
        });

        Ok(Either::Right(transformed))
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

        // Read offset from journal and calculate section from position
        let offset = self.offsets.read(position).await?;
        let section = position_to_section(position, self.items_per_section);

        // Read item from data journal
        self.data.get(section, offset).await
    }

    /// Durably persist the journal.
    ///
    /// This is faster than `sync()` but recovery will be required on startup if a crash occurs
    /// before the next call to `sync()`.
    pub async fn commit(&mut self) -> Result<(), Error> {
        let section = self.current_section();
        self.data.sync(section).await
    }

    /// Durably persist the journal and ensure recovery is not required on startup.
    ///
    /// This is slower than `commit()` but ensures the journal doesn't require recovery on startup.
    pub async fn sync(&mut self) -> Result<(), Error> {
        // Persist only the current (final) section of the data journal.
        // All non-final sections are already persisted per Invariant #1.
        let section = self.current_section();

        // Persist both journals concurrently
        futures::try_join!(self.data.sync(section), self.offsets.sync())?;

        Ok(())
    }

    /// Close the journal, persisting all pending writes.
    ///
    /// This closes both the data journal and the offsets journal.
    pub async fn close(mut self) -> Result<(), Error> {
        self.sync().await?;
        self.data.close().await?;
        self.offsets.close().await
    }

    /// Remove any underlying blobs created by the journal.
    ///
    /// This destroys both the data journal and the offsets journal.
    pub async fn destroy(self) -> Result<(), Error> {
        self.data.destroy().await?;
        self.offsets.destroy().await
    }

    /// Return the section number where the next append will write.
    const fn current_section(&self) -> u64 {
        position_to_section(self.size, self.items_per_section)
    }

    /// Align the offsets journal and data journal to be consistent in case a crash occured
    /// on a previous run and left the journals in an inconsistent state.
    ///
    /// The data journal is the source of truth. This function scans it to determine
    /// what SHOULD be in the offsets journal, then fixes any mismatches.
    ///
    /// # Returns
    ///
    /// Returns `(oldest_retained_pos, size)` for the contiguous journal.
    async fn align_journals(
        data: &mut variable::Journal<E, V>,
        offsets: &mut fixed::Journal<E, u32>,
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
            let size = offsets.size();

            if !data.blobs.is_empty() {
                // A section exists but contains 0 items. This can happen in two cases:
                // 1. Rewind crash: we rewound the data journal but crashed before rewinding offsets
                // 2. First append crash: we opened the first section blob but crashed before writing to it
                // In both cases, calculate target position from the first remaining section
                let first_section = *data.blobs.first_key_value().unwrap().0;
                let target_pos = first_section * items_per_section;

                info!("crash repair: rewinding offsets from {size} to {target_pos}");
                offsets.rewind(target_pos).await?;
                offsets.sync().await?;
                return Ok((target_pos, target_pos));
            }

            // data.blobs is empty. This can happen in two cases:
            // 1. We completely pruned the data journal but crashed before pruning
            //    the offsets journal.
            // 2. The data journal was never opened.
            if let Some(oldest) = offsets.oldest_retained_pos() {
                if oldest < size {
                    // Offsets has unpruned entries but data is gone - align by pruning
                    info!("crash repair: pruning offsets to {size} (prune-all crash)");
                    offsets.prune(size).await?;
                    offsets.sync().await?;
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

        // Align pruning state. We always prune the data journal before the offsets journal,
        // so we validate that invariant and repair crash faults or detect corruption.
        match offsets.oldest_retained_pos() {
            Some(oldest_retained_pos) if oldest_retained_pos < data_oldest_pos => {
                // Offsets behind on pruning -- prune to catch up
                info!("crash repair: pruning offsets journal to {data_oldest_pos}");
                offsets.prune(data_oldest_pos).await?;
            }
            Some(oldest_retained_pos) if oldest_retained_pos > data_oldest_pos => {
                return Err(Error::Corruption(format!(
                    "offsets oldest pos ({oldest_retained_pos}) > data oldest pos ({data_oldest_pos})"
                )));
            }
            Some(_) => {
                // Both journals are pruned to the same position.
            }
            None if data_oldest_pos > 0 => {
                // Offsets journal is empty (size == oldest_retained_pos).
                // This can happen if we pruned all data, then appended new data, persisted the
                // data journal, but crashed before persisting the offsets journal.
                // We can recover if offsets.size() matches data_oldest_pos (proper pruning).
                let offsets_size = offsets.size();
                if offsets_size != data_oldest_pos {
                    return Err(Error::Corruption(format!(
                        "offsets journal empty: size ({offsets_size}) != data oldest pos ({data_oldest_pos})"
                    )));
                }
                info!("crash repair: offsets journal empty at {data_oldest_pos}");
            }
            None => {
                // Both journals are empty/fully pruned.
            }
        }

        let offsets_size = offsets.size();
        if offsets_size > data_size {
            // We must have crashed after writing offsets but before writing data.
            info!("crash repair: rewinding offsets from {offsets_size} to {data_size}");
            offsets.rewind(data_size).await?;
        } else if offsets_size < data_size {
            // We must have crashed after writing the data journal but before writing the offsets
            // journal.
            Self::add_missing_offsets(data, offsets, offsets_size, items_per_section).await?;
        }

        assert_eq!(offsets.size(), data_size);
        // Oldest retained position is always Some because the data journal is non-empty.
        assert_eq!(offsets.oldest_retained_pos(), Some(data_oldest_pos));

        offsets.sync().await?;
        Ok((data_oldest_pos, data_size))
    }

    /// Rebuild missing offset entries by replaying the data journal and
    /// appending the missing entries to the offsets journal.
    ///
    /// The data journal is the source of truth. This function brings the offsets
    /// journal up to date by replaying data items and indexing their positions.
    ///
    /// # Warning
    ///
    /// - Panics if `data.blobs` is empty
    /// - Panics if `offsets_size` >= `data.size()`
    async fn add_missing_offsets(
        data: &variable::Journal<E, V>,
        offsets: &mut fixed::Journal<E, u32>,
        offsets_size: u64,
        items_per_section: u64,
    ) -> Result<(), Error> {
        assert!(
            !data.blobs.is_empty(),
            "rebuild_offsets called with empty data journal"
        );

        // Find where to start replaying
        let (start_section, resume_offset, skip_first) =
            if let Some(oldest) = offsets.oldest_retained_pos() {
                if oldest < offsets_size {
                    // Offsets has items -- resume from last indexed position
                    let last_offset = offsets.read(offsets_size - 1).await?;
                    let last_section = position_to_section(offsets_size - 1, items_per_section);
                    (last_section, last_offset, true)
                } else {
                    // Offsets fully pruned but data has items -- start from first data section
                    // SAFETY: data.blobs is non-empty (checked above)
                    let first_section = *data.blobs.first_key_value().unwrap().0;
                    (first_section, 0, false)
                }
            } else {
                // Offsets empty -- start from first data section
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
            let (_section, offset, _size, _item) = result?;

            // Skip first item if resuming from last indexed offset
            if skip_first && !skipped_first {
                skipped_first = true;
                continue;
            }

            offsets.append(offset).await?;
        }

        Ok(())
    }
}

// Implement Contiguous trait for variable-length items
impl<E: Storage + Metrics, V: Codec> Contiguous for Journal<E, V> {
    type Item = V;

    fn size(&self) -> u64 {
        Journal::size(self)
    }

    fn oldest_retained_pos(&self) -> Option<u64> {
        Journal::oldest_retained_pos(self)
    }

    fn pruning_boundary(&self) -> u64 {
        Journal::pruning_boundary(self)
    }

    async fn replay(
        &self,
        start_pos: u64,
        buffer: NonZeroUsize,
    ) -> Result<impl Stream<Item = Result<(u64, Self::Item), Error>> + '_, Error> {
        Journal::replay(self, start_pos, buffer).await
    }

    async fn read(&self, position: u64) -> Result<Self::Item, Error> {
        Journal::read(self, position).await
    }
}

impl<E: Storage + Metrics, V: Codec> MutableContiguous for Journal<E, V> {
    async fn append(&mut self, item: Self::Item) -> Result<u64, Error> {
        Journal::append(self, item).await
    }

    async fn prune(&mut self, min_position: u64) -> Result<bool, Error> {
        Journal::prune(self, min_position).await
    }

    async fn rewind(&mut self, size: u64) -> Result<(), Error> {
        Journal::rewind(self, size).await
    }
}

impl<E: Storage + Metrics, V: Codec> PersistableContiguous for Journal<E, V> {
    async fn commit(&mut self) -> Result<(), Error> {
        Journal::commit(self).await
    }

    async fn sync(&mut self) -> Result<(), Error> {
        Journal::sync(self).await
    }

    async fn close(self) -> Result<(), Error> {
        Journal::close(self).await
    }

    async fn destroy(self) -> Result<(), Error> {
        Journal::destroy(self).await
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

    // Use some jank sizes to exercise boundary conditions.
    const PAGE_SIZE: usize = 101;
    const PAGE_CACHE_SIZE: usize = 2;

    /// Test that complete offsets partition loss after pruning is detected as unrecoverable.
    ///
    /// When the offsets partition is completely lost and the data has been pruned, we cannot
    /// rebuild the index with correct position alignment (would require creating placeholder blobs).
    /// This is a genuine external failure that should be detected and reported clearly.
    #[test_traced]
    fn test_variable_offsets_partition_loss_after_prune_unrecoverable() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "offsets_loss_after_prune".to_string(),
                items_per_section: NZU64!(10),
                compression: None,
                codec_config: (),
                buffer_pool: PoolRef::new(NZUsize!(1024), NZUsize!(10)),
                write_buffer: NZUsize!(1024),
            };

            // === Phase 1: Create journal with data and prune ===
            let mut journal = Journal::<_, u64>::init(context.clone(), cfg.clone())
                .await
                .unwrap();

            // Append 40 items across 4 sections (0-3)
            for i in 0..40u64 {
                journal.append(i * 100).await.unwrap();
            }

            // Prune to position 20 (removes sections 0-1, keeps sections 2-3)
            journal.prune(20).await.unwrap();
            assert_eq!(journal.oldest_retained_pos(), Some(20));
            assert_eq!(journal.size(), 40);

            journal.close().await.unwrap();

            // === Phase 2: Simulate complete offsets partition loss ===
            context
                .remove(&cfg.offsets_partition(), None)
                .await
                .expect("Failed to remove offsets partition");

            // === Phase 3: Verify this is detected as unrecoverable ===
            let result = Journal::<_, u64>::init(context.clone(), cfg.clone()).await;
            assert!(matches!(result, Err(Error::Corruption(_))));
        });
    }

    /// Test that init aligns state when data is pruned/lost but offsets survives.
    ///
    /// This handles both:
    /// 1. Crash during prune-all (data pruned, offsets not yet)
    /// 2. External data partition loss
    ///
    /// In both cases, we align by pruning offsets to match.
    #[test_traced]
    fn test_variable_align_data_offsets_mismatch() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "data_loss_test".to_string(),
                items_per_section: NZU64!(10),
                compression: None,
                codec_config: (),
                buffer_pool: PoolRef::new(NZUsize!(1024), NZUsize!(10)),
                write_buffer: NZUsize!(1024),
            };

            // === Setup: Create journal with data ===
            let mut variable = Journal::<_, u64>::init(context.clone(), cfg.clone())
                .await
                .unwrap();

            // Append 20 items across 2 sections
            for i in 0..20u64 {
                variable.append(i * 100).await.unwrap();
            }

            variable.close().await.unwrap();

            // === Simulate data loss: Delete data partition but keep offsets ===
            context
                .remove(&cfg.data_partition(), None)
                .await
                .expect("Failed to remove data partition");

            // === Verify init aligns the mismatch ===
            let mut journal = Journal::<_, u64>::init(context.clone(), cfg.clone())
                .await
                .expect("Should align offsets to match empty data");

            // Size should be preserved
            assert_eq!(journal.size(), 20);

            // But no items remain (both journals pruned)
            assert_eq!(journal.oldest_retained_pos(), None);

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

    #[test_traced]
    fn test_variable_contiguous() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            run_contiguous_tests(move |test_name: String| {
                let context = context.clone();
                async move {
                    Journal::<_, u64>::init(
                        context,
                        Config {
                            partition: format!("generic_test_{test_name}"),
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
                partition: "sequential_prunes".to_string(),
                items_per_section: NZU64!(10),
                compression: None,
                codec_config: (),
                buffer_pool: PoolRef::new(NZUsize!(1024), NZUsize!(10)),
                write_buffer: NZUsize!(1024),
            };

            let mut journal = Journal::<_, u64>::init(context, cfg).await.unwrap();

            // Append items across 4 sections: [0-9], [10-19], [20-29], [30-39]
            for i in 0..40u64 {
                journal.append(i * 100).await.unwrap();
            }

            // Initial state: all items accessible
            assert_eq!(journal.oldest_retained_pos(), Some(0));
            assert_eq!(journal.size(), 40);

            // First prune: remove section 0 (positions 0-9)
            let pruned = journal.prune(10).await.unwrap();
            assert!(pruned);

            // Variable-specific guarantee: oldest is EXACTLY at section boundary
            let oldest = journal.oldest_retained_pos().unwrap();
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
            let oldest = journal.oldest_retained_pos().unwrap();
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
            let oldest = journal.oldest_retained_pos().unwrap();
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
            assert_eq!(journal.size(), 40);

            journal.destroy().await.unwrap();
        });
    }

    /// Test that pruning all data and re-initializing preserves positions.
    #[test_traced]
    fn test_variable_prune_all_then_reinit() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "prune_all_reinit".to_string(),
                items_per_section: NZU64!(10),
                compression: None,
                codec_config: (),
                buffer_pool: PoolRef::new(NZUsize!(1024), NZUsize!(10)),
                write_buffer: NZUsize!(1024),
            };

            // === Phase 1: Create journal and append data ===
            let mut journal = Journal::<_, u64>::init(context.clone(), cfg.clone())
                .await
                .unwrap();

            for i in 0..100u64 {
                journal.append(i * 100).await.unwrap();
            }

            assert_eq!(journal.size(), 100);
            assert_eq!(journal.oldest_retained_pos(), Some(0));

            // === Phase 2: Prune all data ===
            let pruned = journal.prune(100).await.unwrap();
            assert!(pruned);

            // All data is pruned - no items remain
            assert_eq!(journal.size(), 100);
            assert_eq!(journal.oldest_retained_pos(), None);

            // All reads should fail with ItemPruned
            for i in 0..100 {
                assert!(matches!(
                    journal.read(i).await,
                    Err(crate::journal::Error::ItemPruned(_))
                ));
            }

            journal.close().await.unwrap();

            // === Phase 3: Re-init and verify position preserved ===
            let mut journal = Journal::<_, u64>::init(context.clone(), cfg.clone())
                .await
                .unwrap();

            // Size should be preserved, but no items remain
            assert_eq!(journal.size(), 100);
            assert_eq!(journal.oldest_retained_pos(), None);

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
            assert_eq!(journal.size(), 101);
            // Now we have one item at position 100
            assert_eq!(journal.oldest_retained_pos(), Some(100));

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

    /// Test recovery from crash after data journal pruned but before offsets journal.
    #[test_traced]
    fn test_variable_recovery_prune_crash_offsets_behind() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // === Setup: Create Variable wrapper with data ===
            let cfg = Config {
                partition: "recovery_prune_crash".to_string(),
                items_per_section: NZU64!(10),
                compression: None,
                codec_config: (),
                buffer_pool: PoolRef::new(NZUsize!(1024), NZUsize!(10)),
                write_buffer: NZUsize!(1024),
            };

            let mut variable = Journal::<_, u64>::init(context.clone(), cfg.clone())
                .await
                .unwrap();

            // Append 40 items across 4 sections to both journals
            for i in 0..40u64 {
                variable.append(i * 100).await.unwrap();
            }

            // Prune to position 10 normally (both data and offsets journals pruned)
            variable.prune(10).await.unwrap();
            assert_eq!(variable.oldest_retained_pos(), Some(10));

            // === Simulate crash: Prune data journal but not offsets journal ===
            // Manually prune data journal to section 2 (position 20)
            variable.data.prune(2).await.unwrap();
            // Offsets journal still has data from position 10-19

            variable.close().await.unwrap();

            // === Verify recovery ===
            let variable = Journal::<_, u64>::init(context.clone(), cfg.clone())
                .await
                .unwrap();

            // Init should auto-repair: offsets journal pruned to match data journal
            assert_eq!(variable.oldest_retained_pos(), Some(20));
            assert_eq!(variable.size(), 40);

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

    /// Test recovery detects corruption when offsets journal pruned ahead of data journal.
    ///
    /// Simulates an impossible state (offsets journal pruned more than data journal) which
    /// should never happen due to write ordering. Verifies that init() returns corruption error.
    #[test_traced]
    fn test_variable_recovery_offsets_ahead_corruption() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // === Setup: Create Variable wrapper with data ===
            let cfg = Config {
                partition: "recovery_offsets_ahead".to_string(),
                items_per_section: NZU64!(10),
                compression: None,
                codec_config: (),
                buffer_pool: PoolRef::new(NZUsize!(1024), NZUsize!(10)),
                write_buffer: NZUsize!(1024),
            };

            let mut variable = Journal::<_, u64>::init(context.clone(), cfg.clone())
                .await
                .unwrap();

            // Append 40 items across 4 sections to both journals
            for i in 0..40u64 {
                variable.append(i * 100).await.unwrap();
            }

            // Prune offsets journal ahead of data journal (impossible state)
            variable.offsets.prune(20).await.unwrap(); // Prune to position 20
            variable.data.prune(1).await.unwrap(); // Only prune data journal to section 1 (position 10)

            variable.close().await.unwrap();

            // === Verify corruption detected ===
            let result = Journal::<_, u64>::init(context.clone(), cfg.clone()).await;
            assert!(matches!(result, Err(Error::Corruption(_))));
        });
    }

    /// Test recovery from crash after appending to data journal but before appending to offsets journal.
    #[test_traced]
    fn test_variable_recovery_append_crash_offsets_behind() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // === Setup: Create Variable wrapper with partial data ===
            let cfg = Config {
                partition: "recovery_append_crash".to_string(),
                items_per_section: NZU64!(10),
                compression: None,
                codec_config: (),
                buffer_pool: PoolRef::new(NZUsize!(1024), NZUsize!(10)),
                write_buffer: NZUsize!(1024),
            };

            let mut variable = Journal::<_, u64>::init(context.clone(), cfg.clone())
                .await
                .unwrap();

            // Append 15 items to both journals (fills section 0, partial section 1)
            for i in 0..15u64 {
                variable.append(i * 100).await.unwrap();
            }

            assert_eq!(variable.size(), 15);

            // Manually append 5 more items directly to data journal only
            for i in 15..20u64 {
                variable.data.append(1, i * 100).await.unwrap();
            }
            // Offsets journal still has only 15 entries

            variable.close().await.unwrap();

            // === Verify recovery ===
            let variable = Journal::<_, u64>::init(context.clone(), cfg.clone())
                .await
                .unwrap();

            // Init should rebuild offsets journal from data journal replay
            assert_eq!(variable.size(), 20);
            assert_eq!(variable.oldest_retained_pos(), Some(0));

            // All items should be readable from both journals
            for i in 0..20u64 {
                assert_eq!(variable.read(i).await.unwrap(), i * 100);
            }

            // Offsets journal should be fully rebuilt to match data journal
            assert_eq!(variable.offsets.size(), 20);

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
                partition: "recovery_multiple_prunes".to_string(),
                items_per_section: NZU64!(10),
                compression: None,
                codec_config: (),
                buffer_pool: PoolRef::new(NZUsize!(1024), NZUsize!(10)),
                write_buffer: NZUsize!(1024),
            };

            let mut variable = Journal::<_, u64>::init(context.clone(), cfg.clone())
                .await
                .unwrap();

            // Append 50 items across 5 sections to both journals
            for i in 0..50u64 {
                variable.append(i * 100).await.unwrap();
            }

            // Prune to position 10 normally (both data and offsets journals pruned)
            variable.prune(10).await.unwrap();
            assert_eq!(variable.oldest_retained_pos(), Some(10));

            // === Simulate crash: Multiple prunes on data journal, not on offsets journal ===
            // Manually prune data journal to section 3 (position 30)
            variable.data.prune(3).await.unwrap();
            // Offsets journal still thinks oldest is position 10

            variable.close().await.unwrap();

            // === Verify recovery ===
            let variable = Journal::<_, u64>::init(context.clone(), cfg.clone())
                .await
                .unwrap();

            // Init should auto-repair: offsets journal pruned to match data journal
            assert_eq!(variable.oldest_retained_pos(), Some(30));
            assert_eq!(variable.size(), 50);

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
    /// Simulates a crash after offsets.rewind() completes but before data.rewind() completes.
    /// This creates a situation where offsets journal has been rewound but data journal still
    /// contains items across multiple sections. Verifies that init() correctly rebuilds the
    /// offsets index across all sections to match the data journal.
    #[test_traced]
    fn test_variable_recovery_rewind_crash_multi_section() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // === Setup: Create Variable wrapper with data across multiple sections ===
            let cfg = Config {
                partition: "recovery_rewind_crash".to_string(),
                items_per_section: NZU64!(10),
                compression: None,
                codec_config: (),
                buffer_pool: PoolRef::new(NZUsize!(1024), NZUsize!(10)),
                write_buffer: NZUsize!(1024),
            };

            let mut variable = Journal::<_, u64>::init(context.clone(), cfg.clone())
                .await
                .unwrap();

            // Append 25 items across 3 sections (section 0: 0-9, section 1: 10-19, section 2: 20-24)
            for i in 0..25u64 {
                variable.append(i * 100).await.unwrap();
            }

            assert_eq!(variable.size(), 25);

            // === Simulate crash during rewind(5) ===
            // Rewind offsets journal to size 5 (keeps positions 0-4)
            variable.offsets.rewind(5).await.unwrap();
            // CRASH before data.rewind() completes - data still has all 3 sections

            variable.close().await.unwrap();

            // === Verify recovery ===
            let mut variable = Journal::<_, u64>::init(context.clone(), cfg.clone())
                .await
                .unwrap();

            // Init should rebuild offsets[5-24] from data journal across all 3 sections
            assert_eq!(variable.size(), 25);
            assert_eq!(variable.oldest_retained_pos(), Some(0));

            // All items should be readable - offsets rebuilt correctly across all sections
            for i in 0..25u64 {
                assert_eq!(variable.read(i).await.unwrap(), i * 100);
            }

            // Verify offsets journal fully rebuilt
            assert_eq!(variable.offsets.size(), 25);

            // Verify next append gets position 25
            let pos = variable.append(2500).await.unwrap();
            assert_eq!(pos, 25);
            assert_eq!(variable.read(25).await.unwrap(), 2500);

            variable.destroy().await.unwrap();
        });
    }

    /// Test recovery from crash after data sync but before offsets sync when journal was
    /// previously emptied by pruning.
    #[test_traced]
    fn test_variable_recovery_empty_offsets_after_prune_and_append() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "recovery_empty_after_prune".to_string(),
                items_per_section: NZU64!(10),
                compression: None,
                codec_config: (),
                buffer_pool: PoolRef::new(NZUsize!(1024), NZUsize!(10)),
                write_buffer: NZUsize!(1024),
            };

            // === Phase 1: Create journal with one full section ===
            let mut journal = Journal::<_, u64>::init(context.clone(), cfg.clone())
                .await
                .unwrap();

            // Append 10 items (positions 0-9), fills section 0
            for i in 0..10u64 {
                journal.append(i * 100).await.unwrap();
            }
            assert_eq!(journal.size(), 10);
            assert_eq!(journal.oldest_retained_pos(), Some(0));

            // === Phase 2: Prune to create empty journal ===
            journal.prune(10).await.unwrap();
            assert_eq!(journal.size(), 10);
            assert_eq!(journal.oldest_retained_pos(), None); // Empty!

            // === Phase 3: Append directly to data journal to simulate crash ===
            // Manually append to data journal only (bypassing Variable's append logic)
            // This simulates the case where data was synced but offsets wasn't
            for i in 10..20u64 {
                journal.data.append(1, i * 100).await.unwrap();
            }
            // Sync the data journal (section 1)
            journal.data.sync(1).await.unwrap();
            // Do NOT sync offsets journal - simulates crash before offsets.sync()

            // Close without syncing offsets
            drop(journal);

            // === Phase 4: Verify recovery succeeds ===
            let journal = Journal::<_, u64>::init(context.clone(), cfg.clone())
                .await
                .expect("Should recover from crash after data sync but before offsets sync");

            // All data should be recovered
            assert_eq!(journal.size(), 20);
            assert_eq!(journal.oldest_retained_pos(), Some(10));

            // All items from position 10-19 should be readable
            for i in 10..20u64 {
                assert_eq!(journal.read(i).await.unwrap(), i * 100);
            }

            // Items 0-9 should be pruned
            for i in 0..10 {
                assert!(matches!(journal.read(i).await, Err(Error::ItemPruned(_))));
            }

            journal.destroy().await.unwrap();
        });
    }

    /// Test that offsets index is rebuilt from data after sync writes data but not offsets.
    #[test_traced]
    fn test_variable_concurrent_sync_recovery() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "concurrent_sync_recovery".to_string(),
                items_per_section: NZU64!(10),
                compression: None,
                codec_config: (),
                buffer_pool: PoolRef::new(NZUsize!(1024), NZUsize!(10)),
                write_buffer: NZUsize!(1024),
            };

            let mut journal = Journal::<_, u64>::init(context.clone(), cfg.clone())
                .await
                .unwrap();

            // Append items across a section boundary
            for i in 0..15u64 {
                journal.append(i * 100).await.unwrap();
            }

            // Manually sync only data to simulate crash during concurrent sync
            journal.commit().await.unwrap();

            // Simulate a crash (offsets not synced)
            drop(journal);

            let journal = Journal::<_, u64>::init(context.clone(), cfg.clone())
                .await
                .unwrap();

            // Data should be intact and offsets rebuilt
            assert_eq!(journal.size(), 15);
            for i in 0..15u64 {
                assert_eq!(journal.read(i).await.unwrap(), i * 100);
            }

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_init_at_size_zero() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "init_at_size_zero".to_string(),
                items_per_section: NZU64!(5),
                compression: None,
                codec_config: (),
                buffer_pool: PoolRef::new(NZUsize!(512), NZUsize!(2)),
                write_buffer: NZUsize!(1024),
            };

            let mut journal = Journal::<_, u64>::init_at_size(context.clone(), cfg.clone(), 0)
                .await
                .unwrap();

            // Size should be 0
            assert_eq!(journal.size(), 0);

            // No oldest retained position (empty journal)
            assert_eq!(journal.oldest_retained_pos(), None);

            // Next append should get position 0
            let pos = journal.append(100).await.unwrap();
            assert_eq!(pos, 0);
            assert_eq!(journal.size(), 1);
            assert_eq!(journal.read(0).await.unwrap(), 100);

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_init_at_size_section_boundary() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "init_a  t_size_boundary".to_string(),
                items_per_section: NZU64!(5),
                compression: None,
                codec_config: (),
                buffer_pool: PoolRef::new(NZUsize!(512), NZUsize!(2)),
                write_buffer: NZUsize!(1024),
            };

            // Initialize at position 10 (exactly at section 1 boundary with items_per_section=5)
            let mut journal = Journal::<_, u64>::init_at_size(context.clone(), cfg.clone(), 10)
                .await
                .unwrap();

            // Size should be 10
            assert_eq!(journal.size(), 10);

            // No data yet, so no oldest retained position
            assert_eq!(journal.oldest_retained_pos(), None);

            // Next append should get position 10
            let pos = journal.append(1000).await.unwrap();
            assert_eq!(pos, 10);
            assert_eq!(journal.size(), 11);
            assert_eq!(journal.read(10).await.unwrap(), 1000);

            // Can continue appending
            let pos = journal.append(1001).await.unwrap();
            assert_eq!(pos, 11);
            assert_eq!(journal.read(11).await.unwrap(), 1001);

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_init_at_size_mid_section() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "init_at_size_mid".to_string(),
                items_per_section: NZU64!(5),
                compression: None,
                codec_config: (),
                buffer_pool: PoolRef::new(NZUsize!(512), NZUsize!(2)),
                write_buffer: NZUsize!(1024),
            };

            // Initialize at position 7 (middle of section 1 with items_per_section=5)
            let mut journal = Journal::<_, u64>::init_at_size(context.clone(), cfg.clone(), 7)
                .await
                .unwrap();

            // Size should be 7
            assert_eq!(journal.size(), 7);

            // No data yet, so no oldest retained position
            assert_eq!(journal.oldest_retained_pos(), None);

            // Next append should get position 7
            let pos = journal.append(700).await.unwrap();
            assert_eq!(pos, 7);
            assert_eq!(journal.size(), 8);
            assert_eq!(journal.read(7).await.unwrap(), 700);

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_init_at_size_persistence() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "init_at_size_persist".to_string(),
                items_per_section: NZU64!(5),
                compression: None,
                codec_config: (),
                buffer_pool: PoolRef::new(NZUsize!(512), NZUsize!(2)),
                write_buffer: NZUsize!(1024),
            };

            // Initialize at position 15
            let mut journal = Journal::<_, u64>::init_at_size(context.clone(), cfg.clone(), 15)
                .await
                .unwrap();

            // Append some items
            for i in 0..5u64 {
                let pos = journal.append(1500 + i).await.unwrap();
                assert_eq!(pos, 15 + i);
            }

            assert_eq!(journal.size(), 20);

            // Close and reopen
            journal.close().await.unwrap();

            let mut journal = Journal::<_, u64>::init(context.clone(), cfg.clone())
                .await
                .unwrap();

            // Size and data should be preserved
            assert_eq!(journal.size(), 20);
            assert_eq!(journal.oldest_retained_pos(), Some(15));

            // Verify data
            for i in 0..5u64 {
                assert_eq!(journal.read(15 + i).await.unwrap(), 1500 + i);
            }

            // Can continue appending
            let pos = journal.append(9999).await.unwrap();
            assert_eq!(pos, 20);
            assert_eq!(journal.read(20).await.unwrap(), 9999);

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_init_at_size_large_offset() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "init_at_size_large".to_string(),
                items_per_section: NZU64!(5),
                compression: None,
                codec_config: (),
                buffer_pool: PoolRef::new(NZUsize!(512), NZUsize!(2)),
                write_buffer: NZUsize!(1024),
            };

            // Initialize at a large position (position 1000)
            let mut journal = Journal::<_, u64>::init_at_size(context.clone(), cfg.clone(), 1000)
                .await
                .unwrap();

            assert_eq!(journal.size(), 1000);
            // No data yet, so no oldest retained position
            assert_eq!(journal.oldest_retained_pos(), None);

            // Next append should get position 1000
            let pos = journal.append(100000).await.unwrap();
            assert_eq!(pos, 1000);
            assert_eq!(journal.read(1000).await.unwrap(), 100000);

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_init_at_size_prune_and_append() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "init_at_size_prune".to_string(),
                items_per_section: NZU64!(5),
                compression: None,
                codec_config: (),
                buffer_pool: PoolRef::new(NZUsize!(512), NZUsize!(2)),
                write_buffer: NZUsize!(1024),
            };

            // Initialize at position 20
            let mut journal = Journal::<_, u64>::init_at_size(context.clone(), cfg.clone(), 20)
                .await
                .unwrap();

            // Append items 20-29
            for i in 0..10u64 {
                journal.append(2000 + i).await.unwrap();
            }

            assert_eq!(journal.size(), 30);

            // Prune to position 25
            journal.prune(25).await.unwrap();

            assert_eq!(journal.size(), 30);
            assert_eq!(journal.oldest_retained_pos(), Some(25));

            // Verify remaining items are readable
            for i in 25..30u64 {
                assert_eq!(journal.read(i).await.unwrap(), 2000 + (i - 20));
            }

            // Continue appending
            let pos = journal.append(3000).await.unwrap();
            assert_eq!(pos, 30);

            journal.destroy().await.unwrap();
        });
    }

    /// Test `init_sync` when there is no existing data on disk.
    #[test_traced]
    fn test_init_sync_no_existing_data() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "test_fresh_start".into(),
                items_per_section: NZU64!(5),
                compression: None,
                codec_config: (),
                write_buffer: NZUsize!(1024),
                buffer_pool: PoolRef::new(NZUsize!(PAGE_SIZE), NZUsize!(PAGE_CACHE_SIZE)),
            };

            // Initialize journal with sync boundaries when no existing data exists
            let lower_bound = 10;
            let upper_bound = 26;
            let mut journal =
                Journal::init_sync(context.clone(), cfg.clone(), lower_bound..upper_bound)
                    .await
                    .expect("Failed to initialize journal with sync boundaries");

            assert_eq!(journal.size(), lower_bound);
            assert_eq!(journal.oldest_retained_pos(), None);

            // Append items using the contiguous API
            let pos1 = journal.append(42u64).await.unwrap();
            assert_eq!(pos1, lower_bound);
            assert_eq!(journal.read(pos1).await.unwrap(), 42u64);

            let pos2 = journal.append(43u64).await.unwrap();
            assert_eq!(pos2, lower_bound + 1);
            assert_eq!(journal.read(pos2).await.unwrap(), 43u64);

            journal.destroy().await.unwrap();
        });
    }

    /// Test `init_sync` when there is existing data that overlaps with the sync target range.
    #[test_traced]
    fn test_init_sync_existing_data_overlap() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "test_overlap".into(),
                items_per_section: NZU64!(5),
                compression: None,
                codec_config: (),
                write_buffer: NZUsize!(1024),
                buffer_pool: PoolRef::new(NZUsize!(PAGE_SIZE), NZUsize!(PAGE_CACHE_SIZE)),
            };

            // Create initial journal with data in multiple sections
            let mut journal =
                Journal::<deterministic::Context, u64>::init(context.clone(), cfg.clone())
                    .await
                    .expect("Failed to create initial journal");

            // Add data at positions 0-19 (sections 0-3 with items_per_section=5)
            for i in 0..20u64 {
                journal.append(i * 100).await.unwrap();
            }
            journal.close().await.unwrap();

            // Initialize with sync boundaries that overlap with existing data
            // lower_bound: 8 (section 1), upper_bound: 31 (last location 30, section 6)
            let lower_bound = 8;
            let upper_bound = 31;
            let mut journal = Journal::<deterministic::Context, u64>::init_sync(
                context.clone(),
                cfg.clone(),
                lower_bound..upper_bound,
            )
            .await
            .expect("Failed to initialize journal with overlap");

            assert_eq!(journal.size(), 20);

            // Verify oldest retained is pruned to lower_bound's section boundary (5)
            let oldest = journal.oldest_retained_pos();
            assert_eq!(oldest, Some(5)); // Section 1 starts at position 5

            // Verify data integrity: positions before 5 are pruned
            assert!(matches!(journal.read(0).await, Err(Error::ItemPruned(_))));
            assert!(matches!(journal.read(4).await, Err(Error::ItemPruned(_))));

            // Positions 5-19 should be accessible
            assert_eq!(journal.read(5).await.unwrap(), 500);
            assert_eq!(journal.read(8).await.unwrap(), 800);
            assert_eq!(journal.read(19).await.unwrap(), 1900);

            // Position 20+ should not exist yet
            assert!(matches!(
                journal.read(20).await,
                Err(Error::ItemOutOfRange(_))
            ));

            // Assert journal can accept new items
            let pos = journal.append(999).await.unwrap();
            assert_eq!(pos, 20);
            assert_eq!(journal.read(20).await.unwrap(), 999);

            journal.destroy().await.unwrap();
        });
    }

    /// Test `init_sync` with invalid parameters.
    #[should_panic]
    #[test_traced]
    fn test_init_sync_invalid_parameters() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "test_invalid".into(),
                items_per_section: NZU64!(5),
                compression: None,
                codec_config: (),
                write_buffer: NZUsize!(1024),
                buffer_pool: PoolRef::new(NZUsize!(PAGE_SIZE), NZUsize!(PAGE_CACHE_SIZE)),
            };

            #[allow(clippy::reversed_empty_ranges)]
            let _result = Journal::<deterministic::Context, u64>::init_sync(
                context.clone(),
                cfg,
                10..5, // invalid range: lower > upper
            )
            .await;
        });
    }

    /// Test `init_sync` when existing data exactly matches the sync range.
    #[test_traced]
    fn test_init_sync_existing_data_exact_match() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let items_per_section = NZU64!(5);
            let cfg = Config {
                partition: "test_exact_match".to_string(),
                items_per_section,
                compression: None,
                codec_config: (),
                write_buffer: NZUsize!(1024),
                buffer_pool: PoolRef::new(NZUsize!(PAGE_SIZE), NZUsize!(PAGE_CACHE_SIZE)),
            };

            // Create initial journal with data exactly matching sync range
            let mut journal =
                Journal::<deterministic::Context, u64>::init(context.clone(), cfg.clone())
                    .await
                    .expect("Failed to create initial journal");

            // Add data at positions 0-19 (sections 0-3 with items_per_section=5)
            for i in 0..20u64 {
                journal.append(i * 100).await.unwrap();
            }
            journal.close().await.unwrap();

            // Initialize with sync boundaries that exactly match existing data
            let lower_bound = 5; // section 1
            let upper_bound = 20; // section 3
            let mut journal = Journal::<deterministic::Context, u64>::init_sync(
                context.clone(),
                cfg.clone(),
                lower_bound..upper_bound,
            )
            .await
            .expect("Failed to initialize journal with exact match");

            assert_eq!(journal.size(), 20);

            // Verify pruning to lower bound (section 1 boundary = position 5)
            let oldest = journal.oldest_retained_pos();
            assert_eq!(oldest, Some(5)); // Section 1 starts at position 5

            // Verify positions before 5 are pruned
            assert!(matches!(journal.read(0).await, Err(Error::ItemPruned(_))));
            assert!(matches!(journal.read(4).await, Err(Error::ItemPruned(_))));

            // Positions 5-19 should be accessible
            assert_eq!(journal.read(5).await.unwrap(), 500);
            assert_eq!(journal.read(10).await.unwrap(), 1000);
            assert_eq!(journal.read(19).await.unwrap(), 1900);

            // Position 20+ should not exist yet
            assert!(matches!(
                journal.read(20).await,
                Err(Error::ItemOutOfRange(_))
            ));

            // Assert journal can accept new operations
            let pos = journal.append(999).await.unwrap();
            assert_eq!(pos, 20);
            assert_eq!(journal.read(20).await.unwrap(), 999);

            journal.destroy().await.unwrap();
        });
    }

    /// Test `init_sync` when existing data exceeds the sync target range.
    /// This tests that UnexpectedData error is returned when existing data goes beyond the upper bound.
    #[test_traced]
    fn test_init_sync_existing_data_exceeds_upper_bound() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let items_per_section = NZU64!(5);
            let cfg = Config {
                partition: "test_unexpected_data".into(),
                items_per_section,
                compression: None,
                codec_config: (),
                write_buffer: NZUsize!(1024),
                buffer_pool: PoolRef::new(NZUsize!(PAGE_SIZE), NZUsize!(PAGE_CACHE_SIZE)),
            };

            // Create initial journal with data beyond sync range
            let mut journal =
                Journal::<deterministic::Context, u64>::init(context.clone(), cfg.clone())
                    .await
                    .expect("Failed to create initial journal");

            // Add data at positions 0-29 (sections 0-5 with items_per_section=5)
            for i in 0..30u64 {
                journal.append(i * 1000).await.unwrap();
            }
            journal.close().await.unwrap();

            // Initialize with sync boundaries that are exceeded by existing data
            let lower_bound = 8; // section 1
            for upper_bound in 9..29 {
                let result = Journal::<deterministic::Context, u64>::init_sync(
                    context.clone(),
                    cfg.clone(),
                    lower_bound..upper_bound,
                )
                .await;

                // Should return UnexpectedData error since data exists beyond upper_bound
                assert!(matches!(result, Err(crate::adb::Error::UnexpectedData(_))));
            }
        });
    }

    /// Test `init_sync` when all existing data is stale (before lower bound).
    #[test_traced]
    fn test_init_sync_existing_data_stale() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let items_per_section = NZU64!(5);
            let cfg = Config {
                partition: "test_stale".into(),
                items_per_section,
                compression: None,
                codec_config: (),
                write_buffer: NZUsize!(1024),
                buffer_pool: PoolRef::new(NZUsize!(PAGE_SIZE), NZUsize!(PAGE_CACHE_SIZE)),
            };

            // Create initial journal with stale data
            let mut journal =
                Journal::<deterministic::Context, u64>::init(context.clone(), cfg.clone())
                    .await
                    .expect("Failed to create initial journal");

            // Add data at positions 0-9 (sections 0-1 with items_per_section=5)
            for i in 0..10u64 {
                journal.append(i * 100).await.unwrap();
            }
            journal.close().await.unwrap();

            // Initialize with sync boundaries beyond all existing data
            let lower_bound = 15; // section 3
            let upper_bound = 26; // last element in section 5
            let journal = Journal::<deterministic::Context, u64>::init_sync(
                context.clone(),
                cfg.clone(),
                lower_bound..upper_bound,
            )
            .await
            .expect("Failed to initialize journal with stale data");

            assert_eq!(journal.size(), 15);

            // Verify fresh journal (all old data destroyed, starts at position 15)
            assert_eq!(journal.oldest_retained_pos(), None);

            // Verify old positions don't exist
            assert!(matches!(journal.read(0).await, Err(Error::ItemPruned(_))));
            assert!(matches!(journal.read(9).await, Err(Error::ItemPruned(_))));
            assert!(matches!(journal.read(14).await, Err(Error::ItemPruned(_))));

            journal.destroy().await.unwrap();
        });
    }

    /// Test `init_sync` with section boundary edge cases.
    #[test_traced]
    fn test_init_sync_section_boundaries() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let items_per_section = NZU64!(5);
            let cfg = Config {
                partition: "test_boundaries".into(),
                items_per_section,
                compression: None,
                codec_config: (),
                write_buffer: NZUsize!(1024),
                buffer_pool: PoolRef::new(NZUsize!(PAGE_SIZE), NZUsize!(PAGE_CACHE_SIZE)),
            };

            // Create journal with data at section boundaries
            let mut journal =
                Journal::<deterministic::Context, u64>::init(context.clone(), cfg.clone())
                    .await
                    .expect("Failed to create initial journal");

            // Add data at positions 0-24 (sections 0-4 with items_per_section=5)
            for i in 0..25u64 {
                journal.append(i * 100).await.unwrap();
            }
            journal.close().await.unwrap();

            // Test sync boundaries exactly at section boundaries
            let lower_bound = 15; // Exactly at section boundary (15/5 = 3)
            let upper_bound = 25; // Last element exactly at section boundary (24/5 = 4)
            let mut journal = Journal::<deterministic::Context, u64>::init_sync(
                context.clone(),
                cfg.clone(),
                lower_bound..upper_bound,
            )
            .await
            .expect("Failed to initialize journal at boundaries");

            assert_eq!(journal.size(), 25);

            // Verify oldest retained is at section 3 boundary (position 15)
            let oldest = journal.oldest_retained_pos();
            assert_eq!(oldest, Some(15));

            // Verify positions before 15 are pruned
            assert!(matches!(journal.read(0).await, Err(Error::ItemPruned(_))));
            assert!(matches!(journal.read(14).await, Err(Error::ItemPruned(_))));

            // Verify positions 15-24 are accessible
            assert_eq!(journal.read(15).await.unwrap(), 1500);
            assert_eq!(journal.read(20).await.unwrap(), 2000);
            assert_eq!(journal.read(24).await.unwrap(), 2400);

            // Position 25+ should not exist yet
            assert!(matches!(
                journal.read(25).await,
                Err(Error::ItemOutOfRange(_))
            ));

            // Assert journal can accept new operations
            let pos = journal.append(999).await.unwrap();
            assert_eq!(pos, 25);
            assert_eq!(journal.read(25).await.unwrap(), 999);

            journal.destroy().await.unwrap();
        });
    }

    /// Test `init_sync` when range.start and range.end-1 are in the same section.
    #[test_traced]
    fn test_init_sync_same_section_bounds() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let items_per_section = NZU64!(5);
            let cfg = Config {
                partition: "test_same_section".into(),
                items_per_section,
                compression: None,
                codec_config: (),
                write_buffer: NZUsize!(1024),
                buffer_pool: PoolRef::new(NZUsize!(PAGE_SIZE), NZUsize!(PAGE_CACHE_SIZE)),
            };

            // Create journal with data in multiple sections
            let mut journal =
                Journal::<deterministic::Context, u64>::init(context.clone(), cfg.clone())
                    .await
                    .expect("Failed to create initial journal");

            // Add data at positions 0-14 (sections 0-2 with items_per_section=5)
            for i in 0..15u64 {
                journal.append(i * 100).await.unwrap();
            }
            journal.close().await.unwrap();

            // Test sync boundaries within the same section
            let lower_bound = 10; // operation 10 (section 2: 10/5 = 2)
            let upper_bound = 15; // Last operation 14 (section 2: 14/5 = 2)
            let mut journal = Journal::<deterministic::Context, u64>::init_sync(
                context.clone(),
                cfg.clone(),
                lower_bound..upper_bound,
            )
            .await
            .expect("Failed to initialize journal with same-section bounds");

            assert_eq!(journal.size(), 15);

            // Both operations are in section 2, so sections 0, 1 should be pruned, section 2 retained
            // Oldest retained position should be at section 2 boundary (position 10)
            let oldest = journal.oldest_retained_pos();
            assert_eq!(oldest, Some(10));

            // Verify positions before 10 are pruned
            assert!(matches!(journal.read(0).await, Err(Error::ItemPruned(_))));
            assert!(matches!(journal.read(9).await, Err(Error::ItemPruned(_))));

            // Verify positions 10-14 are accessible
            assert_eq!(journal.read(10).await.unwrap(), 1000);
            assert_eq!(journal.read(11).await.unwrap(), 1100);
            assert_eq!(journal.read(14).await.unwrap(), 1400);

            // Position 15+ should not exist yet
            assert!(matches!(
                journal.read(15).await,
                Err(Error::ItemOutOfRange(_))
            ));

            // Assert journal can accept new operations
            let pos = journal.append(999).await.unwrap();
            assert_eq!(pos, 15);
            assert_eq!(journal.read(15).await.unwrap(), 999);

            journal.destroy().await.unwrap();
        });
    }
}
