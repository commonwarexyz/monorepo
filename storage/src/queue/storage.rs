//! Queue storage implementation.

use super::Error;
use crate::{
    journal::contiguous::variable,
    metadata::{self, Metadata},
    rmap::RMap,
    Persistable,
};
use commonware_codec::CodecShared;
use commonware_runtime::{buffer::paged::CacheRef, Clock, Metrics, Storage};
use commonware_utils::sequence::U64;
use std::num::{NonZeroU64, NonZeroUsize};
use tracing::debug;

/// Metadata key for storing ack floor.
const ACK_FLOOR_KEY: U64 = U64::new(0);

/// Metadata key for storing ack ranges count.
const ACK_RANGES_KEY: U64 = U64::new(1);

/// Suffix for the ack metadata partition.
const ACK_SUFFIX: &str = "_ack";

/// Configuration for [Queue].
#[derive(Clone)]
pub struct Config<C> {
    /// The storage partition name for the queue's journal.
    pub partition: String,

    /// The number of items to store in each journal section.
    ///
    /// Larger values reduce file overhead but increase minimum pruning granularity.
    /// Once set, this value cannot be changed across restarts.
    pub items_per_section: NonZeroU64,

    /// Optional zstd compression level for stored items.
    ///
    /// If set, items will be compressed before storage. Higher values provide
    /// better compression but use more CPU.
    pub compression: Option<u8>,

    /// Codec configuration for encoding/decoding items.
    pub codec_config: C,

    /// Page cache for caching data.
    pub page_cache: CacheRef,

    /// Write buffer size for each section.
    pub write_buffer: NonZeroUsize,
}

impl<C> Config<C> {
    /// Returns the partition name for the ack metadata.
    fn ack_partition(&self) -> String {
        format!("{}{}", self.partition, ACK_SUFFIX)
    }
}

/// A durable, at-least-once delivery queue with per-item acknowledgment.
///
/// Items are stored in a journal and survive crashes. The reader must acknowledge
/// each item individually after processing to allow pruning. Items can be acknowledged
/// out of order, enabling parallel processing.
///
/// # Acknowledgment Model
///
/// The queue tracks acknowledgments using:
/// - `ack_floor`: All items at positions < floor are considered acknowledged
/// - `acked_above`: An [RMap] of acknowledged positions >= floor
///
/// When items are acked contiguously from the floor (e.g., floor=5, then ack 5, 6, 7),
/// the floor advances automatically. This coalescing keeps memory usage bounded.
///
/// # Delivery Semantics
///
/// - **Enqueue**: Items are appended to the journal. Call [Queue::sync] to guarantee
///   durability.
/// - **Dequeue**: Returns unacked items in FIFO order, skipping already-acked items.
/// - **Ack**: Marks a specific item as processed.
/// - **Prune**: Removes items below the ack floor from storage.
///
/// # Crash Recovery
///
/// On restart, the queue loads the persisted ack state and replays from the ack floor,
/// skipping items that were previously acknowledged. This means:
/// - Items that were enqueued but not synced may be lost
/// - Items that were acked but not synced will be re-delivered
/// - Items above the ack floor that were acked and synced will be skipped
pub struct Queue<E: Clock + Storage + Metrics, V: CodecShared> {
    /// The underlying journal storing queue items.
    journal: variable::Journal<E, V>,

    /// Metadata store for persisting ack state.
    ack_metadata: Metadata<E, U64, Vec<u8>>,

    /// Position of the next item to dequeue.
    ///
    /// Invariant: `ack_floor <= read_pos <= journal.size()`
    read_pos: u64,

    /// All items at positions < ack_floor are acknowledged.
    ///
    /// Invariant: `journal.pruning_boundary() <= ack_floor`
    ack_floor: u64,

    /// Ranges of acknowledged items at positions >= ack_floor.
    ///
    /// When an item at position == ack_floor is acked, the floor advances
    /// and any contiguous acked items are consumed.
    acked_above: RMap,

    /// Whether ack state has been modified since last sync.
    ack_dirty: bool,
}

impl<E: Clock + Storage + Metrics, V: CodecShared> Queue<E, V> {
    /// Initialize a queue from storage.
    ///
    /// On first initialization, creates an empty queue. On restart, loads the persisted
    /// ack state and begins reading from the ack floor (providing at-least-once delivery
    /// for unacked items).
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying journal or metadata cannot be initialized.
    pub async fn init(context: E, cfg: Config<V::Cfg>) -> Result<Self, Error> {
        let ack_partition = cfg.ack_partition();

        let journal = variable::Journal::init(
            context.with_label("journal"),
            variable::Config {
                partition: cfg.partition,
                items_per_section: cfg.items_per_section,
                compression: cfg.compression,
                codec_config: cfg.codec_config,
                page_cache: cfg.page_cache,
                write_buffer: cfg.write_buffer,
            },
        )
        .await?;

        let ack_metadata = Metadata::init(
            context.with_label("ack"),
            metadata::Config {
                partition: ack_partition,
                codec_config: ((0..).into(), ()),
            },
        )
        .await?;

        // Load persisted ack state
        let (ack_floor, acked_above) = Self::load_ack_state(&ack_metadata);

        // On restart, begin reading from the ack floor
        let start_pos = ack_floor;

        debug!(
            start_pos,
            ack_floor,
            size = journal.size(),
            pruning_boundary = journal.pruning_boundary(),
            "queue initialized"
        );

        Ok(Self {
            journal,
            ack_metadata,
            read_pos: start_pos,
            ack_floor,
            acked_above,
            ack_dirty: false,
        })
    }

    /// Load ack state from metadata.
    fn load_ack_state(metadata: &Metadata<E, U64, Vec<u8>>) -> (u64, RMap) {
        // Load ack floor
        let ack_floor = metadata
            .get(&ACK_FLOOR_KEY)
            .and_then(|bytes| {
                if bytes.len() >= 8 {
                    Some(u64::from_le_bytes(bytes[..8].try_into().unwrap()))
                } else {
                    None
                }
            })
            .unwrap_or(0);

        // Load ack ranges
        let mut acked_above = RMap::new();
        if let Some(bytes) = metadata.get(&ACK_RANGES_KEY) {
            // Format: [count: u64][start: u64, end: u64]*
            if bytes.len() >= 8 {
                let count = u64::from_le_bytes(bytes[..8].try_into().unwrap()) as usize;
                let mut offset = 8;
                for _ in 0..count {
                    if offset + 16 <= bytes.len() {
                        let start =
                            u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap());
                        let end =
                            u64::from_le_bytes(bytes[offset + 8..offset + 16].try_into().unwrap());
                        // Insert each value in the range
                        for pos in start..=end {
                            acked_above.insert(pos);
                        }
                        offset += 16;
                    }
                }
            }
        }

        (ack_floor, acked_above)
    }

    /// Save ack state to metadata.
    fn save_ack_state(&mut self) {
        // Save ack floor
        self.ack_metadata
            .put(ACK_FLOOR_KEY, self.ack_floor.to_le_bytes().to_vec());

        // Save ack ranges
        let ranges: Vec<_> = self.acked_above.iter().collect();
        let mut bytes = Vec::with_capacity(8 + ranges.len() * 16);
        bytes.extend_from_slice(&(ranges.len() as u64).to_le_bytes());
        for (&start, &end) in &ranges {
            bytes.extend_from_slice(&start.to_le_bytes());
            bytes.extend_from_slice(&end.to_le_bytes());
        }
        self.ack_metadata.put(ACK_RANGES_KEY, bytes);

        self.ack_dirty = false;
    }

    /// Check if a position is acknowledged.
    fn is_acked(&self, position: u64) -> bool {
        position < self.ack_floor || self.acked_above.get(&position).is_some()
    }

    /// Enqueue an item, returning its position.
    ///
    /// The item is appended to the journal but may not be durable until [Queue::sync]
    /// is called. If the process crashes before sync, the item may be lost.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying storage operation fails.
    pub async fn enqueue(&mut self, item: V) -> Result<u64, Error> {
        let pos = self.journal.append(item).await?;
        debug!(position = pos, "enqueued item");
        Ok(pos)
    }

    /// Dequeue the next unacknowledged item, returning its position and value.
    ///
    /// Returns `None` if the queue is empty (all items have been read or acknowledged).
    ///
    /// Items that have been acknowledged (even if not yet pruned) will be skipped.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying storage operation fails.
    pub async fn dequeue(&mut self) -> Result<Option<(u64, V)>, Error> {
        // Find next unacked position
        while self.read_pos < self.journal.size() {
            if self.is_acked(self.read_pos) {
                self.read_pos += 1;
                continue;
            }

            let item = self.journal.read(self.read_pos).await?;
            let pos = self.read_pos;
            self.read_pos += 1;

            debug!(position = pos, "dequeued item");
            return Ok(Some((pos, item)));
        }

        Ok(None)
    }

    /// Peek at the next unacknowledged item without advancing the read position.
    ///
    /// Returns `None` if the queue is empty (all items have been read or acknowledged).
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying storage operation fails.
    pub async fn peek(&self) -> Result<Option<(u64, V)>, Error> {
        let mut pos = self.read_pos;
        while pos < self.journal.size() {
            if self.is_acked(pos) {
                pos += 1;
                continue;
            }

            let item = self.journal.read(pos).await?;
            return Ok(Some((pos, item)));
        }

        Ok(None)
    }

    /// Acknowledge processing of an item at the given position.
    ///
    /// After acknowledgment, the item will be skipped on dequeue and may be pruned
    /// (once it falls below the ack floor). The ack state is not durable until
    /// [Queue::sync] is called.
    ///
    /// If items are acked contiguously from the ack floor, the floor advances
    /// automatically to keep memory bounded.
    ///
    /// # Arguments
    ///
    /// * `position` - The position of the item to acknowledge.
    ///
    /// # Errors
    ///
    /// - Returns [Error::PositionOutOfRange] if position >= queue size.
    pub fn ack(&mut self, position: u64) -> Result<(), Error> {
        let size = self.journal.size();
        if position >= size {
            return Err(Error::PositionOutOfRange(position, size));
        }

        // Already acked via floor
        if position < self.ack_floor {
            return Ok(());
        }

        // Already acked above floor
        if self.acked_above.get(&position).is_some() {
            return Ok(());
        }

        self.ack_dirty = true;

        if position == self.ack_floor {
            // Advance floor
            self.ack_floor = position + 1;

            // Consume any contiguous acked items
            while self.acked_above.get(&self.ack_floor).is_some() {
                self.acked_above.remove(self.ack_floor, self.ack_floor);
                self.ack_floor += 1;
            }

            debug!(ack_floor = self.ack_floor, "advanced ack floor");
        } else {
            // Add to acked_above
            self.acked_above.insert(position);
            debug!(position, "acked item above floor");
        }

        Ok(())
    }

    /// Acknowledge all items up to (but not including) the given position.
    ///
    /// This is a convenience method for batch acknowledgment. It's equivalent to calling
    /// [Queue::ack] for each position in `[ack_floor, up_to)`, but more efficient as it
    /// directly advances the ack floor.
    ///
    /// # Arguments
    ///
    /// * `up_to` - The exclusive upper bound. Items at positions `[ack_floor, up_to)` are acknowledged.
    ///
    /// # Errors
    ///
    /// - Returns [Error::PositionOutOfRange] if `up_to > queue size`.
    pub fn ack_up_to(&mut self, up_to: u64) -> Result<(), Error> {
        let size = self.journal.size();
        if up_to > size {
            return Err(Error::PositionOutOfRange(up_to, size));
        }

        // Nothing to do if up_to is at or below current floor
        if up_to <= self.ack_floor {
            return Ok(());
        }

        self.ack_dirty = true;

        // Remove any acked_above entries that will be covered by the new floor
        self.acked_above.remove(self.ack_floor, up_to - 1);

        // Advance floor
        self.ack_floor = up_to;

        // Consume any contiguous acked items above the new floor
        while self.acked_above.get(&self.ack_floor).is_some() {
            self.acked_above.remove(self.ack_floor, self.ack_floor);
            self.ack_floor += 1;
        }

        debug!(ack_floor = self.ack_floor, "batch acked up to");
        Ok(())
    }

    /// Returns the current read position.
    ///
    /// This is the position of the next item that will be checked by [Queue::dequeue].
    pub const fn read_position(&self) -> u64 {
        self.read_pos
    }

    /// Returns the current ack floor.
    ///
    /// All items at positions less than this value are considered acknowledged.
    pub const fn ack_floor(&self) -> u64 {
        self.ack_floor
    }

    /// Returns the total number of items that have been enqueued.
    ///
    /// This count is not affected by pruning. It represents the position that the
    /// next enqueued item will receive.
    pub const fn size(&self) -> u64 {
        self.journal.size()
    }

    /// Returns the number of items available to be dequeued.
    ///
    /// This is an upper bound - it counts items from read_pos to size, but some
    /// may already be acknowledged.
    pub const fn pending(&self) -> u64 {
        self.journal.size().saturating_sub(self.read_pos)
    }

    /// Returns the number of unacked items above the ack floor that are tracked.
    ///
    /// This represents the memory overhead of out-of-order acking.
    pub fn acked_above_count(&self) -> usize {
        self.acked_above
            .iter()
            .map(|(&s, &e)| (e - s + 1) as usize)
            .sum()
    }

    /// Returns the number of items currently retained in storage.
    ///
    /// This includes both acknowledged (awaiting prune) and unacknowledged items.
    pub fn retained(&self) -> u64 {
        self.journal
            .size()
            .saturating_sub(self.journal.pruning_boundary())
    }

    /// Returns whether the queue has any pending unacked items.
    pub fn is_empty(&self) -> bool {
        // Total acked = items below floor + items tracked in acked_above
        // Empty when all items in queue are acked
        let total_acked = self.ack_floor + self.acked_above_count() as u64;
        total_acked >= self.journal.size()
    }

    /// Returns whether a specific position has been acknowledged.
    pub fn is_position_acked(&self, position: u64) -> bool {
        self.is_acked(position)
    }

    /// Prune acknowledged items from storage.
    ///
    /// Removes items at positions less than the current ack floor from the
    /// underlying journal. Returns `true` if any data was pruned.
    ///
    /// Note: Due to section alignment, some items may be retained even after pruning.
    /// The actual pruning boundary may be less than `ack_floor`.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying storage operation fails.
    pub async fn prune(&mut self) -> Result<bool, Error> {
        let pruned = self.journal.prune(self.ack_floor).await?;
        if pruned {
            debug!(ack_floor = self.ack_floor, "pruned acknowledged items");
        }
        Ok(pruned)
    }

    /// Reset the read position to re-deliver all unacknowledged items.
    ///
    /// After calling this method, [Queue::dequeue] will return items starting from
    /// the ack floor, skipping any that have been acknowledged.
    pub fn reset(&mut self) {
        let old_pos = self.read_pos;
        self.read_pos = self.ack_floor;
        debug!(
            old_read_pos = old_pos,
            new_read_pos = self.read_pos,
            "reset read position"
        );
    }
}

impl<E: Clock + Storage + Metrics, V: CodecShared> Persistable for Queue<E, V> {
    type Error = Error;

    /// Commit enqueued items and ack state to storage.
    ///
    /// # Sync Ordering
    ///
    /// The journal is synced before the ack metadata. This ordering ensures
    /// at-least-once delivery semantics:
    ///
    /// - If a crash occurs after journal sync but before ack metadata sync,
    ///   items are persisted but ack state may be stale. On recovery, some
    ///   items may be re-delivered (at-least-once).
    ///
    /// - If ack metadata were synced first, a crash could leave acks persisted
    ///   for items that were never durably written, causing item loss.
    ///
    /// This ordering prioritizes data safety over exactly-once delivery.
    async fn commit(&mut self) -> Result<(), Self::Error> {
        if self.ack_dirty {
            self.save_ack_state();
        }
        // Sync journal first to ensure items are durable before acks
        self.journal.commit().await?;
        self.ack_metadata.sync().await?;
        Ok(())
    }

    /// Sync enqueued items and ack state to storage.
    ///
    /// # Sync Ordering
    ///
    /// The journal is synced before the ack metadata. This ordering ensures
    /// at-least-once delivery semantics:
    ///
    /// - If a crash occurs after journal sync but before ack metadata sync,
    ///   items are persisted but ack state may be stale. On recovery, some
    ///   items may be re-delivered (at-least-once).
    ///
    /// - If ack metadata were synced first, a crash could leave acks persisted
    ///   for items that were never durably written, causing item loss.
    ///
    /// This ordering prioritizes data safety over exactly-once delivery.
    async fn sync(&mut self) -> Result<(), Self::Error> {
        if self.ack_dirty {
            self.save_ack_state();
        }
        // Sync journal first to ensure items are durable before acks
        self.journal.sync().await?;
        self.ack_metadata.sync().await?;
        Ok(())
    }

    async fn destroy(self) -> Result<(), Self::Error> {
        self.journal.destroy().await?;
        self.ack_metadata.destroy().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::RangeCfg;
    use commonware_macros::test_traced;
    use commonware_runtime::{buffer::paged::CacheRef, deterministic, Runner};
    use commonware_utils::{NZUsize, NZU16, NZU64};
    use std::num::NonZeroU16;

    const PAGE_SIZE: NonZeroU16 = NZU16!(1024);
    const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(10);

    fn test_config(partition: &str) -> Config<(RangeCfg<usize>, ())> {
        Config {
            partition: partition.to_string(),
            items_per_section: NZU64!(10),
            compression: None,
            codec_config: ((0..).into(), ()),
            page_cache: CacheRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
            write_buffer: NZUsize!(4096),
        }
    }

    #[test_traced]
    fn test_basic_enqueue_dequeue() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_config("test_basic");
            let mut queue = Queue::<_, Vec<u8>>::init(context.clone(), cfg)
                .await
                .unwrap();

            // Queue should be empty initially
            assert!(queue.is_empty());
            assert_eq!(queue.pending(), 0);
            assert_eq!(queue.size(), 0);

            // Enqueue items
            let pos0 = queue.enqueue(b"item0".to_vec()).await.unwrap();
            let pos1 = queue.enqueue(b"item1".to_vec()).await.unwrap();
            let pos2 = queue.enqueue(b"item2".to_vec()).await.unwrap();

            assert_eq!(pos0, 0);
            assert_eq!(pos1, 1);
            assert_eq!(pos2, 2);
            assert_eq!(queue.size(), 3);
            assert_eq!(queue.pending(), 3);
            assert!(!queue.is_empty());

            // Dequeue items
            let (p, item) = queue.dequeue().await.unwrap().unwrap();
            assert_eq!(p, 0);
            assert_eq!(item, b"item0");
            assert_eq!(queue.pending(), 2);

            let (p, item) = queue.dequeue().await.unwrap().unwrap();
            assert_eq!(p, 1);
            assert_eq!(item, b"item1");
            assert_eq!(queue.pending(), 1);

            let (p, item) = queue.dequeue().await.unwrap().unwrap();
            assert_eq!(p, 2);
            assert_eq!(item, b"item2");
            assert_eq!(queue.pending(), 0);

            // Queue still has unacked items
            assert!(!queue.is_empty());
            assert!(queue.dequeue().await.unwrap().is_none());

            queue.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_sequential_ack() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_config("test_seq_ack");
            let mut queue = Queue::<_, Vec<u8>>::init(context.clone(), cfg)
                .await
                .unwrap();

            // Enqueue items
            for i in 0..5u8 {
                queue.enqueue(vec![i]).await.unwrap();
            }

            // Dequeue and ack sequentially
            for i in 0..5 {
                let (pos, _) = queue.dequeue().await.unwrap().unwrap();
                assert_eq!(pos, i);
                queue.ack(pos).unwrap();
                assert_eq!(queue.ack_floor(), i + 1);
            }

            // All items acked
            assert!(queue.is_empty());
            assert_eq!(queue.ack_floor(), 5);

            queue.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_out_of_order_ack() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_config("test_ooo_ack");
            let mut queue = Queue::<_, Vec<u8>>::init(context.clone(), cfg)
                .await
                .unwrap();

            // Enqueue items
            for i in 0..5u8 {
                queue.enqueue(vec![i]).await.unwrap();
            }

            // Dequeue all
            for _ in 0..5 {
                queue.dequeue().await.unwrap();
            }

            // Ack out of order: 2, 4, 1, 3, 0
            queue.ack(2).unwrap();
            assert_eq!(queue.ack_floor(), 0); // Floor doesn't move
            assert!(queue.is_position_acked(2));

            queue.ack(4).unwrap();
            assert_eq!(queue.ack_floor(), 0);
            assert!(queue.is_position_acked(4));

            queue.ack(1).unwrap();
            assert_eq!(queue.ack_floor(), 0);

            queue.ack(3).unwrap();
            assert_eq!(queue.ack_floor(), 0);

            // Ack 0 - floor should advance to 5 (consuming 1,2,3,4)
            queue.ack(0).unwrap();
            assert_eq!(queue.ack_floor(), 5);
            assert!(queue.is_empty());

            queue.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_ack_up_to() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_config("test_ack_up_to");
            let mut queue = Queue::<_, Vec<u8>>::init(context.clone(), cfg)
                .await
                .unwrap();

            // Enqueue items
            for i in 0..10u8 {
                queue.enqueue(vec![i]).await.unwrap();
            }

            // Batch ack items 0-4
            queue.ack_up_to(5).unwrap();
            assert_eq!(queue.ack_floor(), 5);

            // Items 0-4 should be acked
            for i in 0..5 {
                assert!(queue.is_position_acked(i));
            }
            // Items 5-9 should not be acked
            for i in 5..10 {
                assert!(!queue.is_position_acked(i));
            }

            // Dequeue should start at 5
            let (p, _) = queue.dequeue().await.unwrap().unwrap();
            assert_eq!(p, 5);

            queue.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_ack_up_to_with_existing_acks() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_config("test_ack_up_to_existing");
            let mut queue = Queue::<_, Vec<u8>>::init(context.clone(), cfg)
                .await
                .unwrap();

            // Enqueue items
            for i in 0..10u8 {
                queue.enqueue(vec![i]).await.unwrap();
            }

            // Ack some items out of order first
            queue.ack(7).unwrap();
            queue.ack(8).unwrap();
            assert_eq!(queue.acked_above_count(), 2);

            // Batch ack up to 5
            queue.ack_up_to(5).unwrap();
            assert_eq!(queue.ack_floor(), 5);
            // Items 7, 8 should still be tracked in acked_above
            assert_eq!(queue.acked_above_count(), 2);

            // Now batch ack up to 9 - should consume the acked_above entries
            queue.ack_up_to(9).unwrap();
            assert_eq!(queue.ack_floor(), 9);
            assert_eq!(queue.acked_above_count(), 0);

            queue.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_ack_up_to_coalesces_with_acked_above() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_config("test_ack_up_to_coalesce");
            let mut queue = Queue::<_, Vec<u8>>::init(context.clone(), cfg)
                .await
                .unwrap();

            // Enqueue items
            for i in 0..10u8 {
                queue.enqueue(vec![i]).await.unwrap();
            }

            // Ack items 5, 6, 7 first
            queue.ack(5).unwrap();
            queue.ack(6).unwrap();
            queue.ack(7).unwrap();
            assert_eq!(queue.ack_floor(), 0);

            // Batch ack up to 5 - should coalesce with 5, 6, 7
            queue.ack_up_to(5).unwrap();
            assert_eq!(queue.ack_floor(), 8); // Consumed 5, 6, 7

            queue.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_ack_up_to_errors() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_config("test_ack_up_to_errors");
            let mut queue = Queue::<_, Vec<u8>>::init(context.clone(), cfg)
                .await
                .unwrap();

            queue.enqueue(b"item0".to_vec()).await.unwrap();
            queue.enqueue(b"item1".to_vec()).await.unwrap();

            // Can't ack_up_to beyond queue size
            let err = queue.ack_up_to(5).unwrap_err();
            assert!(matches!(err, Error::PositionOutOfRange(5, 2)));

            // Can ack_up_to at queue size
            queue.ack_up_to(2).unwrap();
            assert_eq!(queue.ack_floor(), 2);

            // Acking up_to at or below floor is a no-op
            queue.ack_up_to(1).unwrap();
            assert_eq!(queue.ack_floor(), 2);

            queue.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_dequeue_skips_acked() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_config("test_skip_acked");
            let mut queue = Queue::<_, Vec<u8>>::init(context.clone(), cfg)
                .await
                .unwrap();

            // Enqueue items 0-4
            for i in 0..5u8 {
                queue.enqueue(vec![i]).await.unwrap();
            }

            // Ack items 1 and 3 before reading
            queue.ack(1).unwrap();
            queue.ack(3).unwrap();

            // Dequeue should skip 1 and 3
            let (p, item) = queue.dequeue().await.unwrap().unwrap();
            assert_eq!(p, 0);
            assert_eq!(item, vec![0]);

            let (p, item) = queue.dequeue().await.unwrap().unwrap();
            assert_eq!(p, 2); // Skipped 1
            assert_eq!(item, vec![2]);

            let (p, item) = queue.dequeue().await.unwrap().unwrap();
            assert_eq!(p, 4); // Skipped 3
            assert_eq!(item, vec![4]);

            assert!(queue.dequeue().await.unwrap().is_none());

            queue.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_peek() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_config("test_peek");
            let mut queue = Queue::<_, Vec<u8>>::init(context.clone(), cfg)
                .await
                .unwrap();

            // Peek on empty queue
            assert!(queue.peek().await.unwrap().is_none());

            // Enqueue and peek
            queue.enqueue(b"item0".to_vec()).await.unwrap();
            let (p, item) = queue.peek().await.unwrap().unwrap();
            assert_eq!(p, 0);
            assert_eq!(item, b"item0");

            // Peek doesn't advance position
            let (p, item) = queue.peek().await.unwrap().unwrap();
            assert_eq!(p, 0);
            assert_eq!(item, b"item0");

            // Dequeue returns same item
            let (p, item) = queue.dequeue().await.unwrap().unwrap();
            assert_eq!(p, 0);
            assert_eq!(item, b"item0");

            queue.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_ack_errors() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_config("test_ack_errors");
            let mut queue = Queue::<_, Vec<u8>>::init(context.clone(), cfg)
                .await
                .unwrap();

            queue.enqueue(b"item0".to_vec()).await.unwrap();
            queue.enqueue(b"item1".to_vec()).await.unwrap();

            // Can't ack position beyond queue size
            let err = queue.ack(5).unwrap_err();
            assert!(matches!(err, Error::PositionOutOfRange(5, 2)));

            // Can ack unread items
            queue.ack(1).unwrap();
            assert!(queue.is_position_acked(1));

            // Double ack is a no-op
            queue.ack(1).unwrap();

            queue.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_prune() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_config("test_prune");
            let mut queue = Queue::<_, Vec<u8>>::init(context.clone(), cfg)
                .await
                .unwrap();

            // Enqueue items (more than items_per_section to test pruning)
            for i in 0..25u8 {
                queue.enqueue(vec![i]).await.unwrap();
            }
            queue.sync().await.unwrap();

            // Read and ack some items
            for i in 0..15 {
                queue.dequeue().await.unwrap();
                queue.ack(i).unwrap();
            }
            assert_eq!(queue.ack_floor(), 15);

            // Prune acknowledged items
            let pruned = queue.prune().await.unwrap();
            assert!(pruned);

            // Items 15+ should still be readable
            let (p, item) = queue.dequeue().await.unwrap().unwrap();
            assert_eq!(p, 15);
            assert_eq!(item, vec![15]);

            queue.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_multiple_sequential_prunes() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_config("test_multi_prune");
            let mut queue = Queue::<_, Vec<u8>>::init(context.clone(), cfg)
                .await
                .unwrap();

            // Enqueue many items across multiple sections (items_per_section = 10)
            for i in 0..50u8 {
                queue.enqueue(vec![i]).await.unwrap();
            }
            queue.sync().await.unwrap();

            // First batch: ack and prune items 0-14
            for i in 0..15 {
                queue.dequeue().await.unwrap();
                queue.ack(i).unwrap();
            }
            assert_eq!(queue.ack_floor(), 15);
            queue.sync().await.unwrap();
            let pruned1 = queue.prune().await.unwrap();
            assert!(pruned1);

            // Verify items 15+ still readable
            let (p, item) = queue.dequeue().await.unwrap().unwrap();
            assert_eq!(p, 15);
            assert_eq!(item, vec![15]);

            // Second batch: ack and prune items 15-29
            queue.ack(15).unwrap();
            for i in 16..30 {
                queue.dequeue().await.unwrap();
                queue.ack(i).unwrap();
            }
            assert_eq!(queue.ack_floor(), 30);
            queue.sync().await.unwrap();
            let pruned2 = queue.prune().await.unwrap();
            assert!(pruned2);

            // Verify items 30+ still readable
            let (p, item) = queue.dequeue().await.unwrap().unwrap();
            assert_eq!(p, 30);
            assert_eq!(item, vec![30]);

            // Third batch: ack remaining items
            queue.ack(30).unwrap();
            for i in 31..50 {
                queue.dequeue().await.unwrap();
                queue.ack(i).unwrap();
            }
            assert_eq!(queue.ack_floor(), 50);
            queue.sync().await.unwrap();
            let pruned3 = queue.prune().await.unwrap();
            assert!(pruned3);

            // Queue should be empty now
            assert!(queue.is_empty());
            assert!(queue.dequeue().await.unwrap().is_none());

            queue.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_crash_recovery_preserves_ack_state() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_config("test_recovery_ack");

            // First session: enqueue, ack out of order, sync
            {
                let mut queue = Queue::<_, Vec<u8>>::init(context.with_label("first"), cfg.clone())
                    .await
                    .unwrap();

                for i in 0..10u8 {
                    queue.enqueue(vec![i]).await.unwrap();
                }

                // Ack items 0, 1, 2, 5, 7
                queue.ack(0).unwrap();
                queue.ack(1).unwrap();
                queue.ack(2).unwrap();
                queue.ack(5).unwrap();
                queue.ack(7).unwrap();

                assert_eq!(queue.ack_floor(), 3); // 0,1,2 consumed

                queue.sync().await.unwrap();
                drop(queue);
            }

            // Second session: verify ack state is preserved
            {
                let mut queue =
                    Queue::<_, Vec<u8>>::init(context.with_label("second"), cfg.clone())
                        .await
                        .unwrap();

                assert_eq!(queue.ack_floor(), 3);
                assert!(queue.is_position_acked(5));
                assert!(queue.is_position_acked(7));
                assert!(!queue.is_position_acked(4));
                assert!(!queue.is_position_acked(6));

                // Dequeue should return items 3, 4, 6, 8, 9 (skipping acked 5, 7)
                let (p, _) = queue.dequeue().await.unwrap().unwrap();
                assert_eq!(p, 3);

                let (p, _) = queue.dequeue().await.unwrap().unwrap();
                assert_eq!(p, 4);

                let (p, _) = queue.dequeue().await.unwrap().unwrap();
                assert_eq!(p, 6); // Skipped 5

                let (p, _) = queue.dequeue().await.unwrap().unwrap();
                assert_eq!(p, 8); // Skipped 7

                let (p, _) = queue.dequeue().await.unwrap().unwrap();
                assert_eq!(p, 9);

                queue.destroy().await.unwrap();
            }
        });
    }

    #[test_traced]
    fn test_crash_recovery_unsynced_acks_lost() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_config("test_recovery_unsync");

            // First session: enqueue, ack, but don't sync
            {
                let mut queue = Queue::<_, Vec<u8>>::init(context.with_label("first"), cfg.clone())
                    .await
                    .unwrap();

                for i in 0..5u8 {
                    queue.enqueue(vec![i]).await.unwrap();
                }
                queue.sync().await.unwrap(); // Sync journal only

                // Ack without sync
                queue.ack(0).unwrap();
                queue.ack(1).unwrap();
                queue.ack(2).unwrap();
                assert_eq!(queue.ack_floor(), 3);

                // Don't sync - simulate crash
                drop(queue);
            }

            // Second session: ack state should be lost
            {
                let mut queue =
                    Queue::<_, Vec<u8>>::init(context.with_label("second"), cfg.clone())
                        .await
                        .unwrap();

                // Ack floor should be 0 (lost)
                assert_eq!(queue.ack_floor(), 0);

                // All items re-delivered
                for i in 0..5 {
                    let (p, _) = queue.dequeue().await.unwrap().unwrap();
                    assert_eq!(p, i);
                }

                queue.destroy().await.unwrap();
            }
        });
    }

    #[test_traced]
    fn test_reset() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_config("test_reset");
            let mut queue = Queue::<_, Vec<u8>>::init(context.clone(), cfg)
                .await
                .unwrap();

            // Enqueue items
            for i in 0..5u8 {
                queue.enqueue(vec![i]).await.unwrap();
            }

            // Read some
            queue.dequeue().await.unwrap();
            queue.dequeue().await.unwrap();
            queue.dequeue().await.unwrap();
            assert_eq!(queue.read_position(), 3);

            // Reset without ack - should go back to 0
            queue.reset();
            assert_eq!(queue.read_position(), 0);

            // Verify we can re-read
            let (p, item) = queue.dequeue().await.unwrap().unwrap();
            assert_eq!(p, 0);
            assert_eq!(item, vec![0]);

            queue.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_reset_with_ack() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_config("test_reset_ack");
            let mut queue = Queue::<_, Vec<u8>>::init(context.clone(), cfg)
                .await
                .unwrap();

            // Enqueue items
            for i in 0..10u8 {
                queue.enqueue(vec![i]).await.unwrap();
            }

            // Read and ack some
            for i in 0..5 {
                queue.dequeue().await.unwrap();
                queue.ack(i).unwrap();
            }
            assert_eq!(queue.ack_floor(), 5);
            assert_eq!(queue.read_position(), 5);

            // Read a few more
            queue.dequeue().await.unwrap();
            queue.dequeue().await.unwrap();
            assert_eq!(queue.read_position(), 7);

            // Reset - should go back to ack floor
            queue.reset();
            assert_eq!(queue.read_position(), 5);

            // Next dequeue should return item 5
            let (p, item) = queue.dequeue().await.unwrap().unwrap();
            assert_eq!(p, 5);
            assert_eq!(item, vec![5]);

            queue.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_empty_queue_operations() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_config("test_empty");
            let mut queue = Queue::<_, Vec<u8>>::init(context.clone(), cfg)
                .await
                .unwrap();

            // Operations on empty queue
            assert!(queue.is_empty());
            assert!(queue.dequeue().await.unwrap().is_none());
            assert!(queue.peek().await.unwrap().is_none());
            queue.prune().await.unwrap();
            queue.reset();

            queue.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_persistence() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_config("test_persist");

            // First session
            {
                let mut queue = Queue::<_, Vec<u8>>::init(context.with_label("first"), cfg.clone())
                    .await
                    .unwrap();

                queue.enqueue(b"item0".to_vec()).await.unwrap();
                queue.enqueue(b"item1".to_vec()).await.unwrap();
                queue.sync().await.unwrap();
            }

            // Second session - data should persist
            {
                let mut queue =
                    Queue::<_, Vec<u8>>::init(context.with_label("second"), cfg.clone())
                        .await
                        .unwrap();

                assert_eq!(queue.size(), 2);

                let (_, item) = queue.dequeue().await.unwrap().unwrap();
                assert_eq!(item, b"item0");

                let (_, item) = queue.dequeue().await.unwrap().unwrap();
                assert_eq!(item, b"item1");

                queue.destroy().await.unwrap();
            }
        });
    }

    #[test_traced]
    fn test_large_queue_with_sparse_acks() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_config("test_sparse");
            let mut queue = Queue::<_, Vec<u8>>::init(context.clone(), cfg)
                .await
                .unwrap();

            // Enqueue many items
            for i in 0..100u8 {
                queue.enqueue(vec![i]).await.unwrap();
            }

            // Ack every 3rd item (sparse acking)
            for i in (0..100).step_by(3) {
                queue.ack(i).unwrap();
            }

            // Dequeue should skip acked items
            let mut received = Vec::new();
            while let Some((pos, _)) = queue.dequeue().await.unwrap() {
                received.push(pos);
            }

            // Should have received all items not divisible by 3
            let expected: Vec<u64> = (0..100).filter(|x| x % 3 != 0).collect();
            assert_eq!(received, expected);

            queue.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_acked_above_coalescing() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_config("test_coalesce");
            let mut queue = Queue::<_, Vec<u8>>::init(context.clone(), cfg)
                .await
                .unwrap();

            // Enqueue items
            for i in 0..10u8 {
                queue.enqueue(vec![i]).await.unwrap();
            }

            // Ack items 1-8 (not 0)
            for i in 1..9 {
                queue.ack(i).unwrap();
            }

            // Acked_above should have items 1-8
            assert_eq!(queue.ack_floor(), 0);
            assert!(queue.acked_above_count() > 0);

            // Now ack 0 - floor should advance to 9, consuming all acked_above
            queue.ack(0).unwrap();
            assert_eq!(queue.ack_floor(), 9);
            assert_eq!(queue.acked_above_count(), 0);

            queue.destroy().await.unwrap();
        });
    }
}
