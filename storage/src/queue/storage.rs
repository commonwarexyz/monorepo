//! Queue storage implementation.

use super::{metrics, Error};
use crate::{journal::contiguous::variable, rmap::RMap, Persistable};
use commonware_codec::CodecShared;
use commonware_runtime::{buffer::paged::CacheRef, Clock, Metrics, Storage};
use std::num::{NonZeroU64, NonZeroUsize};
use tracing::debug;

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

/// A durable, at-least-once delivery queue with per-item acknowledgment.
///
/// Items are durably stored in a journal and survive crashes. The reader must
/// acknowledge each item individually after processing. Items can be acknowledged
/// out of order, enabling parallel processing.
///
/// # Operations
///
/// - [append](Self::append) / [commit](Self::commit): Write items to the journal
///   buffer, then persist. Items are readable immediately after append (before commit),
///   but are lost on restart if not committed.
/// - [enqueue](Self::enqueue): Append + commit in one step; the item is durable before return.
/// - [dequeue](Self::dequeue): Return the next unacked item in FIFO order.
/// - [ack](Self::ack) / [ack_up_to](Self::ack_up_to): Mark items as processed (in-memory only).
/// - [sync](Self::sync): Commit, then prune completed sections below the ack floor.
///
/// # Acknowledgment
///
/// Acks are tracked in-memory with an `ack_floor` (all positions below are acked)
/// plus an [RMap] of acked positions above the floor. When items are acked
/// contiguously from the floor, the floor advances automatically.
///
/// Acks are **not** persisted. The durable equivalent is the journal's pruning
/// boundary, advanced by [commit](Self::commit). On restart, all non-pruned
/// items are re-delivered regardless of prior ack state.
///
/// # Crash Recovery
///
/// On restart, `ack_floor` is set to the journal's pruning boundary.
/// Items that were pruned are gone; everything else is re-delivered.
/// Applications must handle duplicates (idempotent processing).
pub struct Queue<E: Clock + Storage + Metrics, V: CodecShared> {
    /// The underlying journal storing queue items.
    journal: variable::Journal<E, V>,

    /// Position of the next item to dequeue.
    ///
    /// Invariant: `read_pos <= journal.size()`. Note that `ack_up_to` can advance
    /// `ack_floor` past `read_pos`; in this case, `dequeue` skips the already-acked items.
    read_pos: u64,

    /// All items at positions < ack_floor are considered acknowledged.
    ///
    /// On restart, this is initialized to `journal.bounds().start`.
    ack_floor: u64,

    /// Ranges of acknowledged items at positions >= ack_floor (in-memory only).
    ///
    /// When an item at position == ack_floor is acked, the floor advances
    /// and any contiguous acked items are consumed. Lost on restart.
    acked_above: RMap,

    /// Metrics for monitoring queue state.
    metrics: metrics::Metrics,
}

impl<E: Clock + Storage + Metrics, V: CodecShared> Queue<E, V> {
    /// Initialize a queue from storage.
    ///
    /// On first initialization, creates an empty queue. On restart, begins reading
    /// from the journal's pruning boundary (providing at-least-once delivery for
    /// all non-pruned items).
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying journal cannot be initialized.
    pub async fn init(context: E, cfg: Config<V::Cfg>) -> Result<Self, Error> {
        // Initialize metrics before creating sub-contexts
        let metrics = metrics::Metrics::init(&context);

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

        // On restart, ack_floor is the pruning boundary (items below are deleted).
        // acked_above is empty (in-memory state lost on restart).
        let ack_floor = journal.bounds().start;
        let acked_above = RMap::new();

        debug!(ack_floor, size = journal.size(), "queue initialized");

        metrics.tip.set(journal.size() as i64);
        metrics.floor.set(ack_floor as i64);
        metrics.next.set(ack_floor as i64);

        Ok(Self {
            journal,
            read_pos: ack_floor,
            ack_floor,
            acked_above,
            metrics,
        })
    }

    /// Returns whether a specific position has been acknowledged.
    pub fn is_acked(&self, position: u64) -> bool {
        position < self.ack_floor || self.acked_above.get(&position).is_some()
    }

    /// Append an item without persisting. Call [Self::commit] or [Self::sync]
    /// afterwards to make it durable. The item is readable immediately but
    /// is not guaranteed to survive a crash until committed or the journal
    /// auto-syncs at a section boundary (see [`variable::Journal`] invariant 1).
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying storage operation fails.
    pub async fn append(&mut self, item: V) -> Result<u64, Error> {
        let pos = self.journal.append(item).await?;
        self.metrics.tip.set(self.journal.size() as i64);
        debug!(position = pos, "appended item");
        Ok(pos)
    }

    /// Append and commit an item in one step, returning its position.
    /// The item is durable before this method returns.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying storage operation fails.
    pub async fn enqueue(&mut self, item: V) -> Result<u64, Error> {
        let pos = self.append(item).await?;
        self.commit().await?;
        Ok(pos)
    }

    /// Dequeue the next unacknowledged item, returning its position and value.
    /// Returns `None` when all items have been read or acknowledged.
    /// Already-acked items are skipped automatically.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying storage operation fails.
    pub async fn dequeue(&mut self) -> Result<Option<(u64, V)>, Error> {
        let size = self.journal.size();

        // Fast-forward above ack floor
        if self.read_pos < self.ack_floor {
            self.read_pos = self.ack_floor;
        }

        // Fast-forward past the ack range containing read_pos (if any).
        if let Some((_, end)) = self.acked_above.get(&self.read_pos) {
            self.read_pos = end.saturating_add(1);
        }

        if self.read_pos >= size {
            return Ok(None);
        }

        let item = self.journal.read(self.read_pos).await?;
        let pos = self.read_pos;
        self.read_pos += 1;

        self.metrics.next.set(self.read_pos as i64);
        debug!(position = pos, "dequeued item");
        Ok(Some((pos, item)))
    }

    /// Mark the item at `position` as processed (in-memory only).
    /// The item will be skipped on subsequent dequeues. If this creates a
    /// contiguous run from the ack floor, the floor advances automatically.
    ///
    /// # Errors
    ///
    /// Returns [Error::PositionOutOfRange] if `position >= queue size`.
    pub fn ack(&mut self, position: u64) -> Result<(), Error> {
        let size = self.journal.size();
        if position >= size {
            return Err(Error::PositionOutOfRange(position, size));
        }

        // Already acked (below floor)
        if position < self.ack_floor {
            return Ok(());
        }

        // Already acked (above floor)
        if self.acked_above.get(&position).is_some() {
            return Ok(());
        }

        // Check if we can advance the floor
        if position == self.ack_floor {
            // Advance floor, consuming any contiguous acked items
            let next = position + 1;
            let final_floor = match self.acked_above.get(&next) {
                Some((_, end)) => end + 1,
                None => next,
            };
            self.acked_above.remove(next, final_floor - 1);
            self.ack_floor = final_floor;
            debug!(ack_floor = self.ack_floor, "advanced ack floor");
        } else {
            // Floor is not advancing, so add to acked_above
            self.acked_above.insert(position);
            debug!(position, "acked item above floor");
        }

        self.metrics.floor.set(self.ack_floor as i64);

        Ok(())
    }

    /// Acknowledge all items in `[ack_floor, up_to)` by advancing the floor
    /// directly. More efficient than calling [Self::ack] in a loop.
    ///
    /// # Errors
    ///
    /// Returns [Error::PositionOutOfRange] if `up_to > queue size`.
    pub fn ack_up_to(&mut self, up_to: u64) -> Result<(), Error> {
        let size = self.journal.size();
        if up_to > size {
            return Err(Error::PositionOutOfRange(up_to, size));
        }

        // Nothing to do if up_to is at or below current floor
        if up_to <= self.ack_floor {
            return Ok(());
        }

        // Determine final floor: either up_to, or past any contiguous acked range at up_to
        let final_floor = match self.acked_above.get(&up_to) {
            Some((_, end)) => end + 1,
            None => up_to,
        };

        // Remove all entries covered by the new floor and advance
        self.acked_above.remove(self.ack_floor, final_floor - 1);
        self.ack_floor = final_floor;

        self.metrics.floor.set(self.ack_floor as i64);

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

    /// Returns whether all enqueued items have been acknowledged.
    pub const fn is_empty(&self) -> bool {
        // If acked_above is non-empty, there's a gap at ack_floor (otherwise floor
        // would have advanced). So all items acked implies ack_floor == size.
        self.ack_floor >= self.journal.size()
    }

    /// Reset the read position to the ack floor so [Self::dequeue] re-delivers
    /// all unacknowledged items from the beginning.
    pub fn reset(&mut self) {
        let old_pos = self.read_pos;
        self.read_pos = self.ack_floor;
        self.metrics.next.set(self.read_pos as i64);
        debug!(
            old_read_pos = old_pos,
            new_read_pos = self.read_pos,
            "reset read position"
        );
    }

    /// Returns the number of items not yet read (test-only).
    #[cfg(test)]
    pub(crate) const fn pending(&self) -> u64 {
        self.journal.size().saturating_sub(self.read_pos)
    }
}

impl<E: Clock + Storage + Metrics + Send, V: CodecShared + Send> Persistable for Queue<E, V> {
    type Error = Error;

    async fn commit(&mut self) -> Result<(), Error> {
        self.journal.commit().await?;
        Ok(())
    }

    async fn sync(&mut self) -> Result<(), Error> {
        self.journal.commit().await?;
        self.journal.prune(self.ack_floor).await?;
        Ok(())
    }

    async fn destroy(self) -> Result<(), Error> {
        self.journal.destroy().await?;
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
        });
    }

    #[test_traced]
    fn test_append_flush_batch() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_config("test_batch");
            let mut queue = Queue::<_, Vec<u8>>::init(context.clone(), cfg)
                .await
                .unwrap();

            // Append multiple items, then commit once
            for i in 0..5u8 {
                queue.append(vec![i]).await.unwrap();
            }
            queue.commit().await.unwrap();
            assert_eq!(queue.size(), 5);

            // Dequeue and verify order
            for i in 0..5 {
                let (pos, item) = queue.dequeue().await.unwrap().unwrap();
                assert_eq!(pos, i);
                assert_eq!(item, vec![i as u8]);
            }

            // Mix batch and single enqueue
            for i in 5..8u8 {
                queue.append(vec![i]).await.unwrap();
            }
            queue.commit().await.unwrap();
            queue.enqueue(vec![8]).await.unwrap();
            assert_eq!(queue.size(), 9);

            queue.ack_up_to(9).unwrap();
            assert!(queue.is_empty());
        });
    }

    #[test_traced]
    fn test_append_flush_persistence() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_config("test_batch_persist");

            {
                let mut queue = Queue::<_, Vec<u8>>::init(context.with_label("first"), cfg.clone())
                    .await
                    .unwrap();
                for i in 0..4u8 {
                    queue.append(vec![i]).await.unwrap();
                }
                queue.commit().await.unwrap();
                queue.sync().await.unwrap();
            }

            {
                let mut queue = Queue::<_, Vec<u8>>::init(context.with_label("second"), cfg)
                    .await
                    .unwrap();
                assert_eq!(queue.size(), 4);
                for i in 0..4 {
                    let (pos, item) = queue.dequeue().await.unwrap().unwrap();
                    assert_eq!(pos, i);
                    assert_eq!(item, vec![i as u8]);
                }
            }
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
            assert!(queue.is_acked(2));

            queue.ack(4).unwrap();
            assert_eq!(queue.ack_floor(), 0);
            assert!(queue.is_acked(4));

            queue.ack(1).unwrap();
            assert_eq!(queue.ack_floor(), 0);

            queue.ack(3).unwrap();
            assert_eq!(queue.ack_floor(), 0);

            // Ack 0 - floor should advance to 5 (consuming 1,2,3,4)
            queue.ack(0).unwrap();
            assert_eq!(queue.ack_floor(), 5);
            assert!(queue.is_empty());
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
                assert!(queue.is_acked(i));
            }
            // Items 5-9 should not be acked
            for i in 5..10 {
                assert!(!queue.is_acked(i));
            }

            // Dequeue should start at 5
            let (p, _) = queue.dequeue().await.unwrap().unwrap();
            assert_eq!(p, 5);
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

            // Batch ack up to 5
            queue.ack_up_to(5).unwrap();
            assert_eq!(queue.ack_floor(), 5);

            // Now batch ack up to 9 - should consume the acked_above entries
            queue.ack_up_to(9).unwrap();
            assert_eq!(queue.ack_floor(), 9);
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
            assert!(queue.is_acked(1));

            // Double ack is a no-op
            queue.ack(1).unwrap();
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

            // Items 15+ should still be readable
            let (p, item) = queue.dequeue().await.unwrap().unwrap();
            assert_eq!(p, 15);
            assert_eq!(item, vec![15]);
        });
    }

    #[test_traced]
    fn test_ack_across_sections() {
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

            // First batch: ack items 0-14
            for i in 0..15 {
                queue.dequeue().await.unwrap();
                queue.ack(i).unwrap();
            }
            assert_eq!(queue.ack_floor(), 15);

            // Verify items 15+ still readable
            let (p, item) = queue.dequeue().await.unwrap().unwrap();
            assert_eq!(p, 15);
            assert_eq!(item, vec![15]);

            // Second batch: ack items 15-29
            queue.ack(15).unwrap();
            for i in 16..30 {
                queue.dequeue().await.unwrap();
                queue.ack(i).unwrap();
            }
            assert_eq!(queue.ack_floor(), 30);

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

            // Queue should be empty now
            assert!(queue.is_empty());
            assert!(queue.dequeue().await.unwrap().is_none());
        });
    }

    #[test_traced]
    fn test_crash_recovery_replays_from_pruning_boundary() {
        // On restart, ack_floor = pruning_boundary. Items not pruned are re-delivered.
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_config("test_recovery_replay");

            // First session: enqueue items, ack some (but not enough to prune)
            {
                let mut queue = Queue::<_, Vec<u8>>::init(context.with_label("first"), cfg.clone())
                    .await
                    .unwrap();

                for i in 0..5u8 {
                    queue.enqueue(vec![i]).await.unwrap();
                }

                // Ack items 0, 1, 2 - but items_per_section=10, so no pruning
                queue.ack(0).unwrap();
                queue.ack(1).unwrap();
                queue.ack(2).unwrap();
                assert_eq!(queue.ack_floor(), 3);

                queue.sync().await.unwrap();
            }

            // Second session: all items are re-delivered (no pruning occurred)
            {
                let mut queue =
                    Queue::<_, Vec<u8>>::init(context.with_label("second"), cfg.clone())
                        .await
                        .unwrap();

                // ack_floor = pruning_boundary = 0 (nothing was pruned)
                assert_eq!(queue.ack_floor(), 0);

                // All items re-delivered
                for i in 0..5 {
                    let (p, _) = queue.dequeue().await.unwrap().unwrap();
                    assert_eq!(p, i);
                }
            }
        });
    }

    #[test_traced]
    fn test_crash_recovery_with_pruning() {
        // Items pruned before crash are not re-delivered.
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_config("test_recovery_pruned");

            // First session: enqueue many items, ack enough to trigger pruning
            let expected_pruning_boundary = {
                let mut queue = Queue::<_, Vec<u8>>::init(context.with_label("first"), cfg.clone())
                    .await
                    .unwrap();

                // Enqueue items across multiple sections (items_per_section = 10)
                for i in 0..25u8 {
                    queue.enqueue(vec![i]).await.unwrap();
                }

                // Ack items 0-14 to advance floor past section 0
                for i in 0..15 {
                    queue.ack(i).unwrap();
                }
                assert_eq!(queue.ack_floor(), 15);

                // Sync triggers pruning
                queue.sync().await.unwrap();

                // Verify pruning occurred
                let pruning_boundary = queue.journal.bounds().start;
                assert!(pruning_boundary > 0, "expected some pruning to occur");

                pruning_boundary
            };

            // Second session: only non-pruned items are available
            {
                let mut queue =
                    Queue::<_, Vec<u8>>::init(context.with_label("second"), cfg.clone())
                        .await
                        .unwrap();

                // ack_floor = pruning_boundary (items 0-9 were pruned)
                let pruning_boundary = queue.journal.bounds().start;
                assert_eq!(queue.ack_floor(), pruning_boundary);
                assert_eq!(pruning_boundary, expected_pruning_boundary);

                // Items from pruning_boundary to 24 are re-delivered
                for i in pruning_boundary..25 {
                    let (p, item) = queue.dequeue().await.unwrap().unwrap();
                    assert_eq!(p, i);
                    assert_eq!(item, vec![i as u8]);
                }

                assert!(queue.dequeue().await.unwrap().is_none());
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
            queue.sync().await.unwrap();
            queue.reset();
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

            // Now ack 0 - floor should advance to 9, consuming all acked_above
            queue.ack(0).unwrap();
            assert_eq!(queue.ack_floor(), 9);
        });
    }

    #[test_traced]
    fn test_ack_up_to_past_read_pos() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_config("test_ack_up_to_past_read_pos");
            let mut queue = Queue::<_, Vec<u8>>::init(context.clone(), cfg)
                .await
                .unwrap();

            for i in 0..10u8 {
                queue.enqueue(vec![i]).await.unwrap();
            }

            // Read only 3 items
            for _ in 0..3 {
                queue.dequeue().await.unwrap();
            }
            assert_eq!(queue.read_position(), 3);

            // Batch ack past read position
            queue.ack_up_to(7).unwrap();
            assert_eq!(queue.ack_floor(), 7);

            // Dequeue should skip 3-6 and return 7
            let (pos, item) = queue.dequeue().await.unwrap().unwrap();
            assert_eq!(pos, 7);
            assert_eq!(item, vec![7]);
        });
    }

    #[test_traced]
    fn test_metrics() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_config("test_metrics");
            let ctx = context.with_label("test_metrics");
            let mut queue = Queue::<_, Vec<u8>>::init(ctx, cfg).await.unwrap();

            let encoded = context.encode();
            assert!(
                encoded.contains("test_metrics_tip 0"),
                "expected tip 0: {encoded}"
            );
            assert!(
                encoded.contains("test_metrics_floor 0"),
                "expected floor 0: {encoded}"
            );
            assert!(
                encoded.contains("test_metrics_next 0"),
                "expected next 0: {encoded}"
            );

            // Enqueue items
            for i in 0..5u8 {
                queue.enqueue(vec![i]).await.unwrap();
            }
            let encoded = context.encode();
            assert!(
                encoded.contains("test_metrics_tip 5"),
                "expected tip 5: {encoded}"
            );

            // Dequeue advances next
            queue.dequeue().await.unwrap();
            let encoded = context.encode();
            assert!(
                encoded.contains("test_metrics_next 1"),
                "expected next 1: {encoded}"
            );

            // Ack advances floor
            queue.ack(0).unwrap();
            let encoded = context.encode();
            assert!(
                encoded.contains("test_metrics_floor 1"),
                "expected floor 1: {encoded}"
            );

            // Ack out of order, then fill gap
            queue.ack(2).unwrap();
            queue.ack(4).unwrap();
            queue.ack(1).unwrap();
            let encoded = context.encode();
            assert!(
                encoded.contains("test_metrics_floor 3"),
                "expected floor 3: {encoded}"
            );

            queue.ack(3).unwrap();
            let encoded = context.encode();
            assert!(
                encoded.contains("test_metrics_floor 5"),
                "expected floor 5: {encoded}"
            );

            // Reset brings next back to floor
            queue.reset();
            let encoded = context.encode();
            assert!(
                encoded.contains("test_metrics_next 5"),
                "expected next 5: {encoded}"
            );
        });
    }
}
