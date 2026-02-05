#![no_main]

//! Fuzz test for queue crash recovery and durability guarantees.
//!
//! Tests that:
//! - Enqueued items survive crashes
//! - Unacknowledged items are re-delivered after recovery
//! - Acknowledged items (with synced ack floor) are not re-delivered
//! - Queue state is consistent after recovery

use arbitrary::{Arbitrary, Result, Unstructured};
use commonware_runtime::{buffer::paged::CacheRef, deterministic, Runner};
use commonware_storage::{
    queue::{Config, Queue},
    Persistable,
};
use libfuzzer_sys::fuzz_target;
use std::num::{NonZeroU16, NonZeroU64, NonZeroUsize};

/// Maximum write buffer size.
const MAX_WRITE_BUF: usize = 2048;

/// Item size for queue entries (32 bytes like a hash digest).
const ITEM_SIZE: usize = 32;

fn bounded_page_size(u: &mut Unstructured<'_>) -> Result<u16> {
    u.int_in_range(1..=256)
}

fn bounded_page_cache_size(u: &mut Unstructured<'_>) -> Result<usize> {
    u.int_in_range(1..=16)
}

fn bounded_items_per_section(u: &mut Unstructured<'_>) -> Result<u64> {
    u.int_in_range(1..=64)
}

fn bounded_write_buffer(u: &mut Unstructured<'_>) -> Result<usize> {
    u.int_in_range(1..=MAX_WRITE_BUF)
}

fn bounded_nonzero_rate(u: &mut Unstructured<'_>) -> Result<f64> {
    let percent: u8 = u.int_in_range(1..=100)?;
    Ok(f64::from(percent) / 100.0)
}

/// Operations that can be performed on the queue.
#[derive(Arbitrary, Debug, Clone)]
enum QueueOperation {
    /// Enqueue a new item with the given value (repeated to fill ITEM_SIZE).
    Enqueue { value: u8 },

    /// Dequeue and acknowledge the next item.
    DequeueAndAck,

    /// Dequeue without acknowledging (item should be re-delivered on recovery).
    DequeueNoAck,

    /// Acknowledge a specific position offset from ack_floor.
    AckOffset { offset: u8 },

    /// Acknowledge all items up to a position.
    AckUpToOffset { offset: u8 },

    /// Sync the queue (persists ack state and prunes).
    Sync,

    /// Reset read position to ack floor.
    Reset,
}

/// Fuzz input containing fault injection parameters and operations.
#[derive(Arbitrary, Debug)]
struct FuzzInput {
    /// Seed for deterministic execution.
    seed: u64,
    /// Page size for buffer pool.
    #[arbitrary(with = bounded_page_size)]
    page_size: u16,
    /// Number of pages in the buffer pool cache.
    #[arbitrary(with = bounded_page_cache_size)]
    page_cache_size: usize,
    /// Items per section.
    #[arbitrary(with = bounded_items_per_section)]
    items_per_section: u64,
    /// Write buffer size.
    #[arbitrary(with = bounded_write_buffer)]
    write_buffer: usize,
    /// Failure rate for sync operations (0, 1].
    #[arbitrary(with = bounded_nonzero_rate)]
    sync_failure_rate: f64,
    /// Failure rate for write operations (0, 1].
    #[arbitrary(with = bounded_nonzero_rate)]
    write_failure_rate: f64,
    /// Sequence of operations to execute.
    operations: Vec<QueueOperation>,
}

/// Tracking state for verifying recovery.
///
/// Note: Queue ack state is NOT persisted. On restart, `ack_floor` equals
/// `journal.bounds().start` (the pruning boundary). Items that were acked
/// in-memory but not pruned will be re-delivered.
#[derive(Debug, Clone)]
struct RecoveryState {
    /// Items that were successfully enqueued and committed.
    /// Each enqueue() does append + commit, so successful enqueues are durable.
    committed: Vec<u8>,

    /// Items that were enqueued but the operation may have failed.
    pending: Vec<u8>,

    /// The ack floor at the time of last successful sync.
    /// Pruning happens during sync, so this determines what was deleted.
    synced_ack_floor: u64,

    /// Current in-memory ack floor (lost on crash).
    current_ack_floor: u64,

    /// Items per section (needed to calculate pruning boundaries).
    items_per_section: u64,
}

impl RecoveryState {
    fn new(items_per_section: u64) -> Self {
        Self {
            committed: Vec::new(),
            pending: Vec::new(),
            synced_ack_floor: 0,
            current_ack_floor: 0,
            items_per_section,
        }
    }

    fn enqueue_succeeded(&mut self, value: u8) {
        // Enqueue does append + commit, so success means it's durable.
        // Move any pending items to committed (they must have succeeded too),
        // then add the new item.
        self.committed.append(&mut self.pending);
        self.committed.push(value);
    }

    fn enqueue_failed(&mut self, value: u8) {
        // Enqueue may have partially succeeded (append but not commit).
        // Track as pending - it may or may not be persisted.
        self.pending.push(value);
    }

    fn update_ack_floor(&mut self, ack_floor: u64) {
        // Get the actual ack floor from the queue (handles coalescing correctly)
        self.current_ack_floor = ack_floor;
    }

    fn sync_succeeded(&mut self, ack_floor: u64) {
        // Sync succeeded: pruning happened at current ack_floor
        self.committed.append(&mut self.pending);
        self.current_ack_floor = ack_floor;
        self.synced_ack_floor = ack_floor;
    }

    /// Returns the minimum size we expect after recovery.
    fn min_recovered_size(&self) -> u64 {
        self.committed.len() as u64
    }

    /// Returns the maximum size we expect after recovery.
    fn max_recovered_size(&self) -> u64 {
        (self.committed.len() + self.pending.len()) as u64
    }

    /// Returns the minimum ack floor (pruning boundary) we expect after recovery.
    ///
    /// After recovery, ack_floor = journal.bounds().start, which is the
    /// first non-pruned position. Pruning is section-granular.
    fn min_recovered_ack_floor(&self) -> u64 {
        // Pruning only removes complete sections below ack_floor.
        // The minimum is 0 if no sync succeeded, or section-aligned floor otherwise.
        if self.synced_ack_floor == 0 {
            return 0;
        }
        // Pruning removes sections where all items are below ack_floor
        // A section starting at pos is pruned if pos + items_per_section <= ack_floor
        let complete_sections = self.synced_ack_floor / self.items_per_section;
        complete_sections * self.items_per_section
    }

    /// Returns the maximum ack floor we expect after recovery.
    fn max_recovered_ack_floor(&self) -> u64 {
        // The maximum is the current ack floor if a sync was in progress
        // and happened to complete despite faults
        self.current_ack_floor
    }
}

fn make_item(value: u8) -> Vec<u8> {
    vec![value; ITEM_SIZE]
}

/// Run operations on the queue, tracking state for recovery verification.
async fn run_operations(
    queue: &mut Queue<deterministic::Context, Vec<u8>>,
    operations: &[QueueOperation],
    items_per_section: u64,
) -> RecoveryState {
    let mut state = RecoveryState::new(items_per_section);

    for op in operations {
        match op {
            QueueOperation::Enqueue { value } => {
                let item = make_item(*value);
                match queue.enqueue(item).await {
                    Ok(_pos) => {
                        state.enqueue_succeeded(*value);
                    }
                    Err(_) => {
                        // Enqueue failed - item may or may not be persisted
                        state.enqueue_failed(*value);
                    }
                }
            }

            QueueOperation::DequeueAndAck => {
                if let Ok(Some((pos, _item))) = queue.dequeue().await {
                    if queue.ack(pos).is_ok() {
                        state.update_ack_floor(queue.ack_floor());
                    }
                }
            }

            QueueOperation::DequeueNoAck => {
                // Dequeue without acking - item should be re-delivered on recovery
                let _ = queue.dequeue().await;
            }

            QueueOperation::AckOffset { offset } => {
                let size = queue.size();
                let ack_floor = queue.ack_floor();
                if size > ack_floor {
                    let range = size - ack_floor;
                    let pos = ack_floor + (*offset as u64 % range);
                    if queue.ack(pos).is_ok() {
                        state.update_ack_floor(queue.ack_floor());
                    }
                }
            }

            QueueOperation::AckUpToOffset { offset } => {
                let size = queue.size();
                let up_to = (*offset as u64) % (size + 1);
                if queue.ack_up_to(up_to).is_ok() {
                    state.update_ack_floor(queue.ack_floor());
                }
            }

            QueueOperation::Sync => {
                if queue.sync().await.is_ok() {
                    state.sync_succeeded(queue.ack_floor());
                }
            }

            QueueOperation::Reset => {
                queue.reset();
            }
        }
    }

    state
}

/// Verify the queue state after recovery.
async fn verify_recovery(
    queue: &mut Queue<deterministic::Context, Vec<u8>>,
    state: &RecoveryState,
) {
    let size = queue.size();
    let ack_floor = queue.ack_floor();

    // Size should be within expected bounds
    assert!(
        size >= state.min_recovered_size(),
        "recovered size {} is less than minimum expected {}",
        size,
        state.min_recovered_size()
    );
    assert!(
        size <= state.max_recovered_size(),
        "recovered size {} is greater than maximum expected {}",
        size,
        state.max_recovered_size()
    );

    // Ack floor should be within expected bounds
    // Note: ack_floor after recovery = journal.bounds().start (pruning boundary)
    assert!(
        ack_floor >= state.min_recovered_ack_floor(),
        "recovered ack_floor {} is less than minimum expected {}",
        ack_floor,
        state.min_recovered_ack_floor()
    );
    assert!(
        ack_floor <= state.max_recovered_ack_floor(),
        "recovered ack_floor {} is greater than maximum expected {}",
        ack_floor,
        state.max_recovered_ack_floor()
    );

    // Reset to re-read all unacked items from the beginning
    queue.reset();

    // Verify all unacked items can be dequeued and have correct content
    let mut dequeued_count = 0u64;
    while let Ok(Some((pos, item))) = queue.dequeue().await {
        dequeued_count += 1;

        // Verify item content if we know what it should be
        if (pos as usize) < state.committed.len() {
            let expected = make_item(state.committed[pos as usize]);
            assert_eq!(
                item, expected,
                "item at position {} has wrong content after recovery",
                pos
            );
        }

        // Prevent infinite loop
        if dequeued_count > size {
            panic!("dequeued more items than queue size");
        }
    }

    // The number of unacked items should be size - ack_floor
    let expected_unacked = size - ack_floor;
    assert_eq!(
        dequeued_count, expected_unacked,
        "dequeued {} items but expected {} unacked (size={}, ack_floor={})",
        dequeued_count, expected_unacked, size, ack_floor
    );

    // Verify we can enqueue new items after recovery
    let new_pos = queue.enqueue(make_item(0xFF)).await.unwrap();
    assert_eq!(new_pos, size, "new item should be at position {}", size);
}

fn fuzz(input: FuzzInput) {
    if input.operations.is_empty() {
        return;
    }

    let page_size = NonZeroU16::new(input.page_size).unwrap();
    let page_cache_size = NonZeroUsize::new(input.page_cache_size).unwrap();
    let items_per_section = NonZeroU64::new(input.items_per_section).unwrap();
    let write_buffer = NonZeroUsize::new(input.write_buffer).unwrap();
    let cfg = deterministic::Config::default().with_seed(input.seed);
    let partition_name = format!("queue_crash_recovery_{}", input.seed);
    let operations = input.operations.clone();
    let sync_failure_rate = input.sync_failure_rate;
    let write_failure_rate = input.write_failure_rate;

    let runner = deterministic::Runner::new(cfg);

    let items_per_section_val = input.items_per_section;
    let (state, checkpoint) = runner.start_and_recover(|ctx| {
        let partition_name = partition_name.clone();
        let operations = operations.clone();
        async move {
            let queue_cfg = Config {
                partition: partition_name,
                items_per_section,
                compression: None,
                codec_config: ((0usize..).into(), ()),
                page_cache: CacheRef::new(page_size, page_cache_size),
                write_buffer,
            };

            let mut queue = Queue::<_, Vec<u8>>::init(ctx.clone(), queue_cfg)
                .await
                .unwrap();

            // Enable fault injection
            let fault_config = deterministic::FaultConfig {
                sync_rate: Some(sync_failure_rate),
                write_rate: Some(write_failure_rate),
                ..Default::default()
            };
            let faults = ctx.storage_faults();
            *faults.write().unwrap() = fault_config;

            run_operations(&mut queue, &operations, items_per_section_val).await
        }
    });

    // Recovery phase - re-initialize queue from checkpoint
    let runner = deterministic::Runner::from(checkpoint);
    runner.start(|ctx| async move {
        // Disable fault injection for recovery verification
        *ctx.storage_faults().write().unwrap() = deterministic::FaultConfig::default();

        let queue_cfg = Config {
            partition: partition_name,
            items_per_section,
            compression: None,
            codec_config: ((0usize..).into(), ()),
            page_cache: CacheRef::new(page_size, page_cache_size),
            write_buffer,
        };

        let mut queue = Queue::<_, Vec<u8>>::init(ctx.clone(), queue_cfg)
            .await
            .expect("Queue recovery should succeed");

        verify_recovery(&mut queue, &state).await;

        queue
            .destroy()
            .await
            .expect("Should be able to destroy queue");
    });
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
