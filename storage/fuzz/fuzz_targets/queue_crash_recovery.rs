#![no_main]

//! Fuzz test for queue crash recovery and durability guarantees.
//!
//! Tests that:
//! - Enqueued items survive crashes
//! - Unacknowledged items are re-delivered after recovery
//! - Acknowledged items (once committed) may or may not be re-delivered after crash
//! - Queue state is consistent after recovery

use arbitrary::{Arbitrary, Result, Unstructured};
use commonware_runtime::{buffer::paged::CacheRef, deterministic, Runner};
use commonware_storage::{
    queue::{Config, Queue},
    Persistable,
};
use libfuzzer_sys::fuzz_target;
use std::{
    collections::BTreeMap,
    num::{NonZeroU16, NonZeroU64, NonZeroUsize},
};

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
    /// Append a new item without committing (not durable until Commit).
    Append { value: u8 },
    /// Commit appended items to disk.
    Commit,
    /// Dequeue and acknowledge the next item.
    DequeueAndAck,
    /// Dequeue without acknowledging (item should be re-delivered on recovery).
    DequeueNoAck,
    /// Acknowledge a specific position offset from ack_floor.
    AckOffset { offset: u8 },
    /// Acknowledge all items up to a position.
    AckUpToOffset { offset: u8 },
    /// Sync the queue (commit and prune).
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
    /// Items that were successfully enqueued or committed (position -> value).
    committed: BTreeMap<u64, u8>,

    /// Items that were enqueued/appended but the operation may have failed,
    /// or were appended but not yet committed.
    pending: Vec<u8>,

    /// Current in-memory ack floor (lost on crash).
    current_ack_floor: u64,

    /// Items that were appended but not yet committed (position -> value).
    /// These may be lost on crash. On commit, they move to `committed`.
    uncommitted: BTreeMap<u64, u8>,

    /// Whether we observed a mutable storage error during the operation phase.
    ///
    /// After mutable errors, the queue may be left in an inconsistent state until
    /// restart. In that case recovery checks should only assert basic liveness,
    /// not exact durability/accounting bounds.
    saw_mutable_error: bool,
}

impl RecoveryState {
    fn new() -> Self {
        Self {
            committed: BTreeMap::new(),
            pending: Vec::new(),
            current_ack_floor: 0,
            uncommitted: BTreeMap::new(),
            saw_mutable_error: false,
        }
    }

    fn mark_mutable_error(&mut self) {
        self.saw_mutable_error = true;
    }

    fn saw_mutable_error(&self) -> bool {
        self.saw_mutable_error
    }

    fn enqueue_succeeded(&mut self, pos: u64, value: u8) {
        // Enqueue does append + commit, so success means it's durable at `pos`.
        self.committed.insert(pos, value);
    }

    fn enqueue_failed(&mut self, value: u8) {
        // Enqueue may have partially succeeded (append but not commit).
        // Track as pending - it may or may not be persisted.
        self.pending.push(value);
    }

    fn append_succeeded(&mut self, pos: u64, value: u8) {
        // Append only - not durable until committed.
        self.uncommitted.insert(pos, value);
    }

    fn append_failed(&mut self, value: u8) {
        self.pending.push(value);
    }

    fn commit_succeeded(&mut self) {
        // All uncommitted items are now durable.
        let uncommitted = std::mem::take(&mut self.uncommitted);
        for (pos, value) in uncommitted {
            self.committed.insert(pos, value);
        }
    }

    fn commit_failed(&mut self) {
        // Uncommitted items remain uncommitted; they may or may not be durable.
        // Move them to pending since we can't be sure.
        let uncommitted = std::mem::take(&mut self.uncommitted);
        for (_pos, value) in uncommitted {
            self.pending.push(value);
        }
    }

    fn update_ack_floor(&mut self, ack_floor: u64) {
        self.current_ack_floor = ack_floor;
    }

    /// Returns the minimum size we expect after recovery.
    fn min_recovered_size(&self) -> u64 {
        self.committed.len() as u64
    }

    /// Returns the maximum size we expect after recovery.
    fn max_recovered_size(&self) -> u64 {
        (self.committed.len() + self.pending.len() + self.uncommitted.len()) as u64
    }

    /// Returns the minimum ack floor we expect after recovery.
    fn min_recovered_ack_floor(&self) -> u64 {
        0
    }

    /// Returns the maximum ack floor we expect after recovery.
    fn max_recovered_ack_floor(&self) -> u64 {
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
) -> RecoveryState {
    let mut state = RecoveryState::new();

    for op in operations {
        match op {
            QueueOperation::Enqueue { value } => {
                let item = make_item(*value);
                match queue.enqueue(item).await {
                    Ok(pos) => {
                        // enqueue = append + commit, so success means ALL
                        // previously uncommitted items are now durable too.
                        state.commit_succeeded();
                        state.enqueue_succeeded(pos, *value);
                    }
                    Err(_) => {
                        state.enqueue_failed(*value);
                        state.mark_mutable_error();
                        return state;
                    }
                }
            }

            QueueOperation::Append { value } => {
                let item = make_item(*value);
                match queue.append(item).await {
                    Ok(pos) => {
                        state.append_succeeded(pos, *value);
                    }
                    Err(_) => {
                        state.append_failed(*value);
                        state.mark_mutable_error();
                        return state;
                    }
                }
            }

            QueueOperation::Commit => match queue.commit().await {
                Ok(()) => {
                    state.commit_succeeded();
                }
                Err(_) => {
                    state.commit_failed();
                    state.mark_mutable_error();
                    return state;
                }
            },

            QueueOperation::DequeueAndAck => {
                if let Ok(Some((pos, _item))) = queue.dequeue().await {
                    if queue.ack(pos).await.is_ok() {
                        state.update_ack_floor(queue.ack_floor());
                    }
                }
            }

            QueueOperation::DequeueNoAck => {
                // Dequeue without acking - item should be re-delivered on recovery
                let _ = queue.dequeue().await;
            }

            QueueOperation::AckOffset { offset } => {
                let size = queue.size().await;
                let ack_floor = queue.ack_floor();
                if size > ack_floor {
                    let range = size - ack_floor;
                    let pos = ack_floor + (*offset as u64 % range);
                    match queue.ack(pos).await {
                        Ok(()) => {
                            state.update_ack_floor(queue.ack_floor());
                        }
                        Err(_) => {
                            state.mark_mutable_error();
                            return state;
                        }
                    }
                }
            }

            QueueOperation::AckUpToOffset { offset } => {
                let size = queue.size().await;
                let up_to = (*offset as u64) % (size + 1);
                match queue.ack_up_to(up_to).await {
                    Ok(()) => {
                        state.update_ack_floor(queue.ack_floor());
                    }
                    Err(_) => {
                        state.mark_mutable_error();
                        return state;
                    }
                }
            }

            QueueOperation::Sync => {
                match queue.sync().await {
                    Ok(()) => {
                        // sync = commit + prune, so success means ALL
                        // previously uncommitted items are now durable too.
                        state.commit_succeeded();
                        state.update_ack_floor(queue.ack_floor());
                    }
                    Err(_) => {
                        state.commit_failed();
                        state.mark_mutable_error();
                        return state;
                    }
                }
            }

            QueueOperation::Reset => {
                queue.reset();
            }
        }
    }

    state
}

/// Verify recovery after a mutable error during the operation phase.
///
/// Mutable errors may leave storage temporarily inconsistent, so we only assert
/// that the queue can be re-initialized and used again for basic operations.
async fn verify_recovery_after_mutable_error(queue: &mut Queue<deterministic::Context, Vec<u8>>) {
    // Basic read-path sanity should not fail.
    let size_before = queue.size().await;
    queue
        .dequeue()
        .await
        .expect("dequeue should not error after recovery");

    // Queue should remain writable after recovery.
    let new_pos = queue
        .enqueue(make_item(0xFF))
        .await
        .expect("enqueue should succeed after recovery");
    assert_eq!(
        new_pos, size_before,
        "new item should be appended at current queue size"
    );

    // Persist path should also remain usable.
    queue
        .sync()
        .await
        .expect("sync should succeed after recovery");
}

/// Verify the queue state after recovery.
async fn verify_recovery(
    queue: &mut Queue<deterministic::Context, Vec<u8>>,
    state: &RecoveryState,
) {
    if state.saw_mutable_error() {
        verify_recovery_after_mutable_error(queue).await;
        return;
    }

    let size = queue.size().await;
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
    loop {
        match queue.dequeue().await {
            Ok(Some((pos, item))) => {
                dequeued_count += 1;

                // Verify item content if we know what it should be
                if let Some(value) = state.committed.get(&pos) {
                    let expected = make_item(*value);
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
            Ok(None) => break,
            Err(e) => panic!(
                "dequeue at position {} failed after recovery: {e} (size={}, ack_floor={})",
                ack_floor + dequeued_count,
                size,
                ack_floor
            ),
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
    let page_size = NonZeroU16::new(input.page_size).unwrap();
    let page_cache_size = NonZeroUsize::new(input.page_cache_size).unwrap();
    let items_per_section = NonZeroU64::new(input.items_per_section).unwrap();
    let write_buffer = NonZeroUsize::new(input.write_buffer).unwrap();
    let cfg = deterministic::Config::default().with_seed(input.seed);
    let partition_name = format!("queue-crash-recovery-{}", input.seed);
    let operations = input.operations.clone();
    let sync_failure_rate = input.sync_failure_rate;
    let write_failure_rate = input.write_failure_rate;

    let runner = deterministic::Runner::new(cfg);

    let (state, checkpoint) = runner.start_and_recover(|ctx| {
        let partition_name = partition_name.clone();
        let operations = operations.clone();
        async move {
            let queue_cfg = Config {
                partition: partition_name,
                items_per_section,
                compression: None,
                codec_config: ((0usize..).into(), ()),
                page_cache: CacheRef::from_pooler_physical(&ctx, page_size, page_cache_size),
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
            let faults = ctx.storage_fault_config();
            *faults.write() = fault_config;

            run_operations(&mut queue, &operations).await
        }
    });

    // Recovery phase - re-initialize queue from checkpoint
    let runner = deterministic::Runner::from(checkpoint);
    runner.start(|ctx| async move {
        // Disable fault injection for recovery verification
        *ctx.storage_fault_config().write() = deterministic::FaultConfig::default();

        let queue_cfg = Config {
            partition: partition_name,
            items_per_section,
            compression: None,
            codec_config: ((0usize..).into(), ()),
            page_cache: CacheRef::from_pooler_physical(&ctx, page_size, page_cache_size),
            write_buffer,
        };

        let mut queue = Queue::<_, Vec<u8>>::init(ctx.clone(), queue_cfg)
            .await
            .expect("Queue recovery should succeed");

        verify_recovery(&mut queue, &state).await;
    });
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
