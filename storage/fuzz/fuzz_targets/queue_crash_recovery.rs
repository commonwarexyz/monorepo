#![no_main]

//! Fuzz test for queue crash recovery and durability guarantees.
//!
//! Tests that:
//! - Enqueued items survive crashes
//! - Unacknowledged items are re-delivered after recovery
//! - Acknowledged items (once committed) may or may not be re-delivered after crash
//! - Queue state is consistent after recovery

use arbitrary::Arbitrary;
use commonware_runtime::{Runner, Supervisor as _, buffer::paged::CacheRef, deterministic};
use commonware_storage::queue::{Config, Queue};
use commonware_storage_fuzz::{
    bounded_buffer, bounded_items, bounded_nonzero_rate, bounded_page_cache_size,
    bounded_page_size, faulted_recovery,
};
use commonware_utils::Probability;
use libfuzzer_sys::fuzz_target;
use std::{
    collections::BTreeMap,
    num::{NonZeroU16, NonZeroU64, NonZeroUsize},
};

/// Item size for queue entries (32 bytes like a hash digest).
const ITEM_SIZE: usize = 32;

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
    #[arbitrary(with = bounded_items)]
    items_per_section: u64,
    /// Write buffer size.
    #[arbitrary(with = bounded_buffer)]
    write_buffer: usize,
    #[arbitrary(with = bounded_buffer)]
    replay_buffer: usize,
    /// Failure rate for sync operations (0, 1].
    #[arbitrary(with = bounded_nonzero_rate)]
    sync_failure_rate: Probability,
    /// Failure and byte-retention configuration for write operations.
    write_config: deterministic::WriteConfig,
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
    /// The failed operation's suffix is uncertain, but earlier committed items remain durable.
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
    mut queue: Queue<deterministic::Context, Vec<u8>>,
    operations: &[QueueOperation],
) -> RecoveryState {
    let mut state = RecoveryState::new();

    for op in operations {
        queue = match op {
            QueueOperation::Enqueue { value } => {
                let item = make_item(*value);
                match queue.enqueue(item).await {
                    Ok((queue, pos)) => {
                        // enqueue = append + commit, so success means ALL
                        // previously uncommitted items are now durable too.
                        state.commit_succeeded();
                        state.enqueue_succeeded(pos, *value);
                        queue
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
                    Ok((queue, pos)) => {
                        state.append_succeeded(pos, *value);
                        queue
                    }
                    Err(_) => {
                        state.append_failed(*value);
                        state.mark_mutable_error();
                        return state;
                    }
                }
            }

            QueueOperation::Commit => match queue.commit().await {
                Ok(queue) => {
                    state.commit_succeeded();
                    queue
                }
                Err(_) => {
                    state.commit_failed();
                    state.mark_mutable_error();
                    return state;
                }
            },

            QueueOperation::DequeueAndAck => {
                if let Ok(Some((pos, _item))) = queue.dequeue().await
                    && queue.ack(pos).is_ok()
                {
                    state.update_ack_floor(queue.ack_floor());
                }
                queue
            }

            QueueOperation::DequeueNoAck => {
                // Dequeue without acking - item should be re-delivered on recovery
                let _ = queue.dequeue().await;
                queue
            }

            QueueOperation::AckOffset { offset } => {
                let size = queue.size();
                let ack_floor = queue.ack_floor();
                if size > ack_floor {
                    let range = size - ack_floor;
                    let pos = ack_floor + (*offset as u64 % range);
                    match queue.ack(pos) {
                        Ok(()) => {
                            state.update_ack_floor(queue.ack_floor());
                        }
                        Err(_) => {
                            state.mark_mutable_error();
                            return state;
                        }
                    }
                }
                queue
            }

            QueueOperation::AckUpToOffset { offset } => {
                let size = queue.size();
                let up_to = (*offset as u64) % (size + 1);
                match queue.ack_up_to(up_to) {
                    Ok(()) => {
                        state.update_ack_floor(queue.ack_floor());
                    }
                    Err(_) => {
                        state.mark_mutable_error();
                        return state;
                    }
                }
                queue
            }

            QueueOperation::Sync => match queue.sync().await {
                Ok(queue) => {
                    // sync = commit + prune, so success means ALL
                    // previously uncommitted items are now durable too.
                    state.commit_succeeded();
                    state.update_ack_floor(queue.ack_floor());
                    queue
                }
                Err(_) => {
                    state.commit_failed();
                    state.mark_mutable_error();
                    return state;
                }
            },

            QueueOperation::Reset => {
                queue.reset();
                queue
            }
        };
    }

    state
}

async fn verify_recovered_items(
    queue: &mut Queue<deterministic::Context, Vec<u8>>,
    state: &RecoveryState,
    size: u64,
    ack_floor: u64,
) {
    queue.reset();
    let mut dequeued_count = 0u64;
    loop {
        match queue.dequeue().await {
            Ok(Some((pos, item))) => {
                dequeued_count += 1;
                if let Some(value) = state.committed.get(&pos) {
                    assert_eq!(
                        item,
                        make_item(*value),
                        "item at position {pos} has wrong content after recovery",
                    );
                }
                assert!(
                    dequeued_count <= size,
                    "dequeued more items than queue size"
                );
            }
            Ok(None) => break,
            Err(err) => panic!(
                "dequeue at position {} failed after recovery: {err} (size={size}, \
                 ack_floor={ack_floor})",
                ack_floor + dequeued_count,
            ),
        }
    }
    assert_eq!(
        dequeued_count,
        size - ack_floor,
        "dequeued {dequeued_count} items but expected {} unacked (size={size}, \
         ack_floor={ack_floor})",
        size - ack_floor,
    );
}

/// Verify the durable prefix and basic usability after a mutable operation failed.
async fn verify_recovery_after_mutable_error(
    mut queue: Queue<deterministic::Context, Vec<u8>>,
    state: &RecoveryState,
) {
    let size_before = queue.size();
    let ack_floor = queue.ack_floor();
    let durable_end = state
        .committed
        .last_key_value()
        .map_or(0, |(&position, _)| position + 1);
    assert!(
        size_before >= durable_end,
        "recovered size {size_before} lost committed positions through {durable_end}",
    );
    assert!(
        ack_floor <= state.current_ack_floor,
        "recovered ack floor {ack_floor} exceeds requested floor {}",
        state.current_ack_floor,
    );
    verify_recovered_items(&mut queue, state, size_before, ack_floor).await;

    // Queue should remain writable after recovery.
    let (queue, new_pos) = queue
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
async fn verify_recovery(mut queue: Queue<deterministic::Context, Vec<u8>>, state: &RecoveryState) {
    if state.saw_mutable_error() {
        verify_recovery_after_mutable_error(queue, state).await;
        return;
    }

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

    verify_recovered_items(&mut queue, state, size, ack_floor).await;

    // Verify we can enqueue new items after recovery
    let (_queue, new_pos) = queue.enqueue(make_item(0xFF)).await.unwrap();
    assert_eq!(new_pos, size, "new item should be at position {}", size);
}

fn fuzz(input: FuzzInput) {
    let page_size = NonZeroU16::new(input.page_size).unwrap();
    let page_cache_size = NonZeroUsize::new(input.page_cache_size).unwrap();
    let items_per_section = NonZeroU64::new(input.items_per_section).unwrap();
    let write_buffer = NonZeroUsize::new(input.write_buffer).unwrap();
    let replay_buffer = NonZeroUsize::new(input.replay_buffer).unwrap();
    let cfg = deterministic::Config::default().with_seed(input.seed);
    let partition_name = format!("queue-crash-recovery-{}", input.seed);
    let operations = input.operations.clone();
    let sync_failure_rate = input.sync_failure_rate;
    let write_config = input.write_config;

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
                page_cache: CacheRef::from_pooler(&ctx, page_size, page_cache_size),
                write_buffer,
                replay_buffer,
            };

            let queue = Queue::<_, Vec<u8>>::init(ctx.child("storage"), queue_cfg)
                .await
                .unwrap();

            // Enable fault injection
            let fault_config = deterministic::FaultConfig {
                sync_rate: Some(sync_failure_rate),
                write_rate: Some(write_config),
                ..Default::default()
            };
            let faults = ctx.storage_fault_config();
            *faults.write() = fault_config;

            run_operations(queue, &operations).await
        }
    });

    let recovery_partition = partition_name.clone();
    let checkpoint = faulted_recovery(checkpoint, input.seed, move |ctx| async move {
        let queue_cfg = Config {
            partition: recovery_partition,
            items_per_section,
            compression: None,
            codec_config: ((0usize..).into(), ()),
            page_cache: CacheRef::from_pooler(&ctx, page_size, page_cache_size),
            write_buffer,
            replay_buffer,
        };
        Queue::<_, Vec<u8>>::init(ctx.child("faulted_recovery"), queue_cfg).await
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
            page_cache: CacheRef::from_pooler(&ctx, page_size, page_cache_size),
            write_buffer,
            replay_buffer,
        };

        let queue = Queue::<_, Vec<u8>>::init(ctx.child("storage"), queue_cfg)
            .await
            .expect("Queue recovery should succeed");

        verify_recovery(queue, &state).await;
    });
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
