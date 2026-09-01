#![no_main]

//! Fuzz test for queue crash recovery and durability guarantees.
//!
//! Tests that:
//! - Enqueued items survive crashes
//! - Unacknowledged items are re-delivered after recovery
//! - Acknowledged items (once committed) may or may not be re-delivered after crash
//! - Queue state is consistent after recovery
//!
//! The operation phase runs under write and sync fault injection. Remove faults are armed only
//! around each Sync drive, so its internal prune can fail after removing whole sections and
//! strand a partially pruned image. Between the crash and the clean verification, a chain of
//! faulted recovery attempts reopens the queue under fresh faults, each crashing into the next.

use arbitrary::Arbitrary;
use commonware_runtime::{Runner, Supervisor as _, buffer::paged::CacheRef, deterministic};
use commonware_storage::queue::{Config, Queue};
use commonware_storage_fuzz::{
    bounded_buffer, bounded_entropy, bounded_items, bounded_nonzero_rate, bounded_page_cache_size,
    bounded_page_size, faulted_recovery,
};
use commonware_utils::{FuzzRng, Probability, sync::RwLock};
use libfuzzer_sys::fuzz_target;
use std::{
    collections::BTreeMap,
    num::{NonZeroU16, NonZeroU64, NonZeroUsize},
    sync::Arc,
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
    /// Replay buffer size.
    #[arbitrary(with = bounded_buffer)]
    replay_buffer: usize,
    /// Failure rate for sync operations (0, 1].
    #[arbitrary(with = bounded_nonzero_rate)]
    sync_failure_rate: Probability,
    /// Failure and byte-retention configuration for write operations.
    write_config: deterministic::WriteConfig,
    /// Remove failure rate (percent) armed only around each Sync drive, sampled per blob
    /// removal so the internal prune can fail after removing only some sections.
    remove_failure: u8,
    /// Sequence of operations to execute.
    operations: Vec<QueueOperation>,
    /// Byte stream driving the runtime rng: all in-run randomness, fault sampling, and the
    /// faulted recovery chain's depth and shapes.
    #[arbitrary(with = bounded_entropy)]
    entropy: Vec<u8>,
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

    /// Items whose covering operation failed (position -> value). Every append
    /// targets the queue size at call time, so a failed operation's bytes can only
    /// become durable at its predicted position.
    pending: BTreeMap<u64, u8>,

    /// Current in-memory ack floor (lost on crash).
    current_ack_floor: u64,

    /// Items that were appended but not yet committed (position -> value).
    /// These may be lost on crash. On commit, they move to `committed`.
    uncommitted: BTreeMap<u64, u8>,

    /// Blob-aligned pruning boundary established by the last successful Sync.
    /// Recovery reports this boundary as the ack floor.
    synced_boundary: u64,

    /// Whether we observed a mutable storage error during the operation phase.
    ///
    /// The failed operation's suffix is uncertain, but earlier committed items remain durable.
    saw_mutable_error: bool,
}

impl RecoveryState {
    fn new() -> Self {
        Self {
            committed: BTreeMap::new(),
            pending: BTreeMap::new(),
            current_ack_floor: 0,
            uncommitted: BTreeMap::new(),
            synced_boundary: 0,
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

    fn enqueue_failed(&mut self, pos: u64, value: u8) {
        // Enqueue may have partially succeeded (append but not commit).
        // Track the item as pending because it may or may not be persisted.
        self.pending.insert(pos, value);
    }

    fn append_succeeded(&mut self, pos: u64, value: u8) {
        // Append establishes no durability, so the item stays uncommitted until a commit.
        self.uncommitted.insert(pos, value);
    }

    fn append_failed(&mut self, pos: u64, value: u8) {
        self.pending.insert(pos, value);
    }

    fn commit_succeeded(&mut self) {
        // All uncommitted items are now durable.
        let uncommitted = std::mem::take(&mut self.uncommitted);
        for (pos, value) in uncommitted {
            self.committed.insert(pos, value);
        }
    }

    fn commit_failed(&mut self) {
        // Uncommitted items remain uncommitted. They may or may not be durable,
        // so move them to pending.
        let uncommitted = std::mem::take(&mut self.uncommitted);
        for (pos, value) in uncommitted {
            self.pending.insert(pos, value);
        }
    }

    fn update_ack_floor(&mut self, ack_floor: u64) {
        self.current_ack_floor = ack_floor;
    }

    /// Record the boundary pruned by a successful Sync, mirroring the journal's
    /// clamp: the target blob is capped to the tail blob, boundaries are
    /// blob-aligned, and the boundary never regresses.
    fn sync_succeeded(&mut self, ack_floor: u64, size: u64, items_per_section: u64) {
        let min_blob = (ack_floor / items_per_section).min(size / items_per_section);
        self.synced_boundary = self.synced_boundary.max(min_blob * items_per_section);
    }

    /// Returns the expected item content at a recovered position, if tracked.
    fn expected_item(&self, pos: u64) -> Option<u8> {
        self.committed
            .get(&pos)
            .or_else(|| self.uncommitted.get(&pos))
            .or_else(|| self.pending.get(&pos))
            .copied()
    }

    /// Returns the minimum size we expect after recovery.
    fn min_recovered_size(&self) -> u64 {
        self.committed.len() as u64
    }

    /// Returns the maximum size we expect after recovery.
    fn max_recovered_size(&self) -> u64 {
        (self.committed.len() + self.pending.len() + self.uncommitted.len()) as u64
    }
}

fn make_item(value: u8) -> Vec<u8> {
    vec![value; ITEM_SIZE]
}

/// Run operations on the queue, tracking state for recovery verification.
async fn run_operations(
    mut queue: Queue<deterministic::Context, Vec<u8>>,
    operations: &[QueueOperation],
    items_per_section: u64,
    faults: &Arc<RwLock<deterministic::FaultConfig>>,
    op_faults: &deterministic::FaultConfig,
    sync_faults: &deterministic::FaultConfig,
) -> RecoveryState {
    let mut state = RecoveryState::new();

    for op in operations {
        queue = match op {
            QueueOperation::Enqueue { value } => {
                let item = make_item(*value);
                let pos = queue.size();
                match queue.enqueue(item).await {
                    Ok((queue, pos)) => {
                        // enqueue = append + commit, so success means ALL
                        // previously uncommitted items are now durable too.
                        state.commit_succeeded();
                        state.enqueue_succeeded(pos, *value);
                        queue
                    }
                    Err(_) => {
                        state.enqueue_failed(pos, *value);
                        state.mark_mutable_error();
                        return state;
                    }
                }
            }

            QueueOperation::Append { value } => {
                let item = make_item(*value);
                let pos = queue.size();
                match queue.append(item).await {
                    Ok((queue, pos)) => {
                        state.append_succeeded(pos, *value);
                        queue
                    }
                    Err(_) => {
                        state.append_failed(pos, *value);
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
                // Reads are never fault-injected and every prior mutable op
                // succeeded, so a dequeue error here can only be a real bug.
                let dequeued = queue
                    .dequeue()
                    .await
                    .expect("dequeue failed on successfully written data");
                if let Some((pos, _item)) = dequeued {
                    // Ack of a just-dequeued position is in-memory bookkeeping on an
                    // in-range position, so it has no legal way to fail.
                    queue.ack(pos).expect("ack of dequeued position failed");
                    state.update_ack_floor(queue.ack_floor());
                }
                queue
            }

            QueueOperation::DequeueNoAck => {
                // Dequeue without acking. The unacked item must be re-delivered on recovery.
                queue
                    .dequeue()
                    .await
                    .expect("dequeue failed on successfully written data");
                queue
            }

            QueueOperation::AckOffset { offset } => {
                let size = queue.size();
                let ack_floor = queue.ack_floor();
                if size > ack_floor {
                    let range = size - ack_floor;
                    let pos = ack_floor + (*offset as u64 % range);

                    // Ack is in-memory bookkeeping and the position is in range, so an
                    // error here is a real bug, never an injected fault.
                    queue.ack(pos).expect("ack of in-range position failed");
                    state.update_ack_floor(queue.ack_floor());
                }
                queue
            }

            QueueOperation::AckUpToOffset { offset } => {
                let size = queue.size();
                let up_to = (*offset as u64) % (size + 1);

                // Same as ack: in-memory, in-range, no legal failure.
                queue
                    .ack_up_to(up_to)
                    .expect("ack_up_to of in-range position failed");
                state.update_ack_floor(queue.ack_floor());
                queue
            }

            QueueOperation::Sync => {
                // Remove faults are armed only around the Sync drive: its internal prune is
                // the only remove site, and a failed removal strands a partially pruned image
                // for recovery to observe.
                *faults.write() = sync_faults.clone();
                let result = queue.sync().await;
                *faults.write() = op_faults.clone();
                match result {
                    Ok(queue) => {
                        // sync = commit + prune, so success means ALL
                        // previously uncommitted items are now durable too.
                        state.commit_succeeded();
                        state.update_ack_floor(queue.ack_floor());
                        state.sync_succeeded(queue.ack_floor(), queue.size(), items_per_section);
                        queue
                    }
                    Err(_) => {
                        // The internal prune can fail after removing whole sections, so the
                        // recovered floor may land anywhere between the last synced boundary
                        // and the blob-aligned ack floor. `sync_succeeded` is deliberately not
                        // called: `synced_boundary` stays at the last completed Sync, which
                        // remains a valid floor because removals only move the boundary
                        // forward.
                        state.commit_failed();
                        state.mark_mutable_error();
                        return state;
                    }
                }
            }

            QueueOperation::Reset => {
                queue.reset();
                queue
            }
        };
    }

    state
}

/// Dequeue every unacked item from the recovered queue, checking each recovered position holds
/// tracked content and that exactly `size - ack_floor` items are delivered.
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

                // Every surviving position was appended by exactly one tracked
                // operation, so it must be tracked and its content must match.
                let value = state
                    .expected_item(pos)
                    .unwrap_or_else(|| panic!("recovered untracked position {pos}"));
                assert_eq!(
                    item,
                    make_item(value),
                    "item at position {pos} has wrong content after recovery",
                );
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

    // A failed operation can leave at most its own tracked items behind, and the
    // faulted recovery pass only truncates, so recovery cannot fabricate items.
    assert!(
        size_before <= state.max_recovered_size(),
        "recovered size {size_before} exceeds all tracked appends ({})",
        state.max_recovered_size(),
    );
    assert!(
        ack_floor <= state.current_ack_floor,
        "recovered ack floor {ack_floor} exceeds requested floor {}",
        state.current_ack_floor,
    );

    // Successful prunes remove blobs durably, so the boundary cannot regress even
    // when a later operation failed. A failed Sync's partial prune can only advance
    // the floor further, at most to the blob-aligned ack floor, which the requested
    // floor ceiling above already admits.
    assert!(
        ack_floor >= state.synced_boundary,
        "recovered ack floor {ack_floor} regressed below the last synced boundary {}",
        state.synced_boundary,
    );
    verify_recovered_items(&mut queue, state, size_before, ack_floor).await;

    // Usability phase: the recovered instance must accept new writes.
    let (queue, new_pos) = queue
        .enqueue(make_item(0xFF))
        .await
        .expect("recovered queue rejected a new enqueue");
    assert_eq!(
        new_pos, size_before,
        "new item landed away from the recovered queue size"
    );

    // The persist path must also remain usable.
    let queue = queue.sync().await.expect("recovered queue failed to sync");

    // Destroy exercises the removal path on a post-crash image.
    queue.destroy().await.expect("destroy");
}

/// Verify the queue state after recovery.
async fn verify_recovery(mut queue: Queue<deterministic::Context, Vec<u8>>, state: &RecoveryState) {
    if state.saw_mutable_error() {
        verify_recovery_after_mutable_error(queue, state).await;
        return;
    }

    let size = queue.size();
    let ack_floor = queue.ack_floor();

    // The recovered size is bounded below by committed items and above by every tracked append.
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

    // Recovery reports ack_floor = journal.bounds().start (the pruning boundary),
    // and with every operation successful the only prunes are from Syncs, so the
    // recovered floor must equal the boundary the last successful Sync established.
    assert_eq!(
        ack_floor, state.synced_boundary,
        "recovered ack_floor diverged from the boundary pruned by the last successful sync"
    );

    verify_recovered_items(&mut queue, state, size, ack_floor).await;

    // Usability phase: the recovered instance must accept new writes.
    let (queue, new_pos) = queue
        .enqueue(make_item(0xFF))
        .await
        .expect("recovered queue rejected a new enqueue");
    assert_eq!(
        new_pos, size,
        "new item landed away from the recovered queue size"
    );

    // Destroy exercises the removal path on a post-crash image.
    queue.destroy().await.expect("destroy");
}

fn fuzz(input: FuzzInput) {
    let page_size = NonZeroU16::new(input.page_size).unwrap();
    let page_cache_size = NonZeroUsize::new(input.page_cache_size).unwrap();
    let items_per_section = NonZeroU64::new(input.items_per_section).unwrap();
    let write_buffer = NonZeroUsize::new(input.write_buffer).unwrap();
    let replay_buffer = NonZeroUsize::new(input.replay_buffer).unwrap();
    let cfg =
        deterministic::Config::default().with_rng(Box::new(FuzzRng::new(input.entropy.clone())));
    let partition_name = "queue-crash-recovery".to_string();
    let operations = input.operations.clone();
    let sync_failure_rate = input.sync_failure_rate;
    let write_config = input.write_config;
    let remove_rate = Probability::new(u64::from(input.remove_failure) % 101, 100).unwrap();

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
                .expect("init on a fresh partition with no faults armed");

            // Enable fault injection
            let op_faults = deterministic::FaultConfig {
                sync_rate: Some(sync_failure_rate),
                write_rate: Some(write_config),
                ..Default::default()
            };
            let sync_faults = deterministic::FaultConfig {
                remove_rate: Some(remove_rate),
                ..op_faults.clone()
            };
            let faults = ctx.storage_fault_config();
            *faults.write() = op_faults.clone();

            run_operations(
                queue,
                &operations,
                items_per_section.get(),
                &faults,
                &op_faults,
                &sync_faults,
            )
            .await
        }
    });

    let recovery_partition = partition_name.clone();
    let checkpoint = faulted_recovery(checkpoint, move |ctx| {
        let recovery_partition = recovery_partition.clone();
        async move {
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
        }
    });

    // Recovery phase: re-initialize the queue from the crash checkpoint.
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
            .expect("clean recovery must succeed on a post-crash image");

        verify_recovery(queue, &state).await;
    });
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
