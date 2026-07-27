#![no_main]

//! Fuzz test for queue crash recovery and durability guarantees.
//!
//! Tests that:
//! - Enqueued items survive crashes
//! - Unacknowledged items are re-delivered after recovery
//! - Acknowledged items (once committed) may or may not be re-delivered after crash
//! - Queue state is consistent after recovery

use arbitrary::{Arbitrary, Result, Unstructured};
use commonware_runtime::{Runner, Supervisor as _, buffer::paged::CacheRef, deterministic};
use commonware_storage::queue::{Config, Queue};
use commonware_utils::FuzzRng;
use libfuzzer_sys::fuzz_target;
use std::{
    collections::BTreeMap,
    num::{NonZeroU16, NonZeroU64, NonZeroUsize},
};

/// Maximum write buffer size.
const MAX_WRITE_BUF: usize = 2048;

/// Item size for queue entries (32 bytes like a hash digest).
const ITEM_SIZE: usize = 32;

/// Maximum number of operations per fuzz input.
const MAX_OPERATIONS: usize = 128;

/// Bytes reserved for deterministic runtime choices.
const RNG_BYTES: usize = 32;

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

fn bounded_rate(u: &mut Unstructured<'_>) -> Result<f64> {
    let percent: u8 = u.int_in_range(0..=100)?;
    Ok(f64::from(percent) / 100.0)
}

fn bounded_operations(u: &mut Unstructured<'_>) -> Result<Vec<QueueOperation>> {
    let count = u.int_in_range(0..=MAX_OPERATIONS)?;
    (0..count).map(|_| QueueOperation::arbitrary(u)).collect()
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
    /// Fuzzer-controlled randomness for deterministic runtime choices.
    raw_bytes: [u8; RNG_BYTES],
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
    /// Optional variable-journal compression.
    compression: bool,
    /// Failure rate for sync operations.
    #[arbitrary(with = bounded_rate)]
    sync_failure_rate: f64,
    /// Failure rate for write operations.
    #[arbitrary(with = bounded_rate)]
    write_failure_rate: f64,
    /// Sequence of operations to execute.
    #[arbitrary(with = bounded_operations)]
    operations: Vec<QueueOperation>,
}

/// Conservative bounds and known contents for crash recovery.
#[derive(Debug, Clone)]
struct RecoveryState {
    /// Value written at every position that may survive. Operations stop on the first mutation
    /// error, so even the uncertain tail has a single known value.
    values: BTreeMap<u64, u8>,
    /// Smallest end position guaranteed to survive.
    durable_size: u64,
    /// Largest end position that may survive.
    max_size: u64,
    /// Smallest pruning boundary guaranteed to survive.
    durable_prune: u64,
    /// Largest pruning boundary that may survive.
    max_prune: u64,
}

impl RecoveryState {
    fn new() -> Self {
        Self {
            values: BTreeMap::new(),
            durable_size: 0,
            max_size: 0,
            durable_prune: 0,
            max_prune: 0,
        }
    }

    fn appended(&mut self, pos: u64, value: u8) {
        self.values.insert(pos, value);
        self.max_size = self.max_size.max(pos + 1);
    }

    fn committed(&mut self, size: u64) {
        self.durable_size = size;
        self.max_size = size;
    }

    fn synced(&mut self, size: u64, boundary: u64) {
        self.committed(size);
        self.durable_prune = boundary;
        self.max_prune = boundary;
    }

    fn sync_failed(&mut self, possible_boundary: u64) {
        self.max_prune = self.max_prune.max(possible_boundary);
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
) -> RecoveryState {
    let mut state = RecoveryState::new();

    for op in operations {
        queue = match op {
            QueueOperation::Enqueue { value } => {
                let pos = queue.size();
                let item = make_item(*value);
                match queue.enqueue(item).await {
                    Ok((queue, actual_pos)) => {
                        assert_eq!(actual_pos, pos, "enqueue returned non-contiguous position");
                        state.appended(pos, *value);
                        state.committed(queue.size());
                        queue
                    }
                    Err(_) => {
                        state.appended(pos, *value);
                        return state;
                    }
                }
            }

            QueueOperation::Append { value } => {
                let pos = queue.size();
                let item = make_item(*value);
                match queue.append(item).await {
                    Ok((queue, actual_pos)) => {
                        assert_eq!(actual_pos, pos, "append returned non-contiguous position");
                        state.appended(pos, *value);
                        queue
                    }
                    Err(_) => {
                        state.appended(pos, *value);
                        return state;
                    }
                }
            }

            QueueOperation::Commit => match queue.commit().await {
                Ok(queue) => {
                    state.committed(queue.size());
                    queue
                }
                Err(_) => return state,
            },

            QueueOperation::DequeueAndAck => {
                if let Some((pos, _)) = queue.dequeue().await.expect("live dequeue should not fail")
                {
                    queue
                        .ack(pos)
                        .expect("dequeued position must be valid for ack");
                }
                queue
            }

            QueueOperation::DequeueNoAck => {
                queue.dequeue().await.expect("live dequeue should not fail");
                queue
            }

            QueueOperation::AckOffset { offset } => {
                let size = queue.size();
                let ack_floor = queue.ack_floor();
                if size > ack_floor {
                    let range = size - ack_floor;
                    let pos = ack_floor + (*offset as u64 % range);
                    queue.ack(pos).expect("clamped ack position must be valid");
                }
                queue
            }

            QueueOperation::AckUpToOffset { offset } => {
                let size = queue.size();
                let up_to = (*offset as u64) % (size + 1);
                queue
                    .ack_up_to(up_to)
                    .expect("clamped ack range must be valid");
                queue
            }

            QueueOperation::Sync => {
                let size = queue.size();
                let possible_boundary = (queue.ack_floor() / items_per_section)
                    .min(size / items_per_section)
                    * items_per_section;
                match queue.sync().await {
                    Ok(queue) => {
                        state.synced(size, possible_boundary);
                        queue
                    }
                    Err(_) => {
                        state.sync_failed(possible_boundary);
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

/// Verify the queue state after recovery.
async fn verify_recovery(
    mut queue: Queue<deterministic::Context, Vec<u8>>,
    state: &RecoveryState,
    items_per_section: u64,
) -> Queue<deterministic::Context, Vec<u8>> {
    let size = queue.size();
    let ack_floor = queue.ack_floor();

    assert!(
        size >= state.durable_size,
        "recovered size {} is less than minimum expected {}",
        size,
        state.durable_size
    );
    assert!(
        size <= state.max_size,
        "recovered size {} is greater than maximum expected {}",
        size,
        state.max_size
    );

    assert!(
        ack_floor >= state.durable_prune,
        "recovered ack_floor {} is less than minimum expected {}",
        ack_floor,
        state.durable_prune
    );
    assert!(
        ack_floor <= state.max_prune,
        "recovered ack_floor {} is greater than maximum expected {}",
        ack_floor,
        state.max_prune
    );
    assert!(ack_floor <= size, "recovered ack floor exceeds size");
    assert_eq!(
        ack_floor % items_per_section,
        0,
        "recovered ack floor is not a physical section boundary"
    );
    if ack_floor > state.durable_prune {
        assert_eq!(
            size, state.max_size,
            "an advanced ack floor requires the complete pre-prune tip"
        );
    }

    queue.reset();

    let mut dequeued_count = 0u64;
    loop {
        match queue.dequeue().await {
            Ok(Some((pos, item))) => {
                let expected_pos = ack_floor + dequeued_count;
                assert_eq!(
                    pos, expected_pos,
                    "dequeue returned non-contiguous position"
                );
                dequeued_count += 1;
                let value = state
                    .values
                    .get(&pos)
                    .unwrap_or_else(|| panic!("no modeled value for recovered position {pos}"));
                assert_eq!(item, make_item(*value), "wrong recovered item at {pos}");
                assert!(
                    dequeued_count <= size,
                    "dequeued more items than queue size"
                );
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
    queue
}

fn fuzz(input: FuzzInput) {
    let page_size = NonZeroU16::new(input.page_size).unwrap();
    let page_cache_size = NonZeroUsize::new(input.page_cache_size).unwrap();
    let items_per_section = NonZeroU64::new(input.items_per_section).unwrap();
    let write_buffer = NonZeroUsize::new(input.write_buffer).unwrap();
    let rng = FuzzRng::new(input.raw_bytes.to_vec());
    let cfg = deterministic::Config::default().with_rng(Box::new(rng));
    let partition_name = "queue-crash-recovery".to_string();
    let operations = input.operations.clone();
    let sync_failure_rate = input.sync_failure_rate;
    let write_failure_rate = input.write_failure_rate;
    let compression = input.compression.then_some(3);

    let runner = deterministic::Runner::new(cfg);

    let (mut state, checkpoint) = runner.start_and_recover(|ctx| {
        let partition_name = partition_name.clone();
        let operations = operations.clone();
        async move {
            let queue_cfg = Config {
                partition: partition_name,
                items_per_section,
                compression,
                codec_config: ((0usize..).into(), ()),
                page_cache: CacheRef::from_pooler(&ctx, page_size, page_cache_size),
                write_buffer,
            };

            let queue = Queue::<_, Vec<u8>>::init(ctx.child("storage"), queue_cfg)
                .await
                .unwrap();

            // Enable fault injection
            let fault_config = deterministic::FaultConfig {
                sync_rate: Some(sync_failure_rate),
                write_rate: Some(write_failure_rate),
                partial_write_rate: Some(1.0),
                ..Default::default()
            };
            let faults = ctx.storage_fault_config();
            *faults.write() = fault_config;

            run_operations(queue, &operations, items_per_section.get()).await
        }
    });

    // Recover, verify the modeled state, then persist a sentinel.
    let verify_partition = partition_name.clone();
    let ((state, sentinel_pos), checkpoint) = deterministic::Runner::from(checkpoint)
        .start_and_recover(|ctx| async move {
            *ctx.storage_fault_config().write() = deterministic::FaultConfig::default();

            let queue_cfg = Config {
                partition: verify_partition,
                items_per_section,
                compression,
                codec_config: ((0usize..).into(), ()),
                page_cache: CacheRef::from_pooler(&ctx, page_size, page_cache_size),
                write_buffer,
            };

            let queue = Queue::<_, Vec<u8>>::init(ctx.child("storage"), queue_cfg)
                .await
                .expect("Queue recovery should succeed");
            let queue = verify_recovery(queue, &state, items_per_section.get()).await;

            let sentinel_pos = queue.size();
            let (queue, actual_pos) = queue
                .enqueue(make_item(0xFF))
                .await
                .expect("enqueue after recovery should succeed");
            assert_eq!(actual_pos, sentinel_pos);
            let queue = queue
                .sync()
                .await
                .expect("sync after recovery should succeed");
            state.appended(sentinel_pos, 0xFF);
            state.synced(queue.size(), queue.ack_floor());
            (state, sentinel_pos)
        });

    // Cross one more crash boundary so the sentinel's durability is actually exercised, then
    // interrupt the real composite destroy at one of its storage awaits.
    let (_, checkpoint) =
        deterministic::Runner::from(checkpoint).start_and_recover(|ctx| async move {
            let queue_cfg = Config {
                partition: partition_name,
                items_per_section,
                compression,
                codec_config: ((0usize..).into(), ()),
                page_cache: CacheRef::from_pooler(&ctx, page_size, page_cache_size),
                write_buffer,
            };
            let queue = Queue::<_, Vec<u8>>::init(ctx.child("storage"), queue_cfg)
                .await
                .expect("Queue sentinel recovery should succeed");
            assert_eq!(queue.size(), sentinel_pos + 1);
            let queue = verify_recovery(queue, &state, items_per_section.get()).await;
            *ctx.storage_fault_config().write() = deterministic::FaultConfig {
                write_rate: Some(0.5),
                partial_write_rate: Some(1.0),
                sync_rate: Some(0.5),
                remove_rate: Some(0.5),
                ..Default::default()
            };
            let _ = queue.destroy().await;
        });

    // Any interrupted-destroy state must remain openable, including the fully removed state, and
    // destruction must be retryable.
    deterministic::Runner::from(checkpoint).start(|ctx| async move {
        *ctx.storage_fault_config().write() = deterministic::FaultConfig::default();
        let queue_cfg = Config {
            partition: "queue-crash-recovery".to_string(),
            items_per_section,
            compression,
            codec_config: ((0usize..).into(), ()),
            page_cache: CacheRef::from_pooler(&ctx, page_size, page_cache_size),
            write_buffer,
        };
        let queue = Queue::<_, Vec<u8>>::init(ctx.child("redestroy"), queue_cfg)
            .await
            .expect("queue must reopen after interrupted destroy");
        queue.destroy().await.expect("destroy retry must succeed");
    });
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
