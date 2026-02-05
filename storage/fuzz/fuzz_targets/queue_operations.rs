#![no_main]

use arbitrary::{Arbitrary, Result, Unstructured};
use commonware_runtime::{buffer::paged::CacheRef, deterministic, Runner};
use commonware_storage::{
    queue::{Config, Queue},
    Persistable,
};
use libfuzzer_sys::fuzz_target;
use std::{
    collections::BTreeSet,
    num::{NonZeroU16, NonZeroU64, NonZeroUsize},
};

/// Maximum write buffer size.
const MAX_WRITE_BUF: usize = 2048;

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

#[derive(Arbitrary, Debug, Clone)]
enum QueueOperation {
    /// Enqueue a new item.
    Enqueue { value: u8 },

    /// Dequeue the next unacked item.
    Dequeue,

    /// Acknowledge a specific position.
    Ack { pos_offset: u8 },

    /// Acknowledge all items up to a position.
    AckUpTo { pos_offset: u8 },

    /// Peek at the next unacked item.
    Peek,

    /// Reset the read position.
    Reset,

    /// Sync and prune.
    Sync,
}

#[derive(Arbitrary, Debug)]
struct FuzzInput {
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
    /// Sequence of operations to execute.
    operations: Vec<QueueOperation>,
}

/// Reference model for verifying queue behavior.
struct ReferenceQueue {
    /// Items that have been enqueued (position -> value).
    items: Vec<u8>,

    /// Positions that have been acknowledged.
    acked: BTreeSet<u64>,

    /// Current read position.
    read_pos: u64,
}

impl ReferenceQueue {
    fn new() -> Self {
        Self {
            items: Vec::new(),
            acked: BTreeSet::new(),
            read_pos: 0,
        }
    }

    fn enqueue(&mut self, value: u8) -> u64 {
        let pos = self.items.len() as u64;
        self.items.push(value);
        pos
    }

    fn size(&self) -> u64 {
        self.items.len() as u64
    }

    fn is_acked(&self, pos: u64) -> bool {
        self.acked.contains(&pos)
    }

    fn ack_floor(&self) -> u64 {
        // Find the lowest unacked position
        for pos in 0..self.size() {
            if !self.acked.contains(&pos) {
                return pos;
            }
        }
        self.size()
    }

    fn dequeue(&mut self) -> Option<(u64, u8)> {
        while self.read_pos < self.size() {
            let pos = self.read_pos;
            self.read_pos += 1;
            if !self.is_acked(pos) {
                return Some((pos, self.items[pos as usize]));
            }
        }
        None
    }

    fn peek(&self) -> Option<(u64, u8)> {
        let mut pos = self.read_pos;
        while pos < self.size() {
            if !self.is_acked(pos) {
                return Some((pos, self.items[pos as usize]));
            }
            pos += 1;
        }
        None
    }

    fn ack(&mut self, pos: u64) -> bool {
        if pos >= self.size() {
            return false;
        }
        self.acked.insert(pos);
        true
    }

    fn ack_up_to(&mut self, up_to: u64) -> bool {
        if up_to > self.size() {
            return false;
        }
        for pos in 0..up_to {
            self.acked.insert(pos);
        }
        true
    }

    fn reset(&mut self) {
        self.read_pos = self.ack_floor();
    }

    fn is_empty(&self) -> bool {
        self.ack_floor() >= self.size()
    }
}

fn fuzz(input: FuzzInput) {
    let runner = deterministic::Runner::default();

    let page_size = NonZeroU16::new(input.page_size).unwrap();
    let page_cache_size = NonZeroUsize::new(input.page_cache_size).unwrap();
    let items_per_section = NonZeroU64::new(input.items_per_section).unwrap();
    let write_buffer = NonZeroUsize::new(input.write_buffer).unwrap();

    runner.start(|context| async move {
        let cfg = Config {
            partition: "queue_operations_fuzz_test".to_string(),
            items_per_section,
            compression: None,
            codec_config: ((0usize..).into(), ()),
            page_cache: CacheRef::new(page_size, page_cache_size),
            write_buffer,
        };

        let mut queue = Queue::<_, Vec<u8>>::init(context.clone(), cfg)
            .await
            .unwrap();
        let mut reference = ReferenceQueue::new();

        for op in input.operations.iter() {
            match op {
                QueueOperation::Enqueue { value } => {
                    let pos = queue.enqueue(vec![*value]).await.unwrap();
                    let ref_pos = reference.enqueue(*value);
                    assert_eq!(pos, ref_pos, "enqueue position mismatch");
                }

                QueueOperation::Dequeue => {
                    let result = queue.dequeue().await.unwrap();
                    let ref_result = reference.dequeue();

                    match (result, ref_result) {
                        (Some((pos, item)), Some((ref_pos, ref_item))) => {
                            assert_eq!(pos, ref_pos, "dequeue position mismatch");
                            assert_eq!(item, vec![ref_item], "dequeue value mismatch");
                        }
                        (None, None) => {}
                        (actual, expected) => {
                            panic!("dequeue mismatch: got {actual:?}, expected {expected:?}");
                        }
                    }
                }

                QueueOperation::Ack { pos_offset } => {
                    let size = queue.size();
                    if size == 0 {
                        continue;
                    }
                    // Map offset to a valid position range
                    let pos = (*pos_offset as u64) % size;

                    let result = queue.ack(pos);
                    let ref_result = reference.ack(pos);

                    assert_eq!(
                        result.is_ok(),
                        ref_result,
                        "ack result mismatch for pos {pos}"
                    );
                }

                QueueOperation::AckUpTo { pos_offset } => {
                    let size = queue.size();
                    // Map offset to valid range [0, size]
                    let up_to = (*pos_offset as u64) % (size + 1);

                    let result = queue.ack_up_to(up_to);
                    let ref_result = reference.ack_up_to(up_to);

                    assert_eq!(
                        result.is_ok(),
                        ref_result,
                        "ack_up_to result mismatch for up_to {up_to}"
                    );
                }

                QueueOperation::Peek => {
                    let result = queue.peek().await.unwrap();
                    let ref_result = reference.peek();

                    match (result, ref_result) {
                        (Some((pos, item)), Some((ref_pos, ref_item))) => {
                            assert_eq!(pos, ref_pos, "peek position mismatch");
                            assert_eq!(item, vec![ref_item], "peek value mismatch");
                        }
                        (None, None) => {}
                        (actual, expected) => {
                            panic!("peek mismatch: got {actual:?}, expected {expected:?}");
                        }
                    }
                }

                QueueOperation::Reset => {
                    queue.reset();
                    reference.reset();
                }

                QueueOperation::Sync => {
                    queue.sync().await.unwrap();
                }
            }

            // Verify invariants after each operation
            assert_eq!(queue.size(), reference.size(), "size mismatch after {op:?}");
            assert_eq!(
                queue.ack_floor(),
                reference.ack_floor(),
                "ack_floor mismatch after {op:?}"
            );
            assert_eq!(
                queue.is_empty(),
                reference.is_empty(),
                "is_empty mismatch after {op:?}"
            );

            // Verify is_acked consistency for a sample of positions
            for pos in 0..queue.size().min(20) {
                assert_eq!(
                    queue.is_acked(pos),
                    reference.is_acked(pos),
                    "is_acked mismatch for pos {pos} after {op:?}"
                );
            }
        }

        queue.destroy().await.unwrap();
    });
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
