#![no_main]

use arbitrary::Arbitrary;
use commonware_runtime::{Runner, Supervisor as _, buffer::paged::CacheRef, deterministic};
use commonware_storage::queue::{Config, Error, Queue};
use commonware_storage_fuzz::{
    bounded_buffer, bounded_items, bounded_page_cache_size, bounded_page_size,
};
use commonware_utils::NZUsize;
use libfuzzer_sys::fuzz_target;
use std::{
    collections::BTreeSet,
    num::{NonZeroU16, NonZeroU64, NonZeroUsize},
};

#[derive(Arbitrary, Debug, Clone)]
enum QueueOperation {
    /// Enqueue a new item (append + commit).
    Enqueue { value: u8 },
    /// Append a new item without committing.
    Append { value: u8 },
    /// Commit appended items to disk and publish them to the reader.
    Commit,
    /// Dequeue the next unacked published item.
    Dequeue,
    /// Acknowledge a specific position.
    Ack { pos_offset: u8 },
    /// Acknowledge all items up to a position.
    AckUpTo { pos_offset: u8 },
    /// Reset the read position.
    Reset,
    /// Sync (commit, prune, and publish).
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
    #[arbitrary(with = bounded_items)]
    items_per_section: u64,
    /// Write buffer size.
    #[arbitrary(with = bounded_buffer)]
    write_buffer: usize,
    /// Sequence of operations to execute.
    operations: Vec<QueueOperation>,
}

/// Reference model for verifying queue behavior.
struct ReferenceQueue {
    /// Items that have been appended (position -> value).
    items: Vec<u8>,

    /// Number of items published to the reader by a successful commit or sync.
    published: u64,

    /// Positions that have been acknowledged.
    acked: BTreeSet<u64>,

    /// Current read position.
    read_pos: u64,
}

impl ReferenceQueue {
    fn new() -> Self {
        Self {
            items: Vec::new(),
            published: 0,
            acked: BTreeSet::new(),
            read_pos: 0,
        }
    }

    fn append(&mut self, value: u8) -> u64 {
        let pos = self.items.len() as u64;
        self.items.push(value);
        pos
    }

    fn publish(&mut self) {
        self.published = self.size();
    }

    fn size(&self) -> u64 {
        self.items.len() as u64
    }

    fn is_acked(&self, pos: u64) -> bool {
        self.acked.contains(&pos)
    }

    fn ack_floor(&self) -> u64 {
        // Find the lowest unacked published position
        for pos in 0..self.published {
            if !self.acked.contains(&pos) {
                return pos;
            }
        }
        self.published
    }

    fn dequeue(&mut self) -> Option<(u64, u8)> {
        while self.read_pos < self.published {
            let pos = self.read_pos;
            self.read_pos += 1;
            if !self.is_acked(pos) {
                return Some((pos, self.items[pos as usize]));
            }
        }
        None
    }

    fn ack(&mut self, pos: u64) -> bool {
        if pos >= self.published {
            return false;
        }
        self.acked.insert(pos);
        true
    }

    fn ack_up_to(&mut self, up_to: u64) -> bool {
        if up_to > self.published {
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
        self.ack_floor() >= self.published
    }

    fn read_pos(&self) -> u64 {
        self.read_pos
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
            partition: "queue-operations-fuzz-test".into(),
            items_per_section,
            compression: None,
            codec_config: ((0usize..).into(), ()),
            page_cache: CacheRef::from_pooler(&context, page_size, page_cache_size),
            write_buffer,
            // The queue is initialized once on an empty partition and never reopened,
            // so replay never reads anything: fuzzing this knob adds no coverage.
            replay_buffer: NZUsize!(1024),
        };

        let (mut queue, mut reader) = Queue::<_, Vec<u8>>::init(context.child("storage"), cfg)
            .await
            .unwrap();
        let mut reference = ReferenceQueue::new();

        for op in input.operations.iter() {
            queue = match op {
                QueueOperation::Enqueue { value } => {
                    let (queue, pos) = queue.enqueue(vec![*value]).await.unwrap();
                    let ref_pos = reference.append(*value);
                    reference.publish();
                    assert_eq!(pos, ref_pos, "enqueue position mismatch");
                    queue
                }

                QueueOperation::Append { value } => {
                    let (queue, pos) = queue.append(vec![*value]).await.unwrap();
                    let ref_pos = reference.append(*value);
                    assert_eq!(pos, ref_pos, "append position mismatch");
                    queue
                }

                QueueOperation::Commit => {
                    let queue = queue.commit().await.unwrap();
                    reference.publish();
                    queue
                }

                QueueOperation::Dequeue => {
                    let result = reader.try_recv().await.unwrap();
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
                    queue
                }

                QueueOperation::Ack { pos_offset } => {
                    // Map the offset with slack past size so positions past the published items
                    // stay reachable.
                    let size = reference.size();
                    let published = reference.published;
                    let pos = (*pos_offset as u64) % (size + size / 4 + 1);

                    // Snapshot ack state to pin that a rejected ack is a no-op
                    let floor_before = reader.ack_floor();
                    let read_before = reader.read_position();

                    let result = reader.ack(pos);
                    let ref_result = reference.ack(pos);

                    assert_eq!(
                        result.is_ok(),
                        ref_result,
                        "ack result mismatch for pos {pos}"
                    );
                    if let Err(err) = result {
                        // Unpublished positions must fail with the documented error
                        assert!(
                            matches!(
                                err,
                                Error::PositionOutOfRange(p, s) if p == pos && s == published
                            ),
                            "unexpected ack error for pos {pos} published {published}: {err:?}"
                        );

                        // A rejected ack must not mutate ack state
                        assert_eq!(reader.ack_floor(), floor_before, "rejected ack moved floor");
                        assert_eq!(
                            reader.read_position(),
                            read_before,
                            "rejected ack moved read position"
                        );
                        assert!(!reader.is_acked(pos), "rejected ack marked pos {pos} acked");
                    }
                    queue
                }

                QueueOperation::AckUpTo { pos_offset } => {
                    // Map the offset with slack past size + 1 so values past the published items
                    // stay reachable.
                    let size = reference.size();
                    let published = reference.published;
                    let up_to = (*pos_offset as u64) % (size + size / 4 + 2);

                    // Snapshot ack state to pin that a rejected ack_up_to is a no-op
                    let floor_before = reader.ack_floor();
                    let read_before = reader.read_position();

                    let result = reader.ack_up_to(up_to);
                    let ref_result = reference.ack_up_to(up_to);

                    assert_eq!(
                        result.is_ok(),
                        ref_result,
                        "ack_up_to result mismatch for up_to {up_to}"
                    );
                    if let Err(err) = result {
                        // Values past the published items must fail with the documented error
                        assert!(
                            matches!(
                                err,
                                Error::PositionOutOfRange(p, s) if p == up_to && s == published
                            ),
                            "unexpected ack_up_to({up_to}) error with published {published}: {err:?}"
                        );

                        // A rejected ack_up_to must not mutate ack state
                        assert_eq!(
                            reader.ack_floor(),
                            floor_before,
                            "rejected ack_up_to moved floor"
                        );
                        assert_eq!(
                            reader.read_position(),
                            read_before,
                            "rejected ack_up_to moved read position"
                        );
                    }
                    queue
                }

                QueueOperation::Reset => {
                    reader.reset();
                    reference.reset();
                    queue
                }

                QueueOperation::Sync => {
                    let queue = queue.sync().await.unwrap();
                    reference.publish();
                    queue
                }
            };

            // Verify invariants after each operation
            assert_eq!(queue.size(), reference.size(), "size mismatch after {op:?}");
            assert_eq!(
                reader.ack_floor(),
                reference.ack_floor(),
                "ack_floor mismatch after {op:?}"
            );
            assert_eq!(
                reader.read_position(),
                reference.read_pos(),
                "read_position mismatch after {op:?}"
            );
            assert_eq!(
                reader.is_empty(),
                reference.is_empty(),
                "is_empty mismatch after {op:?}"
            );

            // Verify is_acked consistency for a sample of positions, including unpublished ones
            for pos in 0..queue.size().min(20) {
                assert_eq!(
                    reader.is_acked(pos),
                    reference.is_acked(pos),
                    "is_acked mismatch for pos {pos} after {op:?}"
                );
            }
        }
    });
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
