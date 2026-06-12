#![no_main]

use arbitrary::{Arbitrary, Result, Unstructured};
use commonware_runtime::{buffer::paged::CacheRef, deterministic, Runner, Supervisor as _};
use commonware_storage::queue::{shared, Config};
use commonware_utils::FuzzRng;
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
enum SharedOperation {
    /// Enqueue a new item via the writer (append + commit).
    Enqueue { value: u8 },
    /// Enqueue a batch of items with a single commit.
    EnqueueBulk { values: Vec<u8> },
    /// Append a new item without committing.
    Append { value: u8 },
    /// Commit appended items to disk.
    Commit,
    /// Sync (commit and prune).
    Sync,
    /// Receive the next unacked item (waits only when an item is available).
    Recv,
    /// Try to receive the next unacked item without waiting.
    TryRecv,
    /// Acknowledge a specific position.
    Ack { pos_offset: u8 },
    /// Acknowledge all items up to a position.
    AckUpTo { pos_offset: u8 },
    /// Reset the read position.
    Reset,
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
    operations: Vec<SharedOperation>,
    raw_bytes: Vec<u8>,
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

    fn read_pos(&self) -> u64 {
        self.read_pos
    }
}

fn fuzz(input: FuzzInput) {
    let cfg = deterministic::Config::new().with_rng(Box::new(FuzzRng::new(input.raw_bytes)));
    let runner = deterministic::Runner::new(cfg);

    let page_size = NonZeroU16::new(input.page_size).unwrap();
    let page_cache_size = NonZeroUsize::new(input.page_cache_size).unwrap();
    let items_per_section = NonZeroU64::new(input.items_per_section).unwrap();
    let write_buffer = NonZeroUsize::new(input.write_buffer).unwrap();

    runner.start(|context| async move {
        let cfg = Config {
            partition: "queue-shared-fuzz-test".into(),
            items_per_section,
            compression: None,
            codec_config: ((0usize..).into(), ()),
            page_cache: CacheRef::from_pooler(&context, page_size, page_cache_size),
            write_buffer,
        };

        let (writer, mut reader) = shared::init::<_, Vec<u8>>(context.child("storage"), cfg)
            .await
            .unwrap();
        // Use a cloned writer for appends to exercise the multi-writer path.
        let appender = writer.clone();
        let mut reference = ReferenceQueue::new();

        for op in input.operations.iter() {
            match op {
                SharedOperation::Enqueue { value } => {
                    let pos = writer.enqueue(vec![*value]).await.unwrap();
                    let ref_pos = reference.enqueue(*value);
                    assert_eq!(pos, ref_pos, "enqueue position mismatch");
                }

                SharedOperation::EnqueueBulk { values } => {
                    let range = writer
                        .enqueue_bulk(values.iter().map(|v| vec![*v]))
                        .await
                        .unwrap();
                    let start = reference.size();
                    for value in values {
                        reference.enqueue(*value);
                    }
                    assert_eq!(
                        range,
                        start..reference.size(),
                        "enqueue_bulk range mismatch"
                    );
                }

                SharedOperation::Append { value } => {
                    let pos = appender.append(vec![*value]).await.unwrap();
                    let ref_pos = reference.enqueue(*value);
                    assert_eq!(pos, ref_pos, "append position mismatch");
                }

                SharedOperation::Commit => {
                    writer.commit().await.unwrap();
                }

                SharedOperation::Sync => {
                    writer.sync().await.unwrap();
                }

                SharedOperation::Recv => {
                    // Only wait on recv when the reference model guarantees an
                    // item is available (recv blocks on an empty queue).
                    let ref_result = reference.dequeue();
                    if let Some((ref_pos, ref_item)) = ref_result {
                        let (pos, item) = reader.recv().await.unwrap().unwrap();
                        assert_eq!(pos, ref_pos, "recv position mismatch");
                        assert_eq!(item, vec![ref_item], "recv value mismatch");
                    } else {
                        let result = reader.try_recv().await.unwrap();
                        assert!(result.is_none(), "try_recv should return None");
                    }
                }

                SharedOperation::TryRecv => {
                    let result = reader.try_recv().await.unwrap();
                    let ref_result = reference.dequeue();

                    match (result, ref_result) {
                        (Some((pos, item)), Some((ref_pos, ref_item))) => {
                            assert_eq!(pos, ref_pos, "try_recv position mismatch");
                            assert_eq!(item, vec![ref_item], "try_recv value mismatch");
                        }
                        (None, None) => {}
                        (actual, expected) => {
                            panic!("try_recv mismatch: got {actual:?}, expected {expected:?}");
                        }
                    }
                }

                SharedOperation::Ack { pos_offset } => {
                    let size = writer.size().await;
                    if size == 0 {
                        continue;
                    }
                    // Map offset to a valid position range
                    let pos = (*pos_offset as u64) % size;

                    let result = reader.ack(pos).await;
                    let ref_result = reference.ack(pos);

                    assert_eq!(
                        result.is_ok(),
                        ref_result,
                        "ack result mismatch for pos {pos}"
                    );
                }

                SharedOperation::AckUpTo { pos_offset } => {
                    let size = writer.size().await;
                    // Map offset to valid range [0, size]
                    let up_to = (*pos_offset as u64) % (size + 1);

                    let result = reader.ack_up_to(up_to).await;
                    let ref_result = reference.ack_up_to(up_to);

                    assert_eq!(
                        result.is_ok(),
                        ref_result,
                        "ack_up_to result mismatch for up_to {up_to}"
                    );
                }

                SharedOperation::Reset => {
                    reader.reset().await;
                    reference.reset();
                }
            }

            // Verify invariants after each operation
            assert_eq!(
                writer.size().await,
                reference.size(),
                "size mismatch after {op:?}"
            );
            assert_eq!(
                reader.ack_floor().await,
                reference.ack_floor(),
                "ack_floor mismatch after {op:?}"
            );
            assert_eq!(
                reader.read_position().await,
                reference.read_pos(),
                "read_position mismatch after {op:?}"
            );
            assert_eq!(
                reader.is_empty().await,
                reference.is_empty(),
                "is_empty mismatch after {op:?}"
            );
        }

        // Drop all writers and drain remaining items: recv must return all
        // unacked items and then None (writer-dropped path).
        drop(writer);
        drop(appender);
        loop {
            let result = reader.recv().await.unwrap();
            let ref_result = reference.dequeue();
            match (result, ref_result) {
                (Some((pos, item)), Some((ref_pos, ref_item))) => {
                    assert_eq!(pos, ref_pos, "drain position mismatch");
                    assert_eq!(item, vec![ref_item], "drain value mismatch");
                }
                (None, None) => break,
                (actual, expected) => {
                    panic!("drain mismatch: got {actual:?}, expected {expected:?}");
                }
            }
        }
    });
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
