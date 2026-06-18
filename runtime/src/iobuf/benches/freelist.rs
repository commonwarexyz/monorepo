//! Focused microbenchmarks for the shared global freelist.
//!
//! `BufferPool` keeps free pooled buffers in a global freelist that is shared
//! across threads. Threads hit this structure when they refill or spill their
//! thread-local caches.
//!
//! This module benchmarks that global freelist directly and compares three
//! implementations behind the same batch-oriented slot-id interface:
//!
//! - [`Freelist`]: a striped atomic bitmap freelist
//! - `Mutex<Vec<_>>`: a simple locked batched baseline
//! - `ArrayQueue<_>`: a bounded lock-free queue baseline
//!
//! Each worker repeatedly removes `batch` entries, then returns the same
//! entries, keeping occupancy stable throughout the run. This matches the
//! steady-state shape of multi-threaded freelist reuse.
//!
//! The benchmarked entries are synthetic slot ids paired with a small
//! [`PooledBuffer`]. That keeps the shape close to the real pooled freelist
//! while avoiding unrelated `BufferPool` logic.

use super::utils::{measure, Threading};
use commonware_runtime::iobuf::bench::{Freelist, PooledBuffer, PooledSlot};
use commonware_utils::sync::Mutex;
use criterion::Criterion;
use crossbeam_queue::ArrayQueue;
use crossbeam_utils::CachePadded;
use std::{
    alloc::Layout,
    cell::UnsafeCell,
    hint::black_box,
    num::{NonZeroU32, NonZeroUsize},
    ptr::NonNull,
    sync::Arc,
};

const SLOTS: &[usize] = &[16, 64, 512];
const BATCH_SIZES: &[usize] = &[1, 2, 4, 8, 16, 32];

const BENCH_BUFFER_CAPACITY: usize = 256;
const BENCH_BUFFER_ALIGNMENT: usize = 64;
const BENCH_LAYOUT: Layout =
    match Layout::from_size_align(BENCH_BUFFER_CAPACITY, BENCH_BUFFER_ALIGNMENT) {
        Ok(layout) => layout,
        Err(_) => panic!("valid bench layout"),
    };

#[derive(Debug)]
struct Entry {
    buffer: PooledBuffer,
}

impl Entry {
    fn new(slot: usize, slots: &[CachePadded<UnsafeCell<PooledSlot>>]) -> Self {
        let slot_ptr = slots[slot].get();
        let slot_ptr = NonNull::new(slot_ptr).expect("slot pointers are non-null");
        Self {
            // SAFETY: each benchmark slot is initialized once before the
            // entry is published to the baseline container.
            buffer: unsafe { PooledBuffer::new_in_slot(slot_ptr, BENCH_LAYOUT, false) },
        }
    }
}

fn new_slots(capacity: usize) -> Box<[CachePadded<UnsafeCell<PooledSlot>>]> {
    (0..capacity)
        .map(|slot| {
            CachePadded::new(UnsafeCell::new(PooledSlot::new(
                slot as u32,
                BENCH_BUFFER_CAPACITY,
                0,
                0,
            )))
        })
        .collect::<Vec<_>>()
        .into_boxed_slice()
}

trait FreelistImplementation: Send + Sync {
    fn as_str() -> &'static str;
    fn with_capacity(capacity: usize, parallelism: usize) -> Self;
    fn take_batch(&self, out: &mut Vec<Entry>, max: usize);
    fn put_batch(&self, entries: &mut Vec<Entry>);

    fn fill_batch(&self, out: &mut Vec<Entry>, target: usize) {
        out.clear();
        while out.len() < target {
            self.take_batch(out, target - out.len());
        }
    }
}

struct WorkerState<S: FreelistImplementation> {
    shared: Arc<S>,
    held: Vec<Entry>,
    batch: usize,
}

impl<S: FreelistImplementation> WorkerState<S> {
    fn new(shared: Arc<S>, batch: usize) -> Self {
        let mut held = Vec::with_capacity(batch);
        shared.fill_batch(&mut held, batch);
        Self {
            shared,
            held,
            batch,
        }
    }

    #[inline]
    fn step(&mut self) {
        self.shared.put_batch(black_box(&mut self.held));
        self.shared.fill_batch(&mut self.held, self.batch);
    }
}

impl<S: FreelistImplementation> Drop for WorkerState<S> {
    fn drop(&mut self) {
        self.shared.put_batch(&mut self.held);
    }
}

pub fn bench(c: &mut Criterion) {
    let threadings = Threading::standard();

    for &slots in SLOTS {
        for &threading in &threadings {
            for &batch in BATCH_SIZES {
                if batch > slots / threading.threads() {
                    continue;
                }

                bench_case::<Freelist>(c, slots, threading, batch);
                bench_case::<MutexVec>(c, slots, threading, batch);
                bench_case::<ArrayQueueFreelist>(c, slots, threading, batch);
            }
        }
    }
}

fn bench_case<S: FreelistImplementation>(
    c: &mut Criterion,
    slots: usize,
    threading: Threading,
    batch: usize,
) {
    let name = bench_name::<S>(slots, threading, batch);
    c.bench_function(&name, |b| {
        b.iter_custom(|iters| {
            let shared = Arc::new(S::with_capacity(slots, threading.threads()));
            measure(
                iters,
                threading,
                move || WorkerState::new(Arc::clone(&shared), batch),
                |state| state.step(),
            )
        })
    });
}

fn bench_name<S: FreelistImplementation>(
    slots: usize,
    threading: Threading,
    batch: usize,
) -> String {
    let threads = threading.threads();
    let mut name = format!(
        "{}/impl={} slots={slots} threads={threads} batch={batch}",
        module_path!(),
        S::as_str(),
    );
    if let Threading::Multi { pattern, .. } = threading {
        name.push_str(&format!(" pattern={}", pattern.as_str()));
    }
    name
}

struct MutexVec {
    _slots: Box<[CachePadded<UnsafeCell<PooledSlot>>]>,
    entries: Mutex<Vec<Entry>>,
}

// SAFETY: benchmark slot entries are mutated only while their corresponding
// `Entry` is exclusively owned by one worker or protected by the container.
unsafe impl Send for MutexVec {}
// SAFETY: shared access to entries is synchronized by the mutex.
unsafe impl Sync for MutexVec {}

impl FreelistImplementation for MutexVec {
    fn as_str() -> &'static str {
        "mutex_vec"
    }

    fn with_capacity(capacity: usize, _parallelism: usize) -> Self {
        let slots = new_slots(capacity);
        let entries = (0..capacity).map(|slot| Entry::new(slot, &slots)).collect();
        Self {
            _slots: slots,
            entries: Mutex::new(entries),
        }
    }

    #[inline]
    fn take_batch(&self, out: &mut Vec<Entry>, max: usize) {
        let mut slots = self.entries.lock();
        let count = max.min(slots.len());
        let split = slots.len() - count;
        out.extend(slots.drain(split..));
    }

    #[inline]
    fn put_batch(&self, slots: &mut Vec<Entry>) {
        let mut inner = self.entries.lock();
        inner.extend(slots.drain(..));
    }
}

impl Drop for MutexVec {
    fn drop(&mut self) {
        for entry in self.entries.get_mut().drain(..) {
            // SAFETY: benchmark entries are allocated with `BENCH_LAYOUT`.
            unsafe { entry.buffer.deallocate(BENCH_LAYOUT) };
        }
    }
}

struct ArrayQueueFreelist {
    _slots: Box<[CachePadded<UnsafeCell<PooledSlot>>]>,
    queue: ArrayQueue<Entry>,
}

// SAFETY: benchmark slot entries are mutated only while their corresponding
// `Entry` is exclusively owned by one worker or protected by the queue.
unsafe impl Send for ArrayQueueFreelist {}
// SAFETY: shared access to entries is synchronized by `ArrayQueue`.
unsafe impl Sync for ArrayQueueFreelist {}

impl FreelistImplementation for ArrayQueueFreelist {
    fn as_str() -> &'static str {
        "array_queue"
    }

    fn with_capacity(capacity: usize, _parallelism: usize) -> Self {
        let slots = new_slots(capacity);
        let queue = ArrayQueue::new(capacity);
        for slot in 0..capacity {
            queue
                .push(Entry::new(slot, &slots))
                .expect("array queue prefill must fit");
        }
        Self {
            _slots: slots,
            queue,
        }
    }

    #[inline]
    fn take_batch(&self, out: &mut Vec<Entry>, mut max: usize) {
        while max > 0 {
            let Some(entry) = self.queue.pop() else {
                break;
            };
            out.push(entry);
            max -= 1;
        }
    }

    #[inline]
    fn put_batch(&self, slots: &mut Vec<Entry>) {
        for entry in slots.drain(..) {
            self.queue
                .push(entry)
                .expect("array queue push must fit in steady state");
        }
    }
}

impl Drop for ArrayQueueFreelist {
    fn drop(&mut self) {
        while let Some(entry) = self.queue.pop() {
            // SAFETY: benchmark entries are allocated with `BENCH_LAYOUT`.
            unsafe { entry.buffer.deallocate(BENCH_LAYOUT) };
        }
    }
}

impl FreelistImplementation for Freelist {
    fn as_str() -> &'static str {
        "freelist"
    }

    fn with_capacity(capacity: usize, parallelism: usize) -> Self {
        Self::new(
            NonZeroU32::new(u32::try_from(capacity).expect("bench capacity must fit in u32"))
                .expect("bench capacity must be non-zero"),
            NonZeroUsize::new(parallelism).expect("bench parallelism must be non-zero"),
            BENCH_LAYOUT,
            true,
        )
    }

    #[inline]
    fn take_batch(&self, out: &mut Vec<Entry>, max: usize) {
        if max == 1 {
            if let Some(buffer) = self.take() {
                out.push(Entry { buffer });
            }
            return;
        }

        self.take_batch(max, |buffer| {
            out.push(Entry { buffer });
        });
    }

    #[inline]
    fn put_batch(&self, entries: &mut Vec<Entry>) {
        if entries.len() == 1 {
            let entry = entries.pop().unwrap();
            self.put(entry.buffer);
            return;
        }
        // unique and each is returned exactly once; the drain iterator cannot panic.
        self.put_batch(entries.drain(..).map(|entry| entry.buffer));
    }
}
