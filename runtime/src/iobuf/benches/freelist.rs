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
//! [`AlignedBuffer`]. That keeps the shape close to the real pooled freelist
//! while avoiding unrelated `BufferPool` logic.

use super::utils::{measure, Threading};
use commonware_runtime::iobuf::bench::{AlignedBuffer, Freelist};
use commonware_utils::sync::Mutex;
use criterion::Criterion;
use crossbeam_queue::ArrayQueue;
use std::{hint::black_box, num::NonZeroUsize, sync::Arc};

const SLOTS: &[usize] = &[16, 64, 512];
const BATCH_SIZES: &[usize] = &[1, 2, 4, 8, 16, 32];

const BENCH_BUFFER_CAPACITY: usize = 256;
const BENCH_BUFFER_ALIGNMENT: usize = 64;
const BENCH_MIN_STRIPES: usize = 8;

#[derive(Debug)]
struct Entry {
    slot: u32,
    buffer: AlignedBuffer,
}

// SAFETY: this entry uniquely owns its buffer and slot id, so moving it across
// threads is equivalent to moving a uniquely-owned heap allocation.
unsafe impl Send for Entry {}

trait FreelistImplementation: Send + Sync {
    fn as_str() -> &'static str;
    fn with_capacity(capacity: usize) -> Self;
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
            let shared = Arc::new(S::with_capacity(slots));
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

struct MutexVec(Mutex<Vec<Entry>>);

impl FreelistImplementation for MutexVec {
    fn as_str() -> &'static str {
        "mutex_vec"
    }

    fn with_capacity(capacity: usize) -> Self {
        let slots = (0..capacity)
            .map(|slot| Entry {
                slot: slot as u32,
                buffer: AlignedBuffer::new(BENCH_BUFFER_CAPACITY, BENCH_BUFFER_ALIGNMENT),
            })
            .collect();
        Self(Mutex::new(slots))
    }

    #[inline]
    fn take_batch(&self, out: &mut Vec<Entry>, max: usize) {
        let mut slots = self.0.lock();
        let count = max.min(slots.len());
        let split = slots.len() - count;
        out.extend(slots.drain(split..));
    }

    #[inline]
    fn put_batch(&self, slots: &mut Vec<Entry>) {
        let mut inner = self.0.lock();
        inner.extend(slots.drain(..));
    }
}

struct ArrayQueueFreelist(ArrayQueue<Entry>);

impl FreelistImplementation for ArrayQueueFreelist {
    fn as_str() -> &'static str {
        "array_queue"
    }

    fn with_capacity(capacity: usize) -> Self {
        let queue = ArrayQueue::new(capacity);
        for slot in 0..capacity {
            queue
                .push(Entry {
                    slot: slot as u32,
                    buffer: AlignedBuffer::new(BENCH_BUFFER_CAPACITY, BENCH_BUFFER_ALIGNMENT),
                })
                .expect("array queue prefill must fit");
        }
        Self(queue)
    }

    #[inline]
    fn take_batch(&self, out: &mut Vec<Entry>, mut max: usize) {
        while max > 0 {
            let Some(entry) = self.0.pop() else {
                break;
            };
            out.push(entry);
            max -= 1;
        }
    }

    #[inline]
    fn put_batch(&self, slots: &mut Vec<Entry>) {
        for entry in slots.drain(..) {
            self.0
                .push(entry)
                .expect("array queue push must fit in steady state");
        }
    }
}

impl FreelistImplementation for Freelist {
    fn as_str() -> &'static str {
        "freelist"
    }

    fn with_capacity(capacity: usize) -> Self {
        let freelist = Self::new(
            NonZeroUsize::new(capacity).expect("bench capacity must be non-zero"),
            NonZeroUsize::new(BENCH_MIN_STRIPES.min(capacity).max(1))
                .expect("bench minimum stripe count must be non-zero"),
        );
        for slot in 0..capacity {
            freelist.put(
                slot as u32,
                AlignedBuffer::new(BENCH_BUFFER_CAPACITY, BENCH_BUFFER_ALIGNMENT),
            );
        }
        freelist
    }

    #[inline]
    fn take_batch(&self, out: &mut Vec<Entry>, max: usize) {
        self.take_batch(max, |slot, buffer| {
            out.push(Entry { slot, buffer });
        });
    }

    #[inline]
    fn put_batch(&self, entries: &mut Vec<Entry>) {
        self.put_batch(entries.drain(..).map(|entry| (entry.slot, entry.buffer)));
    }
}
