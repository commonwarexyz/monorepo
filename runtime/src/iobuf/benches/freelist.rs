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
//! - `Mutex<Vec<u32>>`: a simple locked batched baseline
//! - [`ArrayQueue<u32>`]: a bounded lock-free queue baseline
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
use std::{hint::black_box, sync::Arc};

const SLOTS: &[usize] = &[16, 64, 512];
const BATCH_SIZES: &[usize] = &[1, 2, 4, 8, 16, 32];
const BENCH_BUFFER_CAPACITY: usize = 64;
const BENCH_BUFFER_ALIGNMENT: usize = 64;
const BENCH_PREFERRED_WORDS: usize = 8;

#[derive(Clone, Copy)]
enum Implementation {
    Freelist,
    MutexVec,
    ArrayQueue,
}

impl Implementation {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Freelist => "freelist",
            Self::MutexVec => "mutex_vec",
            Self::ArrayQueue => "array_queue",
        }
    }
}

trait BatchFreelist: Send + Sync + 'static {
    type Entry: Send + 'static;

    fn with_capacity(capacity: usize) -> Self;
    fn take_batch(&self, out: &mut Vec<Self::Entry>, max: usize);
    fn put_batch(&self, entries: &mut Vec<Self::Entry>);
}

struct WorkerState<S: BatchFreelist> {
    shared: Arc<S>,
    held: Vec<S::Entry>,
    batch: usize,
}

impl<S: BatchFreelist> WorkerState<S> {
    fn new(shared: Arc<S>, batch: usize) -> Self {
        let mut held = Vec::with_capacity(batch);
        fill_batch(shared.as_ref(), &mut held, batch);
        Self {
            shared,
            held,
            batch,
        }
    }

    fn step(&mut self) {
        self.shared.put_batch(black_box(&mut self.held));
        fill_batch(self.shared.as_ref(), &mut self.held, self.batch);
    }
}

pub fn bench(c: &mut Criterion) {
    let threadings = Threading::standard();

    for implementation in [
        Implementation::Freelist,
        Implementation::MutexVec,
        Implementation::ArrayQueue,
    ] {
        for &slots in SLOTS {
            for &threading in &threadings {
                for &batch in BATCH_SIZES {
                    if batch > slots / threading.threads() {
                        continue;
                    }

                    match implementation {
                        Implementation::Freelist => {
                            bench_case::<Freelist>(c, implementation, slots, threading, batch)
                        }
                        Implementation::MutexVec => bench_case::<MutexVecBatchFreelist>(
                            c,
                            implementation,
                            slots,
                            threading,
                            batch,
                        ),
                        Implementation::ArrayQueue => bench_case::<ArrayQueueBatchFreelist>(
                            c,
                            implementation,
                            slots,
                            threading,
                            batch,
                        ),
                    }
                }
            }
        }
    }
}

fn bench_case<S: BatchFreelist>(
    c: &mut Criterion,
    implementation: Implementation,
    slots: usize,
    threading: Threading,
    batch: usize,
) {
    let name = bench_name(implementation, slots, threading, batch);
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

fn fill_batch<S: BatchFreelist>(shared: &S, out: &mut Vec<S::Entry>, target: usize) {
    out.clear();
    while out.len() < target {
        let before = out.len();
        shared.take_batch(out, target);
        assert!(
            out.len() > before,
            "freelist must provide enough slots for the configured batch"
        );
    }
}

fn bench_name(
    implementation: Implementation,
    slots: usize,
    threading: Threading,
    batch: usize,
) -> String {
    let threads = threading.threads();
    let mut name = format!(
        "{}/impl={} slots={slots} threads={threads} batch={batch}",
        module_path!(),
        implementation.as_str(),
    );
    if let Threading::Multi { pattern, .. } = threading {
        name.push_str(&format!(" pattern={}", pattern.as_str()));
    }
    name
}

struct MutexVecBatchFreelist(Mutex<Vec<u32>>);

impl BatchFreelist for MutexVecBatchFreelist {
    type Entry = u32;

    fn with_capacity(capacity: usize) -> Self {
        let slots = (0..capacity as u32).collect();
        Self(Mutex::new(slots))
    }

    fn take_batch(&self, out: &mut Vec<u32>, max: usize) {
        let mut slots = self.0.lock();
        let count = max.saturating_sub(out.len()).min(slots.len());
        let split = slots.len() - count;
        out.extend_from_slice(&slots[split..]);
        slots.truncate(split);
    }

    fn put_batch(&self, slots: &mut Vec<u32>) {
        let mut inner = self.0.lock();
        inner.extend(slots.drain(..));
    }
}

struct ArrayQueueBatchFreelist(ArrayQueue<u32>);

impl BatchFreelist for ArrayQueueBatchFreelist {
    type Entry = u32;

    fn with_capacity(capacity: usize) -> Self {
        let queue = ArrayQueue::new(capacity);
        for slot in 0..capacity as u32 {
            queue.push(slot).expect("array queue prefill must fit");
        }
        Self(queue)
    }

    fn take_batch(&self, out: &mut Vec<u32>, max: usize) {
        while out.len() < max {
            let Some(slot) = self.0.pop() else {
                break;
            };
            out.push(slot);
        }
    }

    fn put_batch(&self, slots: &mut Vec<u32>) {
        for slot in slots.drain(..) {
            self.0
                .push(slot)
                .expect("array queue push must fit in steady state");
        }
    }
}

struct FreelistEntry {
    slot: u32,
    buffer: AlignedBuffer,
}

// SAFETY: this entry uniquely owns its buffer and slot id, so moving it across
// threads is equivalent to moving a uniquely-owned heap allocation.
unsafe impl Send for FreelistEntry {}

impl BatchFreelist for Freelist {
    type Entry = FreelistEntry;

    fn with_capacity(capacity: usize) -> Self {
        let freelist = Self::new(capacity, BENCH_PREFERRED_WORDS);
        for slot in 0..capacity {
            freelist.put(
                slot as u32,
                AlignedBuffer::new(BENCH_BUFFER_CAPACITY, BENCH_BUFFER_ALIGNMENT),
            );
        }
        freelist
    }

    fn take_batch(&self, out: &mut Vec<FreelistEntry>, max: usize) {
        let remaining = max.saturating_sub(out.len());
        if remaining == 0 {
            return;
        }

        Self::take_batch(self, remaining, |slot, buffer| {
            out.push(FreelistEntry { slot, buffer });
        });
    }

    fn put_batch(&self, entries: &mut Vec<FreelistEntry>) {
        Self::put_batch(
            self,
            entries.drain(..).map(|entry| (entry.slot, entry.buffer)),
        );
    }
}
