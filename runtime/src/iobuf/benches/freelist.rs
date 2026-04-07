use commonware_runtime::benchmarks::iobuf::{FreelistBench, FreelistEntry};
use commonware_utils::sync::Mutex;
use criterion::Criterion;
use crossbeam_queue::ArrayQueue;
use std::{
    hint::{black_box, spin_loop},
    sync::{Arc, Barrier},
    thread,
    time::{Duration, Instant},
};

const MIN_BENCH_THREADS: usize = 2;
const MAX_BENCH_THREADS: usize = 8;
const SLOTS: &[usize] = &[16, 64, 512];
const BATCH_SIZES: &[usize] = &[1, 2, 4, 8, 16, 32];

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

#[derive(Clone, Copy)]
enum Pattern {
    Lockstep,
    Staggered,
}

impl Pattern {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Lockstep => "lockstep",
            Self::Staggered => "staggered",
        }
    }
}

#[derive(Clone, Copy)]
enum Threading {
    Single,
    Multi { threads: usize, pattern: Pattern },
}

impl Threading {
    const fn threads(self) -> usize {
        match self {
            Self::Single => 1,
            Self::Multi { threads, .. } => threads,
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
    let threads = std::thread::available_parallelism().map_or(MIN_BENCH_THREADS, |n| {
        n.get().clamp(MIN_BENCH_THREADS, MAX_BENCH_THREADS)
    });
    let threadings: &[Threading] = &[
        Threading::Single,
        Threading::Multi {
            threads,
            pattern: Pattern::Lockstep,
        },
        Threading::Multi {
            threads,
            pattern: Pattern::Staggered,
        },
    ];

    for implementation in [
        Implementation::Freelist,
        Implementation::MutexVec,
        Implementation::ArrayQueue,
    ] {
        for &slots in SLOTS {
            for &threading in threadings {
                for &batch in BATCH_SIZES {
                    if batch > slots / threading.threads() {
                        continue;
                    }

                    match implementation {
                        Implementation::Freelist => bench_case::<FreelistBatchFreelist>(
                            c,
                            implementation,
                            slots,
                            threading,
                            batch,
                        ),
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

fn measure<T>(
    iters: u64,
    threading: Threading,
    setup: impl Fn() -> T + Sync,
    step: impl Fn(&mut T) + Sync,
) -> Duration {
    let Threading::Multi { threads, pattern } = threading else {
        let mut state = setup();
        let start = Instant::now();
        for _ in 0..iters {
            step(&mut state);
        }
        return start.elapsed();
    };

    let start = thread::scope(|scope| {
        let ready = Arc::new(Barrier::new(threads + 1));
        let launch = Arc::new(Barrier::new(threads + 1));

        for thread_id in 0..threads {
            let ready = ready.clone();
            let launch = launch.clone();
            let setup = &setup;
            let step = &step;
            scope.spawn(move || {
                let mut state = setup();
                ready.wait();
                launch.wait();
                for iter in 0..iters {
                    step(&mut state);

                    if matches!(pattern, Pattern::Staggered) {
                        let spins = (iter as usize).wrapping_add(1).wrapping_mul(
                            thread_id
                                .wrapping_mul(MAX_BENCH_THREADS - 1)
                                .wrapping_add(1),
                        ) & 0xF;

                        for _ in 0..spins {
                            spin_loop();
                        }
                    }
                }
            });
        }

        ready.wait();
        let start = Instant::now();
        launch.wait();
        start
    });

    start.elapsed()
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

struct FreelistBatchFreelist(FreelistBench);

impl BatchFreelist for FreelistBatchFreelist {
    type Entry = FreelistEntry;

    fn with_capacity(capacity: usize) -> Self {
        Self(FreelistBench::with_capacity(capacity))
    }

    fn take_batch(&self, out: &mut Vec<FreelistEntry>, max: usize) {
        self.0.take_batch(out, max);
    }

    fn put_batch(&self, entries: &mut Vec<FreelistEntry>) {
        self.0.put_batch(entries);
    }
}
