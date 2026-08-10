//! End-to-end buffer reuse after partial lazy growth.
//!
//! Each worker creates and returns a sparse batch before timing starts, then
//! repeatedly allocates and returns that batch with thread-local caching
//! disabled. This isolates whether lazy slot placement improves later global
//! freelist access.

use super::utils::start_pool;
use commonware_runtime::{BufferPool, BufferPoolConfig, IoBufMut};
use commonware_utils::{NZU32, NZUsize};
use criterion::Criterion;
use std::{
    hint::black_box,
    sync::{Arc, Barrier},
    thread,
    time::{Duration, Instant},
};

// Capacity 4096 yields 64 bitmap words. Sequential creation spreads the first
// 64 slots across all words, while probe-affine creation gives each worker's
// eight slots to its distinct home word. Any eight consecutive probe ids have
// distinct home words, so the fixture is independent of the global id phase.
const SIZE: usize = 1024;
const CAPACITY: u32 = 4096;
const PARALLELISM: usize = 8;
const THREADS: usize = 8;
const BATCH: usize = 8;

struct State {
    pool: BufferPool,
    buffers: Vec<IoBufMut>,
}

impl State {
    fn new(pool: BufferPool, grown: &Barrier) -> Self {
        let mut buffers = Vec::with_capacity(BATCH);
        for _ in 0..BATCH {
            buffers.push(
                pool.try_alloc(SIZE)
                    .expect("lazy-growth pool exhausted during setup"),
            );
        }

        // Keep every new buffer checked out until all workers have created
        // their batch, so setup cannot reuse a slot created by another worker.
        grown.wait();
        buffers.clear();

        Self { pool, buffers }
    }

    #[inline]
    fn step(&mut self) {
        for _ in 0..BATCH {
            self.buffers.push(
                self.pool
                    .try_alloc(SIZE)
                    .expect("lazy-growth pool exhausted during reuse"),
            );
        }
        black_box(self.buffers.as_slice());
        self.buffers.clear();
    }
}

pub fn bench(c: &mut Criterion) {
    let created = THREADS * BATCH;
    let name = format!(
        "{}/size={SIZE} capacity={CAPACITY} created={created} threads={THREADS} parallelism={PARALLELISM} batch={BATCH}",
        module_path!(),
    );

    c.bench_function(&name, |b| {
        b.iter_custom(|iters| measure(iters, build_pool()));
    });
}

fn measure(iters: u64, pool: BufferPool) -> Duration {
    thread::scope(|scope| {
        let grown = Arc::new(Barrier::new(THREADS));
        let ready = Arc::new(Barrier::new(THREADS + 1));
        let launch = Arc::new(Barrier::new(THREADS + 1));
        let finish = Arc::new(Barrier::new(THREADS + 1));
        let teardown = Arc::new(Barrier::new(THREADS + 1));

        for _ in 0..THREADS {
            let pool = pool.clone();
            let grown = Arc::clone(&grown);
            let ready = Arc::clone(&ready);
            let launch = Arc::clone(&launch);
            let finish = Arc::clone(&finish);
            let teardown = Arc::clone(&teardown);
            scope.spawn(move || {
                let mut state = State::new(pool, &grown);
                ready.wait();
                launch.wait();

                for _ in 0..iters {
                    state.step();
                }

                finish.wait();
                teardown.wait();
            });
        }

        ready.wait();
        let start = Instant::now();
        launch.wait();
        finish.wait();
        let elapsed = start.elapsed();

        // Keep worker destruction and thread joins outside the reported time.
        teardown.wait();
        elapsed
    })
}

fn build_pool() -> BufferPool {
    let cfg = BufferPoolConfig::for_network()
        .with_pool_min_size(0)
        .with_size_class_range(NZUsize!(SIZE), NZUsize!(SIZE), NZU32!(CAPACITY))
        .with_parallelism(NZUsize!(PARALLELISM))
        .with_thread_cache_disabled();

    start_pool(cfg)
}
