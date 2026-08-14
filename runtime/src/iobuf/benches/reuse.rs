//! End-to-end buffer reuse.
//!
//! The batch rows create and return sparse buffers before timing, then reuse
//! them with thread-local caching disabled. The TLS rows use a working set one
//! larger than the local cache, forcing one batched global refill and spill per
//! iteration while retaining the surrounding local-cache work.

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

// Capacity 4096 leaves ample global room for eight workers while parallelism 8
// gives each worker an independent freelist stripe in the uncontended case.
const SIZE: usize = 1024;
const CAPACITY: u32 = 4096;
const PARALLELISM: usize = 8;
const THREADS: usize = 8;
const BATCHES: &[usize] = &[1, 8];
const TLS_CACHE_CAPACITIES: &[usize] = &[16, 256];

struct State {
    pool: BufferPool,
    buffers: Vec<IoBufMut>,
    batch: usize,
}

impl State {
    fn new(pool: BufferPool, grown: &Barrier, batch: usize) -> Self {
        let mut buffers = Vec::with_capacity(batch);
        for _ in 0..batch {
            buffers.push(
                pool.try_alloc(SIZE)
                    .expect("lazy-growth pool exhausted during setup"),
            );
        }

        // Keep every new buffer checked out until all workers have created
        // their batch, so setup cannot reuse an owner created by another worker.
        grown.wait();
        buffers.clear();

        Self {
            pool,
            buffers,
            batch,
        }
    }

    #[inline]
    fn step(&mut self) {
        for _ in 0..self.batch {
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
    for &batch in BATCHES {
        let name = format!(
            "{}/size={SIZE} capacity={CAPACITY} threads={THREADS} parallelism={PARALLELISM} batch={batch}",
            module_path!(),
        );

        c.bench_function(&name, |b| {
            b.iter_custom(|iters| measure(iters, build_pool(), batch));
        });
    }

    for &cache in TLS_CACHE_CAPACITIES {
        // Exceeding the cache by one forces one refill and one spill each step.
        let working_set = cache + 1;
        let name = format!(
            "{}/size={SIZE} capacity={CAPACITY} threads={THREADS} parallelism={PARALLELISM} mode=tls cache={cache} working_set={working_set}",
            module_path!(),
        );
        c.bench_function(&name, |b| {
            b.iter_custom(|iters| measure(iters, build_tls_pool(cache), working_set));
        });
    }
}

fn measure(iters: u64, pool: BufferPool, batch: usize) -> Duration {
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
                let mut state = State::new(pool, &grown, batch);
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

fn build_tls_pool(cache: usize) -> BufferPool {
    let cfg = BufferPoolConfig::for_network()
        .with_pool_min_size(0)
        .with_size_class_range(NZUsize!(SIZE), NZUsize!(SIZE), NZU32!(CAPACITY))
        .with_parallelism(NZUsize!(PARALLELISM))
        .with_prefill(true)
        .with_max_thread_cache_capacity(NZUsize!(cache));

    start_pool(cfg)
}
