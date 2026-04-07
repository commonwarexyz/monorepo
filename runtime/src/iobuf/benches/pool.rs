use commonware_runtime::{
    tokio, BufferPool, BufferPoolConfig, BufferPoolThreadCache, BufferPooler, IoBufMut, Runner as _,
};
use commonware_utils::NZUsize;
use criterion::Criterion;
use std::{
    hint::{black_box, spin_loop},
    num::NonZeroUsize,
    sync::{Arc, Barrier},
    thread,
    time::{Duration, Instant},
};

const MIN_BENCH_THREADS: usize = 2;
const MAX_BENCH_THREADS: usize = 8;
const SIZES: &[usize] = &[256, 1024, 4096, 65536, 1024 * 1024, 8 * 1024 * 1024];

const GLOBAL_FREELIST_SIZES: &[usize] = &[1024, 4096, 65536];
const GLOBAL_FREELIST_SLOTS: &[usize] = &[16, 64, 512];

#[derive(Clone, Copy)]
enum Metric {
    Raw,
    Adjusted,
}

impl Metric {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Raw => "raw",
            Self::Adjusted => "adjusted",
        }
    }
}

#[derive(Clone, Copy)]
enum Mode {
    Direct,
    Pool,
}

impl Mode {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Pool => "pool",
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

pub fn bench(c: &mut Criterion) {
    let page_size = page_size();
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

    for &size in SIZES {
        let pool = build_pool(size, threads);
        let alignment = pool.config().alignment.get();

        for &threading in threadings {
            for metric in [Metric::Raw, Metric::Adjusted] {
                bench_case(
                    c,
                    Mode::Direct,
                    size,
                    threading,
                    metric,
                    || {
                        let mut buf =
                            IoBufMut::with_alignment(size, NonZeroUsize::new(alignment).unwrap());
                        touch_pages(buf.as_mut_ptr(), size, page_size);
                        buf
                    },
                    page_size,
                );
                bench_case(
                    c,
                    Mode::Pool,
                    size,
                    threading,
                    metric,
                    {
                        let pool = pool.clone();
                        move || {
                            let mut buf = pool
                                .try_alloc(size)
                                .expect("buffer pool exhausted during benchmark");
                            touch_pages(buf.as_mut_ptr(), size, page_size);
                            buf
                        }
                    },
                    page_size,
                );
            }
        }
    }

    bench_global_freelist(c, threadings);
}

fn bench_global_freelist(c: &mut Criterion, threadings: &[Threading]) {
    for &size in GLOBAL_FREELIST_SIZES {
        for &slots in GLOBAL_FREELIST_SLOTS {
            let pool = build_global_freelist_pool(size, slots);

            for &threading in threadings {
                bench_global_freelist_case(c, size, threading, slots, pool.clone());
            }
        }
    }
}

fn bench_case(
    c: &mut Criterion,
    mode: Mode,
    size: usize,
    threading: Threading,
    metric: Metric,
    work: impl Fn() -> IoBufMut + Sync,
    page_size: usize,
) {
    let name = bench_name(mode, metric, size, threading);
    c.bench_function(&name, |b| {
        b.iter_custom(|iters| {
            let full = measure(
                iters,
                threading,
                || {},
                |_| {
                    let buffer = black_box(work());
                    drop(buffer);
                },
            );

            if matches!(metric, Metric::Raw) {
                return full;
            }

            // Measure the cost of touching pages on a pre-allocated buffer.
            // Always single-threaded: each thread writes to private memory so
            // the per-iteration touch cost is the same regardless of thread
            // count, and single-threaded avoids wall-clock noise from thread
            // scheduling that would swamp the subtraction signal.
            let baseline = measure(iters, Threading::Single, &work, |buffer| {
                touch_pages(buffer.as_mut_ptr(), size, page_size)
            });

            full.saturating_sub(baseline)
        });
    });
}

fn bench_global_freelist_case(
    c: &mut Criterion,
    size: usize,
    threading: Threading,
    slots: usize,
    pool: BufferPool,
) {
    let name = global_freelist_bench_name(size, threading, slots);
    c.bench_function(&name, |b| {
        b.iter_custom(|iters| {
            let pool = pool.clone();
            measure(
                iters,
                threading,
                BufferPoolThreadCache::flush,
                |_| {
                    let buffer = pool
                        .try_alloc(size)
                        .expect("buffer pool exhausted during global freelist benchmark");
                    drop(black_box(buffer));
                },
            )
        })
    });
}

/// Measure `iters` repetitions of `step`.
///
/// `setup` runs per-worker before timing starts and returns state passed to
/// each `step` invocation. For multi-threaded runs, all workers synchronize
/// via a barrier after setup so timing captures concurrent execution only.
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
                        // Desynchronize threads so they don't all hit the
                        // allocator at once. This spreads access times apart
                        // without adding enough delay to dominate the
                        // measurement.
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

#[inline]
fn touch_pages(ptr: *mut u8, size: usize, page_size: usize) {
    if size == 0 {
        return;
    }

    // Force the allocation to back each page before timing the drop path.
    // Otherwise large aligned allocations can look artificially cheap when the
    // allocator hands out lazily materialized virtual memory (i.e. `mmap`).
    //
    // We vary the write offset within each page so that consecutive pages hit
    // different L1 cache sets. A naive page-strided write (offset 0 on every
    // page) maps all stores to the same set because the page size is an exact
    // multiple of the L1 set count times the cache line size, causing
    // pathological eviction.
    const CACHE_LINE: usize = 128;
    let lines_per_page = page_size / CACHE_LINE;

    // SAFETY: `ptr` is valid for writes to `size` bytes.
    unsafe {
        for (i, offset) in (0..size).step_by(page_size).enumerate() {
            let within_page = (i % lines_per_page) * CACHE_LINE;
            let pos = offset + within_page;
            ptr.add(pos.min(size - 1)).write_volatile(0);
        }
        ptr.add(size - 1).write_volatile(0);
    }
}

fn bench_name(mode: Mode, metric: Metric, size: usize, threading: Threading) -> String {
    let threads = threading.threads();
    let mut name = format!(
        "{}/mode={} size={size} threads={threads} metric={}",
        module_path!(),
        mode.as_str(),
        metric.as_str(),
    );
    if let Threading::Multi { pattern, .. } = threading {
        name.push_str(&format!(" pattern={}", pattern.as_str()));
    }
    name
}

fn global_freelist_bench_name(size: usize, threading: Threading, slots: usize) -> String {
    let threads = threading.threads();
    let mut name = format!(
        "{}::global_freelist/size={size} threads={threads} slots={slots}",
        module_path!(),
    );
    if let Threading::Multi { pattern, .. } = threading {
        name.push_str(&format!(" pattern={}", pattern.as_str()));
    }
    name
}

fn build_pool(size: usize, threads: usize) -> BufferPool {
    let cfg = BufferPoolConfig::for_network()
        .with_pool_min_size(1024)
        .with_min_size(NZUsize!(size.max(1024)))
        .with_max_size(NZUsize!(size.max(1024)))
        .with_max_per_class(NZUsize!(threads * 4))
        .with_thread_cache_for_parallelism(NZUsize!(threads))
        .with_prefill(true);

    let runner_cfg = tokio::Config::default()
        .with_worker_threads(1)
        .with_network_buffer_pool_config(cfg);

    tokio::Runner::new(runner_cfg).start(|ctx| async move { ctx.network_buffer_pool().clone() })
}

fn build_global_freelist_pool(size: usize, slots: usize) -> BufferPool {
    let cfg = BufferPoolConfig::for_network()
        .with_pool_min_size(0)
        .with_min_size(NZUsize!(size))
        .with_max_size(NZUsize!(size))
        .with_max_per_class(NZUsize!(slots))
        .with_thread_cache_disabled()
        .with_prefill(true);

    let runner_cfg = tokio::Config::default()
        .with_worker_threads(1)
        .with_network_buffer_pool_config(cfg);

    tokio::Runner::new(runner_cfg).start(|ctx| async move { ctx.network_buffer_pool().clone() })
}

#[allow(clippy::missing_const_for_fn)]
fn page_size() -> usize {
    #[cfg(unix)]
    {
        // SAFETY: sysconf is safe to call.
        let size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        if size <= 0 {
            4096
        } else {
            size as usize
        }
    }

    #[cfg(not(unix))]
    {
        4096
    }
}
