//! End-to-end `BufferPool` allocation benchmarks.
//!
//! This module compares pooled allocation against direct aligned allocation for
//! the steady-state hot path we care about here: allocate, touch the requested
//! bytes at page granularity, and drop.
//!
//! # Metrics
//!
//! - **raw**: end-to-end time for allocate + page-touch + drop.
//! - **adjusted**: raw time minus the cost of repeatedly touching pages on an
//!   already-materialized buffer. This isolates allocator overhead. The
//!   baseline is always measured single-threaded because each thread writes to
//!   private memory, so the touch cost is the same per iteration regardless of
//!   thread count, and single-threaded measurement avoids scheduling noise that
//!   would swamp the subtraction signal.
//!
//! # Thread Configurations
//!
//! For each buffer size, the benchmark runs:
//!
//! - one single-threaded case
//! - one multi-threaded lockstep case
//! - one multi-threaded staggered case
//!
//! The shared [`Threading`] presets and timing harness come from [`super::utils`].
//!
//! # Why Touch Pages?
//!
//! Large allocations may be backed by lazily materialized virtual memory once
//! the allocator starts using `mmap`, so timing allocation alone can undercount
//! the real cost of actually using the buffer. Touching each page forces
//! materialization and makes the comparison between direct aligned allocation
//! and pooled reuse fairer.
//!
//! For large sizes this means much of the raw benchmark measures page writes
//! rather than allocator bookkeeping. That is acceptable because both
//! implementations pay the same page-touch cost, so the relative comparison
//! still isolates the allocation strategy.

use super::utils::{measure, Threading};
use commonware_runtime::{
    tokio, BufferPool, BufferPoolConfig, BufferPooler, IoBufMut, Runner as _,
};
use commonware_utils::NZUsize;
use criterion::Criterion;
use std::{hint::black_box, num::NonZeroUsize};
const SIZES: &[usize] = &[256, 1024, 4096, 65536, 1024 * 1024, 8 * 1024 * 1024];

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

pub fn bench(c: &mut Criterion) {
    let page_size = page_size();
    let threadings = Threading::standard();
    let threads = threadings
        .iter()
        .map(|threading| threading.threads())
        .max()
        .unwrap_or(1);

    for &size in SIZES {
        let pool = build_pool(size, threads);
        let alignment = pool.config().alignment.get();

        for threading in threadings {
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

fn build_pool(size: usize, threads: usize) -> BufferPool {
    let cfg = BufferPoolConfig::for_network()
        .with_pool_min_size(1024)
        .with_min_size(NZUsize!(size.max(1024)))
        .with_max_size(NZUsize!(size.max(1024)))
        .with_max_per_class(NZUsize!(threads * 4))
        .with_parallelism(NZUsize!(threads))
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
