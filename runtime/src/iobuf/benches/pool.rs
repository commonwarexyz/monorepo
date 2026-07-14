//! End-to-end `BufferPool` allocation benchmarks.
//!
//! This module compares pooled allocation against direct aligned allocation for
//! the steady-state hot path we care about here: allocate and drop, optionally
//! touching the requested bytes at page granularity.
//!
//! # Touch Modes
//!
//! - **touch=false**: allocate and drop only.
//! - **touch=true**: allocate, touch one byte per page, and drop.
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
//! # Sparse Layouts
//!
//! `layout=sparse` cases use a pool whose class layout skips the exponents
//! between a small minimum class and the target class, and request a size
//! whose natural exponent is disabled. Allocation routes through the aliased
//! routing entries to the target class, exercising the same steady-state
//! paths as the contiguous cases over a sparse routing vector.
//!
//! # Why Touch Pages?
//!
//! Large allocations may be backed by lazily materialized virtual memory once
//! the allocator starts using `mmap`, so timing allocation alone can undercount
//! the real cost of actually using the buffer. Touching each page forces
//! materialization and makes the comparison between direct aligned allocation
//! and pooled reuse fairer.
//!
//! The no-touch mode keeps the allocator-only shape visible. The touch mode
//! measures the cost observed by callers that actually use the buffer, including
//! first-touch behavior for pages that have not yet been materialized.

use super::utils::{measure, Threading};
use commonware_runtime::{
    page_size, tokio, BufferPool, BufferPoolConfig, BufferPooler, IoBufMut, Runner as _,
};
use commonware_utils::{NZUsize, NZU32};
use criterion::Criterion;
use std::{hint::black_box, num::NonZeroUsize};
const SIZES: &[usize] = &[256, 1024, 4096, 65536, 1024 * 1024, 8 * 1024 * 1024];

#[derive(Clone, Copy)]
enum Allocation {
    Direct,
    Pooled,
}

impl Allocation {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Pooled => "pooled",
        }
    }
}

/// Smallest class enabled in the sparse layouts.
///
/// Sparse cases request half the target size, whose exponent is disabled, so
/// allocation routes through aliased gap entries to the target class. This
/// exercises the same steady-state allocation and return paths as the
/// contiguous cases with a sparse routing vector.
const SPARSE_MIN_CLASS: usize = 256;

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
            for touch in [false, true] {
                bench_case(
                    c,
                    Allocation::Direct,
                    size,
                    threading,
                    touch,
                    None,
                    || IoBufMut::with_alignment(size, NonZeroUsize::new(alignment).unwrap()),
                    page_size,
                );
                bench_case(
                    c,
                    Allocation::Pooled,
                    size,
                    threading,
                    touch,
                    None,
                    {
                        let pool = pool.clone();
                        move || {
                            pool.try_alloc(size)
                                .expect("buffer pool exhausted during benchmark")
                        }
                    },
                    page_size,
                );
            }
        }
    }

    // Sparse layouts need a disabled exponent between the minimum class and
    // the target class, so the smallest sizes are skipped.
    for &size in SIZES {
        let request = size / 2;
        if request <= SPARSE_MIN_CLASS {
            continue;
        }
        let pool = build_sparse_pool(size, threads);

        for threading in threadings {
            bench_case(
                c,
                Allocation::Pooled,
                size,
                threading,
                false,
                Some("sparse"),
                {
                    let pool = pool.clone();
                    move || {
                        pool.try_alloc(request)
                            .expect("buffer pool exhausted during benchmark")
                    }
                },
                page_size,
            );
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn bench_case(
    c: &mut Criterion,
    allocation: Allocation,
    size: usize,
    threading: Threading,
    touch: bool,
    layout: Option<&str>,
    alloc: impl Fn() -> IoBufMut + Sync,
    page_size: usize,
) {
    let name = bench_name(allocation, touch, size, threading, layout);
    match touch {
        false => {
            c.bench_function(&name, |b| {
                b.iter_custom(|iters| {
                    measure(
                        iters,
                        threading,
                        || {},
                        |_| {
                            let buffer = alloc();
                            drop(black_box(buffer));
                        },
                    )
                });
            });
        }
        true => {
            c.bench_function(&name, |b| {
                b.iter_custom(|iters| {
                    measure(
                        iters,
                        threading,
                        || {},
                        |_| {
                            let mut buffer = alloc();
                            touch_pages(buffer.as_mut_ptr(), size, page_size);
                            drop(black_box(buffer));
                        },
                    )
                });
            });
        }
    }
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

fn bench_name(
    allocation: Allocation,
    touch: bool,
    size: usize,
    threading: Threading,
    layout: Option<&str>,
) -> String {
    let threads = threading.threads();
    let mut name = format!(
        "{}/allocation={} touch={} size={size} threads={threads}",
        module_path!(),
        allocation.as_str(),
        touch,
    );
    if let Threading::Multi { pattern, .. } = threading {
        name.push_str(&format!(" pattern={}", pattern.as_str()));
    }
    if let Some(layout) = layout {
        name.push_str(&format!(" layout={layout}"));
    }
    name
}

fn start_pool(cfg: BufferPoolConfig) -> BufferPool {
    let runner_cfg = tokio::Config::default()
        .with_worker_threads(1)
        .with_network_buffer_pool_config(cfg);

    tokio::Runner::new(runner_cfg).start(|ctx| async move { ctx.network_buffer_pool().clone() })
}

fn build_pool(size: usize, threads: usize) -> BufferPool {
    let max_per_class =
        u32::try_from(threads * 4).expect("bench capacity must fit in u32 slot ids");
    start_pool(
        BufferPoolConfig::for_network()
            .with_pool_min_size(0)
            .with_size_class_range(NZUsize!(size), NZUsize!(size), NZU32!(max_per_class))
            .with_parallelism(NZUsize!(threads))
            .with_prefill(true),
    )
}

fn build_sparse_pool(size: usize, threads: usize) -> BufferPool {
    let max_per_class =
        u32::try_from(threads * 4).expect("bench capacity must fit in u32 slot ids");
    start_pool(
        BufferPoolConfig::for_network()
            .with_pool_min_size(0)
            .with_size_classes([
                (NZUsize!(SPARSE_MIN_CLASS), NZU32!(max_per_class)),
                (NZUsize!(size), NZU32!(max_per_class)),
            ])
            .with_parallelism(NZUsize!(threads))
            .with_prefill(true),
    )
}
