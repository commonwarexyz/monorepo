//! Microbenchmark: allocation throughput through the counting allocator on
//! 1..N threads (the multi-thread slowdown found by the AVX-512 model
//! campaign, docs/avx512-models.md §6).
//!
//! ```text
//! CARGO_TARGET_DIR=target/opt cargo bench -p sandblaster-memguard --bench contention
//! ```
//!
//! Every thread runs the same fixed work: `OPS` free + allocate pairs over a
//! ring of `RING` live blocks of 16..=256 bytes (the shape of kernel
//! evaluation: many small, short-lived nodes). Three allocators are timed
//! in the same run:
//!
//! * `memguard` — the installed global allocator (this crate's `Guard`,
//!   per-thread stock);
//! * `shared` — the previous accounting (process-wide atomics updated on
//!   every call) over the system allocator, reproduced below;
//! * `system` — the system allocator without accounting.
//!
//! Scaling is `wall(threads) / wall(1 thread)` for the same per-thread work
//! (1.0 = perfect; above the performance-core count the slower cores add
//! some). Numbers are the best of `REPS` runs.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

// Linking the crate installs `Guard` as this binary's global allocator.
use sandblaster_memguard as memguard;

const RING: usize = 1024;
const OPS: usize = 2_000_000;
const REPS: usize = 3;

/// The accounting of `sandblaster-memguard` before per-thread stock: every
/// allocation does `fetch_add` + `fetch_max` on process-wide atomics, every
/// deallocation a `fetch_sub`.
struct SharedCounting;

static ALLOCATED: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
static HARD: AtomicUsize = AtomicUsize::new(memguard::DEFAULT_HARD_LIMIT);

impl SharedCounting {
    #[inline]
    fn reserve(size: usize) -> bool {
        let prev = ALLOCATED.fetch_add(size, Ordering::Relaxed);
        let now = prev.saturating_add(size);
        if now > HARD.load(Ordering::Relaxed) {
            ALLOCATED.fetch_sub(size, Ordering::Relaxed);
            return false;
        }
        PEAK.fetch_max(now, Ordering::Relaxed);
        true
    }
}

// SAFETY: forwards to `System` unchanged, plus atomic bookkeeping.
unsafe impl GlobalAlloc for SharedCounting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if !Self::reserve(layout.size()) {
            return std::ptr::null_mut();
        }
        // SAFETY: forwarded unchanged.
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: forwarded unchanged.
        unsafe { System.dealloc(ptr, layout) };
        ALLOCATED.fetch_sub(layout.size(), Ordering::Relaxed);
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Via {
    Memguard,
    Shared,
    System,
}

#[inline(always)]
unsafe fn alloc(via: Via, l: Layout) -> *mut u8 {
    // SAFETY: `l` has a non-zero size (callers).
    unsafe {
        match via {
            Via::Memguard => std::alloc::alloc(l),
            Via::Shared => SharedCounting.alloc(l),
            Via::System => System.alloc(l),
        }
    }
}

#[inline(always)]
unsafe fn dealloc(via: Via, p: *mut u8, l: Layout) {
    // SAFETY: `p` was returned by `alloc(via, l)` (callers).
    unsafe {
        match via {
            Via::Memguard => std::alloc::dealloc(p, l),
            Via::Shared => SharedCounting.dealloc(p, l),
            Via::System => System.dealloc(p, l),
        }
    }
}

/// One thread's work: `OPS` free + allocate pairs over a ring of live blocks.
fn work(via: Via, seed: u64) {
    let mut x = seed | 1;
    let mut ring: Vec<(*mut u8, Layout)> = vec![(std::ptr::null_mut(), Layout::new::<u8>()); RING];
    for i in 0..OPS {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        let size = 16 + (x as usize % 241);
        let slot = &mut ring[i % RING];
        if !slot.0.is_null() {
            // SAFETY: allocated below with this layout.
            unsafe { dealloc(via, slot.0, slot.1) };
        }
        let l = Layout::from_size_align(size, 8).unwrap();
        // SAFETY: non-zero size.
        let p = unsafe { alloc(via, l) };
        assert!(!p.is_null());
        // SAFETY: `p` points to `size` writable bytes.
        unsafe { p.write_volatile(i as u8) };
        *slot = (p, l);
    }
    for (p, l) in ring {
        if !p.is_null() {
            // SAFETY: as above.
            unsafe { dealloc(via, p, l) };
        }
    }
}

fn run(via: Via, threads: usize) -> Duration {
    (0..REPS)
        .map(|_| {
            let go = std::sync::Barrier::new(threads + 1);
            // `scope` joins every thread before it returns.
            let t0 = std::thread::scope(|s| {
                for t in 0..threads {
                    let go = &go;
                    s.spawn(move || {
                        go.wait();
                        work(via, 0x9e37_79b9_7f4a_7c15 ^ t as u64);
                    });
                }
                go.wait();
                Instant::now()
            });
            t0.elapsed()
        })
        .min()
        .unwrap()
}

fn main() {
    // `cargo bench` passes `--bench`; a filter argument is ignored.
    let cores = std::thread::available_parallelism().map_or(4, |n| n.get());
    let counts: Vec<usize> = [1, 2, 4, 8, 16]
        .into_iter()
        .filter(|&t| t <= cores.max(1))
        .collect();
    println!(
        "memguard contention microbenchmark: {OPS} free+alloc pairs per thread, ring of {RING} blocks of 16..=256 B, best of {REPS}"
    );
    println!(
        "{:>7} | {:>10} {:>7} | {:>10} {:>7} | {:>10} {:>7}",
        "threads", "memguard", "scale", "shared", "scale", "system", "scale"
    );
    let mut base = [Duration::ZERO; 3];
    for &t in &counts {
        let mut row = String::new();
        for (k, via) in [Via::Memguard, Via::Shared, Via::System]
            .into_iter()
            .enumerate()
        {
            let d = run(via, t);
            if t == 1 {
                base[k] = d;
            }
            row.push_str(&format!(
                " | {:>8.1}ms {:>6.2}x",
                d.as_secs_f64() * 1e3,
                d.as_secs_f64() / base[k].as_secs_f64()
            ));
        }
        println!("{t:>7}{row}");
    }
    println!(
        "memguard after the run: allocated {} KiB, peak {} KiB, shared-counter updates {}",
        memguard::allocated() >> 10,
        memguard::peak() >> 10,
        memguard::shared_updates()
    );
}
