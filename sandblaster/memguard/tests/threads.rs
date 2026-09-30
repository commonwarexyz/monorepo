//! Per-thread accounting of the counting allocator under many threads:
//! exact after the threads exit (cross-thread frees, large requests,
//! thread-local destructors), the hard limit enforced, the soft limit
//! seeing near-real totals, and the process-wide counter off the fast path.
//!
//! The limits and counters are process-wide, so this binary has exactly one
//! test, which runs the scenarios one after the other. Every thread is
//! joined explicitly: a scope counts a thread as finished before its
//! thread-local destructors (which return its stock) have run, a join
//! waits for them.

use std::alloc::Layout;
use std::cell::RefCell;
use std::hint::black_box;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use sandblaster_memguard::{
    THREAD_STOCK, THREAD_STOCK_MAX, allocated, limits, peak, set_limits, shared_updates,
    soft_limit_exceeded,
};

const THREADS: usize = 16;
const MIB: usize = 1 << 20;

#[test]
fn per_thread_accounting() {
    // First spawns initialize lazy runtime state that is never freed.
    std::thread::spawn(|| black_box(vec![0u8; 100]))
        .join()
        .unwrap();
    std::thread::scope(|s| s.spawn(|| black_box(vec![0u8; 100])).join().unwrap());
    exact_after_threads_exit();
    fast_path_does_not_touch_the_shared_counter();
    soft_limit_sees_near_real_totals();
    hard_limit_is_exact_on_one_thread();
    hard_limit_holds_under_many_threads();
    // after every scenario: nothing leaked
    exact_after_threads_exit();
}

/// A deterministic PRNG (xorshift64).
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

/// A block size: mostly small (the stock path), sometimes at or above
/// [`THREAD_STOCK`] (the direct path).
fn size(r: &mut Rng) -> usize {
    match r.below(100) {
        0 => THREAD_STOCK + r.below(4 * THREAD_STOCK),
        1..=4 => 1024 + r.below(THREAD_STOCK),
        _ => 1 + r.below(256),
    }
}

thread_local! {
    /// Memory held in a lazily initialized thread-local, freed by its
    /// destructor at thread exit (before or after the allocator's exit hook).
    static HELD: RefCell<Vec<Vec<u8>>> = const { RefCell::new(Vec::new()) };
    /// Registered before the thread's first allocation (so its destructor
    /// runs after the allocator's exit hook); allocates and frees in `drop`.
    static EARLY: Early = const { Early };
}

struct Early;

impl Drop for Early {
    fn drop(&mut self) {
        let v: Vec<Vec<u8>> = (0..64).map(|i| vec![i as u8; 1 + i * 97]).collect();
        black_box(&v);
        let big = black_box(vec![1u8; 3 * THREAD_STOCK]);
        drop((v, big));
    }
}

/// Threads allocate, free, hand blocks to each other and leave some to the
/// main thread; once they have exited and the main thread has freed what it
/// got, `allocated()` is back to its value before, exactly.
fn exact_after_threads_exit() {
    let base = allocated();
    let (txs, rxs): (Vec<_>, Vec<_>) = (0..THREADS)
        .map(|_| std::sync::mpsc::channel::<Vec<u8>>())
        .unzip();
    let mut rxs: Vec<Option<_>> = rxs.into_iter().map(Some).collect();
    let handles: Vec<_> = (0..THREADS)
        .map(|t| {
            let next = txs[(t + 1) % THREADS].clone();
            let rx = rxs[t].take().unwrap();
            std::thread::spawn(move || {
                EARLY.with(|_| ());
                let mut r = Rng(0x9e37_79b9_7f4a_7c15 ^ (t as u64 + 1));
                let mut live: Vec<Vec<u8>> = Vec::new();
                for i in 0..20_000 {
                    if live.len() >= 256 || (!live.is_empty() && r.below(3) == 0) {
                        let k = r.below(live.len());
                        let b = live.swap_remove(k);
                        // a third of the frees happen on the next thread
                        if i % 3 == 0 {
                            let _ = next.send(b);
                        } else {
                            drop(b);
                        }
                    } else {
                        live.push(vec![i as u8; size(&mut r)]);
                    }
                    // grow and shrink with realloc too
                    if i % 1000 == 0 && !live.is_empty() {
                        let k = r.below(live.len());
                        live[k].resize(size(&mut r), 7);
                        live[k].shrink_to_fit();
                    }
                    while let Ok(b) = rx.try_recv() {
                        drop(b);
                    }
                }
                HELD.with(|h| h.borrow_mut().extend(live.drain(..live.len() / 2)));
                drop(next);
                // the rest outlives the thread: freed by the main thread
                (live, rx)
            })
        })
        .collect();
    drop(txs);
    let mut left: Vec<Vec<u8>> = Vec::new();
    let mut rxs_left = Vec::new();
    for h in handles {
        let (live, rx) = h.join().unwrap();
        left.extend(live);
        rxs_left.push(rx);
    }
    let outstanding: usize = left.iter().map(|b| b.capacity()).sum();
    let mid = allocated();
    assert!(
        mid >= base + outstanding,
        "allocated() under-reports: {mid} < {base} + {outstanding}"
    );
    drop(left);
    drop(rxs_left); // frees the blocks still queued in the channels
    drop(rxs);
    let end = allocated();
    eprintln!(
        "exact after exit: base {base} B, {outstanding} B outstanding after join (allocated +{} B), end {end} B",
        mid - base
    );
    assert_eq!(
        end, base,
        "the accounting must be exact once the threads have exited"
    );
}

/// Churning a steady set of small blocks touches the process-wide counter a
/// handful of times per thread, not twice per allocation.
fn fast_path_does_not_touch_the_shared_counter() {
    const PAIRS: usize = 500_000;
    let before = shared_updates();
    std::thread::scope(|s| {
        let hs: Vec<_> = (0..8)
            .map(|t| {
                s.spawn(move || {
                    let mut r = Rng(t as u64 + 7);
                    let mut ring: Vec<Box<[u8]>> =
                        (0..256).map(|_| vec![0u8; 16].into_boxed_slice()).collect();
                    for i in 0..PAIRS {
                        let k = i % ring.len();
                        ring[k] = vec![i as u8; 16 + r.below(240)].into_boxed_slice();
                    }
                    black_box(ring);
                })
            })
            .collect();
        hs.into_iter().for_each(|h| h.join().unwrap());
    });
    let updates = shared_updates() - before;
    eprintln!("shared-counter updates for 8 threads x {PAIRS} free+alloc pairs: {updates}");
    assert!(
        updates <= 8 * 32,
        "{updates} updates of the process-wide counter"
    );
}

/// A barrier that never allocates (usable with the hard limit exhausted).
struct Spin {
    arrived: AtomicUsize,
}

impl Spin {
    const fn new() -> Spin {
        Spin {
            arrived: AtomicUsize::new(0),
        }
    }
    /// Arrive, then wait until `n` have arrived in total.
    fn wait(&self, n: usize) {
        self.arrived.fetch_add(1, Ordering::AcqRel);
        while self.arrived.load(Ordering::Acquire) < n {
            std::thread::yield_now();
        }
    }
}

/// Allocate `bytes` in blocks of 16..=4096 bytes (infallible allocations).
fn fill(bytes: usize, seed: u64) -> Vec<Box<[u8]>> {
    let mut r = Rng(seed | 1);
    let mut v = Vec::new();
    let mut n = 0;
    while n < bytes {
        let s = (16 + r.below(4081)).min(bytes - n).max(1);
        v.push(vec![1u8; s].into_boxed_slice());
        n += s;
    }
    v
}

/// The soft limit trips once the threads' live heap is above it, and not
/// while it is below it by more than the threads' stock.
fn soft_limit_sees_near_real_totals() {
    const N: usize = 8;
    let (hard, soft) = limits();
    let base = allocated();
    let limit = base + 16 * MIB;
    set_limits(hard, limit);
    let (a, b, c, d) = (Spin::new(), Spin::new(), Spin::new(), Spin::new());
    let below = AtomicUsize::new(0);
    let above = AtomicUsize::new(0);
    std::thread::scope(|s| {
        let hs: Vec<_> = (0..N)
            .map(|t| {
                let (a, b, c, d, below, above) = (&a, &b, &c, &d, &below, &above);
                s.spawn(move || {
                    // 8 MiB in total: below the limit by more than the stock of
                    // all threads (9 × 128 KiB)
                    let mut v = fill(MIB, t as u64);
                    a.wait(N);
                    if !soft_limit_exceeded() {
                        below.fetch_add(1, Ordering::Relaxed);
                    }
                    b.wait(N);
                    // 24 MiB in total: above the limit
                    v.extend(fill(2 * MIB, t as u64 + 100));
                    c.wait(N);
                    if soft_limit_exceeded() {
                        above.fetch_add(1, Ordering::Relaxed);
                    }
                    d.wait(N);
                    drop(v);
                })
            })
            .collect();
        hs.into_iter().for_each(|h| h.join().unwrap());
    });
    set_limits(hard, soft);
    eprintln!(
        "soft limit base+16 MiB: {} of {N} threads saw it clear at 8 MiB, {} of {N} saw it exceeded at 24 MiB",
        below.load(Ordering::Relaxed),
        above.load(Ordering::Relaxed)
    );
    assert_eq!(
        below.load(Ordering::Relaxed),
        N,
        "the soft limit tripped early (8 MiB of 16 MiB in use)"
    );
    assert_eq!(
        above.load(Ordering::Relaxed),
        N,
        "the soft limit missed 24 MiB in use (limit 16 MiB)"
    );
}

/// With no other thread allocating, the hard limit is exact against
/// `allocated()`: a request that fills it exactly succeeds (spending the
/// thread's own stock), the next one fails.
fn hard_limit_is_exact_on_one_thread() {
    const Z: usize = 4 * THREAD_STOCK;
    let (hard, soft) = limits();
    // this thread now holds some stock
    let small = black_box(Box::new([1u8; 100]));
    let base = allocated();
    set_limits(base + Z, soft);
    let mut fits: Vec<u8> = Vec::new();
    let r1 = fits.try_reserve_exact(Z);
    let at = allocated();
    let mut over: Vec<u8> = Vec::new();
    let r2 = over.try_reserve_exact(THREAD_STOCK);
    set_limits(hard, soft);
    assert!(
        r1.is_ok(),
        "a request filling the hard limit exactly was refused"
    );
    assert_eq!(at, base + Z);
    assert!(r2.is_err(), "a request above the hard limit succeeded");
    drop((small, fits, over));
}

/// 16 threads allocate until refused under a hard limit 64 MiB above the
/// current heap: together they get 64 MiB, give or take the threads' stock,
/// and the process-wide reservation never exceeds the limit.
fn hard_limit_holds_under_many_threads() {
    const ROOM: usize = 64 * MIB;
    /// The largest request below.
    const MAX_REQUEST: usize = 2 * THREAD_STOCK;
    let (hard, soft) = limits();
    let ready = Spin::new();
    let go = AtomicBool::new(false);
    let refused = Spin::new();
    let release = AtomicBool::new(false);
    let got: Vec<AtomicUsize> = (0..THREADS).map(|_| AtomicUsize::new(0)).collect();
    let soft_seen = AtomicUsize::new(0);
    let mut limit = 0;
    std::thread::scope(|s| {
        let hs: Vec<_> = (0..THREADS)
            .map(|t| {
                let (ready, go, refused, release, got, soft_seen) =
                    (&ready, &go, &refused, &release, &got, &soft_seen);
                s.spawn(move || {
                    let mut r = Rng(t as u64 + 1000);
                    black_box(vec![0u8; 64]); // registers this thread's stock
                    ready.wait(THREADS + 1);
                    while !go.load(Ordering::Acquire) {
                        std::thread::yield_now();
                    }
                    // Raw allocations (a refusal returns null instead of
                    // aborting), kept in an intrusive list: [next, size] headers.
                    let mut head: *mut u8 = std::ptr::null_mut();
                    let mut total = 0usize;
                    loop {
                        let n = if r.below(50) == 0 {
                            MAX_REQUEST - r.below(THREAD_STOCK)
                        } else {
                            16 + r.below(4081)
                        };
                        let l = Layout::from_size_align(n, 8).unwrap();
                        // SAFETY: non-zero size.
                        let p = unsafe { std::alloc::alloc(l) };
                        if p.is_null() {
                            break;
                        }
                        // SAFETY: `p` holds at least 16 bytes, 8-aligned.
                        unsafe {
                            (p as *mut *mut u8).write(head);
                            (p as *mut usize).add(1).write(n);
                        }
                        head = p;
                        total += n;
                    }
                    got[t].store(total, Ordering::Relaxed);
                    if soft_limit_exceeded() {
                        soft_seen.fetch_add(1, Ordering::Relaxed);
                    }
                    refused.wait(THREADS);
                    while !release.load(Ordering::Acquire) {
                        std::thread::yield_now();
                    }
                    while !head.is_null() {
                        // SAFETY: a block of the list, allocated with this size.
                        unsafe {
                            let next = (head as *const *mut u8).read();
                            let n = (head as *const usize).add(1).read();
                            std::alloc::dealloc(head, Layout::from_size_align(n, 8).unwrap());
                            head = next;
                        }
                    }
                })
            })
            .collect();
        ready.wait(THREADS + 1);
        let base = allocated();
        limit = base + ROOM;
        // the soft limit halfway: exhausting the hard limit must trip it
        set_limits(limit, base + ROOM / 2);
        go.store(true, Ordering::Release);
        while refused.arrived.load(Ordering::Acquire) < THREADS {
            std::thread::yield_now();
        }
        let during = allocated();
        set_limits(hard, soft);
        release.store(true, Ordering::Release);
        hs.into_iter().for_each(|h| h.join().unwrap());
        assert!(
            during <= limit,
            "allocated() {during} above the hard limit {limit}"
        );
    });
    let total: usize = got.iter().map(|g| g.load(Ordering::Relaxed)).sum();
    // other threads' stock: the workers' and the harness thread's
    let slack = (THREADS + 2) * THREAD_STOCK_MAX;
    eprintln!(
        "hard limit base+64 MiB, {THREADS} threads: got {total} B together ({:+} B vs 64 MiB; bound ±{} B), peak {} (limit {limit})",
        total as i64 - ROOM as i64,
        slack + MAX_REQUEST,
        peak()
    );
    assert!(
        total <= ROOM + slack,
        "the threads got {total} B under a hard limit {ROOM} B above the heap"
    );
    assert!(
        total + slack + MAX_REQUEST >= ROOM,
        "refused too early: {total} B of {ROOM} B"
    );
    assert!(
        peak() <= limit,
        "the reservation ({}) exceeded the hard limit ({limit})",
        peak()
    );
    assert_eq!(
        soft_seen.load(Ordering::Relaxed),
        THREADS,
        "every thread saw the soft limit exceeded"
    );
}
