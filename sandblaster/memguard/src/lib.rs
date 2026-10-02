//! A process-wide allocation cap for sandblaster's tools (the `build.rs`
//! verifier, the CLI, and every test binary that links the front end).
//!
//! Proof search and symbolic execution can, on adversarial or simply large
//! inputs, build enormous terms. Without a cap, one runaway process can
//! exhaust the host's memory (this happened during the phase-4 red team).
//! Linking this crate installs a counting global allocator:
//!
//! * a **hard limit** (default [`DEFAULT_HARD_LIMIT`]): an allocation that
//!   would exceed it fails, which makes Rust abort the process with
//!   "memory allocation failed" instead of taking the machine down;
//! * a **soft limit** ([`soft_limit_exceeded`]) that long-running loops (the
//!   kernel's step ticker) poll to fail gracefully (`OutOfFuel`) well before
//!   the hard limit.
//!
//! Limits can be set programmatically ([`set_limits`]) or from the
//! environment by calling [`init_from_env`] (`SANDBLASTER_MEM_LIMIT_GB`, hard;
//! the soft limit is 75% of it). This crate is resource control only; it is
//! not part of the trusted computing base (a failed allocation can only make
//! a check fail, never succeed).
//!
//! # Per-thread accounting
//!
//! Updating one process-wide counter on every allocation made threads
//! contend on its cache line: kernel campaigns ran about 2× slower on 2-16
//! threads than on one (docs/avx512-models.md §6). The counter is therefore
//! a **reservation**, drawn by each thread in batches:
//!
//! * the process-wide counter holds the bytes *reserved*: the live heap plus
//!   every thread's unspent **stock**. It is raised only by a
//!   compare-and-swap that keeps it at or below the hard limit;
//! * an allocation below [`THREAD_STOCK`] bytes is taken from the calling
//!   thread's stock (thread-local, no atomic operation). An empty stock is
//!   refilled from the counter with the request plus [`THREAD_STOCK`] bytes
//!   (if that fails, with the request alone); a freed block goes back to the
//!   stock, and a stock above [`THREAD_STOCK_MAX`] returns its excess to the
//!   counter. Requests of [`THREAD_STOCK`] bytes or more go to the counter
//!   directly (and use the stock only if the counter refuses them), and so
//!   do the allocations of a thread whose stock is not usable (while it
//!   registers its exit hook, or after its thread-local destructors ran);
//! * a thread's stock is returned to the counter when the thread exits, so
//!   the accounting is exact again once the worker threads have exited.
//!
//! The shared cache line is touched once per [`THREAD_STOCK`] bytes of net
//! growth or shrinkage of a thread's heap, not per allocation
//! ([`shared_updates`] counts the touches).
//!
//! **Per-thread growth.** Each thread also counts the bytes it allocated
//! minus the bytes it freed ([`thread_allocated`], a plain thread-local
//! cell next to the stock), so a limit on the growth caused by one piece of
//! work on one thread — the prover's per-goal heap cap — measures that
//! work, not what other threads allocate meanwhile (the mutation gate
//! elaborates its batches on several threads at once). A block freed by
//! another thread than the one that allocated it lowers the freeing
//! thread's count instead: compare two readings of one thread with
//! [`thread_growth`], which reads the wrapping difference.
//!
//! **Guarantees.** With `n` threads holding stock (each at most
//! [`THREAD_STOCK_MAX`] = 128 KiB):
//!
//! * the hard limit is never overshot: every live byte is covered by the
//!   reservation, which never exceeds the hard limit. (If [`set_limits`]
//!   lowers the hard limit below the current reservation, allocations can
//!   still be served from the stock already reserved, at most `n` ×
//!   [`THREAD_STOCK_MAX`] bytes, and every new reservation fails.)
//! * An allocation is refused only if the live heap plus the request would
//!   exceed the hard limit minus the other threads' stock: at most (`n` − 1)
//!   × [`THREAD_STOCK_MAX`] bytes early. (On one thread the hard limit is
//!   exact against [`allocated`].)
//! * [`allocated`] and [`soft_limit_exceeded`] never under-report the live
//!   heap, and over-report it by at most the other threads' stock: they see
//!   the reservation minus the calling thread's own stock.
//! * [`peak`] is the peak of the reservation: at least the peak of the live
//!   heap, and above it by at most `n` × [`THREAD_STOCK_MAX`].
//!
//! (16 threads: 2 MiB; the default limits are 8 GiB hard, 6 GiB soft.)

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Default hard limit: 8 GiB per process.
pub const DEFAULT_HARD_LIMIT: usize = 8 << 30;
/// Default soft limit: 6 GiB per process.
pub const DEFAULT_SOFT_LIMIT: usize = 6 << 30;

/// A thread's stock after a refill or after returning its excess; also the
/// size from which a request bypasses the stock and reserves directly.
pub const THREAD_STOCK: usize = 64 << 10;
/// The most stock a thread keeps; above it the excess (down to
/// [`THREAD_STOCK`]) goes back to the process-wide counter. It is at least
/// `THREAD_STOCK` plus the largest stock-served request, so a refill
/// followed by a free (or a return followed by an allocation) never
/// touches the counter again.
pub const THREAD_STOCK_MAX: usize = 2 * THREAD_STOCK;

/// The counters written on the slow path, on their own cache line (128
/// bytes: Apple M-series lines, and x86 adjacent-line prefetch pairs).
#[repr(align(128))]
struct Shared {
    /// Live heap + every thread's stock (bytes); at most the hard limit
    /// whenever it is raised.
    reserved: AtomicUsize,
    /// Peak of `reserved`.
    peak: AtomicUsize,
    /// Number of updates of `reserved` (diagnostic, [`shared_updates`]).
    updates: AtomicUsize,
}

/// The limits (read on the slow path and by the soft-limit poll; written
/// rarely), on another cache line than [`Shared`].
#[repr(align(128))]
struct Limits {
    hard: AtomicUsize,
    soft: AtomicUsize,
}

static SHARED: Shared = Shared {
    reserved: AtomicUsize::new(0),
    peak: AtomicUsize::new(0),
    updates: AtomicUsize::new(0),
};
static LIMITS: Limits = Limits {
    hard: AtomicUsize::new(DEFAULT_HARD_LIMIT),
    soft: AtomicUsize::new(DEFAULT_SOFT_LIMIT),
};

/// Reserve `n` bytes on the process-wide counter, unless that would take it
/// above the hard limit.
fn reserve_shared(n: usize) -> bool {
    let hard = LIMITS.hard.load(Ordering::Relaxed);
    match SHARED
        .reserved
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |r| {
            r.checked_add(n).filter(|&t| t <= hard)
        }) {
        Ok(prev) => {
            // `prev + n` cannot overflow: checked above.
            let now = prev + n;
            SHARED.updates.fetch_add(1, Ordering::Relaxed);
            if now > SHARED.peak.load(Ordering::Relaxed) {
                SHARED.peak.fetch_max(now, Ordering::Relaxed);
            }
            true
        }
        Err(_) => false,
    }
}

/// Return `n` reserved bytes to the process-wide counter.
fn release_shared(n: usize) {
    SHARED.reserved.fetch_sub(n, Ordering::Relaxed);
    SHARED.updates.fetch_add(1, Ordering::Relaxed);
}

/// States of a thread's [`Local`].
const NEW: u8 = 0;
/// Registering the exit hook: allocations made meanwhile (by the
/// registration itself, on some platforms) go to the counter directly.
const REGISTERING: u8 = 1;
const LIVE: u8 = 2;
/// The exit hook ran (or could not be registered): no stock any more.
const DEAD: u8 = 3;

/// A thread's accounting state. It has no destructor, so it is a plain
/// `#[thread_local]` static, accessible at any time (even from other
/// thread-local destructors) and never allocating.
struct Local {
    /// Bytes reserved on the counter and not in use by this thread.
    stock: Cell<usize>,
    state: Cell<u8>,
    /// Bytes this thread allocated minus the bytes it freed, wrapping
    /// ([`thread_allocated`]); counted in every state.
    net: Cell<usize>,
}

/// Returns the thread's stock to the counter when the thread exits.
struct ExitHook;

impl Drop for ExitHook {
    fn drop(&mut self) {
        let _ = LOCAL.try_with(|l| {
            l.state.set(DEAD);
            let s = l.stock.replace(0);
            if s > 0 {
                release_shared(s);
            }
        });
    }
}

thread_local! {
    static LOCAL: Local = const { Local { stock: Cell::new(0), state: Cell::new(NEW), net: Cell::new(0) } };
    static EXIT: ExitHook = const { ExitHook };
}

/// Counts `size` more bytes in use by the calling thread
/// ([`thread_allocated`]); never allocates, panics or unwinds.
#[inline]
fn net_add(size: usize) {
    let _ = LOCAL.try_with(|l| l.net.set(l.net.get().wrapping_add(size)));
}

/// Counts `size` fewer bytes in use by the calling thread.
#[inline]
fn net_sub(size: usize) {
    let _ = LOCAL.try_with(|l| l.net.set(l.net.get().wrapping_sub(size)));
}

impl Local {
    /// Whether the stock can be used (registers the exit hook on first use).
    #[inline]
    fn ready(&self) -> bool {
        match self.state.get() {
            LIVE => true,
            NEW => self.register(),
            _ => false,
        }
    }

    #[cold]
    #[inline(never)]
    fn register(&self) -> bool {
        self.state.set(REGISTERING);
        // Touching `EXIT` registers its destructor. `try_with` never panics
        // (a panic must not unwind out of the allocator).
        let ok = EXIT.try_with(|_| ()).is_ok();
        self.state.set(if ok { LIVE } else { DEAD });
        ok
    }

    /// Account for `size` more bytes in use (`size < THREAD_STOCK`); `None`
    /// if the stock is not usable. Counts them in [`Local::net`] when they
    /// are granted.
    #[inline]
    fn charge(&self, size: usize) -> Option<bool> {
        if !self.ready() {
            return None;
        }
        let s = self.stock.get();
        let ok = if s >= size {
            self.stock.set(s - size);
            true
        } else {
            self.refill(size - s)
        };
        if ok {
            self.net.set(self.net.get().wrapping_add(size));
        }
        Some(ok)
    }

    /// The stock is `need` bytes short of a request: reserve those plus a
    /// fresh stock, or failing that the shortfall alone.
    #[cold]
    #[inline(never)]
    fn refill(&self, need: usize) -> bool {
        if reserve_shared(need + THREAD_STOCK) {
            self.stock.set(THREAD_STOCK);
            true
        } else if reserve_shared(need) {
            self.stock.set(0);
            true
        } else {
            false
        }
    }

    /// Account for `size` fewer bytes in use (`size < THREAD_STOCK`); false
    /// if the stock is not usable. Counts them in [`Local::net`] when it
    /// accounts for them.
    #[inline]
    fn credit(&self, size: usize) -> bool {
        if !self.ready() {
            return false;
        }
        self.net.set(self.net.get().wrapping_sub(size));
        let s = self.stock.get() + size;
        if s > THREAD_STOCK_MAX {
            self.stock.set(THREAD_STOCK);
            release_shared(s - THREAD_STOCK);
        } else {
            self.stock.set(s);
        }
        true
    }
}

/// Account for an allocation of `size` bytes; false if it would exceed the
/// hard limit. A granted allocation is counted for the calling thread
/// ([`thread_allocated`]).
#[inline]
fn charge(size: usize) -> bool {
    if size < THREAD_STOCK {
        if let Ok(Some(ok)) = LOCAL.try_with(|l| l.charge(size)) {
            return ok;
        }
        let ok = reserve_shared(size);
        if ok {
            net_add(size);
        }
        return ok;
    }
    let ok = reserve_shared(size) || charge_with_stock(size);
    if ok {
        net_add(size);
    }
    ok
}

/// A request of at least [`THREAD_STOCK`] bytes that the counter refused:
/// spend this thread's stock on it too, so that only the *other* threads'
/// stock can make an allocation fail early.
#[cold]
#[inline(never)]
fn charge_with_stock(size: usize) -> bool {
    LOCAL
        .try_with(|l| {
            if l.state.get() != LIVE {
                return false;
            }
            let s = l.stock.get();
            if s >= size {
                l.stock.set(s - size);
                true
            } else if s > 0 && reserve_shared(size - s) {
                l.stock.set(0);
                true
            } else {
                false
            }
        })
        .unwrap_or(false)
}

/// Account for `size` bytes no longer in use (and no longer counted for the
/// calling thread).
#[inline]
fn credit(size: usize) {
    if size < THREAD_STOCK && matches!(LOCAL.try_with(|l| l.credit(size)), Ok(true)) {
        return;
    }
    net_sub(size);
    release_shared(size);
}

/// The counting allocator (wraps the system allocator).
pub struct Guard;

// SAFETY: every method forwards to `System` with the caller's layout and
// pointer unchanged; the only addition is bookkeeping on thread-local cells
// and atomic counters, which never allocates, panics or unwinds. A refused
// reservation returns null, which `GlobalAlloc` permits (it signals
// allocation failure).
unsafe impl GlobalAlloc for Guard {
    #[inline]
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if !charge(layout.size()) {
            return std::ptr::null_mut();
        }
        // SAFETY: forwarded unchanged; the caller upholds `alloc`'s contract.
        let p = unsafe { System.alloc(layout) };
        if p.is_null() {
            credit(layout.size());
        }
        p
    }

    #[inline]
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        if !charge(layout.size()) {
            return std::ptr::null_mut();
        }
        // SAFETY: forwarded unchanged.
        let p = unsafe { System.alloc_zeroed(layout) };
        if p.is_null() {
            credit(layout.size());
        }
        p
    }

    #[inline]
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: forwarded unchanged; `ptr` was allocated by this allocator
        // (i.e. by `System`) with `layout`.
        unsafe { System.dealloc(ptr, layout) };
        credit(layout.size());
    }

    #[inline]
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let old = layout.size();
        if new_size > old && !charge(new_size - old) {
            return std::ptr::null_mut();
        }
        // SAFETY: forwarded unchanged.
        let p = unsafe { System.realloc(ptr, layout, new_size) };
        if p.is_null() {
            if new_size > old {
                credit(new_size - old);
            }
        } else if new_size < old {
            credit(old - new_size);
        }
        p
    }
}

#[global_allocator]
static GLOBAL: Guard = Guard;

/// Bytes currently allocated by this process (heap, through Rust's
/// allocator), as seen from the calling thread: the process-wide
/// reservation minus this thread's unspent stock. Never below the live
/// heap; above it by at most the other threads' stock (module docs).
#[inline]
pub fn allocated() -> usize {
    let own = LOCAL.try_with(|l| l.stock.get()).unwrap_or(0);
    SHARED.reserved.load(Ordering::Relaxed).saturating_sub(own)
}

/// Bytes allocated by the calling thread so far minus the bytes it freed,
/// through Rust's allocator: a wrapping counter (a thread that frees blocks
/// another thread allocated can take it below an earlier reading), so read
/// differences with [`thread_growth`]. Unlike [`allocated`] it does not
/// move when other threads allocate (module docs, *Per-thread growth*).
#[inline]
pub fn thread_allocated() -> usize {
    LOCAL.try_with(|l| l.net.get()).unwrap_or(0)
}

/// The calling thread's heap growth since `since`, an earlier reading of
/// [`thread_allocated`] on the same thread: bytes allocated minus bytes
/// freed by this thread in between (negative when it freed more).
#[inline]
pub fn thread_growth(since: usize) -> isize {
    thread_allocated().wrapping_sub(since) as isize
}

/// The peak of the process-wide reservation so far: at least the peak of
/// the live heap, and above it by at most the threads' stock (module docs).
pub fn peak() -> usize {
    SHARED.peak.load(Ordering::Relaxed)
}

/// How many times the process-wide counter has been updated (a diagnostic:
/// the allocator touches it once per [`THREAD_STOCK`] bytes of net growth
/// or shrinkage of a thread's heap, and for every request of at least
/// [`THREAD_STOCK`] bytes, not on every allocation).
pub fn shared_updates() -> usize {
    SHARED.updates.load(Ordering::Relaxed)
}

/// Set the hard and soft limits (bytes). `soft` is clamped to `hard`.
pub fn set_limits(hard: usize, soft: usize) {
    LIMITS.hard.store(hard, Ordering::Relaxed);
    LIMITS.soft.store(soft.min(hard), Ordering::Relaxed);
}

/// The current (hard, soft) limits in bytes.
pub fn limits() -> (usize, usize) {
    (
        LIMITS.hard.load(Ordering::Relaxed),
        LIMITS.soft.load(Ordering::Relaxed),
    )
}

/// True when the soft limit is exceeded ([`allocated`] above it); long-running
/// loops should stop and report failure (never success). Cheap enough to
/// poll often: a thread-local read and two loads of rarely written atomics.
/// A `true` answer is remembered for the calling thread
/// ([`take_soft_limit_hit`]), so a build can report that a check failed for
/// memory (a resource failure, never a proof result; DESIGN.md §15.8).
#[inline]
pub fn soft_limit_exceeded() -> bool {
    let hit = allocated() > LIMITS.soft.load(Ordering::Relaxed);
    if hit {
        SOFT_HIT.with(|c| c.set(true));
    }
    hit
}

thread_local! {
    /// [`soft_limit_exceeded`] answered `true` on this thread.
    static SOFT_HIT: Cell<bool> = const { Cell::new(false) };
}

/// Whether [`soft_limit_exceeded`] answered `true` on this thread since the
/// last call (the flag is cleared).
pub fn take_soft_limit_hit() -> bool {
    SOFT_HIT.with(|c| c.replace(false))
}

/// Read `SANDBLASTER_MEM_LIMIT_GB` (hard limit in GiB; soft = 75%). Call once
/// at startup, outside the allocator.
pub fn init_from_env() {
    if let Ok(v) = std::env::var("SANDBLASTER_MEM_LIMIT_GB")
        && let Ok(gb) = v.trim().parse::<f64>()
        && gb > 0.0
    {
        let hard = (gb * (1u64 << 30) as f64) as usize;
        set_limits(hard, hard / 4 * 3);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_and_refuses_beyond_the_hard_limit() {
        let before = allocated();
        let v = vec![0u8; 1 << 20];
        assert!(allocated() >= before + (1 << 20));
        drop(v);
        let (hard, soft) = limits();
        // A soft limit below current usage is reported as exceeded.
        set_limits(hard, 0);
        assert!(soft_limit_exceeded());
        set_limits(hard, soft);
        // try_reserve beyond the hard limit fails gracefully (no abort).
        let mut big: Vec<u8> = Vec::new();
        assert!(big.try_reserve_exact(hard + 1).is_err());
    }
}
