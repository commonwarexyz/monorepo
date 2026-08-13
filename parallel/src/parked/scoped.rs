//! The scoped-job core: one erased primitive that runs a chunk-claiming loop over `0..len`
//! against a caller-frame body, plus the slot publication protocol that lets persistent
//! workers help without extending any lifetime.
//!
//! # Safety model
//!
//! Exactly one lifetime erasure exists in this module: [`Job`] stores the caller's borrowed
//! body closure as `(data: *const (), call: unsafe fn)` so pool workers can invoke it.
//! Two invariants make every use sound:
//!
//! 1. **Range exclusivity**: a claimed range is executed by exactly one executor, exactly
//!    once (claims are `fetch_add` on a monotonic cursor).
//! 2. **Pinning**: a worker touches the erased body only while holding a pin on the slot
//!    that published it. [`run`] does not return -- and therefore the caller frame that owns
//!    the [`Job`] and everything the body borrows cannot die -- until the job is unpublished
//!    and `pins == 0`.
//!
//! The caller participates in its own job while claimable work remains, then blocks on a
//! completion latch (never spinning on counters). Panics in chunks are caught where they
//! happen: workers store the first payload, close the job, and return to their loop; only
//! the caller resumes the payload, after every executor has finished touching the frame.

use super::sync::{AtomicBool, AtomicPtr, AtomicU8, AtomicUsize, Condvar, Mutex, Ordering, spin};
use core::ops::Range;
use std::panic::{self, AssertUnwindSafe};

/// Payload of a caught chunk panic.
type Payload = Box<dyn core::any::Any + Send + 'static>;

/// Control surface a body may use to stop further claims (fallible operations record their
/// error and close; infallible bodies ignore it).
pub(super) struct Ctl<'a> {
    job: &'a Job,
}

impl Ctl<'_> {
    /// Closes the job: no further ranges will be claimed. In-flight chunks finish normally.
    pub(super) fn close(&self) {
        self.job.closed.store(true, Ordering::SeqCst);
    }
}

/// Invokes the type-erased body. `data` must point to a live `F` chosen at erasure time.
unsafe fn call_shim<F: Fn(Range<usize>, &Ctl<'_>) + Sync>(
    data: *const (),
    range: Range<usize>,
    ctl: &Ctl<'_>,
) {
    // SAFETY: the caller guarantees `data` points to a live `F` (see the module safety
    // model: the owning frame is pinned for as long as this pointer is reachable).
    let body = unsafe { &*(data as *const F) };
    body(range, ctl);
}

/// Shared state of one scoped job. Lives in the frame of [`run`]; published to workers via a
/// [`Slot`] under the pin protocol.
pub(super) struct Job {
    /// Erased pointer to the caller-frame body closure.
    data: *const (),
    /// Monomorphic shim that reconstitutes the closure type and calls it.
    call: unsafe fn(*const (), Range<usize>, &Ctl<'_>),
    /// Total number of items.
    len: usize,
    /// Executor count hint for chunk sizing (workers + caller).
    executors: usize,
    /// Claim cursor: the next unclaimed index. Monotonic; claims are `[start, start + c)`.
    next: AtomicUsize,
    /// Number of items whose body execution completed successfully.
    completed: AtomicUsize,
    /// Number of executors currently inside a claimed chunk.
    executing: AtomicUsize,
    /// Closed against further claims (panic, error, or cancellation).
    closed: AtomicBool,
    /// First caught panic payload; later payloads are dropped.
    panic: Mutex<Option<Payload>>,
    /// Completion latch: signaled when `completed == len`, or the job is closed and the last
    /// in-flight chunk finished.
    latch: Mutex<bool>,
    latch_cv: Condvar,
}

// SAFETY: `data` points to a `Sync` closure (enforced by the `F: Sync` bound at the only
// construction site) and is only used under the pin protocol; all other fields are Sync.
unsafe impl Sync for Job {}

impl Job {
    fn new<F: Fn(Range<usize>, &Ctl<'_>) + Sync>(body: &F, len: usize, executors: usize) -> Self {
        Self {
            // The one lifetime erasure: sound per the module safety model, because `run`
            // keeps `body`'s frame alive until no executor can reach this pointer.
            data: body as *const F as *const (),
            call: call_shim::<F>,
            len,
            executors: executors.max(1),
            next: AtomicUsize::new(0),
            completed: AtomicUsize::new(0),
            executing: AtomicUsize::new(0),
            closed: AtomicBool::new(false),
            panic: Mutex::new(None),
            latch: Mutex::new(false),
            latch_cv: Condvar::new(),
        }
    }

    /// Records a panic payload (first wins) and closes the job.
    fn poison(&self, payload: Payload) {
        {
            let mut slot = self.panic.lock().unwrap();
            if slot.is_none() {
                *slot = Some(payload);
            }
        }
        self.closed.store(true, Ordering::SeqCst);
    }

    /// Whether the completion predicate holds: all items completed, or the job is closed and
    /// nothing is executing (nobody will complete the rest).
    fn done(&self) -> bool {
        self.completed.load(Ordering::Acquire) == self.len
            || (self.closed.load(Ordering::SeqCst) && self.executing.load(Ordering::Acquire) == 0)
    }

    /// Signals the completion latch.
    fn wake_waiter(&self) {
        let mut done = self.latch.lock().unwrap();
        *done = true;
        self.latch_cv.notify_all();
    }

    /// Blocks until the completion predicate holds.
    fn wait_done(&self) {
        loop {
            if self.done() {
                return;
            }
            {
                let mut done = self.latch.lock().unwrap();
                // Recheck under the lock so a signal that raced our predicate check is not
                // missed; then wait for the next signal and consume it.
                if self.done() {
                    return;
                }
                while !*done {
                    done = self.latch_cv.wait(done).unwrap();
                }
                *done = false;
            }
        }
    }

    /// The chunk size for a claim when `remaining` items are unclaimed: large early for low
    /// contention, shrinking toward the tail so straggler chunks rebalance.
    fn chunk(&self, remaining: usize) -> usize {
        (remaining / (2 * self.executors)).max(1)
    }
}

/// Runs the claim loop against `job` until no more work is claimable. Returns whether any
/// chunk was executed. Used by workers (under a slot pin) and by the submitting caller.
///
/// Panics in the body are caught here: the first payload is stored on the job, the job is
/// closed, and claiming stops. This function never unwinds.
pub(super) fn drive(job: &Job) -> bool {
    let mut any = false;
    loop {
        if job.closed.load(Ordering::SeqCst) {
            break;
        }
        let claimed = job.next.load(Ordering::Relaxed);
        if claimed >= job.len {
            break;
        }
        let c = job.chunk(job.len - claimed);
        let start = job.next.fetch_add(c, Ordering::AcqRel);
        if start >= job.len {
            break;
        }
        let end = (start + c).min(job.len);
        any = true;
        job.executing.fetch_add(1, Ordering::AcqRel);
        let ctl = Ctl { job };
        // SAFETY: the body pointer is valid per the module safety model (we are either the
        // owning caller or a worker pinned on the publishing slot).
        let result = panic::catch_unwind(AssertUnwindSafe(|| unsafe {
            (job.call)(job.data, start..end, &ctl)
        }));
        match result {
            Ok(()) => {
                job.completed.fetch_add(end - start, Ordering::AcqRel);
            }
            Err(payload) => {
                // The typed wrapper already cleaned this chunk's partial state before
                // rethrowing; record the first payload and stop claiming.
                job.poison(payload);
            }
        }
        let was_last = job.executing.fetch_sub(1, Ordering::AcqRel) == 1;
        if job.completed.load(Ordering::Acquire) == job.len
            || (job.closed.load(Ordering::SeqCst) && was_last)
        {
            job.wake_waiter();
        }
    }
    any
}

/// Slot lifecycle states.
const EMPTY: u8 = 0;
const INSTALLING: u8 = 1;
const PUBLISHED: u8 = 2;
const DRAINING: u8 = 3;

/// One publication slot of the K-slot job table.
pub(super) struct Slot {
    /// Lifecycle state; see the constants above.
    state: AtomicU8,
    /// Number of threads currently inside this slot's critical region (between pin
    /// acquisition and release). The unpublisher waits for zero before the job frame may die.
    pins: AtomicUsize,
    /// The published job; valid to dereference only while pinned and `state == PUBLISHED`.
    job: AtomicPtr<Job>,
}

impl Slot {
    pub(super) fn new() -> Self {
        Self {
            state: AtomicU8::new(EMPTY),
            pins: AtomicUsize::new(0),
            job: AtomicPtr::new(core::ptr::null_mut()),
        }
    }

    /// Whether this slot currently looks published (cheap scan probe; racy by design).
    pub(super) fn looks_published(&self) -> bool {
        self.state.load(Ordering::SeqCst) == PUBLISHED
    }

    /// Pins the slot and, if it holds a published job, drives it. Returns whether any chunk
    /// was executed. Safe to call from any worker at any time.
    pub(super) fn try_drive(&self) -> bool {
        // Pin FIRST, then validate: the unpublisher stores DRAINING before waiting on
        // `pins`, so a pin taken after the store observes non-PUBLISHED and unpins without
        // touching the pointer, and a pin taken before the store is waited out.
        self.pins.fetch_add(1, Ordering::SeqCst);
        let executed = if self.state.load(Ordering::SeqCst) == PUBLISHED {
            let ptr = self.job.load(Ordering::SeqCst);
            // SAFETY: `state == PUBLISHED` observed while pinned. Unpublishing stores
            // DRAINING and then waits for `pins == 0` before the job frame may die, and
            // re-installation requires the slot to first reach EMPTY (after that wait), so
            // our pin keeps this exact referent alive until we unpin.
            drive(unsafe { &*ptr })
        } else {
            false
        };
        self.pins.fetch_sub(1, Ordering::SeqCst);
        executed
    }

    /// Attempts to publish `job` into this slot. Returns false if the slot is not empty.
    pub(super) fn try_publish(&self, job: &Job) -> bool {
        if self
            .state
            .compare_exchange(EMPTY, INSTALLING, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return false;
        }
        self.job
            .store(job as *const Job as *mut Job, Ordering::SeqCst);
        self.state.store(PUBLISHED, Ordering::SeqCst);
        true
    }

    /// Unpublishes the slot's job and waits until no thread can still reach it.
    pub(super) fn unpublish(&self) {
        self.state.store(DRAINING, Ordering::SeqCst);
        // Wait out every pinned thread. The caller's completion latch already waited for
        // in-flight chunks, so residual pins are transient scanners between their
        // `fetch_add` and state check; they run no user code before unpinning.
        while self.pins.load(Ordering::SeqCst) != 0 {
            spin();
        }
        self.job.store(core::ptr::null_mut(), Ordering::SeqCst);
        self.state.store(EMPTY, Ordering::SeqCst);
    }
}

/// Outcome of a scoped run, consumed by the typed wrappers for cleanup decisions.
pub(super) struct Outcome {
    /// The stable claim watermark: indexes `>= claimed` were never claimed by any executor.
    pub(super) claimed: usize,
    /// The first panic payload, if any chunk panicked. The wrapper performs its cleanup and
    /// then resumes this payload.
    pub(super) panic: Option<Payload>,
}

/// The single scoped primitive: runs `body` over `0..len` with the caller participating and
/// up to `workers - 1` woken helpers assisting via the slot table.
///
/// Returns only after every executor has stopped touching `body`'s frame; the borrowed body
/// and everything it captures are safe to drop after this returns, on every path.
pub(super) fn run<F: Fn(Range<usize>, &Ctl<'_>) + Sync>(
    pool: &super::pool::Shared,
    len: usize,
    body: &F,
) -> Outcome {
    if len == 0 {
        return Outcome {
            claimed: 0,
            panic: None,
        };
    }

    let job = Job::new(body, len, pool.workers() + 1);
    // Publish before waking so woken workers find the job. Overflow (no empty slot) means
    // the caller executes the whole job inline: submission never blocks on capacity.
    let slot = pool.try_install(&job);
    if slot.is_some() {
        // Wake at most workers-1 helpers: the caller is an executor too, so a single job's
        // executor count stays at the pool's parallelism.
        let budget = pool.workers().saturating_sub(1).min(len.saturating_sub(1));
        pool.wake(budget);
    }

    // Participate while claimable work remains, then block on the completion latch.
    drive(&job);
    job.wait_done();

    // Unpublish and drain pins before the job (and the body's frame) may die.
    if let Some(idx) = slot {
        pool.slot(idx).unpublish();
    }

    let claimed = job.next.load(Ordering::Acquire).min(job.len);
    let panic = job.panic.lock().unwrap().take();
    Outcome { claimed, panic }
}
