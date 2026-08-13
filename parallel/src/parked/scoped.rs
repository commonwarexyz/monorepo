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
//! Every announce-store/cross-check-load handshake in this module (pin vs unpublish,
//! executing vs close, publish vs wake) uses an explicit `fence(SeqCst)` between the
//! announcement and the check on BOTH sides. Per-access SeqCst alone is sufficient under
//! the C++11 total order, but loom deliberately under-models SeqCst accesses, and the
//! fence form makes the required ordering visible by construction; loom is the safety
//! oracle for this module, so the fenced form is the shipped form.
//!
//! The caller participates in its own job while claimable work remains, then blocks on a
//! completion latch (never spinning on counters). Panics in chunks are caught where they
//! happen: workers store the first payload, close the job, and return to their loop; only
//! the caller resumes the payload, after every executor has finished touching the frame.

use super::sync::{
    AtomicBool, AtomicPtr, AtomicU8, AtomicUsize, Condvar, Mutex, Ordering, fence, spin,
};
use core::ops::Range;
use std::panic::{self, AssertUnwindSafe};

/// Minimum items per claim: bounds the per-item share of claim/handshake overhead on
/// small jobs while leaving straggler rebalancing intact at realistic sizes. Set by the
/// burst-train gate bench alongside `SEARCH_ROUNDS`. Under loom the floor is 1 so tiny
/// models still produce multiple claimable chunks: the chunking POLICY differs from
/// production there, but the claim/close/completion PROTOCOL under test is identical.
#[cfg(not(feature = "loom"))]
pub(super) const MIN_CHUNK: usize = 32;
#[cfg(feature = "loom")]
pub(super) const MIN_CHUNK: usize = 1;

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
        // Executing-vs-close handshake (see drive).
        fence(Ordering::SeqCst);
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
    /// Executors currently inside [`drive`] for this job. Capped at `executors` so a single
    /// job never runs on more executors than the pool's parallelism.
    participants: AtomicUsize,
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
            participants: AtomicUsize::new(0),
            completed: AtomicUsize::new(0),
            executing: AtomicUsize::new(0),
            closed: AtomicBool::new(false),
            panic: Mutex::new(None),
            latch: Mutex::new(false),
            latch_cv: Condvar::new(),
        }
    }

    /// Records a panic payload (first wins) and closes the job. A losing payload is dropped
    /// under `catch_unwind`: a payload whose `Drop` panics must not unwind out of a worker
    /// (which would leak its slot pin and hang unpublish forever).
    fn poison(&self, payload: Payload) {
        let losing = {
            let mut slot = self.panic.lock().unwrap();
            if slot.is_none() {
                *slot = Some(payload);
                None
            } else {
                Some(payload)
            }
        };
        self.closed.store(true, Ordering::SeqCst);
        // Executing-vs-close handshake (see drive).
        fence(Ordering::SeqCst);
        if let Some(payload) = losing {
            if let Err(second) = panic::catch_unwind(AssertUnwindSafe(move || drop(payload))) {
                // A payload whose Drop panics with ANOTHER Drop-panicking payload: leak it
                // rather than let any depth of malice unwind out of a worker.
                core::mem::forget(second);
            }
        }
    }

    /// Whether the completion predicate holds: all items completed, or the job is closed and
    /// nothing is executing (nobody will complete the rest).
    fn done(&self) -> bool {
        if self.completed.load(Ordering::Acquire) == self.len {
            return true;
        }
        if !self.closed.load(Ordering::SeqCst) {
            return false;
        }
        // Executing-vs-close handshake: order the closed read before the executing read,
        // so a claimant that missed the close is seen executing here.
        fence(Ordering::SeqCst);
        self.executing.load(Ordering::SeqCst) == 0
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
    /// contention, shrinking toward the tail so straggler chunks rebalance. The floor keeps
    /// tiny jobs from being shredded into per-item claims, where the SeqCst claim/handshake
    /// traffic would dwarf the work itself.
    fn chunk(&self, remaining: usize) -> usize {
        (remaining / (2 * self.executors)).max(MIN_CHUNK)
    }
}

/// Leaves the executing set, signaling the completion latch if this makes the job done.
fn finish_executing(job: &Job) {
    let was_last = job.executing.fetch_sub(1, Ordering::SeqCst) == 1;
    if job.completed.load(Ordering::Acquire) == job.len
        || (job.closed.load(Ordering::SeqCst) && was_last)
    {
        job.wake_waiter();
    }
}

/// Runs the claim loop against `job` until no more work is claimable. Returns whether any
/// chunk was executed. Used by workers (under a slot pin) and by the submitting caller.
///
/// Panics in the body are caught here: the first payload is stored on the job, the job is
/// closed, and claiming stops. This function never unwinds.
pub(super) fn drive(job: &Job) -> bool {
    // Participant cap: a single job never runs on more executors than the pool's
    // parallelism; excess workers leave immediately and can park.
    if job.participants.fetch_add(1, Ordering::SeqCst) >= job.executors {
        job.participants.fetch_sub(1, Ordering::SeqCst);
        return false;
    }
    let mut any = false;
    loop {
        // Enter the executing set BEFORE claiming, then re-check `closed`. This pairs with
        // `done()`'s `closed && executing == 0` (both SeqCst): once a closer observes
        // `executing == 0` after storing `closed`, every later would-be claimant must see
        // `closed` here and back out, so no chunk can start after the completion latch
        // releases. That is what makes `Ctl::close`'s "no further ranges will be claimed"
        // and unpublish's "residual pins run no user code" contracts hold.
        job.executing.fetch_add(1, Ordering::SeqCst);
        // Executing-vs-close handshake: order our entry before the closed check against
        // the closer's closed-store-then-executing-check (via done()).
        fence(Ordering::SeqCst);
        if job.closed.load(Ordering::SeqCst) {
            finish_executing(job);
            break;
        }
        let claimed = job.next.load(Ordering::Relaxed);
        if claimed >= job.len {
            finish_executing(job);
            break;
        }
        let c = job.chunk(job.len - claimed);
        let start = job.next.fetch_add(c, Ordering::AcqRel);
        if start >= job.len {
            finish_executing(job);
            break;
        }
        let end = (start + c).min(job.len);
        any = true;
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
        finish_executing(job);
    }
    job.participants.fetch_sub(1, Ordering::SeqCst);
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

    /// Whether this slot holds work a new executor could actually claim (racy by design).
    ///
    /// Distinguishes "published" from "claimable": a job whose ranges are all claimed (or
    /// that is closed, or already at its participant cap) offers nothing to a searching
    /// worker, and treating it as work would keep every worker hot-spinning for the
    /// duration of a straggler chunk.
    pub(super) fn looks_claimable(&self) -> bool {
        if self.state.load(Ordering::SeqCst) != PUBLISHED {
            return false;
        }
        self.pins.fetch_add(1, Ordering::SeqCst);
        // Pin-vs-unpublish handshake: order our pin before the state check against the
        // unpublisher's DRAINING-store-then-pins-check.
        fence(Ordering::SeqCst);
        let claimable = if self.state.load(Ordering::SeqCst) == PUBLISHED {
            let ptr = self.job.load(Ordering::SeqCst);
            debug_assert!(!ptr.is_null(), "PUBLISHED slot with null job");
            // SAFETY: PUBLISHED observed while pinned; see `try_drive`.
            let job = unsafe { &*ptr };
            !job.closed.load(Ordering::SeqCst)
                && job.next.load(Ordering::SeqCst) < job.len
                && job.participants.load(Ordering::SeqCst) < job.executors
        } else {
            false
        };
        self.pins.fetch_sub(1, Ordering::SeqCst);
        claimable
    }

    /// Pins the slot and, if it holds a published job, drives it. Returns whether any chunk
    /// was executed. Safe to call from any worker at any time.
    pub(super) fn try_drive(&self) -> bool {
        // Pin FIRST, then validate: the unpublisher stores DRAINING before waiting on
        // `pins`, so a pin taken after the store observes non-PUBLISHED and unpins without
        // touching the pointer, and a pin taken before the store is waited out.
        self.pins.fetch_add(1, Ordering::SeqCst);
        // Pin-vs-unpublish handshake (see looks_claimable).
        fence(Ordering::SeqCst);
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
        // Publish-vs-register handshake: order the publication before the submitter's
        // idle-registry scan, pairing with the worker's register-then-recheck fence.
        fence(Ordering::SeqCst);
        true
    }

    /// Unpublishes the slot's job and waits until no thread can still reach it.
    pub(super) fn unpublish(&self) {
        self.state.store(DRAINING, Ordering::SeqCst);
        // Pin-vs-unpublish handshake: order the DRAINING store before the pins check, so
        // any pin that missed DRAINING is seen here (and waited out).
        fence(Ordering::SeqCst);
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
    parallelism: usize,
    body: &F,
) -> Outcome {
    if len == 0 {
        return Outcome {
            claimed: 0,
            panic: None,
        };
    }

    // The participant cap is the STRATEGY's parallelism (the caller plus helpers), which
    // may differ from the pool's worker count (`with_parallelism`); a single job never
    // runs on more executors than the strategy plans for.
    let cap = parallelism.max(1);
    let job = Job::new(body, len, cap);
    // Publish before waking so woken workers find the job. Overflow (no empty slot) means
    // the caller executes the whole job inline: submission never blocks on capacity.
    let slot = pool.try_install(&job);
    if slot.is_some() {
        // Wake only as many helpers as can actually claim a chunk: the caller is one
        // executor, chunks are at least MIN_CHUNK items, and helpers beyond the pool's
        // worker count do not exist. Waking more would unpark workers into an immediate
        // bounce (scan, fail to claim, search window, re-park) -- the idle tax itself.
        let usable = len.div_ceil(MIN_CHUNK).min(cap);
        let budget = usable.saturating_sub(1).min(pool.workers());
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
