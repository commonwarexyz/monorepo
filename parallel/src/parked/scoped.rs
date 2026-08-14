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
//! The caller participates in its own job while claimable work remains, spins a bounded
//! window on the completion predicate (straggler chunks usually land within microseconds,
//! and the window saves a futex round-trip per run), then blocks on a completion latch.
//! Panics in chunks are caught where they happen: workers store the first payload, close
//! the job, and return to their loop; only the caller resumes the payload, after every
//! executor has finished touching the frame.

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

/// Rounds the caller spins on the completion predicate before blocking on the latch (see
/// [`Job::wait_done`]). Set by the gate benches alongside `SEARCH_ROUNDS`.
#[cfg(not(any(feature = "loom", miri)))]
const DONE_SPIN_ROUNDS: usize = 64;

/// Payload of a caught chunk panic.
pub(super) type Payload = Box<dyn core::any::Any + Send + 'static>;

/// Control surface a body may use to stop further claims (fallible operations record their
/// error and close; infallible bodies ignore it).
pub(super) struct Ctl<'a> {
    job: &'a Job,
}

impl Ctl<'_> {
    /// Closes the job: no further ranges will be claimed. In-flight chunks finish normally.
    pub(super) fn close(&self) {
        self.job.close();
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
    /// Maximum concurrent executors for this job (the strategy's parallelism): the
    /// participant cap, and the divisor for guided chunk sizing.
    max_executors: usize,
    /// Claim granularity floor for this job. [`MIN_CHUNK`] for per-item bodies; callers
    /// whose items are themselves coarse work units (a run to sort, a pair of runs to
    /// merge, one side of a join) pass 1 so single items can be claimed and fanned out.
    min_chunk: usize,
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
    fn new<F: Fn(Range<usize>, &Ctl<'_>) + Sync>(
        body: &F,
        len: usize,
        max_executors: usize,
        min_chunk: usize,
    ) -> Self {
        Self {
            // The one lifetime erasure: sound per the module safety model, because `run`
            // keeps `body`'s frame alive until no executor can reach this pointer.
            data: body as *const F as *const (),
            call: call_shim::<F>,
            len,
            max_executors: max_executors.max(1),
            min_chunk: min_chunk.max(1),
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

    /// Closes the job: no further ranges will be claimed. In-flight chunks finish normally.
    fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
        // Executing-vs-close handshake (see drive).
        fence(Ordering::SeqCst);
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
        self.close();
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
    ///
    /// Spins a bounded window on the predicate first: the guided chunking shrinks tail
    /// chunks toward the claim floor, so a straggler usually finishes within microseconds
    /// of the caller exhausting claims, and the spin saves a futex round-trip (sleep and
    /// wake) on the tail of most scoped runs. Bounded, so a long straggler still parks
    /// the caller; disabled under loom (the modeled protocol needs no schedule hint) and
    /// miri (spinning wastes interpreter time).
    fn wait_done(&self) {
        #[cfg(not(any(feature = "loom", miri)))]
        for _ in 0..DONE_SPIN_ROUNDS {
            if self.done() {
                return;
            }
            super::sync::spin();
        }
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
    /// traffic would dwarf the work itself. Saturating: an absurd planning parallelism must
    /// degrade to floor-sized chunks, not panic mid-claim.
    fn chunk(&self, remaining: usize) -> usize {
        (remaining / self.max_executors.saturating_mul(2)).max(self.min_chunk)
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

/// Leaves the executing set on drop, so the executing count balances even if the claim
/// path unwinds outside the body's `catch_unwind` (the completion latch would otherwise
/// wait forever on a count that can no longer reach zero).
struct ExecutingGuard<'a>(&'a Job);

impl Drop for ExecutingGuard<'_> {
    fn drop(&mut self) {
        finish_executing(self.0);
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
    if job.participants.fetch_add(1, Ordering::SeqCst) >= job.max_executors {
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
        //
        // The guard leaves the executing set on every exit from this iteration, including
        // an unwind from the claim path itself: the completion latch must never wait on a
        // count that cannot drain.
        job.executing.fetch_add(1, Ordering::SeqCst);
        let executing = ExecutingGuard(job);
        // Executing-vs-close handshake: order our entry before the closed check against
        // the closer's closed-store-then-executing-check (via done()).
        fence(Ordering::SeqCst);
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
        drop(executing);
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

    /// Pins the slot and, if it holds a published job, calls `f` on it; `None` when the
    /// slot is not published. The pin is released even if `f` unwinds, so an unwinding
    /// callback cannot strand the unpublisher's pins wait.
    fn with_pinned<R>(&self, f: impl FnOnce(&Job) -> R) -> Option<R> {
        /// Releases the pin on every exit path, including unwinds.
        struct PinGuard<'a>(&'a Slot);
        impl Drop for PinGuard<'_> {
            fn drop(&mut self) {
                self.0.pins.fetch_sub(1, Ordering::SeqCst);
            }
        }

        // Pin FIRST, then validate: the unpublisher stores DRAINING before waiting on
        // `pins`, so a pin taken after the store observes non-PUBLISHED and unpins without
        // touching the pointer, and a pin taken before the store is waited out.
        self.pins.fetch_add(1, Ordering::SeqCst);
        let _pin = PinGuard(self);
        // Pin-vs-unpublish handshake: order our pin before the state check against the
        // unpublisher's DRAINING-store-then-pins-check.
        fence(Ordering::SeqCst);
        if self.state.load(Ordering::SeqCst) == PUBLISHED {
            let ptr = self.job.load(Ordering::SeqCst);
            debug_assert!(!ptr.is_null(), "PUBLISHED slot with null job");
            // SAFETY: PUBLISHED observed while pinned. Unpublishing stores DRAINING and
            // then waits for `pins == 0` before the job frame may die, and re-installation
            // requires the slot to first reach EMPTY (after that wait), so our pin keeps
            // this exact referent alive until we unpin.
            Some(f(unsafe { &*ptr }))
        } else {
            None
        }
    }

    /// Whether this slot holds work a new executor could actually claim (racy by design).
    ///
    /// Distinguishes "published" from "claimable": a job whose ranges are all claimed (or
    /// that is closed, or already at its participant cap) offers nothing to a searching
    /// worker, and treating it as work would keep every worker hot-spinning for the
    /// duration of a straggler chunk.
    pub(super) fn looks_claimable(&self) -> bool {
        // Unpinned pre-check: this probe runs in every idle-scan round.
        if self.state.load(Ordering::SeqCst) != PUBLISHED {
            return false;
        }
        self.with_pinned(|job| {
            !job.closed.load(Ordering::SeqCst)
                && job.next.load(Ordering::SeqCst) < job.len
                && job.participants.load(Ordering::SeqCst) < job.max_executors
        })
        .unwrap_or(false)
    }

    /// Pins the slot and, if it holds a published job, drives it. Returns whether any chunk
    /// was executed. Safe to call from any worker at any time.
    pub(super) fn try_drive(&self) -> bool {
        self.with_pinned(drive).unwrap_or(false)
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
/// `min_chunk` is the claim granularity floor: [`MIN_CHUNK`] for per-item bodies, 1 for
/// bodies whose items are themselves coarse work units (sort runs, merge pairs, join sides).
///
/// Returns only after every executor has stopped touching `body`'s frame; the borrowed body
/// and everything it captures are safe to drop after this returns, on every path.
pub(super) fn run<F: Fn(Range<usize>, &Ctl<'_>) + Sync>(
    pool: &super::pool::Shared,
    len: usize,
    parallelism: usize,
    min_chunk: usize,
    body: &F,
) -> Outcome {
    if len == 0 {
        return Outcome {
            claimed: 0,
            panic: None,
        };
    }

    // The participant cap is the STRATEGY's parallelism (the caller plus helpers), which
    // may differ from the pool's worker count; a single job never runs on more executors
    // than the strategy plans for.
    let cap = parallelism.max(1);
    let job = Job::new(body, len, cap, min_chunk);

    /// Tears the job down if `run` unwinds after publication: closes it against further
    /// claims, waits out in-flight executors, and unpublishes the slot, so the lifetime
    /// invariant (no executor can reach the job after `run` returns or unwinds) holds even
    /// if something on the claim path panics -- without it, an internal unwind would
    /// destroy the stack Job behind a still-PUBLISHED slot.
    ///
    /// `Drop` is the UNWIND path only; normal completion goes through [`RunGuard::finish`],
    /// which must NOT close: the caller can be rejected by the participant cap when enough
    /// lingering workers beat it into the job, and closing then would abandon unclaimed
    /// chunks of a job that completed no-panic in the workers' hands (observed as silent
    /// partial sort rounds).
    struct RunGuard<'a> {
        job: &'a Job,
        slot: Option<&'a Slot>,
    }
    impl RunGuard<'_> {
        /// Normal completion: wait for the job, unpublish, and disarm the drop.
        fn finish(self) {
            self.job.wait_done();
            if let Some(slot) = self.slot {
                slot.unpublish();
            }
            core::mem::forget(self);
        }
    }
    impl Drop for RunGuard<'_> {
        fn drop(&mut self) {
            self.job.close();
            self.job.wait_done();
            if let Some(slot) = self.slot {
                slot.unpublish();
            }
        }
    }

    // Publish before waking so woken workers find the job. Overflow (no empty slot) means
    // the caller executes the whole job inline: submission never blocks on capacity.
    let slot = pool.try_install(&job);
    let guard = RunGuard {
        job: &job,
        slot: slot.map(|idx| pool.slot(idx)),
    };
    if slot.is_some() {
        // Wake only as many helpers as can actually claim a chunk: the caller is one
        // executor, chunks are at least `min_chunk` items, and helpers beyond the pool's
        // worker count do not exist. Waking more would unpark workers into an immediate
        // bounce (scan, fail to claim, search window, re-park) -- the idle tax itself.
        let usable = len.div_ceil(min_chunk.max(1)).min(cap);
        let budget = usable.saturating_sub(1).min(pool.workers());
        pool.wake(budget);
    }

    // Participate while claimable work remains, then block on the completion latch and
    // unpublish before the job and the body's frame may die.
    drive(&job);
    guard.finish();

    let claimed = job.next.load(Ordering::Acquire).min(job.len);
    let panic = job.panic.lock().unwrap().take();
    Outcome { claimed, panic }
}
