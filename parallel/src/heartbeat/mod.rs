//! Experimental caller-runs thread pool with heartbeat promotion.
//!
//! This module explores replacing the adaptive serial-vs-parallel policy used by
//! [`crate::Rayon`] with a scheduler that makes the decision structurally instead of
//! statistically. It follows the heartbeat scheduling construction of Acar, Chargueraud,
//! Muller, and Rainey ("Heartbeat Scheduling: Provable Efficiency for Nested Parallelism",
//! PLDI 2018), popularized by the Spice (Zig) and Chili (Rust) libraries.
//!
//! # Motivation
//!
//! Every parallel collection operation faces the same decision: is this call large enough
//! that distributing it across threads beats running it serially? Entering a conventional
//! thread pool costs tens of microseconds (job posting, worker wakeups, cache migration), so
//! dispatching a call that folds a handful of elements can be a thousand times slower than a
//! serial loop. The crate currently answers the question empirically: [`crate::Rayon`] times
//! both paths per callsite and size bucket and replays whichever was faster. That works, but
//! it carries permanent costs: a lookup on every call, mispredictions on the first call and
//! whenever timing samples are noisy, stale estimates that are never revisited, and a
//! serial and a parallel body for every operation.
//!
//! Heartbeat scheduling inverts the question. No prediction is made at all: every call runs
//! on the calling thread as ordinary serial recursion, and forked work is merely marked as
//! available for theft at a cost of a few nanoseconds per fork. Marked forks become actually
//! stealable only when a periodic heartbeat promotes them, so scheduling overhead is bounded
//! by construction (at most one promotion per interval per thread) rather than by a model or
//! a measurement. A call that completes within one heartbeat interval is a serial call,
//! automatically; a call that outlives the interval starts spreading across the pool,
//! automatically. Neither outcome required knowing the input size, the per-element cost, or
//! the pool load in advance.
//!
//! The intended contract, in three bands of per-call work:
//!
//! - Below one interval: indistinguishable from serial execution. Callers should never
//!   hesitate to route work through the pool.
//! - Within a few intervals: bounded indifference. The call may pay up to roughly one
//!   interval of ramp overhead over the better of serial or parallel execution, and can
//!   run modestly slower than serial in the worst case. This band is deliberately
//!   sacrificed for simplicity.
//! - Above that: full scaling. Ramp-up is a fixed three to four intervals, which genuinely
//!   large workloads amortize to noise.
//!
//! # Design
//!
//! - [`Scope::join`] pushes the second closure onto a thread-local list of latent forks and
//!   runs the first closure inline. On return, if the fork was never promoted, the second
//!   closure also runs inline: the whole call is an ordinary serial recursion plus one
//!   vector push, one branch, and one vector pop. Because `join` does not return until both
//!   closures complete, the closures may borrow non-`'static` data, including disjoint
//!   `&mut` splits of a slice.
//! - Heartbeats are self-timed at fork points; there is no ticker thread. Every
//!   [`BEAT_CHECK_FORKS`] forks a scope reads the clock, and if [`Pool::interval`] has
//!   elapsed since its last beat it promotes its oldest latent fork (the largest pending
//!   subtree) into a shared queue. The first check only establishes a baseline, so
//!   activations shorter than one interval never promote and, if they fork fewer than
//!   [`BEAT_CHECK_FORKS`] times, never read the clock at all.
//! - Promotion is demand-gated: a fork is promoted only when idle threads outnumber queued
//!   jobs. A saturated pool keeps forks local, where resolving them is free, instead of
//!   churning them through the queue for their owners to reclaim.
//! - A worker executing a claimed fork starts its scope with the first beat already due
//!   (checked at its first fork). A steal is evidence that the surrounding computation has
//!   outlived one interval, so expansion accelerates exactly where that evidence exists,
//!   while fresh caller scopes stay conservative. Parallelism therefore spreads
//!   geometrically, roughly doubling per interval, from whoever holds the most work.
//! - When a joining frame finds its fork promoted, it first tries to reclaim it from the
//!   shared queue (nobody claimed it: run inline). If a worker claimed it, the frame counts
//!   itself as an idle thread, registering demand so beats route work toward it, and
//!   executes other queued jobs while it waits instead of parking.
//! - Idle workers poll a lock-free queue-length hint for [`SPIN_BEFORE_PARK`] before
//!   parking, so promotions during busy periods are claimed in microseconds instead of
//!   paying a futex wake. Wake latency otherwise dominates ramp-up on medium-sized work.
//!
//! Promotion cadence is tied to fork frequency: a leaf that runs for a long time without
//! forking delays promotion of the forks pending above it. Recursive divide-and-conquer
//! workloads fork constantly, so in practice beats land within one leaf of the interval.
//!
//! # Tuning
//!
//! The knobs are few and carry physical units:
//!
//! - [`Pool::interval`] is the definition of "small": the per-call work below which the pool
//!   promises serial-speed execution, and the cadence at which parallelism ramps above it.
//!   Intervals below the worker wake latency buy nothing; larger intervals widen the
//!   guaranteed-cheap band at a fixed (and amortizable) cost to ramp-up.
//! - The `grain` argument of [`fold`] bounds the smallest leaf run as a tight loop. Leaves
//!   should represent at least several times the per-join bookkeeping cost, so a few hundred
//!   nanoseconds of work and up.
//! - [`BEAT_CHECK_FORKS`] and [`SPIN_BEFORE_PARK`] amortize clock reads and futex wakes
//!   respectively and should rarely need attention.
//!
//! There are deliberately no per-call hints and no per-callsite state: the same code path
//! serves every call, and a wrong-sized call costs a bounded constant, never a learned
//! misprediction.
//!
//! # Safety
//!
//! Forked closures and their result slots live on the stack of the `join` frame that created
//! them and are shared with at most one thief through a type-erased pointer. This is sound
//! because `join` does not return (or unwind) until the fork has either been executed, been
//! withdrawn from all shared state, or been waited on to completion; the `done` flag
//! transfers the result with release/acquire ordering. The protocol is exercised under miri
//! by the zero-interval tests.
//!
//! # Limitations
//!
//! - Work in the few-intervals band parallelizes late and can run up to roughly a third
//!   slower than serial in the worst case. This is the accepted trade for having no
//!   prediction machinery.
//! - The pool cannot detect that a workload does not benefit from parallelism (for example
//!   memory-bound folds); it will still promote once the interval elapses. Only measurement
//!   can learn that, and this design deliberately does not measure.
//! - Execution order is nondeterministic, like any work-stealing pool; operations must be
//!   associative exactly as they must be under [`crate::Rayon`]. [`crate::Sequential`]
//!   remains the deterministic strategy for tests.
//! - Helping while waiting couples a joiner's latency to the length of the job it helps
//!   with, and grows the stack with the depth of simultaneously helped jobs.
//!
//! # Status
//!
//! This is an experiment used to evaluate replacing the adaptive policy in [`crate::Rayon`].
//! It is not wired into the [`crate::Strategy`] trait; [`fold`] exists to benchmark the
//! scheduler against the existing strategies.
//!
//! # Examples
//!
//! ```
//! use commonware_parallel::heartbeat::{fold, Pool};
//!
//! let pool = Pool::new(2);
//! let data: Vec<u64> = (0..10_000).collect();
//! let sum = pool.run(|scope| {
//!     fold(scope, &data, 128, &|| 0u64, &|acc, x| acc + x, &|a, b| a + b)
//! });
//! assert_eq!(sum, 49_995_000);
//! ```

use parking_lot::{Condvar, Mutex};
use std::{
    cell::UnsafeCell,
    collections::VecDeque,
    hint,
    panic::{self, AssertUnwindSafe},
    ptr::NonNull,
    sync::{
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        Arc,
    },
    thread,
    time::{Duration, Instant},
};

/// Default interval between heartbeats on each participating thread.
///
/// Promotion of latent forks into stealable jobs happens at most once per interval per
/// participating thread, so this bounds scheduling overhead: work that completes within one
/// interval never pays for anything beyond the local fork bookkeeping.
///
/// The interval trades ramp-up speed on medium-sized work against the width of the band
/// where calling into the pool is guaranteed to cost nothing over serial execution. The
/// default is deliberately conservative: callers should never hesitate to route work through
/// the pool, and workloads large enough to be genuine bottlenecks amortize the ramp (a fixed
/// three to four intervals) regardless.
pub const DEFAULT_INTERVAL: Duration = Duration::from_micros(50);

/// Number of forks between clock reads when checking whether a heartbeat is due.
///
/// Amortizes the cost of reading the clock across forks; with leaves of a few hundred
/// nanoseconds this keeps timing overhead well under one percent while bounding how far a
/// beat can land past the interval.
pub const BEAT_CHECK_FORKS: u32 = 8;

/// How long an idle worker polls for new work before parking on the condvar.
///
/// Trades idle CPU for pickup latency: a promotion landing within this window is claimed in
/// microseconds instead of paying a futex wake, which dominates ramp-up time on medium-sized
/// work. Spinning workers poll a queue-length hint, not the lock, so they do not contend
/// with promoters.
pub const SPIN_BEFORE_PARK: Duration = Duration::from_micros(100);

/// A type-erased header for a stack-allocated job.
///
/// The header is the first field of [`StackJob`] (which is `repr(C)`), so a pointer to the
/// containing job can be recovered from a pointer to the header.
struct Job {
    /// Runs the job on the given scope, stores the result, and signals completion.
    execute: unsafe fn(NonNull<Self>, &mut Scope<'_>),
    /// Set with `Release` ordering after the result has been written by a thief.
    done: AtomicBool,
}

/// A job allocated on the forking frame's stack.
///
/// The closure and result slot live on the stack of the [`Scope::join`] call that created the
/// job. This is sound because `join` does not return (or unwind) until the job has either been
/// executed or withdrawn from all shared state.
#[repr(C)]
struct StackJob<F, R> {
    job: Job,
    f: UnsafeCell<Option<F>>,
    result: UnsafeCell<Option<thread::Result<R>>>,
}

impl<F, R> StackJob<F, R>
where
    F: FnOnce(&mut Scope<'_>) -> R + Send,
    R: Send,
{
    fn new(f: F) -> Self {
        Self {
            job: Job {
                execute: Self::execute,
                done: AtomicBool::new(false),
            },
            f: UnsafeCell::new(Some(f)),
            result: UnsafeCell::new(None),
        }
    }

    /// Takes the closure out of the job.
    ///
    /// Only called by the owning frame once the job is guaranteed to be absent from the shared
    /// queue and unclaimed, so no other thread can access the cell.
    fn take_closure(&self) -> F {
        // SAFETY: the caller has exclusive logical access to the job (see above).
        unsafe { (*self.f.get()).take().expect("closure already taken") }
    }

    /// Takes the result written by a thief.
    ///
    /// Only called by the owning frame after observing `done` with `Acquire` ordering, which
    /// happens after the thief's `Release` store that follows the result write.
    fn take_result(&self) -> thread::Result<R> {
        // SAFETY: the done flag orders the thief's write before this read, and the thief never
        // touches the job again after setting it.
        unsafe { (*self.result.get()).take().expect("job completed without result") }
    }

    /// Executes a claimed job on a thief's scope.
    ///
    /// # Safety
    ///
    /// `job` must point at the `job` field of a live `StackJob<F, R>` that has been claimed by
    /// exactly one thread.
    unsafe fn execute(job: NonNull<Job>, scope: &mut Scope<'_>) {
        let stack = job.cast::<Self>();
        // SAFETY: per the contract, the pointer refers to a live StackJob<F, R>. The owning
        // frame only performs shared reads of the done flag until it observes completion.
        let stack = unsafe { stack.as_ref() };
        // SAFETY: this thread is the unique claimant, so it has exclusive access to the cells.
        let f = unsafe { (*stack.f.get()).take().expect("claimed job already executed") };
        let result = panic::catch_unwind(AssertUnwindSafe(|| f(scope)));
        // SAFETY: still the unique claimant; the owner does not read the result until done.
        unsafe { *stack.result.get() = Some(result) };
        stack.job.done.store(true, Ordering::Release);
        scope.inner.signal_completion();
    }
}

/// A promoted job traveling through the shared queue.
struct JobRef(NonNull<Job>);

// SAFETY: the job's closure is `Send` (enforced by `Scope::join`), and the queue transfers
// unique claim of the job to exactly one thread.
unsafe impl Send for JobRef {}

struct State {
    /// Promoted jobs that no worker has claimed yet.
    jobs: VecDeque<JobRef>,
    /// Number of workers blocked waiting for a job.
    sleepers: usize,
}

/// Counters describing scheduler activity, for diagnostics and experiments.
#[derive(Clone, Copy, Debug, Default)]
pub struct PoolStats {
    /// Forks promoted into the shared queue.
    pub promoted: u64,
    /// Promoted forks claimed and executed by workers.
    pub claimed: u64,
    /// Promoted forks withdrawn by their owners before any worker claimed them.
    pub reclaimed: u64,
}

#[derive(Default)]
struct Stats {
    promoted: AtomicU64,
    claimed: AtomicU64,
    reclaimed: AtomicU64,
}

struct Inner {
    state: Mutex<State>,
    /// Signaled when a job is injected or a claimed job completes, waking both idle workers
    /// and joiners blocked on a claimed fork.
    wake: Condvar,
    /// Mirror of `state.jobs.len()`, polled lock-free by spinning workers.
    jobs_len: AtomicUsize,
    /// Number of workers in their spin phase, counted as demand for promotion.
    spinning: AtomicUsize,
    shutdown: AtomicBool,
    interval: Duration,
    stats: Stats,
}

impl Inner {
    /// Withdraws a promoted job from the shared queue if no worker has claimed it yet.
    fn reclaim(&self, job: NonNull<Job>) -> bool {
        let mut state = self.state.lock();
        let Some(index) = state.jobs.iter().position(|j| j.0 == job) else {
            return false;
        };
        state.jobs.remove(index);
        self.jobs_len.store(state.jobs.len(), Ordering::Relaxed);
        self.stats.reclaimed.fetch_add(1, Ordering::Relaxed);
        true
    }

    /// Blocks until a thief sets the job's done flag, without executing other work.
    ///
    /// Used only on the unwind path, where running arbitrary queued jobs is undesirable.
    fn wait_done(&self, done: &AtomicBool) {
        let mut state = self.state.lock();
        while !done.load(Ordering::Acquire) {
            state.sleepers += 1;
            self.wake.wait(&mut state);
            state.sleepers -= 1;
        }
    }

    /// Wakes all sleepers after a claimed job completes.
    ///
    /// The done flag is set before this lock is taken, so a joiner either observes it before
    /// sleeping or is already waiting when the notification is delivered.
    fn signal_completion(&self) {
        let _state = self.state.lock();
        self.wake.notify_all();
    }
}

/// A participant's view of the pool, carried through [`Scope::join`] recursion.
///
/// A scope is created per top-level [`Pool::run`] call and per claimed job on a worker; it is
/// neither `Send` nor `Sync` and never outlives the activation that created it.
pub struct Scope<'p> {
    inner: &'p Inner,
    /// Latent forks of this activation, oldest first. Only this thread mutates the list.
    pending: Vec<NonNull<Job>>,
    /// Time of the last heartbeat, set lazily so short activations never read the clock.
    last_beat: Option<Instant>,
    /// Forks remaining until the next clock read.
    until_check: u32,
}

impl<'p> Scope<'p> {
    const fn new(inner: &'p Inner) -> Self {
        Self {
            inner,
            pending: Vec::new(),
            last_beat: None,
            until_check: BEAT_CHECK_FORKS,
        }
    }

    /// Creates a scope for executing a claimed fork, with its first beat already due.
    ///
    /// A claimed fork proves the surrounding computation has outlived one interval, so the
    /// new scope expands eagerly instead of re-establishing a baseline: the first fork checks
    /// the clock immediately and promotes if idle workers remain. Parallelism spreads where
    /// evidence of enough work already exists.
    fn new_claimed(inner: &'p Inner) -> Self {
        Self {
            inner,
            pending: Vec::new(),
            last_beat: Instant::now().checked_sub(inner.interval),
            until_check: 0,
        }
    }

    /// Runs both closures, allowing the second to be claimed by an idle worker if a heartbeat
    /// promotes it first.
    ///
    /// Does not return until both closures have completed, so the closures may borrow
    /// non-`'static` data. If either closure panics, the panic is propagated to the caller
    /// after both closures have stopped executing.
    pub fn join<A, B, RA, RB>(&mut self, a: A, b: B) -> (RA, RB)
    where
        A: FnOnce(&mut Scope<'_>) -> RA + Send,
        B: FnOnce(&mut Scope<'_>) -> RB + Send,
        RA: Send,
        RB: Send,
    {
        self.beat();

        let stack = StackJob::new(b);
        let job = NonNull::from(&stack).cast::<Job>();
        self.pending.push(job);

        let ra = match panic::catch_unwind(AssertUnwindSafe(|| a(self))) {
            Ok(ra) => ra,
            Err(payload) => {
                // The forked job must be resolved before this frame unwinds, otherwise a
                // worker could execute a job whose stack has been freed.
                self.abandon(job, &stack);
                panic::resume_unwind(payload);
            }
        };

        // Deeper frames pushed and resolved their own forks during `a`, so if our fork is
        // still pending it is the newest entry. Run it inline.
        if self.pending.last() == Some(&job) {
            self.pending.pop();
            let f = stack.take_closure();
            return (ra, f(self));
        }

        // Our fork was promoted. If no worker claimed it yet, withdraw it and run inline.
        if self.inner.reclaim(job) {
            let f = stack.take_closure();
            return (ra, f(self));
        }

        // A worker claimed the fork; help with other queued work until it reports completion.
        self.wait_or_help(&stack.job.done);
        match stack.take_result() {
            Ok(rb) => (ra, rb),
            Err(payload) => panic::resume_unwind(payload),
        }
    }

    /// Waits for a claimed fork to complete, executing other queued jobs in the meantime.
    ///
    /// While blocked the joiner counts as a sleeper, so it registers as demand for promotion
    /// and beats route work to it instead of leaving it parked. Helping recurses into this
    /// scope, so stack depth grows with the number of simultaneously helped jobs; promotion
    /// rates bound that in practice.
    fn wait_or_help(&mut self, done: &AtomicBool) {
        loop {
            let job = {
                let mut state = self.inner.state.lock();
                loop {
                    if done.load(Ordering::Acquire) {
                        return;
                    }
                    if let Some(job) = state.jobs.pop_front() {
                        self.inner.jobs_len.store(state.jobs.len(), Ordering::Relaxed);
                        break job;
                    }
                    state.sleepers += 1;
                    self.inner.wake.wait(&mut state);
                    state.sleepers -= 1;
                }
            };
            self.inner.stats.claimed.fetch_add(1, Ordering::Relaxed);
            // SAFETY: the job was uniquely claimed by popping it from the shared queue, and
            // its owning frame blocks until the done flag is set.
            unsafe { (job.0.as_ref().execute)(job.0, self) };
        }
    }

    /// Resolves a fork without running it on this frame, discarding any result.
    ///
    /// Used when the first closure panicked: the fork is withdrawn (or waited on, if already
    /// claimed) so the frame can unwind safely. A panic from the fork is dropped in favor of
    /// the panic already unwinding.
    fn abandon<F, R>(&mut self, job: NonNull<Job>, stack: &StackJob<F, R>)
    where
        F: FnOnce(&mut Scope<'_>) -> R + Send,
        R: Send,
    {
        if self.pending.last() == Some(&job) {
            self.pending.pop();
            return;
        }
        if self.inner.reclaim(job) {
            return;
        }
        self.inner.wait_done(&stack.job.done);
        let _ = stack.take_result();
    }

    /// Checks whether a heartbeat is due and promotes latent forks if so.
    ///
    /// The clock is read once every [`BEAT_CHECK_FORKS`] forks. The first check only
    /// establishes a baseline, so activations shorter than one interval promote nothing.
    #[inline]
    fn beat(&mut self) {
        if self.until_check > 0 {
            self.until_check -= 1;
            return;
        }
        self.until_check = BEAT_CHECK_FORKS;
        let now = Instant::now();
        match self.last_beat {
            None => self.last_beat = Some(now),
            Some(last) if now.duration_since(last) >= self.inner.interval => {
                self.last_beat = Some(now);
                self.promote();
            }
            Some(_) => {}
        }
    }

    /// Promotes the oldest latent fork (the largest pending subtree) into the shared queue.
    ///
    /// At most one fork is promoted per beat, and only when idle workers outnumber queued
    /// jobs: a saturated pool keeps forks local, where resolving them is free, instead of
    /// churning them through the queue for their owners to reclaim. A worker that frees up
    /// mid-interval waits at most one beat for the next promotion.
    fn promote(&mut self) {
        if self.pending.is_empty() {
            return;
        }
        let mut state = self.inner.state.lock();
        let idle = state.sleepers + self.inner.spinning.load(Ordering::Relaxed);
        if idle <= state.jobs.len() {
            return;
        }
        let job = self.pending.remove(0);
        state.jobs.push_back(JobRef(job));
        self.inner.jobs_len.store(state.jobs.len(), Ordering::Relaxed);
        if state.sleepers > 0 {
            self.inner.wake.notify_one();
        }
        drop(state);
        self.inner.stats.promoted.fetch_add(1, Ordering::Relaxed);
    }
}

/// A caller-runs thread pool with heartbeat promotion.
///
/// Work submitted through [`Pool::run`] executes on the calling thread; the pool's workers
/// only participate when a heartbeat promotes part of the computation. Total parallelism for a
/// single caller is therefore `workers + 1`.
///
/// # Examples
///
/// ```
/// use commonware_parallel::heartbeat::{fold, Pool};
///
/// let pool = Pool::new(2);
/// let data: Vec<u64> = (0..10_000).collect();
/// let sum = pool.run(|scope| {
///     fold(scope, &data, 128, &|| 0u64, &|acc, x| acc + x, &|a, b| a + b)
/// });
/// assert_eq!(sum, 49_995_000);
/// ```
pub struct Pool {
    inner: Arc<Inner>,
    workers: Vec<thread::JoinHandle<()>>,
}

impl Pool {
    /// Creates a pool with the given number of worker threads and the default heartbeat
    /// interval.
    ///
    /// `workers` may be zero, in which case all work runs inline on calling threads.
    pub fn new(workers: usize) -> Self {
        Self::with_interval(workers, DEFAULT_INTERVAL)
    }

    /// Creates a pool with the given number of worker threads and heartbeat interval.
    pub fn with_interval(workers: usize, interval: Duration) -> Self {
        let inner = Arc::new(Inner {
            state: Mutex::new(State {
                jobs: VecDeque::new(),
                sleepers: 0,
            }),
            wake: Condvar::new(),
            jobs_len: AtomicUsize::new(0),
            spinning: AtomicUsize::new(0),
            shutdown: AtomicBool::new(false),
            interval,
            stats: Stats::default(),
        });

        let workers = (0..workers)
            .map(|index| {
                let inner = inner.clone();
                thread::Builder::new()
                    .name(format!("heartbeat-worker-{index}"))
                    .spawn(move || Self::worker(&inner))
                    .expect("failed to spawn worker")
            })
            .collect();

        Self { inner, workers }
    }

    /// Returns the heartbeat interval of this pool.
    pub fn interval(&self) -> Duration {
        self.inner.interval
    }

    /// Returns cumulative scheduler activity counters.
    pub fn stats(&self) -> PoolStats {
        PoolStats {
            promoted: self.inner.stats.promoted.load(Ordering::Relaxed),
            claimed: self.inner.stats.claimed.load(Ordering::Relaxed),
            reclaimed: self.inner.stats.reclaimed.load(Ordering::Relaxed),
        }
    }

    /// Runs `f` on the calling thread with a scope that can fork work onto the pool.
    pub fn run<R>(&self, f: impl FnOnce(&mut Scope<'_>) -> R) -> R {
        let mut scope = Scope::new(&self.inner);
        let result = f(&mut scope);
        debug_assert!(scope.pending.is_empty(), "unresolved forks after run");
        result
    }

    /// Worker main loop: claim promoted jobs and execute them to completion.
    ///
    /// After running dry, a worker polls the queue-length hint for [`SPIN_BEFORE_PARK`]
    /// before parking, so promotions during busy periods are claimed without a futex wake.
    fn worker(inner: &Arc<Inner>) {
        loop {
            let mut job = None;

            inner.spinning.fetch_add(1, Ordering::Relaxed);
            let spin_start = Instant::now();
            loop {
                if inner.shutdown.load(Ordering::Relaxed) {
                    inner.spinning.fetch_sub(1, Ordering::Relaxed);
                    return;
                }
                if inner.jobs_len.load(Ordering::Relaxed) > 0 {
                    let mut state = inner.state.lock();
                    if let Some(claimed) = state.jobs.pop_front() {
                        inner.jobs_len.store(state.jobs.len(), Ordering::Relaxed);
                        job = Some(claimed);
                        break;
                    }
                }
                if spin_start.elapsed() >= SPIN_BEFORE_PARK {
                    break;
                }
                for _ in 0..256 {
                    hint::spin_loop();
                }
            }
            inner.spinning.fetch_sub(1, Ordering::Relaxed);

            let job = match job {
                Some(job) => job,
                None => {
                    let mut state = inner.state.lock();
                    loop {
                        if inner.shutdown.load(Ordering::Relaxed) {
                            return;
                        }
                        if let Some(job) = state.jobs.pop_front() {
                            inner.jobs_len.store(state.jobs.len(), Ordering::Relaxed);
                            break job;
                        }
                        state.sleepers += 1;
                        inner.wake.wait(&mut state);
                        state.sleepers -= 1;
                    }
                }
            };
            inner.stats.claimed.fetch_add(1, Ordering::Relaxed);
            let mut scope = Scope::new_claimed(inner);
            // SAFETY: the job was uniquely claimed by popping it from the shared queue, and
            // its owning frame blocks until the done flag is set.
            unsafe { (job.0.as_ref().execute)(job.0, &mut scope) };
            debug_assert!(scope.pending.is_empty(), "unresolved forks after job");
        }
    }
}

impl Drop for Pool {
    fn drop(&mut self) {
        // Setting the flag while holding the state lock ensures every worker either observes
        // it before sleeping or is already waiting when the wakeup below is delivered.
        {
            let _state = self.inner.state.lock();
            self.inner.shutdown.store(true, Ordering::Relaxed);
        }
        self.inner.wake.notify_all();
        for handle in self.workers.drain(..) {
            let _ = handle.join();
        }
    }
}

/// Reduces a slice to a single value, forking recursively so idle workers can claim halves.
///
/// `grain` is the maximum number of items processed by a single leaf without offering
/// parallelism; choose it so one leaf represents at least a few hundred nanoseconds of work.
pub fn fold<T, R, ID, F, RD>(
    scope: &mut Scope<'_>,
    items: &[T],
    grain: usize,
    identity: &ID,
    fold_op: &F,
    reduce_op: &RD,
) -> R
where
    T: Sync,
    R: Send,
    ID: Fn() -> R + Sync,
    F: Fn(R, &T) -> R + Sync,
    RD: Fn(R, R) -> R + Sync,
{
    if items.len() <= grain.max(1) {
        return items.iter().fold(identity(), fold_op);
    }
    let (left, right) = items.split_at(items.len() / 2);
    let (a, b) = scope.join(
        |scope| fold(scope, left, grain, identity, fold_op, reduce_op),
        |scope| fold(scope, right, grain, identity, fold_op, reduce_op),
    );
    reduce_op(a, b)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{collections::HashSet, hint::black_box, thread, time::Duration};

    fn sum(pool: &Pool, items: &[u64], grain: usize) -> u64 {
        pool.run(|scope| {
            fold(
                scope,
                items,
                grain,
                &|| 0u64,
                &|acc, x| acc.wrapping_add(x.rotate_left(7) ^ x),
                &|a, b| a.wrapping_add(b),
            )
        })
    }

    fn serial_sum(items: &[u64]) -> u64 {
        items
            .iter()
            .fold(0u64, |acc, x| acc.wrapping_add(x.rotate_left(7) ^ x))
    }

    #[test]
    fn fold_matches_serial() {
        let pool = Pool::new(4);
        for len in [0usize, 1, 2, 7, 64, 1_000, 100_000] {
            let items: Vec<u64> = (0..len as u64).collect();
            assert_eq!(sum(&pool, &items, 8), serial_sum(&items), "len={len}");
        }
    }

    #[test]
    fn fold_matches_serial_zero_workers() {
        let pool = Pool::new(0);
        let items: Vec<u64> = (0..10_000).collect();
        assert_eq!(sum(&pool, &items, 8), serial_sum(&items));
    }

    #[test]
    fn fold_matches_serial_aggressive_heartbeat() {
        let pool = Pool::with_interval(4, Duration::from_micros(1));
        for _ in 0..20 {
            let items: Vec<u64> = (0..50_000).collect();
            assert_eq!(sum(&pool, &items, 8), serial_sum(&items));
        }
    }

    #[test]
    fn fold_matches_serial_zero_interval() {
        // A zero interval promotes on every heartbeat check, forcing constant stealing. Kept
        // small so it can run under miri to validate the cross-thread completion protocol.
        let pool = Pool::with_interval(2, Duration::ZERO);
        for _ in 0..5 {
            let items: Vec<u64> = (0..2_000).collect();
            assert_eq!(sum(&pool, &items, 1), serial_sum(&items));
        }
    }

    #[test]
    fn join_returns_both_results() {
        let pool = Pool::new(2);
        let (a, b) = pool.run(|scope| scope.join(|_| 1 + 2, |_| 3 * 4));
        assert_eq!((a, b), (3, 12));
    }

    #[test]
    fn join_supports_disjoint_mutation() {
        let pool = Pool::new(2);
        let mut items = vec![0u64; 1024];
        pool.run(|scope| {
            let (left, right) = items.split_at_mut(512);
            scope.join(
                |_| left.iter_mut().for_each(|x| *x = 1),
                |_| right.iter_mut().for_each(|x| *x = 2),
            )
        });
        assert!(items[..512].iter().all(|&x| x == 1));
        assert!(items[512..].iter().all(|&x| x == 2));
    }

    #[test]
    fn work_is_actually_distributed() {
        let pool = Pool::with_interval(4, Duration::from_micros(20));
        let items: Vec<u64> = (0..20_000).collect();
        let threads = Mutex::new(HashSet::new());
        pool.run(|scope| {
            fold(
                scope,
                &items,
                1,
                &|| 0u64,
                &|acc, x| {
                    threads.lock().insert(thread::current().id());
                    let mut v = *x;
                    for _ in 0..500 {
                        v = black_box(v.wrapping_mul(6364136223846793005).wrapping_add(1));
                    }
                    acc.wrapping_add(v)
                },
                &|a, b| a.wrapping_add(b),
            )
        });
        assert!(threads.lock().len() > 1, "no work was stolen");
    }

    #[test]
    fn panics_propagate() {
        let pool = Pool::with_interval(4, Duration::from_micros(5));
        for _ in 0..50 {
            let items: Vec<u64> = (0..10_000).collect();
            let result = panic::catch_unwind(AssertUnwindSafe(|| {
                pool.run(|scope| {
                    fold(
                        scope,
                        &items,
                        1,
                        &|| 0u64,
                        &|acc, x| {
                            if *x == 7_777 {
                                panic!("boom");
                            }
                            acc.wrapping_add(*x)
                        },
                        &|a, b| a.wrapping_add(b),
                    )
                })
            }));
            let payload = result.expect_err("fold should panic");
            let message = payload.downcast_ref::<&str>().copied();
            assert_eq!(message, Some("boom"));
        }
    }

    #[test]
    fn panic_in_first_closure_resolves_fork() {
        let pool = Pool::new(2);
        let result = panic::catch_unwind(AssertUnwindSafe(|| {
            pool.run(|scope| scope.join(|_| panic!("first"), |_| 42))
        }));
        assert!(result.is_err());
    }

    /// Sweeps the mid-range gap (work between one and ~50 heartbeat intervals) across
    /// heartbeat intervals, printing wall time, speedup over serial, and scheduler counters.
    ///
    /// Run with:
    /// cargo test --release -p commonware-parallel --lib \
    ///   heartbeat::tests::midrange_exploration -- --ignored --nocapture
    #[test]
    #[ignore]
    fn midrange_exploration() {
        use rayon::iter::{IntoParallelRefIterator, ParallelIterator};

        fn spin(x: &u64) -> u64 {
            let mut v = x.wrapping_add(1);
            for _ in 0..1000 {
                v = black_box(v.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407));
            }
            v
        }

        fn median(mut f: impl FnMut() -> u64) -> Duration {
            const ITERS: usize = 31;
            for _ in 0..3 {
                black_box(f());
            }
            let mut samples: Vec<Duration> = (0..ITERS)
                .map(|_| {
                    let start = std::time::Instant::now();
                    black_box(f());
                    start.elapsed()
                })
                .collect();
            samples.sort();
            samples[ITERS / 2]
        }

        const SIZES: [usize; 8] = [32, 64, 128, 256, 512, 1024, 2048, 4096];

        let raw = rayon::ThreadPoolBuilder::new()
            .num_threads(8)
            .build()
            .unwrap();
        let hb20 = Pool::with_interval(7, Duration::from_micros(20));
        let hb50 = Pool::with_interval(7, Duration::from_micros(50));

        let fold_on = |pool: &Pool, data: &[u64]| {
            pool.run(|scope| {
                fold(
                    scope,
                    data,
                    1,
                    &|| 0u64,
                    &|acc, x| acc.wrapping_add(spin(x)),
                    &|a, b| a.wrapping_add(b),
                )
            })
        };

        // Measurements for one size run back to back so machine-load drift over the run
        // affects all strategies of a row equally.
        println!(
            "\n{:>6} {:>10} {:>10} | {:>11} {:>11}",
            "n", "serial", "rayon", "hb@20us", "hb@50us"
        );
        for n in SIZES {
            let data: Vec<u64> = (0..n as u64).collect();

            let serial = median(|| data.iter().fold(0u64, |acc, x| acc.wrapping_add(spin(x))));
            let rayon_time = median(|| {
                raw.install(|| {
                    data.par_iter()
                        .fold(|| 0u64, |acc, x| acc.wrapping_add(spin(x)))
                        .reduce(|| 0u64, |a, b| a.wrapping_add(b))
                })
            });
            let hb20_time = median(|| fold_on(&hb20, &data));
            let hb50_time = median(|| fold_on(&hb50, &data));
            println!(
                "{:>6} {:>10.1?} {:>10.1?} | {:>11.1?} {:>11.1?}",
                n, serial, rayon_time, hb20_time, hb50_time,
            );
        }
    }

    #[test]
    fn concurrent_callers() {
        let pool = Pool::new(4);
        thread::scope(|s| {
            for seed in 0..4u64 {
                let pool = &pool;
                s.spawn(move || {
                    let items: Vec<u64> = (seed..seed + 50_000).collect();
                    assert_eq!(sum(pool, &items, 8), serial_sum(&items));
                });
            }
        });
    }
}
