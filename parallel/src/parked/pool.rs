//! Pool state and the worker loop: immediate parking with wake-limited dispatch.
//!
//! Workers scan the K-slot job table (rotating origin so a long-running job in one slot
//! cannot starve the others), linger briefly in a bounded search window to absorb
//! back-to-back job trains, then register in the idle registry and park. Submitters wake
//! at most as many workers as a job can use; a worker that finds work after registering
//! withdraws its registration so stale entries cannot eat the wake budget.

use super::{
    scoped::{Job, Slot},
    sync::{Arc, AtomicBool, AtomicU8, AtomicUsize, Mutex, Ordering, Parker, fence, spin},
};
use crate::topology;
use std::collections::VecDeque;

/// A queued one-shot job (a `spawn` closure, boxed: spawn bodies are `'static`).
pub(super) type OneShot = Box<dyn FnOnce() + Send + 'static>;

std::thread_local! {
    /// `(pool identity, worker id)` when the current thread is a pool worker. Pool identity
    /// is the address of its `Shared`, so a worker of pool A polling a future of pool B is
    /// never misclassified as a member of B.
    static WORKER_OF: core::cell::Cell<Option<(usize, usize)>> =
        const { core::cell::Cell::new(None) };
}

/// Whether the current thread is a worker of `shared`'s pool.
pub(super) fn is_member(shared: &Shared) -> bool {
    WORKER_OF.with(|w| w.get().is_some_and(|(pool, _)| pool == shared.identity()))
}

/// Number of concurrently published jobs. A performance knob, never a correctness bound:
/// when every slot is occupied, a submitter executes its job inline on its own thread.
pub(super) const SLOTS: usize = 4;

/// Rounds of slot rescanning (with a spin hint between rounds) a worker performs after
/// running out of work, before it registers idle and parks.
///
/// This window absorbs trains of back-to-back submissions: parking between two jobs in a
/// train would pay an unpark per worker per job. Set by measurement via the burst-train
/// gate bench; it does not reintroduce the idle tax because it only holds a worker awake
/// immediately after work existed, and is bounded in microseconds.
#[cfg(not(feature = "loom"))]
pub(super) const SEARCH_ROUNDS: usize = 64;
#[cfg(feature = "loom")]
pub(super) const SEARCH_ROUNDS: usize = 0;

/// Upper bound on a worker's adaptive linger: the longest it will spin waiting for the
/// next job before parking. Chosen to cover the inter-phase serial gaps of bulk-synchronous
/// commit workloads (hundreds of microseconds between sub-millisecond parallel phases),
/// where parking between phases costs a wake round-trip per phase per worker; set by
/// measurement via the gapped-train gate bench.
#[cfg(not(any(feature = "loom", miri)))]
const LINGER_CAP: core::time::Duration = core::time::Duration::from_millis(1);

/// Scan rounds between clock checks inside the linger window, keeping `Instant::now` off
/// the per-round path.
#[cfg(not(any(feature = "loom", miri)))]
const LINGER_CHECK_ROUNDS: usize = 8;

/// Idle-entry states.
const ACTIVE: u8 = 0;
const REGISTERED: u8 = 1;
const CLAIMED: u8 = 2;

/// Per-worker idle registration.
struct IdleEntry {
    /// ACTIVE (running), REGISTERED (parked or about to park), or CLAIMED (a submitter
    /// spent wake budget on this worker; a token is deposited).
    state: AtomicU8,
    parker: Parker,
    /// The worker's last-known LLC domain, recorded when it registers idle. Advisory
    /// wake-ordering data only (see [`Shared::wake`]); staleness is harmless.
    domain: AtomicUsize,
}

/// State shared by all workers and every `Parked` handle.
pub(super) struct Shared {
    slots: Box<[Slot]>,
    /// Queued `spawn` one-shots. Unbounded, so `Manual::spawn`'s hand-off contract never
    /// needs an inline fallback; drained (not dropped) on shutdown. A mutexed deque is
    /// deliberate: spawn frequency is per-pipeline-stage, not per-item.
    oneshots: Mutex<VecDeque<OneShot>>,
    /// Lock-free mirror of the queue length, so idle-scan probes (search window, park
    /// recheck) never touch the queue mutex.
    oneshot_len: AtomicUsize,
    idle: Box<[IdleEntry]>,
    /// Approximate count of REGISTERED entries, maintained by registrants and claimants.
    /// Used only to short-circuit wake scans; correctness never depends on it.
    idle_count: AtomicUsize,
    shutdown: AtomicBool,
    workers: usize,
}

impl Shared {
    pub(super) fn new(workers: usize) -> Self {
        Self {
            slots: (0..SLOTS).map(|_| Slot::new()).collect(),
            oneshots: Mutex::new(VecDeque::new()),
            oneshot_len: AtomicUsize::new(0),
            idle: (0..workers)
                .map(|_| IdleEntry {
                    state: AtomicU8::new(ACTIVE),
                    parker: Parker::new(),
                    domain: AtomicUsize::new(0),
                })
                .collect(),
            idle_count: AtomicUsize::new(0),
            shutdown: AtomicBool::new(false),
            workers,
        }
    }

    /// Number of background workers.
    pub(super) fn workers(&self) -> usize {
        self.workers
    }

    /// This pool's identity for thread-local membership checks.
    pub(super) fn identity(&self) -> usize {
        core::ptr::from_ref(self) as usize
    }

    /// Whether the pool has begun shutting down.
    pub(super) fn is_shutdown(&self) -> bool {
        self.shutdown.load(Ordering::SeqCst)
    }

    /// Enqueues a one-shot and wakes one worker to run it.
    ///
    /// The publish-vs-register handshake is carried by the queue mutex on the publish side
    /// paired with the worker's register-then-recheck fence (the recheck locks the same
    /// mutex via `has_oneshots`).
    pub(super) fn enqueue(&self, job: OneShot) {
        self.oneshots.lock().unwrap().push_back(job);
        self.oneshot_len.fetch_add(1, Ordering::SeqCst);
        // Publish-vs-register handshake: order the length publication before the idle
        // scan in wake(), pairing with the worker's register-then-recheck fence.
        fence(Ordering::SeqCst);
        self.wake(1);
    }

    /// Pops one queued one-shot, if any.
    pub(super) fn pop_oneshot(&self) -> Option<OneShot> {
        let job = self.oneshots.lock().unwrap().pop_front();
        if job.is_some() {
            self.oneshot_len.fetch_sub(1, Ordering::SeqCst);
        }
        job
    }

    fn has_oneshots(&self) -> bool {
        self.oneshot_len.load(Ordering::SeqCst) != 0
    }

    /// Runs one unit of pending pool work on the current thread, if any exists: a queued
    /// one-shot first (latency), otherwise chunks of a published job. Used by workers and
    /// by member-polling `spawn` futures.
    pub(super) fn help_once(&self) -> bool {
        if let Some(job) = self.pop_oneshot() {
            job();
            return true;
        }
        for slot in self.slots.iter() {
            if slot.looks_published() && slot.try_drive() {
                return true;
            }
        }
        false
    }

    pub(super) fn slot(&self, idx: usize) -> &Slot {
        &self.slots[idx]
    }

    /// Whether any slot holds work a new executor could claim. The park decision keys on
    /// this rather than on publication: a published job with nothing left to claim will
    /// never produce new work (claims are monotonic), so parking beside it is safe, and
    /// staying awake beside it would hot-spin for the length of a straggler chunk.
    fn any_claimable(&self) -> bool {
        self.slots.iter().any(Slot::looks_claimable)
    }

    /// Attempts to publish `job` into an empty slot, returning its index. `None` means the
    /// table is full and the caller must execute inline (submission never blocks).
    pub(super) fn try_install(&self, job: &Job) -> Option<usize> {
        (0..SLOTS).find(|&k| self.slots[k].try_publish(job))
    }

    /// Wakes up to `budget` idle workers, spending each unit of budget on a genuinely
    /// parked (REGISTERED) worker via CAS so stale registrations cannot consume it.
    ///
    /// Workers whose last-known LLC domain matches the submitting caller's are preferred:
    /// a job with a data relationship to the caller (a spawned hand-off, a small scoped
    /// job) runs several times cheaper when its worker shares the caller's L3, and the
    /// scheduler's own placement is an unrevisited per-process lottery. Purely an
    /// ordering preference over identical CAS claims; with a single detected domain the
    /// first pass claims everything and the behavior is exactly the unordered scan.
    pub(super) fn wake(&self, budget: usize) {
        if budget == 0 {
            return;
        }
        let near = if topology::domain_count() > 1 {
            topology::current_domain_index()
        } else {
            0
        };
        let mut woken = 0;
        for pass in 0..2 {
            for entry in self.idle.iter() {
                if woken == budget || self.idle_count.load(Ordering::SeqCst) == 0 {
                    return;
                }
                // Pass 0 claims only same-domain workers; pass 1 claims the rest. The
                // domain read is advisory (Relaxed; may be stale), so a matching entry
                // skipped by a racing update is simply claimed in pass 1.
                if pass == 0 && entry.domain.load(Ordering::Relaxed) != near {
                    continue;
                }
                if entry
                    .state
                    .compare_exchange(REGISTERED, CLAIMED, Ordering::SeqCst, Ordering::SeqCst)
                    .is_ok()
                {
                    self.idle_count.fetch_sub(1, Ordering::SeqCst);
                    entry.parker.unpark();
                    woken += 1;
                }
            }
            if topology::domain_count() <= 1 {
                return;
            }
        }
    }

    /// Signals shutdown and wakes every worker so parked ones can observe it.
    pub(super) fn shutdown(&self) {
        self.shutdown.store(true, Ordering::SeqCst);
        for entry in self.idle.iter() {
            entry.parker.unpark();
        }
    }
}

/// The body of one background worker thread.
pub(super) fn worker_loop(shared: Arc<Shared>, id: usize) {
    WORKER_OF.with(|w| w.set(Some((shared.identity(), id))));
    let mut rotation = id;
    // Adaptive linger: how long this worker spins for the next job before parking, learned
    // from its own park durations (see the adaptation step after `park`). Zero for workloads
    // whose gaps parking handles well; grows toward `LINGER_CAP` when jobs keep arriving
    // just after parking (bulk-synchronous phases separated by short serial gaps), which
    // removes the per-phase wake round-trip exactly where a spinning pool would win.
    #[cfg(not(any(feature = "loom", miri)))]
    let mut linger = core::time::Duration::ZERO;
    'outer: loop {
        if shared.shutdown.load(Ordering::SeqCst) {
            // Defensive drain. In practice the queue is empty here by construction: every
            // queued one-shot holds a `Parked` (owner) clone, so the owner count cannot
            // reach zero -- and shutdown cannot fire -- while work is pending. The pool
            // therefore outlives all submitted work. The drain stays as a backstop against
            // future changes to that ownership structure.
            while let Some(job) = shared.pop_oneshot() {
                job();
            }
            return;
        }

        // One-shots first: they are latency-sensitive hand-offs (and Manual::spawn's
        // contract), while scoped jobs always have their caller participating. The atomic
        // length probe keeps the queue mutex off the scan path when no one-shots exist.
        if shared.has_oneshots() {
            if let Some(job) = shared.pop_oneshot() {
                job();
                continue;
            }
        }

        // Work phase: drive every published slot, starting at a rotating origin so one
        // continuously claimable job cannot starve later slots.
        let mut executed = false;
        for i in 0..SLOTS {
            let slot = &shared.slots[(rotation + i) % SLOTS];
            if slot.looks_published() && slot.try_drive() {
                executed = true;
            }
        }
        rotation = rotation.wrapping_add(1);
        if executed {
            continue;
        }

        // Search window: linger briefly to absorb back-to-back job trains.
        for _ in 0..SEARCH_ROUNDS {
            if shared.shutdown.load(Ordering::SeqCst) {
                return;
            }
            if shared.any_claimable() || shared.has_oneshots() {
                continue 'outer;
            }
            spin();
        }

        // Adaptive linger window: extend the fixed search window by this worker's learned
        // linger before paying a park/wake round-trip. The clock is consulted once per
        // LINGER_CHECK_ROUNDS scan rounds.
        #[cfg(not(any(feature = "loom", miri)))]
        if !linger.is_zero() {
            let start = std::time::Instant::now();
            'linger: loop {
                for _ in 0..LINGER_CHECK_ROUNDS {
                    if shared.shutdown.load(Ordering::SeqCst) {
                        return;
                    }
                    if shared.any_claimable() || shared.has_oneshots() {
                        continue 'outer;
                    }
                    spin();
                }
                if start.elapsed() >= linger {
                    break 'linger;
                }
            }
        }

        // Register idle, then re-check for work published between our last scan and the
        // registration: a submitter that saw an empty registry will not wake us, so we
        // must not park with work pending.
        let me = &shared.idle[id];
        // Record where this worker currently sits so submitters can prefer waking a
        // worker in their own LLC domain. Relaxed: purely advisory ordering data.
        me.domain
            .store(topology::current_domain_index(), Ordering::Relaxed);
        // Count first, then become claimable: the count over-approximates registered
        // workers, so a claimant's decrement (which follows a successful CAS on `state`,
        // which follows this store) can never underflow it.
        shared.idle_count.fetch_add(1, Ordering::SeqCst);
        me.state.store(REGISTERED, Ordering::SeqCst);
        // Register-vs-publish handshake: order our registration before the work recheck,
        // pairing with the publisher's publish-then-scan fence. A submitter that missed our
        // registration published before our recheck; a publication we miss here claimed us.
        fence(Ordering::SeqCst);
        if shared.shutdown.load(Ordering::SeqCst) || shared.any_claimable() || shared.has_oneshots()
        {
            // Withdraw the registration. A failed CAS means a submitter already claimed
            // (and decremented for) us; the deposited token makes our next park return
            // immediately, which the loop tolerates as a spurious wake.
            if me
                .state
                .compare_exchange(REGISTERED, ACTIVE, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                shared.idle_count.fetch_sub(1, Ordering::SeqCst);
            }
            continue;
        }

        #[cfg(not(any(feature = "loom", miri)))]
        let parked_at = std::time::Instant::now();
        me.parker.park();

        // Woken: by a claimant (CLAIMED; count already adjusted), by shutdown, or by a
        // stale token (still REGISTERED); deregister ourselves in the latter cases.
        if me.state.swap(ACTIVE, Ordering::SeqCst) == REGISTERED {
            shared.idle_count.fetch_sub(1, Ordering::SeqCst);
        } else {
            // A claimant spent wake budget on us: work arrived `park` after we gave up
            // lingering. Adapt so the next same-shaped gap is absorbed without parking:
            // extend the linger by this gap (the exact total wait that would have caught
            // it), capped; a gap the cap cannot cover means parking was right, so decay.
            #[cfg(not(any(feature = "loom", miri)))]
            {
                let park = parked_at.elapsed();
                if park < LINGER_CAP {
                    linger = (linger + park).min(LINGER_CAP);
                } else {
                    linger /= 2;
                }
            }
        }
    }
}
