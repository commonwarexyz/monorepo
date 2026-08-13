//! Pool state and the worker loop: immediate parking with wake-limited dispatch.
//!
//! Workers scan the K-slot job table (rotating origin so a long-running job in one slot
//! cannot starve the others), linger briefly in a bounded search window to absorb
//! back-to-back job trains, then register in the idle registry and park. Submitters wake
//! at most as many workers as a job can use; a worker that finds work after registering
//! withdraws its registration so stale entries cannot eat the wake budget.

use super::{
    scoped::{Job, Slot},
    sync::{Arc, AtomicBool, AtomicU8, AtomicUsize, Ordering, Parker, fence, spin},
};

/// Number of concurrently published jobs. A performance knob, never a correctness bound:
/// when every slot is occupied, a submitter executes its job inline on its own thread.
pub(super) const SLOTS: usize = 4;

/// Rounds of slot rescanning (with a spin hint between rounds) a worker performs after
/// running out of work, before it registers idle and parks.
///
/// This window is what absorbs intra-commit burst trains (e.g. merkleize submits ~15
/// back-to-back per-level jobs per commit); parking between levels would pay an unpark
/// per worker per level. Set by measurement via the burst-train gate bench; it does not
/// reintroduce the idle tax because it only holds a worker awake immediately after work
/// existed, and is bounded in microseconds.
#[cfg(not(feature = "loom"))]
pub(super) const SEARCH_ROUNDS: usize = 64;
#[cfg(feature = "loom")]
pub(super) const SEARCH_ROUNDS: usize = 0;

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
}

/// State shared by all workers and every `Parked` handle.
pub(super) struct Shared {
    slots: Box<[Slot]>,
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
            idle: (0..workers)
                .map(|_| IdleEntry {
                    state: AtomicU8::new(ACTIVE),
                    parker: Parker::new(),
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
    pub(super) fn wake(&self, budget: usize) {
        if budget == 0 {
            return;
        }
        let mut woken = 0;
        for entry in self.idle.iter() {
            if woken == budget || self.idle_count.load(Ordering::SeqCst) == 0 {
                break;
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
    let mut rotation = id;
    'outer: loop {
        if shared.shutdown.load(Ordering::SeqCst) {
            return;
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
            if shared.any_claimable() {
                continue 'outer;
            }
            spin();
        }

        // Register idle, then re-check for work published between our last scan and the
        // registration: a submitter that saw an empty registry will not wake us, so we
        // must not park with work pending.
        let me = &shared.idle[id];
        // Count first, then become claimable: the count over-approximates registered
        // workers, so a claimant's decrement (which follows a successful CAS on `state`,
        // which follows this store) can never underflow it.
        shared.idle_count.fetch_add(1, Ordering::SeqCst);
        me.state.store(REGISTERED, Ordering::SeqCst);
        // Register-vs-publish handshake: order our registration before the work recheck,
        // pairing with the publisher's publish-then-scan fence. A submitter that missed our
        // registration published before our recheck; a publication we miss here claimed us.
        fence(Ordering::SeqCst);
        if shared.shutdown.load(Ordering::SeqCst) || shared.any_claimable() {
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

        me.parker.park();

        // Woken: by a claimant (CLAIMED; count already adjusted), by shutdown, or by a
        // stale token (still REGISTERED); deregister ourselves in the latter cases.
        if me.state.swap(ACTIVE, Ordering::SeqCst) == REGISTERED {
            shared.idle_count.fetch_sub(1, Ordering::SeqCst);
        }
    }
}
