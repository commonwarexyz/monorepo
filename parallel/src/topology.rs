//! Places a call's work on groups of workers that prefer the calling thread's last-level cache.
//!
//! Threads in different last-level cache (LLC) domains pay far more to exchange cache lines than
//! threads in one domain, and the scheduler does not know which threads share data.
//!
//! A strategy therefore splits its pool's workers into groups sized from the domain with the most
//! allowed CPUs (the CPUs the building thread may use). A call runs its work on one group as Local
//! work, or on the whole pool as Wide work.
//!
//! # Homes
//!
//! A group's home is the domain whose allowed CPUs its workers request. Groups without a home float
//! over the CPUs left outside the homes when enough remain, and otherwise keep their original
//! masks. Every request stays within the worker's inherited mask, and the operating system may
//! reject it, so placement is advisory.
//!
//! When the parallelism is not a multiple of the group width, the last group is narrower. It is
//! never homed or leased for Local work, so Local work always has the width the policy planned.
//!
//! ```text
//! host: three eight-CPU LLCs     strategy(16): one pool, groups of 7 + 7 + 2
//!
//!    domain A          domain B          domain C
//!  +------------+    +------------+    +------------+
//!  | cpu 0-7    |    | cpu 8-15   |    | cpu 16-23  |
//!  |            |    |            |    |            |
//!  | group 0    |    | group 1    |    | group 2    |
//!  | w0 .. w6   |    | w7 .. w13  |    | w14, w15   |
//!  | home: A    |    | home: B    |    | floating   |
//!  | 8 CPUs     |    | 8 CPUs     |    | 8 CPUs     |
//!  +------------+    +------------+    +------------+
//!
//! Local from A: group 0 only       Local from B: group 1 only
//! Wide: any worker in groups 0, 1, or 2
//! ```
//!
//! Without fixed homes (below), groups start unhomed. The first Local call from a domain can
//! permanently home an idle group there, if the pool's initial mask is known and allows a CPU in
//! that domain for each of the group's workers. Those workers apply the request asynchronously.
//!
//! ```text
//!        group 0          group 1          event
//!  t0    unhomed, idle    unhomed, idle
//!  t1    home A, busy     unhomed, idle    A starts a local call on group 0
//!  t2    home A, busy     home B, busy     B starts a local call on group 1
//!  t3    home A, busy     home B, busy     C adds a local call to group 0
//!  t4    home A, idle     home B, idle     all three calls have returned
//!  t5    home A, idle     home B, busy     C starts a local call on group 1
//! ```
//!
//! When the pool has one worker per allowed CPU and those CPUs split evenly across two or more
//! domains of at least two CPUs each, every group instead takes a fixed home at startup. Its
//! workers request their masks before running jobs, and no workers float.
//!
//! ```text
//! host: two eight-CPU LLCs      strategy(16): one pool, groups of 8 + 8
//!
//!          domain A                         domain B
//!     +----------------+               +----------------+
//!     | cpu 0-7        |               | cpu 8-15       |
//!     | group 0: w0-7  |               | group 1: w8-15 |
//!     +----------------+               +----------------+
//!           fixed                             fixed
//! ```
//!
//! # Calls
//!
//! Local work uses the group homed in the caller's domain, homing one if it can, and otherwise
//! leases the least loaded full group. Only that group's workers take the work, and the lease lasts
//! until the call returns. Wide work runs on any worker and is offered first to the group homed in
//! the caller's domain.
//!
//! A caller outside any `ThreadPool` may be restricted to the group's home domain for the call,
//! within its current mask. It requests its original mask back on return or unwind.
//!
//! # Spawned jobs
//!
//! A job spawned from outside the pool enters the shared Wide queue, so any idle worker can start
//! it. It prefers waking the group homed in its submitter's domain unless another thread, including
//! a worker, holds a lease there. Jobs submitted by the pool's own workers inherit their current
//! placement.
//!
//! In a pool with several groups, each group admits at most one such job per worker to learn
//! whether its descendants run on the starting worker's group or on the whole pool. Excess jobs,
//! and jobs that start on the narrower group, run Wide.
//!
//! ```text
//! job from thread T in domain D
//!   |
//!   +-- D unknown ----------------------------------------> least loaded group
//!   |
//!   +-- no group homed at D ------------------------------> home an idle group at D,
//!   |                                                       as a local call would,
//!   |                                                       or else least loaded group
//!   |
//!   +-- group homed at D, idle or leased only by T -------> that group
//!   |
//!   +-- group homed at D, leased by another thread -------> least loaded group
//!
//! selected group G (admission charged here)
//!   |
//!   v
//! shared queue, prefer G ----> any idle worker in group H
//!                               |
//!                               +-- admitted, Local, H has planned width --> Local(H)
//!                               |
//!                               +-- otherwise ----------------------------> Wide
//! ```
//!
//! # Platform limits
//!
//! Domains come from the kernel's sysfs cache topology, where each CPU's last-level cache is its
//! highest-level Data or Unified cache leaf. On non-Linux platforms, under miri, and on machines
//! whose possible-CPU count exceeds `cpu_set_t`'s capacity (where the affinity mask cannot be
//! read), a strategy is one unhomed group and never writes a mask.
//!
//! Every written mask, including a restored one, comes from an earlier read and omits CPUs that
//! were offline then. Linux 6.2 and newer can keep a written mask across cpuset changes, so a
//! restored caller and its later threads may not gain added CPUs. Older kernels can replace a
//! written mask with the cpuset's effective CPUs, undoing a group's confinement.
//!
//! A pool's workers keep the mask of the thread that creates the pool, and its groups are sized
//! from that mask. To share a host between pools, create each pool from a thread pinned to the
//! CPUs meant for it. A pool created from inside a job or a strategy call gets only the CPUs that
//! thread was kept to. On a homed worker, or during a call that moved its caller, that is one
//! domain, and on a floating worker it is the CPUs outside the homes.

use crate::ThreadPool;
use commonware_utils::sync::Mutex;
use std::{
    sync::{
        Arc, OnceLock,
        atomic::{AtomicU64, Ordering},
    },
    thread::ThreadId,
};

/// The fewest CPUs the building thread must be allowed in one domain before groups use one fewer
/// worker to leave room for other threads. Smaller domains keep the worker because it is a larger
/// share of their capacity.
#[cfg(all(target_os = "linux", not(miri)))]
const SLACK_FROM: usize = 6;

cfg_if::cfg_if! {
    if #[cfg(all(target_os = "linux", not(miri)))] {
        /// Byte size of `cpu_set_t`, as passed to the affinity syscalls.
        const CPU_SET_BYTES: usize = std::mem::size_of::<libc::cpu_set_t>();

        /// Number of CPUs a `cpu_set_t` can represent.
        const CPU_SETSIZE: usize = libc::CPU_SETSIZE as usize;

        /// A safe wrapper over the CPU affinity mask `libc::cpu_set_t`.
        #[derive(Clone, Copy)]
        struct CpuSet(libc::cpu_set_t);

        impl CpuSet {
            /// The empty set.
            const fn empty() -> Self {
                // SAFETY: an all-zero cpu_set_t is the valid empty set.
                Self(unsafe { std::mem::zeroed() })
            }

            /// Adds `cpu` to the set.
            ///
            /// # Panics
            ///
            /// Panics if `cpu` is at or past `CPU_SETSIZE`.
            fn set(&mut self, cpu: usize) {
                assert!(
                    cpu < CPU_SETSIZE,
                    "cpu must be below CPU_SETSIZE"
                );

                // SAFETY: cpu is below CPU_SETSIZE (asserted above) and the set is valid.
                unsafe { libc::CPU_SET(cpu, &mut self.0) };
            }

            /// Whether `cpu` is in the set (`false` past `CPU_SETSIZE`).
            fn contains(&self, cpu: usize) -> bool {
                if cpu >= CPU_SETSIZE {
                    return false;
                }

                // SAFETY: cpu is below CPU_SETSIZE (checked above) and the set is valid.
                unsafe { libc::CPU_ISSET(cpu, &self.0) }
            }

            /// The CPUs in the set, in ascending order.
            fn cpus(&self) -> impl Iterator<Item = usize> + '_ {
                (0..CPU_SETSIZE).filter(|&cpu| self.contains(cpu))
            }

            /// The CPUs in both sets, with their count.
            fn intersection(&self, other: &Self) -> (Self, usize) {
                let mut mask = Self::empty();
                let mut count = 0;
                for cpu in self.cpus().filter(|&cpu| other.contains(cpu)) {
                    mask.set(cpu);
                    count += 1;
                }
                (mask, count)
            }

            /// The CPUs in this set but not in `other`, with their count.
            fn difference(&self, other: &Self) -> (Self, usize) {
                let mut mask = Self::empty();
                let mut count = 0;
                for cpu in self.cpus().filter(|&cpu| !other.contains(cpu)) {
                    mask.set(cpu);
                    count += 1;
                }
                (mask, count)
            }
        }

        /// The CPUs of one last-level cache domain.
        pub(crate) struct Domain {
            /// The domain's CPUs, in discovery order.
            cpus: Box<[usize]>,
        }

        impl Domain {
            /// The domain of `cpus`, each below `CPU_SETSIZE`.
            fn new(cpus: Vec<usize>) -> Self {
                Self {
                    cpus: cpus.into_boxed_slice(),
                }
            }

            /// The domain's CPUs that `allowed` also contains, and how many there are. The scan
            /// tests one bit per CPU in this domain.
            fn within(&self, allowed: &CpuSet) -> (CpuSet, usize) {
                let mut both = CpuSet::empty();
                let mut count = 0usize;
                for &cpu in &self.cpus {
                    if allowed.contains(cpu) {
                        both.set(cpu);
                        count += 1;
                    }
                }
                (both, count)
            }
        }

        /// The calling thread's current affinity mask, or `None` when the kernel refuses the query.
        /// The kernel refuses it whenever the possible-CPU count exceeds `cpu_set_t`'s capacity.
        fn thread_affinity() -> Option<CpuSet> {
            let mut mask = CpuSet::empty();

            // SAFETY: pid 0 is the calling thread, and the set is a valid cpu_set_t of
            // `CPU_SET_BYTES` bytes.
            if unsafe { libc::sched_getaffinity(0, CPU_SET_BYTES, &mut mask.0) } != 0 {
                return None;
            }
            Some(mask)
        }

        /// Applies `mask` to the calling thread. Returns `false` when the kernel refuses.
        fn set_thread_affinity(mask: &CpuSet) -> bool {
            // SAFETY: pid 0 is the calling thread, and the set is a valid cpu_set_t of
            // `CPU_SET_BYTES` bytes.
            unsafe { libc::sched_setaffinity(0, CPU_SET_BYTES, &mask.0) == 0 }
        }

        /// The CPU the calling thread is running on, or `None` when the query fails. The answer is
        /// advisory because the thread may migrate immediately after.
        fn current_cpu() -> Option<usize> {
            // SAFETY: sched_getcpu takes no arguments and only returns a value (-1 on error).
            let cpu = unsafe { libc::sched_getcpu() };
            usize::try_from(cpu).ok()
        }

        /// The process-wide topology, detected on first use, or `None` when sysfs is unreadable
        /// or `Topology::from_lists` rejects the lists.
        pub(crate) fn topology() -> Option<&'static Topology> {
            static TOPOLOGY: OnceLock<Option<Topology>> = OnceLock::new();
            TOPOLOGY.get_or_init(Topology::from_sysfs).as_ref()
        }

        /// The host's last-level cache domains.
        pub(crate) struct Topology {
            /// Domain of each CPU, or `None` for a CPU whose cache topology was unreadable at
            /// detection time. A thread on such a CPU, or on one past the end of the table, has no
            /// domain, because a guessed domain could move its work away from its cache.
            cpu_to_domain: Box<[Option<u16>]>,

            /// Each domain's CPUs, indexed by domain.
            domains: Box<[Domain]>,
        }

        /// A permanent assignment of one group to each domain with allowed CPUs, used when the
        /// allowed CPUs split evenly into those domains and the pool has exactly that many workers.
        struct Partition {
            /// The workers per group, equal to each domain's allowed CPU count.
            width: usize,

            /// Each group's home domain and the allowed CPUs of that domain, in group order.
            homes: Box<[(u16, CpuSet)]>,
        }

        impl Topology {
            /// Partitions `parallelism` workers across the domains containing `allowed` CPUs, or
            /// returns `None` unless there are at least two such domains, all with the same allowed
            /// CPU count of at least two, every allowed CPU belongs to a domain, and there is one
            /// worker per allowed CPU.
            fn partition(&self, allowed: &CpuSet, parallelism: usize) -> Option<Partition> {
                let mut width = 0;
                let mut homes = Vec::new();
                for (index, domain) in self.domains.iter().enumerate() {
                    let (mask, count) = domain.within(allowed);
                    if count == 0 {
                        continue;
                    }
                    if width == 0 {
                        width = count;
                    } else if count != width {
                        return None;
                    }
                    homes.push((u16::try_from(index).ok()?, mask));
                }
                let exact = homes.len() > 1
                    && width > 1
                    && homes.len() * width == parallelism
                    && allowed.cpus().count() == parallelism;
                exact.then(|| Partition {
                    width,
                    homes: homes.into_boxed_slice(),
                })
            }

            /// Returns masks for homed groups and the remaining CPUs for floating workers. A group
            /// floats if it has no home. Returns no floating mask when fewer CPUs remain than there
            /// are floating workers.
            fn reservations(
                &self,
                allowed: &CpuSet,
                groups: impl IntoIterator<Item = (usize, Option<u16>)>,
            ) -> (Vec<Option<CpuSet>>, Option<CpuSet>) {
                let mut reserved = CpuSet::empty();
                let mut floating = 0;
                let homes = groups
                    .into_iter()
                    .map(|(width, home)| {
                        let mask =
                            home.map(|home| self.domains[usize::from(home)].within(allowed).0);
                        if let Some(mask) = mask {
                            for cpu in mask.cpus() {
                                reserved.set(cpu);
                            }
                        } else {
                            floating += width;
                        }
                        mask
                    })
                    .collect();
                let (remainder, count) = allowed.difference(&reserved);
                (homes, (count >= floating).then_some(remainder))
            }

            /// The domain of `cpu`, or `None` when the snapshot does not cover it.
            fn domain_of(&self, cpu: usize) -> Option<u16> {
                self.cpu_to_domain.get(cpu).copied().flatten()
            }

            /// The domain of the CPU the calling thread is currently running on, or `None` when the
            /// query fails or the snapshot does not cover the CPU. The answer is advisory because
            /// the thread may migrate immediately after.
            fn current_domain(&self) -> Option<u16> {
                self.domain_of(current_cpu()?)
            }

            /// The `shared_cpu_list` of the highest-level Data or Unified cache under `cpu_dir`.
            /// The `cache/index*` leaf index varies by architecture and cache layout, so every leaf
            /// is inspected.
            fn llc_list(cpu_dir: &std::path::Path) -> Option<String> {
                let mut best: Option<(u32, String)> = None;
                for entry in std::fs::read_dir(cpu_dir.join("cache")).ok()?.flatten() {
                    if !entry.file_name().to_string_lossy().starts_with("index") {
                        continue;
                    }
                    let leaf = entry.path();
                    let Ok(kind) = std::fs::read_to_string(leaf.join("type")) else {
                        continue;
                    };
                    let kind = kind.trim();
                    if kind != "Data" && kind != "Unified" {
                        continue;
                    }
                    let Some(level) = std::fs::read_to_string(leaf.join("level"))
                        .ok()
                        .and_then(|s| s.trim().parse::<u32>().ok())
                    else {
                        continue;
                    };
                    let Ok(list) = std::fs::read_to_string(leaf.join("shared_cpu_list")) else {
                        continue;
                    };
                    let list = list.trim();
                    if !list.is_empty() && best.as_ref().is_none_or(|(l, _)| level > *l) {
                        best = Some((level, list.to_string()));
                    }
                }
                best.map(|(_, list)| list)
            }

            /// Builds the tables from each CPU's discovered LLC sharing list. Returns `None` if
            /// nothing was readable or `from_lists` rejects the lists.
            fn from_sysfs() -> Option<Self> {
                let mut lists: Vec<(usize, String)> = Vec::new();
                let entries = std::fs::read_dir("/sys/devices/system/cpu").ok()?;
                for entry in entries.flatten() {
                    let name = entry.file_name();
                    let name = name.to_string_lossy();
                    let Some(id) = name
                        .strip_prefix("cpu")
                        .and_then(|s| s.parse::<usize>().ok())
                    else {
                        continue;
                    };
                    if let Some(list) = Self::llc_list(&entry.path()) {
                        lists.push((id, list));
                    }
                }
                Self::from_lists(&lists)
            }

            /// Builds the tables from `(cpu, shared_cpu_list)` pairs, with one domain per distinct
            /// list string. Returns `None` when the pairs are empty, form a single domain, include
            /// a CPU at or past `CPU_SETSIZE`, or form more domains than a `u16` can index.
            fn from_lists(lists: &[(usize, String)]) -> Option<Self> {
                if lists.is_empty() {
                    return None;
                }

                // cpu_set_t cannot represent CPUs at or past CPU_SETSIZE, so a topology that
                // contains one cannot be pinned faithfully.
                if lists
                    .iter()
                    .any(|(cpu, _)| *cpu >= CPU_SETSIZE)
                {
                    return None;
                }
                let max_cpu = lists.iter().map(|(cpu, _)| *cpu).max()?;
                let mut table: Vec<Option<u16>> = vec![None; max_cpu + 1];
                let mut domains: Vec<&str> = Vec::new();

                let mut cpus: Vec<Vec<usize>> = Vec::new();
                for (cpu, list) in lists {
                    let list = list.as_str();
                    let domain = domains.iter().position(|&d| d == list).unwrap_or_else(|| {
                        domains.push(list);
                        cpus.push(Vec::new());
                        domains.len() - 1
                    });
                    table[*cpu] = Some(u16::try_from(domain).ok()?);
                    cpus[domain].push(*cpu);
                }

                // One domain leaves nowhere to move work.
                if domains.len() <= 1 {
                    return None;
                }
                Some(Self {
                    cpu_to_domain: table.into_boxed_slice(),
                    domains: cpus.into_iter().map(Domain::new).collect(),
                })
            }
        }

        std::thread_local! {
            /// The affinity mask a worker started with. Later requests stay within this mask so
            /// homing respects inherited CPU restrictions.
            static INHERITED: std::cell::Cell<Option<CpuSet>> = const { std::cell::Cell::new(None) };
        }

        /// Records the calling worker's starting mask for later homing.
        fn remember_inherited_mask() {
            INHERITED.with(|cell| cell.set(thread_affinity()));
        }

        /// Applies `requested` within the worker's original mask. A missing request, fewer than
        /// `minimum` CPUs, or a failed write gets one attempt to restore the original mask.
        fn apply_mask(requested: Option<CpuSet>, minimum: usize) {
            let Some(inherited) = INHERITED.with(|cell| cell.get()) else {
                return;
            };
            if let Some(requested) = requested {
                let (effective, count) = requested.intersection(&inherited);
                if count >= minimum && set_thread_affinity(&effective) {
                    return;
                }
            }
            set_thread_affinity(&inherited);
        }

        /// Requests the calling thread's original mask, as read before the nudge, when dropped.
        pub(crate) struct Restore(CpuSet);

        impl Drop for Restore {
            fn drop(&mut self) {
                set_thread_affinity(&self.0);
            }
        }

        /// The CPUs the calling thread may currently use.
        #[cfg(test)]
        fn allowed_cpus() -> Vec<usize> {
            let mask = thread_affinity().expect("affinity mask must be readable");
            (0..CPU_SETSIZE).filter(|&cpu| mask.contains(cpu)).collect()
        }
    }
}

/// A guard that leaves the caller's affinity unchanged.
#[cfg(not(all(target_os = "linux", not(miri))))]
pub(crate) struct Restore;

#[cfg(test)]
std::thread_local! {
    /// A domain tests assign to the calling thread in place of the one the kernel reports, so the
    /// group logic can be driven on any platform.
    static FAKE_DOMAIN: std::cell::Cell<Option<u16>> = const { std::cell::Cell::new(None) };

    /// A pause tests insert into the calling thread's next `local` call whose first home lookup
    /// misses, so another caller can home a group before the call decides what to do.
    static HOMING_SCAN_PAUSE: std::cell::Cell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::Cell::new(None) };
}

/// The [`Lease::Tracked`] claims in flight on a group. The group is idle while it has none.
/// Claims, releases, and homing all hold the group's lock on this state, so a group found idle
/// gains no tracked work before it is homed.
#[derive(Debug)]
struct State {
    /// The tick of the group's latest claim of any kind, so [`Groups::least_loaded`] breaks ties
    /// toward the group used least recently.
    last_used: u64,

    /// Each submitting thread with leases on this group and its lease count, so a job can tell
    /// its submitter's own work from another caller's.
    submitters: Vec<(ThreadId, usize)>,

    /// External roots admitted through this group, bounded by its worker count.
    admitted_roots: usize,
}

impl State {
    /// Counts a placed call or job of `submitter` against the group.
    fn claim(&mut self, tick: u64, submitter: ThreadId) {
        self.last_used = tick;
        match self.submitters.iter_mut().find(|(id, _)| *id == submitter) {
            Some((_, count)) => *count += 1,
            None => self.submitters.push((submitter, 1)),
        }
    }

    /// Releases one claim of `submitter`, forgetting the thread once none remain.
    fn release(&mut self, submitter: ThreadId) {
        if let Some(position) = self.submitters.iter().position(|(id, _)| *id == submitter) {
            self.submitters[position].1 -= 1;
            if self.submitters[position].1 == 0 {
                self.submitters.swap_remove(position);
            }
        }
    }

    /// The number of tracked calls and jobs in flight on the group.
    fn in_flight(&self) -> usize {
        self.submitters.iter().map(|(_, count)| count).sum()
    }
}

/// One group of a strategy's workers, with its home and its load.
#[derive(Debug)]
pub(crate) struct Group {
    /// The number of workers in the group.
    width: usize,

    /// Whether the group can be homed and is preferred for Local work. It must be as wide as the
    /// first group and have more than one worker. Another group takes Local work only when no
    /// group qualifies, as in a pool of one worker.
    placeable: bool,

    /// The requested home domain. It is set at most once, at build or by the first homing, and
    /// read without the state lock.
    home: OnceLock<u16>,

    /// The work in flight on the group.
    state: Mutex<State>,
}

impl Group {
    /// Creates an idle, unhomed group of `width` workers, where `full` is the width of the first
    /// group.
    const fn new(width: usize, full: usize) -> Self {
        Self {
            width,
            placeable: width > 1 && width == full,
            home: OnceLock::new(),
            state: Mutex::new(State {
                last_used: 0,
                submitters: Vec::new(),
                admitted_roots: 0,
            }),
        }
    }

    /// Whether any thread, the caller included, has work registered on the group, for tests
    /// of lease accounting.
    #[cfg(test)]
    pub(crate) fn has_leases(&self) -> bool {
        !self.state.lock().submitters.is_empty()
    }

    /// Whether a thread other than the calling one has work in flight on the group.
    fn busy_with_others(&self) -> bool {
        let me = std::thread::current().id();
        self.state.lock().submitters.iter().any(|(id, _)| *id != me)
    }

    /// The number of workers in the group.
    pub(crate) const fn width(&self) -> usize {
        self.width
    }

    /// Whether the group can be homed and is preferred for Local work.
    pub(crate) const fn placeable(&self) -> bool {
        self.placeable
    }
}

/// The groups a strategy splits the workers of its pool into.
pub(crate) struct Groups {
    /// The strategy's pool.
    pool: ThreadPool,

    /// All of the pool's workers, partitioned into groups in pool order.
    groups: Box<[Group]>,

    /// Claim counter that orders the groups' `last_used` ticks. It starts at 1, so a
    /// claimed group is more recent than a group never claimed.
    ticks: AtomicU64,

    /// Serializes first-home creation and mask requests so a domain has at most one home.
    homing: Mutex<()>,

    /// The topology for homing and the building thread's mask that sized the groups and bounds
    /// their CPU reservations. `None` when either is unknown or no domain allows two CPUs.
    #[cfg(all(target_os = "linux", not(miri)))]
    affinity: Option<(&'static Topology, CpuSet)>,
}

impl std::fmt::Debug for Groups {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Groups")
            .field("pool", &self.pool)
            .field("groups", &self.groups)
            .finish_non_exhaustive()
    }
}

/// A claim by one call or job on a group, or on every group for a Wide claim, until the lease is
/// dropped. An unhomed group with tracked work in flight cannot acquire a home.
#[derive(Debug)]
pub(crate) enum Lease {
    /// A claim on a strategy's only group from a thread with no known domain. It records nothing,
    /// since there is no other group to pick and that thread cannot home this one.
    Untracked,

    /// A claim recorded in the state of every group it counts against.
    Tracked {
        /// The strategy's groups.
        groups: Arc<Groups>,

        /// The thread that made the claim.
        submitter: ThreadId,

        /// The leased group, or for a Wide claim the group its work is offered to first.
        index: usize,

        /// Whether the claim counts against every group.
        wide: bool,

        /// Whether the lease holds one of its group's root admissions.
        admitted: bool,
    },
}

impl Lease {
    /// A lease for a claim of `submitter` that the caller has already recorded in `groups`.
    fn tracked(groups: &Arc<Groups>, submitter: ThreadId, index: usize, wide: bool) -> Self {
        Self::Tracked {
            groups: Arc::clone(groups),
            submitter,
            index,
            wide,
            admitted: false,
        }
    }

    /// The leased group's index among the pool's groups.
    pub(crate) const fn group(&self) -> usize {
        match self {
            Self::Untracked => 0,
            Self::Tracked { index, .. } => *index,
        }
    }

    /// Extends this claim to every group while retaining its root admission, if any.
    pub(crate) fn into_wide(mut self) -> Self {
        if let Self::Tracked {
            groups,
            submitter,
            index,
            wide,
            ..
        } = &mut self
            && !*wide
        {
            let tick = groups.ticks.fetch_add(1, Ordering::Relaxed);
            for (other, group) in groups.groups.iter().enumerate() {
                let mut state = group.state.lock();
                if other == *index {
                    state.last_used = tick;
                } else {
                    state.claim(tick, *submitter);
                }
            }
            *wide = true;
        }
        self
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        let Self::Tracked {
            groups,
            submitter,
            index,
            wide,
            admitted,
        } = self
        else {
            return;
        };
        let groups = &groups.groups;
        {
            let mut state = groups[*index].state.lock();
            if *admitted {
                assert!(state.admitted_roots > 0);
                state.admitted_roots -= 1;
            }
            state.release(*submitter);
        }
        if *wide {
            for (other, group) in groups.iter().enumerate() {
                if other != *index {
                    group.state.lock().release(*submitter);
                }
            }
        }
    }
}

impl Groups {
    /// Wraps the worker groups of `pool` without assigning homes to them.
    pub(crate) fn new(pool: ThreadPool) -> Self {
        let widths = pool.group_widths();
        let full = widths.first().copied().unwrap_or(0);
        let groups = widths
            .iter()
            .map(|&width| Group::new(width, full))
            .collect();
        Self {
            pool,
            groups,
            ticks: AtomicU64::new(1),
            homing: Mutex::new(()),
            #[cfg(all(target_os = "linux", not(miri)))]
            affinity: None,
        }
    }

    /// Builds the pool `builder` describes and splits its workers into groups sized from the widest
    /// domain. A pool filling equal-sized allowed domains gets homes at startup, and otherwise each
    /// full-width group can take one home on demand.
    ///
    /// A host with fewer than two domains, a thread allowed fewer than two CPUs in every domain,
    /// and platforms without affinity control get one unhomed group of all the workers.
    pub(crate) fn build(
        builder: crate::rayon::ThreadPoolBuilder,
    ) -> Result<Self, crate::rayon::ThreadPoolBuildError> {
        #[cfg(all(target_os = "linux", not(miri)))]
        let topology = topology();
        #[cfg(not(all(target_os = "linux", not(miri))))]
        let topology = None;
        Self::build_in(topology, builder)
    }

    /// The worker count for a full group. Returns `None` when every domain has fewer than two
    /// CPUs in `allowed`.
    ///
    /// The width follows the most CPUs `allowed` in any one domain, minus one worker at or above
    /// [`SLACK_FROM`] CPUs.
    #[cfg(all(target_os = "linux", not(miri)))]
    fn group_width(topology: &Topology, allowed: &CpuSet) -> Option<usize> {
        let widest = topology
            .domains
            .iter()
            .map(|domain| domain.within(allowed).1)
            .max()?;
        let width = if widest >= SLACK_FROM {
            widest - 1
        } else {
            widest
        };
        (width > 1).then_some(width)
    }

    /// [`Self::build`] for an explicit topology, or none.
    fn build_in(
        #[cfg(all(target_os = "linux", not(miri)))] topology: Option<&'static Topology>,
        #[cfg(not(all(target_os = "linux", not(miri))))] topology: Option<()>,
        mut builder: crate::rayon::ThreadPoolBuilder,
    ) -> Result<Self, crate::rayon::ThreadPoolBuildError> {
        // The registry caps the worker count the same way, so the groups cover every worker.
        let parallelism = builder
            .get_num_threads()
            .clamp(1, crate::rayon::THREADS_MAX);

        // An exact partition fixes the group width and homes, and otherwise the widest allowed
        // domain sizes the groups. Homing stays disabled when neither applies.
        #[cfg(all(target_os = "linux", not(miri)))]
        let affinity = topology.and_then(|topology| Some((topology, thread_affinity()?)));
        #[cfg(all(target_os = "linux", not(miri)))]
        let partition = affinity
            .as_ref()
            .and_then(|(topology, allowed)| topology.partition(allowed, parallelism));
        #[cfg(all(target_os = "linux", not(miri)))]
        let width = partition
            .as_ref()
            .map(|partition| partition.width)
            .or_else(|| {
                affinity
                    .as_ref()
                    .and_then(|(topology, allowed)| Self::group_width(topology, allowed))
            });
        #[cfg(all(target_os = "linux", not(miri)))]
        let (affinity, width) = (
            affinity.filter(|_| width.is_some()),
            width.unwrap_or(parallelism),
        );
        #[cfg(not(all(target_os = "linux", not(miri))))]
        let width = {
            let _ = topology;
            parallelism
        };
        let width = width.clamp(1, parallelism);
        builder = builder.group_width(width);
        if !builder.has_thread_name() {
            builder =
                builder.thread_name(|worker| format!("group{}-{}", worker.group, worker.offset));
        }
        #[cfg(all(target_os = "linux", not(miri)))]
        {
            // Every worker records its inherited mask, and workers with fixed homes request their
            // domain masks before running any job. The builder's own start handler runs first.
            let masks: Option<Box<[CpuSet]>> = partition
                .as_ref()
                .map(|partition| partition.homes.iter().map(|&(_, mask)| mask).collect());
            let start_handler = builder.take_start_handler();
            builder = builder.start_handler(move |worker| {
                if let Some(start_handler) = &start_handler {
                    start_handler(worker);
                }
                remember_inherited_mask();
                if let Some(masks) = &masks {
                    apply_mask(Some(masks[worker.group]), 2);
                }
            });
        }
        let groups = Self::new(Arc::new(builder.build()?));

        // Fixed homes are recorded before any call can look for a home.
        #[cfg(all(target_os = "linux", not(miri)))]
        let groups = {
            if let Some(partition) = &partition {
                for (group, &(home, _)) in groups.groups.iter().zip(partition.homes.iter()) {
                    assert!(group.home.set(home).is_ok(), "a group must be homed once");
                }
            }
            Self { affinity, ..groups }
        };
        Ok(groups)
    }

    /// Assigns `domain` to the calling thread for the group logic, in place of the domain the
    /// kernel reports.
    #[cfg(test)]
    pub(crate) fn fake_domain(domain: Option<u16>) {
        FAKE_DOMAIN.with(|cell| cell.set(domain));
    }

    /// All of the pool's workers, partitioned into groups in pool order.
    pub(crate) fn groups(&self) -> &[Group] {
        &self.groups
    }

    /// The strategy's pool.
    pub(crate) const fn pool(&self) -> &ThreadPool {
        &self.pool
    }

    /// The calling thread's domain, or `None` when homing is disabled or the domain is unknown.
    #[allow(
        clippy::missing_const_for_fn,
        reason = "const only where no topology exists"
    )]
    fn current_domain(&self) -> Option<u16> {
        #[cfg(test)]
        if let Some(domain) = FAKE_DOMAIN.with(|cell| cell.get()) {
            return Some(domain);
        }
        #[cfg(all(target_os = "linux", not(miri)))]
        {
            self.affinity.as_ref()?.0.current_domain()
        }
        #[cfg(not(all(target_os = "linux", not(miri))))]
        {
            None
        }
    }

    /// Claims a group for a Local call from the calling thread. The call takes the group homed in
    /// the thread's domain, or homes the first idle, unhomed group that can take Local work. A new
    /// home requires enough allowed CPUs for every worker in the group. Returns `None` when the
    /// thread's domain is unknown or no group can serve it.
    pub(crate) fn local(self: &Arc<Self>) -> Option<Lease> {
        let domain = self.current_domain()?;
        self.local_in(domain)
    }

    /// [`Self::local`] for a caller in `domain`.
    fn local_in(self: &Arc<Self>, domain: u16) -> Option<Lease> {
        let submitter = std::thread::current().id();

        // A home never changes once set, so the scans read homes without a lock and only a claim
        // locks its group's state.
        let claim_home = || {
            for (index, group) in self.groups.iter().enumerate() {
                if group.home.get() != Some(&domain) {
                    continue;
                }
                let tick = self.ticks.fetch_add(1, Ordering::Relaxed);
                group.state.lock().claim(tick, submitter);
                return Some(Lease::tracked(self, submitter, index, false));
            }
            None
        };
        if let Some(lease) = claim_home() {
            return Some(lease);
        }
        #[cfg(test)]
        if let Some(pause) = HOMING_SCAN_PAUSE.take() {
            pause();
        }

        // The pool's mask never changes, so a domain without room for a full group is turned away
        // without the lock.
        #[cfg(all(target_os = "linux", not(miri)))]
        if let Some((topology, allowed)) = &self.affinity {
            let (_, count) = topology.domains[usize::from(domain)].within(allowed);
            if count < self.groups[0].width {
                return None;
            }
        }

        // Homes are set once and only on placeable groups. Once every placeable group is seen
        // homed, no home can appear later, so a second lookup is final.
        if !self
            .groups
            .iter()
            .any(|group| group.placeable() && group.home.get().is_none())
        {
            return claim_home();
        }

        // A concurrent creator may assign this domain before the lock is acquired.
        let _homing = self.homing.lock();
        if let Some(lease) = claim_home() {
            return Some(lease);
        }
        let tick = self.ticks.fetch_add(1, Ordering::Relaxed);

        // Home the first idle, unhomed placeable group and queue its mask requests before releasing
        // the homing lock. Each worker applies them after its own deques drain, so a worker that is
        // already searching may take Local work before its new mask applies.
        for (index, group) in self
            .groups
            .iter()
            .enumerate()
            .filter(|(_, group)| group.placeable())
        {
            let mut state = group.state.lock();
            if group.home.get().is_some() || !state.submitters.is_empty() {
                continue;
            }
            assert!(group.home.set(domain).is_ok(), "a group must be homed once");
            state.claim(tick, submitter);
            let lease = Lease::tracked(self, submitter, index, false);
            drop(state);
            self.home(index);
            return Some(lease);
        }
        None
    }

    /// Queues mask requests for the newly homed `group` and for floating workers. The caller must
    /// hold the homing lock. Workers apply requests in order after their own deques drain, so they
    /// may apply them at different times, and the operating system may reject one.
    #[allow(
        clippy::missing_const_for_fn,
        reason = "const only where no topology exists"
    )]
    fn home(&self, group: usize) {
        #[cfg(all(target_os = "linux", not(miri)))]
        if let Some((topology, allowed)) = &self.affinity {
            let (homes, floating) = topology.reservations(
                allowed,
                self.groups
                    .iter()
                    .map(|group| (group.width, group.home.get().copied())),
            );
            let requests: Vec<Option<(Option<CpuSet>, usize)>> = homes
                .into_iter()
                .enumerate()
                .map(|(index, home)| {
                    (index == group || home.is_none())
                        .then_some(home.map_or((floating, 1), |home| (Some(home), 2)))
                })
                .collect();
            let width = self.groups[0].width;
            self.pool.spawn_broadcast(move |context| {
                if let Some((requested, minimum)) = requests[context.index() / width] {
                    apply_mask(requested, minimum);
                }
            });
        }
        let _ = group;
    }

    /// Claims every group for a call that may run on any of them. The lease names the group homed
    /// in the calling thread's domain, or the first group, so the caller can offer its work there
    /// first. Any worker may take the call's work. A tracked lease counts it on every group until
    /// the call finishes.
    pub(crate) fn wide(self: &Arc<Self>) -> Lease {
        let domain = self.current_domain();
        if !self.must_track(|| domain) {
            return Lease::Untracked;
        }
        let home = domain.and_then(|domain| {
            self.groups
                .iter()
                .position(|group| group.home.get() == Some(&domain))
        });
        let submitter = std::thread::current().id();
        let tick = self.ticks.fetch_add(1, Ordering::Relaxed);
        for group in &self.groups {
            group.state.lock().claim(tick, submitter);
        }
        Lease::tracked(self, submitter, home.unwrap_or(0), true)
    }

    /// Claims an existing placement's group without changing its home.
    pub(crate) fn lease(self: &Arc<Self>, index: usize) -> Lease {
        if !self.must_track(|| self.current_domain()) {
            return Lease::Untracked;
        }
        let submitter = std::thread::current().id();
        let tick = self.ticks.fetch_add(1, Ordering::Relaxed);
        self.groups[index].state.lock().claim(tick, submitter);
        Lease::tracked(self, submitter, index, false)
    }

    /// Claims a group for a caller without a usable home, preferring groups that can take Local
    /// work, then fewer calls and jobs in flight to limit contention, then the least recent claim.
    /// Recency steers fallback work away from groups whose callers were recently active.
    pub(crate) fn least_loaded(self: &Arc<Self>) -> Lease {
        if self.groups.len() == 1 {
            return self.lease(0);
        }
        let index = (0..self.groups.len())
            .min_by_key(|&index| {
                let group = &self.groups[index];
                let state = group.state.lock();
                (!group.placeable(), state.in_flight(), state.last_used)
            })
            .expect("a strategy must have at least one group");
        self.lease(index)
    }

    /// Whether a claim must be tracked. A claim is tracked when the strategy has several groups or
    /// the claiming thread's domain is known. `domain` is only called when there is one group.
    fn must_track(&self, domain: impl FnOnce() -> Option<u16>) -> bool {
        self.groups.len() > 1 || domain().is_some()
    }

    /// Requests placement in the home domain of `group`, within the caller's current mask. A
    /// successful change returns a guard that requests the original mask on drop. Workers of any
    /// `ThreadPool` and callers already in the home domain keep their masks.
    ///
    /// Threads created by the caller while the guard is held inherit its current mask and may
    /// remain restricted after the guard drops. The restored mask is written explicitly, so the
    /// caller keeps the limits described under Platform limits in the [module docs](self).
    #[cfg(all(target_os = "linux", not(miri)))]
    pub(crate) fn nudge(&self, group: usize) -> Option<Restore> {
        if crate::rayon::current_thread_index().is_some() {
            return None;
        }
        let (topology, _) = self.affinity.as_ref()?;
        let home = *self.groups[group].home.get()?;
        if self.current_domain() == Some(home) {
            return None;
        }
        let original = thread_affinity()?;
        let (mask, count) = topology.domains[usize::from(home)].within(&original);
        if count == 0 || !set_thread_affinity(&mask) {
            return None;
        }
        Some(Restore(original))
    }

    /// Never moves the caller where no topology exists.
    #[cfg(not(all(target_os = "linux", not(miri))))]
    pub(crate) const fn nudge(&self, group: usize) -> Option<Restore> {
        let _ = group;
        None
    }

    /// Claims an external root's preferred wakeup group and reports whether it may learn
    /// descendant placement. The root prefers its submitter's home unless another thread,
    /// including a worker, holds a lease there. Without a usable home, it homes an idle unhomed
    /// group or takes the least loaded group.
    ///
    /// Every root enters the shared Wide queue and may start on any worker. A group admits at most
    /// one root per worker. Excess roots execute Wide. Admission lasts until the job drops its
    /// lease, independently of its descendants' claims. A single-group pool admits every root.
    pub(crate) fn root(self: &Arc<Self>) -> (Lease, bool) {
        let mut lease = self
            .current_domain()
            .and_then(|domain| {
                let home = self
                    .groups
                    .iter()
                    .position(|group| group.home.get() == Some(&domain));
                if home.is_some_and(|index| self.groups[index].busy_with_others()) {
                    None
                } else {
                    self.local_in(domain)
                }
            })
            .unwrap_or_else(|| self.least_loaded());
        if self.groups.len() == 1 {
            return (lease, true);
        }
        let Lease::Tracked {
            index, admitted, ..
        } = &mut lease
        else {
            unreachable!("a strategy with several groups must track every claim");
        };
        let group = &self.groups[*index];
        let mut state = group.state.lock();
        if state.admitted_roots == group.width {
            return (lease, false);
        }
        assert!(state.admitted_roots < group.width);
        state.admitted_roots += 1;
        *admitted = true;
        (lease, true)
    }

    /// One line per group: width, home, and in-flight count.
    #[cfg(test)]
    pub(crate) fn describe(&self) -> String {
        self.groups
            .iter()
            .enumerate()
            .map(|(index, group)| {
                let state = group.state.lock();
                format!(
                    "group {index}: width {} home {:?} in_flight {}",
                    group.width,
                    group.home.get().copied(),
                    state.in_flight(),
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    }
}

#[cfg(test)]
#[commonware_macros::test_group("miri")]
mod tests {
    use super::*;
    use crate::rayon::ThreadPoolBuilder;
    use commonware_utils::NZUsize;

    /// Groups of `widths` workers in one pool that tests can home through fake domains. Every
    /// width but the last must equal the first.
    fn synthetic(widths: &[usize]) -> Arc<Groups> {
        let pool = crate::rayon::ThreadPoolBuilder::new(NZUsize!(widths.iter().sum()))
            .group_width(widths[0])
            .build()
            .unwrap();
        assert_eq!(pool.group_widths(), widths);
        Arc::new(Groups::new(Arc::new(pool)))
    }

    /// The group a lease holds.
    fn leased<'a>(groups: &'a Groups, lease: &Lease) -> &'a Group {
        &groups.groups()[lease.group()]
    }

    /// The groups of a five-worker build account for all five workers. Without usable homing, all
    /// workers belong to one group.
    #[test]
    fn build_accounts_for_all_workers() {
        let groups = Groups::build(ThreadPoolBuilder::new(NZUsize!(5))).unwrap();
        assert_eq!(groups.pool().current_num_threads(), 5);
        let widths: Vec<usize> = groups.groups().iter().map(Group::width).collect();
        assert_eq!(widths.iter().sum::<usize>(), 5);

        // A host without domains to home groups in gets one group of every thread.
        #[cfg(all(target_os = "linux", not(miri)))]
        let homing = groups.affinity.is_some();
        #[cfg(not(all(target_os = "linux", not(miri))))]
        let homing = false;
        if !homing {
            assert_eq!(widths, vec![5]);
        }
    }

    /// The first Local call from a domain homes an idle group there, a second call from the same
    /// domain reuses it while the first is in flight, and both leases release their claims.
    #[test]
    fn local_homes_and_reuses_idle_group() {
        let groups = synthetic(&[2, 2]);
        Groups::fake_domain(Some(1));

        // The first call homes a group and claims it.
        let lease = groups.local().expect("an idle group must be homed");
        assert_eq!(leased(&groups, &lease).home.get().copied(), Some(1));
        assert_eq!(leased(&groups, &lease).state.lock().in_flight(), 1);

        // A second call from the same domain joins the homed group.
        let again = groups
            .local()
            .expect("the homed group must be reused while busy");
        assert_eq!(again.group(), lease.group());
        assert_eq!(leased(&groups, &lease).state.lock().in_flight(), 2);

        // Both claims are released.
        drop(again);
        drop(lease);
        assert_eq!(groups.groups()[0].state.lock().in_flight(), 0);
        Groups::fake_domain(None);
    }

    /// Each group keeps its first home after its work finishes, so a caller from a third domain
    /// gets no home group and its job falls back to the least loaded group.
    #[test]
    fn local_keeps_home_after_work_finishes() {
        let groups = synthetic(&[2, 2]);

        // Calls from domains 0 and 1 home the two groups.
        Groups::fake_domain(Some(0));
        let a = groups.local().unwrap();
        Groups::fake_domain(Some(1));
        let b = groups.local().unwrap();
        assert_ne!(a.group(), b.group());

        // A third domain has no home, even after the existing groups become idle.
        Groups::fake_domain(Some(2));
        assert!(groups.local().is_none());
        drop(a);
        assert!(groups.local().is_none());

        // The third domain's job falls back to the idle group, and every home survives once all
        // work finishes.
        let (fallback, admitted) = groups.root();
        assert!(admitted);
        assert_eq!(fallback.group(), 0);
        assert_eq!(leased(&groups, &b).home.get().copied(), Some(1));
        drop((fallback, b));
        assert!(groups.local().is_none());
        for (group, home) in groups.groups().iter().zip([0, 1]) {
            assert_eq!(group.home.get(), Some(&home));
            assert_eq!(group.state.lock().in_flight(), 0);
        }
        Groups::fake_domain(None);
    }

    /// Homes fixed at build never move. A caller in a domain without a group gets no home group,
    /// and its job takes the least loaded group, even while every group is idle.
    #[test]
    fn fixed_homes_never_move() {
        let groups = synthetic(&[2, 2]);

        // Fix the homes as a build-time partition does.
        for (group, home) in groups.groups.iter().zip([0, 1]) {
            group.home.set(home).unwrap();
        }

        // A domain without a group gets no home, and its job leaves the homes in place.
        Groups::fake_domain(Some(2));
        assert!(groups.local().is_none());
        let (lease, admitted) = groups.root();
        assert!(admitted);
        drop(lease);
        for (group, home) in groups.groups().iter().zip([0, 1]) {
            assert_eq!(group.home.get().copied(), Some(home));
        }

        // A domain with a fixed home gets its group.
        Groups::fake_domain(Some(1));
        assert_eq!(groups.local().unwrap().group(), 1);
        Groups::fake_domain(None);
    }

    /// An unhomed group with work in flight takes no home until that work finishes.
    #[test]
    fn local_homes_only_idle_groups() {
        let groups = synthetic(&[2, 2]);

        // Group 0 takes a home, and a Wide call keeps group 1 busy while domain 1 looks for one.
        Groups::fake_domain(Some(0));
        drop(groups.local().unwrap());
        let work = groups.wide();
        Groups::fake_domain(Some(1));
        assert!(groups.local().is_none());
        assert_eq!(groups.groups()[1].home.get().copied(), None);
        assert_eq!(groups.groups()[1].state.lock().in_flight(), 1);

        // Once the Wide call finishes, domain 1 homes group 1.
        drop(work);
        let lease = groups.local().unwrap();
        assert_eq!(lease.group(), 1);
        assert_eq!(groups.groups()[0].home.get().copied(), Some(0));
        assert_eq!(leased(&groups, &lease).home.get().copied(), Some(1));
        drop(lease);
        Groups::fake_domain(None);
    }

    /// Callers in one domain that look for a group at the same time share one home group.
    #[test]
    fn local_concurrent_callers_share_home() {
        let groups = synthetic(&[2, 2]);
        let started = std::sync::Barrier::new(3);
        let caller = || {
            Groups::fake_domain(Some(0));
            started.wait();
            groups.local().unwrap()
        };

        // Holding the first group's state lock stalls the first creator inside the homing
        // section, and the sleep gives the other caller time to miss the fast path and queue on
        // the homing lock before any home exists.
        let held = groups.groups()[0].state.lock();
        let leases = std::thread::scope(|scope| {
            let first = scope.spawn(caller);
            let second = scope.spawn(caller);
            started.wait();
            std::thread::sleep(std::time::Duration::from_millis(10));
            drop(held);
            [first.join().unwrap(), second.join().unwrap()]
        });
        assert_eq!(
            leases[0].group(),
            leases[1].group(),
            "both callers must share one group"
        );
        let homes = groups
            .groups()
            .iter()
            .filter(|group| group.home.get() == Some(&0))
            .count();
        assert_eq!(homes, 1, "the domain must have one home group");
    }

    /// A caller whose domain gets the last home while its scan is under way claims that home,
    /// whether it looks for a group directly or through a root.
    #[test]
    fn local_claims_home_set_during_scan() {
        for root in [false, true] {
            let groups = synthetic(&[2, 2]);
            Groups::fake_domain(Some(0));
            drop(groups.local().unwrap());

            // The caller pauses after its first home lookup misses, and resumes once the test has
            // homed the last unhomed group in the caller's domain. The channels live in the scope,
            // so a setup failure drops the sender and releases the paused caller.
            let caller = std::thread::scope(|scope| {
                let (paused_tx, paused_rx) = std::sync::mpsc::channel();
                let (resume_tx, resume_rx) = std::sync::mpsc::channel::<()>();
                let caller = scope.spawn(|| {
                    Groups::fake_domain(Some(1));
                    HOMING_SCAN_PAUSE.set(Some(Box::new(move || {
                        paused_tx.send(()).unwrap();
                        resume_rx.recv().unwrap();
                    })));
                    if root {
                        Some(groups.root().0.group())
                    } else {
                        groups.local().map(|lease| lease.group())
                    }
                });
                paused_rx.recv().unwrap();
                Groups::fake_domain(Some(1));
                let last_home = groups.local().unwrap();
                assert_eq!(last_home.group(), 1);
                drop(last_home);
                resume_tx.send(()).unwrap();
                caller.join().unwrap()
            });
            Groups::fake_domain(None);
            assert_eq!(
                caller,
                Some(1),
                "the caller must claim the home set during its scan"
            );
        }
    }

    /// A Wide claim counts against every group and names the group homed in the caller's domain, or
    /// the first group when the domain has no home, as the one to offer the work first.
    #[test]
    fn wide_claims_groups_and_prefers_home() {
        let groups = synthetic(&[2, 2, 2]);

        // Home the first group elsewhere, so the caller's home is not the group that a
        // home-less order would list first anyway.
        Groups::fake_domain(Some(2));
        drop(groups.local().unwrap());

        // The caller's own Local call homes the second group in its domain.
        Groups::fake_domain(Some(0));
        let local = groups.local().unwrap();
        let homed = local.group();
        assert_eq!(homed, 1);

        // A Wide claim from that domain counts once against every group and names the home first.
        let wide = groups.wide();
        assert!(
            groups
                .groups()
                .iter()
                .enumerate()
                .all(|(index, group)| group.state.lock().in_flight()
                    == 1 + usize::from(index == homed)),
            "a wide claim must count against every group"
        );
        assert_eq!(
            wide.group(),
            homed,
            "the caller's home group must be offered the work first"
        );

        // A domain without a home is offered the first group.
        Groups::fake_domain(Some(1));
        let elsewhere = groups.wide();
        assert_eq!(
            elsewhere.group(),
            0,
            "without a home group the first group must be offered the work"
        );

        // Every claim is released.
        drop(elsewhere);
        drop(wide);
        drop(local);
        assert!(
            groups
                .groups()
                .iter()
                .all(|g| g.state.lock().in_flight() == 0)
        );
        Groups::fake_domain(None);
    }

    /// A root prefers waking its submitter's home group while it has only that submitter's
    /// work. Another caller's work redirects the wakeup preference to a different group.
    #[test]
    fn root_avoids_home_leased_by_others() {
        let groups = synthetic(&[2, 2]);

        // The submitter's own Local call keeps its root's wakeup preference at home.
        Groups::fake_domain(Some(0));
        let own = groups.local().unwrap();
        let home = own.group();
        let (job, _) = groups.root();
        assert_eq!(
            job.group(),
            home,
            "the submitter's own work must keep the wakeup preference at home"
        );
        drop(job);

        // Another thread in the same domain finds the home group occupied by this thread's work,
        // so its root prefers waking another group. It then leaves a Local call on its home.
        let other = std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    Groups::fake_domain(Some(0));
                    let (away, _) = groups.root();
                    assert_ne!(
                        away.group(),
                        home,
                        "another caller's work must redirect the wakeup preference"
                    );
                    drop(away);
                    let lease = groups.local().unwrap();
                    assert_eq!(lease.group(), home);
                    lease
                })
                .join()
                .unwrap()
        });

        // The other thread's Local call redirects this thread's root until it finishes.
        let (job, _) = groups.root();
        assert_ne!(
            job.group(),
            home,
            "the other caller's work must redirect this wakeup preference"
        );
        drop(job);
        drop(other);
        let (job, _) = groups.root();
        assert_eq!(
            job.group(),
            home,
            "the wakeup preference must return home once the other work drains"
        );
        drop(job);
        drop(own);
        assert!(
            groups
                .groups()
                .iter()
                .all(|g| g.state.lock().in_flight() == 0)
        );
        Groups::fake_domain(None);
    }

    /// Without a home group a job homes an idle group like a Local call, and without a known
    /// domain it takes the least loaded group.
    #[test]
    fn root_homes_or_takes_least_loaded() {
        let groups = synthetic(&[2, 2]);

        // A job from domain 1 homes an idle group there.
        Groups::fake_domain(Some(1));
        let (job, _) = groups.root();
        assert_eq!(leased(&groups, &job).home.get().copied(), Some(1));

        // A job without a known domain takes the other, idle group.
        Groups::fake_domain(None);
        let busy_index = job.group();
        let (other, _) = groups.root();
        assert_ne!(
            other.group(),
            busy_index,
            "an unknown domain must take the idle group"
        );
        drop(other);
        drop(job);
    }

    /// Widening a root counts as a fresh claim on its own group too, so a later caller without a
    /// home finds every group equally recent and falls back to the first.
    #[test]
    fn root_widening_refreshes_group_recency() {
        let groups = synthetic(&[2, 2]);

        // Home group 0 in domain 0 and group 1 in domain 1.
        Groups::fake_domain(Some(0));
        drop(groups.local().unwrap());
        Groups::fake_domain(Some(1));
        drop(groups.local().unwrap());

        // A root from domain 1 takes group 1, and widening it claims every group at one tick.
        let (root, admitted) = groups.root();
        assert!(admitted);
        assert_eq!(root.group(), 1);
        drop(root.into_wide());
        Groups::fake_domain(None);

        // Both groups carry the widening's tick, so the tie goes to the first group.
        assert_eq!(groups.least_loaded().group(), 0);
    }

    /// Only external roots use up a group's admissions. Descendant leases and Wide calls leave
    /// them free, and a root's admission ends when its own lease drops.
    #[test]
    fn root_admission_excludes_placement_claims() {
        let groups = synthetic(&[2, 2]);

        // A widened root keeps its admission on group 0 and claims every group.
        Groups::fake_domain(Some(0));
        let (first, admitted) = groups.root();
        assert!(admitted);
        let first = first.into_wide();
        assert_eq!(groups.groups[0].state.lock().admitted_roots, 1);
        for group in &groups.groups {
            assert_eq!(group.state.lock().in_flight(), 1);
        }

        // Descendant leases and Wide calls claim groups without occupying root admissions, and
        // widening an overflowing root takes no admission.
        let child_claims: Vec<_> = (0..3).map(|_| groups.lease(0)).collect();
        let wide_call = groups.wide();
        let (second, admitted) = groups.root();
        assert!(admitted);
        let (overflow, admitted) = groups.root();
        assert!(!admitted);
        assert_eq!(groups.groups[0].state.lock().admitted_roots, 2);
        drop(overflow.into_wide());
        assert_eq!(groups.groups[0].state.lock().admitted_roots, 2);

        // A dropped root frees its admission for a replacement, and the admissions end with their
        // roots while the other claims remain.
        drop(first);
        let (replacement, admitted) = groups.root();
        assert!(admitted);
        assert_eq!(replacement.group(), 0);
        drop(second);
        drop(replacement);
        assert_eq!(groups.groups[0].state.lock().admitted_roots, 0);
        assert!(groups.groups[0].state.lock().in_flight() > 0);

        // Releasing the remaining claims leaves every group idle.
        drop(child_claims);
        drop(wide_call);
        for group in &groups.groups {
            let state = group.state.lock();
            assert_eq!(state.admitted_roots, 0);
            assert_eq!(state.in_flight(), 0);
        }
        Groups::fake_domain(None);
    }

    /// Each group admits at most one concurrent root per worker, and its admission counter matches
    /// the admitted leases. Dropping the leases releases both admissions and claims.
    #[test]
    fn root_admission_stays_within_group_width() {
        let groups = synthetic(&[2, 2]);
        let ready = std::sync::Barrier::new(8);

        // Eight roots from eight threads race for two groups of two workers.
        let roots = std::thread::scope(|scope| {
            let callers: Vec<_> = (0..8)
                .map(|_| {
                    scope.spawn(|| {
                        ready.wait();
                        groups.root()
                    })
                })
                .collect();
            callers
                .into_iter()
                .map(|caller| caller.join().unwrap())
                .collect::<Vec<_>>()
        });

        // Some roots overflow, and each group admitted no more than its width.
        assert!(roots.iter().any(|(_, admitted)| !admitted));
        for (index, group) in groups.groups.iter().enumerate() {
            let admitted = roots
                .iter()
                .filter(|(lease, admitted)| *admitted && lease.group() == index)
                .count();
            assert!(admitted <= group.width);
            assert_eq!(group.state.lock().admitted_roots, admitted);
        }

        // Dropping the leases releases the admissions and the claims.
        drop(roots);
        for group in &groups.groups {
            let state = group.state.lock();
            assert_eq!(state.admitted_roots, 0);
            assert_eq!(state.in_flight(), 0);
        }
    }

    /// A pool with one group admits every root without counting admissions, and the claims of
    /// roots from a known domain are released with their leases.
    #[test]
    fn single_group_admits_all_roots() {
        let groups = synthetic(&[2]);
        Groups::fake_domain(Some(0));
        let roots: Vec<_> = (0..8).map(|_| groups.root()).collect();
        assert!(roots.iter().all(|(_, admitted)| *admitted));
        assert_eq!(groups.groups[0].state.lock().admitted_roots, 0);
        assert_eq!(groups.groups[0].state.lock().in_flight(), 8);
        drop(roots);
        assert_eq!(groups.groups[0].state.lock().in_flight(), 0);
        Groups::fake_domain(None);
    }

    /// Claims on a strategy's only group are tracked only when the calling thread's domain is
    /// known. Claims from a thread without one leave the group idle, so a caller with a domain can
    /// still home it.
    #[test]
    fn single_group_tracks_only_known_domains() {
        let groups = synthetic(&[2]);

        // No kind of claim from a thread without a domain is tracked.
        Groups::fake_domain(None);
        let untracked = [
            groups.wide(),
            groups.lease(0),
            groups.least_loaded(),
            groups.root().0.into_wide(),
        ];
        assert!(!groups.groups[0].has_leases());

        // Claims from callers with a known domain are tracked. The first caller homes the group,
        // and one from another domain falls back to it.
        Groups::fake_domain(Some(0));
        let local = groups.local().expect("the idle group must take a home");
        let wide = groups.wide();
        Groups::fake_domain(Some(1));
        let fallback = groups.least_loaded();
        assert_eq!(groups.groups[0].state.lock().in_flight(), 3);

        // Dropping the untracked leases releases none of the tracked claims.
        drop(untracked);
        assert_eq!(groups.groups[0].state.lock().in_flight(), 3);

        // Dropping the tracked leases leaves the group idle.
        drop((local, wide, fallback));
        assert!(!groups.groups[0].has_leases());
        Groups::fake_domain(None);
    }

    /// A group narrower than the first is never homed or leased for Local work, while a call on
    /// the whole pool still leases it.
    #[test]
    fn narrow_group_takes_only_wide_calls() {
        for widths in [&[2, 1][..], &[3, 2][..]] {
            let groups = synthetic(widths);

            // Domain 0 homes the full group.
            Groups::fake_domain(Some(0));
            let held = groups.local().expect("the full group must be homed");
            assert_eq!(held.group(), 0);

            // With the full group busy, another domain gets no home group, and neither
            // `least_loaded` nor a job picks the narrower group. A Wide call still leases both.
            Groups::fake_domain(Some(1));
            assert!(groups.local().is_none());
            assert_eq!(groups.least_loaded().group(), 0);
            assert_eq!(groups.root().0.group(), 0);
            let wide = groups.wide();
            assert!(
                groups
                    .groups()
                    .iter()
                    .all(|group| group.state.lock().in_flight() >= 1)
            );
            drop(wide);
            drop(held);

            // With every group idle, the narrower group still takes no home or job.
            assert!(groups.local().is_none());
            assert_eq!(groups.root().0.group(), 0);
            Groups::fake_domain(Some(0));
            assert_eq!(groups.local().unwrap().group(), 0);
            Groups::fake_domain(None);
            assert_eq!(groups.groups()[1].home.get().copied(), None);
        }
    }

    #[cfg(all(target_os = "linux", not(miri)))]
    mod linux {
        use super::*;
        use crate::Strategy as _;

        /// A mask allowing exactly `cpus`.
        fn cpu_set(cpus: impl IntoIterator<Item = usize>) -> CpuSet {
            let mut mask = CpuSet::empty();
            for cpu in cpus {
                mask.set(cpu);
            }
            mask
        }

        /// A home reserves every allowed CPU of its domain, including those beyond its group's
        /// width, and floating workers get the rest.
        #[test]
        fn reservations_keep_spare_domain_cpus() {
            let lists: Vec<_> = (0..16).map(|cpu| (cpu, (cpu / 8).to_string())).collect();
            let topology = Topology::from_lists(&lists).unwrap();
            let (homes, floating) =
                topology.reservations(&cpu_set(0..16), [(7, Some(0)), (1, None)]);
            assert_eq!(
                homes[0].unwrap().cpus().collect::<Vec<_>>(),
                (0..8).collect::<Vec<_>>()
            );
            assert!(homes[1].is_none());
            assert_eq!(
                floating.unwrap().cpus().collect::<Vec<_>>(),
                (8..16).collect::<Vec<_>>()
            );
        }

        /// When the homes reserve every allowed CPU, floating groups get no mask and fall back to
        /// their original masks.
        #[test]
        fn reservations_omit_floating_mask_at_capacity() {
            let lists: Vec<_> = (0..64).map(|cpu| (cpu, (cpu / 8).to_string())).collect();
            let topology = Topology::from_lists(&lists).unwrap();
            let groups = (0..8)
                .map(|home| (7, Some(home)))
                .chain([(7, None), (1, None)]);
            let (homes, floating) = topology.reservations(&cpu_set(0..64), groups);
            assert!(floating.is_none());
            for (home, mask) in homes[..8].iter().enumerate() {
                let mask = mask.unwrap();
                assert_eq!(mask.cpus().count(), 8);
                assert!(mask.cpus().all(|cpu| cpu / 8 == home));
            }
            assert!(homes[8..].iter().all(Option::is_none));
        }

        /// A home keeps the allowed CPUs of its domain even when they are fewer than its group's
        /// workers, and floating workers get no mask when fewer CPUs remain than there are
        /// floating workers.
        #[test]
        fn reservations_keep_restricted_home_masks() {
            let lists: Vec<_> = (0..12).map(|cpu| (cpu, (cpu >= 4).to_string())).collect();
            let topology = Topology::from_lists(&lists).unwrap();

            // A home narrower than its group keeps its domain's allowed CPUs, and floating workers
            // get the rest.
            let allowed = cpu_set([0, 2, 3, 5, 7, 9, 11]);
            let (homes, floating) = topology.reservations(&allowed, [(5, Some(0)), (2, None)]);
            assert_eq!(homes[0].unwrap().cpus().collect::<Vec<_>>(), vec![0, 2, 3]);
            assert_eq!(
                floating.unwrap().cpus().collect::<Vec<_>>(),
                vec![5, 7, 9, 11]
            );

            // Floating workers get no mask when the home reserves every allowed CPU.
            let (homes, floating) =
                topology.reservations(&cpu_set(0..4), [(3, Some(0)), (3, None)]);
            assert_eq!(homes[0].unwrap().cpus().count(), 4);
            assert!(floating.is_none());
        }

        /// Floating workers get a mask when exactly one CPU remains per floating worker, and none
        /// when one fewer remains.
        #[test]
        fn reservations_float_at_exact_capacity() {
            let lists: Vec<_> = (0..8).map(|cpu| (cpu, (cpu / 4).to_string())).collect();
            let topology = Topology::from_lists(&lists).unwrap();
            let allowed = cpu_set(0..8);
            let (_, floating) = topology.reservations(&allowed, [(3, Some(0)), (4, None)]);
            assert_eq!(
                floating.unwrap().cpus().collect::<Vec<_>>(),
                (4..8).collect::<Vec<_>>()
            );
            let (_, floating) = topology.reservations(&allowed, [(3, Some(0)), (5, None)]);
            assert!(floating.is_none());
        }

        /// The group width follows the domain with the most allowed CPUs, minus one worker from
        /// six allowed CPUs up, and is unavailable when no domain allows two CPUs.
        #[test]
        fn group_width_leaves_slack_in_wide_domains() {
            // Domains of 8, 6, 5, and 1 CPUs.
            let lists: Vec<_> = (0..20)
                .map(|cpu| {
                    let domain = match cpu {
                        0..8 => 0,
                        8..14 => 1,
                        14..19 => 2,
                        _ => 3,
                    };
                    (cpu, domain.to_string())
                })
                .collect();
            let topology = Topology::from_lists(&lists).unwrap();
            let widths = [
                cpu_set(0..20),
                cpu_set(8..20),
                cpu_set(14..20),
                cpu_set([0, 8, 14, 19]),
            ]
            .map(|allowed| Groups::group_width(&topology, &allowed));
            assert_eq!(widths, [Some(7), Some(5), Some(5), None]);
        }

        /// Scattered CPU ids listed out of order. Domain 0 holds 9, 2, and 14, domain 1 holds 5,
        /// 11, and 0, domain 2 holds 7, 12, and 3, and domain 3 holds 1 and 4.
        fn scattered_topology() -> Topology {
            let lists: Vec<_> = [
                (9, 0),
                (2, 0),
                (5, 1),
                (14, 0),
                (11, 1),
                (7, 2),
                (0, 1),
                (12, 2),
                (1, 3),
                (3, 2),
                (4, 3),
            ]
            .into_iter()
            .map(|(cpu, domain): (usize, u8)| (cpu, domain.to_string()))
            .collect();
            Topology::from_lists(&lists).unwrap()
        }

        /// A partition gives each domain with allowed CPUs one group, as wide as its allowed CPUs,
        /// whose mask holds exactly those CPUs.
        #[test]
        fn partition_assigns_allowed_cpus_by_domain() {
            let topology = scattered_topology();

            // Two allowed CPUs in each of domains 0 to 2 and none in domain 3.
            let mut allowed = [14, 0, 9, 3, 5, 12];
            let partition = topology
                .partition(&cpu_set(allowed), allowed.len())
                .unwrap();
            assert_eq!(partition.width, 2);
            let homes: Vec<u16> = partition.homes.iter().map(|&(home, _)| home).collect();
            assert_eq!(homes, vec![0, 1, 2]);

            // Each home's mask stays within its domain, and the homes together hold exactly the
            // allowed CPUs.
            for (home, mask) in partition.homes.iter() {
                assert!(
                    mask.cpus()
                        .all(|cpu| topology.domain_of(cpu) == Some(*home))
                );
            }
            let mut covered: Vec<usize> = partition
                .homes
                .iter()
                .flat_map(|(_, mask)| mask.cpus())
                .collect();
            covered.sort_unstable();
            allowed.sort_unstable();
            assert_eq!(covered, allowed);
        }

        /// Partitioning rejects unequal allowed CPU counts across domains, unknown CPUs, mismatched
        /// worker counts, a single allowed domain, and domains with only one allowed CPU.
        #[test]
        fn partition_rejects_inexact_geometry() {
            let topology = scattered_topology();
            let even: &[usize] = &[9, 14, 5, 0, 12, 3];

            // Each case violates at least one requirement of an exact partition.
            let cases: [(&[usize], usize, &str); 7] = [
                (&[9, 14, 5, 11, 0, 12], 6, "uneven allowed domains"),
                (
                    &[9, 14, 5, 0, 12, 3, 20],
                    6,
                    "an allowed CPU outside every domain",
                ),
                (
                    &[9, 14, 5, 0, 12, 3, 20],
                    7,
                    "an allowed CPU outside every domain",
                ),
                (even, 4, "fewer workers than allowed CPUs"),
                (even, 8, "more workers than allowed CPUs"),
                (&[9, 14], 2, "a single allowed domain"),
                (&[9, 5, 12], 3, "one allowed CPU per domain"),
            ];
            for (allowed, parallelism, case) in cases {
                let allowed = cpu_set(allowed.iter().copied());
                assert!(
                    topology.partition(&allowed, parallelism).is_none(),
                    "the partition must reject {case}"
                );
            }
        }

        /// A leaked two-domain topology that splits up to eight of the calling thread's allowed
        /// CPUs into two halves of equal size.
        fn split_topology() -> Option<(&'static Topology, Vec<usize>, Vec<usize>)> {
            let mut cpus = allowed_cpus();
            if cpus.len() < 4 {
                return None;
            }
            cpus.truncate(cpus.len().min(8) / 2 * 2);
            let (a, b) = cpus.split_at(cpus.len() / 2);
            let lists: Vec<(usize, String)> = a
                .iter()
                .map(|&cpu| (cpu, "a".to_string()))
                .chain(b.iter().map(|&cpu| (cpu, "b".to_string())))
                .collect();
            let topology = Box::leak(Box::new(Topology::from_lists(&lists)?));
            Some((topology, a.to_vec(), b.to_vec()))
        }

        /// Threads are split into groups no wider than a domain, in order, with the remainder
        /// in the last group.
        #[test]
        fn build_splits_threads_by_domain_width() {
            let Some((topology, a, _)) = split_topology() else {
                return;
            };

            let width = if a.len() >= SLACK_FROM {
                a.len() - 1
            } else {
                a.len()
            };
            let groups = Groups::build_in(
                Some(topology),
                ThreadPoolBuilder::new(NZUsize!(2 * width + 1)),
            )
            .unwrap();
            let widths: Vec<usize> = groups.groups().iter().map(Group::width).collect();
            assert_eq!(widths, vec![width, width, 1]);
            assert_eq!(groups.pool().current_num_threads(), 2 * width + 1);
            assert!(groups.affinity.is_some());
        }

        /// Restricts the calling thread to `cpus`.
        fn restrict_to(cpus: &[usize]) {
            let mut mask = CpuSet::empty();
            for &cpu in cpus {
                mask.set(cpu);
            }
            assert!(set_thread_affinity(&mask), "the mask must be writable");
        }

        /// Group widths account for the building thread's allowed CPUs. If no domain has two
        /// allowed CPUs, the pool has one unhomed group.
        #[test]
        fn build_sizes_groups_by_allowed_cpus() {
            let cpus = allowed_cpus();
            if cpus.len() < 4 {
                return;
            }

            // A domain of three CPUs and a domain of the rest.
            let lists: Vec<(usize, String)> = cpus
                .iter()
                .enumerate()
                .map(|(index, &cpu)| (cpu, if index < 3 { "a" } else { "b" }.to_string()))
                .collect();
            let topology: &'static Topology =
                Box::leak(Box::new(Topology::from_lists(&lists).unwrap()));

            // Build with two allowed CPUs in domain a, then with one allowed CPU in each domain.
            let inherited = thread_affinity().expect("affinity mask must be readable");
            restrict_to(&cpus[..2]);
            let narrowed =
                Groups::build_in(Some(topology), ThreadPoolBuilder::new(NZUsize!(5))).unwrap();
            restrict_to(&[cpus[0], cpus[3]]);
            let scattered =
                Groups::build_in(Some(topology), ThreadPoolBuilder::new(NZUsize!(5))).unwrap();
            assert!(set_thread_affinity(&inherited), "the mask must be restored");

            // The first build sizes groups of two, and the second gets one unhomed group.
            let widths: Vec<usize> = narrowed.groups().iter().map(Group::width).collect();
            assert_eq!(widths, vec![2, 2, 1]);
            assert!(narrowed.affinity.is_some());
            let widths: Vec<usize> = scattered.groups().iter().map(Group::width).collect();
            assert_eq!(widths, vec![5]);
            assert!(scattered.affinity.is_none());
        }

        /// Fixed homes require an exact partition of the workers the registry can create.
        #[test]
        fn fixed_homes_use_effective_worker_count() {
            // Exercise exact partitions and requests that can be capped by the registry.
            let allowed = allowed_cpus();
            let limit = crate::rayon::THREADS_MAX;
            let cases = [
                (4, 2, 4),
                (15, 5, 16),
                (limit + 1, limit.div_ceil(2), limit + 1),
                (limit, limit / 3, limit + 1),
            ];
            for (count, domain_width, requested) in cases {
                if allowed.len() < count || domain_width < 2 {
                    continue;
                }

                // Build under a known domain layout and restore the caller before checking it.
                let cpus = &allowed[..count];
                let lists: Vec<_> = cpus
                    .iter()
                    .enumerate()
                    .map(|(index, &cpu)| (cpu, (index / domain_width).to_string()))
                    .collect();
                let topology = Box::leak(Box::new(Topology::from_lists(&lists).unwrap()));
                let inherited = thread_affinity().expect("affinity mask must be readable");
                restrict_to(cpus);
                let built =
                    Groups::build_in(Some(topology), ThreadPoolBuilder::new(NZUsize!(requested)));
                assert!(set_thread_affinity(&inherited), "the mask must be restored");
                let groups = Arc::new(built.unwrap());

                // Only full-width groups can acquire fixed homes.
                let width = groups.groups()[0].width();
                assert!(
                    groups
                        .groups()
                        .iter()
                        .all(|group| group.home.get().is_none() || group.width() == width),
                    "a fixed home must have the full group width"
                );
                if groups.pool().current_num_threads() == count {
                    assert_eq!(width, domain_width);
                    for (index, group) in groups.groups().iter().enumerate() {
                        assert_eq!(
                            group.home.get().copied(),
                            topology.domain_of(cpus[index * domain_width])
                        );
                    }
                }

                // A call from the last domain must still receive a full-width group.
                Groups::fake_domain(topology.domain_of(cpus[count - 1]));
                let lease = groups.local().unwrap();
                Groups::fake_domain(None);
                assert_eq!(groups.groups()[lease.group()].width(), width);
            }
        }

        /// When the building thread's CPUs split evenly over the domains and the pool has one
        /// worker per CPU, each group is homed permanently in its own domain, and its workers run
        /// within that domain's CPUs.
        #[test]
        fn partition_homes_groups_at_build() {
            let Some((topology, a, b)) = split_topology() else {
                return;
            };

            // Build with exactly the split CPUs allowed and one worker per CPU.
            let inherited = thread_affinity().expect("affinity mask must be readable");
            restrict_to(&[a.as_slice(), b.as_slice()].concat());
            let groups = Groups::build_in(
                Some(topology),
                ThreadPoolBuilder::new(NZUsize!(a.len() + b.len())),
            )
            .unwrap();
            assert!(set_thread_affinity(&inherited), "the mask must be restored");

            // Each group is homed in its own domain, and its workers run on that domain's CPUs.
            assert_eq!(groups.pool().group_widths(), vec![a.len(), b.len()]);
            let homes: Vec<_> = groups
                .groups()
                .iter()
                .map(|group| group.home.get().copied())
                .collect();
            assert_eq!(
                homes,
                vec![topology.domain_of(a[0]), topology.domain_of(b[0])]
            );
            let masks = groups.pool().broadcast(|_| allowed_cpus());
            let (first, second) = masks.split_at(a.len());
            assert!(first.iter().all(|mask| *mask == a));
            assert!(second.iter().all(|mask| *mask == b));
        }

        /// Once a group takes its first home, its workers request that domain's CPUs and the
        /// floating worker requests the rest. A later caller from another domain changes neither.
        #[test]
        fn floating_workers_exclude_established_homes() {
            let Some((topology, a, b)) = split_topology() else {
                return;
            };
            let inherited = allowed_cpus();
            let width = a.len();
            let groups = Arc::new(
                Groups::build_in(Some(topology), ThreadPoolBuilder::new(NZUsize!(width + 1)))
                    .unwrap(),
            );
            assert_eq!(groups.pool().group_widths(), vec![width, 1]);

            // Domain b homes the full group, and a later call from domain a changes no mask.
            for home in [&b, &a] {
                Groups::fake_domain(topology.domain_of(home[0]));
                let lease = groups.local();
                assert_eq!(lease.is_some(), home == &b);
                Groups::fake_domain(None);
                assert_eq!(
                    groups.groups()[0].home.get().copied(),
                    topology.domain_of(b[0])
                );

                // Each worker runs broadcasts in the order they were queued, so it reads its mask
                // after applying its requested one.
                let masks = groups.pool().broadcast(|_| allowed_cpus());
                for mask in &masks[..width] {
                    assert_eq!(mask, &b);
                }
                let floating: Vec<_> = inherited
                    .iter()
                    .copied()
                    .filter(|cpu| !b.contains(cpu))
                    .collect();
                assert_eq!(masks[width], floating);
                drop(lease);
            }
        }

        /// A worker applies a usable mask request within its inherited mask and falls back to the
        /// inherited mask when a request leaves it no CPU.
        #[test]
        fn unusable_mask_restores_inherited_mask() {
            let Some((topology, _, b)) = split_topology() else {
                return;
            };
            let groups =
                Groups::build_in(Some(topology), ThreadPoolBuilder::new(NZUsize!(2))).unwrap();
            let requested = cpu_set(b.iter().copied());

            // On a worker, request a narrowing mask and then an empty one.
            let (inherited, narrowed, restored) = groups.pool().install(|| {
                let inherited = allowed_cpus();
                apply_mask(Some(requested), 2);
                let narrowed = allowed_cpus();
                apply_mask(Some(CpuSet::empty()), 1);
                (inherited, narrowed, allowed_cpus())
            });
            assert_eq!(narrowed, b);
            assert_eq!(restored, inherited);
        }

        /// A strategy with one group confines its workers to the group's first home. A later
        /// caller from another domain neither rehomes the group nor moves its workers.
        #[test]
        fn single_group_keeps_first_home_mask() {
            let Some((topology, a, b)) = split_topology() else {
                return;
            };

            // A call from domain b homes the single group there.
            let groups = Arc::new(
                Groups::build_in(Some(topology), ThreadPoolBuilder::new(NZUsize!(a.len())))
                    .unwrap(),
            );
            let domain_b = topology.domain_of(b[0]).unwrap();
            let domain_a = topology.domain_of(a[0]).unwrap();
            Groups::fake_domain(Some(domain_b));
            let lease = groups.local().unwrap();

            // Each worker runs broadcasts in the order they were queued, so it reads its mask
            // after confining itself.
            let masks: Vec<Vec<usize>> = groups.pool().broadcast_in(lease.group(), allowed_cpus);
            for mask in &masks {
                assert!(
                    mask.iter().all(|cpu| b.contains(cpu)),
                    "worker mask {mask:?} must be within {b:?}"
                );
            }
            drop(lease);

            // A caller from domain a gets no home, and its job runs on workers still within b.
            Groups::fake_domain(Some(domain_a));
            assert!(groups.local().is_none());
            let (lease, admitted) = groups.root();
            assert!(admitted);
            assert_eq!(lease.group(), 0);
            let masks: Vec<Vec<usize>> = groups.pool().broadcast_in(lease.group(), allowed_cpus);
            for mask in &masks {
                assert!(
                    mask.iter().all(|cpu| b.contains(cpu)),
                    "worker mask {mask:?} must remain within {b:?}"
                );
            }
            Groups::fake_domain(None);
        }

        /// A domain with fewer allowed CPUs than a full group has workers takes no home and moves
        /// no worker, while a domain with enough allowed CPUs takes one.
        #[test]
        fn narrow_domain_takes_no_home() {
            let cpus = allowed_cpus();
            for narrow_width in [1, 2] {
                let Some(selected) = cpus.get(..narrow_width + 3) else {
                    continue;
                };

                // A domain of one or two CPUs beside a domain of three.
                let (narrow, wide) = selected.split_at(narrow_width);
                let lists: Vec<(usize, String)> = narrow
                    .iter()
                    .map(|&cpu| (cpu, "narrow".to_string()))
                    .chain(wide.iter().map(|&cpu| (cpu, "wide".to_string())))
                    .collect();
                let topology: &'static Topology =
                    Box::leak(Box::new(Topology::from_lists(&lists).unwrap()));

                // Pools of one full group, and of one full group plus a narrower remainder.
                for parallelism in [wide.len(), wide.len() + 1] {
                    let groups = Arc::new(
                        Groups::build_in(
                            Some(topology),
                            ThreadPoolBuilder::new(NZUsize!(parallelism)),
                        )
                        .unwrap(),
                    );
                    assert_eq!(groups.groups()[0].width(), wide.len());

                    // A call from the narrow domain gets no group, no home is assigned, and no
                    // worker's mask changes.
                    Groups::fake_domain(topology.domain_of(narrow[0]));
                    let lease = groups.local();
                    Groups::fake_domain(None);
                    assert!(lease.is_none());
                    assert!(
                        groups
                            .groups()
                            .iter()
                            .all(|group| group.home.get().is_none())
                    );
                    let masks = groups.pool().broadcast(|_| allowed_cpus());
                    assert!(masks.iter().all(|mask| mask == &cpus));

                    // A call from the wide domain homes a group there.
                    Groups::fake_domain(topology.domain_of(wide[0]));
                    let lease = groups.local();
                    Groups::fake_domain(None);
                    let lease = lease.expect("the wide domain must take a home");
                    assert_eq!(
                        groups.groups()[lease.group()].home.get().copied(),
                        topology.domain_of(wide[0])
                    );
                }
            }
        }

        /// Groups homed in domain `b`, their homing lease, and the CPUs of domains `a` and `b`.
        type Homed = (Arc<Groups>, Lease, Vec<usize>, Vec<usize>);

        /// Groups of `a.len()` workers over a split topology, with the group homed in domain `b`.
        fn homed() -> Option<Homed> {
            let (topology, a, b) = split_topology()?;
            let groups = Arc::new(
                Groups::build_in(Some(topology), ThreadPoolBuilder::new(NZUsize!(a.len())))
                    .unwrap(),
            );
            Groups::fake_domain(topology.domain_of(b[0]));
            let lease = groups.local().unwrap();
            Groups::fake_domain(None);
            Some((groups, lease, a, b))
        }

        /// A thread that is not a worker of any `ThreadPool` is restricted to the group's home
        /// domain. Dropping the guard restores its original mask.
        #[test]
        fn nudge_moves_caller_home_temporarily() {
            let Some((groups, lease, a, b)) = homed() else {
                return;
            };
            let original = allowed_cpus();
            Groups::fake_domain(groups.affinity.unwrap().0.domain_of(a[0]));
            let nudge = groups.nudge(lease.group());
            Groups::fake_domain(None);
            assert!(nudge.is_some());
            assert_eq!(allowed_cpus(), b);
            drop(nudge);
            assert_eq!(allowed_cpus(), original);
        }

        /// A caller already in the home domain, a caller whose mask excludes the home, and a call
        /// on a group without a home all leave the caller's mask unchanged.
        #[test]
        fn nudge_leaves_caller_in_place() {
            let Some((groups, lease, a, b)) = homed() else {
                return;
            };
            let topology = groups.affinity.unwrap().0;
            let original = allowed_cpus();

            // A caller already in the home domain stays in place.
            Groups::fake_domain(topology.domain_of(b[0]));
            assert!(groups.nudge(lease.group()).is_none());
            Groups::fake_domain(None);
            assert_eq!(allowed_cpus(), original);

            // A caller whose mask excludes the home stays in place.
            let inherited = thread_affinity().expect("affinity mask must be readable");
            restrict_to(&a);
            Groups::fake_domain(topology.domain_of(a[0]));
            assert!(groups.nudge(lease.group()).is_none());
            Groups::fake_domain(None);
            assert_eq!(allowed_cpus(), a);
            assert!(set_thread_affinity(&inherited), "the mask must be restored");

            // A group without a home leaves the caller in place.
            let unhomed =
                Groups::build_in(Some(topology), ThreadPoolBuilder::new(NZUsize!(2))).unwrap();
            Groups::fake_domain(topology.domain_of(a[0]));
            assert!(unhomed.nudge(0).is_none());
            Groups::fake_domain(None);
            drop(lease);
        }

        /// Workers of another `ThreadPool` keep their masks because that pool owns their placement.
        #[test]
        fn nudge_leaves_foreign_workers_in_place() {
            let Some((groups, lease, a, _)) = homed() else {
                return;
            };
            let other = Groups::build_in(None, ThreadPoolBuilder::new(NZUsize!(1))).unwrap();
            let group = lease.group();
            let caller = Arc::clone(&groups);
            let (moved, before, after) = other.pool().install(move || {
                let before = allowed_cpus();
                Groups::fake_domain(caller.affinity.unwrap().0.domain_of(a[0]));
                let nudge = caller.nudge(group);
                Groups::fake_domain(None);
                (nudge.is_some(), before, allowed_cpus())
            });
            assert!(!moved);
            assert_eq!(before, after);
            drop(lease);
        }

        /// The CPUs the thread at `task`, a `/proc/thread-self` target, may use.
        fn cpus_of(task: &std::path::Path) -> Vec<usize> {
            let path = std::path::Path::new("/proc").join(task).join("status");
            let status = std::fs::read_to_string(path).expect("thread status must be readable");
            let list = status
                .lines()
                .find_map(|line| line.strip_prefix("Cpus_allowed_list:"))
                .expect("thread status must list its allowed CPUs");
            list.trim()
                .split(',')
                .flat_map(|range| {
                    let (first, last) = range.split_once('-').unwrap_or((range, range));
                    first.parse::<usize>().unwrap()..=last.parse::<usize>().unwrap()
                })
                .collect()
        }

        /// A Local strategy call waits in its group's home domain, and a panicking call still
        /// restores the caller's mask. A sort from outside the pool is placed on one group, and
        /// the first call at a call site runs in parallel.
        #[test]
        fn local_panic_restores_caller_mask() {
            let Some((groups, lease, a, b)) = homed() else {
                return;
            };
            drop(lease);

            // A strategy over groups homed in domain b, called from domain a.
            let strategy = crate::Rayon::with_groups(Arc::clone(&groups));
            let caller = std::fs::read_link("/proc/thread-self").expect("thread-self must resolve");
            let original = allowed_cpus();
            let during = Mutex::new(None);
            Groups::fake_domain(groups.affinity.unwrap().0.domain_of(a[0]));

            // The sort's comparator records the caller's CPUs from a worker and then panics.
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let mut items: Vec<u64> = (0..1024).collect();
                strategy.sort_by(&mut items, |_, _| {
                    during.lock().get_or_insert_with(|| cpus_of(&caller));
                    panic!("the comparator panics");
                });
            }));
            Groups::fake_domain(None);

            // The caller's mask was restricted to the home during the sort and restored on unwind,
            // and the panicking call released its lease.
            assert!(result.is_err());
            assert_eq!(during.into_inner(), Some(b));
            assert_eq!(allowed_cpus(), original);
            assert!(
                groups
                    .groups()
                    .iter()
                    .all(|group| group.state.lock().in_flight() == 0),
                "a panicking placed call must release its leases"
            );
        }
    }
}
