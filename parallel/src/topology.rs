//! Last-level-cache topology and the groups a strategy splits its threads into.
//!
//! Exchanging cache lines costs far more between threads in different last-level cache (LLC)
//! domains, and the scheduler places threads without knowing which of them share data. A strategy
//! therefore splits the workers of its one pool into groups sized to the widest domain.
//!
//! A pool filling all allowed CPUs across multiple equally sized domains, each allowing at least
//! two CPUs, gives each group one domain at startup. Otherwise the first local call can give an
//! idle group a permanent home in a domain with enough allowed CPUs for its workers. These groups
//! use one fewer worker than the widest domain when it allows six CPUs or more.
//!
//! Every mask stays within the worker's inherited mask. Fixed groups request their masks before
//! running jobs. Groups homed on demand apply the request asynchronously. The operating system may
//! reject either request, so placement remains advisory.
//!
//! A caller's local work first tries to use or establish a home in the caller's domain, then
//! falls back to the least loaded full-width group. Only that group's workers take the work.
//! Work placed on the whole pool runs on any worker and is offered first to the caller's home
//! group. The caller waits while the workers run parallel operations. When local work runs on a
//! group homed in another domain, the caller's mask is narrowed to that domain's CPUs within its
//! own mask until the call returns.
//!
//! All groups share the pool's fixed worker budget, however many domains have callers. When
//! that budget is not a multiple of the group width, the last group is narrower. Local work
//! there would run narrower than the policy planned, so the group is never homed or leased for
//! local work and takes only work placed on the whole pool.
//!
//! These mask requests illustrate two homed groups and a narrower floating group. All 24 host
//! CPUs are initially allowed, so the floating group's mask is the eight CPUs outside the homes.
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
//! A home uses its domain's allowed CPUs. In a pool with multiple groups, floating groups,
//! including the narrow final group, use the remaining CPUs from the pool's initial mask when
//! enough remain for all floating workers. Otherwise they request their original masks. Other
//! threads can still use the same CPUs. An unusable mask or failed write requests the worker's
//! original mask instead.
//!
//! Groups homed on demand start unhomed. A domain can take a home only when the pool's initial
//! mask is known and allows at least as many CPUs there as a full group has workers. Its first
//! local call can then home an idle group there. A group keeps that home after its work drains.
//! Floating masks exclude new homes as they are assigned, subject to the capacity rule above.
//! In this example, each domain has enough allowed CPUs for a full group:
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
//! A pool that fills equal-sized allowed domains uses fixed homes instead. No workers float,
//! and an idle group keeps its domain:
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
//! An offloaded job submitted from outside the pool prefers the group homed in the submitting
//! thread's domain, unless another submitting thread has work on that group. Every external root
//! enters the shared Wide queue, so an idle worker can start it even while the preferred group is
//! busy. Its leases count work on every group until the job finishes.
//!
//! Each group admits one external root per worker for learning descendant placement. Admitted
//! roots use the learned Local or Wide placement. Excess roots run Wide. Local descendants stay
//! on the group of the worker that starts the root. A root planned Local that lands on the narrower
//! final group runs Wide and contributes no descendant-placement sample. Jobs submitted by a pool
//! worker inherit its current placement.
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
//!   +-- group homed at D, idle or busy only with T's work -> that group
//!   |
//!   +-- group homed at D, busy with another thread's work -> least loaded group
//!
//! selected group G
//!   |
//!   v
//! shared queue, prefer G ----> any idle worker in group H
//!                               |
//!                               +-- admitted, Local, H has planned width --> Local(H)
//!                               |
//!                               +-- otherwise ----------------------------> Wide
//! ```
//!
//! Domains come from the kernel's sysfs cache topology, where each CPU's last-level cache is its
//! highest-level Data or Unified cache leaf. Machines whose possible-CPU count exceeds
//! `cpu_set_t`'s capacity report no domains. On non-Linux platforms and under miri, a strategy is
//! a single unhomed group and no mask is ever written.
//!
//! A worker's initial affinity mask limits every later home, and CPUs that are offline when the
//! worker starts are absent from that mask. Linux 6.2 and newer preserve a written affinity mask
//! across cpuset changes where possible. Older kernels can replace it with the cpuset's effective
//! CPUs, so a group may lose confinement.

use crate::ThreadPool;
#[cfg(test)]
use crate::rayon::Placement;
use commonware_utils::sync::Mutex;
use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    thread::ThreadId,
};

/// The fewest CPUs the building thread must be allowed in the widest domain before groups use
/// one fewer worker, leaving room for other threads. Smaller domains retain the worker, since
/// it represents a larger share of their capacity.
#[cfg(all(target_os = "linux", not(miri)))]
const SLACK_FROM: usize = 6;

cfg_if::cfg_if! {
    if #[cfg(all(target_os = "linux", not(miri)))] {
        use std::sync::OnceLock;

        /// Byte size of `cpu_set_t`, as passed to the affinity syscalls.
        const CPU_SET_BYTES: usize = std::mem::size_of::<libc::cpu_set_t>();

        /// Number of CPUs a `cpu_set_t` can represent.
        const CPU_SETSIZE: usize = libc::CPU_SETSIZE as usize;

        /// A CPU affinity mask: a safe wrapper over `libc::cpu_set_t`.
        // Together with `thread_affinity`, `set_thread_affinity`, and `current_cpu`, this
        // funnels all of the module's libc FFI through a handful of one-line unsafe blocks, so
        // the rest of the module is safe code.
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

            fn cpus(&self) -> impl Iterator<Item = usize> + '_ {
                (0..CPU_SETSIZE).filter(|&cpu| self.contains(cpu))
            }

            fn intersection(&self, other: &Self) -> (Self, usize) {
                let mut mask = Self::empty();
                let mut count = 0;
                for cpu in self.cpus().filter(|&cpu| other.contains(cpu)) {
                    mask.set(cpu);
                    count += 1;
                }
                (mask, count)
            }

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
            /// touches only the domain's CPUs, so it costs a few bit tests.
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

        /// The process-wide topology, detected on first use.
        pub(crate) fn topology() -> &'static Topology {
            static TOPOLOGY: OnceLock<Topology> = OnceLock::new();
            TOPOLOGY.get_or_init(Topology::detect)
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
            /// The static partition of `parallelism` workers over the domains `allowed` reaches,
            /// or `None` unless every such domain has the same number of allowed CPUs, at least
            /// two, there are at least two such domains, every allowed CPU lies in one of them,
            /// and `parallelism` equals the allowed CPU count.
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

            /// Reserves allowed domain CPUs for home groups and leaves the complement for floaters.
            /// A home with fewer than two allowed CPUs floats. A complement smaller than the
            /// floating worker count requests the inherited-mask fallback instead.
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
                        let mask = home.and_then(|home| {
                            let (mask, count) = self.domains[usize::from(home)].within(allowed);
                            (count > 1).then_some(mask)
                        });
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

            /// Detects the LLC topology, or returns an empty one when the affinity syscalls cannot
            /// work on this host, sysfs is unreadable, or `from_lists` rejects the lists.
            fn detect() -> Self {
                // The affinity syscalls fail on every call when the possible-CPU count exceeds
                // cpu_set_t's capacity, whatever CPU ids sysfs shows, so no worker could ever be
                // confined to a domain.
                if thread_affinity().is_none() {
                    return Self::empty();
                }
                Self::from_sysfs().unwrap_or_else(Self::empty)
            }

            /// An empty topology, under which a strategy is a single unhomed group.
            fn empty() -> Self {
                Self {
                    cpu_to_domain: Box::new([]),
                    domains: Box::new([]),
                }
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

            /// The `shared_cpu_list` of the last-level cache under `cpu_dir`, the
            /// highest-level Data or Unified leaf among its `cache/index*` directories. The leaf
            /// index varies by architecture and cache layout, so every leaf is inspected.
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
            /// list string. Returns `None` when the pairs are empty, form a single domain, leave
            /// every domain with one CPU, include a CPU at or past `CPU_SETSIZE`, or form more
            /// domains than a `u16` can index.
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

                // One domain leaves nowhere to move work, and confinement needs two CPUs in a
                // domain for a group's workers to share. A host whose every cache is private to one
                // CPU therefore has no domain to home a group in.
                if domains.len() <= 1 || cpus.iter().all(|domain| domain.len() < 2) {
                    return None;
                }
                Some(Self {
                    cpu_to_domain: table.into_boxed_slice(),
                    domains: cpus.into_iter().map(Domain::new).collect(),
                })
            }
        }

        std::thread_local! {
            /// The affinity mask a group worker started with. Homing confines the worker within
            /// it, so operator restrictions such as taskset or isolated cores are kept.
            static INHERITED: std::cell::Cell<Option<CpuSet>> = const { std::cell::Cell::new(None) };
        }

        /// Records the calling worker's starting mask for later homing.
        fn remember_inherited_mask() {
            INHERITED.with(|cell| cell.set(thread_affinity()));
        }

        /// Applies a requested mask within the worker's original mask. An unusable request or
        /// failed write gets one attempt to restore that original mask.
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

        /// Confines the calling worker to the CPUs of `domain` that its inherited mask allows. A
        /// worker keeps its current mask when it has no recorded inherited mask, when the write
        /// fails, or when confinement would leave it fewer than two CPUs to share with its group.
        fn confine_to(domain: &'static Domain) {
            let Some(inherited) = INHERITED.with(|cell| cell.get()) else {
                return;
            };
            let (effective, allowed) = domain.within(&inherited);
            if allowed > 1 {
                set_thread_affinity(&effective);
            }
        }

        /// Restores the calling thread's mask when dropped.
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

/// Restores a caller's mask when dropped. No mask changes where no topology exists.
#[cfg(not(all(target_os = "linux", not(miri))))]
pub(crate) struct Restore;

#[cfg(test)]
std::thread_local! {
    /// A domain tests assign to the calling thread in place of the one the kernel reports, so the
    /// group logic can be driven on any platform.
    static FAKE_DOMAIN: std::cell::Cell<Option<u16>> = const { std::cell::Cell::new(None) };
}

/// A group's home and the work in flight on it. The group is idle while no thread has work in
/// flight on it. Claims, releases, and homing all hold the group's lock on this state, so a group
/// found idle gains no work before it is homed.
#[derive(Debug)]
struct State {
    /// The requested home domain, or `None` before the group has been homed.
    home: Option<u16>,
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
    /// Counts a placed call or job of the calling thread against the group.
    fn claim(&mut self, tick: u64) {
        self.last_used = tick;
        let me = std::thread::current().id();
        match self.submitters.iter_mut().find(|(id, _)| *id == me) {
            Some((_, count)) => *count += 1,
            None => self.submitters.push((me, 1)),
        }
    }

    fn release(&mut self, submitter: ThreadId) {
        if let Some(position) = self.submitters.iter().position(|(id, _)| *id == submitter) {
            self.submitters[position].1 -= 1;
            if self.submitters[position].1 == 0 {
                self.submitters.swap_remove(position);
            }
        }
    }

    /// The number of placed calls and jobs in flight on the group.
    fn in_flight(&self) -> usize {
        self.submitters.iter().map(|(_, count)| count).sum()
    }
}

/// One group of a strategy's workers, with its home and its load.
#[derive(Debug)]
pub(crate) struct Group {
    /// The number of workers in the group.
    width: usize,
    /// Whether the group can be homed and is preferred for local work. It must be as wide as the
    /// first group and have more than one worker. Another group takes local work only when no
    /// group qualifies, as in a pool of one worker.
    placeable: bool,
    /// The group's home and the work in flight on it.
    state: Mutex<State>,
}

impl Group {
    const fn new(width: usize, full: usize) -> Self {
        Self {
            width,
            placeable: width > 1 && width == full,
            state: Mutex::new(State {
                home: None,
                last_used: 0,
                submitters: Vec::new(),
                admitted_roots: 0,
            }),
        }
    }

    /// Whether any thread has work registered on the group, for tests of lease accounting.
    #[cfg(test)]
    pub(crate) fn busy_with_others_for_test(&self) -> bool {
        !self.state.lock().submitters.is_empty()
    }

    /// Whether a thread other than the calling one has work in flight on the group.
    fn busy_with_others(&self) -> bool {
        let me = std::thread::current().id();
        self.state.lock().submitters.iter().any(|(id, _)| *id != me)
    }

    pub(crate) const fn width(&self) -> usize {
        self.width
    }

    const fn placeable(&self) -> bool {
        self.placeable
    }
}

/// The groups a strategy splits the workers of its pool into.
pub(crate) struct Groups {
    /// The strategy's pool, whose workers form the groups.
    pool: ThreadPool,
    /// The strategy's groups, in the order of the pool's groups, which together hold all of its
    /// threads.
    groups: Box<[Group]>,
    /// Number of domains a group may be homed in. Zero disables homing.
    domains: usize,
    /// Claim counter that orders the groups' `last_used` ticks. It starts at 1, so a
    /// claimed group is more recent than a group never claimed.
    ticks: AtomicU64,
    /// Held by a local caller from its search for a home group until it holds one, so a domain
    /// has at most one home group.
    homing: Mutex<()>,
    /// The topology whose domains the groups are homed in, if any.
    #[cfg(all(target_os = "linux", not(miri)))]
    topology: Option<&'static Topology>,
    /// The mask used to size the pool's groups and select their CPU reservations.
    #[cfg(all(target_os = "linux", not(miri)))]
    allowed: Option<CpuSet>,
}

impl std::fmt::Debug for Groups {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Groups")
            .field("groups", &self.groups)
            .field("domains", &self.domains)
            .finish_non_exhaustive()
    }
}

/// Counts one call or job against a group until the lease is dropped. An unhomed group with work
/// in flight cannot acquire a home.
#[derive(Debug)]
pub(crate) struct Lease {
    groups: Arc<Groups>,
    index: usize,
    submitter: ThreadId,
    admitted: bool,
}

impl Lease {
    /// The leased group's index among the pool's groups.
    pub(crate) const fn group(&self) -> usize {
        self.index
    }

    /// Extends this claim to every group while retaining its root admission, if any.
    pub(crate) fn into_wide(self) -> Vec<Self> {
        let mut leases = self.groups.wide();
        let home = leases
            .iter()
            .position(|lease| lease.index == self.index)
            .expect("wide claims must include the leased group");
        leases[home] = self;
        leases
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        let mut state = self.groups.groups[self.index].state.lock();
        if self.admitted {
            assert!(state.admitted_roots > 0);
            state.admitted_roots -= 1;
        }
        state.release(self.submitter);
    }
}

impl Groups {
    /// The groups of a caller's pool, which are never homed.
    pub(crate) fn single(pool: ThreadPool) -> Self {
        Self::over(pool, 0)
    }

    /// The groups of `pool`'s workers, homed among `domains` domains.
    fn over(pool: ThreadPool, domains: usize) -> Self {
        let widths = pool.group_widths();
        let full = widths.first().copied().unwrap_or(0);
        let groups = widths
            .iter()
            .map(|&width| Group::new(width, full))
            .collect();
        Self {
            pool,
            groups,
            domains,
            ticks: AtomicU64::new(1),
            homing: Mutex::new(()),
            #[cfg(all(target_os = "linux", not(miri)))]
            topology: None,
            #[cfg(all(target_os = "linux", not(miri)))]
            allowed: None,
        }
    }

    /// Builds a pool of `parallelism` threads, with `stack_size` per worker when one is given, and
    /// splits its workers into groups sized to the widest domain. A pool filling equal-sized
    /// allowed domains gets homes at startup. Other groups are homed once, on demand.
    /// A host with fewer than two domains, a thread allowed fewer than two CPUs in every domain,
    /// and platforms without affinity control get one unhomed group of `parallelism` threads.
    pub(crate) fn build(
        parallelism: usize,
        stack_size: Option<usize>,
    ) -> Result<Self, crate::rayon::ThreadPoolBuildError> {
        #[cfg(all(target_os = "linux", not(miri)))]
        {
            let topology = topology();
            if topology.domains.len() > 1 {
                return Self::build_in(Some(topology), parallelism, stack_size);
            }
        }
        Self::build_in(None, parallelism, stack_size)
    }

    /// The number of domains and the group width for a strategy the calling thread builds, or
    /// `None` when it gets one unhomed group.
    ///
    /// Workers inherit the building thread's mask, and homing confines them within it, so a group
    /// spans the CPUs that mask allows in the widest domain, less one when the mask allows
    /// [`SLACK_FROM`] of them or more. A thread allowed fewer than two CPUs in every domain gets
    /// `None`.
    #[cfg(all(target_os = "linux", not(miri)))]
    fn group_width(topology: &Topology, allowed: Option<&CpuSet>) -> Option<(usize, usize)> {
        let widest = topology
            .domains
            .iter()
            .map(|domain| allowed.map_or(domain.cpus.len(), |allowed| domain.within(allowed).1))
            .max()?;
        let width = if widest >= SLACK_FROM {
            widest - 1
        } else {
            widest
        };
        (width > 1).then_some((topology.domains.len(), width))
    }

    /// [`Self::build`] for an explicit topology, or none.
    fn build_in(
        #[cfg(all(target_os = "linux", not(miri)))] topology: Option<&'static Topology>,
        #[cfg(not(all(target_os = "linux", not(miri))))] topology: Option<()>,
        parallelism: usize,
        stack_size: Option<usize>,
    ) -> Result<Self, crate::rayon::ThreadPoolBuildError> {
        let parallelism = parallelism.max(1);

        #[cfg(all(target_os = "linux", not(miri)))]
        let allowed = topology.and_then(|_| thread_affinity());
        #[cfg(all(target_os = "linux", not(miri)))]
        let partition = topology
            .zip(allowed.as_ref())
            .and_then(|(topology, allowed)| topology.partition(allowed, parallelism));
        #[cfg(all(target_os = "linux", not(miri)))]
        let (domains, width) = match (&partition, topology) {
            (Some(partition), Some(topology)) => (topology.domains.len(), partition.width),
            _ => topology
                .and_then(|topology| Self::group_width(topology, allowed.as_ref()))
                .unwrap_or((0, parallelism)),
        };
        #[cfg(not(all(target_os = "linux", not(miri))))]
        let (domains, width) = {
            let _ = topology;
            (0, parallelism)
        };
        let width = width.clamp(1, parallelism);
        let mut builder = crate::rayon::ThreadPoolBuilder::new()
            .num_threads(parallelism)
            .group_width(width)
            .thread_name(move |index| format!("group{}-{}", index / width, index % width));
        #[cfg(all(target_os = "linux", not(miri)))]
        {
            // A statically partitioned worker confines itself to its group's domain before it
            // runs any job.
            let masks: Option<Box<[CpuSet]>> = partition
                .as_ref()
                .map(|partition| partition.homes.iter().map(|&(_, mask)| mask).collect());
            builder = builder.start_handler(move |index| {
                remember_inherited_mask();
                if let Some(masks) = &masks {
                    apply_mask(Some(masks[index / width]), 2);
                }
            });
        }
        if let Some(stack_size) = stack_size {
            builder = builder.stack_size(stack_size);
        }
        let groups = Self::over(Arc::new(builder.build()?), domains);
        #[cfg(all(target_os = "linux", not(miri)))]
        let groups = {
            if let Some(partition) = &partition {
                for (group, &(home, _)) in groups.groups.iter().zip(partition.homes.iter()) {
                    group.state.lock().home = Some(home);
                }
            }
            Self {
                topology,
                allowed,
                ..groups
            }
        };
        Ok(groups)
    }

    /// The groups of a caller-built pool that tests home among `domains` fake domains.
    #[cfg(test)]
    pub(crate) fn synthetic(pool: ThreadPool, domains: usize) -> Self {
        Self::over(pool, domains)
    }

    /// Assigns `domain` to the calling thread for the group logic, in place of the domain the
    /// kernel reports.
    #[cfg(test)]
    pub(crate) fn fake_domain(domain: Option<u16>) {
        FAKE_DOMAIN.with(|cell| cell.set(domain));
    }

    pub(crate) fn groups(&self) -> &[Group] {
        &self.groups
    }

    /// The strategy's pool.
    pub(crate) const fn pool(&self) -> &ThreadPool {
        &self.pool
    }

    /// The total thread count of the groups.
    pub(crate) fn threads(&self) -> usize {
        self.groups.iter().map(|group| group.width).sum()
    }

    /// The group the calling thread is a worker of, if any.
    #[cfg(test)]
    pub(crate) fn member(&self) -> Option<&Group> {
        self.pool
            .current_worker()
            .map(|worker| &self.groups[worker.group])
    }

    /// The calling thread's domain, or `None` when homing is disabled or the domain is unknown.
    #[allow(
        clippy::missing_const_for_fn,
        reason = "const only where no topology exists"
    )]
    fn current_domain(&self) -> Option<u16> {
        #[cfg(test)]
        if let Some(domain) = FAKE_DOMAIN.with(|cell| cell.get()) {
            return (usize::from(domain) < self.domains).then_some(domain);
        }
        if self.domains == 0 {
            return None;
        }
        #[cfg(all(target_os = "linux", not(miri)))]
        {
            self.topology?.current_domain()
        }
        #[cfg(not(all(target_os = "linux", not(miri))))]
        {
            None
        }
    }

    /// Claims a group for a local call from the calling thread. The call takes the group homed in
    /// the thread's domain, or homes the first idle, unhomed group that can take local work.
    /// A new home requires enough allowed CPUs for every worker in the group. Returns `None`
    /// when the thread's domain is unknown or no group can serve it.
    pub(crate) fn local(self: &Arc<Self>) -> Option<Lease> {
        let domain = self.current_domain()?;
        let _homing = self.homing.lock();
        let tick = self.ticks.fetch_add(1, Ordering::Relaxed);

        // A group already homed here, busy or not.
        for (index, group) in self.groups.iter().enumerate() {
            let mut state = group.state.lock();
            if state.home == Some(domain) {
                state.claim(tick);
                return Some(Lease {
                    groups: Arc::clone(self),
                    index,
                    submitter: std::thread::current().id(),
                    admitted: false,
                });
            }
        }

        // A new home needs a known mask with room for every worker in a full group.
        #[cfg(all(target_os = "linux", not(miri)))]
        if let Some(topology) = self.topology {
            let (_, count) = topology.domains[usize::from(domain)].within(self.allowed.as_ref()?);
            if count < self.groups[0].width {
                return None;
            }
        }

        // Queue the first home's request before releasing the Groups::homing lock. Workers
        // process it after their own deques drain. A worker searching another queue can take
        // local work first.
        for (index, group) in self
            .groups
            .iter()
            .enumerate()
            .filter(|(_, group)| group.placeable())
        {
            let mut state = group.state.lock();
            if state.home.is_some() || !state.submitters.is_empty() {
                continue;
            }
            state.home = Some(domain);
            state.claim(tick);
            let lease = Lease {
                groups: Arc::clone(self),
                index,
                submitter: std::thread::current().id(),
                admitted: false,
            };
            drop(state);
            self.home(index, domain);
            return Some(lease);
        }
        None
    }

    /// Queues a home's mask and the floating workers' complement while the homing lock is held.
    /// Each worker processes the requests in order after its own deques drain. Writes are best
    /// effort, so different workers can temporarily use different mask snapshots.
    #[allow(
        clippy::missing_const_for_fn,
        reason = "const only where no topology exists"
    )]
    fn home(&self, group: usize, domain: u16) {
        #[cfg(all(target_os = "linux", not(miri)))]
        if let Some(topology) = self.topology {
            if let Some(allowed) = self.allowed.as_ref().filter(|_| self.groups.len() > 1) {
                let (homes, floating) = topology.reservations(
                    allowed,
                    self.groups
                        .iter()
                        .map(|group| (group.width, group.state.lock().home)),
                );
                for (index, home) in homes.into_iter().enumerate() {
                    if index == group || home.is_none() {
                        let (requested, minimum) =
                            home.map_or((floating, 1), |home| (Some(home), 2));
                        self.pool
                            .spawn_broadcast_in(index, move || apply_mask(requested, minimum));
                    }
                }
                return;
            }
            let target: &'static Domain = &topology.domains[usize::from(domain)];
            self.pool
                .spawn_broadcast_in(group, move || confine_to(target));
            return;
        }
        let _ = (group, domain);
    }

    /// Claims every group for a call that may run on any of them. The group homed in the calling
    /// thread's domain comes first, and its idle workers are offered the call's work first. Any
    /// worker may take the call's work, and the leases count it on every group until the call
    /// finishes.
    pub(crate) fn wide(self: &Arc<Self>) -> Vec<Lease> {
        let home = self.current_domain().and_then(|domain| {
            self.groups
                .iter()
                .position(|group| group.state.lock().home == Some(domain))
        });
        let mut order: Vec<usize> = (0..self.groups.len()).collect();
        if let Some(home) = home {
            order.remove(home);
            order.insert(0, home);
        }
        let tick = self.ticks.fetch_add(1, Ordering::Relaxed);
        order
            .into_iter()
            .map(|index| {
                self.groups[index].state.lock().claim(tick);
                Lease {
                    groups: Arc::clone(self),
                    index,
                    submitter: std::thread::current().id(),
                    admitted: false,
                }
            })
            .collect()
    }

    /// Claims an existing placement's group without changing its home.
    pub(crate) fn lease(self: &Arc<Self>, index: usize) -> Lease {
        let tick = self.ticks.fetch_add(1, Ordering::Relaxed);
        self.groups[index].state.lock().claim(tick);
        Lease {
            groups: Arc::clone(self),
            index,
            submitter: std::thread::current().id(),
            admitted: false,
        }
    }

    /// Claims the group with the least work in flight, and among those the one used least
    /// recently, so work without a usable home group keeps away from groups other callers are
    /// using. A group that cannot take local work comes last, whatever its load.
    pub(crate) fn least_loaded(self: &Arc<Self>) -> Lease {
        let index = (0..self.groups.len())
            .min_by_key(|&index| {
                let group = &self.groups[index];
                let state = group.state.lock();
                (!group.placeable(), state.in_flight(), state.last_used)
            })
            .expect("a strategy must have at least one group");
        self.lease(index)
    }

    /// Moves the calling thread, which is outside the pool, into the home domain of `group` for a
    /// local call. The returned guard restores the thread's mask. The thread stays put when it
    /// already runs there, when the group has no home, or when it is a worker of any pool, whose
    /// own pool places it.
    #[cfg(all(target_os = "linux", not(miri)))]
    pub(crate) fn nudge(&self, group: usize) -> Option<Restore> {
        if crate::rayon::in_worker() {
            return None;
        }
        let topology = self.topology?;
        let home = self.groups[group].state.lock().home?;
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
    /// descendant placement. The root prefers its submitter's home unless another caller has
    /// work there. Without a usable home, it homes an idle unhomed group or takes the least
    /// loaded group.
    ///
    /// Every root enters the shared Wide queue and may start on any worker. A group admits at
    /// most one root per worker. Excess roots execute Wide. Admission lasts until the job drops
    /// its lease, independently of its descendants' claims. A single-group pool admits every root.
    pub(crate) fn for_job(self: &Arc<Self>) -> (Lease, bool) {
        let mut lease = self
            .current_domain()
            .and_then(|domain| {
                let home = self
                    .groups
                    .iter()
                    .position(|group| group.state.lock().home == Some(domain));
                if home.is_some_and(|index| self.groups[index].busy_with_others()) {
                    None
                } else {
                    self.local()
                }
            })
            .unwrap_or_else(|| self.least_loaded());
        if self.groups.len() == 1 {
            return (lease, true);
        }
        let group = &self.groups[lease.index];
        let mut state = group.state.lock();
        if state.admitted_roots == group.width {
            return (lease, false);
        }
        assert!(state.admitted_roots < group.width);
        state.admitted_roots += 1;
        lease.admitted = true;
        (lease, true)
    }

    /// One line per group: width, home, and in-flight count.
    #[cfg(any(feature = "test-utils", test))]
    pub(crate) fn describe(&self) -> String {
        self.groups
            .iter()
            .enumerate()
            .map(|(index, group)| {
                let state = group.state.lock();
                format!(
                    "group {index}: width {} home {:?} in_flight {}",
                    group.width,
                    state.home,
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

    /// Groups of `widths` workers in one pool, homed among `domains` fake domains. Every width
    /// but the last must equal the first.
    fn synthetic(widths: &[usize], domains: usize) -> Arc<Groups> {
        let pool = crate::rayon::ThreadPoolBuilder::new()
            .num_threads(widths.iter().sum())
            .group_width(widths[0])
            .build()
            .unwrap();
        assert_eq!(pool.group_widths(), widths);
        Arc::new(Groups::synthetic(Arc::new(pool), domains))
    }

    /// The group a lease holds.
    fn leased<'a>(groups: &'a Groups, lease: &Lease) -> &'a Group {
        &groups.groups()[lease.group()]
    }

    #[test]
    fn build_splits_parallelism_into_domain_wide_groups() {
        let groups = Groups::build(5, None).unwrap();
        assert_eq!(groups.threads(), 5);
        let widths: Vec<usize> = groups.groups().iter().map(Group::width).collect();
        assert_eq!(widths.iter().sum::<usize>(), 5);

        // A host without domains to home groups in gets one group of every thread.
        if groups.domains == 0 {
            assert_eq!(widths, vec![5]);
        }
    }

    #[test]
    fn local_homes_an_idle_group_and_reuses_it() {
        let groups = synthetic(&[2, 2], 2);
        Groups::fake_domain(Some(1));
        let lease = groups.local().expect("an idle group must be homed");
        assert_eq!(leased(&groups, &lease).state.lock().home, Some(1));
        assert_eq!(leased(&groups, &lease).state.lock().in_flight(), 1);
        let again = groups
            .local()
            .expect("the homed group must be reused while busy");
        assert_eq!(again.index, lease.index);
        assert_eq!(leased(&groups, &lease).state.lock().in_flight(), 2);
        drop(again);
        drop(lease);
        assert_eq!(groups.groups()[0].state.lock().in_flight(), 0);
        Groups::fake_domain(None);
    }

    #[test]
    fn local_keeps_each_first_home_after_its_work_finishes() {
        let groups = synthetic(&[2, 2], 3);
        Groups::fake_domain(Some(0));
        let a = groups.local().unwrap();
        Groups::fake_domain(Some(1));
        let b = groups.local().unwrap();
        assert_ne!(a.index, b.index);

        // A third domain has no home, even after the existing groups become idle.
        Groups::fake_domain(Some(2));
        assert!(groups.local().is_none());
        drop(a);

        assert!(groups.local().is_none());
        let (fallback, admitted) = groups.for_job();
        assert!(admitted);
        assert_eq!(fallback.group(), 0);
        assert_eq!(leased(&groups, &b).state.lock().home, Some(1));
        drop((fallback, b));
        assert!(groups.local().is_none());
        for (group, home) in groups.groups().iter().zip([0, 1]) {
            let state = group.state.lock();
            assert_eq!(state.home, Some(home));
            assert_eq!(state.in_flight(), 0);
        }
        Groups::fake_domain(None);
    }

    /// Homes fixed at build never move. A caller in a domain without a group gets no home group,
    /// and its job takes the least loaded group, even while every group is idle.
    #[test]
    fn fixed_homes_never_move() {
        let groups = synthetic(&[2, 2], 3);
        for (group, home) in groups.groups.iter().zip([0, 1]) {
            group.state.lock().home = Some(home);
        }

        Groups::fake_domain(Some(2));
        assert!(groups.local().is_none());
        let (lease, admitted) = groups.for_job();
        assert!(admitted);
        drop(lease);
        for (group, home) in groups.groups().iter().zip([0, 1]) {
            assert_eq!(group.state.lock().home, Some(home));
        }

        Groups::fake_domain(Some(1));
        assert_eq!(groups.local().unwrap().group(), 1);
        Groups::fake_domain(None);
    }

    #[test]
    fn local_waits_for_existing_work_before_a_groups_first_home() {
        let groups = synthetic(&[2, 2], 2);
        Groups::fake_domain(Some(0));
        drop(groups.local().unwrap());
        let work = groups.wide();
        Groups::fake_domain(Some(1));
        assert!(groups.local().is_none());
        assert_eq!(groups.groups()[1].state.lock().home, None);
        assert_eq!(groups.groups()[1].state.lock().in_flight(), 1);

        drop(work);
        let lease = groups.local().unwrap();
        assert_eq!(lease.group(), 1);
        assert_eq!(groups.groups()[0].state.lock().home, Some(0));
        assert_eq!(leased(&groups, &lease).state.lock().home, Some(1));
        drop(lease);
        Groups::fake_domain(None);
    }

    /// Callers in one domain that look for a group at the same time share one home group.
    #[test]
    fn local_homes_one_group_for_concurrent_callers_in_a_domain() {
        let groups = synthetic(&[2, 2], 2);
        let started = std::sync::Barrier::new(3);
        let caller = || {
            Groups::fake_domain(Some(0));
            started.wait();
            groups.local().unwrap()
        };

        // Holding the second group's lock stalls a search for a home group partway, and the
        // sleep gives both callers time to ask for a group before either can home one.
        let held = groups.groups()[1].state.lock();
        let leases = std::thread::scope(|scope| {
            let first = scope.spawn(caller);
            let second = scope.spawn(caller);
            started.wait();
            std::thread::sleep(std::time::Duration::from_millis(10));
            drop(held);
            [first.join().unwrap(), second.join().unwrap()]
        });
        assert_eq!(
            leases[0].index, leases[1].index,
            "both callers must share one group"
        );
        let homes = groups
            .groups()
            .iter()
            .filter(|group| group.state.lock().home == Some(0))
            .count();
        assert_eq!(homes, 1, "the domain must have one home group");
    }

    #[test]
    fn wide_takes_every_group_home_first() {
        let groups = synthetic(&[2, 2, 2], 3);
        Groups::fake_domain(Some(0));
        let local = groups.local().unwrap();
        let homed = local.index;
        let leases = groups.wide();
        assert_eq!(leases.len(), 3);
        assert_eq!(
            leases[0].index, homed,
            "the caller's home group must come first"
        );
        Groups::fake_domain(Some(1));
        let elsewhere = groups.wide();
        assert_eq!(
            elsewhere[0].index, 0,
            "without a home group the order must be unchanged"
        );
        drop(elsewhere);
        drop(leases);
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
    fn jobs_prefer_home_unless_another_caller_occupies_it() {
        let groups = synthetic(&[2, 2], 2);
        Groups::fake_domain(Some(0));
        let own = groups.local().unwrap();
        let home = own.index;
        let (job, _) = groups.for_job();
        assert_eq!(
            job.index, home,
            "the submitter's own work must keep the wakeup preference at home"
        );
        drop(job);

        // Another thread in the same domain finds the home group occupied by this thread's
        // work, so its root prefers waking another group. It then leaves a local call on its home.
        let other = std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    Groups::fake_domain(Some(0));
                    let (away, _) = groups.for_job();
                    assert_ne!(
                        away.index, home,
                        "another caller's work must redirect the wakeup preference"
                    );
                    drop(away);
                    let lease = groups.local().unwrap();
                    assert_eq!(lease.index, home);
                    lease
                })
                .join()
                .unwrap()
        });
        let (job, _) = groups.for_job();
        assert_ne!(
            job.index, home,
            "the other caller's work must redirect this wakeup preference"
        );
        drop(job);
        drop(other);
        let (job, _) = groups.for_job();
        assert_eq!(
            job.index, home,
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

    /// Without a home group a job homes an idle group like a local call, and without a known
    /// domain it takes the least loaded group.
    #[test]
    fn jobs_home_an_idle_group_or_take_the_least_loaded() {
        let groups = synthetic(&[2, 2], 2);
        Groups::fake_domain(Some(1));
        let (job, _) = groups.for_job();
        assert_eq!(leased(&groups, &job).state.lock().home, Some(1));
        Groups::fake_domain(None);
        let busy_index = job.index;
        let (other, _) = groups.for_job();
        assert_ne!(
            other.index, busy_index,
            "an unknown domain must take the idle group"
        );
        drop(other);
        drop(job);
    }

    #[test]
    fn root_admission_is_independent_of_placement_claims() {
        let groups = synthetic(&[2, 2], 2);
        Groups::fake_domain(Some(0));
        let (first, admitted) = groups.for_job();
        assert!(admitted);
        let first = first.into_wide();
        assert_eq!(groups.groups[0].state.lock().admitted_roots, 1);
        for group in &groups.groups {
            assert_eq!(group.state.lock().in_flight(), 1);
        }

        // Descendants and placed calls hold homes without occupying root admissions.
        let child_claims: Vec<_> = (0..3).map(|_| groups.lease(0)).collect();
        let wide_call = groups.wide();
        let (second, admitted) = groups.for_job();
        assert!(admitted);
        let (overflow, admitted) = groups.for_job();
        assert!(!admitted);
        assert_eq!(groups.groups[0].state.lock().admitted_roots, 2);
        drop(overflow.into_wide());
        assert_eq!(groups.groups[0].state.lock().admitted_roots, 2);

        drop(first);
        let (replacement, admitted) = groups.for_job();
        assert!(admitted);
        assert_eq!(replacement.group(), 0);
        drop(second);
        drop(replacement);
        assert_eq!(groups.groups[0].state.lock().admitted_roots, 0);
        assert!(groups.groups[0].state.lock().in_flight() > 0);
        drop(child_claims);
        drop(wide_call);
        for group in &groups.groups {
            let state = group.state.lock();
            assert_eq!(state.admitted_roots, 0);
            assert_eq!(state.in_flight(), 0);
        }
        Groups::fake_domain(None);
    }

    #[test]
    fn concurrent_root_admission_stays_within_each_groups_width() {
        let groups = synthetic(&[2, 2], 0);
        let ready = std::sync::Barrier::new(8);
        let roots = std::thread::scope(|scope| {
            let callers: Vec<_> = (0..8)
                .map(|_| {
                    scope.spawn(|| {
                        ready.wait();
                        groups.for_job()
                    })
                })
                .collect();
            callers
                .into_iter()
                .map(|caller| caller.join().unwrap())
                .collect::<Vec<_>>()
        });
        assert!(roots.iter().any(|(_, admitted)| !admitted));
        for (index, group) in groups.groups.iter().enumerate() {
            let admitted = roots
                .iter()
                .filter(|(lease, admitted)| *admitted && lease.group() == index)
                .count();
            assert!(admitted <= group.width);
            assert_eq!(group.state.lock().admitted_roots, admitted);
        }
        drop(roots);
        for group in &groups.groups {
            let state = group.state.lock();
            assert_eq!(state.admitted_roots, 0);
            assert_eq!(state.in_flight(), 0);
        }
    }

    #[test]
    fn a_single_group_admits_every_root() {
        let groups = synthetic(&[2], 0);
        let roots: Vec<_> = (0..8).map(|_| groups.for_job()).collect();
        assert!(roots.iter().all(|(_, admitted)| *admitted));
        assert_eq!(groups.groups[0].state.lock().admitted_roots, 0);
        assert_eq!(groups.groups[0].state.lock().in_flight(), 8);
        drop(roots);
        assert_eq!(groups.groups[0].state.lock().in_flight(), 0);
    }

    /// A group narrower than the first is never homed or leased for local work, while a call on
    /// the whole pool still leases it.
    #[test]
    fn a_narrower_group_takes_only_wide_calls() {
        for widths in [&[2, 1][..], &[3, 2][..]] {
            let groups = synthetic(widths, 2);
            Groups::fake_domain(Some(0));
            let held = groups.local().expect("the full group must be homed");
            assert_eq!(held.group(), 0);

            // With the full group busy, another domain gets no home group, and neither
            // `least_loaded` nor a job picks the narrower group. A wide call still leases both.
            Groups::fake_domain(Some(1));
            assert!(groups.local().is_none());
            assert_eq!(groups.least_loaded().group(), 0);
            assert_eq!(groups.for_job().0.group(), 0);
            assert_eq!(groups.wide().len(), 2);
            drop(held);
            assert!(groups.local().is_none());
            assert_eq!(groups.for_job().0.group(), 0);
            Groups::fake_domain(Some(0));
            assert_eq!(groups.local().unwrap().group(), 0);
            Groups::fake_domain(None);
            assert_eq!(groups.groups()[1].state.lock().home, None);
        }
    }

    #[test]
    fn member_finds_a_workers_own_group() {
        let groups = synthetic(&[2, 1], 0);
        assert!(groups.member().is_none());
        for (group, width) in [(0, 2), (1, 1)] {
            let found = groups.pool().install_in(Placement::Local(group), || {
                groups.member().map(Group::width)
            });
            assert_eq!(found, Some(width));
        }
    }

    #[cfg(all(target_os = "linux", not(miri)))]
    mod linux {
        use super::*;
        use crate::Strategy as _;

        fn cpu_set(cpus: impl IntoIterator<Item = usize>) -> CpuSet {
            let mut mask = CpuSet::empty();
            for cpu in cpus {
                mask.set(cpu);
            }
            mask
        }

        #[test]
        fn full_domain_home_retains_spare_cpus() {
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

        #[test]
        fn full_domains_request_floating_fallback_at_capacity() {
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

        #[test]
        fn reservations_keep_partial_masks_and_underwidth_homes() {
            let lists: Vec<_> = (0..12).map(|cpu| (cpu, (cpu >= 4).to_string())).collect();
            let topology = Topology::from_lists(&lists).unwrap();
            let allowed = cpu_set([0, 2, 3, 5, 7, 9, 11]);
            let (homes, floating) = topology.reservations(&allowed, [(5, Some(0)), (2, None)]);
            assert_eq!(homes[0].unwrap().cpus().collect::<Vec<_>>(), vec![0, 2, 3]);
            assert_eq!(
                floating.unwrap().cpus().collect::<Vec<_>>(),
                vec![5, 7, 9, 11]
            );

            for allowed in [cpu_set([0, 5, 7, 9, 11]), cpu_set([5, 7, 9, 11])] {
                let (homes, floating) = topology.reservations(&allowed, [(2, Some(0)), (2, None)]);
                assert!(homes.iter().all(Option::is_none));
                assert_eq!(
                    floating.unwrap().cpus().collect::<Vec<_>>(),
                    allowed.cpus().collect::<Vec<_>>()
                );
            }

            let (homes, floating) =
                topology.reservations(&cpu_set(0..4), [(3, Some(0)), (3, None)]);
            assert_eq!(homes[0].unwrap().cpus().count(), 4);
            assert!(floating.is_none());
        }

        /// Scattered CPU ids listed out of order: domain 0 holds 9, 2, and 14, domain 1 holds 5,
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

        #[test]
        fn partition_gives_each_allowed_domain_one_group_of_its_allowed_cpus() {
            let topology = scattered_topology();

            // Two allowed CPUs in each of domains 0 to 2 and none in domain 3.
            let mut allowed = [14, 0, 9, 3, 5, 12];
            let partition = topology
                .partition(&cpu_set(allowed), allowed.len())
                .unwrap();
            assert_eq!(partition.width, 2);
            let homes: Vec<u16> = partition.homes.iter().map(|&(home, _)| home).collect();
            assert_eq!(homes, vec![0, 1, 2]);
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

        #[test]
        fn partition_rejects_inexact_geometry() {
            let topology = scattered_topology();
            let even: &[usize] = &[9, 14, 5, 0, 12, 3];
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
                    "{case}"
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
            let groups = Groups::build_in(Some(topology), 2 * width + 1, None).unwrap();
            let widths: Vec<usize> = groups.groups().iter().map(Group::width).collect();
            assert_eq!(widths, vec![width, width, 1]);
            assert_eq!(groups.threads(), 2 * width + 1);
            assert_eq!(groups.domains, 2);
        }

        /// Restricts the calling thread to `cpus`.
        fn restrict_to(cpus: &[usize]) {
            let mut mask = CpuSet::empty();
            for &cpu in cpus {
                mask.set(cpu);
            }
            assert!(set_thread_affinity(&mask), "the mask must be writable");
        }

        /// Groups are as wide as the CPUs the building thread may use in the widest domain, less
        /// one on a domain wide enough to spare it. A thread allowed fewer than two CPUs in every
        /// domain gets one unhomed group.
        #[test]
        fn build_sizes_groups_by_the_allowed_cpus_of_a_domain() {
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
            let inherited = thread_affinity().expect("affinity mask must be readable");
            restrict_to(&cpus[..2]);
            let narrowed = Groups::build_in(Some(topology), 5, None).unwrap();
            restrict_to(&[cpus[0], cpus[3]]);
            let scattered = Groups::build_in(Some(topology), 5, None).unwrap();
            assert!(set_thread_affinity(&inherited), "the mask must be restored");

            let widths: Vec<usize> = narrowed.groups().iter().map(Group::width).collect();
            assert_eq!(widths, vec![2, 2, 1]);
            assert_eq!(narrowed.domains, 2);
            let widths: Vec<usize> = scattered.groups().iter().map(Group::width).collect();
            assert_eq!(widths, vec![5]);
            assert_eq!(scattered.domains, 0);
        }

        /// When the building thread's CPUs split evenly over the domains and the pool has one
        /// worker per CPU, each group is homed permanently in its own domain, and its workers are
        /// confined there before they run any job.
        #[test]
        fn exact_partition_homes_each_group_in_its_domain_at_build() {
            let Some((topology, a, b)) = split_topology() else {
                return;
            };
            let inherited = thread_affinity().expect("affinity mask must be readable");
            restrict_to(&[a.as_slice(), b.as_slice()].concat());
            let groups = Groups::build_in(Some(topology), a.len() + b.len(), None).unwrap();
            assert!(set_thread_affinity(&inherited), "the mask must be restored");

            assert_eq!(groups.pool().group_widths(), vec![a.len(), b.len()]);
            let homes: Vec<_> = groups
                .groups()
                .iter()
                .map(|group| group.state.lock().home)
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

        #[test]
        fn floating_workers_keep_excluding_a_groups_first_home() {
            let Some((topology, a, b)) = split_topology() else {
                return;
            };
            let inherited = allowed_cpus();
            let width = a.len();
            let groups = Arc::new(Groups::build_in(Some(topology), width + 1, None).unwrap());
            assert_eq!(groups.pool().group_widths(), vec![width, 1]);

            for home in [&b, &a] {
                Groups::fake_domain(topology.domain_of(home[0]));
                let lease = groups.local();
                assert_eq!(lease.is_some(), home == &b);
                Groups::fake_domain(None);
                assert_eq!(
                    groups.groups()[0].state.lock().home,
                    topology.domain_of(b[0])
                );

                // FIFO observations follow the mask commands on each worker.
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

        #[test]
        fn unusable_mask_restores_the_workers_inherited_mask() {
            let Some((topology, _, b)) = split_topology() else {
                return;
            };
            let groups = Groups::build_in(Some(topology), 2, None).unwrap();
            let requested = cpu_set(b.iter().copied());
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

        #[test]
        fn a_single_group_keeps_its_first_domain_mask() {
            let Some((topology, a, b)) = split_topology() else {
                return;
            };

            let groups = Arc::new(Groups::build_in(Some(topology), a.len(), None).unwrap());
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
            Groups::fake_domain(Some(domain_a));
            assert!(groups.local().is_none());
            let (lease, admitted) = groups.for_job();
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

        #[test]
        fn a_domain_narrower_than_a_group_takes_no_home() {
            let cpus = allowed_cpus();
            for narrow_width in [1, 2] {
                let Some(selected) = cpus.get(..narrow_width + 3) else {
                    continue;
                };
                let (narrow, wide) = selected.split_at(narrow_width);
                let lists: Vec<(usize, String)> = narrow
                    .iter()
                    .map(|&cpu| (cpu, "narrow".to_string()))
                    .chain(wide.iter().map(|&cpu| (cpu, "wide".to_string())))
                    .collect();
                let topology: &'static Topology =
                    Box::leak(Box::new(Topology::from_lists(&lists).unwrap()));

                for parallelism in [wide.len(), wide.len() + 1] {
                    let groups =
                        Arc::new(Groups::build_in(Some(topology), parallelism, None).unwrap());
                    assert_eq!(groups.groups()[0].width(), wide.len());

                    Groups::fake_domain(topology.domain_of(narrow[0]));
                    let lease = groups.local();
                    Groups::fake_domain(None);
                    assert!(lease.is_none());
                    assert!(
                        groups
                            .groups()
                            .iter()
                            .all(|group| group.state.lock().home.is_none())
                    );
                    let masks = groups.pool().broadcast(|_| allowed_cpus());
                    assert!(masks.iter().all(|mask| mask == &cpus));

                    Groups::fake_domain(topology.domain_of(wide[0]));
                    let lease = groups.local();
                    Groups::fake_domain(None);
                    let lease = lease.expect("the wide domain must take a home");
                    assert_eq!(
                        groups.groups()[lease.group()].state.lock().home,
                        topology.domain_of(wide[0])
                    );
                }
            }
        }

        #[test]
        fn unreadable_building_mask_leaves_groups_unhomed() {
            let Some((topology, a, _)) = split_topology() else {
                return;
            };
            let mut groups = Groups::build_in(Some(topology), a.len() + 1, None).unwrap();
            groups.allowed = None;
            let groups = Arc::new(groups);

            Groups::fake_domain(topology.domain_of(a[0]));
            let lease = groups.local();
            Groups::fake_domain(None);
            assert!(lease.is_none());
            assert!(
                groups
                    .groups()
                    .iter()
                    .all(|group| group.state.lock().home.is_none())
            );
        }

        /// Groups homed in domain `b`, the lease that homed them, and the CPUs of domains `a` and
        /// `b`.
        type Homed = (Arc<Groups>, Lease, Vec<usize>, Vec<usize>);

        /// Groups of `a.len()` workers over a split topology, with the group homed in domain `b`.
        fn homed_in_b() -> Option<Homed> {
            let (topology, a, b) = split_topology()?;
            let groups = Arc::new(Groups::build_in(Some(topology), a.len(), None).unwrap());
            Groups::fake_domain(topology.domain_of(b[0]));
            let lease = groups.local().unwrap();
            Groups::fake_domain(None);
            Some((groups, lease, a, b))
        }

        /// A caller outside the pool runs in its group's home domain for the call and gets its
        /// original mask back when the guard drops.
        #[test]
        fn nudge_moves_the_caller_into_the_home_for_the_call() {
            let Some((groups, lease, a, b)) = homed_in_b() else {
                return;
            };
            let original = allowed_cpus();
            Groups::fake_domain(groups.topology.unwrap().domain_of(a[0]));
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
        fn nudge_leaves_a_caller_in_place() {
            let Some((groups, lease, a, b)) = homed_in_b() else {
                return;
            };
            let topology = groups.topology.unwrap();
            let original = allowed_cpus();
            Groups::fake_domain(topology.domain_of(b[0]));
            assert!(groups.nudge(lease.group()).is_none());
            Groups::fake_domain(None);
            assert_eq!(allowed_cpus(), original);

            let inherited = thread_affinity().expect("affinity mask must be readable");
            restrict_to(&a);
            Groups::fake_domain(topology.domain_of(a[0]));
            assert!(groups.nudge(lease.group()).is_none());
            Groups::fake_domain(None);
            assert_eq!(allowed_cpus(), a);
            assert!(set_thread_affinity(&inherited), "the mask must be restored");

            let unhomed = Groups::build_in(Some(topology), 2, None).unwrap();
            Groups::fake_domain(topology.domain_of(a[0]));
            assert!(unhomed.nudge(0).is_none());
            Groups::fake_domain(None);
            drop(lease);
        }

        /// A worker of another pool is never moved, since its own pool places it.
        #[test]
        fn nudge_leaves_workers_of_other_pools_in_place() {
            let Some((groups, lease, _, _)) = homed_in_b() else {
                return;
            };
            let other = Groups::build_in(None, 1, None).unwrap();
            let group = lease.group();
            let caller = Arc::clone(&groups);
            let (moved, before, after) = other.pool().install(move || {
                let before = allowed_cpus();
                let nudge = caller.nudge(group);
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

        /// A local strategy call waits in its group's home domain, and a panicking call still
        /// restores the caller's mask. A sort from outside the pool is placed on one group, and
        /// the first call at a call site runs in parallel.
        #[test]
        fn local_call_restores_the_callers_mask_when_it_panics() {
            let Some((groups, lease, a, b)) = homed_in_b() else {
                return;
            };
            drop(lease);
            let strategy = crate::Rayon::over(Arc::clone(&groups), groups.threads());
            let caller = std::fs::read_link("/proc/thread-self").expect("thread-self must resolve");
            let original = allowed_cpus();
            let during = Mutex::new(None);
            Groups::fake_domain(groups.topology.unwrap().domain_of(a[0]));
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let mut items: Vec<u64> = (0..1024).collect();
                strategy.sort_by(&mut items, |_, _| {
                    during.lock().get_or_insert_with(|| cpus_of(&caller));
                    panic!("the comparator panics");
                });
            }));
            Groups::fake_domain(None);
            assert!(result.is_err());
            assert_eq!(during.into_inner(), Some(b));
            assert_eq!(allowed_cpus(), original);
        }
    }
}
