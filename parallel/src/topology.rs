//! Last-level-cache topology and the groups a strategy splits its threads into.
//!
//! Exchanging cache lines costs far more between threads in different last-level cache (LLC)
//! domains, and the scheduler places threads without knowing which of them share data. A strategy
//! therefore splits the `parallelism` workers of its one pool into groups, each one worker
//! narrower than a domain of six CPUs or more and as wide as a smaller one, and homes a group in a
//! domain by confining its workers to that domain's CPUs. The CPU a group leaves free is for the
//! caller and the runtime's threads: a group that fills its domain has them preempt its workers
//! and the balancer push the caller out, which costs more than the worker on a wide domain and
//! less on a narrow one. A caller's local work runs on the group homed in the caller's domain,
//! next to the caller's cache, and only that group's workers take any of it. Work that wants every
//! thread runs on any worker, offered first to the caller's home group, and a collection operation
//! from outside the pool has the calling thread help. The strategy never has more threads than its
//! parallelism, however many domains ask for them. A group narrower than the first, left over when
//! the parallelism is not a multiple of the group width, is never homed or leased for a placed
//! call, which would run narrower than the policy planned; its workers take the work placed on
//! the whole pool. [`grouped_parallelism`](crate::grouped_parallelism) sizes a thread budget so
//! that no group is left over.
//!
//! ```text
//! host: three LLC domains of eight CPUs      strategy(14): one pool, two groups of seven
//!
//!    domain A          domain B          domain C
//!  +------------+    +------------+    +------------+
//!  | cpu 0-7    |    | cpu 8-15   |    | cpu 16-23  |
//!  |            |    |            |    |            |
//!  | group 0    |    | group 1    |    | no group   |
//!  | w0 .. w6   |    | w7 .. w13  |    | homed here |
//!  | home: A    |    | home: B    |    |            |
//!  | 1 cpu free |    | 1 cpu free |    |            |
//!  +------------+    +------------+    +------------+
//!        ^                 ^
//!        |                 +-- local work from a task on B runs here and nowhere else
//!        +-- local work from a task on A runs here and nowhere else;
//!            wide work runs on any worker, the caller's home group asked first
//! ```
//!
//! A group is built unhomed: its workers keep the mask they inherited and run anywhere. The first
//! local call from a domain homes an idle group there, and a group with no work in flight can be
//! homed again by a later caller in another domain, so the threads follow demand. A group with
//! work in flight keeps its home until that work drains.
//!
//! ```text
//!        group 0           group 1           caller                 outcome
//!  t0    unhomed, idle     unhomed, idle
//!  t1    home A, busy      unhomed, idle     task on A, local call  homes group 0 at A
//!  t2    home A, busy      home B, busy      task on B, local call  homes group 1 at B
//!  t3    home A, busy      home B, busy      task on C, local call  none free: wide or serial
//!  t4    home A, idle      home B, idle      both calls returned
//!  t5    home C, busy      home B, idle      task on C, local call  re-homes group 0 at C
//! ```
//!
//! A spawned job shares data with its submitter, so it runs in the group homed in the
//! submitter's domain and waits there behind the submitter's own work. When that group is busy
//! with another caller's work, waiting buys the job nothing, so it goes to the least loaded group
//! instead. Each group therefore counts its in-flight calls and jobs per submitting thread.
//!
//! ```text
//! job from thread T in domain D
//!   |
//!   +-- D unknown ----------------------------------------> least loaded group
//!   |
//!   +-- no group homed at D ------------------------------> home an idle group at D,
//!   |                                                       as a local call would
//!   |
//!   +-- group homed at D, idle or busy only with T's work -> that group, queued behind
//!   |                                                       T's own work
//!   |
//!   +-- group homed at D, busy with another thread's work -> least loaded group
//! ```
//!
//! Domains come from the kernel's sysfs cache topology, where each CPU's last-level cache is its
//! highest-level Data or Unified cache leaf. Machines whose possible-CPU count exceeds
//! `cpu_set_t`'s capacity report no domains. On non-Linux platforms and under miri, a strategy is
//! a single unhomed group and no mask is ever written.
//!
//! The kernel reports only active CPUs in a thread's mask, so a mask a worker writes omits every
//! CPU that is offline at that moment. From Linux 6.2 the kernel also keeps a written mask as the
//! thread's own request, so a homed worker stops following later growth of its cpuset until the
//! group is homed again. Before 6.2 the kernel instead rewrites the mask of every task in a cpuset
//! other than the root whenever that cpuset's CPUs change, which removes a group's confinement
//! until its next homing.

use crate::ThreadPool;
#[cfg(test)]
use crate::rayon::Placement;

/// The number of CPUs a domain must allow for a group there to leave one of them free. On
/// domains of eight CPUs the free CPU cut the workers' involuntary context switches ten to
/// thirty times and the pipeline's mean latency ten to twenty percent; on domains of four the
/// lost quarter of a group's width cost more than the contention it removed.
#[cfg(all(target_os = "linux", not(miri)))]
const SLACK_FROM: usize = 6;
use commonware_utils::sync::Mutex;
use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    thread::ThreadId,
};

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
            /// detection time. A submitter on such a CPU, or on one past the end of the table, has
            /// no domain, so it gets no Local arm and its jobs take the least loaded group, because
            /// a guessed domain could move its work away from its cache.
            cpu_to_domain: Box<[Option<u16>]>,
            /// Each domain's CPUs, indexed by domain.
            domains: Box<[Domain]>,
        }

        impl Topology {
            /// Detects the LLC topology, or returns an empty one when the affinity syscalls cannot
            /// work on this host, sysfs is unreadable, or `from_lists` rejects the lists.
            fn detect() -> Self {
                // The affinity syscalls fail on every call when the possible-CPU count exceeds
                // cpu_set_t's capacity, whatever CPU ids sysfs shows. Reporting no domains then
                // saves every spawn a syscall that cannot succeed.
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

            /// The `shared_cpu_list` of `cpu`'s last-level cache: the highest-level Data or
            /// Unified leaf under its `cache/index*` directory. The leaf index varies by
            /// architecture and cache layout, so every leaf is inspected.
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

        /// The CPUs the calling thread may currently use, for tests and diagnostics.
        #[cfg(test)]
        fn allowed_cpus() -> Vec<usize> {
            let mask = thread_affinity().expect("affinity mask must be readable");
            (0..CPU_SETSIZE).filter(|&cpu| mask.contains(cpu)).collect()
        }
    }
}

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
    /// The domain the group's workers are confined to, or `None` while the group runs anywhere.
    home: Option<u16>,
    /// The tick of the group's latest claim by a local caller, so a caller that needs a group
    /// takes the one idle longest.
    used: u64,
    /// The claim tick of the group's latest placed call or job, so a job that leaves its home
    /// group goes to the group used least recently.
    last_used: u64,
    /// The threads with placed calls or jobs from outside the strategy's pool in flight on this
    /// group, with their counts, so a job can tell its submitter's own work from another caller's.
    submitters: Vec<(ThreadId, usize)>,
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

/// One group of a strategy's workers, one worker narrower than a domain, with its home and its
/// load.
#[derive(Debug)]
pub(crate) struct Group {
    /// The number of workers in the group.
    width: usize,
    /// Whether a placed call may run on the group: it is as wide as the first group and has
    /// more than one worker. A narrower leftover group, or one worker, takes only work placed
    /// on the whole pool.
    placeable: bool,
    /// The group's home and the work in flight on it.
    state: Mutex<State>,
    /// Times the group was homed, for diagnostics.
    rehomes: AtomicUsize,
}

impl Group {
    const fn new(width: usize, full: usize) -> Self {
        Self {
            width,
            placeable: width > 1 && width == full,
            state: Mutex::new(State {
                home: None,
                used: 0,
                last_used: 0,
                submitters: Vec::new(),
            }),
            rehomes: AtomicUsize::new(0),
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

    /// Whether a placed call may run on the group, which a narrower leftover group or one
    /// worker never does.
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
    /// Number of domains a group may be homed in; zero disables homing.
    domains: usize,
    /// Claim counter that orders the groups' `used` and `last_used` ticks. It starts at 1, so a
    /// claimed group is more recent than a group never claimed.
    ticks: AtomicU64,
    /// Held by a local caller from its search for a home group until it holds one, so a domain
    /// has at most one home group.
    homing: Mutex<()>,
    /// The topology whose domains the groups are homed in, if any.
    #[cfg(all(target_os = "linux", not(miri)))]
    topology: Option<&'static Topology>,
}

impl std::fmt::Debug for Groups {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Groups")
            .field("groups", &self.groups)
            .field("domains", &self.domains)
            .finish_non_exhaustive()
    }
}

/// Holds one unit of a group's in-flight count for a placed call or job from outside the pool,
/// released on drop. A group with in-flight work is neither homed elsewhere nor counted idle.
#[derive(Debug)]
pub(crate) struct Lease {
    groups: Arc<Groups>,
    index: usize,
    submitter: ThreadId,
}

impl Lease {
    /// The index of the leased group, which is its index among the pool's groups.
    pub(crate) const fn group(&self) -> usize {
        self.index
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        self.groups.groups[self.index]
            .state
            .lock()
            .release(self.submitter);
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
        }
    }

    /// Builds a pool of `parallelism` threads with `stack_size` per worker when one is given, and
    /// splits its workers into groups spanning the CPUs the calling thread may use in the widest
    /// domain, less one on a domain wide enough to spare it. A host with fewer than two domains,
    /// a thread allowed fewer than two CPUs in every domain, and every platform without affinity
    /// control get one unhomed group of `parallelism` threads.
    pub(crate) fn build(
        parallelism: usize,
        stack_size: Option<usize>,
    ) -> Result<Self, crate::ThreadPoolBuildError> {
        #[cfg(all(target_os = "linux", not(miri)))]
        {
            let topology = topology();
            if topology.domains.len() > 1 {
                return Self::build_in(Some(topology), parallelism, stack_size);
            }
        }
        Self::build_in(None, parallelism, stack_size)
    }

    /// The width of the groups a strategy built on this host gets, with the number of domains,
    /// or `None` where it gets one unhomed group.
    ///
    /// Workers inherit the building thread's mask, and homing confines them within it, so a
    /// group spans the CPUs that mask allows in the widest domain, less one when the domain has
    /// [`SLACK_FROM`] CPUs or more: the calling thread and the runtime's threads keep that CPU
    /// instead of preempting a worker. A group needs two workers, so a thread allowed fewer than
    /// two CPUs in every domain gets no groups.
    #[cfg(all(target_os = "linux", not(miri)))]
    fn group_width(topology: &Topology) -> Option<(usize, usize)> {
        let allowed = thread_affinity();
        let widest = topology
            .domains
            .iter()
            .map(|domain| {
                allowed
                    .as_ref()
                    .map_or(domain.cpus.len(), |allowed| domain.within(allowed).1)
            })
            .max()?;
        let width = if widest >= SLACK_FROM {
            widest - 1
        } else {
            widest
        };
        (width > 1).then_some((topology.domains.len(), width))
    }

    /// The parallelism that fills the groups of a strategy built on this host from a budget of
    /// `threads`: the largest multiple of the group width that does not exceed the budget, or
    /// the budget itself where it holds less than one group or the host has no domains.
    #[allow(
        clippy::missing_const_for_fn,
        reason = "const only where no topology exists"
    )]
    pub(crate) fn grouped_parallelism(threads: usize) -> usize {
        #[cfg(all(target_os = "linux", not(miri)))]
        {
            let topology = topology();
            if topology.domains.len() > 1 {
                return Self::grouped_parallelism_in(topology, threads);
            }
        }
        threads
    }

    /// [`Self::grouped_parallelism`] for an explicit topology.
    #[cfg(all(target_os = "linux", not(miri)))]
    fn grouped_parallelism_in(topology: &Topology, threads: usize) -> usize {
        match Self::group_width(topology) {
            Some((_, width)) if threads >= width => threads / width * width,
            _ => threads,
        }
    }

    /// [`Self::build`] for an explicit topology, or none.
    fn build_in(
        #[cfg(all(target_os = "linux", not(miri)))] topology: Option<&'static Topology>,
        #[cfg(not(all(target_os = "linux", not(miri))))] topology: Option<()>,
        parallelism: usize,
        stack_size: Option<usize>,
    ) -> Result<Self, crate::ThreadPoolBuildError> {
        let parallelism = parallelism.max(1);

        #[cfg(all(target_os = "linux", not(miri)))]
        let (domains, width) = topology
            .and_then(Self::group_width)
            .unwrap_or((0, parallelism));
        #[cfg(not(all(target_os = "linux", not(miri))))]
        let (domains, width) = {
            let _ = topology;
            (0, parallelism)
        };
        let width = width.clamp(1, parallelism);
        let mut builder = crate::ThreadPoolBuilder::new()
            .num_threads(parallelism)
            .group_width(width)
            .thread_name(move |index| format!("group{}-{}", index / width, index % width));
        #[cfg(all(target_os = "linux", not(miri)))]
        {
            builder = builder.start_handler(|_| remember_inherited_mask());
        }
        if let Some(stack_size) = stack_size {
            builder = builder.stack_size(stack_size);
        }
        let groups = Self::over(Arc::new(builder.build()?), domains);
        #[cfg(all(target_os = "linux", not(miri)))]
        let groups = Self { topology, ..groups };
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

    /// The calling thread's domain, when it may hold a group.
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

    /// Whether a local call from the calling thread could get a group: one is homed in the
    /// thread's domain, or one a call may be placed on is idle and could be homed there.
    pub(crate) fn can_local(&self) -> bool {
        let Some(domain) = self.current_domain() else {
            return false;
        };
        self.groups
            .iter()
            .filter(|group| group.placeable())
            .any(|group| {
                let state = group.state.lock();
                state.home == Some(domain) || state.submitters.is_empty()
            })
    }

    /// Claims a group for a local call from the calling thread: the group homed in the thread's
    /// domain, or else the idle group unused longest, which is homed there first. A group a call
    /// may not be placed on is never homed. Returns `None` when the thread's domain is unknown or
    /// every other group has work in flight.
    pub(crate) fn local(self: &Arc<Self>) -> Option<Lease> {
        let domain = self.current_domain()?;
        let _homing = self.homing.lock();
        let tick = self.ticks.fetch_add(1, Ordering::Relaxed);

        // A group already homed here, busy or not.
        for (index, group) in self.groups.iter().enumerate() {
            let mut state = group.state.lock();
            if state.home == Some(domain) {
                state.used = tick;
                state.claim(tick);
                return Some(Lease {
                    groups: Arc::clone(self),
                    index,
                    submitter: std::thread::current().id(),
                });
            }
        }

        // Otherwise the idle group unused longest. An unhomed group has never been used, so it is
        // taken before any homed one. Its confinement is queued before its lock is released, so
        // work that finds the new home is queued after the confinement.
        let mut order: Vec<(u64, usize)> = self
            .groups
            .iter()
            .enumerate()
            .filter(|(_, group)| group.placeable())
            .filter_map(|(index, group)| {
                let state = group.state.lock();
                state.submitters.is_empty().then_some((state.used, index))
            })
            .collect();
        order.sort_unstable();
        for (_, index) in order {
            let group = &self.groups[index];
            let mut state = group.state.lock();
            if !state.submitters.is_empty() {
                continue;
            }
            state.home = Some(domain);
            state.used = tick;
            state.claim(tick);
            group.rehomes.fetch_add(1, Ordering::Relaxed);
            self.home(index, domain);
            return Some(Lease {
                groups: Arc::clone(self),
                index,
                submitter: std::thread::current().id(),
            });
        }
        None
    }

    /// Confines the workers of `group` to `domain`. Each worker applies the mask the next time it
    /// looks for work.
    #[allow(
        clippy::missing_const_for_fn,
        reason = "const only where no topology exists"
    )]
    fn home(&self, group: usize, domain: u16) {
        #[cfg(all(target_os = "linux", not(miri)))]
        if let Some(topology) = self.topology {
            let target: &'static Domain = &topology.domains[usize::from(domain)];
            self.pool
                .spawn_broadcast_in(group, move || confine_to(target));
            return;
        }
        let _ = (group, domain);
    }

    /// Claims every group for a call that may run on any of them, the group homed in the calling
    /// thread's domain first, which is offered the call's work first. A busy group contributes
    /// whatever idle moments its workers have and never holds the call back, since a call on the
    /// whole pool waits only for its own work, which any worker may take.
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
                }
            })
            .collect()
    }

    /// Claims the group with the least work in flight, and among those the one used least
    /// recently, for a job that gains nothing from its home group: such jobs keep away from the
    /// groups other callers are using. A group a call may not be placed on comes last, whatever
    /// its load.
    pub(crate) fn least_loaded(self: &Arc<Self>) -> Lease {
        let index = (0..self.groups.len())
            .min_by_key(|&index| {
                let group = &self.groups[index];
                let state = group.state.lock();
                (!group.placeable(), state.in_flight(), state.last_used)
            })
            .expect("a strategy has at least one group");
        let tick = self.ticks.fetch_add(1, Ordering::Relaxed);
        self.groups[index].state.lock().claim(tick);
        Lease {
            groups: Arc::clone(self),
            index,
            submitter: std::thread::current().id(),
        }
    }

    /// Claims a group for a job from the calling thread. The job shares data with its
    /// submitter, so it goes to the group homed in the submitter's domain, waiting behind the
    /// submitter's own work there. When that group is busy with another caller's work, waiting
    /// buys the job nothing, so it goes to the least loaded group instead. Without a home group
    /// the job homes an idle group, as a local call would.
    pub(crate) fn for_job(self: &Arc<Self>) -> Lease {
        if let Some(domain) = self.current_domain() {
            let home = self
                .groups
                .iter()
                .position(|group| group.state.lock().home == Some(domain));
            match home {
                Some(index) if self.groups[index].busy_with_others() => return self.least_loaded(),
                Some(_) | None => {
                    if let Some(lease) = self.local() {
                        return lease;
                    }
                }
            }
        }
        self.least_loaded()
    }

    /// One line per group: width, home, in-flight count, and times homed.
    #[cfg(any(feature = "test-utils", test))]
    pub(crate) fn describe(&self) -> String {
        self.groups
            .iter()
            .enumerate()
            .map(|(index, group)| {
                let state = group.state.lock();
                format!(
                    "group {index}: width {} home {:?} in_flight {} homed {} times",
                    group.width,
                    state.home,
                    state.in_flight(),
                    group.rehomes.load(Ordering::Relaxed),
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Groups of `widths` workers in one pool, homed among `domains` fake domains. Every width
    /// but the last must be the first.
    fn synthetic(widths: &[usize], domains: usize) -> Arc<Groups> {
        let pool = crate::ThreadPoolBuilder::new()
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
        // Without a topology there is one group; with one, no group is wider than a domain.
        if groups.domains == 0 {
            assert_eq!(widths, vec![5]);
        }
    }

    #[test]
    fn local_homes_an_idle_group_and_reuses_it() {
        let groups = synthetic(&[2, 2], 2);
        Groups::fake_domain(Some(1));
        let lease = groups.local().expect("an idle group is homed");
        assert_eq!(leased(&groups, &lease).state.lock().home, Some(1));
        assert_eq!(leased(&groups, &lease).state.lock().in_flight(), 1);
        let again = groups
            .local()
            .expect("the homed group is reused while busy");
        assert_eq!(again.index, lease.index);
        assert_eq!(leased(&groups, &lease).state.lock().in_flight(), 2);
        drop(again);
        drop(lease);
        assert_eq!(groups.groups()[0].state.lock().in_flight(), 0);
        Groups::fake_domain(None);
    }

    #[test]
    fn local_never_rehomes_a_busy_group() {
        let groups = synthetic(&[2, 2], 3);
        Groups::fake_domain(Some(0));
        let a = groups.local().unwrap();
        Groups::fake_domain(Some(1));
        let b = groups.local().unwrap();
        assert_ne!(a.index, b.index);
        // A third domain finds both groups busy and gets no local group.
        Groups::fake_domain(Some(2));
        assert!(groups.local().is_none());
        assert!(!groups.can_local());
        drop(a);
        // Once a group is idle, the third domain homes it, and the group homed in domain 1 stays.
        assert!(groups.can_local());
        let c = groups.local().unwrap();
        assert_eq!(leased(&groups, &c).state.lock().home, Some(2));
        assert_eq!(leased(&groups, &b).state.lock().home, Some(1));
        Groups::fake_domain(None);
    }

    /// A caller that needs a group takes the idle group unused longest, not the first idle one.
    #[test]
    fn local_takes_the_idle_group_unused_longest() {
        let groups = synthetic(&[2, 2], 3);
        Groups::fake_domain(Some(0));
        drop(groups.local().unwrap());
        Groups::fake_domain(Some(1));
        let homed_in_1 = groups.local().unwrap().index;
        assert_ne!(
            homed_in_1, 0,
            "an unhomed group is taken before a homed one"
        );

        // Domain 0 uses its group again, so the group homed in domain 1 is now idle longest.
        Groups::fake_domain(Some(0));
        drop(groups.local().unwrap());
        Groups::fake_domain(Some(2));
        let lease = groups.local().unwrap();
        assert_eq!(
            lease.index, homed_in_1,
            "the group unused longest is homed in the new domain"
        );
        assert_eq!(leased(&groups, &lease).state.lock().home, Some(2));
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
            "both callers share one group"
        );
        let homes = groups
            .groups()
            .iter()
            .filter(|group| group.state.lock().home == Some(0))
            .count();
        assert_eq!(homes, 1, "the domain has one home group");
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
            "the caller's home group comes first"
        );
        Groups::fake_domain(Some(1));
        let elsewhere = groups.wide();
        assert_eq!(
            elsewhere[0].index, 0,
            "without a home group the order is unchanged"
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

    /// A job stays in its submitter's home group behind the submitter's own work, and leaves it
    /// only while another thread's work occupies the group.
    #[test]
    fn jobs_stay_home_unless_another_caller_occupies_it() {
        let groups = synthetic(&[2, 2], 2);
        Groups::fake_domain(Some(0));
        let own = groups.local().unwrap();
        let home = own.index;
        let job = groups.for_job();
        assert_eq!(
            job.index, home,
            "the submitter's own work keeps the job home"
        );
        drop(job);

        // Another thread in the same domain finds the home group occupied by this thread's work,
        // so its job goes elsewhere; it then leaves a placed call of its own on the home group.
        let other = std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    Groups::fake_domain(Some(0));
                    let away = groups.for_job();
                    assert_ne!(away.index, home, "another caller's work sends the job away");
                    drop(away);
                    let lease = groups.local().unwrap();
                    assert_eq!(lease.index, home);
                    lease
                })
                .join()
                .unwrap()
        });
        let job = groups.for_job();
        assert_ne!(
            job.index, home,
            "the other thread's work now sends this job away"
        );
        drop(job);
        drop(other);
        let job = groups.for_job();
        assert_eq!(
            job.index, home,
            "the job returns home once the other work drains"
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
        let job = groups.for_job();
        assert_eq!(leased(&groups, &job).state.lock().home, Some(1));
        Groups::fake_domain(None);
        let busy_index = job.index;
        let other = groups.for_job();
        assert_ne!(
            other.index, busy_index,
            "an unknown domain takes the idle group"
        );
        drop(other);
        drop(job);
    }

    /// A group narrower than the first, or of one worker, is never homed or leased for a placed
    /// call, while a call on the whole pool still leases it.
    #[test]
    fn a_narrower_group_takes_only_wide_calls() {
        for widths in [&[2, 1][..], &[3, 2][..]] {
            let groups = synthetic(widths, 2);
            Groups::fake_domain(Some(0));
            let held = groups.local().expect("the full group is homed");
            assert_eq!(held.group(), 0);
            // With the full group busy, another domain gets no local group rather than the
            // narrower one, and a job or a sort stays on the group a call may be placed on.
            Groups::fake_domain(Some(1));
            assert!(!groups.can_local());
            assert!(groups.local().is_none());
            assert_eq!(groups.least_loaded().group(), 0);
            assert_eq!(groups.for_job().group(), 0);
            assert_eq!(groups.wide().len(), 2);
            drop(held);
            assert_eq!(
                groups
                    .local()
                    .expect("the idle full group is homed")
                    .group(),
                0
            );
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
            // A group leaves one of its domain's CPUs free on a domain wide enough for it.
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
            assert_eq!(
                Groups::grouped_parallelism_in(topology, 2 * width + 1),
                2 * width,
                "a budget is sized down to full groups"
            );
            assert_eq!(
                Groups::grouped_parallelism_in(topology, width - 1),
                width - 1
            );
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
        /// one on a domain wide enough to spare it, and a thread allowed fewer than two CPUs in
        /// every domain gets one unhomed group.
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

        #[test]
        fn homing_confines_workers_to_the_domain() {
            let Some((topology, a, b)) = split_topology() else {
                return;
            };

            // One group, so the second homing moves the workers the first one confined.
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
                    "worker mask {mask:?} not within {b:?}"
                );
            }
            drop(lease);
            Groups::fake_domain(Some(domain_a));
            let lease = groups.local().unwrap();
            let masks: Vec<Vec<usize>> = groups.pool().broadcast_in(lease.group(), allowed_cpus);
            for mask in &masks {
                assert!(
                    mask.iter().all(|cpu| a.contains(cpu)),
                    "worker mask {mask:?} not within {a:?}"
                );
            }
            Groups::fake_domain(None);
        }
    }
}
