//! Last-level-cache topology and worker affinity for spawned jobs.
//!
//! Exchanging cache lines costs far more between threads in different last-level cache (LLC)
//! domains, and the scheduler places threads without knowing which of them share data. A spawned
//! job usually shares data with its submitter, so [`AffinityGuard`] pins the pool worker that runs
//! it into the submitter's domain. A worker already running there needs no affinity queries or
//! writes. Otherwise, the pin moves the worker there by narrowing its affinity mask to the domain's
//! CPUs that the mask already allows, then restores the starting mask at once.
//!
//! The thread stays where it lands unless the scheduler balances it away, so a job keeps its
//! locality while the domain has room, and the scheduler can still move it out of a crowded
//! domain. A thread that served a domain tends to stay there, so later jobs from that domain
//! usually need no move.
//!
//! Domains come from the kernel's sysfs cache topology, where each CPU's last-level cache is its
//! highest-level Data or Unified cache leaf. Machines whose possible-CPU count exceeds
//! `cpu_set_t`'s capacity report no domains. On non-Linux platforms and under miri, the stub below
//! reports no domains and pinning is a no-op.
//!
//! Pinning is best effort, and [`AffinityGuard::pin`] documents when it skips the move. Each pin
//! that moves a worker holds one of its domain's slots for the job's duration. A domain grants at
//! most one slot fewer than the CPUs a pinning thread may use there, so moved jobs alone never
//! fill it.
//!
//! The kernel reports only active CPUs in a thread's mask, and from Linux 6.2 it keeps a mask a
//! thread writes as that thread's own request. A worker that has moved or confined itself therefore
//! stops following later growth of its cpuset or a CPU coming back online.

cfg_if::cfg_if! {
    if #[cfg(all(target_os = "linux", not(miri)))] {
        use std::sync::{
            OnceLock,
            atomic::{AtomicUsize, Ordering},
        };

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

            /// Whether every CPU in `self` is also in `other`.
            fn is_subset_of(&self, other: &Self) -> bool {
                (0..CPU_SETSIZE).all(|cpu| !self.contains(cpu) || other.contains(cpu))
            }

            /// The CPUs of `self` that `allowed` also contains, and how many there are.
            fn within(&self, allowed: &Self) -> (Self, usize) {
                let mut both = Self::empty();
                let mut count = 0usize;
                for cpu in 0..CPU_SETSIZE {
                    if self.contains(cpu) && allowed.contains(cpu) {
                        both.set(cpu);
                        count += 1;
                    }
                }
                (both, count)
            }

            /// Whether the sets hold exactly the same CPUs.
            #[cfg(test)]
            fn equals(&self, other: &Self) -> bool {
                // SAFETY: both sets are valid, and CPU_EQUAL only compares their bits.
                unsafe { libc::CPU_EQUAL(&self.0, &other.0) }
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
        fn topology() -> &'static Topology {
            static TOPOLOGY: OnceLock<Topology> = OnceLock::new();
            TOPOLOGY.get_or_init(Topology::detect)
        }

        /// The host's last-level cache domains, with the live pins of each.
        struct Topology {
            /// Domain of each CPU, or `None` for a CPU whose cache topology was unreadable at
            /// detection time. Jobs submitted from such a CPU, or from one past the end of the
            /// table, run unpinned because a guessed domain could move them away from the
            /// submitter's cache.
            cpu_to_domain: Box<[Option<u16>]>,
            /// The CPUs of each domain, as ready-to-use affinity sets.
            domain_sets: Box<[CpuSet]>,
            /// Number of workers moved into each domain. Each holds one slot until its guard drops.
            pins: Box<[AtomicUsize]>,
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

            /// An empty topology that disables pinning.
            fn empty() -> Self {
                Self {
                    cpu_to_domain: Box::new([]),
                    domain_sets: Box::new([]),
                    pins: Box::new([]),
                }
            }

            /// Number of distinct domains. Pinning needs at least two.
            fn domains(&self) -> usize {
                self.domain_sets.len()
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

                let mut sets: Vec<CpuSet> = Vec::new();
                let mut widths: Vec<usize> = Vec::new();
                for (cpu, list) in lists {
                    let list = list.as_str();
                    let domain = domains.iter().position(|&d| d == list).unwrap_or_else(|| {
                        domains.push(list);
                        sets.push(CpuSet::empty());
                        widths.push(0);
                        domains.len() - 1
                    });
                    table[*cpu] = Some(u16::try_from(domain).ok()?);
                    sets[domain].set(*cpu);
                    widths[domain] += 1;
                }

                // One domain leaves nowhere to move work. A pin also needs two CPUs in the target
                // domain, one for the submitter and one for the job. A host whose every cache is
                // private to one CPU therefore has no domain to pin a job in.
                if domains.len() <= 1 || widths.iter().all(|&width| width < 2) {
                    return None;
                }
                let pins = (0..sets.len()).map(|_| AtomicUsize::new(0)).collect();
                Some(Self {
                    cpu_to_domain: table.into_boxed_slice(),
                    domain_sets: sets.into_boxed_slice(),
                    pins,
                })
            }
        }

        /// The submitting thread's current LLC domain, captured at spawn time and consumed by
        /// [`AffinityGuard::pin`] on whichever thread executes the job.
        #[derive(Clone, Copy)]
        pub(crate) struct SpawnDomain(u16);

        /// Captures the calling thread's current domain, or returns `None` when the topology has
        /// fewer than two domains or the thread's domain is unknown. A `None` domain disables
        /// pinning.
        pub(crate) fn spawn_domain() -> Option<SpawnDomain> {
            let topology = topology();
            if topology.domains() <= 1 {
                return None;
            }
            topology.current_domain().map(SpawnDomain)
        }

        std::thread_local! {
            /// Whether this thread holds a live [`AffinityGuard`]. A pinned worker runs nested jobs
            /// under its existing guard and must not pin again, even when that guard made no move.
            /// The thread occupies one CPU however deep its jobs nest.
            static PINNED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
        }

        /// Prevents nested pins and holds a domain's slot when [`Self::pin`] moves the thread.
        pub(crate) struct AffinityGuard {
            /// The pre-pin mask and the pin mask, kept only when widening failed at pin time so
            /// drop can retry it.
            pending: Option<(CpuSet, CpuSet)>,
            /// The domain's slot counter, present only when this guard moved the thread.
            slot: Option<&'static AtomicUsize>,
            /// The guard acts on the mask and pinned flag of the thread that created it, so it
            /// must not move to another thread.
            thread_bound: std::marker::PhantomData<*const ()>,
        }

        impl AffinityGuard {
            /// Moves the calling thread onto the CPUs of `domain` that its current affinity mask
            /// allows, then widens the mask back at once. The move stays within the mask the thread
            /// has when the pin starts, so it keeps operator restrictions such as taskset, numactl,
            /// or isolated cores.
            ///
            /// The widening writes that starting mask back over any mask written since the
            /// narrowing. When the widening fails, drop retries it only while the thread's mask is
            /// still within the pin. A mask written after a successful widening is left alone.
            ///
            /// A thread already running in the domain stays where it is. Its guard neither queries
            /// nor writes the mask and holds no slot, because the slot cap bounds only moved
            /// workers. The guard still prevents nested pins.
            ///
            /// Returns `None` without pinning when `domain` is `None`, the thread already holds a
            /// guard, or a move cannot proceed: the mask cannot be read or applied, fewer than two
            /// of the domain's CPUs are allowed, or the domain's moved workers already number one
            /// fewer than the CPUs this thread may use there. The thread then keeps its existing
            /// mask.
            pub(crate) fn pin(domain: Option<SpawnDomain>) -> Option<Self> {
                Self::pin_in(topology(), usize::from(domain?.0))
            }

            /// [`Self::pin`] against an explicit topology.
            fn pin_in(topology: &'static Topology, domain: usize) -> Option<Self> {
                Self::pin_from(topology, domain, topology.current_domain())
            }

            /// Pins using an explicit observation of the calling thread's current domain.
            fn pin_from(
                topology: &'static Topology,
                domain: usize,
                here: Option<u16>,
            ) -> Option<Self> {
                if PINNED.get() {
                    return None;
                }
                let target = topology.domain_sets.get(domain)?;
                if here.map(usize::from) == Some(domain) {
                    PINNED.set(true);
                    return Some(Self {
                        pending: None,
                        slot: None,
                        thread_bound: std::marker::PhantomData,
                    });
                }
                let saved = thread_affinity()?;

                // Keep only the domain's CPUs that the thread's current mask allows.
                let (effective, allowed) = target.within(&saved);

                // Fewer than two allowed CPUs would leave no room for both the submitter and this
                // job.
                if allowed <= 1 {
                    return None;
                }

                // Take a pin slot, allowing at most `allowed - 1` moved workers so they alone
                // cannot fill the domain and crowd out the submitting caller. The cap counts the
                // CPUs this thread may use there, since operator restrictions can leave fewer than
                // the domain's sysfs width.
                let cap = allowed - 1;
                let pins = &topology.pins[domain];
                let mut live = pins.load(Ordering::Acquire);
                loop {
                    if live >= cap {
                        return None;
                    }
                    match pins.compare_exchange_weak(
                        live,
                        live + 1,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    ) {
                        Ok(_) => break,
                        Err(current) => live = current,
                    }
                }
                if !set_thread_affinity(&effective) {
                    // A failed narrowing leaves the thread where it was, so hand the slot back.
                    pins.fetch_sub(1, Ordering::AcqRel);
                    return None;
                }

                // Applying the narrowed mask moved the thread into the domain. Widening the mask
                // again leaves the thread where it is, so the job stays in the domain and the
                // scheduler can still balance the thread away later. A failed widening is retried
                // at drop.
                let pending = (!set_thread_affinity(&saved)).then_some((saved, effective));
                PINNED.set(true);
                Some(Self {
                    pending,
                    slot: Some(pins),
                    thread_bound: std::marker::PhantomData,
                })
            }
        }

        impl Drop for AffinityGuard {
            /// Clears the pinned flag, releases any held slot, and retries a failed widening,
            /// including during an unwind.
            fn drop(&mut self) {
                // Retry a widening that failed at pin time, but only while the thread's mask is
                // still within the pin. The kernel reports only active CPUs, so a pinned CPU that
                // went offline leaves the reported mask a subset of the pin. A mask outside the pin
                // was rewritten mid-job by an operator or the kernel. Restoring the pre-pin mask
                // would revive CPUs they removed, so the newer mask stays.
                if let Some((saved, effective)) = self.pending
                    && thread_affinity().is_some_and(|current| current.is_subset_of(&effective))
                {
                    set_thread_affinity(&saved);
                }

                // Clear the flag and release the slot whatever became of the widening, so a guard
                // never strands a slot for the life of the process.
                PINNED.set(false);
                if let Some(slot) = self.slot {
                    slot.fetch_sub(1, Ordering::AcqRel);
                }
            }
        }

        #[cfg(test)]
        mod tests {
            use super::*;
            use std::sync::atomic::AtomicBool;

            /// The calling thread's current affinity mask.
            fn current_mask() -> CpuSet {
                thread_affinity().expect("affinity mask must be readable")
            }

            /// The CPUs the calling thread may currently use.
            fn allowed_cpus() -> Vec<usize> {
                let mask = current_mask();
                (0..CPU_SETSIZE)
                    .filter(|&cpu| mask.contains(cpu))
                    .collect()
            }

            /// A leaked two-domain topology that splits at most eight of the calling thread's
            /// allowed CPUs in half, plus the CPUs of each half. Returns `None` with fewer than
            /// four allowed CPUs, since each half needs two for a pin to engage. Private pin
            /// counters let tests assert exact values without racing other tests.
            fn synthetic_split() -> Option<(&'static Topology, Vec<usize>, Vec<usize>)> {
                let mut cpus = allowed_cpus();
                if cpus.len() < 4 {
                    return None;
                }

                // Bound each domain to at most four CPUs so tests that spawn threads in proportion
                // to domain width stay small on wide machines.
                cpus.truncate(8);
                let (a, b) = cpus.split_at(cpus.len() / 2);
                let lists: Vec<(usize, String)> = a
                    .iter()
                    .map(|&cpu| (cpu, "a".to_string()))
                    .chain(b.iter().map(|&cpu| (cpu, "b".to_string())))
                    .collect();
                let topology = Box::leak(Box::new(Topology::from_lists(&lists)?));
                Some((topology, a.to_vec(), b.to_vec()))
            }

            /// The index of `cpu`'s domain, which `topology` must cover.
            fn domain_index(topology: &Topology, cpu: usize) -> usize {
                usize::from(topology.domain_of(cpu).expect("the topology must cover the cpu"))
            }

            #[test]
            fn from_lists_groups_and_masks() {
                // Each distinct sharing list becomes one domain, and a domain's set holds its own
                // CPUs but not the other domain's.
                let lists: Vec<(usize, String)> = (0..8)
                    .map(|cpu| {
                        let list = if cpu < 4 { "0-3" } else { "4-7" };
                        (cpu, list.to_string())
                    })
                    .collect();
                let topology = Topology::from_lists(&lists).unwrap();
                assert_eq!(topology.domains(), 2);
                assert_ne!(topology.domain_of(0), topology.domain_of(4));
                let d0 = domain_index(&topology, 0);
                for cpu in 0..4 {
                    assert!(topology.domain_sets[d0].contains(cpu));
                }
                assert!(!topology.domain_sets[d0].contains(4));
            }

            #[test]
            fn unknown_cpus_have_no_domain() {
                // CPU 5 is missing from the snapshot, and CPUs beyond the table are unknown too.
                let lists: Vec<(usize, String)> = [0, 1, 2, 3, 4, 6, 7]
                    .into_iter()
                    .map(|cpu| {
                        let list = if cpu < 4 { "0-3" } else { "4-7" };
                        (cpu, list.to_string())
                    })
                    .collect();
                let topology = Topology::from_lists(&lists).unwrap();
                assert_eq!(topology.domain_of(5), None);
                assert_eq!(topology.domain_of(64), None);
                assert!(topology.domain_of(6).is_some());
            }

            #[test]
            fn llc_discovery_reads_a_real_cpu() {
                // Discovery on the real cpu0 must not panic, and any sharing list it finds must be
                // non-empty.
                let dir = std::path::Path::new("/sys/devices/system/cpu/cpu0");
                if !dir.exists() {
                    return;
                }
                if let Some(list) = Topology::llc_list(dir) {
                    assert!(!list.is_empty());
                }
            }

            #[test]
            fn from_lists_single_domain_is_none() {
                // A single domain leaves nowhere to move a job, so no topology is reported.
                let lists: Vec<(usize, String)> =
                    (0..4).map(|cpu| (cpu, "0-3".to_string())).collect();
                assert!(Topology::from_lists(&lists).is_none());
            }

            #[test]
            fn from_lists_private_caches_are_none() {
                // A cache private to each CPU gives every domain one CPU, so no pin or pool can
                // use it and no topology is reported.
                let lists: Vec<(usize, String)> =
                    (0..4).map(|cpu| (cpu, cpu.to_string())).collect();
                assert!(Topology::from_lists(&lists).is_none());

                // One shared cache beside private ones still has a domain to place work in.
                let mut lists = lists;
                lists[1].1 = "0".to_string();
                assert_eq!(Topology::from_lists(&lists).unwrap().domains(), 3);
            }

            #[test]
            fn from_lists_smt_discontiguous_domains() {
                // SMT siblings share the LLC, and their numbering can make sharing lists
                // discontiguous. Here physical cores 0-3 pair with logical CPUs 64-67.
                let mut lists: Vec<(usize, String)> = Vec::new();
                for cpu in (0..4).chain(64..68) {
                    lists.push((cpu, "0-3,64-67".to_string()));
                }
                for cpu in (4..8).chain(68..72) {
                    lists.push((cpu, "4-7,68-71".to_string()));
                }
                let topology = Topology::from_lists(&lists).unwrap();
                assert_eq!(topology.domains(), 2);
                assert_eq!(topology.domain_of(0), topology.domain_of(64));
                assert_eq!(topology.domain_of(4), topology.domain_of(68));
                assert_ne!(topology.domain_of(0), topology.domain_of(4));
                let d0 = domain_index(&topology, 0);
                assert!(topology.domain_sets[d0].contains(64));
            }

            #[test]
            fn from_lists_rejects_cpus_past_setsize() {
                // cpu_set_t cannot represent such CPUs, so a topology containing one must be
                // rejected whole.
                let lists = vec![
                    (0, "a".to_string()),
                    (CPU_SETSIZE, "b".to_string()),
                ];
                assert!(Topology::from_lists(&lists).is_none());
            }

            #[test]
            fn llc_list_picks_highest_level_data_or_unified_leaf() {
                // In this synthetic sysfs cache directory the LLC is the level-3 Unified leaf.
                // Discovery must pick it over the level-1 Data leaf, the Instruction leaf, and the
                // level-2 Unified leaf, and must skip the level-4 leaf whose sharing list is
                // empty.
                let dir =
                    std::env::temp_dir().join(format!("commonware_llc_{}", std::process::id()));
                let cache = dir.join("cache");
                let leaves = [
                    ("index0", "Data", "1", "0"),
                    ("index1", "Instruction", "1", "0"),
                    ("index2", "Unified", "2", "0-1"),
                    ("index3", "Unified", "3", "0-7,64-71"),
                    ("index4", "Unified", "4", "\n"),
                ];
                for (leaf, kind, level, list) in leaves {
                    let path = cache.join(leaf);
                    std::fs::create_dir_all(&path).unwrap();
                    std::fs::write(path.join("type"), kind).unwrap();
                    std::fs::write(path.join("level"), level).unwrap();
                    std::fs::write(path.join("shared_cpu_list"), list).unwrap();
                }
                assert_eq!(Topology::llc_list(&dir).as_deref(), Some("0-7,64-71"));
                std::fs::remove_dir_all(&dir).unwrap();
            }

            #[test]
            fn llc_list_ignores_instruction_only_caches() {
                // A cache directory whose only leaf is an Instruction cache has no LLC to report.
                let dir =
                    std::env::temp_dir().join(format!("commonware_llc_i_{}", std::process::id()));
                let path = dir.join("cache").join("index0");
                std::fs::create_dir_all(&path).unwrap();
                std::fs::write(path.join("type"), "Instruction").unwrap();
                std::fs::write(path.join("level"), "1").unwrap();
                std::fs::write(path.join("shared_cpu_list"), "0").unwrap();
                assert_eq!(Topology::llc_list(&dir), None);
                std::fs::remove_dir_all(&dir).unwrap();
            }

            #[test]
            fn pin_never_widens_a_restricted_mask() {
                std::thread::spawn(|| {
                    // Restrict this thread to its current CPU. CpuSet::set panics at or past
                    // CPU_SETSIZE, and such a CPU id also means the machine has no topology to pin
                    // within, so the test has nothing to check there.
                    let cpu = current_cpu().unwrap();
                    if cpu >= CPU_SETSIZE {
                        return;
                    }
                    let mut only = CpuSet::empty();
                    only.set(cpu);
                    assert!(set_thread_affinity(&only));

                    // A one-CPU mask leaves no room for a move, so any guard must be a resident one
                    // that holds no slot.
                    let guard = AffinityGuard::pin(spawn_domain());
                    assert!(guard.as_ref().is_none_or(|guard| guard.slot.is_none()));
                    drop(guard);

                    // The mask must stay within the restriction.
                    assert!(current_mask().is_subset_of(&only));
                })
                .join()
                .unwrap();
            }

            #[test]
            fn synthetic_resident_pin_holds_no_slot() {
                std::thread::spawn(|| {
                    let Some((topology, half_a, half_b)) = synthetic_split() else {
                        return;
                    };
                    let here = topology.domain_of(half_a[0]).unwrap();
                    let domain = usize::from(here);
                    let other = domain_index(topology, half_b[0]);
                    allow_only(&half_a);
                    let before = current_mask();
                    for unwind in [false, true] {
                        let result = std::panic::catch_unwind(|| {
                            let guard =
                                AffinityGuard::pin_from(topology, domain, Some(here))
                                    .expect("a resident thread must get a guard");
                            assert!(guard.slot.is_none());
                            assert!(guard.pending.is_none());
                            assert!(PINNED.get());
                            assert_eq!(topology.pins[domain].load(Ordering::Acquire), 0);
                            assert!(before.equals(&current_mask()));
                            assert!(
                                AffinityGuard::pin_from(topology, domain, Some(here))
                                    .is_none()
                            );
                            assert!(AffinityGuard::pin_from(topology, other, None).is_none());
                            if unwind {
                                panic!("unwind the resident guard");
                            }
                        });
                        assert_eq!(result.is_err(), unwind);
                        assert!(!PINNED.get());
                        assert_eq!(topology.pins[domain].load(Ordering::Acquire), 0);
                        assert!(before.equals(&current_mask()));
                    }
                })
                .join()
                .unwrap();
            }

            #[test]
            fn synthetic_pin_takes_a_slot_and_widens() {
                std::thread::spawn(|| {
                    let Some((topology, half_a, _)) = synthetic_split() else {
                        return;
                    };
                    let domain = domain_index(topology, half_a[0]);
                    let before = current_mask();
                    {
                        let _guard = AffinityGuard::pin_from(topology, domain, None).unwrap();

                        // The pin took one slot and has already restored the original mask. Where
                        // the thread runs afterwards is the scheduler's choice, so only the mask
                        // and the slot are asserted.
                        assert_eq!(topology.pins[domain].load(Ordering::Acquire), 1);
                        assert!(before.equals(&current_mask()));
                    }

                    // Dropping the guard releases the slot and leaves the mask as it was.
                    assert_eq!(topology.pins[domain].load(Ordering::Acquire), 0);
                    assert!(before.equals(&current_mask()));
                })
                .join()
                .unwrap();
            }

            #[test]
            fn synthetic_pin_in_observes_where_the_thread_runs() {
                std::thread::spawn(|| {
                    let Some((topology, half_a, half_b)) = synthetic_split() else {
                        return;
                    };
                    let domain = domain_index(topology, half_a[0]);
                    let other = domain_index(topology, half_b[0]);

                    // Confined to one half, the thread runs there, so a pin into that half is
                    // resident and a pin into the other half is a move it has no CPUs for.
                    allow_only(&half_a);
                    let before = current_mask();
                    let guard = AffinityGuard::pin_in(topology, domain)
                        .expect("a thread confined to the domain must be resident");
                    assert!(guard.slot.is_none());
                    assert!(before.equals(&current_mask()));
                    drop(guard);
                    assert!(AffinityGuard::pin_in(topology, other).is_none());
                    assert_eq!(topology.pins[other].load(Ordering::Acquire), 0);
                    assert!(!PINNED.get());
                })
                .join()
                .unwrap();
            }

            #[test]
            fn synthetic_pin_whose_narrowing_fails_returns_its_slot() {
                std::thread::spawn(|| {
                    let Some((topology, half_a, _)) = synthetic_split() else {
                        return;
                    };
                    let domain = domain_index(topology, half_a[0]);
                    let before = current_mask();

                    // A seccomp filter makes every affinity write from this thread fail with
                    // EPERM. The filter and the no-new-privileges flag apply only to this thread
                    // and threads it spawns later, and it spawns none. The test skips itself
                    // where the kernel or the sandbox refuses the filter.
                    let mut filter = [
                        libc::sock_filter {
                            code: (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16,
                            jt: 0,
                            jf: 0,
                            k: 0,
                        },
                        libc::sock_filter {
                            code: (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
                            jt: 0,
                            jf: 1,
                            k: libc::SYS_sched_setaffinity as u32,
                        },
                        libc::sock_filter {
                            code: (libc::BPF_RET | libc::BPF_K) as u16,
                            jt: 0,
                            jf: 0,
                            k: libc::SECCOMP_RET_ERRNO | libc::EPERM as u32,
                        },
                        libc::sock_filter {
                            code: (libc::BPF_RET | libc::BPF_K) as u16,
                            jt: 0,
                            jf: 0,
                            k: libc::SECCOMP_RET_ALLOW,
                        },
                    ];
                    let program = libc::sock_fprog {
                        len: filter.len() as u16,
                        filter: filter.as_mut_ptr(),
                    };

                    // SAFETY: the program points at a live filter array of the stated length for
                    // the duration of the call, and the other arguments are plain integers.
                    let installed = unsafe {
                        libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0
                            && libc::prctl(
                                libc::PR_SET_SECCOMP,
                                libc::SECCOMP_MODE_FILTER,
                                &raw const program,
                            ) == 0
                    };
                    if !installed {
                        return;
                    }

                    // The pin reserves a slot before it narrows the mask, so a failed narrowing
                    // must hand the slot back and leave the thread unpinned with its mask intact.
                    assert!(AffinityGuard::pin_from(topology, domain, None).is_none());
                    assert_eq!(topology.pins[domain].load(Ordering::Acquire), 0);
                    assert!(!PINNED.get());
                    assert!(before.equals(&current_mask()));

                    // A resident guard succeeds even when every affinity write is refused.
                    let here = Some(u16::try_from(domain).unwrap());
                    let guard = AffinityGuard::pin_from(topology, domain, here)
                        .expect("a resident guard must not write affinity");
                    assert!(guard.slot.is_none());
                    drop(guard);
                    assert!(!PINNED.get());
                    assert_eq!(topology.pins[domain].load(Ordering::Acquire), 0);
                })
                .join()
                .unwrap();
            }

            #[test]
            fn synthetic_pin_slots_do_not_leak() {
                // Repeated pin and release must not leak slots, or pins would start failing once
                // leaked slots reach the cap.
                std::thread::spawn(|| {
                    let Some((topology, half_a, _)) = synthetic_split() else {
                        return;
                    };
                    let domain = domain_index(topology, half_a[0]);
                    for _ in 0..100 {
                        let guard = AffinityGuard::pin_from(topology, domain, None).unwrap();
                        assert_eq!(topology.pins[domain].load(Ordering::Acquire), 1);
                        drop(guard);
                        assert!(!PINNED.get());
                    }
                    assert_eq!(topology.pins[domain].load(Ordering::Acquire), 0);
                })
                .join()
                .unwrap();
            }

            #[test]
            fn synthetic_nested_pin_refused_then_released() {
                std::thread::spawn(|| {
                    let Some((topology, half_a, half_b)) = synthetic_split() else {
                        return;
                    };
                    let domain = domain_index(topology, half_a[0]);
                    let other = domain_index(topology, half_b[0]);
                    let outer = AffinityGuard::pin_from(topology, domain, None).unwrap();

                    // A pinned thread must not pin again in any domain, so nested jobs stay within
                    // the outer pin.
                    assert!(AffinityGuard::pin_from(topology, domain, None).is_none());
                    assert!(AffinityGuard::pin_from(topology, other, None).is_none());

                    // Dropping the outer guard clears the thread's pinned flag and releases the
                    // slot, so the thread can pin again.
                    drop(outer);
                    assert_eq!(topology.pins[domain].load(Ordering::Acquire), 0);
                    assert!(AffinityGuard::pin_from(topology, domain, None).is_some());
                })
                .join()
                .unwrap();
            }

            #[test]
            fn synthetic_mask_rewritten_outside_the_pin_is_kept() {
                std::thread::spawn(|| {
                    let Some((topology, half_a, half_b)) = synthetic_split() else {
                        return;
                    };
                    let domain = domain_index(topology, half_a[0]);
                    let guard = AffinityGuard::pin_from(topology, domain, None).unwrap();

                    // An operator moves the thread outside the domain while the job runs.
                    let mut elsewhere = CpuSet::empty();
                    for &cpu in &half_b {
                        elsewhere.set(cpu);
                    }
                    assert!(set_thread_affinity(&elsewhere));

                    // Dropping the guard releases the slot but leaves the newer placement alone.
                    drop(guard);
                    assert!(current_mask().equals(&elsewhere));
                    assert_eq!(topology.pins[domain].load(Ordering::Acquire), 0);
                })
                .join()
                .unwrap();
            }

            /// A guard whose widening at pin time failed, built directly with its slot taken and
            /// the thread narrowed to `effective`, as `pin_in` leaves it in that case.
            fn guard_with_pending_widening(
                topology: &'static Topology,
                domain: usize,
                saved: CpuSet,
                effective: CpuSet,
            ) -> AffinityGuard {
                assert!(set_thread_affinity(&effective));
                topology.pins[domain].fetch_add(1, Ordering::AcqRel);
                PINNED.set(true);
                AffinityGuard {
                    pending: Some((saved, effective)),
                    slot: Some(&topology.pins[domain]),
                    thread_bound: std::marker::PhantomData,
                }
            }

            #[test]
            fn synthetic_pending_widening_is_retried_at_drop() {
                std::thread::spawn(|| {
                    let Some((topology, half_a, _)) = synthetic_split() else {
                        return;
                    };
                    let domain = domain_index(topology, half_a[0]);
                    let saved = current_mask();
                    let guard = guard_with_pending_widening(
                        topology,
                        domain,
                        saved,
                        topology.domain_sets[domain],
                    );

                    // The thread is still narrowed, so drop widens it, releases the slot, and
                    // clears the pinned flag.
                    drop(guard);
                    assert!(current_mask().equals(&saved));
                    assert_eq!(topology.pins[domain].load(Ordering::Acquire), 0);
                    assert!(!PINNED.get());
                })
                .join()
                .unwrap();
            }

            #[test]
            fn synthetic_pending_widening_keeps_an_outside_rewrite() {
                std::thread::spawn(|| {
                    let Some((topology, half_a, half_b)) = synthetic_split() else {
                        return;
                    };
                    let domain = domain_index(topology, half_a[0]);
                    let saved = current_mask();
                    let guard = guard_with_pending_widening(
                        topology,
                        domain,
                        saved,
                        topology.domain_sets[domain],
                    );

                    // An operator moves the thread outside the pin before the retry, so drop
                    // leaves that newer placement alone and still releases the slot.
                    let mut elsewhere = CpuSet::empty();
                    for &cpu in &half_b {
                        elsewhere.set(cpu);
                    }
                    assert!(set_thread_affinity(&elsewhere));
                    drop(guard);
                    assert!(current_mask().equals(&elsewhere));
                    assert_eq!(topology.pins[domain].load(Ordering::Acquire), 0);
                })
                .join()
                .unwrap();
            }

            #[test]
            fn synthetic_cap_bounds_pins_and_returns_to_zero() {
                let Some((topology, half_a, _)) = synthetic_split() else {
                    return;
                };
                let domain = domain_index(topology, half_a[0]);

                // Scoped threads inherit this thread's mask. It allows every CPU in the domain, so
                // each thread computes the same cap of the domain's width minus one.
                let cap = half_a.len() - 1;

                // Workers make no assertions and spin on `released`. A drop guard sets it even when
                // an assertion below panics, so a failing assertion fails the test and cannot
                // deadlock the scope's implicit join.
                let granted = AtomicUsize::new(0);
                let settled = AtomicUsize::new(0);
                let released = AtomicBool::new(false);
                struct ReleaseOnDrop<'a>(&'a AtomicBool);
                impl Drop for ReleaseOnDrop<'_> {
                    fn drop(&mut self) {
                        self.0.store(true, Ordering::Release);
                    }
                }
                std::thread::scope(|s| {
                    let _release = ReleaseOnDrop(&released);

                    // Fill the domain. One worker per slot pins and holds its guard until
                    // released.
                    for _ in 0..cap {
                        s.spawn(|| {
                            let guard = AffinityGuard::pin_from(topology, domain, None);
                            if guard.is_some() {
                                granted.fetch_add(1, Ordering::AcqRel);
                            }
                            settled.fetch_add(1, Ordering::AcqRel);
                            while !released.load(Ordering::Acquire) {
                                std::thread::yield_now();
                            }
                        });
                    }
                    while settled.load(Ordering::Acquire) < cap {
                        std::thread::yield_now();
                    }

                    // Every slot is taken. Each pin under the cap succeeded, the counter sits at
                    // the cap, and a further pin is refused.
                    assert_eq!(granted.load(Ordering::Acquire), cap);
                    assert_eq!(topology.pins[domain].load(Ordering::Acquire), cap);
                    assert!(AffinityGuard::pin_from(topology, domain, None).is_none());
                    let here = Some(u16::try_from(domain).unwrap());
                    let resident = AffinityGuard::pin_from(topology, domain, here)
                        .expect("a resident guard must not need a slot");
                    assert!(resident.slot.is_none());
                    drop(resident);
                    assert_eq!(topology.pins[domain].load(Ordering::Acquire), cap);
                });

                // With every guard dropped, the counter returns exactly to zero and pins engage
                // again.
                assert_eq!(topology.pins[domain].load(Ordering::Acquire), 0);
                std::thread::spawn(move || {
                    assert!(AffinityGuard::pin_from(topology, domain, None).is_some());
                })
                .join()
                .unwrap();
            }

            #[test]
            fn synthetic_pin_stress_never_exceeds_cap() {
                let Some((topology, half_a, _)) = synthetic_split() else {
                    return;
                };
                let domain = domain_index(topology, half_a[0]);
                let cap = half_a.len() - 1;

                // Four threads per domain CPU pin and release concurrently. The live count must
                // stay within the cap and end at zero.
                std::thread::scope(|s| {
                    for _ in 0..(4 * half_a.len()) {
                        s.spawn(|| {
                            for _ in 0..200 {
                                let guard = AffinityGuard::pin_from(topology, domain, None);

                                // An underflowed counter would wrap far past the cap.
                                assert!(topology.pins[domain].load(Ordering::Acquire) <= cap);
                                drop(guard);
                            }
                        });
                    }
                });
                assert_eq!(topology.pins[domain].load(Ordering::Acquire), 0);
            }

            #[test]
            fn nested_pin_is_refused() {
                // Concurrently running tests can share the process-wide topology and contend for
                // its pin slots, so this test asserts only a refusal. The synthetic-topology tests
                // cover successful pins.
                std::thread::spawn(|| {
                    let Some(domain) = spawn_domain() else {
                        return;
                    };
                    let Some(_outer) = AffinityGuard::pin(Some(domain)) else {
                        return;
                    };

                    // A nested pin must not take a second slot.
                    assert!(AffinityGuard::pin(Some(domain)).is_none());
                })
                .join()
                .unwrap();
            }

            #[test]
            fn pin_leaves_the_mask_unchanged() {
                // Pin to the current domain (a no-op move) and verify the mask is as it was.
                let before = current_mask();
                {
                    let _guard = AffinityGuard::pin(spawn_domain());
                }
                let after = current_mask();
                assert!(before.equals(&after));
            }

            /// Allows the calling thread exactly `cpus`.
            fn allow_only(cpus: &[usize]) {
                let mut set = CpuSet::empty();
                for &cpu in cpus {
                    set.set(cpu);
                }
                assert!(set_thread_affinity(&set));
            }
        }
    } else {
        /// Stub domain for platforms without affinity control. It is never constructed.
        #[derive(Clone, Copy)]
        pub(crate) struct SpawnDomain;

        /// Always `None`, since there is no topology to pin within.
        pub(crate) const fn spawn_domain() -> Option<SpawnDomain> {
            None
        }

        /// No-op guard on platforms without affinity control.
        pub(crate) struct AffinityGuard;

        impl AffinityGuard {
            /// Never pins.
            pub(crate) const fn pin(_domain: Option<SpawnDomain>) -> Option<Self> {
                None
            }
        }
    }
}
