//! Last-level-cache topology and executor affinity for spawned jobs.
//!
//! Exchanging cache lines costs far more between threads in different last-level cache (LLC)
//! domains, and the scheduler places threads without knowing which of them share data. A spawned
//! job usually shares data with its submitter, so [`AffinityGuard`] pins the pool worker that
//! runs it into the submitter's domain. It narrows the worker's affinity mask to the domain to
//! migrate the thread there, then widens the mask again at once.
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
//! holds one of its domain's slots for the job's duration. A domain grants at most one slot fewer
//! than it has CPUs, so pinned jobs alone never fill it.

cfg_if::cfg_if! {
    if #[cfg(all(target_os = "linux", not(miri)))] {
        use std::sync::{
            OnceLock,
            atomic::{AtomicUsize, Ordering},
        };

        /// Byte size of `cpu_set_t`, as passed to the affinity syscalls. A set represents up to
        /// `libc::CPU_SETSIZE` CPUs.
        const CPU_SET_BYTES: usize = std::mem::size_of::<libc::cpu_set_t>();

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

            /// Adds `cpu` to the set. Panics if `cpu` is at or past `CPU_SETSIZE`.
            fn set(&mut self, cpu: usize) {
                assert!(
                    cpu < libc::CPU_SETSIZE as usize,
                    "cpu must be below CPU_SETSIZE"
                );

                // SAFETY: cpu is below CPU_SETSIZE (asserted above) and the set is valid.
                unsafe { libc::CPU_SET(cpu, &mut self.0) };
            }

            /// Whether `cpu` is in the set (`false` past `CPU_SETSIZE`).
            fn contains(&self, cpu: usize) -> bool {
                if cpu >= libc::CPU_SETSIZE as usize {
                    return false;
                }

                // SAFETY: cpu is below CPU_SETSIZE (checked above) and the set is valid.
                unsafe { libc::CPU_ISSET(cpu, &self.0) }
            }

            /// Whether every CPU in `self` is also in `other`.
            fn is_subset_of(&self, other: &Self) -> bool {
                (0..libc::CPU_SETSIZE as usize).all(|cpu| !self.contains(cpu) || other.contains(cpu))
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

        /// Map from CPU id to last-level-cache domain id, plus each domain's CPU set.
        struct Topology {
            /// Domain of each CPU, or `None` for a CPU whose cache topology was unreadable at
            /// detection time. Jobs submitted from such a CPU, or from one past the end of the
            /// table, run unpinned because a guessed domain could move them away from the
            /// submitter's cache.
            cpu_to_domain: Box<[Option<u16>]>,
            /// The CPUs of each domain, as ready-to-use affinity sets.
            domain_sets: Box<[CpuSet]>,
            /// Live pins per domain. Each pin holds one slot until its guard drops.
            pins: Box<[AtomicUsize]>,
        }

        impl Topology {
            /// Detects the LLC topology, or returns an empty one when it is unreadable, has a
            /// single domain, or cannot be pinned.
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
                    .any(|(cpu, _)| *cpu >= libc::CPU_SETSIZE as usize)
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

                // A pin needs a domain with room for the submitter and the job, and a pool needs
                // room for a worker, so a host whose every cache is private to one CPU has no
                // domain to place work in.
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
            /// under its existing pin and must not pin again. The thread occupies one CPU however
            /// deep its jobs nest, so a second guard would waste a slot.
            static PINNED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
        }

        /// Holds one of a domain's slots for the calling thread after [`Self::pin`] moves it into
        /// that domain.
        pub(crate) struct AffinityGuard {
            /// The pre-pin mask and the pin mask, kept only when widening failed at pin time so
            /// drop can retry it.
            pending: Option<(CpuSet, CpuSet)>,
            /// Topology that owns the held slot.
            topology: &'static Topology,
            /// Domain whose slot this guard holds.
            domain: usize,
            /// The guard acts on the mask and pinned flag of the thread that created it, so it
            /// must not move to another thread.
            thread_bound: std::marker::PhantomData<*const ()>,
        }

        impl AffinityGuard {
            /// Moves the calling thread onto the CPUs of `domain` that its current affinity mask
            /// allows, then widens the mask back at once. The move stays within the mask the
            /// thread has when the pin starts, so it keeps operator restrictions such as taskset,
            /// numactl, or isolated cores. The widening writes that starting mask back, so it
            /// overwrites a mask written during the pin. A mask written after a successful
            /// widening is left alone.
            ///
            /// Returns `None` without pinning when `domain` is `None`, the thread already holds a
            /// pin, the mask cannot be read or applied, fewer than two of the domain's CPUs are
            /// allowed, or the domain already holds one pin fewer than it has allowed CPUs. The
            /// thread then keeps its existing mask.
            pub(crate) fn pin(domain: Option<SpawnDomain>) -> Option<Self> {
                Self::pin_in(topology(), domain?.0 as usize)
            }

            /// [`Self::pin`] against an explicit topology instead of the process-wide one.
            fn pin_in(topology: &'static Topology, domain: usize) -> Option<Self> {
                if PINNED.get() {
                    return None;
                }
                let target = topology.domain_sets.get(domain)?;
                let saved = thread_affinity()?;

                // Keep only the domain's CPUs that the thread's current mask allows.
                let mut effective = CpuSet::empty();
                let mut allowed = 0usize;
                for cpu in 0..(libc::CPU_SETSIZE as usize) {
                    if target.contains(cpu) && saved.contains(cpu) {
                        effective.set(cpu);
                        allowed += 1;
                    }
                }

                // Pinning to a single allowed CPU would leave no room for both the caller and this
                // job, so require at least two.
                if allowed <= 1 {
                    return None;
                }

                // Take a pin slot, allowing at most `allowed - 1` live pins so pinned jobs alone
                // cannot fill the domain and crowd out the submitting caller. The cap counts
                // allowed CPUs rather than the sysfs domain width because operator restrictions
                // may shrink the domain.
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
                    // Applying the mask is the only step after the reservation that can fail, so
                    // hand the slot back.
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
                    topology,
                    domain,
                    thread_bound: std::marker::PhantomData,
                })
            }
        }

        impl Drop for AffinityGuard {
            /// Releases the slot, including during an unwind, and retries a widening that failed
            /// at pin time.
            fn drop(&mut self) {
                // Retry a widening that failed at pin time, but only while the thread's mask is
                // still within the pin. The kernel reports only active CPUs, so a pinned CPU that
                // went offline leaves the reported mask a subset of the pin. A mask outside the
                // pin was rewritten mid-job by an operator or the kernel. Restoring the pin-time
                // mask would revive CPUs they removed, so the newer mask stays.
                if let Some((saved, effective)) = self.pending
                    && thread_affinity().is_some_and(|current| current.is_subset_of(&effective))
                {
                    set_thread_affinity(&saved);
                }

                // Clear the thread's pinned flag and release the domain slot even when a retried
                // widening was skipped or failed. A worker left narrowed costs less than a slot
                // stranded for the life of the process.
                PINNED.set(false);
                self.topology.pins[self.domain].fetch_sub(1, Ordering::AcqRel);
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
                (0..(libc::CPU_SETSIZE as usize))
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
                let d0 = topology.domain_of(0).unwrap() as usize;
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
                let d0 = topology.domain_of(0).unwrap() as usize;
                assert!(topology.domain_sets[d0].contains(64));
            }

            #[test]
            fn from_lists_rejects_cpus_past_setsize() {
                // cpu_set_t cannot represent such CPUs, so a topology containing one must be
                // rejected whole.
                let lists = vec![
                    (0, "a".to_string()),
                    (libc::CPU_SETSIZE as usize, "b".to_string()),
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
                    if cpu >= libc::CPU_SETSIZE as usize {
                        return;
                    }
                    let mut only = CpuSet::empty();
                    only.set(cpu);
                    assert!(set_thread_affinity(&only));

                    // A one-CPU allowance leaves no room for the caller plus a job, so the pin
                    // must be skipped.
                    let guard = AffinityGuard::pin(spawn_domain());
                    assert!(guard.is_none());

                    // The mask must stay within the restriction.
                    assert!(current_mask().is_subset_of(&only));
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
                    let domain = topology.domain_of(half_a[0]).unwrap() as usize;
                    let before = current_mask();
                    {
                        let _guard = AffinityGuard::pin_in(topology, domain).unwrap();

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
            fn synthetic_pin_whose_narrowing_fails_returns_its_slot() {
                std::thread::spawn(|| {
                    let Some((topology, half_a, _)) = synthetic_split() else {
                        return;
                    };
                    let domain = topology.domain_of(half_a[0]).unwrap() as usize;
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
                    assert!(AffinityGuard::pin_in(topology, domain).is_none());
                    assert_eq!(topology.pins[domain].load(Ordering::Acquire), 0);
                    assert!(!PINNED.get());
                    assert!(before.equals(&current_mask()));
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
                    let domain = topology.domain_of(half_a[0]).unwrap() as usize;
                    for _ in 0..100 {
                        assert!(AffinityGuard::pin_in(topology, domain).is_some());
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
                    let domain = topology.domain_of(half_a[0]).unwrap() as usize;
                    let other = topology.domain_of(half_b[0]).unwrap() as usize;
                    let outer = AffinityGuard::pin_in(topology, domain).unwrap();

                    // A pinned thread must not pin again in any domain, so nested jobs stay within
                    // the outer pin.
                    assert!(AffinityGuard::pin_in(topology, domain).is_none());
                    assert!(AffinityGuard::pin_in(topology, other).is_none());

                    // Dropping the outer guard clears the thread's pinned flag and releases the
                    // slot, so the thread can pin again.
                    drop(outer);
                    assert_eq!(topology.pins[domain].load(Ordering::Acquire), 0);
                    assert!(AffinityGuard::pin_in(topology, domain).is_some());
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
                    let domain = topology.domain_of(half_a[0]).unwrap() as usize;
                    let guard = AffinityGuard::pin_in(topology, domain).unwrap();

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
                    topology,
                    domain,
                    thread_bound: std::marker::PhantomData,
                }
            }

            #[test]
            fn synthetic_pending_widening_is_retried_at_drop() {
                std::thread::spawn(|| {
                    let Some((topology, half_a, _)) = synthetic_split() else {
                        return;
                    };
                    let domain = topology.domain_of(half_a[0]).unwrap() as usize;
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
                    let domain = topology.domain_of(half_a[0]).unwrap() as usize;
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
                let domain = topology.domain_of(half_a[0]).unwrap() as usize;

                // Scoped threads inherit this thread's mask. It allows every CPU in the domain, so
                // each thread computes the same cap of the domain's width minus one.
                let cap = half_a.len() - 1;

                // Workers make no assertions and spin on `released`. A drop guard sets it even when
                // an assertion below panics, so a failing assertion fails the test instead of
                // deadlocking the scope's implicit join.
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
                            let guard = AffinityGuard::pin_in(topology, domain);
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
                    assert!(AffinityGuard::pin_in(topology, domain).is_none());
                });

                // With every guard dropped, the counter returns exactly to zero and pins engage
                // again.
                assert_eq!(topology.pins[domain].load(Ordering::Acquire), 0);
                std::thread::spawn(move || {
                    assert!(AffinityGuard::pin_in(topology, domain).is_some());
                })
                .join()
                .unwrap();
            }

            #[test]
            fn synthetic_pin_stress_never_exceeds_cap() {
                let Some((topology, half_a, _)) = synthetic_split() else {
                    return;
                };
                let domain = topology.domain_of(half_a[0]).unwrap() as usize;
                let cap = half_a.len() - 1;

                // Four threads per domain CPU pin and release concurrently. The live count must
                // stay within the cap and end at zero.
                std::thread::scope(|s| {
                    for _ in 0..(4 * half_a.len()) {
                        s.spawn(|| {
                            for _ in 0..200 {
                                let guard = AffinityGuard::pin_in(topology, domain);

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
