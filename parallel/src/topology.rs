//! Last-level-cache topology and executor affinity for spawned jobs.
//!
//! Threads that exchange cache lines pay far more when they sit in different last-level cache
//! (L3) domains, and the scheduler never revisits its initial thread placement. A spawned job
//! usually exchanges data with its submitter, so the executor pins itself to the submitter's
//! domain for the job's duration via [`AffinityGuard`]: one cheap migration the first time, and
//! a no-op afterwards because the restored executor tends to stay where it ran.
//!
//! Domains come from the kernel's sysfs cache topology: each CPU's last-level cache is its
//! highest-level Data or Unified `cache/index*` leaf (the leaf index varies by architecture, so
//! it is discovered rather than assumed). Pinning is best effort: it is skipped whenever it
//! cannot be applied safely and profitably (see [AffinityGuard::pin]), and a mask rewritten
//! mid-job to CPUs outside the pin is left in place at unpin. Machines whose possible-CPU count
//! exceeds `cpu_set_t`'s capacity report no domains. On non-Linux platforms and under miri the
//! stub below reports no domains and pinning is a no-op.

cfg_if::cfg_if! {
    if #[cfg(all(target_os = "linux", not(miri)))] {
        use std::sync::{
            OnceLock,
            atomic::{AtomicUsize, Ordering},
        };

        /// Byte size of `cpu_set_t`, as passed to the affinity syscalls. Distinct from
        /// `libc::CPU_SETSIZE`, which counts representable CPUs.
        const CPU_SET_BYTES: usize = std::mem::size_of::<libc::cpu_set_t>();

        /// A CPU affinity mask: a safe wrapper over `libc::cpu_set_t`.
        ///
        /// Together with [`thread_affinity`], [`set_thread_affinity`], and [`current_cpu`],
        /// this funnels all of the module's libc FFI through a handful of one-line unsafe
        /// blocks, so the rest of the pin protocol is safe code.
        #[derive(Clone, Copy)]
        struct CpuSet(libc::cpu_set_t);

        impl CpuSet {
            /// The empty set.
            const fn empty() -> Self {
                // SAFETY: an all-zero cpu_set_t is the valid empty set.
                Self(unsafe { std::mem::zeroed() })
            }

            /// Adds `cpu` to the set. Panics past `CPU_SETSIZE`, where the libc crate's
            /// `CPU_SET` is unguarded.
            fn set(&mut self, cpu: usize) {
                assert!(cpu < libc::CPU_SETSIZE as usize);

                // SAFETY: cpu is within CPU_SETSIZE (asserted above); the set is valid.
                unsafe { libc::CPU_SET(cpu, &mut self.0) };
            }

            /// Whether `cpu` is in the set (`false` past `CPU_SETSIZE`).
            fn contains(&self, cpu: usize) -> bool {
                if cpu >= libc::CPU_SETSIZE as usize {
                    return false;
                }

                // SAFETY: cpu is within CPU_SETSIZE (checked above); the set is valid.
                unsafe { libc::CPU_ISSET(cpu, &self.0) }
            }

            /// Whether every CPU in `self` is also in `other`.
            fn is_subset_of(&self, other: &Self) -> bool {
                (0..libc::CPU_SETSIZE as usize).all(|cpu| !self.contains(cpu) || other.contains(cpu))
            }

            /// Whether the sets hold exactly the same CPUs. Used by restore assertions in
            /// tests; the pin protocol itself only needs the subset test.
            #[cfg(test)]
            fn equals(&self, other: &Self) -> bool {
                // SAFETY: both sets are valid; CPU_EQUAL only compares their bits.
                unsafe { libc::CPU_EQUAL(&self.0, &other.0) }
            }
        }

        /// The calling thread's current affinity mask, or `None` when the kernel refuses the
        /// query (a possible-CPU count past `cpu_set_t`'s capacity, see [`Topology::detect`]).
        fn thread_affinity() -> Option<CpuSet> {
            let mut mask = CpuSet::empty();

            // SAFETY: pid 0 is the calling thread; the set is a valid cpu_set_t of
            // `CPU_SET_BYTES`.
            if unsafe { libc::sched_getaffinity(0, CPU_SET_BYTES, &mut mask.0) } != 0 {
                return None;
            }
            Some(mask)
        }

        /// Applies `mask` to the calling thread; `false` when the kernel refuses.
        fn set_thread_affinity(mask: &CpuSet) -> bool {
            // SAFETY: pid 0 is the calling thread; the set is a valid cpu_set_t of
            // `CPU_SET_BYTES`.
            unsafe { libc::sched_setaffinity(0, CPU_SET_BYTES, &mask.0) == 0 }
        }

        /// The CPU the calling thread is running on, or `None` when the query fails.
        /// Advisory: the thread may migrate immediately after.
        fn current_cpu() -> Option<usize> {
            // SAFETY: sched_getcpu takes no arguments and only returns a value; -1 on error.
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
            /// `cpu_to_domain[cpu]` is the domain of `cpu`; `None` beyond the table or for CPUs
            /// whose cache topology was unreadable at detection time. Unknown CPUs skip pinning
            /// rather than guess a domain and migrate the job somewhere unrelated.
            cpu_to_domain: Box<[Option<u16>]>,
            /// The CPUs of each domain, as ready-to-use affinity sets.
            domain_sets: Box<[CpuSet]>,
            /// Live pins per domain. Each pin reserves a slot against the domain's effective
            /// width (its CPUs the pinning thread may use) minus one, so pinned jobs can never
            /// crowd a domain or the caller working in it: past the cap, a job simply runs
            /// unpinned wherever the scheduler likes.
            pins: Box<[AtomicUsize]>,
        }

        impl Topology {
            /// Detects the LLC topology; empty when unreadable, single-domain, or unpinnable.
            fn detect() -> Self {
                // When the possible-CPU count exceeds cpu_set_t's capacity, the affinity
                // syscalls fail outright regardless of the CPU ids visible in sysfs, so
                // report no domains rather than charge every spawn for a doomed syscall.
                if thread_affinity().is_none() {
                    return Self::empty();
                }
                Self::from_sysfs().unwrap_or_else(Self::empty)
            }

            /// A topology with no domains: the preference and pinning are disabled.
            fn empty() -> Self {
                Self {
                    cpu_to_domain: Box::new([]),
                    domain_sets: Box::new([]),
                    pins: Box::new([]),
                }
            }

            /// Number of distinct domains (0 or 1 disables the preference and pinning).
            fn domains(&self) -> usize {
                self.domain_sets.len()
            }

            /// The domain of `cpu`, or `None` when the snapshot does not cover it.
            fn domain_of(&self, cpu: usize) -> Option<u16> {
                self.cpu_to_domain.get(cpu).copied().flatten()
            }

            /// The domain of the CPU the calling thread is currently running on, or `None` when
            /// the query fails or the snapshot does not cover the CPU. Advisory: the thread may
            /// migrate immediately after.
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
                    if best.as_ref().is_none_or(|(l, _)| level > *l) {
                        best = Some((level, list.trim().to_string()));
                    }
                }
                best.map(|(_, list)| list)
            }

            /// Builds the tables from each CPU's discovered LLC sharing list. Returns `None` if
            /// nothing was readable or only one domain exists.
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

            /// Builds the tables from `(cpu, shared_cpu_list)` pairs; each distinct list
            /// string is one domain. Separated from sysfs reading for testability.
            fn from_lists(lists: &[(usize, String)]) -> Option<Self> {
                if lists.is_empty() {
                    return None;
                }

                // cpu_set_t cannot represent CPUs past CPU_SETSIZE, so a topology containing
                // one could never be pinned within faithfully: report none.
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
                for (cpu, list) in lists {
                    let list = list.as_str();
                    let domain = domains.iter().position(|&d| d == list).unwrap_or_else(|| {
                        domains.push(list);
                        sets.push(CpuSet::empty());
                        domains.len() - 1
                    });
                    table[*cpu] = Some(u16::try_from(domain).ok()?);
                    sets[domain].set(*cpu);
                }
                if domains.len() <= 1 {
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

        /// The submitting caller's current LLC domain, captured at spawn time and consumed by
        /// [`AffinityGuard::pin`] on whichever thread executes the job. `None` when the topology
        /// has fewer than two domains or the caller's position is unknown.
        #[derive(Clone, Copy)]
        pub(crate) struct SpawnDomain(u16);

        /// Captures the calling thread's current domain (`None` disables pinning).
        pub(crate) fn spawn_domain() -> Option<SpawnDomain> {
            let topology = topology();
            if topology.domains() <= 1 {
                return None;
            }
            topology.current_domain().map(SpawnDomain)
        }

        std::thread_local! {
            /// Whether this thread currently holds a live [`AffinityGuard`]. A worker that
            /// picks up nested jobs while pinned must not pin again: the thread occupies one
            /// CPU no matter how deep its stack of jobs, so a second guard would waste a
            /// cap slot.
            static PINNED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
        }

        /// Pins the calling thread to a domain's CPU set for its lifetime, restoring the previous
        /// affinity mask on drop (including unwinds) unless the thread's mask was rewritten
        /// mid-job to CPUs outside the pin, in which case that newer placement is left in place.
        pub(crate) struct AffinityGuard {
            saved: CpuSet,
            effective: CpuSet,
            topology: &'static Topology,
            domain: usize,
        }

        impl AffinityGuard {
            /// Pins the calling thread to the CPUs of `domain` that its current affinity mask
            /// already allows, so the pin narrows placement and never widens it past an operator's
            /// restrictions (taskset, numactl, isolated cores). Returns `None` (no pin) if the
            /// thread already holds a pin (nested jobs stay within the outer confinement), if the
            /// mask cannot be read or applied, if the allowed intersection has fewer than two
            /// CPUs, or if the domain is already at its pin cap; the job then simply runs
            /// wherever it was.
            pub(crate) fn pin(domain: Option<SpawnDomain>) -> Option<Self> {
                Self::pin_in(topology(), domain?.0 as usize)
            }

            /// [`Self::pin`] against an explicit topology, letting tests drive the full pin
            /// protocol (intersection, cap accounting, apply and restore) on synthetic
            /// domains.
            fn pin_in(topology: &'static Topology, domain: usize) -> Option<Self> {
                if PINNED.get() {
                    return None;
                }
                let target = topology.domain_sets.get(domain)?;
                let saved = thread_affinity()?;

                // Intersect the domain with the thread's current allowance so the pin narrows
                // placement and never widens it past operator restrictions.
                let mut effective = CpuSet::empty();
                let mut allowed = 0usize;
                for cpu in 0..(libc::CPU_SETSIZE as usize) {
                    if target.contains(cpu) && saved.contains(cpu) {
                        effective.set(cpu);
                        allowed += 1;
                    }
                }

                // A one-CPU effective set would co-locate the job on the caller's only core
                // with zero placement freedom; require room for the caller plus this job.
                if allowed <= 1 {
                    return None;
                }

                // Take a pin slot against the effective width (not the sysfs domain width,
                // which operator restrictions may shrink): at most `allowed - 1` live pins,
                // reserving a CPU for the submitting caller. Past the cap the job runs
                // unpinned.
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
                    // The only bail point after the reservation: hand the slot back.
                    pins.fetch_sub(1, Ordering::AcqRel);
                    return None;
                }
                PINNED.set(true);
                Some(Self {
                    saved,
                    effective,
                    topology,
                    domain,
                })
            }
        }

        impl Drop for AffinityGuard {
            fn drop(&mut self) {
                // Restore only if the thread's mask is still within the one this pin applied:
                // equal in the common case, or clamped to a subset by the kernel while a CPU
                // is offline. A mask straying outside the pin was rewritten mid-job by an
                // operator or the kernel, and the newer placement wins: restoring the
                // pin-time snapshot would resurrect a revoked allowance. (A rewrite landing
                // within the pin's own CPUs is indistinguishable from the pin and gets
                // restored over.)
                let ours =
                    thread_affinity().is_some_and(|current| current.is_subset_of(&self.effective));
                if ours {
                    // Restoring wide does not migrate the thread, so a worker that served a
                    // caller tends to stay in that caller's domain: repeat spawns pin without
                    // moving anyone.
                    set_thread_affinity(&self.saved);
                }

                // Release the thread's pin and the domain slot unconditionally: cleanup is
                // best effort, and a failed restore leaving this worker narrowed is preferred
                // over stranding domain capacity for the process lifetime.
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
                thread_affinity().expect("affinity read failed")
            }

            /// The CPUs the calling thread may currently use.
            fn allowed_cpus() -> Vec<usize> {
                let mask = current_mask();
                (0..(libc::CPU_SETSIZE as usize))
                    .filter(|&cpu| mask.contains(cpu))
                    .collect()
            }

            /// A leaked two-domain topology splitting this process's allowed CPUs in half,
            /// plus the CPUs of each half. Private pin counters let tests assert exact
            /// values without racing other tests, and two synthetic domains exist on any
            /// machine with four allowed CPUs (each half needs two so pins can engage).
            fn synthetic_split() -> Option<(&'static Topology, Vec<usize>, Vec<usize>)> {
                let mut cpus = allowed_cpus();
                if cpus.len() < 4 {
                    return None;
                }

                // Bound the domains so the cap and stress tests spawn a handful of threads
                // on any machine, rather than hundreds on a wide builder.
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
                // CPU 5 is missing from the snapshot; CPUs beyond the table are unknown too.
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
                // On any Linux machine with a readable cache topology, discovery must return a
                // non-empty sharing list for cpu0 (or nothing at all, never a panic).
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
                let lists: Vec<(usize, String)> =
                    (0..4).map(|cpu| (cpu, "0-3".to_string())).collect();
                assert!(Topology::from_lists(&lists).is_none());
            }

            #[test]
            fn from_lists_smt_discontiguous_domains() {
                // SMT siblings share the LLC, so real sharing lists are discontiguous:
                // physical cores 0-3 pair with logical CPUs 64-67.
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
                // cpu_set_t cannot represent such CPUs, so the machine must report no
                // topology instead of pinning within a truncated view of it.
                let lists = vec![
                    (0, "a".to_string()),
                    (libc::CPU_SETSIZE as usize, "b".to_string()),
                ];
                assert!(Topology::from_lists(&lists).is_none());
            }

            #[test]
            fn llc_list_picks_highest_level_data_or_unified_leaf() {
                // A synthetic sysfs cache directory: the LLC is the level-3 Unified leaf,
                // and neither the level-1 Data leaf (first in directory order), the
                // Instruction leaf, nor a fixed index number may win instead.
                let dir =
                    std::env::temp_dir().join(format!("commonware_llc_{}", std::process::id()));
                let cache = dir.join("cache");
                let leaves = [
                    ("index0", "Data", "1", "0"),
                    ("index1", "Instruction", "1", "0"),
                    ("index2", "Unified", "2", "0-1"),
                    ("index3", "Unified", "3", "0-7,64-71"),
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
                    // Restrict this thread to its current CPU only.
                    let cpu = current_cpu().unwrap();

                    // CpuSet::set panics past CPU_SETSIZE; such ids also mean the machine
                    // cannot pin at all (see from_lists), so there is nothing to test.
                    if cpu >= libc::CPU_SETSIZE as usize {
                        return;
                    }
                    let mut only = CpuSet::empty();
                    only.set(cpu);
                    assert!(set_thread_affinity(&only));

                    // A one-CPU allowance leaves no room for the caller plus a job, so the
                    // pin must be skipped outright.
                    let guard = AffinityGuard::pin(spawn_domain());
                    assert!(guard.is_none());

                    // The mask must not have widened: still within the restriction.
                    assert!(current_mask().is_subset_of(&only));
                })
                .join()
                .unwrap();
            }

            #[test]
            fn synthetic_pin_narrows_to_domain_and_restores() {
                std::thread::spawn(|| {
                    let Some((topology, half_a, _)) = synthetic_split() else {
                        return;
                    };
                    let domain = topology.domain_of(half_a[0]).unwrap() as usize;
                    let before = current_mask();
                    {
                        let _guard = AffinityGuard::pin_in(topology, domain).unwrap();

                        // The pin narrows the mask to exactly the domain's allowed CPUs.
                        let now = current_mask();
                        for cpu in 0..(libc::CPU_SETSIZE as usize) {
                            let set = now.contains(cpu);
                            assert_eq!(set, half_a.contains(&cpu), "mask mismatch at cpu {cpu}");
                        }
                    }

                    // Dropping the guard restores the pre-pin mask exactly.
                    assert!(before.equals(&current_mask()));
                })
                .join()
                .unwrap();
            }

            #[test]
            fn synthetic_pin_slots_do_not_leak() {
                // Repeated pin and release must not consume permanent slots: if the counter
                // leaked, pins would start failing after about a domain's width of cycles.
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

                    // A pinned thread must not pin again, in any domain: nested jobs stay
                    // within the outer confinement.
                    assert!(AffinityGuard::pin_in(topology, domain).is_none());
                    assert!(AffinityGuard::pin_in(topology, other).is_none());

                    // Dropping the outer guard releases the thread's pin and the slot.
                    drop(outer);
                    assert_eq!(topology.pins[domain].load(Ordering::Acquire), 0);
                    assert!(AffinityGuard::pin_in(topology, domain).is_some());
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

                // Every spawned thread is unrestricted, so each sees the same effective
                // width and the same cap: the domain's CPUs minus the caller reservation.
                let cap = half_a.len() - 1;

                // No assertions run on the worker threads and no thread waits on anything
                // the main thread's unwind would strand: workers spin on `released`, which
                // a drop guard sets even if an assertion below panics, so a failing test
                // fails instead of deadlocking the scope's implicit join.
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

                    // Every slot is taken: each pin under the cap succeeded, the counter
                    // sits at the cap, and a further pin is refused.
                    assert_eq!(granted.load(Ordering::Acquire), cap);
                    assert_eq!(topology.pins[domain].load(Ordering::Acquire), cap);
                    assert!(AffinityGuard::pin_in(topology, domain).is_none());
                });

                // All guards dropped: the counter returns exactly to zero and pins engage
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
                // Success-side assertions live in the synthetic-topology tests: on the
                // process-global topology, concurrently running tests contend for the same
                // pin slots, so only a refusal can be asserted deterministically here.
                std::thread::spawn(|| {
                    let Some(domain) = spawn_domain() else {
                        return;
                    };
                    let Some(_outer) = AffinityGuard::pin(Some(domain)) else {
                        return;
                    };

                    // A pinned thread occupies one CPU regardless of nesting depth; a nested
                    // pin must be refused rather than burn a second cap slot.
                    assert!(AffinityGuard::pin(Some(domain)).is_none());
                })
                .join()
                .unwrap();
            }

            #[test]
            fn pin_and_restore_roundtrip() {
                // Pin to the current domain (a no-op move) and verify the mask restores.
                let before = current_mask();
                {
                    let _guard = AffinityGuard::pin(spawn_domain());
                }
                let after = current_mask();
                assert!(before.equals(&after));
            }
        }
    } else {
        /// Single-domain stub: pinning is unavailable and compiles to a no-op.
        #[derive(Clone, Copy)]
        pub(crate) struct SpawnDomain;

        /// Always `None`: no multi-domain topology to pin within.
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
