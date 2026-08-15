//! Last-level-cache topology and executor affinity for spawned jobs.
//!
//! Threads that exchange cache lines pay far more when they sit in different last-level cache (L3)
//! domains: on multi-CCD parts a cross-domain transfer costs several times a shared-domain one, and
//! the scheduler's thread placement is a sticky per-process lottery it never revisits. A spawned
//! job usually has a data relationship with its submitter (it consumes what the caller just built,
//! and the caller consumes what it produces), so the job's executor pins itself to the submitter's
//! domain for the job's duration via [`AffinityGuard`]: one migration the first time (tens of
//! microseconds, against per-line fabric traffic for the job's lifetime otherwise), and a no-op
//! afterwards because the restored-wide executor tends to stay where it ran.
//!
//! Domains come from the kernel's cache topology: for each CPU, the highest-level Data or Unified
//! leaf under `cache/index*` in sysfs is its last-level cache (the leaf index varies by
//! architecture, so it is discovered rather than assumed; vendor core-layout assumptions also lie,
//! as this was built on a machine whose spec sheet implied 8-core L3 groups while the kernel
//! reported 4-core ones). Pinning is skipped whenever it cannot be done safely and profitably: a
//! single or undetectable domain, a CPU the snapshot does not cover, a failed CPU query, an
//! operator restriction (taskset, numactl, isolated cores) leaving fewer than two allowed CPUs in
//! the domain (the caller needs one and the job another), or a domain already holding its cap of
//! live pins (the allowed CPUs minus one, reserving one for the caller). On non-Linux platforms
//! the stub below reports no domains and pinning is a no-op; the same stub serves miri (the
//! affinity syscalls are unshimmed).

cfg_if::cfg_if! {
    if #[cfg(all(target_os = "linux", not(miri)))] {
        use std::sync::{
            OnceLock,
            atomic::{AtomicUsize, Ordering},
        };

        /// The process-wide topology, detected on first use.
        fn topology() -> &'static Topology {
            static TOPOLOGY: OnceLock<Topology> = OnceLock::new();
            TOPOLOGY.get_or_init(Topology::detect)
        }

        /// Map from CPU id to last-level-cache domain id, plus each domain's CPU set.
        pub(crate) struct Topology {
            /// `cpu_to_domain[cpu]` is the domain of `cpu`; `None` beyond the table or for CPUs
            /// whose cache topology was unreadable at detection time. Unknown CPUs skip pinning
            /// rather than guess: domain numbering is an artifact of iteration order, so a guess
            /// could deliberately migrate a job somewhere unrelated.
            cpu_to_domain: Box<[Option<u16>]>,
            /// The CPUs of each domain, as ready-to-use affinity sets.
            domain_sets: Box<[libc::cpu_set_t]>,
            /// Live pins per domain. Each pin reserves a slot against the domain's effective
            /// width (its CPUs the pinning thread may use) minus one, so pinned jobs can never
            /// crowd a domain or the caller working in it: past the cap, a job simply runs
            /// unpinned wherever the scheduler likes.
            pins: Box<[AtomicUsize]>,
        }

        impl Topology {
            /// Detects the LLC topology; `None` when unreadable or single-domain.
            fn detect() -> Self {
                Self::from_sysfs().unwrap_or(Self {
                    cpu_to_domain: Box::new([]),
                    domain_sets: Box::new([]),
                    pins: Box::new([]),
                })
            }

            /// Number of distinct domains (0 or 1 disables the preference and pinning).
            pub(crate) fn domains(&self) -> usize {
                self.domain_sets.len()
            }

            /// The domain of `cpu`, or `None` when the snapshot does not cover it.
            fn domain_of(&self, cpu: usize) -> Option<u16> {
                self.cpu_to_domain.get(cpu).copied().flatten()
            }

            /// The domain of the CPU the calling thread is currently running on, or `None` when
            /// the query fails or the snapshot does not cover the CPU. Advisory: the thread may
            /// migrate immediately after.
            pub(crate) fn current_domain(&self) -> Option<u16> {
                // SAFETY: sched_getcpu takes no arguments and only returns a value; -1 on error.
                let cpu = unsafe { libc::sched_getcpu() };
                if cpu < 0 {
                    return None;
                }
                self.domain_of(cpu as usize)
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
                let max_cpu = lists.iter().map(|(cpu, _)| *cpu).max()?;
                let mut table: Vec<Option<u16>> = vec![None; max_cpu + 1];
                let mut domains: Vec<&str> = Vec::new();

                // SAFETY: an all-zero cpu_set_t is the valid empty set.
                let empty: libc::cpu_set_t = unsafe { std::mem::zeroed() };
                let mut sets: Vec<libc::cpu_set_t> = Vec::new();
                for (cpu, list) in lists {
                    let list = list.as_str();
                    let domain = domains.iter().position(|&d| d == list).unwrap_or_else(|| {
                        domains.push(list);
                        sets.push(empty);
                        domains.len() - 1
                    });
                    table[*cpu] = Some(u16::try_from(domain).ok()?);
                    if *cpu < libc::CPU_SETSIZE as usize {
                        // SAFETY: cpu is within CPU_SETSIZE and the set is initialized.
                        unsafe { libc::CPU_SET(*cpu, &mut sets[domain]) };
                    }
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

        /// Pins the calling thread to a domain's CPU set for its lifetime, restoring the previous
        /// affinity mask on drop (including unwinds).
        pub(crate) struct AffinityGuard {
            saved: libc::cpu_set_t,
            domain: usize,
        }

        impl AffinityGuard {
            /// Pins the calling thread to the CPUs of `domain` that its current affinity mask
            /// already allows, so the pin narrows placement and never widens it past an operator's
            /// restrictions (taskset, numactl, isolated cores). Returns `None` (no pin) if the mask
            /// cannot be read or applied, if the allowed intersection is empty, or if the domain is
            /// already at its pin cap; the job then simply runs wherever it was.
            pub(crate) fn pin(domain: Option<SpawnDomain>) -> Option<Self> {
                let domain = domain?.0 as usize;
                let topology = topology();
                let target = topology.domain_sets.get(domain)?;

                // SAFETY: an all-zero cpu_set_t is the valid empty set, filled by sched_getaffinity
                // below.
                let mut saved: libc::cpu_set_t = unsafe { std::mem::zeroed() };
                let size = std::mem::size_of::<libc::cpu_set_t>();

                // SAFETY: pid 0 is the calling thread; `saved` is a valid set of `size`.
                if unsafe { libc::sched_getaffinity(0, size, &mut saved) } != 0 {
                    return None;
                }

                // Intersect the domain with the thread's current allowance so the pin narrows
                // placement and never widens it past operator restrictions. SAFETY: an all-zero
                // cpu_set_t is the valid empty set.
                let mut effective: libc::cpu_set_t = unsafe { std::mem::zeroed() };
                let mut allowed = 0usize;
                for cpu in 0..(libc::CPU_SETSIZE as usize) {
                    // SAFETY: cpu is within CPU_SETSIZE; all three sets are valid.
                    unsafe {
                        if libc::CPU_ISSET(cpu, target) && libc::CPU_ISSET(cpu, &saved) {
                            libc::CPU_SET(cpu, &mut effective);
                            allowed += 1;
                        }
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
                let slot = PinSlot { domain };

                // SAFETY: pid 0 is the calling thread; `effective` is a valid set of `size`.
                if unsafe { libc::sched_setaffinity(0, size, &effective) } != 0 {
                    return None;
                }

                // The mask is applied: the guard now owns both the restore and the slot.
                core::mem::forget(slot);
                Some(Self { saved, domain })
            }
        }

        /// Releases a reserved pin slot if `pin` bails before the mask is applied.
        struct PinSlot {
            domain: usize,
        }

        impl Drop for PinSlot {
            fn drop(&mut self) {
                topology().pins[self.domain].fetch_sub(1, Ordering::AcqRel);
            }
        }

        impl Drop for AffinityGuard {
            fn drop(&mut self) {
                let size = std::mem::size_of::<libc::cpu_set_t>();

                // Restore before releasing the slot, so the counter never advertises capacity
                // while this worker is still pinned. SAFETY: pid 0 is the calling thread;
                // `saved` is the mask read at pin time. Restoring wide does not migrate the
                // thread, so a worker that served a caller tends to stay in that caller's
                // domain: repeat spawns pin without moving anyone.
                if unsafe { libc::sched_setaffinity(0, size, &self.saved) } == 0 {
                    topology().pins[self.domain].fetch_sub(1, Ordering::AcqRel);
                }
                // A failed restore leaves the worker pinned; its slot stays occupied so the
                // domain's cap keeps reflecting reality.
            }
        }

        #[cfg(test)]
        mod tests {
            use super::*;

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
                    // SAFETY: cpu < CPU_SETSIZE; the set was built by from_lists.
                    assert!(unsafe { libc::CPU_ISSET(cpu, &topology.domain_sets[d0]) });
                }

                // SAFETY: as above.
                assert!(!unsafe { libc::CPU_ISSET(4, &topology.domain_sets[d0]) });
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
            fn pin_never_widens_a_restricted_mask() {
                std::thread::spawn(|| {
                    // Restrict this thread to its current CPU only.
                    // SAFETY: valid empty set, filled below.
                    let mut only: libc::cpu_set_t = unsafe { std::mem::zeroed() };

                    // SAFETY: no arguments; returns a value.
                    let cpu = unsafe { libc::sched_getcpu() };
                    assert!(cpu >= 0);

                    // SAFETY: cpu < CPU_SETSIZE (kernel CPU ids are small), valid set.
                    unsafe { libc::CPU_SET(cpu as usize, &mut only) };
                    let size = std::mem::size_of::<libc::cpu_set_t>();

                    // SAFETY: pid 0 = this thread, valid set.
                    assert_eq!(unsafe { libc::sched_setaffinity(0, size, &only) }, 0);

                    // A one-CPU allowance leaves no room for the caller plus a job, so the
                    // pin must be skipped outright.
                    let guard = AffinityGuard::pin(spawn_domain());
                    assert!(guard.is_none());

                    // SAFETY: an all-zero cpu_set_t is the valid empty set.
                    let mut now: libc::cpu_set_t = unsafe { std::mem::zeroed() };
                    // SAFETY: pid 0 = this thread; `now` is a valid set of `size`.
                    assert_eq!(unsafe { libc::sched_getaffinity(0, size, &mut now) }, 0);
                    for c in 0..(libc::CPU_SETSIZE as usize) {
                        // SAFETY: c < CPU_SETSIZE, valid sets.
                        let (n, o) = unsafe { (libc::CPU_ISSET(c, &now), libc::CPU_ISSET(c, &only)) };
                        assert!(!n || o, "pin widened the mask at cpu {c}");
                    }
                })
                .join()
                .unwrap();
            }

            #[test]
            fn pin_slots_do_not_leak() {
                // Repeated pin and release must not consume permanent slots: if the counter
                // leaked, pins would start failing after about a domain's width of cycles.
                let Some(domain) = spawn_domain() else {
                    return;
                };

                // The environment may forbid pinning outright (e.g. a taskset restriction
                // leaving fewer than two allowed CPUs in the domain); leak detection needs
                // an environment where a pin can succeed at all.
                if AffinityGuard::pin(Some(domain)).is_none() {
                    return;
                }
                for _ in 0..100 {
                    drop(AffinityGuard::pin(Some(domain)));
                }
                assert!(AffinityGuard::pin(Some(domain)).is_some());
            }

            #[test]
            fn pin_and_restore_roundtrip() {
                // Pin to the current domain (a no-op move) and verify the mask restores.
                // SAFETY: an all-zero cpu_set_t is a valid empty set for getaffinity.
                let mut before: libc::cpu_set_t = unsafe { std::mem::zeroed() };
                let size = std::mem::size_of::<libc::cpu_set_t>();
                // SAFETY: pid 0 = calling thread, valid set.
                assert_eq!(unsafe { libc::sched_getaffinity(0, size, &mut before) }, 0);
                {
                    let _guard = AffinityGuard::pin(spawn_domain());
                }

                // SAFETY: an all-zero cpu_set_t is the valid empty set.
                let mut after: libc::cpu_set_t = unsafe { std::mem::zeroed() };
                // SAFETY: pid 0 = calling thread; `after` is a valid set of `size`.
                assert_eq!(unsafe { libc::sched_getaffinity(0, size, &mut after) }, 0);
                for cpu in 0..(libc::CPU_SETSIZE as usize) {
                    // SAFETY: cpu < CPU_SETSIZE, valid sets.
                    let (b, a) = unsafe { (libc::CPU_ISSET(cpu, &before), libc::CPU_ISSET(cpu, &after)) };
                    assert_eq!(b, a, "mask not restored at cpu {cpu}");
                }
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
