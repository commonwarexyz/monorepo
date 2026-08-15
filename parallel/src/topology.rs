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
//! Domains come from the kernel's cache topology (never from vendor core-layout assumptions, which
//! lie: this was built on a machine whose spec sheet implied 8-core L3 groups while the kernel
//! reported 4-core ones). On non-Linux platforms the stub below reports a single domain and pinning
//! is a no-op; the same stub serves miri (the affinity syscalls are unshimmed).

cfg_if::cfg_if! {
    if #[cfg(all(target_os = "linux", not(miri)))] {
        use std::sync::OnceLock;

        /// The process-wide topology, detected on first use.
        fn topology() -> &'static Topology {
            static TOPOLOGY: OnceLock<Topology> = OnceLock::new();
            TOPOLOGY.get_or_init(Topology::detect)
        }

        /// Map from CPU id to last-level-cache domain id, plus each domain's CPU set.
        pub(crate) struct Topology {
            /// `cpu_to_domain[cpu]` is the domain of `cpu`; CPUs beyond the table
            /// (offline or hot-added) map to domain 0.
            cpu_to_domain: Box<[u16]>,
            /// The CPUs of each domain, as ready-to-use affinity sets.
            domain_sets: Box<[libc::cpu_set_t]>,
        }

        impl Topology {
            /// Detects the LLC topology; `None` when unreadable or single-domain.
            fn detect() -> Self {
                Self::from_sysfs().unwrap_or(Self {
                    cpu_to_domain: Box::new([]),
                    domain_sets: Box::new([]),
                })
            }

            /// Number of distinct domains (0 or 1 disables the preference and pinning).
            pub(crate) fn domains(&self) -> usize {
                self.domain_sets.len()
            }

            /// The domain of `cpu`.
            fn domain_of(&self, cpu: usize) -> u16 {
                self.cpu_to_domain.get(cpu).copied().unwrap_or(0)
            }

            /// The domain of the CPU the calling thread is currently running on.
            /// Advisory: the thread may migrate immediately after.
            pub(crate) fn current_domain(&self) -> u16 {
                // SAFETY: sched_getcpu takes no arguments and only returns a value; -1
                // on error (mapped to domain 0 by the table fallback).
                let cpu = unsafe { libc::sched_getcpu() };
                if cpu >= 0 {
                    return self.domain_of(cpu as usize);
                }
                0
            }

            /// Builds the table from
            /// `/sys/devices/system/cpu/cpu*/cache/index3/shared_cpu_list`. Returns
            /// `None` if nothing was readable or only one domain exists.
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
                    let path = entry.path().join("cache/index3/shared_cpu_list");
                    if let Ok(list) = std::fs::read_to_string(path) {
                        lists.push((id, list.trim().to_string()));
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
                let mut table = vec![0u16; max_cpu + 1];
                let mut domains: Vec<&str> = Vec::new();

                // SAFETY: an all-zero cpu_set_t is the valid empty set.
                let empty: libc::cpu_set_t = unsafe { std::mem::zeroed() };
                let mut sets: Vec<libc::cpu_set_t> = Vec::new();
                for (cpu, list) in lists {
                    let list = list.as_str();
                    let domain = match domains.iter().position(|&d| d == list) {
                        Some(i) => i,
                        None => {
                            domains.push(list);
                            sets.push(empty);
                            domains.len() - 1
                        }
                    };
                    table[*cpu] = u16::try_from(domain).ok()?;
                    if *cpu < libc::CPU_SETSIZE as usize {
                        // SAFETY: cpu is within CPU_SETSIZE and the set is initialized.
                        unsafe { libc::CPU_SET(*cpu, &mut sets[domain]) };
                    }
                }
                if domains.len() <= 1 {
                    return None;
                }
                Some(Self {
                    cpu_to_domain: table.into_boxed_slice(),
                    domain_sets: sets.into_boxed_slice(),
                })
            }
        }

        /// The submitting caller's current LLC domain, captured at spawn time and consumed by
        /// [`AffinityGuard::pin`] on whichever thread executes the job. `None` when the topology
        /// has fewer than two domains.
        #[derive(Clone, Copy)]
        pub(crate) struct SpawnDomain(u16);

        /// Captures the calling thread's current domain (`None` disables pinning).
        pub(crate) fn spawn_domain() -> Option<SpawnDomain> {
            let topology = topology();
            (topology.domains() > 1).then(|| SpawnDomain(topology.current_domain()))
        }

        /// Pins the calling thread to a domain's CPU set for its lifetime, restoring the previous
        /// affinity mask on drop (including unwinds).
        pub(crate) struct AffinityGuard {
            saved: libc::cpu_set_t,
        }

        impl AffinityGuard {
            /// Pins the calling thread to the CPUs of `domain` that its current affinity mask
            /// already allows, so the pin narrows placement and never widens it past an operator's
            /// restrictions (taskset, numactl, isolated cores). Returns `None` (no pin) if the mask
            /// cannot be read or applied, or if the allowed intersection is empty; the job then
            /// simply runs
            /// wherever it was.
            pub(crate) fn pin(domain: Option<SpawnDomain>) -> Option<Self> {
                let domain = domain?;
                let topology = topology();
                let target = topology.domain_sets.get(domain.0 as usize)?;

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
                if allowed == 0 {
                    return None;
                }

                // SAFETY: pid 0 is the calling thread; `effective` is a valid set of `size`.
                if unsafe { libc::sched_setaffinity(0, size, &effective) } != 0 {
                    return None;
                }
                Some(Self { saved })
            }
        }

        impl Drop for AffinityGuard {
            fn drop(&mut self) {
                let size = std::mem::size_of::<libc::cpu_set_t>();

                // SAFETY: pid 0 is the calling thread; `saved` is the mask read at pin time.
                // Restoring wide does not migrate the thread, so a worker that served a caller
                // tends to stay in that caller's domain: repeat spawns pin without moving anyone.
                unsafe { libc::sched_setaffinity(0, size, &self.saved) };
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
                let d0 = topology.domain_of(0) as usize;
                for cpu in 0..4 {
                    // SAFETY: cpu < CPU_SETSIZE; the set was built by from_lists.
                    assert!(unsafe { libc::CPU_ISSET(cpu, &topology.domain_sets[d0]) });
                }

                // SAFETY: as above.
                assert!(!unsafe { libc::CPU_ISSET(4, &topology.domain_sets[d0]) });
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

                    let _guard = AffinityGuard::pin(spawn_domain());

                    // SAFETY: as above.
                    let mut now: libc::cpu_set_t = unsafe { std::mem::zeroed() };
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

                // SAFETY: as above.
                let mut after: libc::cpu_set_t = unsafe { std::mem::zeroed() };
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
        pub(crate) fn spawn_domain() -> Option<SpawnDomain> {
            None
        }

        /// No-op guard on platforms without affinity control.
        pub(crate) struct AffinityGuard;

        impl AffinityGuard {
            /// Never pins.
            pub(crate) fn pin(_domain: Option<SpawnDomain>) -> Option<Self> {
                None
            }
        }
    }
}
