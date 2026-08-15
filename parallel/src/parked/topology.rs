//! Last-level-cache topology for affinity-aware wake ordering.
//!
//! Threads that exchange cache lines pay far more when they sit in different last-level
//! cache (L3) domains: on multi-CCD parts a cross-domain transfer costs several times a
//! shared-domain one, and the scheduler's thread placement is effectively a sticky
//! per-process lottery. Knowing which domain a thread currently occupies lets the pool
//! prefer waking a worker that shares the submitting caller's domain (see
//! [`super::pool::Shared::wake`]), which is purely an ordering preference: correctness
//! never depends on it.
//!
//! Domains come from the kernel's cache topology (never from vendor core-layout
//! assumptions, which lie: this was built on a machine whose spec sheet implied 8-core L3
//! groups while the kernel reported 4-core ones). On non-Linux platforms the stub below
//! reports a single domain and the preference degenerates to the unordered behavior; the
//! same stub serves loom (a sysfs read per explored interleaving would dominate model
//! time) and miri (the getcpu syscall is unshimmed).

cfg_if::cfg_if! {
    if #[cfg(all(target_os = "linux", not(feature = "loom"), not(miri)))] {
        /// Map from CPU id to last-level-cache domain id.
        pub(super) struct Topology {
            /// `cpu_to_domain[cpu]` is the domain of `cpu`; CPUs beyond the table
            /// (offline or hot-added) map to domain 0.
            cpu_to_domain: Box<[u16]>,
            /// Number of distinct domains (1 when detection is unavailable).
            domains: usize,
        }

        impl Topology {
            /// Detects the LLC topology, falling back to a single domain.
            pub(super) fn detect() -> Self {
                Self::from_sysfs().unwrap_or(Self {
                    cpu_to_domain: Box::new([]),
                    domains: 1,
                })
            }

            /// Number of distinct domains.
            pub(super) fn domains(&self) -> usize {
                self.domains
            }

            /// The domain of `cpu`.
            fn domain_of(&self, cpu: usize) -> u16 {
                self.cpu_to_domain.get(cpu).copied().unwrap_or(0)
            }

            /// The domain of the CPU the calling thread is currently running on.
            /// Advisory: the thread may migrate immediately after; callers use this only
            /// as a wake-ordering preference.
            pub(super) fn current_domain(&self) -> u16 {
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

            /// Builds the table from `(cpu, shared_cpu_list)` pairs; each distinct list
            /// string is one domain. Separated from sysfs reading for testability.
            fn from_lists(lists: &[(usize, String)]) -> Option<Self> {
                if lists.is_empty() {
                    return None;
                }
                let max_cpu = lists.iter().map(|(cpu, _)| *cpu).max()?;
                let mut table = vec![0u16; max_cpu + 1];
                let mut domains: Vec<&str> = Vec::new();
                for (cpu, list) in lists {
                    let list = list.as_str();
                    let domain = match domains.iter().position(|&d| d == list) {
                        Some(i) => i,
                        None => {
                            domains.push(list);
                            domains.len() - 1
                        }
                    };
                    table[*cpu] = u16::try_from(domain).ok()?;
                }
                if domains.len() <= 1 {
                    return None;
                }
                Some(Self {
                    cpu_to_domain: table.into_boxed_slice(),
                    domains: domains.len(),
                })
            }
        }

        #[cfg(test)]
        mod tests {
            use super::*;

            #[test]
            fn from_lists_groups_by_shared_list() {
                let lists: Vec<(usize, String)> = (0..8)
                    .map(|cpu| {
                        let list = if cpu < 4 { "0-3" } else { "4-7" };
                        (cpu, list.to_string())
                    })
                    .collect();
                let topology = Topology::from_lists(&lists).unwrap();
                assert_eq!(topology.domains(), 2);
                for cpu in 0..4 {
                    assert_eq!(topology.domain_of(cpu), topology.domain_of(0));
                }
                for cpu in 4..8 {
                    assert_eq!(topology.domain_of(cpu), topology.domain_of(4));
                }
                assert_ne!(topology.domain_of(0), topology.domain_of(4));
                // Out-of-table CPUs map to domain 0.
                assert_eq!(topology.domain_of(64), 0);
            }

            #[test]
            fn from_lists_single_domain_is_none() {
                let lists: Vec<(usize, String)> =
                    (0..4).map(|cpu| (cpu, "0-3".to_string())).collect();
                assert!(Topology::from_lists(&lists).is_none());
            }

            #[test]
            fn from_lists_empty_is_none() {
                assert!(Topology::from_lists(&[]).is_none());
            }

            #[test]
            fn detect_never_panics_and_current_domain_in_range() {
                let topology = Topology::detect();
                let domain = topology.current_domain() as usize;
                assert!(domain < topology.domains().max(1));
            }
        }
    } else {
        /// Single-domain stub: every thread reports domain 0 and the wake preference
        /// compiles down to the plain unordered scan.
        pub(super) struct Topology;

        impl Topology {
            /// See the Linux implementation; here detection is unavailable.
            pub(super) fn detect() -> Self {
                Self
            }

            /// Always 1: a single domain.
            pub(super) fn domains(&self) -> usize {
                1
            }

            /// Always domain 0.
            pub(super) fn current_domain(&self) -> u16 {
                0
            }
        }
    }
}
