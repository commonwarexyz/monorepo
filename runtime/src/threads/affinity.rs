//! CPU affinity of runtime-owned threads.
//!
//! Each native runner records the CPUs the thread calling [crate::Runner::start] may run on, its
//! base set. A pinned runtime thread writes its requested mask before anything else. Linux
//! threads inherit their creator's mask, so the first pin a runner applies arms a reset: from
//! then on, every other runtime-created thread whose inherited mask is narrower than the base set
//! writes the base set at startup. A runner that never pins writes no mask.
//!
//! Affinity is only available on Linux outside miri. Elsewhere the base set is unknown, so every
//! pin fails validation and nothing is written.

use super::Cpus;
#[cfg(all(target_os = "linux", not(miri)))]
use std::sync::atomic::{AtomicBool, Ordering};

/// A runner's base set and whether its reset is armed.
pub(crate) struct AffinityState {
    /// CPUs the thread that started the runner may run on, if known.
    base: Option<Cpus>,
    /// Set once the runner creates its first pinned thread.
    #[cfg(all(target_os = "linux", not(miri)))]
    armed: AtomicBool,
}

impl AffinityState {
    /// Record the calling thread's allowed CPUs as the base set.
    pub(crate) fn capture() -> Self {
        Self {
            base: base_set(),
            #[cfg(all(target_os = "linux", not(miri)))]
            armed: AtomicBool::new(false),
        }
    }

    /// The base set, if known.
    pub(crate) const fn base(&self) -> Option<&Cpus> {
        self.base.as_ref()
    }

    /// Arm the reset before a pinned thread starts.
    pub(crate) fn arm(&self) {
        #[cfg(all(target_os = "linux", not(miri)))]
        self.armed.store(true, Ordering::SeqCst);
    }

    /// Set up the calling runtime-created thread: apply `pin` if it is pinned, or reset an
    /// inherited mask narrower than the base set once the reset is armed (best effort).
    pub(crate) fn enter(&self, pin: Option<&Cpus>) -> std::io::Result<()> {
        pin.map_or_else(
            || {
                self.reset_if_narrowed();
                Ok(())
            },
            apply,
        )
    }

    /// Write the base set if the reset is armed and the calling thread's mask is a strict
    /// subset of it. Keeps the inherited mask on failure.
    pub(crate) fn reset_if_narrowed(&self) {
        cfg_if::cfg_if! {
            if #[cfg(all(target_os = "linux", not(miri)))] {
                if !self.armed.load(Ordering::SeqCst) {
                    return;
                }
                let Some(base) = &self.base else {
                    return;
                };
                let Some(current) = current() else {
                    return;
                };
                if current != *base && current.iter().all(|id| base.contains(id)) {
                    let _ = write(base);
                }
            }
        }
    }
}

cfg_if::cfg_if! {
    if #[cfg(all(target_os = "linux", not(miri)))] {
        /// Byte size of `cpu_set_t`, as passed to the affinity syscalls.
        const CPU_SET_BYTES: usize = std::mem::size_of::<libc::cpu_set_t>();

        /// Number of CPUs a `cpu_set_t` can represent.
        const CPU_SETSIZE: usize = libc::CPU_SETSIZE as usize;

        /// The calling thread's allowed CPUs, or `None` when the kernel refuses the query.
        pub(crate) fn current() -> Option<Cpus> {
            // SAFETY: an all-zero cpu_set_t is the valid empty set.
            let mut set: libc::cpu_set_t = unsafe { std::mem::zeroed() };

            // SAFETY: pid 0 is the calling thread, and the set is a valid cpu_set_t of
            // `CPU_SET_BYTES` bytes.
            if unsafe { libc::sched_getaffinity(0, CPU_SET_BYTES, &mut set) } != 0 {
                return None;
            }
            let ids: Vec<usize> = (0..CPU_SETSIZE)
                // SAFETY: each id is below CPU_SETSIZE and the set is valid.
                .filter(|&id| unsafe { libc::CPU_ISSET(id, &set) })
                .collect();
            Some(Cpus::from(ids))
        }

        /// Write `cpus`, whose ids are all below `CPU_SETSIZE`, as the calling thread's mask.
        fn write(cpus: &Cpus) -> std::io::Result<()> {
            // SAFETY: an all-zero cpu_set_t is the valid empty set.
            let mut set: libc::cpu_set_t = unsafe { std::mem::zeroed() };
            for id in cpus.iter().filter(|&id| id < CPU_SETSIZE) {
                // SAFETY: id is below CPU_SETSIZE (filtered above) and the set is valid.
                unsafe { libc::CPU_SET(id, &mut set) };
            }

            // SAFETY: pid 0 is the calling thread, and the set is a valid cpu_set_t of
            // `CPU_SET_BYTES` bytes.
            if unsafe { libc::sched_setaffinity(0, CPU_SET_BYTES, &set) } != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        }

        /// The calling thread's allowed CPUs, recorded as a runner's base set.
        pub(crate) fn base_set() -> Option<Cpus> {
            #[cfg(test)]
            if let Some(base) = tests::BASE_OVERRIDE.with(|base| base.borrow().clone()) {
                return base;
            }
            current()
        }

        /// Pin the calling thread to `cpus`.
        pub(crate) fn apply(cpus: &Cpus) -> std::io::Result<()> {
            #[cfg(test)]
            if tests::take_write_failure() {
                return Err(std::io::Error::other("injected affinity write failure"));
            }
            write(cpus)
        }
    } else {
        /// The base set is unknown where affinity is unavailable.
        pub(crate) const fn base_set() -> Option<Cpus> {
            None
        }

        /// Nothing can be pinned where affinity is unavailable, and validation rejects every pin
        /// before a thread could get here.
        pub(crate) fn apply(_cpus: &Cpus) -> std::io::Result<()> {
            Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
        }
    }
}

#[cfg(all(test, target_os = "linux", not(miri)))]
pub(crate) mod tests {
    use super::Cpus;
    use std::{
        cell::RefCell,
        sync::atomic::{AtomicUsize, Ordering},
    };

    thread_local! {
        /// The base set the next runners started on this thread record, if overridden.
        pub(super) static BASE_OVERRIDE: RefCell<Option<Option<Cpus>>> = const { RefCell::new(None) };
    }

    /// Mask writes of pinned threads that fail before reaching the kernel. nextest runs every
    /// test in its own process, so one count serves the process.
    static WRITE_FAILURES: AtomicUsize = AtomicUsize::new(0);

    /// Make runners started on this thread record `base` (`None` for an unknown base set), or
    /// with `None`, read the real one again.
    pub(crate) fn override_base(base: Option<Option<Cpus>>) {
        BASE_OVERRIDE.with(|slot| *slot.borrow_mut() = base);
    }

    /// Make the next `count` pins written by new threads fail.
    pub(crate) fn fail_writes(count: usize) {
        WRITE_FAILURES.store(count, Ordering::SeqCst);
    }

    /// Consume one armed failure, if any.
    pub(super) fn take_write_failure() -> bool {
        let mut count = WRITE_FAILURES.load(Ordering::SeqCst);
        while count > 0 {
            match WRITE_FAILURES.compare_exchange(count, count - 1, Ordering::SeqCst, Ordering::SeqCst)
            {
                Ok(_) => return true,
                Err(current) => count = current,
            }
        }
        false
    }
}
