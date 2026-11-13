//! CPU affinity of runtime-owned threads.
//!
//! Each native runner records the CPUs the thread calling [crate::Runner::start] may run on, its
//! base set. A pinned runtime thread writes its requested mask before anything else. Linux
//! threads inherit their creator's mask, so the first pin a runner applies arms a reset. From
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
    /// Set once a pinned thread of this runner applied its mask.
    #[cfg(all(target_os = "linux", not(miri)))]
    armed: AtomicBool,
}

impl AffinityState {
    /// Record the calling thread's allowed CPUs as the base set.
    // Const only where affinity is unavailable.
    #[allow(clippy::missing_const_for_fn)]
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

    /// Apply `pin` to the calling runtime-created thread if it is pinned, and arm the reset once
    /// it applied. Otherwise reset an inherited mask narrower than the base set once the reset is
    /// armed (best effort).
    ///
    /// A pinned thread arms the reset before it runs any task, so every thread it creates is
    /// created afterwards.
    pub(crate) fn enter(&self, pin: Option<&Cpus>) -> std::io::Result<()> {
        let Some(cpus) = pin else {
            self.reset_if_narrowed();
            return Ok(());
        };
        apply(cpus)?;
        #[cfg(all(target_os = "linux", not(miri)))]
        self.armed.store(true, Ordering::SeqCst);
        Ok(())
    }

    /// Write the base set if the reset is armed and the calling thread's mask is a strict
    /// subset of it. Keeps the inherited mask on failure.
    // Const only where affinity is unavailable.
    #[allow(clippy::missing_const_for_fn)]
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
    use super::{Cpus, current, write};
    use crate::{
        Error, Runner, Spawner, Supervisor as _, ThreadError, iouring, tokio,
        utils::{extract_panic_message, thread::tests::fail_spawns},
    };
    use futures::future::ready;
    use rstest::rstest;
    use std::{
        cell::RefCell,
        panic::{AssertUnwindSafe, catch_unwind},
        sync::{
            Arc,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
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
            match WRITE_FAILURES.compare_exchange(
                count,
                count - 1,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => return true,
                Err(current) => count = current,
            }
        }
        false
    }

    /// The calling thread's CPUs, if they include at least two.
    fn base() -> Option<Cpus> {
        current().filter(|cpus| cpus.len() >= 2)
    }

    /// Narrow the calling thread to `cpus` until the guard drops, then restore `base`.
    struct Narrowed(Cpus);

    impl Narrowed {
        fn new(cpus: impl Into<Cpus>, base: &Cpus) -> Self {
            write(&cpus.into()).expect("narrow the runner thread");
            Self(base.clone())
        }
    }

    impl Drop for Narrowed {
        fn drop(&mut self) {
            write(&self.0).expect("restore the runner thread");
        }
    }

    /// Observe the mask and masks inherited by runtime-created descendants.
    async fn masks<C: Spawner>(context: C) -> (Option<Cpus>, Option<Cpus>, Option<Cpus>) {
        let reported = current();
        let blocking = context
            .child("blocking")
            .blocking()
            .spawn(|_| async { current() })
            .await
            .unwrap();
        let unpinned = context
            .child("unpinned")
            .thread()
            .spawn(|_| ready(current()))
            .unwrap()
            .await
            .unwrap();
        (reported, blocking, unpinned)
    }

    /// Pins report the requested mask and arm descendant resets. Without a pin,
    /// descendants retain the narrowed mask inherited from their creator.
    #[rstest]
    #[case::tokio(tokio::Runner::default())]
    #[case::iouring(iouring::Runner::default())]
    fn test_affinity_masks<R: Runner>(#[case] runner: R, #[values(false, true)] pinned: bool)
    where
        R::Context: Spawner,
    {
        let Some(base) = base() else {
            return;
        };
        let mut ids = base.iter();
        let narrow = Cpus::from(ids.next().unwrap());
        let requested = Cpus::from(ids.collect::<Vec<_>>());
        let observed = runner.start(|context| {
            let (base, narrow, requested) = (base.clone(), narrow.clone(), requested.clone());
            async move {
                let _narrowed = Narrowed::new(narrow, &base);
                if pinned {
                    context
                        .child("pinned")
                        .thread()
                        .pin(requested)
                        .spawn(|local| masks(local.into_inner()))
                        .unwrap()
                        .await
                        .unwrap()
                } else {
                    masks(context).await
                }
            }
        });
        if pinned {
            assert_eq!(
                observed,
                (Some(requested), Some(base.clone()), Some(base)),
                "pin outside creator mask reports requested CPUs and resets descendants"
            );
        } else {
            assert_eq!(
                observed,
                (Some(narrow.clone()), Some(narrow.clone()), Some(narrow)),
                "an unpinned runner preserves inherited masks"
            );
        }
    }

    /// How a pinned thread fails before its mask applies.
    #[derive(Clone, Copy, Debug)]
    enum PinFailure {
        /// The OS refuses the thread, so the finisher returns `ThreadError::Spawn`.
        Spawn,
        /// The thread starts, but its mask write fails.
        Write,
    }

    /// A pinned thread that fails before its mask applies does not arm the reset. A later
    /// unpinned thread created while the runner thread is narrowed keeps the narrowed mask it
    /// inherits.
    #[rstest]
    #[case::tokio(tokio::Runner::new(tokio::Config::new().with_catch_panics(true)))]
    #[case::iouring(iouring::Runner::new(iouring::Config::new().with_catch_panics(true)))]
    fn test_affinity_failed_pin_does_not_arm_reset<R: Runner>(
        #[case] runner: R,
        #[values(PinFailure::Spawn, PinFailure::Write)] failure: PinFailure,
    ) where
        R::Context: Spawner,
    {
        let Some(base) = base() else {
            return;
        };
        let pin = base.iter().next().unwrap();
        let narrow = Cpus::from(pin);
        let unpinned = runner.start(|context| {
            let (narrow, base) = (narrow.clone(), base.clone());
            async move {
                match failure {
                    PinFailure::Spawn => {
                        // The failure is armed on this OS thread, which runs the finisher.
                        fail_spawns(1);
                        let built = context.child("pinned").thread().pin(pin).build();
                        assert!(matches!(built, Err(ThreadError::Spawn(_))));
                    }
                    PinFailure::Write => {
                        // Once a spawn toward the thread resolves, its startup failed.
                        fail_writes(1);
                        let thread = context.child("pinned").thread().pin(pin).build().unwrap();
                        let probe = context.child("probe").spawn_on(&thread, |_| ready(()));
                        assert!(matches!(probe.await, Err(Error::Closed)));
                    }
                }
                fail_spawns(0);
                fail_writes(0);
                let _narrowed = Narrowed::new(narrow, &base);
                context
                    .child("unpinned")
                    .thread()
                    .spawn(|_| ready(current()))
                    .unwrap()
                    .await
                    .unwrap()
            }
        });
        assert_eq!(unpinned, Some(narrow));
    }

    /// A mask write that fails on the new thread is a late startup failure. Spawns sent
    /// toward the thread resolve `Closed` without running, the failure reaches
    /// `Panicker::notify` (which fails the runner under `catch_panics(false)`), and
    /// under `catch_panics(true)` `start` returns.
    #[rstest]
    #[case::tokio(false, tokio::Runner::new(tokio::Config::new().with_catch_panics(false)))]
    #[case::tokio_catch(true, tokio::Runner::new(tokio::Config::new().with_catch_panics(true)))]
    #[case::iouring(false, iouring::Runner::new(iouring::Config::new().with_catch_panics(false)))]
    #[case::iouring_catch(true, iouring::Runner::new(iouring::Config::new().with_catch_panics(true)))]
    fn test_affinity_late_write_failure<R: Runner>(#[case] catch: bool, #[case] runner: R)
    where
        R::Context: Spawner,
    {
        let Some(base) = base() else {
            return;
        };
        let pin = base.iter().next().unwrap();
        let ran = Arc::new(AtomicBool::new(false));
        fail_writes(1);
        let result = catch_unwind(AssertUnwindSafe(|| {
            runner.start(|context| {
                let ran = ran.clone();
                async move {
                    let thread = context.child("pinned").thread().pin(pin).build().unwrap();
                    let handle = context.child("queued").spawn_on(&thread, move |_| {
                        ran.store(true, Ordering::SeqCst);
                        ready(())
                    });
                    assert!(
                        matches!(handle.await, Err(Error::Closed)),
                        "failed pin closes queued work"
                    );
                }
            })
        }));
        fail_writes(0);
        assert!(!ran.load(Ordering::SeqCst));
        if catch {
            result.expect("a caught startup failure failed the runner");
        } else {
            let panic = result.expect_err("the startup failure did not fail the runner");
            let message = extract_panic_message(&*panic);
            assert!(
                message.starts_with("failed to pin runtime thread to its CPUs"),
                "{message}"
            );
        }
    }
}
