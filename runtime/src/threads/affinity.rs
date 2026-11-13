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

    /// Arm the reset once a pinned thread applied its mask.
    fn arm(&self) {
        #[cfg(all(target_os = "linux", not(miri)))]
        self.armed.store(true, Ordering::SeqCst);
    }

    /// Apply `pin` to the calling runtime-created thread if it is pinned, and arm the reset once
    /// it applied. Otherwise reset an inherited mask narrower than the base set once the reset is
    /// armed (best effort).
    ///
    /// A pinned thread arms the reset before it runs any task, so every thread it creates is
    /// created afterwards.
    pub(crate) fn enter(&self, pin: Option<&Cpus>) -> std::io::Result<()> {
        pin.map_or_else(
            || {
                self.reset_if_narrowed();
                Ok(())
            },
            |cpus| {
                apply(cpus)?;
                self.arm();
                Ok(())
            },
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
    use super::{Cpus, current, write};
    use crate::{
        Error, Runner, Spawner, Supervisor as _, ThreadError, iouring, tokio,
        utils::extract_panic_message,
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

    /// A pinned thread runs on exactly the CPUs it requested.
    #[rstest]
    #[case::tokio(tokio::Runner::default())]
    #[case::iouring(iouring::Runner::default())]
    fn test_affinity_pinned_thread_reports_requested<R: Runner>(#[case] runner: R)
    where
        R::Context: Spawner,
    {
        let Some(base) = base() else {
            return;
        };
        let requested = Cpus::from(base.iter().skip(1).collect::<Vec<_>>());
        let reported = runner.start(|context| {
            let requested = requested.clone();
            async move {
                context
                    .child("pinned")
                    .thread()
                    .pin(requested)
                    .spawn(|_| ready(current()))
                    .unwrap()
                    .await
                    .unwrap()
            }
        });
        assert_eq!(reported, Some(requested));
    }

    /// Once a pin armed the reset, threads the runtime creates from a pinned thread write
    /// the base set: a blocking task's thread (an io_uring blocking worker on io_uring) and
    /// an unpinned runtime thread.
    #[rstest]
    #[case::tokio(tokio::Runner::default())]
    #[case::iouring(iouring::Runner::default())]
    fn test_affinity_reset_after_pin<R: Runner>(#[case] runner: R)
    where
        R::Context: Spawner,
    {
        let Some(base) = base() else {
            return;
        };
        let pin = base.iter().next().unwrap();
        let (blocking, unpinned) = runner.start(|context| async move {
            context
                .child("pinned")
                .thread()
                .pin(pin)
                .spawn(move |local| async move {
                    assert_eq!(current(), Some(Cpus::from(pin)));
                    let blocking = local
                        .child("blocking")
                        .into_inner()
                        .shared(true)
                        .spawn(|_| async { current() })
                        .await
                        .unwrap();
                    let unpinned = local
                        .child("unpinned")
                        .into_inner()
                        .thread()
                        .spawn(|_| ready(current()))
                        .unwrap()
                        .await
                        .unwrap();
                    (blocking, unpinned)
                })
                .unwrap()
                .await
                .unwrap()
        });
        assert_eq!(blocking.as_ref(), Some(&base));
        assert_eq!(unpinned.as_ref(), Some(&base));
    }

    /// A runner that never pins writes no mask. Threads created while the runner thread is
    /// narrowed keep the narrowed mask they inherit.
    #[rstest]
    #[case::tokio(tokio::Runner::default())]
    #[case::iouring(iouring::Runner::default())]
    fn test_affinity_unpinned_runner_writes_no_mask<R: Runner>(#[case] runner: R)
    where
        R::Context: Spawner,
    {
        let Some(base) = base() else {
            return;
        };
        let narrow = Cpus::from(base.iter().next().unwrap());
        let (blocking, unpinned) = runner.start(|context| {
            let (narrow, base) = (narrow.clone(), base.clone());
            async move {
                let _narrowed = Narrowed::new(narrow, &base);
                let blocking = context
                    .child("blocking")
                    .shared(true)
                    .spawn(|_| async { current() });
                let unpinned = context
                    .child("unpinned")
                    .thread()
                    .spawn(|_| ready(current()))
                    .unwrap();
                (blocking.await.unwrap(), unpinned.await.unwrap())
            }
        });
        assert_eq!(blocking, Some(narrow.clone()));
        assert_eq!(unpinned, Some(narrow));
    }

    /// A pin may name a CPU of the base set that the creating thread may not run on.
    #[rstest]
    #[case::tokio(tokio::Runner::default())]
    #[case::iouring(iouring::Runner::default())]
    fn test_affinity_pin_outside_creator_mask<R: Runner>(#[case] runner: R)
    where
        R::Context: Spawner,
    {
        let Some(base) = base() else {
            return;
        };
        let mut ids = base.iter();
        let (narrow, pin) = (ids.next().unwrap(), ids.next().unwrap());
        let reported = runner.start(|context| {
            let base = base.clone();
            async move {
                let _narrowed = Narrowed::new(narrow, &base);
                context
                    .child("pinned")
                    .thread()
                    .pin(pin)
                    .spawn(|_| ready(current()))
                    .unwrap()
                    .await
                    .unwrap()
            }
        });
        assert_eq!(reported, Some(Cpus::from(pin)));
    }

    /// Every finisher rejects a pin when the base set is unknown.
    #[rstest]
    #[case::tokio(tokio::Runner::default())]
    #[case::iouring(iouring::Runner::default())]
    fn test_affinity_unknown_base_set_is_unsupported<R: Runner>(#[case] runner: R)
    where
        R::Context: Spawner,
    {
        override_base(Some(None));
        runner.start(|context| async move {
            let built = context.child("built").thread().pin(0).build();
            assert!(matches!(built, Err(ThreadError::UnsupportedAffinity)));
            let attached = context.child("attached").thread().pin(0).attach();
            assert!(matches!(attached, Err(ThreadError::UnsupportedAffinity)));
            let spawned = context
                .child("spawned")
                .thread()
                .pin(0)
                .spawn(|_| ready(()));
            assert!(matches!(spawned, Err(ThreadError::UnsupportedAffinity)));

            // An unpinned thread needs no base set.
            context
                .child("unpinned")
                .thread()
                .spawn(|_| ready(()))
                .unwrap()
                .await
                .unwrap();
        });
        override_base(None);
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
        /// Spawns sent toward the failing thread.
        const SPAWNS: usize = 16;
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
                    let handles: Vec<_> = (0..SPAWNS)
                        .map(|_| {
                            let ran = ran.clone();
                            context.child("queued").spawn_on(&thread, move |_| {
                                ran.store(true, Ordering::SeqCst);
                                ready(())
                            })
                        })
                        .collect();
                    for handle in handles {
                        assert!(matches!(handle.await, Err(Error::Closed)));
                    }
                }
            })
        }));
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
