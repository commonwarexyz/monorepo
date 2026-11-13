//! Utility functions for interacting with any runtime.

use crate::Thread;
use commonware_utils::sync::{Condvar, Mutex};
use futures::task::ArcWake;
use std::{
    any::Any,
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

commonware_macros::stability_mod!(BETA, pub mod buffer);
pub(crate) mod abort;
pub mod signal;
#[cfg(not(target_arch = "wasm32"))]
pub(crate) mod thread;

mod handle;
#[commonware_macros::stability(ALPHA)]
pub(crate) use handle::Panicked;
pub use handle::{AbortOnDrop, Handle};
pub(crate) use handle::{Aborter, FactoryGuard, MetricHandle, Panicker, Prepared};

mod cell;
pub use cell::Cell as ContextCell;

pub(crate) mod supervision;

/// Where a spawned task runs, as its task metric reports it.
#[derive(Copy, Clone, Debug)]
pub(crate) enum Execution {
    /// Task runs on the shared executor. `true` marks short blocking work that should
    /// use the runtime's blocking-friendly pool.
    Shared(bool),
    /// Task runs on a runtime thread.
    Thread,
}

/// Where a context line's spawns run.
#[derive(Clone, Debug, Default)]
pub(crate) enum Placement {
    /// The runtime's shared executor.
    #[default]
    Shared,
    /// The runtime's blocking pool, which gives each task a thread of its own.
    Blocking,
    /// A runtime thread.
    Thread(Thread),
}

/// The placement a context carries.
///
/// A spawn hands its task a parked context. It remembers where the task runs, but its spawns
/// run on the shared executor until [`crate::Spawner::placed`] unparks it or an explicit
/// placement replaces what it remembers.
#[derive(Clone, Debug, Default)]
pub(crate) struct Place {
    /// The explicit placement, or where the context's task runs while parked.
    placement: Placement,
    /// Whether spawns run on the shared executor instead of at `placement`.
    parked: bool,
}

impl Place {
    /// The context handed to a task that runs at `placement`.
    pub(crate) const fn parked(placement: Placement) -> Self {
        Self {
            placement,
            parked: true,
        }
    }

    /// Place the context explicitly, replacing what it remembers.
    pub(crate) fn set(&mut self, placement: Placement) {
        self.placement = placement;
        self.parked = false;
    }

    /// Spawn at the remembered placement: where the context's task runs if it is parked.
    pub(crate) const fn unpark(&mut self) {
        self.parked = false;
    }

    /// The runtime thread the next spawn runs on, if any.
    pub(crate) const fn thread(&self) -> Option<&Thread> {
        match (&self.placement, self.parked) {
            (Placement::Thread(thread), false) => Some(thread),
            _ => None,
        }
    }

    /// Whether the next spawn runs on the blocking pool.
    pub(crate) const fn blocking(&self) -> bool {
        matches!((&self.placement, self.parked), (Placement::Blocking, false))
    }

    /// Where the next spawn runs, as its task metric reports it.
    pub(crate) const fn execution(&self) -> Execution {
        if self.thread().is_some() {
            Execution::Thread
        } else {
            Execution::Shared(self.blocking())
        }
    }

    /// The context handed to a task spawned from this one: parked where the task runs.
    pub(crate) fn handoff(&self) -> Self {
        let placement = if self.parked {
            Placement::Shared
        } else {
            self.placement.clone()
        };
        Self::parked(placement)
    }
}

/// Yield control back to the runtime.
pub async fn reschedule() {
    struct Reschedule {
        yielded: bool,
    }

    impl Future for Reschedule {
        type Output = ();

        fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
            if self.yielded {
                Poll::Ready(())
            } else {
                self.yielded = true;
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }
    }

    Reschedule { yielded: false }.await
}

pub(crate) fn extract_panic_message(err: &(dyn Any + Send)) -> String {
    err.downcast_ref::<&str>().map_or_else(
        || {
            err.downcast_ref::<String>()
                .map_or_else(|| format!("{err:?}"), |s| s.clone())
        },
        |s| s.to_string(),
    )
}

/// Synchronization primitive that enables a thread to block until a waker delivers a signal.
pub struct Blocker {
    /// Tracks whether a wake-up signal has been delivered (even if wait has not started yet).
    state: Mutex<bool>,
    /// Condvar used to park and resume the thread when the signal flips to true.
    cv: Condvar,
}

impl Blocker {
    /// Create a new [Blocker].
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(false),
            cv: Condvar::new(),
        })
    }

    /// Block the current thread until a waker delivers a signal.
    pub fn wait(&self) {
        // Use a loop to tolerate spurious wake-ups and only proceed once a real signal arrives.
        let mut signaled = self.state.lock();
        while !*signaled {
            self.cv.wait(&mut signaled);
        }

        // Reset the flag so subsequent waits park again until the next wake signal.
        *signaled = false;
    }
}

impl ArcWake for Blocker {
    fn wake_by_ref(arc_self: &Arc<Self>) {
        // Mark as signaled (and release lock before notifying).
        {
            let mut signaled = arc_self.state.lock();
            *signaled = true;
        }

        // Notify a single waiter so the blocked thread re-checks the flag.
        arc_self.cv.notify_one();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::task::waker;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    #[test]
    fn test_blocker_waits_until_wake() {
        let blocker = Blocker::new();
        let started = Arc::new(AtomicBool::new(false));
        let completed = Arc::new(AtomicBool::new(false));

        let thread_blocker = blocker.clone();
        let thread_started = started.clone();
        let thread_completed = completed.clone();
        let handle = std::thread::spawn(move || {
            thread_started.store(true, Ordering::SeqCst);
            thread_blocker.wait();
            thread_completed.store(true, Ordering::SeqCst);
        });

        while !started.load(Ordering::SeqCst) {
            std::thread::yield_now();
        }

        assert!(!completed.load(Ordering::SeqCst));
        waker(blocker).wake();
        handle.join().unwrap();
        assert!(completed.load(Ordering::SeqCst));
    }

    #[test]
    fn test_blocker_handles_pre_wake() {
        let blocker = Blocker::new();
        waker(blocker.clone()).wake();

        let completed = Arc::new(AtomicBool::new(false));
        let thread_blocker = blocker;
        let thread_completed = completed.clone();
        std::thread::spawn(move || {
            thread_blocker.wait();
            thread_completed.store(true, Ordering::SeqCst);
        })
        .join()
        .unwrap();

        assert!(completed.load(Ordering::SeqCst));
    }

    #[test]
    fn test_blocker_reusable_across_signals() {
        let blocker = Blocker::new();
        let completed = Arc::new(AtomicUsize::new(0));

        let thread_blocker = blocker.clone();
        let thread_completed = completed.clone();
        let handle = std::thread::spawn(move || {
            for _ in 0..2 {
                thread_blocker.wait();
                thread_completed.fetch_add(1, Ordering::SeqCst);
            }
        });

        for expected in 1..=2 {
            waker(blocker.clone()).wake();
            while completed.load(Ordering::SeqCst) < expected {
                std::thread::yield_now();
            }
        }

        handle.join().unwrap();
        assert_eq!(completed.load(Ordering::SeqCst), 2);
    }
}
