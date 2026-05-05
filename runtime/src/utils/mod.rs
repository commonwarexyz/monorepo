//! Utility functions for interacting with any runtime.

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
pub mod signal;
#[cfg(not(target_arch = "wasm32"))]
pub(crate) mod thread;

mod handle;
pub use handle::Handle;
#[commonware_macros::stability(ALPHA)]
pub(crate) use handle::Panicked;
pub(crate) use handle::{Aborter, MetricHandle, Panicker};

mod cell;
pub use cell::Cell as ContextCell;

#[cfg(feature = "test-utils")]
pub mod test_utils {
    fn matches_metric_name(full: &str, name: &str) -> bool {
        full == name
            || full
                .strip_suffix(name)
                .is_some_and(|prefix| prefix.ends_with('_'))
    }

    /// Return `true` if encoded Prometheus metrics contain a sample with `name` and `value`.
    ///
    /// `name` may be either the full encoded metric name or its unprefixed suffix.
    /// Labels attached to the sample are ignored.
    #[must_use]
    pub fn has_metric_value(metrics: &str, name: &str, value: impl std::fmt::Display) -> bool {
        let value = value.to_string();
        metrics.lines().any(|line| {
            let line = line.trim();
            if line.starts_with('#') {
                return false;
            }

            let Some(sample_end) = line.find(|c: char| c == '{' || c.is_whitespace()) else {
                return false;
            };
            let sample_name = &line[..sample_end];
            if !matches_metric_name(sample_name, name) {
                return false;
            }

            let mut rest = &line[sample_end..];
            if let Some(labeled) = rest.strip_prefix('{') {
                let Some(labels_end) = labeled.find('}') else {
                    return false;
                };
                rest = &labeled[labels_end + 1..];
            }
            if !rest.chars().next().is_some_and(char::is_whitespace) {
                return false;
            }

            rest.split_whitespace().next() == Some(value.as_str())
        })
    }

    #[cfg(test)]
    mod tests {
        use super::has_metric_value;

        #[test]
        fn test_has_metric_value_unlabeled() {
            let metrics = "# HELP storage_items_tracked items\nstorage_items_tracked 2\n";
            assert!(has_metric_value(metrics, "items_tracked", 2));
            assert!(has_metric_value(metrics, "storage_items_tracked", 2));
            assert!(!has_metric_value(metrics, "items_tracked_extra", 2));
            assert!(!has_metric_value(metrics, "items_tracked", 3));
        }

        #[test]
        fn test_has_metric_value_labeled() {
            let metrics = r#"storage_init_items_tracked{index="2"} 2"#;
            assert!(has_metric_value(metrics, "items_tracked", 2));
            assert!(has_metric_value(metrics, "storage_init_items_tracked", 2));
        }
    }
}

pub(crate) mod supervision;

/// The execution mode of a task.
#[derive(Copy, Clone, Debug)]
pub enum Execution {
    /// Task runs on a dedicated thread.
    Dedicated,
    /// Task runs on the shared executor. `true` marks short blocking work that should
    /// use the runtime's blocking-friendly pool.
    Shared(bool),
}

impl Default for Execution {
    fn default() -> Self {
        Self::Shared(false)
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
