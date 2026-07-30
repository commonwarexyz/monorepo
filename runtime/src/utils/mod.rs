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

/// Panic payload whose diagnostic was emitted before unwinding a task.
#[derive(Debug)]
struct ReportedPanic(&'static str);

/// Resumes unwinding without invoking the process panic hook again.
#[cfg(any(test, target_os = "linux", target_os = "macos"))]
pub(crate) fn resume_reported_panic(message: &'static str) -> ! {
    std::panic::resume_unwind(Box::new(ReportedPanic(message)))
}

/// Returns whether a panic payload has already been reported.
fn is_reported_panic(err: &(dyn Any + Send)) -> bool {
    err.is::<ReportedPanic>()
}

/// Extracts a stable message from an arbitrary panic payload.
pub(crate) fn extract_panic_message(err: &(dyn Any + Send)) -> String {
    match (
        err.downcast_ref::<&str>(),
        err.downcast_ref::<String>(),
        err.downcast_ref::<ReportedPanic>(),
    ) {
        (Some(message), _, _) => (*message).to_string(),
        (_, Some(message), _) => message.clone(),
        (_, _, Some(reported)) => reported.0.to_string(),
        _ => "non-string panic".to_string(),
    }
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
    use std::{
        panic::{AssertUnwindSafe, catch_unwind},
        sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    };

    #[test]
    fn panic_message_extraction_handles_supported_payloads() {
        let borrowed: Box<dyn Any + Send> = Box::new("borrowed panic");
        let owned: Box<dyn Any + Send> = Box::new("owned panic".to_string());
        let opaque: Box<dyn Any + Send> = Box::new(7_u64);
        let reported = catch_unwind(AssertUnwindSafe(|| {
            resume_reported_panic("reported panic");
        }))
        .expect_err("reported panic did not unwind");

        let messages = [
            extract_panic_message(&*borrowed),
            extract_panic_message(&*owned),
            extract_panic_message(&*opaque),
            extract_panic_message(&*reported),
        ];

        // Strings remain intact and opaque payloads use stable classifications.
        assert_eq!(
            messages,
            [
                "borrowed panic",
                "owned panic",
                "non-string panic",
                "reported panic"
            ]
        );
        assert!(!is_reported_panic(&*opaque));
        assert!(is_reported_panic(&*reported));
    }

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
