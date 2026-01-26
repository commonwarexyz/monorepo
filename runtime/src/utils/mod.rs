//! Utility functions for interacting with any runtime.

use commonware_macros::ready_mod;
use futures::task::ArcWake;
use std::{
    any::Any,
    collections::HashSet,
    future::Future,
    pin::Pin,
    sync::{Arc, Condvar, Mutex},
    task::{Context, Poll},
};

ready_mod!(GAMMA, pub mod buffer);
pub mod signal;

mod handle;
pub use handle::Handle;
pub(crate) use handle::{Aborter, MetricHandle, Panicked, Panicker};

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

fn extract_panic_message(err: &(dyn Any + Send)) -> String {
    err.downcast_ref::<&str>().map_or_else(
        || {
            err.downcast_ref::<String>()
                .map_or_else(|| format!("{err:?}"), |s| s.clone())
        },
        |s| s.to_string(),
    )
}

/// Async reader–writer lock.
///
/// Powered by [async_lock::RwLock], `RwLock` provides both fair writer acquisition
/// and `try_read` / `try_write` without waiting (without any runtime-specific dependencies).
///
/// Usage:
/// ```rust
/// use commonware_runtime::{Spawner, Runner, deterministic, RwLock};
///
/// let executor = deterministic::Runner::default();
/// executor.start(|context| async move {
///     // Create a new RwLock
///     let lock = RwLock::new(2);
///
///     // many concurrent readers
///     let r1 = lock.read().await;
///     let r2 = lock.read().await;
///     assert_eq!(*r1 + *r2, 4);
///
///     // exclusive writer
///     drop((r1, r2));
///     let mut w = lock.write().await;
///     *w += 1;
/// });
/// ```
pub struct RwLock<T>(async_lock::RwLock<T>);

/// Shared guard returned by [RwLock::read].
pub type RwLockReadGuard<'a, T> = async_lock::RwLockReadGuard<'a, T>;

/// Exclusive guard returned by [RwLock::write].
pub type RwLockWriteGuard<'a, T> = async_lock::RwLockWriteGuard<'a, T>;

impl<T> RwLock<T> {
    /// Create a new lock.
    #[inline]
    pub const fn new(value: T) -> Self {
        Self(async_lock::RwLock::new(value))
    }

    /// Acquire a shared read guard.
    #[inline]
    pub async fn read(&self) -> RwLockReadGuard<'_, T> {
        self.0.read().await
    }

    /// Acquire an exclusive write guard.
    #[inline]
    pub async fn write(&self) -> RwLockWriteGuard<'_, T> {
        self.0.write().await
    }

    /// Try to get a read guard without waiting.
    #[inline]
    pub fn try_read(&self) -> Option<RwLockReadGuard<'_, T>> {
        self.0.try_read()
    }

    /// Try to get a write guard without waiting.
    #[inline]
    pub fn try_write(&self) -> Option<RwLockWriteGuard<'_, T>> {
        self.0.try_write()
    }

    /// Get mutable access without locking (requires `&mut self`).
    #[inline]
    pub fn get_mut(&mut self) -> &mut T {
        self.0.get_mut()
    }

    /// Consume the lock, returning the inner value.
    #[inline]
    pub fn into_inner(self) -> T {
        self.0.into_inner()
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
        let mut signaled = self.state.lock().unwrap();
        while !*signaled {
            signaled = self.cv.wait(signaled).unwrap();
        }

        // Reset the flag so subsequent waits park again until the next wake signal.
        *signaled = false;
    }
}

impl ArcWake for Blocker {
    fn wake_by_ref(arc_self: &Arc<Self>) {
        // Mark as signaled (and release lock before notifying).
        {
            let mut signaled = arc_self.state.lock().unwrap();
            *signaled = true;
        }

        // Notify a single waiter so the blocked thread re-checks the flag.
        arc_self.cv.notify_one();
    }
}

#[cfg(any(test, feature = "test-utils"))]
/// Count the number of running tasks whose name starts with the given prefix.
///
/// This function encodes metrics and counts tasks that are currently running
/// (have a value of 1) and whose name starts with the specified prefix.
///
/// This is useful for verifying that all child tasks under a given label hierarchy
/// have been properly shut down.
///
/// # Example
///
/// ```rust
/// use commonware_runtime::{Clock, Metrics, Runner, Spawner, deterministic};
/// use commonware_runtime::utils::count_running_tasks;
/// use std::time::Duration;
///
/// let executor = deterministic::Runner::default();
/// executor.start(|context| async move {
///     // Spawn a task under a labeled context
///     let handle = context.with_label("worker").spawn(|ctx| async move {
///         ctx.sleep(Duration::from_secs(100)).await;
///     });
///
///     // Allow the task to start
///     context.sleep(Duration::from_millis(10)).await;
///
///     // Count running tasks with "worker" prefix
///     let count = count_running_tasks(&context, "worker");
///     assert!(count > 0, "worker task should be running");
///
///     // Abort the task
///     handle.abort();
///     let _ = handle.await;
///     context.sleep(Duration::from_millis(10)).await;
///
///     // Verify task is stopped
///     let count = count_running_tasks(&context, "worker");
///     assert_eq!(count, 0, "worker task should be stopped");
/// });
/// ```
pub fn count_running_tasks(metrics: &impl crate::Metrics, prefix: &str) -> usize {
    let encoded = metrics.encode();
    encoded
        .lines()
        .filter(|line| {
            line.starts_with("runtime_tasks_running{")
                && line.contains("kind=\"Task\"")
                && line.trim_end().ends_with(" 1")
                && line
                    .split("name=\"")
                    .nth(1)
                    .is_some_and(|s| s.split('"').next().unwrap_or("").starts_with(prefix))
        })
        .count()
}

/// Validates that a label matches Prometheus metric name format: `[a-zA-Z][a-zA-Z0-9_]*`.
///
/// # Panics
///
/// Panics if the label is empty, starts with a non-alphabetic character,
/// or contains characters other than `[a-zA-Z0-9_]`.
pub fn validate_label(label: &str) {
    let mut chars = label.chars();
    assert!(
        chars.next().is_some_and(|c| c.is_ascii_alphabetic()),
        "label must start with [a-zA-Z]: {label}"
    );
    assert!(
        chars.all(|c| c.is_ascii_alphanumeric() || c == '_'),
        "label must only contain [a-zA-Z0-9_]: {label}"
    );
}

/// Add an attribute to a sorted attribute list, maintaining sorted order via binary search.
///
/// Returns `true` if the key was new, `false` if it was a duplicate (value overwritten).
pub fn add_attribute(
    attributes: &mut Vec<(String, String)>,
    key: &str,
    value: impl std::fmt::Display,
) -> bool {
    let key_string = key.to_string();
    let value_string = value.to_string();

    match attributes.binary_search_by(|(k, _)| k.cmp(&key_string)) {
        Ok(pos) => {
            attributes[pos].1 = value_string;
            false
        }
        Err(pos) => {
            attributes.insert(pos, (key_string, value_string));
            true
        }
    }
}

/// A writer that deduplicates HELP and TYPE metadata lines during Prometheus encoding.
///
/// When the same metric is registered multiple times with different attribute values
/// (via `sub_registry_with_label`), prometheus_client outputs duplicate HELP/TYPE
/// lines. This writer filters them in a single pass to produce canonical Prometheus format.
///
/// Uses "first wins" semantics: keeps the first HELP/TYPE description encountered
/// for each metric name and discards subsequent duplicates.
pub struct MetricEncoder {
    output: String,
    line_buffer: String,
    seen_help: HashSet<String>,
    seen_type: HashSet<String>,
}

impl MetricEncoder {
    pub fn new() -> Self {
        Self {
            output: String::new(),
            line_buffer: String::new(),
            seen_help: HashSet::new(),
            seen_type: HashSet::new(),
        }
    }

    pub fn into_string(mut self) -> String {
        if !self.line_buffer.is_empty() {
            self.flush_line();
        }
        self.output
    }

    fn flush_line(&mut self) {
        let line = &self.line_buffer;
        let should_write = if let Some(rest) = line.strip_prefix("# HELP ") {
            let metric_name = rest.split_whitespace().next().unwrap_or("");
            self.seen_help.insert(metric_name.to_string())
        } else if let Some(rest) = line.strip_prefix("# TYPE ") {
            let metric_name = rest.split_whitespace().next().unwrap_or("");
            self.seen_type.insert(metric_name.to_string())
        } else {
            true
        };
        if should_write {
            self.output.push_str(line);
            self.output.push('\n');
        }
        self.line_buffer.clear();
    }
}

impl Default for MetricEncoder {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Write for MetricEncoder {
    fn write_str(&mut self, s: &str) -> std::fmt::Result {
        let mut remaining = s;
        while let Some(pos) = remaining.find('\n') {
            self.line_buffer.push_str(&remaining[..pos]);
            self.flush_line();
            remaining = &remaining[pos + 1..];
        }
        self.line_buffer.push_str(remaining);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{deterministic, Metrics, Runner};
    use commonware_macros::test_traced;
    use futures::task::waker;
    use prometheus_client::metrics::counter::Counter;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    fn encode_dedup(input: &str) -> String {
        use std::fmt::Write;
        let mut encoder = MetricEncoder::new();
        encoder.write_str(input).unwrap();
        encoder.into_string()
    }

    #[test]
    fn test_metric_encoder_empty() {
        assert_eq!(encode_dedup(""), "");
        assert_eq!(encode_dedup("# EOF\n"), "# EOF\n");
    }

    #[test]
    fn test_metric_encoder_no_duplicates() {
        let input = r#"# HELP foo_total A counter.
# TYPE foo_total counter
foo_total 1
# HELP bar_gauge A gauge.
# TYPE bar_gauge gauge
bar_gauge 42
# EOF
"#;
        let output = encode_dedup(input);
        assert_eq!(output, input);
    }

    #[test]
    fn test_metric_encoder_with_duplicates() {
        let input = r#"# HELP votes_total vote count.
# TYPE votes_total counter
votes_total{epoch="e5"} 1
# HELP votes_total vote count.
# TYPE votes_total counter
votes_total{epoch="e6"} 2
# EOF
"#;
        let expected = r#"# HELP votes_total vote count.
# TYPE votes_total counter
votes_total{epoch="e5"} 1
votes_total{epoch="e6"} 2
# EOF
"#;
        let output = encode_dedup(input);
        assert_eq!(output, expected);
    }

    #[test]
    fn test_metric_encoder_multiple_metrics() {
        let input = r#"# HELP a_total First.
# TYPE a_total counter
a_total{tag="x"} 1
# HELP b_total Second.
# TYPE b_total counter
b_total 5
# HELP a_total First.
# TYPE a_total counter
a_total{tag="y"} 2
# EOF
"#;
        let expected = r#"# HELP a_total First.
# TYPE a_total counter
a_total{tag="x"} 1
# HELP b_total Second.
# TYPE b_total counter
b_total 5
a_total{tag="y"} 2
# EOF
"#;
        let output = encode_dedup(input);
        assert_eq!(output, expected);
    }

    #[test]
    fn test_metric_encoder_preserves_order() {
        let input = r#"# HELP z First alphabetically last.
# TYPE z counter
z_total 1
# HELP a Last alphabetically first.
# TYPE a counter
a_total 2
# EOF
"#;
        let output = encode_dedup(input);
        assert_eq!(output, input);
    }

    #[test_traced]
    fn test_rwlock() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            // Create a new RwLock
            let lock = RwLock::new(100);

            // many concurrent readers
            let r1 = lock.read().await;
            let r2 = lock.read().await;
            assert_eq!(*r1 + *r2, 200);

            // exclusive writer
            drop((r1, r2)); // all readers must go away
            let mut w = lock.write().await;
            *w += 1;

            // Check the value
            assert_eq!(*w, 101);
        });
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

    #[test_traced]
    fn test_count_running_tasks() {
        use crate::{Metrics, Runner, Spawner};
        use futures::future;

        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Initially no tasks with "worker" prefix
            assert_eq!(
                count_running_tasks(&context, "worker"),
                0,
                "no worker tasks initially"
            );

            // Spawn a task under a labeled context that stays running
            let worker_ctx = context.with_label("worker");
            let handle1 = worker_ctx.clone().spawn(|_| async move {
                future::pending::<()>().await;
            });

            // Count running tasks with "worker" prefix
            let count = count_running_tasks(&context, "worker");
            assert_eq!(count, 1, "worker task should be running");

            // Non-matching prefix should return 0
            assert_eq!(
                count_running_tasks(&context, "other"),
                0,
                "no tasks with 'other' prefix"
            );

            // Spawn a nested task (worker_child)
            let handle2 = worker_ctx.with_label("child").spawn(|_| async move {
                future::pending::<()>().await;
            });

            // Count should include both parent and nested tasks
            let count = count_running_tasks(&context, "worker");
            assert_eq!(count, 2, "both worker and worker_child should be counted");

            // Abort parent task
            handle1.abort();
            let _ = handle1.await;

            // Only nested task remains
            let count = count_running_tasks(&context, "worker");
            assert_eq!(count, 1, "only worker_child should remain");

            // Abort nested task
            handle2.abort();
            let _ = handle2.await;

            // All tasks stopped
            assert_eq!(
                count_running_tasks(&context, "worker"),
                0,
                "all worker tasks should be stopped"
            );
        });
    }

    #[test_traced]
    fn test_no_duplicate_metrics() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Register metrics under different labels (no duplicates)
            let c1 = Counter::<u64>::default();
            context.with_label("a").register("test", "help", c1);
            let c2 = Counter::<u64>::default();
            context.with_label("b").register("test", "help", c2);
        });
        // Test passes if runtime doesn't panic on shutdown
    }

    #[test]
    #[should_panic(expected = "duplicate metric:")]
    fn test_duplicate_metrics_panics() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Register metrics with the same label, causing duplicates
            let c1 = Counter::<u64>::default();
            context.with_label("a").register("test", "help", c1);
            let c2 = Counter::<u64>::default();
            context.with_label("a").register("test", "help", c2);
        });
    }
}
