//! Helpers shared by the runtime thread tests of every module.

#[cfg(target_os = "linux")]
use crate::iouring;
use crate::{Clock, Error, Metrics, Runner, Spawner, deterministic, tokio};
use commonware_utils::channel::oneshot;
use std::{
    future::{Future, Ready, pending, ready},
    panic::resume_unwind,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{RecvTimeoutError, channel},
    },
    time::Duration,
};

/// A runner the thread tests run on.
pub(crate) trait TestRunner:
    Runner<Context: Spawner + Clock + Metrics> + Send + 'static
{
    /// Whether the runner's threads are OS threads.
    const NATIVE: bool = true;
    /// Whether a destructor panic on a thread is reported, rather than contained.
    const REPORTS: bool = true;

    /// A runner that catches panics if `catch`.
    fn catching(catch: bool) -> Self;
}

impl TestRunner for deterministic::Runner {
    const NATIVE: bool = false;

    fn catching(catch: bool) -> Self {
        Self::new(deterministic::Config::default().with_catch_panics(catch))
    }
}

impl TestRunner for tokio::Runner {
    fn catching(catch: bool) -> Self {
        Self::new(tokio::Config::default().with_catch_panics(catch))
    }
}

#[cfg(target_os = "linux")]
impl TestRunner for iouring::Runner {
    const REPORTS: bool = false;

    fn catching(catch: bool) -> Self {
        Self::new(iouring::Config::default().with_catch_panics(catch))
    }
}

/// Run `body` on a helper thread and fail if it does not return within a minute, so a runner
/// that hangs fails the test instead of blocking it.
pub(crate) fn bounded<T: Send + 'static>(body: impl FnOnce() -> T + Send + 'static) -> T {
    let (tx, rx) = channel();
    let helper = std::thread::spawn(move || {
        let _ = tx.send(body());
    });
    match rx.recv_timeout(Duration::from_secs(60)) {
        Ok(value) => {
            helper.join().expect("helper thread");
            value
        }
        Err(RecvTimeoutError::Disconnected) => resume_unwind(helper.join().unwrap_err()),
        Err(RecvTimeoutError::Timeout) => panic!("the test did not finish in time"),
    }
}

/// Poll `done` until it holds, sleeping a millisecond between checks.
pub(crate) async fn settle(context: &impl Clock, mut done: impl FnMut() -> bool) {
    for _ in 0..10_000 {
        if done() {
            return;
        }
        context.sleep(Duration::from_millis(1)).await;
    }
    panic!("condition did not settle");
}

/// Whether `handle` resolves `Closed`.
pub(crate) async fn closed<T>(handle: impl Future<Output = Result<T, Error>>) -> bool {
    matches!(handle.await, Err(Error::Closed))
}

/// Hold `guard`, signal `started` if given, then wait forever.
pub(crate) async fn park<T>(guard: T, started: Option<oneshot::Sender<()>>) {
    let _guard = guard;
    if let Some(started) = started {
        let _ = started.send(());
    }
    pending::<()>().await;
}

/// The value of the last `thread_residents` series for threads named `name`, if any.
pub(crate) fn residents(metrics: &impl Metrics, name: &str) -> Option<i64> {
    let needle = format!("name=\"{name}\"");
    metrics
        .encode()
        .lines()
        .filter(|line| line.starts_with("runtime_thread_residents{") && line.contains(&needle))
        .filter_map(|line| line.trim_end().rsplit(' ').next()?.parse().ok())
        .next_back()
}

/// The execution labels of the tasks spawned under `name`, from the runner's task metrics.
pub(crate) fn executions(metrics: &impl Metrics, name: &str) -> Vec<String> {
    let needle = format!("name=\"{name}\"");
    metrics
        .encode()
        .lines()
        .filter(|line| line.starts_with("runtime_tasks_spawned_total{") && line.contains(&needle))
        .filter_map(|line| {
            let execution = line.split("execution=\"").nth(1)?.split('"').next()?;
            Some(execution.to_string())
        })
        .collect()
}

/// A new flag, initially false.
pub(crate) fn flag() -> Arc<AtomicBool> {
    Arc::new(AtomicBool::new(false))
}

/// Whether `flag` is set.
pub(crate) fn is_set(flag: &AtomicBool) -> bool {
    flag.load(Ordering::SeqCst)
}

/// A factory that sets `ran` and returns a future that completes at once.
pub(crate) fn recording<L>(ran: &Arc<AtomicBool>) -> impl FnOnce(L) -> Ready<()> + Send + 'static {
    capturing((), ran)
}

/// A factory that holds `capture` until it runs or is dropped, and sets `ran` if it runs.
pub(crate) fn capturing<L, T: Send + 'static>(
    capture: T,
    ran: &Arc<AtomicBool>,
) -> impl FnOnce(L) -> Ready<()> + Send + 'static {
    let ran = ran.clone();
    move |_| {
        let _capture = capture;
        ran.store(true, Ordering::SeqCst);
        ready(())
    }
}

/// Sets its flag when dropped.
pub(crate) struct DropFlag(pub(crate) Arc<AtomicBool>);

impl Drop for DropFlag {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

/// Runs its closure when dropped, unless disarmed first.
pub(crate) struct OnDrop<F: FnOnce()>(Option<F>);

/// A value that runs `f` when dropped.
pub(crate) const fn on_drop<F: FnOnce()>(f: F) -> OnDrop<F> {
    OnDrop(Some(f))
}

impl<F: FnOnce()> OnDrop<F> {
    /// Drop without running the closure.
    pub(crate) fn disarm(mut self) {
        self.0 = None;
    }
}

impl<F: FnOnce()> Drop for OnDrop<F> {
    fn drop(&mut self) {
        if let Some(f) = self.0.take() {
            f();
        }
    }
}
