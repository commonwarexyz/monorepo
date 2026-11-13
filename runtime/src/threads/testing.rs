//! Helpers shared by the runtime thread tests of every module.

use crate::{Clock, Metrics};
use std::{
    future::{Ready, ready},
    panic::resume_unwind,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{RecvTimeoutError, channel},
    },
    time::Duration,
};

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

/// A factory that sets `ran` and returns a future that completes at once.
pub(crate) fn recording<L>(ran: &Arc<AtomicBool>) -> impl FnOnce(L) -> Ready<()> + Send + 'static {
    let ran = ran.clone();
    move |_| {
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
