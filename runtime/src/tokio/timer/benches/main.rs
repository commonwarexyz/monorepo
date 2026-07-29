//! Standalone harness for measuring production Tokio timer behavior.
//!
//! The harness compares sleeps through the real Commonware
//! [`commonware_runtime::Clock`] with direct `tokio::time` sleeps. It reports
//! explicit latency distributions because synchronized timer workloads are not
//! well represented by a Criterion iteration loop.

mod accuracy;
mod config;
mod report;
mod worst_case;

use commonware_runtime::{Clock as _, Runner as _, tokio as commonware_tokio};
pub(crate) use config::{Backend, Config, checked_observations};
use std::{
    error::Error,
    future::Future,
    io,
    pin::Pin,
    task::{Context, Poll},
    time::{Duration, SystemTime},
};

/// Heap-allocated sleep used to give both timer backends the same harness cost.
pub(crate) type BenchSleep = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;

/// Constructs a relative sleep through the selected backend.
pub(crate) fn sleep_for(
    clock: &commonware_tokio::Context,
    backend: Backend,
    duration: Duration,
) -> BenchSleep {
    match backend {
        Backend::Commonware => Box::pin(clock.sleep(duration)),
        Backend::Tokio => Box::pin(tokio::time::sleep(duration)),
    }
}

/// Constructs an absolute sleep through the selected backend.
pub(crate) fn sleep_until(
    clock: &commonware_tokio::Context,
    backend: Backend,
    wall_deadline: SystemTime,
    tokio_deadline: tokio::time::Instant,
) -> BenchSleep {
    match backend {
        Backend::Commonware => Box::pin(clock.sleep_until(wall_deadline)),
        Backend::Tokio => Box::pin(tokio::time::sleep_until(tokio_deadline)),
    }
}

/// Constructs a wall-clock sleep while preserving equivalent backend work.
pub(crate) fn sleep_until_wall(
    clock: &commonware_tokio::Context,
    backend: Backend,
    wall_deadline: SystemTime,
) -> BenchSleep {
    match backend {
        Backend::Commonware => Box::pin(clock.sleep_until(wall_deadline)),
        Backend::Tokio => {
            // Mirror Commonware's wall-clock snapshot before delegating to the
            // relative Tokio sleep constructor.
            let duration = wall_deadline
                .duration_since(SystemTime::now())
                .unwrap_or_default();
            Box::pin(tokio::time::sleep(duration))
        }
    }
}

/// Polls a sleep once so lazy backends register before timing continues.
pub(crate) fn poll_once(sleep: &mut BenchSleep) -> Poll<()> {
    let waker = futures::task::noop_waker_ref();
    let mut context = Context::from_waker(waker);
    sleep.as_mut().poll(&mut context)
}

/// Parses configuration and runs the selected production timer workloads.
fn main() -> Result<(), Box<dyn Error>> {
    let Some(config) = Config::parse()? else {
        return Ok(());
    };
    let runtime = commonware_tokio::Runner::new(
        commonware_tokio::Config::default().with_worker_threads(config.worker_threads),
    );

    runtime.start(|context| async {
        report::print_effective_config(&config);
        let clock = std::sync::Arc::new(context);

        if config.scenario.runs_accuracy() {
            accuracy::run(&config, std::sync::Arc::clone(&clock)).await?;
        }
        if config.scenario.runs_worst_case() {
            worst_case::run_contention(&config, clock).await?;
        }
        Ok::<_, io::Error>(())
    })?;

    // Fairness uses one worker so the timer driver and runnable peer must
    // cooperate on the same executor regardless of the main configuration.
    if config.scenario.runs_worst_case() {
        worst_case::run_fairness(&config)?;
    }
    Ok(())
}
