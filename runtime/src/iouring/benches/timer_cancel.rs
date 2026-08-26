//! Fixed-total mass cancellation of registered long-deadline sleeps.
//!
//! Runtime construction, root entry, and batch construction are setup. The
//! timed work polls every sleep exactly once, verifies that it is pending, and
//! drops the batch. Polling registers the timers. Dropping measures future
//! destruction and cancellation, including io_uring tombstone accounting and
//! heap compaction. Tokio's cooperative budget is disabled around the manual
//! poll-and-drop loop so every sleep reaches timer registration.

use super::support::{Backend, tokio_runner};
use commonware_runtime::{Clock as _, Runner as _, iouring};
use criterion::Criterion;
use std::{
    future::Future,
    pin::Pin,
    time::{Duration, Instant},
};

const TOTAL_SLEEPS: usize = 65_536;
const DEADLINE: Duration = Duration::from_secs(3_600);

/// Register fixed-total timer cancellation rows for both runtimes.
pub fn bench(c: &mut Criterion) {
    for backend in Backend::ALL {
        let name = format!(
            "{}/runtime={} total_sleeps={TOTAL_SLEEPS} deadline_s={}",
            module_path!(),
            backend.name(),
            DEADLINE.as_secs()
        );
        match backend {
            Backend::IoUring => c.bench_function(&name, |b| {
                b.iter_custom(measure_iouring);
            }),
            Backend::Tokio => c.bench_function(&name, |b| {
                b.iter_custom(measure_tokio);
            }),
        };
    }
}

/// Measure io_uring timer registration and cancellation inside one runtime root.
fn measure_iouring(iters: u64) -> Duration {
    iouring::Runner::default().start(move |context| async move {
        let mut elapsed = Duration::ZERO;
        for _ in 0..iters {
            let mut sleeps = Vec::with_capacity(TOTAL_SLEEPS);
            for _ in 0..TOTAL_SLEEPS {
                sleeps.push(Box::pin(context.sleep(DEADLINE)));
            }

            elapsed += poll_and_cancel(sleeps).await;
        }
        elapsed
    })
}

/// Measure Commonware Tokio timer registration and cancellation inside one runtime root.
fn measure_tokio(iters: u64) -> Duration {
    tokio_runner().start(move |context| async move {
        let mut elapsed = Duration::ZERO;
        for _ in 0..iters {
            let mut sleeps = Vec::with_capacity(TOTAL_SLEEPS);
            for _ in 0..TOTAL_SLEEPS {
                sleeps.push(Box::pin(context.sleep(DEADLINE)));
            }

            elapsed += tokio::task::unconstrained(poll_and_cancel(sleeps)).await;
        }
        elapsed
    })
}

/// Poll every sleep once, verify registration remains pending, and cancel it.
async fn poll_and_cancel<F>(mut sleeps: Vec<Pin<Box<F>>>) -> Duration
where
    F: Future<Output = ()>,
{
    let start = Instant::now();
    for sleep in &mut sleeps {
        assert!(futures::poll!(sleep.as_mut()).is_pending());
    }
    drop(sleeps);
    start.elapsed()
}
