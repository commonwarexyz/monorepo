//! Offloads CPU-bound work to a strategy's worker pool and catches worker panics.

use commonware_parallel::Strategy;
use commonware_runtime::{
    Clock,
    telemetry::metrics::{Histogram, HistogramExt as _},
};
use futures::FutureExt as _;
use std::{
    future::Future,
    panic::{AssertUnwindSafe, catch_unwind},
    time::SystemTime,
};
use tracing::{Instrument as _, Span};

/// Offloaded work panicked while it was submitted or while it ran.
#[derive(Debug)]
pub(crate) struct WorkerPanicked;

/// Latency histograms for one offloaded job.
pub(crate) struct Timing {
    /// Observes the delay from `issued_at` to submission.
    pub(crate) dispatch: Histogram,
    /// Observes the delay from submission to the start of the work.
    pub(crate) queue: Histogram,
    /// When the job was issued.
    pub(crate) issued_at: SystemTime,
}

/// Submits `op` to `strategy` with `weight` and returns a future that resolves to its result.
///
/// Submission happens before this returns, so an inline strategy runs `op` immediately; call it
/// from an `async` block to defer submission until the future is first polled. `op` runs inside
/// `span`, the returned future is instrumented with it and hands it back, and a panic during
/// submission or inside `op` resolves to [`WorkerPanicked`].
pub(crate) fn offload<S, T, O>(
    strategy: S,
    weight: usize,
    span: Span,
    op: O,
) -> impl Future<Output = (Span, Result<T, WorkerPanicked>)> + Send
where
    S: Strategy,
    O: FnOnce(S) -> T + Send + 'static,
    T: Send + 'static,
{
    let worker = span.clone();
    let submitted = catch_unwind(AssertUnwindSafe(|| {
        strategy
            .manual()
            .spawn(weight, move |_| worker.in_scope(|| op(strategy)))
    }));
    async move {
        let outcome = match submitted {
            Ok(running) => AssertUnwindSafe(running)
                .catch_unwind()
                .instrument(span.clone())
                .await
                .map_err(|_| WorkerPanicked),
            Err(_) => Err(WorkerPanicked),
        };
        (span, outcome)
    }
}

/// Like [`offload`], and observes `timing`: dispatch at submission and queue when `op` starts.
///
/// `op` receives `clock` along with the strategy.
pub(crate) fn offload_timed<C, S, T, O>(
    clock: C,
    timing: Timing,
    strategy: S,
    weight: usize,
    span: Span,
    op: O,
) -> impl Future<Output = (Span, Result<T, WorkerPanicked>)> + Send
where
    C: Clock + Send + 'static,
    S: Strategy,
    O: FnOnce(C, S) -> T + Send + 'static,
    T: Send + 'static,
{
    let submitted = clock.current();
    timing.dispatch.observe_between(timing.issued_at, submitted);
    let queue = timing.queue;
    offload(strategy, weight, span, move |strategy| {
        queue.observe_between(submitted, clock.current());
        op(clock, strategy)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_parallel::{Rayon, Sequential};
    use commonware_runtime::{
        Metrics as _, Runner as _, Spawner as _, Supervisor as _, deterministic,
        telemetry::metrics::MetricsExt as _, tokio,
    };
    use commonware_utils::sync::{Condvar, Mutex};
    use std::{num::NonZeroUsize, sync::Arc, thread, time::Duration};

    fn rayon() -> Rayon {
        Rayon::new(NonZeroUsize::new(2).unwrap()).expect("compute pool starts")
    }

    #[derive(Default)]
    struct ServiceState {
        cpu_started: bool,
        async_serviced: bool,
        cpu_released: bool,
    }

    /// Holds a worker on the CPU until the async executor has serviced another task.
    #[derive(Default)]
    struct ServiceProbe {
        state: Mutex<ServiceState>,
        changed: Condvar,
    }

    impl ServiceProbe {
        fn block_cpu(&self) {
            let mut state = self.state.lock();
            state.cpu_started = true;
            self.changed.notify_all();
            while !state.cpu_released {
                self.changed.wait(&mut state);
            }
        }

        fn service_async(&self) {
            let mut state = self.state.lock();
            state.async_serviced = true;
            self.changed.notify_all();
        }

        fn release_after_service(&self) {
            let mut state = self.state.lock();
            while !state.cpu_started || !state.async_serviced {
                self.changed.wait(&mut state);
            }
            state.cpu_released = true;
            self.changed.notify_all();
        }
    }

    #[test]
    fn dispatch_is_observed_at_submission_and_queue_at_start() {
        deterministic::Runner::default().start(|context| async move {
            // Registered histograms stay exported only while a handle is alive.
            let dispatch = context.histogram("dispatch", "dispatch wait", [0.0, 1.0]);
            let queue = context.histogram("queue", "worker queue", [0.0, 1.0]);
            let timing = Timing {
                dispatch: dispatch.clone(),
                queue: queue.clone(),
                issued_at: context.current(),
            };
            let operation = {
                let context = context.child("inline");
                async move {
                    offload_timed(
                        context,
                        timing,
                        Sequential,
                        1,
                        Span::none(),
                        |context, _| {
                            assert!(context.encode().contains("queue_count 1\n"));
                            7
                        },
                    )
                    .await
                }
            };
            context.sleep(Duration::from_millis(125)).await;
            assert!(context.encode().contains("queue_count 0\n"));
            assert!(context.encode().contains("dispatch_count 0\n"));
            assert_eq!(operation.await.1.unwrap(), 7);
            let encoded = context.encode();
            assert!(encoded.contains("queue_count 1\n"), "{encoded}");
            assert!(encoded.contains("queue_sum 0.0\n"), "{encoded}");
            assert!(encoded.contains("dispatch_count 1\n"), "{encoded}");
            assert!(encoded.contains("dispatch_sum 0.125\n"), "{encoded}");
        });
    }

    // The tokio runner lets rayon complete the work on its own threads; the deterministic
    // runtime would report a stall while its only task waits on one.
    #[test]
    fn work_runs_on_the_strategy_pool() {
        tokio::Runner::default().start(|_| async move {
            let (_, on_strategy) = offload(rayon(), 1, Span::none(), |_| {
                rayon::current_thread_index().is_some()
            })
            .await;
            assert!(on_strategy.expect("worker completes"));
        });
    }

    // A one-worker tokio runner: blocked rayon work must leave that one executor thread free,
    // and the deterministic runtime would report a stall while its only task waits on rayon.
    #[test]
    fn blocked_work_keeps_the_async_executor_serviceable() {
        let runner = tokio::Runner::new(tokio::Config::default().with_worker_threads(1));
        runner.start(|context| async move {
            let probe = Arc::new(ServiceProbe::default());
            let observer = {
                let probe = Arc::clone(&probe);
                thread::spawn(move || probe.release_after_service())
            };
            let work = {
                let probe = Arc::clone(&probe);
                context
                    .child("work")
                    .spawn(move |_| offload(rayon(), 1, Span::none(), move |_| probe.block_cpu()))
            };
            let service = context.child("service").spawn(move |_| async move {
                probe.service_async();
            });

            work.await
                .expect("work task completes")
                .1
                .expect("worker completes");
            service.await.expect("async service completes");
            observer.join().expect("observer completes");
        });
    }

    // The tokio runner lets the rayon cases panic on their own threads; the deterministic runtime
    // would report a stall while its only task waits on one.
    #[rstest::rstest]
    #[case(Sequential)]
    #[case(Rayon::new(NonZeroUsize::MIN).unwrap())]
    #[case(Rayon::new(NonZeroUsize::new(2).unwrap()).unwrap())]
    fn worker_panic_is_reconciled(#[case] strategy: impl Strategy) {
        tokio::Runner::default().start(|_| async move {
            let (_, outcome) = offload(strategy, 1, Span::none(), |_| -> () {
                panic!("worker panic")
            })
            .await;
            assert!(matches!(outcome, Err(WorkerPanicked)));
        });
    }
}
