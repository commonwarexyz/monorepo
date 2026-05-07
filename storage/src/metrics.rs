//! Shared metric helpers.

pub(crate) use commonware_runtime::telemetry::metrics::histogram::Timed;
use commonware_runtime::{
    telemetry::metrics::{histogram::Buckets, Histogram, MetricsExt as _},
    Clock, Metrics,
};
use std::sync::Arc;

/// A duration timer that records when dropped.
pub(crate) struct Timer<E: Clock> {
    timer: Option<commonware_runtime::telemetry::metrics::histogram::Timer>,
    clock: Arc<E>,
}

/// Start a timer that observes when dropped.
pub(crate) fn timer<E: Clock>(timed: &Timed, clock: &Arc<E>) -> Timer<E> {
    Timer {
        timer: Some(timed.timer(clock.as_ref())),
        clock: clock.clone(),
    }
}

impl<E: Clock> Drop for Timer<E> {
    fn drop(&mut self) {
        if let Some(timer) = self.timer.take() {
            timer.observe(self.clock.as_ref());
        }
    }
}

/// Register a call-duration histogram using buckets sized for local storage work.
///
/// Timers returned by [`timer`] observe on drop, so callers should start timers after excluding
/// true no-op paths they do not want represented. Validation failures after an operation begins
/// are still part of the call.
pub(crate) fn duration_histogram<E: Metrics>(
    context: &E,
    name: &'static str,
    help: &'static str,
) -> Histogram {
    context.histogram(name, help, Buckets::LOCAL)
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_runtime::{deterministic, Runner as _, Supervisor as _};
    use std::time::Duration;

    #[test]
    fn duration_records_all_calls() {
        deterministic::Runner::default().start(|context| async move {
            let histogram = duration_histogram(&context, "test_duration", "test duration");
            let timed = Timed::new(histogram);
            let clock = Arc::new(context.child("timer"));

            {
                let _timer = timer(&timed, &clock);
                context.sleep(Duration::from_millis(1)).await;
                let result: Result<(), ()> = Ok(());
                assert!(result.is_ok());
            }

            {
                let _timer = timer(&timed, &clock);
                context.sleep(Duration::from_millis(1)).await;
                let result: Result<(), ()> = Err(());
                assert!(result.is_err());
            }

            {
                let _timer = timer(&timed, &clock);
                context.sleep(Duration::from_millis(1)).await;
            }

            let metrics = context.encode();
            assert!(
                metrics.contains("test_duration_count 3"),
                "unexpected metrics: {metrics}"
            );
        });
    }
}
