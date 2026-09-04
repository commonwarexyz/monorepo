use commonware_runtime::{
    Metrics,
    telemetry::metrics::{Gauge, GaugeExt as _, MetricsExt as _},
};
use std::{
    num::NonZeroU64,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

/// A constant-rate synthetic byte stream, partitioned into fixed-size producer blocks.
///
/// Heights identify input batches, so retrying a proposal does not consume new input. The
/// schedule starts at this application's first proposal request, including after a restart.
/// Backpressure leaves arrivals unchanged; the backlog needs no allocated transaction queue.
pub(super) struct Workload {
    bytes_per_second: NonZeroU64,
    body_size: usize,
    origin: Option<(u64, SystemTime)>,
    started: Gauge,
    admitted: Gauge,
    _rate: Gauge,
}

impl Workload {
    pub(super) fn new(
        context: &impl Metrics,
        bytes_per_second: NonZeroU64,
        body_size: usize,
    ) -> Self {
        assert!(body_size > 0, "offered load requires nonempty block bodies");
        let rate = context.gauge("input_bytes_per_second", "offered payload bytes per second");
        rate.try_set(bytes_per_second.get())
            .expect("offered byte rate must fit in a gauge");
        Self {
            bytes_per_second,
            body_size,
            origin: None,
            started: context.gauge(
                "input_started_timestamp_milliseconds",
                "Unix timestamp of the first synthetic input arrival, zero before production",
            ),
            admitted: context.gauge(
                "input_admitted_bytes",
                "synthetic input byte position returned to consensus, excluding proposal retries",
            ),
            _rate: rate,
        }
    }

    /// Returns when the last byte of this height's input batch arrives.
    pub(super) fn ready_at(&mut self, height: u64, now: SystemTime) -> SystemTime {
        let (first, origin) = *self.origin.get_or_insert_with(|| {
            self.started
                .try_set(
                    now.duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis(),
                )
                .expect("input timestamp must fit in a gauge");
            (height, now)
        });
        // A recovered prefix below the first requested height is not part of this input stream.
        let Some(index) = height.checked_sub(first) else {
            return origin;
        };
        let bytes = (u128::from(index) + 1) * self.body_size as u128;
        let rate = u128::from(self.bytes_per_second.get());
        let seconds = u64::try_from(bytes / rate).expect("input schedule exceeds duration range");
        let nanos = ((bytes % rate) * 1_000_000_000).div_ceil(rate) as u32;
        origin
            .checked_add(Duration::new(seconds, nanos))
            .expect("input schedule exceeds clock range")
    }

    pub(super) fn admit(&self, height: u64) {
        let (first, _) = self.origin.expect("input was scheduled before admission");
        if let Some(index) = height.checked_sub(first) {
            let bytes = (u128::from(index) + 1) * self.body_size as u128;
            self.admitted
                .try_set_max(bytes)
                .expect("admitted input bytes must fit in a gauge");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_runtime::{Clock as _, Runner as _, deterministic};
    use commonware_utils::NZU64;

    #[test]
    fn arrivals_are_independent_of_backpressure_and_retries() {
        deterministic::Runner::default().start(|context| async move {
            let mut workload = Workload::new(&context, NZU64!(1_000), 100);
            let origin = context.current();
            assert_eq!(
                workload.ready_at(11, origin),
                origin + Duration::from_millis(100)
            );
            context.sleep(Duration::from_secs(1)).await;
            assert_eq!(
                workload.ready_at(11, context.current()),
                origin + Duration::from_millis(100)
            );
            assert_eq!(
                workload.ready_at(12, context.current()),
                origin + Duration::from_millis(200)
            );
            workload.admit(12);
            workload.admit(11);
            workload.admit(12);
            assert_eq!(workload.admitted.get(), 200);
            assert_eq!(workload.ready_at(10, context.current()), origin);
            workload.admit(10);
            assert_eq!(workload.admitted.get(), 200);
        });
    }

    #[test]
    fn fractional_intervals_do_not_accumulate_rounding_error() {
        deterministic::Runner::default().start(|context| async move {
            let mut workload = Workload::new(&context, NZU64!(3), 1);
            let origin = context.current();
            assert_eq!(
                workload.ready_at(1, origin),
                origin + Duration::from_nanos(333_333_334)
            );
            assert_eq!(
                workload.ready_at(2, origin),
                origin + Duration::from_nanos(666_666_667)
            );
            assert_eq!(
                workload.ready_at(3, origin),
                origin + Duration::from_secs(1)
            );
            assert_eq!(
                workload.ready_at(3_000_000, origin),
                origin + Duration::from_secs(1_000_000)
            );
        });
    }
}
