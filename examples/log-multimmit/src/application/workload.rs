use commonware_runtime::{
    Metrics,
    telemetry::metrics::{Gauge, GaugeExt as _, MetricsExt as _},
};
use serde::{Deserialize, Serialize};
use std::{
    num::NonZeroU64,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

/// A finite byte arrival schedule shared by producers and the measurement controller.
///
/// Phases are contiguous from `start_unix_ms`. Integrate each rate over its elapsed
/// duration and round down only the cumulative sum to obtain arrived whole bytes.
/// Fractional bytes carry across phases, including zero-rate drain intervals.
/// The byte backlog is arrived bytes minus admitted bytes, saturating at zero.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Schedule {
    /// Absolute start time in Unix milliseconds.
    pub start_unix_ms: u64,
    /// Contiguous intervals in execution order.
    pub phases: Vec<Phase>,
}

/// One interval of a finite arrival schedule; a zero rate admits no new bytes.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Phase {
    /// Positive interval length in milliseconds.
    pub duration_ms: u64,
    /// Payload byte arrival rate during this interval.
    pub bytes_per_second: u64,
}

impl Schedule {
    /// Checks durations, clock bounds, and integer metric bounds before production.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.phases.is_empty() {
            return Err("input schedule requires at least one phase");
        }
        let mut end_ms = self.start_unix_ms;
        let mut millibytes = 0u128;
        for phase in &self.phases {
            if phase.duration_ms == 0 {
                return Err("input schedule phase duration must be positive");
            }
            if phase.bytes_per_second > i64::MAX as u64 {
                return Err("input byte rate must fit in a gauge");
            }
            end_ms = end_ms
                .checked_add(phase.duration_ms)
                .ok_or("input schedule duration overflow")?;
            millibytes = millibytes
                .checked_add(u128::from(phase.duration_ms) * u128::from(phase.bytes_per_second))
                .ok_or("input schedule byte count overflow")?;
        }
        if end_ms > i64::MAX as u64
            || UNIX_EPOCH
                .checked_add(Duration::from_millis(end_ms))
                .is_none()
        {
            return Err("input schedule exceeds clock or timestamp gauge range");
        }
        if millibytes / 1_000 > i64::MAX as u128 {
            return Err("input schedule byte count must fit in a gauge");
        }
        Ok(())
    }

    /// Returns whole bytes arrived by an absolute time, capped at the schedule's end.
    /// The schedule must have passed [`Self::validate`].
    pub fn arrived_bytes(&self, now: SystemTime) -> u64 {
        let start = UNIX_EPOCH + Duration::from_millis(self.start_unix_ms);
        let mut remaining = now.duration_since(start).unwrap_or_default().as_nanos();
        let mut byte_nanos = 0u128;
        for phase in &self.phases {
            let elapsed = remaining.min(u128::from(phase.duration_ms) * 1_000_000);
            byte_nanos += elapsed * u128::from(phase.bytes_per_second);
            remaining -= elapsed;
            if remaining == 0 {
                break;
            }
        }
        (byte_nanos / 1_000_000_000) as u64
    }

    fn ready_at(&self, bytes: u128) -> Option<SystemTime> {
        let mut remaining = bytes.checked_mul(1_000)?;
        let mut elapsed_ms = 0u64;
        for phase in &self.phases {
            let rate = u128::from(phase.bytes_per_second);
            let capacity = u128::from(phase.duration_ms) * rate;
            if rate != 0 && remaining <= capacity {
                let nanos = (remaining * 1_000_000).div_ceil(rate);
                let offset = Duration::new(
                    (nanos / 1_000_000_000) as u64,
                    (nanos % 1_000_000_000) as u32,
                );
                return Some(
                    UNIX_EPOCH + Duration::from_millis(self.start_unix_ms + elapsed_ms) + offset,
                );
            }
            remaining -= capacity;
            elapsed_ms += phase.duration_ms;
        }
        None
    }
}

enum Arrivals {
    Constant(NonZeroU64),
    Scheduled(Schedule),
}

/// A synthetic byte stream partitioned into fixed-size producer blocks.
///
/// Heights identify input batches, so retrying a proposal does not consume new input.
/// The first requested height anchors byte position zero, including after a restart.
/// Constant load starts at that request; finite load uses its absolute start time.
/// Backpressure leaves arrivals unchanged; no allocated transaction queue is needed.
pub(super) struct Workload {
    arrivals: Arrivals,
    body_size: usize,
    origin: Option<(u64, SystemTime)>,
    started: Gauge,
    admitted: Gauge,
    rate: Gauge,
}

impl Workload {
    pub(super) fn new(
        context: &impl Metrics,
        bytes_per_second: NonZeroU64,
        body_size: usize,
    ) -> Self {
        Self::with_arrivals(context, Arrivals::Constant(bytes_per_second), body_size)
    }

    pub(super) fn from_schedule(
        context: &impl Metrics,
        schedule: Schedule,
        body_size: usize,
    ) -> Result<Self, &'static str> {
        schedule.validate()?;
        if body_size == 0 {
            return Err("offered load requires nonempty block bodies");
        }
        Ok(Self::with_arrivals(
            context,
            Arrivals::Scheduled(schedule),
            body_size,
        ))
    }

    fn with_arrivals(context: &impl Metrics, arrivals: Arrivals, body_size: usize) -> Self {
        assert!(body_size > 0, "offered load requires nonempty block bodies");
        let rate = context.gauge(
            "input_bytes_per_second",
            "offered payload bytes per second at the last proposal request",
        );
        if let Arrivals::Constant(value) = &arrivals {
            rate.try_set(value.get())
                .expect("offered byte rate must fit in a gauge");
        }
        let started = context.gauge(
            "input_started_timestamp_milliseconds",
            "Unix timestamp of the synthetic input schedule start, zero before constant-rate production",
        );
        if let Arrivals::Scheduled(schedule) = &arrivals {
            started
                .try_set(schedule.start_unix_ms)
                .expect("validated input timestamp");
        }
        Self {
            arrivals,
            body_size,
            origin: None,
            started,
            admitted: context.gauge(
                "input_admitted_bytes",
                "synthetic input byte position returned to consensus, excluding proposal retries",
            ),
            rate,
        }
    }

    /// Returns the absolute arrival time of this batch's last byte, or exhaustion.
    /// A final partial batch is never admitted. Delayed requests retain historical deadlines.
    pub(super) fn ready_at(&mut self, height: u64, now: SystemTime) -> Option<SystemTime> {
        let origin = match &self.arrivals {
            Arrivals::Constant(_) => now,
            Arrivals::Scheduled(schedule) => {
                let start = UNIX_EPOCH + Duration::from_millis(schedule.start_unix_ms);
                let current_rate = now
                    .duration_since(start)
                    .ok()
                    .and_then(|elapsed| {
                        let mut remaining = elapsed.as_millis();
                        schedule.phases.iter().find_map(|phase| {
                            if remaining < u128::from(phase.duration_ms) {
                                Some(phase.bytes_per_second)
                            } else {
                                remaining -= u128::from(phase.duration_ms);
                                None
                            }
                        })
                    })
                    .unwrap_or(0);
                self.rate
                    .try_set(current_rate)
                    .expect("validated input rate");
                start
            }
        };
        let (first, origin) = *self.origin.get_or_insert_with(|| {
            self.started
                .try_set(
                    origin
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis(),
                )
                .expect("input timestamp must fit in a gauge");
            (height, origin)
        });
        // A recovered prefix below the first requested height is not part of this input stream.
        let Some(index) = height.checked_sub(first) else {
            return Some(origin);
        };
        let bytes = (u128::from(index) + 1) * self.body_size as u128;
        match &self.arrivals {
            Arrivals::Scheduled(schedule) => schedule.ready_at(bytes),
            Arrivals::Constant(rate) => {
                let rate = u128::from(rate.get());
                let seconds =
                    u64::try_from(bytes / rate).expect("input schedule exceeds duration range");
                let nanos = ((bytes % rate) * 1_000_000_000).div_ceil(rate) as u32;
                Some(
                    origin
                        .checked_add(Duration::new(seconds, nanos))
                        .expect("input schedule exceeds clock range"),
                )
            }
        }
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
    use commonware_runtime::{Runner as _, deterministic};
    use commonware_utils::NZU64;

    fn schedule(phases: &[(u64, u64)]) -> Schedule {
        Schedule {
            start_unix_ms: 10_000,
            phases: phases
                .iter()
                .map(|&(duration_ms, bytes_per_second)| Phase {
                    duration_ms,
                    bytes_per_second,
                })
                .collect(),
        }
    }

    fn at(ms: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_millis(10_000 + ms)
    }

    #[test]
    fn multirate_gap_end_retries_and_backlog() {
        deterministic::Runner::default().start(|context| async move {
            let schedule = schedule(&[(1_000, 100), (1_000, 0), (1_000, 200), (1_000, 0)]);
            let mut workload = Workload::from_schedule(&context, schedule.clone(), 50).unwrap();
            assert_eq!(workload.started.get(), 10_000);
            assert_eq!(workload.ready_at(11, at(3_500)), Some(at(500)));
            assert_eq!(workload.ready_at(12, at(3_500)), Some(at(1_000)));
            assert_eq!(workload.ready_at(13, at(3_500)), Some(at(2_250)));
            assert_eq!(workload.ready_at(16, at(3_500)), Some(at(3_000)));
            assert_eq!(workload.ready_at(17, at(3_500)), None);
            assert_eq!(workload.ready_at(13, at(20_000)), Some(at(2_250)));
            workload.admit(12);
            workload.admit(11);
            workload.admit(12);
            assert_eq!(workload.admitted.get(), 100);
            assert_eq!(
                schedule
                    .arrived_bytes(at(2_500))
                    .saturating_sub(workload.admitted.get() as u64),
                100
            );
            assert_eq!(workload.ready_at(10, at(20_000)), Some(at(0)));
            workload.admit(10);
            assert_eq!(workload.admitted.get(), 100);
            assert_eq!(schedule.arrived_bytes(UNIX_EPOCH), 0);
            assert_eq!(schedule.arrived_bytes(at(1_500)), 100);
            assert_eq!(schedule.arrived_bytes(at(20_000)), 300);
        });
    }

    #[test]
    fn fractional_bytes_carry_across_phases_and_gaps() {
        let schedule = schedule(&[(500, 1), (1_000, 0), (500, 3), (1_000, 0)]);
        schedule.validate().unwrap();
        assert_eq!(
            schedule.ready_at(1),
            Some(at(1_500) + Duration::from_nanos(166_666_667))
        );
        assert_eq!(schedule.ready_at(2), Some(at(2_000)));
        assert_eq!(schedule.ready_at(3), None);
        let ready = schedule.ready_at(1).unwrap();
        assert_eq!(schedule.arrived_bytes(ready - Duration::from_nanos(1)), 0);
        assert_eq!(schedule.arrived_bytes(ready), 1);
        assert_eq!(schedule.arrived_bytes(at(1_000)), 0);
        assert_eq!(self::schedule(&[(1_000, 0)]).ready_at(1), None);
        assert_eq!(
            self::schedule(&[(1_000, 0), (1_000, 1)]).ready_at(1),
            Some(at(2_000))
        );
    }

    #[test]
    fn deadlines_match_offline_arrivals() {
        let schedule = schedule(&[(371, 101), (237, 0), (617, 73), (813, 211)]);
        schedule.validate().unwrap();
        let encoded = serde_yaml::to_string(&schedule).unwrap();
        let decoded: Schedule = serde_yaml::from_str(&encoded).unwrap();
        let total = schedule.arrived_bytes(at(10_000));
        for bytes in 1..=total {
            let deadline = schedule.ready_at(u128::from(bytes)).unwrap();
            assert_eq!(decoded.arrived_bytes(deadline), bytes);
            assert_eq!(
                decoded.arrived_bytes(deadline - Duration::from_nanos(1)),
                bytes - 1
            );
        }
        assert_eq!(schedule.ready_at(u128::from(total) + 1), None);
    }

    #[test]
    fn incomplete_final_batch_is_exhausted() {
        deterministic::Runner::default().start(|context| async move {
            let mut workload =
                Workload::from_schedule(&context, schedule(&[(1_000, 99)]), 50).unwrap();
            assert!(workload.ready_at(1, at(0)).is_some());
            assert_eq!(workload.ready_at(2, at(0)), None);
            assert_eq!(workload.ready_at(u64::MAX, at(0)), None);
        });
    }

    #[test]
    fn invalid_schedules_are_rejected() {
        for schedule in [
            schedule(&[]),
            schedule(&[(0, 1)]),
            schedule(&[(u64::MAX, 1)]),
            schedule(&[(1, u64::MAX)]),
            schedule(&[(2_000, i64::MAX as u64)]),
            Schedule {
                start_unix_ms: u64::MAX,
                phases: vec![Phase {
                    duration_ms: 1,
                    bytes_per_second: 1,
                }],
            },
        ] {
            assert!(schedule.validate().is_err());
        }
        deterministic::Runner::default().start(|context| async move {
            assert!(Workload::from_schedule(&context, schedule(&[(1_000, 1)]), 0).is_err());
        });
        assert!(
            serde_yaml::from_str::<Schedule>(
                "start_unix_ms: 0\nphases:\n- duration_ms: 1\n  bytes_per_second: -1"
            )
            .is_err()
        );
    }

    #[test]
    fn constant_arrivals_are_stable_without_accumulated_rounding() {
        deterministic::Runner::default().start(|context| async move {
            let mut workload = Workload::new(&context, NZU64!(3), 1);
            assert_eq!(
                workload.ready_at(1, at(0)),
                Some(at(0) + Duration::from_nanos(333_333_334))
            );
            assert_eq!(
                workload.ready_at(2, at(50_000)),
                Some(at(0) + Duration::from_nanos(666_666_667))
            );
            assert_eq!(workload.ready_at(3, at(50_000)), Some(at(1_000)));
            assert_eq!(
                workload.ready_at(1, at(50_000)),
                Some(at(0) + Duration::from_nanos(333_333_334))
            );
            assert_eq!(workload.ready_at(3_000_000, at(0)), Some(at(1_000_000_000)));
            workload.admit(2);
            workload.admit(1);
            assert_eq!(workload.admitted.get(), 2);
        });
    }
}
