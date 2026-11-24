//! Synthetic payload arrivals that pace block production.

use commonware_runtime::{
    Metrics,
    telemetry::metrics::{Gauge, GaugeExt as _, MetricsExt as _},
};
use serde::{Deserialize, Serialize};
use std::{
    num::NonZeroU64,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use thiserror::Error;

/// A benchmark schedule that cannot be replayed.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum ScheduleError {
    /// The schedule has no phases.
    #[error("input schedule requires at least one phase")]
    NoPhases,
    /// A phase has zero duration.
    #[error("input schedule phase duration must be positive")]
    EmptyPhase,
    /// A phase rate does not fit the rate gauge.
    #[error("input byte rate must fit in a gauge")]
    RateOverflow,
    /// The schedule end overflows a `u64` of milliseconds.
    #[error("input schedule duration overflow")]
    DurationOverflow,
    /// The scheduled byte count overflows.
    #[error("input schedule byte count overflow")]
    ByteOverflow,
    /// The schedule end does not fit the clock or the timestamp gauge.
    #[error("input schedule exceeds clock or timestamp gauge range")]
    ClockOverflow,
    /// The scheduled byte count does not fit the admitted-bytes gauge.
    #[error("input schedule byte count must fit in a gauge")]
    ByteGaugeOverflow,
}

/// Offered load was configured with empty block bodies.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
#[error("offered load requires nonempty block bodies")]
pub struct EmptyBody;

/// A finite byte arrival schedule that paces every producer during a benchmark.
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
    pub fn validate(&self) -> Result<(), ScheduleError> {
        if self.phases.is_empty() {
            return Err(ScheduleError::NoPhases);
        }
        let mut end_ms = self.start_unix_ms;
        let mut millibytes = 0u128;
        for phase in &self.phases {
            if phase.duration_ms == 0 {
                return Err(ScheduleError::EmptyPhase);
            }
            if phase.bytes_per_second > i64::MAX as u64 {
                return Err(ScheduleError::RateOverflow);
            }
            end_ms = end_ms
                .checked_add(phase.duration_ms)
                .ok_or(ScheduleError::DurationOverflow)?;
            millibytes = millibytes
                .checked_add(u128::from(phase.duration_ms) * u128::from(phase.bytes_per_second))
                .ok_or(ScheduleError::ByteOverflow)?;
        }
        if end_ms > i64::MAX as u64
            || UNIX_EPOCH
                .checked_add(Duration::from_millis(end_ms))
                .is_none()
        {
            return Err(ScheduleError::ClockOverflow);
        }
        if millibytes / 1_000 > i64::MAX as u128 {
            return Err(ScheduleError::ByteGaugeOverflow);
        }
        Ok(())
    }

    /// Returns the absolute start time.
    fn start(&self) -> SystemTime {
        UNIX_EPOCH + Duration::from_millis(self.start_unix_ms)
    }

    /// Returns the arrival rate of the phase containing `now`, or zero outside the schedule.
    fn rate_at(&self, now: SystemTime) -> u64 {
        let Ok(elapsed) = now.duration_since(self.start()) else {
            return 0;
        };
        let mut remaining = elapsed.as_millis();
        self.phases
            .iter()
            .find_map(|phase| {
                if remaining < u128::from(phase.duration_ms) {
                    Some(phase.bytes_per_second)
                } else {
                    remaining -= u128::from(phase.duration_ms);
                    None
                }
            })
            .unwrap_or(0)
    }

    /// Returns the arrival time of the `bytes`-th byte, or `None` if the schedule ends first.
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

/// How payload bytes arrive.
enum Arrivals {
    /// A constant rate that starts at the first proposal request.
    Constant(NonZeroU64),
    /// A finite schedule with an absolute start time.
    Scheduled(Schedule),
}

impl Arrivals {
    /// Returns the arrival time of the `bytes`-th byte counted from `origin`, or `None` once a
    /// finite schedule has ended.
    fn deadline(&self, bytes: u128, origin: SystemTime) -> Option<SystemTime> {
        match self {
            Self::Scheduled(schedule) => schedule.ready_at(bytes),
            Self::Constant(rate) => {
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
}

/// Where a workload's byte stream starts.
#[derive(Clone, Copy)]
struct Origin {
    /// First requested height, whose batch starts at byte position zero.
    height: u64,
    /// When the first byte may arrive.
    start: SystemTime,
}

/// Fixed-size input batches submitted at deadlines derived from a byte arrival schedule.
///
/// Heights identify input batches, so retrying a proposal does not consume new input.
/// The first requested height anchors byte position zero, including after a restart.
/// Constant load starts at that request; finite load uses its absolute start time.
/// Each complete batch is submitted atomically at its deadline. Backpressure leaves
/// submissions unchanged; no allocated transaction queue is needed.
pub struct Workload {
    arrivals: Arrivals,
    body_size: usize,
    origin: Option<Origin>,
    started: Gauge,
    admitted: Gauge,
    rate: Gauge,
}

impl Workload {
    /// Creates a constant-rate workload.
    pub fn new(
        context: &impl Metrics,
        bytes_per_second: NonZeroU64,
        body_size: usize,
    ) -> Result<Self, EmptyBody> {
        Self::with_arrivals(context, Arrivals::Constant(bytes_per_second), body_size)
    }

    /// Creates a workload that replays a finite schedule.
    ///
    /// The schedule must have passed [`Schedule::validate`].
    pub fn from_schedule(
        context: &impl Metrics,
        schedule: Schedule,
        body_size: usize,
    ) -> Result<Self, EmptyBody> {
        Self::with_arrivals(context, Arrivals::Scheduled(schedule), body_size)
    }

    fn with_arrivals(
        context: &impl Metrics,
        arrivals: Arrivals,
        body_size: usize,
    ) -> Result<Self, EmptyBody> {
        if body_size == 0 {
            return Err(EmptyBody);
        }
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
        Ok(Self {
            arrivals,
            body_size,
            origin: None,
            started,
            admitted: context.gauge(
                "input_admitted_bytes",
                "synthetic input byte position returned to consensus, excluding proposal retries",
            ),
            rate,
        })
    }

    /// Records a proposal request for `height` and returns the arrival time of its batch's last
    /// byte, or `None` once the schedule is exhausted.
    ///
    /// A final partial batch is never admitted. Delayed requests retain historical deadlines.
    pub fn request(&mut self, height: u64, now: SystemTime) -> Option<SystemTime> {
        self.observe(now);
        let origin = self.origin(height, now);
        // A recovered prefix below the first requested height is not part of this input stream.
        let Some(index) = height.checked_sub(origin.height) else {
            return Some(origin.start);
        };
        self.deadline(index, origin.start)
    }

    /// Records batch `height` as returned to consensus.
    pub fn admit(&self, height: u64) {
        let origin = self.origin.expect("input was scheduled before admission");
        if let Some(index) = height.checked_sub(origin.height) {
            self.admitted
                .try_set_max(self.batch_end(index))
                .expect("admitted input bytes must fit in a gauge");
        }
    }

    /// Publishes the offered rate at `now`.
    fn observe(&self, now: SystemTime) {
        if let Arrivals::Scheduled(schedule) = &self.arrivals {
            self.rate
                .try_set(schedule.rate_at(now))
                .expect("validated input rate");
        }
    }

    /// Anchors byte position zero at the first requested height.
    fn origin(&mut self, height: u64, now: SystemTime) -> Origin {
        if let Some(origin) = self.origin {
            return origin;
        }
        let start = match &self.arrivals {
            Arrivals::Constant(_) => now,
            Arrivals::Scheduled(schedule) => schedule.start(),
        };
        self.started
            .try_set(
                start
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis(),
            )
            .expect("input timestamp must fit in a gauge");
        *self.origin.insert(Origin { height, start })
    }

    /// Returns the arrival time of the last byte of batch `index`.
    fn deadline(&self, index: u64, origin: SystemTime) -> Option<SystemTime> {
        self.arrivals.deadline(self.batch_end(index), origin)
    }

    /// Returns the stream byte position just past batch `index`.
    fn batch_end(&self, index: u64) -> u128 {
        (u128::from(index) + 1) * self.body_size as u128
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

    /// Returns whole bytes arrived by an absolute time, capped at the schedule's end.
    fn arrived_bytes(schedule: &Schedule, now: SystemTime) -> u64 {
        let mut remaining = now
            .duration_since(schedule.start())
            .unwrap_or_default()
            .as_nanos();
        let mut byte_nanos = 0u128;
        for phase in &schedule.phases {
            let elapsed = remaining.min(u128::from(phase.duration_ms) * 1_000_000);
            byte_nanos += elapsed * u128::from(phase.bytes_per_second);
            remaining -= elapsed;
            if remaining == 0 {
                break;
            }
        }
        (byte_nanos / 1_000_000_000) as u64
    }

    #[test]
    fn multirate_gap_end_retries_and_backlog() {
        deterministic::Runner::default().start(|context| async move {
            let schedule = schedule(&[(1_000, 100), (1_000, 0), (1_000, 200), (1_000, 0)]);
            let mut workload = Workload::from_schedule(&context, schedule.clone(), 50).unwrap();
            assert_eq!(workload.started.get(), 10_000);
            assert_eq!(workload.request(11, at(3_500)), Some(at(500)));
            assert_eq!(workload.request(12, at(3_500)), Some(at(1_000)));
            assert_eq!(workload.request(13, at(3_500)), Some(at(2_250)));
            assert_eq!(workload.request(16, at(3_500)), Some(at(3_000)));
            assert_eq!(workload.request(17, at(3_500)), None);
            assert_eq!(workload.request(13, at(20_000)), Some(at(2_250)));
            workload.admit(12);
            workload.admit(11);
            workload.admit(12);
            assert_eq!(workload.admitted.get(), 100);
            assert_eq!(
                arrived_bytes(&schedule, at(2_500)).saturating_sub(workload.admitted.get() as u64),
                100
            );
            assert_eq!(workload.request(10, at(20_000)), Some(at(0)));
            workload.admit(10);
            assert_eq!(workload.admitted.get(), 100);
            assert_eq!(arrived_bytes(&schedule, UNIX_EPOCH), 0);
            assert_eq!(arrived_bytes(&schedule, at(1_500)), 100);
            assert_eq!(arrived_bytes(&schedule, at(20_000)), 300);
        });
    }

    #[test]
    fn scheduled_rate_gauge_follows_the_current_phase() {
        deterministic::Runner::default().start(|context| async move {
            let schedule = schedule(&[(1_000, 100), (1_000, 0), (1_000, 200)]);
            let mut workload = Workload::from_schedule(&context, schedule, 50).unwrap();
            workload.request(1, at(500));
            assert_eq!(workload.rate.get(), 100);
            workload.request(1, at(1_500));
            assert_eq!(workload.rate.get(), 0);
            workload.request(1, at(2_500));
            assert_eq!(workload.rate.get(), 200);
            workload.request(1, at(5_000));
            assert_eq!(workload.rate.get(), 0);
            workload.request(1, UNIX_EPOCH);
            assert_eq!(workload.rate.get(), 0);
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
        assert_eq!(arrived_bytes(&schedule, ready - Duration::from_nanos(1)), 0);
        assert_eq!(arrived_bytes(&schedule, ready), 1);
        assert_eq!(arrived_bytes(&schedule, at(1_000)), 0);
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
        let total = arrived_bytes(&schedule, at(10_000));
        for bytes in 1..=total {
            let deadline = schedule.ready_at(u128::from(bytes)).unwrap();
            assert_eq!(arrived_bytes(&decoded, deadline), bytes);
            assert_eq!(
                arrived_bytes(&decoded, deadline - Duration::from_nanos(1)),
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
            assert!(workload.request(1, at(0)).is_some());
            assert_eq!(workload.request(2, at(0)), None);
            assert_eq!(workload.request(u64::MAX, at(0)), None);
        });
    }

    #[test]
    fn invalid_schedules_are_rejected() {
        let single = |start_unix_ms| Schedule {
            start_unix_ms,
            phases: vec![Phase {
                duration_ms: 1,
                bytes_per_second: 1,
            }],
        };
        for (schedule, error) in [
            (schedule(&[]), ScheduleError::NoPhases),
            (schedule(&[(0, 1)]), ScheduleError::EmptyPhase),
            (schedule(&[(u64::MAX, 1)]), ScheduleError::DurationOverflow),
            (schedule(&[(1, u64::MAX)]), ScheduleError::RateOverflow),
            (
                schedule(&[(2_000, i64::MAX as u64)]),
                ScheduleError::ByteGaugeOverflow,
            ),
            (single(u64::MAX), ScheduleError::DurationOverflow),
            (single(i64::MAX as u64), ScheduleError::ClockOverflow),
        ] {
            assert_eq!(schedule.validate(), Err(error));
        }
        assert!(
            serde_yaml::from_str::<Schedule>(
                "start_unix_ms: 0\nphases:\n- duration_ms: 1\n  bytes_per_second: -1"
            )
            .is_err()
        );
    }

    #[test]
    fn offered_load_rejects_empty_bodies() {
        deterministic::Runner::default().start(|context| async move {
            assert_eq!(
                Workload::from_schedule(&context, schedule(&[(1_000, 1)]), 0).err(),
                Some(EmptyBody)
            );
            assert_eq!(Workload::new(&context, NZU64!(1), 0).err(), Some(EmptyBody));
        });
    }

    #[test]
    fn constant_arrivals_are_stable_without_accumulated_rounding() {
        deterministic::Runner::default().start(|context| async move {
            let mut workload = Workload::new(&context, NZU64!(3), 1).unwrap();
            assert_eq!(
                workload.request(1, at(0)),
                Some(at(0) + Duration::from_nanos(333_333_334))
            );
            assert_eq!(
                workload.request(2, at(50_000)),
                Some(at(0) + Duration::from_nanos(666_666_667))
            );
            assert_eq!(workload.request(3, at(50_000)), Some(at(1_000)));
            assert_eq!(
                workload.request(1, at(50_000)),
                Some(at(0) + Duration::from_nanos(333_333_334))
            );
            assert_eq!(workload.request(3_000_000, at(0)), Some(at(1_000_000_000)));
            assert_eq!(workload.started.get(), 10_000);
            workload.admit(2);
            workload.admit(1);
            assert_eq!(workload.admitted.get(), 2);
        });
    }
}
