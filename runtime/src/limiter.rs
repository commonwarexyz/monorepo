//! Rate limiting with the generic cell rate algorithm (GCRA).
//!
//! A [Quota] admits up to [Quota::burst_size] cells at once and replenishes one cell every
//! [Quota::replenish_interval]. A new [RateLimiter], and each key first seen by a
//! [KeyedRateLimiter], starts with a full burst.
//!
//! Limiters measure time by accumulating the elapsed time between successive [Clock::current]
//! reads. A backward wall-clock step counts as zero elapsed time rather than stalling admission
//! for its length, and a forward jump refills at most one burst.

use crate::Clock;
use commonware_utils::{DurationExt as _, SystemTimeExt as _, time::NANOS_PER_SEC};
use std::{
    collections::HashMap,
    future::pending,
    hash::Hash,
    num::NonZeroU32,
    time::{Duration, SystemTime},
};

/// The rate and burst size admitted by a rate limiter.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Quota {
    interval: Duration,
    burst: NonZeroU32,
}

impl Quota {
    /// Admits `max_burst` cells per `seconds` with a burst of `max_burst`, replenishing at most
    /// one cell per nanosecond.
    const fn per_period(seconds: u64, max_burst: NonZeroU32) -> Self {
        let mut nanos = seconds as u128 * NANOS_PER_SEC / max_burst.get() as u128;
        if nanos == 0 {
            nanos = 1;
        }
        Self {
            interval: Duration::from_nanos(nanos as u64),
            burst: max_burst,
        }
    }

    /// Admits `max_burst` cells per second with a burst of `max_burst`.
    ///
    /// The replenish interval is rounded down to whole nanoseconds, with a minimum of one
    /// nanosecond.
    pub const fn per_second(max_burst: NonZeroU32) -> Self {
        Self::per_period(1, max_burst)
    }

    /// Admits `max_burst` cells per minute with a burst of `max_burst`.
    pub const fn per_minute(max_burst: NonZeroU32) -> Self {
        Self::per_period(60, max_burst)
    }

    /// Admits `max_burst` cells per hour with a burst of `max_burst`.
    pub const fn per_hour(max_burst: NonZeroU32) -> Self {
        Self::per_period(3_600, max_burst)
    }

    /// Replenishes one cell every `period` with a burst of one, or returns `None` if `period`
    /// is zero.
    pub const fn with_period(period: Duration) -> Option<Self> {
        if period.is_zero() {
            return None;
        }
        Some(Self {
            interval: period,
            burst: NonZeroU32::MIN,
        })
    }

    /// Returns this quota with a burst of `max_burst` cells.
    pub const fn allow_burst(self, max_burst: NonZeroU32) -> Self {
        Self {
            interval: self.interval,
            burst: max_burst,
        }
    }

    /// Returns the maximum number of cells admitted at once.
    pub const fn burst_size(&self) -> NonZeroU32 {
        self.burst
    }

    /// Returns the time to replenish one cell.
    pub const fn replenish_interval(&self) -> Duration {
        self.interval
    }
}

/// Clock reads and GCRA parameters shared by direct and keyed limiters.
///
/// Times are nanoseconds of accumulated elapsed time since creation.
struct Gcra<C: Clock> {
    clock: C,
    /// Nanoseconds to replenish one cell.
    interval: u128,
    /// Nanoseconds to replenish a full burst.
    capacity: u128,
    /// Last [Clock::current] read.
    last: SystemTime,
    /// Nanoseconds accumulated over forward steps between reads.
    elapsed: u128,
}

impl<C: Clock> Gcra<C> {
    fn new(quota: Quota, clock: C) -> Self {
        let interval = quota.interval.as_nanos();
        let last = clock.current();
        Self {
            clock,
            interval,
            // Cannot overflow: at most (2^64 * 10^9) * 2^32 < 2^128
            capacity: interval * quota.burst.get() as u128,
            last,
            elapsed: 0,
        }
    }

    /// Reads the clock, treating a backward step as zero elapsed.
    fn now(&mut self) -> u128 {
        let current = self.clock.current();
        if let Ok(step) = current.duration_since(self.last) {
            self.elapsed = self.elapsed.saturating_add(step.as_nanos());
        }
        self.last = current;
        self.elapsed
    }

    /// Returns the theoretical arrival time after admitting one cell at `now`, or the time to
    /// wait until one can be admitted.
    fn admit(&self, tat: u128, now: u128) -> Result<u128, Duration> {
        let next = tat.max(now).saturating_add(self.interval);
        let allowed = now.saturating_add(self.capacity);
        if next <= allowed {
            return Ok(next);
        }
        Err(Duration::from_nanos_saturating(next - allowed))
    }

    /// Converts a wait from the last clock read to a retry time, saturating at the clock limit.
    fn not_until(&self, wait: Duration) -> SystemTime {
        self.last.saturating_add_ext(wait)
    }
}

/// A rate limiter for a single entity.
pub struct RateLimiter<C: Clock> {
    gcra: Gcra<C>,
    tat: u128,
}

impl<C: Clock> RateLimiter<C> {
    /// Creates a limiter that starts with a full burst.
    pub fn new(quota: Quota, clock: C) -> Self {
        Self {
            gcra: Gcra::new(quota, clock),
            tat: 0,
        }
    }

    fn admit(&mut self) -> Result<(), Duration> {
        let now = self.gcra.now();
        self.tat = self.gcra.admit(self.tat, now)?;
        Ok(())
    }

    /// Admits and charges one cell, or returns the earliest time one can be admitted.
    ///
    /// A rejected check charges nothing. The retry time saturates at the clock limit.
    pub fn check(&mut self) -> Result<(), SystemTime> {
        self.admit().map_err(|wait| self.gcra.not_until(wait))
    }

    /// Waits until one cell can be admitted and charges it.
    ///
    /// A backward clock step between checking admission and registering the sleep can delay
    /// the wake. Admission is checked again after waking.
    ///
    /// If the clock reaches its maximum representable time before a cell is ready, this
    /// future stays pending. Cancel it and retry to observe any subsequent clock correction.
    pub async fn until_ready(&mut self) {
        while let Err(wait) = self.admit() {
            let now = self.gcra.last;
            let deadline = self.gcra.not_until(wait);
            if deadline == now {
                return pending().await;
            }
            self.gcra.clock.sleep_until(deadline).await;
        }
    }
}

/// A rate limiter that tracks each key independently.
///
/// Keys are stored with a randomized hasher, to resist collisions from attacker-chosen keys.
/// Call [KeyedRateLimiter::retain_recent] periodically to drop keys with a full burst available.
pub struct KeyedRateLimiter<K, C: Clock> {
    gcra: Gcra<C>,
    tats: HashMap<K, u128>,
}

impl<K: Hash + Eq + Clone, C: Clock> KeyedRateLimiter<K, C> {
    /// Creates a limiter in which every key starts with a full burst.
    pub fn new(quota: Quota, clock: C) -> Self {
        Self {
            gcra: Gcra::new(quota, clock),
            tats: HashMap::new(),
        }
    }

    /// Admits and charges one cell for `key`, or returns the earliest time one can be admitted.
    ///
    /// A rejected check charges nothing. The retry time saturates at the clock limit.
    pub fn check_key(&mut self, key: &K) -> Result<(), SystemTime> {
        let now = self.gcra.now();
        let gcra = &self.gcra;
        match self.tats.get_mut(key) {
            Some(tat) => *tat = gcra.admit(*tat, now).map_err(|wait| gcra.not_until(wait))?,
            None => {
                let next = gcra.admit(0, now).map_err(|wait| gcra.not_until(wait))?;
                self.tats.insert(key.clone(), next);
            }
        }
        Ok(())
    }

    /// Returns what [KeyedRateLimiter::check_key] would return for `key` now, without charging.
    pub fn check_key_available(&mut self, key: &K) -> Result<(), SystemTime> {
        let now = self.gcra.now();
        let tat = self.tats.get(key).copied().unwrap_or(0);
        match self.gcra.admit(tat, now) {
            Ok(_) => Ok(()),
            Err(wait) => Err(self.gcra.not_until(wait)),
        }
    }

    /// Drops every key with a full burst available and releases excess capacity.
    pub fn retain_recent(&mut self) {
        let now = self.gcra.now();
        self.tats.retain(|_, tat| *tat > now);
        let len = self.tats.len();
        if self.tats.capacity() > 4 * len.max(4) {
            self.tats.shrink_to(2 * len);
        }
    }

    /// Returns the number of tracked keys.
    pub fn len(&self) -> usize {
        self.tats.len()
    }

    /// Returns whether no keys are tracked.
    pub fn is_empty(&self) -> bool {
        self.tats.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Runner as _, Supervisor as _, deterministic};
    use commonware_utils::{NZU32, sync::Mutex};
    use rstest::rstest;
    use std::{
        future::{Future, ready},
        pin::pin,
        sync::Arc,
        task::{Context, Waker},
    };

    /// A clock with a configurable delay between reading the time and registering a sleep.
    #[derive(Clone)]
    struct ManualClock {
        time: Arc<Mutex<SystemTime>>,
        registration_delay: Duration,
    }

    impl ManualClock {
        fn new(time: SystemTime) -> Self {
            Self {
                time: Arc::new(Mutex::new(time)),
                registration_delay: Duration::ZERO,
            }
        }

        fn set(&self, time: SystemTime) {
            *self.time.lock() = time;
        }

        fn advance(&self, step: Duration) {
            let mut time = self.time.lock();
            *time += step;
        }

        fn rewind(&self, step: Duration) {
            let mut time = self.time.lock();
            *time -= step;
        }
    }

    impl Clock for ManualClock {
        fn current(&self) -> SystemTime {
            *self.time.lock()
        }

        fn sleep(&self, duration: Duration) -> impl Future<Output = ()> + Send + 'static + use<> {
            assert!(
                !duration.is_zero(),
                "a rejected admission must not request a zero sleep"
            );
            self.advance(self.registration_delay);
            self.advance(duration);
            ready(())
        }

        fn sleep_until(
            &self,
            deadline: SystemTime,
        ) -> impl Future<Output = ()> + Send + 'static + use<> {
            self.advance(self.registration_delay);
            assert!(
                deadline > self.current(),
                "a rejected admission must sleep until a future deadline"
            );
            self.set(deadline);
            ready(())
        }
    }

    const START: SystemTime = SystemTime::UNIX_EPOCH;

    #[test]
    fn test_quota_constructors() {
        let quota = Quota::per_second(NZU32!(4));
        assert_eq!(quota.burst_size(), NZU32!(4));
        assert_eq!(quota.replenish_interval(), Duration::from_millis(250));
        assert_eq!(
            Quota::per_minute(NZU32!(2)).replenish_interval(),
            Duration::from_secs(30)
        );
        assert_eq!(
            Quota::per_hour(NZU32!(3)).replenish_interval(),
            Duration::from_secs(1_200)
        );
        assert_eq!(
            Quota::per_second(NZU32!(3)).replenish_interval(),
            Duration::from_nanos(333_333_333)
        );
        assert_eq!(
            Quota::per_second(NonZeroU32::MAX).replenish_interval(),
            Duration::from_nanos(1)
        );
        assert_eq!(Quota::with_period(Duration::ZERO), None);
        let quota = Quota::with_period(Duration::from_secs(2))
            .unwrap()
            .allow_burst(NZU32!(5));
        assert_eq!(quota.burst_size(), NZU32!(5));
        assert_eq!(quota.replenish_interval(), Duration::from_secs(2));
    }

    #[test]
    fn test_full_burst_then_reject_without_charge() {
        let clock = ManualClock::new(START);
        let mut limiter = RateLimiter::new(Quota::per_second(NZU32!(4)), clock.clone());
        for _ in 0..4 {
            limiter.check().unwrap();
        }
        let earliest = START + Duration::from_millis(250);
        assert_eq!(limiter.check(), Err(earliest));
        assert_eq!(limiter.check(), Err(earliest));

        // Rejections charged nothing, so one cell replenishes after one interval
        clock.advance(Duration::from_millis(249));
        assert_eq!(limiter.check(), Err(earliest));
        clock.advance(Duration::from_millis(1));
        limiter.check().unwrap();
        assert_eq!(limiter.check(), Err(START + Duration::from_millis(500)));
    }

    #[test]
    fn test_forward_jump_refills_one_burst() {
        let clock = ManualClock::new(START);
        let mut limiter = RateLimiter::new(Quota::per_second(NZU32!(2)), clock.clone());
        limiter.check().unwrap();
        limiter.check().unwrap();
        limiter.check().unwrap_err();

        clock.advance(Duration::from_secs(3_600));
        limiter.check().unwrap();
        limiter.check().unwrap();
        assert_eq!(
            limiter.check(),
            Err(START + Duration::from_secs(3_600) + Duration::from_millis(500))
        );
    }

    #[test]
    fn test_backward_step_counts_as_zero_elapsed() {
        let clock = ManualClock::new(START + Duration::from_secs(1_000));
        let mut limiter = RateLimiter::new(Quota::per_second(NZU32!(10)), clock.clone());
        for _ in 0..10 {
            limiter.check().unwrap();
        }
        limiter.check().unwrap_err();

        // A backward step neither refills nor stalls for its length
        clock.rewind(Duration::from_secs(60));
        let stepped = START + Duration::from_secs(940);
        assert_eq!(limiter.check(), Err(stepped + Duration::from_millis(100)));
        clock.advance(Duration::from_millis(100));
        limiter.check().unwrap();
        limiter.check().unwrap_err();

        // A step back before the creation time behaves the same
        clock.set(START);
        assert_eq!(limiter.check(), Err(START + Duration::from_millis(100)));
        clock.advance(Duration::from_millis(100));
        limiter.check().unwrap();
    }

    #[test]
    fn test_sub_nanosecond_rate_clamps_to_one_nanosecond() {
        let clock = ManualClock::new(START);
        let mut limiter = RateLimiter::new(Quota::per_second(NonZeroU32::MAX), clock.clone());
        for _ in 0..10_000 {
            limiter.check().unwrap();
        }

        let quota = Quota::per_second(NonZeroU32::MAX).allow_burst(NZU32!(1));
        let mut limiter = RateLimiter::new(quota, clock.clone());
        limiter.check().unwrap();
        assert_eq!(limiter.check(), Err(START + Duration::from_nanos(1)));
        clock.advance(Duration::from_nanos(1));
        limiter.check().unwrap();
        limiter.check().unwrap_err();
    }

    #[test]
    fn test_extreme_quota_does_not_overflow() {
        let clock = ManualClock::new(START);
        let quota = Quota::with_period(Duration::MAX)
            .unwrap()
            .allow_burst(NonZeroU32::MAX);
        let mut limiter = RateLimiter::new(quota, clock.clone());
        limiter.check().unwrap();

        // Admits the full burst rather than wrapping the burst capacity
        let mut keyed = KeyedRateLimiter::new(
            Quota::with_period(Duration::from_secs(3_600))
                .unwrap()
                .allow_burst(NonZeroU32::MAX),
            clock.clone(),
        );
        for _ in 0..1_000_000 {
            keyed.check_key(&0u8).unwrap();
        }

        // The earliest time saturates when it is not representable
        let quota = Quota::with_period(Duration::MAX).unwrap();
        let mut limiter = RateLimiter::new(quota, clock);
        limiter.check().unwrap();
        assert_eq!(limiter.check(), Err(SystemTime::limit()));
    }

    #[test]
    fn test_large_elapsed_time_refills_one_burst() {
        let clock = ManualClock::new(START);
        let interval = Duration::from_nanos(u64::MAX) + Duration::from_nanos(2);
        let quota = Quota::with_period(interval).unwrap().allow_burst(NZU32!(2));
        let mut limiter = RateLimiter::new(quota, clock.clone());
        limiter.check().unwrap();
        limiter.check().unwrap();
        limiter.check().unwrap_err();

        // Advance the same limiter by more than a u64 can represent in nanoseconds.
        clock.advance(interval * 2);
        limiter.check().unwrap();
        limiter.check().unwrap();
        assert_eq!(limiter.check(), Err(START + interval * 3));
    }

    #[test]
    fn test_keyed_independent_keys() {
        let clock = ManualClock::new(START);
        let mut limiter = KeyedRateLimiter::new(Quota::per_second(NZU32!(2)), clock);
        assert!(limiter.is_empty());
        limiter.check_key(&1u32).unwrap();
        limiter.check_key(&1).unwrap();
        assert_eq!(
            limiter.check_key(&1),
            Err(START + Duration::from_millis(500))
        );

        // A new key starts with a full burst
        limiter.check_key(&2).unwrap();
        limiter.check_key(&2).unwrap();
        limiter.check_key(&2).unwrap_err();
        assert_eq!(limiter.len(), 2);
    }

    #[test]
    fn test_keyed_available_does_not_charge() {
        let clock = ManualClock::new(START);
        let mut limiter = KeyedRateLimiter::new(Quota::per_second(NZU32!(1)), clock.clone());
        limiter.check_key_available(&1u32).unwrap();
        limiter.check_key_available(&1).unwrap();
        assert!(limiter.is_empty());
        limiter.check_key(&1).unwrap();
        let earliest = START + Duration::from_secs(1);
        assert_eq!(limiter.check_key_available(&1), Err(earliest));
        assert_eq!(limiter.check_key(&1), Err(earliest));
        clock.advance(Duration::from_secs(1));
        limiter.check_key_available(&1).unwrap();
        limiter.check_key(&1).unwrap();
    }

    #[test]
    fn test_retain_recent_drops_refilled_keys() {
        let clock = ManualClock::new(START);
        let mut limiter = KeyedRateLimiter::new(Quota::per_second(NZU32!(2)), clock.clone());
        limiter.check_key(&1u32).unwrap();
        clock.advance(Duration::from_millis(250));
        limiter.check_key(&2).unwrap();
        limiter.check_key(&2).unwrap();

        // Key 1 refills at 500ms and key 2 at 1250ms
        clock.advance(Duration::from_millis(249));
        limiter.retain_recent();
        assert_eq!(limiter.len(), 2);
        clock.advance(Duration::from_millis(1));
        limiter.retain_recent();
        assert_eq!(limiter.len(), 1);
        clock.advance(Duration::from_millis(750));
        limiter.retain_recent();
        assert!(limiter.is_empty());
    }

    #[test]
    fn test_retain_recent_releases_capacity() {
        let clock = ManualClock::new(START);
        let mut limiter = KeyedRateLimiter::new(Quota::per_second(NZU32!(1)), clock.clone());
        for key in 0..10_000u32 {
            limiter.check_key(&key).unwrap();
        }
        clock.advance(Duration::from_secs(1));
        limiter.retain_recent();
        assert!(limiter.is_empty());
        assert!(limiter.tats.capacity() < 100);
    }

    #[test]
    fn test_until_ready_waits_and_charges() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let start = context.current();
            let mut limiter =
                RateLimiter::new(Quota::per_second(NZU32!(2)), context.child("limiter"));
            limiter.until_ready().await;
            limiter.until_ready().await;
            assert_eq!(context.current(), start);

            limiter.until_ready().await;
            assert_eq!(context.current(), start + Duration::from_millis(500));
            limiter.until_ready().await;
            assert_eq!(context.current(), start + Duration::from_secs(1));
            assert_eq!(limiter.check(), Err(start + Duration::from_millis(1_500)));
        });
    }

    #[rstest]
    #[case::deterministic(deterministic::Runner::default())]
    #[cfg_attr(
        not(target_arch = "wasm32"),
        case::tokio(crate::tokio::Runner::default())
    )]
    #[cfg_attr(target_os = "linux", case::iouring(crate::iouring::Runner::default()))]
    fn test_until_ready_bounds_unrepresentable_wait<R: crate::Runner>(#[case] executor: R)
    where
        R::Context: Clock,
    {
        executor.start(|context| async move {
            let quota = Quota::with_period(Duration::MAX).unwrap();
            let mut limiter = RateLimiter::new(quota, context);
            limiter.until_ready().await;

            let mut wait = pin!(limiter.until_ready());
            assert!(
                wait.as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_pending()
            );
        });
    }

    #[test]
    fn test_until_ready_registers_at_sampled_deadline() {
        let ceiling = SystemTime::limit();
        let period = Duration::from_nanos(5);
        let clock = ManualClock {
            registration_delay: Duration::from_nanos(1),
            ..ManualClock::new(ceiling - period)
        };
        let mut limiter = RateLimiter::new(Quota::with_period(period).unwrap(), clock.clone());
        limiter.check().unwrap();

        let mut wait = pin!(limiter.until_ready());
        assert!(
            wait.as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_ready()
        );
        assert_eq!(clock.current(), ceiling);
    }

    #[test]
    fn test_until_ready_parks_at_clock_limit_without_charge() {
        let ceiling = SystemTime::limit();
        let period = Duration::from_nanos(5);
        let clock = ManualClock::new(ceiling - Duration::from_nanos(3));
        let mut limiter = RateLimiter::new(Quota::with_period(period).unwrap(), clock.clone());
        limiter.check().unwrap();
        assert_eq!(limiter.check(), Err(ceiling));

        // A ready test sleeper takes the wait to the ceiling in the first poll. Its
        // assertions fail if the limiter tries to sleep again without making progress.
        {
            let mut wait = pin!(limiter.until_ready());
            assert!(
                wait.as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_pending()
            );
            assert_eq!(clock.current(), ceiling);
        }

        // Dropping the pending wait leaves only the original charge in place.
        assert_eq!(limiter.check(), Err(ceiling));
        clock.rewind(Duration::from_nanos(2));
        limiter.check().unwrap_err();
        clock.set(ceiling);
        limiter.check().unwrap();
        assert_eq!(limiter.check(), Err(ceiling));
    }
}
