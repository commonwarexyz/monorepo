//! Monotonic nanosecond time for sleep deadlines.
//!
//! A time is a `u64` count of nanoseconds since one [`Instant`] origin, plus
//! one. The origin is taken on first use and shared by every worker and
//! runtime in the process, and the offset keeps zero free to mark a thread
//! that never ran a worker service pass. Every deadline and every service
//! time goes through the same mapping, so they compare consistently.
//! Conversions are exact inverses for times from one to [`MAX`], which are
//! the instants from the origin until `MAX - 1` nanoseconds after it.
//! Earlier instants convert to the origin's time and later ones saturate at
//! [`MAX`]. Times are private to the process and never reach the kernel.

use std::{
    cell::Cell,
    sync::OnceLock,
    time::{Duration, Instant},
};

/// Latest representable time, about 292 years after the origin: the signed
/// 64-bit nanosecond range, rounded down to a multiple of the sleep wheel's
/// 1024 ns tick, so a rounded deadline never exceeds it and a saturated clock
/// still reaches it.
pub const MAX: u64 = (i64::MAX as u64) & !1023;

/// The process's origin, taken on first use.
fn origin() -> Instant {
    /// The origin shared by every worker and runtime in the process.
    static ORIGIN: OnceLock<Instant> = OnceLock::new();
    *ORIGIN.get_or_init(Instant::now)
}

/// The time of `instant`, saturating at [`MAX`]. Instants before the origin
/// convert to the origin's time, one.
#[inline]
pub fn nanos(instant: Instant) -> u64 {
    let since = instant.saturating_duration_since(origin());
    since
        .as_secs()
        .saturating_mul(1_000_000_000)
        .saturating_add(u64::from(since.subsec_nanos()))
        .saturating_add(1)
        .min(MAX)
}

/// The current time.
#[inline]
pub fn now() -> u64 {
    nanos(Instant::now())
}

/// The deadline `duration` from now, saturating at [`MAX`].
#[inline]
pub fn after(duration: Duration) -> u64 {
    let duration = u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX);
    now().saturating_add(duration).min(MAX)
}

/// The instant of `nanos`, or `None` for `u64::MAX` (no deadline) and times
/// beyond the range of [`Instant`].
#[inline]
pub fn instant(nanos: u64) -> Option<Instant> {
    if nanos == u64::MAX {
        return None;
    }
    origin().checked_add(Duration::from_nanos(nanos.saturating_sub(1)))
}

thread_local! {
    /// Time of this thread's latest worker service pass, zero on a thread
    /// that never ran one.
    static TURN: Cell<u64> = const { Cell::new(0) };
}

/// Record the time of this worker's service pass.
#[inline]
pub fn set_turn(nanos: u64) {
    TURN.set(nanos);
}

/// The time of this thread's latest worker service pass, never later than
/// the true time, or zero on a thread that never ran a worker.
#[inline]
pub fn turn() -> u64 {
    TURN.get()
}

#[cfg(test)]
#[commonware_macros::test_group("miri")]
mod tests {
    use super::*;

    #[test]
    fn test_conversions_are_exact_inverses() {
        // The origin's time is one, and so is any earlier instant's.
        let origin = origin();
        assert_eq!(nanos(origin), 1);
        assert_eq!(instant(1), Some(origin));
        if let Some(earlier) = origin.checked_sub(Duration::from_secs(1)) {
            assert_eq!(nanos(earlier), 1);
        }

        // Later instants round trip exactly.
        let start = Instant::now();
        for offset in [0, 1, 999, 1_000_000_007, 3_600_000_000_000] {
            let at = start + Duration::from_nanos(offset);
            let nanos = nanos(at);
            assert_eq!(instant(nanos), Some(at));
            assert_eq!(super::nanos(instant(nanos).unwrap()), nanos);
        }

        // `u64::MAX`, which means no deadline, has no instant, and the clock
        // never trails an instant read before it.
        assert_eq!(instant(u64::MAX), None);
        assert!(now() >= nanos(start));
    }

    #[test]
    fn test_deadlines_saturate_at_the_end_of_time() {
        // The longest duration saturates to the end of time, a whole number
        // of sleep timer ticks.
        assert_eq!(after(Duration::MAX), MAX);
        assert_eq!(MAX % 1024, 0);

        // A finite deadline lies its duration after the clock reads around it.
        let before = now();
        let deadline = after(Duration::from_millis(5));
        assert!(deadline >= before + 5_000_000);
        assert!(deadline <= now() + 5_000_000);
    }

    #[test]
    fn test_turn_is_per_thread() {
        // Another thread sees no turn time set on this one.
        set_turn(42);
        assert_eq!(turn(), 42);
        std::thread::spawn(|| assert_eq!(turn(), 0)).join().unwrap();

        // Reset the turn time so later tests on this thread see none.
        set_turn(0);
    }
}
