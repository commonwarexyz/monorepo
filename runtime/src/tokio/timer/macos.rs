//! macOS native alarm backed by one private `kqueue` per scheduler shard.
//!
//! Each alarm owns its descriptor, Tokio reactor registration, and a copy of
//! the process-wide validated Mach timebase. A fixed timer identifier is safe
//! because every shard has a distinct `kqueue`. Arms install an absolute,
//! critical, one-shot Mach timer.
//!
//! Conversions are directed so a timer never fires early. Clock observations
//! round Mach ticks up to integral nanoseconds, arms round nanoseconds up to
//! Mach ticks, and the maximum positive `kevent` data value is converted down
//! to a representable deadline.
//!
//! Producers may read the clock concurrently. One shard driver serializes arm,
//! disarm, and wait operations. Relaxed `installed` bookkeeping distinguishes
//! an expected missing one-shot event from a recorded timer that disappeared.
//! Readiness retrieval validates the private event and `EV_ERROR`, then drains
//! the `kqueue` until `WouldBlock` so Tokio can clear cached readiness.
//!
//! Descriptor and timebase setup failures panic before user execution. Live
//! conversion, alarm, descriptor, and readiness errors return to the
//! scheduler's fatal failure path.

use super::scheduler::{Alarm, Deadline};
use std::{
    io,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    sync::{
        OnceLock,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::io::{Interest, unix::AsyncFd};

/// Nanoseconds in one second.
const NANOS_PER_SECOND: u128 = 1_000_000_000;

/// One fixed timer identifier in each independently owned kqueue.
const TIMER_IDENT: libc::uintptr_t = 1;

/// Process-wide validated conversion ratio.
static TIMEBASE: OnceLock<Timebase> = OnceLock::new();

/// One kqueue descriptor with a Mach absolute one-shot timer.
pub(super) struct NativeAlarm {
    /// Owned descriptor and Tokio reactor registration.
    descriptor: AsyncFd<OwnedFd>,
    /// Conversion ratio returned by the Mach timebase.
    timebase: Timebase,
    /// Whether one timer event is known to be installed.
    installed: AtomicBool,
}

impl NativeAlarm {
    /// Creates and registers one kqueue with the active Tokio reactor.
    pub(super) fn new() -> Self {
        let timebase = Timebase::get();
        let raw = retry_interrupted(|| {
            // SAFETY: `kqueue` takes no pointers and returns a new descriptor.
            unsafe { libc::kqueue() }
        })
        .unwrap_or_else(|error| panic!("failed to create kqueue: {error}"));

        // SAFETY: `raw` is a fresh descriptor whose ownership has not moved.
        let descriptor = unsafe { OwnedFd::from_raw_fd(raw) };

        // Ownership is established before fallible setup so every error closes
        // the newly created descriptor.
        let raw = descriptor.as_raw_fd();
        let flags = retry_interrupted(|| {
            // SAFETY: `raw` is live and F_GETFD uses no variadic argument.
            unsafe { libc::fcntl(raw, libc::F_GETFD) }
        })
        .unwrap_or_else(|error| panic!("failed to read kqueue descriptor flags: {error}"));
        retry_interrupted(|| {
            // SAFETY: `raw` is live and the variadic argument is an integer flag set.
            unsafe { libc::fcntl(raw, libc::F_SETFD, flags | libc::FD_CLOEXEC) }
        })
        .unwrap_or_else(|error| panic!("failed to set kqueue close-on-exec: {error}"));

        let descriptor =
            AsyncFd::with_interest(descriptor, Interest::READABLE).unwrap_or_else(|error| {
                panic!("failed to register kqueue with Tokio reactor: {error}")
            });

        Self {
            descriptor,
            timebase,
            installed: AtomicBool::new(false),
        }
    }

    /// Applies one change to the private kqueue timer.
    fn update(&self, flags: u16, fflags: u32, data: libc::intptr_t) -> io::Result<()> {
        let change = libc::kevent {
            ident: TIMER_IDENT,
            filter: libc::EVFILT_TIMER,
            flags,
            fflags,
            data,
            udata: std::ptr::null_mut(),
        };
        let descriptor = self.descriptor.get_ref().as_raw_fd();
        retry_interrupted(|| {
            // SAFETY: `change` is one initialized event and no output buffer is requested.
            unsafe {
                libc::kevent(
                    descriptor,
                    &change,
                    1,
                    std::ptr::null_mut(),
                    0,
                    std::ptr::null(),
                )
            }
        })?;
        Ok(())
    }
}

impl Alarm for NativeAlarm {
    fn max_deadline(&self) -> Deadline {
        // kqueue carries the absolute Mach deadline through its intptr_t data
        // field. Stay within its positive range instead of relying on signed-bit
        // reinterpretation. Rounding down keeps conversion back to ticks within
        // that range. Duration::MAX is used only when it is the smaller limit.
        let max_ticks =
            u64::try_from(libc::intptr_t::MAX).expect("intptr_t maximum must be nonnegative");
        Deadline::from_duration(
            self.timebase
                .ticks_to_duration(max_ticks, false)
                .unwrap_or(Duration::MAX),
        )
    }

    fn now(&self) -> io::Result<Deadline> {
        // SAFETY: `mach_absolute_time` takes no arguments and cannot write memory.
        #[allow(deprecated)]
        let ticks = unsafe { libc::mach_absolute_time() };
        // Rounding the construction-time observation upward prevents a relative
        // duration from inheriting a fractional-nanosecond head start.
        self.timebase
            .ticks_to_duration(ticks, true)
            .map(Deadline::from_duration)
    }

    fn arm(&self, deadline: Deadline) -> io::Result<()> {
        // Both conversions round upward so neither fractional nanoseconds nor
        // fractional Mach ticks can make an alarm fire early.
        let ticks = self.timebase.duration_to_ticks_up(deadline.as_duration())?;
        let data = libc::intptr_t::try_from(ticks).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "Mach deadline exceeds kqueue data range",
            )
        })?;
        self.update(
            libc::EV_ADD | libc::EV_ENABLE | libc::EV_ONESHOT,
            libc::NOTE_ABSOLUTE | libc::NOTE_MACHTIME | libc::NOTE_CRITICAL,
            data,
        )?;
        // One driver serializes alarm operations. The atomic supplies Sync
        // storage for the trait boundary rather than cross-thread ordering.
        self.installed.store(true, Ordering::Relaxed);
        Ok(())
    }

    fn disarm(&self) -> io::Result<()> {
        // Alarm operations are driver-serialized, so no memory publication is
        // coupled to this bookkeeping transition.
        let installed = self.installed.swap(false, Ordering::Relaxed);
        match self.update(libc::EV_DELETE, 0, 0) {
            Ok(()) => Ok(()),
            Err(error) if error.raw_os_error() == Some(libc::ENOENT) && !installed => {
                // Startup, repeated disarm, and consumed EV_ONESHOT events have
                // no recorded registration, so absence is expected.
                Ok(())
            }
            // ENOENT with a recorded timer means its registration disappeared
            // before retrieval and remains an invariant violation.
            Err(error) => Err(error),
        }
    }

    async fn wait(&self) -> io::Result<()> {
        loop {
            let mut readiness = self.descriptor.readable().await?;
            let mut consumed = false;
            loop {
                match readiness.try_io(|inner| {
                    let mut event = libc::kevent {
                        ident: TIMER_IDENT,
                        filter: libc::EVFILT_TIMER,
                        flags: 0,
                        fflags: 0,
                        data: 0,
                        udata: std::ptr::null_mut(),
                    };
                    let timeout = libc::timespec {
                        tv_sec: 0,
                        tv_nsec: 0,
                    };
                    let result = retry_interrupted(|| {
                        // SAFETY: `event` is writable output storage and
                        // `timeout` makes retrieval nonblocking.
                        unsafe {
                            libc::kevent(
                                inner.get_ref().as_raw_fd(),
                                std::ptr::null(),
                                0,
                                &mut event,
                                1,
                                &timeout,
                            )
                        }
                    })?;
                    match result {
                        0 => Err(io::Error::from(io::ErrorKind::WouldBlock)),
                        1 => validate_event(&event),
                        _ => Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "kqueue returned an invalid event count",
                        )),
                    }
                }) {
                    Ok(result) => {
                        result?;
                        // EV_ONESHOT removes the installed event when it is
                        // retrieved, so later disarms may accept its absence.
                        self.installed.store(false, Ordering::Relaxed);
                        consumed = true;
                    }
                    // Tokio readiness is cleared only after the nonblocking
                    // operation observes that the kqueue has been drained.
                    Err(_would_block) if consumed => return Ok(()),
                    Err(_would_block) => break,
                }
            }
        }
    }
}

/// Retries one signed integer-returning syscall when interrupted.
#[inline]
fn retry_interrupted(mut call: impl FnMut() -> libc::c_int) -> io::Result<libc::c_int> {
    loop {
        let result = call();
        if result >= 0 {
            return Ok(result);
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

/// Checked Mach tick and nanosecond conversion ratio.
#[derive(Clone, Copy)]
struct Timebase {
    /// Nanosecond ratio numerator.
    numer: u32,
    /// Tick ratio denominator.
    denom: u32,
}

impl Timebase {
    /// Returns the process-wide Mach timebase.
    fn get() -> Self {
        *TIMEBASE.get_or_init(|| {
            #[allow(deprecated)]
            let mut info = libc::mach_timebase_info { numer: 0, denom: 0 };
            // SAFETY: `info` points to writable storage for one Mach timebase value.
            #[allow(deprecated)]
            let result = unsafe { libc::mach_timebase_info(&mut info) };
            assert_eq!(result, 0, "mach_timebase_info failed with code {result}");
            #[allow(deprecated)]
            let (numer, denom) = (info.numer, info.denom);
            Self::new(numer, denom).expect("Mach timebase must contain a nonzero ratio")
        })
    }

    /// Validates a Mach timebase ratio.
    fn new(numer: u32, denom: u32) -> io::Result<Self> {
        if numer == 0 || denom == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Mach timebase contains zero",
            ));
        }
        Ok(Self { numer, denom })
    }

    /// Converts ticks to a duration with optional upward nanosecond rounding.
    fn ticks_to_duration(self, ticks: u64, round_up: bool) -> io::Result<Duration> {
        // A u64 tick count multiplied by a u32 ratio component fits in u128.
        let product = u128::from(ticks) * u128::from(self.numer);
        let divisor = u128::from(self.denom);
        let nanoseconds = if round_up {
            product.div_ceil(divisor)
        } else {
            product / divisor
        };
        let seconds = u64::try_from(nanoseconds / NANOS_PER_SECOND)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Mach duration overflow"))?;
        let subsecond = u32::try_from(nanoseconds % NANOS_PER_SECOND)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Mach nanoseconds overflow"))?;
        Ok(Duration::new(seconds, subsecond))
    }

    /// Converts duration to ticks and rounds upward so an arm cannot be early.
    fn duration_to_ticks_up(self, duration: Duration) -> io::Result<u64> {
        // Duration's u64 seconds multiplied by a u32 ratio component fit in u128.
        let product = duration.as_nanos() * u128::from(self.denom);
        let ticks = product.div_ceil(u128::from(self.numer));
        u64::try_from(ticks)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Mach deadline overflow"))
    }
}

/// Validates the identity and error state of one retrieved timer event.
fn validate_event(event: &libc::kevent) -> io::Result<()> {
    // Copy packed fields before inspecting them so no unaligned references are
    // formed by comparisons or error formatting.
    let ident = event.ident;
    let filter = event.filter;
    let flags = event.flags;
    let data = event.data;
    if ident != TIMER_IDENT || filter != libc::EVFILT_TIMER {
        return Err(io::Error::other("kqueue returned an unexpected event"));
    }
    if flags & libc::EV_ERROR != 0 {
        let code = i32::try_from(data)
            .map_err(|_| io::Error::other("kqueue returned an invalid error code"))?;
        if code <= 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "kqueue returned EV_ERROR without a valid error code",
            ));
        }
        return Err(io::Error::from_raw_os_error(code));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{os::fd::AsRawFd, time::Duration};

    #[test]
    fn timebase_rounding_and_deadline_conversion() {
        // Use a fractional ratio to exercise truncating limit conversion and
        // upward time and deadline conversion.
        let timebase = Timebase::new(3, 2).unwrap();

        // Observed time may be rounded in either direction as requested.
        assert_eq!(
            timebase.ticks_to_duration(1, false).unwrap(),
            Duration::from_nanos(1)
        );
        assert_eq!(
            timebase.ticks_to_duration(1, true).unwrap(),
            Duration::from_nanos(2)
        );

        // Armed deadlines always round toward a later Mach tick.
        assert_eq!(
            timebase
                .duration_to_ticks_up(Duration::from_nanos(1))
                .unwrap(),
            1
        );
        assert_eq!(
            timebase
                .duration_to_ticks_up(Duration::from_nanos(2))
                .unwrap(),
            2
        );
    }

    #[test]
    fn timebase_rejects_invalid_values() {
        // A zero numerator or denominator cannot define a conversion ratio.
        assert!(Timebase::new(0, 1).is_err());
        assert!(Timebase::new(1, 0).is_err());
    }

    #[test]
    fn timebase_rejects_unrepresentable_conversions() {
        // Make each tick as large as the timebase representation permits.
        let large_tick = Timebase::new(u32::MAX, 1).unwrap();

        // Converting all possible ticks must reject a duration beyond u64 seconds
        // instead of truncating it.
        assert!(large_tick.ticks_to_duration(u64::MAX, false).is_err());

        // Make each nanosecond require as many ticks as possible.
        let small_tick = Timebase::new(1, u32::MAX).unwrap();

        // The largest Duration must be rejected when its tick count exceeds the
        // u64 representation.
        assert!(small_tick.duration_to_ticks_up(Duration::MAX).is_err());
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore = "Miri does not support kqueue descriptors")]
    async fn maximum_deadline_respects_kqueue_data_limit() {
        // Construct an adapter and derive the positive limit of kqueue's data field.
        let alarm = NativeAlarm::new();
        let maximum = alarm.max_deadline();
        let max_ticks = u64::try_from(libc::intptr_t::MAX).expect("intptr_t maximum must fit u64");

        // The selected duration is the floor-converted tick limit, clamped only
        // when Duration itself is smaller, and converts back within that limit.
        let expected = alarm
            .timebase
            .ticks_to_duration(max_ticks, false)
            .unwrap_or(Duration::MAX);
        assert_eq!(maximum.as_duration(), expected);
        assert!(
            alarm
                .timebase
                .duration_to_ticks_up(maximum.as_duration())
                .unwrap()
                <= max_ticks
        );

        // The kernel accepts the exact limit used during shard validation.
        alarm.arm(maximum).unwrap();
        alarm.disarm().unwrap();
    }

    #[test]
    fn retrieved_event_validation() {
        // Build the successful event produced by the private timer.
        let mut event = libc::kevent {
            ident: TIMER_IDENT,
            filter: libc::EVFILT_TIMER,
            flags: 0,
            fflags: 0,
            data: 0,
            udata: std::ptr::null_mut(),
        };

        // The expected identity and filter are accepted.
        validate_event(&event).unwrap();

        // Kernel-reported errors retain their operating system error code.
        let error_code =
            libc::intptr_t::try_from(libc::EINVAL).expect("EINVAL must fit in intptr_t");
        event.flags = libc::EV_ERROR;
        event.data = error_code;
        assert_eq!(
            validate_event(&event).unwrap_err().raw_os_error(),
            Some(libc::EINVAL)
        );

        // EV_ERROR without a positive error code is not a timer expiry.
        event.data = 0;
        assert_eq!(
            validate_event(&event).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );

        // No other event identity can be consumed from this private kqueue.
        event.ident = TIMER_IDENT + 1;
        event.flags = 0;
        assert_eq!(
            validate_event(&event).unwrap_err().kind(),
            io::ErrorKind::Other
        );
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore = "Miri does not support kqueue readiness")]
    async fn critical_absolute_timer_is_ready_and_consumed() {
        // Create two alarms as the scheduler does for separate shards.
        let alarm = NativeAlarm::new();
        let other = NativeAlarm::new();
        let descriptor = alarm.descriptor.get_ref().as_raw_fd();

        // Each alarm owns a distinct kqueue rather than sharing kernel state.
        assert_ne!(descriptor, other.descriptor.get_ref().as_raw_fd());

        // Initialization makes the primary descriptor close-on-exec.
        // SAFETY: `descriptor` is live and F_GETFD uses no variadic argument.
        let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFD) };
        assert!(flags >= 0);
        assert_ne!(flags & libc::FD_CLOEXEC, 0);

        // Arm NOTE_CRITICAL at an absolute future Mach deadline.
        let now = alarm.now().unwrap();
        let deadline = now.saturating_add(Duration::from_millis(20), alarm.max_deadline());
        alarm.arm(deadline).unwrap();
        tokio::time::timeout(Duration::from_secs(2), alarm.wait())
            .await
            .unwrap()
            .unwrap();

        // The upward conversions prevent early completion.
        assert!(alarm.now().unwrap() >= deadline);

        // A successful wait drains both the kqueue event and Tokio readiness.
        assert!(
            tokio::time::timeout(Duration::from_millis(50), alarm.wait())
                .await
                .is_err()
        );

        // A new arm after the drained event must produce a fresh readiness edge.
        let now = alarm.now().unwrap();
        let second_deadline = now.saturating_add(Duration::from_millis(20), alarm.max_deadline());
        alarm.arm(second_deadline).unwrap();
        tokio::time::timeout(Duration::from_secs(2), alarm.wait())
            .await
            .expect("second kqueue readiness timed out")
            .unwrap();
        assert!(alarm.now().unwrap() >= second_deadline);
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore = "Miri does not support kqueue readiness")]
    async fn rearm_after_unconsumed_expiry_replaces_stale_readiness() {
        // Arm a short deadline and wait for Tokio to observe readability without
        // retrieving the expired EV_ONESHOT event from the kqueue.
        let alarm = NativeAlarm::new();
        let first = alarm
            .now()
            .unwrap()
            .saturating_add(Duration::from_millis(10), alarm.max_deadline());
        alarm.arm(first).unwrap();
        let readiness = tokio::time::timeout(Duration::from_secs(2), alarm.descriptor.readable())
            .await
            .expect("first kqueue readiness timed out")
            .unwrap();
        drop(readiness);
        assert!(alarm.now().unwrap() >= first);

        // Rearm to a later deadline while the expired event and cached reactor
        // readiness still describe the first arm.
        let second = alarm
            .now()
            .unwrap()
            .saturating_add(Duration::from_millis(50), alarm.max_deadline());
        alarm.arm(second).unwrap();
        tokio::time::timeout(Duration::from_secs(2), alarm.wait())
            .await
            .expect("rearmed kqueue readiness timed out")
            .unwrap();

        // Updating the timer must invalidate the queued event, so stale readiness
        // cannot complete the replacement arm before its own absolute deadline.
        assert!(alarm.now().unwrap() >= second);
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore = "Miri does not support kqueue readiness")]
    async fn disarm_removes_unconsumed_expired_event() {
        // Arm a short deadline and observe descriptor readiness without retrieving
        // the expired EV_ONESHOT event.
        let alarm = NativeAlarm::new();
        let deadline = alarm
            .now()
            .unwrap()
            .saturating_add(Duration::from_millis(10), alarm.max_deadline());
        alarm.arm(deadline).unwrap();
        let readiness = tokio::time::timeout(Duration::from_secs(2), alarm.descriptor.readable())
            .await
            .expect("kqueue readiness timed out")
            .unwrap();
        drop(readiness);
        assert!(alarm.now().unwrap() >= deadline);

        // EV_ONESHOT remains installed until retrieval, so disarm must delete both
        // its registration and the queued event.
        alarm.disarm().unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(50), alarm.wait())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore = "Miri does not support kqueue readiness")]
    async fn elapsed_rearm_and_disarm() {
        // Create one alarm.
        let alarm = NativeAlarm::new();

        // An already elapsed absolute deadline becomes readable.
        alarm.arm(alarm.now().unwrap()).unwrap();
        tokio::time::timeout(Duration::from_secs(2), alarm.wait())
            .await
            .unwrap()
            .unwrap();

        // Replacing a later arm with an earlier one uses the new deadline.
        let now = alarm.now().unwrap();
        let later = now.saturating_add(Duration::from_secs(5), alarm.max_deadline());
        let earlier = now.saturating_add(Duration::from_millis(50), alarm.max_deadline());
        alarm.arm(later).unwrap();
        alarm.arm(earlier).unwrap();
        tokio::time::timeout(Duration::from_secs(2), alarm.wait())
            .await
            .expect("earlier kqueue rearm did not replace the later deadline")
            .unwrap();
        assert!(alarm.now().unwrap() >= earlier);

        // Replacing an earlier arm with a later one must remove the stale earlier
        // schedule instead of reporting readiness for it.
        let now = alarm.now().unwrap();
        let earlier = now.saturating_add(Duration::from_millis(20), alarm.max_deadline());
        let later = now.saturating_add(Duration::from_millis(80), alarm.max_deadline());
        alarm.arm(earlier).unwrap();
        alarm.arm(later).unwrap();
        tokio::time::timeout(Duration::from_secs(2), alarm.wait())
            .await
            .unwrap()
            .unwrap();
        assert!(alarm.now().unwrap() >= later);

        // Deleting an installed event prevents subsequent readiness.
        let now = alarm.now().unwrap();
        let soon = now.saturating_add(Duration::from_millis(20), alarm.max_deadline());
        alarm.arm(soon).unwrap();
        alarm.disarm().unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(100), alarm.wait())
                .await
                .is_err()
        );

        // Repeating the disarm exercises the proven absent ENOENT path.
        alarm.disarm().unwrap();

        // Retrieving an expired EV_ONESHOT removes its registration and updates
        // bookkeeping. A later disarm must accept the resulting ENOENT.
        alarm.arm(alarm.now().unwrap()).unwrap();
        tokio::time::timeout(Duration::from_secs(2), alarm.wait())
            .await
            .expect("elapsed kqueue readiness timed out")
            .unwrap();
        alarm.disarm().unwrap();
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore = "Miri does not support kqueue descriptors")]
    async fn disarm_rejects_missing_recorded_timer() {
        // Record a future timer in the adapter, then remove its kernel registration
        // directly without updating the adapter's bookkeeping.
        let alarm = NativeAlarm::new();
        let deadline = alarm
            .now()
            .unwrap()
            .saturating_add(Duration::from_secs(5), alarm.max_deadline());
        alarm.arm(deadline).unwrap();
        alarm.update(libc::EV_DELETE, 0, 0).unwrap();

        // Disarm must surface ENOENT while a timer remains recorded instead of
        // treating deadline passage alone as proof of one-shot deletion.
        let error = alarm
            .disarm()
            .expect_err("missing recorded timer must violate the adapter invariant");
        assert_eq!(error.raw_os_error(), Some(libc::ENOENT));
    }
}
