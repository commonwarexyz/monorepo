//! macOS Mach absolute kqueue timer adapter.

use super::scheduler::{Alarm, AlarmInitError, Deadline};
use std::{
    io,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    sync::{
        OnceLock,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::io::{Interest, unix::AsyncFd};

/// Nanoseconds in one second.
const NANOS_PER_SECOND: u128 = 1_000_000_000;

/// One fixed timer identifier in each independently owned kqueue.
const TIMER_IDENT: libc::uintptr_t = 1;

/// Sentinel used when no timer event is known to be installed.
const NO_TIMER: u64 = u64::MAX;

/// Process-wide validated conversion ratio or its reproducible error.
static TIMEBASE: OnceLock<Result<Timebase, TimebaseInitError>> = OnceLock::new();

/// One kqueue descriptor with a Mach absolute one-shot timer.
pub(super) struct NativeAlarm {
    /// Owned descriptor and Tokio reactor registration.
    descriptor: AsyncFd<OwnedFd>,
    /// Conversion ratio returned by the Mach timebase.
    timebase: Timebase,
    /// Installed absolute Mach deadline or [`NO_TIMER`] when absent.
    installed: AtomicU64,
}

impl NativeAlarm {
    /// Creates and registers one kqueue with the active Tokio reactor.
    pub(super) fn new() -> Result<Self, AlarmInitError> {
        let timebase =
            Timebase::read().map_err(|error| AlarmInitError::new("read Mach timebase", error))?;
        let raw = retry_interrupted(|| {
            // SAFETY: `kqueue` takes no pointers and returns a new descriptor.
            unsafe { libc::kqueue() }
        })
        .map_err(|error| AlarmInitError::new("create kqueue", error))?;
        // SAFETY: `raw` is a fresh descriptor whose ownership has not moved.
        let descriptor = unsafe { OwnedFd::from_raw_fd(raw) };
        // Ownership is established before fallible setup so every error closes
        // the newly created descriptor.
        set_close_on_exec(descriptor.as_raw_fd())
            .map_err(|error| AlarmInitError::new("set kqueue close-on-exec", error))?;
        let descriptor = AsyncFd::with_interest(descriptor, Interest::READABLE)
            .map_err(|error| AlarmInitError::new("register kqueue with Tokio reactor", error))?;
        Ok(Self {
            descriptor,
            timebase,
            installed: AtomicU64::new(NO_TIMER),
        })
    }
}

impl Alarm for NativeAlarm {
    fn max_deadline(&self) -> Deadline {
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

    fn now_for_expiry(&self) -> io::Result<Deadline> {
        // SAFETY: `mach_absolute_time` takes no arguments and cannot write memory.
        #[allow(deprecated)]
        let ticks = unsafe { libc::mach_absolute_time() };
        // Expiry uses the opposite bound so stale readiness cannot classify a
        // deadline in the remaining fractional nanosecond as already elapsed.
        self.timebase
            .ticks_to_duration(ticks, false)
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
        let change = timer_change(
            libc::EV_ADD | libc::EV_ENABLE | libc::EV_ONESHOT,
            libc::NOTE_ABSOLUTE | libc::NOTE_MACHTIME | libc::NOTE_CRITICAL,
            data,
        );
        submit_change(self.descriptor.get_ref().as_raw_fd(), &change)?;
        // One driver serializes alarm operations. The atomic supplies Sync
        // storage for the trait boundary rather than cross-thread ordering.
        self.installed.store(ticks, Ordering::Relaxed);
        Ok(())
    }

    fn disarm(&self) -> io::Result<()> {
        // Alarm operations are driver-serialized, so no memory publication is
        // coupled to this bookkeeping transition.
        let installed = self.installed.swap(NO_TIMER, Ordering::Relaxed);
        let change = timer_change(libc::EV_DELETE, 0, 0);
        match submit_change(self.descriptor.get_ref().as_raw_fd(), &change) {
            Ok(()) => Ok(()),
            Err(error) if error.raw_os_error() == Some(libc::ENOENT) && installed == NO_TIMER => {
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
                match readiness.try_io(|inner| consume(inner.get_ref().as_raw_fd())) {
                    Ok(result) => {
                        result?;
                        // EV_ONESHOT removes the installed event when it is
                        // retrieved, so later disarms may accept its absence.
                        self.installed.store(NO_TIMER, Ordering::Relaxed);
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

/// Retries one integer-returning syscall when interrupted.
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
    numer: u64,
    /// Tick ratio denominator.
    denom: u64,
}

/// Cacheable failure returned while reading or validating the Mach timebase.
#[derive(Clone, Copy)]
enum TimebaseInitError {
    /// Kernel return code from `mach_timebase_info`.
    Query(libc::c_int),
    /// A zero numerator or denominator returned by the kernel.
    Zero,
}

impl TimebaseInitError {
    /// Reconstructs the same owned I/O error for each timer shard.
    fn into_io_error(self) -> io::Error {
        match self {
            Self::Query(result) => {
                io::Error::other(format!("mach_timebase_info returned {result}"))
            }
            Self::Zero => io::Error::new(io::ErrorKind::InvalidData, "Mach timebase contains zero"),
        }
    }
}

impl Timebase {
    /// Returns the process-wide Mach timebase or reconstructs its cached error.
    fn read() -> io::Result<Self> {
        match TIMEBASE.get_or_init(Self::read_once) {
            Ok(timebase) => Ok(*timebase),
            Err(error) => Err(error.into_io_error()),
        }
    }

    /// Reads and validates the Mach timebase for the process-wide cache.
    fn read_once() -> Result<Self, TimebaseInitError> {
        #[allow(deprecated)]
        let mut info = libc::mach_timebase_info { numer: 0, denom: 0 };
        // SAFETY: `info` points to writable storage for one Mach timebase value.
        #[allow(deprecated)]
        let result = unsafe { libc::mach_timebase_info(&mut info) };
        if result != 0 {
            return Err(TimebaseInitError::Query(result));
        }
        #[allow(deprecated)]
        let (numer, denom) = (info.numer, info.denom);
        Self::validate(numer, denom)
    }

    /// Validates an explicit ratio for conversion tests.
    #[cfg(test)]
    fn new(numer: u32, denom: u32) -> io::Result<Self> {
        Self::validate(numer, denom).map_err(TimebaseInitError::into_io_error)
    }

    /// Validates an explicit ratio in the cacheable error representation.
    fn validate(numer: u32, denom: u32) -> Result<Self, TimebaseInitError> {
        if numer == 0 || denom == 0 {
            return Err(TimebaseInitError::Zero);
        }
        Ok(Self {
            numer: numer.into(),
            denom: denom.into(),
        })
    }

    /// Converts ticks to a duration with optional upward nanosecond rounding.
    fn ticks_to_duration(self, ticks: u64, round_up: bool) -> io::Result<Duration> {
        let product = u128::from(ticks)
            .checked_mul(u128::from(self.numer))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Mach tick overflow"))?;
        let divisor = u128::from(self.denom);
        let nanoseconds = if round_up {
            product
                .checked_add(divisor - 1)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Mach tick overflow"))?
                / divisor
        } else {
            product / divisor
        };
        duration_from_nanos(nanoseconds)
    }

    /// Converts duration to ticks and rounds upward so an arm cannot be early.
    fn duration_to_ticks_up(self, duration: Duration) -> io::Result<u64> {
        let nanoseconds = u128::from(duration.as_secs())
            .checked_mul(NANOS_PER_SECOND)
            .and_then(|value| value.checked_add(u128::from(duration.subsec_nanos())))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "duration overflow"))?;
        let product = nanoseconds
            .checked_mul(u128::from(self.denom))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Mach deadline overflow"))?;
        let divisor = u128::from(self.numer);
        let ticks = product
            .checked_add(divisor - 1)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Mach deadline overflow"))?
            / divisor;
        u64::try_from(ticks)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Mach deadline overflow"))
    }
}

/// Converts a nanosecond count into a representable duration.
fn duration_from_nanos(nanoseconds: u128) -> io::Result<Duration> {
    let seconds = u64::try_from(nanoseconds / NANOS_PER_SECOND)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Mach duration overflow"))?;
    let subsecond = u32::try_from(nanoseconds % NANOS_PER_SECOND)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Mach nanoseconds overflow"))?;
    Ok(Duration::new(seconds, subsecond))
}

/// Sets close-on-exec while preserving existing descriptor flags.
fn set_close_on_exec(descriptor: libc::c_int) -> io::Result<()> {
    let flags = retry_interrupted(|| {
        // SAFETY: `descriptor` is live and F_GETFD uses no variadic argument.
        unsafe { libc::fcntl(descriptor, libc::F_GETFD) }
    })?;
    retry_interrupted(|| {
        // SAFETY: `descriptor` is live and the variadic argument is an integer flag set.
        unsafe { libc::fcntl(descriptor, libc::F_SETFD, flags | libc::FD_CLOEXEC) }
    })?;
    Ok(())
}

/// Builds one initialized kqueue timer change.
const fn timer_change(flags: u16, fflags: u32, data: libc::intptr_t) -> libc::kevent {
    libc::kevent {
        ident: TIMER_IDENT,
        filter: libc::EVFILT_TIMER,
        flags,
        fflags,
        data,
        udata: std::ptr::null_mut(),
    }
}

/// Applies one timer change while retrying interrupted calls.
fn submit_change(descriptor: libc::c_int, change: &libc::kevent) -> io::Result<()> {
    retry_interrupted(|| {
        // SAFETY: `change` is one initialized event and no output buffer is requested.
        unsafe {
            libc::kevent(
                descriptor,
                change,
                1,
                std::ptr::null_mut(),
                0,
                std::ptr::null(),
            )
        }
    })?;
    Ok(())
}

/// Consumes one ready event with a nonblocking zero-timeout call.
fn consume(descriptor: libc::c_int) -> io::Result<()> {
    let mut event = timer_change(0, 0, 0);
    let timeout = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let result = retry_interrupted(|| {
        // SAFETY: `event` is writable output storage and `timeout` is initialized.
        unsafe { libc::kevent(descriptor, std::ptr::null(), 0, &mut event, 1, &timeout) }
    })?;
    if result == 0 {
        return Err(io::Error::from(io::ErrorKind::WouldBlock));
    }
    validate_event(&event)
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
    if flags & libc::EV_ERROR != 0 && data != 0 {
        let code = i32::try_from(data)
            .map_err(|_| io::Error::other("kqueue returned an invalid error code"))?;
        return Err(io::Error::from_raw_os_error(code));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        os::fd::AsRawFd,
        time::{Duration, Instant},
    };

    #[test]
    fn timebase_uses_opposite_safe_rounding_bounds() {
        // Use a fractional ratio to exercise both truncating observation and
        // upward deadline conversion.
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

        // At the same fractional tick, the lower expiry observation must leave the
        // rounded upper deadline in the future rather than popping it early.
        let expiry_now = timebase.ticks_to_duration(1, false).unwrap();
        let rounded_deadline = timebase.ticks_to_duration(1, true).unwrap();
        assert!(expiry_now < rounded_deadline);

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

    #[test]
    fn retrieved_event_validation() {
        // Build the successful event produced by the private timer.
        let event = timer_change(0, 0, 0);

        // The expected identity and filter are accepted.
        validate_event(&event).unwrap();

        // Kernel-reported errors retain their operating system error code.
        let error_code =
            libc::intptr_t::try_from(libc::EINVAL).expect("EINVAL must fit in intptr_t");
        let error_event = timer_change(libc::EV_ERROR, 0, error_code);
        assert_eq!(
            validate_event(&error_event).unwrap_err().raw_os_error(),
            Some(libc::EINVAL)
        );

        // No other event identity can be consumed from this private kqueue.
        let unexpected = libc::kevent {
            ident: TIMER_IDENT + 1,
            filter: libc::EVFILT_TIMER,
            flags: 0,
            fflags: 0,
            data: 0,
            udata: std::ptr::null_mut(),
        };
        assert_eq!(
            validate_event(&unexpected).unwrap_err().kind(),
            io::ErrorKind::Other
        );
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore = "Miri does not support kqueue readiness")]
    async fn critical_absolute_timer_is_ready_and_consumed() {
        // Create two alarms as the scheduler does for separate shards.
        let alarm = NativeAlarm::new().unwrap();
        let other = NativeAlarm::new().unwrap();
        let descriptor = alarm.descriptor.get_ref().as_raw_fd();

        // Each alarm owns a distinct kqueue rather than sharing kernel state.
        assert_ne!(descriptor, other.descriptor.get_ref().as_raw_fd());

        // Initialization makes the primary descriptor close-on-exec.
        // SAFETY: `descriptor` is live and F_GETFD uses no variadic argument.
        let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFD) };
        assert!(flags >= 0);
        assert_ne!(flags & libc::FD_CLOEXEC, 0);

        // Arm NOTE_CRITICAL at an absolute future Mach deadline.
        let started = Instant::now();
        let now = alarm.now().unwrap();
        let deadline = now.saturating_add(Duration::from_millis(20), alarm.max_deadline());
        alarm.arm(deadline).unwrap();
        tokio::time::timeout(Duration::from_secs(2), alarm.wait())
            .await
            .unwrap()
            .unwrap();

        // The upward conversions prevent early completion.
        assert!(started.elapsed() >= Duration::from_millis(20));

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
        let alarm = NativeAlarm::new().unwrap();
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
        let alarm = NativeAlarm::new().unwrap();
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
        let error = consume(alarm.descriptor.get_ref().as_raw_fd())
            .expect_err("disarmed expired event remained queued");
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore = "Miri does not support kqueue readiness")]
    async fn elapsed_rearm_and_disarm() {
        // Create one alarm and verify that a zero-timeout poll starts empty.
        let alarm = NativeAlarm::new().unwrap();
        let descriptor = alarm.descriptor.get_ref().as_raw_fd();
        assert_eq!(
            consume(descriptor).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );

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
        let alarm = NativeAlarm::new().unwrap();
        alarm.arm(alarm.max_deadline()).unwrap();
        let deletion = timer_change(libc::EV_DELETE, 0, 0);
        submit_change(alarm.descriptor.get_ref().as_raw_fd(), &deletion).unwrap();

        // Disarm must surface ENOENT while a timer remains recorded instead of
        // treating deadline passage alone as proof of one-shot deletion.
        let error = alarm
            .disarm()
            .expect_err("missing recorded timer must violate the adapter invariant");
        assert_eq!(error.raw_os_error(), Some(libc::ENOENT));
    }
}
