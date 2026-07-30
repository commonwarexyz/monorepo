//! macOS Mach absolute kqueue timer adapter.

use super::service::{Alarm, AlarmInitError, Deadline};
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

impl Alarm for NativeAlarm {
    const PLATFORM: &'static str = "macos";

    fn new(_shard: usize) -> Result<Self, AlarmInitError> {
        let timebase =
            Timebase::read().map_err(|error| AlarmInitError::new("read Mach timebase", error))?;
        let raw = loop {
            // SAFETY: `kqueue` takes no pointers and returns a new descriptor.
            let result = unsafe { libc::kqueue() };
            if result >= 0 {
                break result;
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(AlarmInitError::new("create kqueue", error));
            }
        };
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
    let flags = loop {
        // SAFETY: `descriptor` is live and F_GETFD uses no variadic argument.
        let result = unsafe { libc::fcntl(descriptor, libc::F_GETFD) };
        if result >= 0 {
            break result;
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    };
    loop {
        // SAFETY: `descriptor` is live and the variadic argument is an integer flag set.
        let result = unsafe { libc::fcntl(descriptor, libc::F_SETFD, flags | libc::FD_CLOEXEC) };
        if result >= 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
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
    loop {
        // SAFETY: `change` is one initialized event and no output buffer is requested.
        let result = unsafe {
            libc::kevent(
                descriptor,
                change,
                1,
                std::ptr::null_mut(),
                0,
                std::ptr::null(),
            )
        };
        if result == 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

/// Consumes one ready event with a nonblocking zero-timeout call.
fn consume(descriptor: libc::c_int) -> io::Result<()> {
    let mut event = timer_change(0, 0, 0);
    let timeout = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    loop {
        // SAFETY: `event` is writable output storage and `timeout` is initialized.
        let result =
            unsafe { libc::kevent(descriptor, std::ptr::null(), 0, &mut event, 1, &timeout) };
        if result > 0 {
            return validate_event(&event);
        }
        if result == 0 {
            return Err(io::Error::from(io::ErrorKind::WouldBlock));
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
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
    if flags & libc::EV_ERROR != 0 && data != 0 {
        let code = i32::try_from(data)
            .map_err(|_| io::Error::other("kqueue returned an invalid error code"))?;
        return Err(io::Error::from_raw_os_error(code));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
