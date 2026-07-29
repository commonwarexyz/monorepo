//! Linux monotonic timerfd adapter.

use super::service::{Alarm, AlarmInitError, Deadline};
use std::{
    io,
    mem::size_of,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    time::Duration,
};
use tokio::io::{Interest, unix::AsyncFd};

/// One nonblocking monotonic timerfd registered with Tokio.
pub(super) struct NativeAlarm {
    /// Owned descriptor and reactor registration.
    descriptor: AsyncFd<OwnedFd>,
}

impl Alarm for NativeAlarm {
    const PLATFORM: &'static str = "linux";

    fn new(_shard: usize) -> Result<Self, AlarmInitError> {
        let raw = loop {
            // SAFETY: `timerfd_create` takes no pointers and returns a new descriptor.
            let result = unsafe {
                libc::timerfd_create(
                    libc::CLOCK_MONOTONIC,
                    libc::TFD_CLOEXEC | libc::TFD_NONBLOCK,
                )
            };
            if result >= 0 {
                break result;
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(AlarmInitError::new("create timerfd", error));
            }
        };
        // SAFETY: `raw` is a fresh descriptor whose ownership has not moved.
        let descriptor = unsafe { OwnedFd::from_raw_fd(raw) };
        let descriptor = AsyncFd::with_interest(descriptor, Interest::READABLE)
            .map_err(|error| AlarmInitError::new("register timerfd with Tokio reactor", error))?;
        Ok(Self { descriptor })
    }

    fn max_deadline(&self) -> Deadline {
        Deadline::from_duration(max_timerfd_duration())
    }

    fn now(&self) -> io::Result<Deadline> {
        monotonic_now()
    }

    fn arm(&self, deadline: Deadline) -> io::Result<()> {
        update_timerfd(self.descriptor.get_ref().as_raw_fd(), Some(deadline))
    }

    fn disarm(&self) -> io::Result<()> {
        update_timerfd(self.descriptor.get_ref().as_raw_fd(), None)
    }

    async fn wait(&self) -> io::Result<()> {
        loop {
            let mut readiness = self.descriptor.readable().await?;
            let mut consumed = false;
            loop {
                match readiness.try_io(|inner| consume(inner.get_ref().as_raw_fd())) {
                    Ok(result) => {
                        result?;
                        consumed = true;
                    }
                    // Tokio readiness is cleared only after the nonblocking
                    // read confirms the timerfd has been drained.
                    Err(_would_block) if consumed => return Ok(()),
                    Err(_would_block) => break,
                }
            }
        }
    }
}

/// Returns the smaller of the timerfd ABI and kernel hrtimer limits.
fn max_timerfd_duration() -> Duration {
    let time_t_seconds =
        u64::try_from(libc::time_t::MAX).expect("time_t maximum must be nonnegative");
    let time_t_limit = Duration::new(time_t_seconds, 999_999_999);
    let ktime_nanoseconds =
        u64::try_from(i64::MAX).expect("signed ktime maximum must be nonnegative");
    let ktime_limit = Duration::from_nanos(ktime_nanoseconds);
    time_t_limit.min(ktime_limit)
}

/// Reads `CLOCK_MONOTONIC` and validates the returned timespec.
fn monotonic_now() -> io::Result<Deadline> {
    let mut value = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    loop {
        // SAFETY: `value` points to writable storage for one timespec.
        let result = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut value) };
        if result == 0 {
            return duration_from_timespec(value).map(Deadline::from_duration);
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

/// Converts a validated nonnegative timespec to a duration.
fn duration_from_timespec(value: libc::timespec) -> io::Result<Duration> {
    let seconds = u64::try_from(value.tv_sec)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "negative monotonic seconds"))?;
    let nanoseconds = u32::try_from(value.tv_nsec)
        .ok()
        .filter(|value| *value < 1_000_000_000)
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "invalid monotonic nanoseconds")
        })?;
    Ok(Duration::new(seconds, nanoseconds))
}

/// Converts a deadline to a timespec accepted by timerfd.
fn deadline_timespec(deadline: Deadline) -> io::Result<libc::timespec> {
    let duration = deadline.as_duration();
    let seconds = libc::time_t::try_from(duration.as_secs()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "monotonic deadline exceeds time_t",
        )
    })?;
    Ok(libc::timespec {
        tv_sec: seconds,
        tv_nsec: duration.subsec_nanos().into(),
    })
}

/// Arms an absolute one-shot deadline or disarms with a zero specification.
fn update_timerfd(descriptor: libc::c_int, deadline: Option<Deadline>) -> io::Result<()> {
    let specification = libc::itimerspec {
        it_interval: libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        },
        it_value: match deadline {
            Some(deadline) => deadline_timespec(deadline)?,
            None => libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            },
        },
    };
    let flags = if deadline.is_some() {
        libc::TFD_TIMER_ABSTIME
    } else {
        0
    };
    loop {
        // SAFETY: `descriptor` is an owned timerfd and `specification` is initialized.
        let result = unsafe {
            libc::timerfd_settime(descriptor, flags, &specification, std::ptr::null_mut())
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

/// Consumes one timerfd readiness count without blocking.
fn consume(descriptor: libc::c_int) -> io::Result<()> {
    let mut expirations = 0_u64;
    loop {
        // SAFETY: `expirations` provides eight writable bytes for a timerfd read.
        let result = unsafe {
            libc::read(
                descriptor,
                (&mut expirations as *mut u64).cast(),
                size_of::<u64>(),
            )
        };
        if result as usize == size_of::<u64>() {
            return Ok(());
        }
        if result >= 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "timerfd returned a partial expiration count",
            ));
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

#[cfg(test)]
mod tests;
