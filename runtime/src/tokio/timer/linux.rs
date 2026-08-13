//! Linux native alarm backed by one `timerfd` per scheduler shard.
//!
//! Each alarm owns a nonblocking, close-on-exec descriptor and its Tokio
//! reactor registration. All shards use `CLOCK_MONOTONIC`, so their absolute
//! [`super::scheduler::Deadline`] values share one clock domain. Arms use
//! `TFD_TIMER_ABSTIME`, disarms install a zero specification, and the supported
//! deadline is bounded by both `time_t` and Linux's signed nanosecond timer
//! range.
//!
//! Producers may read the clock concurrently. One shard driver serializes arm,
//! disarm, and wait operations. A wait reads expiration counts until a
//! nonblocking read returns `WouldBlock`. Observing that empty state is what
//! clears Tokio's cached readiness after the one-shot kernel event is drained.
//! Interrupted system calls are retried.
//!
//! Descriptor creation and reactor registration are startup invariants and
//! panic on failure. Clock, alarm, descriptor, and readiness errors after
//! startup return to the scheduler's fatal failure path.

use super::scheduler::{Alarm, Deadline};
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

impl NativeAlarm {
    /// Creates and registers one timerfd with the active Tokio reactor.
    pub(super) fn new() -> Self {
        let raw = retry_interrupted(|| {
            // SAFETY: `timerfd_create` takes no pointers and returns a new descriptor.
            unsafe {
                libc::timerfd_create(
                    libc::CLOCK_MONOTONIC,
                    libc::TFD_CLOEXEC | libc::TFD_NONBLOCK,
                )
            }
        })
        .unwrap_or_else(|error| panic!("failed to create timerfd: {error}"));

        // SAFETY: `raw` is a fresh descriptor whose ownership has not moved.
        let descriptor = unsafe { OwnedFd::from_raw_fd(raw) };
        let descriptor =
            AsyncFd::with_interest(descriptor, Interest::READABLE).unwrap_or_else(|error| {
                panic!("failed to register timerfd with Tokio reactor: {error}")
            });

        Self { descriptor }
    }

    /// Arms an absolute one-shot deadline or disarms with a zero specification.
    fn update(&self, deadline: Option<Deadline>) -> io::Result<()> {
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
        let descriptor = self.descriptor.get_ref().as_raw_fd();

        retry_interrupted(|| {
            // SAFETY: the descriptor is an owned timerfd and `specification` is initialized.
            unsafe {
                libc::timerfd_settime(descriptor, flags, &specification, std::ptr::null_mut())
            }
        })?;

        Ok(())
    }
}

impl Alarm for NativeAlarm {
    fn max_deadline(&self) -> Deadline {
        // timerfd accepts a timespec, whose largest normalized value is
        // time_t::MAX seconds plus 999_999_999 nanoseconds.
        let time_t_seconds =
            u64::try_from(libc::time_t::MAX).expect("time_t maximum must be nonnegative");
        let time_t_limit = Duration::new(time_t_seconds, 999_999_999);

        // The kernel ultimately stores hrtimer deadlines as signed nanoseconds.
        let ktime_nanoseconds =
            u64::try_from(i64::MAX).expect("signed ktime maximum must be nonnegative");
        let ktime_limit = Duration::from_nanos(ktime_nanoseconds);

        Deadline::from_duration(time_t_limit.min(ktime_limit))
    }

    fn now(&self) -> io::Result<Deadline> {
        let mut value = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };

        retry_interrupted(|| {
            // SAFETY: `value` points to writable storage for one timespec.
            unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut value) }
        })?;
        duration_from_timespec(value).map(Deadline::from_duration)
    }

    fn arm(&self, deadline: Deadline) -> io::Result<()> {
        self.update(Some(deadline))
    }

    fn disarm(&self) -> io::Result<()> {
        self.update(None)
    }

    async fn wait(&self) -> io::Result<()> {
        loop {
            let mut readiness = self.descriptor.readable().await?;
            let mut consumed = false;
            loop {
                match readiness.try_io(|inner| {
                    // The expiration count itself is irrelevant, reading it
                    // drains the one-shot timerfd readiness.
                    let mut expirations = 0_u64;
                    let result = retry_interrupted(|| {
                        // SAFETY: `expirations` provides eight writable bytes
                        // for a timerfd read.
                        unsafe {
                            libc::read(
                                inner.get_ref().as_raw_fd(),
                                (&mut expirations as *mut u64).cast(),
                                size_of::<u64>(),
                            )
                        }
                    })?;

                    // A successful timerfd read must return exactly one u64.
                    if result as usize == size_of::<u64>() {
                        Ok(())
                    } else {
                        Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "timerfd returned a partial expiration count",
                        ))
                    }
                }) {
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

/// Retries one signed integer-returning syscall when interrupted.
#[inline]
fn retry_interrupted<T>(mut call: impl FnMut() -> T) -> io::Result<T>
where
    T: Copy + From<i8> + PartialOrd,
{
    loop {
        let result = call();
        if result >= T::from(0) {
            return Ok(result);
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::{os::fd::AsRawFd, time::Duration};

    #[test]
    fn timespec_validation() {
        assert_eq!(
            duration_from_timespec(libc::timespec {
                tv_sec: 1,
                tv_nsec: 2,
            })
            .unwrap(),
            Duration::new(1, 2)
        );

        assert!(
            duration_from_timespec(libc::timespec {
                tv_sec: -1,
                tv_nsec: 0,
            })
            .is_err()
        );
        assert!(
            duration_from_timespec(libc::timespec {
                tv_sec: 0,
                tv_nsec: 1_000_000_000,
            })
            .is_err()
        );
        assert!(
            duration_from_timespec(libc::timespec {
                tv_sec: 0,
                tv_nsec: -1,
            })
            .is_err()
        );
    }

    #[test]
    fn deadline_conversion_rejects_seconds_beyond_time_t() {
        // Construct the first duration whose seconds cannot be represented by the
        // signed timespec field.
        let maximum = u64::try_from(libc::time_t::MAX).expect("time_t maximum must fit u64");
        let unrepresentable = maximum
            .checked_add(1)
            .expect("Duration seconds must exceed time_t");
        let deadline = Deadline::from_duration(Duration::from_secs(unrepresentable));

        // Conversion must reject the deadline instead of narrowing its seconds.
        let error = deadline_timespec(deadline).expect_err("deadline must exceed time_t");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[tokio::test]
    async fn maximum_deadline_respects_kernel_and_abi_limits() {
        // Construct an adapter and compute both independent limits imposed by
        // timespec and signed kernel hrtimer storage.
        let alarm = NativeAlarm::new();
        let maximum = alarm.max_deadline();
        let ktime_limit =
            Duration::from_nanos(u64::try_from(i64::MAX).expect("i64::MAX must fit u64"));
        let time_t_limit = Duration::new(
            u64::try_from(libc::time_t::MAX).expect("time_t::MAX must fit u64"),
            999_999_999,
        );

        // The selected deadline is exactly the smaller limit and still converts
        // into the platform timespec without narrowing.
        assert_eq!(maximum.as_duration(), ktime_limit.min(time_t_limit));
        let converted = deadline_timespec(maximum).unwrap();
        assert_eq!(
            u64::try_from(converted.tv_sec).unwrap(),
            maximum.as_duration().as_secs()
        );
        assert_eq!(
            u32::try_from(converted.tv_nsec).unwrap(),
            maximum.as_duration().subsec_nanos()
        );
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore = "Miri does not support timerfd readiness")]
    async fn descriptor_flags_and_absolute_readiness() {
        // Create two adapters as the scheduler does for separate shards.
        let alarm = NativeAlarm::new();
        let other = NativeAlarm::new();
        let descriptor = alarm.descriptor.get_ref().as_raw_fd();

        // Each alarm owns a distinct timerfd rather than sharing kernel state.
        assert_ne!(descriptor, other.descriptor.get_ref().as_raw_fd());

        // Initialization installs the required descriptor flags.
        // SAFETY: `descriptor` is live and F_GETFD does not use a variadic argument.
        let descriptor_flags = unsafe { libc::fcntl(descriptor, libc::F_GETFD) };
        assert!(descriptor_flags >= 0);
        assert_ne!(descriptor_flags & libc::FD_CLOEXEC, 0);
        // SAFETY: `descriptor` is live and F_GETFL does not use a variadic argument.
        let status_flags = unsafe { libc::fcntl(descriptor, libc::F_GETFL) };
        assert!(status_flags >= 0);
        assert_ne!(status_flags & libc::O_NONBLOCK, 0);

        // Exercise the maximum arm and disarm pair used during shard startup.
        alarm.arm(alarm.max_deadline()).unwrap();
        alarm.disarm().unwrap();

        // Arm one generous future deadline and guard the readiness wait with a
        // separate Tokio timeout so a broken adapter cannot hang the test.
        let now = alarm.now().unwrap();
        let deadline = now.saturating_add(Duration::from_millis(10), alarm.max_deadline());
        alarm.arm(deadline).unwrap();
        tokio::time::timeout(Duration::from_secs(2), alarm.wait())
            .await
            .expect("timerfd readiness timed out")
            .unwrap();

        // Readiness must not be delivered before the absolute monotonic deadline,
        // and consuming it must leave the descriptor nonready.
        assert!(alarm.now().unwrap() >= deadline);
        assert!(
            tokio::time::timeout(Duration::from_millis(20), alarm.wait())
                .await
                .is_err()
        );

        // A new arm after the drained event must produce a fresh readiness edge.
        let now = alarm.now().unwrap();
        let second_deadline = now.saturating_add(Duration::from_millis(10), alarm.max_deadline());
        alarm.arm(second_deadline).unwrap();
        tokio::time::timeout(Duration::from_secs(2), alarm.wait())
            .await
            .expect("second timerfd readiness timed out")
            .unwrap();
        assert!(alarm.now().unwrap() >= second_deadline);
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore = "Miri does not support timerfd readiness")]
    async fn rearm_after_unconsumed_expiry_replaces_stale_readiness() {
        // Arm a short deadline and wait for Tokio to observe readability without
        // consuming the timerfd expiration count.
        let alarm = NativeAlarm::new();
        let first = alarm
            .now()
            .unwrap()
            .saturating_add(Duration::from_millis(10), alarm.max_deadline());
        alarm.arm(first).unwrap();
        let readiness = tokio::time::timeout(Duration::from_secs(2), alarm.descriptor.readable())
            .await
            .expect("first timerfd readiness timed out")
            .unwrap();
        drop(readiness);
        assert!(alarm.now().unwrap() >= first);

        // Rearm to a later deadline while both kernel and reactor readiness may
        // still describe the first arm.
        let second = alarm
            .now()
            .unwrap()
            .saturating_add(Duration::from_millis(50), alarm.max_deadline());
        alarm.arm(second).unwrap();
        tokio::time::timeout(Duration::from_secs(2), alarm.wait())
            .await
            .expect("rearmed timerfd readiness timed out")
            .unwrap();

        // Rearming resets the unread expiration, so stale readiness cannot make
        // the replacement arm complete before its own absolute deadline.
        assert!(alarm.now().unwrap() >= second);
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore = "Miri does not support timerfd readiness")]
    async fn elapsed_arm_rearm_and_disarm() {
        // An already elapsed absolute deadline must become readable promptly.
        let alarm = NativeAlarm::new();
        let now = alarm.now().unwrap();
        alarm.arm(now).unwrap();
        tokio::time::timeout(Duration::from_secs(2), alarm.wait())
            .await
            .unwrap()
            .unwrap();

        // Replace a later arm with an earlier one and verify the earlier update
        // drives the next readiness event.
        let now = alarm.now().unwrap();
        let later = now.saturating_add(Duration::from_secs(5), alarm.max_deadline());
        let earlier = now.saturating_add(Duration::from_millis(50), alarm.max_deadline());
        alarm.arm(later).unwrap();
        alarm.arm(earlier).unwrap();
        tokio::time::timeout(Duration::from_secs(2), alarm.wait())
            .await
            .expect("earlier timerfd rearm did not replace the later deadline")
            .unwrap();
        assert!(alarm.now().unwrap() >= earlier);

        // Replace an earlier arm with a later one. Readiness must follow the new
        // deadline rather than a stale kernel schedule.
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

        // Arm once more, disarm before expiry, and observe no readiness over an
        // interval much longer than the removed deadline.
        let now = alarm.now().unwrap();
        let soon = now.saturating_add(Duration::from_millis(20), alarm.max_deadline());
        alarm.arm(soon).unwrap();
        alarm.disarm().unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(100), alarm.wait())
                .await
                .is_err()
        );
    }
}
