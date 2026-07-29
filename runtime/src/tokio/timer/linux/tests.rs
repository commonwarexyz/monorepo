use super::*;
use std::{os::fd::AsRawFd, time::Duration};

#[test]
fn timespec_validation() {
    // Start with an ordinary normalized value and verify exact conversion.
    assert_eq!(
        duration_from_timespec(libc::timespec {
            tv_sec: 1,
            tv_nsec: 2,
        })
        .unwrap(),
        Duration::new(1, 2)
    );

    // Kernel output is adversarial input. Negative seconds and nanoseconds
    // outside the normalized range must be rejected before arithmetic.
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
fn deadline_conversion_preserves_nanosecond_carry() {
    // Construct the largest normalized subsecond value without carrying into
    // the next second.
    let value = deadline_timespec(Deadline::from_duration(Duration::new(7, 999_999_999))).unwrap();

    // Both fields must reach timerfd unchanged.
    assert_eq!(value.tv_sec, 7);
    assert_eq!(value.tv_nsec, 999_999_999);
}

#[test]
fn maximum_deadline_respects_kernel_and_abi_limits() {
    // Compute both independent limits imposed by timespec and signed ktime.
    let maximum = max_timerfd_duration();
    let ktime_limit = Duration::from_nanos(u64::try_from(i64::MAX).expect("i64::MAX must fit u64"));
    let time_t_limit = Duration::new(
        u64::try_from(libc::time_t::MAX).expect("time_t::MAX must fit u64"),
        999_999_999,
    );

    // The selected deadline is exactly the smaller limit and still converts
    // into the platform timespec without narrowing.
    assert_eq!(maximum, ktime_limit.min(time_t_limit));
    let converted = deadline_timespec(Deadline::from_duration(maximum)).unwrap();
    assert_eq!(u64::try_from(converted.tv_sec).unwrap(), maximum.as_secs());
    assert_eq!(
        u32::try_from(converted.tv_nsec).unwrap(),
        maximum.subsec_nanos()
    );
}

#[tokio::test]
#[cfg_attr(miri, ignore = "Miri does not support timerfd descriptors")]
async fn alarms_own_distinct_descriptors() {
    // Construct two alarms as the service does for separate shards.
    let first = NativeAlarm::new(0).unwrap();
    let second = NativeAlarm::new(1).unwrap();

    // Each alarm must retain its own timerfd rather than sharing kernel state.
    assert_ne!(
        first.descriptor.get_ref().as_raw_fd(),
        second.descriptor.get_ref().as_raw_fd()
    );
}

#[tokio::test]
#[cfg_attr(miri, ignore = "Miri does not support timerfd readiness")]
async fn descriptor_flags_and_absolute_readiness() {
    // Create a real adapter inside an active reactor and inspect the owned
    // descriptor flags set during initialization.
    let alarm = NativeAlarm::new(0).unwrap();
    let descriptor = alarm.descriptor.get_ref().as_raw_fd();
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
async fn elapsed_arm_rearm_and_disarm() {
    // An already elapsed absolute deadline must become readable promptly.
    let alarm = NativeAlarm::new(0).unwrap();
    let now = alarm.now().unwrap();
    alarm.arm(now).unwrap();
    tokio::time::timeout(Duration::from_secs(2), alarm.wait())
        .await
        .unwrap()
        .unwrap();

    // Replace a later arm with an earlier one and verify the earlier update
    // drives the next readiness event.
    let now = alarm.now().unwrap();
    let later = now.saturating_add(Duration::from_millis(200), alarm.max_deadline());
    let earlier = now.saturating_add(Duration::from_millis(20), alarm.max_deadline());
    alarm.arm(later).unwrap();
    alarm.arm(earlier).unwrap();
    tokio::time::timeout(Duration::from_secs(2), alarm.wait())
        .await
        .unwrap()
        .unwrap();

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

#[tokio::test]
#[cfg_attr(miri, ignore = "Miri does not support timerfd descriptors")]
async fn dropping_alarm_closes_descriptor() {
    // Install a periodic marker that the one-shot adapter never creates. This
    // distinguishes a leaked timerfd from a descriptor number reused by a
    // parallel test.
    let alarm = NativeAlarm::new(0).unwrap();
    let descriptor = alarm.descriptor.get_ref().as_raw_fd();
    let marker = libc::itimerspec {
        it_interval: libc::timespec {
            tv_sec: 86_401,
            tv_nsec: 314_159_265,
        },
        it_value: libc::timespec {
            tv_sec: 86_401,
            tv_nsec: 314_159_265,
        },
    };
    // SAFETY: `descriptor` is a live timerfd and `marker` is fully initialized.
    let result = unsafe { libc::timerfd_settime(descriptor, 0, &marker, std::ptr::null_mut()) };
    assert_eq!(result, 0);

    // Drop the sole OwnedFd, then inspect whatever the raw descriptor number
    // denotes after parallel tests have had an opportunity to reuse it.
    drop(alarm);
    let mut observed = libc::itimerspec {
        it_interval: libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        },
        it_value: libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        },
    };
    // SAFETY: `observed` is writable and timerfd_gettime reports an invalid or
    // non-timerfd descriptor without dereferencing descriptor-owned memory.
    let result = unsafe { libc::timerfd_gettime(descriptor, &mut observed) };

    // A closed or non-timerfd descriptor proves the marker is unreachable. A
    // reused timerfd must not retain the marker from the dropped adapter.
    if result == 0 {
        assert!(
            observed.it_interval.tv_sec != marker.it_interval.tv_sec
                || observed.it_interval.tv_nsec != marker.it_interval.tv_nsec
        );
    } else {
        assert!(matches!(
            io::Error::last_os_error().raw_os_error(),
            Some(libc::EBADF | libc::EINVAL)
        ));
    }
}
