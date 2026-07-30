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
#[cfg_attr(miri, ignore = "Miri does not support mach_timebase_info")]
fn process_timebase_is_cached_and_stable() {
    // Read through the same process-wide path used by separate alarm shards.
    let first = Timebase::read().unwrap();
    let cached = TIMEBASE.get().expect("timebase must have been initialized");
    let second = Timebase::read().unwrap();

    // Both calls return the cached ratio and leave the same OnceLock value in
    // place rather than querying the kernel again.
    assert_eq!(first.numer, second.numer);
    assert_eq!(first.denom, second.denom);
    assert!(std::ptr::eq(
        cached,
        TIMEBASE.get().expect("timebase cache disappeared")
    ));
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
    let error_code = libc::intptr_t::try_from(libc::EINVAL).expect("EINVAL must fit in intptr_t");
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
    // Setup: Create two alarms as the service does for separate shards.
    let alarm = NativeAlarm::new(0).unwrap();
    let other = NativeAlarm::new(1).unwrap();
    let descriptor = alarm.descriptor.get_ref().as_raw_fd();

    // Assertion: Each alarm owns a distinct kqueue rather than sharing kernel state.
    assert_ne!(descriptor, other.descriptor.get_ref().as_raw_fd());

    // Assertion: Initialization makes the primary descriptor close-on-exec.
    // SAFETY: `descriptor` is live and F_GETFD uses no variadic argument.
    let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFD) };
    assert!(flags >= 0);
    assert_ne!(flags & libc::FD_CLOEXEC, 0);

    // Action: Arm NOTE_CRITICAL at an absolute future Mach deadline.
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
    let alarm = NativeAlarm::new(0).unwrap();
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
    let alarm = NativeAlarm::new(0).unwrap();
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
    let alarm = NativeAlarm::new(0).unwrap();
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
    let alarm = NativeAlarm::new(0).unwrap();
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

#[tokio::test]
#[cfg_attr(miri, ignore = "Miri does not support kqueue descriptors")]
async fn dropping_alarm_closes_descriptor() {
    // Install a user-event marker that the timer adapter never creates. This
    // distinguishes a leaked kqueue from a descriptor number reused by a
    // parallel test.
    let alarm = NativeAlarm::new(0).unwrap();
    let descriptor = alarm.descriptor.get_ref().as_raw_fd();
    let marker = libc::kevent {
        ident: TIMER_IDENT + 1,
        filter: libc::EVFILT_USER,
        flags: libc::EV_ADD | libc::EV_ENABLE,
        fflags: 0,
        data: 0,
        udata: std::ptr::null_mut(),
    };
    submit_change(descriptor, &marker).unwrap();

    // Drop the sole OwnedFd, then try to delete the private marker through the
    // raw descriptor number.
    drop(alarm);
    let deletion = libc::kevent {
        flags: libc::EV_DELETE,
        ..marker
    };
    let error = submit_change(descriptor, &deletion)
        .expect_err("the dropped adapter must not retain its user-event marker");

    // A closed or non-kqueue descriptor reports EBADF or EINVAL. A descriptor
    // reused for another kqueue reports ENOENT because it has no marker.
    assert!(matches!(
        error.raw_os_error(),
        Some(libc::EBADF | libc::EINVAL | libc::ENOENT)
    ));
}
