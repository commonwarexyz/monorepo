#[test]
fn lateness_rejects_early_completion() {
    use std::{
        io,
        time::{Duration, Instant},
    };

    // Setup: Place one observation before the requested deadline and another
    // at a known distance after it.
    let observed_early = Instant::now();
    let deadline = observed_early
        .checked_add(Duration::from_millis(1))
        .unwrap();
    let observed_late = deadline.checked_add(Duration::from_micros(7)).unwrap();

    // Action: Calculate lateness for the early and late observations.
    let early = super::checked_lateness(observed_early, deadline).unwrap_err();
    let late = super::checked_lateness(observed_late, deadline).unwrap();

    // Assertion: An early callback is a correctness error, while an on-time or
    // late callback contributes its actual duration to the distribution.
    assert_eq!(early.kind(), io::ErrorKind::InvalidData);
    assert_eq!(late, Duration::from_micros(7));
}

#[test]
fn common_deadline_reports_the_monotonic_clock_pair_span() {
    use std::time::Duration;

    // Setup: Construct one synchronized deadline using both clock domains.
    let deadline = super::CommonDeadline::new(Duration::from_millis(50)).unwrap();

    // Action: Derive the distance between the paired measurement deadlines.
    let observed_span = deadline
        .tokio_measurement
        .saturating_duration_since(deadline.commonware_measurement);

    // Assertion: The reported span exactly brackets the wall-clock observation.
    assert_eq!(deadline.clock_pair_span, observed_span);
}
