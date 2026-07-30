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
