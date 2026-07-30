//! Tests for expiry-storm peer gap accounting.

#[test]
fn callback_boundaries_preserve_dispatch_lateness_and_suspended_peer_gap() {
    // Setup: Let the peer run once before callbacks, then choose one requested
    // callback deadline.
    let initialized = std::time::Instant::now();
    let before_callbacks = initialized + std::time::Duration::from_micros(5);
    let after_completion = before_callbacks + std::time::Duration::from_micros(20);
    let mut gap = super::PeerGap::new(initialized);
    let target = std::time::Duration::from_micros(10);

    // Action: Record the peer boundary and derive lateness on either side of
    // the callback's requested dispatch time.
    let before_completed = gap.observe(before_callbacks, false, false);
    let completed = gap.observe(after_completion, true, true);
    let early = super::dispatch_lateness(std::time::Duration::from_micros(9), target);
    let late = super::dispatch_lateness(std::time::Duration::from_micros(13), target);

    // Assertion: Termination retains the entire suspended interval, early
    // dispatch is invalid, and late dispatch retains only its excess.
    assert!(!before_completed);
    assert!(completed);
    assert_eq!(gap.maximum(), std::time::Duration::from_micros(20));
    assert_eq!(early.unwrap_err().kind(), std::io::ErrorKind::InvalidData);
    assert_eq!(late.unwrap(), std::time::Duration::from_micros(3));
}
