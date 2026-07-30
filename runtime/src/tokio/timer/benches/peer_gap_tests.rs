//! Tests for expiry-storm peer gap accounting.

#[test]
fn terminal_observation_records_suspended_peer_gap() {
    // Setup: Let the peer run once before callbacks and then become suspended.
    let initialized = std::time::Instant::now();
    let before_callbacks = initialized + std::time::Duration::from_micros(5);
    let after_completion = before_callbacks + std::time::Duration::from_micros(20);
    let mut gap = super::PeerGap::new(initialized);
    assert!(!gap.observe(before_callbacks, false, 0, 10));

    // Action: Observe the peer only after every callback completed.
    let completed = gap.observe(after_completion, true, 10, 10);

    // Assertion: Termination retains the entire interval the peer was suspended.
    assert!(completed);
    assert_eq!(gap.maximum(), std::time::Duration::from_micros(20));
}

#[test]
fn dispatch_lateness_rejects_early_callback() {
    // Setup: Choose callback times immediately before and after one deadline.
    let target = std::time::Duration::from_micros(10);
    let early = std::time::Duration::from_micros(9);
    let late = std::time::Duration::from_micros(13);

    // Action: Derive lateness for both callback times.
    let early = super::dispatch_lateness(early, target);
    let late = super::dispatch_lateness(late, target);

    // Assertion: Early dispatch is invalid and late dispatch retains its excess.
    assert_eq!(early.unwrap_err().kind(), std::io::ErrorKind::InvalidData);
    assert_eq!(late.unwrap(), std::time::Duration::from_micros(3));
}
