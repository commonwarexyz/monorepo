//! Tests for benchmark percentile reporting.

#[test]
fn percentile_distribution_uses_nearest_rank() {
    // Setup: Use three ordered values where floor-based p99 selects the median.
    let samples = [
        std::time::Duration::from_nanos(1),
        std::time::Duration::from_nanos(2),
        std::time::Duration::from_nanos(3),
    ];

    // Action: Summarize the sample with the production report helper.
    let distribution = super::Distribution::new(&samples).unwrap();

    // Assertion: Nearest-rank p50 is the median and p99 selects the maximum.
    assert_eq!(distribution.p50, std::time::Duration::from_nanos(2));
    assert_eq!(distribution.p99, std::time::Duration::from_nanos(3));
    assert_eq!(distribution.max, std::time::Duration::from_nanos(3));
}

#[test]
fn percentile_index_rejects_invalid_dimensions() {
    // Setup: Select empty, out-of-range, and overflowing dimensions.
    let empty_length = 0;
    let invalid_percentile = 101;

    // Action: Ask the checked helper for each invalid index.
    let empty = super::percentile_index(empty_length, 50);
    let invalid = super::percentile_index(3, invalid_percentile);
    let overflow = super::percentile_index(usize::MAX, 99);

    // Assertion: Every invalid request returns a structured input error.
    assert_eq!(empty.unwrap_err().kind(), std::io::ErrorKind::InvalidInput);
    assert_eq!(
        invalid.unwrap_err().kind(),
        std::io::ErrorKind::InvalidInput
    );
    assert_eq!(
        overflow.unwrap_err().kind(),
        std::io::ErrorKind::InvalidInput
    );
}

#[test]
fn peak_fd_count_tracks_available_maximum() {
    // Setup: Start without a descriptor observation.
    let mut peak = super::PeakFdCount::default();

    // Action: Mix an unavailable sample with increasing and decreasing counts.
    peak.observe(None);
    peak.observe(Some(11));
    peak.observe(Some(9));
    peak.observe(Some(14));

    // Assertion: Only available observations contribute and the maximum is retained.
    assert_eq!(peak.count, Some(14));
    assert_eq!(peak.label(), "14");

    // Setup: Keep a second accumulator entirely unsupported.
    let mut unavailable = super::PeakFdCount::default();

    // Action: Record only an unavailable observation.
    unavailable.observe(None);

    // Assertion: Unsupported platforms retain an explicit output marker.
    assert_eq!(unavailable.count, None);
    assert_eq!(unavailable.label(), "unavailable");
}
