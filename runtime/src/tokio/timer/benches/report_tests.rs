//! Tests for benchmark latency calculations.

#[test]
fn latency_statistics_preserve_percentiles_and_drain_boundary() {
    use std::time::{Duration, Instant};

    // Setup: Use unsorted samples where floor-based p99 would select the median.
    let samples = [
        Duration::from_nanos(3),
        Duration::from_nanos(1),
        Duration::from_nanos(2),
    ];

    // Action: Summarize the samples through the production report helper.
    let distribution = super::Distribution::new(&samples).unwrap();

    // Assertion: Nearest-rank p50 is the median and p99 selects the maximum.
    assert_eq!(distribution.p50, Duration::from_nanos(2));
    assert_eq!(distribution.p99, Duration::from_nanos(3));
    assert_eq!(distribution.max, Duration::from_nanos(3));

    // Setup: Record producer completions after one common release time.
    let start = Instant::now();
    let completions = [
        start + Duration::from_micros(4),
        start + Duration::from_micros(9),
        start + Duration::from_micros(6),
    ];

    // Action: Derive drain from completion timestamps rather than join time.
    let drain = super::elapsed_through_last(start, completions).unwrap();

    // Assertion: Join order cannot replace the final measured completion.
    assert_eq!(drain, Duration::from_micros(9));
}
