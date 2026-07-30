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

#[test]
fn sample_counts_distinguish_workload_size_from_metric_samples() {
    // Setup: Model two batches containing many timers and several distributions.
    let batches = 2;
    let dimensions = [("timers_per_batch", 50_000), ("producers", 4)];
    let metrics = [("setup", 8), ("cancellation", 99_000), ("drain", 2)];

    // Action: Format the accounting fields shared by benchmark reports.
    let accounting = super::format_sample_counts(batches, &dimensions, &metrics);

    // Assertion: Workload dimensions remain separate from each distribution's samples.
    assert_eq!(
        accounting,
        "batches=2 timers_per_batch=50000 producers=4 setup_samples=8 \
         cancellation_samples=99000 drain_samples=2"
    );
}

#[test]
fn cancellation_shard_distribution_reports_deterministic_placement() {
    // Setup: Select native placements, the fallback, and the Tokio baseline.
    let one_producer = (super::Backend::Commonware, Some(4), 1);
    let oversubscribed = (super::Backend::Commonware, Some(4), 16);
    let fallback = (super::Backend::Commonware, None, 16);
    let tokio = (super::Backend::Tokio, Some(4), 16);

    // Action: Format each effective timer-shard distribution.
    let one_producer =
        super::cancellation_shard_distribution(one_producer.0, one_producer.1, one_producer.2);
    let oversubscribed = super::cancellation_shard_distribution(
        oversubscribed.0,
        oversubscribed.1,
        oversubscribed.2,
    );
    let fallback = super::cancellation_shard_distribution(fallback.0, fallback.1, fallback.2);
    let tokio = super::cancellation_shard_distribution(tokio.0, tokio.1, tokio.2);

    // Assertion: Native placement is exact and unavailable topology is explicit.
    assert_eq!(
        one_producer,
        "effective_timer_shards=1 producers_per_timer_shard_min=1 \
         producers_per_timer_shard_max=1"
    );
    assert_eq!(
        oversubscribed,
        "effective_timer_shards=4 producers_per_timer_shard_min=4 \
         producers_per_timer_shard_max=4"
    );
    assert_eq!(
        fallback,
        "effective_timer_shards=tokio-fallback \
         producers_per_timer_shard_min=unavailable \
         producers_per_timer_shard_max=unavailable"
    );
    assert_eq!(
        tokio,
        "effective_timer_shards=backend-managed \
         producers_per_timer_shard_min=unavailable \
         producers_per_timer_shard_max=unavailable"
    );
}

#[test]
fn drain_ends_at_the_final_recorded_completion() {
    // Setup: Record producer completions after one common release time.
    let start = std::time::Instant::now();
    let completions = [
        start + std::time::Duration::from_micros(4),
        start + std::time::Duration::from_micros(9),
        start + std::time::Duration::from_micros(6),
    ];

    // Action: Derive drain from completion timestamps rather than join time.
    let drain = super::elapsed_through_last(start, completions).unwrap();

    // Assertion: Only the latest measured operation bounds the distribution.
    assert_eq!(drain, std::time::Duration::from_micros(9));
}
