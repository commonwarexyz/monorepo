//! Tests for complete worst-case benchmark orchestration.

#[test]
fn cancellation_orchestration_handles_one_and_multiple_producers() {
    use commonware_runtime::{Runner as _, tokio as commonware_tokio};
    use std::sync::Arc;

    // Setup: Start the production runtime used by both benchmark backends and
    // choose tiny partitions that give every producer work.
    let runner =
        commonware_tokio::Runner::new(commonware_tokio::Config::default().with_worker_threads(2));

    // Action: Run complete one- and four-producer batches for Commonware and
    // Tokio through the dedicated threads and blocking coordinator.
    let (commonware_one, commonware_multiple, tokio_one, tokio_multiple) =
        runner.start(|context| async move {
            let clock = Arc::new(context);
            let commonware_one = super::run_cancellation_batch(
                Arc::clone(&clock),
                super::Backend::Commonware,
                2,
                1,
                1,
                0,
            )
            .await
            .unwrap();
            let commonware_multiple = super::run_cancellation_batch(
                Arc::clone(&clock),
                super::Backend::Commonware,
                8,
                4,
                4,
                1,
            )
            .await
            .unwrap();
            let tokio_one = super::run_cancellation_batch(
                Arc::clone(&clock),
                super::Backend::Tokio,
                2,
                1,
                1,
                2,
            )
            .await
            .unwrap();
            let tokio_multiple =
                super::run_cancellation_batch(clock, super::Backend::Tokio, 8, 4, 4, 3)
                    .await
                    .unwrap();
            (
                commonware_one,
                commonware_multiple,
                tokio_one,
                tokio_multiple,
            )
        });

    // Assertion: Every producer contributes one setup sample and every selected
    // cancellation contributes one duration for both backends.
    for one in [&commonware_one, &tokio_one] {
        assert_eq!(one.setup.len(), 1);
        assert_eq!(one.cancellation.len(), 1);
    }
    for multiple in [&commonware_multiple, &tokio_multiple] {
        assert_eq!(multiple.setup.len(), 4);
        assert_eq!(multiple.cancellation.len(), 4);
    }
}

#[test]
fn tokio_storm_measurement_reuses_the_passed_deadline() {
    use std::time::Duration;

    // Setup: Construct one Tokio storm deadline from a visible lead duration.
    let lead = Duration::from_millis(50);

    // Action: Build the backend deadline and its measurement pair.
    let deadlines = super::StormDeadlines::new(super::Backend::Tokio, lead).unwrap();

    // Assertion: Cutoff and lateness use the exact Instant passed to Tokio.
    assert_eq!(deadlines.measurement_deadline, deadlines.tokio.into_std());
    assert_eq!(
        deadlines
            .measurement_deadline
            .saturating_duration_since(deadlines.measurement_origin),
        lead
    );
}

#[test]
fn cancellation_scaling_requires_a_measured_baseline() {
    use std::time::Duration;

    // Setup: Choose one multi-producer drain with and without a measured baseline.
    let current = Duration::from_micros(5);
    let baseline = Duration::from_micros(10);

    // Action: Calculate scaling for isolated multi-producer and combined runs.
    let isolated = super::cancellation_scaling(None, current);
    let combined = super::cancellation_scaling(Some(baseline), current);

    // Assertion: Isolated profiling reports no invented baseline while combined
    // profiling retains the measured ratio.
    assert_eq!(isolated, None);
    assert_eq!(combined, Some(2.0));
}
