//! Tests for complete worst-case benchmark orchestration.

#[test]
fn cancellation_orchestration_handles_one_and_multiple_producers() {
    use commonware_runtime::{Runner as _, tokio as commonware_tokio};
    use std::sync::Arc;

    // Setup: Start the production runtime used by both benchmark backends and
    // choose tiny partitions that give every producer work.
    let runner =
        commonware_tokio::Runner::new(commonware_tokio::Config::default().with_worker_threads(2));

    // Action: Run latency and throughput passes at one and four producers for
    // both backends through the dedicated threads and blocking coordinator.
    let results = runner.start(|context| async move {
        let clock = Arc::new(context);
        let configurations = [
            (super::Backend::Commonware, 2, 1, 1),
            (super::Backend::Commonware, 8, 4, 4),
            (super::Backend::Tokio, 2, 1, 1),
            (super::Backend::Tokio, 8, 4, 4),
        ];
        let mut results = Vec::new();
        let mut batch = 0;
        for (backend, timers, canceled, producers) in configurations {
            for pass in [
                super::CancellationPass::Latency,
                super::CancellationPass::Throughput,
            ] {
                let result = super::run_cancellation_batch(
                    Arc::clone(&clock),
                    backend,
                    timers,
                    canceled,
                    producers,
                    batch,
                    pass,
                )
                .await
                .unwrap();
                results.push((pass, canceled, producers, result));
                batch += 1;
            }
        }
        results
    });

    // Assertion: Latency passes retain every initialized sample and producer
    // setup, while throughput passes allocate neither result buffer.
    for (pass, canceled, producers, result) in results {
        match pass {
            super::CancellationPass::Latency => {
                assert_eq!(result.setup.len(), producers);
                assert_eq!(result.cancellation.len(), canceled);
                assert!(
                    result
                        .cancellation
                        .iter()
                        .all(|sample| *sample != std::time::Duration::MAX)
                );
            }
            super::CancellationPass::Throughput => {
                assert!(result.setup.is_empty());
                assert!(result.cancellation.is_empty());
                assert_eq!(result.setup.capacity(), 0);
                assert_eq!(result.cancellation.capacity(), 0);
            }
        }
    }
}

#[test]
fn cancellation_collection_joins_after_first_panic() {
    use std::time::Duration;

    // Setup: Put a panicking producer before one returning a result, and
    // reserve coordinator storage before either producer is joined.
    let panicking = std::thread::spawn(|| -> Option<super::ProducerResult> {
        panic!("injected producer panic");
    });
    let succeeding = std::thread::spawn(|| {
        Some(super::ProducerResult {
            setup: Duration::ZERO,
            cancellation: Vec::new(),
            last_cancellation: None,
            survivors: Vec::new(),
            completed_early: false,
        })
    });
    let mut results = Vec::with_capacity(2);
    let allocation = results.as_ptr();

    // Action: Collect both producers into the preallocated destination.
    let collected = super::collect_producers(vec![panicking, succeeding], &mut results);

    // Assertion: The first panic is retained, the later result was collected,
    // and collection neither replaced nor grew the destination allocation.
    assert!(collected.is_err());
    assert_eq!(results.len(), 1);
    assert_eq!(results.capacity(), 2);
    assert_eq!(results.as_ptr(), allocation);
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
    assert_eq!(deadlines.clock_pair_span, None);
}

#[test]
fn commonware_storm_brackets_the_wall_clock_snapshot() {
    use std::time::Duration;

    // Setup: Construct one Commonware storm deadline from a visible lead.
    let lead = Duration::from_millis(50);

    // Action: Compare the conservative deadline with the later monotonic sample.
    let deadlines = super::StormDeadlines::new(super::Backend::Commonware, lead).unwrap();
    let observed_span = deadlines
        .tokio
        .into_std()
        .saturating_duration_since(deadlines.measurement_deadline);

    // Assertion: The reported span bounds Commonware first-dispatch overstatement.
    assert_eq!(deadlines.clock_pair_span, Some(observed_span));
}

#[test]
fn recorder_timestamps_only_first_and_final_callbacks() {
    use std::{sync::atomic::Ordering, time::Instant};

    // Setup: Create a three-callback recorder with both boundaries unset.
    let recorder = super::Recorder::new(Instant::now(), 3);

    // Action: Record the first callback and then one interior callback.
    recorder.record();
    let first = recorder.first_ns.load(Ordering::Acquire);
    let last_after_first = recorder.last_ns.load(Ordering::Acquire);
    recorder.record();
    let first_after_middle = recorder.first_ns.load(Ordering::Acquire);
    let last_after_middle = recorder.last_ns.load(Ordering::Acquire);

    // Assertion: Only the first boundary is timestamped before completion.
    assert_ne!(first, 0);
    assert_eq!(last_after_first, 0);
    assert_eq!(first_after_middle, first);
    assert_eq!(last_after_middle, 0);

    // Action: Record the final callback.
    recorder.record();
    let last = recorder.last_ns.load(Ordering::Acquire);

    // Assertion: The final boundary is timestamped after one RMW per callback.
    assert_eq!(recorder.completed.load(Ordering::Relaxed), 3);
    assert!(last >= first);
}

#[test]
fn single_callback_recorder_uses_one_boundary_timestamp() {
    use std::{sync::atomic::Ordering, time::Instant};

    // Setup: Create a recorder whose first callback is also its final callback.
    let recorder = super::Recorder::new(Instant::now(), 1);

    // Action: Record that sole callback.
    recorder.record();
    let first = recorder.first_ns.load(Ordering::Acquire);
    let last = recorder.last_ns.load(Ordering::Acquire);

    // Assertion: One timestamp supports both boundaries and a zero drain.
    assert_ne!(first, 0);
    assert_eq!(last, first);
    assert_eq!(recorder.completed.load(Ordering::Relaxed), 1);
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
