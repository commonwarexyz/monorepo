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
fn storm_deadlines_preserve_each_backend_measurement_contract() {
    use std::time::Duration;

    // Setup: Use one visible lead for both backend deadline representations.
    let lead = Duration::from_millis(50);

    // Tokio case - Action: Build its exact monotonic deadline and measurement pair.
    let tokio = super::StormDeadlines::new(super::Backend::Tokio, lead).unwrap();

    // Tokio case - Assertion: Cutoff and lateness reuse the Instant passed to Tokio.
    assert_eq!(tokio.measurement_deadline, tokio.tokio.into_std());
    assert_eq!(
        tokio
            .measurement_deadline
            .saturating_duration_since(tokio.measurement_origin),
        lead
    );
    assert_eq!(tokio.clock_pair_span, None);

    // Commonware case - Action: Pair its wall deadline with monotonic observations.
    let commonware = super::StormDeadlines::new(super::Backend::Commonware, lead).unwrap();
    let observed_span = commonware
        .tokio
        .into_std()
        .saturating_duration_since(commonware.measurement_deadline);

    // Commonware case - Assertion: The span bounds first-dispatch overstatement.
    assert_eq!(commonware.clock_pair_span, Some(observed_span));
}

#[test]
fn recorder_timestamps_first_and_final_callbacks() {
    use std::{sync::atomic::Ordering, time::Instant};

    // Multiple-callback case - Setup: Start with both boundaries unset.
    let multiple = super::Recorder::new(Instant::now(), 3);

    // Multiple-callback case - Action: Record the first and one interior callback.
    multiple.record();
    let first = multiple.first_ns.load(Ordering::Acquire);
    let last_after_first = multiple.last_ns.load(Ordering::Acquire);
    multiple.record();
    let first_after_middle = multiple.first_ns.load(Ordering::Acquire);
    let last_after_middle = multiple.last_ns.load(Ordering::Acquire);

    // Multiple-callback case - Assertion: Only the first boundary is timestamped.
    assert_ne!(first, 0);
    assert_eq!(last_after_first, 0);
    assert_eq!(first_after_middle, first);
    assert_eq!(last_after_middle, 0);

    // Multiple-callback case - Action: Record the final callback.
    multiple.record();
    let last = multiple.last_ns.load(Ordering::Acquire);

    // Multiple-callback case - Assertion: The final boundary is timestamped.
    assert_eq!(multiple.completed.load(Ordering::Relaxed), 3);
    assert!(last >= first);

    // Single-callback case - Setup: The first callback is also the final callback.
    let single = super::Recorder::new(Instant::now(), 1);

    // Single-callback case - Action: Record the sole callback.
    single.record();
    let first = single.first_ns.load(Ordering::Acquire);
    let last = single.last_ns.load(Ordering::Acquire);

    // Single-callback case - Assertion: One timestamp supports both boundaries.
    assert_ne!(first, 0);
    assert_eq!(last, first);
    assert_eq!(single.completed.load(Ordering::Relaxed), 1);
}

#[test]
fn fairness_peer_times_out_when_callbacks_are_missing() {
    use commonware_runtime::{Runner as _, tokio as commonware_tokio};
    use std::{
        sync::Arc,
        time::{Duration, Instant},
    };
    use tokio::sync::oneshot;

    // Setup: Start the one-worker fairness topology with a recorder that
    // expects two callbacks and an already-expired watchdog.
    let runner =
        commonware_tokio::Runner::new(commonware_tokio::Config::default().with_worker_threads(1));
    let recorder = Arc::new(super::Recorder::new(Instant::now(), 2));
    let (ready_sender, ready) = oneshot::channel();
    let timeout = Instant::now();

    // Action: Run the production peer loop without delivering either callback.
    let error = runner.start(move |_| async move {
        let peer = tokio::spawn(super::measure_peer_gap(recorder, ready_sender, timeout));
        let _ = ready.await.unwrap();
        peer.await.unwrap().unwrap_err()
    });

    // Assertion: The watchdog reports the missing callbacks instead of
    // leaving the benchmark blocked indefinitely.
    assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
    assert!(error.to_string().contains("0 of 2"));
    assert!(error.to_string().contains("before timeout"));
    assert_eq!(super::STORM_COMPLETION_TIMEOUT, Duration::from_secs(30));
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
