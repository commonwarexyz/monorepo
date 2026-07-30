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
fn recorder_timestamps_first_and_final_callbacks() {
    use std::{sync::atomic::Ordering, time::Instant};

    // Boundary case - Setup: Start with both callback boundaries unset.
    let multiple = super::Recorder::new(Instant::now(), 3);

    // Boundary case - Action: Record the first and one interior callback.
    multiple.record();
    let first = multiple.first_ns.load(Ordering::Acquire);
    let last_after_first = multiple.last_ns.load(Ordering::Acquire);
    multiple.record();
    let first_after_middle = multiple.first_ns.load(Ordering::Acquire);
    let last_after_middle = multiple.last_ns.load(Ordering::Acquire);

    // Boundary case - Assertion: Only the first boundary is timestamped.
    assert_ne!(first, 0);
    assert_eq!(last_after_first, 0);
    assert_eq!(first_after_middle, first);
    assert_eq!(last_after_middle, 0);

    // Boundary case - Action: Record the final callback.
    multiple.record();
    let last = multiple.last_ns.load(Ordering::Acquire);

    // Boundary case - Assertion: The final boundary is timestamped.
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
