//! Workloads that protect production timer design decisions.

use crate::{
    Backend, BenchSleep, Config, checked_observations,
    config::{
        CANCEL_PERCENT, CANCELLATION_TIMERS, PEER_LEAD, REGISTRATION_STEP, REGISTRATION_TIMERS,
        STORM_LEAD, STORM_TIMERS,
    },
    peer_gap::{PeerGap, dispatch_lateness},
    poll_once,
    producer_gate::{ProducerGate, ProducerRelease},
    report, sleep_until, sleep_until_wall,
};
use commonware_runtime::{Runner as _, tokio as commonware_tokio};
use std::{
    io,
    sync::{
        Arc,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    task::{Context, Poll, Wake, Waker},
    time::{Duration, Instant, SystemTime},
};
use tokio::sync::oneshot;

/// Long lead that keeps registration and cancellation timers from expiring.
const LONG_DEADLINE: Duration = Duration::from_secs(60);

/// Maximum time allowed for all callbacks after a storm deadline.
const STORM_COMPLETION_TIMEOUT: Duration = Duration::from_secs(30);

/// Runs worst-case workloads that use the requested worker topology.
pub(crate) async fn run_contention(
    config: &Config,
    clock: Arc<commonware_tokio::Context>,
) -> io::Result<()> {
    if config.scenario.runs_registration() {
        benchmark_descending_registration(config, Arc::clone(&clock)).await?;
    }
    if config.scenario.runs_cancellation() {
        benchmark_cancellation(config, clock).await?;
    }
    Ok(())
}

/// Runs expiry fairness on a dedicated one-worker runtime.
pub(crate) fn run_fairness(config: &Config) -> io::Result<()> {
    let runtime =
        commonware_tokio::Runner::new(commonware_tokio::Config::default().with_worker_threads(1));
    runtime.start(|context| async move {
        report::print_fairness_config(config);
        benchmark_expiry_storm(config, Arc::new(context)).await
    })
}

/// Measures construction and one initial poll for descending deadlines.
async fn benchmark_descending_registration(
    config: &Config,
    clock: Arc<commonware_tokio::Context>,
) -> io::Result<()> {
    for backend in config.backends() {
        let mut elapsed = Vec::with_capacity(config.worst_batches);
        let mut peak_live_fd_count = report::PeakFdCount::default();
        for _ in 0..config.worst_batches {
            let result =
                run_registration_batch(&clock, backend, REGISTRATION_TIMERS, REGISTRATION_STEP)
                    .await?;
            elapsed.push(result.elapsed);
            peak_live_fd_count.observe(result.live_fd_count);
        }

        let name = format!(
            "{}::descending_registration/backend={} timers={} step_ns={}",
            module_path!(),
            backend,
            REGISTRATION_TIMERS,
            REGISTRATION_STEP.as_nanos(),
        );
        report::print_duration(
            &name,
            config.worst_batches,
            &[("timers_per_batch", REGISTRATION_TIMERS), ("producers", 1)],
            "registration",
            &elapsed,
            Some(&peak_live_fd_count),
            None,
        )?;
    }
    Ok(())
}

/// Registers one strictly descending batch and then cancels it outside timing.
async fn run_registration_batch(
    clock: &commonware_tokio::Context,
    backend: Backend,
    timers: usize,
    step: Duration,
) -> io::Result<RegistrationBatch> {
    let wall_base = checked_system_deadline(LONG_DEADLINE)?;
    let mut sleeps = Vec::with_capacity(timers);
    let start = Instant::now();

    // Register latest to earliest so each insertion becomes the heap minimum.
    for index in 0..timers {
        let positions = timers - index;
        let offset = checked_step(step, positions)?;
        let wall_deadline = wall_base
            .checked_add(offset)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "wall deadline overflow"))?;
        let mut sleep = sleep_until_wall(clock, backend, wall_deadline);

        // Tokio registers lazily, while Commonware registers during construction.
        // Both paths also convert the same wall deadline before this poll.
        if poll_once(&mut sleep).is_ready() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "descending timer expired during registration",
            ));
        }
        sleeps.push(sleep);
    }
    let elapsed = start.elapsed();

    // Observe descriptors while every timer remains resident.
    let live_fd_count = report::fd_count();

    // Cancellation is deliberately outside the registration distribution.
    drop(sleeps);
    tokio::task::yield_now().await;
    Ok(RegistrationBatch {
        elapsed,
        live_fd_count,
    })
}

/// Result of one descending-registration batch.
struct RegistrationBatch {
    /// Construction and initial-poll time for the complete batch.
    elapsed: Duration,
    /// Descriptor count while every registered timer remains resident.
    live_fd_count: Option<usize>,
}

/// Measures deterministic high-rate cancellation at the selected producer levels.
async fn benchmark_cancellation(
    config: &Config,
    clock: Arc<commonware_tokio::Context>,
) -> io::Result<()> {
    for backend in config.backends() {
        let mut one_producer_p50 = None;
        for producers in config.cancellation_producer_counts() {
            let total_canceled =
                CANCELLATION_TIMERS
                    .checked_mul(CANCEL_PERCENT)
                    .ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidInput, "cancel count overflow")
                    })?
                    / 100;
            let cancellation_samples = checked_observations(config.worst_batches, total_canceled)?;
            let setup_samples = checked_observations(config.worst_batches, producers)?;
            let mut setup = Vec::with_capacity(setup_samples);
            let mut cancellation = Vec::with_capacity(cancellation_samples);
            let mut drain = Vec::with_capacity(config.worst_batches);
            let mut peak_live_fd_count = report::PeakFdCount::default();

            for batch in 0..config.worst_batches {
                let batch = u64::try_from(batch).unwrap_or(u64::MAX);
                let latency = run_cancellation_batch(
                    Arc::clone(&clock),
                    backend,
                    CANCELLATION_TIMERS,
                    total_canceled,
                    producers,
                    batch,
                    CancellationPass::Latency,
                )
                .await?;
                let throughput = run_cancellation_batch(
                    Arc::clone(&clock),
                    backend,
                    CANCELLATION_TIMERS,
                    total_canceled,
                    producers,
                    batch,
                    CancellationPass::Throughput,
                )
                .await?;
                if !throughput.cancellation.is_empty() {
                    return Err(io::Error::other(
                        "throughput cancellation pass produced latency samples",
                    ));
                }

                // Per-timer latency and aggregate drain use separate passes so
                // clock reads and sample writes cannot distort drain scaling.
                setup.extend(latency.setup);
                cancellation.extend(latency.cancellation);
                drain.push(throughput.drain);
                peak_live_fd_count.observe(latency.live_fd_count);
                peak_live_fd_count.observe(throughput.live_fd_count);
            }
            if setup.len() != setup_samples
                || cancellation.len() != cancellation_samples
                || drain.len() != config.worst_batches
            {
                return Err(io::Error::other(format!(
                    "cancellation sample accounting mismatch: expected setup={setup_samples}, \
                     cancellation={cancellation_samples}, drain={}; got setup={}, \
                     cancellation={}, drain={}",
                    config.worst_batches,
                    setup.len(),
                    cancellation.len(),
                    drain.len(),
                )));
            }

            let setup_distribution = report::Distribution::new(&setup)?;
            let cancel_distribution = report::Distribution::new(&cancellation)?;
            let drain_distribution = report::Distribution::new(&drain)?;
            if producers == 1 {
                one_producer_p50 = Some(drain_distribution.p50);
            }
            let scaling = cancellation_scaling(one_producer_p50, drain_distribution.p50)
                .map_or_else(|| "unavailable".to_owned(), |value| format!("{value:.3}"));
            let name = format!(
                "{}::cancellation/backend={} timers={} cancel_percent={} producers={}",
                module_path!(),
                backend,
                CANCELLATION_TIMERS,
                CANCEL_PERCENT,
                producers,
            );
            let accounting = report::format_sample_counts(
                config.worst_batches,
                &[
                    ("timers_per_batch", CANCELLATION_TIMERS),
                    ("producers", producers),
                ],
                &[
                    ("setup", setup.len()),
                    ("cancellation", cancellation.len()),
                    ("drain", drain.len()),
                ],
            );
            let shard_distribution =
                report::cancellation_shard_distribution(backend, config.shards(), producers);
            println!(
                "{name} {accounting} setup_p50_us={:.3} setup_p99_us={:.3} setup_max_us={:.3} \
                 cancellation_p50_us={:.3} cancellation_p99_us={:.3} \
                 cancellation_max_us={:.3} drain_p50_us={:.3} drain_p99_us={:.3} \
                 drain_max_us={:.3} scaling_vs_one_producer={scaling} \
                 measurement_passes=2 cancellation_measurement=instrumented \
                 drain_measurement=uninstrumented setup_measurement=latency_pass \
                 fd_count={} peak_live_fd_count={} {shard_distribution}",
                report::micros(setup_distribution.p50),
                report::micros(setup_distribution.p99),
                report::micros(setup_distribution.max),
                report::micros(cancel_distribution.p50),
                report::micros(cancel_distribution.p99),
                report::micros(cancel_distribution.max),
                report::micros(drain_distribution.p50),
                report::micros(drain_distribution.p99),
                report::micros(drain_distribution.max),
                report::fd_count_label(),
                peak_live_fd_count.label(),
            );
        }
    }
    Ok(())
}

/// Work isolated by one cancellation measurement pass.
#[derive(Clone, Copy)]
enum CancellationPass {
    /// Measure every individual timer drop.
    Latency,
    /// Measure aggregate drain without per-drop instrumentation.
    Throughput,
}

/// Returns drain scaling only when this run measured a one-producer baseline.
fn cancellation_scaling(baseline: Option<Duration>, current: Duration) -> Option<f64> {
    baseline.map(|baseline| {
        if current.is_zero() {
            1.0
        } else {
            baseline.as_secs_f64() / current.as_secs_f64()
        }
    })
}

/// Result of one cancellation batch across all producers.
struct CancellationBatch {
    /// Per-producer construction and initial-poll durations.
    setup: Vec<Duration>,
    /// Per-timer cancellation durations.
    cancellation: Vec<Duration>,
    /// Wall time from producer release through the final cancellation.
    drain: Duration,
    /// Descriptor count before cancellation releases any registered timer.
    live_fd_count: Option<usize>,
}

/// Result returned by one contending cancellation producer thread.
struct ProducerResult {
    /// Construction and initial-poll time for this partition.
    setup: Duration,
    /// Individual cancellation durations for this partition.
    cancellation: Vec<Duration>,
    /// Time immediately after this producer's final cancellation.
    last_cancellation: Option<Instant>,
    /// Uncanceled timers retained until the measured phase completes.
    survivors: Vec<BenchSleep>,
    /// Whether a supposedly long timer completed during setup.
    completed_early: bool,
}

/// Results returned after blocking producer coordination and joins complete.
struct CoordinatedCancellation {
    /// Completed producer outputs.
    results: Vec<ProducerResult>,
    /// Wall time from producer release through the final cancellation.
    drain: Duration,
    /// Descriptor count before cancellation releases any registered timer.
    live_fd_count: Option<usize>,
}

/// Inputs owned by one dedicated cancellation producer.
struct CancellationProducer {
    /// Tokio reactor entered while constructing the baseline sleeps.
    runtime: tokio::runtime::Handle,
    /// Commonware clock shared by every producer.
    clock: Arc<commonware_tokio::Context>,
    /// Timer implementation under measurement.
    backend: Backend,
    /// Common wall deadline used by Commonware sleeps.
    wall_deadline: SystemTime,
    /// Common monotonic deadline used by Tokio sleeps.
    tokio_deadline: tokio::time::Instant,
    /// Timers assigned to this producer.
    timers: usize,
    /// Timers this producer cancels.
    canceled: usize,
    /// Deterministic shuffle seed.
    seed: u64,
    /// Measurement work performed after producer release.
    pass: CancellationPass,
    /// Cancelable rendezvous shared with the coordinator.
    gate: Arc<ProducerGate>,
}

/// Registers partitioned timers and releases every producer through a gate.
async fn run_cancellation_batch(
    clock: Arc<commonware_tokio::Context>,
    backend: Backend,
    timers: usize,
    canceled: usize,
    producers: usize,
    batch: u64,
    pass: CancellationPass,
) -> io::Result<CancellationBatch> {
    let wall_deadline = checked_system_deadline(LONG_DEADLINE)?;
    let tokio_deadline = tokio::time::Instant::now()
        .checked_add(LONG_DEADLINE)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Tokio deadline overflow"))?;
    let gate = Arc::new(ProducerGate::new());
    let runtime = tokio::runtime::Handle::current();
    let mut handles = Vec::with_capacity(producers);

    for producer in 0..producers {
        let local_timers = partition(timers, producers, producer);
        let local_canceled = partition(canceled, producers, producer);
        let input = CancellationProducer {
            runtime: runtime.clone(),
            clock: Arc::clone(&clock),
            backend,
            wall_deadline,
            tokio_deadline,
            timers: local_timers,
            canceled: local_canceled,
            seed: batch.wrapping_add(1).wrapping_mul(0x9e37_79b9_7f4a_7c15)
                ^ u64::try_from(producer).unwrap_or(u64::MAX),
            pass,
            gate: Arc::clone(&gate),
        };
        let unwind_gate = Arc::clone(&gate);
        let handle = std::thread::Builder::new()
            .name(format!("timer-cancel-{producer}"))
            .spawn(move || unwind_gate.cancel_on_unwind(|| run_cancellation_producer(input)));
        match handle {
            Ok(handle) => handles.push(handle),
            Err(error) => {
                gate.cancel();
                tokio::task::spawn_blocking(move || discard_producers(handles))
                    .await
                    .map_err(|join_error| {
                        io::Error::other(format!(
                            "cancellation producer cleanup task failed: {join_error}"
                        ))
                    })?;
                return Err(error);
            }
        }
    }

    // Coordination and joins may block, so keep them off every runtime worker.
    let coordinator_gate = Arc::clone(&gate);
    let coordinated = tokio::task::spawn_blocking(move || {
        coordinate_cancellation(coordinator_gate, handles, producers)
    })
    .await
    .map_err(|error| {
        io::Error::other(format!("cancellation coordinator task failed: {error}"))
    })??;

    let retain_samples = matches!(pass, CancellationPass::Latency);
    let mut setup = if retain_samples {
        Vec::with_capacity(producers)
    } else {
        Vec::new()
    };
    let mut cancellation = if retain_samples {
        Vec::with_capacity(canceled)
    } else {
        Vec::new()
    };
    let mut completed_early = false;
    for mut result in coordinated.results {
        if retain_samples {
            setup.push(result.setup);
            cancellation.append(&mut result.cancellation);
        }
        completed_early |= result.completed_early;
        drop(result.survivors);
    }
    if completed_early {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "long cancellation timer completed during setup",
        ));
    }

    // Producer results retain uncanceled timers until after measured drain is derived.
    tokio::task::yield_now().await;
    Ok(CancellationBatch {
        setup,
        cancellation,
        drain: coordinated.drain,
        live_fd_count: coordinated.live_fd_count,
    })
}

/// Registers, partitions, and then cancels one producer's timers.
fn run_cancellation_producer(input: CancellationProducer) -> Option<ProducerResult> {
    // Setup: Enter the shared reactor and register this producer's partition.
    // Dedicated threads give Commonware deterministic round-robin shard claims.
    let _guard = input.runtime.enter();
    let setup_start = matches!(input.pass, CancellationPass::Latency).then(Instant::now);
    let mut sleeps = Vec::with_capacity(input.timers);
    let mut completed_early = false;
    for _ in 0..input.timers {
        let mut sleep = sleep_until(
            &input.clock,
            input.backend,
            input.wall_deadline,
            input.tokio_deadline,
        );
        completed_early |= poll_once(&mut sleep).is_ready();
        sleeps.push(sleep);
    }
    let setup = setup_start.map_or(Duration::ZERO, |start| start.elapsed());
    shuffle(&mut sleeps, input.seed);
    let survivors = sleeps.split_off(input.canceled);

    // Pre-touch latency samples before release so allocation and page faults do
    // not contribute to either cancellation measurement.
    let mut cancellation = match input.pass {
        CancellationPass::Latency => {
            let samples = vec![Duration::MAX; input.canceled];
            let _ = std::hint::black_box(samples.as_slice());
            samples
        }
        CancellationPass::Throughput => Vec::new(),
    };

    // Action: Wait for every producer, then run the selected cancellation pass.
    if input.gate.arrive_and_wait() == ProducerRelease::Cancel {
        return None;
    }
    let last_cancellation = match input.pass {
        CancellationPass::Latency => measure_cancellation_latency(&mut sleeps, &mut cancellation),
        CancellationPass::Throughput => drain_cancellations(&mut sleeps),
    };
    Some(ProducerResult {
        setup,
        cancellation,
        last_cancellation,
        survivors,
        completed_early,
    })
}

/// Drops timers with per-cancellation latency instrumentation.
#[inline(never)]
fn measure_cancellation_latency(
    sleeps: &mut Vec<BenchSleep>,
    samples: &mut [Duration],
) -> Option<Instant> {
    debug_assert_eq!(sleeps.len(), samples.len());
    let mut last_cancellation = None;
    for (sleep, sample) in sleeps.drain(..).zip(samples) {
        let start = Instant::now();
        drop(sleep);
        let finished = Instant::now();
        *sample = finished.saturating_duration_since(start);
        last_cancellation = Some(finished);
    }
    last_cancellation
}

/// Drops timers without per-cancellation instrumentation.
#[inline(never)]
fn drain_cancellations(sleeps: &mut Vec<BenchSleep>) -> Option<Instant> {
    if sleeps.is_empty() {
        return None;
    }
    for sleep in sleeps.drain(..) {
        drop(sleep);
    }
    Some(Instant::now())
}

/// Waits for registration, releases cancellation, and joins every producer.
fn coordinate_cancellation(
    gate: Arc<ProducerGate>,
    handles: Vec<std::thread::JoinHandle<Option<ProducerResult>>>,
    producers: usize,
) -> io::Result<CoordinatedCancellation> {
    // Do not release cancellation until every timer has been initially polled.
    if !gate.wait_until_ready(producers) {
        discard_producers(handles);
        return Err(io::Error::other("cancellation producer setup was canceled"));
    }
    let live_fd_count = report::fd_count();
    // Reserve result storage before release so coordinator allocation cannot
    // contribute to the measured cancellation drain.
    let mut results = Vec::with_capacity(handles.len());
    let drain_start = Instant::now();
    gate.start();
    collect_producers(handles, &mut results)?;
    if results
        .iter()
        .any(|result| result.last_cancellation.is_none())
    {
        return Err(io::Error::other(
            "cancellation producer completed without canceling a timer",
        ));
    }
    let drain = report::elapsed_through_last(
        drain_start,
        results.iter().filter_map(|result| result.last_cancellation),
    )?;
    Ok(CoordinatedCancellation {
        results,
        drain,
        live_fd_count,
    })
}

/// Collects every cancellation producer and returns the first thread failure.
fn collect_producers(
    handles: Vec<std::thread::JoinHandle<Option<ProducerResult>>>,
    results: &mut Vec<ProducerResult>,
) -> io::Result<()> {
    let mut first_error = None;
    for handle in handles {
        match handle.join() {
            Ok(Some(result)) => results.push(result),
            Ok(None) if first_error.is_none() => {
                first_error = Some(io::Error::other("cancellation producer was canceled"));
            }
            Err(_) if first_error.is_none() => {
                first_error = Some(io::Error::other("cancellation producer thread panicked"));
            }
            Ok(None) | Err(_) => {}
        }
    }
    first_error.map_or(Ok(()), Err)
}

/// Joins producers released after setup could not complete.
fn discard_producers(handles: Vec<std::thread::JoinHandle<Option<ProducerResult>>>) {
    for handle in handles {
        let _ = handle.join();
    }
}

/// Assigns an even deterministic partition with low indices taking remainders.
const fn partition(total: usize, partitions: usize, index: usize) -> usize {
    total / partitions + if index < total % partitions { 1 } else { 0 }
}

/// Applies an in-place deterministic Fisher-Yates shuffle.
fn shuffle<T>(values: &mut [T], mut state: u64) {
    if state == 0 {
        state = 1;
    }
    for upper in (1..values.len()).rev() {
        // Xorshift64 is sufficient because ordering, not cryptography, is required.
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let modulus = u64::try_from(upper + 1).unwrap_or(u64::MAX);
        let index = usize::try_from(state % modulus).unwrap_or(0);
        values.swap(upper, index);
    }
}

/// Measures first dispatch, full drain, and peer scheduling during expiry.
async fn benchmark_expiry_storm(
    config: &Config,
    clock: Arc<commonware_tokio::Context>,
) -> io::Result<()> {
    for backend in config.backends() {
        let mut first_dispatch = Vec::with_capacity(config.worst_batches);
        let mut full_drain = Vec::with_capacity(config.worst_batches);
        let mut peer_gap = Vec::with_capacity(config.worst_batches);
        let mut peak_live_fd_count = report::PeakFdCount::default();
        let mut clock_pair_span = report::ClockPairSpan::default();

        for _ in 0..config.worst_batches {
            let result =
                run_storm_batch(&clock, backend, STORM_TIMERS, STORM_LEAD, PEER_LEAD).await?;
            first_dispatch.push(result.first_dispatch);
            full_drain.push(result.full_drain);
            peer_gap.push(result.peer_gap);
            peak_live_fd_count.observe(result.live_fd_count);
            clock_pair_span.observe(result.clock_pair_span);
        }

        let first = report::Distribution::new(&first_dispatch)?;
        let drain = report::Distribution::new(&full_drain)?;
        let peer = report::Distribution::new(&peer_gap)?;
        let name = format!(
            "{}::expiry_storm/backend={} timers={} worker_threads=1",
            module_path!(),
            backend,
            STORM_TIMERS,
        );
        let accounting = report::format_sample_counts(
            config.worst_batches,
            &[("timers_per_batch", STORM_TIMERS)],
            &[
                ("first_dispatch", first_dispatch.len()),
                ("full_drain", full_drain.len()),
                ("peer_gap", peer_gap.len()),
            ],
        );
        let clock_pair_span = clock_pair_span.label("first_dispatch_bound");
        println!(
            "{name} {accounting} first_dispatch_p50_us={:.3} first_dispatch_p99_us={:.3} \
             first_dispatch_max_us={:.3} full_drain_p50_us={:.3} \
             full_drain_p99_us={:.3} full_drain_max_us={:.3} \
             peer_gap_p50_us={:.3} peer_gap_p99_us={:.3} peer_gap_max_us={:.3} \
             fd_count={} peak_live_fd_count={} {clock_pair_span}",
            report::micros(first.p50),
            report::micros(first.p99),
            report::micros(first.max),
            report::micros(drain.p50),
            report::micros(drain.p99),
            report::micros(drain.max),
            report::micros(peer.p50),
            report::micros(peer.p99),
            report::micros(peer.max),
            report::fd_count_label(),
            peak_live_fd_count.label(),
        );
    }
    Ok(())
}

/// One measured common-deadline expiry storm.
struct StormResult {
    /// Lateness of the first timer callback.
    first_dispatch: Duration,
    /// Time between the first and final timer callbacks.
    full_drain: Duration,
    /// Longest interval in which the runnable peer was not scheduled.
    peer_gap: Duration,
    /// Descriptor count while every storm timer remains resident.
    live_fd_count: Option<usize>,
    /// Commonware wall-clock pairing uncertainty, when applicable.
    clock_pair_span: Option<Duration>,
}

/// Backend deadlines paired with one monotonic measurement origin.
#[derive(Clone, Copy)]
struct StormDeadlines {
    /// Wall-clock deadline passed to Commonware.
    wall: SystemTime,
    /// Monotonic deadline passed directly to Tokio.
    tokio: tokio::time::Instant,
    /// Exact Tokio origin or conservative Commonware lower bound.
    measurement_origin: Instant,
    /// Selected backend deadline used for setup and peer cutoffs.
    measurement_deadline: Instant,
    /// Commonware wall-clock pairing uncertainty, when applicable.
    clock_pair_span: Option<Duration>,
}

impl StormDeadlines {
    /// Constructs both backend forms while retaining the selected measurement pair.
    fn new(backend: Backend, lead: Duration) -> io::Result<Self> {
        // Pair Commonware's wall-clock snapshot with the immediately preceding
        // monotonic observation so valid callbacks cannot be classified early.
        let commonware_origin = Instant::now();
        let wall = SystemTime::now()
            .checked_add(lead)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "wall deadline overflow"))?;
        let tokio_origin = tokio::time::Instant::now();
        let tokio = tokio_origin.checked_add(lead).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "Tokio deadline overflow")
        })?;
        let tokio_origin = tokio_origin.into_std();
        let (measurement_origin, clock_pair_span) = match backend {
            Backend::Commonware => (
                commonware_origin,
                Some(tokio_origin.saturating_duration_since(commonware_origin)),
            ),
            Backend::Tokio => (tokio_origin, None),
        };
        let measurement_deadline = measurement_origin.checked_add(lead).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "storm deadline overflow")
        })?;
        Ok(Self {
            wall,
            tokio,
            measurement_origin,
            measurement_deadline,
            clock_pair_span,
        })
    }
}

/// Registers a common-deadline storm with a recording waker and runnable peer.
async fn run_storm_batch(
    clock: &commonware_tokio::Context,
    backend: Backend,
    timers: usize,
    lead: Duration,
    peer_lead: Duration,
) -> io::Result<StormResult> {
    let deadlines = StormDeadlines::new(backend, lead)?;
    let recorder = Arc::new(Recorder::new(deadlines.measurement_origin, timers));
    let waker = Waker::from(Arc::clone(&recorder));
    let mut task_context = Context::from_waker(&waker);
    let mut sleeps = Vec::with_capacity(timers);

    for _ in 0..timers {
        let mut sleep = sleep_until(clock, backend, deadlines.wall, deadlines.tokio);
        if matches!(sleep.as_mut().poll(&mut task_context), Poll::Ready(())) {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "storm timer expired during registration, increase the STORM_LEAD benchmark constant",
            ));
        }
        sleeps.push(sleep);
    }
    let live_fd_count = report::fd_count();
    if Instant::now() >= deadlines.measurement_deadline {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "storm registration exceeded the STORM_LEAD benchmark constant",
        ));
    }

    // Start the peer shortly before expiry so setup does not dominate its gap.
    let remaining = deadlines
        .measurement_deadline
        .saturating_duration_since(Instant::now());
    if remaining > peer_lead {
        tokio::time::sleep(remaining - peer_lead).await;
    }
    let (peer_ready_sender, peer_ready) = oneshot::channel();
    let peer_timeout = deadlines
        .measurement_deadline
        .checked_add(STORM_COMPLETION_TIMEOUT)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "peer timeout overflow"))?;
    let peer_recorder = Arc::clone(&recorder);
    let peer = tokio::spawn(measure_peer_gap(
        peer_recorder,
        peer_ready_sender,
        peer_timeout,
    ));

    // Do not measure a storm that began before peer initialization completed.
    let (peer_initialized_at, callbacks_at_init) = peer_ready
        .await
        .map_err(|_| io::Error::other("storm peer exited before initialization"))?;
    if peer_initialized_at >= deadlines.measurement_deadline || callbacks_at_init != 0 {
        peer.abort();
        let _ = peer.await;
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "storm peer did not initialize before expiry, increase the PEER_LEAD benchmark constant",
        ));
    }
    let peer_gap = peer
        .await
        .map_err(|error| io::Error::other(format!("storm peer task failed: {error}")))??;

    let first = recorder.first_elapsed()?;
    let last = recorder.last_elapsed()?;
    let first_dispatch = dispatch_lateness(first, lead)?;
    drop(sleeps);
    Ok(StormResult {
        first_dispatch,
        full_drain: last.saturating_sub(first),
        peer_gap,
        live_fd_count,
        clock_pair_span: deadlines.clock_pair_span,
    })
}

/// Measures scheduling gaps until every callback arrives or the watchdog expires.
async fn measure_peer_gap(
    recorder: Arc<Recorder>,
    ready: oneshot::Sender<(Instant, usize)>,
    timeout: Instant,
) -> io::Result<Duration> {
    // Initialize measurement before acknowledging that the peer is runnable.
    let initialized_at = Instant::now();
    let callbacks_at_init = recorder.completed.load(Ordering::Relaxed);
    let mut gap = PeerGap::new(initialized_at);
    let _ = ready.send((initialized_at, callbacks_at_init));

    loop {
        tokio::task::yield_now().await;
        let now = Instant::now();
        let callbacks_completed = recorder.last_ns.load(Ordering::Acquire) != 0;
        let callbacks_started =
            callbacks_completed || recorder.first_ns.load(Ordering::Acquire) != 0;
        if gap.observe(now, callbacks_started, callbacks_completed) {
            return Ok(gap.maximum());
        }
        if now >= timeout {
            let observed = recorder.completed.load(Ordering::Relaxed);
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!(
                    "storm observed {observed} of {} timer callbacks before timeout",
                    recorder.target
                ),
            ));
        }
    }
}

/// Atomically records callback progress without scheduling timer tasks.
struct Recorder {
    /// Batch origin used to encode callback times.
    origin: Instant,
    /// Number of callbacks required to finish the batch.
    target: usize,
    /// Number of callbacks observed so far.
    completed: AtomicUsize,
    /// First callback time plus one nanosecond, with zero meaning unset.
    first_ns: AtomicU64,
    /// Final callback time plus one nanosecond, with zero meaning unset.
    last_ns: AtomicU64,
}

impl Recorder {
    /// Creates an empty callback recorder.
    const fn new(origin: Instant, target: usize) -> Self {
        Self {
            origin,
            target,
            completed: AtomicUsize::new(0),
            first_ns: AtomicU64::new(0),
            last_ns: AtomicU64::new(0),
        }
    }

    /// Records one callback and publishes progress to the peer task.
    fn record(&self) {
        // The dedicated one-worker fairness runtime makes this ordinal the
        // callback execution order. Every callback performs only this one RMW.
        let before = self.completed.fetch_add(1, Ordering::Relaxed);
        let is_first = before == 0;
        let is_final = before.checked_add(1) == Some(self.target);
        if !is_first && !is_final {
            return;
        }

        let elapsed = u64::try_from(self.origin.elapsed().as_nanos()).unwrap_or(u64::MAX - 1);
        let encoded = elapsed.saturating_add(1);
        if is_first {
            self.first_ns.store(encoded, Ordering::Release);
        }
        if is_final {
            self.last_ns.store(encoded, Ordering::Release);
        }
    }

    /// Decodes the first callback time.
    fn first_elapsed(&self) -> io::Result<Duration> {
        decode_duration(self.first_ns.load(Ordering::Acquire))
    }

    /// Decodes the final callback time.
    fn last_elapsed(&self) -> io::Result<Duration> {
        decode_duration(self.last_ns.load(Ordering::Acquire))
    }
}

impl Wake for Recorder {
    fn wake(self: Arc<Self>) {
        self.record();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.record();
    }
}

/// Decodes a timestamp whose zero value is reserved for missing callbacks.
fn decode_duration(encoded: u64) -> io::Result<Duration> {
    if encoded == 0 {
        return Err(io::Error::other("storm timer recorder was never woken"));
    }
    Ok(Duration::from_nanos(encoded - 1))
}

/// Adds a fixed duration to the wall clock with overflow validation.
fn checked_system_deadline(duration: Duration) -> io::Result<SystemTime> {
    SystemTime::now()
        .checked_add(duration)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "wall deadline overflow"))
}

/// Multiplies a deadline step by a platform-sized position.
fn checked_step(step: Duration, positions: usize) -> io::Result<Duration> {
    let positions = u32::try_from(positions).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "registration timer count exceeds u32",
        )
    })?;
    step.checked_mul(positions).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "registration deadline offset overflow",
        )
    })
}

#[cfg(test)]
#[path = "worst_case_tests.rs"]
mod tests;
