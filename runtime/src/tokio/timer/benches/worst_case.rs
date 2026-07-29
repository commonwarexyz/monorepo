//! Workloads that protect production timer design decisions.

use crate::{
    Backend, BenchSleep, Config, checked_observations, poll_once, report, sleep_until,
    sleep_until_wall,
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
use tokio::{sync::Barrier, task::JoinHandle};

/// Long lead that keeps registration and cancellation timers from expiring.
const LONG_DEADLINE: Duration = Duration::from_secs(60);

/// Runs worst-case workloads that use the requested worker topology.
pub(crate) async fn run_contention(
    config: &Config,
    clock: Arc<commonware_tokio::Context>,
) -> io::Result<()> {
    benchmark_descending_registration(config, Arc::clone(&clock)).await?;
    benchmark_cancellation(config, clock).await
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
            let result = run_registration_batch(
                &clock,
                backend,
                config.registration_timers,
                config.registration_step,
            )
            .await?;
            elapsed.push(result.elapsed);
            peak_live_fd_count.observe(result.live_fd_count);
        }

        let name = format!(
            "{}::descending_registration/backend={} timers={} step_ns={}",
            module_path!(),
            backend,
            config.registration_timers,
            config.registration_step.as_nanos(),
        );
        report::print_duration(
            &name,
            config.worst_batches,
            config.registration_timers,
            config.worst_batches,
            "registration",
            &elapsed,
            Some(&peak_live_fd_count),
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

/// Measures deterministic high-rate cancellation at three producer levels.
async fn benchmark_cancellation(
    config: &Config,
    clock: Arc<commonware_tokio::Context>,
) -> io::Result<()> {
    for backend in config.backends() {
        let mut one_producer_p50 = None;
        for producers in config.producer_counts() {
            let total_canceled = config
                .cancellation_timers
                .checked_mul(config.cancel_percent)
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "cancel count overflow")
                })?
                / 100;
            let observations = checked_observations(config.worst_batches, total_canceled)?;
            let setup_observations = checked_observations(config.worst_batches, producers)?;
            let mut setup = Vec::with_capacity(setup_observations);
            let mut cancellation = Vec::with_capacity(observations);
            let mut drain = Vec::with_capacity(config.worst_batches);
            let mut peak_live_fd_count = report::PeakFdCount::default();

            for batch in 0..config.worst_batches {
                let result = run_cancellation_batch(
                    Arc::clone(&clock),
                    backend,
                    config.cancellation_timers,
                    total_canceled,
                    producers,
                    u64::try_from(batch).unwrap_or(u64::MAX),
                )
                .await?;
                setup.extend(result.setup);
                cancellation.extend(result.cancellation);
                drain.push(result.drain);
                peak_live_fd_count.observe(result.live_fd_count);
            }
            if cancellation.len() != observations {
                return Err(io::Error::other(format!(
                    "cancellation sample accounting mismatch, expected {observations}, got {}",
                    cancellation.len()
                )));
            }

            let setup_distribution = report::Distribution::new(&setup)?;
            let cancel_distribution = report::Distribution::new(&cancellation)?;
            let drain_distribution = report::Distribution::new(&drain)?;
            let baseline = *one_producer_p50.get_or_insert(drain_distribution.p50);
            let scaling = if drain_distribution.p50.is_zero() {
                1.0
            } else {
                baseline.as_secs_f64() / drain_distribution.p50.as_secs_f64()
            };
            let name = format!(
                "{}::cancellation/backend={} timers={} cancel_percent={} producers={}",
                module_path!(),
                backend,
                config.cancellation_timers,
                config.cancel_percent,
                producers,
            );
            println!(
                "{name} batches={} concurrency={} observations={} \
                 setup_p50_us={:.3} setup_p99_us={:.3} setup_max_us={:.3} \
                 cancellation_p50_us={:.3} cancellation_p99_us={:.3} \
                 cancellation_max_us={:.3} drain_p50_us={:.3} drain_p99_us={:.3} \
                 drain_max_us={:.3} scaling_vs_one_producer={scaling:.3} fd_count={} \
                 peak_live_fd_count={}",
                config.worst_batches,
                producers,
                observations,
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

/// Result returned by one contending cancellation producer.
struct ProducerResult {
    /// Construction and initial-poll time for this partition.
    setup: Duration,
    /// Individual cancellation durations for this partition.
    cancellation: Vec<Duration>,
    /// Uncanceled timers retained until the measured phase completes.
    survivors: Vec<BenchSleep>,
    /// Whether a supposedly long timer completed during setup.
    completed_early: bool,
}

/// Registers partitioned timers and releases every producer through a barrier.
async fn run_cancellation_batch(
    clock: Arc<commonware_tokio::Context>,
    backend: Backend,
    timers: usize,
    canceled: usize,
    producers: usize,
    batch: u64,
) -> io::Result<CancellationBatch> {
    let wall_deadline = checked_system_deadline(LONG_DEADLINE)?;
    let tokio_deadline = tokio::time::Instant::now()
        .checked_add(LONG_DEADLINE)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Tokio deadline overflow"))?;
    let registered = Arc::new(Barrier::new(producers + 1));
    let cancel_start = Arc::new(Barrier::new(producers + 1));
    let mut handles = Vec::with_capacity(producers);

    for producer in 0..producers {
        let local_timers = partition(timers, producers, producer);
        let local_canceled = partition(canceled, producers, producer);
        let clock = Arc::clone(&clock);
        let registered = Arc::clone(&registered);
        let cancel_start = Arc::clone(&cancel_start);
        handles.push(tokio::spawn(async move {
            let setup_start = Instant::now();
            let mut sleeps = Vec::with_capacity(local_timers);
            let mut completed_early = false;
            for _ in 0..local_timers {
                let mut sleep = sleep_until(&clock, backend, wall_deadline, tokio_deadline);
                completed_early |= poll_once(&mut sleep).is_ready();
                sleeps.push(sleep);
            }
            let setup = setup_start.elapsed();

            // Shuffle before the barrier so only cancellation is contended.
            shuffle(
                &mut sleeps,
                batch.wrapping_add(1).wrapping_mul(0x9e37_79b9_7f4a_7c15)
                    ^ u64::try_from(producer).unwrap_or(u64::MAX),
            );
            let survivors = sleeps.split_off(local_canceled);
            registered.wait().await;
            cancel_start.wait().await;

            let mut cancellation = Vec::with_capacity(local_canceled);
            for sleep in sleeps {
                let start = Instant::now();
                drop(sleep);
                cancellation.push(start.elapsed());
            }
            ProducerResult {
                setup,
                cancellation,
                survivors,
                completed_early,
            }
        }));
    }

    // Do not release cancellation until every timer has been initially polled.
    registered.wait().await;
    let live_fd_count = report::fd_count();
    let drain_start = Instant::now();
    cancel_start.wait().await;
    let results = collect_producers(handles).await?;
    let drain = drain_start.elapsed();

    let mut setup = Vec::with_capacity(producers);
    let mut cancellation = Vec::with_capacity(canceled);
    let mut survivors = Vec::with_capacity(timers - canceled);
    let mut completed_early = false;
    for mut result in results {
        setup.push(result.setup);
        cancellation.append(&mut result.cancellation);
        survivors.append(&mut result.survivors);
        completed_early |= result.completed_early;
    }
    if completed_early {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "long cancellation timer completed during setup",
        ));
    }

    // The uncanceled remainder is dropped only after total drain is captured.
    drop(survivors);
    tokio::task::yield_now().await;
    Ok(CancellationBatch {
        setup,
        cancellation,
        drain,
        live_fd_count,
    })
}

/// Collects every cancellation producer and returns the first task failure.
async fn collect_producers(
    handles: Vec<JoinHandle<ProducerResult>>,
) -> io::Result<Vec<ProducerResult>> {
    let mut results = Vec::with_capacity(handles.len());
    for handle in handles {
        results.push(
            handle
                .await
                .map_err(|error| io::Error::other(format!("cancellation task failed: {error}")))?,
        );
    }
    Ok(results)
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

        for _ in 0..config.worst_batches {
            let result = run_storm_batch(
                &clock,
                backend,
                config.storm_timers,
                config.storm_lead,
                config.peer_lead,
            )
            .await?;
            first_dispatch.push(result.first_dispatch);
            full_drain.push(result.full_drain);
            peer_gap.push(result.peer_gap);
            peak_live_fd_count.observe(result.live_fd_count);
        }

        let first = report::Distribution::new(&first_dispatch)?;
        let drain = report::Distribution::new(&full_drain)?;
        let peer = report::Distribution::new(&peer_gap)?;
        let name = format!(
            "{}::expiry_storm/backend={} timers={} worker_threads=1",
            module_path!(),
            backend,
            config.storm_timers,
        );
        println!(
            "{name} batches={} concurrency={} observations={} \
             first_dispatch_p50_us={:.3} first_dispatch_p99_us={:.3} \
             first_dispatch_max_us={:.3} full_drain_p50_us={:.3} \
             full_drain_p99_us={:.3} full_drain_max_us={:.3} \
             peer_gap_p50_us={:.3} peer_gap_p99_us={:.3} peer_gap_max_us={:.3} \
             fd_count={} peak_live_fd_count={}",
            config.worst_batches,
            config.storm_timers,
            checked_observations(config.worst_batches, config.storm_timers)?,
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
}

/// Registers a common-deadline storm with a recording waker and runnable peer.
async fn run_storm_batch(
    clock: &commonware_tokio::Context,
    backend: Backend,
    timers: usize,
    lead: Duration,
    peer_lead: Duration,
) -> io::Result<StormResult> {
    let origin = Instant::now();
    let measurement_deadline = origin
        .checked_add(lead)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "storm deadline overflow"))?;
    let wall_deadline = SystemTime::now()
        .checked_add(lead)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "wall deadline overflow"))?;
    let tokio_deadline = tokio::time::Instant::now()
        .checked_add(lead)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Tokio deadline overflow"))?;
    let recorder = Arc::new(Recorder::new(origin));
    let waker = Waker::from(Arc::clone(&recorder));
    let mut task_context = Context::from_waker(&waker);
    let mut sleeps = Vec::with_capacity(timers);

    for _ in 0..timers {
        let mut sleep = sleep_until(clock, backend, wall_deadline, tokio_deadline);
        if matches!(sleep.as_mut().poll(&mut task_context), Poll::Ready(())) {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "storm timer expired during registration, increase --storm-lead-us",
            ));
        }
        sleeps.push(sleep);
    }
    let live_fd_count = report::fd_count();
    if Instant::now() >= measurement_deadline {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "storm registration exceeded --storm-lead-us",
        ));
    }

    // Start the peer shortly before expiry so setup does not dominate its gap.
    let remaining = measurement_deadline.saturating_duration_since(Instant::now());
    if remaining > peer_lead {
        tokio::time::sleep(remaining - peer_lead).await;
    }
    let peer_recorder = Arc::clone(&recorder);
    let peer = tokio::spawn(async move {
        let mut max_gap = Duration::ZERO;
        let mut previous_run = Instant::now();
        while peer_recorder.completed.load(Ordering::Acquire) < timers {
            tokio::task::yield_now().await;
            let now = Instant::now();
            if peer_recorder.first_ns.load(Ordering::Acquire) != 0 {
                max_gap = max_gap.max(now.saturating_duration_since(previous_run));
            }
            previous_run = now;
        }
        max_gap
    });
    let peer_gap = peer
        .await
        .map_err(|error| io::Error::other(format!("storm peer task failed: {error}")))?;

    let first = recorder.first_elapsed()?;
    let last = recorder.last_elapsed()?;
    drop(sleeps);
    Ok(StormResult {
        first_dispatch: first.saturating_sub(lead),
        full_drain: last.saturating_sub(first),
        peer_gap,
        live_fd_count,
    })
}

/// Atomically records callback progress without scheduling timer tasks.
struct Recorder {
    /// Batch origin used to encode callback times.
    origin: Instant,
    /// Number of callbacks observed so far.
    completed: AtomicUsize,
    /// First callback time plus one nanosecond, with zero meaning unset.
    first_ns: AtomicU64,
    /// Most recent callback time plus one nanosecond.
    last_ns: AtomicU64,
}

impl Recorder {
    /// Creates an empty callback recorder.
    const fn new(origin: Instant) -> Self {
        Self {
            origin,
            completed: AtomicUsize::new(0),
            first_ns: AtomicU64::new(0),
            last_ns: AtomicU64::new(0),
        }
    }

    /// Records one callback and publishes progress to the peer task.
    fn record(&self) {
        let elapsed = u64::try_from(self.origin.elapsed().as_nanos()).unwrap_or(u64::MAX - 1);
        let encoded = elapsed.saturating_add(1);

        // Callback timestamps are written before the release count publishes them.
        let _ = self
            .first_ns
            .compare_exchange(0, encoded, Ordering::AcqRel, Ordering::Acquire);
        self.last_ns.fetch_max(encoded, Ordering::Release);
        self.completed.fetch_add(1, Ordering::Release);
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
