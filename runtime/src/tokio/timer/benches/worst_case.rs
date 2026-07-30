//! Workloads that protect production timer design decisions.

use crate::{
    Backend, BenchSleep, Config,
    backend::DeadlinePair,
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
        println!(
            "fairness_note one worker forces the timer driver and always-runnable peer to cooperate on the same executor"
        );
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
        for _ in 0..config.worst_batches {
            elapsed.push(
                run_registration_batch(&clock, backend, REGISTRATION_TIMERS, REGISTRATION_STEP)
                    .await?,
            );
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
) -> io::Result<Duration> {
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

    // Cancellation is deliberately outside the registration distribution.
    drop(sleeps);
    tokio::task::yield_now().await;
    Ok(elapsed)
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
            let mut drain = Vec::with_capacity(config.worst_batches);

            for batch in 0..config.worst_batches {
                let batch = u64::try_from(batch).unwrap_or(u64::MAX);
                drain.push(
                    run_cancellation_batch(
                        Arc::clone(&clock),
                        backend,
                        CANCELLATION_TIMERS,
                        total_canceled,
                        producers,
                        batch,
                    )
                    .await?,
                );
            }

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
                &[("drain", drain.len())],
            );
            let shard_distribution =
                report::cancellation_shard_distribution(backend, config.shards(), producers);
            println!(
                "{name} {accounting} drain_p50_us={:.3} drain_p99_us={:.3} \
                 drain_max_us={:.3} scaling_vs_one_producer={scaling} measurement_passes=1 \
                 cancellation_measurement=aggregate_drain {shard_distribution}",
                report::micros(drain_distribution.p50),
                report::micros(drain_distribution.p99),
                report::micros(drain_distribution.max),
            );
        }
    }
    Ok(())
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

/// Result returned by one contending cancellation producer thread.
struct ProducerResult {
    /// Time immediately after this producer's final cancellation.
    last_cancellation: Instant,
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
    /// Cancelable rendezvous shared with the coordinator.
    gate: Arc<ProducerGate>,
}

/// Registers partitioned timers and releases every producer through a gate.
pub(super) async fn run_cancellation_batch(
    clock: Arc<commonware_tokio::Context>,
    backend: Backend,
    timers: usize,
    canceled: usize,
    producers: usize,
    batch: u64,
) -> io::Result<Duration> {
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

    let CoordinatedCancellation { results, drain } = coordinated;
    let mut completed_early = false;
    for result in results {
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
    Ok(drain)
}

/// Registers, partitions, and then cancels one producer's timers.
fn run_cancellation_producer(input: CancellationProducer) -> Option<ProducerResult> {
    // Dedicated threads give Commonware deterministic round-robin shard claims.
    let _guard = input.runtime.enter();
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
    shuffle(&mut sleeps, input.seed);
    let survivors = sleeps.split_off(input.canceled);

    if input.gate.arrive_and_wait() == ProducerRelease::Cancel {
        return None;
    }
    let last_cancellation = drain_cancellations(&mut sleeps);
    Some(ProducerResult {
        last_cancellation,
        survivors,
        completed_early,
    })
}

/// Drops every selected timer and records aggregate completion.
#[inline(never)]
fn drain_cancellations(sleeps: &mut Vec<BenchSleep>) -> Instant {
    debug_assert!(!sleeps.is_empty());
    for sleep in sleeps.drain(..) {
        drop(sleep);
    }
    Instant::now()
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
    // Reserve result storage before release so coordinator allocation cannot
    // contribute to the measured cancellation drain.
    let mut results = Vec::with_capacity(handles.len());
    let drain_start = Instant::now();
    gate.start();
    collect_producers(handles, &mut results)?;
    let drain = report::elapsed_through_last(
        drain_start,
        results.iter().map(|result| result.last_cancellation),
    )?;
    Ok(CoordinatedCancellation { results, drain })
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
        let mut clock_pair_span = report::ClockPairSpan::default();

        for _ in 0..config.worst_batches {
            let result =
                run_storm_batch(&clock, backend, STORM_TIMERS, STORM_LEAD, PEER_LEAD).await?;
            first_dispatch.push(result.first_dispatch);
            full_drain.push(result.full_drain);
            peer_gap.push(result.peer_gap);
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
             {clock_pair_span}",
            report::micros(first.p50),
            report::micros(first.p99),
            report::micros(first.max),
            report::micros(drain.p50),
            report::micros(drain.p99),
            report::micros(drain.max),
            report::micros(peer.p50),
            report::micros(peer.p99),
            report::micros(peer.max),
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
    /// Commonware wall-clock pairing uncertainty, when applicable.
    clock_pair_span: Option<Duration>,
}

/// Registers a common-deadline storm with a recording waker and runnable peer.
async fn run_storm_batch(
    clock: &commonware_tokio::Context,
    backend: Backend,
    timers: usize,
    lead: Duration,
    peer_lead: Duration,
) -> io::Result<StormResult> {
    let deadlines = DeadlinePair::new(backend, lead)?;
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
pub(super) struct Recorder {
    /// Batch origin used to encode callback times.
    origin: Instant,
    /// Number of callbacks required to finish the batch.
    target: usize,
    /// Number of callbacks observed so far.
    pub(super) completed: AtomicUsize,
    /// First callback time plus one nanosecond, with zero meaning unset.
    pub(super) first_ns: AtomicU64,
    /// Final callback time plus one nanosecond, with zero meaning unset.
    pub(super) last_ns: AtomicU64,
}

impl Recorder {
    /// Creates an empty callback recorder.
    pub(super) const fn new(origin: Instant, target: usize) -> Self {
        Self {
            origin,
            target,
            completed: AtomicUsize::new(0),
            first_ns: AtomicU64::new(0),
            last_ns: AtomicU64::new(0),
        }
    }

    /// Records one callback and publishes progress to the peer task.
    pub(super) fn record(&self) {
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
