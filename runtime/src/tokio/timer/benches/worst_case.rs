//! Workloads that protect production timer design decisions.

use crate::{
    Backend, Config,
    config::{
        CANCEL_PERCENT, CANCELLATION_TIMERS, PEER_LEAD, REGISTRATION_STEP, REGISTRATION_TIMERS,
        STORM_LEAD, STORM_TIMERS,
    },
    report,
    utils::{
        BenchSleep, DeadlinePair, PeerGap, ProducerGate, dispatch_lateness, poll_once, sleep_until,
        sleep_until_wall,
    },
};
use commonware_runtime::{Runner as _, tokio as commonware_tokio};
use rand::{SeedableRng, prelude::SliceRandom, rngs::StdRng};
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
        // One worker forces the timer driver and runnable peer to cooperate.
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
            elapsed.push(run_registration_batch(&clock, backend).await?);
        }

        let name = format!(
            "{}::descending_registration/backend={} timers={} step_ns={} worker_threads={} \
             timer_shards={}",
            module_path!(),
            backend,
            REGISTRATION_TIMERS,
            REGISTRATION_STEP.as_nanos(),
            config.worker_threads,
            report::timer_shards_label(backend, config.shards()),
        );
        let distribution = report::Distribution::new(&elapsed)?;
        println!(
            "{name} batches={} registration_samples={} registration_p50_us={:.3} \
             registration_max_us={:.3}",
            config.worst_batches,
            elapsed.len(),
            report::micros(distribution.p50),
            report::micros(distribution.max),
        );
    }
    Ok(())
}

/// Registers one strictly descending batch and then cancels it outside timing.
async fn run_registration_batch(
    clock: &commonware_tokio::Context,
    backend: Backend,
) -> io::Result<Duration> {
    let wall_base = SystemTime::now() + LONG_DEADLINE;
    let mut sleeps = Vec::with_capacity(REGISTRATION_TIMERS);
    let start = Instant::now();

    // Manual bulk polling must not let Tokio's task budget leave sleeps unregistered.
    tokio::task::unconstrained(async {
        // Register latest to earliest so each insertion becomes the heap minimum.
        for index in 0..REGISTRATION_TIMERS {
            let positions = u32::try_from(REGISTRATION_TIMERS - index)
                .expect("fixed registration count must fit into u32");
            let wall_deadline = wall_base + REGISTRATION_STEP * positions;
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
        Ok::<_, io::Error>(())
    })
    .await?;
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
    // Aggregate drain excludes registration and retains every survivor until
    // all producers finish.
    for backend in config.backends() {
        for producers in config.cancellation_producer_counts() {
            let total_canceled = CANCELLATION_TIMERS * CANCEL_PERCENT / 100;
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
            let name = format!(
                "{}::cancellation/backend={} timers={} cancel_percent={} producers={} \
                 worker_threads={} timer_shards={}",
                module_path!(),
                backend,
                CANCELLATION_TIMERS,
                CANCEL_PERCENT,
                producers,
                config.worker_threads,
                report::timer_shards_label(backend, config.shards()),
            );
            println!(
                "{name} batches={} drain_samples={} drain_p50_us={:.3} drain_max_us={:.3}",
                config.worst_batches,
                drain.len(),
                report::micros(drain_distribution.p50),
                report::micros(drain_distribution.max),
            );
        }
    }
    Ok(())
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
    let deadlines = DeadlinePair::new(backend, LONG_DEADLINE);
    let runtime = tokio::runtime::Handle::current();

    // Keep thread creation, coordination, and joins off every runtime worker.
    let coordinated = tokio::task::spawn_blocking(move || {
        let gate = Arc::new(ProducerGate::new());
        let mut handles = Vec::with_capacity(producers);
        for producer in 0..producers {
            let input = CancellationProducer {
                runtime: runtime.clone(),
                clock: Arc::clone(&clock),
                backend,
                wall_deadline: deadlines.wall,
                tokio_deadline: deadlines.tokio,
                timers: partition(timers, producers, producer),
                canceled: partition(canceled, producers, producer),
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
                    discard_producers(handles);
                    return Err(error);
                }
            }
        }
        coordinate_cancellation(gate, handles, producers, deadlines.measurement_deadline)
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
    sleeps.shuffle(&mut StdRng::seed_from_u64(input.seed));
    let survivors = sleeps.split_off(input.canceled);

    if !input.gate.arrive_and_wait() {
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
    sleeps.clear();
    Instant::now()
}

/// Waits for registration, releases cancellation, and joins every producer.
fn coordinate_cancellation(
    gate: Arc<ProducerGate>,
    handles: Vec<std::thread::JoinHandle<Option<ProducerResult>>>,
    producers: usize,
    deadline: Instant,
) -> io::Result<CoordinatedCancellation> {
    // Do not release cancellation until every timer has been initially polled.
    if !gate.wait_until_ready(producers) {
        discard_producers(handles);
        return Err(io::Error::other("cancellation producer setup was canceled"));
    }
    if Instant::now() >= deadline {
        gate.cancel();
        discard_producers(handles);
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "cancellation setup reached the long timer deadline",
        ));
    }
    // Reserve result storage before release so coordinator allocation cannot
    // contribute to the measured cancellation drain.
    let mut results = Vec::with_capacity(handles.len());
    let drain_start = Instant::now();
    gate.start();
    collect_producers(handles, &mut results)?;
    if results
        .iter()
        .any(|result| result.last_cancellation >= deadline)
    {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "cancellation drain reached the long timer deadline",
        ));
    }
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
        let fairness_shards = cfg!(any(target_os = "linux", target_os = "macos")).then_some(1);
        let name = format!(
            "{}::expiry_storm/backend={} timers={} lead_us={} peer_lead_us={} worker_threads=1 \
             timer_shards={}",
            module_path!(),
            backend,
            STORM_TIMERS,
            STORM_LEAD.as_micros(),
            PEER_LEAD.as_micros(),
            report::timer_shards_label(backend, fairness_shards),
        );
        let clock_pair_span = clock_pair_span.label("first_dispatch_bound");
        println!(
            "{name} batches={} first_dispatch_samples={} full_drain_samples={} \
             peer_gap_samples={} first_dispatch_p50_us={:.3} first_dispatch_max_us={:.3} \
             full_drain_p50_us={:.3} full_drain_max_us={:.3} peer_gap_p50_us={:.3} \
             peer_gap_max_us={:.3} {clock_pair_span}",
            config.worst_batches,
            first_dispatch.len(),
            full_drain.len(),
            peer_gap.len(),
            report::micros(first.p50),
            report::micros(first.max),
            report::micros(drain.p50),
            report::micros(drain.max),
            report::micros(peer.p50),
            report::micros(peer.max),
        );
    }
    Ok(())
}

/// One measured common-deadline expiry storm.
pub(super) struct StormResult {
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
pub(super) async fn run_storm_batch(
    clock: &commonware_tokio::Context,
    backend: Backend,
    timers: usize,
    lead: Duration,
    peer_lead: Duration,
) -> io::Result<StormResult> {
    let deadlines = DeadlinePair::new(backend, lead);
    let recorder = Arc::new(Recorder::new(deadlines.measurement_origin, timers));
    let waker = Waker::from(Arc::clone(&recorder));
    let mut task_context = Context::from_waker(&waker);
    let mut sleeps = Vec::with_capacity(timers);

    // Manual bulk polling must not let Tokio's task budget leave sleeps unregistered.
    tokio::task::unconstrained(async {
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
        Ok::<_, io::Error>(())
    })
    .await?;
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
    let peer_timeout = deadlines.measurement_deadline + STORM_COMPLETION_TIMEOUT;
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
    tokio::task::unconstrained(async {
        validate_storm_completion(&mut sleeps, last, lead + STORM_COMPLETION_TIMEOUT)
    })
    .await?;
    let first_dispatch = dispatch_lateness(first, lead)?;
    drop(sleeps);
    Ok(StormResult {
        first_dispatch,
        full_drain: last.saturating_sub(first),
        peer_gap,
        clock_pair_span: deadlines.clock_pair_span,
    })
}

/// Rejects a late wake target or a target reached by redundant wakes.
pub(super) fn validate_storm_completion(
    sleeps: &mut [BenchSleep],
    last: Duration,
    completion_deadline: Duration,
) -> io::Result<()> {
    if last > completion_deadline {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "storm callbacks completed after the benchmark timeout",
        ));
    }
    let pending = sleeps
        .iter_mut()
        .map(|sleep| matches!(poll_once(sleep), Poll::Ready(())))
        .filter(|ready| !ready)
        .count();
    if pending != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("storm wake target was reached with {pending} timers still pending"),
        ));
    }
    Ok(())
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
        let is_final = before + 1 == self.target;
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
