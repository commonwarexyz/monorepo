//! Application-observed timer accuracy scenarios.

use crate::{
    Backend, Config,
    backend::DeadlinePair,
    checked_observations,
    config::{ACCURACY_CONCURRENCY, ACCURACY_SPREAD},
    report, sleep_for, sleep_until,
};
use commonware_runtime::tokio as commonware_tokio;
use futures::future::join_all;
use std::{
    io,
    sync::{Arc, OnceLock},
    time::{Duration, Instant},
};
use tokio::{sync::Barrier, task::JoinHandle};

/// Deadline topology used by a measured accuracy batch.
#[derive(Clone, Copy)]
enum Mode {
    /// Release every timer together to create a run-queue fan-out.
    Synchronized,
    /// Distribute timer registration evenly across a fixed window.
    Spread,
}

impl Mode {
    /// Stable value used in machine-readable scenario names.
    const fn name(self) -> &'static str {
        match self {
            Self::Synchronized => "synchronized",
            Self::Spread => "spread",
        }
    }
}

/// One fixed accuracy scenario.
#[derive(Clone, Copy)]
struct Scenario {
    /// Simultaneous tasks in each batch.
    concurrency: usize,
    /// Duration requested from the selected timer.
    target: Duration,
    /// Registration topology.
    mode: Mode,
}

/// Measurements returned by one accuracy batch.
struct AccuracyBatch {
    /// Per-timer lateness observations.
    lateness: Vec<Duration>,
    /// Commonware wall-clock pairing uncertainty, when applicable.
    clock_pair_span: Option<Duration>,
}

/// Runs the small production accuracy matrix for both backends.
pub(crate) async fn run(config: &Config, clock: Arc<commonware_tokio::Context>) -> io::Result<()> {
    println!(
        "accuracy_note synchronized tasks share one absolute deadline at the requested 10us or 100us distance"
    );
    println!(
        "accuracy_note high-concurrency synchronized lateness includes barrier release, registration, and wake run-queue fan-out because a 100us deadline can pass before every task registers"
    );
    println!(
        "accuracy_note commonware synchronized lateness is an upper bound and subtracting clock_pair_span_max_ns with saturation gives the lower bound, sleep_until construction remains included in both bounds"
    );

    let mut scenarios = vec![
        Scenario {
            concurrency: 1,
            target: Duration::from_micros(10),
            mode: Mode::Synchronized,
        },
        Scenario {
            concurrency: 1,
            target: Duration::from_micros(100),
            mode: Mode::Synchronized,
        },
    ];
    for &concurrency in &ACCURACY_CONCURRENCY {
        scenarios.push(Scenario {
            concurrency,
            target: Duration::from_micros(100),
            mode: Mode::Synchronized,
        });
        scenarios.push(Scenario {
            concurrency,
            target: Duration::from_micros(100),
            mode: Mode::Spread,
        });
    }

    for backend in config.backends() {
        for scenario in &scenarios {
            let observations = checked_observations(config.accuracy_batches, scenario.concurrency)?;
            let mut lateness = Vec::with_capacity(observations);
            let mut clock_pair_span = report::ClockPairSpan::default();

            // A configured sample is a batch, so every slot contributes one value.
            for _ in 0..config.accuracy_batches {
                let batch = run_batch(Arc::clone(&clock), backend, *scenario).await?;
                lateness.extend(batch.lateness);
                clock_pair_span.observe(batch.clock_pair_span);
            }
            if lateness.len() != observations {
                return Err(io::Error::other(format!(
                    "accuracy sample accounting mismatch, expected {observations}, got {}",
                    lateness.len()
                )));
            }

            let name = format!(
                "{}::sleep/backend={} mode={} target_us={} concurrency={}",
                module_path!(),
                backend,
                scenario.mode.name(),
                scenario.target.as_micros(),
                scenario.concurrency,
            );
            let clock_pair_span = clock_pair_span.label("lateness_bound");
            report::print_duration(
                &name,
                config.accuracy_batches,
                &[("concurrency", scenario.concurrency)],
                "lateness",
                &lateness,
                Some(&clock_pair_span),
            )?;
        }
    }
    Ok(())
}

/// Measures one synchronized or evenly spread group of timer tasks.
async fn run_batch(
    clock: Arc<commonware_tokio::Context>,
    backend: Backend,
    scenario: Scenario,
) -> io::Result<AccuracyBatch> {
    let ready = Arc::new(Barrier::new(scenario.concurrency + 1));
    let start = Arc::new(Barrier::new(scenario.concurrency + 1));
    let common_deadline = Arc::new(OnceLock::<DeadlinePair>::new());
    let spread_origin = Arc::new(OnceLock::<tokio::time::Instant>::new());
    let offsets = spread_offsets(scenario.concurrency);
    let mut handles = Vec::with_capacity(scenario.concurrency);

    for offset in offsets {
        let clock = Arc::clone(&clock);
        let ready = Arc::clone(&ready);
        let start = Arc::clone(&start);
        let common_deadline = Arc::clone(&common_deadline);
        let spread_origin = Arc::clone(&spread_origin);
        handles.push(tokio::spawn(async move {
            // Both barriers ensure the deadline is published before a task uses it.
            ready.wait().await;
            start.wait().await;

            match scenario.mode {
                Mode::Synchronized => {
                    let deadline = *common_deadline
                        .get()
                        .expect("common deadline initialized before start barrier");
                    sleep_until(&clock, backend, deadline.wall, deadline.tokio).await;
                    checked_lateness(Instant::now(), deadline.measurement_deadline)
                }
                Mode::Spread => {
                    let origin = *spread_origin
                        .get()
                        .expect("spread origin initialized before start barrier");
                    let deadline = origin + offset;
                    tokio::time::sleep_until(deadline).await;

                    // Capture completion before construction so registration cost
                    // remains inside the relative 100 microsecond measurement.
                    let requested = Instant::now() + scenario.target;
                    sleep_for(&clock, backend, scenario.target).await;
                    checked_lateness(Instant::now(), requested)
                }
            }
        }));
    }

    ready.wait().await;
    let clock_pair_span = match scenario.mode {
        Mode::Synchronized => {
            let deadline = DeadlinePair::new(backend, scenario.target);
            let span = deadline.clock_pair_span;
            common_deadline
                .set(deadline)
                .map_err(|_| io::Error::other("common deadline initialized twice"))?;
            span
        }
        Mode::Spread => {
            spread_origin
                .set(tokio::time::Instant::now())
                .map_err(|_| io::Error::other("spread origin initialized twice"))?;
            None
        }
    };
    start.wait().await;
    Ok(AccuracyBatch {
        lateness: collect_handles(handles).await?,
        clock_pair_span,
    })
}

/// Returns observed lateness while rejecting an early timer callback.
fn checked_lateness(observed: Instant, deadline: Instant) -> io::Result<Duration> {
    observed.checked_duration_since(deadline).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "accuracy timer completed before its requested deadline",
        )
    })
}

/// Builds offsets that include both endpoints of the configured spread.
fn spread_offsets(concurrency: usize) -> Vec<Duration> {
    if concurrency == 1 {
        return vec![Duration::ZERO];
    }

    let last =
        u32::try_from(concurrency - 1).expect("fixed accuracy concurrency must fit into u32");
    (0..=last)
        .map(|index| ACCURACY_SPREAD * index / last)
        .collect()
}

/// Collects every task result while preserving the first observed failure.
async fn collect_handles(
    handles: Vec<JoinHandle<io::Result<Duration>>>,
) -> io::Result<Vec<Duration>> {
    join_all(handles)
        .await
        .into_iter()
        .map(|result| {
            result.map_err(|error| io::Error::other(format!("accuracy task failed: {error}")))?
        })
        .collect()
}
