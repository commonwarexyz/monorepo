//! Command-line parsing and checked benchmark configuration.

use clap::{CommandFactory, Parser, ValueEnum, builder::Styles, error::ErrorKind};
use std::{env, ffi::OsString, fmt, io, time::Duration};

/// Default number of Tokio workers and production timer shards.
const DEFAULT_WORKER_THREADS: usize = 4;
/// Default batches measured for each accuracy scenario.
const DEFAULT_ACCURACY_BATCHES: usize = 10;
/// Default batches measured for each worst-case scenario.
const DEFAULT_WORST_BATCHES: usize = 3;
/// High-concurrency accuracy levels.
pub(crate) const ACCURACY_CONCURRENCY: [usize; 2] = [1_000, 10_000];
/// Width used to distribute spread-mode registrations.
pub(crate) const ACCURACY_SPREAD: Duration = Duration::from_micros(100_000);
/// Number of descending registrations per batch.
pub(crate) const REGISTRATION_TIMERS: usize = 50_000;
/// Distance between adjacent descending deadlines.
pub(crate) const REGISTRATION_STEP: Duration = Duration::from_nanos(1_000);
/// Number of long-lived timers in each cancellation batch.
pub(crate) const CANCELLATION_TIMERS: usize = 100_000;
/// Integer percentage of long-lived timers canceled.
pub(crate) const CANCEL_PERCENT: usize = 99;
/// Number of timers in each common-deadline expiry storm.
pub(crate) const STORM_TIMERS: usize = 50_000;
/// Time reserved to register a complete expiry storm.
pub(crate) const STORM_LEAD: Duration = Duration::from_micros(50_000);
/// Time before expiry when the always-runnable peer starts.
pub(crate) const PEER_LEAD: Duration = Duration::from_micros(5_000);

/// Timer implementations selected for a benchmark run.
#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub(crate) enum BackendSelection {
    /// Run both timer implementations.
    All,
    /// Run only the Commonware clock.
    Commonware,
    /// Run only Tokio's timer.
    Tokio,
}

impl BackendSelection {
    /// Returns whether a concrete backend should run.
    const fn includes(self, backend: Backend) -> bool {
        matches!(self, Self::All)
            || matches!(
                (self, backend),
                (Self::Commonware, Backend::Commonware) | (Self::Tokio, Backend::Tokio)
            )
    }
}

impl fmt::Display for BackendSelection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(
            self.to_possible_value()
                .expect("every backend has a clap value")
                .get_name(),
        )
    }
}

/// A concrete timer implementation under measurement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Backend {
    /// The production Commonware Tokio clock.
    Commonware,
    /// A direct `tokio::time` baseline.
    Tokio,
}

impl Backend {
    /// All concrete backends in stable output order.
    const ALL: [Self; 2] = [Self::Commonware, Self::Tokio];
}

impl fmt::Display for Backend {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Commonware => formatter.write_str("commonware"),
            Self::Tokio => formatter.write_str("tokio"),
        }
    }
}

/// Benchmark scenario groups selected for a run.
#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub(crate) enum ScenarioSelection {
    /// Run accuracy and worst-case scenarios.
    All,
    /// Run only application-observed timer accuracy.
    Accuracy,
    /// Run every workload that protects timer design decisions.
    WorstCase,
    /// Run only descending timer registration.
    Registration,
    /// Run cancellation at every configured producer level.
    Cancellation,
    /// Run cancellation with one producer.
    CancellationSingle,
    /// Run cancellation with every producer level greater than one.
    CancellationMulti,
    /// Run only the common-deadline expiry storm.
    Expiry,
}

impl ScenarioSelection {
    /// Returns whether the accuracy scenarios should run.
    pub(crate) const fn runs_accuracy(self) -> bool {
        matches!(self, Self::All | Self::Accuracy)
    }

    /// Returns whether descending registration should run.
    pub(crate) const fn runs_registration(self) -> bool {
        matches!(self, Self::All | Self::WorstCase | Self::Registration)
    }

    /// Returns whether any cancellation workload should run.
    pub(crate) const fn runs_cancellation(self) -> bool {
        matches!(
            self,
            Self::All
                | Self::WorstCase
                | Self::Cancellation
                | Self::CancellationSingle
                | Self::CancellationMulti
        )
    }

    /// Returns whether cancellation should include one producer.
    const fn runs_single_producer(self) -> bool {
        matches!(
            self,
            Self::All | Self::WorstCase | Self::Cancellation | Self::CancellationSingle
        )
    }

    /// Returns whether cancellation should include contending producers.
    const fn runs_multiple_producers(self) -> bool {
        matches!(
            self,
            Self::All | Self::WorstCase | Self::Cancellation | Self::CancellationMulti
        )
    }

    /// Returns whether the common-deadline expiry storm should run.
    pub(crate) const fn runs_expiry(self) -> bool {
        matches!(self, Self::All | Self::WorstCase | Self::Expiry)
    }

    /// Returns whether the main runtime has a selected worst-case workload.
    pub(crate) const fn runs_contention(self) -> bool {
        self.runs_registration() || self.runs_cancellation()
    }
}

impl fmt::Display for ScenarioSelection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(
            self.to_possible_value()
                .expect("every scenario has a clap value")
                .get_name(),
        )
    }
}

/// Effective benchmark configuration.
#[derive(Debug, Parser)]
#[command(
    name = "timer",
    bin_name = "cargo bench -p commonware-runtime --bench timer --",
    about = "Benchmark the production Commonware and Tokio timer implementations",
    styles = Styles::styled(),
    disable_version_flag = true,
    args_override_self = true,
)]
pub(crate) struct Config {
    /// Scenario groups to run.
    #[arg(long, value_enum, default_value_t = ScenarioSelection::All)]
    pub(crate) scenario: ScenarioSelection,
    /// Timer implementations to compare.
    #[arg(long, value_enum, default_value_t = BackendSelection::All)]
    pub(crate) backend: BackendSelection,
    /// Tokio workers and production timer shards.
    #[arg(
        long,
        default_value_t = DEFAULT_WORKER_THREADS,
        value_parser = parse_positive
    )]
    pub(crate) worker_threads: usize,
    /// Measured batches for each accuracy scenario.
    #[arg(
        long,
        default_value_t = DEFAULT_ACCURACY_BATCHES,
        value_parser = parse_positive
    )]
    pub(crate) accuracy_batches: usize,
    /// Measured batches for each worst-case scenario.
    #[arg(
        long,
        default_value_t = DEFAULT_WORST_BATCHES,
        value_parser = parse_positive
    )]
    pub(crate) worst_batches: usize,
}

impl Config {
    /// Parses process arguments, printing clap diagnostics before exiting.
    pub(crate) fn parse() -> Option<Self> {
        Self::parse_from(env::args_os().skip(1)).unwrap_or_else(|error| error.exit())
    }

    /// Parses an explicit argument stream for production and unit tests.
    fn parse_from<I, T>(arguments: I) -> Result<Option<Self>, clap::Error>
    where
        I: IntoIterator<Item = T>,
        T: Into<OsString>,
    {
        let mut arguments: Vec<_> = arguments.into_iter().map(Into::into).collect();
        let cargo_bench = arguments.iter().any(|argument| argument == "--bench");
        arguments.retain(|argument| argument != "--bench");
        let has_timer_selector = arguments.iter().any(is_timer_selector);

        let config =
            Self::try_parse_from(std::iter::once(OsString::from("timer")).chain(arguments));
        let config = match config {
            Ok(config) => config,
            // Cargo passes filters and harness flags to every benchmark target.
            // If no timer selector was present, an unknown argument belongs to
            // that outer invocation and this expensive custom harness stays idle.
            Err(error)
                if cargo_bench
                    && !has_timer_selector
                    && matches!(
                        error.kind(),
                        ErrorKind::UnknownArgument | ErrorKind::InvalidSubcommand
                    ) =>
            {
                return Ok(None);
            }
            Err(error) => return Err(error),
        };

        if let Err(error) = config.validate() {
            return Err(Self::command().error(ErrorKind::ValueValidation, error));
        }
        Ok(Some(config))
    }

    /// Validates derived counts before starting the runtime.
    fn validate(&self) -> io::Result<()> {
        if self.scenario.runs_accuracy() {
            for &concurrency in &ACCURACY_CONCURRENCY {
                checked_observations(self.accuracy_batches, concurrency)?;
            }
        }
        if self.scenario.runs_registration() {
            checked_observations(self.worst_batches, REGISTRATION_TIMERS)?;
        }
        if self.scenario.runs_cancellation() {
            checked_observations(self.worst_batches, CANCELLATION_TIMERS)?;
            let maximum_producers = *self
                .cancellation_producer_counts_checked()?
                .iter()
                .max()
                .expect("selected cancellation includes a producer count");
            let canceled = CANCELLATION_TIMERS * CANCEL_PERCENT / 100;
            if canceled < maximum_producers {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "--worker-threads selects {maximum_producers} cancellation producers, \
                         but the fixed workload cancels only {canceled} timers"
                    ),
                ));
            }
        }
        if self.scenario.runs_expiry() {
            checked_observations(self.worst_batches, STORM_TIMERS)?;
        }
        Ok(())
    }

    /// Iterates over the concrete backends selected by the user.
    pub(crate) fn backends(&self) -> impl Iterator<Item = Backend> + '_ {
        Backend::ALL
            .into_iter()
            .filter(|backend| self.backend.includes(*backend))
    }

    /// Returns the producer levels selected for cancellation.
    pub(crate) fn cancellation_producer_counts(&self) -> Vec<usize> {
        self.cancellation_producer_counts_checked()
            .expect("selected cancellation topology was validated")
    }

    /// Computes selected cancellation producer levels with checked arithmetic.
    fn cancellation_producer_counts_checked(&self) -> io::Result<Vec<usize>> {
        let mut counts = Vec::with_capacity(3);
        if self.scenario.runs_single_producer() {
            counts.push(1);
        }
        if self.scenario.runs_multiple_producers() {
            counts.push(self.worker_threads);
            counts.push(self.worker_threads.checked_mul(4).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "four times --worker-threads exceeds usize",
                )
            })?);
        }
        counts.sort_unstable();
        counts.dedup();
        counts.retain(|count| self.scenario.runs_single_producer() || *count > 1);
        Ok(counts)
    }

    /// Returns the native shard count when this platform uses native timers.
    pub(crate) const fn shards(&self) -> Option<usize> {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            Some(self.worker_threads)
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            None
        }
    }
}

/// Returns whether one argument selects this benchmark's configuration.
fn is_timer_selector(argument: &OsString) -> bool {
    let Some(argument) = argument.to_str() else {
        return false;
    };
    let option = argument
        .split_once('=')
        .map_or(argument, |(option, _)| option);
    matches!(
        option,
        "-h" | "--help"
            | "--scenario"
            | "--backend"
            | "--worker-threads"
            | "--accuracy-batches"
            | "--worst-batches"
    )
}

/// Parses one positive platform-sized count for clap.
fn parse_positive(value: &str) -> Result<usize, String> {
    let value = value
        .parse::<usize>()
        .map_err(|_| "expected a positive integer".to_owned())?;
    if value == 0 {
        return Err("expected a positive integer".to_owned());
    }
    Ok(value)
}

/// Computes a checked observation count for one scenario.
pub(crate) fn checked_observations(batches: usize, concurrency: usize) -> io::Result<usize> {
    batches.checked_mul(concurrency).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "batches times concurrency exceeds usize",
        )
    })
}
