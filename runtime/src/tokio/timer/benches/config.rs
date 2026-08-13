//! Command-line parsing and checked benchmark configuration.

use clap::{
    CommandFactory, Parser, ValueEnum,
    builder::Styles,
    error::{ContextKind, ErrorKind},
};
use std::{env, ffi::OsString, fmt, io, time::Duration};

/// Default number of Tokio workers and production timer shards.
const DEFAULT_WORKER_THREADS: usize = 4;
/// Largest worker topology supported by this diagnostic harness.
const MAX_WORKER_THREADS: usize = 128;
/// Largest measured batch count supported by this diagnostic harness.
const MAX_BATCHES: usize = 100;
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
        matches!(self, Self::All | Self::WorstCase | Self::Cancellation)
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
    /// Tokio workers and production timer shards, from 1 through 128.
    #[arg(
        long,
        default_value_t = DEFAULT_WORKER_THREADS,
        value_parser = parse_positive
    )]
    pub(crate) worker_threads: usize,
    /// Measured batches for each accuracy scenario, from 1 through 100.
    #[arg(
        long,
        default_value_t = DEFAULT_ACCURACY_BATCHES,
        value_parser = parse_positive
    )]
    pub(crate) accuracy_batches: usize,
    /// Measured batches for each worst-case scenario, from 1 through 100.
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
    pub(crate) fn parse_from<I, T>(arguments: I) -> Result<Option<Self>, clap::Error>
    where
        I: IntoIterator<Item = T>,
        T: Into<OsString>,
    {
        let mut arguments: Vec<_> = arguments.into_iter().map(Into::into).collect();
        let cargo_bench = arguments.iter().any(|argument| argument == "--bench");
        arguments.retain(|argument| argument != "--bench");
        let has_timer_selector = arguments.iter().any(is_timer_selector);
        if !has_timer_selector {
            if !cargo_bench && arguments.is_empty() {
                return Ok(None);
            }
            if !arguments.is_empty() {
                match classify_harness_arguments(&arguments) {
                    HarnessArguments::Valid => return Ok(None),
                    HarnessArguments::Foreign if !arguments.iter().any(is_timer_selector_typo) => {
                        return Ok(None);
                    }
                    HarnessArguments::Foreign | HarnessArguments::Malformed => {}
                }
            }
        }

        let config =
            Self::try_parse_from(std::iter::once(OsString::from("timer")).chain(arguments))?;

        if let Err(error) = config.validate() {
            return Err(Self::command().error(ErrorKind::ValueValidation, error));
        }
        Ok(Some(config))
    }

    /// Validates derived counts before starting the runtime.
    fn validate(&self) -> io::Result<()> {
        validate_maximum(self.worker_threads, MAX_WORKER_THREADS, "--worker-threads")?;
        validate_maximum(self.accuracy_batches, MAX_BATCHES, "--accuracy-batches")?;
        validate_maximum(self.worst_batches, MAX_BATCHES, "--worst-batches")?;
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
        let mut counts = vec![
            1,
            self.worker_threads,
            self.worker_threads.checked_mul(4).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "four times --worker-threads exceeds usize",
                )
            })?,
        ];
        counts.sort_unstable();
        counts.dedup();
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

/// Rejects a count that would create an unreasonable benchmark topology.
fn validate_maximum(value: usize, maximum: usize, option: &str) -> io::Result<()> {
    if value > maximum {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{option} exceeds the benchmark limit of {maximum}"),
        ));
    }
    Ok(())
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

/// Classification of arguments forwarded from another benchmark harness.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HarnessArguments {
    /// Every option and value is recognized and valid.
    Valid,
    /// At least one option belongs to another benchmark implementation.
    Foreign,
    /// A recognized harness option is malformed.
    Malformed,
}

/// Classifies arguments forwarded from Rust's or another benchmark harness.
fn classify_harness_arguments(arguments: &[OsString]) -> HarnessArguments {
    let mut index = 0;
    let mut positional_only = false;
    let mut foreign = false;

    while let Some(argument) = arguments.get(index) {
        index += 1;
        let Some(argument) = argument.to_str() else {
            // Non-UTF-8 filters are valid outer harness inputs.
            continue;
        };
        if positional_only || !argument.starts_with('-') || argument == "-" {
            continue;
        }
        if argument == "--" {
            positional_only = true;
            continue;
        }

        let (option, has_inline_value) = argument
            .split_once('=')
            .map_or((argument, false), |(option, _)| (option, true));
        if matches!(
            option,
            "--list"
                | "--verbose"
                | "-v"
                | "--quiet"
                | "-q"
                | "--ignored"
                | "--include-ignored"
                | "--exact"
                | "--nocapture"
                | "--no-capture"
                | "--show-output"
                | "--report-time"
                | "--ensure-time"
                | "--shuffle"
                | "--test"
                | "--force-run-in-process"
                | "--exclude-should-panic"
                | "--fail-fast"
                | "--version"
                | "-V"
        ) {
            if has_inline_value {
                return HarnessArguments::Malformed;
            }
            continue;
        }
        if matches!(
            option,
            "--color"
                | "--format"
                | "--logfile"
                | "--skip"
                | "--test-threads"
                | "--shuffle-seed"
                | "--output-format"
                | "-Z"
        ) {
            let value = if has_inline_value {
                argument
                    .split_once('=')
                    .expect("inline harness value was already detected")
                    .1
            } else {
                let Some(value) = arguments.get(index).and_then(|value| value.to_str()) else {
                    return HarnessArguments::Malformed;
                };
                index += 1;
                value
            };
            if !is_harness_value(option, value) {
                return HarnessArguments::Malformed;
            }
            continue;
        }
        if let Some(value) = argument.strip_prefix("-Z") {
            if !value.is_empty() && is_harness_value("-Z", value) {
                continue;
            }
            return HarnessArguments::Malformed;
        }
        if argument.strip_prefix('-').is_some_and(|options| {
            !options.is_empty() && options.chars().all(|option| "qv".contains(option))
        }) {
            continue;
        }
        foreign = true;
    }

    if foreign {
        HarnessArguments::Foreign
    } else {
        HarnessArguments::Valid
    }
}

/// Returns whether clap recognizes an unknown option as a timer selector typo.
fn is_timer_selector_typo(argument: &OsString) -> bool {
    let Some(argument_text) = argument.to_str() else {
        return false;
    };
    if !argument_text.starts_with('-') || is_timer_selector(argument) {
        return false;
    }

    let error = Config::try_parse_from([OsString::from("timer"), argument.clone()]);
    error.is_err_and(|error| {
        error.kind() == ErrorKind::UnknownArgument && error.get(ContextKind::SuggestedArg).is_some()
    })
}

/// Validates one value consumed by a recognized harness option.
fn is_harness_value(option: &str, value: &str) -> bool {
    if value.is_empty() || value.starts_with('-') {
        return false;
    }
    match option {
        "--color" => matches!(value, "auto" | "always" | "never"),
        "--format" => matches!(value, "pretty" | "terse" | "json" | "junit"),
        "--test-threads" => value.parse::<usize>().is_ok_and(|value| value > 0),
        "--shuffle-seed" => value.parse::<u64>().is_ok(),
        "-Z" => value == "unstable-options",
        "--logfile" | "--skip" | "--output-format" => true,
        _ => false,
    }
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

/// Computes a checked derived count for one benchmark workload.
pub(crate) fn checked_observations(batches: usize, items_per_batch: usize) -> io::Result<usize> {
    batches.checked_mul(items_per_batch).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "batches times workload size exceeds usize",
        )
    })
}
