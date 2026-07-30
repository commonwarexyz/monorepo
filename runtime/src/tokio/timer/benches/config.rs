//! Command-line parsing and checked benchmark configuration.

use std::{env, fmt, io, time::Duration};

/// Timer implementations selected for a benchmark run.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BackendSelection {
    /// Run both timer implementations.
    All,
    /// Run only the Commonware clock.
    Commonware,
    /// Run only Tokio's timer.
    Tokio,
}

impl BackendSelection {
    /// Parses the value accepted by `--backend`.
    fn parse(value: &str) -> io::Result<Self> {
        match value {
            "all" => Ok(Self::All),
            "commonware" => Ok(Self::Commonware),
            "tokio" => Ok(Self::Tokio),
            _ => Err(invalid_value(
                "--backend",
                value,
                "expected all, commonware, or tokio",
            )),
        }
    }

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
        match self {
            Self::All => formatter.write_str("all"),
            Self::Commonware => formatter.write_str("commonware"),
            Self::Tokio => formatter.write_str("tokio"),
        }
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
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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
    /// Parses the value accepted by `--scenario`.
    fn parse(value: &str) -> io::Result<Self> {
        match value {
            "all" => Ok(Self::All),
            "accuracy" => Ok(Self::Accuracy),
            "worst-case" => Ok(Self::WorstCase),
            "registration" => Ok(Self::Registration),
            "cancellation" => Ok(Self::Cancellation),
            "cancellation-single" => Ok(Self::CancellationSingle),
            "cancellation-multi" => Ok(Self::CancellationMulti),
            "expiry" => Ok(Self::Expiry),
            _ => Err(invalid_value(
                "--scenario",
                value,
                "expected all, accuracy, worst-case, registration, cancellation, \
                 cancellation-single, cancellation-multi, or expiry",
            )),
        }
    }

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
        match self {
            Self::All => formatter.write_str("all"),
            Self::Accuracy => formatter.write_str("accuracy"),
            Self::WorstCase => formatter.write_str("worst-case"),
            Self::Registration => formatter.write_str("registration"),
            Self::Cancellation => formatter.write_str("cancellation"),
            Self::CancellationSingle => formatter.write_str("cancellation-single"),
            Self::CancellationMulti => formatter.write_str("cancellation-multi"),
            Self::Expiry => formatter.write_str("expiry"),
        }
    }
}

/// Effective benchmark configuration.
#[derive(Debug)]
pub(crate) struct Config {
    /// Scenario groups to run.
    pub(crate) scenario: ScenarioSelection,
    /// Timer implementations to compare.
    pub(crate) backend: BackendSelection,
    /// Tokio workers and production timer shards.
    pub(crate) worker_threads: usize,
    /// Measured batches for each accuracy scenario.
    pub(crate) accuracy_batches: usize,
    /// High-concurrency accuracy levels.
    pub(crate) accuracy_concurrency: Vec<usize>,
    /// Width used to distribute spread-mode registrations.
    pub(crate) accuracy_spread: Duration,
    /// Measured batches for each worst-case scenario.
    pub(crate) worst_batches: usize,
    /// Number of descending registrations per batch.
    pub(crate) registration_timers: usize,
    /// Distance between adjacent descending deadlines.
    pub(crate) registration_step: Duration,
    /// Number of long-lived timers in each cancellation batch.
    pub(crate) cancellation_timers: usize,
    /// Integer percentage of long-lived timers canceled.
    pub(crate) cancel_percent: usize,
    /// Number of timers in each common-deadline expiry storm.
    pub(crate) storm_timers: usize,
    /// Time reserved to register a complete expiry storm.
    pub(crate) storm_lead: Duration,
    /// Time before expiry when the always-runnable peer starts.
    pub(crate) peer_lead: Duration,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            scenario: ScenarioSelection::All,
            backend: BackendSelection::All,
            worker_threads: 4,
            accuracy_batches: 10,
            accuracy_concurrency: vec![1_000, 10_000],
            accuracy_spread: Duration::from_micros(100_000),
            worst_batches: 3,
            registration_timers: 50_000,
            registration_step: Duration::from_nanos(1_000),
            cancellation_timers: 100_000,
            cancel_percent: 99,
            storm_timers: 50_000,
            storm_lead: Duration::from_micros(50_000),
            peer_lead: Duration::from_micros(5_000),
        }
    }
}

impl Config {
    /// Parses process arguments without adding a benchmark dependency.
    pub(crate) fn parse() -> io::Result<Option<Self>> {
        Self::parse_from(env::args().skip(1))
    }

    /// Parses an explicit argument stream for production and unit tests.
    fn parse_from(arguments: impl IntoIterator<Item = String>) -> io::Result<Option<Self>> {
        let mut config = Self::default();
        let mut arguments = arguments.into_iter();

        while let Some(argument) = arguments.next() {
            if matches!(argument.as_str(), "-h" | "--help") {
                print_help();
                return Ok(None);
            }
            // Cargo appends this libtest-compatible marker to custom benches.
            if argument == "--bench" {
                continue;
            }
            // Filtered and harness-oriented Cargo invocations apply their
            // arguments to every bench target. This custom harness has its own
            // selectors, so exit without running its production-sized suite.
            if is_harness_argument(&argument) || !argument.starts_with('-') {
                return Ok(None);
            }

            let (option, inline_value) = argument
                .split_once('=')
                .map_or((argument.as_str(), None), |(option, value)| {
                    (option, Some(value))
                });
            let value = match inline_value {
                Some(value) => value.to_owned(),
                None => arguments.next().ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("missing value for {option}"),
                    )
                })?,
            };

            match option {
                "--scenario" => config.scenario = ScenarioSelection::parse(&value)?,
                "--backend" => config.backend = BackendSelection::parse(&value)?,
                "--worker-threads" => config.worker_threads = parse_nonzero_usize(option, &value)?,
                "--accuracy-batches" | "--batches" => {
                    config.accuracy_batches = parse_nonzero_usize(option, &value)?
                }
                "--accuracy-concurrency" => {
                    config.accuracy_concurrency = parse_nonzero_list(option, &value)?
                }
                "--accuracy-spread-us" => {
                    config.accuracy_spread = Duration::from_micros(parse_u64(option, &value)?);
                }
                "--worst-batches" => config.worst_batches = parse_nonzero_usize(option, &value)?,
                "--registration-timers" => {
                    config.registration_timers = parse_nonzero_usize(option, &value)?
                }
                "--registration-step-ns" => {
                    config.registration_step =
                        Duration::from_nanos(parse_nonzero_u64(option, &value)?);
                }
                "--cancellation-timers" => {
                    config.cancellation_timers = parse_nonzero_usize(option, &value)?
                }
                "--cancel-percent" => config.cancel_percent = parse_nonzero_usize(option, &value)?,
                "--storm-timers" => config.storm_timers = parse_nonzero_usize(option, &value)?,
                "--storm-lead-us" => {
                    config.storm_lead = Duration::from_micros(parse_nonzero_u64(option, &value)?);
                }
                "--peer-lead-us" => {
                    config.peer_lead = Duration::from_micros(parse_nonzero_u64(option, &value)?);
                }
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("unknown option {option}. Use --help for supported options"),
                    ));
                }
            }
        }

        config.validate()?;
        Ok(Some(config))
    }

    /// Validates relationships and sample counts before starting the runtime.
    fn validate(&self) -> io::Result<()> {
        // Validate only selected workloads so profiling can ignore unrelated settings.
        if self.scenario.runs_accuracy() {
            for &concurrency in &self.accuracy_concurrency {
                checked_observations(self.accuracy_batches, concurrency)?;
                concurrency.checked_add(1).ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "accuracy concurrency cannot be represented by a barrier",
                    )
                })?;
            }
        }
        if self.scenario.runs_registration() {
            checked_observations(self.worst_batches, self.registration_timers)?;
        }
        if self.scenario.runs_cancellation() {
            if self.cancel_percent > 100 {
                return Err(invalid_value(
                    "--cancel-percent",
                    &self.cancel_percent.to_string(),
                    "expected a value from 1 through 100",
                ));
            }
            checked_observations(self.worst_batches, self.cancellation_timers)?;
            let maximum_producers = *self
                .cancellation_producer_counts_checked()?
                .iter()
                .max()
                .expect("selected cancellation includes a producer count");
            if self.cancellation_timers < maximum_producers {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "--cancellation-timers must be at least {maximum_producers} so every \
                         producer registers a timer"
                    ),
                ));
            }
            let canceled = self
                .cancellation_timers
                .checked_mul(self.cancel_percent)
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "cancel count overflow")
                })?
                / 100;
            if canceled < maximum_producers {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "--cancellation-timers and --cancel-percent must select at least \
                         {maximum_producers} canceled timers so every producer cancels a timer"
                    ),
                ));
            }
        }
        if self.scenario.runs_expiry() {
            if self.peer_lead >= self.storm_lead {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "--peer-lead-us must be smaller than --storm-lead-us",
                ));
            }
            checked_observations(self.worst_batches, self.storm_timers)?;
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

/// Returns whether an argument belongs to Criterion or libtest.
fn is_harness_argument(argument: &str) -> bool {
    let option = argument
        .split_once('=')
        .map_or(argument, |(option, _)| option);
    if let Some(shorts) = option
        .strip_prefix('-')
        .filter(|shorts| !shorts.is_empty() && !shorts.starts_with('-'))
    {
        // Criterion accepts attached values for these options and clusters its
        // boolean short options, so recognize the same forms.
        return matches!(shorts.as_bytes()[0], b'b' | b'c' | b's' | b'Z')
            || shorts
                .bytes()
                .all(|short| matches!(short, b'V' | b'n' | b'q' | b'v'));
    }
    matches!(
        option,
        "--baseline"
            | "--baseline-lenient"
            | "--color"
            | "--colour"
            | "--confidence-level"
            | "--discard-baseline"
            | "--ensure-time"
            | "--exact"
            | "--exclude-should-panic"
            | "--fail-fast"
            | "--force-run-in-process"
            | "--format"
            | "--ignored"
            | "--include-ignored"
            | "--list"
            | "--load-baseline"
            | "--logfile"
            | "--measurement-time"
            | "--no-capture"
            | "--noise-threshold"
            | "--nocapture"
            | "--noplot"
            | "--nresamples"
            | "--output-format"
            | "--plotting-backend"
            | "--profile-time"
            | "--quick"
            | "--quiet"
            | "--report-time"
            | "--sample-size"
            | "--save-baseline"
            | "--show-output"
            | "--shuffle"
            | "--shuffle-seed"
            | "--significance-level"
            | "--skip"
            | "--test"
            | "--test-threads"
            | "--version"
            | "--verbose"
            | "--warm-up-time"
    )
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

/// Parses a positive platform-sized integer.
fn parse_nonzero_usize(option: &str, value: &str) -> io::Result<usize> {
    let parsed = value
        .parse::<usize>()
        .map_err(|_| invalid_value(option, value, "expected a positive integer"))?;
    if parsed == 0 {
        return Err(invalid_value(option, value, "expected a positive integer"));
    }
    Ok(parsed)
}

/// Parses a comma-separated list of positive platform-sized integers.
fn parse_nonzero_list(option: &str, value: &str) -> io::Result<Vec<usize>> {
    let values = value
        .split(',')
        .map(|item| parse_nonzero_usize(option, item))
        .collect::<io::Result<Vec<_>>>()?;
    if values.is_empty() {
        return Err(invalid_value(
            option,
            value,
            "expected at least one integer",
        ));
    }
    Ok(values)
}

/// Parses an unsigned 64-bit integer.
fn parse_u64(option: &str, value: &str) -> io::Result<u64> {
    value
        .parse::<u64>()
        .map_err(|_| invalid_value(option, value, "expected an unsigned integer"))
}

/// Parses a positive unsigned 64-bit integer.
fn parse_nonzero_u64(option: &str, value: &str) -> io::Result<u64> {
    let parsed = parse_u64(option, value)?;
    if parsed == 0 {
        return Err(invalid_value(option, value, "expected a positive integer"));
    }
    Ok(parsed)
}

/// Builds a consistent invalid-option error.
fn invalid_value(option: &str, value: &str, expectation: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("invalid value {value:?} for {option}, {expectation}"),
    )
}

/// Prints command-line options and their production-sized defaults.
fn print_help() {
    println!(
        "\
Usage: cargo bench -p commonware-runtime --bench timer -- [OPTIONS]

Options:
  --scenario <SCENARIO>                  all, accuracy, worst-case, registration,
                                         cancellation, cancellation-single,
                                         cancellation-multi, or expiry [default: all]
  --backend <all|commonware|tokio>       Timer backend [default: all]
  --worker-threads <N>                   Tokio workers and native shards [default: 4]
  --accuracy-batches <N>                 Batches per accuracy case [default: 10]
  --batches <N>                          Alias for --accuracy-batches
  --accuracy-concurrency <N,N>           Higher concurrency levels [default: 1000,10000]
  --accuracy-spread-us <N>               Spread-mode window [default: 100000]
  --worst-batches <N>                    Batches per worst-case setting [default: 3]
  --registration-timers <N>              Descending registrations [default: 50000]
  --registration-step-ns <N>             Descending deadline spacing [default: 1000]
  --cancellation-timers <N>              Long-lived timers [default: 100000]
  --cancel-percent <1..100>               Timers canceled [default: 99]
  --storm-timers <N>                     Common-deadline timers [default: 50000]
  --storm-lead-us <N>                    Storm registration lead [default: 50000]
  --peer-lead-us <N>                     Peer start lead [default: 5000]
  -h, --help                              Print this help"
    );
}

#[cfg(test)]
#[path = "config_tests.rs"]
mod tests;
