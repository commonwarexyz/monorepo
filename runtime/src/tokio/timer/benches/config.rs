//! Command-line configuration for the timer benchmarks.

use clap::{Parser, ValueEnum, builder::RangedU64ValueParser};
use std::{env, ffi::OsString, fmt, time::Duration};

/// Default number of Tokio workers and production timer shards.
const DEFAULT_WORKER_THREADS: usize = 4;
/// Default batches measured for each accuracy scenario.
const DEFAULT_ACCURACY_BATCHES: usize = 10;
/// Default batches measured for each worst-case scenario.
const DEFAULT_WORST_BATCHES: usize = 3;
/// Task counts used by loaded accuracy scenarios.
pub(crate) const ACCURACY_TASKS: [usize; 2] = [1_000, 10_000];
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

/// A timer implementation under measurement.
#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub(crate) enum Backend {
    /// The production Commonware Tokio clock.
    Commonware,
    /// A direct `tokio::time` baseline.
    Tokio,
}

impl Backend {
    /// All backends in stable output order.
    const ALL: [Self; 2] = [Self::Commonware, Self::Tokio];

    /// Stable value used in machine-readable output.
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Commonware => "commonware",
            Self::Tokio => "tokio",
        }
    }
}

impl fmt::Display for Backend {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.name())
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

    /// Stable value used in machine-readable output.
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::Accuracy => "accuracy",
            Self::WorstCase => "worst-case",
            Self::Registration => "registration",
            Self::Cancellation => "cancellation",
            Self::Expiry => "expiry",
        }
    }
}

impl fmt::Display for ScenarioSelection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.name())
    }
}

/// Effective benchmark configuration.
#[derive(Debug, Parser)]
#[command(
    name = "timer",
    bin_name = "cargo bench -p commonware-runtime --bench timer --",
    about = "Benchmark the production Commonware and Tokio timer implementations"
)]
pub(crate) struct Config {
    /// Scenario group to run.
    #[arg(long, value_enum, default_value_t = ScenarioSelection::All)]
    pub(crate) scenario: ScenarioSelection,
    /// Timer implementation to run. Omit to compare both.
    #[arg(long, value_enum)]
    pub(crate) backend: Option<Backend>,
    /// Tokio workers and production timer shards, from 1 through 128.
    #[arg(
        long,
        default_value_t = DEFAULT_WORKER_THREADS,
        value_parser = RangedU64ValueParser::<usize>::new().range(1..=128)
    )]
    pub(crate) worker_threads: usize,
    /// Measured batches for each accuracy scenario, from 1 through 100.
    #[arg(
        long,
        default_value_t = DEFAULT_ACCURACY_BATCHES,
        value_parser = RangedU64ValueParser::<usize>::new().range(1..=100)
    )]
    pub(crate) accuracy_batches: usize,
    /// Measured batches for each worst-case scenario, from 1 through 100.
    #[arg(
        long,
        default_value_t = DEFAULT_WORST_BATCHES,
        value_parser = RangedU64ValueParser::<usize>::new().range(1..=100)
    )]
    pub(crate) worst_batches: usize,
}

impl Config {
    /// Parses a Cargo benchmark invocation, printing diagnostics before exiting.
    pub(crate) fn parse() -> Option<Self> {
        Self::parse_from(env::args_os().skip(1)).unwrap_or_else(|error| error.exit())
    }

    /// Parses an explicit Cargo benchmark argument stream for unit tests.
    pub(crate) fn parse_from<I, T>(arguments: I) -> Result<Option<Self>, clap::Error>
    where
        I: IntoIterator<Item = T>,
        T: Into<OsString>,
    {
        let mut arguments: Vec<_> = arguments.into_iter().map(Into::into).collect();
        if arguments
            .last()
            .is_none_or(|argument| argument != "--bench")
        {
            return Ok(None);
        }
        arguments.pop();

        Self::try_parse_from(std::iter::once(OsString::from("timer")).chain(arguments)).map(Some)
    }

    /// Iterates over the backends selected by the user.
    pub(crate) fn backends(&self) -> impl Iterator<Item = Backend> + '_ {
        Backend::ALL
            .into_iter()
            .filter(|backend| self.backend.is_none_or(|selected| selected == *backend))
    }

    /// Returns the producer levels used for cancellation.
    pub(crate) fn cancellation_producer_counts(&self) -> Vec<usize> {
        let mut counts = vec![1, self.worker_threads, self.worker_threads * 4];
        counts.sort_unstable();
        counts.dedup();
        counts
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
