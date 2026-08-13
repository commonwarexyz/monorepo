//! Percentile calculation and machine-readable benchmark reporting.

use crate::{Backend, Config};
use std::{
    io,
    time::{Duration, Instant},
};

/// Nearest-rank summary for a nonempty duration sample.
#[derive(Clone, Copy)]
pub(crate) struct Distribution {
    /// Empirical median.
    pub(crate) p50: Duration,
    /// Empirical 99th percentile.
    pub(crate) p99: Duration,
    /// Largest observed value.
    pub(crate) max: Duration,
}

impl Distribution {
    /// Sorts a copy of the samples and derives the reported percentiles.
    pub(crate) fn new(samples: &[Duration]) -> io::Result<Self> {
        if samples.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "cannot report an empty distribution",
            ));
        }
        let mut sorted = samples.to_vec();
        sorted.sort_unstable();
        let p50 = percentile_index(sorted.len(), 50)?;
        let p99 = percentile_index(sorted.len(), 99)?;
        Ok(Self {
            p50: sorted[p50],
            p99: sorted[p99],
            max: *sorted.last().expect("distribution was checked as nonempty"),
        })
    }
}

/// Largest monotonic interval bracketing paired wall-clock observations.
#[derive(Default)]
pub(crate) struct ClockPairSpan {
    /// Number of wall-clock pairs observed.
    samples: usize,
    /// Largest span between the surrounding monotonic observations.
    maximum: Duration,
}

impl ClockPairSpan {
    /// Includes one optional clock-pair span in the reported bound.
    pub(crate) fn observe(&mut self, span: Option<Duration>) {
        if let Some(span) = span {
            self.samples += 1;
            self.maximum = self.maximum.max(span);
        }
    }

    /// Formats the span and whether the named latency is exact or an upper bound.
    pub(crate) fn label(&self, bound_name: &str) -> String {
        let bound = if self.samples == 0 { "exact" } else { "upper" };
        format!(
            "clock_pair_span_samples={} clock_pair_span_max_ns={} {bound_name}={bound}",
            self.samples,
            self.maximum.as_nanos(),
        )
    }
}

/// Prints the benchmark configuration for one runtime topology.
pub(crate) fn print_effective_config(
    config: &Config,
    runtime_scope: &str,
    worker_threads: usize,
    shards: Option<usize>,
) {
    let backend = config.backend.map_or("all", Backend::name);
    let shards = shards.map_or_else(|| "tokio-fallback".to_owned(), |count| count.to_string());
    println!(
        "effective_config runtime_scope={runtime_scope} scenario={} backend={backend} os={} \
         arch={} worker_threads={worker_threads} \
         commonware_timer_shards={shards} accuracy_batches={} worst_batches={}",
        config.scenario,
        std::env::consts::OS,
        std::env::consts::ARCH,
        config.accuracy_batches,
        config.worst_batches,
    );
}

/// Prints one accuracy distribution and its clock-pair bound.
pub(crate) fn print_accuracy(
    name: &str,
    batches: usize,
    samples: &[Duration],
    clock_pair_bound: &str,
) -> io::Result<()> {
    let distribution = Distribution::new(samples)?;
    println!(
        "{name} batches={batches} lateness_samples={} lateness_p50_us={:.3} \
         lateness_p99_us={:.3} lateness_max_us={:.3} {clock_pair_bound}",
        samples.len(),
        micros(distribution.p50),
        micros(distribution.p99),
        micros(distribution.max),
    );
    Ok(())
}

/// Describes the timer shards used by one backend.
pub(crate) fn timer_shards_label(backend: Backend, shards: Option<usize>) -> String {
    match (backend, shards) {
        (Backend::Commonware, Some(shards)) => shards.to_string(),
        (Backend::Commonware, None) => "tokio-fallback".to_owned(),
        (Backend::Tokio, _) => "backend-managed".to_owned(),
    }
}

/// Measures from release through the final recorded operation completion.
pub(crate) fn elapsed_through_last(
    start: Instant,
    completions: impl IntoIterator<Item = Instant>,
) -> io::Result<Duration> {
    let last = completions.into_iter().max().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "cannot measure drain without a completed operation",
        )
    })?;
    last.checked_duration_since(start).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "cancellation completed before its common release",
        )
    })
}

/// Converts a duration to fractional microseconds for compact output.
pub(crate) fn micros(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1_000_000.0
}

/// Returns the checked zero-based index for a nearest-rank percentile.
fn percentile_index(length: usize, percentile: usize) -> io::Result<usize> {
    if length == 0 || !(1..=100).contains(&percentile) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "percentiles require samples and a rank from 1 through 100",
        ));
    }
    let scaled = length.checked_mul(percentile).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "sample count times percentile exceeds usize",
        )
    })?;
    scaled.div_ceil(100).checked_sub(1).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "nearest-rank percentile produced no sample",
        )
    })
}
