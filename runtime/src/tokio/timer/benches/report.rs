//! Shared percentile calculation and benchmark reporting.

use crate::{
    Backend, Config,
    config::{
        ACCURACY_CONCURRENCY, ACCURACY_SPREAD, CANCEL_PERCENT, CANCELLATION_TIMERS, PEER_LEAD,
        REGISTRATION_STEP, REGISTRATION_TIMERS, STORM_LEAD, STORM_TIMERS,
    },
};
use std::{
    fmt::Write as _,
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

/// Largest descriptor count observed while a timer batch was resident.
#[derive(Default)]
pub(crate) struct PeakFdCount {
    /// Largest available observation, or none when counting is unsupported.
    count: Option<usize>,
}

impl PeakFdCount {
    /// Includes one descriptor observation in the reported maximum.
    pub(crate) fn observe(&mut self, count: Option<usize>) {
        if let Some(count) = count {
            self.count = Some(self.count.map_or(count, |peak| peak.max(count)));
        }
    }

    /// Returns a printable maximum or an explicit unavailable marker.
    pub(crate) fn label(&self) -> String {
        fd_count_value_label(self.count)
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
            self.samples = self.samples.saturating_add(1);
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

/// Prints the effective benchmark configuration and platform.
pub(crate) fn print_effective_config(config: &Config) {
    let shards = config
        .shards()
        .map_or_else(|| "tokio-fallback".to_owned(), |count| count.to_string());
    println!(
        "effective_config scenario={} backend={} os={} arch={} worker_threads={} shards={} \
         accuracy_batches={} samples_per_concurrency_slot={} accuracy_concurrency={:?} \
         accuracy_spread_us={} worst_batches={} registration_timers={} registration_step_ns={} \
         cancellation_timers={} cancel_percent={} storm_timers={} storm_lead_us={} \
         peer_lead_us={} fairness_worker_threads=1 fairness_shards={} fd_count={}",
        config.scenario,
        config.backend,
        std::env::consts::OS,
        std::env::consts::ARCH,
        config.worker_threads,
        shards,
        config.accuracy_batches,
        config.accuracy_batches,
        ACCURACY_CONCURRENCY,
        ACCURACY_SPREAD.as_micros(),
        config.worst_batches,
        REGISTRATION_TIMERS,
        REGISTRATION_STEP.as_nanos(),
        CANCELLATION_TIMERS,
        CANCEL_PERCENT,
        STORM_TIMERS,
        STORM_LEAD.as_micros(),
        PEER_LEAD.as_micros(),
        fairness_shards_label(),
        fd_count_label(),
    );
}

/// Prints one duration distribution with common accounting fields.
pub(crate) fn print_duration(
    name: &str,
    batches: usize,
    dimensions: &[(&str, usize)],
    metric: &str,
    samples: &[Duration],
    peak_live_fd_count: Option<&PeakFdCount>,
    additional_fields: Option<&str>,
) -> io::Result<Distribution> {
    let distribution = Distribution::new(samples)?;
    let accounting = format_sample_counts(batches, dimensions, &[(metric, samples.len())]);
    let peak_live_fd_count = peak_live_fd_count.map_or_else(String::new, |peak| {
        format!(" peak_live_fd_count={}", peak.label())
    });
    let additional_fields =
        additional_fields.map_or_else(String::new, |fields| format!(" {fields}"));
    println!(
        "{name} {accounting} {metric}_p50_us={:.3} {metric}_p99_us={:.3} \
         {metric}_max_us={:.3} fd_count={}{}{}",
        micros(distribution.p50),
        micros(distribution.p99),
        micros(distribution.max),
        fd_count_label(),
        peak_live_fd_count,
        additional_fields,
    );
    Ok(distribution)
}

/// Formats workload dimensions and the sample count for each metric.
pub(crate) fn format_sample_counts(
    batches: usize,
    dimensions: &[(&str, usize)],
    metrics: &[(&str, usize)],
) -> String {
    let mut output = format!("batches={batches}");
    for (name, value) in dimensions {
        write!(output, " {name}={value}").expect("writing to a string cannot fail");
    }
    for (name, samples) in metrics {
        write!(output, " {name}_samples={samples}").expect("writing to a string cannot fail");
    }
    output
}

/// Describes deterministic producer placement across native timer shards.
pub(crate) fn cancellation_shard_distribution(
    backend: Backend,
    shards: Option<usize>,
    producers: usize,
) -> String {
    let Backend::Commonware = backend else {
        return "effective_timer_shards=backend-managed \
                producers_per_timer_shard_min=unavailable \
                producers_per_timer_shard_max=unavailable"
            .to_owned();
    };
    let Some(shards) = shards else {
        return "effective_timer_shards=tokio-fallback \
                producers_per_timer_shard_min=unavailable \
                producers_per_timer_shard_max=unavailable"
            .to_owned();
    };

    // Dedicated producer threads receive consecutive round-robin claims.
    let effective = producers.min(shards);
    let minimum = if producers < shards {
        1
    } else {
        producers / shards
    };
    let maximum = producers.div_ceil(shards);
    format!(
        "effective_timer_shards={effective} producers_per_timer_shard_min={minimum} \
         producers_per_timer_shard_max={maximum}"
    )
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
    Ok(last.saturating_duration_since(start))
}

/// Converts a duration to fractional microseconds for compact output.
pub(crate) fn micros(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1_000_000.0
}

/// Returns a printable descriptor count or an explicit unavailable marker.
pub(crate) fn fd_count_label() -> String {
    fd_count_value_label(fd_count())
}

/// Formats a captured descriptor count without taking another observation.
fn fd_count_value_label(count: Option<usize>) -> String {
    count.map_or_else(|| "unavailable".to_owned(), |count| count.to_string())
}

/// Counts open descriptors using the Linux process filesystem.
#[cfg(target_os = "linux")]
pub(crate) fn fd_count() -> Option<usize> {
    // The directory iterator owns one descriptor that appears in its own listing.
    std::fs::read_dir("/proc/self/fd")
        .ok()
        .map(|entries| entries.count().saturating_sub(1))
}

/// Reports descriptor counting as unavailable on platforms without procfs.
#[cfg(not(target_os = "linux"))]
pub(crate) const fn fd_count() -> Option<usize> {
    None
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

/// Returns the fixed fairness shard count for the active platform.
const fn fairness_shards_label() -> &'static str {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        "1"
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        "tokio-fallback"
    }
}
