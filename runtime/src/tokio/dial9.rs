//! Optional [dial9](https://github.com/dial9-rs/dial9) trace recording for the `tokio`
//! runtime.
//!
//! When a [Config] is provided via
//! [Config::with_dial9](crate::tokio::Config::with_dial9), the runtime records every task
//! poll, spawn, and worker park/unpark into rotating trace files for post-hoc analysis.
//! Tasks spawned through the runtime are additionally wrapped with dial9 wake-event
//! tracking, which records when a task became ready to run in addition to when it was
//! polled, so per-task scheduling delay is measurable. Recorded spawn locations point
//! at the application's `context.spawn(...)` call sites, so trace analysis groups
//! tasks by the code that spawned them.
//!
//! On Linux, sampled CPU stacks and kernel scheduler events (to attribute
//! time a worker spent descheduled mid-poll) are recorded onto the same
//! timeline.
//!
//! # Coverage
//!
//! The runner's root future and tasks using dedicated or blocking shared
//! execution are driven with `Runtime::block_on`, outside a Tokio task. Their
//! polls and wakes are therefore not recorded. Use the default async
//! [Spawner::spawn](crate::Spawner::spawn) execution for per-task visibility.
//!
//! Recording is production-safe by design: if the trace directory cannot be
//! created, telemetry is disabled with an error log and the runtime starts
//! normally. Trace files are rotated and bounded by a total disk budget.
//!
//! # Build requirements
//!
//! Tokio only exposes its runtime hooks when built with the `tokio_unstable`
//! cfg, which must apply to the whole build (compilation fails with an
//! explanation otherwise). Frame pointers make CPU stack samples usable.
//! Set both in the binary's `.cargo/config.toml`:
//!
//! ```toml
//! [build]
//! rustflags = ["--cfg", "tokio_unstable", "-C", "force-frame-pointers=yes"]
//! ```
//!
//! # System requirements (Linux profiling)
//!
//! CPU and scheduler profiling use `perf_event_open`, which the kernel gates
//! behind `perf_event_paranoid` (unless the process has `CAP_PERFMON`). CPU
//! sampling requires a value of 2 or lower and scheduler events 1 or lower.
//! Kernel frames in scheduler stacks only symbolize when `kptr_restrict`
//! is 0:
//!
//! ```text
//! sudo sysctl kernel.perf_event_paranoid=1
//! sudo sysctl kernel.kptr_restrict=0
//! ```
//!
//! Both profilers log an error and stay off when unavailable, and the tokio
//! event stream still records.
//!
//! # Overhead and volume
//!
//! dial9 documents roughly 50ns per event with two events per poll, about
//! 1us of kernel reads per worker park/unpark, and a 1 MiB thread-local
//! buffer per recording thread. A busy service can produce tens of GiB of
//! trace per day, so size [Config::with_max_total_size] to the capture
//! window needed (the oldest files are evicted once the budget is reached).
//!
//! # Analysis
//!
//! View recorded traces with the `dial9` CLI
//! (`cargo install --locked dial9 --features cli`):
//!
//! ```text
//! dial9 serve --local-dir <trace_directory>
//! ```
//!
//! For scripted analysis, `dial9 agents` unpacks skill documentation and a
//! JS toolkit for querying traces programmatically.
//!
//! # Example
//!
//! ```no_run
//! use commonware_runtime::{tokio, Runner as _};
//!
//! let cfg = tokio::Config::default()
//!     .with_dial9(tokio::dial9::Config::new("/tmp/my_traces"));
//! tokio::Runner::new(cfg).start(|context| async move {
//!     // Tasks spawned with the default async execution are traced.
//! });
//! ```

// `rustdoc` invocations receive RUSTDOCFLAGS rather than RUSTFLAGS, so doc
// builds and doctest collection are exempt.
#[cfg(all(not(tokio_unstable), not(any(doc, doctest))))]
compile_error!(
    "the `dial9` feature requires RUSTFLAGS=\"--cfg tokio_unstable\" so tokio exposes its runtime hooks"
);

use ::dial9::{
    Dial9HandleTokioExt as _, DiskBuffer, Recorder, RecorderPerfExt as _, TokioAttachOptions,
    cpu::{CpuProfilingConfig, SchedEventConfig},
    recorder_or_disabled, spawn_in,
};
use std::{future::Future, path::PathBuf, time::Duration};
use tokio::runtime::{Builder, Handle, Runtime};

/// Configuration for dial9 trace recording.
#[derive(Clone, Debug)]
pub struct Config {
    /// Directory to write rotating trace files into.
    ///
    /// Created if it does not exist. If creation fails, recording is
    /// disabled with an error log and the runtime starts normally.
    trace_directory: PathBuf,

    /// Maximum total size of trace files on disk, in bytes.
    ///
    /// The oldest files are evicted to stay within budget.
    ///
    /// Defaults to 1 GiB.
    max_total_size: u64,

    /// How often to rotate to a new trace file.
    ///
    /// Defaults to 60 seconds.
    rotation_period: Duration,

    /// Whether to record task spawn/terminate events.
    ///
    /// Defaults to `true`.
    task_tracking: bool,

    /// Whether to record sampled CPU stacks (Linux only).
    ///
    /// Defaults to `true`.
    cpu_profiling: bool,

    /// Whether to record kernel scheduler events for off-CPU analysis
    /// (Linux only).
    ///
    /// Defaults to `true`.
    sched_profiling: bool,

    /// How long to wait for trace processing to drain on shutdown.
    ///
    /// Defaults to 5 seconds.
    shutdown_timeout: Duration,
}

impl Config {
    /// Returns a new [Config] writing traces to `trace_directory`.
    pub fn new(trace_directory: impl Into<PathBuf>) -> Self {
        Self {
            trace_directory: trace_directory.into(),
            max_total_size: 1024 * 1024 * 1024, // 1 GiB
            rotation_period: Duration::from_secs(60),
            task_tracking: true,
            cpu_profiling: true,
            sched_profiling: true,
            shutdown_timeout: Duration::from_secs(5),
        }
    }

    // Setters
    /// See [Config]
    pub const fn with_max_total_size(mut self, n: u64) -> Self {
        self.max_total_size = n;
        self
    }
    /// See [Config]
    pub const fn with_rotation_period(mut self, d: Duration) -> Self {
        self.rotation_period = d;
        self
    }
    /// See [Config]
    pub const fn with_task_tracking(mut self, b: bool) -> Self {
        self.task_tracking = b;
        self
    }
    /// See [Config]
    pub const fn with_cpu_profiling(mut self, b: bool) -> Self {
        self.cpu_profiling = b;
        self
    }
    /// See [Config]
    pub const fn with_sched_profiling(mut self, b: bool) -> Self {
        self.sched_profiling = b;
        self
    }
    /// See [Config]
    pub const fn with_shutdown_timeout(mut self, d: Duration) -> Self {
        self.shutdown_timeout = d;
        self
    }

    // Getters
    /// See [Config]
    pub const fn trace_directory(&self) -> &PathBuf {
        &self.trace_directory
    }
    /// See [Config]
    pub const fn max_total_size(&self) -> u64 {
        self.max_total_size
    }
    /// See [Config]
    pub const fn rotation_period(&self) -> Duration {
        self.rotation_period
    }
    /// See [Config]
    pub const fn task_tracking(&self) -> bool {
        self.task_tracking
    }
    /// See [Config]
    pub const fn cpu_profiling(&self) -> bool {
        self.cpu_profiling
    }
    /// See [Config]
    pub const fn sched_profiling(&self) -> bool {
        self.sched_profiling
    }
    /// See [Config]
    pub const fn shutdown_timeout(&self) -> Duration {
        self.shutdown_timeout
    }
}

/// Drops the Tokio runtime before shutting down its dial9 recorder.
pub(super) struct InstrumentedRuntime {
    // Fields are dropped in declaration order. Keep the runtime before the
    // recorder so worker-local trace buffers are flushed before the recorder
    // drains the trace pipeline.
    runtime: Runtime,
    _recorder: RecorderShutdown,
}

impl InstrumentedRuntime {
    pub(super) const fn new(runtime: Runtime, recorder: Option<(Recorder, Duration)>) -> Self {
        Self {
            runtime,
            _recorder: RecorderShutdown(recorder),
        }
    }
}

impl std::ops::Deref for InstrumentedRuntime {
    type Target = Runtime;

    fn deref(&self) -> &Self::Target {
        &self.runtime
    }
}

struct RecorderShutdown(Option<(Recorder, Duration)>);

impl Drop for RecorderShutdown {
    fn drop(&mut self) {
        if let Some((recorder, timeout)) = self.0.take() {
            recorder.graceful_shutdown(timeout);
        }
    }
}

/// Build a [Recorder] from `cfg` and a tokio [Runtime] instrumented against
/// it.
///
/// `configure` receives the runtime builder to apply the runtime's own
/// settings (worker counts, stack sizes, etc.). Drop the [Runtime] before
/// calling [Recorder::graceful_shutdown] so worker-local trace buffers are
/// flushed.
pub(super) fn attach(
    cfg: &Config,
    configure: impl FnOnce(&mut Builder),
) -> std::io::Result<(Recorder, Runtime)> {
    let writer = DiskBuffer::builder()
        .base_path(&cfg.trace_directory)
        .max_total_size(cfg.max_total_size)
        .rotation_period(cfg.rotation_period)
        .build();
    let mut recorder = recorder_or_disabled(writer);
    if cfg.cpu_profiling {
        recorder = recorder.with_cpu_profiling(CpuProfilingConfig::default());
    }
    if cfg.sched_profiling {
        recorder = recorder.with_sched_events(SchedEventConfig::default().include_kernel(true));
    }
    let recorder = recorder.build();
    let mut builder = Builder::new_multi_thread();
    configure(&mut builder);
    let runtime = recorder.handle().attach_tokio_runtime(
        builder,
        TokioAttachOptions::builder()
            .runtime_name("commonware")
            .task_tracking_enabled(cfg.task_tracking)
            .build(),
    )?;
    Ok((recorder, runtime))
}

/// Returns whether `recorder` is actually recording, so untraced runtimes
/// skip spawn instrumentation entirely.
pub(super) fn traced(recorder: &Recorder) -> bool {
    recorder.handle().is_enabled()
}

/// Spawn `future` on `runtime` wrapped with dial9 wake-event tracking, so
/// per-task scheduling delay is recorded.
///
/// Propagates the caller's location into tokio's spawn so recorded spawn
/// sites point at application code.
#[track_caller]
pub(super) fn spawn<F>(runtime: &Handle, future: F)
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    spawn_in(runtime, future);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Runner as _, Spawner as _, tokio};

    #[test]
    fn test_trace_recorded() {
        let trace_directory =
            std::env::temp_dir().join(format!("commonware_dial9_test_{}", std::process::id()));
        let cfg = tokio::Config::default().with_dial9(
            Config::new(&trace_directory)
                .with_cpu_profiling(false)
                .with_sched_profiling(false),
        );
        let spawn_line = line!() + 2;
        tokio::Runner::new(cfg).start(|context| async move {
            let handle = context.spawn(|_| async move { 42 });
            assert_eq!(handle.await.unwrap(), 42);
        });

        // The recorder wrote trace segments attributing the spawn to the
        // `context.spawn` call site above (guarding `#[track_caller]`
        // propagation through the spawn path).
        let location = format!("{}:{spawn_line}", file!());
        let location = location.as_bytes();
        let attributed = std::fs::read_dir(&trace_directory)
            .unwrap()
            .map(|entry| std::fs::read(entry.unwrap().path()).unwrap())
            .any(|segment| {
                segment
                    .windows(location.len())
                    .any(|window| window == location)
            });
        assert!(attributed);
        std::fs::remove_dir_all(&trace_directory).unwrap();
    }

    #[test]
    fn test_invalid_trace_directory_disables_recording() {
        let trace_directory = std::env::temp_dir().join(format!(
            "commonware_dial9_invalid_path_test_{}",
            std::process::id()
        ));
        std::fs::write(&trace_directory, []).unwrap();
        let cfg = tokio::Config::default().with_dial9(
            Config::new(&trace_directory)
                .with_cpu_profiling(false)
                .with_sched_profiling(false),
        );

        let output = tokio::Runner::new(cfg)
            .start(|context| async move { context.spawn(|_| async move { 42 }).await.unwrap() });

        assert_eq!(output, 42);
        std::fs::remove_file(trace_directory).unwrap();
    }

    #[test]
    fn test_recorder_shutdown_waits_for_returned_context() {
        let trace_directory = std::env::temp_dir().join(format!(
            "commonware_dial9_returned_context_test_{}",
            std::process::id()
        ));
        if trace_directory.exists() {
            std::fs::remove_dir_all(&trace_directory).unwrap();
        }
        let cfg = tokio::Config::default().with_dial9(
            Config::new(&trace_directory)
                .with_cpu_profiling(false)
                .with_sched_profiling(false),
        );

        let context = tokio::Runner::new(cfg).start(|context| async move { context });

        let has_segment = |suffix: &str| {
            std::fs::read_dir(&trace_directory).unwrap().any(|entry| {
                entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .ends_with(suffix)
            })
        };
        assert!(has_segment(".bin.active"));

        drop(context);
        assert!(!has_segment(".bin.active"));
        assert!(has_segment(".bin"));
        std::fs::remove_dir_all(trace_directory).unwrap();
    }
}
