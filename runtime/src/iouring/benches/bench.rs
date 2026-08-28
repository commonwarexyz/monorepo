//! Scheduler benchmarks for io_uring and Commonware's one-worker Tokio runtime.
//!
//! The suites cover fixed-total self-wake and foreign-wake work, low-load
//! parked wakes, ready task spawn and join, fixed-total timer cancellation,
//! and timer consumer latency under a self-waking ready load.
//!
//! Self-wake, foreign-wake, and spawn-and-join throughput samples each report
//! one root-level workload interval. The interval starts after runtime
//! construction and root entry, spans the workload iterations, and ends before
//! runtime teardown.
//!
//! Foreign-wake rows start a helper thread and wait for it before entering the
//! runtime root. The timed interval covers bounded-channel wake handoffs and
//! scheduler reinjection. Helper shutdown and joining are excluded. These rows
//! are not proven parked-wake latency measurements because the helper may wake
//! a task before the executor enters the kernel.
//!
//! Parked-wake rows leave the runtime root pending with no other benchmark
//! work, then have a foreign helper wait 5 milliseconds before waking it. The
//! reported interval starts when the helper publishes its timestamp immediately
//! before `Waker::wake` and ends when the root next polls its wait future. It
//! includes timestamp publication, the wake call, scheduler reinjection and
//! unpark, root scheduling, and the final future poll. Runtime construction,
//! the request handoff, the 5 millisecond park-settle delay, helper shutdown,
//! and helper joining are excluded. The delay is a practical assumption that
//! the otherwise idle runtime has passed its spin phase and parked. Host
//! preemption means the benchmark cannot directly prove kernel park state.
//!
//! Timer latency instead reports the sum of consumer-local intervals under the
//! persistent load. Each interval starts when the timer consumer is first
//! polled and ends when it wakes after the requested delay. Load setup, load
//! teardown, and queueing before the consumer's first poll are excluded.
//!
//! Timer cancellation reports the sum of fixed-total cancellation intervals.
//! Before each interval, the benchmark allocates a batch of long-deadline
//! sleeps. Each interval polls every sleep once to register it, verifies that
//! it is pending, and drops the batch. Runtime construction, root entry, and
//! batch construction are excluded. Dropping the batch includes future
//! destruction, timer cancellation, tombstone accounting, and compaction.
//!
//! Tokio rows use Commonware's Tokio runtime with one worker and a global queue
//! interval of 31. Both backends therefore include the same public context,
//! supervision, metrics, task handle, and result-transport abstractions.
//!
//! Results are intentionally reported independently. Compare the two backends
//! from Criterion output rather than enforcing a ratio or threshold here.
//!
//! Run with `cargo bench -p commonware-runtime --bench iouring_scheduler --features iouring`.

#[cfg(target_os = "linux")]
use criterion::{criterion_group, criterion_main};

#[cfg(target_os = "linux")]
mod foreign_wake;
#[cfg(target_os = "linux")]
mod parked_wake;
#[cfg(target_os = "linux")]
mod self_wake;
#[cfg(target_os = "linux")]
mod spawn_join;
#[cfg(target_os = "linux")]
mod support;
#[cfg(target_os = "linux")]
mod timer_cancel;
#[cfg(target_os = "linux")]
mod timer_latency;

#[cfg(target_os = "linux")]
criterion_group!(
    benches,
    foreign_wake::bench,
    parked_wake::bench,
    self_wake::bench,
    spawn_join::bench,
    timer_cancel::bench,
    timer_latency::bench
);
#[cfg(target_os = "linux")]
criterion_main!(benches);

#[cfg(not(target_os = "linux"))]
fn main() {}
