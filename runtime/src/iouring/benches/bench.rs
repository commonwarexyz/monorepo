//! Scheduler benchmarks for the io_uring runtime and Tokio's current-thread runtime.
//!
//! The suites cover fixed-total self-wake work, ready task spawn and join, and
//! timer consumer latency under a self-waking ready load.
//!
//! Each throughput sample reports one root-level workload interval. The interval
//! starts after runtime construction and root entry, spans all self-wake or
//! spawn-and-join iterations, and ends before runtime teardown.
//!
//! Timer latency instead reports the sum of consumer-local intervals under the
//! persistent load. Each interval starts when the timer consumer is first
//! polled and ends when it wakes after the requested delay. Load setup, load
//! teardown, and queueing before the consumer's first poll are excluded.
//!
//! Tokio uses a current-thread runtime with I/O and time enabled, an event
//! interval of 64, and a global queue interval of 31.
//!
//! Results are intentionally reported independently. Compare the two backends
//! from Criterion output rather than enforcing a ratio or threshold here.
//!
//! Run with `cargo bench -p commonware-runtime --bench iouring_scheduler --features iouring`.

#[cfg(target_os = "linux")]
use criterion::{criterion_group, criterion_main};

#[cfg(target_os = "linux")]
mod self_wake;
#[cfg(target_os = "linux")]
mod spawn_join;
#[cfg(target_os = "linux")]
mod support;
#[cfg(target_os = "linux")]
mod timer_latency;

#[cfg(target_os = "linux")]
criterion_group!(
    benches,
    self_wake::bench,
    spawn_join::bench,
    timer_latency::bench
);
#[cfg(target_os = "linux")]
criterion_main!(benches);

#[cfg(not(target_os = "linux"))]
fn main() {}
