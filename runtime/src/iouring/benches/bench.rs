//! Scheduler benchmarks for the io_uring runtime and Tokio's current-thread runtime.
//!
//! The suites cover fixed-total self-wake work, ready task spawn and join, and
//! timer consumer latency under a self-waking ready load. Runtime construction
//! and teardown are outside the durations reported to Criterion. Tokio uses a
//! current-thread runtime with I/O and time enabled, an event interval of 64,
//! and a global queue interval of 31.
//!
//! Each custom Criterion sample has the same timing boundary:
//!
//! ```text
//! construct runtime                 excluded
//!        |
//!        v
//! enter one root future
//!        |
//!        v
//! +-----------------------------+
//! | run and await the workload  |  reported
//! +-----------------------------+
//!        |
//!        v
//! tear down runtime                  excluded
//! ```
//!
//! Results are intentionally reported independently. Compare the two backends
//! from Criterion output rather than enforcing a ratio or threshold here.
//!
//! Run with `cargo bench -p commonware-runtime --bench iouring_scheduler --features iouring`.

use criterion::{criterion_group, criterion_main};

mod self_wake;
mod spawn_join;
mod support;
mod timer_latency;

criterion_group!(
    benches,
    self_wake::bench,
    spawn_join::bench,
    timer_latency::bench
);
criterion_main!(benches);
