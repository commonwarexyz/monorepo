//! Matched TCP benchmarks for the io_uring and one-worker Tokio runtimes.
//!
//! The suite exercises the public Commonware [`Network`](commonware_runtime::Network),
//! [`Listener`](commonware_runtime::Listener), [`Sink`](commonware_runtime::Sink), and
//! [`Stream`](commonware_runtime::Stream) traits. It covers connection establishment, 64-byte
//! request and reply exchanges, 64 KiB one-way streams over one or 64 concurrent connections, and
//! one-byte pending receive fanout around a 64-entry io_uring admission boundary. The fanout rows
//! use raw clients so sender work is identical while both backends retain the public listener and
//! stream receive path under test.
//!
//! Runtime construction is outside every returned Criterion duration. Connection establishment
//! is timed only by the connect-and-accept rows. The request and streaming rows establish their
//! connections before starting the clock, then reuse those connections for the complete sample.
//! The pending receive rows also establish their raw-client connections, start their sender helper,
//! construct and initially poll every receive, and yield the root once before timing each batch.
//! Their interval includes the command handoff, identical raw socket writes, and every public
//! receive completion. Payload construction is setup, except for cheap handle clones passed
//! through the public send API.
//!
//! Tokio uses its multi-thread scheduler with one worker and a global queue interval of 31. Both
//! runtimes use identical explicit connect and read/write timeouts, TCP options, loopback
//! TCP, and the same Commonware abstractions. The pending receive Tokio rows report `ring_size=na`
//! because Tokio has no corresponding io_uring capacity setting. Results are reported independently
//! without comparative thresholds.
//!
//! Run with `cargo bench -p commonware-runtime --bench network --features iouring` on Linux.

#[cfg(target_os = "linux")]
use criterion::{criterion_group, criterion_main};

#[cfg(target_os = "linux")]
mod connect_accept;
#[cfg(target_os = "linux")]
mod ping_pong;
#[cfg(target_os = "linux")]
mod ring_pressure;
#[cfg(target_os = "linux")]
mod stream;
#[cfg(target_os = "linux")]
mod support;

#[cfg(target_os = "linux")]
criterion_group!(
    benches,
    connect_accept::bench,
    ping_pong::bench,
    ring_pressure::bench,
    stream::bench
);
#[cfg(target_os = "linux")]
criterion_main!(benches);

#[cfg(not(target_os = "linux"))]
fn main() {}
