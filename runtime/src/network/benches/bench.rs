//! Matched TCP benchmarks for the io_uring and one-worker Tokio runtimes.
//!
//! Every row uses the public Commonware [`Network`](commonware_runtime::Network),
//! [`Listener`](commonware_runtime::Listener), [`Sink`](commonware_runtime::Sink), and
//! [`Stream`](commonware_runtime::Stream) traits. The suite covers connection establishment,
//! 64-byte request and reply exchanges, and 64 KiB one-way streams over one or 64 concurrent
//! connections.
//!
//! Runtime construction is outside every returned Criterion duration. Connection establishment
//! is timed only by the connect-and-accept rows. The request and streaming rows establish their
//! connections before starting the clock, then reuse those connections for the complete sample.
//! Payload construction is also setup, except for cheap handle clones passed through the public
//! send API.
//!
//! Tokio uses its multi-thread scheduler with one worker and a global queue interval of 31. Both
//! runtimes use identical explicit connect and read/write timeouts, default TCP options, loopback
//! TCP, and the same Commonware abstractions. Results are reported independently without
//! comparative thresholds.
//!
//! Run with `cargo bench -p commonware-runtime --bench network --features iouring` on Linux.

#[cfg(target_os = "linux")]
use criterion::{criterion_group, criterion_main};

#[cfg(target_os = "linux")]
mod connect_accept;
#[cfg(target_os = "linux")]
mod ping_pong;
#[cfg(target_os = "linux")]
mod stream;
#[cfg(target_os = "linux")]
mod support;

#[cfg(target_os = "linux")]
criterion_group!(
    benches,
    connect_accept::bench,
    ping_pong::bench,
    stream::bench
);
#[cfg(target_os = "linux")]
criterion_main!(benches);

#[cfg(not(target_os = "linux"))]
fn main() {}
