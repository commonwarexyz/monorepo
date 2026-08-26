//! Shared runtime configuration and connection setup for network benchmarks.

use commonware_runtime::{
    Listener as _, ListenerOf, Network, SinkOf, StreamOf,
    iouring::{self, Runner as IoUringRunner},
    tokio::{self, Runner as TokioRunner},
};
use std::{net::SocketAddr, time::Duration};

/// Connect and read/write timeout shared by both network implementations.
///
/// Workloads never use a timer directly. The timeout bounds public dial and established I/O calls
/// if a backend stops making progress. The io_uring listener also applies its configured accept
/// deadline, while Tokio accept has no corresponding timeout.
const NETWORK_TIMEOUT: Duration = Duration::from_secs(30);

/// Runtime implementation exercised by a benchmark row.
#[derive(Clone, Copy)]
pub enum Backend {
    /// Commonware's single-threaded io_uring runtime.
    IoUring,
    /// Commonware's Tokio multi-thread scheduler configured with one worker.
    Tokio,
}

impl Backend {
    /// Backends emitted for every workload shape.
    pub const ALL: [Self; 2] = [Self::IoUring, Self::Tokio];

    /// Return the stable benchmark parameter value for this backend.
    pub const fn name(self) -> &'static str {
        match self {
            Self::IoUring => "iouring",
            Self::Tokio => "tokio_multi_thread_1w",
        }
    }
}

/// Client and server halves for one established connection.
///
/// Client halves are first, followed by server halves.
pub type Connection<N> = (SinkOf<N>, StreamOf<N>, SinkOf<N>, StreamOf<N>);

/// Construct the io_uring runner used by every io_uring row.
pub fn iouring_runner() -> IoUringRunner {
    IoUringRunner::new(
        iouring::Config::default()
            .with_connect_timeout(NETWORK_TIMEOUT)
            .with_read_write_timeout(NETWORK_TIMEOUT),
    )
}

/// Construct the one-worker Tokio baseline used by every Tokio row.
pub fn tokio_runner() -> TokioRunner {
    TokioRunner::new(
        tokio::Config::default()
            .with_worker_threads(1)
            .with_global_queue_interval(31)
            .with_connect_timeout(NETWORK_TIMEOUT)
            .with_read_write_timeout(NETWORK_TIMEOUT),
    )
}

/// Bind a listener to an ephemeral IPv4 loopback port.
pub async fn bind_loopback<N: Network>(network: &N) -> ListenerOf<N> {
    network
        .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .expect("failed to bind benchmark listener")
}

/// Establish one connection through concurrent public dial and accept calls.
pub async fn connect<N: Network>(
    network: &N,
    listener: &mut ListenerOf<N>,
    address: SocketAddr,
) -> Connection<N> {
    let (accepted, dialed) = futures::join!(listener.accept(), network.dial(address));
    let (_, server_sink, server_stream) = accepted.expect("failed to accept benchmark connection");
    let (client_sink, client_stream) = dialed.expect("failed to dial benchmark listener");
    (client_sink, client_stream, server_sink, server_stream)
}

/// Establish `width` connections before a steady-state measurement begins.
pub async fn connections<N: Network>(network: &N, width: usize) -> Vec<Connection<N>> {
    let mut listener = bind_loopback(network).await;
    let address = listener
        .local_addr()
        .expect("failed to read benchmark listener address");
    let mut connections = Vec::with_capacity(width);
    for _ in 0..width {
        connections.push(connect(network, &mut listener, address).await);
    }
    connections
}
