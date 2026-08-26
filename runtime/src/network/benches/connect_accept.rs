//! TCP connection establishment through matched public dial and accept calls.
//!
//! Listener binding and runtime construction are setup. Each iteration starts immediately before
//! concurrently polling one dial and one accept, then stops once both calls complete and their
//! results are validated. Dropping the established connection is excluded so the row represents
//! establishment, not socket teardown.

use super::support::{Backend, bind_loopback, connect, iouring_runner, tokio_runner};
use commonware_runtime::{Listener as _, Network, Runner as _};
use criterion::{Criterion, Throughput};
use std::time::{Duration, Instant};

/// Register matched connect-and-accept rows for both runtimes.
pub fn bench(c: &mut Criterion) {
    let mut group = c.benchmark_group(module_path!());
    group.throughput(Throughput::Elements(1));
    for backend in Backend::ALL {
        let name = format!("runtime={}", backend.name());
        match backend {
            Backend::IoUring => group.bench_function(&name, |b| {
                b.iter_custom(measure_iouring);
            }),
            Backend::Tokio => group.bench_function(&name, |b| {
                b.iter_custom(measure_tokio);
            }),
        };
    }
    group.finish();
}

/// Measure io_uring connection establishment inside one runtime root.
fn measure_iouring(iters: u64) -> Duration {
    iouring_runner().start(move |network| measure(network, iters))
}

/// Measure one-worker Tokio connection establishment inside one runtime root.
fn measure_tokio(iters: u64) -> Duration {
    tokio_runner().start(move |network| measure(network, iters))
}

/// Sum only the interval in which both sides establish each connection.
async fn measure<N: Network>(network: N, iters: u64) -> Duration {
    let mut listener = bind_loopback(&network).await;
    let address = listener
        .local_addr()
        .expect("failed to read benchmark listener address");
    let mut elapsed = Duration::ZERO;

    for _ in 0..iters {
        // Stop the interval before dropping the socket halves. This keeps close behavior and client
        // port reclamation out of the connect-and-accept measurement.
        let start = Instant::now();
        let connection = connect(&network, &mut listener, address).await;
        elapsed += start.elapsed();
        drop(connection);
    }

    elapsed
}
