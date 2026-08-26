//! One-way 64 KiB streaming throughput over persistent loopback connections.
//!
//! Width one captures one connection's steady-state path. Width 64 keeps 64 sends and 64 exact
//! receives ready together to exercise the runtimes under matched network concurrency. Runtime
//! construction, listener binding, all connection establishment, and payload construction are
//! setup. Each iteration transfers one 64 KiB payload per connection through public Commonware
//! sink and stream APIs.

use super::support::{Backend, connections, iouring_runner, tokio_runner};
use commonware_runtime::{IoBuf, Network, Runner as _, Sink as _, SinkOf, Stream as _, StreamOf};
use criterion::{Criterion, Throughput};
use futures::{future::join_all, join};
use std::time::{Duration, Instant};

/// Payload bytes transferred over each connection per iteration.
const STREAM_BYTES: usize = 64 * 1024;

/// Concurrent persistent connection counts.
const WIDTHS: [usize; 2] = [1, 64];

/// Static payload shared by every connection.
const STREAM_PAYLOAD: &[u8] = &[0xc3; STREAM_BYTES];

/// Register matched streaming rows for both runtimes and both widths.
pub fn bench(c: &mut Criterion) {
    let mut group = c.benchmark_group(module_path!());
    for width in WIDTHS {
        group.throughput(Throughput::Bytes((STREAM_BYTES * width) as u64));
        for backend in Backend::ALL {
            let name = format!(
                "runtime={} width={width} bytes_per_connection={STREAM_BYTES}",
                backend.name()
            );
            match backend {
                Backend::IoUring => group.bench_function(&name, |b| {
                    b.iter_custom(|iters| measure_iouring(iters, width));
                }),
                Backend::Tokio => group.bench_function(&name, |b| {
                    b.iter_custom(|iters| measure_tokio(iters, width));
                }),
            };
        }
    }
    group.finish();
}

/// Measure io_uring streaming inside one runtime root.
fn measure_iouring(iters: u64, width: usize) -> Duration {
    iouring_runner().start(move |network| measure(network, iters, width))
}

/// Measure one-worker Tokio streaming inside one runtime root.
fn measure_tokio(iters: u64, width: usize) -> Duration {
    tokio_runner().start(move |network| measure(network, iters, width))
}

/// Measure concurrent send and receive work over persistent connections.
async fn measure<N: Network>(network: N, iters: u64, width: usize) -> Duration {
    let connections = connections(&network, width).await;
    let mut sinks: Vec<SinkOf<N>> = Vec::with_capacity(width);
    let mut streams: Vec<StreamOf<N>> = Vec::with_capacity(width);
    for (client_sink, client_stream, server_sink, server_stream) in connections {
        sinks.push(client_sink);
        streams.push(server_stream);
        drop((client_stream, server_sink));
    }
    let payload = IoBuf::from(STREAM_PAYLOAD);

    // The single interval starts after every connection is ready. Driving all send and receive
    // futures together prevents socket buffering from serializing the two sides of the workload.
    let start = Instant::now();
    for _ in 0..iters {
        let sends = join_all(sinks.iter_mut().map(|sink| sink.send(payload.clone())));
        let receives = join_all(streams.iter_mut().map(|stream| stream.recv(STREAM_BYTES)));
        let (sends, receives) = join!(sends, receives);

        for result in sends {
            result.expect("failed to stream benchmark payload");
        }
        for result in receives {
            let received = result.expect("failed to receive benchmark stream");
            assert_eq!(received.len(), STREAM_BYTES);
        }
    }
    start.elapsed()
}
