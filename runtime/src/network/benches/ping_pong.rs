//! Request and reply latency for contiguous and two-chunk vectored payloads.
//!
//! Each iteration sends a 64-byte client request, receives it completely on the server, sends a
//! 64-byte reply with the same buffer shape, and receives it completely on the client. Runtime
//! construction, listener binding, connection establishment, and initial payload construction are
//! setup. The timed interval includes public send and receive calls, receive allocation, payload
//! handle cloning, completion checks, and buffer destruction.

use super::support::{Backend, connections, iouring_runner, tokio_runner};
use commonware_runtime::{IoBuf, IoBufs, Network, Runner as _, Sink as _, Stream as _};
use criterion::{Criterion, Throughput};
use std::time::{Duration, Instant};

/// Logical request or reply size in bytes.
const PAYLOAD_BYTES: usize = 64;

/// Static contiguous bytes used by the single-buffer row.
const CONTIGUOUS_PAYLOAD: &[u8] = &[0x5a; PAYLOAD_BYTES];

/// Static half used twice by the vectored row.
const PAYLOAD_HALF: &[u8] = &[0xa5; PAYLOAD_BYTES / 2];

/// Physical representation passed through the public sink API.
#[derive(Clone, Copy)]
enum PayloadShape {
    /// One immutable 64-byte buffer.
    Contiguous,
    /// Two immutable 32-byte buffers forming one logical message.
    Vectored,
}

impl PayloadShape {
    /// Shapes emitted for each runtime.
    const ALL: [Self; 2] = [Self::Contiguous, Self::Vectored];

    /// Return the stable benchmark parameter value for this shape.
    const fn name(self) -> &'static str {
        match self {
            Self::Contiguous => "contiguous",
            Self::Vectored => "two_chunk_vectored",
        }
    }

    /// Build the payload before timing starts.
    fn payload(self) -> IoBufs {
        match self {
            Self::Contiguous => IoBufs::from(CONTIGUOUS_PAYLOAD),
            Self::Vectored => {
                IoBufs::from(vec![IoBuf::from(PAYLOAD_HALF), IoBuf::from(PAYLOAD_HALF)])
            }
        }
    }
}

/// Register matched 64-byte request and reply rows for both runtimes.
pub fn bench(c: &mut Criterion) {
    let mut group = c.benchmark_group(module_path!());
    group.throughput(Throughput::Bytes((PAYLOAD_BYTES * 2) as u64));
    for shape in PayloadShape::ALL {
        for backend in Backend::ALL {
            let name = format!(
                "runtime={} payload={} bytes={PAYLOAD_BYTES}",
                backend.name(),
                shape.name()
            );
            match backend {
                Backend::IoUring => group.bench_function(&name, |b| {
                    b.iter_custom(|iters| measure_iouring(iters, shape));
                }),
                Backend::Tokio => group.bench_function(&name, |b| {
                    b.iter_custom(|iters| measure_tokio(iters, shape));
                }),
            };
        }
    }
    group.finish();
}

/// Measure io_uring request and reply exchanges inside one runtime root.
fn measure_iouring(iters: u64, shape: PayloadShape) -> Duration {
    iouring_runner().start(move |network| measure(network, iters, shape))
}

/// Measure one-worker Tokio request and reply exchanges inside one runtime root.
fn measure_tokio(iters: u64, shape: PayloadShape) -> Duration {
    tokio_runner().start(move |network| measure(network, iters, shape))
}

/// Measure complete request and reply exchanges over one persistent connection.
async fn measure<N: Network>(network: N, iters: u64, shape: PayloadShape) -> Duration {
    let mut connections = connections(&network, 1).await;
    let (mut client_sink, mut client_stream, mut server_sink, mut server_stream) = connections
        .pop()
        .expect("one benchmark connection was requested");
    let payload = shape.payload();

    // The single interval starts only after connection and payload setup. It deliberately includes
    // every steady-state operation and its result handling.
    let start = Instant::now();
    for _ in 0..iters {
        client_sink
            .send(payload.clone())
            .await
            .expect("failed to send benchmark request");
        let request = server_stream
            .recv(PAYLOAD_BYTES)
            .await
            .expect("failed to receive benchmark request");
        assert_eq!(request.len(), PAYLOAD_BYTES);

        server_sink
            .send(payload.clone())
            .await
            .expect("failed to send benchmark reply");
        let reply = client_stream
            .recv(PAYLOAD_BYTES)
            .await
            .expect("failed to receive benchmark reply");
        assert_eq!(reply.len(), PAYLOAD_BYTES);
    }
    start.elapsed()
}
