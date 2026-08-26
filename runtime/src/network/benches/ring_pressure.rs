//! Pending receive fanout around the io_uring ring capacity.
//!
//! The io_uring rows use a 64-entry ring and fanouts immediately below, at, and above its
//! waiter-backed operation capacity. Setup creates persistent loopback connections whose raw
//! [`std::net::TcpStream`] clients remain owned by one helper thread and whose server stream halves
//! remain owned by the Commonware runtime.
//!
//! Before each timed batch, the benchmark constructs every one-byte receive future, polls the
//! joined future once and asserts that it is pending, then yields the root exactly once. Returning
//! control to the io_uring worker loop stages its admitted receives. Tokio registers socket
//! readiness during the initial receive poll and has no corresponding ring-staging boundary. The
//! interval starts immediately before commanding the helper to write one byte on every connection.
//! It stops only after the helper reports completion and every public Commonware receive completes.
//! Sender command handling and raw socket writes are included, but the sender mechanism is
//! identical for both backends. Result validation, helper startup, and helper shutdown are outside
//! the clock. The workload does not call timer or runtime worker-spawn APIs.
//!
//! Tokio exercises the same pending receive fanout through its public Commonware stream path. It
//! has no io_uring capacity setting, so its benchmark names report `ring_size=na`.

use super::support::{Backend, bind_loopback, iouring_runner_with_ring, tokio_runner};
use commonware_runtime::{Listener as _, Network, Runner as _, Stream as _, StreamOf, reschedule};
use commonware_utils::channel::oneshot;
use criterion::{Criterion, Throughput};
use futures::{future::join_all, join};
use std::{
    io::{self, Write},
    net::{SocketAddr, TcpStream},
    sync::mpsc::{self, Sender},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

/// io_uring waiter capacity exercised by every io_uring row.
const RING_SIZE: u32 = 64;

/// Concurrent pending receive counts around the configured capacity.
const WIDTHS: [usize; 4] = [63, 64, 65, 128];

/// Byte written once to every connection in each batch.
const SEND_BYTE: &[u8] = &[0x5a];

/// Raw sender thread state returned across runtime teardown for an untimed join.
struct RawSender {
    /// Sends one completion channel per batch to release the helper.
    commands: Sender<oneshot::Sender<io::Result<usize>>>,
    /// Helper that owns every raw client socket.
    helper: JoinHandle<usize>,
}

/// Completed benchmark state whose validation must happen outside the runtime and clock.
struct Measurement {
    /// Sum of timed fanout intervals.
    elapsed: Duration,
    /// Raw sender helper to join after runtime teardown.
    helper: JoinHandle<usize>,
}

/// Register matched pending receive fanout rows for both runtimes.
pub fn bench(c: &mut Criterion) {
    let mut group = c.benchmark_group(module_path!());
    for width in WIDTHS {
        group.throughput(Throughput::Elements(width as u64));
        for backend in Backend::ALL {
            let ring_size = match backend {
                Backend::IoUring => RING_SIZE.to_string(),
                Backend::Tokio => "na".to_string(),
            };
            let name = format!(
                "runtime={} ring_size={ring_size} pending_receive_fanout={width} bytes_per_connection=1",
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

/// Measure pending receive fanout on io_uring with the explicit benchmark ring size.
fn measure_iouring(iters: u64, width: usize) -> Duration {
    let measurement =
        iouring_runner_with_ring(RING_SIZE).start(move |network| measure(network, iters, width));
    finish_measurement(measurement, iters, width)
}

/// Measure pending receive fanout on the one-worker Tokio adapter.
fn measure_tokio(iters: u64, width: usize) -> Duration {
    let measurement = tokio_runner().start(move |network| measure(network, iters, width));
    finish_measurement(measurement, iters, width)
}

/// Create raw loopback clients on one helper thread and retain them there until shutdown.
fn start_raw_sender(address: SocketAddr, width: usize) -> RawSender {
    let (commands, receiver) = mpsc::channel::<oneshot::Sender<io::Result<usize>>>();
    let helper = thread::spawn(move || {
        let mut clients = Vec::with_capacity(width);
        for _ in 0..width {
            let client = TcpStream::connect(address).expect("failed to connect raw sender client");
            client
                .set_nodelay(true)
                .expect("failed to configure raw sender client");
            clients.push(client);
        }

        let mut writes = 0usize;
        for completion in receiver {
            let result = clients.iter_mut().try_fold(0usize, |batch_writes, client| {
                client.write_all(SEND_BYTE).map(|()| batch_writes + 1)
            });
            if let Ok(batch_writes) = result {
                writes = writes
                    .checked_add(batch_writes)
                    .expect("raw sender write count overflowed");
            }
            let _ = completion.send(result);
        }
        writes
    });
    RawSender { commands, helper }
}

/// Build persistent raw-client to Commonware-server connections before measurement.
async fn setup<N: Network>(network: &N, width: usize) -> (Vec<StreamOf<N>>, RawSender) {
    let mut listener = bind_loopback(network).await;
    let address = listener
        .local_addr()
        .expect("failed to read pending receive listener address");
    let sender = start_raw_sender(address, width);
    let mut streams = Vec::with_capacity(width);
    for _ in 0..width {
        let (_, server_sink, server_stream) = listener
            .accept()
            .await
            .expect("failed to accept raw sender connection");
        drop(server_sink);
        streams.push(server_stream);
    }
    drop(listener);
    (streams, sender)
}

/// Time command handoff, identical raw writes, and all public receive completions.
async fn measure<N: Network>(network: N, iters: u64, width: usize) -> Measurement {
    let (mut streams, sender) = setup(&network, width).await;
    let RawSender { commands, helper } = sender;
    let mut elapsed = Duration::ZERO;

    for _ in 0..iters {
        let receives = join_all(
            streams
                .iter_mut()
                .map(|stream| stream.recv(SEND_BYTE.len())),
        );
        let mut receives = std::pin::pin!(receives);
        assert!(
            futures::poll!(receives.as_mut()).is_pending(),
            "pending receive fanout became ready before sender release"
        );

        // The first poll admits every operation that fits. Returning from one root yield lets the
        // io_uring worker stage those operations before the helper can make sockets readable.
        // Tokio registered its read interests during the first poll and needs no staging step.
        reschedule().await;

        let (completion_tx, completion_rx) = oneshot::channel();
        let start = Instant::now();
        let commanded = commands.send(completion_tx);
        let (sent, received) = join!(completion_rx, receives);
        let batch_elapsed = start.elapsed();

        assert!(
            commanded.is_ok(),
            "raw sender helper stopped before command"
        );
        let sent = sent
            .expect("raw sender helper stopped before completion")
            .expect("raw sender write failed");
        assert_eq!(sent, width);
        for result in received {
            let received = result.expect("pending receive failed");
            assert_eq!(received.coalesce(), SEND_BYTE);
        }
        elapsed += batch_elapsed;
    }

    drop(commands);
    Measurement { elapsed, helper }
}

/// Join the raw helper and validate its total outside the runtime and measured intervals.
fn finish_measurement(measurement: Measurement, iters: u64, width: usize) -> Duration {
    let writes = measurement
        .helper
        .join()
        .expect("raw sender helper panicked");
    let expected = usize::try_from(iters)
        .expect("iteration count does not fit usize")
        .checked_mul(width)
        .expect("expected raw sender write count overflowed");
    assert_eq!(writes, expected);
    measurement.elapsed
}
