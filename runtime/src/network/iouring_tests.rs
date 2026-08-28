use super::{RawSocketAddr, Sink, Stream, local_addr, new_socket};
use crate::{
    BufferPool, BufferPoolConfig, Error, IoBuf, IoBufs, Listener as _, Network as _, Runner as _,
    Sink as _, Stream as _, Supervisor as _, iouring,
    iouring::testing::{TestLoop, poll_once},
    network::{
        iouring::{Config, Network},
        tests,
    },
    telemetry::metrics::{Register, Registry},
};
use commonware_macros::test_group;
use std::{
    net::SocketAddr,
    os::{fd::AsRawFd, unix::net::UnixStream},
    sync::Arc,
    time::{Duration, Instant},
};

fn test_pool(scope: &mut impl Register) -> BufferPool {
    BufferPool::new(BufferPoolConfig::for_network(), scope)
}

/// Start a test network backed by a loop harness on this thread, mirroring
/// how the runtime hands the network a driver for the runtime-driven loop.
fn test_network_with_ring(cfg: Config, ring: iouring::RingConfig) -> (TestLoop, Network) {
    let mut registry = Registry::default();
    let pool = test_pool(&mut registry.sub_registry("pool"));
    // Match the runtime's startup behavior so network deadlines are never
    // clamped by the loop's timeout horizon.
    let max_request_timeout = cfg.read_write_timeout.max(cfg.connect_timeout);
    let harness = TestLoop::new_with_max_request_timeout(ring, max_request_timeout);
    let network = Network::new(cfg, harness.clone_handle(), pool);
    (harness, network)
}

/// [test_network_with_ring] with the default ring configuration.
fn test_network(cfg: Config) -> (TestLoop, Network) {
    test_network_with_ring(cfg, iouring::RingConfig::default())
}

#[test]
fn test_trait() {
    // Verify the io_uring backend satisfies the shared network trait suite.
    let (mut harness, network) = test_network(Config {
        read_write_timeout: Duration::from_secs(15),
        ..Default::default()
    });
    harness.block_on(tests::test_network_trait(move || network.clone()));

    // The sub-tests share one driver, so a slot leaked by any of them
    // would degrade the others: assert everything was reclaimed.
    assert_eq!(harness.tracked(), 0, "trait suite leaked waiter slots");
}

#[test]
fn test_connect_timeout() {
    let connect_timeout = Duration::from_millis(100);
    let (mut harness, network) = test_network(Config {
        connect_timeout,
        ..Default::default()
    });

    // Create a loopback listener with the smallest possible accept queue
    // and fill it with one unaccepted connection, so the dial below stays
    // pending until its timeout fires. Mirrors the shared
    // `test_network_connect_timeout` helper, which needs a tokio reactor.
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let fd = new_socket(&addr).expect("failed to create listener socket");
    let raw = RawSocketAddr::from_socket_addr(&addr);
    // SAFETY: `fd` owns a live descriptor and the pointer references an
    // encoded address of the provided length.
    let rc = unsafe { libc::bind(fd.as_raw_fd(), raw.as_sockaddr_ptr(), raw.len()) };
    assert!(rc != -1, "failed to bind listener socket");
    // SAFETY: `fd` owns a live descriptor, and `listen` touches no caller memory.
    let rc = unsafe { libc::listen(fd.as_raw_fd(), 0) };
    assert!(rc != -1, "failed to listen on socket");
    let listener_addr = local_addr(&fd).expect("failed to read listener address");
    let _queued_connection =
        std::net::TcpStream::connect(listener_addr).expect("failed to fill listener accept queue");

    let start = Instant::now();
    let result = harness.block_on(network.dial(listener_addr));
    assert!(matches!(result, Err(Error::Timeout)));

    // Confirm the dial remained pending for the configured budget and
    // the timed-out connect released its waiter slot.
    assert!(start.elapsed() >= connect_timeout);
    assert_eq!(harness.tracked(), 0, "connect timeout leaked waiter slots");
}

#[test]
fn test_foreign_worker_dial_panics_before_admission() {
    let (harness, network) = test_network(Config::default());
    let addr = "127.0.0.1:9".parse().unwrap();

    let panicked = std::thread::spawn(move || {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            futures::executor::block_on(network.dial(addr))
        }));
        result.is_err()
    })
    .join()
    .unwrap();

    assert!(panicked, "foreign dial must panic on worker affinity");
    assert_eq!(harness.tracked(), 0, "foreign dial admitted an operation");
}

#[test_group("slow")]
#[test]
fn test_stress_trait() {
    // Exercise the io_uring backend under the shared stress suite on the
    // real runtime, with a ring large enough that nearly every stream can
    // keep an operation in flight.
    let runner = crate::iouring::Runner::new(crate::iouring::Config::default().with_ring(
        iouring::RingConfig {
            size: 256,
            ..Default::default()
        },
    ));
    runner.start(|context| async move {
        // The context doubles as the network under test, and contexts are
        // only duplicable through the supervision tree.
        let network = context.child("network");
        tests::stress_test_network_trait(move || network.child("socket"), context).await;
    });
}

#[test]
fn test_ipv6_end_to_end() {
    // Preflight with the standard library so skipping means the host lacks
    // IPv6 loopback. An io_uring `BindFailed` must remain a test failure.
    if std::net::TcpListener::bind("[::1]:0").is_err() {
        return;
    }

    let (mut harness, network) = test_network(Config::default());
    harness.block_on(async move {
        let mut listener = network.bind("[::1]:0".parse().unwrap()).await.unwrap();
        let addr = listener.local_addr().unwrap();
        assert!(addr.is_ipv6(), "listener must bind a v6 address");

        let ping = b"ping".to_vec();
        let pong = b"pong".to_vec();

        let server = async {
            let (remote, mut sink, mut stream) = listener.accept().await.unwrap();
            assert!(remote.is_ipv6(), "accepted peer must decode as v6");
            let received = stream.recv(4).await.unwrap();
            sink.send(b"pong".to_vec()).await.unwrap();
            received
        };

        let client = async {
            let (mut sink, mut stream) = network.dial(addr).await.unwrap();
            sink.send(b"ping".to_vec()).await.unwrap();
            stream.recv(4).await.unwrap()
        };

        let (received_ping, received_pong) = futures::join!(server, client);
        assert_eq!(received_ping.coalesce(), ping.as_slice());
        assert_eq!(received_pong.coalesce(), pong.as_slice());
    });
}

#[test]
fn test_read_timeout_with_partial_data() {
    // Verify a top-level recv returns timeout after partial progress stalls.
    let op_timeout = Duration::from_millis(100);
    let (mut harness, network) = test_network(Config {
        read_write_timeout: op_timeout,
        ..Default::default()
    });
    harness.block_on(async move {
        let mut listener = network.bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let addr = listener.local_addr().unwrap();

        let reader = async move {
            let (_addr, _sink, mut stream) = listener.accept().await.unwrap();

            // Try to read 100 bytes, but only 5 will be sent
            let start = Instant::now();
            let result = stream.recv(100).await;
            let elapsed = start.elapsed();

            (result, elapsed)
        };

        // Connect and send only partial data. Keep the connection open so
        // the reader observes a stall rather than EOF.
        let sender = async {
            let (mut sink, stream) = network.dial(addr).await.unwrap();
            sink.send([1u8, 2, 3, 4, 5].as_slice()).await.unwrap();
            (sink, stream)
        };

        let ((result, elapsed), (_sink, _stream)) = futures::join!(reader, sender);
        assert!(matches!(result, Err(Error::Timeout)));

        // Verify the timeout occurred around the expected time, with some
        // margin for timing variance.
        assert!(elapsed >= op_timeout);
        assert!(elapsed < op_timeout * 3);
    });
}

#[test]
fn test_unbuffered_mode() {
    // Verify disabling the internal read buffer preserves direct recv behavior.
    let (mut harness, network) = test_network(Config {
        read_buffer_size: 0,
        ..Default::default()
    });
    harness.block_on(async move {
        let mut listener = network.bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Accept one connection and verify that peeking never observes
        // buffered bytes because the wrapper retains no internal read state.
        let reader = async move {
            let (_addr, _sink, mut stream) = listener.accept().await.unwrap();

            // In unbuffered mode, peek should always return empty
            assert!(stream.peek(100).is_empty());

            // Read messages without buffering
            let buf1 = stream.recv(5).await.unwrap();

            // Even after recv, peek should be empty in unbuffered mode
            assert!(stream.peek(100).is_empty());

            let buf2 = stream.recv(5).await.unwrap();
            assert!(stream.peek(100).is_empty());

            (buf1, buf2)
        };

        // Send two independent messages so the reader exercises repeated
        // direct recvs.
        let sender = async {
            let (mut sink, _stream) = network.dial(addr).await.unwrap();
            sink.send([1u8, 2, 3, 4, 5].as_slice()).await.unwrap();
            sink.send([6u8, 7, 8, 9, 10].as_slice()).await.unwrap();
            (sink, _stream)
        };

        let ((buf1, buf2), (_sink, _stream)) = futures::join!(reader, sender);
        assert_eq!(buf1.coalesce(), &[1u8, 2, 3, 4, 5]);
        assert_eq!(buf2.coalesce(), &[6u8, 7, 8, 9, 10]);
    });
}

#[test]
fn test_op_fd_keeps_descriptor_alive() {
    // Verify admitted recv requests keep their socket fd alive after
    // caller cancellation: the slot's fd clone prevents the OS from
    // reusing the FD number while the kernel may still reference it.
    let op_timeout = Duration::from_millis(200);
    let (mut harness, network) = test_network(Config {
        read_write_timeout: op_timeout,
        ..Default::default()
    });

    // Keep the server halves alive so the connection stays open while the
    // client recv is in flight.
    let (_server_halves, client_sink, mut client_stream) = harness.block_on(async {
        let mut listener = network.bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accept = async { listener.accept().await.unwrap() };
        let dial = async { network.dial(addr).await.unwrap() };
        let (server_halves, (client_sink, client_stream)) = futures::join!(accept, dial);
        (server_halves, client_sink, client_stream)
    });

    // Sink + stream + our clone.
    let fd = client_stream.fd.clone();
    assert_eq!(Arc::strong_count(&fd), 3);

    // Cancel a recv mid-flight (no data arrives): admit and submit the
    // recv, then drop the future.
    {
        let mut recv = Box::pin(client_stream.recv(1));
        assert!(poll_once(&harness, &mut recv).is_pending());
        harness.turn();

        // The admitted request holds an additional clone.
        assert_eq!(Arc::strong_count(&fd), 4);
    }

    // Drop all handles. The in-flight request still retains the fd until
    // the eager cancellation retires it.
    drop(client_sink);
    drop(client_stream);
    assert_eq!(Arc::strong_count(&fd), 2); // our clone + request

    // The dropped future requested cancellation, so the fd releases
    // promptly rather than at the deadline.
    let start = Instant::now();
    while Arc::strong_count(&fd) != 1 {
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "cancelled recv still holds fd after {:?}",
            start.elapsed()
        );
        harness.turn();
        harness.park(Some(Duration::from_millis(10)));
    }
}

#[test]
fn test_inflight_cancel_poisons_stream() {
    // Verify cancelling a recv whose SQE already reached the kernel
    // poisons the stream while the sink stays usable: the shared-suite
    // variant drops its recv before the loop ever turns, so only this
    // test exercises the kernel-in-flight cancel with stream poisoning.
    let (mut harness, network) = test_network(Config::default());

    // Keep the server halves alive so the connection stays open.
    let (_server_halves, mut client_sink, mut client_stream) = harness.block_on(async {
        let mut listener = network.bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accept = async { listener.accept().await.unwrap() };
        let dial = async { network.dial(addr).await.unwrap() };
        let (server_halves, (client_sink, client_stream)) = futures::join!(accept, dial);
        (server_halves, client_sink, client_stream)
    });

    // Admit and submit the recv, then drop the future mid-flight.
    {
        let mut recv = Box::pin(client_stream.recv(1));
        assert!(poll_once(&harness, &mut recv).is_pending());
        harness.turn();
    }

    harness.block_on(async {
        // The stream must be poisoned by the cancellation.
        assert!(matches!(client_stream.recv(1).await, Err(Error::Closed)));

        // The sink must remain usable.
        client_sink
            .send(crate::IoBuf::from(b"ok"))
            .await
            .expect("sink should remain usable after stream cancellation");
    });
}

#[test]
fn test_peek_with_buffered_data() {
    // Verify buffered recv calls leave unread bytes visible via peek().
    let (mut harness, network) = test_network(Config::default());
    harness.block_on(async move {
        let mut listener = network.bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let addr = listener.local_addr().unwrap();

        let reader = async move {
            let (_addr, _sink, mut stream) = listener.accept().await.unwrap();

            assert!(stream.peek(100).is_empty());

            // Receive partial data - this should buffer more than requested
            let first = stream.recv(5).await.unwrap();
            assert_eq!(first.coalesce(), b"hello");

            // Peek should show remaining buffered data
            let peeked = stream.peek(100);
            assert!(!peeked.is_empty());
            assert_eq!(peeked, b" world");

            // Peek again should return the same (non-consuming)
            assert_eq!(stream.peek(100), b" world");

            // Peek with max_len should truncate
            assert_eq!(stream.peek(3), b" wo");

            // Receive the rest
            let rest = stream.recv(6).await.unwrap();
            assert_eq!(rest.coalesce(), b" world");

            // Peek should be empty after consuming all buffered data
            assert!(stream.peek(100).is_empty());
        };

        let sender = async {
            let (mut sink, _stream) = network.dial(addr).await.unwrap();
            sink.send(b"hello world").await.unwrap();
            (sink, _stream)
        };

        let ((), (_sink, _stream)) = futures::join!(reader, sender);
    });
}

#[test]
fn test_zero_length_send_short_circuits_before_submit() {
    // Verify empty sends return locally without staging any request.
    let mut harness = TestLoop::new(iouring::RingConfig::default());
    harness.close_admission();

    // Construct a sink whose driver would fail immediately if the wrapper
    // tried to hand work to the loop.
    let (left, _right) = UnixStream::pair().unwrap();
    let mut sink = Sink::new(
        Arc::new(left.into()),
        harness.clone_handle(),
        Duration::from_secs(1),
    );

    harness.block_on(sink.send(IoBufs::default())).unwrap();
    harness.block_on(sink.send(IoBuf::default())).unwrap();
    harness.block_on(sink.send(Vec::<u8>::new())).unwrap();
}

#[test]
fn test_large_recv_skips_internal_buffer() {
    // Verify reads that are at least as large as the internal buffer go
    // straight into the caller-owned output buffer.
    let (mut harness, network) = test_network(Config {
        read_buffer_size: 8,
        ..Default::default()
    });
    harness.block_on(async move {
        let mut listener = network.bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let expected = *b"abcdefgh";

        // Accept one connection and issue a recv that exactly matches the
        // internal buffer size, forcing the direct-recv branch.
        let reader = async move {
            let (_addr, _sink, mut stream) = listener.accept().await.unwrap();
            let received = stream.recv(expected.len()).await.unwrap();
            assert!(stream.peek(1).is_empty());
            received
        };

        let sender = async {
            let (mut sink, _stream) = network.dial(addr).await.unwrap();
            sink.send(expected.to_vec()).await.unwrap();
            (sink, _stream)
        };

        let (received, (_sink, _stream)) = futures::join!(reader, sender);
        assert_eq!(received.coalesce(), expected);
    });
}

#[test]
fn test_closed_driver_fallbacks() {
    // Verify send/recv callers get wrapper-level failures once the driver
    // has closed.
    let mut registry = Registry::default();
    let pool = test_pool(&mut registry.sub_registry("pool"));
    let mut harness = TestLoop::new(iouring::RingConfig::default());
    harness.close_admission();

    // Send should fail locally once the driver no longer admits work.
    let (send_left, _send_right) = UnixStream::pair().unwrap();
    let mut sink = Sink::new(
        Arc::new(send_left.into()),
        harness.clone_handle(),
        Duration::from_secs(1),
    );
    assert!(matches!(
        harness.block_on(sink.send(b"hello")),
        Err(Error::SendFailed)
    ));

    // Recv should surface the symmetric wrapper-specific failure.
    let (recv_left, _recv_right) = UnixStream::pair().unwrap();
    let mut stream = Stream::new(
        Arc::new(recv_left.into()),
        harness.clone_handle(),
        Duration::from_secs(1),
        0,
        pool,
    );
    assert!(matches!(
        harness.block_on(stream.recv(1)),
        Err(Error::RecvFailed)
    ));
}

#[test]
fn test_closed_driver_public_dial_and_accept() {
    // Accept normalizes the internal fallback to `Closed` for tokio parity,
    // while dial exposes `ConnectionFailed` unchanged.
    let (mut harness, network) = test_network(Config::default());
    let mut listener = harness
        .block_on(network.bind("127.0.0.1:0".parse().unwrap()))
        .unwrap();
    let addr = listener.local_addr().unwrap();

    harness.close_admission();

    assert!(matches!(
        harness.block_on(listener.accept()),
        Err(Error::Closed)
    ));
    assert!(
        listener.pending_accept.is_none(),
        "a failed accept must not retain a pending ticket"
    );

    assert!(matches!(
        harness.block_on(network.dial(addr)),
        Err(Error::ConnectionFailed)
    ));
}
