use super::{
    super::{AcceptTicket, Cache, handle::SyncTicket, testing::*},
    *,
};
use crate::{Error, IoBuf, IoBufMut, IoBufs, WriteOptions, telemetry::metrics::Registry};
use commonware_utils::sync::Mutex;
use futures::task::{ArcWake, waker as arc_waker};
use std::{
    fs::File,
    future::Future,
    io::{Read, Write},
    os::{
        fd::{FromRawFd, IntoRawFd, OwnedFd},
        unix::net::UnixStream,
    },
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::{Duration, Instant},
};

#[test]
fn test_iouring_loop_rounds_ring_size_up_to_power_of_two() {
    let cfg = RingConfig {
        size: 100,
        ..Default::default()
    };
    let mut registry = Registry::default();
    let (mut ring, handle, _ioloop) = IoUringLoop::new(cfg, Duration::from_secs(60), &mut registry)
        .expect("io_uring creation should succeed");
    assert_eq!(ring.submission().capacity(), 128);
    handle.with(|ops| assert_eq!(ops.waiters.free_len(), 128));
}

#[test]
fn test_ring_size_accepts_linux_limit_after_rounding() {
    assert_eq!(MAX_RING_SIZE, 32_768);
    assert_eq!(validated_ring_size(MAX_RING_SIZE / 2 + 1), MAX_RING_SIZE);
    assert_eq!(validated_ring_size(MAX_RING_SIZE), MAX_RING_SIZE);
}

#[test]
fn test_ring_size_rejects_rounded_size_above_linux_limit() {
    let rejected = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        validated_ring_size(MAX_RING_SIZE + 1);
    }));
    assert!(rejected.is_err());
}

#[test]
fn test_submit_and_wait_non_etime_error_is_not_misclassified() {
    // Verify only ETIME maps to a timed-out wait: other errno values from
    // `io_uring_enter` must propagate as real errors rather than being
    // swallowed as transient.
    let mut harness = TestLoop::new(RingConfig::default());

    // Closing the ring fd out from under the loop makes the next enter
    // fail with EBADF.
    let driver = harness.driver();
    // SAFETY: the fd is intentionally invalidated, and the harness issues
    // no further ring operations after the failed wait.
    unsafe {
        libc::close(std::os::fd::AsRawFd::as_raw_fd(&driver.ring));
    }
    let err = driver
        .inner
        .submit_and_wait(&mut driver.ring, 1, Some(Duration::from_millis(1)))
        .expect_err("enter on a closed ring must fail");
    assert_eq!(err.raw_os_error(), Some(libc::EBADF));

    // The ring fd is gone, so skip the harness drain.
    std::mem::forget(harness);
}

#[test]
fn test_recv_completes_and_frees_slot() {
    // Verify a recv with available data completes and its slot frees once
    // the result is taken.
    let mut harness = TestLoop::new(RingConfig::default());
    let (left, right) = UnixStream::pair().unwrap();
    (&right).write_all(&[42]).unwrap();

    let handle = harness.handle.clone();
    let (mut buf, read) = harness
        .block_on(handle.recv(
            Arc::new(left.into()),
            IoBufMut::with_capacity(1),
            0,
            1,
            false,
            Instant::now() + Duration::from_secs(5),
        ))
        .expect("recv should succeed");
    assert_eq!(read, 1);
    // SAFETY: the kernel filled `read` bytes before completion.
    unsafe { buf.set_len(read) };
    assert_eq!(buf.as_ref(), &[42]);
    assert_eq!(harness.tracked(), 0);
}

#[test]
fn test_recv_timeout() {
    // Verify a timed recv completes with timeout once its deadline expires.
    let mut harness = TestLoop::new(RingConfig::default());
    let (left, _right) = UnixStream::pair().unwrap();

    let handle = harness.handle.clone();
    let start = Instant::now();
    let result = harness.block_on(handle.recv(
        Arc::new(left.into()),
        IoBufMut::with_capacity(8),
        0,
        8,
        false,
        Instant::now() + Duration::from_millis(80),
    ));
    assert!(matches!(result, Err((_, Error::Timeout))));
    assert!(
        start.elapsed() >= Duration::from_millis(50),
        "timeout fired too early: {:?}",
        start.elapsed()
    );
    assert_eq!(harness.tracked(), 0);
}

#[test]
fn test_timeout_slot_reuse_does_not_cancel_new_waiter_early() {
    // Verify stale timeout-wheel entries from an earlier generation do not
    // cancel a newly inserted waiter that reused the same slot.
    let mut harness = TestLoop::new(RingConfig {
        size: 8,
        timeout_wheel_tick: Duration::from_millis(5),
        ..Default::default()
    });

    // First operation completes quickly but still carries a generous
    // deadline, leaving a stale timeout entry that should be ignored later
    // after slot reuse.
    let (left1, right1) = UnixStream::pair().unwrap();
    (&right1).write_all(&[42]).unwrap();
    let handle = harness.handle.clone();
    let (_buf1, read1) = harness
        .block_on(handle.recv(
            Arc::new(left1.into()),
            IoBufMut::with_capacity(1),
            0,
            1,
            false,
            Instant::now() + Duration::from_millis(200),
        ))
        .expect("first recv should succeed");
    assert!(read1 > 0);

    // Second request reuses the slot and blocks until timeout.
    let (left2, _right2) = UnixStream::pair().unwrap();
    let start = Instant::now();
    let result2 = harness.block_on(handle.recv(
        Arc::new(left2.into()),
        IoBufMut::with_capacity(8),
        0,
        8,
        false,
        Instant::now() + Duration::from_millis(80),
    ));
    let elapsed = start.elapsed();
    assert!(matches!(result2, Err((_, Error::Timeout))));
    assert!(
        elapsed >= Duration::from_millis(50),
        "timeout fired too early after slot reuse: {elapsed:?}"
    );
}

#[test]
fn test_exact_recv_partial_progress() {
    // Verify an exact recv keeps requeuing until the full length arrives.
    let mut harness = TestLoop::new(RingConfig::default());
    let (left, right) = UnixStream::pair().unwrap();
    (&right).write_all(&[1, 2, 3]).unwrap();

    let handle = harness.handle.clone();
    let mut recv = Box::pin(handle.recv(
        Arc::new(left.into()),
        IoBufMut::with_capacity(5),
        0,
        5,
        true,
        Instant::now() + Duration::from_secs(5),
    ));

    // Drive until the partial bytes are consumed, then supply the rest.
    for _ in 0..10 {
        if poll_once(&harness, &mut recv).is_ready() {
            panic!("exact recv completed before all bytes arrived");
        }
        harness.driver().turn();
    }
    (&right).write_all(&[4, 5]).unwrap();

    let (mut buf, read) = harness
        .block_on(recv)
        .expect("exact recv should complete after remaining bytes");
    assert_eq!(read, 5);
    // SAFETY: the kernel filled `read` bytes before completion.
    unsafe { buf.set_len(read) };
    assert_eq!(buf.as_ref(), &[1, 2, 3, 4, 5]);
}

#[test]
fn test_expired_deadline_completes_immediately() {
    // Verify a request admitted with an already-expired deadline completes
    // with timeout before any SQE is issued.
    let mut harness = TestLoop::new(RingConfig::default());
    let (left, _right) = UnixStream::pair().unwrap();

    let handle = harness.handle.clone();
    let start = Instant::now();
    let result = harness.block_on(handle.recv(
        Arc::new(left.into()),
        IoBufMut::with_capacity(8),
        0,
        8,
        false,
        Instant::now() - Duration::from_millis(10),
    ));
    assert!(matches!(result, Err((_, Error::Timeout))));
    assert!(
        start.elapsed() < Duration::from_millis(50),
        "expired deadline should complete locally, took {:?}",
        start.elapsed()
    );
}

#[test]
fn test_drop_cancels_inflight_recv() {
    // Verify dropping an op future mid-flight eagerly cancels the
    // operation and frees its slot without waiting for the deadline.
    let mut harness = TestLoop::new(RingConfig::default());
    let (left, _right) = UnixStream::pair().unwrap();
    let fd = Arc::new(OwnedFd::from(left));

    let handle = harness.handle.clone();
    let mut recv = Box::pin(handle.recv(
        Arc::new(fd.try_clone().unwrap()),
        IoBufMut::with_capacity(8),
        0,
        8,
        false,
        Instant::now() + Duration::from_secs(60),
    ));

    // Admit and submit the recv.
    assert!(poll_once(&harness, &mut recv).is_pending());
    harness.driver().turn();
    assert_eq!(harness.pending(), 1);

    // Dropping the future orphans the slot and requests cancellation. The
    // next turn stages the async cancel and the kernel retires the op.
    drop(recv);
    let start = Instant::now();
    while harness.tracked() != 0 {
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "orphaned recv still tracked after {:?}",
            start.elapsed()
        );
        harness.driver().turn();
        harness.driver().park(Some(Duration::from_millis(10)));
    }
}

#[test]
fn test_drop_before_first_submit_retires_locally() {
    // Verify dropping an op future that was admitted but never staged
    // retires the slot without issuing an SQE.
    let mut harness = TestLoop::new(RingConfig::default());
    let (left, _right) = UnixStream::pair().unwrap();

    let handle = harness.handle.clone();
    let mut recv = Box::pin(handle.recv(
        Arc::new(left.into()),
        IoBufMut::with_capacity(8),
        0,
        8,
        false,
        Instant::now() + Duration::from_secs(60),
    ));

    // Admit without turning the loop, then drop.
    assert!(poll_once(&harness, &mut recv).is_pending());
    assert_eq!(harness.tracked(), 1);
    drop(recv);

    // The backlog entry is retired locally on the next turn.
    harness.driver().turn();
    assert_eq!(harness.tracked(), 0);
}

#[test]
fn test_write_detaches_on_drop() {
    // Verify a dropped write keeps running to completion for durability
    // parity with the tokio backend.
    let dir = std::env::temp_dir().join(format!(
        "commonware_iouring_write_detach_{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("detached_write");
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();

    let mut harness = TestLoop::new(RingConfig::default());
    let handle = harness.handle.clone();
    let payload = vec![7u8; 1 << 20];
    let mut write = Box::pin(handle.write_at(
        Arc::new(file),
        0,
        IoBufs::from(IoBuf::from(payload.clone())),
        WriteOptions::SYNC,
        Cache::Enabled,
    ));

    // Admit the write, then drop the future before it completes.
    assert!(poll_once(&harness, &mut write).is_pending());
    drop(write);

    // Drain runs the detached write to completion.
    harness.shutdown();
    let written = std::fs::read(&path).unwrap();
    assert_eq!(written, payload);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn test_capacity_fifo_grant_admits_waiting_op() {
    // Verify a FIFO-granted op admits once its reserved slot frees.
    let mut harness = TestLoop::new(RingConfig {
        size: 1,
        ..Default::default()
    });
    let (left_a, right_a) = UnixStream::pair().unwrap();
    let (left_b, right_b) = UnixStream::pair().unwrap();

    let handle = harness.handle.clone();
    let recv_a = handle.recv(
        Arc::new(left_a.into()),
        IoBufMut::with_capacity(1),
        0,
        1,
        false,
        Instant::now() + Duration::from_secs(5),
    );
    let recv_b = handle.recv(
        Arc::new(left_b.into()),
        IoBufMut::with_capacity(1),
        0,
        1,
        false,
        Instant::now() + Duration::from_secs(5),
    );

    // Feed both sockets so each recv completes as soon as it is admitted.
    (&right_a).write_all(&[1]).unwrap();
    (&right_b).write_all(&[2]).unwrap();

    let (result_a, result_b) = harness.block_on(futures::future::join(recv_a, recv_b));
    let (mut buf_a, read_a) = result_a.expect("first recv should succeed");
    let (mut buf_b, read_b) = result_b.expect("second recv should succeed");
    // SAFETY: the kernel filled the reported bytes before completion.
    unsafe { buf_a.set_len(read_a) };
    // SAFETY: the kernel filled the reported bytes before completion.
    unsafe { buf_b.set_len(read_b) };
    assert_eq!(buf_a.as_ref(), &[1]);
    assert_eq!(buf_b.as_ref(), &[2]);
}

#[test]
fn test_capacity_wait_counts_toward_connect_deadline() {
    let mut harness = TestLoop::new(RingConfig {
        size: 1,
        ..Default::default()
    });
    let handle = harness.handle.clone();

    // Keep the only waiter slot occupied by a recv whose own deadline is
    // deliberately much longer than the connect budget.
    let (blocker, _blocker_peer) = UnixStream::pair().unwrap();
    let mut blocker = Box::pin(handle.recv(
        Arc::new(blocker.into()),
        IoBufMut::with_capacity(1),
        0,
        1,
        false,
        Instant::now() + Duration::from_secs(60),
    ));
    assert!(poll_once(&harness, &mut blocker).is_pending());
    harness.driver().turn();

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let stream = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let mut connect = Box::pin(handle.connect(
        Arc::new(OwnedFd::from(stream)),
        listener.local_addr().unwrap(),
        Instant::now() + Duration::from_millis(20),
    ));
    assert!(poll_once(&harness, &mut connect).is_pending());
    handle.with(|ops| assert_eq!(ops.capacity.queued(), 1));

    let parked_at = Instant::now();
    harness.driver().park(Some(Duration::from_millis(500)));
    assert!(
        parked_at.elapsed() < Duration::from_millis(250),
        "park ignored the queued connect deadline: {:?}",
        parked_at.elapsed()
    );
    harness.driver().turn();
    assert!(matches!(
        poll_once(&harness, &mut connect),
        Poll::Ready(Err(Error::Timeout))
    ));
    handle.with(|ops| assert_eq!(ops.capacity.registered(), 0));
}

#[test]
fn test_capacity_wait_counts_toward_send_deadline() {
    let mut harness = TestLoop::new(RingConfig {
        size: 1,
        ..Default::default()
    });
    let handle = harness.handle.clone();

    let (blocker, _blocker_peer) = UnixStream::pair().unwrap();
    let mut blocker = Box::pin(handle.recv(
        Arc::new(blocker.into()),
        IoBufMut::with_capacity(1),
        0,
        1,
        false,
        Instant::now() + Duration::from_secs(60),
    ));
    assert!(poll_once(&harness, &mut blocker).is_pending());
    harness.driver().turn();

    let (sender, _receiver) = UnixStream::pair().unwrap();
    let mut send = Box::pin(handle.send(
        Arc::new(sender.into()),
        IoBufs::from(IoBuf::from(vec![1])),
        Instant::now() + Duration::from_millis(20),
    ));
    assert!(poll_once(&harness, &mut send).is_pending());
    handle.with(|ops| assert_eq!(ops.capacity.queued(), 1));

    std::thread::sleep(Duration::from_millis(50));
    harness.driver().turn();
    assert!(matches!(
        poll_once(&harness, &mut send),
        Poll::Ready(Err(Error::Timeout))
    ));
    handle.with(|ops| assert_eq!(ops.capacity.registered(), 0));
}

#[test]
fn test_capacity_wait_counts_toward_recv_deadline() {
    let mut harness = TestLoop::new(RingConfig {
        size: 1,
        ..Default::default()
    });
    let handle = harness.handle.clone();

    let (blocker, _blocker_peer) = UnixStream::pair().unwrap();
    let mut blocker = Box::pin(handle.recv(
        Arc::new(blocker.into()),
        IoBufMut::with_capacity(1),
        0,
        1,
        false,
        Instant::now() + Duration::from_secs(60),
    ));
    assert!(poll_once(&harness, &mut blocker).is_pending());
    harness.driver().turn();

    let (receiver, _sender) = UnixStream::pair().unwrap();
    let mut recv = Box::pin(handle.recv(
        Arc::new(receiver.into()),
        IoBufMut::with_capacity(1),
        0,
        1,
        false,
        Instant::now() + Duration::from_millis(20),
    ));
    assert!(poll_once(&harness, &mut recv).is_pending());
    handle.with(|ops| assert_eq!(ops.capacity.queued(), 1));

    std::thread::sleep(Duration::from_millis(50));
    harness.driver().turn();
    assert!(matches!(
        poll_once(&harness, &mut recv),
        Poll::Ready(Err((_, Error::Timeout)))
    ));
    handle.with(|ops| assert_eq!(ops.capacity.registered(), 0));
}

#[test]
fn test_capacity_wait_counts_toward_accept_deadline() {
    let mut harness = TestLoop::new(RingConfig {
        size: 1,
        ..Default::default()
    });
    let handle = harness.handle.clone();

    let (blocker, _blocker_peer) = UnixStream::pair().unwrap();
    let mut blocker = Box::pin(handle.recv(
        Arc::new(blocker.into()),
        IoBufMut::with_capacity(1),
        0,
        1,
        false,
        Instant::now() + Duration::from_secs(60),
    ));
    assert!(poll_once(&harness, &mut blocker).is_pending());
    harness.driver().turn();

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let mut accept = Box::pin(handle.start_accept(
        Arc::new(OwnedFd::from(listener)),
        Instant::now() + Duration::from_millis(20),
    ));
    assert!(poll_once(&harness, &mut accept).is_pending());
    handle.with(|ops| assert_eq!(ops.capacity.queued(), 1));

    std::thread::sleep(Duration::from_millis(50));
    harness.driver().turn();
    let Poll::Ready(mut ticket) = poll_once(&harness, &mut accept) else {
        panic!("accept admission did not observe its capacity timeout");
    };
    let noop = futures::task::noop_waker();
    let mut cx = Context::from_waker(&noop);
    assert!(matches!(
        Pin::new(&mut ticket).poll(&mut cx),
        Poll::Ready(Err(Error::Timeout))
    ));
    handle.with(|ops| {
        assert_eq!(ops.capacity.registered(), 0);
        assert!(ops.completions.is_empty());
    });
}

#[test]
fn test_pending_operations_aggregates_across_drivers() {
    // Every worker's driver registers the same pending-operations gauge
    // (the registry dedups by name): drivers must fold deltas into it
    // rather than set absolute values, and a destroyed driver must remove
    // its own contribution, including Ready escaped tickets, which
    // survive the drain without retaining a waiter.
    let mut registry = Registry::default();
    // Registration dedup hands back the same gauge the drivers share.
    let gauge: crate::telemetry::metrics::Gauge = Register::register(
        &mut registry,
        "pending_operations",
        "Number of retained logical operations in the io_uring loop",
        raw::Gauge::default(),
    );
    let (mut driver_a, handle_a) = Driver::new(
        RingConfig::default(),
        Duration::from_secs(60),
        &mut registry,
    )
    .unwrap();
    let (mut driver_b, _handle_b) = Driver::new(
        RingConfig::default(),
        Duration::from_secs(60),
        &mut registry,
    )
    .unwrap();

    // Admit a sync whose ticket is never awaited. Its terminal result
    // parks in driver A's completion arena after a socket fd fails fsync.
    let (socket, _peer) = UnixStream::pair().unwrap();
    // SAFETY: `into_raw_fd` transfers ownership of the socket fd into
    // `File`.
    let file = unsafe { std::fs::File::from_raw_fd(socket.into_raw_fd()) };
    let mut admit = Box::pin(handle_a.start_sync(Arc::new(file)));
    let noop = futures::task::noop_waker();
    let mut cx = std::task::Context::from_waker(&noop);
    let Poll::Ready(ticket) = admit.as_mut().poll(&mut cx) else {
        panic!("admission should not park on an empty slab");
    };

    // Driver A reports its pending op, and an idle driver B turn must not
    // clobber that contribution.
    driver_a.turn();
    assert_eq!(gauge.get(), 1);
    driver_b.turn();
    assert_eq!(gauge.get(), 1);

    // Close and drain A: the parked result survives the drain, but
    // destroying the driver removes its contribution from the shared
    // gauge.
    driver_a.close();
    driver_a.drain();
    assert_eq!(gauge.get(), 0);

    drop(ticket);
}

#[test]
fn test_pending_operations_refreshes_after_reentrant_completion_poll() {
    /// Result produced by the receive consumed inside its completion callback.
    type RecvResult = Result<(IoBufMut, usize), (IoBufMut, Error)>;

    /// Waker that synchronously consumes the completed ordinary operation.
    struct ConsumeCompletion {
        future: Mutex<Option<Pin<Box<dyn Future<Output = RecvResult> + Send>>>>,
        completed: AtomicBool,
    }

    impl ArcWake for ConsumeCompletion {
        fn wake_by_ref(arc_self: &Arc<Self>) {
            let mut slot = arc_self.future.lock();
            let future = slot
                .as_mut()
                .expect("receive callback invoked after completion");
            let noop = futures::task::noop_waker();
            let mut cx = Context::from_waker(&noop);
            assert!(future.as_mut().poll(&mut cx).is_ready());
            *slot = None;
            arc_self.completed.store(true, Ordering::Release);
        }
    }

    let mut registry = Registry::default();
    let gauge: crate::telemetry::metrics::Gauge = Register::register(
        &mut registry,
        "pending_operations",
        "Number of retained logical operations in the io_uring loop",
        raw::Gauge::default(),
    );
    let (mut driver, handle) = Driver::new(
        RingConfig::default(),
        Duration::from_secs(60),
        &mut registry,
    )
    .unwrap();
    let (left, mut right) = UnixStream::pair().unwrap();
    let recv_handle = handle.clone();
    let consumer = Arc::new(ConsumeCompletion {
        future: Mutex::new(Some(Box::pin(async move {
            recv_handle
                .recv(
                    Arc::new(left.into()),
                    IoBufMut::with_capacity(1),
                    0,
                    1,
                    false,
                    Instant::now() + Duration::from_secs(60),
                )
                .await
        }))),
        completed: AtomicBool::new(false),
    });
    let completion_waker = arc_waker(Arc::clone(&consumer));
    let mut cx = Context::from_waker(&completion_waker);
    assert!(
        consumer
            .future
            .lock()
            .as_mut()
            .unwrap()
            .as_mut()
            .poll(&mut cx)
            .is_pending()
    );
    driver.turn();
    assert_eq!(gauge.get(), 1);

    right.write_all(b"x").unwrap();
    let start = Instant::now();
    while !consumer.completed.load(Ordering::Acquire) {
        assert!(start.elapsed() < Duration::from_secs(5));
        driver.turn();
        if !consumer.completed.load(Ordering::Acquire) {
            driver.park(Some(Duration::from_millis(10)));
        }
    }

    // The completion callback removed the final ordinary operation after
    // the turn's first metric report. The lightweight callback refresh
    // must fold that removal into the gauge before returning.
    assert_eq!(handle.with(|ops| ops.operation_count()), 0);
    assert_eq!(gauge.get(), 0);
    drop(completion_waker);
    drop(consumer);
    driver.close();
    driver.drain();
}

#[test]
fn test_ticket_metric_counts_pending_and_ready_once() {
    let mut registry = Registry::default();
    let gauge: crate::telemetry::metrics::Gauge = Register::register(
        &mut registry,
        "pending_operations",
        "Number of retained logical operations in the io_uring loop",
        raw::Gauge::default(),
    );
    let (mut driver, handle) = Driver::new(
        RingConfig {
            size: 1,
            ..Default::default()
        },
        Duration::from_secs(60),
        &mut registry,
    )
    .unwrap();

    // Pending completion entries mirror a live waiter and count once.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let mut accept_admission = Box::pin(handle.start_accept(
        Arc::new(OwnedFd::from(listener)),
        Instant::now() + Duration::from_secs(60),
    ));
    let noop = futures::task::noop_waker();
    let mut cx = Context::from_waker(&noop);
    let Poll::Ready(accept_ticket) = accept_admission.as_mut().poll(&mut cx) else {
        panic!("accept admission unexpectedly parked");
    };
    driver.turn();
    assert_eq!(gauge.get(), 1);
    handle.with(|ops| {
        assert_eq!(ops.waiters.len(), 1);
        assert_eq!(ops.completions.ready(), 0);
        assert_eq!(ops.operation_count(), 1);
    });

    drop(accept_ticket);
    let start = Instant::now();
    while handle.with(|ops| ops.waiters.pending()) != 0 {
        assert!(start.elapsed() < Duration::from_secs(5));
        driver.turn();
        driver.park(Some(Duration::from_millis(10)));
    }
    driver.turn();
    assert_eq!(gauge.get(), 0);

    // A Ready completion has no waiter and still contributes one until
    // its ticket is consumed.
    let (left, _right) = UnixStream::pair().unwrap();
    // SAFETY: `left` is a valid owned fd and is transferred into `File`.
    let file = unsafe { File::from_raw_fd(left.into_raw_fd()) };
    let mut sync_admission = Box::pin(handle.start_sync(Arc::new(file)));
    let Poll::Ready(mut sync_ticket) = sync_admission.as_mut().poll(&mut cx) else {
        panic!("sync admission unexpectedly parked");
    };
    let start = Instant::now();
    while handle.with(|ops| ops.waiters.pending()) != 0 {
        assert!(start.elapsed() < Duration::from_secs(5));
        driver.turn();
        driver.park(Some(Duration::from_millis(10)));
    }
    driver.turn();
    assert_eq!(gauge.get(), 1);
    handle.with(|ops| {
        assert_eq!(ops.waiters.len(), 0);
        assert_eq!(ops.completions.ready(), 1);
        assert_eq!(ops.operation_count(), 1);
    });

    assert!(matches!(
        Pin::new(&mut sync_ticket).poll(&mut cx),
        Poll::Ready(Err(_))
    ));
    driver.turn();
    assert_eq!(gauge.get(), 0);
    driver.close();
    driver.drain();
}

#[test]
fn test_foreign_drop_wakes_unbounded_drain() {
    // A drain blocked in an unbounded `submit_and_wait` must be woken by
    // a foreign-thread ticket drop: the orphan-mailbox push must reach
    // the armed eventfd path and cancel the in-flight accept, instead of
    // latching a wake nothing observes while the drain sleeps toward the
    // distant wheel deadline.
    let mut harness = TestLoop::new(RingConfig::default());
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let fd: Arc<OwnedFd> = Arc::new(OwnedFd::from(listener));

    let handle = harness.handle.clone();
    let mut admit = Box::pin(handle.start_accept(fd, Instant::now() + Duration::from_secs(3600)));
    let noop = futures::task::noop_waker();
    let mut cx = std::task::Context::from_waker(&noop);
    let Poll::Ready(ticket) = admit.as_mut().poll(&mut cx) else {
        panic!("accept admission should not park on an empty slab");
    };
    harness.driver().turn();
    assert_eq!(harness.pending(), 1);

    // Drop the ticket on a foreign thread once the drain is underway.
    let dropper = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(200));
        drop(ticket);
    });

    let start = Instant::now();
    harness.driver().close();
    harness.shutdown();
    assert!(
        start.elapsed() < Duration::from_secs(30),
        "drain slept through the foreign-thread drop: {:?}",
        start.elapsed()
    );
    dropper.join().unwrap();
}

#[test]
fn test_drain_rearms_wake_poll_before_armed_wait() {
    // On a size-1 ring, staging can fill the SQ before the wake-poll
    // rearm lands. The drain must flush and retry until the poll is live
    // before blocking: with the poll terminated, a foreign-thread drop
    // writes the eventfd without producing a CQE, and an unbounded wait
    // sleeps through it toward the distant wheel deadline.
    let mut harness = TestLoop::new(RingConfig {
        size: 1,
        ..Default::default()
    });
    let handle = harness.handle.clone();

    // Admit a recv but never turn: at drain entry the request is still
    // in the backlog and the wake poll was never installed, so the
    // drain's first staging pass fills the single-entry SQ before the
    // rearm can land.
    let (left, _right) = UnixStream::pair().unwrap();
    let mut recv = Box::pin(handle.recv(
        Arc::new(left.into()),
        IoBufMut::with_capacity(1),
        0,
        1,
        false,
        Instant::now() + Duration::from_secs(3600),
    ));
    assert!(poll_once(&harness, &mut recv).is_pending());

    std::thread::scope(|scope| {
        // Drop the recv on a foreign thread once the drain is blocked.
        let dropper = scope.spawn(move || {
            std::thread::sleep(Duration::from_millis(300));
            drop(recv);
        });

        let start = Instant::now();
        harness.driver().close();
        harness.shutdown();
        assert!(
            start.elapsed() < Duration::from_secs(30),
            "drain slept behind a dead wake poll: {:?}",
            start.elapsed()
        );
        dropper.join().unwrap();
    });
}

#[test]
fn test_off_thread_drop_releases_capacity_slot() {
    // An admission attempt parked on a full slab and dropped on a
    // foreign thread must release its capacity registration through the
    // orphan mailbox: a saturated ring never drains the wait list, so a
    // retained registration would otherwise persist indefinitely.
    let mut harness = TestLoop::new(RingConfig {
        size: 1,
        ..Default::default()
    });
    let handle = harness.handle.clone();

    let (blocker_left, _blocker_right) = UnixStream::pair().unwrap();
    let mut blocker = Box::pin(handle.recv(
        Arc::new(blocker_left.into()),
        IoBufMut::with_capacity(1),
        0,
        1,
        false,
        Instant::now() + Duration::from_secs(60),
    ));
    assert!(poll_once(&harness, &mut blocker).is_pending());

    let (left, _right) = UnixStream::pair().unwrap();
    let mut parked = Box::pin(handle.recv(
        Arc::new(left.into()),
        IoBufMut::with_capacity(1),
        0,
        1,
        false,
        Instant::now() + Duration::from_secs(60),
    ));
    assert!(poll_once(&harness, &mut parked).is_pending());
    harness
        .handle
        .with(|ops| assert_eq!(ops.capacity.registered(), 1));

    // Drop the parked attempt on a foreign thread: the registration
    // routes through the mailbox and the next turn releases it.
    std::thread::scope(|scope| {
        scope.spawn(move || drop(parked)).join().unwrap();
    });
    harness.driver().turn();
    harness
        .handle
        .with(|ops| assert_eq!(ops.capacity.registered(), 0));
}

#[test]
fn test_off_thread_drop_transfers_granted_capacity_slot() {
    let mut harness = TestLoop::new(RingConfig {
        size: 1,
        ..Default::default()
    });
    let handle = harness.handle.clone();

    let (blocker_left, _blocker_right) = UnixStream::pair().unwrap();
    let mut blocker = Box::pin(handle.recv(
        Arc::new(blocker_left.into()),
        IoBufMut::with_capacity(1),
        0,
        1,
        false,
        Instant::now() + Duration::from_secs(60),
    ));
    assert!(poll_once(&harness, &mut blocker).is_pending());

    let first_count = Arc::new(WakeCount(AtomicUsize::new(0)));
    let first_waker = arc_waker(Arc::clone(&first_count));
    let mut first_cx = Context::from_waker(&first_waker);
    let (first_left, _first_right) = UnixStream::pair().unwrap();
    let mut first = Box::pin(handle.recv(
        Arc::new(first_left.into()),
        IoBufMut::with_capacity(1),
        0,
        1,
        false,
        Instant::now() + Duration::from_secs(60),
    ));
    assert!(first.as_mut().poll(&mut first_cx).is_pending());

    // The blocker is still in the backlog. Its owner drop and the next
    // turn retire it locally, granting the released slot to `first`.
    drop(blocker);
    harness.driver().turn();
    assert_eq!(first_count.0.load(Ordering::Acquire), 1);
    harness.handle.with(|ops| {
        assert_eq!(ops.waiters.len(), 0);
        assert_eq!(ops.capacity.registered(), 1);
        assert_eq!(ops.capacity.queued(), 0);
        assert_eq!(ops.capacity.reserved(), 1);
    });

    let second_count = Arc::new(WakeCount(AtomicUsize::new(0)));
    let second_waker = arc_waker(Arc::clone(&second_count));
    let mut second_cx = Context::from_waker(&second_waker);
    let (second_left, _second_right) = UnixStream::pair().unwrap();
    let mut second = Box::pin(handle.recv(
        Arc::new(second_left.into()),
        IoBufMut::with_capacity(1),
        0,
        1,
        false,
        Instant::now() + Duration::from_secs(60),
    ));
    assert!(second.as_mut().poll(&mut second_cx).is_pending());
    assert_eq!(second_count.0.load(Ordering::Acquire), 0);

    // A foreign drop routes the granted CapacityId through the mailbox.
    // Cancelling it transfers the reserved permit to the queued head.
    std::thread::scope(|scope| {
        scope.spawn(move || drop(first)).join().unwrap();
    });
    harness.driver().turn();
    assert_eq!(second_count.0.load(Ordering::Acquire), 1);
    harness.handle.with(|ops| {
        assert_eq!(ops.capacity.registered(), 1);
        assert_eq!(ops.capacity.queued(), 0);
        assert_eq!(ops.capacity.reserved(), 1);
    });
    drop(second);
    assert_eq!(harness.tracked(), 0);
}

/// Park a completed sync ticket's terminal result in its independent
/// completion entry while retaining the ticket.
///
/// fsync on a socket-backed file fails fast, so the terminal error parks
/// in the completion entry while the returned ticket is held.
fn park_sync_ticket(harness: &mut TestLoop, handle: &Handle) -> SyncTicket {
    let (left, _right) = UnixStream::pair().unwrap();
    // SAFETY: `left` is a valid owned fd and is transferred into `File`.
    let file = unsafe { File::from_raw_fd(left.into_raw_fd()) };
    let ticket = harness.block_on(handle.start_sync(Arc::new(file)));

    // Bounded turn loop: drive the fsync CQE so the result parks.
    let start = Instant::now();
    while harness.pending() != 0 {
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "sync result did not park: {:?}",
            start.elapsed()
        );
        harness.driver().turn();
        harness.driver().park(Some(Duration::from_millis(10)));
    }
    harness.handle.with(|ops| {
        assert_eq!(ops.waiters.len(), 0, "terminal ticket retained a waiter");
        assert_eq!(ops.completions.ready(), 1);
        assert_eq!(ops.operation_count(), 1);
    });
    ticket
}

/// Admit and stage an accept that has no peer, leaving its completion
/// entry Pending and its waiter in flight.
fn pending_accept_ticket(harness: &mut TestLoop, handle: &Handle) -> AcceptTicket {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let fd = Arc::new(OwnedFd::from(listener));
    let ticket =
        harness.block_on(handle.start_accept(fd, Instant::now() + Duration::from_secs(60)));
    harness.driver().turn();
    harness.handle.with(|ops| {
        assert_eq!(ops.waiters.len(), 1);
        assert_eq!(ops.completions.ready(), 0);
        assert_eq!(ops.operation_count(), 1);
    });
    ticket
}

struct WokenFlag(AtomicBool);

impl ArcWake for WokenFlag {
    fn wake_by_ref(arc_self: &Arc<Self>) {
        arc_self.0.store(true, Ordering::Release);
    }
}

struct WakeCount(AtomicUsize);

impl ArcWake for WakeCount {
    fn wake_by_ref(arc_self: &Arc<Self>) {
        arc_self.0.fetch_add(1, Ordering::AcqRel);
    }
}

#[test]
fn test_ready_ticket_poll_does_not_double_release_capacity() {
    let mut harness = TestLoop::new(RingConfig {
        size: 1,
        ..Default::default()
    });
    let handle = harness.handle.clone();
    let (sync_left, _sync_right) = UnixStream::pair().unwrap();
    // SAFETY: `sync_left` is a valid owned fd and is transferred into
    // `File`.
    let file = unsafe { File::from_raw_fd(sync_left.into_raw_fd()) };
    let ticket = harness.block_on(handle.start_sync(Arc::new(file)));

    // Register a second request while the ticket still owns the only
    // active waiter.
    let (left, _right) = UnixStream::pair().unwrap();
    let mut second = Box::pin(handle.recv(
        Arc::new(left.into()),
        IoBufMut::with_capacity(1),
        0,
        1,
        false,
        Instant::now() + Duration::from_secs(60),
    ));
    let flag = Arc::new(WokenFlag(AtomicBool::new(false)));
    let waker = arc_waker(Arc::clone(&flag));
    let mut cx = Context::from_waker(&waker);
    assert!(second.as_mut().poll(&mut cx).is_pending());
    assert_eq!(harness.handle.with(|ops| ops.capacity.registered()), 1);

    // Terminal ticket publication frees the waiter and wakes capacity
    // before the ticket itself is consumed.
    let start = Instant::now();
    while harness.pending() != 0 {
        assert!(start.elapsed() < Duration::from_secs(5));
        harness.driver().turn();
        harness.driver().park(Some(Duration::from_millis(10)));
    }
    harness.handle.with(|ops| {
        assert_eq!(ops.waiters.len(), 0);
        assert_eq!(ops.completions.ready(), 1);
        assert_eq!(ops.operation_count(), 1);
        assert_eq!(ops.capacity.registered(), 1);
        assert_eq!(ops.capacity.queued(), 0);
        assert_eq!(ops.capacity.reserved(), 1);
    });
    assert!(flag.0.load(Ordering::Acquire));

    // The only free waiter is reserved for `second`, so a later poll
    // queues behind it.
    let third_count = Arc::new(WakeCount(AtomicUsize::new(0)));
    let third_waker = arc_waker(Arc::clone(&third_count));
    let mut third_cx = Context::from_waker(&third_waker);
    let (third_left, _third_right) = UnixStream::pair().unwrap();
    let mut third = Box::pin(handle.recv(
        Arc::new(third_left.into()),
        IoBufMut::with_capacity(1),
        0,
        1,
        false,
        Instant::now() + Duration::from_secs(60),
    ));
    assert!(third.as_mut().poll(&mut third_cx).is_pending());
    harness.handle.with(|ops| {
        assert_eq!(ops.capacity.registered(), 2);
        assert_eq!(ops.capacity.queued(), 1);
        assert_eq!(ops.capacity.reserved(), 1);
    });

    // Polling the independently stored Ready output removes no waiter and
    // therefore cannot create or transfer another capacity permit.
    assert!(harness.block_on(ticket).is_err());
    assert_eq!(third_count.0.load(Ordering::Acquire), 0);
    harness.handle.with(|ops| {
        assert_eq!(ops.waiters.len(), 0);
        assert_eq!(ops.completions.ready(), 0);
        assert_eq!(ops.capacity.registered(), 2);
        assert_eq!(ops.capacity.queued(), 1);
        assert_eq!(ops.capacity.reserved(), 1);
    });

    // The granted request reuses the waiter. Its later terminal removal,
    // not the Ready ticket poll, transfers capacity to `third`.
    assert!(second.as_mut().poll(&mut cx).is_pending());
    harness.handle.with(|ops| {
        assert_eq!(ops.waiters.len(), 1);
        assert_eq!(ops.completions.ready(), 0);
        assert_eq!(ops.operation_count(), 1);
        assert_eq!(ops.capacity.registered(), 1);
        assert_eq!(ops.capacity.queued(), 1);
        assert_eq!(ops.capacity.reserved(), 0);
    });

    drop(second);
    let start = Instant::now();
    while harness.pending() != 0 {
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "second request did not wind down"
        );
        harness.driver().turn();
        harness.driver().park(Some(Duration::from_millis(10)));
    }
    assert_eq!(third_count.0.load(Ordering::Acquire), 1);
    harness.handle.with(|ops| {
        assert_eq!(ops.capacity.registered(), 1);
        assert_eq!(ops.capacity.queued(), 0);
        assert_eq!(ops.capacity.reserved(), 1);
    });
    drop(third);
    assert_eq!(harness.tracked(), 0);
}

#[test]
fn test_ready_ticket_drop_does_not_double_release_capacity() {
    let mut harness = TestLoop::new(RingConfig {
        size: 1,
        ..Default::default()
    });
    let handle = harness.handle.clone();
    let (sync_left, _sync_right) = UnixStream::pair().unwrap();
    // SAFETY: `sync_left` is a valid owned fd and is transferred into
    // `File`.
    let file = unsafe { File::from_raw_fd(sync_left.into_raw_fd()) };
    let ticket = harness.block_on(handle.start_sync(Arc::new(file)));

    let (second_left, _second_right) = UnixStream::pair().unwrap();
    let mut second = Box::pin(handle.recv(
        Arc::new(second_left.into()),
        IoBufMut::with_capacity(1),
        0,
        1,
        false,
        Instant::now() + Duration::from_secs(60),
    ));
    assert!(poll_once(&harness, &mut second).is_pending());
    while harness.pending() != 0 {
        harness.driver().turn();
        harness.driver().park(Some(Duration::from_millis(10)));
    }

    let third_count = Arc::new(WakeCount(AtomicUsize::new(0)));
    let third_waker = arc_waker(Arc::clone(&third_count));
    let mut third_cx = Context::from_waker(&third_waker);
    let (third_left, _third_right) = UnixStream::pair().unwrap();
    let mut third = Box::pin(handle.recv(
        Arc::new(third_left.into()),
        IoBufMut::with_capacity(1),
        0,
        1,
        false,
        Instant::now() + Duration::from_secs(60),
    ));
    assert!(third.as_mut().poll(&mut third_cx).is_pending());
    harness.handle.with(|ops| {
        assert_eq!(ops.completions.ready(), 1);
        assert_eq!(ops.capacity.registered(), 2);
        assert_eq!(ops.capacity.queued(), 1);
        assert_eq!(ops.capacity.reserved(), 1);
    });

    drop(ticket);
    harness.handle.with(|ops| {
        assert_eq!(ops.waiters.len(), 0);
        assert_eq!(ops.completions.ready(), 0);
        assert_eq!(ops.completions.arena_len(), 1);
        assert_eq!(ops.operation_count(), 0);
        assert_eq!(ops.capacity.registered(), 2);
        assert_eq!(ops.capacity.queued(), 1);
        assert_eq!(ops.capacity.reserved(), 1);
    });
    assert_eq!(third_count.0.load(Ordering::Acquire), 0);

    drop(second);
    assert_eq!(third_count.0.load(Ordering::Acquire), 1);
    harness.handle.with(|ops| {
        assert_eq!(ops.capacity.registered(), 1);
        assert_eq!(ops.capacity.queued(), 0);
        assert_eq!(ops.capacity.reserved(), 1);
    });
    drop(third);
}

#[test]
fn test_ready_ticket_foreign_drop_preserves_reused_waiter() {
    let mut harness = TestLoop::new(RingConfig {
        size: 1,
        ..Default::default()
    });
    let handle = harness.handle.clone();
    let ticket = park_sync_ticket(&mut harness, &handle);

    // Reuse the old ticket's waiter with a recv that remains active.
    let (left, _right) = UnixStream::pair().unwrap();
    let mut second = Box::pin(handle.recv(
        Arc::new(left.into()),
        IoBufMut::with_capacity(1),
        0,
        1,
        false,
        Instant::now() + Duration::from_secs(60),
    ));
    assert!(poll_once(&harness, &mut second).is_pending());
    harness.handle.with(|ops| {
        assert_eq!(ops.waiters.len(), 1);
        assert_eq!(ops.completions.ready(), 1);
    });

    std::thread::scope(|scope| {
        scope.spawn(move || drop(ticket)).join().unwrap();
    });
    harness.driver().turn();
    harness.handle.with(|ops| {
        assert_eq!(ops.waiters.len(), 1, "Ready drop touched reused waiter");
        assert_eq!(ops.completions.ready(), 0);
        assert_eq!(ops.operation_count(), 1);
    });

    drop(second);
    while harness.pending() != 0 {
        harness.driver().turn();
        harness.driver().park(Some(Duration::from_millis(10)));
    }
    assert_eq!(harness.tracked(), 0);
}

#[test]
fn test_pending_accept_owner_drop_cancels_and_reuses_waiter() {
    let mut harness = TestLoop::new(RingConfig {
        size: 1,
        ..Default::default()
    });
    let handle = harness.handle.clone();
    let ticket = pending_accept_ticket(&mut harness, &handle);
    drop(ticket);

    let start = Instant::now();
    while harness.pending() != 0 {
        assert!(start.elapsed() < Duration::from_secs(5));
        harness.driver().turn();
        harness.driver().park(Some(Duration::from_millis(10)));
    }
    harness.handle.with(|ops| {
        assert_eq!(ops.waiters.len(), 0);
        assert_eq!(ops.completions.ready(), 0);
        assert_eq!(ops.operation_count(), 0);
    });

    // The next accept reuses the freed waiter and retains the exact fd
    // and peer address through its independent completion entry.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let local_addr = listener.local_addr().unwrap();
    let mut reused = harness.block_on(handle.start_accept(
        Arc::new(OwnedFd::from(listener)),
        Instant::now() + Duration::from_secs(60),
    ));
    let mut client = std::net::TcpStream::connect(local_addr).unwrap();
    let expected_remote = client.local_addr().unwrap();
    let (fd, remote) = harness.block_on(&mut reused).unwrap();
    assert_eq!(remote, expected_remote);

    let mut accepted = std::net::TcpStream::from(fd);
    client.write_all(b"x").unwrap();
    let mut byte = [0];
    accepted.read_exact(&mut byte).unwrap();
    assert_eq!(byte, *b"x");
}

#[test]
fn test_pending_accept_foreign_drop_cancels() {
    let mut harness = TestLoop::new(RingConfig {
        size: 1,
        ..Default::default()
    });
    let handle = harness.handle.clone();
    let ticket = pending_accept_ticket(&mut harness, &handle);
    std::thread::scope(|scope| {
        scope.spawn(move || drop(ticket)).join().unwrap();
    });

    let start = Instant::now();
    while harness.pending() != 0 {
        assert!(start.elapsed() < Duration::from_secs(5));
        harness.driver().turn();
        harness.driver().park(Some(Duration::from_millis(10)));
    }
    harness.handle.with(|ops| {
        assert_eq!(ops.waiters.len(), 0);
        assert_eq!(ops.completions.ready(), 0);
        assert_eq!(ops.operation_count(), 0);
    });
}

#[test]
fn test_pending_sync_foreign_drop_detaches_until_terminal_completion() {
    let mut harness = TestLoop::new(RingConfig {
        size: 1,
        ..Default::default()
    });
    let handle = harness.handle.clone();
    let (sync_left, _sync_right) = UnixStream::pair().unwrap();
    // SAFETY: `sync_left` is a valid owned fd and is transferred into
    // `File`.
    let file = unsafe { File::from_raw_fd(sync_left.into_raw_fd()) };
    let ticket = harness.block_on(handle.start_sync(Arc::new(file)));

    // Park another admission on the live sync waiter. The counter proves
    // terminal retirement releases this capacity registration once.
    let (waiting_left, _waiting_right) = UnixStream::pair().unwrap();
    let mut waiting = Box::pin(handle.recv(
        Arc::new(waiting_left.into()),
        IoBufMut::with_capacity(1),
        0,
        1,
        false,
        Instant::now() + Duration::from_secs(60),
    ));
    let count = Arc::new(WakeCount(AtomicUsize::new(0)));
    let count_waker = arc_waker(count.clone());
    let mut count_cx = Context::from_waker(&count_waker);
    assert!(waiting.as_mut().poll(&mut count_cx).is_pending());
    harness.handle.with(|ops| {
        assert_eq!(ops.waiters.len(), 1);
        assert_eq!(ops.completions.ready(), 0);
        assert_eq!(ops.completions.arena_len(), 1);
        assert_eq!(ops.capacity.registered(), 1);
        assert_eq!(ops.operation_count(), 1);
    });

    std::thread::scope(|scope| {
        scope.spawn(move || drop(ticket)).join().unwrap();
    });

    // Process the foreign mailbox before staging so the detach transition
    // is directly observable. Completion state is gone, but sync orphan
    // policy retains the waiter without a cancel SQE or premature
    // capacity release.
    {
        let driver = harness.driver();
        let owner = driver.inner.handle.clone();
        owner.with(|ops| driver.inner.process_orphans(ops));
        driver.inner.flush_wakers();
    }
    harness.handle.with(|ops| {
        assert_eq!(ops.waiters.len(), 1);
        assert_eq!(ops.completions.ready(), 0);
        assert_eq!(ops.operation_count(), 1);
        assert!(ops.pending_cancels.is_empty());
        assert_eq!(ops.capacity.registered(), 1);
    });
    assert_eq!(count.0.load(Ordering::Acquire), 0);

    let start = Instant::now();
    while harness.pending() != 0 {
        assert!(start.elapsed() < Duration::from_secs(5));
        harness.driver().turn();
        if harness.pending() != 0 {
            harness.driver().park(Some(Duration::from_millis(10)));
        }
    }
    harness.handle.with(|ops| {
        assert_eq!(ops.waiters.len(), 0);
        assert_eq!(ops.completions.ready(), 0);
        assert_eq!(ops.operation_count(), 0);
        assert_eq!(ops.capacity.registered(), 1);
        assert_eq!(ops.capacity.queued(), 0);
        assert_eq!(ops.capacity.reserved(), 1);
    });
    assert_eq!(count.0.load(Ordering::Acquire), 1);

    // Extra loop work cannot notify the granted registration again.
    harness.driver().turn();
    assert_eq!(count.0.load(Ordering::Acquire), 1);
    drop(waiting);
    assert_eq!(harness.tracked(), 0);
}

#[test]
fn test_accept_ticket_timeout_releases_deadline_before_poll() {
    let mut harness = TestLoop::new(RingConfig {
        timeout_wheel_tick: Duration::from_millis(1),
        ..Default::default()
    });
    let handle = harness.handle.clone();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let ticket = harness.block_on(handle.start_accept(
        Arc::new(OwnedFd::from(listener)),
        Instant::now() + Duration::from_millis(10),
    ));

    let start = Instant::now();
    while harness.pending() != 0 {
        assert!(start.elapsed() < Duration::from_secs(5));
        harness.driver().turn();
        harness.driver().park(Some(Duration::from_millis(10)));
    }
    assert_eq!(harness.driver().inner.timeout_wheel.next_deadline(), None);
    harness.handle.with(|ops| {
        assert_eq!(ops.waiters.len(), 0);
        assert_eq!(ops.completions.ready(), 1);
    });
    assert!(matches!(harness.block_on(ticket), Err(Error::Timeout)));
}

/// Waker that panics whenever the driver or a completing op invokes it.
struct PanicWaker;

impl ArcWake for PanicWaker {
    fn wake_by_ref(_: &Arc<Self>) {
        panic!("intentional test waker panic");
    }
}

unsafe fn clone_panicking_drop_waker(_: *const ()) -> std::task::RawWaker {
    std::task::RawWaker::new(std::ptr::null(), &PANICKING_DROP_WAKER_VTABLE)
}

unsafe fn wake_panicking_drop_waker(_: *const ()) {}

unsafe fn wake_by_ref_panicking_drop_waker(_: *const ()) {}

unsafe fn drop_panicking_drop_waker(_: *const ()) {
    panic!("intentional RawWaker drop panic");
}

static PANICKING_DROP_WAKER_VTABLE: std::task::RawWakerVTable = std::task::RawWakerVTable::new(
    clone_panicking_drop_waker,
    wake_panicking_drop_waker,
    wake_by_ref_panicking_drop_waker,
    drop_panicking_drop_waker,
);

fn panicking_drop_waker() -> std::task::Waker {
    // SAFETY: the static vtable accepts the null data pointer and every
    // entry treats it as an opaque token. Its drop panic is intentional
    // test behavior exercised behind catch_unwind.
    unsafe {
        std::task::Waker::from_raw(std::task::RawWaker::new(
            std::ptr::null(),
            &PANICKING_DROP_WAKER_VTABLE,
        ))
    }
}

#[test]
fn test_pending_op_waker_drop_panics_after_owner_orphan_commit() {
    let mut harness = TestLoop::new(RingConfig {
        size: 1,
        ..Default::default()
    });
    let handle = harness.handle.clone();
    let (left, _right) = UnixStream::pair().unwrap();
    let mut recv = Box::pin(handle.recv(
        Arc::new(left.into()),
        IoBufMut::with_capacity(1),
        0,
        1,
        false,
        Instant::now() + Duration::from_secs(60),
    ));

    let waker = panicking_drop_waker();
    {
        let mut cx = Context::from_waker(&waker);
        assert!(recv.as_mut().poll(&mut cx).is_pending());
    }
    // The waiter owns a clone. Forget the original so only orphan
    // wind-down exercises the intentional RawWaker drop panic.
    std::mem::forget(waker);

    // Fill capacity before dropping the admitted op. Its reservation can
    // be granted only after the committed cancel state retires the waiter.
    let (waiting_left, _waiting_right) = UnixStream::pair().unwrap();
    let mut waiting = Box::pin(handle.recv(
        Arc::new(waiting_left.into()),
        IoBufMut::with_capacity(1),
        0,
        1,
        false,
        Instant::now() + Duration::from_secs(60),
    ));
    let flag = Arc::new(WokenFlag(AtomicBool::new(false)));
    let flag_waker = arc_waker(Arc::clone(&flag));
    let mut flag_cx = Context::from_waker(&flag_waker);
    assert!(waiting.as_mut().poll(&mut flag_cx).is_pending());

    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(recv)))
        .expect_err("stored op waker drop should panic");
    assert_eq!(
        panic.downcast_ref::<&'static str>(),
        Some(&"intentional RawWaker drop panic")
    );
    harness.handle.with(|ops| {
        assert_eq!(ops.waiters.len(), 1);
        assert_eq!(ops.waiters.pending(), 1);
        assert_eq!(ops.backlog.len(), 1);
        assert!(ops.pending_cancels.is_empty());
        assert_eq!(ops.capacity.registered(), 1);
        assert_eq!(ops.capacity.queued(), 1);
    });

    // The next turn observes the committed CancelRequested state, frees
    // the waiter, and grants its capacity without touching the old waker.
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            harness.driver().turn();
        }))
        .is_ok()
    );
    assert_eq!(harness.tracked(), 0);
    assert!(flag.0.load(Ordering::Acquire));
    harness.handle.with(|ops| {
        assert_eq!(ops.capacity.registered(), 1);
        assert_eq!(ops.capacity.queued(), 0);
        assert_eq!(ops.capacity.reserved(), 1);
    });

    // Releasing the granted successor proves the loop remains usable and
    // does not encounter a second drop of the adversarial waker.
    drop(waiting);
    harness.handle.with(|ops| {
        assert_eq!(ops.capacity.registered(), 0);
        assert_eq!(ops.capacity.reserved(), 0);
    });
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            harness.driver().turn();
        }))
        .is_ok()
    );
}

#[test]
fn test_foreign_op_waker_drop_panics_after_mailbox_orphan_commit() {
    let mut harness = TestLoop::new(RingConfig {
        size: 1,
        ..Default::default()
    });
    let handle = harness.handle.clone();
    let (left, _right) = UnixStream::pair().unwrap();
    let mut recv = Box::pin(handle.recv(
        Arc::new(left.into()),
        IoBufMut::with_capacity(1),
        0,
        1,
        false,
        Instant::now() + Duration::from_secs(60),
    ));

    let waker = panicking_drop_waker();
    {
        let mut cx = Context::from_waker(&waker);
        assert!(recv.as_mut().poll(&mut cx).is_pending());
    }
    std::mem::forget(waker);
    harness.driver().turn();
    assert_eq!(harness.pending(), 1);

    let (waiting_left, _waiting_right) = UnixStream::pair().unwrap();
    let mut waiting = Box::pin(handle.recv(
        Arc::new(waiting_left.into()),
        IoBufMut::with_capacity(1),
        0,
        1,
        false,
        Instant::now() + Duration::from_secs(60),
    ));
    let flag = Arc::new(WokenFlag(AtomicBool::new(false)));
    let flag_waker = arc_waker(Arc::clone(&flag));
    let mut flag_cx = Context::from_waker(&flag_waker);
    assert!(waiting.as_mut().poll(&mut flag_cx).is_pending());

    // The foreign destructor only publishes the waiter ID. Owner-side
    // mailbox processing commits cancellation before dropping its waker.
    std::thread::scope(|scope| {
        scope.spawn(move || drop(recv)).join().unwrap();
    });
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let driver = harness.driver();
        let owner = driver.inner.handle.clone();
        owner.with(|ops| driver.inner.process_orphans(ops));
        driver.inner.flush_wakers();
    }))
    .expect_err("mailbox orphan waker drop should panic");
    assert_eq!(
        panic.downcast_ref::<&'static str>(),
        Some(&"intentional RawWaker drop panic")
    );
    harness.handle.with(|ops| {
        assert_eq!(ops.waiters.len(), 1);
        assert_eq!(ops.waiters.pending(), 1);
        assert_eq!(ops.pending_cancels.len(), 1);
        assert_eq!(ops.released_deadlines.len(), 1);
        assert_eq!(ops.capacity.registered(), 1);
        assert_eq!(ops.capacity.queued(), 1);
    });

    // Later turns release deadline accounting, submit the recorded
    // cancel, retire the waiter, and grant the waiting task exactly once.
    let start = Instant::now();
    while harness.tracked() != 0 {
        assert!(start.elapsed() < Duration::from_secs(5));
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                harness.driver().turn();
                if harness.tracked() != 0 {
                    harness.driver().park(Some(Duration::from_millis(10)));
                }
            }))
            .is_ok()
        );
    }
    assert!(flag.0.load(Ordering::Acquire));
    assert_eq!(harness.driver().inner.timeout_wheel.next_deadline(), None);
    harness.handle.with(|ops| {
        assert!(ops.pending_cancels.is_empty());
        assert!(ops.released_deadlines.is_empty());
        assert_eq!(ops.capacity.registered(), 1);
        assert_eq!(ops.capacity.queued(), 0);
        assert_eq!(ops.capacity.reserved(), 1);
    });

    drop(waiting);
    harness.handle.with(|ops| {
        assert_eq!(ops.capacity.registered(), 0);
        assert_eq!(ops.capacity.reserved(), 0);
    });
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            harness.driver().turn();
        }))
        .is_ok()
    );
}

#[test]
fn test_pending_ticket_waker_drop_panics_after_sync_detach_commit() {
    let mut harness = TestLoop::new(RingConfig {
        size: 1,
        ..Default::default()
    });
    let handle = harness.handle.clone();
    let (left, _right) = UnixStream::pair().unwrap();
    // SAFETY: `left` is a valid owned fd and is transferred into `File`.
    let file = unsafe { File::from_raw_fd(left.into_raw_fd()) };
    let mut ticket = harness.block_on(handle.start_sync(Arc::new(file)));

    let waker = panicking_drop_waker();
    {
        let mut cx = Context::from_waker(&waker);
        assert!(Pin::new(&mut ticket).poll(&mut cx).is_pending());
    }
    // The completion entry owns a clone. Forget the test's original so
    // only owner-side completion removal exercises the panicking drop.
    std::mem::forget(waker);

    let dropped = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(ticket)));
    assert!(dropped.is_err());
    harness.handle.with(|ops| {
        assert_eq!(ops.completions.ready(), 0);
        assert_eq!(ops.waiters.len(), 1);
        assert_eq!(ops.operation_count(), 1);
        assert!(ops.pending_cancels.is_empty());
    });

    // The sync was already detached before RawWaker destruction ran.
    // Its terminal CQE therefore frees the waiter without addressing the
    // removed completion entry or producing a second panic.
    let start = Instant::now();
    while harness.pending() != 0 {
        assert!(start.elapsed() < Duration::from_secs(5));
        let progressed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            harness.driver().turn();
            if harness.pending() != 0 {
                harness.driver().park(Some(Duration::from_millis(10)));
            }
        }));
        assert!(progressed.is_ok());
    }
    assert_eq!(harness.tracked(), 0);
}

#[test]
fn test_panicking_ticket_waker_leaves_committed_completion() {
    let mut harness = TestLoop::new(RingConfig {
        size: 1,
        ..Default::default()
    });
    let handle = harness.handle.clone();
    let (left, _right) = UnixStream::pair().unwrap();
    // SAFETY: `left` is a valid owned fd and is transferred into `File`.
    let file = unsafe { File::from_raw_fd(left.into_raw_fd()) };
    let mut ticket = harness.block_on(handle.start_sync(Arc::new(file)));

    let waker = arc_waker(Arc::new(PanicWaker));
    let mut cx = Context::from_waker(&waker);
    assert!(Pin::new(&mut ticket).poll(&mut cx).is_pending());

    // Register a capacity waiter after the panicking ticket waker. Its
    // grant is committed when ticket completion frees the only waiter,
    // before callbacks run.
    let (waiting_left, _waiting_right) = UnixStream::pair().unwrap();
    let mut waiting = Box::pin(handle.recv(
        Arc::new(waiting_left.into()),
        IoBufMut::with_capacity(1),
        0,
        1,
        false,
        Instant::now() + Duration::from_secs(60),
    ));
    let noop = futures::task::noop_waker();
    let mut noop_cx = Context::from_waker(&noop);
    assert!(waiting.as_mut().poll(&mut noop_cx).is_pending());
    assert_eq!(harness.handle.with(|ops| ops.capacity.registered()), 1);

    let start = Instant::now();
    let panic = loop {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            harness.driver().turn();
            harness.driver().park(Some(Duration::from_millis(10)));
        }));
        if result.is_err() {
            break result;
        }
        assert!(start.elapsed() < Duration::from_secs(5));
    };
    assert!(panic.is_err());
    harness.handle.with(|ops| {
        assert_eq!(ops.waiters.len(), 0);
        assert_eq!(ops.completions.ready(), 1);
        assert_eq!(ops.capacity.registered(), 1);
        assert_eq!(ops.capacity.queued(), 0);
        assert_eq!(ops.capacity.reserved(), 1);
    });

    // Drop observes Ready by CompletionId. It must not touch the recycled
    // waiter or panic while unwinding from the callback.
    let dropped = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(ticket)));
    assert!(dropped.is_ok());
    harness.handle.with(|ops| {
        assert_eq!(ops.waiters.len(), 0);
        assert_eq!(ops.completions.ready(), 0);
    });
    drop(waiting);
}

#[test]
fn test_panicking_capacity_waker_observes_done_op() {
    let mut harness = TestLoop::new(RingConfig {
        size: 1,
        ..Default::default()
    });
    let handle = harness.handle.clone();

    // Complete an ordinary recv but leave its output parked in the only
    // waiter until the future is polled again.
    let (left, mut right) = UnixStream::pair().unwrap();
    let mut first = Box::pin(handle.recv(
        Arc::new(left.into()),
        IoBufMut::with_capacity(1),
        0,
        1,
        false,
        Instant::now() + Duration::from_secs(60),
    ));
    assert!(poll_once(&harness, &mut first).is_pending());
    right.write_all(b"x").unwrap();
    let start = Instant::now();
    while harness.pending() != 0 {
        assert!(start.elapsed() < Duration::from_secs(5));
        harness.driver().turn();
        harness.driver().park(Some(Duration::from_millis(10)));
    }
    assert_eq!(harness.handle.with(|ops| ops.waiters.len()), 1);

    // Register two admissions in order. Only the FIFO head receives the
    // released permit, and its capacity waker panics.
    let (second_left, _second_right) = UnixStream::pair().unwrap();
    let mut second = Box::pin(handle.recv(
        Arc::new(second_left.into()),
        IoBufMut::with_capacity(1),
        0,
        1,
        false,
        Instant::now() + Duration::from_secs(60),
    ));
    let panic_waker = arc_waker(Arc::new(PanicWaker));
    let mut panic_cx = Context::from_waker(&panic_waker);
    assert!(second.as_mut().poll(&mut panic_cx).is_pending());

    let (third_left, _third_right) = UnixStream::pair().unwrap();
    let mut third = Box::pin(handle.recv(
        Arc::new(third_left.into()),
        IoBufMut::with_capacity(1),
        0,
        1,
        false,
        Instant::now() + Duration::from_secs(60),
    ));
    let flag = Arc::new(WokenFlag(AtomicBool::new(false)));
    let flag_waker = arc_waker(flag.clone());
    let mut flag_cx = Context::from_waker(&flag_waker);
    assert!(third.as_mut().poll(&mut flag_cx).is_pending());
    assert_eq!(harness.handle.with(|ops| ops.capacity.registered()), 2);

    // Consuming the first op recycles its waiter, changes its local state
    // to Done, then invokes capacity wakers. Drop after the callback panic
    // must therefore be a no-op instead of orphaning a stale waiter ID.
    let completed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let noop = futures::task::noop_waker();
        let mut cx = Context::from_waker(&noop);
        let _ = first.as_mut().poll(&mut cx);
    }));
    assert!(completed.is_err());
    assert!(!flag.0.load(Ordering::SeqCst));
    harness.handle.with(|ops| {
        assert_eq!(ops.capacity.registered(), 2);
        assert_eq!(ops.capacity.queued(), 1);
        assert_eq!(ops.capacity.reserved(), 1);
    });
    let dropped = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(first)));
    assert!(dropped.is_ok());

    // Cancelling the granted head transfers its permit to the next FIFO
    // node and wakes that task exactly once.
    drop(second);
    assert!(flag.0.load(Ordering::SeqCst));
    harness.handle.with(|ops| {
        assert_eq!(ops.capacity.registered(), 1);
        assert_eq!(ops.capacity.queued(), 0);
        assert_eq!(ops.capacity.reserved(), 1);
    });
    drop(third);
    assert_eq!(harness.tracked(), 0);
}

#[test]
fn test_drop_terminal_op_grants_capacity_once() {
    let mut harness = TestLoop::new(RingConfig {
        size: 1,
        ..Default::default()
    });
    let handle = harness.handle.clone();

    // Complete an ordinary recv but leave its terminal output unobserved
    // in the only waiter slot.
    let (first_left, mut first_right) = UnixStream::pair().unwrap();
    let mut first = Box::pin(handle.recv(
        Arc::new(first_left.into()),
        IoBufMut::with_capacity(1),
        0,
        1,
        false,
        Instant::now() + Duration::from_secs(60),
    ));
    assert!(poll_once(&harness, &mut first).is_pending());
    first_right.write_all(b"x").unwrap();
    let start = Instant::now();
    while harness.pending() != 0 {
        assert!(start.elapsed() < Duration::from_secs(5));
        harness.driver().turn();
        if harness.pending() != 0 {
            harness.driver().park(Some(Duration::from_millis(10)));
        }
    }
    harness.handle.with(|ops| {
        assert_eq!(ops.waiters.len(), 1);
        assert_eq!(ops.waiters.pending(), 0);
    });

    // The second recv cannot acquire capacity until dropping the first
    // future recycles its terminal waiter. That drop grants the queued
    // owner and invokes its callback exactly once.
    let (second_left, _second_right) = UnixStream::pair().unwrap();
    let mut second = Box::pin(handle.recv(
        Arc::new(second_left.into()),
        IoBufMut::with_capacity(1),
        0,
        1,
        false,
        Instant::now() + Duration::from_secs(60),
    ));
    let count = Arc::new(WakeCount(AtomicUsize::new(0)));
    let count_waker = arc_waker(count.clone());
    let mut count_cx = Context::from_waker(&count_waker);
    assert!(second.as_mut().poll(&mut count_cx).is_pending());
    harness.handle.with(|ops| {
        assert_eq!(ops.capacity.registered(), 1);
        assert_eq!(ops.capacity.queued(), 1);
        assert_eq!(ops.capacity.reserved(), 0);
    });
    assert_eq!(count.0.load(Ordering::Acquire), 0);

    drop(first);
    harness.handle.with(|ops| {
        assert_eq!(ops.waiters.len(), 0);
        assert_eq!(ops.capacity.registered(), 1);
        assert_eq!(ops.capacity.queued(), 0);
        assert_eq!(ops.capacity.reserved(), 1);
    });
    assert_eq!(count.0.load(Ordering::Acquire), 1);

    // Unrelated loop progress cannot re-grant or re-wake the owner.
    harness.driver().turn();
    assert_eq!(count.0.load(Ordering::Acquire), 1);
    drop(second);
    harness.handle.with(|ops| {
        assert_eq!(ops.capacity.registered(), 0);
        assert_eq!(ops.capacity.reserved(), 0);
    });
    assert_eq!(count.0.load(Ordering::Acquire), 1);
    assert_eq!(harness.tracked(), 0);
}

/// A capacity callback may synchronously poll its operation. Work admitted
/// by that reentrant poll must be staged before the turn can return.
#[test]
fn test_capacity_waker_reentrant_admission_is_staged_in_same_turn() {
    /// Result produced by the reentrantly polled receive operation.
    type RecvResult = Result<(IoBufMut, usize), (IoBufMut, Error)>;

    /// Waker that synchronously polls a capacity-blocked receive.
    struct ReentrantAdmission {
        /// Receive future waiting for the capacity callback.
        future: Mutex<Pin<Box<dyn Future<Output = RecvResult> + Send>>>,
        /// Number of capacity callbacks observed by the test.
        callbacks: AtomicUsize,
    }

    impl ArcWake for ReentrantAdmission {
        fn wake_by_ref(arc_self: &Arc<Self>) {
            arc_self.callbacks.fetch_add(1, Ordering::AcqRel);
            let waker = futures::task::noop_waker();
            let mut cx = Context::from_waker(&waker);
            assert!(arc_self.future.lock().as_mut().poll(&mut cx).is_pending());
        }
    }

    let mut harness = TestLoop::new(RingConfig {
        size: 1,
        ..Default::default()
    });
    let handle = harness.handle.clone();

    // Occupy the only waiter with a ticket whose CQE frees the slot
    // inside the driver turn and grants the queued successor.
    let (sync_left, _sync_right) = UnixStream::pair().unwrap();
    // SAFETY: `sync_left` is a valid owned fd and is transferred into File.
    let file = unsafe { File::from_raw_fd(sync_left.into_raw_fd()) };
    let ticket = harness.block_on(handle.start_sync(Arc::new(file)));

    let (recv_left, _recv_right) = UnixStream::pair().unwrap();
    let recv_handle = handle.clone();
    let admission = Arc::new(ReentrantAdmission {
        future: Mutex::new(Box::pin(async move {
            recv_handle
                .recv(
                    Arc::new(recv_left.into()),
                    IoBufMut::with_capacity(1),
                    0,
                    1,
                    false,
                    Instant::now() + Duration::from_secs(60),
                )
                .await
        })),
        callbacks: AtomicUsize::new(0),
    });
    let admission_waker = arc_waker(Arc::clone(&admission));
    let mut admission_cx = Context::from_waker(&admission_waker);
    assert!(
        admission
            .future
            .lock()
            .as_mut()
            .poll(&mut admission_cx)
            .is_pending()
    );

    // Drive until the sync CQE grants capacity and invokes the callback.
    let start = Instant::now();
    while admission.callbacks.load(Ordering::Acquire) == 0 {
        assert!(start.elapsed() < Duration::from_secs(5));
        harness.driver().turn();
        if admission.callbacks.load(Ordering::Acquire) == 0 {
            harness.driver().park(Some(Duration::from_millis(10)));
        }
    }

    // The callback admitted the recv after the turn's first staging pass.
    // It must nevertheless have an SQE and timeout entry before return.
    harness.handle.with(|ops| {
        assert!(ops.backlog.is_empty());
        assert_eq!(ops.waiters.pending(), 1);
    });
    assert!(
        harness
            .driver()
            .inner
            .timeout_wheel
            .next_deadline()
            .is_some()
    );

    drop(ticket);
    drop(admission_waker);
    drop(admission);
}

#[test]
fn test_turn_refreshes_deadlines_after_waker_callback() {
    struct SleepPast(Instant);

    impl ArcWake for SleepPast {
        fn wake_by_ref(arc_self: &Arc<Self>) {
            std::thread::sleep(arc_self.0.saturating_duration_since(Instant::now()));
        }
    }

    let cfg = RingConfig {
        timeout_wheel_tick: Duration::from_millis(1),
        ..RingConfig::default()
    };
    let mut registry = Registry::default();
    let (mut ring, handle, mut ioloop) =
        IoUringLoop::new(cfg, Duration::from_secs(1), &mut registry)
            .expect("io_uring creation should succeed");
    let (left, _right) = UnixStream::pair().unwrap();
    let deadline = Instant::now() + Duration::from_millis(50);
    let mut recv = Box::pin(handle.recv(
        Arc::new(left.into()),
        IoBufMut::with_capacity(1),
        0,
        1,
        false,
        deadline,
    ));
    let waker = futures::task::noop_waker();
    let mut cx = Context::from_waker(&waker);
    assert!(recv.as_mut().poll(&mut cx).is_pending());
    ioloop.turn(&mut ring);
    assert!(ioloop.timeout_wheel.next_deadline().is_some());

    // The callback consumes the entire remaining timeout without
    // publishing any driver work. The turn must refresh deadlines before
    // it can return control to a blocking park.
    let sleepy = arc_waker(Arc::new(SleepPast(deadline + Duration::from_millis(5))));
    ioloop
        .pending_waker_actions
        .push(handle::WakerAction::Wake(sleepy));
    ioloop.turn(&mut ring);
    assert_eq!(ioloop.timeout_wheel.next_deadline(), None);

    drop(recv);
    handle::wake_batch(handle.close().into_iter().map(handle::WakerAction::Wake));
    ioloop.drain(&mut ring);
}

#[test]
fn test_ready_ticket_survives_driver_close() {
    let mut harness = TestLoop::new(RingConfig::default());
    let handle = harness.handle.clone();
    let ticket = park_sync_ticket(&mut harness, &handle);
    harness.shutdown();

    // The ring is gone, but the ticket's Handle keeps the userspace-only
    // Ready completion alive and directly consumable.
    assert!(harness.block_on(ticket).is_err());
    harness.handle.with(|ops| {
        assert_eq!(ops.waiters.len(), 0);
        assert_eq!(ops.completions.ready(), 0);
    });
}

#[test]
fn test_capacity_cancel_releases_slot() {
    // Cancelled admission attempts must release their capacity slots
    // immediately and reuse the arena, so a long-saturated ring retains
    // no wakers (and no growing arena) for attempts that no longer exist.
    let mut harness = TestLoop::new(RingConfig {
        size: 1,
        ..Default::default()
    });
    let handle = harness.handle.clone();

    // Fill the single waiter slot with a recv that stays in flight.
    let (blocker_left, _blocker_right) = UnixStream::pair().unwrap();
    let mut blocker = Box::pin(handle.recv(
        Arc::new(blocker_left.into()),
        IoBufMut::with_capacity(1),
        0,
        1,
        false,
        Instant::now() + Duration::from_secs(60),
    ));
    assert!(poll_once(&harness, &mut blocker).is_pending());

    // Park-and-cancel churn: every attempt holds exactly one slot
    // (re-polls refresh in place), releases it on drop, and the arena
    // recycles that slot instead of growing.
    for _ in 0..64 {
        let (left, _right) = UnixStream::pair().unwrap();
        let mut parked = Box::pin(handle.recv(
            Arc::new(left.into()),
            IoBufMut::with_capacity(1),
            0,
            1,
            false,
            Instant::now() + Duration::from_secs(60),
        ));
        assert!(poll_once(&harness, &mut parked).is_pending());
        assert!(poll_once(&harness, &mut parked).is_pending());
        harness.handle.with(|ops| {
            assert_eq!(ops.capacity.registered(), 1);
            assert_eq!(ops.capacity.arena_len(), 1);
        });
        drop(parked);
        harness
            .handle
            .with(|ops| assert_eq!(ops.capacity.registered(), 0));
    }
    harness
        .handle
        .with(|ops| assert_eq!(ops.capacity.arena_len(), 1));

    // Close recycles the terminal registration immediately. A later owner
    // drop carries a stale generation and cannot affect another waiter.
    let (left, _right) = UnixStream::pair().unwrap();
    let mut parked = Box::pin(handle.recv(
        Arc::new(left.into()),
        IoBufMut::with_capacity(1),
        0,
        1,
        false,
        Instant::now() + Duration::from_secs(60),
    ));
    assert!(poll_once(&harness, &mut parked).is_pending());
    harness.driver().close();
    harness
        .handle
        .with(|ops| assert_eq!(ops.capacity.registered(), 0));
    drop(parked);
    harness
        .handle
        .with(|ops| assert_eq!(ops.capacity.registered(), 0));
}

#[test]
fn test_closed_driver_fails_admission() {
    // Verify ops staged after close resolve with their kind-specific
    // failures without touching the ring.
    let mut harness = TestLoop::new(RingConfig::default());
    harness.driver().close();

    let (left, _right) = UnixStream::pair().unwrap();
    let handle = harness.handle.clone();
    let result = harness.block_on(handle.recv(
        Arc::new(left.into()),
        IoBufMut::with_capacity(8),
        0,
        8,
        false,
        Instant::now() + Duration::from_secs(1),
    ));
    assert!(matches!(result, Err((_, Error::RecvFailed))));

    let (sock, _keep) = UnixStream::pair().unwrap();
    // SAFETY: sock is a valid fd that we own.
    let file = unsafe { std::fs::File::from_raw_fd(sock.into_raw_fd()) };
    let ticket = harness.block_on(handle.start_sync(Arc::new(file)));
    let result = harness.block_on(ticket);
    assert!(matches!(result, Err(Error::Closed)));
    harness.handle.with(|ops| {
        assert_eq!(ops.waiters.len(), 0);
        assert_eq!(ops.completions.ready(), 0);
        assert_eq!(ops.completions.arena_len(), 0);
        assert_eq!(ops.operation_count(), 0);
    });
}

#[test]
fn test_shutdown_waits_for_inflight_write() {
    // Verify shutdown without a cancellation grace waits for the last
    // in-flight request instead of abandoning it.
    let dir = std::env::temp_dir().join(format!(
        "commonware_iouring_shutdown_write_{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("shutdown_write");
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();

    let mut harness = TestLoop::new(RingConfig {
        shutdown_timeout: None,
        ..Default::default()
    });
    let handle = harness.handle.clone();
    let payload = vec![9u8; 1 << 20];
    let mut write = Box::pin(handle.write_at(
        Arc::new(file),
        0,
        IoBufs::from(IoBuf::from(payload.clone())),
        WriteOptions::SYNC,
        Cache::Enabled,
    ));
    assert!(poll_once(&harness, &mut write).is_pending());

    // Shutdown drains the write, and the future then observes success.
    harness.shutdown();
    match poll_once(&harness, &mut write) {
        Poll::Ready(Ok(())) => {}
        other => panic!("expected completed write after drain, got {other:?}"),
    }
    let written = std::fs::read(&path).unwrap();
    assert_eq!(written, payload);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn test_shutdown_timeout_cancels_stuck_recv() {
    // Verify shutdown requests cancellation after the grace and the live
    // future observes the closed result.
    let mut harness = TestLoop::new(RingConfig {
        shutdown_timeout: Some(Duration::from_millis(200)),
        ..Default::default()
    });
    let (left, _right) = UnixStream::pair().unwrap();

    let handle = harness.handle.clone();
    let mut recv = Box::pin(handle.recv(
        Arc::new(left.into()),
        IoBufMut::with_capacity(8),
        0,
        8,
        false,
        Instant::now() + Duration::from_secs(60),
    ));
    assert!(poll_once(&harness, &mut recv).is_pending());
    harness.driver().turn();
    assert_eq!(harness.pending(), 1);

    let start = Instant::now();
    harness.shutdown();
    assert!(
        start.elapsed() < Duration::from_secs(5),
        "shutdown cancellation did not retire promptly: {:?}",
        start.elapsed()
    );

    // The shutdown-cancelled recv parked a closed result for the live
    // future: shutdown is distinguishable from an operation timeout.
    match poll_once(&harness, &mut recv) {
        Poll::Ready(Err((_, Error::Closed))) => {}
        other => panic!("expected shutdown-cancelled recv to be closed, got {other:?}"),
    }
    assert_eq!(harness.tracked(), 0);
}

#[test]
fn test_shutdown_preserves_deadline_result() {
    // Verify an op whose own deadline expires during the drain reports
    // timeout even when the shutdown cancellation grace is longer.
    let mut harness = TestLoop::new(RingConfig {
        shutdown_timeout: Some(Duration::from_secs(10)),
        timeout_wheel_tick: Duration::from_millis(5),
        ..Default::default()
    });
    let (left, _right) = UnixStream::pair().unwrap();

    let handle = harness.handle.clone();
    let mut recv = Box::pin(handle.recv(
        Arc::new(left.into()),
        IoBufMut::with_capacity(8),
        0,
        8,
        false,
        Instant::now() + Duration::from_millis(100),
    ));
    assert!(poll_once(&harness, &mut recv).is_pending());
    harness.driver().turn();

    let start = Instant::now();
    harness.shutdown();
    let elapsed = start.elapsed();
    assert!(
        elapsed < Duration::from_secs(5),
        "deadline-driven drain took {elapsed:?}"
    );

    match poll_once(&harness, &mut recv) {
        Poll::Ready(Err((_, Error::Timeout))) => {}
        other => panic!("expected recv deadline timeout, got {other:?}"),
    }
}

#[test]
fn test_dropped_op_releases_wheel_deadline() {
    // Verify dropping a deadline-carrying op future after first staging
    // releases its timeout-wheel accounting: a leaked tick would make the
    // wheel report an elapsed deadline forever, degrading park into a
    // busy loop.
    let mut harness = TestLoop::new(RingConfig {
        timeout_wheel_tick: Duration::from_millis(5),
        ..Default::default()
    });
    let (left, _right) = UnixStream::pair().unwrap();

    let handle = harness.handle.clone();
    let mut recv = Box::pin(handle.recv(
        Arc::new(left.into()),
        IoBufMut::with_capacity(8),
        0,
        8,
        false,
        Instant::now() + Duration::from_millis(50),
    ));

    // Admit and submit the recv (first staging schedules the deadline).
    assert!(poll_once(&harness, &mut recv).is_pending());
    harness.driver().turn();
    assert_eq!(harness.pending(), 1);

    // Drop the future: orphan plus eager async-cancel.
    drop(recv);
    let start = Instant::now();
    while harness.tracked() != 0 {
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "orphaned recv still tracked after {:?}",
            start.elapsed()
        );
        harness.driver().turn();
        harness.driver().park(Some(Duration::from_millis(10)));
    }

    // No waiters remain, so once the original deadline elapses the wheel
    // must not report an active deadline.
    std::thread::sleep(Duration::from_millis(100));
    harness.driver().turn();
    assert_eq!(
        harness.driver().inner.timeout_wheel.next_deadline(),
        None,
        "dropped op leaked its timeout-wheel deadline"
    );
}

#[test]
fn test_cross_thread_wake_lands_with_saturated_submission_queue() {
    // Verify the wake poll wins its rearm retry against a single-slot SQ
    // (where it competes with op SQEs for the only entry) so an
    // out-of-band wake still unparks a blocked loop.
    let mut harness = TestLoop::new(RingConfig {
        size: 1,
        ..Default::default()
    });
    let (left, _right) = UnixStream::pair().unwrap();

    // Keep a recv in flight so park blocks in the eventfd-backed path.
    let handle = harness.handle.clone();
    let mut recv = Box::pin(handle.recv(
        Arc::new(left.into()),
        IoBufMut::with_capacity(1),
        0,
        1,
        false,
        Instant::now() + Duration::from_secs(60),
    ));
    assert!(poll_once(&harness, &mut recv).is_pending());
    harness.driver().turn();
    assert_eq!(harness.pending(), 1);

    // Wake from a foreign thread after the loop has had time to block.
    let waker = harness.driver().waker();
    let start = Instant::now();
    let wake_thread = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(50));
        waker.wake();
    });
    harness.driver().park(None);
    let elapsed = start.elapsed();
    wake_thread.join().unwrap();
    assert!(
        elapsed < Duration::from_secs(5),
        "cross-thread wake did not unpark the loop: {elapsed:?}"
    );

    // Drop the recv before the harness so shutdown cancels it eagerly.
    drop(recv);
}

#[test]
fn test_fill_requires_flush_only_for_sq_pressure() {
    // A full SQ with backlog work remaining must request a flush even when
    // the slab is also full.
    let mut harness = TestLoop::new(RingConfig {
        size: 2,
        ..Default::default()
    });
    let (left_a, _right_a) = UnixStream::pair().unwrap();
    let (left_b, _right_b) = UnixStream::pair().unwrap();

    let handle = harness.handle.clone();
    let mut recv_a = Box::pin(handle.recv(
        Arc::new(left_a.into()),
        IoBufMut::with_capacity(1),
        0,
        1,
        false,
        Instant::now() + Duration::from_secs(60),
    ));
    let mut recv_b = Box::pin(handle.recv(
        Arc::new(left_b.into()),
        IoBufMut::with_capacity(1),
        0,
        1,
        false,
        Instant::now() + Duration::from_secs(60),
    ));
    assert!(poll_once(&harness, &mut recv_a).is_pending());
    assert!(poll_once(&harness, &mut recv_b).is_pending());

    // First pass: the wake-poll rearm plus one op fill the two-slot SQ
    // while the second op stays in the backlog, so SQ pressure must dominate the
    // (also true) waiter-capacity pressure.
    let driver_state = harness.handle.clone();
    let driver = harness.driver();
    let needs_flush =
        driver_state.with(|ops| driver.inner.fill_submission_queue(ops, &mut driver.ring));
    assert!(needs_flush);

    // After flushing, the second op stages without filling the SQ, so no
    // further flush is needed even though the slab remains full.
    driver.inner.submit(&mut driver.ring).unwrap();
    let needs_flush =
        driver_state.with(|ops| driver.inner.fill_submission_queue(ops, &mut driver.ring));
    assert!(!needs_flush);

    drop(recv_a);
    drop(recv_b);
}

#[test]
fn test_fill_retries_wake_rearm_when_sq_is_full() {
    let mut harness = TestLoop::new(RingConfig {
        size: 1,
        ..Default::default()
    });
    let (left, _right) = UnixStream::pair().unwrap();

    let handle = harness.handle.clone();
    let mut recv = Box::pin(handle.recv(
        Arc::new(left.into()),
        IoBufMut::with_capacity(1),
        0,
        1,
        false,
        Instant::now() + Duration::from_secs(60),
    ));
    assert!(poll_once(&harness, &mut recv).is_pending());

    // Stage the op directly so the initial wake rearm still needs the
    // single SQ slot.
    let driver_state = harness.handle.clone();
    let driver = harness.driver();
    driver_state.with(|ops| {
        let mut submission_queue = driver.ring.submission();
        assert!(!driver.inner.stage_backlog(ops, &mut submission_queue));
        assert!(submission_queue.is_full());
    });

    let needs_flush =
        driver_state.with(|ops| driver.inner.fill_submission_queue(ops, &mut driver.ring));
    assert!(needs_flush);
    assert!(driver.inner.wake_rearm_needed);

    driver.inner.submit(&mut driver.ring).unwrap();
    let needs_flush = driver_state.with(|ops| {
        let needs_flush = driver.inner.fill_submission_queue(ops, &mut driver.ring);
        assert!(ops.waiters.is_full());
        assert!(ops.backlog.is_empty());
        needs_flush
    });
    // The wake poll exactly fills the SQ while the only waiter is in
    // flight. The turn can flush and reap it in one submit-and-wait call.
    assert!(!needs_flush);
    assert!(!driver.inner.wake_rearm_needed);

    drop(recv);
}

#[test]
fn test_fill_reports_exact_sq_saturation() {
    let mut harness = TestLoop::new(RingConfig {
        size: 2,
        ..Default::default()
    });
    let (left, _right) = UnixStream::pair().unwrap();

    let handle = harness.handle.clone();
    let mut recv = Box::pin(handle.recv(
        Arc::new(left.into()),
        IoBufMut::with_capacity(1),
        0,
        1,
        false,
        Instant::now() + Duration::from_secs(60),
    ));
    assert!(poll_once(&harness, &mut recv).is_pending());

    // The wake poll and one op exactly fill the SQ without exhausting the
    // waiter table or leaving more work queued.
    let driver_state = harness.handle.clone();
    let driver = harness.driver();
    let needs_flush = driver_state.with(|ops| {
        let needs_flush = driver.inner.fill_submission_queue(ops, &mut driver.ring);
        assert!(ops.backlog.is_empty());
        assert!(!ops.waiters.is_full());
        needs_flush
    });
    assert!(needs_flush);

    drop(recv);
}

#[test]
fn test_cancel_staging_batches_across_sq_submissions() {
    let mut harness = TestLoop::new(RingConfig {
        size: 2,
        ..Default::default()
    });
    let (left_a, _right_a) = UnixStream::pair().unwrap();
    let (left_b, _right_b) = UnixStream::pair().unwrap();

    let handle = harness.handle.clone();
    let mut recvs = vec![
        Box::pin(handle.recv(
            Arc::new(left_a.into()),
            IoBufMut::with_capacity(1),
            0,
            1,
            false,
            Instant::now() + Duration::from_secs(60),
        )),
        Box::pin(handle.recv(
            Arc::new(left_b.into()),
            IoBufMut::with_capacity(1),
            0,
            1,
            false,
            Instant::now() + Duration::from_secs(60),
        )),
    ];
    for recv in &mut recvs {
        assert!(poll_once(&harness, recv).is_pending());
    }

    // Submit the ops without consuming the initial wake-poll slot. The
    // next fill has room for only one of the two queued cancellations.
    let driver_state = harness.handle.clone();
    let driver = harness.driver();
    driver_state.with(|ops| {
        let mut submission_queue = driver.ring.submission();
        assert!(!driver.inner.stage_backlog(ops, &mut submission_queue));
        assert!(submission_queue.is_full());
    });
    driver.inner.submit(&mut driver.ring).unwrap();
    driver_state.with(|ops| driver.inner.cancel_all(ops));

    let needs_flush =
        driver_state.with(|ops| driver.inner.fill_submission_queue(ops, &mut driver.ring));
    assert!(needs_flush);
    driver_state.with(|ops| assert_eq!(ops.pending_cancels.len(), 1));

    driver.inner.submit(&mut driver.ring).unwrap();
    let needs_flush =
        driver_state.with(|ops| driver.inner.fill_submission_queue(ops, &mut driver.ring));
    assert!(!needs_flush);
    driver_state.with(|ops| assert!(ops.pending_cancels.is_empty()));
    driver.inner.submit(&mut driver.ring).unwrap();

    let results = harness.block_on(futures::future::join_all(recvs));
    for result in results {
        assert!(matches!(result, Err((_, Error::Closed))));
    }
}

#[test]
fn test_cancel_all_retires_local_ticket_without_cancel_sqe() {
    let mut harness = TestLoop::new(RingConfig::default());
    let (left, _right) = UnixStream::pair().unwrap();
    let file = File::from(OwnedFd::from(left));

    let handle = harness.handle.clone();
    let mut admission = Box::pin(handle.start_sync(Arc::new(file)));
    let Poll::Ready(mut ticket) = poll_once(&harness, &mut admission) else {
        panic!("sync admission should not wait for capacity");
    };

    let driver_state = harness.handle.clone();
    let driver = harness.driver();
    driver_state.with(|ops| {
        driver.inner.cancel_all(ops);
        assert!(ops.pending_cancels.is_empty());

        let mut submission_queue = driver.ring.submission();
        assert!(!driver.inner.stage_backlog(ops, &mut submission_queue));
        assert!(submission_queue.is_empty());
    });

    assert!(matches!(
        poll_once(&harness, &mut ticket),
        Poll::Ready(Err(Error::Closed))
    ));
    assert_eq!(harness.tracked(), 0);
}

#[test]
fn test_cancel_staging_skips_op_retired_by_original_completion() {
    let mut harness = TestLoop::new(RingConfig::default());
    let (left, _right) = UnixStream::pair().unwrap();
    let handle = harness.handle.clone();
    let mut recv = Box::pin(handle.recv(
        Arc::new(left.into()),
        IoBufMut::with_capacity(1),
        0,
        1,
        false,
        Instant::now() + Duration::from_secs(60),
    ));
    assert!(poll_once(&harness, &mut recv).is_pending());

    let driver_state = harness.handle.clone();
    let driver = harness.driver();
    let waker = driver_state.with(|ops| {
        let waiter_id = ops.backlog.pop_front().expect("recv should be queued");
        assert!(matches!(
            ops.waiters.stage(waiter_id),
            StageOutcome::Submit(_)
        ));
        driver.inner.cancel_all(ops);
        assert_eq!(ops.pending_cancels.front(), Some(&waiter_id));

        let CompletionOutcome::Ready { waker, target_tick } =
            ops.waiters.on_completion(waiter_id.user_data(), 0)
        else {
            panic!("original completion did not retire cancelled recv");
        };
        if let Some(tick) = target_tick {
            driver.inner.timeout_wheel.remove(tick);
        }

        let mut submission_queue = driver.ring.submission();
        assert!(!driver.inner.stage_cancellations(ops, &mut submission_queue));
        assert!(ops.pending_cancels.is_empty());
        assert!(submission_queue.is_empty());
        waker
    });
    waker.expect("recv waker missing").wake();

    assert!(matches!(
        poll_once(&harness, &mut recv),
        Poll::Ready(Err((_, Error::RecvFailed)))
    ));
    assert_eq!(harness.tracked(), 0);
}

#[test]
fn test_drain_retires_staged_cancelled_op_without_blocking() {
    // Verify drain breaks after staging locally retires the last waiter:
    // an op admitted but never submitted whose ticket dropped must not
    // leave drain blocked in a kernel wait that nothing will complete.
    let mut harness = TestLoop::new(RingConfig {
        shutdown_timeout: None,
        ..Default::default()
    });
    let (left, _right) = UnixStream::pair().unwrap();

    let handle = harness.handle.clone();
    let mut recv = Box::pin(handle.recv(
        Arc::new(left.into()),
        IoBufMut::with_capacity(8),
        0,
        8,
        false,
        Instant::now() + Duration::from_secs(60),
    ));
    // Admit without turning the loop, then drop: the entry stays in the
    // backlog in cancel-requested state.
    assert!(poll_once(&harness, &mut recv).is_pending());
    drop(recv);

    let start = Instant::now();
    harness.shutdown();
    assert!(
        start.elapsed() < Duration::from_secs(5),
        "drain blocked on a locally-retired op: {:?}",
        start.elapsed()
    );
    assert_eq!(harness.pending(), 0);
}

#[test]
fn test_drain_restages_partial_recv_to_completion() {
    // Verify requeued partial progress keeps advancing inside the drain
    // loop: an exact recv that has consumed part of its target must be
    // restaged by drain until the remaining bytes complete it.
    let mut harness = TestLoop::new(RingConfig {
        shutdown_timeout: None,
        ..Default::default()
    });
    let (left, right) = UnixStream::pair().unwrap();
    (&right).write_all(&[1]).unwrap();

    let handle = harness.handle.clone();
    let mut recv = Box::pin(handle.recv(
        Arc::new(left.into()),
        IoBufMut::with_capacity(2),
        0,
        2,
        true,
        Instant::now() + Duration::from_secs(60),
    ));
    assert!(poll_once(&harness, &mut recv).is_pending());
    harness.driver().turn();

    // Supply the rest before shutdown so drain can finish the requeue.
    (&right).write_all(&[2]).unwrap();

    let start = Instant::now();
    harness.shutdown();
    assert!(
        start.elapsed() < Duration::from_secs(5),
        "drain did not restage the partial recv: {:?}",
        start.elapsed()
    );

    match poll_once(&harness, &mut recv) {
        Poll::Ready(Ok((_, read))) => assert_eq!(read, 2),
        other => panic!("expected completed exact recv after drain, got {other:?}"),
    }
}

#[test]
fn test_off_thread_drop_reclaims_slot() {
    // A future dropped on a foreign thread hands its slot to the loop
    // through the orphan mailbox: subsequent turns wind it down
    // (cancelling the in-flight recv) instead of leaking the slot until
    // shutdown.
    let mut harness = TestLoop::new(RingConfig::default());
    let (left, _right) = UnixStream::pair().unwrap();

    let handle = harness.handle.clone();
    let mut recv = Box::pin(handle.recv(
        Arc::new(left.into()),
        IoBufMut::with_capacity(8),
        0,
        8,
        false,
        Instant::now() + Duration::from_secs(60),
    ));
    assert!(poll_once(&harness, &mut recv).is_pending());
    harness.driver().turn();
    assert_eq!(harness.tracked(), 1);

    // Drop the admitted future on a foreign thread: the affinity check
    // cannot run the wind-down there, so it routes through the mailbox.
    std::thread::scope(|scope| {
        scope.spawn(move || drop(recv)).join().unwrap();
    });

    // The loop winds the orphan down (async-cancelling the recv) and the
    // slot frees without any shutdown cancellation grace.
    let start = Instant::now();
    while harness.tracked() != 0 {
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "foreign-thread drop did not reclaim the slot: {:?}",
            start.elapsed()
        );
        harness.driver().turn();
        harness.driver().park(Some(Duration::from_millis(10)));
    }
}

#[test]
fn test_closed_driver_fails_capacity_parked_admission() {
    // Verify an admission parked on the capacity wait list observes a
    // driver close and resolves with its kind-specific error instead of
    // re-parking.
    let mut harness = TestLoop::new(RingConfig {
        size: 1,
        ..Default::default()
    });
    let (left_a, _right_a) = UnixStream::pair().unwrap();
    let (left_b, _right_b) = UnixStream::pair().unwrap();

    let handle = harness.handle.clone();
    let mut recv_a = Box::pin(handle.recv(
        Arc::new(left_a.into()),
        IoBufMut::with_capacity(1),
        0,
        1,
        false,
        Instant::now() + Duration::from_secs(60),
    ));
    let mut recv_b = Box::pin(handle.recv(
        Arc::new(left_b.into()),
        IoBufMut::with_capacity(1),
        0,
        1,
        false,
        Instant::now() + Duration::from_secs(60),
    ));

    // Fill the single slot, then park the second admission.
    assert!(poll_once(&harness, &mut recv_a).is_pending());
    harness.driver().turn();
    assert!(poll_once(&harness, &mut recv_b).is_pending());

    // Close the driver: the parked admission must fail on its next poll.
    harness.driver().close();
    match poll_once(&harness, &mut recv_b) {
        Poll::Ready(Err((_, Error::RecvFailed))) => {}
        other => panic!("expected closed-driver recv failure, got {other:?}"),
    }

    drop(recv_a);
}

#[test]
fn test_mass_timeout_cancel_burst_exceeds_sq_capacity() {
    // Verify a timeout burst whose cancel SQEs exceed one SQ pass batches
    // across submit cycles instead of stranding in-flight waiters.
    let mut harness = TestLoop::new(RingConfig {
        size: 8,
        timeout_wheel_tick: Duration::from_millis(5),
        ..Default::default()
    });

    let handle = harness.handle.clone();
    let mut sockets = Vec::new();
    let mut recvs = Vec::new();
    for _ in 0..8 {
        let (left, right) = UnixStream::pair().unwrap();
        sockets.push(right);
        recvs.push(Box::pin(handle.recv(
            Arc::new(left.into()),
            IoBufMut::with_capacity(1),
            0,
            1,
            false,
            Instant::now() + Duration::from_millis(60),
        )));
    }
    for recv in &mut recvs {
        assert!(poll_once(&harness, recv).is_pending());
    }
    harness.driver().turn();

    // Let every deadline expire, then drive all ops to their timeout
    // results: the cancel burst plus the wake-poll rearm exceeds the
    // eight-slot SQ and must batch.
    std::thread::sleep(Duration::from_millis(100));
    let start = Instant::now();
    let results = harness.block_on(futures::future::join_all(recvs));
    assert!(
        start.elapsed() < Duration::from_secs(5),
        "cancel burst did not batch: {:?}",
        start.elapsed()
    );
    for result in results {
        assert!(matches!(result, Err((_, Error::Timeout))));
    }
}

fn assert_recv_capacity_reused(harness: &mut TestLoop) {
    let (left, right) = UnixStream::pair().unwrap();
    (&right).write_all(&[9]).unwrap();
    let handle = harness.handle.clone();
    let (mut buf, read) = harness
        .block_on(handle.recv(
            Arc::new(left.into()),
            IoBufMut::with_capacity(1),
            0,
            1,
            false,
            Instant::now() + Duration::from_secs(30),
        ))
        .expect("reused waiter slot should complete");
    assert_eq!(read, 1);
    // SAFETY: the kernel filled `read` bytes before completion.
    unsafe { buf.set_len(read) };
    assert_eq!(buf.as_ref(), &[9]);
    assert_eq!(harness.pending(), 0);
    assert_eq!(harness.tracked(), 0);
}

#[test]
fn test_completion_before_timeout_expiry_wins() {
    // Reap a successful CQE before advancing synthetic wheel time past
    // the same request's deadline. Completion must remove timeout
    // accounting before expiry observes the waiter.
    let mut harness = TestLoop::new(RingConfig {
        size: 1,
        timeout_wheel_tick: Duration::from_millis(1),
        ..Default::default()
    });
    let handle = harness.handle.clone();
    let (left, right) = UnixStream::pair().unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut recv = Box::pin(handle.recv(
        Arc::new(left.into()),
        IoBufMut::with_capacity(1),
        0,
        1,
        false,
        deadline,
    ));
    assert!(poll_once(&harness, &mut recv).is_pending());
    harness.driver().turn();

    (&right).write_all(&[7]).unwrap();
    let driver = harness.driver();
    driver
        .inner
        .submit_and_wait(&mut driver.ring, 1, None)
        .expect("recv completion should enter the CQ");
    let owner = driver.inner.handle.clone();
    owner.with(|ops| {
        for cqe in driver.ring.completion() {
            driver.inner.handle_cqe(ops, cqe);
        }
        driver.inner.advance_timeouts_at(
            ops,
            deadline
                .checked_add(Duration::from_millis(1))
                .expect("test deadline should be representable"),
        );
    });
    driver.inner.flush_wakers();

    assert_eq!(harness.pending(), 0);
    assert_eq!(harness.tracked(), 1);
    assert_eq!(harness.driver().inner.timeout_wheel.next_deadline(), None);
    let (mut buf, read) = match poll_once(&harness, &mut recv) {
        Poll::Ready(Ok(result)) => result,
        other => panic!("completion-first recv should succeed, got {other:?}"),
    };
    assert_eq!(read, 1);
    // SAFETY: the kernel filled `read` bytes before completion.
    unsafe { buf.set_len(read) };
    assert_eq!(buf.as_ref(), &[7]);
    assert_eq!(harness.pending(), 0);
    assert_eq!(harness.tracked(), 0);
    assert_recv_capacity_reused(&mut harness);
}

#[test]
fn test_timeout_expiry_before_completion_wins() {
    // Advance synthetic wheel time first, then stage and retire the
    // cancellation before any successful original CQE can arrive. The
    // committed timeout must own the exact terminal result.
    let mut harness = TestLoop::new(RingConfig {
        size: 1,
        timeout_wheel_tick: Duration::from_millis(1),
        ..Default::default()
    });
    let handle = harness.handle.clone();
    let (left, _right) = UnixStream::pair().unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut recv = Box::pin(handle.recv(
        Arc::new(left.into()),
        IoBufMut::with_capacity(1),
        0,
        1,
        false,
        deadline,
    ));
    assert!(poll_once(&harness, &mut recv).is_pending());
    harness.driver().turn();

    let driver = harness.driver();
    let owner = driver.inner.handle.clone();
    owner.with(|ops| {
        driver.inner.advance_timeouts_at(
            ops,
            deadline
                .checked_add(Duration::from_millis(1))
                .expect("test deadline should be representable"),
        );
        assert_eq!(ops.pending_cancels.len(), 1);
        assert_eq!(ops.waiters.pending(), 1);
    });
    assert_eq!(driver.inner.timeout_wheel.next_deadline(), None);

    match harness.block_on(recv) {
        Err((_, Error::Timeout)) => {}
        other => panic!("timeout-first recv should time out, got {other:?}"),
    }
    assert_eq!(harness.pending(), 0);
    assert_eq!(harness.tracked(), 0);

    assert_eq!(harness.driver().inner.timeout_wheel.next_deadline(), None);
    harness
        .handle
        .with(|ops| assert!(ops.pending_cancels.is_empty()));
    assert_recv_capacity_reused(&mut harness);
}

#[test]
fn test_backlogged_request_expires_before_first_staging_without_sqe() {
    let mut harness = TestLoop::new(RingConfig {
        timeout_wheel_tick: Duration::from_millis(1),
        ..Default::default()
    });
    let handle = harness.handle.clone();
    let (left, _right) = UnixStream::pair().unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut recv = Box::pin(handle.recv(
        Arc::new(left.into()),
        IoBufMut::with_capacity(1),
        0,
        1,
        false,
        deadline,
    ));
    assert!(poll_once(&harness, &mut recv).is_pending());
    harness.handle.with(|ops| {
        assert_eq!(ops.backlog.len(), 1);
        assert_eq!(ops.waiters.pending(), 1);
    });

    // Advance the idle wheel beyond the admitted deadline before the
    // backlog receives its first staging pass. Staging must commit the
    // timeout locally and leave the submission queue untouched.
    let expired_at = deadline
        .checked_add(Duration::from_millis(1))
        .expect("test deadline should be representable");
    let driver_state = harness.handle.clone();
    let driver = harness.driver();
    assert!(
        !driver
            .inner
            .timeout_wheel
            .advance_into(expired_at, &mut driver.inner.expired_timeouts)
    );
    driver_state.with(|ops| {
        let mut submission_queue = driver.ring.submission();
        assert!(submission_queue.is_empty());
        assert!(!driver.inner.stage_backlog(ops, &mut submission_queue));
        assert!(submission_queue.is_empty());
        assert!(ops.backlog.is_empty());
        assert!(ops.pending_cancels.is_empty());
        assert_eq!(ops.waiters.len(), 1);
        assert_eq!(ops.waiters.pending(), 0);
    });
    assert_eq!(driver.inner.timeout_wheel.next_deadline(), None);
    driver.inner.flush_wakers();

    assert!(matches!(
        poll_once(&harness, &mut recv),
        Poll::Ready(Err((_, Error::Timeout)))
    ));
    assert_eq!(harness.tracked(), 0);
}

#[test]
fn test_exact_recv_partial_then_timeout() {
    // An exact recv that made partial progress (requeued) must resolve
    // with timeout at its deadline and return the buffer.
    let mut harness = TestLoop::new(RingConfig {
        timeout_wheel_tick: Duration::from_millis(5),
        ..Default::default()
    });
    let (left, right) = UnixStream::pair().unwrap();
    (&right).write_all(&[1, 2]).unwrap();

    let handle = harness.handle.clone();
    let recv = Box::pin(handle.recv(
        Arc::new(left.into()),
        IoBufMut::with_capacity(4),
        0,
        4,
        true,
        Instant::now() + Duration::from_millis(80),
    ));
    let start = Instant::now();
    match harness.block_on(recv) {
        Err((mut buf, Error::Timeout)) => {
            // The partial bytes were received before the deadline.
            // SAFETY: the kernel filled 2 bytes before the requeue.
            unsafe { buf.set_len(2) };
            assert_eq!(buf.as_ref(), &[1, 2]);
        }
        other => panic!("expected timeout after partial progress, got {other:?}"),
    }
    assert!(
        start.elapsed() >= Duration::from_millis(50),
        "timeout fired too early: {:?}",
        start.elapsed()
    );
    assert_eq!(harness.tracked(), 0);
}

#[test]
fn test_drop_after_timeout_before_cancel_resolves() {
    // Deadline expiry transitions the waiter to cancel-requested and
    // releases its wheel tick. Dropping the future in that window must
    // not double-release deadline accounting or leak the slot.
    let mut harness = TestLoop::new(RingConfig {
        timeout_wheel_tick: Duration::from_millis(5),
        ..Default::default()
    });
    let (left, _right) = UnixStream::pair().unwrap();

    let handle = harness.handle.clone();
    let mut recv = Box::pin(handle.recv(
        Arc::new(left.into()),
        IoBufMut::with_capacity(1),
        0,
        1,
        false,
        Instant::now() + Duration::from_millis(30),
    ));
    assert!(poll_once(&harness, &mut recv).is_pending());
    harness.driver().turn();
    assert_eq!(harness.pending(), 1);

    // Let the deadline elapse, then advance timeouts WITHOUT staging the
    // cancel SQE or reaping its CQE: the waiter is now cancel-requested
    // with its op still in flight.
    std::thread::sleep(Duration::from_millis(50));
    let driver = harness.driver();
    handle.with(|ops| driver.inner.advance_timeouts(ops));
    assert!(driver.inner.timeout_wheel.next_deadline().is_none());

    // Drop the future in the cancel-requested window.
    drop(recv);

    // The slot must wind down through the normal cancel path.
    let start = Instant::now();
    while harness.tracked() != 0 {
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "cancel-requested orphan still tracked after {:?}",
            start.elapsed()
        );
        harness.driver().turn();
        harness.driver().park(Some(Duration::from_millis(10)));
    }
    assert_eq!(harness.driver().inner.timeout_wheel.next_deadline(), None);
}

#[test]
fn test_required_ring_flags_construct() {
    // The runtime cannot operate without single-issuer and deferred
    // task-run mode, so every RingConfig must exercise both flags.
    let ring = new_ring(RingConfig::default().size).expect("required ring flags should construct");
    drop(ring);
}
