use super::*;
use crate::{
    Blob as _, IoBuf, IoBufMut, Listener as _, Metrics as _, Network as _, ReadOptions,
    Resolver as _, Runner as _, Sink as _, Spawner as _, Storage as _, Strategizer as _,
    Stream as _, Supervisor as _, WriteOptions,
};
use commonware_parallel::Strategy as _;
use commonware_utils::{NZUsize, channel::oneshot};
use futures::task::{ArcWake, waker};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc::{Receiver, SyncSender},
    },
    task::{RawWaker, RawWakerVTable},
};

#[test]
fn test_secondary_panic_payload_cannot_interrupt_teardown() {
    struct PanicOnDrop;

    impl Drop for PanicOnDrop {
        fn drop(&mut self) {
            panic!("secondary panic payload dropped");
        }
    }

    let mut first = Some(Box::new("first panic") as PanicPayload);
    retain_first_panic(&mut first, Box::new(PanicOnDrop));
    assert_eq!(
        first
            .as_ref()
            .and_then(|payload| payload.downcast_ref::<&str>()),
        Some(&"first panic")
    );
}

#[derive(Default)]
struct ReentrantWakerCounts {
    callbacks: AtomicUsize,
    clones: AtomicUsize,
    drops: AtomicUsize,
}

/// Raw-waker state whose callbacks reacquire both sleeper locks.
struct ReentrantWaker {
    executor: Weak<Executor>,
    alarm: Mutex<Option<Weak<Alarm>>>,
    counts: Arc<ReentrantWakerCounts>,
}

impl ReentrantWaker {
    fn assert_locks_available(&self) {
        let executor = self.executor.upgrade().expect("executor dropped");
        let alarm = self.alarm.lock().as_ref().and_then(Weak::upgrade);
        let _sleeping = executor
            .sleeping
            .try_lock()
            .expect("waker callback ran under the sleeping lock");
        if let Some(alarm) = alarm.as_ref() {
            let _slot = alarm
                .waker
                .try_lock()
                .expect("waker callback ran under the alarm lock");
        }
        self.counts.callbacks.fetch_add(1, Ordering::AcqRel);
    }
}

unsafe fn clone_reentrant_waker(data: *const ()) -> RawWaker {
    let state = {
        // SAFETY: every raw waker using this vtable stores the pointer
        // returned by Arc::into_raw for ReentrantWaker.
        unsafe { &*data.cast::<ReentrantWaker>() }
    };
    state.assert_locks_available();
    state.counts.clones.fetch_add(1, Ordering::AcqRel);
    // SAFETY: the raw waker owns one strong reference, and cloning it
    // creates one additional reference for the returned raw waker.
    unsafe { Arc::increment_strong_count(data.cast::<ReentrantWaker>()) };
    RawWaker::new(data, &REENTRANT_WAKER_VTABLE)
}

unsafe fn wake_reentrant_waker(data: *const ()) {
    let state = {
        // SAFETY: wake consumes the raw waker's one strong reference.
        unsafe { Arc::from_raw(data.cast::<ReentrantWaker>()) }
    };
    state.assert_locks_available();
}

unsafe fn wake_reentrant_waker_by_ref(data: *const ()) {
    let state = {
        // SAFETY: wake_by_ref borrows the strong reference held by the
        // raw waker for the duration of this callback.
        unsafe { &*data.cast::<ReentrantWaker>() }
    };
    state.assert_locks_available();
}

unsafe fn drop_reentrant_waker(data: *const ()) {
    let state = {
        // SAFETY: drop consumes the raw waker's one strong reference.
        unsafe { Arc::from_raw(data.cast::<ReentrantWaker>()) }
    };
    state.assert_locks_available();
    state.counts.drops.fetch_add(1, Ordering::AcqRel);
}

static REENTRANT_WAKER_VTABLE: RawWakerVTable = RawWakerVTable::new(
    clone_reentrant_waker,
    wake_reentrant_waker,
    wake_reentrant_waker_by_ref,
    drop_reentrant_waker,
);

fn reentrant_waker(
    executor: &Arc<Executor>,
) -> (Waker, Arc<ReentrantWaker>, Arc<ReentrantWakerCounts>) {
    let counts = Arc::new(ReentrantWakerCounts::default());
    let state = Arc::new(ReentrantWaker {
        executor: Arc::downgrade(executor),
        alarm: Mutex::new(None),
        counts: Arc::clone(&counts),
    });
    let raw = RawWaker::new(
        Arc::into_raw(Arc::clone(&state)).cast(),
        &REENTRANT_WAKER_VTABLE,
    );
    let waker = {
        // SAFETY: raw owns one Arc strong reference and its vtable
        // preserves that ownership contract across clone, wake, and drop.
        unsafe { Waker::from_raw(raw) }
    };
    (waker, state, counts)
}

/// Property: network timeouts at exactly the 30-year policy bound pass
/// validation. Setup: both timeouts set to [MAX_TIMER_DURATION]. Action:
/// drive the private validator directly so no ring is constructed.
/// Expected: validation returns without panicking.
#[test]
fn test_config_accepts_maximum_network_timeouts() {
    Config::default()
        .with_ring(RingConfig {
            timeout_wheel_tick: Duration::from_secs(60 * 60),
            ..RingConfig::default()
        })
        .with_connect_timeout(MAX_TIMER_DURATION)
        .with_read_write_timeout(MAX_TIMER_DURATION)
        .validate();
}

#[test]
fn test_config_accepts_exact_timeout_wheel_slot_cap() {
    // At a 5 ms tick, this horizon needs 1,048,575 ticks plus one guard
    // tick, exactly the 1,048,576-slot wheel cap.
    let horizon = Duration::from_millis(5_242_875);
    Config::default()
        .with_connect_timeout(horizon)
        .with_read_write_timeout(horizon)
        .validate();
}

#[test]
#[should_panic(
    expected = "timeout wheel requires 2097152 slots, maximum is 1048576. Reduce network timeouts or increase timeout_wheel_tick"
)]
fn test_config_rejects_first_timeout_wheel_horizon_above_cap() {
    let horizon = Duration::from_millis(5_242_875) + Duration::from_nanos(1);
    Config::default()
        .with_connect_timeout(horizon)
        .with_read_write_timeout(horizon)
        .validate();
}

#[test]
fn test_runner_rejects_timeout_wheel_before_startup_side_effects() {
    // `/dev/null/child` would fail the startup sync with ENOTDIR if
    // validation did not run before registry, pool, syncfs, and ring setup.
    let horizon = Duration::from_millis(5_242_875) + Duration::from_nanos(1);
    let cfg = Config::default()
        .with_storage_directory("/dev/null/child")
        .with_connect_timeout(horizon)
        .with_read_write_timeout(horizon);
    let panic = catch_unwind(AssertUnwindSafe(|| {
        Runner::new(cfg).start(|_| async {
            panic!("root future must not be constructed");
        });
    }))
    .expect_err("invalid wheel layout must panic before startup");
    let message = panic
        .downcast_ref::<String>()
        .expect("wheel cap panic should carry a formatted message");
    assert_eq!(
        message,
        "timeout wheel requires 2097152 slots, maximum is 1048576. \
         Reduce network timeouts or increase timeout_wheel_tick"
    );
}

#[test]
#[should_panic(expected = "connect_timeout must be non-zero")]
fn test_config_rejects_zero_connect_timeout() {
    Config::default()
        .with_connect_timeout(Duration::ZERO)
        .validate();
}

#[test]
#[should_panic(expected = "read_write_timeout must be non-zero")]
fn test_config_rejects_zero_read_write_timeout() {
    Config::default()
        .with_read_write_timeout(Duration::ZERO)
        .validate();
}

/// Property: a connect timeout above the 30-year policy bound is rejected
/// at validation. Setup: connect timeout one nanosecond past the bound.
/// Action: drive the private validator directly so no ring is
/// constructed. Expected: panic with the documented message.
#[test]
#[should_panic(expected = "connect_timeout must be at most 30 years")]
fn test_config_rejects_excessive_connect_timeout() {
    Config::default()
        .with_connect_timeout(MAX_TIMER_DURATION + Duration::from_nanos(1))
        .validate();
}

/// Property: a read/write timeout above the 30-year policy bound is
/// rejected at validation. Setup: read/write timeout one nanosecond past
/// the bound. Action: drive the private validator directly so no ring is
/// constructed. Expected: panic with the documented message.
#[test]
#[should_panic(expected = "read_write_timeout must be at most 30 years")]
fn test_config_rejects_excessive_read_write_timeout() {
    Config::default()
        .with_read_write_timeout(MAX_TIMER_DURATION + Duration::from_nanos(1))
        .validate();
}

/// Property: every public Config builder round-trips through its getter
/// (including the new connect_timeout getter and the buffer-pool
/// configs), so builder regressions are immediately diagnosable.
/// Setup: set every builder to a nondefault value. Action: read every
/// getter. Expected: each returns the value that was set, with no
/// runtime constructed.
#[test]
fn test_config_builder_getter_round_trip() {
    let ring = RingConfig {
        size: 64,
        ..RingConfig::default()
    };
    let network_pool = BufferPoolConfig::for_network().with_pool_min_size(111);
    let storage_pool = BufferPoolConfig::for_storage().with_pool_min_size(222);
    let cfg = Config::default()
        .with_ring(ring)
        .with_catch_panics(true)
        .with_storage_directory("/tmp/iouring-config-round-trip")
        .with_thread_stack_size(1 << 21)
        .with_connect_timeout(Duration::from_secs(7))
        .with_read_write_timeout(Duration::from_secs(33))
        .with_tcp_nodelay(None)
        .with_zero_linger(false)
        .with_read_buffer_size(4096)
        .with_network_buffer_pool_config(network_pool)
        .with_storage_buffer_pool_config(storage_pool);

    assert_eq!(cfg.ring().size, 64);
    assert!(cfg.catch_panics());
    assert_eq!(
        cfg.storage_directory(),
        &PathBuf::from("/tmp/iouring-config-round-trip")
    );
    assert_eq!(cfg.thread_stack_size(), 1 << 21);
    assert_eq!(cfg.connect_timeout(), Duration::from_secs(7));
    assert_eq!(cfg.read_write_timeout(), Duration::from_secs(33));
    assert_eq!(cfg.tcp_nodelay(), None);
    assert!(!cfg.zero_linger());
    assert_eq!(cfg.read_buffer_size(), 4096);
    assert_eq!(cfg.network_buffer_pool_cfg.pool_min_size(), 111);
    assert_eq!(cfg.storage_buffer_pool_cfg.pool_min_size(), 222);
}

/// Root readiness is serviced once after one spawned-task batch. If the
/// root completes at that boundary, tasks beyond the batch stay unpolled
/// and teardown drops every child future exactly once.
#[test]
fn test_root_completion_tears_down_at_ready_batch_boundary() {
    struct PendingProbe {
        polls: Arc<AtomicUsize>,
        drops: Arc<AtomicUsize>,
    }

    impl Future for PendingProbe {
        type Output = ();

        fn poll(self: Pin<&mut Self>, _: &mut std_task::Context<'_>) -> Poll<()> {
            self.polls.fetch_add(1, Ordering::AcqRel);
            Poll::Pending
        }
    }

    impl Drop for PendingProbe {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::AcqRel);
        }
    }

    let polls = Arc::new(AtomicUsize::new(0));
    let drops = Arc::new(AtomicUsize::new(0));
    let observed_polls = Arc::clone(&polls);
    let observed_drops = Arc::clone(&drops);

    Runner::default().start(move |context| async move {
        let mut handles = Vec::new();
        for _ in 0..=READY_TASKS_PER_TURN {
            let polls = Arc::clone(&polls);
            let drops = Arc::clone(&drops);
            handles.push(
                context
                    .child("pending")
                    .spawn(move |_| PendingProbe { polls, drops }),
            );
        }

        let mut yielded = false;
        std::future::poll_fn(move |cx| {
            if yielded {
                Poll::Ready(())
            } else {
                yielded = true;
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        })
        .await;

        drop(handles);
    });

    assert_eq!(
        observed_polls.load(Ordering::Acquire),
        READY_TASKS_PER_TURN,
        "only one ready batch may run before the root completes"
    );
    assert_eq!(
        observed_drops.load(Ordering::Acquire),
        READY_TASKS_PER_TURN + 1,
        "teardown must drop both polled and queued child futures"
    );
}

/// A lone self-waker refills unused capacity in the current task turn.
/// A due internal alarm records the first event-service boundary, which
/// must occur only after the task consumes four of the 64 token slots.
#[test]
fn test_in_turn_refill_polls_self_waker_before_event_service() {
    struct ServiceWake {
        /// Whether sleeper delivery invoked this waker.
        delivered: Arc<AtomicBool>,
        /// Resolves the root after the service boundary.
        sender: Mutex<Option<oneshot::Sender<()>>>,
    }

    impl ArcWake for ServiceWake {
        fn wake_by_ref(arc_self: &Arc<Self>) {
            arc_self.delivered.store(true, Ordering::Release);
            if let Some(sender) = arc_self.sender.lock().take() {
                let _ = sender.send(());
            }
        }
    }

    struct RefillProbe {
        /// Worker whose sleeper queue marks the service boundary.
        executor: Arc<Executor>,
        /// Waker installed in the due alarm on the first poll.
        service_waker: Option<Waker>,
        /// Whether the worker serviced the due alarm.
        delivered: Arc<AtomicBool>,
        /// Total task polls observed.
        polls: Arc<AtomicUsize>,
    }

    impl Future for RefillProbe {
        type Output = ();

        fn poll(mut self: Pin<&mut Self>, cx: &mut std_task::Context<'_>) -> Poll<()> {
            let poll = self.polls.fetch_add(1, Ordering::AcqRel) + 1;
            assert!(
                !self.delivered.load(Ordering::Acquire),
                "event service ran before in-turn refill poll {poll}"
            );
            if poll == 1 {
                let alarm = Arc::new(Alarm {
                    time: Instant::now(),
                    waker: Mutex::new(self.service_waker.take()),
                });
                self.executor.register_alarm(alarm);
            }
            if poll == 4 {
                return Poll::Ready(());
            }
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }

    let delivered = Arc::new(AtomicBool::new(false));
    let polls = Arc::new(AtomicUsize::new(0));
    let observed_delivered = Arc::clone(&delivered);
    let observed_polls = Arc::clone(&polls);

    Runner::default().start(move |context| async move {
        let (send, recv) = oneshot::channel();
        let service_waker = waker(Arc::new(ServiceWake {
            delivered: Arc::clone(&delivered),
            sender: Mutex::new(Some(send)),
        }));
        let executor = context.executor.upgrade().unwrap();
        let child_delivered = Arc::clone(&delivered);
        let child_polls = Arc::clone(&polls);
        context
            .child("refill")
            .spawn(move |_| RefillProbe {
                executor,
                service_waker: Some(service_waker),
                delivered: child_delivered,
                polls: child_polls,
            })
            .await
            .unwrap();

        assert_eq!(polls.load(Ordering::Acquire), 4);
        assert!(!delivered.load(Ordering::Acquire));
        recv.await.unwrap();
        assert!(delivered.load(Ordering::Acquire));
    });

    assert_eq!(observed_polls.load(Ordering::Acquire), 4);
    assert!(observed_delivered.load(Ordering::Acquire));
}

/// An ordinary spawned sleeper that has returned Pending consumes its
/// timer wake before the old normal backlog drains. More than four batches
/// of self-waking children keep the normal lane saturated, and the first
/// child blocks long enough to make the sleeper due during that batch.
#[test]
fn test_spawned_sleep_event_precedes_old_ready_backlog() {
    struct Saturating {
        first: bool,
        blocked: bool,
        polls: Arc<AtomicUsize>,
        stop: Arc<AtomicBool>,
    }

    impl Future for Saturating {
        type Output = ();

        fn poll(mut self: Pin<&mut Self>, cx: &mut std_task::Context<'_>) -> Poll<()> {
            let poll = self.polls.fetch_add(1, Ordering::AcqRel) + 1;
            assert!(
                poll <= READY_TASKS_PER_TURN * 8,
                "spawned sleeper was not serviced under ready saturation"
            );
            if self.first && !self.blocked {
                self.blocked = true;
                std::thread::sleep(Duration::from_millis(10));
            }
            if self.stop.load(Ordering::Acquire) {
                return Poll::Ready(());
            }
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }

    let polls = Arc::new(AtomicUsize::new(0));
    let pending_seen = Arc::new(AtomicBool::new(false));
    let resumed_at = Arc::new(AtomicUsize::new(usize::MAX));
    let stop = Arc::new(AtomicBool::new(false));

    Runner::default().start(move |context| async move {
        let sleeper_polls = Arc::clone(&polls);
        let sleeper_pending_seen = Arc::clone(&pending_seen);
        let sleeper_resumed_at = Arc::clone(&resumed_at);
        let sleeper = context.child("sleeper").spawn(move |context| async move {
            let mut sleep = Box::pin(context.sleep(Duration::from_millis(1)));
            let pending =
                std::future::poll_fn(|cx| Poll::Ready(sleep.as_mut().poll(cx).is_pending())).await;
            assert!(pending, "spawned sleeper must first return Pending");
            sleeper_pending_seen.store(true, Ordering::Release);
            sleep.await;
            sleeper_resumed_at.store(sleeper_polls.load(Ordering::Acquire), Ordering::Release);
        });

        let mut handles = Vec::new();
        for i in 0..READY_TASKS_PER_TURN * 4 {
            let polls = Arc::clone(&polls);
            let stop = Arc::clone(&stop);
            handles.push(context.child("saturating").spawn(move |_| Saturating {
                first: i == 0,
                blocked: false,
                polls,
                stop,
            }));
        }

        sleeper.await.unwrap();
        let at_timer = resumed_at.load(Ordering::Acquire);
        assert!(pending_seen.load(Ordering::Acquire));
        assert!(
            at_timer < READY_TASKS_PER_TURN * 4,
            "spawned sleeper resumed after the old backlog drained at {at_timer} child polls"
        );
        assert!(
            at_timer < READY_TASKS_PER_TURN,
            "event-ready sleeper did not lead the next batch at {at_timer} child polls"
        );

        stop.store(true, Ordering::Release);
        for handle in handles {
            handle.await.unwrap();
        }
    });
}

/// An ordinary spawned accept consumer is polled immediately after the
/// driver observes its CQE, before the old normal backlog drains. A proxy
/// waker records driver observation separately from the consumer poll.
#[test]
fn test_spawned_accept_event_precedes_old_ready_backlog() {
    struct CompletionWake {
        task: Waker,
        polls: Arc<AtomicUsize>,
        observed_at: Arc<AtomicUsize>,
    }

    impl ArcWake for CompletionWake {
        fn wake_by_ref(arc_self: &Arc<Self>) {
            let polls = arc_self.polls.load(Ordering::Acquire);
            let _ = arc_self.observed_at.compare_exchange(
                usize::MAX,
                polls,
                Ordering::AcqRel,
                Ordering::Acquire,
            );
            arc_self.task.wake_by_ref();
        }
    }

    struct Saturating {
        connection_gate: Option<(SyncSender<()>, Receiver<()>)>,
        polls: Arc<AtomicUsize>,
        stop: Arc<AtomicBool>,
    }

    impl Future for Saturating {
        type Output = ();

        fn poll(mut self: Pin<&mut Self>, cx: &mut std_task::Context<'_>) -> Poll<()> {
            self.polls.fetch_add(1, Ordering::AcqRel);
            if let Some((start, connected)) = self.connection_gate.take() {
                start.send(()).expect("connector thread exited");
                connected
                    .recv_timeout(Duration::from_secs(10))
                    .expect("connector did not establish loopback connection");
            }
            if self.stop.load(Ordering::Acquire) {
                return Poll::Ready(());
            }
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }

    let polls = Arc::new(AtomicUsize::new(0));
    let completion_at = Arc::new(AtomicUsize::new(usize::MAX));
    let consumer_at = Arc::new(AtomicUsize::new(usize::MAX));
    let pending_seen = Arc::new(AtomicBool::new(false));
    let stop = Arc::new(AtomicBool::new(false));

    Runner::default().start(move |context| async move {
        let mut listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();

        let (start_send, start_recv) = std::sync::mpsc::sync_channel(0);
        let (connected_send, connected_recv) = std::sync::mpsc::sync_channel(0);
        let connector = std::thread::spawn(move || {
            start_recv.recv().expect("saturating child exited");
            let client = TcpStream::connect(addr).expect("connect loopback listener");
            connected_send
                .send(())
                .expect("saturating child exited before connection acknowledgment");
            client
        });

        // The guard only bounds a scheduler regression. The poll-count
        // assertions below are the fairness oracle.
        let (guard_cancel_send, guard_cancel_recv) = std::sync::mpsc::channel();
        let guard_stop = Arc::clone(&stop);
        let guard = std::thread::spawn(move || {
            if guard_cancel_recv
                .recv_timeout(Duration::from_secs(10))
                .is_err()
            {
                guard_stop.store(true, Ordering::Release);
            }
        });

        // Register the ordinary accept consumer before the old backlog.
        // Its first poll submits the accept and leaves its queued latch
        // clear before the first saturating child starts the connector.
        let accept_polls = Arc::clone(&polls);
        let accept_completion_at = Arc::clone(&completion_at);
        let accept_consumer_at = Arc::clone(&consumer_at);
        let accept_pending_seen = Arc::clone(&pending_seen);
        let accept_task = context.child("accept").spawn(move |_| async move {
            let mut accept = Box::pin(listener.accept());
            let accepted = std::future::poll_fn(|cx| {
                let proxy = waker(Arc::new(CompletionWake {
                    task: cx.waker().clone(),
                    polls: Arc::clone(&accept_polls),
                    observed_at: Arc::clone(&accept_completion_at),
                }));
                let mut proxy_cx = std_task::Context::from_waker(&proxy);
                let result = accept.as_mut().poll(&mut proxy_cx);
                match result {
                    Poll::Pending => {
                        accept_pending_seen.store(true, Ordering::Release);
                        Poll::Pending
                    }
                    Poll::Ready(result) => {
                        accept_consumer_at
                            .store(accept_polls.load(Ordering::Acquire), Ordering::Release);
                        Poll::Ready(result)
                    }
                }
            })
            .await;
            drop(accept);
            drop(listener);
            accepted
        });

        let mut connection_gate = Some((start_send, connected_recv));
        let mut handles = Vec::new();
        for _ in 0..READY_TASKS_PER_TURN * 4 {
            let connection_gate = connection_gate.take();
            let polls = Arc::clone(&polls);
            let stop = Arc::clone(&stop);
            handles.push(context.child("saturating").spawn(move |_| Saturating {
                connection_gate,
                polls,
                stop,
            }));
        }

        // The first saturating child waits for the foreign connector,
        // guaranteeing the connection is queued before this batch ends.
        let accepted = accept_task.await.unwrap();

        stop.store(true, Ordering::Release);
        let _ = guard_cancel_send.send(());
        guard.join().expect("hang guard panicked");
        for handle in handles {
            handle.await.unwrap();
        }

        let client = connector.join().expect("connector thread panicked");
        let (_, sink, stream) = accepted.unwrap();
        drop(stream);
        drop(sink);
        drop(client);

        let driver_at = completion_at.load(Ordering::Acquire);
        let consumed_at = consumer_at.load(Ordering::Acquire);
        assert!(pending_seen.load(Ordering::Acquire));
        assert!(
            driver_at < READY_TASKS_PER_TURN * 4,
            "driver observed the accept CQE after {driver_at} child polls"
        );
        assert_eq!(
            consumed_at, driver_at,
            "accept consumer polled at {consumed_at}, driver observed its CQE at {driver_at}"
        );
    });
}

/// A dedicated task runs on its own worker with its own ring: storage
/// and network operations issued from it must work end to end, including
/// against a listener owned by another worker.
#[test]
fn test_dedicated_worker_io() {
    Runner::default().start(|context| async move {
        // Bind a listener on the root worker.
        let mut listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();

        // The dedicated task writes durable storage through its own ring
        // and dials the root worker's listener over real TCP.
        let dedicated = context
            .child("dedicated")
            .dedicated()
            .spawn(move |context| async move {
                let (blob, len) = context.open("partition", b"blob").await.unwrap();
                assert_eq!(len, 0);
                blob.write_at(0, IoBuf::from(b"hello"), WriteOptions::default())
                    .await
                    .unwrap();
                blob.sync().await.unwrap();
                let read = blob.read_at(0, 5, ReadOptions::default()).await.unwrap();
                assert_eq!(read.coalesce(), b"hello");

                let (mut sink, mut stream) = context.dial(addr).await.unwrap();
                sink.send(IoBuf::from(b"ping")).await.unwrap();
                let response = stream.recv(4).await.unwrap();
                assert_eq!(response.coalesce(), b"pong");
            });

        // Serve the dedicated task's connection from the root worker.
        let (_, mut sink, mut stream) = listener.accept().await.unwrap();
        let msg = stream.recv(4).await.unwrap();
        assert_eq!(msg.coalesce(), b"ping");
        sink.send(IoBuf::from(b"pong")).await.unwrap();

        dedicated.await.unwrap();
    });
}

/// Aborting a dedicated task tears its worker down promptly, and the
/// runtime joins the worker thread at teardown.
#[test]
fn test_dedicated_worker_abort() {
    let start = std::time::Instant::now();
    Runner::default().start(|context| async move {
        let handle = context
            .child("dedicated")
            .dedicated()
            .spawn(|context| async move {
                loop {
                    context.sleep(Duration::from_millis(10)).await;
                }
            });
        context.sleep(Duration::from_millis(50)).await;
        handle.abort();
        assert!(matches!(handle.await, Err(Error::Closed)));
    });
    assert!(
        start.elapsed() < Duration::from_secs(10),
        "worker teardown took {:?}",
        start.elapsed()
    );
}

/// Until a shared blocking pool lands, blocking shared tasks alias
/// dedicated ones: std-blocking work must not starve the root executor.
#[test]
fn test_spawn_blocking_runs_off_thread() {
    Runner::default().start(|context| async move {
        let blocking = context
            .child("blocking")
            .shared(true)
            .spawn(|_| async move {
                std::thread::sleep(Duration::from_millis(200));
                42
            });

        // The root worker keeps making progress while the blocking task
        // holds its own thread.
        let start = std::time::Instant::now();
        context.sleep(Duration::from_millis(20)).await;
        assert!(start.elapsed() < Duration::from_millis(150));

        assert_eq!(blocking.await.unwrap(), 42);
    });
}

/// A panic while constructing the root future must still close the root
/// worker's driver before the panic leaves `start`.
#[test]
fn test_root_closure_panic_closes_driver() {
    let cfg = Config::default();
    let storage_directory = cfg.storage_directory().clone();
    let escaped = Arc::new(Mutex::new(None));
    let capture = Arc::clone(&escaped);

    let result = catch_unwind(AssertUnwindSafe(|| {
        Runner::new(cfg).start(move |context| -> std::future::Ready<()> {
            *capture.lock() = Some(context);
            panic!("root closure panic");
        });
    }));
    assert!(result.is_err(), "root closure should panic");

    let context = escaped.lock().take().expect("context should escape");
    let (blob, _) = futures::executor::block_on(context.open("partition", b"blob")).unwrap();
    let waker = futures::task::noop_waker();
    let mut cx = std_task::Context::from_waker(&waker);
    let mut read = Box::pin(blob.read_at(0, 1, ReadOptions::default()));
    assert!(
        matches!(
            read.as_mut().poll(&mut cx),
            Poll::Ready(Err(Error::ReadFailed))
        ),
        "escaped driver accepted work after root cleanup"
    );

    drop(read);
    drop(blob);
    drop(context);
    let _ = std::fs::remove_dir_all(storage_directory);
}

/// Context-backed resource constructors retain their origin worker's
/// ring. Moving a context to another worker must reject construction
/// before creating storage or observing a bind result.
#[test]
fn test_resource_construction_with_moved_context_panics_before_side_effects() {
    let cfg = Config::default().with_catch_panics(true);
    let storage_directory = cfg.storage_directory().clone();
    let test_storage_directory = storage_directory.clone();

    Runner::new(cfg).start(|context| async move {
        let storage_context = context.child("foreign_storage_context");
        let storage =
            context
                .child("foreign_storage_worker")
                .dedicated()
                .spawn(move |_| async move {
                    let _ = storage_context.open("partition", b"blob").await;
                });
        assert!(matches!(storage.await, Err(Error::Exited)));
        assert!(
            !test_storage_directory.exists(),
            "foreign open created the storage directory"
        );

        let occupied = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let occupied_addr = occupied.local_addr().unwrap();
        let network_context = context.child("foreign_network_context");
        let network =
            context
                .child("foreign_network_worker")
                .dedicated()
                .spawn(move |_| async move {
                    let _ = network_context.bind(occupied_addr).await;
                });
        assert!(
            matches!(network.await, Err(Error::Exited)),
            "foreign bind returned the kernel error before checking affinity"
        );
    });

    let _ = std::fs::remove_dir_all(storage_directory);
}

/// Cached listener and stream accessors are still worker-affine. A
/// foreign worker must not read a cached address or buffered bytes.
#[test]
fn test_cached_network_accessors_on_other_worker_panic() {
    let cfg = Config::default().with_catch_panics(true);
    Runner::new(cfg).start(|context| async move {
        let listener = context
            .bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .unwrap();
        let local_addr =
            context
                .child("foreign_local_addr")
                .dedicated()
                .spawn(move |_| async move {
                    let _ = listener.local_addr();
                });
        assert!(
            matches!(local_addr.await, Err(Error::Exited)),
            "foreign local_addr returned cached data"
        );

        let mut listener = context
            .bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let (mut client_sink, _client_stream) = context.dial(addr).await.unwrap();
        let (_, _server_sink, mut server_stream) = listener.accept().await.unwrap();

        client_sink.send(IoBuf::from(b"buffered")).await.unwrap();
        let first = server_stream.recv(1).await.unwrap();
        assert_eq!(first.coalesce(), b"b");
        assert_eq!(server_stream.peek(7), b"uffered");

        let peek = context
            .child("foreign_buffered_peek")
            .dedicated()
            .spawn(move |_| async move {
                let _ = server_stream.peek(7);
            });
        assert!(
            matches!(peek.await, Err(Error::Exited)),
            "foreign peek returned buffered data"
        );
    });
}

/// Using a ring-bound resource from another worker fails loudly with the
/// documented affinity panic (the task fails, the runtime survives): the
/// io_uring runtime deliberately does not provide the tokio backend's
/// location transparency for blobs, sockets, and listeners.
#[test]
fn test_blob_use_on_other_worker_panics() {
    #[derive(Clone, Copy, Debug)]
    enum Operation {
        Resize,
        Read,
        ReadBufferEmpty,
        ReadBufferOverflow,
        WriteEmpty,
        WriteOverflow,
    }

    let cases = [
        ("resize", Operation::Resize),
        ("read", Operation::Read),
        ("read_buffer_empty", Operation::ReadBufferEmpty),
        ("read_buffer_overflow", Operation::ReadBufferOverflow),
        ("write_empty", Operation::WriteEmpty),
        ("write_overflow", Operation::WriteOverflow),
    ];

    let cfg = Config::default().with_catch_panics(true);
    Runner::new(cfg).start(|context| async move {
        let (blob, _) = context.open("partition", b"blob").await.unwrap();
        for (label, operation) in cases {
            let blob = blob.clone();
            let handle = context.child(label).dedicated().spawn(move |_| async move {
                match operation {
                    Operation::Resize => {
                        let _ = blob.resize(1).await;
                    }
                    Operation::Read => {
                        let _ = blob.read_at(0, 1, ReadOptions::default()).await;
                    }
                    Operation::ReadBufferEmpty => {
                        let _ = blob
                            .read_at_buf(0, 0, IoBufMut::with_capacity(1), ReadOptions::default())
                            .await;
                    }
                    Operation::ReadBufferOverflow => {
                        let _ = blob
                            .read_at_buf(
                                u64::MAX,
                                1,
                                IoBufMut::with_capacity(1),
                                ReadOptions::default(),
                            )
                            .await;
                    }
                    Operation::WriteEmpty => {
                        let _ = blob
                            .write_at(0, Vec::<u8>::new(), WriteOptions::default())
                            .await;
                    }
                    Operation::WriteOverflow => {
                        let _ = blob
                            .write_at(u64::MAX, b"x".to_vec(), WriteOptions::default())
                            .await;
                    }
                }
            });
            assert!(
                matches!(handle.await, Err(Error::Exited)),
                "{operation:?} should panic on another worker"
            );
        }
    });
}

/// A capacity waker panic during close must not skip the ring drain: the
/// accepted connection is parked by the drain and remains available
/// through the listener that escaped the root future.
#[test]
fn test_close_waker_panic_still_drains_ring() {
    struct PanicWake;

    impl std::task::Wake for PanicWake {
        fn wake(self: Arc<Self>) {
            panic!("capacity wake panic");
        }
    }

    let listener = Arc::new(Mutex::new(None));
    let escaped = Arc::clone(&listener);
    let (addr_send, addr_recv) = std::sync::mpsc::channel();
    let (connected_send, connected_recv) = std::sync::mpsc::channel();
    let connector = std::thread::spawn(move || {
        let addr = addr_recv.recv().unwrap();
        let connection = std::net::TcpStream::connect(addr).unwrap();
        connected_send.send(()).unwrap();
        connection
    });

    let cfg = Config::default().with_ring(RingConfig {
        size: 1,
        ..RingConfig::default()
    });
    let result = catch_unwind(AssertUnwindSafe(|| {
        Runner::new(cfg).start(|context| async move {
            // Occupy the only waiter slot with an accept whose ticket
            // survives in the escaped listener.
            let mut first = context
                .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
                .await
                .unwrap();
            let addr = first.local_addr().unwrap();
            let mut accept = Box::pin(first.accept());
            assert!(futures::poll!(accept.as_mut()).is_pending());
            drop(accept);
            *escaped.lock() = Some(first);

            // Park a capacity admission whose close wake panics.
            let mut blocked = context
                .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
                .await
                .unwrap();
            let waker = Waker::from(Arc::new(PanicWake));
            let mut cx = std_task::Context::from_waker(&waker);
            let mut accept = Box::pin(blocked.accept());
            assert!(accept.as_mut().poll(&mut cx).is_pending());
            std::mem::forget(accept);
            std::mem::forget(blocked);

            addr_send.send(addr).unwrap();
            connected_recv.recv().unwrap();
            std::thread::sleep(Duration::from_millis(100));
        })
    }));
    assert!(result.is_err(), "capacity waker should panic");
    let _connection = connector.join().unwrap();

    // The root returned before the first accept was submitted. Only the
    // shutdown drain can have completed its ticket.
    let mut listener = listener.lock().take().unwrap();
    let waker = futures::task::noop_waker();
    let mut cx = std_task::Context::from_waker(&waker);
    let mut accept = Box::pin(listener.accept());
    assert!(
        matches!(accept.as_mut().poll(&mut cx), Poll::Ready(Ok(_))),
        "close-time waker panic skipped the ring drain"
    );
}

/// With the default `catch_panics(false)`, the affinity panic is
/// forwarded to the root and unwinds `start` (the documented behavior).
#[test]
fn test_blob_use_on_other_worker_panics_uncaught() {
    let result = catch_unwind(AssertUnwindSafe(|| {
        Runner::default().start(|context| async move {
            let (blob, _) = context.open("partition", b"blob").await.unwrap();
            let handle = context
                .child("dedicated")
                .dedicated()
                .spawn(move |_| async move {
                    let _ = blob.read_at(0, 1, ReadOptions::default()).await;
                });
            let _ = handle.await;
        })
    }));
    assert!(result.is_err(), "affinity panic must unwind start");
}

/// Dropping a `start_sync` completion handle on another worker must not
/// leak the origin worker's waiter slot: the foreign drop routes through
/// the orphan mailbox and the loop frees the parked result.
#[test]
fn test_start_sync_handle_dropped_on_other_worker() {
    Runner::default().start(|context| async move {
        let (blob, _) = context.open("partition", b"blob").await.unwrap();
        blob.write_at(0, IoBuf::from(b"hello"), WriteOptions::default())
            .await
            .unwrap();
        let sync_handle = blob.start_sync().await;

        // Hand the completion handle to a dedicated task, which drops it
        // without awaiting.
        context
            .child("dedicated")
            .dedicated()
            .spawn(move |_| async move {
                drop(sync_handle);
            })
            .await
            .unwrap();

        // The mailbox wind-down frees the slot on a subsequent turn:
        // poll the runtime-wide gauge until it drains.
        let pending = |metrics: String| -> i64 {
            let line = metrics
                .lines()
                .find(|line| {
                    line.starts_with("runtime_iouring_pending_operations")
                        && !line.starts_with("runtime_iouring_pending_operations{")
                })
                .expect("pending_operations metric missing");
            line.split_whitespace().nth(1).unwrap().parse().unwrap()
        };
        let start = std::time::Instant::now();
        loop {
            if pending(context.encode()) == 0 {
                break;
            }
            assert!(
                start.elapsed() < Duration::from_secs(5),
                "waiter slot leaked by cross-worker handle drop"
            );
            context.sleep(Duration::from_millis(20)).await;
        }
    });
}

/// Worker threads of completed dedicated (or blocking shared) tasks must
/// not accumulate for the runtime's lifetime: an exited joinable thread
/// retains its stack mapping (and its `JoinHandle`) until joined, so a
/// long-lived runtime that periodically spawns blocking tasks would grow
/// without bound if completed workers were only reaped at shutdown.
#[test]
fn test_completed_workers_not_retained() {
    const SPAWNS: usize = 64;
    Runner::default().start(|context| async move {
        for _ in 0..SPAWNS {
            context
                .child("blocking")
                .shared(true)
                .spawn(|_| async move { 42 })
                .await
                .unwrap();
        }
        let executor = context.executor.upgrade().unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let all_finished = executor
                .shared
                .workers
                .lock()
                .as_ref()
                .unwrap()
                .iter()
                .all(std::thread::JoinHandle::is_finished);
            if all_finished {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "dedicated workers did not finish"
            );
            context.sleep(Duration::from_millis(1)).await;
        }

        // Registration reaps every previously finished worker first.
        let reaper = context
            .child("reaper")
            .shared(true)
            .spawn(|_| async move { 42 });
        let retained = executor.shared.workers.lock().as_ref().unwrap().len();
        assert!(
            retained <= 1,
            "{retained} exited worker threads retained until shutdown"
        );
        assert_eq!(reaper.await.unwrap(), 42);
    });
}

#[test]
fn test_child_drop_panic_propagates_after_teardown() {
    struct PanicOnDrop;

    impl Future for PanicOnDrop {
        type Output = ();

        fn poll(self: Pin<&mut Self>, _: &mut std_task::Context<'_>) -> Poll<()> {
            Poll::Pending
        }
    }

    impl Drop for PanicOnDrop {
        fn drop(&mut self) {
            panic!("child drop panic");
        }
    }

    let result = catch_unwind(AssertUnwindSafe(|| {
        Runner::default().start(|context| async move {
            let _handle = context.child("pending").spawn(|_| PanicOnDrop);
        })
    }));
    let payload = result.expect_err("child drop panic should fail start");
    let message = payload
        .downcast_ref::<&str>()
        .copied()
        .or_else(|| payload.downcast_ref::<String>().map(String::as_str));
    assert_eq!(message, Some("child drop panic"));
}

/// A task destructor panic must not strand a later task's submitted
/// operation. The later task must be cleared before the driver drains.
#[test]
fn test_child_drop_panic_clears_later_in_flight_task() {
    struct PanicOnDrop;

    impl Future for PanicOnDrop {
        type Output = ();

        fn poll(self: Pin<&mut Self>, _: &mut std_task::Context<'_>) -> Poll<()> {
            Poll::Pending
        }
    }

    impl Drop for PanicOnDrop {
        fn drop(&mut self) {
            panic!("first child drop panic");
        }
    }

    let result = catch_unwind(AssertUnwindSafe(|| {
        Runner::default().start(|context| async move {
            let mut listener = context
                .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
                .await
                .unwrap();
            let _first = context.child("first").spawn(|_| PanicOnDrop);
            let (started_send, started_recv) = oneshot::channel();
            let _second = context.child("second").spawn(move |_| async move {
                let mut accept = Box::pin(listener.accept());
                let mut started_send = Some(started_send);
                let _ = std::future::poll_fn(move |cx| {
                    let result = accept.as_mut().poll(cx);
                    if result.is_pending()
                        && let Some(send) = started_send.take()
                    {
                        let _ = send.send(());
                    }
                    result
                })
                .await;
            });

            started_recv.await.unwrap();
            context.sleep(Duration::from_millis(10)).await;
        })
    }));
    let payload = result.expect_err("first child drop panic should fail start");
    let message = payload
        .downcast_ref::<&str>()
        .copied()
        .or_else(|| payload.downcast_ref::<String>().map(String::as_str));
    assert_eq!(message, Some("first child drop panic"));
}

/// An alarm waker panic must not skip a pending child's cleanup or leave
/// its submitted operation attached while the driver drains.
#[test]
fn test_alarm_wake_panic_clears_pending_child() {
    struct PanicWake;

    struct SetOnDrop(Arc<AtomicBool>);

    impl std::task::Wake for PanicWake {
        fn wake(self: Arc<Self>) {
            panic!("alarm wake panic");
        }
    }

    impl Drop for SetOnDrop {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Release);
        }
    }

    let child_dropped = Arc::new(AtomicBool::new(false));
    let observed_child_drop = Arc::clone(&child_dropped);
    let result = catch_unwind(AssertUnwindSafe(|| {
        Runner::default().start(|context| async move {
            let executor = context.executor.upgrade().unwrap();
            let mut listener = context
                .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
                .await
                .unwrap();
            let (started_send, started_recv) = oneshot::channel();
            let _child = context.child("pending").spawn(move |_| async move {
                let _guard = SetOnDrop(observed_child_drop);
                let mut accept = Box::pin(listener.accept());
                let mut started_send = Some(started_send);
                let _ = std::future::poll_fn(move |cx| {
                    let result = accept.as_mut().poll(cx);
                    if result.is_pending()
                        && let Some(send) = started_send.take()
                    {
                        let _ = send.send(());
                    }
                    result
                })
                .await;
            });

            started_recv.await.unwrap();
            context.sleep(Duration::from_millis(10)).await;
            executor.register_alarm(Arc::new(Alarm {
                time: Instant::now() + Duration::from_secs(3600),
                waker: Mutex::new(Some(Waker::from(Arc::new(PanicWake)))),
            }));
        })
    }));
    let payload = result.expect_err("alarm wake panic should fail start");
    assert_eq!(
        payload.downcast_ref::<&str>().copied(),
        Some("alarm wake panic")
    );
    assert!(
        child_dropped.load(Ordering::Acquire),
        "alarm wake panic skipped pending child cleanup"
    );
}

/// A teardown panic must remain isolated from panic-capable drop glue on
/// the root's already-produced output.
#[test]
fn test_alarm_wake_panic_isolates_root_output_drop_panic() {
    struct PanicWake;

    #[derive(Debug)]
    struct PanicOutput;

    impl std::task::Wake for PanicWake {
        fn wake(self: Arc<Self>) {
            panic!("alarm wake panic");
        }
    }

    impl Drop for PanicOutput {
        fn drop(&mut self) {
            panic!("root output drop panic");
        }
    }

    let result = catch_unwind(AssertUnwindSafe(|| {
        Runner::default().start(|context| async move {
            let executor = context.executor.upgrade().unwrap();
            executor.register_alarm(Arc::new(Alarm {
                time: Instant::now() + Duration::from_secs(3600),
                waker: Mutex::new(Some(Waker::from(Arc::new(PanicWake)))),
            }));
            PanicOutput
        })
    }));
    let payload = result.expect_err("alarm wake panic should fail start");
    assert_eq!(
        payload.downcast_ref::<&str>().copied(),
        Some("alarm wake panic")
    );
}

/// A dedicated task's poll panic that races root completion must still
/// fail `start` (with the default `catch_panics(false)`): the root's
/// interrupt receiver is already gone, so the payload routes through the
/// worker-panic stash instead of vanishing while the worker exits
/// cleanly.
#[test]
fn test_dedicated_poll_panic_races_root_completion() {
    let (send, recv) = std::sync::mpsc::channel();
    let result = catch_unwind(AssertUnwindSafe(|| {
        Runner::default().start(|context| async move {
            let _handle = context
                .child("late")
                .dedicated()
                .spawn(move |_| async move {
                    send.send(()).unwrap();
                    std::thread::sleep(Duration::from_millis(300));
                    panic!("late worker panic");
                });
            // Return as soon as the task is mid-poll: the panic then
            // lands after this worker's root future (and its interrupt
            // receiver) is gone, while `start` waits in the join loop.
            recv.recv().unwrap();
        })
    }));
    let payload = result.expect_err("racing poll panic should fail start");
    let message = payload
        .downcast_ref::<&str>()
        .copied()
        .or_else(|| payload.downcast_ref::<String>().map(String::as_str));
    assert_eq!(message, Some("late worker panic"));
}

/// A default inline child on a dedicated worker can panic after the main
/// root's interrupt receiver closes. The join phase must retain that
/// undeliverable payload even though the dedicated worker exits normally.
#[test]
fn test_nested_inline_panic_after_root_receiver_closes() {
    const PAYLOAD: u64 = 0x5eed_cafe;

    let (shared_send, shared_recv) = std::sync::mpsc::channel();
    let (blocked_send, blocked_recv) = std::sync::mpsc::channel();
    let (returning_send, returning_recv) = std::sync::mpsc::channel();
    let (release_send, release_recv) = std::sync::mpsc::channel();

    let runtime = std::thread::spawn(move || {
        catch_unwind(AssertUnwindSafe(|| {
            Runner::default().start(|context| async move {
                let executor = context.executor.upgrade().unwrap();
                shared_send.send(Arc::clone(&executor.shared)).unwrap();

                let _handle =
                    context
                        .child("worker")
                        .dedicated()
                        .spawn(move |context| async move {
                            let _handle = context.child("nested").spawn(move |_| async move {
                                blocked_send.send(()).unwrap();
                                release_recv.recv().unwrap();
                                std::panic::panic_any(PAYLOAD);
                            });
                            futures::future::pending::<()>().await;
                        });

                blocked_recv.recv().unwrap();
                returning_send.send(()).unwrap();
            });
        }))
    });

    let shared = shared_recv.recv().unwrap();
    returning_recv.recv().unwrap();

    // Once the registry is closed, the main root has closed its panic
    // receiver and moved the dedicated worker into the final join batch.
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let joining = shared.workers.lock().is_none();
        if joining {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "runtime did not enter join phase"
        );
        std::thread::yield_now();
    }

    release_send.send(()).unwrap();
    let result = runtime.join().expect("runtime thread should join");
    let payload = result.expect_err("nested panic should unwind start");
    assert_eq!(payload.downcast_ref::<u64>(), Some(&PAYLOAD));
}

/// Registry closure linearizes racing dedicated spawns. Workers started
/// before closure are captured and joined, while a spawn after closure
/// resolves closed without invoking its body.
#[test]
fn test_worker_spawn_races_registry_close() {
    let anchor_release = Arc::new(std::sync::Barrier::new(2));
    let before_started = Arc::new(std::sync::Barrier::new(2));
    let before_release = Arc::new(std::sync::Barrier::new(2));
    let before_ran = Arc::new(AtomicBool::new(false));
    let after_ran = Arc::new(AtomicBool::new(false));
    let (shared_send, shared_recv) = std::sync::mpsc::channel();
    let (contexts_send, contexts_recv) = std::sync::mpsc::channel();
    let (return_send, return_recv) = std::sync::mpsc::channel();

    let anchor_release_worker = Arc::clone(&anchor_release);
    let runtime = std::thread::spawn(move || {
        Runner::default().start(move |context| async move {
            let executor = context.executor.upgrade().unwrap();
            shared_send.send(Arc::clone(&executor.shared)).unwrap();

            let _anchor = context
                .child("anchor")
                .dedicated()
                .spawn(move |context| async move {
                    // Fresh trees keep these contexts admissible after the
                    // runtime root aborts, allowing the registry state to
                    // decide each spawn in this targeted race test.
                    let mut before = context.child("before");
                    before.tree = Tree::root();
                    let mut after = context.child("after");
                    after.tree = Tree::root();
                    contexts_send.send((before, after)).unwrap();
                    anchor_release_worker.wait();
                });

            return_recv.recv().unwrap();
        });
    });

    let shared = shared_recv.recv().unwrap();
    let (before, after) = contexts_recv.recv().unwrap();

    let before_started_worker = Arc::clone(&before_started);
    let before_release_worker = Arc::clone(&before_release);
    let before_ran_worker = Arc::clone(&before_ran);
    let _before_handle = before.dedicated().spawn(move |_| async move {
        before_ran_worker.store(true, Ordering::Release);
        before_started_worker.wait();
        before_release_worker.wait();
    });
    before_started.wait();
    assert!(before_ran.load(Ordering::Acquire));

    // Let the root return while both registered workers remain blocked.
    // Observing `None` proves closure captured the complete pre-close
    // batch before attempting any join.
    return_send.send(()).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if shared.workers.lock().is_none() {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "runtime did not close worker registry"
        );
        std::thread::yield_now();
    }
    assert!(!runtime.is_finished(), "captured workers were not joined");

    let after_ran_worker = Arc::clone(&after_ran);
    let after_handle = after.dedicated().spawn(move |_| async move {
        after_ran_worker.store(true, Ordering::Release);
    });
    assert!(matches!(
        futures::executor::block_on(after_handle),
        Err(Error::Closed)
    ));
    assert!(!after_ran.load(Ordering::Acquire));

    before_release.wait();
    anchor_release.wait();
    runtime.join().expect("runtime thread should join");
}

/// A worker panic already observed by an opportunistic reap happened
/// before a later root panic and must remain the payload propagated by
/// `start` (earliest cause wins over its cascade).
#[test]
fn test_reaped_worker_panic_precedes_root_panic() {
    struct PanicOnDrop;

    impl Future for PanicOnDrop {
        type Output = ();

        fn poll(self: Pin<&mut Self>, _: &mut std_task::Context<'_>) -> Poll<()> {
            Poll::Ready(())
        }
    }

    impl Drop for PanicOnDrop {
        fn drop(&mut self) {
            panic!("worker panic");
        }
    }

    let result = catch_unwind(AssertUnwindSafe(|| {
        Runner::default().start(|context| async move {
            let executor = context.executor.upgrade().unwrap();
            let handle = context
                .child("panicking_worker")
                .dedicated()
                .spawn(|_| PanicOnDrop);
            assert!(matches!(handle.await, Err(Error::Closed)));

            // Wait until the worker has exited, then exercise the
            // opportunistic reaper so its payload is stashed before the
            // root panics.
            loop {
                let finished = executor
                    .shared
                    .workers
                    .lock()
                    .as_ref()
                    .unwrap()
                    .iter()
                    .any(std::thread::JoinHandle::is_finished);
                if finished {
                    break;
                }
                context.sleep(Duration::from_millis(10)).await;
            }
            executor.shared.reap_workers();
            assert!(executor.shared.worker_panic.lock().is_some());

            panic!("root panic");
        })
    }));

    let payload = result.expect_err("start should propagate the first panic");
    let message = payload
        .downcast_ref::<&str>()
        .copied()
        .or_else(|| payload.downcast_ref::<String>().map(String::as_str));
    assert_eq!(message, Some("worker panic"));
}

/// Completion of a dedicated task must abort the consumed context's node
/// before the handle resolves (as the inline path does): contexts derived
/// from it before the spawn cannot spawn afterwards.
#[test]
fn test_dedicated_completion_closes_parent() {
    Runner::default().start(|context| async move {
        let worker_context = context.child("worker");
        let saved = worker_context.child("saved");
        worker_context
            .dedicated()
            .spawn(|_| async {})
            .await
            .unwrap();
        let orphan = saved.spawn(|_| async {});
        assert!(matches!(orphan.await, Err(Error::Closed)));
    });
}

/// Aborting a dedicated task closes the consumed context's node as well.
#[test]
fn test_dedicated_abort_closes_parent() {
    Runner::default().start(|context| async move {
        let worker_context = context.child("worker");
        let saved = worker_context.child("saved");
        let handle = worker_context.dedicated().spawn(|context| async move {
            loop {
                context.sleep(Duration::from_secs(1)).await;
            }
        });
        context.sleep(Duration::from_millis(50)).await;
        handle.abort();
        assert!(matches!(handle.await, Err(Error::Closed)));
        let orphan = saved.spawn(|_| async {});
        assert!(matches!(orphan.await, Err(Error::Closed)));
    });
}

/// A handle resolution observed from another worker happens strictly
/// after the completed task's node closed: post-await spawns from saved
/// sibling contexts are rejected on any worker.
#[test]
fn test_inline_completion_closes_parent_across_workers() {
    Runner::default().start(|context| async move {
        let task_context = context.child("task");
        let saved = task_context.child("saved");
        let handle = task_context.spawn(|_| async {});
        let checker = context
            .child("checker")
            .dedicated()
            .spawn(move |_| async move {
                handle.await.unwrap();
                let orphan = saved.spawn(|_| async {});
                matches!(orphan.await, Err(Error::Closed))
            });
        assert!(checker.await.unwrap());
    });
}

/// A panic in the dedicated spawn closure itself (before it returns the
/// future) is task failure, matching the inline path: the handle
/// resolves with [Error::Exited] and the runtime survives.
#[test]
fn test_dedicated_closure_panic() {
    let cfg = Config::default().with_catch_panics(true);
    Runner::new(cfg).start(|context| async move {
        let handle = context
            .child("dedicated")
            .dedicated()
            .spawn(|_| -> std::future::Ready<()> { panic!("closure panic") });
        assert!(matches!(handle.await, Err(Error::Exited)));
    });
}

/// Worker threads are joined even when the root task's panic unwinds
/// `start`: the dedicated task must have been dropped by the time
/// `start` returns.
#[test]
fn test_root_panic_joins_workers() {
    struct SetOnDrop(Arc<AtomicBool>);
    impl Drop for SetOnDrop {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Release);
        }
    }

    let dropped = Arc::new(AtomicBool::new(false));
    let guard = SetOnDrop(Arc::clone(&dropped));
    let result = catch_unwind(AssertUnwindSafe(|| {
        Runner::default().start(|context| async move {
            let _handle = context
                .child("dedicated")
                .dedicated()
                .spawn(move |context| async move {
                    let _guard = guard;
                    loop {
                        context.sleep(Duration::from_secs(1)).await;
                    }
                });
            panic!("root panic");
        })
    }));
    assert!(result.is_err());
    assert!(
        dropped.load(Ordering::Acquire),
        "worker not joined before start returned"
    );
}

/// A task awaiting a sleep created from another worker's context must
/// fail loudly (not hang) when that worker tears down before the
/// deadline: the teardown wake makes the sleeper re-poll and observe the
/// closed alarm queue.
#[test]
fn test_foreign_sleep_fails_on_worker_teardown() {
    let cfg = Config::default().with_catch_panics(true);
    Runner::new(cfg).start(|context| async move {
        let (send, recv) = oneshot::channel();
        let origin = context
            .child("origin")
            .dedicated()
            .spawn(move |context| async move {
                let _ = send.send(context.child("clock"));
                // Stay alive long enough for the sleeper to register.
                context.sleep(Duration::from_millis(300)).await;
            });
        let clock = recv.await.unwrap();
        let sleeper = context.child("sleeper").spawn(move |_| async move {
            clock.sleep(Duration::from_secs(3600)).await;
        });
        origin.await.unwrap();
        assert!(matches!(sleeper.await, Err(Error::Exited)));
    });
}

/// Alarm refresh and cancellation must run RawWaker clone and drop
/// callbacks only after releasing both sleeper locks.
#[test]
fn test_sleep_waker_callbacks_run_outside_locks() {
    Runner::default().start(|context| async move {
        let executor = context.executor.upgrade().unwrap();
        let (old_waker, old_state, old_counts) = reentrant_waker(&executor);
        let alarm = Arc::new(Alarm {
            time: Instant::now() + Duration::from_secs(3600),
            waker: Mutex::new(Some(old_waker)),
        });
        *old_state.alarm.lock() = Some(Arc::downgrade(&alarm));
        executor.register_alarm(Arc::clone(&alarm));

        let (replacement, replacement_state, replacement_counts) = reentrant_waker(&executor);
        *replacement_state.alarm.lock() = Some(Arc::downgrade(&alarm));

        assert!(!executor.refresh_alarm(&alarm, &replacement));
        assert_eq!(old_counts.clones.load(Ordering::Acquire), 0);
        assert_eq!(old_counts.drops.load(Ordering::Acquire), 1);
        assert_eq!(old_counts.callbacks.load(Ordering::Acquire), 1);
        assert_eq!(replacement_counts.clones.load(Ordering::Acquire), 1);
        assert_eq!(replacement_counts.drops.load(Ordering::Acquire), 0);
        assert_eq!(replacement_counts.callbacks.load(Ordering::Acquire), 1);

        executor.cancel_alarm(&alarm);
        assert_eq!(replacement_counts.drops.load(Ordering::Acquire), 1);
        assert_eq!(replacement_counts.callbacks.load(Ordering::Acquire), 2);

        drop(replacement);
        assert_eq!(replacement_counts.drops.load(Ordering::Acquire), 2);
        assert_eq!(replacement_counts.callbacks.load(Ordering::Acquire), 3);
    });
}

/// Cancelling sleeps before their deadline (e.g. by losing a `select!`)
/// must not retain their alarms until the deadline elapses: cancellation
/// releases the waker immediately and compaction keeps the heap
/// proportional to live sleepers.
#[test]
fn test_sleep_cancel_releases_alarm() {
    Runner::default().start(|context| async move {
        let executor = context.executor.upgrade().unwrap();
        let alarms = |executor: &Arc<Executor>| {
            let guard = executor.sleeping.lock();
            let sleeping = guard.as_ref().unwrap();
            (sleeping.alarms.len(), sleeping.cancelled)
        };

        // The heap may hold unrelated live alarms (e.g. the process
        // metrics collector), but nothing else runs between these reads
        // (no awaits on this single-threaded worker), so counts are exact.
        let (baseline, baseline_cancelled) = alarms(&executor);
        assert_eq!(baseline_cancelled, 0);

        // Register far-future sleeps (one pending poll each), then cancel
        // them all by dropping the futures.
        let mut sleeps = Vec::new();
        for _ in 0..8 {
            let mut sleep = Box::pin(context.sleep(Duration::from_secs(3600)));
            assert!(futures::poll!(sleep.as_mut()).is_pending());
            sleeps.push(sleep);
        }
        assert_eq!(alarms(&executor).0, baseline + 8);
        drop(sleeps);

        // Only the baseline alarms remain live, and tombstones are within
        // the compaction bound (so the heap cannot grow unboundedly).
        let (len, cancelled) = alarms(&executor);
        assert_eq!(len - cancelled, baseline, "cancelled sleeps retained");
        assert!(cancelled * 2 <= len, "tombstones exceed compaction bound");
    });
}

/// Race foreign-thread sleeps, cancellations, and re-polls against the
/// worker's alarm firing: sleeps must neither fire early nor hang, and
/// tombstone accounting must stay exact under churn (an accounting bug
/// underflows `cancelled` and panics).
#[test]
fn test_sleep_churn_stress() {
    use futures::FutureExt as _;
    Runner::default().start(|context| async move {
        let executor = context.executor.upgrade().unwrap();

        // Foreign threads: timed sleeps registered against a (mostly)
        // parked runtime must complete promptly and never early.
        let mut threads = Vec::new();
        for t in 0..4 {
            let clock = context.child("timed");
            threads.push(std::thread::spawn(move || {
                for i in 0..50 {
                    let d = Duration::from_micros(200 * ((t + i) % 7 + 1));
                    let start = std::time::Instant::now();
                    futures::executor::block_on(clock.sleep(d));
                    assert!(start.elapsed() >= d, "sleep fired early");
                }
                drop(clock);
            }));
        }

        // Foreign threads: register far-future alarms, poll them pending
        // once, then drop them (cancel path + compaction churn), and race
        // short-deadline drops against the worker popping due alarms
        // (cancel-vs-fire on the tombstone accounting).
        for _ in 0..4 {
            let clock = context.child("cancelled");
            threads.push(std::thread::spawn(move || {
                for i in 0..200 {
                    let mut far = Box::pin(clock.sleep(Duration::from_secs(3600)));
                    assert!(far.as_mut().now_or_never().is_none());
                    let mut near = Box::pin(clock.sleep(Duration::from_micros(50 * (i % 5 + 1))));
                    let _ = near.as_mut().now_or_never();
                    // Let the deadline elapse so the drop below races the
                    // worker's wake_ready_sleepers pop.
                    std::thread::sleep(Duration::from_micros(50 * (i % 5 + 1)));
                    drop(near);
                    drop(far);
                }
                drop(clock);
            }));
        }

        // Keep the worker's loop turning between parks while the churn
        // runs, so alarms fire from both the parked and running paths.
        while threads.iter().any(|thread| !thread.is_finished()) {
            context.sleep(Duration::from_micros(500)).await;
        }
        for thread in threads {
            thread.join().unwrap();
        }

        // All churned alarms are gone, up to tombstones bounded by the
        // compaction invariant (checked after cancellation and firing).
        let guard = executor.sleeping.lock();
        let sleeping = guard.as_ref().unwrap();
        assert!(
            sleeping.alarms.len() <= 32,
            "alarm heap retained churned sleeps: {}",
            sleeping.alarms.len()
        );
        assert!(sleeping.cancelled * 2 <= sleeping.alarms.len().max(1));
    });
}

/// A sleeper whose alarm fires between its deadline check and its waker
/// refresh (a foreign poll racing the origin worker at the deadline) must
/// resolve, not panic: an emptied slot under an open queue means the
/// alarm completed.
#[test]
fn test_sleep_refresh_after_fire_resolves() {
    Runner::default().start(|context| async move {
        let executor = context.executor.upgrade().unwrap();
        let mut sleep = Box::pin(context.sleep(Duration::from_secs(3600)));
        assert!(futures::poll!(sleep.as_mut()).is_pending());

        // Fire every registered alarm as the worker loop would at its
        // deadline, emptying the sleeper's waker slot while the queue
        // stays open (the interleaving a racing foreign poll observes).
        executor.wake_ready_sleepers(Instant::now() + Duration::from_secs(7200));

        assert!(futures::poll!(sleep.as_mut()).is_ready());
    });
}

/// A sleep polled once in one task and then moved to another must wake
/// the task that most recently polled it, not the original registrant.
#[test]
fn test_sleep_waker_refresh_across_tasks() {
    Runner::default().start(|context| async move {
        // Register the sleep with the root task's waker.
        let mut sleep = Box::pin(context.sleep(Duration::from_millis(300)));
        assert!(futures::poll!(sleep.as_mut()).is_pending());

        // Move the pending sleep to a spawned task: its first poll must
        // refresh the alarm to wake the new task at the deadline.
        let handle = context.child("mover").spawn(move |_| sleep);
        handle.await.unwrap();
    });
}

#[test]
fn test_registered_sleep_drop_after_worker_teardown_is_inert() {
    let (sleeper, executor) = Runner::default().start(|context| async move {
        context
            .child("worker")
            .dedicated()
            .spawn(|_| async {})
            .await
            .unwrap();

        let executor = context.executor.clone();
        // Keep the concrete sleeper alive past executor teardown to
        // exercise its weak-owner cancellation path.
        let mut sleeper = Box::pin(Sleeper {
            executor: executor.clone(),
            time: Instant::now() + Duration::from_secs(3600),
            alarm: None,
        });
        assert!(futures::poll!(sleeper.as_mut()).is_pending());
        (sleeper, executor)
    });

    assert!(executor.upgrade().is_none());
    drop(sleeper);
}

#[test]
fn test_inline_spawn_after_task_arena_close_resolves_closed() {
    Runner::default().start(|context| async move {
        let executor = context.executor.upgrade().unwrap();
        executor.tasks.clear();

        let invoked = Arc::new(AtomicBool::new(false));
        let task_invoked = Arc::clone(&invoked);
        let handle = context.child("late").spawn(move |_| async move {
            task_invoked.store(true, Ordering::Release);
        });
        assert!(matches!(handle.await, Err(Error::Closed)));
        assert!(!invoked.load(Ordering::Acquire));
    });
}

/// Spawning through a context whose worker fully tore down (executor
/// dropped, not merely tree-aborted) resolves [Error::Closed] instead of
/// panicking: the outcome must not depend on which side of the teardown
/// race the spawn lands.
#[test]
fn test_spawn_on_dead_worker_resolves_closed() {
    Runner::default().start(|context| async move {
        let (send, recv) = oneshot::channel();
        let origin = context
            .child("origin")
            .dedicated()
            .spawn(move |context| async move {
                let executor = context.executor.clone();
                let _ = send.send((context.child("spawner"), executor));
            });
        let (spawner, executor) = recv.await.unwrap();
        origin.await.unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while executor.upgrade().is_some() {
            assert!(Instant::now() < deadline, "origin executor remained alive");
            context.sleep(Duration::from_millis(1)).await;
        }

        let handle = spawner.spawn(|_| async move { 7 });
        assert!(matches!(handle.await, Err(Error::Closed)));
    });
}

/// Sleeping on a context whose worker already tore down fails loudly in
/// the sleeping task instead of registering an alarm nothing will fire.
#[test]
fn test_sleep_on_dead_worker_fails() {
    let cfg = Config::default().with_catch_panics(true);
    Runner::new(cfg).start(|context| async move {
        let (send, recv) = oneshot::channel();
        let origin = context
            .child("origin")
            .dedicated()
            .spawn(move |context| async move {
                let executor = context.executor.clone();
                let _ = send.send((context.child("clock"), executor));
            });
        let (clock, executor) = recv.await.unwrap();
        origin.await.unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while executor.upgrade().is_some() {
            assert!(Instant::now() < deadline, "origin executor remained alive");
            context.sleep(Duration::from_millis(1)).await;
        }
        let sleeper = context.child("sleeper").spawn(move |_| async move {
            clock.sleep(Duration::from_secs(3600)).await;
        });
        assert!(matches!(sleeper.await, Err(Error::Exited)));
    });
}

#[test]
fn test_network_echo() {
    // Exercise bind, accept, dial, send, and recv end-to-end on the
    // runtime's own ring (all connection setup goes through io_uring).
    let executor = Runner::default();
    executor.start(|context| async move {
        let mut listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();

        let server = context.child("server").spawn(move |_| async move {
            let (_, mut sink, mut stream) = listener.accept().await.unwrap();
            let msg = stream.recv(5).await.unwrap();
            assert_eq!(msg.coalesce(), b"hello");
            sink.send(IoBuf::from(b"world")).await.unwrap();
        });

        let (mut sink, mut stream) = context.dial(addr).await.unwrap();
        sink.send(IoBuf::from(b"hello")).await.unwrap();
        let response = stream.recv(5).await.unwrap();
        assert_eq!(response.coalesce(), b"world");
        server.await.unwrap();
    });
}

#[test]
fn test_network_recv_timeout() {
    // Exercise a network deadline expiring while the executor drives
    // the ring (turn/park path): the recv must report a timeout close
    // to the configured budget instead of stalling.
    let op_timeout = Duration::from_millis(100);
    let cfg = Config::default().with_read_write_timeout(op_timeout);
    Runner::new(cfg).start(|context| async move {
        let mut listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();

        let server = context.child("server").spawn(move |_| async move {
            let (_, sink, mut stream) = listener.accept().await.unwrap();
            let result = stream.recv(1).await;
            assert!(matches!(result, Err(Error::Timeout)));
            // Keep the connection alive until the recv resolves.
            drop(sink);
        });

        // Dial but never send, so the server's recv can only expire.
        let start = std::time::Instant::now();
        let (_sink, _stream) = context.dial(addr).await.unwrap();
        server.await.unwrap();
        let elapsed = start.elapsed();
        assert!(elapsed >= op_timeout);
        assert!(elapsed < op_timeout * 30, "recv timeout took {elapsed:?}");
    });
}

#[test]
fn test_fast_teardown_with_inflight_recv() {
    // A recv still in flight when the root task returns must not delay
    // teardown until its (60s) deadline: teardown cancels operations
    // whose tasks were dropped.
    let start = std::time::Instant::now();
    let cfg = Config::default().with_read_write_timeout(Duration::from_secs(60));
    Runner::new(cfg).start(|context| async move {
        let mut listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let (pending_send, pending_recv) = oneshot::channel();

        context.child("server").spawn(move |_| async move {
            let (_, _sink, mut stream) = listener.accept().await.unwrap();
            let mut recv = Box::pin(stream.recv(1));
            let mut pending_send = Some(pending_send);
            std::future::poll_fn(move |cx| match recv.as_mut().poll(cx) {
                Poll::Pending => {
                    if let Some(send) = pending_send.take() {
                        let _ = send.send(());
                    }
                    Poll::<()>::Pending
                }
                Poll::Ready(_) => panic!("recv resolved before first Pending"),
            })
            .await;
        });

        let (_sink, _stream) = context.dial(addr).await.unwrap();
        pending_recv.await.unwrap();

        // A child spawned by the root runs after the next driver turn.
        context
            .child("turn_barrier")
            .spawn(|_| async move {})
            .await
            .unwrap();
    });
    assert!(
        start.elapsed() < Duration::from_secs(10),
        "teardown took {:?}",
        start.elapsed()
    );
}

#[test]
fn test_accept_survives_reissue() {
    // An accept that waits longer than the read/write timeout is
    // transparently reissued: a connection arriving after several
    // reissue cycles must still be accepted.
    let op_timeout = Duration::from_millis(50);
    let cfg = Config::default().with_read_write_timeout(op_timeout);
    Runner::new(cfg).start(|context| async move {
        let mut listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();

        let server = context.child("server").spawn(move |_| async move {
            let (_, _sink, mut stream) = listener.accept().await.unwrap();
            let msg = stream.recv(4).await.unwrap();
            assert_eq!(msg.coalesce(), b"ping");
        });

        // Wait through multiple accept deadlines before connecting.
        context.sleep(op_timeout * 4).await;
        let (mut sink, _stream) = context.dial(addr).await.unwrap();
        sink.send(IoBuf::from(b"ping")).await.unwrap();
        server.await.unwrap();
    });
}

#[test]
fn test_cross_thread_wake() {
    // Verify a foreign thread can wake the runtime thread out of its
    // park: the sleep gives the runtime time to park (so the alarm is
    // registered from another thread against a parked runtime), and
    // the oneshot send must then unblock the root task.
    let executor = Runner::default();
    executor.start(|context| async move {
        let start = std::time::Instant::now();
        let (tx, rx) = oneshot::channel();
        let thread = std::thread::spawn(move || {
            futures::executor::block_on(context.sleep(Duration::from_millis(50)));
            tx.send(42).unwrap();
        });
        assert_eq!(rx.await.unwrap(), 42);

        // Join so the helper has finished before the runtime returns.
        thread.join().unwrap();

        // The wake must arrive promptly after the 50ms sleep, not at
        // the runtime's next unrelated park deadline.
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "cross-thread wake took {:?}",
            start.elapsed()
        );
    });
}

#[test]
fn test_process_rss_metric() {
    let executor = Runner::default();
    executor.start(|context| async move {
        loop {
            // Wait for RSS metric to be available
            let metrics = context.encode();
            if !metrics.contains("runtime_process_rss") {
                context.sleep(Duration::from_millis(100)).await;
                continue;
            }

            // Verify the RSS value is eventually populated (greater than 0)
            for line in metrics.lines() {
                if line.starts_with("runtime_process_rss")
                    && !line.starts_with("runtime_process_rss{")
                {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 2 {
                        let rss_value: i64 = parts[1].parse().expect("Failed to parse RSS value");
                        if rss_value > 0 {
                            return;
                        }
                    }
                }
            }
        }
    });
}

#[test]
fn test_root_task_metric_balanced() {
    const RUNNING_ROOT: &str =
        "runtime_tasks_running{name=\"\",kind=\"Root\",execution=\"Shared\"}";

    let retained = Arc::new(Mutex::new(None));
    let capture = Arc::clone(&retained);
    Runner::default().start(move |context| async move {
        let shared = Arc::clone(&context.executor().shared);
        let metrics = shared.registry.encode();
        assert!(
            metrics.contains(&format!("{RUNNING_ROOT} 1")),
            "root task was not counted while running: {metrics}"
        );
        *capture.lock() = Some(shared);
    });

    let shared = retained
        .lock()
        .take()
        .expect("root did not retain shared runtime state");
    let metrics = shared.registry.encode();
    assert!(
        metrics.contains(&format!("{RUNNING_ROOT} 0")),
        "root task metric was not balanced after shutdown: {metrics}"
    );
}

#[test]
fn test_resolver() {
    let executor = Runner::default();
    executor.start(|context| async move {
        let addrs = context.resolve("localhost").await.unwrap();
        assert!(!addrs.is_empty());
        for addr in addrs {
            assert!(
                addr == IpAddr::V4(Ipv4Addr::LOCALHOST) || addr == IpAddr::V6(Ipv6Addr::LOCALHOST)
            );
        }
    });
}

/// Pool work runs on dedicated worker threads, so awaiting a spawned
/// strategy task exercises the loop's cross-thread wake path.
#[test]
fn test_parallel_strategy_spawn_completes() {
    let executor = Runner::default();
    executor.start(|context| async move {
        let strategy = context.child("pool").strategy(NZUsize!(2)).manual();
        assert_eq!(strategy.parallelism(), 2);

        let output = strategy
            .spawn(|strategy| strategy.map_collect_vec(0..2, |i| i + 1))
            .await;

        assert_eq!(output, vec![1, 2]);
    });
}
