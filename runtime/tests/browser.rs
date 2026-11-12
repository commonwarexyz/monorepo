//! Tests for the `browser` runtime, run in a browser with `wasm-bindgen-test`.

#![cfg(all(target_arch = "wasm32", feature = "browser"))]

use commonware_macros::select;
use commonware_runtime::{
    Clock, Error, IoBuf, IoBufs, Metrics, Sink as _, Spawner, Stream as _, Supervisor,
    browser::{Config, Context, Runner, Sink, Stream},
};
use commonware_utils::{channel::oneshot, sync::Mutex};
use futures::{FutureExt as _, future::pending, poll};
use std::{
    pin::pin,
    sync::Arc,
    time::{Duration, SystemTime},
};
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};

wasm_bindgen_test_configure!(run_in_browser);

/// Longest a connection attempt between two contexts of one page may take.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Both halves of one side of a connection.
type Halves = (Sink, Stream);

/// Connects two contexts, returning the halves of the offering side then the answering side.
async fn connect(offerer: &Context, answerer: &Context) -> (Halves, Halves) {
    let attempt = {
        let (offer, answer) = (offerer.offer(), answerer.child("answer"));
        async move {
            let (offer, offering) = offer.await.expect("offer must succeed");
            let (answer, answering) = answer.answer(offer).await.expect("answer must succeed");
            let (offered, answered) = futures::join!(offering.connect(answer), answering.connect());
            (
                offered.expect("offering side must connect"),
                answered.expect("answering side must connect"),
            )
        }
    };
    offerer
        .timeout(CONNECT_TIMEOUT, attempt)
        .await
        .expect("pages must connect before the deadline")
}

/// Returns `len` bytes whose pattern changes if a transfer reorders or drops a message.
fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

#[wasm_bindgen_test]
async fn test_spawn_returns_output() {
    let output = Runner::default()
        .start(|context| async move {
            context
                .child("task")
                .spawn(|context| async move {
                    context.sleep(Duration::from_millis(1)).await;
                    7
                })
                .await
        })
        .await;
    assert_eq!(output.unwrap(), 7);
}

#[wasm_bindgen_test]
async fn test_spawn_aborts_children_when_parent_finishes() {
    Runner::default()
        .start(|context| async move {
            // The parent returns once its child runs. Returning aborts the child.
            let (started, running) = oneshot::channel();
            let (spawned, child) = oneshot::channel();
            let parent = context.child("parent").spawn(|context| async move {
                let child = context.child("child").spawn(|_| async move {
                    started.send(()).unwrap();
                    pending::<()>().await;
                });
                assert!(spawned.send(child).is_ok());
                running.await.unwrap();
            });
            parent.await.unwrap();
            assert!(matches!(child.await.unwrap().await, Err(Error::Closed)));
        })
        .await;
}

#[wasm_bindgen_test]
async fn test_start_aborts_tasks_when_root_finishes() {
    let (task, kept) = Runner::default()
        .start(|context| async move {
            let task = context.child("task").spawn(|_| pending::<()>());
            (task, context.child("kept"))
        })
        .await;

    // Completing the run aborts the task it left pending.
    assert!(matches!(task.await, Err(Error::Closed)));

    // A context kept past the run cannot spawn.
    let late = kept.spawn(|_| async {});
    assert!(matches!(late.await, Err(Error::Closed)));
}

#[wasm_bindgen_test]
async fn test_start_aborts_tasks_when_dropped() {
    // Run the root until it has spawned a task, then abandon the run.
    let (spawned, task) = oneshot::channel();
    let mut run = Box::pin(Runner::default().start(|context| async move {
        let task = context.child("task").spawn(|_| pending::<()>());
        assert!(spawned.send(task).is_ok());
        pending::<()>().await
    }));
    assert!((&mut run).now_or_never().is_none());
    drop(run);
    assert!(matches!(task.await.unwrap().await, Err(Error::Closed)));
}

#[wasm_bindgen_test]
async fn test_stop_signals_tasks() {
    Runner::default()
        .start(|context| async move {
            // A task waits for the signal before anything stops the runtime.
            let (waiting, ready) = oneshot::channel();
            let task = context.child("task").spawn(|context| async move {
                let mut stopped = context.stopped();
                assert!(waiting.send(()).is_ok());
                (&mut stopped).await.unwrap()
            });
            ready.await.unwrap();

            // Stopping completes once the task has dropped its signal.
            context.child("stopper").stop(3, None).await.unwrap();
            assert_eq!(task.await.unwrap(), 3);
        })
        .await;
}

#[wasm_bindgen_test]
async fn test_metrics_count_spawned_tasks() {
    Runner::default()
        .start(|context| async move {
            context.child("task").spawn(|_| async {}).await.unwrap();
            let counter = context.register(
                "counter",
                "help",
                commonware_runtime::telemetry::metrics::raw::Counter::<u64>::default(),
            );
            counter.inc();
            let metrics = context.encode();
            assert!(
                metrics.contains(
                    "runtime_tasks_spawned_total{name=\"task\",kind=\"Task\",execution=\"Shared\"} 1"
                ),
                "{metrics}"
            );
            assert!(metrics.contains("counter_total 1"), "{metrics}");
        })
        .await;
}

#[wasm_bindgen_test]
async fn test_current_reads_wall_clock() {
    Runner::default()
        .start(|context| async move {
            let since_epoch = context
                .current()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap();
            let expected = Duration::from_secs_f64(js_sys::Date::now() / 1_000.0);
            assert!(expected.abs_diff(since_epoch) < Duration::from_secs(1));
        })
        .await;
}

#[wasm_bindgen_test]
async fn test_sleep_waits_for_duration() {
    Runner::default()
        .start(|context| async move {
            // A zero sleep needs no timer.
            assert!(context.sleep(Duration::ZERO).now_or_never().is_some());

            // A sleep's deadline counts from when the sleep is created.
            let late = context.sleep(Duration::from_millis(30));
            let start = js_sys::Date::now();
            context.sleep(Duration::from_millis(60)).await;
            assert!(js_sys::Date::now() - start >= 59.0);
            assert!(late.now_or_never().is_some());

            // A deadline in the past has already passed.
            assert!(
                context
                    .sleep_until(context.current() - Duration::from_secs(1))
                    .now_or_never()
                    .is_some()
            );
        })
        .await;
}

#[wasm_bindgen_test]
async fn test_sleeps_complete_in_deadline_order() {
    Runner::default()
        .start(|context| async move {
            // The longest sleep starts first, and two sleeps last equally long.
            let order = Arc::new(Mutex::new(Vec::new()));
            let mut tasks = Vec::new();
            for millis in [150u64, 50, 100, 50] {
                let order = order.clone();
                tasks.push(context.child("sleeper").spawn(move |context| async move {
                    context.sleep(Duration::from_millis(millis)).await;
                    order.lock().push(millis);
                }));
            }
            for task in tasks {
                task.await.unwrap();
            }
            assert_eq!(*order.lock(), vec![50, 50, 100, 150]);
        })
        .await;
}

#[wasm_bindgen_test]
async fn test_earlier_sleep_replaces_armed_timeout() {
    Runner::default()
        .start(|context| async move {
            // A task waits on a long sleep, so the timeout is armed for that sleep's deadline.
            let (waiting, ready) = oneshot::channel();
            let long = context.child("long").spawn(|context| async move {
                let mut sleep = pin!(context.sleep(Duration::from_secs(30)));
                assert!(poll!(&mut sleep).is_pending());
                assert!(waiting.send(()).is_ok());
                sleep.await;
            });
            ready.await.unwrap();

            // A shorter sleep still completes at its own deadline.
            let start = js_sys::Date::now();
            context.sleep(Duration::from_millis(20)).await;
            let elapsed = js_sys::Date::now() - start;
            assert!(elapsed < 10_000.0, "{elapsed}");
            long.abort();
        })
        .await;
}

#[wasm_bindgen_test]
async fn test_dropped_sleep_does_not_delay_others() {
    Runner::default()
        .start(|context| async move {
            // Wait on a sleep until the timeout is armed for it, then drop it. Its timeout is
            // left to fire for no one.
            let mut early = context.sleep(Duration::from_millis(30));
            assert!((&mut early).now_or_never().is_none());
            context.sleep(Duration::from_millis(1)).await;
            drop(early);

            // The next sleep still completes at its own deadline.
            let start = js_sys::Date::now();
            context.sleep(Duration::from_millis(80)).await;
            let elapsed = js_sys::Date::now() - start;
            assert!((79.0..5_000.0).contains(&elapsed), "{elapsed}");

            // A sleep longer than any browser timeout stays pending through the timeouts armed
            // on its way.
            let result = context
                .timeout(Duration::from_millis(20), context.sleep(Duration::MAX))
                .await;
            assert!(matches!(result, Err(Error::Timeout)));
        })
        .await;
}

#[wasm_bindgen_test]
async fn test_connection_carries_bytes_both_ways() {
    Runner::default()
        .start(|context| async move {
            let ((mut a_sink, mut a_stream), (mut b_sink, mut b_stream)) =
                connect(&context, &context).await;

            // An empty send and an empty read complete without a message.
            a_sink.send(IoBufs::default()).await.unwrap();
            assert!(b_stream.recv(0).await.unwrap().is_empty());

            // One send may be read in pieces, and several sends in one read.
            a_sink.send(IoBuf::from(b"hello world")).await.unwrap();
            assert_eq!(b_stream.recv(5).await.unwrap().coalesce(), b"hello");
            assert_eq!(b_stream.recv(6).await.unwrap().coalesce(), b" world");
            b_sink.send(IoBuf::from(b"a")).await.unwrap();
            b_sink
                .send(IoBufs::from(vec![
                    IoBuf::from(b"b"),
                    IoBuf::from(b"cd"),
                    IoBuf::from(b"e"),
                ]))
                .await
                .unwrap();
            assert_eq!(a_stream.recv(5).await.unwrap().coalesce(), b"abcde");
        })
        .await;
}

#[wasm_bindgen_test]
async fn test_connection_carries_large_transfer() {
    // The transfer exceeds what the browser buffers for a sender and what a connection holds
    // for a reader, so it completes only if sends wait and a pending read may exceed the
    // receive buffer.
    const LEN: usize = 8 * 1024 * 1024;

    Runner::default()
        .start(|context| async move {
            let ((mut a_sink, _a_stream), (_b_sink, mut b_stream)) =
                connect(&context, &context).await;
            let reader = context
                .child("reader")
                .spawn(move |_| async move { b_stream.recv(LEN).await.unwrap().coalesce() });
            let data = pattern(LEN);
            a_sink.send(data.clone()).await.unwrap();
            assert!(reader.await.unwrap() == data.as_slice());
        })
        .await;
}

#[wasm_bindgen_test]
async fn test_peek_returns_buffered_bytes() {
    const DATA: &[u8] = b"hello world - peek test data";

    Runner::default()
        .start(|context| async move {
            let ((mut a_sink, _a_stream), (_b_sink, mut b_stream)) =
                connect(&context, &context).await;
            assert!(b_stream.peek(100).is_empty());
            a_sink.send(IoBuf::from(DATA)).await.unwrap();

            // A partial read buffers the rest of the message.
            assert_eq!(b_stream.recv(5).await.unwrap().coalesce(), b"hello");
            assert_eq!(b_stream.peek(100), &DATA[5..]);
            assert_eq!(b_stream.peek(3), &DATA[5..8]);
            assert_eq!(b_stream.peek(100), &DATA[5..]);
            assert_eq!(
                b_stream.recv(DATA.len() - 5).await.unwrap().coalesce(),
                &DATA[5..]
            );
            assert!(b_stream.peek(100).is_empty());
        })
        .await;
}

#[wasm_bindgen_test]
async fn test_canceled_recv_poisons_stream() {
    Runner::default()
        .start(|context| async move {
            let ((mut a_sink, mut a_stream), (mut b_sink, mut b_stream)) =
                connect(&context, &context).await;

            // Leave bytes buffered in the stream, then cancel a read that needs more of them.
            b_sink.send(vec![1u8; 50]).await.unwrap();
            assert_eq!(a_stream.recv(10).await.unwrap().len(), 10);
            assert_eq!(a_stream.peek(100).len(), 40);
            select! {
                received = a_stream.recv(100) => panic!("read must stay pending: {received:?}"),
                _ = context.sleep(Duration::from_millis(5)) => {},
            };

            // The stream is poisoned and holds nothing.
            assert!(a_stream.peek(100).is_empty());
            assert!(matches!(a_stream.recv(1).await, Err(Error::Closed)));

            // The sink remains usable, and bytes sent to the poisoned stream are dropped
            // without closing the connection.
            b_sink.send(vec![0u8; 16]).await.unwrap();
            a_sink.send(IoBuf::from(b"ok")).await.unwrap();
            assert_eq!(b_stream.recv(2).await.unwrap().coalesce(), b"ok");
        })
        .await;
}

#[wasm_bindgen_test]
async fn test_canceled_send_poisons_sink() {
    Runner::default()
        .start(|context| async move {
            let ((mut a_sink, mut a_stream), (mut b_sink, _b_stream)) =
                connect(&context, &context).await;

            // Send without yielding to the browser until it holds enough unsent bytes for a
            // send to wait, then drop that send.
            let mut blocked = false;
            for _ in 0..64 {
                match a_sink.send(vec![0u8; 128 * 1024]).now_or_never() {
                    Some(Ok(())) => {}
                    Some(Err(err)) => panic!("send must succeed until one waits: {err:?}"),
                    None => {
                        blocked = true;
                        break;
                    }
                }
            }
            assert!(
                blocked,
                "a send must wait once the browser holds enough bytes"
            );
            assert!(matches!(
                a_sink.send(IoBuf::from(b"after")).await,
                Err(Error::Closed)
            ));

            // The stream remains usable.
            b_sink.send(IoBuf::from(b"ok")).await.unwrap();
            assert_eq!(a_stream.recv(2).await.unwrap().coalesce(), b"ok");
        })
        .await;
}

#[wasm_bindgen_test]
async fn test_closed_connection_fails_both_halves() {
    Runner::default()
        .start(|context| async move {
            let ((mut a_sink, mut a_stream), (b_sink, b_stream)) =
                connect(&context, &context).await;

            // A task holds one side of the connection.
            let (sent, ready) = oneshot::channel();
            let holder = context.child("holder").spawn(move |_| async move {
                let (mut b_sink, _b_stream) = (b_sink, b_stream);
                b_sink.send(IoBuf::from(b"okay")).await.unwrap();
                sent.send(()).unwrap();
                pending::<()>().await;
            });
            ready.await.unwrap();
            assert_eq!(a_stream.recv(2).await.unwrap().coalesce(), b"ok");

            // Aborting the task drops both halves and so closes the connection. A send may
            // succeed until the close arrives.
            holder.abort();
            assert!(matches!(holder.await, Err(Error::Closed)));
            let mut failed = None;
            for _ in 0..500 {
                match a_sink.send(IoBuf::from(b"late")).await {
                    Ok(()) => context.sleep(Duration::from_millis(10)).await,
                    Err(err) => {
                        failed = Some(err);
                        break;
                    }
                }
            }
            assert!(matches!(failed, Some(Error::SendFailed)));
            assert!(matches!(
                a_sink.send(IoBuf::from(b"late")).await,
                Err(Error::Closed)
            ));

            // Bytes received before the close remain readable.
            assert_eq!(a_stream.recv(2).await.unwrap().coalesce(), b"ay");
            assert!(matches!(a_stream.recv(1).await, Err(Error::RecvFailed)));
            assert!(matches!(a_stream.recv(1).await, Err(Error::Closed)));
        })
        .await;
}

#[wasm_bindgen_test]
async fn test_closed_connection_wakes_pending_operations() {
    Runner::default()
        .start(|context| async move {
            let ((mut a_sink, mut a_stream), (b_sink, mut b_stream)) =
                connect(&context, &context).await;

            // One side reads everything it is sent until its task is aborted.
            let holder = context.child("holder").spawn(move |_| async move {
                let _b_sink = b_sink;
                let _ = b_stream.recv(usize::MAX).await;
            });

            // The other side waits in a read for bytes that never come.
            let (reading, read_pending) = oneshot::channel();
            let reader = context.child("reader").spawn(move |_| async move {
                let mut recv = pin!(a_stream.recv(100));
                assert!(poll!(&mut recv).is_pending());
                assert!(reading.send(()).is_ok());
                recv.await
            });

            // It also waits in a send of more bytes than the browser takes before the abort.
            let (sending, send_pending) = oneshot::channel();
            let writer = context.child("writer").spawn(move |_| async move {
                let chunk = IoBuf::from(vec![0u8; 1024 * 1024]);
                let mut send = pin!(a_sink.send(IoBufs::from(vec![chunk; 1024])));
                assert!(poll!(&mut send).is_pending());
                assert!(sending.send(()).is_ok());
                send.await
            });
            read_pending.await.unwrap();
            send_pending.await.unwrap();

            // Closing the connection fails both.
            holder.abort();
            assert!(matches!(reader.await.unwrap(), Err(Error::RecvFailed)));
            assert!(matches!(writer.await.unwrap(), Err(Error::SendFailed)));
        })
        .await;
}

#[wasm_bindgen_test]
async fn test_dropped_sink_keeps_stream_readable() {
    Runner::default()
        .start(|context| async move {
            let ((a_sink, mut a_stream), (mut b_sink, _b_stream)) =
                connect(&context, &context).await;

            // The stream keeps receiving after its sink is dropped.
            drop(a_sink);
            b_sink.send(IoBuf::from(b"ok")).await.unwrap();
            assert_eq!(a_stream.recv(2).await.unwrap().coalesce(), b"ok");
        })
        .await;
}

#[wasm_bindgen_test]
async fn test_receive_buffer_bounds_unread_bytes() {
    const BUFFER: usize = 64 * 1024;
    const LEN: usize = 1024 * 1024;

    // Only the answering side has a small buffer.
    Runner::default()
        .start(|a| async move {
            Runner::new(Config::new().with_receive_buffer_size(BUFFER))
                .start(|b| async move {
                    // A read that is already pending may exceed the buffer.
                    let ((mut a_sink, _a_stream), (_b_sink, mut b_stream)) = connect(&a, &b).await;
                    let reader = b.child("reader").spawn(move |_| async move {
                        let received = b_stream.recv(LEN).await.unwrap().coalesce();
                        (b_stream, received)
                    });
                    b.sleep(Duration::from_millis(10)).await;
                    let data = pattern(LEN);
                    a_sink.send(data.clone()).await.unwrap();
                    let (mut b_stream, received) = reader.await.unwrap();
                    assert!(received == data.as_slice());

                    // Bytes no read asked for may fill the buffer.
                    a_sink.send(vec![1u8; BUFFER]).await.unwrap();
                    b.sleep(Duration::from_millis(100)).await;
                    assert_eq!(
                        b_stream.recv(BUFFER).await.unwrap().coalesce(),
                        vec![1u8; BUFFER].as_slice()
                    );

                    // One byte more closes the connection, and the sender observes it.
                    a_sink.send(vec![2u8; BUFFER + 1]).await.unwrap();
                    let closed = {
                        let a = a.child("closed");
                        async move {
                            while a_sink.send(vec![0u8]).await.is_ok() {
                                a.sleep(Duration::from_millis(10)).await;
                            }
                        }
                    };
                    a.timeout(Duration::from_secs(5), closed).await.unwrap();
                    assert!(matches!(
                        b_stream.recv(BUFFER + 1).await,
                        Err(Error::RecvFailed)
                    ));
                })
                .await
        })
        .await;
}

#[wasm_bindgen_test]
async fn test_dropped_stream_discards_received_bytes() {
    const BUFFER: usize = 64 * 1024;

    Runner::default()
        .start(|a| async move {
            Runner::new(Config::new().with_receive_buffer_size(BUFFER))
                .start(|b| async move {
                    // Nothing reads what the offering side sends, yet the connection stays
                    // open past the buffer.
                    let ((mut a_sink, mut a_stream), (mut b_sink, b_stream)) =
                        connect(&a, &b).await;
                    drop(b_stream);
                    a_sink.send(vec![0u8; 4 * BUFFER]).await.unwrap();
                    b.sleep(Duration::from_millis(100)).await;
                    b_sink.send(IoBuf::from(b"ok")).await.unwrap();
                    assert_eq!(a_stream.recv(2).await.unwrap().coalesce(), b"ok");
                    a_sink.send(vec![0u8; 16]).await.unwrap();
                })
                .await
        })
        .await;
}

#[wasm_bindgen_test]
async fn test_invalid_descriptions_fail() {
    Runner::default()
        .start(|context| async move {
            // A step given a malformed description fails.
            assert!(matches!(
                context.answer("not an offer".into()).await,
                Err(Error::ConnectionFailed)
            ));
            let (_, offering) = context.offer().await.unwrap();
            assert!(matches!(
                offering.connect("not an answer".into()).await,
                Err(Error::ConnectionFailed)
            ));
        })
        .await;
}

#[wasm_bindgen_test]
async fn test_abandoned_attempts_do_not_block_others() {
    Runner::default()
        .start(|context| async move {
            // Abandon an offer, an unpolled offer, an answer, and a pending connection.
            let (offer, offering) = context.offer().await.unwrap();
            drop(context.offer());
            let (_, answering) = context.answer(offer).await.unwrap();
            assert!(matches!(
                context
                    .timeout(Duration::from_millis(50), answering.connect())
                    .await,
                Err(Error::Timeout)
            ));
            drop(offering);

            // A new attempt still connects.
            let ((mut a_sink, _a_stream), (_b_sink, mut b_stream)) =
                connect(&context, &context).await;
            a_sink.send(IoBuf::from(b"ok")).await.unwrap();
            assert_eq!(b_stream.recv(2).await.unwrap().coalesce(), b"ok");
        })
        .await;
}
