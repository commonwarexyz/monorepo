use commonware_actor::{self as actor, Backpressure, Feedback, MessagePolicy};
use criterion::{criterion_group, BatchSize, Criterion, Throughput};
use futures::pin_mut;
use std::{
    future::{poll_fn, Future},
    hint::black_box,
    sync::Barrier,
    task::Poll,
};
use tokio::sync::mpsc;

const CAPACITY: usize = 1024;
const CONTENDED_MESSAGES: usize = 64 * 1024;
const MATRIX_MESSAGES_PER_PRODUCER: usize = 1024;
const MESSAGES: usize = 1024;
const PRODUCERS: usize = 4;
const PRODUCER_MESSAGES: usize = CONTENDED_MESSAGES / PRODUCERS;
const SPSC_OVERLAP_MESSAGES: usize = 1024 * 1024;
const TOKIO_STYLE_MESSAGES: usize = 5_000;
const TOKIO_STYLE_PRODUCERS: usize = 5;
const TOKIO_STYLE_MESSAGES_PER_PRODUCER: usize = TOKIO_STYLE_MESSAGES / TOKIO_STYLE_PRODUCERS;

const MATRIX_CAPACITIES: &[usize] = &[1, 8, 64, 1024];
const MATRIX_PRODUCERS: &[usize] = &[1, 2, 4, 8, 16];
const REPLACE_CAPACITIES: &[usize] = &[1, 8, 64, 1024];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Message {
    Reject(u64),
    Retain(u64),
    Replace(u64),
}

impl MessagePolicy for Message {
    fn handle(overflow: &mut actor::Overflow<'_, Self>, message: Self) -> Backpressure {
        match message {
            Self::Reject(_) => Backpressure::dropped(),
            Self::Retain(_) => overflow.spill(message),
            Self::Replace(_) => {
                let result =
                    overflow.replace_last(message, |pending| matches!(pending, Self::Replace(_)));
                overflow.replace_or_spill(result)
            }
        }
    }
}

fn bench_enqueue_ready(c: &mut Criterion) {
    let mut group = c.benchmark_group(module_path!());
    group.throughput(Throughput::Elements(MESSAGES as u64));

    group.bench_function(
        format!("operation=enqueue_ready impl=actor capacity={CAPACITY}"),
        |b| {
            b.iter_batched(
                || actor::Mailbox::<Message>::new(CAPACITY),
                |(sender, _receiver)| {
                    for i in 0..MESSAGES as u64 {
                        black_box(sender.enqueue(black_box(Message::Reject(i))));
                    }
                },
                BatchSize::LargeInput,
            );
        },
    );

    group.bench_function(
        format!("operation=enqueue_ready impl=tokio_mpsc capacity={CAPACITY}"),
        |b| {
            b.iter_batched(
                || mpsc::channel::<Message>(CAPACITY),
                |(sender, _receiver)| {
                    for i in 0..MESSAGES as u64 {
                        black_box(sender.try_send(black_box(Message::Reject(i))).unwrap());
                    }
                },
                BatchSize::LargeInput,
            );
        },
    );

    group.finish();
}

fn bench_recv_ready(c: &mut Criterion) {
    let mut group = c.benchmark_group(module_path!());
    group.throughput(Throughput::Elements(MESSAGES as u64));

    group.bench_function(
        format!("operation=recv_ready impl=actor capacity={CAPACITY}"),
        |b| {
            b.iter_batched(
                || {
                    let (sender, receiver) = actor::Mailbox::<Message>::new(CAPACITY);
                    for i in 0..MESSAGES as u64 {
                        assert_eq!(sender.enqueue(Message::Reject(i)), Feedback::Ok);
                    }
                    receiver
                },
                |mut receiver| {
                    for _ in 0..MESSAGES {
                        black_box(receiver.try_recv().unwrap());
                    }
                },
                BatchSize::LargeInput,
            );
        },
    );

    group.bench_function(
        format!("operation=recv_ready impl=tokio_mpsc capacity={CAPACITY}"),
        |b| {
            b.iter_batched(
                || {
                    let (sender, receiver) = mpsc::channel::<Message>(CAPACITY);
                    for i in 0..MESSAGES as u64 {
                        sender.try_send(Message::Reject(i)).unwrap();
                    }
                    receiver
                },
                |mut receiver| {
                    for _ in 0..MESSAGES {
                        black_box(receiver.try_recv().unwrap());
                    }
                },
                BatchSize::LargeInput,
            );
        },
    );

    group.finish();
}

fn bench_round_trip_ready(c: &mut Criterion) {
    let mut group = c.benchmark_group(module_path!());
    group.throughput(Throughput::Elements(MESSAGES as u64));

    group.bench_function(
        format!("operation=round_trip_ready impl=actor capacity={CAPACITY}"),
        |b| {
            b.iter_batched(
                || actor::Mailbox::<Message>::new(CAPACITY),
                |(sender, mut receiver)| {
                    for i in 0..MESSAGES as u64 {
                        black_box(sender.enqueue(black_box(Message::Reject(i))));
                        black_box(receiver.try_recv().unwrap());
                    }
                },
                BatchSize::LargeInput,
            );
        },
    );

    group.bench_function(
        format!("operation=round_trip_ready impl=tokio_mpsc capacity={CAPACITY}"),
        |b| {
            b.iter_batched(
                || mpsc::channel::<Message>(CAPACITY),
                |(sender, mut receiver)| {
                    for i in 0..MESSAGES as u64 {
                        black_box(sender.try_send(black_box(Message::Reject(i))).unwrap());
                        black_box(receiver.try_recv().unwrap());
                    }
                },
                BatchSize::LargeInput,
            );
        },
    );

    group.finish();
}

fn bench_recv_waiting(c: &mut Criterion) {
    let mut group = c.benchmark_group(module_path!());
    group.throughput(Throughput::Elements(MESSAGES as u64));

    group.bench_function(
        format!("operation=recv_waiting impl=actor capacity={CAPACITY}"),
        |b| {
            b.iter_batched(
                || actor::Mailbox::<Message>::new(CAPACITY),
                |(sender, mut receiver)| {
                    futures::executor::block_on(async {
                        for i in 0..MESSAGES as u64 {
                            let next = receiver.recv();
                            pin_mut!(next);
                            poll_fn(|cx| {
                                assert!(next.as_mut().poll(cx).is_pending());
                                Poll::Ready(())
                            })
                            .await;

                            assert_eq!(sender.enqueue(Message::Reject(i)), Feedback::Ok);
                            black_box(next.await.unwrap());
                        }
                    });
                },
                BatchSize::LargeInput,
            );
        },
    );

    group.bench_function(
        format!("operation=recv_waiting impl=tokio_mpsc capacity={CAPACITY}"),
        |b| {
            b.iter_batched(
                || mpsc::channel::<Message>(CAPACITY),
                |(sender, mut receiver)| {
                    futures::executor::block_on(async {
                        for i in 0..MESSAGES as u64 {
                            let next = receiver.recv();
                            pin_mut!(next);
                            poll_fn(|cx| {
                                assert!(next.as_mut().poll(cx).is_pending());
                                Poll::Ready(())
                            })
                            .await;

                            sender.try_send(Message::Reject(i)).unwrap();
                            black_box(next.await.unwrap());
                        }
                    });
                },
                BatchSize::LargeInput,
            );
        },
    );

    group.finish();
}

fn bench_full_queue(c: &mut Criterion) {
    let mut group = c.benchmark_group(module_path!());
    group.throughput(Throughput::Elements(MESSAGES as u64));

    group.bench_function("operation=full_reject impl=actor capacity=1", |b| {
        b.iter_batched(
            || {
                let (sender, receiver) = actor::Mailbox::<Message>::new(1);
                assert_eq!(sender.enqueue(Message::Reject(0)), Feedback::Ok);
                (sender, receiver)
            },
            |(sender, _receiver)| {
                for i in 0..MESSAGES as u64 {
                    black_box(sender.enqueue(black_box(Message::Reject(i))));
                }
            },
            BatchSize::LargeInput,
        );
    });

    group.bench_function("operation=full_reject impl=tokio_mpsc capacity=1", |b| {
        b.iter_batched(
            || {
                let (sender, receiver) = mpsc::channel::<Message>(1);
                sender.try_send(Message::Reject(0)).unwrap();
                (sender, receiver)
            },
            |(sender, _receiver)| {
                for i in 0..MESSAGES as u64 {
                    black_box(sender.try_send(black_box(Message::Reject(i))).unwrap_err());
                }
            },
            BatchSize::LargeInput,
        );
    });

    group.bench_function("operation=full_retain impl=actor capacity=1", |b| {
        b.iter_batched(
            || {
                let (sender, receiver) = actor::Mailbox::<Message>::new(1);
                assert_eq!(sender.enqueue(Message::Reject(0)), Feedback::Ok);
                (sender, receiver)
            },
            |(sender, _receiver)| {
                for i in 0..MESSAGES as u64 {
                    black_box(sender.enqueue(black_box(Message::Retain(i))));
                }
            },
            BatchSize::LargeInput,
        );
    });

    group.bench_function("operation=full_replace impl=actor capacity=1", |b| {
        b.iter_batched(
            || {
                let (sender, receiver) = actor::Mailbox::<Message>::new(1);
                assert_eq!(sender.enqueue(Message::Reject(0)), Feedback::Ok);
                assert_eq!(sender.enqueue(Message::Replace(0)), Feedback::Backoff);
                (sender, receiver)
            },
            |(sender, _receiver)| {
                for i in 0..MESSAGES as u64 {
                    black_box(sender.enqueue(black_box(Message::Replace(i))));
                }
            },
            BatchSize::LargeInput,
        );
    });

    group.finish();
}

fn fill_replace_queue(
    capacity: usize,
    newest: bool,
) -> (actor::Sender<Message>, actor::Receiver<Message>) {
    let (sender, receiver) = actor::Mailbox::<Message>::new(capacity);
    for i in 0..capacity {
        assert_eq!(sender.enqueue(Message::Reject(i as u64)), Feedback::Ok);
    }
    assert_eq!(sender.enqueue(Message::Replace(0)), Feedback::Backoff);
    if !newest {
        for i in 1..capacity {
            assert_eq!(sender.enqueue(Message::Retain(i as u64)), Feedback::Backoff);
        }
    }
    (sender, receiver)
}

fn bench_replace_hit(c: &mut Criterion) {
    let mut group = c.benchmark_group(module_path!());
    group.throughput(Throughput::Elements(MESSAGES as u64));

    for &capacity in REPLACE_CAPACITIES {
        group.bench_function(
            format!("operation=replace_hit impl=actor capacity={capacity} position=newest"),
            |b| {
                b.iter_batched(
                    || fill_replace_queue(capacity, true),
                    |(sender, _receiver)| {
                        for i in 0..MESSAGES as u64 {
                            let result = sender.enqueue(black_box(Message::Replace(i)));
                            debug_assert_eq!(result, Feedback::Backoff);
                            black_box(result);
                        }
                    },
                    BatchSize::LargeInput,
                );
            },
        );

        group.bench_function(
            format!("operation=replace_hit impl=actor capacity={capacity} position=oldest"),
            |b| {
                b.iter_batched(
                    || fill_replace_queue(capacity, false),
                    |(sender, _receiver)| {
                        for i in 0..MESSAGES as u64 {
                            let result = sender.enqueue(black_box(Message::Replace(i)));
                            debug_assert_eq!(result, Feedback::Backoff);
                            black_box(result);
                        }
                    },
                    BatchSize::LargeInput,
                );
            },
        );
    }

    group.finish();
}

fn bench_spsc_contended(c: &mut Criterion) {
    let mut group = c.benchmark_group(module_path!());
    group.throughput(Throughput::Elements(CONTENDED_MESSAGES as u64));

    group.bench_function(
        format!("operation=spsc_contended impl=actor capacity={CONTENDED_MESSAGES}"),
        |b| {
            b.iter(|| {
                let (sender, mut receiver) = actor::Mailbox::<Message>::new(CONTENDED_MESSAGES);
                std::thread::scope(|scope| {
                    let handle = scope.spawn(move || {
                        let mut received = 0;
                        while received < CONTENDED_MESSAGES {
                            match receiver.try_recv() {
                                Ok(message) => {
                                    black_box(message);
                                    received += 1;
                                }
                                Err(mpsc::error::TryRecvError::Empty) => std::hint::spin_loop(),
                                Err(error) => panic!("actor receiver closed early: {error:?}"),
                            }
                        }
                    });

                    for i in 0..CONTENDED_MESSAGES as u64 {
                        assert_eq!(sender.enqueue(Message::Reject(i)), Feedback::Ok);
                    }
                    handle.join().unwrap();
                });
            });
        },
    );

    group.bench_function(
        format!("operation=spsc_contended impl=tokio_mpsc capacity={CONTENDED_MESSAGES}"),
        |b| {
            b.iter(|| {
                let (sender, mut receiver) = mpsc::channel::<Message>(CONTENDED_MESSAGES);
                std::thread::scope(|scope| {
                    let handle = scope.spawn(move || {
                        let mut received = 0;
                        while received < CONTENDED_MESSAGES {
                            match receiver.try_recv() {
                                Ok(message) => {
                                    black_box(message);
                                    received += 1;
                                }
                                Err(mpsc::error::TryRecvError::Empty) => std::hint::spin_loop(),
                                Err(error) => panic!("tokio receiver closed early: {error:?}"),
                            }
                        }
                    });

                    for i in 0..CONTENDED_MESSAGES as u64 {
                        sender.try_send(Message::Reject(i)).unwrap();
                    }
                    handle.join().unwrap();
                });
            });
        },
    );

    group.finish();
}

fn run_actor_spsc_overlap(messages: usize, capacity: usize) {
    let (sender, mut receiver) = actor::Mailbox::<Message>::new(capacity);
    let start = Barrier::new(3);

    std::thread::scope(|scope| {
        let producer = scope.spawn(|| {
            start.wait();
            for i in 0..messages as u64 {
                assert_eq!(sender.enqueue(Message::Reject(i)), Feedback::Ok);
            }
        });

        let consumer = scope.spawn(|| {
            start.wait();
            let mut received = 0;
            while received < messages {
                match receiver.try_recv() {
                    Ok(message) => {
                        black_box(message);
                        received += 1;
                    }
                    Err(mpsc::error::TryRecvError::Empty) => std::hint::spin_loop(),
                    Err(error) => panic!("actor receiver closed early: {error:?}"),
                }
            }
        });

        start.wait();
        producer.join().unwrap();
        consumer.join().unwrap();
    });
}

fn run_tokio_spsc_overlap(messages: usize, capacity: usize) {
    let (sender, mut receiver) = mpsc::channel::<Message>(capacity);
    let start = Barrier::new(3);

    std::thread::scope(|scope| {
        let producer = scope.spawn(|| {
            start.wait();
            for i in 0..messages as u64 {
                sender.try_send(Message::Reject(i)).unwrap();
            }
        });

        let consumer = scope.spawn(|| {
            start.wait();
            let mut received = 0;
            while received < messages {
                match receiver.try_recv() {
                    Ok(message) => {
                        black_box(message);
                        received += 1;
                    }
                    Err(mpsc::error::TryRecvError::Empty) => std::hint::spin_loop(),
                    Err(error) => panic!("tokio receiver closed early: {error:?}"),
                }
            }
        });

        start.wait();
        producer.join().unwrap();
        consumer.join().unwrap();
    });
}

fn bench_spsc_overlap(c: &mut Criterion) {
    let mut group = c.benchmark_group(module_path!());
    group.throughput(Throughput::Elements(SPSC_OVERLAP_MESSAGES as u64));

    group.bench_function(
        format!("operation=spsc_overlap impl=actor capacity={SPSC_OVERLAP_MESSAGES}"),
        |b| {
            b.iter(|| {
                run_actor_spsc_overlap(SPSC_OVERLAP_MESSAGES, SPSC_OVERLAP_MESSAGES);
            });
        },
    );

    group.bench_function(
        format!("operation=spsc_overlap impl=tokio_mpsc capacity={SPSC_OVERLAP_MESSAGES}"),
        |b| {
            b.iter(|| {
                run_tokio_spsc_overlap(SPSC_OVERLAP_MESSAGES, SPSC_OVERLAP_MESSAGES);
            });
        },
    );

    group.finish();
}

fn bench_concurrent_enqueue(c: &mut Criterion) {
    let mut group = c.benchmark_group(module_path!());
    group.throughput(Throughput::Elements(CONTENDED_MESSAGES as u64));

    group.bench_function(
        format!(
            "operation=concurrent_enqueue impl=actor producers={PRODUCERS} capacity={CONTENDED_MESSAGES}"
        ),
        |b| {
            b.iter(|| {
                let (sender, _receiver) = actor::Mailbox::<Message>::new(CONTENDED_MESSAGES);
                std::thread::scope(|scope| {
                    for producer in 0..PRODUCERS {
                        let sender = sender.clone();
                        scope.spawn(move || {
                            let base = producer * PRODUCER_MESSAGES;
                            for offset in 0..PRODUCER_MESSAGES {
                                assert_eq!(
                                    sender.enqueue(Message::Reject((base + offset) as u64)),
                                    Feedback::Ok
                                );
                            }
                        });
                    }
                });
                black_box(sender);
            });
        },
    );

    group.bench_function(
        format!(
            "operation=concurrent_enqueue impl=tokio_mpsc producers={PRODUCERS} capacity={CONTENDED_MESSAGES}"
        ),
        |b| {
            b.iter(|| {
                let (sender, receiver) = mpsc::channel::<Message>(CONTENDED_MESSAGES);
                std::thread::scope(|scope| {
                    for producer in 0..PRODUCERS {
                        let sender = sender.clone();
                        scope.spawn(move || {
                            let base = producer * PRODUCER_MESSAGES;
                            for offset in 0..PRODUCER_MESSAGES {
                                sender
                                    .try_send(Message::Reject((base + offset) as u64))
                                    .unwrap();
                            }
                        });
                    }
                });
                black_box(receiver.len());
            });
        },
    );

    group.finish();
}

fn run_actor_try_send_contended(producers: usize, messages_per_producer: usize, capacity: usize) {
    let total = producers * messages_per_producer;
    let (sender, mut receiver) = actor::Mailbox::<Message>::new(capacity);

    std::thread::scope(|scope| {
        let handle = scope.spawn(move || {
            let mut received = 0;
            while received < total {
                match receiver.try_recv() {
                    Ok(message) => {
                        black_box(message);
                        received += 1;
                    }
                    Err(mpsc::error::TryRecvError::Empty) => std::hint::spin_loop(),
                    Err(error) => panic!("actor receiver closed early: {error:?}"),
                }
            }
        });

        for producer in 0..producers {
            let sender = sender.clone();
            scope.spawn(move || {
                let base = producer * messages_per_producer;
                for offset in 0..messages_per_producer {
                    let message = Message::Reject((base + offset) as u64);
                    loop {
                        match sender.enqueue(message) {
                            Feedback::Ok => break,
                            Feedback::Dropped => std::hint::spin_loop(),
                            result => panic!("unexpected actor enqueue result: {result:?}"),
                        }
                    }
                }
            });
        }

        handle.join().unwrap();
    });
}

fn run_tokio_try_send_contended(producers: usize, messages_per_producer: usize, capacity: usize) {
    let total = producers * messages_per_producer;
    let (sender, mut receiver) = mpsc::channel::<Message>(capacity);

    std::thread::scope(|scope| {
        let handle = scope.spawn(move || {
            let mut received = 0;
            while received < total {
                match receiver.try_recv() {
                    Ok(message) => {
                        black_box(message);
                        received += 1;
                    }
                    Err(mpsc::error::TryRecvError::Empty) => std::hint::spin_loop(),
                    Err(error) => panic!("tokio receiver closed early: {error:?}"),
                }
            }
        });

        for producer in 0..producers {
            let sender = sender.clone();
            scope.spawn(move || {
                let base = producer * messages_per_producer;
                for offset in 0..messages_per_producer {
                    let message = Message::Reject((base + offset) as u64);
                    loop {
                        match sender.try_send(message) {
                            Ok(()) => break,
                            Err(mpsc::error::TrySendError::Full(_)) => std::hint::spin_loop(),
                            Err(error) => panic!("unexpected tokio try_send result: {error:?}"),
                        }
                    }
                }
            });
        }

        handle.join().unwrap();
    });
}

fn run_actor_retain_contended(producers: usize, messages_per_producer: usize, capacity: usize) {
    let total = producers * messages_per_producer;
    let (sender, mut receiver) = actor::Mailbox::<Message>::new(capacity);

    std::thread::scope(|scope| {
        let handle = scope.spawn(move || {
            futures::executor::block_on(async {
                for _ in 0..total {
                    black_box(receiver.recv().await.unwrap());
                }
            });
        });

        for producer in 0..producers {
            let sender = sender.clone();
            scope.spawn(move || {
                let base = producer * messages_per_producer;
                for offset in 0..messages_per_producer {
                    assert!(sender
                        .enqueue(Message::Retain((base + offset) as u64))
                        .accepted());
                }
            });
        }

        handle.join().unwrap();
    });
}

fn run_tokio_send_contended(producers: usize, messages_per_producer: usize, capacity: usize) {
    let total = producers * messages_per_producer;
    let (sender, mut receiver) = mpsc::channel::<Message>(capacity);

    std::thread::scope(|scope| {
        let handle = scope.spawn(move || {
            futures::executor::block_on(async {
                for _ in 0..total {
                    black_box(receiver.recv().await.unwrap());
                }
            });
        });

        for producer in 0..producers {
            let sender = sender.clone();
            scope.spawn(move || {
                futures::executor::block_on(async {
                    let base = producer * messages_per_producer;
                    for offset in 0..messages_per_producer {
                        sender
                            .send(Message::Retain((base + offset) as u64))
                            .await
                            .unwrap();
                    }
                });
            });
        }

        handle.join().unwrap();
    });
}

fn bench_try_send_matrix(c: &mut Criterion) {
    let mut group = c.benchmark_group(module_path!());

    for &capacity in MATRIX_CAPACITIES {
        for &producers in MATRIX_PRODUCERS {
            let total = producers * MATRIX_MESSAGES_PER_PRODUCER;
            group.throughput(Throughput::Elements(total as u64));

            group.bench_function(
                format!(
                    "operation=try_send_matrix impl=actor producers={producers} capacity={capacity}"
                ),
                |b| {
                    b.iter(|| {
                        run_actor_try_send_contended(
                            producers,
                            MATRIX_MESSAGES_PER_PRODUCER,
                            capacity,
                        );
                    });
                },
            );

            group.bench_function(
                format!(
                    "operation=try_send_matrix impl=tokio_mpsc producers={producers} capacity={capacity}"
                ),
                |b| {
                    b.iter(|| {
                        run_tokio_try_send_contended(
                            producers,
                            MATRIX_MESSAGES_PER_PRODUCER,
                            capacity,
                        );
                    });
                },
            );
        }
    }

    group.finish();
}

fn bench_tokio_style(c: &mut Criterion) {
    let mut group = c.benchmark_group(module_path!());
    group.throughput(Throughput::Elements(TOKIO_STYLE_MESSAGES as u64));

    for capacity in [1_000_000, 100] {
        group.bench_function(
            format!("operation=tokio_style_contention impl=actor capacity={capacity}"),
            |b| {
                b.iter(|| {
                    run_actor_retain_contended(
                        TOKIO_STYLE_PRODUCERS,
                        TOKIO_STYLE_MESSAGES_PER_PRODUCER,
                        capacity,
                    );
                });
            },
        );

        group.bench_function(
            format!("operation=tokio_style_contention impl=tokio_mpsc capacity={capacity}"),
            |b| {
                b.iter(|| {
                    run_tokio_send_contended(
                        TOKIO_STYLE_PRODUCERS,
                        TOKIO_STYLE_MESSAGES_PER_PRODUCER,
                        capacity,
                    );
                });
            },
        );
    }

    group.bench_function("operation=tokio_style_uncontented impl=actor", |b| {
        b.iter(|| {
            let (sender, mut receiver) = actor::Mailbox::<Message>::new(1_000_000);
            for i in 0..TOKIO_STYLE_MESSAGES as u64 {
                assert_eq!(sender.enqueue(Message::Reject(i)), Feedback::Ok);
            }
            futures::executor::block_on(async {
                for _ in 0..TOKIO_STYLE_MESSAGES {
                    black_box(receiver.recv().await.unwrap());
                }
            });
        });
    });

    group.bench_function("operation=tokio_style_uncontented impl=tokio_mpsc", |b| {
        b.iter(|| {
            let (sender, mut receiver) = mpsc::channel::<Message>(1_000_000);
            futures::executor::block_on(async {
                for i in 0..TOKIO_STYLE_MESSAGES as u64 {
                    sender.send(Message::Reject(i)).await.unwrap();
                }
                for _ in 0..TOKIO_STYLE_MESSAGES {
                    black_box(receiver.recv().await.unwrap());
                }
            });
        });
    });

    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_enqueue_ready, bench_recv_ready, bench_round_trip_ready, bench_recv_waiting, bench_full_queue, bench_replace_hit, bench_spsc_contended, bench_spsc_overlap, bench_concurrent_enqueue, bench_try_send_matrix, bench_tokio_style,
}
