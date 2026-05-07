use commonware_utils::channel::{
    actor::{self, Enqueue, FullPolicy, MessagePolicy},
    mpsc,
};
use criterion::{criterion_group, BatchSize, Criterion, Throughput};
use futures::pin_mut;
use std::{
    collections::VecDeque,
    future::{poll_fn, Future},
    hint::black_box,
    task::Poll,
};

const CAPACITY: usize = 1024;
const CONTENDED_MESSAGES: usize = 64 * 1024;
const MESSAGES: usize = 1024;
const PRODUCERS: usize = 4;
const PRODUCER_MESSAGES: usize = CONTENDED_MESSAGES / PRODUCERS;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Message {
    Reject(u64),
    Retain(u64),
    Replace(u64),
}

impl MessagePolicy for Message {
    fn kind(&self) -> &'static str {
        match self {
            Self::Reject(_) => "reject",
            Self::Retain(_) => "retain",
            Self::Replace(_) => "replace",
        }
    }

    fn full_policy(&self) -> FullPolicy {
        match self {
            Self::Reject(_) => FullPolicy::Reject,
            Self::Retain(_) => FullPolicy::Retain,
            Self::Replace(_) => FullPolicy::Replace,
        }
    }

    fn replace(queue: &mut VecDeque<Self>, message: Self) -> Result<(), Self> {
        match message {
            Self::Replace(_) => actor::replace_last(queue, message, |pending| {
                matches!(pending, Self::Replace(_))
            }),
            message => Err(message),
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
                || actor::channel::<Message>(CAPACITY),
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
                    let (sender, receiver) = actor::channel::<Message>(CAPACITY);
                    for i in 0..MESSAGES as u64 {
                        assert_eq!(sender.enqueue(Message::Reject(i)), Enqueue::Queued);
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
                || actor::channel::<Message>(CAPACITY),
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
                || actor::channel::<Message>(CAPACITY),
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

                            assert_eq!(sender.enqueue(Message::Reject(i)), Enqueue::Queued);
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
                let (sender, _receiver) = actor::channel::<Message>(1);
                assert_eq!(sender.enqueue(Message::Reject(0)), Enqueue::Queued);
                sender
            },
            |sender| {
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
                let (sender, _receiver) = mpsc::channel::<Message>(1);
                sender.try_send(Message::Reject(0)).unwrap();
                sender
            },
            |sender| {
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
                let (sender, _receiver) = actor::channel_with_retention::<Message>(1, MESSAGES);
                assert_eq!(sender.enqueue(Message::Reject(0)), Enqueue::Queued);
                sender
            },
            |sender| {
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
                let (sender, _receiver) = actor::channel::<Message>(1);
                assert_eq!(sender.enqueue(Message::Replace(0)), Enqueue::Queued);
                sender
            },
            |sender| {
                for i in 0..MESSAGES as u64 {
                    black_box(sender.enqueue(black_box(Message::Replace(i))));
                }
            },
            BatchSize::LargeInput,
        );
    });

    group.finish();
}

fn bench_spsc_contended(c: &mut Criterion) {
    let mut group = c.benchmark_group(module_path!());
    group.throughput(Throughput::Elements(CONTENDED_MESSAGES as u64));

    group.bench_function(
        format!("operation=spsc_contended impl=actor capacity={CONTENDED_MESSAGES}"),
        |b| {
            b.iter(|| {
                let (sender, mut receiver) = actor::channel::<Message>(CONTENDED_MESSAGES);
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
                        assert_eq!(sender.enqueue(Message::Reject(i)), Enqueue::Queued);
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

fn bench_concurrent_enqueue(c: &mut Criterion) {
    let mut group = c.benchmark_group(module_path!());
    group.throughput(Throughput::Elements(CONTENDED_MESSAGES as u64));

    group.bench_function(
        format!(
            "operation=concurrent_enqueue impl=actor producers={PRODUCERS} capacity={CONTENDED_MESSAGES}"
        ),
        |b| {
            b.iter(|| {
                let (sender, _receiver) = actor::channel::<Message>(CONTENDED_MESSAGES);
                std::thread::scope(|scope| {
                    for producer in 0..PRODUCERS {
                        let sender = sender.clone();
                        scope.spawn(move || {
                            let base = producer * PRODUCER_MESSAGES;
                            for offset in 0..PRODUCER_MESSAGES {
                                assert_eq!(
                                    sender.enqueue(Message::Reject((base + offset) as u64)),
                                    Enqueue::Queued
                                );
                            }
                        });
                    }
                });
                black_box(sender.len());
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

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_enqueue_ready, bench_recv_ready, bench_round_trip_ready, bench_recv_waiting, bench_full_queue, bench_spsc_contended, bench_concurrent_enqueue,
}
