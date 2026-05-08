use commonware_actor::{self as actor, Backpressure, Feedback, MessagePolicy};
use commonware_utils::NZUsize;
use criterion::{criterion_group, BatchSize, Criterion, Throughput};
use futures::pin_mut;
use std::{
    future::{poll_fn, Future},
    hint::black_box,
    task::Poll,
};

const CAPACITY: usize = 1024;
const MESSAGES: usize = 1024;
const PRODUCERS: usize = 4;
const PRODUCER_MESSAGES: usize = 16 * 1024;
const REPLACE_CAPACITY: usize = 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Policy {
    DropOnOverflow,
    Spill,
    Replace,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Message {
    policy: Policy,
    _value: u64,
}

impl Message {
    const fn drop_on_overflow(value: u64) -> Self {
        Self {
            policy: Policy::DropOnOverflow,
            _value: value,
        }
    }

    const fn spill(value: u64) -> Self {
        Self {
            policy: Policy::Spill,
            _value: value,
        }
    }

    const fn replace(value: u64) -> Self {
        Self {
            policy: Policy::Replace,
            _value: value,
        }
    }
}

impl MessagePolicy for Message {
    fn handle(overflow: &mut actor::Overflow<'_, Self>, message: Self) -> Backpressure {
        match message.policy {
            Policy::DropOnOverflow => Backpressure::dropped(),
            Policy::Spill => overflow.spill(message),
            Policy::Replace => {
                let result =
                    overflow.replace_last(message, |pending| pending.policy == Policy::Replace);
                overflow.replace_or_spill(result)
            }
        }
    }
}

fn bench_enqueue_ready(c: &mut Criterion) {
    let mut group = c.benchmark_group(format!("{}::enqueue_ready", module_path!()));
    group.throughput(Throughput::Elements(MESSAGES as u64));

    group.bench_function(format!("capacity={CAPACITY}"), |b| {
        b.iter_batched(
            || actor::Mailbox::<Message>::new(NZUsize!(CAPACITY)),
            |(sender, _receiver)| {
                for i in 0..MESSAGES as u64 {
                    let result = sender.enqueue(black_box(Message::drop_on_overflow(i)));
                    debug_assert_eq!(result, Feedback::Ok);
                    black_box(result);
                }
            },
            BatchSize::LargeInput,
        );
    });

    group.finish();
}

fn bench_try_recv_ready(c: &mut Criterion) {
    let mut group = c.benchmark_group(format!("{}::try_recv_ready", module_path!()));
    group.throughput(Throughput::Elements(MESSAGES as u64));

    group.bench_function(format!("capacity={CAPACITY}"), |b| {
        b.iter_batched(
            || {
                let (sender, receiver) = actor::Mailbox::<Message>::new(NZUsize!(CAPACITY));
                for i in 0..MESSAGES as u64 {
                    assert_eq!(sender.enqueue(Message::drop_on_overflow(i)), Feedback::Ok);
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
    });

    group.finish();
}

fn bench_round_trip_ready(c: &mut Criterion) {
    let mut group = c.benchmark_group(format!("{}::round_trip_ready", module_path!()));
    group.throughput(Throughput::Elements(MESSAGES as u64));

    group.bench_function(format!("capacity={CAPACITY}"), |b| {
        b.iter_batched(
            || actor::Mailbox::<Message>::new(NZUsize!(CAPACITY)),
            |(sender, mut receiver)| {
                for i in 0..MESSAGES as u64 {
                    let result = sender.enqueue(black_box(Message::drop_on_overflow(i)));
                    debug_assert_eq!(result, Feedback::Ok);
                    black_box(result);
                    black_box(receiver.try_recv().unwrap());
                }
            },
            BatchSize::LargeInput,
        );
    });

    group.finish();
}

fn bench_recv_waiting(c: &mut Criterion) {
    let mut group = c.benchmark_group(format!("{}::recv_waiting", module_path!()));
    group.throughput(Throughput::Elements(MESSAGES as u64));

    group.bench_function("capacity=1", |b| {
        b.iter_batched(
            || actor::Mailbox::<Message>::new(NZUsize!(1)),
            |(sender, mut receiver)| {
                futures::executor::block_on(async {
                    for i in 0..MESSAGES as u64 {
                        let next = receiver.recv();
                        pin_mut!(next);
                        poll_fn(|cx| {
                            let pending = next.as_mut().poll(cx).is_pending();
                            debug_assert!(pending);
                            Poll::Ready(())
                        })
                        .await;

                        let result = sender.enqueue(Message::drop_on_overflow(i));
                        debug_assert_eq!(result, Feedback::Ok);
                        black_box(result);
                        black_box(next.await.unwrap());
                    }
                });
            },
            BatchSize::LargeInput,
        );
    });

    group.finish();
}

fn bench_overflow_drop(c: &mut Criterion) {
    let mut group = c.benchmark_group(format!("{}::overflow_drop", module_path!()));
    group.throughput(Throughput::Elements(MESSAGES as u64));

    group.bench_function("capacity=1", |b| {
        b.iter_batched(
            || {
                let (sender, receiver) = actor::Mailbox::<Message>::new(NZUsize!(1));
                assert_eq!(sender.enqueue(Message::drop_on_overflow(0)), Feedback::Ok);
                (sender, receiver)
            },
            |(sender, _receiver)| {
                for i in 0..MESSAGES as u64 {
                    let result = sender.enqueue(black_box(Message::drop_on_overflow(i)));
                    debug_assert_eq!(result, Feedback::Dropped);
                    black_box(result);
                }
            },
            BatchSize::LargeInput,
        );
    });

    group.finish();
}

fn bench_overflow_spill(c: &mut Criterion) {
    let mut group = c.benchmark_group(format!("{}::overflow_spill", module_path!()));
    group.throughput(Throughput::Elements(MESSAGES as u64));

    group.bench_function("capacity=1", |b| {
        b.iter_batched(
            || {
                let (sender, receiver) = actor::Mailbox::<Message>::new(NZUsize!(1));
                assert_eq!(sender.enqueue(Message::drop_on_overflow(0)), Feedback::Ok);
                (sender, receiver)
            },
            |(sender, _receiver)| {
                for i in 0..MESSAGES as u64 {
                    let result = sender.enqueue(black_box(Message::spill(i)));
                    debug_assert_eq!(result, Feedback::Backoff);
                    black_box(result);
                }
            },
            BatchSize::LargeInput,
        );
    });

    group.finish();
}

fn replace_queue(newest: bool) -> (actor::Sender<Message>, actor::Receiver<Message>) {
    let (sender, receiver) = actor::Mailbox::<Message>::new(NZUsize!(REPLACE_CAPACITY));

    for i in 0..REPLACE_CAPACITY {
        assert_eq!(
            sender.enqueue(Message::drop_on_overflow(i as u64)),
            Feedback::Ok
        );
    }
    assert_eq!(sender.enqueue(Message::replace(0)), Feedback::Backoff);

    if !newest {
        for i in 1..REPLACE_CAPACITY {
            assert_eq!(sender.enqueue(Message::spill(i as u64)), Feedback::Backoff);
        }
    }

    (sender, receiver)
}

fn bench_overflow_replace(c: &mut Criterion) {
    let mut group = c.benchmark_group(format!("{}::overflow_replace", module_path!()));
    group.throughput(Throughput::Elements(MESSAGES as u64));

    for (position, newest) in [("newest", true), ("oldest", false)] {
        group.bench_function(
            format!("capacity={REPLACE_CAPACITY} position={position}"),
            |b| {
                b.iter_batched(
                    || replace_queue(newest),
                    |(sender, _receiver)| {
                        for i in 0..MESSAGES as u64 {
                            let result = sender.enqueue(black_box(Message::replace(i)));
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

fn bench_concurrent_enqueue(c: &mut Criterion) {
    let total = PRODUCERS * PRODUCER_MESSAGES;
    let mut group = c.benchmark_group(format!("{}::concurrent_enqueue", module_path!()));
    group.throughput(Throughput::Elements(total as u64));

    group.bench_function(format!("producers={PRODUCERS} capacity={total}"), |b| {
        b.iter(|| {
            let (sender, _receiver) = actor::Mailbox::<Message>::new(NZUsize!(total));

            std::thread::scope(|scope| {
                for producer in 0..PRODUCERS {
                    let sender = sender.clone();
                    scope.spawn(move || {
                        let base = producer * PRODUCER_MESSAGES;
                        for offset in 0..PRODUCER_MESSAGES {
                            let result =
                                sender.enqueue(Message::drop_on_overflow((base + offset) as u64));
                            debug_assert_eq!(result, Feedback::Ok);
                            black_box(result);
                        }
                    });
                }
            });

            black_box(sender);
        });
    });

    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets =
        bench_enqueue_ready,
        bench_try_recv_ready,
        bench_round_trip_ready,
        bench_recv_waiting,
        bench_overflow_drop,
        bench_overflow_spill,
        bench_overflow_replace,
        bench_concurrent_enqueue,
}
