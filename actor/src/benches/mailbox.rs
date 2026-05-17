use commonware_actor::{mailbox, Feedback};
use commonware_runtime::{
    telemetry::metrics::{Metric, Registered, Registration},
    Metrics, Name, Supervisor,
};
use commonware_utils::NZUsize;
use criterion::{criterion_group, BatchSize, Criterion, Throughput};
use futures::pin_mut;
use std::{
    collections::VecDeque,
    future::{poll_fn, Future},
    hint::black_box,
    task::Poll,
};

const CAPACITY: usize = 1024;
const MESSAGES: usize = 1024;
const PRODUCERS: usize = 4;
const PRODUCER_MESSAGES: usize = 16 * 1024;
const REPLACE_CAPACITY: usize = 1024;

#[derive(Clone, Copy, Debug, Default)]
struct NoopMetrics;

impl Supervisor for NoopMetrics {
    fn name(&self) -> Name {
        Name::default()
    }

    fn child(&self, _label: &'static str) -> Self {
        Self
    }

    fn with_attribute(self, _key: &'static str, _value: impl std::fmt::Display) -> Self {
        self
    }
}

impl Metrics for NoopMetrics {
    fn register<N: Into<String>, H: Into<String>, M: Metric>(
        &self,
        _name: N,
        _help: H,
        metric: M,
    ) -> Registered<M> {
        Registered::with_registration(metric, Registration::from(()))
    }

    fn encode(&self) -> String {
        String::new()
    }
}

fn new<T: mailbox::Policy>(
    capacity: std::num::NonZeroUsize,
) -> (mailbox::Sender<T>, mailbox::Receiver<T>) {
    mailbox::new(NoopMetrics, capacity)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Policy {
    Drop,
    Spill,
    Replace,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Message {
    policy: Policy,
}

impl Message {
    const fn drop() -> Self {
        Self {
            policy: Policy::Drop,
        }
    }

    const fn spill() -> Self {
        Self {
            policy: Policy::Spill,
        }
    }

    const fn replace() -> Self {
        Self {
            policy: Policy::Replace,
        }
    }
}

impl mailbox::Policy for Message {
    type Overflow = VecDeque<Self>;

    fn handle(overflow: &mut VecDeque<Self>, message: Self) -> bool {
        match message.policy {
            Policy::Drop => false,
            Policy::Spill => {
                overflow.push_back(message);
                true
            }
            Policy::Replace => {
                if let Some(pending) = overflow
                    .iter_mut()
                    .rev()
                    .find(|pending| pending.policy == Policy::Replace)
                {
                    *pending = message;
                } else {
                    overflow.push_back(message);
                }
                true
            }
        }
    }
}

fn bench_enqueue_ready(c: &mut Criterion) {
    let mut group = c.benchmark_group(format!("{}::enqueue_ready", module_path!()));
    group.throughput(Throughput::Elements(MESSAGES as u64));

    group.bench_function(format!("capacity={CAPACITY}"), |b| {
        b.iter_batched(
            || new::<Message>(NZUsize!(CAPACITY)),
            |(sender, _receiver)| {
                for _ in 0..MESSAGES {
                    let result = sender.enqueue(black_box(Message::drop()));
                    assert_eq!(result, Feedback::Ok);
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
                let (sender, receiver) = new::<Message>(NZUsize!(CAPACITY));
                for _ in 0..MESSAGES {
                    assert_eq!(sender.enqueue(Message::drop()), Feedback::Ok);
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

fn bench_try_recv_overflow(c: &mut Criterion) {
    let mut group = c.benchmark_group(format!("{}::try_recv_overflow", module_path!()));
    group.throughput(Throughput::Elements((CAPACITY + MESSAGES) as u64));

    group.bench_function(format!("capacity={CAPACITY} overflow={MESSAGES}"), |b| {
        b.iter_batched(
            || {
                let (sender, receiver) = new::<Message>(NZUsize!(CAPACITY));
                for _ in 0..CAPACITY {
                    assert_eq!(sender.enqueue(Message::drop()), Feedback::Ok);
                }
                for _ in 0..MESSAGES {
                    assert_eq!(sender.enqueue(Message::spill()), Feedback::Backoff);
                }
                receiver
            },
            |mut receiver| {
                for _ in 0..(CAPACITY + MESSAGES) {
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
            || new::<Message>(NZUsize!(CAPACITY)),
            |(sender, mut receiver)| {
                for _ in 0..MESSAGES {
                    let result = sender.enqueue(black_box(Message::drop()));
                    assert_eq!(result, Feedback::Ok);
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
            || new::<Message>(NZUsize!(1)),
            |(sender, mut receiver)| {
                futures::executor::block_on(async {
                    for _ in 0..MESSAGES {
                        let next = receiver.recv();
                        pin_mut!(next);
                        poll_fn(|cx| {
                            let pending = next.as_mut().poll(cx).is_pending();
                            assert!(pending);
                            Poll::Ready(())
                        })
                        .await;

                        let result = sender.enqueue(Message::drop());
                        assert_eq!(result, Feedback::Ok);
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
                let (sender, receiver) = new::<Message>(NZUsize!(1));
                assert_eq!(sender.enqueue(Message::drop()), Feedback::Ok);
                (sender, receiver)
            },
            |(sender, _receiver)| {
                for _ in 0..MESSAGES {
                    let result = sender.enqueue(black_box(Message::drop()));
                    assert_eq!(result, Feedback::Rejected);
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
                let (sender, receiver) = new::<Message>(NZUsize!(1));
                assert_eq!(sender.enqueue(Message::drop()), Feedback::Ok);
                (sender, receiver)
            },
            |(sender, _receiver)| {
                for _ in 0..MESSAGES {
                    let result = sender.enqueue(black_box(Message::spill()));
                    assert_eq!(result, Feedback::Backoff);
                    black_box(result);
                }
            },
            BatchSize::LargeInput,
        );
    });

    group.finish();
}

fn replace_queue(newest: bool) -> (mailbox::Sender<Message>, mailbox::Receiver<Message>) {
    let (sender, receiver) = new::<Message>(NZUsize!(REPLACE_CAPACITY));

    for _ in 0..REPLACE_CAPACITY {
        assert_eq!(sender.enqueue(Message::drop()), Feedback::Ok);
    }
    assert_eq!(sender.enqueue(Message::replace()), Feedback::Backoff);

    if !newest {
        for _ in 1..REPLACE_CAPACITY {
            assert_eq!(sender.enqueue(Message::spill()), Feedback::Backoff);
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
                        for _ in 0..MESSAGES {
                            let result = sender.enqueue(black_box(Message::replace()));
                            assert_eq!(result, Feedback::Backoff);
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
            let (sender, _receiver) = new::<Message>(NZUsize!(total));

            std::thread::scope(|scope| {
                for _ in 0..PRODUCERS {
                    let sender = sender.clone();
                    scope.spawn(move || {
                        for _ in 0..PRODUCER_MESSAGES {
                            let result = sender.enqueue(Message::drop());
                            assert_eq!(result, Feedback::Ok);
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
        bench_try_recv_overflow,
        bench_round_trip_ready,
        bench_recv_waiting,
        bench_overflow_drop,
        bench_overflow_spill,
        bench_overflow_replace,
        bench_concurrent_enqueue,
}
