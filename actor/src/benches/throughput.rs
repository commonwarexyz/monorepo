use commonware_actor::{ingress, service::Builder, Actor};
use commonware_runtime::{
    benchmarks::{context, tokio},
    Handle, Spawner, Supervisor as _,
};
use commonware_utils::NZUsize;
use criterion::{criterion_group, BenchmarkGroup, Criterion, Throughput};
use futures::stream::{FuturesUnordered, StreamExt};
use std::{
    hint::black_box,
    num::NonZeroUsize,
    time::{Duration, Instant},
};

const MAILBOX_CAPACITY: usize = 4096;
const OVERFLOW_CAPACITY: usize = 1;
const READ_CONCURRENCY: usize = 256;
const MESSAGES: u64 = 1024;
const READS_PER_WRITE: u64 = 7;
const MIXED_CYCLES: u64 = 128;
const PRODUCERS: usize = 4;
const PRODUCER_MESSAGES: u64 = 512;

ingress! {
    ThroughputMailbox,

    pub tell Increment;
    pub ask Value -> u64;
    pub subscribe Read -> u64;
    pub ask read_write Drain -> u64;
}

struct ThroughputActor {
    value: u64,
    lane_batch: NonZeroUsize,
}

impl<E: Spawner> Actor<E> for ThroughputActor {
    type Mailbox = ThroughputMailbox;
    type Ingress = ThroughputMailboxMessage;
    type Error = std::convert::Infallible;
    type Snapshot = u64;
    type Args = ();

    fn snapshot(&self, _args: &Self::Args) -> Self::Snapshot {
        self.value
    }

    fn max_lane_batch(&self, _args: &Self::Args) -> NonZeroUsize {
        self.lane_batch
    }

    async fn on_read_only(
        _context: E,
        snapshot: Self::Snapshot,
        message: ThroughputMailboxReadOnlyMessage,
    ) -> Result<(), Self::Error> {
        match message {
            ThroughputMailboxReadOnlyMessage::Value { response }
            | ThroughputMailboxReadOnlyMessage::Read { response } => {
                let _ = response.send(snapshot);
                Ok(())
            }
        }
    }

    async fn on_read_write(
        &mut self,
        _context: &mut E,
        _args: &mut Self::Args,
        message: ThroughputMailboxReadWriteMessage,
    ) -> Result<(), Self::Error> {
        match message {
            ThroughputMailboxReadWriteMessage::Increment => {
                self.value += 1;
            }
            ThroughputMailboxReadWriteMessage::Drain { response } => {
                let _ = response.send(self.value);
            }
        }
        Ok(())
    }
}

fn start_single(
    label: &'static str,
    lane_batch: usize,
    value: u64,
    capacity: usize,
    read_concurrency: usize,
) -> (ThroughputMailbox, Handle<()>) {
    let context = context::get::<commonware_runtime::tokio::Context>();
    let actor = ThroughputActor {
        value,
        lane_batch: NZUsize!(lane_batch),
    };
    let (mailbox, service) = Builder::new(actor)
        .with_read_concurrency(NZUsize!(read_concurrency))
        .build_with_capacity(context.child(label), NZUsize!(capacity));
    (mailbox, service.start())
}

async fn stop_actor(mailbox: ThroughputMailbox, handle: Handle<()>) {
    drop(mailbox);
    handle.await.expect("service join failed");
}

async fn tell_flush(mailbox: &ThroughputMailbox, iters: u64, msgs: u64) -> Duration {
    let mut expected = 0;
    let start = Instant::now();
    for _ in 0..iters {
        for _ in 0..msgs {
            let feedback = mailbox.increment_internal();
            assert!(feedback.accepted());
            black_box(feedback);
        }
        expected += msgs;
        assert_eq!(
            mailbox.drain_internal().await.expect("drain ask failed"),
            expected
        );
    }
    start.elapsed()
}

async fn ask_readonly_seq(mailbox: &ThroughputMailbox, iters: u64, msgs: u64) -> Duration {
    let start = Instant::now();
    for _ in 0..iters {
        for _ in 0..msgs {
            black_box(mailbox.value_internal().await.expect("value ask failed"));
        }
    }
    start.elapsed()
}

async fn ask_readwrite_seq(mailbox: &ThroughputMailbox, iters: u64, msgs: u64) -> Duration {
    let start = Instant::now();
    for _ in 0..iters {
        for _ in 0..msgs {
            black_box(mailbox.drain_internal().await.expect("drain ask failed"));
        }
    }
    start.elapsed()
}

async fn ask_readonly_parallel(
    mailbox: &ThroughputMailbox,
    iters: u64,
    msgs: u64,
    window: usize,
) -> Duration {
    let start = Instant::now();
    for _ in 0..iters {
        let mut issued = 0;
        let mut completed = 0;
        let mut inflight = FuturesUnordered::new();
        while issued < msgs || completed < msgs {
            while issued < msgs && inflight.len() < window {
                let mailbox = mailbox.clone();
                inflight
                    .push(async move { mailbox.value_internal().await.expect("value ask failed") });
                issued += 1;
            }
            if let Some(value) = inflight.next().await {
                black_box(value);
                completed += 1;
            }
        }
    }
    start.elapsed()
}

async fn mixed_readonly_readwrite(mailbox: &ThroughputMailbox, iters: u64) -> Duration {
    let start = Instant::now();
    for _ in 0..iters {
        for _ in 0..MIXED_CYCLES {
            let mut reads = Vec::with_capacity(READS_PER_WRITE as usize);
            for _ in 0..READS_PER_WRITE {
                reads.push(mailbox.read_internal());
            }
            black_box(mailbox.drain_internal().await.expect("drain ask failed"));
            for read in reads {
                black_box(read.await.expect("read response missing"));
            }
        }
    }
    start.elapsed()
}

fn bench_tell_flush(group: &mut BenchmarkGroup<'_, criterion::measurement::WallTime>) {
    for lane_batch in [1usize, 8, 64] {
        group.throughput(Throughput::Elements(MESSAGES + 1));
        group.bench_function(
            format!("kind=tell_flush lane_batch={lane_batch} capacity={MAILBOX_CAPACITY} msgs={MESSAGES} flushes=1"),
            |b| {
                b.to_async(tokio_runner()).iter_custom(move |iters| async move {
                    let (mailbox, handle) = start_single(
                        "tell_flush",
                        lane_batch,
                        0,
                        MAILBOX_CAPACITY,
                        READ_CONCURRENCY,
                    );
                    let elapsed = tell_flush(&mailbox, iters, MESSAGES).await;
                    stop_actor(mailbox, handle).await;
                    elapsed
                });
            },
        );
    }
}

fn bench_tell_overflow(group: &mut BenchmarkGroup<'_, criterion::measurement::WallTime>) {
    group.throughput(Throughput::Elements(MESSAGES + 1));
    group.bench_function(
        format!(
            "kind=tell_flush lane_batch=64 capacity={OVERFLOW_CAPACITY} msgs={MESSAGES} flushes=1"
        ),
        |b| {
            b.to_async(tokio_runner())
                .iter_custom(move |iters| async move {
                    let (mailbox, handle) =
                        start_single("tell_overflow", 64, 0, OVERFLOW_CAPACITY, READ_CONCURRENCY);
                    let elapsed = tell_flush(&mailbox, iters, MESSAGES).await;
                    stop_actor(mailbox, handle).await;
                    elapsed
                });
        },
    );
}

fn bench_sequential_asks(group: &mut BenchmarkGroup<'_, criterion::measurement::WallTime>) {
    group.throughput(Throughput::Elements(MESSAGES));
    group.bench_function(
        format!("kind=ask_readonly_seq lane_batch=1 msgs={MESSAGES}"),
        |b| {
            b.to_async(tokio_runner())
                .iter_custom(move |iters| async move {
                    let (mailbox, handle) = start_single(
                        "ask_readonly_seq",
                        1,
                        42,
                        MAILBOX_CAPACITY,
                        READ_CONCURRENCY,
                    );
                    let elapsed = ask_readonly_seq(&mailbox, iters, MESSAGES).await;
                    stop_actor(mailbox, handle).await;
                    elapsed
                });
        },
    );

    group.bench_function(
        format!("kind=ask_readwrite_seq lane_batch=1 msgs={MESSAGES}"),
        |b| {
            b.to_async(tokio_runner())
                .iter_custom(move |iters| async move {
                    let (mailbox, handle) = start_single(
                        "ask_readwrite_seq",
                        1,
                        42,
                        MAILBOX_CAPACITY,
                        READ_CONCURRENCY,
                    );
                    let elapsed = ask_readwrite_seq(&mailbox, iters, MESSAGES).await;
                    stop_actor(mailbox, handle).await;
                    elapsed
                });
        },
    );
}

fn bench_parallel_reads(group: &mut BenchmarkGroup<'_, criterion::measurement::WallTime>) {
    for lane_batch in [1usize, 64] {
        for window in [8usize, 64] {
            group.throughput(Throughput::Elements(MESSAGES));
            group.bench_function(
                format!("kind=ask_readonly_parallel lane_batch={lane_batch} window={window} msgs={MESSAGES}"),
                |b| {
                    b.to_async(tokio_runner()).iter_custom(move |iters| async move {
                        let (mailbox, handle) = start_single(
                            "ask_readonly_parallel",
                            lane_batch,
                            42,
                            MAILBOX_CAPACITY,
                            READ_CONCURRENCY,
                        );
                        let elapsed =
                            ask_readonly_parallel(&mailbox, iters, MESSAGES, window).await;
                        stop_actor(mailbox, handle).await;
                        elapsed
                    });
                },
            );
        }
    }
}

fn bench_mixed_fence(group: &mut BenchmarkGroup<'_, criterion::measurement::WallTime>) {
    let messages = MIXED_CYCLES * (READS_PER_WRITE + 1);
    for lane_batch in [1usize, 64] {
        group.throughput(Throughput::Elements(messages));
        group.bench_function(
            format!(
                "kind=mixed_readonly_readwrite lane_batch={lane_batch} reads_per_write={READS_PER_WRITE} msgs={messages}"
            ),
            |b| {
                b.to_async(tokio_runner()).iter_custom(move |iters| async move {
                    let (mailbox, handle) = start_single(
                        "mixed_readonly_readwrite",
                        lane_batch,
                        42,
                        MAILBOX_CAPACITY,
                        READ_CONCURRENCY,
                    );
                    let elapsed = mixed_readonly_readwrite(&mailbox, iters).await;
                    stop_actor(mailbox, handle).await;
                    elapsed
                });
            },
        );
    }
}

async fn multi_lane_tell(
    first: &ThroughputMailbox,
    second: &ThroughputMailbox,
    iters: u64,
    msgs: u64,
    balanced: bool,
) -> Duration {
    let mut expected = 0;
    let start = Instant::now();
    for _ in 0..iters {
        for i in 0..msgs {
            let mailbox = if balanced && i % 2 == 1 {
                second
            } else {
                first
            };
            let feedback = mailbox.increment_internal();
            assert!(feedback.accepted());
            black_box(feedback);
        }
        expected += msgs;
        assert_eq!(
            second.drain_internal().await.expect("drain ask failed"),
            expected
        );
    }
    start.elapsed()
}

fn bench_multi_lane(group: &mut BenchmarkGroup<'_, criterion::measurement::WallTime>) {
    for lane_batch in [1usize, 64] {
        for (distribution, balanced) in [("hot", false), ("balanced", true)] {
            group.throughput(Throughput::Elements(MESSAGES + 1));
            group.bench_function(
                format!(
                    "kind=multi_lane_tell lanes=2 distribution={distribution} lane_batch={lane_batch} msgs={MESSAGES} flushes=1"
                ),
                |b| {
                    b.to_async(tokio_runner()).iter_custom(move |iters| async move {
                        let context = context::get::<commonware_runtime::tokio::Context>();
                        let actor = ThroughputActor {
                            value: 0,
                            lane_batch: NZUsize!(lane_batch),
                        };
                        let (lanes, service) = Builder::new(actor)
                            .with_lane(0usize, NZUsize!(MAILBOX_CAPACITY))
                            .with_lane(1usize, NZUsize!(MAILBOX_CAPACITY))
                            .build(context.child("multi_lane_tell"))
                            .expect("multi-lane build failed");
                        let mut lanes = lanes.into_inner();
                        let first = lanes.remove(&0).expect("first lane missing");
                        let second = lanes.remove(&1).expect("second lane missing");
                        let handle = service.start();

                        let elapsed =
                            multi_lane_tell(&first, &second, iters, MESSAGES, balanced).await;

                        drop(first);
                        stop_actor(second, handle).await;
                        elapsed
                    });
                },
            );
        }
    }
}

fn bench_cloned_producers(group: &mut BenchmarkGroup<'_, criterion::measurement::WallTime>) {
    let total = PRODUCERS as u64 * PRODUCER_MESSAGES;

    group.throughput(Throughput::Elements(total + 1));
    group.bench_function(
        format!("kind=producer_tell producers={PRODUCERS} msgs={total} flushes=1"),
        |b| {
            b.to_async(tokio_runner())
                .iter_custom(move |iters| async move {
                    let context = context::get::<commonware_runtime::tokio::Context>();
                    let actor = ThroughputActor {
                        value: 0,
                        lane_batch: NZUsize!(64),
                    };
                    let (mailbox, service) = Builder::new(actor)
                        .with_read_concurrency(NZUsize!(READ_CONCURRENCY))
                        .build_with_capacity(
                            context.child("producer_tell"),
                            NZUsize!(MAILBOX_CAPACITY),
                        );
                    let handle = service.start();

                    let start = Instant::now();
                    for _ in 0..iters {
                        let mut producers = FuturesUnordered::new();
                        for producer in 0..PRODUCERS {
                            let mailbox = mailbox.clone();
                            let context =
                                context.child("producer").with_attribute("index", producer);
                            producers.push(context.spawn(|_| async move {
                                for _ in 0..PRODUCER_MESSAGES {
                                    let feedback = mailbox.increment_internal();
                                    assert!(feedback.accepted());
                                    black_box(feedback);
                                }
                            }));
                        }
                        while let Some(result) = producers.next().await {
                            result.expect("producer join failed");
                        }
                        black_box(mailbox.drain_internal().await.expect("drain ask failed"));
                    }
                    let elapsed = start.elapsed();

                    stop_actor(mailbox, handle).await;
                    elapsed
                });
        },
    );

    group.throughput(Throughput::Elements(total));
    group.bench_function(
        format!("kind=producer_ask_readonly producers={PRODUCERS} msgs={total}"),
        |b| {
            b.to_async(tokio_runner())
                .iter_custom(move |iters| async move {
                    let context = context::get::<commonware_runtime::tokio::Context>();
                    let actor = ThroughputActor {
                        value: 42,
                        lane_batch: NZUsize!(64),
                    };
                    let (mailbox, service) = Builder::new(actor)
                        .with_read_concurrency(NZUsize!(READ_CONCURRENCY))
                        .build_with_capacity(
                            context.child("producer_ask_readonly"),
                            NZUsize!(MAILBOX_CAPACITY),
                        );
                    let handle = service.start();

                    let start = Instant::now();
                    for _ in 0..iters {
                        let mut producers = FuturesUnordered::new();
                        for producer in 0..PRODUCERS {
                            let mailbox = mailbox.clone();
                            let context =
                                context.child("producer").with_attribute("index", producer);
                            producers.push(context.spawn(|_| async move {
                                for _ in 0..PRODUCER_MESSAGES {
                                    black_box(
                                        mailbox.value_internal().await.expect("value ask failed"),
                                    );
                                }
                            }));
                        }
                        while let Some(result) = producers.next().await {
                            result.expect("producer join failed");
                        }
                    }
                    let elapsed = start.elapsed();

                    stop_actor(mailbox, handle).await;
                    elapsed
                });
        },
    );
}

fn tokio_runner() -> &'static tokio::Runner {
    static RUNNER: std::sync::OnceLock<tokio::Runner> = std::sync::OnceLock::new();
    RUNNER.get_or_init(|| {
        tokio::Runner::new(commonware_runtime::tokio::Config::new().with_worker_threads(4))
    })
}

fn bench_message_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group(module_path!());
    group.measurement_time(Duration::from_secs(3));
    group.sample_size(10);

    bench_tell_flush(&mut group);
    bench_tell_overflow(&mut group);
    bench_sequential_asks(&mut group);
    bench_parallel_reads(&mut group);
    bench_mixed_fence(&mut group);
    bench_multi_lane(&mut group);
    bench_cloned_producers(&mut group);

    group.finish();
}

criterion_group!(benches, bench_message_throughput);
