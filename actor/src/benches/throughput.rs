use commonware_actor::{ingress, service::ServiceBuilder, Actor};
use commonware_runtime::{
    benchmarks::{context, tokio},
    Metrics, Spawner,
};
use commonware_utils::{channel::fallible::OneshotExt, test_rng};
use criterion::{criterion_group, Criterion, Throughput};
use futures::stream::{FuturesUnordered, StreamExt};
use rand::RngCore;
use std::{
    hint::black_box,
    num::NonZeroUsize,
    time::{Duration, Instant},
};

ingress! {
    ThroughputMailbox,

    pub tell Increment;
    pub ask Value -> u64;
    pub ask read_write Drain -> u64;
}

struct ThroughputActor {
    value: u64,
    lane_batch: NonZeroUsize,
}

#[derive(Clone, Copy)]
enum MixedOp {
    Tell,
    AskReadOnly,
    AskReadWrite,
}

impl<E: Spawner> Actor<E> for ThroughputActor {
    type Mailbox = ThroughputMailbox;
    type Ingress = ThroughputMailboxMessage;
    type Error = std::convert::Infallible;
    type Args = ();
    type Snapshot = u64;

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
            ThroughputMailboxReadOnlyMessage::Value { response } => {
                response.send_lossy(snapshot);
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
                Ok(())
            }
            ThroughputMailboxReadWriteMessage::Drain { response } => {
                response.send_lossy(self.value);
                Ok(())
            }
        }
    }
}

fn deterministic_mixed_ops(
    len: usize,
    tell_weight: u32,
    ask_readonly_weight: u32,
    ask_readwrite_weight: u32,
) -> Vec<MixedOp> {
    let total = tell_weight + ask_readonly_weight + ask_readwrite_weight;
    assert!(total > 0, "total weight must be non-zero");

    let mut rng = test_rng();
    let mut ops = Vec::with_capacity(len);
    for _ in 0..len {
        let ticket = (rng.next_u64() % u64::from(total)) as u32;
        let op = if ticket < tell_weight {
            MixedOp::Tell
        } else if ticket < tell_weight + ask_readonly_weight {
            MixedOp::AskReadOnly
        } else {
            MixedOp::AskReadWrite
        };
        ops.push(op);
    }

    ops
}

fn bench_message_throughput(c: &mut Criterion) {
    let runner =
        tokio::Runner::new(commonware_runtime::tokio::Config::new().with_worker_threads(4));
    let mut group = c.benchmark_group(module_path!());
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(10);

    for lane_batch in [1usize, 8, 64] {
        for msgs in [256u64, 1024] {
            group.throughput(Throughput::Elements(msgs));
            group.bench_function(
                format!("kind=tell lane_batch={lane_batch} msgs={msgs}"),
                |b| {
                    b.to_async(&runner).iter_custom(move |iters| async move {
                        let context = context::get::<commonware_runtime::tokio::Context>();
                        let actor = ThroughputActor {
                            value: 0,
                            lane_batch: NonZeroUsize::new(lane_batch)
                                .expect("lane batch must be non-zero"),
                        };
                        let (mailbox, service) = ServiceBuilder::new(actor).build_with_capacity(
                            context.with_label("tell_throughput"),
                            NonZeroUsize::new(4096).expect("mailbox capacity must be non-zero"),
                        );
                        let handle = service.start();

                        let mut expected = 0u64;
                        let start = Instant::now();
                        for _ in 0..iters {
                            for _ in 0..msgs {
                                mailbox.increment().await.expect("increment failed");
                            }
                            expected += msgs;
                        }
                        let elapsed = start.elapsed();

                        let observed = mailbox.drain().await.expect("drain ask failed");
                        assert_eq!(observed, expected);

                        drop(mailbox);
                        handle.await.expect("service join failed");
                        elapsed
                    });
                },
            );
        }
    }

    for lane_batch in [1usize, 8, 64] {
        for msgs in [256u64, 1024] {
            group.throughput(Throughput::Elements(msgs));
            group.bench_function(
                format!("kind=ask_readonly_seq lane_batch={lane_batch} msgs={msgs}"),
                |b| {
                    b.to_async(&runner).iter_custom(move |iters| async move {
                        let context = context::get::<commonware_runtime::tokio::Context>();
                        let actor = ThroughputActor {
                            value: 42,
                            lane_batch: NonZeroUsize::new(lane_batch)
                                .expect("lane batch must be non-zero"),
                        };
                        let (mailbox, service) = ServiceBuilder::new(actor).build_with_capacity(
                            context.with_label("ask_throughput"),
                            NonZeroUsize::new(4096).expect("mailbox capacity must be non-zero"),
                        );
                        let handle = service.start();

                        let start = Instant::now();
                        for _ in 0..iters {
                            for _ in 0..msgs {
                                black_box(mailbox.value().await.expect("value ask failed"));
                            }
                        }
                        let elapsed = start.elapsed();

                        drop(mailbox);
                        handle.await.expect("service join failed");
                        elapsed
                    });
                },
            );
        }
    }

    for lane_batch in [1usize, 8, 64] {
        for window in [8usize, 64] {
            for msgs in [256u64, 1024] {
                group.throughput(Throughput::Elements(msgs));
                group.bench_function(
                    format!(
                        "kind=ask_readonly_parallel lane_batch={lane_batch} window={window} msgs={msgs}"
                    ),
                    |b| {
                        b.to_async(&runner).iter_custom(move |iters| async move {
                            let context = context::get::<commonware_runtime::tokio::Context>();
                            let actor = ThroughputActor {
                                value: 42,
                                lane_batch: NonZeroUsize::new(lane_batch)
                                    .expect("lane batch must be non-zero"),
                            };
                            let (mailbox, service) = ServiceBuilder::new(actor)
                                .with_read_concurrency(
                                    NonZeroUsize::new(256)
                                        .expect("read concurrency must be non-zero"),
                                )
                                .build_with_capacity(
                                    context.with_label("ask_parallel_throughput"),
                                    NonZeroUsize::new(4096)
                                        .expect("mailbox capacity must be non-zero"),
                                );
                            let handle = service.start();

                            let start = Instant::now();
                            for _ in 0..iters {
                                let mut issued = 0u64;
                                let mut completed = 0u64;
                                let mut inflight = FuturesUnordered::new();
                                while issued < msgs || completed < msgs {
                                    while issued < msgs && inflight.len() < window {
                                        let mailbox = mailbox.clone();
                                        inflight.push(async move {
                                            mailbox.value().await.expect("value ask failed")
                                        });
                                        issued += 1;
                                    }
                                    if let Some(value) = inflight.next().await {
                                        black_box(value);
                                        completed += 1;
                                    }
                                }
                            }
                            let elapsed = start.elapsed();

                            drop(mailbox);
                            handle.await.expect("service join failed");
                            elapsed
                        });
                    },
                );
            }
        }
    }

    for lane_batch in [1usize, 8, 64] {
        for msgs in [256u64, 1024] {
            group.throughput(Throughput::Elements(msgs));
            group.bench_function(
                format!("kind=ask_readwrite_seq lane_batch={lane_batch} msgs={msgs}"),
                |b| {
                    b.to_async(&runner).iter_custom(move |iters| async move {
                        let context = context::get::<commonware_runtime::tokio::Context>();
                        let actor = ThroughputActor {
                            value: 42,
                            lane_batch: NonZeroUsize::new(lane_batch)
                                .expect("lane batch must be non-zero"),
                        };
                        let (mailbox, service) = ServiceBuilder::new(actor).build_with_capacity(
                            context.with_label("ask_readwrite_throughput"),
                            NonZeroUsize::new(4096).expect("mailbox capacity must be non-zero"),
                        );
                        let handle = service.start();

                        let start = Instant::now();
                        for _ in 0..iters {
                            for _ in 0..msgs {
                                black_box(mailbox.drain().await.expect("drain ask failed"));
                            }
                        }
                        let elapsed = start.elapsed();

                        drop(mailbox);
                        handle.await.expect("service join failed");
                        elapsed
                    });
                },
            );
        }
    }

    for lane_batch in [1usize, 8, 64] {
        for (mix, tell_weight, ask_readonly_weight, ask_readwrite_weight) in [
            ("balanced", 60u32, 30u32, 10u32),
            ("write_heavy", 80u32, 15u32, 5u32),
        ] {
            for msgs in [256u64, 1024] {
                let ops = deterministic_mixed_ops(
                    msgs as usize,
                    tell_weight,
                    ask_readonly_weight,
                    ask_readwrite_weight,
                );
                group.throughput(Throughput::Elements(msgs));
                group.bench_function(
                    format!("kind=mixed_seq mix={mix} lane_batch={lane_batch} msgs={msgs}"),
                    |b| {
                        b.to_async(&runner).iter_custom({
                            let ops = ops.clone();
                            move |iters| {
                                let ops = ops.clone();
                                async move {
                                    let context =
                                        context::get::<commonware_runtime::tokio::Context>();
                                    let actor = ThroughputActor {
                                        value: 0,
                                        lane_batch: NonZeroUsize::new(lane_batch)
                                            .expect("lane batch must be non-zero"),
                                    };
                                    let (mailbox, service) = ServiceBuilder::new(actor)
                                        .build_with_capacity(
                                            context.with_label("mixed_throughput"),
                                            NonZeroUsize::new(4096)
                                                .expect("mailbox capacity must be non-zero"),
                                        );
                                    let handle = service.start();

                                    let mut expected = 0u64;
                                    let start = Instant::now();
                                    for _ in 0..iters {
                                        for op in &ops {
                                            match op {
                                                MixedOp::Tell => {
                                                    mailbox
                                                        .increment()
                                                        .await
                                                        .expect("increment failed");
                                                    expected += 1;
                                                }
                                                MixedOp::AskReadOnly => {
                                                    let value = mailbox
                                                        .value()
                                                        .await
                                                        .expect("value ask failed");
                                                    assert_eq!(value, expected);
                                                    black_box(value);
                                                }
                                                MixedOp::AskReadWrite => {
                                                    let value = mailbox
                                                        .drain()
                                                        .await
                                                        .expect("drain ask failed");
                                                    assert_eq!(value, expected);
                                                    black_box(value);
                                                }
                                            }
                                        }
                                    }
                                    let elapsed = start.elapsed();

                                    drop(mailbox);
                                    handle.await.expect("service join failed");
                                    elapsed
                                }
                            }
                        });
                    },
                );
            }
        }
    }

    group.finish();
}

criterion_group!(benches, bench_message_throughput);
