#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use bytes::Bytes;
use commonware_cryptography::{
    ed25519::{PrivateKey, PublicKey},
    Signer,
};
use commonware_resolver::{
    opaque::{self, Fetcher},
    Consumer, Delivery, Fetch, Resolver, TargetedResolver,
};
use commonware_runtime::{
    deterministic, telemetry::metrics::count_running_tasks, Clock, Runner, Supervisor as _,
};
use commonware_utils::{channel::oneshot, sync::Mutex, vec::NonEmptyVec, FuzzRng};
use libfuzzer_sys::fuzz_target;
use std::{
    collections::{HashMap, VecDeque},
    future::Future,
    num::NonZeroUsize,
    sync::Arc,
    time::Duration,
};

const MAX_OPERATIONS: usize = 256;
const MAX_RAW_BYTES: usize = 32_768;
const MAX_MISS_KEYS: usize = 16;
const MAX_MISS_ATTEMPTS: u8 = 4;
const MAX_BATCH: usize = 64;
const MIN_MAILBOX_SIZE: usize = 1;
const MAX_MAILBOX_SIZE: usize = 64;
const MIN_RETRY_MS: u64 = 1;
const MAX_RETRY_MS: u64 = 100;
const MAX_SLEEP_MS: u64 = 300;
const SETTLE_MS: u64 = 10;
const BURST_SUBSCRIBERS: u16 = 16;
const OPERATION_VARIANTS: u8 = 9;
const DRAIN_ROUNDS: usize = 8;

#[derive(Clone, Debug)]
enum Operation {
    Fetch { key: u8, sub: u16 },
    FetchAll { items: Vec<(u8, u16)> },
    FetchTargeted { key: u8, sub: u16 },
    FetchAllTargeted { items: Vec<(u8, u16)> },
    Retain { sub: u16 },
    Clear,
    Sleep { ms: u64 },
    Complete { valid: bool },
    Burst { key: u8 },
}

// Bound batch length during generation so parsing and allocation stay proportional
// to the remaining input (each (key, subscriber) pair is 3 bytes).
fn arbitrary_batch(u: &mut Unstructured<'_>) -> arbitrary::Result<Vec<(u8, u16)>> {
    let max = MAX_BATCH.min((u.len() / 3).max(1));
    let count = u.int_in_range(0..=max)?;
    let mut items = Vec::with_capacity(count);
    for _ in 0..count {
        items.push((u.arbitrary()?, u.arbitrary()?));
    }
    Ok(items)
}

impl<'a> Arbitrary<'a> for Operation {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let variant = u.int_in_range(0..=OPERATION_VARIANTS - 1)?;
        match variant {
            0 => Ok(Self::Fetch {
                key: u.arbitrary()?,
                sub: u.arbitrary()?,
            }),
            1 => Ok(Self::FetchAll {
                items: arbitrary_batch(u)?,
            }),
            2 => Ok(Self::FetchTargeted {
                key: u.arbitrary()?,
                sub: u.arbitrary()?,
            }),
            3 => Ok(Self::FetchAllTargeted {
                items: arbitrary_batch(u)?,
            }),
            4 => Ok(Self::Retain {
                sub: u.arbitrary()?,
            }),
            5 => Ok(Self::Clear),
            6 => Ok(Self::Sleep { ms: u.arbitrary()? }),
            7 => Ok(Self::Complete {
                valid: u.arbitrary()?,
            }),
            _ => Ok(Self::Burst {
                key: u.arbitrary()?,
            }),
        }
    }
}

#[derive(Clone, Debug)]
struct FuzzInput {
    raw_bytes: Vec<u8>,
    mailbox_size: usize,
    small_mailbox: bool,
    retry_ms: u64,
    // Per-key transient miss budget: the fetcher returns `None` this many times for the
    // key (driving retry scheduling) before it starts succeeding.
    misses: Vec<(u8, u8)>,
    operations: Vec<Operation>,
}

impl<'a> Arbitrary<'a> for FuzzInput {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let raw_len = u.len().min(MAX_RAW_BYTES);
        let raw_bytes = if raw_len == 0 {
            vec![0]
        } else {
            u.peek_bytes(raw_len)
                .expect("raw_len is in bounds")
                .to_vec()
        };
        let mailbox_size = if u.is_empty() {
            MIN_MAILBOX_SIZE
        } else {
            u.int_in_range(MIN_MAILBOX_SIZE..=MAX_MAILBOX_SIZE)?
        };
        // Bias toward a size-1 mailbox so bursts overflow into the ingress policy.
        let small_mailbox = !u.is_empty() && u.arbitrary()?;
        let retry_ms = if u.is_empty() {
            MIN_RETRY_MS
        } else {
            u.int_in_range(MIN_RETRY_MS..=MAX_RETRY_MS)?
        };
        let miss_keys = if u.is_empty() {
            0
        } else {
            u.int_in_range(0..=MAX_MISS_KEYS)?
        };
        let mut misses = Vec::with_capacity(miss_keys);
        for _ in 0..miss_keys {
            if u.is_empty() {
                break;
            }
            let key = u.arbitrary()?;
            let attempts = u.int_in_range(1..=MAX_MISS_ATTEMPTS)?;
            misses.push((key, attempts));
        }
        let max_ops = MAX_OPERATIONS.min((u.len() / 2).max(1));
        let count = if u.is_empty() {
            1
        } else {
            u.int_in_range(1..=max_ops)?
        };
        let mut operations = Vec::with_capacity(count);
        for _ in 0..count {
            operations.push(Operation::arbitrary(u)?);
        }
        Ok(Self {
            raw_bytes,
            mailbox_size,
            small_mailbox,
            retry_ms,
            misses,
            operations,
        })
    }
}

fn key_value(key: u8) -> Bytes {
    Bytes::from(vec![key; (key % 7) as usize + 1])
}

#[derive(Clone)]
struct FuzzFetcher {
    // Remaining transient misses per key; decremented on each fetch until the key succeeds.
    misses: Arc<Mutex<HashMap<u8, u8>>>,
}

impl Fetcher for FuzzFetcher {
    type Key = u8;
    type Value = Bytes;

    fn fetch(&self, key: Self::Key) -> impl Future<Output = Option<Self::Value>> + Send {
        let misses = self.misses.clone();
        async move {
            let mut misses = misses.lock();
            match misses.get_mut(&key) {
                Some(remaining) if *remaining > 0 => {
                    *remaining -= 1;
                    None
                }
                _ => Some(key_value(key)),
            }
        }
    }
}

type Pending = Arc<Mutex<VecDeque<oneshot::Sender<bool>>>>;

#[derive(Clone)]
struct GatedConsumer {
    pending: Pending,
}

impl GatedConsumer {
    fn new() -> (Self, Pending) {
        let pending: Pending = Arc::new(Mutex::new(VecDeque::new()));
        (
            Self {
                pending: pending.clone(),
            },
            pending,
        )
    }
}

impl Consumer for GatedConsumer {
    type Key = u8;
    type Value = Bytes;
    type Subscriber = u16;

    fn deliver(
        &mut self,
        delivery: Delivery<Self::Key, Self::Subscriber>,
        value: Self::Value,
    ) -> oneshot::Receiver<bool> {
        assert_eq!(value, key_value(delivery.key), "delivered unexpected bytes");
        let (tx, rx) = oneshot::channel();
        self.pending.lock().push_back(tx);
        rx
    }
}

fn run(input: FuzzInput) -> String {
    let cfg = deterministic::Config::new().with_rng(Box::new(FuzzRng::new(input.raw_bytes)));
    let executor = deterministic::Runner::new(cfg);
    executor.start(|context| async move {
        let misses: HashMap<u8, u8> = input.misses.iter().copied().collect();
        let fetcher = FuzzFetcher {
            misses: Arc::new(Mutex::new(misses)),
        };
        let (consumer, pending) = GatedConsumer::new();
        let mailbox_size = if input.small_mailbox {
            MIN_MAILBOX_SIZE
        } else {
            input.mailbox_size
        };
        let target = PrivateKey::from_seed(0).public_key();
        let mut resolver: opaque::Resolver<u8, u16, PublicKey> = opaque::init(
            context.child("resolver"),
            fetcher,
            consumer,
            NonZeroUsize::new(mailbox_size).unwrap(),
            Duration::from_millis(input.retry_ms),
        );
        context.sleep(Duration::from_millis(SETTLE_MS)).await;
        assert_eq!(count_running_tasks(&context, "resolver"), 1);

        for operation in input.operations {
            match operation {
                Operation::Fetch { key, sub } => {
                    assert!(resolver
                        .fetch(Fetch {
                            key,
                            subscriber: sub,
                            span: tracing::Span::none(),
                        })
                        .accepted());
                }
                Operation::FetchAll { items } => {
                    let fetches: Vec<Fetch<u8, u16>> = items
                        .into_iter()
                        .map(|(key, sub)| Fetch {
                            key,
                            subscriber: sub,
                            span: tracing::Span::none(),
                        })
                        .collect();
                    assert!(resolver.fetch_all(fetches).accepted());
                }
                Operation::FetchTargeted { key, sub } => {
                    // Opaque resolvers ignore target hints; this exercises that delegation.
                    assert!(resolver
                        .fetch_targeted(
                            Fetch {
                                key,
                                subscriber: sub,
                                span: tracing::Span::none(),
                            },
                            NonEmptyVec::new(target.clone()),
                        )
                        .accepted());
                }
                Operation::FetchAllTargeted { items } => {
                    let requests: Vec<(Fetch<u8, u16>, NonEmptyVec<PublicKey>)> = items
                        .into_iter()
                        .map(|(key, sub)| {
                            (
                                Fetch {
                                    key,
                                    subscriber: sub,
                                    span: tracing::Span::none(),
                                },
                                NonEmptyVec::new(target.clone()),
                            )
                        })
                        .collect();
                    assert!(resolver.fetch_all_targeted(requests).accepted());
                }
                Operation::Retain { sub } => {
                    assert!(resolver
                        .retain(move |_, subscriber| *subscriber == sub)
                        .accepted());
                }
                Operation::Clear => {
                    assert!(resolver.retain(|_, _| false).accepted());
                }
                Operation::Sleep { ms } => {
                    context
                        .sleep(Duration::from_millis(ms % MAX_SLEEP_MS + 1))
                        .await;
                }
                Operation::Complete { valid } => {
                    let sender = pending.lock().pop_front();
                    if let Some(sender) = sender {
                        let _ = sender.send(valid);
                    }
                }
                Operation::Burst { key } => {
                    // Synchronously enqueue many same-key fetches with distinct subscribers so
                    // they pile into the ingress overflow policy (effective when size-1): the
                    // unit metadata merge runs and merge_subscribers pushes new subscribers.
                    for sub in 0..BURST_SUBSCRIBERS {
                        assert!(resolver
                            .fetch(Fetch {
                                key,
                                subscriber: sub,
                                span: tracing::Span::none(),
                            })
                            .accepted());
                    }
                    assert!(resolver.retain(|_, sub| *sub % 2 == 0).accepted());
                    assert!(resolver.retain(|_, _| true).accepted());
                }
            }
            context.sleep(Duration::from_millis(SETTLE_MS)).await;
        }

        // Complete gated deliveries until none remain. A valid completion can trigger
        // a redelivery to later subscribers (a new gated sender), so iterate a bounded
        // number of rounds to exercise those redelivery chains.
        for _ in 0..DRAIN_ROUNDS {
            let senders: Vec<_> = std::mem::take(&mut *pending.lock()).into_iter().collect();
            if senders.is_empty() {
                break;
            }
            for sender in senders {
                let _ = sender.send(true);
            }
            context.sleep(Duration::from_millis(SETTLE_MS)).await;
        }
        // Dropping the only mailbox sender closes the actor; confirm it exits (no leak).
        drop(resolver);
        context.sleep(Duration::from_millis(SETTLE_MS)).await;
        assert_eq!(count_running_tasks(&context, "resolver"), 0);
        context.auditor().state()
    })
}

fn fuzz(input: FuzzInput) {
    let first = run(input.clone());
    let second = run(input);
    assert_eq!(first, second);
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
