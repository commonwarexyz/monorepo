#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use bytes::Bytes;
use commonware_cryptography::{
    ed25519::{PrivateKey, PublicKey},
    Signer,
};
use commonware_p2p::{
    simulated::{Link, Network},
    Manager as _,
};
use commonware_resolver::{
    p2p::{
        mocks::{Consumer, Key, Producer},
        Config, Engine,
    },
    Resolver,
};
use commonware_runtime::{
    deterministic, telemetry::metrics::count_running_tasks, Clock, Quota, Runner, Supervisor as _,
};
use commonware_utils::{ordered::Set, vec::NonEmptyVec, NZUsize};
use libfuzzer_sys::fuzz_target;
use rand::{rngs::StdRng, Rng, SeedableRng};
use std::{
    collections::{BTreeMap, BTreeSet},
    num::{NonZeroU32, NonZeroUsize},
    time::Duration,
};

const MAX_OPERATIONS: usize = 256;
const MIN_PEERS: usize = 3;
const MAX_PEERS: usize = 8;
const MAX_INITIAL_ITEMS: usize = 32;
const MAX_BATCH_ITEMS: usize = 256;
const MAX_VALUE_LEN: usize = 128;
const MIN_SLEEP_DURATION_MS: u64 = 1;
const MAX_SLEEP_DURATION_MS: u64 = 500;
const MIN_LINK_LATENCY_MS: u64 = 1;
const MAX_LINK_LATENCY_MS: u64 = 100;
const MAX_LINK_JITTER_MS: u64 = 50;
const MIN_SUCCESS_RATE_PERCENT: u8 = 0;
const MAX_SUCCESS_RATE_PERCENT: u8 = 100;
const PERCENT_DENOMINATOR: f64 = 100.0;
const MAX_NETWORK_SIZE: u32 = 1024 * 1024;
const MIN_MAILBOX_SIZE: usize = 1;
const MAX_MAILBOX_SIZE: usize = 128;
const MIN_QUOTA_PER_SECOND: u32 = 1;
const MAX_QUOTA_PER_SECOND: u32 = 64;
const MIN_FETCH_INITIAL_MS: u64 = 1;
const MAX_FETCH_INITIAL_MS: u64 = 100;
const MIN_FETCH_TIMEOUT_MS: u64 = 10;
const MAX_FETCH_TIMEOUT_MS: u64 = 300;
const MIN_FETCH_RETRY_TIMEOUT_MS: u64 = 1;
const MAX_FETCH_RETRY_TIMEOUT_MS: u64 = 100;
const MIN_COMPLETION_WINDOW_MS: u64 = 200;
const MAX_COMPLETION_WINDOW_MS: u64 = 2_000;
const CHANNEL: u64 = 0;
const TRACKED_PEER_SETS: usize = 8;
const TASK_SETTLE_MS: u64 = 100;
const TRACK_MIN_ID: u64 = 1;
const TRACK_ALL_ID: u64 = u64::MAX;

#[derive(Clone, Debug)]
struct Item {
    key: u8,
    value: Vec<u8>,
}

#[derive(Clone, Debug)]
enum Operation {
    Fetch {
        peer: usize,
        key: u8,
    },
    FetchAll {
        peer: usize,
        keys: Vec<u8>,
    },
    FetchTargeted {
        peer: usize,
        key: u8,
        target: usize,
        target_mask: u8,
    },
    FetchAllTargeted {
        peer: usize,
        requests: Vec<TargetedRequest>,
    },
    Cancel {
        peer: usize,
        key: u8,
    },
    Clear {
        peer: usize,
    },
    Retain {
        peer: usize,
        divisor: u8,
        remainder: u8,
    },
    Sleep {
        duration_ms: u64,
    },
    Link {
        from: usize,
        to: usize,
        latency_ms: u64,
        jitter_ms: u64,
        success_rate_percent: u8,
    },
    RemoveLink {
        from: usize,
        to: usize,
    },
    Track {
        id: u64,
        primary_mask: u8,
    },
    CompleteFetch {
        peer: usize,
        key: u8,
        settle_ms: u64,
    },
}

#[derive(Clone, Debug)]
struct TargetedRequest {
    key: u8,
    target: usize,
    target_mask: u8,
}

#[derive(Clone, Debug)]
struct FuzzInput {
    seed: u64,
    peers: usize,
    latency_ms: u64,
    jitter_ms: u64,
    success_rate_percent: u8,
    mailbox_size: usize,
    quota_per_second: u32,
    fetch_initial_ms: u64,
    fetch_timeout_ms: u64,
    fetch_retry_timeout_ms: u64,
    completion_window_ms: u64,
    priority_requests: bool,
    priority_responses: bool,
    items: Vec<Item>,
    operations: Vec<Operation>,
}

impl<'a> Arbitrary<'a> for Item {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let value_len = u.int_in_range(0..=MAX_VALUE_LEN)?;
        Ok(Self {
            key: u.arbitrary()?,
            value: u.bytes(value_len)?.to_vec(),
        })
    }
}

impl<'a> Arbitrary<'a> for Operation {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        match u.int_in_range(0..=11)? {
            0 => Ok(Self::Fetch {
                peer: u.arbitrary()?,
                key: u.arbitrary()?,
            }),
            1 => {
                let count = u.int_in_range(0..=MAX_BATCH_ITEMS)?;
                let mut keys = Vec::with_capacity(count);
                for _ in 0..count {
                    keys.push(u.arbitrary()?);
                }
                Ok(Self::FetchAll {
                    peer: u.arbitrary()?,
                    keys,
                })
            }
            2 => Ok(Self::FetchTargeted {
                peer: u.arbitrary()?,
                key: u.arbitrary()?,
                target: u.arbitrary()?,
                target_mask: u.arbitrary()?,
            }),
            3 => {
                let count = u.int_in_range(0..=MAX_BATCH_ITEMS)?;
                let mut requests = Vec::with_capacity(count);
                for _ in 0..count {
                    requests.push(u.arbitrary()?);
                }
                Ok(Self::FetchAllTargeted {
                    peer: u.arbitrary()?,
                    requests,
                })
            }
            4 => Ok(Self::Cancel {
                peer: u.arbitrary()?,
                key: u.arbitrary()?,
            }),
            5 => Ok(Self::Clear {
                peer: u.arbitrary()?,
            }),
            6 => Ok(Self::Retain {
                peer: u.arbitrary()?,
                divisor: u.int_in_range(2..=u8::MAX)?,
                remainder: u.arbitrary()?,
            }),
            7 => Ok(Self::Sleep {
                duration_ms: u.int_in_range(MIN_SLEEP_DURATION_MS..=MAX_SLEEP_DURATION_MS)?,
            }),
            8 => Ok(Self::Link {
                from: u.arbitrary()?,
                to: u.arbitrary()?,
                latency_ms: u.int_in_range(MIN_LINK_LATENCY_MS..=MAX_LINK_LATENCY_MS)?,
                jitter_ms: u.int_in_range(0..=MAX_LINK_JITTER_MS)?,
                success_rate_percent: u
                    .int_in_range(MIN_SUCCESS_RATE_PERCENT..=MAX_SUCCESS_RATE_PERCENT)?,
            }),
            9 => Ok(Self::RemoveLink {
                from: u.arbitrary()?,
                to: u.arbitrary()?,
            }),
            10 => Ok(Self::Track {
                id: u.int_in_range(TRACK_MIN_ID..=TRACK_ALL_ID - 1)?,
                primary_mask: u.arbitrary()?,
            }),
            _ => Ok(Self::CompleteFetch {
                peer: u.arbitrary()?,
                key: u.arbitrary()?,
                settle_ms: u.int_in_range(MIN_COMPLETION_WINDOW_MS..=MAX_COMPLETION_WINDOW_MS)?,
            }),
        }
    }
}

impl<'a> Arbitrary<'a> for TargetedRequest {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self {
            key: u.arbitrary()?,
            target: u.arbitrary()?,
            target_mask: u.arbitrary()?,
        })
    }
}

impl<'a> Arbitrary<'a> for FuzzInput {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let seed = u.arbitrary()?;
        let peers = u.int_in_range(MIN_PEERS..=MAX_PEERS)?;
        let latency_ms = u.int_in_range(MIN_LINK_LATENCY_MS..=MAX_LINK_LATENCY_MS)?;
        let jitter_ms = u.int_in_range(0..=MAX_LINK_JITTER_MS)?;
        let success_rate_percent =
            u.int_in_range(MIN_SUCCESS_RATE_PERCENT..=MAX_SUCCESS_RATE_PERCENT)?;
        let mailbox_size = u.int_in_range(MIN_MAILBOX_SIZE..=MAX_MAILBOX_SIZE)?;
        let quota_per_second = u.int_in_range(MIN_QUOTA_PER_SECOND..=MAX_QUOTA_PER_SECOND)?;
        let fetch_initial_ms = u.int_in_range(MIN_FETCH_INITIAL_MS..=MAX_FETCH_INITIAL_MS)?;
        let fetch_timeout_ms = u.int_in_range(MIN_FETCH_TIMEOUT_MS..=MAX_FETCH_TIMEOUT_MS)?;
        let fetch_retry_timeout_ms =
            u.int_in_range(MIN_FETCH_RETRY_TIMEOUT_MS..=MAX_FETCH_RETRY_TIMEOUT_MS)?;
        let completion_window_ms =
            u.int_in_range(MIN_COMPLETION_WINDOW_MS..=MAX_COMPLETION_WINDOW_MS)?;
        let item_count = u.int_in_range(1..=MAX_INITIAL_ITEMS)?;
        let mut items = Vec::with_capacity(item_count);
        for _ in 0..item_count {
            items.push(u.arbitrary()?);
        }
        let operation_count = u.int_in_range(1..=MAX_OPERATIONS)?;
        let mut operations = Vec::with_capacity(operation_count);
        for _ in 0..operation_count {
            operations.push(u.arbitrary()?);
        }
        Ok(Self {
            seed,
            peers,
            latency_ms,
            jitter_ms,
            success_rate_percent,
            mailbox_size,
            quota_per_second,
            fetch_initial_ms,
            fetch_timeout_ms,
            fetch_retry_timeout_ms,
            completion_window_ms,
            priority_requests: u.arbitrary()?,
            priority_responses: u.arbitrary()?,
            items,
            operations,
        })
    }
}

fn link(latency_ms: u64, jitter_ms: u64, success_rate_percent: u8) -> Link {
    Link {
        latency: Duration::from_millis(latency_ms),
        jitter: Duration::from_millis(jitter_ms),
        success_rate: f64::from(success_rate_percent) / PERCENT_DENOMINATOR,
    }
}

fn targets(peers: &[PublicKey], first: usize, mask: u8) -> NonEmptyVec<PublicKey> {
    assert!(peers.len() <= u8::BITS as usize);
    let mut targets = NonEmptyVec::new(peers[first % peers.len()].clone());
    for (index, peer) in peers.iter().enumerate() {
        if (mask & (1 << index)) != 0 && !targets.contains(peer) {
            targets.push(peer.clone());
        }
    }
    targets
}

fn tracked(peers: &[PublicKey], mask: u8) -> Set<PublicKey> {
    let mut selected = Vec::new();
    for (index, peer) in peers.iter().enumerate() {
        if (mask & (1 << index)) != 0 {
            selected.push(peer.clone());
        }
    }
    if selected.is_empty() {
        selected.push(peers[0].clone());
    }
    Set::try_from(selected).unwrap()
}

fn producer_holds(key: &Key, peer: usize, peers: usize) -> bool {
    let holder_count = (peers / 2).max(1);
    (key.0 as usize + peer * holder_count) % peers < holder_count
}

fn drain_outputs(
    outputs: &mut [commonware_utils::channel::mpsc::UnboundedReceiver<(Key, Bytes)>],
    expected: &BTreeMap<Key, Bytes>,
    delivered: &mut [BTreeSet<Key>],
) {
    for (index, output) in outputs.iter_mut().enumerate() {
        while let Ok((key, value)) = output.try_recv() {
            let expected_value = expected.get(&key).expect("unexpected delivered key");
            assert_eq!(&value, expected_value);
            delivered[index].insert(key);
        }
    }
}

async fn make_reliable(
    oracle: &commonware_p2p::simulated::Oracle<PublicKey, deterministic::Context>,
    peers: &[PublicKey],
    link: Link,
) {
    for from in peers {
        for to in peers {
            if from != to {
                oracle
                    .add_link(from.clone(), to.clone(), link.clone())
                    .await
                    .unwrap();
            }
        }
    }
}

fn run(input: FuzzInput) -> String {
    let executor = deterministic::Runner::seeded(input.seed);
    executor.start(|context| async move {
        let mut rng = StdRng::seed_from_u64(input.seed);
        let schemes = (0..input.peers)
            .map(|_| PrivateKey::from_seed(rng.gen()))
            .collect::<Vec<_>>();
        let peers = schemes
            .iter()
            .map(|scheme| scheme.public_key())
            .collect::<Vec<_>>();
        let (network, oracle) = Network::new_with_peers(
            context.child("network"),
            commonware_p2p::simulated::Config {
                max_size: MAX_NETWORK_SIZE,
                disconnect_on_block: false,
                tracked_peer_sets: NZUsize!(TRACKED_PEER_SETS),
            },
            peers.clone(),
        )
        .await;
        network.start();
        let mut manager = oracle.manager();
        assert!(manager
            .track(0, Set::try_from(peers.clone()).unwrap())
            .accepted());
        make_reliable(
            &oracle,
            &peers,
            link(
                input.latency_ms,
                input.jitter_ms,
                input.success_rate_percent,
            ),
        )
        .await;
        let mut expected = BTreeMap::new();
        for item in input.items {
            expected.insert(Key(item.key), Bytes::from(item.value));
        }
        let mut producers = vec![Producer::<Key, Bytes>::default(); peers.len()];
        for (index, producer) in producers.iter_mut().enumerate() {
            for (key, value) in &expected {
                if producer_holds(key, index, peers.len()) {
                    producer.insert(key.clone(), value.clone());
                }
            }
        }
        let mut mailboxes = Vec::with_capacity(peers.len());
        let mut outputs = Vec::with_capacity(peers.len());
        let mut handles = Vec::with_capacity(peers.len());
        for (index, scheme) in schemes.into_iter().enumerate() {
            let (mut consumer, output) = Consumer::<Key, Bytes>::new();
            for (key, value) in &expected {
                consumer.add_expected(key.clone(), value.clone());
            }
            let (sender, receiver) = oracle
                .control(scheme.public_key())
                .register(
                    CHANNEL,
                    Quota::per_second(NonZeroU32::new(input.quota_per_second).unwrap()),
                )
                .await
                .unwrap();
            let (engine, mailbox) = Engine::new(
                context.child("resolver").with_attribute("peer", index),
                Config {
                    peer_provider: oracle.manager(),
                    blocker: oracle.control(scheme.public_key()),
                    consumer,
                    producer: producers[index].clone(),
                    mailbox_size: NonZeroUsize::new(input.mailbox_size).unwrap(),
                    me: Some(scheme.public_key()),
                    initial: Duration::from_millis(input.fetch_initial_ms),
                    timeout: Duration::from_millis(input.fetch_timeout_ms),
                    fetch_retry_timeout: Duration::from_millis(input.fetch_retry_timeout_ms),
                    priority_requests: input.priority_requests,
                    priority_responses: input.priority_responses,
                },
            );
            handles.push(engine.start((sender, receiver)));
            mailboxes.push(mailbox);
            outputs.push(output);
        }
        context.sleep(Duration::from_millis(TASK_SETTLE_MS)).await;
        assert_eq!(count_running_tasks(&context, "resolver"), input.peers);
        let mut delivered = vec![BTreeSet::new(); peers.len()];
        for operation in input.operations {
            match operation {
                Operation::Fetch { peer, key } => {
                    let index = peer % mailboxes.len();
                    assert!(mailboxes[index].fetch(Key(key)).accepted());
                }
                Operation::FetchAll { peer, keys } => {
                    let index = peer % mailboxes.len();
                    assert!(mailboxes[index]
                        .fetch_all(keys.into_iter().map(Key).collect())
                        .accepted());
                }
                Operation::FetchTargeted {
                    peer,
                    key,
                    target,
                    target_mask,
                } => {
                    let index = peer % mailboxes.len();
                    let targets = targets(&peers, target, target_mask);
                    assert!(mailboxes[index]
                        .fetch_targeted(Key(key), targets)
                        .accepted());
                }
                Operation::FetchAllTargeted { peer, requests } => {
                    let index = peer % mailboxes.len();
                    let requests = requests
                        .into_iter()
                        .map(
                            |TargetedRequest {
                                 key,
                                 target,
                                 target_mask,
                             }| {
                                (Key(key), targets(&peers, target, target_mask))
                            },
                        )
                        .collect();
                    assert!(mailboxes[index].fetch_all_targeted(requests).accepted());
                }
                Operation::Cancel { peer, key } => {
                    let index = peer % mailboxes.len();
                    assert!(mailboxes[index].cancel(Key(key)).accepted());
                }
                Operation::Clear { peer } => {
                    let index = peer % mailboxes.len();
                    assert!(mailboxes[index].clear().accepted());
                }
                Operation::Retain {
                    peer,
                    divisor,
                    remainder,
                } => {
                    let index = peer % mailboxes.len();
                    assert!(mailboxes[index]
                        .retain(move |key| key.0 % divisor == remainder % divisor)
                        .accepted());
                }
                Operation::Sleep { duration_ms } => {
                    context.sleep(Duration::from_millis(duration_ms)).await;
                }
                Operation::Link {
                    from,
                    to,
                    latency_ms,
                    jitter_ms,
                    success_rate_percent,
                } => {
                    let from = from % peers.len();
                    let to = to % peers.len();
                    if from != to {
                        oracle
                            .add_link(
                                peers[from].clone(),
                                peers[to].clone(),
                                link(latency_ms, jitter_ms, success_rate_percent),
                            )
                            .await
                            .unwrap();
                    }
                }
                Operation::RemoveLink { from, to } => {
                    let from = from % peers.len();
                    let to = to % peers.len();
                    if from != to {
                        let _ = oracle
                            .remove_link(peers[from].clone(), peers[to].clone())
                            .await;
                    }
                }
                Operation::Track { id, primary_mask } => {
                    let mut manager = oracle.manager();
                    assert!(manager.track(id, tracked(&peers, primary_mask)).accepted());
                }
                Operation::CompleteFetch {
                    peer,
                    key,
                    settle_ms,
                } => {
                    let key = expected
                        .keys()
                        .nth(key as usize % expected.len())
                        .unwrap()
                        .clone();
                    make_reliable(
                        &oracle,
                        &peers,
                        link(MIN_LINK_LATENCY_MS, 0, MAX_SUCCESS_RATE_PERCENT),
                    )
                    .await;
                    let mut manager = oracle.manager();
                    assert!(manager
                        .track(TRACK_ALL_ID, Set::try_from(peers.clone()).unwrap())
                        .accepted());
                    assert!(manager
                        .track(0, Set::try_from(peers.clone()).unwrap())
                        .accepted());
                    let index = peer % mailboxes.len();
                    let settle = Duration::from_millis(
                        settle_ms
                            .max(input.completion_window_ms)
                            .max(input.fetch_timeout_ms + input.fetch_retry_timeout_ms),
                    );
                    assert!(mailboxes[index].clear().accepted());
                    context.sleep(settle).await;
                    drain_outputs(&mut outputs, &expected, &mut delivered);
                    assert!(mailboxes[index].cancel(key.clone()).accepted());
                    context.sleep(settle).await;
                    drain_outputs(&mut outputs, &expected, &mut delivered);
                    let mut oracle_window = vec![BTreeSet::new(); peers.len()];
                    assert!(mailboxes[index].fetch(key.clone()).accepted());
                    context.sleep(settle).await;
                    drain_outputs(&mut outputs, &expected, &mut oracle_window);
                    for (peer_idx, keys) in oracle_window.iter().enumerate() {
                        delivered[peer_idx].extend(keys.iter().cloned());
                    }
                    assert!(oracle_window[index].contains(&key));
                }
            }
            drain_outputs(&mut outputs, &expected, &mut delivered);
        }
        context
            .sleep(Duration::from_millis(input.completion_window_ms))
            .await;
        drain_outputs(&mut outputs, &expected, &mut delivered);
        for handle in handles {
            handle.abort();
        }
        context.sleep(Duration::from_millis(TASK_SETTLE_MS)).await;
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
