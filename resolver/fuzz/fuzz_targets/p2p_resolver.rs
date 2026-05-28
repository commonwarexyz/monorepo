#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use bytes::Bytes;
use commonware_cryptography::{
    ed25519::{PrivateKey, PublicKey},
    Signer,
};
use commonware_p2p::{
    simulated::{Error as NetworkError, Link, Network},
    Manager as _,
};
use commonware_resolver::{
    p2p::{
        mocks::{Consumer, Key, Producer},
        Config, Engine,
    },
    Resolver, TargetedResolver,
};
use commonware_runtime::{
    deterministic, telemetry::metrics::count_running_tasks, Clock, Quota, Runner, Supervisor as _,
};
use commonware_utils::{ordered::Set, vec::NonEmptyVec, FuzzRng, NZUsize};
use libfuzzer_sys::fuzz_target;
use std::{
    collections::{BTreeMap, BTreeSet},
    num::{NonZeroU32, NonZeroUsize},
    time::Duration,
};

const MAX_OPERATIONS: usize = 256;
// Keeps runtime RNG snapshots bounded; cargo-fuzz defaults to 4096-byte inputs.
const MAX_RAW_BYTES: usize = 32_768;
const OPERATION_BYTE_COST_ESTIMATE: usize = 5;
const PREAMBLE_BYTE_RESERVE: usize = 16;
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
const MAX_TRACK_ID: u64 = 1024;
const DEFAULT_SUCCESS_RATE_PERCENT: u8 = MAX_SUCCESS_RATE_PERCENT;
const DEFAULT_MAILBOX_SIZE: usize = MAX_MAILBOX_SIZE;
const DEFAULT_QUOTA_PER_SECOND: u32 = MAX_QUOTA_PER_SECOND;
const DEFAULT_FETCH_TIMEOUT_MS: u64 = MAX_FETCH_TIMEOUT_MS;
// Keep in sync with the match arms in Operation::arbitrary.
const OPERATION_VARIANTS: u8 = 13;

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
    Burst {
        peer: usize,
        key: u8,
    },
}

#[derive(Arbitrary, Clone, Debug)]
struct TargetedRequest {
    key: u8,
    #[arbitrary(with = arbitrary_peer)]
    target: usize,
    target_mask: u8,
}

#[derive(Clone, Debug)]
struct FuzzInput {
    raw_bytes: Vec<u8>,
    peers: usize,
    latency_ms: u64,
    jitter_ms: u64,
    success_rate_percent: u8,
    mailbox_size: usize,
    small_mailbox: bool,
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
        let key = u.arbitrary()?;
        let value_len = u.int_in_range(0..=MAX_VALUE_LEN.min(u.len().saturating_sub(1)))?;
        Ok(Self {
            key,
            value: u.bytes(value_len)?.to_vec(),
        })
    }
}

fn arbitrary_peer(u: &mut Unstructured<'_>) -> arbitrary::Result<usize> {
    u.int_in_range(0..=MAX_PEERS - 1)
}

fn arbitrary_divisor(u: &mut Unstructured<'_>) -> arbitrary::Result<u8> {
    u.int_in_range(2..=u8::MAX)
}

fn arbitrary_sleep_duration(u: &mut Unstructured<'_>) -> arbitrary::Result<u64> {
    u.int_in_range(MIN_SLEEP_DURATION_MS..=MAX_SLEEP_DURATION_MS)
}

fn arbitrary_link_latency(u: &mut Unstructured<'_>) -> arbitrary::Result<u64> {
    u.int_in_range(MIN_LINK_LATENCY_MS..=MAX_LINK_LATENCY_MS)
}

fn arbitrary_link_jitter(u: &mut Unstructured<'_>) -> arbitrary::Result<u64> {
    u.int_in_range(0..=MAX_LINK_JITTER_MS)
}

fn arbitrary_success_rate(u: &mut Unstructured<'_>) -> arbitrary::Result<u8> {
    u.int_in_range(MIN_SUCCESS_RATE_PERCENT..=MAX_SUCCESS_RATE_PERCENT)
}

fn arbitrary_track_id(u: &mut Unstructured<'_>) -> arbitrary::Result<u64> {
    u.int_in_range(TRACK_MIN_ID..=MAX_TRACK_ID)
}

fn arbitrary_completion_window(u: &mut Unstructured<'_>) -> arbitrary::Result<u64> {
    u.int_in_range(MIN_COMPLETION_WINDOW_MS..=MAX_COMPLETION_WINDOW_MS)
}

fn arbitrary_keys(u: &mut Unstructured<'_>) -> arbitrary::Result<Vec<u8>> {
    let max = MAX_BATCH_ITEMS.min(u.len().saturating_sub(1).max(1));
    let count = u.int_in_range(1..=max)?;
    (0..count).map(|_| u.arbitrary()).collect()
}

fn arbitrary_requests(u: &mut Unstructured<'_>) -> arbitrary::Result<Vec<TargetedRequest>> {
    let max = MAX_BATCH_ITEMS.min((u.len().saturating_sub(1) / 3).max(1));
    let count = u.int_in_range(1..=max)?;
    (0..count).map(|_| u.arbitrary()).collect()
}

fn arbitrary_operations(u: &mut Unstructured<'_>) -> arbitrary::Result<Vec<Operation>> {
    let max = MAX_OPERATIONS
        .min((u.len().saturating_sub(PREAMBLE_BYTE_RESERVE) / OPERATION_BYTE_COST_ESTIMATE).max(1));
    let count = u.int_in_range(1..=max)?;
    (0..count).map(|_| Operation::arbitrary(u)).collect()
}

impl<'a> Arbitrary<'a> for Operation {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let variant = u.int_in_range(0..=OPERATION_VARIANTS - 1)?;
        match variant {
            0 => Ok(Self::Fetch {
                peer: arbitrary_peer(u)?,
                key: u.arbitrary()?,
            }),
            1 => Ok(Self::FetchAll {
                peer: arbitrary_peer(u)?,
                keys: arbitrary_keys(u)?,
            }),
            2 => Ok(Self::FetchTargeted {
                peer: arbitrary_peer(u)?,
                key: u.arbitrary()?,
                target: arbitrary_peer(u)?,
                target_mask: u.arbitrary()?,
            }),
            3 => Ok(Self::FetchAllTargeted {
                peer: arbitrary_peer(u)?,
                requests: arbitrary_requests(u)?,
            }),
            4 => Ok(Self::Cancel {
                peer: arbitrary_peer(u)?,
                key: u.arbitrary()?,
            }),
            5 => Ok(Self::Clear {
                peer: arbitrary_peer(u)?,
            }),
            6 => Ok(Self::Retain {
                peer: arbitrary_peer(u)?,
                divisor: arbitrary_divisor(u)?,
                remainder: u.arbitrary()?,
            }),
            7 => Ok(Self::Sleep {
                duration_ms: arbitrary_sleep_duration(u)?,
            }),
            8 => Ok(Self::Link {
                from: arbitrary_peer(u)?,
                to: arbitrary_peer(u)?,
                latency_ms: arbitrary_link_latency(u)?,
                jitter_ms: arbitrary_link_jitter(u)?,
                success_rate_percent: arbitrary_success_rate(u)?,
            }),
            9 => Ok(Self::RemoveLink {
                from: arbitrary_peer(u)?,
                to: arbitrary_peer(u)?,
            }),
            10 => Ok(Self::Track {
                id: arbitrary_track_id(u)?,
                primary_mask: u.arbitrary()?,
            }),
            11 => Ok(Self::CompleteFetch {
                peer: arbitrary_peer(u)?,
                key: u.arbitrary()?,
                settle_ms: arbitrary_completion_window(u)?,
            }),
            _ => Ok(Self::Burst {
                peer: arbitrary_peer(u)?,
                key: u.arbitrary()?,
            }),
        }
    }
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
        let operations = arbitrary_operations(u)?;
        let peers = if u.is_empty() {
            MIN_PEERS
        } else {
            u.int_in_range(MIN_PEERS..=MAX_PEERS)?
        };
        let latency_ms = if u.is_empty() {
            MIN_LINK_LATENCY_MS
        } else {
            u.int_in_range(MIN_LINK_LATENCY_MS..=MAX_LINK_LATENCY_MS)?
        };
        let jitter_ms = if u.is_empty() {
            0
        } else {
            u.int_in_range(0..=MAX_LINK_JITTER_MS)?
        };
        let success_rate_percent = if u.is_empty() {
            DEFAULT_SUCCESS_RATE_PERCENT
        } else {
            u.int_in_range(MIN_SUCCESS_RATE_PERCENT..=MAX_SUCCESS_RATE_PERCENT)?
        };
        let mailbox_size = if u.is_empty() {
            DEFAULT_MAILBOX_SIZE
        } else {
            u.int_in_range(MIN_MAILBOX_SIZE..=MAX_MAILBOX_SIZE)?
        };
        // Bias toward a size-1 mailbox so bursts overflow into the ingress
        // policy instead of resting in the ready queue.
        let small_mailbox = !u.is_empty() && u.arbitrary()?;
        let quota_per_second = if u.is_empty() {
            DEFAULT_QUOTA_PER_SECOND
        } else {
            u.int_in_range(MIN_QUOTA_PER_SECOND..=MAX_QUOTA_PER_SECOND)?
        };
        let fetch_initial_ms = if u.is_empty() {
            MIN_FETCH_INITIAL_MS
        } else {
            u.int_in_range(MIN_FETCH_INITIAL_MS..=MAX_FETCH_INITIAL_MS)?
        };
        let fetch_timeout_ms = if u.is_empty() {
            DEFAULT_FETCH_TIMEOUT_MS
        } else {
            u.int_in_range(MIN_FETCH_TIMEOUT_MS..=MAX_FETCH_TIMEOUT_MS)?
        };
        let fetch_retry_timeout_ms = if u.is_empty() {
            MIN_FETCH_RETRY_TIMEOUT_MS
        } else {
            u.int_in_range(MIN_FETCH_RETRY_TIMEOUT_MS..=MAX_FETCH_RETRY_TIMEOUT_MS)?
        };
        let completion_window_ms = if u.is_empty() {
            MIN_COMPLETION_WINDOW_MS
        } else {
            u.int_in_range(MIN_COMPLETION_WINDOW_MS..=MAX_COMPLETION_WINDOW_MS)?
        };
        let priority_requests = !u.is_empty() && u.arbitrary()?;
        let priority_responses = !u.is_empty() && u.arbitrary()?;
        let item_count = if u.is_empty() {
            1
        } else {
            u.int_in_range(1..=MAX_INITIAL_ITEMS)?
        };
        let mut items = Vec::with_capacity(item_count);
        for _ in 0..item_count {
            items.push(u.arbitrary()?);
        }
        Ok(Self {
            raw_bytes,
            peers,
            latency_ms,
            jitter_ms,
            success_rate_percent,
            mailbox_size,
            small_mailbox,
            quota_per_second,
            fetch_initial_ms,
            fetch_timeout_ms,
            fetch_retry_timeout_ms,
            completion_window_ms,
            priority_requests,
            priority_responses,
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
    let holder_count = peers.div_ceil(2).max(1);
    (key.0 as usize + peer * holder_count) % peers < holder_count
}

fn remote_holder(key: &Key, requester: usize, peers: usize) -> usize {
    (0..peers)
        .find(|peer| *peer != requester && producer_holds(key, *peer, peers))
        .expect("key must have a remote holder")
}

fn oracle_fetch_timeout_floor_ms(quota_per_second: u32) -> u64 {
    let quota_interval_ms = 1_000_u64.div_ceil(u64::from(quota_per_second));
    2 * (quota_interval_ms + MIN_LINK_LATENCY_MS) + 1
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

async fn set_link(
    oracle: &commonware_p2p::simulated::Oracle<PublicKey, deterministic::Context>,
    from: PublicKey,
    to: PublicKey,
    link: Link,
) {
    loop {
        match oracle
            .add_link(from.clone(), to.clone(), link.clone())
            .await
        {
            Ok(()) => return,
            Err(NetworkError::LinkExists) => {
                let _ = oracle.remove_link(from.clone(), to.clone()).await;
            }
            Err(err) => panic!("failed to add link: {err}"),
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
                set_link(oracle, from.clone(), to.clone(), link.clone()).await;
            }
        }
    }
}

fn run(input: FuzzInput) -> String {
    let cfg = deterministic::Config::new().with_rng(Box::new(FuzzRng::new(input.raw_bytes)));
    let executor = deterministic::Runner::new(cfg);
    executor.start(|context| async move {
        let schemes = (0..input.peers)
            .map(|index| PrivateKey::from_seed(index as u64))
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
        let mailbox_size = if input.small_mailbox {
            MIN_MAILBOX_SIZE
        } else {
            input.mailbox_size
        };
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
                    mailbox_size: NonZeroUsize::new(mailbox_size).unwrap(),
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
                    assert!(mailboxes[index]
                        .retain(move |fetch_key, _| fetch_key != &Key(key))
                        .accepted());
                }
                Operation::Clear { peer } => {
                    let index = peer % mailboxes.len();
                    assert!(mailboxes[index].retain(|_, _| false).accepted());
                }
                Operation::Retain {
                    peer,
                    divisor,
                    remainder,
                } => {
                    let index = peer % mailboxes.len();
                    assert!(mailboxes[index]
                        .retain(move |key, _| key.0 % divisor == remainder % divisor)
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
                        set_link(
                            &oracle,
                            peers[from].clone(),
                            peers[to].clone(),
                            link(latency_ms, jitter_ms, success_rate_percent),
                        )
                        .await;
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
                } => 'complete_fetch: {
                    // This oracle requires a request and response to complete before the engine's
                    // configured timeout. Very small timeouts remain useful fuzz inputs, but they
                    // cannot guarantee delivery even over a reliable, rate-limited link.
                    if input.fetch_timeout_ms
                        < oracle_fetch_timeout_floor_ms(input.quota_per_second)
                    {
                        break 'complete_fetch;
                    }
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
                    let quota_window_ms =
                        (peers.len() as u64 * 1_000).div_ceil(input.quota_per_second as u64);
                    let settle = Duration::from_millis(
                        settle_ms
                            .max(input.completion_window_ms)
                            .max(input.fetch_timeout_ms + input.fetch_retry_timeout_ms)
                            .max(
                                quota_window_ms
                                    + input.fetch_timeout_ms
                                    + input.fetch_retry_timeout_ms,
                            ),
                    );
                    // Isolate this liveness oracle from background fetch retries
                    // created by earlier fuzz operations.
                    for mailbox in &mut mailboxes {
                        assert!(mailbox.retain(|_, _| false).accepted());
                    }
                    context.sleep(settle).await;
                    drain_outputs(&mut outputs, &expected, &mut delivered);
                    let canceled = key.clone();
                    assert!(mailboxes[index]
                        .retain(move |fetch_key, _| fetch_key != &canceled)
                        .accepted());
                    context.sleep(settle).await;
                    drain_outputs(&mut outputs, &expected, &mut delivered);
                    let mut oracle_window = vec![BTreeSet::new(); peers.len()];
                    let holder = remote_holder(&key, index, peers.len());
                    assert!(mailboxes[index]
                        .fetch_targeted(key.clone(), NonEmptyVec::new(peers[holder].clone()))
                        .accepted());
                    context.sleep(settle).await;
                    drain_outputs(&mut outputs, &expected, &mut oracle_window);
                    for (peer_idx, keys) in oracle_window.iter().enumerate() {
                        delivered[peer_idx].extend(keys.iter().cloned());
                    }
                    assert!(
                        oracle_window[index].contains(&key),
                        "missing oracle delivery: index={index}, holder={holder}, key={key:?}"
                    );
                }
                Operation::Burst { peer, key } => {
                    // Synchronously enqueue without yielding so messages pile into the ingress
                    // overflow policy. Pre-filling the ready queue with same-key fetches forces
                    // the scripted fetches below to overflow regardless of mailbox size; reusing
                    // `key` keeps the actor's eventual fetch work to a single coalesced key.
                    let index = peer % mailboxes.len();
                    // Bias the coalesced burst key toward an existing key so the single resulting
                    // fetch resolves instead of retrying indefinitely as background work.
                    let base = expected
                        .keys()
                        .nth(key as usize % expected.len())
                        .cloned()
                        .unwrap_or(Key(key));
                    let mut overlapping = NonEmptyVec::new(peers[0].clone());
                    overlapping.push(peers[1].clone());
                    let mailbox = &mut mailboxes[index];
                    for _ in 0..mailbox_size {
                        assert!(mailbox.fetch(base.clone()).accepted());
                    }
                    // Same-key targeted/untargeted fetches drive every metadata-merge branch.
                    assert!(mailbox
                        .fetch_targeted(base.clone(), NonEmptyVec::new(peers[0].clone()))
                        .accepted());
                    assert!(mailbox.fetch_targeted(base.clone(), overlapping).accepted());
                    assert!(mailbox.fetch(base.clone()).accepted());
                    assert!(mailbox
                        .fetch_targeted(base.clone(), NonEmptyVec::new(peers[0].clone()))
                        .accepted());
                    // Extra keys keep the overflow non-empty so the drain re-push paths run, and
                    // the two retains exercise retain-on-overflow (keep and drop) plus push_front.
                    assert!(mailbox.fetch(Key(key.wrapping_add(1))).accepted());
                    assert!(mailbox.fetch(Key(key.wrapping_add(2))).accepted());
                    assert!(mailbox.fetch(Key(key.wrapping_add(3))).accepted());
                    let dropped = Key(key.wrapping_add(2));
                    assert!(mailbox.retain(move |k, _| k != &dropped).accepted());
                    assert!(mailbox.retain(|_, _| true).accepted());
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
