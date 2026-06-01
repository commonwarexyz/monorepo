#![no_main]

use arbitrary::Arbitrary;
use commonware_broadcast::{
    buffered::{Config, Engine, Mailbox},
    Broadcaster,
};
use commonware_codec::{Encode, RangeCfg, ReadRangeExt};
use commonware_cryptography::{
    ed25519::{PrivateKey, PublicKey},
    sha256::Digest,
    Digestible, Hasher, Sha256, Signer,
};
use commonware_p2p::{simulated::Network, Manager as _, Recipients, Sender as _, TrackedPeers};
use commonware_runtime::{
    deterministic, Buf, BufMut, Clock, IoBuf, Quota, Runner, Spawner as _, Supervisor as _,
};
use commonware_utils::{
    channel::oneshot, futures::Pool, ordered::Set, vec::Bounded, FuzzRng, NZUsize,
};
use futures::FutureExt as _;
use libfuzzer_sys::fuzz_target;
use rand::{seq::SliceRandom, SeedableRng};
use std::{collections::BTreeMap, num::NonZeroU32, time::Duration};

/// Default rate limit set high enough to not interfere with normal operation
const TEST_QUOTA: Quota = Quota::per_second(NonZeroU32::MAX);

/// Maximum sleep duration in milliseconds for fuzz tests.
///
/// Capped to avoid overflow in governor rate limiter which uses nanoseconds internally
/// and can only represent durations up to ~584 years.
const MAX_SLEEP_DURATION_MS: u64 = 1000;

/// Minimum number of pressure rounds in one `PressureMailbox` action.
const MIN_PRESSURE_MAILBOX_COUNT: u8 = 2;

/// Maximum number of pressure rounds in one `PressureMailbox` action.
const MAX_PRESSURE_MAILBOX_COUNT: u8 = 8;

/// Minimum number of peers in one fuzz run.
const MIN_PEERS: u64 = 1;

/// Maximum number of peers in one fuzz run.
const MAX_PEERS: u64 = 5;

/// Minimum simulated network success rate, as a percentage.
const MIN_NETWORK_SUCCESS_PERCENT: u8 = 30;

/// Maximum simulated network success rate, as a percentage.
const MAX_NETWORK_SUCCESS_PERCENT: u8 = 100;

/// Scale factor for percentage values.
const PERCENT_DENOMINATOR: f64 = 100.0;

/// Minimum simulated network latency in milliseconds.
const MIN_NETWORK_LATENCY_MS: u64 = 1;

/// Maximum simulated network latency in milliseconds.
const MAX_NETWORK_LATENCY_MS: u64 = 100;

/// Minimum simulated network jitter in milliseconds.
const MIN_NETWORK_JITTER_MS: u64 = 0;

/// Maximum simulated network jitter in milliseconds.
const MAX_NETWORK_JITTER_MS: u64 = 50;

/// Minimum engine cache size.
const MIN_CACHE_SIZE: usize = 5;

/// Maximum engine cache size.
const MAX_CACHE_SIZE: usize = 10;

/// Minimum mailbox size.
const MIN_MAILBOX_SIZE: usize = 1;

/// Maximum mailbox size.
const MAX_MAILBOX_SIZE: usize = 4;

/// Minimum number of actions in one fuzz run.
const MIN_ACTIONS: usize = 1;

/// Maximum number of actions in one fuzz run.
const MAX_ACTIONS: usize = 32;

/// Maximum raw fuzz bytes used to drive runtime scheduling randomness.
const MAX_RAW_FUZZ_BYTES: usize = 32_768;

/// Maximum number of recently broadcast digests tracked for `Recent` lookups.
///
/// Indexed by `u8` modulo length, so a larger buffer would leave entries past 255
/// unreachable via `Source::Recent`.
const MAX_RECENT_DIGESTS: usize = (u8::MAX as usize) + 1;

/// Subscription result paired with the digest requested so completions can be validated.
type Subscription = (Digest, Result<FuzzMessage, oneshot::error::RecvError>);

#[derive(Clone, Debug, Arbitrary)]
pub enum RecipientPattern {
    All,
    Some(u64),
    One(u64),
}

#[derive(Debug, Clone, PartialEq, Eq, Arbitrary)]
pub struct FuzzMessage {
    pub commitment: Vec<u8>,
    pub content: Vec<u8>,
}

impl Digestible for FuzzMessage {
    type Digest = Digest;
    fn digest(&self) -> Self::Digest {
        Sha256::hash(&self.encode())
    }
}

impl commonware_codec::Write for FuzzMessage {
    fn write(&self, buf: &mut impl BufMut) {
        self.commitment.write(buf);
        self.content.write(buf);
    }
}

impl commonware_codec::EncodeSize for FuzzMessage {
    fn encode_size(&self) -> usize {
        self.commitment.encode_size() + self.content.encode_size()
    }
}

impl commonware_codec::Read for FuzzMessage {
    type Cfg = RangeCfg<usize>;
    fn read_cfg(buf: &mut impl Buf, range: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        let commitment = Vec::<u8>::read_range(buf, *range)?;
        let content = Vec::<u8>::read_range(buf, *range)?;
        Ok(Self {
            commitment,
            content,
        })
    }
}

/// Source for the digest used by `Subscribe`/`Get` actions.
#[derive(Clone, Debug, Arbitrary)]
enum Source {
    /// A random message.
    Random(FuzzMessage),
    /// Index into messages broadcast earlier in this run.
    Recent(u8),
}

impl Source {
    /// Resolve to a concrete digest. Returns `None` when `Recent` is selected
    /// before any messages have been broadcast.
    fn resolve(self, recent: &Bounded<Digest>) -> Option<Digest> {
        match self {
            Source::Random(message) => Some(message.digest()),
            Source::Recent(_) if recent.is_empty() => None,
            Source::Recent(idx) => recent.get((idx as usize) % recent.len()).cloned(),
        }
    }
}

#[derive(Clone, Debug)]
enum BroadcastAction {
    SendMessage {
        peer_index: usize,
        recipients: RecipientPattern,
        message: FuzzMessage,
    },
    Subscribe {
        peer_index: usize,
        digest: Source,
    },
    Get {
        peer_index: usize,
        digest: Source,
    },
    SubscribeDropped {
        peer_index: usize,
        digest: Source,
    },
    SubscribePreparedDropped {
        peer_index: usize,
        digest: Source,
    },
    GetDropped {
        peer_index: usize,
        digest: Source,
    },
    SendRaw {
        sender_index: usize,
        recipient_index: usize,
        payload: Vec<u8>,
    },
    TrackPeers {
        primary_mask: u8,
    },
    DropMailbox {
        peer_index: usize,
    },
    CloseNetworkReceiver {
        peer_index: usize,
    },
    AbortNetwork,
    PressureMailbox {
        peer_index: usize,
        message: FuzzMessage,
        count: u8,
    },
    Sleep {
        duration_ms: u64,
    },
}

impl<'a> Arbitrary<'a> for BroadcastAction {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let variant = u.int_in_range(0..=13)?;
        match variant {
            0 => Ok(BroadcastAction::SendMessage {
                peer_index: u.arbitrary()?,
                recipients: u.arbitrary()?,
                message: u.arbitrary()?,
            }),
            1 => Ok(BroadcastAction::Subscribe {
                peer_index: u.arbitrary()?,
                digest: u.arbitrary()?,
            }),
            2 => Ok(BroadcastAction::Get {
                peer_index: u.arbitrary()?,
                digest: u.arbitrary()?,
            }),
            3 => Ok(BroadcastAction::SubscribeDropped {
                peer_index: u.arbitrary()?,
                digest: u.arbitrary()?,
            }),
            4 => Ok(BroadcastAction::SubscribePreparedDropped {
                peer_index: u.arbitrary()?,
                digest: u.arbitrary()?,
            }),
            5 => Ok(BroadcastAction::GetDropped {
                peer_index: u.arbitrary()?,
                digest: u.arbitrary()?,
            }),
            6 => Ok(BroadcastAction::SendRaw {
                sender_index: u.arbitrary()?,
                recipient_index: u.arbitrary()?,
                payload: u.arbitrary()?,
            }),
            7 => Ok(BroadcastAction::TrackPeers {
                primary_mask: u.arbitrary()?,
            }),
            8 => Ok(BroadcastAction::DropMailbox {
                peer_index: u.arbitrary()?,
            }),
            9 => Ok(BroadcastAction::CloseNetworkReceiver {
                peer_index: u.arbitrary()?,
            }),
            10 => Ok(BroadcastAction::AbortNetwork),
            11 => Ok(BroadcastAction::PressureMailbox {
                peer_index: u.arbitrary()?,
                message: u.arbitrary()?,
                count: u.int_in_range(MIN_PRESSURE_MAILBOX_COUNT..=MAX_PRESSURE_MAILBOX_COUNT)?,
            }),
            _ => Ok(BroadcastAction::Sleep {
                duration_ms: u.int_in_range(0..=MAX_SLEEP_DURATION_MS)?,
            }),
        }
    }
}

#[derive(Debug)]
pub struct FuzzInput {
    raw_fuzz_bytes: Vec<u8>,
    peer_seeds: Vec<u64>,
    network_success_rate: f64,
    network_latency_ms: u64,
    network_jitter_ms: u64,
    cache_size: usize,
    mailbox_size: usize,
    actions: Vec<BroadcastAction>,
}

impl<'a> arbitrary::Arbitrary<'a> for FuzzInput {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let raw_len = u.len().min(MAX_RAW_FUZZ_BYTES);
        let raw_fuzz_bytes = if raw_len == 0 {
            vec![0]
        } else {
            u.peek_bytes(raw_len)
                .expect("raw_len is in bounds")
                .to_vec()
        };
        let num_peers = u.int_in_range(MIN_PEERS..=MAX_PEERS)?;
        let peer_seeds = (0..num_peers).collect::<Vec<_>>(); // avoid duplicate seeds
        let network_success_rate =
            u.int_in_range(MIN_NETWORK_SUCCESS_PERCENT..=MAX_NETWORK_SUCCESS_PERCENT)? as f64
                / PERCENT_DENOMINATOR;
        let network_latency_ms = u.int_in_range(MIN_NETWORK_LATENCY_MS..=MAX_NETWORK_LATENCY_MS)?;
        let network_jitter_ms = u.int_in_range(MIN_NETWORK_JITTER_MS..=MAX_NETWORK_JITTER_MS)?;
        let cache_size = u.int_in_range(MIN_CACHE_SIZE..=MAX_CACHE_SIZE)?;
        let mailbox_size = u.int_in_range(MIN_MAILBOX_SIZE..=MAX_MAILBOX_SIZE)?;

        let num_actions = u.int_in_range(MIN_ACTIONS..=MAX_ACTIONS)?;
        let actions = (0..num_actions)
            .map(|_| BroadcastAction::arbitrary(u))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(FuzzInput {
            raw_fuzz_bytes,
            peer_seeds,
            network_success_rate,
            network_latency_ms,
            network_jitter_ms,
            cache_size,
            mailbox_size,
            actions,
        })
    }
}

fn resolve_recipients(pattern: &RecipientPattern, peers: &[PublicKey]) -> Recipients<PublicKey> {
    match pattern {
        RecipientPattern::All => Recipients::All,
        RecipientPattern::One(seed) => {
            let index = (*seed as usize) % peers.len();
            Recipients::One(peers[index].clone())
        }
        RecipientPattern::Some(seed) => {
            let mut rng = rand::rngs::StdRng::seed_from_u64(*seed);
            let mut shuffled_peers = peers.to_vec();
            shuffled_peers.shuffle(&mut rng);

            let count = ((seed % peers.len() as u64) as usize).max(1);
            let peer_slice = shuffled_peers.into_iter().take(count).collect();
            Recipients::Some(peer_slice)
        }
    }
}

// Keep subscriptions alive without spawning one task per receiver. Ready
// subscriptions are validated, while unresolved ones remain pending.
fn drain_ready_subscriptions(pending: &mut Pool<Subscription>) {
    while let Some((digest, result)) = pending.next_completed().now_or_never() {
        if let Ok(message) = result {
            assert_eq!(message.digest(), digest);
        }
    }
}

fn fuzz(input: FuzzInput) {
    let cfg =
        deterministic::Config::new().with_rng(Box::new(FuzzRng::new(input.raw_fuzz_bytes.clone())));
    let executor = deterministic::Runner::new(cfg);
    executor.start(|context| async move {
        // Generate peer identities before building the network so the initial
        // peer set can be seeded through the constructor.
        let peers = input
            .peer_seeds
            .iter()
            .map(|&seed| PrivateKey::from_seed(seed).public_key())
            .collect::<Vec<_>>();

        // Create network
        let (network, oracle) = Network::<deterministic::Context, PublicKey>::new_with_peers(
            context.child("network"),
            commonware_p2p::simulated::Config {
                max_size: 1024 * 1024,
                disconnect_on_block: false,
                tracked_peer_sets: NZUsize!(1),
            },
            peers.clone(),
        )
        .await;
        let network_handle = network.start();

        // Create peers
        let mut mailboxes: BTreeMap<PublicKey, Mailbox<PublicKey, FuzzMessage>> = BTreeMap::new();
        let mut raw_senders = BTreeMap::new();
        for (i, public_key) in peers.iter().cloned().enumerate() {
            // Create channel
            let (sender, receiver) = oracle
                .control(public_key.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();
            raw_senders.insert(public_key.clone(), sender.clone());

            // Create mailbox
            let config = Config {
                public_key: public_key.clone(),
                mailbox_size: input.mailbox_size.try_into().unwrap(),
                deque_size: input.cache_size,
                priority: false,
                codec_config: RangeCfg::from(..),
                peer_provider: oracle.manager(),
            };

            // Create engine
            let engine_context = context.child("peer").with_attribute("index", i);
            let (engine, mailbox) =
                Engine::<_, PublicKey, FuzzMessage, _>::new(engine_context, config);
            mailboxes.insert(public_key.clone(), mailbox);
            engine.start((sender, receiver));
        }

        // Add links between peers
        let link = commonware_p2p::simulated::Link {
            latency: Duration::from_millis(input.network_latency_ms),
            jitter: Duration::from_millis(input.network_jitter_ms),
            success_rate: input.network_success_rate,
        };
        for p1 in &peers {
            for p2 in &peers {
                if p1 != p2 {
                    let _ = oracle.add_link(p1.clone(), p2.clone(), link.clone()).await;
                }
            }
        }
        context.sleep(Duration::from_millis(1)).await;

        // Execute fuzzed actions
        let mut recent_digests = Bounded::new(NZUsize!(MAX_RECENT_DIGESTS));
        let mut pending_subscriptions = Pool::default();
        let mut next_peer_set = 1;
        let mailbox_size = input.mailbox_size;
        let network_settle = Duration::from_millis(
            input.network_latency_ms + input.network_jitter_ms.saturating_mul(4) + 1,
        );
        for action in input.actions {
            match action {
                BroadcastAction::SendMessage {
                    peer_index,
                    recipients,
                    message,
                } => {
                    let clamped_peer_idx = peer_index % peers.len();
                    let peer = peers[clamped_peer_idx].clone();

                    if let Some(mailbox) = mailboxes.get(&peer).cloned() {
                        let resolved_recipients = resolve_recipients(&recipients, &peers);
                        recent_digests.push(message.digest());
                        let _ = mailbox.broadcast(resolved_recipients, message);
                        context.sleep(network_settle).await;
                    }
                }
                BroadcastAction::Subscribe {
                    peer_index,
                    digest: source,
                } => {
                    let Some(digest) = source.resolve(&recent_digests) else {
                        continue;
                    };
                    let clamped_peer_idx = peer_index % peers.len();
                    let peer = peers[clamped_peer_idx].clone();

                    if let Some(mailbox) = mailboxes.get(&peer).cloned() {
                        let receiver = mailbox.subscribe(digest);
                        pending_subscriptions.push(async move { (digest, receiver.await) });
                    }
                }
                BroadcastAction::Get {
                    peer_index,
                    digest: source,
                } => {
                    let Some(digest) = source.resolve(&recent_digests) else {
                        continue;
                    };
                    let clamped_peer_idx = peer_index % peers.len();
                    let peer = peers[clamped_peer_idx].clone();

                    if let Some(mailbox) = mailboxes.get(&peer).cloned() {
                        if let Some(message) = mailbox.get(digest).await {
                            assert_eq!(message.digest(), digest);
                        }
                    }
                }
                BroadcastAction::SubscribeDropped {
                    peer_index,
                    digest: source,
                } => {
                    let Some(digest) = source.resolve(&recent_digests) else {
                        continue;
                    };
                    let clamped_peer_idx = peer_index % peers.len();
                    let peer = peers[clamped_peer_idx].clone();

                    if let Some(mailbox) = mailboxes.get(&peer).cloned() {
                        drop(mailbox.subscribe(digest));
                        context.sleep(Duration::from_millis(1)).await;
                    }
                }
                BroadcastAction::SubscribePreparedDropped {
                    peer_index,
                    digest: source,
                } => {
                    let Some(digest) = source.resolve(&recent_digests) else {
                        continue;
                    };
                    let clamped_peer_idx = peer_index % peers.len();
                    let peer = peers[clamped_peer_idx].clone();

                    if let Some(mailbox) = mailboxes.get(&peer).cloned() {
                        let (responder, receiver) = oneshot::channel();
                        drop(receiver);
                        mailbox.subscribe_prepared(digest, responder);
                        context.sleep(Duration::from_millis(1)).await;
                    }
                }
                BroadcastAction::GetDropped {
                    peer_index,
                    digest: source,
                } => {
                    let Some(digest) = source.resolve(&recent_digests) else {
                        continue;
                    };
                    let clamped_peer_idx = peer_index % peers.len();
                    let peer = peers[clamped_peer_idx].clone();

                    if let Some(mailbox) = mailboxes.get(&peer).cloned() {
                        let _ = mailbox.get(digest).now_or_never();
                    }
                }
                BroadcastAction::SendRaw {
                    sender_index,
                    recipient_index,
                    mut payload,
                } => {
                    let sender_peer = peers[sender_index % peers.len()].clone();
                    let recipient = if peers.len() == 1 {
                        peers[0].clone()
                    } else {
                        let recipient_index = recipient_index % (peers.len() - 1);
                        peers
                            .iter()
                            .filter(|peer| **peer != sender_peer)
                            .nth(recipient_index)
                            .unwrap()
                            .clone()
                    };
                    payload.truncate(1024);

                    if let Some(sender) = raw_senders.get_mut(&sender_peer) {
                        let _ =
                            sender.send(Recipients::One(recipient), IoBuf::from(payload), false);
                        context.sleep(network_settle).await;
                    }
                }
                BroadcastAction::TrackPeers { primary_mask } => {
                    let primary = Set::from_iter_dedup(
                        peers
                            .iter()
                            .enumerate()
                            .filter(|(i, _)| primary_mask & (1u8 << i) != 0)
                            .map(|(_, peer)| peer.clone()),
                    );
                    let secondary = Set::from_iter_dedup(
                        peers
                            .iter()
                            .enumerate()
                            .filter(|(i, _)| primary_mask & (1u8 << i) == 0)
                            .map(|(_, peer)| peer.clone()),
                    );
                    let mut manager = oracle.manager();
                    let _ = manager.track(next_peer_set, TrackedPeers::new(primary, secondary));
                    next_peer_set += 1;
                    context.sleep(Duration::from_millis(1)).await;
                }
                BroadcastAction::DropMailbox { peer_index } => {
                    let peer = peers[peer_index % peers.len()].clone();
                    mailboxes.remove(&peer);
                    context.sleep(Duration::from_millis(1)).await;
                }
                BroadcastAction::CloseNetworkReceiver { peer_index } => {
                    let peer = peers[peer_index % peers.len()].clone();
                    let _ = oracle.control(peer).register(0, TEST_QUOTA).await;
                    context.sleep(Duration::from_millis(1)).await;
                }
                BroadcastAction::AbortNetwork => {
                    network_handle.abort();
                    context.sleep(Duration::from_millis(1)).await;
                }
                BroadcastAction::PressureMailbox {
                    peer_index,
                    message,
                    count,
                } => {
                    let peer = peers[peer_index % peers.len()].clone();

                    if let Some(mailbox) = mailboxes.get(&peer).cloned() {
                        let digest = message.digest();
                        recent_digests.push(digest);
                        let pressure_count = usize::from(count).max(mailbox_size + 3);
                        for _ in 0..pressure_count {
                            let _ = mailbox.broadcast(Recipients::All, message.clone());

                            let (responder, receiver) = oneshot::channel();
                            drop(receiver);
                            mailbox.subscribe_prepared(digest, responder);

                            let _ = mailbox.get(digest).now_or_never();
                        }
                        context.sleep(Duration::from_millis(1)).await;
                    }
                }
                BroadcastAction::Sleep { duration_ms } => {
                    context.sleep(Duration::from_millis(duration_ms)).await;
                }
            }
            drain_ready_subscriptions(&mut pending_subscriptions);
        }
        let _ = context
            .child("shutdown")
            .stop(0, Some(Duration::from_millis(100)))
            .await;
    });
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
