#![no_main]

use arbitrary::Arbitrary;
use bytes::{Buf, BufMut};
use commonware_broadcast::{
    buffered::{Config, Engine, Mailbox},
    Broadcaster,
};
use commonware_codec::{Encode, RangeCfg, ReadRangeExt};
use commonware_cryptography::{
    ed25519::{PrivateKey, PublicKey},
    sha256::Digest,
    Committable, Digestible, Hasher, PrivateKeyExt as _, Sha256, Signer,
};
use commonware_p2p::{simulated::Network, Recipients};
use commonware_runtime::{deterministic, Clock, Metrics, Runner};
use governor::Quota;
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

impl Committable for FuzzMessage {
    type Commitment = commonware_cryptography::sha256::Digest;
    fn commitment(&self) -> Self::Commitment {
        Sha256::hash(&self.commitment)
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

#[derive(Clone, Debug)]
enum BroadcastAction {
    SendMessage {
        peer_index: usize,
        recipients: RecipientPattern,
        message: FuzzMessage,
    },
    Subscribe {
        peer_index: usize,
        sender: Option<usize>,
        commitment: [u8; 32],
        digest: Option<[u8; 32]>,
    },
    Get {
        peer_index: usize,
        sender: Option<usize>,
        commitment: [u8; 32],
        digest: Option<[u8; 32]>,
    },
    Sleep {
        duration_ms: u64,
    },
}

impl<'a> Arbitrary<'a> for BroadcastAction {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let variant = u.int_in_range(0..=3)?;
        match variant {
            0 => Ok(BroadcastAction::SendMessage {
                peer_index: u.arbitrary()?,
                recipients: u.arbitrary()?,
                message: u.arbitrary()?,
            }),
            1 => Ok(BroadcastAction::Subscribe {
                peer_index: u.arbitrary()?,
                sender: u.arbitrary()?,
                commitment: u.arbitrary()?,
                digest: u.arbitrary()?,
            }),
            2 => Ok(BroadcastAction::Get {
                peer_index: u.arbitrary()?,
                sender: u.arbitrary()?,
                commitment: u.arbitrary()?,
                digest: u.arbitrary()?,
            }),
            _ => Ok(BroadcastAction::Sleep {
                duration_ms: u.int_in_range(0..=MAX_SLEEP_DURATION_MS)?,
            }),
        }
    }
}

#[derive(Debug)]
pub struct FuzzInput {
    peer_seeds: Vec<u64>,
    network_success_rate: f64,
    network_latency_ms: u64,
    network_jitter_ms: u64,
    cache_size: usize,
    actions: Vec<BroadcastAction>,
}

impl<'a> arbitrary::Arbitrary<'a> for FuzzInput {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let num_peers = u.int_in_range(1..=5)?;
        let peer_seeds = (0..num_peers).collect::<Vec<_>>(); // avoid duplicate seeds
        let network_success_rate = u.int_in_range(30..=100)? as f64 / 100.0;
        let network_latency_ms = u.int_in_range(1..=100)?;
        let network_jitter_ms = u.int_in_range(0..=50)?;
        let cache_size = u.int_in_range(5..=10)?;

        let num_actions = u.int_in_range(1..=10)?;
        let actions = (0..num_actions)
            .map(|_| BroadcastAction::arbitrary(u))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(FuzzInput {
            peer_seeds,
            network_success_rate,
            network_latency_ms,
            network_jitter_ms,
            cache_size,
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

fn fuzz(input: FuzzInput) {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        // Create network
        let (network, mut oracle) = Network::<deterministic::Context, PublicKey>::new(
            context.with_label("network"),
            commonware_p2p::simulated::Config {
                max_size: 1024 * 1024,
                disconnect_on_block: false,
                tracked_peer_sets: None,
            },
        );
        network.start();

        // Create peers
        let mut peers = Vec::new();
        let mut mailboxes: BTreeMap<PublicKey, Mailbox<PublicKey, FuzzMessage>> = BTreeMap::new();
        for (i, &seed) in input.peer_seeds.iter().enumerate() {
            // Create peer
            let crypto = PrivateKey::from_seed(seed);
            let public_key = crypto.public_key();
            peers.push(public_key.clone());

            // Create channel
            let (sender, receiver) = oracle
                .control(public_key.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();

            // Create mailbox
            let config = Config {
                public_key: public_key.clone(),
                mailbox_size: 1024,
                deque_size: input.cache_size,
                priority: false,
                codec_config: RangeCfg::from(..),
            };

            // Create engine
            let engine_context = context.with_label(&format!("peer_{i}"));
            let (engine, mailbox) =
                Engine::<_, PublicKey, FuzzMessage>::new(engine_context, config);
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

        // Execute fuzzed actions
        for action in input.actions {
            match action {
                BroadcastAction::SendMessage {
                    peer_index,
                    recipients,
                    message,
                } => {
                    let clamped_peer_idx = peer_index % peers.len();
                    let peer = peers[clamped_peer_idx].clone();

                    if let Some(mut mailbox) = mailboxes.get(&peer).cloned() {
                        let resolved_recipients = resolve_recipients(&recipients, &peers);
                        drop(mailbox.broadcast(resolved_recipients, message).await);
                    }
                }
                BroadcastAction::Subscribe {
                    peer_index,
                    sender,
                    commitment,
                    digest,
                } => {
                    let clamped_peer_idx = peer_index % peers.len();
                    let peer = peers[clamped_peer_idx].clone();

                    if let Some(mut mailbox) = mailboxes.get(&peer).cloned() {
                        let sender_key = sender.map(|sender_idx| {
                            let clamped_sender_idx = sender_idx % peers.len();
                            peers[clamped_sender_idx].clone()
                        });
                        drop(
                            mailbox
                                .subscribe(sender_key, commitment.into(), digest.map(|d| d.into()))
                                .await,
                        );
                    }
                }
                BroadcastAction::Get {
                    peer_index,
                    sender,
                    commitment,
                    digest,
                } => {
                    let clamped_peer_idx = peer_index % peers.len();
                    let peer = peers[clamped_peer_idx].clone();

                    if let Some(mut mailbox) = mailboxes.get(&peer).cloned() {
                        let sender_key = sender.map(|sender_idx| {
                            let clamped_sender_idx = sender_idx % peers.len();
                            peers[clamped_sender_idx].clone()
                        });
                        drop(
                            mailbox
                                .get(sender_key, commitment.into(), digest.map(|d| d.into()))
                                .await,
                        );
                    }
                }
                BroadcastAction::Sleep { duration_ms } => {
                    context.sleep(Duration::from_millis(duration_ms)).await;
                }
            }
        }
    });
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
