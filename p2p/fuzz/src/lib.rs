use arbitrary::Arbitrary;
use bytes::Bytes;
use commonware_codec::codec::FixedSize;
use commonware_cryptography::{ed25519, PrivateKeyExt, Signer};
use commonware_p2p::{
    authenticated::{
        discovery,
        lookup::{self, Network as LookupNetwork},
    },
    Blocker, Channel, Receiver, Recipients, Sender,
};
use commonware_runtime::{deterministic, Clock, Handle, Metrics, Runner};
use commonware_runtime::deterministic::Context;
use commonware_utils::NZU32;
use futures::future::BoxFuture;
use governor::Quota;
use rand::{rngs::StdRng, seq::SliceRandom, Rng, SeedableRng};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::Duration,
};

const MAX_OPERATIONS: usize = 30;
const MAX_PEERS: usize = 8;
const MIN_PEERS: usize = 4;
const MAX_MSG_SIZE: usize = 1024 * 1024;
const MAX_INDEX: u8 = 10;
const PEER_SUBSET_NUMBER: usize = 5;
const DEFAULT_MESSAGE_BACKLOG: usize = 128;
const MAX_SLEEP_DURATION: u64 = 1000;

#[derive(Debug, Arbitrary)]
pub enum RecipientMode {
    All,
    One,
    Some,
}

#[derive(Debug, Arbitrary)]
pub enum NetworkOperation {
    SendMessage {
        sender_idx: u8,
        recipient_mode: RecipientMode,
        recipient_idx: u8,
        msg_size: usize,
        priority: bool,
    },
    ReceiveMessages,
    RegisterPeers {
        peer_idx: u8,
        index: u8,
        num_peers: u8,
    },
    BlockPeer {
        peer_idx: u8,
        target_idx: u8,
    },
}

#[derive(Debug)]
pub struct FuzzInput {
    pub seed: u64,
    pub operations: Vec<NetworkOperation>,
    pub peers: u8,
}

impl<'a> Arbitrary<'a> for FuzzInput {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let seed = u.arbitrary()?;
        let operations = u.arbitrary()?;
        let peers = u.int_in_range(MIN_PEERS..=MAX_PEERS)? as u8;
        Ok(FuzzInput {
            seed,
            operations,
            peers,
        })
    }
}

pub struct PeerInfo {
    pub private_key: ed25519::PrivateKey,
    pub public_key: ed25519::PublicKey,
    pub address: SocketAddr,
}

pub trait NetworkScheme: Send + 'static {
    type Sender: Sender<PublicKey = ed25519::PublicKey> + Send;
    type Receiver: Receiver<PublicKey = ed25519::PublicKey> + Send;
    type Oracle: Blocker<PublicKey = ed25519::PublicKey> + Send;

    fn create_network<'a>(
        context: Context,
        peer: &'a PeerInfo,
        peers: &'a [PeerInfo],
        peer_idx: usize,
        base_port: u16,
        rng: &'a mut StdRng,
    ) -> BoxFuture<'a, (Self::Sender, Self::Receiver, Self::Oracle, Handle<()>)>;

    fn register_peers<'a>(
        oracle: &'a mut Self::Oracle,
        index: u64,
        peers: &'a [PeerInfo],
        subset: Vec<ed25519::PublicKey>,
    ) -> BoxFuture<'a, ()>;
}

/// Discovery network implementation
pub struct Discovery;

impl NetworkScheme for Discovery {
    type Sender = discovery::Sender<ed25519::PublicKey>;
    type Receiver = discovery::Receiver<ed25519::PublicKey>;
    type Oracle = discovery::Oracle<ed25519::PublicKey>;

    fn create_network<'a>(
        context: Context,
        peer: &'a PeerInfo,
        peers: &'a [PeerInfo],
        peer_idx: usize,
        base_port: u16,
        rng: &'a mut StdRng,
    ) -> BoxFuture<'a, (Self::Sender, Self::Receiver, Self::Oracle, Handle<()>)> {
        Box::pin(async move {
            let addresses = peers.iter().map(|p| p.public_key.clone()).collect::<Vec<_>>();
            let mut bootstrappers = Vec::new();
            if peer_idx > 0 {
                bootstrappers.push((
                    addresses[0].clone(),
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), base_port),
                ));
            }

            let mut config = discovery::Config::recommended(
                peer.private_key.clone(),
                b"fuzz_namespace",
                peer.address,
                peer.address,
                bootstrappers,
                MAX_MSG_SIZE,
            );
            config.mailbox_size = 100;
            config.allow_private_ips = true;
            config.tracked_peer_sets = PEER_SUBSET_NUMBER;

            let (mut network, mut oracle) = discovery::Network::new(
                context.with_label("fuzzed-discovery-network"),
                config,
            );

            for index in 0..PEER_SUBSET_NUMBER {
                let mut addrs = addresses.clone();
                addrs.shuffle(rng);
                let subset = addrs[..3].to_vec();
                oracle.register(index as u64, subset).await;
            }

            let quota = Quota::per_second(NZU32!(100));
            let (sender, receiver) = network.register(0, quota, DEFAULT_MESSAGE_BACKLOG);
            let handle = network.start();

            (sender, receiver, oracle, handle)
        })
    }

    fn register_peers<'a>(
        oracle: &'a mut Self::Oracle,
        index: u64,
        _peers: &'a [PeerInfo],
        subset: Vec<ed25519::PublicKey>,
    ) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            let _ = oracle.register(index, subset).await;
        })
    }
}

/// Lookup network implementation
pub struct Lookup;

impl NetworkScheme for Lookup {
    type Sender = lookup::Sender<ed25519::PublicKey>;
    type Receiver = lookup::Receiver<ed25519::PublicKey>;
    type Oracle = lookup::Oracle<ed25519::PublicKey>;

    fn create_network<'a>(
        context: Context,
        peer: &'a PeerInfo,
        peers: &'a [PeerInfo],
        _peer_idx: usize,
        _base_port: u16,
        rng: &'a mut StdRng,
    ) -> BoxFuture<'a, (Self::Sender, Self::Receiver, Self::Oracle, Handle<()>)> {
        Box::pin(async move {
            let mut config = lookup::Config::recommended(
                peer.private_key.clone(),
                b"fuzz_namespace",
                peer.address,
                peer.address,
                MAX_MSG_SIZE,
            );
            config.allow_private_ips = true;

            let (mut network, mut oracle) = LookupNetwork::new(
                context.with_label("fuzzed-lookup-network"),
                config,
            );

            // For lookup, register peers by address instead of discovery
            let peer_list: Vec<_> = peers
                .iter()
                .map(|p| (p.public_key.clone(), p.address))
                .collect();

            // First registration: register all peers for each index
            for index in 0..PEER_SUBSET_NUMBER {
                oracle.register(index as u64, peer_list.clone()).await;
            }

            // Second registration: register shuffled subsets
            for index in 0..PEER_SUBSET_NUMBER {
                let mut peers = peer_list.clone();
                peers.shuffle(rng);
                let subset = peers[..3].to_vec();
                oracle.register(index as u64, subset).await;
            }

            let quota = Quota::per_second(NZU32!(100));
            let (sender, receiver) = network.register(0, quota, DEFAULT_MESSAGE_BACKLOG);
            let handle = network.start();

            (sender, receiver, oracle, handle)
        })
    }

    fn register_peers<'a>(
        oracle: &'a mut Self::Oracle,
        index: u64,
        peers: &'a [PeerInfo],
        subset: Vec<ed25519::PublicKey>,
    ) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            let peer_list: Vec<_> = subset
                .iter()
                .filter_map(|pk| {
                    peers
                        .iter()
                        .find(|p| &p.public_key == pk)
                        .map(|p| (p.public_key.clone(), p.address))
                })
                .collect();
            let _ = oracle.register(index, peer_list).await;
        })
    }
}

pub async fn fuzz_network<N: NetworkScheme>(input: FuzzInput) {
    let n = input.peers;
    let seed = input.seed;

    let executor = deterministic::Runner::seeded(seed);
    executor.start(|context| async move {
        let mut rng = StdRng::seed_from_u64(seed);
        
        // Create peers
        let mut peers = Vec::new();
        let base_port = 63000;

        for i in 0..n {
            let seed = rng.gen::<u64>() ^ (i as u64);
            let private_key = ed25519::PrivateKey::from_seed(seed);
            let public_key = private_key.public_key();
            let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), base_port + i as u16);
            peers.push(PeerInfo {
                private_key,
                public_key,
                address,
            });
        }

        let pk_to_idx: HashMap<ed25519::PublicKey, u8> = peers
            .iter()
            .enumerate()
            .map(|(idx, peer)| (peer.public_key.clone(), idx as u8))
            .collect();

        // Create network instances
        let mut networks = Vec::new();
        let mut oracles = Vec::new();

        for (peer_idx, peer) in peers.iter().enumerate() {
            let context = context.with_label(&format!("peer-{peer_idx}"));
            let (sender, receiver, oracle, handle) = N::create_network(
                context,
                peer,
                &peers,
                peer_idx,
                base_port,
                &mut rng,
            )
            .await;
            
            networks.push((sender, receiver, Some(handle)));
            oracles.push(oracle);
        }
        
        // Process operations
        let mut expected_messages: HashMap<(u8, u8), VecDeque<Bytes>> = HashMap::new();
        let mut pending_by_receiver: HashMap<u8, Vec<u8>> = HashMap::new();

        for op in input.operations.into_iter().take(MAX_OPERATIONS) {
            match op {
                NetworkOperation::SendMessage {
                    sender_idx,
                    recipient_mode,
                    recipient_idx,
                    msg_size,
                    priority,
                } => {
                    let sender_idx = (sender_idx as usize) % peers.len();
                    let sender_idx_u8 = sender_idx as u8;
                    let msg_size = msg_size.clamp(0, MAX_MSG_SIZE - Channel::SIZE);

                    let mut bytes = vec![0u8; msg_size];
                    rng.fill(&mut bytes[..]);
                    let message = Bytes::from(bytes);

                    let recipients = match recipient_mode {
                        RecipientMode::All => Recipients::All,
                        RecipientMode::One => {
                            let recipient_idx = (recipient_idx as usize) % peers.len();
                            if recipient_idx == sender_idx {
                                continue;
                            }
                            let recipient_pk = peers[recipient_idx].public_key.clone();
                            Recipients::One(recipient_pk)
                        }
                        RecipientMode::Some => {
                            let num_recipients = rng.gen_range(1..peers.len() - 1);
                            let mut recipients_set = HashSet::new();
                            for _ in 0..num_recipients {
                                let idx = rng.gen::<usize>() % peers.len();
                                if idx != sender_idx {
                                    recipients_set.insert(peers[idx].public_key.clone());
                                }
                            }
                            if recipients_set.is_empty() {
                                continue;
                            }
                            Recipients::Some(recipients_set.into_iter().collect())
                        }
                    };

                    // Collect target recipient indices
                    let target_recipients: Vec<u8> = match &recipients {
                        Recipients::One(pk) => {
                            if let Some(&to_idx) = pk_to_idx.get(pk) {
                                if to_idx != sender_idx_u8 {
                                    vec![to_idx]
                                } else {
                                    vec![]
                                }
                            } else {
                                vec![]
                            }
                        }
                        Recipients::Some(pk_list) => pk_list
                            .iter()
                            .filter_map(|pk| pk_to_idx.get(pk).copied())
                            .filter(|&to_idx| to_idx != sender_idx_u8)
                            .collect(),
                        Recipients::All => {
                            let all_recipients: Vec<u8> = (0..peers.len())
                                .map(|i| i as u8)
                                .filter(|&to_idx| to_idx != sender_idx_u8)
                                .collect();
                            all_recipients
                        }
                    };

                    let sent = networks[sender_idx]
                        .0
                        .send(recipients, message.clone(), priority)
                        .await
                        .is_ok();

                    if sent {
                        for to_idx in target_recipients {
                            expected_messages
                                .entry((to_idx, sender_idx_u8))
                                .or_default()
                                .push_back(message.clone());
                            pending_by_receiver
                                .entry(to_idx)
                                .or_default()
                                .push(sender_idx_u8);
                        }
                    }
                }

                NetworkOperation::ReceiveMessages => {
                    let receivers_with_pending: Vec<u8> = pending_by_receiver.keys().cloned().collect();

                    for receiver_idx_u8 in receivers_with_pending {
                        let receiver_idx = receiver_idx_u8 as usize;
                        if receiver_idx >= networks.len() {
                            continue;
                        }

                        if !pending_by_receiver.contains_key(&receiver_idx_u8) {
                            continue;
                        }

                        let receiver = &mut networks[receiver_idx].1;

                        commonware_macros::select! {
                            result = receiver.recv() => {
                                let Ok((sender_pk, message)) = result else {
                                    continue;
                                };

                                let Some(&actual_sender_idx) = pk_to_idx.get(&sender_pk) else {
                                    continue;
                                };

                                let key = (receiver_idx_u8, actual_sender_idx);
                                if let Some(queue) = expected_messages.get_mut(&key) {
                                    let mut found_index = None;
                                    for (i, expected) in queue.iter().enumerate() {
                                        if message == *expected {
                                            found_index = Some(i);
                                            break;
                                        }
                                    }

                                    if let Some(index) = found_index {
                                        queue.remove(index);
                                        if queue.is_empty() {
                                            expected_messages.remove(&key);
                                        }
                                        if let Some(senders) = pending_by_receiver.get_mut(&receiver_idx_u8) {
                                            if let Some(pos) = senders.iter().position(|&x| x == actual_sender_idx) {
                                                senders.remove(pos);
                                            }
                                            if senders.is_empty() {
                                                pending_by_receiver.remove(&receiver_idx_u8);
                                            }
                                        }
                                    } else {
                                        panic!("Peer index {} Received unexpected message from sender {}", receiver_idx_u8, actual_sender_idx);
                                    }
                                } else {
                                    panic!("Unexpected delivery for peer {} with index {}", peers[receiver_idx_u8 as usize].public_key, receiver_idx_u8);
                                }
                            },
                            _ = context.sleep(Duration::from_millis(MAX_SLEEP_DURATION)) => {
                                continue;
                            },
                        }
                    }
                }

                NetworkOperation::RegisterPeers {
                    peer_idx,
                    index,
                    num_peers,
                } => {
                    let peer_idx = (peer_idx as usize) % peers.len();
                    let index = index % MAX_INDEX;
                    let num_peers = (num_peers as usize).clamp(1, peers.len());

                    let mut peer_set = HashSet::new();
                    for _ in 0..num_peers {
                        let idx = rng.gen::<usize>() % peers.len();
                        peer_set.insert(peers[idx].public_key.clone());
                    }
                    let peer_subset: Vec<_> = peer_set.into_iter().collect();

                    N::register_peers(
                        &mut oracles[peer_idx],
                        index as u64,
                        &peers,
                        peer_subset,
                    )
                    .await;
                }

                NetworkOperation::BlockPeer { peer_idx, target_idx } => {
                    let peer_idx = (peer_idx as usize) % peers.len();
                    let peer_idx_u8 = peer_idx as u8;
                    let target_idx = (target_idx as usize) % peers.len();
                    let target_idx_u8 = target_idx as u8;

                    let target_pk = peers[target_idx].public_key.clone();
                    let _ = oracles[peer_idx].block(target_pk).await;

                    // Remove expectations
                    expected_messages.retain(|(to_idx, from_idx), _queue| {
                        !(*to_idx == peer_idx_u8 && *from_idx == target_idx_u8)
                    });

                    if let Some(senders) = pending_by_receiver.get_mut(&peer_idx_u8) {
                        senders.retain(|&from_idx| from_idx != target_idx_u8);
                        if senders.is_empty() {
                            pending_by_receiver.remove(&peer_idx_u8);
                        }
                    }
                }
            }
        }

        // Cleanup
        for (_, _, handle) in networks {
            if let Some(h) = handle {
                h.abort();
            }
        }
    });
}

pub fn fuzz(input: FuzzInput) {
    futures::executor::block_on(fuzz_network::<Discovery>(input));
}