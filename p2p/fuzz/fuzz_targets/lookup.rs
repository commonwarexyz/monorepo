#![no_main]

use arbitrary::Arbitrary;
use bytes::Bytes;
use commonware_cryptography::{ed25519, PrivateKeyExt, Signer};
use commonware_p2p::{
    authenticated::lookup::{Config, Network, Oracle},
    Blocker, Receiver, Recipients, Sender,
};
use commonware_runtime::{deterministic, Clock, Handle, Metrics, Runner};
use commonware_utils::NZU32;
use governor::Quota;
use libfuzzer_sys::fuzz_target;
use rand::{rngs::StdRng, Rng, SeedableRng};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::Duration,
};

const MAX_PEERS: usize = 16;
const MAX_MESSAGE_SIZE: usize = 64 * 1024;
const MAX_CHANNELS: u8 = 3;

#[derive(Debug, Arbitrary)]
enum LookupOperation {
    SendMessage {
        sender_idx: u8,
        recipient_mode: u8,
        recipient_idx: u8,
        msg_size: u32,
        priority: bool,
        channel: u8,
    },
    ReceiveMessage {
        receiver_idx: u8,
    },
    RegisterPeers {
        peer_idx: u8,
        channel: u8,
        num_peers: u8,
    },
    BlockPeer {
        peer_idx: u8,
        target_idx: u8,
    },
    Sleep {
        ms: u16,
    },
}

#[derive(Debug)]
struct FuzzInput {
    seed: u64,
    operations: Vec<LookupOperation>,
    n: u8,
}

impl<'a> Arbitrary<'a> for FuzzInput {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let seed = u.arbitrary()?;
        let operations = u.arbitrary()?;
        let n = u.int_in_range(2..=MAX_PEERS as u32)? as u8;
        Ok(FuzzInput {
            seed,
            operations,
            n,
        })
    }
}

struct PeerInfo {
    private_key: ed25519::PrivateKey,
    public_key: ed25519::PublicKey,
    address: SocketAddr,
}

struct NetworkState {
    handle: Option<Handle<()>>,
    senders: HashMap<u8, commonware_p2p::authenticated::lookup::Sender<ed25519::PublicKey>>,
    receivers: HashMap<u8, commonware_p2p::authenticated::lookup::Receiver<ed25519::PublicKey>>,
    oracle: Oracle<deterministic::Context, ed25519::PublicKey>,
}

fn fuzz(input: FuzzInput) {
    let mut rng = StdRng::seed_from_u64(input.seed);
    let n = input.n;

    let executor = deterministic::Runner::seeded(input.seed);
    executor.start(|context| async move {
        let mut peers = Vec::new();
        let base_port = 64000;
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

        let mut networks: HashMap<u8, NetworkState> = HashMap::new();

        for (peer_idx, peer) in peers.iter().enumerate() {
            let peer_idx_u8 = peer_idx as u8;

            let mut config = Config::aggressive(
                peer.private_key.clone(),
                b"fuzz_namespace",
                peer.address,
                peer.address,
                MAX_MESSAGE_SIZE,
            );
            config.mailbox_size = 100;
            config.allow_private_ips = true;

            let (mut network, oracle) =
                Network::new(context.with_label(&format!("peer-{peer_idx}")), config);

            let mut senders = HashMap::new();
            let mut receivers = HashMap::new();

            for ch in 0..MAX_CHANNELS {
                let quota = Quota::per_second(NZU32!(100));
                let (sender, receiver) = network.register(ch as u32, quota, 32);
                senders.insert(ch, sender);
                receivers.insert(ch, receiver);
            }

            let handle = network.start();

            networks.insert(
                peer_idx_u8,
                NetworkState {
                    handle: Some(handle),
                    senders,
                    receivers,
                    oracle,
                },
            );
        }

        let mut expected_messages: HashMap<(u8, u8, u8), VecDeque<Bytes>> = HashMap::new();
        let mut pending_by_receiver: HashMap<(u8, u8), Vec<u8>> = HashMap::new();

        for operation in input.operations.iter().take(50) {
            match operation {
                LookupOperation::SendMessage {
                    sender_idx,
                    recipient_mode,
                    recipient_idx,
                    msg_size,
                    priority,
                    channel,
                } => {
                    let sender_idx = (*sender_idx as usize) % peers.len();
                    let sender_idx_u8 = sender_idx as u8;
                    let channel = *channel % MAX_CHANNELS;

                    if let Some(state) = networks.get_mut(&sender_idx_u8) {
                        if let Some(sender) = state.senders.get_mut(&channel) {
                            let msg_size = (*msg_size as usize).clamp(1, MAX_MESSAGE_SIZE);
                            let mut message = vec![0u8; msg_size];
                            rng.fill(&mut message[..]);

                            let recipient_idx = (*recipient_idx as usize) % peers.len();
                            let recipient_pk = peers[recipient_idx].public_key.clone();

                            let recipients = match recipient_mode % 3 {
                                0 => Recipients::All,
                                1 => {
                                    if recipient_idx == sender_idx {
                                        continue;
                                    }
                                    Recipients::One(recipient_pk)
                                },
                                _ => {
                                    let max_recipients = peers.len().min(3);
                                    let num_recipients = (rng.gen::<usize>() % max_recipients).max(1);
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

                            let message_bytes = Bytes::from(message);

                            // Collect target recipient indices first
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
                                },
                                Recipients::Some(pk_list) => {
                                    pk_list.iter()
                                        .filter_map(|pk| pk_to_idx.get(pk).copied())
                                        .filter(|&to_idx| to_idx != sender_idx_u8)
                                        .collect()
                                },
                                Recipients::All => {
                                    (0..peers.len())
                                        .map(|i| i as u8)
                                        .filter(|&to_idx| to_idx != sender_idx_u8)
                                        .collect()
                                },
                            };

                            // Only add expectations if send succeeds
                            if sender.send(recipients, message_bytes.clone(), *priority).await.is_ok() {
                                for to_idx in target_recipients {
                                    expected_messages.entry((to_idx, sender_idx_u8, channel))
                                        .or_default()
                                        .push_back(message_bytes.clone());
                                    pending_by_receiver.entry((to_idx, channel))
                                        .or_default()
                                        .push(sender_idx_u8);
                                }
                            }
                        }
                    }
                }

                LookupOperation::ReceiveMessage { receiver_idx } => {
                    let receiver_idx = (*receiver_idx as usize) % peers.len();
                    let receiver_idx_u8 = receiver_idx as u8;

                    if let Some(state) = networks.get_mut(&receiver_idx_u8) {
                        let channels_with_pending: Vec<u8> = pending_by_receiver
                            .iter()
                            .filter_map(|((to_idx, ch), senders)| {
                                if *to_idx == receiver_idx_u8 && !senders.is_empty() {
                                    Some(*ch)
                                } else {
                                    None
                                }
                            })
                            .collect();

                        if channels_with_pending.is_empty() {
                            continue;
                        }

                        for channel in channels_with_pending {
                            if let Some(receiver) = state.receivers.get_mut(&channel) {
                                commonware_macros::select! {
                                    result = receiver.recv() => {
                                        if let Ok((sender_pk, message)) = result {
                                            if let Some(&actual_sender_idx) = pk_to_idx.get(&sender_pk) {
                                                let key = (receiver_idx_u8, actual_sender_idx, channel);
                                                if let Some(queue) = expected_messages.get_mut(&key) {
                                                    if let Some(expected_message) = queue.pop_front() {
                                                        assert_eq!(message, expected_message);
                                                        if queue.is_empty() {
                                                            expected_messages.remove(&key);
                                                        }
                                                        // Remove from pending_by_receiver
                                                        if let Some(senders) = pending_by_receiver.get_mut(&(receiver_idx_u8, channel)) {
                                                            if let Some(pos) = senders.iter().position(|&x| x == actual_sender_idx) {
                                                                senders.remove(pos);
                                                            }
                                                            if senders.is_empty() {
                                                                pending_by_receiver.remove(&(receiver_idx_u8, channel));
                                                            }
                                                        }
                                                        break;
                                                    }
                                                } else {
                                                    // Unexpected delivery - still need to clean up pending_by_receiver
                                                    if let Some(senders) = pending_by_receiver.get_mut(&(receiver_idx_u8, channel)) {
                                                        if let Some(pos) = senders.iter().position(|&x| x == actual_sender_idx) {
                                                            senders.remove(pos);
                                                        }
                                                        if senders.is_empty() {
                                                            pending_by_receiver.remove(&(receiver_idx_u8, channel));
                                                        }
                                                    }
                                                    break;
                                                }
                                            }
                                        }
                                    },
                                    _ = context.sleep(Duration::from_millis(100)) => {
                                        continue;
                                    },
                                }
                            }
                        }
                    }
                }

                LookupOperation::RegisterPeers {
                    peer_idx,
                    channel,
                    num_peers,
                } => {
                    let peer_idx = (*peer_idx as usize) % peers.len();
                    let peer_idx_u8 = peer_idx as u8;
                    let channel = *channel % MAX_CHANNELS;
                    let num_peers = (*num_peers as usize).clamp(1, peers.len());
                    
                    if let Some(state) = networks.get_mut(&peer_idx_u8) {
                        let mut peer_set = HashSet::new();
                        for _ in 0..num_peers {
                            let idx = rng.gen::<usize>() % peers.len();
                            let peer = &peers[idx];
                            peer_set.insert((peer.public_key.clone(), peer.address));
                        }
                        let peer_subset: Vec<_> = peer_set.into_iter().collect();
                        
                        let _ = state.oracle.register(channel as u64, peer_subset).await;
                    }
                }

                LookupOperation::BlockPeer {
                    peer_idx,
                    target_idx,
                } => {
                    let peer_idx = (*peer_idx as usize) % peers.len();
                    let peer_idx_u8 = peer_idx as u8;
                    let target_idx = (*target_idx as usize) % peers.len();
                    let target_idx_u8 = target_idx as u8;
                    
                    if let Some(state) = networks.get_mut(&peer_idx_u8) {
                        let target_pk = peers[target_idx].public_key.clone();
                        let _ = state.oracle.block(target_pk).await;
                        
                        // Remove expectations for messages from target_idx to peer_idx
                        expected_messages.retain(|(to_idx, from_idx, _ch), _queue| {
                            !(*to_idx == peer_idx_u8 && *from_idx == target_idx_u8)
                        });
                        
                        // Remove from pending_by_receiver index
                        pending_by_receiver.retain(|(to_idx, _ch), senders| {
                            if *to_idx == peer_idx_u8 {
                                senders.retain(|&from_idx| from_idx != target_idx_u8);
                            }
                            !senders.is_empty()
                        });
                    }
                }

                LookupOperation::Sleep { ms } => {
                    let duration = Duration::from_millis((*ms as u64).min(100));
                    context.sleep(duration).await;
                }
            }
        }

        for (_, state) in networks {
            if let Some(handle) = state.handle {
                handle.abort();
            }
        }
    });
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
