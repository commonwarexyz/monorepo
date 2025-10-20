#![no_main]

use arbitrary::Arbitrary;
use bytes::Bytes;
use commonware_codec::codec::FixedSize;
use commonware_cryptography::{ed25519, PrivateKeyExt, Signer};
use commonware_p2p::{
    simulated::{self},
    Channel, Receiver as ReceiverTrait, Recipients, Sender as SenderTrait,
};
use commonware_runtime::{deterministic, Clock, Metrics, Runner};
use libfuzzer_sys::fuzz_target;
use rand::Rng;
use std::{
    collections::{HashMap, VecDeque},
    time::Duration,
};

const MAX_OPERATIONS: usize = 50;
const MAX_PEERS: usize = 16;
const MAX_SLEEP_DURATION: u64 = 1000;
const MAX_MSG_SIZE: usize = 1024 * 1024; // 1MB

#[derive(Debug, Arbitrary)]
enum SimulatedOperation {
    RegisterChannel {
        peer_idx: u8,
        channel_id: u8,
    },
    SendMessage {
        peer_idx: u8,
        channel_id: u8,
        to_idx: u8,
        msg_size: usize,
    },
    ReceiveMessages,
    AddLink {
        from_idx: u8,
        to_idx: u8,
        latency_ms: u16,
        jitter: u16,
        success_rate: u8,
    },
    RemoveLink {
        from_idx: u8,
        to_idx: u8,
    },
}

#[derive(Debug)]
struct FuzzInput {
    seed: u64,
    // Length is in [1, MAX_OPERATIONS]
    operations: Vec<SimulatedOperation>,
    // Length is in [2, MAX_PEERS]
    num_peers: u8,
}

impl<'a> Arbitrary<'a> for FuzzInput {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let seed = u.arbitrary()?;
        let num_operations = u.int_in_range(1..=MAX_OPERATIONS)?;
        let mut operations = Vec::with_capacity(num_operations);
        for _ in 0..num_operations {
            operations.push(u.arbitrary()?);
        }
        let num_peers = u.int_in_range(2..=MAX_PEERS)? as u8;
        Ok(FuzzInput {
            seed,
            operations,
            num_peers,
        })
    }
}

fn fuzz(input: FuzzInput) {
    let num_peers = input.num_peers;

    let p2p_cfg = simulated::Config {
        max_size: MAX_MSG_SIZE,
        disconnect_on_block: false,
    };

    let executor = deterministic::Runner::seeded(input.seed);
    executor.start(|mut context| async move {
        let mut peers = Vec::new();
        for _ in 0..num_peers {
            let private_key = ed25519::PrivateKey::from_seed(context.gen());
            peers.push(private_key.public_key());
        }
        let (network, mut oracle) = simulated::Network::new(context.with_label("network"), p2p_cfg);
        let network_handler = network.start();

        let mut channels: HashMap<
            (usize, u8),
            (
                commonware_p2p::simulated::Sender<ed25519::PublicKey>,
                commonware_p2p::simulated::Receiver<ed25519::PublicKey>,
            ),
        > = HashMap::new();
        let mut registered_peer_channels = std::collections::HashSet::new();
        let mut expected: HashMap<(usize, ed25519::PublicKey, u8), VecDeque<Bytes>> = HashMap::new();

        for op in input.operations.into_iter() {
            match op {
                SimulatedOperation::RegisterChannel {
                    peer_idx,
                    channel_id,
                } => {
                    let idx = (peer_idx as usize) % peers.len();
                    let key = (idx, peers[idx].clone(), channel_id);
                    if !registered_peer_channels.contains(&key) {
                        if let Ok((sender, receiver)) =
                            oracle.register(peers[idx].clone(), channel_id as u32).await
                        {
                            channels.insert((idx, channel_id), (sender, receiver));
                            registered_peer_channels.insert(key);
                        }
                    }
                }

                SimulatedOperation::SendMessage {
                    peer_idx,
                    channel_id,
                    to_idx,
                    msg_size,
                } => {
                    let from_idx = (peer_idx as usize) % peers.len();
                    let to_idx = (to_idx as usize) % peers.len();
                    let msg_size = msg_size.clamp(0, MAX_MSG_SIZE - Channel::SIZE);

                    let Some((ref mut sender, _)) = channels.get_mut(&(from_idx, channel_id))
                    else {
                        continue;
                    };

                    let mut bytes = vec![0u8; msg_size];
                    context.fill(&mut bytes[..]);
                    let message = Bytes::from(bytes);

                    // Only add expectation if send succeeds
                    let res = sender
                        .send(
                            Recipients::One(peers[to_idx].clone()),
                            message.clone(),
                            true,
                        )
                        .await;
                    if res.is_ok() {
                        expected
                            .entry((to_idx, peers[from_idx].clone(), channel_id))
                            .or_default()
                            .push_back(message);
                    }
                }

                SimulatedOperation::ReceiveMessages => {
                    let expected_keys: Vec<_> = expected.keys().cloned().collect();
                    for (to_idx, real_sender_id, channel_id) in expected_keys {
                        let Some((_, ref mut receiver)) = channels.get_mut(&(to_idx, channel_id))
                        else {
                            continue;
                        };
                        let Some(queue) = expected.get_mut(&(to_idx, real_sender_id.clone(), channel_id)) else {
                            continue;
                        };

                        commonware_macros::select! {
                            result = receiver.recv() => {
                                if let Ok((recv_sender_id, message)) = result {
                                    if let Some(pos) = queue.iter().position(|m: &Bytes| m == &message) {
                                        queue.remove(pos);
                                        if recv_sender_id != real_sender_id {
                                            panic!("Message sender: {recv_sender_id}, but real sender: {real_sender_id}");
                                        }
                                        if queue.is_empty() {
                                            expected.remove(&(to_idx, real_sender_id, channel_id));
                                        }
                                    } else {
                                        panic!("Message not found in expected queue");
                                    }
                                }
                            },
                            _ = context.sleep(Duration::from_millis(MAX_SLEEP_DURATION)) => {
                                continue;
                            }
                        }
                    }
                }

                SimulatedOperation::AddLink {
                    from_idx,
                    to_idx,
                    latency_ms,
                    jitter,
                    success_rate,
                } => {
                    let from_idx = (from_idx as usize) % peers.len();
                    let to_idx = (to_idx as usize) % peers.len();

                    let link = simulated::Link {
                        latency: Duration::from_millis(latency_ms as u64),
                        jitter: Duration::from_millis(jitter as u64),
                        success_rate: (success_rate as f64) / 255.0,
                    };
                    let _ = oracle
                        .add_link(peers[from_idx].clone(), peers[to_idx].clone(), link)
                        .await;
                }

                SimulatedOperation::RemoveLink { from_idx, to_idx } => {
                    let from_idx = (from_idx as usize) % peers.len();
                    let to_idx = (to_idx as usize) % peers.len();
                    let _ = oracle
                        .remove_link(peers[from_idx].clone(), peers[to_idx].clone())
                        .await;
                }
            }
        }

        network_handler.abort();
    });
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
