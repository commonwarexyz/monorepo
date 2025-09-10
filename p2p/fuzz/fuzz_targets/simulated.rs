#![no_main]

use arbitrary::Arbitrary;
use bytes::Bytes;
use commonware_cryptography::{ed25519, PrivateKeyExt, Signer};
use commonware_p2p::{
    simulated::{Config, Link, Network, Oracle},
    Receiver as ReceiverTrait, Recipients, Sender as SenderTrait,
};
use commonware_runtime::{deterministic, Clock, Handle, Metrics, Runner};
use libfuzzer_sys::fuzz_target;
use rand::{rngs::StdRng, Rng, SeedableRng};
use std::{
    collections::{HashMap, VecDeque},
    time::Duration,
};

const MAX_OPERATIONS: usize = 50;
const MAX_PEERS: usize = 16;
const MIN_SLEEP_DURATION: u64 = 100;
const MAX_SLEEP_DURATION: u64 = 3000;
const MAX_MESSAGE_SIZE: usize = 10 * 1024 * 1024;

#[derive(Debug, Arbitrary)]
enum SimulatedOperation {
    CreateNetwork {
        max_size: u32,
    },
    RegisterChannel {
        peer_idx: u8,
        channel_id: u8,
    },
    SendMessage {
        peer_idx: u8,
        channel_id: u8,
        to_idx: u8,
        msg_size: u32,
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
    RegisterAndLink {
        from_idx: u8,
        to_idx: u8,
        channel_id: u8,
        latency_ms: u16,
        success_rate: u8,
        jitter_ms: u16,
    },
    AbortNetwork,
    DropChannel {
        peer_idx: u8,
        channel_id: u8,
    },
    Sleep {
        ms: u16,
    },
}

#[derive(Debug)]
struct FuzzInput {
    seed: u64,
    operations: Vec<SimulatedOperation>,
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

fn fuzz(input: FuzzInput) {
    let mut rng = StdRng::seed_from_u64(input.seed);
    let n = input.n;

    let executor = deterministic::Runner::seeded(input.seed);
    executor.start(|context| async move {
        let mut peers = Vec::new();
        for i in 0..n {
            let seed = rng.gen::<u64>() ^ (i as u64);
            let private_key = ed25519::PrivateKey::from_seed(seed);
            peers.push(private_key.public_key());
        }

        let mut oracle: Option<Oracle<ed25519::PublicKey>> = None;
        let mut channels: HashMap<
            (usize, u8),
            (
                commonware_p2p::simulated::Sender<ed25519::PublicKey>,
                commonware_p2p::simulated::Receiver<ed25519::PublicKey>,
            ),
        > = HashMap::new();
        let mut registered_peer_channels = std::collections::HashSet::new();
        let mut network_handle: Option<Handle<()>> = None;
        let mut expected: HashMap<(usize, u8), VecDeque<Bytes>> = HashMap::new();

        for op in input.operations.into_iter().take(MAX_OPERATIONS) {
            match op {
                SimulatedOperation::CreateNetwork { max_size } => {
                    let config = Config {
                        max_size: (max_size as usize).clamp(1, MAX_MESSAGE_SIZE),
                    };
                    if let Some(handle) = network_handle.take() {
                        handle.abort();
                    }
                    let (new_network, new_oracle) =
                        Network::new(context.with_label("network"), config);
                    let handle = new_network.start();
                    oracle = Some(new_oracle);
                    network_handle = Some(handle);
                    channels.clear();
                    registered_peer_channels.clear();
                    expected.clear();
                }

                SimulatedOperation::RegisterChannel {
                    peer_idx,
                    channel_id,
                } => {
                    let idx = (peer_idx as usize) % peers.len();
                    let key = (idx, channel_id);
                    if !registered_peer_channels.contains(&key) {
                        if let Some(ref mut oracle) = oracle {
                            if let Ok((sender, receiver)) =
                                oracle.register(peers[idx].clone(), channel_id as u32).await
                            {
                                channels.insert((idx, channel_id), (sender, receiver));
                                registered_peer_channels.insert(key);
                            }
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
                    let msg_size = msg_size.clamp(1, MAX_MESSAGE_SIZE as u32);

                    if let Some((ref mut sender, _)) = channels.get_mut(&(from_idx, channel_id)) {
                        let mut bytes = vec![0u8; msg_size as usize];
                        rng.fill(&mut bytes[..]);
                        let message = Bytes::from(bytes);

                        // Only add expectation if send succeeds
                        let res = sender
                            .send(Recipients::One(peers[to_idx].clone()), message.clone(), true)
                            .await;
                        if res.is_ok() {
                            expected.entry((to_idx, channel_id))
                                .or_default()
                                .push_back(message);
                        }
                    }
                }

                SimulatedOperation::ReceiveMessages => {
                    let expected_keys: Vec<_> = expected.keys().copied().collect();
                    for (to_idx, channel_id) in expected_keys {
                        if let Some((_, ref mut receiver)) = channels.get_mut(&(to_idx, channel_id)) {
                            if let Some(queue) = expected.get_mut(&(to_idx, channel_id)) {
                                commonware_macros::select! {
                                    result = receiver.recv() => {
                                        if let Ok((_peer, message)) = result {
                                            if let Some(pos) = queue.iter().position(|m| m == &message) {
                                                queue.remove(pos); // remove the matched one
                                                if queue.is_empty() { expected.remove(&(to_idx, channel_id)); }
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

                    if from_idx != to_idx {
                        if let Some(ref mut oracle) = oracle {
                            let link = Link {
                                latency: Duration::from_millis(latency_ms as u64),
                                jitter: Duration::from_millis(jitter as u64),
                                success_rate: (success_rate as f64) / 255.0,
                            };
                            let _ = oracle
                                .add_link(peers[from_idx].clone(), peers[to_idx].clone(), link)
                                .await;
                        }
                    }
                }

                SimulatedOperation::RemoveLink { from_idx, to_idx } => {
                    let from_idx = (from_idx as usize) % peers.len();
                    let to_idx = (to_idx as usize) % peers.len();

                    if let Some(ref mut oracle) = oracle {
                        let _ = oracle
                            .remove_link(peers[from_idx].clone(), peers[to_idx].clone())
                            .await;
                    }
                }

                SimulatedOperation::RegisterAndLink {
                    from_idx,
                    to_idx,
                    channel_id,
                    latency_ms,
                    success_rate,
                    jitter_ms,
                } => {
                    let from_idx = (from_idx as usize) % peers.len();
                    let to_idx = (to_idx as usize) % peers.len();

                    if let Some(ref mut oracle) = oracle {
                        // Register channels for both peers if they don't exist
                        let from_key = (from_idx, channel_id);
                        let to_key = (to_idx, channel_id);

                        if !registered_peer_channels.contains(&from_key) {
                            if let Ok((sender, receiver)) = oracle
                                .register(peers[from_idx].clone(), channel_id as u32)
                                .await
                            {
                                channels.insert(from_key, (sender, receiver));
                                registered_peer_channels.insert(from_key);
                            }
                        }

                        if !registered_peer_channels.contains(&to_key) {
                            if let Ok((sender, receiver)) = oracle
                                .register(peers[to_idx].clone(), channel_id as u32)
                                .await
                            {
                                channels.insert(to_key, (sender, receiver));
                                registered_peer_channels.insert(to_key);
                            }
                        }

                        // Add link between the peers
                        if from_idx != to_idx {
                            let link = Link {
                                latency: Duration::from_millis(latency_ms as u64),
                                jitter: Duration::from_millis(jitter_ms as u64),
                                success_rate: (success_rate as f64) / 255.0,
                            };
                            let _ = oracle
                                .add_link(peers[from_idx].clone(), peers[to_idx].clone(), link)
                                .await;
                        }
                    }
                }

                SimulatedOperation::AbortNetwork => {
                    if let Some(handle) = network_handle.take() {
                        handle.abort();
                    }
                    oracle = None;
                    channels.clear();
                    registered_peer_channels.clear();
                    expected.clear();
                }

                SimulatedOperation::DropChannel {
                    peer_idx,
                    channel_id,
                } => {
                    let idx = (peer_idx as usize) % peers.len();
                    let key = (idx, channel_id);
                    channels.remove(&key);
                    registered_peer_channels.remove(&key);
                    expected.remove(&key);
                }

                SimulatedOperation::Sleep { ms } => {
                    let sleep_duration = (ms as u64).clamp(MIN_SLEEP_DURATION, MAX_SLEEP_DURATION);
                    context.sleep(Duration::from_millis(sleep_duration)).await;
                }
            }
        }

        // Final teardown
        if let Some(handle) = network_handle.take() {
            handle.abort();
        }
    });
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
