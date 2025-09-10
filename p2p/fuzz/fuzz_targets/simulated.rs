#![no_main]

use arbitrary::Arbitrary;
use bytes::Bytes;
use commonware_cryptography::{ed25519, PrivateKeyExt, Signer};
use commonware_p2p::{
    simulated::{Config, Link, Network},
    Receiver as ReceiverTrait, Recipients, Sender as SenderTrait,
};
use commonware_runtime::{deterministic, Clock, Metrics, Runner};
use libfuzzer_sys::fuzz_target;
use rand::{rngs::StdRng, Rng, SeedableRng};
use std::{collections::HashMap, time::Duration};

const MAX_OPERATIONS: usize = 100;
const MAX_PEERS: usize = 5;

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
        message_data: Vec<u8>,
    },
    ReceiveMessage {
        peer_idx: u8,
        channel_id: u8,
    },
    AddLink {
        from_idx: u8,
        to_idx: u8,
        latency_ms: u16,
        success_rate: u8,
    },
    RemoveLink {
        from_idx: u8,
        to_idx: u8,
    },
    StartNetwork,
    StopNetwork,
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
}

impl<'a> Arbitrary<'a> for FuzzInput {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let seed = u.arbitrary()?;
        let operations = u.arbitrary()?;
        Ok(FuzzInput { seed, operations })
    }
}

fn fuzz(input: FuzzInput) {
    let mut rng = StdRng::seed_from_u64(input.seed);
    
    let executor = deterministic::Runner::seeded(input.seed);
    executor.start(|context| async move {
        let mut peers = Vec::new();
        for i in 0..MAX_PEERS {
            let seed = rng.gen::<u64>() ^ (i as u64);
            let private_key = ed25519::PrivateKey::from_seed(seed);
            peers.push(private_key.public_key());
        }
        
        let config = Config {
            max_size: 1024 * 1024,
        };
        
        let (network, mut oracle) = Network::new(context.with_label("network"), config);
        
        let _network_handle = network.start();
        
        let mut channels = HashMap::new();
        let mut registered_peer_channels = std::collections::HashSet::new();
        
        for op in input.operations.into_iter().take(MAX_OPERATIONS) {
            match op {
                SimulatedOperation::CreateNetwork { max_size: _ } => {
                }
                
                SimulatedOperation::RegisterChannel {
                    peer_idx,
                    channel_id,
                } => {
                    let idx = (peer_idx as usize) % MAX_PEERS;
                    let key = (idx, channel_id);
                    if !registered_peer_channels.contains(&key) {
                        if let Ok((sender, receiver)) = oracle.register(peers[idx].clone(), channel_id as u32).await {
                            channels.insert((idx, channel_id), (sender, receiver));
                            registered_peer_channels.insert(key);
                        }
                    }
                }
                
                SimulatedOperation::SendMessage {
                    peer_idx,
                    channel_id,
                    to_idx,
                    message_data,
                } => {
                    let from_idx = (peer_idx as usize) % MAX_PEERS;
                    let to_idx = (to_idx as usize) % MAX_PEERS;
                    
                    if let Some((ref mut sender, _)) = channels.get_mut(&(from_idx, channel_id)) {
                        let message = Bytes::from(message_data);
                        let _ = sender.send(Recipients::One(peers[to_idx].clone()), message, false).await;
                    }
                }
                
                SimulatedOperation::ReceiveMessage {
                    peer_idx,
                    channel_id,
                } => {
                    let idx = (peer_idx as usize) % MAX_PEERS;
                    
                    if let Some((_, ref mut receiver)) = channels.get_mut(&(idx, channel_id)) {
                        commonware_macros::select! {
                            _ = receiver.recv() => {},
                            _ = context.sleep(Duration::from_millis(10)) => {},
                        }
                    }
                }
                
                SimulatedOperation::AddLink {
                    from_idx,
                    to_idx,
                    latency_ms,
                    success_rate,
                } => {
                    let from_idx = (from_idx as usize) % MAX_PEERS;
                    let to_idx = (to_idx as usize) % MAX_PEERS;
                    
                    if from_idx != to_idx {
                        let link = Link {
                            latency: Duration::from_millis(latency_ms as u64),
                            jitter: Duration::from_millis(0),
                            success_rate: (success_rate as f64) / 255.0,
                        };
                        let _ = oracle.add_link(peers[from_idx].clone(), peers[to_idx].clone(), link).await;
                    }
                }
                
                SimulatedOperation::RemoveLink {
                    from_idx,
                    to_idx,
                } => {
                    let from_idx = (from_idx as usize) % MAX_PEERS;
                    let to_idx = (to_idx as usize) % MAX_PEERS;
                    
                    let _ = oracle.remove_link(peers[from_idx].clone(), peers[to_idx].clone()).await;
                }
                
                SimulatedOperation::StartNetwork => {
                }
                
                SimulatedOperation::StopNetwork => {
                }
                
                SimulatedOperation::DropChannel {
                    peer_idx,
                    channel_id,
                } => {
                    let idx = (peer_idx as usize) % MAX_PEERS;
                    let key = (idx, channel_id);
                    channels.remove(&key);
                    registered_peer_channels.remove(&key);
                }
                
                SimulatedOperation::Sleep { ms } => {
                    let sleep_duration = (ms as u64).min(100);
                    context.sleep(Duration::from_millis(sleep_duration)).await;
                }
            }
        }
    });
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});