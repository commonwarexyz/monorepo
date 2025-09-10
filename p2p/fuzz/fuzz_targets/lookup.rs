#![no_main]

use arbitrary::Arbitrary;
use bytes::Bytes;
use commonware_cryptography::{ed25519, PrivateKeyExt, Signer};
use commonware_p2p::{
    authenticated::lookup::{Config, Network},
    Receiver as ReceiverTrait, Recipients, Sender,
};
use commonware_runtime::{deterministic, Clock, Metrics, Runner};
use governor::Quota;
use libfuzzer_sys::fuzz_target;
use rand::{rngs::StdRng, Rng, SeedableRng};
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    num::NonZeroU32,
    time::Duration,
};

const MAX_OPERATIONS: usize = 100;

#[derive(Debug, Arbitrary)]
enum LookupOperation {
    CreateNetwork {
        peer_idx: u8,
        port: u16,
    },
    RegisterChannel {
        channel_id: u16,
    },
    SendMessage {
        channel_id: u16,
        message_data: Vec<u8>,
        priority: bool,
    },
    ReceiveMessage {
        channel_id: u16,
    },
    StartNetwork,
    StopNetwork,
    DropChannel {
        channel_id: u16,
    },
    Disconnect,
    Sleep {
        ms: u16,
    },
}

#[derive(Debug)]
struct FuzzInput {
    seed: u64,
    operations: Vec<LookupOperation>,
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
        let private_key = ed25519::PrivateKey::from_seed(rng.gen());
        let peer2 = ed25519::PrivateKey::from_seed(rng.gen());
        let peer3 = ed25519::PrivateKey::from_seed(rng.gen());
        
        let port = 20000 + (rng.gen::<u16>() % 10000);
        let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
        
        let peers = vec![
            (peer2.public_key(), SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port + 1)),
            (peer3.public_key(), SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port + 2)),
        ];
        
        let config = Config::recommended(
            private_key,
            b"fuzz",
            address,
            address,
            1024 * 1024,
        );
        
        let (network, mut oracle) = Network::new(context.with_label("network"), config.clone());
        
        oracle.register(0, peers.clone()).await;
        
        let _network_handle = network.start();
        
        let (mut channel_network, _) = Network::new(context.with_label("channels"), config);
        
        let mut channels = std::collections::HashMap::new();
        let mut registered_channels = std::collections::HashSet::new();
        
        for op in input.operations.into_iter().take(MAX_OPERATIONS) {
            match op {
                LookupOperation::CreateNetwork { peer_idx: _, port: _ } => {
                }
                
                LookupOperation::RegisterChannel { channel_id } => {
                    if !registered_channels.contains(&channel_id) {
                        let (sender, receiver) = channel_network.register(
                            channel_id as u32,
                            Quota::per_second(NonZeroU32::new(100).unwrap()),
                            128,
                        );
                        channels.insert(channel_id, (sender, receiver));
                        registered_channels.insert(channel_id);
                    }
                }
                
                LookupOperation::SendMessage {
                    channel_id,
                    message_data,
                    priority,
                } => {
                    if let Some((ref mut sender, _)) = channels.get_mut(&channel_id) {
                        let message = Bytes::from(message_data);
                        let recipients = if rng.gen_bool(0.5) {
                            Recipients::All
                        } else {
                            Recipients::One(peer2.public_key())
                        };
                        let _ = sender.send(recipients, message, priority).await;
                    }
                }
                
                LookupOperation::ReceiveMessage { channel_id } => {
                    if let Some((_, ref mut receiver)) = channels.get_mut(&channel_id) {
                        commonware_macros::select! {
                            _ = receiver.recv() => {},
                            _ = context.sleep(Duration::from_millis(10)) => {},
                        }
                    }
                }
                
                LookupOperation::StartNetwork => {
                }
                
                LookupOperation::StopNetwork => {
                }
                
                LookupOperation::DropChannel { channel_id } => {
                    channels.remove(&channel_id);
                    registered_channels.remove(&channel_id);
                }
                
                LookupOperation::Disconnect => {
                }
                
                LookupOperation::Sleep { ms } => {
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