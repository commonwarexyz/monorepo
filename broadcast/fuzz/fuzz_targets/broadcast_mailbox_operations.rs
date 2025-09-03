#![no_main]

use commonware_broadcast::{
    buffered::{Config, Engine},
    Broadcaster,
};
use commonware_codec::RangeCfg;
use commonware_cryptography::{
    ed25519::{PrivateKey, PublicKey},
    Committable, Digestible, Hasher, PrivateKeyExt as _, Sha256, Signer,
};
use commonware_p2p::{simulated::Network, Recipients};
use commonware_runtime::{deterministic, Clock, Metrics, Runner, Spawner};
use bytes::{Buf, BufMut};
use libfuzzer_sys::fuzz_target;
use std::time::Duration;

// Reuse FuzzMessage from the first target
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FuzzMessage {
    pub commitment: Vec<u8>,
    pub content: Vec<u8>,
}

impl FuzzMessage {
    fn new(commitment: Vec<u8>, content: Vec<u8>) -> Self {
        Self {
            commitment,
            content,
        }
    }

    fn shared(msg: Vec<u8>) -> Self {
        Self::new(msg.clone(), msg)
    }
}

impl Digestible for FuzzMessage {
    type Digest = commonware_cryptography::sha256::Digest;
    fn digest(&self) -> Self::Digest {
        Sha256::hash(&self.content)
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
    type Cfg = RangeCfg;

    fn read_cfg(buf: &mut impl Buf, range: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        use commonware_codec::ReadRangeExt;
        let commitment = Vec::<u8>::read_range(buf, *range)?;
        let content = Vec::<u8>::read_range(buf, *range)?;
        Ok(Self {
            commitment,
            content,
        })
    }
}

#[derive(Debug, Clone)]
enum MailboxOperation {
    Broadcast {
        recipients: Recipients<PublicKey>,
        message_data: Vec<u8>,
    },
    Subscribe {
        sender_seed: Option<u64>,
        commitment_data: Vec<u8>,
        digest_data: Option<Vec<u8>>,
        timeout_ms: u64,
    },
    GetImmediate {
        sender_seed: Option<u64>,
        commitment_data: Vec<u8>,
        digest_data: Option<Vec<u8>>,
    },
    ConcurrentBroadcast {
        message_count: usize,
        base_message: Vec<u8>,
    },
    SubscribeThenBroadcast {
        commitment_data: Vec<u8>,
        message_data: Vec<u8>,
        delay_ms: u64,
    },
}

impl<'a> arbitrary::Arbitrary<'a> for MailboxOperation {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let op_type = u.int_in_range(0..=4)?;
        match op_type {
            0 => {
                let recipients = if u.int_in_range(0..=1)? == 0 {
                    Recipients::All
                } else {
                    let seed = u64::arbitrary(u)?;
                    let peer = PrivateKey::from_seed(seed).public_key();
                    Recipients::One(peer)
                };
                
                let msg_len = u.int_in_range(1..=512)?;
                let message_data = (0..msg_len)
                    .map(|_| u8::arbitrary(u))
                    .collect::<Result<Vec<_>, _>>()?;
                    
                Ok(MailboxOperation::Broadcast { recipients, message_data })
            }
            1 => {
                let sender_seed = if u.int_in_range(0..=1)? == 0 {
                    None
                } else {
                    Some(u64::arbitrary(u)?)
                };
                
                let commitment_len = u.int_in_range(1..=128)?;
                let commitment_data = (0..commitment_len)
                    .map(|_| u8::arbitrary(u))
                    .collect::<Result<Vec<_>, _>>()?;
                    
                let digest_data = if u.int_in_range(0..=1)? == 0 {
                    None
                } else {
                    let digest_len = u.int_in_range(1..=64)?;
                    Some((0..digest_len)
                        .map(|_| u8::arbitrary(u))
                        .collect::<Result<Vec<_>, _>>()?)
                };
                
                let timeout_ms = u.int_in_range(1..=200)?;
                
                Ok(MailboxOperation::Subscribe {
                    sender_seed,
                    commitment_data,
                    digest_data,
                    timeout_ms,
                })
            }
            2 => {
                let sender_seed = if u.int_in_range(0..=1)? == 0 {
                    None
                } else {
                    Some(u64::arbitrary(u)?)
                };
                
                let commitment_len = u.int_in_range(1..=128)?;
                let commitment_data = (0..commitment_len)
                    .map(|_| u8::arbitrary(u))
                    .collect::<Result<Vec<_>, _>>()?;
                    
                let digest_data = if u.int_in_range(0..=1)? == 0 {
                    None
                } else {
                    let digest_len = u.int_in_range(1..=64)?;
                    Some((0..digest_len)
                        .map(|_| u8::arbitrary(u))
                        .collect::<Result<Vec<_>, _>>()?)
                };
                
                Ok(MailboxOperation::GetImmediate {
                    sender_seed,
                    commitment_data,
                    digest_data,
                })
            }
            3 => {
                let message_count = u.int_in_range(1..=5)?;
                let msg_len = u.int_in_range(1..=128)?;
                let base_message = (0..msg_len)
                    .map(|_| u8::arbitrary(u))
                    .collect::<Result<Vec<_>, _>>()?;
                    
                Ok(MailboxOperation::ConcurrentBroadcast { message_count, base_message })
            }
            _ => {
                let commitment_len = u.int_in_range(1..=64)?;
                let commitment_data = (0..commitment_len)
                    .map(|_| u8::arbitrary(u))
                    .collect::<Result<Vec<_>, _>>()?;
                    
                let msg_len = u.int_in_range(1..=256)?;
                let message_data = (0..msg_len)
                    .map(|_| u8::arbitrary(u))
                    .collect::<Result<Vec<_>, _>>()?;
                    
                let delay_ms = u.int_in_range(1..=100)?;
                
                Ok(MailboxOperation::SubscribeThenBroadcast {
                    commitment_data,
                    message_data,
                    delay_ms,
                })
            }
        }
    }
}

#[derive(Debug)]
pub struct FuzzInput {
    primary_peer_seed: u64,
    secondary_peer_seeds: Vec<u64>,
    network_config: NetworkConfig,
    cache_config: CacheConfig,
    operations: Vec<MailboxOperation>,
}

#[derive(Debug)]
struct NetworkConfig {
    success_rate: f64,
    latency_ms: u64,
    jitter_ms: u64,
}

#[derive(Debug)]
struct CacheConfig {
    deque_size: usize,
    mailbox_size: usize,
    priority: bool,
}

impl<'a> arbitrary::Arbitrary<'a> for NetworkConfig {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(NetworkConfig {
            success_rate: if u.int_in_range(0..=1)? == 0 { 0.5 } else { 1.0 },
            latency_ms: u.int_in_range(1..=200)?,
            jitter_ms: u.int_in_range(0..=50)?,
        })
    }
}

impl<'a> arbitrary::Arbitrary<'a> for CacheConfig {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(CacheConfig {
            deque_size: u.int_in_range(1..=50)?,
            mailbox_size: u.int_in_range(64..=2048)?,
            priority: u.int_in_range(0..=1)? == 1,
        })
    }
}

impl<'a> arbitrary::Arbitrary<'a> for FuzzInput {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let primary_peer_seed = u64::arbitrary(u)?;
        
        let num_secondary_peers = u.int_in_range(0..=3)?;
        let secondary_peer_seeds = (0..num_secondary_peers)
            .map(|_| u64::arbitrary(u))
            .collect::<Result<Vec<_>, _>>()?;
            
        let network_config = NetworkConfig::arbitrary(u)?;
        let cache_config = CacheConfig::arbitrary(u)?;
        
        let num_operations = u.int_in_range(1..=15)?;
        let operations = (0..num_operations)
            .map(|_| MailboxOperation::arbitrary(u))
            .collect::<Result<Vec<_>, _>>()?;
            
        Ok(FuzzInput {
            primary_peer_seed,
            secondary_peer_seeds,
            network_config,
            cache_config,
            operations,
        })
    }
}

fn fuzz(input: FuzzInput) {
    if input.operations.is_empty() {
        return;
    }

    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let (network, mut oracle) = Network::<deterministic::Context, PublicKey>::new(
            context.with_label("network"),
            commonware_p2p::simulated::Config {
                max_size: 1024 * 1024,
            },
        );
        network.start();

        // Create primary peer
        let primary_crypto = PrivateKey::from_seed(input.primary_peer_seed);
        let primary_key = primary_crypto.public_key();
        let (primary_sender, primary_receiver) = oracle.register(primary_key.clone(), 0).await.unwrap();

        let config = Config {
            public_key: primary_key.clone(),
            mailbox_size: input.cache_config.mailbox_size,
            deque_size: input.cache_config.deque_size,
            priority: input.cache_config.priority,
            codec_config: RangeCfg::from(..),
        };

        let primary_context = context.with_label("primary");
        let (primary_engine, mut primary_mailbox) = Engine::<_, PublicKey, FuzzMessage>::new(primary_context, config);
        primary_engine.start((primary_sender, primary_receiver));

        // Create secondary peers
        let mut secondary_keys = Vec::new();
        for (i, &seed) in input.secondary_peer_seeds.iter().enumerate() {
            let crypto = PrivateKey::from_seed(seed);
            let key = crypto.public_key();
            secondary_keys.push(key.clone());

            let (sender, receiver) = oracle.register(key.clone(), (i + 1) as u32).await.unwrap();

            let config = Config {
                public_key: key.clone(),
                mailbox_size: input.cache_config.mailbox_size,
                deque_size: input.cache_config.deque_size,
                priority: input.cache_config.priority,
                codec_config: RangeCfg::from(..),
            };

            let peer_context = context.with_label(&format!("secondary_{}", i));
            let (engine, _mailbox) = Engine::<_, PublicKey, FuzzMessage>::new(peer_context, config);
            engine.start((sender, receiver));
        }

        // Add network links
        let link = commonware_p2p::simulated::Link {
            latency: Duration::from_millis(input.network_config.latency_ms),
            jitter: Duration::from_millis(input.network_config.jitter_ms),
            success_rate: input.network_config.success_rate,
        };

        for secondary_key in &secondary_keys {
            let _ = oracle.add_link(primary_key.clone(), secondary_key.clone(), link.clone()).await;
            let _ = oracle.add_link(secondary_key.clone(), primary_key.clone(), link.clone()).await;
        }

        // Execute mailbox operations  
        for operation in input.operations {
            let operation_context = context.clone();
            match operation {
                MailboxOperation::Broadcast { recipients, message_data } => {
                    let message = FuzzMessage::shared(message_data);
                    let _ = primary_mailbox.broadcast(recipients, message).await;
                }
                MailboxOperation::Subscribe {
                    sender_seed,
                    commitment_data,
                    digest_data,
                    timeout_ms,
                } => {
                    let sender = sender_seed.map(|seed| PrivateKey::from_seed(seed).public_key());
                    let commitment = Sha256::hash(&commitment_data);
                    let digest = digest_data.as_ref().map(|d| Sha256::hash(d));
                    
                    let receiver = primary_mailbox.subscribe(sender, commitment, digest).await;
                    
                    // Set a timeout to avoid infinite waiting
                    use commonware_macros::select;
                    select! {
                        _result = receiver => {},
                        _ = operation_context.sleep(Duration::from_millis(timeout_ms)) => {},
                    }
                }
                MailboxOperation::GetImmediate {
                    sender_seed,
                    commitment_data,
                    digest_data,
                } => {
                    let sender = sender_seed.map(|seed| PrivateKey::from_seed(seed).public_key());
                    let commitment = Sha256::hash(&commitment_data);
                    let digest = digest_data.as_ref().map(|d| Sha256::hash(d));
                    
                    let _ = primary_mailbox.get(sender, commitment, digest).await;
                }
                MailboxOperation::ConcurrentBroadcast { message_count, base_message } => {
                    for i in 0..message_count {
                        let mut message_data = base_message.clone();
                        message_data.extend_from_slice(&i.to_le_bytes());
                        let message = FuzzMessage::shared(message_data);
                        let _ = primary_mailbox.broadcast(Recipients::All, message).await;
                    }
                }
                MailboxOperation::SubscribeThenBroadcast {
                    commitment_data,
                    message_data,
                    delay_ms,
                } => {
                    let commitment = Sha256::hash(&commitment_data);
                    let receiver = primary_mailbox.subscribe(None, commitment, None).await;
                    
                    // Spawn task to broadcast after delay
                    let message = FuzzMessage::new(commitment_data, message_data);
                    let spawn_context = operation_context.clone();
                    let delay_context = operation_context.clone();
                    let timeout_context = operation_context.clone();
                    let mut delayed_mailbox = primary_mailbox.clone();
                    spawn_context.spawn(move |_| async move {
                        delay_context.sleep(Duration::from_millis(delay_ms)).await;
                        let _ = delayed_mailbox.broadcast(Recipients::All, message).await;
                    });
                    
                    // Wait for the subscription to complete or timeout
                    use commonware_macros::select;
                    select! {
                        _result = receiver => {},
                        _ = timeout_context.sleep(Duration::from_millis(delay_ms + 100)) => {},
                    }
                }
            }
            
            // Small delay between operations to allow network propagation
            operation_context.sleep(Duration::from_millis(1)).await;
        }
    });
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});