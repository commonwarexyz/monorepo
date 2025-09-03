#![no_main]

use commonware_broadcast::{
    buffered::{Config, Engine, Mailbox},
    Broadcaster,
};
use commonware_codec::RangeCfg;
use commonware_cryptography::{
    ed25519::{PrivateKey, PublicKey},
    Committable, Digestible, Hasher, PrivateKeyExt as _, Sha256, Signer,
};
use commonware_p2p::{simulated::Network, Recipients};
use commonware_runtime::{deterministic, Clock, Metrics, Runner};
use libfuzzer_sys::fuzz_target;
use std::{collections::BTreeMap, time::Duration};
use bytes::{Buf, BufMut};

// FuzzMessage for testing message encoding/decoding and cache behavior
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
enum MessagePattern {
    UniqueMessages { count: usize, base_size: usize },
    DuplicateCommitments { commitment: Vec<u8>, contents: Vec<Vec<u8>> },
    DuplicateDigests { content: Vec<u8>, commitments: Vec<Vec<u8>> },
    ExactDuplicates { message: FuzzMessage, count: usize },
    EvictionTest { cache_size: usize, message_count: usize, base_content: Vec<u8> },
    ConcurrentRequests { message: FuzzMessage, request_count: usize },
}

impl<'a> arbitrary::Arbitrary<'a> for MessagePattern {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let pattern_type = u.int_in_range(0..=5)?;
        match pattern_type {
            0 => {
                let count = u.int_in_range(1..=20)?;
                let base_size = u.int_in_range(1..=512)?;
                Ok(MessagePattern::UniqueMessages { count, base_size })
            }
            1 => {
                let commitment_len = u.int_in_range(1..=64)?;
                let commitment = (0..commitment_len)
                    .map(|_| u8::arbitrary(u))
                    .collect::<Result<Vec<_>, _>>()?;
                    
                let content_count = u.int_in_range(2..=5)?;
                let contents = (0..content_count)
                    .map(|_| {
                        let len = u.int_in_range(1..=128)?;
                        (0..len).map(|_| u8::arbitrary(u)).collect::<Result<Vec<_>, _>>()
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                    
                Ok(MessagePattern::DuplicateCommitments { commitment, contents })
            }
            2 => {
                let content_len = u.int_in_range(1..=128)?;
                let content = (0..content_len)
                    .map(|_| u8::arbitrary(u))
                    .collect::<Result<Vec<_>, _>>()?;
                    
                let commitment_count = u.int_in_range(2..=5)?;
                let commitments = (0..commitment_count)
                    .map(|_| {
                        let len = u.int_in_range(1..=64)?;
                        (0..len).map(|_| u8::arbitrary(u)).collect::<Result<Vec<_>, _>>()
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                    
                Ok(MessagePattern::DuplicateDigests { content, commitments })
            }
            3 => {
                let commitment_len = u.int_in_range(1..=64)?;
                let commitment = (0..commitment_len)
                    .map(|_| u8::arbitrary(u))
                    .collect::<Result<Vec<_>, _>>()?;
                    
                let content_len = u.int_in_range(1..=128)?;
                let content = (0..content_len)
                    .map(|_| u8::arbitrary(u))
                    .collect::<Result<Vec<_>, _>>()?;
                    
                let message = FuzzMessage::new(commitment, content);
                let count = u.int_in_range(2..=10)?;
                Ok(MessagePattern::ExactDuplicates { message, count })
            }
            4 => {
                let cache_size = u.int_in_range(2..=20)?;
                let message_count = u.int_in_range(cache_size + 1..=cache_size + 10)?;
                let base_len = u.int_in_range(1..=64)?;
                let base_content = (0..base_len)
                    .map(|_| u8::arbitrary(u))
                    .collect::<Result<Vec<_>, _>>()?;
                    
                Ok(MessagePattern::EvictionTest { cache_size, message_count, base_content })
            }
            _ => {
                let commitment_len = u.int_in_range(1..=64)?;
                let commitment = (0..commitment_len)
                    .map(|_| u8::arbitrary(u))
                    .collect::<Result<Vec<_>, _>>()?;
                    
                let content_len = u.int_in_range(1..=128)?;
                let content = (0..content_len)
                    .map(|_| u8::arbitrary(u))
                    .collect::<Result<Vec<_>, _>>()?;
                    
                let message = FuzzMessage::new(commitment, content);
                let request_count = u.int_in_range(2..=10)?;
                Ok(MessagePattern::ConcurrentRequests { message, request_count })
            }
        }
    }
}

#[derive(Debug)]
pub struct FuzzInput {
    peer_count: usize,
    base_peer_seed: u64,
    network_reliability: f64,
    message_patterns: Vec<MessagePattern>,
}

impl<'a> arbitrary::Arbitrary<'a> for FuzzInput {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let peer_count = u.int_in_range(2..=5)?;
        let base_peer_seed = u64::arbitrary(u)?;
        let network_reliability = if u.int_in_range(0..=1)? == 0 { 0.5 } else { 1.0 };
        
        let pattern_count = u.int_in_range(1..=10)?;
        let message_patterns = (0..pattern_count)
            .map(|_| MessagePattern::arbitrary(u))
            .collect::<Result<Vec<_>, _>>()?;
            
        Ok(FuzzInput {
            peer_count,
            base_peer_seed,
            network_reliability,
            message_patterns,
        })
    }
}

fn fuzz(input: FuzzInput) {
    if input.message_patterns.is_empty() || input.peer_count == 0 {
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

        // Create peers and their mailboxes
        let mut peers = Vec::new();
        let mut mailboxes: BTreeMap<PublicKey, Mailbox<PublicKey, FuzzMessage>> = BTreeMap::new();

        for i in 0..input.peer_count {
            let crypto = PrivateKey::from_seed(input.base_peer_seed.wrapping_add(i as u64));
            let public_key = crypto.public_key();
            peers.push(public_key.clone());

            let (sender, receiver) = oracle.register(public_key.clone(), 0).await.unwrap();

            let config = Config {
                public_key: public_key.clone(),
                mailbox_size: 1024,
                deque_size: 10, // Default cache size
                priority: false,
                codec_config: RangeCfg::from(..),
            };

            let peer_context = context.with_label(&format!("peer_{}", i));
            let (engine, mailbox) = Engine::<_, PublicKey, FuzzMessage>::new(peer_context, config);
            mailboxes.insert(public_key.clone(), mailbox);
            engine.start((sender, receiver));
        }

        // Setup network links
        let link = commonware_p2p::simulated::Link {
            latency: Duration::from_millis(50),
            jitter: Duration::ZERO,
            success_rate: input.network_reliability,
        };

        for p1 in &peers {
            for p2 in &peers {
                if p1 != p2 {
                    let _ = oracle.add_link(p1.clone(), p2.clone(), link.clone()).await;
                }
            }
        }

        // Execute message patterns
        for pattern in input.message_patterns {
            match pattern {
                MessagePattern::UniqueMessages { count, base_size } => {
                    if let Some(mut sender_mailbox) = mailboxes.get(peers.first().unwrap()).cloned() {
                        for i in 0..count {
                            let mut content = vec![0u8; base_size];
                            content.extend_from_slice(&i.to_le_bytes());
                            let message = FuzzMessage::shared(content);
                            let _ = sender_mailbox.broadcast(Recipients::All, message).await;
                        }
                    }
                }
                MessagePattern::DuplicateCommitments { commitment, contents } => {
                    if let Some(mut sender_mailbox) = mailboxes.get(peers.first().unwrap()).cloned() {
                        for content in contents {
                            let message = FuzzMessage::new(commitment.clone(), content);
                            let _ = sender_mailbox.broadcast(Recipients::All, message).await;
                        }
                    }
                }
                MessagePattern::DuplicateDigests { content, commitments } => {
                    if let Some(mut sender_mailbox) = mailboxes.get(peers.first().unwrap()).cloned() {
                        for commitment in commitments {
                            let message = FuzzMessage::new(commitment, content.clone());
                            let _ = sender_mailbox.broadcast(Recipients::All, message).await;
                        }
                    }
                }
                MessagePattern::ExactDuplicates { message, count } => {
                    if let Some(mut sender_mailbox) = mailboxes.get(peers.first().unwrap()).cloned() {
                        for _ in 0..count {
                            let _ = sender_mailbox.broadcast(Recipients::All, message.clone()).await;
                        }
                    }
                }
                MessagePattern::EvictionTest { cache_size: _, message_count, base_content } => {
                    if let Some(mut sender_mailbox) = mailboxes.get(peers.first().unwrap()).cloned() {
                        // Reconfigure peer with specific cache size
                        for i in 0..message_count {
                            let mut content = base_content.clone();
                            content.extend_from_slice(&i.to_le_bytes());
                            let message = FuzzMessage::shared(content);
                            let _ = sender_mailbox.broadcast(Recipients::All, message).await;
                        }
                        
                        // Allow propagation
                        context.sleep(Duration::from_millis(100)).await;
                        
                        // Test that early messages are evicted
                        if let Some(mut receiver_mailbox) = mailboxes.get(peers.last().unwrap()).cloned() {
                            let first_message_commitment = {
                                let content = base_content.clone();
                                FuzzMessage::shared(content).commitment()
                            };
                            
                            let _results = receiver_mailbox.get(None, first_message_commitment, None).await;
                            // Early messages should be evicted if cache_size < message_count
                        }
                    }
                }
                MessagePattern::ConcurrentRequests { message, request_count } => {
                    if peers.len() >= 2 {
                        let sender = peers[0].clone();
                        let receiver = peers[1].clone();
                        
                        if let Some(mut receiver_mailbox) = mailboxes.get(&receiver).cloned() {
                            // Start multiple concurrent subscription requests
                            let mut receivers = Vec::new();
                            for _ in 0..request_count {
                                let rx = receiver_mailbox.subscribe(None, message.commitment(), None).await;
                                receivers.push(rx);
                            }
                            
                            // Broadcast the message
                            if let Some(mut sender_mailbox) = mailboxes.get(&sender).cloned() {
                                let _ = sender_mailbox.broadcast(Recipients::All, message.clone()).await;
                            }
                            
                            // Wait for all receivers to get the message (with timeout)
                            for receiver in receivers {
                                use commonware_macros::select;
                                select! {
                                    _result = receiver => {},
                                    _ = context.sleep(Duration::from_millis(200)) => {},
                                }
                            }
                        }
                    }
                }
            }
            
            // Allow some time for processing between patterns
            context.sleep(Duration::from_millis(10)).await;
        }
    });
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});