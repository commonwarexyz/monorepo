#![no_main]

use arbitrary::Arbitrary;
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
use bytes::{Buf, BufMut};
use libfuzzer_sys::fuzz_target;
use rand::{seq::SliceRandom, SeedableRng};
use std::{collections::BTreeMap, time::Duration};


#[derive(Clone, Debug, Arbitrary)]
pub enum RecipientPattern {
    All,
    Some(u64),
    One(u64),
}


// Test message implementation for fuzzing
#[derive(Debug, Clone, PartialEq, Eq, Arbitrary)]
pub struct FuzzMessage {
    pub commitment: Vec<u8>,
    pub content: Vec<u8>,
}


impl Digestible for FuzzMessage {
    type Digest = commonware_cryptography::sha256::Digest;
    fn digest(&self) -> Self::Digest {
        let mut combined = self.commitment.clone();
        combined.extend_from_slice(&self.content);
        Sha256::hash(&combined)
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

#[derive(Clone, Debug, Arbitrary)]
enum BroadcastAction {
    SendMessage { peer_index: usize, recipients: RecipientPattern, message: FuzzMessage },
    Subscribe { peer_index: usize, sender: Option<usize>, commitment: Vec<u8>, digest: Option<Vec<u8>> },
    Get { peer_index: usize, sender: Option<usize>, commitment: Vec<u8>, digest: Option<Vec<u8>> },
    Sleep { duration_ms: u64 },
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
        let peer_seeds = (0..num_peers)
            .map(|_| u64::arbitrary(u))
            .collect::<Result<Vec<_>, _>>()?;
        //anywhere from 30 to 100% success rate    
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
            
            let count = (seed % peers.len() as u64) as usize;
            let count = if count == 0 { 1 } else { count }; // Ensure at least 1 peer
            
            let peer_slice = shuffled_peers.into_iter().take(count).collect();
            Recipients::Some(peer_slice)
        }
    }
}

fn fuzz(input: FuzzInput) {
    if input.peer_seeds.is_empty() || input.actions.is_empty() {
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

        // Create peers
        let mut peers = Vec::new();
        let mut mailboxes: BTreeMap<PublicKey, Mailbox<PublicKey, FuzzMessage>> = BTreeMap::new();
        
        for (i, &seed) in input.peer_seeds.iter().enumerate() {
            let crypto = PrivateKey::from_seed(seed);
            let public_key = crypto.public_key();
            peers.push(public_key.clone());

            let (sender, receiver) = oracle.register(public_key.clone(), i as u32).await.unwrap();

            let config = Config {
                public_key: public_key.clone(),
                mailbox_size: 1024,
                deque_size: input.cache_size,
                priority: false,
                codec_config: RangeCfg::from(..),
            };

            let engine_context = context.with_label(&format!("peer_{}", i));
            let (engine, mailbox) = Engine::<_, PublicKey, FuzzMessage>::new(engine_context, config);
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
            if peers.is_empty() {
                break;
            }
            
            match action {
                BroadcastAction::SendMessage { peer_index, recipients, message } => {
                    let clamped_peer_idx = peer_index % peers.len();
                    let peer = peers[clamped_peer_idx].clone();
                    
                    if let Some(mut mailbox) = mailboxes.get(&peer).cloned() {
                        let resolved_recipients = resolve_recipients(&recipients, &peers);
                        let _ = mailbox.broadcast(resolved_recipients, message).await;
                    }
                }
                BroadcastAction::Subscribe { peer_index, sender, commitment, digest } => {
                    let clamped_peer_idx = peer_index % peers.len();
                    let peer = peers[clamped_peer_idx].clone();
                    
                    if let Some(mut mailbox) = mailboxes.get(&peer).cloned() {
                        let commitment_digest = Sha256::hash(&commitment);
                        let digest_hash = digest.as_ref().map(|d| Sha256::hash(d));
                        let sender_key = sender.map(|sender_idx| {
                            let clamped_sender_idx = sender_idx % peers.len();
                            peers[clamped_sender_idx].clone()
                        });
                        let _ = mailbox.subscribe(sender_key, commitment_digest, digest_hash).await;
                    }
                }
                BroadcastAction::Get { peer_index, sender, commitment, digest } => {
                    let clamped_peer_idx = peer_index % peers.len();
                    let peer = peers[clamped_peer_idx].clone();
                    
                    if let Some(mut mailbox) = mailboxes.get(&peer).cloned() {
                        let commitment_digest = Sha256::hash(&commitment);
                        let digest_hash = digest.as_ref().map(|d| Sha256::hash(d));
                        let sender_key = sender.map(|sender_idx| {
                            let clamped_sender_idx = sender_idx % peers.len();
                            peers[clamped_sender_idx].clone()
                        });
                        let _ = mailbox.get(sender_key, commitment_digest, digest_hash).await;
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