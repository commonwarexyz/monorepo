//! Erasure coding wrapper for [buffered::Mailbox]

use crate::{
    marshal::ingress::coding::types::{CodedBlock, DistributionShard, Shard},
    types::CodingCommitment,
    Block,
};
use commonware_broadcast::{buffered, Broadcaster};
use commonware_codec::{Decode, Error as CodecError};
use commonware_coding::Scheme;
use commonware_cryptography::{Hasher, PublicKey};
use commonware_p2p::Recipients;
use commonware_runtime::Metrics;
use futures::channel::oneshot;
use prometheus_client::metrics::gauge::Gauge;
use std::{
    collections::{btree_map::Entry, BTreeMap},
    ops::Deref,
    time::Instant,
};
use thiserror::Error;
use tracing::debug;

/// An error that can occur during reconstruction of a [CodedBlock] from [Shard]s
#[derive(Debug, Error)]
pub enum ReconstructionError<S: Scheme> {
    /// An error occurred while recovering the encoded blob from the [Shard]s
    #[error(transparent)]
    CodingRecovery(S::Error),

    /// An error occurred while decoding the reconstructed blob into a [CodedBlock]
    #[error(transparent)]
    Codec(#[from] CodecError),
}

/// A subscription for a block by its commitment
struct BlockSubscription<B: Block> {
    /// A list of subscribers waiting for the block to be reconstructed
    subscribers: Vec<oneshot::Sender<B>>,
}

/// A wrapper around a [buffered::Mailbox] for broadcasting and receiving erasure-coded
/// [Block]s as [Shard]s.
///
/// When enough [Shard]s are present in the mailbox, the [ShardMailbox] may facilitate
/// reconstruction of the original [Block] and notify any subscribers waiting for it.
pub struct ShardMailbox<S, H, B, P>
where
    S: Scheme,
    H: Hasher,
    B: Block<Commitment = CodingCommitment>,
    P: PublicKey,
{
    /// Buffered mailbox for broadcasting and receiving [Shard]s to/from peers
    mailbox: buffered::Mailbox<P, Shard<S, H>>,

    /// [commonware_codec::Read] configuration for decoding blocks
    block_codec_cfg: B::Cfg,

    /// Open subscriptions for [CodedBlock]s by commitment
    block_subscriptions: BTreeMap<CodingCommitment, BlockSubscription<CodedBlock<B, S>>>,

    /// A temporary in-memory cache of reconstructed blocks by commitment.
    ///
    /// These blocks are evicted by marshal after they are delivered to the application.
    reconstructed_blocks: BTreeMap<CodingCommitment, CodedBlock<B, S>>,

    /// Transient caches for progressive block reconstruction.
    checking_data: BTreeMap<CodingCommitment, S::CheckingData>,
    checked_shards: BTreeMap<CodingCommitment, BTreeMap<usize, S::CheckedShard>>,

    erasure_decode_duration: Gauge,
}

impl<S, H, B, P> ShardMailbox<S, H, B, P>
where
    S: Scheme,
    H: Hasher,
    B: Block<Commitment = CodingCommitment>,
    P: PublicKey,
{
    pub fn new(
        context: impl Metrics,
        mailbox: buffered::Mailbox<P, Shard<S, H>>,
        block_codec_cfg: B::Cfg,
    ) -> Self {
        let erasure_decode_duration = Gauge::default();
        context.register(
            "erasure_decode_duration",
            "Duration of erasure decoding in milliseconds",
            erasure_decode_duration.clone(),
        );

        Self {
            mailbox,
            block_codec_cfg,
            block_subscriptions: BTreeMap::new(),
            reconstructed_blocks: BTreeMap::new(),
            checking_data: BTreeMap::new(),
            checked_shards: BTreeMap::new(),
            erasure_decode_duration,
        }
    }

    /// Broadcasts [Shard]s of a [Block] to a pre-determined set of peers
    ///
    /// ## Panics
    ///
    /// Panics if the number of `participants` is not equal to the number of [Shard]s in the `block`
    pub async fn broadcast_shards(&mut self, block: CodedBlock<B, S>, participants: Vec<P>) {
        assert_eq!(
            participants.len(),
            block.shards().len(),
            "number of participants must equal number of shards"
        );

        for (index, peer) in participants.into_iter().enumerate() {
            let message = block
                .shard(index)
                .expect("peer index impossibly out of bounds");
            let _peers = self.mailbox.broadcast(Recipients::One(peer), message).await;
        }
    }

    /// Broadcasts a local [Shard] of a block to all peers, if the [Shard] is present
    pub async fn try_broadcast_shard(&mut self, commitment: CodingCommitment, index: usize) {
        let shard = self
            .mailbox
            .get(None, commitment, None)
            .await
            .iter()
            .find(|c| c.index() == index)
            .cloned();

        if let Some(shard) = shard {
            let index = shard.index();
            let DistributionShard::Strong(shard) = shard.into_inner() else {
                // If the shard is already weak, it's been broadcasted to us already;
                // no need to re-broadcast.
                return;
            };

            let Ok((_, _, reshard)) = S::reshard(
                &commitment.config(),
                &commitment.inner(),
                index as u16,
                shard,
            ) else {
                // If the shard can't be verified locally, don't broadcast anything.
                return;
            };

            // TODO: Cache checked shard too? If we do this, it'll complicate things a decent bit; More heap
            // allocation / complexity might make it not worth. Right now we'll just recompute it when we try to
            // reconstruct, same with the checking data.

            // Broadcast the weak shard to all peers for reconstruction.
            let reshard = Shard::new(commitment, index, DistributionShard::Weak(reshard));

            let _peers = self.mailbox.broadcast(Recipients::All, reshard).await;

            debug!(%commitment, index, "broadcasted local shard to all peers");
        } else {
            debug!(%commitment, index, "no local shard to broadcast");
        }
    }

    /// Attempts to reconstruct a [CodedBlock] from [Shard]s present in the mailbox
    ///
    /// If not enough [Shard]s are present, returns [None]. If enough [Shard]s are present and
    /// reconstruction fails, returns a [ReconstructionError]
    pub async fn try_reconstruct(
        &mut self,
        commitment: CodingCommitment,
    ) -> Result<Option<CodedBlock<B, S>>, ReconstructionError<S>> {
        if let Some(block) = self.reconstructed_blocks.get(&commitment) {
            // Notify any subscribers that have been waiting for this block to be reconstructed
            if let Some(mut sub) = self.block_subscriptions.remove(&commitment) {
                for sub in sub.subscribers.drain(..) {
                    let _ = sub.send(block.clone());
                }
            }
            return Ok(Some(block.clone()));
        }

        let shards = self.mailbox.get(None, commitment, None).await;
        let config = commitment.config();

        // Search for a strong shard to form the checking data. We must have at least one strong shard
        // sent to us by the proposer. In the case of the proposer, all shards in the mailbox will be strong,
        // but any can be used for forming the checking data.
        //
        // NOTE: Byzantine peers may send us strong shards as well, but we don't care about those;
        // `Scheme::reshard` verifies the shard against the commitment, and if it doesn't check out,
        // it will be ignored.
        let checking_data = match self.checking_data.entry(commitment) {
            Entry::Vacant(entry) => {
                let Some(checking_data) = shards.iter().find_map(|s| {
                    if let DistributionShard::Strong(shard) = s.deref() {
                        S::reshard(
                            &config,
                            &commitment.inner(),
                            s.index() as u16,
                            shard.clone(),
                        )
                        .map(|(checking_data, _, _)| checking_data)
                        .ok()
                    } else {
                        None
                    }
                }) else {
                    debug!(%commitment, "No strong shards present to form checking data");
                    return Ok(None);
                };
                entry.insert(checking_data.clone());
                checking_data
            }
            Entry::Occupied(entry) => entry.get().clone(),
        };

        let cached_checked_shards = self.checked_shards.entry(commitment).or_default();
        let checked_shards = shards
            .into_iter()
            .filter_map(|s| {
                let index = s.index() as u16;
                match s.into_inner() {
                    DistributionShard::Strong(shard) => {
                        // Any strong shards, at this point, were sent from the proposer.
                        // We use the reshard interface to produce our checked shard rather
                        // than taking two hops.
                        match cached_checked_shards.entry(index as usize) {
                            Entry::Vacant(entry) => {
                                let (_, checked, _) =
                                    S::reshard(&config, &commitment.inner(), index, shard).ok()?;
                                entry.insert(checked.clone());
                                Some(checked)
                            }
                            Entry::Occupied(entry) => Some(entry.get().clone()),
                        }
                    }
                    DistributionShard::Weak(re_shard) => {
                        match cached_checked_shards.entry(index as usize) {
                            Entry::Vacant(entry) => {
                                let checked = S::check(
                                    &config,
                                    &commitment.inner(),
                                    &checking_data,
                                    index,
                                    re_shard,
                                )
                                .ok()?;
                                entry.insert(checked.clone());
                                Some(checked)
                            }
                            Entry::Occupied(entry) => Some(entry.get().clone()),
                        }
                    }
                }
            })
            .collect::<Vec<_>>();

        if checked_shards.len() < config.minimum_shards as usize {
            debug!(%commitment, "Not enough checked shards to reconstruct block");
            return Ok(None);
        }

        // Attempt to reconstruct the encoded blob
        let start = Instant::now();
        let decoded = S::decode(
            &config,
            &commitment.inner(),
            checking_data.clone(),
            checked_shards.as_slice(),
        )
        .map_err(ReconstructionError::CodingRecovery)?;
        self.erasure_decode_duration
            .set(start.elapsed().as_millis() as i64);

        // Attempt to decode the block from the encoded blob
        let block = CodedBlock::<B, S>::decode_cfg(decoded.as_slice(), &self.block_codec_cfg)?;

        debug!(
            %commitment,
            parent = %block.parent(),
            height = block.height(),
            "Successfully reconstructed block from shards"
        );

        self.reconstructed_blocks.insert(commitment, block.clone());
        self.checking_data.remove(&commitment);
        self.checked_shards.remove(&commitment);

        // Notify any subscribers that have been waiting for this block to be reconstructed
        if let Some(mut sub) = self.block_subscriptions.remove(&commitment) {
            for sub in sub.subscribers.drain(..) {
                let _ = sub.send(block.clone());
            }
        }

        Ok(Some(block))
    }

    /// Performs a best-effort retrieval of a [Shard] by commitment and index
    ///
    /// If the mailbox does not have the shard cached, [None] is returned
    pub async fn get_shard(
        &mut self,
        commitment: CodingCommitment,
        index: usize,
    ) -> Option<Shard<S, H>> {
        let index_hash = Shard::<S, H>::uuid(commitment, index);
        self.mailbox
            .get(None, commitment, Some(index_hash))
            .await
            .first()
            .cloned()
    }

    /// Subscribes to a [Shard] by commitment and index with an externally prepared responder
    ///
    /// The responder will be sent the shard when it is available; either instantly (if cached)
    /// or when it is received from the network. The request can be canceled by dropping the
    /// responder
    pub async fn subscribe_shard(
        &mut self,
        commitment: CodingCommitment,
        index: usize,
        responder: oneshot::Sender<Shard<S, H>>,
    ) {
        let index_hash = Shard::<S, H>::uuid(commitment, index);
        self.mailbox
            .subscribe_prepared(None, commitment, Some(index_hash), responder)
            .await;
    }

    /// Subscribes to a [CodedBlock] by commitment with an externally prepared responder
    ///
    /// The responder will be sent the block when it is available; either instantly (if cached)
    /// or when it is received from the network. The request can be canceled by dropping the
    /// responder
    pub async fn subscribe_block(
        &mut self,
        commitment: CodingCommitment,
        responder: oneshot::Sender<CodedBlock<B, S>>,
    ) -> Result<(), ReconstructionError<S>> {
        if let Some(block) = self.reconstructed_blocks.get(&commitment) {
            // If we already have the block reconstructed, send it immediately.
            let _ = responder.send(block.clone());
            return Ok(());
        }

        match self.block_subscriptions.entry(commitment) {
            Entry::Vacant(entry) => {
                entry.insert(BlockSubscription {
                    subscribers: vec![responder],
                });
            }
            Entry::Occupied(mut entry) => {
                entry.get_mut().subscribers.push(responder);
            }
        }

        // Try to reconstruct the block immediately in case we already have enough shards.
        self.try_reconstruct(commitment).await?;

        Ok(())
    }

    /// Evicts a reconstructed block from the local cache, if it is present.
    pub fn evict_block(&mut self, commitment: &CodingCommitment) {
        self.reconstructed_blocks.remove(commitment);
    }

    /// Checks if a reconstructed block is present in the local cache.
    pub fn has_block(&self, commitment: &CodingCommitment) -> bool {
        self.reconstructed_blocks.contains_key(commitment)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::marshal::mocks::block::Block as MockBlock;
    use commonware_coding::ReedSolomon;
    use commonware_cryptography::{
        ed25519::{PrivateKey, PublicKey},
        sha256::Digest as Sha256Digest,
        Committable, PrivateKeyExt, Sha256, Signer,
    };
    use commonware_macros::test_traced;
    use commonware_p2p::simulated::{Link, Oracle, Receiver, Sender};
    use commonware_runtime::{deterministic, Clock, Metrics, Runner};
    use std::time::Duration;

    // Number of messages to cache per sender
    const CACHE_SIZE: usize = 10;

    // Network speed for the simulated network
    const NETWORK_SPEED: Duration = Duration::from_millis(100);

    // The max size of a shard sent over the wire
    const MAX_SHARD_SIZE: usize = 1024 * 1024; // 1 MiB

    // The number of peers in the simulated network
    const NUM_PEERS: u32 = 8;

    type Registrations = BTreeMap<PublicKey, (Sender<PublicKey>, Receiver<PublicKey>)>;
    type B = MockBlock<Sha256Digest>;
    type SMailbox = ShardMailbox<ReedSolomon<Sha256>, Sha256, B, PublicKey>;

    async fn initialize_simulation(
        context: deterministic::Context,
        num_peers: u32,
        success_rate: f64,
    ) -> (Vec<PublicKey>, Registrations, Oracle<PublicKey>) {
        let (network, mut oracle) =
            commonware_p2p::simulated::Network::<deterministic::Context, PublicKey>::new(
                context.with_label("network"),
                commonware_p2p::simulated::Config {
                    max_size: 1024 * 1024,
                    disconnect_on_block: true,
                },
            );
        network.start();

        let mut schemes = (0..num_peers)
            .map(|i| PrivateKey::from_seed(i as u64))
            .collect::<Vec<_>>();
        schemes.sort_by_key(|s| s.public_key());
        let peers: Vec<PublicKey> = schemes.iter().map(|c| c.public_key()).collect();

        let mut registrations: Registrations = BTreeMap::new();
        for peer in peers.iter() {
            let (sender, receiver) = oracle.register(peer.clone(), 0).await.unwrap();
            registrations.insert(peer.clone(), (sender, receiver));
        }

        // Add links between all peers
        let link = Link {
            latency: NETWORK_SPEED,
            jitter: Duration::ZERO,
            success_rate,
        };
        for p1 in peers.iter() {
            for p2 in peers.iter() {
                if p2 == p1 {
                    continue;
                }
                oracle
                    .add_link(p1.clone(), p2.clone(), link.clone())
                    .await
                    .unwrap();
            }
        }

        (peers, registrations, oracle)
    }

    fn spawn_peer_engines(
        context: deterministic::Context,
        registrations: &mut Registrations,
    ) -> BTreeMap<PublicKey, SMailbox> {
        let mut mailboxes = BTreeMap::new();
        while let Some((peer, network)) = registrations.pop_first() {
            let context = context.with_label(&peer.to_string());
            let config = buffered::Config {
                public_key: peer.clone(),
                mailbox_size: 1024,
                deque_size: CACHE_SIZE,
                priority: false,
                codec_config: (MAX_SHARD_SIZE, MAX_SHARD_SIZE),
            };
            let (engine, engine_mailbox) = buffered::Engine::<
                _,
                PublicKey,
                Shard<ReedSolomon<Sha256>, Sha256>,
            >::new(context.clone(), config);
            let shard_mailbox =
                SMailbox::new(context.with_label("shard_mailbox"), engine_mailbox, ());
            mailboxes.insert(peer.clone(), shard_mailbox);

            engine.start(network);
        }
        mailboxes
    }

    #[test]
    #[should_panic]
    fn test_broadcast_mismatched_peers_panics() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            let (peers, mut registrations, _network) =
                initialize_simulation(ctx.with_label("network"), NUM_PEERS, 1.0).await;
            let mut mailboxes = spawn_peer_engines(ctx.with_label("mailboxes"), &mut registrations);

            let coding_config = commonware_coding::Config {
                minimum_shards: (NUM_PEERS / 2) as u16,
                extra_shards: (NUM_PEERS / 2) as u16,
            };

            let inner = B::new::<Sha256>(Default::default(), 1, 2);
            let coded_block = CodedBlock::<B, ReedSolomon<Sha256>>::new(inner, coding_config);

            // Broadcast all shards out (proposer) with too few peers - should panic.
            let first_mailbox = mailboxes.get_mut(peers.first().unwrap()).unwrap();
            first_mailbox
                .broadcast_shards(
                    coded_block.clone(),
                    peers
                        .clone()
                        .into_iter()
                        .take(NUM_PEERS as usize - 1)
                        .collect(),
                )
                .await;
        });
    }

    #[test_traced("DEBUG")]
    fn test_basic_delivery_and_retrieval() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            let (peers, mut registrations, _network) =
                initialize_simulation(ctx.with_label("network"), NUM_PEERS, 1.0).await;
            let mut mailboxes = spawn_peer_engines(ctx.with_label("mailboxes"), &mut registrations);

            let coding_config = commonware_coding::Config {
                minimum_shards: (NUM_PEERS / 2) as u16,
                extra_shards: (NUM_PEERS / 2) as u16,
            };

            let inner = B::new::<Sha256>(Default::default(), 1, 2);
            let coded_block = CodedBlock::<B, ReedSolomon<Sha256>>::new(inner, coding_config);

            // Broadcast all shards out (proposer)
            let first_mailbox = mailboxes.get_mut(peers.first().unwrap()).unwrap();
            first_mailbox
                .broadcast_shards(coded_block.clone(), peers.clone())
                .await;
            ctx.sleep(Duration::from_millis(200)).await;

            // Broadcast individual shards (post-notarization votes).
            for (i, peer) in peers.iter().enumerate() {
                let mailbox = mailboxes.get_mut(peer).unwrap();
                mailbox
                    .try_broadcast_shard(coded_block.commitment(), i)
                    .await;
            }
            ctx.sleep(Duration::from_millis(200)).await;

            // Ensure all peers get the block.
            for peer in peers.iter() {
                let first_mailbox = mailboxes.get_mut(peer).unwrap();
                let block = first_mailbox
                    .try_reconstruct(coded_block.commitment())
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(block.commitment(), coded_block.commitment());
                assert_eq!(block.height(), coded_block.height());
            }
        });
    }

    #[test_traced("DEBUG")]
    fn test_subscribe_to_block() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            let (peers, mut registrations, _network) =
                initialize_simulation(ctx.with_label("network"), NUM_PEERS, 1.0).await;
            let mut mailboxes = spawn_peer_engines(ctx.with_label("mailboxes"), &mut registrations);

            let coding_config = commonware_coding::Config {
                minimum_shards: (NUM_PEERS / 2) as u16,
                extra_shards: (NUM_PEERS / 2) as u16,
            };

            let inner = B::new::<Sha256>(Default::default(), 1, 2);
            let coded_block = CodedBlock::<B, ReedSolomon<Sha256>>::new(inner, coding_config);

            // Broadcast all shards out (proposer)
            let first_mailbox = mailboxes.get_mut(peers.first().unwrap()).unwrap();
            first_mailbox
                .broadcast_shards(coded_block.clone(), peers.clone())
                .await;
            ctx.sleep(Duration::from_millis(200)).await;

            // Broadcast individual shards (post-notarization votes).
            for (i, peer) in peers.iter().enumerate() {
                let mailbox = mailboxes.get_mut(peer).unwrap();
                mailbox
                    .try_broadcast_shard(coded_block.commitment(), i)
                    .await;
            }
            ctx.sleep(Duration::from_millis(200)).await;

            // Ensure all peers get the block.
            for peer in peers.iter() {
                let first_mailbox = mailboxes.get_mut(peer).unwrap();
                let (tx, rx) = oneshot::channel();
                first_mailbox
                    .subscribe_block(coded_block.commitment(), tx)
                    .await
                    .unwrap();
                let block = rx.await.unwrap();

                assert_eq!(block.commitment(), coded_block.commitment());
                assert_eq!(block.height(), coded_block.height());
            }
        });
    }

    #[test_traced("DEBUG")]
    fn test_subscribe_to_shard() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            let (peers, mut registrations, _network) =
                initialize_simulation(ctx.with_label("network"), NUM_PEERS, 1.0).await;
            let mut mailboxes = spawn_peer_engines(ctx.with_label("mailboxes"), &mut registrations);

            let coding_config = commonware_coding::Config {
                minimum_shards: (NUM_PEERS / 2) as u16,
                extra_shards: (NUM_PEERS / 2) as u16,
            };

            let inner = B::new::<Sha256>(Default::default(), 1, 2);
            let coded_block = CodedBlock::<B, ReedSolomon<Sha256>>::new(inner, coding_config);

            // Broadcast all shards out (proposer)
            let first_mailbox = mailboxes.get_mut(peers.first().unwrap()).unwrap();
            first_mailbox
                .broadcast_shards(coded_block.clone(), peers.clone())
                .await;
            ctx.sleep(Duration::from_millis(200)).await;

            // Broadcast individual shards (post-notarization votes).
            for (i, peer) in peers.iter().enumerate() {
                let mailbox = mailboxes.get_mut(peer).unwrap();
                mailbox
                    .try_broadcast_shard(coded_block.commitment(), i)
                    .await;
            }
            ctx.sleep(Duration::from_millis(200)).await;

            // Ensure all peers get their shards.
            for (i, peer) in peers.iter().enumerate() {
                let first_mailbox = mailboxes.get_mut(peer).unwrap();
                let (tx, rx) = oneshot::channel();
                first_mailbox
                    .subscribe_shard(coded_block.commitment(), i, tx)
                    .await;
                let shard = rx.await.unwrap();

                assert_eq!(shard.commitment(), coded_block.commitment());
                assert_eq!(shard.index(), i);
            }
        });
    }
}
