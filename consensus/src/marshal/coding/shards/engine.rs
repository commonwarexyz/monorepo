//! Shard buffer engine.

use crate::{
    marshal::coding::{
        shards::mailbox::{Mailbox, Message},
        types::{CodedBlock, CodingCommitment, DigestOrCommitment, DistributionShard, Shard},
    },
    Block, Scheme,
};
use commonware_broadcast::{buffered, Broadcaster};
use commonware_codec::Error as CodecError;
use commonware_coding::Scheme as CodingScheme;
use commonware_cryptography::{Committable, Digestible, Hasher, PublicKey};
use commonware_macros::select;
use commonware_p2p::Recipients;
use commonware_runtime::{spawn_cell, Clock, ContextCell, Handle, Metrics, Spawner};
use commonware_utils::futures::{AbortablePool, Aborter};
use futures::{
    channel::{mpsc, oneshot},
    StreamExt,
};
use governor::clock::Clock as GClock;
use prometheus_client::metrics::gauge::Gauge;
use rand::Rng;
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use std::{
    collections::{btree_map::Entry, BTreeMap},
    ops::Deref,
    time::Instant,
};
use thiserror::Error;
use tracing::debug;

/// An error that can occur during reconstruction of a [CodedBlock] from [Shard]s
#[derive(Debug, Error)]
pub enum ReconstructionError<C: CodingScheme> {
    /// An error occurred while recovering the encoded blob from the [Shard]s
    #[error(transparent)]
    CodingRecovery(C::Error),

    /// An error occurred while decoding the reconstructed blob into a [CodedBlock]
    #[error(transparent)]
    Codec(#[from] CodecError),
}

/// A subscription for a reconstructed [Block] by its [CodingCommitment].
struct BlockSubscription<B: Block> {
    /// A list of subscribers waiting for the block to be reconstructed
    subscribers: Vec<oneshot::Sender<B>>,
}

/// A subscription for a [Shard]'s validity, relative to a [CodingCommitment].
struct ShardSubscription {
    /// A list of subscribers waiting for the [Shard]'s validity to be checked.
    subscribers: Vec<oneshot::Sender<bool>>,
    /// Aborter that aborts the waiter future when dropped.
    _aborter: Aborter,
}

/// A wrapper around a [buffered::Mailbox] for broadcasting and receiving erasure-coded
/// [Block]s as [Shard]s.
///
/// When enough [Shard]s are present in the mailbox, the [Engine] may facilitate
/// reconstruction of the original [Block] and notify any subscribers waiting for it.
pub struct Engine<E, S, C, H, B, P>
where
    E: Rng + Spawner + Metrics + Clock + GClock,
    S: Scheme,
    C: CodingScheme,
    H: Hasher,
    B: Block,
    P: PublicKey,
{
    /// Context held by the actor.
    context: ContextCell<E>,

    /// Receiver for incoming messages to the actor.
    mailbox: mpsc::Receiver<Message<B, S, C, P>>,

    /// Buffered mailbox for broadcasting and receiving [Shard]s to/from peers
    buffer: buffered::Mailbox<P, Shard<C, H>>,

    /// [commonware_codec::Read] configuration for decoding blocks
    block_codec_cfg: B::Cfg,

    /// Open subscriptions for [CodedBlock]s by digest.
    block_subscriptions: BTreeMap<B::Digest, BlockSubscription<CodedBlock<B, C>>>,

    /// Open subscriptions for [Shard]s checks by commitment and index
    shard_subscriptions: BTreeMap<(CodingCommitment, usize), ShardSubscription>,

    /// An ephemeral cache of reconstructed blocks, keyed by commitment.
    ///
    /// These blocks are evicted by marshal after they are durably persisted to disk.
    reconstructed_blocks: BTreeMap<CodingCommitment, CodedBlock<B, C>>,

    erasure_decode_duration: Gauge,
}

impl<E, S, C, H, B, P> Engine<E, S, C, H, B, P>
where
    E: Rng + Spawner + Metrics + Clock + GClock,
    S: Scheme,
    C: CodingScheme<Commitment = B::Digest>,
    H: Hasher,
    B: Block,
    P: PublicKey,
{
    /// Create a new [Engine].
    pub fn new(
        context: E,
        buffer: buffered::Mailbox<P, Shard<C, H>>,
        block_codec_cfg: B::Cfg,
        mailbox_size: usize,
    ) -> (Self, Mailbox<B, S, C, P>) {
        let erasure_decode_duration = Gauge::default();
        context.register(
            "erasure_decode_duration",
            "Duration of erasure decoding in milliseconds",
            erasure_decode_duration.clone(),
        );

        let (sender, mailbox) = mpsc::channel(mailbox_size);
        (
            Self {
                context: ContextCell::new(context),
                mailbox,
                buffer,
                block_codec_cfg,
                block_subscriptions: BTreeMap::new(),
                shard_subscriptions: BTreeMap::new(),
                reconstructed_blocks: BTreeMap::new(),
                erasure_decode_duration,
            },
            Mailbox::new(sender),
        )
    }

    /// Start the engine.
    pub fn start(mut self) -> Handle<()> {
        spawn_cell!(self.context, self.run().await)
    }

    /// Run the shard engine.
    async fn run(mut self) {
        let mut shard_validity_waiters =
            AbortablePool::<((CodingCommitment, usize), Shard<C, H>)>::default();
        let mut shutdown = self.context.stopped();

        loop {
            // Prune any dropped subscribers.
            self.shard_subscriptions.retain(|_, sub| {
                sub.subscribers.retain(|tx| !tx.is_canceled());
                !sub.subscribers.is_empty()
            });

            select! {
                // Check for the shutdown signal.
                _ = &mut shutdown => {
                    debug!("received shutdown signal, stopping shard engine");
                    break;
                },
                // Always serve any outstanding subscriptions first to unblock the hotpath of proposals / notarizations.
                result = shard_validity_waiters.next_completed() => {
                    let Ok(((commitment, index), shard)) = result else {
                        // Aborted future
                        continue;
                    };

                    let valid = shard.verify();

                    // Notify all subscribers
                    if let Some(mut sub) = self.shard_subscriptions.remove(&(commitment, index)) {
                        for responder in sub.subscribers.drain(..) {
                            let _ = responder.send(valid);
                        }
                    }

                    if valid {
                        // If the shard is valid, broadcast it to all peers.
                        if let Some(shard) = self.get_shard(commitment, index).await {
                            self.broadcast_shard(shard).await;
                        }
                    }
                },
                message = self.mailbox.next() => {
                    let Some(message) = message else {
                        debug!("Shard mailbox closed, shutting down");
                        return;
                    };
                    match message {
                        Message::Broadcast { block, peers } => {
                            self.broadcast_shards(block, peers).await;
                        }
                        Message::SubscribeShardValidity {
                            commitment,
                            index,
                            response,
                        } => {
                            self.subscribe_shard_validity(
                                commitment,
                                index,
                                response,
                                &mut shard_validity_waiters
                            ).await;
                        }
                        Message::TryReconstruct {
                            commitment,
                            response,
                        } => {
                            let result = self.try_reconstruct(commitment).await;

                            // Send the response; if the receiver has been dropped, we don't care.
                            let _ = response.send(result);
                        }
                        Message::SubscribeBlock {
                            id,
                            response,
                        } => {
                            self.subscribe_block(id, response).await;
                        }
                        Message::Finalized { commitment } => {
                            // Evict any finalized blocks from the cache to free up memory; They're
                            // now persisted on disk durably by marshal.
                            self.reconstructed_blocks.remove(&commitment);
                        }
                        Message::Notarize { notarization } => {
                            let _ = self.try_reconstruct(notarization.proposal.payload).await;
                        }
                    }
                }
            }
        }
    }

    /// Broadcasts [Shard]s of a [Block] to a pre-determined set of peers
    ///
    /// ## Panics
    ///
    /// Panics if the number of `participants` is not equal to the number of [Shard]s in the `block`
    #[inline]
    async fn broadcast_shards(&mut self, mut block: CodedBlock<B, C>, participants: Vec<P>) {
        assert_eq!(
            participants.len(),
            block.shards().len(),
            "number of participants must equal number of shards"
        );

        // TODO(clabby): Measure perf; Consider adding batched broadcast in buffered mailbox.
        for (index, peer) in participants.into_iter().enumerate() {
            let message = block
                .shard(index)
                .expect("peer index impossibly out of bounds");
            let _peers = self.buffer.broadcast(Recipients::One(peer), message).await;
        }
    }

    /// Broadcasts a local [Shard] of a block to all peers.
    #[inline]
    async fn broadcast_shard(&mut self, shard: Shard<C, H>) {
        let commitment = shard.commitment();
        let index = shard.index();

        let DistributionShard::Strong(shard) = shard.into_inner() else {
            // If the shard is already weak, it's been broadcasted to us already;
            // no need to re-broadcast.
            return;
        };

        let Ok((_, _, reshard)) = C::reshard(
            &commitment.config(),
            &commitment.coding_digest(),
            index as u16,
            shard,
        ) else {
            // If the shard can't be verified locally, don't broadcast anything.
            return;
        };

        // Broadcast the weak shard to all peers for reconstruction.
        let reshard = Shard::new(commitment, index, DistributionShard::Weak(reshard));
        let _peers = self.buffer.broadcast(Recipients::All, reshard).await;

        debug!(%commitment, index, "broadcasted local shard to all peers");
    }

    /// Attempts to reconstruct a [CodedBlock] from [Shard]s present in the mailbox
    ///
    /// If not enough [Shard]s are present, returns [None]. If enough [Shard]s are present and
    /// reconstruction fails, returns a [ReconstructionError]
    #[inline]
    async fn try_reconstruct(
        &mut self,
        commitment: CodingCommitment,
    ) -> Result<Option<CodedBlock<B, C>>, ReconstructionError<C>> {
        if let Some(block) = self.reconstructed_blocks.get(&commitment) {
            let block = block.clone();
            self.notify_subscribers(&block).await;
            return Ok(Some(block));
        }

        let shards = self.buffer.get(None, commitment, None).await;
        let config = commitment.config();

        // Search for a strong shard to form the checking data. We must have at least one strong shard
        // sent to us by the proposer. In the case of the proposer, all shards in the mailbox will be strong,
        // but any can be used for forming the checking data.
        //
        // NOTE: Byzantine peers may send us strong shards as well, but we don't care about those;
        // `Scheme::reshard` verifies the shard against the commitment, and if it doesn't check out,
        // it will be ignored.
        let Some(checking_data) = shards.iter().find_map(|s| {
            if let DistributionShard::Strong(shard) = s.deref() {
                C::reshard(
                    &config,
                    &commitment.coding_digest(),
                    s.index() as u16,
                    shard.clone(),
                )
                .map(|(checking_data, _, _)| checking_data)
                .ok()
            } else {
                None
            }
        }) else {
            debug!(%commitment, "no strong shards present to form checking data");
            return Ok(None);
        };

        let checked_shards = shards
            .into_par_iter()
            .filter_map(|s| {
                let index = s.index() as u16;
                match s.into_inner() {
                    DistributionShard::Strong(shard) => {
                        // Any strong shards, at this point, were sent from the proposer.
                        // We use the reshard interface to produce our checked shard rather
                        // than taking two hops.
                        C::reshard(&config, &commitment.coding_digest(), index, shard)
                            .map(|(_, checked, _)| checked)
                            .ok()
                    }
                    DistributionShard::Weak(re_shard) => C::check(
                        &config,
                        &commitment.coding_digest(),
                        &checking_data,
                        index,
                        re_shard,
                    )
                    .ok(),
                }
            })
            .collect::<Vec<_>>();

        if checked_shards.len() < config.minimum_shards as usize {
            debug!(%commitment, "not enough checked shards to reconstruct block");
            return Ok(None);
        }

        // Attempt to reconstruct the encoded blob
        let start = Instant::now();
        let decoded = C::decode(
            &config,
            &commitment.coding_digest(),
            checking_data.clone(),
            checked_shards.as_slice(),
        )
        .map_err(ReconstructionError::CodingRecovery)?;
        self.erasure_decode_duration
            .set(start.elapsed().as_millis() as i64);

        // Attempt to decode the block from the encoded blob
        let inner = B::read_cfg(&mut decoded.as_slice(), &self.block_codec_cfg)?;

        // Construct a coding block with a _trusted_ commitment. `S::decode` verified the blob's
        // integrity against the commitment, so shards can be lazily re-constructed if need be.
        let block = CodedBlock::new_trusted(inner, commitment);

        debug!(
            %commitment,
            parent = %block.parent(),
            height = block.height(),
            "successfully reconstructed block from shards"
        );

        self.reconstructed_blocks.insert(commitment, block.clone());

        // Notify any subscribers that have been waiting for this block to be reconstructed
        self.notify_subscribers(&block).await;

        Ok(Some(block))
    }

    /// Subscribes to a [Shard]'s presence and validity check by commitment and index with an
    /// externally prepared responder.
    ///
    /// The responder will be sent the shard when it is available; either instantly (if cached)
    /// or when it is received from the network. The request can be canceled by dropping the
    /// responder.
    ///
    /// When the shard is prepared and verified, it is broadcasted to all peers if valid.
    #[inline]
    #[allow(clippy::type_complexity)]
    async fn subscribe_shard_validity(
        &mut self,
        commitment: CodingCommitment,
        index: usize,
        responder: oneshot::Sender<bool>,
        pool: &mut AbortablePool<((CodingCommitment, usize), Shard<C, H>)>,
    ) {
        // If we already have the shard cached, send it immediately.
        if let Some(shard) = self.get_shard(commitment, index).await {
            let valid = shard.verify();
            let _ = responder.send(valid);

            // Broadcast the shard to all peers if it's valid.
            if valid {
                self.broadcast_shard(shard).await;
            }
            return;
        }

        match self.shard_subscriptions.entry((commitment, index)) {
            Entry::Vacant(entry) => {
                let (tx, rx) = oneshot::channel();
                let index_hash = Shard::<C, H>::uuid(commitment, index);
                self.buffer
                    .subscribe_prepared(None, commitment, Some(index_hash), tx)
                    .await;
                let aborter = pool.push(async move {
                    let shard = rx.await.expect("shard subscription aborted");
                    ((commitment, index), shard)
                });
                entry.insert(ShardSubscription {
                    subscribers: vec![responder],
                    _aborter: aborter,
                });
            }
            Entry::Occupied(mut entry) => {
                entry.get_mut().subscribers.push(responder);
            }
        }
    }

    /// Subscribes to a [CodedBlock] by digest with an externally prepared responder.
    ///
    /// The responder will be sent the block when it is available; either instantly (if cached)
    /// or when it is received from the network. The request can be canceled by dropping the
    /// responder
    #[inline]
    async fn subscribe_block(
        &mut self,
        id: DigestOrCommitment<B::Digest>,
        responder: oneshot::Sender<CodedBlock<B, C>>,
    ) {
        let block = match id {
            DigestOrCommitment::Digest(digest) => self
                .reconstructed_blocks
                .values()
                .find(|b| b.digest() == digest),
            DigestOrCommitment::Commitment(commitment) => {
                self.reconstructed_blocks.get(&commitment)
            }
        };
        if let Some(block) = block {
            // If we already have the block reconstructed, send it immediately.
            let _ = responder.send(block.clone());
            return;
        }

        match self.block_subscriptions.entry(id.digest()) {
            Entry::Vacant(entry) => {
                entry.insert(BlockSubscription {
                    subscribers: vec![responder],
                });
            }
            Entry::Occupied(mut entry) => {
                entry.get_mut().subscribers.push(responder);
            }
        }
    }

    /// Performs a best-effort retrieval of a [Shard] by commitment and index
    ///
    /// If the mailbox does not have the shard cached, [None] is returned
    #[inline]
    async fn get_shard(
        &mut self,
        commitment: CodingCommitment,
        index: usize,
    ) -> Option<Shard<C, H>> {
        let index_hash = Shard::<C, H>::uuid(commitment, index);
        self.buffer
            .get(None, commitment, Some(index_hash))
            .await
            .first()
            .cloned()
    }

    /// Notifies any subscribers waiting for a block to be reconstructed that it is now available.
    #[inline]
    async fn notify_subscribers(&mut self, block: &CodedBlock<B, C>) {
        if let Some(mut sub) = self.block_subscriptions.remove(&block.digest()) {
            for sub in sub.subscribers.drain(..) {
                let _ = sub.send(block.clone());
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        marshal::{
            coding::types::coding_config_for_participants, mocks::block::Block as MockBlock,
        },
        simplex::signing_scheme::bls12381_threshold::Scheme,
    };
    use commonware_coding::{CodecConfig, Config as CodingConfig, ReedSolomon};
    use commonware_cryptography::{
        bls12381::primitives::variant::MinSig,
        ed25519::{PrivateKey, PublicKey},
        sha256::Digest as Sha256Digest,
        PrivateKeyExt, Sha256, Signer,
    };
    use commonware_macros::{test_collect_traces, test_traced};
    use commonware_p2p::simulated::Link;
    use commonware_runtime::{
        deterministic, telemetry::traces::collector::TraceStorage, Metrics, Runner,
    };
    use std::{future::Future, time::Duration};
    use tracing::Level;

    // Number of messages to cache per sender
    const CACHE_SIZE: usize = 10;

    // The max size of a shard sent over the wire
    const MAX_SHARD_SIZE: usize = 1024 * 1024; // 1 MiB

    // The default link configuration for tests
    const DEFAULT_LINK: Link = Link {
        latency: Duration::from_millis(50),
        jitter: Duration::ZERO,
        success_rate: 1.0,
    };

    type B = MockBlock<Sha256Digest>;
    type H = Sha256;
    type P = PublicKey;
    type S = Scheme<P, MinSig>;
    type C = ReedSolomon<H>;
    type ShardEngine = Engine<deterministic::Context, S, C, H, B, P>;
    type ShardMailbox = Mailbox<B, S, C, P>;

    struct Fixture {
        num_peers: usize,
        link: Link,
    }

    impl Fixture {
        pub fn start<F: Future<Output = ()>>(
            self,
            f: impl FnOnce(
                Fixture,
                deterministic::Context,
                BTreeMap<PublicKey, ShardMailbox>,
                CodingConfig,
            ) -> F,
        ) {
            let executor = deterministic::Runner::default();
            executor.start(|context| async move {
                let (network, mut oracle) =
                    commonware_p2p::simulated::Network::<deterministic::Context, P>::new(
                        context.with_label("network"),
                        commonware_p2p::simulated::Config {
                            max_size: 1024 * 1024,
                            disconnect_on_block: true,
                            tracked_peer_sets: None,
                        },
                    );
                network.start();

                let mut schemes = (0..self.num_peers)
                    .map(|i| PrivateKey::from_seed(i as u64))
                    .collect::<Vec<_>>();
                schemes.sort_by_key(|s| s.public_key());
                let peers: Vec<P> = schemes.iter().map(|c| c.public_key()).collect();

                let mut registrations = BTreeMap::new();
                for peer in peers.iter() {
                    let (sender, receiver) =
                        oracle.control(peer.clone()).register(0).await.unwrap();
                    registrations.insert(peer.clone(), (sender, receiver));
                }

                // Add links between all peers
                for p1 in peers.iter() {
                    for p2 in peers.iter() {
                        if p2 == p1 {
                            continue;
                        }
                        oracle
                            .add_link(p1.clone(), p2.clone(), self.link.clone())
                            .await
                            .unwrap();
                    }
                }

                let coding_config =
                    coding_config_for_participants(u16::try_from(self.num_peers).unwrap());

                let mut mailboxes = BTreeMap::new();
                while let Some((peer, network)) = registrations.pop_first() {
                    let context = context.with_label(&peer.to_string());
                    let config = buffered::Config {
                        public_key: peer.clone(),
                        mailbox_size: 1024,
                        deque_size: CACHE_SIZE,
                        priority: false,
                        codec_config: CodecConfig {
                            maximum_shard_size: MAX_SHARD_SIZE,
                        },
                    };
                    let (engine, engine_mailbox) =
                        buffered::Engine::<_, P, Shard<C, H>>::new(context.clone(), config);
                    let (shard_engine, shard_mailbox) = ShardEngine::new(
                        context.with_label("shard_mailbox"),
                        engine_mailbox,
                        (),
                        10,
                    );
                    mailboxes.insert(peer.clone(), shard_mailbox);

                    // Start the buffered mailbox engine.
                    engine.start(network);

                    // Start the shard engine.
                    shard_engine.start();
                }

                f(self, context, mailboxes, coding_config).await;
            });
        }
    }

    #[test_traced]
    #[should_panic]
    fn test_broadcast_mismatched_peers_panics() {
        let fixture = Fixture {
            num_peers: 4,
            link: DEFAULT_LINK,
        };

        fixture.start(|config, context, mut mailboxes, coding_config| async move {
            let inner = B::new::<H>(H::empty(), 1, 2);
            let coded_block = CodedBlock::<B, C>::new(inner, coding_config);
            let peers: Vec<P> = mailboxes.keys().cloned().collect();

            let mut mailbox = mailboxes.first_entry().unwrap();
            mailbox
                .get_mut()
                .broadcast(
                    coded_block.clone(),
                    peers.into_iter().take(config.num_peers - 1).collect(),
                )
                .await;

            // Give the shard engine time to process the message. Once the message is processed,
            // the test should panic due to the mismatched number of peers.
            context.sleep(config.link.latency * 2).await;
        });
    }

    #[test_collect_traces("DEBUG")]
    fn test_gracefully_shuts_down(traces: TraceStorage) {
        let fixture = Fixture {
            num_peers: 4,
            link: DEFAULT_LINK,
        };

        fixture.start(|_, context, mailboxes, _| async move {
            // Reference the mailboxes to keep them alive during the test.
            let _mailboxes = mailboxes;

            context.sleep(Duration::from_millis(100)).await;
            context.stop(0, None).await.unwrap();

            traces
                .get_by_level(Level::DEBUG)
                .expect_message_exact("received shutdown signal, stopping shard engine")
                .unwrap();
        });
    }

    #[test_traced]
    fn test_basic_delivery_and_reconstruction() {
        let fixture = Fixture {
            num_peers: 8,
            link: DEFAULT_LINK,
        };

        fixture.start(|config, context, mut mailboxes, coding_config| async move {
            let inner = B::new::<H>(H::empty(), 1, 2);
            let coded_block = CodedBlock::<B, C>::new(inner, coding_config);
            let peers: Vec<P> = mailboxes.keys().cloned().collect();

            // Broadcast all shards out (proposer)
            let first_mailbox = mailboxes.get_mut(peers.first().unwrap()).unwrap();
            first_mailbox
                .broadcast(coded_block.clone(), peers.clone())
                .await;

            // Give the shard engine time to process the message and deliver shards.
            context.sleep(config.link.latency * 2).await;

            // Ensure all peers got their shards.
            for (i, peer) in peers.iter().enumerate() {
                let mailbox = mailboxes.get_mut(peer).unwrap();
                let valid = mailbox
                    .subscribe_shard_validity(coded_block.commitment(), i)
                    .await
                    .await
                    .unwrap();
                assert!(valid);
            }

            // Give each peer time to broadcast their shards; Once the peer validates their
            // shard above, they will broadcast it to all other peers.
            context.sleep(config.link.latency * 2).await;

            // Ensure all peers are able to reconstruct the block.
            for peer in peers.iter() {
                let mailbox = mailboxes.get_mut(peer).unwrap();
                let valid = mailbox
                    .try_reconstruct(coded_block.commitment())
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(valid.commitment(), coded_block.commitment());
                assert_eq!(valid.height(), coded_block.height());
            }
        });
    }

    #[test_traced]
    fn test_subscribe_to_block() {
        let fixture = Fixture {
            num_peers: 8,
            link: DEFAULT_LINK,
        };

        fixture.start(|config, context, mut mailboxes, coding_config| async move {
            let inner = B::new::<H>(H::empty(), 1, 2);
            let coded_block = CodedBlock::<B, C>::new(inner, coding_config);
            let peers: Vec<P> = mailboxes.keys().cloned().collect();

            // Broadcast all shards out (proposer)
            let first_mailbox = mailboxes.get_mut(&peers[0]).unwrap();
            first_mailbox
                .broadcast(coded_block.clone(), peers.clone())
                .await;

            // Give the shard engine time to process the message and deliver shards.
            context.sleep(config.link.latency * 2).await;

            // Open a subscription for the block from the second peer's mailbox. At the time of opening
            // the subscription, the block cannot yet be reconstructed by the second peer, since
            // they don't have enough shards yet.
            let second_mailbox = mailboxes.get_mut(&peers[1]).unwrap();
            let block_subscription = second_mailbox
                .subscribe_block(DigestOrCommitment::Digest(coded_block.digest()))
                .await;
            let block_reconstruction_result = second_mailbox
                .try_reconstruct(coded_block.commitment())
                .await
                .unwrap();
            assert!(block_reconstruction_result.is_none());

            // Ensure all peers got their shards.
            for (i, peer) in peers.iter().enumerate() {
                let mailbox = mailboxes.get_mut(peer).unwrap();
                let valid = mailbox
                    .subscribe_shard_validity(coded_block.commitment(), i)
                    .await
                    .await
                    .unwrap();
                assert!(valid);
            }

            // Give each peer time to broadcast their shards; Once the peer validates their
            // shard above, they will broadcast it to all other peers.
            context.sleep(config.link.latency * 2).await;

            // Attempt to reconstruct the block, which should fulfill the subscription.
            let second_mailbox = mailboxes.get_mut(&peers[1]).unwrap();
            let _ = second_mailbox
                .try_reconstruct(coded_block.commitment())
                .await;

            // Resolve the block subscription; it should now be fulfilled.
            let block = block_subscription.await.unwrap();
            assert_eq!(block.commitment(), coded_block.commitment());
        });
    }
}
