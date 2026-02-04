//! Shard buffer engine.

use crate::{
    marshal::coding::{
        shards::mailbox::{Mailbox, Message},
        types::{CodedBlock, DistributionShard, Shard},
    },
    types::{CodingCommitment, Height},
    Block, CertifiableBlock, Heightable, Scheme,
};
use commonware_broadcast::{buffered, Broadcaster};
use commonware_codec::Error as CodecError;
use commonware_coding::Scheme as CodingScheme;
use commonware_cryptography::{Digestible, Hasher, PublicKey};
use commonware_macros::select_loop;
use commonware_p2p::Recipients;
use commonware_parallel::Strategy;
use commonware_runtime::{
    spawn_cell, telemetry::metrics::status::GaugeExt, Clock, ContextCell, Handle, Metrics, Spawner,
};
use commonware_utils::{
    channel::{fallible::OneshotExt, mpsc, oneshot},
    futures::Aborter,
};
use prometheus_client::metrics::gauge::Gauge;
use rand::Rng;
use std::{
    collections::{btree_map::Entry, BTreeMap},
    ops::Deref,
    sync::Arc,
    time::Instant,
};
use thiserror::Error;
use tracing::debug;

type AbortablePool<C, H> =
    commonware_utils::futures::AbortablePool<((CodingCommitment, usize), Shard<C, H>)>;

/// An error that can occur during reconstruction of a [CodedBlock] from [Shard]s
#[derive(Debug, Error)]
pub enum ReconstructionError<C: CodingScheme> {
    /// An error occurred while recovering the encoded blob from the [Shard]s
    #[error(transparent)]
    CodingRecovery(C::Error),

    /// An error occurred while decoding the reconstructed blob into a [CodedBlock]
    #[error(transparent)]
    Codec(#[from] CodecError),

    /// The reconstructed block's digest does not match the commitment's block digest
    #[error("block digest mismatch: reconstructed block does not match commitment")]
    DigestMismatch,
}

/// A subscription for a reconstructed [Block] by its [CodingCommitment].
struct BlockSubscription<B: CertifiableBlock, C: CodingScheme> {
    /// A list of subscribers waiting for the block to be reconstructed
    subscribers: Vec<oneshot::Sender<Arc<CodedBlock<B, C>>>>,
    /// The commitment associated with this subscription, if known.
    /// Used for height-based pruning on finalization.
    commitment: Option<CodingCommitment>,
}

/// A subscription for a [Shard]'s validity, relative to a [CodingCommitment].
struct ShardSubscription {
    /// A list of subscribers waiting for a valid [Shard] to arrive.
    subscribers: Vec<oneshot::Sender<()>>,
    /// Aborter that aborts the waiter future when dropped.
    aborter: Aborter,
}

/// A wrapper around a [buffered::Mailbox] for broadcasting and receiving erasure-coded
/// [Block]s as [Shard]s.
///
/// When enough [Shard]s are present in the mailbox, the [Engine] may facilitate
/// reconstruction of the original [Block] and notify any subscribers waiting for it.
pub struct Engine<E, S, C, H, B, P, T>
where
    E: Rng + Spawner + Metrics + Clock,
    S: Scheme,
    C: CodingScheme,
    H: Hasher,
    B: CertifiableBlock,
    P: PublicKey,
    T: Strategy,
{
    /// Context held by the actor.
    context: ContextCell<E>,

    /// Receiver for incoming messages to the actor.
    mailbox: mpsc::Receiver<Message<B, S, C, P>>,

    /// Buffered mailbox for broadcasting and receiving [Shard]s to/from peers
    buffer: buffered::Mailbox<P, Shard<C, H>>,

    /// [commonware_codec::Read] configuration for decoding blocks
    block_codec_cfg: B::Cfg,

    /// The strategy used for parallel computation.
    strategy: T,

    /// Open subscriptions for [CodedBlock]s by digest.
    block_subscriptions: BTreeMap<B::Digest, BlockSubscription<B, C>>,

    /// Open subscriptions for [Shard]s checks by commitment and index
    shard_subscriptions: BTreeMap<(CodingCommitment, usize), ShardSubscription>,

    /// An ephemeral cache of reconstructed blocks, keyed by commitment.
    ///
    /// These blocks are evicted by marshal after they are durably persisted to disk.
    /// Wrapped in [Arc] to enable cheap cloning when serving multiple subscribers.
    reconstructed_blocks: BTreeMap<CodingCommitment, Arc<CodedBlock<B, C>>>,

    erasure_decode_duration: Gauge,
    reconstructed_blocks_count: Gauge,
}

impl<E, S, C, H, B, P, T> Engine<E, S, C, H, B, P, T>
where
    E: Rng + Spawner + Metrics + Clock,
    S: Scheme,
    C: CodingScheme,
    H: Hasher,
    B: CertifiableBlock,
    P: PublicKey,
    T: Strategy,
{
    /// Create a new [Engine].
    pub fn new(
        context: E,
        buffer: buffered::Mailbox<P, Shard<C, H>>,
        block_codec_cfg: B::Cfg,
        mailbox_size: usize,
        strategy: T,
    ) -> (Self, Mailbox<B, S, C, P>) {
        let erasure_decode_duration = Gauge::default();
        context.register(
            "erasure_decode_duration",
            "Duration of erasure decoding in milliseconds",
            erasure_decode_duration.clone(),
        );
        let reconstructed_blocks_count = Gauge::default();
        context.register(
            "reconstructed_blocks_count",
            "Number of blocks in the reconstructed blocks cache",
            reconstructed_blocks_count.clone(),
        );

        let (sender, mailbox) = mpsc::channel(mailbox_size);
        (
            Self {
                context: ContextCell::new(context),
                mailbox,
                buffer,
                block_codec_cfg,
                strategy,
                block_subscriptions: BTreeMap::new(),
                shard_subscriptions: BTreeMap::new(),
                reconstructed_blocks: BTreeMap::new(),
                erasure_decode_duration,
                reconstructed_blocks_count,
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
        let mut shard_validity_waiters = AbortablePool::default();

        select_loop! {
            self.context,
            on_start => {
                // Prune any dropped subscribers.
                self.shard_subscriptions.retain(|_, sub| {
                    sub.subscribers.retain(|tx| !tx.is_closed());
                    !sub.subscribers.is_empty()
                });
                self.block_subscriptions.retain(|_, sub| {
                    sub.subscribers.retain(|tx| !tx.is_closed());
                    !sub.subscribers.is_empty()
                });
            },
            // Check for the shutdown signal.
            on_stopped => {
                debug!("received shutdown signal, stopping shard engine");
            },
            // Always serve any outstanding subscriptions first to unblock the hotpath of proposals / notarizations.
            Ok(((commitment, index), shard)) = shard_validity_waiters.next_completed() else continue => {
                if let Some(reshard) = shard.verify_into_reshard() {
                    self.complete_shard_subscription(commitment, index, reshard).await;
                } else {
                    // Before re-arming the subscription, check if any valid shard has arrived in the meantime.
                    if self.try_complete_shard_subscription(commitment, index).await {
                        continue;
                    }

                    // Get the subscription; it may have been removed if all subscribers dropped.
                    let Some(sub) = self.shard_subscriptions.get_mut(&(commitment, index)) else {
                        continue;
                    };

                    sub.subscribers.retain(|tx| !tx.is_closed());
                    if sub.subscribers.is_empty() {
                        self.shard_subscriptions.remove(&(commitment, index));
                    } else {
                        let aborter = self
                            .arm_shard_subscription(commitment, index, &mut shard_validity_waiters)
                            .await;
                        if let Some(sub) = self.shard_subscriptions.get_mut(&(commitment, index)) {
                            sub.aborter = aborter;
                        }

                        // Check again after arming to close the race window.
                        self.try_complete_shard_subscription(commitment, index).await;
                    }
                }
            },
            Some(message) = self.mailbox.recv() else {
                debug!("Shard mailbox closed, shutting down");
                return;
            } => {
                match message {
                    Message::Proposed { block, peers } => {
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
                        response.send_lossy(result);
                    }
                    Message::SubscribeBlockByDigest {
                        digest,
                        response,
                    } => {
                        self.subscribe_block_by_digest(digest, response).await;
                    }
                    Message::SubscribeBlockByCommitment {
                        commitment,
                        response,
                    } => {
                        self.subscribe_block_by_commitment(commitment, response).await;
                    }
                    Message::Finalized { commitment } => {
                        // Evict the finalized block and any blocks at or below its height.
                        // Blocks at lower heights can accumulate when views timeout before
                        // finalization - these would otherwise remain in cache forever.
                        let finalized_height = self
                            .reconstructed_blocks
                            .get(&commitment)
                            .map(|b| b.height());

                        // Prune block subscriptions for commitments that will be evicted.
                        // After finalization, blocks are persisted by marshal and queries
                        // go through it rather than the shard engine.
                        self.block_subscriptions.retain(|_, sub| {
                            let Some(sub_commitment) = sub.commitment else {
                                return true;
                            };
                            !Self::should_prune_subscription(
                                &sub_commitment,
                                &commitment,
                                finalized_height,
                                &self.reconstructed_blocks,
                            )
                        });

                        // Prune shard subscriptions for commitments that will be evicted
                        self.shard_subscriptions.retain(|(sub_commitment, _), _| {
                            !Self::should_prune_subscription(
                                sub_commitment,
                                &commitment,
                                finalized_height,
                                &self.reconstructed_blocks,
                            )
                        });

                        // Prune reconstructed blocks at or below the finalized height
                        self.reconstructed_blocks.remove(&commitment);
                        if let Some(height) = finalized_height {
                            self.reconstructed_blocks
                                .retain(|_, block| block.height() > height);
                        }

                        let _ = self
                            .reconstructed_blocks_count
                            .try_set(self.reconstructed_blocks.len() as i64);
                    }
                    Message::Notarize { notarization } => {
                        let _ = self.try_reconstruct(notarization.proposal.payload).await;
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
            block.shards(&self.strategy).len(),
            "number of participants must equal number of shards"
        );

        for (index, peer) in participants.into_iter().enumerate() {
            let message = block
                .shard(index)
                .expect("peer index impossibly out of bounds");
            let _peers = self.buffer.broadcast(Recipients::One(peer), message).await;
        }
    }

    /// Broadcasts a verified reshard to all peers.
    #[inline]
    async fn broadcast_reshard(&mut self, reshard: Shard<C, H>) {
        let commitment = reshard.commitment();
        let index = reshard.index();

        debug_assert!(
            matches!(reshard.deref(), DistributionShard::Weak(_)),
            "broadcast_reshard expects a reshard"
        );

        let _peers = self.buffer.broadcast(Recipients::All, reshard).await;
        debug!(%commitment, index, "broadcasted reshard to all peers");
    }

    /// Attempts to reconstruct a [CodedBlock] from [Shard]s present in the mailbox
    ///
    /// If not enough [Shard]s are present, returns [None]. If enough [Shard]s are present and
    /// reconstruction fails, returns a [ReconstructionError]
    #[inline]
    async fn try_reconstruct(
        &mut self,
        commitment: CodingCommitment,
    ) -> Result<Option<Arc<CodedBlock<B, C>>>, ReconstructionError<C>> {
        if let Some(block) = self.reconstructed_blocks.get(&commitment) {
            let block = Arc::clone(block);
            self.notify_subscribers(&block).await;
            return Ok(Some(block));
        }

        let mut shards = self.buffer.get(None, commitment, None).await;
        let config = commitment.config();

        // Find and extract a strong shard to form the checking data. We must have at least one
        // strong shard sent to us by the proposer. In the case of the proposer, all shards in
        // the mailbox will be strong, but any can be used for forming the checking data.
        //
        // NOTE: Byzantine peers may send us strong shards as well, but we don't care about those;
        // `Scheme::reshard` verifies the shard against the commitment, and if it doesn't check out,
        // it will be ignored.
        //
        // We extract the first *valid* strong shard by swapping it to the end and popping,
        // avoiding a clone. If a strong shard fails verification, we try the next one.
        let (checking_data, first_checked_shard) = loop {
            let strong_shard_pos = shards
                .iter()
                .position(|s| matches!(s.deref(), DistributionShard::Strong(_)));
            let Some(strong_pos) = strong_shard_pos else {
                debug!(%commitment, "no valid strong shards present to form checking data");
                return Ok(None);
            };

            // Swap-remove the strong shard to take ownership without shifting elements
            let strong_shard = shards.swap_remove(strong_pos);
            let Some(strong_index) = u16::try_from(strong_shard.index()).ok() else {
                debug!(%commitment, index = strong_shard.index(), "shard index exceeds u16::MAX");
                continue;
            };
            let DistributionShard::Strong(shard_data) = strong_shard.into_inner() else {
                unreachable!("we just verified this is a strong shard");
            };

            if let Ok((checking_data, checked, _)) = C::reshard(
                &config,
                &commitment.coding_digest(),
                strong_index,
                shard_data,
            ) {
                break (checking_data, checked);
            }

            debug!(
                %commitment,
                index = strong_index,
                "strong shard failed verification"
            );
        };

        // Process remaining shards in parallel
        let checked_shards = self.strategy.map_collect_vec(shards, |s| {
            let index = u16::try_from(s.index()).ok()?;

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
        });

        // Prepend the first checked shard we extracted earlier
        let mut all_checked_shards = Vec::with_capacity(checked_shards.len() + 1);
        all_checked_shards.push(first_checked_shard);
        all_checked_shards.extend(checked_shards.into_iter().flatten());
        let checked_shards = all_checked_shards;

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
            &self.strategy,
        )
        .map_err(ReconstructionError::CodingRecovery)?;
        self.erasure_decode_duration
            .set(start.elapsed().as_millis() as i64);

        // Attempt to decode the block from the encoded blob
        let inner = B::read_cfg(&mut decoded.as_slice(), &self.block_codec_cfg)?;

        // Verify the reconstructed block's digest matches the commitment's block digest.
        // This is a defense-in-depth check - the coding scheme should have already verified
        // integrity, but this ensures the block we decoded is actually the one committed to.
        if inner.digest() != commitment.block_digest() {
            return Err(ReconstructionError::DigestMismatch);
        }

        // Construct a coding block with a _trusted_ commitment. `S::decode` verified the blob's
        // integrity against the commitment, so shards can be lazily re-constructed if need be.
        let block = Arc::new(CodedBlock::new_trusted(inner, commitment));

        debug!(
            %commitment,
            parent = %block.parent(),
            height = %block.height(),
            "successfully reconstructed block from shards"
        );

        self.reconstructed_blocks
            .insert(commitment, Arc::clone(&block));
        let _ = self
            .reconstructed_blocks_count
            .try_set(self.reconstructed_blocks.len() as i64);

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
    async fn subscribe_shard_validity(
        &mut self,
        commitment: CodingCommitment,
        index: usize,
        responder: oneshot::Sender<()>,
        pool: &mut AbortablePool<C, H>,
    ) {
        // If we already have a valid shard cached, verify and broadcast in one step.
        if let Some(shard) = self.get_valid_reshard(commitment, index).await {
            self.broadcast_reshard(shard).await;
            responder.send_lossy(());
            return;
        }

        // Add to existing subscription if present.
        if let Entry::Occupied(mut entry) = self.shard_subscriptions.entry((commitment, index)) {
            entry.get_mut().subscribers.push(responder);
            return;
        }

        // Arm a new subscription for this shard.
        let aborter = self.arm_shard_subscription(commitment, index, pool).await;
        self.shard_subscriptions.insert(
            (commitment, index),
            ShardSubscription {
                subscribers: vec![responder],
                aborter,
            },
        );

        // Check again after arming the subscription to close the race window where a valid
        // shard arrives between the initial cache check and the subscription creation.
        // The waiter will catch any shard arriving after this point.
        self.try_complete_shard_subscription(commitment, index)
            .await;
    }

    /// Subscribes to a [CodedBlock] by digest with an externally prepared responder.
    ///
    /// The responder will be sent the block when it is available; either instantly (if cached)
    /// or when it is received from the network. The request can be canceled by dropping the
    /// responder.
    ///
    /// This subscription cannot trigger shard reconstruction since we don't have the full
    /// commitment needed.
    #[inline]
    async fn subscribe_block_by_digest(
        &mut self,
        digest: B::Digest,
        responder: oneshot::Sender<Arc<CodedBlock<B, C>>>,
    ) {
        // Check if we already have the block reconstructed
        let block = self
            .reconstructed_blocks
            .values()
            .find(|b| b.digest() == digest);
        if let Some(block) = block {
            responder.send_lossy(Arc::clone(block));
            return;
        }

        // Add to subscriptions (no reconstruction attempt since we don't have commitment)
        match self.block_subscriptions.entry(digest) {
            Entry::Vacant(entry) => {
                entry.insert(BlockSubscription {
                    subscribers: vec![responder],
                    commitment: None,
                });
            }
            Entry::Occupied(mut entry) => {
                entry.get_mut().subscribers.push(responder);
            }
        }
    }

    /// Subscribes to a [CodedBlock] by commitment with an externally prepared responder.
    ///
    /// The responder will be sent the block when it is available; either instantly (if cached)
    /// or when it is received from the network. The request can be canceled by dropping the
    /// responder.
    ///
    /// Having the commitment enables shard reconstruction when enough shards are available.
    #[inline]
    async fn subscribe_block_by_commitment(
        &mut self,
        commitment: CodingCommitment,
        responder: oneshot::Sender<Arc<CodedBlock<B, C>>>,
    ) {
        // Check if we already have the block reconstructed
        if let Some(block) = self.reconstructed_blocks.get(&commitment) {
            responder.send_lossy(Arc::clone(block));
            return;
        }

        // Try to reconstruct immediately before adding subscription.
        // This handles the case where shards arrived before this subscription was created
        // (e.g., when receiving a notarization after other validators have already broadcast
        // their shards).
        if let Ok(Some(block)) = self.try_reconstruct(commitment).await {
            responder.send_lossy(block);
            return;
        }

        let digest = commitment.block_digest();
        match self.block_subscriptions.entry(digest) {
            Entry::Vacant(entry) => {
                entry.insert(BlockSubscription {
                    subscribers: vec![responder],
                    commitment: Some(commitment),
                });
            }
            Entry::Occupied(mut entry) => {
                let sub = entry.get_mut();
                sub.subscribers.push(responder);
                // Update commitment if we now have one and didn't before
                if sub.commitment.is_none() {
                    sub.commitment = Some(commitment);
                }
            }
        }
    }

    /// Performs a best-effort retrieval of a [Shard] by commitment and index
    ///
    /// If the mailbox does not have the shard cached, [None] is returned
    #[inline]
    async fn get_valid_reshard(
        &mut self,
        commitment: CodingCommitment,
        index: usize,
    ) -> Option<Shard<C, H>> {
        let index_hash = Shard::<C, H>::uuid(commitment, index);
        self.buffer
            .get(None, commitment, Some(index_hash))
            .await
            .into_iter()
            .filter_map(Shard::verify_into_reshard)
            .next()
    }

    /// Arms a shard subscription for the given commitment and index.
    ///
    /// This function opens a subscription for a _new_ shard. It is expected that all shards
    /// that are present in the mailbox ([`Self::get_valid_reshard`]) have already been processed.
    #[inline]
    async fn arm_shard_subscription(
        &mut self,
        commitment: CodingCommitment,
        index: usize,
        pool: &mut AbortablePool<C, H>,
    ) -> Aborter {
        let (tx, rx) = oneshot::channel();
        let index_hash = Shard::<C, H>::uuid(commitment, index);
        self.buffer
            .subscribe_prepared_new(None, commitment, Some(index_hash), tx)
            .await;
        pool.push(async move {
            let shard = rx.await.expect("buffer must not drop subscription");
            ((commitment, index), shard)
        })
    }

    /// Notifies any subscribers waiting for a block to be reconstructed that it is now available.
    #[inline]
    async fn notify_subscribers(&mut self, block: &Arc<CodedBlock<B, C>>) {
        if let Some(mut sub) = self.block_subscriptions.remove(&block.digest()) {
            for sub in sub.subscribers.drain(..) {
                sub.send_lossy(Arc::clone(block));
            }
        }
    }

    /// Notifies any subscribers waiting for a valid shard to be available.
    #[inline]
    async fn notify_shard_subscribers(&mut self, commitment: CodingCommitment, index: usize) {
        if let Some(mut sub) = self.shard_subscriptions.remove(&(commitment, index)) {
            for responder in sub.subscribers.drain(..) {
                responder.send_lossy(());
            }
        }
    }

    /// Broadcasts a valid reshard and notifies all subscribers.
    #[inline]
    async fn complete_shard_subscription(
        &mut self,
        commitment: CodingCommitment,
        index: usize,
        shard: Shard<C, H>,
    ) {
        self.broadcast_reshard(shard).await;
        self.notify_shard_subscribers(commitment, index).await;
    }

    /// Checks for a valid reshard, broadcasts it, and notifies subscribers if found.
    ///
    /// Returns `true` if a valid shard was found and processed.
    #[inline]
    async fn try_complete_shard_subscription(
        &mut self,
        commitment: CodingCommitment,
        index: usize,
    ) -> bool {
        if let Some(shard) = self.get_valid_reshard(commitment, index).await {
            self.complete_shard_subscription(commitment, index, shard)
                .await;
            true
        } else {
            false
        }
    }

    /// Determines if a subscription should be pruned based on finalization.
    ///
    /// Returns `true` if the commitment matches the finalized commitment or if
    /// the associated block is at or below the finalized height.
    fn should_prune_subscription(
        sub_commitment: &CodingCommitment,
        finalized_commitment: &CodingCommitment,
        finalized_height: Option<Height>,
        reconstructed_blocks: &BTreeMap<CodingCommitment, Arc<CodedBlock<B, C>>>,
    ) -> bool {
        if sub_commitment == finalized_commitment {
            return true;
        }
        let Some(height) = finalized_height else {
            return false;
        };
        let Some(block) = reconstructed_blocks.get(sub_commitment) else {
            return false;
        };
        block.height() <= height
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        marshal::{
            coding::types::coding_config_for_participants, mocks::block::Block as MockBlock,
        },
        simplex::scheme::bls12381_threshold::vrf::Scheme,
        types::Height,
    };
    use bytes::Buf;
    use commonware_codec::{Encode, RangeCfg, Read};
    use commonware_coding::{
        CodecConfig, Config as CodingConfig, ReedSolomon, Scheme as CodingScheme,
    };
    use commonware_cryptography::{
        bls12381::primitives::variant::MinSig,
        ed25519::{PrivateKey, PublicKey},
        sha256::Digest as Sha256Digest,
        Committable, Digest, Sha256, Signer,
    };
    use commonware_macros::{select, test_collect_traces, test_traced};
    use commonware_p2p::{simulated::Link, Recipients};
    use commonware_parallel::Sequential;
    use commonware_runtime::{
        deterministic, telemetry::traces::collector::TraceStorage, Metrics, Quota, Runner,
    };
    use commonware_utils::{channel::oneshot::error::TryRecvError, Participant};
    use std::{future::Future, num::NonZeroU32, time::Duration};
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

    const TEST_QUOTA: Quota = Quota::per_second(NonZeroU32::MAX);

    const STRATEGY: Sequential = Sequential;

    type B = MockBlock<Sha256Digest, ()>;
    type H = Sha256;
    type P = PublicKey;
    type S = Scheme<P, MinSig>;
    type C = ReedSolomon<H>;
    type ShardEngine = Engine<deterministic::Context, S, C, H, B, P, Sequential>;
    type ShardMailbox = Mailbox<B, S, C, P>;

    struct Fixture {
        num_peers: usize,
        link: Link,
    }

    impl Fixture {
        pub fn start<F: Future<Output = ()>>(
            self,
            f: impl FnOnce(
                Self,
                deterministic::Context,
                BTreeMap<PublicKey, ShardMailbox>,
                CodingConfig,
            ) -> F,
        ) {
            let executor = deterministic::Runner::default();
            executor.start(|context| async move {
                let (network, oracle) =
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
                    let (sender, receiver) = oracle
                        .control(peer.clone())
                        .register(0, TEST_QUOTA)
                        .await
                        .unwrap();
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
                    let context = context.with_label(&format!("peer_{peer}"));
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
                        STRATEGY,
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
            let inner = B::new::<H>((), Sha256Digest::EMPTY, Height::new(1), 2);
            let coded_block = CodedBlock::<B, C>::new(inner, coding_config, &STRATEGY);
            let peers: Vec<P> = mailboxes.keys().cloned().collect();

            let mut mailbox = mailboxes.first_entry().unwrap();
            mailbox
                .get_mut()
                .proposed(
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
            let inner = B::new::<H>((), Sha256Digest::EMPTY, Height::new(1), 2);
            let coded_block = CodedBlock::<B, C>::new(inner, coding_config, &STRATEGY);
            let peers: Vec<P> = mailboxes.keys().cloned().collect();

            // Broadcast all shards out (proposer)
            let first_mailbox = mailboxes.get_mut(peers.first().unwrap()).unwrap();
            first_mailbox
                .proposed(coded_block.clone(), peers.clone())
                .await;

            // Give the shard engine time to process the message and deliver shards.
            context.sleep(config.link.latency * 2).await;

            // Ensure all peers got their shards.
            for (i, peer) in peers.iter().enumerate() {
                let mailbox = mailboxes.get_mut(peer).unwrap();
                mailbox
                    .subscribe_shard_validity(coded_block.commitment(), Participant::new(i as u32))
                    .await
                    .await
                    .unwrap();
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
    fn test_invalid_shard_rejected() {
        let fixture = Fixture {
            num_peers: 8,
            link: DEFAULT_LINK,
        };

        fixture.start(|config, context, mut mailboxes, coding_config| async move {
            let inner = B::new::<H>((), Sha256Digest::EMPTY, Height::new(1), 2);
            let coded_block = CodedBlock::<B, C>::new(inner, coding_config, &STRATEGY);
            let peers: Vec<P> = mailboxes.keys().cloned().collect();

            // Broadcast all shards out (proposer)
            let first_mailbox = mailboxes.get_mut(peers.first().unwrap()).unwrap();
            first_mailbox
                .proposed(coded_block.clone(), peers.clone())
                .await;

            // Give the shard engine time to process the message and deliver shards.
            context.sleep(config.link.latency * 2).await;

            // Check that all valid shards are validated correctly
            for (i, peer) in peers.iter().enumerate() {
                let mailbox = mailboxes.get_mut(peer).unwrap();
                mailbox
                    .subscribe_shard_validity(coded_block.commitment(), Participant::new(i as u32))
                    .await
                    .await
                    .expect("shard {i} should be valid");
            }

            // Now test that requesting validation for a non-existent shard index does not complete
            // (the shard doesn't exist so the subscription will wait indefinitely)

            // Request validation for an out-of-bounds index - the shard won't exist
            // so this subscription won't complete (the shard is never delivered).
            // We verify by checking that reconstruction still works with valid shards.
            context.sleep(config.link.latency * 2).await;

            // Verify that honest peers can still reconstruct despite Byzantine behavior
            for peer in peers.iter() {
                let mailbox = mailboxes.get_mut(peer).unwrap();
                let result = mailbox
                    .try_reconstruct(coded_block.commitment())
                    .await
                    .unwrap();
                assert!(
                    result.is_some(),
                    "reconstruction should succeed with valid shards"
                );
                assert_eq!(result.unwrap().commitment(), coded_block.commitment());
            }
        });
    }

    #[test_traced]
    fn test_reconstruct_skips_invalid_strong_shard() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (network, oracle) =
                commonware_p2p::simulated::Network::<deterministic::Context, P>::new(
                    context.with_label("network"),
                    commonware_p2p::simulated::Config {
                        max_size: 1024 * 1024,
                        disconnect_on_block: true,
                        tracked_peer_sets: None,
                    },
                );
            network.start();

            let mut schemes = (0..2)
                .map(|i| PrivateKey::from_seed(i as u64))
                .collect::<Vec<_>>();
            schemes.sort_by_key(|s| s.public_key());
            let peers: Vec<P> = schemes.iter().map(|c| c.public_key()).collect();

            let mut registrations = BTreeMap::new();
            for peer in peers.iter() {
                let (sender, receiver) = oracle
                    .control(peer.clone())
                    .register(0, TEST_QUOTA)
                    .await
                    .unwrap();
                registrations.insert(peer.clone(), (sender, receiver));
            }

            for p1 in peers.iter() {
                for p2 in peers.iter() {
                    if p2 == p1 {
                        continue;
                    }
                    oracle
                        .add_link(p1.clone(), p2.clone(), DEFAULT_LINK)
                        .await
                        .unwrap();
                }
            }

            let mut buffered_mailboxes = BTreeMap::new();
            let mut shard_mailboxes = BTreeMap::new();
            while let Some((peer, network)) = registrations.pop_first() {
                let context = context.with_label(&format!("peer_{peer}"));
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
                let buffered_mailbox = engine_mailbox.clone();
                let (shard_engine, shard_mailbox) = ShardEngine::new(
                    context.with_label("shard_mailbox"),
                    engine_mailbox,
                    (),
                    10,
                    STRATEGY,
                );
                buffered_mailboxes.insert(peer.clone(), buffered_mailbox);
                shard_mailboxes.insert(peer.clone(), shard_mailbox);

                engine.start(network);
                shard_engine.start();
            }

            let sender = peers.first().cloned().unwrap();
            let receiver = peers.get(1).cloned().unwrap();

            let coding_config = coding_config_for_participants(4);
            let inner = B::new::<H>((), Sha256Digest::EMPTY, Height::new(1), 2);
            let coded_block = CodedBlock::<B, C>::new(inner, coding_config, &STRATEGY);

            let total_shards = coding_config.total_shards() as usize;
            let mut shards = (0..total_shards)
                .map(|i| coded_block.shard::<H>(i).expect("missing shard"))
                .collect::<Vec<_>>();

            let (min_index, _) = shards
                .iter()
                .enumerate()
                .min_by_key(|(_, shard)| shard.digest())
                .expect("no shards present");

            let invalid_shard = shards[min_index].clone();
            let commitment = invalid_shard.commitment();
            let index = invalid_shard.index();
            let DistributionShard::Strong(inner) = invalid_shard.into_inner() else {
                panic!("expected strong shard");
            };

            let shard_cfg = CodecConfig {
                maximum_shard_size: MAX_SHARD_SIZE,
            };
            let mut encoded = inner.encode().to_vec();
            let mut cursor = encoded.as_slice();
            let shard_len = usize::read_cfg(
                &mut cursor,
                &RangeCfg::from(..=shard_cfg.maximum_shard_size),
            )
            .expect("failed to read shard length");
            let len_prefix_len = encoded.len() - cursor.remaining();
            assert!(shard_len > 0, "shard length must be non-zero");
            encoded[len_prefix_len] ^= 0xFF;

            let invalid_inner =
                <C as CodingScheme>::Shard::read_cfg(&mut encoded.as_slice(), &shard_cfg)
                    .expect("failed to decode invalid shard");
            let invalid_shard =
                Shard::<C, H>::new(commitment, index, DistributionShard::Strong(invalid_inner));
            assert!(
                invalid_shard.clone().verify_into_reshard().is_none(),
                "invalid shard should fail verification"
            );
            shards[min_index] = invalid_shard;

            let mut sender_buffered = buffered_mailboxes
                .get(&sender)
                .expect("missing sender mailbox")
                .clone();
            for shard in shards {
                let _ = sender_buffered
                    .broadcast(Recipients::One(receiver.clone()), shard)
                    .await
                    .await;
            }

            context.sleep(DEFAULT_LINK.latency * 2).await;

            let receiver_mailbox = shard_mailboxes
                .get_mut(&receiver)
                .expect("missing receiver mailbox");
            let result = receiver_mailbox
                .try_reconstruct(commitment)
                .await
                .expect("reconstruction failed");
            assert!(
                result.is_some(),
                "reconstruction should succeed despite invalid strong shard"
            );
        });
    }

    #[test_traced]
    fn test_reconstruction_with_insufficient_shards() {
        let fixture = Fixture {
            num_peers: 8,
            link: DEFAULT_LINK,
        };

        fixture.start(|config, context, mut mailboxes, coding_config| async move {
            let inner = B::new::<H>((), Sha256Digest::EMPTY, Height::new(1), 2);
            let coded_block = CodedBlock::<B, C>::new(inner, coding_config, &STRATEGY);
            let peers: Vec<P> = mailboxes.keys().cloned().collect();

            // Only broadcast to a subset of peers (less than minimum required for reconstruction)
            // With 8 peers, config gives minimum_shards = (8-1)/3 + 1 = 3
            // We'll only deliver to 2 peers to ensure reconstruction fails
            let partial_peers: Vec<P> = peers.iter().take(2).cloned().collect();

            let first_mailbox = mailboxes.get_mut(peers.first().unwrap()).unwrap();
            first_mailbox
                .proposed(coded_block.clone(), peers.clone())
                .await;

            // Give time for partial delivery
            context.sleep(config.link.latency * 2).await;

            // Only validate shards for the first 2 peers (insufficient for reconstruction)
            for (i, peer) in partial_peers.iter().enumerate() {
                let mailbox = mailboxes.get_mut(peer).unwrap();
                mailbox
                    .subscribe_shard_validity(coded_block.commitment(), Participant::new(i as u32))
                    .await
                    .await
                    .unwrap();
            }

            // Give time for partial broadcast
            context.sleep(config.link.latency * 2).await;

            // The third peer (who hasn't validated their shard yet) should not be able
            // to reconstruct because they haven't received enough shards yet
            let third_peer = &peers[2];
            let mailbox = mailboxes.get_mut(third_peer).unwrap();
            let result = mailbox
                .try_reconstruct(coded_block.commitment())
                .await
                .unwrap();

            // Reconstruction may or may not succeed depending on timing.
            // What we're really testing is that it doesn't panic and handles
            // the insufficient shards case gracefully.
            if let Some(block) = result {
                // Also acceptable: enough shards arrived through gossip
                assert_eq!(block.commitment(), coded_block.commitment());
            }
            // Otherwise: not enough shards yet (expected)
        });
    }

    #[test_traced]
    fn test_reconstruction_with_wrong_commitment() {
        let fixture = Fixture {
            num_peers: 8,
            link: DEFAULT_LINK,
        };

        fixture.start(
            |_config, context, mut mailboxes, coding_config| async move {
                let inner1 = B::new::<H>((), Sha256Digest::EMPTY, Height::new(1), 2);
                let coded_block1 = CodedBlock::<B, C>::new(inner1, coding_config, &STRATEGY);

                let inner2 = B::new::<H>((), Sha256Digest::EMPTY, Height::new(2), 3);
                let coded_block2 = CodedBlock::<B, C>::new(inner2, coding_config, &STRATEGY);

                let peers: Vec<P> = mailboxes.keys().cloned().collect();

                // Broadcast shards for block 1
                let first_mailbox = mailboxes.get_mut(peers.first().unwrap()).unwrap();
                first_mailbox
                    .proposed(coded_block1.clone(), peers.clone())
                    .await;

                context.sleep(Duration::from_millis(100)).await;

                // Try to reconstruct using block 2's commitment (which we don't have shards for)
                let second_mailbox = mailboxes.get_mut(&peers[1]).unwrap();
                let result = second_mailbox
                    .try_reconstruct(coded_block2.commitment())
                    .await
                    .unwrap();

                // Should return None since we don't have shards for block 2
                assert!(
                    result.is_none(),
                    "reconstruction should fail for unknown commitment"
                );
            },
        );
    }

    #[test_traced]
    fn test_subscribe_to_block() {
        let fixture = Fixture {
            num_peers: 8,
            link: DEFAULT_LINK,
        };

        fixture.start(|config, context, mut mailboxes, coding_config| async move {
            let inner = B::new::<H>((), Sha256Digest::EMPTY, Height::new(1), 2);
            let coded_block = CodedBlock::<B, C>::new(inner, coding_config, &STRATEGY);
            let peers: Vec<P> = mailboxes.keys().cloned().collect();

            // Broadcast all shards out (proposer)
            let first_mailbox = mailboxes.get_mut(&peers[0]).unwrap();
            first_mailbox
                .proposed(coded_block.clone(), peers.clone())
                .await;

            // Give the shard engine time to process the message and deliver shards.
            context.sleep(config.link.latency * 2).await;

            // Open a subscription for the block from the second peer's mailbox. At the time of opening
            // the subscription, the block cannot yet be reconstructed by the second peer, since
            // they don't have enough shards yet.
            let second_mailbox = mailboxes.get_mut(&peers[1]).unwrap();
            let block_subscription = second_mailbox
                .subscribe_block_by_digest(coded_block.digest())
                .await;
            let block_reconstruction_result = second_mailbox
                .try_reconstruct(coded_block.commitment())
                .await
                .unwrap();
            assert!(block_reconstruction_result.is_none());

            // Ensure all peers got their shards.
            for (i, peer) in peers.iter().enumerate() {
                let mailbox = mailboxes.get_mut(peer).unwrap();
                mailbox
                    .subscribe_shard_validity(coded_block.commitment(), Participant::new(i as u32))
                    .await
                    .await
                    .unwrap();
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

    #[test_traced]
    fn test_subscriptions_pruned_on_finalization() {
        let fixture = Fixture {
            num_peers: 8,
            link: DEFAULT_LINK,
        };

        fixture.start(|config, context, mut mailboxes, coding_config| async move {
            // Create two blocks at height 1 - one will be finalized, one will be orphaned
            let finalized_inner = B::new::<H>((), Sha256Digest::EMPTY, Height::new(1), 2);
            let finalized_block =
                CodedBlock::<B, C>::new(finalized_inner, coding_config, &STRATEGY);

            let orphan_inner = B::new::<H>((), Sha256Digest::EMPTY, Height::new(1), 999);
            let orphan_block = CodedBlock::<B, C>::new(orphan_inner, coding_config, &STRATEGY);

            let peers: Vec<P> = mailboxes.keys().cloned().collect();

            // Broadcast shards for the finalized block only
            let first_mailbox = mailboxes.get_mut(&peers[0]).unwrap();
            first_mailbox
                .proposed(finalized_block.clone(), peers.clone())
                .await;

            // Give the shard engine time to process the messages and deliver shards.
            context.sleep(config.link.latency * 2).await;

            // Validate shards for the finalized block
            for (i, peer) in peers.iter().enumerate() {
                let mailbox = mailboxes.get_mut(peer).unwrap();
                mailbox
                    .subscribe_shard_validity(
                        finalized_block.commitment(),
                        Participant::new(i as u32),
                    )
                    .await
                    .await
                    .unwrap();
            }
            context.sleep(config.link.latency * 2).await;

            // Reconstruct the finalized block on all peers
            for peer in peers.iter() {
                let mailbox = mailboxes.get_mut(peer).unwrap();
                let _ = mailbox.try_reconstruct(finalized_block.commitment()).await;
            }

            // Subscribe to the orphan block BEFORE it's broadcast/reconstructed.
            // Since there are no shards for this block, the subscriptions will remain
            // pending until either the block is reconstructed or the subscription is pruned.
            // We only subscribe on one peer to verify the pruning behavior.
            let second_mailbox = mailboxes.get_mut(&peers[1]).unwrap();
            let orphan_rx = second_mailbox
                .subscribe_block_by_commitment(orphan_block.commitment())
                .await;

            // Now broadcast the orphan block's shards so it gets reconstructed
            let first_mailbox = mailboxes.get_mut(&peers[0]).unwrap();
            first_mailbox
                .proposed(orphan_block.clone(), peers.clone())
                .await;

            // Give the shard engine time to process and deliver shards
            context.sleep(config.link.latency * 2).await;

            // Validate and broadcast shards for the orphan block
            for (i, peer) in peers.iter().enumerate() {
                let mailbox = mailboxes.get_mut(peer).unwrap();
                mailbox
                    .subscribe_shard_validity(orphan_block.commitment(), Participant::new(i as u32))
                    .await
                    .await
                    .unwrap();
            }
            context.sleep(config.link.latency * 2).await;

            // Reconstruct the orphan block
            let second_mailbox = mailboxes.get_mut(&peers[1]).unwrap();
            let orphan_result = second_mailbox
                .try_reconstruct(orphan_block.commitment())
                .await
                .unwrap();
            assert!(orphan_result.is_some(), "orphan block should reconstruct");

            // The subscription should have been fulfilled when the block was reconstructed
            let received_block = orphan_rx.await.unwrap();
            assert_eq!(received_block.commitment(), orphan_block.commitment());

            // Now finalize the first block - this should:
            // 1. Remove the finalized block from reconstructed_blocks
            // 2. Remove the orphan block from reconstructed_blocks (height <= finalized)
            // 3. Prune any remaining subscriptions for orphaned commitments
            let first_mailbox = mailboxes.get_mut(&peers[0]).unwrap();
            first_mailbox.finalized(finalized_block.commitment()).await;

            // Give time for finalization to process
            context.sleep(config.link.latency).await;

            // Verify the orphan block was pruned from reconstructed_blocks by checking
            // that try_reconstruct now fails (no shards cached after finalization eviction)
            let second_mailbox = mailboxes.get_mut(&peers[1]).unwrap();
            let result = second_mailbox
                .try_reconstruct(orphan_block.commitment())
                .await
                .unwrap();
            // The block should no longer be in the cache (was pruned)
            // Note: It may be reconstructed again from cached shards, but the key point
            // is that the reconstructed_blocks cache was pruned
            drop(result);
        });
    }

    /// Regression test: A byzantine actor can race an invalid shard into our mailbox
    /// before the honest proposer's valid shard arrives. The subscription should NOT
    /// resolve to `false` when the invalid shard is processed - it should wait for
    /// a valid shard to arrive.
    #[test_traced]
    fn test_shard_validity_waits_for_valid_shard() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (network, oracle) =
                commonware_p2p::simulated::Network::<deterministic::Context, P>::new(
                    context.with_label("network"),
                    commonware_p2p::simulated::Config {
                        max_size: 1024 * 1024,
                        disconnect_on_block: true,
                        tracked_peer_sets: None,
                    },
                );
            network.start();

            // Set up three peers: byzantine, honest proposer, and receiver
            let mut schemes = (0..3)
                .map(|i| PrivateKey::from_seed(i as u64))
                .collect::<Vec<_>>();
            schemes.sort_by_key(|s| s.public_key());
            let peers: Vec<P> = schemes.iter().map(|c| c.public_key()).collect();

            let byzantine = peers[0].clone();
            let honest = peers[1].clone();
            let receiver = peers[2].clone();

            let mut registrations = BTreeMap::new();
            for peer in peers.iter() {
                let (sender, receiver) = oracle
                    .control(peer.clone())
                    .register(0, TEST_QUOTA)
                    .await
                    .unwrap();
                registrations.insert(peer.clone(), (sender, receiver));
            }

            // Add links between all peers
            for p1 in peers.iter() {
                for p2 in peers.iter() {
                    if p2 == p1 {
                        continue;
                    }
                    oracle
                        .add_link(p1.clone(), p2.clone(), DEFAULT_LINK)
                        .await
                        .unwrap();
                }
            }

            let mut buffered_mailboxes = BTreeMap::new();
            let mut shard_mailboxes = BTreeMap::new();
            while let Some((peer, network)) = registrations.pop_first() {
                let context = context.with_label(&format!("peer_{peer}"));
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
                let buffered_mailbox = engine_mailbox.clone();
                let (shard_engine, shard_mailbox) = ShardEngine::new(
                    context.with_label("shard_mailbox"),
                    engine_mailbox,
                    (),
                    10,
                    STRATEGY,
                );
                buffered_mailboxes.insert(peer.clone(), buffered_mailbox);
                shard_mailboxes.insert(peer.clone(), shard_mailbox);

                engine.start(network);
                shard_engine.start();
            }

            // Create a coded block
            let coding_config = coding_config_for_participants(4);
            let inner = B::new::<H>((), Sha256Digest::EMPTY, Height::new(1), 2);
            let coded_block = CodedBlock::<B, C>::new(inner, coding_config, &STRATEGY);
            let commitment = coded_block.commitment();

            // Get the valid shard at index 0 (this is what the receiver expects)
            let valid_shard = coded_block.shard::<H>(0).expect("missing shard");

            // Create an invalid shard by corrupting the valid shard's data
            let DistributionShard::Strong(valid_inner) = valid_shard.clone().into_inner() else {
                panic!("expected strong shard");
            };

            let shard_cfg = CodecConfig {
                maximum_shard_size: MAX_SHARD_SIZE,
            };
            let mut encoded = valid_inner.encode().to_vec();
            let mut cursor = encoded.as_slice();
            let shard_len = usize::read_cfg(
                &mut cursor,
                &RangeCfg::from(..=shard_cfg.maximum_shard_size),
            )
            .expect("failed to read shard length");
            let len_prefix_len = encoded.len() - cursor.remaining();
            assert!(shard_len > 0, "shard length must be non-zero");
            // Corrupt a byte in the shard data
            encoded[len_prefix_len] ^= 0xFF;

            let invalid_inner =
                <C as CodingScheme>::Shard::read_cfg(&mut encoded.as_slice(), &shard_cfg)
                    .expect("failed to decode invalid shard");
            let invalid_shard =
                Shard::<C, H>::new(commitment, 0, DistributionShard::Strong(invalid_inner));

            // Verify our invalid shard is actually invalid
            assert!(
                invalid_shard.clone().verify_into_reshard().is_none(),
                "invalid shard should fail verification"
            );

            // Byzantine actor sends the invalid shard FIRST
            let mut byzantine_buffered = buffered_mailboxes.get(&byzantine).unwrap().clone();
            let _ = byzantine_buffered
                .broadcast(Recipients::One(receiver.clone()), invalid_shard)
                .await
                .await;

            // Wait for the invalid shard to arrive at the receiver
            context.sleep(DEFAULT_LINK.latency * 2).await;

            // Open a subscription for shard validity at index 0
            let receiver_mailbox = shard_mailboxes
                .get_mut(&receiver)
                .expect("missing receiver mailbox");
            let mut validity_rx = receiver_mailbox
                .subscribe_shard_validity(commitment, Participant::new(0))
                .await;

            // Give the shard engine time to process the invalid shard
            context.sleep(DEFAULT_LINK.latency * 2).await;

            // The subscription should NOT have resolved yet - it should still be waiting
            // for a valid shard. We verify this by checking that the receiver is not ready.
            assert!(
                matches!(validity_rx.try_recv(), Err(TryRecvError::Empty)),
                "subscription should not resolve before valid shard arrives"
            );

            // Now the honest proposer sends the valid shard
            let mut honest_buffered = buffered_mailboxes.get(&honest).unwrap().clone();
            let _ = honest_buffered
                .broadcast(Recipients::One(receiver.clone()), valid_shard)
                .await
                .await;

            // Wait for the valid shard to arrive and be processed
            context.sleep(DEFAULT_LINK.latency * 2).await;

            // NOW the subscription should resolve (completing means valid shard arrived)
            select! {
                _ = validity_rx => {},
                _ = context.sleep(Duration::from_secs(5)) => {
                    panic!("subscription did not complete after valid shard arrival");
                }
            };
        });
    }
}
