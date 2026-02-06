//! Shard engine for erasure-coded block distribution and reconstruction.
//!
//! This module implements the core logic for distributing blocks as erasure-coded
//! shards and reconstructing blocks from received shards.
//!
//! # Overview
//!
//! The shard engine serves two primary functions:
//! 1. Broadcast: When a node proposes a block, the engine broadcasts
//!    erasure-coded shards to all participants.
//! 2. Block Reconstruction: When a node receives shards from peers, the engine
//!    validates them incrementally and reconstructs the original block once
//!    enough valid shards are available.
//!
//! # Shard Types
//!
//! The engine distinguishes between two shard types:
//!
//! - Strong shards (`Scheme::StrongShard`): Original erasure-coded shards sent by the proposer.
//!   These contain the data needed to derive checking data for validation.
//!
//! - Weak shards (`Scheme::WeakShard`): Shards that have been validated and re-broadcast
//!   by participants. These require checking data (derived from a strong shard)
//!   for validation.
//!
//! # Message Flow
//!
//! ```text
//!                           PROPOSER
//!                              |
//!                              | Proposed(block)
//!                              v
//!                    +------------------+
//!                    |   Shard Engine   |
//!                    +------------------+
//!                              |
//!            broadcast_shards (strong shards to each participant)
//!                              |
//!         +--------------------+--------------------+
//!         |                    |                    |
//!         v                    v                    v
//!    Participant 0        Participant 1        Participant N
//!         |                    |                    |
//!         | (receive strong    | (receive strong    |
//!         |  shard for self)   |  shard for self)   |
//!         v                    v                    v
//!    +----------+         +----------+         +----------+
//!    | Buffer   |         | Buffer   |         | Buffer   |
//!    | (await   |         | (await   |         | (await   |
//!    |  leader) |         |  leader) |         |  leader) |
//!    +----------+         +----------+         +----------+
//!         |                    |                    |
//!         | ExternalProposed   | ExternalProposed   |
//!         | (leader identity)  | (leader identity)  |
//!         v                    v                    v
//!    +----------+         +----------+         +----------+
//!    | Validate |         | Validate |         | Validate |
//!    | (weaken) |         | (weaken) |         | (weaken) |
//!    +----------+         +----------+         +----------+
//!         |                    |                    |
//!         | Store checking     | Store checking     |
//!         | data + checked     | data + checked     |
//!         | shard              | shard              |
//!         |                    |                    |
//!         +--------------------+--------------------+
//!                              |
//!                    (gossip weak shards)
//!                              |
//!         +--------------------+--------------------+
//!         |                    |                    |
//!         v                    v                    v
//!    +----------+         +----------+         +----------+
//!    | Validate |         | Validate |         | Validate |
//!    | (check)  |         | (check)  |         | (check)  |
//!    +----------+         +----------+         +----------+
//!         |                    |                    |
//!         v                    v                    v
//!    Accumulate checked shards until minimum_shards reached
//!         |                    |                    |
//!         v                    v                    v
//!    +-------------+      +-------------+      +-------------+
//!    | Reconstruct |      | Reconstruct |      | Reconstruct |
//!    |    Block    |      |    Block    |      |    Block    |
//!    +-------------+      +-------------+      +-------------+
//! ```
//!
//! # Reconstruction State Machine
//!
//! For each [`CodingCommitment`], the engine maintains a [`ReconstructionState`]:
//!
//! ```text
//!    +------------------+
//!    |  Initial State   |
//!    | (no shards,      |
//!    |  leader unknown) |
//!    +------------------+
//!           |       |
//!           |       | Receive strong shard
//!           |       | (buffered in pending_strong_shards)
//!           |       |
//!           |       | Receive weak shard
//!           |       | (buffered in pending_shards)
//!           |       v
//!           |  +------------------+
//!           |  | Buffering        |
//!           |  | (awaiting leader |
//!           |  |  + strong shard) |
//!           |  +------------------+
//!           |       |
//!           +-------+
//!                   |
//!                   | ExternalProposed (leader identity)
//!                   v
//!    +------------------+
//!    | Leader Known     |
//!    | (drain buffered  |
//!    |  strong shards)  |
//!    +------------------+
//!             |
//!             | Leader's strong shard verified (C::weaken)
//!             v
//!    +------------------+
//!    | Has Checking     |<----+
//!    | Data             |     |
//!    +------------------+     |
//!             |               |
//!             | Drain any     | Receive weak shard
//!             | pending       | (validated with checking data)
//!             | weak shards   |
//!             v               |
//!    +------------------+     |
//!    | Accumulating     |-----+
//!    | Checked Shards   |
//!    +------------------+
//!             |
//!             | checked_shards.len() >= minimum_shards
//!             v
//!    +------------------+
//!    | Reconstruction   |
//!    | Attempt          |
//!    +------------------+
//!             |
//!        +----+----+
//!        |         |
//!        v         v
//!    Success    Failure
//!        |         |
//!        v         v
//!    Cache      Remove
//!    Block      State
//! ```
//!
//! # Peer Validation and Blocking Rules
//!
//! The engine enforces strict validation to prevent Byzantine attacks:
//!
//! - All shards MUST be sent by participants in the current epoch.
//! - Strong shards MUST correspond to the recipient's index.
//! - Weak shards MUST be sent by the participant whose index matches
//!   the shard index.
//! - All shards MUST pass cryptographic verification against the commitment.
//! - Each participant may only contribute ONE weak shard per commitment.
//!
//! Peers violating these rules are blocked via the [`Blocker`] trait.
//!
//! Note: Strong shards are only accepted from the leader. If the leader is not
//! yet known, strong shards are buffered until consensus signals the leader via
//! [`ExternalProposed`]. When the leader arrives, the leader's buffered shard is
//! verified and all other buffered senders are blocked. Duplicate strong shards
//! from the leader are treated as Byzantine behavior and result in blocking.
//!
//! [`ExternalProposed`]: super::mailbox::Message::ExternalProposed

use super::{
    mailbox::{Mailbox, Message},
    metrics::{Peer, ShardMetrics},
};
use crate::{
    marshal::coding::types::{CodedBlock, DistributionShard, Shard},
    types::CodingCommitment,
    Block, CertifiableBlock, Heightable,
};
use commonware_codec::{Codec, Error as CodecError, Read};
use commonware_coding::Scheme as CodingScheme;
use commonware_cryptography::{Committable, Digestible, Hasher, PublicKey};
use commonware_macros::select_loop;
use commonware_p2p::{
    utils::codec::{wrap, WrappedReceiver, WrappedSender},
    Blocker, Receiver, Recipients, Sender,
};
use commonware_parallel::Strategy;
use commonware_runtime::{
    spawn_cell, telemetry::metrics::status::GaugeExt, Clock, ContextCell, Handle, Metrics, Spawner,
};
use commonware_utils::{
    bitmap::BitMap,
    channel::{fallible::OneshotExt, mpsc, oneshot},
    ordered::{Quorum, Set},
    Participant,
};
use rand::Rng;
use rayon::iter::Either;
use std::{
    collections::BTreeMap,
    sync::Arc,
    time::{Duration, Instant, SystemTime},
};
use thiserror::Error;
use tracing::{debug, warn};

/// An error that can occur during reconstruction of a [`CodedBlock`] from [`Shard`]s
#[derive(Debug, Error)]
pub enum ReconstructionError<C: CodingScheme> {
    /// An error occurred while recovering the encoded blob from the [`Shard`]s
    #[error(transparent)]
    CodingRecovery(C::Error),

    /// An error occurred while decoding the reconstructed blob into a [`CodedBlock`]
    #[error(transparent)]
    Codec(#[from] CodecError),

    /// The reconstructed block's digest does not match the commitment's block digest
    #[error("block digest mismatch: reconstructed block does not match commitment")]
    DigestMismatch,
}

/// Configuration for the [`Engine`].
pub struct Config<P, X, C, H, B, T>
where
    P: PublicKey,
    X: Blocker<PublicKey = P>,
    C: CodingScheme,
    H: Hasher,
    B: CertifiableBlock,
    T: Strategy,
{
    /// Self's index in the participant set, if participating.
    pub me: Option<Participant>,

    /// The set of participants for the active epoch.
    pub participants: Set<P>,

    /// The peer blocker.
    pub blocker: X,

    /// [`Read`] configuration for decoding [`Shard`]s.
    pub shard_codec_cfg: <Shard<C, H> as Read>::Cfg,

    /// [`commonware_codec::Read`] configuration for decoding blocks.
    pub block_codec_cfg: B::Cfg,

    /// The strategy used for parallel computation.
    pub strategy: T,

    /// The size of the mailbox buffer.
    pub mailbox_size: usize,

    /// Time-to-live for reconstruction state entries.
    ///
    /// Entries that have not been updated within this duration are pruned to
    /// prevent unbounded state growth from Byzantine participants sending shards
    /// for fake commitments.
    ///
    /// # Safety
    ///
    /// This value MUST be >= the consensus `notarization_timeout`. If shorter,
    /// reconstruction state could be pruned while consensus is still actively
    /// trying to reconstruct a block, causing block subscriptions to hang until
    /// consensus eventually nullifies the view.
    pub state_ttl: Duration,
}

/// A network layer for broadcasting and receiving [`CodedBlock`]s as [`Shard`]s.
///
/// When enough [`Shard`]s are present in the mailbox, the [`Engine`] may facilitate
/// reconstruction of the original [`CodedBlock`] and notify any subscribers waiting for it.
pub struct Engine<E, X, C, H, B, P, T>
where
    E: Rng + Spawner + Metrics + Clock,
    X: Blocker,
    C: CodingScheme,
    H: Hasher,
    B: CertifiableBlock,
    P: PublicKey,
    T: Strategy,
{
    /// Context held by the actor.
    context: ContextCell<E>,

    /// Receiver for incoming messages to the actor.
    mailbox: mpsc::Receiver<Message<B, C, P>>,

    /// Self's index in the participant set, if participating.
    me: Option<Participant>,

    /// The current set of participants for the active epoch.
    participants: Set<P>,

    /// The peer blocker.
    blocker: X,

    /// [`Read`] configuration for decoding [`Shard`]s.
    shard_codec_cfg: <Shard<C, H> as Read>::Cfg,

    /// [`Read`] configuration for decoding [`CodedBlock`]s.
    block_codec_cfg: B::Cfg,

    /// The strategy used for parallel computation.
    strategy: T,

    /// A map of [`CodingCommitment`]s to [`ReconstructionState`]s.
    state: BTreeMap<CodingCommitment, ReconstructionState<P, C, H>>,

    /// Time-to-live for reconstruction state entries.
    state_ttl: Duration,

    /// An ephemeral cache of reconstructed blocks, keyed by commitment.
    ///
    /// These blocks are evicted after we receive a finalization signal.
    /// Wrapped in [`Arc`] to enable cheap cloning when serving multiple subscribers.
    reconstructed_blocks: BTreeMap<CodingCommitment, Arc<CodedBlock<B, C>>>,

    /// Open subscriptions for the receipt of our valid shard corresponding
    /// to the keyed [`CodingCommitment`] from the leader.
    shard_subscriptions: BTreeMap<CodingCommitment, Vec<oneshot::Sender<()>>>,

    /// Open subscriptions for the reconstruction of a [`CodedBlock`] with
    /// the keyed [`CodingCommitment`].
    #[allow(clippy::type_complexity)]
    block_subscriptions:
        BTreeMap<Either<CodingCommitment, B::Digest>, Vec<oneshot::Sender<Arc<CodedBlock<B, C>>>>>,

    /// Metrics for the shard engine.
    metrics: ShardMetrics,
}

impl<E, X, C, H, B, P, T> Engine<E, X, C, H, B, P, T>
where
    E: Rng + Spawner + Metrics + Clock,
    X: Blocker<PublicKey = P>,
    C: CodingScheme,
    H: Hasher,
    B: CertifiableBlock,
    P: PublicKey,
    T: Strategy,
{
    /// Create a new [Engine] with the given configuration.
    pub fn new(context: E, config: Config<P, X, C, H, B, T>) -> (Self, Mailbox<B, C, P>) {
        let metrics = ShardMetrics::new(&context, &config.participants);
        let (sender, mailbox) = mpsc::channel(config.mailbox_size);
        (
            Self {
                context: ContextCell::new(context),
                mailbox,
                me: config.me,
                participants: config.participants,
                blocker: config.blocker,
                shard_codec_cfg: config.shard_codec_cfg,
                block_codec_cfg: config.block_codec_cfg,
                strategy: config.strategy,
                state: BTreeMap::new(),
                state_ttl: config.state_ttl,
                reconstructed_blocks: BTreeMap::new(),
                shard_subscriptions: BTreeMap::new(),
                block_subscriptions: BTreeMap::new(),
                metrics,
            },
            Mailbox::new(sender),
        )
    }

    /// Start the engine.
    pub fn start(
        mut self,
        network: (impl Sender<PublicKey = P>, impl Receiver<PublicKey = P>),
    ) -> Handle<()> {
        spawn_cell!(self.context, self.run(network).await)
    }

    /// Run the shard engine's event loop.
    async fn run(
        mut self,
        (sender, receiver): (impl Sender<PublicKey = P>, impl Receiver<PublicKey = P>),
    ) {
        let (mut sender, receiver) =
            wrap::<_, _, Shard<C, H>>(self.shard_codec_cfg.clone(), sender, receiver);
        let (receiver_service, mut receiver) = WrappedBackgroundReceiver::new(
            self.context.with_label("wrapped_background_receiver"),
            receiver,
            self.blocker.clone(),
        );
        // Keep the handle alive to prevent the background receiver from being aborted.
        let _receiver_handle = receiver_service.start();

        select_loop! {
            self.context,
            on_start => {
                // Clean up closed subscriptions.
                self.block_subscriptions.retain(|_, subscribers| {
                    subscribers.retain(|tx| !tx.is_closed());
                    !subscribers.is_empty()
                });
                self.shard_subscriptions.retain(|_, subscribers| {
                    subscribers.retain(|tx| !tx.is_closed());
                    !subscribers.is_empty()
                });
                // Prune stale reconstruction states.
                self.prune_stale_states();
            },
            on_stopped => {
                debug!("received shutdown signal, stopping shard engine");
            },
            Some(message) = self.mailbox.recv() else {
                debug!("shard mailbox closed, stopping shard engine");
                return;
            } => {
                match message {
                    Message::UpdateParticipants { me, participants } => {
                        self.me = participants.index(&me);
                        self.participants = participants;

                        // Clear reconstruction state and subscriptions
                        self.update_state(|s| s.clear());
                        self.shard_subscriptions.clear();
                        self.block_subscriptions.clear();

                        debug!("updated participant set");
                    },
                    Message::Proposed { block } => {
                        self.broadcast_shards(&mut sender, block).await;
                    },
                    Message::ExternalProposed { commitment, leader } => {
                        if self.reconstructed_blocks.contains_key(&commitment) {
                            continue;
                        }
                        let Some(me) = self.me.as_ref().copied() else {
                            continue;
                        };
                        self.state
                            .entry(commitment)
                            .or_default()
                            .set_leader(
                                leader,
                                &me,
                                &self.strategy,
                                &mut self.blocker,
                            ).await;
                        self.try_advance(&mut sender, commitment).await;
                    },
                    Message::GetByCommitment { commitment, response } => {
                        let block = self.reconstructed_blocks.get(&commitment).cloned();
                        response.send_lossy(block);
                    },
                    Message::GetByDigest { digest, response } => {
                        let block = self.reconstructed_blocks
                            .iter()
                            .find_map(|(_, b)| (b.digest() == digest).then_some(b))
                            .cloned();
                        response.send_lossy(block);
                    },
                    Message::SubscribeShard { commitment, response } => {
                        self.handle_shard_subscription(commitment, response).await;
                    }
                    Message::SubscribeBlockByCommitment { commitment, response } => {
                        self.handle_block_subscription(
                            Either::Left(commitment),
                            response
                        ).await;
                    },
                    Message::SubscribeBlockByDigest { digest, response } => {
                        self.handle_block_subscription(
                            Either::Right(digest),
                            response
                        ).await;
                    },
                    Message::Durable { commitment } => {
                        self.prune_reconstructed(commitment);
                    },
                }
            },
            Some((peer, shard)) = receiver.recv() else {
                debug!("receiver closed, stopping shard engine");
                return;
            } => {
                // Block peers that are not participants.
                if self.participants.index(&peer).is_none() {
                    warn!(?peer, "shard sent by non-participant, blocking peer");
                    self.blocker.block(peer).await;
                    continue;
                }

                // Track shard receipt per peer.
                self.metrics.shards_received.get_or_create(&Peer::new(&peer)).inc();

                // Insert the shard into the reconstruction state.
                let commitment = shard.commitment();
                if !self.reconstructed_blocks.contains_key(&commitment) {
                    let now = self.context.current();
                    let state = self.state
                        .entry(shard.commitment())
                        .or_default();
                    state.insert(
                        self.me.as_ref(),
                        peer,
                        shard,
                        &self.participants,
                        &self.strategy,
                        &mut self.blocker,
                        now,
                    ).await;

                }
                self.try_advance(&mut sender, commitment).await;
            }
        }
    }

    /// Attempts to reconstruct a [`CodedBlock`] from the checked [`Shard`]s present in the
    /// [`ReconstructionState`].
    ///
    /// # Returns
    /// - `Ok(Some(block))` if reconstruction was successful or the block was already reconstructed.
    /// - `Ok(None)` if reconstruction could not be attempted due to insufficient checked shards.
    /// - `Err(ReconstructionError)` if reconstruction was attempted but failed.
    #[inline]
    async fn try_reconstruct(
        &mut self,
        commitment: CodingCommitment,
    ) -> Result<Option<Arc<CodedBlock<B, C>>>, ReconstructionError<C>> {
        if let Some(block) = self.reconstructed_blocks.get(&commitment) {
            return Ok(Some(Arc::clone(block)));
        }

        let Some(state) = self.state.get(&commitment) else {
            return Ok(None);
        };
        if state.checked_shards.len() < commitment.config().minimum_shards as usize {
            debug!(%commitment, "not enough checked shards to reconstruct block");
            return Ok(None);
        }

        let Some(checking_data) = &state.checking_data else {
            unreachable!("checked shards cannot be present without checking data");
        };

        // Attempt to reconstruct the encoded blob
        let start = Instant::now();
        let blob = C::decode(
            &commitment.config(),
            &commitment.coding_digest(),
            checking_data.clone(),
            state.checked_shards.as_slice(),
            &self.strategy,
        )
        .map_err(ReconstructionError::CodingRecovery)?;
        let _ = self
            .metrics
            .erasure_decode_duration
            .try_set(start.elapsed().as_millis());

        // Attempt to decode the block from the encoded blob
        let inner = B::read_cfg(&mut blob.as_slice(), &self.block_codec_cfg)?;

        // Verify the reconstructed block's digest matches the commitment's block digest.
        if inner.digest() != commitment.block_digest() {
            return Err(ReconstructionError::DigestMismatch);
        }

        // Construct a coding block with a _trusted_ commitment. `S::decode` verified the blob's
        // integrity against the commitment, so shards can be lazily re-constructed if need be.
        let block = Arc::new(CodedBlock::new_trusted(inner, commitment));

        self.update_reconstructed_blocks(|b| b.insert(commitment, Arc::clone(&block)));
        self.metrics.blocks_reconstructed_total.inc();
        Ok(Some(block))
    }

    /// Broadcasts the shards of a [`CodedBlock`] to all participants and caches the block.
    #[inline]
    async fn broadcast_shards<Sr: Sender<PublicKey = P>>(
        &mut self,
        sender: &mut WrappedSender<Sr, Shard<C, H>>,
        mut block: CodedBlock<B, C>,
    ) {
        assert_eq!(block.shards(&self.strategy).len(), self.participants.len());

        // Cache the block so we don't have to reconstruct it again.
        let commitment = block.commitment();
        self.update_reconstructed_blocks(|b| b.insert(commitment, Arc::new(block.clone())));

        // Broadcast each shard to the corresponding participant.
        for (index, peer) in self.participants.iter().enumerate() {
            if self.me.is_some_and(|me| me.get() as usize == index) {
                continue;
            }

            let shard = block
                .shard(index)
                .expect("block must have shard for each participant");
            let _ = sender
                .send(Recipients::One(peer.clone()), shard, true)
                .await;
        }

        debug!(?commitment, "broadasted shards to participants");
    }

    /// Broadcasts a [`Shard`] to all participants.
    #[inline]
    async fn broadcast_weak_shard<Sr: Sender<PublicKey = P>>(
        &mut self,
        sender: &mut WrappedSender<Sr, Shard<C, H>>,
        shard: Shard<C, H>,
    ) {
        let commitment = shard.commitment();
        let _ = sender.send(Recipients::All, shard, true).await;
        debug!(?commitment, "broadasted shard to all participants");
    }

    /// Broadcasts any pending weak shard for the given commitment and attempts
    /// reconstruction. If reconstruction succeeds or fails, the state is cleaned
    /// up and subscribers are notified.
    #[inline]
    async fn try_advance<Sr: Sender<PublicKey = P>>(
        &mut self,
        sender: &mut WrappedSender<Sr, Shard<C, H>>,
        commitment: CodingCommitment,
    ) {
        if let Some(weak_shard) = self
            .state
            .get_mut(&commitment)
            .and_then(|s| s.take_weak_shard())
        {
            self.broadcast_weak_shard(sender, weak_shard).await;
            self.notify_shard_subscribers(commitment).await;
        }

        let _ = self
            .metrics
            .reconstruction_states_count
            .try_set(self.state.len());

        match self.try_reconstruct(commitment).await {
            Ok(Some(block)) => {
                debug!(
                    %commitment,
                    parent = %block.parent(),
                    height = %block.height(),
                    "successfully reconstructed block from shards"
                );
                self.update_state(|s| s.remove(&commitment));
                self.notify_block_subscribers(block).await;
            }
            Ok(None) => {
                debug!(%commitment, "not enough checked shards to reconstruct block");
            }
            Err(err) => {
                warn!(%commitment, ?err, "failed to reconstruct block from checked shards");
                self.update_state(|s| s.remove(&commitment));
                self.metrics.reconstruction_failures_total.inc();
            }
        }
    }

    /// Handles the registry of a shard subscription.
    #[inline]
    async fn handle_shard_subscription(
        &mut self,
        commitment: CodingCommitment,
        response: oneshot::Sender<()>,
    ) {
        // Answer immediately if we have our shard or the block has already
        // been reconstructed (implies that our shard arrived and was verified).
        let has_shard = self
            .state
            .get(&commitment)
            .is_some_and(|state| state.checking_data.is_some());
        let block_reconstructed = self.reconstructed_blocks.contains_key(&commitment);
        if has_shard || block_reconstructed {
            response.send_lossy(());
            return;
        }

        self.shard_subscriptions
            .entry(commitment)
            .or_default()
            .push(response);
    }

    /// Handles the registry of a block subscription.
    #[inline]
    async fn handle_block_subscription(
        &mut self,
        key: Either<CodingCommitment, B::Digest>,
        response: oneshot::Sender<Arc<CodedBlock<B, C>>>,
    ) {
        let block = match key {
            Either::Left(commitment) => self.reconstructed_blocks.get(&commitment),
            Either::Right(digest) => self
                .reconstructed_blocks
                .iter()
                .find_map(|(_, block)| (block.digest() == digest).then_some(block)),
        };

        // Answer immediately if we have the block cached.
        if let Some(block) = block {
            response.send_lossy(Arc::clone(block));
            return;
        }

        self.block_subscriptions
            .entry(key)
            .or_default()
            .push(response);
    }

    /// Notifies and cleans up any subscriptions for a valid shard.
    #[inline]
    async fn notify_shard_subscribers(&mut self, commitment: CodingCommitment) {
        if let Some(mut subscribers) = self.shard_subscriptions.remove(&commitment) {
            for subscriber in subscribers.drain(..) {
                subscriber.send_lossy(());
            }
        }
    }

    /// Notifies and cleans up any subscriptions for a reconstructed block.
    #[inline]
    async fn notify_block_subscribers(&mut self, block: Arc<CodedBlock<B, C>>) {
        let commitment = block.commitment();
        let digest = block.digest();

        // Notify by-commitment subscribers.
        if let Some(mut subscribers) = self.block_subscriptions.remove(&Either::Left(commitment)) {
            for subscriber in subscribers.drain(..) {
                subscriber.send_lossy(Arc::clone(&block));
            }
        }

        // Notify by-digest subscribers.
        if let Some(mut subscribers) = self.block_subscriptions.remove(&Either::Right(digest)) {
            for subscriber in subscribers.drain(..) {
                subscriber.send_lossy(Arc::clone(&block));
            }
        }
    }

    /// Prunes reconstruction state entries that have not been updated within the
    /// configured TTL.
    ///
    /// This prevents unbounded state growth from Byzantine participants sending
    /// shards for fake commitments. Legitimate proposals should reconstruct within
    /// the consensus timeout, so stale entries can be safely removed.
    fn prune_stale_states(&mut self) {
        let now = self.context.current();
        let ttl = self.state_ttl;
        let before = self.state.len();
        self.update_state(|s| {
            s.retain(|_, state| {
                now.duration_since(state.last_updated)
                    .map(|elapsed| elapsed < ttl)
                    .unwrap_or(true) // Keep if clock went backwards (shouldn't happen)
            });
        });
        let pruned = before - self.state.len();
        if pruned > 0 {
            debug!(pruned, "pruned stale reconstruction states");
            self.metrics.stale_states_pruned_total.inc_by(pruned as u64);
        }
    }

    /// Prunes all blocks in the reconstructed block cache that are older than the block
    /// with the given commitment.
    fn prune_reconstructed(&mut self, commitment: CodingCommitment) {
        let Some(height) = self
            .reconstructed_blocks
            .get(&commitment)
            .map(|b| b.height())
        else {
            return;
        };

        self.update_reconstructed_blocks(|b| b.retain(|_, block| block.height() > height));
    }

    /// Updates the reconstructed blocks cache via the provided closure and then
    /// syncs the reconstructed blocks count metric.
    fn update_reconstructed_blocks<U>(
        &mut self,
        f: impl FnOnce(&mut BTreeMap<CodingCommitment, Arc<CodedBlock<B, C>>>) -> U,
    ) -> U {
        let result = f(&mut self.reconstructed_blocks);
        let _ = self
            .metrics
            .reconstructed_blocks_cache_count
            .try_set(self.reconstructed_blocks.len());
        result
    }

    /// Updates the reconstruction state via the provided closure and then
    /// syncs the reconstruction states count metric.
    fn update_state<U>(
        &mut self,
        f: impl FnOnce(&mut BTreeMap<CodingCommitment, ReconstructionState<P, C, H>>) -> U,
    ) -> U {
        let result = f(&mut self.state);
        let _ = self
            .metrics
            .reconstruction_states_count
            .try_set(self.state.len());
        result
    }
}

/// Erasure coded block reconstruction state machine.
struct ReconstructionState<P, C, H>
where
    P: PublicKey,
    C: CodingScheme,
    H: Hasher,
{
    /// The checking data for this commitment.
    checking_data: Option<C::CheckingData>,
    /// The leader of the round that this state corresponds to.
    leader: Option<P>,
    /// Strong shards buffered while the leader is unknown, keyed by sender.
    /// When the leader arrives, the leader's shard is processed and all
    /// other senders are blocked.
    pending_strong_shards: BTreeMap<P, Shard<C, H>>,
    /// Our validated weak shard, ready to broadcast to other participants.
    /// This is set when we receive and validate our own strong shard.
    own_weak_shard: Option<Shard<C, H>>,
    /// Shards that have been received prior to the checking data being available.
    pending_shards: BTreeMap<P, Shard<C, H>>,
    /// Shards that have been verified and are ready to contribute to reconstruction.
    checked_shards: Vec<C::CheckedShard>,
    /// Bitmap tracking which participant indices have contributed a valid shard.
    /// Bit at index `i` is set if participant `i` has contributed.
    contributed: BitMap,
    /// The last time this state was updated.
    last_updated: SystemTime,
}

impl<P, C, H> Default for ReconstructionState<P, C, H>
where
    P: PublicKey,
    C: CodingScheme,
    H: Hasher,
{
    fn default() -> Self {
        Self {
            checking_data: None,
            leader: None,
            pending_strong_shards: BTreeMap::new(),
            own_weak_shard: None,
            pending_shards: BTreeMap::new(),
            checked_shards: Vec::new(),
            contributed: BitMap::new(),
            last_updated: SystemTime::UNIX_EPOCH,
        }
    }
}

impl<P, C, H> ReconstructionState<P, C, H>
where
    P: PublicKey,
    C: CodingScheme,
    H: Hasher,
{
    /// Inserts a [`Shard`] into the state.
    ///
    /// ## Peer Blocking Rules
    ///
    /// The `sender` may be blocked via the provided [`Blocker`] if any of the following rules are violated:
    ///
    /// Strong shards (`CodingScheme::StrongShard`):
    /// - MUST be sent by a participant.
    /// - MUST correspond to self's index (self must be a participant).
    /// - MUST be sent by the leader (when the leader is known). Non-leader senders
    ///   are blocked.
    /// - The leader may only send ONE strong shard. Duplicates result in blocking
    ///   the sender.
    /// - MUST pass cryptographic verification via [`CodingScheme::weaken`].
    /// - If the leader is not yet known, the shard is buffered until the leader
    ///   is set via [`ExternalProposed`](super::Message::ExternalProposed).
    ///
    /// Weak shards (`CodingScheme::WeakShard`):
    /// - MUST be sent by a participant.
    /// - MUST be sent by the participant whose index matches the shard index.
    /// - MUST pass cryptographic verification via [`CodingScheme::check`].
    /// - Each participant may only contribute ONE weak shard per commitment. Duplicates
    ///   result in blocking the sender.
    #[allow(clippy::too_many_arguments)]
    pub async fn insert(
        &mut self,
        me: Option<&Participant>,
        sender: P,
        shard: Shard<C, H>,
        participants: &Set<P>,
        strategy: &impl Strategy,
        blocker: &mut impl Blocker<PublicKey = P>,
        now: SystemTime,
    ) {
        if self.contributed.is_empty() {
            self.contributed = BitMap::zeroes(participants.len() as u64);
        }

        let Some(sender_index) = participants.index(&sender) else {
            warn!(?sender, "shard sent by non-participant, blocking peer");
            blocker.block(sender).await;
            return;
        };

        if shard.is_strong() {
            self.insert_shard(me, sender, shard, strategy, blocker)
                .await;
        } else {
            self.insert_weak_shard(sender, sender_index, shard, blocker)
                .await;
        }

        self.last_updated = now;
    }

    /// Sets the leader and processes any buffered strong shards.
    ///
    /// The leader's buffered shard (if present) is verified via
    /// [`Self::verify_strong_shard`]. All other buffered senders are blocked.
    async fn set_leader(
        &mut self,
        leader: P,
        me: &Participant,
        strategy: &impl Strategy,
        blocker: &mut impl Blocker<PublicKey = P>,
    ) {
        self.leader = Some(leader.clone());

        if self.checking_data.is_some() {
            return;
        }

        let pending = std::mem::take(&mut self.pending_strong_shards);
        for (sender, shard) in pending {
            if sender == leader {
                self.contributed.set(me.get() as u64, true);
                self.verify_strong_shard(sender, shard, strategy, blocker)
                    .await;
            } else {
                warn!(
                    ?sender,
                    ?leader,
                    "buffered strong shard from non-leader, blocking peer"
                );
                blocker.block(sender).await;
            }
        }
    }

    /// Takes the validated [`Shard`] for broadcasting to other participants.
    /// Returns [`None`] if we haven't validated our own shard yet.
    pub const fn take_weak_shard(&mut self) -> Option<Shard<C, H>> {
        self.own_weak_shard.take()
    }

    /// Handles a strong shard received from the network.
    ///
    /// If the leader is not yet known, the shard is buffered. If the leader is
    /// known, the shard is validated immediately: the sender must be the leader,
    /// and the shard must pass cryptographic verification via [`CodingScheme::weaken`].
    ///
    /// # Panics
    ///
    /// Panics if `shard` is a [`DistributionShard::Weak`].
    async fn insert_shard(
        &mut self,
        me: Option<&Participant>,
        sender: P,
        shard: Shard<C, H>,
        strategy: &impl Strategy,
        blocker: &mut impl Blocker<PublicKey = P>,
    ) {
        let shard_index: u16 = shard
            .index()
            .try_into()
            .expect("shard index impossibly out of bounds");

        let Some(me) = me else {
            warn!(
                ?sender,
                "strong shard sent to non-participant, blocking peer"
            );
            blocker.block(sender).await;
            return;
        };

        if shard_index != me.get() as u16 {
            warn!(
                ?sender,
                shard_index,
                expected_index = me.get() as usize,
                "strong shard index does not match self index, blocking peer"
            );
            blocker.block(sender).await;
            return;
        }

        match &self.leader {
            None => {
                // Leader unknown: buffer the shard for later processing.
                if self.pending_strong_shards.contains_key(&sender) {
                    warn!(
                        ?sender,
                        "duplicate strong shard from participant while leader unknown, blocking peer"
                    );
                    blocker.block(sender).await;
                    return;
                }
                self.pending_strong_shards.insert(sender, shard);
            }
            Some(leader) => {
                if sender != *leader {
                    warn!(
                        ?sender,
                        ?leader,
                        "strong shard from non-leader, blocking peer"
                    );
                    blocker.block(sender).await;
                    return;
                }
                if self.contributed.get(me.get() as u64) {
                    warn!(?sender, "duplicate strong shard from leader, blocking peer");
                    blocker.block(sender).await;
                    return;
                }
                self.contributed.set(me.get() as u64, true);
                self.verify_strong_shard(sender, shard, strategy, blocker)
                    .await;
            }
        }
    }

    /// Cryptographically verifies a strong shard and, if valid, stores the
    /// checking data and drains any pending weak shards.
    ///
    /// The caller is responsible for ensuring the sender is the leader.
    ///
    /// # Panics
    ///
    /// Panics if `shard` is a [`DistributionShard::Weak`].
    async fn verify_strong_shard(
        &mut self,
        sender: P,
        shard: Shard<C, H>,
        strategy: &impl Strategy,
        blocker: &mut impl Blocker<PublicKey = P>,
    ) {
        let commitment = shard.commitment();
        let shard_index = shard
            .index()
            .try_into()
            .expect("shard index impossibly out of bounds");

        let DistributionShard::Strong(shard_data) = shard.into_inner() else {
            panic!("verify_strong_shard called with non-strong shard");
        };

        let Ok((checking_data, checked, weak_shard_data)) = C::weaken(
            &commitment.config(),
            &commitment.coding_digest(),
            shard_index,
            shard_data,
        ) else {
            warn!(?sender, "invalid strong shard received, blocking peer");
            blocker.block(sender).await;
            return;
        };

        self.checking_data = Some(checking_data);
        self.checked_shards.push(checked);
        self.own_weak_shard = Some(Shard::new(
            commitment,
            shard_index as usize,
            DistributionShard::Weak(weak_shard_data),
        ));

        // Drain pending weak shards now that we have checking data.
        self.drain_pending(commitment, strategy, blocker).await;
    }

    /// Inserts a weak shard into the state.
    ///
    /// The caller must have already checked (and set) the sender's `contributed`
    /// bit via [`Self::insert`]. This method validates the shard's index and
    /// cryptographic integrity.
    ///
    /// # Panics
    ///
    /// Panics if `shard` is a [`DistributionShard::Strong`].
    async fn insert_weak_shard(
        &mut self,
        sender: P,
        sender_index: Participant,
        shard: Shard<C, H>,
        blocker: &mut impl Blocker<PublicKey = P>,
    ) {
        let commitment = shard.commitment();
        let shard_index: u16 = shard
            .index()
            .try_into()
            .expect("shard index impossibly out of bounds");

        if self.contributed.get(sender_index.get() as u64) {
            warn!(
                ?sender,
                "duplicate weak shard from participant, blocking peer"
            );
            blocker.block(sender).await;
            return;
        }
        self.contributed.set(sender_index.get() as u64, true);

        if shard_index != sender_index.get() as u16 {
            warn!(
                ?sender,
                shard_index,
                expected_index = sender_index.get() as usize,
                "weak shard index does not match participant index, blocking peer"
            );
            blocker.block(sender).await;
            return;
        }

        let Some(checking_data) = &self.checking_data else {
            self.pending_shards.insert(sender, shard);
            return;
        };

        let DistributionShard::Weak(shard_data) = shard.into_inner() else {
            panic!("insert_weak_shard called with strong shard");
        };
        let Ok(checked) = C::check(
            &commitment.config(),
            &commitment.coding_digest(),
            checking_data,
            shard_index,
            shard_data,
        ) else {
            warn!(?sender, "invalid shard received, blocking peer");
            blocker.block(sender).await;
            return;
        };

        self.checked_shards.push(checked);
    }

    /// Attempts to drain any pending shards if the checking data is available, using
    /// the provided [`Strategy`] for parallelization.
    ///
    /// Invalid shards will result in the sender being blocked via the provided [`Blocker`].
    async fn drain_pending(
        &mut self,
        commitment: CodingCommitment,
        strategy: &impl Strategy,
        blocker: &mut impl Blocker<PublicKey = P>,
    ) {
        // We can only drain pending shards if we have the checking data.
        let Some(checking_data) = &self.checking_data else {
            return;
        };

        // Run through the pending shards and attempt to validate them.
        let pending_shards = std::mem::take(&mut self.pending_shards);
        let (checked_shards, to_block) =
            strategy.map_partition_collect_vec(pending_shards, |(peer, shard)| {
                let shard_index = shard
                    .index()
                    .try_into()
                    .expect("shard index impossibly out of bounds");
                let DistributionShard::Weak(shard_data) = shard.into_inner() else {
                    // Strong shards should have been validated upon receipt.
                    return (peer, None);
                };

                let checked = C::check(
                    &commitment.config(),
                    &commitment.coding_digest(),
                    checking_data,
                    shard_index,
                    shard_data,
                );
                (peer, checked.ok())
            });

        // Block any peers that sent invalid shards.
        for peer in to_block {
            warn!(?peer, "invalid shard received, blocking peer");
            blocker.block(peer).await;
        }

        // Add valid shards.
        for checked in checked_shards {
            self.checked_shards.push(checked);
        }
    }
}

/// A background receiver that wraps a [`WrappedReceiver`] and decodes messages using a [`Codec`]
/// in a separate task.
///
/// This is particularly useful for situations where decoding large messages introduces pressure
/// on an event loop that uses [`WrappedReceiver`], such as in the shard engine.
struct WrappedBackgroundReceiver<E, P, B, R, V>
where
    E: Spawner,
    P: PublicKey,
    B: Blocker<PublicKey = P>,
    R: Receiver<PublicKey = P>,
    V: Codec + Send,
{
    context: ContextCell<E>,
    receiver: WrappedReceiver<R, V>,
    blocker: B,
    sender: mpsc::Sender<(P, V)>,
}

impl<E, P, B, R, V> WrappedBackgroundReceiver<E, P, B, R, V>
where
    E: Spawner,
    P: PublicKey,
    B: Blocker<PublicKey = P>,
    R: Receiver<PublicKey = P>,
    V: Codec + Send + 'static,
{
    /// Create a new [`WrappedBackgroundReceiver`] with the given receiver and blocker.
    pub fn new(
        context: E,
        receiver: WrappedReceiver<R, V>,
        blocker: B,
    ) -> (Self, mpsc::Receiver<(P, V)>) {
        let (tx, rx) = mpsc::channel(1024);
        (
            Self {
                context: ContextCell::new(context),
                receiver,
                blocker,
                sender: tx,
            },
            rx,
        )
    }

    /// Start the background receiver.
    ///
    /// Returns a [`Handle`] that must be kept alive for the background receiver to continue
    /// running. Dropping the handle will abort the background receiver.
    pub fn start(mut self) -> Handle<()> {
        spawn_cell!(self.context, self.run().await)
    }

    /// Run the background receiver's event loop.
    async fn run(mut self) {
        select_loop! {
            self.context,
            on_stopped => {
                debug!("wrapped background receiver received shutdown signal, stopping");
            },
            Ok((peer, value)) = self.receiver.recv() else {
                debug!("wrapped background receiver closed, stopping");
                return;
            } => {
                let value = match value {
                    Ok(value) => value,
                    Err(err) => {
                        warn!(?peer, ?err, "received invalid message, blocking peer");
                        self.blocker.block(peer).await;
                        continue;
                    }
                };

                let _ = self.sender.send((peer, value)).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        marshal::{
            coding::types::coding_config_for_participants, mocks::block::Block as MockBlock,
        },
        types::Height,
    };
    use bytes::Bytes;
    use commonware_codec::Encode;
    use commonware_coding::{CodecConfig, Config as CodingConfig, ReedSolomon};
    use commonware_cryptography::{
        ed25519::{PrivateKey, PublicKey},
        sha256::Digest as Sha256Digest,
        Committable, Digest, Sha256, Signer,
    };
    use commonware_macros::{select, test_traced};
    use commonware_p2p::simulated::{self, Control, Link, Oracle};
    use commonware_parallel::Sequential;
    use commonware_runtime::{deterministic, Quota, Runner};
    use commonware_utils::{channel::oneshot::error::TryRecvError, ordered::Set, Participant};
    use std::{future::Future, num::NonZeroU32, time::Duration};

    /// The max size of a shard sent over the wire.
    const MAX_SHARD_SIZE: usize = 1024 * 1024; // 1 MiB

    /// The default link configuration for tests.
    const DEFAULT_LINK: Link = Link {
        latency: Duration::from_millis(50),
        jitter: Duration::ZERO,
        success_rate: 1.0,
    };

    /// Rate limit quota for tests (effectively unlimited).
    const TEST_QUOTA: Quota = Quota::per_second(NonZeroU32::MAX);

    /// The parallelization strategy used for tests.
    const STRATEGY: Sequential = Sequential;

    /// Default state TTL for tests (30 seconds).
    const DEFAULT_STATE_TTL: Duration = Duration::from_secs(30);

    // Type aliases for test convenience.
    type B = MockBlock<Sha256Digest, ()>;
    type H = Sha256;
    type P = PublicKey;
    type C = ReedSolomon<H>;
    type X = Control<P, deterministic::Context>;
    type O = Oracle<P, deterministic::Context>;
    type NetworkSender = simulated::Sender<P, deterministic::Context>;
    type ShardEngine = Engine<deterministic::Context, X, C, H, B, P, Sequential>;
    type ShardMailbox = Mailbox<B, C, P>;

    async fn assert_blocked(oracle: &O, blocker: &P, blocked: &P) {
        let blocked_peers = oracle.blocked().await.unwrap();
        let is_blocked = blocked_peers
            .iter()
            .any(|(a, b)| a == blocker && b == blocked);
        assert!(is_blocked, "expected {blocker} to have blocked {blocked}");
    }

    /// A participant in the test network with its engine mailbox and blocker.
    struct Peer {
        /// The peer's public key.
        public_key: PublicKey,
        /// The peer's index in the participant set.
        index: Participant,
        /// The mailbox for sending messages to the peer's shard engine.
        mailbox: ShardMailbox,
        /// Raw network sender for injecting messages (e.g., byzantine behavior).
        sender: NetworkSender,
    }

    /// Test fixture for setting up multiple participants with shard engines.
    struct Fixture {
        /// Number of peers in the test network.
        num_peers: usize,
        /// Network link configuration.
        link: Link,
        /// State TTL for reconstruction state entries.
        state_ttl: Duration,
    }

    impl Default for Fixture {
        fn default() -> Self {
            Self {
                num_peers: 4,
                link: DEFAULT_LINK,
                state_ttl: DEFAULT_STATE_TTL,
            }
        }
    }

    impl Fixture {
        pub fn start<F: Future<Output = ()>>(
            self,
            f: impl FnOnce(Self, deterministic::Context, O, Vec<Peer>, CodingConfig) -> F,
        ) {
            let executor = deterministic::Runner::default();
            executor.start(|context| async move {
                let (network, oracle) = simulated::Network::<deterministic::Context, P>::new(
                    context.with_label("network"),
                    simulated::Config {
                        max_size: MAX_SHARD_SIZE as u32,
                        disconnect_on_block: true,
                        tracked_peer_sets: None,
                    },
                );
                network.start();

                let mut schemes = (0..self.num_peers)
                    .map(|i| PrivateKey::from_seed(i as u64))
                    .collect::<Vec<_>>();
                schemes.sort_by_key(|s| s.public_key());
                let peer_keys: Vec<P> = schemes.iter().map(|c| c.public_key()).collect();

                let participants: Set<P> = Set::from_iter_dedup(peer_keys.clone());

                let mut registrations = BTreeMap::new();
                for peer in peer_keys.iter() {
                    let control = oracle.control(peer.clone());
                    let (sender, receiver) = control
                        .register(0, TEST_QUOTA)
                        .await
                        .expect("registration should succeed");
                    registrations.insert(peer.clone(), (control, sender, receiver));
                }
                for p1 in peer_keys.iter() {
                    for p2 in peer_keys.iter() {
                        if p2 == p1 {
                            continue;
                        }
                        oracle
                            .add_link(p1.clone(), p2.clone(), self.link.clone())
                            .await
                            .expect("link should be added");
                    }
                }

                let coding_config =
                    coding_config_for_participants(u16::try_from(self.num_peers).unwrap());

                let mut peers = Vec::with_capacity(self.num_peers);
                for (idx, peer_key) in peer_keys.iter().enumerate() {
                    let (control, sender, receiver) = registrations
                        .remove(peer_key)
                        .expect("peer should be registered");

                    let participant = Participant::new(idx as u32);
                    let engine_context = context.with_label(&format!("peer_{}", idx));

                    let config = Config {
                        me: Some(participant),
                        participants: participants.clone(),
                        blocker: control.clone(),
                        shard_codec_cfg: CodecConfig {
                            maximum_shard_size: MAX_SHARD_SIZE,
                        },
                        block_codec_cfg: (),
                        strategy: STRATEGY,
                        mailbox_size: 1024,
                        state_ttl: self.state_ttl,
                    };

                    let (engine, mailbox) = ShardEngine::new(engine_context, config);
                    let sender_clone = sender.clone();
                    engine.start((sender, receiver));

                    peers.push(Peer {
                        public_key: peer_key.clone(),
                        index: participant,
                        mailbox,
                        sender: sender_clone,
                    });
                }

                f(self, context, oracle, peers, coding_config).await;
            });
        }
    }

    #[test_traced]
    fn test_e2e_broadcast_and_reconstruction() {
        let fixture = Fixture {
            num_peers: 10,
            ..Default::default()
        };

        fixture.start(|config, context, _, mut peers, coding_config| async move {
            let inner = B::new::<H>((), Sha256Digest::EMPTY, Height::new(1), 100);
            let coded_block = CodedBlock::<B, C>::new(inner, coding_config, &STRATEGY);
            let commitment = coded_block.commitment();

            let leader = peers[0].public_key.clone();
            peers[0].mailbox.proposed(coded_block.clone()).await;

            // Inform all peers of the leader so strong shards are processed.
            for peer in peers[1..].iter_mut() {
                peer.mailbox
                    .external_proposed(commitment, leader.clone())
                    .await;
            }
            context.sleep(config.link.latency).await;

            for peer in peers.iter_mut() {
                peer.mailbox
                    .subscribe_shard(commitment)
                    .await
                    .await
                    .expect("shard subscription should complete");
            }
            context.sleep(config.link.latency).await;

            for peer in peers.iter_mut() {
                let reconstructed = peer
                    .mailbox
                    .get(commitment)
                    .await
                    .expect("block should be reconstructed");
                assert_eq!(reconstructed.commitment(), commitment);
                assert_eq!(reconstructed.height(), coded_block.height());
            }
        });
    }

    #[test_traced]
    fn test_block_subscriptions() {
        let fixture = Fixture {
            num_peers: 10,
            ..Default::default()
        };

        fixture.start(|config, context, _, mut peers, coding_config| async move {
            let inner = B::new::<H>((), Sha256Digest::EMPTY, Height::new(1), 100);
            let coded_block = CodedBlock::<B, C>::new(inner, coding_config, &STRATEGY);
            let commitment = coded_block.commitment();
            let digest = coded_block.digest();

            let leader = peers[0].public_key.clone();

            // Subscribe before broadcasting.
            let commitment_sub = peers[1].mailbox.subscribe_block(commitment).await;
            let digest_sub = peers[2].mailbox.subscribe_block_by_digest(digest).await;

            peers[0].mailbox.proposed(coded_block.clone()).await;

            // Inform all peers of the leader so strong shards are processed.
            for peer in peers[1..].iter_mut() {
                peer.mailbox
                    .external_proposed(commitment, leader.clone())
                    .await;
            }
            context.sleep(config.link.latency * 2).await;

            for peer in peers.iter_mut() {
                peer.mailbox
                    .subscribe_shard(commitment)
                    .await
                    .await
                    .expect("shard subscription should complete");
            }
            context.sleep(config.link.latency).await;

            let block_by_commitment = commitment_sub.await.expect("subscription should resolve");
            assert_eq!(block_by_commitment.commitment(), commitment);
            assert_eq!(block_by_commitment.height(), coded_block.height());

            let block_by_digest = digest_sub.await.expect("subscription should resolve");
            assert_eq!(block_by_digest.commitment(), commitment);
            assert_eq!(block_by_digest.height(), coded_block.height());
        });
    }

    #[test_traced]
    fn test_shard_subscription_rejects_invalid_shard() {
        let fixture = Fixture {
            ..Default::default()
        };

        fixture.start(
            |config, context, oracle, mut peers, coding_config| async move {
                // peers[0] = byzantine
                // peers[1] = honest proposer
                // peers[2] = receiver

                let inner = B::new::<H>((), Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block = CodedBlock::<B, C>::new(inner, coding_config, &STRATEGY);
                let commitment = coded_block.commitment();
                let receiver_index = peers[2].index.get() as usize;

                let valid_shard = coded_block
                    .shard::<H>(receiver_index)
                    .expect("missing shard");

                // corrupt the shard's index
                let mut invalid_shard = valid_shard.clone();
                invalid_shard.index = 0;

                // Receiver subscribes to their shard and learns the leader.
                let receiver_pk = peers[2].public_key.clone();
                let leader = peers[1].public_key.clone();
                peers[2].mailbox.external_proposed(commitment, leader).await;
                let mut shard_sub = peers[2].mailbox.subscribe_shard(commitment).await;

                // Byzantine peer sends the invalid shard.
                let invalid_bytes = invalid_shard.encode();
                peers[0]
                    .sender
                    .send(Recipients::One(receiver_pk.clone()), invalid_bytes, true)
                    .await
                    .expect("send failed");

                context.sleep(config.link.latency * 2).await;

                assert!(
                    matches!(shard_sub.try_recv(), Err(TryRecvError::Empty)),
                    "subscription should not resolve from invalid shard"
                );
                assert_blocked(&oracle, &peers[2].public_key, &peers[0].public_key).await;

                // Honest proposer sends the valid shard.
                let valid_bytes = valid_shard.encode();
                peers[1]
                    .sender
                    .send(Recipients::One(receiver_pk), valid_bytes, true)
                    .await
                    .expect("send failed");
                context.sleep(config.link.latency * 2).await;

                // Subscription should now resolve.
                select! {
                    _ = shard_sub => {},
                    _ = context.sleep(Duration::from_secs(5)) => {
                        panic!("subscription did not complete after valid shard arrival");
                    }
                };
            },
        );
    }

    #[test_traced]
    fn test_durable_prunes_reconstructed_blocks() {
        let fixture = Fixture {
            ..Default::default()
        };

        fixture.start(|_, context, _, mut peers, coding_config| async move {
            // Create 3 blocks at heights 1, 2, 3.
            let block1 = CodedBlock::<B, C>::new(
                B::new::<H>((), Sha256Digest::EMPTY, Height::new(1), 100),
                coding_config,
                &STRATEGY,
            );
            let block2 = CodedBlock::<B, C>::new(
                B::new::<H>((), Sha256Digest::EMPTY, Height::new(2), 100),
                coding_config,
                &STRATEGY,
            );
            let block3 = CodedBlock::<B, C>::new(
                B::new::<H>((), Sha256Digest::EMPTY, Height::new(3), 100),
                coding_config,
                &STRATEGY,
            );
            let commitment1 = block1.commitment();
            let commitment2 = block2.commitment();
            let commitment3 = block3.commitment();

            // Cache all blocks via `proposed`.
            let peer = &mut peers[0];
            peer.mailbox.proposed(block1).await;
            peer.mailbox.proposed(block2).await;
            peer.mailbox.proposed(block3).await;
            context.sleep(Duration::from_millis(10)).await;

            // Verify all blocks are in the cache.
            assert!(
                peer.mailbox.get(commitment1).await.is_some(),
                "block1 should be cached"
            );
            assert!(
                peer.mailbox.get(commitment2).await.is_some(),
                "block2 should be cached"
            );
            assert!(
                peer.mailbox.get(commitment3).await.is_some(),
                "block3 should be cached"
            );

            // Prune at height 2 (blocks with height <= 2 should be removed).
            peer.mailbox.durable(commitment2).await;
            context.sleep(Duration::from_millis(10)).await;

            // Blocks at heights 1 and 2 should be pruned.
            assert!(
                peer.mailbox.get(commitment1).await.is_none(),
                "block1 should be pruned"
            );
            assert!(
                peer.mailbox.get(commitment2).await.is_none(),
                "block2 should be pruned"
            );

            // Block at height 3 should still be cached.
            assert!(
                peer.mailbox.get(commitment3).await.is_some(),
                "block3 should still be cached"
            );
        });
    }

    #[test_traced]
    fn test_duplicate_leader_strong_shard_blocked() {
        let fixture = Fixture {
            ..Default::default()
        };

        fixture.start(
            |config, context, oracle, mut peers, coding_config| async move {
                let inner = B::new::<H>((), Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block = CodedBlock::<B, C>::new(inner, coding_config, &STRATEGY);
                let commitment = coded_block.commitment();

                // Get peer 2's strong shard.
                let peer2_index = peers[2].index.get() as usize;
                let peer2_strong_shard =
                    coded_block.shard::<H>(peer2_index).expect("missing shard");
                let strong_bytes = peer2_strong_shard.encode();

                let peer2_pk = peers[2].public_key.clone();
                let leader = peers[0].public_key.clone();

                // Inform peer 2 that peer 0 is the leader.
                peers[2].mailbox.external_proposed(commitment, leader).await;

                // Send peer 2 their strong shard from peer 0 (leader, first time - should succeed).
                peers[0]
                    .sender
                    .send(
                        Recipients::One(peer2_pk.clone()),
                        strong_bytes.clone(),
                        true,
                    )
                    .await
                    .expect("send failed");
                context.sleep(config.link.latency * 2).await;

                // Send the same strong shard again from peer 0 (leader duplicate - blocked).
                peers[0]
                    .sender
                    .send(Recipients::One(peer2_pk), strong_bytes, true)
                    .await
                    .expect("send failed");
                context.sleep(config.link.latency * 2).await;

                // The leader's duplicate strong shard should result in blocking.
                assert_blocked(&oracle, &peers[2].public_key, &peers[0].public_key).await;
            },
        );
    }

    #[test_traced]
    fn test_non_leader_strong_shard_blocked() {
        // Test that a non-leader sending a strong shard is blocked.
        let fixture = Fixture {
            ..Default::default()
        };

        fixture.start(
            |config, context, oracle, mut peers, coding_config| async move {
                let inner = B::new::<H>((), Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block = CodedBlock::<B, C>::new(inner, coding_config, &STRATEGY);
                let commitment = coded_block.commitment();

                // Get peer 2's strong shard.
                let peer2_index = peers[2].index.get() as usize;
                let peer2_strong_shard =
                    coded_block.shard::<H>(peer2_index).expect("missing shard");
                let strong_bytes = peer2_strong_shard.encode();

                let peer2_pk = peers[2].public_key.clone();
                let leader = peers[0].public_key.clone();

                // Inform peer 2 that peer 0 is the leader.
                peers[2].mailbox.external_proposed(commitment, leader).await;

                // Peer 1 (not the leader) sends peer 2 their strong shard.
                peers[1]
                    .sender
                    .send(Recipients::One(peer2_pk), strong_bytes, true)
                    .await
                    .expect("send failed");
                context.sleep(config.link.latency * 2).await;

                // Peer 1 should be blocked by peer 2 for being a non-leader.
                assert_blocked(&oracle, &peers[2].public_key, &peers[1].public_key).await;
            },
        );
    }

    #[test_traced]
    fn test_buffered_non_leader_blocked_on_leader_arrival() {
        // Test that when a non-leader's strong shard is buffered (leader unknown)
        // and then the leader arrives, the non-leader is blocked.
        let fixture = Fixture {
            ..Default::default()
        };

        fixture.start(
            |config, context, oracle, mut peers, coding_config| async move {
                let inner = B::new::<H>((), Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block = CodedBlock::<B, C>::new(inner, coding_config, &STRATEGY);
                let commitment = coded_block.commitment();

                // Get peer 2's strong shard.
                let peer2_index = peers[2].index.get() as usize;
                let peer2_strong_shard =
                    coded_block.shard::<H>(peer2_index).expect("missing shard");
                let strong_bytes = peer2_strong_shard.encode();

                let peer2_pk = peers[2].public_key.clone();

                // Peer 1 sends the strong shard before the leader is known (buffered).
                peers[1]
                    .sender
                    .send(Recipients::One(peer2_pk), strong_bytes, true)
                    .await
                    .expect("send failed");
                context.sleep(config.link.latency * 2).await;

                // Nobody should be blocked yet (shard is buffered, leader unknown).
                let blocked = oracle.blocked().await.unwrap();
                assert!(
                    blocked.is_empty(),
                    "no peers should be blocked while leader is unknown"
                );

                // Now inform peer 2 that peer 0 is the leader.
                // This drains the buffer: peer 1's shard is from a non-leader, so
                // peer 1 should be blocked.
                let leader = peers[0].public_key.clone();
                peers[2].mailbox.external_proposed(commitment, leader).await;
                context.sleep(Duration::from_millis(10)).await;

                assert_blocked(&oracle, &peers[2].public_key, &peers[1].public_key).await;
            },
        );
    }

    #[test_traced]
    fn test_duplicate_weak_shard_blocks_peer() {
        // Use 10 peers so minimum_shards=4, giving us time to send duplicate before reconstruction.
        let fixture = Fixture {
            num_peers: 10,
            ..Default::default()
        };

        fixture.start(
            |config, context, oracle, mut peers, coding_config| async move {
                let inner = B::new::<H>((), Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block = CodedBlock::<B, C>::new(inner, coding_config, &STRATEGY);

                // Get peer 2's strong shard (to initialize their checking_data).
                let peer2_index = peers[2].index.get() as usize;
                let peer2_strong_shard =
                    coded_block.shard::<H>(peer2_index).expect("missing shard");

                // Get peer 1's weak shard.
                let peer1_index = peers[1].index.get() as usize;
                let peer1_strong_shard =
                    coded_block.shard::<H>(peer1_index).expect("missing shard");
                let peer1_weak_shard = peer1_strong_shard
                    .verify_into_weak()
                    .expect("verify_into_weak failed");

                let peer2_pk = peers[2].public_key.clone();
                let leader = peers[0].public_key.clone();

                // Inform peer 2 of the leader.
                peers[2]
                    .mailbox
                    .external_proposed(coded_block.commitment(), leader)
                    .await;

                // Send peer 2 their strong shard (initializes checking_data, 1 checked shard).
                let strong_bytes = peer2_strong_shard.encode();
                peers[0]
                    .sender
                    .send(Recipients::One(peer2_pk.clone()), strong_bytes, true)
                    .await
                    .expect("send failed");
                context.sleep(config.link.latency * 2).await;

                // Send peer 1's weak shard to peer 2 (first time - should succeed, 2 checked shards).
                let weak_shard_bytes = peer1_weak_shard.encode();
                peers[1]
                    .sender
                    .send(
                        Recipients::One(peer2_pk.clone()),
                        weak_shard_bytes.clone(),
                        true,
                    )
                    .await
                    .expect("send failed");
                context.sleep(config.link.latency * 2).await;

                // Send peer 1's weak shard to peer 2 again (duplicate - should block).
                // With 10 peers, minimum_shards=4, so we haven't reconstructed yet.
                peers[1]
                    .sender
                    .send(Recipients::One(peer2_pk), weak_shard_bytes, true)
                    .await
                    .expect("send failed");
                context.sleep(config.link.latency * 2).await;

                // Peer 2 should have blocked peer 1 for sending a duplicate weak shard.
                assert_blocked(&oracle, &peers[2].public_key, &peers[1].public_key).await;
            },
        );
    }

    #[test_traced]
    fn test_stale_reconstruction_state_pruned_after_ttl() {
        // Use a short TTL for testing.
        let state_ttl = Duration::from_secs(1);
        // Use 10 peers so minimum_shards=4, preventing early reconstruction.
        let fixture = Fixture {
            num_peers: 10,
            state_ttl,
            ..Default::default()
        };

        fixture.start(
            |config, context, oracle, mut peers, coding_config| async move {
                let inner = B::new::<H>((), Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block = CodedBlock::<B, C>::new(inner, coding_config, &STRATEGY);

                // Get peer 2's strong shard (to initialize their checking_data).
                let peer2_index = peers[2].index.get() as usize;
                let peer2_strong_shard =
                    coded_block.shard::<H>(peer2_index).expect("missing shard");

                // Get peer 1's weak shard.
                let peer1_index = peers[1].index.get() as usize;
                let peer1_strong_shard =
                    coded_block.shard::<H>(peer1_index).expect("missing shard");
                let peer1_weak_shard = peer1_strong_shard
                    .verify_into_weak()
                    .expect("verify_into_weak failed");

                let peer2_pk = peers[2].public_key.clone();

                // Send peer 2 their strong shard (initializes checking_data).
                let strong_bytes = peer2_strong_shard.encode();
                peers[0]
                    .sender
                    .send(Recipients::One(peer2_pk.clone()), strong_bytes, true)
                    .await
                    .expect("send failed");
                context.sleep(config.link.latency * 2).await;

                // Send peer 1's weak shard to peer 2 (first time - should succeed).
                let weak_shard_bytes = peer1_weak_shard.encode();
                peers[1]
                    .sender
                    .send(
                        Recipients::One(peer2_pk.clone()),
                        weak_shard_bytes.clone(),
                        true,
                    )
                    .await
                    .expect("send failed");
                context.sleep(config.link.latency * 2).await;

                // Verify no one is blocked yet.
                let blocked = oracle.blocked().await.unwrap();
                assert!(blocked.is_empty(), "no peers should be blocked yet");

                // Advance time past the TTL to trigger pruning of stale state.
                context
                    .sleep(config.state_ttl + Duration::from_millis(100))
                    .await;

                // Trigger the select loop by sending a message that will be processed.
                // The on_start handler will prune stale states before processing.
                // After pruning, the reconstruction state (including contributed bitmap)
                // is gone, so sending the same weak shard again should NOT block peer 1.
                peers[1].mailbox.get(coded_block.commitment()).await;
                context.sleep(config.link.latency * 2).await;
                peers[1]
                    .sender
                    .send(Recipients::One(peer2_pk), weak_shard_bytes, true)
                    .await
                    .expect("send failed");

                // If state was pruned, the weak shard is treated as new (not duplicate),
                // so peer 1 should NOT be blocked.
                let blocked_after_ttl = oracle.blocked().await.unwrap();
                assert!(
                    blocked_after_ttl.is_empty(),
                    "peer 1 should not be blocked after state was pruned by TTL"
                );
            },
        );
    }

    #[test_traced]
    fn test_drain_pending_validates_weak_shards_after_strong_shard() {
        // Test that weak shards arriving BEFORE the strong shard are validated
        // via drain_pending once the strong shard arrives, enabling reconstruction.
        //
        // With 10 peers: minimum_shards = (10-1)/3 + 1 = 4
        // We send 3 pending weak shards + 1 strong shard = 4 shards -> reconstruction.
        let fixture = Fixture {
            num_peers: 10,
            ..Default::default()
        };

        fixture.start(
            |config, context, oracle, mut peers, coding_config| async move {
                let inner = B::new::<H>((), Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block = CodedBlock::<B, C>::new(inner, coding_config, &STRATEGY);
                let commitment = coded_block.commitment();

                // Get peer 3's strong shard.
                let peer3_index = peers[3].index.get() as usize;
                let peer3_strong_shard =
                    coded_block.shard::<H>(peer3_index).expect("missing shard");

                // Get weak shards from peers 0, 1, and 2 (3 total to meet minimum_shards=4).
                let weak_shards: Vec<_> = [0, 1, 2]
                    .iter()
                    .map(|&i| {
                        coded_block
                            .shard::<H>(peers[i].index.get() as usize)
                            .expect("missing shard")
                            .verify_into_weak()
                            .expect("verify_into_weak failed")
                    })
                    .collect();

                let peer3_pk = peers[3].public_key.clone();

                // Send weak shards to peer 3 BEFORE their strong shard arrives.
                // These will be stored in pending_shards since there's no checking data yet.
                for (i, weak_shard) in weak_shards.iter().enumerate() {
                    let sender_idx = [0, 1, 2][i];
                    let weak_shard_bytes = weak_shard.encode();
                    peers[sender_idx]
                        .sender
                        .send(Recipients::One(peer3_pk.clone()), weak_shard_bytes, true)
                        .await
                        .expect("send failed");
                }

                context.sleep(config.link.latency * 2).await;

                // Block should not be reconstructed yet (no checking data from strong shard).
                let block = peers[3].mailbox.get(commitment).await;
                assert!(block.is_none(), "block should not be reconstructed yet");

                // Inform peer 3 that peer 2 is the leader.
                let leader = peers[2].public_key.clone();
                peers[3].mailbox.external_proposed(commitment, leader).await;

                // Now send peer 2's strong shard. This should:
                // 1. Provide checking data
                // 2. Trigger drain_pending which validates the 3 pending weak shards
                // 3. With 4 checked shards (1 strong + 3 from pending), trigger reconstruction
                let strong_bytes = peer3_strong_shard.encode();
                peers[2]
                    .sender
                    .send(Recipients::One(peer3_pk), strong_bytes, true)
                    .await
                    .expect("send failed");

                context.sleep(config.link.latency * 2).await;

                // No peers should be blocked (all weak shards were valid).
                let blocked = oracle.blocked().await.unwrap();
                assert!(
                    blocked.is_empty(),
                    "no peers should be blocked for valid pending weak shards"
                );

                // Block should now be reconstructed (4 checked shards >= minimum_shards).
                let block = peers[3].mailbox.get(commitment).await;
                assert!(
                    block.is_some(),
                    "block should be reconstructed after drain_pending"
                );

                // Verify the reconstructed block has the correct commitment.
                let reconstructed = block.unwrap();
                assert_eq!(
                    reconstructed.commitment(),
                    commitment,
                    "reconstructed block should have correct commitment"
                );
            },
        );
    }

    #[test_traced]
    fn test_update_participants_clears_state() {
        // Test that UpdateParticipants clears reconstruction state and subscriptions.
        let fixture = Fixture {
            num_peers: 5,
            ..Default::default()
        };

        fixture.start(
            |config, context, oracle, mut peers, coding_config| async move {
                let inner = B::new::<H>((), Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block = CodedBlock::<B, C>::new(inner, coding_config, &STRATEGY);
                let commitment = coded_block.commitment();

                // Send some shards to peer 0 to create reconstruction state.
                let peer0_pk = peers[0].public_key.clone();
                for peer in peers[1..3].iter_mut() {
                    let weak_shard = coded_block
                        .shard::<H>(peer.index.get() as usize)
                        .expect("missing shard")
                        .verify_into_weak()
                        .expect("verify_into_weak failed");
                    let weak_shard_bytes = weak_shard.encode();
                    peer
                        .sender
                        .send(Recipients::One(peer0_pk.clone()), weak_shard_bytes, true)
                        .await
                        .expect("send failed");
                }
                context.sleep(config.link.latency * 2).await;

                // Create a subscription that should be cleared.
                let sub = peers[0].mailbox.subscribe_block(commitment).await;

                // Send UpdateParticipants to clear state.
                // Use a new participant set (same keys, just triggers the clear).
                let new_participants: Set<P> =
                    Set::from_iter_dedup(peers.iter().map(|p| p.public_key.clone()));
                peers[0]
                    .mailbox
                    .update_participants(peer0_pk.clone(), new_participants)
                    .await;

                // Give time for the message to be processed.
                context.sleep(Duration::from_millis(10)).await;

                // The subscription should now be dropped (sender closed).
                // Try to await it with a timeout - it should not resolve with a block.
                select! {
                    result = sub => {
                        // If we get a result, it should be an error (subscription was dropped).
                        assert!(result.is_err(), "subscription should be cleared after UpdateParticipants");
                    },
                    _ = context.sleep(Duration::from_millis(100)) => {
                        // Timeout is also acceptable - subscription was cleared.
                    }
                }

                // Now send the same shards again - they should be treated as new
                // (state was cleared), not duplicates.
                for peer in peers[1..3].iter_mut() {
                    let weak_shard = coded_block
                        .shard::<H>(peer.index.get() as usize)
                        .expect("missing shard")
                        .verify_into_weak()
                        .expect("verify_into_weak failed");
                    let weak_shard_bytes = weak_shard.encode();
                    peer
                        .sender
                        .send(Recipients::One(peer0_pk.clone()), weak_shard_bytes, true)
                        .await
                        .expect("send failed");
                }
                context.sleep(config.link.latency * 2).await;

                // No peers should be blocked (shards treated as new after state clear).
                let blocked = oracle.blocked().await.unwrap();
                assert!(
                    blocked.is_empty(),
                    "no peers should be blocked after UpdateParticipants cleared state"
                );
            },
        );
    }

    #[test_traced]
    fn test_invalid_shard_codec_blocks_peer() {
        // Test that receiving an invalid shard (codec failure) blocks the sender.
        let fixture = Fixture {
            num_peers: 4,
            ..Default::default()
        };

        fixture.start(
            |config, context, oracle, mut peers, _coding_config| async move {
                let peer0_pk = peers[0].public_key.clone();
                let peer1_pk = peers[1].public_key.clone();

                // Send garbage bytes that will fail codec decoding.
                let garbage = Bytes::from(vec![0xFF, 0xFE, 0xFD, 0xFC, 0xFB]);
                peers[1]
                    .sender
                    .send(Recipients::One(peer0_pk.clone()), garbage, true)
                    .await
                    .expect("send failed");

                context.sleep(config.link.latency * 2).await;

                // Peer 1 should be blocked by peer 0 for sending invalid shard.
                assert_blocked(&oracle, &peer0_pk, &peer1_pk).await;
            },
        );
    }

    #[test_traced]
    fn test_shard_from_non_participant_blocks_peer() {
        // Test that receiving a shard from a non-participant blocks the sender.
        // We simulate this by having a peer send a shard after being removed
        // from the participant set.
        let fixture = Fixture {
            num_peers: 4,
            ..Default::default()
        };

        fixture.start(
            |config, context, oracle, mut peers, coding_config| async move {
                let inner = B::new::<H>((), Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block = CodedBlock::<B, C>::new(inner, coding_config, &STRATEGY);

                let peer0_pk = peers[0].public_key.clone();
                let peer3_pk = peers[3].public_key.clone();

                // Update participants to exclude peer 3.
                let new_participants: Set<P> =
                    Set::from_iter_dedup(peers.iter().take(3).map(|p| p.public_key.clone()));
                peers[0]
                    .mailbox
                    .update_participants(peer0_pk.clone(), new_participants)
                    .await;

                context.sleep(Duration::from_millis(10)).await;

                // Peer 3 (now non-participant) sends a shard to peer 0.
                let weak_shard = coded_block
                    .shard::<H>(peers[3].index.get() as usize)
                    .expect("missing shard")
                    .verify_into_weak()
                    .expect("verify_into_weak failed");
                let weak_shard_bytes = weak_shard.encode();
                peers[3]
                    .sender
                    .send(Recipients::One(peer0_pk.clone()), weak_shard_bytes, true)
                    .await
                    .expect("send failed");

                context.sleep(config.link.latency * 2).await;

                // Peer 3 should be blocked by peer 0 for being a non-participant.
                assert_blocked(&oracle, &peer0_pk, &peer3_pk).await;
            },
        );
    }

    #[test_traced]
    fn test_duplicate_buffered_strong_shard_blocks_peer() {
        // Test that the same peer sending two strong shards before the leader is known
        // results in the sender being blocked on the second attempt.
        let fixture = Fixture {
            ..Default::default()
        };

        fixture.start(
            |config, context, oracle, mut peers, coding_config| async move {
                let inner = B::new::<H>((), Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block = CodedBlock::<B, C>::new(inner, coding_config, &STRATEGY);

                // Get peer 2's strong shard.
                let peer2_index = peers[2].index.get() as usize;
                let peer2_strong_shard =
                    coded_block.shard::<H>(peer2_index).expect("missing shard");
                let strong_bytes = peer2_strong_shard.encode();

                let peer2_pk = peers[2].public_key.clone();

                // Do NOT set a leader — shards should be buffered.

                // Peer 1 sends the strong shard to peer 2 (buffered, leader unknown).
                peers[1]
                    .sender
                    .send(
                        Recipients::One(peer2_pk.clone()),
                        strong_bytes.clone(),
                        true,
                    )
                    .await
                    .expect("send failed");
                context.sleep(config.link.latency * 2).await;

                // No one should be blocked yet.
                let blocked = oracle.blocked().await.unwrap();
                assert!(blocked.is_empty(), "no peers should be blocked yet");

                // Peer 1 sends the same strong shard AGAIN (duplicate while leader unknown).
                peers[1]
                    .sender
                    .send(Recipients::One(peer2_pk), strong_bytes, true)
                    .await
                    .expect("send failed");
                context.sleep(config.link.latency * 2).await;

                // Peer 1 should be blocked for sending a duplicate buffered strong shard.
                assert_blocked(&oracle, &peers[2].public_key, &peers[1].public_key).await;
            },
        );
    }

    #[test_traced]
    fn test_invalid_strong_shard_crypto_blocks_leader() {
        // Test that a strong shard failing cryptographic verification (C::weaken)
        // results in the leader being blocked.
        let fixture = Fixture {
            ..Default::default()
        };

        fixture.start(
            |config, context, oracle, mut peers, coding_config| async move {
                // Create two different blocks — shard from block2 won't verify
                // against commitment from block1.
                let inner1 = B::new::<H>((), Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block1 = CodedBlock::<B, C>::new(inner1, coding_config, &STRATEGY);
                let commitment1 = coded_block1.commitment();

                let inner2 = B::new::<H>((), Sha256Digest::EMPTY, Height::new(2), 200);
                let coded_block2 = CodedBlock::<B, C>::new(inner2, coding_config, &STRATEGY);

                // Get peer 2's strong shard from block2, but re-wrap it with
                // block1's commitment so it fails C::weaken.
                let peer2_index = peers[2].index.get() as usize;
                let mut wrong_shard = coded_block2.shard::<H>(peer2_index).expect("missing shard");
                wrong_shard.commitment = commitment1;
                let wrong_bytes = wrong_shard.encode();

                let peer2_pk = peers[2].public_key.clone();
                let leader = peers[0].public_key.clone();

                // Inform peer 2 that peer 0 is the leader.
                peers[2]
                    .mailbox
                    .external_proposed(commitment1, leader)
                    .await;

                // Leader (peer 0) sends the invalid strong shard.
                peers[0]
                    .sender
                    .send(Recipients::One(peer2_pk), wrong_bytes, true)
                    .await
                    .expect("send failed");
                context.sleep(config.link.latency * 2).await;

                // Peer 0 (leader) should be blocked for invalid crypto.
                assert_blocked(&oracle, &peers[2].public_key, &peers[0].public_key).await;
            },
        );
    }

    #[test_traced]
    fn test_weak_shard_index_mismatch_blocks_peer() {
        // Test that a weak shard whose shard index doesn't match the sender's
        // participant index results in blocking the sender.
        let fixture = Fixture {
            num_peers: 10,
            ..Default::default()
        };

        fixture.start(
            |config, context, oracle, mut peers, coding_config| async move {
                let inner = B::new::<H>((), Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block = CodedBlock::<B, C>::new(inner, coding_config, &STRATEGY);
                let commitment = coded_block.commitment();

                // Get peer 2's strong shard so peer 3 can validate weak shards.
                let peer3_index = peers[3].index.get() as usize;
                let peer3_strong_shard =
                    coded_block.shard::<H>(peer3_index).expect("missing shard");

                // Get peer 1's valid weak shard, then change the index to peer 4's index.
                let peer1_index = peers[1].index.get() as usize;
                let mut wrong_index_weak_shard = coded_block
                    .shard::<H>(peer1_index)
                    .expect("missing shard")
                    .verify_into_weak()
                    .expect("verify_into_weak failed");
                // Mutate the index so it doesn't match sender (peer 1).
                wrong_index_weak_shard.index = peers[4].index.get() as usize;
                let wrong_bytes = wrong_index_weak_shard.encode();

                let peer3_pk = peers[3].public_key.clone();
                let leader = peers[0].public_key.clone();

                // Inform peer 3 of the leader and send them the strong shard.
                peers[3].mailbox.external_proposed(commitment, leader).await;
                let strong_bytes = peer3_strong_shard.encode();
                peers[0]
                    .sender
                    .send(Recipients::One(peer3_pk.clone()), strong_bytes, true)
                    .await
                    .expect("send failed");
                context.sleep(config.link.latency * 2).await;

                // Peer 1 sends a weak shard with a mismatched index to peer 3.
                peers[1]
                    .sender
                    .send(Recipients::One(peer3_pk), wrong_bytes, true)
                    .await
                    .expect("send failed");
                context.sleep(config.link.latency * 2).await;

                // Peer 1 should be blocked for weak shard index mismatch.
                assert_blocked(&oracle, &peers[3].public_key, &peers[1].public_key).await;
            },
        );
    }

    #[test_traced]
    fn test_invalid_weak_shard_crypto_blocks_peer() {
        // Test that a weak shard failing cryptographic verification (C::check)
        // results in blocking the sender (immediate path, checking_data available).
        let fixture = Fixture {
            num_peers: 10,
            ..Default::default()
        };

        fixture.start(
            |config, context, oracle, mut peers, coding_config| async move {
                // Create two different blocks.
                let inner1 = B::new::<H>((), Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block1 = CodedBlock::<B, C>::new(inner1, coding_config, &STRATEGY);
                let commitment1 = coded_block1.commitment();

                let inner2 = B::new::<H>((), Sha256Digest::EMPTY, Height::new(2), 200);
                let coded_block2 = CodedBlock::<B, C>::new(inner2, coding_config, &STRATEGY);

                // Get peer 3's strong shard from block1 (valid).
                let peer3_index = peers[3].index.get() as usize;
                let peer3_strong_shard =
                    coded_block1.shard::<H>(peer3_index).expect("missing shard");

                // Get peer 1's weak shard from block2, but re-wrap with block1's
                // commitment so C::check fails.
                let peer1_index = peers[1].index.get() as usize;
                let mut wrong_weak_shard = coded_block2
                    .shard::<H>(peer1_index)
                    .expect("missing shard")
                    .verify_into_weak()
                    .expect("verify_into_weak failed");
                wrong_weak_shard.commitment = commitment1;
                let wrong_bytes = wrong_weak_shard.encode();

                let peer3_pk = peers[3].public_key.clone();
                let leader = peers[0].public_key.clone();

                // Inform peer 3 of the leader and send the valid strong shard.
                peers[3]
                    .mailbox
                    .external_proposed(commitment1, leader)
                    .await;
                let strong_bytes = peer3_strong_shard.encode();
                peers[0]
                    .sender
                    .send(Recipients::One(peer3_pk.clone()), strong_bytes, true)
                    .await
                    .expect("send failed");
                context.sleep(config.link.latency * 2).await;

                // Peer 1 sends the invalid weak shard.
                peers[1]
                    .sender
                    .send(Recipients::One(peer3_pk), wrong_bytes, true)
                    .await
                    .expect("send failed");
                context.sleep(config.link.latency * 2).await;

                // Peer 1 should be blocked for invalid weak shard crypto.
                assert_blocked(&oracle, &peers[3].public_key, &peers[1].public_key).await;
            },
        );
    }

    #[test_traced]
    fn test_invalid_pending_weak_shard_blocked_on_drain() {
        // Test that a weak shard buffered in pending_shards (before checking data) is
        // blocked when drain_pending runs and C::check fails.
        let fixture = Fixture {
            num_peers: 10,
            ..Default::default()
        };

        fixture.start(
            |config, context, oracle, mut peers, coding_config| async move {
                // Create two different blocks.
                let inner1 = B::new::<H>((), Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block1 = CodedBlock::<B, C>::new(inner1, coding_config, &STRATEGY);
                let commitment1 = coded_block1.commitment();

                let inner2 = B::new::<H>((), Sha256Digest::EMPTY, Height::new(2), 200);
                let coded_block2 = CodedBlock::<B, C>::new(inner2, coding_config, &STRATEGY);

                // Get peer 1's weak shard from block2, but wrap with block1's commitment.
                let peer1_index = peers[1].index.get() as usize;
                let mut wrong_weak_shard = coded_block2
                    .shard::<H>(peer1_index)
                    .expect("missing shard")
                    .verify_into_weak()
                    .expect("verify_into_weak failed");
                wrong_weak_shard.commitment = commitment1;
                let wrong_bytes = wrong_weak_shard.encode();

                let peer3_pk = peers[3].public_key.clone();

                // Send the invalid weak shard BEFORE the strong shard (no checking data yet,
                // so it gets buffered in pending_shards).
                peers[1]
                    .sender
                    .send(Recipients::One(peer3_pk.clone()), wrong_bytes, true)
                    .await
                    .expect("send failed");
                context.sleep(config.link.latency * 2).await;

                // No one should be blocked yet (weak shard is buffered).
                let blocked = oracle.blocked().await.unwrap();
                assert!(blocked.is_empty(), "no peers should be blocked yet");

                // Now inform peer 3 of the leader and send the valid strong shard.
                let leader = peers[0].public_key.clone();
                peers[3]
                    .mailbox
                    .external_proposed(commitment1, leader)
                    .await;
                let peer3_index = peers[3].index.get() as usize;
                let peer3_strong_shard =
                    coded_block1.shard::<H>(peer3_index).expect("missing shard");
                let strong_bytes = peer3_strong_shard.encode();
                peers[0]
                    .sender
                    .send(Recipients::One(peer3_pk), strong_bytes, true)
                    .await
                    .expect("send failed");
                context.sleep(config.link.latency * 2).await;

                // Peer 1 should be blocked after drain_pending validates and
                // rejects their invalid weak shard.
                assert_blocked(&oracle, &peers[3].public_key, &peers[1].public_key).await;
            },
        );
    }
}
