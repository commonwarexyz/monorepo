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
//! For each [`CodingCommitment`] with a known leader, participating nodes
//! maintain a [`ReconstructionState`]. Before leader announcement, shards are buffered in
//! bounded per-peer queues:
//!
//! ```text
//!    +----------------------+
//!    | AwaitingQuorum       |
//!    | - leader known       |
//!    | - buffer weak        |  <--- pre-leader buffered shards are ingested here
//!    | - checking_data when |
//!    |   strong verified    |
//!    +----------------------+
//!               |
//!               | quorum met + batch validation passes
//!               v
//!    +----------------------+
//!    | Ready                |
//!    | - has checking_data  |
//!    | - checked shards     |
//!    +----------------------+
//!               |
//!               | checked_shards.len() >= minimum_shards
//!               v
//!    +----------------------+
//!    | Reconstruction        |
//!    | Attempt               |
//!    +----------------------+
//!               |
//!          +----+----+
//!          |         |
//!          v         v
//!       Success    Failure
//!          |         |
//!          v         v
//!       Cache      Remove
//!       Block      State
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
//! Validation and blocking rules are applied while a commitment is actively
//! tracked in reconstruction state. Once a block is already reconstructed and
//! cached, additional shards for that commitment are ignored.
//!
//! Note: Strong shards are only accepted from the leader. If the leader is not
//! yet known, shards are buffered in fixed-size per-peer queues until consensus
//! signals the leader via [`ExternalProposed`]. Once leader is known, buffered
//! shards for that commitment are ingested into the active state machine.
//!
//! [`ExternalProposed`]: super::Message::ExternalProposed

use super::{
    mailbox::{Mailbox, Message},
    metrics::{Peer, ShardMetrics},
};
use crate::{
    marshal::coding::types::{CodedBlock, DistributionShard, Shard},
    types::{CodingCommitment, View},
    Block, CertifiableBlock, Heightable,
};
use commonware_codec::{Codec, Error as CodecError, Read};
use commonware_coding::Scheme as CodingScheme;
use commonware_cryptography::{Committable, Digestible, Hasher, PublicKey};
use commonware_macros::select_loop;
use commonware_p2p::{utils::codec::WrappedSender, Blocker, Receiver, Recipients, Sender};
use commonware_parallel::Strategy;
use commonware_runtime::{
    spawn_cell, telemetry::metrics::status::GaugeExt, Clock, ContextCell, Handle, Metrics, Spawner,
};
use commonware_utils::{
    bitmap::BitMap,
    channel::{
        fallible::{AsyncFallibleExt, OneshotExt},
        mpsc, oneshot,
    },
    ordered::{Quorum, Set},
    Participant,
};
use rand::Rng;
use rayon::iter::Either;
use std::{
    collections::{BTreeMap, VecDeque},
    num::NonZeroUsize,
    sync::Arc,
    time::Instant,
};
use thiserror::Error;
use tracing::{debug, warn};

/// An error that can occur during reconstruction of a [`CodedBlock`] from [`Shard`]s
#[derive(Debug, Error)]
pub enum Error<C: CodingScheme> {
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

    /// Number of pre-leader shards to buffer per peer.
    ///
    /// Shards for commitments without a reconstruction state are buffered per
    /// peer in a fixed-size ring to bound memory under Byzantine spam. These
    /// shards are only ingested when consensus provides a leader via
    /// [`ExternalProposed`](super::Message::ExternalProposed).
    ///
    /// The worst-case total memory usage for pre-leader buffers is
    /// `num_participants * pre_leader_buffer_size * max_shard_size`.
    pub pre_leader_buffer_size: NonZeroUsize,

    /// Capacity of the channel between the background receiver and the engine.
    ///
    /// The background receiver decodes incoming network messages in a separate
    /// task and forwards them to the engine over an `mpsc` channel with this
    /// capacity.
    pub background_channel_capacity: usize,
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

    /// Per-peer ring buffers for shards received before leader announcement.
    pre_leader_buffers: BTreeMap<P, VecDeque<Shard<C, H>>>,

    /// Maximum buffered pre-leader shards per peer.
    pre_leader_buffer_size: NonZeroUsize,

    /// Capacity of the background receiver channel.
    background_channel_capacity: usize,

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
                pre_leader_buffers: BTreeMap::new(),
                pre_leader_buffer_size: config.pre_leader_buffer_size,
                background_channel_capacity: config.background_channel_capacity,
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
        let mut sender = WrappedSender::<_, Shard<C, H>>::new(sender);
        let (receiver_service, mut receiver): (_, mpsc::Receiver<(P, Shard<C, H>)>) =
            WrappedBackgroundReceiver::new(
                self.context.with_label("wrapped_background_receiver"),
                receiver,
                self.shard_codec_cfg.clone(),
                self.blocker.clone(),
                self.background_channel_capacity,
            );
        // Keep the handle alive to prevent the background receiver from being aborted.
        let _receiver_handle = receiver_service.start();

        select_loop! {
            self.context,
            on_start => {
                self.sync_metrics();

                // Clean up closed subscriptions.
                self.block_subscriptions.retain(|_, subscribers| {
                    subscribers.retain(|tx| !tx.is_closed());
                    !subscribers.is_empty()
                });
                self.shard_subscriptions.retain(|_, subscribers| {
                    subscribers.retain(|tx| !tx.is_closed());
                    !subscribers.is_empty()
                });
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
                        self.state.clear();
                        self.pre_leader_buffers.clear();
                        self.shard_subscriptions.clear();
                        self.block_subscriptions.clear();

                        debug!("updated participant set");
                    },
                    Message::Proposed { block } => {
                        self.broadcast_shards(&mut sender, block).await;
                    },
                    Message::ExternalProposed {
                        commitment,
                        leader,
                        view,
                    } => {
                        self.handle_external_proposal(&mut sender, commitment, leader, view)
                            .await;
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
                // Track shard receipt per peer.
                self.metrics.shards_received.get_or_create(&Peer::new(&peer)).inc();

                // Insert the shard into the reconstruction state.
                let commitment = shard.commitment();
                if !self.reconstructed_blocks.contains_key(&commitment) {
                    if let Some(state) = self.state.get_mut(&commitment) {
                        let progressed = state
                            .on_network_shard(
                                peer,
                                shard,
                                InsertCtx {
                                    me: self.me.as_ref(),
                                    participants: &self.participants,
                                    strategy: &self.strategy,
                                },
                                &mut self.blocker,
                            )
                            .await;
                        if progressed {
                            self.try_advance(&mut sender, commitment).await;
                        }
                    } else if self.participants.index(&peer).is_none() {
                        warn!(?peer, "shard sent by non-participant, blocking peer");
                        self.blocker.block(peer).await;
                    } else {
                        self.buffer_pre_leader_shard(peer, shard);
                    }
                }
            }
        }
    }

    /// Attempts to reconstruct a [`CodedBlock`] from the checked [`Shard`]s present in the
    /// [`ReconstructionState`].
    ///
    /// # Returns
    /// - `Ok(Some(block))` if reconstruction was successful or the block was already reconstructed.
    /// - `Ok(None)` if reconstruction could not be attempted due to insufficient checked shards.
    /// - `Err(_)` if reconstruction was attempted but failed.
    #[inline]
    async fn try_reconstruct(
        &mut self,
        commitment: CodingCommitment,
    ) -> Result<Option<Arc<CodedBlock<B, C>>>, Error<C>> {
        if let Some(block) = self.reconstructed_blocks.get(&commitment) {
            return Ok(Some(Arc::clone(block)));
        }

        let Some(state) = self.state.get(&commitment) else {
            return Ok(None);
        };
        if state.checked_shards().len() < usize::from(commitment.config().minimum_shards) {
            debug!(%commitment, "not enough checked shards to reconstruct block");
            return Ok(None);
        }

        let Some(checking_data) = state.checking_data() else {
            unreachable!("checked shards cannot be present without checking data");
        };

        // Attempt to reconstruct the encoded blob
        let start = Instant::now();
        let blob = C::decode(
            &commitment.config(),
            &commitment.coding_digest(),
            checking_data.clone(),
            state.checked_shards(),
            &self.strategy,
        )
        .map_err(Error::CodingRecovery)?;
        self.metrics
            .erasure_decode_duration
            .observe(start.elapsed().as_secs_f64());

        // Attempt to decode the block from the encoded blob
        let inner = B::read_cfg(&mut blob.as_slice(), &self.block_codec_cfg)?;

        // Verify the reconstructed block's digest matches the commitment's block digest.
        if inner.digest() != commitment.block_digest() {
            return Err(Error::DigestMismatch);
        }

        // Construct a coding block with a _trusted_ commitment. `S::decode` verified the blob's
        // integrity against the commitment, so shards can be lazily re-constructed if need be.
        let block = Arc::new(CodedBlock::new_trusted(inner, commitment));

        self.reconstructed_blocks
            .insert(commitment, Arc::clone(&block));
        self.metrics.blocks_reconstructed_total.inc();
        Ok(Some(block))
    }

    /// Handles leader announcements for a commitment and advances reconstruction.
    #[inline]
    async fn handle_external_proposal<Sr: Sender<PublicKey = P>>(
        &mut self,
        sender: &mut WrappedSender<Sr, Shard<C, H>>,
        commitment: CodingCommitment,
        leader: P,
        view: View,
    ) {
        if self.reconstructed_blocks.contains_key(&commitment) {
            return;
        }
        if self.me.is_none() {
            return;
        }
        if self.participants.index(&leader).is_none() {
            warn!(?leader, %commitment, "leader update for non-participant, ignoring");
            return;
        }

        if let Some(state) = self.state.get(&commitment) {
            if state.leader() != &leader {
                warn!(
                    existing = ?state.leader(),
                    ?leader,
                    %commitment,
                    "conflicting leader update, ignoring"
                );
            }
            return;
        }

        self.state
            .insert(commitment, ReconstructionState::new(leader, view));
        let buffered_progress = self.ingest_buffered_shards(commitment).await;
        if buffered_progress {
            self.try_advance(sender, commitment).await;
        }
    }

    /// Buffer a shard from a participant until a leader is known.
    fn buffer_pre_leader_shard(&mut self, peer: P, shard: Shard<C, H>) {
        let queue = self.pre_leader_buffers.entry(peer).or_default();
        if queue.len() >= self.pre_leader_buffer_size.get() {
            let _ = queue.pop_front();
        }
        queue.push_back(shard);
    }

    /// Ingest buffered pre-leader shards for a commitment into active state.
    async fn ingest_buffered_shards(&mut self, commitment: CodingCommitment) -> bool {
        let mut buffered_weak = Vec::new();
        let mut buffered_strong = Vec::new();
        for (peer, queue) in self.pre_leader_buffers.iter_mut() {
            let mut retained = VecDeque::with_capacity(queue.len());
            for shard in queue.drain(..) {
                if shard.commitment() == commitment {
                    if shard.is_strong() {
                        buffered_strong.push((peer.clone(), shard));
                    } else {
                        buffered_weak.push((peer.clone(), shard));
                    }
                    continue;
                }
                retained.push_back(shard);
            }
            *queue = retained;
        }
        self.pre_leader_buffers.retain(|_, queue| !queue.is_empty());

        let Some(state) = self.state.get_mut(&commitment) else {
            return false;
        };

        // Ingest weak shards first so they populate pending_weak_shards before
        // the strong shard sets checking_data and triggers batch validation.
        let mut progressed = false;
        for (peer, shard) in buffered_weak.into_iter().chain(buffered_strong) {
            progressed |= state
                .on_network_shard(
                    peer,
                    shard,
                    InsertCtx {
                        me: self.me.as_ref(),
                        participants: &self.participants,
                        strategy: &self.strategy,
                    },
                    &mut self.blocker,
                )
                .await;
        }
        progressed
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
        self.reconstructed_blocks
            .insert(commitment, Arc::new(block.clone()));

        // Broadcast each shard to the corresponding participant.
        for (index, peer) in self.participants.iter().enumerate() {
            if self.me.is_some_and(|me| me.get() as usize == index) {
                continue;
            }

            let shard = block
                .shard(index as u16)
                .expect("block must have shard for each participant");
            let _ = sender
                .send(Recipients::One(peer.clone()), shard, true)
                .await;
        }

        debug!(?commitment, "broadcasted shards to participants");
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
        debug!(?commitment, "broadcasted shard to all participants");
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

        match self.try_reconstruct(commitment).await {
            Ok(Some(block)) => {
                debug!(
                    %commitment,
                    parent = %block.parent(),
                    height = %block.height(),
                    "successfully reconstructed block from shards"
                );
                if let Some(view) = self.state.get(&commitment).map(ReconstructionState::view) {
                    self.state.retain(|_, state| state.view() > view);
                }
                self.notify_block_subscribers(block).await;
            }
            Ok(None) => {
                debug!(%commitment, "not enough checked shards to reconstruct block");
            }
            Err(err) => {
                warn!(%commitment, ?err, "failed to reconstruct block from checked shards");
                self.state.remove(&commitment);
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
            .is_some_and(|state| state.checking_data().is_some());
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

        self.reconstructed_blocks
            .retain(|_, block| block.height() > height);
    }

    /// Syncs gauge metrics for map sizes.
    fn sync_metrics(&self) {
        let _ = self
            .metrics
            .reconstruction_states_count
            .try_set(self.state.len());
        let _ = self
            .metrics
            .reconstructed_blocks_cache_count
            .try_set(self.reconstructed_blocks.len());
    }
}

/// Erasure coded block reconstruction state machine.
enum ReconstructionState<P, C, H>
where
    P: PublicKey,
    C: CodingScheme,
    H: Hasher,
{
    /// Stage 1: leader known; buffer weak shards and optionally hold checking
    /// data from a verified strong shard. Transitions to `Ready` when quorum
    /// is met and batch validation succeeds.
    AwaitingQuorum(AwaitingQuorumState<P, C, H>),
    /// Stage 2: batch validation passed; checked shards are available for
    /// reconstruction.
    Ready(ReadyState<P, C, H>),
}

/// State shared across all reconstruction phases.
struct CommonState<P, C, H>
where
    P: PublicKey,
    C: CodingScheme,
    H: Hasher,
{
    /// The leader associated with this reconstruction state.
    leader: P,
    /// Our validated weak shard, ready to broadcast to other participants.
    our_weak_shard: Option<Shard<C, H>>,
    /// Shards that have been verified and are ready to contribute to reconstruction.
    checked_shards: Vec<C::CheckedShard>,
    /// Bitmap tracking which participant indices have contributed a valid shard.
    contributed: BitMap,
    /// The view for which this commitment was externally proposed.
    view: View,
}

/// Phase data for `ReconstructionState::AwaitingQuorum`.
///
/// In this phase, the leader is known. Weak shards are buffered until enough
/// shards (strong + pending weak) are available to attempt batch validation.
/// `checking_data` is populated once the leader's strong shard is verified via
/// `C::weaken`.
struct AwaitingQuorumState<P, C, H>
where
    P: PublicKey,
    C: CodingScheme,
    H: Hasher,
{
    common: CommonState<P, C, H>,
    pending_weak_shards: BTreeMap<P, WeakShard<C>>,
    checking_data: Option<C::CheckingData>,
}

/// Phase data for `ReconstructionState::Ready`.
///
/// Batch validation has passed. Checked shards are available for
/// reconstruction.
struct ReadyState<P, C, H>
where
    P: PublicKey,
    C: CodingScheme,
    H: Hasher,
{
    common: CommonState<P, C, H>,
    checking_data: C::CheckingData,
}

/// Parsed strong shard payload used by internal state-machine handlers.
struct StrongShard<C>
where
    C: CodingScheme,
{
    commitment: CodingCommitment,
    index: u16,
    data: C::StrongShard,
}

/// Parsed weak shard payload used by internal state-machine handlers.
struct WeakShard<C>
where
    C: CodingScheme,
{
    index: u16,
    data: C::WeakShard,
}

impl<P, C, H> CommonState<P, C, H>
where
    P: PublicKey,
    C: CodingScheme,
    H: Hasher,
{
    /// Create a new empty common state for the provided leader and view.
    const fn new(leader: P, view: View) -> Self {
        Self {
            leader,
            our_weak_shard: None,
            checked_shards: Vec::new(),
            contributed: BitMap::new(),
            view,
        }
    }

    /// Lazily initialize the contributor bitmap for the participant set size.
    fn ensure_contributed(&mut self, participants_len: usize) {
        if self.contributed.is_empty() {
            self.contributed = BitMap::zeroes(
                u64::try_from(participants_len)
                    .expect("participant count impossibly out of bounds"),
            );
        }
    }
}

impl<P, C, H> AwaitingQuorumState<P, C, H>
where
    P: PublicKey,
    C: CodingScheme,
    H: Hasher,
{
    /// Verify the leader's strong shard and store checking data.
    ///
    /// Returns `false` if verification fails (sender is blocked), `true` on
    /// success. Does not transition state; the caller should invoke
    /// `try_transition` after this returns `true`.
    async fn verify_strong_shard(
        &mut self,
        sender: P,
        shard: StrongShard<C>,
        blocker: &mut impl Blocker<PublicKey = P>,
    ) -> bool {
        let StrongShard {
            commitment,
            index,
            data,
        } = shard;
        let Ok((checking_data, checked, weak_shard_data)) = C::weaken(
            &commitment.config(),
            &commitment.coding_digest(),
            index,
            data,
        ) else {
            warn!(?sender, "invalid strong shard received, blocking peer");
            blocker.block(sender).await;
            return false;
        };

        self.common.checked_shards.push(checked);
        self.common.our_weak_shard = Some(Shard::new(
            commitment,
            index,
            DistributionShard::Weak(weak_shard_data),
        ));
        self.checking_data = Some(checking_data);
        true
    }

    /// Check whether quorum is met and, if so, batch-validate all pending weak
    /// shards in parallel. Returns `Some(ReadyState)` on successful transition.
    async fn try_transition(
        &mut self,
        commitment: CodingCommitment,
        strategy: &impl Strategy,
        blocker: &mut impl Blocker<PublicKey = P>,
    ) -> Option<ReadyState<P, C, H>> {
        if self.checking_data.is_none() {
            return None;
        }
        let minimum = usize::from(commitment.config().minimum_shards);
        if self.common.checked_shards.len() + self.pending_weak_shards.len() < minimum {
            return None;
        }

        // Batch-validate all pending weak shards in parallel.
        let pending = std::mem::take(&mut self.pending_weak_shards);
        let checking_data = self.checking_data.as_ref().unwrap();
        let (new_checked, to_block) =
            strategy.map_partition_collect_vec(pending, |(peer, shard)| {
                let checked = C::check(
                    &commitment.config(),
                    &commitment.coding_digest(),
                    checking_data,
                    shard.index,
                    shard.data,
                );
                (peer, checked.ok())
            });

        for peer in to_block {
            warn!(?peer, "invalid shard received, blocking peer");
            blocker.block(peer).await;
        }
        self.common.checked_shards.extend(new_checked);

        // After validation, some may have failed; recheck threshold.
        if self.common.checked_shards.len() < minimum {
            return None;
        }

        // Transition to Ready.
        let checking_data = self.checking_data.take().unwrap();
        let view = self.common.view;
        let leader = self.common.leader.clone();
        let common = std::mem::replace(&mut self.common, CommonState::new(leader, view));
        Some(ReadyState {
            common,
            checking_data,
        })
    }
}

/// Context required for processing incoming network shards.
struct InsertCtx<'a, P, S>
where
    P: PublicKey,
    S: Strategy,
{
    me: Option<&'a Participant>,
    participants: &'a Set<P>,
    strategy: &'a S,
}

impl<P, C, H> ReconstructionState<P, C, H>
where
    P: PublicKey,
    C: CodingScheme,
    H: Hasher,
{
    /// Create an initial reconstruction state for a commitment.
    const fn new(leader: P, view: View) -> Self {
        Self::AwaitingQuorum(AwaitingQuorumState {
            common: CommonState::new(leader, view),
            pending_weak_shards: BTreeMap::new(),
            checking_data: None,
        })
    }

    /// Access common state shared across all phases.
    const fn common(&self) -> &CommonState<P, C, H> {
        match self {
            Self::AwaitingQuorum(state) => &state.common,
            Self::Ready(state) => &state.common,
        }
    }

    /// Mutably access common state shared across all phases.
    const fn common_mut(&mut self) -> &mut CommonState<P, C, H> {
        match self {
            Self::AwaitingQuorum(state) => &mut state.common,
            Self::Ready(state) => &mut state.common,
        }
    }

    /// Return the leader associated with this state.
    const fn leader(&self) -> &P {
        &self.common().leader
    }

    /// Returns checking data when available.
    ///
    /// In `AwaitingQuorum`, this is `Some` once the leader's strong shard has
    /// been verified. In `Ready`, it is always `Some`.
    const fn checking_data(&self) -> Option<&C::CheckingData> {
        match self {
            Self::AwaitingQuorum(state) => state.checking_data.as_ref(),
            Self::Ready(state) => Some(&state.checking_data),
        }
    }

    /// Return the proposal view associated with this state.
    const fn view(&self) -> View {
        self.common().view
    }

    /// Returns all verified shards accumulated for reconstruction.
    ///
    /// This slice grows as valid strong/weak shards are accepted.
    const fn checked_shards(&self) -> &[C::CheckedShard] {
        self.common().checked_shards.as_slice()
    }

    /// Takes the validated [`Shard`] for broadcasting to other participants.
    /// Returns [`None`] if we haven't validated our own shard yet.
    const fn take_weak_shard(&mut self) -> Option<Shard<C, H>> {
        self.common_mut().our_weak_shard.take()
    }

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
    /// - When leader is unknown, buffering happens at the engine level in
    ///   bounded pre-leader queues until [`ExternalProposed`](super::Message::ExternalProposed)
    ///   creates a reconstruction state for this commitment.
    ///
    /// Weak shards (`CodingScheme::WeakShard`):
    /// - MUST be sent by a participant.
    /// - MUST be sent by the participant whose index matches the shard index.
    /// - MUST pass cryptographic verification via [`CodingScheme::check`].
    /// - Each participant may only contribute ONE weak shard per commitment. Duplicates
    ///   result in blocking the sender.
    ///
    /// Handle an incoming network shard.
    ///
    /// Returns `true` only when the shard caused state progress (buffered,
    /// validated, or transitioned), and `false` when rejected/blocked.
    async fn on_network_shard<S, X>(
        &mut self,
        sender: P,
        shard: Shard<C, H>,
        ctx: InsertCtx<'_, P, S>,
        blocker: &mut X,
    ) -> bool
    where
        S: Strategy,
        X: Blocker<PublicKey = P>,
    {
        let Some(sender_index) = ctx.participants.index(&sender) else {
            warn!(?sender, "shard sent by non-participant, blocking peer");
            blocker.block(sender).await;
            return false;
        };
        let commitment = shard.commitment();
        let index = shard.index();

        self.common_mut().ensure_contributed(ctx.participants.len());

        let progressed = match shard.into_inner() {
            DistributionShard::Strong(data) => {
                let strong = StrongShard {
                    commitment,
                    index,
                    data,
                };
                self.insert_strong_shard(ctx.me, sender, strong, blocker)
                    .await
            }
            DistributionShard::Weak(data) => {
                let weak = WeakShard { index, data };
                self.insert_weak_shard(sender, sender_index, weak, blocker)
                    .await
            }
        };

        if progressed {
            if let Self::AwaitingQuorum(state) = self {
                if let Some(ready) =
                    state.try_transition(commitment, ctx.strategy, blocker).await
                {
                    *self = Self::Ready(ready);
                }
            }
        }

        progressed
    }

    /// Insert a strong shard according to the current phase.
    ///
    /// Returns `true` only when this progresses reconstruction state.
    async fn insert_strong_shard(
        &mut self,
        me: Option<&Participant>,
        sender: P,
        shard: StrongShard<C>,
        blocker: &mut impl Blocker<PublicKey = P>,
    ) -> bool {
        let Some(me) = me else {
            warn!(
                ?sender,
                "strong shard sent to non-participant, blocking peer"
            );
            blocker.block(sender).await;
            return false;
        };

        let expected_index: u16 = me
            .get()
            .try_into()
            .expect("participant index impossibly out of bounds");
        if shard.index != expected_index {
            warn!(
                ?sender,
                shard_index = shard.index,
                expected_index = me.get() as usize,
                "strong shard index does not match self index, blocking peer"
            );
            blocker.block(sender).await;
            return false;
        }

        match self {
            Self::AwaitingQuorum(state) => {
                if sender != state.common.leader {
                    warn!(
                        ?sender,
                        leader = ?state.common.leader,
                        "strong shard from non-leader, blocking peer"
                    );
                    blocker.block(sender).await;
                    return false;
                }
                if state.checking_data.is_some() {
                    warn!(?sender, "duplicate strong shard from leader, blocking peer");
                    blocker.block(sender).await;
                    return false;
                }
                state.common.contributed.set(u64::from(me.get()), true);
                state.verify_strong_shard(sender, shard, blocker).await
            }
            Self::Ready(state) => {
                if sender != state.common.leader {
                    warn!(
                        ?sender,
                        leader = ?state.common.leader,
                        "strong shard from non-leader, blocking peer"
                    );
                } else {
                    warn!(?sender, "duplicate strong shard from leader, blocking peer");
                }
                blocker.block(sender).await;
                false
            }
        }
    }

    /// Insert a weak shard according to the current phase.
    ///
    /// Returns `true` only when this progresses reconstruction state.
    async fn insert_weak_shard(
        &mut self,
        sender: P,
        sender_index: Participant,
        shard: WeakShard<C>,
        blocker: &mut impl Blocker<PublicKey = P>,
    ) -> bool {
        let expected_index: u16 = sender_index
            .get()
            .try_into()
            .expect("participant index impossibly out of bounds");
        if shard.index != expected_index {
            warn!(
                ?sender,
                shard_index = shard.index,
                expected_index = sender_index.get() as usize,
                "weak shard index does not match participant index, blocking peer"
            );
            blocker.block(sender).await;
            return false;
        }

        if self.common().contributed.get(u64::from(sender_index.get())) {
            warn!(
                ?sender,
                "duplicate weak shard from participant, blocking peer"
            );
            blocker.block(sender).await;
            return false;
        }
        self.common_mut()
            .contributed
            .set(u64::from(sender_index.get()), true);

        match self {
            Self::AwaitingQuorum(state) => {
                state.pending_weak_shards.insert(sender, shard);
                true
            }
            Self::Ready(_) => false,
        }
    }
}

/// A background receiver that receives raw bytes from a [`Receiver`] and spawns concurrent
/// decode tasks using a [`Codec`].
///
/// This pipelines network I/O (receiving bytes) with CPU work (decoding messages) by spawning
/// a separate task for each decode operation, rather than decoding sequentially on the receive
/// loop. This is particularly useful when decoding large messages (such as erasure-coded shards)
/// would otherwise create backpressure on the event loop.
struct WrappedBackgroundReceiver<E, P, B, R, V>
where
    E: Spawner,
    P: PublicKey,
    B: Blocker<PublicKey = P>,
    R: Receiver<PublicKey = P>,
    V: Codec + Send,
{
    context: ContextCell<E>,
    receiver: R,
    codec_config: V::Cfg,
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
    /// Create a new [`WrappedBackgroundReceiver`] with the given receiver, codec config, and
    /// blocker.
    pub fn new(
        context: E,
        receiver: R,
        codec_config: V::Cfg,
        blocker: B,
        channel_capacity: usize,
    ) -> (Self, mpsc::Receiver<(P, V)>) {
        let (tx, rx) = mpsc::channel(channel_capacity);
        (
            Self {
                context: ContextCell::new(context),
                receiver,
                codec_config,
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
    ///
    /// Each incoming message is decoded in a separate spawned task, allowing
    /// the receive loop to continue draining the network buffer while decodes
    /// proceed concurrently.
    async fn run(mut self) {
        select_loop! {
            self.context,
            on_stopped => {
                debug!("wrapped background receiver received shutdown signal, stopping");
            },
            Ok((peer, bytes)) = self.receiver.recv() else {
                debug!("wrapped background receiver closed, stopping");
                return;
            } => {
                let config = self.codec_config.clone();
                let mut sender = self.sender.clone();
                let mut blocker = self.blocker.clone();

                let ctx = self.context.take();
                ctx.clone().spawn(|_| async move {
                    match V::decode_cfg(bytes.as_ref(), &config) {
                        Ok(value) => {
                            sender.send_lossy((peer, value)).await;
                        }
                        Err(err) => {
                            warn!(?peer, ?err, "received invalid message, blocking peer");
                            blocker.block(peer).await;
                        }
                    }
                });
                self.context.restore(ctx);
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
        types::{Height, View},
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
    use commonware_utils::{
        channel::oneshot::error::TryRecvError, ordered::Set, NZUsize, Participant,
    };
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
    }

    impl Default for Fixture {
        fn default() -> Self {
            Self {
                num_peers: 4,
                link: DEFAULT_LINK,
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
                        pre_leader_buffer_size: NZUsize!(64),
                        background_channel_capacity: 1024,
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
                    .external_proposed(commitment, leader.clone(), View::new(1))
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
                    .external_proposed(commitment, leader.clone(), View::new(1))
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
                let receiver_index = peers[2].index.get() as u16;

                let valid_shard = coded_block
                    .shard::<H>(receiver_index)
                    .expect("missing shard");

                // corrupt the shard's index
                let mut invalid_shard = valid_shard.clone();
                invalid_shard.index = 0;

                // Receiver subscribes to their shard and learns the leader.
                let receiver_pk = peers[2].public_key.clone();
                let leader = peers[1].public_key.clone();
                peers[2]
                    .mailbox
                    .external_proposed(commitment, leader, View::new(1))
                    .await;
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
                let peer2_index = peers[2].index.get() as u16;
                let peer2_strong_shard =
                    coded_block.shard::<H>(peer2_index).expect("missing shard");
                let strong_bytes = peer2_strong_shard.encode();

                let peer2_pk = peers[2].public_key.clone();
                let leader = peers[0].public_key.clone();

                // Inform peer 2 that peer 0 is the leader.
                peers[2]
                    .mailbox
                    .external_proposed(commitment, leader, View::new(1))
                    .await;

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
                let peer2_index = peers[2].index.get() as u16;
                let peer2_strong_shard =
                    coded_block.shard::<H>(peer2_index).expect("missing shard");
                let strong_bytes = peer2_strong_shard.encode();

                let peer2_pk = peers[2].public_key.clone();
                let leader = peers[0].public_key.clone();

                // Inform peer 2 that peer 0 is the leader.
                peers[2]
                    .mailbox
                    .external_proposed(commitment, leader, View::new(1))
                    .await;

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
                let peer2_index = peers[2].index.get() as u16;
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
                peers[2]
                    .mailbox
                    .external_proposed(commitment, leader, View::new(1))
                    .await;
                context.sleep(Duration::from_millis(10)).await;

                assert_blocked(&oracle, &peers[2].public_key, &peers[1].public_key).await;
            },
        );
    }

    #[test_traced]
    fn test_conflicting_external_proposed_ignored() {
        let fixture = Fixture {
            ..Default::default()
        };

        fixture.start(
            |config, context, oracle, mut peers, coding_config| async move {
                let inner = B::new::<H>((), Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block = CodedBlock::<B, C>::new(inner, coding_config, &STRATEGY);
                let commitment = coded_block.commitment();

                // Get peer 2's strong shard.
                let peer2_index = peers[2].index.get() as u16;
                let peer2_strong_shard = coded_block.shard::<H>(peer2_index).expect("missing shard");
                let strong_bytes = peer2_strong_shard.encode();

                let peer2_pk = peers[2].public_key.clone();
                let leader_a = peers[0].public_key.clone();
                let leader_b = peers[1].public_key.clone();

                // Subscribe before shards arrive so we can verify acceptance.
                let shard_sub = peers[2].mailbox.subscribe_shard(commitment).await;

                // First leader update should stick.
                peers[2]
                    .mailbox
                    .external_proposed(commitment, leader_a.clone(), View::new(1))
                    .await;
                // Conflicting update should be ignored.
                peers[2]
                    .mailbox
                    .external_proposed(commitment, leader_b, View::new(1))
                    .await;

                // Original leader sends strong shard; this should still be accepted.
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

                // Subscription should resolve from accepted strong shard.
                select! {
                    _ = shard_sub => {},
                    _ = context.sleep(Duration::from_secs(5)) => {
                        panic!("subscription did not complete after strong shard from original leader");
                    }
                };

                // The conflicting leader should still be treated as non-leader and blocked.
                peers[1]
                    .sender
                    .send(Recipients::One(peer2_pk), strong_bytes, true)
                    .await
                    .expect("send failed");
                context.sleep(config.link.latency * 2).await;

                assert_blocked(&oracle, &peers[2].public_key, &peers[1].public_key).await;

                // Original leader should not be blocked.
                let blocked_peers = oracle.blocked().await.unwrap();
                let leader_a_blocked = blocked_peers
                    .iter()
                    .any(|(a, b)| a == &peers[2].public_key && b == &leader_a);
                assert!(
                    !leader_a_blocked,
                    "original leader should not be blocked after conflicting leader update"
                );
            },
        );
    }

    #[test_traced]
    fn test_non_participant_external_proposed_ignored() {
        let fixture = Fixture {
            ..Default::default()
        };

        fixture.start(
            |config, context, oracle, mut peers, coding_config| async move {
                let inner = B::new::<H>((), Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block = CodedBlock::<B, C>::new(inner, coding_config, &STRATEGY);
                let commitment = coded_block.commitment();

                // Get peer 2's strong shard.
                let peer2_index = peers[2].index.get() as u16;
                let peer2_strong_shard =
                    coded_block.shard::<H>(peer2_index).expect("missing shard");
                let strong_bytes = peer2_strong_shard.encode();

                let peer2_pk = peers[2].public_key.clone();
                let leader = peers[0].public_key.clone();
                let non_participant_leader = PrivateKey::from_seed(10_000).public_key();

                // Subscribe before shards arrive.
                let shard_sub = peers[2].mailbox.subscribe_shard(commitment).await;

                // A non-participant leader update should be ignored.
                peers[2]
                    .mailbox
                    .external_proposed(commitment, non_participant_leader, View::new(1))
                    .await;

                // Leader unknown path: this strong shard should be buffered, not blocked.
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

                let blocked = oracle.blocked().await.unwrap();
                let leader_blocked = blocked
                    .iter()
                    .any(|(a, b)| a == &peers[2].public_key && b == &leader);
                assert!(
                    !leader_blocked,
                    "leader should not be blocked when non-participant update is ignored"
                );

                // A valid leader update should then process buffered shards and resolve subscription.
                peers[2]
                    .mailbox
                    .external_proposed(commitment, leader, View::new(1))
                    .await;
                context.sleep(config.link.latency * 2).await;

                select! {
                    _ = shard_sub => {},
                    _ = context.sleep(Duration::from_secs(5)) => {
                        panic!("subscription did not complete after valid leader update");
                    }
                };
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
                let peer2_index = peers[2].index.get() as u16;
                let peer2_strong_shard =
                    coded_block.shard::<H>(peer2_index).expect("missing shard");

                // Get peer 1's weak shard.
                let peer1_index = peers[1].index.get() as u16;
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
                    .external_proposed(coded_block.commitment(), leader, View::new(1))
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
    fn test_reconstruction_states_pruned_at_or_below_reconstructed_view() {
        // Use 10 peers so minimum_shards=4.
        let fixture = Fixture {
            num_peers: 10,
            ..Default::default()
        };

        fixture.start(
            |config, context, oracle, mut peers, coding_config| async move {
                // Commitment A at lower view (1).
                let block_a = CodedBlock::<B, C>::new(
                    B::new::<H>((), Sha256Digest::EMPTY, Height::new(1), 100),
                    coding_config,
                    &STRATEGY,
                );
                let commitment_a = block_a.commitment();

                // Commitment B at higher view (2), which we will reconstruct.
                let block_b = CodedBlock::<B, C>::new(
                    B::new::<H>((), Sha256Digest::EMPTY, Height::new(2), 200),
                    coding_config,
                    &STRATEGY,
                );
                let commitment_b = block_b.commitment();

                let peer2_pk = peers[2].public_key.clone();
                let leader = peers[0].public_key.clone();

                // Create state for A and ingest one weak shard from peer1.
                peers[2]
                    .mailbox
                    .external_proposed(commitment_a, leader.clone(), View::new(1))
                    .await;
                let peer1_strong_a = block_a
                    .shard::<H>(peers[1].index.get() as u16)
                    .expect("missing shard");
                let weak_a = peer1_strong_a
                    .verify_into_weak()
                    .expect("verify_into_weak failed")
                    .encode();
                peers[1]
                    .sender
                    .send(Recipients::One(peer2_pk.clone()), weak_a.clone(), true)
                    .await
                    .expect("send failed");
                context.sleep(config.link.latency * 2).await;

                // Create/reconstruct B at higher view.
                peers[2]
                    .mailbox
                    .external_proposed(commitment_b, leader, View::new(2))
                    .await;
                // Strong shard for peer2 from leader.
                let strong_b = block_b
                    .shard::<H>(peers[2].index.get() as u16)
                    .expect("missing shard")
                    .encode();
                peers[0]
                    .sender
                    .send(Recipients::One(peer2_pk.clone()), strong_b, true)
                    .await
                    .expect("send failed");

                // Three weak shards for minimum threshold (4 total with strong).
                for i in [1usize, 3usize, 4usize] {
                    let weak = block_b
                        .shard::<H>(peers[i].index.get() as u16)
                        .expect("missing shard")
                        .verify_into_weak()
                        .expect("verify_into_weak failed")
                        .encode();
                    peers[i]
                        .sender
                        .send(Recipients::One(peer2_pk.clone()), weak, true)
                        .await
                        .expect("send failed");
                }
                context.sleep(config.link.latency * 4).await;

                // B should reconstruct.
                let reconstructed = peers[2]
                    .mailbox
                    .get(commitment_b)
                    .await
                    .expect("block B should reconstruct");
                assert_eq!(reconstructed.commitment(), commitment_b);

                // A state should be pruned (at/below reconstructed view). Sending the same
                // weak shard for A again should NOT be treated as duplicate.
                peers[1]
                    .sender
                    .send(Recipients::One(peer2_pk), weak_a, true)
                    .await
                    .expect("send failed");
                context.sleep(config.link.latency * 2).await;

                let blocked = oracle.blocked().await.unwrap();
                let blocked_peer1 = blocked
                    .iter()
                    .any(|(a, b)| a == &peers[2].public_key && b == &peers[1].public_key);
                assert!(
                    !blocked_peer1,
                    "peer1 should not be blocked after lower-view state was pruned"
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
                let peer3_index = peers[3].index.get() as u16;
                let peer3_strong_shard =
                    coded_block.shard::<H>(peer3_index).expect("missing shard");

                // Get weak shards from peers 0, 1, and 2 (3 total to meet minimum_shards=4).
                let weak_shards: Vec<_> = [0, 1, 2]
                    .iter()
                    .map(|&i| {
                        coded_block
                            .shard::<H>(peers[i].index.get() as u16)
                            .expect("missing shard")
                            .verify_into_weak()
                            .expect("verify_into_weak failed")
                    })
                    .collect();

                let peer3_pk = peers[3].public_key.clone();

                // Send weak shards to peer 3 BEFORE their strong shard arrives.
                // These will be stored in pending_weak_shards since there's no checking data yet.
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
                peers[3]
                    .mailbox
                    .external_proposed(commitment, leader, View::new(1))
                    .await;

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
    fn test_pre_leader_shards_buffered_until_external_proposed() {
        // Test that shards received before leader announcement do not progress
        // reconstruction until ExternalProposed is delivered.
        let fixture = Fixture {
            num_peers: 10,
            ..Default::default()
        };

        fixture.start(
            |config, context, oracle, mut peers, coding_config| async move {
                let inner = B::new::<H>((), Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block = CodedBlock::<B, C>::new(inner, coding_config, &STRATEGY);
                let commitment = coded_block.commitment();

                let receiver_idx = 3usize;
                let receiver_pk = peers[receiver_idx].public_key.clone();
                let leader = peers[0].public_key.clone();

                // Subscribe before any shards arrive.
                let mut shard_sub = peers[receiver_idx]
                    .mailbox
                    .subscribe_shard(commitment)
                    .await;

                // Send one strong shard from the eventual leader and three weak shards,
                // all before leader announcement.
                let strong = coded_block
                    .shard::<H>(peers[receiver_idx].index.get() as u16)
                    .expect("missing shard")
                    .encode();
                peers[0]
                    .sender
                    .send(Recipients::One(receiver_pk.clone()), strong, true)
                    .await
                    .expect("send failed");

                for i in [1usize, 2usize, 4usize] {
                    let weak = coded_block
                        .shard::<H>(peers[i].index.get() as u16)
                        .expect("missing shard")
                        .verify_into_weak()
                        .expect("verify_into_weak failed")
                        .encode();
                    peers[i]
                        .sender
                        .send(Recipients::One(receiver_pk.clone()), weak, true)
                        .await
                        .expect("send failed");
                }

                context.sleep(config.link.latency * 2).await;

                // No leader yet: shard subscription should still be pending and block unavailable.
                assert!(
                    matches!(shard_sub.try_recv(), Err(TryRecvError::Empty)),
                    "shard subscription should not resolve before leader announcement"
                );
                assert!(
                    peers[receiver_idx].mailbox.get(commitment).await.is_none(),
                    "block should not reconstruct before leader announcement"
                );

                // Announce leader, which drains buffered shards and should progress immediately.
                peers[receiver_idx]
                    .mailbox
                    .external_proposed(commitment, leader, View::new(1))
                    .await;

                select! {
                    _ = shard_sub => {},
                    _ = context.sleep(Duration::from_secs(5)) => {
                        panic!("shard subscription did not resolve after leader announcement");
                    }
                }

                context.sleep(config.link.latency * 2).await;
                assert!(
                    peers[receiver_idx].mailbox.get(commitment).await.is_some(),
                    "block should reconstruct after buffered shards are ingested"
                );

                // All shards were valid and from participants.
                assert!(
                    oracle.blocked().await.unwrap().is_empty(),
                    "no peers should be blocked for valid buffered shards"
                );
            },
        );
    }

    #[test_traced]
    fn test_post_leader_shards_processed_immediately() {
        // Test that shards arriving after leader announcement are processed
        // without waiting for any extra trigger.
        let fixture = Fixture {
            num_peers: 10,
            ..Default::default()
        };

        fixture.start(
            |config, context, oracle, mut peers, coding_config| async move {
                let inner = B::new::<H>((), Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block = CodedBlock::<B, C>::new(inner, coding_config, &STRATEGY);
                let commitment = coded_block.commitment();

                let receiver_idx = 3usize;
                let receiver_pk = peers[receiver_idx].public_key.clone();
                let leader = peers[0].public_key.clone();

                let shard_sub = peers[receiver_idx]
                    .mailbox
                    .subscribe_shard(commitment)
                    .await;
                peers[receiver_idx]
                    .mailbox
                    .external_proposed(commitment, leader.clone(), View::new(1))
                    .await;

                // Send leader strong shard after leader is known.
                let strong = coded_block
                    .shard::<H>(peers[receiver_idx].index.get() as u16)
                    .expect("missing shard")
                    .encode();
                peers[0]
                    .sender
                    .send(Recipients::One(receiver_pk.clone()), strong, true)
                    .await
                    .expect("send failed");

                // Subscription should resolve from the strong shard.
                select! {
                    _ = shard_sub => {},
                    _ = context.sleep(Duration::from_secs(5)) => {
                        panic!("shard subscription did not resolve after post-leader strong shard");
                    }
                }

                // Send enough weak shards after leader known to reconstruct.
                for i in [1usize, 2usize, 4usize] {
                    let weak = coded_block
                        .shard::<H>(peers[i].index.get() as u16)
                        .expect("missing shard")
                        .verify_into_weak()
                        .expect("verify_into_weak failed")
                        .encode();
                    peers[i]
                        .sender
                        .send(Recipients::One(receiver_pk.clone()), weak, true)
                        .await
                        .expect("send failed");
                }

                context.sleep(config.link.latency * 2).await;
                let reconstructed = peers[receiver_idx]
                    .mailbox
                    .get(commitment)
                    .await
                    .expect("block should reconstruct from post-leader shards");
                assert_eq!(reconstructed.commitment(), commitment);

                assert!(
                    oracle.blocked().await.unwrap().is_empty(),
                    "no peers should be blocked for valid post-leader shards"
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
                        .shard::<H>(peer.index.get() as u16)
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
                        .shard::<H>(peer.index.get() as u16)
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
                    .shard::<H>(peers[3].index.get() as u16)
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
    fn test_duplicate_buffered_strong_shard_does_not_block_before_leader() {
        // Test that duplicate strong shards before leader announcement are
        // buffered and do not immediately block the sender.
        let fixture = Fixture {
            ..Default::default()
        };

        fixture.start(
            |config, context, oracle, mut peers, coding_config| async move {
                let inner = B::new::<H>((), Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block = CodedBlock::<B, C>::new(inner, coding_config, &STRATEGY);

                // Get peer 2's strong shard.
                let peer2_index = peers[2].index.get() as u16;
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

                // Still no blocking before a leader is known.
                let blocked = oracle.blocked().await.unwrap();
                assert!(
                    blocked.is_empty(),
                    "no peers should be blocked before leader"
                );
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
                let peer2_index = peers[2].index.get() as u16;
                let mut wrong_shard = coded_block2.shard::<H>(peer2_index).expect("missing shard");
                wrong_shard.commitment = commitment1;
                let wrong_bytes = wrong_shard.encode();

                let peer2_pk = peers[2].public_key.clone();
                let leader = peers[0].public_key.clone();

                // Inform peer 2 that peer 0 is the leader.
                peers[2]
                    .mailbox
                    .external_proposed(commitment1, leader, View::new(1))
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
                let peer3_index = peers[3].index.get() as u16;
                let peer3_strong_shard =
                    coded_block.shard::<H>(peer3_index).expect("missing shard");

                // Get peer 1's valid weak shard, then change the index to peer 4's index.
                let peer1_index = peers[1].index.get() as u16;
                let mut wrong_index_weak_shard = coded_block
                    .shard::<H>(peer1_index)
                    .expect("missing shard")
                    .verify_into_weak()
                    .expect("verify_into_weak failed");
                // Mutate the index so it doesn't match sender (peer 1).
                wrong_index_weak_shard.index = peers[4].index.get() as u16;
                let wrong_bytes = wrong_index_weak_shard.encode();

                let peer3_pk = peers[3].public_key.clone();
                let leader = peers[0].public_key.clone();

                // Inform peer 3 of the leader and send them the strong shard.
                peers[3]
                    .mailbox
                    .external_proposed(commitment, leader, View::new(1))
                    .await;
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
        // results in blocking the sender once batch validation fires at quorum.
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
                let peer3_index = peers[3].index.get() as u16;
                let peer3_strong_shard =
                    coded_block1.shard::<H>(peer3_index).expect("missing shard");

                // Get peer 1's weak shard from block2, but re-wrap with block1's
                // commitment so C::check fails.
                let peer1_index = peers[1].index.get() as u16;
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
                    .external_proposed(commitment1, leader, View::new(1))
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
                    .send(Recipients::One(peer3_pk.clone()), wrong_bytes, true)
                    .await
                    .expect("send failed");
                context.sleep(config.link.latency * 2).await;

                // No block yet: batch validation deferred until quorum.
                // Send valid weak shards from peers 2 and 4 to reach quorum
                // (minimum_shards = 4: 1 strong + 3 pending weak).
                for &idx in &[2, 4] {
                    let peer_index = peers[idx].index.get() as u16;
                    let weak = coded_block1
                        .shard::<H>(peer_index)
                        .expect("missing shard")
                        .verify_into_weak()
                        .expect("verify_into_weak failed");
                    let bytes = weak.encode();
                    peers[idx]
                        .sender
                        .send(Recipients::One(peer3_pk.clone()), bytes, true)
                        .await
                        .expect("send failed");
                }
                context.sleep(config.link.latency * 2).await;

                // Peer 1 should be blocked for invalid weak shard crypto.
                assert_blocked(&oracle, &peers[3].public_key, &peers[1].public_key).await;
            },
        );
    }

    #[test_traced]
    fn test_invalid_pending_weak_shard_blocked_on_drain() {
        // Test that a weak shard buffered in pending_weak_shards (before checking data) is
        // blocked when batch validation runs at quorum and C::check fails.
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
                let peer1_index = peers[1].index.get() as u16;
                let mut wrong_weak_shard = coded_block2
                    .shard::<H>(peer1_index)
                    .expect("missing shard")
                    .verify_into_weak()
                    .expect("verify_into_weak failed");
                wrong_weak_shard.commitment = commitment1;
                let wrong_bytes = wrong_weak_shard.encode();

                let peer3_pk = peers[3].public_key.clone();

                // Send the invalid weak shard BEFORE the strong shard (no checking data yet,
                // so it gets buffered in pending_weak_shards).
                peers[1]
                    .sender
                    .send(Recipients::One(peer3_pk.clone()), wrong_bytes, true)
                    .await
                    .expect("send failed");
                context.sleep(config.link.latency * 2).await;

                // No one should be blocked yet (weak shard is buffered).
                let blocked = oracle.blocked().await.unwrap();
                assert!(blocked.is_empty(), "no peers should be blocked yet");

                // Send valid weak shards from peers 2 and 4 so the pending count
                // reaches quorum once the strong shard arrives
                // (minimum_shards = 4: 1 strong + 3 pending weak).
                for &idx in &[2, 4] {
                    let peer_index = peers[idx].index.get() as u16;
                    let weak = coded_block1
                        .shard::<H>(peer_index)
                        .expect("missing shard")
                        .verify_into_weak()
                        .expect("verify_into_weak failed");
                    let bytes = weak.encode();
                    peers[idx]
                        .sender
                        .send(Recipients::One(peer3_pk.clone()), bytes, true)
                        .await
                        .expect("send failed");
                }
                context.sleep(config.link.latency * 2).await;

                // No one should be blocked yet (all shards are buffered pending leader).
                let blocked = oracle.blocked().await.unwrap();
                assert!(blocked.is_empty(), "no peers should be blocked yet");

                // Now inform peer 3 of the leader and send the valid strong shard.
                let leader = peers[0].public_key.clone();
                peers[3]
                    .mailbox
                    .external_proposed(commitment1, leader, View::new(1))
                    .await;
                let peer3_index = peers[3].index.get() as u16;
                let peer3_strong_shard =
                    coded_block1.shard::<H>(peer3_index).expect("missing shard");
                let strong_bytes = peer3_strong_shard.encode();
                peers[0]
                    .sender
                    .send(Recipients::One(peer3_pk), strong_bytes, true)
                    .await
                    .expect("send failed");
                context.sleep(config.link.latency * 2).await;

                // Peer 1 should be blocked after batch validation validates and
                // rejects their invalid weak shard.
                assert_blocked(&oracle, &peers[3].public_key, &peers[1].public_key).await;
            },
        );
    }
}
