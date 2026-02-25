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
//! _These are separated because some coding schemes enable the proposer to send extra data along
//! with the shard, reducing redundant transmission of checking data from multiple participants._
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
//!         | Discovered         | Discovered         |
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
//! For each [`Commitment`] with a known leader, participating nodes
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
//!    | (frozen; no new weak |
//!    |  shards accepted)    |
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
//! - Sending a second shard (strong or weak) with different data than the
//!   first (equivocation) results in blocking. Exact duplicates are silently
//!   ignored.
//!
//! Peers violating these rules are blocked via the [`Blocker`] trait.
//! Validation and blocking rules are applied while a commitment is actively
//! tracked in reconstruction state. Once a block is already reconstructed and
//! cached, additional shards for that commitment are ignored.
//!
//! _Strong shards are only accepted from the leader. If the leader is not
//! yet known, shards are buffered in fixed-size per-peer queues until consensus
//! signals the leader via [`Discovered`]. Once leader is known, buffered
//! shards for that commitment are ingested into the active state machine._
//!
//! [`Discovered`]: super::Message::Discovered

use super::{
    mailbox::{Mailbox, Message},
    metrics::{Peer, ShardMetrics},
};
use crate::{
    marshal::coding::{
        types::{CodedBlock, DistributionShard, Shard},
        validation::{validate_reconstruction, ReconstructionError as InvariantError},
    },
    types::{coding::Commitment, Epoch, Round},
    Block, CertifiableBlock, Heightable,
};
use commonware_codec::{Decode, Error as CodecError, Read};
use commonware_coding::{Config as CodingConfig, Scheme as CodingScheme};
use commonware_cryptography::{
    certificate::{Provider, Scheme as CertificateScheme},
    Committable, Digestible, Hasher, PublicKey,
};
use commonware_macros::select_loop;
use commonware_p2p::{
    utils::codec::{WrappedBackgroundReceiver, WrappedSender},
    Blocker, PeerSetSubscription, Receiver, Recipients, Sender,
};
use commonware_parallel::Strategy;
use commonware_runtime::{
    spawn_cell,
    telemetry::metrics::{histogram::HistogramExt, status::GaugeExt},
    BufferPooler, Clock, ContextCell, Handle, Metrics, Spawner,
};
use commonware_utils::{
    bitmap::BitMap,
    channel::{fallible::OneshotExt, mpsc, oneshot},
    ordered::Quorum,
    Participant,
};
use rand::Rng;
use std::{
    collections::{BTreeMap, VecDeque},
    num::NonZeroUsize,
    sync::Arc,
};
use thiserror::Error;
use tracing::{debug, warn};

/// An error that can occur during reconstruction of a [`CodedBlock`] from [`Shard`]s
#[derive(Debug, Error)]
pub enum Error<C: CodingScheme> {
    /// An error occurred while recovering the encoded blob from the [`Shard`]s
    #[error(transparent)]
    Coding(C::Error),

    /// An error occurred while decoding the reconstructed blob into a [`CodedBlock`]
    #[error(transparent)]
    Codec(#[from] CodecError),

    /// The reconstructed block's digest does not match the commitment's block digest
    #[error("block digest mismatch: reconstructed block does not match commitment digest")]
    DigestMismatch,

    /// The reconstructed block's config does not match the commitment's coding config
    #[error("block config mismatch: reconstructed config does not match commitment config")]
    ConfigMismatch,

    /// The reconstructed block's embedded context does not match the commitment context digest
    #[error("block context mismatch: reconstructed context does not match commitment context")]
    ContextMismatch,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum BlockSubscriptionKey<D> {
    Commitment(Commitment),
    Digest(D),
}

/// Configuration for the [`Engine`].
pub struct Config<P, S, X, C, H, B, T>
where
    P: PublicKey,
    S: Provider<Scope = Epoch>,
    X: Blocker<PublicKey = P>,
    C: CodingScheme,
    H: Hasher,
    B: CertifiableBlock,
    T: Strategy,
{
    /// The scheme provider.
    pub scheme_provider: S,

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

    /// Number of shards to buffer per peer.
    ///
    /// Shards for commitments without a reconstruction state are buffered per
    /// peer in a fixed-size ring to bound memory under Byzantine spam. These
    /// shards are only ingested when consensus provides a leader via
    /// [`Discovered`](super::Message::Discovered).
    ///
    /// The worst-case total memory usage for the set of shard buffers is
    /// `num_participants * peer_buffer_size * max_shard_size`.
    pub peer_buffer_size: NonZeroUsize,

    /// Capacity of the channel between the background receiver and the engine.
    ///
    /// The background receiver decodes incoming network messages in a separate
    /// task and forwards them to the engine over an `mpsc` channel with this
    /// capacity.
    pub background_channel_capacity: usize,

    /// Subscription to peer set changes. Per-peer shard buffers
    /// are freed when a peer leaves all tracked peer sets.
    pub peer_set_subscription: PeerSetSubscription<P>,
}

/// A network layer for broadcasting and receiving [`CodedBlock`]s as [`Shard`]s.
///
/// When enough [`Shard`]s are present in the mailbox, the [`Engine`] may facilitate
/// reconstruction of the original [`CodedBlock`] and notify any subscribers waiting for it.
pub struct Engine<E, S, X, C, H, B, P, T>
where
    E: BufferPooler + Rng + Spawner + Metrics + Clock,
    S: Provider<Scope = Epoch>,
    S::Scheme: CertificateScheme<PublicKey = P>,
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
    mailbox: mpsc::Receiver<Message<B, C, H, P>>,

    /// The scheme provider.
    scheme_provider: S,

    /// The peer blocker.
    blocker: X,

    /// [`Read`] configuration for decoding [`Shard`]s.
    shard_codec_cfg: <Shard<C, H> as Read>::Cfg,

    /// [`Read`] configuration for decoding [`CodedBlock`]s.
    block_codec_cfg: B::Cfg,

    /// The strategy used for parallel shard verification.
    strategy: T,

    /// A map of [`Commitment`]s to [`ReconstructionState`]s.
    state: BTreeMap<Commitment, ReconstructionState<P, C, H>>,

    /// Per-peer ring buffers for shards received before leader announcement.
    peer_buffers: BTreeMap<P, VecDeque<Shard<C, H>>>,

    /// Maximum buffered pre-leader shards per peer.
    peer_buffer_size: NonZeroUsize,

    /// Subscription to peer set changes.
    peer_set_subscription: PeerSetSubscription<P>,

    /// Capacity of the background receiver channel.
    background_channel_capacity: usize,

    /// An ephemeral cache of reconstructed blocks, keyed by commitment.
    ///
    /// These blocks are evicted after a durability signal from the marshal.
    /// Wrapped in [`Arc`] to enable cheap cloning when serving multiple subscribers.
    reconstructed_blocks: BTreeMap<Commitment, Arc<CodedBlock<B, C, H>>>,

    /// Open subscriptions for the receipt of our valid shard corresponding
    /// to the keyed [`Commitment`] from the leader.
    shard_subscriptions: BTreeMap<Commitment, Vec<oneshot::Sender<()>>>,

    /// Open subscriptions for the reconstruction of a [`CodedBlock`] with
    /// the keyed [`Commitment`].
    #[allow(clippy::type_complexity)]
    block_subscriptions:
        BTreeMap<BlockSubscriptionKey<B::Digest>, Vec<oneshot::Sender<Arc<CodedBlock<B, C, H>>>>>,

    /// Metrics for the shard engine.
    metrics: ShardMetrics,
}

impl<E, S, X, C, H, B, P, T> Engine<E, S, X, C, H, B, P, T>
where
    E: BufferPooler + Rng + Spawner + Metrics + Clock,
    S: Provider<Scope = Epoch>,
    S::Scheme: CertificateScheme<PublicKey = P>,
    X: Blocker<PublicKey = P>,
    C: CodingScheme,
    H: Hasher,
    B: CertifiableBlock,
    P: PublicKey,
    T: Strategy,
{
    /// Create a new [`Engine`] with the given configuration.
    pub fn new(context: E, config: Config<P, S, X, C, H, B, T>) -> (Self, Mailbox<B, C, H, P>) {
        let metrics = ShardMetrics::new(&context);
        let (sender, mailbox) = mpsc::channel(config.mailbox_size);
        (
            Self {
                context: ContextCell::new(context),
                mailbox,
                scheme_provider: config.scheme_provider,
                blocker: config.blocker,
                shard_codec_cfg: config.shard_codec_cfg,
                block_codec_cfg: config.block_codec_cfg,
                strategy: config.strategy,
                state: BTreeMap::new(),
                peer_buffers: BTreeMap::new(),
                peer_buffer_size: config.peer_buffer_size,
                peer_set_subscription: config.peer_set_subscription,
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
        let mut sender = WrappedSender::<_, Shard<C, H>>::new(
            self.context.network_buffer_pool().clone(),
            sender,
        );
        let (receiver_service, mut receiver): (_, mpsc::Receiver<(P, Shard<C, H>)>) =
            WrappedBackgroundReceiver::new(
                self.context.with_label("shard_ingress"),
                receiver,
                self.shard_codec_cfg.clone(),
                self.blocker.clone(),
                self.background_channel_capacity,
                &self.strategy,
            );
        // Keep the handle alive to prevent the background receiver from being aborted.
        let _receiver_handle = receiver_service.start();

        select_loop! {
            self.context,
            on_start => {
                let _ = self
                    .metrics
                    .reconstruction_states_count
                    .try_set(self.state.len());
                let _ = self
                    .metrics
                    .reconstructed_blocks_cache_count
                    .try_set(self.reconstructed_blocks.len());

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
            } => match message {
                Message::Proposed { block, round } => {
                    self.broadcast_shards(&mut sender, round, block).await;
                }
                Message::Discovered {
                    commitment,
                    leader,
                    round,
                } => {
                    self.handle_external_proposal(&mut sender, commitment, leader, round)
                        .await;
                }
                Message::GetByCommitment {
                    commitment,
                    response,
                } => {
                    let block = self.reconstructed_blocks.get(&commitment).cloned();
                    response.send_lossy(block);
                }
                Message::GetByDigest { digest, response } => {
                    let block = self
                        .reconstructed_blocks
                        .iter()
                        .find_map(|(_, b)| (b.digest() == digest).then_some(b))
                        .cloned();
                    response.send_lossy(block);
                }
                Message::SubscribeShard {
                    commitment,
                    response,
                } => {
                    self.handle_shard_subscription(commitment, response);
                }
                Message::SubscribeByCommitment {
                    commitment,
                    response,
                } => {
                    self.handle_block_subscription(
                        BlockSubscriptionKey::Commitment(commitment),
                        response,
                    );
                }
                Message::SubscribeByDigest { digest, response } => {
                    self.handle_block_subscription(BlockSubscriptionKey::Digest(digest), response);
                }
                Message::Prune { through } => {
                    self.prune(through);
                }
            },
            Some((peer, shard)) = receiver.recv() else {
                debug!("receiver closed, stopping shard engine");
                return;
            } => {
                // Track shard receipt per peer.
                self.metrics
                    .shards_received
                    .get_or_create(&Peer::new(&peer))
                    .inc();

                let commitment = shard.commitment();
                if self.reconstructed_blocks.contains_key(&commitment) {
                    continue;
                }

                if let Some(state) = self.state.get_mut(&commitment) {
                    let round = state.round();
                    let Some(scheme) = self.scheme_provider.scoped(round.epoch()) else {
                        warn!(%commitment, "no scheme for epoch, ignoring shard");
                        continue;
                    };
                    let progressed = state
                        .on_network_shard(
                            peer,
                            shard,
                            InsertCtx::new(scheme.as_ref(), &self.strategy),
                            &mut self.blocker,
                        )
                        .await;
                    if progressed {
                        self.try_advance(&mut sender, commitment).await;
                    }
                } else {
                    self.buffer_peer_shard(peer, shard);
                }
            },
            Some((_, _, tracked_peers)) = self.peer_set_subscription.recv() else {
                debug!("peer set subscription closed");
                return;
            } => {
                self.peer_buffers
                    .retain(|peer, _| tracked_peers.as_ref().contains(peer));
            },
        }
    }

    /// Attempts to reconstruct a [`CodedBlock`] from the checked [`Shard`]s present in the
    /// [`ReconstructionState`].
    ///
    /// # Returns
    /// - `Ok(Some(block))` if reconstruction was successful or the block was already reconstructed.
    /// - `Ok(None)` if reconstruction could not be attempted due to insufficient checked shards.
    /// - `Err(_)` if reconstruction was attempted but failed.
    #[allow(clippy::type_complexity)]
    fn try_reconstruct(
        &mut self,
        commitment: Commitment,
    ) -> Result<Option<Arc<CodedBlock<B, C, H>>>, Error<C>> {
        if let Some(block) = self.reconstructed_blocks.get(&commitment) {
            return Ok(Some(Arc::clone(block)));
        }
        let Some(state) = self.state.get(&commitment) else {
            return Ok(None);
        };
        if state.checked_shards().len() < usize::from(commitment.config().minimum_shards.get()) {
            debug!(%commitment, "not enough checked shards to reconstruct block");
            return Ok(None);
        }
        let checking_data = state
            .checking_data()
            .expect("checking data must be present");

        // Attempt to reconstruct the encoded blob
        let start = self.context.current();
        let blob = C::decode(
            &commitment.config(),
            &commitment.root(),
            checking_data.clone(),
            state.checked_shards(),
            &self.strategy,
        )
        .map_err(Error::Coding)?;
        self.metrics
            .erasure_decode_duration
            .observe_between(start, self.context.current());

        // Attempt to decode the block from the encoded blob
        let (inner, config): (B, CodingConfig) =
            Decode::decode_cfg(&mut blob.as_slice(), &(self.block_codec_cfg.clone(), ()))?;

        match validate_reconstruction::<H, _>(&inner, config, commitment) {
            Ok(()) => {}
            Err(InvariantError::BlockDigest) => {
                return Err(Error::DigestMismatch);
            }
            Err(InvariantError::CodingConfig) => {
                warn!(
                    %commitment,
                    expected_config = ?commitment.config(),
                    actual_config = ?config,
                    "reconstructed block config does not match commitment config, but digest matches"
                );
                return Err(Error::ConfigMismatch);
            }
            Err(InvariantError::ContextDigest(expected, actual)) => {
                warn!(
                    %commitment,
                    expected_context_digest = ?expected,
                    actual_context_digest = ?actual,
                    "reconstructed block context digest does not match commitment context digest"
                );
                return Err(Error::ContextMismatch);
            }
        }

        // Construct a coding block with a _trusted_ commitment. `S::decode` verified the blob's
        // integrity against the commitment, so shards can be lazily re-constructed if need be.
        let block = Arc::new(CodedBlock::new_trusted(inner, commitment));
        self.cache_block(Arc::clone(&block));
        self.metrics.blocks_reconstructed_total.inc();
        Ok(Some(block))
    }

    /// Handles leader announcements for a commitment and advances reconstruction.
    async fn handle_external_proposal<Sr: Sender<PublicKey = P>>(
        &mut self,
        sender: &mut WrappedSender<Sr, Shard<C, H>>,
        commitment: Commitment,
        leader: P,
        round: Round,
    ) {
        if self.reconstructed_blocks.contains_key(&commitment) {
            return;
        }
        let Some(scheme) = self.scheme_provider.scoped(round.epoch()) else {
            warn!(%commitment, "no scheme for epoch, ignoring external proposal");
            return;
        };
        if scheme.me().is_none() {
            // If we're not a participant, we won't be receiving any shards for this commitment,
            // so we can ignore it.
            return;
        }
        let participants = scheme.participants();
        if participants.index(&leader).is_none() {
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

        let participants_len =
            u64::try_from(participants.len()).expect("participant count impossibly out of bounds");
        self.state.insert(
            commitment,
            ReconstructionState::new(leader, round, participants_len),
        );
        let buffered_progress = self.ingest_buffered_shards(commitment).await;
        if buffered_progress {
            self.try_advance(sender, commitment).await;
        }
    }

    /// Buffer a shard from a peer until a leader is known.
    fn buffer_peer_shard(&mut self, peer: P, shard: Shard<C, H>) {
        let queue = self.peer_buffers.entry(peer).or_default();
        if queue.len() >= self.peer_buffer_size.get() {
            let _ = queue.pop_front();
        }
        queue.push_back(shard);
    }

    /// Ingest buffered pre-leader shards for a commitment into active state.
    async fn ingest_buffered_shards(&mut self, commitment: Commitment) -> bool {
        let mut buffered_weak = Vec::new();
        let mut buffered_strong = Vec::new();
        for (peer, queue) in self.peer_buffers.iter_mut() {
            let mut i = 0;
            while i < queue.len() {
                if queue[i].commitment() != commitment {
                    i += 1;
                    continue;
                }
                let shard = queue.swap_remove_back(i).expect("index is valid");
                if shard.is_strong() {
                    buffered_strong.push((peer.clone(), shard));
                } else {
                    buffered_weak.push((peer.clone(), shard));
                }
            }
        }
        self.peer_buffers.retain(|_, queue| !queue.is_empty());

        let Some(state) = self.state.get_mut(&commitment) else {
            return false;
        };
        let round = state.round();
        let Some(scheme) = self.scheme_provider.scoped(round.epoch()) else {
            warn!(%commitment, "no scheme for epoch, dropping buffered shards");
            return false;
        };

        // Ingest weak shards first so they populate pending_weak_shards before
        // the strong shard sets checking_data and triggers batch validation.
        let mut progressed = false;
        let ctx = InsertCtx::new(scheme.as_ref(), &self.strategy);
        for (peer, shard) in buffered_weak.into_iter().chain(buffered_strong) {
            progressed |= state
                .on_network_shard(peer, shard, ctx, &mut self.blocker)
                .await;
        }
        progressed
    }

    /// Cache a block and notify block subscribers waiting on it.
    fn cache_block(&mut self, block: Arc<CodedBlock<B, C, H>>) {
        let commitment = block.commitment();
        self.reconstructed_blocks
            .insert(commitment, Arc::clone(&block));
        self.notify_block_subscribers(block);
    }

    /// Broadcasts the shards of a [`CodedBlock`] to all participants and caches the block.
    async fn broadcast_shards<Sr: Sender<PublicKey = P>>(
        &mut self,
        sender: &mut WrappedSender<Sr, Shard<C, H>>,
        round: Round,
        mut block: CodedBlock<B, C, H>,
    ) {
        let commitment = block.commitment();

        let Some(scheme) = self.scheme_provider.scoped(round.epoch()) else {
            warn!(%commitment, "no scheme available, cannot broadcast shards");
            return;
        };
        let participants = scheme.participants();
        let me = scheme.me();

        let shard_count = block.shards(&self.strategy).len();
        if shard_count != participants.len() {
            warn!(
                %commitment,
                shard_count,
                participants = participants.len(),
                "cannot broadcast shards: participant/shard count mismatch"
            );
            return;
        }

        // Broadcast each shard to the corresponding participant.
        for (index, peer) in participants.iter().enumerate() {
            if me.is_some_and(|m| m.get() as usize == index) {
                continue;
            }

            let Some(shard) = block.shard(index as u16) else {
                warn!(
                    %commitment,
                    index,
                    "cannot broadcast shards: missing shard for participant index"
                );
                return;
            };
            let _ = sender
                .send(Recipients::One(peer.clone()), shard, true)
                .await;
        }

        // Cache the block so we don't have to reconstruct it again.
        let block = Arc::new(block);
        self.cache_block(block);

        // Local proposals bypass reconstruction, so shard subscribers waiting
        // for "our valid shard arrived" still need a notification.
        self.notify_shard_subscribers(commitment);

        debug!(?commitment, "broadcasted shards to participants");
    }

    /// Broadcasts a [`Shard`] to all participants.
    async fn broadcast_weak_shard<Sr: Sender<PublicKey = P>>(
        &mut self,
        sender: &mut WrappedSender<Sr, Shard<C, H>>,
        shard: Shard<C, H>,
    ) {
        let commitment = shard.commitment();
        if let Ok(peers) = sender.send(Recipients::All, shard, true).await {
            debug!(
                ?commitment,
                peers = peers.len(),
                "broadcasted shard to all participants"
            );
        }
    }

    /// Broadcasts any pending weak shard for the given commitment and attempts
    /// reconstruction. If reconstruction succeeds or fails, the state is cleaned
    /// up and subscribers are notified.
    async fn try_advance<Sr: Sender<PublicKey = P>>(
        &mut self,
        sender: &mut WrappedSender<Sr, Shard<C, H>>,
        commitment: Commitment,
    ) {
        if let Some(weak_shard) = self
            .state
            .get_mut(&commitment)
            .and_then(|s| s.take_weak_shard())
        {
            self.broadcast_weak_shard(sender, weak_shard).await;
            self.notify_shard_subscribers(commitment);
        }

        match self.try_reconstruct(commitment) {
            Ok(Some(block)) => {
                // Do not prune other reconstruction state here. A Byzantine
                // leader can equivocate by proposing multiple commitments in
                // the same round, so more than one block may be reconstructed
                // for a given round. Pruning is deferred to `prune()`, which
                // is called once a commitment is finalized.
                debug!(
                    %commitment,
                    parent = %block.parent(),
                    height = %block.height(),
                    "successfully reconstructed block from shards"
                );
            }
            Ok(None) => {
                debug!(%commitment, "not enough checked shards to reconstruct block");
            }
            Err(err) => {
                warn!(%commitment, ?err, "failed to reconstruct block from checked shards");
                self.state.remove(&commitment);
                self.drop_subscriptions(commitment);
                self.metrics.reconstruction_failures_total.inc();
            }
        }
    }

    /// Handles the registry of a shard subscription.
    fn handle_shard_subscription(&mut self, commitment: Commitment, response: oneshot::Sender<()>) {
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
    fn handle_block_subscription(
        &mut self,
        key: BlockSubscriptionKey<B::Digest>,
        response: oneshot::Sender<Arc<CodedBlock<B, C, H>>>,
    ) {
        let block = match key {
            BlockSubscriptionKey::Commitment(commitment) => {
                self.reconstructed_blocks.get(&commitment)
            }
            BlockSubscriptionKey::Digest(digest) => self
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
    fn notify_shard_subscribers(&mut self, commitment: Commitment) {
        if let Some(mut subscribers) = self.shard_subscriptions.remove(&commitment) {
            for subscriber in subscribers.drain(..) {
                subscriber.send_lossy(());
            }
        }
    }

    /// Notifies and cleans up any subscriptions for a reconstructed block.
    fn notify_block_subscribers(&mut self, block: Arc<CodedBlock<B, C, H>>) {
        let commitment = block.commitment();
        let digest = block.digest();

        // Notify by-commitment subscribers.
        if let Some(mut subscribers) = self
            .block_subscriptions
            .remove(&BlockSubscriptionKey::Commitment(commitment))
        {
            for subscriber in subscribers.drain(..) {
                subscriber.send_lossy(Arc::clone(&block));
            }
        }

        // Notify by-digest subscribers.
        if let Some(mut subscribers) = self
            .block_subscriptions
            .remove(&BlockSubscriptionKey::Digest(digest))
        {
            for subscriber in subscribers.drain(..) {
                subscriber.send_lossy(Arc::clone(&block));
            }
        }
    }

    /// Drops all subscriptions associated with a commitment.
    ///
    /// Removing these entries drops all senders, causing receivers to resolve
    /// with cancellation (`RecvError`) instead of hanging indefinitely.
    fn drop_subscriptions(&mut self, commitment: Commitment) {
        self.shard_subscriptions.remove(&commitment);
        self.block_subscriptions
            .remove(&BlockSubscriptionKey::Commitment(commitment));
        self.block_subscriptions
            .remove(&BlockSubscriptionKey::Digest(
                commitment.block::<B::Digest>(),
            ));
    }

    /// Prunes all blocks in the reconstructed block cache that are older than the block
    /// with the given commitment. Also cleans up stale reconstruction state
    /// and subscriptions.
    ///
    /// This is the only place reconstruction state is pruned by round. We
    /// intentionally avoid pruning on reconstruction success because a
    /// Byzantine leader can equivocate, producing multiple valid commitments
    /// in the same round. Both must remain recoverable until finalization
    /// determines which one is canonical.
    fn prune(&mut self, through: Commitment) {
        if let Some(height) = self.reconstructed_blocks.get(&through).map(|b| b.height()) {
            self.reconstructed_blocks
                .retain(|_, block| block.height() > height);
        }

        // Always clear direct state/subscriptions for the pruned commitment.
        // This avoids dangling waiters when prune is called for a commitment
        // that was never reconstructed locally.
        self.drop_subscriptions(through);
        let Some(round) = self.state.remove(&through).map(|state| state.round()) else {
            return;
        };

        let mut pruned_commitments = Vec::new();
        self.state.retain(|c, s| {
            let keep = s.round() > round;
            if !keep {
                pruned_commitments.push(*c);
            }
            keep
        });
        for pruned in pruned_commitments {
            self.drop_subscriptions(pruned);
        }
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
    /// The round for which this commitment was externally proposed.
    round: Round,
    /// The strong shard data received from the leader, retained for equivocation detection.
    received_strong: Option<C::StrongShard>,
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
    commitment: Commitment,
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
    /// Create a new empty common state for the provided leader and round.
    fn new(leader: P, round: Round, participants_len: u64) -> Self {
        Self {
            leader,
            our_weak_shard: None,
            checked_shards: Vec::new(),
            contributed: BitMap::zeroes(participants_len),
            round,
            received_strong: None,
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
        let received_strong = data.clone();
        let Ok((checking_data, checked, weak_shard_data)) =
            C::weaken(&commitment.config(), &commitment.root(), index, data)
        else {
            warn!(?sender, "invalid strong shard received, blocking peer");
            blocker.block(sender).await;
            return false;
        };

        // Only persist the strong shard (for later equivocation detection) after
        // it has passed `C::weaken` verification.
        self.common.received_strong = Some(received_strong);
        self.common.contributed.set(u64::from(index), true);
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
        commitment: Commitment,
        participants_len: u64,
        strategy: &impl Strategy,
        blocker: &mut impl Blocker<PublicKey = P>,
    ) -> Option<ReadyState<P, C, H>> {
        self.checking_data.as_ref()?;
        let minimum = usize::from(commitment.config().minimum_shards.get());
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
                    &commitment.root(),
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
        let round = self.common.round;
        let leader = self.common.leader.clone();
        let common = std::mem::replace(
            &mut self.common,
            CommonState::new(leader, round, participants_len),
        );
        Some(ReadyState {
            common,
            checking_data,
        })
    }
}

/// Context required for processing incoming network shards.
struct InsertCtx<'a, Sch, S>
where
    Sch: CertificateScheme,
    S: Strategy,
{
    scheme: &'a Sch,
    strategy: &'a S,
    participants_len: u64,
}

impl<Sch: CertificateScheme, S: Strategy> Clone for InsertCtx<'_, Sch, S> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<Sch: CertificateScheme, S: Strategy> Copy for InsertCtx<'_, Sch, S> {}

impl<'a, Sch: CertificateScheme, S: Strategy> InsertCtx<'a, Sch, S> {
    fn new(scheme: &'a Sch, strategy: &'a S) -> Self {
        let participants_len = u64::try_from(scheme.participants().len())
            .expect("participant count impossibly out of bounds");
        Self {
            scheme,
            strategy,
            participants_len,
        }
    }
}

impl<P, C, H> ReconstructionState<P, C, H>
where
    P: PublicKey,
    C: CodingScheme,
    H: Hasher,
{
    /// Create an initial reconstruction state for a commitment.
    fn new(leader: P, round: Round, participants_len: u64) -> Self {
        Self::AwaitingQuorum(AwaitingQuorumState {
            common: CommonState::new(leader, round, participants_len),
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

    /// Return the proposal round associated with this state.
    const fn round(&self) -> Round {
        self.common().round
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
    /// - The leader may only send ONE strong shard. Sending a second strong shard
    ///   with different data (equivocation) results in blocking the sender. Exact
    ///   duplicates are silently ignored.
    /// - MUST pass cryptographic verification via [`CodingScheme::weaken`].
    /// - When leader is unknown, buffering happens at the engine level in
    ///   bounded pre-leader queues until [`Discovered`](super::Message::Discovered)
    ///   creates a reconstruction state for this commitment.
    ///
    /// Weak shards (`CodingScheme::WeakShard`):
    /// - MUST be sent by a participant.
    /// - MUST be sent by the participant whose index matches the shard index.
    /// - MUST pass cryptographic verification via [`CodingScheme::check`].
    /// - Each participant may only contribute ONE weak shard per commitment.
    ///   Sending a second weak shard with different data (equivocation) results
    ///   in blocking the sender. Exact duplicates are silently ignored.
    /// - Weak shards that arrive after the state has transitioned to `Ready`
    ///   (i.e., batch validation has already passed) are silently discarded.
    ///   The sender's contribution slot is still consumed, preventing future
    ///   submissions from the same participant.
    ///
    /// Handle an incoming network shard.
    ///
    /// Returns `true` only when the shard caused state progress (buffered,
    /// validated, or transitioned), and `false` when rejected/blocked.
    async fn on_network_shard<Sch, S, X>(
        &mut self,
        sender: P,
        shard: Shard<C, H>,
        ctx: InsertCtx<'_, Sch, S>,
        blocker: &mut X,
    ) -> bool
    where
        Sch: CertificateScheme<PublicKey = P>,
        S: Strategy,
        X: Blocker<PublicKey = P>,
    {
        let Some(sender_index) = ctx.scheme.participants().index(&sender) else {
            warn!(?sender, "shard sent by non-participant, blocking peer");
            blocker.block(sender).await;
            return false;
        };
        let commitment = shard.commitment();
        let index = shard.index();

        let progressed = match shard.into_inner() {
            DistributionShard::Strong(data) => {
                let strong = StrongShard {
                    commitment,
                    index,
                    data,
                };
                self.insert_strong_shard(ctx.scheme.me().as_ref(), sender, strong, blocker)
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
                if let Some(ready) = state
                    .try_transition(commitment, ctx.participants_len, ctx.strategy, blocker)
                    .await
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

        let common = self.common();
        if sender != common.leader {
            warn!(
                ?sender,
                leader = ?common.leader,
                "strong shard from non-leader, blocking peer"
            );
            blocker.block(sender).await;
            return false;
        }
        if let Some(received_strong) = common.received_strong.as_ref() {
            if received_strong != &shard.data {
                warn!(
                    ?sender,
                    "strong shard equivocation from leader, blocking peer"
                );
                blocker.block(sender).await;
            }
            return false;
        }

        match self {
            Self::AwaitingQuorum(state) => state.verify_strong_shard(sender, shard, blocker).await,
            Self::Ready(_) => false,
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
            let equivocated = matches!(
                self,
                Self::AwaitingQuorum(state)
                    if state.pending_weak_shards.get(&sender).is_some_and(|existing| existing.data != shard.data)
            );
            if equivocated {
                warn!(
                    ?sender,
                    "duplicate weak shard with different data, blocking peer"
                );
                blocker.block(sender).await;
            }
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
    use commonware_coding::{CodecConfig, Config as CodingConfig, ReedSolomon, Zoda};
    use commonware_cryptography::{
        certificate::Subject,
        ed25519::{PrivateKey, PublicKey},
        impl_certificate_ed25519,
        sha256::Digest as Sha256Digest,
        Committable, Digest, Sha256, Signer,
    };
    use commonware_macros::{select, test_traced};
    use commonware_p2p::{
        simulated::{self, Control, Link, Oracle},
        Provider as _,
    };
    use commonware_parallel::Sequential;
    use commonware_runtime::{deterministic, Quota, Runner};
    use commonware_utils::{
        channel::oneshot::error::TryRecvError, ordered::Set, NZUsize, Participant,
    };
    use std::{future::Future, marker::PhantomData, num::NonZeroU32, time::Duration};

    #[derive(Clone, Debug)]
    pub struct TestSubject {
        pub message: Bytes,
    }

    impl Subject for TestSubject {
        type Namespace = Vec<u8>;

        fn namespace<'a>(&self, derived: &'a Self::Namespace) -> &'a [u8] {
            derived
        }

        fn message(&self) -> Bytes {
            self.message.clone()
        }
    }

    impl_certificate_ed25519!(TestSubject, Vec<u8>);

    const SCHEME_NAMESPACE: &[u8] = b"_COMMONWARE_SHARD_ENGINE_TEST";

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

    /// A scheme provider that maps each epoch to a potentially different scheme.
    ///
    /// For most tests only epoch 0 is registered, matching the previous
    /// `ConstantProvider` behaviour. Cross-epoch tests register additional
    /// epochs with different participant sets.
    #[derive(Clone)]
    struct MultiEpochProvider {
        schemes: BTreeMap<Epoch, Arc<Scheme>>,
    }

    impl MultiEpochProvider {
        fn single(scheme: Scheme) -> Self {
            let mut schemes = BTreeMap::new();
            schemes.insert(Epoch::zero(), Arc::new(scheme));
            Self { schemes }
        }

        fn with_epoch(mut self, epoch: Epoch, scheme: Scheme) -> Self {
            self.schemes.insert(epoch, Arc::new(scheme));
            self
        }
    }

    impl Provider for MultiEpochProvider {
        type Scope = Epoch;
        type Scheme = Scheme;

        fn scoped(&self, scope: Epoch) -> Option<Arc<Scheme>> {
            self.schemes.get(&scope).cloned()
        }
    }

    // Type aliases for test convenience.
    type B = MockBlock<Sha256Digest, ()>;
    type H = Sha256;
    type P = PublicKey;
    type C = ReedSolomon<H>;
    type X = Control<P, deterministic::Context>;
    type O = Oracle<P, deterministic::Context>;
    type Prov = MultiEpochProvider;
    type NetworkSender = simulated::Sender<P, deterministic::Context>;
    type ShardEngine<S> = Engine<deterministic::Context, Prov, X, S, H, B, P, Sequential>;

    async fn assert_blocked(oracle: &O, blocker: &P, blocked: &P) {
        let blocked_peers = oracle.blocked().await.unwrap();
        let is_blocked = blocked_peers
            .iter()
            .any(|(a, b)| a == blocker && b == blocked);
        assert!(is_blocked, "expected {blocker} to have blocked {blocked}");
    }

    /// A participant in the test network with its engine mailbox and blocker.
    struct Peer<S: CodingScheme = C> {
        /// The peer's public key.
        public_key: PublicKey,
        /// The peer's index in the participant set.
        index: Participant,
        /// The mailbox for sending messages to the peer's shard engine.
        mailbox: Mailbox<B, S, H, P>,
        /// Raw network sender for injecting messages (e.g., byzantine behavior).
        sender: NetworkSender,
    }

    /// Test fixture for setting up multiple participants with shard engines.
    struct Fixture<S: CodingScheme = C> {
        /// Number of peers in the test network.
        num_peers: usize,
        /// Network link configuration.
        link: Link,
        /// Marker for the coding scheme type parameter.
        _marker: PhantomData<S>,
    }

    impl<S: CodingScheme> Default for Fixture<S> {
        fn default() -> Self {
            Self {
                num_peers: 4,
                link: DEFAULT_LINK,
                _marker: PhantomData,
            }
        }
    }

    impl<S: CodingScheme> Fixture<S> {
        pub fn start<F: Future<Output = ()>>(
            self,
            f: impl FnOnce(Self, deterministic::Context, O, Vec<Peer<S>>, CodingConfig) -> F,
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

                let mut private_keys = (0..self.num_peers)
                    .map(|i| PrivateKey::from_seed(i as u64))
                    .collect::<Vec<_>>();
                private_keys.sort_by_key(|s| s.public_key());
                let peer_keys: Vec<P> = private_keys.iter().map(|c| c.public_key()).collect();

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

                    let scheme = Scheme::signer(
                        SCHEME_NAMESPACE,
                        participants.clone(),
                        private_keys[idx].clone(),
                    )
                    .expect("signer scheme should be created");
                    let scheme_provider: Prov = MultiEpochProvider::single(scheme);

                    let config = Config {
                        scheme_provider,
                        blocker: control.clone(),
                        shard_codec_cfg: CodecConfig {
                            maximum_shard_size: MAX_SHARD_SIZE,
                        },
                        block_codec_cfg: (),
                        strategy: STRATEGY,
                        mailbox_size: 1024,
                        peer_buffer_size: NZUsize!(64),
                        background_channel_capacity: 1024,
                        peer_set_subscription: oracle.manager().subscribe().await,
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
            let coded_block = CodedBlock::<B, C, H>::new(inner, coding_config, &STRATEGY);
            let commitment = coded_block.commitment();

            let leader = peers[0].public_key.clone();
            let round = Round::new(Epoch::zero(), View::new(1));
            peers[0].mailbox.proposed(round, coded_block.clone()).await;

            // Inform all peers of the leader so strong shards are processed.
            for peer in peers[1..].iter_mut() {
                peer.mailbox
                    .discovered(commitment, leader.clone(), round)
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
    fn test_e2e_broadcast_and_reconstruction_zoda() {
        let fixture = Fixture {
            num_peers: 10,
            ..Default::default()
        };

        fixture.start(|config, context, _, mut peers, coding_config| async move {
            let inner = B::new::<H>((), Sha256Digest::EMPTY, Height::new(1), 100);
            let coded_block = CodedBlock::<B, Zoda<H>, H>::new(inner, coding_config, &STRATEGY);
            let commitment = coded_block.commitment();

            let leader = peers[0].public_key.clone();
            let round = Round::new(Epoch::zero(), View::new(1));
            peers[0].mailbox.proposed(round, coded_block.clone()).await;

            // Inform all peers of the leader so strong shards are processed.
            for peer in peers[1..].iter_mut() {
                peer.mailbox
                    .discovered(commitment, leader.clone(), round)
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
            let coded_block = CodedBlock::<B, C, H>::new(inner, coding_config, &STRATEGY);
            let commitment = coded_block.commitment();
            let digest = coded_block.digest();

            let leader = peers[0].public_key.clone();
            let round = Round::new(Epoch::zero(), View::new(1));

            // Subscribe before broadcasting.
            let commitment_sub = peers[1].mailbox.subscribe(commitment).await;
            let digest_sub = peers[2].mailbox.subscribe_by_digest(digest).await;

            peers[0].mailbox.proposed(round, coded_block.clone()).await;

            // Inform all peers of the leader so strong shards are processed.
            for peer in peers[1..].iter_mut() {
                peer.mailbox
                    .discovered(commitment, leader.clone(), round)
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
    fn test_proposer_preproposal_subscriptions_resolve_after_local_cache() {
        let fixture = Fixture {
            num_peers: 10,
            ..Default::default()
        };

        fixture.start(|config, context, _, peers, coding_config| async move {
            let inner = B::new::<H>((), Sha256Digest::EMPTY, Height::new(1), 100);
            let coded_block = CodedBlock::<B, C, H>::new(inner, coding_config, &STRATEGY);
            let commitment = coded_block.commitment();
            let digest = coded_block.digest();
            let round = Round::new(Epoch::zero(), View::new(1));

            // Subscribe on the proposer before it caches the locally proposed block.
            let shard_sub = peers[0].mailbox.subscribe_shard(commitment).await;
            let commitment_sub = peers[0].mailbox.subscribe(commitment).await;
            let digest_sub = peers[0].mailbox.subscribe_by_digest(digest).await;

            peers[0].mailbox.proposed(round, coded_block.clone()).await;
            context.sleep(config.link.latency).await;

            select! {
                result = shard_sub => {
                    result.expect("shard subscription should resolve");
                },
                _ = context.sleep(Duration::from_secs(5)) => {
                    panic!("shard subscription did not resolve after local proposal cache");
                }
            }

            let block_by_commitment = select! {
                result = commitment_sub => {
                    result.expect("block subscription by commitment should resolve")
                },
                _ = context.sleep(Duration::from_secs(5)) => {
                    panic!("block subscription by commitment did not resolve after local proposal cache");
                }
            };
            assert_eq!(block_by_commitment.commitment(), commitment);
            assert_eq!(block_by_commitment.height(), coded_block.height());

            let block_by_digest = select! {
                result = digest_sub => {
                    result.expect("block subscription by digest should resolve")
                },
                _ = context.sleep(Duration::from_secs(5)) => {
                    panic!("block subscription by digest did not resolve after local proposal cache");
                }
            };
            assert_eq!(block_by_digest.commitment(), commitment);
            assert_eq!(block_by_digest.height(), coded_block.height());
        });
    }

    #[test_traced]
    fn test_shard_subscription_rejects_invalid_shard() {
        let fixture = Fixture::<C>::default();
        fixture.start(
            |config, context, oracle, mut peers, coding_config| async move {
                // peers[0] = byzantine
                // peers[1] = honest proposer
                // peers[2] = receiver

                let inner = B::new::<H>((), Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block = CodedBlock::<B, C, H>::new(inner, coding_config, &STRATEGY);
                let commitment = coded_block.commitment();
                let receiver_index = peers[2].index.get() as u16;

                let valid_shard = coded_block.shard(receiver_index).expect("missing shard");

                // corrupt the shard's index
                let mut invalid_shard = valid_shard.clone();
                invalid_shard.index = 0;

                // Receiver subscribes to their shard and learns the leader.
                let receiver_pk = peers[2].public_key.clone();
                let leader = peers[1].public_key.clone();
                peers[2]
                    .mailbox
                    .discovered(commitment, leader, Round::new(Epoch::zero(), View::new(1)))
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
                    },
                };
            },
        );
    }

    #[test_traced]
    fn test_durable_prunes_reconstructed_blocks() {
        let fixture = Fixture::<C>::default();
        fixture.start(|_, context, _, mut peers, coding_config| async move {
            // Create 3 blocks at heights 1, 2, 3.
            let block1 = CodedBlock::<B, C, H>::new(
                B::new::<H>((), Sha256Digest::EMPTY, Height::new(1), 100),
                coding_config,
                &STRATEGY,
            );
            let block2 = CodedBlock::<B, C, H>::new(
                B::new::<H>((), Sha256Digest::EMPTY, Height::new(2), 100),
                coding_config,
                &STRATEGY,
            );
            let block3 = CodedBlock::<B, C, H>::new(
                B::new::<H>((), Sha256Digest::EMPTY, Height::new(3), 100),
                coding_config,
                &STRATEGY,
            );
            let commitment1 = block1.commitment();
            let commitment2 = block2.commitment();
            let commitment3 = block3.commitment();

            // Cache all blocks via `proposed`.
            let peer = &mut peers[0];
            let round = Round::new(Epoch::zero(), View::new(1));
            peer.mailbox.proposed(round, block1).await;
            peer.mailbox.proposed(round, block2).await;
            peer.mailbox.proposed(round, block3).await;
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
            peer.mailbox.prune(commitment2).await;
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
    fn test_duplicate_leader_strong_shard_ignored() {
        let fixture = Fixture::<C>::default();
        fixture.start(
            |config, context, oracle, mut peers, coding_config| async move {
                let inner = B::new::<H>((), Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block = CodedBlock::<B, C, H>::new(inner, coding_config, &STRATEGY);
                let commitment = coded_block.commitment();

                // Get peer 2's strong shard.
                let peer2_index = peers[2].index.get() as u16;
                let peer2_strong_shard = coded_block.shard(peer2_index).expect("missing shard");
                let strong_bytes = peer2_strong_shard.encode();

                let peer2_pk = peers[2].public_key.clone();
                let leader = peers[0].public_key.clone();

                // Inform peer 2 that peer 0 is the leader.
                peers[2]
                    .mailbox
                    .discovered(commitment, leader, Round::new(Epoch::zero(), View::new(1)))
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

                // Send the same strong shard again from peer 0 (leader duplicate - ignored).
                peers[0]
                    .sender
                    .send(Recipients::One(peer2_pk), strong_bytes, true)
                    .await
                    .expect("send failed");
                context.sleep(config.link.latency * 2).await;

                // The leader should NOT be blocked for sending an identical duplicate.
                let blocked_peers = oracle.blocked().await.unwrap();
                let is_blocked = blocked_peers
                    .iter()
                    .any(|(a, b)| a == &peers[2].public_key && b == &peers[0].public_key);
                assert!(
                    !is_blocked,
                    "leader should not be blocked for duplicate strong shard"
                );
            },
        );
    }

    #[test_traced]
    fn test_equivocating_leader_strong_shard_blocks_peer() {
        let fixture = Fixture::<C>::default();
        fixture.start(
            |config, context, oracle, mut peers, coding_config| async move {
                let inner1 = B::new::<H>((), Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block1 = CodedBlock::<B, C, H>::new(inner1, coding_config, &STRATEGY);
                let commitment = coded_block1.commitment();

                // Create a second block with different payload to get different shard data.
                let inner2 = B::new::<H>((), Sha256Digest::EMPTY, Height::new(1), 200);
                let coded_block2 = CodedBlock::<B, C, H>::new(inner2, coding_config, &STRATEGY);

                // Get peer 2's strong shard from both blocks.
                let peer2_index = peers[2].index.get() as u16;
                let strong_bytes1 = coded_block1
                    .shard(peer2_index)
                    .expect("missing shard")
                    .encode();
                let mut equivocating_shard =
                    coded_block2.shard(peer2_index).expect("missing shard");
                // Override the commitment so it targets the same reconstruction state.
                equivocating_shard.commitment = commitment;
                let strong_bytes2 = equivocating_shard.encode();

                let peer2_pk = peers[2].public_key.clone();
                let leader = peers[0].public_key.clone();

                // Inform peer 2 that peer 0 is the leader.
                peers[2]
                    .mailbox
                    .discovered(commitment, leader, Round::new(Epoch::zero(), View::new(1)))
                    .await;

                // Send peer 2 their strong shard from the leader (first time - succeeds).
                peers[0]
                    .sender
                    .send(Recipients::One(peer2_pk.clone()), strong_bytes1, true)
                    .await
                    .expect("send failed");
                context.sleep(config.link.latency * 2).await;

                // Send a different strong shard from the leader (equivocation - should block).
                peers[0]
                    .sender
                    .send(Recipients::One(peer2_pk), strong_bytes2, true)
                    .await
                    .expect("send failed");
                context.sleep(config.link.latency * 2).await;

                // Peer 2 should have blocked the leader for equivocation.
                assert_blocked(&oracle, &peers[2].public_key, &peers[0].public_key).await;
            },
        );
    }

    #[test_traced]
    fn test_non_leader_strong_shard_blocked() {
        // Test that a non-leader sending a strong shard is blocked.
        let fixture = Fixture::<C>::default();
        fixture.start(
            |config, context, oracle, mut peers, coding_config| async move {
                let inner = B::new::<H>((), Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block = CodedBlock::<B, C, H>::new(inner, coding_config, &STRATEGY);
                let commitment = coded_block.commitment();

                // Get peer 2's strong shard.
                let peer2_index = peers[2].index.get() as u16;
                let peer2_strong_shard = coded_block.shard(peer2_index).expect("missing shard");
                let strong_bytes = peer2_strong_shard.encode();

                let peer2_pk = peers[2].public_key.clone();
                let leader = peers[0].public_key.clone();

                // Inform peer 2 that peer 0 is the leader.
                peers[2]
                    .mailbox
                    .discovered(commitment, leader, Round::new(Epoch::zero(), View::new(1)))
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
        let fixture = Fixture::<C>::default();
        fixture.start(
            |config, context, oracle, mut peers, coding_config| async move {
                let inner = B::new::<H>((), Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block = CodedBlock::<B, C, H>::new(inner, coding_config, &STRATEGY);
                let commitment = coded_block.commitment();

                // Get peer 2's strong shard.
                let peer2_index = peers[2].index.get() as u16;
                let peer2_strong_shard = coded_block.shard(peer2_index).expect("missing shard");
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
                    .discovered(commitment, leader, Round::new(Epoch::zero(), View::new(1)))
                    .await;
                context.sleep(Duration::from_millis(10)).await;

                assert_blocked(&oracle, &peers[2].public_key, &peers[1].public_key).await;
            },
        );
    }

    #[test_traced]
    fn test_conflicting_external_proposed_ignored() {
        let fixture = Fixture::<C>::default();
        fixture.start(
            |config, context, oracle, mut peers, coding_config| async move {
                let inner = B::new::<H>((), Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block = CodedBlock::<B, C, H>::new(inner, coding_config, &STRATEGY);
                let commitment = coded_block.commitment();

                // Get peer 2's strong shard.
                let peer2_index = peers[2].index.get() as u16;
                let peer2_strong_shard = coded_block.shard(peer2_index).expect("missing shard");
                let strong_bytes = peer2_strong_shard.encode();

                let peer2_pk = peers[2].public_key.clone();
                let leader_a = peers[0].public_key.clone();
                let leader_b = peers[1].public_key.clone();

                // Subscribe before shards arrive so we can verify acceptance.
                let shard_sub = peers[2].mailbox.subscribe_shard(commitment).await;

                // First leader update should stick.
                peers[2]
                    .mailbox
                    .discovered(
                        commitment,
                        leader_a.clone(),
                        Round::new(Epoch::zero(), View::new(1)),
                    )
                    .await;
                // Conflicting update should be ignored.
                peers[2]
                    .mailbox
                    .discovered(
                        commitment,
                        leader_b,
                        Round::new(Epoch::zero(), View::new(1)),
                    )
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
                        panic!(
                            "subscription did not complete after strong shard from original leader"
                        );
                    },
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
        let fixture = Fixture::<C>::default();
        fixture.start(
            |config, context, oracle, mut peers, coding_config| async move {
                let inner = B::new::<H>((), Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block = CodedBlock::<B, C, H>::new(inner, coding_config, &STRATEGY);
                let commitment = coded_block.commitment();

                // Get peer 2's strong shard.
                let peer2_index = peers[2].index.get() as u16;
                let peer2_strong_shard = coded_block.shard(peer2_index).expect("missing shard");
                let strong_bytes = peer2_strong_shard.encode();

                let peer2_pk = peers[2].public_key.clone();
                let leader = peers[0].public_key.clone();
                let non_participant_leader = PrivateKey::from_seed(10_000).public_key();

                // Subscribe before shards arrive.
                let shard_sub = peers[2].mailbox.subscribe_shard(commitment).await;

                // A non-participant leader update should be ignored.
                peers[2]
                    .mailbox
                    .discovered(
                        commitment,
                        non_participant_leader,
                        Round::new(Epoch::zero(), View::new(1)),
                    )
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
                    .discovered(commitment, leader, Round::new(Epoch::zero(), View::new(1)))
                    .await;
                context.sleep(config.link.latency * 2).await;

                select! {
                    _ = shard_sub => {},
                    _ = context.sleep(Duration::from_secs(5)) => {
                        panic!("subscription did not complete after valid leader update");
                    },
                };
            },
        );
    }

    #[test_traced]
    fn test_shard_from_non_participant_blocks_peer() {
        let fixture = Fixture::<C>::default();
        fixture.start(|config, context, oracle, peers, coding_config| async move {
            let inner = B::new::<H>((), Sha256Digest::EMPTY, Height::new(1), 100);
            let coded_block = CodedBlock::<B, C, H>::new(inner, coding_config, &STRATEGY);
            let commitment = coded_block.commitment();

            let leader = peers[0].public_key.clone();
            let receiver_pk = peers[2].public_key.clone();

            let non_participant_key = PrivateKey::from_seed(10_000);
            let non_participant_pk = non_participant_key.public_key();

            let non_participant_control = oracle.control(non_participant_pk.clone());
            let (mut non_participant_sender, _non_participant_receiver) = non_participant_control
                .register(0, TEST_QUOTA)
                .await
                .expect("registration should succeed");
            oracle
                .add_link(
                    non_participant_pk.clone(),
                    receiver_pk.clone(),
                    DEFAULT_LINK,
                )
                .await
                .expect("link should be added");

            peers[2]
                .mailbox
                .discovered(commitment, leader, Round::new(Epoch::zero(), View::new(1)))
                .await;

            let peer2_index = peers[2].index.get() as u16;
            let strong_shard = coded_block.shard(peer2_index).expect("missing shard");
            let weak_shard = strong_shard
                .verify_into_weak()
                .expect("verify_into_weak failed");
            let weak_bytes = weak_shard.encode();

            non_participant_sender
                .send(Recipients::One(receiver_pk), weak_bytes, true)
                .await
                .expect("send failed");
            context.sleep(config.link.latency * 2).await;

            assert_blocked(&oracle, &peers[2].public_key, &non_participant_pk).await;
        });
    }

    #[test_traced]
    fn test_buffered_shard_from_non_participant_blocks_peer() {
        let fixture = Fixture::<C>::default();
        fixture.start(|config, context, oracle, peers, coding_config| async move {
            let inner = B::new::<H>((), Sha256Digest::EMPTY, Height::new(1), 100);
            let coded_block = CodedBlock::<B, C, H>::new(inner, coding_config, &STRATEGY);
            let commitment = coded_block.commitment();

            let leader = peers[0].public_key.clone();
            let receiver_pk = peers[2].public_key.clone();

            let non_participant_key = PrivateKey::from_seed(10_000);
            let non_participant_pk = non_participant_key.public_key();

            let non_participant_control = oracle.control(non_participant_pk.clone());
            let (mut non_participant_sender, _non_participant_receiver) = non_participant_control
                .register(0, TEST_QUOTA)
                .await
                .expect("registration should succeed");
            oracle
                .add_link(
                    non_participant_pk.clone(),
                    receiver_pk.clone(),
                    DEFAULT_LINK,
                )
                .await
                .expect("link should be added");

            let peer2_index = peers[2].index.get() as u16;
            let strong_shard = coded_block.shard(peer2_index).expect("missing shard");
            let weak_shard = strong_shard
                .verify_into_weak()
                .expect("verify_into_weak failed");
            let weak_bytes = weak_shard.encode();

            non_participant_sender
                .send(Recipients::One(receiver_pk), weak_bytes, true)
                .await
                .expect("send failed");
            context.sleep(config.link.latency * 2).await;

            peers[2]
                .mailbox
                .discovered(commitment, leader, Round::new(Epoch::zero(), View::new(1)))
                .await;
            context.sleep(config.link.latency * 2).await;

            assert_blocked(&oracle, &peers[2].public_key, &non_participant_pk).await;
        });
    }

    #[test_traced]
    fn test_duplicate_weak_shard_ignored() {
        // Use 10 peers so minimum_shards=4, giving us time to send duplicate before reconstruction.
        let fixture: Fixture<C> = Fixture {
            num_peers: 10,
            ..Default::default()
        };

        fixture.start(
            |config, context, oracle, mut peers, coding_config| async move {
                let inner = B::new::<H>((), Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block = CodedBlock::<B, C, H>::new(inner, coding_config, &STRATEGY);

                // Get peer 2's strong shard (to initialize their checking_data).
                let peer2_index = peers[2].index.get() as u16;
                let peer2_strong_shard = coded_block.shard(peer2_index).expect("missing shard");

                // Get peer 1's weak shard.
                let peer1_index = peers[1].index.get() as u16;
                let peer1_strong_shard = coded_block.shard(peer1_index).expect("missing shard");
                let peer1_weak_shard = peer1_strong_shard
                    .verify_into_weak()
                    .expect("verify_into_weak failed");

                let peer2_pk = peers[2].public_key.clone();
                let leader = peers[0].public_key.clone();

                // Inform peer 2 of the leader.
                peers[2]
                    .mailbox
                    .discovered(
                        coded_block.commitment(),
                        leader,
                        Round::new(Epoch::zero(), View::new(1)),
                    )
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

                // Send the same weak shard again (exact duplicate - should be ignored, not blocked).
                // With 10 peers, minimum_shards=4, so we haven't reconstructed yet.
                peers[1]
                    .sender
                    .send(Recipients::One(peer2_pk), weak_shard_bytes, true)
                    .await
                    .expect("send failed");
                context.sleep(config.link.latency * 2).await;

                // Peer 1 should NOT be blocked for sending an identical duplicate.
                let blocked_peers = oracle.blocked().await.unwrap();
                let is_blocked = blocked_peers
                    .iter()
                    .any(|(a, b)| a == &peers[2].public_key && b == &peers[1].public_key);
                assert!(
                    !is_blocked,
                    "peer should not be blocked for exact duplicate weak shard"
                );
            },
        );
    }

    #[test_traced]
    fn test_equivocating_weak_shard_blocks_peer() {
        // Use 10 peers so minimum_shards=4, giving us time to send equivocating shard.
        let fixture: Fixture<C> = Fixture {
            num_peers: 10,
            ..Default::default()
        };

        fixture.start(
            |config, context, oracle, mut peers, coding_config| async move {
                let inner1 = B::new::<H>((), Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block1 = CodedBlock::<B, C, H>::new(inner1, coding_config, &STRATEGY);

                // Create a second block with different payload to get different shard data.
                let inner2 = B::new::<H>((), Sha256Digest::EMPTY, Height::new(1), 200);
                let coded_block2 = CodedBlock::<B, C, H>::new(inner2, coding_config, &STRATEGY);

                // Get peer 2's strong shard from block 1 (to initialize their checking_data).
                let peer2_index = peers[2].index.get() as u16;
                let peer2_strong_shard = coded_block1.shard(peer2_index).expect("missing shard");

                // Get peer 1's weak shard from block 1.
                let peer1_index = peers[1].index.get() as u16;
                let peer1_strong_shard = coded_block1.shard(peer1_index).expect("missing shard");
                let peer1_weak_shard = peer1_strong_shard
                    .verify_into_weak()
                    .expect("verify_into_weak failed");

                // Get peer 1's weak shard from block 2 (different data, same index).
                let peer1_strong_shard2 = coded_block2.shard(peer1_index).expect("missing shard");
                let mut peer1_equivocating_shard = peer1_strong_shard2
                    .verify_into_weak()
                    .expect("verify_into_weak failed");
                // Override the commitment to match block 1 so the shard targets
                // the same reconstruction state.
                peer1_equivocating_shard.commitment = coded_block1.commitment();

                let peer2_pk = peers[2].public_key.clone();
                let leader = peers[0].public_key.clone();

                // Inform peer 2 of the leader.
                peers[2]
                    .mailbox
                    .discovered(
                        coded_block1.commitment(),
                        leader,
                        Round::new(Epoch::zero(), View::new(1)),
                    )
                    .await;

                // Send peer 2 their strong shard (initializes checking_data).
                let strong_bytes = peer2_strong_shard.encode();
                peers[0]
                    .sender
                    .send(Recipients::One(peer2_pk.clone()), strong_bytes, true)
                    .await
                    .expect("send failed");
                context.sleep(config.link.latency * 2).await;

                // Send peer 1's valid weak shard to peer 2 (first time - succeeds).
                let weak_shard_bytes = peer1_weak_shard.encode();
                peers[1]
                    .sender
                    .send(Recipients::One(peer2_pk.clone()), weak_shard_bytes, true)
                    .await
                    .expect("send failed");
                context.sleep(config.link.latency * 2).await;

                // Send a different weak shard from peer 1 (equivocation - should block).
                let equivocating_bytes = peer1_equivocating_shard.encode();
                peers[1]
                    .sender
                    .send(Recipients::One(peer2_pk), equivocating_bytes, true)
                    .await
                    .expect("send failed");
                context.sleep(config.link.latency * 2).await;

                // Peer 2 should have blocked peer 1 for equivocation.
                assert_blocked(&oracle, &peers[2].public_key, &peers[1].public_key).await;
            },
        );
    }

    #[test_traced]
    fn test_reconstruction_states_pruned_at_or_below_reconstructed_view() {
        // Use 10 peers so minimum_shards=4.
        let fixture: Fixture<C> = Fixture {
            num_peers: 10,
            ..Default::default()
        };

        fixture.start(
            |config, context, oracle, mut peers, coding_config| async move {
                // Commitment A at lower view (1).
                let block_a = CodedBlock::<B, C, H>::new(
                    B::new::<H>((), Sha256Digest::EMPTY, Height::new(1), 100),
                    coding_config,
                    &STRATEGY,
                );
                let commitment_a = block_a.commitment();

                // Commitment B at higher view (2), which we will reconstruct.
                let block_b = CodedBlock::<B, C, H>::new(
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
                    .discovered(
                        commitment_a,
                        leader.clone(),
                        Round::new(Epoch::zero(), View::new(1)),
                    )
                    .await;
                let peer1_strong_a = block_a
                    .shard(peers[1].index.get() as u16)
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
                    .discovered(
                        commitment_b,
                        leader,
                        Round::new(Epoch::zero(), View::new(2)),
                    )
                    .await;
                // Strong shard for peer2 from leader.
                let strong_b = block_b
                    .shard(peers[2].index.get() as u16)
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
                        .shard(peers[i].index.get() as u16)
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
        let fixture: Fixture<C> = Fixture {
            num_peers: 10,
            ..Default::default()
        };

        fixture.start(
            |config, context, oracle, mut peers, coding_config| async move {
                let inner = B::new::<H>((), Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block = CodedBlock::<B, C, H>::new(inner, coding_config, &STRATEGY);
                let commitment = coded_block.commitment();

                // Get peer 3's strong shard.
                let peer3_index = peers[3].index.get() as u16;
                let peer3_strong_shard = coded_block.shard(peer3_index).expect("missing shard");

                // Get weak shards from peers 0, 1, and 2 (3 total to meet minimum_shards=4).
                let weak_shards: Vec<_> = [0, 1, 2]
                    .iter()
                    .map(|&i| {
                        coded_block
                            .shard(peers[i].index.get() as u16)
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
                    .discovered(commitment, leader, Round::new(Epoch::zero(), View::new(1)))
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
    fn test_peer_shards_buffered_until_external_proposed() {
        // Test that shards received before leader announcement do not progress
        // reconstruction until Discovered is delivered.
        let fixture: Fixture<C> = Fixture {
            num_peers: 10,
            ..Default::default()
        };

        fixture.start(
            |config, context, oracle, mut peers, coding_config| async move {
                let inner = B::new::<H>((), Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block = CodedBlock::<B, C, H>::new(inner, coding_config, &STRATEGY);
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
                    .shard(peers[receiver_idx].index.get() as u16)
                    .expect("missing shard")
                    .encode();
                peers[0]
                    .sender
                    .send(Recipients::One(receiver_pk.clone()), strong, true)
                    .await
                    .expect("send failed");

                for i in [1usize, 2usize, 4usize] {
                    let weak = coded_block
                        .shard(peers[i].index.get() as u16)
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
                    .discovered(commitment, leader, Round::new(Epoch::zero(), View::new(1)))
                    .await;

                select! {
                    _ = shard_sub => {},
                    _ = context.sleep(Duration::from_secs(5)) => {
                        panic!("shard subscription did not resolve after leader announcement");
                    },
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
        let fixture: Fixture<C> = Fixture {
            num_peers: 10,
            ..Default::default()
        };

        fixture.start(
            |config, context, oracle, mut peers, coding_config| async move {
                let inner = B::new::<H>((), Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block = CodedBlock::<B, C, H>::new(inner, coding_config, &STRATEGY);
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
                    .discovered(
                        commitment,
                        leader.clone(),
                        Round::new(Epoch::zero(), View::new(1)),
                    )
                    .await;

                // Send leader strong shard after leader is known.
                let strong = coded_block
                    .shard(peers[receiver_idx].index.get() as u16)
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
                    },
                }

                // Send enough weak shards after leader known to reconstruct.
                for i in [1usize, 2usize, 4usize] {
                    let weak = coded_block
                        .shard(peers[i].index.get() as u16)
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
    fn test_invalid_shard_codec_blocks_peer() {
        // Test that receiving an invalid shard (codec failure) blocks the sender.
        let fixture: Fixture<C> = Fixture {
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
    fn test_duplicate_buffered_strong_shard_does_not_block_before_leader() {
        // Test that duplicate strong shards before leader announcement are
        // buffered and do not immediately block the sender.
        let fixture: Fixture<C> = Fixture {
            ..Default::default()
        };

        fixture.start(
            |config, context, oracle, mut peers, coding_config| async move {
                let inner = B::new::<H>((), Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block = CodedBlock::<B, C, H>::new(inner, coding_config, &STRATEGY);

                // Get peer 2's strong shard.
                let peer2_index = peers[2].index.get() as u16;
                let peer2_strong_shard = coded_block.shard(peer2_index).expect("missing shard");
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
        let fixture: Fixture<C> = Fixture {
            ..Default::default()
        };

        fixture.start(
            |config, context, oracle, mut peers, coding_config| async move {
                // Create two different blocks — shard from block2 won't verify
                // against commitment from block1.
                let inner1 = B::new::<H>((), Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block1 = CodedBlock::<B, C, H>::new(inner1, coding_config, &STRATEGY);
                let commitment1 = coded_block1.commitment();

                let inner2 = B::new::<H>((), Sha256Digest::EMPTY, Height::new(2), 200);
                let coded_block2 = CodedBlock::<B, C, H>::new(inner2, coding_config, &STRATEGY);

                // Get peer 2's strong shard from block2, but re-wrap it with
                // block1's commitment so it fails C::weaken.
                let peer2_index = peers[2].index.get() as u16;
                let mut wrong_shard = coded_block2.shard(peer2_index).expect("missing shard");
                wrong_shard.commitment = commitment1;
                let wrong_bytes = wrong_shard.encode();

                let peer2_pk = peers[2].public_key.clone();
                let leader = peers[0].public_key.clone();

                // Inform peer 2 that peer 0 is the leader.
                peers[2]
                    .mailbox
                    .discovered(commitment1, leader, Round::new(Epoch::zero(), View::new(1)))
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
        let fixture: Fixture<C> = Fixture {
            num_peers: 10,
            ..Default::default()
        };

        fixture.start(
            |config, context, oracle, mut peers, coding_config| async move {
                let inner = B::new::<H>((), Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block = CodedBlock::<B, C, H>::new(inner, coding_config, &STRATEGY);
                let commitment = coded_block.commitment();

                // Get peer 2's strong shard so peer 3 can validate weak shards.
                let peer3_index = peers[3].index.get() as u16;
                let peer3_strong_shard = coded_block.shard(peer3_index).expect("missing shard");

                // Get peer 1's valid weak shard, then change the index to peer 4's index.
                let peer1_index = peers[1].index.get() as u16;
                let mut wrong_index_weak_shard = coded_block
                    .shard(peer1_index)
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
                    .discovered(commitment, leader, Round::new(Epoch::zero(), View::new(1)))
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
        let fixture: Fixture<C> = Fixture {
            num_peers: 10,
            ..Default::default()
        };

        fixture.start(
            |config, context, oracle, mut peers, coding_config| async move {
                // Create two different blocks.
                let inner1 = B::new::<H>((), Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block1 = CodedBlock::<B, C, H>::new(inner1, coding_config, &STRATEGY);
                let commitment1 = coded_block1.commitment();

                let inner2 = B::new::<H>((), Sha256Digest::EMPTY, Height::new(2), 200);
                let coded_block2 = CodedBlock::<B, C, H>::new(inner2, coding_config, &STRATEGY);

                // Get peer 3's strong shard from block1 (valid).
                let peer3_index = peers[3].index.get() as u16;
                let peer3_strong_shard = coded_block1.shard(peer3_index).expect("missing shard");

                // Get peer 1's weak shard from block2, but re-wrap with block1's
                // commitment so C::check fails.
                let peer1_index = peers[1].index.get() as u16;
                let mut wrong_weak_shard = coded_block2
                    .shard(peer1_index)
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
                    .discovered(commitment1, leader, Round::new(Epoch::zero(), View::new(1)))
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
                        .shard(peer_index)
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
    fn test_reconstruction_recovers_after_quorum_with_one_invalid_weak_shard() {
        // With 10 peers, minimum_shards=4.
        // Contribute exactly 4 shards first (1 strong + 3 weak), with one weak invalid:
        // quorum is reached, but checked_shards stays at 3 after batch validation.
        // Then send one more valid weak shard to meet reconstruction threshold.
        let fixture: Fixture<C> = Fixture {
            num_peers: 10,
            ..Default::default()
        };

        fixture.start(
            |config, context, oracle, mut peers, coding_config| async move {
                let inner1 = B::new::<H>((), Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block1 = CodedBlock::<B, C, H>::new(inner1, coding_config, &STRATEGY);
                let commitment1 = coded_block1.commitment();

                let inner2 = B::new::<H>((), Sha256Digest::EMPTY, Height::new(2), 200);
                let coded_block2 = CodedBlock::<B, C, H>::new(inner2, coding_config, &STRATEGY);

                let receiver_idx = 3usize;
                let receiver_pk = peers[receiver_idx].public_key.clone();

                // Prepare one invalid weak shard: shard data from block2, commitment from block1.
                let peer1_index = peers[1].index.get() as u16;
                let mut invalid_weak = coded_block2
                    .shard(peer1_index)
                    .expect("missing shard")
                    .verify_into_weak()
                    .expect("verify_into_weak failed");
                invalid_weak.commitment = commitment1;

                // Announce leader and deliver receiver's strong shard.
                let leader = peers[0].public_key.clone();
                peers[receiver_idx]
                    .mailbox
                    .discovered(commitment1, leader, Round::new(Epoch::zero(), View::new(1)))
                    .await;
                let receiver_strong = coded_block1
                    .shard(peers[receiver_idx].index.get() as u16)
                    .expect("missing shard")
                    .encode();
                peers[0]
                    .sender
                    .send(Recipients::One(receiver_pk.clone()), receiver_strong, true)
                    .await
                    .expect("send failed");

                // Contribute exactly minimum_shards total:
                // - invalid weak from peer1
                // - valid weak from peer2
                // - valid weak from peer4
                peers[1]
                    .sender
                    .send(
                        Recipients::One(receiver_pk.clone()),
                        invalid_weak.encode(),
                        true,
                    )
                    .await
                    .expect("send failed");
                for idx in [2usize, 4usize] {
                    let weak = coded_block1
                        .shard(peers[idx].index.get() as u16)
                        .expect("missing shard")
                        .verify_into_weak()
                        .expect("verify_into_weak failed")
                        .encode();
                    peers[idx]
                        .sender
                        .send(Recipients::One(receiver_pk.clone()), weak, true)
                        .await
                        .expect("send failed");
                }

                context.sleep(config.link.latency * 2).await;

                // Invalid weak shard should be blocked, and reconstruction should not happen yet.
                assert_blocked(
                    &oracle,
                    &peers[receiver_idx].public_key,
                    &peers[1].public_key,
                )
                .await;
                assert!(
                    peers[receiver_idx].mailbox.get(commitment1).await.is_none(),
                    "block should not reconstruct with only 3 checked shards"
                );

                // Send one additional valid weak shard; this should now satisfy checked threshold.
                let extra_valid = coded_block1
                    .shard(peers[5].index.get() as u16)
                    .expect("missing shard")
                    .verify_into_weak()
                    .expect("verify_into_weak failed")
                    .encode();
                peers[5]
                    .sender
                    .send(Recipients::One(receiver_pk), extra_valid, true)
                    .await
                    .expect("send failed");

                context.sleep(config.link.latency * 2).await;

                let reconstructed = peers[receiver_idx]
                    .mailbox
                    .get(commitment1)
                    .await
                    .expect("block should reconstruct after additional valid weak shard");
                assert_eq!(reconstructed.commitment(), commitment1);
            },
        );
    }

    #[test_traced]
    fn test_invalid_pending_weak_shard_blocked_on_drain() {
        // Test that a weak shard buffered in pending_weak_shards (before checking data) is
        // blocked when batch validation runs at quorum and C::check fails.
        let fixture: Fixture<C> = Fixture {
            num_peers: 10,
            ..Default::default()
        };

        fixture.start(
            |config, context, oracle, mut peers, coding_config| async move {
                // Create two different blocks.
                let inner1 = B::new::<H>((), Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block1 = CodedBlock::<B, C, H>::new(inner1, coding_config, &STRATEGY);
                let commitment1 = coded_block1.commitment();

                let inner2 = B::new::<H>((), Sha256Digest::EMPTY, Height::new(2), 200);
                let coded_block2 = CodedBlock::<B, C, H>::new(inner2, coding_config, &STRATEGY);

                // Get peer 1's weak shard from block2, but wrap with block1's commitment.
                let peer1_index = peers[1].index.get() as u16;
                let mut wrong_weak_shard = coded_block2
                    .shard(peer1_index)
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
                        .shard(peer_index)
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
                    .discovered(commitment1, leader, Round::new(Epoch::zero(), View::new(1)))
                    .await;
                let peer3_index = peers[3].index.get() as u16;
                let peer3_strong_shard = coded_block1.shard(peer3_index).expect("missing shard");
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

    #[test_traced]
    fn test_cross_epoch_buffered_shard_not_blocked() {
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

            // Epoch 0 participants: peers 0..4 (seeds 0..4).
            // Epoch 1 participants: peers 0..3 + peer 4 (seed 4 replaces seed 3).
            let mut epoch0_keys: Vec<PrivateKey> = (0..4).map(PrivateKey::from_seed).collect();
            epoch0_keys.sort_by_key(|s| s.public_key());
            let epoch0_pks: Vec<P> = epoch0_keys.iter().map(|c| c.public_key()).collect();
            let epoch0_set: Set<P> = Set::from_iter_dedup(epoch0_pks.clone());

            let future_peer_key = PrivateKey::from_seed(4);
            let future_peer_pk = future_peer_key.public_key();
            let mut epoch1_pks: Vec<P> = epoch0_pks[..3]
                .iter()
                .cloned()
                .chain(std::iter::once(future_peer_pk.clone()))
                .collect();
            epoch1_pks.sort();
            let epoch1_set: Set<P> = Set::from_iter_dedup(epoch1_pks);

            let receiver_idx_in_epoch0 = epoch0_set
                .index(&epoch0_pks[0])
                .expect("receiver must be in epoch 0")
                .get() as usize;
            let receiver_key = epoch0_keys[receiver_idx_in_epoch0].clone();
            let receiver_pk = receiver_key.public_key();

            let receiver_control = oracle.control(receiver_pk.clone());
            let (sender_handle, receiver_handle) = receiver_control
                .register(0, TEST_QUOTA)
                .await
                .expect("registration should succeed");

            let future_peer_control = oracle.control(future_peer_pk.clone());
            let (mut future_peer_sender, _future_peer_receiver) = future_peer_control
                .register(0, TEST_QUOTA)
                .await
                .expect("registration should succeed");
            oracle
                .add_link(future_peer_pk.clone(), receiver_pk.clone(), DEFAULT_LINK)
                .await
                .expect("link should be added");

            // Set up the receiver's engine with a multi-epoch provider.
            let scheme_epoch0 =
                Scheme::signer(SCHEME_NAMESPACE, epoch0_set.clone(), receiver_key.clone())
                    .expect("signer scheme should be created");
            let scheme_epoch1 =
                Scheme::signer(SCHEME_NAMESPACE, epoch1_set.clone(), receiver_key.clone())
                    .expect("signer scheme should be created");
            let scheme_provider =
                MultiEpochProvider::single(scheme_epoch0).with_epoch(Epoch::new(1), scheme_epoch1);

            let config: Config<_, _, _, C, _, _, _> = Config {
                scheme_provider,
                blocker: receiver_control.clone(),
                shard_codec_cfg: CodecConfig {
                    maximum_shard_size: MAX_SHARD_SIZE,
                },
                block_codec_cfg: (),
                strategy: STRATEGY,
                mailbox_size: 1024,
                peer_buffer_size: NZUsize!(64),
                background_channel_capacity: 1024,
                peer_set_subscription: oracle.manager().subscribe().await,
            };

            let (engine, mailbox) = ShardEngine::new(context.with_label("receiver"), config);
            engine.start((sender_handle, receiver_handle));

            // Build a coded block using epoch 1's participant set.
            let coding_config = coding_config_for_participants(epoch1_set.len() as u16);
            let inner = B::new::<H>((), Sha256Digest::EMPTY, Height::new(1), 100);
            let coded_block = CodedBlock::<B, C, H>::new(inner, coding_config, &STRATEGY);
            let commitment = coded_block.commitment();

            // The future peer creates a weak shard at their epoch 1 index.
            let future_peer_index = epoch1_set
                .index(&future_peer_pk)
                .expect("future peer must be in epoch 1");
            let strong_shard = coded_block
                .shard(future_peer_index.get() as u16)
                .expect("missing shard");
            let weak_shard = strong_shard
                .verify_into_weak()
                .expect("verify_into_weak failed");
            let weak_bytes = weak_shard.encode();

            // Send the shard BEFORE external_proposed (goes to pre-leader buffer).
            future_peer_sender
                .send(Recipients::One(receiver_pk.clone()), weak_bytes, true)
                .await
                .expect("send failed");
            context.sleep(DEFAULT_LINK.latency * 2).await;

            // No one should be blocked yet (shard is buffered, leader unknown).
            let blocked = oracle.blocked().await.unwrap();
            assert!(
                blocked.is_empty(),
                "no peers should be blocked while shard is buffered"
            );

            // Announce the leader with an epoch 1 round.
            let leader = epoch0_pks[1].clone();
            mailbox
                .discovered(commitment, leader, Round::new(Epoch::new(1), View::new(1)))
                .await;
            context.sleep(DEFAULT_LINK.latency * 2).await;

            // The future peer is a valid participant in epoch 1, so they must NOT
            // be blocked after their buffered shard is ingested.
            let blocked = oracle.blocked().await.unwrap();
            assert!(
                blocked.is_empty(),
                "future-epoch participant should not be blocked: {blocked:?}"
            );
        });
    }

    #[test_traced]
    fn test_failed_reconstruction_digest_mismatch_then_recovery() {
        // Byzantine scenario: all shards pass coding verification (correct root) but the
        // decoded blob has a different digest than what the commitment claims. This triggers
        // Error::DigestMismatch in try_reconstruct. Verify that:
        //   1. The failed commitment's state is cleaned up
        //   2. Subscriptions for the failed commitment never resolve
        //   3. A subsequent valid commitment reconstructs successfully
        let fixture: Fixture<C> = Fixture {
            num_peers: 10,
            ..Default::default()
        };

        fixture.start(
            |config, context, _oracle, mut peers, coding_config| async move {
                // Block 1: the "claimed" block (its digest goes in the fake commitment).
                let inner1 = B::new::<H>((), Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block1 = CodedBlock::<B, C, H>::new(inner1, coding_config, &STRATEGY);

                // Block 2: the actual data behind the shards.
                let inner2 = B::new::<H>((), Sha256Digest::EMPTY, Height::new(2), 200);
                let coded_block2 = CodedBlock::<B, C, H>::new(inner2, coding_config, &STRATEGY);
                let real_commitment2 = coded_block2.commitment();

                // Build a fake commitment: block1's digest + block2's coding root/context/config.
                // Shards from block2 will verify against block2's root (present in the fake
                // commitment), but try_reconstruct will decode block2 and find its digest != D1.
                let fake_commitment = Commitment::from((
                    coded_block1.digest(),
                    real_commitment2.root::<Sha256Digest>(),
                    real_commitment2.context::<Sha256Digest>(),
                    coding_config,
                ));

                let receiver_idx = 3usize;
                let receiver_pk = peers[receiver_idx].public_key.clone();
                let leader = peers[0].public_key.clone();
                let round = Round::new(Epoch::zero(), View::new(1));

                // Discover the fake commitment.
                peers[receiver_idx]
                    .mailbox
                    .discovered(fake_commitment, leader.clone(), round)
                    .await;

                // Open a block subscription before sending shards.
                let mut block_sub = peers[receiver_idx].mailbox.subscribe(fake_commitment).await;
                let mut digest_sub = peers[receiver_idx]
                    .mailbox
                    .subscribe_by_digest(coded_block1.digest())
                    .await;

                // Send the receiver's strong shard (from block2, with fake commitment).
                let receiver_shard_idx = peers[receiver_idx].index.get() as u16;
                let mut strong_shard = coded_block2
                    .shard(receiver_shard_idx)
                    .expect("missing shard");
                strong_shard.commitment = fake_commitment;
                peers[0]
                    .sender
                    .send(
                        Recipients::One(receiver_pk.clone()),
                        strong_shard.encode(),
                        true,
                    )
                    .await
                    .expect("send failed");

                // Send enough weak shards to reach minimum_shards (4 for 10 peers).
                // Need 3 more weak shards after the strong shard.
                for &idx in &[1usize, 2, 4] {
                    let peer_shard_idx = peers[idx].index.get() as u16;
                    let mut weak = coded_block2
                        .shard(peer_shard_idx)
                        .expect("missing shard")
                        .verify_into_weak()
                        .expect("verify_into_weak failed");
                    weak.commitment = fake_commitment;
                    peers[idx]
                        .sender
                        .send(Recipients::One(receiver_pk.clone()), weak.encode(), true)
                        .await
                        .expect("send failed");
                }

                context.sleep(config.link.latency * 2).await;

                // Reconstruction should have failed with DigestMismatch.
                // State for fake_commitment should be removed (engine.rs:792).
                assert!(
                    peers[receiver_idx]
                        .mailbox
                        .get(fake_commitment)
                        .await
                        .is_none(),
                    "block should not be available after DigestMismatch"
                );

                // Block subscription should be closed after failed reconstruction cleanup.
                assert!(
                    matches!(block_sub.try_recv(), Err(TryRecvError::Closed)),
                    "subscription should close for failed reconstruction"
                );
                assert!(
                    matches!(digest_sub.try_recv(), Err(TryRecvError::Closed)),
                    "digest subscription should close after failed reconstruction"
                );

                // Now verify the engine is not stuck: send valid shards for block1's real
                // commitment and confirm reconstruction succeeds.
                let real_commitment1 = coded_block1.commitment();
                let round2 = Round::new(Epoch::zero(), View::new(2));
                peers[receiver_idx]
                    .mailbox
                    .discovered(real_commitment1, leader.clone(), round2)
                    .await;

                let strong1 = coded_block1
                    .shard(receiver_shard_idx)
                    .expect("missing shard");
                peers[0]
                    .sender
                    .send(Recipients::One(receiver_pk.clone()), strong1.encode(), true)
                    .await
                    .expect("send failed");

                for &idx in &[1usize, 2, 4] {
                    let peer_shard_idx = peers[idx].index.get() as u16;
                    let weak = coded_block1
                        .shard(peer_shard_idx)
                        .expect("missing shard")
                        .verify_into_weak()
                        .expect("verify_into_weak failed");
                    peers[idx]
                        .sender
                        .send(Recipients::One(receiver_pk.clone()), weak.encode(), true)
                        .await
                        .expect("send failed");
                }

                context.sleep(config.link.latency * 2).await;

                let reconstructed = peers[receiver_idx]
                    .mailbox
                    .get(real_commitment1)
                    .await
                    .expect("valid block should reconstruct after prior failure");
                assert_eq!(reconstructed.commitment(), real_commitment1);
            },
        );
    }

    #[test_traced]
    fn test_failed_reconstruction_context_mismatch_then_recovery() {
        // Byzantine scenario: shards decode to a block whose digest and coding root/config
        // match the commitment, but the commitment carries a mismatched context digest.
        // The engine must reject reconstruction and keep the commitment unresolved.
        let fixture: Fixture<C> = Fixture {
            num_peers: 10,
            ..Default::default()
        };

        fixture.start(
            |config, context, _oracle, mut peers, coding_config| async move {
                let inner = B::new::<H>((), Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block = CodedBlock::<B, C, H>::new(inner, coding_config, &STRATEGY);
                let real_commitment = coded_block.commitment();

                let wrong_context_digest = Sha256::hash(b"wrong_context");
                assert_ne!(
                    real_commitment.context::<Sha256Digest>(),
                    wrong_context_digest,
                    "test requires a distinct context digest"
                );
                let fake_commitment = Commitment::from((
                    coded_block.digest(),
                    real_commitment.root::<Sha256Digest>(),
                    wrong_context_digest,
                    coding_config,
                ));

                let receiver_idx = 3usize;
                let receiver_pk = peers[receiver_idx].public_key.clone();
                let leader = peers[0].public_key.clone();
                let round = Round::new(Epoch::zero(), View::new(1));

                peers[receiver_idx]
                    .mailbox
                    .discovered(fake_commitment, leader.clone(), round)
                    .await;
                let mut block_sub = peers[receiver_idx].mailbox.subscribe(fake_commitment).await;

                let receiver_shard_idx = peers[receiver_idx].index.get() as u16;
                let mut strong_shard = coded_block
                    .shard(receiver_shard_idx)
                    .expect("missing shard");
                strong_shard.commitment = fake_commitment;
                peers[0]
                    .sender
                    .send(
                        Recipients::One(receiver_pk.clone()),
                        strong_shard.encode(),
                        true,
                    )
                    .await
                    .expect("send failed");

                for &idx in &[1usize, 2, 4] {
                    let peer_shard_idx = peers[idx].index.get() as u16;
                    let mut weak = coded_block
                        .shard(peer_shard_idx)
                        .expect("missing shard")
                        .verify_into_weak()
                        .expect("verify_into_weak failed");
                    weak.commitment = fake_commitment;
                    peers[idx]
                        .sender
                        .send(Recipients::One(receiver_pk.clone()), weak.encode(), true)
                        .await
                        .expect("send failed");
                }

                context.sleep(config.link.latency * 2).await;

                assert!(
                    peers[receiver_idx]
                        .mailbox
                        .get(fake_commitment)
                        .await
                        .is_none(),
                    "block should not be available after ContextMismatch"
                );
                assert!(
                    matches!(block_sub.try_recv(), Err(TryRecvError::Closed)),
                    "subscription should close for context-mismatched commitment"
                );

                // Verify the receiver still reconstructs valid commitments afterward.
                let round2 = Round::new(Epoch::zero(), View::new(2));
                peers[receiver_idx]
                    .mailbox
                    .discovered(real_commitment, leader.clone(), round2)
                    .await;

                let strong_real = coded_block
                    .shard(receiver_shard_idx)
                    .expect("missing shard");
                peers[0]
                    .sender
                    .send(
                        Recipients::One(receiver_pk.clone()),
                        strong_real.encode(),
                        true,
                    )
                    .await
                    .expect("send failed");

                for &idx in &[1usize, 2, 4] {
                    let peer_shard_idx = peers[idx].index.get() as u16;
                    let weak = coded_block
                        .shard(peer_shard_idx)
                        .expect("missing shard")
                        .verify_into_weak()
                        .expect("verify_into_weak failed");
                    peers[idx]
                        .sender
                        .send(Recipients::One(receiver_pk.clone()), weak.encode(), true)
                        .await
                        .expect("send failed");
                }

                context.sleep(config.link.latency * 2).await;

                let reconstructed = peers[receiver_idx]
                    .mailbox
                    .get(real_commitment)
                    .await
                    .expect("valid block should reconstruct after prior context mismatch");
                assert_eq!(reconstructed.commitment(), real_commitment);
            },
        );
    }

    #[test_traced]
    fn test_same_round_equivocation_preserves_certifiable_recovery() {
        // Regression coverage for same-round leader equivocation:
        // - leader equivocates across two commitments in the same round
        // - we receive a shard for commitment B (the certifiable one)
        // - commitment A reconstructs first
        // - commitment B must still remain recoverable
        let fixture: Fixture<C> = Fixture {
            num_peers: 10,
            ..Default::default()
        };

        fixture.start(
            |config, context, _oracle, mut peers, coding_config| async move {
                let receiver_idx = 3usize;
                let receiver_pk = peers[receiver_idx].public_key.clone();
                let receiver_shard_idx = peers[receiver_idx].index.get() as u16;

                let leader = peers[0].public_key.clone();
                let round = Round::new(Epoch::zero(), View::new(7));

                // Two different commitments in the same round (equivocation scenario).
                let block_a = CodedBlock::<B, C, H>::new(
                    B::new::<H>((), Sha256Digest::EMPTY, Height::new(1), 111),
                    coding_config,
                    &STRATEGY,
                );
                let commitment_a = block_a.commitment();
                let block_b = CodedBlock::<B, C, H>::new(
                    B::new::<H>((), Sha256Digest::EMPTY, Height::new(1), 222),
                    coding_config,
                    &STRATEGY,
                );
                let commitment_b = block_b.commitment();

                // Receiver learns both commitments in the same round.
                peers[receiver_idx]
                    .mailbox
                    .discovered(commitment_a, leader.clone(), round)
                    .await;
                peers[receiver_idx]
                    .mailbox
                    .discovered(commitment_b, leader.clone(), round)
                    .await;

                // Subscribe to the certifiable commitment before any reconstruction.
                let certifiable_sub = peers[receiver_idx].mailbox.subscribe(commitment_b).await;

                // We receive our strong shard for commitment B from the equivocating leader.
                let strong_b = block_b
                    .shard(receiver_shard_idx)
                    .expect("missing shard")
                    .encode();
                peers[0]
                    .sender
                    .send(Recipients::One(receiver_pk.clone()), strong_b, true)
                    .await
                    .expect("send failed");

                // Reconstruct conflicting commitment A first.
                let strong_a = block_a
                    .shard(receiver_shard_idx)
                    .expect("missing shard")
                    .encode();
                peers[0]
                    .sender
                    .send(Recipients::One(receiver_pk.clone()), strong_a, true)
                    .await
                    .expect("send failed");
                for i in [1usize, 2usize, 4usize] {
                    let weak_a = block_a
                        .shard(peers[i].index.get() as u16)
                        .expect("missing shard")
                        .verify_into_weak()
                        .expect("verify_into_weak failed")
                        .encode();
                    peers[i]
                        .sender
                        .send(Recipients::One(receiver_pk.clone()), weak_a, true)
                        .await
                        .expect("send failed");
                }
                context.sleep(config.link.latency * 4).await;
                let reconstructed_a = peers[receiver_idx]
                    .mailbox
                    .get(commitment_a)
                    .await
                    .expect("conflicting commitment should reconstruct first");
                assert_eq!(reconstructed_a.commitment(), commitment_a);

                // Commitment B should still be recoverable after A reconstructed.
                for i in [1usize, 2usize, 4usize] {
                    let weak_b = block_b
                        .shard(peers[i].index.get() as u16)
                        .expect("missing shard")
                        .verify_into_weak()
                        .expect("verify_into_weak failed")
                        .encode();
                    peers[i]
                        .sender
                        .send(Recipients::One(receiver_pk.clone()), weak_b, true)
                        .await
                        .expect("send failed");
                }

                select! {
                    result = certifiable_sub => {
                        let reconstructed_b =
                            result.expect("certifiable commitment should remain recoverable");
                        assert_eq!(reconstructed_b.commitment(), commitment_b);
                    },
                    _ = context.sleep(Duration::from_secs(5)) => {
                        panic!("certifiable commitment was not recoverable after same-round equivocation");
                    },
                }
            },
        );
    }

    #[test_traced]
    fn test_leader_unrelated_weak_shard_blocks_peer() {
        // Regression test: if the leader sends an unrelated/invalid weak shard
        // (i.e. a shard for a different participant index), the receiver must
        // block the leader.
        let fixture: Fixture<C> = Fixture {
            num_peers: 10,
            ..Default::default()
        };

        fixture.start(
            |config, context, oracle, mut peers, coding_config| async move {
                // Commitment being tracked by the receiver.
                let tracked_block = CodedBlock::<B, C, H>::new(
                    B::new::<H>((), Sha256Digest::EMPTY, Height::new(1), 100),
                    coding_config,
                    &STRATEGY,
                );
                let tracked_commitment = tracked_block.commitment();

                // Separate block used to source "unrelated" shard data.
                let unrelated_block = CodedBlock::<B, C, H>::new(
                    B::new::<H>((), Sha256Digest::EMPTY, Height::new(2), 200),
                    coding_config,
                    &STRATEGY,
                );

                let receiver_idx = 3usize;
                let receiver_pk = peers[receiver_idx].public_key.clone();
                let leader_idx = 0usize;
                let leader_pk = peers[leader_idx].public_key.clone();

                // Receiver tracks the commitment with peer0 as leader.
                peers[receiver_idx]
                    .mailbox
                    .discovered(
                        tracked_commitment,
                        leader_pk.clone(),
                        Round::new(Epoch::zero(), View::new(1)),
                    )
                    .await;

                // Construct an unrelated weak shard from peer1's slot and retarget
                // its commitment to the tracked commitment so it hits active state.
                let mut unrelated_weak = unrelated_block
                    .shard(peers[1].index.get() as u16)
                    .expect("missing shard")
                    .verify_into_weak()
                    .expect("verify_into_weak failed");
                unrelated_weak.commitment = tracked_commitment;

                // Leader sends this unrelated/invalid weak shard to receiver.
                // The shard index no longer matches sender's participant index,
                // so leader must be blocked.
                peers[leader_idx]
                    .sender
                    .send(Recipients::One(receiver_pk), unrelated_weak.encode(), true)
                    .await
                    .expect("send failed");
                context.sleep(config.link.latency * 2).await;

                assert_blocked(&oracle, &peers[receiver_idx].public_key, &leader_pk).await;
            },
        );
    }

    #[test_traced]
    fn test_peer_set_update_evicts_peer_buffers() {
        // Shards buffered before leader announcement should be evicted when
        // the sender leaves the tracked peer set. After eviction, announcing
        // the leader should NOT reconstruct the block (the buffered shard is
        // gone), but sending the shard again post-leader should succeed.
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let num_peers = 10usize;
            let (network, oracle) = simulated::Network::<deterministic::Context, P>::new(
                context.with_label("network"),
                simulated::Config {
                    max_size: MAX_SHARD_SIZE as u32,
                    disconnect_on_block: true,
                    tracked_peer_sets: None,
                },
            );
            network.start();

            let mut private_keys = (0..num_peers)
                .map(|i| PrivateKey::from_seed(i as u64))
                .collect::<Vec<_>>();
            private_keys.sort_by_key(|s| s.public_key());
            let peer_keys: Vec<P> = private_keys.iter().map(|c| c.public_key()).collect();
            let participants: Set<P> = Set::from_iter_dedup(peer_keys.clone());

            // Test from the perspective of a single receiver (peer 3).
            let receiver_idx = 3usize;
            let receiver_pk = peer_keys[receiver_idx].clone();
            let leader_pk = peer_keys[0].clone();

            let receiver_control = oracle.control(receiver_pk.clone());
            let (sender_handle, receiver_handle) = receiver_control
                .register(0, TEST_QUOTA)
                .await
                .expect("registration should succeed");

            // Register the leader so it can send shards.
            let leader_control = oracle.control(leader_pk.clone());
            let (mut leader_sender, _leader_receiver) = leader_control
                .register(0, TEST_QUOTA)
                .await
                .expect("registration should succeed");
            oracle
                .add_link(leader_pk.clone(), receiver_pk.clone(), DEFAULT_LINK)
                .await
                .expect("link should be added");

            // Create a peer set subscription for the receiver's engine.
            let (peer_set_tx, peer_set_rx) = commonware_utils::channel::mpsc::unbounded_channel();

            let scheme = Scheme::signer(
                SCHEME_NAMESPACE,
                participants.clone(),
                private_keys[receiver_idx].clone(),
            )
            .expect("signer scheme should be created");

            let config: Config<_, _, _, C, _, _, _> = Config {
                scheme_provider: MultiEpochProvider::single(scheme),
                blocker: receiver_control.clone(),
                shard_codec_cfg: CodecConfig {
                    maximum_shard_size: MAX_SHARD_SIZE,
                },
                block_codec_cfg: (),
                strategy: STRATEGY,
                mailbox_size: 1024,
                peer_buffer_size: NZUsize!(64),
                background_channel_capacity: 1024,
                peer_set_subscription: peer_set_rx,
            };

            let (engine, mailbox) = ShardEngine::new(context.with_label("receiver"), config);
            engine.start((sender_handle, receiver_handle));

            // Build a coded block and extract the strong shard destined for the receiver.
            let coding_config = coding_config_for_participants(num_peers as u16);
            let inner = B::new::<H>((), Sha256Digest::EMPTY, Height::new(1), 100);
            let coded_block = CodedBlock::<B, C, H>::new(inner, coding_config, &STRATEGY);
            let commitment = coded_block.commitment();

            let receiver_participant = participants
                .index(&receiver_pk)
                .expect("receiver must be a participant");
            let strong_shard = coded_block
                .shard(receiver_participant.get() as u16)
                .expect("missing shard");
            let strong_bytes = strong_shard.encode();

            // Send the strong shard BEFORE leader announcement (it gets buffered).
            leader_sender
                .send(
                    Recipients::One(receiver_pk.clone()),
                    strong_bytes.clone(),
                    true,
                )
                .await
                .expect("send failed");
            context.sleep(DEFAULT_LINK.latency * 2).await;

            // Now send a peer set update that excludes the leader.
            let remaining: Set<P> =
                Set::from_iter_dedup(peer_keys.iter().filter(|pk| **pk != leader_pk).cloned());
            peer_set_tx.send((1, remaining.clone(), remaining)).unwrap();
            context.sleep(Duration::from_millis(10)).await;

            // Announce the leader. Buffered shards from the leader should have been
            // evicted, so the strong shard will NOT be ingested.
            let mut shard_sub = mailbox.subscribe_shard(commitment).await;
            mailbox
                .discovered(
                    commitment,
                    leader_pk.clone(),
                    Round::new(Epoch::zero(), View::new(1)),
                )
                .await;
            context.sleep(DEFAULT_LINK.latency * 2).await;

            // The shard subscription should still be pending (no shard was ingested).
            assert!(
                matches!(shard_sub.try_recv(), Err(TryRecvError::Empty)),
                "shard subscription should not resolve after evicted leader's buffer"
            );
            assert!(
                mailbox.get(commitment).await.is_none(),
                "block should not reconstruct from evicted buffers"
            );
        });
    }
}
