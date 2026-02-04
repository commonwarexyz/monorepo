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
//! - Strong shards (`Scheme::Shard`): Original erasure-coded shards sent by the proposer.
//!   These contain the data needed to derive checking data for validation.
//!
//! - Weak shards (`Scheme::ReShard`): Shards that have been validated and re-broadcast
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
//!    | Validate |         | Validate |         | Validate |
//!    | (reshard)|         | (reshard)|         | (reshard)|
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
//!    | (no shards)      |
//!    +------------------+
//!             |
//!             | Receive strong shard (for self)
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
//! - Weak shards (reshards) MUST be sent by the participant whose index matches
//!   the shard index.
//! - All shards MUST pass cryptographic verification against the commitment.
//! - Each participant may only contribute ONE reshard per commitment.
//!
//! Peers violating these rules are blocked via the [`Blocker`] trait.
//!
//! Note: Duplicate strong shards are silently ignored without blocking. This
//! prevents a Byzantine actor from relaying our strong shard before the honest
//! proposer's message arrives, which would otherwise cause us to block the
//! proposer.

use super::mailbox_new::{Mailbox, Message};
use crate::{
    marshal::coding::types::{CodedBlock, DistributionShard, Shard},
    types::CodingCommitment,
    Block, CertifiableBlock, Heightable,
};
use commonware_codec::{Error as CodecError, Read};
use commonware_coding::Scheme as CodingScheme;
use commonware_cryptography::{Committable, Digestible, Hasher, PublicKey};
use commonware_macros::select_loop;
use commonware_p2p::{
    utils::codec::{wrap, WrappedSender},
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
use prometheus_client::metrics::gauge::Gauge;
use rand::Rng;
use rayon::iter::Either;
use std::{
    collections::BTreeMap,
    sync::Arc,
    time::{Duration, Instant, SystemTime},
};
use thiserror::Error;
use tracing::{debug, error, warn};

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

/// A wrapper around a [`buffered::Mailbox`] for broadcasting and receiving [`CodedBlock`]s as [`Shard`]s.
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
    block_subscriptions:
        BTreeMap<Either<CodingCommitment, B::Digest>, Vec<oneshot::Sender<Arc<CodedBlock<B, C>>>>>,

    erasure_decode_duration: Gauge,
    reconstructed_blocks_count: Gauge,
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
                erasure_decode_duration,
                reconstructed_blocks_count,
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
        let (mut sender, mut receiver) =
            wrap::<_, _, Shard<C, H>>(self.shard_codec_cfg.clone(), sender, receiver);

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
            },
            on_stopped => {
                debug!("received shutdown signal, stopping shard engine");
            },
            Some(message) = self.mailbox.recv() else {
                debug!("shard mailbox closed, shutting down shard engine");
                return;
            } => {
                match message {
                    Message::UpdateParticipants { participants } => {
                        self.participants = participants;

                        // Clear reconstruction state and subscriptions
                        self.state.clear();
                        self.shard_subscriptions.clear();
                        self.block_subscriptions.clear();

                        debug!("updated participant set");
                    },
                    Message::Proposed { block } => {
                        self.broadcast_shards(&mut sender, block).await;
                    },
                    Message::Get { commitment, response } => {
                        let block = self.reconstructed_blocks.get(&commitment).cloned();
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
            Ok((peer, shard)) = receiver.recv() else {
                error!("receiver failed, stopping shard engine");
                return;
            } => {
                // Verify that the codec for the shard is valid.
                let shard = match shard {
                    Ok(shard) => shard,
                    Err(err) => {
                        warn!(?peer, ?err, "received invalid shard, blocking peer");
                        self.blocker.block(peer).await;
                        continue;
                    }
                };

                // Block peers that are not participants.
                if self.participants.index(&peer).is_none() {
                    warn!(?peer, "shard sent by non-participant, blocking peer");
                    self.blocker.block(peer).await;
                    continue;
                }

                // Prune states that haven't been updated within the TTL.
                self.prune_stale_states();

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

                    if let Some(reshard) = state.take_reshard() {
                        self.notify_shard_subscribers(commitment).await;
                        self.broadcast_reshard(&mut sender, reshard).await;
                    }
                }

                // Attempt to reconstruct the block.
                match self.try_reconstruct(commitment).await {
                    Ok(Some(block)) => {
                        debug!(
                            %commitment,
                            parent = %block.parent(),
                            height = %block.height(),
                            "successfully reconstructed block from shards"
                        );
                        self.state.remove(&commitment);
                        self.notify_block_subscribers(block).await;
                    }
                    Ok(None) => {
                        debug!(%commitment, "not enough checked shards to reconstruct block");
                    }
                    Err(err) => {
                        warn!(%commitment, ?err, "failed to reconstruct block from checked shards");
                        self.state.remove(&commitment);
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
    /// - `Err(ReconstructionError)` if reconstruction was attempted but failed.
    #[inline]
    async fn try_reconstruct(
        &mut self,
        commitment: CodingCommitment,
    ) -> Result<Option<Arc<CodedBlock<B, C>>>, ReconstructionError<C>> {
        if let Some(block) = self.reconstructed_blocks.get(&commitment) {
            return Ok(Some(Arc::clone(&block)));
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
        Ok(Some(block))
    }

    /// Broadcasts the shards of a [`CodedBlock`] to all participants and caches the block.
    #[inline]
    async fn broadcast_shards<Sr: Sender<PublicKey = P>>(
        &mut self,
        sender: &mut WrappedSender<Sr, Shard<C, H>>,
        block: CodedBlock<B, C>,
    ) {
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
    async fn broadcast_reshard<Sr: Sender<PublicKey = P>>(
        &mut self,
        sender: &mut WrappedSender<Sr, Shard<C, H>>,
        shard: Shard<C, H>,
    ) {
        let commitment = shard.commitment();
        let _ = sender.send(Recipients::All, shard, true).await;
        debug!(?commitment, "broadasted shard to all participants");
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
        let block_reconstructed = self.reconstructed_blocks.get(&commitment).is_some();
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
        let before = self.state.len();
        self.state.retain(|_, state| {
            now.duration_since(state.last_updated)
                .map(|elapsed| elapsed < self.state_ttl)
                .unwrap_or(true) // Keep if clock went backwards (shouldn't happen)
        });
        let pruned = before - self.state.len();
        if pruned > 0 {
            debug!(pruned, "pruned stale reconstruction states");
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
    ) {
        f(&mut self.reconstructed_blocks);
        let _ = self
            .reconstructed_blocks_count
            .try_set(self.reconstructed_blocks.len());
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
    /// Our validated reshard, ready to broadcast to other participants.
    /// This is set when we receive and validate our own strong shard.
    own_reshard: Option<Shard<C, H>>,
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
            own_reshard: None,
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
    /// Strong shards (`CodingScheme::Shard`):
    /// - MUST be sent by a participant.
    /// - MUST correspond to self's index (self must be a participant).
    /// - MUST pass cryptographic verification via [`CodingScheme::reshard`].
    /// - Duplicates are silently ignored (not blocked) to prevent Byzantine actors
    ///   from causing us to block the honest proposer.
    ///
    /// Weak shards (`CodingScheme::ReShard`):
    /// - MUST be sent by a participant.
    /// - MUST be sent by the participant whose index matches the shard index.
    /// - MUST pass cryptographic verification via [`CodingScheme::check`].
    /// - Each participant may only contribute ONE reshard per commitment. Duplicates
    ///   result in blocking the sender.
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

        let before = self.checked_shards.len();
        if shard.is_strong() {
            self.insert_shard(me, sender, shard, strategy, blocker)
                .await;
        } else {
            self.insert_reshard(sender, shard, participants, blocker)
                .await;
        }

        // Only update timestamp when we actually made progress.
        if self.checked_shards.len() > before {
            self.last_updated = now;
        }
    }

    /// Takes the validated [`Shard`] for broadcasting to other participants.
    /// Returns [`None`] if we haven't validated our own shard yet.
    pub fn take_reshard(&mut self) -> Option<Shard<C, H>> {
        self.own_reshard.take()
    }

    /// Attempts to insert a shard into the state. If successful, validates any pending
    /// weak shards via [`Self::drain_pending`].
    ///
    /// If the shard is invalid, the peer is blocked via the provided [`Blocker`].
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
        let commitment = shard.commitment();
        let shard_index = shard
            .index()
            .try_into()
            .expect("shard index impossibly out of bounds");

        let DistributionShard::Strong(shard_data) = shard.into_inner() else {
            panic!("insert_strong_shard called with non-strong shard");
        };

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

        // Short-circuit if we already have our strong shard. Don't block, but don't
        // do any expensive work either. The sender may be an honest proposer whose
        // message arrived after a Byzantine actor relayed the same shard.
        if self.checking_data.is_some() {
            return;
        }

        let Ok((checking_data, checked, reshard_data)) = C::reshard(
            &commitment.config(),
            &commitment.coding_digest(),
            shard_index,
            shard_data,
        ) else {
            warn!(?sender, "invalid strong shard received, blocking peer");
            blocker.block(sender).await;
            return;
        };

        self.contributed.set(me.get() as u64, true);
        self.checking_data = Some(checking_data);
        self.checked_shards.push(checked);
        self.own_reshard = Some(Shard::new(
            commitment,
            shard_index as usize,
            DistributionShard::Weak(reshard_data),
        ));

        // Drain pending shards now that we have checking data.
        self.drain_pending(commitment, strategy, blocker).await;
    }

    /// Inserts a reshard into the state.
    ///
    /// If the shard is invalid, or the shard's index does not correspond with the sender,
    /// the sender is blocked via the provided [`Blocker`].
    ///
    /// # Panics
    ///
    /// Panics if `shard` is a [`DistributionShard::Strong`].
    async fn insert_reshard(
        &mut self,
        sender: P,
        shard: Shard<C, H>,
        participants: &Set<P>,
        blocker: &mut impl Blocker<PublicKey = P>,
    ) {
        let commitment = shard.commitment();
        let shard_index = shard
            .index()
            .try_into()
            .expect("shard index impossibly out of bounds");

        let Some(index) = participants.index(&sender) else {
            warn!(?sender, "shard sent by non-participant, blocking peer");
            blocker.block(sender).await;
            return;
        };

        if shard_index != index.get() as u16 {
            warn!(
                ?sender,
                shard_index,
                expected_index = index.get() as usize,
                "reshard index does not match participant index, blocking peer"
            );
            blocker.block(sender).await;
            return;
        }

        if self.contributed.get(index.get() as u64) {
            warn!(
                ?sender,
                shard_index, "participant has already contributed a valid shard, blocking peer"
            );
            blocker.block(sender).await;
            return;
        }

        let Some(checking_data) = &self.checking_data else {
            self.pending_shards.insert(sender, shard);
            return;
        };

        let DistributionShard::Weak(shard_data) = shard.into_inner() else {
            panic!("insert_strong_shard called with non-strong shard");
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

        self.contributed.set(index.get() as u64, true);
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
                (peer, checked.ok().map(|c| (shard_index, c)))
            });

        // Block any peers that sent invalid shards.
        for peer in to_block {
            warn!(?peer, "invalid shard received, blocking peer");
            blocker.block(peer).await;
        }

        // Mark contributed and add valid shards
        for (index, checked) in checked_shards {
            let index = index as u64;
            if !self.contributed.get(index) {
                self.contributed.set(index, true);
                self.checked_shards.push(checked);
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
            .find(|(a, b)| a == blocker && b == blocked)
            .is_some();
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

            peers[0].mailbox.proposed(coded_block.clone()).await;
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

            // Subscribe before broadcasting.
            let commitment_sub = peers[1]
                .mailbox
                .subscribe_block_by_commitment(commitment)
                .await;
            let digest_sub = peers[2].mailbox.subscribe_block_by_digest(digest).await;

            peers[0].mailbox.proposed(coded_block.clone()).await;
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

                // Receiver subscribes to their shard.
                let receiver_pk = peers[2].public_key.clone();
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
                coding_config.clone(),
                &STRATEGY,
            );
            let block2 = CodedBlock::<B, C>::new(
                B::new::<H>((), Sha256Digest::EMPTY, Height::new(2), 100),
                coding_config.clone(),
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
    fn test_duplicate_strong_shard_ignored_without_blocking() {
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

                // Send peer 2 their strong shard from peer 0 (first time - should succeed).
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

                // Send peer 2 the same strong shard from peer 1 (duplicate - ignored, not blocked).
                peers[1]
                    .sender
                    .send(Recipients::One(peer2_pk), strong_bytes, true)
                    .await
                    .expect("send failed");
                context.sleep(config.link.latency * 2).await;

                // Peer 2 should NOT have blocked peer 1 (duplicate strong shards are ignored).
                let blocked = oracle.blocked().await.unwrap();
                assert!(
                    blocked.is_empty(),
                    "no peers should be blocked for duplicate strong shards"
                );
            },
        );
    }

    #[test_traced]
    fn test_duplicate_reshard_blocks_peer() {
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

                // Get peer 1's reshard.
                let peer1_index = peers[1].index.get() as usize;
                let peer1_strong_shard =
                    coded_block.shard::<H>(peer1_index).expect("missing shard");
                let peer1_reshard = peer1_strong_shard
                    .verify_into_reshard()
                    .expect("reshard failed");

                let peer2_pk = peers[2].public_key.clone();

                // Send peer 2 their strong shard (initializes checking_data, 1 checked shard).
                let strong_bytes = peer2_strong_shard.encode();
                peers[0]
                    .sender
                    .send(Recipients::One(peer2_pk.clone()), strong_bytes, true)
                    .await
                    .expect("send failed");
                context.sleep(config.link.latency * 2).await;

                // Send peer 1's reshard to peer 2 (first time - should succeed, 2 checked shards).
                let reshard_bytes = peer1_reshard.encode();
                peers[1]
                    .sender
                    .send(
                        Recipients::One(peer2_pk.clone()),
                        reshard_bytes.clone(),
                        true,
                    )
                    .await
                    .expect("send failed");
                context.sleep(config.link.latency * 2).await;

                // Send peer 1's reshard to peer 2 again (duplicate - should block).
                // With 10 peers, minimum_shards=4, so we haven't reconstructed yet.
                peers[1]
                    .sender
                    .send(Recipients::One(peer2_pk), reshard_bytes, true)
                    .await
                    .expect("send failed");
                context.sleep(config.link.latency * 2).await;

                // Peer 2 should have blocked peer 1 for sending a duplicate reshard.
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

                // Get peer 1's reshard.
                let peer1_index = peers[1].index.get() as usize;
                let peer1_strong_shard =
                    coded_block.shard::<H>(peer1_index).expect("missing shard");
                let peer1_reshard = peer1_strong_shard
                    .verify_into_reshard()
                    .expect("reshard failed");

                let peer2_pk = peers[2].public_key.clone();

                // Send peer 2 their strong shard (initializes checking_data).
                let strong_bytes = peer2_strong_shard.encode();
                peers[0]
                    .sender
                    .send(Recipients::One(peer2_pk.clone()), strong_bytes, true)
                    .await
                    .expect("send failed");
                context.sleep(config.link.latency * 2).await;

                // Send peer 1's reshard to peer 2 (first time - should succeed).
                let reshard_bytes = peer1_reshard.encode();
                peers[1]
                    .sender
                    .send(
                        Recipients::One(peer2_pk.clone()),
                        reshard_bytes.clone(),
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
                // is gone, so sending the same reshard again should NOT block peer 1.
                peers[1]
                    .sender
                    .send(Recipients::One(peer2_pk), reshard_bytes, true)
                    .await
                    .expect("send failed");
                context.sleep(config.link.latency * 2).await;

                // If state was pruned, the reshard is treated as new (not duplicate),
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
    fn test_drain_pending_validates_reshards_after_strong_shard() {
        // Test that reshards arriving BEFORE the strong shard are validated
        // via drain_pending once the strong shard arrives, enabling reconstruction.
        //
        // With 10 peers: minimum_shards = (10-1)/3 + 1 = 4
        // We send 3 pending reshards + 1 strong shard = 4 shards -> reconstruction.
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

                // Get reshards from peers 0, 1, and 2 (3 total to meet minimum_shards=4).
                let reshards: Vec<_> = [0, 1, 2]
                    .iter()
                    .map(|&i| {
                        coded_block
                            .shard::<H>(peers[i].index.get() as usize)
                            .expect("missing shard")
                            .verify_into_reshard()
                            .expect("reshard failed")
                    })
                    .collect();

                let peer3_pk = peers[3].public_key.clone();

                // Send reshards to peer 3 BEFORE their strong shard arrives.
                // These will be stored in pending_shards since there's no checking data yet.
                for (i, reshard) in reshards.iter().enumerate() {
                    let sender_idx = [0, 1, 2][i];
                    let reshard_bytes = reshard.encode();
                    peers[sender_idx]
                        .sender
                        .send(Recipients::One(peer3_pk.clone()), reshard_bytes, true)
                        .await
                        .expect("send failed");
                }

                context.sleep(config.link.latency * 2).await;

                // Block should not be reconstructed yet (no checking data from strong shard).
                let block = peers[3].mailbox.get(commitment).await;
                assert!(block.is_none(), "block should not be reconstructed yet");

                // Now send peer 2's strong shard. This should:
                // 1. Provide checking data
                // 2. Trigger drain_pending which validates the 3 pending reshards
                // 3. With 4 checked shards (1 strong + 3 from pending), trigger reconstruction
                let strong_bytes = peer3_strong_shard.encode();
                peers[2]
                    .sender
                    .send(Recipients::One(peer3_pk), strong_bytes, true)
                    .await
                    .expect("send failed");

                context.sleep(config.link.latency * 2).await;

                // No peers should be blocked (all reshards were valid).
                let blocked = oracle.blocked().await.unwrap();
                assert!(
                    blocked.is_empty(),
                    "no peers should be blocked for valid pending reshards"
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
                let coded_block = CodedBlock::<B, C>::new(inner, coding_config.clone(), &STRATEGY);
                let commitment = coded_block.commitment();

                // Send some shards to peer 0 to create reconstruction state.
                let peer0_pk = peers[0].public_key.clone();
                for i in 1..3 {
                    let reshard = coded_block
                        .shard::<H>(peers[i].index.get() as usize)
                        .expect("missing shard")
                        .verify_into_reshard()
                        .expect("reshard failed");
                    let reshard_bytes = reshard.encode();
                    peers[i]
                        .sender
                        .send(Recipients::One(peer0_pk.clone()), reshard_bytes, true)
                        .await
                        .expect("send failed");
                }
                context.sleep(config.link.latency * 2).await;

                // Create a subscription that should be cleared.
                let sub = peers[0].mailbox.subscribe_block_by_commitment(commitment).await;

                // Send UpdateParticipants to clear state.
                // Use a new participant set (same keys, just triggers the clear).
                let new_participants: Set<P> =
                    Set::from_iter_dedup(peers.iter().map(|p| p.public_key.clone()));
                peers[0]
                    .mailbox
                    .update_participants(new_participants)
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
                for i in 1..3 {
                    let reshard = coded_block
                        .shard::<H>(peers[i].index.get() as usize)
                        .expect("missing shard")
                        .verify_into_reshard()
                        .expect("reshard failed");
                    let reshard_bytes = reshard.encode();
                    peers[i]
                        .sender
                        .send(Recipients::One(peer0_pk.clone()), reshard_bytes, true)
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
                peers[0].mailbox.update_participants(new_participants).await;

                context.sleep(Duration::from_millis(10)).await;

                // Peer 3 (now non-participant) sends a shard to peer 0.
                let reshard = coded_block
                    .shard::<H>(peers[3].index.get() as usize)
                    .expect("missing shard")
                    .verify_into_reshard()
                    .expect("reshard failed");
                let reshard_bytes = reshard.encode();
                peers[3]
                    .sender
                    .send(Recipients::One(peer0_pk.clone()), reshard_bytes, true)
                    .await
                    .expect("send failed");

                context.sleep(config.link.latency * 2).await;

                // Peer 3 should be blocked by peer 0 for being a non-participant.
                assert_blocked(&oracle, &peer0_pk, &peer3_pk).await;
            },
        );
    }
}
