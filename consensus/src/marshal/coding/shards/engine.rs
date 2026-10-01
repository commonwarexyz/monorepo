//! Shard engine for erasure-coded block distribution and reconstruction.
//!
//! This module implements the core logic for distributing blocks as erasure-coded
//! shards and reconstructing blocks from received shards.
//!
//! # Overview
//!
//! The shard engine serves two primary functions:
//! 1. Broadcast: When a node proposes a block, the engine broadcasts
//!    erasure-coded shards to all participants and to non-participants in
//!    aggregate membership (peers in [`commonware_p2p::PeerSetUpdate::all`]
//!    but not in the epoch participant list).
//!    The leader sends each participant their indexed shard.
//! 2. Block Reconstruction: When a node receives shards from peers, the engine
//!    validates them and reconstructs the original block once enough valid
//!    shards are available. Both participants and non-participants can
//!    reconstruct blocks: participants receive their own indexed shard from
//!    the leader, while non-participants reconstruct from shards gossiped
//!    by participants. All participants gossip their validated shard to peers.
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
//!            broadcast_shards (each participant's indexed shard)
//!                              |
//!         +--------------------+--------------------+
//!         |                    |                    |
//!         v                    v                    v
//!    Participant 0        Participant 1        Participant N
//!         |                    |                    |
//!         | (receive shard     | (receive shard     |
//!         |  for own index)    |  for own index)    |
//!         v                    v                    v
//!    +----------+         +----------+         +----------+
//!    | Validate |         | Validate |         | Validate |
//!    | (check)  |         | (check)  |         | (check)  |
//!    +----------+         +----------+         +----------+
//!         |                    |                    |
//!         +--------------------+--------------------+
//!                              |
//!                    (gossip validated shards)
//!                              |
//!         +--------------------+--------------------+
//!         |                    |                    |
//!         v                    v                    v
//!    Accumulate checked shards until minimum_shards reached
//!         |                    |                    |
//!         v                    v                    v
//!            Batch verify pending shards at quorum
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
//! For each [`Commitment`] that is either leader-discovered or notarized and
//! admitted by the record window, nodes (both participants and non-participants)
//! maintain a [`ReconstructionState`].
//! Before either consensus signal is observed (a leader announcement or a
//! notarization for the commitment), shards are buffered in bounded per-peer
//! queues:
//!
//! ```text
//!    +----------------------+
//!    | AwaitingQuorum       |
//!    | - leader known       |
//!    | - assigned shard     |  <--- verified immediately on receipt
//!    |   verified eagerly   |
//!    | - other shards       |  <--- buffered in pending_shards
//!    |   buffered           |
//!    +----------------------+
//!               |
//!               | checked + pending shards >= minimum_shards
//!               v
//!    +----------------------+
//!    | Reconstruction Job   |  <--- one strategy job runs batch
//!    |                      |       validation and decoding
//!    +----------------------+
//!               |
//!      +--------+--------+
//!      |        |        |
//!      v        v        v
//!   Success  Too few   Failure
//!      |      valid      |
//!      |        |        v
//!      |        v      Remove
//!      |   AwaitingQuorum  State
//!      v
//!    +----------------------+
//!    | Ready                |
//!    | - block cached       |
//!    | - no new gossip      |
//!    |   shards accepted    |
//!    | - assigned shard may |
//!    |   still arrive late  |
//!    +----------------------+
//! ```
//!
//! _Per-peer buffers are only kept for peers in `latest.primary`, matching [`commonware_broadcast::buffered`].
//! When a peer is no longer in `latest.primary`, all its buffered shards are evicted._
//!
//! # Peer Validation and Blocking Rules
//!
//! The engine enforces strict validation to prevent Byzantine attacks:
//!
//! - All shards MUST be sent by participants in the current epoch.
//! - Any participant may deliver the recipient's assigned shard.
//! - Any participant may gossip its own shard.
//! - All shards MUST pass cryptographic verification against the commitment.
//! - Shards MUST NOT be wider than the coding scheme produces for a block of the
//!   maximum block size under the shard's coding config.
//! - Each shard index may only contribute ONE shard per commitment.
//! - Sending a second shard for the same index with different data
//!   (equivocation) while the commitment awaits quorum results in blocking.
//!   Exact duplicates are silently ignored.
//!
//! Peers found violating these rules are blocked via the [`Blocker`] trait.
//! The width rule is enforced on receipt of every shard. The other rules are
//! applied while a commitment is actively tracked in reconstruction state.
//! Buffered shards are verified only as reconstruction needs them. Until the
//! leader is known, shards whose index differs from their sender's stay in the
//! per-peer queues. Once a block is cached, its record retains no shards,
//! verifies only a late assigned shard, and ignores other sender-indexed
//! shards.
//!
//! _Before proposal context is known, shards are buffered in fixed-size per-peer
//! queues until consensus signals the proposal via [`Mailbox::discovered`]
//! or a notarization via [`Mailbox::notarized`]. A notarization activates
//! reconstruction interest without a leader, so only sender-indexed gossip
//! shards can be ingested. Other shards remain buffered until proposal
//! discovery._
//!
//! # Record Window
//!
//! The engine retains at most [`Config::records`] commitment records. Only
//! local signals ([`Mailbox::proposed`], [`Mailbox::discovered`], and
//! [`Mailbox::notarized`]) create records. Once the window is full, records
//! with the lowest rounds are evicted first, and a signal at or below the
//! lowest retained round creates no record and leaves the commitment's shards
//! in the per-peer queues. Eviction closes no subscription.

use super::{
    mailbox::{Mailbox, Message},
    metrics::ShardMetrics,
};
use crate::{
    Block, CertifiableBlock, Heightable,
    marshal::coding::{
        types::{CodedBlock, Shard},
        validation::{ReconstructionError as InvariantError, validate_reconstruction},
    },
    types::{Epoch, Round, coding::Commitment},
};
use commonware_actor::mailbox;
use commonware_codec::{Decode, EncodeSize, Error as CodecError, FixedSize};
use commonware_coding::{Config as CodingConfig, Scheme as CodingScheme};
use commonware_cryptography::{
    Committable, Digestible, Hasher, PublicKey,
    certificate::{Provider, Scheme as CertificateScheme},
};
use commonware_macros::select_loop;
use commonware_p2p::{
    Blocker, Provider as PeerProvider, Receiver, Recipients, Sender,
    utils::codec::{WrappedBackgroundReceiver, WrappedSender},
};
use commonware_parallel::Strategy;
use commonware_runtime::{
    BufferPooler, Clock, ContextCell, Handle, Metrics, Spawner, spawn_cell,
    telemetry::metrics::HistogramExt,
};
use commonware_utils::{
    bitmap::BitMap,
    channel::{fallible::OneshotExt, oneshot},
    futures::{AbortablePool, Aborter},
    iter::zip_eq,
    ordered::{Quorum, Set},
};
use rand_core::Rng;
use std::{
    collections::{BTreeMap, VecDeque, btree_map::Entry},
    iter, mem,
    num::NonZeroUsize,
    sync::Arc,
    time::SystemTime,
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

    /// The reconstructed block is larger than the maximum block size
    #[error("oversized block: reconstructed block exceeds the maximum block size")]
    Oversized,
}

/// The outcome of a reconstruction job.
enum Outcome<B, C: CodingScheme> {
    /// Fewer than the minimum shards passed verification. Holds every checked shard.
    Insufficient(Vec<C::CheckedShard>),
    /// Enough shards passed verification to decode the block.
    Decoded(Result<B, Error<C>>),
}

/// A finished reconstruction job.
struct Reconstructed<P, B, C: CodingScheme, H> {
    /// The commitment whose block the job reconstructs.
    commitment: Commitment<B, C, H>,
    /// When the job was submitted.
    start: SystemTime,
    /// Senders whose shards failed verification.
    invalid: Vec<P>,
    /// The result of verification and decoding.
    outcome: Outcome<B, C>,
}

/// Verifies `pending` shards and decodes the block once at least the minimum are checked.
fn reconstruct<P, B, C, H>(
    commitment: Commitment<B, C, H>,
    start: SystemTime,
    mut checked: Vec<C::CheckedShard>,
    pending: Vec<(P, IndexedShard<C>)>,
    cfg: &B::Cfg,
    max_block_size: NonZeroUsize,
    strategy: &impl Strategy,
) -> Reconstructed<P, B, C, H>
where
    P: PublicKey,
    B: CertifiableBlock,
    C: CodingScheme,
    H: Hasher,
{
    let config = commitment.config();
    let mut invalid = Vec::new();
    if !pending.is_empty() {
        // The batch result order keeps verification failures bound to their senders.
        let shards = pending
            .iter()
            .map(|(_, shard)| (shard.index, &shard.data))
            .collect::<Vec<_>>();
        let results = C::check_many(&config, &commitment.root(), &shards, strategy);
        for ((peer, _), result) in zip_eq(pending, results) {
            match result {
                Ok(shard) => checked.push(shard),
                Err(_) => invalid.push(peer),
            }
        }
    }
    let outcome = if checked.len() < usize::from(config.minimum_shards.get()) {
        Outcome::Insufficient(checked)
    } else {
        Outcome::Decoded(decode(commitment, &checked, cfg, max_block_size, strategy))
    };
    Reconstructed {
        commitment,
        start,
        invalid,
        outcome,
    }
}

/// Decodes the block encoded by `checked` shards and validates it against `commitment`.
fn decode<B, C, H>(
    commitment: Commitment<B, C, H>,
    checked: &[C::CheckedShard],
    cfg: &B::Cfg,
    max_block_size: NonZeroUsize,
    strategy: &impl Strategy,
) -> Result<B, Error<C>>
where
    B: CertifiableBlock,
    C: CodingScheme,
    H: Hasher,
{
    let blob = C::decode(
        &commitment.config(),
        &commitment.root(),
        checked.iter(),
        strategy,
    )
    .map_err(Error::Coding)?;

    // The blob is the block followed by its coding config.
    if blob.len() > max_block_size.get().saturating_add(CodingConfig::SIZE) {
        return Err(Error::Oversized);
    }
    let (inner, config): (B, CodingConfig) = Decode::decode_cfg(blob, &(cfg.clone(), ()))?;
    match validate_reconstruction(&inner, config, commitment) {
        Ok(()) => Ok(inner),
        Err(InvariantError::BlockDigest) => Err(Error::DigestMismatch),
        Err(InvariantError::CodingConfig) => {
            debug!(
                %commitment,
                expected_config = ?commitment.config(),
                actual_config = ?config,
                "reconstructed block config does not match commitment config, but digest matches"
            );
            Err(Error::ConfigMismatch)
        }
        Err(InvariantError::ContextDigest(expected, actual)) => {
            debug!(
                %commitment,
                expected_context_digest = ?expected,
                actual_context_digest = ?actual,
                "reconstructed block context digest does not match commitment context digest"
            );
            Err(Error::ContextMismatch)
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum BlockSubscriptionKey<K, D> {
    Commitment(K),
    Digest(D),
}

/// Configuration for the [`Engine`].
pub struct Config<P, S, X, D, B, T>
where
    P: PublicKey,
    S: Provider<Scope = Epoch>,
    X: Blocker<PublicKey = P>,
    D: PeerProvider<PublicKey = P>,
    B: CertifiableBlock,
    T: Strategy,
{
    /// The scheme provider.
    pub scheme_provider: S,

    /// The peer blocker.
    pub blocker: X,

    /// The maximum encoded size of a block.
    ///
    /// Peers are blocked for sending a shard wider than the coding scheme produces for a block of
    /// this size under the shard's coding config. Larger blocks are neither reconstructed nor
    /// broadcast. Every node must use the same value.
    pub max_block_size: NonZeroUsize,

    /// [`commonware_codec::Read`] configuration for decoding blocks.
    pub block_codec_cfg: B::Cfg,

    /// The strategy used for parallel computation.
    ///
    /// Reconstruction jobs are submitted to this strategy, which may run a job inline on the
    /// engine task.
    pub strategy: T,

    /// The size of the mailbox buffer.
    pub mailbox_size: NonZeroUsize,

    /// Number of shards to buffer per peer.
    ///
    /// Shards for commitments without a reconstruction state are buffered per
    /// peer in a fixed-size ring to bound memory under Byzantine spam. These
    /// shards are only ingested when consensus provides a leader via
    /// [`Mailbox::discovered`] or reports a notarization via
    /// [`Mailbox::notarized`].
    ///
    /// The shard buffers hold at most `peer_buffer_size` shards per `latest.primary` peer. Each
    /// shard is no wider than the coding scheme produces for a `max_block_size` block under the
    /// coding config the shard claims. A config that claims one minimum shard makes a shard as
    /// wide as the whole coded block, so each peer buffers at most `peer_buffer_size` blocks.
    pub peer_buffer_size: NonZeroUsize,

    /// The maximum number of commitment records retained.
    ///
    /// Records with the lowest rounds are evicted first. Once the window is full, a consensus
    /// signal at or below the lowest retained round creates no record. Must be at least
    /// `2 * (max(1, optimistic_views) + 2)`, where `optimistic_views` is
    /// [`crate::simplex::elector::Terms::optimistic_views`].
    pub records: NonZeroUsize,

    /// Capacity of the channel between the background receiver and the engine.
    ///
    /// The background receiver decodes incoming network messages in a separate
    /// task and forwards them to the engine over a mailbox with this
    /// capacity.
    pub background_channel_capacity: NonZeroUsize,

    /// Provider for peer set information. Pre-leader shards are buffered per
    /// peer only while that peer appears in the
    /// [`commonware_p2p::PeerSetUpdate::latest`] primary set, matching
    /// [`commonware_broadcast::buffered::Engine`]. Broadcast delivery uses the
    /// aggregate [`commonware_p2p::PeerSetUpdate::all`] union.
    pub peer_provider: D,
}

/// The data currently owned for a consensus commitment.
enum CommitmentPhase<B, C, H, P>
where
    B: Block,
    C: CodingScheme,
    H: Hasher,
    P: PublicKey,
{
    /// Shards are still being accumulated or validated.
    Reconstructing(ReconstructionState<P, B, C, H>),
    /// The block is cached. Retained reconstruction state holds no shards and only
    /// tracks verification of a late assigned shard.
    Cached {
        block: Arc<CodedBlock<B, C, H>>,
        reconstruction: Option<ReconstructionState<P, B, C, H>>,
    },
}

/// The single lifecycle owner for a consensus commitment.
///
/// The observation round determines both the eviction order and the epoch whose
/// participant scheme classifies shards. Keeping it outside the phase prevents
/// cached and reconstructing views of the same commitment from diverging.
struct CommitmentRecord<B, C, H, P>
where
    B: Block,
    C: CodingScheme,
    H: Hasher,
    P: PublicKey,
{
    round: Round,
    phase: CommitmentPhase<B, C, H, P>,
    proposed: bool,
}

/// Lifecycle records keyed by the complete commitment, including its coding
/// root and configuration.
type CommitmentRecords<B, C, H, P> = BTreeMap<Commitment<B, C, H>, CommitmentRecord<B, C, H, P>>;

/// The current lifecycle status of a commitment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CommitmentStatus {
    /// No record exists for the commitment.
    Absent,
    /// The commitment is accumulating or validating shards.
    Reconstructing,
    /// The commitment has an available block.
    Cached,
}

impl<B, C, H, P> CommitmentRecord<B, C, H, P>
where
    B: Block,
    C: CodingScheme,
    H: Hasher,
    P: PublicKey,
{
    /// Creates a record that is reconstructing a commitment observed at `round`.
    const fn reconstructing(round: Round, reconstruction: ReconstructionState<P, B, C, H>) -> Self {
        Self {
            round,
            phase: CommitmentPhase::Reconstructing(reconstruction),
            proposed: false,
        }
    }

    /// Creates a record for a block already available at `round`.
    const fn cached(round: Round, block: Arc<CodedBlock<B, C, H>>) -> Self {
        Self {
            round,
            phase: CommitmentPhase::Cached {
                block,
                reconstruction: None,
            },
            proposed: false,
        }
    }

    /// Returns the latest valid observation round.
    const fn round(&self) -> Round {
        self.round
    }

    /// Ensures that `round` uses the epoch that owns this commitment record.
    fn validate_epoch(&self, round: Round) -> Result<(), Epoch> {
        let existing_epoch = self.round.epoch();
        if existing_epoch != round.epoch() {
            return Err(existing_epoch);
        }
        Ok(())
    }

    /// Records a same-epoch observation without moving the eviction round backward.
    fn observe(&mut self, round: Round) -> Result<(), Epoch> {
        self.validate_epoch(round)?;
        self.round = self.round.max(round);
        Ok(())
    }

    /// Returns the cached block, if available.
    const fn block(&self) -> Option<&Arc<CodedBlock<B, C, H>>> {
        match &self.phase {
            CommitmentPhase::Reconstructing(_) => None,
            CommitmentPhase::Cached { block, .. } => Some(block),
        }
    }

    /// Returns shard reconstruction state retained for the commitment, if any.
    const fn reconstruction(&self) -> Option<&ReconstructionState<P, B, C, H>> {
        match &self.phase {
            CommitmentPhase::Reconstructing(reconstruction) => Some(reconstruction),
            CommitmentPhase::Cached { reconstruction, .. } => reconstruction.as_ref(),
        }
    }

    /// Returns mutable shard reconstruction state retained for the commitment, if any.
    const fn reconstruction_mut(&mut self) -> Option<&mut ReconstructionState<P, B, C, H>> {
        match &mut self.phase {
            CommitmentPhase::Reconstructing(reconstruction) => Some(reconstruction),
            CommitmentPhase::Cached { reconstruction, .. } => reconstruction.as_mut(),
        }
    }

    /// Returns whether the local validator can satisfy its assigned-shard obligation.
    fn is_assigned_shard_ready(&self) -> bool {
        self.proposed
            || self
                .reconstruction()
                .is_some_and(ReconstructionState::is_assigned_shard_verified)
    }

    /// Records that the local validator built and cached this commitment.
    const fn mark_proposed(&mut self) {
        self.proposed = true;
    }

    /// Caches `block` while preserving reconstruction state needed for shard readiness.
    ///
    /// If a block is already cached, retains and returns the existing instance.
    fn install_block(&mut self, block: Arc<CodedBlock<B, C, H>>) -> Arc<CodedBlock<B, C, H>> {
        let previous = std::mem::replace(
            &mut self.phase,
            CommitmentPhase::Cached {
                block: Arc::clone(&block),
                reconstruction: None,
            },
        );
        self.phase = match previous {
            CommitmentPhase::Reconstructing(reconstruction) => CommitmentPhase::Cached {
                block: Arc::clone(&block),
                reconstruction: Some(reconstruction.into_ready()),
            },
            cached @ CommitmentPhase::Cached { .. } => cached,
        };
        self.block()
            .cloned()
            .expect("installing a block must leave a cached phase")
    }
}

/// A network layer for broadcasting and receiving [`CodedBlock`]s as [`Shard`]s.
///
/// When enough [`Shard`]s are present in the mailbox, the [`Engine`] may facilitate
/// reconstruction of the original [`CodedBlock`] and notify any subscribers waiting for it.
pub struct Engine<E, S, X, D, C, H, B, P, T>
where
    E: BufferPooler + Rng + Spawner + Metrics + Clock,
    S: Provider<Scope = Epoch>,
    S::Scheme: CertificateScheme<PublicKey = P>,
    X: Blocker,
    D: PeerProvider<PublicKey = P>,
    C: CodingScheme,
    H: Hasher,
    B: CertifiableBlock,
    P: PublicKey,
    T: Strategy,
{
    /// Context held by the actor.
    context: ContextCell<E>,

    /// Receiver for incoming messages to the actor.
    mailbox: mailbox::Receiver<Message<B, C, H, P>>,

    /// The scheme provider.
    scheme_provider: S,

    /// The peer blocker.
    blocker: X,

    /// The maximum encoded size of a block.
    max_block_size: NonZeroUsize,

    /// [`commonware_codec::Read`] configuration for decoding [`CodedBlock`]s.
    block_codec_cfg: B::Cfg,

    /// The strategy used for parallel shard verification.
    strategy: T,

    /// The cache and reconstruction lifecycle for each observed [`Commitment`].
    records: CommitmentRecords<B, C, H, P>,

    /// Per-peer ring buffers for shards received before leader announcement.
    ///
    /// Empty buffers are retained for active peers and only evicted when the
    /// peer leaves `latest.primary`.
    peer_buffers: BTreeMap<P, VecDeque<Shard<B, C, H>>>,

    /// Maximum buffered pre-leader shards per peer.
    peer_buffer_size: NonZeroUsize,

    /// Maximum number of commitment records retained.
    window: NonZeroUsize,

    /// Provider for peer set information.
    peer_provider: D,

    /// Latest union of peer membership from the peer set subscription
    /// ([`commonware_p2p::PeerSetUpdate::all`]).
    aggregate_peers: Set<P>,

    /// Latest primary peers allowed to retain pre-leader shard buffers.
    latest_primary_peers: Set<P>,

    /// Capacity of the background receiver channel.
    background_channel_capacity: NonZeroUsize,

    /// Open subscriptions for assigned shard verification for the keyed
    /// [`Commitment`].
    ///
    /// For participants, readiness is satisfied once the shard for the local
    /// participant index has been verified. Reconstruction from peer gossip is
    /// tracked separately and does not satisfy this readiness condition.
    ///
    /// Proposers are a special case: they satisfy readiness once their local
    /// proposal is cached because they already hold all shards.
    assigned_shard_verified_subscriptions: BTreeMap<Commitment<B, C, H>, Vec<oneshot::Sender<()>>>,

    /// Open subscriptions for the reconstruction of a [`CodedBlock`] with
    /// the keyed [`Commitment`].
    #[allow(clippy::type_complexity)]
    block_subscriptions: BTreeMap<
        BlockSubscriptionKey<Commitment<B, C, H>, B::Digest>,
        Vec<oneshot::Sender<Arc<CodedBlock<B, C, H>>>>,
    >,

    /// Reconstruction jobs. Each job's [`Aborter`] is held by the reconstruction state of its
    /// commitment.
    jobs: AbortablePool<'static, Reconstructed<P, B, C, H>>,

    /// Metrics for the shard engine.
    metrics: ShardMetrics<P>,
}

impl<E, S, X, D, C, H, B, P, T> Engine<E, S, X, D, C, H, B, P, T>
where
    E: BufferPooler + Rng + Spawner + Metrics + Clock,
    S: Provider<Scope = Epoch>,
    S::Scheme: CertificateScheme<PublicKey = P>,
    X: Blocker<PublicKey = P>,
    D: PeerProvider<PublicKey = P>,
    C: CodingScheme,
    H: Hasher,
    B: CertifiableBlock,
    P: PublicKey,
    T: Strategy,
{
    /// Create a new [`Engine`] with the given configuration.
    pub fn new(context: E, config: Config<P, S, X, D, B, T>) -> (Self, Mailbox<B, C, H, P>) {
        let metrics = ShardMetrics::new(&context);
        let (sender, mailbox) = mailbox::new(context.child("mailbox"), config.mailbox_size);
        (
            Self {
                context: ContextCell::new(context),
                mailbox,
                scheme_provider: config.scheme_provider,
                blocker: config.blocker,
                max_block_size: config.max_block_size,
                block_codec_cfg: config.block_codec_cfg,
                strategy: config.strategy,
                records: BTreeMap::new(),
                peer_buffers: BTreeMap::new(),
                peer_buffer_size: config.peer_buffer_size,
                window: config.records,
                peer_provider: config.peer_provider,
                aggregate_peers: Set::default(),
                latest_primary_peers: Set::default(),
                background_channel_capacity: config.background_channel_capacity,
                assigned_shard_verified_subscriptions: BTreeMap::new(),
                block_subscriptions: BTreeMap::new(),
                jobs: AbortablePool::default(),
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
        spawn_cell!(self.context, self.run(network))
    }

    /// Run the shard engine's event loop.
    async fn run(
        mut self,
        (sender, receiver): (impl Sender<PublicKey = P>, impl Receiver<PublicKey = P>),
    ) {
        let mut sender = WrappedSender::<_, Shard<B, C, H>>::new(
            self.context.network_buffer_pool().clone(),
            sender,
        );
        let (receiver_service, mut receiver) =
            WrappedBackgroundReceiver::<_, P, X, _, Shard<B, C, H>, T>::new(
                self.context.child("shard_ingress"),
                receiver,
                self.max_block_size,
                self.blocker.clone(),
                self.background_channel_capacity,
                self.strategy.clone(),
            );
        // Keep the handle alive to prevent the background receiver from being aborted.
        let _receiver_handle = receiver_service.start();
        let mut peer_set_subscription = self.peer_provider.subscribe().await;

        select_loop! {
            self.context,
            on_start => {
                // Clean up closed subscriptions.
                self.block_subscriptions.retain(|_, subscribers| {
                    subscribers.retain(|tx| !tx.is_closed());
                    !subscribers.is_empty()
                });
                self.assigned_shard_verified_subscriptions
                    .retain(|_, subscribers| {
                        subscribers.retain(|tx| !tx.is_closed());
                        !subscribers.is_empty()
                    });
            },
            on_stopped => {
                debug!("received shutdown signal, stopping shard engine");
            },
            // Removing or caching a record aborts its job.
            Ok(reconstructed) = self.jobs.next_completed() else continue => {
                self.complete(reconstructed);
            },
            Some(update) = peer_set_subscription.recv() else {
                debug!("peer set subscription closed");
                return;
            } => {
                let all_peers = update.all.union();
                self.update_latest_primary_peers(update.latest.primary);
                self.aggregate_peers = all_peers;
            },
            Some(message) = self.mailbox.recv() else {
                debug!("shard mailbox closed, stopping shard engine");
                return;
            } => {
                if message.response_closed() {
                    continue;
                }

                match message {
                    Message::Proposed { block, round } => {
                        self.broadcast_shards(&mut sender, round, block);
                    }
                    Message::Discovered {
                        commitment,
                        leader,
                        round,
                    } => {
                        self.handle_external_proposal(&mut sender, commitment, leader, round);
                    }
                    Message::Notarized { commitment, round } => {
                        self.handle_notarized_commitment(&mut sender, commitment, round);
                    }
                    Message::GetByCommitment {
                        commitment,
                        response,
                    } => {
                        let block = self
                            .records
                            .get(&commitment)
                            .and_then(CommitmentRecord::block)
                            .cloned();
                        response.send_lossy(block);
                    }
                    Message::GetByDigest { digest, response } => {
                        let block = self.records.values().find_map(|record| {
                            let block = record.block()?;
                            (block.digest() == digest).then(|| Arc::clone(block))
                        });
                        response.send_lossy(block);
                    }
                    Message::SubscribeAssignedShardVerified {
                        commitment,
                        response,
                    } => {
                        self.handle_assigned_shard_verified_subscription(commitment, response);
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
                        self.handle_block_subscription(
                            BlockSubscriptionKey::Digest(digest),
                            response,
                        );
                    }
                }

                // A consensus signal may have admitted a record beyond the window.
                self.trim();
            },
            Some((peer, shard)) = receiver.recv() else {
                debug!("receiver closed, stopping shard engine");
                return;
            } => {
                self.handle_network_shard(&mut sender, peer, shard);
            },
        }
    }

    /// Handles a decoded shard received from the network.
    fn handle_network_shard<Sr: Sender<PublicKey = P>>(
        &mut self,
        sender: &mut WrappedSender<Sr, Shard<B, C, H>>,
        peer: P,
        shard: Shard<B, C, H>,
    ) {
        self.metrics.shards_received.get_or_create_by(&peer).inc();

        let commitment = shard.commitment();
        if !self.should_handle_network_shard(commitment) {
            return;
        }

        if let Some(record) = self.records.get(&commitment)
            && let Some(existing) = record.reconstruction()
        {
            let round = record.round();
            let Some(scheme) = self.scheme_provider.scheme(round.epoch()) else {
                debug!(%commitment, "no scheme for epoch, ignoring shard");
                return;
            };

            // Notarized recovery can create state before leader discovery. Until
            // the leader is known, only sender-indexed gossip shards are safe to
            // ingest: a participant may only gossip its own shard.
            if existing.leader().is_none()
                && let Some(sender_index) = scheme.participants().index(&peer)
            {
                let expected_index: u16 = sender_index
                    .get()
                    .try_into()
                    .expect("participant index impossibly out of bounds");
                if shard.index() != expected_index {
                    // A mismatched shard may be assigned to us, but it cannot be
                    // classified until consensus supplies the proposal context.
                    self.buffer_peer_shard(peer, shard);
                    return;
                }
            }

            let state = self
                .records
                .get_mut(&commitment)
                .and_then(CommitmentRecord::reconstruction_mut)
                .expect("reconstruction checked as present");
            let progressed =
                state.on_network_shard(peer, shard, scheme.as_ref(), &mut self.blocker);
            if progressed {
                self.try_advance(sender, commitment);
            }
        } else {
            self.buffer_peer_shard(peer, shard);
        }
    }

    /// Returns whether an incoming network shard should still be processed.
    ///
    /// Shards for reconstructed commitments are normally ignored. The only
    /// exception is a late shard for the assigned index, which we still accept
    /// so we can notify readiness and gossip it to slower peers.
    fn should_handle_network_shard(&self, commitment: Commitment<B, C, H>) -> bool {
        if let Some(record) = self.records.get(&commitment)
            && record.block().is_some()
        {
            // State can be populated before our assigned shard is verified. Keep
            // handling shards until that state is complete.
            return record
                .reconstruction()
                .is_some_and(|s| !s.is_assigned_shard_verified());
        }
        true
    }

    /// Starts a job that verifies pending shards and decodes the block once the checked and
    /// pending shards reach the minimum.
    fn try_reconstruct(&mut self, commitment: Commitment<B, C, H>) {
        // Only records without a cached block await quorum, and each holds at most one job.
        let Some(ReconstructionState::AwaitingQuorum(state)) = self
            .records
            .get_mut(&commitment)
            .and_then(CommitmentRecord::reconstruction_mut)
        else {
            return;
        };
        let minimum = usize::from(commitment.config().minimum_shards.get());
        let checked = state.checked_shards.len();
        if state.job.is_some() || checked + state.pending_shards.len() < minimum {
            return;
        }

        // Verify only the pending shards decoding needs. The rest replace any that fail.
        let pending = iter::from_fn(|| state.pending_shards.pop_first())
            .take(minimum.saturating_sub(checked))
            .collect::<Vec<_>>();
        let checked = mem::take(&mut state.checked_shards);
        let len = state
            .received_shards
            .values()
            .map(EncodeSize::encode_size)
            .sum();
        let cfg = self.block_codec_cfg.clone();
        let max_block_size = self.max_block_size;
        let start = self.context.current();
        let job = self.strategy.spawn(len, move |strategy| {
            reconstruct(
                commitment,
                start,
                checked,
                pending,
                &cfg,
                max_block_size,
                &strategy,
            )
        });
        state.job = Some(self.jobs.push(job));
    }

    /// Applies a finished reconstruction job to the record that started it.
    ///
    /// A successful reconstruction caches the block and drops the record's shards. A failed
    /// reconstruction removes the record and closes its commitment-specific subscriptions. With
    /// too few valid shards, the checked shards return to the record and another job starts once
    /// enough shards are available.
    fn complete(&mut self, reconstructed: Reconstructed<P, B, C, H>) {
        let Reconstructed {
            commitment,
            start,
            invalid,
            outcome,
        } = reconstructed;
        for peer in invalid {
            commonware_p2p::block!(self.blocker, peer, "invalid shard received");
        }

        // Removing or caching a record drops its job's aborter, and an aborted job never
        // completes.
        let record = self
            .records
            .get_mut(&commitment)
            .expect("a completed job's record must exist");
        let round = record.round();
        let Some(ReconstructionState::AwaitingQuorum(state)) = record.reconstruction_mut() else {
            unreachable!("a completed job's record must await quorum");
        };
        state.job = None;
        match outcome {
            Outcome::Insufficient(checked) => {
                state.checked_shards.extend(checked);
                self.try_reconstruct(commitment);
            }
            Outcome::Decoded(Ok(inner)) => {
                self.metrics
                    .reconstruction_duration
                    .observe_between(start, self.context.current());

                // Decoding verified the blob against the commitment, so shards can be lazily
                // re-constructed if need be.
                let block = self
                    .cache_block(round, Arc::new(CodedBlock::new_trusted(inner, commitment)))
                    .expect("reconstruction uses its commitment record's epoch");
                self.metrics.blocks_reconstructed_total.inc();

                // Do not prune other records here. A Byzantine leader can
                // equivocate by proposing multiple commitments in the same
                // round, so more than one block may be reconstructed for a
                // given round. Cached blocks leave only through window eviction.
                debug!(
                    %commitment,
                    parent = %block.parent(),
                    height = %block.height(),
                    "successfully reconstructed block from shards"
                );
            }
            Outcome::Decoded(Err(err)) => {
                debug!(%commitment, ?err, "failed to reconstruct block from checked shards");
                self.evict(commitment);
                self.assigned_shard_verified_subscriptions
                    .remove(&commitment);

                // Before marshal accepts a block, a candidate can claim a digest it cannot
                // reconstruct. Removing it therefore does not prove the digest unavailable.
                self.block_subscriptions
                    .remove(&BlockSubscriptionKey::Commitment(commitment));
                self.metrics.reconstruction_failures_total.inc();
            }
        }
    }

    /// Handles leader announcements for a commitment and advances reconstruction.
    fn handle_external_proposal<Sr: Sender<PublicKey = P>>(
        &mut self,
        sender: &mut WrappedSender<Sr, Shard<B, C, H>>,
        commitment: Commitment<B, C, H>,
        leader: P,
        round: Round,
    ) {
        let Some(scheme) = self.scheme_provider.scheme(round.epoch()) else {
            warn!(%commitment, "no scheme for epoch, ignoring external proposal");
            return;
        };
        let participants = scheme.participants();
        if participants.index(&leader).is_none() {
            warn!(?leader, %commitment, "leader update for non-participant, ignoring");
            return;
        }
        // A reconstructed block normally makes duplicate leader announcements
        // redundant, unless notarized recovery created leaderless state first.
        // In that case, the leader announcement must still populate the
        // leader-dependent path.
        let Some(status) = self.observe_existing_commitment(commitment, round) else {
            return;
        };
        if status == CommitmentStatus::Cached
            && self
                .records
                .get(&commitment)
                .and_then(CommitmentRecord::reconstruction)
                .is_none_or(|state| state.leader().is_some())
        {
            return;
        }
        if let Some(state) = self
            .records
            .get_mut(&commitment)
            .and_then(CommitmentRecord::reconstruction_mut)
        {
            if let Some(existing) = state.leader() {
                if existing != &leader {
                    // A later leader is expected when this commitment is
                    // re-proposed. Retaining the first does not impede participant
                    // readiness because assigned shards are source-independent.
                    debug!(
                        existing = ?existing,
                        ?leader,
                        %commitment,
                        "commitment already has a leader, ignoring update"
                    );
                }
                return;
            }
            state
                .set_leader(leader)
                .expect("leader was checked as absent");
        } else {
            // Shards for a commitment the window declines stay in the peer buffers.
            if !self.admits(round) {
                debug!(
                    %commitment,
                    %round,
                    "discovered commitment at or below the lowest retained round"
                );
                return;
            }
            let participants_len = u64::try_from(participants.len())
                .expect("participant count impossibly out of bounds");
            self.insert_reconstruction_record(
                commitment,
                round,
                ReconstructionState::new(Some(leader), participants_len),
            );
        }
        let buffered_progress = self.ingest_buffered_shards(commitment);
        if buffered_progress {
            self.try_advance(sender, commitment);
        }
    }

    /// Handles notarized reconstruction interest before the leader is known.
    ///
    /// This is intentionally narrower than leader discovery: it may reconstruct
    /// the block from sender-indexed gossip shards, but it cannot mark the
    /// local assigned shard as verified.
    fn handle_notarized_commitment<Sr: Sender<PublicKey = P>>(
        &mut self,
        sender: &mut WrappedSender<Sr, Shard<B, C, H>>,
        commitment: Commitment<B, C, H>,
        round: Round,
    ) {
        let Some(status) = self.observe_existing_commitment(commitment, round) else {
            return;
        };
        if status == CommitmentStatus::Cached {
            return;
        }
        if status == CommitmentStatus::Reconstructing {
            let buffered_progress = self.ingest_buffered_shards(commitment);
            if buffered_progress {
                self.try_advance(sender, commitment);
            }
            return;
        }
        let Some(scheme) = self.scheme_provider.scheme(round.epoch()) else {
            warn!(%commitment, "no scheme for epoch, ignoring notarized commitment");
            return;
        };

        // Shards for a commitment the window declines stay in the peer buffers.
        if !self.admits(round) {
            debug!(
                %commitment,
                %round,
                "notarized commitment at or below the lowest retained round"
            );
            return;
        }
        let participants_len = u64::try_from(scheme.participants().len())
            .expect("participant count impossibly out of bounds");
        self.insert_reconstruction_record(
            commitment,
            round,
            ReconstructionState::new(None, participants_len),
        );
        let buffered_progress = self.ingest_buffered_shards(commitment);
        if buffered_progress {
            self.try_advance(sender, commitment);
        }
    }

    /// Buffer a shard from a peer until a leader is known.
    fn buffer_peer_shard(&mut self, peer: P, shard: Shard<B, C, H>) {
        if self.latest_primary_peers.position(&peer).is_none() {
            debug!(
                ?peer,
                "pre-leader shard from peer outside latest.primary not buffered"
            );
            return;
        }
        let queue = self.peer_buffers.entry(peer).or_default();
        if queue.len() >= self.peer_buffer_size.get() {
            let _ = queue.pop_front();
        }
        queue.push_back(shard);
    }

    fn update_latest_primary_peers(&mut self, peers: Set<P>) {
        self.peer_buffers
            .retain(|peer, _| peers.position(peer).is_some());
        self.latest_primary_peers = peers;
    }

    /// Ingest buffered pre-leader shards for a commitment into active state.
    ///
    /// Before proposal context is known, only sender-indexed gossip is
    /// actionable. Once context exists, the local assigned index is valid from
    /// any participant because its proof is bound to the commitment.
    fn ingest_buffered_shards(&mut self, commitment: Commitment<B, C, H>) -> bool {
        let record = self
            .records
            .get(&commitment)
            .expect("buffered shards can only be ingested with a commitment record");
        let round = record.round();
        let state = record
            .reconstruction()
            .expect("buffered shards can only be ingested with reconstruction state");
        let leader_known = state.leader().is_some();
        let Some(scheme) = self.scheme_provider.scheme(round.epoch()) else {
            warn!(%commitment, "no scheme for epoch, dropping buffered shards");
            return false;
        };

        let mut buffered = Vec::new();
        for (peer, queue) in self.peer_buffers.iter_mut() {
            let mut i = 0;
            while i < queue.len() {
                if queue[i].commitment() != commitment {
                    i += 1;
                    continue;
                }
                if !leader_known {
                    let Some(sender_index) = scheme.participants().index(peer) else {
                        i += 1;
                        continue;
                    };
                    let expected_index: u16 = sender_index
                        .get()
                        .try_into()
                        .expect("participant index impossibly out of bounds");
                    if queue[i].index() != expected_index {
                        i += 1;
                        continue;
                    }
                }
                let shard = queue.swap_remove_back(i).expect("index is valid");
                buffered.push((peer.clone(), shard));
            }
        }

        let state = self
            .records
            .get_mut(&commitment)
            .and_then(CommitmentRecord::reconstruction_mut)
            .expect("reconstruction state checked before buffered shard drain");

        // Ingest buffered shards into the active reconstruction state.
        let mut progressed = false;
        for (peer, shard) in buffered {
            progressed |= state.on_network_shard(peer, shard, scheme.as_ref(), &mut self.blocker);
        }
        progressed
    }

    /// Records a consensus observation on an existing commitment owner.
    ///
    /// Returns the record's phase, [`CommitmentStatus::Absent`] if it has no
    /// owner yet, or `None` when its owner is bound to a different epoch.
    fn observe_existing_commitment(
        &mut self,
        commitment: Commitment<B, C, H>,
        round: Round,
    ) -> Option<CommitmentStatus> {
        let observed_epoch = round.epoch();
        let Some(record) = self.records.get_mut(&commitment) else {
            return Some(CommitmentStatus::Absent);
        };
        if let Err(existing_epoch) = record.observe(round) {
            warn!(
                %commitment,
                %existing_epoch,
                %observed_epoch,
                "commitment observation has conflicting epoch, ignoring"
            );
            return None;
        }
        Some(if record.block().is_some() {
            CommitmentStatus::Cached
        } else {
            CommitmentStatus::Reconstructing
        })
    }

    /// Creates the first lifecycle record for a reconstructing commitment.
    fn insert_reconstruction_record(
        &mut self,
        commitment: Commitment<B, C, H>,
        round: Round,
        reconstruction: ReconstructionState<P, B, C, H>,
    ) {
        let Entry::Vacant(entry) = self.records.entry(commitment) else {
            unreachable!("commitment status was checked as absent");
        };
        entry.insert(CommitmentRecord::reconstructing(round, reconstruction));
        self.metrics.reconstruction_states_count.inc();
    }

    /// Returns whether the window admits a new record observed at `round`.
    fn admits(&self, round: Round) -> bool {
        self.records.len() < self.window.get()
            || self.records.values().any(|record| record.round() < round)
    }

    /// Evicts the lowest-round records while the window is over capacity.
    ///
    /// Ties are evicted in commitment order.
    fn trim(&mut self) {
        while self.records.len() > self.window.get() {
            let (&commitment, _) = self
                .records
                .iter()
                .min_by_key(|(_, record)| record.round())
                .expect("an over-capacity window must hold a record");
            self.evict(commitment);
        }
    }

    /// Removes the record for `commitment` without closing any subscription.
    ///
    /// Dropping the record aborts its reconstruction job.
    fn evict(&mut self, commitment: Commitment<B, C, H>) {
        let Some(record) = self.records.remove(&commitment) else {
            return;
        };
        if record.reconstruction().is_some() {
            self.metrics.reconstruction_states_count.dec();
        }
        if record.block().is_some() {
            self.metrics.reconstructed_blocks_cache_count.dec();
        }
    }

    /// Caches a block and notifies all subscribers waiting on it.
    ///
    /// A block without a record is retained only if the window admits `round`.
    fn cache_block(
        &mut self,
        round: Round,
        block: Arc<CodedBlock<B, C, H>>,
    ) -> Result<Arc<CodedBlock<B, C, H>>, Epoch> {
        let commitment = block.commitment();
        let cached = if let Some(record) = self.records.get_mut(&commitment) {
            record.observe(round)?;
            let newly_cached = record.block().is_none();
            let cached = record.install_block(block);
            if newly_cached {
                self.metrics.reconstructed_blocks_cache_count.inc();
            }
            cached
        } else {
            if self.admits(round) {
                self.records.insert(
                    commitment,
                    CommitmentRecord::cached(round, Arc::clone(&block)),
                );
                self.metrics.reconstructed_blocks_cache_count.inc();
            }
            block
        };
        self.notify_block_subscribers(Arc::clone(&cached));
        Ok(cached)
    }

    /// Broadcasts the shards of a [`CodedBlock`] and caches the block.
    ///
    /// - Participants receive the shard matching their participant index.
    /// - Non-participants in aggregate membership receive the leader's shard.
    fn broadcast_shards<Sr: Sender<PublicKey = P>>(
        &mut self,
        sender: &mut WrappedSender<Sr, Shard<B, C, H>>,
        round: Round,
        block: Arc<CodedBlock<B, C, H>>,
    ) {
        let commitment = block.commitment();

        if let Some(record) = self.records.get(&commitment)
            && let Err(existing_epoch) = record.validate_epoch(round)
        {
            warn!(
                %commitment,
                %existing_epoch,
                observed_epoch = %round.epoch(),
                "local proposal has conflicting epoch, ignoring"
            );
            return;
        }

        let Some(scheme) = self.scheme_provider.scheme(round.epoch()) else {
            warn!(%commitment, "no scheme available, cannot broadcast shards");
            return;
        };
        let participants = scheme.participants();
        let Some(me) = scheme.me() else {
            warn!(
                %commitment,
                "cannot broadcast shards: local proposer is not a participant"
            );
            return;
        };

        // Peers block senders of shards wider than a block of the maximum size produces.
        let size = block.inner().encode_size();
        if size > self.max_block_size.get() {
            debug!(
                %commitment,
                size,
                max = self.max_block_size.get(),
                "cannot broadcast shards: block exceeds the maximum size"
            );
            return;
        }

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

        let my_index = me.get() as usize;
        let leader_shard = block
            .shard(my_index as u16)
            .expect("proposer's shard must exist");

        // Broadcast each participant their corresponding shard.
        for (index, peer) in participants.iter().enumerate() {
            if index == my_index {
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
            let _ = sender.send(Recipients::One(peer.clone()), shard, true);
        }

        // Send the leader's shard to peers in aggregate membership who are not participants.
        let non_participants: Vec<P> = self
            .aggregate_peers
            .iter()
            .filter(|peer| participants.index(peer).is_none())
            .cloned()
            .collect();
        if !non_participants.is_empty() {
            let _ = sender.send(Recipients::Some(non_participants), leader_shard, true);
        }

        // Cache the block so we don't have to reconstruct it again. The window may decline a
        // block from an old round.
        self.cache_block(round, block)
            .expect("local proposal epoch was validated before broadcast");
        if let Some(record) = self.records.get_mut(&commitment) {
            record.mark_proposed();
        }

        // Local proposals bypass reconstruction, so shard subscribers waiting
        // for "our valid shard arrived" still need a notification.
        self.notify_assigned_shard_verified_subscribers(commitment);

        debug!(?commitment, "broadcasted shards");
    }

    /// Gossips a validated [`Shard`] using [`commonware_p2p::Recipients::All`].
    fn broadcast_shard<Sr: Sender<PublicKey = P>>(
        &mut self,
        sender: &mut WrappedSender<Sr, Shard<B, C, H>>,
        shard: Shard<B, C, H>,
    ) {
        let commitment = shard.commitment();
        let peers = sender.send(Recipients::All, shard, true);
        debug!(
            ?commitment,
            peers = peers.len(),
            "broadcasted shard to all peers"
        );
    }

    /// Broadcasts any pending validated shard and starts reconstruction when enough shards
    /// are available.
    fn try_advance<Sr: Sender<PublicKey = P>>(
        &mut self,
        sender: &mut WrappedSender<Sr, Shard<B, C, H>>,
        commitment: Commitment<B, C, H>,
    ) {
        if let Some(state) = self
            .records
            .get_mut(&commitment)
            .and_then(CommitmentRecord::reconstruction_mut)
        {
            match state.take_pending_action() {
                Some(AssignedShardVerifiedAction::Broadcast(shard)) => {
                    self.broadcast_shard(sender, shard);
                    self.notify_assigned_shard_verified_subscribers(commitment);
                }
                Some(AssignedShardVerifiedAction::NotifyOnly) => {
                    self.notify_assigned_shard_verified_subscribers(commitment);
                }
                None => {}
            }
        }
        self.try_reconstruct(commitment);
    }

    /// Handles the registry of an assigned shard verification subscription.
    ///
    /// For participants this is tied to verification of the shard for the local
    /// index, not to generic block reconstruction.
    fn handle_assigned_shard_verified_subscription(
        &mut self,
        commitment: Commitment<B, C, H>,
        response: oneshot::Sender<()>,
    ) {
        // Answer immediately if our own shard has been verified or we built the block.
        if self
            .records
            .get(&commitment)
            .is_some_and(CommitmentRecord::is_assigned_shard_ready)
        {
            response.send_lossy(());
            return;
        }

        self.assigned_shard_verified_subscriptions
            .entry(commitment)
            .or_default()
            .push(response);
    }

    /// Handles the registry of a block subscription.
    fn handle_block_subscription(
        &mut self,
        key: BlockSubscriptionKey<Commitment<B, C, H>, B::Digest>,
        response: oneshot::Sender<Arc<CodedBlock<B, C, H>>>,
    ) {
        let block = match key {
            BlockSubscriptionKey::Commitment(commitment) => self
                .records
                .get(&commitment)
                .and_then(CommitmentRecord::block),
            BlockSubscriptionKey::Digest(digest) => self
                .records
                .values()
                .filter_map(CommitmentRecord::block)
                .find(|block| block.digest() == digest),
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

    /// Notifies and cleans up any subscriptions waiting for assigned shard
    /// verification.
    fn notify_assigned_shard_verified_subscribers(&mut self, commitment: Commitment<B, C, H>) {
        if let Some(mut subscribers) = self
            .assigned_shard_verified_subscriptions
            .remove(&commitment)
        {
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
}

/// Erasure coded block reconstruction state machine.
enum ReconstructionState<P, B, C, H>
where
    P: PublicKey,
    B: Digestible,
    C: CodingScheme,
    H: Hasher,
{
    /// Stage 1: accumulate shards. The shard for our assigned index is verified
    /// immediately. Other shards are buffered, and reconstruction jobs verify those
    /// that decoding needs.
    AwaitingQuorum(AwaitingQuorumState<P, B, C, H>),
    /// Stage 2: the block is cached. Only the assigned shard is still accepted.
    Ready(ReadyState<P, B, C, H>),
}

/// Action to take once assigned shard verification has been established.
///
/// Participants broadcast the shard to all peers, while non-participants
/// only notify local subscribers.
enum AssignedShardVerifiedAction<B: Digestible, C: CodingScheme, H: Hasher> {
    /// Broadcast the shard to all peers and notify local subscribers.
    Broadcast(Shard<B, C, H>),
    /// Only notify local subscribers (non-participant validated the leader's shard).
    NotifyOnly,
}

/// A coding shard paired with its participant index.
struct IndexedShard<C: CodingScheme> {
    index: u16,
    data: C::Shard,
}

/// State shared across all reconstruction phases.
struct CommonState<P, B, C, H>
where
    P: PublicKey,
    B: Digestible,
    C: CodingScheme,
    H: Hasher,
{
    /// The leader associated with this reconstruction state, if consensus has
    /// provided it.
    leader: Option<P>,
    /// Our validated shard and the action to take with it.
    pending_action: Option<AssignedShardVerifiedAction<B, C, H>>,
    /// Bitmap tracking which participant indices have contributed a shard.
    contributed: BitMap,
    /// Whether the shard for our assigned index has been verified.
    assigned_shard_verified: bool,
}

/// Phase data for `ReconstructionState::AwaitingQuorum`.
///
/// In this phase, the leader may be unknown. Sender-indexed shards can still be
/// buffered until enough are available to attempt batch validation. Once proposal
/// context is known, the shard for our assigned index is verified eagerly via
/// `C::check`, regardless of which participant delivered it.
struct AwaitingQuorumState<P, B, C, H>
where
    P: PublicKey,
    B: Digestible,
    C: CodingScheme,
    H: Hasher,
{
    common: CommonState<P, B, C, H>,
    /// Raw shard data received per index, retained for equivocation detection.
    received_shards: BTreeMap<u16, C::Shard>,
    /// Shards that have been verified and are ready to contribute to reconstruction.
    checked_shards: Vec<C::CheckedShard>,
    /// Shards pending batch validation, keyed by sender.
    pending_shards: BTreeMap<P, IndexedShard<C>>,
    /// The in-flight reconstruction job. Dropping it discards the job's result.
    job: Option<Aborter>,
}

/// Phase data for `ReconstructionState::Ready`.
///
/// The block is cached and no shards are retained. Only the assigned shard is still accepted.
struct ReadyState<P, B, C, H>
where
    P: PublicKey,
    B: Digestible,
    C: CodingScheme,
    H: Hasher,
{
    common: CommonState<P, B, C, H>,
}

impl<P, B, C, H> CommonState<P, B, C, H>
where
    P: PublicKey,
    B: Digestible,
    C: CodingScheme,
    H: Hasher,
{
    /// Create a new empty common state for the provided leader.
    fn new(leader: Option<P>, participants_len: u64) -> Self {
        Self {
            leader,
            pending_action: None,
            contributed: BitMap::zeroes(participants_len),
            assigned_shard_verified: false,
        }
    }
}

impl<P, B, C, H> ReconstructionState<P, B, C, H>
where
    P: PublicKey,
    B: Digestible,
    C: CodingScheme,
    H: Hasher,
{
    /// Create an initial reconstruction state for a commitment.
    fn new(leader: Option<P>, participants_len: u64) -> Self {
        Self::AwaitingQuorum(AwaitingQuorumState {
            common: CommonState::new(leader, participants_len),
            received_shards: BTreeMap::new(),
            checked_shards: Vec::new(),
            pending_shards: BTreeMap::new(),
            job: None,
        })
    }

    /// Ends shard accumulation once the block is cached, dropping received, checked, and
    /// pending shards and any in-flight job.
    fn into_ready(self) -> Self {
        match self {
            Self::AwaitingQuorum(state) => Self::Ready(ReadyState {
                common: state.common,
            }),
            ready @ Self::Ready(_) => ready,
        }
    }

    /// Access common state shared across all phases.
    const fn common(&self) -> &CommonState<P, B, C, H> {
        match self {
            Self::AwaitingQuorum(state) => &state.common,
            Self::Ready(state) => &state.common,
        }
    }

    /// Mutably access common state shared across all phases.
    const fn common_mut(&mut self) -> &mut CommonState<P, B, C, H> {
        match self {
            Self::AwaitingQuorum(state) => &mut state.common,
            Self::Ready(state) => &mut state.common,
        }
    }

    /// Return the leader associated with this state.
    const fn leader(&self) -> Option<&P> {
        self.common().leader.as_ref()
    }

    /// Set the leader for this state if it has not already been set.
    fn set_leader(&mut self, leader: P) -> Result<(), P> {
        if self.common().leader.is_some() {
            return Err(leader);
        }
        self.common_mut().leader = Some(leader);
        Ok(())
    }

    /// Returns whether the shard for our assigned index has been verified.
    const fn is_assigned_shard_verified(&self) -> bool {
        self.common().assigned_shard_verified
    }

    /// Takes the pending action for this commitment's validated shard.
    ///
    /// Returns [`None`] if the assigned shard hasn't been validated yet.
    const fn take_pending_action(&mut self) -> Option<AssignedShardVerifiedAction<B, C, H>> {
        self.common_mut().pending_action.take()
    }

    /// Verify the assigned shard and schedule the action to take with it.
    ///
    /// When `is_participant` is true, the validated shard is stored for
    /// broadcasting to peers. When false (non-participant), only subscriber
    /// notification is scheduled. While awaiting quorum, the shard also
    /// contributes to reconstruction.
    ///
    /// Returns `false` if verification fails (sender is blocked), `true` on
    /// success.
    fn verify_assigned_shard(
        &mut self,
        sender: P,
        commitment: Commitment<B, C, H>,
        shard: IndexedShard<C>,
        is_participant: bool,
        blocker: &mut impl Blocker<PublicKey = P>,
    ) -> bool {
        let Ok(checked) = C::check(
            &commitment.config(),
            &commitment.root(),
            shard.index,
            &shard.data,
        ) else {
            commonware_p2p::block!(blocker, sender, "invalid assigned shard received");
            return false;
        };

        let common = self.common_mut();
        common.contributed.set(u64::from(shard.index), true);
        common.assigned_shard_verified = true;
        common.pending_action = Some(if is_participant {
            AssignedShardVerifiedAction::Broadcast(Shard::new(
                commitment,
                shard.index,
                shard.data.clone(),
            ))
        } else {
            AssignedShardVerifiedAction::NotifyOnly
        });
        if let Self::AwaitingQuorum(state) = self {
            state.received_shards.insert(shard.index, shard.data);
            state.checked_shards.push(checked);
        }
        true
    }

    /// Handle an incoming network shard.
    ///
    /// Returns `true` only when the shard caused state progress (buffered or
    /// validated), and `false` when rejected/blocked.
    ///
    /// ## Peer Blocking Rules
    ///
    /// The `sender` may be blocked via the provided [`Blocker`] if any of
    /// the following rules are violated:
    ///
    /// - MUST be sent by a participant in the current epoch. Non-participant
    ///   senders are blocked.
    /// - A participant's assigned index may be delivered by any participant.
    /// - Other shards MUST match the sender's participant index.
    /// - Once proposal context is known, any other shard index results in
    ///   blocking.
    /// - Each shard index may only contribute ONE shard per commitment.
    ///   Sending a second shard for the same index with different data
    ///   (equivocation) while awaiting quorum results in blocking the sender.
    /// - The assigned shard is verified eagerly via [`CodingScheme::check`].
    ///   If verification fails, the sender is blocked.
    /// - Own-index shards are buffered in `pending_shards`. Once enough shards
    ///   are available, a reconstruction job batch-validates the pending shards
    ///   that decoding needs and blocks the sender of each invalid one. Pending
    ///   shards left over when the block is cached are dropped unchecked.
    ///
    /// ## Silent Discard Rules
    ///
    /// The following conditions cause a shard to be silently ignored
    /// without blocking the sender:
    ///
    /// - Exact duplicate of a previously received shard for the same index
    ///   while awaiting quorum.
    /// - The index has already been marked as contributed (via the bitmap,
    ///   e.g. after batch validation).
    /// - Sender-indexed shards that arrive after the state has transitioned to
    ///   [`ReconstructionState::Ready`] (i.e., the block is cached), including
    ///   ones that conflict with earlier shards. An assigned shard for our
    ///   index is still verified in `Ready` state.
    /// - Before a reconstruction state exists, shards are buffered at the
    ///   engine level in bounded per-peer queues until [`Mailbox::discovered`]
    ///   or [`Mailbox::notarized`] creates state for this commitment.
    fn on_network_shard<Sch, X>(
        &mut self,
        sender: P,
        shard: Shard<B, C, H>,
        scheme: &Sch,
        blocker: &mut X,
    ) -> bool
    where
        Sch: CertificateScheme<PublicKey = P>,
        X: Blocker<PublicKey = P>,
    {
        let Some(sender_index) = scheme.participants().index(&sender) else {
            commonware_p2p::block!(blocker, sender, "shard sent by non-participant");
            return false;
        };
        let commitment = shard.commitment();
        let indexed = IndexedShard {
            index: shard.index(),
            data: shard.into_inner(),
        };

        // A participant's assigned shard is source-independent because it is
        // verified eagerly. Every other shard must be sender-owned so each sender
        // contributes at most one shard before batch verification.
        let sender_index: u16 = sender_index
            .get()
            .try_into()
            .expect("participant index impossibly out of bounds");
        let assigned_index: Option<u16> = scheme.me().map(|assigned_index| {
            assigned_index
                .get()
                .try_into()
                .expect("participant index impossibly out of bounds")
        });
        let is_from_leader = self.leader().is_some_and(|leader| leader == &sender);
        let is_assigned_shard = assigned_index
            .is_some_and(|assigned_index| indexed.index == assigned_index)
            || assigned_index.is_none() && is_from_leader && indexed.index == sender_index;
        let is_gossip_shard = indexed.index == sender_index;
        if !is_assigned_shard && !is_gossip_shard {
            if self.leader().is_some() {
                commonware_p2p::block!(
                    blocker,
                    sender,
                    shard_index = indexed.index,
                    "shard index is neither assigned nor sender-owned"
                );
            }
            return false;
        }

        // Equivocation/duplicate check while awaiting quorum.
        if let Self::AwaitingQuorum(state) = self
            && let Some(existing) = state.received_shards.get(&indexed.index)
        {
            if existing != &indexed.data {
                commonware_p2p::block!(blocker, sender, "shard equivocation");
            }
            return false;
        }

        // Check if this index already contributed (via batch validation).
        if self.common().contributed.get(u64::from(indexed.index)) {
            return false;
        }

        // The assigned shard is always verified eagerly, even after transitioning
        // to Ready. This ensures we broadcast it to help slower peers reach quorum.
        if is_assigned_shard && !self.common().assigned_shard_verified {
            return self.verify_assigned_shard(
                sender,
                commitment,
                indexed,
                scheme.me().is_some(),
                blocker,
            );
        }

        // Gossip shards are only accepted while awaiting quorum.
        let Self::AwaitingQuorum(state) = self else {
            return false;
        };

        // Buffer for batch validation.
        state
            .received_shards
            .insert(indexed.index, indexed.data.clone());
        state.common.contributed.set(u64::from(indexed.index), true);
        state.pending_shards.insert(sender, indexed);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        marshal::{coding::types::coding_config_for_participants, mocks::block::EmptyBlock},
        types::{Epoch, Height, View},
    };
    use bytes::Bytes;
    use commonware_codec::Encode;
    use commonware_coding::{Config as CodingConfig, ReedSolomon};
    use commonware_cryptography::{
        Committable, Digest, Sha256, Signer,
        certificate::{Scoped, Subject},
        ed25519::{PrivateKey, PublicKey},
        impl_certificate_ed25519,
        sha256::Digest as Sha256Digest,
    };
    use commonware_macros::{select, test_traced};
    use commonware_p2p::{
        Manager as _, TrackedPeers,
        simulated::{self, Control, Link, Oracle},
    };
    use commonware_parallel::{Rayon, Sequential};
    use commonware_runtime::{Quota, Runner, Supervisor as _, deterministic, utils::reschedule};
    use commonware_utils::{
        N3f1, NZUsize, Participant, channel::oneshot::error::TryRecvError, ordered::Set,
        probability, sync::Mutex,
    };
    use futures::FutureExt as _;
    use std::{
        future::Future,
        marker::PhantomData,
        num::{NonZeroU32, NonZeroUsize},
        sync::{
            Arc,
            atomic::{AtomicIsize, Ordering},
            mpsc,
        },
        thread,
        time::Duration,
    };

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

    impl_certificate_ed25519!(TestSubject, Vec<u8>, N3f1);

    const SCHEME_NAMESPACE: &[u8] = b"_COMMONWARE_SHARD_ENGINE_TEST";

    /// The max size of a shard sent over the wire.
    const MAX_SHARD_SIZE: usize = 1024 * 1024; // 1 MiB

    /// The maximum encoded size of a block.
    const MAX_BLOCK_SIZE: NonZeroUsize = NZUsize!(1024);

    /// The default link configuration for tests.
    const DEFAULT_LINK: Link = Link {
        latency: Duration::from_millis(50),
        jitter: Duration::ZERO,
        success_rate: probability!(1.0),
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

        fn scoped(&self, scope: Epoch) -> Option<Scoped<Scheme>> {
            self.schemes.get(&scope).cloned().map(Scoped::scheme)
        }
    }

    /// A one-epoch scheme provider that churns to `None` after a fixed number
    /// of successful scope lookups.
    #[derive(Clone)]
    struct ChurningProvider {
        scheme: Arc<Scheme>,
        remaining_successes: Arc<AtomicIsize>,
    }

    impl ChurningProvider {
        fn new(scheme: Scheme, successes: isize) -> Self {
            Self {
                scheme: Arc::new(scheme),
                remaining_successes: Arc::new(AtomicIsize::new(successes)),
            }
        }
    }

    impl Provider for ChurningProvider {
        type Scope = Epoch;
        type Scheme = Scheme;

        fn scoped(&self, scope: Epoch) -> Option<Scoped<Scheme>> {
            if scope != Epoch::zero() {
                return None;
            }
            if self.remaining_successes.fetch_sub(1, Ordering::AcqRel) <= 0 {
                return None;
            }
            Some(Scoped::scheme(Arc::clone(&self.scheme)))
        }
    }

    // Type aliases for test convenience.
    type B = EmptyBlock<H>;
    type H = Sha256;
    type P = PublicKey;
    type C = ReedSolomon<H>;
    type X = Control<P, deterministic::Context>;
    type O = Oracle<P, deterministic::Context>;
    type Prov = MultiEpochProvider;
    type NetworkSender = simulated::Sender<P, deterministic::Context>;
    type D = simulated::Manager<P, deterministic::Context>;
    type ShardEngine<S> = Engine<deterministic::Context, Prov, X, D, S, H, B, P, Sequential>;
    type ChurningShardEngine<S> =
        Engine<deterministic::Context, ChurningProvider, X, D, S, H, B, P, Sequential>;

    /// Requires individual checking for the assigned shard and one batch for queued shards.
    #[derive(Clone, Debug)]
    struct BatchChecking;

    impl CodingScheme for BatchChecking {
        type Commitment = <C as CodingScheme>::Commitment;
        type Shard = <C as CodingScheme>::Shard;
        type CheckedShard = <C as CodingScheme>::CheckedShard;
        type Error = <C as CodingScheme>::Error;

        fn encode(
            config: &CodingConfig,
            data: impl bytes::Buf,
            strategy: &impl Strategy,
        ) -> Result<(Self::Commitment, Vec<Self::Shard>), Self::Error> {
            C::encode(config, data, strategy)
        }

        fn check(
            config: &CodingConfig,
            commitment: &Self::Commitment,
            index: u16,
            shard: &Self::Shard,
        ) -> Result<Self::CheckedShard, Self::Error> {
            assert_eq!(index, 3, "only the assigned shard is checked eagerly");
            C::check(config, commitment, index, shard)
        }

        fn check_many(
            config: &CodingConfig,
            commitment: &Self::Commitment,
            shards: &[(u16, &Self::Shard)],
            strategy: &impl Strategy,
        ) -> Vec<Result<Self::CheckedShard, Self::Error>> {
            assert_eq!(shards.len(), 7);
            C::check_many(config, commitment, shards, strategy)
        }

        fn decode<'a>(
            config: &CodingConfig,
            commitment: &Self::Commitment,
            shards: impl Iterator<Item = &'a Self::CheckedShard>,
            strategy: &impl Strategy,
        ) -> Result<Vec<u8>, Self::Error> {
            C::decode(config, commitment, shards, strategy)
        }
    }

    /// An armed [`GATE`].
    struct Gate {
        /// Signals that decode started.
        started: mpsc::Sender<()>,
        /// Releases the held decode.
        release: mpsc::Receiver<()>,
        /// The engine thread, which decode must not run on.
        engine: thread::ThreadId,
    }

    /// Holds [`Gated::decode`] until released.
    static GATE: Mutex<Option<Gate>> = Mutex::new(None);

    /// Reed-Solomon coding whose decode holds while [`GATE`] is armed.
    #[derive(Clone, Debug)]
    struct Gated;

    impl CodingScheme for Gated {
        type Commitment = <C as CodingScheme>::Commitment;
        type Shard = <C as CodingScheme>::Shard;
        type CheckedShard = <C as CodingScheme>::CheckedShard;
        type Error = <C as CodingScheme>::Error;

        fn encode(
            config: &CodingConfig,
            data: impl bytes::Buf,
            strategy: &impl Strategy,
        ) -> Result<(Self::Commitment, Vec<Self::Shard>), Self::Error> {
            C::encode(config, data, strategy)
        }

        fn check(
            config: &CodingConfig,
            commitment: &Self::Commitment,
            index: u16,
            shard: &Self::Shard,
        ) -> Result<Self::CheckedShard, Self::Error> {
            C::check(config, commitment, index, shard)
        }

        fn check_many(
            config: &CodingConfig,
            commitment: &Self::Commitment,
            shards: &[(u16, &Self::Shard)],
            strategy: &impl Strategy,
        ) -> Vec<Result<Self::CheckedShard, Self::Error>> {
            C::check_many(config, commitment, shards, strategy)
        }

        fn decode<'a>(
            config: &CodingConfig,
            commitment: &Self::Commitment,
            shards: impl Iterator<Item = &'a Self::CheckedShard>,
            strategy: &impl Strategy,
        ) -> Result<Vec<u8>, Self::Error> {
            let gate = GATE.lock().take();
            if let Some(Gate {
                started,
                release,
                engine,
            }) = gate
            {
                assert_ne!(
                    thread::current().id(),
                    engine,
                    "reconstruction ran on the engine task"
                );
                started.send(()).unwrap();
                release.recv().unwrap();
            }
            C::decode(config, commitment, shards, strategy)
        }
    }

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

    /// A non-participant in the test network with its engine mailbox.
    #[allow(dead_code)]
    struct NonParticipant<S: CodingScheme = C> {
        /// The peer's public key.
        public_key: PublicKey,
        /// The mailbox for sending messages to the peer's shard engine.
        mailbox: Mailbox<B, S, H, P>,
        /// Raw network sender for injecting messages.
        sender: NetworkSender,
    }

    /// Test fixture for setting up multiple participants with shard engines.
    struct Fixture<S: CodingScheme = C> {
        /// Number of primary peers created during setup.
        num_primary_peers: usize,
        /// Number of secondary peers created during setup.
        num_secondary_peers: usize,
        /// Number of peers introduced after setup.
        num_future_peers: usize,
        /// Additional epochs that use the fixture's participant set.
        additional_scheme_epochs: Vec<Epoch>,
        /// Network link configuration.
        link: Link,
        /// Per-peer capacity for shards received before leader discovery.
        peer_buffer_size: NonZeroUsize,
        /// Maximum number of commitment records each engine retains.
        records: NonZeroUsize,
        /// The maximum encoded size of a block.
        max_block_size: NonZeroUsize,
        /// Marker for the coding scheme type parameter.
        _marker: PhantomData<S>,
    }

    impl<S: CodingScheme> Default for Fixture<S> {
        fn default() -> Self {
            Self {
                num_primary_peers: 4,
                num_secondary_peers: 0,
                num_future_peers: 0,
                additional_scheme_epochs: Vec::new(),
                link: DEFAULT_LINK,
                peer_buffer_size: NZUsize!(64),
                records: NZUsize!(16),
                max_block_size: MAX_BLOCK_SIZE,
                _marker: PhantomData,
            }
        }
    }

    impl<S: CodingScheme> Fixture<S> {
        pub fn start<F: Future<Output = ()>>(
            self,
            f: impl FnOnce(
                Self,
                deterministic::Context,
                O,
                Vec<Peer<S>>,
                Vec<NonParticipant<S>>,
                CodingConfig,
            ) -> F,
        ) {
            let executor = deterministic::Runner::default();
            executor.start(|context| async move {
                let mut private_keys = (0..self.num_primary_peers)
                    .map(|i| PrivateKey::from_seed(i as u64))
                    .collect::<Vec<_>>();
                private_keys.sort_by_key(|s| s.public_key());
                let peer_keys: Vec<P> = private_keys.iter().map(|c| c.public_key()).collect();

                let participants: Set<P> = Set::from_iter_dedup(peer_keys.clone());

                let mut np_private_keys = (0..self.num_secondary_peers)
                    .map(|i| PrivateKey::from_seed((self.num_primary_peers + i) as u64))
                    .collect::<Vec<_>>();
                np_private_keys.sort_by_key(|s| s.public_key());
                let np_keys: Vec<P> = np_private_keys.iter().map(|k| k.public_key()).collect();

                let (network, oracle) =
                    simulated::Network::<deterministic::Context, P>::new_with_split_peers(
                        context.child("network"),
                        simulated::Config {
                            max_size: MAX_SHARD_SIZE as u32,
                            max_peers_per_set: NZUsize!(
                                self.num_primary_peers
                                    + self.num_secondary_peers.max(self.num_future_peers)
                            ),
                            disconnect_on_block: true,
                            tracked_peer_sets: NZUsize!(1),
                        },
                        peer_keys.clone(),
                        np_keys.clone(),
                    )
                    .await;
                network.start();

                let all_keys: Vec<P> = peer_keys.iter().chain(np_keys.iter()).cloned().collect();

                let mut registrations = BTreeMap::new();
                for key in all_keys.iter() {
                    let control = oracle.control(key.clone());
                    let (sender, receiver) = control
                        .register(0, TEST_QUOTA)
                        .await
                        .expect("registration should succeed");
                    registrations.insert(key.clone(), (control, sender, receiver));
                }
                for p1 in all_keys.iter() {
                    for p2 in all_keys.iter() {
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
                    coding_config_for_participants(u16::try_from(self.num_primary_peers).unwrap());

                let mut peers = Vec::with_capacity(self.num_primary_peers);
                for (idx, peer_key) in peer_keys.iter().enumerate() {
                    let (control, sender, receiver) = registrations
                        .remove(peer_key)
                        .expect("peer should be registered");

                    let participant = Participant::new(idx as u32);
                    let engine_context = context.child("peer").with_attribute("index", idx);

                    let scheme = Scheme::signer(
                        SCHEME_NAMESPACE,
                        participants.clone(),
                        private_keys[idx].clone(),
                    )
                    .expect("signer scheme should be created");
                    let mut scheme_provider = MultiEpochProvider::single(scheme);
                    for epoch in self.additional_scheme_epochs.iter().copied() {
                        let scheme = Scheme::signer(
                            SCHEME_NAMESPACE,
                            participants.clone(),
                            private_keys[idx].clone(),
                        )
                        .expect("signer scheme should be created");
                        scheme_provider = scheme_provider.with_epoch(epoch, scheme);
                    }

                    let config = Config {
                        scheme_provider,
                        blocker: control.clone(),
                        max_block_size: self.max_block_size,
                        block_codec_cfg: (),
                        strategy: STRATEGY,
                        mailbox_size: NZUsize!(1024),
                        peer_buffer_size: self.peer_buffer_size,
                        records: self.records,
                        background_channel_capacity: NZUsize!(1024),
                        peer_provider: oracle.manager(),
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

                let mut non_participants = Vec::with_capacity(self.num_secondary_peers);
                for (idx, np_key) in np_keys.iter().enumerate() {
                    let (control, sender, receiver) = registrations
                        .remove(np_key)
                        .expect("non-participant should be registered");

                    let engine_context = context
                        .child("non_participant")
                        .with_attribute("index", idx);

                    let scheme = Scheme::verifier(SCHEME_NAMESPACE, participants.clone());
                    let mut scheme_provider = MultiEpochProvider::single(scheme);
                    for epoch in self.additional_scheme_epochs.iter().copied() {
                        scheme_provider = scheme_provider.with_epoch(
                            epoch,
                            Scheme::verifier(SCHEME_NAMESPACE, participants.clone()),
                        );
                    }

                    let config = Config {
                        scheme_provider,
                        blocker: control.clone(),
                        max_block_size: self.max_block_size,
                        block_codec_cfg: (),
                        strategy: STRATEGY,
                        mailbox_size: NZUsize!(1024),
                        peer_buffer_size: self.peer_buffer_size,
                        records: self.records,
                        background_channel_capacity: NZUsize!(1024),
                        peer_provider: oracle.manager(),
                    };

                    let (engine, mailbox) = ShardEngine::new(engine_context, config);
                    let sender_clone = sender.clone();
                    engine.start((sender, receiver));

                    non_participants.push(NonParticipant {
                        public_key: np_key.clone(),
                        mailbox,
                        sender: sender_clone,
                    });
                }

                f(
                    self,
                    context,
                    oracle,
                    peers,
                    non_participants,
                    coding_config,
                )
                .await;
            });
        }
    }

    /// Builds an unstarted engine for the participant at `index` and the sender its handlers
    /// take. Every participant is in `latest.primary`.
    async fn unstarted(
        context: &deterministic::Context,
        oracle: &O,
        private_keys: &[PrivateKey],
        index: usize,
        records: NonZeroUsize,
    ) -> (ShardEngine<C>, WrappedSender<NetworkSender, Shard<B, C, H>>) {
        let participants: Set<P> =
            Set::from_iter_dedup(private_keys.iter().map(|key| key.public_key()));
        let control = oracle.control(private_keys[index].public_key());
        let (sender, _) = control
            .register(0, TEST_QUOTA)
            .await
            .expect("registration should succeed");
        let scheme = Scheme::signer(
            SCHEME_NAMESPACE,
            participants.clone(),
            private_keys[index].clone(),
        )
        .expect("signer scheme should be created");
        let config: Config<_, _, _, _, _, _> = Config {
            scheme_provider: MultiEpochProvider::single(scheme),
            blocker: control,
            max_block_size: MAX_BLOCK_SIZE,
            block_codec_cfg: (),
            strategy: STRATEGY,
            mailbox_size: NZUsize!(16),
            peer_buffer_size: NZUsize!(4),
            records,
            background_channel_capacity: NZUsize!(16),
            peer_provider: oracle.manager(),
        };
        let (mut engine, _) = ShardEngine::new(context.child("engine"), config);
        engine.update_latest_primary_peers(participants);
        let sender = WrappedSender::new(context.network_buffer_pool().clone(), sender);
        (engine, sender)
    }

    /// Returns the number of shards for `commitment` buffered from `peer`.
    fn buffered(engine: &ShardEngine<C>, peer: &P, commitment: Commitment<B, C, H>) -> usize {
        engine.peer_buffers.get(peer).map_or(0, |queue| {
            queue
                .iter()
                .filter(|shard| shard.commitment() == commitment)
                .count()
        })
    }

    /// Returns each engine's value of the gauge `name` from encoded metrics.
    fn gauges(metrics: &str, name: &str) -> Vec<i64> {
        metrics
            .lines()
            .filter(|line| !line.starts_with('#') && line.contains(name))
            .map(|line| {
                line.rsplit(' ')
                    .next()
                    .and_then(|value| value.parse().ok())
                    .expect("gauge value should parse")
            })
            .collect()
    }

    #[test_traced]
    fn test_e2e_broadcast_and_reconstruction() {
        let fixture = Fixture {
            num_primary_peers: 10,
            ..Default::default()
        };

        fixture.start(
            |config, context, _, mut peers, _, coding_config| async move {
                let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block = CodedBlock::<B, C, H>::new(inner, coding_config, &STRATEGY);
                let commitment = coded_block.commitment();

                let leader = peers[0].public_key.clone();
                let round = Round::new(Epoch::zero(), View::new(1));
                peers[0].mailbox.proposed(round, coded_block.clone());

                // Inform all peers of the leader so shards are processed.
                for peer in peers[1..].iter_mut() {
                    peer.mailbox.discovered(commitment, leader.clone(), round);
                }
                context.sleep(config.link.latency).await;

                for peer in peers.iter_mut() {
                    peer.mailbox
                        .subscribe_assigned_shard_verified(commitment)
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
            },
        );
    }

    #[test_traced]
    fn test_block_subscriptions() {
        let fixture = Fixture {
            num_primary_peers: 10,
            ..Default::default()
        };

        fixture.start(
            |config, context, _, mut peers, _, coding_config| async move {
                let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block = CodedBlock::<B, C, H>::new(inner, coding_config, &STRATEGY);
                let commitment = coded_block.commitment();
                let digest = coded_block.digest();

                let leader = peers[0].public_key.clone();
                let round = Round::new(Epoch::zero(), View::new(1));

                // Subscribe before broadcasting.
                let commitment_sub = peers[1].mailbox.subscribe(commitment);
                let digest_sub = peers[2].mailbox.subscribe_by_digest(digest);

                peers[0].mailbox.proposed(round, coded_block.clone());

                // Inform all peers of the leader so shards are processed.
                for peer in peers[1..].iter_mut() {
                    peer.mailbox.discovered(commitment, leader.clone(), round);
                }
                context.sleep(config.link.latency * 2).await;

                for peer in peers.iter_mut() {
                    peer.mailbox
                        .subscribe_assigned_shard_verified(commitment)
                        .await
                        .expect("shard subscription should complete");
                }
                context.sleep(config.link.latency).await;

                let block_by_commitment =
                    commitment_sub.await.expect("subscription should resolve");
                assert_eq!(block_by_commitment.commitment(), commitment);
                assert_eq!(block_by_commitment.height(), coded_block.height());

                let block_by_digest = digest_sub.await.expect("subscription should resolve");
                assert_eq!(block_by_digest.commitment(), commitment);
                assert_eq!(block_by_digest.height(), coded_block.height());
            },
        );
    }

    #[test_traced]
    fn test_proposer_preproposal_subscriptions_resolve_after_local_cache() {
        let fixture = Fixture {
            num_primary_peers: 10,
            ..Default::default()
        };

        fixture.start(|config, context, _, peers, _, coding_config| async move {
            let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
            let coded_block = CodedBlock::<B, C, H>::new(inner, coding_config, &STRATEGY);
            let commitment = coded_block.commitment();
            let digest = coded_block.digest();
            let round = Round::new(Epoch::zero(), View::new(1));

            // Subscribe on the proposer before it caches the locally proposed block.
            let shard_sub = peers[0].mailbox.subscribe_assigned_shard_verified(commitment);
            let commitment_sub = peers[0].mailbox.subscribe(commitment);
            let digest_sub = peers[0].mailbox.subscribe_by_digest(digest);

            peers[0].mailbox.proposed(round, coded_block.clone());
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
            |config, context, oracle, mut peers, _, coding_config| async move {
                // peers[0] = byzantine
                // peers[1] = honest proposer
                // peers[2] = receiver

                let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block = CodedBlock::<B, C, H>::new(inner, coding_config, &STRATEGY);
                let commitment = coded_block.commitment();
                let receiver_index = peers[2].index.get() as u16;

                let valid_shard = coded_block.shard(receiver_index).expect("missing shard");

                // Corrupt the shard's index to one that doesn't match
                // peers[0]'s participant index, triggering a block.
                let mut invalid_shard = valid_shard.clone();
                invalid_shard.index = peers[3].index.get() as u16;

                // Receiver subscribes to their shard and learns the leader.
                let receiver_pk = peers[2].public_key.clone();
                let leader = peers[1].public_key.clone();
                peers[2].mailbox.discovered(
                    commitment,
                    leader,
                    Round::new(Epoch::zero(), View::new(1)),
                );
                let mut shard_sub = peers[2]
                    .mailbox
                    .subscribe_assigned_shard_verified(commitment);

                // Byzantine peer sends the invalid shard.
                let invalid_bytes = invalid_shard.encode();
                peers[0]
                    .sender
                    .send(Recipients::One(receiver_pk.clone()), invalid_bytes, true);

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
                    .send(Recipients::One(receiver_pk), valid_bytes, true);
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

    /// Local re-proposals raise the rounds of cached blocks, and the window evicts the blocks
    /// last observed in the lowest rounds.
    #[test_traced]
    fn test_window_evicts_lowest_cached_rounds() {
        let fixture = Fixture::<C> {
            records: NZUsize!(4),
            ..Default::default()
        };
        fixture.start(|_, _, _, peers, _, coding_config| async move {
            let make_block = |id| {
                CodedBlock::<B, C, H>::new(
                    B::new(Sha256Digest::EMPTY, Height::new(id), id),
                    coding_config,
                    &STRATEGY,
                )
            };
            let round = |view| Round::new(Epoch::zero(), View::new(view));
            let reproposed = make_block(1);
            let low = make_block(2);
            let middle = make_block(3);
            let refreshed = make_block(4);
            let later = [make_block(5), make_block(6)];
            let reproposed_commitment = reproposed.commitment();
            let low_commitment = low.commitment();
            let middle_commitment = middle.commitment();
            let refreshed_commitment = refreshed.commitment();

            // Cache four blocks via `proposed`. Re-proposals raise the first and fourth
            // blocks above the other two, independently of their original context rounds.
            let peer = &peers[0];
            peer.mailbox.proposed(round(1), reproposed.clone());
            peer.mailbox.proposed(round(2), low);
            peer.mailbox.proposed(round(3), middle);
            peer.mailbox.proposed(round(1), refreshed.clone());
            peer.mailbox.proposed(round(5), reproposed);
            peer.mailbox.proposed(round(4), refreshed);
            for commitment in [
                reproposed_commitment,
                low_commitment,
                middle_commitment,
                refreshed_commitment,
            ] {
                assert!(
                    peer.mailbox.get(commitment).await.is_some(),
                    "a full window retains every block"
                );
            }

            // Two blocks proposed in later rounds evict the two lowest-round blocks.
            for (block, view) in later.iter().zip([6, 7]) {
                peer.mailbox.proposed(round(view), block.clone());
            }
            assert!(
                peer.mailbox.get(low_commitment).await.is_none(),
                "the lowest-round block should be evicted"
            );
            assert!(
                peer.mailbox.get(middle_commitment).await.is_none(),
                "the next lowest-round block should be evicted"
            );
            assert!(
                peer.mailbox.get(reproposed_commitment).await.is_some(),
                "a re-proposed block should remain cached"
            );
            assert!(
                peer.mailbox.get(refreshed_commitment).await.is_some(),
                "a re-proposed block should remain cached"
            );
            for block in &later {
                assert!(peer.mailbox.get(block.commitment()).await.is_some());
            }
        });
    }

    /// Evicting a record closes none of its subscriptions, and a record recreated after
    /// eviction resolves them.
    #[test_traced]
    fn test_eviction_keeps_subscriptions_open() {
        let fixture = Fixture::<C> {
            records: NZUsize!(2),
            ..Default::default()
        };
        fixture.start(|_, _, oracle, mut peers, _, coding_config| async move {
            let make_block = |id| {
                CodedBlock::<B, C, H>::new(
                    B::new(Sha256Digest::EMPTY, Height::new(id), id),
                    coding_config,
                    &STRATEGY,
                )
            };
            let round = |view| Round::new(Epoch::zero(), View::new(view));
            let leader = peers[0].public_key.clone();
            let receiver_pk = peers[2].public_key.clone();
            let block = make_block(1);
            let commitment = block.commitment();
            let cached = make_block(2);
            let cached_commitment = cached.commitment();

            // The receiver tracks the commitment at view 1 and caches its own proposal at
            // view 2.
            peers[2]
                .mailbox
                .discovered(commitment, leader.clone(), round(1));
            let mut assigned = peers[2]
                .mailbox
                .subscribe_assigned_shard_verified(commitment);
            let mut subscription = peers[2].mailbox.subscribe(commitment);
            peers[2].mailbox.proposed(round(2), cached);
            assert!(peers[2].mailbox.get(cached_commitment).await.is_some());

            // Records at views 3 and 4 evict both, lowest round first. The commitment's
            // subscriptions stay open.
            for view in [3, 4] {
                peers[2].mailbox.discovered(
                    make_block(view).commitment(),
                    leader.clone(),
                    round(view),
                );
            }
            assert!(peers[2].mailbox.get(cached_commitment).await.is_none());
            assert!(matches!(assigned.try_recv(), Err(TryRecvError::Empty)));
            assert!(matches!(subscription.try_recv(), Err(TryRecvError::Empty)));

            // Rediscovery at view 5 recreates the record. The assigned shard and one gossip
            // shard reconstruct the block and resolve both subscriptions.
            peers[2].mailbox.discovered(commitment, leader, round(5));
            for (sender, index) in [(0, peers[2].index), (1, peers[1].index)] {
                let shard = block.shard(index.get() as u16).expect("missing shard");
                peers[sender].sender.send(
                    Recipients::One(receiver_pk.clone()),
                    shard.encode(),
                    true,
                );
            }
            assigned.await.expect("assigned shard should be verified");
            let reconstructed = subscription.await.expect("block should be reconstructed");
            assert_eq!(reconstructed.commitment(), commitment);
            assert!(oracle.blocked().await.unwrap().is_empty());
        });
    }

    /// Subquorum reconstruction state survives records for `records - 1` later views and is
    /// evicted by the next. Its block subscription stays open, and its last shard then enters
    /// the sender's buffer without rebuilding the block.
    #[test_traced]
    fn test_subquorum_reconstruction_evicted_by_window() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (network, oracle) = simulated::Network::<deterministic::Context, P>::new(
                context.child("network"),
                simulated::Config {
                    max_size: MAX_SHARD_SIZE as u32,
                    max_peers_per_set: NZUsize!(10),
                    disconnect_on_block: true,
                    tracked_peer_sets: NZUsize!(1),
                },
            );
            network.start();

            let mut private_keys: Vec<PrivateKey> = (0..10).map(PrivateKey::from_seed).collect();
            private_keys.sort_by_key(|key| key.public_key());
            let peer_keys: Vec<P> = private_keys.iter().map(|key| key.public_key()).collect();
            let records = NZUsize!(4);
            let (mut engine, mut sender) =
                unstarted(&context, &oracle, &private_keys, 3, records).await;
            let coding_config = coding_config_for_participants(peer_keys.len() as u16);
            let make_block = |id| {
                CodedBlock::<B, C, H>::new(
                    B::new(Sha256Digest::EMPTY, Height::new(id), id),
                    coding_config,
                    &STRATEGY,
                )
            };
            let round = |view| Round::new(Epoch::zero(), View::new(view));
            let leader = peer_keys[0].clone();

            // The candidate at view 10 receives three of the four shards needed.
            let block = make_block(1);
            let commitment = block.commitment();
            engine.handle_external_proposal(&mut sender, commitment, leader.clone(), round(10));
            let (response, mut subscription) = oneshot::channel();
            engine
                .handle_block_subscription(BlockSubscriptionKey::Commitment(commitment), response);
            for index in [1, 2, 4] {
                let shard = block.shard(index).expect("missing shard");
                engine.handle_network_shard(
                    &mut sender,
                    peer_keys[usize::from(index)].clone(),
                    shard,
                );
            }

            // Records for three later views fill the window, and the candidate survives.
            for view in 11..=13 {
                engine.handle_external_proposal(
                    &mut sender,
                    make_block(view).commitment(),
                    leader.clone(),
                    round(view),
                );
                engine.trim();
                assert!(engine.records.contains_key(&commitment), "view {view}");
            }

            // The record for the next view evicts the candidate. Its block subscription stays
            // open.
            engine.handle_external_proposal(
                &mut sender,
                make_block(14).commitment(),
                leader,
                round(14),
            );
            engine.trim();
            assert!(!engine.records.contains_key(&commitment));
            assert_eq!(engine.records.len(), records.get());
            assert!(matches!(subscription.try_recv(), Err(TryRecvError::Empty)));

            // The last shard enters its sender's buffer and rebuilds nothing.
            let sender_key = peer_keys[5].clone();
            let shard = block.shard(5).expect("missing shard");
            engine.handle_network_shard(&mut sender, sender_key.clone(), shard);
            assert_eq!(buffered(&engine, &sender_key, commitment), 1);
            assert!(!engine.records.contains_key(&commitment));
            assert!(engine.jobs.is_empty());
            assert!(matches!(subscription.try_recv(), Err(TryRecvError::Empty)));
            assert!(oracle.blocked().await.unwrap().is_empty());
        });
    }

    /// Once the window is full, a notarization or discovery at or below its lowest round creates
    /// no record and leaves the commitment's shards in their sender's buffer, and a block from
    /// such a round still resolves its subscribers. A notarization above the lowest round creates
    /// the record and drains the buffer.
    #[test_traced]
    fn test_full_window_declines_rounds_at_or_below_lowest() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (network, oracle) = simulated::Network::<deterministic::Context, P>::new(
                context.child("network"),
                simulated::Config {
                    max_size: MAX_SHARD_SIZE as u32,
                    max_peers_per_set: NZUsize!(4),
                    disconnect_on_block: true,
                    tracked_peer_sets: NZUsize!(1),
                },
            );
            network.start();

            let mut private_keys: Vec<PrivateKey> = (0..4).map(PrivateKey::from_seed).collect();
            private_keys.sort_by_key(|key| key.public_key());
            let peer_keys: Vec<P> = private_keys.iter().map(|key| key.public_key()).collect();
            let records = NZUsize!(2);
            let (mut engine, mut sender) =
                unstarted(&context, &oracle, &private_keys, 0, records).await;
            let coding_config = coding_config_for_participants(peer_keys.len() as u16);
            let make_block = |id| {
                CodedBlock::<B, C, H>::new(
                    B::new(Sha256Digest::EMPTY, Height::new(id), id),
                    coding_config,
                    &STRATEGY,
                )
            };
            let round = |view| Round::new(Epoch::zero(), View::new(view));

            // Notarizations at views 5 and 6 fill the window.
            for view in [5, 6] {
                engine.handle_notarized_commitment(
                    &mut sender,
                    make_block(view).commitment(),
                    round(view),
                );
                engine.trim();
            }
            assert_eq!(engine.records.len(), records.get());

            // A sender-indexed shard for a commitment without a record enters its sender's
            // buffer.
            let block = make_block(1);
            let commitment = block.commitment();
            let gossiper = peer_keys[1].clone();
            let shard = block.shard(1).expect("missing shard");
            engine.handle_network_shard(&mut sender, gossiper.clone(), shard);
            assert_eq!(buffered(&engine, &gossiper, commitment), 1);

            // Notarizations at and below the lowest retained view create no record, and the
            // shard stays buffered.
            for view in [5, 4] {
                engine.handle_notarized_commitment(&mut sender, commitment, round(view));
                engine.trim();
                assert!(!engine.records.contains_key(&commitment), "view {view}");
                assert_eq!(buffered(&engine, &gossiper, commitment), 1, "view {view}");
            }

            // A discovery at the lowest retained view creates no record either, so its known
            // leader drains no buffered shard.
            engine.handle_external_proposal(
                &mut sender,
                commitment,
                peer_keys[2].clone(),
                round(5),
            );
            engine.trim();
            assert!(!engine.records.contains_key(&commitment));
            assert_eq!(buffered(&engine, &gossiper, commitment), 1);

            // A block from the lowest retained view resolves its subscriber without a record. Its
            // commitment sorts above the commitment retained at that view, which the window
            // would evict first if the block were retained.
            let lowest = make_block(5).commitment();
            let declined = (100..)
                .map(make_block)
                .find(|block| block.commitment() > lowest)
                .expect("a commitment should sort above the lowest retained record");
            let declined_commitment = declined.commitment();
            let (response, mut subscription) = oneshot::channel();
            engine.handle_block_subscription(
                BlockSubscriptionKey::Commitment(declined_commitment),
                response,
            );
            engine
                .cache_block(round(5), Arc::new(declined))
                .expect("a block without a record has no epoch conflict");
            engine.trim();
            let delivered = subscription
                .try_recv()
                .expect("declined block should resolve its subscriber");
            assert_eq!(delivered.commitment(), declined_commitment);
            assert!(!engine.records.contains_key(&declined_commitment));
            assert!(engine.records.contains_key(&lowest));
            assert_eq!(engine.records.len(), records.get());

            // A notarization above the lowest retained view creates the record and drains the
            // buffered shard. The window then evicts view 5.
            engine.handle_notarized_commitment(&mut sender, commitment, round(7));
            engine.trim();
            assert!(engine.records.contains_key(&commitment));
            assert_eq!(buffered(&engine, &gossiper, commitment), 0);
            assert_eq!(engine.records.len(), records.get());
            assert!(
                engine
                    .records
                    .values()
                    .all(|record| record.round() > round(5))
            );
        });
    }

    /// A local proposal from a round the full window declines still delivers each participant
    /// its shard and resolves the proposer's subscriptions without retaining the block.
    #[test_traced]
    fn test_declined_proposal_still_broadcasts() {
        let fixture = Fixture::<C> {
            records: NZUsize!(2),
            ..Default::default()
        };
        fixture.start(|_, _, oracle, peers, _, coding_config| async move {
            let make_block = |id| {
                CodedBlock::<B, C, H>::new(
                    B::new(Sha256Digest::EMPTY, Height::new(id), id),
                    coding_config,
                    &STRATEGY,
                )
            };
            let round = |view| Round::new(Epoch::zero(), View::new(view));
            let proposer = &peers[0];
            let receiver = &peers[1];

            // The proposer fills its window with proposals at views 5 and 6.
            for view in [5, 6] {
                proposer.mailbox.proposed(round(view), make_block(view));
            }

            // The receiver discovers a proposal at view 4, and both peers subscribe to it.
            let block = make_block(4);
            let commitment = block.commitment();
            receiver
                .mailbox
                .discovered(commitment, proposer.public_key.clone(), round(4));
            let verified = receiver
                .mailbox
                .subscribe_assigned_shard_verified(commitment);
            let ready = proposer
                .mailbox
                .subscribe_assigned_shard_verified(commitment);
            let subscription = proposer.mailbox.subscribe(commitment);

            // The proposer broadcasts the declined proposal and resolves its subscriptions, but
            // retains only the blocks at views 5 and 6.
            proposer.mailbox.proposed(round(4), block);
            verified.await.expect("receiver should verify its shard");
            ready.await.expect("proposer should be ready");
            let delivered = subscription
                .await
                .expect("proposer should receive its block");
            assert_eq!(delivered.commitment(), commitment);
            assert!(proposer.mailbox.get(commitment).await.is_none());
            for view in [5, 6] {
                let retained = make_block(view).commitment();
                assert!(proposer.mailbox.get(retained).await.is_some());
            }
            assert!(oracle.blocked().await.unwrap().is_empty());
        });
    }

    /// Each engine holds at most `records` cached blocks and reconstruction states while blocks
    /// are proposed and reconstructed for more than three windows of views.
    #[test_traced]
    fn test_records_bounded_over_many_views() {
        let fixture = Fixture::<C> {
            records: NZUsize!(4),
            ..Default::default()
        };
        fixture.start(
            |config, context, oracle, peers, _, coding_config| async move {
                let records = config.records.get();
                let leader = peers[0].public_key.clone();
                let mut commitments = Vec::new();
                for view in 1..=3 * records as u64 + 1 {
                    // The leader proposes, and every other participant reconstructs the block.
                    let block = CodedBlock::<B, C, H>::new(
                        B::new(Sha256Digest::EMPTY, Height::new(view), view),
                        coding_config,
                        &STRATEGY,
                    );
                    let commitment = block.commitment();
                    let round = Round::new(Epoch::zero(), View::new(view));
                    peers[0].mailbox.proposed(round, block);
                    let mut subscriptions = Vec::new();
                    for peer in &peers[1..] {
                        peer.mailbox.discovered(commitment, leader.clone(), round);
                        subscriptions.push(peer.mailbox.subscribe(commitment));
                    }
                    for subscription in subscriptions {
                        subscription.await.expect("block should be reconstructed");
                    }
                    commitments.push(commitment);

                    // No engine caches more blocks or holds more reconstruction states than the
                    // window holds.
                    let metrics = context.encode();
                    for name in [
                        "reconstructed_blocks_cache_count",
                        "reconstruction_states_count",
                    ] {
                        let counts = gauges(&metrics, name);
                        assert_eq!(counts.len(), peers.len());
                        assert!(
                            counts.iter().all(|count| *count <= records as i64),
                            "view {view}: {name} {counts:?}"
                        );
                    }
                }

                // Each engine retains exactly the blocks of the last `records` views.
                let (evicted, retained) = commitments.split_at(commitments.len() - records);
                for peer in &peers {
                    for commitment in evicted {
                        assert!(peer.mailbox.get(*commitment).await.is_none());
                    }
                    for commitment in retained {
                        assert!(peer.mailbox.get(*commitment).await.is_some());
                    }
                }
                assert!(oracle.blocked().await.unwrap().is_empty());
            },
        );
    }

    /// Records from a later epoch evict records from an earlier epoch, whatever their views.
    #[test_traced]
    fn test_later_epoch_evicts_earlier_epoch_records() {
        let fixture = Fixture::<C> {
            additional_scheme_epochs: vec![Epoch::new(1)],
            records: NZUsize!(2),
            ..Default::default()
        };
        fixture.start(|_, _, _, peers, _, coding_config| async move {
            let make_block = |id| {
                CodedBlock::<B, C, H>::new(
                    B::new(Sha256Digest::EMPTY, Height::new(id), id),
                    coding_config,
                    &STRATEGY,
                )
            };
            let receiver = &peers[2];

            // The receiver caches its own proposals at high views of epoch 0.
            let earlier = [make_block(1), make_block(2)];
            for (block, view) in earlier.iter().zip([100, 101]) {
                receiver
                    .mailbox
                    .proposed(Round::new(Epoch::zero(), View::new(view)), block.clone());
            }
            for block in &earlier {
                assert!(receiver.mailbox.get(block.commitment()).await.is_some());
            }

            // Proposals at the first views of epoch 1 evict both.
            let later = [make_block(3), make_block(4)];
            for (block, view) in later.iter().zip([1, 2]) {
                receiver
                    .mailbox
                    .proposed(Round::new(Epoch::new(1), View::new(view)), block.clone());
            }
            for block in &earlier {
                assert!(receiver.mailbox.get(block.commitment()).await.is_none());
            }
            for block in &later {
                assert!(receiver.mailbox.get(block.commitment()).await.is_some());
            }
        });
    }

    /// Two commitments observed in one view evict only records from lower views. Later
    /// commitments at or below that view create no record, and records tied at the lowest view
    /// are evicted in commitment order.
    #[test_traced]
    fn test_same_view_records_never_evict_later_views() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (network, oracle) = simulated::Network::<deterministic::Context, P>::new(
                context.child("network"),
                simulated::Config {
                    max_size: MAX_SHARD_SIZE as u32,
                    max_peers_per_set: NZUsize!(4),
                    disconnect_on_block: true,
                    tracked_peer_sets: NZUsize!(1),
                },
            );
            network.start();

            let mut private_keys: Vec<PrivateKey> = (0..4).map(PrivateKey::from_seed).collect();
            private_keys.sort_by_key(|key| key.public_key());
            let peer_keys: Vec<P> = private_keys.iter().map(|key| key.public_key()).collect();
            let (mut engine, mut sender) =
                unstarted(&context, &oracle, &private_keys, 2, NZUsize!(4)).await;
            let coding_config = coding_config_for_participants(peer_keys.len() as u16);
            let make_block = |id| {
                CodedBlock::<B, C, H>::new(
                    B::new(Sha256Digest::EMPTY, Height::new(id), id),
                    coding_config,
                    &STRATEGY,
                )
            };
            let round = |view| Round::new(Epoch::zero(), View::new(view));
            let leader = peer_keys[0].clone();

            // The engine caches its own proposals at views 1, 2, 10, and 11.
            let [first, second, tenth, eleventh] = [1, 2, 10, 11].map(|view| {
                let block = make_block(view);
                let commitment = block.commitment();
                engine.broadcast_shards(&mut sender, round(view), Arc::new(block));
                engine.trim();
                commitment
            });
            assert_eq!(engine.records.len(), 4);

            // The leader equivocates at view 5: the engine verifies one commitment and certifies
            // the notarization of another. Both evict the records at views 1 and 2.
            let tied = [make_block(20).commitment(), make_block(21).commitment()];
            engine.handle_external_proposal(&mut sender, tied[0], leader.clone(), round(5));
            engine.trim();
            engine.handle_notarized_commitment(&mut sender, tied[1], round(5));
            engine.trim();
            assert!(!engine.records.contains_key(&first));
            assert!(!engine.records.contains_key(&second));
            for commitment in [tenth, eleventh, tied[0], tied[1]] {
                assert!(engine.records.contains_key(&commitment));
            }

            // Further commitments at and below view 5 create no record.
            let notarized = make_block(22).commitment();
            engine.handle_notarized_commitment(&mut sender, notarized, round(5));
            assert!(!engine.records.contains_key(&notarized));
            let discovered = make_block(23).commitment();
            engine.handle_external_proposal(&mut sender, discovered, leader, round(4));
            assert!(!engine.records.contains_key(&discovered));
            assert_eq!(engine.records.len(), 4);

            // A record above view 5 evicts the lower commitment of the tied pair.
            let (lower, higher) = (tied[0].min(tied[1]), tied[0].max(tied[1]));
            engine.handle_notarized_commitment(&mut sender, make_block(24).commitment(), round(12));
            engine.trim();
            assert!(!engine.records.contains_key(&lower));
            for commitment in [higher, tenth, eleventh] {
                assert!(engine.records.contains_key(&commitment));
            }
            assert!(oracle.blocked().await.unwrap().is_empty());
        });
    }

    /// Caching a reconstructed block drops its record's shards. A conflicting shard is then
    /// ignored without blocking its sender, and a late assigned shard is still verified and
    /// gossiped.
    #[test_traced]
    fn test_cached_record_retains_no_shards() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (network, oracle) = simulated::Network::<deterministic::Context, P>::new(
                context.child("network"),
                simulated::Config {
                    max_size: MAX_SHARD_SIZE as u32,
                    max_peers_per_set: NZUsize!(4),
                    disconnect_on_block: true,
                    tracked_peer_sets: NZUsize!(1),
                },
            );
            network.start();

            let mut private_keys: Vec<PrivateKey> = (0..4).map(PrivateKey::from_seed).collect();
            private_keys.sort_by_key(|key| key.public_key());
            let peer_keys: Vec<P> = private_keys.iter().map(|key| key.public_key()).collect();
            let participants: Set<P> = Set::from_iter_dedup(peer_keys.clone());
            let (mut engine, mut sender) =
                unstarted(&context, &oracle, &private_keys, 0, NZUsize!(16)).await;

            // Peer 1 observes the engine's gossip.
            let (_, mut observer) = oracle
                .control(peer_keys[1].clone())
                .register(0, TEST_QUOTA)
                .await
                .expect("registration should succeed");
            oracle
                .add_link(peer_keys[0].clone(), peer_keys[1].clone(), DEFAULT_LINK)
                .await
                .expect("link should be added");
            oracle.manager().track(0, participants.clone());
            context.sleep(Duration::from_millis(10)).await;

            let coding_config = coding_config_for_participants(participants.len() as u16);
            let block = CodedBlock::<B, C, H>::new(
                B::new(Sha256Digest::EMPTY, Height::new(1), 100),
                coding_config,
                &STRATEGY,
            );
            let commitment = block.commitment();
            let leader = peer_keys[1].clone();

            // Gossip shards from peers 2 and 3 reconstruct the block before the assigned shard
            // arrives.
            engine.handle_external_proposal(
                &mut sender,
                commitment,
                leader.clone(),
                Round::new(Epoch::zero(), View::new(1)),
            );
            for index in [2, 3] {
                let shard = block.shard(index).expect("missing shard");
                engine.handle_network_shard(
                    &mut sender,
                    peer_keys[usize::from(index)].clone(),
                    shard,
                );
            }
            let reconstructed = engine
                .jobs
                .next_completed()
                .await
                .expect("reconstruction job should complete");
            engine.complete(reconstructed);
            let record = engine.records.get(&commitment).expect("record must exist");
            assert!(record.block().is_some());
            assert!(matches!(
                record.reconstruction(),
                Some(ReconstructionState::Ready(_))
            ));

            // A shard that conflicts with peer 2's contribution is ignored without blocking.
            let other = CodedBlock::<B, C, H>::new(
                B::new(Sha256Digest::EMPTY, Height::new(1), 200),
                coding_config,
                &STRATEGY,
            );
            let mut conflicting = other.shard(2).expect("missing shard");
            conflicting.commitment = commitment;
            engine.handle_network_shard(&mut sender, peer_keys[2].clone(), conflicting);
            assert!(oracle.blocked().await.unwrap().is_empty());

            // The leader's late assigned shard is verified, resolves readiness, and is gossiped.
            let (response, mut verified) = oneshot::channel();
            engine.handle_assigned_shard_verified_subscription(commitment, response);
            assert!(matches!(verified.try_recv(), Err(TryRecvError::Empty)));
            let assigned = block.shard(0).expect("missing shard");
            engine.handle_network_shard(&mut sender, leader, assigned.clone());
            assert!(matches!(verified.try_recv(), Ok(())));
            let (from, gossip) = observer.recv().await.expect("gossip should arrive");
            assert_eq!(from, peer_keys[0]);
            assert_eq!(gossip.as_ref(), assigned.encode().as_ref());
            assert!(oracle.blocked().await.unwrap().is_empty());
        });
    }

    /// A notarized record reconstructs its block from gossip while the leader's delivery of the
    /// assigned shard waits in the leader's buffer. Discovery then verifies and gossips that
    /// shard.
    #[test_traced]
    fn test_cached_leaderless_record_keeps_buffered_assigned_shard() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (network, oracle) = simulated::Network::<deterministic::Context, P>::new(
                context.child("network"),
                simulated::Config {
                    max_size: MAX_SHARD_SIZE as u32,
                    max_peers_per_set: NZUsize!(4),
                    disconnect_on_block: true,
                    tracked_peer_sets: NZUsize!(1),
                },
            );
            network.start();

            let mut private_keys: Vec<PrivateKey> = (0..4).map(PrivateKey::from_seed).collect();
            private_keys.sort_by_key(|key| key.public_key());
            let peer_keys: Vec<P> = private_keys.iter().map(|key| key.public_key()).collect();
            let participants: Set<P> = Set::from_iter_dedup(peer_keys.clone());
            let (mut engine, mut sender) =
                unstarted(&context, &oracle, &private_keys, 0, NZUsize!(16)).await;

            // Peer 1 observes the engine's gossip.
            let (_, mut observer) = oracle
                .control(peer_keys[1].clone())
                .register(0, TEST_QUOTA)
                .await
                .expect("registration should succeed");
            oracle
                .add_link(peer_keys[0].clone(), peer_keys[1].clone(), DEFAULT_LINK)
                .await
                .expect("link should be added");
            oracle.manager().track(0, participants.clone());
            context.sleep(Duration::from_millis(10)).await;

            let coding_config = coding_config_for_participants(participants.len() as u16);
            let block = CodedBlock::<B, C, H>::new(
                B::new(Sha256Digest::EMPTY, Height::new(1), 100),
                coding_config,
                &STRATEGY,
            );
            let commitment = block.commitment();
            let round = Round::new(Epoch::zero(), View::new(1));
            let leader = peer_keys[1].clone();

            // A notarization creates a leaderless record. The leader's delivery of the assigned
            // shard cannot be classified and enters the leader's buffer.
            engine.handle_notarized_commitment(&mut sender, commitment, round);
            let (response, mut verified) = oneshot::channel();
            engine.handle_assigned_shard_verified_subscription(commitment, response);
            let assigned = block.shard(0).expect("missing shard");
            engine.handle_network_shard(&mut sender, leader.clone(), assigned.clone());
            assert_eq!(buffered(&engine, &leader, commitment), 1);

            // Gossip shards from peers 2 and 3 reconstruct the block. The assigned shard stays
            // buffered and readiness stays pending.
            for index in [2, 3] {
                let shard = block.shard(index).expect("missing shard");
                engine.handle_network_shard(
                    &mut sender,
                    peer_keys[usize::from(index)].clone(),
                    shard,
                );
            }
            let reconstructed = engine
                .jobs
                .next_completed()
                .await
                .expect("reconstruction job should complete");
            engine.complete(reconstructed);
            let record = engine.records.get(&commitment).expect("record must exist");
            assert!(record.block().is_some());
            assert_eq!(buffered(&engine, &leader, commitment), 1);
            assert!(matches!(verified.try_recv(), Err(TryRecvError::Empty)));

            // Discovery drains the buffered assigned shard, which is verified, resolves readiness,
            // and is gossiped.
            engine.handle_external_proposal(&mut sender, commitment, leader.clone(), round);
            assert_eq!(buffered(&engine, &leader, commitment), 0);
            assert!(matches!(verified.try_recv(), Ok(())));
            let (from, gossip) = observer.recv().await.expect("gossip should arrive");
            assert_eq!(from, peer_keys[0]);
            assert_eq!(gossip.as_ref(), assigned.encode().as_ref());
            assert!(oracle.blocked().await.unwrap().is_empty());
        });
    }

    /// A failed reconstruction removes the record and closes the commitment's assigned-shard and
    /// block subscriptions.
    #[test_traced]
    fn test_failed_reconstruction_closes_subscriptions() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (network, oracle) = simulated::Network::<deterministic::Context, P>::new(
                context.child("network"),
                simulated::Config {
                    max_size: MAX_SHARD_SIZE as u32,
                    max_peers_per_set: NZUsize!(4),
                    disconnect_on_block: true,
                    tracked_peer_sets: NZUsize!(1),
                },
            );
            network.start();

            let mut private_keys: Vec<PrivateKey> = (0..4).map(PrivateKey::from_seed).collect();
            private_keys.sort_by_key(|key| key.public_key());
            let peer_keys: Vec<P> = private_keys.iter().map(|key| key.public_key()).collect();
            let (mut engine, mut sender) =
                unstarted(&context, &oracle, &private_keys, 0, NZUsize!(16)).await;
            let coding_config = coding_config_for_participants(peer_keys.len() as u16);

            // The commitment claims the digest of one block and the coding root of another.
            let claimed = CodedBlock::<B, C, H>::new(
                B::new(Sha256Digest::EMPTY, Height::new(1), 100),
                coding_config,
                &STRATEGY,
            );
            let actual = CodedBlock::<B, C, H>::new(
                B::new(Sha256Digest::EMPTY, Height::new(2), 200),
                coding_config,
                &STRATEGY,
            );
            let commitment = Commitment::from((
                claimed.digest(),
                actual.commitment().root(),
                actual.commitment().context(),
                coding_config,
            ));

            // The engine tracks the commitment and subscribes before any shard arrives.
            engine.handle_external_proposal(
                &mut sender,
                commitment,
                peer_keys[1].clone(),
                Round::new(Epoch::zero(), View::new(1)),
            );
            let (response, mut assigned) = oneshot::channel();
            engine.handle_assigned_shard_verified_subscription(commitment, response);
            let (response, mut subscription) = oneshot::channel();
            engine
                .handle_block_subscription(BlockSubscriptionKey::Commitment(commitment), response);

            // Gossip shards from peers 2 and 3 decode to a block that does not match the
            // commitment's digest.
            for index in [2, 3] {
                let mut shard = actual.shard(index).expect("missing shard");
                shard.commitment = commitment;
                engine.handle_network_shard(
                    &mut sender,
                    peer_keys[usize::from(index)].clone(),
                    shard,
                );
            }
            assert!(matches!(assigned.try_recv(), Err(TryRecvError::Empty)));
            let reconstructed = engine
                .jobs
                .next_completed()
                .await
                .expect("reconstruction job should complete");
            engine.complete(reconstructed);

            // The failure removes the record and closes both subscriptions without blocking
            // anyone.
            assert!(!engine.records.contains_key(&commitment));
            assert!(matches!(assigned.try_recv(), Err(TryRecvError::Closed)));
            assert!(matches!(subscription.try_recv(), Err(TryRecvError::Closed)));
            assert!(oracle.blocked().await.unwrap().is_empty());
        });
    }

    /// A local proposal of a tracked commitment resolves its assigned-shard subscriptions, and
    /// its record keeps the highest observed round when the window evicts.
    #[test_traced]
    fn test_local_reproposal_refreshes_existing_reconstruction_state() {
        let fixture = Fixture::<C> {
            records: NZUsize!(3),
            ..Default::default()
        };
        fixture.start(|_, _, _, mut peers, _, coding_config| async move {
            let make_block = |id| {
                CodedBlock::<B, C, H>::new(
                    B::new(Sha256Digest::EMPTY, Height::new(id), id * 100),
                    coding_config,
                    &STRATEGY,
                )
            };
            let live = make_block(1);
            let state_first = make_block(3);
            let lower = make_block(4);
            let later = make_block(5);
            let live_commitment = live.commitment();
            let state_first_commitment = state_first.commitment();
            let lower_commitment = lower.commitment();
            let leader = peers[0].public_key.clone();
            let round = |view| Round::new(Epoch::zero(), View::new(view));
            let reproposal_round = round(8);
            let peer = &mut peers[0];

            // The peer discovers a commitment at view 1 and re-proposes it at view 8. It also
            // notarizes another commitment at view 8 and then proposes it at view 5.
            peer.mailbox.discovered(live_commitment, leader, round(1));
            peer.mailbox.proposed(reproposal_round, live);
            peer.mailbox
                .notarized(state_first_commitment, reproposal_round);
            peer.mailbox.proposed(round(5), state_first);
            assert!(peer.mailbox.get(live_commitment).await.is_some());

            // A later assigned-shard subscription resolves from the local re-proposal.
            let mut shard_sub = peer
                .mailbox
                .subscribe_assigned_shard_verified(live_commitment);
            assert!(peer.mailbox.get(live_commitment).await.is_some());
            assert!(
                matches!(shard_sub.try_recv(), Ok(())),
                "late subscription should resolve after a local reproposal"
            );

            // Caching blocks at views 6 and 9 exceeds the window by one record. Both earlier
            // records were last observed at view 8, so the window evicts the block at view 6.
            peer.mailbox.proposed(round(6), lower);
            peer.mailbox.proposed(round(9), later);
            assert!(peer.mailbox.get(lower_commitment).await.is_none());
            assert!(peer.mailbox.get(live_commitment).await.is_some());
            assert!(peer.mailbox.get(state_first_commitment).await.is_some());
            let mut retained_shard_sub = peer
                .mailbox
                .subscribe_assigned_shard_verified(live_commitment);
            assert!(peer.mailbox.get(live_commitment).await.is_some());
            assert!(
                matches!(retained_shard_sub.try_recv(), Ok(())),
                "retained local proposal should resolve a late subscription"
            );
        });
    }

    #[test_traced]
    fn test_duplicate_leader_shard_ignored() {
        let fixture = Fixture::<C>::default();
        fixture.start(
            |config, context, oracle, mut peers, _, coding_config| async move {
                let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block = CodedBlock::<B, C, H>::new(inner, coding_config, &STRATEGY);
                let commitment = coded_block.commitment();

                // Get peer 2's own-index shard (the one the leader sends them).
                let peer2_index = peers[2].index.get() as u16;
                let peer2_shard = coded_block.shard(peer2_index).expect("missing shard");
                let shard_bytes = peer2_shard.encode();

                let peer2_pk = peers[2].public_key.clone();
                let leader = peers[0].public_key.clone();

                // Inform peer 2 that peer 0 is the leader.
                peers[2].mailbox.discovered(
                    commitment,
                    leader,
                    Round::new(Epoch::zero(), View::new(1)),
                );

                // Send peer 2 their shard from peer 0 (leader, first time - should succeed).
                peers[0]
                    .sender
                    .send(Recipients::One(peer2_pk.clone()), shard_bytes.clone(), true);
                context.sleep(config.link.latency * 2).await;

                // Send the same shard again from peer 0 (leader duplicate - ignored).
                peers[0]
                    .sender
                    .send(Recipients::One(peer2_pk), shard_bytes, true);
                context.sleep(config.link.latency * 2).await;

                // The leader should NOT be blocked for sending an identical duplicate.
                let blocked_peers = oracle.blocked().await.unwrap();
                let is_blocked = blocked_peers
                    .iter()
                    .any(|(a, b)| a == &peers[2].public_key && b == &peers[0].public_key);
                assert!(
                    !is_blocked,
                    "leader should not be blocked for duplicate shard"
                );
            },
        );
    }

    #[test_traced]
    fn test_equivocating_leader_shard_blocks_peer() {
        let fixture = Fixture::<C>::default();
        fixture.start(
            |config, context, oracle, mut peers, _, coding_config| async move {
                let inner1 = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block1 = CodedBlock::<B, C, H>::new(inner1, coding_config, &STRATEGY);
                let commitment = coded_block1.commitment();

                // Create a second block with different payload to get different shard data.
                let inner2 = B::new(Sha256Digest::EMPTY, Height::new(1), 200);
                let coded_block2 = CodedBlock::<B, C, H>::new(inner2, coding_config, &STRATEGY);

                // Get peer 2's shard from both blocks.
                let peer2_index = peers[2].index.get() as u16;
                let shard_bytes1 = coded_block1
                    .shard(peer2_index)
                    .expect("missing shard")
                    .encode();
                let mut equivocating_shard =
                    coded_block2.shard(peer2_index).expect("missing shard");
                // Override the commitment so it targets the same reconstruction state.
                equivocating_shard.commitment = commitment;
                let shard_bytes2 = equivocating_shard.encode();

                let peer2_pk = peers[2].public_key.clone();
                let leader = peers[0].public_key.clone();

                // Inform peer 2 that peer 0 is the leader.
                peers[2].mailbox.discovered(
                    commitment,
                    leader,
                    Round::new(Epoch::zero(), View::new(1)),
                );

                // Send peer 2 their shard from the leader (first time - succeeds).
                peers[0]
                    .sender
                    .send(Recipients::One(peer2_pk.clone()), shard_bytes1, true);
                context.sleep(config.link.latency * 2).await;

                // Send a different shard from the leader (equivocation - should block).
                peers[0]
                    .sender
                    .send(Recipients::One(peer2_pk), shard_bytes2, true);
                context.sleep(config.link.latency * 2).await;

                // Peer 2 should have blocked the leader for equivocation.
                assert_blocked(&oracle, &peers[2].public_key, &peers[0].public_key).await;
            },
        );
    }

    #[test_traced]
    fn test_non_leader_wrong_index_shard_blocked() {
        // Test that a non-leader sending a shard with the wrong index is blocked.
        // Non-leaders must send shards at their own participant index.
        let fixture = Fixture::<C>::default();
        fixture.start(
            |config, context, oracle, mut peers, _, coding_config| async move {
                let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block = CodedBlock::<B, C, H>::new(inner, coding_config, &STRATEGY);
                let commitment = coded_block.commitment();

                // Get a shard that belongs to neither the sender nor receiver.
                let unrelated_index = peers[3].index.get() as u16;
                let unrelated_shard = coded_block.shard(unrelated_index).expect("missing shard");
                let shard_bytes = unrelated_shard.encode();

                let peer2_pk = peers[2].public_key.clone();
                let leader = peers[0].public_key.clone();

                // Inform peer 2 that peer 0 is the leader.
                peers[2].mailbox.discovered(
                    commitment,
                    leader,
                    Round::new(Epoch::zero(), View::new(1)),
                );

                // Peer 1 (not the leader) sends peer 2 a shard for peer 3. It
                // cannot be either sender-indexed gossip or an assigned shard.
                peers[1]
                    .sender
                    .send(Recipients::One(peer2_pk), shard_bytes, true);
                context.sleep(config.link.latency * 2).await;

                // Peer 1 should be blocked by peer 2 for wrong shard index.
                assert_blocked(&oracle, &peers[2].public_key, &peers[1].public_key).await;
            },
        );
    }

    #[test_traced]
    fn test_buffered_wrong_index_shard_blocked_on_leader_arrival() {
        // Test that when a non-leader's shard with the wrong index is buffered
        // (leader unknown) and then the leader arrives, the sender is blocked.
        let fixture = Fixture::<C>::default();
        fixture.start(
            |config, context, oracle, mut peers, _, coding_config| async move {
                let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block = CodedBlock::<B, C, H>::new(inner, coding_config, &STRATEGY);
                let commitment = coded_block.commitment();

                // Get a shard that belongs to neither the sender nor receiver.
                let unrelated_index = peers[3].index.get() as u16;
                let unrelated_shard = coded_block.shard(unrelated_index).expect("missing shard");
                let shard_bytes = unrelated_shard.encode();

                let peer2_pk = peers[2].public_key.clone();

                // Peer 1 sends peer 3's shard before the leader is known.
                peers[1]
                    .sender
                    .send(Recipients::One(peer2_pk), shard_bytes, true);
                context.sleep(config.link.latency * 2).await;

                // Nobody should be blocked yet (shard is buffered, leader unknown).
                let blocked = oracle.blocked().await.unwrap();
                assert!(
                    blocked.is_empty(),
                    "no peers should be blocked while leader is unknown"
                );

                // Now inform peer 2 that peer 0 is the leader.
                // This drains the impossible candidate: it belongs to neither
                // peer 1 nor peer 2.
                let leader = peers[0].public_key.clone();
                peers[2].mailbox.discovered(
                    commitment,
                    leader,
                    Round::new(Epoch::zero(), View::new(1)),
                );
                context.sleep(Duration::from_millis(10)).await;

                assert_blocked(&oracle, &peers[2].public_key, &peers[1].public_key).await;
            },
        );
    }

    #[test_traced]
    fn test_assigned_shard_from_non_leader_accepted() {
        let fixture = Fixture::<C>::default();
        fixture.start(
            |_config, context, oracle, mut peers, _, coding_config| async move {
                let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block = CodedBlock::<B, C, H>::new(inner, coding_config, &STRATEGY);
                let commitment = coded_block.commitment();

                // Get peer 2's assigned shard.
                let peer2_index = peers[2].index.get() as u16;
                let peer2_shard = coded_block.shard(peer2_index).expect("missing shard");
                let shard_bytes = peer2_shard.encode();

                let peer2_pk = peers[2].public_key.clone();
                let leader = peers[0].public_key.clone();

                // Subscribe before shards arrive so we can verify acceptance.
                let shard_sub = peers[2]
                    .mailbox
                    .subscribe_assigned_shard_verified(commitment);

                // Discover the proposal under peer 0.
                peers[2].mailbox.discovered(
                    commitment,
                    leader,
                    Round::new(Epoch::zero(), View::new(1)),
                );

                // The assigned shard is commitment-bound, so another participant
                // may deliver it without being treated as a conflicting proposer.
                peers[1]
                    .sender
                    .send(Recipients::One(peer2_pk), shard_bytes, true);

                select! {
                    _ = shard_sub => {},
                    _ = context.sleep(Duration::from_secs(5)) => {
                        panic!("subscription did not complete after assigned shard");
                    },
                };

                assert!(oracle.blocked().await.unwrap().is_empty());
            },
        );
    }

    #[test_traced]
    fn test_non_participant_external_proposed_ignored() {
        let fixture = Fixture::<C>::default();
        fixture.start(
            |config, context, oracle, mut peers, _, coding_config| async move {
                let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block = CodedBlock::<B, C, H>::new(inner, coding_config, &STRATEGY);
                let commitment = coded_block.commitment();

                // Get the shard the leader would send to peer 2 (at peer 2's index).
                let peer2_index = peers[2].index.get() as u16;
                let peer2_shard = coded_block.shard(peer2_index).expect("missing shard");
                let shard_bytes = peer2_shard.encode();

                let peer2_pk = peers[2].public_key.clone();
                let leader = peers[0].public_key.clone();
                let non_participant_leader = PrivateKey::from_seed(10_000).public_key();

                // Subscribe before shards arrive.
                let shard_sub = peers[2]
                    .mailbox
                    .subscribe_assigned_shard_verified(commitment);

                // A non-participant leader update should be ignored.
                peers[2].mailbox.discovered(
                    commitment,
                    non_participant_leader,
                    Round::new(Epoch::zero(), View::new(1)),
                );

                // Leader unknown path: this shard should be buffered, not blocked.
                peers[0]
                    .sender
                    .send(Recipients::One(peer2_pk.clone()), shard_bytes.clone(), true);
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
                peers[2].mailbox.discovered(
                    commitment,
                    leader,
                    Round::new(Epoch::zero(), View::new(1)),
                );
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

    /// A rejected leader update does not raise a record's eviction round.
    #[test_traced]
    fn test_rejected_leader_does_not_refresh_eviction_round() {
        let fixture = Fixture::<C> {
            records: NZUsize!(2),
            ..Default::default()
        };
        fixture.start(|_, _, _, peers, _, coding_config| async move {
            let make_block = |id| {
                CodedBlock::<B, C, H>::new(
                    B::new(Sha256Digest::EMPTY, Height::new(id), id * 100),
                    coding_config,
                    &STRATEGY,
                )
            };
            let round = |view| Round::new(Epoch::zero(), View::new(view));
            let commitment = make_block(1).commitment();
            let leader = peers[0].public_key.clone();
            let non_participant = PrivateKey::from_seed(10_000).public_key();
            let receiver = &peers[2];

            // The receiver tracks the commitment at view 1 and rejects a leader update at view
            // 10 that names a non-participant.
            let mut subscription = receiver
                .mailbox
                .subscribe_assigned_shard_verified(commitment);
            receiver.mailbox.discovered(commitment, leader, round(1));
            receiver
                .mailbox
                .discovered(commitment, non_participant, round(10));

            // Blocks cached at views 2, 3, and 4 exceed the window by two records. The rejected
            // leader update left the commitment at view 1, so the window evicts it and then
            // the block at view 2.
            let [first, second, third] = [2, 3, 4].map(|view| {
                let block = make_block(view);
                receiver.mailbox.proposed(round(view), block.clone());
                block.commitment()
            });
            assert!(receiver.mailbox.get(first).await.is_none());
            assert!(receiver.mailbox.get(second).await.is_some());
            assert!(receiver.mailbox.get(third).await.is_some());
            assert!(matches!(subscription.try_recv(), Err(TryRecvError::Empty)));
        });
    }

    /// Observations from another epoch do not raise a record's eviction round.
    #[test_traced]
    fn test_cross_epoch_observations_do_not_refresh_eviction_round() {
        let fixture = Fixture::<C> {
            additional_scheme_epochs: vec![Epoch::new(1)],
            records: NZUsize!(2),
            ..Default::default()
        };
        fixture.start(|_, _, _, peers, _, coding_config| async move {
            let make_block = |id| {
                CodedBlock::<B, C, H>::new(
                    B::new(Sha256Digest::EMPTY, Height::new(id), id * 100),
                    coding_config,
                    &STRATEGY,
                )
            };
            let round = |view| Round::new(Epoch::zero(), View::new(view));
            let cached = make_block(1);
            let incomplete = make_block(2);
            let incomplete_commitment = incomplete.commitment();
            let cached_commitment = cached.commitment();
            let leader = peers[0].public_key.clone();
            let receiver = &peers[2];

            // The receiver caches its own proposal and tracks another commitment at view 1.
            receiver.mailbox.proposed(round(1), cached);
            receiver
                .mailbox
                .discovered(incomplete_commitment, leader, round(1));

            // A proposal and notarizations from epoch 1 conflict with both records and are
            // ignored.
            let conflicting_round = Round::new(Epoch::new(1), View::new(10));
            receiver.mailbox.proposed(conflicting_round, incomplete);
            receiver
                .mailbox
                .notarized(cached_commitment, conflicting_round);
            receiver
                .mailbox
                .notarized(incomplete_commitment, conflicting_round);

            // Blocks cached at views 2 and 3 exceed the window by two records. The ignored
            // observations left both records at view 1, so the window evicts them.
            let later = [make_block(3), make_block(4)];
            for (block, view) in later.iter().zip([2, 3]) {
                receiver.mailbox.proposed(round(view), block.clone());
            }
            assert!(receiver.mailbox.get(cached_commitment).await.is_none());
            for block in &later {
                assert!(receiver.mailbox.get(block.commitment()).await.is_some());
            }
        });
    }

    #[test_traced]
    fn test_shard_from_non_participant_blocks_peer() {
        let fixture = Fixture {
            num_future_peers: 1,
            ..Fixture::<C>::default()
        };
        fixture.start(
            |config, context, oracle, peers, _, coding_config| async move {
                let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block = CodedBlock::<B, C, H>::new(inner, coding_config, &STRATEGY);
                let commitment = coded_block.commitment();

                let leader = peers[0].public_key.clone();
                let receiver_pk = peers[2].public_key.clone();

                let non_participant_key = PrivateKey::from_seed(10_000);
                let non_participant_pk = non_participant_key.public_key();

                let non_participant_control = oracle.control(non_participant_pk.clone());
                let (mut non_participant_sender, _non_participant_receiver) =
                    non_participant_control
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
                oracle.manager().track(
                    2,
                    TrackedPeers::new(
                        Set::from_iter_dedup(peers.iter().map(|peer| peer.public_key.clone())),
                        Set::from_iter_dedup([non_participant_pk.clone()]),
                    ),
                );
                context.sleep(Duration::from_millis(10)).await;

                peers[2].mailbox.discovered(
                    commitment,
                    leader,
                    Round::new(Epoch::zero(), View::new(1)),
                );

                let peer2_index = peers[2].index.get() as u16;
                let shard = coded_block.shard(peer2_index).expect("missing shard");
                let shard_bytes = shard.encode();

                non_participant_sender.send(Recipients::One(receiver_pk), shard_bytes, true);
                context.sleep(config.link.latency * 2).await;

                assert_blocked(&oracle, &peers[2].public_key, &non_participant_pk).await;
            },
        );
    }

    #[test_traced]
    fn test_preleader_shard_from_non_participant_is_not_buffered() {
        let fixture = Fixture {
            num_future_peers: 1,
            ..Fixture::<C>::default()
        };
        fixture.start(
            |config, context, oracle, peers, _, coding_config| async move {
                let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block = CodedBlock::<B, C, H>::new(inner, coding_config, &STRATEGY);
                let commitment = coded_block.commitment();

                let leader = peers[0].public_key.clone();
                let receiver_pk = peers[2].public_key.clone();

                let non_participant_key = PrivateKey::from_seed(10_000);
                let non_participant_pk = non_participant_key.public_key();

                let non_participant_control = oracle.control(non_participant_pk.clone());
                let (mut non_participant_sender, _non_participant_receiver) =
                    non_participant_control
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
                oracle.manager().track(
                    2,
                    TrackedPeers::new(
                        Set::from_iter_dedup(peers.iter().map(|peer| peer.public_key.clone())),
                        Set::from_iter_dedup([non_participant_pk.clone()]),
                    ),
                );
                context.sleep(Duration::from_millis(10)).await;

                let peer2_index = peers[2].index.get() as u16;
                let shard = coded_block.shard(peer2_index).expect("missing shard");
                let shard_bytes = shard.encode();
                let mut shard_sub = peers[2]
                    .mailbox
                    .subscribe_assigned_shard_verified(commitment);

                non_participant_sender.send(Recipients::One(receiver_pk), shard_bytes, true);
                context.sleep(config.link.latency * 2).await;

                peers[2].mailbox.discovered(
                    commitment,
                    leader,
                    Round::new(Epoch::zero(), View::new(1)),
                );
                context.sleep(config.link.latency * 2).await;

                let blocked = oracle.blocked().await.unwrap();
                let non_participant_blocked = blocked
                    .iter()
                    .any(|(a, b)| a == &peers[2].public_key && b == &non_participant_pk);
                assert!(
                    !non_participant_blocked,
                    "non-participant should not be blocked when its pre-leader shard is ignored"
                );
                assert!(
                    matches!(shard_sub.try_recv(), Err(TryRecvError::Empty)),
                    "pre-leader shard from non-participant should not be buffered"
                );
            },
        );
    }

    #[test_traced]
    fn test_duplicate_shard_ignored() {
        // Use 10 peers so minimum_shards=4, giving us time to send duplicate before reconstruction.
        let fixture: Fixture<C> = Fixture {
            num_primary_peers: 10,
            ..Default::default()
        };

        fixture.start(
            |config, context, oracle, mut peers, _, coding_config| async move {
                let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block = CodedBlock::<B, C, H>::new(inner, coding_config, &STRATEGY);

                // Get peer 2's shard (from the leader).
                let peer2_index = peers[2].index.get() as u16;
                let peer2_shard = coded_block.shard(peer2_index).expect("missing shard");

                // Get peer 1's shard.
                let peer1_index = peers[1].index.get() as u16;
                let peer1_shard = coded_block.shard(peer1_index).expect("missing shard");

                let peer2_pk = peers[2].public_key.clone();
                let leader = peers[0].public_key.clone();

                // Inform peer 2 of the leader.
                peers[2].mailbox.discovered(
                    coded_block.commitment(),
                    leader,
                    Round::new(Epoch::zero(), View::new(1)),
                );

                // Send peer 2 their shard from the leader (1 checked shard).
                let leader_shard_bytes = peer2_shard.encode();
                peers[0]
                    .sender
                    .send(Recipients::One(peer2_pk.clone()), leader_shard_bytes, true);
                context.sleep(config.link.latency * 2).await;

                // Send peer 1's shard to peer 2 (first time - should succeed, 2 checked shards).
                let peer1_shard_bytes = peer1_shard.encode();
                peers[1].sender.send(
                    Recipients::One(peer2_pk.clone()),
                    peer1_shard_bytes.clone(),
                    true,
                );
                context.sleep(config.link.latency * 2).await;

                // Send the same shard again (exact duplicate - should be ignored, not blocked).
                // With 10 peers, minimum_shards=4, so we haven't reconstructed yet.
                peers[1]
                    .sender
                    .send(Recipients::One(peer2_pk), peer1_shard_bytes, true);
                context.sleep(config.link.latency * 2).await;

                // Peer 1 should NOT be blocked for sending an identical duplicate.
                let blocked_peers = oracle.blocked().await.unwrap();
                let is_blocked = blocked_peers
                    .iter()
                    .any(|(a, b)| a == &peers[2].public_key && b == &peers[1].public_key);
                assert!(
                    !is_blocked,
                    "peer should not be blocked for exact duplicate shard"
                );
            },
        );
    }

    #[test_traced]
    fn test_equivocating_shard_blocks_peer() {
        // Use 10 peers so minimum_shards=4, giving us time to send equivocating shard.
        let fixture: Fixture<C> = Fixture {
            num_primary_peers: 10,
            ..Default::default()
        };

        fixture.start(
            |config, context, oracle, mut peers, _, coding_config| async move {
                let inner1 = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block1 = CodedBlock::<B, C, H>::new(inner1, coding_config, &STRATEGY);

                // Create a second block with different payload to get different shard data.
                let inner2 = B::new(Sha256Digest::EMPTY, Height::new(1), 200);
                let coded_block2 = CodedBlock::<B, C, H>::new(inner2, coding_config, &STRATEGY);

                // Get peer 1's shard from block 1.
                let peer1_index = peers[1].index.get() as u16;
                let peer1_shard = coded_block1.shard(peer1_index).expect("missing shard");

                // Get peer 1's shard from block 2 (different data, same index).
                let mut peer1_equivocating_shard =
                    coded_block2.shard(peer1_index).expect("missing shard");
                // Override the commitment to match block 1 so the shard targets
                // the same reconstruction state.
                peer1_equivocating_shard.commitment = coded_block1.commitment();

                let peer2_pk = peers[2].public_key.clone();
                let leader = peers[0].public_key.clone();

                // Inform peer 2 of the leader.
                peers[2].mailbox.discovered(
                    coded_block1.commitment(),
                    leader,
                    Round::new(Epoch::zero(), View::new(1)),
                );

                // Send peer 2 the leader's shard (verified immediately).
                let peer2_index = peers[2].index.get() as u16;
                let leader_shard = coded_block1.shard(peer2_index).expect("missing shard");
                let leader_shard_bytes = leader_shard.encode();
                peers[0]
                    .sender
                    .send(Recipients::One(peer2_pk.clone()), leader_shard_bytes, true);
                context.sleep(config.link.latency * 2).await;

                // Send peer 1's valid shard to peer 2 (first time - succeeds).
                let shard_bytes = peer1_shard.encode();
                peers[1]
                    .sender
                    .send(Recipients::One(peer2_pk.clone()), shard_bytes, true);
                context.sleep(config.link.latency * 2).await;

                // Send a different shard from peer 1 (equivocation - should block).
                let equivocating_bytes = peer1_equivocating_shard.encode();
                peers[1]
                    .sender
                    .send(Recipients::One(peer2_pk), equivocating_bytes, true);
                context.sleep(config.link.latency * 2).await;

                // Peer 2 should have blocked peer 1 for equivocation.
                assert_blocked(&oracle, &peers[2].public_key, &peers[1].public_key).await;
            },
        );
    }

    /// Reconstructing a higher-view commitment leaves a lower-view record in place. An exact
    /// duplicate for the lower-view record is ignored, and a conflicting shard blocks its sender.
    #[test_traced]
    fn test_reconstruction_keeps_lower_view_records() {
        // Use 10 peers so minimum_shards=4.
        let fixture: Fixture<C> = Fixture {
            num_primary_peers: 10,
            ..Default::default()
        };

        fixture.start(
            |config, context, oracle, mut peers, _, coding_config| async move {
                // Commitment A at lower view (1).
                let block_a = CodedBlock::<B, C, H>::new(
                    B::new(Sha256Digest::EMPTY, Height::new(1), 100),
                    coding_config,
                    &STRATEGY,
                );
                let commitment_a = block_a.commitment();

                // Commitment B at higher view (2), which we will reconstruct.
                let block_b = CodedBlock::<B, C, H>::new(
                    B::new(Sha256Digest::EMPTY, Height::new(2), 200),
                    coding_config,
                    &STRATEGY,
                );
                let commitment_b = block_b.commitment();

                let peer2_pk = peers[2].public_key.clone();
                let leader = peers[0].public_key.clone();

                // Create state for A and ingest one shard from peer1.
                peers[2].mailbox.discovered(
                    commitment_a,
                    leader.clone(),
                    Round::new(Epoch::zero(), View::new(1)),
                );
                let shard_a = block_a
                    .shard(peers[1].index.get() as u16)
                    .expect("missing shard")
                    .encode();
                peers[1]
                    .sender
                    .send(Recipients::One(peer2_pk.clone()), shard_a.clone(), true);
                context.sleep(config.link.latency * 2).await;

                // Create/reconstruct B at higher view.
                peers[2].mailbox.discovered(
                    commitment_b,
                    leader,
                    Round::new(Epoch::zero(), View::new(2)),
                );
                // Leader's shard for peer2.
                let leader_shard_b = block_b
                    .shard(peers[2].index.get() as u16)
                    .expect("missing shard")
                    .encode();
                peers[0]
                    .sender
                    .send(Recipients::One(peer2_pk.clone()), leader_shard_b, true);

                // Three shards for minimum threshold (4 total with leader's).
                for i in [1usize, 3usize, 4usize] {
                    let shard = block_b
                        .shard(peers[i].index.get() as u16)
                        .expect("missing shard")
                        .encode();
                    peers[i]
                        .sender
                        .send(Recipients::One(peer2_pk.clone()), shard, true);
                }
                context.sleep(config.link.latency * 4).await;

                // B should reconstruct.
                let reconstructed = peers[2]
                    .mailbox
                    .get(commitment_b)
                    .await
                    .expect("block B should reconstruct");
                assert_eq!(reconstructed.commitment(), commitment_b);

                // Reconstructing B leaves A's record in place. Resending A's shard is an exact
                // duplicate and does not block peer 1.
                peers[1]
                    .sender
                    .send(Recipients::One(peer2_pk.clone()), shard_a, true);
                context.sleep(config.link.latency * 2).await;

                let blocked = oracle.blocked().await.unwrap();
                let blocked_peer1 = blocked
                    .iter()
                    .any(|(a, b)| a == &peers[2].public_key && b == &peers[1].public_key);
                assert!(
                    !blocked_peer1,
                    "peer1 should not be blocked for an exact duplicate"
                );

                // A shard that conflicts with peer 1's contribution to A blocks peer 1.
                let mut conflicting = CodedBlock::<B, C, H>::new(
                    B::new(Sha256Digest::EMPTY, Height::new(1), 300),
                    coding_config,
                    &STRATEGY,
                )
                .shard(peers[1].index.get() as u16)
                .expect("missing shard");
                conflicting.commitment = commitment_a;
                peers[1]
                    .sender
                    .send(Recipients::One(peer2_pk), conflicting.encode(), true);
                context.sleep(config.link.latency * 2).await;
                assert_blocked(&oracle, &peers[2].public_key, &peers[1].public_key).await;
            },
        );
    }

    /// A later notarization raises a reconstructing record's eviction round. The window then
    /// evicts a lower-round block, and the record still reconstructs its block.
    #[test_traced]
    fn test_later_notarization_refreshes_reconstruction_state_round() {
        let fixture: Fixture<C> = Fixture {
            num_primary_peers: 10,
            records: NZUsize!(2),
            ..Default::default()
        };

        fixture.start(
            |config, context, _, mut peers, _, coding_config| async move {
                let make_block = |id| {
                    CodedBlock::<B, C, H>::new(
                        B::new(Sha256Digest::EMPTY, Height::new(id), id * 100),
                        coding_config,
                        &STRATEGY,
                    )
                };
                let round = |view| Round::new(Epoch::zero(), View::new(view));
                let live = make_block(2);
                let live_commitment = live.commitment();
                let receiver_idx = 3usize;
                let receiver_pk = peers[receiver_idx].public_key.clone();
                let leader = peers[0].public_key.clone();

                // The receiver tracks the commitment at view 1 and subscribes to its block.
                peers[receiver_idx]
                    .mailbox
                    .discovered(live_commitment, leader, round(1));
                let mut live_sub = peers[receiver_idx].mailbox.subscribe(live_commitment);

                // The same commitment becomes live in a later round.
                peers[receiver_idx]
                    .mailbox
                    .notarized(live_commitment, round(4));

                // Blocks cached at views 2 and 5 exceed the window by one record. The
                // notarization raised the commitment to view 4, so the window evicts the block at
                // view 2.
                let lower = make_block(3);
                let lower_commitment = lower.commitment();
                peers[receiver_idx].mailbox.proposed(round(2), lower);
                peers[receiver_idx]
                    .mailbox
                    .proposed(round(5), make_block(4));
                assert!(
                    peers[receiver_idx]
                        .mailbox
                        .get(lower_commitment)
                        .await
                        .is_none()
                );
                assert!(
                    matches!(live_sub.try_recv(), Err(TryRecvError::Empty)),
                    "later-round reconstruction subscription should remain open"
                );

                // The assigned shard and three gossip shards reconstruct the block.
                let leader_shard = live
                    .shard(peers[receiver_idx].index.get() as u16)
                    .expect("missing leader shard");
                peers[0].sender.send(
                    Recipients::One(receiver_pk.clone()),
                    leader_shard.encode(),
                    true,
                );
                for i in [1usize, 2usize, 4usize] {
                    let shard = live
                        .shard(peers[i].index.get() as u16)
                        .expect("missing gossip shard");
                    peers[i].sender.send(
                        Recipients::One(receiver_pk.clone()),
                        shard.encode(),
                        true,
                    );
                }

                select! {
                    result = live_sub => {
                        let reconstructed =
                            result.expect("later-round reconstruction should remain live");
                        assert_eq!(reconstructed.commitment(), live_commitment);
                    },
                    _ = context.sleep(config.link.latency * 10) => {
                        panic!("later-round reconstruction did not complete");
                    },
                }
            },
        );
    }

    /// Notarizations and discoveries of a cached block raise its record's eviction round and
    /// keep its assigned-shard verification pending.
    #[test_traced]
    fn test_cached_observations_refresh_reconstruction_state_round() {
        let fixture: Fixture<C> = Fixture {
            num_primary_peers: 10,
            records: NZUsize!(2),
            ..Default::default()
        };

        fixture.start(
            |config, context, _, mut peers, _, coding_config| async move {
                let make_block = |id| {
                    CodedBlock::<B, C, H>::new(
                        B::new(Sha256Digest::EMPTY, Height::new(id), id * 100),
                        coding_config,
                        &STRATEGY,
                    )
                };
                let round = |view| Round::new(Epoch::zero(), View::new(view));
                let live = make_block(2);
                let live_commitment = live.commitment();
                let leader = peers[0].public_key.clone();
                let receivers = [3usize, 6usize];
                let receiver_keys = [
                    peers[receivers[0]].public_key.clone(),
                    peers[receivers[1]].public_key.clone(),
                ];

                // Both receivers track the commitment at view 1.
                for &receiver_idx in &receivers {
                    peers[receiver_idx].mailbox.discovered(
                        live_commitment,
                        leader.clone(),
                        round(1),
                    );
                }

                // Reconstruct from gossip while leaving assigned-shard verification pending.
                for sender_idx in [1usize, 2usize, 4usize, 5usize] {
                    let shard = live
                        .shard(peers[sender_idx].index.get() as u16)
                        .expect("missing gossip shard")
                        .encode();
                    for receiver in &receiver_keys {
                        peers[sender_idx].sender.send(
                            Recipients::One(receiver.clone()),
                            shard.clone(),
                            true,
                        );
                    }
                }
                context.sleep(config.link.latency * 4).await;

                for &receiver_idx in &receivers {
                    assert!(
                        peers[receiver_idx]
                            .mailbox
                            .get(live_commitment)
                            .await
                            .is_some(),
                        "block should be cached before its round is refreshed"
                    );
                }

                // One receiver observes a notarization and the other a discovery at view 4.
                let mut notarized_sub = peers[receivers[0]]
                    .mailbox
                    .subscribe_assigned_shard_verified(live_commitment);
                let mut discovered_sub = peers[receivers[1]]
                    .mailbox
                    .subscribe_assigned_shard_verified(live_commitment);
                peers[receivers[0]]
                    .mailbox
                    .notarized(live_commitment, round(4));
                peers[receivers[1]]
                    .mailbox
                    .discovered(live_commitment, leader, round(4));

                // Blocks cached at views 2 and 5 exceed each window by one record. The cached
                // observations raised the commitment to view 4, so each window evicts the block
                // at view 2.
                let lower = make_block(3);
                let higher = make_block(4);
                for &receiver_idx in &receivers {
                    peers[receiver_idx].mailbox.proposed(round(2), lower.clone());
                    peers[receiver_idx].mailbox.proposed(round(5), higher.clone());
                    assert!(
                        peers[receiver_idx]
                            .mailbox
                            .get(lower.commitment())
                            .await
                            .is_none()
                    );
                }

                assert!(
                    matches!(notarized_sub.try_recv(), Err(TryRecvError::Empty)),
                    "cached notarization should keep reconstruction state live"
                );
                assert!(
                    matches!(discovered_sub.try_recv(), Err(TryRecvError::Empty)),
                    "cached discovery should keep reconstruction state live"
                );
                for &receiver_idx in &receivers {
                    assert!(
                        peers[receiver_idx]
                            .mailbox
                            .get(live_commitment)
                            .await
                            .is_some(),
                        "cached observation should keep the reconstructed block live"
                    );
                }

                // The leader's shards resolve both assigned-shard subscriptions.
                for (&receiver_idx, receiver) in receivers.iter().zip(&receiver_keys) {
                    let leader_shard = live
                        .shard(peers[receiver_idx].index.get() as u16)
                        .expect("missing leader shard");
                    peers[0].sender.send(
                        Recipients::One(receiver.clone()),
                        leader_shard.encode(),
                        true,
                    );
                }

                select! {
                    result = notarized_sub => {
                        result.expect("notarized reconstruction state should accept the leader shard");
                    },
                    _ = context.sleep(config.link.latency * 10) => {
                        panic!("notarized reconstruction state did not accept the leader shard");
                    },
                }
                select! {
                    result = discovered_sub => {
                        result.expect("discovered reconstruction state should accept the leader shard");
                    },
                    _ = context.sleep(config.link.latency * 10) => {
                        panic!("discovered reconstruction state did not accept the leader shard");
                    },
                }
            },
        );
    }

    /// A local proposal in a one-record window evicts an older reconstruction state. A shard that
    /// conflicts with the evicted state's shard then enters its sender's buffer without blocking.
    #[test_traced]
    fn test_local_proposal_evicts_older_reconstruction_state() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (network, oracle) = simulated::Network::<deterministic::Context, P>::new(
                context.child("network"),
                simulated::Config {
                    max_size: MAX_SHARD_SIZE as u32,
                    max_peers_per_set: NZUsize!(4),
                    disconnect_on_block: true,
                    tracked_peer_sets: NZUsize!(1),
                },
            );
            network.start();

            let mut private_keys: Vec<PrivateKey> = (0..4).map(PrivateKey::from_seed).collect();
            private_keys.sort_by_key(|key| key.public_key());
            let peer_keys: Vec<P> = private_keys.iter().map(|key| key.public_key()).collect();
            let (mut engine, mut sender) =
                unstarted(&context, &oracle, &private_keys, 2, NZUsize!(1)).await;
            let coding_config = coding_config_for_participants(peer_keys.len() as u16);
            let make_block = |height, payload| {
                CodedBlock::<B, C, H>::new(
                    B::new(Sha256Digest::EMPTY, Height::new(height), payload),
                    coding_config,
                    &STRATEGY,
                )
            };
            let block_a = make_block(1, 100);
            let commitment_a = block_a.commitment();
            let block_b = make_block(2, 200);
            let commitment_b = block_b.commitment();
            let peer1 = peer_keys[1].clone();

            // The engine tracks A at view 1, and peer 1 contributes its shard.
            engine.handle_external_proposal(
                &mut sender,
                commitment_a,
                peer_keys[0].clone(),
                Round::new(Epoch::zero(), View::new(1)),
            );
            engine.trim();
            let shard_a = block_a.shard(1).expect("missing shard");
            engine.handle_network_shard(&mut sender, peer1.clone(), shard_a);

            // The one-record window evicts A for the local proposal of B at view 2.
            engine.broadcast_shards(
                &mut sender,
                Round::new(Epoch::zero(), View::new(2)),
                Arc::new(block_b),
            );
            engine.trim();
            let record = engine
                .records
                .get(&commitment_b)
                .expect("record must exist");
            assert!(record.block().is_some());
            assert!(!engine.records.contains_key(&commitment_a));

            // A shard that conflicts with peer 1's contribution to A enters peer 1's buffer
            // without blocking.
            let mut equivocating = make_block(1, 300).shard(1).expect("missing shard");
            equivocating.commitment = commitment_a;
            engine.handle_network_shard(&mut sender, peer1.clone(), equivocating);
            assert_eq!(buffered(&engine, &peer1, commitment_a), 1);
            assert!(oracle.blocked().await.unwrap().is_empty());
        });
    }

    #[test_traced]
    fn test_pending_shards_batch_validated_at_quorum() {
        let fixture: Fixture<BatchChecking> = Fixture {
            num_primary_peers: 22,
            ..Default::default()
        };

        fixture.start(
            |config, context, oracle, mut peers, _, coding_config| async move {
                let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block =
                    CodedBlock::<B, BatchChecking, H>::new(inner, coding_config, &STRATEGY);
                let commitment = coded_block.commitment();

                let peer3_pk = peers[3].public_key.clone();
                let leader = peers[0].public_key.clone();

                // Inform peer 3 that peer 0 is the leader.
                peers[3].mailbox.discovered(
                    commitment,
                    leader,
                    Round::new(Epoch::zero(), View::new(1)),
                );

                // Queue peer-indexed shards until the assigned shard completes quorum.
                for &sender_idx in &[1, 2, 4, 5, 6, 7, 8] {
                    let shard = coded_block
                        .shard(peers[sender_idx].index.get() as u16)
                        .expect("missing shard");
                    let shard_bytes = shard.encode();
                    peers[sender_idx].sender.send(
                        Recipients::One(peer3_pk.clone()),
                        shard_bytes,
                        true,
                    );
                }

                context.sleep(config.link.latency * 2).await;

                // Block should not be reconstructed yet (no leader shard verified).
                let block = peers[3].mailbox.get(commitment).await;
                assert!(block.is_none(), "block should not be reconstructed yet");

                // The leader supplies the eagerly verified assigned shard.
                let peer3_index = peers[3].index.get() as u16;
                let leader_shard = coded_block.shard(peer3_index).expect("missing shard");
                let leader_shard_bytes = leader_shard.encode();
                peers[0]
                    .sender
                    .send(Recipients::One(peer3_pk), leader_shard_bytes, true);

                context.sleep(config.link.latency * 2).await;

                // No peers should be blocked (all shards were valid).
                let blocked = oracle.blocked().await.unwrap();
                assert!(
                    blocked.is_empty(),
                    "no peers should be blocked for valid pending shards"
                );

                // Eight checked shards are sufficient to reconstruct the block.
                let block = peers[3].mailbox.get(commitment).await;
                assert!(
                    block.is_some(),
                    "block should be reconstructed after batch validation"
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
            num_primary_peers: 10,
            ..Default::default()
        };

        fixture.start(
            |config, context, oracle, mut peers, _, coding_config| async move {
                let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block = CodedBlock::<B, C, H>::new(inner, coding_config, &STRATEGY);
                let commitment = coded_block.commitment();

                let receiver_idx = 3usize;
                let receiver_pk = peers[receiver_idx].public_key.clone();
                let leader = peers[0].public_key.clone();

                // Subscribe before any shards arrive.
                let mut shard_sub = peers[receiver_idx]
                    .mailbox
                    .subscribe_assigned_shard_verified(commitment);

                // Send the leader's shard (for receiver's index) and three shards,
                // all before leader announcement.
                let leader_shard = coded_block
                    .shard(peers[receiver_idx].index.get() as u16)
                    .expect("missing shard")
                    .encode();
                peers[0]
                    .sender
                    .send(Recipients::One(receiver_pk.clone()), leader_shard, true);

                for i in [1usize, 2usize, 4usize] {
                    let shard = coded_block
                        .shard(peers[i].index.get() as u16)
                        .expect("missing shard")
                        .encode();
                    peers[i]
                        .sender
                        .send(Recipients::One(receiver_pk.clone()), shard, true);
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
                peers[receiver_idx].mailbox.discovered(
                    commitment,
                    leader,
                    Round::new(Epoch::zero(), View::new(1)),
                );

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
    fn test_notarized_commitment_reconstructs_from_buffered_peer_shards_without_leader() {
        let fixture: Fixture<C> = Fixture {
            num_primary_peers: 10,
            ..Default::default()
        };

        fixture.start(
            |config, context, oracle, mut peers, _, coding_config| async move {
                let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block = CodedBlock::<B, C, H>::new(inner, coding_config, &STRATEGY);
                let commitment = coded_block.commitment();
                let round = Round::new(Epoch::zero(), View::new(1));

                let receiver_idx = 3usize;
                let receiver = peers[receiver_idx].public_key.clone();

                let block_sub = peers[receiver_idx].mailbox.subscribe(commitment);

                // Four sender-indexed shards are enough to reconstruct without
                // classifying any sender as the leader.
                for sender_idx in [1usize, 2, 4, 5] {
                    let shard = coded_block
                        .shard(peers[sender_idx].index.get() as u16)
                        .expect("missing shard")
                        .encode();
                    peers[sender_idx].sender.send(
                        Recipients::One(receiver.clone()),
                        shard,
                        true,
                    );
                }
                context.sleep(config.link.latency * 2).await;

                assert!(
                    peers[receiver_idx].mailbox.get(commitment).await.is_none(),
                    "block should not reconstruct before the commitment is notarized"
                );

                peers[receiver_idx].mailbox.notarized(commitment, round);

                select! {
                    _ = block_sub => {},
                    _ = context.sleep(Duration::from_secs(5)) => {
                        panic!("block subscription did not resolve after notarized reconstruction interest");
                    },
                }

                let reconstructed = peers[receiver_idx]
                    .mailbox
                    .get(commitment)
                    .await
                    .expect("block should reconstruct from buffered peer shards");
                assert_eq!(reconstructed.commitment(), commitment);

                let mut assigned = peers[receiver_idx]
                    .mailbox
                    .subscribe_assigned_shard_verified(commitment);
                assert!(
                    matches!(assigned.try_recv(), Err(TryRecvError::Empty)),
                    "leaderless reconstruction must not satisfy assigned shard readiness"
                );

                let leader = peers[0].public_key.clone();
                peers[receiver_idx]
                    .mailbox
                    .discovered(commitment, leader, round);
                let leader_shard = coded_block
                    .shard(peers[receiver_idx].index.get() as u16)
                    .expect("missing leader shard")
                    .encode();
                peers[0].sender.send(
                    Recipients::One(receiver),
                    leader_shard,
                    true,
                );

                select! {
                    _ = assigned => {},
                    _ = context.sleep(Duration::from_secs(5)) => {
                        panic!("assigned shard subscription did not resolve after leader discovery");
                    },
                }

                assert!(
                    oracle.blocked().await.unwrap().is_empty(),
                    "valid sender-indexed shards should not block peers"
                );
            },
        );
    }

    #[test_traced]
    fn test_late_subscription_uses_notarized_cache_after_peer_buffer_pressure() {
        let fixture: Fixture<C> = Fixture {
            num_primary_peers: 10,
            peer_buffer_size: NZUsize!(1),
            ..Default::default()
        };

        fixture.start(
            |config, context, oracle, mut peers, _, coding_config| async move {
                let target = CodedBlock::<B, C, H>::new(
                    B::new(Sha256Digest::EMPTY, Height::new(1), 1),
                    coding_config,
                    &STRATEGY,
                );
                let target_commitment = target.commitment();
                let receiver_idx = 3usize;
                let receiver = peers[receiver_idx].public_key.clone();
                let initial_round = Round::new(Epoch::zero(), View::new(1));
                let later_round = Round::new(Epoch::zero(), View::new(4));

                for sender_idx in [1usize, 2, 4, 5] {
                    let shard = target
                        .shard(peers[sender_idx].index.get() as u16)
                        .expect("missing target shard")
                        .encode();
                    peers[sender_idx].sender.send(
                        Recipients::One(receiver.clone()),
                        shard,
                        true,
                    );
                }
                context.sleep(config.link.latency * 2).await;

                peers[receiver_idx]
                    .mailbox
                    .notarized(target_commitment, initial_round);
                let target_sub = peers[receiver_idx].mailbox.subscribe(target_commitment);
                select! {
                    result = target_sub => {
                        let block = result.expect("notarized target should reconstruct");
                        assert_eq!(block.commitment(), target_commitment);
                    },
                    _ = context.sleep(Duration::from_secs(5)) => {
                        panic!("notarized target did not reconstruct");
                    },
                }

                // A later notarization leaves the target cached. The record owns the block
                // independently of bounded pre-leader shard buffers.
                peers[receiver_idx]
                    .mailbox
                    .notarized(target_commitment, later_round);
                assert!(
                    peers[receiver_idx]
                        .mailbox
                        .get(target_commitment)
                        .await
                        .is_some(),
                    "target should remain cached after a later notarization"
                );

                // The fixture retains one pre-leader shard per peer. One authenticated peer
                // sends two distinct codec-valid shards to exercise the same eviction boundary.
                let pressure_blocks = [2u64, 3].map(|id| {
                    CodedBlock::<B, C, H>::new(
                        B::new(Sha256Digest::EMPTY, Height::new(id), id),
                        coding_config,
                        &STRATEGY,
                    )
                });
                for block in &pressure_blocks {
                    let shard = block
                        .shard(peers[1].index.get() as u16)
                        .expect("missing pressure shard")
                        .encode();
                    peers[1].sender.send(
                        Recipients::One(receiver.clone()),
                        shard,
                        true,
                    );
                }
                context.sleep(config.link.latency * 2).await;

                let [evicted_block, retained_block] = &pressure_blocks;
                for (block, should_reconstruct) in
                    [(evicted_block, false), (retained_block, true)]
                {
                    for sender_idx in [2usize, 4, 5] {
                        let shard = block
                            .shard(peers[sender_idx].index.get() as u16)
                            .expect("missing complementary pressure shard")
                            .encode();
                        peers[sender_idx].sender.send(
                            Recipients::One(receiver.clone()),
                            shard,
                            true,
                        );
                    }
                    context.sleep(config.link.latency * 2).await;

                    let commitment = block.commitment();
                    peers[receiver_idx]
                        .mailbox
                        .notarized(commitment, initial_round);
                    if should_reconstruct {
                        let block_sub = peers[receiver_idx].mailbox.subscribe(commitment);
                        select! {
                            result = block_sub => {
                                let block = result.expect("retained pressure block should reconstruct");
                                assert_eq!(block.commitment(), commitment);
                            },
                            _ = context.sleep(Duration::from_secs(5)) => {
                                panic!("retained same-peer shard did not reconstruct");
                            },
                        }
                    } else {
                        assert!(
                            peers[receiver_idx]
                                .mailbox
                                .get(commitment)
                                .await
                                .is_none(),
                            "evicted same-peer shard should not reconstruct"
                        );
                    }
                }

                // This is the subscription used by Coding's Marshal buffer. It is installed
                // only after peer pressure, with no resolver in this fixture.
                let late_sub = peers[receiver_idx].mailbox.subscribe(target_commitment);
                select! {
                    result = late_sub => {
                        let block = result.expect("target should remain cached");
                        assert_eq!(block.commitment(), target_commitment);
                    },
                    _ = context.sleep(Duration::from_secs(5)) => {
                        panic!("late target subscription lost cached ownership");
                    },
                }

                assert!(
                    oracle.blocked().await.unwrap().is_empty(),
                    "valid pressure shards should not block peers"
                );
            },
        );
    }

    #[test_traced]
    fn test_leader_shard_after_notarized_is_buffered_until_discovered() {
        let fixture: Fixture<C> = Fixture {
            num_primary_peers: 10,
            ..Default::default()
        };

        fixture.start(
            |config, context, oracle, mut peers, _, coding_config| async move {
                let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block = CodedBlock::<B, C, H>::new(inner, coding_config, &STRATEGY);
                let commitment = coded_block.commitment();
                let round = Round::new(Epoch::zero(), View::new(1));

                let leader_idx = 0usize;
                let receiver_idx = 3usize;
                let leader = peers[leader_idx].public_key.clone();
                let receiver = peers[receiver_idx].public_key.clone();

                peers[receiver_idx].mailbox.notarized(commitment, round);
                let assigned = peers[receiver_idx]
                    .mailbox
                    .subscribe_assigned_shard_verified(commitment);

                let leader_shard = coded_block
                    .shard(peers[receiver_idx].index.get() as u16)
                    .expect("missing receiver shard")
                    .encode();
                peers[leader_idx]
                    .sender
                    .send(Recipients::One(receiver), leader_shard, true);

                context.sleep(config.link.latency * 2).await;
                peers[receiver_idx]
                    .mailbox
                    .discovered(commitment, leader, round);

                assigned
                    .await
                    .expect("assigned shard should resolve after leader discovery");
                assert!(
                    oracle.blocked().await.unwrap().is_empty(),
                    "valid leader shard should not block peers"
                );
            },
        );
    }

    #[test_traced]
    fn test_post_leader_shards_processed_immediately() {
        // Test that shards arriving after leader announcement are processed
        // without waiting for any extra trigger.
        let fixture: Fixture<C> = Fixture {
            num_primary_peers: 10,
            ..Default::default()
        };

        fixture.start(
            |config, context, oracle, mut peers, _, coding_config| async move {
                let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block = CodedBlock::<B, C, H>::new(inner, coding_config, &STRATEGY);
                let commitment = coded_block.commitment();

                let receiver_idx = 3usize;
                let receiver_pk = peers[receiver_idx].public_key.clone();
                let leader = peers[0].public_key.clone();

                let shard_sub = peers[receiver_idx]
                    .mailbox
                    .subscribe_assigned_shard_verified(commitment);
                peers[receiver_idx].mailbox.discovered(
                    commitment,
                    leader.clone(),
                    Round::new(Epoch::zero(), View::new(1)),
                );

                // Send leader's shard (for receiver's index) after leader is known.
                let leader_shard = coded_block
                    .shard(peers[receiver_idx].index.get() as u16)
                    .expect("missing shard")
                    .encode();
                peers[0]
                    .sender
                    .send(Recipients::One(receiver_pk.clone()), leader_shard, true);

                // Subscription should resolve from the leader's shard.
                select! {
                    _ = shard_sub => {},
                    _ = context.sleep(Duration::from_secs(5)) => {
                        panic!("shard subscription did not resolve after post-leader shard");
                    },
                }

                // Send enough shards after leader known to reconstruct.
                for i in [1usize, 2usize, 4usize] {
                    let shard = coded_block
                        .shard(peers[i].index.get() as u16)
                        .expect("missing shard")
                        .encode();
                    peers[i]
                        .sender
                        .send(Recipients::One(receiver_pk.clone()), shard, true);
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
            num_primary_peers: 4,
            ..Default::default()
        };

        fixture.start(
            |config, context, oracle, mut peers, _, _coding_config| async move {
                let peer0_pk = peers[0].public_key.clone();
                let peer1_pk = peers[1].public_key.clone();

                // Send garbage bytes that will fail codec decoding.
                let garbage = Bytes::from(vec![0xFF, 0xFE, 0xFD, 0xFC, 0xFB]);
                peers[1]
                    .sender
                    .send(Recipients::One(peer0_pk.clone()), garbage, true);

                context.sleep(config.link.latency * 2).await;

                // Peer 1 should be blocked by peer 0 for sending invalid shard.
                assert_blocked(&oracle, &peer0_pk, &peer1_pk).await;
            },
        );
    }

    /// A peer that sends a shard wider than a block of the maximum size produces is blocked.
    #[test_traced]
    fn test_oversized_shard_blocks_peer() {
        let fixture: Fixture<C> = Fixture {
            max_block_size: NZUsize!(1),
            ..Default::default()
        };
        fixture.start(
            |config, context, oracle, mut peers, _, coding_config| async move {
                // Peer 1 sends peer 2 a shard of a block larger than the maximum.
                let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block = CodedBlock::<B, C, H>::new(inner, coding_config, &STRATEGY);
                let shard = coded_block
                    .shard(peers[2].index.get() as u16)
                    .expect("missing shard");
                let peer2 = peers[2].public_key.clone();
                peers[1]
                    .sender
                    .send(Recipients::One(peer2.clone()), shard.encode(), true);
                context.sleep(config.link.latency * 2).await;

                // Peer 2 rejects the shard when decoding it and blocks peer 1.
                assert_blocked(&oracle, &peer2, &peers[1].public_key).await;
            },
        );
    }

    /// A reconstructed block larger than the maximum block size is rejected, even when its shards
    /// are no wider than a block of the maximum size produces.
    #[test_traced]
    fn test_oversized_reconstruction_rejected() {
        let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
        let size = inner.encode_size();
        let coded_block =
            CodedBlock::<B, C, H>::new(inner, coding_config_for_participants(4), &STRATEGY);
        let shard = coded_block.shard(0).expect("missing shard").encode();
        let max = (1..size)
            .rev()
            .find(|&max| {
                Shard::<B, C, H>::decode_cfg(shard.clone(), &NonZeroUsize::new(max).unwrap())
                    .is_ok()
            })
            .expect("shard widths round up");
        let fixture: Fixture<C> = Fixture {
            max_block_size: NonZeroUsize::new(max).unwrap(),
            ..Default::default()
        };
        fixture.start(|config, context, oracle, mut peers, _, _| async move {
            // The leader delivers peer 3's shard and peer 1 gossips its own, reaching the
            // minimum for a block over the maximum whose shards share the maximum's width.
            let commitment = coded_block.commitment();
            let receiver = peers[3].public_key.clone();
            peers[3].mailbox.discovered(
                commitment,
                peers[0].public_key.clone(),
                Round::new(Epoch::zero(), View::new(1)),
            );
            let mut subscription = peers[3].mailbox.subscribe(commitment);
            for (from, index) in [(0, 3), (1, 1)] {
                let shard = coded_block.shard(index).expect("missing shard");
                peers[from]
                    .sender
                    .send(Recipients::One(receiver.clone()), shard.encode(), true);
            }
            context.sleep(config.link.latency * 2).await;

            // Reconstruction rejects the block and removes the commitment without blocking
            // anyone.
            assert!(matches!(subscription.try_recv(), Err(TryRecvError::Closed)));
            assert!(peers[3].mailbox.get(commitment).await.is_none());
            assert!(oracle.blocked().await.unwrap().is_empty());
        });
    }

    /// A local proposal larger than the maximum block size is not broadcast, so peers never
    /// receive shards they would reject.
    #[test_traced]
    fn test_oversized_proposal_not_broadcast() {
        let fixture: Fixture<C> = Fixture {
            max_block_size: NZUsize!(1),
            ..Default::default()
        };
        fixture.start(
            |config, context, oracle, peers, _, coding_config| async move {
                // Peer 0 proposes a block larger than the maximum while peer 1 awaits its shard.
                let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block = CodedBlock::<B, C, H>::new(inner, coding_config, &STRATEGY);
                let commitment = coded_block.commitment();
                let round = Round::new(Epoch::zero(), View::new(1));
                let leader = peers[0].public_key.clone();
                peers[1].mailbox.discovered(commitment, leader, round);
                let mut verified = peers[1]
                    .mailbox
                    .subscribe_assigned_shard_verified(commitment);
                peers[0].mailbox.proposed(round, coded_block);
                context.sleep(config.link.latency * 2).await;

                // No shard was sent, so nobody blocked the proposer and peer 1 still waits.
                assert!(oracle.blocked().await.unwrap().is_empty());
                assert!(matches!(verified.try_recv(), Err(TryRecvError::Empty)));
                assert!(peers[0].mailbox.get(commitment).await.is_none());
            },
        );
    }

    #[test_traced]
    fn test_duplicate_buffered_shard_does_not_block_before_leader() {
        // Test that duplicate shards before leader announcement are
        // buffered and do not immediately block the sender.
        let fixture: Fixture<C> = Fixture {
            ..Default::default()
        };

        fixture.start(
            |config, context, oracle, mut peers, _, coding_config| async move {
                let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block = CodedBlock::<B, C, H>::new(inner, coding_config, &STRATEGY);

                // Get peer 2's shard.
                let peer2_index = peers[2].index.get() as u16;
                let peer2_shard = coded_block.shard(peer2_index).expect("missing shard");
                let shard_bytes = peer2_shard.encode();

                let peer2_pk = peers[2].public_key.clone();

                // Do NOT set a leader — shards should be buffered.

                // Peer 1 sends the shard to peer 2 (buffered, leader unknown).
                peers[1]
                    .sender
                    .send(Recipients::One(peer2_pk.clone()), shard_bytes.clone(), true);
                context.sleep(config.link.latency * 2).await;

                // No one should be blocked yet.
                let blocked = oracle.blocked().await.unwrap();
                assert!(blocked.is_empty(), "no peers should be blocked yet");

                // Peer 1 sends the same shard AGAIN (duplicate while leader unknown).
                peers[1]
                    .sender
                    .send(Recipients::One(peer2_pk), shard_bytes, true);
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
    fn test_invalid_leader_shard_crypto_blocks_leader() {
        // Test that a leader shard failing cryptographic verification
        // results in the leader being blocked.
        let fixture: Fixture<C> = Fixture {
            ..Default::default()
        };

        fixture.start(
            |config, context, oracle, mut peers, _, coding_config| async move {
                // Create two different blocks — shard from block2 won't verify
                // against commitment from block1.
                let inner1 = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block1 = CodedBlock::<B, C, H>::new(inner1, coding_config, &STRATEGY);
                let commitment1 = coded_block1.commitment();

                let inner2 = B::new(Sha256Digest::EMPTY, Height::new(2), 200);
                let coded_block2 = CodedBlock::<B, C, H>::new(inner2, coding_config, &STRATEGY);

                // Get peer 2's shard from block2, but re-wrap it with
                // block1's commitment so it fails verification.
                let peer2_index = peers[2].index.get() as u16;
                let mut wrong_shard = coded_block2.shard(peer2_index).expect("missing shard");
                wrong_shard.commitment = commitment1;
                let wrong_bytes = wrong_shard.encode();

                let peer2_pk = peers[2].public_key.clone();
                let leader = peers[0].public_key.clone();

                // Inform peer 2 that peer 0 is the leader.
                peers[2].mailbox.discovered(
                    commitment1,
                    leader,
                    Round::new(Epoch::zero(), View::new(1)),
                );

                // Leader (peer 0) sends the invalid shard.
                peers[0]
                    .sender
                    .send(Recipients::One(peer2_pk), wrong_bytes, true);
                context.sleep(config.link.latency * 2).await;

                // Peer 0 (leader) should be blocked for invalid crypto.
                assert_blocked(&oracle, &peers[2].public_key, &peers[0].public_key).await;
            },
        );
    }

    #[test_traced]
    fn test_invalid_assigned_shard_from_non_leader_blocks_only_sender() {
        // A Byzantine participant can race the leader with garbage at the
        // victim's assigned index, since the assigned index is accepted from
        // any participant. The sender must be blocked without poisoning the
        // slot: the leader's genuine shard must still verify afterward.
        let fixture: Fixture<C> = Fixture {
            ..Default::default()
        };

        fixture.start(
            |config, context, oracle, mut peers, _, coding_config| async move {
                // Create two different blocks — shard from block2 won't verify
                // against commitment from block1.
                let inner1 = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block1 = CodedBlock::<B, C, H>::new(inner1, coding_config, &STRATEGY);
                let commitment1 = coded_block1.commitment();

                let inner2 = B::new(Sha256Digest::EMPTY, Height::new(2), 200);
                let coded_block2 = CodedBlock::<B, C, H>::new(inner2, coding_config, &STRATEGY);

                // Get peer 2's shard from block2, but re-wrap it with
                // block1's commitment so it fails verification.
                let peer2_index = peers[2].index.get() as u16;
                let mut wrong_shard = coded_block2.shard(peer2_index).expect("missing shard");
                wrong_shard.commitment = commitment1;
                let wrong_bytes = wrong_shard.encode();

                let peer2_pk = peers[2].public_key.clone();
                let leader = peers[0].public_key.clone();

                let mut shard_sub = peers[2]
                    .mailbox
                    .subscribe_assigned_shard_verified(commitment1);

                // Inform peer 2 that peer 0 is the leader.
                peers[2].mailbox.discovered(
                    commitment1,
                    leader,
                    Round::new(Epoch::zero(), View::new(1)),
                );

                // Non-leader peer 1 sends the invalid shard at peer 2's
                // assigned index.
                peers[1]
                    .sender
                    .send(Recipients::One(peer2_pk.clone()), wrong_bytes, true);
                context.sleep(config.link.latency * 2).await;

                // Peer 1 should be blocked for invalid crypto, and the assigned
                // slot must not be treated as satisfied.
                assert_blocked(&oracle, &peers[2].public_key, &peers[1].public_key).await;
                assert!(
                    matches!(shard_sub.try_recv(), Err(TryRecvError::Empty)),
                    "subscription should not resolve from invalid shard"
                );

                // The leader's genuine shard for the same index must still verify.
                let real_bytes = coded_block1
                    .shard(peer2_index)
                    .expect("missing shard")
                    .encode();
                peers[0]
                    .sender
                    .send(Recipients::One(peer2_pk), real_bytes, true);
                select! {
                    _ = shard_sub => {},
                    _ = context.sleep(Duration::from_secs(5)) => {
                        panic!("genuine assigned shard did not verify after invalid one");
                    },
                };
            },
        );
    }

    #[test_traced]
    fn test_shard_index_mismatch_blocks_peer() {
        // Test that a shard whose shard index doesn't match the sender's
        // participant index results in blocking the sender.
        let fixture: Fixture<C> = Fixture {
            num_primary_peers: 10,
            ..Default::default()
        };

        fixture.start(
            |config, context, oracle, mut peers, _, coding_config| async move {
                let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block = CodedBlock::<B, C, H>::new(inner, coding_config, &STRATEGY);
                let commitment = coded_block.commitment();

                // Get peer 3's leader shard so peer 3 can validate shards.
                let peer3_index = peers[3].index.get() as u16;
                let leader_shard = coded_block.shard(peer3_index).expect("missing shard");

                // Get peer 1's valid shard, then change the index to peer 4's index.
                let peer1_index = peers[1].index.get() as u16;
                let mut wrong_index_shard = coded_block.shard(peer1_index).expect("missing shard");
                // Mutate the index so it doesn't match sender (peer 1).
                wrong_index_shard.index = peers[4].index.get() as u16;
                let wrong_bytes = wrong_index_shard.encode();

                let peer3_pk = peers[3].public_key.clone();
                let leader = peers[0].public_key.clone();

                // Inform peer 3 of the leader and send them the leader shard.
                peers[3].mailbox.discovered(
                    commitment,
                    leader,
                    Round::new(Epoch::zero(), View::new(1)),
                );
                let shard_bytes = leader_shard.encode();
                peers[0]
                    .sender
                    .send(Recipients::One(peer3_pk.clone()), shard_bytes, true);
                context.sleep(config.link.latency * 2).await;

                // Peer 1 sends a shard with a mismatched index to peer 3.
                peers[1]
                    .sender
                    .send(Recipients::One(peer3_pk), wrong_bytes, true);
                context.sleep(config.link.latency * 2).await;

                // Peer 1 should be blocked for shard index mismatch.
                assert_blocked(&oracle, &peers[3].public_key, &peers[1].public_key).await;
            },
        );
    }

    #[test_traced]
    fn test_invalid_shard_crypto_blocks_peer() {
        // Test that a shard failing cryptographic verification
        // results in blocking the sender once batch validation fires at quorum.
        let fixture: Fixture<C> = Fixture {
            num_primary_peers: 10,
            ..Default::default()
        };

        fixture.start(
            |config, context, oracle, mut peers, _, coding_config| async move {
                // Create two different blocks.
                let inner1 = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block1 = CodedBlock::<B, C, H>::new(inner1, coding_config, &STRATEGY);
                let commitment1 = coded_block1.commitment();

                let inner2 = B::new(Sha256Digest::EMPTY, Height::new(2), 200);
                let coded_block2 = CodedBlock::<B, C, H>::new(inner2, coding_config, &STRATEGY);

                // Get peer 3's leader shard from block1 (valid).
                let peer3_index = peers[3].index.get() as u16;
                let leader_shard = coded_block1.shard(peer3_index).expect("missing shard");

                // Get peer 1's shard from block2, but re-wrap with block1's
                // commitment so verification fails.
                let peer1_index = peers[1].index.get() as u16;
                let mut wrong_shard = coded_block2.shard(peer1_index).expect("missing shard");
                wrong_shard.commitment = commitment1;
                let wrong_bytes = wrong_shard.encode();

                let peer3_pk = peers[3].public_key.clone();
                let leader = peers[0].public_key.clone();

                // Inform peer 3 of the leader and send the valid leader shard.
                peers[3].mailbox.discovered(
                    commitment1,
                    leader,
                    Round::new(Epoch::zero(), View::new(1)),
                );
                let shard_bytes = leader_shard.encode();
                peers[0]
                    .sender
                    .send(Recipients::One(peer3_pk.clone()), shard_bytes, true);
                context.sleep(config.link.latency * 2).await;

                // Peer 1 sends the invalid shard.
                peers[1]
                    .sender
                    .send(Recipients::One(peer3_pk.clone()), wrong_bytes, true);
                context.sleep(config.link.latency * 2).await;

                // No block yet: batch validation deferred until quorum.
                // Send valid shards from peers 2 and 4 to reach quorum
                // (minimum_shards = 4: 1 leader + 3 pending).
                for &idx in &[2, 4] {
                    let peer_index = peers[idx].index.get() as u16;
                    let shard = coded_block1.shard(peer_index).expect("missing shard");
                    let bytes = shard.encode();
                    peers[idx]
                        .sender
                        .send(Recipients::One(peer3_pk.clone()), bytes, true);
                }
                context.sleep(config.link.latency * 2).await;

                // Peer 1 should be blocked for invalid shard crypto.
                assert_blocked(&oracle, &peers[3].public_key, &peers[1].public_key).await;
            },
        );
    }

    #[test_traced]
    fn test_reconstruction_recovers_after_quorum_with_one_invalid_shard() {
        // With 10 peers, minimum_shards=4.
        // Contribute exactly 4 shards first (1 leader + 3 pending), with one invalid:
        // quorum is reached, but checked_shards stays at 3 after batch validation.
        // Then send one more valid shard to meet reconstruction threshold.
        let fixture: Fixture<C> = Fixture {
            num_primary_peers: 10,
            ..Default::default()
        };

        fixture.start(
            |config, context, oracle, mut peers, _, coding_config| async move {
                let inner1 = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block1 = CodedBlock::<B, C, H>::new(inner1, coding_config, &STRATEGY);
                let commitment1 = coded_block1.commitment();

                let inner2 = B::new(Sha256Digest::EMPTY, Height::new(2), 200);
                let coded_block2 = CodedBlock::<B, C, H>::new(inner2, coding_config, &STRATEGY);

                let receiver_idx = 3usize;
                let receiver_pk = peers[receiver_idx].public_key.clone();

                // Prepare one invalid shard: shard data from block2, commitment from block1.
                let peer1_index = peers[1].index.get() as u16;
                let mut invalid_shard = coded_block2.shard(peer1_index).expect("missing shard");
                invalid_shard.commitment = commitment1;

                // Announce leader and deliver receiver's leader shard.
                let leader = peers[0].public_key.clone();
                peers[receiver_idx].mailbox.discovered(
                    commitment1,
                    leader,
                    Round::new(Epoch::zero(), View::new(1)),
                );
                let leader_shard = coded_block1
                    .shard(peers[receiver_idx].index.get() as u16)
                    .expect("missing shard")
                    .encode();
                peers[0]
                    .sender
                    .send(Recipients::One(receiver_pk.clone()), leader_shard, true);

                // Contribute exactly minimum_shards total:
                // - invalid shard from peer1
                // - valid shard from peer2
                // - valid shard from peer4
                peers[1].sender.send(
                    Recipients::One(receiver_pk.clone()),
                    invalid_shard.encode(),
                    true,
                );
                for idx in [2usize, 4usize] {
                    let shard = coded_block1
                        .shard(peers[idx].index.get() as u16)
                        .expect("missing shard")
                        .encode();
                    peers[idx]
                        .sender
                        .send(Recipients::One(receiver_pk.clone()), shard, true);
                }

                context.sleep(config.link.latency * 2).await;

                // Invalid shard should be blocked, and reconstruction should not happen yet.
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

                // Send one additional valid shard; this should now satisfy checked threshold.
                let extra_shard = coded_block1
                    .shard(peers[5].index.get() as u16)
                    .expect("missing shard")
                    .encode();
                peers[5]
                    .sender
                    .send(Recipients::One(receiver_pk), extra_shard, true);

                context.sleep(config.link.latency * 2).await;

                let reconstructed = peers[receiver_idx]
                    .mailbox
                    .get(commitment1)
                    .await
                    .expect("block should reconstruct after additional valid shard");
                assert_eq!(reconstructed.commitment(), commitment1);
            },
        );
    }

    /// A pending shard left over from a reconstruction job replaces a shard that fails
    /// verification, without waiting for another shard to arrive.
    #[test_traced]
    fn test_surplus_pending_shard_replaces_invalid_shard() {
        let fixture: Fixture<C> = Fixture {
            num_primary_peers: 10,
            ..Default::default()
        };
        fixture.start(
            |config, context, oracle, mut peers, _, coding_config| async move {
                let block = CodedBlock::<B, C, H>::new(
                    B::new(Sha256Digest::EMPTY, Height::new(1), 100),
                    coding_config,
                    &STRATEGY,
                );
                let other = CodedBlock::<B, C, H>::new(
                    B::new(Sha256Digest::EMPTY, Height::new(2), 200),
                    coding_config,
                    &STRATEGY,
                );
                let commitment = block.commitment();
                let receiver = peers[3].public_key.clone();

                // Before discovery, peer 1 sends a shard of another block under this commitment
                // and peers 2, 4, 5, and 6 send the four valid shards the minimum needs.
                let mut invalid = other
                    .shard(peers[1].index.get() as u16)
                    .expect("missing shard");
                invalid.commitment = commitment;
                peers[1]
                    .sender
                    .send(Recipients::One(receiver.clone()), invalid.encode(), true);
                for sender in [2, 4, 5, 6] {
                    let shard = block
                        .shard(peers[sender].index.get() as u16)
                        .expect("missing shard");
                    peers[sender].sender.send(
                        Recipients::One(receiver.clone()),
                        shard.encode(),
                        true,
                    );
                }
                context.sleep(config.link.latency * 2).await;

                // Discovery ingests all five shards. The first job verifies four of them, finds
                // peer 1's shard invalid, and the leftover shard completes a second job.
                let mut subscription = peers[3].mailbox.subscribe(commitment);
                peers[3].mailbox.discovered(
                    commitment,
                    peers[0].public_key.clone(),
                    Round::new(Epoch::zero(), View::new(1)),
                );
                context.sleep(config.link.latency).await;
                let reconstructed = subscription.try_recv().expect("block reconstructed");
                assert_eq!(reconstructed.commitment(), commitment);
                assert_blocked(&oracle, &receiver, &peers[1].public_key).await;
            },
        );
    }

    #[test_traced]
    fn test_invalid_pending_shard_blocked_on_drain() {
        // Test that a shard buffered in pending shards (before checking data) is
        // blocked when batch validation runs at quorum and verification fails.
        let fixture: Fixture<C> = Fixture {
            num_primary_peers: 10,
            ..Default::default()
        };

        fixture.start(
            |config, context, oracle, mut peers, _, coding_config| async move {
                // Create two different blocks.
                let inner1 = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block1 = CodedBlock::<B, C, H>::new(inner1, coding_config, &STRATEGY);
                let commitment1 = coded_block1.commitment();

                let inner2 = B::new(Sha256Digest::EMPTY, Height::new(2), 200);
                let coded_block2 = CodedBlock::<B, C, H>::new(inner2, coding_config, &STRATEGY);

                // Get peer 1's shard from block2, but wrap with block1's commitment.
                let peer1_index = peers[1].index.get() as u16;
                let mut wrong_shard = coded_block2.shard(peer1_index).expect("missing shard");
                wrong_shard.commitment = commitment1;
                let wrong_bytes = wrong_shard.encode();

                let peer3_pk = peers[3].public_key.clone();

                // Send the invalid shard BEFORE the leader shard (no checking data yet,
                // so it gets buffered in pending shards).
                peers[1]
                    .sender
                    .send(Recipients::One(peer3_pk.clone()), wrong_bytes, true);
                context.sleep(config.link.latency * 2).await;

                // No one should be blocked yet (shard is buffered).
                let blocked = oracle.blocked().await.unwrap();
                assert!(blocked.is_empty(), "no peers should be blocked yet");

                // Send valid shards from peers 2 and 4 so the pending count
                // reaches quorum once the leader shard arrives
                // (minimum_shards = 4: 1 leader + 3 pending).
                for &idx in &[2, 4] {
                    let peer_index = peers[idx].index.get() as u16;
                    let shard = coded_block1.shard(peer_index).expect("missing shard");
                    let bytes = shard.encode();
                    peers[idx]
                        .sender
                        .send(Recipients::One(peer3_pk.clone()), bytes, true);
                }
                context.sleep(config.link.latency * 2).await;

                // No one should be blocked yet (all shards are buffered pending leader).
                let blocked = oracle.blocked().await.unwrap();
                assert!(blocked.is_empty(), "no peers should be blocked yet");

                // Now inform peer 3 of the leader and send the valid leader shard.
                let leader = peers[0].public_key.clone();
                peers[3].mailbox.discovered(
                    commitment1,
                    leader,
                    Round::new(Epoch::zero(), View::new(1)),
                );
                let peer3_index = peers[3].index.get() as u16;
                let leader_shard = coded_block1.shard(peer3_index).expect("missing shard");
                let shard_bytes = leader_shard.encode();
                peers[0]
                    .sender
                    .send(Recipients::One(peer3_pk), shard_bytes, true);
                context.sleep(config.link.latency * 2).await;

                // Peer 1 should be blocked after batch validation validates and
                // rejects their invalid shard.
                assert_blocked(&oracle, &peers[3].public_key, &peers[1].public_key).await;
            },
        );
    }

    #[test_traced]
    fn test_cross_epoch_buffered_shard_not_blocked() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (network, oracle) = simulated::Network::<deterministic::Context, P>::new(
                context.child("network"),
                simulated::Config {
                    max_size: MAX_SHARD_SIZE as u32,
                    max_peers_per_set: NZUsize!(2),
                    disconnect_on_block: true,
                    tracked_peer_sets: NZUsize!(1),
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
            oracle.manager().track(
                0,
                Set::from_iter_dedup([receiver_pk.clone(), future_peer_pk.clone()]),
            );
            context.sleep(Duration::from_millis(10)).await;

            // Set up the receiver's engine with a multi-epoch provider.
            let scheme_epoch0 =
                Scheme::signer(SCHEME_NAMESPACE, epoch0_set.clone(), receiver_key.clone())
                    .expect("signer scheme should be created");
            let scheme_epoch1 =
                Scheme::signer(SCHEME_NAMESPACE, epoch1_set.clone(), receiver_key.clone())
                    .expect("signer scheme should be created");
            let scheme_provider =
                MultiEpochProvider::single(scheme_epoch0).with_epoch(Epoch::new(1), scheme_epoch1);

            let config: Config<_, _, _, _, _, _> = Config {
                scheme_provider,
                blocker: receiver_control.clone(),
                max_block_size: MAX_BLOCK_SIZE,
                block_codec_cfg: (),
                strategy: STRATEGY,
                mailbox_size: NZUsize!(1024),
                peer_buffer_size: NZUsize!(64),
                records: NZUsize!(16),
                background_channel_capacity: NZUsize!(1024),
                peer_provider: oracle.manager(),
            };

            let (engine, mailbox) = ShardEngine::new(context.child("receiver"), config);
            engine.start((sender_handle, receiver_handle));

            // Build a coded block using epoch 1's participant set.
            let coding_config = coding_config_for_participants(epoch1_set.len() as u16);
            let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
            let coded_block = CodedBlock::<B, C, H>::new(inner, coding_config, &STRATEGY);
            let commitment = coded_block.commitment();

            // The future peer creates a shard at their epoch 1 index.
            let future_peer_index = epoch1_set
                .index(&future_peer_pk)
                .expect("future peer must be in epoch 1");
            let future_shard = coded_block
                .shard(future_peer_index.get() as u16)
                .expect("missing shard");
            let shard_bytes = future_shard.encode();

            // Send the shard BEFORE external_proposed (goes to pre-leader buffer).
            future_peer_sender.send(Recipients::One(receiver_pk.clone()), shard_bytes, true);
            context.sleep(DEFAULT_LINK.latency * 2).await;

            // No one should be blocked yet (shard is buffered, leader unknown).
            let blocked = oracle.blocked().await.unwrap();
            assert!(
                blocked.is_empty(),
                "no peers should be blocked while shard is buffered"
            );

            // Announce the leader with an epoch 1 round.
            let leader = epoch0_pks[1].clone();
            mailbox.discovered(commitment, leader, Round::new(Epoch::new(1), View::new(1)));
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
    fn test_shard_broadcast_survives_provider_churn() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (network, oracle) = simulated::Network::<deterministic::Context, P>::new(
                context.child("network"),
                simulated::Config {
                    max_size: MAX_SHARD_SIZE as u32,
                    max_peers_per_set: NZUsize!(4),
                    disconnect_on_block: true,
                    tracked_peer_sets: NZUsize!(1),
                },
            );
            network.start();

            let mut private_keys: Vec<PrivateKey> = (0..4).map(PrivateKey::from_seed).collect();
            private_keys.sort_by_key(|s| s.public_key());
            let peer_keys: Vec<P> = private_keys.iter().map(|k| k.public_key()).collect();
            let participants: Set<P> = Set::from_iter_dedup(peer_keys.clone());

            let leader_idx = 0usize;
            let broadcaster_idx = 1usize;
            let receiver_idx = 2usize;

            let leader_pk = peer_keys[leader_idx].clone();
            let broadcaster_pk = peer_keys[broadcaster_idx].clone();
            let receiver_pk = peer_keys[receiver_idx].clone();

            let mut registrations = BTreeMap::new();
            for key in &peer_keys {
                let control = oracle.control(key.clone());
                let (sender, receiver) = control
                    .register(0, TEST_QUOTA)
                    .await
                    .expect("registration should succeed");
                registrations.insert(key.clone(), (control, sender, receiver));
            }

            for src in &peer_keys {
                for dst in &peer_keys {
                    if src == dst {
                        continue;
                    }
                    oracle
                        .add_link(src.clone(), dst.clone(), DEFAULT_LINK)
                        .await
                        .expect("link should be added");
                }
            }
            oracle.manager().track(0, participants.clone());
            context.sleep(Duration::from_millis(10)).await;

            let (_leader_control, mut leader_sender, _leader_receiver) = registrations
                .remove(&leader_pk)
                .expect("leader should be registered");
            let (broadcaster_control, broadcaster_sender, broadcaster_receiver) = registrations
                .remove(&broadcaster_pk)
                .expect("broadcaster should be registered");
            let (receiver_control, receiver_sender, receiver_receiver) = registrations
                .remove(&receiver_pk)
                .expect("receiver should be registered");

            let broadcaster_scheme = Scheme::signer(
                SCHEME_NAMESPACE,
                participants.clone(),
                private_keys[broadcaster_idx].clone(),
            )
            .expect("signer scheme should be created");
            // `discovered` performs two scoped lookups (`handle_external_proposal`
            // and `ingest_buffered_shards`). Leader-shard validation is the third.
            // Any additional lookup for epoch 0 churns to `None`.
            let broadcaster_provider = ChurningProvider::new(broadcaster_scheme, 3);
            let broadcaster_config: Config<_, _, _, _, _, _> = Config {
                scheme_provider: broadcaster_provider,
                blocker: broadcaster_control.clone(),
                max_block_size: MAX_BLOCK_SIZE,
                block_codec_cfg: (),
                strategy: STRATEGY,
                mailbox_size: NZUsize!(1024),
                peer_buffer_size: NZUsize!(64),
                records: NZUsize!(16),
                background_channel_capacity: NZUsize!(1024),
                peer_provider: oracle.manager(),
            };
            let (broadcaster_engine, broadcaster_mailbox) =
                ChurningShardEngine::new(context.child("broadcaster"), broadcaster_config);
            broadcaster_engine.start((broadcaster_sender, broadcaster_receiver));

            let receiver_scheme = Scheme::signer(
                SCHEME_NAMESPACE,
                participants.clone(),
                private_keys[receiver_idx].clone(),
            )
            .expect("signer scheme should be created");
            let receiver_config: Config<_, _, _, _, _, _> = Config {
                scheme_provider: MultiEpochProvider::single(receiver_scheme),
                blocker: receiver_control.clone(),
                max_block_size: MAX_BLOCK_SIZE,
                block_codec_cfg: (),
                strategy: STRATEGY,
                mailbox_size: NZUsize!(1024),
                peer_buffer_size: NZUsize!(64),
                records: NZUsize!(16),
                background_channel_capacity: NZUsize!(1024),
                peer_provider: oracle.manager(),
            };
            let (receiver_engine, receiver_mailbox) =
                ShardEngine::new(context.child("receiver"), receiver_config);
            receiver_engine.start((receiver_sender, receiver_receiver));

            let coding_config = coding_config_for_participants(peer_keys.len() as u16);
            let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
            let coded_block = CodedBlock::<B, C, H>::new(inner, coding_config, &STRATEGY);
            let commitment = coded_block.commitment();
            let round = Round::new(Epoch::zero(), View::new(1));

            broadcaster_mailbox.discovered(commitment, leader_pk.clone(), round);
            receiver_mailbox.discovered(commitment, leader_pk.clone(), round);
            context.sleep(DEFAULT_LINK.latency).await;

            let broadcaster_index = participants
                .index(&broadcaster_pk)
                .expect("broadcaster must be a participant")
                .get() as u16;
            let broadcaster_shard = coded_block
                .shard(broadcaster_index)
                .expect("missing shard")
                .encode();
            leader_sender.send(Recipients::One(broadcaster_pk), broadcaster_shard, true);

            let receiver_index = participants
                .index(&receiver_pk)
                .expect("receiver must be a participant")
                .get() as u16;
            let receiver_shard = coded_block
                .shard(receiver_index)
                .expect("missing shard")
                .encode();
            leader_sender.send(Recipients::One(receiver_pk.clone()), receiver_shard, true);

            context.sleep(DEFAULT_LINK.latency * 3).await;

            let reconstructed = receiver_mailbox.get(commitment).await;
            assert!(
                reconstructed.is_some(),
                "receiver should reconstruct after broadcaster validates and broadcasts shard"
            );
        });
    }

    /// A reconstruction job runs on the strategy, so the engine keeps verifying assigned shards
    /// for other commitments while a decode is in flight.
    #[test_traced]
    fn test_reconstruction_job_does_not_stall_engine() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (network, oracle) = simulated::Network::<deterministic::Context, P>::new(
                context.child("network"),
                simulated::Config {
                    max_size: MAX_SHARD_SIZE as u32,
                    max_peers_per_set: NZUsize!(4),
                    disconnect_on_block: true,
                    tracked_peer_sets: NZUsize!(1),
                },
            );
            network.start();

            let mut private_keys: Vec<PrivateKey> = (0..4).map(PrivateKey::from_seed).collect();
            private_keys.sort_by_key(|s| s.public_key());
            let peer_keys: Vec<P> = private_keys.iter().map(|k| k.public_key()).collect();
            let participants: Set<P> = Set::from_iter_dedup(peer_keys.clone());
            let mut senders = Vec::new();
            let mut registrations = BTreeMap::new();
            for key in &peer_keys {
                let control = oracle.control(key.clone());
                let (sender, receiver) = control
                    .register(0, TEST_QUOTA)
                    .await
                    .expect("registration should succeed");
                senders.push(sender.clone());
                registrations.insert(key.clone(), (control, sender, receiver));
            }
            for src in &peer_keys {
                for dst in &peer_keys {
                    if src != dst {
                        oracle
                            .add_link(src.clone(), dst.clone(), DEFAULT_LINK)
                            .await
                            .expect("link should be added");
                    }
                }
            }
            oracle.manager().track(0, participants.clone());
            context.sleep(Duration::from_millis(10)).await;

            // Peer 2 runs its engine on a two-worker strategy.
            let receiver_pk = peer_keys[2].clone();
            let (control, sender, receiver) = registrations
                .remove(&receiver_pk)
                .expect("receiver should be registered");
            let scheme = Scheme::signer(
                SCHEME_NAMESPACE,
                participants.clone(),
                private_keys[2].clone(),
            )
            .expect("signer scheme should be created");
            let config: Config<_, _, _, _, _, _> = Config {
                scheme_provider: MultiEpochProvider::single(scheme),
                blocker: control,
                max_block_size: MAX_BLOCK_SIZE,
                block_codec_cfg: (),
                strategy: Rayon::new(NZUsize!(2)).unwrap(),
                mailbox_size: NZUsize!(1024),
                peer_buffer_size: NZUsize!(64),
                records: NZUsize!(16),
                background_channel_capacity: NZUsize!(1024),
                peer_provider: oracle.manager(),
            };
            let (engine, mailbox) =
                Engine::<_, _, _, _, Gated, H, B, P, _>::new(context.child("receiver"), config);
            engine.start((sender, receiver));

            let coding_config = coding_config_for_participants(peer_keys.len() as u16);
            let make_block = |id| {
                CodedBlock::<B, Gated, H>::new(
                    B::new(Sha256Digest::EMPTY, Height::new(id), id),
                    coding_config,
                    &STRATEGY,
                )
            };
            let leader = peer_keys[0].clone();
            let send = |senders: &mut Vec<NetworkSender>,
                        block: &CodedBlock<B, Gated, H>,
                        from: usize,
                        index: u16| {
                let shard = block.shard(index).expect("missing shard").encode();
                senders[from].send(Recipients::One(receiver_pk.clone()), shard, true);
            };

            // The leader delivers the receiver's shard of A and peer 1 gossips its own, which
            // starts a job whose decode holds.
            let (started_tx, started) = mpsc::channel();
            let (release, release_rx) = mpsc::channel();
            *GATE.lock() = Some(Gate {
                started: started_tx,
                release: release_rx,
                engine: thread::current().id(),
            });
            let a = make_block(1);
            mailbox.discovered(
                a.commitment(),
                leader.clone(),
                Round::new(Epoch::zero(), View::new(1)),
            );
            send(&mut senders, &a, 0, 2);
            send(&mut senders, &a, 1, 1);
            while started.try_recv().is_err() {
                reschedule().await;
            }

            // The engine verifies the receiver's shard of B while A's decode holds.
            let b = make_block(2);
            mailbox.discovered(
                b.commitment(),
                leader,
                Round::new(Epoch::zero(), View::new(2)),
            );
            let mut verified = mailbox.subscribe_assigned_shard_verified(b.commitment());
            send(&mut senders, &b, 0, 2);
            while verified.try_recv().is_err() {
                reschedule().await;
            }
            assert!(mailbox.get(a.commitment()).await.is_none());

            // Releasing the decode reconstructs A.
            release.send(()).unwrap();
            while mailbox.get(a.commitment()).await.is_none() {
                reschedule().await;
            }
            assert!(oracle.blocked().await.unwrap().is_empty());
        });
    }

    /// Evicting or caching a record aborts its reconstruction job, so a stale result never
    /// recreates, caches, or removes the record.
    #[test_traced]
    fn test_reconstruction_job_aborted_with_its_record() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (network, oracle) = simulated::Network::<deterministic::Context, P>::new(
                context.child("network"),
                simulated::Config {
                    max_size: MAX_SHARD_SIZE as u32,
                    max_peers_per_set: NZUsize!(4),
                    disconnect_on_block: true,
                    tracked_peer_sets: NZUsize!(1),
                },
            );
            network.start();

            let mut private_keys: Vec<PrivateKey> = (0..4).map(PrivateKey::from_seed).collect();
            private_keys.sort_by_key(|s| s.public_key());
            let peer_keys: Vec<P> = private_keys.iter().map(|k| k.public_key()).collect();
            let participants: Set<P> = Set::from_iter_dedup(peer_keys.clone());
            let scheme = Scheme::signer(
                SCHEME_NAMESPACE,
                participants.clone(),
                private_keys[0].clone(),
            )
            .expect("signer scheme should be created");
            let config: Config<_, _, _, _, _, _> = Config {
                scheme_provider: MultiEpochProvider::single(scheme.clone()),
                blocker: oracle.control(peer_keys[0].clone()),
                max_block_size: MAX_BLOCK_SIZE,
                block_codec_cfg: (),
                strategy: STRATEGY,
                mailbox_size: NZUsize!(16),
                peer_buffer_size: NZUsize!(4),
                records: NZUsize!(16),
                background_channel_capacity: NZUsize!(16),
                peer_provider: oracle.manager(),
            };
            let (mut engine, _mailbox) = ShardEngine::new(context.child("engine"), config);
            let coding_config = coding_config_for_participants(participants.len() as u16);
            let round = Round::new(Epoch::zero(), View::new(1));

            for (id, action) in ["evicted", "proposed"].into_iter().enumerate() {
                // Two own-index shards reach the minimum and start a job for the commitment.
                let block = CodedBlock::<B, C, H>::new(
                    B::new(Sha256Digest::EMPTY, Height::new(1), id as u64),
                    coding_config,
                    &STRATEGY,
                );
                let commitment = block.commitment();
                engine.insert_reconstruction_record(
                    commitment,
                    round,
                    ReconstructionState::new(Some(peer_keys[1].clone()), 4),
                );
                for index in [1, 2] {
                    let state = engine
                        .records
                        .get_mut(&commitment)
                        .and_then(CommitmentRecord::reconstruction_mut)
                        .expect("record must be reconstructing");
                    let shard = block.shard(index).expect("missing shard");
                    assert!(state.on_network_shard(
                        peer_keys[usize::from(index)].clone(),
                        shard,
                        &scheme,
                        &mut engine.blocker,
                    ));
                }
                engine.try_reconstruct(commitment);
                assert_eq!(engine.jobs.len(), 1, "{action}");

                // The record is evicted or cached before the job's result is applied.
                match action {
                    "evicted" => engine.evict(commitment),
                    "proposed" => {
                        engine
                            .cache_block(round, Arc::new(block))
                            .expect("proposal uses the record's epoch");
                    }
                    _ => unreachable!(),
                }

                // The job yields nothing, and the record keeps the state the action left.
                assert!(
                    matches!(engine.jobs.next_completed().now_or_never(), Some(Err(_))),
                    "{action}"
                );
                assert!(engine.jobs.is_empty(), "{action}");
                let record = engine.records.get(&commitment);
                if action == "proposed" {
                    assert!(record.and_then(CommitmentRecord::block).is_some());
                } else {
                    assert!(record.is_none(), "{action}");
                }
            }
        });
    }

    #[test_traced]
    fn test_failed_reconstruction_digest_mismatch_then_recovery() {
        // Byzantine scenario: all shards pass coding verification (correct root) but the
        // decoded blob has a different digest than what the commitment claims. This triggers
        // Error::DigestMismatch in the reconstruction job. Verify that:
        //   1. The failed commitment's state is cleaned up
        //   2. The exact commitment subscription closes
        //   3. The digest subscription survives the invalid candidate
        //   4. The valid commitment later reconstructs the claimed digest
        let fixture: Fixture<C> = Fixture {
            num_primary_peers: 10,
            ..Default::default()
        };

        fixture.start(
            |config, context, _oracle, mut peers, _, coding_config| async move {
                // Block 1: the "claimed" block (its digest goes in the fake commitment).
                let inner1 = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block1 = CodedBlock::<B, C, H>::new(inner1, coding_config, &STRATEGY);

                // Block 2: the actual data behind the shards.
                let inner2 = B::new(Sha256Digest::EMPTY, Height::new(2), 200);
                let coded_block2 = CodedBlock::<B, C, H>::new(inner2, coding_config, &STRATEGY);
                let real_commitment2 = coded_block2.commitment();

                // This is an invalid claim, not a second accepted commitment for block1.
                // Build it from block1's digest and block2's coding root/context/config.
                // Shards from block2 will verify against block2's root (present in the fake
                // commitment), but the reconstruction job will decode block2 and find its
                // digest != D1.
                let fake_commitment = Commitment::from((
                    coded_block1.digest(),
                    real_commitment2.root(),
                    real_commitment2.context(),
                    coding_config,
                ));

                let receiver_idx = 3usize;
                let receiver_pk = peers[receiver_idx].public_key.clone();
                let leader = peers[0].public_key.clone();
                let round = Round::new(Epoch::zero(), View::new(1));

                // Discover the fake commitment.
                peers[receiver_idx]
                    .mailbox
                    .discovered(fake_commitment, leader.clone(), round);

                // Open a block subscription before sending shards.
                let mut block_sub = peers[receiver_idx].mailbox.subscribe(fake_commitment);
                let mut digest_sub = peers[receiver_idx]
                    .mailbox
                    .subscribe_by_digest(coded_block1.digest());

                // Send the receiver's shard (from block2, with fake commitment).
                let receiver_shard_idx = peers[receiver_idx].index.get() as u16;
                let mut leader_shard = coded_block2
                    .shard(receiver_shard_idx)
                    .expect("missing shard");
                leader_shard.commitment = fake_commitment;
                peers[0].sender.send(
                    Recipients::One(receiver_pk.clone()),
                    leader_shard.encode(),
                    true,
                );

                // Send enough shards to reach minimum_shards (4 for 10 peers).
                // Need 3 more shards after the leader's shard.
                for &idx in &[1usize, 2, 4] {
                    let peer_shard_idx = peers[idx].index.get() as u16;
                    let mut shard = coded_block2.shard(peer_shard_idx).expect("missing shard");
                    shard.commitment = fake_commitment;
                    peers[idx].sender.send(
                        Recipients::One(receiver_pk.clone()),
                        shard.encode(),
                        true,
                    );
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

                // Commitment validity governs the exact-commitment subscription.
                // The digest subscription accepts another valid commitment.
                assert!(
                    matches!(block_sub.try_recv(), Err(TryRecvError::Closed)),
                    "subscription should close for failed reconstruction"
                );
                assert!(
                    matches!(digest_sub.try_recv(), Err(TryRecvError::Empty)),
                    "digest subscription should survive failed reconstruction"
                );
                // Now verify the engine is not stuck: send valid shards for block1's real
                // commitment and confirm reconstruction succeeds.
                let real_commitment1 = coded_block1.commitment();
                let round2 = Round::new(Epoch::zero(), View::new(2));
                peers[receiver_idx]
                    .mailbox
                    .discovered(real_commitment1, leader.clone(), round2);

                let leader_shard1 = coded_block1
                    .shard(receiver_shard_idx)
                    .expect("missing shard");
                peers[0].sender.send(
                    Recipients::One(receiver_pk.clone()),
                    leader_shard1.encode(),
                    true,
                );

                for &idx in &[1usize, 2, 4] {
                    let peer_shard_idx = peers[idx].index.get() as u16;
                    let shard = coded_block1.shard(peer_shard_idx).expect("missing shard");
                    peers[idx].sender.send(
                        Recipients::One(receiver_pk.clone()),
                        shard.encode(),
                        true,
                    );
                }

                context.sleep(config.link.latency * 2).await;

                let reconstructed = peers[receiver_idx]
                    .mailbox
                    .get(real_commitment1)
                    .await
                    .expect("valid block should reconstruct after prior failure");
                assert_eq!(reconstructed.commitment(), real_commitment1);
                let by_digest = digest_sub
                    .await
                    .expect("valid commitment should satisfy digest subscription");
                assert_eq!(by_digest.commitment(), real_commitment1);
            },
        );
    }

    #[test_traced]
    fn test_failed_reconstruction_context_mismatch_then_recovery() {
        // Byzantine scenario: shards decode to a block whose digest and coding root/config
        // match the commitment, but the commitment carries a mismatched context digest.
        // The engine must reject reconstruction and keep the commitment unresolved.
        let fixture: Fixture<C> = Fixture {
            num_primary_peers: 10,
            ..Default::default()
        };

        fixture.start(
            |config, context, _oracle, mut peers, _, coding_config| async move {
                let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block = CodedBlock::<B, C, H>::new(inner, coding_config, &STRATEGY);
                let real_commitment = coded_block.commitment();

                let wrong_context_digest = Sha256::hash(&[b"wrong_context"]);
                assert_ne!(
                    real_commitment.context(),
                    wrong_context_digest,
                    "test requires a distinct context digest"
                );
                let fake_commitment = Commitment::from((
                    coded_block.digest(),
                    real_commitment.root(),
                    wrong_context_digest,
                    coding_config,
                ));

                let receiver_idx = 3usize;
                let receiver_pk = peers[receiver_idx].public_key.clone();
                let leader = peers[0].public_key.clone();
                let round = Round::new(Epoch::zero(), View::new(1));

                peers[receiver_idx]
                    .mailbox
                    .discovered(fake_commitment, leader.clone(), round);
                let mut block_sub = peers[receiver_idx].mailbox.subscribe(fake_commitment);

                let receiver_shard_idx = peers[receiver_idx].index.get() as u16;
                let mut leader_shard = coded_block
                    .shard(receiver_shard_idx)
                    .expect("missing shard");
                leader_shard.commitment = fake_commitment;
                peers[0].sender.send(
                    Recipients::One(receiver_pk.clone()),
                    leader_shard.encode(),
                    true,
                );

                for &idx in &[1usize, 2, 4] {
                    let peer_shard_idx = peers[idx].index.get() as u16;
                    let mut shard = coded_block.shard(peer_shard_idx).expect("missing shard");
                    shard.commitment = fake_commitment;
                    peers[idx].sender.send(
                        Recipients::One(receiver_pk.clone()),
                        shard.encode(),
                        true,
                    );
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
                    .discovered(real_commitment, leader.clone(), round2);

                let real_leader_shard = coded_block
                    .shard(receiver_shard_idx)
                    .expect("missing shard");
                peers[0].sender.send(
                    Recipients::One(receiver_pk.clone()),
                    real_leader_shard.encode(),
                    true,
                );

                for &idx in &[1usize, 2, 4] {
                    let peer_shard_idx = peers[idx].index.get() as u16;
                    let shard = coded_block.shard(peer_shard_idx).expect("missing shard");
                    peers[idx].sender.send(
                        Recipients::One(receiver_pk.clone()),
                        shard.encode(),
                        true,
                    );
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
        // - the leader must not be blocked (a leader that crashes after its
        //   broadcast but before its local persist legitimately re-proposes
        //   a different block for the same round after restart)
        let fixture: Fixture<C> = Fixture {
            num_primary_peers: 10,
            ..Default::default()
        };

        fixture.start(
            |config, context, oracle, mut peers, _, coding_config| async move {
                let receiver_idx = 3usize;
                let receiver_pk = peers[receiver_idx].public_key.clone();
                let receiver_shard_idx = peers[receiver_idx].index.get() as u16;

                let leader = peers[0].public_key.clone();
                let round = Round::new(Epoch::zero(), View::new(7));

                // Two different commitments in the same round (equivocation scenario).
                let block_a = CodedBlock::<B, C, H>::new(
                    B::new(Sha256Digest::EMPTY, Height::new(1), 111),
                    coding_config,
                    &STRATEGY,
                );
                let commitment_a = block_a.commitment();
                let block_b = CodedBlock::<B, C, H>::new(
                    B::new(Sha256Digest::EMPTY, Height::new(1), 222),
                    coding_config,
                    &STRATEGY,
                );
                let commitment_b = block_b.commitment();

                // Receiver learns both commitments in the same round.
                peers[receiver_idx]
                    .mailbox
                    .discovered(commitment_a, leader.clone(), round);
                peers[receiver_idx]
                    .mailbox
                    .discovered(commitment_b, leader.clone(), round);

                // Subscribe to the certifiable commitment before any reconstruction.
                let certifiable_sub = peers[receiver_idx].mailbox.subscribe(commitment_b);

                // We receive our shard for commitment B from the equivocating leader.
                let shard_b = block_b
                    .shard(receiver_shard_idx)
                    .expect("missing shard")
                    .encode();
                peers[0]
                    .sender
                    .send(Recipients::One(receiver_pk.clone()), shard_b, true);

                // Reconstruct conflicting commitment A first.
                let shard_a = block_a
                    .shard(receiver_shard_idx)
                    .expect("missing shard")
                    .encode();
                peers[0]
                    .sender
                    .send(Recipients::One(receiver_pk.clone()), shard_a, true);
                for i in [1usize, 2usize, 4usize] {
                    let shard_a = block_a
                        .shard(peers[i].index.get() as u16)
                        .expect("missing shard")
                        .encode();
                    peers[i]
                        .sender
                        .send(Recipients::One(receiver_pk.clone()), shard_a, true);
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
                    let shard_b = block_b
                        .shard(peers[i].index.get() as u16)
                        .expect("missing shard")
                        .encode();
                    peers[i]
                        .sender
                        .send(Recipients::One(receiver_pk.clone()), shard_b, true);
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

                // Cross-commitment equivocation within a round is tolerated,
                // so the leader must not be blocked.
                let blocked_peers = oracle.blocked().await.unwrap();
                let is_blocked = blocked_peers
                    .iter()
                    .any(|(a, b)| a == &receiver_pk && b == &leader);
                assert!(
                    !is_blocked,
                    "leader must not be blocked for same-round cross-commitment shards"
                );
            },
        );
    }

    #[test_traced]
    fn test_leader_unrelated_shard_blocks_peer() {
        // Regression test: if the leader sends an unrelated/invalid shard
        // (i.e. a shard for a different participant index), the receiver must
        // block the leader.
        let fixture: Fixture<C> = Fixture {
            num_primary_peers: 10,
            ..Default::default()
        };

        fixture.start(
            |config, context, oracle, mut peers, _, coding_config| async move {
                // Commitment being tracked by the receiver.
                let tracked_block = CodedBlock::<B, C, H>::new(
                    B::new(Sha256Digest::EMPTY, Height::new(1), 100),
                    coding_config,
                    &STRATEGY,
                );
                let tracked_commitment = tracked_block.commitment();

                // Separate block used to source "unrelated" shard data.
                let unrelated_block = CodedBlock::<B, C, H>::new(
                    B::new(Sha256Digest::EMPTY, Height::new(2), 200),
                    coding_config,
                    &STRATEGY,
                );

                let receiver_idx = 3usize;
                let receiver_pk = peers[receiver_idx].public_key.clone();
                let leader_idx = 0usize;
                let leader_pk = peers[leader_idx].public_key.clone();

                // Receiver tracks the commitment with peer0 as leader.
                peers[receiver_idx].mailbox.discovered(
                    tracked_commitment,
                    leader_pk.clone(),
                    Round::new(Epoch::zero(), View::new(1)),
                );

                // Construct an unrelated shard from peer1's slot and retarget
                // its commitment to the tracked commitment so it hits active state.
                let mut unrelated_shard = unrelated_block
                    .shard(peers[1].index.get() as u16)
                    .expect("missing shard");
                unrelated_shard.commitment = tracked_commitment;

                // Leader sends this unrelated/invalid shard to receiver.
                // The shard index no longer matches sender's participant index,
                // so leader must be blocked.
                peers[leader_idx].sender.send(
                    Recipients::One(receiver_pk),
                    unrelated_shard.encode(),
                    true,
                );
                context.sleep(config.link.latency * 2).await;

                assert_blocked(&oracle, &peers[receiver_idx].public_key, &leader_pk).await;
            },
        );
    }

    #[test_traced]
    fn test_withholding_leader_victim_reconstructs_via_gossip() {
        // A Byzantine leader withholds the shard destined for one participant.
        // That participant should still reconstruct the block from shards
        // gossiped by other participants (sent via Recipients::All) without
        // any backfill mechanism.
        let fixture = Fixture {
            num_primary_peers: 10,
            ..Default::default()
        };

        fixture.start(
            |config, context, oracle, mut peers, _, coding_config| async move {
                let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block = CodedBlock::<B, C, H>::new(inner, coding_config, &STRATEGY);
                let commitment = coded_block.commitment();
                let round = Round::new(Epoch::zero(), View::new(1));

                let leader = peers[0].public_key.clone();
                let victim = peers[1].public_key.clone();

                // Sever the link from leader to victim so the leader's
                // direct shard never arrives.
                oracle
                    .remove_link(leader.clone(), victim.clone())
                    .await
                    .expect("remove_link should succeed");

                // Leader proposes. The victim will not receive a direct shard
                // because the link is severed.
                peers[0].mailbox.proposed(round, coded_block.clone());

                // Inform all non-leader peers of the leader so they validate
                // and re-broadcast their shards via Recipients::All.
                for peer in peers[1..].iter_mut() {
                    peer.mailbox.discovered(commitment, leader.clone(), round);
                }
                context.sleep(config.link.latency * 2).await;

                // The victim should reconstruct via gossiped shards from other
                // participants even though the leader withheld.
                let block_sub = peers[1].mailbox.subscribe(commitment);
                select! {
                    result = block_sub => {
                        let reconstructed = result.expect("block subscription should resolve");
                        assert_eq!(reconstructed.commitment(), commitment);
                        assert_eq!(reconstructed.height(), coded_block.height());
                    },
                    _ = context.sleep(Duration::from_secs(5)) => {
                        panic!("victim did not reconstruct block despite withholding leader");
                    },
                }

                // All other participants should also have reconstructed.
                for peer in peers[2..].iter_mut() {
                    let reconstructed = peer
                        .mailbox
                        .get(commitment)
                        .await
                        .expect("block should be reconstructed");
                    assert_eq!(reconstructed.commitment(), commitment);
                }

                // No peer should be blocked — withholding is not detectable.
                let blocked = oracle.blocked().await.unwrap();
                assert!(
                    blocked.is_empty(),
                    "no peer should be blocked in withholding leader test"
                );
            },
        );
    }

    /// When the leader withholds its shard from a participant, the block
    /// can still be reconstructed from gossipped shards. However, the shard
    /// subscription must NOT resolve because the participant's own shard was
    /// never verified. Voting requires own-shard verification to ensure the
    /// participant re-broadcasts its shard and helps slower peers reach quorum.
    #[test_traced]
    fn test_shard_subscription_pending_after_reconstruction_without_leader_shard() {
        let fixture = Fixture {
            num_primary_peers: 10,
            ..Default::default()
        };

        fixture.start(
            |config, context, oracle, mut peers, _, coding_config| async move {
                let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block = CodedBlock::<B, C, H>::new(inner, coding_config, &STRATEGY);
                let commitment = coded_block.commitment();
                let round = Round::new(Epoch::zero(), View::new(1));

                let leader = peers[0].public_key.clone();
                let victim = peers[1].public_key.clone();

                // Remove the link from leader to victim so the leader's shard
                // never reaches the victim directly.
                oracle
                    .remove_link(leader.clone(), victim.clone())
                    .await
                    .expect("remove_link should succeed");

                // Subscribe to the shard and block BEFORE any broadcasting.
                let mut shard_sub = peers[1]
                    .mailbox
                    .subscribe_assigned_shard_verified(commitment);
                let block_sub = peers[1].mailbox.subscribe(commitment);

                // Leader broadcasts.
                peers[0].mailbox.proposed(round, coded_block.clone());

                // All non-leader peers discover the leader.
                for peer in peers[1..].iter_mut() {
                    peer.mailbox.discovered(commitment, leader.clone(), round);
                }

                // Wait for gossip to propagate.
                context.sleep(config.link.latency * 4).await;

                // Block subscription should resolve (victim reconstructs from
                // gossipped shards).
                let reconstructed = block_sub.await.expect("block subscription should resolve");
                assert_eq!(reconstructed.commitment(), commitment);

                let mut late_shard_sub = peers[1]
                    .mailbox
                    .subscribe_assigned_shard_verified(commitment);
                context.sleep(Duration::from_millis(10)).await;

                // Neither an existing nor a late shard subscription may resolve because
                // the leader never sent the victim its own shard.
                assert!(
                    matches!(shard_sub.try_recv(), Err(TryRecvError::Empty)),
                    "shard subscription must not resolve without own shard verification"
                );
                assert!(
                    matches!(late_shard_sub.try_recv(), Err(TryRecvError::Empty)),
                    "late shard subscription must not resolve from reconstruction alone"
                );
            },
        );
    }

    #[test_traced]
    fn test_broadcast_routes_participant_and_non_participant_shards() {
        let fixture = Fixture {
            num_secondary_peers: 1,
            ..Default::default()
        };

        fixture.start(
            |config, context, oracle, mut peers, non_participants, coding_config| async move {
                let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block = CodedBlock::<B, C, H>::new(inner, coding_config, &STRATEGY);
                let commitment = coded_block.commitment();

                let leader = peers[0].public_key.clone();
                let round = Round::new(Epoch::zero(), View::new(1));
                peers[0].mailbox.proposed(round, coded_block.clone());

                for peer in peers[1..].iter_mut() {
                    peer.mailbox.discovered(commitment, leader.clone(), round);
                }
                for np in non_participants.iter() {
                    np.mailbox.discovered(commitment, leader.clone(), round);
                }
                context.sleep(config.link.latency * 2).await;

                // Participants should receive and validate their own shards.
                for peer in peers.iter_mut() {
                    peer.mailbox
                        .subscribe_assigned_shard_verified(commitment)
                        .await
                        .expect("participant shard subscription should complete");
                }

                // Non-participant should receive and validate the leader's shard.
                for np in non_participants.iter() {
                    np.mailbox
                        .subscribe_assigned_shard_verified(commitment)
                        .await
                        .expect("non-participant shard subscription should complete");
                }
                context.sleep(config.link.latency).await;

                // Non-participant should reconstruct the block from received shards.
                for np in non_participants.iter() {
                    let reconstructed = np
                        .mailbox
                        .get(commitment)
                        .await
                        .expect("non-participant should reconstruct block");
                    assert_eq!(reconstructed.commitment(), commitment);
                }

                let blocked = oracle.blocked().await.unwrap();
                assert!(
                    blocked.is_empty(),
                    "no peer should be blocked in participant/non-participant shard routing test"
                );
            },
        );
    }

    #[test_traced]
    fn test_non_participant_reconstructs_after_discovered() {
        let fixture = Fixture {
            num_secondary_peers: 1,
            ..Default::default()
        };

        fixture.start(
            |config, context, oracle, mut peers, non_participants, coding_config| async move {
                let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block = CodedBlock::<B, C, H>::new(inner, coding_config, &STRATEGY);
                let commitment = coded_block.commitment();
                let round = Round::new(Epoch::zero(), View::new(1));

                let leader = peers[0].public_key.clone();
                peers[0].mailbox.proposed(round, coded_block.clone());

                // Inform participants of the leader so they validate and re-broadcast
                // shards.
                for peer in peers[1..].iter_mut() {
                    peer.mailbox.discovered(commitment, leader.clone(), round);
                }
                context.sleep(config.link.latency).await;

                // Non-participant discovers the leader after shards are already
                // propagating through the network.
                let np = &non_participants[0];
                let block_sub = np.mailbox.subscribe(commitment);
                np.mailbox.discovered(commitment, leader.clone(), round);

                // Wait for enough shards (leader's shard + shards from
                // participants) to arrive and reconstruct.
                select! {
                    result = block_sub => {
                        let reconstructed = result.expect("block subscription should resolve");
                        assert_eq!(reconstructed.commitment(), commitment);
                        assert_eq!(reconstructed.height(), coded_block.height());
                    },
                    _ = context.sleep(Duration::from_secs(5)) => {
                        panic!("non-participant block subscription did not resolve");
                    },
                }

                let blocked = oracle.blocked().await.unwrap();
                assert!(
                    blocked.is_empty(),
                    "no peer should be blocked in non-participant reconstruction test"
                );
            },
        );
    }

    #[test_traced]
    fn test_peer_set_update_evicts_peer_buffers() {
        // Shards buffered before leader announcement should be evicted when
        // the sender leaves latest.primary. Even if the overlap window keeps
        // the sender connected, fresh pre-leader shards from that peer must
        // not recreate the buffer.
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let num_peers = 10usize;
            let (network, oracle) = simulated::Network::<deterministic::Context, P>::new(
                context.child("network"),
                simulated::Config {
                    max_size: MAX_SHARD_SIZE as u32,
                    max_peers_per_set: NZUsize!(num_peers),
                    disconnect_on_block: true,
                    tracked_peer_sets: NZUsize!(2),
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

            // Track the full participant set so the engine sees all peers.
            oracle.manager().track(0, participants.clone());
            context.sleep(Duration::from_millis(10)).await;

            let scheme = Scheme::signer(
                SCHEME_NAMESPACE,
                participants.clone(),
                private_keys[receiver_idx].clone(),
            )
            .expect("signer scheme should be created");

            let config: Config<_, _, _, _, _, _> = Config {
                scheme_provider: MultiEpochProvider::single(scheme),
                blocker: receiver_control.clone(),
                max_block_size: MAX_BLOCK_SIZE,
                block_codec_cfg: (),
                strategy: STRATEGY,
                mailbox_size: NZUsize!(1024),
                peer_buffer_size: NZUsize!(64),
                records: NZUsize!(16),
                background_channel_capacity: NZUsize!(1024),
                peer_provider: oracle.manager(),
            };

            let (engine, mailbox) = ShardEngine::new(context.child("receiver"), config);
            engine.start((sender_handle, receiver_handle));

            // Build a coded block and extract the shard destined for the receiver.
            let coding_config = coding_config_for_participants(num_peers as u16);
            let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
            let coded_block = CodedBlock::<B, C, H>::new(inner, coding_config, &STRATEGY);
            let commitment = coded_block.commitment();

            let receiver_participant = participants
                .index(&receiver_pk)
                .expect("receiver must be a participant");
            let leader_shard = coded_block
                .shard(receiver_participant.get() as u16)
                .expect("missing shard");
            let shard_bytes = leader_shard.encode();

            // Send the shard BEFORE leader announcement (it gets buffered).
            leader_sender.send(
                Recipients::One(receiver_pk.clone()),
                shard_bytes.clone(),
                true,
            );
            context.sleep(DEFAULT_LINK.latency * 2).await;

            // Now send a peer set update that excludes the leader.
            let remaining: Set<P> =
                Set::from_iter_dedup(peer_keys.iter().filter(|pk| **pk != leader_pk).cloned());
            oracle.manager().track(1, remaining);
            context.sleep(Duration::from_millis(10)).await;

            // The retained overlap window still lets the leader reach the receiver,
            // but this fresh pre-leader shard must not be buffered again.
            leader_sender.send(Recipients::One(receiver_pk.clone()), shard_bytes, true);
            context.sleep(DEFAULT_LINK.latency * 2).await;

            // Announce the leader. Buffered shards from the leader should have been
            // evicted, so the shard will NOT be ingested.
            let mut shard_sub = mailbox.subscribe_assigned_shard_verified(commitment);
            mailbox.discovered(
                commitment,
                leader_pk.clone(),
                Round::new(Epoch::zero(), View::new(1)),
            );
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

    #[test_traced]
    fn test_peer_buffer_lifetime_tracks_latest_primary() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (network, oracle) = simulated::Network::<deterministic::Context, P>::new(
                context.child("network"),
                simulated::Config {
                    max_size: MAX_SHARD_SIZE as u32,
                    max_peers_per_set: NZUsize!(1),
                    disconnect_on_block: true,
                    tracked_peer_sets: NZUsize!(1),
                },
            );
            network.start();

            let mut private_keys = (0..4)
                .map(|i| PrivateKey::from_seed(i as u64))
                .collect::<Vec<_>>();
            private_keys.sort_by_key(|s| s.public_key());
            let peer_keys: Vec<P> = private_keys.iter().map(|c| c.public_key()).collect();
            let receiver_pk = peer_keys[0].clone();
            let sender_pk = peer_keys[1].clone();
            let participants: Set<P> = Set::from_iter_dedup(peer_keys);

            let receiver_control = oracle.control(receiver_pk);
            let scheme = Scheme::signer(
                SCHEME_NAMESPACE,
                participants.clone(),
                private_keys[0].clone(),
            )
            .expect("signer scheme should be created");

            let config: Config<_, _, _, _, _, _> = Config {
                scheme_provider: MultiEpochProvider::single(scheme),
                blocker: receiver_control,
                max_block_size: MAX_BLOCK_SIZE,
                block_codec_cfg: (),
                strategy: STRATEGY,
                mailbox_size: NZUsize!(16),
                peer_buffer_size: NZUsize!(4),
                records: NZUsize!(16),
                background_channel_capacity: NZUsize!(16),
                peer_provider: oracle.manager(),
            };

            let (mut engine, _mailbox) = ShardEngine::new(context.child("engine"), config);

            // Only `sender_pk` is in `latest.primary`, so only that peer may retain a pre-leader
            // buffer row (`buffer_peer_shard` / `peer_buffers`).
            engine.update_latest_primary_peers(Set::from_iter_dedup([sender_pk.clone()]));

            let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
            let coded_block = CodedBlock::<B, C, H>::new(
                inner,
                coding_config_for_participants(participants.len() as u16),
                &STRATEGY,
            );
            let shard = coded_block.shard(0).expect("missing shard");

            // Pre-leader path: buffer one shard before any leader or notarized interest arrives.
            engine.buffer_peer_shard(sender_pk.clone(), shard);
            assert_eq!(
                engine.peer_buffers.get(&sender_pk).map(VecDeque::len),
                Some(1),
                "peer buffer should contain the buffered shard"
            );

            // Empty primary: no peer may retain buffers; `update_latest_primary_peers` drops the
            // staged shard and the deque entry for `sender_pk`.
            engine.update_latest_primary_peers(Set::default());
            assert!(
                !engine.peer_buffers.contains_key(&sender_pk),
                "peer buffer should be evicted once sender leaves latest.primary"
            );
        });
    }

    #[test_traced]
    fn test_old_epoch_buffered_shards_are_dropped_after_cutover() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let num_peers = 6usize;
            let (network, oracle) = simulated::Network::<deterministic::Context, P>::new(
                context.child("network"),
                simulated::Config {
                    max_size: MAX_SHARD_SIZE as u32,
                    max_peers_per_set: NZUsize!(num_peers - 1),
                    disconnect_on_block: true,
                    tracked_peer_sets: NZUsize!(2),
                },
            );
            network.start();

            let mut private_keys = (0..num_peers)
                .map(|i| PrivateKey::from_seed(i as u64))
                .collect::<Vec<_>>();
            private_keys.sort_by_key(|s| s.public_key());
            let peer_keys: Vec<P> = private_keys.iter().map(|c| c.public_key()).collect();

            // Epoch 0: first five peers. Epoch 1: swap out `peer_keys[0]` for `peer_keys[5]` so the
            // cutover changes who is in `latest.primary` while `tracked_peer_sets` retains overlap.
            let epoch0_set: Set<P> = Set::from_iter_dedup(peer_keys[..5].iter().cloned());
            let epoch1_set: Set<P> = Set::from_iter_dedup([
                peer_keys[1].clone(),
                peer_keys[2].clone(),
                peer_keys[3].clone(),
                peer_keys[4].clone(),
                peer_keys[5].clone(),
            ]);

            let receiver_idx = 3usize;
            let receiver_pk = peer_keys[receiver_idx].clone();
            let receiver_key = private_keys[receiver_idx].clone();
            let leader_pk = peer_keys[0].clone();

            let receiver_control = oracle.control(receiver_pk.clone());
            let (sender_handle, receiver_handle) = receiver_control
                .register(0, TEST_QUOTA)
                .await
                .expect("registration should succeed");

            let leader_control = oracle.control(leader_pk.clone());
            let (mut leader_sender, _leader_receiver) = leader_control
                .register(0, TEST_QUOTA)
                .await
                .expect("registration should succeed");
            oracle
                .add_link(leader_pk.clone(), receiver_pk.clone(), DEFAULT_LINK)
                .await
                .expect("link should be added");

            // Peer-set id 0: epoch 0 primaries before any cutover.
            oracle.manager().track(0, epoch0_set.clone());
            context.sleep(Duration::from_millis(10)).await;

            let scheme_epoch0 =
                Scheme::signer(SCHEME_NAMESPACE, epoch0_set.clone(), receiver_key.clone())
                    .expect("epoch 0 signer scheme should be created");
            let scheme_epoch1 =
                Scheme::signer(SCHEME_NAMESPACE, epoch1_set.clone(), receiver_key.clone())
                    .expect("epoch 1 signer scheme should be created");

            let config: Config<_, _, _, _, _, _> = Config {
                scheme_provider: MultiEpochProvider::single(scheme_epoch0)
                    .with_epoch(Epoch::new(1), scheme_epoch1),
                blocker: receiver_control.clone(),
                max_block_size: MAX_BLOCK_SIZE,
                block_codec_cfg: (),
                strategy: STRATEGY,
                mailbox_size: NZUsize!(1024),
                peer_buffer_size: NZUsize!(64),
                records: NZUsize!(16),
                background_channel_capacity: NZUsize!(1024),
                peer_provider: oracle.manager(),
            };

            // Receiver engine: schemes for both epochs so post-cutover validation can run if needed.
            let (engine, mailbox) = ShardEngine::new(context.child("receiver"), config);
            engine.start((sender_handle, receiver_handle));

            let coding_config = coding_config_for_participants(epoch0_set.len() as u16);
            let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
            let coded_block = CodedBlock::<B, C, H>::new(inner, coding_config, &STRATEGY);
            let commitment = coded_block.commitment();

            let receiver_participant = epoch0_set
                .index(&receiver_pk)
                .expect("receiver must be an epoch 0 participant");
            let leader_shard = coded_block
                .shard(receiver_participant.get() as u16)
                .expect("missing shard");

            // Inbound: epoch-0 leader shard arrives before `Discovered` (pre-leader buffer path).
            leader_sender.send(
                Recipients::One(receiver_pk.clone()),
                leader_shard.encode(),
                true,
            );
            context.sleep(DEFAULT_LINK.latency * 2).await;

            // Cutover to epoch 1 primaries before `Discovered`: `leader_pk` (epoch-0-only) is no
            // longer in `latest.primary`, so overlap-buffered shards for that sender must not feed
            // reconstruction.
            oracle.manager().track(1, epoch1_set);
            context.sleep(Duration::from_millis(10)).await;

            // Leader announcement for the old commitment: should not complete reconstruction from
            // dropped pre-cutover buffers.
            let mut shard_sub = mailbox.subscribe_assigned_shard_verified(commitment);
            mailbox.discovered(
                commitment,
                leader_pk,
                Round::new(Epoch::zero(), View::new(1)),
            );
            context.sleep(DEFAULT_LINK.latency * 2).await;

            assert!(
                matches!(shard_sub.try_recv(), Err(TryRecvError::Empty)),
                "old-epoch shard subscription should stay pending after cutover"
            );
            assert!(
                mailbox.get(commitment).await.is_none(),
                "old-epoch commitment should not reconstruct from overlap-only buffered shards"
            );
        });
    }

    /// If the evicted node leaves the
    /// [`commonware_p2p::PeerSetUpdate::latest`] primary set, it must still
    /// reconstruct once the leader is discovered, as long as enough buffered
    /// shards came from peers that remain in `latest.primary`.
    ///
    /// This does not rely on a self-buffered shard or a leader-delivered shard:
    /// reconstruction should succeed from the remaining buffered peer shards
    /// alone.
    #[test_traced]
    fn test_evicted_node_still_reconstructs_from_buffered_peer_shards() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let num_peers = 10usize;
            let (network, oracle) = simulated::Network::<deterministic::Context, P>::new(
                context.child("network"),
                simulated::Config {
                    max_size: MAX_SHARD_SIZE as u32,
                    max_peers_per_set: NZUsize!(num_peers),
                    disconnect_on_block: true,
                    tracked_peer_sets: NZUsize!(2),
                },
            );
            network.start();

            let mut private_keys = (0..num_peers)
                .map(|i| PrivateKey::from_seed(i as u64))
                .collect::<Vec<_>>();
            private_keys.sort_by_key(|s| s.public_key());
            let peer_keys: Vec<P> = private_keys.iter().map(|c| c.public_key()).collect();
            let participants: Set<P> = Set::from_iter_dedup(peer_keys.clone());

            // Receiver (`peer_keys[1]`) is evicted from `latest.primary` after shards are buffered.
            // The leader (`peer_keys[0]`) has no link to the receiver, so reconstruction cannot use a
            // leader-delivered shard or a self-buffered shard; it must use gossip from peers 2/4/5/6 only.
            let receiver_idx = 1usize;
            let receiver_pk = peer_keys[receiver_idx].clone();
            let leader_pk = peer_keys[0].clone();
            let peer2_pk = peer_keys[2].clone();
            let peer4_pk = peer_keys[4].clone();
            let peer5_pk = peer_keys[5].clone();
            let peer6_pk = peer_keys[6].clone();

            let receiver_control = oracle.control(receiver_pk.clone());
            let (evicted_sender, evicted_receiver) = receiver_control
                .register(0, TEST_QUOTA)
                .await
                .expect("registration should succeed");

            let peer2_control = oracle.control(peer2_pk.clone());
            let (mut peer2_sender, _peer2_receiver) = peer2_control
                .register(0, TEST_QUOTA)
                .await
                .expect("registration should succeed");

            let peer4_control = oracle.control(peer4_pk.clone());
            let (mut peer4_sender, _peer4_receiver) = peer4_control
                .register(0, TEST_QUOTA)
                .await
                .expect("registration should succeed");

            let peer5_control = oracle.control(peer5_pk.clone());
            let (mut peer5_sender, _peer5_receiver) = peer5_control
                .register(0, TEST_QUOTA)
                .await
                .expect("registration should succeed");

            let peer6_control = oracle.control(peer6_pk.clone());
            let (mut peer6_sender, _peer6_receiver) = peer6_control
                .register(0, TEST_QUOTA)
                .await
                .expect("registration should succeed");

            // Only secondary peers that will forward shards are connected to the receiver (not the leader).
            for sender in [&peer2_pk, &peer4_pk, &peer5_pk, &peer6_pk] {
                oracle
                    .add_link(sender.clone(), receiver_pk.clone(), DEFAULT_LINK)
                    .await
                    .expect("link should be added");
            }

            // Start with the full committee so the receiver's signer scheme matches the coded block.
            oracle.manager().track(0, participants.clone());
            context.sleep(Duration::from_millis(10)).await;

            let scheme = Scheme::signer(
                SCHEME_NAMESPACE,
                participants.clone(),
                private_keys[receiver_idx].clone(),
            )
            .expect("signer scheme should be created");

            let config: Config<_, _, _, _, _, _> = Config {
                scheme_provider: MultiEpochProvider::single(scheme),
                blocker: receiver_control.clone(),
                max_block_size: MAX_BLOCK_SIZE,
                block_codec_cfg: (),
                strategy: STRATEGY,
                mailbox_size: NZUsize!(1024),
                peer_buffer_size: NZUsize!(64),
                records: NZUsize!(16),
                background_channel_capacity: NZUsize!(1024),
                peer_provider: oracle.manager(),
            };

            let (engine, mailbox) = ShardEngine::new(context.child("evicted"), config);
            engine.start((evicted_sender, evicted_receiver));

            let coding_config = coding_config_for_participants(num_peers as u16);
            let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
            let coded_block = CodedBlock::<B, C, H>::new(inner, coding_config, &STRATEGY);
            let commitment = coded_block.commitment();

            let peer2_shard = coded_block.shard(2).expect("missing shard 2").encode();
            let peer4_shard = coded_block.shard(4).expect("missing shard 4").encode();
            let peer5_shard = coded_block.shard(5).expect("missing shard 5").encode();
            let peer6_shard = coded_block.shard(6).expect("missing shard 6").encode();

            let block_sub = mailbox.subscribe(commitment);

            // Pre-`Discovered` path: four shards from peers that will still be in `latest.primary` after
            // the receiver is evicted (indices 2, 4, 5, 6). Together they are enough to reconstruct.
            peer2_sender
                .send(
                    Recipients::One(receiver_pk.clone()),
                    peer2_shard,
                    true,
                );
            peer4_sender
                .send(
                    Recipients::One(receiver_pk.clone()),
                    peer4_shard,
                    true,
                );
            peer5_sender
                .send(
                    Recipients::One(receiver_pk.clone()),
                    peer5_shard,
                    true,
                );
            peer6_sender
                .send(
                    Recipients::One(receiver_pk.clone()),
                    peer6_shard,
                    true,
                );
            context.sleep(DEFAULT_LINK.latency * 2).await;

            // Evict the receiver from `latest.primary`: buffered shards from remaining primaries must
            // still count toward reconstruction once the leader is known.
            let latest_primary: Set<P> = Set::from_iter_dedup(
                peer_keys
                    .iter()
                    .filter(|pk| **pk != receiver_pk)
                    .cloned(),
            );
            oracle.manager().track(1, latest_primary);
            context.sleep(Duration::from_millis(10)).await;

            // Leader announcement drains overlap-buffered peer shards; the evicted receiver should
            // still reach quorum without ever receiving the leader's direct shard.
            mailbox
                .discovered(
                    commitment,
                    leader_pk.clone(),
                    Round::new(Epoch::zero(), View::new(1)),
                );

            select! {
                _ = block_sub => {},
                _ = context.sleep(Duration::from_secs(5)) => {
                    panic!("block subscription did not resolve after leader discovery");
                },
            }

            context.sleep(DEFAULT_LINK.latency * 2).await;
            let block = mailbox.get(commitment).await;
            assert!(
                block.is_some(),
                "evicted node should reconstruct from buffered shards sent by remaining latest.primary peers"
            );
            assert_eq!(block.unwrap().commitment(), commitment);

            assert!(
                oracle.blocked().await.unwrap().is_empty(),
                "no peer should be blocked when overlapping shards are valid"
            );
        });
    }

    /// When peer gossip shards arrive before the leader's direct shard,
    /// the state may transition to Ready before the leader shard is
    /// processed. The late leader shard must still be accepted, verified,
    /// and broadcast so that slower peers can reach quorum.
    #[test_traced]
    fn test_late_leader_shard_accepted_after_quorum_transition() {
        let fixture = Fixture {
            num_primary_peers: 10,
            ..Default::default()
        };

        fixture.start(
            |config, context, oracle, mut peers, _, coding_config| async move {
                let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block = CodedBlock::<B, C, H>::new(inner, coding_config, &STRATEGY);
                let commitment = coded_block.commitment();
                let round = Round::new(Epoch::zero(), View::new(1));

                let leader_idx = 0usize;
                let victim_idx = 1usize;
                let leader = peers[leader_idx].public_key.clone();
                let victim = peers[victim_idx].public_key.clone();

                // Sever the link from leader to victim so the leader's
                // direct shard does not arrive initially.
                oracle
                    .remove_link(leader.clone(), victim.clone())
                    .await
                    .expect("remove_link should succeed");

                // Leader proposes. All peers except the victim get their
                // shard from the leader, verify it, and gossip it.
                peers[leader_idx]
                    .mailbox
                    .proposed(round, coded_block.clone());

                // Inform all non-leader peers of the leader.
                for peer in peers[1..].iter_mut() {
                    peer.mailbox.discovered(commitment, leader.clone(), round);
                }

                // Wait for gossip to propagate. The victim should
                // reconstruct the block from gossiped peer shards,
                // transitioning to Ready without its own shard.
                context.sleep(config.link.latency * 4).await;

                let block_sub = peers[victim_idx].mailbox.subscribe(commitment);
                select! {
                    result = block_sub => {
                        let reconstructed = result.expect("block subscription should resolve");
                        assert_eq!(reconstructed.commitment(), commitment);
                    },
                    _ = context.sleep(Duration::from_secs(5)) => {
                        panic!("victim did not reconstruct block from gossip");
                    },
                }

                // The shard subscription should NOT have resolved yet
                // because the victim has not verified its own shard.
                let mut shard_sub = peers[victim_idx]
                    .mailbox
                    .subscribe_assigned_shard_verified(commitment);
                assert!(
                    matches!(shard_sub.try_recv(), Err(TryRecvError::Empty)),
                    "shard subscription must not resolve before own shard is verified"
                );

                // Now restore the link so the leader's shard arrives late.
                oracle
                    .add_link(leader.clone(), victim.clone(), DEFAULT_LINK)
                    .await
                    .expect("add_link should succeed");

                // Re-send the leader's shard manually via the leader's
                // network sender (the engine already broadcast it earlier,
                // but the link was down).
                let leader_shard = coded_block
                    .shard(peers[victim_idx].index.get() as u16)
                    .expect("missing victim shard");
                peers[leader_idx].sender.send(
                    Recipients::One(victim.clone()),
                    leader_shard.encode(),
                    true,
                );
                context.sleep(config.link.latency * 2).await;

                // The shard subscription should now resolve because the
                // late leader shard was accepted and verified.
                select! {
                    _ = shard_sub => {},
                    _ = context.sleep(Duration::from_secs(5)) => {
                        panic!("shard subscription did not resolve after late leader shard");
                    },
                }

                // No peer should be blocked.
                let blocked = oracle.blocked().await.unwrap();
                assert!(
                    blocked.is_empty(),
                    "no peer should be blocked in late leader shard test"
                );

                // After both reconstruction and assigned shard readiness,
                // additional gossip shards should be silently ignored.
                let extra_sender_idx = 2usize;
                let extra_shard = coded_block
                    .shard(peers[extra_sender_idx].index.get() as u16)
                    .expect("missing shard");
                peers[extra_sender_idx].sender.send(
                    Recipients::One(victim.clone()),
                    extra_shard.encode(),
                    true,
                );
                context.sleep(config.link.latency * 2).await;

                // The gossip shard should be silently dropped (not blocked).
                let blocked = oracle.blocked().await.unwrap();
                assert!(
                    blocked.is_empty(),
                    "gossip shard after full reconstruction should be silently ignored"
                );
            },
        );
    }
}
