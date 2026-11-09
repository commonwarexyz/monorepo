//! Shard engine for erasure-coded block distribution and reconstruction.
//!
//! This module implements the core logic for distributing blocks as erasure-coded
//! shards and reconstructing blocks from received shards.
//!
//! # Overview
//!
//! The shard engine serves two primary functions:
//! 1. Broadcast: When a node proposes a block, the engine sends erasure-coded
//!    shards to all participants and to non-participants in aggregate membership
//!    (peers in [`commonware_p2p::PeerSetUpdate::all`] but not in the epoch
//!    participant list). Shards travel one segment's chunk at a time: the leader
//!    sends each participant the chunk at its index as each segment is coded,
//!    which may be before the block is sealed (see [`crate::BodySink`]), and
//!    then sends every peer the segment roots that bind the chunks to the block's
//!    commitment.
//! 2. Block Reconstruction: When a node receives chunks from peers, the engine
//!    validates them and reconstructs the original block once every segment holds
//!    enough valid chunks. Both participants and non-participants can reconstruct
//!    blocks: participants receive their own indexed chunks from the leader, while
//!    non-participants reconstruct from chunks relayed by participants. Each
//!    participant relays the leader's chunk at its own index to all peers as soon
//!    as it verifies, before the commitment exists.
//!
//! The engine treats a node as a participant in an epoch when its scheme for
//! that epoch reports the node's membership through [`CertificateScheme::me`].
//! Signer and member schemes report it, and verifier schemes do not. A
//! participant's assigned shard is the one at its index, and a
//! non-participant's assigned shard is the leader's own shard.
//!
//! # Message Flow
//!
//! ```text
//! time -->
//!
//! leader           build body ..........................| seal
//!   sends          Stream(seg 0)   Stream(seg 1)  ...   Stream(seg S-1)   Stream(tail)   Roots
//!                       |               |                    |                |            |
//! participant i         v               v                    v                v            v
//!   checks         c0,i vs root_0  c1,i vs root_1  ...  cS-1,i vs root_S-1  tail chunk   roots hash to a
//!   relays         c0,i -> peers   c1,i -> peers   ...  cS-1,i -> peers     -> peers     commitment consensus
//!                                                                                        signaled?
//!                  <------------ before the commitment exists ---------------->          |
//!                                                                                        v
//! every node       per segment, minimum_shards chunks under the sealed roots  -->  decode  -->  block cached
//!                  (own chunks from the leader, the rest relayed by participants)
//!
//! non-participant  receives the leader's own chunks and the relayed ones, reconstructs the same way
//! ```
//!
//! # Streams
//!
//! Chunks name only their round, because a leader may send them before its block, and so its
//! commitment, exists. A receiver checks each chunk against its segment root on arrival and
//! stores it in the round's stream record. Only the round leader's messages or a consensus
//! signal open a record. [`Config::leader`] (for example [`scheduled_leader`](super::scheduled_leader))
//! or a commitment consensus discovered in the round names the leader, the only sender of chunks
//! it does not own, and a notarization opens the record even while the leader is unknown,
//! accepting only participants' own chunks until then.
//!
//! Once roots for the round hash to a commitment's coding root and consensus has signaled that
//! commitment, the round's chunks under those roots move into the commitment's reconstruction
//! state, and each participant relays the roots to its peers. Roots are accepted from the
//! round's leader, or from any participant for a commitment consensus signaled in the round, so
//! a node the leader never reached can still bind the chunks participants relay to it.
//!
//! A leader may stream a second candidate in the same round, as when a prepared build is
//! abandoned and the proposal that replaces it streams its own segments. The record keeps the
//! chunks of up to two candidates side by side, and the roots decide which candidate's chunks
//! move. Chunks of any further candidate in the round are ignored, so a receiver relays at most
//! two chunks per segment per round.
//!
//! # Reconstruction State Machine
//!
//! For each [`Commitment`] that is either leader-discovered or notarized and
//! admitted by the record window, nodes (both participants and non-participants)
//! maintain a [`ReconstructionState`]:
//!
//! ```text
//! stream record, one per round                       commitment record, one per commitment
//! (opened by the leader's first chunk,                (created by Mailbox::proposed, discovered
//!  Config::leader, a discovery or a notarization)      or notarized inside the record window)
//!
//! chunk arrives ---> check vs its segment root ---> store under (segment, index, root)
//!                       |                             at most 2 roots per (segment, index)
//!                       +--> own index from the leader: relay to all peers
//!
//! roots arrive -----> commit(roots) == commitment.root ?  --no--> block the sender
//!                       |yes
//!                       v
//!                  consensus signaled that commitment in this round ?  --not yet--> keep, retry on the signal
//!                       |yes
//!                       v
//!                  move the chunks under those roots ==================> AwaitingQuorum
//!                  (other candidates' chunks stay in the record)           |
//!                                                                          | minimum_shards chunks
//!                                                                          | in every segment
//!                                                                          v
//!                                                                    Reconstruction job: decode,
//!                                                                    check digest, config, context
//!                                                                      | ok               | failed
//!                                                                      v                  v
//!                                                                    Ready             record removed
//!                                                                    block cached,
//!                                                                    chunks released
//! own proposal ------------------------------------------------------> Ready directly
//! window moves past the round ------> stream record dropped with its chunks
//! ```
//!
//! _Per-peer buffers are only kept for primary peers of a tracked peer set
//! ([`commonware_p2p::PeerSetUpdate::all`]), matching [`commonware_broadcast::buffered`].
//! A peer that is no longer a primary of any tracked set loses its buffered chunks.
//! One that only leaves the latest set keeps them through the overlap window, so a
//! departing participant's chunks for its final epoch are still ingested._
//!
//! # Peer Validation and Blocking Rules
//!
//! The engine enforces strict validation to prevent Byzantine attacks:
//!
//! - All chunks MUST be sent by participants in the round's epoch.
//! - A chunk from the round's leader MUST be the one assigned to this node (the
//!   chunk at its index, or the leader's own for a non-participant). Any other
//!   participant may only send its own chunk.
//! - A chunk MUST claim the round's coding config, name a segment a block at the
//!   bound can have, and verify against its segment root.
//! - Chunk data MUST NOT be wider than the coding scheme produces, under the
//!   chunk's coding config, for a block at the [`BoundedBlock::max_encode_size`]
//!   bound of [`Config::block_codec_config`].
//! - Roots MUST come from the round's leader, or from a participant relaying them
//!   for a commitment consensus signaled in the round, and hash to the coding root
//!   of a commitment coded with the round's config.
//! - Each round holds at most two chunks per segment and index, under distinct
//!   roots. A repeated chunk, or a third one, is silently ignored.
//!
//! Peers found violating these rules are blocked via the [`Blocker`] trait.
//! Chunks and roots for a round whose leader is not yet known wait in fixed-size
//! per-peer queues until the leader is known. A record is opened only for a round
//! the window admits within a window's length of views of the highest signaled
//! round, and is dropped with its round when the window moves past it. Once a
//! block is cached, its record retains no chunks and only completes verification
//! of a late assigned shard.
//!
//! # Record Window
//!
//! The engine retains at most [`Config::records`] commitment records. Only
//! local signals ([`Mailbox::proposed`], [`Mailbox::discovered`], and
//! [`Mailbox::notarized`]) create records. Once the window is full, records
//! with the lowest rounds are evicted first, and a signal at or below the
//! lowest retained round creates no record and leaves the commitment's chunks
//! in their round's stream record. Eviction closes no subscription.

use super::{
    leader::RoundLeader,
    mailbox::{Mailbox, Message},
    metrics::ShardMetrics,
};
use crate::{
    Block, BoundedBlock, CertifiableBlock, Heightable,
    marshal::coding::{
        stream::StreamedSegment,
        types::{
            CodedBlock, CodedLayout, ShardMessage, StreamChunk, StreamRoots,
            coding_config_for_participants, read_coded_payload,
        },
        validation::{ReconstructionError as InvariantError, validate_reconstruction},
    },
    types::{Epoch, Round, coding::Commitment},
};
use commonware_actor::mailbox;
use commonware_codec::{EncodeSize, Error as CodecError};
use commonware_coding::{Scheme as CodingScheme, Segmentable};
use commonware_cryptography::{
    Committable, Digested, Digestible, Hasher, PublicKey,
    certificate::{Provider, Scheme as CertificateScheme},
};
use commonware_macros::select_loop;
use commonware_p2p::{
    Blocker, Provider as PeerProvider, Receiver, Recipients, Sender,
    utils::codec::{WrappedBackgroundReceiver, WrappedSender},
};
use commonware_parallel::Strategy;
use commonware_runtime::{
    Clock, ContextCell, Handle, Metrics, Spawner, spawn_cell, telemetry::metrics::HistogramExt,
};
use commonware_utils::{
    Widen,
    bitmap::BitMap,
    channel::{fallible::OneshotExt, oneshot},
    futures::{AbortablePool, Aborter},
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

/// An error that can occur during reconstruction of a [`CodedBlock`] from shard chunks
#[derive(Debug, Error)]
pub enum Error<C: CodingScheme> {
    /// An error occurred while recovering the encoded blob from the shard chunks
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

/// A finished reconstruction job.
struct Reconstructed<B, C: Segmentable, H> {
    /// The commitment whose block the job reconstructs.
    commitment: Commitment<B, C, H>,
    /// When the job was submitted.
    start: SystemTime,
    /// The decoded block.
    result: Result<B, Error<C>>,
}

/// Decodes the block from checked chunks, at least the minimum per segment.
///
/// Every chunk was checked against `roots` on arrival, and `roots` against the commitment, so
/// no sender is found invalid here.
fn reconstruct<B, C, H>(
    commitment: Commitment<B, C, H>,
    start: SystemTime,
    roots: Vec<C::Commitment>,
    chunks: Vec<SizedChunk<C>>,
    cfg: &B::Cfg,
    strategy: &impl Strategy,
) -> Reconstructed<B, C, H>
where
    B: CertifiableBlock + CodedLayout,
    C: Segmentable,
    H: Hasher,
{
    let result = C::decode_chunks(
        &commitment.config(),
        &commitment.root(),
        &roots,
        chunks.iter().map(|sized| &sized.chunk),
        strategy,
    )
    .map_err(Error::Coding)
    .and_then(|blob| decode(commitment, blob, cfg, strategy));
    Reconstructed {
        commitment,
        start,
        result,
    }
}

/// Decodes the block from the blob the coding scheme recovered and validates it against
/// `commitment`.
fn decode<B, C, H>(
    commitment: Commitment<B, C, H>,
    blob: Vec<u8>,
    cfg: &B::Cfg,
    strategy: &impl Strategy,
) -> Result<B, Error<C>>
where
    B: CertifiableBlock + CodedLayout,
    C: Segmentable,
    H: Hasher,
{
    // The blob is the block in its coded layout followed by its coding config.
    let (inner, config) = read_coded_payload::<B>(blob, cfg)?;
    match validate_reconstruction(&inner, config, commitment, strategy) {
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
    B: CertifiableBlock + CodedLayout,
    T: Strategy,
{
    /// The scheme provider.
    ///
    /// A scheme registered for an epoch in which this node is a committee member must report
    /// the node's membership ([`CertificateScheme::me`]) even when it cannot sign. The leader
    /// sends each committee member the shard at its index, and the engine needs that index to
    /// accept the shard, gossip it once verified, and broadcast the node's own proposals.
    pub scheme_provider: S,

    /// The peer blocker.
    pub blocker: X,

    /// [`commonware_codec::Read`] configuration for decoding blocks. Every node must use the same
    /// value.
    ///
    /// Peers are blocked for sending a shard whose data is wider than the coding scheme produces,
    /// under the config the shard's commitment claims, from a block at the
    /// [`BoundedBlock::max_encode_size`] bound of this configuration followed by its coding config.
    /// The claimed config is untrusted until consensus confirms the commitment, so shard data may
    /// reach the scheme's widest for such a block. Under a one-shard config, that data is at least
    /// the whole block.
    pub block_codec_config: B::Cfg,

    /// The strategy that checks and decodes received shards, encodes shards for broadcast, and
    /// runs reconstruction jobs.
    pub strategy: T,

    /// The size of the mailbox buffer.
    pub mailbox_size: NonZeroUsize,

    /// Number of chunks or roots to buffer per peer.
    ///
    /// Chunks and roots for a round whose leader is not yet known are buffered per peer in a
    /// fixed-size ring to bound memory under Byzantine spam. They are ingested once
    /// [`Config::leader`] or a proposal consensus discovers via [`Mailbox::discovered`]
    /// names the round's leader. A notarization via [`Mailbox::notarized`] ingests the
    /// senders' own chunks and roots that hash to the notarized commitment before then.
    ///
    /// Chunks wait here in memory until their round's leader is known: at most
    /// `peer_buffer_size` per tracked primary peer, each carrying data up to the scheme's widest
    /// for the block bound of `block_codec_config`. An honest peer sends each recipient about one
    /// chunk per segment of each block, so size the ring for that many chunks times the number of
    /// blocks a node can trail its peers by. A ring too small for a distant or slow node evicts
    /// chunks before they are needed, and the node then fetches those blocks from the resolver
    /// instead of reconstructing them.
    pub peer_buffer_size: NonZeroUsize,

    /// The maximum number of commitment records retained.
    ///
    /// Records with the lowest rounds are evicted first. Once the window is full, a consensus
    /// signal at or below the lowest retained round creates no record. Must be at least
    /// `2 * (max(1, optimistic_views) + 2)`, where `optimistic_views` is
    /// [`crate::simplex::elector::Terms::optimistic_views`].
    pub records: NonZeroUsize,

    /// Provider for peer set information. Pre-leader shards are buffered per
    /// peer only while that peer is a primary of some tracked peer set
    /// ([`commonware_p2p::PeerSetUpdate::all`]), matching
    /// [`commonware_broadcast::buffered::Engine`]. Broadcast delivery uses
    /// the whole [`commonware_p2p::PeerSetUpdate::all`] union.
    pub peer_provider: D,

    /// Returns the leader of a round, or `None` while it is not known (see
    /// [`scheduled_leader`](super::scheduled_leader)).
    ///
    /// A receiver verifies and relays a leader's streamed chunks before the commitment exists
    /// only once it knows who leads the round. Until then they wait in the per-peer buffers, and
    /// a discovered proposal names the leader.
    pub leader: RoundLeader<P>,
}

/// The most candidate blocks whose chunks a stream record keeps per round: a prepared build and
/// the proposal that replaces it.
const CANDIDATES: usize = 2;

/// The data currently owned for a consensus commitment.
enum CommitmentPhase<B, C, H>
where
    B: Block,
    C: Segmentable,
    H: Hasher,
{
    /// Shards are still being accumulated or validated.
    Reconstructing(ReconstructionState<C>),
    /// The block is cached. Retained reconstruction state holds no shards and only
    /// tracks verification of a late assigned shard.
    Cached {
        block: Arc<CodedBlock<B, C, H>>,
        reconstruction: Option<ReconstructionState<C>>,
    },
}

/// The single lifecycle owner for a consensus commitment.
///
/// The observation round determines both the eviction order and the epoch whose
/// participant scheme classifies shards. Keeping it outside the phase prevents
/// cached and reconstructing views of the same commitment from diverging.
struct CommitmentRecord<B, C, H>
where
    B: Block,
    C: Segmentable,
    H: Hasher,
{
    round: Round,
    phase: CommitmentPhase<B, C, H>,
    proposed: bool,
}

/// Lifecycle records keyed by the complete commitment, including its coding
/// root and configuration.
type CommitmentRecords<B, C, H> = BTreeMap<Commitment<B, C, H>, CommitmentRecord<B, C, H>>;

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

impl<B, C, H> CommitmentRecord<B, C, H>
where
    B: Block,
    C: Segmentable,
    H: Hasher,
{
    /// Creates a record that is reconstructing a commitment observed at `round`.
    const fn reconstructing(round: Round, reconstruction: ReconstructionState<C>) -> Self {
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
    const fn reconstruction(&self) -> Option<&ReconstructionState<C>> {
        match &self.phase {
            CommitmentPhase::Reconstructing(reconstruction) => Some(reconstruction),
            CommitmentPhase::Cached { reconstruction, .. } => reconstruction.as_ref(),
        }
    }

    /// Returns mutable shard reconstruction state retained for the commitment, if any.
    const fn reconstruction_mut(&mut self) -> Option<&mut ReconstructionState<C>> {
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

/// A network layer for broadcasting and receiving [`CodedBlock`]s as shard chunks.
///
/// When enough chunks are present, the [`Engine`] may facilitate reconstruction of the original
/// [`CodedBlock`] and notify any subscribers waiting for it.
///
/// # Message Sizes
///
/// ```text
/// Stream message (one segment's chunk of a shard):
///
/// +---------+------------+-------+-----------+-------------+------+---------------------------+
/// | tag (1) | config (4) | round | index (2) | segment (2) | root | chunk                     |
/// +---------+------------+-------+-----------+-------------+------+---------------------------+
///
/// Roots message (binds a round's chunks to the commitment):
///
/// +---------+------------------+-------+------------------------------------+
/// | tag (1) | commitment (100) | round | roots (up to C::segments digests)  |
/// +---------+------------------+-------+------------------------------------+
/// ```
///
/// Each payload the engine sends is the encoding of one message. A chunk is at most
/// `C::max_chunk_size` for the coded block bound. The engine sends the chunks and roots of each
/// block the node proposes, relays each chunk of the node's own shard it receives from the
/// round's leader, and relays the roots of each commitment consensus signals. A relayed chunk
/// arrived on the engine's receiver, so the receiver must yield no payload larger than the
/// sender's network admits. The channels of one p2p network and the paired subchannels of a
/// [`Muxer`](commonware_p2p::utils::mux::Muxer) meet this.
pub struct Engine<E, S, X, D, C, H, B, P, T>
where
    E: Rng + Spawner + Metrics + Clock,
    S: Provider<Scope = Epoch>,
    S::Scheme: CertificateScheme<PublicKey = P>,
    X: Blocker,
    D: PeerProvider<PublicKey = P>,
    C: Segmentable,
    H: Hasher,
    B: CertifiableBlock + CodedLayout,
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

    /// [`commonware_codec::Read`] configuration for decoding [`CodedBlock`]s.
    block_codec_config: B::Cfg,

    /// The strategy that checks and decodes received chunks, encodes shards for broadcast, and
    /// runs reconstruction jobs.
    strategy: T,

    /// The cache and reconstruction lifecycle for each observed [`Commitment`].
    records: CommitmentRecords<B, C, H>,

    /// Per-peer ring buffers for chunks and roots received before their round's leader is known.
    ///
    /// Empty buffers are retained for active peers and only evicted when the
    /// peer is no longer a primary of any tracked peer set.
    peer_buffers: BTreeMap<P, VecDeque<ShardMessage<B, C, H>>>,

    /// Maximum buffered messages per peer.
    peer_buffer_size: NonZeroUsize,

    /// Maximum number of commitment records retained.
    window: NonZeroUsize,

    /// Provider for peer set information.
    peer_provider: D,

    /// Latest union of peer membership from the peer set subscription
    /// ([`commonware_p2p::PeerSetUpdate::all`]).
    aggregate_peers: Set<P>,

    /// Primary peers of every tracked peer set, allowed to retain pre-leader buffers.
    primary_peers: Set<P>,

    /// Open subscriptions for assigned shard verification for the keyed
    /// [`Commitment`].
    ///
    /// For participants, readiness is satisfied once every chunk of the shard for the local
    /// participant index has been verified. Reconstruction from peer chunks is
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
    jobs: AbortablePool<'static, Reconstructed<B, C, H>>,

    /// Metrics for the shard engine.
    metrics: ShardMetrics<P>,

    /// Returns the leader of a round, if known.
    leader: RoundLeader<P>,

    /// The most segments a block at the bound of the block codec config codes into.
    max_segments: u16,

    /// Chunks streamed for each round's block, keyed by round.
    streams: BTreeMap<Round, StreamRecord<B, C, H, P>>,

    /// The roots of the segments this node streamed for the block it is building, keyed by
    /// round, in segment order.
    streamed: BTreeMap<Round, Vec<C::Commitment>>,
}

/// The chunks streamed for one round.
///
/// A record admits at most [`CANDIDATES`] chunks per segment and shard index, under distinct
/// roots, and at most [`Engine::max_segments`] segments per index. Once the leader's roots bind
/// the record to a commitment and consensus has signaled that commitment, its chunks under those
/// roots move into the commitment's reconstruction state.
struct StreamRecord<B, C, H, P>
where
    B: Digestible,
    C: Segmentable,
    H: Hasher,
    P: PublicKey,
{
    /// The round's leader, the only sender of chunks it does not own, once known.
    leader: Option<P>,
    /// The roots received for each segment and index, at most [`CANDIDATES`] of them, so a
    /// repeated chunk is neither stored nor relayed.
    seen: BTreeMap<(u16, u16), Vec<C::Commitment>>,
    /// Chunks not yet moved into reconstruction state, keyed by segment, index, and the root
    /// they were checked against.
    chunks: BTreeMap<(u16, u16, C::Commitment), SizedChunk<C>>,
    /// The commitment and segment roots that bind the round's chunks: the latest the leader
    /// sent, or that a participant relayed for a commitment consensus signaled in the round.
    #[allow(clippy::type_complexity)]
    sealed: Option<(Commitment<B, C, H>, Vec<C::Commitment>)>,
    /// The commitments whose roots this node relayed, at most [`CANDIDATES`] of them.
    relayed: Vec<Commitment<B, C, H>>,
}

impl<B, C, H, P> StreamRecord<B, C, H, P>
where
    B: Digestible,
    C: Segmentable,
    H: Hasher,
    P: PublicKey,
{
    const fn new(leader: Option<P>) -> Self {
        Self {
            leader,
            seen: BTreeMap::new(),
            chunks: BTreeMap::new(),
            sealed: None,
            relayed: Vec::new(),
        }
    }
}

impl<E, S, X, D, C, H, B, P, T> Engine<E, S, X, D, C, H, B, P, T>
where
    E: Rng + Spawner + Metrics + Clock,
    S: Provider<Scope = Epoch>,
    S::Scheme: CertificateScheme<PublicKey = P>,
    X: Blocker<PublicKey = P>,
    D: PeerProvider<PublicKey = P>,
    C: Segmentable,
    H: Hasher,
    B: CertifiableBlock + BoundedBlock + CodedLayout,
    P: PublicKey,
    T: Strategy,
{
    /// Create a new [`Engine`] with the given configuration.
    pub fn new(context: E, config: Config<P, S, X, D, B, T>) -> (Self, Mailbox<B, C, H, P>) {
        let metrics = ShardMetrics::new(&context);
        let (sender, mailbox) = mailbox::new(context.child("mailbox"), config.mailbox_size);
        let max_segments = C::segments(CodedBlock::<B, C, H>::max_coded_size(B::max_encode_size(
            &config.block_codec_config,
        )));
        (
            Self {
                context: ContextCell::new(context),
                mailbox,
                scheme_provider: config.scheme_provider,
                blocker: config.blocker,
                block_codec_config: config.block_codec_config,
                strategy: config.strategy,
                records: BTreeMap::new(),
                peer_buffers: BTreeMap::new(),
                peer_buffer_size: config.peer_buffer_size,
                window: config.records,
                peer_provider: config.peer_provider,
                aggregate_peers: Set::default(),
                primary_peers: Set::default(),
                assigned_shard_verified_subscriptions: BTreeMap::new(),
                block_subscriptions: BTreeMap::new(),
                jobs: AbortablePool::default(),
                metrics,
                leader: config.leader,
                max_segments,
                streams: BTreeMap::new(),
                streamed: BTreeMap::new(),
            },
            Mailbox::new(sender),
        )
    }

    /// Start the engine.
    ///
    /// Decoded messages wait for the engine in a mailbox sized to the network receiver's
    /// [`commonware_p2p::Receiver::capacity`]. Each carries chunk data up to the scheme's widest
    /// for the block bound of [`Config::block_codec_config`].
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
        let mut sender = WrappedSender::<_, ShardMessage<B, C, H>>::new(sender);
        let (receiver_service, mut receiver) =
            WrappedBackgroundReceiver::<_, P, X, _, ShardMessage<B, C, H>, T>::new(
                self.context.child("shard_ingress"),
                receiver,
                B::max_encode_size(&self.block_codec_config),
                self.blocker.clone(),
                self.strategy.clone(),
            );
        receiver_service.start();
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
            // Removing or caching a record discards its job's result.
            Ok(reconstructed) = self.jobs.next_completed() else continue => {
                self.complete(reconstructed);
            },
            Some(update) = peer_set_subscription.recv() else {
                debug!("peer set subscription closed");
                return;
            } => {
                self.update_primary_peers(update.all.primary.clone());
                self.aggregate_peers = update.all.union();
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
                    Message::StreamSegment { round, segment } => {
                        self.stream_segment(&mut sender, round, segment);
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
            Some((peer, message)) = receiver.recv() else {
                debug!("receiver closed, stopping shard engine");
                return;
            } => {
                self.handle_network_message(&mut sender, peer, message);
            },
        }
    }

    /// Handles a decoded chunk or roots message received from the network.
    fn handle_network_message<Sr: Sender<PublicKey = P>>(
        &mut self,
        sender: &mut WrappedSender<Sr, ShardMessage<B, C, H>>,
        peer: P,
        message: ShardMessage<B, C, H>,
    ) {
        match message {
            ShardMessage::Stream(chunk) => {
                self.metrics.shards_received.get_or_create_by(&peer).inc();
                self.handle_stream_chunk(sender, peer, chunk);
            }
            ShardMessage::Roots(roots) => self.handle_stream_roots(sender, peer, roots),
        }
    }

    /// Starts a job that decodes the block once every segment holds the minimum of checked
    /// chunks.
    fn try_reconstruct(&mut self, commitment: Commitment<B, C, H>) {
        // Only records without a cached block await quorum, and each holds at most one job.
        let Some(ReconstructionState::AwaitingQuorum(state)) = self
            .records
            .get_mut(&commitment)
            .and_then(CommitmentRecord::reconstruction_mut)
        else {
            return;
        };
        if state.job.is_some() {
            return;
        }
        let minimum = usize::from(commitment.config().minimum_shards.get());
        let Some(chunks) = state.take_decodable_chunks(minimum) else {
            return;
        };
        let roots = state
            .common
            .roots
            .clone()
            .expect("stored chunks were checked against verified roots");

        // The spawn hint is the encoded size of the chunks the job takes.
        let len = chunks.iter().map(|sized| sized.size).sum();
        let cfg = self.block_codec_config.clone();
        let start = self.context.current();
        let job = self.strategy.spawn(len, move |strategy| {
            reconstruct(commitment, start, roots, chunks, &cfg, &strategy)
        });
        state.job = Some(self.jobs.push(job));
    }

    /// Applies a finished reconstruction job to the record that started it.
    ///
    /// A successful reconstruction caches the block and drops the record's chunks. A failed
    /// reconstruction removes the record and closes its commitment-specific subscriptions.
    fn complete(&mut self, reconstructed: Reconstructed<B, C, H>) {
        let Reconstructed {
            commitment,
            start,
            result,
        } = reconstructed;

        // Removing or caching a record drops its job's aborter, so only a job whose record awaits
        // quorum yields its result.
        let record = self
            .records
            .get_mut(&commitment)
            .expect("a completed job's record must exist");
        let round = record.round();
        let Some(ReconstructionState::AwaitingQuorum(state)) = record.reconstruction_mut() else {
            unreachable!("a completed job's record must await quorum");
        };
        state.job = None;
        match result {
            Ok(inner) => {
                self.metrics
                    .reconstruction_duration
                    .observe_between(start, self.context.current());

                // Decoding verified the blob against the commitment, so shards can be lazily
                // re-constructed if need be.
                let block = self
                    .cache_block(
                        round,
                        Arc::new(CodedBlock::precomputed(
                            Digested::precomputed(inner, commitment.block()),
                            commitment,
                        )),
                    )
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
            Err(err) => {
                debug!(%commitment, ?err, "failed to reconstruct block from checked chunks");
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
        sender: &mut WrappedSender<Sr, ShardMessage<B, C, H>>,
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
        // Consensus names the round's leader, so the round's chunks can be checked even when
        // [`Config::leader`] cannot name it.
        self.open_stream(round, Some(leader));
        let Some(status) = self.observe_existing_commitment(commitment, round) else {
            return;
        };
        if status == CommitmentStatus::Absent {
            // Chunks for a commitment the window declines stay in their round's stream record.
            if !self.admits(round) {
                debug!(
                    %commitment,
                    %round,
                    "discovered commitment at or below the lowest retained round"
                );
                return;
            }
            self.insert_reconstruction_record(commitment, round, ReconstructionState::new());
        }
        self.drain_stream(sender, round);
    }

    /// Handles notarized reconstruction interest before the leader is known.
    ///
    /// The notarization opens the round's stream record, so participants' own chunks are accepted
    /// even while the round's leader is unknown, and roots any participant relays for the
    /// commitment bind them to it.
    fn handle_notarized_commitment<Sr: Sender<PublicKey = P>>(
        &mut self,
        sender: &mut WrappedSender<Sr, ShardMessage<B, C, H>>,
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
            self.open_stream(round, None);
            self.drain_stream(sender, round);
            return;
        }
        if self.scheme_provider.scheme(round.epoch()).is_none() {
            warn!(%commitment, "no scheme for epoch, ignoring notarized commitment");
            return;
        }

        // Shards for a commitment the window declines stay in the peer buffers.
        if !self.admits(round) {
            debug!(
                %commitment,
                %round,
                "notarized commitment at or below the lowest retained round"
            );
            return;
        }
        self.insert_reconstruction_record(commitment, round, ReconstructionState::new());
        self.open_stream(round, None);
        self.drain_stream(sender, round);
    }

    /// Buffer a chunk or roots message from a peer until its round's leader is known.
    ///
    /// Each peer's ring holds at most [`Config::peer_buffer_size`] messages, evicting its oldest
    /// to make room.
    fn buffer_peer_shard(&mut self, peer: P, message: ShardMessage<B, C, H>) {
        if self.primary_peers.position(&peer).is_none() {
            debug!(
                ?peer,
                "pre-leader shard from peer outside tracked primary sets not buffered"
            );
            return;
        }
        let queue = self.peer_buffers.entry(peer).or_default();
        if queue.len() >= self.peer_buffer_size.get() {
            let _ = queue.pop_front();
        }
        queue.push_back(message);
    }

    fn update_primary_peers(&mut self, peers: Set<P>) {
        self.peer_buffers
            .retain(|peer, _| peers.position(peer).is_some());
        self.primary_peers = peers;
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
        reconstruction: ReconstructionState<C>,
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
        self.trim_streams();
    }

    /// Returns whether a stream record may be opened for `round`: the window must admit the
    /// round, and the round must be at most a window's length of views beyond the highest
    /// round consensus has signaled, so the rounds that can hold records stay bounded.
    fn admits_stream(&self, round: Round) -> bool {
        if !self.admits(round) {
            return false;
        }
        let horizon = self.window.get() as u64;
        match self.records.values().map(CommitmentRecord::round).max() {
            None => true,
            Some(highest) if round.epoch() == highest.epoch() => {
                round.view().get() <= highest.view().get().saturating_add(horizon)
            }
            Some(highest) => round.epoch() < highest.epoch() || round.view().get() <= horizon,
        }
    }

    /// Drops stream records for rounds the window no longer admits, and the lowest rounds while
    /// more than the window's capacity of rounds are streaming.
    fn trim_streams(&mut self) {
        if self.records.len() >= self.window.get()
            && let Some(lowest) = self.records.values().map(CommitmentRecord::round).min()
        {
            self.streams = self.streams.split_off(&lowest);
            self.streamed = self.streamed.split_off(&lowest);
        }
        while self.streams.len() > self.window.get() {
            self.streams.pop_first();
        }
        while self.streamed.len() > self.window.get() {
            self.streamed.pop_first();
        }
    }

    /// Removes the record for `commitment` without closing any subscription.
    ///
    /// Dropping the record discards its reconstruction job's result.
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
        self.notify_block_subscribers(&cached);
        Ok(cached)
    }

    /// Broadcasts the shards of a [`CodedBlock`] and caches the block.
    ///
    /// Every recipient receives the block's chunks as stream messages, then the segment roots
    /// that bind them to the commitment. A block sealed from the segments this node streamed in
    /// the round needs only its roots: every recipient already has its chunks.
    fn broadcast_shards<Sr: Sender<PublicKey = P>>(
        &mut self,
        sender: &mut WrappedSender<Sr, ShardMessage<B, C, H>>,
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
        let Some(my_index) = scheme.me().map(|m| Widen::widen(m.index().get())) else {
            warn!(
                %commitment,
                "cannot broadcast shards: local proposer is not a participant"
            );
            return;
        };

        // Shards map to participants by index, so the block must be coded into exactly one shard
        // per member of the committee.
        let shards = block.shards(&self.strategy);
        let shard_count = shards.len();
        if shard_count != participants.len() {
            warn!(
                %commitment,
                shard_count,
                participants = participants.len(),
                "cannot broadcast shards: participant/shard count mismatch"
            );
            return;
        }

        // Segments go out one at a time, each to every recipient before the next, so every
        // participant can verify and relay its first chunk while the rest are in flight.
        let (roots, _) = C::split(&shards[my_index]);
        if self.streamed.remove(&round).as_ref() != Some(&roots) {
            let mut columns: Vec<_> = shards
                .iter()
                .map(|shard| C::split(shard).1.into_iter())
                .collect();
            for (segment, root) in roots.iter().enumerate() {
                let chunks = columns
                    .iter_mut()
                    .map(|column| {
                        column
                            .next()
                            .expect("every shard holds a chunk per segment")
                    })
                    .collect();
                let segment = StreamedSegment::<C> {
                    segment: segment as u16,
                    root: *root,
                    chunks,
                };
                self.send_segment(sender, round, participants, my_index, segment);
            }
        }
        let message = StreamRoots {
            commitment,
            round,
            roots,
        };
        let _ = sender.send(Recipients::All, message.into(), true);
        self.finish_broadcast(round, block);
    }

    /// Caches a block this node broadcast and marks it proposed.
    fn finish_broadcast(&mut self, round: Round, block: Arc<CodedBlock<B, C, H>>) {
        let commitment = block.commitment();

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

    /// Sends the chunks of a segment of the block this node is building in `round`.
    fn stream_segment<Sr: Sender<PublicKey = P>>(
        &mut self,
        sender: &mut WrappedSender<Sr, ShardMessage<B, C, H>>,
        round: Round,
        segment: StreamedSegment<C>,
    ) {
        let Some(scheme) = self.scheme_provider.scheme(round.epoch()) else {
            warn!(%round, "no scheme available, cannot stream segment");
            return;
        };
        let participants = scheme.participants();
        let Some(my_index) = scheme.me().map(|m| Widen::widen(m.index().get())) else {
            warn!(%round, "cannot stream segment: local proposer is not a participant");
            return;
        };
        if segment.chunks.len() != participants.len() {
            warn!(
                %round,
                chunks = segment.chunks.len(),
                participants = participants.len(),
                "cannot stream segment: participant/chunk count mismatch"
            );
            self.streamed.remove(&round);
            return;
        }

        // Segments arrive in order. A first segment starts another build in the round, replacing
        // the roots of any earlier one.
        let roots = self.streamed.entry(round).or_default();
        if segment.segment == 0 {
            roots.clear();
        }
        if usize::from(segment.segment) != roots.len() {
            warn!(%round, segment = segment.segment, "segment streamed out of order");
            self.streamed.remove(&round);
            return;
        }
        roots.push(segment.root);
        self.send_segment(sender, round, participants, my_index, segment);
        self.trim_streams();
    }

    /// Sends each participant its chunk of `segment`, and peers in aggregate membership who are not
    /// participants the chunk at this node's index.
    fn send_segment<Sr: Sender<PublicKey = P>>(
        &self,
        sender: &mut WrappedSender<Sr, ShardMessage<B, C, H>>,
        round: Round,
        participants: &Set<P>,
        my_index: usize,
        segment: StreamedSegment<C>,
    ) {
        let n_participants = u16::try_from(participants.len()).expect("too many participants");
        let config = coding_config_for_participants(n_participants);
        let non_participants: Vec<P> = self
            .aggregate_peers
            .iter()
            .filter(|peer| participants.index(peer).is_none())
            .cloned()
            .collect();
        for (index, chunk) in segment.chunks.into_iter().enumerate() {
            let recipients = if index == my_index {
                if non_participants.is_empty() {
                    continue;
                }
                Recipients::Some(non_participants.clone())
            } else {
                Recipients::One(participants[index].clone())
            };
            let message = StreamChunk {
                config,
                round,
                index: index as u16,
                segment: segment.segment,
                root: segment.root,
                chunk,
            };
            let _ = sender.send(recipients, message.into(), true);
        }
    }

    /// Returns the leader of `round`: the leader its stream record names, or else
    /// [`Config::leader`].
    fn round_leader(&self, round: Round) -> Option<P> {
        self.streams
            .get(&round)
            .and_then(|stream| stream.leader.clone())
            .or_else(|| (self.leader)(round))
    }

    /// Opens the stream record of `round` if the window admits it, or names the leader of a
    /// record opened before its leader was known.
    fn open_stream(&mut self, round: Round, leader: Option<P>) {
        let leader = leader.or_else(|| self.round_leader(round));
        if let Some(stream) = self.streams.get_mut(&round) {
            if stream.leader.is_none() {
                stream.leader = leader;
            }
        } else if self.admits_stream(round) {
            self.streams.insert(round, StreamRecord::new(leader));
        }
    }

    /// Handles a chunk streamed before its commitment existed.
    ///
    /// The chunk is buffered per peer until its round's leader is known or a notarization opens
    /// the round's record. Then the sender must be a participant, and the chunk must be the
    /// leader's chunk for this node (the chunk at the local index, or the leader's own for a
    /// non-participant) or the sender's own chunk. It must claim the round's coding config, name
    /// a segment a block at the bound can have, and verify against its root. Any other chunk
    /// blocks the sender. A participant relays the leader's chunk at its index to all peers as
    /// soon as it verifies.
    fn handle_stream_chunk<Sr: Sender<PublicKey = P>>(
        &mut self,
        sender: &mut WrappedSender<Sr, ShardMessage<B, C, H>>,
        peer: P,
        chunk: StreamChunk<C>,
    ) {
        let round = chunk.round;
        let leader = self.round_leader(round);
        let Some(scheme) = self.scheme_provider.scheme(round.epoch()) else {
            self.buffer_peer_shard(peer, chunk.into());
            return;
        };
        if leader.is_none() && !self.streams.contains_key(&round) {
            self.buffer_peer_shard(peer, chunk.into());
            return;
        }
        let participants = scheme.participants();
        let Some(sender_index) = participants.index(&peer) else {
            commonware_p2p::block!(self.blocker, peer, "stream chunk sent by non-participant");
            return;
        };
        let sender_index: u16 = sender_index
            .get()
            .try_into()
            .expect("participant index impossibly out of bounds");

        // Until the round's leader is known, a chunk at an index other than its sender's may be
        // the leader's chunk for this node, so it waits in the sender's buffer.
        if leader.is_none() && chunk.index != sender_index {
            self.buffer_peer_shard(peer, chunk.into());
            return;
        }
        let leader_index: Option<u16> = match &leader {
            Some(leader) => {
                let Some(index) = participants.index(leader) else {
                    debug!(%round, ?leader, "round leader is not a participant, ignoring stream chunk");
                    return;
                };
                Some(
                    index
                        .get()
                        .try_into()
                        .expect("participant index impossibly out of bounds"),
                )
            }
            None => None,
        };
        let local_index: Option<u16> = scheme.me().map(|m| {
            m.index()
                .get()
                .try_into()
                .expect("participant index impossibly out of bounds")
        });
        let from_leader = leader.as_ref() == Some(&peer);
        let allowed = if from_leader {
            Some(chunk.index) == local_index.or(leader_index)
        } else {
            chunk.index == sender_index
        };
        if !allowed {
            commonware_p2p::block!(
                self.blocker,
                peer,
                shard_index = chunk.index,
                "stream chunk index is neither assigned nor sender-owned"
            );
            return;
        }
        let n_participants = u16::try_from(participants.len()).expect("too many participants");
        let config = coding_config_for_participants(n_participants);
        if chunk.config != config {
            commonware_p2p::block!(self.blocker, peer, "stream chunk coded with another config");
            return;
        }
        if chunk.segment >= self.max_segments {
            commonware_p2p::block!(
                self.blocker,
                peer,
                segment = chunk.segment,
                "stream chunk segment out of range"
            );
            return;
        }
        // Only the leader's messages or a consensus signal open a round's record. A forward that
        // arrives first waits in the sender's buffer until the record opens.
        let opened = !self.streams.contains_key(&round);
        if opened {
            if !from_leader {
                self.buffer_peer_shard(peer, chunk.into());
                return;
            }
            if !self.admits_stream(round) {
                return;
            }
        }

        let record = self
            .streams
            .entry(round)
            .or_insert_with(|| StreamRecord::new(leader));
        let key = (chunk.segment, chunk.index);
        if record
            .seen
            .get(&key)
            .is_some_and(|roots| roots.len() >= CANDIDATES || roots.contains(&chunk.root))
        {
            return;
        }
        let Ok(checked) = C::check_chunk(
            &config,
            &chunk.root,
            chunk.index,
            chunk.segment,
            &chunk.chunk,
        ) else {
            commonware_p2p::block!(
                self.blocker,
                peer,
                segment = chunk.segment,
                "invalid stream chunk received"
            );
            return;
        };
        record.seen.entry(key).or_default().push(chunk.root);
        let size = chunk.chunk.encode_size();
        record.chunks.insert(
            (chunk.segment, chunk.index, chunk.root),
            SizedChunk {
                chunk: checked,
                size,
            },
        );

        // Relaying the leader's chunk for this participant before the commitment exists lets
        // every peer collect a segment while the leader is still sending later ones.
        if from_leader && local_index == Some(chunk.index) {
            let segment = chunk.segment;
            let peers = sender.send(Recipients::All, chunk.into(), true);
            self.metrics.chunks_forwarded.inc();
            debug!(%round, segment, peers = peers.len(), "forwarded stream chunk to all peers");
        }
        if opened {
            self.drain_stream(sender, round);
        } else {
            self.merge_stream(sender, round);
        }
        self.trim_streams();
    }

    /// Handles the segment roots of a round's block.
    ///
    /// The round's leader sends them once the block it streamed is sealed. Any other participant
    /// may relay them, but only for a commitment consensus signaled in the round, which is what
    /// authenticates them, so relayed roots wait in the sender's buffer until that signal. Either
    /// way, the roots must hash to the coding root of a commitment coded with the round's config,
    /// or the sender is blocked. The latest roots of a round replace earlier ones. Chunks of
    /// another candidate stay stored, so roots for a replacement can still claim them.
    fn handle_stream_roots<Sr: Sender<PublicKey = P>>(
        &mut self,
        sender: &mut WrappedSender<Sr, ShardMessage<B, C, H>>,
        peer: P,
        roots: StreamRoots<B, C, H>,
    ) {
        let round = roots.round;
        let Some(scheme) = self.scheme_provider.scheme(round.epoch()) else {
            self.buffer_peer_shard(peer, roots.into());
            return;
        };
        if scheme.participants().index(&peer).is_none() {
            commonware_p2p::block!(self.blocker, peer, "stream roots sent by non-participant");
            return;
        }
        let leader = self.round_leader(round);
        let commitment = roots.commitment;
        if leader.as_ref() != Some(&peer)
            && !self
                .records
                .get(&commitment)
                .is_some_and(|record| record.round() == round)
        {
            self.buffer_peer_shard(peer, roots.into());
            return;
        }
        let n_participants =
            u16::try_from(scheme.participants().len()).expect("too many participants");
        let config = coding_config_for_participants(n_participants);
        if commitment.config() != config || C::commit(&roots.roots) != commitment.root() {
            commonware_p2p::block!(self.blocker, peer, "stream roots do not match commitment");
            return;
        }
        if !self.streams.contains_key(&round) && !self.admits_stream(round) {
            return;
        }
        let record = self
            .streams
            .entry(round)
            .or_insert_with(|| StreamRecord::new(leader));
        if record
            .sealed
            .as_ref()
            .is_some_and(|(sealed, _)| *sealed == commitment)
        {
            return;
        }
        record.sealed = Some((commitment, roots.roots));
        self.merge_stream(sender, round);
        self.trim_streams();
    }

    /// Handles the stream messages buffered for `round` before its leader was known, then moves
    /// the round's streamed chunks into reconstruction state.
    fn drain_stream<Sr: Sender<PublicKey = P>>(
        &mut self,
        sender: &mut WrappedSender<Sr, ShardMessage<B, C, H>>,
        round: Round,
    ) {
        let mut buffered = Vec::new();
        for (peer, queue) in self.peer_buffers.iter_mut() {
            let mut i = 0;
            while i < queue.len() {
                if queue[i].round() == round {
                    let message = queue.remove(i).expect("index is valid");
                    buffered.push((peer.clone(), message));
                } else {
                    i += 1;
                }
            }
        }
        for (peer, message) in buffered {
            match message {
                ShardMessage::Stream(chunk) => self.handle_stream_chunk(sender, peer, chunk),
                ShardMessage::Roots(roots) => self.handle_stream_roots(sender, peer, roots),
            }
        }
        self.merge_stream(sender, round);
    }

    /// Moves the streamed chunks of `round` into the reconstruction state of the commitment its
    /// roots bind, once consensus has signaled that commitment, and relays those roots.
    fn merge_stream<Sr: Sender<PublicKey = P>>(
        &mut self,
        sender: &mut WrappedSender<Sr, ShardMessage<B, C, H>>,
        round: Round,
    ) {
        let Some((commitment, _)) = self
            .streams
            .get(&round)
            .and_then(|stream| stream.sealed.as_ref())
        else {
            return;
        };
        let commitment = *commitment;
        if !self
            .records
            .get(&commitment)
            .is_some_and(|record| record.validate_epoch(round).is_ok())
        {
            return;
        }
        self.relay_roots(sender, round);
        if self.move_streamed(round) {
            self.try_advance(commitment);
        }
    }

    /// Relays the sealed roots of `round` to all peers, so a participant the leader did not
    /// reach can still bind the chunks relayed to it.
    ///
    /// Only participants relay, since peers block roots from anyone else, and each relays the
    /// roots of at most [`CANDIDATES`] commitments per round.
    fn relay_roots<Sr: Sender<PublicKey = P>>(
        &mut self,
        sender: &mut WrappedSender<Sr, ShardMessage<B, C, H>>,
        round: Round,
    ) {
        if self
            .scheme_provider
            .scheme(round.epoch())
            .is_none_or(|scheme| scheme.me().is_none())
        {
            return;
        }
        let Some(stream) = self.streams.get_mut(&round) else {
            return;
        };
        let Some((commitment, roots)) = &stream.sealed else {
            return;
        };
        if stream.relayed.len() >= CANDIDATES || stream.relayed.contains(commitment) {
            return;
        }
        stream.relayed.push(*commitment);
        let message = StreamRoots {
            commitment: *commitment,
            round,
            roots: roots.clone(),
        };
        let _ = sender.send(Recipients::All, message.into(), true);
    }

    /// Moves the streamed chunks of `round` into the reconstruction state of the sealed
    /// commitment, which consensus has signaled in the round's epoch, and returns whether any
    /// chunk was recorded.
    fn move_streamed(&mut self, round: Round) -> bool {
        let stream = self
            .streams
            .get_mut(&round)
            .expect("merged stream must exist");
        let (commitment, roots) = stream.sealed.clone().expect("merged stream must be sealed");
        let record = self
            .records
            .get_mut(&commitment)
            .expect("merged commitment must have a record");
        let Some(scheme) = self.scheme_provider.scheme(round.epoch()) else {
            return false;
        };
        let participants = scheme.participants();
        let leader_index: Option<u16> = match &stream.leader {
            Some(leader) => {
                let Some(index) = participants.index(leader) else {
                    return false;
                };
                Some(
                    index
                        .get()
                        .try_into()
                        .expect("participant index impossibly out of bounds"),
                )
            }
            None => None,
        };
        let local_index: Option<u16> = scheme.me().map(|m| {
            m.index()
                .get()
                .try_into()
                .expect("participant index impossibly out of bounds")
        });
        let (sealed, other) = mem::take(&mut stream.chunks)
            .into_iter()
            .partition::<BTreeMap<_, _>, _>(|((segment, _, root), _)| {
                roots.get(usize::from(*segment)) == Some(root)
            });
        stream.chunks = other;
        let Some(state) = record.reconstruction_mut() else {
            return false;
        };
        let mut progressed = false;
        for ((segment, index, _), chunk) in sealed {
            let is_assigned_chunk = local_index.or(leader_index) == Some(index);
            progressed |= state.record_chunk(&roots, segment, index, chunk, is_assigned_chunk);
        }
        progressed
    }

    /// Notifies readiness once the whole local shard is verified, and starts reconstruction when
    /// enough chunks are available.
    fn try_advance(&mut self, commitment: Commitment<B, C, H>) {
        if let Some(state) = self
            .records
            .get_mut(&commitment)
            .and_then(CommitmentRecord::reconstruction_mut)
            && mem::take(&mut state.common_mut().notify_assigned)
        {
            self.notify_assigned_shard_verified_subscribers(commitment);
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
    fn notify_block_subscribers(&mut self, block: &Arc<CodedBlock<B, C, H>>) {
        let commitment = block.commitment();
        let digest = block.digest();

        // Notify by-commitment subscribers.
        if let Some(mut subscribers) = self
            .block_subscriptions
            .remove(&BlockSubscriptionKey::Commitment(commitment))
        {
            for subscriber in subscribers.drain(..) {
                subscriber.send_lossy(Arc::clone(block));
            }
        }

        // Notify by-digest subscribers.
        if let Some(mut subscribers) = self
            .block_subscriptions
            .remove(&BlockSubscriptionKey::Digest(digest))
        {
            for subscriber in subscribers.drain(..) {
                subscriber.send_lossy(Arc::clone(block));
            }
        }
    }
}

/// Erasure coded block reconstruction state machine.
enum ReconstructionState<C>
where
    C: Segmentable,
{
    /// Stage 1: accumulate chunks, each checked against its segment root before it is recorded.
    AwaitingQuorum(AwaitingQuorumState<C>),
    /// Stage 2: the block is cached. Only chunks of the assigned shard are still recorded.
    Ready(ReadyState<C>),
}

/// A checked chunk paired with the encoded size of the chunk it was checked from.
struct SizedChunk<C: Segmentable> {
    chunk: C::CheckedChunk,
    size: usize,
}

/// State shared across all reconstruction phases.
struct CommonState<C>
where
    C: Segmentable,
{
    /// Whether assigned shard verification awaits notification of local subscribers.
    notify_assigned: bool,
    /// Whether every chunk of the shard for our assigned index has been verified.
    assigned_shard_verified: bool,
    /// The segment roots, once they have been verified to hash to the commitment's coding root.
    roots: Option<Vec<C::Commitment>>,
    /// Segments whose chunk of our assigned shard has been verified, sized once the roots are
    /// verified.
    assigned_chunks: BitMap,
}

/// Phase data for `ReconstructionState::AwaitingQuorum`.
struct AwaitingQuorumState<C>
where
    C: Segmentable,
{
    common: CommonState<C>,
    /// Checked chunks per segment, keyed by shard index, sized once the roots are verified.
    chunks: Vec<BTreeMap<u16, SizedChunk<C>>>,
    /// Whether a job took the checked chunks. Its decode either caches the block or removes the
    /// record, so later chunks of other shards cannot help.
    chunks_taken: bool,
    /// The in-flight reconstruction job. Dropping it discards the job's result.
    job: Option<Aborter>,
}

/// Phase data for `ReconstructionState::Ready`.
///
/// The block is cached and no chunks are retained. Only the assigned shard's chunks are still
/// recorded.
struct ReadyState<C>
where
    C: Segmentable,
{
    common: CommonState<C>,
}

impl<C> ReconstructionState<C>
where
    C: Segmentable,
{
    /// Create an initial reconstruction state for a commitment.
    const fn new() -> Self {
        Self::AwaitingQuorum(AwaitingQuorumState {
            common: CommonState {
                notify_assigned: false,
                assigned_shard_verified: false,
                roots: None,
                assigned_chunks: BitMap::new(),
            },
            chunks: Vec::new(),
            chunks_taken: false,
            job: None,
        })
    }

    /// Ends chunk accumulation once the block is cached, dropping the checked chunks and
    /// discarding the result of any in-flight job.
    fn into_ready(self) -> Self {
        match self {
            Self::AwaitingQuorum(state) => Self::Ready(ReadyState {
                common: state.common,
            }),
            ready @ Self::Ready(_) => ready,
        }
    }

    /// Access common state shared across all phases.
    const fn common(&self) -> &CommonState<C> {
        match self {
            Self::AwaitingQuorum(state) => &state.common,
            Self::Ready(state) => &state.common,
        }
    }

    /// Mutably access common state shared across all phases.
    const fn common_mut(&mut self) -> &mut CommonState<C> {
        match self {
            Self::AwaitingQuorum(state) => &mut state.common,
            Self::Ready(state) => &mut state.common,
        }
    }

    /// Returns whether the shard for our assigned index has been verified.
    const fn is_assigned_shard_verified(&self) -> bool {
        self.common().assigned_shard_verified
    }

    /// Records a chunk checked against the root of segment `segment` in `roots`, which hash to
    /// the commitment's coding root, and returns whether it was recorded.
    ///
    /// A chunk of our assigned shard marks its segment verified, and verifies the assigned shard
    /// once every segment is. Chunks of any shard contribute to reconstruction while awaiting
    /// quorum, until a job takes them.
    fn record_chunk(
        &mut self,
        roots: &[C::Commitment],
        segment: u16,
        index: u16,
        chunk: SizedChunk<C>,
        is_assigned_chunk: bool,
    ) -> bool {
        match &self.common().roots {
            Some(installed) if installed.as_slice() != roots => return false,
            Some(_) => {}
            None => {
                let common = self.common_mut();
                common.assigned_chunks = BitMap::zeroes(roots.len() as u64);
                common.roots = Some(roots.to_vec());
                if let Self::AwaitingQuorum(state) = self {
                    state.chunks = iter::repeat_with(BTreeMap::new).take(roots.len()).collect();
                }
            }
        }
        let recorded = if is_assigned_chunk {
            let common = self.common_mut();
            let fresh = !common.assigned_chunks.get(u64::from(segment));
            if fresh {
                common.assigned_chunks.set(u64::from(segment), true);
                if common.assigned_chunks.count_zeros() == 0 {
                    common.assigned_shard_verified = true;
                    common.notify_assigned = true;
                }
            }
            fresh
        } else {
            false
        };
        match self {
            Self::AwaitingQuorum(state)
                if !state.chunks_taken
                    && !state.chunks[usize::from(segment)].contains_key(&index) =>
            {
                state.chunks[usize::from(segment)].insert(index, chunk);
                true
            }
            _ => recorded,
        }
    }
}

impl<C> AwaitingQuorumState<C>
where
    C: Segmentable,
{
    /// Takes the checked chunks for decoding once every segment holds at least `minimum` of
    /// them, keeping `minimum` per segment.
    fn take_decodable_chunks(&mut self, minimum: usize) -> Option<Vec<SizedChunk<C>>> {
        if self.chunks_taken
            || self.chunks.is_empty()
            || self.chunks.iter().any(|segment| segment.len() < minimum)
        {
            return None;
        }
        self.chunks_taken = true;
        Some(
            mem::take(&mut self.chunks)
                .into_iter()
                .flat_map(|segment| segment.into_values().take(minimum))
                .collect(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        marshal::{
            coding::{Coding, types::coding_config_for_participants},
            core::Variant,
            mocks::{
                block::{EmptyBlock, encode_block},
                harness::{CodingB, TestCoding},
            },
        },
        types::{Epoch, Height, View},
    };
    use bytes::Bytes;
    use commonware_codec::{Decode, Encode as _};
    use commonware_coding::{Config as CodingConfig, EncodedSegment, Segmented};
    use commonware_cryptography::{
        Committable, Digest, Sha256, Signer,
        certificate::{Membership, Scoped, Subject},
        ed25519::{PrivateKey, PublicKey},
        impl_certificate_ed25519,
        sha256::Digest as Sha256Digest,
    };
    use commonware_macros::{select, test_traced};
    use commonware_p2p::{
        Manager as _, TrackedPeers,
        simulated::{self, Control, Link, Oracle},
    };
    use commonware_parallel::{Rayon, Sequential, mocks::Explorer, rayon::ThreadPoolBuilder};
    use commonware_runtime::{Quota, Runner, Supervisor as _, deterministic, utils::reschedule};
    use commonware_utils::{
        N3f1, NZU16, NZU32, NZUsize, Participant, channel::oneshot::error::TryRecvError,
        ordered::Set, probability, sync::Mutex,
    };
    use futures::FutureExt as _;
    use std::{
        future::Future,
        marker::PhantomData,
        num::NonZeroUsize,
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

    /// Returns the largest stream or roots message coding with `S` produces for the largest [`B`]
    /// its codec decodes, over committees of 4 to `participants` members.
    fn stream_bound<S: Segmentable>(participants: usize) -> usize {
        let payload = CodedBlock::<B, S, H>::max_encode_size(B::max_encode_size(&()));
        (4..=u16::try_from(participants).unwrap())
            .map(|n| {
                ShardMessage::<B, S, H>::max_encode_size(
                    S::max_chunk_size(&coding_config_for_participants(n), payload),
                    S::segments(payload),
                )
            })
            .max()
            .expect("committee must have at least 4 members")
    }

    /// Returns a simulated network configuration for committees of at most `participants` members,
    /// sized by the coding buffer's bound and the shard messages of [`C`] and [`SC`] for the
    /// largest [`B`] its codec decodes. The other test coding schemes delegate their widths to
    /// `C`, so the bound covers them too.
    fn network_config(participants: usize) -> simulated::Config {
        // `CodingB` supplies the context type the coding variant requires, and both bounds use
        // the encoded size of the largest `B`.
        let application = B::max_encode_size(&());
        simulated::Config {
            max_size: commonware_p2p::max_message_size([
                <Coding<CodingB, C, H, P> as Variant>::max_buffer_payload_size(
                    u32::try_from(participants).unwrap(),
                    application,
                ),
                stream_bound::<C>(participants),
                stream_bound::<SC>(participants),
            ]),
            max_peers_per_set: NZUsize!(participants),
            disconnect_on_block: true,
            tracked_peer_sets: NZUsize!(1),
        }
    }

    /// The default link configuration for tests.
    const DEFAULT_LINK: Link = Link {
        latency: Duration::from_millis(50),
        jitter: Duration::ZERO,
        success_rate: probability!(1.0),
    };

    /// Per-peer rate. Its burst sizes the derived channel capacities, so every test must stay
    /// below it for one peer within one second of simulated time.
    const TEST_QUOTA: Quota = Quota::per_second(NZU32!(1_024));

    /// The parallelization strategy used for tests.
    const STRATEGY: Sequential = Sequential;

    /// A scheme provider that maps each epoch to a potentially different scheme.
    ///
    /// For most tests only epoch 0 is registered. Cross-epoch tests register additional epochs
    /// with different participant sets.
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
    type C = TestCoding;
    type X = Control<P, deterministic::Context>;
    type O = Oracle<P, deterministic::Context>;
    type Prov = MultiEpochProvider;
    type NetworkSender = simulated::Sender<P, deterministic::Context>;
    type D = simulated::Manager<P, deterministic::Context>;
    type ShardEngine<S, T = Sequential> = Engine<deterministic::Context, Prov, X, D, S, H, B, P, T>;
    type ChurningShardEngine<S> =
        Engine<deterministic::Context, ChurningProvider, X, D, S, H, B, P, Sequential>;
    type EngineSender<S> = WrappedSender<NetworkSender, ShardMessage<B, S, H>>;

    /// Segmented coding whose segments are small enough that a test block spans several.
    type SC = Segmented<H, 16>;

    /// An armed [`GATE`].
    struct Gate {
        /// Signals that decode started.
        started: mpsc::Sender<()>,
        /// Releases the held decode.
        release: mpsc::Receiver<()>,
        /// The engine thread, which decode must not run on.
        engine: thread::ThreadId,
    }

    /// Holds [`Gated::decode_chunks`] until released.
    static GATE: Mutex<Option<Gate>> = Mutex::new(None);

    /// [`C`] coding whose chunk decode holds while [`GATE`] is armed.
    #[derive(Clone, Debug)]
    struct Gated;

    impl CodingScheme for Gated {
        type Commitment = <C as CodingScheme>::Commitment;
        type Shard = <C as CodingScheme>::Shard;
        type CheckedShard = <C as CodingScheme>::CheckedShard;
        type Error = <C as CodingScheme>::Error;

        fn max_shard_size(config: &CodingConfig, data: usize) -> usize {
            C::max_shard_size(config, data)
        }

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
            strategy: &impl Strategy,
        ) -> Result<Self::CheckedShard, Self::Error> {
            C::check(config, commitment, index, shard, strategy)
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

    impl Segmentable for Gated {
        type Chunk = <C as Segmentable>::Chunk;
        type CheckedChunk = <C as Segmentable>::CheckedChunk;
        type Encoder = <C as Segmentable>::Encoder;

        fn segments(data: usize) -> u16 {
            C::segments(data)
        }

        fn max_chunk_size(config: &CodingConfig, data: usize) -> usize {
            C::max_chunk_size(config, data)
        }

        fn split(shard: &Self::Shard) -> (Vec<Self::Commitment>, Vec<Self::Chunk>) {
            C::split(shard)
        }

        fn commit(roots: &[Self::Commitment]) -> Self::Commitment {
            C::commit(roots)
        }

        fn check_chunk(
            config: &CodingConfig,
            root: &Self::Commitment,
            index: u16,
            segment: u16,
            chunk: &Self::Chunk,
        ) -> Result<Self::CheckedChunk, Self::Error> {
            C::check_chunk(config, root, index, segment, chunk)
        }

        fn decode_chunks<'a>(
            config: &CodingConfig,
            commitment: &Self::Commitment,
            roots: &[Self::Commitment],
            chunks: impl Iterator<Item = &'a Self::CheckedChunk>,
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
            C::decode_chunks(config, commitment, roots, chunks, strategy)
        }

        fn encoder(config: CodingConfig) -> Self::Encoder {
            C::encoder(config)
        }

        fn push(
            encoder: &mut Self::Encoder,
            bytes: &[u8],
            strategy: &impl Strategy,
        ) -> Result<Vec<EncodedSegment<Self::Commitment, Self::Chunk>>, Self::Error> {
            C::push(encoder, bytes, strategy)
        }

        #[allow(clippy::type_complexity)]
        fn finish(
            encoder: Self::Encoder,
            strategy: &impl Strategy,
        ) -> Result<
            (
                Self::Commitment,
                Vec<Self::Commitment>,
                Option<EncodedSegment<Self::Commitment, Self::Chunk>>,
            ),
            Self::Error,
        > {
            C::finish(encoder, strategy)
        }

        fn assemble_shards(
            roots: Vec<Self::Commitment>,
            segments: Vec<EncodedSegment<Self::Commitment, Self::Chunk>>,
        ) -> Vec<Self::Shard> {
            C::assemble_shards(roots, segments)
        }
    }

    /// Returns the chunks of shard `index` of `block` streamed in `round`, in segment order.
    fn stream_of<S: Segmentable>(
        block: &CodedBlock<B, S, H>,
        round: Round,
        index: u16,
    ) -> Vec<StreamChunk<S>> {
        let (roots, chunks) = S::split(&block.shards(&STRATEGY)[usize::from(index)]);
        chunks
            .into_iter()
            .zip(roots)
            .enumerate()
            .map(|(segment, (chunk, root))| StreamChunk {
                config: block.config(),
                round,
                index,
                segment: segment as u16,
                root,
                chunk,
            })
            .collect()
    }

    /// Returns the roots that bind the chunks of `block` streamed in `round` to its commitment.
    fn roots_of<S: Segmentable>(block: &CodedBlock<B, S, H>, round: Round) -> StreamRoots<B, S, H> {
        StreamRoots {
            commitment: block.commitment(),
            round,
            roots: S::split(&block.shards(&STRATEGY)[0]).0,
        }
    }

    /// Returns the messages the leader of `round` sends the holder of shard `index` of `block`:
    /// the shard's chunks in segment order, then the roots.
    fn assigned<S: Segmentable>(
        block: &CodedBlock<B, S, H>,
        round: Round,
        index: u16,
    ) -> Vec<ShardMessage<B, S, H>> {
        stream_of(block, round, index)
            .into_iter()
            .map(ShardMessage::from)
            .chain(iter::once(roots_of(block, round).into()))
            .collect()
    }

    /// Returns the messages the holder of shard `index` of `block` relays to its peers.
    fn relayed<S: Segmentable>(
        block: &CodedBlock<B, S, H>,
        round: Round,
        index: u16,
    ) -> Vec<ShardMessage<B, S, H>> {
        stream_of(block, round, index)
            .into_iter()
            .map(ShardMessage::from)
            .collect()
    }

    /// Sends every message over `sender` to `recipient`, encoded as the engine's wire format.
    fn send<S: Segmentable>(
        sender: &mut NetworkSender,
        recipient: &P,
        messages: impl IntoIterator<Item = ShardMessage<B, S, H>>,
    ) {
        for message in messages {
            let _ = sender.send(Recipients::One(recipient.clone()), message.encode(), true);
        }
    }

    /// Hands every message to `engine` as if received from `peer`.
    fn receive<S: Segmentable, T: Strategy>(
        engine: &mut ShardEngine<S, T>,
        sender: &mut EngineSender<S>,
        peer: &P,
        messages: impl IntoIterator<Item = ShardMessage<B, S, H>>,
    ) {
        for message in messages {
            engine.handle_network_message(sender, peer.clone(), message);
        }
    }

    /// Makes `leader` the known leader of every round.
    fn elect<S: Segmentable, T: Strategy>(engine: &mut ShardEngine<S, T>, leader: &P) {
        let leader = leader.clone();
        engine.leader = Arc::new(move |_| Some(leader.clone()));
    }

    /// Waits for the next message sent to `observer`, or `None` if none arrives within a few
    /// link latencies.
    async fn next_message<S: Segmentable>(
        context: &deterministic::Context,
        observer: &mut simulated::Receiver<P>,
    ) -> Option<ShardMessage<B, S, H>> {
        select! {
            message = observer.recv() => {
                let (_, bytes) = message.expect("observer must stay open");
                Some(
                    ShardMessage::<B, S, H>::decode_cfg(
                        commonware_codec::Copying(bytes.as_ref()),
                        &B::max_encode_size(&()),
                    )
                    .expect("message must decode"),
                )
            },
            _ = context.sleep(DEFAULT_LINK.latency * 4) => None,
        }
    }

    /// Sequential execution that records the `len` of each spawned job.
    #[derive(Clone, Debug, Default)]
    struct Recording {
        lens: Arc<Mutex<Vec<usize>>>,
    }

    impl Strategy for Recording {
        fn spawn<F, T>(&self, len: usize, f: F) -> impl Future<Output = T> + Send + 'static
        where
            F: FnOnce(Self) -> T + Send + 'static,
            T: Send + 'static,
        {
            self.lens.lock().push(len);
            let strategy = self.clone();
            Sequential.spawn(len, move |_| f(strategy))
        }

        fn run<R, SEQ, PAR>(&self, len: usize, serial: SEQ, parallel: PAR) -> R
        where
            R: Send,
            SEQ: FnOnce() -> R + Send,
            PAR: FnOnce() -> R + Send,
        {
            Sequential.run(len, serial, parallel)
        }

        fn try_run<R, E, SEQ, PAR>(&self, len: usize, serial: SEQ, parallel: PAR) -> Result<R, E>
        where
            R: Send,
            E: Send,
            SEQ: FnOnce() -> Result<R, E> + Send,
            PAR: FnOnce() -> Result<R, E> + Send,
        {
            Sequential.try_run(len, serial, parallel)
        }

        fn fold_init<I, INIT, T, R, ID, F, RD>(
            &self,
            iter: I,
            init: INIT,
            identity: ID,
            fold_op: F,
            reduce_op: RD,
        ) -> R
        where
            I: IntoIterator<IntoIter: Send, Item: Send> + Send,
            INIT: Fn() -> T + Send + Sync,
            T: Send,
            R: Send,
            ID: Fn() -> R + Send + Sync,
            F: Fn(R, &mut T, I::Item) -> R + Send + Sync,
            RD: Fn(R, R) -> R + Send + Sync,
        {
            Sequential.fold_init(iter, init, identity, fold_op, reduce_op)
        }

        fn try_fold<I, R, E, ID, F, RD>(
            &self,
            iter: I,
            identity: ID,
            fold_op: F,
            reduce_op: RD,
        ) -> Result<R, E>
        where
            I: IntoIterator<IntoIter: Send, Item: Send> + Send,
            R: Send,
            E: Send,
            ID: Fn() -> R + Send + Sync,
            F: Fn(R, I::Item) -> Result<R, E> + Send + Sync,
            RD: Fn(R, R) -> R + Send + Sync,
        {
            Sequential.try_fold(iter, identity, fold_op, reduce_op)
        }

        fn join<A, Z, RA, RZ>(&self, a: A, z: Z) -> (RA, RZ)
        where
            A: FnOnce() -> RA + Send,
            Z: FnOnce() -> RZ + Send,
            RA: Send,
            RZ: Send,
        {
            Sequential.join(a, z)
        }

        fn sort_by<T, F>(&self, items: &mut [T], compare: F)
        where
            T: Send,
            F: Fn(&T, &T) -> std::cmp::Ordering + Send + Sync,
        {
            Sequential.sort_by(items, compare)
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
    struct Peer<S: Segmentable = C> {
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
    struct NonParticipant<S: Segmentable = C> {
        /// The peer's public key.
        public_key: PublicKey,
        /// The mailbox for sending messages to the peer's shard engine.
        mailbox: Mailbox<B, S, H, P>,
        /// Raw network sender for injecting messages.
        sender: NetworkSender,
    }

    /// Test fixture for setting up multiple participants with shard engines.
    struct Fixture<S: Segmentable = C> {
        /// Number of primary peers created during setup.
        num_primary_peers: usize,
        /// Index of a primary peer that holds no signing share in the initial epoch. Its
        /// engine runs a member scheme that reports the peer's membership but cannot sign.
        shareless_member: Option<usize>,
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
        /// Index of the primary peer every engine knows in advance to lead every round, through
        /// [`Config::leader`], or `None` for engines that learn leaders only from discovery.
        round_leader: Option<usize>,
        /// Marker for the coding scheme type parameter.
        _marker: PhantomData<S>,
    }

    impl<S: Segmentable> Default for Fixture<S> {
        fn default() -> Self {
            Self {
                num_primary_peers: 4,
                shareless_member: None,
                num_secondary_peers: 0,
                num_future_peers: 0,
                additional_scheme_epochs: Vec::new(),
                link: DEFAULT_LINK,
                peer_buffer_size: NZUsize!(64),
                records: NZUsize!(16),
                round_leader: None,
                _marker: PhantomData,
            }
        }
    }

    impl<S: Segmentable> Fixture<S> {
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
                let round_leader: RoundLeader<P> = match self.round_leader {
                    Some(index) => {
                        let leader = peer_keys[index].clone();
                        Arc::new(move |_| Some(leader.clone()))
                    }
                    None => Arc::new(|_| None),
                };

                let mut np_private_keys = (0..self.num_secondary_peers)
                    .map(|i| PrivateKey::from_seed((self.num_primary_peers + i) as u64))
                    .collect::<Vec<_>>();
                np_private_keys.sort_by_key(|s| s.public_key());
                let np_keys: Vec<P> = np_private_keys.iter().map(|k| k.public_key()).collect();

                let max_peers_per_set =
                    self.num_primary_peers + self.num_secondary_peers.max(self.num_future_peers);
                let (network, oracle) =
                    simulated::Network::<deterministic::Context, P>::new_with_split_peers(
                        context.child("network"),
                        simulated::Config {
                            max_peers_per_set: NZUsize!(max_peers_per_set),
                            ..network_config(self.num_primary_peers)
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

                    let scheme = if self.shareless_member == Some(idx) {
                        Scheme::member(SCHEME_NAMESPACE, participants.clone(), peer_key)
                            .expect("shareless member must be a participant")
                    } else {
                        Scheme::signer(
                            SCHEME_NAMESPACE,
                            participants.clone(),
                            private_keys[idx].clone(),
                        )
                        .expect("signer scheme must be created")
                    };
                    let mut scheme_provider = MultiEpochProvider::single(scheme);
                    for epoch in self.additional_scheme_epochs.iter().copied() {
                        let scheme = Scheme::signer(
                            SCHEME_NAMESPACE,
                            participants.clone(),
                            private_keys[idx].clone(),
                        )
                        .expect("signer scheme must be created");
                        scheme_provider = scheme_provider.with_epoch(epoch, scheme);
                    }

                    let config = Config {
                        scheme_provider,
                        blocker: control.clone(),
                        block_codec_config: (),
                        strategy: STRATEGY,
                        mailbox_size: NZUsize!(1024),
                        peer_buffer_size: self.peer_buffer_size,
                        records: self.records,
                        peer_provider: oracle.manager(),
                        leader: round_leader.clone(),
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
                        block_codec_config: (),
                        strategy: STRATEGY,
                        mailbox_size: NZUsize!(1024),
                        peer_buffer_size: self.peer_buffer_size,
                        records: self.records,
                        peer_provider: oracle.manager(),
                        leader: round_leader.clone(),
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

    /// Builds an unstarted engine on `strategy` for the participant at `index` and the sender its
    /// handlers take. Every participant is a tracked primary.
    async fn unstarted<T: Strategy>(
        context: &deterministic::Context,
        oracle: &O,
        private_keys: &[PrivateKey],
        index: usize,
        records: NonZeroUsize,
        strategy: T,
    ) -> (ShardEngine<C, T>, EngineSender<C>) {
        unstarted_with(context, oracle, private_keys, index, records, strategy).await
    }

    /// Builds an unstarted engine coding with `S`, as [`unstarted`] does.
    async fn unstarted_with<S: Segmentable, T: Strategy>(
        context: &deterministic::Context,
        oracle: &O,
        private_keys: &[PrivateKey],
        index: usize,
        records: NonZeroUsize,
        strategy: T,
    ) -> (ShardEngine<S, T>, EngineSender<S>) {
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
        .expect("signer scheme must be created");
        let config: Config<_, _, _, _, _, _> = Config {
            scheme_provider: MultiEpochProvider::single(scheme),
            blocker: control,
            block_codec_config: (),
            strategy,
            mailbox_size: NZUsize!(16),
            peer_buffer_size: NZUsize!(4),
            records,
            peer_provider: oracle.manager(),
            leader: Arc::new(|_| None),
        };
        let (mut engine, _) = ShardEngine::new(context.child("engine"), config);
        engine.update_primary_peers(participants);
        let sender = WrappedSender::new(sender);
        (engine, sender)
    }

    /// Returns the number of messages for `round` buffered from `peer`.
    fn buffered<S: Segmentable, T: Strategy>(
        engine: &ShardEngine<S, T>,
        peer: &P,
        round: Round,
    ) -> usize {
        engine.peer_buffers.get(peer).map_or(0, |queue| {
            queue
                .iter()
                .filter(|message| message.round() == round)
                .count()
        })
    }

    /// Waits for the next job of `engine` to finish and returns its result.
    async fn finished<S: Segmentable, T: Strategy>(
        engine: &mut ShardEngine<S, T>,
    ) -> Reconstructed<B, S, H> {
        assert!(!engine.jobs.is_empty(), "engine must hold a job");
        loop {
            if let Some(result) = engine.jobs.next_completed().now_or_never() {
                return result.expect("job result must not be discarded");
            }
            reschedule().await;
        }
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
    /// Every participant verifies its assigned shard and reconstructs the block a leader
    /// proposes once it discovers the proposal.
    #[test_traced]
    fn test_e2e_broadcast_and_reconstruction() {
        let fixture = Fixture {
            num_primary_peers: 10,
            ..Default::default()
        };

        fixture.start(
            |config, context, _, mut peers, _, coding_config| async move {
                let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block = encode_block::<B, C, H>(inner.clone(), coding_config);
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

    /// Subscriptions by commitment and by digest made before a proposal resolve once the block
    /// is reconstructed.
    #[test_traced]
    fn test_block_subscriptions() {
        let fixture = Fixture {
            num_primary_peers: 10,
            ..Default::default()
        };

        fixture.start(
            |config, context, _, mut peers, _, coding_config| async move {
                let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block = encode_block::<B, C, H>(inner.clone(), coding_config);
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

    /// Subscriptions the proposer makes before proposing resolve once it caches its own block.
    #[test_traced]
    fn test_proposer_preproposal_subscriptions_resolve_after_local_cache() {
        let fixture = Fixture {
            num_primary_peers: 10,
            ..Default::default()
        };

        fixture.start(|config, context, _, peers, _, coding_config| async move {
            let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
            let coded_block = encode_block::<B, C, H>(inner.clone(), coding_config);
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

    /// A chunk a non-leader sends for an index it does not own blocks the sender and leaves the
    /// receiver's assigned shard unverified until the leader delivers it.
    #[test_traced]
    fn test_shard_subscription_rejects_invalid_shard() {
        let fixture = Fixture::<C>::default();
        fixture.start(
            |config, context, oracle, mut peers, _, coding_config| async move {
                // peers[0] = byzantine
                // peers[1] = honest proposer
                // peers[2] = receiver

                let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block = encode_block::<B, C, H>(inner.clone(), coding_config);
                let commitment = coded_block.commitment();
                let round = Round::new(Epoch::zero(), View::new(1));
                let receiver_index = peers[2].index.get() as u16;

                // The byzantine peer claims the index of peers[3], which it does not own.
                let mut invalid = stream_of(&coded_block, round, receiver_index).remove(0);
                invalid.index = peers[3].index.get() as u16;

                // Receiver subscribes to their shard and learns the leader.
                let receiver_pk = peers[2].public_key.clone();
                let leader = peers[1].public_key.clone();
                peers[2].mailbox.discovered(commitment, leader, round);
                let mut shard_sub = peers[2]
                    .mailbox
                    .subscribe_assigned_shard_verified(commitment);

                send::<C>(&mut peers[0].sender, &receiver_pk, [invalid.into()]);
                context.sleep(config.link.latency * 2).await;

                assert!(
                    matches!(shard_sub.try_recv(), Err(TryRecvError::Empty)),
                    "subscription should not resolve from invalid chunk"
                );
                assert_blocked(&oracle, &peers[2].public_key, &peers[0].public_key).await;

                // Honest proposer sends the receiver its chunk and the roots.
                send(
                    &mut peers[1].sender,
                    &receiver_pk,
                    assigned(&coded_block, round, receiver_index),
                );
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
                let inner = B::new(Sha256Digest::EMPTY, Height::new(id), id);
                encode_block::<B, C, H>(inner, coding_config)
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
                let inner = B::new(Sha256Digest::EMPTY, Height::new(id), id);
                encode_block::<B, C, H>(inner, coding_config)
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
            let mut verified = peers[2]
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
            assert!(matches!(verified.try_recv(), Err(TryRecvError::Empty)));
            assert!(matches!(subscription.try_recv(), Err(TryRecvError::Empty)));

            // Rediscovery at view 5 recreates the record. The leader's chunk for the receiver,
            // one relayed chunk, and the leader's roots reconstruct the block and resolve both
            // subscriptions.
            peers[2].mailbox.discovered(commitment, leader, round(5));
            let receiver_index = peers[2].index.get() as u16;
            let relayer_index = peers[1].index.get() as u16;
            send(
                &mut peers[0].sender,
                &receiver_pk,
                assigned(&block, round(5), receiver_index),
            );
            send(
                &mut peers[1].sender,
                &receiver_pk,
                relayed(&block, round(5), relayer_index),
            );
            verified.await.expect("assigned shard should be verified");
            let reconstructed = subscription.await.expect("block should be reconstructed");
            assert_eq!(reconstructed.commitment(), commitment);
            assert!(oracle.blocked().await.unwrap().is_empty());
        });
    }

    /// Subquorum reconstruction state survives records for `records - 1` later views and is
    /// evicted by the next, which also drops its round's stream. Its block subscription stays
    /// open, and its last chunk then enters the sender's buffer without rebuilding the block.
    #[test_traced]
    fn test_subquorum_reconstruction_evicted_by_window() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (network, oracle) = simulated::Network::<deterministic::Context, P>::new(
                context.child("network"),
                network_config(10),
            );
            network.start();

            let mut private_keys: Vec<PrivateKey> = (0..10).map(PrivateKey::from_seed).collect();
            private_keys.sort_by_key(|key| key.public_key());
            let peer_keys: Vec<P> = private_keys.iter().map(|key| key.public_key()).collect();
            let records = NZUsize!(4);
            let (mut engine, mut sender) =
                unstarted(&context, &oracle, &private_keys, 3, records, STRATEGY).await;
            let coding_config = coding_config_for_participants(peer_keys.len() as u16);
            let make_block = |id| {
                let inner = B::new(Sha256Digest::EMPTY, Height::new(id), id);
                encode_block::<B, C, H>(inner, coding_config)
            };
            let round = |view| Round::new(Epoch::zero(), View::new(view));
            let leader = peer_keys[0].clone();

            // The candidate at view 10 receives three of the four chunks needed.
            let block = make_block(1);
            let commitment = block.commitment();
            let candidate = round(10);
            engine.handle_external_proposal(&mut sender, commitment, leader.clone(), candidate);
            let (response, mut subscription) = oneshot::channel();
            engine
                .handle_block_subscription(BlockSubscriptionKey::Commitment(commitment), response);
            for index in [1, 2, 4] {
                let relayer = &peer_keys[usize::from(index)];
                receive(
                    &mut engine,
                    &mut sender,
                    relayer,
                    relayed(&block, candidate, index),
                );
            }
            receive(
                &mut engine,
                &mut sender,
                &leader,
                [roots_of(&block, candidate).into()],
            );
            let Some(ReconstructionState::AwaitingQuorum(state)) = engine
                .records
                .get(&commitment)
                .and_then(CommitmentRecord::reconstruction)
            else {
                panic!("candidate must await quorum");
            };
            assert_eq!(state.chunks[0].len(), 3);
            assert!(engine.jobs.is_empty());

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

            // The record for the next view evicts the candidate and its round's stream. Its block
            // subscription stays open.
            engine.handle_external_proposal(
                &mut sender,
                make_block(14).commitment(),
                leader,
                round(14),
            );
            engine.trim();
            assert!(!engine.records.contains_key(&commitment));
            assert!(!engine.streams.contains_key(&candidate));
            assert_eq!(engine.records.len(), records.get());
            assert!(matches!(subscription.try_recv(), Err(TryRecvError::Empty)));

            // The round's leader is no longer known, so the last chunk enters its sender's buffer
            // and rebuilds nothing.
            let sender_key = peer_keys[5].clone();
            receive(
                &mut engine,
                &mut sender,
                &sender_key,
                relayed(&block, candidate, 5),
            );
            assert_eq!(buffered(&engine, &sender_key, candidate), 1);
            assert!(!engine.records.contains_key(&commitment));
            assert!(engine.jobs.is_empty());
            assert!(matches!(subscription.try_recv(), Err(TryRecvError::Empty)));
            assert!(oracle.blocked().await.unwrap().is_empty());
        });
    }

    /// Once the window is full, a notarization or discovery at or below its lowest round creates
    /// no record and opens no stream, leaving the round's chunks in their sender's buffer, and a
    /// block from such a round still resolves its subscribers. A notarization above the lowest
    /// round creates the record and opens the round's stream, which takes the senders' own
    /// chunks, and roots for the commitment move them into the record.
    #[test_traced]
    fn test_full_window_declines_rounds_at_or_below_lowest() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (network, oracle) = simulated::Network::<deterministic::Context, P>::new(
                context.child("network"),
                network_config(4),
            );
            network.start();

            let mut private_keys: Vec<PrivateKey> = (0..4).map(PrivateKey::from_seed).collect();
            private_keys.sort_by_key(|key| key.public_key());
            let peer_keys: Vec<P> = private_keys.iter().map(|key| key.public_key()).collect();
            let records = NZUsize!(2);
            let (mut engine, mut sender) =
                unstarted(&context, &oracle, &private_keys, 0, records, STRATEGY).await;
            let coding_config = coding_config_for_participants(peer_keys.len() as u16);
            let make_block = |id| {
                let inner = B::new(Sha256Digest::EMPTY, Height::new(id), id);
                encode_block::<B, C, H>(inner, coding_config)
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

            // Relayed chunks of rounds without a stream record enter their sender's buffer.
            let block = make_block(1);
            let commitment = block.commitment();
            let gossiper = peer_keys[1].clone();
            for view in [4, 7] {
                receive(
                    &mut engine,
                    &mut sender,
                    &gossiper,
                    relayed(&block, round(view), 1),
                );
                assert_eq!(buffered(&engine, &gossiper, round(view)), 1, "view {view}");
            }

            // Notarizations at and below the lowest retained view create no record, and the
            // chunk stays buffered.
            for view in [5, 4] {
                engine.handle_notarized_commitment(&mut sender, commitment, round(view));
                engine.trim();
                assert!(!engine.records.contains_key(&commitment), "view {view}");
                assert_eq!(buffered(&engine, &gossiper, round(4)), 1, "view {view}");
            }

            // A discovery below the lowest retained view creates neither a record nor a stream,
            // so its leader drains no buffered chunk.
            let leader = peer_keys[2].clone();
            engine.handle_external_proposal(&mut sender, commitment, leader.clone(), round(4));
            engine.trim();
            assert!(!engine.records.contains_key(&commitment));
            assert!(!engine.streams.contains_key(&round(4)));
            assert_eq!(buffered(&engine, &gossiper, round(4)), 1);

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

            // A notarization above the lowest retained view creates the record, and the window
            // then evicts view 5. The notarization opens the round's stream, which takes the
            // gossiper's own chunk although the round's leader is unknown.
            engine.handle_notarized_commitment(&mut sender, commitment, round(7));
            engine.trim();
            assert!(engine.records.contains_key(&commitment));
            assert_eq!(buffered(&engine, &gossiper, round(7)), 0);
            assert_eq!(engine.records.len(), records.get());
            assert!(
                engine
                    .records
                    .values()
                    .all(|record| record.round() > round(5))
            );

            // Roots for the notarized commitment move the chunk into the record.
            receive(
                &mut engine,
                &mut sender,
                &leader,
                [roots_of(&block, round(7)).into()],
            );
            let Some(ReconstructionState::AwaitingQuorum(state)) = engine
                .records
                .get(&commitment)
                .and_then(CommitmentRecord::reconstruction)
            else {
                panic!("record must await quorum");
            };
            assert!(state.chunks[0].contains_key(&1));
            assert!(oracle.blocked().await.unwrap().is_empty());
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
                let inner = B::new(Sha256Digest::EMPTY, Height::new(id), id);
                encode_block::<B, C, H>(inner, coding_config)
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
                    let block = {
                        let inner = B::new(Sha256Digest::EMPTY, Height::new(view), view);
                        encode_block::<B, C, H>(inner.clone(), coding_config)
                    };
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
                let inner = B::new(Sha256Digest::EMPTY, Height::new(id), id);
                encode_block::<B, C, H>(inner, coding_config)
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
                network_config(4),
            );
            network.start();

            let mut private_keys: Vec<PrivateKey> = (0..4).map(PrivateKey::from_seed).collect();
            private_keys.sort_by_key(|key| key.public_key());
            let peer_keys: Vec<P> = private_keys.iter().map(|key| key.public_key()).collect();
            let (mut engine, mut sender) =
                unstarted(&context, &oracle, &private_keys, 2, NZUsize!(4), STRATEGY).await;
            let coding_config = coding_config_for_participants(peer_keys.len() as u16);
            let make_block = |id| {
                let inner = B::new(Sha256Digest::EMPTY, Height::new(id), id);
                encode_block::<B, C, H>(inner, coding_config)
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

    /// Caching a reconstructed block drops its record's chunks. A repeated or conflicting chunk
    /// is then ignored without blocking its sender, and a late assigned chunk is still verified
    /// and relayed without being retained.
    #[test_traced]
    fn test_cached_record_retains_no_shards() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (network, oracle) = simulated::Network::<deterministic::Context, P>::new(
                context.child("network"),
                network_config(4),
            );
            network.start();

            let mut private_keys: Vec<PrivateKey> = (0..4).map(PrivateKey::from_seed).collect();
            private_keys.sort_by_key(|key| key.public_key());
            let peer_keys: Vec<P> = private_keys.iter().map(|key| key.public_key()).collect();
            let participants: Set<P> = Set::from_iter_dedup(peer_keys.clone());
            let (mut engine, mut sender) =
                unstarted(&context, &oracle, &private_keys, 0, NZUsize!(16), STRATEGY).await;

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
            let block = {
                let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                encode_block::<B, C, H>(inner, coding_config)
            };
            let commitment = block.commitment();
            let round = Round::new(Epoch::zero(), View::new(1));
            let leader = peer_keys[1].clone();

            // Relayed chunks from peers 2 and 3 and the leader's roots reconstruct the block
            // before the assigned chunk arrives.
            engine.handle_external_proposal(&mut sender, commitment, leader.clone(), round);
            for index in [2, 3] {
                let relayer = &peer_keys[usize::from(index)];
                receive(
                    &mut engine,
                    &mut sender,
                    relayer,
                    relayed(&block, round, index),
                );
            }
            receive(
                &mut engine,
                &mut sender,
                &leader,
                [roots_of(&block, round).into()],
            );
            let relay = next_message::<C>(&context, &mut observer).await;
            assert!(relay == Some(ShardMessage::Roots(roots_of(&block, round))));
            let reconstructed = finished(&mut engine).await;
            engine.complete(reconstructed);
            let record = engine.records.get(&commitment).expect("record must exist");
            assert!(record.block().is_some());
            assert!(matches!(
                record.reconstruction(),
                Some(ReconstructionState::Ready(_))
            ));
            assert!(engine.streams[&round].chunks.is_empty());

            // Another block's chunks are kept apart without blocking, both from peer 2 and from
            // the leader for the local index. The leader's may belong to a replacement
            // candidate, so they are relayed.
            let other = {
                let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 200);
                encode_block::<B, C, H>(inner, coding_config)
            };
            receive(
                &mut engine,
                &mut sender,
                &peer_keys[2],
                relayed(&other, round, 2),
            );
            receive(&mut engine, &mut sender, &leader, relayed(&other, round, 0));
            let kept = engine.streams[&round].chunks.len();
            assert_eq!(kept, 2 * stream_of(&other, round, 0).len());
            for chunk in stream_of(&other, round, 0) {
                let relay = next_message::<C>(&context, &mut observer).await;
                assert!(matches!(relay, Some(ShardMessage::Stream(relayed)) if relayed == chunk));
            }
            assert!(oracle.blocked().await.unwrap().is_empty());

            // The leader's late assigned chunk is verified, resolves readiness, and is relayed.
            let (response, mut verified) = oneshot::channel();
            engine.handle_assigned_shard_verified_subscription(commitment, response);
            assert!(matches!(verified.try_recv(), Err(TryRecvError::Empty)));
            let assigned = stream_of(&block, round, 0);
            receive(
                &mut engine,
                &mut sender,
                &leader,
                assigned.iter().cloned().map(ShardMessage::from),
            );
            assert!(matches!(verified.try_recv(), Ok(())));
            assert_eq!(engine.streams[&round].chunks.len(), kept);
            let relay = next_message::<C>(&context, &mut observer).await;
            assert!(matches!(relay, Some(ShardMessage::Stream(chunk)) if chunk == assigned[0]));
            assert!(oracle.blocked().await.unwrap().is_empty());
        });
    }

    /// A record a notarization creates without naming its round's leader reconstructs its block
    /// from an earlier round that proposed the same commitment, while the notarized round's
    /// delivery of the assigned chunk waits in its leader's buffer. Discovery of that leader then
    /// verifies and relays the chunk.
    #[test_traced]
    fn test_cached_leaderless_record_keeps_buffered_assigned_shard() {
        cached_leaderless_record_keeps_buffered_assigned_shard(false);
    }

    /// A committee member without a signing key still has an assigned shard, so the buffered
    /// chunk is verified and relayed exactly as it is for a signer.
    #[test_traced]
    fn test_member_cached_leaderless_record_keeps_buffered_assigned_shard() {
        cached_leaderless_record_keeps_buffered_assigned_shard(true);
    }

    fn cached_leaderless_record_keeps_buffered_assigned_shard(member: bool) {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (network, oracle) = simulated::Network::<deterministic::Context, P>::new(
                context.child("network"),
                network_config(4),
            );
            network.start();

            let mut private_keys: Vec<PrivateKey> = (0..4).map(PrivateKey::from_seed).collect();
            private_keys.sort_by_key(|key| key.public_key());
            let peer_keys: Vec<P> = private_keys.iter().map(|key| key.public_key()).collect();
            let participants: Set<P> = Set::from_iter_dedup(peer_keys.clone());
            let (mut engine, mut sender) =
                unstarted(&context, &oracle, &private_keys, 0, NZUsize!(16), STRATEGY).await;

            // Install the member's scheme before the engine handles any message, so every
            // handler observes the same role.
            if member {
                engine.scheme_provider = MultiEpochProvider::single(
                    Scheme::member(SCHEME_NAMESPACE, participants.clone(), &peer_keys[0])
                        .expect("local key must be a participant"),
                );
            }
            let index = participants
                .index(&peer_keys[0])
                .expect("local key must be a participant");
            let role = if member {
                Membership::Member(index)
            } else {
                Membership::Signer(index)
            };
            let scheme = engine
                .scheme_provider
                .scheme(Epoch::zero())
                .expect("epoch zero scheme must exist");
            assert_eq!(scheme.me(), Some(role));

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
            let block = {
                let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                encode_block::<B, C, H>(inner, coding_config)
            };
            let commitment = block.commitment();
            let proposed = Round::new(Epoch::zero(), View::new(1));
            let notarized = Round::new(Epoch::zero(), View::new(2));
            let proposer = peer_keys[1].clone();
            let leader = peer_keys[3].clone();

            // A notarization at view 2 creates a record without naming the round's leader. That
            // leader's delivery of the assigned chunk waits in the leader's buffer, while its
            // roots, which hash to the notarized commitment, bind the round and are relayed.
            engine.handle_notarized_commitment(&mut sender, commitment, notarized);
            let (response, mut verified) = oneshot::channel();
            engine.handle_assigned_shard_verified_subscription(commitment, response);
            receive(
                &mut engine,
                &mut sender,
                &leader,
                assigned(&block, notarized, 0),
            );
            assert_eq!(buffered(&engine, &leader, notarized), 1);
            let relay = next_message::<C>(&context, &mut observer).await;
            assert!(relay == Some(ShardMessage::Roots(roots_of(&block, notarized))));

            // The commitment was also proposed at view 1, whose discovered leader binds relayed
            // chunks from peers 2 and 3 to the record. They reconstruct the block, while the
            // assigned chunk stays buffered and readiness stays pending.
            engine.handle_external_proposal(&mut sender, commitment, proposer.clone(), proposed);
            for index in [2, 3] {
                let relayer = &peer_keys[usize::from(index)];
                receive(
                    &mut engine,
                    &mut sender,
                    relayer,
                    relayed(&block, proposed, index),
                );
            }
            receive(
                &mut engine,
                &mut sender,
                &proposer,
                [roots_of(&block, proposed).into()],
            );
            let reconstructed = finished(&mut engine).await;
            engine.complete(reconstructed);
            let record = engine.records.get(&commitment).expect("record must exist");
            assert!(record.block().is_some());
            assert_eq!(buffered(&engine, &leader, notarized), 1);
            assert!(matches!(verified.try_recv(), Err(TryRecvError::Empty)));
            let relay = next_message::<C>(&context, &mut observer).await;
            assert!(relay == Some(ShardMessage::Roots(roots_of(&block, proposed))));

            // Discovery names the view 2 leader and drains the buffered assigned chunk, which is
            // verified, resolves readiness, and is relayed.
            engine.handle_external_proposal(&mut sender, commitment, leader.clone(), notarized);
            assert_eq!(buffered(&engine, &leader, notarized), 0);
            assert!(matches!(verified.try_recv(), Ok(())));
            let assigned = stream_of(&block, notarized, 0).remove(0);
            let relay = next_message::<C>(&context, &mut observer).await;
            assert!(matches!(relay, Some(ShardMessage::Stream(chunk)) if chunk == assigned));
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
                network_config(4),
            );
            network.start();

            let mut private_keys: Vec<PrivateKey> = (0..4).map(PrivateKey::from_seed).collect();
            private_keys.sort_by_key(|key| key.public_key());
            let peer_keys: Vec<P> = private_keys.iter().map(|key| key.public_key()).collect();
            let (mut engine, mut sender) =
                unstarted(&context, &oracle, &private_keys, 0, NZUsize!(16), STRATEGY).await;
            let coding_config = coding_config_for_participants(peer_keys.len() as u16);

            // The commitment claims the digest of one block and the coding root of another.
            let claimed = {
                let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                encode_block::<B, C, H>(inner, coding_config)
            };
            let actual = {
                let inner = B::new(Sha256Digest::EMPTY, Height::new(2), 200);
                encode_block::<B, C, H>(inner, coding_config)
            };
            let commitment = Commitment::from((
                claimed.digest(),
                actual.commitment().root(),
                actual.commitment().context(),
                coding_config,
            ));

            // The engine tracks the commitment and subscribes before any chunk arrives.
            let round = Round::new(Epoch::zero(), View::new(1));
            let leader = peer_keys[1].clone();
            engine.handle_external_proposal(&mut sender, commitment, leader.clone(), round);
            let (response, mut assigned) = oneshot::channel();
            engine.handle_assigned_shard_verified_subscription(commitment, response);
            let (response, mut subscription) = oneshot::channel();
            engine
                .handle_block_subscription(BlockSubscriptionKey::Commitment(commitment), response);

            // Relayed chunks from peers 2 and 3, bound to the commitment by the leader's roots of
            // the other block, decode to a block that does not match the commitment's digest.
            for index in [2, 3] {
                let relayer = &peer_keys[usize::from(index)];
                receive(
                    &mut engine,
                    &mut sender,
                    relayer,
                    relayed(&actual, round, index),
                );
            }
            let roots = StreamRoots {
                commitment,
                round,
                roots: roots_of(&actual, round).roots,
            };
            receive(&mut engine, &mut sender, &leader, [roots.into()]);
            assert!(matches!(assigned.try_recv(), Err(TryRecvError::Empty)));
            let reconstructed = finished(&mut engine).await;
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
                let inner = B::new(Sha256Digest::EMPTY, Height::new(id), id * 100);
                encode_block::<B, C, H>(inner, coding_config)
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

    /// A repeated chunk or roots message from the leader is ignored without blocking it and is
    /// not relayed again, and the assigned shard still verifies.
    #[test_traced]
    fn test_duplicate_leader_shard_ignored() {
        let fixture = Fixture::<C>::default();
        fixture.start(
            |config, context, oracle, mut peers, _, coding_config| async move {
                let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block = encode_block::<B, C, H>(inner, coding_config);
                let commitment = coded_block.commitment();
                let round = Round::new(Epoch::zero(), View::new(1));
                let peer2_index = peers[2].index.get() as u16;
                let peer2_pk = peers[2].public_key.clone();
                let leader = peers[0].public_key.clone();

                let verified = peers[2]
                    .mailbox
                    .subscribe_assigned_shard_verified(commitment);
                peers[2].mailbox.discovered(commitment, leader, round);

                // The leader sends peer 2 its chunk and the roots twice.
                for _ in 0..2 {
                    send(
                        &mut peers[0].sender,
                        &peer2_pk,
                        assigned(&coded_block, round, peer2_index),
                    );
                    context.sleep(config.link.latency * 2).await;
                }

                assert!(
                    oracle.blocked().await.unwrap().is_empty(),
                    "leader should not be blocked for a duplicate chunk"
                );
                assert_eq!(
                    gauges(&context.encode(), "chunks_forwarded")
                        .iter()
                        .sum::<i64>(),
                    1,
                    "only the first copy of the chunk should be relayed"
                );
                select! {
                    _ = verified => {},
                    _ = context.sleep(Duration::from_secs(5)) => {
                        panic!("subscription did not complete after the leader's chunk");
                    },
                };
            },
        );
    }

    /// A leader's second chunk for a segment and index it already sent, under another root, is
    /// kept apart without blocking, so the first chunk still verifies against the roots. A chunk
    /// that fails its check against the root it claims blocks the leader.
    #[test_traced]
    fn test_equivocating_leader_chunk_ignored_and_forged_chunk_blocks_peer() {
        let fixture = Fixture::<C>::default();
        fixture.start(
            |config, context, oracle, mut peers, _, coding_config| async move {
                let block1 = encode_block::<B, C, H>(
                    B::new(Sha256Digest::EMPTY, Height::new(1), 100),
                    coding_config,
                );
                let commitment = block1.commitment();
                let block2 = encode_block::<B, C, H>(
                    B::new(Sha256Digest::EMPTY, Height::new(1), 200),
                    coding_config,
                );
                let round = Round::new(Epoch::zero(), View::new(1));
                let peer2_index = peers[2].index.get() as u16;
                let peer2_pk = peers[2].public_key.clone();
                let leader = peers[0].public_key.clone();

                let verified = peers[2]
                    .mailbox
                    .subscribe_assigned_shard_verified(commitment);
                peers[2]
                    .mailbox
                    .discovered(commitment, leader.clone(), round);

                // The leader sends peer 2 its chunk of block 1, then its chunk of block 2 for the
                // same segment and index, then the roots of block 1.
                let chunk1 = stream_of(&block1, round, peer2_index).remove(0);
                let chunk2 = stream_of(&block2, round, peer2_index).remove(0);
                send(
                    &mut peers[0].sender,
                    &peer2_pk,
                    [
                        ShardMessage::from(chunk1.clone()),
                        ShardMessage::from(chunk2.clone()),
                        ShardMessage::from(roots_of(&block1, round)),
                    ],
                );
                context.sleep(config.link.latency * 2).await;

                assert!(
                    oracle.blocked().await.unwrap().is_empty(),
                    "leader should not be blocked for a conflicting chunk"
                );
                select! {
                    _ = verified => {},
                    _ = context.sleep(Duration::from_secs(5)) => {
                        panic!("the first chunk did not verify the assigned shard");
                    },
                };

                // In a later round, the leader sends block 2's chunk under block 1's root.
                let forged_round = Round::new(Epoch::zero(), View::new(2));
                peers[2]
                    .mailbox
                    .discovered(block2.commitment(), leader, forged_round);
                let forged = StreamChunk {
                    round: forged_round,
                    chunk: chunk2.chunk,
                    ..chunk1
                };
                send(
                    &mut peers[0].sender,
                    &peer2_pk,
                    [ShardMessage::from(forged)],
                );
                context.sleep(config.link.latency * 2).await;

                assert_blocked(&oracle, &peers[2].public_key, &peers[0].public_key).await;
            },
        );
    }

    /// A chunk a non-leader sends at an index other than its own blocks the sender.
    #[test_traced]
    fn test_non_leader_wrong_index_shard_blocked() {
        let fixture = Fixture::<C>::default();
        fixture.start(
            |config, context, oracle, mut peers, _, coding_config| async move {
                let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block = encode_block::<B, C, H>(inner, coding_config);
                let commitment = coded_block.commitment();
                let round = Round::new(Epoch::zero(), View::new(1));
                let unrelated_index = peers[3].index.get() as u16;
                let peer2_pk = peers[2].public_key.clone();
                let leader = peers[0].public_key.clone();

                peers[2].mailbox.discovered(commitment, leader, round);

                // Peer 1 (not the leader) sends peer 2 the chunk of peer 3.
                send(
                    &mut peers[1].sender,
                    &peer2_pk,
                    relayed(&coded_block, round, unrelated_index),
                );
                context.sleep(config.link.latency * 2).await;

                assert_blocked(&oracle, &peers[2].public_key, &peers[1].public_key).await;
            },
        );
    }

    /// A non-leader's chunk at an index other than its own waits in the sender's buffer while
    /// the round's leader is unknown, and blocks the sender once the leader is discovered.
    #[test_traced]
    fn test_buffered_wrong_index_shard_blocked_on_leader_arrival() {
        let fixture = Fixture::<C>::default();
        fixture.start(
            |config, context, oracle, mut peers, _, coding_config| async move {
                let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block = encode_block::<B, C, H>(inner, coding_config);
                let commitment = coded_block.commitment();
                let round = Round::new(Epoch::zero(), View::new(1));
                let unrelated_index = peers[3].index.get() as u16;
                let peer2_pk = peers[2].public_key.clone();

                // Peer 1 sends the chunk of peer 3 before the leader is known.
                send(
                    &mut peers[1].sender,
                    &peer2_pk,
                    relayed(&coded_block, round, unrelated_index),
                );
                context.sleep(config.link.latency * 2).await;

                assert!(
                    oracle.blocked().await.unwrap().is_empty(),
                    "no peers should be blocked while leader is unknown"
                );

                let leader = peers[0].public_key.clone();
                peers[2].mailbox.discovered(commitment, leader, round);
                context.sleep(Duration::from_millis(10)).await;

                assert_blocked(&oracle, &peers[2].public_key, &peers[1].public_key).await;
            },
        );
    }

    /// Only the round's leader may send this node's assigned chunk. Another participant sending
    /// it is blocked, and the leader's roots then leave the assigned shard unverified.
    #[test_traced]
    fn test_assigned_shard_from_non_leader_blocked() {
        let fixture = Fixture::<C>::default();
        fixture.start(
            |config, context, oracle, mut peers, _, coding_config| async move {
                let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block = encode_block::<B, C, H>(inner, coding_config);
                let commitment = coded_block.commitment();
                let round = Round::new(Epoch::zero(), View::new(1));
                let peer2_index = peers[2].index.get() as u16;
                let peer2_pk = peers[2].public_key.clone();
                let leader = peers[0].public_key.clone();

                let mut verified = peers[2]
                    .mailbox
                    .subscribe_assigned_shard_verified(commitment);
                peers[2].mailbox.discovered(commitment, leader, round);

                send(
                    &mut peers[1].sender,
                    &peer2_pk,
                    relayed(&coded_block, round, peer2_index),
                );
                send(
                    &mut peers[0].sender,
                    &peer2_pk,
                    [ShardMessage::from(roots_of(&coded_block, round))],
                );
                context.sleep(config.link.latency * 2).await;

                assert_blocked(&oracle, &peers[2].public_key, &peers[1].public_key).await;
                assert!(
                    matches!(verified.try_recv(), Err(TryRecvError::Empty)),
                    "the assigned chunk from a non-leader must not verify the assigned shard"
                );
            },
        );
    }

    /// A discovery naming a non-participant leader is ignored, so the real leader's messages wait
    /// in its buffer without blocking it until a valid discovery names it.
    #[test_traced]
    fn test_non_participant_external_proposed_ignored() {
        let fixture = Fixture::<C>::default();
        fixture.start(
            |config, context, oracle, mut peers, _, coding_config| async move {
                let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block = encode_block::<B, C, H>(inner, coding_config);
                let commitment = coded_block.commitment();
                let round = Round::new(Epoch::zero(), View::new(1));
                let peer2_index = peers[2].index.get() as u16;
                let peer2_pk = peers[2].public_key.clone();
                let leader = peers[0].public_key.clone();
                let non_participant_leader = PrivateKey::from_seed(10_000).public_key();

                let shard_sub = peers[2]
                    .mailbox
                    .subscribe_assigned_shard_verified(commitment);
                peers[2]
                    .mailbox
                    .discovered(commitment, non_participant_leader, round);

                send(
                    &mut peers[0].sender,
                    &peer2_pk,
                    assigned(&coded_block, round, peer2_index),
                );
                context.sleep(config.link.latency * 2).await;

                let blocked = oracle.blocked().await.unwrap();
                let leader_blocked = blocked
                    .iter()
                    .any(|(a, b)| a == &peers[2].public_key && b == &leader);
                assert!(
                    !leader_blocked,
                    "leader should not be blocked when non-participant update is ignored"
                );

                peers[2].mailbox.discovered(commitment, leader, round);
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

    /// A leader update naming a non-participant does not raise a record's eviction round.
    #[test_traced]
    fn test_rejected_leader_does_not_refresh_eviction_round() {
        let fixture = Fixture::<C> {
            records: NZUsize!(2),
            ..Default::default()
        };
        fixture.start(|_, _, _, peers, _, coding_config| async move {
            let make_block = |id| {
                let inner = B::new(Sha256Digest::EMPTY, Height::new(id), id * 100);
                encode_block::<B, C, H>(inner, coding_config)
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
                let inner = B::new(Sha256Digest::EMPTY, Height::new(id), id * 100);
                encode_block::<B, C, H>(inner, coding_config)
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

    /// A chunk from a peer outside the round's participants blocks it once the leader is known.
    #[test_traced]
    fn test_shard_from_non_participant_blocks_peer() {
        let fixture = Fixture {
            num_future_peers: 1,
            ..Fixture::<C>::default()
        };
        fixture.start(
            |config, context, oracle, peers, _, coding_config| async move {
                let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block = encode_block::<B, C, H>(inner, coding_config);
                let commitment = coded_block.commitment();
                let round = Round::new(Epoch::zero(), View::new(1));

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

                peers[2].mailbox.discovered(commitment, leader, round);

                let peer2_index = peers[2].index.get() as u16;
                send(
                    &mut non_participant_sender,
                    &receiver_pk,
                    relayed(&coded_block, round, peer2_index),
                );
                context.sleep(config.link.latency * 2).await;

                assert_blocked(&oracle, &peers[2].public_key, &non_participant_pk).await;
            },
        );
    }

    /// A chunk sent before the round's leader is known by a peer that is not a tracked primary
    /// is dropped rather than buffered, so discovering the leader neither blocks the sender nor
    /// verifies the assigned shard.
    #[test_traced]
    fn test_preleader_shard_from_non_participant_is_not_buffered() {
        let fixture = Fixture {
            num_future_peers: 1,
            ..Fixture::<C>::default()
        };
        fixture.start(
            |config, context, oracle, peers, _, coding_config| async move {
                let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block = encode_block::<B, C, H>(inner, coding_config);
                let commitment = coded_block.commitment();
                let round = Round::new(Epoch::zero(), View::new(1));

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
                let mut shard_sub = peers[2]
                    .mailbox
                    .subscribe_assigned_shard_verified(commitment);

                send(
                    &mut non_participant_sender,
                    &receiver_pk,
                    relayed(&coded_block, round, peer2_index),
                );
                context.sleep(config.link.latency * 2).await;

                peers[2].mailbox.discovered(commitment, leader, round);
                context.sleep(config.link.latency * 2).await;

                let blocked = oracle.blocked().await.unwrap();
                let non_participant_blocked = blocked
                    .iter()
                    .any(|(a, b)| a == &peers[2].public_key && b == &non_participant_pk);
                assert!(
                    !non_participant_blocked,
                    "non-participant should not be blocked when its pre-leader chunk is ignored"
                );
                assert!(
                    matches!(shard_sub.try_recv(), Err(TryRecvError::Empty)),
                    "pre-leader chunk from non-participant should not be buffered"
                );
            },
        );
    }

    /// A participant's repeated chunk is ignored without blocking it and does not count twice
    /// toward the minimum a segment needs to reconstruct.
    #[test_traced]
    fn test_duplicate_shard_ignored() {
        // Ten peers need four chunks per segment.
        let fixture: Fixture<C> = Fixture {
            num_primary_peers: 10,
            ..Default::default()
        };

        fixture.start(
            |config, context, oracle, mut peers, _, coding_config| async move {
                let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block = encode_block::<B, C, H>(inner, coding_config);
                let commitment = coded_block.commitment();
                let round = Round::new(Epoch::zero(), View::new(1));
                let peer2_index = peers[2].index.get() as u16;
                let peer2_pk = peers[2].public_key.clone();
                let leader = peers[0].public_key.clone();

                peers[2].mailbox.discovered(commitment, leader, round);
                send(
                    &mut peers[0].sender,
                    &peer2_pk,
                    assigned(&coded_block, round, peer2_index),
                );
                context.sleep(config.link.latency * 2).await;

                // Peer 1 sends its chunk twice, and peer 3 brings the distinct chunks to three.
                for sender_idx in [1usize, 1, 3] {
                    let index = peers[sender_idx].index.get() as u16;
                    send(
                        &mut peers[sender_idx].sender,
                        &peer2_pk,
                        relayed(&coded_block, round, index),
                    );
                    context.sleep(config.link.latency * 2).await;
                }

                let blocked_peers = oracle.blocked().await.unwrap();
                let is_blocked = blocked_peers
                    .iter()
                    .any(|(a, b)| a == &peers[2].public_key && b == &peers[1].public_key);
                assert!(
                    !is_blocked,
                    "peer should not be blocked for exact duplicate chunk"
                );
                assert!(
                    peers[2].mailbox.get(commitment).await.is_none(),
                    "three distinct chunks must not reconstruct the block"
                );

                let index = peers[4].index.get() as u16;
                send(
                    &mut peers[4].sender,
                    &peer2_pk,
                    relayed(&coded_block, round, index),
                );
                context.sleep(config.link.latency * 2).await;
                assert!(peers[2].mailbox.get(commitment).await.is_some());
            },
        );
    }

    /// Once the leader's roots seal a round, a participant's chunk whose root differs from its
    /// segment's sealed root does not count toward reconstruction and does not block the sender,
    /// and the sender's valid chunk still counts.
    #[test_traced]
    fn test_equivocating_chunk_ignored() {
        // Ten peers need four chunks per segment.
        let fixture: Fixture<C> = Fixture {
            num_primary_peers: 10,
            ..Default::default()
        };

        fixture.start(
            |config, context, oracle, mut peers, _, coding_config| async move {
                let block1 = encode_block::<B, C, H>(
                    B::new(Sha256Digest::EMPTY, Height::new(1), 100),
                    coding_config,
                );
                let commitment = block1.commitment();
                let block2 = encode_block::<B, C, H>(
                    B::new(Sha256Digest::EMPTY, Height::new(1), 200),
                    coding_config,
                );
                let round = Round::new(Epoch::zero(), View::new(1));
                let peer2_index = peers[2].index.get() as u16;
                let peer2_pk = peers[2].public_key.clone();
                let leader = peers[0].public_key.clone();

                peers[2].mailbox.discovered(commitment, leader, round);
                send(
                    &mut peers[0].sender,
                    &peer2_pk,
                    assigned(&block1, round, peer2_index),
                );
                context.sleep(config.link.latency * 2).await;

                // Peer 1 sends its chunk of block 2, which checks against block 2's root only.
                let peer1_index = peers[1].index.get() as u16;
                send(
                    &mut peers[1].sender,
                    &peer2_pk,
                    relayed(&block2, round, peer1_index),
                );
                context.sleep(config.link.latency * 2).await;

                let blocked = oracle.blocked().await.unwrap();
                assert!(
                    !blocked
                        .iter()
                        .any(|(a, b)| a == &peers[2].public_key && b == &peers[1].public_key),
                    "a chunk under a conflicting root should not block its sender"
                );

                // With the leader's, the valid chunks of peers 1, 3, and 4 reach the minimum.
                for sender_idx in [1usize, 3, 4] {
                    let index = peers[sender_idx].index.get() as u16;
                    send(
                        &mut peers[sender_idx].sender,
                        &peer2_pk,
                        relayed(&block1, round, index),
                    );
                }
                context.sleep(config.link.latency * 2).await;

                let reconstructed = peers[2]
                    .mailbox
                    .get(commitment)
                    .await
                    .expect("block should reconstruct with peer 1's valid chunk");
                assert_eq!(reconstructed.commitment(), commitment);
            },
        );
    }

    /// Reconstructing a higher-view commitment leaves a lower-view record and its chunks in
    /// place. An exact duplicate for the lower-view record is ignored, and the record still
    /// reconstructs its block.
    #[test_traced]
    fn test_reconstruction_keeps_lower_view_records() {
        // Ten peers need four chunks per segment.
        let fixture: Fixture<C> = Fixture {
            num_primary_peers: 10,
            ..Default::default()
        };

        fixture.start(
            |config, context, oracle, mut peers, _, coding_config| async move {
                let block_a = encode_block::<B, C, H>(
                    B::new(Sha256Digest::EMPTY, Height::new(1), 100),
                    coding_config,
                );
                let commitment_a = block_a.commitment();
                let round_a = Round::new(Epoch::zero(), View::new(1));
                let block_b = encode_block::<B, C, H>(
                    B::new(Sha256Digest::EMPTY, Height::new(2), 200),
                    coding_config,
                );
                let commitment_b = block_b.commitment();
                let round_b = Round::new(Epoch::zero(), View::new(2));
                let peer2_index = peers[2].index.get() as u16;
                let peer2_pk = peers[2].public_key.clone();
                let leader = peers[0].public_key.clone();
                let indices: Vec<u16> = peers.iter().map(|peer| peer.index.get() as u16).collect();

                // A holds the leader's chunk for peer 2 and the chunk of peer 1.
                let a_sub = peers[2].mailbox.subscribe(commitment_a);
                peers[2]
                    .mailbox
                    .discovered(commitment_a, leader.clone(), round_a);
                send(
                    &mut peers[0].sender,
                    &peer2_pk,
                    assigned(&block_a, round_a, peer2_index),
                );
                send(
                    &mut peers[1].sender,
                    &peer2_pk,
                    relayed(&block_a, round_a, indices[1]),
                );
                context.sleep(config.link.latency * 2).await;

                // B at the higher view reconstructs from the leader's chunk and three relays.
                peers[2].mailbox.discovered(commitment_b, leader, round_b);
                send(
                    &mut peers[0].sender,
                    &peer2_pk,
                    assigned(&block_b, round_b, peer2_index),
                );
                for i in [1usize, 3, 4] {
                    send(
                        &mut peers[i].sender,
                        &peer2_pk,
                        relayed(&block_b, round_b, indices[i]),
                    );
                }
                context.sleep(config.link.latency * 4).await;

                let reconstructed = peers[2]
                    .mailbox
                    .get(commitment_b)
                    .await
                    .expect("block B should reconstruct");
                assert_eq!(reconstructed.commitment(), commitment_b);

                // Resending A's chunk is an exact duplicate and does not block peer 1.
                send(
                    &mut peers[1].sender,
                    &peer2_pk,
                    relayed(&block_a, round_a, indices[1]),
                );
                context.sleep(config.link.latency * 2).await;

                let blocked = oracle.blocked().await.unwrap();
                assert!(
                    !blocked
                        .iter()
                        .any(|(a, b)| a == &peers[2].public_key && b == &peers[1].public_key),
                    "peer1 should not be blocked for an exact duplicate"
                );

                // A reaches the minimum only with the two chunks it held before B reconstructed.
                for i in [3usize, 4] {
                    send(
                        &mut peers[i].sender,
                        &peer2_pk,
                        relayed(&block_a, round_a, indices[i]),
                    );
                }
                select! {
                    result = a_sub => {
                        let reconstructed = result.expect("block A should reconstruct");
                        assert_eq!(reconstructed.commitment(), commitment_a);
                    },
                    _ = context.sleep(config.link.latency * 10) => {
                        panic!("lower-view reconstruction did not complete");
                    },
                }
            },
        );
    }

    /// A later notarization raises a reconstructing record's eviction round. The window then
    /// evicts a lower-round block, and the record still reconstructs its block from the chunks
    /// streamed in the later round.
    #[test_traced]
    fn test_later_notarization_refreshes_reconstruction_state_round() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (network, oracle) = simulated::Network::<deterministic::Context, P>::new(
                context.child("network"),
                network_config(10),
            );
            network.start();

            let mut private_keys: Vec<PrivateKey> = (0..10).map(PrivateKey::from_seed).collect();
            private_keys.sort_by_key(|key| key.public_key());
            let peer_keys: Vec<P> = private_keys.iter().map(|key| key.public_key()).collect();
            let (mut engine, mut sender) =
                unstarted(&context, &oracle, &private_keys, 3, NZUsize!(2), STRATEGY).await;
            let leader = peer_keys[0].clone();
            elect(&mut engine, &leader);
            let coding_config = coding_config_for_participants(peer_keys.len() as u16);
            let make_block = |id| {
                let inner = B::new(Sha256Digest::EMPTY, Height::new(id), id * 100);
                encode_block::<B, C, H>(inner, coding_config)
            };
            let round = |view| Round::new(Epoch::zero(), View::new(view));
            let live = make_block(2);
            let live_commitment = live.commitment();

            // The engine tracks the commitment at view 1 and subscribes to its block.
            engine.handle_external_proposal(&mut sender, live_commitment, leader.clone(), round(1));
            engine.trim();
            let (response, mut live_sub) = oneshot::channel();
            engine.handle_block_subscription(
                BlockSubscriptionKey::Commitment(live_commitment),
                response,
            );

            // The same commitment is notarized at view 4, whose leader streams it again. The
            // assigned chunk and two relayed chunks fall one short of the minimum of four.
            engine.handle_notarized_commitment(&mut sender, live_commitment, round(4));
            engine.trim();
            receive(
                &mut engine,
                &mut sender,
                &leader,
                assigned(&live, round(4), 3),
            );
            for index in [1u16, 2] {
                receive(
                    &mut engine,
                    &mut sender,
                    &peer_keys[usize::from(index)],
                    relayed(&live, round(4), index),
                );
            }
            assert!(engine.jobs.is_empty());

            // Blocks cached at views 2 and 5 exceed the window by one record. The notarization
            // raised the commitment to view 4, so the window evicts the block at view 2.
            let lower = make_block(3);
            let lower_commitment = lower.commitment();
            engine.broadcast_shards(&mut sender, round(2), Arc::new(lower));
            engine.trim();
            engine.broadcast_shards(&mut sender, round(5), Arc::new(make_block(4)));
            engine.trim();
            assert!(!engine.records.contains_key(&lower_commitment));
            assert!(
                matches!(live_sub.try_recv(), Err(TryRecvError::Empty)),
                "later-round reconstruction subscription should remain open"
            );

            // A fourth relayed chunk reconstructs the block.
            receive(
                &mut engine,
                &mut sender,
                &peer_keys[4],
                relayed(&live, round(4), 4),
            );
            let reconstructed = finished(&mut engine).await;
            engine.complete(reconstructed);
            let block = live_sub
                .try_recv()
                .expect("later-round reconstruction should remain live");
            assert_eq!(block.commitment(), live_commitment);
        });
    }

    /// Notarizations and discoveries of a cached block raise its record's eviction round and
    /// keep its assigned-shard verification pending until the leader's chunk arrives.
    #[test_traced]
    fn test_cached_observations_refresh_reconstruction_state_round() {
        for notarize in [true, false] {
            let executor = deterministic::Runner::default();
            executor.start(|context| async move {
                let (network, oracle) = simulated::Network::<deterministic::Context, P>::new(
                    context.child("network"),
                    network_config(10),
                );
                network.start();

                let mut private_keys: Vec<PrivateKey> =
                    (0..10).map(PrivateKey::from_seed).collect();
                private_keys.sort_by_key(|key| key.public_key());
                let peer_keys: Vec<P> = private_keys.iter().map(|key| key.public_key()).collect();
                let (mut engine, mut sender) =
                    unstarted(&context, &oracle, &private_keys, 3, NZUsize!(2), STRATEGY).await;
                let leader = peer_keys[0].clone();
                elect(&mut engine, &leader);
                let coding_config = coding_config_for_participants(peer_keys.len() as u16);
                let make_block = |id| {
                    let inner = B::new(Sha256Digest::EMPTY, Height::new(id), id * 100);
                    encode_block::<B, C, H>(inner, coding_config)
                };
                let round = |view| Round::new(Epoch::zero(), View::new(view));
                let live = make_block(2);
                let live_commitment = live.commitment();
                let cached = |engine: &ShardEngine<C>| {
                    engine
                        .records
                        .get(&live_commitment)
                        .and_then(CommitmentRecord::block)
                        .is_some()
                };

                // The engine tracks the commitment at view 1 and reconstructs it from the
                // leader's roots and four relayed chunks, none of them its own.
                engine.handle_external_proposal(
                    &mut sender,
                    live_commitment,
                    leader.clone(),
                    round(1),
                );
                engine.trim();
                receive(
                    &mut engine,
                    &mut sender,
                    &leader,
                    [roots_of(&live, round(1)).into()],
                );
                for index in [1u16, 2, 4, 5] {
                    receive(
                        &mut engine,
                        &mut sender,
                        &peer_keys[usize::from(index)],
                        relayed(&live, round(1), index),
                    );
                }
                let reconstructed = finished(&mut engine).await;
                engine.complete(reconstructed);
                assert!(
                    cached(&engine),
                    "block should be cached before its round is refreshed"
                );

                // The commitment is observed again at view 4, whose leader seals it anew.
                let (response, mut verified) = oneshot::channel();
                engine.handle_assigned_shard_verified_subscription(live_commitment, response);
                if notarize {
                    engine.handle_notarized_commitment(&mut sender, live_commitment, round(4));
                } else {
                    engine.handle_external_proposal(
                        &mut sender,
                        live_commitment,
                        leader.clone(),
                        round(4),
                    );
                }
                engine.trim();
                receive(
                    &mut engine,
                    &mut sender,
                    &leader,
                    [roots_of(&live, round(4)).into()],
                );

                // Blocks cached at views 2 and 5 exceed the window by one record. The cached
                // observation raised the commitment to view 4, so the window evicts the block at
                // view 2.
                let lower = make_block(3);
                let lower_commitment = lower.commitment();
                engine.broadcast_shards(&mut sender, round(2), Arc::new(lower));
                engine.trim();
                engine.broadcast_shards(&mut sender, round(5), Arc::new(make_block(4)));
                engine.trim();
                assert!(!engine.records.contains_key(&lower_commitment));
                assert!(
                    matches!(verified.try_recv(), Err(TryRecvError::Empty)),
                    "cached observation should keep assigned-shard verification pending"
                );
                assert!(
                    cached(&engine),
                    "cached observation should keep the reconstructed block live"
                );

                // The leader's chunk for this node at view 4 verifies the assigned shard.
                receive(
                    &mut engine,
                    &mut sender,
                    &leader,
                    stream_of(&live, round(4), 3)
                        .into_iter()
                        .map(ShardMessage::from),
                );
                assert!(matches!(verified.try_recv(), Ok(())));
            });
        }
    }

    /// A local proposal in a one-record window evicts an older reconstruction state and drops
    /// the stream of its round. A chunk that conflicts with one streamed in that round then
    /// enters its sender's buffer without blocking.
    #[test_traced]
    fn test_local_proposal_evicts_older_reconstruction_state() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (network, oracle) = simulated::Network::<deterministic::Context, P>::new(
                context.child("network"),
                network_config(4),
            );
            network.start();

            let mut private_keys: Vec<PrivateKey> = (0..4).map(PrivateKey::from_seed).collect();
            private_keys.sort_by_key(|key| key.public_key());
            let peer_keys: Vec<P> = private_keys.iter().map(|key| key.public_key()).collect();
            let (mut engine, mut sender) =
                unstarted(&context, &oracle, &private_keys, 2, NZUsize!(1), STRATEGY).await;
            let coding_config = coding_config_for_participants(peer_keys.len() as u16);
            let make_block = |height, payload| {
                let inner = B::new(Sha256Digest::EMPTY, Height::new(height), payload);
                encode_block::<B, C, H>(inner, coding_config)
            };
            let block_a = make_block(1, 100);
            let commitment_a = block_a.commitment();
            let round_a = Round::new(Epoch::zero(), View::new(1));
            let block_b = make_block(2, 200);
            let commitment_b = block_b.commitment();
            let peer1 = peer_keys[1].clone();

            // The engine tracks A at view 1, and peer 1 streams its chunk.
            engine.handle_external_proposal(
                &mut sender,
                commitment_a,
                peer_keys[0].clone(),
                round_a,
            );
            engine.trim();
            receive(
                &mut engine,
                &mut sender,
                &peer1,
                relayed(&block_a, round_a, 1),
            );
            assert!(
                engine
                    .streams
                    .get(&round_a)
                    .is_some_and(|stream| !stream.chunks.is_empty())
            );

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
            assert!(!engine.streams.contains_key(&round_a));

            // A chunk that conflicts with peer 1's chunk of A enters peer 1's buffer without
            // blocking.
            receive(
                &mut engine,
                &mut sender,
                &peer1,
                relayed(&make_block(1, 300), round_a, 1),
            );
            assert_eq!(buffered(&engine, &peer1, round_a), 1);
            assert!(oracle.blocked().await.unwrap().is_empty());
        });
    }

    /// Chunks and roots that arrive before the round's leader is known wait in the per-peer
    /// buffers, and discovery of the proposal ingests them at once: the assigned shard verifies
    /// and the block reconstructs without further messages.
    #[test_traced]
    fn test_peer_shards_buffered_until_external_proposed() {
        let fixture: Fixture<C> = Fixture {
            num_primary_peers: 10,
            ..Default::default()
        };

        fixture.start(
            |config, context, oracle, mut peers, _, coding_config| async move {
                let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block = encode_block::<B, C, H>(inner, coding_config);
                let commitment = coded_block.commitment();
                let round = Round::new(Epoch::zero(), View::new(1));

                let receiver_idx = 3usize;
                let receiver_pk = peers[receiver_idx].public_key.clone();
                let receiver_index = peers[receiver_idx].index.get() as u16;
                let leader = peers[0].public_key.clone();

                let mut shard_sub = peers[receiver_idx]
                    .mailbox
                    .subscribe_assigned_shard_verified(commitment);

                // The leader's chunk and roots for the receiver and three relayed chunks all
                // arrive before the receiver knows who leads the round.
                send(
                    &mut peers[0].sender,
                    &receiver_pk,
                    assigned(&coded_block, round, receiver_index),
                );
                for i in [1usize, 2, 4] {
                    let index = peers[i].index.get() as u16;
                    send(
                        &mut peers[i].sender,
                        &receiver_pk,
                        relayed(&coded_block, round, index),
                    );
                }
                context.sleep(config.link.latency * 2).await;

                assert!(
                    matches!(shard_sub.try_recv(), Err(TryRecvError::Empty)),
                    "shard subscription should not resolve before leader announcement"
                );
                assert!(
                    peers[receiver_idx].mailbox.get(commitment).await.is_none(),
                    "block should not reconstruct before leader announcement"
                );

                peers[receiver_idx]
                    .mailbox
                    .discovered(commitment, leader, round);
                select! {
                    _ = shard_sub => {},
                    _ = context.sleep(Duration::from_secs(5)) => {
                        panic!("shard subscription did not resolve after leader announcement");
                    },
                }
                context.sleep(config.link.latency * 2).await;
                assert!(
                    peers[receiver_idx].mailbox.get(commitment).await.is_some(),
                    "block should reconstruct after buffered messages are ingested"
                );
                assert!(
                    oracle.blocked().await.unwrap().is_empty(),
                    "no peers should be blocked for valid buffered messages"
                );
            },
        );
    }

    /// With an inline strategy, a block reconstructed while handling a consensus signal is cached
    /// before the engine handles the next queued message.
    #[test_traced]
    fn test_inline_reconstruction_completes_before_next_message() {
        let fixture: Fixture<C> = Fixture {
            num_primary_peers: 10,
            ..Default::default()
        };

        fixture.start(
            |config, context, oracle, mut peers, _, coding_config| async move {
                let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block = encode_block::<B, C, H>(inner, coding_config);
                let commitment = coded_block.commitment();
                let round = Round::new(Epoch::zero(), View::new(1));

                let receiver_idx = 3usize;
                let receiver_pk = peers[receiver_idx].public_key.clone();
                let receiver_index = peers[receiver_idx].index.get() as u16;
                let leader = peers[0].public_key.clone();

                // Buffer the leader's messages for the receiver and enough relayed chunks to
                // reach the minimum before any consensus signal.
                send(
                    &mut peers[0].sender,
                    &receiver_pk,
                    assigned(&coded_block, round, receiver_index),
                );
                for i in [1usize, 2, 4] {
                    let index = peers[i].index.get() as u16;
                    send(
                        &mut peers[i].sender,
                        &receiver_pk,
                        relayed(&coded_block, round, index),
                    );
                }
                context.sleep(config.link.latency * 2).await;

                // Discovery ingests the buffered messages and reconstructs inline. The request
                // queued right behind it observes the cached block.
                peers[receiver_idx]
                    .mailbox
                    .discovered(commitment, leader, round);
                assert!(
                    peers[receiver_idx].mailbox.get(commitment).await.is_some(),
                    "inline reconstruction must complete before the next message"
                );
                assert!(
                    oracle.blocked().await.unwrap().is_empty(),
                    "no peers should be blocked for valid buffered messages"
                );
            },
        );
    }

    /// A cached block outlives pressure on the per-peer buffers: a peer whose ring holds one
    /// message keeps only its latest, so only the round whose chunk survived reconstructs, while
    /// a subscription installed afterwards still receives the earlier cached block. A block
    /// reconstructed from other participants' chunks does not verify the assigned shard until the
    /// leader's chunk for the local index arrives.
    #[test_traced]
    fn test_late_subscription_uses_notarized_cache_after_peer_buffer_pressure() {
        let fixture: Fixture<C> = Fixture {
            num_primary_peers: 10,
            peer_buffer_size: NZUsize!(1),
            ..Default::default()
        };

        fixture.start(
            |config, context, oracle, mut peers, _, coding_config| async move {
                let target = {
                    let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 1);
                    encode_block::<B, C, H>(inner, coding_config)
                };
                let target_commitment = target.commitment();
                let receiver_idx = 3usize;
                let receiver = peers[receiver_idx].public_key.clone();
                let receiver_index = peers[receiver_idx].index.get() as u16;
                let leader = peers[0].public_key.clone();
                let initial_round = Round::new(Epoch::zero(), View::new(1));
                let later_round = Round::new(Epoch::zero(), View::new(4));

                // The target reconstructs from the leader's roots and four relayed chunks, none
                // of them the receiver's own.
                peers[receiver_idx].mailbox.discovered(
                    target_commitment,
                    leader.clone(),
                    initial_round,
                );
                send(
                    &mut peers[0].sender,
                    &receiver,
                    [ShardMessage::Roots(roots_of(&target, initial_round))],
                );
                for sender_idx in [1usize, 2, 4, 5] {
                    let index = peers[sender_idx].index.get() as u16;
                    send(
                        &mut peers[sender_idx].sender,
                        &receiver,
                        relayed(&target, initial_round, index),
                    );
                }
                let target_sub = peers[receiver_idx].mailbox.subscribe(target_commitment);
                select! {
                    result = target_sub => {
                        let block = result.expect("target should reconstruct");
                        assert_eq!(block.commitment(), target_commitment);
                    },
                    _ = context.sleep(Duration::from_secs(5)) => {
                        panic!("target did not reconstruct");
                    },
                }

                // Reconstruction alone leaves the assigned shard unverified. The engine handles
                // the subscription before answering the lookup queued behind it.
                let mut assigned_sub = peers[receiver_idx]
                    .mailbox
                    .subscribe_assigned_shard_verified(target_commitment);
                assert!(
                    peers[receiver_idx]
                        .mailbox
                        .get(target_commitment)
                        .await
                        .is_some()
                );
                assert!(
                    matches!(assigned_sub.try_recv(), Err(TryRecvError::Empty)),
                    "reconstruction must not satisfy assigned shard readiness"
                );
                send(
                    &mut peers[0].sender,
                    &receiver,
                    relayed(&target, initial_round, receiver_index),
                );
                select! {
                    _ = assigned_sub => {},
                    _ = context.sleep(Duration::from_secs(5)) => {
                        panic!("assigned shard did not verify after the leader's chunk");
                    },
                }

                // A later notarization leaves the target cached. The record owns the block
                // independently of the bounded per-peer buffers.
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

                // Peer 1 relays its chunk of two blocks in rounds whose leader the receiver does
                // not know yet, so the second evicts the first from its one-message ring.
                let pressure = [2u64, 3].map(|id| {
                    let inner = B::new(Sha256Digest::EMPTY, Height::new(id), id);
                    (
                        encode_block::<B, C, H>(inner, coding_config),
                        Round::new(Epoch::zero(), View::new(id)),
                    )
                });
                let peer1_index = peers[1].index.get() as u16;
                for (block, round) in &pressure {
                    send(
                        &mut peers[1].sender,
                        &receiver,
                        relayed(block, *round, peer1_index),
                    );
                }
                context.sleep(config.link.latency * 2).await;

                // Each round then receives the leader's chunk and two relays, one short of the
                // minimum without peer 1's chunk.
                for ((block, round), should_reconstruct) in pressure.iter().zip([false, true]) {
                    let commitment = block.commitment();
                    peers[receiver_idx]
                        .mailbox
                        .discovered(commitment, leader.clone(), *round);
                    send(
                        &mut peers[0].sender,
                        &receiver,
                        assigned(block, *round, receiver_index),
                    );
                    for sender_idx in [2usize, 4] {
                        let index = peers[sender_idx].index.get() as u16;
                        send(
                            &mut peers[sender_idx].sender,
                            &receiver,
                            relayed(block, *round, index),
                        );
                    }
                    context.sleep(config.link.latency * 2).await;

                    if should_reconstruct {
                        let block_sub = peers[receiver_idx].mailbox.subscribe(commitment);
                        select! {
                            result = block_sub => {
                                let block = result.expect("retained pressure block should reconstruct");
                                assert_eq!(block.commitment(), commitment);
                            },
                            _ = context.sleep(Duration::from_secs(5)) => {
                                panic!("retained same-peer chunk did not reconstruct");
                            },
                        }
                    } else {
                        assert!(
                            peers[receiver_idx].mailbox.get(commitment).await.is_none(),
                            "evicted same-peer chunk should not reconstruct"
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
                    "valid pressure chunks should not block peers"
                );
            },
        );
    }

    /// Notarization does not name a round's leader, so the leader's messages that follow it wait
    /// in the buffers until discovery names the leader, and then verify the assigned shard.
    #[test_traced]
    fn test_leader_shard_after_notarized_is_buffered_until_discovered() {
        let fixture: Fixture<C> = Fixture {
            num_primary_peers: 10,
            ..Default::default()
        };

        fixture.start(
            |config, context, oracle, mut peers, _, coding_config| async move {
                let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block = encode_block::<B, C, H>(inner, coding_config);
                let commitment = coded_block.commitment();
                let round = Round::new(Epoch::zero(), View::new(1));

                let leader_idx = 0usize;
                let receiver_idx = 3usize;
                let leader = peers[leader_idx].public_key.clone();
                let receiver = peers[receiver_idx].public_key.clone();
                let receiver_index = peers[receiver_idx].index.get() as u16;

                peers[receiver_idx].mailbox.notarized(commitment, round);
                let mut assigned_sub = peers[receiver_idx]
                    .mailbox
                    .subscribe_assigned_shard_verified(commitment);
                send(
                    &mut peers[leader_idx].sender,
                    &receiver,
                    assigned(&coded_block, round, receiver_index),
                );
                context.sleep(config.link.latency * 2).await;
                assert!(
                    matches!(assigned_sub.try_recv(), Err(TryRecvError::Empty)),
                    "leader messages should stay buffered until discovery"
                );

                peers[receiver_idx]
                    .mailbox
                    .discovered(commitment, leader, round);
                select! {
                    _ = assigned_sub => {},
                    _ = context.sleep(Duration::from_secs(5)) => {
                        panic!("assigned shard did not verify after leader discovery");
                    },
                }
                assert!(
                    oracle.blocked().await.unwrap().is_empty(),
                    "valid leader messages should not block peers"
                );
            },
        );
    }

    /// A leader that relays a candidate before voting may abandon it and relay a replacement
    /// for the same round. The replacement's chunks reach every participant. A participant that
    /// discovers only the replacement verifies its assigned shard and reconstructs that block,
    /// but never the abandoned candidate.
    #[test_traced]
    fn test_replacement_proposal_in_same_round_reaches_peers() {
        let fixture: Fixture<C> = Fixture {
            num_primary_peers: 10,
            ..Default::default()
        };

        fixture.start(
            |config, context, oracle, mut peers, _, coding_config| async move {
                let abandoned = {
                    let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                    encode_block::<B, C, H>(inner, coding_config)
                };
                let replacement = {
                    let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 200);
                    encode_block::<B, C, H>(inner, coding_config)
                };
                assert_ne!(abandoned.commitment(), replacement.commitment());
                let round = Round::new(Epoch::zero(), View::new(1));
                let leader = peers[0].public_key.clone();

                // Both candidates are relayed before any participant learns the proposal.
                peers[0].mailbox.proposed(round, abandoned.clone());
                peers[0].mailbox.proposed(round, replacement.clone());
                context.sleep(config.link.latency * 2).await;

                // Only the replacement is ever proposed.
                let commitment = replacement.commitment();
                for peer in peers[1..].iter_mut() {
                    peer.mailbox.discovered(commitment, leader.clone(), round);
                }
                for peer in peers.iter_mut() {
                    let assigned_sub = peer.mailbox.subscribe_assigned_shard_verified(commitment);
                    select! {
                        _ = assigned_sub => {},
                        _ = context.sleep(Duration::from_secs(5)) => {
                            panic!("assigned shard of the replacement did not verify");
                        },
                    }
                }
                context.sleep(config.link.latency * 2).await;

                for peer in peers.iter_mut() {
                    let reconstructed = peer
                        .mailbox
                        .get(commitment)
                        .await
                        .expect("replacement should be reconstructed");
                    assert_eq!(reconstructed.digest(), replacement.digest());
                }
                for peer in peers[1..].iter_mut() {
                    assert!(
                        peer.mailbox.get(abandoned.commitment()).await.is_none(),
                        "an abandoned candidate is never reconstructed"
                    );
                }
                assert!(
                    oracle.blocked().await.unwrap().is_empty(),
                    "a replacement candidate should not block the leader"
                );
            },
        );
    }

    /// Once discovery names the round's leader, chunks are ingested as they arrive: the leader's
    /// chunk verifies the assigned shard, and relayed chunks complete reconstruction without any
    /// further signal.
    #[test_traced]
    fn test_post_leader_shards_processed_immediately() {
        let fixture: Fixture<C> = Fixture {
            num_primary_peers: 10,
            ..Default::default()
        };

        fixture.start(
            |config, context, oracle, mut peers, _, coding_config| async move {
                let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block = encode_block::<B, C, H>(inner, coding_config);
                let commitment = coded_block.commitment();
                let round = Round::new(Epoch::zero(), View::new(1));

                let receiver_idx = 3usize;
                let receiver_pk = peers[receiver_idx].public_key.clone();
                let receiver_index = peers[receiver_idx].index.get() as u16;
                let leader = peers[0].public_key.clone();

                let shard_sub = peers[receiver_idx]
                    .mailbox
                    .subscribe_assigned_shard_verified(commitment);
                peers[receiver_idx]
                    .mailbox
                    .discovered(commitment, leader, round);

                send(
                    &mut peers[0].sender,
                    &receiver_pk,
                    assigned(&coded_block, round, receiver_index),
                );
                select! {
                    _ = shard_sub => {},
                    _ = context.sleep(Duration::from_secs(5)) => {
                        panic!("shard subscription did not resolve after post-leader chunk");
                    },
                }

                for i in [1usize, 2, 4] {
                    let index = peers[i].index.get() as u16;
                    send(
                        &mut peers[i].sender,
                        &receiver_pk,
                        relayed(&coded_block, round, index),
                    );
                }
                context.sleep(config.link.latency * 2).await;
                let reconstructed = peers[receiver_idx]
                    .mailbox
                    .get(commitment)
                    .await
                    .expect("block should reconstruct from post-leader chunks");
                assert_eq!(reconstructed.commitment(), commitment);

                assert!(
                    oracle.blocked().await.unwrap().is_empty(),
                    "no peers should be blocked for valid post-leader chunks"
                );
            },
        );
    }

    /// A payload that does not decode as a shard message blocks its sender.
    #[test_traced]
    fn test_invalid_shard_codec_blocks_peer() {
        let fixture: Fixture<C> = Fixture {
            num_primary_peers: 4,
            ..Default::default()
        };

        fixture.start(
            |config, context, oracle, mut peers, _, _coding_config| async move {
                let peer0_pk = peers[0].public_key.clone();
                let peer1_pk = peers[1].public_key.clone();

                let garbage = Bytes::from(vec![0xFF, 0xFE, 0xFD, 0xFC, 0xFB]);
                peers[1]
                    .sender
                    .send(Recipients::One(peer0_pk.clone()), garbage, true);
                context.sleep(config.link.latency * 2).await;

                assert_blocked(&oracle, &peer0_pk, &peer1_pk).await;
            },
        );
    }

    /// A peer that sends a chunk whose data is wider than the chunk's claimed coding config allows
    /// for the largest block is blocked when the chunk is decoded, before the round's leader is
    /// known.
    #[test_traced]
    fn test_oversized_shard_blocks_peer() {
        let fixture: Fixture<C> = Fixture::default();
        fixture.start(
            |config, context, oracle, mut peers, _, coding_config| async move {
                // Peer 1 sends peer 2 its chunk of the largest block, coded under the committee's
                // config but claiming one with more minimum shards. The claimed config codes the
                // largest block into narrower chunks, so this chunk is too wide for it.
                let claimed = CodingConfig {
                    minimum_shards: NZU16!(3),
                    extra_shards: NZU16!(1),
                };
                let inner = B::new(Sha256Digest::EMPTY, Height::new(u64::MAX), u64::MAX);
                let coded_block = encode_block::<B, C, H>(inner, coding_config);
                let round = Round::new(Epoch::zero(), View::new(1));
                let mut chunk =
                    stream_of(&coded_block, round, peers[1].index.get() as u16).remove(0);
                chunk.config = claimed;
                let peer2 = peers[2].public_key.clone();
                send(&mut peers[1].sender, &peer2, [ShardMessage::Stream(chunk)]);
                context.sleep(config.link.latency * 2).await;

                // No engine knows the round's leader, so a chunk that decodes would only be
                // buffered. Peer 2 blocks peer 1 when decoding the chunk.
                assert_blocked(&oracle, &peer2, &peers[1].public_key).await;
            },
        );
    }

    /// A repeated chunk received before the round's leader is known is buffered without blocking
    /// its sender, and ingesting both copies once the leader is known stores one and ignores the
    /// other without blocking.
    #[test_traced]
    fn test_duplicate_buffered_shard_does_not_block_before_leader() {
        let fixture: Fixture<C> = Fixture::default();

        fixture.start(
            |config, context, oracle, mut peers, _, coding_config| async move {
                let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block = encode_block::<B, C, H>(inner, coding_config);
                let round = Round::new(Epoch::zero(), View::new(1));
                let peer1_index = peers[1].index.get() as u16;
                let peer2_pk = peers[2].public_key.clone();

                send(
                    &mut peers[1].sender,
                    &peer2_pk,
                    relayed(&coded_block, round, peer1_index),
                );
                context.sleep(config.link.latency * 2).await;
                assert!(
                    oracle.blocked().await.unwrap().is_empty(),
                    "no peers should be blocked yet"
                );

                send(
                    &mut peers[1].sender,
                    &peer2_pk,
                    relayed(&coded_block, round, peer1_index),
                );
                context.sleep(config.link.latency * 2).await;
                assert!(
                    oracle.blocked().await.unwrap().is_empty(),
                    "no peers should be blocked before leader"
                );

                let leader = peers[0].public_key.clone();
                peers[2]
                    .mailbox
                    .discovered(coded_block.commitment(), leader, round);
                context.sleep(config.link.latency * 2).await;
                assert!(
                    oracle.blocked().await.unwrap().is_empty(),
                    "a repeated chunk should not block its sender once ingested"
                );
            },
        );
    }

    /// A leader chunk that fails verification against its claimed root blocks the leader.
    #[test_traced]
    fn test_invalid_leader_shard_crypto_blocks_leader() {
        let fixture: Fixture<C> = Fixture::default();

        fixture.start(
            |config, context, oracle, mut peers, _, coding_config| async move {
                let inner1 = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block1 = encode_block::<B, C, H>(inner1, coding_config);
                let commitment1 = coded_block1.commitment();
                let inner2 = B::new(Sha256Digest::EMPTY, Height::new(2), 200);
                let coded_block2 = encode_block::<B, C, H>(inner2, coding_config);
                let round = Round::new(Epoch::zero(), View::new(1));

                // Peer 2's chunk of block 2 under the root of block 1's chunk.
                let peer2_index = peers[2].index.get() as u16;
                let mut wrong = stream_of(&coded_block2, round, peer2_index).remove(0);
                wrong.root = stream_of(&coded_block1, round, peer2_index)[0].root;

                let peer2_pk = peers[2].public_key.clone();
                let leader = peers[0].public_key.clone();
                peers[2].mailbox.discovered(commitment1, leader, round);

                send(
                    &mut peers[0].sender,
                    &peer2_pk,
                    [ShardMessage::Stream(wrong)],
                );
                context.sleep(config.link.latency * 2).await;

                assert_blocked(&oracle, &peers[2].public_key, &peers[0].public_key).await;
            },
        );
    }

    /// A participant that races the leader with a chunk at the victim's assigned index is blocked
    /// without claiming the slot: the leader's genuine chunk still verifies afterwards.
    #[test_traced]
    fn test_invalid_assigned_shard_from_non_leader_blocks_only_sender() {
        let fixture: Fixture<C> = Fixture::default();

        fixture.start(
            |config, context, oracle, mut peers, _, coding_config| async move {
                let inner1 = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block1 = encode_block::<B, C, H>(inner1, coding_config);
                let commitment1 = coded_block1.commitment();
                let inner2 = B::new(Sha256Digest::EMPTY, Height::new(2), 200);
                let coded_block2 = encode_block::<B, C, H>(inner2, coding_config);
                let round = Round::new(Epoch::zero(), View::new(1));

                // Peer 2's chunk of block 2 under the root of block 1's chunk.
                let peer2_index = peers[2].index.get() as u16;
                let mut wrong = stream_of(&coded_block2, round, peer2_index).remove(0);
                wrong.root = stream_of(&coded_block1, round, peer2_index)[0].root;

                let peer2_pk = peers[2].public_key.clone();
                let leader = peers[0].public_key.clone();
                let mut shard_sub = peers[2]
                    .mailbox
                    .subscribe_assigned_shard_verified(commitment1);
                peers[2].mailbox.discovered(commitment1, leader, round);

                send(
                    &mut peers[1].sender,
                    &peer2_pk,
                    [ShardMessage::Stream(wrong)],
                );
                context.sleep(config.link.latency * 2).await;

                assert_blocked(&oracle, &peers[2].public_key, &peers[1].public_key).await;
                assert!(
                    matches!(shard_sub.try_recv(), Err(TryRecvError::Empty)),
                    "subscription should not resolve from an invalid chunk"
                );

                send(
                    &mut peers[0].sender,
                    &peer2_pk,
                    assigned(&coded_block1, round, peer2_index),
                );
                select! {
                    _ = shard_sub => {},
                    _ = context.sleep(Duration::from_secs(5)) => {
                        panic!("genuine assigned chunk did not verify after invalid one");
                    },
                };
            },
        );
    }

    /// A non-leader chunk whose index is not the sender's own blocks the sender.
    #[test_traced]
    fn test_shard_index_mismatch_blocks_peer() {
        let fixture: Fixture<C> = Fixture {
            num_primary_peers: 10,
            ..Default::default()
        };

        fixture.start(
            |config, context, oracle, mut peers, _, coding_config| async move {
                let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block = encode_block::<B, C, H>(inner, coding_config);
                let commitment = coded_block.commitment();
                let round = Round::new(Epoch::zero(), View::new(1));

                let peer3_index = peers[3].index.get() as u16;
                let peer1_index = peers[1].index.get() as u16;
                let mut wrong_index = stream_of(&coded_block, round, peer1_index).remove(0);
                wrong_index.index = peers[4].index.get() as u16;

                let peer3_pk = peers[3].public_key.clone();
                let leader = peers[0].public_key.clone();
                peers[3].mailbox.discovered(commitment, leader, round);
                send(
                    &mut peers[0].sender,
                    &peer3_pk,
                    assigned(&coded_block, round, peer3_index),
                );
                context.sleep(config.link.latency * 2).await;

                send(
                    &mut peers[1].sender,
                    &peer3_pk,
                    [ShardMessage::Stream(wrong_index)],
                );
                context.sleep(config.link.latency * 2).await;

                assert_blocked(&oracle, &peers[3].public_key, &peers[1].public_key).await;
            },
        );
    }

    /// A relayed chunk that fails verification against the sealed root of its segment blocks its
    /// sender as soon as it arrives, without waiting for the minimum of chunks.
    #[test_traced]
    fn test_invalid_shard_crypto_blocks_peer() {
        let fixture: Fixture<C> = Fixture {
            num_primary_peers: 10,
            ..Default::default()
        };

        fixture.start(
            |config, context, oracle, mut peers, _, coding_config| async move {
                let inner1 = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block1 = encode_block::<B, C, H>(inner1, coding_config);
                let commitment1 = coded_block1.commitment();
                let inner2 = B::new(Sha256Digest::EMPTY, Height::new(2), 200);
                let coded_block2 = encode_block::<B, C, H>(inner2, coding_config);
                let round = Round::new(Epoch::zero(), View::new(1));

                // Peer 1's chunk of block 2 under the root of block 1's chunk.
                let peer1_index = peers[1].index.get() as u16;
                let mut wrong = stream_of(&coded_block2, round, peer1_index).remove(0);
                wrong.root = stream_of(&coded_block1, round, peer1_index)[0].root;

                let peer3_pk = peers[3].public_key.clone();
                let peer3_index = peers[3].index.get() as u16;
                let leader = peers[0].public_key.clone();
                peers[3].mailbox.discovered(commitment1, leader, round);
                send(
                    &mut peers[0].sender,
                    &peer3_pk,
                    assigned(&coded_block1, round, peer3_index),
                );
                context.sleep(config.link.latency * 2).await;

                send(
                    &mut peers[1].sender,
                    &peer3_pk,
                    [ShardMessage::Stream(wrong)],
                );
                context.sleep(config.link.latency * 2).await;

                assert_blocked(&oracle, &peers[3].public_key, &peers[1].public_key).await;
            },
        );
    }

    /// An invalid chunk counts toward nothing: with the minimum of chunks received but one of
    /// them invalid, the sender is blocked and the block reconstructs once another valid chunk
    /// arrives.
    #[test_traced]
    fn test_reconstruction_recovers_after_quorum_with_one_invalid_shard() {
        let fixture: Fixture<C> = Fixture {
            num_primary_peers: 10,
            ..Default::default()
        };

        fixture.start(
            |config, context, oracle, mut peers, _, coding_config| async move {
                let inner1 = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block1 = encode_block::<B, C, H>(inner1, coding_config);
                let commitment1 = coded_block1.commitment();
                let inner2 = B::new(Sha256Digest::EMPTY, Height::new(2), 200);
                let coded_block2 = encode_block::<B, C, H>(inner2, coding_config);
                let round = Round::new(Epoch::zero(), View::new(1));

                let receiver_idx = 3usize;
                let receiver_pk = peers[receiver_idx].public_key.clone();
                let receiver_index = peers[receiver_idx].index.get() as u16;

                // Peer 1's chunk of block 2 under the root of block 1's chunk.
                let peer1_index = peers[1].index.get() as u16;
                let mut invalid = stream_of(&coded_block2, round, peer1_index).remove(0);
                invalid.root = stream_of(&coded_block1, round, peer1_index)[0].root;

                let leader = peers[0].public_key.clone();
                peers[receiver_idx]
                    .mailbox
                    .discovered(commitment1, leader, round);
                send(
                    &mut peers[0].sender,
                    &receiver_pk,
                    assigned(&coded_block1, round, receiver_index),
                );

                // The leader's chunk, the invalid chunk, and two valid relays make the minimum
                // of four chunks, only three of them valid.
                send(
                    &mut peers[1].sender,
                    &receiver_pk,
                    [ShardMessage::Stream(invalid)],
                );
                for idx in [2usize, 4] {
                    let index = peers[idx].index.get() as u16;
                    send(
                        &mut peers[idx].sender,
                        &receiver_pk,
                        relayed(&coded_block1, round, index),
                    );
                }
                context.sleep(config.link.latency * 2).await;

                assert_blocked(
                    &oracle,
                    &peers[receiver_idx].public_key,
                    &peers[1].public_key,
                )
                .await;
                assert!(
                    peers[receiver_idx].mailbox.get(commitment1).await.is_none(),
                    "block should not reconstruct with only 3 valid chunks"
                );

                let peer5_index = peers[5].index.get() as u16;
                send(
                    &mut peers[5].sender,
                    &receiver_pk,
                    relayed(&coded_block1, round, peer5_index),
                );
                context.sleep(config.link.latency * 2).await;

                let reconstructed = peers[receiver_idx]
                    .mailbox
                    .get(commitment1)
                    .await
                    .expect("block should reconstruct after additional valid chunk");
                assert_eq!(reconstructed.commitment(), commitment1);
            },
        );
    }

    /// An invalid chunk buffered before the round's leader is known blocks its sender only once
    /// discovery names the leader and the buffered messages are checked.
    #[test_traced]
    fn test_invalid_pending_shard_blocked_on_drain() {
        let fixture: Fixture<C> = Fixture {
            num_primary_peers: 10,
            ..Default::default()
        };

        fixture.start(
            |config, context, oracle, mut peers, _, coding_config| async move {
                let inner1 = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block1 = encode_block::<B, C, H>(inner1, coding_config);
                let commitment1 = coded_block1.commitment();
                let inner2 = B::new(Sha256Digest::EMPTY, Height::new(2), 200);
                let coded_block2 = encode_block::<B, C, H>(inner2, coding_config);
                let round = Round::new(Epoch::zero(), View::new(1));

                // Peer 1's chunk of block 2 under the root of block 1's chunk.
                let peer1_index = peers[1].index.get() as u16;
                let mut wrong = stream_of(&coded_block2, round, peer1_index).remove(0);
                wrong.root = stream_of(&coded_block1, round, peer1_index)[0].root;

                let peer3_pk = peers[3].public_key.clone();
                let peer3_index = peers[3].index.get() as u16;

                send(
                    &mut peers[1].sender,
                    &peer3_pk,
                    [ShardMessage::Stream(wrong)],
                );
                for idx in [2usize, 4] {
                    let index = peers[idx].index.get() as u16;
                    send(
                        &mut peers[idx].sender,
                        &peer3_pk,
                        relayed(&coded_block1, round, index),
                    );
                }
                context.sleep(config.link.latency * 2).await;
                assert!(
                    oracle.blocked().await.unwrap().is_empty(),
                    "no peers should be blocked while their chunks are buffered"
                );

                let leader = peers[0].public_key.clone();
                peers[3].mailbox.discovered(commitment1, leader, round);
                send(
                    &mut peers[0].sender,
                    &peer3_pk,
                    assigned(&coded_block1, round, peer3_index),
                );
                context.sleep(config.link.latency * 2).await;

                assert_blocked(&oracle, &peers[3].public_key, &peers[1].public_key).await;
            },
        );
    }

    /// A chunk buffered from a peer that participates only in a later epoch is checked against
    /// that epoch's participants once discovery names the round's leader, so its sender is not
    /// blocked.
    #[test_traced]
    fn test_cross_epoch_buffered_shard_not_blocked() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (network, oracle) = simulated::Network::<deterministic::Context, P>::new(
                context.child("network"),
                simulated::Config {
                    max_peers_per_set: NZUsize!(2),
                    ..network_config(4)
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

            let scheme_epoch0 =
                Scheme::signer(SCHEME_NAMESPACE, epoch0_set.clone(), receiver_key.clone())
                    .expect("signer scheme must be created");
            let scheme_epoch1 =
                Scheme::signer(SCHEME_NAMESPACE, epoch1_set.clone(), receiver_key.clone())
                    .expect("signer scheme must be created");
            let scheme_provider =
                MultiEpochProvider::single(scheme_epoch0).with_epoch(Epoch::new(1), scheme_epoch1);

            let config: Config<_, _, _, _, _, _> = Config {
                scheme_provider,
                blocker: receiver_control.clone(),
                block_codec_config: (),
                strategy: STRATEGY,
                mailbox_size: NZUsize!(1024),
                peer_buffer_size: NZUsize!(64),
                records: NZUsize!(16),
                peer_provider: oracle.manager(),
                leader: Arc::new(|_| None),
            };

            let (engine, mailbox) = ShardEngine::new(context.child("receiver"), config);
            engine.start((sender_handle, receiver_handle));

            // A block coded for epoch 1's participants.
            let coding_config = coding_config_for_participants(epoch1_set.len() as u16);
            let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
            let coded_block = encode_block::<B, C, H>(inner, coding_config);
            let commitment = coded_block.commitment();
            let round = Round::new(Epoch::new(1), View::new(1));

            // The future peer relays its epoch 1 chunk before the round's leader is known.
            let future_peer_index = epoch1_set
                .index(&future_peer_pk)
                .expect("future peer must be in epoch 1")
                .get() as u16;
            send(
                &mut future_peer_sender,
                &receiver_pk,
                relayed(&coded_block, round, future_peer_index),
            );
            context.sleep(DEFAULT_LINK.latency * 2).await;
            assert!(
                oracle.blocked().await.unwrap().is_empty(),
                "no peers should be blocked while the chunk is buffered"
            );

            let leader = epoch0_pks[1].clone();
            mailbox.discovered(commitment, leader, round);
            context.sleep(DEFAULT_LINK.latency * 2).await;

            // The future peer participates in epoch 1, so its ingested chunk must not block it.
            let blocked = oracle.blocked().await.unwrap();
            assert!(
                blocked.is_empty(),
                "future-epoch participant should not be blocked: {blocked:?}"
            );
        });
    }

    /// A participant whose scheme provider churns away right after it verifies the leader's
    /// chunk still relays that chunk, so a peer reconstructs from its own chunk and the relay.
    #[test_traced]
    fn test_shard_broadcast_survives_provider_churn() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (network, oracle) = simulated::Network::<deterministic::Context, P>::new(
                context.child("network"),
                network_config(4),
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
            .expect("signer scheme must be created");

            // Discovery and the leader's chunk each look up the epoch's scheme once. Any later
            // lookup churns to None.
            let broadcaster_provider = ChurningProvider::new(broadcaster_scheme, 2);
            let broadcaster_config: Config<_, _, _, _, _, _> = Config {
                scheme_provider: broadcaster_provider,
                blocker: broadcaster_control.clone(),
                block_codec_config: (),
                strategy: STRATEGY,
                mailbox_size: NZUsize!(1024),
                peer_buffer_size: NZUsize!(64),
                records: NZUsize!(16),
                peer_provider: oracle.manager(),
                leader: Arc::new(|_| None),
            };
            let (broadcaster_engine, broadcaster_mailbox) =
                ChurningShardEngine::new(context.child("broadcaster"), broadcaster_config);
            broadcaster_engine.start((broadcaster_sender, broadcaster_receiver));

            let receiver_scheme = Scheme::signer(
                SCHEME_NAMESPACE,
                participants.clone(),
                private_keys[receiver_idx].clone(),
            )
            .expect("signer scheme must be created");
            let receiver_config: Config<_, _, _, _, _, _> = Config {
                scheme_provider: MultiEpochProvider::single(receiver_scheme),
                blocker: receiver_control.clone(),
                block_codec_config: (),
                strategy: STRATEGY,
                mailbox_size: NZUsize!(1024),
                peer_buffer_size: NZUsize!(64),
                records: NZUsize!(16),
                peer_provider: oracle.manager(),
                leader: Arc::new(|_| None),
            };
            let (receiver_engine, receiver_mailbox) =
                ShardEngine::new(context.child("receiver"), receiver_config);
            receiver_engine.start((receiver_sender, receiver_receiver));

            let coding_config = coding_config_for_participants(peer_keys.len() as u16);
            let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
            let coded_block = encode_block::<B, C, H>(inner, coding_config);
            let commitment = coded_block.commitment();
            let round = Round::new(Epoch::zero(), View::new(1));

            broadcaster_mailbox.discovered(commitment, leader_pk.clone(), round);
            receiver_mailbox.discovered(commitment, leader_pk.clone(), round);
            context.sleep(DEFAULT_LINK.latency).await;

            for pk in [&broadcaster_pk, &receiver_pk] {
                let index = participants
                    .index(pk)
                    .expect("recipient must be a participant")
                    .get() as u16;
                send(&mut leader_sender, pk, assigned(&coded_block, round, index));
            }
            context.sleep(DEFAULT_LINK.latency * 3).await;

            let reconstructed = receiver_mailbox.get(commitment).await;
            assert!(
                reconstructed.is_some(),
                "receiver should reconstruct after broadcaster verifies and relays its chunk"
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
                network_config(4),
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

            // Peer 2 runs its engine on a two-worker strategy that hands off every job.
            let receiver_pk = peer_keys[2].clone();
            let (control, sender, receiver) = registrations
                .remove(&receiver_pk)
                .expect("receiver should be registered");
            let scheme = Scheme::signer(
                SCHEME_NAMESPACE,
                participants.clone(),
                private_keys[2].clone(),
            )
            .expect("signer scheme must be created");
            let config: Config<_, _, _, _, _, _> = Config {
                scheme_provider: MultiEpochProvider::single(scheme),
                blocker: control,
                block_codec_config: (),
                strategy: Explorer::parallel(
                    &Rayon::new(ThreadPoolBuilder::new(NZUsize!(2))).unwrap(),
                ),
                mailbox_size: NZUsize!(1024),
                peer_buffer_size: NZUsize!(64),
                records: NZUsize!(16),
                peer_provider: oracle.manager(),
                leader: Arc::new(|_| None),
            };
            let (engine, mailbox) =
                Engine::<_, _, _, _, Gated, H, B, P, _>::new(context.child("receiver"), config);
            engine.start((sender, receiver));

            let coding_config = coding_config_for_participants(peer_keys.len() as u16);
            let make_block = |id| {
                let inner = B::new(Sha256Digest::EMPTY, Height::new(id), id);
                encode_block::<B, Gated, H>(inner, coding_config)
            };
            let leader = peer_keys[0].clone();

            // The leader delivers the receiver's chunk of A and its roots, and peer 1 relays its
            // own chunk, which starts a job whose decode holds.
            let (started_tx, started) = mpsc::channel();
            let (release, release_rx) = mpsc::channel();
            *GATE.lock() = Some(Gate {
                started: started_tx,
                release: release_rx,
                engine: thread::current().id(),
            });
            let a = make_block(1);
            let round_a = Round::new(Epoch::zero(), View::new(1));
            mailbox.discovered(a.commitment(), leader.clone(), round_a);
            send(&mut senders[0], &receiver_pk, assigned(&a, round_a, 2));
            send(&mut senders[1], &receiver_pk, relayed(&a, round_a, 1));
            while started.try_recv().is_err() {
                reschedule().await;
            }

            // The engine verifies the receiver's shard of B while A's decode holds.
            let b = make_block(2);
            let round_b = Round::new(Epoch::zero(), View::new(2));
            mailbox.discovered(b.commitment(), leader, round_b);
            let mut verified = mailbox.subscribe_assigned_shard_verified(b.commitment());
            send(&mut senders[0], &receiver_pk, assigned(&b, round_b, 2));
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

    /// Evicting or caching a record discards its reconstruction job's result, so a stale result
    /// never recreates, caches, or removes the record.
    #[test_traced]
    fn test_reconstruction_result_discarded_with_its_record() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (network, oracle) = simulated::Network::<deterministic::Context, P>::new(
                context.child("network"),
                network_config(4),
            );
            network.start();

            let mut private_keys: Vec<PrivateKey> = (0..4).map(PrivateKey::from_seed).collect();
            private_keys.sort_by_key(|s| s.public_key());
            let peer_keys: Vec<P> = private_keys.iter().map(|k| k.public_key()).collect();
            let (mut engine, mut sender) =
                unstarted(&context, &oracle, &private_keys, 0, NZUsize!(16), STRATEGY).await;
            let coding_config = coding_config_for_participants(peer_keys.len() as u16);

            for (id, action) in ["evicted", "proposed"].into_iter().enumerate() {
                // Peer 1 leads the round. Its chunk for this node, its roots, and peer 2's relayed
                // chunk reach the minimum and start a job for the commitment.
                let block = {
                    let inner = B::new(Sha256Digest::EMPTY, Height::new(1), id as u64);
                    encode_block::<B, C, H>(inner, coding_config)
                };
                let commitment = block.commitment();
                let round = Round::new(Epoch::zero(), View::new(id as u64 + 1));
                engine.handle_external_proposal(
                    &mut sender,
                    commitment,
                    peer_keys[1].clone(),
                    round,
                );
                receive(
                    &mut engine,
                    &mut sender,
                    &peer_keys[1],
                    assigned(&block, round, 0),
                );
                receive(
                    &mut engine,
                    &mut sender,
                    &peer_keys[2],
                    relayed(&block, round, 2),
                );
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

    /// While a job holds the chunks it took, the record still verifies the assigned shard.
    /// Chunks of other shards arriving meanwhile do not join the job, and a repeated or
    /// conflicting copy of a chunk the job took is ignored without blocking its sender.
    #[test_traced]
    fn test_mid_job_assigned_chunk_verified_without_joining_job() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (network, oracle) = simulated::Network::<deterministic::Context, P>::new(
                context.child("network"),
                network_config(4),
            );
            network.start();

            let mut private_keys: Vec<PrivateKey> = (0..4).map(PrivateKey::from_seed).collect();
            private_keys.sort_by_key(|key| key.public_key());
            let peer_keys: Vec<P> = private_keys.iter().map(|key| key.public_key()).collect();
            let (mut engine, mut sender) =
                unstarted(&context, &oracle, &private_keys, 0, NZUsize!(16), STRATEGY).await;
            let coding_config = coding_config_for_participants(peer_keys.len() as u16);
            let block = {
                let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                encode_block::<B, C, H>(inner, coding_config)
            };
            let other = {
                let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 200);
                encode_block::<B, C, H>(inner, coding_config)
            };
            let commitment = block.commitment();
            let round = Round::new(Epoch::zero(), View::new(1));

            // Discovery names peer 1 the leader. Its roots and the relayed chunks of peers 2 and 3
            // reach the minimum and start a job.
            engine.handle_external_proposal(&mut sender, commitment, peer_keys[1].clone(), round);
            receive(
                &mut engine,
                &mut sender,
                &peer_keys[1],
                [roots_of(&block, round).into()],
            );
            receive(
                &mut engine,
                &mut sender,
                &peer_keys[2],
                relayed(&block, round, 2),
            );
            receive(
                &mut engine,
                &mut sender,
                &peer_keys[3],
                relayed(&block, round, 3),
            );
            assert_eq!(engine.jobs.len(), 1);

            // Before the job's result is applied, the leader delivers the assigned chunk, which is
            // verified. Peer 3 then repeats its chunk and sends a conflicting one.
            receive(
                &mut engine,
                &mut sender,
                &peer_keys[1],
                relayed(&block, round, 0),
            );
            receive(
                &mut engine,
                &mut sender,
                &peer_keys[3],
                relayed(&block, round, 3),
            );
            receive(
                &mut engine,
                &mut sender,
                &peer_keys[3],
                relayed(&other, round, 3),
            );
            let Some(ReconstructionState::AwaitingQuorum(state)) = engine
                .records
                .get(&commitment)
                .and_then(CommitmentRecord::reconstruction)
            else {
                panic!("record must await quorum");
            };
            assert!(state.common.assigned_shard_verified);
            assert!(state.chunks_taken);
            assert!(state.chunks.is_empty());
            assert!(state.job.is_some());
            assert_eq!(engine.jobs.len(), 1);

            // The job rebuilds the block from the chunks it took.
            let reconstructed = finished(&mut engine).await;
            engine.complete(reconstructed);
            let record = engine.records.get(&commitment).expect("record must exist");
            assert_eq!(
                record.block().expect("block must be cached").commitment(),
                commitment
            );
            assert!(engine.jobs.is_empty());
            assert!(oracle.blocked().await.unwrap().is_empty());
        });
    }

    /// A job's spawn len is the encoded size of the chunks it takes, the minimum in every
    /// segment. It excludes surplus chunks recorded for the same segments.
    #[test_traced]
    fn test_job_len_counts_taken_chunks() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (network, oracle) = simulated::Network::<deterministic::Context, P>::new(
                context.child("network"),
                network_config(10),
            );
            network.start();

            let mut private_keys: Vec<PrivateKey> = (0..10).map(PrivateKey::from_seed).collect();
            private_keys.sort_by_key(|key| key.public_key());
            let peer_keys: Vec<P> = private_keys.iter().map(|key| key.public_key()).collect();
            let strategy = Recording::default();
            let (mut engine, mut sender) = unstarted_with::<SC, _>(
                &context,
                &oracle,
                &private_keys,
                0,
                NZUsize!(16),
                strategy.clone(),
            )
            .await;
            let coding_config = coding_config_for_participants(peer_keys.len() as u16);
            let block = {
                let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                encode_block::<B, SC, H>(inner, coding_config)
            };
            let commitment = block.commitment();
            let round = Round::new(Epoch::zero(), View::new(1));
            assert!(stream_of(&block, round, 0).len() > 1);
            let size = |index| {
                stream_of(&block, round, index)
                    .iter()
                    .map(|chunk| chunk.chunk.encode_size())
                    .sum::<usize>()
            };
            let expected = size(0) + size(2) + size(3) + size(4);

            // Discovery names peer 1 the leader. Before its roots arrive, it delivers the assigned
            // chunks and peers 2 through 6 relay their own, so every segment holds six chunks.
            engine.handle_external_proposal(&mut sender, commitment, peer_keys[1].clone(), round);
            receive(
                &mut engine,
                &mut sender,
                &peer_keys[1],
                relayed(&block, round, 0),
            );
            for index in 2..=6u16 {
                receive(
                    &mut engine,
                    &mut sender,
                    &peer_keys[usize::from(index)],
                    relayed(&block, round, index),
                );
            }
            assert!(engine.jobs.is_empty());

            // The roots bind the chunks to the commitment and start a job that takes the four
            // lowest-indexed chunks of every segment and rebuilds the block.
            receive(
                &mut engine,
                &mut sender,
                &peer_keys[1],
                [roots_of(&block, round).into()],
            );
            let reconstructed = finished(&mut engine).await;
            engine.complete(reconstructed);
            assert!(
                engine
                    .records
                    .get(&commitment)
                    .and_then(CommitmentRecord::block)
                    .is_some()
            );
            assert_eq!(*strategy.lens.lock(), [expected]);
        });
    }

    /// Sends peer `receiver` the chunk at its index that peer 0, leading the round of `roots`,
    /// sends it from `block`, then `roots`, then the chunks `relayers` relay from `block`.
    fn deliver(
        peers: &mut [Peer],
        receiver: usize,
        block: &CodedBlock<B, C, H>,
        roots: StreamRoots<B, C, H>,
        relayers: &[usize],
    ) {
        let recipient = peers[receiver].public_key.clone();
        let round = roots.round;
        let index = peers[receiver].index.get() as u16;
        let messages = relayed(block, round, index)
            .into_iter()
            .chain([roots.into()]);
        send(&mut peers[0].sender, &recipient, messages);
        for &relayer in relayers {
            let index = peers[relayer].index.get() as u16;
            send(
                &mut peers[relayer].sender,
                &recipient,
                relayed(block, round, index),
            );
        }
    }

    /// A Byzantine leader seals another block's chunks under a commitment that claims a different
    /// digest. Every chunk checks against the roots, but the decoded block fails the digest check,
    /// so the record is removed and its exact-commitment subscription closes while a digest
    /// subscription survives. The honest commitment for the claimed digest then reconstructs and
    /// satisfies the digest subscription.
    #[test_traced]
    fn test_failed_reconstruction_digest_mismatch_then_recovery() {
        let fixture: Fixture<C> = Fixture {
            num_primary_peers: 10,
            ..Default::default()
        };

        fixture.start(
            |config, context, _oracle, mut peers, _, coding_config| async move {
                // Block 1 is the claimed block, whose digest goes in the fake commitment.
                let inner1 = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block1 = encode_block::<B, C, H>(inner1, coding_config);

                // Block 2 is the data behind the chunks.
                let inner2 = B::new(Sha256Digest::EMPTY, Height::new(2), 200);
                let coded_block2 = encode_block::<B, C, H>(inner2, coding_config);
                let real_commitment2 = coded_block2.commitment();

                // The fake commitment pairs block 1's digest with block 2's coding root, context,
                // and config, so block 2's chunks and roots check against it but decode to a block
                // whose digest differs.
                let fake_commitment = Commitment::from((
                    coded_block1.digest(),
                    real_commitment2.root(),
                    real_commitment2.context(),
                    coding_config,
                ));

                let receiver_idx = 3usize;
                let leader = peers[0].public_key.clone();
                let round = Round::new(Epoch::zero(), View::new(1));

                peers[receiver_idx]
                    .mailbox
                    .discovered(fake_commitment, leader.clone(), round);
                let mut block_sub = peers[receiver_idx].mailbox.subscribe(fake_commitment);
                let mut digest_sub = peers[receiver_idx]
                    .mailbox
                    .subscribe_by_digest(coded_block1.digest());

                // The leader seals block 2 under the fake commitment, and three relays reach the
                // minimum of four chunks.
                let fake_roots = StreamRoots {
                    commitment: fake_commitment,
                    round,
                    roots: roots_of(&coded_block2, round).roots,
                };
                deliver(
                    &mut peers,
                    receiver_idx,
                    &coded_block2,
                    fake_roots,
                    &[1, 2, 4],
                );
                context.sleep(config.link.latency * 2).await;

                assert!(
                    peers[receiver_idx]
                        .mailbox
                        .get(fake_commitment)
                        .await
                        .is_none(),
                    "block should not be available after DigestMismatch"
                );

                // Commitment validity governs the exact-commitment subscription. The digest
                // subscription accepts another valid commitment.
                assert!(
                    matches!(block_sub.try_recv(), Err(TryRecvError::Closed)),
                    "subscription should close for failed reconstruction"
                );
                assert!(
                    matches!(digest_sub.try_recv(), Err(TryRecvError::Empty)),
                    "digest subscription should survive failed reconstruction"
                );

                // The engine still reconstructs block 1 under its real commitment.
                let real_commitment1 = coded_block1.commitment();
                let round2 = Round::new(Epoch::zero(), View::new(2));
                peers[receiver_idx]
                    .mailbox
                    .discovered(real_commitment1, leader.clone(), round2);
                deliver(
                    &mut peers,
                    receiver_idx,
                    &coded_block1,
                    roots_of(&coded_block1, round2),
                    &[1, 2, 4],
                );
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

    /// A Byzantine leader seals a block's chunks under a commitment whose digest, coding root, and
    /// config match but whose context digest does not. The decoded block fails the context check,
    /// so the commitment stays unresolved and its subscription closes. The real commitment then
    /// reconstructs.
    #[test_traced]
    fn test_failed_reconstruction_context_mismatch_then_recovery() {
        let fixture: Fixture<C> = Fixture {
            num_primary_peers: 10,
            ..Default::default()
        };

        fixture.start(
            |config, context, _oracle, mut peers, _, coding_config| async move {
                let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block = encode_block::<B, C, H>(inner, coding_config);
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
                let leader = peers[0].public_key.clone();
                let round = Round::new(Epoch::zero(), View::new(1));

                peers[receiver_idx]
                    .mailbox
                    .discovered(fake_commitment, leader.clone(), round);
                let mut block_sub = peers[receiver_idx].mailbox.subscribe(fake_commitment);

                let fake_roots = StreamRoots {
                    commitment: fake_commitment,
                    round,
                    roots: roots_of(&coded_block, round).roots,
                };
                deliver(
                    &mut peers,
                    receiver_idx,
                    &coded_block,
                    fake_roots,
                    &[1, 2, 4],
                );
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

                // The receiver still reconstructs the real commitment.
                let round2 = Round::new(Epoch::zero(), View::new(2));
                peers[receiver_idx]
                    .mailbox
                    .discovered(real_commitment, leader.clone(), round2);
                deliver(
                    &mut peers,
                    receiver_idx,
                    &coded_block,
                    roots_of(&coded_block, round2),
                    &[1, 2, 4],
                );
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

    /// A leader that equivocates within a round splits the committee between two commitments.
    /// The receiver gets its chunk of B, then the roots of A with relays from the peers that got
    /// A, and reconstructs A. B's roots then replace A's, and relays from the peers that got B
    /// still reconstruct the certifiable B. The leader is not blocked, since a leader that
    /// crashes after its broadcast but before its local persist legitimately re-proposes a
    /// different block for the same round after restart.
    #[test_traced]
    fn test_same_round_equivocation_preserves_certifiable_recovery() {
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

                let block_a = {
                    let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 111);
                    encode_block::<B, C, H>(inner, coding_config)
                };
                let commitment_a = block_a.commitment();
                let block_b = {
                    let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 222);
                    encode_block::<B, C, H>(inner, coding_config)
                };
                let commitment_b = block_b.commitment();

                // The receiver learns both commitments in the same round and subscribes to the
                // certifiable one before any reconstruction.
                peers[receiver_idx]
                    .mailbox
                    .discovered(commitment_a, leader.clone(), round);
                peers[receiver_idx]
                    .mailbox
                    .discovered(commitment_b, leader.clone(), round);
                let certifiable_sub = peers[receiver_idx].mailbox.subscribe(commitment_b);

                // The leader sends the receiver its chunk of B, then its chunk of A, which repeats
                // the index and is ignored, and A's roots. Peers 1, 2, 4, and 5 relay A.
                send(
                    &mut peers[0].sender,
                    &receiver_pk,
                    relayed(&block_b, round, receiver_shard_idx),
                );
                deliver(
                    &mut peers,
                    receiver_idx,
                    &block_a,
                    roots_of(&block_a, round),
                    &[1, 2, 4, 5],
                );
                context.sleep(config.link.latency * 4).await;
                let reconstructed_a = peers[receiver_idx]
                    .mailbox
                    .get(commitment_a)
                    .await
                    .expect("conflicting commitment should reconstruct first");
                assert_eq!(reconstructed_a.commitment(), commitment_a);

                // B's roots replace A's, and peers 6 through 9 relay B.
                send(
                    &mut peers[0].sender,
                    &receiver_pk,
                    [roots_of(&block_b, round).into()],
                );
                context.sleep(config.link.latency * 2).await;
                for peer in &mut peers[6..10] {
                    let index = peer.index.get() as u16;
                    send(&mut peer.sender, &receiver_pk, relayed(&block_b, round, index));
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

                let blocked_peers = oracle.blocked().await.unwrap();
                let is_blocked = blocked_peers
                    .iter()
                    .any(|(a, b)| a == &receiver_pk && b == &leader);
                assert!(
                    !is_blocked,
                    "leader must not be blocked for same-round cross-commitment chunks"
                );
            },
        );
    }

    /// A leader that sends a receiver a chunk at an index that is not the receiver's is blocked.
    #[test_traced]
    fn test_leader_unrelated_shard_blocks_peer() {
        let fixture: Fixture<C> = Fixture {
            num_primary_peers: 10,
            ..Default::default()
        };

        fixture.start(
            |config, context, oracle, mut peers, _, coding_config| async move {
                let tracked_block = {
                    let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                    encode_block::<B, C, H>(inner, coding_config)
                };
                let tracked_commitment = tracked_block.commitment();
                let unrelated_block = {
                    let inner = B::new(Sha256Digest::EMPTY, Height::new(2), 200);
                    encode_block::<B, C, H>(inner, coding_config)
                };

                let receiver_idx = 3usize;
                let receiver_pk = peers[receiver_idx].public_key.clone();
                let leader_idx = 0usize;
                let leader_pk = peers[leader_idx].public_key.clone();
                let round = Round::new(Epoch::zero(), View::new(1));

                peers[receiver_idx].mailbox.discovered(
                    tracked_commitment,
                    leader_pk.clone(),
                    round,
                );

                // The leader sends the receiver the chunk of an unrelated block at peer 1's index.
                let unrelated_index = peers[1].index.get() as u16;
                send(
                    &mut peers[leader_idx].sender,
                    &receiver_pk,
                    relayed(&unrelated_block, round, unrelated_index),
                );
                context.sleep(config.link.latency * 2).await;

                assert_blocked(&oracle, &peers[receiver_idx].public_key, &leader_pk).await;
            },
        );
    }

    /// Sends every participant but peer 0, which leads `round`, and `victim` what an honest
    /// leader sends it for `block`, and `victim` only the roots, as a leader withholding the
    /// victim's chunks does.
    fn withhold_chunks(
        peers: &mut [Peer],
        block: &CodedBlock<B, C, H>,
        round: Round,
        victim: usize,
    ) {
        let mut leader = peers[0].sender.clone();
        for (i, peer) in peers.iter().enumerate().skip(1) {
            let messages = if i == victim {
                vec![roots_of(block, round).into()]
            } else {
                assigned(block, round, peer.index.get() as u16)
            };
            send(&mut leader, &peer.public_key, messages);
        }
    }

    /// A Byzantine leader withholds the chunks destined for one participant. That participant
    /// still reconstructs the block from the chunks other participants relay, and no peer is
    /// blocked.
    #[test_traced]
    fn test_withholding_leader_victim_reconstructs_via_gossip() {
        let fixture = Fixture {
            num_primary_peers: 10,
            ..Default::default()
        };

        fixture.start(
            |config, context, oracle, mut peers, _, coding_config| async move {
                let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block = encode_block::<B, C, H>(inner, coding_config);
                let commitment = coded_block.commitment();
                let round = Round::new(Epoch::zero(), View::new(1));
                let leader = peers[0].public_key.clone();

                for peer in peers[1..].iter_mut() {
                    peer.mailbox.discovered(commitment, leader.clone(), round);
                }
                withhold_chunks(&mut peers, &coded_block, round, 1);
                context.sleep(config.link.latency * 2).await;

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

                for peer in peers[2..].iter_mut() {
                    let reconstructed = peer
                        .mailbox
                        .get(commitment)
                        .await
                        .expect("block should be reconstructed");
                    assert_eq!(reconstructed.commitment(), commitment);
                }

                // Withholding is not detectable.
                let blocked = oracle.blocked().await.unwrap();
                assert!(
                    blocked.is_empty(),
                    "no peer should be blocked in withholding leader test"
                );
            },
        );
    }

    /// When the leader withholds a participant's chunks, the participant still reconstructs the
    /// block from relayed chunks, but its assigned-shard subscription stays pending because its
    /// own shard was never verified. Voting requires that verification so the participant relays
    /// its shard and helps slower peers reach the minimum.
    #[test_traced]
    fn test_shard_subscription_pending_after_reconstruction_without_leader_shard() {
        let fixture = Fixture {
            num_primary_peers: 10,
            ..Default::default()
        };

        fixture.start(
            |config, context, _oracle, mut peers, _, coding_config| async move {
                let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block = encode_block::<B, C, H>(inner, coding_config);
                let commitment = coded_block.commitment();
                let round = Round::new(Epoch::zero(), View::new(1));
                let leader = peers[0].public_key.clone();

                let mut shard_sub = peers[1]
                    .mailbox
                    .subscribe_assigned_shard_verified(commitment);
                let block_sub = peers[1].mailbox.subscribe(commitment);

                for peer in peers[1..].iter_mut() {
                    peer.mailbox.discovered(commitment, leader.clone(), round);
                }
                withhold_chunks(&mut peers, &coded_block, round, 1);
                context.sleep(config.link.latency * 4).await;

                let reconstructed = block_sub.await.expect("block subscription should resolve");
                assert_eq!(reconstructed.commitment(), commitment);

                let mut late_shard_sub = peers[1]
                    .mailbox
                    .subscribe_assigned_shard_verified(commitment);
                context.sleep(Duration::from_millis(10)).await;
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

    /// A proposal sends each participant the chunk at its index and a non-participant the
    /// leader's own chunk. Every participant and the non-participant verify their assigned shards,
    /// the non-participant reconstructs from relayed chunks, and no peer is blocked.
    #[test_traced]
    fn test_broadcast_routes_participant_and_non_participant_shards() {
        let fixture = Fixture {
            num_secondary_peers: 1,
            ..Default::default()
        };

        fixture.start(
            |config, context, oracle, mut peers, non_participants, coding_config| async move {
                let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block = encode_block::<B, C, H>(inner, coding_config);
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

                for peer in peers.iter_mut() {
                    peer.mailbox
                        .subscribe_assigned_shard_verified(commitment)
                        .await
                        .expect("participant shard subscription should complete");
                }
                for np in non_participants.iter() {
                    np.mailbox
                        .subscribe_assigned_shard_verified(commitment)
                        .await
                        .expect("non-participant shard subscription should complete");
                }
                context.sleep(config.link.latency).await;

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

    /// A non-participant that discovers the leader after chunks are already propagating ingests
    /// the chunks it buffered and those still arriving, and reconstructs the block.
    #[test_traced]
    fn test_non_participant_reconstructs_after_discovered() {
        let fixture = Fixture {
            num_secondary_peers: 1,
            ..Default::default()
        };

        fixture.start(
            |config, context, oracle, mut peers, non_participants, coding_config| async move {
                let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block = encode_block::<B, C, H>(inner, coding_config);
                let commitment = coded_block.commitment();
                let round = Round::new(Epoch::zero(), View::new(1));

                let leader = peers[0].public_key.clone();
                peers[0].mailbox.proposed(round, coded_block.clone());

                // Participants learn the leader so they verify and relay their chunks.
                for peer in peers[1..].iter_mut() {
                    peer.mailbox.discovered(commitment, leader.clone(), round);
                }
                context.sleep(config.link.latency).await;

                let np = &non_participants[0];
                let block_sub = np.mailbox.subscribe(commitment);
                np.mailbox.discovered(commitment, leader.clone(), round);

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

    /// Delivers a proposal from peer 0 to peer 1 and checks that peer 1 verifies its assigned shard
    /// and relays its chunk. Peer 1 runs a member scheme that reports its membership but cannot
    /// sign.
    ///
    /// When `buffered` is set, the chunk arrives before peer 1 discovers the leader. Peer 3 cannot
    /// reach peer 2, so with four participants (minimum two chunks) peer 2 reconstructs only if the
    /// member relays its verified chunk.
    fn committee_member_without_share_accepts_assigned_shard(buffered: bool) {
        let fixture = Fixture::<C> {
            shareless_member: Some(1),
            ..Default::default()
        };
        fixture.start(
            move |config, context, oracle, mut peers, _, coding_config| async move {
                let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block = encode_block::<B, C, H>(inner, coding_config);
                let commitment = coded_block.commitment();
                let round = Round::new(Epoch::zero(), View::new(1));
                let leader = peers[0].public_key.clone();

                // Peer 2 hears no relay from peer 3.
                oracle
                    .remove_link(peers[3].public_key.clone(), peers[2].public_key.clone())
                    .await
                    .expect("link from peer 3 to peer 2 must exist");

                // The member receives the leader's chunk either after or before discovery.
                if !buffered {
                    peers[1]
                        .mailbox
                        .discovered(commitment, leader.clone(), round);
                    context.sleep(config.link.latency * 2).await;
                }

                peers[0].mailbox.proposed(round, coded_block);
                context.sleep(config.link.latency * 2).await;

                if buffered {
                    assert!(oracle.blocked().await.unwrap().is_empty());
                    peers[1]
                        .mailbox
                        .discovered(commitment, leader.clone(), round);
                    context.sleep(config.link.latency * 2).await;
                }

                // The leader's chunk at the member's index does not get the leader blocked.
                let blocked = oracle.blocked().await.unwrap();
                assert!(
                    blocked.is_empty(),
                    "honest leader must not be blocked: {blocked:?}"
                );

                // The member verifies the shard at its index as its assigned shard.
                let shard_sub = peers[1]
                    .mailbox
                    .subscribe_assigned_shard_verified(commitment);
                select! {
                    result = shard_sub => {
                        result.expect("assigned shard subscription must resolve");
                    },
                    _ = context.sleep(Duration::from_secs(5)) => {
                        panic!("committee member must verify its assigned shard");
                    },
                }

                // Peers 2 and 3 learn the leader so they ingest their buffered chunks.
                for peer in peers[2..].iter_mut() {
                    peer.mailbox.discovered(commitment, leader.clone(), round);
                }

                // The member reconstructs from relayed chunks, and peer 2 reaches the minimum only
                // with the member's relayed chunk.
                for (peer, who) in [(&peers[1], "committee member"), (&peers[2], "peer 2")] {
                    let block_sub = peer.mailbox.subscribe(commitment);
                    select! {
                        result = block_sub => {
                            let block = result.expect("block subscription must resolve");
                            assert_eq!(block.commitment(), commitment);
                        },
                        _ = context.sleep(Duration::from_secs(5)) => {
                            panic!("{who} must reconstruct the block");
                        },
                    }
                }

                // The member's relay gets no peer blocked.
                assert!(oracle.blocked().await.unwrap().is_empty());
            },
        );
    }

    /// A committee member without a signing share accepts the leader's chunk at its index as its
    /// assigned shard when the chunk arrives after discovery, and no peer is blocked.
    #[test_traced]
    fn test_committee_member_without_share_accepts_assigned_shard_after_discovery() {
        committee_member_without_share_accepts_assigned_shard(false);
    }

    /// A committee member without a signing share accepts the leader's chunk at its index as its
    /// assigned shard when the chunk is buffered before discovery, and no peer is blocked.
    #[test_traced]
    fn test_committee_member_without_share_accepts_assigned_shard_after_buffered_delivery() {
        committee_member_without_share_accepts_assigned_shard(true);
    }

    /// A leader whose member scheme cannot sign still broadcasts its proposal's chunks, and a peer
    /// verifies its assigned shard without blocking the leader.
    #[test_traced]
    fn test_committee_member_without_share_broadcasts_proposal() {
        let fixture = Fixture::<C> {
            shareless_member: Some(0),
            ..Default::default()
        };
        fixture.start(
            |config, context, oracle, peers, _, coding_config| async move {
                let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block = encode_block::<B, C, H>(inner, coding_config);
                let commitment = coded_block.commitment();
                let round = Round::new(Epoch::zero(), View::new(1));
                let leader = peers[0].public_key.clone();

                // Peer 1 discovers the leader before the member leader proposes.
                peers[1].mailbox.discovered(commitment, leader, round);
                context.sleep(config.link.latency * 2).await;
                peers[0].mailbox.proposed(round, coded_block);

                // Peer 1 verifies the chunk the member leader sent to its index.
                let shard_sub = peers[1]
                    .mailbox
                    .subscribe_assigned_shard_verified(commitment);
                select! {
                    result = shard_sub => {
                        result.expect("assigned shard subscription must resolve");
                    },
                    _ = context.sleep(Duration::from_secs(5)) => {
                        panic!("peer must verify the shard broadcast by the member leader");
                    },
                }

                // The member leader's chunks get no peer blocked.
                assert!(oracle.blocked().await.unwrap().is_empty());
            },
        );
    }

    /// Buffered stream messages from a leader that left the latest peer set survive while an
    /// older tracked set still lists it as primary, and are evicted once it leaves every tracked
    /// set.
    #[test_traced]
    fn test_peer_set_update_keeps_buffers_of_tracked_primaries() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let num_peers = 10usize;
            let (network, oracle) = simulated::Network::<deterministic::Context, P>::new(
                context.child("network"),
                simulated::Config {
                    tracked_peer_sets: NZUsize!(2),
                    ..network_config(num_peers)
                },
            );
            network.start();

            let mut private_keys = (0..num_peers)
                .map(|i| PrivateKey::from_seed(i as u64))
                .collect::<Vec<_>>();
            private_keys.sort_by_key(|s| s.public_key());
            let peer_keys: Vec<P> = private_keys.iter().map(|c| c.public_key()).collect();
            let participants: Set<P> = Set::from_iter_dedup(peer_keys.clone());

            let receiver_idx = 3usize;
            let receiver_pk = peer_keys[receiver_idx].clone();
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

            oracle.manager().track(0, participants.clone());
            context.sleep(Duration::from_millis(10)).await;

            let scheme = Scheme::signer(
                SCHEME_NAMESPACE,
                participants.clone(),
                private_keys[receiver_idx].clone(),
            )
            .expect("signer scheme must be created");
            let config: Config<_, _, _, _, _, _> = Config {
                scheme_provider: MultiEpochProvider::single(scheme),
                blocker: receiver_control.clone(),
                block_codec_config: (),
                strategy: STRATEGY,
                mailbox_size: NZUsize!(1024),
                peer_buffer_size: NZUsize!(64),
                records: NZUsize!(16),
                peer_provider: oracle.manager(),
                leader: Arc::new(|_| None),
            };
            let (engine, mailbox) = ShardEngine::new(context.child("receiver"), config);
            engine.start((sender_handle, receiver_handle));

            let coding_config = coding_config_for_participants(num_peers as u16);
            let receiver_index = participants
                .index(&receiver_pk)
                .expect("receiver must be a participant")
                .get() as u16;
            let coded_block = |height: u64| {
                let inner = B::new(Sha256Digest::EMPTY, Height::new(height), 100);
                encode_block::<B, C, H>(inner, coding_config)
            };

            // Set 0 stays tracked, so the leader remains a tracked primary after a set that
            // excludes it becomes the latest.
            let remaining: Set<P> =
                Set::from_iter_dedup(peer_keys.iter().filter(|pk| **pk != leader_pk).cloned());
            oracle.manager().track(1, remaining.clone());
            context.sleep(Duration::from_millis(10)).await;

            // Messages from the leader arrive before consensus names it, wait in its buffer, and
            // are ingested once it is discovered.
            let round = Round::new(Epoch::zero(), View::new(1));
            let block = coded_block(1);
            send(
                &mut leader_sender,
                &receiver_pk,
                assigned(&block, round, receiver_index),
            );
            context.sleep(DEFAULT_LINK.latency * 2).await;
            let mut shard_sub = mailbox.subscribe_assigned_shard_verified(block.commitment());
            mailbox.discovered(block.commitment(), leader_pk.clone(), round);
            context.sleep(DEFAULT_LINK.latency * 2).await;
            assert!(
                matches!(shard_sub.try_recv(), Ok(())),
                "messages from a leader outside the latest set but still tracked should be buffered"
            );

            // Tracking another set without the leader ages set 0 out of the window, so the
            // leader leaves every tracked set and its buffer is evicted.
            let round = Round::new(Epoch::zero(), View::new(2));
            let block = coded_block(2);
            send(
                &mut leader_sender,
                &receiver_pk,
                assigned(&block, round, receiver_index),
            );
            context.sleep(DEFAULT_LINK.latency * 2).await;
            oracle.manager().track(2, remaining);
            context.sleep(Duration::from_millis(10)).await;
            let mut shard_sub = mailbox.subscribe_assigned_shard_verified(block.commitment());
            mailbox.discovered(block.commitment(), leader_pk.clone(), round);
            context.sleep(DEFAULT_LINK.latency * 2).await;
            assert!(
                matches!(shard_sub.try_recv(), Err(TryRecvError::Empty)),
                "shard subscription should not resolve after the leader left every tracked set"
            );
            assert!(
                mailbox.get(block.commitment()).await.is_none(),
                "block should not reconstruct from evicted buffers"
            );
        });
    }

    /// Regression test for https://github.com/commonwarexyz/monorepo/issues/5223.
    ///
    /// A peer sends more than `peer_buffer_size` of the widest chunks the receiver admits, each
    /// claiming a one-shard config, for rounds whose leader is never known. The peer's ring retains
    /// exactly `peer_buffer_size` of them, the most recent, and evicts the oldest.
    #[test_traced]
    fn issue_5223_regression_peer_buffer_bound() {
        const ONE: CodingConfig = CodingConfig {
            minimum_shards: NZU16!(1),
            extra_shards: NZU16!(1),
        };
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (network, oracle) = simulated::Network::<deterministic::Context, P>::new(
                context.child("network"),
                network_config(4),
            );
            network.start();
            let mut private_keys: Vec<PrivateKey> = (0..4).map(PrivateKey::from_seed).collect();
            private_keys.sort_by_key(|key| key.public_key());
            let peer = private_keys[1].public_key();
            let (mut engine, mut sender) =
                unstarted(&context, &oracle, &private_keys, 0, NZUsize!(16), STRATEGY).await;
            let slots = engine.peer_buffer_size.get();

            // Under the one-shard config, a chunk of the largest coded payload carries the whole
            // payload and is wider than any chunk an honest committee codes. Each message is
            // decoded as the background receiver decodes it.
            let max_block_size = B::max_encode_size(&());
            let payload = vec![0u8; CodedBlock::<B, C, H>::max_coded_size(max_block_size)];
            let (_, shards) = C::encode(&ONE, payload.as_slice(), &STRATEGY).unwrap();
            let (roots, chunks) = C::split(&shards[1]);
            let widest = |view: u64| {
                let message = ShardMessage::<B, C, H>::from(StreamChunk::<C> {
                    config: ONE,
                    round: Round::new(Epoch::zero(), View::new(view)),
                    index: 1,
                    segment: 0,
                    root: roots[0],
                    chunk: chunks[0].clone(),
                });
                ShardMessage::<B, C, H>::decode_cfg(message.encode(), &max_block_size)
                    .expect("widest chunk must decode")
            };
            let views = 1..=2 * slots as u64;
            receive(&mut engine, &mut sender, &peer, views.clone().map(widest));

            let queue = engine.peer_buffers.get(&peer).expect("peer buffers chunks");
            assert_eq!(queue.len(), slots);
            let retained: Vec<_> = queue.iter().map(|message| message.round().view()).collect();
            let latest: Vec<_> = views.skip(slots).map(View::new).collect();
            assert_eq!(retained, latest);
        });
    }

    /// A peer's ring is kept only while it is a primary of a tracked peer set: messages from
    /// other participants are not buffered, and the ring is dropped once its peer leaves every
    /// tracked set.
    #[test_traced]
    fn test_peer_buffer_lifetime_tracks_primary_peers() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (network, oracle) = simulated::Network::<deterministic::Context, P>::new(
                context.child("network"),
                simulated::Config {
                    max_peers_per_set: NZUsize!(1),
                    ..network_config(4)
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
            let untracked_pk = peer_keys[2].clone();
            let participants: Set<P> = Set::from_iter_dedup(peer_keys);

            let receiver_control = oracle.control(receiver_pk);
            let (network_sender, _) = receiver_control
                .register(0, TEST_QUOTA)
                .await
                .expect("registration should succeed");
            let mut sender = WrappedSender::new(network_sender);
            let scheme = Scheme::signer(
                SCHEME_NAMESPACE,
                participants.clone(),
                private_keys[0].clone(),
            )
            .expect("signer scheme must be created");
            let config: Config<_, _, _, _, _, _> = Config {
                scheme_provider: MultiEpochProvider::single(scheme),
                blocker: receiver_control,
                block_codec_config: (),
                strategy: STRATEGY,
                mailbox_size: NZUsize!(16),
                peer_buffer_size: NZUsize!(4),
                records: NZUsize!(16),
                peer_provider: oracle.manager(),
                leader: Arc::new(|_| None),
            };
            let (mut engine, _mailbox) = ShardEngine::new(context.child("engine"), config);
            engine.update_primary_peers(Set::from_iter_dedup([sender_pk.clone()]));

            // No round has a known leader, so every relayed chunk waits for one.
            let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
            let coded_block = encode_block::<B, C, H>(
                inner,
                coding_config_for_participants(participants.len() as u16),
            );
            let round = Round::new(Epoch::zero(), View::new(1));
            receive(
                &mut engine,
                &mut sender,
                &sender_pk,
                relayed(&coded_block, round, 1),
            );
            receive(
                &mut engine,
                &mut sender,
                &untracked_pk,
                relayed(&coded_block, round, 2),
            );
            assert_eq!(
                buffered(&engine, &sender_pk, round),
                1,
                "a tracked primary's chunk should be buffered"
            );
            assert!(
                !engine.peer_buffers.contains_key(&untracked_pk),
                "a peer outside every tracked primary set should have no buffer"
            );

            engine.update_primary_peers(Set::default());
            assert!(
                !engine.peer_buffers.contains_key(&sender_pk),
                "peer buffer should be evicted once sender leaves every tracked set"
            );
        });
    }

    /// Messages an epoch's leader sends before it is discovered survive a cutover that removes
    /// the leader from the latest peer set while the old set stays tracked, and verify the
    /// assigned shard once the leader is discovered.
    #[test_traced]
    fn test_old_epoch_buffered_shards_survive_cutover() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let num_peers = 6usize;
            let (network, oracle) = simulated::Network::<deterministic::Context, P>::new(
                context.child("network"),
                simulated::Config {
                    tracked_peer_sets: NZUsize!(2),
                    ..network_config(num_peers - 1)
                },
            );
            network.start();

            let mut private_keys = (0..num_peers)
                .map(|i| PrivateKey::from_seed(i as u64))
                .collect::<Vec<_>>();
            private_keys.sort_by_key(|s| s.public_key());
            let peer_keys: Vec<P> = private_keys.iter().map(|c| c.public_key()).collect();

            // Epoch 1 swaps `peer_keys[0]` for `peer_keys[5]`, so the cutover changes the latest
            // set while the epoch 0 set stays tracked.
            let epoch0_set: Set<P> = Set::from_iter_dedup(peer_keys[..5].iter().cloned());
            let epoch1_set: Set<P> = Set::from_iter_dedup(peer_keys[1..].iter().cloned());

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

            oracle.manager().track(0, epoch0_set.clone());
            context.sleep(Duration::from_millis(10)).await;

            let scheme_epoch0 =
                Scheme::signer(SCHEME_NAMESPACE, epoch0_set.clone(), receiver_key.clone())
                    .expect("epoch 0 signer scheme must be created");
            let scheme_epoch1 =
                Scheme::signer(SCHEME_NAMESPACE, epoch1_set.clone(), receiver_key.clone())
                    .expect("epoch 1 signer scheme must be created");
            let config: Config<_, _, _, _, _, _> = Config {
                scheme_provider: MultiEpochProvider::single(scheme_epoch0)
                    .with_epoch(Epoch::new(1), scheme_epoch1),
                blocker: receiver_control.clone(),
                block_codec_config: (),
                strategy: STRATEGY,
                mailbox_size: NZUsize!(1024),
                peer_buffer_size: NZUsize!(64),
                records: NZUsize!(16),
                peer_provider: oracle.manager(),
                leader: Arc::new(|_| None),
            };
            let (engine, mailbox) = ShardEngine::new(context.child("receiver"), config);
            engine.start((sender_handle, receiver_handle));

            let coding_config = coding_config_for_participants(epoch0_set.len() as u16);
            let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
            let coded_block = encode_block::<B, C, H>(inner, coding_config);
            let commitment = coded_block.commitment();
            let round = Round::new(Epoch::zero(), View::new(1));
            let receiver_index = epoch0_set
                .index(&receiver_pk)
                .expect("receiver must be an epoch 0 participant")
                .get() as u16;

            send(
                &mut leader_sender,
                &receiver_pk,
                assigned(&coded_block, round, receiver_index),
            );
            context.sleep(DEFAULT_LINK.latency * 2).await;

            oracle.manager().track(1, epoch1_set);
            context.sleep(Duration::from_millis(10)).await;

            let mut shard_sub = mailbox.subscribe_assigned_shard_verified(commitment);
            mailbox.discovered(commitment, leader_pk, round);
            context.sleep(DEFAULT_LINK.latency * 2).await;
            assert!(
                matches!(shard_sub.try_recv(), Ok(())),
                "old-epoch messages from a still-tracked primary should be ingested after cutover"
            );
        });
    }

    /// A node evicted from the latest primary set still reconstructs once the leader is
    /// discovered, from chunks relayed by peers that remain primaries and the leader's buffered
    /// roots, without its own chunk.
    #[test_traced]
    fn test_evicted_node_still_reconstructs_from_buffered_peer_shards() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let num_peers = 10usize;
            let (network, oracle) = simulated::Network::<deterministic::Context, P>::new(
                context.child("network"),
                simulated::Config {
                    tracked_peer_sets: NZUsize!(2),
                    ..network_config(num_peers)
                },
            );
            network.start();

            let mut private_keys = (0..num_peers)
                .map(|i| PrivateKey::from_seed(i as u64))
                .collect::<Vec<_>>();
            private_keys.sort_by_key(|s| s.public_key());
            let peer_keys: Vec<P> = private_keys.iter().map(|c| c.public_key()).collect();
            let participants: Set<P> = Set::from_iter_dedup(peer_keys.clone());

            let receiver_idx = 1usize;
            let receiver_pk = peer_keys[receiver_idx].clone();
            let leader_pk = peer_keys[0].clone();
            let relayers = [2usize, 4, 5, 6];

            let receiver_control = oracle.control(receiver_pk.clone());
            let (evicted_sender, evicted_receiver) = receiver_control
                .register(0, TEST_QUOTA)
                .await
                .expect("registration should succeed");
            let mut senders = Vec::new();
            for index in iter::once(0).chain(relayers) {
                let (sender, _) = oracle
                    .control(peer_keys[index].clone())
                    .register(0, TEST_QUOTA)
                    .await
                    .expect("registration should succeed");
                oracle
                    .add_link(peer_keys[index].clone(), receiver_pk.clone(), DEFAULT_LINK)
                    .await
                    .expect("link should be added");
                senders.push((index, sender));
            }

            oracle.manager().track(0, participants.clone());
            context.sleep(Duration::from_millis(10)).await;

            let scheme = Scheme::signer(
                SCHEME_NAMESPACE,
                participants.clone(),
                private_keys[receiver_idx].clone(),
            )
            .expect("signer scheme must be created");
            let config: Config<_, _, _, _, _, _> = Config {
                scheme_provider: MultiEpochProvider::single(scheme),
                blocker: receiver_control.clone(),
                block_codec_config: (),
                strategy: STRATEGY,
                mailbox_size: NZUsize!(1024),
                peer_buffer_size: NZUsize!(64),
                records: NZUsize!(16),
                peer_provider: oracle.manager(),
                leader: Arc::new(|_| None),
            };
            let (engine, mailbox) = ShardEngine::new(context.child("evicted"), config);
            engine.start((evicted_sender, evicted_receiver));

            let coding_config = coding_config_for_participants(num_peers as u16);
            let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
            let coded_block = encode_block::<B, C, H>(inner, coding_config);
            let commitment = coded_block.commitment();
            let round = Round::new(Epoch::zero(), View::new(1));
            let block_sub = mailbox.subscribe(commitment);
            let mut shard_sub = mailbox.subscribe_assigned_shard_verified(commitment);

            // The leader sends only its roots, and the relayers send their own chunks, minimum
            // shards in all, before consensus names the leader.
            for (index, sender) in senders.iter_mut() {
                if *index == 0 {
                    send(sender, &receiver_pk, [roots_of(&coded_block, round).into()]);
                } else {
                    send(
                        sender,
                        &receiver_pk,
                        relayed(&coded_block, round, *index as u16),
                    );
                }
            }
            context.sleep(DEFAULT_LINK.latency * 2).await;

            // Every sender stays a primary of the latest set, which excludes the receiver.
            let latest_primary: Set<P> =
                Set::from_iter_dedup(peer_keys.iter().filter(|pk| **pk != receiver_pk).cloned());
            oracle.manager().track(1, latest_primary);
            context.sleep(Duration::from_millis(10)).await;

            mailbox.discovered(commitment, leader_pk.clone(), round);
            select! {
                result = block_sub => {
                    let block = result.expect("block subscription should resolve");
                    assert_eq!(block.commitment(), commitment);
                },
                _ = context.sleep(Duration::from_secs(5)) => {
                    panic!("block subscription did not resolve after leader discovery");
                },
            }
            assert!(
                matches!(shard_sub.try_recv(), Err(TryRecvError::Empty)),
                "the assigned shard must not verify without the receiver's own chunk"
            );
            assert!(
                oracle.blocked().await.unwrap().is_empty(),
                "no peer should be blocked when buffered messages are valid"
            );
        });
    }

    /// A participant that reconstructs from relayed chunks before the leader's chunk for its
    /// index arrives still accepts that late chunk once the block is cached: it verifies the
    /// assigned shard and is relayed so slower peers can reach quorum, while a repeated chunk
    /// from another peer is silently ignored.
    #[test_traced]
    fn test_late_leader_shard_accepted_after_quorum_transition() {
        let fixture = Fixture {
            num_primary_peers: 10,
            ..Default::default()
        };

        fixture.start(
            |config, context, oracle, mut peers, _, coding_config| async move {
                let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block = encode_block::<B, C, H>(inner, coding_config);
                let commitment = coded_block.commitment();
                let round = Round::new(Epoch::zero(), View::new(1));

                let leader_idx = 0usize;
                let victim_idx = 1usize;
                let leader = peers[leader_idx].public_key.clone();
                let victim = peers[victim_idx].public_key.clone();
                let victim_index = peers[victim_idx].index.get() as u16;
                let victim_forwarded = |metrics: String| {
                    let label = format!("index=\"{victim_idx}\"");
                    let lines: Vec<_> = metrics
                        .lines()
                        .filter(|line| line.contains(&label))
                        .collect();
                    gauges(&lines.join("\n"), "chunks_forwarded")
                };

                // Nothing the leader sends reaches the victim until the link is restored.
                oracle
                    .remove_link(leader.clone(), victim.clone())
                    .await
                    .expect("remove_link should succeed");
                peers[leader_idx]
                    .mailbox
                    .proposed(round, coded_block.clone());
                for peer in peers[1..].iter_mut() {
                    peer.mailbox.discovered(commitment, leader.clone(), round);
                }
                context.sleep(config.link.latency * 4).await;

                // The leader's roots alone let the victim reconstruct from the relayed chunks.
                oracle
                    .add_link(leader.clone(), victim.clone(), DEFAULT_LINK)
                    .await
                    .expect("add_link should succeed");
                send(
                    &mut peers[leader_idx].sender,
                    &victim,
                    [roots_of(&coded_block, round).into()],
                );
                let block_sub = peers[victim_idx].mailbox.subscribe(commitment);
                select! {
                    result = block_sub => {
                        let reconstructed = result.expect("block subscription should resolve");
                        assert_eq!(reconstructed.commitment(), commitment);
                    },
                    _ = context.sleep(Duration::from_secs(5)) => {
                        panic!("victim did not reconstruct block from relayed chunks");
                    },
                }
                let mut shard_sub = peers[victim_idx]
                    .mailbox
                    .subscribe_assigned_shard_verified(commitment);
                context.sleep(config.link.latency).await;
                assert!(
                    matches!(shard_sub.try_recv(), Err(TryRecvError::Empty)),
                    "shard subscription must not resolve before own chunk is verified"
                );
                assert_eq!(victim_forwarded(context.encode()), vec![0]);

                send(
                    &mut peers[leader_idx].sender,
                    &victim,
                    relayed(&coded_block, round, victim_index),
                );
                select! {
                    _ = shard_sub => {},
                    _ = context.sleep(Duration::from_secs(5)) => {
                        panic!("shard subscription did not resolve after late leader chunk");
                    },
                }
                assert_eq!(victim_forwarded(context.encode()), vec![1]);

                // Once the block is cached and the assigned shard verified, a repeated chunk is
                // dropped without blocking its sender.
                let extra_idx = 2usize;
                let extra_index = peers[extra_idx].index.get() as u16;
                send(
                    &mut peers[extra_idx].sender,
                    &victim,
                    relayed(&coded_block, round, extra_index),
                );
                context.sleep(config.link.latency * 2).await;
                assert!(
                    oracle.blocked().await.unwrap().is_empty(),
                    "no peer should be blocked in the late leader chunk test"
                );
            },
        );
    }

    /// An unstarted [`SC`] engine of the participant at index 0 of four, whose sends peer 2
    /// observes, with two blocks proposed in the same round.
    struct ChunkSetup {
        engine: ShardEngine<SC>,
        sender: EngineSender<SC>,
        peer_keys: Vec<P>,
        observer: simulated::Receiver<P>,
        block: CodedBlock<B, SC, H>,
        other: CodedBlock<B, SC, H>,
        round: Round,
    }

    /// Builds a [`ChunkSetup`] whose test block spans several segments.
    async fn chunk_setup(context: &deterministic::Context, oracle: &O) -> ChunkSetup {
        let mut private_keys: Vec<PrivateKey> = (0..4).map(PrivateKey::from_seed).collect();
        private_keys.sort_by_key(|key| key.public_key());
        let peer_keys: Vec<P> = private_keys.iter().map(|key| key.public_key()).collect();
        let participants: Set<P> = Set::from_iter_dedup(peer_keys.clone());
        let (mut engine, sender) =
            unstarted_with::<SC, _>(context, oracle, &private_keys, 0, NZUsize!(16), STRATEGY)
                .await;

        // Each peer's ring holds a whole block's stream, so a round can wait in full for its
        // leader.
        engine.peer_buffer_size = NZUsize!(64);
        let (_, observer) = oracle
            .control(peer_keys[2].clone())
            .register(0, TEST_QUOTA)
            .await
            .expect("registration should succeed");
        oracle
            .add_link(peer_keys[0].clone(), peer_keys[2].clone(), DEFAULT_LINK)
            .await
            .expect("link should be added");
        oracle.manager().track(0, participants);
        context.sleep(Duration::from_millis(10)).await;

        let coding_config = coding_config_for_participants(4);
        let block = |timestamp| {
            encode_block::<B, SC, H>(
                B::new(Sha256Digest::EMPTY, Height::new(1), timestamp),
                coding_config,
            )
        };
        let block_a = block(100);
        let round = Round::new(Epoch::zero(), View::new(1));
        assert!(
            stream_of(&block_a, round, 0).len() > 2,
            "the test block must span several segments"
        );
        ChunkSetup {
            engine,
            sender,
            peer_keys,
            observer,
            block: block_a,
            other: block(200),
            round,
        }
    }

    /// Once consensus discovers the round and the leader's roots seal it, the roots are relayed,
    /// and each chunk of the assigned shard is relayed as soon as it verifies, before the next
    /// chunk arrives, and only once. The assigned shard is verified only once all of its chunks
    /// are.
    #[test_traced]
    fn test_assigned_chunks_relayed_as_they_verify() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (network, oracle) = simulated::Network::<deterministic::Context, P>::new(
                context.child("network"),
                network_config(4),
            );
            network.start();
            let ChunkSetup {
                mut engine,
                mut sender,
                peer_keys,
                mut observer,
                block,
                round,
                ..
            } = chunk_setup(&context, &oracle).await;
            let commitment = block.commitment();
            let leader = peer_keys[1].clone();
            engine.handle_external_proposal(&mut sender, commitment, leader.clone(), round);
            receive(
                &mut engine,
                &mut sender,
                &leader,
                [roots_of(&block, round).into()],
            );
            let relayed = next_message::<SC>(&context, &mut observer).await;
            assert!(relayed == Some(ShardMessage::Roots(roots_of(&block, round))));
            let (response, mut verified) = oneshot::channel();
            engine.handle_assigned_shard_verified_subscription(commitment, response);

            let assigned = stream_of(&block, round, 0);
            for chunk in &assigned {
                assert!(
                    matches!(verified.try_recv(), Err(TryRecvError::Empty)),
                    "the assigned shard must not verify before its last chunk"
                );
                receive(&mut engine, &mut sender, &leader, [chunk.clone().into()]);
                let relayed = next_message::<SC>(&context, &mut observer)
                    .await
                    .expect("a verified chunk must be relayed before the next one arrives");
                assert!(
                    relayed == ShardMessage::Stream(chunk.clone()),
                    "the relayed chunk must be the verified one"
                );

                // A repeat is not relayed again.
                receive(&mut engine, &mut sender, &leader, [chunk.clone().into()]);
                assert!(next_message::<SC>(&context, &mut observer).await.is_none());
            }
            assert!(matches!(verified.try_recv(), Ok(())));

            // Repeats after the shard verified are not relayed either.
            receive(
                &mut engine,
                &mut sender,
                &leader,
                assigned.iter().cloned().map(ShardMessage::from),
            );
            assert!(next_message::<SC>(&context, &mut observer).await.is_none());
            assert_eq!(
                gauges(&context.encode(), "chunks_forwarded"),
                vec![assigned.len() as i64]
            );
            assert!(oracle.blocked().await.unwrap().is_empty());
        });
    }

    /// Reconstruction needs the minimum of verified chunks in every segment, from any shards.
    /// Each segment here takes its chunks from a different pair of shards, some including the
    /// local shard's chunk from the leader, whose own shard never reaches another participant.
    #[test_traced]
    fn test_reconstruction_from_chunks_mixed_across_peers() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (network, oracle) = simulated::Network::<deterministic::Context, P>::new(
                context.child("network"),
                network_config(4),
            );
            network.start();
            let ChunkSetup {
                mut engine,
                mut sender,
                peer_keys,
                block,
                round,
                ..
            } = chunk_setup(&context, &oracle).await;
            let commitment = block.commitment();
            let leader = peer_keys[1].clone();
            engine.handle_external_proposal(&mut sender, commitment, leader.clone(), round);
            receive(
                &mut engine,
                &mut sender,
                &leader,
                [roots_of(&block, round).into()],
            );

            let chunks: Vec<_> = (0..4)
                .map(|index| stream_of(&block, round, index))
                .collect();
            for segment in 0..chunks[0].len() {
                for index in [[2u16, 3], [0, 3], [0, 2]][segment % 3] {
                    assert!(
                        engine.jobs.is_empty(),
                        "every segment must reach the minimum first"
                    );
                    let from = if index == 0 {
                        &leader
                    } else {
                        &peer_keys[usize::from(index)]
                    };
                    let chunk = chunks[usize::from(index)][segment].clone();
                    receive(&mut engine, &mut sender, from, [chunk.into()]);
                }
            }

            let reconstructed = finished(&mut engine).await;
            engine.complete(reconstructed);
            let cached = engine
                .records
                .get(&commitment)
                .and_then(CommitmentRecord::block)
                .expect("block must be reconstructed from chunks");
            assert_eq!(cached.commitment(), commitment);
            assert!(oracle.blocked().await.unwrap().is_empty());
        });
    }

    /// A chunk that fails verification, claims another coding config, or names a segment beyond
    /// the bound blocks its sender. A well-formed chunk of another payload blocks no one, and
    /// stays apart from the candidate the leader's roots seal.
    #[test_traced]
    fn test_invalid_chunk_blocks_peer() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (network, oracle) = simulated::Network::<deterministic::Context, P>::new(
                context.child("network"),
                network_config(4),
            );
            network.start();
            let ChunkSetup {
                mut engine,
                mut sender,
                peer_keys,
                block,
                other,
                round,
                ..
            } = chunk_setup(&context, &oracle).await;
            let leader = peer_keys[1].clone();
            elect(&mut engine, &leader);
            let honest: Vec<_> = (0..4)
                .map(|index| stream_of(&block, round, index))
                .collect();
            let foreign: Vec<_> = (0..4)
                .map(|index| stream_of(&other, round, index))
                .collect();
            let segment = (0..honest[0].len())
                .find(|&segment| honest[0][segment].root != foreign[0][segment].root)
                .expect("the blocks must differ in some segment");

            receive(
                &mut engine,
                &mut sender,
                &leader,
                [honest[0][0].clone().into()],
            );
            receive(
                &mut engine,
                &mut sender,
                &peer_keys[2],
                [foreign[2][segment].clone().into()],
            );
            assert_eq!(engine.streams[&round].chunks.len(), 2);
            receive(
                &mut engine,
                &mut sender,
                &leader,
                [roots_of(&block, round).into()],
            );
            receive(
                &mut engine,
                &mut sender,
                &peer_keys[3],
                [foreign[3][segment].clone().into()],
            );
            assert_eq!(engine.streams[&round].chunks.len(), 3);
            assert!(oracle.blocked().await.unwrap().is_empty());

            // Another shard's chunk claimed as the sender's own fails verification.
            let mut forged = honest[2][0].clone();
            forged.index = 3;
            receive(&mut engine, &mut sender, &peer_keys[3], [forged.into()]);
            assert_blocked(&oracle, &peer_keys[0], &peer_keys[3]).await;

            let mut misconfigured = honest[2][1].clone();
            misconfigured.config = coding_config_for_participants(5);
            receive(
                &mut engine,
                &mut sender,
                &peer_keys[2],
                [misconfigured.into()],
            );
            assert_blocked(&oracle, &peer_keys[0], &peer_keys[2]).await;

            let mut beyond = honest[0][1].clone();
            beyond.segment = engine.max_segments;
            receive(&mut engine, &mut sender, &leader, [beyond.into()]);
            assert_blocked(&oracle, &peer_keys[0], &leader).await;
            assert_eq!(engine.streams[&round].chunks.len(), 3);
        });
    }

    /// Chunks and roots that arrive before the round's leader is known wait in their senders'
    /// buffers. Discovery names the leader and ingests them: the leader's chunks are relayed in
    /// segment order, the assigned shard verifies, and the block reconstructs.
    #[test_traced]
    fn test_stream_chunks_buffered_until_leader_known() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (network, oracle) = simulated::Network::<deterministic::Context, P>::new(
                context.child("network"),
                network_config(4),
            );
            network.start();
            let ChunkSetup {
                mut engine,
                mut sender,
                peer_keys,
                mut observer,
                block,
                round,
                ..
            } = chunk_setup(&context, &oracle).await;
            let commitment = block.commitment();
            let leader = peer_keys[1].clone();

            let own = stream_of(&block, round, 0);
            receive(
                &mut engine,
                &mut sender,
                &leader,
                assigned(&block, round, 0),
            );
            receive(
                &mut engine,
                &mut sender,
                &peer_keys[2],
                relayed(&block, round, 2),
            );
            assert_eq!(buffered(&engine, &leader, round), own.len() + 1);
            assert_eq!(buffered(&engine, &peer_keys[2], round), own.len());
            assert!(engine.streams.is_empty());
            assert!(engine.records.is_empty());
            assert!(next_message::<SC>(&context, &mut observer).await.is_none());

            let (response, mut verified) = oneshot::channel();
            engine.handle_assigned_shard_verified_subscription(commitment, response);
            engine.handle_external_proposal(&mut sender, commitment, leader.clone(), round);
            assert_eq!(buffered(&engine, &leader, round), 0);
            assert_eq!(buffered(&engine, &peer_keys[2], round), 0);
            assert!(matches!(verified.try_recv(), Ok(())));
            for chunk in &own {
                let relayed = next_message::<SC>(&context, &mut observer)
                    .await
                    .expect("buffered leader chunks must be relayed once the leader is known");
                assert!(relayed == ShardMessage::Stream(chunk.clone()));
            }

            let reconstructed = finished(&mut engine).await;
            engine.complete(reconstructed);
            assert!(
                engine
                    .records
                    .get(&commitment)
                    .and_then(CommitmentRecord::block)
                    .is_some()
            );
            assert!(oracle.blocked().await.unwrap().is_empty());
        });
    }

    /// A proposal coded in several segments reaches every participant and non-participant as
    /// chunks, each participant relays its own, and all of them verify their assigned shard and
    /// reconstruct the block.
    #[test_traced]
    fn test_e2e_chunked_broadcast_and_reconstruction() {
        let fixture: Fixture<SC> = Fixture {
            num_primary_peers: 10,
            num_secondary_peers: 1,
            ..Default::default()
        };

        fixture.start(
            |config, context, oracle, mut peers, non_participants, coding_config| async move {
                let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block = encode_block::<B, SC, H>(inner, coding_config);
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
                context.sleep(config.link.latency * 3).await;

                for peer in peers.iter_mut() {
                    peer.mailbox
                        .subscribe_assigned_shard_verified(commitment)
                        .await
                        .expect("participant shard subscription should complete");
                    let reconstructed = peer
                        .mailbox
                        .get(commitment)
                        .await
                        .expect("participant should reconstruct the block");
                    assert_eq!(reconstructed.commitment(), commitment);
                }
                for np in non_participants.iter() {
                    np.mailbox
                        .subscribe_assigned_shard_verified(commitment)
                        .await
                        .expect("non-participant shard subscription should complete");
                    let reconstructed = np
                        .mailbox
                        .get(commitment)
                        .await
                        .expect("non-participant should reconstruct the block");
                    assert_eq!(reconstructed.commitment(), commitment);
                }
                assert!(oracle.blocked().await.unwrap().is_empty());
            },
        );
    }

    /// A proposal with no segment streamed beforehand reaches each participant as the chunk of
    /// its index in every segment, in segment order, followed by the roots that bind them to the
    /// commitment. The proposer caches the block and counts its assigned shard as verified.
    /// Reconstruction at the peers is pinned by [`test_e2e_chunked_broadcast_and_reconstruction`].
    #[test_traced]
    fn test_whole_block_proposal_streams_chunks_then_roots() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (network, oracle) = simulated::Network::<deterministic::Context, P>::new(
                context.child("network"),
                network_config(4),
            );
            network.start();
            let ChunkSetup {
                mut engine,
                mut sender,
                mut observer,
                block,
                round,
                ..
            } = chunk_setup(&context, &oracle).await;
            let commitment = block.commitment();
            let (response, mut verified) = oneshot::channel();
            engine.handle_assigned_shard_verified_subscription(commitment, response);

            engine.broadcast_shards(&mut sender, round, Arc::new(block.clone()));
            for chunk in stream_of(&block, round, 2) {
                let sent = next_message::<SC>(&context, &mut observer)
                    .await
                    .expect("every segment's chunk must be sent");
                assert!(
                    sent == ShardMessage::Stream(chunk),
                    "chunks must arrive in segment order"
                );
            }
            let sent = next_message::<SC>(&context, &mut observer)
                .await
                .expect("the roots must follow the chunks");
            assert!(sent == ShardMessage::Roots(roots_of(&block, round)));
            assert!(next_message::<SC>(&context, &mut observer).await.is_none());

            assert!(matches!(verified.try_recv(), Ok(())));
            let record = &engine.records[&commitment];
            assert!(record.block().is_some());
            assert!(record.is_assigned_shard_ready());
            assert!(oracle.blocked().await.unwrap().is_empty());
        });
    }

    /// A participant relays each chunk the round's known leader streams for its index the moment
    /// it verifies, before the commitment exists. Forwards from other participants are stored but
    /// not relayed. Once the leader's roots seal the round and consensus names the commitment,
    /// the roots are relayed, and the stored chunks verify the assigned shard and reconstruct the
    /// block without relaying any chunk again.
    #[test_traced]
    fn test_stream_chunks_forwarded_before_roots_then_reconstructed() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (network, oracle) = simulated::Network::<deterministic::Context, P>::new(
                context.child("network"),
                network_config(4),
            );
            network.start();
            let ChunkSetup {
                mut engine,
                mut sender,
                peer_keys,
                mut observer,
                block,
                round,
                ..
            } = chunk_setup(&context, &oracle).await;
            let commitment = block.commitment();
            let leader = peer_keys[1].clone();
            elect(&mut engine, &leader);

            let own = stream_of(&block, round, 0);
            for chunk in &own {
                receive(&mut engine, &mut sender, &leader, [chunk.clone().into()]);
                let relayed = next_message::<SC>(&context, &mut observer)
                    .await
                    .expect("the leader's chunk must be relayed on arrival");
                assert!(relayed == ShardMessage::Stream(chunk.clone()));
            }
            for index in [2u16, 3] {
                receive(
                    &mut engine,
                    &mut sender,
                    &peer_keys[usize::from(index)],
                    relayed(&block, round, index),
                );
            }
            assert!(next_message::<SC>(&context, &mut observer).await.is_none());
            assert!(!engine.records.contains_key(&commitment));
            assert!(engine.jobs.is_empty());

            let (response, mut verified) = oneshot::channel();
            engine.handle_assigned_shard_verified_subscription(commitment, response);
            receive(
                &mut engine,
                &mut sender,
                &leader,
                [roots_of(&block, round).into()],
            );
            assert!(matches!(verified.try_recv(), Err(TryRecvError::Empty)));
            assert!(engine.jobs.is_empty());

            engine.handle_external_proposal(&mut sender, commitment, leader.clone(), round);
            assert!(matches!(verified.try_recv(), Ok(())));
            let relayed = next_message::<SC>(&context, &mut observer).await;
            assert!(relayed == Some(ShardMessage::Roots(roots_of(&block, round))));
            let reconstructed = finished(&mut engine).await;
            engine.complete(reconstructed);
            let cached = engine
                .records
                .get(&commitment)
                .and_then(CommitmentRecord::block)
                .expect("block must be reconstructed from streamed chunks");
            assert_eq!(cached.commitment(), commitment);

            assert!(next_message::<SC>(&context, &mut observer).await.is_none());
            assert_eq!(
                gauges(&context.encode(), "chunks_forwarded"),
                vec![own.len() as i64]
            );
            assert!(oracle.blocked().await.unwrap().is_empty());
        });
    }

    /// Only the round's leader may stream a chunk it does not own, and only the chunk for this
    /// node, while any participant may stream its own chunk, which is stored but not relayed.
    #[test_traced]
    fn test_stream_forward_only_for_leader_chunks_of_local_index() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (network, oracle) = simulated::Network::<deterministic::Context, P>::new(
                context.child("network"),
                network_config(4),
            );
            network.start();
            let ChunkSetup {
                mut engine,
                mut sender,
                peer_keys,
                mut observer,
                block,
                round,
                ..
            } = chunk_setup(&context, &oracle).await;
            let leader = peer_keys[1].clone();
            elect(&mut engine, &leader);

            // A participant's own chunk waits until the leader's chunk opens the round, and is
            // then stored but not relayed.
            let own_of_3 = stream_of(&block, round, 3).remove(0);
            receive(&mut engine, &mut sender, &peer_keys[3], [own_of_3.into()]);
            assert!(engine.streams.is_empty());
            let first = stream_of(&block, round, 0).remove(0);
            receive(&mut engine, &mut sender, &leader, [first.clone().into()]);
            let relayed = next_message::<SC>(&context, &mut observer)
                .await
                .expect("the leader's chunk must be relayed");
            assert!(relayed == ShardMessage::Stream(first));
            assert!(next_message::<SC>(&context, &mut observer).await.is_none());
            assert_eq!(engine.streams.get(&round).map(|s| s.seen.len()), Some(2));
            assert!(oracle.blocked().await.unwrap().is_empty());

            // A non-leader streaming this node's chunk is blocked, and nothing is relayed.
            let ours = stream_of(&block, round, 0).remove(1);
            receive(&mut engine, &mut sender, &peer_keys[2], [ours.into()]);
            assert!(next_message::<SC>(&context, &mut observer).await.is_none());
            assert_blocked(&oracle, &peer_keys[0], &peer_keys[2]).await;

            // The leader streaming another participant's chunk is blocked.
            let other = stream_of(&block, round, 3).remove(1);
            receive(&mut engine, &mut sender, &leader, [other.into()]);
            assert!(next_message::<SC>(&context, &mut observer).await.is_none());
            assert_blocked(&oracle, &peer_keys[0], &leader).await;
            assert_eq!(engine.streams.get(&round).map(|s| s.seen.len()), Some(2));
        });
    }

    /// The leader's chunk for this node under a second root, as from a replacement candidate, is
    /// stored and relayed beside the first, and a chunk under a third root is ignored without
    /// blocking the leader.
    #[test_traced]
    fn test_stream_keeps_two_candidates_per_chunk() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (network, oracle) = simulated::Network::<deterministic::Context, P>::new(
                context.child("network"),
                network_config(4),
            );
            network.start();
            let ChunkSetup {
                mut engine,
                mut sender,
                peer_keys,
                mut observer,
                block,
                other,
                round,
            } = chunk_setup(&context, &oracle).await;
            let leader = peer_keys[1].clone();
            elect(&mut engine, &leader);
            let third = encode_block::<B, SC, H>(
                B::new(Sha256Digest::EMPTY, Height::new(1), 300),
                coding_config_for_participants(4),
            );
            let candidates = [&block, &other, &third].map(|block| stream_of(block, round, 0));
            let segment = (0..candidates[0].len())
                .find(|&segment| {
                    let roots = candidates.each_ref().map(|chunks| chunks[segment].root);
                    roots[0] != roots[1] && roots[0] != roots[2] && roots[1] != roots[2]
                })
                .expect("the candidates must differ in some segment");

            for (chunks, relays) in candidates.into_iter().zip([true, true, false]) {
                let chunk = chunks[segment].clone();
                receive(&mut engine, &mut sender, &leader, [chunk.clone().into()]);
                let relayed = next_message::<SC>(&context, &mut observer).await;
                assert_eq!(relayed.is_some(), relays);
                if let Some(relayed) = relayed {
                    assert!(relayed == ShardMessage::Stream(chunk));
                }
            }
            assert_eq!(engine.streams[&round].chunks.len(), 2);
            assert!(oracle.blocked().await.unwrap().is_empty());
        });
    }

    /// Roots a participant relays for a commitment consensus has not signaled in the round wait in
    /// its buffer, and roots from the leader that do not hash to the commitment's coding root
    /// block the leader. Neither seals the round, so the leader's honest roots still seal it
    /// afterward. Once consensus signals a commitment, relayed roots that do not hash to it block
    /// the relayer, and relayed roots that do seal the round.
    #[test_traced]
    fn test_stream_roots_mismatch_blocks_leader() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (network, oracle) = simulated::Network::<deterministic::Context, P>::new(
                context.child("network"),
                network_config(4),
            );
            network.start();
            let ChunkSetup {
                mut engine,
                mut sender,
                peer_keys,
                block,
                other,
                round,
                ..
            } = chunk_setup(&context, &oracle).await;
            let leader = peer_keys[1].clone();
            elect(&mut engine, &leader);
            let sealed = |engine: &ShardEngine<SC>| {
                engine
                    .streams
                    .get(&round)
                    .and_then(|stream| stream.sealed.as_ref())
                    .map(|(commitment, _)| *commitment)
            };

            receive(
                &mut engine,
                &mut sender,
                &peer_keys[3],
                [roots_of(&block, round).into()],
            );
            assert_eq!(buffered(&engine, &peer_keys[3], round), 1);
            assert!(sealed(&engine).is_none());

            let mut mismatched = roots_of(&block, round);
            mismatched.roots = roots_of(&other, round).roots;
            receive(&mut engine, &mut sender, &leader, [mismatched.into()]);
            assert_blocked(&oracle, &peer_keys[0], &leader).await;
            assert!(sealed(&engine).is_none());

            receive(
                &mut engine,
                &mut sender,
                &leader,
                [roots_of(&block, round).into()],
            );
            assert_eq!(sealed(&engine), Some(block.commitment()));

            engine.handle_notarized_commitment(&mut sender, other.commitment(), round);
            let mut forged = roots_of(&other, round);
            forged.roots = roots_of(&block, round).roots;
            receive(&mut engine, &mut sender, &peer_keys[2], [forged.into()]);
            assert_blocked(&oracle, &peer_keys[0], &peer_keys[2]).await;
            assert_eq!(sealed(&engine), Some(block.commitment()));

            receive(
                &mut engine,
                &mut sender,
                &peer_keys[3],
                [roots_of(&other, round).into()],
            );
            assert_eq!(sealed(&engine), Some(other.commitment()));
        });
    }

    /// A round's stream record is dropped once the record window no longer admits the round.
    #[test_traced]
    fn test_stream_record_dropped_on_window_eviction() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (network, oracle) = simulated::Network::<deterministic::Context, P>::new(
                context.child("network"),
                network_config(4),
            );
            network.start();
            let ChunkSetup {
                mut engine,
                mut sender,
                peer_keys,
                block,
                round,
                ..
            } = chunk_setup(&context, &oracle).await;
            let leader = peer_keys[1].clone();
            elect(&mut engine, &leader);
            let chunk = stream_of(&block, round, 0).remove(0);
            receive(&mut engine, &mut sender, &leader, [chunk.into()]);
            assert!(engine.streams.contains_key(&round));

            let config = coding_config_for_participants(4);
            for view in 2..=(engine.window.get() as u64 + 1) {
                let later = encode_block::<B, SC, H>(
                    B::new(Sha256Digest::EMPTY, Height::new(view), view),
                    config,
                );
                engine
                    .cache_block(Round::new(Epoch::zero(), View::new(view)), Arc::new(later))
                    .expect("same epoch");
            }
            engine.trim();
            assert!(!engine.streams.contains_key(&round));
        });
    }

    /// A leader sends each participant the chunk at its index as each segment is coded, and once
    /// the block sealed from those segments is proposed, sends only its roots.
    #[test_traced]
    fn test_streamed_proposal_sends_roots_only() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (network, oracle) = simulated::Network::<deterministic::Context, P>::new(
                context.child("network"),
                network_config(4),
            );
            network.start();
            let ChunkSetup {
                mut engine,
                mut sender,
                mut observer,
                block,
                round,
                ..
            } = chunk_setup(&context, &oracle).await;
            let shards: Vec<_> = (0..4)
                .map(|index| stream_of(&block, round, index))
                .collect();
            for (segment, chunk) in shards[2].iter().enumerate() {
                engine.stream_segment(
                    &mut sender,
                    round,
                    StreamedSegment::<SC> {
                        segment: chunk.segment,
                        root: chunk.root,
                        chunks: shards
                            .iter()
                            .map(|shard| shard[segment].chunk.clone())
                            .collect(),
                    },
                );
                let sent = next_message::<SC>(&context, &mut observer)
                    .await
                    .expect("each segment's chunk must be sent as it is coded");
                assert!(sent == ShardMessage::Stream(chunk.clone()));
            }

            engine.broadcast_shards(&mut sender, round, Arc::new(block.clone()));
            let sent = next_message::<SC>(&context, &mut observer)
                .await
                .expect("the roots must be sent");
            assert!(sent == ShardMessage::Roots(roots_of(&block, round)));
            assert!(next_message::<SC>(&context, &mut observer).await.is_none());
            assert!(
                engine
                    .records
                    .get(&block.commitment())
                    .and_then(CommitmentRecord::block)
                    .is_some()
            );
        });
    }

    /// A notarization lets a node the leader never reached reconstruct from the chunks other
    /// participants relay and the roots one of them relays, without naming the round's leader.
    /// That reconstruction does not verify the assigned shard, which the leader's chunks still
    /// verify once discovery names it.
    #[test_traced]
    fn test_notarized_commitment_reconstructs_from_relayed_chunks_without_leader() {
        let fixture: Fixture<C> = Fixture {
            num_primary_peers: 10,
            ..Default::default()
        };

        fixture.start(
            |config, context, oracle, mut peers, _, coding_config| async move {
                let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block = encode_block::<B, C, H>(inner, coding_config);
                let commitment = coded_block.commitment();
                let round = Round::new(Epoch::zero(), View::new(1));
                let receiver_idx = 3usize;
                let receiver = peers[receiver_idx].public_key.clone();
                let block_sub = peers[receiver_idx].mailbox.subscribe(commitment);

                // Four participants relay their own chunks, and one of them the roots.
                for sender_idx in [1usize, 2, 4, 5] {
                    let index = peers[sender_idx].index.get() as u16;
                    send(
                        &mut peers[sender_idx].sender,
                        &receiver,
                        relayed(&coded_block, round, index),
                    );
                }
                send(
                    &mut peers[1].sender,
                    &receiver,
                    [roots_of(&coded_block, round).into()],
                );
                context.sleep(config.link.latency * 2).await;
                assert!(
                    peers[receiver_idx].mailbox.get(commitment).await.is_none(),
                    "block should not reconstruct before the commitment is notarized"
                );

                peers[receiver_idx].mailbox.notarized(commitment, round);
                select! {
                    _ = block_sub => {},
                    _ = context.sleep(Duration::from_secs(5)) => {
                        panic!("block did not reconstruct after the notarization");
                    },
                }
                let mut readiness = peers[receiver_idx]
                    .mailbox
                    .subscribe_assigned_shard_verified(commitment);
                assert!(
                    matches!(readiness.try_recv(), Err(TryRecvError::Empty)),
                    "leaderless reconstruction must not satisfy assigned shard readiness"
                );

                let leader = peers[0].public_key.clone();
                peers[receiver_idx]
                    .mailbox
                    .discovered(commitment, leader, round);
                let receiver_index = peers[receiver_idx].index.get() as u16;
                send(
                    &mut peers[0].sender,
                    &receiver,
                    assigned(&coded_block, round, receiver_index),
                );
                select! {
                    _ = readiness => {},
                    _ = context.sleep(Duration::from_secs(5)) => {
                        panic!("assigned shard did not verify after leader discovery");
                    },
                }
                assert!(
                    oracle.blocked().await.unwrap().is_empty(),
                    "relayed chunks and roots should not block peers"
                );
            },
        );
    }
}
