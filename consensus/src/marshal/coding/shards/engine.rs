//! Shard engine for erasure-coded block distribution and reconstruction.
//!
//! The engine sends and receives [`CodedBlock`]s coded with a [`Segmentable`] scheme, one
//! segment at a time, and reconstructs blocks from the chunks it receives.
//!
//! # Overview
//!
//! A proposer codes its block's body while the application is still building the block (see
//! [`crate::BodySink`]). As each segment is coded, it sends every participant the chunk at that
//! participant's index. Once the block is sealed, it sends the tail segment's chunks and then the
//! roots of every segment. Together the roots hash to the coding root in the block's
//! [`Commitment`].
//!
//! A chunk names only its round, segment, and segment root, so nothing ties it to a commitment
//! until consensus names one and roots that hash to its coding root are known. Until then every
//! message waits in its sender's ring. Binding a named commitment's roots copies the chunks under
//! them into the commitment's record, which keeps them and every later chunk under them. There the
//! node checks and relays its assigned chunks and reconstructs the block from the chunks other
//! participants relay.
//!
//! The engine treats a node as a participant in an epoch when its scheme for that epoch reports
//! the node's membership through [`CertificateScheme::me`]. Signer and member schemes report it,
//! and verifier schemes do not. A participant's assigned chunks are the ones at its index, and a
//! non-participant's assigned chunks are the leader's own.
//!
//! # Message Flow
//!
//! ```text
//!    leader L                         participant i                           participant j
//!        |                                  |                                       |
//!        |--- chunk (0, i) ---------------->| ring[L]                               |
//!        |               ...                |                                       |
//!        |--- chunk (S-1, i) -------------->| ring[L]                               |
//!        |--- roots R --------------------->| ring[L]                               |
//!        |--- proposal C, via consensus --->|                                       |
//!        |                                  | C named, R hashes to C -> bind R      |
//!        |                                  |--- roots R -------------------------->| ring[i]
//!        |                                  | each (s, i) checks against R[s]       |
//!        |                                  |--- chunk (s, i), each s ------------->| ring[i]
//!        |                                  |<-- chunk (s, j), each s --------------|
//!        |                                  | record keeps each (s, j) -> shard j   |
//!        |                                  | enough shards -> check, decode        |
//!        v                                  v                                       v
//! ```
//!
//! A participant votes to notarize only once every chunk of its own shard has checked against roots
//! that hash to the commitment, and it relays each of those chunks as it checks.
//!
//! Once its roots bind, a record keeps every chunk it ingests. Of the honest participants whose
//! votes notarize a commitment, the first to bind its roots therefore keeps every chunk the others
//! relay. They bind later and relay after binding, unless a relay before naming stands in, and such
//! a relay that arrived before the first one bound was still in its rings then (see Relaying Before
//! Naming). Either it collects enough shards to reconstruct the block, or the proposer, which holds
//! the block, is one of those voters. A node that binds too late to collect the relays fetches the
//! block from one that has it.
//!
//! # Where Data Waits
//!
//! ```text
//!   rings, one per primary peer                               records, one per named commitment
//!   (last peer_buffer_size messages)                          (at most Config::records)
//!
//!   ring[L]  [ (0,i) (1,i) .. (S-1,i)  R ]  --+
//!   ring[j]  [ (0,j) (1,j) .. (S-1,j)  R ]  --+-- bind R to C -->  record C
//!   ring[k]  [ (0,k) (1,k) ..            ]  --+                      roots R
//!               ^                                                    assigned chunks
//!               every message lands here,   later (s,k) ------->     chunks of k, by segment
//!               oldest evicted first,       on arrival               shards j, k ...
//!               never removed by a bind                                |
//!                                                                      v
//!                                                                    block
//! ```
//!
//! A ring keeps its peer's latest messages and is read by clone, never drained, so two commitments
//! whose roots share a segment root can both use the same chunks. A chunk needs its ring only until
//! a record ingests it. Binding copies the chunks under the roots from the rings into the record,
//! the record ingests each later chunk under them as it arrives, and what the record ingests stays
//! there even once later messages push the chunk out of its sender's ring.
//!
//! Rings are kept only for primary peers of a tracked peer set, matching
//! [`commonware_broadcast::buffered`]. A peer loses its ring once no tracked set lists it as a
//! primary. One that leaves only the latest set keeps its ring through the overlap window, so a
//! departing participant's chunks for its final epoch are still used.
//!
//! # Binding
//!
//! Only local consensus signals create records: [`Mailbox::proposed`], [`Mailbox::discovered`],
//! and [`Mailbox::notarized`]. When a record exists and roots that hash to its coding root are
//! known, from the leader or relayed by any participant, the engine binds them once and relays
//! them once if it is a participant. Roots that claim a named commitment and do not hash to its
//! coding root block their sender. Roots for a commitment consensus has not named only wait, and
//! roots for one that is already bound, or that this node proposed, are ignored.
//!
//! Once the roots bind, the record ingests every chunk under them that claims the record's epoch,
//! both those already in the rings and those that arrive later.
//!
//! - A chunk at the node's assigned index is checked against its segment root and, by a
//!   participant, relayed to all peers. When every segment's chunk is in, the assembled shard
//!   completes the assigned-shard check that readiness to vote waits on.
//! - The record keeps a chunk at its sender's own index unless it already holds that sender's chunk
//!   of the segment. Once it holds the sender's chunk of every segment, the assembled shard waits
//!   with other senders' shards until enough are available to decode, and a reconstruction job
//!   checks only the shards decoding needs.
//!
//! # Relaying Before Naming
//!
//! A [`Scheduled`](crate::simplex::elector::Scheduled) elector names a round's leader before
//! consensus names the round's commitment. With one in [`Config::elector`], a participant relays
//! each chunk at its index as soon as that leader sends it, so its peers collect each segment
//! while the leader is still streaming later ones.
//!
//! ```text
//!   time -------------------------------------------------------------------------------------->
//!
//!   leader L         (0, i)         (1, i)           ...        (S-1, i)         roots R
//!                       |              |                            |               |
//!                       v              v                            v               v
//!   participant i    check,         check,           ...         check,          ring[L]
//!                     relay          relay                        relay
//!                       |              |                            |
//!                       v              v                            v
//!   peers            (0, i)         (1, i)           ...        (S-1, i)
//! ```
//!
//! Let H be [`Config::records`] and S the most segments a block at the
//! [`Config::block_codec_config`] bound codes into. A node relays a chunk before naming only when
//! the chunk is at the node's index, comes from the leader the elector names for the chunk's
//! round, claims a round at most H views past the highest round consensus has signaled or among
//! the first H views of the next epoch, and verifies against the root it claims. A chunk from that
//! leader that fails verification blocks it, since no honest sender sends one.
//!
//! Each round relays at most 2S chunks this way in total, two blocks' worth for a prepared build
//! and the proposal that replaces it. At most 2H + 2 rounds are open to such relays at a time, so
//! a node relays at most 2S(2H + 2) chunks ahead of consensus.
//!
//! A relayed chunk counts toward nothing until consensus names its commitment and the roots bind,
//! and until then each peer holds it only in its ring. Once the chunk verifies against the bound
//! roots, the node relays it again if it has since sent at least 2(S + 1) later messages. That is
//! the most an honest sender sends a peer for one round, so a ring sized as
//! [`Config::peer_buffer_size`] asks still holds the earlier relay while fewer have been sent. A
//! peer that bound the roots before this node did therefore holds the earlier relay in its record.
//!
//! An elector configured differently from the consensus engine's, or a leader that streams a
//! block consensus never names, therefore costs at most those relays and blocks no honest sender.
//! Without an elector, with a [`Dynamic`](crate::simplex::elector::Dynamic) one, or before
//! consensus signals any round, nothing is relayed before naming.
//!
//! # Peer Validation and Blocking Rules
//!
//! The engine enforces strict validation to prevent Byzantine attacks:
//!
//! - A chunk counts only toward named commitments of the epoch its round claims, and MUST be sent
//!   by a participant of that epoch.
//! - Any participant may deliver a participant's assigned chunk. Only the leader may deliver a
//!   non-participant's assigned chunk.
//! - Any participant may relay its own chunks.
//! - Every chunk MUST verify against its root in roots that hash to the commitment.
//! - Chunk data MUST NOT be wider than the coding scheme produces, under the chunk's coding
//!   config, for a segment of a block at the [`BoundedBlock::max_encode_size`] bound of
//!   [`Config::block_codec_config`].
//! - Roots for a named commitment MUST hash to its coding root.
//! - A chunk relayed before naming MUST verify against the root it claims.
//! - Each shard index contributes at most ONE shard per commitment. A sender's shard is assembled
//!   from the first chunk of each segment the record ingests from it, so a later chunk for the same
//!   segment is ignored.
//!
//! Peers found violating these rules are blocked via the [`Blocker`] trait. The width rule is
//! enforced on receipt of every message, and a chunk relayed before naming is checked on arrival.
//! The other rules apply only once a named commitment's bound roots cover a chunk. Until the
//! leader is known, a chunk at an index other than its sender's stays in the ring, since it may
//! be this node's assigned chunk. Once the leader is known, any other index blocks its sender.
//!
//! Once a block is cached, its record keeps the assigned chunks collected so far but no other
//! chunks or shards, and only completes verification of a late assigned shard.
//!
//! # Record Window
//!
//! The engine retains at most [`Config::records`] commitment records. Once the window is full,
//! records with the lowest rounds are evicted first, and a signal at or below the lowest retained
//! round creates no record and leaves the commitment's chunks in the rings. Eviction closes no
//! subscription.
//!
//! # Ring Sizing
//!
//! For each candidate of a round, an honest sender sends a peer at most S + 1 messages, where S is
//! the number of segments in a block. They are its chunk of every segment and one roots message,
//! whether it leads the round or relays. [`Config::peer_buffer_size`] sizes rings from that bound,
//! including the 2(S + 1) more messages a ring needs with a scheduled elector in
//! [`Config::elector`]. A ring must hold a chunk only until its commitment binds, since the record
//! keeps what it ingests. Chunks evicted before their commitment binds are lost to the stream, and
//! the node fetches that block from a peer that reconstructed it.

use super::{
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
    simplex::elector::{Config as ElectorConfig, Elector, Mode},
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

/// An error that can occur during reconstruction of a [`CodedBlock`] from shards
#[derive(Debug, Error)]
pub enum Error<C: CodingScheme> {
    /// An error occurred while recovering the encoded blob from the shards
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

/// The outcome of a reconstruction job.
enum Outcome<B, C: CodingScheme> {
    /// Fewer than the minimum shards passed verification. Holds every checked shard.
    Insufficient(Vec<SizedShard<C>>),
    /// Enough shards passed verification to decode the block.
    Decoded(Result<B, Error<C>>),
}

/// A finished reconstruction job.
struct Reconstructed<P, B, C: Segmentable, H> {
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
    mut checked: Vec<SizedShard<C>>,
    pending: Vec<(P, IndexedShard<C>)>,
    cfg: &B::Cfg,
    strategy: &impl Strategy,
) -> Reconstructed<P, B, C, H>
where
    P: PublicKey,
    B: CertifiableBlock + CodedLayout,
    C: Segmentable,
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
        for ((peer, indexed), result) in zip_eq(pending, results) {
            match result {
                Ok(shard) => checked.push(SizedShard {
                    shard,
                    size: indexed.data.encode_size(),
                }),
                Err(_) => invalid.push(peer),
            }
        }
    }
    let outcome = if checked.len() < usize::from(config.minimum_shards.get()) {
        Outcome::Insufficient(checked)
    } else {
        Outcome::Decoded(decode(commitment, &checked, cfg, strategy))
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
    checked: &[SizedShard<C>],
    cfg: &B::Cfg,
    strategy: &impl Strategy,
) -> Result<B, Error<C>>
where
    B: CertifiableBlock + CodedLayout,
    C: Segmentable,
    H: Hasher,
{
    let blob = C::decode(
        &commitment.config(),
        &commitment.root(),
        checked.iter().map(|sized| &sized.shard),
        strategy,
    )
    .map_err(Error::Coding)?;

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
pub struct Config<P, S, X, D, B, T, L>
where
    P: PublicKey,
    S: Provider<Scope = Epoch>,
    X: Blocker<PublicKey = P>,
    D: PeerProvider<PublicKey = P>,
    B: CertifiableBlock + CodedLayout,
    T: Strategy,
    L: ElectorConfig<S::Scheme>,
{
    /// The scheme provider.
    ///
    /// A scheme registered for an epoch in which this node is a committee member must report
    /// the node's membership ([`CertificateScheme::me`]) even when it cannot sign. The leader
    /// sends each committee member the chunks at its index, and the engine needs that index to
    /// accept them, relay them once checked, and broadcast the node's own proposals.
    pub scheme_provider: S,

    /// The peer blocker.
    pub blocker: X,

    /// [`commonware_codec::Read`] configuration for decoding blocks. Every node must use the same
    /// value.
    ///
    /// A peer is blocked for sending a chunk whose data is wider than the coding scheme produces,
    /// under the config the chunk claims, for a segment of a block at the
    /// [`BoundedBlock::max_encode_size`] bound of this configuration (plus its coding trailer).
    /// The claimed config is untrusted until roots bound to a named commitment cover the chunk, so
    /// chunk data may reach the scheme's widest for such a block.
    pub block_codec_config: B::Cfg,

    /// The strategy that checks and decodes received shards, encodes shards for broadcast, and
    /// runs reconstruction jobs.
    pub strategy: T,

    /// The size of the mailbox buffer.
    pub mailbox_size: NonZeroUsize,

    /// Number of chunk and roots messages to buffer per peer.
    ///
    /// Every message joins its sender's ring. The ring keeps the sender's last `peer_buffer_size`
    /// messages to bound memory under Byzantine spam. Chunk messages carry data up to the scheme's
    /// widest chunk for the block bound of `block_codec_config`, and roots messages carry the
    /// bounded list of segment roots. Chunks wait there until consensus names their commitment and
    /// its roots bind, and the commitment's record keeps the chunks it ingests from then on.
    ///
    /// For each candidate of a round, an honest sender sends a peer at most S + 1 messages, where S
    /// is the number of segments in a block at the bound of `block_codec_config`. Size the ring for
    /// S + 1 messages times the number of rounds a node can trail its peers by, and double it if a
    /// leader can replace a candidate within a round. With a scheduled elector in
    /// [`Config::elector`], add 2(S + 1) messages, since a peer must still hold a chunk relayed
    /// before naming when its commitment is named.
    ///
    /// A ring too small for a distant or slow node evicts chunks before they are needed, and the
    /// node then fetches those blocks from peers that reconstructed them.
    pub peer_buffer_size: NonZeroUsize,

    /// The maximum number of commitment records retained.
    ///
    /// Records with the lowest rounds are evicted first. Once the window is full, a consensus
    /// signal at or below the lowest retained round creates no record. Must be at least
    /// `2 * (max(1, optimistic_views) + 2)`, where `optimistic_views` is
    /// [`crate::simplex::elector::Terms::optimistic_views`].
    ///
    /// It is also how many views past the highest round consensus has signaled a chunk may claim
    /// to be relayed before its commitment is named (see [`Config::elector`]).
    pub records: NonZeroUsize,

    /// Provider for peer set information. Messages are buffered per peer only while that peer is a
    /// primary of some tracked peer set ([`commonware_p2p::PeerSetUpdate::all`]), matching
    /// [`commonware_broadcast::buffered::Engine`]. Broadcast delivery uses the whole
    /// [`commonware_p2p::PeerSetUpdate::all`] union.
    pub peer_provider: D,

    /// The consensus engine's elector configuration, or `None` to relay nothing before naming.
    ///
    /// A [`Scheduled`](crate::simplex::elector::Scheduled) elector names a round's leader before
    /// consensus names the round's commitment. A [`Dynamic`](crate::simplex::elector::Dynamic)
    /// one names none that early, so nothing is relayed before naming.
    ///
    /// The leader gates only the relay of chunks at this node's index before the commitment is
    /// named, and a chunk chosen for that relay must verify or its sender is blocked. Admission and
    /// classification after naming use the leader consensus names, so a configuration that differs
    /// from the consensus engine's costs at most those relays. A scheduled elector requires room
    /// for more messages in each ring ([`Config::peer_buffer_size`]).
    pub elector: Option<L>,
}

/// The number of candidates one round may carry: a prepared build and the proposal that replaces
/// it. A round relays at most this many blocks' worth of chunks before naming, and an honest
/// sender sends a peer at most this many candidates' chunks and roots for one round.
const RELAY_CANDIDATES: usize = 2;

/// Returns whether `round` is `anchor` or at most `horizon` views after it in the same epoch, or
/// among the first `horizon` views of the next epoch.
fn within_horizon(anchor: Round, round: Round, horizon: u64) -> bool {
    if round.epoch() == anchor.epoch() {
        round.view() >= anchor.view()
            && round.view().get() <= anchor.view().get().saturating_add(horizon)
    } else {
        round.epoch().get() == anchor.epoch().get().saturating_add(1)
            && round.view().get() <= horizon
    }
}

/// The data currently owned for a consensus commitment.
enum CommitmentPhase<B, C, H, P>
where
    B: Block,
    C: Segmentable,
    H: Hasher,
    P: PublicKey,
{
    /// Shards are still being accumulated or validated.
    Reconstructing(ReconstructionState<P, C>),
    /// The block is cached. Retained reconstruction state keeps the assigned chunks collected so
    /// far but no other chunks or shards, and only tracks verification of a late assigned shard.
    Cached {
        block: Arc<CodedBlock<B, C, H>>,
        reconstruction: Option<ReconstructionState<P, C>>,
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
    C: Segmentable,
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
    C: Segmentable,
    H: Hasher,
    P: PublicKey,
{
    /// Creates a record that is reconstructing a commitment observed at `round`.
    const fn reconstructing(round: Round, reconstruction: ReconstructionState<P, C>) -> Self {
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
    const fn reconstruction(&self) -> Option<&ReconstructionState<P, C>> {
        match &self.phase {
            CommitmentPhase::Reconstructing(reconstruction) => Some(reconstruction),
            CommitmentPhase::Cached { reconstruction, .. } => reconstruction.as_ref(),
        }
    }

    /// Returns mutable shard reconstruction state retained for the commitment, if any.
    const fn reconstruction_mut(&mut self) -> Option<&mut ReconstructionState<P, C>> {
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

/// A network layer for broadcasting and receiving [`CodedBlock`]s as segment chunks.
///
/// Once a named commitment's roots bind and enough shards are in, the [`Engine`] reconstructs the
/// [`CodedBlock`] and notifies the subscribers waiting for it. A block that does not match its
/// commitment is discarded.
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
/// block the node proposes, relays each chunk of the node's own shard once it checks against
/// bound roots, and relays the roots of each commitment it binds.
///
/// A relayed message arrived on the engine's receiver, so the receiver must yield no payload
/// larger than the sender's network admits. The channels of one p2p network and the paired
/// subchannels of a [`Muxer`](commonware_p2p::utils::mux::Muxer) meet this.
pub struct Engine<E, S, X, D, C, H, B, P, T, L>
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
    L: ElectorConfig<S::Scheme>,
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

    /// The strategy that checks and decodes received shards, encodes shards for broadcast, and
    /// runs reconstruction jobs.
    strategy: T,

    /// The cache and reconstruction lifecycle for each observed [`Commitment`].
    records: CommitmentRecords<B, C, H, P>,

    /// Each primary peer's ring of the chunk and roots messages it sent most recently.
    ///
    /// Empty buffers are retained for active peers and only evicted when the
    /// peer is no longer a primary of any tracked peer set.
    peer_buffers: BTreeMap<P, VecDeque<ShardMessage<B, C, H>>>,

    /// Maximum messages kept in each peer's ring.
    peer_buffer_size: NonZeroUsize,

    /// Maximum number of commitment records retained.
    window: NonZeroUsize,

    /// Provider for peer set information.
    peer_provider: D,

    /// Latest union of peer membership from the peer set subscription
    /// ([`commonware_p2p::PeerSetUpdate::all`]).
    aggregate_peers: Set<P>,

    /// Primary peers of every tracked peer set, allowed to keep a ring.
    primary_peers: Set<P>,

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

    /// The roots of the segments this node streamed for the block it is building, keyed by
    /// round, in segment order.
    streamed: BTreeMap<Round, Vec<C::Commitment>>,

    /// The elector configuration from [`Config::elector`].
    elector: Option<L>,

    /// The elector built for each epoch open to relays before naming. They are the epoch of the
    /// highest round consensus has signaled and the next.
    electors: BTreeMap<Epoch, L::Elector>,

    /// The most segments a block at the bound of the block codec config codes into.
    max_segments: u16,

    /// The highest round consensus has signaled. A chunk relayed before naming must claim a round
    /// [`within_horizon`] of it.
    signaled: Option<Round>,

    /// An upper bound on the number of messages this node has sent any one peer.
    ///
    /// Each broadcast and each streamed segment counts once, since a peer receives at most one
    /// chunk of a segment. Over-counting only repeats a relay peers still hold, while
    /// under-counting could skip one they dropped, so every send must count.
    sent: u64,

    /// The most messages an honest sender sends a peer for one round, [`RELAY_CANDIDATES`]
    /// candidates' chunks and roots.
    span: u64,

    /// The segment, root, and value of [`Self::sent`] of each chunk at this node's index relayed
    /// before its commitment was named, keyed by the round the chunk claims.
    relayed: BTreeMap<Round, Vec<(u16, C::Commitment, u64)>>,
}

impl<E, S, X, D, C, H, B, P, T, L> Engine<E, S, X, D, C, H, B, P, T, L>
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
    L: ElectorConfig<S::Scheme>,
{
    /// Create a new [`Engine`] with the given configuration.
    pub fn new(context: E, config: Config<P, S, X, D, B, T, L>) -> (Self, Mailbox<B, C, H, P>) {
        let metrics = ShardMetrics::new(&context);
        let (sender, mailbox) = mailbox::new(context.child("mailbox"), config.mailbox_size);
        let max_segments = C::segments(CodedBlock::<B, C, H>::max_coded_size(B::max_encode_size(
            &config.block_codec_config,
        )));
        let span = Widen::widen(RELAY_CANDIDATES * (usize::from(max_segments) + 1));
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
                streamed: BTreeMap::new(),
                elector: config.elector,
                electors: BTreeMap::new(),
                max_segments,
                signaled: None,
                sent: 0,
                span,
                relayed: BTreeMap::new(),
            },
            Mailbox::new(sender),
        )
    }

    /// Start the engine.
    ///
    /// Decoded shards wait for the engine in a mailbox sized to the network receiver's
    /// [`commonware_p2p::Receiver::capacity`]. Each carries data up to the scheme's widest for the
    /// block bound of [`Config::block_codec_config`].
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

    /// Handles a chunk or roots message received from the network.
    ///
    /// The message joins its sender's ring first. A chunk is then relayed if it qualifies for
    /// relay before naming, and ingested by every named commitment whose bound roots cover it.
    /// Roots bind the commitment they claim if consensus has named it.
    fn handle_network_message<Sr: Sender<PublicKey = P>>(
        &mut self,
        sender: &mut WrappedSender<Sr, ShardMessage<B, C, H>>,
        peer: P,
        message: ShardMessage<B, C, H>,
    ) {
        self.buffer_peer_shard(peer.clone(), message.clone());
        match message {
            ShardMessage::Stream(chunk) => {
                self.metrics.shards_received.get_or_create_by(&peer).inc();
                self.relay_early(sender, &peer, &chunk);
                for commitment in self.commitments_covering(chunk.segment, &chunk.root) {
                    self.ingest_chunk(sender, commitment, &peer, &chunk);
                }
            }
            ShardMessage::Roots(roots) => {
                if self.bind_roots(sender, roots.commitment, &peer, roots.roots) {
                    self.ingest_buffered_chunks(sender, roots.commitment);
                }
            }
        }
    }

    /// Relays a chunk at this node's index that the round's leader sends before consensus names
    /// its commitment, so peers collect each segment while the leader still streams later ones.
    ///
    /// The chunk must claim a round [`within_horizon`] of the highest round consensus has signaled,
    /// with [`Config::records`] as the horizon. It must also come from the leader the elector names
    /// for that round and verify against the root it claims, and a chunk from that leader that
    /// fails verification blocks it. A round relays at most [`RELAY_CANDIDATES`] blocks' worth of
    /// chunks this way. The ledger entry lets the relay after naming skip the chunk while peers
    /// still hold this relay.
    fn relay_early<Sr: Sender<PublicKey = P>>(
        &mut self,
        sender: &mut WrappedSender<Sr, ShardMessage<B, C, H>>,
        peer: &P,
        chunk: &StreamChunk<C>,
    ) {
        let round = chunk.round;
        let horizon: u64 = Widen::widen(self.window.get());
        if !self
            .signaled
            .is_some_and(|anchor| within_horizon(anchor, round, horizon))
        {
            return;
        }
        let Some(scheme) = self.scheme_provider.scheme(round.epoch()) else {
            return;
        };
        let Some(local) = scheme.me().map(|m| {
            u16::try_from(m.index().get()).expect("participant index impossibly out of bounds")
        }) else {
            return;
        };
        let participants =
            u16::try_from(scheme.participants().len()).expect("too many participants");
        if chunk.index != local
            || chunk.segment >= self.max_segments
            || chunk.config != coding_config_for_participants(participants)
        {
            return;
        }
        if self.relayed.get(&round).is_some_and(|relayed| {
            relayed.len() >= RELAY_CANDIDATES * usize::from(self.max_segments)
                || relayed
                    .iter()
                    .any(|&(segment, root, _)| segment == chunk.segment && root == chunk.root)
        }) {
            return;
        }
        let Some(config) = &self.elector else {
            return;
        };
        let Some(input) = <<L::Elector as Elector<S::Scheme>>::Mode as Mode>::early() else {
            return;
        };
        let elector = self
            .electors
            .entry(round.epoch())
            .or_insert_with(|| config.clone().build(scheme.participants()));
        if scheme.participants().key(elector.elect(round, input)) != Some(peer) {
            return;
        }
        if C::check_chunk(
            &chunk.config,
            &chunk.root,
            chunk.index,
            chunk.segment,
            &chunk.chunk,
        )
        .is_err()
        {
            commonware_p2p::block!(self.blocker, peer.clone(), "invalid stream chunk received");
            return;
        }
        self.sent += 1;
        self.relayed
            .entry(round)
            .or_default()
            .push((chunk.segment, chunk.root, self.sent));
        let _ = sender.send(Recipients::All, chunk.clone().into(), true);
        self.metrics.chunks_forwarded.inc();
    }

    /// Records that consensus signaled `round`, and drops the electors of earlier epochs.
    fn signal(&mut self, round: Round) {
        if self.signaled.is_none_or(|anchor| anchor < round) {
            self.signaled = Some(round);
            self.electors.retain(|epoch, _| *epoch >= round.epoch());
        }
    }

    /// Returns the named commitments whose bound roots have `root` at `segment`.
    fn commitments_covering(&self, segment: u16, root: &C::Commitment) -> Vec<Commitment<B, C, H>> {
        self.records
            .iter()
            .filter(|(_, record)| {
                record
                    .reconstruction()
                    .and_then(ReconstructionState::roots)
                    .is_some_and(|roots| roots.get(usize::from(segment)) == Some(root))
            })
            .map(|(commitment, _)| *commitment)
            .collect()
    }

    /// Binds `roots`, received from `peer`, to the named `commitment` and returns whether they
    /// were bound.
    ///
    /// Roots bind once. A participant relays them when they do, so a node the leader did not reach
    /// can still check the chunks participants relay to it. Roots that do not hash to the coding
    /// root of the commitment they claim block their sender. Roots for a commitment that is already
    /// bound, or whose record holds no reconstruction state, are ignored unchecked.
    fn bind_roots<Sr: Sender<PublicKey = P>>(
        &mut self,
        sender: &mut WrappedSender<Sr, ShardMessage<B, C, H>>,
        commitment: Commitment<B, C, H>,
        peer: &P,
        roots: Vec<C::Commitment>,
    ) -> bool {
        let Some(record) = self.records.get_mut(&commitment) else {
            return false;
        };
        let round = record.round();
        let Some(state) = record.reconstruction_mut() else {
            return false;
        };
        if state.roots().is_some() {
            return false;
        }
        if C::commit(&roots) != commitment.root() {
            commonware_p2p::block!(
                self.blocker,
                peer.clone(),
                "stream roots do not match commitment"
            );
            return false;
        }
        state.bind_roots(roots.clone());
        if self
            .scheme_provider
            .scheme(round.epoch())
            .is_some_and(|scheme| scheme.me().is_some())
        {
            let message = StreamRoots {
                commitment,
                round,
                roots,
            };
            self.sent += 1;
            let _ = sender.send(Recipients::All, message.into(), true);
        }
        true
    }

    /// Binds the named `commitment` to roots any peer sent for it, unless it is already bound or
    /// its record holds no reconstruction state.
    fn bind_buffered_roots<Sr: Sender<PublicKey = P>>(
        &mut self,
        sender: &mut WrappedSender<Sr, ShardMessage<B, C, H>>,
        commitment: Commitment<B, C, H>,
    ) {
        if self
            .records
            .get(&commitment)
            .and_then(CommitmentRecord::reconstruction)
            .is_none_or(|state| state.roots().is_some())
        {
            return;
        }
        let buffered: Vec<(P, Vec<C::Commitment>)> = self
            .peer_buffers
            .iter()
            .flat_map(|(peer, queue)| {
                queue.iter().filter_map(move |message| match message {
                    ShardMessage::Roots(roots) if roots.commitment == commitment => {
                        Some((peer.clone(), roots.roots.clone()))
                    }
                    _ => None,
                })
            })
            .collect();
        for (peer, roots) in buffered {
            if self.bind_roots(sender, commitment, &peer, roots) {
                return;
            }
        }
    }

    /// Ingests every buffered chunk that the bound roots of `commitment` cover.
    ///
    /// The chunks stay in their senders' rings, so another commitment whose roots share a
    /// segment root can still use them.
    fn ingest_buffered_chunks<Sr: Sender<PublicKey = P>>(
        &mut self,
        sender: &mut WrappedSender<Sr, ShardMessage<B, C, H>>,
        commitment: Commitment<B, C, H>,
    ) {
        let Some(roots) = self
            .records
            .get(&commitment)
            .and_then(CommitmentRecord::reconstruction)
            .and_then(ReconstructionState::roots)
            .map(<[_]>::to_vec)
        else {
            return;
        };
        let buffered: Vec<(P, StreamChunk<C>)> = self
            .peer_buffers
            .iter()
            .flat_map(|(peer, queue)| {
                let roots = &roots;
                queue.iter().filter_map(move |message| match message {
                    ShardMessage::Stream(chunk)
                        if roots.get(usize::from(chunk.segment)) == Some(&chunk.root) =>
                    {
                        Some((peer.clone(), chunk.clone()))
                    }
                    _ => None,
                })
            })
            .collect();
        for (peer, chunk) in buffered {
            self.ingest_chunk(sender, commitment, &peer, &chunk);
        }
    }

    /// Ingests a chunk that the bound roots of `commitment` cover.
    ///
    /// A chunk whose round claims another epoch than the record's is ignored. Otherwise the sender
    /// must be a participant of that epoch. A chunk at this node's assigned index is checked and
    /// collected into the assigned shard, and a chunk at its sender's own index contributes the
    /// sender's shard. Until the leader is known, a chunk at an index other than its sender's
    /// stays in the ring, and once the leader is known such a chunk blocks its sender.
    fn ingest_chunk<Sr: Sender<PublicKey = P>>(
        &mut self,
        sender: &mut WrappedSender<Sr, ShardMessage<B, C, H>>,
        commitment: Commitment<B, C, H>,
        peer: &P,
        chunk: &StreamChunk<C>,
    ) {
        let Some(record) = self.records.get(&commitment) else {
            return;
        };
        let epoch = record.round().epoch();
        if chunk.round.epoch() != epoch {
            return;
        }
        let Some(state) = record.reconstruction() else {
            return;
        };
        let Some(scheme) = self.scheme_provider.scheme(epoch) else {
            return;
        };
        let participants = scheme.participants();
        let Some(sender_index) = participants.index(peer) else {
            commonware_p2p::block!(self.blocker, peer.clone(), "chunk sent by non-participant");
            return;
        };
        let sender_index: u16 = sender_index
            .get()
            .try_into()
            .expect("participant index impossibly out of bounds");
        let local_index: Option<u16> = scheme.me().map(|m| {
            m.index()
                .get()
                .try_into()
                .expect("participant index impossibly out of bounds")
        });
        let leader = state.leader().cloned();
        let is_own = chunk.index == sender_index;
        let is_assigned = local_index.is_some_and(|local_index| chunk.index == local_index)
            || local_index.is_none() && leader.as_ref() == Some(peer) && is_own;
        if leader.is_none() && !is_own {
            return;
        }
        if is_assigned {
            self.ingest_assigned_chunk(sender, commitment, peer, chunk, local_index.is_some());
        } else if is_own {
            self.ingest_sender_shard(commitment, peer, chunk);
        } else {
            commonware_p2p::block!(
                self.blocker,
                peer.clone(),
                shard_index = chunk.index,
                "chunk index is neither assigned nor sender-owned"
            );
        }
    }

    /// Checks a chunk of this node's assigned shard against its segment root and, if this node
    /// is a participant, relays it to all peers.
    ///
    /// Once every segment's chunk is in, the assembled shard completes the assigned-shard check.
    fn ingest_assigned_chunk<Sr: Sender<PublicKey = P>>(
        &mut self,
        sender: &mut WrappedSender<Sr, ShardMessage<B, C, H>>,
        commitment: Commitment<B, C, H>,
        peer: &P,
        chunk: &StreamChunk<C>,
        is_participant: bool,
    ) {
        let state = self
            .records
            .get_mut(&commitment)
            .and_then(CommitmentRecord::reconstruction_mut)
            .expect("an ingested chunk's record must hold reconstruction state");
        let segment = usize::from(chunk.segment);
        if state.has_contributed(chunk.index) || state.has_assigned_chunk(segment) {
            return;
        }
        let root = state
            .roots()
            .expect("an ingested chunk must be under bound roots")[segment];
        if C::check_chunk(
            &commitment.config(),
            &root,
            chunk.index,
            chunk.segment,
            &chunk.chunk,
        )
        .is_err()
        {
            commonware_p2p::block!(
                self.blocker,
                peer.clone(),
                "invalid assigned chunk received"
            );
            return;
        }

        // A relay before naming stands in for this one while fewer than a round's worth of later
        // messages could have pushed it out of the peers' rings.
        let relayed_early = self.relayed.get(&chunk.round).is_some_and(|relayed| {
            relayed.iter().any(|&(segment, root, sent)| {
                segment == chunk.segment && root == chunk.root && self.sent - sent < self.span
            })
        });
        if is_participant && !relayed_early {
            self.sent += 1;
            let _ = sender.send(Recipients::All, chunk.clone().into(), true);
            self.metrics.chunks_forwarded.inc();
        }

        let Some(shard) = state.add_assigned_chunk(segment, chunk.chunk.clone()) else {
            return;
        };
        let indexed = IndexedShard {
            index: chunk.index,
            data: shard,
        };
        if state.verify_assigned_shard(
            peer.clone(),
            commitment,
            indexed,
            &mut self.blocker,
            &self.strategy,
        ) {
            self.try_advance(commitment);
        }
    }

    /// Keeps the chunk `peer` sent of its own shard in the record of `commitment`, and adds the
    /// assembled shard to the shards awaiting a batch check once the record holds the peer's chunk
    /// of every segment.
    ///
    /// The record keeps the first chunk of each segment it ingests from a sender, so a later chunk
    /// for the same segment is ignored, and each index contributes one shard. A cached block needs
    /// no sender shards.
    fn ingest_sender_shard(
        &mut self,
        commitment: Commitment<B, C, H>,
        peer: &P,
        chunk: &StreamChunk<C>,
    ) {
        let Some(ReconstructionState::AwaitingQuorum(state)) = self
            .records
            .get_mut(&commitment)
            .and_then(CommitmentRecord::reconstruction_mut)
        else {
            return;
        };
        if state.common.contributed.get(u64::from(chunk.index)) {
            return;
        }
        let roots = state
            .common
            .roots
            .as_deref()
            .expect("an ingested chunk must be under bound roots");
        let slots = state
            .sender_chunks
            .entry(peer.clone())
            .or_insert_with(|| vec![None; roots.len()]);
        let slot = &mut slots[usize::from(chunk.segment)];
        if slot.is_some() {
            return;
        }
        *slot = Some(chunk.chunk.clone());
        if slots.iter().any(Option::is_none) {
            return;
        }
        let chunks = state
            .sender_chunks
            .remove(peer)
            .expect("the sender's chunks must be in")
            .into_iter()
            .map(|chunk| chunk.expect("every chunk must be in"))
            .collect();
        let data = C::assemble(roots.to_vec(), chunks);
        state.common.contributed.set(u64::from(chunk.index), true);
        state.pending_shards.insert(
            peer.clone(),
            IndexedShard {
                index: chunk.index,
                data,
            },
        );
        self.try_reconstruct(commitment);
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

        // The spawn hint is the encoded size of the shards the job takes.
        let len = checked
            .iter()
            .map(|sized| sized.size)
            .chain(pending.iter().map(|(_, shard)| shard.data.encode_size()))
            .sum();
        let cfg = self.block_codec_config.clone();
        let start = self.context.current();
        let job = self.strategy.spawn(len, move |strategy| {
            reconstruct(commitment, start, checked, pending, &cfg, &strategy)
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
        sender: &mut WrappedSender<Sr, ShardMessage<B, C, H>>,
        commitment: Commitment<B, C, H>,
        leader: P,
        round: Round,
    ) {
        self.signal(round);
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
            // Chunks for a commitment the window declines stay in the rings.
            if !self.admits(round) {
                debug!(
                    %commitment,
                    %round,
                    "discovered commitment at or below the lowest retained round"
                );
                return;
            }
            let participants_len: u64 = Widen::widen(participants.len());
            self.insert_reconstruction_record(
                commitment,
                round,
                ReconstructionState::new(Some(leader), participants_len),
            );
        }
        self.bind_buffered_roots(sender, commitment);
        self.ingest_buffered_chunks(sender, commitment);
    }

    /// Handles notarized reconstruction interest before the leader is known.
    ///
    /// This is intentionally narrower than leader discovery: it may reconstruct
    /// the block from sender-indexed gossip shards, but it cannot mark the
    /// local assigned shard as verified.
    fn handle_notarized_commitment<Sr: Sender<PublicKey = P>>(
        &mut self,
        sender: &mut WrappedSender<Sr, ShardMessage<B, C, H>>,
        commitment: Commitment<B, C, H>,
        round: Round,
    ) {
        self.signal(round);
        let Some(status) = self.observe_existing_commitment(commitment, round) else {
            return;
        };
        if status == CommitmentStatus::Cached {
            return;
        }
        if status == CommitmentStatus::Reconstructing {
            self.bind_buffered_roots(sender, commitment);
            self.ingest_buffered_chunks(sender, commitment);
            return;
        }
        let Some(scheme) = self.scheme_provider.scheme(round.epoch()) else {
            warn!(%commitment, "no scheme for epoch, ignoring notarized commitment");
            return;
        };

        // Chunks for a commitment the window declines stay in the rings.
        if !self.admits(round) {
            debug!(
                %commitment,
                %round,
                "notarized commitment at or below the lowest retained round"
            );
            return;
        }
        let participants_len: u64 = Widen::widen(scheme.participants().len());
        self.insert_reconstruction_record(
            commitment,
            round,
            ReconstructionState::new(None, participants_len),
        );
        self.bind_buffered_roots(sender, commitment);
        self.ingest_buffered_chunks(sender, commitment);
    }

    /// Buffers a message in its sender's ring, evicting the oldest message once the ring holds
    /// [`Config::peer_buffer_size`] messages. A sender that is not a primary peer gets no ring.
    fn buffer_peer_shard(&mut self, peer: P, message: ShardMessage<B, C, H>) {
        if self.primary_peers.position(&peer).is_none() {
            debug!(
                ?peer,
                "message from peer outside tracked primary sets not buffered"
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
        reconstruction: ReconstructionState<P, C>,
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
        if self.records.len() >= self.window.get()
            && let Some(lowest) = self.records.values().map(CommitmentRecord::round).min()
        {
            self.streamed = self.streamed.split_off(&lowest);
        }
        while self.streamed.len() > self.window.get() {
            self.streamed.pop_first();
        }

        // A round at or above the anchor keeps its allowance of relays before naming. A round
        // below it is kept only while its newest relay may still stand in for the relay after
        // naming.
        let (anchor, sent, span) = (self.signaled, self.sent, self.span);
        self.relayed.retain(|round, relayed| {
            anchor.is_none_or(|anchor| *round >= anchor)
                || relayed.last().is_some_and(|&(_, _, at)| sent - at < span)
        });
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
    /// the round needs only its roots, since every recipient already has its chunks.
    fn broadcast_shards<Sr: Sender<PublicKey = P>>(
        &mut self,
        sender: &mut WrappedSender<Sr, ShardMessage<B, C, H>>,
        round: Round,
        block: Arc<CodedBlock<B, C, H>>,
    ) {
        self.signal(round);
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
                            .expect("every shard must hold a chunk per segment")
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
        self.sent += 1;
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
    }

    /// Sends every other participant its chunk of `segment`, and sends the chunk at this node's
    /// index to every peer in aggregate membership that is not a participant.
    fn send_segment<Sr: Sender<PublicKey = P>>(
        &mut self,
        sender: &mut WrappedSender<Sr, ShardMessage<B, C, H>>,
        round: Round,
        participants: &Set<P>,
        my_index: usize,
        segment: StreamedSegment<C>,
    ) {
        self.sent += 1;
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

    /// Notifies readiness once the assigned shard is verified, and starts reconstruction when
    /// enough shards are available.
    fn try_advance(&mut self, commitment: Commitment<B, C, H>) {
        if let Some(state) = self
            .records
            .get_mut(&commitment)
            .and_then(CommitmentRecord::reconstruction_mut)
            && state.take_notify()
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
enum ReconstructionState<P, C>
where
    P: PublicKey,
    C: Segmentable,
{
    /// Stage 1: accumulate shards. The shard for our assigned index is verified
    /// immediately. Other shards are buffered, and reconstruction jobs verify those
    /// that decoding needs.
    AwaitingQuorum(AwaitingQuorumState<P, C>),
    /// Stage 2: the block is cached. Only the assigned shard is still accepted.
    Ready(ReadyState<P, C>),
}

/// A coding shard paired with its participant index.
struct IndexedShard<C: CodingScheme> {
    index: u16,
    data: C::Shard,
}

/// A checked coding shard paired with the encoded size of the shard it was checked from.
struct SizedShard<C: CodingScheme> {
    shard: C::CheckedShard,
    size: usize,
}

/// State shared across all reconstruction phases.
struct CommonState<P, C>
where
    P: PublicKey,
    C: Segmentable,
{
    /// The leader associated with this reconstruction state, if consensus has
    /// provided it.
    leader: Option<P>,
    /// Whether the assigned shard's verification awaits notification of local subscribers.
    notify: bool,
    /// The segment roots, once roots that hash to the commitment's coding root are known.
    roots: Option<Vec<C::Commitment>>,
    /// The checked chunks of the assigned shard, one slot per segment, until all are in.
    assigned_chunks: Vec<Option<C::Chunk>>,
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
struct AwaitingQuorumState<P, C>
where
    P: PublicKey,
    C: Segmentable,
{
    common: CommonState<P, C>,
    /// The chunks of each sender's own shard ingested under the bound roots, one slot per segment,
    /// until every segment's chunk is in and the shard is assembled.
    sender_chunks: BTreeMap<P, Vec<Option<C::Chunk>>>,
    /// Shards that have been verified and are ready to contribute to reconstruction.
    checked_shards: Vec<SizedShard<C>>,
    /// Shards pending batch validation, keyed by sender.
    pending_shards: BTreeMap<P, IndexedShard<C>>,
    /// The in-flight reconstruction job. Dropping it discards the job's result.
    job: Option<Aborter>,
}

/// Phase data for `ReconstructionState::Ready`.
///
/// The block is cached, so the senders' chunks and the checked and pending shards are dropped. Only
/// the assigned shard's chunks are still collected and verified.
struct ReadyState<P, C>
where
    P: PublicKey,
    C: Segmentable,
{
    common: CommonState<P, C>,
}

impl<P, C> CommonState<P, C>
where
    P: PublicKey,
    C: Segmentable,
{
    /// Create a new empty common state for the provided leader.
    fn new(leader: Option<P>, participants_len: u64) -> Self {
        Self {
            leader,
            notify: false,
            roots: None,
            assigned_chunks: Vec::new(),
            contributed: BitMap::zeroes(participants_len),
            assigned_shard_verified: false,
        }
    }
}

impl<P, C> ReconstructionState<P, C>
where
    P: PublicKey,
    C: Segmentable,
{
    /// Create an initial reconstruction state for a commitment.
    fn new(leader: Option<P>, participants_len: u64) -> Self {
        Self::AwaitingQuorum(AwaitingQuorumState {
            common: CommonState::new(leader, participants_len),
            sender_chunks: BTreeMap::new(),
            checked_shards: Vec::new(),
            pending_shards: BTreeMap::new(),
            job: None,
        })
    }

    /// Ends shard accumulation once the block is cached, dropping the senders' chunks and the
    /// checked and pending shards, and discarding the result of any in-flight job.
    fn into_ready(self) -> Self {
        match self {
            Self::AwaitingQuorum(state) => Self::Ready(ReadyState {
                common: state.common,
            }),
            ready @ Self::Ready(_) => ready,
        }
    }

    /// Access common state shared across all phases.
    const fn common(&self) -> &CommonState<P, C> {
        match self {
            Self::AwaitingQuorum(state) => &state.common,
            Self::Ready(state) => &state.common,
        }
    }

    /// Mutably access common state shared across all phases.
    const fn common_mut(&mut self) -> &mut CommonState<P, C> {
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

    /// Returns whether the assigned shard's verification awaits notification, and clears it.
    const fn take_notify(&mut self) -> bool {
        std::mem::replace(&mut self.common_mut().notify, false)
    }

    /// Returns the bound segment roots.
    fn roots(&self) -> Option<&[C::Commitment]> {
        self.common().roots.as_deref()
    }

    /// Binds the segment roots. The caller has checked that they hash to the commitment's coding
    /// root.
    fn bind_roots(&mut self, roots: Vec<C::Commitment>) {
        let common = self.common_mut();
        common.assigned_chunks = vec![None; roots.len()];
        common.roots = Some(roots);
    }

    /// Returns whether the assigned shard's chunk of `segment` is in, or the shard has no slot
    /// for `segment`.
    fn has_assigned_chunk(&self, segment: usize) -> bool {
        self.common()
            .assigned_chunks
            .get(segment)
            .is_none_or(Option::is_some)
    }

    /// Records a checked chunk of the assigned shard and returns the whole shard once every
    /// segment's chunk is in.
    fn add_assigned_chunk(&mut self, segment: usize, chunk: C::Chunk) -> Option<C::Shard> {
        let common = self.common_mut();
        common.assigned_chunks[segment] = Some(chunk);
        if common.assigned_chunks.iter().any(Option::is_none) {
            return None;
        }
        let chunks = mem::take(&mut common.assigned_chunks)
            .into_iter()
            .map(|chunk| chunk.expect("every chunk must be in"))
            .collect();
        let roots = common.roots.clone().expect("the roots must be bound");
        Some(C::assemble(roots, chunks))
    }

    /// Returns whether a shard at `index` has contributed.
    fn has_contributed(&self, index: u16) -> bool {
        self.common().contributed.get(u64::from(index))
    }

    /// Verifies the assigned shard against the commitment and schedules notification of local
    /// subscribers. While awaiting quorum, the shard also contributes to reconstruction.
    ///
    /// Returns `false` if verification fails (the sender is blocked), `true` on success.
    fn verify_assigned_shard<B: Digestible, H: Hasher>(
        &mut self,
        sender: P,
        commitment: Commitment<B, C, H>,
        shard: IndexedShard<C>,
        blocker: &mut impl Blocker<PublicKey = P>,
        strategy: &impl Strategy,
    ) -> bool {
        let Ok(checked) = C::check(
            &commitment.config(),
            &commitment.root(),
            shard.index,
            &shard.data,
            strategy,
        ) else {
            commonware_p2p::block!(blocker, sender, "invalid assigned shard received");
            return false;
        };

        let common = self.common_mut();
        common.contributed.set(u64::from(shard.index), true);
        common.assigned_shard_verified = true;
        common.notify = true;
        if let Self::AwaitingQuorum(state) = self {
            state.checked_shards.push(SizedShard {
                shard: checked,
                size: shard.data.encode_size(),
            });
        }
        true
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
        simplex::elector::{Dynamic, Input as ElectorInput, Scheduled, Terms},
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
            atomic::{AtomicIsize, AtomicUsize, Ordering},
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

    /// Returns the encoded size of the largest stream or roots message that coding with `S`
    /// produces for the largest [`B`] its codec decodes, in committees of 4 to `participants`
    /// members.
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

    /// Returns a simulated network configuration for committees of at most `participants`
    /// members. Its message bound covers the coding variant's buffer payload and the shard
    /// messages of [`C`] and [`SC`] for the largest [`B`] its codec decodes. The other test
    /// coding schemes take their shard and chunk sizes from `C`, so the bound covers them too.
    fn network_config(participants: usize) -> simulated::Config {
        // `CodingB` supplies the context type the coding variant requires. The buffer bound, like
        // each stream bound, is sized for the encoded size of the largest `B`.
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
    type ShardEngine<S, T = Sequential, L = Named> =
        Engine<deterministic::Context, Prov, X, D, S, H, B, P, T, L>;
    type ChurningShardEngine<S> =
        Engine<deterministic::Context, ChurningProvider, X, D, S, H, B, P, Sequential, Named>;
    type EngineSender<S> = WrappedSender<NetworkSender, ShardMessage<B, S, H>>;

    /// Segmented coding whose segments are small enough that a test block spans several.
    type SC = Segmented<H, 16>;

    /// An armed [`GATE`].
    struct Gate {
        /// Signals that decode started.
        started: mpsc::Sender<()>,
        /// Releases the held decode.
        release: mpsc::Receiver<()>,
        /// The engine's thread. Decode must not run on it.
        engine: thread::ThreadId,
    }

    /// Holds [`Gated::decode`] until released.
    static GATE: Mutex<Option<Gate>> = Mutex::new(None);

    /// [`C`] coding whose decode holds while [`GATE`] is armed.
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

    /// [`C`] coding that asserts that only the assigned shard of peer 3 is checked on its own and
    /// that the shards other peers relay are checked in one batch of seven.
    #[derive(Clone, Debug)]
    struct BatchChecking;

    impl CodingScheme for BatchChecking {
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
            assert_eq!(index, 3, "only the assigned shard is checked eagerly");
            C::check(config, commitment, index, shard, strategy)
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

    /// Implements [`Segmentable`] for a test coding scheme as [`C`] does.
    macro_rules! segmentable_as_c {
        ($scheme:ty) => {
            impl Segmentable for $scheme {
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

                fn assemble(roots: Vec<Self::Commitment>, chunks: Vec<Self::Chunk>) -> Self::Shard {
                    C::assemble(roots, chunks)
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
        };
    }

    segmentable_as_c!(Gated);
    segmentable_as_c!(BatchChecking);

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
    fn receive<S: Segmentable, T: Strategy, L: ElectorConfig<Scheme>>(
        engine: &mut ShardEngine<S, T, L>,
        sender: &mut EngineSender<S>,
        peer: &P,
        messages: impl IntoIterator<Item = ShardMessage<B, S, H>>,
    ) {
        for message in messages {
            engine.handle_network_message(sender, peer.clone(), message);
        }
    }

    /// A scheduled elector that names one participant for every round and counts its builds and
    /// elections. It is its own configuration.
    #[derive(Clone)]
    struct Named {
        leader: Participant,
        built: Arc<AtomicUsize>,
        elected: Arc<AtomicUsize>,
    }

    impl Named {
        fn new(leader: usize) -> Self {
            Self {
                leader: Participant::from_usize(leader),
                built: Arc::default(),
                elected: Arc::default(),
            }
        }
    }

    impl ElectorConfig<Scheme> for Named {
        type Elector = Self;

        fn build(self, _: &Set<P>) -> Self {
            self.built.fetch_add(1, Ordering::Relaxed);
            self
        }
    }

    impl Elector<Scheme> for Named {
        type Mode = Scheduled;

        fn terms(&self) -> Terms {
            Terms::rotating()
        }

        fn elect(&self, _: Round, _: ()) -> Participant {
            self.elected.fetch_add(1, Ordering::Relaxed);
            self.leader
        }
    }

    /// A dynamic elector. It names no leader before the certificate that unlocks a round.
    #[derive(Clone)]
    struct Late;

    impl ElectorConfig<Scheme> for Late {
        type Elector = Self;

        fn build(self, _: &Set<P>) -> Self {
            self
        }
    }

    impl Elector<Scheme> for Late {
        type Mode = Dynamic;

        fn terms(&self) -> Terms {
            Terms::rotating()
        }

        fn elect(&self, _: Round, _: ElectorInput<'_, Scheme, Self>) -> Participant {
            unreachable!("the engine must not elect without the round's certificate")
        }
    }

    /// Makes the engine's elector name participant `leader` for every round.
    fn elect<S: Segmentable, T: Strategy>(engine: &mut ShardEngine<S, T>, leader: usize) {
        engine.elector = Some(Named::new(leader));
        engine.electors.clear();
    }

    /// Returns a block that shares no segment with the other test blocks. A test notarizes its
    /// commitment to give consensus a signaled round.
    fn unrelated() -> CodedBlock<B, SC, H> {
        encode_block::<B, SC, H>(
            B::new(Sha256::hash(&[b"unrelated"]), Height::new(1), 1),
            coding_config_for_participants(4),
        )
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
        /// Per-peer ring capacity, in messages.
        peer_buffer_size: NonZeroUsize,
        /// Maximum number of commitment records each engine retains.
        records: NonZeroUsize,
        /// Index of the primary peer every engine's elector names for every round, or `None` for
        /// engines without an elector.
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
                let elector = self.round_leader.map(Named::new);

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
                        elector: elector.clone(),
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
                        elector: elector.clone(),
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
        unstarted_electing(
            context,
            oracle,
            private_keys,
            index,
            records,
            strategy,
            None,
        )
        .await
    }

    /// Builds an unstarted engine that holds `elector`, as [`unstarted_with`] does.
    async fn unstarted_electing<S: Segmentable, T: Strategy, L: ElectorConfig<Scheme>>(
        context: &deterministic::Context,
        oracle: &O,
        private_keys: &[PrivateKey],
        index: usize,
        records: NonZeroUsize,
        strategy: T,
        elector: Option<L>,
    ) -> (ShardEngine<S, T, L>, EngineSender<S>) {
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
        let config = Config {
            scheme_provider: MultiEpochProvider::single(scheme),
            blocker: control,
            block_codec_config: (),
            strategy,
            mailbox_size: NZUsize!(16),
            peer_buffer_size: NZUsize!(4),
            records,
            peer_provider: oracle.manager(),
            elector,
        };
        let (mut engine, _) = Engine::new(context.child("engine"), config);
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
    ) -> Reconstructed<P, B, S, H> {
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
                // Peer 0 leads view 1 and proposes the block.
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

                // Every participant's assigned-shard subscription resolves, including the
                // proposer's from its cached block.
                for peer in peers.iter_mut() {
                    peer.mailbox
                        .subscribe_assigned_shard_verified(commitment)
                        .await
                        .expect("shard subscription should complete");
                }
                context.sleep(config.link.latency).await;

                // Every participant has the block available.
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
                // Peer 0 will propose the block in view 1.
                let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block = encode_block::<B, C, H>(inner.clone(), coding_config);
                let commitment = coded_block.commitment();
                let digest = coded_block.digest();

                let leader = peers[0].public_key.clone();
                let round = Round::new(Epoch::zero(), View::new(1));

                // Subscribe before broadcasting.
                let commitment_sub = peers[1].mailbox.subscribe(commitment);
                let digest_sub = peers[2].mailbox.subscribe_by_digest(digest);

                // Peer 0 proposes the block.
                peers[0].mailbox.proposed(round, coded_block.clone());

                // Inform all peers of the leader so shards are processed.
                for peer in peers[1..].iter_mut() {
                    peer.mailbox.discovered(commitment, leader.clone(), round);
                }
                context.sleep(config.link.latency * 2).await;

                // Every participant's assigned-shard subscription resolves, including the
                // proposer's from its cached block.
                for peer in peers.iter_mut() {
                    peer.mailbox
                        .subscribe_assigned_shard_verified(commitment)
                        .await
                        .expect("shard subscription should complete");
                }
                context.sleep(config.link.latency).await;

                // Both subscriptions resolve to the reconstructed block.
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
            // Peer 0 will propose the block in view 1.
            let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
            let coded_block = encode_block::<B, C, H>(inner.clone(), coding_config);
            let commitment = coded_block.commitment();
            let digest = coded_block.digest();
            let round = Round::new(Epoch::zero(), View::new(1));

            // Subscribe on the proposer before it caches the locally proposed block.
            let shard_sub = peers[0].mailbox.subscribe_assigned_shard_verified(commitment);
            let commitment_sub = peers[0].mailbox.subscribe(commitment);
            let digest_sub = peers[0].mailbox.subscribe_by_digest(digest);

            // Peer 0 proposes the block and caches it locally.
            peers[0].mailbox.proposed(round, coded_block.clone());
            context.sleep(config.link.latency).await;

            // The cached proposal resolves the assigned-shard subscription.
            select! {
                result = shard_sub => {
                    result.expect("shard subscription should resolve");
                },
                _ = context.sleep(Duration::from_secs(5)) => {
                    panic!("shard subscription did not resolve after local proposal cache");
                }
            }

            // The cached proposal also resolves the block subscription by commitment.
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

            // The cached proposal also resolves the block subscription by digest.
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

    /// A non-leader's chunk at an index belonging to neither the sender nor the receiver blocks its
    /// sender once the roots bind, and the receiver's assigned shard still verifies from the
    /// leader's chunk.
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

                // The invalid chunk arrives before any roots bind, so it waits in the byzantine
                // peer's ring and leaves the subscription pending.
                send::<C>(&mut peers[0].sender, &receiver_pk, [invalid.into()]);
                context.sleep(config.link.latency * 2).await;
                assert!(
                    matches!(shard_sub.try_recv(), Err(TryRecvError::Empty)),
                    "an invalid chunk must not resolve the subscription"
                );

                // The honest proposer sends the receiver its chunk and the roots. The roots bind
                // the commitment, so the waiting chunk is classified and blocks the byzantine peer.
                send(
                    &mut peers[1].sender,
                    &receiver_pk,
                    assigned(&coded_block, round, receiver_index),
                );
                context.sleep(config.link.latency * 2).await;
                assert_blocked(&oracle, &peers[2].public_key, &peers[0].public_key).await;

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
            // Peer 0 leads the discovered commitments, and peer 2 also proposes a block at view 2.
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
            verified.await.expect("the assigned shard must verify");
            let reconstructed = subscription.await.expect("block should be reconstructed");
            assert_eq!(reconstructed.commitment(), commitment);
            assert!(oracle.blocked().await.unwrap().is_empty());
        });
    }

    /// Subquorum reconstruction state survives records for `records - 1` later views and is
    /// evicted by the next. Its block subscription stays open, and its last chunk then only joins
    /// the sender's ring without rebuilding the block.
    #[test_traced]
    fn test_subquorum_reconstruction_evicted_by_window() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Participant 3 of 10 runs an unstarted engine that retains four records, and peer 0
            // leads every view.
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

            // The candidate at view 10 receives three of the four chunks it needs, and the leader's
            // roots bind them.
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
            assert_eq!(state.checked_shards.len() + state.pending_shards.len(), 3);
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

            // The record is gone, so the last chunk only joins its sender's ring and rebuilds
            // nothing.
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
    /// no record and leaves the round's chunks in their senders' rings. A block from such a round
    /// still resolves its subscribers. A notarization above the lowest round creates the record,
    /// and roots for the commitment then bind it and ingest the sender's own chunk from its ring.
    #[test_traced]
    fn test_full_window_declines_rounds_at_or_below_lowest() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Participant 0 of 4 runs an unstarted engine that retains two records.
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

            // Relayed chunks of commitments without a record wait in their sender's ring.
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
            // chunk stays in the ring.
            for view in [5, 4] {
                engine.handle_notarized_commitment(&mut sender, commitment, round(view));
                engine.trim();
                assert!(!engine.records.contains_key(&commitment), "view {view}");
                assert_eq!(buffered(&engine, &gossiper, round(4)), 1, "view {view}");
            }

            // A discovery below the lowest retained view creates no record either.
            let leader = peer_keys[2].clone();
            engine.handle_external_proposal(&mut sender, commitment, leader.clone(), round(4));
            engine.trim();
            assert!(!engine.records.contains_key(&commitment));
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
            // then evicts view 5. The chunk waits in the ring until roots bind the record.
            engine.handle_notarized_commitment(&mut sender, commitment, round(7));
            engine.trim();
            assert!(engine.records.contains_key(&commitment));
            assert_eq!(buffered(&engine, &gossiper, round(7)), 1);
            assert_eq!(engine.records.len(), records.get());
            assert!(
                engine
                    .records
                    .values()
                    .all(|record| record.round() > round(5))
            );

            // Roots for the notarized commitment bind it, and the gossiper's own chunk contributes
            // its shard although the round's leader is unknown.
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
            assert!(state.common.contributed.get(1));
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

    /// Caching a reconstructed block drops its record's checked and pending shards. Another
    /// block's chunks then wait in their senders' rings without being relayed or blocking anyone,
    /// and a late assigned chunk is still verified and relayed.
    #[test_traced]
    fn test_cached_record_retains_no_shards() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Participant 0 of 4 runs an unstarted engine.
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

            // Peer 1 leads view 1 with the block.
            let coding_config = coding_config_for_participants(participants.len() as u16);
            let block = {
                let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                encode_block::<B, C, H>(inner, coding_config)
            };
            let commitment = block.commitment();
            let round = Round::new(Epoch::zero(), View::new(1));
            let leader = peer_keys[1].clone();

            // Relayed chunks from peers 2 and 3 and the leader's roots reconstruct the block
            // before the assigned chunk arrives, and the engine relays the roots.
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

            // Another block's chunks, from peer 2 and from the leader for the local index, wait in
            // their senders' rings without being relayed or blocking anyone.
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
            assert!(next_message::<C>(&context, &mut observer).await.is_none());
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
            let relay = next_message::<C>(&context, &mut observer).await;
            assert!(matches!(relay, Some(ShardMessage::Stream(chunk)) if chunk == assigned[0]));
            assert!(oracle.blocked().await.unwrap().is_empty());
        });
    }

    /// A notarized record reconstructs its block from relayed chunks while the leader's delivery
    /// of the assigned chunk waits in the leader's ring. Discovery then verifies and relays that
    /// chunk.
    #[test_traced]
    fn test_cached_leaderless_record_keeps_buffered_assigned_shard() {
        cached_leaderless_record_keeps_buffered_assigned_shard(false);
    }

    /// A committee member without a signing key still has an assigned shard, so the waiting
    /// chunk is verified and relayed exactly as it is for a signer.
    #[test_traced]
    fn test_member_cached_leaderless_record_keeps_buffered_assigned_shard() {
        cached_leaderless_record_keeps_buffered_assigned_shard(true);
    }

    /// Runs the leaderless-record scenario on participant 0, under a member scheme when `member`
    /// is set and a signer scheme otherwise.
    fn cached_leaderless_record_keeps_buffered_assigned_shard(member: bool) {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Participant 0 of 4 runs an unstarted engine.
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

            // Peer 1 leads view 1 with the block.
            let coding_config = coding_config_for_participants(participants.len() as u16);
            let block = {
                let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                encode_block::<B, C, H>(inner, coding_config)
            };
            let commitment = block.commitment();
            let round = Round::new(Epoch::zero(), View::new(1));
            let leader = peer_keys[1].clone();

            // A notarization creates a leaderless record. The leader's roots bind it and are
            // relayed. Without a known leader, the assigned chunk the leader delivers cannot be
            // classified, so it waits in the leader's ring.
            engine.handle_notarized_commitment(&mut sender, commitment, round);
            let (response, mut verified) = oneshot::channel();
            engine.handle_assigned_shard_verified_subscription(commitment, response);
            receive(
                &mut engine,
                &mut sender,
                &leader,
                assigned(&block, round, 0),
            );
            let relay = next_message::<C>(&context, &mut observer).await;
            assert!(relay == Some(ShardMessage::Roots(roots_of(&block, round))));
            assert!(next_message::<C>(&context, &mut observer).await.is_none());

            // Relayed chunks from peers 2 and 3 reconstruct the block, and readiness stays
            // pending.
            for index in [2, 3] {
                let relayer = &peer_keys[usize::from(index)];
                receive(
                    &mut engine,
                    &mut sender,
                    relayer,
                    relayed(&block, round, index),
                );
            }
            let reconstructed = finished(&mut engine).await;
            engine.complete(reconstructed);
            let record = engine.records.get(&commitment).expect("record must exist");
            assert!(record.block().is_some());
            assert!(matches!(verified.try_recv(), Err(TryRecvError::Empty)));

            // Discovery names the leader. The assigned chunk waiting in the leader's ring then
            // verifies, resolves readiness, and is relayed.
            engine.handle_external_proposal(&mut sender, commitment, leader.clone(), round);
            assert!(matches!(verified.try_recv(), Ok(())));
            let assigned = stream_of(&block, round, 0).remove(0);
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
            // Participant 0 of 4 runs an unstarted engine.
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
                // Peer 0 leads view 1, and peer 2 receives.
                let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block = encode_block::<B, C, H>(inner, coding_config);
                let commitment = coded_block.commitment();
                let round = Round::new(Epoch::zero(), View::new(1));
                let peer2_index = peers[2].index.get() as u16;
                let peer2_pk = peers[2].public_key.clone();
                let leader = peers[0].public_key.clone();

                // Peer 2 subscribes to its assigned shard and discovers the commitment.
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

                // The copies block no one, peer 2 relays its chunk once, and its assigned shard
                // verifies.
                assert!(
                    oracle.blocked().await.unwrap().is_empty(),
                    "a duplicate chunk must not block the leader"
                );
                assert_eq!(
                    gauges(&context.encode(), "chunks_forwarded")
                        .iter()
                        .sum::<i64>(),
                    1,
                    "only the first copy of the chunk must be relayed"
                );
                select! {
                    _ = verified => {},
                    _ = context.sleep(Duration::from_secs(5)) => {
                        panic!("the leader's chunk must complete the subscription");
                    },
                };
            },
        );
    }

    /// A leader's second chunk for a segment and index it already sent, under another root, waits
    /// in the leader's ring without blocking it, so the first chunk still verifies against the
    /// roots. A chunk that fails its check against the root it claims blocks the leader once roots
    /// that include that root bind.
    #[test_traced]
    fn test_equivocating_leader_chunk_ignored_and_forged_chunk_blocks_peer() {
        let fixture = Fixture::<C>::default();
        fixture.start(
            |config, context, oracle, mut peers, _, coding_config| async move {
                // Blocks 1 and 2 are distinct blocks at height 1, peer 0 leads view 1, and peer 2
                // receives.
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

                // Peer 2 subscribes to its assigned shard and discovers block 1.
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
                        ShardMessage::from(chunk2),
                        ShardMessage::from(roots_of(&block1, round)),
                    ],
                );
                context.sleep(config.link.latency * 2).await;

                // The conflicting chunk blocks no one, and block 1's chunk verifies the assigned
                // shard.
                assert!(
                    oracle.blocked().await.unwrap().is_empty(),
                    "a conflicting chunk must not block the leader"
                );
                select! {
                    _ = verified => {},
                    _ = context.sleep(Duration::from_secs(5)) => {
                        panic!("the first chunk must verify the assigned shard");
                    },
                };

                // In a later round, the leader sends block 1's chunk data under the root of a third
                // block, and then the third block's roots.
                let block3 = encode_block::<B, C, H>(
                    B::new(Sha256Digest::EMPTY, Height::new(1), 300),
                    coding_config,
                );
                let forged_round = Round::new(Epoch::zero(), View::new(2));
                peers[2]
                    .mailbox
                    .discovered(block3.commitment(), leader, forged_round);
                let forged = StreamChunk {
                    chunk: chunk1.chunk,
                    ..stream_of(&block3, forged_round, peer2_index).remove(0)
                };
                send(
                    &mut peers[0].sender,
                    &peer2_pk,
                    [
                        ShardMessage::from(forged),
                        ShardMessage::from(roots_of(&block3, forged_round)),
                    ],
                );
                context.sleep(config.link.latency * 2).await;

                // The forged chunk fails its check against block 3's root, so peer 2 blocks the
                // leader.
                assert_blocked(&oracle, &peers[2].public_key, &peers[0].public_key).await;
            },
        );
    }

    /// A chunk a non-leader sends at an index other than its own blocks the sender once the
    /// leader's roots bind its root.
    #[test_traced]
    fn test_non_leader_wrong_index_shard_blocked() {
        let fixture = Fixture::<C>::default();
        fixture.start(
            |config, context, oracle, mut peers, _, coding_config| async move {
                // Peer 0 leads view 1, and peer 2 receives.
                let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block = encode_block::<B, C, H>(inner, coding_config);
                let commitment = coded_block.commitment();
                let round = Round::new(Epoch::zero(), View::new(1));
                let unrelated_index = peers[3].index.get() as u16;
                let peer2_pk = peers[2].public_key.clone();
                let leader = peers[0].public_key.clone();

                // Peer 2 discovers the commitment and its leader.
                peers[2].mailbox.discovered(commitment, leader, round);

                // Peer 1 (not the leader) sends peer 2 the chunk of peer 3, and the leader sends
                // the roots.
                send(
                    &mut peers[1].sender,
                    &peer2_pk,
                    relayed(&coded_block, round, unrelated_index),
                );
                send(
                    &mut peers[0].sender,
                    &peer2_pk,
                    [ShardMessage::from(roots_of(&coded_block, round))],
                );
                context.sleep(config.link.latency * 2).await;

                // The chunk is neither peer 2's nor peer 1's own, so peer 2 blocks peer 1.
                assert_blocked(&oracle, &peers[2].public_key, &peers[1].public_key).await;
            },
        );
    }

    /// A non-leader's chunk at an index other than its own waits in the sender's ring while the
    /// round's leader is unknown, even under bound roots, and blocks the sender once discovery
    /// names the leader.
    #[test_traced]
    fn test_buffered_wrong_index_shard_blocked_on_leader_arrival() {
        let fixture = Fixture::<C>::default();
        fixture.start(
            |config, context, oracle, mut peers, _, coding_config| async move {
                // Peer 0 leads view 1, and peer 2 receives.
                let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block = encode_block::<B, C, H>(inner, coding_config);
                let commitment = coded_block.commitment();
                let round = Round::new(Epoch::zero(), View::new(1));
                let unrelated_index = peers[3].index.get() as u16;
                let peer2_pk = peers[2].public_key.clone();

                // Peer 1 sends the chunk of peer 3. A notarization names the commitment without
                // its leader, and the leader's roots bind it.
                send(
                    &mut peers[1].sender,
                    &peer2_pk,
                    relayed(&coded_block, round, unrelated_index),
                );
                peers[2].mailbox.notarized(commitment, round);
                send(
                    &mut peers[0].sender,
                    &peer2_pk,
                    [ShardMessage::from(roots_of(&coded_block, round))],
                );
                context.sleep(config.link.latency * 2).await;

                // Without a known leader, the chunk waits in peer 1's ring.
                assert!(
                    oracle.blocked().await.unwrap().is_empty(),
                    "no peers should be blocked while leader is unknown"
                );

                // Discovery names the leader, so the waiting chunk blocks peer 1.
                let leader = peers[0].public_key.clone();
                peers[2].mailbox.discovered(commitment, leader, round);
                context.sleep(Duration::from_millis(10)).await;
                assert_blocked(&oracle, &peers[2].public_key, &peers[1].public_key).await;
            },
        );
    }

    /// Any participant may deliver this node's assigned chunks, since each is checked against the
    /// bound roots. Chunks a participant other than the leader delivers verify the assigned shard
    /// and block no one.
    #[test_traced]
    fn test_assigned_shard_from_non_leader_accepted() {
        let fixture = Fixture::<C>::default();
        fixture.start(
            |_, context, oracle, mut peers, _, coding_config| async move {
                // Peer 0 leads view 1, and peer 2 receives.
                let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block = encode_block::<B, C, H>(inner, coding_config);
                let commitment = coded_block.commitment();
                let round = Round::new(Epoch::zero(), View::new(1));
                let peer2_index = peers[2].index.get() as u16;
                let peer2_pk = peers[2].public_key.clone();
                let leader = peers[0].public_key.clone();

                // Peer 2 subscribes to its assigned shard and discovers the commitment.
                let verified = peers[2]
                    .mailbox
                    .subscribe_assigned_shard_verified(commitment);
                peers[2].mailbox.discovered(commitment, leader, round);

                // Peer 1 delivers peer 2's chunks, and the leader's roots bind them.
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

                // Peer 1's chunks verify the assigned shard and block no one.
                select! {
                    _ = verified => {},
                    _ = context.sleep(Duration::from_secs(5)) => {
                        panic!("chunks from a non-leader must verify the assigned shard");
                    },
                };
                assert!(oracle.blocked().await.unwrap().is_empty());
            },
        );
    }

    /// A discovery naming a non-participant leader is ignored, so the real leader's messages wait
    /// in its ring without blocking it until a valid discovery names it.
    #[test_traced]
    fn test_non_participant_external_proposed_ignored() {
        let fixture = Fixture::<C>::default();
        fixture.start(
            |config, context, oracle, mut peers, _, coding_config| async move {
                // Peer 0 leads view 1, and `non_participant_leader` is outside the committee.
                let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block = encode_block::<B, C, H>(inner, coding_config);
                let commitment = coded_block.commitment();
                let round = Round::new(Epoch::zero(), View::new(1));
                let peer2_index = peers[2].index.get() as u16;
                let peer2_pk = peers[2].public_key.clone();
                let leader = peers[0].public_key.clone();
                let non_participant_leader = PrivateKey::from_seed(10_000).public_key();

                // Peer 2 subscribes to its assigned shard and ignores a discovery naming the
                // non-participant.
                let shard_sub = peers[2]
                    .mailbox
                    .subscribe_assigned_shard_verified(commitment);
                peers[2]
                    .mailbox
                    .discovered(commitment, non_participant_leader, round);

                // Peer 2 holds no record, so the leader's chunk and roots wait in the leader's ring
                // without blocking the leader.
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

                // A valid discovery creates the record and ingests the waiting messages, and they
                // verify the assigned shard.
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

    /// A chunk from a peer outside the round's participants blocks that peer once bound roots
    /// cover the chunk.
    #[test_traced]
    fn test_shard_from_non_participant_blocks_peer() {
        let fixture = Fixture {
            num_future_peers: 1,
            ..Fixture::<C>::default()
        };
        fixture.start(
            |config, context, oracle, mut peers, _, coding_config| async move {
                // Peer 0 leads view 1, and peer 2 receives.
                let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block = encode_block::<B, C, H>(inner, coding_config);
                let commitment = coded_block.commitment();
                let round = Round::new(Epoch::zero(), View::new(1));

                let leader = peers[0].public_key.clone();
                let receiver_pk = peers[2].public_key.clone();

                // A non-participant joins as a tracked secondary peer with a link to peer 2.
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

                // Only primary peers keep a ring, so the leader's roots bind the commitment before
                // the non-participant's chunk arrives.
                peers[2].mailbox.discovered(commitment, leader, round);
                send(
                    &mut peers[0].sender,
                    &receiver_pk,
                    [ShardMessage::from(roots_of(&coded_block, round))],
                );
                context.sleep(config.link.latency * 2).await;

                // The bound roots cover the chunk the non-participant sends, so peer 2 blocks the
                // sender.
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

    /// A peer that is not a tracked primary keeps no ring, so its chunk sent before the commitment
    /// is named is dropped. Naming the commitment and binding its roots then neither blocks the
    /// sender nor verifies the assigned shard.
    #[test_traced]
    fn test_preleader_shard_from_non_participant_is_not_buffered() {
        let fixture = Fixture {
            num_future_peers: 1,
            ..Fixture::<C>::default()
        };
        fixture.start(
            |config, context, oracle, mut peers, _, coding_config| async move {
                // Peer 0 leads view 1, and peer 2 receives.
                let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block = encode_block::<B, C, H>(inner, coding_config);
                let commitment = coded_block.commitment();
                let round = Round::new(Epoch::zero(), View::new(1));

                let leader = peers[0].public_key.clone();
                let receiver_pk = peers[2].public_key.clone();

                // A non-participant joins as a tracked secondary peer with a link to peer 2.
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

                // Peer 2 subscribes to its assigned shard.
                let peer2_index = peers[2].index.get() as u16;
                let mut shard_sub = peers[2]
                    .mailbox
                    .subscribe_assigned_shard_verified(commitment);

                // The non-participant sends peer 2's chunk before the commitment is named.
                send(
                    &mut non_participant_sender,
                    &receiver_pk,
                    relayed(&coded_block, round, peer2_index),
                );
                context.sleep(config.link.latency * 2).await;

                // Discovery names the commitment, and the leader's roots bind it.
                peers[2].mailbox.discovered(commitment, leader, round);
                send(
                    &mut peers[0].sender,
                    &receiver_pk,
                    [ShardMessage::from(roots_of(&coded_block, round))],
                );
                context.sleep(config.link.latency * 2).await;

                // The dropped chunk neither blocks the non-participant nor verifies the shard.
                let blocked = oracle.blocked().await.unwrap();
                let non_participant_blocked = blocked
                    .iter()
                    .any(|(a, b)| a == &peers[2].public_key && b == &non_participant_pk);
                assert!(
                    !non_participant_blocked,
                    "an ignored chunk must not block the non-participant"
                );
                assert!(
                    matches!(shard_sub.try_recv(), Err(TryRecvError::Empty)),
                    "a non-participant's chunk must not verify the assigned shard"
                );
            },
        );
    }

    /// A participant's repeated chunk is ignored without blocking it and does not count twice
    /// toward the shards reconstruction needs.
    #[test_traced]
    fn test_duplicate_shard_ignored() {
        // Ten peers need four chunks per segment.
        let fixture: Fixture<C> = Fixture {
            num_primary_peers: 10,
            ..Default::default()
        };

        fixture.start(
            |config, context, oracle, mut peers, _, coding_config| async move {
                // Peer 0 leads view 1, and peer 2 receives.
                let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block = encode_block::<B, C, H>(inner, coding_config);
                let commitment = coded_block.commitment();
                let round = Round::new(Epoch::zero(), View::new(1));
                let peer2_index = peers[2].index.get() as u16;
                let peer2_pk = peers[2].public_key.clone();
                let leader = peers[0].public_key.clone();

                // Peer 2 discovers the commitment and receives its chunk and the roots from the
                // leader.
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

                // The duplicate blocks no one, and three distinct chunks fall short of the minimum.
                let blocked_peers = oracle.blocked().await.unwrap();
                let is_blocked = blocked_peers
                    .iter()
                    .any(|(a, b)| a == &peers[2].public_key && b == &peers[1].public_key);
                assert!(
                    !is_blocked,
                    "an exact duplicate chunk must not block its sender"
                );
                assert!(
                    peers[2].mailbox.get(commitment).await.is_none(),
                    "three distinct chunks must not reconstruct the block"
                );

                // Peer 4's chunk is the fourth distinct one and reconstructs the block.
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

    /// Once roots bind a commitment, a participant's chunk whose root differs from its segment's
    /// bound root does not count toward reconstruction and does not block the sender, and the
    /// sender's valid chunk still counts.
    #[test_traced]
    fn test_equivocating_chunk_ignored() {
        // Ten peers need four chunks per segment.
        let fixture: Fixture<C> = Fixture {
            num_primary_peers: 10,
            ..Default::default()
        };

        fixture.start(
            |config, context, oracle, mut peers, _, coding_config| async move {
                // Blocks 1 and 2 are distinct blocks at height 1, peer 0 leads view 1 with block
                // 1, and peer 2 receives.
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

                // Peer 2 discovers block 1 and receives its chunk and the roots from the leader.
                peers[2].mailbox.discovered(commitment, leader, round);
                send(
                    &mut peers[0].sender,
                    &peer2_pk,
                    assigned(&block1, round, peer2_index),
                );
                context.sleep(config.link.latency * 2).await;

                // Peer 1 sends its chunk of block 2, under a root that block 1's roots do not
                // contain.
                let peer1_index = peers[1].index.get() as u16;
                send(
                    &mut peers[1].sender,
                    &peer2_pk,
                    relayed(&block2, round, peer1_index),
                );
                context.sleep(config.link.latency * 2).await;

                // The chunk under block 2's root does not block peer 1.
                let blocked = oracle.blocked().await.unwrap();
                assert!(
                    !blocked
                        .iter()
                        .any(|(a, b)| a == &peers[2].public_key && b == &peers[1].public_key),
                    "a chunk under a conflicting root must not block its sender"
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

                // Peer 1's valid chunk counts, and block 1 reconstructs.
                let reconstructed = peers[2]
                    .mailbox
                    .get(commitment)
                    .await
                    .expect("the block must reconstruct with peer 1's valid chunk");
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
                // Peer 0 leads A at view 1 and B at view 2, and peer 2 receives.
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

                // Peer 2 reconstructs B.
                let reconstructed = peers[2]
                    .mailbox
                    .get(commitment_b)
                    .await
                    .expect("block B should reconstruct");
                assert_eq!(reconstructed.commitment(), commitment_b);

                // Peer 1 resends its chunk of A, an exact duplicate.
                send(
                    &mut peers[1].sender,
                    &peer2_pk,
                    relayed(&block_a, round_a, indices[1]),
                );
                context.sleep(config.link.latency * 2).await;

                // The duplicate does not block peer 1.
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
                        let reconstructed = result.expect("block A must reconstruct");
                        assert_eq!(reconstructed.commitment(), commitment_a);
                    },
                    _ = context.sleep(config.link.latency * 10) => {
                        panic!("the lower-view reconstruction must complete");
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
            // Participant 3 of 10 runs an unstarted engine that retains two records, and peer 0
            // leads the commitment being reconstructed.
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

            // The same commitment is notarized at view 4, and that view's leader streams it again.
            // The assigned chunk and two relayed chunks fall one short of the minimum of four.
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
                .expect("the reconstructed block must resolve the subscription");
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
                // Participant 3 of 10 runs an unstarted engine that retains two records, and peer 0
                // leads the commitment being reconstructed.
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

                // The commitment is observed again at view 4, and that view's leader resends the
                // roots.
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
                    "a cached observation must keep assigned-shard verification pending"
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

    /// A local proposal in a one-record window evicts an older reconstruction state. A chunk that
    /// conflicts with one its sender streamed for the evicted commitment then waits in the
    /// sender's ring without blocking.
    #[test_traced]
    fn test_local_proposal_evicts_older_reconstruction_state() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Participant 2 of 4 runs an unstarted engine that retains one record, and peer 0
            // leads A.
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

            // A chunk that conflicts with peer 1's chunk of A joins peer 1's ring without
            // blocking.
            receive(
                &mut engine,
                &mut sender,
                &peer1,
                relayed(&make_block(1, 300), round_a, 1),
            );
            assert_eq!(buffered(&engine, &peer1, round_a), 2);
            assert!(oracle.blocked().await.unwrap().is_empty());
        });
    }

    /// Relayed chunks wait until the leader's roots bind them. The assigned shard is checked on
    /// its own, and the relayed shards are checked in one batch once they and the assigned shard
    /// reach the minimum.
    #[test_traced]
    fn test_pending_shards_batch_validated_at_quorum() {
        let fixture: Fixture<BatchChecking> = Fixture {
            num_primary_peers: 22,
            ..Default::default()
        };

        fixture.start(
            |config, context, oracle, mut peers, _, coding_config| async move {
                // Peer 0 leads view 1 in a committee of 22, and peer 3 receives.
                let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block = encode_block::<B, BatchChecking, H>(inner, coding_config);
                let commitment = coded_block.commitment();
                let round = Round::new(Epoch::zero(), View::new(1));

                // Peer 3 discovers the commitment.
                let peer3_pk = peers[3].public_key.clone();
                let leader = peers[0].public_key.clone();
                peers[3].mailbox.discovered(commitment, leader, round);

                // Seven participants relay their chunks, one short of the minimum of eight.
                for sender_idx in [1usize, 2, 4, 5, 6, 7, 8] {
                    let index = peers[sender_idx].index.get() as u16;
                    send(
                        &mut peers[sender_idx].sender,
                        &peer3_pk,
                        relayed(&coded_block, round, index),
                    );
                }
                context.sleep(config.link.latency * 2).await;
                assert!(
                    peers[3].mailbox.get(commitment).await.is_none(),
                    "the block must not reconstruct before the roots bind"
                );

                // The leader's chunk and roots complete the minimum.
                let peer3_index = peers[3].index.get() as u16;
                send(
                    &mut peers[0].sender,
                    &peer3_pk,
                    assigned(&coded_block, round, peer3_index),
                );
                context.sleep(config.link.latency * 2).await;

                // The batch check accepts every relayed shard, and the block reconstructs.
                assert!(
                    oracle.blocked().await.unwrap().is_empty(),
                    "no peers should be blocked for valid pending shards"
                );
                let reconstructed = peers[3]
                    .mailbox
                    .get(commitment)
                    .await
                    .expect("the block must reconstruct after the batch check");
                assert_eq!(reconstructed.commitment(), commitment);
            },
        );
    }

    /// Chunks and roots that arrive before consensus names their commitment wait in the rings,
    /// and discovery of the proposal ingests them at once. The assigned shard verifies and the
    /// block reconstructs without further messages.
    #[test_traced]
    fn test_peer_shards_buffered_until_external_proposed() {
        let fixture: Fixture<C> = Fixture {
            num_primary_peers: 10,
            ..Default::default()
        };

        fixture.start(
            |config, context, oracle, mut peers, _, coding_config| async move {
                // Peer 0 leads view 1, and peer 3 receives.
                let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block = encode_block::<B, C, H>(inner, coding_config);
                let commitment = coded_block.commitment();
                let round = Round::new(Epoch::zero(), View::new(1));

                let receiver_idx = 3usize;
                let receiver_pk = peers[receiver_idx].public_key.clone();
                let receiver_index = peers[receiver_idx].index.get() as u16;
                let leader = peers[0].public_key.clone();

                // The receiver subscribes to its assigned shard.
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

                // Without a named commitment, every message waits in its sender's ring.
                assert!(
                    matches!(shard_sub.try_recv(), Err(TryRecvError::Empty)),
                    "shard subscription should not resolve before leader announcement"
                );
                assert!(
                    peers[receiver_idx].mailbox.get(commitment).await.is_none(),
                    "block should not reconstruct before leader announcement"
                );

                // Discovery ingests the waiting messages. They verify the assigned shard and
                // reconstruct the block without blocking anyone.
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
                    "the block must reconstruct once buffered messages are ingested"
                );
                assert!(
                    oracle.blocked().await.unwrap().is_empty(),
                    "valid buffered messages must not block peers"
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
                // Peer 0 leads view 1, and peer 3 receives.
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
                    "valid buffered messages must not block peers"
                );
            },
        );
    }

    /// A cached block outlives pressure on the rings. Each ring holds two messages, so when one
    /// peer relays chunks for three rounds, only the two rounds whose chunks survive reconstruct.
    /// A subscription installed afterwards still receives the earlier cached block. A block
    /// reconstructed from other participants' chunks does not verify the assigned shard until the
    /// leader's chunk for the local index arrives.
    #[test_traced]
    fn test_late_subscription_uses_notarized_cache_after_peer_buffer_pressure() {
        let fixture: Fixture<C> = Fixture {
            num_primary_peers: 10,
            peer_buffer_size: NZUsize!(2),
            ..Default::default()
        };

        fixture.start(
            |config, context, oracle, mut peers, _, coding_config| async move {
                // Peer 0 leads every view, and peer 3 receives.
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
                        let block = result.expect("the target must reconstruct");
                        assert_eq!(block.commitment(), target_commitment);
                    },
                    _ = context.sleep(Duration::from_secs(5)) => {
                        panic!("the target must reconstruct");
                    },
                }

                // Reconstruction alone leaves the assigned shard unverified. The engine handles the
                // subscription before answering the lookup queued behind it. The leader's chunk for
                // the receiver then verifies the shard.
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
                        panic!("the leader's chunk must verify the assigned shard");
                    },
                }

                // A later notarization leaves the target cached. The record owns the block
                // independently of the bounded rings.
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

                // Peer 1 relays its chunk of three blocks before consensus names them, so the third
                // evicts the first from peer 1's two-message ring.
                let pressure = [2u64, 3, 5].map(|id| {
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

                // Each round then receives the leader's chunk and roots and two relays, one short
                // of the minimum without peer 1's chunk.
                for ((block, round), should_reconstruct) in pressure.iter().zip([false, true, true]) {
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
                                panic!("a retained same-peer chunk must reconstruct its block");
                            },
                        }
                    } else {
                        assert!(
                            peers[receiver_idx].mailbox.get(commitment).await.is_none(),
                            "an evicted same-peer chunk must not reconstruct its block"
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

                // Every relayed chunk was valid, so no peer is blocked.
                assert!(
                    oracle.blocked().await.unwrap().is_empty(),
                    "valid pressure chunks must not block peers"
                );
            },
        );
    }

    /// Notarization does not name a round's leader, so the leader's chunks that follow it wait in
    /// the leader's ring even once its roots bind. Discovery then names the leader, and the chunks
    /// verify the assigned shard.
    #[test_traced]
    fn test_leader_shard_after_notarized_is_buffered_until_discovered() {
        let fixture: Fixture<C> = Fixture {
            num_primary_peers: 10,
            ..Default::default()
        };

        fixture.start(
            |config, context, oracle, mut peers, _, coding_config| async move {
                // Peer 0 leads view 1, and peer 3 receives.
                let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block = encode_block::<B, C, H>(inner, coding_config);
                let commitment = coded_block.commitment();
                let round = Round::new(Epoch::zero(), View::new(1));

                let leader_idx = 0usize;
                let receiver_idx = 3usize;
                let leader = peers[leader_idx].public_key.clone();
                let receiver = peers[receiver_idx].public_key.clone();
                let receiver_index = peers[receiver_idx].index.get() as u16;

                // After a notarization, the leader's chunk and roots arrive. The roots bind, but
                // the chunk waits in the leader's ring.
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
                    "leader chunks must wait in the ring until discovery"
                );

                // Discovery names the leader, and its waiting chunk verifies the assigned shard.
                peers[receiver_idx]
                    .mailbox
                    .discovered(commitment, leader, round);
                select! {
                    _ = assigned_sub => {},
                    _ = context.sleep(Duration::from_secs(5)) => {
                        panic!("the assigned shard must verify after leader discovery");
                    },
                }
                assert!(
                    oracle.blocked().await.unwrap().is_empty(),
                    "valid leader messages must not block peers"
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
                            panic!("the replacement's assigned shard must verify");
                        },
                    }
                }
                context.sleep(config.link.latency * 2).await;

                // The replacement is available on every participant, the other participants do not
                // reconstruct the abandoned candidate, and the leader is not blocked.
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

    /// A ring large enough for every candidate a leader streams in a round lets the third
    /// candidate, once consensus names it, verify its assigned shard and reconstruct.
    #[test_traced]
    fn test_third_candidate_in_a_round_is_delivered() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Participant 0 of 4 runs an unstarted engine with 16-message rings, and peer 1 leads
            // view 1 with three candidates.
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
            engine.peer_buffer_size = NZUsize!(16);
            let coding_config = coding_config_for_participants(peer_keys.len() as u16);
            let round = Round::new(Epoch::zero(), View::new(1));
            let leader = peer_keys[1].clone();
            let candidates: Vec<_> = (1..=3u64)
                .map(|id| {
                    encode_block::<B, C, H>(
                        B::new(Sha256Digest::EMPTY, Height::new(1), id),
                        coding_config,
                    )
                })
                .collect();

            // The leader streams three candidates for the round, and peer 2 relays its chunk of
            // each.
            for candidate in &candidates {
                receive(
                    &mut engine,
                    &mut sender,
                    &leader,
                    assigned(candidate, round, 0),
                );
                receive(
                    &mut engine,
                    &mut sender,
                    &peer_keys[2],
                    relayed(candidate, round, 2),
                );
            }

            // Consensus names the third. Its roots in the leader's ring bind, and the chunks
            // waiting in the rings verify the assigned shard and reconstruct the block.
            let third = candidates[2].commitment();
            let (response, mut verified) = oneshot::channel();
            engine.handle_assigned_shard_verified_subscription(third, response);
            engine.handle_external_proposal(&mut sender, third, leader, round);
            assert!(matches!(verified.try_recv(), Ok(())));
            let reconstructed = finished(&mut engine).await;
            engine.complete(reconstructed);
            assert!(
                engine
                    .records
                    .get(&third)
                    .and_then(CommitmentRecord::block)
                    .is_some()
            );
            assert!(oracle.blocked().await.unwrap().is_empty());
        });
    }

    /// Once discovery names the commitment and its roots bind, chunks are ingested as they
    /// arrive. The leader's chunk verifies the assigned shard, and relayed chunks complete
    /// reconstruction without any further signal.
    #[test_traced]
    fn test_post_leader_shards_processed_immediately() {
        let fixture: Fixture<C> = Fixture {
            num_primary_peers: 10,
            ..Default::default()
        };

        fixture.start(
            |config, context, oracle, mut peers, _, coding_config| async move {
                // Peer 0 leads view 1, and peer 3 receives.
                let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block = encode_block::<B, C, H>(inner, coding_config);
                let commitment = coded_block.commitment();
                let round = Round::new(Epoch::zero(), View::new(1));

                let receiver_idx = 3usize;
                let receiver_pk = peers[receiver_idx].public_key.clone();
                let receiver_index = peers[receiver_idx].index.get() as u16;
                let leader = peers[0].public_key.clone();

                // The receiver subscribes to its assigned shard and discovers the commitment.
                let shard_sub = peers[receiver_idx]
                    .mailbox
                    .subscribe_assigned_shard_verified(commitment);
                peers[receiver_idx]
                    .mailbox
                    .discovered(commitment, leader, round);

                // After discovery, the leader's chunk and roots verify the assigned shard.
                send(
                    &mut peers[0].sender,
                    &receiver_pk,
                    assigned(&coded_block, round, receiver_index),
                );
                select! {
                    _ = shard_sub => {},
                    _ = context.sleep(Duration::from_secs(5)) => {
                        panic!("the leader's chunk must resolve the shard subscription");
                    },
                }

                // Three relayed chunks complete the minimum, and the block reconstructs.
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
                    .expect("the block must reconstruct from chunks sent after discovery");
                assert_eq!(reconstructed.commitment(), commitment);

                // Every chunk was valid, so no peer is blocked.
                assert!(
                    oracle.blocked().await.unwrap().is_empty(),
                    "valid chunks must not block peers"
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

                // Peer 1 sends peer 0 a payload that does not decode, and peer 0 blocks it.
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

                // No engine has named the chunk's commitment, so a chunk that decodes would only
                // wait in its sender's ring. Peer 2 blocks peer 1 when decoding the chunk.
                assert_blocked(&oracle, &peer2, &peers[1].public_key).await;
            },
        );
    }

    /// A repeated chunk received before its commitment is named waits in its sender's ring without
    /// blocking it. Once discovery names the commitment and the leader's roots bind it, one copy
    /// contributes and the other is ignored without blocking.
    #[test_traced]
    fn test_duplicate_buffered_shard_does_not_block_before_leader() {
        let fixture: Fixture<C> = Fixture::default();

        fixture.start(
            |config, context, oracle, mut peers, _, coding_config| async move {
                // Peer 0 leads view 1, and peer 2 receives.
                let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block = encode_block::<B, C, H>(inner, coding_config);
                let round = Round::new(Epoch::zero(), View::new(1));
                let peer1_index = peers[1].index.get() as u16;
                let peer2_pk = peers[2].public_key.clone();

                // Peer 1's chunk arrives before its commitment is named and blocks no one.
                send(
                    &mut peers[1].sender,
                    &peer2_pk,
                    relayed(&coded_block, round, peer1_index),
                );
                context.sleep(config.link.latency * 2).await;
                assert!(
                    oracle.blocked().await.unwrap().is_empty(),
                    "the first copy must not block its sender"
                );

                // A second copy also waits in peer 1's ring without blocking.
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

                // Discovery names the commitment and the leader's roots bind it. The two copies
                // still block no one.
                let leader = peers[0].public_key.clone();
                peers[2]
                    .mailbox
                    .discovered(coded_block.commitment(), leader, round);
                send(
                    &mut peers[0].sender,
                    &peer2_pk,
                    [ShardMessage::from(roots_of(&coded_block, round))],
                );
                context.sleep(config.link.latency * 2).await;
                assert!(
                    oracle.blocked().await.unwrap().is_empty(),
                    "a repeated chunk must not block its sender once ingested"
                );
            },
        );
    }

    /// A leader chunk that fails verification against its claimed root blocks the leader once the
    /// leader's roots bind and include that root.
    #[test_traced]
    fn test_invalid_leader_shard_crypto_blocks_leader() {
        let fixture: Fixture<C> = Fixture::default();

        fixture.start(
            |config, context, oracle, mut peers, _, coding_config| async move {
                // Peer 0 leads view 1 with block 1, and peer 2 receives.
                let inner1 = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block1 = encode_block::<B, C, H>(inner1, coding_config);
                let commitment1 = coded_block1.commitment();
                let inner2 = B::new(Sha256Digest::EMPTY, Height::new(2), 200);
                let coded_block2 = encode_block::<B, C, H>(inner2, coding_config);
                let round = Round::new(Epoch::zero(), View::new(1));

                // The forged chunk carries peer 2's chunk of block 2 under the root of block 1's
                // chunk.
                let peer2_index = peers[2].index.get() as u16;
                let mut wrong = stream_of(&coded_block2, round, peer2_index).remove(0);
                wrong.root = stream_of(&coded_block1, round, peer2_index)[0].root;

                // Peer 2 discovers block 1, and the leader sends the forged chunk and block 1's
                // roots.
                let peer2_pk = peers[2].public_key.clone();
                let leader = peers[0].public_key.clone();
                peers[2].mailbox.discovered(commitment1, leader, round);
                send(
                    &mut peers[0].sender,
                    &peer2_pk,
                    [
                        ShardMessage::Stream(wrong),
                        ShardMessage::from(roots_of(&coded_block1, round)),
                    ],
                );
                context.sleep(config.link.latency * 2).await;

                // The bound roots cover the forged chunk, so it fails its check and blocks the
                // leader.
                assert_blocked(&oracle, &peers[2].public_key, &peers[0].public_key).await;
            },
        );
    }

    /// A participant that races the leader with an invalid chunk at the receiver's assigned index
    /// is blocked without claiming the slot, so the leader's genuine chunk still verifies
    /// afterwards.
    #[test_traced]
    fn test_invalid_assigned_shard_from_non_leader_blocks_only_sender() {
        let fixture: Fixture<C> = Fixture::default();

        fixture.start(
            |config, context, oracle, mut peers, _, coding_config| async move {
                // Peer 0 leads view 1 with block 1, and peer 2 receives.
                let inner1 = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block1 = encode_block::<B, C, H>(inner1, coding_config);
                let commitment1 = coded_block1.commitment();
                let inner2 = B::new(Sha256Digest::EMPTY, Height::new(2), 200);
                let coded_block2 = encode_block::<B, C, H>(inner2, coding_config);
                let round = Round::new(Epoch::zero(), View::new(1));

                // The forged chunk carries peer 2's chunk of block 2 under the root of block 1's
                // chunk.
                let peer2_index = peers[2].index.get() as u16;
                let mut wrong = stream_of(&coded_block2, round, peer2_index).remove(0);
                wrong.root = stream_of(&coded_block1, round, peer2_index)[0].root;

                // Peer 2 subscribes to its assigned shard and discovers block 1, and the leader's
                // roots bind it.
                let peer2_pk = peers[2].public_key.clone();
                let leader = peers[0].public_key.clone();
                let mut shard_sub = peers[2]
                    .mailbox
                    .subscribe_assigned_shard_verified(commitment1);
                peers[2].mailbox.discovered(commitment1, leader, round);
                send(
                    &mut peers[0].sender,
                    &peer2_pk,
                    [ShardMessage::from(roots_of(&coded_block1, round))],
                );
                context.sleep(config.link.latency * 2).await;

                // Peer 1 sends the forged chunk ahead of the leader.
                send(
                    &mut peers[1].sender,
                    &peer2_pk,
                    [ShardMessage::Stream(wrong)],
                );
                context.sleep(config.link.latency * 2).await;

                // The forged chunk fails its check, so peer 2 blocks peer 1 and the subscription
                // stays pending.
                assert_blocked(&oracle, &peers[2].public_key, &peers[1].public_key).await;
                assert!(
                    matches!(shard_sub.try_recv(), Err(TryRecvError::Empty)),
                    "an invalid chunk must not resolve the subscription"
                );

                // The leader's genuine chunk still verifies the assigned shard.
                send(
                    &mut peers[0].sender,
                    &peer2_pk,
                    assigned(&coded_block1, round, peer2_index),
                );
                select! {
                    _ = shard_sub => {},
                    _ = context.sleep(Duration::from_secs(5)) => {
                        panic!("the genuine assigned chunk must verify after the invalid one");
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
                // Peer 0 leads view 1, and peer 3 receives.
                let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block = encode_block::<B, C, H>(inner, coding_config);
                let commitment = coded_block.commitment();
                let round = Round::new(Epoch::zero(), View::new(1));

                // The relabeled chunk is peer 1's chunk under the index of peer 4.
                let peer3_index = peers[3].index.get() as u16;
                let peer1_index = peers[1].index.get() as u16;
                let mut wrong_index = stream_of(&coded_block, round, peer1_index).remove(0);
                wrong_index.index = peers[4].index.get() as u16;

                // Peer 3 discovers the commitment and receives its chunk and the roots from the
                // leader.
                let peer3_pk = peers[3].public_key.clone();
                let leader = peers[0].public_key.clone();
                peers[3].mailbox.discovered(commitment, leader, round);
                send(
                    &mut peers[0].sender,
                    &peer3_pk,
                    assigned(&coded_block, round, peer3_index),
                );
                context.sleep(config.link.latency * 2).await;

                // Peer 1 sends the relabeled chunk. It is neither peer 3's nor peer 1's own, so
                // peer 3 blocks peer 1.
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

    /// A relayed chunk that fails verification against its segment root blocks its sender once
    /// enough shards are available for the batch check to reach it, and not before.
    #[test_traced]
    fn test_invalid_shard_crypto_blocks_peer() {
        let fixture: Fixture<C> = Fixture {
            num_primary_peers: 10,
            ..Default::default()
        };

        fixture.start(
            |config, context, oracle, mut peers, _, coding_config| async move {
                // Peer 0 leads view 1 with block 1, and peer 3 receives.
                let inner1 = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block1 = encode_block::<B, C, H>(inner1, coding_config);
                let commitment1 = coded_block1.commitment();
                let inner2 = B::new(Sha256Digest::EMPTY, Height::new(2), 200);
                let coded_block2 = encode_block::<B, C, H>(inner2, coding_config);
                let round = Round::new(Epoch::zero(), View::new(1));

                // The forged chunk carries peer 1's chunk of block 2 under the root of block 1's
                // chunk.
                let peer1_index = peers[1].index.get() as u16;
                let mut wrong = stream_of(&coded_block2, round, peer1_index).remove(0);
                wrong.root = stream_of(&coded_block1, round, peer1_index)[0].root;

                // Peer 3 discovers block 1 and receives its chunk and the roots from the leader.
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

                // The invalid chunk completes peer 1's shard. The shard waits with the others for
                // the minimum of four.
                send(
                    &mut peers[1].sender,
                    &peer3_pk,
                    [ShardMessage::Stream(wrong)],
                );
                context.sleep(config.link.latency * 2).await;
                assert!(
                    oracle.blocked().await.unwrap().is_empty(),
                    "the batch check must wait for the minimum"
                );

                // Relays from peers 2 and 4 reach the minimum.
                for idx in [2usize, 4] {
                    let index = peers[idx].index.get() as u16;
                    send(
                        &mut peers[idx].sender,
                        &peer3_pk,
                        relayed(&coded_block1, round, index),
                    );
                }
                context.sleep(config.link.latency * 2).await;

                // The batch check rejects peer 1's shard and blocks peer 1.
                assert_blocked(&oracle, &peers[3].public_key, &peers[1].public_key).await;
            },
        );
    }

    /// An invalid chunk counts toward nothing. With the minimum of chunks received but one of
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
                // Peer 0 leads view 1 with block 1, and peer 3 receives.
                let inner1 = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block1 = encode_block::<B, C, H>(inner1, coding_config);
                let commitment1 = coded_block1.commitment();
                let inner2 = B::new(Sha256Digest::EMPTY, Height::new(2), 200);
                let coded_block2 = encode_block::<B, C, H>(inner2, coding_config);
                let round = Round::new(Epoch::zero(), View::new(1));

                let receiver_idx = 3usize;
                let receiver_pk = peers[receiver_idx].public_key.clone();
                let receiver_index = peers[receiver_idx].index.get() as u16;

                // The invalid chunk carries peer 1's chunk of block 2 under the root of block 1's
                // chunk.
                let peer1_index = peers[1].index.get() as u16;
                let mut invalid = stream_of(&coded_block2, round, peer1_index).remove(0);
                invalid.root = stream_of(&coded_block1, round, peer1_index)[0].root;

                // The receiver discovers block 1 and receives its chunk and the roots from the
                // leader.
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

                // The batch check blocks peer 1, and three valid chunks are too few to reconstruct.
                assert_blocked(
                    &oracle,
                    &peers[receiver_idx].public_key,
                    &peers[1].public_key,
                )
                .await;
                assert!(
                    peers[receiver_idx].mailbox.get(commitment1).await.is_none(),
                    "the block must not reconstruct from only 3 valid chunks"
                );

                // Peer 5's valid chunk is the fourth valid one, and the block reconstructs.
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
                    .expect("the block must reconstruct after another valid chunk");
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
                let block = {
                    let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                    encode_block::<B, C, H>(inner, coding_config)
                };
                let other = {
                    let inner = B::new(Sha256Digest::EMPTY, Height::new(2), 200);
                    encode_block::<B, C, H>(inner, coding_config)
                };
                let commitment = block.commitment();
                let round = Round::new(Epoch::zero(), View::new(1));
                let receiver = peers[3].public_key.clone();

                // Before discovery, peer 1 sends its chunk of another block under this block's
                // root, peers 2, 4, 5, and 6 send the four valid chunks the minimum needs, and the
                // leader sends the roots.
                let peer1_index = peers[1].index.get() as u16;
                let mut invalid = stream_of(&other, round, peer1_index).remove(0);
                invalid.root = stream_of(&block, round, peer1_index)[0].root;
                send(
                    &mut peers[1].sender,
                    &receiver,
                    [ShardMessage::Stream(invalid)],
                );
                for sender in [2usize, 4, 5, 6] {
                    let index = peers[sender].index.get() as u16;
                    send(
                        &mut peers[sender].sender,
                        &receiver,
                        relayed(&block, round, index),
                    );
                }
                send(
                    &mut peers[0].sender,
                    &receiver,
                    [ShardMessage::from(roots_of(&block, round))],
                );
                context.sleep(config.link.latency * 2).await;

                // Discovery binds the roots and takes all five shards. The first job checks four
                // of them and finds peer 1's shard invalid, and the leftover shard completes a
                // second job.
                let mut subscription = peers[3].mailbox.subscribe(commitment);
                peers[3]
                    .mailbox
                    .discovered(commitment, peers[0].public_key.clone(), round);
                context.sleep(config.link.latency).await;
                let reconstructed = subscription.try_recv().expect("block reconstructed");
                assert_eq!(reconstructed.commitment(), commitment);
                assert_blocked(&oracle, &receiver, &peers[1].public_key).await;
            },
        );
    }

    /// An invalid chunk that arrives before its commitment is named blocks its sender only once
    /// discovery names the commitment, the leader's roots bind it, and the batch check reaches its
    /// shard.
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

                // Before discovery, peer 1 sends the forged chunk and peers 2 and 4 relay valid
                // chunks of block 1. They wait in the rings without blocking anyone.
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
                    "buffered chunks must not block their senders"
                );

                // Discovery names block 1, and the leader's chunk and roots bind it. The batch
                // check then reaches peer 1's shard and blocks peer 1.
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

    /// A chunk from a peer that participates only in a later epoch is checked against that epoch's
    /// participants once discovery names its commitment and the roots bind it, so its sender is
    /// not blocked.
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

            // The receiver and the future peer register, the future peer links to the receiver, and
            // both are tracked primaries, so the future peer keeps a ring.
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

            // The receiver's engine holds a scheme for each epoch.
            let scheme_epoch0 =
                Scheme::signer(SCHEME_NAMESPACE, epoch0_set.clone(), receiver_key.clone())
                    .expect("signer scheme must be created");
            let scheme_epoch1 =
                Scheme::signer(SCHEME_NAMESPACE, epoch1_set.clone(), receiver_key.clone())
                    .expect("signer scheme must be created");
            let scheme_provider =
                MultiEpochProvider::single(scheme_epoch0).with_epoch(Epoch::new(1), scheme_epoch1);

            let config: Config<_, _, _, _, _, _, Named> = Config {
                scheme_provider,
                blocker: receiver_control.clone(),
                block_codec_config: (),
                strategy: STRATEGY,
                mailbox_size: NZUsize!(1024),
                peer_buffer_size: NZUsize!(64),
                records: NZUsize!(16),
                peer_provider: oracle.manager(),
                elector: None,
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
                "a buffered chunk must not block its sender"
            );

            // Discovery names the commitment, and the future peer relays the roots that bind it.
            let leader = epoch0_pks[1].clone();
            mailbox.discovered(commitment, leader, round);
            send(
                &mut future_peer_sender,
                &receiver_pk,
                [ShardMessage::from(roots_of(&coded_block, round))],
            );
            context.sleep(DEFAULT_LINK.latency * 2).await;

            // The future peer participates in epoch 1, so its ingested chunk must not block it.
            let blocked = oracle.blocked().await.unwrap();
            assert!(
                blocked.is_empty(),
                "future-epoch participant should not be blocked: {blocked:?}"
            );
        });
    }

    /// A participant whose scheme provider churns away once it admits the leader's chunk still
    /// verifies and relays that chunk, so a peer reconstructs from its own chunk and the relay.
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

            // Peer 0 leads, peer 1 relays under the churning provider, and peer 2 receives.
            let leader_idx = 0usize;
            let broadcaster_idx = 1usize;
            let receiver_idx = 2usize;

            let leader_pk = peer_keys[leader_idx].clone();
            let broadcaster_pk = peer_keys[broadcaster_idx].clone();
            let receiver_pk = peer_keys[receiver_idx].clone();

            // Every participant registers, every pair links, and all four are tracked primaries.
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

            // The leader sends raw messages, while the broadcaster and the receiver run engines.
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

            // Discovery, the check of whether to relay the leader's chunk before naming, binding
            // the leader's roots, and ingesting the leader's chunk each look up the epoch's scheme
            // once. Any later lookup churns to None.
            let broadcaster_provider = ChurningProvider::new(broadcaster_scheme, 4);
            let broadcaster_config: Config<_, _, _, _, _, _, Named> = Config {
                scheme_provider: broadcaster_provider,
                blocker: broadcaster_control.clone(),
                block_codec_config: (),
                strategy: STRATEGY,
                mailbox_size: NZUsize!(1024),
                peer_buffer_size: NZUsize!(64),
                records: NZUsize!(16),
                peer_provider: oracle.manager(),
                elector: None,
            };
            let (broadcaster_engine, broadcaster_mailbox) =
                ChurningShardEngine::new(context.child("broadcaster"), broadcaster_config);
            broadcaster_engine.start((broadcaster_sender, broadcaster_receiver));

            // The receiver's provider never churns.
            let receiver_scheme = Scheme::signer(
                SCHEME_NAMESPACE,
                participants.clone(),
                private_keys[receiver_idx].clone(),
            )
            .expect("signer scheme must be created");
            let receiver_config: Config<_, _, _, _, _, _, Named> = Config {
                scheme_provider: MultiEpochProvider::single(receiver_scheme),
                blocker: receiver_control.clone(),
                block_codec_config: (),
                strategy: STRATEGY,
                mailbox_size: NZUsize!(1024),
                peer_buffer_size: NZUsize!(64),
                records: NZUsize!(16),
                peer_provider: oracle.manager(),
                elector: None,
            };
            let (receiver_engine, receiver_mailbox) =
                ShardEngine::new(context.child("receiver"), receiver_config);
            receiver_engine.start((receiver_sender, receiver_receiver));

            let coding_config = coding_config_for_participants(peer_keys.len() as u16);
            let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
            let coded_block = encode_block::<B, C, H>(inner, coding_config);
            let commitment = coded_block.commitment();
            let round = Round::new(Epoch::zero(), View::new(1));

            // Both engines learn the leader before it sends each of them its chunk.
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

            // The receiver reconstructs from its own chunk and the broadcaster's relay.
            let reconstructed = receiver_mailbox.get(commitment).await;
            assert!(
                reconstructed.is_some(),
                "the receiver must reconstruct once the broadcaster verifies and relays its chunk"
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

            // Four participants register, and every pair links.
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
            let config: Config<_, _, _, _, _, _, Named> = Config {
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
                elector: None,
            };
            let (engine, mailbox) =
                Engine::<_, _, _, _, Gated, H, B, P, _, _>::new(context.child("receiver"), config);
            engine.start((sender, receiver));

            let coding_config = coding_config_for_participants(peer_keys.len() as u16);
            let make_block = |id| {
                let inner = B::new(Sha256Digest::EMPTY, Height::new(id), id);
                encode_block::<B, Gated, H>(inner, coding_config)
            };
            let leader = peer_keys[0].clone();

            // The leader delivers the receiver's chunk of A and its roots, and peer 1 relays its
            // own chunk. Together they start a job whose decode the gate holds.
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

            // Participant 0 runs an unstarted engine that the test drives directly.
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

    /// While a job is in flight, the record still takes shards. The assigned shard verifies and
    /// joins the shards an insufficient job returns, and a repeated relay is ignored.
    #[test_traced]
    fn test_mid_job_shards_merge_with_insufficient_result() {
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

            // Every job hands off to the pool.
            let strategy =
                Explorer::parallel(&Rayon::new(ThreadPoolBuilder::new(NZUsize!(2))).unwrap());
            let (mut engine, mut sender) =
                unstarted(&context, &oracle, &private_keys, 0, NZUsize!(16), strategy).await;
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
            let leader = peer_keys[1].clone();

            // Peer 2's chunk of another block under this block's root.
            let mut forged = stream_of(&other, round, 2).remove(0);
            forged.root = stream_of(&block, round, 2)[0].root;

            // Discovery names peer 1 the leader, and its roots bind the commitment. Peer 2's
            // invalid shard and peer 3's valid shard reach the minimum and start a job.
            engine.handle_external_proposal(&mut sender, commitment, leader.clone(), round);
            receive(
                &mut engine,
                &mut sender,
                &leader,
                [roots_of(&block, round).into()],
            );
            receive(&mut engine, &mut sender, &peer_keys[2], [forged.into()]);
            receive(
                &mut engine,
                &mut sender,
                &peer_keys[3],
                relayed(&block, round, 3),
            );
            assert_eq!(engine.jobs.len(), 1);

            // Before the job's result is applied, the leader delivers the assigned chunk and it
            // verifies, while peer 3's repeated relay is ignored.
            receive(&mut engine, &mut sender, &leader, relayed(&block, round, 0));
            receive(
                &mut engine,
                &mut sender,
                &peer_keys[3],
                relayed(&block, round, 3),
            );
            assert!(oracle.blocked().await.unwrap().is_empty());
            let Some(ReconstructionState::AwaitingQuorum(state)) = engine
                .records
                .get(&commitment)
                .and_then(CommitmentRecord::reconstruction)
            else {
                panic!("record must await quorum");
            };
            assert!(state.common.assigned_shard_verified);
            assert_eq!(state.checked_shards.len(), 1);
            assert!(state.pending_shards.is_empty());
            assert!(state.job.is_some());

            // The job finds peer 2's shard invalid and returns peer 3's checked shard, which joins
            // the assigned shard. The two reach the minimum and start a job that rebuilds the
            // block.
            let reconstructed = finished(&mut engine).await;
            assert!(matches!(reconstructed.outcome, Outcome::Insufficient(_)));
            engine.complete(reconstructed);
            assert_blocked(&oracle, &peer_keys[0], &peer_keys[2]).await;
            assert_eq!(engine.jobs.len(), 1);
            let reconstructed = finished(&mut engine).await;
            engine.complete(reconstructed);
            let record = engine.records.get(&commitment).expect("record must exist");
            assert_eq!(
                record.block().expect("block must be cached").commitment(),
                commitment
            );
            assert_eq!(oracle.blocked().await.unwrap().len(), 1);
        });
    }

    /// A job's spawn `len` is the encoded size of the checked shard and the pending shards it takes
    /// to reach the minimum. It excludes surplus pending shards.
    #[test_traced]
    fn test_job_len_counts_taken_shards() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (network, oracle) = simulated::Network::<deterministic::Context, P>::new(
                context.child("network"),
                network_config(10),
            );
            network.start();

            // Participant 0's engine records each job's `len`, and each ring holds a whole block's
            // stream. The expected `len` counts the assigned shard and the shards of peers 2
            // through 4.
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
            engine.peer_buffer_size = NZUsize!(64);
            let coding_config = coding_config_for_participants(peer_keys.len() as u16);
            let block = {
                let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                encode_block::<B, SC, H>(inner, coding_config)
            };
            let commitment = block.commitment();
            let round = Round::new(Epoch::zero(), View::new(1));
            assert!(stream_of(&block, round, 0).len() > 1);
            let size = |index: usize| block.shards(&STRATEGY)[index].encode_size();
            let expected = size(0) + size(2) + size(3) + size(4);

            // Discovery names peer 1 the leader. Before its roots arrive, it delivers the assigned
            // chunks and peers 2 through 6 relay their own.
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

            // The roots bind the chunks. The assigned shard and the shards of peers 2 through 4
            // reach the minimum and start a job, and the shards of peers 5 and 6 stay pending.
            receive(
                &mut engine,
                &mut sender,
                &peer_keys[1],
                [roots_of(&block, round).into()],
            );
            let Some(ReconstructionState::AwaitingQuorum(state)) = engine
                .records
                .get(&commitment)
                .and_then(CommitmentRecord::reconstruction)
            else {
                panic!("record must await quorum");
            };
            assert_eq!(state.pending_shards.len(), 2);
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

    /// Delivers `block` to peer `receiver` from peer 0, the leader of the round of `roots`, and
    /// from each of `relayers`.
    fn deliver(
        peers: &mut [Peer],
        receiver: usize,
        block: &CodedBlock<B, C, H>,
        roots: StreamRoots<B, C, H>,
        relayers: &[usize],
    ) {
        // The leader sends the chunks at the receiver's index, then `roots`.
        let recipient = peers[receiver].public_key.clone();
        let round = roots.round;
        let index = peers[receiver].index.get() as u16;
        let messages = relayed(block, round, index)
            .into_iter()
            .chain([roots.into()]);
        send(&mut peers[0].sender, &recipient, messages);

        // Each relayer sends its own chunks.
        for &relayer in relayers {
            let index = peers[relayer].index.get() as u16;
            send(
                &mut peers[relayer].sender,
                &recipient,
                relayed(block, round, index),
            );
        }
    }

    /// A Byzantine leader's roots bind another block's chunks to a commitment that claims a
    /// different digest. Every chunk checks against the roots, but the decoded block fails the
    /// digest check, so the record is removed and its exact-commitment subscription closes while a
    /// digest subscription survives. The honest commitment for the claimed digest then
    /// reconstructs and satisfies the digest subscription.
    #[test_traced]
    fn test_failed_reconstruction_digest_mismatch_then_recovery() {
        let fixture: Fixture<C> = Fixture {
            num_primary_peers: 10,
            ..Default::default()
        };

        fixture.start(
            |config, context, _oracle, mut peers, _, coding_config| async move {
                // Block 1 is the claimed block. Its digest goes in the fake commitment.
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

                // The receiver learns the fake commitment and subscribes to it and to block 1's
                // digest.
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

                // The leader binds block 2's chunks to the fake commitment, and three relays reach
                // the minimum of four chunks.
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

                // The decoded block fails the digest check, so the fake commitment yields no block.
                assert!(
                    peers[receiver_idx]
                        .mailbox
                        .get(fake_commitment)
                        .await
                        .is_none(),
                    "block should not be available after DigestMismatch"
                );

                // The failure closes the subscription to the fake commitment, while the digest
                // subscription stays open for another commitment with that digest.
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

                // Block 1 reconstructs and satisfies the digest subscription.
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

    /// A Byzantine leader's roots bind a block's chunks to a commitment whose digest, coding root,
    /// and config match but whose context digest does not. The decoded block fails the context
    /// check, so the commitment stays unresolved and its subscription closes. The real commitment
    /// then reconstructs.
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

                // The fake commitment differs from the real one only in its context digest.
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

                // The receiver learns the fake commitment and subscribes to it.
                let receiver_idx = 3usize;
                let leader = peers[0].public_key.clone();
                let round = Round::new(Epoch::zero(), View::new(1));

                peers[receiver_idx]
                    .mailbox
                    .discovered(fake_commitment, leader.clone(), round);
                let mut block_sub = peers[receiver_idx].mailbox.subscribe(fake_commitment);

                // The leader binds the block's chunks to the fake commitment, and three relays
                // reach the minimum of four chunks.
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

                // The decoded block fails the context check, so no block is available and the
                // subscription closes.
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

    /// A leader that equivocates within a round splits the committee between two commitments. The
    /// receiver gets its chunk of B first, then reconstructs A from its chunk of A, A's roots, and
    /// relays from the peers that got A. B's roots then bind B, and relays from the peers that got
    /// B still reconstruct the certifiable B. The leader is not blocked, since a leader that
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

                // The leader sends the receiver its chunk of B, then its chunk of A and A's roots.
                // Peers 1, 2, 4, and 5 relay A.
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

                // B's roots bind B, and peers 6 through 9 relay B.
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

                // The certifiable B reconstructs.
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

                // The leader's chunks of two commitments in one round do not block it.
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

    /// A leader that sends a receiver a chunk at an index that is neither the receiver's nor its
    /// own is blocked once the leader's roots bind the chunk's root.
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

                let receiver_idx = 3usize;
                let receiver_pk = peers[receiver_idx].public_key.clone();
                let leader_idx = 0usize;
                let leader_pk = peers[leader_idx].public_key.clone();
                let round = Round::new(Epoch::zero(), View::new(1));

                // The receiver learns the leader.
                peers[receiver_idx].mailbox.discovered(
                    tracked_commitment,
                    leader_pk.clone(),
                    round,
                );

                // The leader sends the receiver the roots and then the chunk at peer 1's index.
                let unrelated_index = peers[1].index.get() as u16;
                send(
                    &mut peers[leader_idx].sender,
                    &receiver_pk,
                    [ShardMessage::from(roots_of(&tracked_block, round))],
                );
                send(
                    &mut peers[leader_idx].sender,
                    &receiver_pk,
                    relayed(&tracked_block, round, unrelated_index),
                );
                context.sleep(config.link.latency * 2).await;

                // The chunk blocks the leader.
                assert_blocked(&oracle, &peers[receiver_idx].public_key, &leader_pk).await;
            },
        );
    }

    /// Sends what peer 0, leading `round`, sends for `block` when it withholds the chunks of peer
    /// `victim`. Every participant other than the leader and `victim` gets its chunks and the
    /// roots, and `victim` gets only the roots.
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

                // Every participant but the leader learns the leader, and the leader withholds the
                // chunks of peer 1.
                for peer in peers[1..].iter_mut() {
                    peer.mailbox.discovered(commitment, leader.clone(), round);
                }
                withhold_chunks(&mut peers, &coded_block, round, 1);
                context.sleep(config.link.latency * 2).await;

                // The victim reconstructs from the chunks other participants relay.
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

                // Participants 2 through 9 reconstruct the block too.
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

                // Peer 1 subscribes to its assigned shard and to the block before anything arrives.
                let mut shard_sub = peers[1]
                    .mailbox
                    .subscribe_assigned_shard_verified(commitment);
                let block_sub = peers[1].mailbox.subscribe(commitment);

                // Every participant but the leader learns the leader, and the leader withholds the
                // chunks of peer 1.
                for peer in peers[1..].iter_mut() {
                    peer.mailbox.discovered(commitment, leader.clone(), round);
                }
                withhold_chunks(&mut peers, &coded_block, round, 1);
                context.sleep(config.link.latency * 4).await;

                // Peer 1 reconstructs from relayed chunks.
                let reconstructed = block_sub.await.expect("block subscription should resolve");
                assert_eq!(reconstructed.commitment(), commitment);

                // Neither the early nor a late assigned-shard subscription resolves, since peer 1
                // never verified its own shard.
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

    /// A proposal sends each participant the chunk at its index and a non-participant the leader's
    /// own chunk. Every participant and the non-participant verify their assigned shards, the
    /// non-participant reconstructs from relayed chunks, and no peer is blocked.
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

                // The leader proposes, and every other participant and the non-participant learn
                // the leader.
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

                // Every participant and the non-participant verify their assigned shards.
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

                // The non-participant reconstructs from relayed chunks, and no peer is blocked.
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

                // The leader proposes.
                let leader = peers[0].public_key.clone();
                peers[0].mailbox.proposed(round, coded_block.clone());

                // Participants learn the leader so they verify and relay their chunks.
                for peer in peers[1..].iter_mut() {
                    peer.mailbox.discovered(commitment, leader.clone(), round);
                }
                context.sleep(config.link.latency).await;

                // The non-participant learns the leader while chunks are already propagating, and
                // reconstructs from the chunks it buffered and those still arriving.
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

                // No peer is blocked.
                let blocked = oracle.blocked().await.unwrap();
                assert!(
                    blocked.is_empty(),
                    "no peer should be blocked in non-participant reconstruction test"
                );
            },
        );
    }

    /// A non-participant's assigned shard is the leader's own. Chunks the leader sends before
    /// discovery names it contribute that shard as any sender's would, and discovery does not
    /// count them a second time as the assigned shard, so the block still reconstructs.
    #[test_traced]
    fn test_non_participant_counts_the_leaders_shard_once() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (network, oracle) = simulated::Network::<deterministic::Context, P>::new(
                context.child("network"),
                network_config(4),
            );
            network.start();

            // This node's engine runs a verifier scheme, so it is a non-participant whose assigned
            // shard is the leader's.
            let mut private_keys: Vec<PrivateKey> = (0..4).map(PrivateKey::from_seed).collect();
            private_keys.sort_by_key(|key| key.public_key());
            let peer_keys: Vec<P> = private_keys.iter().map(|key| key.public_key()).collect();
            let participants: Set<P> = Set::from_iter_dedup(peer_keys.clone());
            let (mut engine, mut sender) =
                unstarted(&context, &oracle, &private_keys, 0, NZUsize!(16), STRATEGY).await;
            engine.scheme_provider = MultiEpochProvider::single(Scheme::verifier(
                SCHEME_NAMESPACE,
                participants.clone(),
            ));
            let coding_config = coding_config_for_participants(participants.len() as u16);
            let block = encode_block::<B, C, H>(
                B::new(Sha256Digest::EMPTY, Height::new(1), 100),
                coding_config,
            );
            let commitment = block.commitment();
            let round = Round::new(Epoch::zero(), View::new(1));
            let leader = peer_keys[1].clone();

            // A notarization creates a leaderless record. The leader's roots bind it, and its own
            // chunk contributes its shard as any sender's would.
            engine.handle_notarized_commitment(&mut sender, commitment, round);
            receive(
                &mut engine,
                &mut sender,
                &leader,
                assigned(&block, round, 1),
            );
            let Some(ReconstructionState::AwaitingQuorum(state)) = engine
                .records
                .get(&commitment)
                .and_then(CommitmentRecord::reconstruction)
            else {
                panic!("record must await quorum");
            };
            assert_eq!(state.pending_shards.len(), 1);

            // Discovery makes the leader's chunk this node's assigned chunk. Its shard has already
            // contributed, so no second copy joins it and no job starts.
            engine.handle_external_proposal(&mut sender, commitment, leader, round);
            assert!(engine.jobs.is_empty());

            // Peer 2's relayed shard completes the minimum, and the block reconstructs.
            receive(
                &mut engine,
                &mut sender,
                &peer_keys[2],
                relayed(&block, round, 2),
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
            assert!(oracle.blocked().await.unwrap().is_empty());
        });
    }

    /// Delivers a proposal from peer 0 to peer 1 and checks that peer 1 verifies its assigned shard
    /// and relays its chunk. Peer 1 runs a member scheme that reports its membership but cannot
    /// sign.
    ///
    /// When `buffered` is set, the chunk arrives before peer 1 discovers the leader. Peer 3 cannot
    /// reach peer 2, so with four participants (a minimum of two shards) peer 2 reconstructs only
    /// if the member relays its verified chunk.
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

            // The receiver and the leader register, the leader links to the receiver, and set 0
            // tracks every participant.
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

            // The receiver's engine learns leaders only from consensus.
            let scheme = Scheme::signer(
                SCHEME_NAMESPACE,
                participants.clone(),
                private_keys[receiver_idx].clone(),
            )
            .expect("signer scheme must be created");
            let config: Config<_, _, _, _, _, _, Named> = Config {
                scheme_provider: MultiEpochProvider::single(scheme),
                blocker: receiver_control.clone(),
                block_codec_config: (),
                strategy: STRATEGY,
                mailbox_size: NZUsize!(1024),
                peer_buffer_size: NZUsize!(64),
                records: NZUsize!(16),
                peer_provider: oracle.manager(),
                elector: None,
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

            // Messages from the leader arrive before consensus names it, wait in its ring, and are
            // ingested once it is discovered.
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
                "messages from a leader outside the latest set but still tracked must be buffered"
            );

            // The leader sends the messages of view 2. Tracking another set without the leader then
            // ages set 0 out of the window, so the leader leaves every tracked set and its ring is
            // evicted with those messages.
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
    /// claiming a config with a minimum of one shard, for rounds whose leader is never known. The
    /// peer's ring retains exactly the most recent `peer_buffer_size` of them.
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

            // With a minimum of one shard, a chunk of the largest coded payload carries the whole
            // payload and is wider than any chunk an honest committee codes. Each message is
            // decoded as the background receiver decodes it, and the peer sends twice as many as
            // its ring holds.
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

            // The ring holds exactly the last `slots` chunks.
            let queue = engine
                .peer_buffers
                .get(&peer)
                .expect("the peer must buffer chunks");
            assert_eq!(queue.len(), slots);
            let retained: Vec<_> = queue.iter().map(|message| message.round().view()).collect();
            let latest: Vec<_> = views.skip(slots).map(View::new).collect();
            assert_eq!(retained, latest);
        });
    }

    /// A peer's ring is kept only while it is a primary of a tracked peer set. Messages from
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

            // The receiver's engine tracks only the sender as a primary.
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
            let config: Config<_, _, _, _, _, _, Named> = Config {
                scheme_provider: MultiEpochProvider::single(scheme),
                blocker: receiver_control,
                block_codec_config: (),
                strategy: STRATEGY,
                mailbox_size: NZUsize!(16),
                peer_buffer_size: NZUsize!(4),
                records: NZUsize!(16),
                peer_provider: oracle.manager(),
                elector: None,
            };
            let (mut engine, _mailbox) = ShardEngine::new(context.child("engine"), config);
            engine.update_primary_peers(Set::from_iter_dedup([sender_pk.clone()]));

            // No round has a known leader, so a relayed chunk only joins its sender's ring, and
            // only a tracked primary has one.
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
                "a tracked primary's chunk must be buffered"
            );
            assert!(
                !engine.peer_buffers.contains_key(&untracked_pk),
                "a peer outside every tracked primary set must have no buffer"
            );

            // Once the sender leaves every tracked set, its ring is dropped.
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

            // The receiver and the leader register, the leader links to the receiver, and epoch 0's
            // set is tracked.
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

            // The receiver's engine holds a scheme for each epoch.
            let scheme_epoch0 =
                Scheme::signer(SCHEME_NAMESPACE, epoch0_set.clone(), receiver_key.clone())
                    .expect("epoch 0 signer scheme must be created");
            let scheme_epoch1 =
                Scheme::signer(SCHEME_NAMESPACE, epoch1_set.clone(), receiver_key.clone())
                    .expect("epoch 1 signer scheme must be created");
            let config: Config<_, _, _, _, _, _, Named> = Config {
                scheme_provider: MultiEpochProvider::single(scheme_epoch0)
                    .with_epoch(Epoch::new(1), scheme_epoch1),
                blocker: receiver_control.clone(),
                block_codec_config: (),
                strategy: STRATEGY,
                mailbox_size: NZUsize!(1024),
                peer_buffer_size: NZUsize!(64),
                records: NZUsize!(16),
                peer_provider: oracle.manager(),
                elector: None,
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

            // The leader sends the receiver its chunks and roots before it is discovered, and the
            // cutover to epoch 1's set follows.
            send(
                &mut leader_sender,
                &receiver_pk,
                assigned(&coded_block, round, receiver_index),
            );
            context.sleep(DEFAULT_LINK.latency * 2).await;

            oracle.manager().track(1, epoch1_set);
            context.sleep(Duration::from_millis(10)).await;

            // Discovery ingests the buffered messages and verifies the assigned shard.
            let mut shard_sub = mailbox.subscribe_assigned_shard_verified(commitment);
            mailbox.discovered(commitment, leader_pk, round);
            context.sleep(DEFAULT_LINK.latency * 2).await;
            assert!(
                matches!(shard_sub.try_recv(), Ok(())),
                "old-epoch messages from a still-tracked primary must be ingested after cutover"
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

            // The receiver, the leader, and the relayers register, and the leader and the relayers
            // link to the receiver.
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

            // The receiver's engine learns leaders only from consensus.
            let scheme = Scheme::signer(
                SCHEME_NAMESPACE,
                participants.clone(),
                private_keys[receiver_idx].clone(),
            )
            .expect("signer scheme must be created");
            let config: Config<_, _, _, _, _, _, Named> = Config {
                scheme_provider: MultiEpochProvider::single(scheme),
                blocker: receiver_control.clone(),
                block_codec_config: (),
                strategy: STRATEGY,
                mailbox_size: NZUsize!(1024),
                peer_buffer_size: NZUsize!(64),
                records: NZUsize!(16),
                peer_provider: oracle.manager(),
                elector: None,
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

            // Before consensus names the leader, the leader sends only its roots, and the four
            // relayers send their own chunks, enough for the minimum of four shards.
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

            // Discovery reconstructs the block from the buffered messages, but the assigned shard
            // stays unverified and no peer is blocked.
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
                "valid buffered messages must not block peers"
            );
        });
    }

    /// A participant that reconstructs from relayed chunks before the leader's chunk for its index
    /// arrives still accepts that late chunk once the block is cached. The chunk verifies the
    /// assigned shard and is relayed so slower peers can reach the minimum, while a repeated chunk
    /// from another peer is ignored without blocking its sender.
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

                // Reads the victim's count of relayed chunks from the metrics.
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
                        panic!("the victim must reconstruct the block from relayed chunks");
                    },
                }

                // The victim's assigned shard is still unverified, and it has relayed no chunks.
                let mut shard_sub = peers[victim_idx]
                    .mailbox
                    .subscribe_assigned_shard_verified(commitment);
                context.sleep(config.link.latency).await;
                assert!(
                    matches!(shard_sub.try_recv(), Err(TryRecvError::Empty)),
                    "shard subscription must not resolve before own chunk is verified"
                );
                assert_eq!(victim_forwarded(context.encode()), vec![0]);

                // The leader's late chunk verifies the assigned shard and is relayed once.
                send(
                    &mut peers[leader_idx].sender,
                    &victim,
                    relayed(&coded_block, round, victim_index),
                );
                select! {
                    _ = shard_sub => {},
                    _ = context.sleep(Duration::from_secs(5)) => {
                        panic!("the late leader chunk must resolve the shard subscription");
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
                    "valid chunks must not block peers"
                );
            },
        );
    }

    /// An unstarted [`SC`] engine for participant 0 of four and two blocks for the same round.
    /// Peer 2 observes the engine's sends.
    struct ChunkSetup<L: ElectorConfig<Scheme> = Named> {
        engine: ShardEngine<SC, Sequential, L>,
        sender: EngineSender<SC>,
        peer_keys: Vec<P>,
        observer: simulated::Receiver<P>,
        block: CodedBlock<B, SC, H>,
        other: CodedBlock<B, SC, H>,
        round: Round,
    }

    /// Builds a [`ChunkSetup`] whose test block spans several segments.
    async fn chunk_setup(context: &deterministic::Context, oracle: &O) -> ChunkSetup {
        chunk_setup_electing(context, oracle, None).await
    }

    /// Builds a [`ChunkSetup`] whose engine holds `elector`, as [`chunk_setup`] does.
    async fn chunk_setup_electing<L: ElectorConfig<Scheme>>(
        context: &deterministic::Context,
        oracle: &O,
        elector: Option<L>,
    ) -> ChunkSetup<L> {
        let mut private_keys: Vec<PrivateKey> = (0..4).map(PrivateKey::from_seed).collect();
        private_keys.sort_by_key(|key| key.public_key());
        let peer_keys: Vec<P> = private_keys.iter().map(|key| key.public_key()).collect();
        let participants: Set<P> = Set::from_iter_dedup(peer_keys.clone());
        let (mut engine, sender) = unstarted_electing::<SC, _, _>(
            context,
            oracle,
            &private_keys,
            0,
            NZUsize!(16),
            STRATEGY,
            elector,
        )
        .await;

        // Each peer's ring holds a whole block's stream, so a round can wait in full for its
        // leader. Peer 2 registers, and a link from participant 0 lets it observe what the engine
        // sends.
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

        // The setup holds two blocks for view 1, and the first spans several segments.
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

    /// Once consensus names the commitment and the leader's roots bind it, the roots are relayed,
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

            // Discovery and the leader's roots bind the commitment, and the roots are relayed.
            engine.handle_external_proposal(&mut sender, commitment, leader.clone(), round);
            receive(
                &mut engine,
                &mut sender,
                &leader,
                [roots_of(&block, round).into()],
            );
            let relayed = next_message::<SC>(&context, &mut observer).await;
            assert!(relayed == Some(ShardMessage::Roots(roots_of(&block, round))));
            assert_eq!(engine.sent, 1);

            // Each assigned chunk is relayed as it verifies, and the shard verifies with the last.
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
            assert_eq!(engine.sent, assigned.len() as u64 + 1);

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

    /// A chunk that fails its check against the root it claims blocks its sender only once
    /// consensus names a commitment and roots that hash to it bind that root. Well-formed chunks
    /// of another payload in the same round block no one.
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
            let commitment = block.commitment();
            let leader = peer_keys[1].clone();
            let honest = stream_of(&block, round, 0);
            let foreign = stream_of(&other, round, 0);
            let segment = (0..honest.len())
                .find(|&segment| honest[segment].root != foreign[segment].root)
                .expect("the blocks must differ in some segment");

            // The leader's chunk at the local index carries the other payload's data under this
            // block's root, and peer 2 relays its own chunks of the other payload.
            let forged = StreamChunk {
                chunk: foreign[segment].chunk.clone(),
                ..honest[segment].clone()
            };
            receive(&mut engine, &mut sender, &leader, [forged.into()]);
            receive(
                &mut engine,
                &mut sender,
                &peer_keys[2],
                relayed(&other, round, 2),
            );
            assert!(oracle.blocked().await.unwrap().is_empty());

            // Naming the commitment classifies nothing until its roots bind.
            engine.handle_external_proposal(&mut sender, commitment, leader.clone(), round);
            assert!(oracle.blocked().await.unwrap().is_empty());
            receive(
                &mut engine,
                &mut sender,
                &leader,
                [roots_of(&block, round).into()],
            );
            assert_blocked(&oracle, &peer_keys[0], &leader).await;
            assert_eq!(oracle.blocked().await.unwrap().len(), 1);
        });
    }

    /// Roots that claim a commitment and do not hash to its coding root wait in their sender's
    /// ring until consensus names that commitment, and then block their sender. They never bind,
    /// so roots that do hash to it still bind afterwards.
    #[test_traced]
    fn test_mismatched_roots_block_their_sender_once_the_commitment_is_named() {
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
            let commitment = block.commitment();
            let leader = peer_keys[1].clone();
            let mut mismatched = roots_of(&block, round);
            mismatched.roots = roots_of(&other, round).roots;
            let bound = |engine: &ShardEngine<SC>| {
                engine
                    .records
                    .get(&commitment)
                    .and_then(CommitmentRecord::reconstruction)
                    .and_then(ReconstructionState::roots)
                    .is_some()
            };

            // Peer 3's mismatched roots wait in its ring until discovery names the commitment.
            receive(
                &mut engine,
                &mut sender,
                &peer_keys[3],
                [mismatched.clone().into()],
            );
            assert!(oracle.blocked().await.unwrap().is_empty());
            engine.handle_external_proposal(&mut sender, commitment, leader.clone(), round);
            assert_blocked(&oracle, &peer_keys[0], &peer_keys[3]).await;
            assert!(!bound(&engine));

            // Once the commitment is named, mismatched roots from the leader block it on arrival.
            receive(&mut engine, &mut sender, &leader, [mismatched.into()]);
            assert_blocked(&oracle, &peer_keys[0], &leader).await;
            assert!(!bound(&engine));

            // Roots that peer 2 relays and that hash to the commitment bind it.
            receive(
                &mut engine,
                &mut sender,
                &peer_keys[2],
                [roots_of(&block, round).into()],
            );
            assert!(bound(&engine));
            assert_eq!(oracle.blocked().await.unwrap().len(), 2);
        });
    }

    /// Roots bind a named commitment whether they arrive before consensus names it or after, and
    /// whether the leader sends them or another participant relays them. Each commitment's roots
    /// are relayed once, when they bind.
    #[test_traced]
    fn test_roots_bind_the_named_commitment_in_either_order() {
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
            let later = Round::new(Epoch::zero(), View::new(2));

            // The leader's roots for the block wait in its ring until discovery names the block.
            receive(
                &mut engine,
                &mut sender,
                &leader,
                [roots_of(&block, round).into()],
            );
            assert!(next_message::<SC>(&context, &mut observer).await.is_none());
            engine.handle_external_proposal(&mut sender, block.commitment(), leader.clone(), round);
            let relay = next_message::<SC>(&context, &mut observer).await;
            assert!(relay == Some(ShardMessage::Roots(roots_of(&block, round))));

            // A notarization names the other block in a later round before peer 3 relays its
            // roots, so they bind on arrival.
            engine.handle_notarized_commitment(&mut sender, other.commitment(), later);
            assert!(next_message::<SC>(&context, &mut observer).await.is_none());
            receive(
                &mut engine,
                &mut sender,
                &peer_keys[3],
                [roots_of(&other, later).into()],
            );
            let relay = next_message::<SC>(&context, &mut observer).await;
            assert!(relay == Some(ShardMessage::Roots(roots_of(&other, later))));

            // Repeated roots are not relayed again.
            receive(
                &mut engine,
                &mut sender,
                &leader,
                [roots_of(&block, round).into()],
            );
            receive(
                &mut engine,
                &mut sender,
                &peer_keys[2],
                [roots_of(&other, later).into()],
            );
            assert!(next_message::<SC>(&context, &mut observer).await.is_none());
            for (commitment, roots) in [
                (block.commitment(), roots_of(&block, round).roots),
                (other.commitment(), roots_of(&other, later).roots),
            ] {
                let bound = engine
                    .records
                    .get(&commitment)
                    .and_then(CommitmentRecord::reconstruction)
                    .and_then(ReconstructionState::roots);
                assert_eq!(bound, Some(roots.as_slice()));
            }
            assert!(oracle.blocked().await.unwrap().is_empty());
        });
    }

    /// Roots bind only the commitment they claim. The leader's roots for a second candidate in the
    /// round leave the named commitment's roots in place, and once consensus names the second
    /// candidate too, each commitment holds its own roots and the first still reconstructs.
    #[test_traced]
    fn test_roots_for_another_commitment_do_not_unbind_a_named_one() {
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
            let commitment = block.commitment();
            let leader = peer_keys[1].clone();
            let bound = |engine: &ShardEngine<SC>, commitment: Commitment<B, SC, H>| {
                engine
                    .records
                    .get(&commitment)
                    .and_then(CommitmentRecord::reconstruction)
                    .and_then(ReconstructionState::roots)
                    .map(<[_]>::to_vec)
            };
            let roots = roots_of(&block, round).roots;

            // Discovery names the block, and the leader's roots bind it.
            engine.handle_external_proposal(&mut sender, commitment, leader.clone(), round);
            receive(
                &mut engine,
                &mut sender,
                &leader,
                [roots_of(&block, round).into()],
            );
            assert_eq!(bound(&engine, commitment), Some(roots.clone()));

            // The leader's roots for the other candidate leave the named commitment bound.
            receive(
                &mut engine,
                &mut sender,
                &leader,
                [roots_of(&other, round).into()],
            );
            assert_eq!(bound(&engine, commitment), Some(roots.clone()));
            assert!(!engine.records.contains_key(&other.commitment()));

            // Once consensus names the other candidate, it binds its own roots.
            engine.handle_notarized_commitment(&mut sender, other.commitment(), round);
            assert_eq!(
                bound(&engine, other.commitment()),
                Some(roots_of(&other, round).roots)
            );
            assert_eq!(bound(&engine, commitment), Some(roots));

            // The first commitment still reconstructs from its own chunks.
            for index in [2u16, 3] {
                receive(
                    &mut engine,
                    &mut sender,
                    &peer_keys[usize::from(index)],
                    relayed(&block, round, index),
                );
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

    /// Two candidates whose roots share segment roots both reconstruct. Chunks of the shared
    /// segments stay in their senders' rings after one candidate takes them, so the other needs
    /// only the chunks of the segments where it differs.
    #[test_traced]
    fn test_commitments_sharing_segment_roots_both_reconstruct() {
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
            let block_roots = roots_of(&block, round).roots;
            let other_roots = roots_of(&other, round).roots;
            let differing: Vec<usize> = (0..block_roots.len())
                .filter(|&segment| block_roots[segment] != other_roots[segment])
                .collect();
            assert!(
                !differing.is_empty() && differing.len() < block_roots.len(),
                "the blocks must share some segments and differ in others"
            );

            // Consensus names both candidates of the round, and the leader's roots bind them.
            engine.handle_external_proposal(&mut sender, block.commitment(), leader.clone(), round);
            engine.handle_notarized_commitment(&mut sender, other.commitment(), round);
            receive(
                &mut engine,
                &mut sender,
                &leader,
                [
                    roots_of(&block, round).into(),
                    roots_of(&other, round).into(),
                ],
            );

            // Peers 2 and 3 relay every chunk of their own shards, enough to reconstruct the block.
            for index in [2u16, 3] {
                receive(
                    &mut engine,
                    &mut sender,
                    &peer_keys[usize::from(index)],
                    relayed(&block, round, index),
                );
            }
            let reconstructed = finished(&mut engine).await;
            engine.complete(reconstructed);
            assert!(
                engine
                    .records
                    .get(&block.commitment())
                    .and_then(CommitmentRecord::block)
                    .is_some()
            );
            assert!(engine.jobs.is_empty());

            // They then relay only the other candidate's chunks of the segments where it differs.
            for index in [2u16, 3] {
                let chunks = stream_of(&other, round, index);
                receive(
                    &mut engine,
                    &mut sender,
                    &peer_keys[usize::from(index)],
                    differing
                        .iter()
                        .map(|&segment| ShardMessage::from(chunks[segment].clone())),
                );
            }
            let reconstructed = finished(&mut engine).await;
            engine.complete(reconstructed);
            assert!(
                engine
                    .records
                    .get(&other.commitment())
                    .and_then(CommitmentRecord::block)
                    .is_some()
            );
            assert!(oracle.blocked().await.unwrap().is_empty());
        });
    }

    /// A chunk counts only toward named commitments of the epoch its round claims. A member of
    /// the next epoch whose valid chunk shares a segment root with a retained record of the
    /// current epoch is not judged against the current epoch's participants and is not blocked,
    /// and a sender's shard for the record is assembled only from its chunks of that epoch.
    #[test_traced]
    fn test_chunks_match_only_records_of_their_epoch() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (network, oracle) = simulated::Network::<deterministic::Context, P>::new(
                context.child("network"),
                simulated::Config {
                    tracked_peer_sets: NZUsize!(2),
                    ..network_config(5)
                },
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

            // Epoch 1 replaces peer 3 with a newcomer, and the members of both epochs keep rings.
            let mut private_keys: Vec<PrivateKey> = (0..4).map(PrivateKey::from_seed).collect();
            private_keys.sort_by_key(|key| key.public_key());
            let newcomer = PrivateKey::from_seed(4).public_key();
            let next_set: Set<P> =
                Set::from_iter_dedup(peer_keys[..3].iter().cloned().chain([newcomer.clone()]));
            let next_scheme =
                Scheme::signer(SCHEME_NAMESPACE, next_set.clone(), private_keys[0].clone())
                    .expect("signer scheme must be created");
            engine.scheme_provider = engine
                .scheme_provider
                .clone()
                .with_epoch(Epoch::new(1), next_scheme);
            oracle.manager().track(1, next_set.clone());
            engine.update_primary_peers(Set::from_iter_dedup(
                peer_keys.iter().cloned().chain([newcomer.clone()]),
            ));

            // Epoch 0 names the block, and the leader's roots bind it.
            let leader = peer_keys[1].clone();
            engine.handle_external_proposal(&mut sender, block.commitment(), leader.clone(), round);
            receive(
                &mut engine,
                &mut sender,
                &leader,
                [roots_of(&block, round).into()],
            );

            // The newcomer's own epoch 1 chunk of the other block is valid and has the same root
            // as the block's chunk of that segment.
            let next = Round::new(Epoch::new(1), View::new(1));
            let index = next_set
                .index(&newcomer)
                .expect("the newcomer must be an epoch 1 participant")
                .get() as u16;
            let roots = roots_of(&block, round).roots;
            let chunk = stream_of(&other, next, index)
                .into_iter()
                .find(|chunk| roots[usize::from(chunk.segment)] == chunk.root)
                .expect("the blocks must share a segment");
            assert!(
                SC::check_chunk(
                    &chunk.config,
                    &chunk.root,
                    chunk.index,
                    chunk.segment,
                    &chunk.chunk
                )
                .is_ok()
            );

            // The chunk does not count toward the epoch 0 record, so the newcomer is not blocked.
            receive(&mut engine, &mut sender, &newcomer, [chunk.into()]);
            assert!(oracle.blocked().await.unwrap().is_empty());

            // Peer 2 first sends a chunk that claims epoch 1 and carries the other block's data
            // under the block's root of a segment where the blocks differ, then its own epoch 0
            // chunks of the block.
            let other_roots = roots_of(&other, round).roots;
            let segment = (0..roots.len())
                .find(|&segment| roots[segment] != other_roots[segment])
                .expect("the blocks must differ in some segment");
            let own = stream_of(&block, round, 2);
            let foreign = StreamChunk {
                round: next,
                chunk: stream_of(&other, round, 2)[segment].chunk.clone(),
                ..own[segment].clone()
            };
            receive(&mut engine, &mut sender, &peer_keys[2], [foreign.into()]);
            receive(
                &mut engine,
                &mut sender,
                &peer_keys[2],
                own.into_iter().map(ShardMessage::from),
            );

            // Peer 2's shard comes only from its epoch 0 chunks, so with peer 3's it rebuilds the
            // block and no one is blocked.
            receive(
                &mut engine,
                &mut sender,
                &peer_keys[3],
                relayed(&block, round, 3),
            );
            let reconstructed = finished(&mut engine).await;
            engine.complete(reconstructed);
            assert!(
                engine
                    .records
                    .get(&block.commitment())
                    .and_then(CommitmentRecord::block)
                    .is_some()
            );
            assert!(oracle.blocked().await.unwrap().is_empty());
        });
    }

    /// Chunks and roots join only their sender's ring until consensus names their commitment,
    /// whatever round they claim. A peer streaming rounds far ahead before any consensus signal
    /// creates no record, displaces no other sender's messages, and blocks no one, and the named
    /// round then delivers its block.
    #[test_traced]
    fn test_far_future_and_unsignaled_chunks_do_not_displace_a_named_round() {
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
            let spammer = peer_keys[3].clone();
            let segments = stream_of(&block, round, 0).len();

            // Before any consensus signal, the leader streams the local shard and its roots, and
            // peer 2 relays its own chunks.
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

            // Peer 3 streams another block's chunks and roots for rounds far ahead, more than its
            // ring holds.
            let far = encode_block::<B, SC, H>(
                B::new(Sha256::hash(&[b"far"]), Height::new(1_000), 1_000),
                coding_config_for_participants(4),
            );
            for view in 1_000..1_000 + engine.peer_buffer_size.get() as u64 {
                let far_round = Round::new(Epoch::zero(), View::new(view));
                receive(
                    &mut engine,
                    &mut sender,
                    &spammer,
                    assigned(&far, far_round, 0),
                );
            }
            assert!(engine.records.is_empty());
            assert_eq!(
                engine.peer_buffers[&spammer].len(),
                engine.peer_buffer_size.get()
            );
            assert_eq!(buffered(&engine, &leader, round), segments + 1);
            assert_eq!(buffered(&engine, &peer_keys[2], round), segments);

            // Discovery binds the leader's roots, the assigned shard verifies from the leader's
            // ring, and peer 2's shard completes the minimum.
            let (response, mut verified) = oneshot::channel();
            engine.handle_assigned_shard_verified_subscription(commitment, response);
            engine.handle_external_proposal(&mut sender, commitment, leader, round);
            assert!(matches!(verified.try_recv(), Ok(())));
            let reconstructed = finished(&mut engine).await;
            engine.complete(reconstructed);
            assert!(
                engine
                    .records
                    .get(&commitment)
                    .and_then(CommitmentRecord::block)
                    .is_some()
            );
            assert_eq!(engine.records.len(), 1);
            assert!(oracle.blocked().await.unwrap().is_empty());
        });
    }

    /// A ring too small to hold a sender's chunks of a round loses the ones that arrive before the
    /// roots bind, so the node cannot verify its assigned shard from the stream, and no sender is
    /// blocked for the loss. Once the roots bind, the record keeps each chunk as it arrives, so
    /// relays that pass through one-message rings still reconstruct the block.
    #[test_traced]
    fn test_ring_too_small_for_a_round_keeps_chunks_after_binding() {
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
            engine.peer_buffer_size = NZUsize!(1);
            let commitment = block.commitment();
            let leader = peer_keys[1].clone();

            // Each sender's ring keeps only its last message, so the rings hold the leader's roots
            // and the last chunk each of peers 2 and 3 relays.
            receive(
                &mut engine,
                &mut sender,
                &leader,
                assigned(&block, round, 0),
            );
            for index in [2u16, 3] {
                receive(
                    &mut engine,
                    &mut sender,
                    &peer_keys[usize::from(index)],
                    relayed(&block, round, index),
                );
            }

            // Discovery binds the roots, but no shard can be completed from the rings.
            let (response, mut verified) = oneshot::channel();
            engine.handle_assigned_shard_verified_subscription(commitment, response);
            engine.handle_external_proposal(&mut sender, commitment, leader, round);
            assert!(
                engine
                    .records
                    .get(&commitment)
                    .and_then(CommitmentRecord::reconstruction)
                    .and_then(ReconstructionState::roots)
                    .is_some()
            );
            assert!(engine.jobs.is_empty());

            // Relays after binding pass through one-message rings, and the record keeps each chunk
            // as it arrives, so the shards of peers 2 and 3 reconstruct the block.
            for index in [2u16, 3] {
                receive(
                    &mut engine,
                    &mut sender,
                    &peer_keys[usize::from(index)],
                    relayed(&block, round, index),
                );
            }
            let reconstructed = finished(&mut engine).await;
            engine.complete(reconstructed);
            assert!(
                engine
                    .records
                    .get(&commitment)
                    .and_then(CommitmentRecord::block)
                    .is_some(),
                "the block must reconstruct from the chunks relayed after binding"
            );

            // The assigned shard stays unverified, and no sender is blocked for the loss.
            assert!(matches!(verified.try_recv(), Err(TryRecvError::Empty)));
            assert!(oracle.blocked().await.unwrap().is_empty());
        });
    }

    /// A record keeps the first chunk of each segment it ingests from a sender, and ignores a later
    /// chunk for the same segment even when it is valid. A sender whose first chunk is forged has
    /// its shard rejected and is blocked, and the block reconstructs without it.
    #[test_traced]
    fn test_sender_shard_keeps_the_first_chunk_of_each_segment() {
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
            let commitment = block.commitment();
            let leader = peer_keys[1].clone();

            // Discovery names peer 1 the leader, and its roots bind the commitment.
            engine.handle_external_proposal(&mut sender, commitment, leader.clone(), round);
            receive(
                &mut engine,
                &mut sender,
                &leader,
                [roots_of(&block, round).into()],
            );

            // Peer 2 first sends its chunk of another block under this block's root for a segment
            // the blocks do not share, then its valid chunk of that segment, and then its valid
            // chunk of every segment.
            let valid = stream_of(&block, round, 2);
            let (segment, forged) = stream_of(&other, round, 2)
                .into_iter()
                .zip(&valid)
                .enumerate()
                .find(|(_, (theirs, ours))| theirs.root != ours.root)
                .map(|(segment, (theirs, ours))| {
                    let forged = StreamChunk {
                        root: ours.root,
                        ..theirs
                    };
                    (segment, forged)
                })
                .expect("the blocks must differ in some segment");
            receive(
                &mut engine,
                &mut sender,
                &peer_keys[2],
                [forged.into(), valid[segment].clone().into()],
            );
            receive(
                &mut engine,
                &mut sender,
                &peer_keys[2],
                valid.into_iter().map(ShardMessage::from),
            );

            // Peer 3's shard brings the shards to the minimum, and the job rejects peer 2's,
            // assembled from the forged chunk, and blocks peer 2.
            receive(
                &mut engine,
                &mut sender,
                &peer_keys[3],
                relayed(&block, round, 3),
            );
            let reconstructed = finished(&mut engine).await;
            assert!(matches!(reconstructed.outcome, Outcome::Insufficient(_)));
            engine.complete(reconstructed);
            assert_blocked(&oracle, &peer_keys[0], &peer_keys[2]).await;

            // The leader's chunks verify the assigned shard, which joins peer 3's shard and
            // reconstructs the block.
            receive(&mut engine, &mut sender, &leader, relayed(&block, round, 0));
            let reconstructed = finished(&mut engine).await;
            engine.complete(reconstructed);
            assert!(
                engine
                    .records
                    .get(&commitment)
                    .and_then(CommitmentRecord::block)
                    .is_some(),
                "the block must reconstruct without peer 2's shard"
            );
            assert_eq!(oracle.blocked().await.unwrap().len(), 1);
        });
    }

    /// Once consensus has signaled a round, a participant relays each chunk at its index from the
    /// leader the elector names for a round within the horizon, as the chunk arrives and before any
    /// roots. Chunks other participants relay are not relayed. Once consensus names the commitment,
    /// the roots bind and the block reconstructs.
    #[test_traced]
    fn test_leader_chunks_relayed_before_roots_once_consensus_signals() {
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

            // Peer 1 leads every round.
            let leader = peer_keys[1].clone();
            elect(&mut engine, 1);
            let next = Round::new(Epoch::zero(), View::new(2));
            let commitment = block.commitment();

            // Consensus notarizes an unrelated block at view 1, and view 2's leader then streams.
            // Each of its chunks is relayed on arrival, while the chunks peers 2 and 3 relay are
            // not.
            engine.handle_notarized_commitment(&mut sender, unrelated().commitment(), round);
            for chunk in stream_of(&block, next, 0) {
                receive(&mut engine, &mut sender, &leader, [chunk.clone().into()]);
                let relayed = next_message::<SC>(&context, &mut observer)
                    .await
                    .expect("the leader's chunk must be relayed on arrival");
                assert!(relayed == ShardMessage::Stream(chunk));
            }
            assert!(!engine.records.contains_key(&commitment));
            for index in [2u16, 3] {
                receive(
                    &mut engine,
                    &mut sender,
                    &peer_keys[usize::from(index)],
                    relayed(&block, next, index),
                );
            }
            assert!(next_message::<SC>(&context, &mut observer).await.is_none());

            // Discovery names the commitment and binds the leader's roots, and the engine relays
            // them.
            let (response, mut verified) = oneshot::channel();
            engine.handle_assigned_shard_verified_subscription(commitment, response);
            receive(
                &mut engine,
                &mut sender,
                &leader,
                [roots_of(&block, next).into()],
            );
            engine.handle_external_proposal(&mut sender, commitment, leader.clone(), next);
            assert!(matches!(verified.try_recv(), Ok(())));
            let relayed = next_message::<SC>(&context, &mut observer).await;
            assert!(relayed == Some(ShardMessage::Roots(roots_of(&block, next))));
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

    /// Nothing is relayed before naming while consensus has signaled no round, even from the leader
    /// the elector names, or without an elector. Once consensus names a commitment, its roots and
    /// then its chunks are relayed as the chunks verify.
    #[test_traced]
    fn test_no_relay_before_naming_without_a_signal_or_an_elector() {
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

            // The elector names peer 1 for every round.
            let leader = peer_keys[1].clone();
            elect(&mut engine, 1);

            // Before any consensus signal, the leader's chunks and roots only wait in its ring.
            let own = stream_of(&block, round, 0);
            receive(
                &mut engine,
                &mut sender,
                &leader,
                assigned(&block, round, 0),
            );
            assert!(next_message::<SC>(&context, &mut observer).await.is_none());

            // Discovery names the commitment, so its roots and then its chunks are relayed.
            engine.handle_external_proposal(&mut sender, block.commitment(), leader.clone(), round);
            let relay = next_message::<SC>(&context, &mut observer).await;
            assert!(relay == Some(ShardMessage::Roots(roots_of(&block, round))));
            for chunk in &own {
                let relay = next_message::<SC>(&context, &mut observer).await;
                assert!(relay == Some(ShardMessage::Stream(chunk.clone())));
            }

            // Without an elector, the chunks from view 2's leader wait.
            engine.elector = None;
            let next = Round::new(Epoch::zero(), View::new(2));
            receive(&mut engine, &mut sender, &leader, relayed(&other, next, 0));
            assert!(next_message::<SC>(&context, &mut observer).await.is_none());
            assert!(oracle.blocked().await.unwrap().is_empty());
        });
    }

    /// A dynamic elector names no leader before the certificate that unlocks a round, so nothing is
    /// relayed before naming. Once consensus names the commitment, its roots and then its chunks
    /// are relayed as the chunks verify.
    #[test_traced]
    fn test_no_relay_before_naming_with_a_dynamic_elector() {
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
            } = chunk_setup_electing(&context, &oracle, Some(Late)).await;

            // Consensus has notarized view 1, and the chunks and roots from view 2's leader wait.
            let leader = peer_keys[1].clone();
            let next = Round::new(Epoch::zero(), View::new(2));
            engine.handle_notarized_commitment(&mut sender, unrelated().commitment(), round);
            let own = stream_of(&block, next, 0);
            receive(&mut engine, &mut sender, &leader, assigned(&block, next, 0));
            assert!(next_message::<SC>(&context, &mut observer).await.is_none());

            // Discovery names the commitment, so its roots and then its chunks are relayed.
            engine.handle_external_proposal(&mut sender, block.commitment(), leader.clone(), next);
            let relay = next_message::<SC>(&context, &mut observer).await;
            assert!(relay == Some(ShardMessage::Roots(roots_of(&block, next))));
            for chunk in &own {
                let relay = next_message::<SC>(&context, &mut observer).await;
                assert!(relay == Some(ShardMessage::Stream(chunk.clone())));
            }
            assert!(oracle.blocked().await.unwrap().is_empty());
        });
    }

    /// An elector that names the wrong leader blocks no one and still delivers the block. With it
    /// naming peer 3 while peer 1 leads, the leader's chunks wait for naming, and peer 3's valid
    /// chunks of an unrelated block at this node's index are relayed within the round's bound.
    /// Once consensus names the leader's commitment, its chunks verify and are relayed, and the
    /// block reconstructs.
    #[test_traced]
    fn test_wrong_leader_answer_blocks_no_one_and_the_block_is_still_delivered() {
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

            // The elector names peer 3 for every round while peer 1 leads view 2, and consensus has
            // notarized view 1.
            let leader = peer_keys[1].clone();
            elect(&mut engine, 3);
            let next = Round::new(Epoch::zero(), View::new(2));
            let commitment = block.commitment();
            engine.handle_notarized_commitment(&mut sender, unrelated().commitment(), round);

            // The leader streams the local shard and its roots, and peer 2 relays its own chunks.
            // None of them is relayed before naming.
            receive(&mut engine, &mut sender, &leader, assigned(&block, next, 0));
            receive(
                &mut engine,
                &mut sender,
                &peer_keys[2],
                relayed(&block, next, 2),
            );
            assert!(next_message::<SC>(&context, &mut observer).await.is_none());

            // Peer 3 streams an unrelated block's chunks at this node's index. They verify against
            // their own roots and are relayed.
            let junk = stream_of(&unrelated(), next, 0);
            receive(
                &mut engine,
                &mut sender,
                &peer_keys[3],
                junk.iter().cloned().map(ShardMessage::from),
            );
            for chunk in &junk {
                let relay = next_message::<SC>(&context, &mut observer).await;
                assert!(relay == Some(ShardMessage::Stream(chunk.clone())));
            }
            assert!(oracle.blocked().await.unwrap().is_empty());

            // Discovery names the leader's commitment. Its roots and chunks are relayed, the
            // assigned shard verifies, and the block reconstructs.
            let (response, mut verified) = oneshot::channel();
            engine.handle_assigned_shard_verified_subscription(commitment, response);
            engine.handle_external_proposal(&mut sender, commitment, leader, next);
            assert!(matches!(verified.try_recv(), Ok(())));
            let relay = next_message::<SC>(&context, &mut observer).await;
            assert!(relay == Some(ShardMessage::Roots(roots_of(&block, next))));
            for chunk in stream_of(&block, next, 0) {
                let relay = next_message::<SC>(&context, &mut observer).await;
                assert!(relay == Some(ShardMessage::Stream(chunk)));
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

    /// Before naming, a round relays at most two blocks' worth of chunks in total, whatever roots
    /// the leader's chunks claim, and each round has its own allowance.
    #[test_traced]
    fn test_relays_before_naming_are_capped_per_round() {
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
                round,
                ..
            } = chunk_setup(&context, &oracle).await;

            // Peer 1 leads every round, consensus has notarized view 1, and a round may relay two
            // blocks' worth of chunks before naming.
            let leader = peer_keys[1].clone();
            elect(&mut engine, 1);
            engine.handle_notarized_commitment(&mut sender, unrelated().commitment(), round);
            let cap = 2 * usize::from(engine.max_segments);

            // The leader streams the chunks of `cap + 1` candidates for view 2, more chunks than
            // the cap, each candidate under its own roots.
            let next = Round::new(Epoch::zero(), View::new(2));
            let candidates: Vec<_> = (0..=cap as u64)
                .map(|id| {
                    encode_block::<B, SC, H>(
                        B::new(Sha256::hash(&[&id.to_be_bytes()]), Height::new(1), id),
                        coding_config_for_participants(4),
                    )
                })
                .collect();
            for candidate in &candidates {
                receive(
                    &mut engine,
                    &mut sender,
                    &leader,
                    relayed(candidate, next, 0),
                );
            }
            let mut relays = 0;
            while next_message::<SC>(&context, &mut observer).await.is_some() {
                relays += 1;
            }
            assert_eq!(relays, cap);

            // View 3 has its own allowance.
            let later = Round::new(Epoch::zero(), View::new(3));
            receive(
                &mut engine,
                &mut sender,
                &leader,
                [stream_of(&candidates[0], later, 0).remove(0).into()],
            );
            assert!(next_message::<SC>(&context, &mut observer).await.is_some());
            assert!(oracle.blocked().await.unwrap().is_empty());
        });
    }

    /// A chunk relayed before naming is relayed once, and a repeat from the leader is not relayed
    /// again, even after a trim. After naming and relaying the roots, an earlier chunk relay stands
    /// in for the relay after naming while fewer than a round's worth of messages have been sent
    /// since it, even if consensus has signaled a later round.
    #[test_traced]
    fn test_chunks_relayed_before_naming_are_not_relayed_again() {
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

            // Peer 1 leads every round, and consensus has notarized view 1.
            let leader = peer_keys[1].clone();
            elect(&mut engine, 1);
            engine.handle_notarized_commitment(&mut sender, unrelated().commitment(), round);
            let next = Round::new(Epoch::zero(), View::new(2));
            let own = stream_of(&block, next, 0);

            // The leader streams the local shard for view 2, and each chunk is relayed once.
            receive(
                &mut engine,
                &mut sender,
                &leader,
                own.iter().cloned().map(ShardMessage::from),
            );
            for _ in &own {
                assert!(next_message::<SC>(&context, &mut observer).await.is_some());
            }
            assert_eq!(engine.sent, own.len() as u64);

            // View 2 is above the signaled view 1, so a trim keeps its relays and a repeat from the
            // leader is not relayed.
            engine.trim();
            receive(
                &mut engine,
                &mut sender,
                &leader,
                own.iter().cloned().map(ShardMessage::from),
            );
            assert!(next_message::<SC>(&context, &mut observer).await.is_none());
            assert_eq!(engine.sent, own.len() as u64);

            // Consensus signals view 3. A trim still keeps the relays of view 2, since this node
            // has sent fewer messages since then than one round may take.
            let later = Round::new(Epoch::zero(), View::new(3));
            engine.handle_notarized_commitment(&mut sender, other.commitment(), later);
            engine.trim();

            // Naming the commitment verifies the assigned shard and relays only the roots.
            let (response, mut verified) = oneshot::channel();
            engine.handle_assigned_shard_verified_subscription(block.commitment(), response);
            engine.handle_external_proposal(&mut sender, block.commitment(), leader.clone(), next);
            receive(
                &mut engine,
                &mut sender,
                &leader,
                [roots_of(&block, next).into()],
            );
            assert!(matches!(verified.try_recv(), Ok(())));
            let relay = next_message::<SC>(&context, &mut observer).await;
            assert!(relay == Some(ShardMessage::Roots(roots_of(&block, next))));
            assert!(next_message::<SC>(&context, &mut observer).await.is_none());
            assert_eq!(engine.sent, own.len() as u64 + 1);
            assert_eq!(
                gauges(&context.encode(), "chunks_forwarded"),
                vec![own.len() as i64]
            );
            assert!(oracle.blocked().await.unwrap().is_empty());
        });
    }

    /// Chunks are relayed before naming only for rounds from the highest round consensus has
    /// signaled to [`Config::records`] views past it, or among the first that many views of the
    /// next epoch. The elector is asked only about chunks at this node's index.
    #[test_traced]
    fn test_rounds_outside_the_relay_horizon_are_not_relayed_early() {
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
                ..
            } = chunk_setup(&context, &oracle).await;

            // This node holds a scheme for epochs 0 and 1, and the elector names peer 1 for every
            // round.
            let mut private_keys: Vec<PrivateKey> = (0..4).map(PrivateKey::from_seed).collect();
            private_keys.sort_by_key(|key| key.public_key());
            let participants: Set<P> = Set::from_iter_dedup(peer_keys.clone());
            let signer = || {
                Scheme::signer(
                    SCHEME_NAMESPACE,
                    participants.clone(),
                    private_keys[0].clone(),
                )
                .expect("signer scheme must be created")
            };
            engine.scheme_provider =
                MultiEpochProvider::single(signer()).with_epoch(Epoch::new(1), signer());
            let leader = peer_keys[1].clone();
            let named = Named::new(1);
            let elected = named.elected.clone();
            engine.elector = Some(named);
            let horizon = engine.window.get() as u64;
            let at = |epoch, view| Round::new(Epoch::new(epoch), View::new(view));

            // Consensus signals view 10 of epoch 0, and the leader's chunk is relayed early only
            // for rounds inside the horizon.
            engine.handle_notarized_commitment(&mut sender, unrelated().commitment(), at(0, 10));
            for (round, relays) in [
                (at(0, 9), false),
                (at(0, 10), true),
                (at(0, 10 + horizon), true),
                (at(0, 11 + horizon), false),
                (at(1, horizon), true),
                (at(1, horizon + 1), false),
                (at(2, 0), false),
            ] {
                receive(
                    &mut engine,
                    &mut sender,
                    &leader,
                    [stream_of(&block, round, 0).remove(0).into()],
                );
                let relayed = next_message::<SC>(&context, &mut observer).await.is_some();
                assert_eq!(
                    relayed, relays,
                    "a chunk of round {round} must be relayed early only inside the horizon"
                );
            }

            // A chunk at another index never reaches the elector.
            let before = elected.load(Ordering::Relaxed);
            receive(
                &mut engine,
                &mut sender,
                &leader,
                [stream_of(&block, at(0, 11), 2).remove(0).into()],
            );
            assert_eq!(elected.load(Ordering::Relaxed), before);
            assert!(oracle.blocked().await.unwrap().is_empty());
        });
    }

    /// The engine builds one elector for each epoch it is asked about and keeps those of the epoch
    /// consensus has signaled and the next. Each epoch's elector is built once, even when chunks
    /// for the next epoch arrive before chunks for the signaled one.
    #[test_traced]
    fn test_one_elector_is_built_for_each_epoch() {
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
                ..
            } = chunk_setup(&context, &oracle).await;

            // This node holds a scheme for epochs 0 to 2, and the elector names peer 1 for every
            // round.
            let mut private_keys: Vec<PrivateKey> = (0..4).map(PrivateKey::from_seed).collect();
            private_keys.sort_by_key(|key| key.public_key());
            let participants: Set<P> = Set::from_iter_dedup(peer_keys.clone());
            let signer = || {
                Scheme::signer(
                    SCHEME_NAMESPACE,
                    participants.clone(),
                    private_keys[0].clone(),
                )
                .expect("signer scheme must be created")
            };
            engine.scheme_provider = MultiEpochProvider::single(signer())
                .with_epoch(Epoch::new(1), signer())
                .with_epoch(Epoch::new(2), signer());
            let leader = peer_keys[1].clone();
            let named = Named::new(1);
            let built = named.built.clone();
            engine.elector = Some(named);
            let at = |epoch, view| Round::new(Epoch::new(epoch), View::new(view));

            // Consensus signals epoch 0 and then epoch 1. After each signal the leader's chunk for
            // the next epoch arrives before its chunk for the signaled one, and both are relayed.
            for (signaled, claimed) in [
                (at(0, 1), [at(1, 1), at(0, 2)]),
                (at(1, 1), [at(2, 1), at(1, 2)]),
            ] {
                engine.signal(signaled);
                for round in claimed {
                    receive(
                        &mut engine,
                        &mut sender,
                        &leader,
                        [stream_of(&block, round, 0).remove(0).into()],
                    );
                    assert!(
                        next_message::<SC>(&context, &mut observer).await.is_some(),
                        "a chunk of round {round} must be relayed before naming"
                    );
                }
            }

            // Each epoch's elector was built once, and epoch 0's was dropped when consensus
            // signaled epoch 1.
            assert_eq!(built.load(Ordering::Relaxed), 3);
            assert!(
                engine
                    .electors
                    .keys()
                    .copied()
                    .eq([Epoch::new(1), Epoch::new(2)])
            );
            assert!(oracle.blocked().await.unwrap().is_empty());
        });
    }

    /// A node that streams a segment for view 3 relays the chunk at its index from view 2's leader
    /// before naming. Consensus has signaled only view 1, so the horizon starts there.
    #[test_traced]
    fn test_earlier_view_relayed_before_naming_while_streaming_a_later_view() {
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

            // Peer 1 leads every round, and consensus has notarized view 1.
            let leader = peer_keys[1].clone();
            elect(&mut engine, 1);
            let next = Round::new(Epoch::zero(), View::new(2));
            engine.handle_notarized_commitment(&mut sender, unrelated().commitment(), round);

            // Peer 2 receives its chunk of the first segment this node streams for view 3.
            let building = Round::new(Epoch::zero(), View::new(3));
            let shards: Vec<_> = (0..4)
                .map(|index| stream_of(&other, building, index))
                .collect();
            engine.stream_segment(
                &mut sender,
                building,
                StreamedSegment::<SC> {
                    segment: 0,
                    root: shards[2][0].root,
                    chunks: shards.iter().map(|shard| shard[0].chunk.clone()).collect(),
                },
            );
            let sent = next_message::<SC>(&context, &mut observer).await;
            assert!(sent == Some(ShardMessage::Stream(shards[2][0].clone())));

            // The chunk at this node's index from view 2's leader is relayed on arrival.
            let chunk = stream_of(&block, next, 0).remove(0);
            receive(&mut engine, &mut sender, &leader, [chunk.clone().into()]);
            let relayed = next_message::<SC>(&context, &mut observer).await;
            assert!(
                relayed == Some(ShardMessage::Stream(chunk)),
                "view 2's chunk must be relayed while this node streams view 3"
            );
            assert!(oracle.blocked().await.unwrap().is_empty());
        });
    }

    /// Checks that every honest participant reconstructs a notarized target whose relays before
    /// naming have left every peer's ring.
    ///
    /// The leader sends each honest participant its chunk of the target's first segment before
    /// consensus reaches the target's round, and each relays it before naming. Later traffic pushes
    /// that relay out of every ring, sized to one round's messages. With `flood` the traffic is
    /// other rounds' relays before naming, and otherwise the blocks of the intervening rounds. The
    /// leader then delivers the target's assigned shards to only two participants.
    fn early_relay_evicted_before_naming(flood: bool) {
        // Every ring holds one round's worth of messages from each sender, and every engine's
        // elector names participant 0 for every round.
        let max_segments = SC::segments(CodedBlock::<B, SC, H>::max_coded_size(
            B::max_encode_size(&()),
        ));
        let span = RELAY_CANDIDATES * (usize::from(max_segments) + 1);
        let fixture: Fixture<SC> = Fixture {
            peer_buffer_size: NonZeroUsize::new(span).expect("a ring must hold a message"),
            round_leader: Some(0),
            ..Default::default()
        };
        fixture.start(
            |config, context, oracle, mut peers, _, coding_config| async move {
                // The target block is proposed in a later round than consensus has reached.
                let at = |view| Round::new(Epoch::zero(), View::new(view));
                let target_round = at(if flood { 4 } else { 12 });
                let target = encode_block::<B, SC, H>(
                    B::new(Sha256::hash(&[b"target"]), Height::new(12), 1_000),
                    coding_config,
                );
                let commitment = target.commitment();
                let leader = peers[0].public_key.clone();

                // Every participant has seen consensus notarize view 1.
                for peer in &peers {
                    peer.mailbox.notarized(unrelated().commitment(), at(1));
                }
                context.sleep(config.link.latency).await;

                // The leader sends each honest participant its chunk of the target's first
                // segment, and each relays it before naming.
                for index in 1..4u16 {
                    let recipient = peers[usize::from(index)].public_key.clone();
                    send(
                        &mut peers[0].sender,
                        &recipient,
                        [stream_of(&target, target_round, index).remove(0).into()],
                    );
                }
                context.sleep(config.link.latency * 4).await;
                let relays = gauges(&context.encode(), "chunks_forwarded");
                assert_eq!(relays.iter().filter(|&&count| count == 1).count(), 3);

                if flood {
                    // The leader spends the allowance of three later rounds on chunks of other
                    // blocks, and every honest participant relays them before naming.
                    let cap = RELAY_CANDIDATES * usize::from(max_segments);
                    for view in [8u64, 12, 16] {
                        for candidate in 0..cap as u64 {
                            let other = encode_block::<B, SC, H>(
                                B::new(
                                    Sha256::hash(&[&view.to_be_bytes(), &candidate.to_be_bytes()]),
                                    Height::new(1),
                                    candidate,
                                ),
                                coding_config,
                            );
                            for index in 1..4u16 {
                                let recipient = peers[usize::from(index)].public_key.clone();
                                send(
                                    &mut peers[0].sender,
                                    &recipient,
                                    [stream_of(&other, at(view), index).remove(0).into()],
                                );
                            }
                        }
                    }
                    context.sleep(config.link.latency * 4).await;
                    let relays = gauges(&context.encode(), "chunks_forwarded");
                    let expected = (1 + 3 * cap) as i64;
                    assert_eq!(relays.iter().filter(|&&count| count == expected).count(), 3);
                } else {
                    // Honest participants take turns proposing the blocks of views 2 through 10,
                    // and every honest participant reconstructs each of them.
                    for view in 2..=10u64 {
                        let block = encode_block::<B, SC, H>(
                            B::new(
                                Sha256::hash(&[&view.to_be_bytes()]),
                                Height::new(view),
                                view,
                            ),
                            coding_config,
                        );
                        let proposer = 1 + view as usize % 3;
                        let proposer_key = peers[proposer].public_key.clone();
                        peers[proposer].mailbox.proposed(at(view), block.clone());
                        for peer in &peers {
                            peer.mailbox.discovered(
                                block.commitment(),
                                proposer_key.clone(),
                                at(view),
                            );
                        }
                        context.sleep(config.link.latency * 5).await;
                        for peer in &peers[1..] {
                            assert!(
                                peer.mailbox.get(block.commitment()).await.is_some(),
                                "every honest participant must reconstruct view {view}"
                            );
                        }
                    }
                }

                // The leader delivers the target's assigned shards and roots to participants 1 and
                // 2 only. Once consensus names the target, both are ready to vote for it.
                let mut first = peers[1]
                    .mailbox
                    .subscribe_assigned_shard_verified(commitment);
                let mut second = peers[2]
                    .mailbox
                    .subscribe_assigned_shard_verified(commitment);
                for index in 1..=2u16 {
                    let recipient = peers[usize::from(index)].public_key.clone();
                    send(
                        &mut peers[0].sender,
                        &recipient,
                        assigned(&target, target_round, index),
                    );
                }
                for peer in &peers[1..] {
                    peer.mailbox
                        .discovered(commitment, leader.clone(), target_round);
                }
                context.sleep(config.link.latency * 5).await;
                assert!(matches!(first.try_recv(), Ok(())));
                assert!(matches!(second.try_recv(), Ok(())));

                // Once the target is notarized, every honest participant reconstructs it.
                for peer in &peers[1..] {
                    peer.mailbox.notarized(commitment, target_round);
                }
                context.sleep(config.link.latency * 5).await;
                for peer in &peers[1..] {
                    assert!(
                        peer.mailbox.get(commitment).await.is_some(),
                        "every honest participant must reconstruct the notarized target"
                    );
                }
                assert!(oracle.blocked().await.unwrap().is_empty());
            },
        );
    }

    /// A participant whose relay before naming was pushed out of its peers' rings by the blocks
    /// of later rounds relays the chunk again after naming, so a target delivered to only two
    /// participants is still reconstructed by every honest participant.
    #[test_traced]
    fn test_relay_before_naming_evicted_by_later_blocks_is_repeated_after_naming() {
        early_relay_evicted_before_naming(false);
    }

    /// A participant whose relay before naming was pushed out of its peers' rings by later
    /// rounds' relays before naming relays the chunk again after naming, so a target delivered
    /// to only two participants is still reconstructed by every honest participant.
    #[test_traced]
    fn test_relay_before_naming_evicted_by_other_early_relays_is_repeated_after_naming() {
        early_relay_evicted_before_naming(true);
    }

    /// When the leader the elector names sends a chunk at this node's index that fails its check
    /// against the root it claims, the chunk blocks the leader and is not relayed.
    #[test_traced]
    fn test_invalid_chunk_from_the_named_leader_blocks_it_and_is_not_relayed() {
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

            // Peer 1 leads every round, and consensus has notarized view 1.
            let leader = peer_keys[1].clone();
            elect(&mut engine, 1);
            engine.handle_notarized_commitment(&mut sender, unrelated().commitment(), round);

            // The leader's chunk for view 2 carries another block's data under this block's root.
            let next = Round::new(Epoch::zero(), View::new(2));
            let own = stream_of(&block, next, 0);
            let foreign = stream_of(&other, next, 0);
            let segment = (0..own.len())
                .find(|&segment| own[segment].root != foreign[segment].root)
                .expect("the blocks must differ in some segment");
            let forged = StreamChunk {
                chunk: foreign[segment].chunk.clone(),
                ..own[segment].clone()
            };

            // The chunk blocks the leader and is not relayed.
            receive(&mut engine, &mut sender, &leader, [forged.into()]);
            assert_blocked(&oracle, &peer_keys[0], &leader).await;
            assert!(next_message::<SC>(&context, &mut observer).await.is_none());
        });
    }

    /// While a retained record is observed at ever later rounds and each next round relays a
    /// chunk before naming, the ledger of relays keeps no more rounds than the messages one round
    /// may take, however long the record stays.
    #[test_traced]
    fn test_relay_ledger_stays_bounded_while_the_anchor_advances() {
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

            // Peer 1 leads every round, consensus has notarized view 1, and one round's messages
            // bound the rounds the ledger may keep.
            let leader = peer_keys[1].clone();
            elect(&mut engine, 1);
            engine.handle_notarized_commitment(&mut sender, unrelated().commitment(), round);
            engine.trim();
            let span = RELAY_CANDIDATES * (usize::from(engine.max_segments) + 1);

            for view in 2..102 {
                // A later observation of the retained block advances the anchor.
                let observed = Round::new(Epoch::zero(), View::new(view));
                engine.handle_notarized_commitment(&mut sender, block.commitment(), observed);
                engine.trim();

                // The next round's leader sends a chunk at this node's index, and it is relayed.
                let next = Round::new(Epoch::zero(), View::new(view + 1));
                receive(
                    &mut engine,
                    &mut sender,
                    &leader,
                    [stream_of(&other, next, 0).remove(0).into()],
                );
                engine.trim();
                assert!(engine.relayed.len() <= span);
            }
            assert_eq!(engine.records.len(), 2);
            assert!(oracle.blocked().await.unwrap().is_empty());
        });
    }

    /// With every engine's elector naming the proposer, the other participants relay their chunks
    /// while the proposer streams, before consensus names the block. The proposer caches the block
    /// and counts its assigned shard as verified. Once the block is named elsewhere, the other
    /// participants verify their assigned shards, all recipients reconstruct the block, and no
    /// chunk is relayed twice.
    #[test_traced]
    fn test_e2e_chunks_relayed_before_naming_reconstruct_everywhere() {
        let fixture: Fixture<SC> = Fixture {
            num_primary_peers: 10,
            num_secondary_peers: 1,
            round_leader: Some(0),
            ..Default::default()
        };

        fixture.start(
            |config, context, oracle, mut peers, non_participants, coding_config| async move {
                let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block = encode_block::<B, SC, H>(inner, coding_config);
                let commitment = coded_block.commitment();
                let segments = stream_of(&coded_block, Round::new(Epoch::zero(), View::new(2)), 0)
                    .len() as i64;
                let leader = peers[0].public_key.clone();

                // Every engine has seen consensus notarize view 1 before the leader of view 2
                // proposes.
                let signaled = Round::new(Epoch::zero(), View::new(1));
                for peer in peers.iter() {
                    peer.mailbox.notarized(unrelated().commitment(), signaled);
                }
                for np in non_participants.iter() {
                    np.mailbox.notarized(unrelated().commitment(), signaled);
                }

                // The leader of view 2 proposes, and each of the nine other participants relays its
                // chunk of every segment before naming.
                let round = Round::new(Epoch::zero(), View::new(2));
                peers[0].mailbox.proposed(round, coded_block.clone());
                context.sleep(config.link.latency * 3).await;
                let forwarded = gauges(&context.encode(), "chunks_forwarded");
                assert_eq!(
                    forwarded.iter().filter(|&&count| count == segments).count(),
                    9
                );

                // Discovery names the block at every other participant and the non-participant.
                for peer in peers[1..].iter_mut() {
                    peer.mailbox.discovered(commitment, leader.clone(), round);
                }
                for np in non_participants.iter() {
                    np.mailbox.discovered(commitment, leader.clone(), round);
                }
                context.sleep(config.link.latency * 3).await;

                // Every participant's assigned shard is ready. The proposer retains its cached
                // block, the other participants and the non-participant reconstruct the block, and
                // no chunk is relayed again.
                for peer in peers.iter_mut() {
                    peer.mailbox
                        .subscribe_assigned_shard_verified(commitment)
                        .await
                        .expect("participant shard subscription should complete");
                    let reconstructed = peer
                        .mailbox
                        .get(commitment)
                        .await
                        .expect("the participant must reconstruct the block");
                    assert_eq!(reconstructed.commitment(), commitment);
                }
                for np in non_participants.iter() {
                    let reconstructed = np
                        .mailbox
                        .get(commitment)
                        .await
                        .expect("the non-participant must reconstruct the block");
                    assert_eq!(reconstructed.commitment(), commitment);
                }
                assert_eq!(gauges(&context.encode(), "chunks_forwarded"), forwarded);
                assert!(oracle.blocked().await.unwrap().is_empty());
            },
        );
    }

    /// A record keeps every chunk it ingests once its roots bind, even after later traffic pushes
    /// the chunk out of its sender's ring. Every other participant binds the roots of view 4 while
    /// the relays before naming of the first segment are fresh, and relays of other blocks then
    /// push those relays out of every ring. Once the leader completes the assigned shards of
    /// participants 1 and 2 only and consensus notarizes the block, every other participant still
    /// reconstructs it.
    #[test_traced]
    fn test_bound_record_keeps_relays_before_naming_through_later_traffic() {
        // Each ring holds two rounds' worth of a sender's messages, and participant 0 leads every
        // round.
        let max_segments = SC::segments(CodedBlock::<B, SC, H>::max_coded_size(
            B::max_encode_size(&()),
        ));
        let span = RELAY_CANDIDATES * (usize::from(max_segments) + 1);
        let fixture: Fixture<SC> = Fixture {
            peer_buffer_size: NonZeroUsize::new(2 * span).expect("a ring must hold a message"),
            round_leader: Some(0),
            ..Default::default()
        };
        fixture.start(
            |config, context, oracle, mut peers, _, coding_config| async move {
                let at = |view| Round::new(Epoch::zero(), View::new(view));
                let round = at(4);
                let block = encode_block::<B, SC, H>(
                    B::new(Sha256::hash(&[b"target"]), Height::new(12), 1_000),
                    coding_config,
                );
                let commitment = block.commitment();
                let leader = peers[0].public_key.clone();

                // Every participant has seen consensus notarize view 1.
                for peer in &peers {
                    peer.mailbox.notarized(unrelated().commitment(), at(1));
                }
                context.sleep(config.link.latency).await;

                // The leader of view 4 sends every other participant its chunk of the first
                // segment, and each relays it before naming.
                for index in 1..4u16 {
                    let recipient = peers[usize::from(index)].public_key.clone();
                    let chunk = stream_of(&block, round, index).remove(0);
                    send(&mut peers[0].sender, &recipient, [chunk.into()]);
                }
                context.sleep(config.link.latency * 4).await;
                let relays = gauges(&context.encode(), "chunks_forwarded");
                assert_eq!(relays.iter().filter(|&&count| count == 1).count(), 3);

                // Discovery names the block at every other participant, and the roots reach
                // participants 1 and 2 from the leader and participant 3 from their relays. Each
                // binds them while the relays are fresh and relays no chunk again.
                for peer in &peers[1..] {
                    peer.mailbox.discovered(commitment, leader.clone(), round);
                }
                for index in 1..=2usize {
                    let recipient = peers[index].public_key.clone();
                    send(
                        &mut peers[0].sender,
                        &recipient,
                        [roots_of(&block, round).into()],
                    );
                }
                context.sleep(config.link.latency * 5).await;
                assert_eq!(gauges(&context.encode(), "chunks_forwarded"), relays);

                // The leader spends the relay allowance of views 8, 12, and 16 on the first
                // segments of other blocks, and every other participant relays them, pushing the
                // relays of the block out of every ring.
                let cap = RELAY_CANDIDATES * usize::from(max_segments);
                for view in [8u64, 12, 16] {
                    for candidate in 0..cap as u64 {
                        let other = encode_block::<B, SC, H>(
                            B::new(
                                Sha256::hash(&[&view.to_be_bytes(), &candidate.to_be_bytes()]),
                                Height::new(1),
                                candidate,
                            ),
                            coding_config,
                        );
                        for index in 1..4u16 {
                            let recipient = peers[usize::from(index)].public_key.clone();
                            let chunk = stream_of(&other, at(view), index).remove(0);
                            send(&mut peers[0].sender, &recipient, [chunk.into()]);
                        }
                    }
                }
                context.sleep(config.link.latency * 4).await;
                let flooded = (1 + 3 * cap) as i64;
                assert!(2 * span < 3 * cap);
                assert_eq!(
                    gauges(&context.encode(), "chunks_forwarded")
                        .iter()
                        .filter(|&&count| count == flooded)
                        .count(),
                    3
                );

                // The leader completes the assigned shards of participants 1 and 2 only, and both
                // verify.
                let mut first = peers[1]
                    .mailbox
                    .subscribe_assigned_shard_verified(commitment);
                let mut second = peers[2]
                    .mailbox
                    .subscribe_assigned_shard_verified(commitment);
                for index in 1..=2u16 {
                    let recipient = peers[usize::from(index)].public_key.clone();
                    send(
                        &mut peers[0].sender,
                        &recipient,
                        assigned(&block, round, index),
                    );
                }
                context.sleep(config.link.latency * 5).await;
                assert!(matches!(first.try_recv(), Ok(())));
                assert!(matches!(second.try_recv(), Ok(())));

                // Once consensus notarizes the block, every other participant reconstructs it from
                // the shards of participants 1 and 2, and no peer is blocked.
                for peer in &peers[1..] {
                    peer.mailbox.notarized(commitment, round);
                }
                context.sleep(config.link.latency * 5).await;
                for peer in &peers[1..] {
                    assert!(
                        peer.mailbox.get(commitment).await.is_some(),
                        "every other participant must reconstruct the block"
                    );
                }
                assert!(oracle.blocked().await.unwrap().is_empty());
            },
        );
    }

    /// Chunks and roots that arrive before consensus names their commitment wait in their senders'
    /// rings and stay there after the roots bind. Discovery binds and relays the roots, relays each
    /// of the leader's chunks in segment order as it verifies, and reconstructs the block.
    #[test_traced]
    fn test_chunks_and_roots_wait_in_rings_until_discovery() {
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

            // Before consensus names the commitment, the leader streams the local shard and its
            // roots and peer 2 relays its own chunks. They only wait in their senders' rings.
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
            assert!(engine.records.is_empty());
            assert!(next_message::<SC>(&context, &mut observer).await.is_none());

            // Discovery binds and relays the roots, then relays each buffered leader chunk as it
            // verifies, and the assigned shard verifies. The rings keep every message.
            let (response, mut verified) = oneshot::channel();
            engine.handle_assigned_shard_verified_subscription(commitment, response);
            engine.handle_external_proposal(&mut sender, commitment, leader.clone(), round);
            assert_eq!(buffered(&engine, &leader, round), own.len() + 1);
            assert_eq!(buffered(&engine, &peer_keys[2], round), own.len());
            assert!(matches!(verified.try_recv(), Ok(())));
            let relayed = next_message::<SC>(&context, &mut observer).await;
            assert!(relayed == Some(ShardMessage::Roots(roots_of(&block, round))));
            for chunk in &own {
                let relayed = next_message::<SC>(&context, &mut observer)
                    .await
                    .expect("buffered leader chunks must be relayed once they verify");
                assert!(relayed == ShardMessage::Stream(chunk.clone()));
            }

            // Peer 2's shard completes the minimum, and the block reconstructs.
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

                // The leader proposes, and every other participant and the non-participant learn
                // the leader.
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

                // The proposer caches the block and counts its assigned shard as verified. The
                // other participants and the non-participant verify their assigned shards and
                // reconstruct the block, and no peer is blocked.
                for peer in peers.iter_mut() {
                    peer.mailbox
                        .subscribe_assigned_shard_verified(commitment)
                        .await
                        .expect("participant shard subscription should complete");
                    let reconstructed = peer
                        .mailbox
                        .get(commitment)
                        .await
                        .expect("the participant must reconstruct the block");
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
                        .expect("the non-participant must reconstruct the block");
                    assert_eq!(reconstructed.commitment(), commitment);
                }
                assert!(oracle.blocked().await.unwrap().is_empty());
            },
        );
    }

    /// A proposal with no segment streamed beforehand reaches each participant as the chunk of its
    /// index in every segment, in segment order, followed by the roots that bind them to the
    /// commitment. The proposer caches the block and counts its assigned shard as verified.
    /// Reconstruction at the peers is checked by [`test_e2e_chunked_broadcast_and_reconstruction`].
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

            // This node subscribes to its assigned shard's verification before it proposes.
            let (response, mut verified) = oneshot::channel();
            engine.handle_assigned_shard_verified_subscription(commitment, response);

            // Peer 2 receives its chunk of every segment in order, then the roots, and each
            // segment and the roots count as one message sent.
            engine.broadcast_shards(&mut sender, round, Arc::new(block.clone()));
            let segments = stream_of(&block, round, 2);
            for chunk in segments.iter().cloned() {
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
            assert_eq!(engine.sent, segments.len() as u64 + 1);

            // The proposer caches the block and counts its assigned shard as verified.
            assert!(matches!(verified.try_recv(), Ok(())));
            let record = &engine.records[&commitment];
            assert!(record.block().is_some());
            assert!(record.is_assigned_shard_ready());
            assert!(oracle.blocked().await.unwrap().is_empty());
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

            // Each segment reaches peer 2 as it is coded, and each counts as one message sent.
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
            assert_eq!(engine.sent, shards[2].len() as u64);

            // Proposing the block sealed from those segments sends only its roots and caches the
            // block.
            engine.broadcast_shards(&mut sender, round, Arc::new(block.clone()));
            let sent = next_message::<SC>(&context, &mut observer)
                .await
                .expect("the roots must be sent");
            assert!(sent == ShardMessage::Roots(roots_of(&block, round)));
            assert!(next_message::<SC>(&context, &mut observer).await.is_none());
            assert_eq!(engine.sent, shards[2].len() as u64 + 1);
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
    /// participants relay and the roots one of them relays, without naming the round's leader. That
    /// reconstruction does not verify the assigned shard. The leader's chunks still verify it once
    /// discovery names the leader.
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

                // The notarization reconstructs the block from the relayed chunks and roots, but
                // leaves the assigned shard unverified.
                peers[receiver_idx].mailbox.notarized(commitment, round);
                select! {
                    result = block_sub => {
                        let block = result.expect("the notarization must reconstruct the block");
                        assert_eq!(block.commitment(), commitment);
                    },
                    _ = context.sleep(Duration::from_secs(5)) => {
                        panic!("the block must reconstruct after the notarization");
                    },
                }
                let mut readiness = peers[receiver_idx]
                    .mailbox
                    .subscribe_assigned_shard_verified(commitment);
                assert!(
                    matches!(readiness.try_recv(), Err(TryRecvError::Empty)),
                    "leaderless reconstruction must not satisfy assigned shard readiness"
                );

                // Once discovery names the leader, its chunks verify the assigned shard, and no
                // peer is blocked.
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
                    result = readiness => {
                        result.expect("the leader's chunks must verify the assigned shard");
                    },
                    _ = context.sleep(Duration::from_secs(5)) => {
                        panic!("the assigned shard must verify after leader discovery");
                    },
                }
                assert!(
                    oracle.blocked().await.unwrap().is_empty(),
                    "relayed chunks and roots must not block peers"
                );
            },
        );
    }
}
