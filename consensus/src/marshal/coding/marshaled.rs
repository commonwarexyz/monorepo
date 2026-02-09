//! Wrapper for consensus applications that handles epochs, erasure coding, and block dissemination.
//!
//! # Overview
//!
//! [`Marshaled`] is an adapter that wraps any [`VerifyingApplication`] implementation to handle
//! epoch transitions and erasure coded broadcast automatically. It intercepts consensus
//! operations (propose, verify, certify) and ensures blocks are only produced within valid epoch boundaries.
//!
//! # Epoch Boundaries
//!
//! An epoch is a fixed number of blocks (the `epoch_length`). When the last block in an epoch
//! is reached, this wrapper prevents new blocks from being built & proposed until the next epoch begins.
//! Instead, it re-proposes the boundary block to avoid producing blocks that would be pruned
//! by the epoch transition.
//!
//! # Erasure Coding
//!
//! This wrapper integrates with a variant of marshal that supports erasure coded broadcast. When a leader
//! proposes a new block, it is automatically erasure encoded and its shards are broadcasted to active
//! participants. When verifying a proposed block (the precondition for notarization), the wrapper
//! ensures the commitment's context hash matches the consensus context and subscribes to shard validity
//! for the shard received by the proposer. If the shard is valid, the local shard is relayed to all
//! other participants to aid in block reconstruction.
//!
//! During certification (the phase between notarization and finalization), the wrapper subscribes to
//! block reconstruction and validates epoch boundaries, parent commitment, height contiguity, and
//! that the block's embedded context matches the consensus context before allowing the block to be
//! certified. If certification fails, the voter can still emit a nullify vote to advance the view.
//!
//! # Usage
//!
//! Wrap your [`VerifyingApplication`] implementation with [`Marshaled::new`] and provide it to your
//! consensus engine for the [`Automaton`] and [`Relay`]. The wrapper handles all epoch logic transparently.
//!
//! ```rust,ignore
//! let cfg = MarshaledConfig {
//!     application: my_application,
//!     marshal: marshal_mailbox,
//!     shards: shard_mailbox,
//!     scheme_provider,
//!     epocher,
//!     strategy,
//! };
//! let application = Marshaled::new(context, cfg);
//! ```
//!
//! # Implementation Notes
//!
//! - Genesis blocks are handled specially: epoch 0 returns the application's genesis block,
//!   while subsequent epochs use the last block of the previous epoch as genesis
//! - Blocks are automatically verified to be within the current epoch
//!
//! # Notarization and Data Availability
//!
//! In rare crash cases, it is possible for a notarization certificate to exist without a block being
//! available to the honest parties (e.g., if the whole network crashed before receiving `f+1` shards
//! and the proposer went permanently offline). In this case, `certify` will be unable to fetch the
//! block before timeout and result in a nullification.
//!
//! For this reason, it should not be expected that every notarized payload will be certifiable due
//! to the lack of an available block. However, if even one honest and online party has the block,
//! they will attempt to forward it to others via marshal's resolver.

use crate::{
    marshal::{
        ancestry::AncestorStream,
        coding::{
            shards,
            types::{coding_config_for_participants, context_hash, CodedBlock},
            Coding,
        },
        core, is_at_epoch_boundary, Update,
    },
    simplex::{scheme::Scheme, types::Context},
    types::{CodingCommitment, Epoch, Epocher, Round},
    Application, Automaton, Block, CertifiableAutomaton, CertifiableBlock, Epochable, Heightable,
    Relay, Reporter, VerifyingApplication,
};
use commonware_coding::{Config as CodingConfig, Scheme as CodingScheme};
use commonware_cryptography::{
    certificate::{Provider, Scheme as CertificateScheme},
    sha256::Digest as Sha256Digest,
    Committable, Digestible,
};
use commonware_macros::select;
use commonware_parallel::Strategy;
use commonware_runtime::{telemetry::metrics::status::GaugeExt, Clock, Metrics, Spawner, Storage};
use commonware_utils::channel::{fallible::OneshotExt, oneshot};
use futures::{
    future::{try_join, Either, Ready},
    lock::Mutex,
};
use prometheus_client::metrics::{gauge::Gauge, histogram::Histogram};
use rand::Rng;
use std::{
    collections::HashMap,
    sync::{Arc, OnceLock},
    time::Instant,
};
use tracing::{debug, warn};

/// The [`CodingConfig`] used for genesis blocks. These blocks are never broadcasted in
/// the proposal phase, and thus the configuration is irrelevant.
const GENESIS_CODING_CONFIG: CodingConfig = CodingConfig {
    minimum_shards: 0,
    extra_shards: 0,
};

type TasksMap<B> = HashMap<(Round, <B as Digestible>::Digest), oneshot::Receiver<bool>>;

/// Configuration for initializing [`Marshaled`].
#[allow(clippy::type_complexity)]
pub struct MarshaledConfig<A, B, C, Z, S, ES>
where
    B: CertifiableBlock,
    C: CodingScheme,
    Z: Provider<Scope = Epoch, Scheme: Scheme<CodingCommitment>>,
    S: Strategy,
    ES: Epocher,
{
    /// The underlying application to wrap.
    pub application: A,
    /// Mailbox for communicating with the marshal engine.
    pub marshal:
        core::Mailbox<Z::Scheme, Coding<B, C, <Z::Scheme as CertificateScheme>::PublicKey>>,
    /// Mailbox for communicating with the shards engine.
    pub shards: shards::Mailbox<B, C, <Z::Scheme as CertificateScheme>::PublicKey>,
    /// Provider for signing schemes scoped by epoch.
    pub scheme_provider: Z,
    /// Strategy for parallel operations.
    pub strategy: S,
    /// Strategy for determining epoch boundaries.
    pub epocher: ES,
}

/// An [`Application`] adapter that handles epoch transitions and erasure coded broadcast.
///
/// This wrapper intercepts consensus operations to enforce epoch boundaries. It prevents
/// blocks from being produced outside their valid epoch and handles the special case of
/// re-proposing boundary blocks during epoch transitions.
#[derive(Clone)]
#[allow(clippy::type_complexity)]
pub struct Marshaled<E, A, B, C, Z, S, ES>
where
    E: Rng + Storage + Spawner + Metrics + Clock,
    A: Application<E>,
    B: CertifiableBlock,
    C: CodingScheme,
    Z: Provider<Scope = Epoch, Scheme: Scheme<CodingCommitment>>,
    S: Strategy,
    ES: Epocher,
{
    context: E,
    application: A,
    marshal: core::Mailbox<Z::Scheme, Coding<B, C, <Z::Scheme as CertificateScheme>::PublicKey>>,
    shards: shards::Mailbox<B, C, <Z::Scheme as CertificateScheme>::PublicKey>,
    scheme_provider: Z,
    epocher: ES,
    strategy: S,
    #[allow(clippy::type_complexity)]
    last_built: Arc<Mutex<Option<(Round, CodedBlock<B, C>)>>>,
    verification_tasks: Arc<Mutex<TasksMap<B>>>,
    cached_genesis: Arc<OnceLock<(CodingCommitment, CodedBlock<B, C>)>>,

    build_duration: Gauge,
    verify_duration: Gauge,
    proposal_parent_fetch_duration: Gauge,
    erasure_encode_duration: Histogram,
}

impl<E, A, B, C, Z, S, ES> Marshaled<E, A, B, C, Z, S, ES>
where
    E: Rng + Storage + Spawner + Metrics + Clock,
    A: VerifyingApplication<
        E,
        Block = B,
        SigningScheme = Z::Scheme,
        Context = Context<CodingCommitment, <Z::Scheme as CertificateScheme>::PublicKey>,
    >,
    B: CertifiableBlock<Context = <A as Application<E>>::Context>,
    C: CodingScheme,
    Z: Provider<Scope = Epoch, Scheme: Scheme<CodingCommitment>>,
    S: Strategy,
    ES: Epocher,
{
    /// Creates a new [`Marshaled`] wrapper.
    ///
    /// # Panics
    ///
    /// Panics if the marshal metadata store cannot be initialized.
    pub fn new(context: E, cfg: MarshaledConfig<A, B, C, Z, S, ES>) -> Self {
        let MarshaledConfig {
            application,
            marshal,
            shards,
            scheme_provider,
            strategy,
            epocher,
        } = cfg;

        let build_duration = Gauge::default();
        context.register(
            "build_duration",
            "Time taken for the application to build a new block, in milliseconds",
            build_duration.clone(),
        );
        let verify_duration = Gauge::default();
        context.register(
            "verify_duration",
            "Time taken for the application to verify a block, in milliseconds",
            verify_duration.clone(),
        );
        let proposal_parent_fetch_duration = Gauge::default();
        context.register(
            "parent_fetch_duration",
            "Time taken to fetch a parent block in the proposal process, in milliseconds",
            proposal_parent_fetch_duration.clone(),
        );
        let erasure_encode_duration =
            Histogram::new([0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0]);
        context.register(
            "erasure_encode_duration",
            "Histogram of time taken to erasure encode a block, in seconds",
            erasure_encode_duration.clone(),
        );

        Self {
            context,
            application,
            marshal,
            shards,
            scheme_provider,
            strategy,
            epocher,
            last_built: Arc::new(Mutex::new(None)),
            verification_tasks: Arc::new(Mutex::new(HashMap::new())),
            cached_genesis: Arc::new(OnceLock::new()),

            build_duration,
            verify_duration,
            proposal_parent_fetch_duration,
            erasure_encode_duration,
        }
    }

    /// Verifies a proposed block within epoch boundaries.
    ///
    /// This method validates that:
    /// 1. The block is within the current epoch (unless it's a boundary block re-proposal)
    /// 2. Re-proposals are only allowed for the last block in an epoch
    /// 3. The block's parent digest matches the consensus context's expected parent
    /// 4. The block's height is exactly one greater than the parent's height
    /// 5. The block's embedded context hash matches the commitment
    /// 6. The block's embedded context matches the consensus context
    /// 7. The underlying application's verification logic passes
    ///
    /// Verification is spawned in a background task and returns a receiver that will contain
    /// the verification result.
    ///
    /// If `prefetched_block` is provided, it will be used directly instead of fetching from
    /// the marshal. This is useful in `certify` when we've already fetched the block to
    /// extract its embedded context.
    async fn deferred_verify(
        &mut self,
        context: Context<CodingCommitment, <Z::Scheme as CertificateScheme>::PublicKey>,
        commitment: CodingCommitment,
        prefetched_block: Option<CodedBlock<B, C>>,
    ) -> oneshot::Receiver<bool> {
        let mut marshal = self.marshal.clone();
        let mut application = self.application.clone();
        let epocher = self.epocher.clone();
        let verify_duration = self.verify_duration.clone();
        let cached_genesis = self.cached_genesis.clone();

        let (mut tx, rx) = oneshot::channel();
        self.context
            .with_label("deferred_verify")
            .with_attribute("round", context.round)
            .spawn(move |runtime_context| async move {
                let round = context.round;

                // Fetch parent block
                let (parent_view, parent_commitment) = context.parent;
                let parent_request = fetch_parent(
                    parent_commitment,
                    Some(Round::new(context.epoch(), parent_view)),
                    &mut application,
                    &mut marshal,
                    cached_genesis,
                )
                .await;

                // Get block either from prefetched or by subscribing
                let (parent, block) = if let Some(block) = prefetched_block {
                    // We have a prefetched block, just fetch the parent
                    let parent = select! {
                        _ = tx.closed() => {
                            debug!(
                                reason = "consensus dropped receiver",
                                "skipping verification"
                            );
                            return;
                        },
                        result = parent_request => match result {
                            Ok(parent) => parent,
                            Err(_) => {
                                debug!(reason = "failed to fetch parent", "skipping verification");
                                return;
                            }
                        },
                    };
                    (parent, block)
                } else {
                    // No prefetched block, fetch both parent and block
                    let block_request = marshal
                        .subscribe_by_commitment(Some(round), commitment)
                        .await;
                    let block_requests = try_join(parent_request, block_request);

                    select! {
                        _ = tx.closed() => {
                            debug!(
                                reason = "consensus dropped receiver",
                                "skipping verification"
                            );
                            return;
                        },
                        result = block_requests => match result {
                            Ok(results) => results,
                            Err(_) => {
                                debug!(
                                    reason = "failed to fetch parent or block",
                                    "skipping verification"
                                );
                                return;
                            }
                        },
                    }
                };

                // Validate that block commitments match what consensus expects.
                if block.commitment() != commitment {
                    debug!(
                        expected_commitment = %commitment,
                        block_commitment = %block.commitment(),
                        "block commitment does not match expected commitment"
                    );
                    tx.send_lossy(false);
                    return;
                }
                if parent.commitment() != parent_commitment {
                    debug!(
                        expected_parent_commitment = %parent_commitment,
                        parent_commitment = %parent.commitment(),
                        "parent commitment does not match expected parent commitment"
                    );
                    tx.send_lossy(false);
                    return;
                }

                // Epoch boundary check
                let Some(block_bounds) = epocher.containing(block.height()) else {
                    debug!(
                        height = %block.height(),
                        "block height not covered by epoch strategy"
                    );
                    tx.send_lossy(false);
                    return;
                };
                if block_bounds.epoch() != context.epoch() {
                    tx.send_lossy(false);
                    return;
                }

                // Validate that the block's parent digest matches what consensus expects.
                if block.parent() != parent.digest() {
                    debug!(
                        block_parent = %block.parent(),
                        expected_parent = %parent.digest(),
                        "block parent digest does not match expected parent"
                    );
                    tx.send_lossy(false);
                    return;
                }

                // Validate that heights are contiguous.
                if parent.height().next() != block.height() {
                    debug!(
                        parent_height = %parent.height(),
                        block_height = %block.height(),
                        "block height is not contiguous with parent height"
                    );
                    tx.send_lossy(false);
                    return;
                }

                // Ensure the block's embedded context matches the commitment's context hash.
                let expected_context_hash = commitment.context_digest::<Sha256Digest>();
                let got_context_hash = context_hash(&block.context());
                if expected_context_hash != got_context_hash {
                    debug!(
                        expected_context_hash = ?expected_context_hash,
                        got_context_hash = ?got_context_hash,
                        "block context hash does not match commitment"
                    );
                    tx.send_lossy(false);
                    return;
                }

                // Ensure the block's embedded context matches the consensus context.
                //
                // We already checked the commitment's context hash against the block's embedded
                // context above (and `verify()` ties the commitment hash to the consensus context).
                // This check enforces full context equality for certification, rejecting any
                // reconstructed block whose context does not exactly match the consensus context.
                if block.context() != context {
                    debug!(
                        ?context,
                        block_context = ?block.context(),
                        "block-embedded context does not match consensus context"
                    );
                    tx.send_lossy(false);
                    return;
                }

                let ancestry_stream = AncestorStream::new(
                    marshal.clone(),
                    [block.clone().into_inner(), parent.into_inner()],
                );
                let validity_request = application.verify(
                    (runtime_context.with_label("app_verify"), context.clone()),
                    ancestry_stream,
                );

                // If consensus drops the receiver, we can stop work early.
                let start = Instant::now();
                let application_valid = select! {
                    _ = tx.closed() => {
                        debug!(
                            reason = "consensus dropped receiver",
                            "skipping verification"
                        );
                        return;
                    },
                    is_valid = validity_request => is_valid,
                };
                let _ = verify_duration.try_set(start.elapsed().as_millis());
                if application_valid {
                    marshal.verified(round, block).await;
                }
                tx.send_lossy(application_valid);
            });

        rx
    }
}

impl<E, A, B, C, Z, S, ES> Automaton for Marshaled<E, A, B, C, Z, S, ES>
where
    E: Rng + Storage + Spawner + Metrics + Clock,
    A: VerifyingApplication<
        E,
        Block = B,
        SigningScheme = Z::Scheme,
        Context = Context<CodingCommitment, <Z::Scheme as CertificateScheme>::PublicKey>,
    >,
    B: CertifiableBlock<Context = <A as Application<E>>::Context>,
    C: CodingScheme,
    Z: Provider<Scope = Epoch, Scheme: Scheme<CodingCommitment>>,
    S: Strategy,
    ES: Epocher,
{
    type Digest = CodingCommitment;
    type Context = Context<Self::Digest, <Z::Scheme as CertificateScheme>::PublicKey>;

    /// Returns the genesis digest for a given epoch.
    ///
    /// For epoch 0, this returns the application's genesis block digest. For subsequent
    /// epochs, it returns the digest of the last block from the previous epoch, which
    /// serves as the genesis block for the new epoch.
    ///
    /// # Panics
    ///
    /// Panics if a non-zero epoch is requested but the previous epoch's final block is not
    /// available in storage. This indicates a critical error in the consensus engine startup
    /// sequence, as engines must always have the genesis block before starting.
    async fn genesis(&mut self, epoch: Epoch) -> Self::Digest {
        let Some(previous_epoch) = epoch.previous() else {
            let genesis_block = self.application.genesis().await;
            return genesis_coding_commitment(&genesis_block);
        };

        let last_height = self
            .epocher
            .last(previous_epoch)
            .expect("previous epoch should exist");
        let Some(block) = self.marshal.get_block(last_height).await else {
            // A new consensus engine will never be started without having the genesis block
            // of the new epoch (the last block of the previous epoch) already stored.
            unreachable!("missing starting epoch block at height {last_height}");
        };
        block.commitment()
    }

    /// Proposes a new block or re-proposes the epoch boundary block.
    ///
    /// This method builds a new block from the underlying application unless the parent block
    /// is the last block in the current epoch. When at an epoch boundary, it re-proposes the
    /// boundary block to avoid creating blocks that would be invalidated by the epoch transition.
    ///
    /// The proposal operation is spawned in a background task and returns a receiver that will
    /// contain the proposed block's digest when ready. The built block is cached for later
    /// broadcasting.
    async fn propose(
        &mut self,
        consensus_context: Context<CodingCommitment, <Z::Scheme as CertificateScheme>::PublicKey>,
    ) -> oneshot::Receiver<Self::Digest> {
        let mut marshal = self.marshal.clone();
        let mut application = self.application.clone();
        let last_built = self.last_built.clone();
        let epocher = self.epocher.clone();
        let strategy = self.strategy.clone();
        let cached_genesis = self.cached_genesis.clone();

        // If there's no scheme for the current epoch, we cannot verify the proposal.
        // Send back a receiver with a dropped sender.
        let Some(scheme) = self.scheme_provider.scoped(consensus_context.epoch()) else {
            let (_, rx) = oneshot::channel();
            return rx;
        };

        let n_participants =
            u16::try_from(scheme.participants().len()).expect("too many participants");
        let coding_config = coding_config_for_participants(n_participants);

        // Metrics
        let build_duration = self.build_duration.clone();
        let proposal_parent_fetch_duration = self.proposal_parent_fetch_duration.clone();
        let erasure_encode_duration = self.erasure_encode_duration.clone();

        let (mut tx, rx) = oneshot::channel();
        self.context
            .with_label("propose")
            .with_attribute("round", consensus_context.round)
            .spawn(move |runtime_context| async move {
                let (parent_view, parent_commitment) = consensus_context.parent;
                let parent_request = fetch_parent(
                    parent_commitment,
                    Some(Round::new(consensus_context.epoch(), parent_view)),
                    &mut application,
                    &mut marshal,
                    cached_genesis,
                )
                .await;

                let start = Instant::now();
                let parent = select! {
                    _ = tx.closed() => {
                        debug!(reason = "consensus dropped receiver", "skipping proposal");
                        return;
                    },
                    result = parent_request => match result {
                        Ok(parent) => parent,
                        Err(_) => {
                            debug!(
                                ?parent_commitment,
                                reason = "failed to fetch parent block",
                                "skipping proposal"
                            );
                            return;
                        }
                    },
                };
                let _ = proposal_parent_fetch_duration.try_set(start.elapsed().as_millis());

                // Special case: If the parent block is the last block in the epoch,
                // re-propose it as to not produce any blocks that will be cut out
                // by the epoch transition.
                let last_in_epoch = epocher
                    .last(consensus_context.epoch())
                    .expect("current epoch should exist");
                if parent.height() == last_in_epoch {
                    let commitment = parent.commitment();
                    {
                        let mut lock = last_built.lock().await;
                        *lock = Some((consensus_context.round, parent));
                    }

                    let success = tx.send_lossy(commitment);
                    debug!(
                        round = ?consensus_context.round,
                        ?commitment,
                        success,
                        "re-proposed parent block at epoch boundary"
                    );
                    return;
                }

                let ancestor_stream = AncestorStream::new(marshal.clone(), [parent.into_inner()]);
                let build_request = application.propose(
                    (
                        runtime_context.with_label("app_propose"),
                        consensus_context.clone(),
                    ),
                    ancestor_stream,
                );

                let start = Instant::now();
                let built_block = select! {
                    _ = tx.closed() => {
                        debug!(reason = "consensus dropped receiver", "skipping proposal");
                        return;
                    },
                    result = build_request => match result {
                        Some(block) => block,
                        None => {
                            debug!(
                                ?parent_commitment,
                                reason = "block building failed",
                                "skipping proposal"
                            );
                            return;
                        }
                    },
                };
                let _ = build_duration.try_set(start.elapsed().as_millis());

                let start = Instant::now();
                let coded_block = CodedBlock::<B, C>::new(built_block, coding_config, &strategy);
                erasure_encode_duration.observe(start.elapsed().as_secs_f64());

                let commitment = coded_block.commitment();
                {
                    let mut lock = last_built.lock().await;
                    *lock = Some((consensus_context.round, coded_block));
                }

                let success = tx.send_lossy(commitment);
                debug!(
                    round = ?consensus_context.round,
                    ?commitment,
                    success,
                    "proposed new block"
                );
            });
        rx
    }

    /// Verifies a received shard for a given round.
    ///
    /// This method validates that:
    /// 1. The coding configuration matches the expected configuration for the current scheme.
    /// 2. The commitment's context hash matches the consensus context (unless this is a re-proposal).
    /// 3. The shard is contained within the consensus commitment.
    ///
    /// Verification is spawned in a background task and returns a receiver that will contain
    /// the verification result. Additionally, this method kicks off deferred verification to
    /// start block verification early (hidden behind shard validity and network latency).
    async fn verify(
        &mut self,
        context: Context<Self::Digest, <Z::Scheme as CertificateScheme>::PublicKey>,
        payload: Self::Digest,
    ) -> oneshot::Receiver<bool> {
        // If there's no scheme for the current epoch, we cannot vote on the proposal.
        // Send back a receiver with a dropped sender.
        let Some(scheme) = self.scheme_provider.scoped(context.epoch()) else {
            let (_, rx) = oneshot::channel();
            return rx;
        };

        let n_participants =
            u16::try_from(scheme.participants().len()).expect("too many participants");
        let coding_config = coding_config_for_participants(n_participants);

        // Short-circuit if the coding configuration does not match what it should be
        // with the current scheme.
        if coding_config != payload.config() {
            warn!(
                round = %context.round,
                got = ?payload.config(),
                expected = ?coding_config,
                "rejected proposal with unexpected coding configuration"
            );

            let (tx, rx) = oneshot::channel();
            tx.send_lossy(false);
            return rx;
        }

        // Re-proposals skip context-hash validation because the consensus context will point
        // at the prior epoch-boundary block while the embedded block context is from the
        // original proposal view.
        //
        // Re-proposals also skip shard-validity and deferred verification because:
        // 1. The block was already verified when originally proposed
        // 2. The parent-child height check would fail (parent IS the block)
        // 3. Waiting for shards could stall if the leader doesn't rebroadcast
        let is_reproposal = payload == context.parent.1;
        if is_reproposal {
            // Fetch the block to verify it's at the epoch boundary.
            // This should be fast since the parent block is typically already cached.
            let block_rx = self
                .marshal
                .subscribe_by_commitment(Some(context.round), payload)
                .await;
            let mut marshal = self.marshal.clone();
            let epocher = self.epocher.clone();
            let round = context.round;
            let block_digest: B::Digest = payload.block_digest();
            let verification_tasks = Arc::clone(&self.verification_tasks);

            // Register a verification task synchronously before spawning work so
            // `certify` can always find it (no race with task startup).
            let (task_tx, task_rx) = oneshot::channel();
            verification_tasks
                .lock()
                .await
                .insert((round, block_digest), task_rx);

            let (mut tx, rx) = oneshot::channel();
            self.context
                .with_label("verify_reproposal")
                .spawn(move |_| async move {
                    let block = select! {
                        _ = tx.closed() => {
                            debug!(
                                reason = "consensus dropped receiver",
                                "skipping re-proposal verification"
                            );
                            return;
                        },
                        block = block_rx => match block {
                            Ok(block) => block,
                            Err(_) => {
                                debug!(
                                    ?payload,
                                    reason = "failed to fetch block for re-proposal verification",
                                    "skipping re-proposal verification"
                                );
                                task_tx.send_lossy(false);
                                tx.send_lossy(false);
                                return;
                            }
                        },
                    };

                    if !is_at_epoch_boundary(&epocher, block.height(), round.epoch()) {
                        debug!(
                            height = %block.height(),
                            "re-proposal is not at epoch boundary"
                        );
                        task_tx.send_lossy(false);
                        tx.send_lossy(false);
                        return;
                    }

                    // Valid re-proposal. Notify the marshal and complete the
                    // verification task for `certify`.
                    marshal.verified(round, block).await;
                    task_tx.send_lossy(true);
                    tx.send_lossy(true);
                });
            return rx;
        }

        let expected = context_hash(&context);
        let got = payload.context_digest::<Sha256Digest>();
        if expected != got {
            warn!(
                round = %context.round,
                expected = ?expected,
                got = ?got,
                "rejected proposal with mismatched context hash"
            );

            let (tx, rx) = oneshot::channel();
            tx.send_lossy(false);
            return rx;
        }

        // Inform the shard engine of an externally proposed commitment.
        self.shards
            .external_proposed(payload, context.leader.clone(), context.round.view())
            .await;

        // Kick off deferred verification early to hide verification latency behind
        // shard validity checks and network latency for collecting votes.
        let round = context.round;
        let task = self.deferred_verify(context, payload, None).await;
        let block_digest: B::Digest = payload.block_digest();
        self.verification_tasks
            .lock()
            .await
            .insert((round, block_digest), task);

        match scheme.me() {
            Some(_) => {
                // Subscribe to shard validity. The subscription completes when a valid shard arrives.
                let validity_rx = self.shards.subscribe_shard(payload).await;
                let (tx, rx) = oneshot::channel();
                self.context.clone().spawn(|_| async move {
                    if validity_rx.await.is_ok() {
                        tx.send_lossy(true);
                    }
                });
                rx
            }
            None => {
                // If we are not participating, there's no shard to verify; just accept the proposal.
                //
                // Later, when certifying, we will wait to receive the block from the network.
                let (tx, rx) = oneshot::channel();
                tx.send_lossy(true);
                rx
            }
        }
    }
}

impl<E, A, B, C, Z, S, ES> CertifiableAutomaton for Marshaled<E, A, B, C, Z, S, ES>
where
    E: Rng + Storage + Spawner + Metrics + Clock,
    A: VerifyingApplication<
        E,
        Block = B,
        SigningScheme = Z::Scheme,
        Context = Context<CodingCommitment, <Z::Scheme as CertificateScheme>::PublicKey>,
    >,
    B: CertifiableBlock<Context = <A as Application<E>>::Context>,
    C: CodingScheme,
    Z: Provider<Scope = Epoch, Scheme: Scheme<CodingCommitment>>,
    S: Strategy,
    ES: Epocher,
{
    async fn certify(&mut self, round: Round, payload: Self::Digest) -> oneshot::Receiver<bool> {
        let block_digest: B::Digest = payload.block_digest();

        // First, check for an in-progress verification task from `verify()`.
        let mut tasks_guard = self.verification_tasks.lock().await;
        let task = tasks_guard.remove(&(round, block_digest));
        drop(tasks_guard);
        if let Some(task) = task {
            return task;
        }

        // No in-progress task means we never verified this proposal locally.
        // We can use the block's embedded context to move to the next view. If a Byzantine
        // proposer embedded a malicious context, the f+1 honest validators from the notarizing quorum
        // will verify against the proper context and reject the mismatch, preventing a 2f+1
        // finalization quorum.
        //
        // Subscribe to the block and verify using its embedded context once available.
        debug!(
            ?round,
            ?payload,
            "subscribing to block for certification using embedded context"
        );
        let block_rx = self
            .marshal
            .subscribe_by_commitment(Some(round), payload)
            .await;
        let mut marshaled = self.clone();
        let mut shards = self.shards.clone();
        let (mut tx, rx) = oneshot::channel();
        self.context
            .with_label("certify")
            .with_attribute("round", round)
            .spawn(move |_| async move {
                let block = select! {
                    _ = tx.closed() => {
                        debug!(
                            reason = "consensus dropped receiver",
                            "skipping certification"
                        );
                        return;
                    },
                    result = block_rx => match result {
                        Ok(block) => block,
                        Err(_) => {
                            debug!(
                                ?payload,
                                reason = "failed to fetch block for certification",
                                "skipping certification"
                            );
                            return;
                        }
                    },
                };

                // Re-proposal detection for certify path: we don't have the consensus
                // context, only the block's embedded context from original proposal.
                // Infer re-proposal from:
                // 1. Block is at epoch boundary (only boundary blocks can be re-proposed)
                // 2. Certification round's view > embedded context's view (re-proposals
                //    retain their original embedded context, so a later view indicates
                //    the block was re-proposed)
                // 3. Same epoch (re-proposals don't cross epoch boundaries)
                let embedded_context = block.context();
                let is_reproposal = is_at_epoch_boundary(
                    &marshaled.epocher,
                    block.height(),
                    embedded_context.round.epoch(),
                ) && round.view() > embedded_context.round.view()
                    && round.epoch() == embedded_context.round.epoch();
                if is_reproposal {
                    // NOTE: It is possible that, during crash recovery, we call
                    // `marshal.verified` twice for the same block. That function is
                    // idempotent, so this is safe.
                    marshaled.marshal.verified(round, block).await;
                    tx.send_lossy(true);
                    return;
                }

                // Inform the shard engine of an externally proposed commitment.
                shards
                    .external_proposed(payload, embedded_context.leader.clone(), round.view())
                    .await;

                // Use the block's embedded context for verification, passing the
                // prefetched block to avoid fetching it again inside deferred_verify.
                let verify_rx = marshaled
                    .deferred_verify(embedded_context, payload, Some(block))
                    .await;
                if let Ok(result) = verify_rx.await {
                    tx.send_lossy(result);
                }
            });
        rx
    }
}

impl<E, A, B, C, Z, S, ES> Relay for Marshaled<E, A, B, C, Z, S, ES>
where
    E: Rng + Storage + Spawner + Metrics + Clock,
    A: Application<
        E,
        Block = B,
        Context = Context<CodingCommitment, <Z::Scheme as CertificateScheme>::PublicKey>,
    >,
    B: CertifiableBlock<Context = <A as Application<E>>::Context>,
    C: CodingScheme,
    Z: Provider<Scope = Epoch, Scheme: Scheme<CodingCommitment>>,
    S: Strategy,
    ES: Epocher,
{
    type Digest = CodingCommitment;

    /// Broadcasts a previously built block to the network.
    ///
    /// This uses the cached block from the last proposal operation. If no block was built or
    /// the digest does not match the cached block, the broadcast is skipped with a warning.
    async fn broadcast(&mut self, commitment: Self::Digest) {
        let Some((round, block)) = self.last_built.lock().await.clone() else {
            warn!("missing block to broadcast");
            return;
        };

        if block.commitment() != commitment {
            warn!(
                round = %round,
                commitment = %block.commitment(),
                height = %block.height(),
                "skipping requested broadcast of block with mismatched commitment"
            );
            return;
        }

        debug!(
            round = %round,
            commitment = %block.commitment(),
            height = %block.height(),
            "requested broadcast of built block"
        );

        self.shards.proposed(block).await;
    }
}

impl<E, A, B, C, Z, S, ES> Reporter for Marshaled<E, A, B, C, Z, S, ES>
where
    E: Rng + Storage + Spawner + Metrics + Clock,
    A: Application<
            E,
            Block = B,
            Context = Context<CodingCommitment, <Z::Scheme as CertificateScheme>::PublicKey>,
        > + Reporter<Activity = Update<B>>,
    B: CertifiableBlock<Context = <A as Application<E>>::Context>,
    C: CodingScheme,
    Z: Provider<Scope = Epoch, Scheme: Scheme<CodingCommitment>>,
    S: Strategy,
    ES: Epocher,
{
    type Activity = A::Activity;

    /// Relays a report to the underlying [`Application`] and cleans up old verification data.
    async fn report(&mut self, update: Self::Activity) {
        // Clean up verification tasks and contexts for rounds <= the finalized round.
        if let Update::Tip(round, _, _) = &update {
            // Clean up in-memory verification tasks
            let mut tasks_guard = self.verification_tasks.lock().await;
            tasks_guard.retain(|(task_round, _), _| task_round > round);
            drop(tasks_guard);
        }
        self.application.report(update).await
    }
}

/// Fetches the parent block given its digest and optional round.
///
/// This is a helper function used during proposal and verification to retrieve the parent
/// block. If the parent digest matches the genesis block, it returns the genesis block
/// directly without querying the marshal. Otherwise, it subscribes to the marshal to await
/// the parent block's availability.
///
/// Returns an error if the marshal subscription is cancelled.
async fn fetch_parent<E, S, A, B, C>(
    parent_commitment: CodingCommitment,
    parent_round: Option<Round>,
    application: &mut A,
    marshal: &mut core::Mailbox<S, Coding<B, C, S::PublicKey>>,
    cached_genesis: Arc<OnceLock<(CodingCommitment, CodedBlock<B, C>)>>,
) -> Either<
    Ready<Result<CodedBlock<B, C>, oneshot::error::RecvError>>,
    oneshot::Receiver<CodedBlock<B, C>>,
>
where
    E: Rng + Spawner + Metrics + Clock,
    S: CertificateScheme,
    A: Application<E, Block = B, Context = Context<CodingCommitment, S::PublicKey>>,
    B: CertifiableBlock,
    C: CodingScheme,
{
    if cached_genesis.get().is_none() {
        let genesis = application.genesis().await;
        let genesis_coding_commitment = genesis_coding_commitment(&genesis);
        let coded_genesis = CodedBlock::<B, C>::new_trusted(genesis, genesis_coding_commitment);
        let _ = cached_genesis.set((genesis_coding_commitment, coded_genesis));
    }

    let (genesis_commitment, coded_genesis) = cached_genesis
        .get()
        .expect("genesis cache should be initialized");
    if parent_commitment == *genesis_commitment {
        Either::Left(futures::future::ready(Ok(coded_genesis.clone())))
    } else {
        Either::Right(
            marshal
                .subscribe_by_commitment(parent_round, parent_commitment)
                .await,
        )
    }
}

/// Constructs the [`CodingCommitment`] for the genesis block.
fn genesis_coding_commitment<B: CertifiableBlock>(block: &B) -> CodingCommitment {
    CodingCommitment::from((
        block.digest(),
        block.digest(),
        context_hash(&block.context()),
        GENESIS_CODING_CONFIG,
    ))
}
