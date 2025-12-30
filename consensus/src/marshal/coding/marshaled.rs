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
//! participants. When verifying a proposed block (the precondition for notarization), the wrapper subscribes
//! to the shard validity for the shard received by the proposer. If the shard is valid, the local shard
//! is relayed to all other participants to aid in block reconstruction.
//!
//! During certification (the phase between notarization and finalization), the wrapper subscribes to
//! block reconstruction and validates epoch boundaries, parent commitment, and height contiguity before
//! allowing the block to be certified.
//!
//! # Usage
//!
//! Wrap your [`VerifyingApplication`] implementation with [`Marshaled::init`] and provide it to your
//! consensus engine for the [`Automaton`] and [`Relay`]. The wrapper handles all epoch logic transparently.
//!
//! ```rust,ignore
//! let cfg = MarshaledConfig {
//!     application: my_application,
//!     marshal: marshal_mailbox,
//!     shards: shard_mailbox,
//!     scheme_provider,
//!     epocher,
//!     concurrency,
//!     partition_prefix,
//! };
//! let application = Marshaled::init(context, cfg).await;
//! ```
//!
//! # Implementation Notes
//!
//! - Genesis blocks are handled specially: epoch 0 returns the application's genesis block,
//!   while subsequent epochs use the last block of the previous epoch as genesis
//! - Blocks are automatically verified to be within the current epoch

use crate::{
    marshal::{
        ancestry::AncestorStream,
        coding::{
            self, shards,
            types::{coding_config_for_participants, CodedBlock, DigestOrCommitment},
        },
        Update,
    },
    simplex::{scheme::Scheme, types::Context},
    types::{CodingCommitment, Epoch, Epocher, Round},
    Application, Automaton, Block, CertifiableAutomaton, Epochable, Relay, Reporter,
    VerifyingApplication,
};
use commonware_codec::RangeCfg;
use commonware_coding::{Config as CodingConfig, Scheme as CodingScheme};
use commonware_cryptography::{
    certificate::{Provider, Scheme as CertificateScheme},
    Committable, Digestible,
};
use commonware_runtime::{telemetry::metrics::status::GaugeExt, Clock, Metrics, Spawner, Storage};
use commonware_storage::metadata::{self, Metadata};
use commonware_utils::futures::ClosedExt;
use futures::{
    channel::oneshot::{self, Canceled},
    future::{select, try_join, Either, Ready},
    lock::Mutex,
    pin_mut,
};
use prometheus_client::metrics::gauge::Gauge;
use rand::Rng;
use std::{collections::BTreeMap, sync::Arc, time::Instant};
use tracing::{debug, warn};

/// The [`CodingConfig`] used for genesis blocks. These blocks are never broadcasted in
/// the proposal phase, and thus the configuration is irrelevant.
const GENESIS_CODING_CONFIG: CodingConfig = CodingConfig {
    minimum_shards: 0,
    extra_shards: 0,
};

type VerificationContexts<E, B, Z> = Metadata<
    E,
    <B as Digestible>::Digest,
    BTreeMap<
        Round,
        Context<CodingCommitment, <<Z as Provider>::Scheme as CertificateScheme>::PublicKey>,
    >,
>;

/// Configuration for initializing [`Marshaled`].
pub struct MarshaledConfig<A, B, C, Z, ES>
where
    B: Block,
    C: CodingScheme,
    Z: Provider<Scope = Epoch, Scheme: Scheme<CodingCommitment>>,
    ES: Epocher,
{
    /// The underlying application to wrap.
    pub application: A,
    /// Mailbox for communicating with the marshal engine.
    pub marshal: coding::Mailbox<Z::Scheme, B, C>,
    /// Mailbox for communicating with the shards engine.
    pub shards: shards::Mailbox<B, Z::Scheme, C, <Z::Scheme as CertificateScheme>::PublicKey>,
    /// Provider for signing schemes scoped by epoch.
    pub scheme_provider: Z,
    /// Strategy for determining epoch boundaries.
    pub epocher: ES,
    /// Number of threads to use for erasure encoding.
    pub concurrency: usize,
    /// Prefix for storage partitions.
    pub partition_prefix: String,
}

/// An [`Application`] adapter that handles epoch transitions and erasure coded broadcast.
///
/// This wrapper intercepts consensus operations to enforce epoch boundaries. It prevents
/// blocks from being produced outside their valid epoch and handles the special case of
/// re-proposing boundary blocks during epoch transitions.
#[derive(Clone)]
pub struct Marshaled<E, A, B, C, Z, ES>
where
    E: Rng + Storage + Spawner + Metrics + Clock,
    A: Application<E>,
    B: Block,
    C: CodingScheme,
    Z: Provider<Scope = Epoch, Scheme: Scheme<CodingCommitment>>,
    ES: Epocher,
{
    context: E,
    application: A,
    marshal: coding::Mailbox<Z::Scheme, B, C>,
    shards: shards::Mailbox<B, Z::Scheme, C, <Z::Scheme as CertificateScheme>::PublicKey>,
    scheme_provider: Z,
    epocher: ES,
    concurrency: usize,
    #[allow(clippy::type_complexity)]
    last_built: Arc<Mutex<Option<(Round, CodedBlock<B, C>)>>>,
    verification_contexts: Arc<Mutex<VerificationContexts<E, B, Z>>>,
    certification_txs: Arc<Mutex<Vec<oneshot::Sender<bool>>>>,

    build_duration: Gauge,
    verify_duration: Gauge,
    proposal_parent_fetch_duration: Gauge,
    erasure_encode_duration: Gauge,
}

impl<E, A, B, C, Z, ES> Marshaled<E, A, B, C, Z, ES>
where
    E: Rng + Storage + Spawner + Metrics + Clock,
    A: VerifyingApplication<
        E,
        Block = B,
        SigningScheme = Z::Scheme,
        Context = Context<CodingCommitment, <Z::Scheme as CertificateScheme>::PublicKey>,
    >,
    B: Block,
    C: CodingScheme,
    Z: Provider<Scope = Epoch, Scheme: Scheme<CodingCommitment>>,
    ES: Epocher,
{
    /// Creates a new [`Marshaled`] wrapper.
    ///
    /// # Panics
    ///
    /// Panics if the verification contexts [`Metadata`] store cannot be initialized.
    pub async fn init(context: E, cfg: MarshaledConfig<A, B, C, Z, ES>) -> Self {
        let MarshaledConfig {
            application,
            marshal,
            shards,
            scheme_provider,
            epocher,
            concurrency,
            partition_prefix,
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

        let erasure_encode_duration = Gauge::default();
        context.register(
            "erasure_encode_duration",
            "Time taken to erasure encode a block, in milliseconds",
            erasure_encode_duration.clone(),
        );

        let verification_contexts = Metadata::init(
            context.with_label("verification_contexts_metadata"),
            metadata::Config {
                partition: format!("{partition_prefix}_verification_contexts"),
                // BTreeMap codec config: (RangeCfg<usize> for length, (Round::Cfg, Context::Cfg))
                codec_config: (RangeCfg::from(..), ((), ())),
            },
        )
        .await
        .expect("must initialize verification contexts metadata");

        Self {
            context,
            application,
            marshal,
            shards,
            scheme_provider,
            epocher,
            concurrency,
            last_built: Arc::new(Mutex::new(None)),
            verification_contexts: Arc::new(Mutex::new(verification_contexts)),
            certification_txs: Arc::new(Mutex::new(Vec::new())),

            build_duration,
            verify_duration,
            proposal_parent_fetch_duration,
            erasure_encode_duration,
        }
    }

    /// Store a verification context for later use in certification.
    ///
    /// # Panics
    ///
    /// Panics if the verification context cannot be persisted.
    #[inline]
    async fn store_verification_context(
        lock: &Arc<Mutex<VerificationContexts<E, B, Z>>>,
        context: Context<CodingCommitment, <Z::Scheme as CertificateScheme>::PublicKey>,
        block_digest: B::Digest,
    ) {
        let round = context.round;
        let mut contexts_guard = lock.lock().await;
        contexts_guard
            .upsert_sync(block_digest, |map| {
                map.insert(round, context);
            })
            .await
            .expect("must persist verification context");
    }

    /// Verifies a proposed block within epoch boundaries.
    ///
    /// This method validates that:
    /// 1. The block is within the current epoch (unless it's a boundary block re-proposal)
    /// 2. Re-proposals are only allowed for the last block in an epoch
    /// 3. The block's parent digest matches the consensus context's expected parent
    /// 4. The block's height is exactly one greater than the parent's height
    /// 5. The underlying application's verification logic passes
    ///
    /// Verification is spawned in a background task and returns a receiver that will contain
    /// the verification result. Valid blocks are reported to the marshal as verified.
    #[inline]
    async fn verify_block(
        &mut self,
        context: Context<CodingCommitment, <Z::Scheme as CertificateScheme>::PublicKey>,
        commitment: CodingCommitment,
    ) -> oneshot::Receiver<bool> {
        let mut shards = self.shards.clone();
        let mut marshal = self.marshal.clone();
        let mut application = self.application.clone();
        let epocher = self.epocher.clone();
        let verify_duration = self.verify_duration.clone();
        let verification_contexts = self.verification_contexts.clone();

        let (mut tx, rx) = oneshot::channel();
        self.context
            .with_label("verify")
            .spawn(move |runtime_context| async move {
                let tx_closed = tx.closed();
                pin_mut!(tx_closed);

                // Extract values needed for cleanup before any moves
                let block_digest: B::Digest = commitment.block_digest();
                let round = context.round;

                // Helper to clean up verification context for this round
                let cleanup = || async {
                    let mut contexts_guard = verification_contexts.lock().await;
                    if contexts_guard.get(&block_digest).is_some() {
                        let mut is_empty = false;
                        contexts_guard.upsert(block_digest, |map| {
                            map.remove(&round);
                            is_empty = map.is_empty();
                        });
                        if is_empty {
                            contexts_guard.remove(&block_digest);
                        }
                        // Sync is best-effort; failure just means stale data after crash
                        let _ = contexts_guard.sync().await;
                    }
                };

                let (parent_view, parent_commitment) = context.parent;
                let parent_request = fetch_parent(
                    parent_commitment,
                    Some(Round::new(context.epoch(), parent_view)),
                    &mut application,
                    &mut marshal,
                )
                .await;
                let block_request = shards
                    .subscribe_block(DigestOrCommitment::Commitment(commitment))
                    .await;
                let block_requests = try_join(parent_request, block_request);
                pin_mut!(block_requests);

                let (parent, block) = match select(block_requests, &mut tx_closed).await {
                    Either::Left((Ok(parent), _)) => parent,
                    Either::Left((Err(_), _)) => {
                        debug!(
                            reason = "failed to fetch parent or block",
                            "skipping verification"
                        );
                        return;
                    }
                    Either::Right(_) => {
                        debug!(
                            reason = "consensus dropped receiver",
                            "skipping verification"
                        );
                        return;
                    }
                };

                // Re-proposal check: same block can only be re-proposed at epoch boundary
                if parent.commitment() == block.commitment() {
                    let last_in_epoch = epocher
                        .last(context.epoch())
                        .expect("current epoch should exist");
                    cleanup().await;
                    let _ = tx.send(block.height() == last_in_epoch);
                    return;
                }

                // Epoch boundary check
                let Some(block_bounds) = epocher.containing(block.height()) else {
                    debug!(
                        height = block.height(),
                        "block height not covered by epoch strategy"
                    );
                    cleanup().await;
                    let _ = tx.send(false);
                    return;
                };
                if block_bounds.epoch() != context.epoch() {
                    cleanup().await;
                    let _ = tx.send(false);
                    return;
                }

                // Validate that the block's parent digest matches what consensus expects.
                if block.parent() != parent.digest() {
                    debug!(
                        block_parent = %block.parent(),
                        expected_parent = %parent.digest(),
                        "block parent digest does not match expected parent"
                    );
                    cleanup().await;
                    let _ = tx.send(false);
                    return;
                }

                // Validate that heights are contiguous.
                if parent.height().checked_add(1) != Some(block.height()) {
                    debug!(
                        parent_height = parent.height(),
                        block_height = block.height(),
                        "block height is not contiguous with parent height"
                    );
                    cleanup().await;
                    let _ = tx.send(false);
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
                pin_mut!(validity_request);

                // If consensus drops the rceiver, we can stop work early.
                let start = Instant::now();
                let application_valid = match select(validity_request, &mut tx_closed).await {
                    Either::Left((is_valid, _)) => is_valid,
                    Either::Right(_) => {
                        debug!(
                            reason = "consensus dropped receiver",
                            "skipping verification"
                        );
                        return;
                    }
                };
                let _ = verify_duration.try_set(start.elapsed().as_millis());
                cleanup().await;
                let _ = tx.send(application_valid);
            });

        rx
    }
}

impl<E, A, B, C, Z, ES> Automaton for Marshaled<E, A, B, C, Z, ES>
where
    E: Rng + Storage + Spawner + Metrics + Clock,
    A: VerifyingApplication<
        E,
        Block = B,
        SigningScheme = Z::Scheme,
        Context = Context<CodingCommitment, <Z::Scheme as CertificateScheme>::PublicKey>,
    >,
    B: Block,
    C: CodingScheme,
    Z: Provider<Scope = Epoch, Scheme: Scheme<CodingCommitment>>,
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
        if epoch.is_zero() {
            let genesis_block = self.application.genesis().await;
            return genesis_coding_commitment(&genesis_block);
        }

        let prev = epoch.previous().expect("checked to be non-zero above");
        let last_height = self
            .epocher
            .last(prev)
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
        let verification_contexts = self.verification_contexts.clone();
        let epocher = self.epocher.clone();
        let concurrency = self.concurrency;

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
            .spawn(move |runtime_context| async move {
                // Create a future for tracking if the receiver is dropped, which could allow
                // us to cancel work early.
                let tx_closed = tx.closed();
                pin_mut!(tx_closed);

                let (parent_view, parent_commitment) = consensus_context.parent;
                let parent_request = fetch_parent(
                    parent_commitment,
                    Some(Round::new(consensus_context.epoch(), parent_view)),
                    &mut application,
                    &mut marshal,
                )
                .await;
                pin_mut!(parent_request);

                let start = Instant::now();
                let parent = match select(parent_request, &mut tx_closed).await {
                    Either::Left((Ok(parent), _)) => parent,
                    Either::Left((Err(_), _)) => {
                        debug!(
                            ?parent_commitment,
                            reason = "failed to fetch parent block",
                            "skipping proposal"
                        );
                        return;
                    }
                    Either::Right(_) => {
                        debug!(reason = "consensus dropped receiver", "skipping proposal");
                        return;
                    }
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

                    Self::store_verification_context(
                        &verification_contexts,
                        consensus_context.clone(),
                        commitment.block_digest(),
                    )
                    .await;

                    let result = tx.send(commitment);
                    debug!(
                        round = ?consensus_context.round,
                        ?commitment,
                        success = result.is_ok(),
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
                pin_mut!(build_request);

                let start = Instant::now();
                let built_block = match select(build_request, &mut tx_closed).await {
                    Either::Left((Some(block), _)) => block,
                    Either::Left((None, _)) => {
                        debug!(
                            ?parent_commitment,
                            reason = "block building failed",
                            "skipping proposal"
                        );
                        return;
                    }
                    Either::Right(_) => {
                        debug!(reason = "consensus dropped receiver", "skipping proposal");
                        return;
                    }
                };
                let _ = build_duration.try_set(start.elapsed().as_millis());

                let start = Instant::now();
                let coded_block = CodedBlock::<B, C>::new(built_block, coding_config, concurrency);
                let _ = erasure_encode_duration.try_set(start.elapsed().as_millis());

                let commitment = coded_block.commitment();
                {
                    let mut lock = last_built.lock().await;
                    *lock = Some((consensus_context.round, coded_block));
                }

                Self::store_verification_context(
                    &verification_contexts,
                    consensus_context.clone(),
                    commitment.block_digest(),
                )
                .await;

                let result = tx.send(commitment);
                debug!(
                    round = ?consensus_context.round,
                    ?commitment,
                    success = result.is_ok(),
                    "proposed new block"
                );
            });
        rx
    }

    /// Verifies a received shard for a given round.
    ///
    /// This method validates that:
    /// 1. The coding configuration matches the expected configuration for the current scheme.
    /// 2. The shard is contained within the consensus commitment.
    ///
    /// Verification is spawned in a background task and returns a receiver that will contain
    /// the verification result.
    async fn verify(
        &mut self,
        context: Context<Self::Digest, <Z::Scheme as CertificateScheme>::PublicKey>,
        payload: Self::Digest,
    ) -> oneshot::Receiver<bool> {
        // Store context for later certification, keyed by the block digest
        let block_digest: B::Digest = payload.block_digest();
        Self::store_verification_context(
            &self.verification_contexts,
            context.clone(),
            block_digest,
        )
        .await;

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
            let _ = tx.send(false);
            return rx;
        }

        match scheme.me() {
            Some(me) => {
                self.shards
                    .subscribe_shard_validity(payload, me as usize)
                    .await
            }
            None => {
                // If we are not participating, there's no shard to verify; just accept the proposal.
                //
                // Later, when certifying, we will be waiting for a quorum of shard validities
                // that we won't contribute to, but we will still be able to recover the block.
                let (tx, rx) = oneshot::channel();
                let _ = tx.send(true);
                rx
            }
        }
    }
}

impl<E, A, B, C, Z, ES> CertifiableAutomaton for Marshaled<E, A, B, C, Z, ES>
where
    E: Rng + Storage + Spawner + Metrics + Clock,
    A: VerifyingApplication<
        E,
        Block = B,
        SigningScheme = Z::Scheme,
        Context = Context<CodingCommitment, <Z::Scheme as CertificateScheme>::PublicKey>,
    >,
    B: Block,
    C: CodingScheme,
    Z: Provider<Scope = Epoch, Scheme: Scheme<CodingCommitment>>,
    ES: Epocher,
{
    async fn certify(&mut self, payload: Self::Digest) -> oneshot::Receiver<bool> {
        // Look up context by block digest extracted from the CodingCommitment
        let block_digest: B::Digest = payload.block_digest();
        let mut contexts_guard = self.verification_contexts.lock().await;
        // Get any context from the map for this block digest
        let context = contexts_guard
            .get_mut(&block_digest)
            .and_then(|map| map.first_entry().map(|v| v.get().clone()));
        drop(contexts_guard);

        if let Some(context) = context {
            self.verify_block(context, payload).await
        } else {
            // Acquire the lock on the certification transactions and store the sender.
            // While we're here, we can also clean up any senders from previous views
            // that consensus is no longer waiting on.
            let (tx, rx) = oneshot::channel();
            let mut txs_guard = self.certification_txs.lock().await;
            txs_guard.retain(|tx| !tx.is_canceled());
            txs_guard.push(tx);
            drop(txs_guard);

            // If we don't have a verification context, we cannot verify the block.
            // In this event, we return a receiver that will never resolve to signal
            // to consensus that we should time out the view and vote to nullify.
            rx
        }
    }
}

impl<E, A, B, C, Z, ES> Relay for Marshaled<E, A, B, C, Z, ES>
where
    E: Rng + Storage + Spawner + Metrics + Clock,
    A: Application<
        E,
        Block = B,
        Context = Context<CodingCommitment, <Z::Scheme as CertificateScheme>::PublicKey>,
    >,
    B: Block,
    C: CodingScheme,
    Z: Provider<Scope = Epoch, Scheme: Scheme<CodingCommitment>>,
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
                height = block.height(),
                "skipping requested broadcast of block with mismatched digest"
            );
            return;
        }

        debug!(
            round = %round,
            commitment = %block.commitment(),
            height = block.height(),
            "requested broadcast of built block"
        );

        let scheme = self
            .scheme_provider
            .scoped(round.epoch())
            .expect("missing scheme for epoch");
        let peers = scheme.participants().iter().cloned().collect();
        self.shards.proposed(block, peers).await;
    }
}

impl<E, A, B, C, Z, ES> Reporter for Marshaled<E, A, B, C, Z, ES>
where
    E: Rng + Storage + Spawner + Metrics + Clock,
    A: Application<
            E,
            Block = B,
            Context = Context<CodingCommitment, <Z::Scheme as CertificateScheme>::PublicKey>,
        > + Reporter<Activity = Update<B>>,
    B: Block,
    C: CodingScheme,
    Z: Provider<Scope = Epoch, Scheme: Scheme<CodingCommitment>>,
    ES: Epocher,
{
    type Activity = A::Activity;

    /// Relays a report to the underlying [`Application`].
    async fn report(&mut self, update: Self::Activity) {
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
#[inline]
async fn fetch_parent<E, S, A, B, C>(
    parent_commitment: CodingCommitment,
    parent_round: Option<Round>,
    application: &mut A,
    marshal: &mut coding::Mailbox<S, B, C>,
) -> Either<Ready<Result<CodedBlock<B, C>, Canceled>>, oneshot::Receiver<CodedBlock<B, C>>>
where
    E: Rng + Spawner + Metrics + Clock,
    S: CertificateScheme,
    A: Application<E, Block = B, Context = Context<CodingCommitment, S::PublicKey>>,
    B: Block,
    C: CodingScheme,
{
    let genesis = application.genesis().await;
    let genesis_coding_commitment = genesis_coding_commitment(&genesis);

    if parent_commitment == genesis_coding_commitment {
        let coded_genesis = CodedBlock::<B, C>::new_trusted(genesis, genesis_coding_commitment);
        Either::Left(futures::future::ready(Ok(coded_genesis)))
    } else {
        Either::Right(
            marshal
                .subscribe(
                    parent_round,
                    DigestOrCommitment::Commitment(parent_commitment),
                )
                .await,
        )
    }
}

/// Constructs the [`CodingCommitment`] for the genesis block.
#[inline(always)]
fn genesis_coding_commitment<B: Block>(block: &B) -> CodingCommitment {
    CodingCommitment::from((block.digest(), block.digest(), GENESIS_CODING_CONFIG))
}
