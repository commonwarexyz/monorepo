//! Wrapper for consensus applications that handles epochs and block dissemination.
//!
//! # Overview
//!
//! [`Marshaled`] is an adapter that wraps any [`VerifyingApplication`] implementation to handle
//! epoch transitions automatically. It intercepts consensus operations (propose, verify) and
//! ensures blocks are only produced within valid epoch boundaries.
//!
//! # Epoch Boundaries
//!
//! An epoch is a fixed number of blocks (the `epoch_length`). When the last block in an epoch
//! is reached, this wrapper prevents new blocks from being built & proposed until the next epoch begins.
//! Instead, it re-proposes the boundary block to avoid producing blocks that would be pruned
//! by the epoch transition.
//!
//! # Deferred Verification
//!
//! By default, [`Marshaled`] uses deferred verification, optimistically voting in favor
//! of the proposed block but waiting to finalize until verification is complete. In
//! [`Automaton::verify`], verification is started, and in [`CertifiableAutomaton::certify`],
//! we wait on the result (before voting to finalize.)
//!
//! # Usage
//!
//! Wrap your [`Application`] implementation with [`Marshaled::init`] and provide it to your
//! consensus engine for the [`Automaton`] and [`Relay`]. The wrapper handles all epoch logic transparently.
//!
//! ```rust,ignore
//! let application = Marshaled::init(
//!     context,
//!     my_application,
//!     marshal_mailbox,
//!     epocher,
//!     partition_prefix
//! ).await;
//! ```
//!
//! # Implementation Notes
//!
//! - Genesis blocks are handled specially: epoch 0 returns the application's genesis block,
//!   while subsequent epochs use the last block of the previous epoch as genesis
//! - Blocks are automatically verified to be within the current epoch

use crate::{
    marshal::{self, ingress::mailbox::AncestorStream, Update},
    simplex::types::Context,
    types::{Epoch, Epocher, Round},
    Application, Automaton, Block, CertifiableAutomaton, Epochable, Relay, Reporter,
    VerifyingApplication,
};
use commonware_codec::RangeCfg;
use commonware_cryptography::{certificate::Scheme, Committable};
use commonware_runtime::{telemetry::metrics::status::GaugeExt, Clock, Metrics, Spawner, Storage};
use commonware_storage::metadata::{self, Metadata};
use commonware_utils::{channels::fallible::OneshotExt, futures::ClosedExt};
use futures::{
    channel::oneshot::{self, Canceled},
    future::{ready, select, try_join, Either, Ready},
    lock::Mutex,
    pin_mut,
};
use prometheus_client::metrics::gauge::Gauge;
use rand::Rng;
use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
    time::Instant,
};
use tracing::{debug, warn};

type VerificationContexts<E, B, S> = Metadata<
    E,
    <B as Committable>::Commitment,
    BTreeMap<Round, Context<<B as Committable>::Commitment, <S as Scheme>::PublicKey>>,
>;

/// An [`Application`] adapter that handles epoch transitions and validates block ancestry.
///
/// This wrapper intercepts consensus operations to enforce epoch boundaries and validate
/// block ancestry. It prevents blocks from being produced outside their valid epoch,
/// handles the special case of re-proposing boundary blocks during epoch transitions,
/// and ensures all blocks have valid parent linkage and contiguous heights.
///
/// # Ancestry Validation
///
/// Applications wrapped by [`Marshaled`] can rely on the following ancestry checks being
/// performed automatically during verification:
/// - Parent commitment matches the consensus context's expected parent
/// - Block height is exactly one greater than the parent's height
///
/// Verifying only the immediate parent is sufficient since the parent itself must have
/// been notarized by consensus, which guarantees it was verified and accepted by a quorum.
/// This means the entire ancestry chain back to genesis is transitively validated.
///
/// Applications do not need to re-implement these checks in their own verification logic.
#[derive(Clone)]
pub struct Marshaled<E, S, A, B, ES>
where
    E: Rng + Storage + Spawner + Metrics + Clock,
    S: Scheme,
    A: Application<E>,
    B: Block,
    ES: Epocher,
{
    context: E,
    application: A,
    marshal: marshal::Mailbox<S, B>,
    epocher: ES,
    last_built: Arc<Mutex<Option<(Round, B)>>>,
    verification_contexts: Arc<Mutex<VerificationContexts<E, B, S>>>,
    verification_tasks: Arc<Mutex<HashMap<Round, oneshot::Receiver<bool>>>>,

    build_duration: Gauge,
}

impl<E, S, A, B, ES> Marshaled<E, S, A, B, ES>
where
    E: Rng + Storage + Spawner + Metrics + Clock,
    S: Scheme,
    A: VerifyingApplication<
        E,
        Block = B,
        SigningScheme = S,
        Context = Context<B::Commitment, S::PublicKey>,
    >,
    B: Block,
    ES: Epocher,
{
    /// Creates a new [`Marshaled`] wrapper.
    ///
    /// # Panics
    ///
    /// Panics if the verification contexts [`Metadata`] store cannot be initialized.
    pub async fn init(
        context: E,
        application: A,
        marshal: marshal::Mailbox<S, B>,
        epocher: ES,
        partition_prefix: String,
    ) -> Self {
        let build_duration = Gauge::default();
        context.register(
            "build_duration",
            "Time taken for the application to build a new block, in milliseconds",
            build_duration.clone(),
        );

        let verification_contexts = Metadata::init(
            context.with_label("verification_contexts_metadata"),
            metadata::Config {
                partition: format!("{partition_prefix}-verification-contexts"),
                codec_config: (RangeCfg::from(..), ((), ())),
            },
        )
        .await
        .expect("must initialize verification contexts metadata");

        Self {
            context,
            application,
            marshal,
            epocher,
            last_built: Arc::new(Mutex::new(None)),
            verification_contexts: Arc::new(Mutex::new(verification_contexts)),
            verification_tasks: Arc::new(Mutex::new(HashMap::new())),

            build_duration,
        }
    }

    /// Verifies a proposed block within epoch boundaries.
    ///
    /// This method validates that:
    /// 1. The block is within the current epoch (unless it's a boundary block re-proposal)
    /// 2. Re-proposals are only allowed for the last block in an epoch
    /// 3. The block's parent commitment matches the consensus context's expected parent
    /// 4. The block's height is exactly one greater than the parent's height
    /// 5. The underlying application's verification logic passes
    ///
    /// Verification is spawned in a background task and returns a receiver that will contain
    /// the verification result. Valid blocks are reported to the marshal as verified.
    #[inline]
    async fn verify(
        &mut self,
        context: <Self as Automaton>::Context,
        digest: B::Commitment,
    ) -> oneshot::Receiver<bool> {
        let mut marshal = self.marshal.clone();
        let mut application = self.application.clone();
        let epocher = self.epocher.clone();

        let (mut tx, rx) = oneshot::channel();
        self.context
            .with_label("verify")
            .spawn(move |runtime_context| async move {
                // Create a future for tracking if the receiver is dropped, which could allow
                // us to cancel work early.
                let tx_closed = tx.closed();
                pin_mut!(tx_closed);

                let (parent_view, parent_commitment) = context.parent;
                let parent_request = fetch_parent(
                    parent_commitment,
                    Some(Round::new(context.epoch(), parent_view)),
                    &mut application,
                    &mut marshal,
                )
                .await;
                let block_request = marshal.subscribe(None, digest).await;
                let block_requests = try_join(parent_request, block_request);
                pin_mut!(block_requests);

                // If consensus drops the rceiver, we can stop work early.
                let (parent, block) = match select(block_requests, &mut tx_closed).await {
                    Either::Left((Ok((parent, block)), _)) => (parent, block),
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

                // You can only re-propose the same block if it's the last height in the epoch.
                if parent.commitment() == block.commitment() {
                    let last_in_epoch = epocher
                        .last(context.epoch())
                        .expect("current epoch should exist");
                    let is_valid = block.height() == last_in_epoch;
                    if is_valid {
                        marshal.verified(context.round, block).await;
                    }
                    tx.send_lossy(is_valid);
                    return;
                }

                // Blocks are invalid if they are not within the current epoch and they aren't
                // a re-proposal of the boundary block.
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

                // Validate that the block's parent commitment matches what consensus expects.
                if block.parent() != parent.commitment() {
                    debug!(
                        block_parent = %block.parent(),
                        expected_parent = %parent.commitment(),
                        "block parent commitment does not match expected parent"
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

                let ancestry_stream = AncestorStream::new(marshal.clone(), [block.clone(), parent]);
                let validity_request = application.verify(
                    (runtime_context.with_label("app_verify"), context.clone()),
                    ancestry_stream,
                );
                pin_mut!(validity_request);

                // If consensus drops the rceiver, we can stop work early.
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

                if application_valid {
                    marshal.verified(context.round, block).await;
                }
                tx.send_lossy(application_valid);
            });

        rx
    }

    /// Acquire a lock to the verification contexts and store the given context.
    ///
    /// # Panics
    ///
    /// Panics if the verification context cannot be persisted.
    #[inline]
    async fn store_verification_context(
        contexts_lock: &Arc<Mutex<VerificationContexts<E, B, S>>>,
        context: <Self as Automaton>::Context,
        digest: B::Commitment,
    ) {
        contexts_lock
            .lock()
            .await
            .upsert_sync(digest, |map| {
                map.insert(context.round, context);
            })
            .await
            .expect("must persist verification context");
    }
}

impl<E, S, A, B, ES> Automaton for Marshaled<E, S, A, B, ES>
where
    E: Rng + Storage + Spawner + Metrics + Clock,
    S: Scheme,
    A: VerifyingApplication<
        E,
        Block = B,
        SigningScheme = S,
        Context = Context<B::Commitment, S::PublicKey>,
    >,
    B: Block,
    ES: Epocher,
{
    type Digest = B::Commitment;
    type Context = Context<Self::Digest, S::PublicKey>;

    /// Returns the genesis commitment for a given epoch.
    ///
    /// For epoch 0, this returns the application's genesis block commitment. For subsequent
    /// epochs, it returns the commitment of the last block from the previous epoch, which
    /// serves as the genesis block for the new epoch.
    ///
    /// # Panics
    ///
    /// Panics if a non-zero epoch is requested but the previous epoch's final block is not
    /// available in storage. This indicates a critical error in the consensus engine startup
    /// sequence, as engines must always have the genesis block before starting.
    async fn genesis(&mut self, epoch: Epoch) -> Self::Digest {
        if epoch.is_zero() {
            return self.application.genesis().await.commitment();
        }

        let prev = epoch.previous().expect("checked to be non-zero above");
        let last_height = self
            .epocher
            .last(prev)
            .expect("previous epoch should exist");
        let Some(block) = self.marshal.get_block(last_height).await else {
            // A new consensus engine will never be started without having the genesis block
            // of the new epoch (the last block of the previous epoch) already stored.
            unreachable!("missing starting epoch block at height {}", last_height);
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
    /// contain the proposed block's commitment when ready. The built block is cached for later
    /// broadcasting.
    async fn propose(
        &mut self,
        consensus_context: Context<Self::Digest, S::PublicKey>,
    ) -> oneshot::Receiver<Self::Digest> {
        let mut marshal = self.marshal.clone();
        let mut application = self.application.clone();
        let last_built = self.last_built.clone();
        let epocher = self.epocher.clone();
        let verification_contexts = self.verification_contexts.clone();

        // Metrics
        let build_duration = self.build_duration.clone();

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

                // Special case: If the parent block is the last block in the epoch,
                // re-propose it as to not produce any blocks that will be cut out
                // by the epoch transition.
                let last_in_epoch = epocher
                    .last(consensus_context.epoch())
                    .expect("current epoch should exist");
                if parent.height() == last_in_epoch {
                    let digest = parent.commitment();
                    {
                        let mut lock = last_built.lock().await;
                        *lock = Some((consensus_context.round, parent));
                    }

                    Self::store_verification_context(
                        &verification_contexts,
                        consensus_context.clone(),
                        digest,
                    )
                    .await;

                    let success = tx.send_lossy(digest);
                    debug!(
                        round = ?consensus_context.round,
                        ?digest,
                        success,
                        "re-proposed parent block at epoch boundary"
                    );
                    return;
                }

                let ancestor_stream = AncestorStream::new(marshal.clone(), [parent]);
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

                let digest = built_block.commitment();
                {
                    let mut lock = last_built.lock().await;
                    *lock = Some((consensus_context.round, built_block));
                }

                Self::store_verification_context(
                    &verification_contexts,
                    consensus_context.clone(),
                    digest,
                )
                .await;

                let success = tx.send_lossy(digest);
                debug!(
                    round = ?consensus_context.round,
                    ?digest,
                    success,
                    "proposed new block"
                );
            });
        rx
    }

    async fn verify(
        &mut self,
        context: Context<Self::Digest, S::PublicKey>,
        digest: Self::Digest,
    ) -> oneshot::Receiver<bool> {
        Self::store_verification_context(&self.verification_contexts, context.clone(), digest)
            .await;

        // Begin the verification process.
        let round = context.round;
        let task = self.verify(context, digest).await;
        self.verification_tasks.lock().await.insert(round, task);

        let (tx, rx) = oneshot::channel();
        tx.send_lossy(true);
        rx
    }
}

impl<E, S, A, B, ES> CertifiableAutomaton for Marshaled<E, S, A, B, ES>
where
    E: Rng + Storage + Spawner + Metrics + Clock,
    S: Scheme,
    A: VerifyingApplication<
        E,
        Block = B,
        SigningScheme = S,
        Context = Context<B::Commitment, S::PublicKey>,
    >,
    B: Block,
    ES: Epocher,
{
    async fn certify(&mut self, round: Round, payload: Self::Digest) -> oneshot::Receiver<bool> {
        // Attempt to retrieve the existing verification task for this round.
        let mut tasks_guard = self.verification_tasks.lock().await;
        let task = tasks_guard.remove(&round);
        drop(tasks_guard);

        if let Some(task) = task {
            task
        } else {
            // Look up context by (payload, round) to get the exact verification context.
            // This is necessary because the same block may be proposed in multiple rounds
            // (e.g., re-proposals at epoch boundaries), and each round has its own context.
            // We clone rather than remove so the context remains available for crash recovery.
            // Contexts are cleaned up when finalization advances past them (see report()).
            let contexts_guard = self.verification_contexts.lock().await;
            let context = contexts_guard
                .get(&payload)
                .and_then(|map| map.get(&round).cloned());
            drop(contexts_guard);

            if let Some(context) = context {
                self.verify(context, payload).await
            } else {
                // Verify is always called before certify for a given proposal (if we are
                // online and don't see the notarization certificate first), so if we don't
                // have a verification context here, it means this proposal was never verified
                // by us. Return a receiver that never resolves to signal to consensus that
                // we should time out the view and vote to nullify.
                let (_tx, rx) = oneshot::channel();
                rx
            }
        }
    }
}

impl<E, S, A, B, ES> Relay for Marshaled<E, S, A, B, ES>
where
    E: Rng + Storage + Spawner + Metrics + Clock,
    S: Scheme,
    A: Application<E, Block = B, Context = Context<B::Commitment, S::PublicKey>>,
    B: Block,
    ES: Epocher,
{
    type Digest = B::Commitment;

    /// Broadcasts a previously built block to the network.
    ///
    /// This uses the cached block from the last proposal operation. If no block was built or
    /// the commitment does not match the cached block, the broadcast is skipped with a warning.
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
        self.marshal.proposed(round, block).await;
    }
}

impl<E, S, A, B, ES> Reporter for Marshaled<E, S, A, B, ES>
where
    E: Rng + Storage + Spawner + Metrics + Clock,
    S: Scheme,
    A: Application<E, Block = B, Context = Context<B::Commitment, S::PublicKey>>
        + Reporter<Activity = Update<B>>,
    B: Block,
    ES: Epocher,
{
    type Activity = A::Activity;

    /// Relays a report to the underlying [`Application`] and cleans up old verification contexts.
    async fn report(&mut self, update: Self::Activity) {
        // Clean up verification contexts for rounds <= the finalized round.
        // This only modifies in-memory state; sync is called later when a new context is added.
        if let Update::Tip(_, _, round) = &update {
            let mut contexts_guard = self.verification_contexts.lock().await;
            let keys: Vec<_> = contexts_guard.keys().cloned().collect();
            for key in keys {
                if let Some(map) = contexts_guard.get_mut(&key) {
                    map.retain(|ctx_round, _| ctx_round > round);
                    if map.is_empty() {
                        contexts_guard.remove(&key);
                    }
                }
            }

            let mut tasks_guard = self.verification_tasks.lock().await;
            tasks_guard.retain(|ctx_round, _| *ctx_round > *round);
        }
        self.application.report(update).await
    }
}

/// Fetches the parent block given its commitment and optional round.
///
/// This is a helper function used during proposal and verification to retrieve the parent
/// block. If the parent commitment matches the genesis block, it returns the genesis block
/// directly without querying the marshal. Otherwise, it subscribes to the marshal to await
/// the parent block's availability.
///
/// Returns an error if the marshal subscription is cancelled.
#[inline]
async fn fetch_parent<E, S, A, B>(
    parent_commitment: B::Commitment,
    parent_round: Option<Round>,
    application: &mut A,
    marshal: &mut marshal::Mailbox<S, B>,
) -> Either<Ready<Result<B, Canceled>>, oneshot::Receiver<B>>
where
    E: Rng + Storage + Spawner + Metrics + Clock,
    S: Scheme,
    A: Application<E, Block = B, Context = Context<B::Commitment, S::PublicKey>>,
    B: Block,
{
    let genesis = application.genesis().await;
    if parent_commitment == genesis.commitment() {
        Either::Left(ready(Ok(genesis)))
    } else {
        Either::Right(marshal.subscribe(parent_round, parent_commitment).await)
    }
}
