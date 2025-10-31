//! Epoch management wrapper for consensus applications.
//!
//! # Overview
//!
//! [EpochedApplication] is an adapter that wraps any [VerifyingApplication] implementation to handle
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
//! # Usage
//!
//! Wrap your application implementation with [EpochedApplication::new] and provide it to your
//! consensus engine for the [Automaton] and [Relay]. The wrapper handles all epoch logic transparently.
//!
//! ```rust,ignore
//! let application = EpochedApplication::new(
//!     context,
//!     my_application,
//!     marshal_mailbox,
//!     BLOCKS_PER_EPOCH,
//! );
//! ```
//!
//! # Implementation Notes
//!
//! - Genesis blocks are handled specially: epoch 0 returns the application's genesis block,
//!   while subsequent epochs use the last block of the previous epoch as genesis
//! - Blocks are automatically verified to be within the current epoch

use crate::{
    marshal,
    simplex::{signing_scheme::Scheme, types::Context},
    types::{Epoch, Round},
    utils, Application, Automaton, Block, Epochable, Relay, Reporter, VerifyingApplication,
};
use commonware_runtime::{Clock, Metrics, Spawner};
use futures::{
    channel::oneshot::{self, Canceled},
    lock::Mutex,
};
use prometheus_client::metrics::gauge::Gauge;
use rand::Rng;
use std::{sync::Arc, time::Instant};
use tracing::{debug, warn};

/// An [Application] adapter that handles epoch transitions.
///
/// This wrapper intercepts consensus operations to enforce epoch boundaries. It prevents
/// blocks from being produced outside their valid epoch and handles the special case of
/// re-proposing boundary blocks during epoch transitions.
#[derive(Clone)]
pub struct EpochedApplication<E, S, A, B>
where
    E: Rng + Spawner + Metrics + Clock,
    S: Scheme,
    A: Application<E>,
    B: Block,
{
    context: E,
    application: A,
    marshal: marshal::Mailbox<S, B>,
    epoch_length: u64,
    last_built: Arc<Mutex<Option<(Round, B)>>>,

    build_duration: Gauge,
}

impl<E, S, A, B> EpochedApplication<E, S, A, B>
where
    E: Rng + Spawner + Metrics + Clock,
    S: Scheme,
    A: Application<E, Block = B, Context = Context<B::Commitment, S::PublicKey>>,
    B: Block,
{
    /// Creates a new [EpochedApplication] wrapper.
    pub fn new(
        context: E,
        application: A,
        marshal: marshal::Mailbox<S, B>,
        epoch_length: u64,
    ) -> Self {
        let build_duration = Gauge::default();
        context.register(
            "build_duration",
            "Time taken for the application to build a new block, in milliseconds",
            build_duration.clone(),
        );

        Self {
            context,
            application,
            marshal,
            epoch_length,
            last_built: Arc::new(Mutex::new(None)),

            build_duration,
        }
    }
}

impl<E, S, A, B> Automaton for EpochedApplication<E, S, A, B>
where
    E: Rng + Spawner + Metrics + Clock,
    S: Scheme,
    A: VerifyingApplication<E, Block = B, Context = Context<B::Commitment, S::PublicKey>>,
    B: Block,
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
        if epoch == 0 {
            return self.application.genesis().await.commitment();
        }

        let height = utils::last_block_in_epoch(self.epoch_length, epoch - 1);
        let Some(block) = self.marshal.get_block(height).await else {
            // A new consensus engine will never be started without having the genesis block
            // of the new epoch (the last block of the previous epoch) already stored.
            unreachable!("missing starting epoch block at height {}", height);
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
        context: Context<Self::Digest, S::PublicKey>,
    ) -> oneshot::Receiver<Self::Digest> {
        let mut marshal = self.marshal.clone();
        let mut application = self.application.clone();
        let last_built = self.last_built.clone();
        let epoch_length = self.epoch_length;

        // Metrics
        let build_duration = self.build_duration.clone();

        let (tx, rx) = oneshot::channel();
        self.context
            .with_label("propose")
            .spawn(move |r_ctx| async move {
                let (parent_view, parent_commitment) = context.parent;
                let Ok(parent) = fetch_parent(
                    parent_commitment,
                    Some(Round::new(context.epoch(), parent_view)),
                    &mut application,
                    &mut marshal,
                )
                .await
                else {
                    warn!(
                        ?parent_commitment,
                        reason = "missing parent block",
                        "skipping proposal"
                    );
                    return;
                };

                // Special case: If the parent block is the last block in the epoch,
                // re-propose it as to not produce any blocks that will be cut out
                // by the epoch transition.
                let last_in_epoch = utils::last_block_in_epoch(epoch_length, context.epoch());
                if parent.height() == last_in_epoch {
                    let digest = parent.commitment();
                    {
                        let mut lock = last_built.lock().await;
                        *lock = Some((context.round, parent));
                    }

                    let result = tx.send(digest);
                    debug!(
                        round = ?context.round,
                        ?digest,
                        success = result.is_ok(),
                        "re-proposed parent block at epoch boundary"
                    );
                    return;
                }

                let start = Instant::now();
                let built_block = application
                    .build(r_ctx.with_label("app_build"), parent_commitment, parent)
                    .await;
                build_duration.set(start.elapsed().as_millis() as i64);

                let digest = built_block.commitment();
                {
                    let mut lock = last_built.lock().await;
                    *lock = Some((context.round, built_block));
                }

                let result = tx.send(digest);
                debug!(
                    round = ?context.round,
                    ?digest,
                    success = result.is_ok(),
                    "proposed new block"
                );
            });
        rx
    }

    /// Verifies a proposed block within epoch boundaries.
    ///
    /// This method validates that:
    /// 1. The block is within the current epoch (unless it's a boundary block re-proposal)
    /// 2. Re-proposals are only allowed for the last block in an epoch
    /// 3. The underlying application's verification logic passes
    ///
    /// Verification is spawned in a background task and returns a receiver that will contain
    /// the verification result. Valid blocks are reported to the marshal as verified.
    async fn verify(
        &mut self,
        context: Context<Self::Digest, S::PublicKey>,
        digest: Self::Digest,
    ) -> oneshot::Receiver<bool> {
        let mut marshal = self.marshal.clone();
        let mut application = self.application.clone();
        let epoch_length = self.epoch_length;

        let (tx, rx) = oneshot::channel();
        self.context
            .with_label("verify")
            .spawn(move |r_ctx| async move {
                let (parent_view, parent_commitment) = context.parent;
                let parent = fetch_parent(
                    parent_commitment,
                    Some(Round::new(context.epoch(), parent_view)),
                    &mut application,
                    &mut marshal,
                )
                .await;
                let block = marshal.subscribe(None, digest).await.await;

                let Ok(parent) = parent else {
                    warn!(
                        ?parent_commitment,
                        reason = "missing parent block",
                        "skipping verification"
                    );
                    return;
                };
                let Ok(block) = block else {
                    warn!(?digest, reason = "missing block", "skipping verification");
                    return;
                };

                // You can only re-propose the same block if it's the last height in the epoch.
                if parent.commitment() == block.commitment() {
                    let last_in_epoch = utils::last_block_in_epoch(epoch_length, context.epoch());
                    if block.height() == last_in_epoch {
                        marshal.verified(context.round, block).await;
                        let _ = tx.send(true);
                    } else {
                        let _ = tx.send(false);
                    }
                    return;
                }

                // Blocks are invalid if they are not within the current epoch and they aren't
                // a re-proposal of the boundary block.
                if utils::epoch(epoch_length, block.height()) != context.epoch() {
                    let _ = tx.send(false);
                    return;
                }

                let application_valid = application
                    .verify(r_ctx.with_label("app_verify"), parent, block.clone())
                    .await;

                if application_valid {
                    marshal.verified(context.round, block).await;
                }
                let _ = tx.send(application_valid);
            });
        rx
    }
}

impl<E, S, A, B> Relay for EpochedApplication<E, S, A, B>
where
    E: Rng + Spawner + Metrics + Clock,
    S: Scheme,
    A: Application<E, Block = B, Context = Context<B::Commitment, S::PublicKey>>,
    B: Block,
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
                height = block.height(),
                "skipping requested broadcast of block with mismatched commitment"
            );
            return;
        }

        debug!(
            round = %round,
            commitment = %block.commitment(),
            height = block.height(),
            "requested broadcast of built block"
        );
        self.marshal.broadcast(block).await;
    }
}

impl<E, S, A, B> Reporter for EpochedApplication<E, S, A, B>
where
    E: Rng + Spawner + Metrics + Clock,
    S: Scheme,
    A: Application<E, Block = B, Context = Context<B::Commitment, S::PublicKey>>,
    B: Block,
{
    type Activity = B;

    /// Reports a finalized block to the underlying application.
    ///
    /// This forwards the finalized block to the wrapped application's finalize method,
    /// allowing the application to perform any necessary state updates or cleanup.
    async fn report(&mut self, block: Self::Activity) {
        self.application.finalize(block).await
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
) -> Result<B, Canceled>
where
    E: Rng + Spawner + Metrics + Clock,
    S: Scheme,
    A: Application<E, Block = B, Context = Context<B::Commitment, S::PublicKey>>,
    B: Block,
{
    let genesis = application.genesis().await;
    if parent_commitment == genesis.commitment() {
        Ok(genesis)
    } else {
        marshal
            .subscribe(parent_round, parent_commitment)
            .await
            .await
    }
}
