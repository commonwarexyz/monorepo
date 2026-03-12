//! Consensus-facing wrapper that manages pending state on behalf of a
//! stateful application.
//!
//! [`Stateful`] implements the consensus [`Application`](ConsensusApplication)
//! and [`VerifyingApplication`](ConsensusVerifyingApplication) traits by
//! delegating execution to the inner [`Application`] while managing the
//! pending-tip DAG of merkleized batches:
//!
//! - Before each `propose` or `verify`, the wrapper forks unmerkleized
//!   batches from the parent block's pending state (or from the committed
//!   database state if the parent has been finalized).
//! - After execution, the wrapper stores the resulting merkleized batches
//!   as a new pending tip keyed by the block's payload.
//! - On finalization, the wrapper applies the winning tip's changesets to
//!   the underlying databases and prunes dead forks.
//!
//! # Lazy Recovery
//!
//! Pending state lives entirely in memory. After a restart the map is empty,
//! but the wrapper recovers lazily: when a parent's state is missing, it
//! walks back through the block DAG via a [`BlockProvider`] to the nearest
//! known ancestor, then replays forward via [`Application::replay`]. Each
//! replayed block is inserted into the pending map immediately so that
//! partial progress survives timeouts.

use super::{db::DatabaseSet, sync, Application};
use commonware_consensus::{
    marshal::ancestry::{AncestorStream, BlockProvider},
    simplex::types::Activity,
    types::Round,
    Application as ConsensusApplication, Block, CertifiableBlock, Epochable, Reporter,
    VerifyingApplication as ConsensusVerifyingApplication, Viewable,
};
use commonware_cryptography::Digestible;
use commonware_runtime::{Clock, Metrics, Spawner};
use rand::Rng;
use std::collections::HashMap;

/// Configuration for constructing a [`Stateful`] wrapper.
pub struct Config<E, A, P>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
    P: BlockProvider<Block = A::Block>,
{
    /// The inner application that drives state transitions.
    pub app: A,

    /// The set of databases whose batch lifecycle is managed by the wrapper.
    pub databases: A::Databases,

    /// Source of input (e.g. transactions) passed to the application on
    /// propose.
    pub input_provider: A::InputProvider,

    /// Provider for fetching blocks during lazy recovery.
    pub block_provider: P,

    /// The payload of the last finalized block, or `None` if no
    /// finalization has occurred yet.
    ///
    /// Should be set to the genesis payload on first boot, or the last
    /// finalized payload on restart.
    pub finalized_payload: Option<A::Payload>,

    /// Optional startup sync configuration.
    ///
    /// When present, `propose` and `verify` pend until sync completes.
    pub sync: Option<sync::Config<A::Databases>>,
}

/// Wraps an [`Application`] and manages the pending-tip DAG of merkleized
/// batches on its behalf, implementing the consensus
/// [`Application`](ConsensusApplication) and
/// [`VerifyingApplication`](ConsensusVerifyingApplication) traits.
///
/// When a parent block's pending state is missing (e.g. after a restart),
/// the wrapper lazily rebuilds it by walking back through the block DAG
/// via the [`BlockProvider`] and replaying forward via
/// [`Application::replay`].
pub struct Stateful<E, A, P>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
    P: BlockProvider<Block = A::Block>,
{
    /// Runtime context providing RNG, task spawning, metrics, and clock.
    context: E,

    /// The inner application that drives state transitions.
    inner: A,

    /// The set of databases whose batch lifecycle is managed by this wrapper.
    databases: A::Databases,

    /// Source of input (e.g. transactions) passed to the application on propose.
    input_provider: A::InputProvider,

    /// Provider for fetching blocks during lazy recovery.
    block_provider: P,

    /// The payload of the last finalized block, or `None` if no
    /// finalization has occurred.
    ///
    /// Used during lazy recovery to detect when the walk-back has reached
    /// the committed database state boundary.
    finalized_payload: Option<A::Payload>,

    /// Pending merkleized batches keyed by block payload, tagged with the
    /// round in which they were produced.
    ///
    /// Each entry represents a speculative state that has been executed but
    /// not yet finalized. On finalization at round R, entries with round
    /// less than R are pruned (dead forks) while entries ahead of R are
    /// kept (still-live chains).
    pending: HashMap<A::Payload, (Round, <A::Databases as DatabaseSet>::Merkleized)>,

    /// Shared startup sync coordinator.
    ///
    /// This is shared across `Stateful` clones so report-driven sync updates
    /// and readiness are visible process-wide.
    sync: sync::Coordinator<E, A::Databases>,
}

/// `Stateful` is `Clone` for the fields consensus needs. The `databases`
/// field clones cheaply (each database is behind an `Arc`). The pending
/// map is not shared -- each clone starts with a fresh map because
/// pending state is local to a single consensus actor.
impl<E, A, P> Clone for Stateful<E, A, P>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
    P: BlockProvider<Block = A::Block>,
{
    fn clone(&self) -> Self {
        Self {
            context: self.context.clone(),
            inner: self.inner.clone(),
            databases: self.databases.clone(),
            input_provider: self.input_provider.clone(),
            block_provider: self.block_provider.clone(),
            finalized_payload: self.finalized_payload,
            pending: HashMap::new(),
            sync: self.sync.clone(),
        }
    }
}

impl<E, A, P> Stateful<E, A, P>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
    P: BlockProvider<Block = A::Block>,
{
    pub fn new(context: E, cfg: Config<E, A, P>) -> Self {
        let sync = sync::Coordinator::new(context.clone(), cfg.databases.clone(), cfg.sync);

        Self {
            context,
            inner: cfg.app,
            databases: cfg.databases,
            input_provider: cfg.input_provider,
            block_provider: cfg.block_provider,
            finalized_payload: cfg.finalized_payload,
            pending: HashMap::new(),
            sync,
        }
    }

    /// Extract and forward sync targets for a finalized payload.
    async fn forward_sync_target_update(
        sync: sync::Coordinator<E, A::Databases>,
        block_provider: P,
        payload: A::Payload,
    ) {
        if sync.is_ready() {
            return;
        }

        let Some(finalized_block) = block_provider.fetch_block(payload.into()).await else {
            return;
        };

        let Some(sync_targets) = A::sync_targets(&finalized_block) else {
            return;
        };

        sync.update_targets(sync_targets).await;
    }

    /// Fork unmerkleized batches for building on top of `parent`.
    ///
    /// If the parent's merkleized state is in the pending map, creates
    /// child batches from it. Otherwise (parent is the finalized tip),
    /// creates batches from the committed database state.
    async fn start_batches(
        &mut self,
        parent: &A::Payload,
    ) -> <A::Databases as DatabaseSet>::Unmerkleized {
        match self.pending.get(parent) {
            Some((_, m)) => <A::Databases as DatabaseSet>::fork_batches(m),
            None => self.databases.new_batches().await,
        }
    }

    /// Walk back from `target` to the nearest known ancestor (either in
    /// the pending map or the finalized tip), then replay forward to
    /// populate the pending map with the missing chain segment.
    ///
    /// Each replayed block's merkleized state is inserted into the pending
    /// map immediately so that partial progress survives timeouts.
    async fn rebuild_pending(&mut self, target: <A::Block as Digestible>::Digest) {
        // Walk back, collecting blocks whose pending state is missing.
        let mut to_replay = Vec::new();
        let mut current = target;

        loop {
            let Some(block) = self.block_provider.clone().fetch_block(current).await else {
                // Reached end of chain (e.g. genesis parent).
                break;
            };

            if self.pending.contains_key(&A::payload(&block)) {
                break;
            }

            let parent_digest = block.parent();
            to_replay.push(block);

            // Stop if the parent is the finalized tip (committed state).
            if let Some(fp) = &self.finalized_payload {
                if A::parent_payload(to_replay.last().unwrap()) == *fp {
                    break;
                }
            }

            current = parent_digest;
        }

        // Replay in parent-before-child order, inserting into the pending
        // map after each block for incremental progress.
        for block in to_replay.into_iter().rev() {
            let payload = A::payload(&block);
            let parent_payload = A::parent_payload(&block);
            let context = block.context();
            let round = Round::new(context.epoch(), context.view());

            let batches = self.start_batches(&parent_payload).await;
            let merkleized = self
                .inner
                .replay((self.context.clone(), context), &block, batches)
                .await;

            self.pending.insert(payload, (round, merkleized));
        }
    }
}

impl<E, A, P> ConsensusApplication<E> for Stateful<E, A, P>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
    P: BlockProvider<Block = A::Block>,
{
    type SigningScheme = A::SigningScheme;
    type Context = A::Context;
    type Block = A::Block;

    async fn genesis(&mut self) -> Self::Block {
        self.inner.genesis().await
    }

    async fn propose<BP: BlockProvider<Block = Self::Block>>(
        &mut self,
        context: (E, Self::Context),
        ancestry: AncestorStream<BP, Self::Block>,
    ) -> Option<Self::Block> {
        // While startup sync is in progress this await will pend. Consensus
        // interprets this as a slow node and times out naturally.
        //
        // TODO: If not ready, immediately drop channel. We can't currently do this
        // from the `Application` interface, because `Automaton` is what manages this.
        self.sync.wait_until_ready().await;

        // The ancestry stream starts from the parent block.
        let parent = ancestry.peek()?;
        let parent_payload = A::payload(parent);

        // Lazy replay if the parent's pending state is missing.
        if !self.pending.contains_key(&parent_payload) {
            self.rebuild_pending(parent.digest()).await;
        }

        let round = Round::new(context.1.epoch(), context.1.view());
        let batches = self.start_batches(&parent_payload).await;

        let (block, merkleized) = self
            .inner
            .propose(context, ancestry, batches, &mut self.input_provider)
            .await?;

        self.pending.insert(A::payload(&block), (round, merkleized));
        Some(block)
    }
}

impl<E, A, P> ConsensusVerifyingApplication<E> for Stateful<E, A, P>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
    P: BlockProvider<Block = A::Block>,
{
    async fn verify<BP: BlockProvider<Block = Self::Block>>(
        &mut self,
        context: (E, Self::Context),
        ancestry: AncestorStream<BP, Self::Block>,
    ) -> bool {
        // While startup sync is in progress this await will pend. Consensus
        // interprets this as a slow node and times out naturally.
        self.sync.wait_until_ready().await;

        // The ancestry stream starts from the block being verified.
        let tip = match ancestry.peek() {
            Some(block) => block,
            None => return false,
        };
        let (block_payload, parent_payload) = (A::payload(tip), A::parent_payload(tip));

        // Lazy replay if the parent's pending state is missing.
        if !self.pending.contains_key(&parent_payload) {
            self.rebuild_pending(tip.parent()).await;
        }

        let round = Round::new(context.1.epoch(), context.1.view());
        let batches = self.start_batches(&parent_payload).await;

        let Some(merkleized) = self.inner.verify(context, ancestry, batches).await else {
            return false;
        };

        self.pending.insert(block_payload, (round, merkleized));
        true
    }
}

impl<E, A, P> Reporter for Stateful<E, A, P>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
    P: BlockProvider<Block = A::Block>,
{
    type Activity = Activity<A::SigningScheme, A::Payload>;

    async fn report(&mut self, activity: Self::Activity) {
        if let Activity::Finalization(finalization) = activity {
            let finalized_round = finalization.proposal.round;
            let payload = finalization.proposal.payload;

            // Keep sync engines chasing the latest finalized tip.
            Self::forward_sync_target_update(
                self.sync.clone(),
                self.block_provider.clone(),
                payload,
            )
            .await;

            // Remove the finalized entry and apply it.
            if let Some((_, batches)) = self.pending.remove(&payload) {
                self.databases.finalize(batches).await;
            }

            // Track the finalized tip for lazy recovery.
            self.finalized_payload = Some(payload);

            // Prune pending entries from rounds at or below the finalized
            // round. These belong to dead forks that can no longer be
            // finalized. Entries at rounds above the finalized round are
            // kept; they sit on still-live chains ahead of the tip.
            self.pending
                .retain(|_, (round, _)| *round > finalized_round);
        }
    }
}
