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
//!   as a new pending tip keyed by the block's digest.
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
    marshal::{
        ancestry::{AncestorStream, BlockProvider},
        core::Variant,
    },
    simplex::types::Activity,
    types::{Epoch, Height, Round},
    Application as ConsensusApplication, Block, CertifiableBlock, Epochable, Heightable, Reporter,
    VerifyingApplication as ConsensusVerifyingApplication, Viewable,
};
use commonware_cryptography::Digestible;
use commonware_runtime::{Clock, Metrics, Spawner};
use commonware_utils::sync::Mutex;
use rand::Rng;
use std::{collections::HashMap, sync::Arc};

type PendingDigest<A, E> = <<A as Application<E>>::Block as Digestible>::Digest;
type PendingBatches<A, E> = <<A as Application<E>>::Databases as DatabaseSet>::Merkleized;
type PendingEntry<A, E> = (Round, PendingBatches<A, E>);

/// Pending merkleized batches keyed by block digest.
struct Pending<A, E>
where
    A: Application<E>,
    E: Rng + Spawner + Metrics + Clock,
{
    entries: HashMap<PendingDigest<A, E>, PendingEntry<A, E>>,
}

impl<A, E> Pending<A, E>
where
    A: Application<E>,
    E: Rng + Spawner + Metrics + Clock,
{
    fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    fn contains(&self, digest: &PendingDigest<A, E>) -> bool {
        self.entries.contains_key(digest)
    }

    fn get_merkleized(&self, digest: &PendingDigest<A, E>) -> Option<&PendingBatches<A, E>> {
        self.entries.get(digest).map(|(_, merkleized)| merkleized)
    }

    fn insert(
        &mut self,
        digest: PendingDigest<A, E>,
        round: Round,
        merkleized: PendingBatches<A, E>,
    ) {
        self.entries.insert(digest, (round, merkleized));
    }

    fn remove(&mut self, digest: &PendingDigest<A, E>) -> Option<PendingEntry<A, E>> {
        self.entries.remove(digest)
    }

    fn retain_newer_than(&mut self, finalized_round: Round) {
        self.entries
            .retain(|_, (round, _)| *round > finalized_round);
    }
}

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

    /// The digest of the last finalized block, or `None` if no
    /// finalization has occurred yet.
    ///
    /// Should be set to the genesis digest on first boot, or the last
    /// finalized digest on restart.
    pub finalized_digest: Option<<A::Block as Digestible>::Digest>,

    /// Startup sync configuration.
    ///
    /// The sync coordinator gates `propose` and `verify` until sync
    /// completes. For genesis validators (no prior state), the wrapper
    /// auto-marks ready on the first finalization.
    pub sync: sync::Config<A::Databases>,
}

/// Mutable state shared across `Stateful` clones.
///
/// Both the consensus application path (propose/verify) and the reporter
/// path (finalization) need access to the same pending map and finalized
/// digest. Wrapping these in `Arc<Mutex<...>>` allows `Stateful` clones
/// to share this state.
struct Shared<A, E>
where
    A: Application<E>,
    E: Rng + Spawner + Metrics + Clock,
{
    /// Pending merkleized batches keyed by block digest, tagged with the
    /// round in which they were produced.
    pending: Pending<A, E>,

    /// The digest of the last finalized block, or `None` if no
    /// finalization has occurred.
    finalized_digest: Option<<A::Block as Digestible>::Digest>,
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

    /// Shared mutable state (pending map + finalized digest).
    shared: Arc<Mutex<Shared<A, E>>>,

    /// Shared startup sync coordinator.
    ///
    /// This is shared across `Stateful` clones so report-driven sync updates
    /// and readiness are visible process-wide.
    sync: sync::Coordinator<E, A::Databases>,
}

/// `Stateful` is `Clone` for the fields consensus needs. The `databases`
/// field clones cheaply (each database is behind an `Arc`). The `shared`
/// field is an `Arc<Mutex<...>>` so all clones share the same pending
/// map and finalized digest.
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
            shared: self.shared.clone(),
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
            shared: Arc::new(Mutex::new(Shared {
                pending: Pending::new(),
                finalized_digest: cfg.finalized_digest,
            })),
            sync,
        }
    }

    /// Fork unmerkleized batches for building on top of `parent`.
    ///
    /// If the parent's merkleized state is in the pending map, creates
    /// child batches from it. Otherwise (parent is the finalized tip),
    /// creates batches from the committed database state.
    ///
    /// Takes `databases` and `shared` by reference so that the returned
    /// batch borrows only `databases`, leaving other fields (e.g. `inner`)
    /// available to the caller.
    async fn start_batches<'db>(
        databases: &'db A::Databases,
        shared: &Mutex<Shared<A, E>>,
        parent: &<A::Block as Digestible>::Digest,
    ) -> <A::Databases as DatabaseSet>::Unmerkleized<'db> {
        let merkleized = shared.lock().pending.get_merkleized(parent).cloned();
        match merkleized {
            Some(ref parent) => databases.fork_batches(parent).await,
            None => databases.new_batches().await,
        }
    }

    /// Lazily rebuild pending state for `parent` if needed.
    ///
    /// Rebuilds when at least one finalization has occurred, the parent is
    /// not the finalized tip, and its pending state is missing.
    async fn ensure_pending(&mut self, parent: <A::Block as Digestible>::Digest) {
        let needs_rebuild = {
            let shared = self.shared.lock();
            shared.finalized_digest.is_some_and(|fd| fd != parent)
                && !shared.pending.contains(&parent)
        };
        if needs_rebuild {
            self.rebuild_pending(parent).await;
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
            // Stop if we have reached the finalized tip. Its state is
            // already committed to the database, so there is nothing to
            // replay and the block provider (marshal) cannot serve the
            // genesis block that lies beyond it.
            {
                let shared = self.shared.lock();
                if let Some(fd) = &shared.finalized_digest {
                    if current == *fd {
                        break;
                    }
                }
            }

            let Some(block) = self.block_provider.clone().fetch_block(current).await else {
                // Reached end of chain (e.g. genesis parent).
                break;
            };

            if self.shared.lock().pending.contains(&block.digest()) {
                break;
            }

            let parent_digest = block.parent();
            to_replay.push(block);

            current = parent_digest;
        }

        // Replay in parent-before-child order, inserting into the pending
        // map after each block for incremental progress.
        for block in to_replay.into_iter().rev() {
            let digest = block.digest();
            let parent_digest = block.parent();
            let context = block.context();
            let round = Round::new(context.epoch(), context.view());

            let batches = Self::start_batches(&self.databases, &self.shared, &parent_digest).await;
            let merkleized = self
                .inner
                .replay((self.context.clone(), context), &block, batches)
                .await;

            self.shared.lock().pending.insert(digest, round, merkleized);
        }
    }

    /// Extract and forward sync targets for a finalized block digest.
    async fn forward_sync_target_update(
        sync: sync::Coordinator<E, A::Databases>,
        block_provider: P,
        shared: Arc<Mutex<Shared<A, E>>>,
        digest: <A::Block as Digestible>::Digest,
    ) {
        // Check if sync is ready or the finalized digest has changed.
        if sync.is_ready() || shared.lock().finalized_digest != Some(digest) {
            return;
        }

        let finalized_block = block_provider.fetch_block(digest).await.expect(
            "state sync requires finalized block availability while startup sync is pending",
        );

        // Re-check after fetch because a newer finalization may have arrived
        // while waiting on block availability.
        if sync.is_ready() || shared.lock().finalized_digest != Some(digest) {
            return;
        }

        let sync_targets = A::sync_targets(&finalized_block)
            .expect("state sync requires finalized blocks to expose per-database sync targets");
        sync.update_targets(sync_targets);
    }

    /// If building on genesis in epoch 0, mark sync as ready -- there
    /// is no prior state to sync. Pass the **parent** block's height.
    fn maybe_skip_sync(&self, epoch: Epoch, parent_height: Height) {
        if !self.sync.is_ready() && epoch == Epoch::zero() && parent_height == Height::zero() {
            self.sync.mark_ready();
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
        // The ancestry stream starts from the parent block.
        let parent = ancestry.peek()?;
        let parent_digest = parent.digest();

        // If startup sync has not completed, decline to propose so
        // consensus can time out and move on.
        self.maybe_skip_sync(context.1.epoch(), parent.height());
        if !self.sync.is_ready() {
            return None;
        }

        // Ensure we have the pending state necessary to verify
        // this block, rebuilding it if necessary.
        self.ensure_pending(parent_digest).await;

        let round = Round::new(context.1.epoch(), context.1.view());
        let batches = Self::start_batches(&self.databases, &self.shared, &parent_digest).await;
        let (block, merkleized) = self
            .inner
            .propose(context, ancestry, batches, &mut self.input_provider)
            .await?;
        self.shared
            .lock()
            .pending
            .insert(block.digest(), round, merkleized);
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
        (runtime_context, consensus_context): (E, Self::Context),
        ancestry: AncestorStream<BP, Self::Block>,
    ) -> bool {
        // The ancestry stream starts from the block being verified.
        let tip = match ancestry.peek() {
            Some(block) => block,
            None => return false,
        };
        let block_digest = tip.digest();
        let parent_digest = tip.parent();

        // Safe to skip sync here despite the tip coming from a peer's
        // proposal: simplex's `parent_payload` check rejects any
        // proposal whose parent view is before `last_finalized`. Once
        // ANY block is finalized, genesis (view 0) can never be a
        // valid parent again. So if we're asked to verify a block
        // building on genesis, the network genuinely hasn't finalized
        // anything yet and there is no state to sync.
        //
        // TODO: I'm not thrilled with relying on such a deep assumption,
        // though it's mighty convenient to not have to supply a sync
        // target on startup.
        let Some(parent_height) = tip.height().previous() else {
            return false;
        };
        self.maybe_skip_sync(consensus_context.epoch(), parent_height);

        // While startup sync is in progress this await will pend.
        // Consensus interprets this as a slow node and times out.
        self.sync.wait_until_ready().await;

        // Ensure we have the pending state necessary to verify
        // this block, rebuilding it if necessary.
        self.ensure_pending(parent_digest).await;

        let round = Round::new(consensus_context.epoch(), consensus_context.view());
        let batches = Self::start_batches(&self.databases, &self.shared, &parent_digest).await;
        let Some(merkleized) = self
            .inner
            .verify((runtime_context, consensus_context), ancestry, batches)
            .await
        else {
            return false;
        };
        self.shared
            .lock()
            .pending
            .insert(block_digest, round, merkleized);
        true
    }
}

impl<E, A, P> Reporter for Stateful<E, A, P>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
    P: BlockProvider<Block = A::Block>,
{
    type Activity = Activity<A::SigningScheme, <A::MarshalVariant as Variant>::Commitment>;

    async fn report(&mut self, activity: Self::Activity) {
        if let Activity::Finalization(finalization) = activity {
            let finalized_round = finalization.proposal.round;
            let digest = A::MarshalVariant::commitment_to_inner(finalization.proposal.payload);

            // Duplicate finalization reports are benign. A node may
            // observe the same finalization certificate multiple times
            // from replay or the network.
            if self.shared.lock().finalized_digest == Some(digest) {
                return;
            }

            // Remove the finalized entry and apply it.
            let mut finalized_batches = self.shared.lock().pending.remove(&digest);
            if finalized_batches.is_none() && self.sync.is_ready() {
                self.rebuild_pending(digest).await;
                finalized_batches = self.shared.lock().pending.remove(&digest);
            }
            match finalized_batches {
                Some((_, batches)) => self.databases.finalize(batches).await,
                None if self.sync.is_ready() => {
                    panic!("finalized state could not be replayed while sync is ready")
                }
                None => {}
            }

            // Track the finalized tip for lazy recovery and prune dead
            // forks. Entries at rounds above the finalized round are kept;
            // they sit on still-live chains ahead of the tip.
            {
                let mut shared = self.shared.lock();
                shared.finalized_digest = Some(digest);
                shared.pending.retain_newer_than(finalized_round);
            }

            // Forward sync targets to the sync engine.
            if !self.sync.is_ready() {
                let sync = self.sync.clone();
                let block_provider = self.block_provider.clone();
                let shared = self.shared.clone();
                self.context.clone().spawn(move |_| async move {
                    Self::forward_sync_target_update(sync, block_provider, shared, digest).await;
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::stateful::{
        db::{DatabaseSet, SyncHandle, SyncableDatabaseSet},
        sync,
        tests::mocks::app::Block,
        Application, Config as StatefulConfig, Stateful,
    };
    use commonware_consensus::{
        marshal::{
            ancestry::{AncestorStream, BlockProvider},
            core::Variant,
            standard::Standard,
        },
        simplex::{
            mocks::scheme::Scheme as MockScheme,
            types::{Activity, Finalization, Proposal},
        },
        types::{Epoch, Round, View},
        CertifiableBlock, Reporter,
    };
    use commonware_cryptography::{ed25519, sha256, Digestible};
    use commonware_macros::test_traced;
    use commonware_runtime::{deterministic, Clock, Metrics, Runner as _, Spawner};
    use commonware_utils::{
        channel::{mpsc, oneshot},
        sequence::U64,
        sync::Mutex,
    };
    use rand::Rng;
    use std::{collections::HashMap, convert::Infallible, sync::Arc, time::Duration};

    type DigestLog = Arc<Mutex<Vec<sha256::Digest>>>;
    type CompletionSender = oneshot::Sender<Result<(), Infallible>>;
    type CompletionSenders = Arc<Mutex<Vec<CompletionSender>>>;

    fn block(view: u64, marker: u8, target: u8) -> Block {
        Block::sync_target(view, marker, target)
    }

    #[derive(Clone)]
    struct SyncTargetApp;

    impl Application<deterministic::Context> for SyncTargetApp {
        type SigningScheme = MockScheme<ed25519::PublicKey>;
        type Context = <Block as CertifiableBlock>::Context;
        type Block = Block;
        type MarshalVariant = Standard<Block>;
        type Databases = TrackingDatabases;
        type InputProvider = ();

        fn sync_targets(
            block: &Self::Block,
        ) -> Option<<Self::Databases as SyncableDatabaseSet>::SyncTargets> {
            Some(block.state_root())
        }

        async fn genesis(&mut self) -> Self::Block {
            block(0, 0, 0)
        }

        async fn propose<BP: BlockProvider<Block = Self::Block>>(
            &mut self,
            _context: (deterministic::Context, Self::Context),
            _ancestry: AncestorStream<BP, Self::Block>,
            _batches: <Self::Databases as DatabaseSet>::Unmerkleized<'_>,
            _input: &mut Self::InputProvider,
        ) -> Option<(Self::Block, <Self::Databases as DatabaseSet>::Merkleized)> {
            panic!("unused in test")
        }

        async fn verify<BP: BlockProvider<Block = Self::Block>>(
            &mut self,
            _context: (deterministic::Context, Self::Context),
            _ancestry: AncestorStream<BP, Self::Block>,
            _batches: <Self::Databases as DatabaseSet>::Unmerkleized<'_>,
        ) -> Option<<Self::Databases as DatabaseSet>::Merkleized> {
            panic!("unused in test")
        }

        async fn replay(
            &mut self,
            _context: (deterministic::Context, Self::Context),
            _block: &Self::Block,
            _batches: <Self::Databases as DatabaseSet>::Unmerkleized<'_>,
        ) -> <Self::Databases as DatabaseSet>::Merkleized {
            panic!("unused in test")
        }
    }

    #[derive(Clone, Default)]
    struct TrackingDatabases {
        started_with: DigestLog,
        forwarded_updates: DigestLog,
        completion_senders: CompletionSenders,
    }

    impl TrackingDatabases {
        fn started_with(&self) -> Vec<sha256::Digest> {
            self.started_with.lock().clone()
        }

        fn forwarded_updates(&self) -> Vec<sha256::Digest> {
            self.forwarded_updates.lock().clone()
        }
    }

    #[derive(Clone, Default)]
    struct RecordingDatabases {
        finalized: Arc<Mutex<Vec<sha256::Digest>>>,
    }

    impl RecordingDatabases {
        fn finalized(&self) -> Vec<sha256::Digest> {
            self.finalized.lock().clone()
        }
    }

    impl DatabaseSet for RecordingDatabases {
        type Unmerkleized<'a> = ();
        type Merkleized = sha256::Digest;

        async fn new_batches(&self) -> Self::Unmerkleized<'_> {}

        async fn fork_batches(&self, _parent: &Self::Merkleized) -> Self::Unmerkleized<'_> {}

        async fn finalize(&self, batches: Self::Merkleized) {
            self.finalized.lock().push(batches);
        }
    }

    impl SyncableDatabaseSet for RecordingDatabases {
        type SyncConfigs = ();
        type SyncResolvers = ();
        type SyncTargets = sha256::Digest;
        type SyncError = Infallible;

        fn start_sync<RT>(
            &self,
            _context: RT,
            _sync_configs: Self::SyncConfigs,
            _sync_resolvers: Self::SyncResolvers,
            _initial_targets: Self::SyncTargets,
        ) -> Result<SyncHandle<Self::SyncTargets, Self::SyncError>, Self::SyncError>
        where
            RT: Rng + Spawner + Metrics + Clock,
        {
            panic!("unused in test")
        }
    }

    #[derive(Clone)]
    struct ReplayOnFinalizeApp;

    impl Application<deterministic::Context> for ReplayOnFinalizeApp {
        type SigningScheme = MockScheme<ed25519::PublicKey>;
        type Context = <Block as CertifiableBlock>::Context;
        type Block = Block;
        type MarshalVariant = Standard<Block>;
        type Databases = RecordingDatabases;
        type InputProvider = ();

        fn sync_targets(
            block: &Self::Block,
        ) -> Option<<Self::Databases as SyncableDatabaseSet>::SyncTargets> {
            Some(block.state_root())
        }

        async fn genesis(&mut self) -> Self::Block {
            block(0, 0, 0)
        }

        async fn propose<BP: BlockProvider<Block = Self::Block>>(
            &mut self,
            _context: (deterministic::Context, Self::Context),
            _ancestry: AncestorStream<BP, Self::Block>,
            _batches: <Self::Databases as DatabaseSet>::Unmerkleized<'_>,
            _input: &mut Self::InputProvider,
        ) -> Option<(Self::Block, <Self::Databases as DatabaseSet>::Merkleized)> {
            panic!("unused in test")
        }

        async fn verify<BP: BlockProvider<Block = Self::Block>>(
            &mut self,
            _context: (deterministic::Context, Self::Context),
            _ancestry: AncestorStream<BP, Self::Block>,
            _batches: <Self::Databases as DatabaseSet>::Unmerkleized<'_>,
        ) -> Option<<Self::Databases as DatabaseSet>::Merkleized> {
            panic!("unused in test")
        }

        async fn replay(
            &mut self,
            _context: (deterministic::Context, Self::Context),
            block: &Self::Block,
            _batches: <Self::Databases as DatabaseSet>::Unmerkleized<'_>,
        ) -> <Self::Databases as DatabaseSet>::Merkleized {
            block.digest()
        }
    }

    impl DatabaseSet for TrackingDatabases {
        type Unmerkleized<'a> = ();
        type Merkleized = ();

        async fn new_batches(&self) -> Self::Unmerkleized<'_> {}

        async fn fork_batches(&self, _parent: &Self::Merkleized) -> Self::Unmerkleized<'_> {}

        async fn finalize(&self, _batches: Self::Merkleized) {}
    }

    impl SyncableDatabaseSet for TrackingDatabases {
        type SyncConfigs = ();
        type SyncResolvers = ();
        type SyncTargets = sha256::Digest;
        type SyncError = Infallible;

        fn start_sync<RT>(
            &self,
            context: RT,
            _sync_configs: Self::SyncConfigs,
            _sync_resolvers: Self::SyncResolvers,
            initial_targets: Self::SyncTargets,
        ) -> Result<SyncHandle<Self::SyncTargets, Self::SyncError>, Self::SyncError>
        where
            RT: Rng + Spawner + Metrics + Clock,
        {
            self.started_with.lock().push(initial_targets);

            let forwarded = self.forwarded_updates.clone();
            let (target_updates, mut target_updates_rx) = mpsc::channel(8);
            context
                .with_label("tracking_sync_updates")
                .spawn(move |_| async move {
                    while let Some(target) = target_updates_rx.recv().await {
                        forwarded.lock().push(target);
                    }
                });

            let (completion_sender, completion) = oneshot::channel::<Result<(), Infallible>>();
            self.completion_senders.lock().push(completion_sender);
            Ok(SyncHandle {
                target_updates,
                completion,
            })
        }
    }

    #[derive(Clone)]
    struct GatedBlockProvider {
        delayed: sha256::Digest,
        blocks: Arc<HashMap<sha256::Digest, Block>>,
        gate: Arc<Mutex<Option<oneshot::Receiver<()>>>>,
    }

    struct FetchGate {
        release: Mutex<Option<oneshot::Sender<()>>>,
    }

    impl FetchGate {
        fn unblock(&self) {
            if let Some(sender) = self.release.lock().take() {
                let _ = sender.send(());
            }
        }
    }

    impl GatedBlockProvider {
        fn new(delayed: sha256::Digest, blocks: Vec<Block>) -> (Self, FetchGate) {
            let (release, gate) = oneshot::channel();
            (
                Self {
                    delayed,
                    blocks: Arc::new(blocks.into_iter().map(|b| (b.digest(), b)).collect()),
                    gate: Arc::new(Mutex::new(Some(gate))),
                },
                FetchGate {
                    release: Mutex::new(Some(release)),
                },
            )
        }
    }

    impl BlockProvider for GatedBlockProvider {
        type Block = Block;

        async fn fetch_block(
            self,
            digest: <Self::Block as Digestible>::Digest,
        ) -> Option<Self::Block> {
            if digest == self.delayed {
                let gate = self.gate.lock().take();
                if let Some(gate) = gate {
                    let _ = gate.await;
                }
            }
            self.blocks.get(&digest).cloned()
        }
    }

    fn finalization(
        digest: sha256::Digest,
        round: Round,
    ) -> Activity<MockScheme<ed25519::PublicKey>, <Standard<Block> as Variant>::Commitment> {
        Activity::Finalization(Finalization {
            proposal: Proposal {
                round,
                parent: View::zero(),
                payload: digest,
            },
            certificate: U64::new(0),
        })
    }

    #[test_traced("DEBUG")]
    fn stale_sync_target_update_is_ignored_when_fetch_completes_late() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let old_block = block(1, 1, 1);
            let new_block = block(2, 2, 2);
            let (block_provider, fetch_gate) = GatedBlockProvider::new(
                old_block.digest(),
                vec![old_block.clone(), new_block.clone()],
            );

            let databases = TrackingDatabases::default();
            let mut stateful = Stateful::new(
                context.clone(),
                StatefulConfig {
                    app: SyncTargetApp,
                    databases: databases.clone(),
                    input_provider: (),
                    block_provider,
                    finalized_digest: None,
                    sync: sync::Config {
                        sync_configs: (),
                        sync_resolvers: (),
                    },
                },
            );

            // Finalize old then new. Old fetch is blocked so new target is
            // forwarded first and starts sync with the newer target.
            stateful
                .report(finalization(
                    old_block.digest(),
                    Round::new(Epoch::zero(), View::new(1)),
                ))
                .await;
            stateful
                .report(finalization(
                    new_block.digest(),
                    Round::new(Epoch::zero(), View::new(2)),
                ))
                .await;

            for _ in 0..10 {
                if !databases.started_with().is_empty() {
                    break;
                }
                context.sleep(Duration::from_millis(1)).await;
            }
            assert_eq!(databases.started_with(), vec![new_block.state_root()]);

            // Now let the stale fetch complete. It must be ignored.
            fetch_gate.unblock();
            context.sleep(Duration::from_millis(1)).await;
            assert!(
                databases.forwarded_updates().is_empty(),
                "stale sync target was forwarded after a newer finalization"
            );
        });
    }

    #[test]
    fn finalization_missing_pending_is_replayed_and_duplicate_is_ignored_when_sync_is_ready() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let finalized = block(1, 9, 9);
            let databases = RecordingDatabases::default();
            let mut stateful = Stateful::new(
                context,
                StatefulConfig {
                    app: ReplayOnFinalizeApp,
                    databases: databases.clone(),
                    input_provider: (),
                    block_provider: GatedBlockProvider::new(
                        sha256::Digest::from([0; 32]),
                        vec![finalized.clone()],
                    )
                    .0,
                    finalized_digest: None,
                    sync: sync::Config {
                        sync_configs: (),
                        sync_resolvers: (),
                    },
                },
            );
            stateful.sync.mark_ready();
            stateful
                .report(finalization(
                    finalized.digest(),
                    Round::new(Epoch::zero(), View::new(1)),
                ))
                .await;
            stateful
                .report(finalization(
                    finalized.digest(),
                    Round::new(Epoch::zero(), View::new(1)),
                ))
                .await;

            assert_eq!(databases.finalized(), vec![finalized.digest()]);
            assert_eq!(
                stateful.shared.lock().finalized_digest,
                Some(finalized.digest())
            );
        });
    }

    #[test]
    fn verify_parent_height_computation_rejects_zero_height() {
        assert_eq!(commonware_consensus::types::Height::zero().previous(), None);
    }
}
