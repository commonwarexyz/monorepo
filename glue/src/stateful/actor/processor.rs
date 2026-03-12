//! Speculative execution engine for the [`Stateful`](super::Stateful) actor.
//!
//! The [`Processor`] owns the in-memory pending-tip DAG and the committed
//! database set. It is the workhorse behind the actor's `Processing` mode,
//! handling three operations:
//!
//! - Propose/Verify: fork unmerkleized batches from a parent's pending
//!   state (or from committed state), delegate to the [`Application`], and
//!   cache the resulting merkleized batches keyed by block digest.
//!
//! - Lazy recovery: when a parent's pending state is missing (e.g. after
//!   restart), [`Processor::rebuild_pending`] walks the block DAG backward
//!   via a [`BlockProvider`] to the nearest known anchor, then replays
//!   forward via [`Application::apply`], inserting each intermediate result
//!   into the pending map.
//!
//! - Finalization: apply the winning fork's merkleized batches to the
//!   committed databases, then prune all pending entries at or below the
//!   finalized round.
//!
//! All propose/verify paths are cancellation-aware: if the caller drops the
//! response channel, in-progress work stops at the next await point via
//! [`await_or_cancel`].

use crate::stateful::{db::DatabaseSet, Application, Proposed};
use commonware_consensus::{
    marshal::ancestry::{AncestorStream, BlockProvider},
    types::{Height, Round},
    Block, CertifiableBlock, Epochable, Heightable, Viewable,
};
use commonware_cryptography::Digestible;
use commonware_macros::select;
use commonware_runtime::{Clock, Metrics, Spawner};
use commonware_utils::channel::{fallible::OneshotExt, oneshot};
use rand::Rng;
use std::{collections::HashMap, future::Future};
use tracing::{debug, warn};

type PendingDigest<A, E> = <<A as Application<E>>::Block as Digestible>::Digest;
type PendingBatches<A, E> = <<A as Application<E>>::Databases as DatabaseSet<E>>::Merkleized;
type PendingMap<A, E> = HashMap<PendingDigest<A, E>, (Round, PendingBatches<A, E>)>;

/// Errors while preparing parent-relative batches for propose/verify.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum PrepareBatchesError {
    /// Parent ancestry is provably invalid.
    Invalid,
    /// Caller dropped the response while waiting.
    Cancelled,
}

/// Finalization result for a finalized block report.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum FinalizeStatus {
    /// The finalized digest was already processed.
    Duplicate,

    /// The finalized state was persisted and in-memory forks were pruned.
    Persisted { height: Height },
}

/// Owns speculative execution and state persistence for a running stateful actor.
pub(super) struct Processor<E, A>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    app: A,
    databases: A::Databases,
    pending: PendingMap<A, E>,
    last_processed_digest: <A::Block as Digestible>::Digest,
}

impl<E, A> Processor<E, A>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    /// Create a new processor with the given application, databases, and
    /// the digest of the last finalized block.
    pub(super) fn new(
        app: A,
        databases: A::Databases,
        last_processed_digest: <A::Block as Digestible>::Digest,
    ) -> Self {
        Self {
            app,
            databases,
            pending: HashMap::new(),
            last_processed_digest,
        }
    }

    /// Delegate to the application to produce the genesis block.
    pub(super) async fn genesis(&mut self) -> A::Block {
        self.app.genesis().await
    }

    /// Prepare parent-relative batches and delegate to the application to
    /// build a new block proposal. The resulting block and its merkleized
    /// state are cached in `pending`. Sends `None` on `response` if the
    /// ancestry is invalid or the application declines to propose.
    pub(super) async fn propose<P, BP>(
        &mut self,
        context: &E,
        provider: P,
        (runtime_context, consensus_context): (E, A::Context),
        ancestry: AncestorStream<BP, A::Block>,
        input_provider: &mut A::InputProvider,
        mut response: oneshot::Sender<Option<A::Block>>,
    ) where
        P: BlockProvider<Block = A::Block> + Clone,
        BP: BlockProvider<Block = A::Block>,
    {
        let Some(parent) = ancestry.peek() else {
            response.send_lossy(None);
            return;
        };
        let parent_digest = parent.digest();

        let round = Round::new(consensus_context.epoch(), consensus_context.view());
        let batches = match self
            .prepare_batches(context, provider, parent_digest, &mut response)
            .await
        {
            Ok(batches) => batches,
            Err(PrepareBatchesError::Invalid) => {
                response.send_lossy(None);
                return;
            }
            Err(PrepareBatchesError::Cancelled) => {
                debug!(
                    ?parent_digest,
                    "proposal request cancelled during prepare_batches"
                );
                return;
            }
        };

        let proposed = match await_or_cancel(
            &mut response,
            self.app.propose(
                (runtime_context, consensus_context),
                ancestry,
                batches,
                input_provider,
            ),
        )
        .await
        {
            Some(result) => result,
            None => {
                debug!(?parent_digest, "proposal request cancelled during propose");
                return;
            }
        };

        let Some(Proposed { block, merkleized }) = proposed else {
            response.send_lossy(None);
            return;
        };
        self.pending.insert(block.digest(), (round, merkleized));
        response.send_lossy(Some(block));
    }

    /// Prepare parent-relative batches and delegate to the application to
    /// verify a received block. On success the block's merkleized state is
    /// cached in `pending` and `true` is sent on `response`.
    pub(super) async fn verify<P, BP>(
        &mut self,
        context: &E,
        provider: P,
        (runtime_context, consensus_context): (E, A::Context),
        ancestry: AncestorStream<BP, A::Block>,
        mut response: oneshot::Sender<bool>,
    ) where
        P: BlockProvider<Block = A::Block> + Clone,
        BP: BlockProvider<Block = A::Block>,
    {
        let Some(block) = ancestry.peek() else {
            response.send_lossy(false);
            return;
        };
        let block_digest = block.digest();
        let parent_digest = block.parent();

        // After state sync the application already has this block's
        // committed database state, but the voter may still ask us to
        // verify it. This happens because the marshal, voter, and state
        // sync resolver learn about finalizations through three
        // independent P2P channels:
        //
        // 1. The marshal's block resolver fetches finalized blocks from
        //    peers. It sends `Update::Tip` to the application, which
        //    feeds state sync targets. This channel delivered the block.
        // 2. State sync's resolver fetches database operations from
        //    peers using those targets. This channel built the database.
        // 3. The voter receives certificates from peers to walk through
        //    historical views. This channel may not have delivered the
        //    finalization certificate for the synced block's view yet.
        //
        // On reliable networks the voter receives the finalization
        // certificate before it catches up to the synced view, which
        // advances `last_finalized` past that view and skips
        // verification. On lossy networks the certificate may be
        // dropped, so the voter reaches the view with only the proposal
        // and certified ancestry, and asks us to verify a block whose
        // state we already committed.
        //
        // Re-execution is impossible: the database already reflects this
        // block's state, so we cannot fork batches from its parent
        // (which was never individually processed).
        //
        // `last_processed_digest` is only ever set from a finalized
        // block (genesis, state sync anchor, or `finalize()`), so this
        // is safe to accept. The corresponding `finalize()` call will
        // return `Duplicate` and skip re-application.
        if block_digest == self.last_processed_digest {
            response.send_lossy(true);
            return;
        }

        let round = Round::new(consensus_context.epoch(), consensus_context.view());
        let batches = match self
            .prepare_batches(context, provider, parent_digest, &mut response)
            .await
        {
            Ok(batches) => batches,
            Err(PrepareBatchesError::Invalid) => {
                warn!(
                    ?parent_digest,
                    ?block_digest,
                    pending_keys = self.pending.len(),
                    last_processed = ?self.last_processed_digest,
                    "verification rejected: prepare_batches returned Invalid"
                );
                response.send_lossy(false);
                return;
            }
            Err(PrepareBatchesError::Cancelled) => {
                debug!(
                    ?parent_digest,
                    "verification request cancelled during prepare_batches"
                );
                return;
            }
        };

        let verified = match await_or_cancel(
            &mut response,
            self.app
                .verify((runtime_context, consensus_context), ancestry, batches),
        )
        .await
        {
            Some(result) => result,
            None => {
                debug!(
                    ?parent_digest,
                    "verification request cancelled during verify"
                );
                return;
            }
        };

        let Some(merkleized) = verified else {
            warn!(
                ?parent_digest,
                ?block_digest,
                "verification rejected: app.verify returned None"
            );
            response.send_lossy(false);
            return;
        };
        self.pending.insert(block_digest, (round, merkleized));
        response.send_lossy(true);
    }

    /// Ensure parent state exists, then prepare unmerkleized batches for execution.
    pub(super) async fn prepare_batches<P, Response>(
        &mut self,
        context: &E,
        provider: P,
        parent_digest: <A::Block as Digestible>::Digest,
        response: &mut oneshot::Sender<Response>,
    ) -> Result<<A::Databases as DatabaseSet<E>>::Unmerkleized, PrepareBatchesError>
    where
        P: BlockProvider<Block = A::Block> + Clone,
    {
        // Rebuild pending state if no pending state exists for the parent and the
        // parent is not the processed tip.
        let needs_rebuild = self.last_processed_digest != parent_digest
            && !self.pending.contains_key(&parent_digest);
        if needs_rebuild {
            self.rebuild_pending(context, provider, parent_digest, response)
                .await?;
        }

        await_or_cancel(response, self.fork_batches(&parent_digest))
            .await
            .unwrap_or(Err(PrepareBatchesError::Cancelled))
    }

    /// Fork unmerkleized batches from known parent state.
    pub(super) async fn fork_batches(
        &mut self,
        parent: &<A::Block as Digestible>::Digest,
    ) -> Result<<A::Databases as DatabaseSet<E>>::Unmerkleized, PrepareBatchesError> {
        if let Some((_, merkleized)) = self.pending.get(parent) {
            return Ok(<A::Databases as DatabaseSet<E>>::fork_batches(merkleized));
        }
        if &self.last_processed_digest == parent {
            return Ok(self.databases.new_batches().await);
        }
        Err(PrepareBatchesError::Invalid)
    }

    /// Rebuild missing pending ancestry up to `target` lazily from provider history.
    pub(super) async fn rebuild_pending<P, Response>(
        &mut self,
        context: &E,
        provider: P,
        target: <A::Block as Digestible>::Digest,
        response: &mut oneshot::Sender<Response>,
    ) -> Result<(), PrepareBatchesError>
    where
        P: BlockProvider<Block = A::Block> + Clone,
    {
        // Walk backward until we hit a known safe anchor.
        let mut to_replay = Vec::new();
        let mut current = target;
        while current != self.last_processed_digest {
            if self.pending.contains_key(&current) {
                break;
            }

            let fetched =
                match await_or_cancel(response, provider.clone().fetch_block(current)).await {
                    Some(block) => block,
                    None => return Err(PrepareBatchesError::Cancelled),
                };
            let Some(block) = fetched else {
                // A dropped subscription is not proof of invalidity, so retry.
                //
                // This loop is cancellation-bound by consensus timeouts: the
                // caller drops `response` when propose/verify expires, and every
                // await in this method is wrapped with `await_or_cancel`.
                debug!(
                    ?target,
                    ?current,
                    "ancestor subscription ended before delivery, retrying"
                );
                continue;
            };

            // Marshal ancestry fetches cannot step past height 1 because
            // genesis is not served by the provider.
            if block.height() <= Height::new(1) {
                warn!(
                    ?target,
                    ?current,
                    reached_height = %block.height(),
                    last_processed = ?self.last_processed_digest,
                    pending_keys = self.pending.len(),
                    "rebuild reached ancestry boundary without known anchor"
                );
                return Err(PrepareBatchesError::Invalid);
            }

            let parent_digest = block.parent();
            to_replay.push(block);
            current = parent_digest;
        }

        // Replay from oldest to newest and cache intermediate tips.
        for block in to_replay.into_iter().rev() {
            let (digest, parent_digest) = (block.digest(), block.parent());
            let consensus_context = block.context();
            let round = Round::new(consensus_context.epoch(), consensus_context.view());

            let batches = match await_or_cancel(response, self.fork_batches(&parent_digest)).await {
                Some(Ok(batches)) => batches,
                Some(Err(err)) => return Err(err),
                None => return Err(PrepareBatchesError::Cancelled),
            };
            let merkleized = match await_or_cancel(
                response,
                self.app
                    .apply((context.clone(), consensus_context), &block, batches),
            )
            .await
            {
                Some(merkleized) => merkleized,
                None => return Err(PrepareBatchesError::Cancelled),
            };

            self.pending.insert(digest, (round, merkleized));
        }

        Ok(())
    }

    /// Persist finalized state and prune dead in-memory forks.
    pub(super) async fn finalize(&mut self, context: &E, block: A::Block) -> FinalizeStatus {
        let (height, digest) = (block.height(), block.digest());
        if self.last_processed_digest == digest {
            return FinalizeStatus::Duplicate;
        }

        // Marshal finalization is ordered. A pending miss means we can safely
        // apply this block on top of finalized state.
        let batch = match self.pending.remove(&digest) {
            Some((_, merkleized)) => merkleized,
            None => {
                let batches = self.databases.new_batches().await;
                self.app
                    .apply((context.clone(), block.context()), &block, batches)
                    .await
            }
        };

        let round = Round::new(block.context().epoch(), block.context().view());
        self.databases.finalize(batch).await;
        self.pending.retain(|_, (r, _)| *r > round);
        self.last_processed_digest = digest;

        FinalizeStatus::Persisted { height }
    }
}

/// Wait for `future` unless the response receiver is dropped.
pub(super) async fn await_or_cancel<R, T, F>(
    response: &mut oneshot::Sender<R>,
    future: F,
) -> Option<T>
where
    F: Future<Output = T>,
{
    select! {
        _ = response.closed() => None,
        output = future => Some(output),
    }
}

#[cfg(test)]
mod tests {
    use super::{FinalizeStatus, PrepareBatchesError, Processor};
    use crate::stateful::{
        db::{DatabaseSet, Merkleized as _, Unmerkleized as _},
        Application, Proposed,
    };
    use commonware_codec::{Encode, EncodeSize, Error as CodecError, Read, ReadExt as _, Write};
    use commonware_consensus::{
        marshal::ancestry::{AncestorStream, BlockProvider},
        simplex::{mocks::scheme::Scheme as MockScheme, types::Context as ConsensusContext},
        types::{Epoch, Height, Round, View},
        Block as ConsensusBlock, CertifiableBlock, Heightable,
    };
    use commonware_cryptography::{
        ed25519, sha256::Digest, Digest as _, Digestible, Hasher, Sha256, Signer as _,
    };
    use commonware_runtime::{
        buffer::paged::CacheRef, deterministic, ContextCell, Metrics as _, Runner as _,
    };
    use commonware_storage::{
        mmr::Location,
        qmdb::{any, sync::Target},
        translator::TwoCap,
    };
    use commonware_utils::{
        channel::oneshot,
        non_empty_range,
        range::NonEmptyRange,
        sync::{AsyncRwLock, Mutex},
        NZUsize, NZU16, NZU64,
    };
    use std::{
        collections::BTreeMap,
        num::NonZeroUsize,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        },
    };

    type TestContext = ConsensusContext<Digest, ed25519::PublicKey>;

    const PAGE_SIZE: std::num::NonZeroU16 = NZU16!(1024);
    const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(8);
    const IO_BUFFER_SIZE: NonZeroUsize = NZUsize!(2048);

    type Qmdb<E> = any::unordered::fixed::Db<E, Digest, Digest, Sha256, TwoCap>;
    type DbSet<E> = Arc<AsyncRwLock<Qmdb<E>>>;

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct Block {
        context: TestContext,
        parent: Digest,
        height: Height,
        state_root: Digest,
        range: NonEmptyRange<Location>,
    }

    impl Write for Block {
        fn write(&self, buf: &mut impl commonware_runtime::BufMut) {
            self.context.write(buf);
            self.parent.write(buf);
            self.height.write(buf);
            self.state_root.write(buf);
            self.range.write(buf);
        }
    }

    impl EncodeSize for Block {
        fn encode_size(&self) -> usize {
            self.context.encode_size()
                + self.parent.encode_size()
                + self.height.encode_size()
                + self.state_root.encode_size()
                + self.range.encode_size()
        }
    }

    impl Read for Block {
        type Cfg = ();

        fn read_cfg(
            buf: &mut impl commonware_runtime::Buf,
            _: &Self::Cfg,
        ) -> Result<Self, CodecError> {
            Ok(Self {
                context: TestContext::read(buf)?,
                parent: Digest::read(buf)?,
                height: Height::read(buf)?,
                state_root: Digest::read(buf)?,
                range: commonware_utils::range::NonEmptyRange::read(buf)?,
            })
        }
    }

    impl Digestible for Block {
        type Digest = Digest;

        fn digest(&self) -> Digest {
            Sha256::hash(&self.encode())
        }
    }

    impl Heightable for Block {
        fn height(&self) -> Height {
            self.height
        }
    }

    impl ConsensusBlock for Block {
        fn parent(&self) -> Digest {
            self.parent
        }
    }

    impl CertifiableBlock for Block {
        type Context = TestContext;

        fn context(&self) -> Self::Context {
            self.context.clone()
        }
    }

    impl Block {
        fn genesis() -> Self {
            Self {
                context: consensus_context(Digest::EMPTY, View::zero()),
                parent: Digest::EMPTY,
                height: Height::zero(),
                state_root: Digest::EMPTY,
                range: non_empty_range!(Location::new(0), Location::new(1)),
            }
        }
    }

    fn consensus_context(parent: Digest, view: View) -> TestContext {
        TestContext {
            round: Round::new(Epoch::zero(), view),
            leader: ed25519::PrivateKey::from_seed(0).public_key(),
            parent: (
                if view.is_zero() {
                    View::zero()
                } else {
                    View::new(view.get() - 1)
                },
                parent,
            ),
        }
    }

    fn u64_to_digest(value: u64) -> Digest {
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&value.to_be_bytes());
        Digest::from(bytes)
    }

    fn digest_to_u64(value: &Digest) -> u64 {
        let bytes: &[u8] = value.as_ref();
        u64::from_be_bytes(
            bytes[..8]
                .try_into()
                .expect("digest prefix should be 8 bytes"),
        )
    }

    fn height_key(height: Height) -> Digest {
        Sha256::hash(&height.get().to_be_bytes())
    }

    fn counter_key() -> Digest {
        Sha256::hash(b"processor_harness_counter")
    }

    #[derive(Clone)]
    struct ExecutionApp {
        genesis: Block,
    }

    impl ExecutionApp {
        fn new() -> Self {
            Self {
                genesis: Block::genesis(),
            }
        }

        async fn execute(
            height: Height,
            view: View,
            mut batches: <DbSet<deterministic::Context> as DatabaseSet<deterministic::Context>>::Unmerkleized,
        ) -> <DbSet<deterministic::Context> as DatabaseSet<deterministic::Context>>::Merkleized
        {
            let current_counter = batches
                .get(&counter_key())
                .await
                .expect("counter read should succeed")
                .map_or(0, |digest| digest_to_u64(&digest));
            batches = batches.write(counter_key(), Some(u64_to_digest(current_counter + 1)));
            batches = batches.write(height_key(height), Some(u64_to_digest(view.get())));
            batches.merkleize().await.expect("merkleize should succeed")
        }
    }

    impl Application<deterministic::Context> for ExecutionApp {
        type SigningScheme = MockScheme<ed25519::PublicKey>;
        type Context = TestContext;
        type Block = Block;
        type Databases = DbSet<deterministic::Context>;
        type InputProvider = ();

        async fn genesis(&mut self) -> Self::Block {
            self.genesis.clone()
        }

        async fn propose<A: BlockProvider<Block = Self::Block>>(
            &mut self,
            context: (deterministic::Context, Self::Context),
            ancestry: AncestorStream<A, Self::Block>,
            batches: <Self::Databases as DatabaseSet<deterministic::Context>>::Unmerkleized,
            _input: &mut Self::InputProvider,
        ) -> Option<Proposed<Self, deterministic::Context>> {
            let parent = ancestry.peek()?;
            let context = context.1.clone();
            let view = context.round.view();
            let height = parent.height().next();
            let merkleized = Self::execute(height, view, batches).await;
            let block = Block {
                context,
                parent: parent.digest(),
                height,
                state_root: merkleized.root(),
                range: non_empty_range!(Location::new(0), Location::new(1)),
            };
            Some(Proposed { block, merkleized })
        }

        async fn verify<A: BlockProvider<Block = Self::Block>>(
            &mut self,
            _context: (deterministic::Context, Self::Context),
            ancestry: AncestorStream<A, Self::Block>,
            batches: <Self::Databases as DatabaseSet<deterministic::Context>>::Unmerkleized,
        ) -> Option<<Self::Databases as DatabaseSet<deterministic::Context>>::Merkleized> {
            let block = ancestry.peek()?;
            let merkleized =
                Self::execute(block.height(), block.context.round.view(), batches).await;
            if merkleized.root() != block.state_root {
                return None;
            }
            Some(merkleized)
        }

        async fn apply(
            &mut self,
            _context: (deterministic::Context, Self::Context),
            block: &Self::Block,
            batches: <Self::Databases as DatabaseSet<deterministic::Context>>::Unmerkleized,
        ) -> <Self::Databases as DatabaseSet<deterministic::Context>>::Merkleized {
            Self::execute(block.height(), block.context.round.view(), batches).await
        }

        fn sync_targets(
            block: &Self::Block,
        ) -> <Self::Databases as DatabaseSet<deterministic::Context>>::SyncTargets {
            Target {
                root: block.state_root,
                range: block.range.clone(),
            }
        }
    }

    #[derive(Clone, Default)]
    struct MapProvider {
        blocks: Arc<Mutex<BTreeMap<Digest, Block>>>,
    }

    impl MapProvider {
        fn insert(&self, block: Block) {
            self.blocks.lock().insert(block.digest(), block);
        }
    }

    impl BlockProvider for MapProvider {
        type Block = Block;

        async fn fetch_block(self, digest: Digest) -> Option<Self::Block> {
            self.blocks.lock().get(&digest).cloned()
        }
    }

    struct Harness {
        context_cell: ContextCell<deterministic::Context>,
        processor: Processor<deterministic::Context, ExecutionApp>,
        provider: MapProvider,
        db_config: any::FixedConfig<TwoCap>,
    }

    impl Harness {
        async fn new(context: deterministic::Context) -> Self {
            let provider = MapProvider::default();
            let config = qmdb_config(&next_partition_prefix(), &context);
            let databases = <DbSet<deterministic::Context> as DatabaseSet<
                deterministic::Context,
            >>::init(context.with_label("db_set"), config.clone())
            .await;
            Self {
                context_cell: ContextCell::new(context),
                processor: Processor::new(
                    ExecutionApp::new(),
                    databases,
                    Block::genesis().digest(),
                ),
                provider,
                db_config: config,
            }
        }

        async fn stage_pending_child(&mut self, parent: &Block, view: View) -> Block {
            let context = consensus_context(parent.digest(), view);
            let height = Height::new(parent.height().get() + 1);
            let batches = self
                .processor
                .fork_batches(&parent.digest())
                .await
                .expect("parent should be available");
            let merkleized = ExecutionApp::execute(height, view, batches).await;
            let block = Block {
                context,
                parent: parent.digest(),
                height,
                state_root: merkleized.root(),
                range: non_empty_range!(Location::new(0), Location::new(1)),
            };
            let round = Round::new(Epoch::zero(), view);
            self.processor
                .pending
                .insert(block.digest(), (round, merkleized));
            self.provider.insert(block.clone());
            block
        }

        async fn rebuild_pending(
            &mut self,
            target: Digest,
            response: &mut oneshot::Sender<bool>,
        ) -> Result<(), PrepareBatchesError> {
            self.processor
                .rebuild_pending(
                    self.context_cell.as_present(),
                    self.provider.clone(),
                    target,
                    response,
                )
                .await
        }

        async fn finalize(&mut self, block: Block) -> FinalizeStatus {
            self.processor
                .finalize(self.context_cell.as_present(), block)
                .await
        }

        async fn height_value(&self, height: Height) -> Option<u64> {
            let db = self.processor.databases.read().await;
            db.get(&height_key(height))
                .await
                .expect("database read should succeed")
                .map(|value| digest_to_u64(&value))
        }

        async fn counter_value(&self) -> Option<u64> {
            let db = self.processor.databases.read().await;
            db.get(&counter_key())
                .await
                .expect("database read should succeed")
                .map(|value| digest_to_u64(&value))
        }

        async fn reopen_height_value(
            &self,
            context: deterministic::Context,
            height: Height,
        ) -> Option<u64> {
            let reopened: Qmdb<deterministic::Context> =
                Qmdb::init(context.with_label("reopen_db"), self.db_config.clone())
                    .await
                    .expect("database reopen should succeed");
            reopened
                .get(&height_key(height))
                .await
                .expect("reopened db read should succeed")
                .map(|value| digest_to_u64(&value))
        }
    }

    fn next_partition_prefix() -> String {
        static NEXT_ID: AtomicUsize = AtomicUsize::new(0);
        let id = NEXT_ID.fetch_add(1, Ordering::SeqCst);
        format!("processor_harness_{id}")
    }

    fn qmdb_config(prefix: &str, context: &deterministic::Context) -> any::FixedConfig<TwoCap> {
        any::FixedConfig {
            mmr_journal_partition: format!("{prefix}_mmr_journal"),
            mmr_items_per_blob: NZU64!(11),
            mmr_write_buffer: IO_BUFFER_SIZE,
            mmr_metadata_partition: format!("{prefix}_mmr_metadata"),
            log_journal_partition: format!("{prefix}_log_journal"),
            log_items_per_blob: NZU64!(7),
            log_write_buffer: IO_BUFFER_SIZE,
            translator: TwoCap,
            thread_pool: None,
            page_cache: CacheRef::from_pooler(context, PAGE_SIZE, PAGE_CACHE_SIZE),
        }
    }

    #[test]
    fn execution_finalization_prunes_losing_fork() {
        deterministic::Runner::default().start(|context| async move {
            let mut harness = Harness::new(context).await;
            let genesis = Block::genesis();
            let block1 = harness.stage_pending_child(&genesis, View::new(1)).await;
            let winner = harness.stage_pending_child(&block1, View::new(3)).await;
            let loser = harness.stage_pending_child(&block1, View::new(2)).await;

            assert!(harness.processor.pending.contains_key(&winner.digest()));
            assert!(harness.processor.pending.contains_key(&loser.digest()));

            let status = harness.finalize(winner.clone()).await;
            assert_eq!(
                status,
                FinalizeStatus::Persisted {
                    height: Height::new(2)
                },
                "finalization should persist winner state",
            );
            assert!(
                !harness.processor.pending.contains_key(&loser.digest()),
                "losing fork at finalized round should be pruned",
            );
            assert_eq!(harness.processor.last_processed_digest, winner.digest());
            assert_eq!(harness.height_value(Height::new(2)).await, Some(3));
        });
    }

    #[test]
    fn execution_rebuild_pending_restores_missing_chain() {
        deterministic::Runner::default().start(|context| async move {
            let mut harness = Harness::new(context).await;
            let genesis = Block::genesis();
            let block1 = harness.stage_pending_child(&genesis, View::new(1)).await;
            let status = harness.finalize(block1.clone()).await;
            assert_eq!(
                status,
                FinalizeStatus::Persisted {
                    height: Height::new(1)
                }
            );

            let block2 = harness.stage_pending_child(&block1, View::new(2)).await;
            let block3 = harness.stage_pending_child(&block2, View::new(3)).await;
            harness.processor.pending.clear();
            harness.provider.insert(block2.clone());
            harness.provider.insert(block3.clone());

            let (mut response, _rx) = oneshot::channel::<bool>();
            let result = harness
                .rebuild_pending(block3.digest(), &mut response)
                .await;
            assert_eq!(result, Ok(()), "rebuild should succeed");
            assert!(
                harness.processor.pending.contains_key(&block2.digest()),
                "first missing descendant should be reconstructed",
            );
            assert!(
                harness.processor.pending.contains_key(&block3.digest()),
                "target block should be reconstructed",
            );
        });
    }

    #[test]
    fn execution_finalization_persists_state_to_db() {
        deterministic::Runner::default().start(|context| async move {
            let mut harness = Harness::new(context.clone()).await;
            let genesis = Block::genesis();
            let block1 = harness.stage_pending_child(&genesis, View::new(1)).await;

            let status = harness.finalize(block1).await;
            assert_eq!(
                status,
                FinalizeStatus::Persisted {
                    height: Height::new(1)
                }
            );
            assert_eq!(harness.counter_value().await, Some(1));
            assert_eq!(
                harness.reopen_height_value(context, Height::new(1)).await,
                Some(1),
                "height state should survive reopen after finalization",
            );
        });
    }
}
