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

use super::metrics::Metrics as ProcessorMetrics;
use crate::stateful::{
    db::{Anchor, DatabaseSet},
    Application, Proposed,
};
use commonware_consensus::{
    marshal::ancestry::{AncestorStream, BlockProvider},
    types::{Height, Round},
    Block, CertifiableBlock, Epochable, Heightable, Viewable,
};
use commonware_cryptography::Digestible;
use commonware_macros::select;
use commonware_runtime::{telemetry::metrics::status::GaugeExt, Clock, Metrics, Spawner};
use commonware_utils::channel::{fallible::OneshotExt, oneshot};
use rand::Rng;
use std::{
    collections::{BTreeMap, HashSet, VecDeque},
    future::Future,
};
use tracing::{debug, warn};

type PendingDigest<A, E> = <<A as Application<E>>::Block as Digestible>::Digest;
type PendingBatches<A, E> = <<A as Application<E>>::Databases as DatabaseSet<E>>::Merkleized;

/// Cached speculative state for a block digest.
struct PendingEntry<A, E>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    round: Round,
    parent: PendingDigest<A, E>,
    merkleized: PendingBatches<A, E>,
}

type PendingMap<A, E> = BTreeMap<PendingDigest<A, E>, PendingEntry<A, E>>;

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
    last_processed: Anchor<PendingDigest<A, E>>,
    metrics: ProcessorMetrics<E>,
}

impl<E, A> Processor<E, A>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    /// Create a new processor with the given application, databases, and
    /// the last finalized block's anchor.
    pub(super) const fn new(
        app: A,
        databases: A::Databases,
        last_processed: Anchor<PendingDigest<A, E>>,
        metrics: ProcessorMetrics<E>,
    ) -> Self {
        Self {
            app,
            databases,
            pending: BTreeMap::new(),
            last_processed,
            metrics,
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
    pub(super) async fn propose<P1, P2>(
        &mut self,
        context: &E,
        provider: P1,
        (runtime_context, consensus_context): (E, A::Context),
        ancestry: AncestorStream<P2, A::Block>,
        input_provider: &mut A::InputProvider,
        mut response: oneshot::Sender<Option<A::Block>>,
    ) where
        P1: BlockProvider<Block = A::Block> + Clone,
        P2: BlockProvider<Block = A::Block>,
    {
        let timer = self.metrics.propose_duration.timer();

        let Some(parent) = ancestry.peek() else {
            timer.cancel();
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
                timer.cancel();
                response.send_lossy(None);
                return;
            }
            Err(PrepareBatchesError::Cancelled) => {
                timer.cancel();
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
                timer.cancel();
                debug!(?parent_digest, "proposal request cancelled during propose");
                return;
            }
        };

        let Some(Proposed { block, merkleized }) = proposed else {
            timer.cancel();
            response.send_lossy(None);
            return;
        };
        self.cache_pending(block.digest(), parent_digest, round, merkleized);
        let _ = self.metrics.pending_blocks.try_set(self.pending.len());
        response.send_lossy(Some(block));
    }

    /// Prepare parent-relative batches and delegate to the application to
    /// verify a received block. On success the block's merkleized state is
    /// cached in `pending` and `true` is sent on `response`.
    pub(super) async fn verify<P1, P2>(
        &mut self,
        context: &E,
        provider: P1,
        (runtime_context, consensus_context): (E, A::Context),
        ancestry: AncestorStream<P2, A::Block>,
        mut response: oneshot::Sender<bool>,
    ) where
        P1: BlockProvider<Block = A::Block> + Clone,
        P2: BlockProvider<Block = A::Block>,
    {
        let timer = self.metrics.verify_duration.timer();

        let Some(block) = ancestry.peek() else {
            timer.cancel();
            response.send_lossy(false);
            return;
        };
        let block_digest = block.digest();
        let parent_digest = block.parent();

        // If the block has already been executed, don't execute again.
        if self.pending.contains_key(&block_digest) {
            timer.cancel();
            response.send_lossy(true);
            return;
        }

        // The voter may ask us to verify blocks that are at or below the
        // already-processed height. This happens because marshal/state sync and
        // simplex advance on different message streams.
        //
        // In this case, re-execution is impossible because databases already
        // contain state at or beyond that height. We accept verification and
        // let `finalize()` handle duplicates as no-ops.
        //
        // `last_processed.height` is only advanced from finalized state
        // (genesis, startup reconciliation, or finalize/ack path).
        if self.is_already_processed(block) {
            timer.cancel();
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
                timer.cancel();
                warn!(
                    ?parent_digest,
                    ?block_digest,
                    pending_keys = self.pending.len(),
                    last_processed = ?self.last_processed.digest,
                    "verification rejected: prepare_batches returned Invalid"
                );
                response.send_lossy(false);
                return;
            }
            Err(PrepareBatchesError::Cancelled) => {
                timer.cancel();
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
                timer.cancel();
                debug!(
                    ?parent_digest,
                    "verification request cancelled during verify"
                );
                return;
            }
        };

        let Some(merkleized) = verified else {
            timer.cancel();
            warn!(
                ?parent_digest,
                ?block_digest,
                "verification rejected: app.verify returned None"
            );
            response.send_lossy(false);
            return;
        };
        self.cache_pending(block_digest, parent_digest, round, merkleized);
        let _ = self.metrics.pending_blocks.try_set(self.pending.len());
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
        if self.last_processed.digest != parent_digest && !self.pending.contains_key(&parent_digest)
        {
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
        if let Some(entry) = self.pending.get(parent) {
            return Ok(<A::Databases as DatabaseSet<E>>::fork_batches(
                &entry.merkleized,
            ));
        }
        if &self.last_processed.digest == parent {
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
        let timer = self.metrics.rebuild_pending_duration.timer();

        // Walk backward until we hit a known safe anchor.
        let mut replay_path = Vec::new();
        let mut cursor = target;
        while cursor != self.last_processed.digest && !self.pending.contains_key(&cursor) {
            let Some(fetched) =
                await_or_cancel(response, provider.clone().fetch_block(cursor)).await
            else {
                timer.cancel();
                return Err(PrepareBatchesError::Cancelled);
            };

            let Some(block) = fetched else {
                // A dropped subscription is not proof of invalidity, so retry.
                //
                // This loop is cancellation-bound by consensus timeouts: the
                // caller drops `response` when propose/verify expires, and every
                // await in this method is wrapped with `await_or_cancel`. So,
                // this will never deadlock.
                debug!(
                    ?target,
                    ?cursor,
                    "ancestor subscription ended before delivery, retrying"
                );
                continue;
            };

            let block_height = block.height();
            if block_height <= self.last_processed.height {
                timer.cancel();
                warn!(
                    ?target,
                    ?cursor,
                    current_height = block_height.get(),
                    last_processed_height = self.last_processed.height.get(),
                    last_processed = ?self.last_processed.digest,
                    "rebuild_pending reached stale ancestry below processed height"
                );
                return Err(PrepareBatchesError::Invalid);
            }

            // By definition, there are no blocks below height 0.
            if block_height.previous().is_none() {
                timer.cancel();
                warn!(
                    ?target,
                    ?cursor,
                    reached_height = %block_height,
                    last_processed = ?self.last_processed.digest,
                    pending_keys = self.pending.len(),
                    "rebuild reached ancestry boundary without known anchor"
                );
                return Err(PrepareBatchesError::Invalid);
            }

            cursor = block.parent();
            replay_path.push(block);
        }

        let depth = replay_path.len();

        // Replay from oldest to newest and cache intermediate tips.
        for block in replay_path.into_iter().rev() {
            let (digest, parent_digest) = (block.digest(), block.parent());
            let consensus_context = block.context();
            let round = Round::new(consensus_context.epoch(), consensus_context.view());

            let Some(batches) = await_or_cancel(response, self.fork_batches(&parent_digest)).await
            else {
                timer.cancel();
                return Err(PrepareBatchesError::Cancelled);
            };
            let batches = batches.expect("rebuild replay parent must be available");

            let Some(merkleized) = await_or_cancel(
                response,
                self.app
                    .apply((context.clone(), consensus_context), &block, batches),
            )
            .await
            else {
                timer.cancel();
                return Err(PrepareBatchesError::Cancelled);
            };

            self.cache_pending(digest, parent_digest, round, merkleized);
        }

        let _ = self.metrics.pending_blocks.try_set(self.pending.len());
        let _ = self.metrics.rebuild_pending_depth.try_set(depth);
        Ok(())
    }

    /// Persist finalized state and prune dead in-memory forks.
    pub(super) async fn finalize(&mut self, context: &E, block: A::Block) -> FinalizeStatus {
        let (height, digest) = (block.height(), block.digest());
        if height <= self.last_processed.height {
            return FinalizeStatus::Duplicate;
        }

        let _timer = self.metrics.finalize_duration.timer();
        let block_context = block.context();
        let round = Round::new(block_context.epoch(), block_context.view());

        // Marshal finalization is ordered. A pending miss means we can replay
        // this block on top of finalized state.
        //
        // Safety contract: replayed `Application::apply` output must match the
        // block commitments previously enforced by `Application::verify`.
        let batch = match self.pending.remove(&digest) {
            Some(entry) => entry.merkleized,
            None => {
                let batches = self.databases.new_batches().await;
                self.app
                    .apply((context.clone(), block_context), &block, batches)
                    .await
            }
        };

        self.databases.finalize(batch).await;
        self.prune_pending_after_finalize(&digest, round);
        self.last_processed = Anchor { height, digest };

        FinalizeStatus::Persisted { height }
    }

    /// Remove pending state that is not compatible with the finalized winner.
    ///
    /// A pending block is kept only when:
    /// - it is a descendant of `finalized_digest`, and
    /// - it was created after `finalized_round`.
    fn prune_pending_after_finalize(
        &mut self,
        finalized_digest: &<A::Block as Digestible>::Digest,
        finalized_round: Round,
    ) {
        let mut children_by_parent = BTreeMap::new();
        for (candidate_digest, entry) in &self.pending {
            children_by_parent
                .entry(entry.parent)
                .or_insert_with(Vec::new)
                .push(*candidate_digest);
        }

        let mut compatible = HashSet::new();
        compatible.insert(*finalized_digest);

        let mut to_visit = VecDeque::new();
        to_visit.push_back(*finalized_digest);
        while let Some(parent) = to_visit.pop_front() {
            let Some(children) = children_by_parent.get(&parent) else {
                continue;
            };

            for &child in children {
                if compatible.insert(child) {
                    to_visit.push_back(child);
                }
            }
        }

        let before = self.pending.len();
        self.pending.retain(|candidate_digest, entry| {
            entry.round > finalized_round && compatible.contains(candidate_digest)
        });
        let pruned = before - self.pending.len();
        self.metrics.pruned_forks.inc_by(pruned as u64);
        let _ = self.metrics.pending_blocks.try_set(self.pending.len());
    }

    /// Cache merkleized pending state for a block digest.
    fn cache_pending(
        &mut self,
        digest: PendingDigest<A, E>,
        parent: PendingDigest<A, E>,
        round: Round,
        merkleized: PendingBatches<A, E>,
    ) {
        if let Some(existing) = self.pending.get(&digest) {
            debug_assert_eq!(existing.parent, parent, "pending parent changed for digest");
            debug_assert_eq!(existing.round, round, "pending round changed for digest");
            return;
        }
        self.pending.insert(
            digest,
            PendingEntry {
                round,
                parent,
                merkleized,
            },
        );
    }

    /// Returns true when `block` is already covered by committed state.
    fn is_already_processed(&self, block: &A::Block) -> bool {
        block.height() <= self.last_processed.height
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
        actor::metrics::Metrics as ProcessorMetrics,
        db::{Anchor, DatabaseSet, Merkleized as _, Unmerkleized as _},
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
        journal::contiguous::fixed::Config as FixedLogConfig,
        mmr::{self, journaled::Config as MmrJournalConfig, Location},
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

    type Qmdb<E> = any::unordered::fixed::Db<mmr::Family, E, Digest, Digest, Sha256, TwoCap>;
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
        fetches: Arc<AtomicUsize>,
    }

    impl MapProvider {
        fn insert(&self, block: Block) {
            self.blocks.lock().insert(block.digest(), block);
        }

        fn fetches(&self) -> usize {
            self.fetches.load(Ordering::SeqCst)
        }
    }

    impl BlockProvider for MapProvider {
        type Block = Block;

        async fn fetch_block(self, digest: Digest) -> Option<Self::Block> {
            self.fetches.fetch_add(1, Ordering::SeqCst);
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
            let metrics = ProcessorMetrics::new(context.clone());
            Self {
                context_cell: ContextCell::new(context),
                processor: Processor::new(
                    ExecutionApp::new(),
                    databases,
                    Anchor {
                        height: Height::zero(),
                        digest: Block::genesis().digest(),
                    },
                    metrics,
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
                .cache_pending(block.digest(), parent.digest(), round, merkleized);
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
        let page_cache = CacheRef::from_pooler(context, PAGE_SIZE, PAGE_CACHE_SIZE);
        any::FixedConfig {
            merkle_config: MmrJournalConfig {
                journal_partition: format!("{prefix}_mmr_journal"),
                metadata_partition: format!("{prefix}_mmr_metadata"),
                items_per_blob: NZU64!(11),
                write_buffer: IO_BUFFER_SIZE,
                thread_pool: None,
                page_cache: page_cache.clone(),
            },
            journal_config: FixedLogConfig {
                partition: format!("{prefix}_log_journal"),
                items_per_blob: NZU64!(7),
                page_cache,
                write_buffer: IO_BUFFER_SIZE,
            },
            translator: TwoCap,
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
            assert_eq!(harness.processor.last_processed.digest, winner.digest());
            assert_eq!(harness.height_value(Height::new(2)).await, Some(3));
        });
    }

    #[test]
    fn execution_finalization_prunes_losing_fork_descendants() {
        deterministic::Runner::default().start(|context| async move {
            let mut harness = Harness::new(context).await;
            let genesis = Block::genesis();
            let block1 = harness.stage_pending_child(&genesis, View::new(1)).await;
            let loser = harness.stage_pending_child(&block1, View::new(2)).await;
            let winner = harness.stage_pending_child(&block1, View::new(3)).await;
            let loser_child = harness.stage_pending_child(&loser, View::new(4)).await;

            assert!(harness.processor.pending.contains_key(&winner.digest()));
            assert!(harness.processor.pending.contains_key(&loser.digest()));
            assert!(harness
                .processor
                .pending
                .contains_key(&loser_child.digest()));

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
            assert!(
                !harness
                    .processor
                    .pending
                    .contains_key(&loser_child.digest()),
                "descendants of the losing fork should also be pruned",
            );
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
    fn execution_rebuild_pending_rejects_stale_ancestor_quickly() {
        deterministic::Runner::default().start(|context| async move {
            let mut harness = Harness::new(context).await;
            let genesis = Block::genesis();

            let mut chain = Vec::new();
            let mut parent = genesis;
            for view in 1..=5 {
                let block = harness.stage_pending_child(&parent, View::new(view)).await;
                let status = harness.finalize(block.clone()).await;
                assert_eq!(
                    status,
                    FinalizeStatus::Persisted {
                        height: Height::new(view),
                    }
                );
                parent = block.clone();
                chain.push(block);
            }

            harness.processor.pending.clear();
            let stale_parent = chain[1].digest(); // height 2, below processed height 5
            let fetches_before = harness.provider.fetches();

            let (mut response, _rx) = oneshot::channel::<bool>();
            let result = harness.rebuild_pending(stale_parent, &mut response).await;
            assert_eq!(
                result,
                Err(PrepareBatchesError::Invalid),
                "stale ancestry should be rejected",
            );

            let fetches_after = harness.provider.fetches();
            assert_eq!(
                fetches_after.saturating_sub(fetches_before),
                1,
                "stale ancestry should be rejected after a single fetch",
            );
        });
    }

    #[test]
    fn execution_processed_height_classifier_accepts_stale_blocks() {
        deterministic::Runner::default().start(|context| async move {
            let mut harness = Harness::new(context).await;
            let genesis = Block::genesis();

            let mut chain = Vec::new();
            let mut parent = genesis;
            for view in 1..=5 {
                let block = harness.stage_pending_child(&parent, View::new(view)).await;
                let status = harness.finalize(block.clone()).await;
                assert_eq!(
                    status,
                    FinalizeStatus::Persisted {
                        height: Height::new(view),
                    }
                );
                parent = block.clone();
                chain.push(block);
            }

            harness.processor.pending.clear();
            let stale = chain[1].clone(); // height 2, below processed height 5
            assert!(
                harness.processor.is_already_processed(&stale),
                "stale finalized block should be treated as already processed",
            );

            let fresh = harness
                .stage_pending_child(chain.last().expect("chain must be non-empty"), View::new(6))
                .await;
            assert!(
                !harness.processor.is_already_processed(&fresh),
                "new block above processed height should not be treated as already processed",
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
