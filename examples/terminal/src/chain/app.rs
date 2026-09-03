//! The settlement chain's `glue::stateful` application.

use crate::{
    chain::{
        ingress::Provider,
        state::execute,
        types::{
            Block, Database, MAX_BLOCK_BYTES, MAX_BLOCK_TXS, MAX_TX_BYTES, Qmdb, SyncTarget, now,
        },
    },
    protocol::{Deployment, Timing},
};
use commonware_codec::EncodeSize as _;
use commonware_consensus::{Heightable as _, marshal::ancestry::Ancestry, simplex::types::Context};
use commonware_cryptography::{Digestible as _, certificate::Scheme, ed25519, sha256::Digest};
use commonware_glue::stateful::{
    Application, Input, Proposed,
    db::{DatabaseSet, ManagedDb, Merkleized as _},
};
use commonware_runtime::{Clock, Spawner};
use commonware_storage::Context as StorageContext;
use commonware_utils::{non_empty_range, sync::Mutex};
use futures::StreamExt as _;
use rand_core::Rng;
use std::{marker::PhantomData, sync::Arc, time::Duration};

/// Maximum milliseconds a block's timestamp may lead the verifier's clock at
/// vote time.
///
/// Demo-grade bound: generous against honest clock skew and scheduling delay,
/// while capping both how far ahead a proposer can date a block over honest
/// clocks and, therefore, how long verifiers wait out a future-dated block.
pub(crate) const MAX_TIMESTAMP_DRIFT: u64 = 2_000;

/// One finalized tip entry: the block's height, digest, canonical root, and
/// timestamp.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Tip {
    pub(crate) height: u64,
    pub(crate) digest: Digest,
    pub(crate) root: Digest,
    pub(crate) timestamp: u64,
}

/// Shared latest finalized [`Tip`] of the chain.
///
/// Maintained by [`Application::finalized`] for the query server and the
/// operator's local reads. Only the latest entry is ever consumed, so exactly
/// one is retained. Updates are monotonic by height and idempotent, so
/// marshal's at-least-once finalized stream is safe to replay into it.
#[derive(Clone, Default)]
pub(crate) struct Finalized {
    inner: Arc<Mutex<Option<Tip>>>,
}

impl Finalized {
    /// Returns the highest finalized tip.
    pub(crate) fn latest(&self) -> Option<Tip> {
        *self.inner.lock()
    }

    pub(crate) fn record(&self, height: u64, digest: Digest, root: Digest, timestamp: u64) {
        let mut inner = self.inner.lock();
        if inner.is_none_or(|tip| tip.height <= height) {
            *inner = Some(Tip {
                height,
                digest,
                root,
                timestamp,
            });
        }
    }
}

/// The settlement application: every block executes its transactions through
/// [`crate::chain::state`] against the managed QMDB.
///
/// Generic over the certificate scheme and the transaction provider so the
/// same application serves the deterministic tests (mock scheme, in-memory
/// queue) and the networked validators.
pub(crate) struct App<S, P> {
    genesis: Block,
    /// Chain-wide genesis epoch timing policy applied to every deployment.
    timing: Timing,
    /// The configured deployment set from the shared genesis.
    deployments: Vec<Deployment>,
    finalized: Finalized,
    _marker: PhantomData<fn() -> (S, P)>,
}

impl<S, P> Clone for App<S, P> {
    fn clone(&self) -> Self {
        Self {
            genesis: self.genesis.clone(),
            timing: self.timing,
            deployments: self.deployments.clone(),
            finalized: self.finalized.clone(),
            _marker: PhantomData,
        }
    }
}

impl<S, P> App<S, P> {
    /// Creates the application with its genesis block, the chain-wide timing
    /// policy, the configured deployment set, and the finalized index it
    /// maintains.
    pub(crate) const fn new(
        genesis: Block,
        timing: Timing,
        deployments: Vec<Deployment>,
        finalized: Finalized,
    ) -> Self {
        Self {
            genesis,
            timing,
            deployments,
            finalized,
            _marker: PhantomData,
        }
    }
}

impl<E, S, P> Application<E> for App<S, P>
where
    E: Rng + Spawner + StorageContext + Clock,
    S: Scheme,
    P: Provider,
{
    type SigningScheme = S;
    type Context = Context<Digest, ed25519::PublicKey>;
    type Block = Block;
    type Databases = Database<E>;
    type Provider = P;
    type Input = ();

    async fn genesis(&mut self) -> Self::Block {
        self.genesis.clone()
    }

    async fn propose(
        &mut self,
        context: (E, Self::Context),
        ancestry: impl Ancestry<Self::Block>,
        batches: <Self::Databases as DatabaseSet<E>>::Unmerkleized,
        mut input: Input<Self::Input, Self::Provider>,
    ) -> Option<Proposed<Self, E>> {
        let mut ancestry = Box::pin(ancestry);
        let parent = ancestry.next().await?;
        let height = parent.height().next();

        // The proposed timestamp is the local clock, floored one past the
        // parent's so timestamps stay strictly monotonic even under clock
        // regression. It serves query recency and display only.
        let timestamp = parent.timestamp.checked_add(1)?.max(now(&context.0));

        // The drain stops under the block byte budget, so the proposed block
        // always fits the p2p frame and its decode bound. Transactions beyond
        // the per-transaction wire bound could never decode on a peer, so
        // they are dropped rather than proposed.
        let transactions = input
            .provider
            .drain(MAX_BLOCK_TXS, MAX_BLOCK_BYTES)
            .await
            .into_iter()
            .filter(|tx| tx.encode_size() <= MAX_TX_BYTES)
            .collect::<Vec<_>>();
        let merkleized = execute(
            batches,
            height,
            timestamp,
            &self.timing,
            &self.deployments,
            &transactions,
        )
        .await
        .expect("proposal execution must read settlement state");
        let block = Block {
            context: context.1,
            parent: parent.digest(),
            height,
            timestamp,
            state_root: merkleized.root(),
            ops_root: merkleized.ops_root(),
            range: non_empty_range!(merkleized.sync_boundary(), merkleized.bounds().tip.size),
            transactions,
        };
        Some(Proposed { block, merkleized })
    }

    async fn verify(
        &mut self,
        context: (E, Self::Context),
        ancestry: impl Ancestry<Self::Block>,
        batches: <Self::Databases as DatabaseSet<E>>::Unmerkleized,
    ) -> Option<<Self::Databases as DatabaseSet<E>>::Merkleized> {
        let mut ancestry = Box::pin(ancestry);
        let block = ancestry.next().await?;
        let parent = ancestry.next().await?;

        // Timestamp check one, deterministic: a block whose timestamp does
        // not strictly exceed its parent's is permanently invalid for this
        // ancestry.
        if block.timestamp <= parent.timestamp {
            return None;
        }

        // Timestamp check two, vote-time drift: a block dated beyond the
        // local clock plus the drift bound is not voted on yet. It is not
        // permanently invalid (the clock catches up), so wait it out instead
        // of returning `None`. The wait is bounded by the drift an honest or
        // dishonest proposer could have claimed over honest clocks, and the
        // loop mutates nothing, so cancelling and re-running it is safe.
        loop {
            let bound = now(&context.0).saturating_add(MAX_TIMESTAMP_DRIFT);
            if block.timestamp <= bound {
                break;
            }

            // The subtraction cannot underflow: the loop only reaches it
            // while the timestamp exceeds the bound.
            let wait = block.timestamp - bound;
            context.0.sleep(Duration::from_millis(wait)).await;
        }

        // Execution is decidable from the block and its ancestry state: a
        // not-yet-finalizable admission is a valid state write, so execution
        // itself never waits. `None` is returned only for a block whose
        // committed canonical root does not match re-execution. The wrapper
        // checks only the ops root and range for current databases, so the
        // canonical-root check must happen here.
        let merkleized = execute(
            batches,
            block.height(),
            block.timestamp,
            &self.timing,
            &self.deployments,
            &block.transactions,
        )
        .await
        .expect("verification execution must read settlement state");
        if merkleized.root() != block.state_root {
            return None;
        }
        Some(merkleized)
    }

    async fn apply(
        &mut self,
        _context: (E, Self::Context),
        block: &Self::Block,
        batches: <Self::Databases as DatabaseSet<E>>::Unmerkleized,
    ) -> <Self::Databases as DatabaseSet<E>>::Merkleized {
        // Replay of a certified block: only the deterministic timestamp
        // monotonicity is re-checked (inside execution), never the vote-time
        // drift bound.
        execute(
            batches,
            block.height(),
            block.timestamp,
            &self.timing,
            &self.deployments,
            &block.transactions,
        )
        .await
        .expect("replay execution must read settlement state")
    }

    fn sync_targets(block: &Self::Block) -> <Self::Databases as DatabaseSet<E>>::SyncTargets {
        SyncTarget::new(block.ops_root, block.range.clone())
    }

    async fn finalized(
        &mut self,
        _context: (E, Self::Context),
        block: &Self::Block,
        _readers: <Self::Databases as DatabaseSet<E>>::Readers,
    ) {
        self.finalized.record(
            block.height().get(),
            block.digest(),
            block.state_root,
            block.timestamp,
        );
    }
}

/// The initial sync target of an empty settlement database.
pub(crate) fn initial_sync_target<E>() -> SyncTarget
where
    E: StorageContext + Spawner,
{
    <Qmdb<E> as ManagedDb<E>>::initial_sync_target()
}
