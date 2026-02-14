//! Consensus-facing application implementation for the REVM chain example.
//!
//! Threshold-simplex orders only block commitments (digests). Full blocks are disseminated and
//! backfilled by `commonware_consensus::marshal`. The `commonware_consensus::application::marshaled::Marshaled`
//! wrapper bridges these layers by fetching required ancestors from marshal and calling into this
//! module with an `AncestorStream` you can iterate to walk back over pending blocks.
//!
//! The node wiring that wraps this application lives in `examples/revm/src/application/node.rs`.

use super::{
    execution::{evm_env, execute_txs},
    ledger::{LedgerService, LedgerView},
};
use crate::{
    domain::{Block, BlockContext, TxId},
    ConsensusDigest, PublicKey,
};
use alloy_evm::revm::primitives::B256;
use commonware_consensus::{
    marshal::ingress::mailbox::AncestorStream,
    simplex::{scheme::Scheme, types::Context},
    Application, VerifyingApplication,
};
use commonware_cryptography::{certificate::Scheme as CertScheme, Committable as _};
use commonware_runtime::{Clock, Metrics, Spawner};
use futures::StreamExt as _;
use rand::Rng;
use std::{collections::BTreeSet, marker::PhantomData};

/// Helper function for propose that owns all its inputs.
async fn propose_inner<S>(
    // Ledger service commands for proposal preparation.
    state: LedgerService,
    max_txs: usize,
    context: BlockContext,
    mut ancestry: AncestorStream<S, Block>,
) -> Option<Block>
where
    S: CertScheme,
{
    let parent = ancestry.next().await?;

    // Transactions remain in the mempool until the block that includes them finalizes. Walk
    // back over pending ancestors so we do not propose a block that re-includes in-flight txs.
    let mut included = BTreeSet::<TxId>::new();
    for tx in parent.txs.iter() {
        included.insert(tx.id());
    }
    while let Some(block) = ancestry.next().await {
        for tx in block.txs.iter() {
            included.insert(tx.id());
        }
    }

    let parent_digest = parent.commitment();
    let parent_snapshot = state.parent_snapshot(parent_digest).await?;
    let seed_hash = state.seed_for_parent(parent_digest).await;
    let prevrandao = seed_hash.unwrap_or_else(|| B256::from(parent_digest.0));
    let height = parent.height + 1;

    let txs = state.build_txs(max_txs, &included).await;

    let env = evm_env(height, prevrandao);
    let (db, outcome) = execute_txs(parent_snapshot.db, env, &txs).ok()?;

    let mut child = Block {
        context,
        parent: parent.id(),
        height,
        prevrandao,
        state_root: parent.state_root,
        txs,
    };
    child.state_root = state
        .compute_root(parent_digest, outcome.qmdb_changes.clone())
        .await
        .ok()?;

    let digest = child.commitment();
    state
        .insert_snapshot(
            digest,
            parent_digest,
            db,
            child.state_root,
            outcome.qmdb_changes,
        )
        .await;
    Some(child)
}

/// Helper function for verify that owns all its inputs.
async fn verify_inner<S>(
    state: LedgerService,
    context: BlockContext,
    mut ancestry: AncestorStream<S, Block>,
) -> bool
where
    S: CertScheme,
{
    let block = match ancestry.next().await {
        Some(block) => block,
        None => return false,
    };
    if block.context != context {
        return false;
    }
    let parent = match ancestry.next().await {
        Some(block) => block,
        None => return false,
    };

    let parent_digest = parent.commitment();
    let Some(parent_snapshot) = state.parent_snapshot(parent_digest).await else {
        return false;
    };

    let env = evm_env(block.height, block.prevrandao);
    let (db, outcome) = match execute_txs(parent_snapshot.db, env, &block.txs) {
        Ok(result) => result,
        Err(_) => return false,
    };
    let state_root = match state
        .compute_root(parent_digest, outcome.qmdb_changes.clone())
        .await
    {
        Ok(root) => root,
        Err(_) => return false,
    };
    if state_root != block.state_root {
        return false;
    }

    let digest = block.commitment();
    state
        .insert_snapshot(digest, parent_digest, db, state_root, outcome.qmdb_changes)
        .await;
    true
}

#[derive(Clone)]
/// Consensus-facing REVM application that bridges marshal and REVM state.
pub(crate) struct RevmApplication<S> {
    /// Maximum number of transactions to include when proposing new blocks.
    max_txs: usize,
    /// Ledger service used to orchestrate ledger commands.
    state: LedgerService,
    /// Marker tracking the signing scheme used by this application instance.
    _scheme: PhantomData<S>,
}

impl<S> RevmApplication<S> {
    /// Create a REVM application with the shared state handle.
    pub(crate) fn new(max_txs: usize, state: LedgerView) -> Self {
        Self {
            max_txs,
            state: LedgerService::new(state),
            _scheme: PhantomData,
        }
    }
}

impl<E, S> Application<E> for RevmApplication<S>
where
    E: Rng + Spawner + Metrics + Clock,
    S: Scheme<ConsensusDigest>
        + commonware_cryptography::certificate::Scheme<PublicKey = PublicKey>,
{
    type SigningScheme = S;
    type Context = Context<ConsensusDigest, PublicKey>;
    type Block = Block;

    fn genesis(&mut self) -> impl std::future::Future<Output = Self::Block> + Send {
        let block = self.state.genesis_block();
        async move { block }
    }

    fn propose(
        &mut self,
        context: (E, Self::Context),
        ancestry: AncestorStream<Self::SigningScheme, Self::Block>,
    ) -> impl std::future::Future<Output = Option<Self::Block>> + Send {
        let state = self.state.clone();
        let max_txs = self.max_txs;
        let (_, context) = context;
        async move { propose_inner(state, max_txs, context, ancestry).await }
    }
}

impl<E, S> VerifyingApplication<E> for RevmApplication<S>
where
    E: Rng + Spawner + Metrics + Clock,
    S: Scheme<ConsensusDigest>
        + commonware_cryptography::certificate::Scheme<PublicKey = PublicKey>,
{
    fn verify(
        &mut self,
        context: (E, Self::Context),
        ancestry: AncestorStream<Self::SigningScheme, Self::Block>,
    ) -> impl std::future::Future<Output = bool> + Send {
        let state = self.state.clone();
        let (_, context) = context;
        async move { verify_inner(state, context, ancestry).await }
    }
}
