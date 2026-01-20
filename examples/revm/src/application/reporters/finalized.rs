use super::super::{
    execution::{evm_env, execute_txs},
    ledger::LedgerService,
};
use crate::domain::Block;
use commonware_consensus::{marshal::Update, Block as _, Reporter};
use commonware_cryptography::Committable as _;
use commonware_utils::acknowledgement::Acknowledgement as _;
use tracing::{error, trace, warn};

/// Helper function for `FinalizedReporter::report` that owns all its inputs.
async fn handle_finalized_update(state: LedgerService, update: Update<Block>) {
    match update {
        Update::Tip(_, _) => {}
        Update::Block(block, ack) => {
            let digest = block.commitment();
            if state.query_state_root(digest).await.is_none() {
                trace!(
                    ?digest,
                    "missing snapshot for finalized block; re-executing"
                );
                let parent_digest = block.parent();
                let Some(parent_snapshot) = state.parent_snapshot(parent_digest).await else {
                    error!(
                        ?digest,
                        ?parent_digest,
                        "missing parent snapshot for finalized block"
                    );
                    ack.acknowledge();
                    return;
                };
                let env = evm_env(block.height, block.prevrandao);
                let (db, outcome) = match execute_txs(parent_snapshot.db, env, &block.txs) {
                    Ok((db, outcome)) => (db, outcome),
                    Err(err) => {
                        error!(?digest, error = ?err, "failed to execute finalized block");
                        ack.acknowledge();
                        return;
                    }
                };
                let state_root = match state
                    .compute_root(parent_digest, outcome.qmdb_changes.clone())
                    .await
                {
                    Ok(root) => root,
                    Err(err) => {
                        error!(?digest, error = ?err, "failed to compute qmdb root");
                        ack.acknowledge();
                        return;
                    }
                };
                if state_root != block.state_root {
                    warn!(
                        ?digest,
                        expected = ?block.state_root,
                        computed = ?state_root,
                        "state root mismatch for finalized block"
                    );
                    ack.acknowledge();
                    return;
                }
                state
                    .insert_snapshot(digest, parent_digest, db, state_root, outcome.qmdb_changes)
                    .await;
            } else {
                trace!(?digest, "using cached snapshot for finalized block");
            }
            if let Err(err) = state.persist_snapshot(digest).await {
                error!(?digest, error = ?err, "failed to persist finalized block");
                ack.acknowledge();
                return;
            }
            state.prune_mempool(&block.txs).await;
            // Marshal waits for the application to acknowledge processing before advancing the
            // delivery floor. Without this, the node can stall on finalized block delivery.
            ack.acknowledge();
        }
    }
}

#[derive(Clone)]
/// Persists finalized blocks.
pub(crate) struct FinalizedReporter {
    /// Ledger service used to verify blocks and persist snapshots.
    state: LedgerService,
}

impl FinalizedReporter {
    pub(crate) const fn new(state: LedgerService) -> Self {
        Self { state }
    }
}

impl Reporter for FinalizedReporter {
    type Activity = Update<Block>;

    fn report(&mut self, update: Self::Activity) -> impl std::future::Future<Output = ()> + Send {
        let state = self.state.clone();
        async move {
            handle_finalized_update(state, update).await;
        }
    }
}
