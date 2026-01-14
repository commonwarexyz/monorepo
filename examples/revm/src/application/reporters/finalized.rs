use super::super::{
    execution::{evm_env, execute_txs},
    ledger::LedgerService,
};
use crate::domain::Block;
use commonware_consensus::{marshal::Update, Block as _, Reporter};
use commonware_cryptography::Committable as _;
use commonware_runtime::Spawner;
use commonware_utils::acknowledgement::Acknowledgement as _;

/// Helper function for `FinalizedReporter::report` that owns all its inputs.
async fn finalized_report_inner<E>(state: LedgerService, spawner: E, update: Update<Block>)
where
    E: Spawner + Clone,
{
    match update {
        Update::Tip(_, _) => {}
        Update::Block(block, ack) => {
            let mut block = block;
            let digest = block.commitment();
            if state.query_state_root(digest).await.is_none() {
                let parent_digest = block.parent();
                let parent_snapshot = state
                    .parent_snapshot(parent_digest)
                    .await
                    .expect("missing parent snapshot");
                let env = evm_env(block.height, block.prevrandao);
                let state_for_root = state.clone();
                let exec_spawner = spawner.clone();
                let exec = exec_spawner.shared(true).spawn(move |_| async move {
                    let (db, outcome) = execute_txs(parent_snapshot.db, env, &block.txs)?;
                    let state_root = state_for_root
                        .preview_root(parent_digest, outcome.qmdb_changes.clone())
                        .await?;
                    Ok::<_, anyhow::Error>((block, db, outcome, state_root))
                });
                let (next_block, db, outcome, state_root) = exec
                    .await
                    .expect("execute task failed")
                    .expect("execute finalized block");
                block = next_block;
                assert_eq!(state_root, block.state_root, "state root mismatch");
                state
                    .insert_snapshot(digest, parent_digest, db, state_root, outcome.qmdb_changes)
                    .await;
            }
            let persist_state = state.clone();
            let persist = spawner
                .shared(true)
                .spawn(move |_| async move { persist_state.persist_snapshot(digest).await });
            persist
                .await
                .expect("persist task failed")
                .expect("persist finalized block");
            state.prune_mempool(&block.txs).await;
            // Marshal waits for the application to acknowledge processing before advancing the
            // delivery floor. Without this, the node can stall on finalized block delivery.
            ack.acknowledge();
        }
    }
}

#[derive(Clone)]
/// Persists finalized blocks.
pub(crate) struct FinalizedReporter<E> {
    /// Ledger service used to verify blocks and persist snapshots.
    state: LedgerService,
    /// Runtime spawner used for executing block replay tasks.
    spawner: E,
}

impl<E> FinalizedReporter<E>
where
    E: Spawner,
{
    pub(crate) const fn new(state: LedgerService, spawner: E) -> Self {
        Self { state, spawner }
    }
}

impl<E> Reporter for FinalizedReporter<E>
where
    E: Spawner,
{
    type Activity = Update<Block>;

    fn report(&mut self, update: Self::Activity) -> impl std::future::Future<Output = ()> + Send {
        let state = self.state.clone();
        let spawner = self.spawner.clone();
        async move {
            finalized_report_inner(state, spawner, update).await;
        }
    }
}
