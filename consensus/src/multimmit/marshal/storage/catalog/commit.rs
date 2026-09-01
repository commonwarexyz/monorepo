//! The checkpoint-last commit protocol and its pending-archive cleanup.

use super::{CatalogStore, CommitPublication, Footprint, start_sync_if};
use crate::multimmit::{
    marshal::storage::{
        Error,
        blocks::FinalBlockMeta,
        catalog_state::{CatalogState, CommitCleanup, next_lqc_index},
        commit::Commit,
    },
    types::Body,
};
use commonware_cryptography::{Digest, Hasher, bls12381::primitives::variant::Variant};
use commonware_runtime::Handle;
use commonware_storage::{Context, translator::Translator};

/// Archive positions and resulting state computed for one commit before any write.
struct CommitPlan<D: Digest> {
    /// Finalized L-QC ordinal of each selected L-QC, in order.
    lqc_indices: Vec<u64>,
    /// Finalized history ordinal of the first opening, if any.
    history_start: Option<u64>,
    /// L-QC high-water mark attached to the checkpoint.
    lqc_index: Option<u64>,
    /// Cleanup owed by buffered commits, including this one.
    cleanup: CommitCleanup,
    /// Record published by this commit if it were the next publication.
    state: CatalogState<D>,
}

impl<T, E, H, V, B> CatalogStore<T, E, H, V, B>
where
    T: Translator,
    E: Context,
    H: Hasher,
    V: Variant,
    B: Body<H>,
    B::Cfg: Clone,
{
    /// Computes where `batch` writes and the record it publishes, without changing storage.
    fn plan_commit(&self, batch: &Commit<H, V>) -> Result<CommitPlan<H::Digest>, Error> {
        let mut lqc_indices = Vec::with_capacity(batch.selected.len());
        let mut allocated = self.allocated_lqc_index;
        for selected in &batch.selected {
            let index = next_lqc_index(allocated, selected.view)
                .ok_or(Error::Invalid("finalized LQC index overflow"))?;
            lqc_indices.push(index);
            allocated = Some(index);
        }
        let lqc_index = lqc_indices.last().copied().or(self.accepted_lqc_index);
        let mut cleanup = self.accepted_cleanup;
        cleanup.coalesce(CommitCleanup {
            selected: batch.selected.last().map(|selected| selected.view),
        });
        let state = self
            .state
            .publish_commit(batch.checkpoint.clone(), lqc_index, cleanup)
            .ok_or(Error::Invalid(
                "ordinary commit cannot replace an install intent",
            ))?;
        self.check_state(&state)?;
        let history_start = if batch.history.is_empty() {
            None
        } else {
            let count = u64::try_from(batch.history.len())
                .map_err(|_| Error::Invalid("history index overflow"))?;
            let last = batch
                .checkpoint
                .history_index()
                .ok_or(Error::Invalid("history index overflow"))?;
            Some(
                last.checked_sub(count - 1)
                    .ok_or(Error::Invalid("history index overflow"))?,
            )
        };
        Ok(CommitPlan {
            lqc_indices,
            history_start,
            lqc_index,
            cleanup,
            state,
        })
    }

    /// Buffers one validated ordinary commit without starting durability or cleanup.
    pub(crate) async fn buffer_commit(
        &mut self,
        batch: Commit<H, V>,
    ) -> Result<CommitPublication<H::Digest>, Error> {
        let plan = self.plan_commit(&batch)?;
        let Commit {
            selected,
            history,
            outputs,
            checkpoint,
        } = batch;
        let touched = Footprint {
            lqc: !selected.is_empty(),
            history: !history.is_empty(),
            blocks: !outputs.is_empty(),
        };
        let floor_generation = checkpoint.floor_generation();
        let mut lqc = self.final_lqc.take()?;
        let mut histories = self.final_history.take()?;
        let mut blocks = self.final_blocks.take()?;
        let (lqc, histories, blocks) = futures::try_join!(
            async move {
                for (selected, index) in selected.into_iter().zip(plan.lqc_indices) {
                    lqc = lqc.put(index, selected.id.get(), selected.proof).await?;
                }
                Ok::<_, Error>(lqc)
            },
            async move {
                let indices = plan.history_start.into_iter().flat_map(|start| start..);
                for (opening, index) in history.into_iter().zip(indices) {
                    histories = histories
                        .put(index, opening.commitment, opening.record)
                        .await?;
                }
                Ok::<_, Error>(histories)
            },
            async move {
                for output in outputs {
                    let (index, reference, meta) = output.into_parts();
                    blocks = blocks
                        .put(
                            index.get(),
                            reference.digest(),
                            FinalBlockMeta::new(meta, floor_generation),
                        )
                        .await?;
                }
                Ok::<_, Error>(blocks)
            },
        )?;
        self.final_lqc.restore(lqc);
        self.final_history.restore(histories);
        self.final_blocks.restore(blocks);
        if touched.lqc {
            self.allocated_lqc_index = plan.lqc_index;
        }
        self.accepted_lqc_index = plan.lqc_index;
        self.accepted_cleanup = plan.cleanup;
        let cleanup = plan
            .state
            .commit_cleanup()
            .expect("ordinary publication carries cleanup");
        Ok(CommitPublication {
            checkpoint,
            lqc_index: plan.lqc_index,
            cleanup,
            touched,
        })
    }

    /// Starts finalized-archive durability for one buffered publication.
    pub(crate) async fn start_finalized_sync(
        &mut self,
        publication: &CommitPublication<H::Digest>,
    ) -> Result<Vec<Handle<()>>, Error> {
        let touched = publication.touched;
        let lqc = self.final_lqc.take()?;
        let histories = self.final_history.take()?;
        let blocks = self.final_blocks.take()?;
        let ((lqc, lqc_sync), (histories, history_sync), (blocks, block_sync)) = futures::try_join!(
            start_sync_if(lqc, touched.lqc),
            start_sync_if(histories, touched.history),
            start_sync_if(blocks, touched.blocks),
        )?;
        self.final_lqc.restore(lqc);
        self.final_history.restore(histories);
        self.final_blocks.restore(blocks);
        Ok(lqc_sync
            .into_iter()
            .chain(history_sync)
            .chain(block_sync)
            .collect())
    }

    /// Starts checkpoint-last durability for an archive-durable publication.
    ///
    /// The record is recomputed from the current one rather than taken from
    /// [`Self::buffer_commit`]: with pipelined commits, an earlier commit's publication may have
    /// started after this commit was buffered and changed the cleanup owed.
    pub(crate) async fn start_sync_publication(
        &mut self,
        publication: &CommitPublication<H::Digest>,
    ) -> Result<Handle<()>, Error> {
        let state = self
            .state
            .publish_commit(
                publication.checkpoint.clone(),
                publication.lqc_index,
                publication.cleanup,
            )
            .ok_or(Error::Invalid(
                "ordinary commit cannot replace an install intent",
            ))?;
        self.start_sync_state(state).await
    }

    /// Completes cleanup that an interrupted ordinary commit still owes.
    pub(crate) async fn recover_commit(&mut self) -> Result<(), Error> {
        let Some(cleanup) = self.state.commit_cleanup() else {
            return Ok(());
        };
        self.cleanup_pending(cleanup).await
    }

    /// Prunes pending L-QCs and history at or below the selected view of `cleanup`.
    pub(crate) async fn cleanup_pending(&mut self, cleanup: CommitCleanup) -> Result<(), Error> {
        let Some(selected) = cleanup.selected else {
            return Ok(());
        };
        let floor = selected.get().saturating_add(1);
        let lqc = self.pending_lqc.take()?;
        let history = self.pending_history.take()?;
        let (lqc, history) = futures::try_join!(lqc.prune(floor), history.prune(floor))?;
        self.pending_lqc.restore(lqc);
        self.pending_history.restore(history);
        Ok(())
    }
}
