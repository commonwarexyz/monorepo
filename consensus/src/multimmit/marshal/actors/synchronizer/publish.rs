//! Checkpoint-last publication of synchronized outputs.

use super::{
    actor::Core,
    inbox::Absorb,
    mailbox::Error,
    ports::{CatalogPort, Fetcher},
};
use crate::multimmit::{
    marshal::{
        actors::delivery,
        protocol::order::{Reconciliation, Slot},
        storage::{
            catalog::StoredRef,
            catalog_state::{Checkpoint, CheckpointParts},
            commit::{Commit, CustodyRef, HistoryOpening, OutputRow, SelectedLqc},
            scratch::{BlockStack, HistoryStack},
        },
        types::{LqcVerifier, OutputIndex},
    },
    types::{Body, TransactionBlock},
};
use commonware_cryptography::{Hasher, bls12381::primitives::variant::Variant};
use commonware_macros::select;
use std::{mem, sync::Arc};

/// Maximum number of started commits that may wait for durability at once.
pub(super) const COMMIT_WINDOW: usize = 2;

/// Dense output metadata accumulated across history openings before publication.
pub(super) struct PlannedOutput<H: Hasher, B: Body<H>> {
    pub index: OutputIndex,
    pub custody: CustodyRef<H::Digest>,
    /// Body retained from a peer fetch, handed to delivery once the commit is durable.
    pub block: Option<Arc<TransactionBlock<H, B>>>,
}

/// One bounded checkpoint-last publication assembled from compact ordering metadata.
pub(super) struct PublicationBatch<H: Hasher, V: Variant, B: Body<H>> {
    pub selected: Vec<SelectedLqc<V, H>>,
    pub history: Vec<HistoryOpening<H>>,
    pub outputs: Vec<PlannedOutput<H, B>>,
    /// Encoded block bytes of `outputs`.
    pub output_bytes: u64,
}

impl<H: Hasher, V: Variant, B: Body<H>> PublicationBatch<H, V, B> {
    pub(super) fn new(max_outputs: usize, selected: usize) -> Self {
        Self {
            selected: Vec::with_capacity(selected.min(max_outputs)),
            history: Vec::with_capacity(max_outputs),
            outputs: Vec::with_capacity(max_outputs),
            output_bytes: 0,
        }
    }

    pub(super) const fn is_empty(&self) -> bool {
        self.selected.is_empty() && self.history.is_empty() && self.outputs.is_empty()
    }
}

impl<H: Hasher, V: Variant, B: Body<H>> Default for PublicationBatch<H, V, B> {
    fn default() -> Self {
        Self {
            selected: Vec::new(),
            history: Vec::new(),
            outputs: Vec::new(),
            output_bytes: 0,
        }
    }
}

impl<I, C, F, S, K, Q, H, V, B> Core<I, C, F, S, K, Q, H, V, B>
where
    I: Absorb<V, H::Digest>,
    C: CatalogPort<H, V, B>,
    F: Fetcher<H, V, B>,
    S: HistoryStack<H>,
    K: BlockStack<H::Digest>,
    Q: LqcVerifier<H, V>,
    H: Hasher,
    V: Variant,
    B: Body<H>,
    Error: From<C::Error> + From<F::Error> + From<S::Error> + From<K::Error>,
{
    /// Reconciles the output filling `slot` and adds it to `batch`, committing the batch first
    /// when the output would overflow its byte bound.
    pub(super) async fn emit_output(
        &mut self,
        slot: Slot<H::Digest>,
        custody: CustodyRef<H::Digest>,
        block: Option<Arc<TransactionBlock<H, B>>>,
        batch: &mut PublicationBatch<H, V, B>,
    ) -> Result<(), Error> {
        let reference = custody.reference();
        let encoded_len = custody.meta().encoded_len();
        if !batch.outputs.is_empty()
            && batch
                .output_bytes
                .checked_add(encoded_len)
                .is_none_or(|total| total > self.bounds.max_commit_block_bytes)
        {
            self.commit_pending(batch).await?;
        }
        if self.state.reconcile(slot, reference)? != Reconciliation::Emit {
            return Err(Error::Invalid(
                "staged ordering slot reconciled as a duplicate",
            ));
        }
        let index = match self.committed {
            Some(index) => index.next().ok_or(Error::OutputExhausted)?,
            None => OutputIndex::ZERO,
        };
        self.committed = Some(index);
        batch.output_bytes = batch.output_bytes.saturating_add(encoded_len);
        batch.outputs.push(PlannedOutput {
            index,
            custody,
            block,
        });
        if batch.outputs.len() == self.bounds.max_commit_outputs
            || batch.output_bytes >= self.bounds.max_commit_block_bytes
        {
            self.commit_pending(batch).await?;
        }
        Ok(())
    }

    /// Starts a commit of everything `batch` accumulated, leaving it empty.
    ///
    /// Advances the floor to the last selected proof and drops cached headers at or below the
    /// emitted frontier.
    pub(super) async fn commit_pending(
        &mut self,
        batch: &mut PublicationBatch<H, V, B>,
    ) -> Result<(), Error> {
        if batch.is_empty() {
            return Ok(());
        }
        if let Some(selected) = batch.selected.last() {
            self.floor = selected.id;
            self.floor_view = selected.view;
        }
        let advances_frontier = !batch.outputs.is_empty();
        self.commit(mem::take(batch)).await?;
        if advances_frontier {
            let emitted = self.state.emitted();
            self.headers.retain(|reference, _| {
                emitted
                    .get(reference.chain().get() as usize)
                    .is_some_and(|frontier| reference.height() > frontier.height())
            });
        }
        Ok(())
    }

    /// Starts a checkpoint-last commit of `batch` once a commit slot is free.
    #[tracing::instrument(
        name = "multimmit.marshal.synchronizer.publish",
        level = "info",
        skip_all,
        fields(
            selected = batch.selected.len(),
            history = batch.history.len(),
            outputs = batch.outputs.len(),
            bytes = batch.output_bytes,
        )
    )]
    pub(super) async fn commit(&mut self, batch: PublicationBatch<H, V, B>) -> Result<(), Error> {
        if batch.is_empty() {
            return Ok(());
        }
        let PublicationBatch {
            selected,
            history,
            outputs,
            ..
        } = batch;
        self.wait_for_commit_slot().await?;
        let checkpoint = self.checkpoint()?;
        let mut handoff = Vec::new();
        let outputs = outputs
            .into_iter()
            .map(|output| {
                let PlannedOutput {
                    index,
                    custody,
                    block,
                } = output;
                let row = OutputRow::new(index, custody);
                if let Some(block) = block {
                    handoff.push(delivery::HotOutput {
                        stored: StoredRef::new(&row, checkpoint.floor_generation()),
                        block,
                    });
                }
                row
            })
            .collect();
        let commit = Commit {
            selected,
            history,
            outputs,
            checkpoint,
        };
        let token = self.catalog.start_commit(commit, handoff).await?;
        self.pending_commits
            .push(async move { C::wait_commit(token).await.map_err(Error::from) });
        Ok(())
    }

    /// Waits until every started commit is durable.
    pub(super) async fn finish_commits(&mut self) -> Result<(), Error> {
        while !self.pending_commits.is_empty() {
            self.pending_commits.next_completed().await?;
        }
        Ok(())
    }

    /// Waits until fewer than [`COMMIT_WINDOW`] commits are in flight, taking in input meanwhile.
    async fn wait_for_commit_slot(&mut self) -> Result<(), Error> {
        while self.pending_commits.len() >= COMMIT_WINDOW {
            select! {
                completion = self.pending_commits.next_completed() => {
                    completion?;
                },
                absorbed = self.inbox.absorb() => {
                    if let Some(absorbed) = absorbed? {
                        self.apply(absorbed);
                    }
                },
            }
        }
        Ok(())
    }

    /// Returns the checkpoint of the current synchronization state.
    fn checkpoint(&self) -> Result<Checkpoint<H::Digest>, Error> {
        Checkpoint::try_from(CheckpointParts {
            epoch: self.epoch,
            floor_generation: self.floor_generation,
            archive_layout: self.archive_layout,
            floor: self.floor,
            history: self.state.history(),
            history_index: self.history_index,
            ordered: self.state.ordered().to_vec(),
            emitted: self.state.emitted().to_vec(),
            committed: self.committed,
        })
        .map_err(|_| Error::Invalid("synchronizer produced a non-canonical checkpoint"))
    }
}
