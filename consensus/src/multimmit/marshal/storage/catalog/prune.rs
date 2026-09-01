//! Reclaiming pending custody and finalized rows.

use super::CatalogStore;
use crate::{
    multimmit::{
        marshal::{
            storage::{Error, pending::ChainFloors},
            types::OutputIndex,
        },
        types::{BlockRef, Body, Frontier},
    },
    types::Height,
};
use commonware_cryptography::{Hasher, bls12381::primitives::variant::Variant};
use commonware_storage::{Context, translator::Translator};
use std::collections::BTreeSet;

impl<T, E, H, V, B> CatalogStore<T, E, H, V, B>
where
    T: Translator,
    E: Context,
    H: Hasher,
    V: Variant,
    B: Body<H>,
    B::Cfg: Clone,
{
    /// Reclaims immutable-mode pending bodies covered by a durable promotion cursor.
    ///
    /// Returns the destroyed custody segments so their advisory readers can be released.
    pub(crate) async fn promoted(
        &mut self,
        frontiers: Vec<BlockRef<H::Digest>>,
        pinned: &BTreeSet<u64>,
    ) -> Result<Vec<u64>, Error> {
        if self.prunable_blocks {
            return Err(Error::Invalid(
                "prunable finalized bodies cannot be promoted away",
            ));
        }
        let emitted = self.checkpoint().emitted();
        let promoted = Frontier::new(frontiers)
            .ok()
            .filter(|promoted| {
                promoted.chains() == emitted.len()
                    && promoted
                        .references()
                        .iter()
                        .zip(emitted)
                        .all(|(promoted, emitted)| promoted.height() <= emitted.height())
            })
            .ok_or(Error::Invalid(
                "promotion frontier is outside the checkpoint",
            ))?;
        self.pending_blocks
            .prune(&ChainFloors::above(&promoted), pinned)
            .await
    }

    /// Prunes acknowledged finalized data and returns destroyed pending custody segments.
    pub(crate) async fn prune_finalized(
        &mut self,
        floor_generation: u64,
        acknowledged: Option<OutputIndex>,
        pinned: &BTreeSet<u64>,
    ) -> Result<Vec<u64>, Error> {
        let checkpoint = self.checkpoint().clone();
        if checkpoint.floor_generation() != floor_generation {
            return Err(Error::Invalid("prune generation is not current"));
        }
        let floor_lqc = self
            .final_lqc
            .get()?
            .get_by_key(&checkpoint.floor().get())
            .await?;
        let lqc_floor = match (floor_lqc, self.state.lqc_index()) {
            (Some(_), Some(index)) => index,
            // At genesis the floor is the synthetic genesis L-QC, which no archive stores.
            (None, None) if checkpoint.history_index().is_none() => 0,
            _ => return Err(Error::Inconsistent("checkpoint floor LQC is missing")),
        };
        let history_floor = checkpoint.history_index().unwrap_or(0);
        let output_floor = OutputIndex::after(acknowledged).unwrap_or(OutputIndex::new(u64::MAX));

        let reclaimed = if self.prunable_blocks {
            let mut floors = ChainFloors::unchanged(self.pending_blocks.chain_count());
            let blocks = self.final_blocks.get()?;
            if let (Some(first), Some(acknowledged)) = (blocks.first_index(), acknowledged) {
                for index in first..=acknowledged.get() {
                    let (digest, row) = blocks
                        .get_at(index)
                        .await?
                        .ok_or(Error::Inconsistent("finalized block row is missing"))?;
                    let reference = self.authenticate(digest, row.block())?;
                    floors.raise(
                        reference.chain(),
                        Height::new(reference.height().get().saturating_add(1)),
                    );
                }
            }
            // An unchanged floor still reclaims segments retained by an earlier materialization
            // pin, so every application prune reaches pending custody.
            self.pending_blocks.prune(&floors, pinned).await?
        } else {
            Vec::new()
        };

        let lqc = self.final_lqc.take()?;
        let histories = self.final_history.take()?;
        let blocks = self.final_blocks.take()?;
        let (lqc, histories, blocks) = futures::try_join!(
            lqc.prune(lqc_floor),
            histories.prune(history_floor),
            blocks.prune(output_floor.get()),
        )?;
        self.final_lqc.restore(lqc);
        self.final_history.restore(histories);
        self.final_blocks.restore(blocks);
        Ok(reclaimed)
    }
}
