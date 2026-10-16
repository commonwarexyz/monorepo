//! Reclaiming pending custody and finalized rows.

use super::CatalogStore;
use crate::{
    multimmit::{
        marshal::{
            OutputIndex,
            storage::{Error, pending::ChainFloors},
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
        let floors = promoted
            .references()
            .iter()
            .map(|reference| Some(Height::new(reference.height().get().saturating_add(1))))
            .collect();
        self.pending_blocks.prune(&floors, pinned).await
    }

    /// Prunes what the newest floor at or below `below` makes obsolete and returns destroyed
    /// pending custody segments.
    ///
    /// That floor, its L-QC and tip-history opening, and every output at or after `below` stay
    /// retained, so [`Self::floor_at`] still answers at `below` and a node that installs the floor
    /// can fetch every later output. Only floors at or below the finalized ordinal `through`, the
    /// published checkpoint's, are considered; without one at or below `below`, no finalized data
    /// is pruned. The caller bounds `below` by the delivery cursor.
    ///
    /// Each chain keeps its blocks from its tip at the floor, which its next block builds on and
    /// peers may fetch. The bound comes from the floor rather than from finalized rows, so a later
    /// prune reclaims blocks whose rows an earlier prune removed.
    pub(crate) async fn prune_finalized(
        &mut self,
        below: OutputIndex,
        through: Option<u64>,
        pinned: &BTreeSet<u64>,
    ) -> Result<Vec<u64>, Error> {
        let floor = self.floor_record_at(below, through).await?;
        let reclaimed = if self.prunable_blocks {
            let chains = match &floor {
                Some(floor) => floor
                    .record
                    .tips()
                    .iter()
                    .map(|tip| Some(tip.height()))
                    .collect(),
                None => ChainFloors::unchanged(self.pending_blocks.chain_count()),
            };
            // An unchanged floor still reclaims segments retained by an earlier materialization
            // pin, so every application prune reaches pending custody.
            self.pending_blocks.prune(&chains, pinned).await?
        } else {
            Vec::new()
        };
        let Some(floor) = floor else {
            return Ok(reclaimed);
        };

        let lqc = self.final_lqc.take()?;
        let floors = self.final_floors.take()?;
        let histories = self.final_history.take()?;
        let blocks = self.final_blocks.take()?;
        let (lqc, floors, histories, blocks) = futures::try_join!(
            lqc.prune(floor.ordinal),
            floors.prune(floor.ordinal),
            histories.prune(floor.record.history_index()),
            blocks.prune(floor.record.index().next().min(below).get()),
        )?;
        self.final_lqc.restore(lqc);
        self.final_floors.restore(floors);
        self.final_history.restore(histories);
        self.final_blocks.restore(blocks);
        Ok(reclaimed)
    }
}
