//! Point reads from pending and finalized catalog storage.

use super::{CatalogStore, StoredRef};
use crate::{
    multimmit::{
        marshal::{
            storage::{Error, blocks::BlockMeta, floors::FloorRecord},
            types::{Floor, MaybeFloor},
        },
        types::{BlockRef, Body, CertificateId, Lqc, TipRecord, TransactionBlockHeader},
    },
    types::OutputIndex,
};
use commonware_cryptography::{Digest, Hasher, bls12381::primitives::variant::Variant};
use commonware_storage::{
    Context,
    archive::{Archive as _, Identifier, MultiArchive as _},
    translator::Translator,
};
use std::sync::Arc;

/// A retained floor record with the coordinates it is stored under.
pub(super) struct StoredFloor<D: Digest> {
    /// Finalized ordinal of the floor's L-QC.
    pub(super) ordinal: u64,
    /// Certificate identity of the floor's L-QC.
    pub(super) id: CertificateId<D>,
    pub(super) record: FloorRecord<D>,
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
    /// Returns the L-QC with `id`, finalized or pending.
    pub(crate) async fn lqc(
        &self,
        id: CertificateId<H::Digest>,
    ) -> Result<Option<Arc<Lqc<V, H::Digest>>>, Error> {
        if let Some(proof) = self.final_lqc.get()?.get_by_key(&id.get()).await? {
            return Ok(Some(proof));
        }
        Ok(self
            .pending_lqc
            .get()?
            .get(Identifier::Key(&id.get()))
            .await?)
    }

    /// Returns whether the L-QC with `id` is finalized.
    pub(crate) async fn final_lqc(&self, id: CertificateId<H::Digest>) -> Result<bool, Error> {
        Ok(self.final_lqc.get()?.get_by_key(&id.get()).await?.is_some())
    }

    /// Returns the first pending L-QC at the highest pending view.
    pub(crate) async fn latest_lqc(&self) -> Result<Option<Arc<Lqc<V, H::Digest>>>, Error> {
        let pending = self.pending_lqc.get()?;
        let Some(view) = pending.last_index() else {
            return Ok(None);
        };
        Ok(pending
            .get_all(view)
            .await?
            .and_then(|proofs| proofs.into_iter().next()))
    }

    /// Returns the history opening with commitment `key`, finalized or pending.
    pub(crate) async fn history(
        &self,
        key: H::Digest,
    ) -> Result<Option<Arc<TipRecord<H::Digest>>>, Error> {
        if let Some(record) = self.final_history.get()?.get_by_key(&key).await? {
            return Ok(Some(record));
        }
        Ok(self
            .pending_history
            .get()?
            .get(Identifier::Key(&key))
            .await?)
    }

    /// Returns the retained floor record with the highest index at or below `at`, among floors
    /// at or below the finalized ordinal `through`.
    ///
    /// Floors are recorded at their L-QC's finalized ordinal, and their indices never decrease as
    /// ordinals grow, so a binary search over the retained ordinals finds it. Records past
    /// `through` belong to commits whose checkpoint is not published, so they are ignored.
    ///
    /// A crash can leave records past the published ordinal that reopen skips, and replay then
    /// records the same floors again at higher ordinals, so once `through` passes both copies the
    /// indices can repeat out of order. The search may then return an older floor than the newest
    /// one at or below `at`, but never one above it, so a caller only resumes or prunes less.
    pub(super) async fn floor_record_at(
        &self,
        at: OutputIndex,
        through: Option<u64>,
    ) -> Result<Option<StoredFloor<H::Digest>>, Error> {
        let floors = self.final_floors.get()?;
        let (Some(mut low), Some(last), Some(through)) =
            (floors.first_index(), floors.last_index(), through)
        else {
            return Ok(None);
        };
        let mut high = last.min(through);
        let mut found = None;
        while low <= high {
            let middle = low + (high - low) / 2;
            let probe = match floors.next_index(middle).filter(|ordinal| *ordinal <= high) {
                Some(ordinal) => {
                    let (id, record) = floors
                        .get_at(ordinal)
                        .await?
                        .ok_or(Error::Inconsistent("retained floor is missing"))?;
                    Some(StoredFloor {
                        ordinal,
                        id: CertificateId::new(id),
                        record,
                    })
                }
                None => None,
            };
            match probe {
                // Every floor at or below this ordinal ends at or below `at`.
                Some(floor) if floor.record.index() <= at => {
                    let next = floor.ordinal.checked_add(1);
                    found = Some(floor);
                    match next {
                        Some(next) => low = next,
                        None => break,
                    }
                }
                // No floor from `middle` through `high` ends at or below `at`.
                _ => match middle.checked_sub(1) {
                    Some(previous) => high = previous,
                    None => break,
                },
            }
        }
        Ok(found)
    }

    /// Returns the retained floor with the highest index at or below `at`, with that index, among
    /// floors at or below the finalized ordinal `through`.
    ///
    /// A floor whose L-QC or tip-history opening is no longer retained is absent.
    pub(crate) async fn floor_at(
        &self,
        at: OutputIndex,
        through: Option<u64>,
    ) -> Result<MaybeFloor<V, H::Digest>, Error> {
        let Some(StoredFloor { id, record, .. }) = self.floor_record_at(at, through).await? else {
            return Ok(None);
        };
        let Some(anchor) = self.final_lqc.get()?.get_by_key(&id.get()).await? else {
            return Ok(None);
        };
        let Some((commitment, history)) = self
            .final_history
            .get()?
            .get_at(record.history_index())
            .await?
        else {
            return Ok(None);
        };
        // A record a crash left before its checkpoint was published may name an opening that a
        // later commit rewrote, so such a floor is absent rather than inconsistent.
        if commitment != anchor.leader().history() {
            return Ok(None);
        }
        Ok(Some((
            record.index(),
            Floor::new(anchor, history, record.emitted().to_vec()),
        )))
    }

    /// Returns the header of `reference` from pending custody or finalized rows.
    pub(crate) async fn block_header(
        &self,
        reference: BlockRef<H::Digest>,
    ) -> Result<Option<TransactionBlockHeader<H::Digest>>, Error> {
        if let Some(header) = self.pending_blocks.header(reference) {
            return Ok(Some(header));
        }
        Ok(self
            .final_meta(reference)
            .await?
            .map(|meta| meta.header().clone()))
    }

    /// Returns the lowest retained finalized output row, if any.
    pub(crate) fn first_output_row(&self) -> Result<Option<u64>, Error> {
        Ok(self.final_blocks.get()?.first_index())
    }

    /// Returns the lowest retained output row at or above `from`, if any.
    pub(crate) fn next_output_row(&self, from: u64) -> Result<Option<u64>, Error> {
        Ok(self.final_blocks.get()?.next_index(from))
    }

    /// Resolves the committed output row at `index`, if one is stored.
    pub(crate) async fn stored_ref(
        &self,
        index: u64,
    ) -> Result<Option<StoredRef<H::Digest>>, Error> {
        let Some((digest, row)) = self.final_blocks.get()?.get_at(index).await? else {
            return Ok(None);
        };
        Ok(Some(StoredRef {
            index: OutputIndex::new(index),
            reference: self.authenticate(digest, row.block())?,
            encoded_len: row.block().encoded_len(),
            floor_generation: row.floor_generation(),
        }))
    }

    /// Returns custody metadata without decoding the block body.
    ///
    /// Pending custody remains authoritative until pruning; finalized rows are the historical
    /// fallback after custody is reclaimed.
    pub(crate) async fn block_meta(
        &self,
        reference: BlockRef<H::Digest>,
    ) -> Result<Option<BlockMeta<H::Digest>>, Error> {
        if let Some(meta) = self.pending_blocks.custody_meta(reference) {
            return Ok(Some(meta));
        }
        self.final_meta(reference).await
    }

    /// Returns the finalized row metadata of exactly `reference`.
    async fn final_meta(
        &self,
        reference: BlockRef<H::Digest>,
    ) -> Result<Option<BlockMeta<H::Digest>>, Error> {
        let Some(row) = self
            .final_blocks
            .get()?
            .get_by_key(&reference.digest())
            .await?
        else {
            return Ok(None);
        };
        Ok(
            (self.authenticate(reference.digest(), row.block())? == reference)
                .then(|| row.block().clone()),
        )
    }
}
