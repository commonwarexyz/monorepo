//! Point reads from pending and finalized catalog storage.

use super::{CatalogStore, StoredRef};
use crate::multimmit::{
    marshal::{
        storage::{Error, blocks::BlockMeta},
        types::OutputIndex,
    },
    types::{BlockRef, Body, CertificateId, Lqc, TipRecord, TransactionBlockHeader},
};
use commonware_cryptography::{Hasher, bls12381::primitives::variant::Variant};
use commonware_storage::{
    Context,
    archive::{Archive as _, Identifier, MultiArchive as _},
    translator::Translator,
};
use std::sync::Arc;

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

    /// Resolves the committed output row at `index`.
    pub(crate) async fn stored_ref(&self, index: u64) -> Result<StoredRef<H::Digest>, Error> {
        let (digest, row) = self
            .final_blocks
            .get()?
            .get_at(index)
            .await?
            .ok_or(Error::Inconsistent("committed output row is missing"))?;
        Ok(StoredRef {
            index: OutputIndex::new(index),
            reference: self.authenticate(digest, row.block())?,
            encoded_len: row.block().encoded_len(),
            floor_generation: row.floor_generation(),
        })
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
