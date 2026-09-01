//! Body lookups that prefer live custody and fall back to the immutable archive.

use super::{
    actors::{catalog, promoter},
    storage::catalog::StoredRef,
    types::{BodyValues, OutputIndex},
};
use crate::multimmit::types::{BlockRef, Body, ChainId, TransactionBlock};
use commonware_cryptography::{Hasher, bls12381::primitives::variant::Variant};
use std::sync::Arc;

/// A body lookup failed.
#[derive(Clone, Debug, thiserror::Error)]
pub(crate) enum Error {
    /// The catalog could not answer.
    #[error("catalog lookup failed: {0}")]
    Catalog(#[from] catalog::Error),
    /// The immutable archive could not answer.
    #[error("immutable lookup failed: {0}")]
    Promoter(#[from] promoter::Error),
    /// A committed output's body is in neither store.
    #[error("committed output {0} is missing its body")]
    Missing(OutputIndex),
}

/// Fills each empty slot, in order, with the next value from `source`.
///
/// `source` yields one value per empty slot, such as the reply to a lookup of the missing keys.
pub(crate) fn fill_missing<T>(slots: &mut [Option<T>], source: Vec<Option<T>>) {
    let mut source = source.into_iter();
    for slot in slots.iter_mut().filter(|slot| slot.is_none()) {
        *slot = source.next().flatten();
    }
}

/// Body access for delivery, backfill serving and the public mailbox.
///
/// The catalog answers from live custody; the promoter, when finalized bodies move to an
/// immutable archive, answers the rest.
pub(crate) struct Bodies<H, V, B>
where
    H: Hasher,
    V: Variant,
    B: Body<H>,
{
    catalog: catalog::Mailbox<H, V, B>,
    promoter: Option<promoter::Mailbox<H, B>>,
}

impl<H, V, B> Clone for Bodies<H, V, B>
where
    H: Hasher,
    V: Variant,
    B: Body<H>,
{
    fn clone(&self) -> Self {
        Self {
            catalog: self.catalog.clone(),
            promoter: self.promoter.clone(),
        }
    }
}

impl<H, V, B> Bodies<H, V, B>
where
    H: Hasher,
    V: Variant,
    B: Body<H>,
{
    pub(crate) const fn new(
        catalog: catalog::Mailbox<H, V, B>,
        promoter: Option<promoter::Mailbox<H, B>>,
    ) -> Self {
        Self { catalog, promoter }
    }

    /// Returns the block named by `reference`, if either store holds it.
    #[tracing::instrument(name = "multimmit.marshal.bodies.block", level = "debug", skip_all)]
    pub(crate) async fn block(
        &self,
        reference: BlockRef<H::Digest>,
    ) -> Result<Option<Arc<TransactionBlock<H, B>>>, Error> {
        if let Some(block) = self.catalog.block(reference).await? {
            return Ok(Some(block));
        }
        if let Some(promoter) = &self.promoter
            && let Some(block) = promoter.block(reference).await?
        {
            return Ok(Some(block));
        }
        Ok(None)
    }

    /// Returns the block on `chain` with `digest`, if either store holds it.
    #[tracing::instrument(
        name = "multimmit.marshal.bodies.block_by_digest",
        level = "debug",
        skip_all
    )]
    pub(crate) async fn block_by_digest(
        &self,
        chain: ChainId,
        digest: H::Digest,
    ) -> Result<Option<Arc<TransactionBlock<H, B>>>, Error> {
        if let Some(block) = self.catalog.block_by_digest(chain, digest).await? {
            return Ok(Some(block));
        }
        if let Some(promoter) = &self.promoter
            && let Some(block) = promoter.block_by_digest(digest).await?
            && block.header().chain() == chain
        {
            return Ok(Some(block));
        }
        Ok(None)
    }

    /// Returns blocks in request order, preferring live custody over immutable storage.
    #[tracing::instrument(
        name = "multimmit.marshal.bodies.blocks",
        level = "debug",
        skip_all,
        fields(blocks = references.len())
    )]
    pub(crate) async fn blocks(
        &self,
        references: Vec<BlockRef<H::Digest>>,
    ) -> Result<BodyValues<H, B>, Error> {
        let bodies = self.catalog.bodies(references.clone()).await?;
        self.fill_immutable(&references, bodies).await
    }

    async fn fill_immutable(
        &self,
        references: &[BlockRef<H::Digest>],
        mut bodies: BodyValues<H, B>,
    ) -> Result<BodyValues<H, B>, Error> {
        if let Some(promoter) = &self.promoter {
            let missing = references
                .iter()
                .zip(&bodies)
                .filter_map(|(reference, body)| body.is_none().then_some(*reference))
                .collect::<Vec<_>>();
            if !missing.is_empty() {
                fill_missing(&mut bodies, promoter.blocks(missing).await?);
            }
        }
        Ok(bodies)
    }

    /// Reads the blocks of committed output rows, in row order.
    #[tracing::instrument(
        name = "multimmit.marshal.bodies.materialize",
        level = "info",
        skip_all,
        fields(outputs = refs.len())
    )]
    pub(crate) async fn materialize(
        &self,
        refs: &[StoredRef<H::Digest>],
    ) -> Result<Vec<Arc<TransactionBlock<H, B>>>, Error> {
        let references = refs
            .iter()
            .map(|output| output.reference)
            .collect::<Vec<_>>();
        let bodies = self.catalog.committed_bodies(references.clone()).await?;
        let bodies = self.fill_immutable(&references, bodies).await?;
        let mut bodies = bodies.into_iter();
        refs.iter()
            .map(|output| {
                bodies
                    .next()
                    .flatten()
                    .filter(|block| output.matches(block))
                    .ok_or(Error::Missing(output.index))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fill_missing_fills_only_empty_slots_in_order() {
        let mut slots = vec![Some(1), None, Some(3), None, None];
        fill_missing(&mut slots, vec![Some(2), None, Some(5)]);
        assert_eq!(slots, vec![Some(1), Some(2), Some(3), None, Some(5)]);
    }
}
