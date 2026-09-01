//! Commit inputs and the output rows and custody references they record.

use crate::{
    multimmit::{
        marshal::{
            storage::{blocks::BlockMeta, catalog_state::Checkpoint},
            types::OutputIndex,
        },
        types::{BlockRef, CertificateId, Lqc, TipRecord},
    },
    types::View,
};
use commonware_cryptography::{Digest, Hasher, bls12381::primitives::variant::Variant};
use std::sync::Arc;

/// The selected finality proof in a commit.
pub(crate) struct SelectedLqc<V: Variant, H: Hasher> {
    /// View of the L-QC.
    pub view: View,
    /// Certificate identity of the L-QC.
    pub id: CertificateId<H::Digest>,
    /// The L-QC.
    pub proof: Arc<Lqc<V, H::Digest>>,
}

/// One authenticated tip-history opening, ordered oldest first.
pub(crate) struct HistoryOpening<H: Hasher> {
    /// Commitment of `record`.
    pub commitment: H::Digest,
    /// The opening.
    pub record: Arc<TipRecord<H::Digest>>,
}

/// Catalog-proven durable custody needed to order a block without reading its body.
pub(crate) struct CustodyRef<D: Digest> {
    reference: BlockRef<D>,
    meta: BlockMeta<D>,
}

impl<D: Digest> CustodyRef<D> {
    /// Binds block metadata to the reference it was proven for.
    pub(crate) const fn new(reference: BlockRef<D>, meta: BlockMeta<D>) -> Self {
        Self { reference, meta }
    }

    /// Returns the block reference.
    pub(crate) const fn reference(&self) -> BlockRef<D> {
        self.reference
    }

    /// Returns the block metadata.
    pub(crate) const fn meta(&self) -> &BlockMeta<D> {
        &self.meta
    }

    /// Returns the reference and metadata.
    pub(crate) const fn into_parts(self) -> (BlockRef<D>, BlockMeta<D>) {
        (self.reference, self.meta)
    }
}

/// Dense publication coordinate paired with catalog-proven body custody.
pub(crate) struct OutputRow<D: Digest> {
    /// Dense output index of the row.
    pub index: OutputIndex,
    custody: CustodyRef<D>,
}

impl<D: Digest> OutputRow<D> {
    /// Creates a row at `index` for proven custody.
    pub(crate) const fn new(index: OutputIndex, custody: CustodyRef<D>) -> Self {
        Self { index, custody }
    }

    /// Returns the block reference.
    pub(crate) const fn reference(&self) -> BlockRef<D> {
        self.custody.reference()
    }

    /// Returns the block metadata.
    pub(crate) const fn meta(&self) -> &BlockMeta<D> {
        self.custody.meta()
    }

    /// Returns the index, reference, and metadata.
    pub(crate) const fn into_parts(self) -> (OutputIndex, BlockRef<D>, BlockMeta<D>) {
        let (reference, block) = self.custody.into_parts();
        (self.index, reference, block)
    }
}

/// A complete checkpoint-last commit.
pub(crate) struct Commit<H, V>
where
    H: Hasher,
    V: Variant,
{
    /// L-QCs selected by the commit, in view order; the last one anchors the checkpoint.
    pub selected: Vec<SelectedLqc<V, H>>,
    /// History openings from the current checkpoint's history to the new one.
    pub history: Vec<HistoryOpening<H>>,
    /// Dense output rows following the current committed output.
    pub outputs: Vec<OutputRow<H::Digest>>,
    /// Checkpoint the commit publishes.
    pub checkpoint: Checkpoint<H::Digest>,
}

#[cfg(test)]
mod fixtures {
    use super::{BlockMeta, CustodyRef};
    use crate::multimmit::types::{Body, TransactionBlock};
    use commonware_codec::EncodeSize as _;
    use commonware_cryptography::{Digest, Hasher};
    use std::sync::Arc;

    impl<D: Digest> CustodyRef<D> {
        /// Returns the custody reference of `block`.
        pub(crate) fn for_test<H, B>(block: &Arc<TransactionBlock<H, B>>) -> Self
        where
            H: Hasher<Digest = D>,
            B: Body<H>,
        {
            Self::new(
                block.reference(),
                BlockMeta::new(
                    block.header().clone(),
                    u64::try_from(block.encode_size()).unwrap(),
                ),
            )
        }
    }
}
