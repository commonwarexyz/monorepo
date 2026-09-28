//! Multimmit's marshal as an engine-neutral [`Ledger`] of its finalized stream.
//!
//! The stream interleaves many producer chains, so it is not [`Linear`](crate::marshal::Linear):
//! a block's height is its height in its own chain, not its index.

use super::{Floor, Mailbox, Update, storage::catalog_state::frontier_index};
use crate::{
    marshal::{Delivery, Finalized, Floors, Ledger},
    multimmit::types::{Body, TransactionBlock},
    types::OutputIndex,
};
use commonware_cryptography::{Hasher, bls12381::primitives::variant::Variant};
use commonware_utils::acknowledgement::Exact;
use std::num::NonZeroUsize;
use tracing::{debug, warn};

impl<B: crate::Block> Delivery for Update<B> {
    type Block = B;
    type Acknowledgement = Exact;

    fn finalized(self) -> Option<Finalized<B>> {
        Some(Finalized {
            index: self.index,
            block: self.block,
            acknowledgement: self.acknowledgement,
        })
    }
}

impl<H, V, B> Ledger for Mailbox<H, V, B>
where
    H: Hasher,
    V: Variant,
    B: Body<H>,
{
    type Block = TransactionBlock<H, B>;

    async fn prune(&self, below: OutputIndex) {
        if let Err(error) = Self::prune(self, below).await {
            warn!(?error, %below, "marshal did not prune");
        }
    }

    fn ack_window(&self) -> NonZeroUsize {
        self.max_pending_acks()
    }
}

impl<H, V, B> Floors for Mailbox<H, V, B>
where
    H: Hasher,
    V: Variant,
    B: Body<H>,
{
    type Floor = Floor<V, H::Digest>;

    async fn floor_at(&self, at: OutputIndex) -> Option<(OutputIndex, Self::Floor)> {
        Self::floor_at(self, at).await.ok().flatten()
    }

    /// The floor's index is the sum of its emitted frontier's heights, which installing the floor
    /// authenticates.
    async fn install(&self, floor: Self::Floor) -> Option<OutputIndex> {
        let index = frontier_index(floor.emitted())?;
        if let Err(error) = self.install_floor(floor).await {
            debug!(?error, "marshal rejected the floor");
            return None;
        }
        Some(index)
    }
}
