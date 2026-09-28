//! Multimmit's marshal as an engine-neutral [`Ledger`] of its finalized stream.
//!
//! The stream interleaves many producer chains, so it is not [`Linear`](crate::marshal::Linear):
//! a block's height is its height in its own chain, not its index.

use super::{Error, Floor, Mailbox, Update};
use crate::{
    marshal::{Delivery, Finalized, Floors, Ledger},
    multimmit::{
        scheme::Scheme,
        types::{Body, TransactionBlock},
    },
    types::OutputIndex,
};
use commonware_cryptography::Hasher;
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

impl<H, S, B> Ledger for Mailbox<H, S, B>
where
    H: Hasher,
    S: Scheme,
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

impl<H, S, B> Floors for Mailbox<H, S, B>
where
    H: Hasher,
    S: Scheme,
    B: Body<H>,
{
    type Floor = Floor<S, H::Digest>;

    async fn floor_at(&self, at: OutputIndex) -> Option<(OutputIndex, Self::Floor)> {
        Self::floor_at(self, at).await.ok().flatten()
    }

    /// The floor's index is the sum of its emitted frontier's heights (decoding bounds the sum),
    /// which installing the floor authenticates. Only a floor marshal refuses is rejected: any
    /// other failure leaves the floor unheld as well.
    async fn install(&self, floor: Self::Floor) -> Option<OutputIndex> {
        let index = floor
            .emitted()
            .iter()
            .try_fold(0u64, |sum, block| sum.checked_add(block.height().get()))?;
        match self.install_floor(floor).await {
            Ok(()) => Some(OutputIndex::new(index)),
            Err(Error::Rejected(reason)) => {
                debug!(reason, "marshal rejected the floor");
                None
            }
            Err(error) => {
                warn!(?error, "marshal did not install the floor");
                None
            }
        }
    }
}
