//! Multimmit's marshal as an engine-neutral [`Ledger`] of its finalized stream.
//!
//! The stream interleaves many producer chains, so it is not [`Linear`](crate::marshal::Linear):
//! a block's height is its height in its own chain, not its index.

use super::{Error, Floor, Mailbox, Update};
use crate::{
    marshal::{Delivery, Finalized, Floors, Ledger, Reported},
    multimmit::{
        scheme::Scheme,
        types::{Body, TransactionBlock},
    },
    types::OutputIndex,
};
use commonware_cryptography::Hasher;
use commonware_utils::acknowledgement::Exact;
use std::num::NonZeroUsize;
use tracing::debug;

impl<B: crate::Block> Delivery for Update<B> {
    type Block = B;
    type Acknowledgement = Exact;

    fn reported(self) -> Reported<B> {
        match self {
            Self::Block {
                index,
                block,
                acknowledgement,
            } => Reported::Finalized(Finalized {
                index,
                block,
                acknowledgement,
            }),
            Self::Final(block) => Reported::Final(block),
        }
    }
}

impl<H, S, B> Ledger for Mailbox<H, S, B>
where
    H: Hasher,
    S: Scheme,
    B: Body<H>,
{
    type Block = TransactionBlock<H, B>;
    type Error = Error;

    async fn prune(&self, below: OutputIndex) -> Result<(), Error> {
        Self::prune(self, below).await
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

    async fn floor_at(&self, at: OutputIndex) -> Result<Option<(OutputIndex, Self::Floor)>, Error> {
        Self::floor_at(self, at).await
    }

    /// The floor's index is the sum of its emitted frontier's heights (decoding bounds the sum),
    /// which installing the floor authenticates. Only a floor marshal refuses is rejected: a
    /// busy, closed or failed marshal is an error.
    async fn install(&self, floor: Self::Floor) -> Result<Option<OutputIndex>, Error> {
        let Some(index) = floor
            .emitted()
            .iter()
            .try_fold(0u64, |sum, block| sum.checked_add(block.height().get()))
        else {
            return Ok(None);
        };
        match self.install_floor(floor).await {
            Ok(()) => Ok(Some(OutputIndex::new(index))),
            Err(Error::Rejected(reason)) => {
                debug!(reason, "marshal rejected the floor");
                Ok(None)
            }
            Err(error) => Err(error),
        }
    }
}
