//! Multimmit's marshal as an engine-neutral [`Ledger`] of its finalized stream.
//!
//! The stream interleaves many producer chains, so it is not [`Linear`](crate::marshal::Linear):
//! a block's height is its height in its own chain, not its index.

use super::{Error, Floor, Mailbox, Update, storage::catalog_state::frontier_index};
use crate::{
    marshal::{Delivery, Finalized, Floors, Ledger, Reported},
    multimmit::types::{Body, TransactionBlock},
    types::OutputIndex,
};
use commonware_cryptography::{Hasher, bls12381::primitives::variant::Variant};
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

impl<H, V, B> Ledger for Mailbox<H, V, B>
where
    H: Hasher,
    V: Variant,
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

impl<H, V, B> Floors for Mailbox<H, V, B>
where
    H: Hasher,
    V: Variant,
    B: Body<H>,
{
    type Floor = Floor<V, H::Digest>;

    async fn floor_at(&self, at: OutputIndex) -> Result<Option<(OutputIndex, Self::Floor)>, Error> {
        Self::floor_at(self, at).await
    }

    /// The floor's index is the sum of its emitted frontier's heights, which installing the floor
    /// authenticates. A floor that fails to install is rejected; a busy or closed marshal is an
    /// error.
    async fn install(&self, floor: Self::Floor) -> Result<Option<OutputIndex>, Error> {
        let Some(index) = frontier_index(floor.emitted()) else {
            return Ok(None);
        };
        match self.install_floor(floor).await {
            Ok(()) => Ok(Some(index)),
            Err(Error::Failed(error)) => {
                debug!(%error, "marshal rejected the floor");
                Ok(None)
            }
            Err(error) => Err(error),
        }
    }
}
