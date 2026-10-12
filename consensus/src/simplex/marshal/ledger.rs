//! Simplex's marshal as an engine-neutral [`Ledger`] of its finalized chain.
//!
//! Simplex finalizes one chain, so a block's index in the finalized stream is its height.

use super::{
    Update,
    core::{Mailbox, Variant},
};
use crate::{
    Heightable as _,
    marshal::{Delivery, Finalized, Floors, Ledger, Linear, Reported},
    simplex::{scheme::Scheme, types::Finalization},
    types::{Height, OutputIndex},
};
use commonware_utils::Acknowledgement;
use std::{convert::Infallible, num::NonZeroUsize};

/// Simplex orders blocks as they finalize, so it never reports [`Reported::Final`].
impl<B: crate::Block, A: Acknowledgement> Delivery for Update<B, A> {
    type Block = B;
    type Acknowledgement = A;

    fn reported(self) -> Reported<B, A> {
        match self {
            Self::Tip(..) => Reported::Advisory,
            Self::Block(block, acknowledgement) => Reported::Finalized(Finalized {
                index: OutputIndex::new(block.height().get()),
                block,
                acknowledgement,
            }),
        }
    }
}

impl<S, V> Ledger for Mailbox<S, V>
where
    S: Scheme<V::Commitment>,
    V: Variant,
{
    type Block = V::ApplicationBlock;

    /// Marshal serves every request, and answers none once it stops.
    type Error = Infallible;

    /// Keeps the floor at `below`, the newest finalization at or below the block after it, and the
    /// block it finalizes, so the floor stays servable.
    async fn prune(&self, below: OutputIndex) -> Result<(), Infallible> {
        let below = Height::new(below.get());
        let keep = self
            .get_finalization_at_or_below(Height::new(below.get().saturating_add(1)))
            .await
            .map_or(below, |(height, _)| height.min(below));
        Self::prune(self, keep);
        Ok(())
    }

    fn ack_window(&self) -> NonZeroUsize {
        self.max_pending_acks
    }
}

/// A floor is a finalization. Marshal delivers the block it finalizes again, so the floor resumes
/// the stream after the block before it.
impl<S, V> Floors for Mailbox<S, V>
where
    S: Scheme<V::Commitment>,
    V: Variant,
{
    type Floor = Finalization<S, V::Commitment>;

    async fn floor_at(
        &self,
        at: OutputIndex,
    ) -> Result<Option<(OutputIndex, Self::Floor)>, Infallible> {
        let Some((height, finalization)) = self
            .get_finalization_at_or_below(Height::new(at.get().saturating_add(1)))
            .await
        else {
            return Ok(None);
        };
        Ok(height
            .previous()
            .map(|previous| (OutputIndex::new(previous.get()), finalization)))
    }

    /// Marshal fetches the block the floor finalizes, which states the floor's height.
    async fn install(&self, floor: Self::Floor) -> Result<Option<OutputIndex>, Infallible> {
        // Marshal redelivers the floor's block.
        Ok(self
            .install_floor(floor)
            .await
            .and_then(|height| height.previous())
            .map(|previous| OutputIndex::new(previous.get())))
    }
}

impl<S, V> Linear for Mailbox<S, V>
where
    S: Scheme<V::Commitment>,
    V: Variant,
{
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        simplex::marshal::mocks::harness::{B as Block, make_raw_block},
        types::{Epoch, Round, View},
    };
    use commonware_cryptography::{Digestible as _, Hasher as _, Sha256};
    use commonware_utils::acknowledgement::Exact;
    use std::sync::Arc;

    #[test]
    fn blocks_are_finalized_at_their_height_and_tips_are_advisory() {
        let block: Arc<Block> = Arc::new(make_raw_block(
            Sha256::hash(&[b"parent"]),
            Height::new(7),
            0,
        ));
        let round = Round::new(Epoch::zero(), View::new(9));
        let tip = Update::<Block, Exact>::Tip(round, Height::new(7), block.digest());
        assert!(matches!(tip.reported(), Reported::Advisory));

        let (acknowledgement, _waiter) = Exact::handle();
        let Reported::Finalized(finalized) =
            Update::Block(Arc::clone(&block), acknowledgement).reported()
        else {
            panic!("a block update reports a finalized block");
        };
        assert_eq!(finalized.index, OutputIndex::new(7));
        assert!(Arc::ptr_eq(&finalized.block, &block));
    }
}
