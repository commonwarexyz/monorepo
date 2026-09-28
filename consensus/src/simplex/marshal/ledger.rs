//! Simplex's marshal as an engine-neutral [`Ledger`] of its finalized chain.
//!
//! Simplex finalizes one chain, so a block's index in the finalized stream is its height.

use super::{
    Update,
    core::{CommitmentFallback, Mailbox, Variant},
};
use crate::{
    Heightable as _,
    marshal::{Delivery, Finalized, Floors, Ledger, Linear},
    simplex::{scheme::Scheme, types::Finalization},
    types::{Height, OutputIndex},
};
use commonware_utils::Acknowledgement;
use std::num::NonZeroUsize;

impl<B: crate::Block, A: Acknowledgement> Delivery for Update<B, A> {
    type Block = B;
    type Acknowledgement = A;

    fn finalized(self) -> Option<Finalized<B, A>> {
        match self {
            Self::Tip(..) => None,
            Self::Block(block, acknowledgement) => Some(Finalized {
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

    /// Keeps the floor at `below`, the newest finalization at or below the block after it, and the
    /// block it finalizes, so the floor stays servable.
    async fn prune(&self, below: OutputIndex) {
        let below = Height::new(below.get());
        let keep = self
            .get_finalization_at_or_below(Height::new(below.get().saturating_add(1)))
            .await
            .map_or(below, |(height, _)| height.min(below));
        Self::prune(self, keep);
    }

    fn ack_window(&self) -> NonZeroUsize {
        NonZeroUsize::new(self.max_pending_acks())
            .expect("marshal allows a pending acknowledgement")
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

    async fn floor_at(&self, at: OutputIndex) -> Option<(OutputIndex, Self::Floor)> {
        let (height, finalization) = self
            .get_finalization_at_or_below(Height::new(at.get().saturating_add(1)))
            .await?;
        Some((OutputIndex::new(height.previous()?.get()), finalization))
    }

    /// Marshal fetches the block the floor finalizes, which states the floor's height.
    async fn install(&self, floor: Self::Floor) -> Option<OutputIndex> {
        // Marshal ignores a floor of a round it already processed, whose block it may have pruned.
        // Its round floor comes from the finalization at or below the block it resumes at.
        if let Some(processed) = self.get_processed().await
            && let Some((_, finalization)) = self
                .get_finalization_at_or_below(Height::new(
                    processed.height().get().saturating_add(1),
                ))
                .await
            && floor.round() <= finalization.round()
        {
            return None;
        }
        let commitment = floor.proposal.payload;
        self.set_floor(floor);
        let block = self
            .subscribe_by_commitment(commitment, CommitmentFallback::Wait)
            .await
            .ok()?;
        // Marshal redelivers the floor's block.
        Some(OutputIndex::new(block.height().previous()?.get()))
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
        assert!(tip.finalized().is_none());

        let (acknowledgement, _waiter) = Exact::handle();
        let finalized = Update::Block(Arc::clone(&block), acknowledgement)
            .finalized()
            .unwrap();
        assert_eq!(finalized.index, OutputIndex::new(7));
        assert!(Arc::ptr_eq(&finalized.block, &block));
    }
}
