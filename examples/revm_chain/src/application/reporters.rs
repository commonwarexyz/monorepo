//! Reporters used by the REVM chain example.
//!
//! This example uses two independent reporting streams:
//! - `SeedReporter`: listens to threshold-simplex notarization/finalization activity and stores a
//!   32-byte hash of the threshold seed for each digest. The proposer uses this to set
//!   `prevrandao` for the next block.
//! - `FinalizedReporter`: listens to `commonware_consensus::marshal::Update` and reacts to
//!   finalized blocks (prunes the mempool and forwards a finalization event to the simulation).

use super::state::Shared;
use crate::{
    consensus::{digest_for_block, ConsensusDigest, FinalizationEvent},
    types::Block,
};
use alloy_evm::revm::primitives::{keccak256, B256};
use commonware_consensus::{
    marshal::Update,
    simplex::{
        signing_scheme::{bls12381_threshold, bls12381_threshold::Seedable as _},
        types::Activity,
    },
    Reporter,
};
use commonware_cryptography::bls12381::primitives::variant::Variant;
use commonware_utils::acknowledgement::Acknowledgement as _;
use futures::channel::mpsc;
use std::marker::PhantomData;

#[derive(Clone)]
pub(crate) struct SeedReporter<V> {
    state: Shared,
    _variant: PhantomData<V>,
}

impl<V> SeedReporter<V> {
    pub(crate) const fn new(state: Shared) -> Self {
        Self {
            state,
            _variant: PhantomData,
        }
    }

    fn hash_seed(seed: impl commonware_codec::Encode) -> B256 {
        keccak256(seed.encode())
    }
}

impl<V> Reporter for SeedReporter<V>
where
    V: Variant,
{
    type Activity = Activity<bls12381_threshold::Scheme<crate::PublicKey, V>, ConsensusDigest>;

    async fn report(&mut self, activity: Self::Activity) {
        match activity {
            Activity::Notarization(notarization) => {
                self.state
                    .set_seed(
                        notarization.proposal.payload,
                        Self::hash_seed(notarization.seed()),
                    )
                    .await;
            }
            Activity::Finalization(finalization) => {
                self.state
                    .set_seed(
                        finalization.proposal.payload,
                        Self::hash_seed(finalization.seed()),
                    )
                    .await;
            }
            _ => {}
        }
    }
}

#[derive(Clone)]
pub(crate) struct FinalizedReporter {
    node: u32,
    state: Shared,
    finalized: mpsc::UnboundedSender<FinalizationEvent>,
}

impl FinalizedReporter {
    pub(crate) const fn new(
        node: u32,
        state: Shared,
        finalized: mpsc::UnboundedSender<FinalizationEvent>,
    ) -> Self {
        Self {
            node,
            state,
            finalized,
        }
    }
}

impl Reporter for FinalizedReporter {
    type Activity = Update<Block>;

    async fn report(&mut self, update: Self::Activity) {
        match update {
            Update::Tip(_, _) => {}
            Update::Block(block, ack) => {
                let digest = digest_for_block(&block);
                self.state.prune_mempool(&block.txs).await;
                let _ = self.finalized.unbounded_send((self.node, digest));
                // Marshal waits for the application to acknowledge processing before advancing the
                // delivery floor. Without this, the node can stall on finalized block delivery.
                ack.acknowledge();
            }
        }
    }
}
