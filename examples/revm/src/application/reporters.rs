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
    execution::{evm_env, execute_txs},
    types::Block,
    ConsensusDigest, FinalizationEvent,
};
use alloy_evm::revm::primitives::{keccak256, B256};
use commonware_consensus::{
    marshal::Update,
    simplex::{
        scheme::{bls12381_threshold, bls12381_threshold::Seedable as _},
        types::Activity,
    },
    Block as _, Reporter,
};
use commonware_cryptography::{bls12381::primitives::variant::Variant, Committable as _};
use commonware_runtime::Spawner;
use commonware_utils::acknowledgement::Acknowledgement as _;
use futures::channel::mpsc;
use std::marker::PhantomData;

/// Helper function for SeedReporter::report that owns all its inputs
async fn seed_report_inner<V: Variant>(
    state: Shared,
    activity: Activity<bls12381_threshold::Scheme<crate::PublicKey, V>, ConsensusDigest>,
) {
    match activity {
        Activity::Notarization(notarization) => {
            state
                .set_seed(
                    notarization.proposal.payload,
                    SeedReporter::<V>::hash_seed(notarization.seed()),
                )
                .await;
        }
        Activity::Finalization(finalization) => {
            state
                .set_seed(
                    finalization.proposal.payload,
                    SeedReporter::<V>::hash_seed(finalization.seed()),
                )
                .await;
        }
        _ => {}
    }
}

/// Helper function for FinalizedReporter::report that owns all its inputs
async fn finalized_report_inner<E>(
    state: Shared,
    finalized: mpsc::UnboundedSender<FinalizationEvent>,
    node: u32,
    spawner: E,
    update: Update<Block>,
) where
    E: Spawner,
{
    match update {
        Update::Tip(_, _) => {}
        Update::Block(block, ack) => {
            let mut block = block;
            let digest = block.commitment();
            if state.query_state_root(digest).await.is_none() {
                let parent_digest = block.parent();
                let parent_snapshot = state
                    .parent_snapshot(parent_digest)
                    .await
                    .expect("missing parent snapshot");
                let env = evm_env(block.height, block.prevrandao);
                let exec = spawner.shared(true).spawn(|_| async move {
                    execute_txs(parent_snapshot.db, env, &block.txs)
                        .map(|(db, outcome)| (block, db, outcome))
                });
                let (next_block, db, outcome) = exec
                    .await
                    .expect("execute task failed")
                    .expect("execute finalized block");
                block = next_block;
                let state_root = state
                    .preview_qmdb_root(parent_digest, outcome.qmdb_changes.clone())
                    .await
                    .expect("preview qmdb root");
                assert_eq!(state_root, block.state_root, "state root mismatch");
                state
                    .insert_snapshot(digest, parent_digest, db, state_root, outcome.qmdb_changes)
                    .await;
            }
            state
                .persist_snapshot(digest)
                .await
                .expect("persist finalized block");
            state.prune_mempool(&block.txs).await;
            let _ = finalized.unbounded_send((node, digest));
            // Marshal waits for the application to acknowledge processing before advancing the
            // delivery floor. Without this, the node can stall on finalized block delivery.
            ack.acknowledge();
        }
    }
}

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

    fn report(&mut self, activity: Self::Activity) -> impl std::future::Future<Output = ()> + Send {
        let state = self.state.clone();
        async move {
            seed_report_inner(state, activity).await;
        }
    }
}

#[derive(Clone)]
pub(crate) struct FinalizedReporter<E> {
    node: u32,
    state: Shared,
    finalized: mpsc::UnboundedSender<FinalizationEvent>,
    spawner: E,
}

impl<E> FinalizedReporter<E>
where
    E: Spawner,
{
    pub(crate) const fn new(
        node: u32,
        state: Shared,
        finalized: mpsc::UnboundedSender<FinalizationEvent>,
        spawner: E,
    ) -> Self {
        Self {
            node,
            state,
            finalized,
            spawner,
        }
    }
}

impl<E> Reporter for FinalizedReporter<E>
where
    E: Spawner,
{
    type Activity = Update<Block>;

    fn report(&mut self, update: Self::Activity) -> impl std::future::Future<Output = ()> + Send {
        let state = self.state.clone();
        let finalized = self.finalized.clone();
        let node = self.node;
        let spawner = self.spawner.clone();
        async move {
            finalized_report_inner(state, finalized, node, spawner, update).await;
        }
    }
}
