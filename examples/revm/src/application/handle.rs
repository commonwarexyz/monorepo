//! Handle for interacting with the application state.
//!
//! The simulation harness uses this handle to:
//! - submit transactions into the node-local mempool, and
//! - query state at a finalized digest for assertions.

use super::state::LedgerView;
use crate::{
    types::{StateRoot, Tx},
    ConsensusDigest,
};
use alloy_evm::revm::primitives::{Address, B256, U256};
use commonware_runtime::Spawner;

#[derive(Clone)]
/// Handle that exposes application queries and submissions to the simulation harness.
pub struct NodeHandle<E> {
    /// Ledger view that backs the application state.
    state: LedgerView,
    /// Spawner used to execute queries that interact with runtime traits.
    spawner: E,
}

impl<E> NodeHandle<E>
where
    E: Spawner,
{
    pub(crate) const fn new(state: LedgerView, spawner: E) -> Self {
        Self { state, spawner }
    }

    pub async fn submit_tx(&self, tx: Tx) -> bool {
        self.state.submit_tx(tx).await
    }

    pub async fn query_balance(&self, digest: ConsensusDigest, address: Address) -> Option<U256> {
        let state = self.state.clone();
        let spawner = self.spawner.clone();
        spawner
            .shared(true)
            .spawn(move |_| async move { state.query_balance(digest, address).await })
            .await
            .ok()
            .flatten()
    }

    pub async fn query_state_root(&self, digest: ConsensusDigest) -> Option<StateRoot> {
        self.state.query_state_root(digest).await
    }

    pub async fn query_seed(&self, digest: ConsensusDigest) -> Option<B256> {
        self.state.query_seed(digest).await
    }
}
