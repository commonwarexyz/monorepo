use super::{adapter::QmdbRefDb, Error, QmdbChangeSet, QmdbConfig, QmdbState};
use crate::domain::StateRoot;
use alloy_evm::revm::primitives::{Address, U256};
use commonware_runtime::tokio::Context;
use std::sync::Arc;

/// Domain service that owns QMDB persistence for the REVM example.
#[derive(Clone)]
pub(crate) struct QmdbLedger {
    state: Arc<QmdbState>,
}

impl QmdbLedger {
    /// Initializes the QMDB partitions and populates the genesis allocation.
    pub(crate) async fn init(
        context: Context,
        config: QmdbConfig,
        genesis_alloc: Vec<(Address, U256)>,
    ) -> Result<Self, Error> {
        let state = QmdbState::init(context, config, genesis_alloc).await?;
        Ok(Self {
            state: Arc::new(state),
        })
    }

    /// Exposes a synchronous REVM database view backed by QMDB.
    pub(crate) fn database(&self) -> Result<QmdbRefDb, Error> {
        self.state.database()
    }

    /// Computes the root for a change set without committing.
    pub(crate) async fn compute_root(&self, changes: QmdbChangeSet) -> Result<StateRoot, Error> {
        self.state.compute_root(changes).await
    }

    /// Commits the provided changes to QMDB and returns the resulting root.
    pub(crate) async fn commit_changes(&self, changes: QmdbChangeSet) -> Result<StateRoot, Error> {
        self.state.commit_changes(changes).await
    }

    /// Returns the current authenticated root stored in QMDB.
    pub(crate) async fn root(&self) -> Result<StateRoot, Error> {
        self.state.root().await
    }
}
