use super::ledger::LedgerService;
use crate::domain::LedgerEvent;
use commonware_runtime::Spawner;
use tracing::{debug, trace};

/// Observers that react to ledger domain events without mutating aggregates.
pub(crate) struct LedgerObservers;

impl LedgerObservers {
    pub(crate) fn spawn<S>(service: LedgerService, spawner: S)
    where
        S: Spawner,
    {
        let mut receiver = service.subscribe();
        spawner.shared(true).spawn(move |_| async move {
            while let Some(event) = receiver.recv().await {
                match event {
                    LedgerEvent::TransactionSubmitted(id) => {
                        trace!(tx=?id, "mempool accepted transaction");
                    }
                    LedgerEvent::SeedUpdated(digest, seed) => {
                        debug!(digest=?digest, seed=?seed, "seed cache refreshed");
                    }
                    LedgerEvent::SnapshotPersisted(digest) => {
                        trace!(?digest, "snapshot persisted");
                    }
                }
            }
        });
    }
}
