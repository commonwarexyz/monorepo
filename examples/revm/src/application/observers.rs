use super::state::LedgerService;
use crate::application::domain::DomainEvent;
use commonware_runtime::Spawner;
use futures::{channel::mpsc::UnboundedReceiver, StreamExt};
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
            while let Some(event) = receiver.next().await {
                match event {
                    DomainEvent::TransactionSubmitted(id) => {
                        trace!(tx=%id, "mempool accepted transaction");
                    }
                    DomainEvent::SeedUpdated(digest, seed) => {
                        debug!(digest=?digest, seed=?seed, "seed cache refreshed");
                    }
                    DomainEvent::SnapshotPersisted(digest) => {
                        trace!(?digest, "snapshot persisted");
                    }
                }
            }
        });
    }
}
