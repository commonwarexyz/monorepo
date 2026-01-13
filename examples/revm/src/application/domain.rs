//! Domain-level helpers for the REVM example.

use crate::{types::TxId, ConsensusDigest};
use alloy_evm::revm::primitives::B256;
use futures::channel::mpsc::{unbounded, UnboundedReceiver, UnboundedSender};
use std::sync::{Arc, Mutex as StdMutex};

/// Domain events published by the ledger.
#[derive(Clone, Debug)]
pub(crate) enum DomainEvent {
    #[allow(dead_code)]
    TransactionSubmitted(TxId),
    #[allow(dead_code)]
    SnapshotPersisted(ConsensusDigest),
    #[allow(dead_code)]
    SeedUpdated(ConsensusDigest, B256),
}

#[derive(Clone)]
pub(crate) struct DomainEvents {
    listeners: Arc<StdMutex<Vec<UnboundedSender<DomainEvent>>>>,
}

impl DomainEvents {
    pub(crate) fn new() -> Self {
        Self {
            listeners: Arc::new(StdMutex::new(Vec::new())),
        }
    }

    pub(crate) fn publish(&self, event: DomainEvent) {
        let mut guard = self.listeners.lock().unwrap();
        guard.retain(|sender| sender.unbounded_send(event.clone()).is_ok());
    }

    pub(crate) fn subscribe(&self) -> UnboundedReceiver<DomainEvent> {
        let (sender, receiver) = unbounded();
        self.listeners.lock().unwrap().push(sender);
        receiver
    }
}
