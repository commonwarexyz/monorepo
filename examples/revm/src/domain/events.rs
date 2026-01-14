//! Domain events for the REVM example.

use super::TxId;
use crate::ConsensusDigest;
use alloy_evm::revm::primitives::B256;
use futures::channel::mpsc::{unbounded, UnboundedReceiver, UnboundedSender};
use std::sync::{Arc, Mutex as StdMutex};

/// Ledger-related domain events.
#[derive(Clone, Debug)]
pub(crate) enum LedgerEvent {
    #[allow(dead_code)]
    TransactionSubmitted(TxId),
    #[allow(dead_code)]
    SnapshotPersisted(ConsensusDigest),
    #[allow(dead_code)]
    SeedUpdated(ConsensusDigest, B256),
}

#[derive(Clone)]
pub(crate) struct LedgerEvents {
    listeners: Arc<StdMutex<Vec<UnboundedSender<LedgerEvent>>>>,
}

impl LedgerEvents {
    pub(crate) fn new() -> Self {
        Self {
            listeners: Arc::new(StdMutex::new(Vec::new())),
        }
    }

    pub(crate) fn publish(&self, event: LedgerEvent) {
        let mut guard = self.listeners.lock().unwrap();
        guard.retain(|sender| sender.unbounded_send(event.clone()).is_ok());
    }

    pub(crate) fn subscribe(&self) -> UnboundedReceiver<LedgerEvent> {
        let (sender, receiver) = unbounded();
        self.listeners.lock().unwrap().push(sender);
        receiver
    }
}
