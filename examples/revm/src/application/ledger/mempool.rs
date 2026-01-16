use crate::domain::{Tx, TxId};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Default, Clone)]
pub(crate) struct Mempool(BTreeMap<TxId, Tx>);

impl Mempool {
    pub(crate) const fn new() -> Self {
        Self(BTreeMap::new())
    }

    pub(crate) fn insert(&mut self, tx: Tx) -> bool {
        self.0.insert(tx.id(), tx).is_none()
    }

    pub(crate) fn build(&self, max_txs: usize, excluded: &BTreeSet<TxId>) -> Vec<Tx> {
        self.0
            .iter()
            .filter(|(tx_id, _)| !excluded.contains(tx_id))
            .take(max_txs)
            .map(|(_, tx)| tx.clone())
            .collect()
    }

    pub(crate) fn prune(&mut self, txs: &[Tx]) {
        for tx in txs {
            self.0.remove(&tx.id());
        }
    }
}
