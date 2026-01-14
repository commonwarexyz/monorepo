use crate::{
    qmdb::{QmdbChanges, RevmDb},
    ConsensusDigest, StateRoot,
};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone)]
pub(crate) struct LedgerSnapshot {
    pub(crate) parent: Option<ConsensusDigest>,
    pub(crate) db: RevmDb,
    pub(crate) state_root: StateRoot,
    pub(crate) qmdb_changes: QmdbChanges,
}

#[derive(Clone)]
pub(crate) struct SnapshotStore {
    snapshots: BTreeMap<ConsensusDigest, LedgerSnapshot>,
    persisted: BTreeSet<ConsensusDigest>,
}

impl SnapshotStore {
    pub(crate) fn new(genesis_digest: ConsensusDigest, genesis_snapshot: LedgerSnapshot) -> Self {
        let mut snapshots = BTreeMap::new();
        snapshots.insert(genesis_digest, genesis_snapshot);
        let persisted = BTreeSet::from([genesis_digest]);
        Self {
            snapshots,
            persisted,
        }
    }

    pub(crate) fn get(&self, digest: &ConsensusDigest) -> Option<&LedgerSnapshot> {
        self.snapshots.get(digest)
    }

    pub(crate) fn get_mut(&mut self, digest: &ConsensusDigest) -> Option<&mut LedgerSnapshot> {
        self.snapshots.get_mut(digest)
    }

    pub(crate) fn insert(&mut self, digest: ConsensusDigest, snapshot: LedgerSnapshot) {
        self.snapshots.insert(digest, snapshot);
    }

    pub(crate) fn mark_persisted(&mut self, digest: ConsensusDigest) {
        self.persisted.insert(digest);
    }

    pub(crate) fn is_persisted(&self, digest: &ConsensusDigest) -> bool {
        self.persisted.contains(digest)
    }

    pub(crate) fn merged_changes_from(
        &self,
        mut parent: ConsensusDigest,
        changes: QmdbChanges,
    ) -> anyhow::Result<QmdbChanges> {
        let mut chain = Vec::new();
        while !self.persisted.contains(&parent) {
            let snapshot = self
                .snapshots
                .get(&parent)
                .ok_or_else(|| anyhow::anyhow!("missing snapshot"))?;
            let Some(next) = snapshot.parent else {
                return Err(anyhow::anyhow!("missing parent snapshot"));
            };
            chain.push(snapshot.qmdb_changes.clone());
            parent = next;
        }

        let mut merged = QmdbChanges::default();
        for delta in chain.into_iter().rev() {
            merged.merge(delta);
        }
        merged.merge(changes);
        Ok(merged)
    }
}
