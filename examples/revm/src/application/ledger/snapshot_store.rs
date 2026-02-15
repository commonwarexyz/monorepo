//! Snapshot storage for per-digest execution state and pending QMDB deltas.
//!
//! The store keeps:
//! - cached execution snapshots keyed by consensus digest, and
//! - a set of digests already persisted to QMDB.
//!
//! When computing a root for a new proposal, we must merge all unpersisted
//! ancestor deltas so the computed root reflects the full chain.

use crate::{
    qmdb::{QmdbChangeSet, RevmDb},
    ConsensusDigest, StateRoot,
};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone)]
/// Cached execution snapshot for a specific digest.
pub(crate) struct LedgerSnapshot {
    /// Parent digest used to walk back through unpersisted ancestors.
    pub(crate) parent: Option<ConsensusDigest>,
    /// REVM overlay database after executing the block.
    pub(crate) db: RevmDb,
    /// State root computed for this snapshot.
    pub(crate) state_root: StateRoot,
    /// QMDB delta produced by executing the block.
    pub(crate) qmdb_changes: QmdbChangeSet,
}

#[derive(Clone)]
/// Stores snapshots and tracks which digests are already persisted.
pub(crate) struct SnapshotStore {
    snapshots: BTreeMap<ConsensusDigest, LedgerSnapshot>,
    persisted: BTreeSet<ConsensusDigest>,
    /// Digests currently being committed to QMDB to avoid duplicate concurrent commits.
    persisting: BTreeSet<ConsensusDigest>,
}

impl SnapshotStore {
    pub(crate) fn new(genesis_digest: ConsensusDigest, genesis_snapshot: LedgerSnapshot) -> Self {
        let mut snapshots = BTreeMap::new();
        snapshots.insert(genesis_digest, genesis_snapshot);
        let persisted = BTreeSet::from([genesis_digest]);
        let persisting = BTreeSet::new();
        Self {
            snapshots,
            persisted,
            persisting,
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

    #[cfg(test)]
    pub(crate) fn is_persisted(&self, digest: &ConsensusDigest) -> bool {
        self.persisted.contains(digest)
    }

    /// Returns true if every digest in the chain is neither persisted nor in-flight.
    pub(crate) fn can_persist_chain(&self, chain: &[ConsensusDigest]) -> bool {
        chain
            .iter()
            .all(|digest| !self.persisted.contains(digest) && !self.persisting.contains(digest))
    }

    pub(crate) fn mark_persisting_chain(&mut self, chain: &[ConsensusDigest]) {
        for digest in chain {
            self.persisting.insert(*digest);
        }
    }

    pub(crate) fn clear_persisting_chain(&mut self, chain: &[ConsensusDigest]) {
        for digest in chain {
            self.persisting.remove(digest);
        }
    }

    pub(crate) fn mark_persisted_chain(&mut self, chain: &[ConsensusDigest]) {
        for digest in chain {
            self.persisted.insert(*digest);
        }
    }

    /// Merge unpersisted ancestor deltas up to the last persisted digest.
    ///
    /// Returns the ordered chain (oldest to newest) and the merged change set so commits
    /// apply in strict height order.
    pub(crate) fn merged_changes_for_persist(
        &self,
        mut digest: ConsensusDigest,
    ) -> anyhow::Result<(Vec<ConsensusDigest>, QmdbChangeSet)> {
        let mut chain = Vec::new();
        while !self.persisted.contains(&digest) {
            let snapshot = self
                .snapshots
                .get(&digest)
                .ok_or_else(|| anyhow::anyhow!("missing snapshot"))?;
            chain.push(digest);
            let Some(parent) = snapshot.parent else {
                return Err(anyhow::anyhow!("missing parent snapshot"));
            };
            digest = parent;
        }

        if chain.is_empty() {
            return Ok((Vec::new(), QmdbChangeSet::default()));
        }

        chain.reverse();
        let mut merged = QmdbChangeSet::default();
        for digest in &chain {
            let snapshot = self
                .snapshots
                .get(digest)
                .ok_or_else(|| anyhow::anyhow!("missing snapshot"))?;
            merged.merge(snapshot.qmdb_changes.clone());
        }
        Ok((chain, merged))
    }

    /// Merge unpersisted ancestor deltas with new changes for a consistent root computation.
    ///
    /// The merge order is oldest ancestor first, then the provided `changes` last.
    pub(crate) fn merged_changes_from(
        &self,
        mut parent: ConsensusDigest,
        changes: QmdbChangeSet,
    ) -> anyhow::Result<QmdbChangeSet> {
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

        let mut merged = QmdbChangeSet::default();
        for delta in chain.into_iter().rev() {
            merged.merge(delta);
        }
        merged.merge(changes);
        Ok(merged)
    }
}
