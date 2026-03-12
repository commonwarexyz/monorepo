//! Mock database types for stateful wrapper tests.

use crate::stateful::db::{ManagedDb, Merkleized, SyncableDb, Unmerkleized};
use commonware_cryptography::{sha256, Hasher, Sha256};
use commonware_runtime::{Clock, Metrics, Spawner};
use commonware_utils::{
    channel::{mpsc, oneshot},
    sync::{AsyncRwLock, Mutex},
};
use rand::Rng;
use std::{collections::BTreeMap, convert::Infallible, sync::Arc};
use tracing::info;

/// Parent state for an unmerkleized batch: either the committed DB state
/// or a merkleized batch's resolved state.
enum ParentState {
    Committed(Arc<Mutex<BTreeMap<Vec<u8>, Vec<u8>>>>),
    Resolved(Arc<BTreeMap<Vec<u8>, Vec<u8>>>),
}

impl ParentState {
    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        match self {
            Self::Committed(state) => state.lock().get(key).cloned(),
            Self::Resolved(state) => state.get(key).cloned(),
        }
    }
}

/// An in-progress batch of mutations backed by an in-memory overlay.
pub struct MockUnmerkleized {
    parent: ParentState,
    overlay: BTreeMap<Vec<u8>, Option<Vec<u8>>>,
}

impl Unmerkleized for MockUnmerkleized {
    type Key = Vec<u8>;
    type Value = Vec<u8>;
    type Merkleized = MockMerkleized;
    type Error = Infallible;

    async fn get(&self, key: &Vec<u8>) -> Result<Option<Vec<u8>>, Infallible> {
        if let Some(value) = self.overlay.get(key) {
            return Ok(value.clone());
        }
        Ok(self.parent.get(key))
    }

    fn write(mut self, key: Vec<u8>, value: Option<Vec<u8>>) -> Self {
        self.overlay.insert(key, value);
        self
    }

    async fn merkleize(self) -> Result<MockMerkleized, Infallible> {
        // Resolve overlay against parent into a flat map.
        let mut resolved = match &self.parent {
            ParentState::Committed(state) => state.lock().clone(),
            ParentState::Resolved(state) => (**state).clone(),
        };
        for (key, value) in self.overlay {
            match value {
                Some(v) => {
                    resolved.insert(key, v);
                }
                None => {
                    resolved.remove(&key);
                }
            }
        }

        let root = compute_root(&resolved);

        Ok(MockMerkleized {
            resolved: Arc::new(resolved),
            state_root: root,
        })
    }
}

/// Compute a deterministic root digest from sorted key-value entries.
///
/// This is the mock equivalent of a Merkle root -- used by both
/// [`MockMerkleized`] and the mock sync engine to verify state.
pub fn compute_root(state: &BTreeMap<Vec<u8>, Vec<u8>>) -> sha256::Digest {
    let mut hasher = Sha256::new();
    hasher.update(b"_COMMONWARE_GLUE_MOCK_DB_ROOT");
    for (k, v) in state {
        hasher.update(k);
        hasher.update(v);
    }
    hasher.finalize()
}

/// A sealed batch whose state root has been computed.
pub struct MockMerkleized {
    resolved: Arc<BTreeMap<Vec<u8>, Vec<u8>>>,
    state_root: sha256::Digest,
}

impl Merkleized for MockMerkleized {
    type Digest = sha256::Digest;
    type Unmerkleized = MockUnmerkleized;

    fn root(&self) -> sha256::Digest {
        self.state_root
    }

    fn new_batch(&self) -> MockUnmerkleized {
        MockUnmerkleized {
            parent: ParentState::Resolved(self.resolved.clone()),
            overlay: BTreeMap::new(),
        }
    }
}

/// An in-memory database implementing [`ManagedDb`] and [`SyncableDb`].
pub struct MockDb {
    committed: Arc<Mutex<BTreeMap<Vec<u8>, Vec<u8>>>>,
}

impl Default for MockDb {
    fn default() -> Self {
        Self {
            committed: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }
}

impl MockDb {
    /// Return a snapshot of the committed state (for test assertions).
    pub fn committed_state(&self) -> BTreeMap<Vec<u8>, Vec<u8>> {
        self.committed.lock().clone()
    }
}

impl ManagedDb for MockDb {
    type Unmerkleized = MockUnmerkleized;
    type Merkleized = MockMerkleized;
    type Error = Infallible;

    fn new_batch(&self) -> MockUnmerkleized {
        MockUnmerkleized {
            parent: ParentState::Committed(self.committed.clone()),
            overlay: BTreeMap::new(),
        }
    }

    async fn finalize(&mut self, batch: MockMerkleized) -> Result<(), Infallible> {
        *self.committed.lock() = Arc::unwrap_or_clone(batch.resolved);
        Ok(())
    }
}

/// Error type for mock sync operations.
#[derive(Debug)]
pub struct MockSyncError;

/// Resolver that serves key-value state from a source database.
///
/// Models the real QMDB sync resolver which fetches operations from
/// peers. Each call to [`fetch`](Self::fetch) reads the source
/// database's current committed state, reflecting any finalizations
/// that have occurred since the resolver was created.
#[derive(Clone)]
pub struct MockSyncResolver {
    source: Arc<AsyncRwLock<MockDb>>,
}

impl MockSyncResolver {
    /// Create a resolver that serves state from the given source
    /// database.
    pub fn new(source: &Arc<AsyncRwLock<MockDb>>) -> Self {
        Self {
            source: source.clone(),
        }
    }

    /// Fetch the current state from the source database.
    ///
    /// Analogous to QMDB's `Resolver::get_operations` -- returns the
    /// current set of key-value entries. Each call reads the source's
    /// latest committed state, so results evolve as the source
    /// finalizes blocks.
    async fn fetch(&self) -> BTreeMap<Vec<u8>, Vec<u8>> {
        self.source.read().await.committed_state()
    }
}

impl SyncableDb for MockDb {
    type SyncConfig = ();
    type SyncResolver = MockSyncResolver;
    type SyncTarget = sha256::Digest;
    type SyncError = MockSyncError;

    fn spawn_sync<E>(
        database: Arc<AsyncRwLock<Self>>,
        context: E,
        _sync_config: (),
        resolver: MockSyncResolver,
        initial_target: sha256::Digest,
        mut target_updates: mpsc::Receiver<sha256::Digest>,
    ) -> Result<oneshot::Receiver<Result<(), MockSyncError>>, MockSyncError>
    where
        E: Rng + Spawner + Metrics + Clock,
    {
        let (completion_tx, completion_rx) = oneshot::channel();

        context.with_label("mock_sync").spawn(move |_| async move {
            let mut target = initial_target;

            loop {
                // Fetch operations from the resolver (analogous to
                // QMDB fetching operation batches from peers).
                let operations = resolver.fetch().await;

                // Compute root of fetched state (analogous to QMDB
                // verifying the MMR proof and comparing roots).
                let root = compute_root(&operations);

                if root == target {
                    // Root matches target -- sync complete. Apply
                    // state to the database.
                    database
                        .write()
                        .await
                        .committed
                        .lock()
                        .clone_from(&operations);
                    info!(?root, "mock sync complete");
                    let _ = completion_tx.send(Ok(()));
                    return;
                }

                // Root doesn't match target. The source hasn't
                // caught up to our target yet, or the target has
                // moved. Wait for a target update and retry.
                let Some(new_target) = target_updates.recv().await else {
                    // Channel closed -- sync coordinator shut down.
                    return;
                };
                target = new_target;
            }
        });

        Ok(completion_rx)
    }
}
