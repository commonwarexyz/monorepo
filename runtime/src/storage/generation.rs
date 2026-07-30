//! Live filesystem blob generations.

use super::batch::Operation;
use crate::RemoveTarget;
use commonware_utils::sync::Mutex;
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{
        Arc, Weak,
        atomic::{AtomicUsize, Ordering},
    },
};

// Avoid scanning small registries while bounding dead names relative to live generations.
const CLEANUP_FLOOR: usize = 64;

#[derive(Default)]
struct State {
    entries: BTreeMap<(String, Vec<u8>), Weak<Token>>,
    partitions: BTreeSet<String>,
}

/// Identity shared by every live handle for one blob-name generation.
pub(super) struct Token {
    live: Arc<AtomicUsize>,
}

impl Token {
    #[cfg(all(test, feature = "iouring-storage"))]
    pub(super) fn detached() -> Arc<Self> {
        Arc::new(Self {
            live: Arc::new(AtomicUsize::new(1)),
        })
    }
}

impl Drop for Token {
    fn drop(&mut self) {
        self.live.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Tracks the live handle generation for filesystem blob names.
#[derive(Default)]
pub(super) struct Registry {
    state: Mutex<State>,
    live: Arc<AtomicUsize>,
}

impl Registry {
    pub(super) fn knows_partition(&self, partition: &str) -> bool {
        self.state.lock().partitions.contains(partition)
    }

    pub(super) fn generation(&self, partition: &str, name: &[u8]) -> Arc<Token> {
        let key = (partition.to_string(), name.to_vec());
        let mut state = self.state.lock();
        state.partitions.insert(partition.to_string());
        if let Some(generation) = state.entries.get(&key).and_then(Weak::upgrade) {
            return generation;
        }

        let cleanup_at = self
            .live
            .load(Ordering::Relaxed)
            .saturating_mul(2)
            .max(CLEANUP_FLOOR);
        if state.entries.len() >= cleanup_at {
            state
                .entries
                .retain(|_, generation| generation.strong_count() != 0);
        }

        let generation = Arc::new(Token {
            live: self.live.clone(),
        });
        self.live.fetch_add(1, Ordering::Relaxed);
        state.entries.insert(key, Arc::downgrade(&generation));
        generation
    }

    pub(super) fn is_current(&self, partition: &str, name: &[u8], generation: &Arc<Token>) -> bool {
        self.state
            .lock()
            .entries
            .get(&(partition.to_string(), name.to_vec()))
            .and_then(Weak::upgrade)
            .is_some_and(|current| Arc::ptr_eq(&current, generation))
    }

    pub(super) fn invalidate(&self, operations: &[Operation]) {
        self.invalidate_with(operations, || {});
    }

    fn invalidate_with(&self, operations: &[Operation], mut visit: impl FnMut()) {
        let mut removed_partitions = BTreeSet::new();
        let mut removed_blobs = Vec::new();
        for operation in operations {
            match operation {
                Operation::Remove(RemoveTarget::Blob { partition, name }) => {
                    removed_blobs.push((partition.as_str(), name.as_slice()));
                }
                Operation::Remove(RemoveTarget::Partition(partition)) => {
                    removed_partitions.insert(partition.as_str());
                }
                Operation::Resize { .. } | Operation::Update { .. } => {}
            }
        }

        let mut state = self.state.lock();
        for (partition, name) in removed_blobs {
            state
                .entries
                .remove(&(partition.to_string(), name.to_vec()));
        }
        if !removed_partitions.is_empty() {
            state.entries.retain(|(partition, _), _| {
                visit();
                !removed_partitions.contains(partition.as_str())
            });
            state
                .partitions
                .retain(|partition| !removed_partitions.contains(partition.as_str()));
        }
    }

    #[cfg(all(test, not(feature = "iouring-storage")))]
    pub(super) fn len(&self) -> usize {
        self.state.lock().entries.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partition_batch_scans_registry_once() {
        let registry = Registry::default();
        let live = (0..8)
            .map(|partition| registry.generation(&format!("live_{partition}"), b"blob"))
            .collect::<Vec<_>>();
        let operations = (0..100)
            .map(|partition| {
                Operation::Remove(RemoveTarget::Partition(format!("missing_{partition}")))
            })
            .collect::<Vec<_>>();

        let mut visits = 0;
        registry.invalidate_with(&operations, || visits += 1);
        assert_eq!(visits, live.len());
    }
}
