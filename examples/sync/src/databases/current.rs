//! Current database types and helpers for the sync example.
//!
//! A `current` database extends an `any` database with an activity bitmap that tracks which
//! operations are active (i.e. represent the current state of their key) vs inactive (superseded or
//! deleted). Its canonical root folds the ops root, a grafted merkle root (combining bitmap chunks
//! with ops subtree roots), and an optional partial-chunk digest. See [current] module
//! documentation for more details.
//!
//! For sync, the engine targets the **ops root** (not the canonical root). The operations and proof
//! format are identical to `any` -- the bitmap is reconstructed deterministically from the
//! operations after sync completes. See the [Root structure](commonware_storage::qmdb::current)
//! module documentation for details.
//!
//! This module re-uses the same [`Operation`] type as [`super::any`] since the underlying
//! operations log is the same.

use crate::{Hasher, Key, Translator, Value};
use commonware_codec::FixedSize;
use commonware_cryptography::{sha256, Hasher as CryptoHasher};
use commonware_runtime::{buffer, BufferPooler, Clock, Metrics, Storage};
use commonware_storage::{
    journal::contiguous::fixed::Config as FConfig,
    mmr::{self, full::Config as MmrConfig, Location, Proof},
    qmdb::{
        self,
        any::unordered::{fixed::Operation as FixedOperation, Update},
        current::{self, FixedConfig as Config},
        operation::Committable,
    },
};
use commonware_utils::{NZUsize, NZU16, NZU64};
use std::{future::Future, num::NonZeroU64};
use tracing::error;

/// Bitmap chunk size in bytes. Each chunk covers `N * 8` operations' activity bits.
const CHUNK_SIZE: usize = sha256::Digest::SIZE;

/// Database type alias.
pub type Database<E> =
    current::unordered::fixed::Db<mmr::Family, E, Key, Value, Hasher, Translator, CHUNK_SIZE>;

/// Operation type alias. Same as the `any` operation type.
pub type Operation = FixedOperation<mmr::Family, Key, Value>;

/// Create a database configuration.
pub fn create_config(context: &impl BufferPooler) -> Config<Translator> {
    let page_cache = buffer::paged::CacheRef::from_pooler(context, NZU16!(2048), NZUsize!(10));
    Config {
        merkle_config: MmrConfig {
            journal_partition: "mmr-journal".into(),
            metadata_partition: "mmr-metadata".into(),
            items_per_blob: NZU64!(4096),
            write_buffer: NZUsize!(4096),
            thread_pool: None,
            page_cache: page_cache.clone(),
        },
        journal_config: FConfig {
            partition: "log-journal".into(),
            items_per_blob: NZU64!(4096),
            write_buffer: NZUsize!(4096),
            page_cache,
        },
        grafted_metadata_partition: "grafted-mmr-metadata".into(),
        translator: Translator::default(),
    }
}

impl<E> super::ExampleDatabase for Database<E>
where
    E: Storage + Clock + Metrics,
{
    type Family = mmr::Family;
    type Operation = Operation;

    fn create_test_operations(count: usize, seed: u64, _starting_loc: u64) -> Vec<Self::Operation> {
        let mut hasher = <Hasher as CryptoHasher>::new();
        let mut operations = Vec::new();
        for i in 0..count {
            let key = {
                hasher.update(&i.to_be_bytes());
                hasher.update(&seed.to_be_bytes());
                hasher.finalize()
            };

            let value = {
                hasher.update(&key);
                hasher.update(b"value");
                hasher.finalize()
            };

            operations.push(Operation::Update(Update(key, value)));

            if (i + 1) % 10 == 0 {
                operations.push(Operation::CommitFloor(None, Location::from(i + 1)));
            }
        }

        // Always end with a commit.
        operations.push(Operation::CommitFloor(None, Location::from(count)));
        operations
    }

    async fn add_operations(
        &mut self,
        operations: Vec<Self::Operation>,
    ) -> Result<(), qmdb::Error<mmr::Family>> {
        if operations.last().is_none() || !operations.last().unwrap().is_commit() {
            error!("operations must end with a commit");
            return Ok(());
        }

        let mut batch = self.new_batch();
        for operation in operations {
            match operation {
                Operation::Update(Update(key, value)) => {
                    batch = batch.write(key, Some(value));
                }
                Operation::Delete(key) => {
                    batch = batch.write(key, None);
                }
                Operation::CommitFloor(metadata, _) => {
                    let merkleized = batch.merkleize(self, metadata).await?;
                    self.apply_batch(merkleized).await?;
                    self.commit().await?;
                    batch = self.new_batch();
                }
            }
        }
        Ok(())
    }

    fn current_floor(&self) -> u64 {
        // `current`'s `merkleize` derives the floor internally; the `starting_loc` passed to
        // `create_test_operations` is unused, so any value is safe.
        0
    }

    fn root(&self) -> Key {
        // Return the ops root (not the canonical root) because this is what the
        // sync engine verifies against.
        self.ops_root()
    }

    fn name() -> &'static str {
        "current"
    }
}

impl<E> super::Syncable for Database<E>
where
    E: Storage + Clock + Metrics,
{
    async fn size(&self) -> Location {
        self.bounds().await.end
    }

    async fn sync_boundary(&self) -> Location {
        self.sync_boundary()
    }

    fn historical_proof(
        &self,
        op_count: Location,
        start_loc: Location,
        max_ops: NonZeroU64,
    ) -> impl Future<Output = Result<(Proof<Key>, Vec<Self::Operation>), qmdb::Error<mmr::Family>>> + Send
    {
        // Return ops-level proofs (not grafted proofs) for the sync engine.
        self.ops_historical_proof(op_count, start_loc, max_ops)
    }

    fn pinned_nodes_at(
        &self,
        loc: Location,
    ) -> impl Future<Output = Result<Vec<Key>, qmdb::Error<mmr::Family>>> + Send {
        self.pinned_nodes_at(loc)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::databases::ExampleDatabase;
    use commonware_runtime::deterministic;

    type CurrentDb = Database<deterministic::Context>;

    #[test]
    fn test_create_test_operations() {
        let ops = <CurrentDb as ExampleDatabase>::create_test_operations(5, 12345, 0);
        assert_eq!(ops.len(), 6); // 5 operations + 1 commit

        if let Operation::CommitFloor(_, loc) = &ops[5] {
            assert_eq!(*loc, 5);
        } else {
            panic!("last operation should be a commit");
        }
    }

    #[test]
    fn test_deterministic_operations() {
        let ops1 = <CurrentDb as ExampleDatabase>::create_test_operations(3, 12345, 0);
        let ops2 = <CurrentDb as ExampleDatabase>::create_test_operations(3, 12345, 0);
        assert_eq!(ops1, ops2);

        let ops3 = <CurrentDb as ExampleDatabase>::create_test_operations(3, 54321, 0);
        assert_ne!(ops1, ops3);
    }
}
