//! Keyless database types and helpers for the sync example.
//!
//! A `keyless` database is append-only: operations are stored by location rather than by key.
//! It supports `Append(value)` and `Commit(metadata, floor)` operations. For sync, the engine
//! targets the Merkle root over all operations, and the client reconstructs the same state by
//! replaying the fetched operations.

use crate::{Hasher, Key, Value};
use commonware_cryptography::{Hasher as CryptoHasher, Sha256};
use commonware_parallel::Sequential;
use commonware_runtime::{buffer, BufferPooler, Clock, Metrics, Storage};
use commonware_storage::{
    journal::contiguous::fixed::Config as FConfig,
    merkle::{
        full::Config as MmrConfig,
        mmr::{self, Location, Proof},
    },
    qmdb::{
        self,
        keyless::{self, fixed},
        operation::Committable,
        sync::compact,
    },
};
use commonware_utils::{NZUsize, NZU16, NZU64};
use std::num::NonZeroU64;
use tracing::error;

/// Database type alias.
pub type Database<E> = fixed::Db<mmr::Family, E, Value, Hasher, Sequential>;

/// Operation type alias.
pub type Operation = fixed::Operation<mmr::Family, Value>;

/// Create a database configuration for the keyless variant.
pub fn create_config(context: &impl BufferPooler) -> fixed::Config<Sequential> {
    let page_cache = buffer::paged::CacheRef::from_pooler(context, NZU16!(2048), NZUsize!(10));
    keyless::Config {
        merkle: MmrConfig {
            journal_partition: "mmr-journal".into(),
            metadata_partition: "mmr-metadata".into(),
            items_per_blob: NZU64!(4096),
            write_buffer: NZUsize!(4096),
            strategy: Sequential,
            page_cache: page_cache.clone(),
        },
        log: FConfig {
            partition: "log-journal".into(),
            items_per_blob: NZU64!(4096),
            write_buffer: NZUsize!(4096),
            page_cache,
        },
    }
}

/// Create deterministic test operations for demonstration purposes.
///
/// Generates Append operations and periodic Commit operations. Every commit in the stream
/// carries `starting_loc` as its inactivity floor. Pass `0` for a fresh db; for growth, pass
/// the live db's [`super::ExampleDatabase::current_floor`] so floors stay monotonic.
pub fn create_test_operations(count: usize, seed: u64, starting_loc: u64) -> Vec<Operation> {
    let mut operations = Vec::new();
    let mut hasher = <Hasher as CryptoHasher>::new();
    let floor = Location::new(starting_loc);

    for i in 0..count {
        let value = {
            hasher.update(&i.to_be_bytes());
            hasher.update(&seed.to_be_bytes());
            hasher.finalize()
        };

        operations.push(Operation::Append(value));

        if (i + 1) % 10 == 0 {
            operations.push(Operation::Commit(None, floor));
        }
    }

    // Always end with a commit.
    operations.push(Operation::Commit(Some(Sha256::fill(1)), floor));
    operations
}

impl<E> super::ExampleDatabase for Database<E>
where
    E: Storage + Clock + Metrics,
{
    type Family = mmr::Family;
    type Operation = Operation;

    fn create_test_operations(count: usize, seed: u64, starting_loc: u64) -> Vec<Self::Operation> {
        create_test_operations(count, seed, starting_loc)
    }

    async fn add_operations(
        &mut self,
        operations: Vec<Self::Operation>,
    ) -> Result<(), qmdb::Error<mmr::Family>> {
        if operations.last().is_none() || !operations.last().unwrap().is_commit() {
            // Ignore bad inputs rather than return errors.
            error!("operations must end with a commit");
            return Ok(());
        }

        let mut batch = self.new_batch();
        for operation in operations {
            match operation {
                Operation::Append(value) => {
                    batch = batch.append(value);
                }
                Operation::Commit(metadata, floor) => {
                    let merkleized = batch.merkleize(self, metadata, floor);
                    self.apply_batch(merkleized).await?;
                    self.commit().await?;
                    batch = self.new_batch();
                }
            }
        }
        Ok(())
    }

    fn current_floor(&self) -> u64 {
        *self.last_commit_loc()
    }

    fn root(&self) -> Key {
        self.root()
    }

    fn name() -> &'static str {
        "keyless"
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

    async fn historical_proof(
        &self,
        op_count: Location,
        start_loc: Location,
        max_ops: NonZeroU64,
    ) -> Result<(Proof<Key>, Vec<Self::Operation>), qmdb::Error<mmr::Family>> {
        self.historical_proof(op_count, start_loc, max_ops).await
    }

    async fn pinned_nodes_at(&self, loc: Location) -> Result<Vec<Key>, qmdb::Error<mmr::Family>> {
        self.pinned_nodes_at(loc).await
    }
}

impl<E> super::CompactSyncable for Database<E>
where
    E: Storage + Clock + Metrics,
{
    async fn current_target(&self) -> compact::Target<Self::Family, Key> {
        compact::Target {
            root: self.root(),
            leaf_count: self.bounds().await.end,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::databases::ExampleDatabase;
    use commonware_runtime::deterministic;

    type KeylessDb = Database<deterministic::Context>;

    #[test]
    fn test_create_test_operations() {
        let ops = <KeylessDb as ExampleDatabase>::create_test_operations(5, 12345, 0);
        assert_eq!(ops.len(), 6); // 5 operations + 1 commit

        if let Operation::Commit(Some(_), _) = &ops[5] {
            // ok
        } else {
            panic!("last operation should be a commit with metadata");
        }
    }

    #[test]
    fn test_deterministic_operations() {
        // Operations should be deterministic based on seed
        let ops1 = <KeylessDb as ExampleDatabase>::create_test_operations(3, 12345, 0);
        let ops2 = <KeylessDb as ExampleDatabase>::create_test_operations(3, 12345, 0);
        assert_eq!(ops1, ops2);

        // Different seeds should produce different operations
        let ops3 = <KeylessDb as ExampleDatabase>::create_test_operations(3, 54321, 0);
        assert_ne!(ops1, ops3);
    }
}
