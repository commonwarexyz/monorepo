//! Current database types and helpers for the sync example.
//!
//! A `current` database extends an `any` database with an activity bitmap that tracks which
//! operations are active (i.e. represent the current state of their key) vs inactive
//! (superseded or deleted). Its canonical root folds the ops root, a grafted MMR root
//! (combining bitmap chunks with ops subtree roots), and an optional partial-chunk digest.
//! See [current] module documentation for more details.
//!
//! For sync, the engine targets the **ops root** (not the canonical root). The operations and
//! proof format are identical to `any` -- the bitmap is reconstructed deterministically from
//! the operations after sync completes. See the
//! [Root structure](commonware_storage::qmdb::current) module documentation for details.
//!
//! This module re-uses the same [`Operation`] type as [`super::any`] since the underlying
//! operations log is the same.

use crate::{Hasher, Key, Translator, Value};
use commonware_codec::FixedSize;
use commonware_cryptography::{sha256, Hasher as CryptoHasher};
use commonware_runtime::{buffer, BufferPooler, Clock, Metrics, Storage};
use commonware_storage::{
    mmr::{Location, Proof},
    qmdb::{
        self,
        any::unordered::{fixed::Operation as FixedOperation, Update},
        current::{self, FixedConfig as Config},
        operation::Committable,
        store::LogStore,
    },
};
use commonware_utils::{NZUsize, NZU16, NZU64};
use std::{future::Future, num::NonZeroU64};
use tracing::error;

/// Bitmap chunk size in bytes. Each chunk covers `N * 8` operations' activity bits.
const CHUNK_SIZE: usize = sha256::Digest::SIZE;

/// Database type alias for the clean (merkleized, durable) state.
pub type Database<E> = current::unordered::fixed::Db<E, Key, Value, Hasher, Translator, CHUNK_SIZE>;

/// Operation type alias. Same as the `any` operation type.
pub type Operation = FixedOperation<Key, Value>;

/// Create a database configuration.
pub fn create_config(context: &impl BufferPooler) -> Config<Translator> {
    Config {
        mmr_journal_partition: "mmr-journal".into(),
        mmr_metadata_partition: "mmr-metadata".into(),
        mmr_items_per_blob: NZU64!(4096),
        mmr_write_buffer: NZUsize!(4096),
        log_journal_partition: "log-journal".into(),
        log_items_per_blob: NZU64!(4096),
        log_write_buffer: NZUsize!(4096),
        grafted_mmr_metadata_partition: "grafted-mmr-metadata".into(),
        translator: Translator::default(),
        thread_pool: None,
        page_cache: buffer::paged::CacheRef::from_pooler(context, NZU16!(2048), NZUsize!(10)),
    }
}

impl<E> super::Syncable for Database<E>
where
    E: Storage + Clock + Metrics,
{
    type Operation = Operation;

    fn create_test_operations(count: usize, seed: u64) -> Vec<Self::Operation> {
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

    async fn add_operations(self, operations: Vec<Self::Operation>) -> Result<Self, qmdb::Error> {
        if operations.last().is_none() || !operations.last().unwrap().is_commit() {
            error!("operations must end with a commit");
            return Ok(self);
        }
        let mut db = self.into_mutable();
        let num_ops = operations.len();

        for (i, operation) in operations.into_iter().enumerate() {
            match operation {
                Operation::Update(Update(key, value)) => {
                    db.write_batch([(key, Some(value))]).await?;
                }
                Operation::Delete(key) => {
                    db.write_batch([(key, None)]).await?;
                }
                Operation::CommitFloor(metadata, _) => {
                    let (durable_db, _) = db.commit(metadata).await?;
                    if i == num_ops - 1 {
                        return Ok(durable_db);
                    }
                    db = durable_db.into_mutable();
                }
            }
        }
        panic!("operations should end with a commit");
    }

    fn root(&self) -> Key {
        // Return the ops root (not the canonical root) because this is what the
        // sync engine verifies against.
        self.ops_root()
    }

    async fn size(&self) -> Location {
        LogStore::bounds(self).await.end
    }

    async fn inactivity_floor(&self) -> Location {
        self.inactivity_floor_loc()
    }

    fn historical_proof(
        &self,
        op_count: Location,
        start_loc: Location,
        max_ops: NonZeroU64,
    ) -> impl Future<Output = Result<(Proof<Key>, Vec<Self::Operation>), qmdb::Error>> + Send {
        // Return ops-level proofs (not grafted proofs) for the sync engine.
        self.ops_historical_proof(op_count, start_loc, max_ops)
    }

    fn name() -> &'static str {
        "current"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::databases::Syncable;
    use commonware_runtime::deterministic;

    type CurrentDb = Database<deterministic::Context>;

    #[test]
    fn test_create_test_operations() {
        let ops = <CurrentDb as Syncable>::create_test_operations(5, 12345);
        assert_eq!(ops.len(), 6); // 5 operations + 1 commit

        if let Operation::CommitFloor(_, loc) = &ops[5] {
            assert_eq!(*loc, 5);
        } else {
            panic!("last operation should be a commit");
        }
    }

    #[test]
    fn test_deterministic_operations() {
        let ops1 = <CurrentDb as Syncable>::create_test_operations(3, 12345);
        let ops2 = <CurrentDb as Syncable>::create_test_operations(3, 12345);
        assert_eq!(ops1, ops2);

        let ops3 = <CurrentDb as Syncable>::create_test_operations(3, 54321);
        assert_ne!(ops1, ops3);
    }
}
