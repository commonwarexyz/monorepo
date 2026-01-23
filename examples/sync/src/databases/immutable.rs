//! Immutable database types and helpers for the sync example.

use crate::{Hasher, Key, Translator, Value};
use commonware_cryptography::{Hasher as CryptoHasher, Sha256};
use commonware_runtime::{Clock, Metrics, Storage};
use commonware_storage::{
    mmr::{Location, Proof},
    qmdb::{
        self,
        immutable::{self, Config},
        Durable, Merkleized,
    },
};
use commonware_utils::{NZUsize, NZU16, NZU64};
use std::{future::Future, num::NonZeroU64};
use tracing::error;

/// Database type alias for the clean (merkleized, durable) state.
pub type Database<E> =
    immutable::Immutable<E, Key, Value, Hasher, Translator, Merkleized<Hasher>, Durable>;

/// Operation type alias.
pub type Operation = immutable::Operation<Key, Value>;

/// Create a database configuration with appropriate partitioning for Immutable.
pub fn create_config() -> Config<Translator, ()> {
    Config {
        mmr_journal_partition: "mmr_journal".into(),
        mmr_metadata_partition: "mmr_metadata".into(),
        mmr_items_per_blob: NZU64!(4096),
        mmr_write_buffer: NZUsize!(1024),
        log_partition: "log".into(),
        log_items_per_section: NZU64!(512),
        log_compression: None,
        log_codec_config: (),
        log_write_buffer: NZUsize!(1024),
        translator: commonware_storage::translator::EightCap,
        thread_pool: None,
        buffer_pool: commonware_runtime::buffer::PoolRef::new(NZU16!(1024), NZUsize!(10)),
    }
}

/// Create deterministic test operations for demonstration purposes.
/// Generates Set operations and periodic Commit operations.
pub fn create_test_operations(count: usize, seed: u64) -> Vec<Operation> {
    let mut operations = Vec::new();
    let mut hasher = <Hasher as CryptoHasher>::new();

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

        operations.push(Operation::Set(key, value));

        if (i + 1) % 10 == 0 {
            operations.push(Operation::Commit(None));
        }
    }

    // Always end with a commit
    operations.push(Operation::Commit(Some(Sha256::fill(1))));
    operations
}

impl<E> super::Syncable for Database<E>
where
    E: Storage + Clock + Metrics,
{
    type Operation = Operation;

    fn create_test_operations(count: usize, seed: u64) -> Vec<Self::Operation> {
        create_test_operations(count, seed)
    }

    async fn add_operations(
        self,
        operations: Vec<Self::Operation>,
    ) -> Result<Self, commonware_storage::qmdb::Error> {
        if operations.last().is_none() || !operations.last().unwrap().is_commit() {
            // Ignore bad inputs rather than return errors.
            error!("operations must end with a commit");
            return Ok(self);
        }
        let mut db = self.into_mutable();
        let num_ops = operations.len();

        for (i, operation) in operations.into_iter().enumerate() {
            match operation {
                Operation::Set(key, value) => {
                    db.set(key, value).await?;
                }
                Operation::Commit(metadata) => {
                    let (durable_db, _) = db.commit(metadata).await?;
                    if i == num_ops - 1 {
                        // Last operation - return the clean database
                        return Ok(durable_db.into_merkleized());
                    }
                    // Not the last operation - continue in mutable state
                    db = durable_db.into_mutable();
                }
            }
        }
        unreachable!("operations must end with a commit");
    }

    fn root(&self) -> Key {
        self.root()
    }

    fn op_count(&self) -> Location {
        self.op_count()
    }

    fn lower_bound(&self) -> Location {
        self.oldest_retained_loc()
    }

    fn historical_proof(
        &self,
        op_count: Location,
        start_loc: Location,
        max_ops: NonZeroU64,
    ) -> impl Future<Output = Result<(Proof<Key>, Vec<Self::Operation>), qmdb::Error>> + Send {
        self.historical_proof(op_count, start_loc, max_ops)
    }

    fn name() -> &'static str {
        "immutable"
    }
}
