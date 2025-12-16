//! Immutable database types and helpers for the sync example.

use crate::{Hasher, Key, Translator, Value};
use commonware_cryptography::{Hasher as CryptoHasher, Sha256};
use commonware_runtime::{Clock, Metrics, Storage};
use commonware_storage::{
    mmr::{Location, Proof},
    qmdb::{
        self,
        immutable::{self, Config},
    },
};
use commonware_utils::{NZUsize, NZU64};
use std::{future::Future, num::NonZeroU64};

/// Database type alias.
pub type Database<E> = immutable::Immutable<E, Key, Value, Hasher, Translator>;

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
        buffer_pool: commonware_runtime::buffer::PoolRef::new(NZUsize!(1024), NZUsize!(10)),
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
        database: &mut Self,
        operations: Vec<Self::Operation>,
    ) -> Result<(), commonware_storage::qmdb::Error> {
        for operation in operations {
            match operation {
                Operation::Set(key, value) => {
                    database.set(key, value).await?;
                }
                Operation::Commit(metadata) => {
                    database.commit(metadata).await?;
                }
            }
        }
        Ok(())
    }

    async fn commit(&mut self) -> Result<(), commonware_storage::qmdb::Error> {
        self.commit(None).await
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
