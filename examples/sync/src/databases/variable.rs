//! Variable-size Any database types and helpers for the sync example.

use crate::{Hasher, Key, Translator, Value};
use commonware_cryptography::Hasher as CryptoHasher;
use commonware_runtime::{buffer, Clock, Metrics, Storage};
use commonware_storage::{
    adb::{self, any::variable},
    mmr::{hasher::Standard, Proof},
    store::operation,
};
use commonware_utils::{NZUsize, NZU64};
use std::{future::Future, num::NonZeroU64};

/// Variable-size Any database type alias.
pub type Database<E> = variable::Any<E, Key, Value, Hasher, Translator>;

/// Variable operation type alias.
pub type Operation = operation::Variable<Key, Value>;

/// Create a database configuration for use in tests.
pub fn create_config() -> variable::Config<Translator, ()> {
    variable::Config {
        mmr_journal_partition: "mmr_journal".into(),
        mmr_metadata_partition: "mmr_metadata".into(),
        mmr_items_per_blob: NZU64!(4096),
        mmr_write_buffer: NZUsize!(1024),
        log_journal_partition: "log_journal".into(),
        log_items_per_section: NZU64!(512),
        log_compression: None,
        log_codec_config: (),
        log_write_buffer: NZUsize!(1024),
        locations_journal_partition: "locations_journal".into(),
        locations_items_per_blob: NZU64!(4096),
        metadata_partition: "metadata".into(),
        translator: Translator::default(),
        thread_pool: None,
        buffer_pool: buffer::PoolRef::new(NZUsize!(1024), NZUsize!(10)),
    }
}

impl<E> crate::databases::Syncable for Database<E>
where
    E: Storage + Clock + Metrics,
{
    type Operation = Operation;

    // Only returns Update and Commit operations
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

            operations.push(Operation::Update(key, value));

            if (i + 1) % 10 == 0 {
                operations.push(Operation::Commit(None));
            }
        }

        // Always end with a commit
        operations.push(Operation::Commit(None));
        operations
    }

    // Expects only Update and Commit operations
    async fn add_operations(
        database: &mut Self,
        operations: Vec<Self::Operation>,
    ) -> Result<(), commonware_storage::adb::Error> {
        for operation in operations {
            match operation {
                Operation::Update(key, value) => {
                    database.update(key, value).await?;
                }
                Operation::Commit(metadata) => {
                    database.commit(metadata).await?;
                }
                _ => {
                    panic!("invalid operation. expected Update or Commit, got {operation:?}");
                }
            }
        }
        Ok(())
    }

    async fn commit(&mut self) -> Result<(), commonware_storage::adb::Error> {
        self.commit(None).await
    }

    fn root(&self, hasher: &mut Standard<commonware_cryptography::Sha256>) -> Key {
        self.root(hasher)
    }

    fn op_count(&self) -> u64 {
        self.op_count()
    }

    fn lower_bound_ops(&self) -> u64 {
        self.oldest_retained_loc().unwrap_or(0)
    }

    fn historical_proof(
        &self,
        size: u64,
        start_loc: u64,
        max_ops: NonZeroU64,
    ) -> impl Future<Output = Result<(Proof<Key>, Vec<Self::Operation>), adb::Error>> + Send {
        self.historical_proof(size, start_loc, max_ops)
    }

    fn name() -> &'static str {
        "any::variable"
    }
}
