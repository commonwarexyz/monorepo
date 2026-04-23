//! Compact keyless database types and helpers for compact sync demonstration.

use crate::{Hasher, Key, Value};
use commonware_runtime::{BufferPooler, Clock, Metrics, Storage};
use commonware_storage::{
    merkle::{
        compact::Config as MerkleConfig,
        mmr::{self},
    },
    qmdb::{
        self,
        keyless::fixed::{self, CompactConfig},
        sync::compact,
    },
};
use tracing::error;

/// Database type alias.
pub type Database<E> = fixed::CompactDb<mmr::Family, E, Value, Hasher>;

/// Operation type alias.
pub type Operation = fixed::Operation<mmr::Family, Value>;

/// Create a database configuration for the compact keyless variant.
pub fn create_config(_context: &impl BufferPooler) -> CompactConfig {
    CompactConfig {
        merkle: MerkleConfig {
            partition: "compact-keyless".into(),
            thread_pool: None,
        },
        commit_codec_config: (),
    }
}

impl<E> super::ExampleDatabase for Database<E>
where
    E: Storage + Clock + Metrics,
{
    type Family = mmr::Family;
    type Operation = Operation;

    fn create_test_operations(count: usize, seed: u64) -> Vec<Self::Operation> {
        // Keep the compact example's operation stream aligned with the full variant.
        super::keyless::create_test_operations(count, seed)
    }

    async fn add_operations(
        &mut self,
        operations: Vec<Self::Operation>,
    ) -> Result<(), qmdb::Error<mmr::Family>> {
        let Some(last) = operations.last() else {
            error!("operations must end with a commit");
            return Ok(());
        };
        if !matches!(last, Operation::Commit(..)) {
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
                    self.apply_batch(merkleized)?;
                    self.commit().await?;
                    batch = self.new_batch();
                }
            }
        }
        Ok(())
    }

    fn root(&self) -> Key {
        Self::root(self)
    }

    fn name() -> &'static str {
        "keyless-compact"
    }
}

impl<E> super::CompactSyncable for Database<E>
where
    E: Storage + Clock + Metrics,
{
    async fn current_target(&self) -> compact::Target<Self::Family, Key> {
        Self::current_target(self)
    }
}
