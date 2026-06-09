//! Compact immutable database types and helpers for compact sync demonstration.

use crate::{Hasher, Key, Value};
use commonware_parallel::Sequential;
use commonware_runtime::{buffer::paged::CacheRef, BufferPooler, Clock, Metrics, Storage};
use commonware_storage::{
    journal::contiguous::variable,
    merkle::mmr,
    qmdb::{
        self,
        immutable::fixed::{self, CompactConfig},
        sync::compact,
    },
};
use commonware_utils::{NZUsize, NZU16, NZU64};
use tracing::error;

/// Database type alias.
pub type Database<E> = fixed::CompactDb<mmr::Family, E, Key, Value, Hasher, Sequential>;

/// Operation type alias.
pub type Operation = fixed::Operation<mmr::Family, Key, Value>;

/// Create a database configuration for the compact immutable variant.
pub fn create_config(context: &impl BufferPooler) -> CompactConfig<Sequential> {
    CompactConfig {
        strategy: Sequential,
        witness: variable::Config {
            partition: "compact-immutable-witness".into(),
            items_per_section: NZU64!(4096),
            compression: None,
            codec_config: (),
            page_cache: CacheRef::from_pooler(context, NZU16!(1024), NZUsize!(64)),
            write_buffer: NZUsize!(1024),
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

    fn create_test_operations(count: usize, seed: u64, starting_loc: u64) -> Vec<Self::Operation> {
        super::immutable::create_test_operations(count, seed, starting_loc)
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
                Operation::Set(key, value) => {
                    batch = batch.set(key, value);
                }
                Operation::Commit(metadata, floor) => {
                    let merkleized = batch.merkleize(self, metadata, floor);
                    self.apply_batch(merkleized)?;
                    self.sync().await?;
                    batch = self.new_batch();
                }
            }
        }
        Ok(())
    }

    fn current_floor(&self) -> u64 {
        *Self::inactivity_floor_loc(self)
    }

    fn root(&self) -> Key {
        Self::root(self)
    }

    fn name() -> &'static str {
        "compact immutable"
    }
}

impl<E> super::CompactSyncable for Database<E>
where
    E: Storage + Clock + Metrics,
{
    async fn current_target(&self) -> compact::Target<Self::Family, Key> {
        Self::target(self)
    }
}
