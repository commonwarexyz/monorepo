//! Immutable database types and helpers for the sync example.

use crate::{Hasher, Key, Translator, Value};
use commonware_cryptography::{Hasher as CryptoHasher, Sha256};
use commonware_runtime::{BufferPooler, Clock, Metrics, Storage};
use commonware_storage::{
    journal::contiguous::fixed::Config as FConfig,
    merkle::{
        full::Config as MmrConfig,
        mmr::{self, Location, Proof},
    },
    qmdb::{
        self,
        immutable::{fixed, Config},
        sync::compact,
    },
};
use commonware_utils::{NZUsize, NZU16, NZU64};
use std::{future::Future, num::NonZeroU64};
use tracing::error;

/// Database type alias.
pub type Database<E> = fixed::Db<mmr::Family, E, Key, Value, Hasher, Translator>;

/// Operation type alias.
pub type Operation = fixed::Operation<mmr::Family, Key, Value>;

/// Create a database configuration with appropriate partitioning for Immutable.
pub fn create_config(context: &impl BufferPooler) -> Config<Translator, FConfig> {
    let page_cache = commonware_runtime::buffer::paged::CacheRef::from_pooler(
        context,
        NZU16!(2048),
        NZUsize!(10),
    );
    Config {
        merkle_config: MmrConfig {
            journal_partition: "mmr-journal".into(),
            metadata_partition: "mmr-metadata".into(),
            items_per_blob: NZU64!(4096),
            write_buffer: NZUsize!(4096),
            thread_pool: None,
            page_cache: page_cache.clone(),
        },
        log: FConfig {
            partition: "log".into(),
            items_per_blob: NZU64!(4096),
            write_buffer: NZUsize!(4096),
            page_cache,
        },
        translator: commonware_storage::translator::EightCap,
    }
}

/// Create deterministic test operations for demonstration purposes.
///
/// Generates Set operations and periodic Commit operations. Every commit in the stream
/// carries `starting_loc` as its inactivity floor. Pass `0` for a fresh db; for growth, pass
/// the live db's [`super::ExampleDatabase::current_floor`] so floors stay monotonic.
pub fn create_test_operations(count: usize, seed: u64, starting_loc: u64) -> Vec<Operation> {
    let mut operations = Vec::new();
    let mut hasher = <Hasher as CryptoHasher>::new();
    let floor = Location::new(starting_loc);

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
            operations.push(Operation::Commit(None, floor));
        }
    }

    // Always end with a commit
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
    ) -> Result<(), commonware_storage::qmdb::Error<mmr::Family>> {
        if operations.last().is_none() || !operations.last().unwrap().is_commit() {
            // Ignore bad inputs rather than return errors.
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
                    self.apply_batch(merkleized).await?;
                    self.commit().await?;
                    batch = self.new_batch();
                }
            }
        }
        Ok(())
    }

    fn current_floor(&self) -> u64 {
        *self.inactivity_floor_loc()
    }

    fn root(&self) -> Key {
        self.root()
    }

    fn name() -> &'static str {
        "immutable"
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
        self.historical_proof(op_count, start_loc, max_ops)
    }

    fn pinned_nodes_at(
        &self,
        loc: Location,
    ) -> impl Future<Output = Result<Vec<Key>, qmdb::Error<mmr::Family>>> + Send {
        self.pinned_nodes_at(loc)
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
