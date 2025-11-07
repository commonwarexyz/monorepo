//! Immutable database types and helpers for the sync example.

use crate::{Hasher, Key, Translator, Value};
use commonware_cryptography::{Hasher as CryptoHasher, Sha256};
use commonware_runtime::{Clock, Metrics, Storage};
use commonware_storage::{
    adb::{
        self,
        immutable::{self, Config},
        operation,
    },
    mmr::{
        mem::{Clean, Dirty},
        Location, Proof, StandardHasher as Standard,
    },
};
use commonware_utils::{NZUsize, NZU64};
use std::{future::Future, num::NonZeroU64};

/// Database enum that can be either Clean or Dirty.
pub enum Database<E>
where
    E: Storage + Clock + Metrics,
{
    Clean(
        immutable::Immutable<
            E,
            Key,
            Value,
            Hasher,
            Translator,
            Clean<<Hasher as CryptoHasher>::Digest>,
        >,
    ),
    Dirty(immutable::Immutable<E, Key, Value, Hasher, Translator, Dirty>),
}

/// Operation type alias.
pub type Operation = operation::variable::Operation<Key, Value>;

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

impl<E: Storage + Clock + Metrics> Database<E> {
    /// Initialize a new database from the given context and config.
    pub async fn init(
        context: E,
        config: Config<Translator, ()>,
    ) -> Result<Self, commonware_storage::adb::Error> {
        let db = immutable::Immutable::init(context, config).await?;
        Ok(Database::Clean(db))
    }

    /// Get the root digest (only available for Clean state).
    pub fn root(&self) -> Key {
        match self {
            Database::Clean(db) => db.root(),
            Database::Dirty(_) => {
                panic!("root() requires Clean state");
            }
        }
    }

    /// Close the database.
    pub async fn close(self) -> Result<(), commonware_storage::adb::Error> {
        match self {
            Database::Clean(db) => db.close().await,
            Database::Dirty(db) => db.merkleize().close().await,
        }
    }
}

// Note: We can't implement adb::sync::Database here because it's pub(crate) in the storage crate.
// Instead, we use Immutable directly for sync operations and convert to/from Database enum as needed.

impl<E> super::Syncable for Database<E>
where
    E: Storage + Clock + Metrics,
{
    type Operation = Operation;

    fn create_test_operations(count: usize, seed: u64) -> Vec<Self::Operation> {
        create_test_operations(count, seed)
    }

    async fn add_operations(
        database: Self,
        operations: Vec<Self::Operation>,
    ) -> Result<Self, commonware_storage::adb::Error> {
        // Convert to Dirty state
        let mut dirty_db = match database {
            Database::Clean(db) => db.into_dirty(),
            Database::Dirty(db) => db,
        };

        // Apply all operations
        for operation in operations {
            match operation {
                Operation::Set(key, value) => {
                    dirty_db.set(key, value).await?;
                }
                Operation::Commit(metadata) => {
                    dirty_db.commit(metadata).await?;
                }
                _ => {}
            }
        }

        // Convert back to Clean after operations
        Ok(Database::Clean(dirty_db.merkleize()))
    }

    async fn commit(self) -> Result<Self, commonware_storage::adb::Error> {
        // Convert to Dirty, commit, then convert back to Clean
        let mut dirty_db = match self {
            Database::Clean(db) => db.into_dirty(),
            Database::Dirty(db) => db,
        };
        dirty_db.commit(None).await?;
        Ok(Database::Clean(dirty_db.merkleize()))
    }

    fn root(&self, _hasher: &mut Standard<commonware_cryptography::Sha256>) -> Key {
        Database::root(self)
    }

    fn op_count(&self) -> Location {
        match self {
            Database::Clean(db) => db.op_count(),
            Database::Dirty(db) => db.op_count(),
        }
    }

    fn lower_bound(&self) -> Location {
        match self {
            Database::Clean(db) => db
                .oldest_retained_loc()
                .unwrap_or(Location::new(0).unwrap()),
            Database::Dirty(db) => db
                .oldest_retained_loc()
                .unwrap_or(Location::new(0).unwrap()),
        }
    }

    #[allow(clippy::manual_async_fn)]
    fn historical_proof(
        &self,
        op_count: Location,
        start_loc: Location,
        max_ops: NonZeroU64,
    ) -> impl Future<Output = Result<(Proof<Key>, Vec<Self::Operation>), adb::Error>> + Send {
        // historical_proof is only available on Clean state
        // Since we only have &self, we can't convert Dirty to Clean
        // Use Box::pin to unify the types from both match arms
        #[allow(clippy::redundant_async_block)]
        async move {
            match self {
                Database::Clean(db) => db.historical_proof(op_count, start_loc, max_ops).await,
                Database::Dirty(_) => {
                    // For Dirty state, we can't convert without ownership
                    // Return an error indicating the database needs to be Clean
                    Err(adb::Error::Mmr(
                        commonware_storage::mmr::Error::RangeOutOfBounds(start_loc),
                    ))
                }
            }
        }
    }

    fn name() -> &'static str {
        "immutable"
    }
}
