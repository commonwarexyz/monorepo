//! Immutable database types and helpers for the sync example.

use crate::{Hasher, Key, Translator, Value};
use commonware_cryptography::{Hasher as CryptoHasher, Sha256};
use commonware_runtime::{Clock, Metrics, Storage};
use commonware_storage::{
    adb::{
        self,
        immutable::{self, Config},
    },
    mmr::{hasher::Standard, verification::Proof},
    store::operation,
};
use commonware_utils::{NZUsize, NZU64};
use std::{future::Future, num::NonZeroU64};

/// Database type alias.
pub type Database<E> = immutable::Immutable<E, Key, Value, Hasher, Translator>;

/// Data type alias.
pub type Data = operation::Variable<Key, Value>;

/// Create a database configuration with appropriate partitioning for Immutable.
pub fn create_config() -> Config<Translator, ()> {
    Config {
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
        translator: commonware_storage::translator::EightCap,
        thread_pool: None,
        buffer_pool: commonware_runtime::buffer::PoolRef::new(NZUsize!(1024), NZUsize!(10)),
    }
}

/// Create deterministic test data for demonstration purposes.
/// Generates Set data and periodic Commit data.
pub fn create_test_data(count: usize, seed: u64) -> Vec<Data> {
    let mut data = Vec::new();
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

        data.push(Data::Set(key, value));

        if (i + 1) % 10 == 0 {
            data.push(Data::Commit(None));
        }
    }

    // Always end with a commit
    data.push(Data::Commit(Some(Sha256::fill(1))));
    data
}

impl<E> super::Syncable for Database<E>
where
    E: Storage + Clock + Metrics,
{
    type Data = Data;

    fn create_test_data(count: usize, seed: u64) -> Vec<Self::Data> {
        create_test_data(count, seed)
    }

    async fn add_data(
        database: &mut Self,
        data: Vec<Self::Data>,
    ) -> Result<(), commonware_storage::adb::Error> {
        for item in data {
            match item {
                Data::Set(key, value) => {
                    database.set(key, value).await?;
                }
                Data::Commit(metadata) => {
                    database.commit(metadata).await?;
                }
                _ => {}
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

    fn size(&self) -> u64 {
        self.op_count()
    }

    fn lower_bound(&self) -> u64 {
        self.oldest_retained_loc().unwrap_or(0)
    }

    fn historical_proof(
        &self,
        size: u64,
        start_loc: u64,
        max_data: NonZeroU64,
    ) -> impl Future<Output = Result<(Proof<Key>, Vec<Self::Data>), adb::Error>> + Send {
        self.historical_proof(size, start_loc, max_data)
    }

    fn name() -> &'static str {
        "immutable"
    }
}
