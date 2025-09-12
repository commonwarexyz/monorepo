//! Any database types and helpers for the sync example.

use crate::{Hasher, Key, Translator, Value};
use commonware_cryptography::Hasher as CryptoHasher;
use commonware_runtime::{buffer, Clock, Metrics, Storage};
use commonware_storage::{
    adb::{self, any::fixed},
    mmr::{Proof, StandardHasher as Standard},
    store::operation,
};
use commonware_utils::{NZUsize, NZU64};
use std::{future::Future, num::NonZeroU64};

/// Database type alias.
pub type Database<E> = fixed::Any<E, Key, Value, Hasher, Translator>;

/// Data type alias.
pub type Data = operation::Fixed<Key, Value>;

/// Create a database configuration for use in tests.
pub fn create_config() -> fixed::Config<Translator> {
    fixed::Config {
        mmr_journal_partition: "mmr_journal".into(),
        mmr_metadata_partition: "mmr_metadata".into(),
        mmr_items_per_blob: NZU64!(4096),
        mmr_write_buffer: NZUsize!(1024),
        log_journal_partition: "log_journal".into(),
        log_items_per_blob: NZU64!(4096),
        log_write_buffer: NZUsize!(1024),
        translator: Translator::default(),
        thread_pool: None,
        buffer_pool: buffer::PoolRef::new(NZUsize!(1024), NZUsize!(10)),
    }
}

impl<E> crate::databases::Syncable for Database<E>
where
    E: Storage + Clock + Metrics,
{
    type Data = Data;

    fn create_test_data(count: usize, seed: u64) -> Vec<Self::Data> {
        let mut hasher = <Hasher as CryptoHasher>::new();
        let mut data = Vec::new();
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

            data.push(Data::Update(key, value));

            if (i + 1) % 10 == 0 {
                data.push(Data::CommitFloor(i as u64 + 1));
            }
        }

        // Always end with a commit
        data.push(Data::CommitFloor(count as u64));
        data
    }

    async fn add_data(
        database: &mut Self,
        data: Vec<Self::Data>,
    ) -> Result<(), commonware_storage::adb::Error> {
        for item in data {
            match item {
                Data::Update(key, value) => {
                    database.update(key, value).await?;
                }
                Data::Delete(key) => {
                    database.delete(key).await?;
                }
                Data::CommitFloor(_) => {
                    database.commit().await?;
                }
            }
        }
        Ok(())
    }

    async fn commit(&mut self) -> Result<(), commonware_storage::adb::Error> {
        self.commit().await
    }

    fn root(&self, hasher: &mut Standard<commonware_cryptography::Sha256>) -> Key {
        self.root(hasher)
    }

    fn size(&self) -> u64 {
        self.op_count()
    }

    fn lower_bound(&self) -> u64 {
        self.inactivity_floor_loc()
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
        "any"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::databases::Syncable;
    use commonware_runtime::deterministic;

    type AnyDb = Database<deterministic::Context>;

    #[test]
    fn test_create_test_data() {
        let data = <AnyDb as Syncable>::create_test_data(5, 12345);
        assert_eq!(data.len(), 6); // 5 data items + 1 commit

        if let Data::CommitFloor(loc) = &data[5] {
            assert_eq!(*loc, 5);
        } else {
            panic!("Last data item should be a commit");
        }
    }

    #[test]
    fn test_deterministic_data() {
        // Data should be deterministic based on seed
        let data1 = <AnyDb as Syncable>::create_test_data(3, 12345);
        let data2 = <AnyDb as Syncable>::create_test_data(3, 12345);
        assert_eq!(data1, data2);

        // Different seeds should produce different data
        let data3 = <AnyDb as Syncable>::create_test_data(3, 54321);
        assert_ne!(data1, data3);
    }
}
