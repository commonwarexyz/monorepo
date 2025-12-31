//! Test utilities for batch operations on qmdb databases.

#[cfg(test)]
pub mod tests {
    use crate::{
        kv::{self, Batchable},
        qmdb::Error,
        Persistable,
    };
    use commonware_codec::Codec;
    use commonware_cryptography::{blake3, sha256};
    use commonware_runtime::{
        deterministic::{self, Context},
        Runner as _,
    };
    use commonware_utils::Array;
    use core::{fmt::Debug, future::Future};
    use rand::{rngs::StdRng, Rng, SeedableRng};
    use std::collections::HashSet;

    pub trait TestKey: Array {
        fn from_seed(seed: u8) -> Self;
    }

    pub trait TestValue: Codec + Clone + PartialEq + Debug {
        fn from_seed(seed: u8) -> Self;
    }

    /// Run the batch test suite against a database factory within a deterministic executor twice,
    /// and test the auditor output for equality.
    pub fn test_batch<D, F, Fut>(mut new_db: F)
    where
        F: FnMut(Context) -> Fut + Clone,
        Fut: Future<Output = D>,
        D: Batchable + Persistable<Error = Error>,
        D::Key: TestKey,
        D::Value: TestValue,
    {
        let executor = deterministic::Runner::default();
        let mut new_db_clone = new_db.clone();
        let state1 = executor.start(|context| async move {
            let ctx = context.clone();
            run_batch_tests::<D, _, Fut>(&mut || new_db_clone(ctx.clone()))
                .await
                .unwrap();
            ctx.auditor().state()
        });

        let executor = deterministic::Runner::default();
        let state2 = executor.start(|context| async move {
            let ctx = context.clone();
            run_batch_tests::<D, _, Fut>(&mut || new_db(ctx.clone()))
                .await
                .unwrap();
            ctx.auditor().state()
        });

        assert_eq!(state1, state2);
    }

    /// Run the shared batch test suite against a database factory.
    pub async fn run_batch_tests<D, F, Fut>(new_db: &mut F) -> Result<(), Error>
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = D>,
        D: Batchable + Persistable<Error = Error>,
        D::Key: TestKey,
        D::Value: TestValue,
    {
        test_overlay_reads(new_db).await?;
        test_create(new_db).await?;
        test_delete(new_db).await?;
        test_delete_unchecked(new_db).await?;
        test_write_batch_from_to_empty(new_db).await?;
        test_write_batch(new_db).await?;
        test_update_delete_update(new_db).await?;
        Ok(())
    }

    async fn test_overlay_reads<D, F, Fut>(new_db: &mut F) -> Result<(), Error>
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = D>,
        D: Batchable + Persistable<Error = Error>,
        D::Key: TestKey,
        D::Value: TestValue,
    {
        let mut db = new_db().await;
        let key = D::Key::from_seed(1);
        db.update(key.clone(), D::Value::from_seed(1)).await?;

        let mut batch = db.start_batch();
        assert_eq!(batch.get(&key).await?, Some(D::Value::from_seed(1)));

        batch.update(key.clone(), D::Value::from_seed(9)).await?;
        assert_eq!(batch.get(&key).await?, Some(D::Value::from_seed(9)));

        db.destroy().await?;
        Ok(())
    }

    async fn test_create<D, F, Fut>(new_db: &mut F) -> Result<(), Error>
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = D>,
        D: Batchable + Persistable<Error = Error>,
        D::Key: TestKey,
        D::Value: TestValue,
    {
        let mut db = new_db().await;
        let mut batch = db.start_batch();
        let key = D::Key::from_seed(2);
        assert!(batch.create(key.clone(), D::Value::from_seed(1)).await?);
        assert!(!batch.create(key.clone(), D::Value::from_seed(2)).await?);

        batch.delete_unchecked(key.clone()).await?;
        assert!(batch.create(key.clone(), D::Value::from_seed(3)).await?);
        assert_eq!(batch.get(&key).await?, Some(D::Value::from_seed(3)));

        let existing = D::Key::from_seed(3);
        db.update(existing.clone(), D::Value::from_seed(4)).await?;
        let mut batch = db.start_batch();
        assert!(
            !batch
                .create(existing.clone(), D::Value::from_seed(5))
                .await?
        );

        db.destroy().await?;
        Ok(())
    }

    async fn test_delete<D, F, Fut>(new_db: &mut F) -> Result<(), Error>
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = D>,
        D: Batchable + Persistable<Error = Error>,
        D::Key: TestKey,
        D::Value: TestValue,
    {
        let mut db = new_db().await;
        let base_key = D::Key::from_seed(4);
        db.update(base_key.clone(), D::Value::from_seed(10)).await?;
        let mut batch = db.start_batch();
        assert!(batch.delete(base_key.clone()).await?);
        assert_eq!(batch.get(&base_key).await?, None);
        assert!(!batch.delete(base_key.clone()).await?);

        let mut batch = db.start_batch();
        let overlay_key = D::Key::from_seed(5);
        batch
            .update(overlay_key.clone(), D::Value::from_seed(11))
            .await?;
        assert!(batch.delete(overlay_key.clone()).await?);
        assert_eq!(batch.get(&overlay_key).await?, None);
        assert!(!batch.delete(overlay_key).await?);

        db.destroy().await?;
        Ok(())
    }

    async fn test_delete_unchecked<D, F, Fut>(new_db: &mut F) -> Result<(), Error>
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = D>,
        D: Batchable + Persistable<Error = Error>,
        D::Key: TestKey,
        D::Value: TestValue,
    {
        let mut db = new_db().await;
        let key = D::Key::from_seed(6);

        let mut batch = db.start_batch();
        batch.update(key.clone(), D::Value::from_seed(12)).await?;
        batch.delete_unchecked(key.clone()).await?;
        assert_eq!(batch.get(&key).await?, None);

        db.update(key.clone(), D::Value::from_seed(13)).await?;
        let mut batch = db.start_batch();
        batch.delete_unchecked(key.clone()).await?;
        assert_eq!(batch.get(&key).await?, None);

        db.destroy().await?;
        Ok(())
    }

    /// Create an empty db, write a small # of keys, then delete half, then recreate those that were
    /// deleted. Also includes a delete_unchecked of an inactive key.
    async fn test_update_delete_update<D, F, Fut>(new_db: &mut F) -> Result<(), Error>
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = D>,
        D: Batchable + Persistable<Error = Error>,
        D::Key: TestKey,
        D::Value: TestValue,
    {
        let mut db = new_db().await;
        // Create 100 keys and commit them.
        for i in 0..100 {
            assert!(
                db.create(D::Key::from_seed(i), D::Value::from_seed(i))
                    .await?
            );
        }
        db.commit().await?;

        // Delete half of the keys at random.
        let mut rng = StdRng::seed_from_u64(1337);
        let mut deleted = HashSet::new();
        let mut batch = db.start_batch();
        for i in 0..100 {
            if rng.gen_bool(0.5) {
                deleted.insert(i);
                assert!(batch.delete(D::Key::from_seed(i)).await?);
            }
        }
        // Try to delete an inactive key.
        batch.delete_unchecked(D::Key::from_seed(255)).await?;

        // Commit the batch then confirm output is as expected.
        db.write_batch(batch.into_iter()).await?;
        db.commit().await?;
        for i in 0..100 {
            if deleted.contains(&i) {
                assert_eq!(kv::Gettable::get(&db, &D::Key::from_seed(i)).await?, None);
            } else {
                assert_eq!(
                    kv::Gettable::get(&db, &D::Key::from_seed(i)).await?,
                    Some(D::Value::from_seed(i))
                );
            }
        }

        // Recreate the deleted keys.
        let mut batch = db.start_batch();
        for i in 0..100 {
            if deleted.contains(&i) {
                batch
                    .create(D::Key::from_seed(i), D::Value::from_seed(i))
                    .await?;
            }
        }

        // Commit the batch then confirm output is as expected.
        db.write_batch(batch.into_iter()).await?;
        db.commit().await?;

        for i in 0..100 {
            assert_eq!(
                kv::Gettable::get(&db, &D::Key::from_seed(i)).await?,
                Some(D::Value::from_seed(i))
            );
        }

        db.destroy().await?;

        Ok(())
    }

    /// Create an empty db, write a batch containing small # of keys, then write another batch deleting those
    /// keys.
    async fn test_write_batch_from_to_empty<D, F, Fut>(new_db: &mut F) -> Result<(), Error>
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = D>,
        D: Batchable + Persistable<Error = Error>,
        D::Key: TestKey,
        D::Value: TestValue,
    {
        // 2 key test
        let mut db = new_db().await;
        let created1 = D::Key::from_seed(1);
        let created2 = D::Key::from_seed(2);
        let mut batch = db.start_batch();
        batch
            .create(created1.clone(), D::Value::from_seed(1))
            .await?;
        batch
            .create(created2.clone(), D::Value::from_seed(2))
            .await?;
        batch
            .update(created1.clone(), D::Value::from_seed(3))
            .await?;
        db.write_batch(batch.into_iter()).await?;

        assert_eq!(
            kv::Gettable::get(&db, &created1).await?,
            Some(D::Value::from_seed(3))
        );
        assert_eq!(
            kv::Gettable::get(&db, &created2).await?,
            Some(D::Value::from_seed(2))
        );

        let mut delete_batch = db.start_batch();
        delete_batch.delete(created1.clone()).await?;
        delete_batch.delete(created2.clone()).await?;
        db.write_batch(delete_batch.into_iter()).await?;
        assert_eq!(kv::Gettable::get(&db, &created1).await?, None);
        assert_eq!(kv::Gettable::get(&db, &created2).await?, None);

        db.destroy().await?;

        // 1 key test
        let mut db = new_db().await;
        let created1 = D::Key::from_seed(1);
        let mut batch = db.start_batch();
        batch
            .create(created1.clone(), D::Value::from_seed(1))
            .await?;
        db.write_batch(batch.into_iter()).await?;
        assert_eq!(
            kv::Gettable::get(&db, &created1).await?,
            Some(D::Value::from_seed(1))
        );
        let mut delete_batch = db.start_batch();
        delete_batch.delete(created1.clone()).await?;
        db.write_batch(delete_batch.into_iter()).await?;
        assert_eq!(kv::Gettable::get(&db, &created1).await?, None);

        db.destroy().await?;

        Ok(())
    }

    async fn test_write_batch<D, F, Fut>(new_db: &mut F) -> Result<(), Error>
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = D>,
        D: Batchable + Persistable<Error = Error>,
        D::Key: TestKey,
        D::Value: TestValue,
    {
        let mut db = new_db().await;
        let existing = D::Key::from_seed(7);
        db.update(existing.clone(), D::Value::from_seed(0)).await?;

        let created = D::Key::from_seed(8);
        let mut batch = db.start_batch();
        batch
            .update(existing.clone(), D::Value::from_seed(8))
            .await?;
        batch
            .create(created.clone(), D::Value::from_seed(9))
            .await?;
        db.write_batch(batch.into_iter()).await?;

        assert_eq!(
            kv::Gettable::get(&db, &existing).await?,
            Some(D::Value::from_seed(8))
        );
        assert_eq!(
            kv::Gettable::get(&db, &created).await?,
            Some(D::Value::from_seed(9))
        );

        let mut delete_batch = db.start_batch();
        delete_batch.delete(existing.clone()).await?;
        db.write_batch(delete_batch.into_iter()).await?;
        assert_eq!(kv::Gettable::get(&db, &existing).await?, None);

        db.destroy().await?;
        Ok(())
    }

    fn seed_bytes(seed: u8) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        bytes[0] = seed;
        bytes
    }

    impl TestKey for blake3::Digest {
        fn from_seed(seed: u8) -> Self {
            Self::from(seed_bytes(seed))
        }
    }

    impl TestKey for sha256::Digest {
        fn from_seed(seed: u8) -> Self {
            Self::from(seed_bytes(seed))
        }
    }

    impl TestValue for Vec<u8> {
        fn from_seed(seed: u8) -> Self {
            vec![seed]
        }
    }

    impl TestValue for blake3::Digest {
        fn from_seed(seed: u8) -> Self {
            Self::from(seed_bytes(seed))
        }
    }

    impl TestValue for sha256::Digest {
        fn from_seed(seed: u8) -> Self {
            Self::from(seed_bytes(seed))
        }
    }
}
