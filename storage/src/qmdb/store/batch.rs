//! Test utilities for batch operations on qmdb databases.

#[cfg(test)]
pub mod tests {
    use crate::{
        kv::{Batchable, Deletable as _, Gettable, Updatable as _},
        qmdb::{
            any::states::{MutableAny, UnmerkleizedDurableAny as _},
            Error,
        },
        Persistable as _,
    };
    use commonware_codec::Codec;
    use commonware_cryptography::sha256;
    use commonware_runtime::{
        deterministic::{self, Context},
        Runner as _,
    };
    use commonware_utils::{test_rng, Array};
    use core::{fmt::Debug, future::Future};
    use rand::Rng;
    use std::collections::HashSet;

    pub trait TestKey: Array + Copy {
        fn from_seed(seed: u8) -> Self;
    }

    pub trait TestValue: Codec + Eq + PartialEq + Debug {
        fn from_seed(seed: u8) -> Self;
    }

    /// Helper trait for async closures that create a database.
    pub trait NewDb<D>: FnMut() -> Self::Fut {
        type Fut: Future<Output = D>;
    }
    impl<F, Fut, D> NewDb<D> for F
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = D>,
    {
        type Fut = Fut;
    }

    /// Destroy an MutableAny database by committing and then destroying.
    async fn destroy_db<D: MutableAny>(db: D) -> Result<(), Error> {
        let db = db.commit(None).await?.0;
        db.into_merkleized().await?.destroy().await
    }

    /// Run the batch test suite against a database factory within a deterministic executor twice,
    /// and test the auditor output for equality.
    pub fn test_batch<D, F, Fut>(mut new_db: F)
    where
        F: FnMut(Context) -> Fut + Clone,
        Fut: Future<Output = D>,
        D: MutableAny,
        D::Key: TestKey,
        <D as Gettable>::Value: TestValue,
    {
        let executor = deterministic::Runner::default();
        let mut new_db_clone = new_db.clone();
        let state1 = executor.start(|context| async move {
            let ctx = context.clone();
            run_batch_tests(&mut || new_db_clone(ctx.clone()))
                .await
                .unwrap();
            ctx.auditor().state()
        });

        let executor = deterministic::Runner::default();
        let state2 = executor.start(|context| async move {
            let ctx = context.clone();
            run_batch_tests(&mut || new_db(ctx.clone())).await.unwrap();
            ctx.auditor().state()
        });

        assert_eq!(state1, state2);
    }

    /// Run the shared batch test suite against a database factory.
    pub async fn run_batch_tests<D, F>(new_db: &mut F) -> Result<(), Error>
    where
        F: NewDb<D>,
        D: MutableAny,
        D::Key: TestKey,
        <D as Gettable>::Value: TestValue,
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

    async fn test_overlay_reads<D, F>(new_db: &mut F) -> Result<(), Error>
    where
        F: NewDb<D>,
        D: MutableAny,
        D::Key: TestKey,
        <D as Gettable>::Value: TestValue,
    {
        let mut db = new_db().await;
        let key = TestKey::from_seed(1);
        db.update(key, TestValue::from_seed(1)).await?;

        let mut batch = db.start_batch();
        assert_eq!(batch.get(&key).await?, Some(TestValue::from_seed(1)));

        batch.update(key, TestValue::from_seed(9)).await?;
        assert_eq!(batch.get(&key).await?, Some(TestValue::from_seed(9)));

        destroy_db(db).await
    }

    async fn test_create<D, F>(new_db: &mut F) -> Result<(), Error>
    where
        F: NewDb<D>,
        D: MutableAny,
        D::Key: TestKey,
        <D as Gettable>::Value: TestValue,
    {
        let mut db = new_db().await;
        let mut batch = db.start_batch();
        let key = TestKey::from_seed(2);
        assert!(batch.create(key, TestValue::from_seed(1)).await?);
        assert!(!batch.create(key, TestValue::from_seed(2)).await?);

        batch.delete_unchecked(key).await?;
        assert!(batch.create(key, TestValue::from_seed(3)).await?);
        assert_eq!(batch.get(&key).await?, Some(TestValue::from_seed(3)));

        let existing = TestKey::from_seed(3);
        db.update(existing, TestValue::from_seed(4)).await?;

        let mut batch = db.start_batch();
        assert!(!batch.create(existing, TestValue::from_seed(5)).await?);

        destroy_db(db).await
    }

    async fn test_delete<D, F>(new_db: &mut F) -> Result<(), Error>
    where
        F: NewDb<D>,
        D: MutableAny,
        D::Key: TestKey,
        <D as Gettable>::Value: TestValue,
    {
        let mut db = new_db().await;
        let base_key = TestKey::from_seed(4);
        db.update(base_key, TestValue::from_seed(10)).await?;
        let mut batch = db.start_batch();
        assert!(batch.delete(base_key).await?);
        assert_eq!(batch.get(&base_key).await?, None);
        assert!(!batch.delete(base_key).await?);

        let mut batch = db.start_batch();
        let overlay_key = TestKey::from_seed(5);
        batch.update(overlay_key, TestValue::from_seed(11)).await?;
        assert!(batch.delete(overlay_key).await?);
        assert_eq!(batch.get(&overlay_key).await?, None);
        assert!(!batch.delete(overlay_key).await?);

        destroy_db(db).await
    }

    async fn test_delete_unchecked<D, F>(new_db: &mut F) -> Result<(), Error>
    where
        F: NewDb<D>,
        D: MutableAny,
        D::Key: TestKey,
        <D as Gettable>::Value: TestValue,
    {
        let mut db = new_db().await;
        let key = TestKey::from_seed(6);

        let mut batch = db.start_batch();
        batch.update(key, TestValue::from_seed(12)).await?;
        batch.delete_unchecked(key).await?;
        assert_eq!(batch.get(&key).await?, None);

        db.update(key, TestValue::from_seed(13)).await?;
        let mut batch = db.start_batch();
        batch.delete_unchecked(key).await?;
        assert_eq!(batch.get(&key).await?, None);

        destroy_db(db).await
    }

    async fn test_write_batch_from_to_empty<D, F>(new_db: &mut F) -> Result<(), Error>
    where
        F: NewDb<D>,
        D: MutableAny,
        D::Key: TestKey,
        <D as Gettable>::Value: TestValue,
    {
        let mut db = new_db().await;
        let mut batch = db.start_batch();
        for i in 0..100 {
            batch
                .update(TestKey::from_seed(i), TestValue::from_seed(i))
                .await?;
        }
        db.write_batch(batch.into_iter()).await?;
        for i in 0..100 {
            assert_eq!(
                db.get(&TestKey::from_seed(i)).await?,
                Some(TestValue::from_seed(i))
            );
        }
        destroy_db(db).await
    }

    async fn test_write_batch<D, F>(new_db: &mut F) -> Result<(), Error>
    where
        F: NewDb<D>,
        D: MutableAny,
        D::Key: TestKey,
        <D as Gettable>::Value: TestValue,
    {
        let mut db = new_db().await;
        for i in 0..100 {
            db.update(TestKey::from_seed(i), TestValue::from_seed(i))
                .await?;
        }

        let mut batch = db.start_batch();
        for i in 0..100 {
            batch.delete(TestKey::from_seed(i)).await?;
        }
        for i in 100..200 {
            batch
                .update(TestKey::from_seed(i), TestValue::from_seed(i))
                .await?;
        }

        db.write_batch(batch.into_iter()).await?;

        for i in 0..100 {
            assert!(db.get(&TestKey::from_seed(i)).await?.is_none());
        }
        for i in 100..200 {
            assert_eq!(
                db.get(&TestKey::from_seed(i)).await?,
                Some(TestValue::from_seed(i))
            );
        }

        destroy_db(db).await
    }

    /// Create an empty db, write a small # of keys, then delete half, then recreate those that were
    /// deleted. Also includes a delete_unchecked of an inactive key.
    async fn test_update_delete_update<D, F>(new_db: &mut F) -> Result<(), Error>
    where
        F: NewDb<D>,
        D: MutableAny,
        D::Key: TestKey,
        <D as Gettable>::Value: TestValue,
    {
        let mut db = new_db().await;
        // Create 100 keys and commit them.
        for i in 0..100 {
            assert!(
                db.create(TestKey::from_seed(i), TestValue::from_seed(i))
                    .await?
            );
        }
        let (durable, _) = db.commit(None).await?;
        let mut db = durable.into_mutable();

        // Delete half of the keys at random.
        let mut rng = test_rng();
        let mut deleted = HashSet::new();
        let mut batch = db.start_batch();
        for i in 0..100 {
            if rng.gen_bool(0.5) {
                deleted.insert(i);
                assert!(batch.delete(TestKey::from_seed(i)).await?);
            }
        }
        // Try to delete an inactive key.
        batch.delete_unchecked(TestKey::from_seed(255)).await?;

        // Commit the batch then confirm output is as expected.
        db.write_batch(batch.into_iter()).await?;
        let (durable, _) = db.commit(None).await?;
        for i in 0..100 {
            if deleted.contains(&i) {
                assert!(durable.get(&TestKey::from_seed(i)).await?.is_none());
            } else {
                assert_eq!(
                    durable.get(&TestKey::from_seed(i)).await?,
                    Some(TestValue::from_seed(i))
                );
            }
        }
        let mut db = durable.into_mutable();

        // Recreate the deleted keys.
        let mut batch = db.start_batch();
        for i in deleted.iter() {
            assert!(
                batch
                    .create(TestKey::from_seed(*i), TestValue::from_seed(*i))
                    .await?
            );
        }
        db.write_batch(batch.into_iter()).await?;

        let (durable, _) = db.commit(None).await?;
        for i in 0..100 {
            assert_eq!(
                durable.get(&TestKey::from_seed(i)).await?,
                Some(TestValue::from_seed(i))
            );
        }

        destroy_db(durable.into_mutable()).await
    }

    impl TestKey for sha256::Digest {
        fn from_seed(seed: u8) -> Self {
            commonware_cryptography::Sha256::fill(seed)
        }
    }

    impl<D: TestKey> TestValue for D {
        fn from_seed(seed: u8) -> Self {
            D::from_seed(seed)
        }
    }

    impl TestValue for Vec<u8> {
        fn from_seed(seed: u8) -> Self {
            vec![seed; 32]
        }
    }
}
