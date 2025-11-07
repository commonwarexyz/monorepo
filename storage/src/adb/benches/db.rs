//! Benchmark trait for ADB implementations.

use commonware_codec::{Codec, CodecFixed};
use commonware_cryptography::{Hasher as CHasher, Hasher};
use commonware_runtime::{Clock, Metrics, Storage, Storage as RStorage};
use commonware_storage::{
    adb::{self, Error},
    mmr::{mem::Clean, Location},
    translator::Translator,
};
use commonware_utils::Array;
use core::future::Future;

/// A trait for any key-value store based on an append-only log of operations.
pub trait Db<E: RStorage + Clock + Metrics, K: Array, V: Codec, T: Translator> {
    /// The number of operations that have been applied to this db, including those that have been
    /// pruned and those that are not yet committed.
    fn op_count(&self) -> Location;

    /// Return the inactivity floor location. This is the location before which all operations are
    /// known to be inactive. Operations before this point can be safely pruned.
    fn inactivity_floor_loc(&self) -> Location;

    /// Get the value of `key` in the db, or None if it has no value.
    fn get(&self, key: &K) -> impl Future<Output = Result<Option<V>, Error>>;

    /// Updates `key` to have value `value`. The operation is reflected in the snapshot, but will be
    /// subject to rollback until the next successful `commit`.
    fn update(&mut self, key: K, value: V) -> impl Future<Output = Result<(), Error>>;

    /// Delete `key` and its value from the db. Deleting a key that already has no value is a no-op.
    /// The operation is reflected in the snapshot, but will be subject to rollback until the next
    /// successful `commit`.
    fn delete(&mut self, key: K) -> impl Future<Output = Result<(), Error>>;

    /// Commit any pending operations to the database, ensuring their durability upon return from
    /// this function. Also raises the inactivity floor according to the schedule.
    ///
    /// Failures after commit (but before `sync` or `close`) may still require reprocessing to
    /// recover the database on restart.
    fn commit(&mut self) -> impl Future<Output = Result<(), Error>>;

    /// Sync all database state to disk. While this isn't necessary to ensure durability of
    /// committed operations, periodic invocation may reduce memory usage and the time required to
    /// recover the database on restart.
    fn sync(&mut self) -> impl Future<Output = Result<(), Error>>;

    /// Prune historical operations prior to `prune_loc`. This does not affect the db's root
    /// or current snapshot.
    fn prune(&mut self, prune_loc: Location) -> impl Future<Output = Result<(), Error>>;

    /// Close the db. Operations that have not been committed will be lost or rolled back on
    /// restart.
    fn close(self) -> impl Future<Output = Result<(), Error>>;

    /// Destroy the db, removing all data from disk.
    fn destroy(self) -> impl Future<Output = Result<(), Error>>;
}

impl<E, K, V, T> Db<E, K, V, T> for adb::store::Store<E, K, V, T>
where
    E: RStorage + Clock + Metrics,
    K: Array,
    V: Codec,
    T: Translator,
{
    fn op_count(&self) -> Location {
        self.op_count()
    }

    fn inactivity_floor_loc(&self) -> Location {
        self.inactivity_floor_loc()
    }

    async fn get(&self, key: &K) -> Result<Option<V>, Error> {
        self.get(key).await
    }

    async fn update(&mut self, key: K, value: V) -> Result<(), Error> {
        self.update(key, value).await
    }

    async fn delete(&mut self, key: K) -> Result<(), Error> {
        self.delete(key).await
    }

    async fn commit(&mut self) -> Result<(), Error> {
        self.commit(None).await
    }

    async fn sync(&mut self) -> Result<(), Error> {
        self.sync().await
    }

    async fn prune(&mut self, prune_loc: Location) -> Result<(), Error> {
        self.prune(prune_loc).await
    }

    async fn close(self) -> Result<(), Error> {
        self.close().await
    }

    async fn destroy(self) -> Result<(), Error> {
        self.destroy().await
    }
}

impl<
        E: RStorage + Clock + Metrics,
        K: Array,
        V: CodecFixed<Cfg = ()>,
        H: Hasher,
        T: Translator,
        const N: usize,
    > Db<E, K, V, T> for adb::current::unordered::Current<E, K, V, H, T, N>
{
    fn op_count(&self) -> Location {
        self.op_count()
    }

    fn inactivity_floor_loc(&self) -> Location {
        self.inactivity_floor_loc()
    }

    async fn get(&self, key: &K) -> Result<Option<V>, Error> {
        self.get(key).await
    }

    async fn update(&mut self, key: K, value: V) -> Result<(), Error> {
        self.update(key, value).await
    }

    async fn delete(&mut self, key: K) -> Result<(), Error> {
        self.delete(key).await
    }

    async fn commit(&mut self) -> Result<(), Error> {
        self.commit().await
    }

    async fn sync(&mut self) -> Result<(), Error> {
        self.sync().await
    }

    async fn prune(&mut self, prune_loc: Location) -> Result<(), Error> {
        self.prune(prune_loc).await
    }

    async fn close(self) -> Result<(), Error> {
        self.close().await
    }

    async fn destroy(self) -> Result<(), Error> {
        self.destroy().await
    }
}

impl<E: Storage + Clock + Metrics, K: Array, V: CodecFixed<Cfg = ()>, H: Hasher, T: Translator>
    Db<E, K, V, T> for adb::any::fixed::ordered::Any<E, K, V, H, T, Clean<<H as Hasher>::Digest>>
{
    fn op_count(&self) -> Location {
        self.op_count()
    }

    fn inactivity_floor_loc(&self) -> Location {
        self.inactivity_floor_loc()
    }

    async fn get(&self, key: &K) -> Result<Option<V>, Error> {
        self.get(key).await
    }

    async fn update(&mut self, key: K, value: V) -> Result<(), Error> {
        self.update(key, value).await
    }

    async fn delete(&mut self, key: K) -> Result<(), Error> {
        self.delete(key).await
    }

    async fn commit(&mut self) -> Result<(), Error> {
        self.commit().await
    }

    async fn sync(&mut self) -> Result<(), Error> {
        self.sync().await
    }

    async fn prune(&mut self, prune_loc: Location) -> Result<(), Error> {
        self.prune(prune_loc).await
    }

    async fn close(self) -> Result<(), Error> {
        self.close().await
    }

    async fn destroy(self) -> Result<(), Error> {
        self.destroy().await
    }
}

impl<E: Storage + Clock + Metrics, K: Array, V: CodecFixed<Cfg = ()>, H: Hasher, T: Translator>
    Db<E, K, V, T> for adb::any::fixed::unordered::Any<E, K, V, H, T>
{
    fn op_count(&self) -> Location {
        self.op_count()
    }

    fn inactivity_floor_loc(&self) -> Location {
        self.inactivity_floor_loc()
    }

    async fn get(&self, key: &K) -> Result<Option<V>, Error> {
        self.get(key).await
    }

    async fn update(&mut self, key: K, value: V) -> Result<(), Error> {
        self.update(key, value).await
    }

    async fn delete(&mut self, key: K) -> Result<(), Error> {
        self.delete(key).await.map(|_| ())
    }

    async fn commit(&mut self) -> Result<(), Error> {
        self.commit().await
    }

    async fn sync(&mut self) -> Result<(), Error> {
        self.sync().await
    }

    async fn prune(&mut self, prune_loc: Location) -> Result<(), Error> {
        self.prune(prune_loc).await
    }

    async fn close(self) -> Result<(), Error> {
        self.close().await
    }

    async fn destroy(self) -> Result<(), Error> {
        self.destroy().await
    }
}

impl<E: Storage + Clock + Metrics, K: Array, V: Codec, H: CHasher, T: Translator> Db<E, K, V, T>
    for adb::any::variable::Any<E, K, V, H, T, Clean<<H as CHasher>::Digest>>
{
    fn op_count(&self) -> Location {
        self.op_count()
    }

    fn inactivity_floor_loc(&self) -> Location {
        self.inactivity_floor_loc()
    }

    async fn get(&self, key: &K) -> Result<Option<V>, Error> {
        self.get(key).await
    }

    async fn update(&mut self, key: K, value: V) -> Result<(), Error> {
        self.update(key, value).await
    }

    async fn delete(&mut self, key: K) -> Result<(), Error> {
        self.delete(key).await
    }

    async fn commit(&mut self) -> Result<(), Error> {
        self.commit(None).await
    }

    async fn sync(&mut self) -> Result<(), Error> {
        self.sync().await
    }

    async fn prune(&mut self, prune_loc: Location) -> Result<(), Error> {
        self.prune(prune_loc).await
    }

    async fn close(self) -> Result<(), Error> {
        self.close().await
    }

    async fn destroy(self) -> Result<(), Error> {
        self.destroy().await
    }
}

impl<
        E: Storage + Clock + Metrics,
        K: Array,
        V: CodecFixed<Cfg = ()>,
        H: CHasher,
        T: Translator,
        const N: usize,
    > Db<E, K, V, T> for adb::current::ordered::Current<E, K, V, H, T, N>
{
    fn op_count(&self) -> Location {
        self.op_count()
    }

    fn inactivity_floor_loc(&self) -> Location {
        self.inactivity_floor_loc()
    }

    async fn get(&self, key: &K) -> Result<Option<V>, Error> {
        self.get(key).await
    }

    async fn update(&mut self, key: K, value: V) -> Result<(), Error> {
        self.update(key, value).await
    }

    async fn delete(&mut self, key: K) -> Result<(), Error> {
        self.delete(key).await
    }

    async fn commit(&mut self) -> Result<(), Error> {
        self.commit().await
    }

    async fn sync(&mut self) -> Result<(), Error> {
        self.sync().await
    }

    async fn prune(&mut self, prune_loc: Location) -> Result<(), Error> {
        self.prune(prune_loc).await
    }

    async fn close(self) -> Result<(), Error> {
        self.close().await
    }

    async fn destroy(self) -> Result<(), Error> {
        self.destroy().await
    }
}
