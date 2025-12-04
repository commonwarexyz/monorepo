//! Shared benchmarking infrastructure for ADB variants.

use commonware_codec::Codec;
use commonware_runtime::{Clock, Metrics, Storage};
use commonware_storage::{
    adb::{
        any::{CleanAny, DirtyAny},
        store::{DirtyStore, LogStore, Store},
        Error,
    },
    mmr::Location,
    store::{Store as StoreTrait, StoreDeletable, StoreMut, StorePersistable},
    translator::Translator,
};
use commonware_utils::Array;
use std::future::Future;

/// A trait abstracting databases for benchmarking purposes.
pub trait BenchmarkableDb {
    type Key;
    type Value;
    type Error: std::fmt::Debug;

    /// Update a key with a new value.
    fn update(
        &mut self,
        key: Self::Key,
        value: Self::Value,
    ) -> impl Future<Output = Result<(), Self::Error>>;

    /// Delete a key. Returns true if deleted, false if didn't exist.
    fn delete(&mut self, key: Self::Key) -> impl Future<Output = Result<bool, Self::Error>>;

    /// Commit changes, optionally with metadata. Ensures durability.
    fn commit(
        &mut self,
        metadata: Option<Self::Value>,
    ) -> impl Future<Output = Result<(), Self::Error>>;

    /// Prune historical operations before the given location.
    fn prune(&mut self, loc: Location) -> impl Future<Output = Result<(), Self::Error>>;

    /// Get the inactivity floor location.
    fn inactivity_floor_loc(&self) -> Location;

    /// Close the database.
    fn close(self) -> impl Future<Output = Result<(), Self::Error>>;

    /// Destroy the database, removing all data.
    fn destroy(self) -> impl Future<Output = Result<(), Self::Error>>;
}

/// Implementation of [BenchmarkableDb] for the unauthenticated [Store] type.
impl<E, K, V, T> BenchmarkableDb for Store<E, K, V, T>
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: Codec + Clone,
    T: Translator,
{
    type Key = K;
    type Value = V;
    type Error = Error;

    async fn update(&mut self, key: Self::Key, value: Self::Value) -> Result<(), Self::Error> {
        StoreMut::update(self, key, value).await
    }

    async fn delete(&mut self, key: Self::Key) -> Result<bool, Self::Error> {
        StoreDeletable::delete(self, key).await
    }

    async fn commit(&mut self, _metadata: Option<Self::Value>) -> Result<(), Self::Error> {
        // Store doesn't support metadata in commit, so ignore it
        Store::commit(self, None).await.map(|_| ())
    }

    async fn prune(&mut self, loc: Location) -> Result<(), Self::Error> {
        Store::prune(self, loc).await
    }

    fn inactivity_floor_loc(&self) -> Location {
        LogStore::inactivity_floor_loc(self)
    }

    async fn close(self) -> Result<(), Self::Error> {
        Store::close(self).await
    }

    async fn destroy(self) -> Result<(), Self::Error> {
        Store::destroy(self).await
    }
}

/// Wrapper for [CleanAny] to implement [BenchmarkableDb].
/// Handles state transitions (into_dirty/merkleize) transparently.
/// Stays in Dirty state during mutations and only merkleizes when necessary.
pub struct CleanAnyWrapper<A: CleanAny> {
    inner: Option<CleanAnyState<A>>,
}

enum CleanAnyState<A: CleanAny> {
    Clean(A),
    Dirty(A::Dirty),
}

impl<A: CleanAny> CleanAnyWrapper<A> {
    pub fn new(db: A) -> Self {
        Self {
            inner: Some(CleanAnyState::Clean(db)),
        }
    }

    /// Ensure we're in dirty state, transitioning if necessary
    fn ensure_dirty(&mut self) {
        let state = self.inner.take().expect("wrapper should never be empty");
        self.inner = Some(match state {
            CleanAnyState::Clean(clean) => CleanAnyState::Dirty(clean.into_dirty()),
            CleanAnyState::Dirty(dirty) => CleanAnyState::Dirty(dirty),
        });
    }

    /// Merkleize if in dirty state, ensuring we're in clean state
    async fn ensure_clean(&mut self) {
        let state = self.inner.take().expect("wrapper should never be empty");
        self.inner = Some(match state {
            CleanAnyState::Clean(clean) => CleanAnyState::Clean(clean),
            CleanAnyState::Dirty(dirty) => CleanAnyState::Clean(dirty.merkleize().await),
        });
    }
}

impl<A> BenchmarkableDb for CleanAnyWrapper<A>
where
    A: CleanAny,
{
    type Key = A::Key;
    type Value = <A as LogStore>::Value;
    type Error = Error;

    async fn update(&mut self, key: Self::Key, value: Self::Value) -> Result<(), Self::Error> {
        // Ensure we're in dirty state, then update
        self.ensure_dirty();
        match self.inner.as_mut().expect("wrapper should never be empty") {
            CleanAnyState::Dirty(dirty) => dirty.update(key, value).await,
            _ => unreachable!("ensure_dirty guarantees Dirty state"),
        }
    }

    async fn delete(&mut self, key: Self::Key) -> Result<bool, Self::Error> {
        // Ensure we're in dirty state, then delete
        self.ensure_dirty();
        match self.inner.as_mut().expect("wrapper should never be empty") {
            CleanAnyState::Dirty(dirty) => dirty.delete(key).await,
            _ => unreachable!("ensure_dirty guarantees Dirty state"),
        }
    }

    async fn commit(&mut self, metadata: Option<Self::Value>) -> Result<(), Self::Error> {
        // Merkleize before commit
        self.ensure_clean().await;
        match self.inner.as_mut().expect("wrapper should never be empty") {
            CleanAnyState::Clean(clean) => clean.commit(metadata).await.map(|_| ()),
            _ => unreachable!("ensure_clean guarantees Clean state"),
        }
    }

    async fn prune(&mut self, loc: Location) -> Result<(), Self::Error> {
        // Merkleize before prune
        self.ensure_clean().await;
        match self.inner.as_mut().expect("wrapper should never be empty") {
            CleanAnyState::Clean(clean) => clean.prune(loc).await,
            _ => unreachable!("ensure_clean guarantees Clean state"),
        }
    }

    fn inactivity_floor_loc(&self) -> Location {
        match self.inner.as_ref().expect("wrapper should never be empty") {
            CleanAnyState::Clean(clean) => clean.inactivity_floor_loc(),
            CleanAnyState::Dirty(dirty) => dirty.inactivity_floor_loc(),
        }
    }

    async fn close(mut self) -> Result<(), Self::Error> {
        // Merkleize before close
        self.ensure_clean().await;
        match self.inner.take().expect("wrapper should never be empty") {
            CleanAnyState::Clean(clean) => clean.close().await,
            _ => unreachable!("ensure_clean guarantees Clean state"),
        }
    }

    async fn destroy(mut self) -> Result<(), Self::Error> {
        // Merkleize before destroy
        self.ensure_clean().await;
        match self.inner.take().expect("wrapper should never be empty") {
            CleanAnyState::Clean(clean) => clean.destroy().await,
            _ => unreachable!("ensure_clean guarantees Clean state"),
        }
    }
}

// Implement standard store traits for CleanAnyWrapper to enable Batchable blanket impl
impl<A> StoreTrait for CleanAnyWrapper<A>
where
    A: CleanAny,
{
    type Key = A::Key;
    type Value = <A as LogStore>::Value;
    type Error = Error;

    async fn get(&self, key: &Self::Key) -> Result<Option<Self::Value>, Self::Error> {
        match self.inner.as_ref().expect("wrapper should never be empty") {
            CleanAnyState::Clean(clean) => CleanAny::get(clean, key).await,
            CleanAnyState::Dirty(dirty) => DirtyAny::get(dirty, key).await,
        }
    }
}

impl<A> StoreMut for CleanAnyWrapper<A>
where
    A: CleanAny,
{
    async fn update(&mut self, key: Self::Key, value: Self::Value) -> Result<(), Self::Error> {
        self.ensure_dirty();
        match self.inner.as_mut().expect("wrapper should never be empty") {
            CleanAnyState::Dirty(dirty) => DirtyAny::update(dirty, key, value).await,
            _ => unreachable!("ensure_dirty guarantees Dirty state"),
        }
    }
}

impl<A> StoreDeletable for CleanAnyWrapper<A>
where
    A: CleanAny,
{
    async fn delete(&mut self, key: Self::Key) -> Result<bool, Self::Error> {
        self.ensure_dirty();
        match self.inner.as_mut().expect("wrapper should never be empty") {
            CleanAnyState::Dirty(dirty) => DirtyAny::delete(dirty, key).await,
            _ => unreachable!("ensure_dirty guarantees Dirty state"),
        }
    }
}

impl<A> StorePersistable for CleanAnyWrapper<A>
where
    A: CleanAny,
{
    type Error = Error;

    async fn commit(&mut self) -> Result<(), Self::Error> {
        BenchmarkableDb::commit(self, None).await
    }

    async fn destroy(self) -> Result<(), Self::Error> {
        BenchmarkableDb::destroy(self).await
    }
}
