//! Extension type for simplified usage of Any authenticated databases.
//!
//! The [AnyExt] wrapper provides a traditional mutable key-value store interface over Any
//! databases, automatically handling Clean/Dirty state transitions. This eliminates the need for
//! manual state management while maintaining the performance benefits of deferred merkleization.

use super::{CleanAny, DirtyAny};
use crate::{
    kv,
    mmr::Location,
    qmdb::{
        store::{Batchable, CleanStore, DirtyStore, LogStore, LogStorePrunable},
        Error,
    },
    Persistable,
};

/// An extension wrapper for [CleanAny] databases that provides a traditional mutable key-value
/// store interface by internally handling Clean/Dirty state transitions.
pub struct AnyExt<A: CleanAny> {
    // Invariant: always Some
    inner: Option<State<A>>,
}

enum State<A: CleanAny> {
    Clean(A),
    Dirty(A::Dirty),
}

impl<A: CleanAny> AnyExt<A> {
    /// Create a new wrapper from a Clean Any database.
    pub const fn new(db: A) -> Self {
        Self {
            inner: Some(State::Clean(db)),
        }
    }

    /// Ensure we're in dirty state, transitioning if necessary.
    fn ensure_dirty(&mut self) {
        let state = self.inner.take().expect("wrapper should never be empty");
        self.inner = Some(match state {
            State::Clean(clean) => State::Dirty(clean.into_dirty()),
            State::Dirty(dirty) => State::Dirty(dirty),
        });
    }

    /// Merkleize if in dirty state, ensuring we're in clean state.
    async fn ensure_clean(&mut self) -> Result<(), Error> {
        let state = self.inner.take().expect("wrapper should never be empty");
        self.inner = Some(match state {
            State::Clean(clean) => State::Clean(clean),
            State::Dirty(dirty) => State::Clean(dirty.merkleize().await?),
        });
        Ok(())
    }
}

impl<A> kv::Gettable for AnyExt<A>
where
    A: CleanAny,
{
    type Key = A::Key;
    type Value = <A as LogStore>::Value;
    type Error = Error;

    async fn get(&self, key: &Self::Key) -> Result<Option<Self::Value>, Self::Error> {
        match self.inner.as_ref().expect("wrapper should never be empty") {
            State::Clean(clean) => CleanAny::get(clean, key).await,
            State::Dirty(dirty) => DirtyAny::get(dirty, key).await,
        }
    }
}

impl<A> kv::Updatable for AnyExt<A>
where
    A: CleanAny,
{
    async fn update(&mut self, key: Self::Key, value: Self::Value) -> Result<(), Self::Error> {
        self.ensure_dirty();
        match self.inner.as_mut().expect("wrapper should never be empty") {
            State::Dirty(dirty) => DirtyAny::update(dirty, key, value).await,
            _ => unreachable!("ensure_dirty guarantees Dirty state"),
        }
    }
}

impl<A> kv::Deletable for AnyExt<A>
where
    A: CleanAny,
{
    async fn delete(&mut self, key: Self::Key) -> Result<bool, Self::Error> {
        self.ensure_dirty();
        match self.inner.as_mut().expect("wrapper should never be empty") {
            State::Dirty(dirty) => DirtyAny::delete(dirty, key).await,
            _ => unreachable!("ensure_dirty guarantees Dirty state"),
        }
    }
}

impl<A> Persistable for AnyExt<A>
where
    A: CleanAny,
{
    type Error = Error;

    async fn commit(&mut self) -> Result<(), Self::Error> {
        // Merkleize before commit
        self.ensure_clean().await?;
        match self.inner.as_mut().expect("wrapper should never be empty") {
            State::Clean(clean) => clean.commit(None).await.map(|_| ()),
            _ => unreachable!("ensure_clean guarantees Clean state"),
        }
    }

    async fn sync(&mut self) -> Result<(), Self::Error> {
        // Merkleize before sync
        self.ensure_clean().await?;
        match self.inner.as_mut().expect("wrapper should never be empty") {
            State::Clean(clean) => clean.sync().await,
            _ => unreachable!("ensure_clean guarantees Clean state"),
        }
    }

    async fn destroy(mut self) -> Result<(), Self::Error> {
        // Merkleize before destroy
        self.ensure_clean().await?;
        match self.inner.take().expect("wrapper should never be empty") {
            State::Clean(clean) => clean.destroy().await,
            _ => unreachable!("ensure_clean guarantees Clean state"),
        }
    }
}

impl<A> LogStore for AnyExt<A>
where
    A: CleanAny,
{
    type Value = <A as LogStore>::Value;

    fn is_empty(&self) -> bool {
        match self.inner.as_ref().expect("wrapper should never be empty") {
            State::Clean(clean) => clean.is_empty(),
            State::Dirty(dirty) => dirty.is_empty(),
        }
    }

    fn op_count(&self) -> Location {
        match self.inner.as_ref().expect("wrapper should never be empty") {
            State::Clean(clean) => clean.op_count(),
            State::Dirty(dirty) => dirty.op_count(),
        }
    }

    fn inactivity_floor_loc(&self) -> Location {
        match self.inner.as_ref().expect("wrapper should never be empty") {
            State::Clean(clean) => clean.inactivity_floor_loc(),
            State::Dirty(dirty) => dirty.inactivity_floor_loc(),
        }
    }

    async fn get_metadata(&self) -> Result<Option<Self::Value>, Error> {
        match self.inner.as_ref().expect("wrapper should never be empty") {
            State::Clean(clean) => clean.get_metadata().await,
            State::Dirty(dirty) => dirty.get_metadata().await,
        }
    }
}

impl<A> LogStorePrunable for AnyExt<A>
where
    A: CleanAny,
{
    async fn prune(&mut self, prune_loc: Location) -> Result<(), Error> {
        // Merkleize before prune
        self.ensure_clean().await?;
        match self.inner.as_mut().expect("wrapper should never be empty") {
            State::Clean(clean) => clean.prune(prune_loc).await,
            _ => unreachable!("ensure_clean guarantees Clean state"),
        }
    }
}

impl<A> Batchable for AnyExt<A>
where
    A: CleanAny,
    <A as CleanStore>::Dirty: Batchable<Key = A::Key, Value = A::Value>,
{
    async fn write_batch(
        &mut self,
        iter: impl Iterator<Item = (Self::Key, Option<Self::Value>)>,
    ) -> Result<(), Error> {
        self.ensure_dirty();
        match self.inner.as_mut().expect("wrapper should never be empty") {
            State::Dirty(dirty) => dirty.write_batch(iter).await,
            _ => unreachable!("ensure_dirty guarantees Dirty state"),
        }
    }
}
