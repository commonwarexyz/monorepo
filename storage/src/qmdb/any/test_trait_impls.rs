//! Test trait implementations for the Any QMDB.

use super::{
    db::Db,
    operation::{Operation, Update},
    traits::{BatchableDb, DbAny, Provable},
};
use crate::{
    Context,
    index::Unordered as UnorderedIndex,
    journal::contiguous::Mutable,
    merkle::{Family, Location, Proof},
    qmdb::Error,
};
use commonware_codec::Codec;
use commonware_cryptography::Hasher;
use commonware_parallel::Strategy;
use commonware_runtime::Handle;
use core::num::NonZeroU64;
use std::ops::Range;

impl<F, E, C, I, H, U, const N: usize, S> DbAny<F> for Db<F, E, C, I, H, U, N, S>
where
    F: Family,
    E: Context,
    C: Mutable<Item = Operation<F, U>>,
    I: UnorderedIndex<Value = Location<F>>,
    H: Hasher,
    U: Update,
    S: Strategy,
    Operation<F, U>: Codec,
    Self: BatchableDb<Family = F, K = U::Key, V = U::Value>,
{
    type Key = U::Key;
    type Value = U::Value;
    type Digest = H::Digest;

    async fn get(&self, key: &U::Key) -> Result<Option<U::Value>, Error<F>> {
        Self::get(self, key).await
    }

    async fn get_many(&self, keys: &[&U::Key]) -> Result<Vec<Option<U::Value>>, Error<F>> {
        Self::get_many(self, keys).await
    }

    fn root(&self) -> H::Digest {
        Self::root(self)
    }

    fn bounds(&self) -> Range<Location<F>> {
        Self::bounds(self)
    }

    async fn get_metadata(&self) -> Result<Option<U::Value>, Error<F>> {
        Self::get_metadata(self).await
    }

    async fn prune(self, loc: Location<F>) -> Result<Self, Error<F>> {
        Self::prune(self, loc).await
    }

    async fn start_sync(self) -> Result<(Self, Handle<()>), Error<F>> {
        Self::start_sync(self).await
    }

    async fn commit(self) -> Result<Self, Error<F>> {
        Self::commit(self).await
    }

    async fn sync(self) -> Result<Self, Error<F>> {
        Self::sync(self).await
    }

    async fn destroy(self) -> Result<(), Error<F>> {
        Self::destroy(self).await
    }

    fn inactivity_floor_loc(&self) -> Location<F> {
        Self::inactivity_floor_loc(self)
    }

    fn sync_boundary(&self) -> Location<F> {
        Self::sync_boundary(self)
    }
}

impl<F, E, C, I, H, U, const N: usize, S> Provable<F> for Db<F, E, C, I, H, U, N, S>
where
    F: Family,
    E: Context,
    C: Mutable<Item = Operation<F, U>>,
    I: UnorderedIndex<Value = Location<F>>,
    H: Hasher,
    U: Update,
    S: Strategy,
    Operation<F, U>: Codec,
    Self: BatchableDb<Family = F, K = U::Key, V = U::Value>,
{
    type Operation = Operation<F, U>;

    async fn historical_proof(
        &self,
        historical_size: Location<F>,
        start_loc: Location<F>,
        max_ops: NonZeroU64,
    ) -> Result<(Proof<F, H::Digest>, Vec<Operation<F, U>>), Error<F>> {
        Self::historical_proof(self, historical_size, start_loc, max_ops).await
    }
}
