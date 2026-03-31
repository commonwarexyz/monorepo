//! [`ManagedDb`] implementation for QMDB [`keyless`](commonware_storage::qmdb::keyless) databases.
//!
//! Keyless databases are append-only: values are addressed by [`Location`]
//! rather than a user-chosen key. The wrapper types here capture
//! `Arc<AsyncRwLock<Keyless>>` so the batch API can read through to
//! committed state (needed by [`UnmerkleizedBatch::get`]).

use crate::stateful::db::{
    ManagedDb, Merkleized as MerkleizedTrait, Unmerkleized as UnmerkleizedTrait,
};
use commonware_cryptography::Hasher;
use commonware_runtime::{Clock, Metrics, Storage};
use commonware_storage::{
    mmr::{self, Location},
    qmdb::{
        any::VariableValue,
        keyless::{
            batch::{MerkleizedBatch, UnmerkleizedBatch},
            Config, Keyless,
        },
        sync, Error,
    },
};
use commonware_utils::{non_empty_range, sync::AsyncRwLock};
use std::{ops::Deref, sync::Arc};

type KeylessDbHandle<E, V, H> = Arc<AsyncRwLock<Keyless<E, V, H>>>;

/// Wraps a keyless [`UnmerkleizedBatch`] with a reference to the parent
/// database, implementing the [`Unmerkleized`](super::Unmerkleized) trait.
pub struct KeylessUnmerkleized<E: Storage + Clock + Metrics, V: VariableValue, H: Hasher> {
    batch: UnmerkleizedBatch<H, V>,
    db: KeylessDbHandle<E, V, H>,
    metadata: Option<V>,
}

impl<E: Storage + Clock + Metrics, V: VariableValue, H: Hasher> Deref
    for KeylessUnmerkleized<E, V, H>
{
    type Target = UnmerkleizedBatch<H, V>;

    fn deref(&self) -> &Self::Target {
        &self.batch
    }
}

impl<E: Storage + Clock + Metrics, V: VariableValue, H: Hasher> KeylessUnmerkleized<E, V, H> {
    /// Set commit metadata included in the next [`merkleize`](UnmerkleizedTrait::merkleize) call.
    pub fn with_metadata(mut self, metadata: V) -> Self {
        self.metadata = Some(metadata);
        self
    }

    /// Read a value at `loc`, falling back to committed state.
    pub async fn get(&self, loc: Location) -> Result<Option<V>, Error<mmr::Family>> {
        let db = self.db.read().await;
        self.batch.get(loc, &*db).await
    }

    /// Append a value to the end of the database, returning its location.
    pub fn append(mut self, value: V) -> Self {
        self.batch = self.batch.append(value);
        self
    }
}

/// Wraps a keyless [`MerkleizedBatch`] with a reference to the parent
/// database, implementing the [`Merkleized`](super::Merkleized) trait.
pub struct KeylessMerkleized<E: Storage + Clock + Metrics, V: VariableValue, H: Hasher> {
    batch: MerkleizedBatch<H::Digest, V>,
    db: KeylessDbHandle<E, V, H>,
}

impl<E: Storage + Clock + Metrics, V: VariableValue, H: Hasher> Deref
    for KeylessMerkleized<E, V, H>
{
    type Target = MerkleizedBatch<H::Digest, V>;

    fn deref(&self) -> &Self::Target {
        &self.batch
    }
}

impl<E: Storage + Clock + Metrics, V: VariableValue, H: Hasher> KeylessMerkleized<E, V, H> {
    /// Read a value at `loc`, falling back to committed state.
    pub async fn get(&self, loc: Location) -> Result<Option<V>, Error<mmr::Family>> {
        let db = self.db.read().await;
        self.batch.get(loc, &*db).await
    }
}

impl<E: Storage + Clock + Metrics, V: VariableValue, H: Hasher> UnmerkleizedTrait
    for KeylessUnmerkleized<E, V, H>
{
    type Merkleized = KeylessMerkleized<E, V, H>;
    type Error = Error<mmr::Family>;

    async fn merkleize(self) -> Result<Self::Merkleized, Error<mmr::Family>> {
        Ok(KeylessMerkleized {
            batch: self.batch.merkleize(self.metadata),
            db: self.db,
        })
    }
}

impl<E: Storage + Clock + Metrics, V: VariableValue, H: Hasher> MerkleizedTrait
    for KeylessMerkleized<E, V, H>
{
    type Digest = H::Digest;
    type Unmerkleized = KeylessUnmerkleized<E, V, H>;

    fn root(&self) -> H::Digest {
        self.batch.root()
    }

    fn new_batch(&self) -> Self::Unmerkleized {
        KeylessUnmerkleized {
            batch: self.batch.new_batch::<H>(),
            db: self.db.clone(),
            metadata: None,
        }
    }
}

impl<E, V, H> ManagedDb<E> for Keyless<E, V, H>
where
    E: Storage + Clock + Metrics,
    V: VariableValue + 'static,
    H: Hasher + 'static,
{
    type Unmerkleized = KeylessUnmerkleized<E, V, H>;
    type Merkleized = KeylessMerkleized<E, V, H>;
    type Error = Error<mmr::Family>;
    type Config = Config<V::Cfg>;
    type SyncTarget = sync::Target<H::Digest>;

    async fn init(context: E, config: Self::Config) -> Result<Self, Error<mmr::Family>> {
        <Self>::init(context, config).await
    }

    async fn new_batch(db: &Arc<AsyncRwLock<Self>>) -> Self::Unmerkleized {
        let inner = db.read().await;
        KeylessUnmerkleized {
            batch: inner.new_batch(),
            db: db.clone(),
            metadata: None,
        }
    }

    async fn finalize(&mut self, batch: Self::Merkleized) -> Result<(), Error<mmr::Family>> {
        let current_size = *self.last_commit_loc() + 1;
        let changeset = batch.batch.finalize_from(current_size);
        self.apply_batch(changeset).await?;
        self.commit().await?;
        Ok(())
    }

    async fn sync_target(&self) -> Self::SyncTarget {
        let bounds = self.bounds().await;
        sync::Target {
            root: self.root(),
            range: non_empty_range!(bounds.start, bounds.end),
        }
    }

    async fn rewind_to_target(
        &mut self,
        target: Self::SyncTarget,
    ) -> Result<(), Error<mmr::Family>> {
        self.rewind(target.range.end()).await?;
        self.commit().await?;

        let rewound_target = self.sync_target().await;
        assert_eq!(
            rewound_target, target,
            "rewound database target mismatch after rewind",
        );
        Ok(())
    }
}
