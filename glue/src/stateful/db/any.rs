use crate::stateful::db::{ManagedDb, Merkleized, Unmerkleized};
use commonware_codec::Codec;
use commonware_cryptography::{Digest, Hasher};
use commonware_runtime::{Clock, Metrics, Storage};
use commonware_storage::{
    index::Unordered as UnorderedIndex,
    journal::contiguous::Mutable,
    mmr::Location,
    qmdb::{
        any::{
            batch::{MerkleizedBatch, UnmerkleizedBatch},
            db::Db,
            operation::{update, Operation},
            ValueEncoding,
        },
        operation::Key,
        Error,
    },
    Persistable,
};

// ---------------------------------------------------------------------------
// DbMerkleized — owned wrapper pairing a MerkleizedBatch with phantom
// database type parameters so that ManagedDb::Unmerkleized<'a> can name
// the full UnmerkleizedBatch type.
// ---------------------------------------------------------------------------

impl<D, U> Merkleized for MerkleizedBatch<D, U>
where
    D: Digest,
    U: update::Update + Send + Sync,
    Operation<U>: Send + Sync,
{
    type Digest = D;

    fn root(&self) -> Self::Digest {
        self.root()
    }
}

// ---------------------------------------------------------------------------
// Unmerkleized — implemented on qmdb's UnmerkleizedBatch (unordered).
// ---------------------------------------------------------------------------

impl<'a, E, K, V, C, I, H> Unmerkleized<'a>
    for UnmerkleizedBatch<'a, E, C, I, H, update::Unordered<K, V>>
where
    E: Storage + Clock + Metrics,
    K: Key,
    V: ValueEncoding,
    C: Mutable<Item = Operation<update::Unordered<K, V>>>,
    I: UnorderedIndex<Value = Location> + 'static,
    H: Hasher,
    Operation<update::Unordered<K, V>>: Codec,
{
    type Key = K;
    type Value = V::Value;
    type Merkleized = MerkleizedBatch<H::Digest, update::Unordered<K, V>>;
    type Error = Error;

    async fn get(&self, key: &Self::Key) -> Result<Option<Self::Value>, Self::Error> {
        UnmerkleizedBatch::get(self, key).await
    }

    fn write(self, key: Self::Key, value: Option<Self::Value>) -> Self {
        UnmerkleizedBatch::write(self, key, value)
    }

    async fn merkleize(self) -> Result<Self::Merkleized, Self::Error> {
        UnmerkleizedBatch::merkleize(self, None).await
    }
}

// ---------------------------------------------------------------------------
// ManagedDb — implemented on qmdb's Db (unordered).
// ---------------------------------------------------------------------------

impl<E, K, V, C, I, H> ManagedDb for Db<E, C, I, H, update::Unordered<K, V>>
where
    E: Storage + Clock + Metrics,
    K: Key,
    V: ValueEncoding + 'static,
    C: Mutable<Item = Operation<update::Unordered<K, V>>>
        + Persistable<Error = commonware_storage::journal::Error>,
    I: UnorderedIndex<Value = Location> + 'static,
    H: Hasher,
    Operation<update::Unordered<K, V>>: Codec,
{
    type Unmerkleized<'a>
        = UnmerkleizedBatch<'a, E, C, I, H, update::Unordered<K, V>>
    where
        Self: 'a;
    type Merkleized = MerkleizedBatch<H::Digest, update::Unordered<K, V>>;
    type Error = Error;

    fn new_batch(&self) -> Self::Unmerkleized<'_> {
        Db::new_batch(self)
    }

    fn fork_batch<'a>(&'a self, parent: &'a Self::Merkleized) -> Self::Unmerkleized<'a> {
        parent.new_batch(self)
    }

    async fn finalize(&mut self, batch: Self::Merkleized) -> Result<(), Self::Error> {
        let changeset = batch.finalize();
        self.apply_batch(changeset).await?;
        self.commit().await
    }
}
