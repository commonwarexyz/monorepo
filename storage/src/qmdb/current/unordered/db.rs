//! Shared implementation for unordered Current QMDB variants.
//!
//! This module contains impl blocks that are generic over `ValueEncoding`, allowing them to be
//! used by both fixed and variable unordered QMDB implementations.

use crate::{
    index::unordered::Index,
    journal::contiguous::{Contiguous, MutableContiguous},
    kv::{self, Batchable},
    mmr::Location,
    qmdb::{
        any::{
            operation::update::Unordered as UnorderedUpdate,
            unordered::{Operation, Update},
            ValueEncoding,
        },
        current::{
            db::{Merkleized, State, Unmerkleized},
            proof::OperationProof,
        },
        store, DurabilityState, Durable, Error, NonDurable,
    },
    translator::Translator,
};
use commonware_codec::Codec;
use commonware_cryptography::{DigestOf, Hasher};
use commonware_runtime::{Clock, Metrics, Storage};
use commonware_utils::Array;

/// Proof information for verifying a key has a particular value in the database.
pub type KeyValueProof<D, const N: usize> = OperationProof<D, N>;

/// The generic Db type for unordered Current QMDB variants.
pub type Db<E, C, K, V, H, T, const N: usize, S = Merkleized<DigestOf<H>>, D = Durable> =
    super::super::db::Db<E, C, Index<T, Location>, H, Update<K, V>, N, S, D>;

// Functionality shared across all DB states, such as most non-mutating operations.
impl<
        E: Storage + Clock + Metrics,
        C: Contiguous<Item = Operation<K, V>>,
        K: Array,
        V: ValueEncoding,
        H: Hasher,
        T: Translator,
        const N: usize,
        S: State<DigestOf<H>>,
        D: DurabilityState,
    > Db<E, C, K, V, H, T, N, S, D>
where
    Operation<K, V>: Codec,
    V::Value: Send + Sync,
{
    /// Get the value of `key` in the db, or None if it has no value.
    pub async fn get(&self, key: &K) -> Result<Option<V::Value>, Error> {
        self.any.get(key).await
    }

    /// Return true if the proof authenticates that `key` currently has value `value` in the db with
    /// the provided `root`.
    pub fn verify_key_value_proof(
        hasher: &mut H,
        key: K,
        value: V::Value,
        proof: &KeyValueProof<H::Digest, N>,
        root: &H::Digest,
    ) -> bool {
        let op = Operation::Update(UnorderedUpdate(key, value));

        proof.verify(hasher, Self::grafting_height(), op, root)
    }
}

// Functionality for any Merkleized state (both Durable and NonDurable).
impl<
        E: Storage + Clock + Metrics,
        C: MutableContiguous<Item = Operation<K, V>>,
        K: Array,
        V: ValueEncoding,
        H: Hasher,
        T: Translator,
        const N: usize,
        D: store::State,
    > Db<E, C, K, V, H, T, N, Merkleized<DigestOf<H>>, D>
where
    Operation<K, V>: Codec,
    V::Value: Send + Sync,
{
    /// Generate and return a proof of the current value of `key`, along with the other
    /// [KeyValueProof] required to verify the proof. Returns KeyNotFound error if the key is not
    /// currently assigned any value.
    ///
    /// # Errors
    ///
    /// Returns [Error::KeyNotFound] if the key is not currently assigned any value.
    pub async fn key_value_proof(
        &self,
        hasher: &mut H,
        key: K,
    ) -> Result<KeyValueProof<H::Digest, N>, Error> {
        let op_loc = self.any.get_with_loc(&key).await?;
        let Some((_, loc)) = op_loc else {
            return Err(Error::KeyNotFound);
        };
        let height = Self::grafting_height();
        let mmr = &self.any.log.mmr;

        OperationProof::<H::Digest, N>::new(hasher, &self.status, height, mmr, loc).await
    }
}

// Functionality for the Mutable state.
impl<
        E: Storage + Clock + Metrics,
        C: MutableContiguous<Item = Operation<K, V>>,
        K: Array,
        V: ValueEncoding,
        H: Hasher,
        T: Translator,
        const N: usize,
    > Db<E, C, K, V, H, T, N, Unmerkleized, NonDurable>
where
    Operation<K, V>: Codec,
    V::Value: Send + Sync,
{
    /// Updates `key` to have value `value`. The operation is reflected in the snapshot, but will be
    /// subject to rollback until the next successful `commit`.
    pub async fn update(&mut self, key: K, value: V::Value) -> Result<(), Error> {
        if let Some(old_loc) = self.any.update_key(key, value).await? {
            self.status.set_bit(*old_loc, false);
        }
        self.status.push(true);

        Ok(())
    }

    /// Creates a new key-value pair in the db. The operation is reflected in the snapshot, but will
    /// be subject to rollback until the next successful `commit`. Returns true if the key was
    /// created, false if it already existed.
    pub async fn create(&mut self, key: K, value: V::Value) -> Result<bool, Error> {
        if !self.any.create(key, value).await? {
            return Ok(false);
        }
        self.status.push(true);

        Ok(true)
    }

    /// Delete `key` and its value from the db. Deleting a key that already has no value is a no-op.
    /// The operation is reflected in the snapshot, but will be subject to rollback until the next
    /// successful `commit`. Returns true if the key was deleted, false if it was already inactive.
    pub async fn delete(&mut self, key: K) -> Result<bool, Error> {
        let Some(loc) = self.any.delete_key(key).await? else {
            return Ok(false);
        };

        self.status.push(false);
        self.status.set_bit(*loc, false);

        Ok(true)
    }
}

// Store implementation for all states
impl<
        E: Storage + Clock + Metrics,
        C: Contiguous<Item = Operation<K, V>>,
        K: Array,
        V: ValueEncoding,
        H: Hasher,
        T: Translator,
        const N: usize,
        S: State<DigestOf<H>>,
        D: DurabilityState,
    > kv::Gettable for Db<E, C, K, V, H, T, N, S, D>
where
    Operation<K, V>: Codec,
    V::Value: Send + Sync,
{
    type Key = K;
    type Value = V::Value;
    type Error = Error;

    async fn get(&self, key: &Self::Key) -> Result<Option<Self::Value>, Self::Error> {
        self.get(key).await
    }
}

// StoreMut for (Unmerkleized, NonDurable) (aka mutable) state
impl<
        E: Storage + Clock + Metrics,
        C: MutableContiguous<Item = Operation<K, V>>,
        K: Array,
        V: ValueEncoding,
        H: Hasher,
        T: Translator,
        const N: usize,
    > kv::Updatable for Db<E, C, K, V, H, T, N, Unmerkleized, NonDurable>
where
    Operation<K, V>: Codec,
    V::Value: Send + Sync,
{
    async fn update(&mut self, key: Self::Key, value: Self::Value) -> Result<(), Self::Error> {
        self.update(key, value).await
    }
}

// StoreDeletable for (Unmerkleized, NonDurable) (aka mutable) state
impl<
        E: Storage + Clock + Metrics,
        C: MutableContiguous<Item = Operation<K, V>>,
        K: Array,
        V: ValueEncoding,
        H: Hasher,
        T: Translator,
        const N: usize,
    > kv::Deletable for Db<E, C, K, V, H, T, N, Unmerkleized, NonDurable>
where
    Operation<K, V>: Codec,
    V::Value: Send + Sync,
{
    async fn delete(&mut self, key: Self::Key) -> Result<bool, Self::Error> {
        self.delete(key).await
    }
}

// Batchable for (Unmerkleized, NonDurable) (aka mutable) state
impl<E, C, K, V, T, H, const N: usize> Batchable
    for Db<E, C, K, V, H, T, N, Unmerkleized, NonDurable>
where
    E: Storage + Clock + Metrics,
    C: MutableContiguous<Item = Operation<K, V>>,
    K: Array,
    V: ValueEncoding,
    T: Translator,
    H: Hasher,
    Operation<K, V>: Codec,
    V::Value: Send + Sync,
{
    async fn write_batch<'a, Iter>(&'a mut self, iter: Iter) -> Result<(), Error>
    where
        Iter: Iterator<Item = (K, Option<V::Value>)> + Send + 'a,
    {
        let status = &mut self.status;
        self.any
            .write_batch_with_callback(iter, move |append: bool, loc: Option<Location>| {
                status.push(append);
                if let Some(loc) = loc {
                    status.set_bit(*loc, false);
                }
            })
            .await
    }
}
