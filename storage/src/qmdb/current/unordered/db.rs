//! Shared implementation for unordered Current QMDB variants.
//!
//! This module contains impl blocks that are generic over `ValueEncoding`, allowing them to be
//! used by both fixed and variable unordered QMDB implementations.

use crate::{
    index::Unordered as UnorderedIndex,
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
};
use commonware_codec::Codec;
use commonware_cryptography::{DigestOf, Hasher};
use commonware_runtime::{Clock, Metrics, Storage};
use commonware_utils::Array;

/// Proof information for verifying a key has a particular value in the database.
pub type KeyValueProof<D, const N: usize> = OperationProof<D, N>;

/// The generic Db type for unordered Current QMDB variants.
///
/// This type is generic over the index type `I`, allowing it to be used with both regular
/// and partitioned indices.
pub type Db<E, C, K, V, I, H, const N: usize, S = Merkleized<DigestOf<H>>, D = Durable> =
    crate::qmdb::current::db::Db<E, C, I, H, Update<K, V>, N, S, D>;

// Functionality shared across all DB states, such as most non-mutating operations.
impl<
        E: Storage + Clock + Metrics,
        C: Contiguous<Item = Operation<K, V>>,
        K: Array,
        V: ValueEncoding,
        I: UnorderedIndex<Value = Location>,
        H: Hasher,
        const N: usize,
        S: State<DigestOf<H>>,
        D: DurabilityState,
    > Db<E, C, K, V, I, H, N, S, D>
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
        I: UnorderedIndex<Value = Location>,
        H: Hasher,
        const N: usize,
        D: store::State,
    > Db<E, C, K, V, I, H, N, Merkleized<DigestOf<H>>, D>
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
        I: UnorderedIndex<Value = Location>,
        H: Hasher,
        const N: usize,
    > Db<E, C, K, V, I, H, N, Unmerkleized, NonDurable>
where
    Operation<K, V>: Codec,
    V::Value: Send + Sync,
{
    /// Writes a batch of key-value pairs to the database.
    ///
    /// For each item in the iterator:
    /// - `(key, Some(value))` updates or creates the key with the given value
    /// - `(key, None)` deletes the key
    pub async fn write_batch(
        &mut self,
        iter: impl IntoIterator<Item = (K, Option<V::Value>)>,
    ) -> Result<(), Error> {
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

// Store implementation for all states
impl<
        E: Storage + Clock + Metrics,
        C: Contiguous<Item = Operation<K, V>>,
        K: Array,
        V: ValueEncoding,
        I: UnorderedIndex<Value = Location>,
        H: Hasher,
        const N: usize,
        S: State<DigestOf<H>>,
        D: DurabilityState,
    > kv::Gettable for Db<E, C, K, V, I, H, N, S, D>
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

// Batchable for (Unmerkleized, NonDurable) (aka mutable) state
impl<E, C, K, V, I, H, const N: usize> Batchable
    for Db<E, C, K, V, I, H, N, Unmerkleized, NonDurable>
where
    E: Storage + Clock + Metrics,
    C: MutableContiguous<Item = Operation<K, V>>,
    K: Array,
    V: ValueEncoding,
    I: UnorderedIndex<Value = Location> + 'static,
    H: Hasher,
    Operation<K, V>: Codec,
    V::Value: Send + Sync,
{
    async fn write_batch<'a, Iter>(&'a mut self, iter: Iter) -> Result<(), Error>
    where
        Iter: IntoIterator<Item = (K, Option<V::Value>)> + Send + 'a,
        Iter::IntoIter: Send,
    {
        self.write_batch(iter).await
    }
}
