//! Shared implementation for unordered Current QMDB variants.
//!
//! This module contains impl blocks that are generic over `ValueEncoding`, allowing them to be
//! used by both fixed and variable unordered QMDB implementations.

use crate::{
    index::Unordered as UnorderedIndex,
    journal::contiguous::{Contiguous, Mutable},
    kv,
    mmr::Location,
    qmdb::{
        any::{
            operation::update::Unordered as UnorderedUpdate,
            unordered::{Operation, Update},
            ValueEncoding,
        },
        current::proof::OperationProof,
        Error,
    },
};
use commonware_codec::Codec;
use commonware_cryptography::Hasher;
use commonware_runtime::{Clock, Metrics, Storage};
use commonware_utils::Array;

/// Proof information for verifying a key has a particular value in the database.
pub type KeyValueProof<D, const N: usize> = OperationProof<D, N>;

/// The generic Db type for unordered Current QMDB variants.
///
/// This type is generic over the index type `I`, allowing it to be used with both regular
/// and partitioned indices.
pub type Db<E, C, K, V, I, H, const N: usize> =
    crate::qmdb::current::db::Db<E, C, I, H, Update<K, V>, N>;

// Shared read-only functionality.
impl<
        E: Storage + Clock + Metrics,
        C: Contiguous<Item = Operation<K, V>>,
        K: Array,
        V: ValueEncoding,
        I: UnorderedIndex<Value = Location>,
        H: Hasher,
        const N: usize,
    > Db<E, C, K, V, I, H, N>
where
    Operation<K, V>: Codec,
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

        proof.verify(hasher, op, root)
    }
}

impl<
        E: Storage + Clock + Metrics,
        C: Mutable<Item = Operation<K, V>>,
        K: Array,
        V: ValueEncoding,
        I: UnorderedIndex<Value = Location>,
        H: Hasher,
        const N: usize,
    > Db<E, C, K, V, I, H, N>
where
    Operation<K, V>: Codec,
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
        self.operation_proof(hasher, loc).await
    }
}

// Store implementation
impl<
        E: Storage + Clock + Metrics,
        C: Contiguous<Item = Operation<K, V>>,
        K: Array,
        V: ValueEncoding,
        I: UnorderedIndex<Value = Location>,
        H: Hasher,
        const N: usize,
    > kv::Gettable for Db<E, C, K, V, I, H, N>
where
    Operation<K, V>: Codec,
{
    type Key = K;
    type Value = V::Value;
    type Error = Error;

    async fn get(&self, key: &Self::Key) -> Result<Option<Self::Value>, Self::Error> {
        self.get(key).await
    }
}
