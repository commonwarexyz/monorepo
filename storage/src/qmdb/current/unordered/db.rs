//! Shared implementation for unordered Current QMDB variants.
//!
//! This module contains impl blocks that are generic over `ValueEncoding`, allowing them to be
//! used by both fixed and variable unordered QMDB implementations.

use crate::{
    index::Unordered as UnorderedIndex,
    journal::contiguous::{Contiguous, Mutable},
    merkle::{self, Location},
    qmdb::{
        any::{
            operation::update::Unordered as UnorderedUpdate,
            unordered::{Operation, Update},
            ValueEncoding,
        },
        current::proof::OperationProof,
        Error,
    },
    Context,
};
use commonware_codec::Codec;
use commonware_cryptography::Hasher;
use commonware_parallel::{Sequential, Strategy};
use commonware_utils::Array;

/// Proof information for verifying a key has a particular value in the database.
pub type KeyValueProof<F, D, const N: usize> = OperationProof<F, D, N>;

/// The generic Db type for unordered Current QMDB variants.
///
/// This type is generic over the index type `I`, allowing it to be used with both regular
/// and partitioned indices.
pub type Db<F, E, C, K, V, I, H, const N: usize, S = Sequential> =
    crate::qmdb::current::db::Db<F, E, C, I, H, Update<K, V>, N, S>;

// Shared read-only functionality.
impl<
        F: merkle::Graftable,
        E: Context,
        C: Contiguous<Item = Operation<F, K, V>>,
        K: Array,
        V: ValueEncoding,
        I: UnorderedIndex<Value = Location<F>>,
        H: Hasher,
        const N: usize,
        S: Strategy,
    > Db<F, E, C, K, V, I, H, N, S>
where
    Operation<F, K, V>: Codec,
{
    /// Get the value of `key` in the db, or None if it has no value.
    pub async fn get(&self, key: &K) -> Result<Option<V::Value>, Error<F>> {
        self.any.get(key).await
    }

    /// Return true if the proof authenticates that `key` currently has value `value` in the db with
    /// the provided `root`.
    pub fn verify_key_value_proof(
        hasher: &mut H,
        key: K,
        value: V::Value,
        proof: &KeyValueProof<F, H::Digest, N>,
        root: &H::Digest,
    ) -> bool {
        let op = Operation::Update(UnorderedUpdate(key, value));

        proof.verify(hasher, op, root)
    }
}

impl<
        F: merkle::Graftable,
        E: Context,
        C: Mutable<Item = Operation<F, K, V>>,
        K: Array,
        V: ValueEncoding,
        I: UnorderedIndex<Value = Location<F>>,
        H: Hasher,
        const N: usize,
        S: Strategy,
    > Db<F, E, C, K, V, I, H, N, S>
where
    Operation<F, K, V>: Codec,
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
    ) -> Result<KeyValueProof<F, H::Digest, N>, Error<F>> {
        let op_loc = self.any.get_with_loc(&key).await?;
        let Some((_, loc)) = op_loc else {
            return Err(Error::<F>::KeyNotFound);
        };
        self.operation_proof(hasher, loc).await
    }
}
