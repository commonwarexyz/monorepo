//! Shared implementation for unordered Current QMDB variants.
//!
//! This module contains impl blocks that are generic over `ValueEncoding`, allowing them to be
//! used by both fixed and variable unordered QMDB implementations.

use super::proof::constant::KeyValueProof;
use crate::{
    Context,
    index::Unordered as UnorderedIndex,
    journal::contiguous::Mutable,
    merkle::{self, Location},
    qmdb::{
        Error,
        any::unordered::{Operation, Update},
        operation::Key,
        value::ValueEncoding,
    },
};
use commonware_codec::Codec;
use commonware_cryptography::Hasher;
use commonware_parallel::Strategy;

/// The generic Db type for unordered Current QMDB variants.
///
/// This type is generic over the index type `I`, allowing it to be used with both regular
/// and partitioned indices.
pub type Db<F, E, C, K, V, I, H, const N: usize, S> =
    crate::qmdb::current::Db<F, E, C, I, H, Update<K, V>, N, S>;

impl<
    F: merkle::Graftable,
    E: Context,
    C: Mutable<Item = Operation<F, K, V>>,
    K: Key,
    V: ValueEncoding,
    I: UnorderedIndex<Value = Location<F>>,
    H: Hasher,
    const N: usize,
    S: Strategy,
> Db<F, E, C, K, V, I, H, N, S>
where
    Operation<F, K, V>: Codec,
{
    /// Return a proof authenticating the current value of `key` against [`Self::root`], and that
    /// value.
    ///
    /// # Errors
    ///
    /// Returns [Error::KeyNotFound] if the key is not currently assigned any value.
    pub async fn key_value_proof(
        &self,
        key: &K,
    ) -> Result<(KeyValueProof<F, H::Digest, N>, V::Value), Error<F>> {
        let op_loc = self.any.get_with_loc(key).await?;
        let Some((Update(_, value), loc)) = op_loc else {
            return Err(Error::<F>::KeyNotFound);
        };
        let proof = self.operation_proof(loc).await?;
        Ok((KeyValueProof { proof }, value))
    }
}
