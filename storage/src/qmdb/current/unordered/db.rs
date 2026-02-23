//! Shared implementation for unordered Current QMDB variants.
//!
//! This module contains impl blocks that are generic over `Encoding`, allowing them to be
//! used by both fixed and variable unordered QMDB implementations.

use crate::{
    index::Unordered as UnorderedIndex,
    journal::contiguous::{Contiguous, Mutable},
    kv::{self, Batchable},
    mmr::Location,
    qmdb::{
        any::{
            encoding::Encoding,
            operation::update::Unordered as UnorderedUpdate,
            unordered::{Operation, Update},
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
use commonware_utils::{bitmap::Prunable as BitMap, Array};

/// Proof information for verifying a key has a particular value in the database.
pub type KeyValueProof<D, const N: usize> = OperationProof<D, N>;

/// The generic Db type for unordered Current QMDB variants.
///
/// This type is generic over the index type `I`, allowing it to be used with both regular
/// and partitioned indices.
pub type Db<E, C, KV, I, H, const N: usize, S = Merkleized<DigestOf<H>>, D = Durable> =
    crate::qmdb::current::db::Db<E, C, I, H, Update<KV>, N, S, D>;

// Functionality shared across all DB states, such as most non-mutating operations.
impl<
        E: Storage + Clock + Metrics,
        C: Contiguous<Item = Operation<KV>>,
        KV: Encoding,
        I: UnorderedIndex<Value = Location>,
        H: Hasher,
        const N: usize,
        S: State<DigestOf<H>>,
        D: DurabilityState,
    > Db<E, C, KV, I, H, N, S, D>
where
    KV::Key: Array,
    Operation<KV>: Codec,
    KV::Value: Send + Sync,
{
    /// Get the value of `key` in the db, or None if it has no value.
    pub async fn get(&self, key: &KV::Key) -> Result<Option<KV::Value>, Error> {
        self.any.get(key).await
    }

    /// Return true if the proof authenticates that `key` currently has value `value` in the db with
    /// the provided `root`.
    pub fn verify_key_value_proof(
        hasher: &mut H,
        key: KV::Key,
        value: KV::Value,
        proof: &KeyValueProof<H::Digest, N>,
        root: &H::Digest,
    ) -> bool {
        let op = Operation::Update(UnorderedUpdate(key, value));

        proof.verify(hasher, op, root)
    }
}

// Functionality for any Merkleized state (both Durable and NonDurable).
impl<
        E: Storage + Clock + Metrics,
        C: Mutable<Item = Operation<KV>>,
        KV: Encoding,
        I: UnorderedIndex<Value = Location>,
        H: Hasher,
        const N: usize,
        D: store::State,
    > Db<E, C, KV, I, H, N, Merkleized<DigestOf<H>>, D>
where
    KV::Key: Array,
    Operation<KV>: Codec,
    KV::Value: Send + Sync,
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
        key: KV::Key,
    ) -> Result<KeyValueProof<H::Digest, N>, Error> {
        let op_loc = self.any.get_with_loc(&key).await?;
        let Some((_, loc)) = op_loc else {
            return Err(Error::KeyNotFound);
        };
        self.operation_proof(hasher, loc).await
    }
}

// Functionality for the Mutable state.
impl<
        E: Storage + Clock + Metrics,
        C: Mutable<Item = Operation<KV>>,
        KV: Encoding,
        I: UnorderedIndex<Value = Location>,
        H: Hasher,
        const N: usize,
    > Db<E, C, KV, I, H, N, Unmerkleized, NonDurable>
where
    KV::Key: Array,
    Operation<KV>: Codec,
    KV::Value: Send + Sync,
{
    /// Writes a batch of key-value pairs to the database.
    ///
    /// For each item in the iterator:
    /// - `(key, Some(value))` updates or creates the key with the given value
    /// - `(key, None)` deletes the key
    pub async fn write_batch(
        &mut self,
        iter: impl IntoIterator<Item = (KV::Key, Option<KV::Value>)>,
    ) -> Result<(), Error> {
        let old_grafted_leaves = *self.grafted_mmr.leaves() as usize;
        let status = &mut self.status;
        let dirty_chunks = &mut self.state.dirty_chunks;
        self.any
            .write_batch_with_callback(iter, move |append: bool, loc: Option<Location>| {
                status.push(append);
                if let Some(loc) = loc {
                    status.set_bit(*loc, false);
                    let chunk = BitMap::<N>::to_chunk_index(*loc);
                    if chunk < old_grafted_leaves {
                        dirty_chunks.insert(chunk);
                    }
                }
            })
            .await
    }
}

// Store implementation for all states
impl<
        E: Storage + Clock + Metrics,
        C: Contiguous<Item = Operation<KV>>,
        KV: Encoding,
        I: UnorderedIndex<Value = Location>,
        H: Hasher,
        const N: usize,
        S: State<DigestOf<H>>,
        D: DurabilityState,
    > kv::Gettable for Db<E, C, KV, I, H, N, S, D>
where
    KV::Key: Array,
    Operation<KV>: Codec,
    KV::Value: Send + Sync,
{
    type Key = KV::Key;
    type Value = KV::Value;
    type Error = Error;

    async fn get(&self, key: &Self::Key) -> Result<Option<Self::Value>, Self::Error> {
        self.get(key).await
    }
}

// Batchable for (Unmerkleized, NonDurable) (aka mutable) state
impl<E, C, KV, I, H, const N: usize> Batchable for Db<E, C, KV, I, H, N, Unmerkleized, NonDurable>
where
    E: Storage + Clock + Metrics,
    C: Mutable<Item = Operation<KV>>,
    KV: Encoding,
    KV::Key: Array,
    I: UnorderedIndex<Value = Location> + 'static,
    H: Hasher,
    Operation<KV>: Codec,
    KV::Value: Send + Sync,
{
    async fn write_batch<'a, Iter>(&'a mut self, iter: Iter) -> Result<(), Error>
    where
        Iter: IntoIterator<Item = (KV::Key, Option<KV::Value>)> + Send + 'a,
        Iter::IntoIter: Send,
    {
        self.write_batch(iter).await
    }
}
