//! Shared implementation for ordered Current QMDB variants.
//!
//! This module contains impl blocks that are generic over `ValueEncoding`, allowing them to be
//! used by both fixed and variable ordered QMDB implementations.

use crate::{
    index::ordered::Index,
    journal::contiguous::{Contiguous, MutableContiguous},
    kv::{self, Batchable},
    mmr::{grafting::Storage as GraftingStorage, Location},
    qmdb::{
        any::{
            ordered::{Operation, Update},
            ValueEncoding,
        },
        current::proof::OperationProof,
        store, DurabilityState, Durable, Error, MerkleizationState, Merkleized, NonDurable,
        Unmerkleized,
    },
    translator::Translator,
};
use commonware_codec::Codec;
use commonware_cryptography::{Digest, DigestOf, Hasher};
use commonware_runtime::{Clock, Metrics, Storage};
use commonware_utils::Array;
use futures::stream::Stream;

/// Proof information for verifying a key has a particular value in the database.
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct KeyValueProof<K: Array, D: Digest, const N: usize> {
    pub proof: OperationProof<D, N>,
    pub next_key: K,
}

/// The generic Db type for ordered Current QMDB variants.
pub type Db<E, C, K, V, H, T, const N: usize, S = Merkleized<H>, D = Durable> =
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
        M: MerkleizationState<DigestOf<H>>,
        D: DurabilityState,
    > Db<E, C, K, V, H, T, N, M, D>
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
        proof: &KeyValueProof<K, H::Digest, N>,
        root: &H::Digest,
    ) -> bool {
        let op = Operation::Update(Update {
            key,
            value,
            next_key: proof.next_key.clone(),
        });

        proof
            .proof
            .verify(hasher, Self::grafting_height(), op, root)
    }

    /// Get the operation that currently defines the span whose range contains `key`, or None if the
    /// DB is empty.
    pub async fn get_span(&self, key: &K) -> Result<Option<(Location, Update<K, V>)>, Error> {
        self.any.get_span(key).await
    }

    /// Streams all active (key, value) pairs in the database in key order, starting from the first
    /// active key greater than or equal to `start`.
    pub async fn stream_range<'a>(
        &'a self,
        start: K,
    ) -> Result<impl Stream<Item = Result<(K, V::Value), Error>> + 'a, Error>
    where
        V: 'a,
    {
        self.any.stream_range(start).await
    }

    /// Return true if the proof authenticates that `key` does _not_ exist in the db with the
    /// provided `root`.
    pub fn verify_exclusion_proof(
        hasher: &mut H,
        key: &K,
        proof: &super::ExclusionProof<K, V, H::Digest, N>,
        root: &H::Digest,
    ) -> bool {
        let (op_proof, op) = match proof {
            super::ExclusionProof::KeyValue(op_proof, data) => {
                if data.key == *key {
                    // The provided `key` is in the DB if it matches the start of the span.
                    return false;
                }
                if !crate::qmdb::any::db::Db::<E, C, Index<T, Location>, H, Update<K, V>, M, D>::span_contains(
                    &data.key,
                    &data.next_key,
                    key,
                ) {
                    // If the key is not within the span, then this proof cannot prove its
                    // exclusion.
                    return false;
                }

                (op_proof, Operation::Update(data.clone()))
            }
            super::ExclusionProof::Commit(op_proof, metadata) => {
                // Handle the case where the proof shows the db is empty, hence any key is proven
                // excluded. For the db to be empty, the floor must equal the commit operation's
                // location.
                let floor_loc = op_proof.loc;
                (
                    op_proof,
                    Operation::CommitFloor(metadata.clone(), floor_loc),
                )
            }
        };

        op_proof.verify(hasher, Self::grafting_height(), op, root)
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
    > Db<E, C, K, V, H, T, N, Merkleized<H>, D>
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
    ) -> Result<KeyValueProof<K, H::Digest, N>, Error> {
        let op_loc = self.any.get_with_loc(&key).await?;
        let Some((data, loc)) = op_loc else {
            return Err(Error::KeyNotFound);
        };
        let height = Self::grafting_height();
        let mmr = &self.any.log.mmr;
        let proof =
            OperationProof::<H::Digest, N>::new(hasher, &self.status, height, mmr, loc).await?;

        Ok(KeyValueProof {
            proof,
            next_key: data.next_key,
        })
    }

    /// Generate and return a proof that the specified `key` does not exist in the db.
    ///
    /// # Errors
    ///
    /// Returns [Error::KeyExists] if the key exists in the db.
    pub async fn exclusion_proof(
        &self,
        hasher: &mut H,
        key: &K,
    ) -> Result<super::ExclusionProof<K, V, H::Digest, N>, Error> {
        let height = Self::grafting_height();
        let grafted_mmr =
            GraftingStorage::<'_, H, _, _>::new(&self.status, &self.any.log.mmr, height);

        let span = self.any.get_span(key).await?;
        let loc = match &span {
            Some((loc, key_data)) => {
                if key_data.key == *key {
                    // Cannot prove exclusion of a key that exists in the db.
                    return Err(Error::KeyExists);
                }
                *loc
            }
            None => self
                .op_count()
                .checked_sub(1)
                .expect("db shouldn't be empty"),
        };

        let op_proof =
            OperationProof::<H::Digest, N>::new(hasher, &self.status, height, &grafted_mmr, loc)
                .await?;

        Ok(match span {
            Some((_, key_data)) => super::ExclusionProof::KeyValue(op_proof, key_data),
            None => {
                let value = match self.any.log.read(loc).await? {
                    Operation::CommitFloor(value, _) => value,
                    _ => unreachable!("last commit is not a CommitFloor operation"),
                };
                super::ExclusionProof::Commit(op_proof, value)
            }
        })
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
        self.any
            .update_with_callback(key, value, |loc| {
                self.status.push(true);
                if let Some(loc) = loc {
                    self.status.set_bit(*loc, false);
                }
            })
            .await
    }

    /// Creates a new key-value pair in the db. The operation is reflected in the snapshot, but will
    /// be subject to rollback until the next successful `commit`. Returns true if the key was
    /// created, false if it already existed.
    pub async fn create(&mut self, key: K, value: V::Value) -> Result<bool, Error> {
        self.any
            .create_with_callback(key, value, |loc| {
                self.status.push(true);
                if let Some(loc) = loc {
                    self.status.set_bit(*loc, false);
                }
            })
            .await
    }

    /// Delete `key` and its value from the db. Deleting a key that already has no value is a no-op.
    /// The operation is reflected in the snapshot, but will be subject to rollback until the next
    /// successful `commit`. Returns true if the key was deleted, false if it was already inactive.
    pub async fn delete(&mut self, key: K) -> Result<bool, Error> {
        let mut r = false;
        self.any
            .delete_with_callback(key, |append, loc| {
                if let Some(loc) = loc {
                    self.status.set_bit(*loc, false);
                }
                self.status.push(append);
                r = true;
            })
            .await?;

        Ok(r)
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
        M: MerkleizationState<DigestOf<H>>,
        D: DurabilityState,
    > kv::Gettable for Db<E, C, K, V, H, T, N, M, D>
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
