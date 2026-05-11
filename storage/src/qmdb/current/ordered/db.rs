//! Shared implementation for ordered Current QMDB variants.
//!
//! This module contains impl blocks that are generic over `ValueEncoding`, allowing them to be
//! used by both fixed and variable ordered QMDB implementations.

use crate::{
    index::Ordered as OrderedIndex,
    journal::contiguous::{Contiguous, Mutable, Reader},
    merkle::{self, hasher::Standard as StandardHasher, Location},
    qmdb::{
        any::{
            ordered::{Operation, Update},
            ValueEncoding,
        },
        current::proof::OperationProof,
        operation::Key,
        Error,
    },
    Context,
};
use bytes::{Buf, BufMut};
use commonware_codec::{Codec, EncodeSize, Read, Write};
use commonware_cryptography::{Digest, Hasher};
use commonware_parallel::{Sequential, Strategy};
use futures::stream::Stream;

/// Proof information for verifying a key has a particular value in the database.
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct KeyValueProof<F: merkle::Family, K: Key, D: Digest, const N: usize> {
    pub proof: OperationProof<F, D, N>,
    pub next_key: K,
}

impl<F: merkle::Family, K: Key, D: Digest, const N: usize> Write for KeyValueProof<F, K, D, N> {
    fn write(&self, buf: &mut impl BufMut) {
        self.proof.write(buf);
        self.next_key.write(buf);
    }
}

impl<F: merkle::Family, K: Key, D: Digest, const N: usize> EncodeSize
    for KeyValueProof<F, K, D, N>
{
    fn encode_size(&self) -> usize {
        self.proof.encode_size() + self.next_key.encode_size()
    }
}

impl<F: merkle::Family, K: Key, D: Digest, const N: usize> Read for KeyValueProof<F, K, D, N> {
    /// `(max_digests, key_cfg)`: the Merkle digest cap forwarded to the embedded operation
    /// proof and the read configuration for the key type.
    type Cfg = (usize, <K as Read>::Cfg);

    fn read_cfg(
        buf: &mut impl Buf,
        (max_digests, key_cfg): &Self::Cfg,
    ) -> Result<Self, commonware_codec::Error> {
        let proof = OperationProof::<F, D, N>::read_cfg(buf, max_digests)?;
        let next_key = K::read_cfg(buf, key_cfg)?;
        Ok(Self { proof, next_key })
    }
}

#[cfg(feature = "arbitrary")]
impl<F: merkle::Family, K: Key, D: Digest, const N: usize> arbitrary::Arbitrary<'_>
    for KeyValueProof<F, K, D, N>
where
    K: for<'a> arbitrary::Arbitrary<'a>,
    D: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            proof: u.arbitrary()?,
            next_key: u.arbitrary()?,
        })
    }
}

/// The generic Db type for ordered Current QMDB variants.
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
        K: Key,
        V: ValueEncoding,
        I: OrderedIndex<Value = Location<F>>,
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
        hasher: &StandardHasher<H>,
        key: K,
        value: V::Value,
        proof: &KeyValueProof<F, K, H::Digest, N>,
        root: &H::Digest,
    ) -> bool {
        let op = Operation::Update(Update {
            key,
            value,
            next_key: proof.next_key.clone(),
        });

        proof.proof.verify(hasher, op, root)
    }

    /// Get the operation that currently defines the span whose range contains `key`, or None if the
    /// DB is empty.
    pub async fn get_span(&self, key: &K) -> Result<Option<(Location<F>, Update<K, V>)>, Error<F>> {
        self.any.get_span(key).await
    }

    /// Streams all active (key, value) pairs in the database in key order, starting from the first
    /// active key greater than or equal to `start`.
    pub async fn stream_range<'a>(
        &'a self,
        start: K,
    ) -> Result<impl Stream<Item = Result<(K, V::Value), Error<F>>> + 'a, Error<F>>
    where
        V: 'a,
    {
        self.any.stream_range(start).await
    }

    /// Return true if the proof authenticates that `key` does _not_ exist in the db with the
    /// provided `root`.
    pub fn verify_exclusion_proof(
        hasher: &StandardHasher<H>,
        key: &K,
        proof: &super::ExclusionProof<F, K, V, H::Digest, N>,
        root: &H::Digest,
    ) -> bool {
        let (op_proof, op) = match proof {
            super::ExclusionProof::KeyValue(op_proof, data) => {
                if data.key == *key {
                    // The provided `key` is in the DB if it matches the start of the span.
                    return false;
                }
                if !crate::qmdb::any::db::Db::<F, E, C, I, H, Update<K, V>>::span_contains(
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

        op_proof.verify(hasher, op, root)
    }
}

impl<
        F: merkle::Graftable,
        E: Context,
        C: Mutable<Item = Operation<F, K, V>>,
        K: Key,
        V: ValueEncoding,
        I: OrderedIndex<Value = Location<F>>,
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
        hasher: &StandardHasher<H>,
        key: K,
    ) -> Result<KeyValueProof<F, K, H::Digest, N>, Error<F>> {
        let op_loc = self.any.get_with_loc(&key).await?;
        let Some((data, loc)) = op_loc else {
            return Err(Error::<F>::KeyNotFound);
        };
        let proof = self.operation_proof(hasher, loc).await?;

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
        hasher: &StandardHasher<H>,
        key: &K,
    ) -> Result<super::ExclusionProof<F, K, V, H::Digest, N>, Error<F>> {
        match self.any.get_span(key).await? {
            Some((loc, key_data)) => {
                if key_data.key == *key {
                    // Cannot prove exclusion of a key that exists in the db.
                    return Err(Error::<F>::KeyExists);
                }
                let op_proof = self.operation_proof(hasher, loc).await?;
                Ok(super::ExclusionProof::KeyValue(op_proof, key_data))
            }
            None => {
                // The DB is empty. Use the last CommitFloor to prove emptiness. The Commit proof
                // variant requires the CommitFloor's floor to equal its own location (genuinely
                // empty at commit time). If this doesn't hold, the persisted state is inconsistent.
                let op = self
                    .any
                    .log
                    .reader()
                    .await
                    .read(*self.any.last_commit_loc)
                    .await?;
                let Operation::CommitFloor(value, floor) = op else {
                    unreachable!("last_commit_loc should always point to a CommitFloor");
                };
                assert_eq!(
                    floor, self.any.last_commit_loc,
                    "inconsistent commit floor: expected last_commit_loc={}, got floor={}",
                    self.any.last_commit_loc, floor
                );
                let op_proof = self
                    .operation_proof(hasher, self.any.last_commit_loc)
                    .await?;
                Ok(super::ExclusionProof::Commit(op_proof, value))
            }
        }
    }
}
