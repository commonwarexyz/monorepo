//! Ordered current proofs with fixed-size or runtime-sized bitmap chunks.

use super::{COMMIT_CONTEXT, KEY_VALUE_CONTEXT};
use crate::{
    merkle::Graftable,
    qmdb::{
        any::{
            ValueEncoding,
            ordered::{Operation, Update, span_contains},
        },
        current::proof::operation::Proof as OperationProof,
        operation::Key,
    },
};
use bytes::{Buf, BufMut};
use commonware_codec::{Codec, EncodeSize, Read, ReadExt as _, Write};
use commonware_cryptography::{Digest, Hasher};

/// Proof information for verifying a key has a particular value in the database.
///
/// `C` stores the embedded operation proof's bitmap chunk.
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct KeyValueProof<F: Graftable, K: Key, D: Digest, C> {
    /// The proof authenticating the active update operation.
    pub proof: OperationProof<F, D, C>,

    /// The next active key in lexicographic order, wrapping at the end.
    pub next_key: K,
}

impl<F: Graftable, K: Key, D: Digest, C: AsRef<[u8]>> KeyValueProof<F, K, D, C> {
    /// Return true if the proof authenticates that `key` currently has `value` in the database
    /// with the provided `root`.
    ///
    /// `V` selects the fixed or variable value encoding used by the database.
    pub fn verify<H, V>(&self, key: K, value: V::Value, root: &D) -> bool
    where
        H: Hasher<Digest = D>,
        V: ValueEncoding,
        Operation<F, K, V>: Codec,
    {
        let op = Operation::<F, K, V>::Update(Update {
            key,
            value,
            next_key: self.next_key.clone(),
        });

        self.proof.verify::<H, _>(op, root)
    }
}

impl<F: Graftable, K: Key, D: Digest, C: AsRef<[u8]>> Write for KeyValueProof<F, K, D, C> {
    fn write(&self, buf: &mut impl BufMut) {
        self.proof.write(buf);
        self.next_key.write(buf);
    }
}

impl<F: Graftable, K: Key, D: Digest, C: AsRef<[u8]>> EncodeSize for KeyValueProof<F, K, D, C> {
    fn encode_size(&self) -> usize {
        self.proof.encode_size() + self.next_key.encode_size()
    }
}

impl<F: Graftable, K: Key, D: Digest, C> Read for KeyValueProof<F, K, D, C>
where
    OperationProof<F, D, C>: Read,
{
    /// `(proof_cfg, key_cfg)`: the read configurations for the embedded operation proof and key.
    type Cfg = (<OperationProof<F, D, C> as Read>::Cfg, <K as Read>::Cfg);

    fn read_cfg(
        buf: &mut impl Buf,
        (proof_cfg, key_cfg): &Self::Cfg,
    ) -> Result<Self, commonware_codec::Error> {
        let proof = OperationProof::<F, D, C>::read_cfg(buf, proof_cfg)?;
        let next_key = K::read_cfg(buf, key_cfg)?;
        Ok(Self { proof, next_key })
    }
}

#[cfg(feature = "arbitrary")]
impl<F: Graftable, K: Key, D: Digest, C> arbitrary::Arbitrary<'_> for KeyValueProof<F, K, D, C>
where
    K: for<'a> arbitrary::Arbitrary<'a>,
    OperationProof<F, D, C>: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            proof: u.arbitrary()?,
            next_key: u.arbitrary()?,
        })
    }
}

/// Proof that a key has no assigned value in the database.
///
/// When the database has active keys, exclusion is proven by showing the key falls within a span
/// between two adjacent active keys. Otherwise exclusion is proven by showing the database contains
/// no active keys through the most recent commit operation.
///
/// `C` stores the embedded operation proof's bitmap chunk. Verify using [Self::verify].
#[derive(Clone, Eq, PartialEq, Debug)]
pub enum ExclusionProof<F: Graftable, K: Key, V: ValueEncoding, D: Digest, C> {
    /// Proves that two keys are active in the database and adjacent to each other in the key
    /// ordering. Any key falling between them (non-inclusively) can be proven excluded.
    KeyValue(OperationProof<F, D, C>, Update<K, V>),

    /// Proves that the database has no active keys, allowing any key to be proven excluded.
    /// The commit operation's activity floor must equal its own location.
    Commit(OperationProof<F, D, C>, Option<V::Value>),
}

impl<F, K, V, D, C> ExclusionProof<F, K, V, D, C>
where
    F: Graftable,
    K: Key,
    V: ValueEncoding,
    D: Digest,
    C: AsRef<[u8]>,
    Operation<F, K, V>: Codec,
{
    /// Return true if the proof authenticates that `key` does not exist in the database with
    /// the provided `root`.
    pub fn verify<H: Hasher<Digest = D>>(&self, key: &K, root: &D) -> bool {
        let (op_proof, op) = match self {
            Self::KeyValue(op_proof, data) => {
                if data.key == *key || !span_contains(&data.key, &data.next_key, key) {
                    return false;
                }

                (op_proof, Operation::Update(data.clone()))
            }
            Self::Commit(op_proof, metadata) => {
                // An empty database's commit floor equals the commit operation's location
                (
                    op_proof,
                    Operation::CommitFloor(metadata.clone(), op_proof.loc),
                )
            }
        };

        op_proof.verify::<H, _>(op, root)
    }
}

impl<F, K, V, D, C> Write for ExclusionProof<F, K, V, D, C>
where
    F: Graftable,
    K: Key,
    V: ValueEncoding,
    D: Digest,
    C: AsRef<[u8]>,
    Update<K, V>: Write,
{
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::KeyValue(op_proof, update) => {
                KEY_VALUE_CONTEXT.write(buf);
                op_proof.write(buf);
                update.write(buf);
            }
            Self::Commit(op_proof, value) => {
                COMMIT_CONTEXT.write(buf);
                op_proof.write(buf);
                value.write(buf);
            }
        }
    }
}

impl<F, K, V, D, C> EncodeSize for ExclusionProof<F, K, V, D, C>
where
    F: Graftable,
    K: Key,
    V: ValueEncoding,
    D: Digest,
    C: AsRef<[u8]>,
    Update<K, V>: EncodeSize,
{
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::KeyValue(op_proof, update) => op_proof.encode_size() + update.encode_size(),
            Self::Commit(op_proof, value) => op_proof.encode_size() + value.encode_size(),
        }
    }
}

impl<F, K, V, D, C> Read for ExclusionProof<F, K, V, D, C>
where
    F: Graftable,
    K: Key,
    V: ValueEncoding,
    D: Digest,
    OperationProof<F, D, C>: Read,
    Update<K, V>: Read,
{
    /// `(proof_cfg, update_cfg, value_cfg)`: the read configurations for the embedded operation
    /// proof, [Update], and commit metadata value.
    type Cfg = (
        <OperationProof<F, D, C> as Read>::Cfg,
        <Update<K, V> as Read>::Cfg,
        <V::Value as Read>::Cfg,
    );

    fn read_cfg(
        buf: &mut impl Buf,
        (proof_cfg, update_cfg, value_cfg): &Self::Cfg,
    ) -> Result<Self, commonware_codec::Error> {
        match u8::read(buf)? {
            KEY_VALUE_CONTEXT => {
                let op_proof = OperationProof::<F, D, C>::read_cfg(buf, proof_cfg)?;
                let update = Update::<K, V>::read_cfg(buf, update_cfg)?;
                Ok(Self::KeyValue(op_proof, update))
            }
            COMMIT_CONTEXT => {
                let op_proof = OperationProof::<F, D, C>::read_cfg(buf, proof_cfg)?;
                let value = Option::<V::Value>::read_cfg(buf, value_cfg)?;
                Ok(Self::Commit(op_proof, value))
            }
            tag => Err(commonware_codec::Error::InvalidEnum(tag)),
        }
    }
}

#[cfg(feature = "arbitrary")]
impl<F, K, V, D, C> arbitrary::Arbitrary<'_> for ExclusionProof<F, K, V, D, C>
where
    F: Graftable,
    K: Key + for<'a> arbitrary::Arbitrary<'a>,
    V: ValueEncoding,
    D: Digest,
    V::Value: for<'a> arbitrary::Arbitrary<'a>,
    OperationProof<F, D, C>: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let op_proof = u.arbitrary()?;
        if u.arbitrary()? {
            Ok(Self::KeyValue(op_proof, u.arbitrary()?))
        } else {
            Ok(Self::Commit(op_proof, u.arbitrary()?))
        }
    }
}
