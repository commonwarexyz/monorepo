//! Ordered current proofs with fixed-size or runtime-sized bitmap chunks.

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
use commonware_codec::{Codec, EncodeSize, Read, Write};
use commonware_cryptography::{Digest, Hasher};

/// Proofs with fixed-size bitmap chunks.
pub mod constant {
    /// Proof information for verifying a key has a particular value in the database.
    pub type KeyValueProof<F, K, D, const N: usize> = super::KeyValueProof<F, K, D, [u8; N]>;

    /// Proof that a key has no assigned value in the database.
    pub type ExclusionProof<F, K, V, D, const N: usize> =
        super::ExclusionProof<F, K, V, D, [u8; N]>;
}

/// Proofs with runtime-sized bitmap chunks.
pub mod dynamic {
    /// Proof information for verifying a key has a particular value in the database.
    pub type KeyValueProof<F, K, D> = super::KeyValueProof<F, K, D, bytes::Bytes>;

    /// Proof that a key has no assigned value in the database.
    pub type ExclusionProof<F, K, V, D> = super::ExclusionProof<F, K, V, D, bytes::Bytes>;
}

/// Proof information for verifying a key has a particular value in the database.
///
/// `C` stores the embedded operation proof's bitmap chunk.
#[derive(Clone, Eq, PartialEq, Debug, Write, EncodeSize, Read)]
#[read_cfg((<OperationProof<F, D, C> as Read>::Cfg, <K as Read>::Cfg))]
#[codec(read_bounds(OperationProof<F, D, C>: Read))]
pub struct KeyValueProof<F: Graftable, K: Key, D: Digest, C> {
    /// The proof authenticating the active update operation.
    #[codec(cfg = &cfg.0)]
    pub proof: OperationProof<F, D, C>,

    /// The next active key in lexicographic order, wrapping at the end.
    #[codec(cfg = &cfg.1)]
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
#[derive(Clone, Eq, PartialEq, Debug, Write, EncodeSize, Read)]
#[read_cfg((<OperationProof<F, D, C> as Read>::Cfg, <Update<K, V> as Read>::Cfg, <V::Value as Read>::Cfg))]
#[codec(read_bounds(OperationProof<F, D, C>: Read, Update<K, V>: Read))]
pub enum ExclusionProof<F: Graftable, K: Key, V: ValueEncoding, D: Digest, C> {
    /// Proves that two keys are active in the database and adjacent to each other in the key
    /// ordering. Any key falling between them (non-inclusively) can be proven excluded.
    #[codec(tag = 0)]
    KeyValue(
        #[codec(cfg = &cfg.0)] OperationProof<F, D, C>,
        #[codec(cfg = &cfg.1)] Update<K, V>,
    ),

    /// Proves that the database has no active keys, allowing any key to be proven excluded.
    /// The commit operation's activity floor must equal its own location.
    #[codec(tag = 1)]
    Commit(
        #[codec(cfg = &cfg.0)] OperationProof<F, D, C>,
        #[codec(cfg = &cfg.2)] Option<V::Value>,
    ),
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
