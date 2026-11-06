//! Unordered current proofs with fixed-size or runtime-sized bitmap chunks.

use crate::{
    merkle::Graftable,
    qmdb::{
        any::unordered::{Operation, Update},
        current::proof::operation::Proof as OperationProof,
        operation::Key,
        value::ValueEncoding,
    },
};
use bytes::BufMut;
use commonware_codec::{Buf, Encode, EncodeSize, Read, Write};
use commonware_cryptography::{Digest, Hasher};

/// Proofs with fixed-size bitmap chunks.
pub mod constant {
    /// Proof information for verifying a key has a particular value in the database.
    pub type KeyValueProof<F, D, const N: usize> = super::KeyValueProof<F, D, [u8; N]>;
}

/// Proofs with runtime-sized bitmap chunks.
pub mod dynamic {
    /// Proof information for verifying a key has a particular value in the database.
    pub type KeyValueProof<F, D> = super::KeyValueProof<F, D, bytes::Bytes>;
}

/// Proof information for verifying a key has a particular value in the database.
///
/// `C` stores the embedded operation proof's bitmap chunk. Verify using [Self::verify].
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct KeyValueProof<F: Graftable, D: Digest, C> {
    /// The proof authenticating the active update operation.
    pub proof: OperationProof<F, D, C>,
}

impl<F: Graftable, D: Digest, C: AsRef<[u8]>> KeyValueProof<F, D, C> {
    /// Return true if the proof authenticates that `key` currently has `value` in the database
    /// with the provided `root`.
    ///
    /// `V` selects the fixed or variable value encoding used by the database.
    ///
    /// # Examples
    ///
    /// ```
    /// use commonware_codec::{Decode, Input};
    /// use commonware_cryptography::{Sha256, sha256::Digest};
    /// use commonware_storage::{
    ///     merkle::mmr,
    ///     qmdb::{value::FixedEncoding, current::unordered::proof::dynamic::KeyValueProof},
    /// };
    ///
    /// fn verify(
    ///     encoded: impl Input,
    ///     chunk_size: usize,
    ///     max_digests: usize,
    ///     key: Digest,
    ///     value: Digest,
    ///     root: &Digest,
    /// ) -> bool {
    ///     let Ok(proof) = KeyValueProof::<mmr::Family, Digest>::decode_cfg(
    ///         encoded,
    ///         &(chunk_size, max_digests),
    ///     ) else {
    ///         return false;
    ///     };
    ///     proof.verify::<Sha256, FixedEncoding<Digest>, _>(key, value, root)
    /// }
    /// ```
    pub fn verify<H, V, K>(&self, key: K, value: V::Value, root: &D) -> bool
    where
        H: Hasher<Digest = D>,
        V: ValueEncoding,
        K: Key,
        Operation<F, K, V>: Encode,
    {
        let op = Operation::<F, K, V>::Update(Update(key, value));
        self.proof.verify::<H, _>(op, root)
    }
}

impl<F: Graftable, D: Digest, C: AsRef<[u8]>> Write for KeyValueProof<F, D, C> {
    fn write(&self, buf: &mut impl BufMut) {
        self.proof.write(buf);
    }
}

impl<F: Graftable, D: Digest, C: AsRef<[u8]>> EncodeSize for KeyValueProof<F, D, C> {
    fn encode_size(&self) -> usize {
        self.proof.encode_size()
    }
}

impl<F: Graftable, D: Digest, C> Read for KeyValueProof<F, D, C>
where
    OperationProof<F, D, C>: Read,
{
    /// The read configuration for the embedded operation proof.
    type Cfg = <OperationProof<F, D, C> as Read>::Cfg;

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        let proof = OperationProof::<F, D, C>::read_cfg(buf, cfg)?;
        Ok(Self { proof })
    }
}

#[cfg(feature = "arbitrary")]
impl<F: Graftable, D: Digest, C> arbitrary::Arbitrary<'_> for KeyValueProof<F, D, C>
where
    OperationProof<F, D, C>: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            proof: u.arbitrary()?,
        })
    }
}
