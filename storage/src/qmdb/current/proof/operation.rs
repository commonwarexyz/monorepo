//! Operation proofs with fixed-size or runtime-sized bitmap chunks.

use super::{RangeProof, chunk_bits};
use crate::{
    merkle::{Graftable, Location, storage::Storage},
    qmdb::Error,
};
use bytes::{Buf, BufMut, Bytes};
use commonware_codec::{Codec, EncodeSize, Read, ReadExt as _, Write, util::at_least};
use commonware_cryptography::{Digest, Hasher};
use commonware_utils::bitmap::{Prunable as BitMap, Readable as BitmapReadable};
use tracing::debug;

/// A proof that a specific operation is currently active in the database.
///
/// `C` stores the bitmap chunk. Arrays provide fixed-size storage, while [Bytes] supports a
/// chunk size supplied when decoding. Both representations encode the chunk without a length
/// prefix.
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct Proof<F: Graftable, D: Digest, C> {
    /// The location of the operation in the database.
    pub loc: Location<F>,

    /// The status bitmap chunk containing the operation's activity bit.
    pub chunk: C,

    /// The range proof authenticating the operation and its activity status.
    pub range_proof: RangeProof<F, D>,
}

impl<F: Graftable, D: Digest, const N: usize> Proof<F, D, [u8; N]> {
    /// Return an inclusion proof that incorporates activity status for the operation at `loc`.
    ///
    /// # Errors
    ///
    /// Returns [Error::OperationPruned] if `loc` falls in a pruned bitmap chunk.
    pub async fn new<H: Hasher<Digest = D>, S: Storage<F, Digest = D>>(
        status: &impl BitmapReadable<N>,
        storage: &S,
        inactivity_floor: Location<F>,
        loc: Location<F>,
        ops_root: D,
    ) -> Result<Self, Error<F>> {
        // Reject locations in pruned bitmap chunks
        if BitMap::<N>::to_chunk_index(*loc) < status.pruned_chunks() {
            return Err(Error::OperationPruned(loc));
        }
        let range_proof =
            RangeProof::new::<H, S, N>(status, storage, inactivity_floor, loc..loc + 1, ops_root)
                .await?;
        let chunk = status.get_chunk(BitMap::<N>::to_chunk_index(*loc));
        Ok(Self {
            loc,
            chunk,
            range_proof,
        })
    }
}

impl<F: Graftable, D: Digest, C: AsRef<[u8]>> Proof<F, D, C> {
    /// Return true if the proof authenticates that `operation` is active in the database with
    /// the provided `root`.
    pub fn verify<H: Hasher<Digest = D>, O: Codec>(&self, operation: O, root: &D) -> bool {
        let chunk = self.chunk.as_ref();
        let Ok(bits) = chunk_bits(chunk.len()) else {
            debug!("proof verification failed, invalid chunk size");
            return false;
        };

        let bit = *self.loc % bits;
        if chunk[(bit / 8) as usize] & (1 << (bit % 8)) == 0 {
            debug!(?self.loc, "proof verification failed, operation is inactive");
            return false;
        }

        self.range_proof.verify_with_chunk_size::<H, O>(
            self.loc,
            &[operation],
            core::slice::from_ref(&self.chunk),
            chunk.len(),
            root,
        )
    }
}

impl<F: Graftable, D: Digest, C: AsRef<[u8]>> Write for Proof<F, D, C> {
    fn write(&self, buf: &mut impl BufMut) {
        self.loc.write(buf);
        buf.put_slice(self.chunk.as_ref());
        self.range_proof.write(buf);
    }
}

impl<F: Graftable, D: Digest, C: AsRef<[u8]>> EncodeSize for Proof<F, D, C> {
    fn encode_size(&self) -> usize {
        self.loc.encode_size() + self.chunk.as_ref().len() + self.range_proof.encode_size()
    }
}

impl<F: Graftable, D: Digest, C> Proof<F, D, C> {
    fn read_with<B: Buf>(
        buf: &mut B,
        max_digests: &usize,
        read_chunk: impl FnOnce(&mut B) -> Result<C, commonware_codec::Error>,
    ) -> Result<Self, commonware_codec::Error> {
        let loc = Location::<F>::read(buf)?;
        let chunk = read_chunk(buf)?;
        let range_proof = RangeProof::<F, D>::read_cfg(buf, max_digests)?;
        Ok(Self {
            loc,
            chunk,
            range_proof,
        })
    }
}

impl<F: Graftable, D: Digest, const N: usize> Read for Proof<F, D, [u8; N]> {
    /// The maximum number of digests forwarded to the embedded range proof.
    type Cfg = usize;

    fn read_cfg(
        buf: &mut impl Buf,
        max_digests: &Self::Cfg,
    ) -> Result<Self, commonware_codec::Error> {
        Self::read_with(buf, max_digests, <[u8; N]>::read)
    }
}

impl<F: Graftable, D: Digest> Read for Proof<F, D, Bytes> {
    /// `(chunk_size, max_digests)`: the exact bitmap chunk size in bytes and the maximum number
    /// of digests forwarded to the embedded range proof.
    ///
    /// The chunk size must be a nonzero power of two whose bit width has grafting height below
    /// 63. It is supplied by the caller and is not encoded in the proof.
    type Cfg = (usize, usize);

    fn read_cfg(
        buf: &mut impl Buf,
        (chunk_size, max_digests): &Self::Cfg,
    ) -> Result<Self, commonware_codec::Error> {
        chunk_bits(*chunk_size)?;
        Self::read_with(buf, max_digests, |buf| {
            at_least(buf, *chunk_size)?;
            Ok(buf.copy_to_bytes(*chunk_size))
        })
    }
}

#[cfg(feature = "arbitrary")]
impl<F: Graftable, D: Digest, const N: usize> arbitrary::Arbitrary<'_> for Proof<F, D, [u8; N]>
where
    D: for<'a> arbitrary::Arbitrary<'a>,
    F::PendingChunk<D>: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            loc: u.arbitrary()?,
            chunk: u.arbitrary()?,
            range_proof: u.arbitrary()?,
        })
    }
}

#[cfg(feature = "arbitrary")]
impl<F: Graftable, D: Digest> arbitrary::Arbitrary<'_> for Proof<F, D, Bytes>
where
    D: for<'a> arbitrary::Arbitrary<'a>,
    F::PendingChunk<D>: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let loc = u.arbitrary()?;
        let chunk_size = 1usize << u.int_in_range(0u8..=8)?;
        let chunk = Bytes::copy_from_slice(u.bytes(chunk_size)?);
        let range_proof = u.arbitrary()?;
        Ok(Self {
            loc,
            chunk,
            range_proof,
        })
    }
}
