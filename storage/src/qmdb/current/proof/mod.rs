//! Proof types for [crate::qmdb::current] authenticated databases.
//!
//! This module provides:
//! - [OpsRootWitness]: Authenticates an ops root against a canonical `current` root.
//! - [RangeProof]: Proves a range of operations exist in the database.
//! - [OperationProof]: Proves a specific operation is active in the database.
//!
//! # Canonical root structure
//!
//! ```text
//! canonical_root = hash(
//!     ops_root
//!     || grafted_root
//!     [|| pending_chunk_digest]
//!     [|| next_bit_be || partial_chunk_digest]
//! )
//! ```
//!
//! - `ops_root` is the root of the operations tree (MMR or MMB).
//! - `grafted_root` commits to the activity bitmap's **graftable** chunks (chunks whose
//!   height-G ancestor has been born in the ops tree).
//! - `pending_chunk_digest` is `H(pending_bytes)` if a chunk is bit-complete in the bitmap
//!   but its h=G ancestor has not yet been born; absent otherwise.
//! - `(next_bit_be, partial_chunk_digest)` covers the trailing partial chunk when the
//!   bitmap length is not chunk-aligned; both elements are absent when it is.
//!
//! Pending and partial slots are independent: at G >= 3 they can coexist. When both are
//! present, pending hashes in before partial.

use crate::{
    journal::contiguous::{Contiguous, Reader as _},
    merkle::{
        self,
        hasher::{Hasher, Standard as StandardHasher},
        storage::Storage,
        Family, Graftable, Location, Proof,
    },
    qmdb::{
        self,
        current::{
            db::{combine_roots, partial_chunk, pending_chunk},
            grafting,
        },
        Error,
    },
};
use bytes::{Buf, BufMut};
use commonware_codec::{varint::UInt, Codec, EncodeSize, Read, ReadExt as _, Write};
use commonware_cryptography::{Digest, Hasher as CHasher};
use commonware_utils::bitmap::{Prunable as BitMap, Readable as BitmapReadable};
use core::{num::NonZeroU64, ops::Range};
use futures::future::try_join_all;
use tracing::debug;

/// Witness that a particular `ops_root` is committed by a `current` canonical root.
///
/// See the [Canonical root structure](self#canonical-root-structure) section in the module
/// documentation for the full layout.
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct OpsRootWitness<D: Digest> {
    /// The grafted-tree root committed by the canonical root.
    pub grafted_root: D,

    /// `H(pending_chunk_bytes)` when the bitmap has a chunk whose bits are complete but
    /// whose h=G ancestor has not yet been born in the ops tree; `None` otherwise.
    pub pending_chunk_digest: Option<D>,

    /// The trailing partial chunk contribution, if the bitmap length is not chunk-aligned:
    /// `(next_bit, partial_chunk_digest)`.
    pub partial_chunk: Option<(u64, D)>,
}

impl<D: Digest> OpsRootWitness<D> {
    /// Return true if this witness proves that `canonical_root` commits to `ops_root`.
    pub fn verify<H: CHasher<Digest = D>>(
        &self,
        hasher: &StandardHasher<H>,
        ops_root: &D,
        canonical_root: &D,
    ) -> bool {
        let partial = self.partial_chunk.as_ref().map(|(nb, d)| (*nb, d));
        combine_roots(
            hasher,
            ops_root,
            &self.grafted_root,
            self.pending_chunk_digest.as_ref(),
            partial,
        ) == *canonical_root
    }
}

impl<D: Digest> Write for OpsRootWitness<D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.grafted_root.write(buf);
        self.pending_chunk_digest.is_some().write(buf);
        if let Some(digest) = &self.pending_chunk_digest {
            digest.write(buf);
        }
        self.partial_chunk.is_some().write(buf);
        if let Some((next_bit, digest)) = &self.partial_chunk {
            UInt(*next_bit).write(buf);
            digest.write(buf);
        }
    }
}

impl<D: Digest> EncodeSize for OpsRootWitness<D> {
    fn encode_size(&self) -> usize {
        self.grafted_root.encode_size()
            + self
                .pending_chunk_digest
                .as_ref()
                .map_or(1, |d| 1 + d.encode_size())
            + self
                .partial_chunk
                .as_ref()
                .map_or(1, |(nb, d)| 1 + UInt(*nb).encode_size() + d.encode_size())
    }
}

impl<D: Digest> Read for OpsRootWitness<D> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        let grafted_root = D::read(buf)?;
        let pending_chunk_digest = if bool::read(buf)? {
            Some(D::read(buf)?)
        } else {
            None
        };
        let partial_chunk = if bool::read(buf)? {
            let next_bit = UInt::<u64>::read(buf)?.into();
            let digest = D::read(buf)?;
            Some((next_bit, digest))
        } else {
            None
        };
        Ok(Self {
            grafted_root,
            pending_chunk_digest,
            partial_chunk,
        })
    }
}

#[cfg(feature = "arbitrary")]
impl<D: Digest> arbitrary::Arbitrary<'_> for OpsRootWitness<D>
where
    D: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            grafted_root: u.arbitrary()?,
            pending_chunk_digest: u.arbitrary()?,
            partial_chunk: u.arbitrary()?,
        })
    }
}

/// A proof that a range of operations exist in the database.
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct RangeProof<F: Family, D: Digest> {
    /// The Merkle digest material required to verify the proof.
    pub proof: Proof<F, D>,

    /// Digest of the bitmap chunk that's complete but not yet graftable, if any.
    pub pending_chunk_digest: Option<D>,

    /// Digest of the bitmap's trailing partial chunk, if any.
    pub partial_chunk_digest: Option<D>,

    /// The ops-tree root digest.
    pub ops_root: D,
}

/// Parameters that identify the operation span and snapshot used to build a range proof.
#[derive(Clone, Copy, Eq, PartialEq, Debug)]
pub struct RangeProofSpec<F: Family, D: Digest> {
    /// First operation location to prove.
    pub start_loc: Location<F>,

    /// Maximum number of operations to include.
    pub max_ops: NonZeroU64,

    /// Inactivity floor used to fold old inactive peaks.
    pub inactivity_floor: Location<F>,

    /// The ops-tree root at the time of proof generation.
    pub ops_root: D,
}

impl<F: Graftable, D: Digest> RangeProof<F, D> {
    /// Create a new range proof for the provided `range` of operations.
    pub async fn new<H: CHasher<Digest = D>, S: Storage<F, Digest = D>, const N: usize>(
        hasher: &StandardHasher<H>,
        status: &impl BitmapReadable<N>,
        storage: &S,
        inactivity_floor: Location<F>,
        range: Range<Location<F>>,
        ops_root: D,
    ) -> Result<Self, Error<F>> {
        // Snapshot ops_leaves once and thread through every derivation that needs it so the
        // pruned <= graftable <= complete invariant holds across all derivations.
        let ops_leaves = Location::try_from(storage.size().await)?;
        let grafting_height = grafting::height::<N>();
        let inactive_peaks = grafting::chunk_aligned_inactive_peaks::<F>(
            ops_leaves,
            inactivity_floor,
            grafting_height,
        )?;

        let proof = merkle::verification::historical_range_proof(
            hasher,
            storage,
            ops_leaves,
            range,
            inactive_peaks,
        )
        .await?;

        let partial_chunk_digest =
            partial_chunk::<_, N>(status).map(|(chunk, _)| hasher.digest(&chunk));

        let pending_chunk_digest = pending_chunk::<_, _, N>(status, ops_leaves, grafting_height)?
            .map(|chunk| hasher.digest(&chunk));

        Ok(Self {
            proof,
            pending_chunk_digest,
            partial_chunk_digest,
            ops_root,
        })
    }

    /// Returns a proof that the specified range of operations are part of the database, along with
    /// the operations from the range and their activity status chunks. A truncated range (from
    /// hitting the max) can be detected by looking at the length of the returned operations vector.
    ///
    /// # Errors
    ///
    /// Returns [Error::OperationPruned] if `start_loc` falls in a pruned bitmap chunk.
    /// Returns [`merkle::Error::LocationOverflow`] if `start_loc` > [merkle::Family::MAX_LEAVES].
    /// Returns [`merkle::Error::RangeOutOfBounds`] if `start_loc` >= number of leaves in the tree.
    pub async fn new_with_ops<
        H: CHasher<Digest = D>,
        C: Contiguous,
        S: Storage<F, Digest = D>,
        const N: usize,
    >(
        hasher: &StandardHasher<H>,
        status: &impl BitmapReadable<N>,
        storage: &S,
        log: &C,
        request: RangeProofSpec<F, D>,
    ) -> Result<(Self, Vec<C::Item>, Vec<[u8; N]>), Error<F>> {
        // Compute the end location of the range.
        let leaves = Location::new(status.len());
        if request.start_loc >= leaves {
            return Err(merkle::Error::RangeOutOfBounds(request.start_loc).into());
        }

        // Reject ranges that start in pruned bitmap chunks.
        let chunk_bits = BitMap::<N>::CHUNK_SIZE_BITS;
        let start = *request.start_loc / chunk_bits;
        if (start as usize) < status.pruned_chunks() {
            return Err(Error::OperationPruned(request.start_loc));
        }

        let max_loc = request.start_loc.saturating_add(request.max_ops.get());
        let end_loc = core::cmp::min(max_loc, leaves);

        // Generate the proof from the grafted storage.
        let proof = Self::new(
            hasher,
            status,
            storage,
            request.inactivity_floor,
            request.start_loc..end_loc,
            request.ops_root,
        )
        .await?;

        // Collect the operations necessary to verify the proof.
        let reader = log.reader().await;
        let futures = (*request.start_loc..*end_loc)
            .map(|i| reader.read(i))
            .collect::<Vec<_>>();
        let ops = try_join_all(futures).await?;

        // Gather the chunks necessary to verify the proof.
        let end = (*end_loc - 1) / chunk_bits; // chunk that contains the last bit
        let chunks = (start..=end)
            .map(|i| status.get_chunk(i as usize))
            .collect::<Vec<_>>();

        Ok((proof, ops, chunks))
    }

    /// Return true if the given sequence of `ops` were applied starting at location `start_loc` in
    /// the db with the provided root, and having the activity status described by `chunks`.
    pub fn verify<H: CHasher<Digest = D>, O: Codec, const N: usize>(
        &self,
        root_hasher: &StandardHasher<H>,
        start_loc: Location<F>,
        ops: &[O],
        chunks: &[[u8; N]],
        root: &H::Digest,
    ) -> bool {
        if ops.is_empty() || chunks.is_empty() {
            debug!("verification failed, empty input");
            return false;
        }
        // Compute the (non-inclusive) end location of the range.
        let Some(end_loc) = start_loc.checked_add(ops.len() as u64) else {
            debug!("verification failed, end_loc overflow");
            return false;
        };

        let leaves = self.proof.leaves;
        if end_loc > leaves {
            debug!(
                loc = ?end_loc,
                ?leaves, "verification failed, invalid range"
            );
            return false;
        }

        // Validate the number of input chunks.
        let chunk_bits = BitMap::<N>::CHUNK_SIZE_BITS;
        let start_chunk = *start_loc / chunk_bits;
        let end_chunk = (*end_loc - 1) / chunk_bits;
        let complete_chunks = *leaves / chunk_bits;

        if (end_chunk - start_chunk + 1) != chunks.len() as u64 {
            debug!("verification failed, chunk metadata length mismatch");
            return false;
        }

        let next_bit = *leaves % chunk_bits;
        let has_partial_chunk = next_bit != 0;

        let elements = ops.iter().map(|op| op.encode()).collect::<Vec<_>>();
        let chunk_vec = chunks.iter().map(|c| c.as_ref()).collect::<Vec<_>>();
        let grafting_height = grafting::height::<N>();

        let graftable_chunks =
            grafting::graftable_chunks::<F>(*leaves, grafting_height).min(complete_chunks);
        let pending_chunks = complete_chunks - graftable_chunks;
        if pending_chunks > 1 {
            debug!(
                ?complete_chunks,
                ?graftable_chunks,
                "verification failed, multiple pending chunks"
            );
            return false;
        }
        let has_pending_chunk = pending_chunks == 1;

        let grafting_verifier = grafting::Verifier::<F, H>::new(
            grafting_height,
            start_chunk,
            chunk_vec,
            graftable_chunks,
            qmdb::ROOT_BAGGING,
        );

        if self.pending_chunk_digest.is_some() != has_pending_chunk {
            debug!(
                pending_in_proof = self.pending_chunk_digest.is_some(),
                expected = has_pending_chunk,
                "pending_chunk_digest presence does not match bitmap state"
            );
            return false;
        }

        // For partial chunks, validate the last chunk digest from the proof.
        if has_partial_chunk {
            let Some(last_chunk_digest) = self.partial_chunk_digest else {
                debug!("proof has no partial chunk digest");
                return false;
            };

            // If the proof covers an operation in the partial chunk, verify that the
            // chunk provided by the caller matches the digest embedded in the proof.
            if end_chunk == complete_chunks {
                let last_chunk = chunks.last().expect("chunks non-empty");
                if last_chunk_digest != grafting_verifier.digest(last_chunk) {
                    debug!("last chunk digest does not match expected value");
                    return false;
                }
            }
        } else if self.partial_chunk_digest.is_some() {
            debug!("proof has unexpected partial chunk digest");
            return false;
        }

        // For a pending chunk, validate the supplied chunk bytes against the digest in the proof
        // when the verifier's range includes the pending chunk's index. The pending chunk is at
        // index `graftable_chunks` (== `complete_chunks - 1` when present).
        if let Some(pending_digest) = self.pending_chunk_digest {
            let pending_idx = graftable_chunks;
            if pending_idx >= start_chunk && pending_idx <= end_chunk {
                let local = (pending_idx - start_chunk) as usize;
                // The earlier `chunks.len() == end_chunk - start_chunk + 1` check makes this
                // index in-bounds for well-formed inputs; treat any mismatch as a malformed
                // proof (rather than panicking) since `verify` runs against attacker-supplied data.
                let Some(pending_chunk_bytes) = chunks.get(local) else {
                    debug!(
                        ?pending_idx,
                        chunks_len = chunks.len(),
                        "pending chunk index out of range in supplied chunks"
                    );
                    return false;
                };
                if pending_digest != grafting_verifier.digest(pending_chunk_bytes) {
                    debug!("pending chunk digest does not match expected value");
                    return false;
                }
            }
        }

        let merkle_root =
            match self
                .proof
                .reconstruct_root(&grafting_verifier, &elements, start_loc)
            {
                Ok(root) => root,
                Err(error) => {
                    debug!(?error, "invalid proof input");
                    return false;
                }
            };

        let partial =
            has_partial_chunk.then(|| (next_bit, self.partial_chunk_digest.as_ref().unwrap()));
        combine_roots(
            root_hasher,
            &self.ops_root,
            &merkle_root,
            self.pending_chunk_digest.as_ref(),
            partial,
        ) == *root
    }
}

impl<F: Family, D: Digest> Write for RangeProof<F, D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.proof.write(buf);
        self.pending_chunk_digest.write(buf);
        self.partial_chunk_digest.write(buf);
        self.ops_root.write(buf);
    }
}

impl<F: Family, D: Digest> EncodeSize for RangeProof<F, D> {
    fn encode_size(&self) -> usize {
        self.proof.encode_size()
            + self.pending_chunk_digest.encode_size()
            + self.partial_chunk_digest.encode_size()
            + self.ops_root.encode_size()
    }
}

impl<F: Family, D: Digest> Read for RangeProof<F, D> {
    /// The maximum number of digests allowed across the range proof.
    type Cfg = usize;

    fn read_cfg(
        buf: &mut impl Buf,
        max_digests: &Self::Cfg,
    ) -> Result<Self, commonware_codec::Error> {
        let proof = Proof::<F, D>::read_cfg(buf, max_digests)?;
        let pending_chunk_digest = Option::<D>::read(buf)?;
        let partial_chunk_digest = Option::<D>::read(buf)?;
        let ops_root = D::read(buf)?;
        Ok(Self {
            proof,
            pending_chunk_digest,
            partial_chunk_digest,
            ops_root,
        })
    }
}

#[cfg(feature = "arbitrary")]
impl<F: Family, D: Digest> arbitrary::Arbitrary<'_> for RangeProof<F, D>
where
    D: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            proof: u.arbitrary()?,
            pending_chunk_digest: u.arbitrary()?,
            partial_chunk_digest: u.arbitrary()?,
            ops_root: u.arbitrary()?,
        })
    }
}

/// A proof that a specific operation is currently active in the database.
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct OperationProof<F: Family, D: Digest, const N: usize> {
    /// The location of the operation in the db.
    pub loc: Location<F>,

    /// The status bitmap chunk that contains the bit corresponding the operation's location.
    pub chunk: [u8; N],

    /// The range proof that incorporates activity status for the operation designated by `loc`.
    pub range_proof: RangeProof<F, D>,
}

impl<F: Graftable, D: Digest, const N: usize> OperationProof<F, D, N> {
    /// Return an inclusion proof that incorporates activity status for the operation designated by
    /// `loc`.
    ///
    /// # Errors
    ///
    /// Returns [Error::OperationPruned] if `loc` falls in a pruned bitmap chunk.
    pub async fn new<H: CHasher<Digest = D>, S: Storage<F, Digest = D>>(
        hasher: &StandardHasher<H>,
        status: &impl BitmapReadable<N>,
        storage: &S,
        inactivity_floor: Location<F>,
        loc: Location<F>,
        ops_root: D,
    ) -> Result<Self, Error<F>> {
        // Reject locations in pruned bitmap chunks.
        if BitMap::<N>::to_chunk_index(*loc) < status.pruned_chunks() {
            return Err(Error::OperationPruned(loc));
        }
        let range_proof = RangeProof::new(
            hasher,
            status,
            storage,
            inactivity_floor,
            loc..loc + 1,
            ops_root,
        )
        .await?;
        let chunk = status.get_chunk(BitMap::<N>::to_chunk_index(*loc));
        Ok(Self {
            loc,
            chunk,
            range_proof,
        })
    }
}

impl<F: Graftable, D: Digest, const N: usize> OperationProof<F, D, N> {
    /// Verify that the proof proves that `operation` is active in the database with the given
    /// `root`.
    pub fn verify<H: CHasher<Digest = D>, O: Codec>(
        &self,
        hasher: &StandardHasher<H>,
        operation: O,
        root: &D,
    ) -> bool {
        // Make sure that the bit for the operation in the bitmap chunk is actually a 1 (indicating
        // the operation is indeed active).
        if !BitMap::<N>::get_bit_from_chunk(&self.chunk, *self.loc) {
            debug!(
                ?self.loc,
                "proof verification failed, operation is inactive"
            );
            return false;
        }

        self.range_proof
            .verify(hasher, self.loc, &[operation], &[self.chunk], root)
    }
}

impl<F: Family, D: Digest, const N: usize> Write for OperationProof<F, D, N> {
    fn write(&self, buf: &mut impl BufMut) {
        self.loc.write(buf);
        self.chunk.write(buf);
        self.range_proof.write(buf);
    }
}

impl<F: Family, D: Digest, const N: usize> EncodeSize for OperationProof<F, D, N> {
    fn encode_size(&self) -> usize {
        self.loc.encode_size() + self.chunk.encode_size() + self.range_proof.encode_size()
    }
}

impl<F: Family, D: Digest, const N: usize> Read for OperationProof<F, D, N> {
    /// The total digest cap forwarded to the embedded range proof.
    type Cfg = usize;

    fn read_cfg(
        buf: &mut impl Buf,
        max_digests: &Self::Cfg,
    ) -> Result<Self, commonware_codec::Error> {
        let loc = Location::<F>::read(buf)?;
        let chunk = <[u8; N]>::read(buf)?;
        let range_proof = RangeProof::<F, D>::read_cfg(buf, max_digests)?;
        Ok(Self {
            loc,
            chunk,
            range_proof,
        })
    }
}

#[cfg(feature = "arbitrary")]
impl<F: Family, D: Digest, const N: usize> arbitrary::Arbitrary<'_> for OperationProof<F, D, N>
where
    D: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            loc: u.arbitrary()?,
            chunk: u.arbitrary()?,
            range_proof: u.arbitrary()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        merkle::{conformance::build_test_mem, mem::Mem},
        mmb,
        qmdb::current::{db, grafting},
    };
    use commonware_codec::{Decode as _, DecodeExt as _, Encode as _};
    use commonware_cryptography::{sha256, Sha256};
    use commonware_macros::test_traced;
    use commonware_parallel::Sequential;
    use commonware_runtime::{deterministic, Runner};
    use commonware_utils::bitmap::{Prunable as BitMap, Readable as BitmapReadable};

    #[test]
    fn test_ops_root_witness_codec_roundtrip() {
        for partial_chunk in [
            None,
            Some((0u64, Sha256::hash(b"partial-zero"))),
            Some((123u64, Sha256::hash(b"partial-nonzero"))),
        ] {
            let witness = OpsRootWitness {
                grafted_root: Sha256::hash(b"grafted"),
                pending_chunk_digest: None,
                partial_chunk,
            };
            let encoded = witness.encode();
            assert_eq!(encoded.len(), witness.encode_size());
            let decoded = OpsRootWitness::<sha256::Digest>::decode(encoded).unwrap();
            assert_eq!(decoded, witness);
        }
    }

    fn range_proof_digest_count<F: Family, D: Digest>(proof: &RangeProof<F, D>) -> usize {
        proof.proof.digests.len()
    }

    #[test]
    fn test_range_proof_codec_roundtrip() {
        type F = mmb::Family;
        const MAX_DIGESTS: usize = 64;

        let proof = Proof::<F, sha256::Digest> {
            leaves: mmb::Location::new(42),
            inactive_peaks: 0,
            digests: vec![
                Sha256::hash(b"d0"),
                Sha256::hash(b"d1"),
                Sha256::hash(b"d2"),
            ],
        };
        let ops_root = Sha256::hash(b"ops-root");

        let cases = [
            // Minimal: no optional fields or prefix/suffix witnesses.
            RangeProof {
                proof: proof.clone(),
                pending_chunk_digest: None,
                partial_chunk_digest: None,
                ops_root,
            },
            // All optional fields populated.
            RangeProof {
                proof,
                pending_chunk_digest: Some(Sha256::hash(b"pending")),
                partial_chunk_digest: Some(Sha256::hash(b"partial")),
                ops_root,
            },
            // Default proof with only partial chunk digest.
            RangeProof {
                proof: Proof::<F, sha256::Digest>::default(),
                pending_chunk_digest: None,
                partial_chunk_digest: Some(Sha256::hash(b"only-partial")),
                ops_root,
            },
        ];

        for proof in cases {
            let encoded = proof.encode();
            assert_eq!(encoded.len(), proof.encode_size());
            let decoded =
                RangeProof::<F, sha256::Digest>::decode_cfg(encoded, &MAX_DIGESTS).unwrap();
            assert_eq!(decoded, proof);
        }
    }

    #[test]
    fn test_range_proof_codec_enforces_total_digest_budget() {
        type F = mmb::Family;

        let proof = RangeProof {
            proof: Proof::<F, sha256::Digest> {
                leaves: mmb::Location::new(42),
                inactive_peaks: 0,
                digests: vec![Sha256::hash(b"d0")],
            },
            pending_chunk_digest: None,
            partial_chunk_digest: None,
            ops_root: Sha256::hash(b"ops-root"),
        };

        let encoded = proof.encode();
        let total_digests = range_proof_digest_count(&proof);

        let decoded =
            RangeProof::<F, sha256::Digest>::decode_cfg(encoded.clone(), &total_digests).unwrap();
        assert_eq!(decoded, proof);
        assert!(
            RangeProof::<F, sha256::Digest>::decode_cfg(encoded, &(total_digests - 1)).is_err()
        );
    }

    #[test]
    fn test_operation_proof_codec_roundtrip() {
        type F = mmb::Family;
        const N: usize = 32;
        const MAX_DIGESTS: usize = 64;

        let range_proof = RangeProof {
            proof: Proof::<F, sha256::Digest> {
                leaves: mmb::Location::new(7),
                inactive_peaks: 0,
                digests: vec![Sha256::hash(b"sib")],
            },
            pending_chunk_digest: None,
            partial_chunk_digest: None,
            ops_root: Sha256::hash(b"ops"),
        };

        let chunk: [u8; N] = core::array::from_fn(|i| i as u8);

        let proof = OperationProof::<F, sha256::Digest, N> {
            loc: mmb::Location::new(5),
            chunk,
            range_proof,
        };

        let encoded = proof.encode();
        assert_eq!(encoded.len(), proof.encode_size());
        let decoded =
            OperationProof::<F, sha256::Digest, N>::decode_cfg(encoded, &MAX_DIGESTS).unwrap();
        assert_eq!(decoded, proof);
    }

    #[test]
    fn test_operation_proof_codec_enforces_total_digest_budget() {
        type F = mmb::Family;
        const N: usize = 32;

        let range_proof = RangeProof {
            proof: Proof::<F, sha256::Digest> {
                leaves: mmb::Location::new(7),
                inactive_peaks: 0,
                digests: vec![Sha256::hash(b"sib")],
            },
            pending_chunk_digest: None,
            partial_chunk_digest: None,
            ops_root: Sha256::hash(b"ops"),
        };
        let total_digests = range_proof_digest_count(&range_proof);
        let proof = OperationProof::<F, sha256::Digest, N> {
            loc: mmb::Location::new(5),
            chunk: core::array::from_fn(|i| i as u8),
            range_proof,
        };

        let encoded = proof.encode();
        let decoded =
            OperationProof::<F, sha256::Digest, N>::decode_cfg(encoded.clone(), &total_digests)
                .unwrap();
        assert_eq!(decoded, proof);
        assert!(
            OperationProof::<F, sha256::Digest, N>::decode_cfg(encoded, &(total_digests - 1))
                .is_err()
        );
    }

    #[test_traced]
    fn test_range_proof_verifies_for_mmb_multi_peak_chunk() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            type F = mmb::Family;
            const N: usize = 1;

            let hasher = qmdb::hasher::<Sha256>();
            let grafting_height = grafting::height::<N>();

            let leaf_count = (16..=64u64)
                .find(|&leaves| {
                    let size = F::location_to_position(mmb::Location::new(leaves));
                    F::chunk_peaks(size, 1, grafting_height).nth(1).is_some()
                })
                .expect("expected an MMB size whose second chunk spans multiple peaks");

            let mut status = BitMap::<N>::new();
            for _ in 0..leaf_count {
                status.push(true);
            }
            let ops = build_test_mem(&hasher, mmb::mem::Mmb::new(), leaf_count);
            let ops_root = ops.root(&hasher, 0).unwrap();

            let graftable_chunks_for_test = grafting::graftable_chunks::<F>(
                *Location::<F>::try_from(ops.size()).unwrap(),
                grafting_height,
            )
            .min(<BitMap<N> as BitmapReadable<N>>::complete_chunks(&status) as u64)
                as usize;
            let chunk_inputs: Vec<_> = (0..graftable_chunks_for_test)
                .map(|chunk_idx| {
                    (
                        chunk_idx,
                        <BitMap<N> as BitmapReadable<N>>::get_chunk(&status, chunk_idx),
                    )
                })
                .collect();
            let mut leaf_digests = db::compute_grafted_leaves::<F, Sha256, Sequential, N>(
                &hasher,
                &ops,
                chunk_inputs,
                &Sequential,
            )
            .await
            .unwrap();
            leaf_digests.sort_by_key(|(chunk_idx, _)| *chunk_idx);

            let grafted_hasher =
                grafting::GraftedHasher::<F, _>::new(hasher.clone(), grafting_height);
            let mut grafted = Mem::<F, sha256::Digest>::new();
            let merkleized = {
                let mut batch = grafted.new_batch();
                for (_, digest) in leaf_digests {
                    batch = batch.add_leaf_digest(digest);
                }
                batch.merkleize(&grafted, &grafted_hasher)
            };
            grafted.apply_batch(&merkleized).unwrap();

            let storage = grafting::Storage::new(&grafted, grafting_height, &ops, hasher.clone());
            let ops_leaves_for_root = Location::<F>::try_from(ops.size()).unwrap();
            let root = db::compute_db_root::<F, Sha256, _, _, N>(
                &hasher,
                &status,
                &storage,
                ops_leaves_for_root,
                None,
                Location::new(0),
                &ops_root,
            )
            .await
            .unwrap();

            let loc = mmb::Location::new(BitMap::<N>::CHUNK_SIZE_BITS + 4);
            let proof = RangeProof::new(
                &hasher,
                &status,
                &storage,
                Location::new(0),
                loc..loc + 1,
                ops_root,
            )
            .await
            .unwrap();

            let element = hasher.digest(&(*loc).to_be_bytes());
            assert!(proof.verify(
                &hasher,
                loc,
                &[element],
                &[<BitMap<N> as BitmapReadable<N>>::get_chunk(&status, 1)],
                &root,
            ));
        });
    }

    #[test_traced]
    fn test_range_proof_verifies_with_partial_suffix_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            type F = mmb::Family;
            const N: usize = 1;

            let hasher = qmdb::hasher::<Sha256>();
            let grafting_height = grafting::height::<N>();
            let chunk_bits = BitMap::<N>::CHUNK_SIZE_BITS;

            let (leaf_count, loc) = (chunk_bits * 2 + 1..=64u64)
                .find_map(|leaves| {
                    let complete_chunks = leaves / chunk_bits;
                    if complete_chunks < 2 || leaves % chunk_bits == 0 {
                        return None;
                    }

                    let size = F::location_to_position(mmb::Location::new(leaves));
                    F::chunk_peaks(size, 1, grafting_height).nth(1)?;
                    Some((leaves, mmb::Location::new(chunk_bits + 1)))
                })
                .expect("expected an MMB proof with a partial trailing suffix chunk");

            let mut status = BitMap::<N>::new();
            for _ in 0..leaf_count {
                status.push(true);
            }
            let ops = build_test_mem(&hasher, mmb::mem::Mmb::new(), leaf_count);
            let ops_root = ops.root(&hasher, 0).unwrap();

            let graftable_chunks_for_test = grafting::graftable_chunks::<F>(
                *Location::<F>::try_from(ops.size()).unwrap(),
                grafting_height,
            )
            .min(<BitMap<N> as BitmapReadable<N>>::complete_chunks(&status) as u64)
                as usize;
            let chunk_inputs: Vec<_> = (0..graftable_chunks_for_test)
                .map(|chunk_idx| {
                    (
                        chunk_idx,
                        <BitMap<N> as BitmapReadable<N>>::get_chunk(&status, chunk_idx),
                    )
                })
                .collect();
            let mut leaf_digests = db::compute_grafted_leaves::<F, Sha256, Sequential, N>(
                &hasher,
                &ops,
                chunk_inputs,
                &Sequential,
            )
            .await
            .unwrap();
            leaf_digests.sort_by_key(|(chunk_idx, _)| *chunk_idx);

            let grafted_hasher =
                grafting::GraftedHasher::<F, _>::new(hasher.clone(), grafting_height);
            let mut grafted = Mem::<F, sha256::Digest>::new();
            let merkleized = {
                let mut batch = grafted.new_batch();
                for (_, digest) in leaf_digests {
                    batch = batch.add_leaf_digest(digest);
                }
                batch.merkleize(&grafted, &grafted_hasher)
            };
            grafted.apply_batch(&merkleized).unwrap();

            let storage = grafting::Storage::new(&grafted, grafting_height, &ops, hasher.clone());
            let partial = {
                let (chunk, next_bit) = status.last_chunk();
                Some((*chunk, next_bit))
            };
            let ops_leaves_for_root = Location::<F>::try_from(ops.size()).unwrap();
            let root = db::compute_db_root::<F, Sha256, _, _, N>(
                &hasher,
                &status,
                &storage,
                ops_leaves_for_root,
                partial,
                Location::new(0),
                &ops_root,
            )
            .await
            .unwrap();
            let proof = RangeProof::new(
                &hasher,
                &status,
                &storage,
                Location::new(0),
                loc..loc + 1,
                ops_root,
            )
            .await
            .unwrap();

            let element = hasher.digest(&(*loc).to_be_bytes());
            let chunk_idx = (*loc / BitMap::<N>::CHUNK_SIZE_BITS) as usize;
            assert!(proof.verify(
                &hasher,
                loc,
                &[element],
                &[<BitMap<N> as BitmapReadable<N>>::get_chunk(
                    &status, chunk_idx
                )],
                &root,
            ));
        });
    }

    #[test_traced]
    fn test_range_proof_verifies_when_range_reaches_partial_chunk_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            type F = mmb::Family;
            const N: usize = 1;

            let hasher = qmdb::hasher::<Sha256>();
            let grafting_height = grafting::height::<N>();
            let chunk_bits = BitMap::<N>::CHUNK_SIZE_BITS;

            // Search for an MMB size whose chunk 1 is multi-peak AND whose total leaves
            // aren't chunk-aligned (so a partial trailing chunk exists). The proven range
            // starts inside chunk 1 and extends to the end (touching the partial chunk).
            let (leaf_count, start_loc, complete_chunks) = (17..=128u64)
                .find_map(|leaves| {
                    let complete_chunks = leaves / chunk_bits;
                    if complete_chunks < 2 || leaves % chunk_bits == 0 {
                        return None;
                    }
                    let leaves_loc = mmb::Location::new(leaves);
                    let size = F::location_to_position(leaves_loc);
                    F::chunk_peaks(size, 1, grafting_height).nth(1)?;
                    let start_loc = mmb::Location::new(chunk_bits + 1);
                    Some((leaves, start_loc, complete_chunks))
                })
                .expect(
                    "expected an MMB size with chunk 1 multi-peak and a partial trailing chunk",
                );

            let mut status = BitMap::<N>::new();
            for _ in 0..leaf_count {
                status.push(true);
            }
            let ops = build_test_mem(&hasher, mmb::mem::Mmb::new(), leaf_count);
            let ops_root = ops.root(&hasher, 0).unwrap();

            let graftable_chunks_for_test = grafting::graftable_chunks::<F>(
                *Location::<F>::try_from(ops.size()).unwrap(),
                grafting_height,
            )
            .min(<BitMap<N> as BitmapReadable<N>>::complete_chunks(&status) as u64)
                as usize;
            let chunk_inputs: Vec<_> = (0..graftable_chunks_for_test)
                .map(|chunk_idx| {
                    (
                        chunk_idx,
                        <BitMap<N> as BitmapReadable<N>>::get_chunk(&status, chunk_idx),
                    )
                })
                .collect();
            let mut leaf_digests = db::compute_grafted_leaves::<F, Sha256, Sequential, N>(
                &hasher,
                &ops,
                chunk_inputs,
                &Sequential,
            )
            .await
            .unwrap();
            leaf_digests.sort_by_key(|(chunk_idx, _)| *chunk_idx);

            let grafted_hasher =
                grafting::GraftedHasher::<F, _>::new(hasher.clone(), grafting_height);
            let mut grafted = Mem::<F, sha256::Digest>::new();
            let merkleized = {
                let mut batch = grafted.new_batch();
                for (_, digest) in leaf_digests {
                    batch = batch.add_leaf_digest(digest);
                }
                batch.merkleize(&grafted, &grafted_hasher)
            };
            grafted.apply_batch(&merkleized).unwrap();

            let storage = grafting::Storage::new(&grafted, grafting_height, &ops, hasher.clone());
            let partial = {
                let (chunk, next_bit) = status.last_chunk();
                Some((*chunk, next_bit))
            };
            let ops_leaves_for_root = Location::<F>::try_from(ops.size()).unwrap();
            let root = db::compute_db_root::<F, Sha256, _, _, N>(
                &hasher,
                &status,
                &storage,
                ops_leaves_for_root,
                partial,
                Location::new(0),
                &ops_root,
            )
            .await
            .unwrap();

            let leaves_loc = mmb::Location::new(leaf_count);
            let proof = RangeProof::new(
                &hasher,
                &status,
                &storage,
                Location::new(0),
                start_loc..leaves_loc,
                ops_root,
            )
            .await
            .unwrap();

            let elements = (*start_loc..leaf_count)
                .map(|idx| hasher.digest(&idx.to_be_bytes()))
                .collect::<Vec<_>>();
            let start_chunk_idx = (*start_loc / chunk_bits) as usize;
            let end_chunk_idx = complete_chunks as usize;
            let chunks = (start_chunk_idx..=end_chunk_idx)
                .map(|chunk_idx| <BitMap<N> as BitmapReadable<N>>::get_chunk(&status, chunk_idx))
                .collect::<Vec<_>>();
            assert!(proof.verify(&hasher, start_loc, &elements, &chunks, &root,));
        });
    }
    #[test_traced]
    fn test_range_proof_rejects_unexpected_partial_chunk_digest() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            type F = mmb::Family;
            const N: usize = 1;

            let hasher = qmdb::hasher::<Sha256>();
            let grafting_height = grafting::height::<N>();
            let chunk_bits = BitMap::<N>::CHUNK_SIZE_BITS;

            let leaf_count = chunk_bits * 2; // Perfect chunks, NO partial trailing bits
            let mut status = BitMap::<N>::new();
            for _ in 0..leaf_count {
                status.push(true);
            }
            let ops = build_test_mem(&hasher, mmb::mem::Mmb::new(), leaf_count);
            let ops_root = ops.root(&hasher, 0).unwrap();

            let graftable_chunks_for_test = grafting::graftable_chunks::<F>(
                *Location::<F>::try_from(ops.size()).unwrap(),
                grafting_height,
            )
            .min(<BitMap<N> as BitmapReadable<N>>::complete_chunks(&status) as u64)
                as usize;
            let chunk_inputs: Vec<_> = (0..graftable_chunks_for_test)
                .map(|chunk_idx| {
                    (
                        chunk_idx,
                        <BitMap<N> as BitmapReadable<N>>::get_chunk(&status, chunk_idx),
                    )
                })
                .collect();
            let mut leaf_digests = db::compute_grafted_leaves::<F, Sha256, Sequential, N>(
                &hasher,
                &ops,
                chunk_inputs,
                &Sequential,
            )
            .await
            .unwrap();
            leaf_digests.sort_by_key(|(chunk_idx, _)| *chunk_idx);

            let grafted_hasher =
                grafting::GraftedHasher::<F, _>::new(hasher.clone(), grafting_height);
            let mut grafted = Mem::<F, sha256::Digest>::new();
            let merkleized = {
                let mut batch = grafted.new_batch();
                for (_, digest) in leaf_digests {
                    batch = batch.add_leaf_digest(digest);
                }
                batch.merkleize(&grafted, &grafted_hasher)
            };
            grafted.apply_batch(&merkleized).unwrap();

            let storage = grafting::Storage::new(&grafted, grafting_height, &ops, hasher.clone());
            let ops_leaves_for_root = Location::<F>::try_from(ops.size()).unwrap();
            let root = db::compute_db_root::<F, Sha256, _, _, N>(
                &hasher,
                &status,
                &storage,
                ops_leaves_for_root,
                None,
                Location::new(0),
                &ops_root,
            )
            .await
            .unwrap();

            let loc = mmb::Location::new(0);
            let mut proof = RangeProof::new(
                &hasher,
                &status,
                &storage,
                Location::new(0),
                loc..loc + 1,
                ops_root,
            )
            .await
            .unwrap();

            let element = hasher.digest(&(*loc).to_be_bytes());
            let chunk = <BitMap<N> as BitmapReadable<N>>::get_chunk(&status, 0);

            // Tamper with the proof by injecting a fake partial chunk digest
            let mut tampered = proof.clone();
            tampered.partial_chunk_digest = Some(hasher.digest(b"fake partial chunk"));
            assert!(!tampered.verify(&hasher, loc, &[element], &[chunk], &root,));

            proof.partial_chunk_digest = Some(hasher.digest(b"fake partial chunk"));
            assert!(!proof.verify(&hasher, loc, &[element], &[chunk], &root,));
        });
    }

    /// Active chunks always have a single h=G peak; multi-peak structure can only appear
    /// at the pending-chunk index. This test exhaustively scans MMB sizes that have a
    /// pending chunk (the only configuration where multi-peak chunks ever existed) and
    /// asserts that every graftable chunk has exactly one peak.
    #[test_traced]
    fn test_graftable_chunks_always_single_peak_at_pending_sizes() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            type F = mmb::Family;
            const N: usize = 1;

            let hasher = qmdb::hasher::<Sha256>();
            let grafting_height = grafting::height::<N>();
            let chunk_bits = BitMap::<N>::CHUNK_SIZE_BITS;

            let mut found_any_pending = false;
            for leaves in chunk_bits * 3..=128u64 {
                let leaves_loc = mmb::Location::new(leaves);
                let leaves_count = *leaves_loc;
                let complete = leaves_count / chunk_bits;
                let graftable = grafting::graftable_chunks::<F>(leaves_count, grafting_height)
                    .min(complete);
                if graftable == complete {
                    continue; // no pending chunk at this size
                }
                found_any_pending = true;

                // Pending chunks (index >= graftable) are allowed multi-peak; their digests
                // are hashed into the canonical root separately.
                let size = F::location_to_position(leaves_loc);
                for chunk_idx in 0..graftable {
                    let count = F::chunk_peaks(size, chunk_idx, grafting_height).count();
                    assert_eq!(
                        count, 1,
                        "graftable chunk {chunk_idx} has {count} peaks (leaves={leaves_count}, graftable={graftable}, complete={complete})"
                    );
                }
            }
            assert!(
                found_any_pending,
                "expected at least one MMB size in [{}, 128] with a pending chunk",
                chunk_bits * 3
            );

            // End-to-end: build a proof for an op in a chunk-aligned MMB whose chunk 1 is
            // multi-peak, and confirm the proof has only the standard digest material.
            let leaf_count = (chunk_bits * 2..=256u64)
                .filter(|leaves| leaves % chunk_bits == 0)
                .find(|&leaves| {
                    let size = F::location_to_position(mmb::Location::new(leaves));
                    F::chunk_peaks(size, 1, grafting_height).nth(1).is_some()
                })
                .expect("expected a chunk-aligned MMB size whose chunk 1 is multi-peak");
            let loc = mmb::Location::new(chunk_bits + 1);

            let mut status = BitMap::<N>::new();
            for _ in 0..leaf_count {
                status.push(true);
            }
            let ops = build_test_mem(&hasher, mmb::mem::Mmb::new(), leaf_count);
            let ops_root = ops.root(&hasher, 0).unwrap();

            let graftable_chunks_for_test = grafting::graftable_chunks::<F>(
                *Location::<F>::try_from(ops.size()).unwrap(),
                grafting_height,
            )
            .min(<BitMap<N> as BitmapReadable<N>>::complete_chunks(&status) as u64)
                as usize;
            let chunk_inputs: Vec<_> = (0..graftable_chunks_for_test)
                .map(|chunk_idx| {
                    (
                        chunk_idx,
                        <BitMap<N> as BitmapReadable<N>>::get_chunk(&status, chunk_idx),
                    )
                })
                .collect();
            let mut leaf_digests = db::compute_grafted_leaves::<F, Sha256, Sequential, N>(
                &hasher,
                &ops,
                chunk_inputs,
                &Sequential,
            )
            .await
            .unwrap();
            leaf_digests.sort_by_key(|(chunk_idx, _)| *chunk_idx);

            let grafted_hasher =
                grafting::GraftedHasher::<F, _>::new(hasher.clone(), grafting_height);
            let mut grafted = Mem::<F, sha256::Digest>::new();
            let merkleized = {
                let mut batch = grafted.new_batch();
                for (_, digest) in leaf_digests {
                    batch = batch.add_leaf_digest(digest);
                }
                batch.merkleize(&grafted, &grafted_hasher)
            };
            grafted.apply_batch(&merkleized).unwrap();

            let storage = grafting::Storage::new(&grafted, grafting_height, &ops, hasher.clone());
            let ops_leaves_for_root = Location::<F>::try_from(ops.size()).unwrap();
            let root = db::compute_db_root::<F, Sha256, _, _, N>(
                &hasher,
                &status,
                &storage,
                ops_leaves_for_root,
                None,
                Location::new(0),
                &ops_root,
            )
            .await
            .unwrap();
            let proof = RangeProof::new(
                &hasher,
                &status,
                &storage,
                Location::new(0),
                loc..loc + 1,
                ops_root,
            )
            .await
            .unwrap();

            let element = hasher.digest(&(*loc).to_be_bytes());
            let chunk_idx = (*loc / chunk_bits) as usize;
            assert!(proof.verify(
                &hasher,
                loc,
                &[element],
                &[<BitMap<N> as BitmapReadable<N>>::get_chunk(
                    &status, chunk_idx
                )],
                &root,
            ));

            let mut tampered = proof.clone();
            tampered.proof.inactive_peaks = 1;
            assert!(!tampered.verify(
                &hasher,
                loc,
                &[element],
                &[<BitMap<N> as BitmapReadable<N>>::get_chunk(
                    &status, chunk_idx
                )],
                &root,
            ));

            let mut tampered = proof.clone();
            tampered.proof.inactive_peaks = usize::MAX;
            assert!(!tampered.verify(
                &hasher,
                loc,
                &[element],
                &[<BitMap<N> as BitmapReadable<N>>::get_chunk(
                    &status, chunk_idx
                )],
                &root,
            ));

            let mut tampered = proof;
            assert!(!tampered.proof.digests.is_empty());
            tampered.proof.digests[0] = hasher.digest(b"fake generic sibling");
            assert!(!tampered.verify(
                &hasher,
                loc,
                &[element],
                &[<BitMap<N> as BitmapReadable<N>>::get_chunk(
                    &status, chunk_idx
                )],
                &root,
            ));
        });
    }

    /// Pending and partial chunks coexist when the bitmap has both (1) a chunk whose bits
    /// are complete but whose h=G ancestor isn't yet born, AND (2) an in-progress trailing
    /// chunk. At G=3 (N=1) chunk 0 is pending for ops_leaves in [8, 11), and any ops_leaves
    /// strictly in (8, 11) also has a partial trailing chunk. This test builds those states
    /// and round-trips a `RangeProof` that spans both regions.
    #[test_traced]
    fn test_pending_and_partial_coexist_at_g_3() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            type F = mmb::Family;
            const N: usize = 1; // G = 3, chunk_bits = 8

            let hasher = qmdb::hasher::<Sha256>();
            let grafting_height = grafting::height::<N>();
            let chunk_bits = BitMap::<N>::CHUNK_SIZE_BITS;
            assert_eq!(grafting_height, 3);
            assert_eq!(chunk_bits, 8);

            // For G=3, chunk 0 is pending while ops_leaves is in [8, 11). Pending+partial
            // coexistence holds for k in [1, 2] (k=3 transitions chunk 0 to graftable).
            for k in 1u64..=2 {
                let leaf_count = chunk_bits + k;
                let mut status = BitMap::<N>::new();
                for _ in 0..leaf_count {
                    status.push(true);
                }
                let ops = build_test_mem(&hasher, mmb::mem::Mmb::new(), leaf_count);
                let ops_root = ops.root(&hasher, 0).unwrap();

                let complete = <BitMap<N> as BitmapReadable<N>>::complete_chunks(&status) as u64;
                let graftable =
                    grafting::graftable_chunks::<F>(leaf_count, grafting_height).min(complete);
                let next_bit = leaf_count % chunk_bits;
                assert_eq!(complete, 1);
                assert_eq!(graftable, 0);
                assert!(next_bit > 0, "expected partial chunk for k={k}");

                // Build a grafted tree from the (zero) graftable chunks and a Storage covering
                // the post-state.
                let chunk_inputs: Vec<_> = (0..graftable as usize)
                    .map(|chunk_idx| {
                        (
                            chunk_idx,
                            <BitMap<N> as BitmapReadable<N>>::get_chunk(&status, chunk_idx),
                        )
                    })
                    .collect();
                let leaf_digests = db::compute_grafted_leaves::<F, Sha256, Sequential, N>(
                    &hasher,
                    &ops,
                    chunk_inputs,
                    &Sequential,
                )
                .await
                .unwrap();
                let grafted_hasher =
                    grafting::GraftedHasher::<F, _>::new(hasher.clone(), grafting_height);
                let mut grafted = Mem::<F, sha256::Digest>::new();
                if !leaf_digests.is_empty() {
                    let merkleized = {
                        let mut batch = grafted.new_batch();
                        for (_, digest) in leaf_digests {
                            batch = batch.add_leaf_digest(digest);
                        }
                        batch.merkleize(&grafted, &grafted_hasher)
                    };
                    grafted.apply_batch(&merkleized).unwrap();
                }
                let storage =
                    grafting::Storage::new(&grafted, grafting_height, &ops, hasher.clone());

                let ops_leaves_for_root = Location::<F>::try_from(ops.size()).unwrap();
                let canonical_root = db::compute_db_root::<F, Sha256, _, _, N>(
                    &hasher,
                    &status,
                    &storage,
                    ops_leaves_for_root,
                    db::partial_chunk::<_, N>(&status),
                    Location::new(0),
                    &ops_root,
                )
                .await
                .unwrap();

                // OpsRootWitness round-trip
                let pending_chunk_digest =
                    db::pending_chunk::<F, _, N>(&status, ops_leaves_for_root, grafting_height)
                        .unwrap()
                        .map(|c| hasher.digest(&c));
                let partial_digest =
                    db::partial_chunk::<_, N>(&status).map(|(c, nb)| (nb, hasher.digest(&c)));
                let grafted_root = db::compute_grafted_root::<F, Sha256, _, _, N>(
                    &hasher,
                    &status,
                    &storage,
                    ops_leaves_for_root,
                    Location::new(0),
                )
                .await
                .unwrap();
                let witness = OpsRootWitness {
                    grafted_root,
                    pending_chunk_digest,
                    partial_chunk: partial_digest,
                };
                assert!(
                    witness.verify(&hasher, &ops_root, &canonical_root),
                    "OpsRootWitness verify failed at k={k}"
                );
                assert!(
                    pending_chunk_digest.is_some(),
                    "expected pending chunk at k={k}"
                );
                assert!(
                    witness.partial_chunk.is_some(),
                    "expected partial chunk at k={k}"
                );

                // Range proof spanning the pending chunk into the partial bits
                let start = mmb::Location::new(0);
                let end = mmb::Location::new(leaf_count);
                let proof = RangeProof::new(
                    &hasher,
                    &status,
                    &storage,
                    Location::new(0),
                    start..end,
                    ops_root,
                )
                .await
                .unwrap();
                assert!(
                    proof.pending_chunk_digest.is_some(),
                    "expected RangeProof pending_chunk_digest at k={k}"
                );
                assert!(
                    proof.partial_chunk_digest.is_some(),
                    "expected RangeProof partial_chunk_digest at k={k}"
                );

                let elements: Vec<sha256::Digest> = (0..leaf_count)
                    .map(|i| hasher.digest(&i.to_be_bytes()))
                    .collect();
                // Range covers chunks 0..=1: chunk 0 is pending, chunk 1 is partial. Provide both.
                let chunks: Vec<[u8; N]> = (0..=1)
                    .map(|i| <BitMap<N> as BitmapReadable<N>>::get_chunk(&status, i))
                    .collect();
                assert!(
                    proof.verify(&hasher, start, &elements, &chunks, &canonical_root),
                    "RangeProof verify failed at k={k}"
                );

                let pending_loc = mmb::Location::new(3);
                let pending_proof = RangeProof::new(
                    &hasher,
                    &status,
                    &storage,
                    Location::new(0),
                    pending_loc..pending_loc + 1,
                    ops_root,
                )
                .await
                .unwrap();
                assert!(
                    pending_proof.pending_chunk_digest.is_some(),
                    "expected single-element proof to carry pending chunk digest at k={k}"
                );
                let pending_element = hasher.digest(&(*pending_loc).to_be_bytes());
                assert!(
                    pending_proof.verify(
                        &hasher,
                        pending_loc,
                        &[pending_element],
                        &[chunks[0]],
                        &canonical_root,
                    ),
                    "single-element proof inside pending chunk failed at k={k}"
                );

                // Tamper with the pending chunk digest or its supplied bytes.
                let mut tampered = proof.clone();
                tampered.pending_chunk_digest = Some(hasher.digest(b"fake pending"));
                assert!(
                    !tampered.verify(&hasher, start, &elements, &chunks, &canonical_root),
                    "tampered pending digest accepted at k={k}"
                );

                let mut tampered = proof.clone();
                tampered.pending_chunk_digest = None;
                assert!(
                    !tampered.verify(&hasher, start, &elements, &chunks, &canonical_root),
                    "missing pending digest accepted at k={k}"
                );

                let mut bad_chunks = chunks.clone();
                bad_chunks[0][0] ^= 1;
                assert!(
                    !proof.verify(&hasher, start, &elements, &bad_chunks, &canonical_root),
                    "tampered pending chunk bytes accepted at k={k}"
                );
            }
        });
    }

    /// Appending one op at the exact birth size of a pending chunk's h=G ancestor causes
    /// the chunk to transition from pending to graftable. The canonical root must change, and
    /// a freshly-rebuilt grafted tree from the post-state must contain the now-graftable
    /// chunk's leaf.
    #[test_traced]
    fn test_pending_to_graftable_transition_at_birth_size() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            type F = mmb::Family;
            const N: usize = 1; // G = 3, chunk_bits = 8

            let hasher = qmdb::hasher::<Sha256>();
            let grafting_height = grafting::height::<N>();
            assert_eq!(grafting_height, 3);

            // chunk 0's h=G ancestor: birth = 3*2^(G-1) - 1 = 11 for G=3.
            let birth = (3u64 << (grafting_height - 1)) - 1;
            let pre_state_leaves = birth - 1; // = 10: chunk 0 still pending
            let post_state_leaves = birth; // = 11: chunk 0 just graftable

            assert_eq!(pre_state_leaves, 10);
            assert_eq!(post_state_leaves, 11);

            let graftable_pre = grafting::graftable_chunks::<F>(pre_state_leaves, grafting_height);
            let graftable_post =
                grafting::graftable_chunks::<F>(post_state_leaves, grafting_height);
            assert_eq!(graftable_pre, 0);
            assert_eq!(graftable_post, 1);

            // Pre-state canonical root: chunk 0 is pending; grafted tree empty.
            let mut status_pre = BitMap::<N>::new();
            for _ in 0..pre_state_leaves {
                status_pre.push(true);
            }
            let ops_pre = build_test_mem(&hasher, mmb::mem::Mmb::new(), pre_state_leaves);
            let ops_root_pre = ops_pre.root(&hasher, 0).unwrap();
            let grafted_pre = Mem::<F, sha256::Digest>::new();
            let storage_pre =
                grafting::Storage::new(&grafted_pre, grafting_height, &ops_pre, hasher.clone());
            let canonical_pre = db::compute_db_root::<F, Sha256, _, _, N>(
                &hasher,
                &status_pre,
                &storage_pre,
                Location::<F>::new(pre_state_leaves),
                db::partial_chunk::<_, N>(&status_pre),
                Location::new(0),
                &ops_root_pre,
            )
            .await
            .unwrap();

            // Post-state canonical root.
            let mut status_post = BitMap::<N>::new();
            for _ in 0..post_state_leaves {
                status_post.push(true);
            }
            let ops_post = build_test_mem(&hasher, mmb::mem::Mmb::new(), post_state_leaves);
            let ops_root_post = ops_post.root(&hasher, 0).unwrap();
            // After transition chunk 0 has a single h=G ancestor; build the grafted tree.
            let leaf_digests = db::compute_grafted_leaves::<F, Sha256, Sequential, N>(
                &hasher,
                &ops_post,
                core::iter::once((
                    0usize,
                    <BitMap<N> as BitmapReadable<N>>::get_chunk(&status_post, 0),
                )),
                &Sequential,
            )
            .await
            .unwrap();
            assert_eq!(
                leaf_digests.len(),
                1,
                "post-state must have 1 graftable chunk"
            );
            let grafted_hasher =
                grafting::GraftedHasher::<F, _>::new(hasher.clone(), grafting_height);
            let mut grafted_post = Mem::<F, sha256::Digest>::new();
            let merkleized = grafted_post
                .new_batch()
                .add_leaf_digest(leaf_digests[0].1)
                .merkleize(&grafted_post, &grafted_hasher);
            grafted_post.apply_batch(&merkleized).unwrap();
            let storage_post =
                grafting::Storage::new(&grafted_post, grafting_height, &ops_post, hasher.clone());

            let canonical_post = db::compute_db_root::<F, Sha256, _, _, N>(
                &hasher,
                &status_post,
                &storage_post,
                Location::<F>::new(post_state_leaves),
                db::partial_chunk::<_, N>(&status_post),
                Location::new(0),
                &ops_root_post,
            )
            .await
            .unwrap();

            assert_ne!(
                canonical_pre, canonical_post,
                "canonical root must change when chunk 0 transitions from pending to graftable"
            );
        });
    }

    #[test_traced]
    fn test_range_proof_allows_ops_and_grafted_inactive_counts_to_differ() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            type F = mmb::Family;
            const N: usize = 1;

            let hasher = qmdb::hasher::<Sha256>();
            let grafting_height = grafting::height::<N>();
            let chunk_bits = BitMap::<N>::CHUNK_SIZE_BITS;
            let leaf_count = chunk_bits;
            let leaves = mmb::Location::new(leaf_count);
            let inactivity_floor = mmb::Location::new(chunk_bits - 2);

            let ops_inactive_peaks =
                F::inactive_peaks(F::location_to_position(leaves), inactivity_floor);
            let aligned_inactive = grafting::chunk_aligned_inactive_peaks::<F>(
                leaves,
                inactivity_floor,
                grafting_height,
            )
            .unwrap();
            assert_ne!(ops_inactive_peaks, aligned_inactive);

            let mut status = BitMap::<N>::new();
            for _ in 0..leaf_count {
                status.push(true);
            }
            let ops = build_test_mem(&hasher, mmb::mem::Mmb::new(), leaf_count);

            // The ops root is the inner QMDB log root and commits the ops-tree inactive peak count.
            // The grafted bitmap root commits the chunk-aligned count, since bitmap chunks are
            // the atomic inactive-prefix boundary for the current root.
            let ops_root = ops.root(&hasher, ops_inactive_peaks).unwrap();

            let graftable_chunks_for_test = grafting::graftable_chunks::<F>(
                *Location::<F>::try_from(ops.size()).unwrap(),
                grafting_height,
            )
            .min(<BitMap<N> as BitmapReadable<N>>::complete_chunks(&status) as u64)
                as usize;
            let chunk_inputs: Vec<_> = (0..graftable_chunks_for_test)
                .map(|chunk_idx| {
                    (
                        chunk_idx,
                        <BitMap<N> as BitmapReadable<N>>::get_chunk(&status, chunk_idx),
                    )
                })
                .collect();
            let mut leaf_digests = db::compute_grafted_leaves::<F, Sha256, Sequential, N>(
                &hasher,
                &ops,
                chunk_inputs,
                &Sequential,
            )
            .await
            .unwrap();
            leaf_digests.sort_by_key(|(chunk_idx, _)| *chunk_idx);

            let grafted_hasher =
                grafting::GraftedHasher::<F, _>::new(hasher.clone(), grafting_height);
            let mut grafted = Mem::<F, sha256::Digest>::new();
            let merkleized = {
                let mut batch = grafted.new_batch();
                for (_, digest) in leaf_digests {
                    batch = batch.add_leaf_digest(digest);
                }
                batch.merkleize(&grafted, &grafted_hasher)
            };
            grafted.apply_batch(&merkleized).unwrap();

            let storage = grafting::Storage::new(&grafted, grafting_height, &ops, hasher.clone());
            let ops_leaves_for_root = Location::<F>::try_from(ops.size()).unwrap();
            let root = db::compute_db_root::<F, Sha256, _, _, N>(
                &hasher,
                &status,
                &storage,
                ops_leaves_for_root,
                None,
                inactivity_floor,
                &ops_root,
            )
            .await
            .unwrap();

            let loc = mmb::Location::new(chunk_bits - 1);
            let proof = RangeProof::new(
                &hasher,
                &status,
                &storage,
                inactivity_floor,
                loc..loc + 1,
                ops_root,
            )
            .await
            .unwrap();
            assert_eq!(proof.proof.inactive_peaks, aligned_inactive);

            let element = hasher.digest(&(*loc).to_be_bytes());
            let chunk = <BitMap<N> as BitmapReadable<N>>::get_chunk(&status, 0);
            assert!(proof.verify(&hasher, loc, &[element], &[chunk], &root));
        });
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::super::{OperationProof, OpsRootWitness, RangeProof};
        use crate::merkle::{mmb, mmr};
        use commonware_codec::conformance::CodecConformance;
        use commonware_cryptography::sha256::Digest as Sha256Digest;

        commonware_conformance::conformance_tests! {
            CodecConformance<OpsRootWitness<Sha256Digest>>,
            CodecConformance<RangeProof<mmr::Family, Sha256Digest>>,
            CodecConformance<RangeProof<mmb::Family, Sha256Digest>>,
            CodecConformance<OperationProof<mmr::Family, Sha256Digest, 32>>,
            CodecConformance<OperationProof<mmb::Family, Sha256Digest, 32>>,
        }
    }
}
