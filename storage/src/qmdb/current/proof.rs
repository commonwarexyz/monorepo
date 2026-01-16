//! Proof types for [crate::qmdb::current] authenticated databases.
//!
//! This module provides:
//! - [RangeProof]: Proves a range of operations exist in the database.
//! - [OperationProof]: Proves a specific operation is active in the database.

use crate::{
    bitmap::{partial_chunk_root, CleanBitMap},
    journal::contiguous::Contiguous,
    mmr::{
        grafting::{Storage as GraftingStorage, Verifier},
        hasher::Hasher,
        journaled::Mmr,
        mem::Clean,
        storage::Storage,
        verification, Location, Proof,
    },
    qmdb::Error,
};
use commonware_codec::Codec;
use commonware_cryptography::{Digest, Hasher as CHasher};
use commonware_runtime::{Clock, Metrics, Storage as RStorage};
use commonware_utils::bitmap::BitMap;
use core::ops::Range;
use futures::future::try_join_all;
use std::num::NonZeroU64;
use tracing::debug;

/// A proof that a range of operations exist in the database.
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct RangeProof<D: Digest> {
    /// The MMR digest material required to verify the proof.
    pub proof: Proof<D>,

    /// The partial chunk digest from the status bitmap at the time of proof generation, if any.
    pub partial_chunk_digest: Option<D>,
}

impl<D: Digest> RangeProof<D> {
    /// Create a new range proof for the provided `range` of operations.
    pub async fn new<
        E: RStorage + Clock + Metrics,
        H: CHasher<Digest = D>,
        S: Storage<D>,
        const N: usize,
    >(
        hasher: &mut H,
        status: &CleanBitMap<E, D, N>,
        grafting_height: u32,
        mmr: &S,
        range: Range<Location>,
    ) -> Result<Self, Error> {
        let grafted_mmr = GraftingStorage::<'_, H, _, _>::new(status, mmr, grafting_height);
        let proof = verification::range_proof(&grafted_mmr, range).await?;

        let (last_chunk, next_bit) = status.last_chunk();
        let partial_chunk_digest = if next_bit != CleanBitMap::<E, D, N>::CHUNK_SIZE_BITS {
            // Last chunk is incomplete, meaning it's not yet in the MMR and needs to be included
            // in the proof.
            hasher.update(last_chunk);
            Some(hasher.finalize())
        } else {
            None
        };

        Ok(Self {
            proof,
            partial_chunk_digest,
        })
    }

    /// Returns a proof that the specified range of operations are part of the database, along with
    /// the operations from the range and their activity status chunks. A truncated range (from
    /// hitting the max) can be detected by looking at the length of the returned operations vector.
    ///
    /// # Errors
    ///
    /// Returns [crate::mmr::Error::LocationOverflow] if `start_loc` > [crate::mmr::MAX_LOCATION].
    /// Returns [crate::mmr::Error::RangeOutOfBounds] if `start_loc` >= number of leaves in the MMR.
    pub async fn new_with_ops<
        E: RStorage + Clock + Metrics,
        H: CHasher<Digest = D>,
        C: Contiguous,
        const N: usize,
    >(
        hasher: &mut H,
        status: &CleanBitMap<E, D, N>,
        height: u32,
        mmr: &Mmr<E, D, Clean<D>>,
        log: &C,
        start_loc: Location,
        max_ops: NonZeroU64,
    ) -> Result<(Self, Vec<C::Item>, Vec<[u8; N]>), Error> {
        // Compute the start and end locations & positions of the range.
        let leaves = mmr.leaves();
        if start_loc >= leaves {
            return Err(crate::mmr::Error::RangeOutOfBounds(start_loc).into());
        }
        let max_loc = start_loc.saturating_add(max_ops.get());
        let end_loc = core::cmp::min(max_loc, leaves);

        // Generate the proof from the grafted MMR.
        let proof = Self::new(hasher, status, height, mmr, start_loc..end_loc).await?;

        // Collect the operations necessary to verify the proof.
        let mut ops = Vec::with_capacity((*end_loc - *start_loc) as usize);
        let futures = (*start_loc..*end_loc)
            .map(|i| log.read(i))
            .collect::<Vec<_>>();
        try_join_all(futures)
            .await?
            .into_iter()
            .for_each(|op| ops.push(op));

        // Gather the chunks necessary to verify the proof.
        let chunk_bits = BitMap::<N>::CHUNK_SIZE_BITS;
        let start = *start_loc / chunk_bits; // chunk that contains the first bit
        let end = (*end_loc - 1) / chunk_bits; // chunk that contains the last bit
        let mut chunks = Vec::with_capacity((end - start + 1) as usize);
        for i in start..=end {
            let bit_offset = i * chunk_bits;
            let chunk = *status.get_chunk_containing(bit_offset);
            chunks.push(chunk);
        }

        Ok((proof, ops, chunks))
    }

    /// Return true if the given sequence of `ops` were applied starting at location `start_loc` in
    /// the db with the provided root, and having the activity status described by `chunks`.
    pub fn verify<H: CHasher<Digest = D>, O: Codec, const N: usize>(
        &self,
        hasher: &mut H,
        grafting_height: u32,
        start_loc: Location,
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
        let start = *start_loc / chunk_bits; // chunk that contains first bit
        let end = (*end_loc.saturating_sub(1)) / chunk_bits; // chunk that contains the last bit
        let expected = end - start + 1;
        let actual = chunks.len() as u64;
        if expected != actual {
            debug!(expected, actual, "verification failed, chunk mismatch");
            return false;
        }

        let elements = ops.iter().map(|op| op.encode()).collect::<Vec<_>>();

        let chunk_vec = chunks.iter().map(|c| c.as_ref()).collect::<Vec<_>>();
        let start_chunk_loc = *start_loc / BitMap::<N>::CHUNK_SIZE_BITS;
        let mut verifier = Verifier::<H>::new(
            grafting_height,
            Location::new_unchecked(start_chunk_loc),
            chunk_vec,
        );

        let next_bit = *leaves % BitMap::<N>::CHUNK_SIZE_BITS;
        if next_bit == 0 {
            return self
                .proof
                .verify_range_inclusion(&mut verifier, &elements, start_loc, root);
        }

        // The proof must contain the partial chunk digest.
        let Some(last_chunk_digest) = self.partial_chunk_digest else {
            debug!("proof has no partial chunk digest");
            return false;
        };

        // If the proof is over an operation in the partial chunk, we need to verify the last chunk
        // digest from the proof matches the digest of chunk, since these bits are not part of the
        // mmr.
        if *(end_loc - 1) / BitMap::<N>::CHUNK_SIZE_BITS == *leaves / BitMap::<N>::CHUNK_SIZE_BITS {
            let Some(last_chunk) = chunks.last() else {
                debug!("chunks is empty");
                return false;
            };
            let expected_last_chunk_digest = verifier.digest(last_chunk);
            if last_chunk_digest != expected_last_chunk_digest {
                debug!("last chunk digest does not match expected value");
                return false;
            }
        }

        // Reconstruct the MMR root.
        let mmr_root = match self
            .proof
            .reconstruct_root(&mut verifier, &elements, start_loc)
        {
            Ok(root) => root,
            Err(error) => {
                debug!(error = ?error, "invalid proof input");
                return false;
            }
        };

        let reconstructed_root =
            partial_chunk_root::<H, N>(hasher, &mmr_root, next_bit, &last_chunk_digest);

        reconstructed_root == *root
    }
}

/// A proof that a specific operation is currently active in the database.
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct OperationProof<D: Digest, const N: usize> {
    /// The location of the operation in the db.
    pub loc: Location,

    /// The status bitmap chunk that contains the bit corresponding the operation's location.
    pub chunk: [u8; N],

    /// The range proof that incorporates activity status for the operation designated by `loc`.
    pub range_proof: RangeProof<D>,
}

impl<D: Digest, const N: usize> OperationProof<D, N> {
    /// Return an inclusion proof that incorporates activity status for the operation designated by
    /// `loc`.
    ///
    /// # Panics
    ///
    /// - Panics if `loc` is out of bounds.
    pub async fn new<E: RStorage + Clock + Metrics, H: CHasher<Digest = D>, S: Storage<D>>(
        hasher: &mut H,
        status: &CleanBitMap<E, D, N>,
        grafting_height: u32,
        mmr: &S,
        loc: Location,
    ) -> Result<Self, Error> {
        // Since `loc` is assumed to be in-bounds, `loc + 1` won't overflow.
        let range_proof =
            RangeProof::<D>::new(hasher, status, grafting_height, mmr, loc..loc + 1).await?;
        let chunk = *status.get_chunk_containing(*loc);

        Ok(Self {
            loc,
            chunk,
            range_proof,
        })
    }

    /// Verify that the proof proves that `operation` is active in the database with the given
    /// `root`.
    pub fn verify<H: CHasher<Digest = D>, O: Codec>(
        &self,
        hasher: &mut H,
        grafting_height: u32,
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

        self.range_proof.verify(
            hasher,
            grafting_height,
            self.loc,
            &[operation],
            &[self.chunk],
            root,
        )
    }
}
