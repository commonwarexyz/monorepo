//! A _Current_ authenticated database provides succinct proofs of _any_ value ever associated with
//! a key, and also whether that value is the _current_ value associated with it. The
//! implementations are based on a [crate::qmdb::any] authenticated database combined with an
//! authenticated [CleanBitMap] over the activity status of each operation.
//! The two structures are "grafted" together to minimize proof sizes.

use crate::{
    bitmap::{CleanBitMap, DirtyBitMap},
    journal::contiguous::Contiguous,
    mmr::{
        grafting::{Hasher as GraftingHasher, Storage as GraftingStorage, Verifier},
        hasher::Hasher,
        journaled::Mmr,
        mem::Clean,
        storage::Storage,
        verification, Location, Proof, StandardHasher,
    },
    qmdb::{any::FixedConfig as AConfig, Error},
    translator::Translator,
};
use commonware_codec::Codec;
use commonware_cryptography::{Digest, DigestOf, Hasher as CHasher};
use commonware_runtime::{buffer::PoolRef, Clock, Metrics, Storage as RStorage, ThreadPool};
use core::ops::Range;
use futures::future::try_join_all;
use std::num::{NonZeroU64, NonZeroUsize};
use tracing::debug;

pub mod ordered;
pub mod unordered;

/// Configuration for a `Current` authenticated db.
#[derive(Clone)]
pub struct Config<T: Translator> {
    /// The name of the storage partition used for the MMR's backing journal.
    pub mmr_journal_partition: String,

    /// The items per blob configuration value used by the MMR journal.
    pub mmr_items_per_blob: NonZeroU64,

    /// The size of the write buffer to use for each blob in the MMR journal.
    pub mmr_write_buffer: NonZeroUsize,

    /// The name of the storage partition used for the MMR's metadata.
    pub mmr_metadata_partition: String,

    /// The name of the storage partition used to persist the (pruned) log of operations.
    pub log_journal_partition: String,

    /// The items per blob configuration value used by the log journal.
    pub log_items_per_blob: NonZeroU64,

    /// The size of the write buffer to use for each blob in the log journal.
    pub log_write_buffer: NonZeroUsize,

    /// The name of the storage partition used for the bitmap metadata.
    pub bitmap_metadata_partition: String,

    /// The translator used by the compressed index.
    pub translator: T,

    /// An optional thread pool to use for parallelizing batch operations.
    pub thread_pool: Option<ThreadPool>,

    /// The buffer pool to use for caching data.
    pub buffer_pool: PoolRef,
}

impl<T: Translator> Config<T> {
    /// Convert this config to an [AConfig] used to initialize the authenticated log.
    pub fn to_any_config(self) -> AConfig<T> {
        AConfig {
            mmr_journal_partition: self.mmr_journal_partition,
            mmr_metadata_partition: self.mmr_metadata_partition,
            mmr_items_per_blob: self.mmr_items_per_blob,
            mmr_write_buffer: self.mmr_write_buffer,
            log_journal_partition: self.log_journal_partition,
            log_items_per_blob: self.log_items_per_blob,
            log_write_buffer: self.log_write_buffer,
            translator: self.translator,
            thread_pool: self.thread_pool,
            buffer_pool: self.buffer_pool,
        }
    }
}

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
    pub async fn new<H: CHasher, S: Storage<H::Digest>, const N: usize>(
        hasher: &mut H,
        status: &CleanBitMap<H::Digest, N>,
        grafting_height: u32,
        mmr: &S,
        range: Range<Location>,
    ) -> Result<RangeProof<H::Digest>, Error> {
        let grafted_mmr = GraftingStorage::<'_, H, _, _>::new(status, mmr, grafting_height);
        let proof = verification::range_proof(&grafted_mmr, range).await?;

        let (last_chunk, next_bit) = status.last_chunk();
        let partial_chunk_digest = if next_bit != CleanBitMap::<H::Digest, N>::CHUNK_SIZE_BITS {
            // Last chunk is incomplete, meaning it's not yet in the MMR and needs to be included
            // in the proof.
            hasher.update(last_chunk);
            Some(hasher.finalize())
        } else {
            None
        };

        Ok(RangeProof {
            proof,
            partial_chunk_digest,
        })
    }

    /// Return true if the given sequence of `ops` were applied starting at location `start_loc` in
    /// the db with the provided root, and having the activity status descibed by `chunks`.
    pub fn verify<H: CHasher<Digest = D>, O: Codec, const N: usize>(
        &self,
        hasher: &mut H,
        grafting_height: u32,
        start_loc: Location,
        ops: &[O],
        chunks: &[[u8; N]],
        root: &H::Digest,
    ) -> bool {
        let Ok(op_count) = Location::try_from(self.proof.size) else {
            debug!("verification failed, invalid proof size");
            return false;
        };

        // Compute the (non-inclusive) end location of the range.
        let Some(end_loc) = start_loc.checked_add(ops.len() as u64) else {
            debug!("verification failed, end_loc overflow");
            return false;
        };
        if end_loc > op_count {
            debug!(
                loc = ?end_loc,
                ?op_count, "proof verification failed, invalid range"
            );
            return false;
        }

        let elements = ops.iter().map(|op| op.encode()).collect::<Vec<_>>();

        let chunk_vec = chunks.iter().map(|c| c.as_ref()).collect::<Vec<_>>();
        let start_chunk_loc = *start_loc / CleanBitMap::<H::Digest, N>::CHUNK_SIZE_BITS;
        let mut verifier = Verifier::<H>::new(
            grafting_height,
            Location::new_unchecked(start_chunk_loc),
            chunk_vec,
        );

        let next_bit = *op_count % CleanBitMap::<H::Digest, N>::CHUNK_SIZE_BITS;
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
        if *(end_loc - 1) / CleanBitMap::<H::Digest, N>::CHUNK_SIZE_BITS
            == *op_count / CleanBitMap::<H::Digest, N>::CHUNK_SIZE_BITS
        {
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

        let reconstructed_root = CleanBitMap::<H::Digest, N>::partial_chunk_root(
            hasher,
            &mmr_root,
            next_bit,
            &last_chunk_digest,
        );

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
    pub async fn new<H: CHasher<Digest = D>, S: Storage<D>>(
        hasher: &mut H,
        status: &CleanBitMap<D, N>,
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
        if !CleanBitMap::<H::Digest, N>::get_bit_from_chunk(&self.chunk, *self.loc) {
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

/// Return the root of the current QMDB represented by the provided mmr and bitmap.
async fn root<E: RStorage + Clock + Metrics, H: CHasher, const N: usize>(
    hasher: &mut StandardHasher<H>,
    height: u32,
    status: &CleanBitMap<H::Digest, N>,
    mmr: &Mmr<E, H::Digest, Clean<DigestOf<H>>>,
) -> Result<H::Digest, Error> {
    let grafted_mmr = GraftingStorage::<'_, H, _, _>::new(status, mmr, height);
    let mmr_root = grafted_mmr.root(hasher).await?;

    // If we are on a chunk boundary, then the mmr_root fully captures the state of the DB.
    let (last_chunk, next_bit) = status.last_chunk();
    if next_bit == CleanBitMap::<H::Digest, N>::CHUNK_SIZE_BITS {
        // Last chunk is complete, no partial chunk to add
        return Ok(mmr_root);
    }

    // There are bits in an uncommitted (partial) chunk, so we need to incorporate that information
    // into the root digest to fully capture the database state. We do so by hashing the mmr root
    // along with the number of bits within the last chunk and the digest of the last chunk.
    hasher.inner().update(last_chunk);
    let last_chunk_digest = hasher.inner().finalize();

    Ok(CleanBitMap::<H::Digest, N>::partial_chunk_root(
        hasher.inner(),
        &mmr_root,
        next_bit,
        &last_chunk_digest,
    ))
}

/// Returns a proof that the specified range of operations are part of the database, along with the
/// operations from the range and their activity status chunks. A truncated range (from hitting the
/// max) can be detected by looking at the length of the returned operations vector.
///
/// # Errors
///
/// Returns [crate::mmr::Error::LocationOverflow] if `start_loc` > [crate::mmr::MAX_LOCATION].
/// Returns [crate::mmr::Error::RangeOutOfBounds] if `start_loc` >= number of leaves in the MMR.
async fn range_proof<E: RStorage + Clock + Metrics, H: CHasher, C: Contiguous, const N: usize>(
    hasher: &mut H,
    status: &CleanBitMap<H::Digest, N>,
    height: u32,
    mmr: &Mmr<E, H::Digest, Clean<DigestOf<H>>>,
    log: &C,
    start_loc: Location,
    max_ops: NonZeroU64,
) -> Result<(RangeProof<H::Digest>, Vec<C::Item>, Vec<[u8; N]>), Error> {
    // Compute the start and end locations & positions of the range.
    let leaves = mmr.leaves();
    if start_loc >= leaves {
        return Err(crate::mmr::Error::RangeOutOfBounds(start_loc).into());
    }
    let max_loc = start_loc.saturating_add(max_ops.get());
    let end_loc = core::cmp::min(max_loc, leaves);

    // Generate the proof from the grafted MMR.
    let proof =
        RangeProof::<H::Digest>::new(hasher, status, height, mmr, start_loc..end_loc).await?;

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
    let chunk_bits = CleanBitMap::<H::Digest, N>::CHUNK_SIZE_BITS;
    let start = *start_loc / chunk_bits; // chunk that contains the very first bit.
    let end = (*end_loc - 1) / chunk_bits; // chunk that contains the very last bit.
    let mut chunks = Vec::with_capacity((end - start + 1) as usize);
    for i in start..=end {
        let bit_offset = i * chunk_bits;
        let chunk = *status.get_chunk_containing(bit_offset);
        chunks.push(chunk);
    }

    Ok((proof, ops, chunks))
}

/// Consumes a `DirtyBitMap`, performs merkleization using the provided hasher and MMR storage,
/// and returns a `CleanBitMap` containing the merkleized result.
///
/// # Arguments
/// * `hasher` - The hasher used for merkleization.
/// * `status` - The `DirtyBitMap` to be merkleized. Ownership is taken.
/// * `mmr` - The MMR storage used for grafting.
/// * `grafting_height` - The height at which grafting occurs.
async fn merkleize_grafted_bitmap<H, const N: usize>(
    hasher: &mut StandardHasher<H>,
    status: DirtyBitMap<H::Digest, N>,
    mmr: &impl crate::mmr::storage::Storage<H::Digest>,
    grafting_height: u32,
) -> Result<CleanBitMap<H::Digest, N>, Error>
where
    H: CHasher,
{
    let mut grafter = GraftingHasher::new(hasher, grafting_height);
    grafter
        .load_grafted_digests(&status.dirty_chunks(), mmr)
        .await?;
    status.merkleize(&mut grafter).await.map_err(Into::into)
}
