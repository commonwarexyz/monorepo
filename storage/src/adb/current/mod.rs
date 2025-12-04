//! A _Current_ authenticated database provides succinct proofs of _any_ value ever associated with
//! a key, and also whether that value is the _current_ value associated with it. The
//! implementations are based on a [crate::adb::any] authenticated database combined with an
//! authenticated [BitMap] over the activity status of each operation. The two structures are
//! "grafted" together to minimize proof sizes.

use crate::{
    adb::{any::FixedConfig as AConfig, Error, Keyed},
    journal::contiguous::Contiguous,
    mmr::{
        grafting::{Hasher as GraftingHasher, Storage as GraftingStorage, Verifier},
        hasher::Hasher,
        journaled::Mmr,
        mem::Clean,
        verification, Location, Proof, StandardHasher,
    },
    translator::Translator,
    AuthenticatedBitMap as BitMap,
};
use commonware_codec::Codec;
use commonware_cryptography::{DigestOf, Hasher as CHasher};
use commonware_runtime::{buffer::PoolRef, Clock, Metrics, Storage as RStorage, ThreadPool};
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

/// Return the root of the current adb represented by the provided mmr and bitmap.
///
/// # Errors
///
/// Returns [Error::UncommittedOperations] if there are uncommitted operations.
async fn root<E: RStorage + Clock + Metrics, H: CHasher, const N: usize>(
    hasher: &mut StandardHasher<H>,
    height: u32,
    status: &BitMap<H::Digest, N>,
    mmr: &Mmr<E, H::Digest, Clean<DigestOf<H>>>,
) -> Result<H::Digest, Error> {
    if status.is_dirty() {
        return Err(Error::UncommittedOperations);
    }
    let grafted_mmr = GraftingStorage::<'_, H, _, _>::new(status, mmr, height);
    let mmr_root = grafted_mmr.root(hasher).await?;

    // The digest contains all information from the base mmr, and all information from the peak
    // tree except for the partial chunk, if any.  If we are at a chunk boundary, then this is
    // all the information we need.

    // Handle empty/fully pruned bitmap
    if status.len() == status.pruned_bits() {
        return Ok(mmr_root);
    }

    let (last_chunk, next_bit) = status.last_chunk();
    if next_bit == BitMap::<H::Digest, N>::CHUNK_SIZE_BITS {
        // Last chunk is complete, no partial chunk to add
        return Ok(mmr_root);
    }

    // There are bits in an uncommitted (partial) chunk, so we need to incorporate that
    // information into the root digest. We do so by computing a root in the same format as an
    // unaligned [Bitmap] root, which involves additionally hashing in the number of bits within
    // the last chunk and the digest of the last chunk.
    hasher.inner().update(last_chunk);
    let last_chunk_digest = hasher.inner().finalize();

    Ok(BitMap::<H::Digest, N>::partial_chunk_root(
        hasher.inner(),
        &mmr_root,
        next_bit,
        &last_chunk_digest,
    ))
}

/// Returns a proof that the specified range of operations are part of the database, along with
/// the operations from the range. A truncated range (from hitting the max) can be detected by
/// looking at the length of the returned operations vector. Also returns the bitmap chunks
/// required to verify the proof.
///
/// # Errors
///
/// Returns [crate::mmr::Error::LocationOverflow] if `start_loc` > [crate::mmr::MAX_LOCATION].
/// Returns [crate::mmr::Error::RangeOutOfBounds] if `start_loc` >= number of leaves in the MMR.
/// Returns [Error::UncommittedOperations] if there are uncommitted operations.
async fn range_proof<
    E: RStorage + Clock + Metrics,
    H: CHasher,
    O: Keyed,
    C: Contiguous<Item = O>,
    const N: usize,
>(
    hasher: &mut H,
    status: &BitMap<H::Digest, N>,
    height: u32,
    mmr: &Mmr<E, H::Digest, Clean<DigestOf<H>>>,
    log: &C,
    start_loc: Location,
    max_ops: NonZeroU64,
) -> Result<(Proof<H::Digest>, Vec<O>, Vec<[u8; N]>), Error> {
    if status.is_dirty() {
        return Err(Error::UncommittedOperations);
    };

    // Compute the start and end locations & positions of the range.
    let leaves = mmr.leaves();
    if start_loc >= leaves {
        return Err(crate::mmr::Error::RangeOutOfBounds(start_loc).into());
    }
    let max_loc = start_loc.saturating_add(max_ops.get());
    let end_loc = core::cmp::min(max_loc, leaves);

    // Generate the proof from the grafted MMR.
    let grafted_mmr = GraftingStorage::<'_, H, _, _>::new(status, mmr, height);
    let mut proof = verification::range_proof(&grafted_mmr, start_loc..end_loc).await?;

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
    let chunk_bits = BitMap::<H::Digest, N>::CHUNK_SIZE_BITS;
    let start = *start_loc / chunk_bits; // chunk that contains the very first bit.
    let end = (*end_loc - 1) / chunk_bits; // chunk that contains the very last bit.
    let mut chunks = Vec::with_capacity((end - start + 1) as usize);
    for i in start..=end {
        let bit_offset = i * chunk_bits;
        let chunk = *status.get_chunk_containing(bit_offset);
        chunks.push(chunk);
    }

    let (last_chunk, next_bit) = status.last_chunk();
    if next_bit == BitMap::<H::Digest, N>::CHUNK_SIZE_BITS {
        // Last chunk is complete, no partial chunk to add
        return Ok((proof, ops, chunks));
    }

    hasher.update(last_chunk);
    proof.digests.push(hasher.finalize());

    Ok((proof, ops, chunks))
}

/// Performs merkleization of a grafted bitmap.
async fn merkleize_grafted_bitmap<H, const N: usize>(
    hasher: &mut StandardHasher<H>,
    status: &mut BitMap<H::Digest, N>,
    mmr: &impl crate::mmr::storage::Storage<H::Digest>,
    grafting_height: u32,
) -> Result<(), Error>
where
    H: CHasher,
{
    let mut grafter = GraftingHasher::new(hasher, grafting_height);
    grafter
        .load_grafted_digests(&status.dirty_chunks(), mmr)
        .await?;
    status.merkleize(&mut grafter).await.map_err(Into::into)
}

/// Verify a key value proof created by a Current db's `key_value_proof` function, returning true if
/// and only if the operation at location `loc` was active and has the value `element` in the
/// Current db with the given `root`.
fn verify_key_value_proof<H: CHasher, E: Codec, const N: usize>(
    hasher: &mut H,
    grafting_height: u32,
    proof: &Proof<H::Digest>,
    loc: Location,
    chunk: &[u8; N],
    root: &H::Digest,
    element: E,
) -> bool {
    let Ok(op_count) = Location::try_from(proof.size) else {
        debug!("verification failed, invalid proof size");
        return false;
    };

    // Make sure that the bit for the operation in the bitmap chunk is actually a 1 (indicating
    // the operation is indeed active).
    if !BitMap::<H::Digest, N>::get_bit_from_chunk(chunk, *loc) {
        debug!(
            loc = ?loc,
            "proof verification failed, operation is inactive"
        );
        return false;
    }

    let num = *loc / BitMap::<H::Digest, N>::CHUNK_SIZE_BITS;
    let mut verifier =
        Verifier::<H>::new(grafting_height, Location::new_unchecked(num), vec![chunk]);

    let element = element.encode();
    let next_bit = *op_count % BitMap::<H::Digest, N>::CHUNK_SIZE_BITS;
    if next_bit == 0 {
        return proof.verify_element_inclusion(&mut verifier, &element, loc, root);
    }

    // The proof must contain the partial chunk digest as its last hash.
    if proof.digests.is_empty() {
        debug!("proof has no digests");
        return false;
    }

    let mut proof = proof.clone();
    let last_chunk_digest = proof.digests.pop().unwrap();

    // If the proof is over an operation in the partial chunk, we need to verify the last chunk
    // digest from the proof matches the digest of chunk, since these bits are not part of the mmr.
    if *loc / BitMap::<H::Digest, N>::CHUNK_SIZE_BITS
        == *op_count / BitMap::<H::Digest, N>::CHUNK_SIZE_BITS
    {
        let expected_last_chunk_digest = verifier.digest(chunk);
        if last_chunk_digest != expected_last_chunk_digest {
            debug!("last chunk digest does not match expected value");
            return false;
        }
    }

    // Reconstruct the MMR root.
    let mmr_root = match proof.reconstruct_root(&mut verifier, &[element], loc) {
        Ok(root) => root,
        Err(error) => {
            debug!(error = ?error, "invalid proof input");
            return false;
        }
    };

    let reconstructed_root =
        BitMap::<H::Digest, N>::partial_chunk_root(hasher, &mmr_root, next_bit, &last_chunk_digest);

    reconstructed_root == *root
}

/// Return true if the given sequence of `ops` were applied starting at location `start_loc` in
/// the log with the provided root.
pub fn verify_range_proof<H: CHasher, O: Codec, const N: usize>(
    hasher: &mut StandardHasher<H>,
    grafting_height: u32,
    proof: &Proof<H::Digest>,
    start_loc: Location,
    ops: &[O],
    chunks: &[[u8; N]],
    root: &H::Digest,
) -> bool {
    let Ok(op_count) = Location::try_from(proof.size) else {
        debug!("verification failed, invalid proof size");
        return false;
    };
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
    let start_chunk_loc = *start_loc / BitMap::<H::Digest, N>::CHUNK_SIZE_BITS;
    let mut verifier = Verifier::<H>::new(
        grafting_height,
        Location::new_unchecked(start_chunk_loc),
        chunk_vec,
    );

    let next_bit = *op_count % BitMap::<H::Digest, N>::CHUNK_SIZE_BITS;
    if next_bit == 0 {
        return proof.verify_range_inclusion(&mut verifier, &elements, start_loc, root);
    }

    // The proof must contain the partial chunk digest as its last hash.
    if proof.digests.is_empty() {
        debug!("proof has no digests");
        return false;
    }
    let mut proof = proof.clone();
    let last_chunk_digest = proof.digests.pop().unwrap();

    // Reconstruct the MMR root.
    let mmr_root = match proof.reconstruct_root(&mut verifier, &elements, start_loc) {
        Ok(root) => root,
        Err(error) => {
            debug!(error = ?error, "invalid proof input");
            return false;
        }
    };

    let reconstructed_root = BitMap::<H::Digest, N>::partial_chunk_root(
        hasher.inner(),
        &mmr_root,
        next_bit,
        &last_chunk_digest,
    );

    reconstructed_root == *root
}
