//! Authenticated databases (ADBs) that provide succinct proofs of _any_ value ever associated with
//! a key, and also whether that value is the _current_ value associated with it. The
//! implementations are based on a [crate::adb::any::fixed] authenticated database combined with an
//! authenticated [BitMap] over the activity status of each operation. The two structures are
//! "grafted" together to minimize proof sizes.

use crate::{
    mmr::{bitmap::BitMap, grafting::Verifier, hasher::Hasher, Location, Proof},
    translator::Translator,
};
use commonware_codec::CodecFixed;
use commonware_cryptography::Hasher as CHasher;
use commonware_runtime::{buffer::PoolRef, ThreadPool};
use commonware_utils::Array;
use std::num::{NonZeroU64, NonZeroUsize};
use tracing::debug;

pub mod unordered;
pub use unordered::Current;

/// Configuration for a [Current] authenticated db.
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

/// The information required to verify a key value proof from a Current db.
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct KeyValueProofInfo<K: Array, V: CodecFixed<Cfg = ()>, const N: usize> {
    /// The key whose value is being proven.
    pub key: K,

    /// The value of the key.
    pub value: V,

    /// The location of the operation that assigned this value to the key.
    pub loc: Location,

    /// The status bitmap chunk that contains the bit corresponding the operation's location.
    pub chunk: [u8; N],
}

/// Verify a key value proof created by a Current db's `key_value_proof` function, returning true if
/// and only if the operation at location `loc` was active and has the value `element` in the
/// Current db with the given `root`.
fn verify_key_value_proof<H: CHasher, const N: usize>(
    hasher: &mut H,
    proof: &Proof<H::Digest>,
    loc: Location,
    chunk: &[u8; N],
    root: &H::Digest,
    element: &[u8],
    grafting_height: u32,
) -> bool {
    let Ok(op_count) = Location::try_from(proof.size) else {
        debug!("verification failed, invalid proof size");
        return false;
    };

    // Make sure that the bit for the operation in the bitmap chunk is actually a 1 (indicating
    // the operation is indeed active).
    if !BitMap::<H, N>::get_bit_from_chunk(chunk, *loc) {
        debug!(
            loc = ?loc,
            "proof verification failed, operation is inactive"
        );
        return false;
    }

    let num = *loc / BitMap::<H, N>::CHUNK_SIZE_BITS;
    let mut verifier =
        Verifier::<H>::new(grafting_height, Location::new_unchecked(num), vec![chunk]);

    let next_bit = *op_count % BitMap::<H, N>::CHUNK_SIZE_BITS;
    if next_bit == 0 {
        return proof.verify_element_inclusion(&mut verifier, element, loc, root);
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
    if *loc / BitMap::<H, N>::CHUNK_SIZE_BITS == *op_count / BitMap::<H, N>::CHUNK_SIZE_BITS {
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
        BitMap::<H, N>::partial_chunk_root(hasher, &mmr_root, next_bit, &last_chunk_digest);

    reconstructed_root == *root
}
