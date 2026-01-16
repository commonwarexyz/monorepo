mod authenticated;
pub use authenticated::{BitMap, CleanBitMap, DirtyBitMap};
use commonware_cryptography::Hasher;
use commonware_utils::bitmap::BitMap as UtilBitMap;

/// Returns a root digest that incorporates bits not yet part of the MMR because they
/// belong to the last (unfilled) chunk.
pub fn partial_chunk_root<H: Hasher, const N: usize>(
    hasher: &mut H,
    mmr_root: &H::Digest,
    next_bit: u64,
    last_chunk_digest: &H::Digest,
) -> H::Digest {
    assert!(next_bit > 0);
    assert!(next_bit < UtilBitMap::<N>::CHUNK_SIZE_BITS);
    hasher.update(mmr_root);
    hasher.update(&next_bit.to_be_bytes());
    hasher.update(last_chunk_digest);
    hasher.finalize()
}
