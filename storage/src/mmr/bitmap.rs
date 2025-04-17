//! An authenticatable bitmap.

use crate::mmr::{
    iterator::leaf_num_to_pos, mem::Mmr, verification::Proof, verification::Storage, Error,
};
use commonware_codec::FixedSize;
use commonware_cryptography::Hasher as CHasher;

/// Implements the [Storage] trait for generating inclusion proofs over the bitmap.
struct BitmapStorage<'a, H: CHasher> {
    /// The Merkle tree over all bitmap bits other than the last chunk.
    mmr: &'a Mmr<H>,

    /// A pruned Merkle tree over all bits of the bitmap including the last chunk.
    last_chunk_mmr: &'a Mmr<H>,
}

impl<H: CHasher + Send + Sync> Storage<H::Digest> for BitmapStorage<'_, H> {
    async fn get_node(&self, pos: u64) -> Result<Option<H::Digest>, Error> {
        if pos < self.mmr.size() {
            Ok(self.mmr.get_node(pos))
        } else {
            Ok(self.last_chunk_mmr.get_node(pos))
        }
    }

    async fn size(&self) -> Result<u64, Error> {
        Ok(self.last_chunk_mmr.size())
    }
}

/// A bitmap supporting inclusion proofs through Merkelization.
///
/// Merkelization of the bitmap is performed over chunks of DIGEST_SIZE bytes in order to reduce
/// overhead (e.g. by a factor of >256 for 32-byte digests).
pub struct Bitmap<H: CHasher> {
    /// The bitmap itself, in chunks of size DIGEST_SIZE bytes. The number of valid bits in the last
    /// chunk is given by `self.next_bit`. Within each byte, lowest order bits are treated as coming
    /// before higher order bits in the bit ordering.
    bitmap: Vec<u8>,

    /// The position within the last chunk of the bitmap where the next bit is to be appended.
    ///
    /// Invariant: This value is always in the range [0, DIGEST_SIZE * 8).
    next_bit: usize,

    /// A Merkle tree with each leaf representing DIGEST_SIZE*8 bits of the bitmap.
    ///
    /// When a chunk of DIGEST_SIZE*8 bits is accumulated by the bitmap, it is added to this tree.
    /// Because leaf elements can be updated when bits in the bitmap are flipped, this tree, while
    /// based on an MMR structure, is not an MMR but a Merkle tree.  The MMR structure results in
    /// reduced update overhead for elements being appended or updated near the tip compared to a
    /// more typical balanced Merkle tree.
    mmr: Mmr<H>,
}

impl<H: CHasher> Default for Bitmap<H> {
    fn default() -> Self {
        Self::new()
    }
}

impl<H: CHasher> Bitmap<H> {
    const CHUNK_SIZE: usize = H::Digest::SIZE;

    /// Return a new empty bitmap.
    pub fn new() -> Self {
        Bitmap {
            bitmap: vec![0u8; Self::CHUNK_SIZE],
            next_bit: 0,
            mmr: Mmr::new(),
        }
    }

    /// Return the number of bitmap bytes that have been pruned.
    fn pruned_bytes(&self) -> usize {
        self.mmr.oldest_retained_pos as usize * Self::CHUNK_SIZE
    }

    /// Return the number of bits currently stored in the bitmap, irrespective of any pruning.
    pub fn bit_count(&self) -> u64 {
        ((self.pruned_bytes() + self.bitmap.len()) * 8 - Self::CHUNK_SIZE * 8 + self.next_bit)
            as u64
    }

    /// Prune the bitmap to the most recent chunk boundary that contains the referenced bit. Panics
    /// if the referenced bit has been pruned or is greater than the number of bits in the bitmap.
    pub fn prune_to_bit(&mut self, bit_offset: u64) {
        let chunk_pos = bit_offset as usize / 8 / Self::CHUNK_SIZE;
        let mut byte_offset = chunk_pos * Self::CHUNK_SIZE;
        let pruned_bytes = self.pruned_bytes();
        assert!(byte_offset >= pruned_bytes, "bit pruned");
        byte_offset -= pruned_bytes;
        self.mmr.prune_to_pos(chunk_pos as u64);
        self.bitmap.drain(0..byte_offset);
    }

    /// Return the last chunk of the bitmap as a digest.
    fn last_chunk(&self) -> H::Digest {
        let len = self.bitmap.len();
        H::Digest::try_from(&self.bitmap[len - Self::CHUNK_SIZE..len]).unwrap()
    }

    /// Return the last chunk of the bitmap as a mutable slice.
    fn last_chunk_mut(&mut self) -> &mut [u8] {
        let len = self.bitmap.len();
        &mut self.bitmap[len - Self::CHUNK_SIZE..len]
    }

    /// Returns the bitmap chunk containing the specified bit as a digest. Panics if the bit doesn't
    /// exist or has been pruned.
    fn get_chunk(&self, bit_offset: u64) -> H::Digest {
        let mut byte_offset = bit_offset as usize / 8 / Self::CHUNK_SIZE * Self::CHUNK_SIZE;
        let pruned_bytes = self.pruned_bytes();
        assert!(byte_offset >= pruned_bytes, "bit pruned");
        byte_offset -= pruned_bytes;
        H::Digest::try_from(&self.bitmap[byte_offset..byte_offset + Self::CHUNK_SIZE]).unwrap()
    }

    /// Commit the last chunk of the bitmap to the Merkle tree and initialize the next chunk.
    fn commit_last_chunk(&mut self, hasher: &mut H) {
        let chunk = self.last_chunk();
        self.mmr.add(hasher, &chunk);
        self.next_bit = 0;
        self.bitmap.extend(vec![0u8; Self::CHUNK_SIZE]);
    }

    /// Efficiently add a digest-sized chunk of bits to the bitmap. Assumes we are at a chunk
    /// boundary (that is, `self.next_bit` is 0) and panics otherwise.
    pub fn append_chunk_unchecked(&mut self, hasher: &mut H, chunk: &H::Digest) {
        assert!(
            self.next_bit == 0,
            "cannot add chunk when not chunk aligned"
        );

        self.last_chunk_mut().copy_from_slice(chunk.as_ref());
        self.commit_last_chunk(hasher);
    }

    /// Efficiently add a byte's worth of bits to the bitmap. Assumes self.next_bit is currently
    /// byte aligned, and panics otherwise.
    pub fn append_byte_unchecked(&mut self, hasher: &mut H, byte: u8) {
        assert!(
            self.next_bit % 8 == 0,
            "cannot add byte when not byte aligned"
        );

        let chunk_byte = self.next_bit / 8;
        self.last_chunk_mut()[chunk_byte] = byte;
        self.next_bit += 8;
        assert!(self.next_bit <= Self::CHUNK_SIZE * 8);

        if self.next_bit == Self::CHUNK_SIZE * 8 {
            self.commit_last_chunk(hasher);
        }
    }

    /// Add a single bit to the bitmap.
    pub fn append(&mut self, hasher: &mut H, bit: bool) {
        if bit {
            let chunk_byte = self.next_bit / 8;
            self.last_chunk_mut()[chunk_byte] |= Self::chunk_byte_bit_mask(self.next_bit as u64);
        }
        self.next_bit += 1;
        assert!(self.next_bit <= Self::CHUNK_SIZE * 8);

        if self.next_bit == Self::CHUNK_SIZE * 8 {
            self.commit_last_chunk(hasher);
        }
    }

    /// Convert a bit offset into a bit mask for the byte containing that bit.
    #[inline]
    pub(crate) fn chunk_byte_bit_mask(bit_offset: u64) -> u8 {
        1 << (bit_offset % 8)
    }

    /// Convert a bit offset into the offset of the byte within a chunk containing the bit.
    #[allow(dead_code)] // Remove when we start using this outside the test module.
    #[inline]
    pub(crate) fn chunk_byte_offset(bit_offset: u64) -> usize {
        (bit_offset as usize / 8) % Self::CHUNK_SIZE
    }

    /// Convert a bit offset into the position of the Merkle tree leaf it belongs to.
    #[inline]
    pub(crate) fn leaf_pos(bit_offset: u64) -> u64 {
        let leaf_num = bit_offset / 8 / Self::CHUNK_SIZE as u64;
        leaf_num_to_pos(leaf_num)
    }

    /// Get the value of a bit. Panics if the bit doesn't exist or has been pruned.
    pub fn get_bit(&self, bit_offset: u64) -> bool {
        assert!(bit_offset < self.bit_count(), "out of bounds");
        let chunk_pos = bit_offset / 8 / Self::CHUNK_SIZE as u64;
        if chunk_pos < self.mmr.oldest_retained_pos {
            panic!("bit pruned");
        }
        let byte_offset = bit_offset as usize / 8 - self.pruned_bytes();
        self.bitmap[byte_offset] & Self::chunk_byte_bit_mask(bit_offset) != 0
    }

    /// Set the value of the referenced bit. Panics if the bit doesn't exist or has been pruned.
    pub fn set_bit(&mut self, hasher: &mut H, bit_offset: u64, bit: bool) {
        assert!(bit_offset < self.bit_count(), "out of bounds");
        let chunk_pos = bit_offset / 8 / Self::CHUNK_SIZE as u64;
        if chunk_pos < self.mmr.oldest_retained_pos {
            panic!("bit pruned");
        }

        let byte_offset = bit_offset as usize / 8 - self.pruned_bytes();
        let mask = Self::chunk_byte_bit_mask(bit_offset);
        if bit {
            self.bitmap[byte_offset] |= mask;
        } else {
            self.bitmap[byte_offset] &= !mask;
        }
        if byte_offset >= self.bitmap.len() - Self::CHUNK_SIZE {
            // No need to update the Merkle tree since this bit is within the last (yet to be
            // inserted) chunk.
            return;
        }

        let chunk = self.get_chunk(bit_offset);
        let leaf_pos = Self::leaf_pos(bit_offset);
        self.mmr.update_leaf(hasher, leaf_pos, &chunk).unwrap();
    }

    /// Return the root hash of the Merkle tree over the bitmap.
    ///
    /// # Warning
    ///
    /// The root hash will not change when adding "0" bits unless a chunk boundary is crossed. If
    /// you require a hash that changes with every bit added, you can hash the value of
    /// `bit_count()` into the result.
    pub fn root(&self, hasher: &mut H) -> H::Digest {
        if self.next_bit == 0 {
            return self.mmr.root(hasher);
        }

        // We must add the partial chunk to the Merkle tree for its bits to be provable. We do so on
        // a temporary lightweight (fully pruned) copy of the tree so that we don't require
        // mutability of the original.
        let mut mmr = self.mmr.clone_pruned();
        let last_chunk = self.last_chunk();
        mmr.add(hasher, &last_chunk);

        mmr.root(hasher)
    }

    /// Return an inclusion proof for the specified bit, along with the chunk of the bitmap
    /// containing that bit. The proof can be used to prove any bit in the chunk.
    pub async fn proof(
        &self,
        hasher: &mut H,
        bit_offset: u64,
    ) -> Result<(Proof<H>, H::Digest), Error> {
        assert!(bit_offset < self.bit_count(), "out of bounds");

        let leaf_pos = Self::leaf_pos(bit_offset);
        let chunk = self.get_chunk(bit_offset);

        if self.next_bit == 0 {
            let proof = Proof::<H>::range_proof(&self.mmr, leaf_pos, leaf_pos).await?;
            return Ok((proof, chunk));
        }

        // We must account for the bits in the last chunk.
        let mut mmr = self.mmr.clone_pruned();
        let last_chunk = self.last_chunk();
        mmr.add(hasher, &last_chunk);

        let storage = BitmapStorage {
            mmr: &self.mmr,
            last_chunk_mmr: &mmr,
        };
        let proof = Proof::<H>::range_proof(&storage, leaf_pos, leaf_pos).await?;

        Ok((proof, chunk))
    }

    pub fn verify_bit_inclusion(
        hasher: &mut H,
        proof: &Proof<H>,
        chunk: &H::Digest,
        bit_offset: u64,
        root_hash: &H::Digest,
    ) -> bool {
        let leaf_pos = Self::leaf_pos(bit_offset);
        proof.verify_element_inclusion(hasher, chunk, leaf_pos, root_hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::{hash, Sha256};
    use commonware_runtime::{deterministic::Executor, Runner};

    #[test]
    fn test_bitmap_empty_then_one() {
        let mut bitmap = Bitmap::<Sha256>::new();
        assert_eq!(bitmap.bit_count(), 0);
        assert_eq!(bitmap.pruned_bytes(), 0);
        bitmap.prune_to_bit(0);
        assert_eq!(bitmap.pruned_bytes(), 0);
        let empty_digest =
            <Sha256 as CHasher>::Digest::try_from(&[0u8; <Sha256 as CHasher>::Digest::SIZE][..])
                .unwrap();
        assert_eq!(bitmap.last_chunk(), empty_digest);

        // Add a single bit
        let mut hasher = Sha256::new();
        let root = bitmap.root(&mut hasher);
        bitmap.append(&mut Sha256::new(), true);
        // Root should change
        assert!(root != bitmap.root(&mut hasher));
        let root = bitmap.root(&mut hasher);
        bitmap.prune_to_bit(1);
        assert_eq!(bitmap.bit_count(), 1);
        assert!(bitmap.last_chunk() != empty_digest);
        // Pruning should be a no-op since we're not beyond a chunk boundary.
        assert_eq!(bitmap.pruned_bytes(), 0);
        assert_eq!(root, bitmap.root(&mut hasher));

        // Fill up a full chunk
        for i in 0..(Bitmap::<Sha256>::CHUNK_SIZE * 8 - 1) {
            bitmap.append(&mut hasher, i % 2 != 0);
        }
        assert_eq!(bitmap.bit_count(), 256);
        assert!(root != bitmap.root(&mut hasher));
        let root = bitmap.root(&mut hasher);
        // Now pruning all bits should matter.
        bitmap.prune_to_bit(256);
        assert_eq!(bitmap.bit_count(), 256);
        assert_eq!(bitmap.pruned_bytes(), 32);
        assert_eq!(root, bitmap.root(&mut hasher));
        // Last digest should be empty again
        assert_eq!(bitmap.last_chunk(), empty_digest);
    }

    #[test]
    fn test_bitmap_building() {
        // Build the same bitmap with 2 digests in multiple ways and make sure they are equivalent
        // based on their root hashes.
        let test_digest = hash(b"test");

        let mut hasher = Sha256::new();

        // Add each bit one at a time after the first chunk.
        let mut bitmap = Bitmap::<Sha256>::new();
        bitmap.append_chunk_unchecked(&mut hasher, &test_digest);
        let vec: Vec<u8> = test_digest.as_ref().to_vec();
        for b in vec {
            for j in 0..8 {
                let mask = 1 << j;
                let bit = (b & mask) != 0;
                bitmap.append(&mut hasher, bit);
            }
        }

        assert_eq!(bitmap.bit_count(), 256 * 2);

        let root = bitmap.root(&mut hasher);
        let inner_root = bitmap.mmr.root(&mut hasher);
        assert_eq!(root, inner_root);

        {
            // Repeat the above MMR build only using append_chunk_unchecked instead, and make sure root
            // hashes match.
            let mut bitmap = Bitmap::<Sha256>::default();
            bitmap.append_chunk_unchecked(&mut hasher, &test_digest);
            bitmap.append_chunk_unchecked(&mut hasher, &test_digest);
            let same_root = bitmap.root(&mut hasher);
            assert_eq!(root, same_root);
        }
        {
            // Repeat build again using append_byte_unchecked this time.
            let mut bitmap = Bitmap::<Sha256>::default();
            bitmap.append_chunk_unchecked(&mut hasher, &test_digest);
            for i in 0..32 {
                bitmap.append_byte_unchecked(&mut hasher, test_digest[i]);
            }
            let same_root = bitmap.root(&mut hasher);
            assert_eq!(root, same_root);
        }
    }

    #[test]
    #[should_panic(expected = "cannot add chunk")]
    fn test_bitmap_build_chunked_panic() {
        let mut hasher = Sha256::new();
        let mut bitmap = Bitmap::<Sha256>::new();
        bitmap.append_chunk_unchecked(&mut hasher, &hash(b"test"));
        bitmap.append(&mut hasher, true);
        bitmap.append_chunk_unchecked(&mut hasher, &hash(b"should panic"));
    }

    #[test]
    #[should_panic(expected = "cannot add byte")]
    fn test_bitmap_build_byte_panic() {
        let mut hasher = Sha256::new();
        let mut bitmap = Bitmap::<Sha256>::new();
        bitmap.append_chunk_unchecked(&mut hasher, &hash(b"test"));
        bitmap.append(&mut hasher, true);
        bitmap.append_byte_unchecked(&mut hasher, 0x01);
    }

    #[test]
    fn test_bitmap_root_hash_boundaries() {
        // Build a starting test MMR with two chunks worth of bits.
        let mut bitmap = Bitmap::<Sha256>::default();
        let test_digest = hash(b"test");
        let mut hasher = Sha256::new();
        bitmap.append_chunk_unchecked(&mut hasher, &test_digest);
        bitmap.append_chunk_unchecked(&mut hasher, &test_digest);

        let root = bitmap.root(&mut hasher);

        // Confirm that root hash changes if we add a 1 bit, even though we won't fill a chunk.
        bitmap.append(&mut hasher, true);
        let new_root = bitmap.root(&mut hasher);
        assert!(root != new_root);
        assert_eq!(bitmap.mmr.size(), 3); // shouldn't include the trailing bits

        // Add 0 bits to fill up entire chunk.
        for _ in 0..(Bitmap::<Sha256>::CHUNK_SIZE * 8 - 1) {
            bitmap.append(&mut hasher, false);
            let newer_root = bitmap.root(&mut hasher);
            // root hash won't change when adding 0s within the same chunk
            assert_eq!(new_root, newer_root);
        }
        assert_eq!(bitmap.mmr.size(), 4); // chunk we filled should have been added to mmr

        // Confirm the root hash changes when we add the next 0 bit since it's part of a new chunk.
        bitmap.append(&mut hasher, false);
        assert_eq!(bitmap.bit_count(), 256 * 3 + 1);
        let newer_root = bitmap.root(&mut hasher);
        assert!(new_root != newer_root);

        // Confirm pruning everything doesn't affect the root hash.
        bitmap.prune_to_bit(bitmap.bit_count());
        assert_eq!(bitmap.bit_count(), 256 * 3 + 1);
        let pruned_root = bitmap.root(&mut hasher);
        assert_eq!(pruned_root, newer_root);
    }

    #[test]
    fn test_bitmap_get_set_bits() {
        // Build a test MMR with two chunks worth of bits.
        let mut bitmap = Bitmap::<Sha256>::default();
        let test_digest = hash(b"test");
        let mut hasher = Sha256::new();
        bitmap.append_chunk_unchecked(&mut hasher, &test_digest);
        bitmap.append_chunk_unchecked(&mut hasher, &test_digest);
        // Add a few extra bits to exercise not being on a chunk or byte boundary.
        bitmap.append_byte_unchecked(&mut hasher, 0xF1);
        bitmap.append(&mut hasher, true);
        bitmap.append(&mut hasher, false);
        bitmap.append(&mut hasher, true);

        let root = bitmap.root(&mut hasher);

        // Flip each bit and confirm the root hash changes, then flip it back to confirm it is
        // safely restored.
        for bit_pos in (0..bitmap.bit_count()).rev() {
            let bit = bitmap.get_bit(bit_pos);
            bitmap.set_bit(&mut hasher, bit_pos, !bit);
            let new_root = bitmap.root(&mut hasher);
            assert!(root != new_root, "failed at bit {}", bit_pos);
            bitmap.set_bit(&mut hasher, bit_pos, bit);
            // flip it back
            let new_root = bitmap.root(&mut hasher);
            assert_eq!(root, new_root);
        }
    }

    #[test]
    fn test_bitmap_mmr_proof_verification() {
        let (executor, _, _) = Executor::default();
        executor.start(async move {
            // Build a bitmap with 10 chunks worth of bits.
            let mut hasher = Sha256::new();
            let mut bitmap = Bitmap::new();
            for i in 0u32..10 {
                let digest = hash(&[b"bytes", i.to_be_bytes().as_ref()].concat());
                bitmap.append_chunk_unchecked(&mut hasher, &digest);
            }
            // Add a few extra bits to exercise not being on a chunk or byte boundary.
            bitmap.append_byte_unchecked(&mut hasher, 0xA6);
            bitmap.append(&mut hasher, true);
            bitmap.append(&mut hasher, false);
            bitmap.append(&mut hasher, true);
            bitmap.append(&mut hasher, true);
            bitmap.append(&mut hasher, false);

            let root = bitmap.root(&mut hasher);

            // Make sure every bit is provable, even after pruning in intervals of 251 bits (251 is
            // the largest prime that is less than the size of one chunk in bits).
            for prune_to_bit in (0..bitmap.bit_count()).step_by(251) {
                assert_eq!(bitmap.root(&mut hasher), root);
                bitmap.prune_to_bit(prune_to_bit);
                for i in prune_to_bit..bitmap.bit_count() {
                    let (proof, chunk) = bitmap.proof(&mut hasher, i).await.unwrap();

                    // Proof should verify for the original chunk containing the bit.
                    assert!(
                        Bitmap::verify_bit_inclusion(&mut hasher, &proof, &chunk, i, &root),
                        "failed to prove bit {}",
                        i
                    );

                    // Flip the bit in the chunk and make sure the proof fails.
                    let mask: u8 = Bitmap::<Sha256>::chunk_byte_bit_mask(i);
                    let byte_offset = Bitmap::<Sha256>::chunk_byte_offset(i);
                    let corrupted = {
                        let mut tmp = chunk.as_ref().to_vec();
                        tmp[byte_offset] ^= mask;
                        <Sha256 as CHasher>::Digest::try_from(&tmp).unwrap()
                    };
                    assert!(
                        !Bitmap::verify_bit_inclusion(&mut hasher, &proof, &corrupted, i, &root),
                        "proving bit {} after flipping should have failed",
                        i
                    );

                    let (proof, chunk) = bitmap.proof(&mut hasher, i).await.unwrap();

                    // Proof should verify for the original chunk containing the bit.
                    assert!(
                        Bitmap::verify_bit_inclusion(&mut hasher, &proof, &chunk, i, &root),
                        "failed to prove bit {}",
                        i
                    );

                    // Flip the bit in the chunk and make sure the proof fails.
                    let mask: u8 = Bitmap::<Sha256>::chunk_byte_bit_mask(i);
                    let byte_offset = Bitmap::<Sha256>::chunk_byte_offset(i);
                    let corrupted = {
                        let mut tmp = chunk.as_ref().to_vec();
                        tmp[byte_offset] ^= mask;
                        <Sha256 as CHasher>::Digest::try_from(&tmp).unwrap()
                    };
                    assert!(
                        !Bitmap::verify_bit_inclusion(&mut hasher, &proof, &corrupted, i, &root),
                        "proving bit {} after flipping should have failed",
                        i
                    );
                }
            }
        })
    }
}
