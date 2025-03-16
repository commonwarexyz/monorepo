//! An authenticatable bitmap.

use crate::mmr::{iterator::leaf_num_to_pos, mem::Mmr};
use commonware_cryptography::Hasher as CHasher;
use commonware_utils::SizedSerialize;

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
    const CHUNK_SIZE: usize = H::Digest::SERIALIZED_LEN;

    /// Return a new empty bitmap.
    pub fn new() -> Self {
        Bitmap {
            bitmap: vec![0u8; Self::CHUNK_SIZE],
            next_bit: 0,
            mmr: Mmr::new(),
        }
    }

    /// Return the number of bits currently stored in the bitmap.
    pub fn bit_count(&self) -> u64 {
        (self.bitmap.len() * 8 - Self::CHUNK_SIZE * 8 + self.next_bit) as u64
    }

    /// Return the last chunk of the bitmap as a slice.
    fn last_chunk(&self) -> &[u8] {
        let len = self.bitmap.len();
        &self.bitmap[len - Self::CHUNK_SIZE..len]
    }

    /// Return the last chunk of the bitmap as a mutable slice.
    fn last_chunk_mut(&mut self) -> &mut [u8] {
        let len = self.bitmap.len();
        &mut self.bitmap[len - Self::CHUNK_SIZE..len]
    }

    /// Commit the last chunk of the bitmap to the Merkle tree and initialize the next chunk.
    fn commit_last_chunk(&mut self, hasher: &mut H) {
        let chunk = H::Digest::try_from(self.last_chunk()).unwrap();
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
            self.last_chunk_mut()[chunk_byte] |= Self::mask_for(self.next_bit as u64);
        }
        self.next_bit += 1;
        assert!(self.next_bit <= Self::CHUNK_SIZE * 8);

        if self.next_bit == Self::CHUNK_SIZE * 8 {
            self.commit_last_chunk(hasher);
        }
    }

    /// Convert a bit offset into a bit mask.
    fn mask_for(bit_offset: u64) -> u8 {
        1 << (bit_offset % 8)
    }

    /// Get the value of a bit.
    pub fn get_bit(&self, bit_offset: u64) -> bool {
        assert!(bit_offset < self.bit_count(), "out of bounds");

        let byte_offset = bit_offset as usize / 8;
        self.bitmap[byte_offset] & Self::mask_for(bit_offset) != 0
    }

    /// Set the value of an existing bit.
    pub fn set_bit(&mut self, hasher: &mut H, bit_offset: u64, bit: bool) {
        assert!(bit_offset < self.bit_count(), "out of bounds");

        let byte_offset = bit_offset as usize / 8;
        let mask = Self::mask_for(bit_offset);
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

        let leaf_num = bit_offset as usize / Self::CHUNK_SIZE / 8;
        let start_byte = leaf_num * Self::CHUNK_SIZE;
        let chunk =
            H::Digest::try_from(&self.bitmap[start_byte..start_byte + Self::CHUNK_SIZE]).unwrap();
        self.mmr
            .update_leaf(hasher, leaf_num_to_pos(leaf_num as u64), &chunk)
            .unwrap();
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
        let chunk = H::Digest::try_from(self.last_chunk()).unwrap();
        mmr.add(hasher, &chunk);

        mmr.root(hasher)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::{hash, Sha256};

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
    }

    #[test]
    fn test_bitmap_get_set_bits() {
        // Build a test MMR with two chunks + 1 byte + a couple extra bits worth of bits.
        let mut bitmap = Bitmap::<Sha256>::default();
        let test_digest = hash(b"test");
        let mut hasher = Sha256::new();
        bitmap.append_chunk_unchecked(&mut hasher, &test_digest);
        bitmap.append_chunk_unchecked(&mut hasher, &test_digest);
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
}
