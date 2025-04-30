//! An authenticated bitmap.
//!
//! The authenticated bitmap is is an in-memory data structure that does not persist its contents
//! other than the data corresponding to its "pruned" section, allowing full restoration by
//! "replaying" any unpruned elements.
//!
//! Authentication is provided by a Merkle tree that is maintained over the bitmap, with each leaf
//! covering a chunk of N bytes. This Merkle tree isn't balanced, but instead mimics the structure
//! of an MMR with an equivalent number of leaves. This structure reduces overhead of updating the
//! most recently added elements, and (more importantly) simplifies aligning the bitmap with an MMR
//! over elements whose activity state is reflected by the bitmap.

use crate::{
    metadata::{Config as MConfig, Metadata},
    mmr::{iterator::leaf_num_to_pos, mem::Mmr, verification::Proof, verification::Storage, Error},
};
use commonware_codec::DecodeExt;
use commonware_cryptography::Hasher as CHasher;
use commonware_runtime::{Clock, Metrics, Storage as RStorage};
use commonware_utils::array::prefixed_u64::U64;
use std::collections::VecDeque;
use tracing::{error, warn};

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
/// Merkelization of the bitmap is performed over chunks of N bytes. If the goal is to minimize
/// proof sizes, choose an N that is equal to the size or double the size of the hasher's digest.
///
/// Warning: Even though we use u64 identifiers for bits, on 32-bit machines, the maximum
/// addressable bit is limited to (u32::MAX * N * 8).
pub struct Bitmap<H: CHasher, const N: usize> {
    /// The bitmap itself, in chunks of size N bytes. The number of valid bits in the last chunk is
    /// given by `self.next_bit`. Within each byte, lowest order bits are treated as coming before
    /// higher order bits in the bit ordering.
    ///
    /// Invariant: The last chunk in the bitmap always has room for at least one more bit.
    bitmap: VecDeque<[u8; N]>,

    /// The position within the last chunk of the bitmap where the next bit is to be appended.
    ///
    /// Invariant: This value is always in the range [0, N * 8).
    next_bit: u64,

    /// A Merkle tree with each leaf representing N*8 bits of the bitmap.
    ///
    /// When a chunk of N*8 bits is accumulated by the bitmap, it is added to this tree. Because
    /// leaf elements can be updated when bits in the bitmap are flipped, this tree, while based on
    /// an MMR structure, is not an MMR but a Merkle tree. The MMR structure results in reduced
    /// update overhead for elements being appended or updated near the tip compared to a more
    /// typical balanced Merkle tree.
    mmr: Mmr<H>,

    /// The number of bitmap chunks that have been pruned.
    pruned_chunks: usize,
}

impl<H: CHasher, const N: usize> Default for Bitmap<H, N> {
    fn default() -> Self {
        Self::new()
    }
}

/// Prefix used for the metadata key identifying node digests.
const NODE_PREFIX: u8 = 0;

/// Prefix used for the metadata key identifying the pruned_chunks value.
const PRUNED_CHUNKS_PREFIX: u8 = 1;

impl<H: CHasher, const N: usize> Bitmap<H, N> {
    /// The size of a chunk in bytes.
    pub const CHUNK_SIZE: usize = N;

    /// The size of a chunk in bits.
    const CHUNK_SIZE_BITS: u64 = N as u64 * 8;

    /// Return a new empty bitmap.
    pub fn new() -> Self {
        let bitmap = VecDeque::from([[0u8; N]]);

        Bitmap {
            bitmap,
            next_bit: 0,
            mmr: Mmr::new(),
            pruned_chunks: 0,
        }
    }

    /// Restore the fully pruned state of a bitmap from the metadata in the given partition. (The
    /// caller must still replay retained elements to restore its full state.)
    ///
    /// The metadata must store the number of pruned chunks and the pinned hashes corresponding to
    /// that pruning boundary.
    pub async fn restore_pruned<C: RStorage + Metrics + Clock>(
        context: C,
        partition: String,
    ) -> Result<Self, Error> {
        let metadata_cfg = MConfig { partition };
        let metadata = Metadata::init(context.with_label("metadata"), metadata_cfg).await?;

        let key: U64 = U64::new(PRUNED_CHUNKS_PREFIX, 0);
        let pruned_chunks = match metadata.get(&key) {
            Some(bytes) => u64::from_be_bytes(
                bytes
                    .as_slice()
                    .try_into()
                    .expect("pruned_chunks bytes could not be converted to u64"),
            ),
            None => {
                warn!("bitmap metadata does not contain pruned chunks, initializing as empty");
                0
            }
        } as usize;
        if pruned_chunks == 0 {
            return Ok(Self::new());
        }
        let mmr_size = leaf_num_to_pos(pruned_chunks as u64);

        let mut pinned_nodes = Vec::new();
        for (index, pos) in Proof::<H>::nodes_to_pin(mmr_size).enumerate() {
            let Some(bytes) = metadata.get(&U64::new(NODE_PREFIX, index as u64)) else {
                error!(size = mmr_size, pos, "missing pinned node");
                return Err(Error::MissingNode(pos));
            };
            let digest = H::Digest::decode(bytes.as_ref());
            let Ok(digest) = digest else {
                error!(
                    size = mmr_size,
                    pos, "could not convert node bytes to digest"
                );
                return Err(Error::MissingNode(pos));
            };
            pinned_nodes.push(digest);
        }

        metadata.close().await?;

        let mmr = Mmr::<H>::init(Vec::new(), mmr_size, pinned_nodes);

        Ok(Self {
            bitmap: VecDeque::from([[0u8; N]]),
            next_bit: 0,
            mmr,
            pruned_chunks,
        })
    }

    /// Write the information necessary to restore the bitmap in its fully pruned state at its last
    /// pruning boundary. Restoring the entire bitmap state is then possible by replaying the
    /// retained elements.
    pub async fn write_pruned<C: RStorage + Metrics + Clock>(
        &self,
        context: C,
        partition: String,
    ) -> Result<(), Error> {
        let metadata_cfg = MConfig { partition };
        let mut metadata = Metadata::init(context.with_label("metadata"), metadata_cfg).await?;
        metadata.clear();

        // Write the number of pruned chunks.
        let key = U64::new(PRUNED_CHUNKS_PREFIX, 0);
        metadata.put(key, self.pruned_chunks.to_be_bytes().to_vec());

        // Write the pinned nodes.
        let mmr_size = leaf_num_to_pos(self.pruned_chunks as u64);
        for (i, digest) in Proof::<H>::nodes_to_pin(mmr_size).enumerate() {
            let digest = self.mmr.get_node_unchecked(digest);
            let key = U64::new(NODE_PREFIX, i as u64);
            metadata.put(key, digest.to_vec());
        }

        metadata.close().await.map_err(Error::MetadataError)
    }

    /// Return the number of bits currently stored in the bitmap, irrespective of any pruning.
    #[inline]
    pub fn bit_count(&self) -> u64 {
        (self.pruned_chunks + self.bitmap.len()) as u64 * Self::CHUNK_SIZE_BITS
            - Self::CHUNK_SIZE_BITS
            + self.next_bit
    }

    /// Prune the bitmap to the most recent chunk boundary that contains the referenced bit. Panics
    /// if the referenced bit is greater than the number of bits in the bitmap.
    pub fn prune_to_bit(&mut self, bit_offset: u64) {
        let chunk_pos = Self::chunk_pos(bit_offset);
        if chunk_pos < self.pruned_chunks {
            return;
        }

        let chunk_index = chunk_pos - self.pruned_chunks;
        self.bitmap.drain(0..chunk_index);
        self.pruned_chunks = chunk_pos;

        let mmr_pos = leaf_num_to_pos(chunk_pos as u64);
        self.mmr.prune_to_pos(mmr_pos);
    }

    /// Return the last chunk of the bitmap.
    #[inline]
    fn last_chunk(&self) -> &[u8; N] {
        &self.bitmap[self.bitmap.len() - 1]
    }

    /// Return the last chunk of the bitmap as a mutable slice.
    #[inline]
    fn last_chunk_mut(&mut self) -> &mut [u8] {
        let len = self.bitmap.len();
        &mut self.bitmap[len - 1]
    }

    /// Returns the bitmap chunk containing the specified bit. Panics if the bit doesn't exist or
    /// has been pruned.
    #[inline]
    fn get_chunk(&self, bit_offset: u64) -> &[u8; N] {
        &self.bitmap[self.chunk_index(bit_offset)]
    }

    /// Commit the last chunk of the bitmap to the Merkle tree and initialize the next chunk.
    fn commit_last_chunk(&mut self, hasher: &mut H) {
        self.mmr.add(hasher, &self.bitmap[self.bitmap.len() - 1]);
        self.next_bit = 0;
        self.bitmap.push_back([0u8; N]);
    }

    /// Efficiently add a chunk of bits to the bitmap. Assumes we are at a chunk boundary (that is,
    /// `self.next_bit` is 0) and panics otherwise.
    pub fn append_chunk_unchecked(&mut self, hasher: &mut H, chunk: &[u8; N]) {
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

        let chunk_byte = (self.next_bit / 8) as usize;
        self.last_chunk_mut()[chunk_byte] = byte;
        self.next_bit += 8;
        assert!(self.next_bit <= Self::CHUNK_SIZE_BITS);

        if self.next_bit == Self::CHUNK_SIZE_BITS {
            self.commit_last_chunk(hasher);
        }
    }

    /// Add a single bit to the bitmap.
    pub fn append(&mut self, hasher: &mut H, bit: bool) {
        if bit {
            let chunk_byte = (self.next_bit / 8) as usize;
            self.last_chunk_mut()[chunk_byte] |= Self::chunk_byte_bitmask(self.next_bit);
        }
        self.next_bit += 1;
        assert!(self.next_bit <= Self::CHUNK_SIZE_BITS);

        if self.next_bit == Self::CHUNK_SIZE_BITS {
            self.commit_last_chunk(hasher);
        }
    }

    /// Convert a bit offset into a bitmask for the byte containing that bit.
    #[inline]
    pub(crate) fn chunk_byte_bitmask(bit_offset: u64) -> u8 {
        1 << (bit_offset % 8)
    }

    /// Convert a bit offset into the offset of the byte within a chunk containing the bit.
    #[inline]
    pub(crate) fn chunk_byte_offset(bit_offset: u64) -> usize {
        (bit_offset / 8) as usize % Self::CHUNK_SIZE
    }

    /// Convert a bit offset into the position of the Merkle tree leaf it belongs to.
    #[inline]
    pub(crate) fn leaf_pos(bit_offset: u64) -> u64 {
        leaf_num_to_pos(Self::chunk_pos(bit_offset) as u64)
    }

    #[inline]
    /// Convert a bit offset into the index of the chunk it belongs to within self.bitmap. Panics if
    /// the bit doesn't exist or has been pruned.
    fn chunk_index(&self, bit_offset: u64) -> usize {
        assert!(
            bit_offset < self.bit_count(),
            "out of bounds: {}",
            bit_offset
        );
        let chunk_pos = Self::chunk_pos(bit_offset);
        assert!(
            chunk_pos >= self.pruned_chunks,
            "bit pruned: {}",
            bit_offset
        );

        chunk_pos - self.pruned_chunks
    }

    // Convert a bit offset into the position of the chunk it belongs to.
    #[inline]
    fn chunk_pos(bit_offset: u64) -> usize {
        (bit_offset / Self::CHUNK_SIZE_BITS) as usize
    }

    /// Get the value of a bit. Panics if the bit doesn't exist or has been pruned.
    #[inline]
    pub fn get_bit(&self, bit_offset: u64) -> bool {
        let byte_offset = Self::chunk_byte_offset(bit_offset);
        let byte = self.get_chunk(bit_offset)[byte_offset];
        let mask = Self::chunk_byte_bitmask(bit_offset);

        (byte & mask) != 0
    }

    /// Set the value of the referenced bit. Panics if the bit doesn't exist or has been pruned.
    pub fn set_bit(&mut self, hasher: &mut H, bit_offset: u64, bit: bool) {
        let chunk_index = self.chunk_index(bit_offset);
        let is_last = chunk_index == self.bitmap.len() - 1;
        let chunk = &mut self.bitmap[chunk_index];

        let byte_offset = Self::chunk_byte_offset(bit_offset);
        let mask = Self::chunk_byte_bitmask(bit_offset);

        if bit {
            chunk[byte_offset] |= mask;
        } else {
            chunk[byte_offset] &= !mask;
        }
        if is_last {
            // No need to update the Merkle tree since this bit is within the last (yet to be
            // committed) chunk.
            return;
        }

        let leaf_pos = Self::leaf_pos(bit_offset);
        self.mmr.update_leaf(hasher, leaf_pos, chunk).unwrap();
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
        mmr.add(hasher, self.last_chunk());

        mmr.root(hasher)
    }

    /// Return an inclusion proof for the specified bit, along with the chunk of the bitmap
    /// containing that bit. The proof can be used to prove any bit in the chunk.
    pub async fn proof(
        &self,
        hasher: &mut H,
        bit_offset: u64,
    ) -> Result<(Proof<H>, [u8; N]), Error> {
        assert!(bit_offset < self.bit_count(), "out of bounds");

        let leaf_pos = Self::leaf_pos(bit_offset);
        let chunk = self.get_chunk(bit_offset);

        if self.next_bit == 0 {
            let proof = Proof::<H>::range_proof(&self.mmr, leaf_pos, leaf_pos).await?;
            return Ok((proof, *chunk));
        }

        // We must account for the bits in the last chunk.
        let mut mmr = self.mmr.clone_pruned();
        mmr.add(hasher, self.last_chunk());

        let storage = BitmapStorage {
            mmr: &self.mmr,
            last_chunk_mmr: &mmr,
        };
        let proof = Proof::<H>::range_proof(&storage, leaf_pos, leaf_pos).await?;

        Ok((proof, *chunk))
    }

    /// Verify whether `proof` proves that the `chunk` containing the referenced bit belongs to the
    /// bitmap corresponding to `root_hash`.
    pub fn verify_bit_inclusion(
        hasher: &mut H,
        proof: &Proof<H>,
        chunk: &[u8; N],
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
    use commonware_macros::test_traced;
    use commonware_runtime::{deterministic, Runner as _};

    fn test_chunk<const N: usize>(s: &[u8]) -> [u8; N] {
        assert_eq!(N % 32, 0);
        let mut vec: Vec<u8> = Vec::new();
        for _ in 0..N / 32 {
            vec.extend(hash(s).iter());
        }

        vec.try_into().unwrap()
    }

    #[test]
    fn test_bitmap_empty_then_one() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut bitmap = Bitmap::<Sha256, 32>::new();
            assert_eq!(bitmap.bit_count(), 0);
            assert_eq!(bitmap.pruned_chunks, 0);
            bitmap.prune_to_bit(0);
            assert_eq!(bitmap.pruned_chunks, 0);
            assert_eq!(bitmap.last_chunk(), &[0u8; 32]);

            // Add a single bit
            let mut hasher = Sha256::new();
            let root = bitmap.root(&mut hasher);
            bitmap.append(&mut Sha256::new(), true);
            // Root should change
            assert!(root != bitmap.root(&mut hasher));
            let root = bitmap.root(&mut hasher);
            bitmap.prune_to_bit(1);
            assert_eq!(bitmap.bit_count(), 1);
            assert!(bitmap.last_chunk() != &[0u8; 32]);
            // Pruning should be a no-op since we're not beyond a chunk boundary.
            assert_eq!(bitmap.pruned_chunks, 0);
            assert_eq!(root, bitmap.root(&mut hasher));

            // Fill up a full chunk
            for i in 0..(Bitmap::<Sha256, 32>::CHUNK_SIZE * 8 - 1) {
                bitmap.append(&mut hasher, i % 2 != 0);
            }
            assert_eq!(bitmap.bit_count(), 256);
            assert!(root != bitmap.root(&mut hasher));
            let root = bitmap.root(&mut hasher);

            // Chunk should be provable.
            let (proof, chunk) = bitmap.proof(&mut hasher, 0).await.unwrap();
            assert!(
                Bitmap::verify_bit_inclusion(&mut hasher, &proof, &chunk, 255, &root),
                "failed to prove bit in only chunk"
            );

            // Now pruning all bits should matter.
            bitmap.prune_to_bit(256);
            assert_eq!(bitmap.bit_count(), 256);
            assert_eq!(bitmap.pruned_chunks, 1);
            assert_eq!(root, bitmap.root(&mut hasher));
            // Last chunk should be empty again
            assert_eq!(bitmap.last_chunk(), &[0u8; 32]);

            // Pruning to an earlier point should be a no-op.
            bitmap.prune_to_bit(10);
            assert_eq!(root, bitmap.root(&mut hasher));
        });
    }

    #[test]
    fn test_bitmap_building() {
        // Build the same bitmap with 2 chunks worth of bits in multiple ways and make sure they are
        // equivalent based on their root hashes.
        let test_chunk = test_chunk(b"test");

        let mut hasher = Sha256::new();

        // Add each bit one at a time after the first chunk.
        let mut bitmap = Bitmap::<Sha256, 32>::new();
        bitmap.append_chunk_unchecked(&mut hasher, &test_chunk);
        for b in test_chunk {
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
            let mut bitmap = Bitmap::<Sha256, 32>::default();
            bitmap.append_chunk_unchecked(&mut hasher, &test_chunk);
            bitmap.append_chunk_unchecked(&mut hasher, &test_chunk);
            let same_root = bitmap.root(&mut hasher);
            assert_eq!(root, same_root);
        }
        {
            // Repeat build again using append_byte_unchecked this time.
            let mut bitmap = Bitmap::<Sha256, 32>::default();
            bitmap.append_chunk_unchecked(&mut hasher, &test_chunk);
            for b in test_chunk {
                bitmap.append_byte_unchecked(&mut hasher, b);
            }
            let same_root = bitmap.root(&mut hasher);
            assert_eq!(root, same_root);
        }
    }

    #[test]
    #[should_panic(expected = "cannot add chunk")]
    fn test_bitmap_build_chunked_panic() {
        let mut hasher = Sha256::new();
        let mut bitmap = Bitmap::<Sha256, 32>::new();
        bitmap.append_chunk_unchecked(&mut hasher, &test_chunk(b"test"));
        bitmap.append(&mut hasher, true);
        bitmap.append_chunk_unchecked(&mut hasher, &test_chunk(b"panic"));
    }

    #[test]
    #[should_panic(expected = "cannot add byte")]
    fn test_bitmap_build_byte_panic() {
        let mut hasher = Sha256::new();
        let mut bitmap = Bitmap::<Sha256, 32>::new();
        bitmap.append_chunk_unchecked(&mut hasher, &test_chunk(b"test"));
        bitmap.append(&mut hasher, true);
        bitmap.append_byte_unchecked(&mut hasher, 0x01);
    }

    #[test]
    #[should_panic(expected = "out of bounds")]
    fn test_bitmap_get_out_of_bounds_bit_panic() {
        let mut bitmap = Bitmap::<Sha256, 32>::new();
        bitmap.append_chunk_unchecked(&mut Sha256::new(), &test_chunk(b"test"));
        bitmap.get_bit(256);
    }
    #[test]
    #[should_panic(expected = "pruned")]
    fn test_bitmap_get_pruned_bit_panic() {
        let mut bitmap = Bitmap::<Sha256, 32>::new();
        bitmap.append_chunk_unchecked(&mut Sha256::new(), &test_chunk(b"test"));
        bitmap.append_chunk_unchecked(&mut Sha256::new(), &test_chunk(b"test2"));
        bitmap.prune_to_bit(256);
        bitmap.get_bit(255);
    }

    #[test]
    fn test_bitmap_root_hash_boundaries() {
        // Build a starting test MMR with two chunks worth of bits.
        let mut bitmap = Bitmap::<Sha256, 32>::default();
        let mut hasher = Sha256::new();
        bitmap.append_chunk_unchecked(&mut hasher, &test_chunk(b"test"));
        bitmap.append_chunk_unchecked(&mut hasher, &test_chunk(b"test2"));

        let root = bitmap.root(&mut hasher);

        // Confirm that root hash changes if we add a 1 bit, even though we won't fill a chunk.
        bitmap.append(&mut hasher, true);
        let new_root = bitmap.root(&mut hasher);
        assert!(root != new_root);
        assert_eq!(bitmap.mmr.size(), 3); // shouldn't include the trailing bits

        // Add 0 bits to fill up entire chunk.
        for _ in 0..(Bitmap::<Sha256, 32>::CHUNK_SIZE * 8 - 1) {
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
        assert_eq!(bitmap.pruned_chunks, 3);
        assert_eq!(bitmap.bit_count(), 256 * 3 + 1);
        assert_eq!(newer_root, bitmap.root(&mut hasher));
    }

    #[test]
    fn test_bitmap_get_set_bits() {
        // Build a test MMR with two chunks worth of bits.
        let mut bitmap = Bitmap::<Sha256, 32>::default();
        let mut hasher = Sha256::new();
        bitmap.append_chunk_unchecked(&mut hasher, &test_chunk(b"test"));
        bitmap.append_chunk_unchecked(&mut hasher, &test_chunk(b"test2"));
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

    fn flip_bit<const N: usize>(bit_offset: u64, chunk: &[u8; N]) -> [u8; N] {
        let byte_offset = Bitmap::<Sha256, 32>::chunk_byte_offset(bit_offset);
        let mask = Bitmap::<Sha256, 32>::chunk_byte_bitmask(bit_offset);
        let mut tmp = chunk.to_vec();
        tmp[byte_offset] ^= mask;
        tmp.try_into().unwrap()
    }

    #[test]
    fn test_bitmap_mmr_proof_verification() {
        test_bitmap_mmr_proof_verification_n::<32>();
        test_bitmap_mmr_proof_verification_n::<64>();
    }

    fn test_bitmap_mmr_proof_verification_n<const N: usize>() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            // Build a bitmap with 10 chunks worth of bits.
            let mut hasher = Sha256::new();
            let mut bitmap = Bitmap::<_, N>::new();
            for i in 0u32..10 {
                bitmap.append_chunk_unchecked(
                    &mut hasher,
                    &test_chunk(format!("test{}", i).as_bytes()),
                );
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
            // the largest prime that is less than the size of one 32-byte chunk in bits).
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
                    let corrupted = flip_bit(i, &chunk);
                    assert!(
                        !Bitmap::verify_bit_inclusion(&mut hasher, &proof, &corrupted, i, &root),
                        "proving bit {} after flipping should have failed",
                        i
                    );
                }
            }
        })
    }

    #[test_traced]
    fn test_bitmap_persistence() {
        const PARTITION: &str = "bitmap_test";
        const FULL_CHUNK_COUNT: usize = 100;

        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Initializing from an empty partition should result in an empty bitmap.
            let mut bitmap =
                Bitmap::<Sha256, 32>::restore_pruned(context.clone(), PARTITION.to_string())
                    .await
                    .unwrap();
            assert_eq!(bitmap.bit_count(), 0);

            // Add a non-trivial amount of data.
            let mut hasher = Sha256::new();
            for i in 0..FULL_CHUNK_COUNT {
                bitmap.append_chunk_unchecked(
                    &mut hasher,
                    &test_chunk(format!("test{}", i).as_bytes()),
                );
            }
            let chunk_aligned_root = bitmap.root(&mut hasher);

            // Add a few extra bits beyond the last chunk boundary.
            bitmap.append_byte_unchecked(&mut hasher, 0xA6);
            bitmap.append(&mut hasher, true);
            bitmap.append(&mut hasher, false);
            bitmap.append(&mut hasher, true);
            let root = bitmap.root(&mut hasher);

            // prune 10 chunks at a time and make sure replay will restore the bitmap every time.
            for i in (10..=FULL_CHUNK_COUNT).step_by(10) {
                bitmap.prune_to_bit(i as u64 * Bitmap::<Sha256, 32>::CHUNK_SIZE_BITS);
                bitmap
                    .write_pruned(context.clone(), PARTITION.to_string())
                    .await
                    .unwrap();
                bitmap =
                    Bitmap::<Sha256, 32>::restore_pruned(context.clone(), PARTITION.to_string())
                        .await
                        .unwrap();
                let _ = bitmap.root(&mut hasher);

                // Replay missing chunks.
                for j in i..FULL_CHUNK_COUNT {
                    bitmap.append_chunk_unchecked(
                        &mut hasher,
                        &test_chunk(format!("test{}", j).as_bytes()),
                    );
                    let _ = bitmap.root(&mut hasher);
                }
                assert_eq!(bitmap.pruned_chunks, i);
                assert_eq!(bitmap.bit_count(), FULL_CHUNK_COUNT as u64 * 256);
                assert_eq!(bitmap.root(&mut hasher), chunk_aligned_root);

                // Replay missing partial chunk.
                bitmap.append_byte_unchecked(&mut hasher, 0xA6);
                bitmap.append(&mut hasher, true);
                bitmap.append(&mut hasher, false);
                bitmap.append(&mut hasher, true);
                assert_eq!(bitmap.root(&mut hasher), root);
            }
        });
    }
}
