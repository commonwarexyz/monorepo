//! An authenticated bitmap.
//!
//! The authenticated bitmap is an in-memory data structure that does not persist its contents other
//! than the data corresponding to its "pruned" section, allowing full restoration by "replaying"
//! all retained elements.
//!
//! Authentication is provided by a Merkle tree that is maintained over the bitmap, with each leaf
//! covering a chunk of N bytes. This Merkle tree isn't balanced, but instead mimics the structure
//! of an MMR with an equivalent number of leaves. This structure reduces overhead of updating the
//! most recently added elements, and (more importantly) simplifies aligning the bitmap with an MMR
//! over elements whose activity state is reflected by the bitmap.

use crate::{
    metadata::{Config as MConfig, Metadata},
    mmr::{
        iterator::leaf_num_to_pos,
        mem::{Config as MemConfig, Mmr},
        verification::Proof,
        Error,
        Error::*,
        Hasher,
    },
};
use commonware_codec::DecodeExt;
use commonware_cryptography::Hasher as CHasher;
use commonware_runtime::{Clock, Metrics, Storage as RStorage, ThreadPool};
use commonware_utils::array::prefixed_u64::U64;
use std::collections::{HashSet, VecDeque};
use tracing::{debug, error, warn};

/// A bitmap supporting inclusion proofs through Merkelization.
///
/// Merkelization of the bitmap is performed over chunks of N bytes. If the goal is to minimize
/// proof sizes, choose an N that is equal to the size or double the size of the hasher's digest.
///
/// # Warning
///
/// Even though we use u64 identifiers for bits, on 32-bit machines, the maximum addressable bit is
/// limited to (u32::MAX * N * 8).
pub struct Bitmap<H: CHasher, const N: usize> {
    /// The bitmap itself, in chunks of size N bytes. The number of valid bits in the last chunk is
    /// given by `self.next_bit`. Within each byte, lowest order bits are treated as coming before
    /// higher order bits in the bit ordering.
    ///
    /// Invariant: The last chunk in the bitmap always has room for at least one more bit. This
    /// implies there is always at least one chunk in the bitmap, it's just empty if no bits have
    /// been added yet.
    bitmap: VecDeque<[u8; N]>,

    /// The length of the bitmap range that is currently included in the `mmr`.
    authenticated_len: usize,

    /// The position within the last chunk of the bitmap where the next bit is to be appended.
    ///
    /// Invariant: This value is always in the range [0, N * 8).
    next_bit: u64,

    /// A Merkle tree with each leaf representing an N*8 bit "chunk" of the bitmap.
    ///
    /// After calling `sync` all chunks are guaranteed to be included in the Merkle tree. The last
    /// chunk of the bitmap is never part of the tree.
    ///
    /// Because leaf elements can be updated when bits in the bitmap are flipped, this tree, while
    /// based on an MMR structure, is not an MMR but a Merkle tree. The MMR structure results in
    /// reduced update overhead for elements being appended or updated near the tip compared to a
    /// more typical balanced Merkle tree.
    mmr: Mmr<H>,

    /// The number of bitmap chunks that have been pruned.
    pruned_chunks: usize,

    /// Chunks that have been modified but not yet synced. Each dirty chunk is identified by its
    /// "chunk index" (the index of the chunk in `self.bitmap`).
    ///
    /// Invariant: Indices are always in the range [0,`authenticated_len`).
    dirty_chunks: HashSet<usize>,
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
    pub const CHUNK_SIZE_BITS: u64 = N as u64 * 8;

    /// Return a new empty bitmap.
    pub fn new() -> Self {
        let bitmap = VecDeque::from([[0u8; N]]);

        Bitmap {
            bitmap,
            authenticated_len: 0,
            next_bit: 0,
            mmr: Mmr::new(),
            pruned_chunks: 0,
            dirty_chunks: HashSet::new(),
        }
    }

    pub fn size(&self) -> u64 {
        self.mmr.size()
    }

    pub fn get_node(&self, position: u64) -> Option<H::Digest> {
        self.mmr.get_node(position)
    }

    /// Restore the fully pruned state of a bitmap from the metadata in the given partition. (The
    /// caller must still replay retained elements to restore its full state.)
    ///
    /// The metadata must store the number of pruned chunks and the pinned digests corresponding to
    /// that pruning boundary.
    pub async fn restore_pruned<C: RStorage + Metrics + Clock>(
        context: C,
        partition: &str,
        pool: Option<ThreadPool>,
    ) -> Result<Self, Error> {
        let metadata_cfg = MConfig {
            partition: partition.to_string(),
        };
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
        for (index, pos) in Proof::<H::Digest>::nodes_to_pin(mmr_size).enumerate() {
            let Some(bytes) = metadata.get(&U64::new(NODE_PREFIX, index as u64)) else {
                error!(size = mmr_size, pos, "missing pinned node");
                return Err(MissingNode(pos));
            };
            let digest = H::Digest::decode(bytes.as_ref());
            let Ok(digest) = digest else {
                error!(
                    size = mmr_size,
                    pos, "could not convert node bytes to digest"
                );
                return Err(MissingNode(pos));
            };
            pinned_nodes.push(digest);
        }

        metadata.close().await?;

        let mmr = Mmr::init(MemConfig {
            nodes: Vec::new(),
            pruned_to_pos: mmr_size,
            pinned_nodes,
            pool,
        });

        Ok(Self {
            bitmap: VecDeque::from([[0u8; N]]),
            authenticated_len: 0,
            next_bit: 0,
            mmr,
            pruned_chunks,
            dirty_chunks: HashSet::new(),
        })
    }

    /// Write the information necessary to restore the bitmap in its fully pruned state at its last
    /// pruning boundary. Restoring the entire bitmap state is then possible by replaying the
    /// retained elements.
    pub async fn write_pruned<C: RStorage + Metrics + Clock>(
        &self,
        context: C,
        partition: &str,
    ) -> Result<(), Error> {
        let metadata_cfg = MConfig {
            partition: partition.to_string(),
        };
        let mut metadata = Metadata::init(context.with_label("metadata"), metadata_cfg).await?;
        metadata.clear();

        // Write the number of pruned chunks.
        let key = U64::new(PRUNED_CHUNKS_PREFIX, 0);
        metadata.put(key, self.pruned_chunks.to_be_bytes().to_vec());

        // Write the pinned nodes.
        let mmr_size = leaf_num_to_pos(self.pruned_chunks as u64);
        for (i, digest) in Proof::<H::Digest>::nodes_to_pin(mmr_size).enumerate() {
            let digest = self.mmr.get_node_unchecked(digest);
            let key = U64::new(NODE_PREFIX, i as u64);
            metadata.put(key, digest.to_vec());
        }

        metadata.close().await.map_err(MetadataError)
    }

    /// Return the number of bits currently stored in the bitmap, irrespective of any pruning.
    #[inline]
    pub fn bit_count(&self) -> u64 {
        (self.pruned_chunks + self.bitmap.len()) as u64 * Self::CHUNK_SIZE_BITS
            - Self::CHUNK_SIZE_BITS
            + self.next_bit
    }

    /// Return the number of bits that have been pruned from this bitmap.
    pub fn pruned_bits(&self) -> u64 {
        self.pruned_chunks as u64 * Self::CHUNK_SIZE_BITS
    }

    /// Prune the bitmap to the most recent chunk boundary that contains the referenced bit.
    ///
    /// # Warning
    ///
    /// - Panics if the referenced bit is greater than the number of bits in the bitmap.
    ///
    /// - Panics if there are unprocessed updates.
    pub fn prune_to_bit(&mut self, bit_offset: u64) {
        let chunk_num = Self::chunk_num(bit_offset);
        if chunk_num < self.pruned_chunks {
            return;
        }
        assert!(!self.is_dirty(), "cannot prune with unprocessed updates");

        let chunk_index = chunk_num - self.pruned_chunks;
        self.bitmap.drain(0..chunk_index);
        self.pruned_chunks = chunk_num;
        self.authenticated_len = self.bitmap.len() - 1;

        let mmr_pos = leaf_num_to_pos(chunk_num as u64);
        self.mmr.prune_to_pos(mmr_pos);
    }

    /// Return the last chunk of the bitmap and its size in bits. The size can be 0 (meaning the
    /// last chunk is empty).
    #[inline]
    pub fn last_chunk(&self) -> (&[u8; N], u64) {
        (self.bitmap.back().unwrap(), self.next_bit)
    }

    /// Return the last chunk of the bitmap as a mutable slice.
    #[inline]
    fn last_chunk_mut(&mut self) -> &mut [u8] {
        self.bitmap.back_mut().unwrap()
    }

    /// Returns the bitmap chunk containing the specified bit.
    ///
    /// # Warning
    ///
    /// Panics if the bit doesn't exist or has been pruned.
    #[inline]
    pub fn get_chunk(&self, bit_offset: u64) -> &[u8; N] {
        &self.bitmap[self.chunk_index(bit_offset)]
    }

    /// Prepares the next chunk of the bitmap to preserve the invariant that there is always room
    /// for one more bit.
    fn prepare_next_chunk(&mut self) {
        self.next_bit = 0;
        self.bitmap.push_back([0u8; N]);
    }

    /// Efficiently add a chunk of bits to the bitmap.
    ///
    /// # Warning
    ///
    /// - The update will not impact the root until `sync` is called.
    ///
    /// - Assumes we are at a chunk boundary (that is, `self.next_bit` is 0) and panics otherwise.
    pub fn append_chunk_unchecked(&mut self, chunk: &[u8; N]) {
        assert!(
            self.next_bit == 0,
            "cannot add chunk when not chunk aligned"
        );

        self.last_chunk_mut().copy_from_slice(chunk.as_ref());
        self.prepare_next_chunk();
    }

    /// Efficiently add a byte's worth of bits to the bitmap.
    ///
    /// # Warning
    ///
    /// - The update will not impact the root until `sync` is called.
    ///
    /// - Assumes self.next_bit is currently byte aligned, and panics otherwise.
    pub fn append_byte_unchecked(&mut self, byte: u8) {
        assert!(
            self.next_bit % 8 == 0,
            "cannot add byte when not byte aligned"
        );

        let chunk_byte = (self.next_bit / 8) as usize;
        self.last_chunk_mut()[chunk_byte] = byte;
        self.next_bit += 8;
        assert!(self.next_bit <= Self::CHUNK_SIZE_BITS);

        if self.next_bit == Self::CHUNK_SIZE_BITS {
            self.prepare_next_chunk();
        }
    }

    /// Add a single bit to the bitmap.
    ///
    /// # Warning
    ///
    /// The update will not affect the root until `sync` is called.
    pub fn append(&mut self, bit: bool) {
        if bit {
            let chunk_byte = (self.next_bit / 8) as usize;
            self.last_chunk_mut()[chunk_byte] |= Self::chunk_byte_bitmask(self.next_bit);
        }
        self.next_bit += 1;
        assert!(self.next_bit <= Self::CHUNK_SIZE_BITS);

        if self.next_bit == Self::CHUNK_SIZE_BITS {
            self.prepare_next_chunk();
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
        leaf_num_to_pos(Self::chunk_num(bit_offset) as u64)
    }

    #[inline]
    /// Convert a bit offset into the index of the chunk it belongs to within self.bitmap.
    ///
    /// # Warning
    ///
    /// Panics if the bit doesn't exist or has been pruned.
    fn chunk_index(&self, bit_offset: u64) -> usize {
        assert!(bit_offset < self.bit_count(), "out of bounds: {bit_offset}");
        let chunk_num = Self::chunk_num(bit_offset);
        assert!(chunk_num >= self.pruned_chunks, "bit pruned: {bit_offset}");

        chunk_num - self.pruned_chunks
    }

    // Convert a bit offset into the number of the chunk it belongs to.
    #[inline]
    fn chunk_num(bit_offset: u64) -> usize {
        (bit_offset / Self::CHUNK_SIZE_BITS) as usize
    }

    /// Get the value of a bit.
    ///
    /// # Warning
    ///
    /// Panics if the bit doesn't exist or has been pruned.
    #[inline]
    pub fn get_bit(&self, bit_offset: u64) -> bool {
        Self::get_bit_from_chunk(self.get_chunk(bit_offset), bit_offset)
    }

    #[inline]
    /// Get the value of a bit from its chunk.
    pub fn get_bit_from_chunk(chunk: &[u8; N], bit_offset: u64) -> bool {
        let byte_offset = Self::chunk_byte_offset(bit_offset);
        let byte = chunk[byte_offset];
        let mask = Self::chunk_byte_bitmask(bit_offset);

        (byte & mask) != 0
    }

    /// Set the value of the referenced bit.
    ///
    /// # Warning
    ///
    /// The update will not impact the root until `sync` is called.
    pub fn set_bit(&mut self, bit_offset: u64, bit: bool) {
        let chunk_index = self.chunk_index(bit_offset);
        let chunk = &mut self.bitmap[chunk_index];

        let byte_offset = Self::chunk_byte_offset(bit_offset);
        let mask = Self::chunk_byte_bitmask(bit_offset);

        if bit {
            chunk[byte_offset] |= mask;
        } else {
            chunk[byte_offset] &= !mask;
        }

        // If the updated chunk is already in the MMR, mark it as dirty.
        if chunk_index < self.authenticated_len {
            self.dirty_chunks.insert(chunk_index);
        }
    }

    /// Whether there are any updates that are not yet reflected in this bitmap's root.
    pub fn is_dirty(&self) -> bool {
        !self.dirty_chunks.is_empty() || self.authenticated_len < self.bitmap.len() - 1
    }

    /// The chunks (identified by their number) that have been modified or added since the last `sync`.
    pub fn dirty_chunks(&self) -> Vec<u64> {
        let mut chunks: Vec<u64> = self
            .dirty_chunks
            .iter()
            .map(|&chunk_index| (chunk_index + self.pruned_chunks) as u64)
            .collect();
        for i in self.authenticated_len..self.bitmap.len() - 1 {
            chunks.push((i + self.pruned_chunks) as u64);
        }

        chunks
    }

    /// Process all updates not yet reflected in the bitmap's root.
    pub async fn sync(&mut self, hasher: &mut impl Hasher<H>) -> Result<(), Error> {
        // Add newly appended chunks to the MMR (other than the very last).
        let start = self.authenticated_len;
        assert!(!self.bitmap.is_empty());
        let end = self.bitmap.len() - 1;
        for i in start..end {
            self.mmr.add_batched(hasher, &self.bitmap[i]);
        }
        self.authenticated_len = end;

        // Inform the MMR of modified chunks.
        let updates = self
            .dirty_chunks
            .iter()
            .map(|chunk_index| {
                let pos = leaf_num_to_pos((*chunk_index + self.pruned_chunks) as u64);
                (pos, &self.bitmap[*chunk_index])
            })
            .collect::<Vec<_>>();
        self.mmr.update_leaf_batched(hasher, &updates);
        self.dirty_chunks.clear();
        self.mmr.sync(hasher);

        Ok(())
    }

    /// Return the root digest against which inclusion proofs can be verified.
    ///
    /// # Format
    ///
    /// The root digest is simply that of the underlying MMR whenever the bit count falls on a chunk
    /// boundary. Otherwise, the root is computed as follows in order to capture the bits that are
    /// not yet part of the MMR:
    ///
    /// hash(mmr_root || next_bit as u64 be_bytes || last_chunk_digest)
    ///
    /// # Warning
    ///
    /// Panics if there are unprocessed updates.
    pub async fn root(&self, hasher: &mut impl Hasher<H>) -> Result<H::Digest, Error> {
        assert!(
            !self.is_dirty(),
            "cannot compute root with unprocessed updates",
        );
        let mmr_root = self.mmr.root(hasher);
        if self.next_bit == 0 {
            return Ok(mmr_root);
        }

        // We must add the partial chunk to the digest for its bits to be provable.
        let last_chunk_digest = hasher.digest(self.last_chunk().0);
        Ok(Self::partial_chunk_root(
            hasher.inner(),
            &mmr_root,
            self.next_bit,
            &last_chunk_digest,
        ))
    }

    /// Returns a root digest that incorporates bits that aren't part of the MMR yet because they
    /// belong to the last (unfilled) chunk.
    pub fn partial_chunk_root(
        hasher: &mut H,
        mmr_root: &H::Digest,
        next_bit: u64,
        last_chunk_digest: &H::Digest,
    ) -> H::Digest {
        assert!(next_bit > 0);
        assert!(next_bit < Self::CHUNK_SIZE_BITS);
        hasher.update(mmr_root);
        hasher.update(&next_bit.to_be_bytes());
        hasher.update(last_chunk_digest);
        hasher.finalize()
    }

    /// Return an inclusion proof for the specified bit, along with the chunk of the bitmap
    /// containing that bit. The proof can be used to prove any bit in the chunk.
    ///
    /// # Warning
    ///
    /// Panics if there are unprocessed updates.
    pub async fn proof(
        &self,
        hasher: &mut impl Hasher<H>,
        bit_offset: u64,
    ) -> Result<(Proof<H::Digest>, [u8; N]), Error> {
        assert!(bit_offset < self.bit_count(), "out of bounds");
        assert!(
            !self.is_dirty(),
            "cannot compute proof with unprocessed updates"
        );

        let leaf_pos = Self::leaf_pos(bit_offset);
        let chunk = self.get_chunk(bit_offset);

        if leaf_pos == self.mmr.size() {
            assert!(self.next_bit > 0);
            // Proof is over a bit in the partial chunk. In this case only a single digest is
            // required in the proof: the mmr's root.
            return Ok((
                Proof {
                    size: self.bit_count(),
                    digests: vec![self.mmr.root(hasher)],
                },
                *chunk,
            ));
        }

        let mut proof = Proof::<H::Digest>::range_proof(&self.mmr, leaf_pos, leaf_pos).await?;
        proof.size = self.bit_count();
        if self.next_bit == 0 {
            // Bitmap is chunk aligned.
            return Ok((proof, *chunk));
        }

        // Since the bitmap wasn't chunk aligned, we'll need to include the digest of the last chunk
        // in the proof to be able to re-derive the root.
        let last_chunk_digest = hasher.digest(self.last_chunk().0);
        proof.digests.push(last_chunk_digest);

        Ok((proof, *chunk))
    }

    /// Verify whether `proof` proves that the `chunk` containing the referenced bit belongs to the
    /// bitmap corresponding to `root_digest`.
    pub fn verify_bit_inclusion(
        hasher: &mut impl Hasher<H>,
        proof: &Proof<H::Digest>,
        chunk: &[u8; N],
        bit_offset: u64,
        root_digest: &H::Digest,
    ) -> bool {
        let bit_count = proof.size;
        if bit_offset >= bit_count {
            debug!(bit_count, bit_offset, "tried to verify non-existent bit");
            return false;
        }
        let leaf_pos = Self::leaf_pos(bit_offset);

        let mut mmr_proof = Proof::<H::Digest> {
            size: leaf_num_to_pos(bit_count / Self::CHUNK_SIZE_BITS),
            digests: proof.digests.clone(),
        };

        if bit_count % Self::CHUNK_SIZE_BITS == 0 {
            return mmr_proof.verify_element_inclusion(hasher, chunk, leaf_pos, root_digest);
        }

        if proof.digests.is_empty() {
            debug!("proof has no digests");
            return false;
        }
        let last_digest = mmr_proof.digests.pop().unwrap();

        if mmr_proof.size == leaf_pos {
            // The proof is over a bit in the partial chunk. In this case the proof's only digest
            // should be the MMR's root, otherwise it is invalid. Since we've popped off the last
            // digest already, there should be no remaining digests.
            if !mmr_proof.digests.is_empty() {
                debug!(
                    digests = mmr_proof.digests.len() + 1,
                    "proof over partial chunk should have exactly 1 digest"
                );
                return false;
            }
            let last_chunk_digest = hasher.digest(chunk);
            let next_bit = bit_count % Self::CHUNK_SIZE_BITS;
            let reconstructed_root = Self::partial_chunk_root(
                hasher.inner(),
                &last_digest,
                next_bit,
                &last_chunk_digest,
            );
            return reconstructed_root == *root_digest;
        };

        // For the case where the proof is over a bit in a full chunk, `last_digest` contains the
        // digest of that chunk.
        let mmr_root = match mmr_proof.reconstruct_root(hasher, &[chunk], leaf_pos, leaf_pos) {
            Ok(root) => root,
            Err(error) => {
                debug!(error = ?error, "invalid proof input");
                return false;
            }
        };

        let next_bit = bit_count % Self::CHUNK_SIZE_BITS;
        let reconstructed_root =
            Self::partial_chunk_root(hasher.inner(), &mmr_root, next_bit, &last_digest);

        reconstructed_root == *root_digest
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mmr::hasher::Standard;
    use commonware_codec::FixedSize;
    use commonware_cryptography::{hash, Sha256};
    use commonware_macros::test_traced;
    use commonware_runtime::{deterministic, Runner as _};

    const SHA256_SIZE: usize = <Sha256 as CHasher>::Digest::SIZE;

    fn test_chunk<const N: usize>(s: &[u8]) -> [u8; N] {
        assert_eq!(N % 32, 0);
        let mut vec: Vec<u8> = Vec::new();
        for _ in 0..N / 32 {
            vec.extend(hash(s).iter());
        }

        vec.try_into().unwrap()
    }

    #[test_traced]
    fn test_bitmap_verify_empty_proof() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut hasher = Standard::new();
            let proof = Proof {
                size: 100,
                digests: Vec::new(),
            };
            assert!(
                !Bitmap::<Sha256, SHA256_SIZE>::verify_bit_inclusion(
                    &mut hasher,
                    &proof,
                    &[0u8; SHA256_SIZE],
                    0,
                    &Sha256::fill(0x00),
                ),
                "proof without digests shouldn't verify or panic"
            );
        });
    }

    #[test_traced]
    fn test_bitmap_empty_then_one() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut bitmap: Bitmap<Sha256, SHA256_SIZE> = Bitmap::new();
            assert_eq!(bitmap.bit_count(), 0);
            assert_eq!(bitmap.pruned_chunks, 0);
            bitmap.prune_to_bit(0);
            assert_eq!(bitmap.pruned_chunks, 0);
            assert_eq!(bitmap.last_chunk().0, &[0u8; SHA256_SIZE]);
            assert_eq!(bitmap.last_chunk().1, 0);

            // Add a single bit
            let mut hasher = Standard::new();
            let root = bitmap.root(&mut hasher).await.unwrap();
            bitmap.append(true);
            bitmap.sync(&mut hasher).await.unwrap();
            // Root should change
            let new_root = bitmap.root(&mut hasher).await.unwrap();
            assert_ne!(root, new_root);
            let root = new_root;
            bitmap.prune_to_bit(1);
            assert_eq!(bitmap.bit_count(), 1);
            assert_ne!(bitmap.last_chunk().0, &[0u8; SHA256_SIZE]);
            assert_eq!(bitmap.last_chunk().1, 1);
            // Pruning should be a no-op since we're not beyond a chunk boundary.
            assert_eq!(bitmap.pruned_chunks, 0);
            assert_eq!(root, bitmap.root(&mut hasher).await.unwrap());

            // Fill up a full chunk
            for i in 0..(Bitmap::<Sha256, SHA256_SIZE>::CHUNK_SIZE_BITS - 1) {
                bitmap.append(i % 2 != 0);
            }
            bitmap.sync(&mut hasher).await.unwrap();
            assert_eq!(bitmap.bit_count(), 256);
            assert_ne!(root, bitmap.root(&mut hasher).await.unwrap());
            let root = bitmap.root(&mut hasher).await.unwrap();

            // Chunk should be provable.
            let (proof, chunk) = bitmap.proof(&mut hasher, 0).await.unwrap();
            assert!(
                Bitmap::verify_bit_inclusion(&mut hasher, &proof, &chunk, 255, &root),
                "failed to prove bit in only chunk"
            );
            // bit outside range should not verify
            assert!(
                !Bitmap::verify_bit_inclusion(&mut hasher, &proof, &chunk, 256, &root),
                "should not be able to prove bit outside of chunk"
            );

            // Now pruning all bits should matter.
            bitmap.prune_to_bit(256);
            assert_eq!(bitmap.bit_count(), 256);
            assert_eq!(bitmap.pruned_chunks, 1);
            assert_eq!(root, bitmap.root(&mut hasher).await.unwrap());
            // Last chunk should be empty again
            assert_eq!(bitmap.last_chunk().0, &[0u8; SHA256_SIZE]);
            assert_eq!(bitmap.last_chunk().1, 0);

            // Pruning to an earlier point should be a no-op.
            bitmap.prune_to_bit(10);
            assert_eq!(root, bitmap.root(&mut hasher).await.unwrap());
        });
    }

    #[test_traced]
    fn test_bitmap_building() {
        // Build the same bitmap with 2 chunks worth of bits in multiple ways and make sure they are
        // equivalent based on their roots.
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let test_chunk = test_chunk(b"test");
            let mut hasher: Standard<Sha256> = Standard::new();

            // Add each bit one at a time after the first chunk.
            let mut bitmap = Bitmap::<_, SHA256_SIZE>::new();
            bitmap.append_chunk_unchecked(&test_chunk);
            for b in test_chunk {
                for j in 0..8 {
                    let mask = 1 << j;
                    let bit = (b & mask) != 0;
                    bitmap.append(bit);
                }
            }
            assert_eq!(bitmap.bit_count(), 256 * 2);

            bitmap.sync(&mut hasher).await.unwrap();
            let root = bitmap.root(&mut hasher).await.unwrap();
            let inner_root = bitmap.mmr.root(&mut hasher);
            assert_eq!(root, inner_root);

            {
                // Repeat the above MMR build only using append_chunk_unchecked instead, and make
                // sure root digests match.
                let mut bitmap = Bitmap::<_, SHA256_SIZE>::default();
                bitmap.append_chunk_unchecked(&test_chunk);
                bitmap.append_chunk_unchecked(&test_chunk);
                bitmap.sync(&mut hasher).await.unwrap();
                let same_root = bitmap.root(&mut hasher).await.unwrap();
                assert_eq!(root, same_root);
            }
            {
                // Repeat build again using append_byte_unchecked this time.
                let mut bitmap = Bitmap::<_, SHA256_SIZE>::default();
                bitmap.append_chunk_unchecked(&test_chunk);
                for b in test_chunk {
                    bitmap.append_byte_unchecked(b);
                }
                bitmap.sync(&mut hasher).await.unwrap();
                let same_root = bitmap.root(&mut hasher).await.unwrap();
                assert_eq!(root, same_root);
            }
        });
    }

    #[test_traced]
    #[should_panic(expected = "cannot add chunk")]
    fn test_bitmap_build_chunked_panic() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut bitmap = Bitmap::<Sha256, SHA256_SIZE>::new();
            bitmap.append_chunk_unchecked(&test_chunk(b"test"));
            bitmap.append(true);
            bitmap.append_chunk_unchecked(&test_chunk(b"panic"));
        });
    }

    #[test_traced]
    #[should_panic(expected = "cannot add byte")]
    fn test_bitmap_build_byte_panic() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut bitmap = Bitmap::<Sha256, SHA256_SIZE>::new();
            bitmap.append_chunk_unchecked(&test_chunk(b"test"));
            bitmap.append(true);
            bitmap.append_byte_unchecked(0x01);
        });
    }

    #[test_traced]
    #[should_panic(expected = "out of bounds")]
    fn test_bitmap_get_out_of_bounds_bit_panic() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut bitmap = Bitmap::<Sha256, SHA256_SIZE>::new();
            bitmap.append_chunk_unchecked(&test_chunk(b"test"));
            bitmap.get_bit(256);
        });
    }

    #[test_traced]
    #[should_panic(expected = "pruned")]
    fn test_bitmap_get_pruned_bit_panic() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut bitmap = Bitmap::<Sha256, SHA256_SIZE>::new();
            bitmap.append_chunk_unchecked(&test_chunk(b"test"));
            bitmap.append_chunk_unchecked(&test_chunk(b"test2"));
            let mut hasher = Standard::new();
            bitmap.sync(&mut hasher).await.unwrap();

            bitmap.prune_to_bit(256);
            bitmap.get_bit(255);
        });
    }

    #[test_traced]
    fn test_bitmap_root_boundaries() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            // Build a starting test MMR with two chunks worth of bits.
            let mut bitmap = Bitmap::<Sha256, SHA256_SIZE>::default();
            let mut hasher = Standard::new();
            bitmap.append_chunk_unchecked(&test_chunk(b"test"));
            bitmap.append_chunk_unchecked(&test_chunk(b"test2"));
            bitmap.sync(&mut hasher).await.unwrap();

            let root = bitmap.root(&mut hasher).await.unwrap();

            // Confirm that root changes if we add a 1 bit, even though we won't fill a chunk.
            bitmap.append(true);
            bitmap.sync(&mut hasher).await.unwrap();
            let new_root = bitmap.root(&mut hasher).await.unwrap();
            assert_ne!(root, new_root);
            assert_eq!(bitmap.mmr.size(), 3); // shouldn't include the trailing bits

            // Add 0 bits to fill up entire chunk.
            for _ in 0..(Bitmap::<Sha256, SHA256_SIZE>::CHUNK_SIZE * 8 - 1) {
                bitmap.append(false);
                bitmap.sync(&mut hasher).await.unwrap();
                let newer_root = bitmap.root(&mut hasher).await.unwrap();
                // root will change when adding 0s within the same chunk
                assert_ne!(new_root, newer_root);
            }
            assert_eq!(bitmap.mmr.size(), 4); // chunk we filled should have been added to mmr

            // Confirm the root changes when we add the next 0 bit since it's part of a new chunk.
            bitmap.append(false);
            assert_eq!(bitmap.bit_count(), 256 * 3 + 1);
            bitmap.sync(&mut hasher).await.unwrap();
            let newer_root = bitmap.root(&mut hasher).await.unwrap();
            assert_ne!(new_root, newer_root);

            // Confirm pruning everything doesn't affect the root.
            bitmap.prune_to_bit(bitmap.bit_count());
            assert_eq!(bitmap.pruned_chunks, 3);
            assert_eq!(bitmap.bit_count(), 256 * 3 + 1);
            assert_eq!(newer_root, bitmap.root(&mut hasher).await.unwrap());
        });
    }

    #[test_traced]
    fn test_bitmap_get_set_bits() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            // Build a test MMR with a few chunks worth of bits.
            let mut bitmap = Bitmap::<Sha256, SHA256_SIZE>::default();
            let mut hasher = Standard::new();
            bitmap.append_chunk_unchecked(&test_chunk(b"test"));
            bitmap.append_chunk_unchecked(&test_chunk(b"test2"));
            bitmap.append_chunk_unchecked(&test_chunk(b"test3"));
            bitmap.append_chunk_unchecked(&test_chunk(b"test4"));
            // Add a few extra bits to exercise not being on a chunk or byte boundary.
            bitmap.append_byte_unchecked(0xF1);
            bitmap.append(true);
            bitmap.append(false);
            bitmap.append(true);

            bitmap.sync(&mut hasher).await.unwrap();
            let root = bitmap.root(&mut hasher).await.unwrap();

            // Flip each bit and confirm the root changes, then flip it back to confirm it is safely
            // restored.
            for bit_pos in (0..bitmap.bit_count()).rev() {
                let bit = bitmap.get_bit(bit_pos);
                bitmap.set_bit(bit_pos, !bit);
                bitmap.sync(&mut hasher).await.unwrap();
                let new_root = bitmap.root(&mut hasher).await.unwrap();
                assert_ne!(root, new_root, "failed at bit {bit_pos}");
                // flip it back
                bitmap.set_bit(bit_pos, bit);
                bitmap.sync(&mut hasher).await.unwrap();
                let new_root = bitmap.root(&mut hasher).await.unwrap();
                assert_eq!(root, new_root);
            }

            // Repeat the test after pruning.
            let start_bit = SHA256_SIZE as u64 * 8 * 2;
            bitmap.prune_to_bit(start_bit);
            for bit_pos in (start_bit..bitmap.bit_count()).rev() {
                let bit = bitmap.get_bit(bit_pos);
                bitmap.set_bit(bit_pos, !bit);
                bitmap.sync(&mut hasher).await.unwrap();
                let new_root = bitmap.root(&mut hasher).await.unwrap();
                assert_ne!(root, new_root, "failed at bit {bit_pos}");
                // flip it back
                bitmap.set_bit(bit_pos, bit);
                bitmap.sync(&mut hasher).await.unwrap();
                let new_root = bitmap.root(&mut hasher).await.unwrap();
                assert_eq!(root, new_root);
            }
        });
    }

    fn flip_bit<const N: usize>(bit_offset: u64, chunk: &[u8; N]) -> [u8; N] {
        let byte_offset = Bitmap::<Sha256, SHA256_SIZE>::chunk_byte_offset(bit_offset);
        let mask = Bitmap::<Sha256, SHA256_SIZE>::chunk_byte_bitmask(bit_offset);
        let mut tmp = chunk.to_vec();
        tmp[byte_offset] ^= mask;
        tmp.try_into().unwrap()
    }

    #[test_traced]
    fn test_bitmap_mmr_proof_verification() {
        test_bitmap_mmr_proof_verification_n::<32>();
        test_bitmap_mmr_proof_verification_n::<64>();
    }

    fn test_bitmap_mmr_proof_verification_n<const N: usize>() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            // Build a bitmap with 10 chunks worth of bits.
            let mut hasher = Standard::new();
            let mut bitmap = Bitmap::<Sha256, N>::new();
            for i in 0u32..10 {
                bitmap.append_chunk_unchecked(&test_chunk(format!("test{i}").as_bytes()));
            }
            // Add a few extra bits to exercise not being on a chunk or byte boundary.
            bitmap.append_byte_unchecked(0xA6);
            bitmap.append(true);
            bitmap.append(false);
            bitmap.append(true);
            bitmap.append(true);
            bitmap.append(false);

            bitmap.sync(&mut hasher).await.unwrap();
            let root = bitmap.root(&mut hasher).await.unwrap();

            // Make sure every bit is provable, even after pruning in intervals of 251 bits (251 is
            // the largest prime that is less than the size of one 32-byte chunk in bits).
            for prune_to_bit in (0..bitmap.bit_count()).step_by(251) {
                assert_eq!(bitmap.root(&mut hasher).await.unwrap(), root);
                bitmap.prune_to_bit(prune_to_bit);
                for i in prune_to_bit..bitmap.bit_count() {
                    let (proof, chunk) = bitmap.proof(&mut hasher, i).await.unwrap();

                    // Proof should verify for the original chunk containing the bit.
                    assert!(
                        Bitmap::<_, N>::verify_bit_inclusion(&mut hasher, &proof, &chunk, i, &root),
                        "failed to prove bit {i}",
                    );

                    // Flip the bit in the chunk and make sure the proof fails.
                    let corrupted = flip_bit(i, &chunk);
                    assert!(
                        !Bitmap::<_, N>::verify_bit_inclusion(
                            &mut hasher,
                            &proof,
                            &corrupted,
                            i,
                            &root
                        ),
                        "proving bit {i} after flipping should have failed",
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
                Bitmap::<Sha256, SHA256_SIZE>::restore_pruned(context.clone(), PARTITION, None)
                    .await
                    .unwrap();
            assert_eq!(bitmap.bit_count(), 0);

            // Add a non-trivial amount of data.
            let mut hasher = Standard::new();
            for i in 0..FULL_CHUNK_COUNT {
                bitmap.append_chunk_unchecked(&test_chunk(format!("test{i}").as_bytes()));
            }
            bitmap.sync(&mut hasher).await.unwrap();
            let chunk_aligned_root = bitmap.root(&mut hasher).await.unwrap();

            // Add a few extra bits beyond the last chunk boundary.
            bitmap.append_byte_unchecked(0xA6);
            bitmap.append(true);
            bitmap.append(false);
            bitmap.append(true);
            bitmap.sync(&mut hasher).await.unwrap();
            let root = bitmap.root(&mut hasher).await.unwrap();

            // prune 10 chunks at a time and make sure replay will restore the bitmap every time.
            for i in (10..=FULL_CHUNK_COUNT).step_by(10) {
                bitmap.prune_to_bit(i as u64 * Bitmap::<Sha256, SHA256_SIZE>::CHUNK_SIZE_BITS);
                bitmap
                    .write_pruned(context.clone(), PARTITION)
                    .await
                    .unwrap();
                bitmap = Bitmap::<_, SHA256_SIZE>::restore_pruned(context.clone(), PARTITION, None)
                    .await
                    .unwrap();
                let _ = bitmap.root(&mut hasher).await.unwrap();

                // Replay missing chunks.
                for j in i..FULL_CHUNK_COUNT {
                    bitmap.append_chunk_unchecked(&test_chunk(format!("test{j}").as_bytes()));
                }
                assert_eq!(bitmap.pruned_chunks, i);
                assert_eq!(bitmap.bit_count(), FULL_CHUNK_COUNT as u64 * 256);
                bitmap.sync(&mut hasher).await.unwrap();
                assert_eq!(bitmap.root(&mut hasher).await.unwrap(), chunk_aligned_root);

                // Replay missing partial chunk.
                bitmap.append_byte_unchecked(0xA6);
                bitmap.append(true);
                bitmap.append(false);
                bitmap.append(true);
                assert_eq!(bitmap.root(&mut hasher).await.unwrap(), root);
            }
        });
    }
}
