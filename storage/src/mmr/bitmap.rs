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
        hasher::Hasher,
        iterator::nodes_to_pin,
        mem::{Config, Mmr},
        storage::Storage,
        verification, Error,
        Error::*,
        Location, Position, Proof,
    },
};
use commonware_codec::DecodeExt;
use commonware_cryptography::Digest;
use commonware_runtime::{Clock, Metrics, Storage as RStorage, ThreadPool};
use commonware_utils::{bitmap::Prunable as PrunableBitMap, sequence::prefixed_u64::U64};
use std::collections::HashSet;
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
pub struct BitMap<D: Digest, const N: usize> {
    /// The underlying bitmap.
    bitmap: PrunableBitMap<N>,

    /// The number of bitmap chunks currently included in the `mmr`.
    authenticated_len: usize,

    /// A Merkle tree with each leaf representing an N*8 bit "chunk" of the bitmap.
    ///
    /// After calling `merkleize` all chunks are guaranteed to be included in the Merkle tree. The
    /// last chunk of the bitmap is never part of the tree.
    ///
    /// Because leaf elements can be updated when bits in the bitmap are flipped, this tree, while
    /// based on an MMR structure, is not an MMR but a Merkle tree. The MMR structure results in
    /// reduced update overhead for elements being appended or updated near the tip compared to a
    /// more typical balanced Merkle tree.
    mmr: Mmr<D>,

    /// Chunks that have been modified but not yet merkleized. Each dirty chunk is identified by its
    /// "chunk index" (the index of the chunk in `self.bitmap`).
    ///
    /// Invariant: Indices are always in the range [0,`authenticated_len`).
    dirty_chunks: HashSet<usize>,
}

impl<D: Digest, const N: usize> Default for BitMap<D, N> {
    fn default() -> Self {
        Self::new()
    }
}

/// Prefix used for the metadata key identifying node digests.
const NODE_PREFIX: u8 = 0;

/// Prefix used for the metadata key identifying the pruned_chunks value.
const PRUNED_CHUNKS_PREFIX: u8 = 1;

impl<D: Digest, const N: usize> BitMap<D, N> {
    /// The size of a chunk in bits.
    pub const CHUNK_SIZE_BITS: u64 = PrunableBitMap::<N>::CHUNK_SIZE_BITS;

    /// Return a new empty bitmap.
    pub fn new() -> Self {
        BitMap {
            bitmap: PrunableBitMap::new(),
            authenticated_len: 0,
            mmr: Mmr::new(),
            dirty_chunks: HashSet::new(),
        }
    }

    pub fn size(&self) -> Position {
        self.mmr.size()
    }

    pub fn get_node(&self, position: Position) -> Option<D> {
        self.mmr.get_node(position)
    }

    /// Restore the fully pruned state of a bitmap from the metadata in the given partition. (The
    /// caller must still replay retained elements to restore its full state.)
    ///
    /// The metadata must store the number of pruned chunks and the pinned digests corresponding to
    /// that pruning boundary.
    ///
    /// Returns an error if the bitmap could not be restored, e.g. because of data corruption or
    /// underlying storage error.
    pub async fn restore_pruned<C: RStorage + Metrics + Clock>(
        context: C,
        partition: &str,
        pool: Option<ThreadPool>,
    ) -> Result<Self, Error> {
        let metadata_cfg = MConfig {
            partition: partition.to_string(),
            codec_config: ((0..).into(), ()),
        };
        let metadata =
            Metadata::<_, U64, Vec<u8>>::init(context.with_label("metadata"), metadata_cfg).await?;

        let key: U64 = U64::new(PRUNED_CHUNKS_PREFIX, 0);
        let pruned_chunks = match metadata.get(&key) {
            Some(bytes) => u64::from_be_bytes(bytes.as_slice().try_into().map_err(|_| {
                error!("pruned chunks value not a valid u64");
                Error::DataCorrupted("pruned chunks value not a valid u64")
            })?),
            None => {
                warn!("bitmap metadata does not contain pruned chunks, initializing as empty");
                0
            }
        } as usize;
        if pruned_chunks == 0 {
            return Ok(Self::new());
        }
        let mmr_size = Position::try_from(Location::new_unchecked(pruned_chunks as u64))?;

        let mut pinned_nodes = Vec::new();
        for (index, pos) in nodes_to_pin(mmr_size).enumerate() {
            let Some(bytes) = metadata.get(&U64::new(NODE_PREFIX, index as u64)) else {
                error!(?mmr_size, ?pos, "missing pinned node");
                return Err(MissingNode(pos));
            };
            let digest = D::decode(bytes.as_ref());
            let Ok(digest) = digest else {
                error!(?mmr_size, ?pos, "could not convert node bytes to digest");
                return Err(MissingNode(pos));
            };
            pinned_nodes.push(digest);
        }

        metadata.close().await?;

        let mmr = Mmr::init(Config {
            nodes: Vec::new(),
            pruned_to_pos: mmr_size,
            pinned_nodes,
            pool,
        })?;

        let bitmap = PrunableBitMap::new_with_pruned_chunks(pruned_chunks)
            .expect("pruned_chunks should never overflow");
        Ok(Self {
            bitmap,
            authenticated_len: 0,
            mmr,
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
            codec_config: ((0..).into(), ()),
        };
        let mut metadata =
            Metadata::<_, U64, Vec<u8>>::init(context.with_label("metadata"), metadata_cfg).await?;
        metadata.clear();

        // Write the number of pruned chunks.
        let key = U64::new(PRUNED_CHUNKS_PREFIX, 0);
        metadata.put(key, self.bitmap.pruned_chunks().to_be_bytes().to_vec());

        // Write the pinned nodes.
        // This will never panic because pruned_chunks is always less than MAX_LOCATION.
        let mmr_size =
            Position::try_from(Location::new_unchecked(self.bitmap.pruned_chunks() as u64))?;
        for (i, digest) in nodes_to_pin(mmr_size).enumerate() {
            let digest = self.mmr.get_node_unchecked(digest);
            let key = U64::new(NODE_PREFIX, i as u64);
            metadata.put(key, digest.to_vec());
        }

        metadata.close().await.map_err(MetadataError)
    }

    /// Return the number of bits currently stored in the bitmap, irrespective of any pruning.
    #[inline]
    pub fn len(&self) -> u64 {
        self.bitmap.len()
    }

    /// Returns true if the bitmap is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Return the number of bits that have been pruned from this bitmap.
    #[inline]
    pub fn pruned_bits(&self) -> u64 {
        self.bitmap.pruned_bits()
    }

    /// Returns the number of complete chunks (excludes partial chunk at end, if any).
    #[inline]
    fn complete_chunks(&self) -> usize {
        let chunks_len = self.bitmap.chunks_len();
        if self.bitmap.is_chunk_aligned() {
            chunks_len
        } else {
            // Last chunk is partial
            chunks_len.checked_sub(1).unwrap()
        }
    }

    /// Prune all complete chunks before the chunk containing the given bit.
    ///
    /// The chunk containing `bit` and all subsequent chunks are retained. All chunks
    /// before it are pruned from the bitmap and the underlying MMR.
    ///
    /// If `bit` equals the bitmap length, this prunes all complete chunks while retaining
    /// the empty trailing chunk, preparing the bitmap for appending new data.
    ///
    /// # Warning
    ///
    /// - Returns [Error::DirtyState] if there are unmerkleized updates.
    pub fn prune_to_bit(&mut self, bit: u64) -> Result<(), Error> {
        if self.is_dirty() {
            return Err(Error::DirtyState);
        }
        let chunk = PrunableBitMap::<N>::unpruned_chunk(bit);
        if chunk < self.bitmap.pruned_chunks() {
            return Ok(());
        }

        // Prune inner bitmap
        self.bitmap.prune_to_bit(bit);

        // Update authenticated length
        self.authenticated_len = self.complete_chunks();

        // This will never panic because chunk is always less than MAX_LOCATION.
        let mmr_pos = Position::try_from(Location::new_unchecked(chunk as u64)).unwrap();
        self.mmr.prune_to_pos(mmr_pos);
        Ok(())
    }

    /// Return the last chunk of the bitmap and its size in bits. The size can be 0 (meaning the
    /// last chunk is empty).
    #[inline]
    pub fn last_chunk(&self) -> (&[u8; N], u64) {
        self.bitmap.last_chunk()
    }

    /// Returns the bitmap chunk containing the specified bit.
    ///
    /// # Warning
    ///
    /// Panics if the bit doesn't exist or has been pruned.
    #[inline]
    pub fn get_chunk_containing(&self, bit: u64) -> &[u8; N] {
        self.bitmap.get_chunk_containing(bit)
    }

    /// Add a single bit to the end of the bitmap.
    ///
    /// # Warning
    ///
    /// The update will not affect the root until `merkleize` is called.
    pub fn push(&mut self, bit: bool) {
        self.bitmap.push(bit);
    }

    /// Get the value of a bit.
    ///
    /// # Warning
    ///
    /// Panics if the bit doesn't exist or has been pruned.
    #[inline]
    pub fn get_bit(&self, bit: u64) -> bool {
        self.bitmap.get_bit(bit)
    }

    #[inline]
    /// Get the value of a bit from its chunk.
    /// `bit` is an index into the entire bitmap, not just the chunk.
    pub fn get_bit_from_chunk(chunk: &[u8; N], bit: u64) -> bool {
        PrunableBitMap::<N>::get_bit_from_chunk(chunk, bit)
    }

    /// Set the value of the given bit.
    ///
    /// # Warning
    ///
    /// The update will not impact the root until `merkleize` is called.
    pub fn set_bit(&mut self, bit: u64, value: bool) {
        // Apply the change to the inner bitmap
        self.bitmap.set_bit(bit, value);

        // If the updated chunk is already in the MMR, mark it as dirty.
        let chunk = self.bitmap.pruned_chunk(bit);
        if chunk < self.authenticated_len {
            self.dirty_chunks.insert(chunk);
        }
    }

    /// Whether there are any updates that are not yet reflected in this bitmap's root.
    pub fn is_dirty(&self) -> bool {
        !self.dirty_chunks.is_empty() || self.authenticated_len < self.complete_chunks()
    }

    /// The chunks that have been modified or added since the last call to `merkleize`.
    pub fn dirty_chunks(&self) -> Vec<Location> {
        let pruned_chunks = self.bitmap.pruned_chunks();
        let mut chunks: Vec<Location> = self
            .dirty_chunks
            .iter()
            .map(|&chunk| Location::new_unchecked((chunk + pruned_chunks) as u64))
            .collect();

        // Include complete chunks that haven't been authenticated yet
        for i in self.authenticated_len..self.complete_chunks() {
            chunks.push(Location::new_unchecked((i + pruned_chunks) as u64));
        }

        chunks
    }

    /// Merkleize all updates not yet reflected in the bitmap's root.
    pub async fn merkleize(&mut self, hasher: &mut impl Hasher<D>) -> Result<(), Error> {
        // Add newly pushed complete chunks to the MMR.
        let start = self.authenticated_len;
        let end = self.complete_chunks();
        let mut mmr = std::mem::take(&mut self.mmr).into_dirty();
        for i in start..end {
            mmr.add_batched(hasher, self.bitmap.get_chunk(i));
        }
        self.authenticated_len = end;

        // Inform the MMR of modified chunks.
        let pruned_chunks = self.bitmap.pruned_chunks();
        let updates = self
            .dirty_chunks
            .iter()
            .map(|chunk| {
                let loc = Location::new_unchecked((*chunk + pruned_chunks) as u64);
                let pos = Position::try_from(loc).expect("invalid location");
                (pos, self.bitmap.get_chunk(*chunk))
            })
            .collect::<Vec<_>>();
        mmr.update_leaf_batched(hasher, &updates)?;
        self.dirty_chunks.clear();
        self.mmr = mmr.merkleize(hasher);

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
    /// Panics if there are unmerkleized updates.
    pub async fn root(&self, hasher: &mut impl Hasher<D>) -> Result<D, Error> {
        assert!(
            !self.is_dirty(),
            "cannot compute root with unmerkleized updates",
        );
        let mmr_root = self.mmr.root(hasher);

        // Check if there's a partial chunk to add
        if self.bitmap.is_chunk_aligned() {
            return Ok(mmr_root);
        }

        let (last_chunk, next_bit) = self.bitmap.last_chunk();

        // We must add the partial chunk to the digest for its bits to be provable.
        let last_chunk_digest = hasher.digest(last_chunk);
        Ok(Self::partial_chunk_root(
            hasher.inner(),
            &mmr_root,
            next_bit,
            &last_chunk_digest,
        ))
    }

    /// Returns a root digest that incorporates bits that aren't part of the MMR yet because they
    /// belong to the last (unfilled) chunk.
    pub fn partial_chunk_root(
        hasher: &mut impl commonware_cryptography::Hasher<Digest = D>,
        mmr_root: &D,
        next_bit: u64,
        last_chunk_digest: &D,
    ) -> D {
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
    /// The bitmap proof stores the number of bits in the bitmap within the `size` field of the
    /// proof instead of MMR size since the underlying MMR's size does not reflect the number of
    /// bits in any partial chunk. The underlying MMR size can be derived from the number of
    /// bits as `leaf_num_to_pos(proof.size / Bitmap<_, N>::CHUNK_SIZE_BITS)`.
    ///
    /// # Errors
    ///
    /// Returns [Error::BitOutOfBounds] if `bit` is out of bounds.
    /// Returns [Error::DirtyState] if there are unmerkleized updates.
    pub async fn proof(
        &self,
        hasher: &mut impl Hasher<D>,
        bit: u64,
    ) -> Result<(Proof<D>, [u8; N]), Error> {
        if bit >= self.len() {
            return Err(Error::BitOutOfBounds(bit, self.len()));
        }
        if self.is_dirty() {
            return Err(Error::DirtyState);
        }

        let chunk = *self.get_chunk_containing(bit);
        let chunk_loc = Location::from(PrunableBitMap::<N>::unpruned_chunk(bit));
        let (last_chunk, next_bit) = self.bitmap.last_chunk();

        if chunk_loc == self.mmr.leaves() {
            assert!(next_bit > 0);
            // Proof is over a bit in the partial chunk. In this case only a single digest is
            // required in the proof: the mmr's root.
            return Ok((
                Proof {
                    size: Position::new(self.len()),
                    digests: vec![self.mmr.root(hasher)],
                },
                chunk,
            ));
        }

        let range = chunk_loc..chunk_loc + 1;
        let mut proof = verification::range_proof(&self.mmr, range).await?;
        proof.size = Position::new(self.len());
        if next_bit == Self::CHUNK_SIZE_BITS {
            // Bitmap is chunk aligned.
            return Ok((proof, chunk));
        }

        // Since the bitmap wasn't chunk aligned, we'll need to include the digest of the last chunk
        // in the proof to be able to re-derive the root.
        let last_chunk_digest = hasher.digest(last_chunk);
        proof.digests.push(last_chunk_digest);

        Ok((proof, chunk))
    }

    /// Verify whether `proof` proves that the `chunk` containing the given bit belongs to the
    /// bitmap corresponding to `root`.
    pub fn verify_bit_inclusion(
        hasher: &mut impl Hasher<D>,
        proof: &Proof<D>,
        chunk: &[u8; N],
        bit: u64,
        root: &D,
    ) -> bool {
        let bit_len = *proof.size;
        if bit >= bit_len {
            debug!(bit_len, bit, "tried to verify non-existent bit");
            return false;
        }

        let leaves = PrunableBitMap::<N>::unpruned_chunk(bit_len);
        // The chunk index should always be < MAX_LOCATION so this should never fail.
        let size = Position::try_from(Location::new_unchecked(leaves as u64))
            .expect("chunk_loc returned invalid location");
        let mut mmr_proof = Proof {
            size,
            digests: proof.digests.clone(),
        };

        let loc = PrunableBitMap::<N>::unpruned_chunk(bit);
        if bit_len.is_multiple_of(Self::CHUNK_SIZE_BITS) {
            return mmr_proof.verify_element_inclusion(
                hasher,
                chunk,
                Location::new_unchecked(loc as u64),
                root,
            );
        }

        if proof.digests.is_empty() {
            debug!("proof has no digests");
            return false;
        }
        let last_digest = mmr_proof.digests.pop().unwrap();

        if leaves == loc {
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
            let next_bit = bit_len % Self::CHUNK_SIZE_BITS;
            let reconstructed_root = Self::partial_chunk_root(
                hasher.inner(),
                &last_digest,
                next_bit,
                &last_chunk_digest,
            );
            return reconstructed_root == *root;
        };

        // For the case where the proof is over a bit in a full chunk, `last_digest` contains the
        // digest of that chunk.
        let mmr_root =
            match mmr_proof.reconstruct_root(hasher, &[chunk], Location::new_unchecked(loc as u64))
            {
                Ok(root) => root,
                Err(error) => {
                    debug!(error = ?error, "invalid proof input");
                    return false;
                }
            };

        let next_bit = bit_len % Self::CHUNK_SIZE_BITS;
        let reconstructed_root =
            Self::partial_chunk_root(hasher.inner(), &mmr_root, next_bit, &last_digest);

        reconstructed_root == *root
    }

    /// Destroy the bitmap metadata from disk.
    pub async fn destroy<C: RStorage + Metrics + Clock>(
        context: C,
        partition: &str,
    ) -> Result<(), Error> {
        let metadata_cfg = MConfig {
            partition: partition.to_string(),
            codec_config: ((0..).into(), ()),
        };
        let metadata =
            Metadata::<_, U64, Vec<u8>>::init(context.with_label("metadata"), metadata_cfg).await?;

        metadata.destroy().await.map_err(MetadataError)
    }
}

impl<D: Digest, const N: usize> Storage<D> for BitMap<D, N> {
    fn size(&self) -> Position {
        self.size()
    }

    async fn get_node(&self, position: Position) -> Result<Option<D>, Error> {
        Ok(self.get_node(position))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mmr::StandardHasher;
    use commonware_codec::FixedSize;
    use commonware_cryptography::{sha256, Hasher, Sha256};
    use commonware_macros::test_traced;
    use commonware_runtime::{deterministic, Runner as _};

    const SHA256_SIZE: usize = sha256::Digest::SIZE;

    impl<D: Digest, const N: usize> BitMap<D, N> {
        // Add a byte's worth of bits to the bitmap.
        //
        // # Warning
        //
        // - The update will not impact the root until `merkleize` is called.
        //
        // - Assumes self.next_bit is currently byte aligned, and panics otherwise.
        fn push_byte(&mut self, byte: u8) {
            self.bitmap.push_byte(byte);
        }

        /// Add a chunk of bits to the bitmap.
        ///
        /// # Warning
        ///
        /// - The update will not impact the root until `merkleize` is called.
        ///
        /// - Panics if self.next_bit is not chunk aligned.
        fn push_chunk(&mut self, chunk: &[u8; N]) {
            self.bitmap.push_chunk(chunk);
        }

        /// Convert a bit into the position of the Merkle tree leaf it belongs to.
        pub(crate) fn leaf_pos(bit: u64) -> Position {
            let chunk = PrunableBitMap::<N>::unpruned_chunk(bit);
            let chunk = Location::new_unchecked(chunk as u64);
            Position::try_from(chunk).expect("chunk should never overflow MAX_LOCATION")
        }
    }

    fn test_chunk<const N: usize>(s: &[u8]) -> [u8; N] {
        assert_eq!(N % 32, 0);
        let mut vec: Vec<u8> = Vec::new();
        for _ in 0..N / 32 {
            vec.extend(Sha256::hash(s).iter());
        }

        vec.try_into().unwrap()
    }

    #[test_traced]
    fn test_bitmap_verify_empty_proof() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut hasher = StandardHasher::<Sha256>::new();
            let proof = Proof {
                size: Position::new(100),
                digests: Vec::new(),
            };
            assert!(
                !BitMap::<_, SHA256_SIZE>::verify_bit_inclusion(
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
            let mut bitmap: BitMap<_, SHA256_SIZE> = BitMap::new();
            assert_eq!(bitmap.len(), 0);
            assert_eq!(bitmap.bitmap.pruned_chunks(), 0);
            bitmap.prune_to_bit(0).unwrap();
            assert_eq!(bitmap.bitmap.pruned_chunks(), 0);

            // Add a single bit
            let mut hasher = StandardHasher::<Sha256>::new();
            let root = bitmap.root(&mut hasher).await.unwrap();
            bitmap.push(true);
            bitmap.merkleize(&mut hasher).await.unwrap();
            // Root should change
            let new_root = bitmap.root(&mut hasher).await.unwrap();
            assert_ne!(root, new_root);
            let root = new_root;
            bitmap.prune_to_bit(1).unwrap();
            assert_eq!(bitmap.len(), 1);
            assert_ne!(bitmap.last_chunk().0, &[0u8; SHA256_SIZE]);
            assert_eq!(bitmap.last_chunk().1, 1);
            // Pruning should be a no-op since we're not beyond a chunk boundary.
            assert_eq!(bitmap.bitmap.pruned_chunks(), 0);
            assert_eq!(root, bitmap.root(&mut hasher).await.unwrap());

            // Fill up a full chunk
            for i in 0..(BitMap::<sha256::Digest, SHA256_SIZE>::CHUNK_SIZE_BITS - 1) {
                bitmap.push(i % 2 != 0);
            }
            bitmap.merkleize(&mut hasher).await.unwrap();
            assert_eq!(bitmap.len(), 256);
            assert_ne!(root, bitmap.root(&mut hasher).await.unwrap());
            let root = bitmap.root(&mut hasher).await.unwrap();

            // Chunk should be provable.
            let (proof, chunk) = bitmap.proof(&mut hasher, 0).await.unwrap();
            assert!(
                BitMap::verify_bit_inclusion(&mut hasher, &proof, &chunk, 255, &root),
                "failed to prove bit in only chunk"
            );
            // bit outside range should not verify
            assert!(
                !BitMap::verify_bit_inclusion(&mut hasher, &proof, &chunk, 256, &root),
                "should not be able to prove bit outside of chunk"
            );

            // Now pruning all bits should matter.
            bitmap.prune_to_bit(256).unwrap();
            assert_eq!(bitmap.len(), 256);
            assert_eq!(bitmap.bitmap.pruned_chunks(), 1);
            assert_eq!(bitmap.bitmap.pruned_bits(), 256);
            assert_eq!(root, bitmap.root(&mut hasher).await.unwrap());

            // Pruning to an earlier point should be a no-op.
            bitmap.prune_to_bit(10).unwrap();
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
            let mut hasher: StandardHasher<Sha256> = StandardHasher::new();

            // Add each bit one at a time after the first chunk.
            let mut bitmap = BitMap::<_, SHA256_SIZE>::new();
            bitmap.push_chunk(&test_chunk);
            for b in test_chunk {
                for j in 0..8 {
                    let mask = 1 << j;
                    let bit = (b & mask) != 0;
                    bitmap.push(bit);
                }
            }
            assert_eq!(bitmap.len(), 256 * 2);

            bitmap.merkleize(&mut hasher).await.unwrap();
            let root = bitmap.root(&mut hasher).await.unwrap();
            let inner_root = bitmap.mmr.root(&mut hasher);
            assert_eq!(root, inner_root);

            {
                // Repeat the above MMR build only using push_chunk instead, and make
                // sure root digests match.
                let mut bitmap = BitMap::<_, SHA256_SIZE>::default();
                bitmap.push_chunk(&test_chunk);
                bitmap.push_chunk(&test_chunk);
                bitmap.merkleize(&mut hasher).await.unwrap();
                let same_root = bitmap.root(&mut hasher).await.unwrap();
                assert_eq!(root, same_root);
            }
            {
                // Repeat build again using push_byte this time.
                let mut bitmap = BitMap::<_, SHA256_SIZE>::default();
                bitmap.push_chunk(&test_chunk);
                for b in test_chunk {
                    bitmap.push_byte(b);
                }
                bitmap.merkleize(&mut hasher).await.unwrap();
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
            let mut bitmap = BitMap::<sha256::Digest, SHA256_SIZE>::new();
            bitmap.push_chunk(&test_chunk(b"test"));
            bitmap.push(true);
            bitmap.push_chunk(&test_chunk(b"panic"));
        });
    }

    #[test_traced]
    #[should_panic(expected = "cannot add byte")]
    fn test_bitmap_build_byte_panic() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut bitmap = BitMap::<sha256::Digest, SHA256_SIZE>::new();
            bitmap.push_chunk(&test_chunk(b"test"));
            bitmap.push(true);
            bitmap.push_byte(0x01);
        });
    }

    #[test_traced]
    #[should_panic(expected = "out of bounds")]
    fn test_bitmap_get_out_of_bounds_bit_panic() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut bitmap = BitMap::<sha256::Digest, SHA256_SIZE>::new();
            bitmap.push_chunk(&test_chunk(b"test"));
            bitmap.get_bit(256);
        });
    }

    #[test_traced]
    #[should_panic(expected = "pruned")]
    fn test_bitmap_get_pruned_bit_panic() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut bitmap = BitMap::<_, SHA256_SIZE>::new();
            bitmap.push_chunk(&test_chunk(b"test"));
            bitmap.push_chunk(&test_chunk(b"test2"));
            let mut hasher = StandardHasher::<Sha256>::new();
            bitmap.merkleize(&mut hasher).await.unwrap();

            bitmap.prune_to_bit(256).unwrap();
            bitmap.get_bit(255);
        });
    }

    #[test_traced]
    fn test_bitmap_root_boundaries() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            // Build a starting test MMR with two chunks worth of bits.
            let mut bitmap = BitMap::<_, SHA256_SIZE>::default();
            let mut hasher = StandardHasher::<Sha256>::new();
            bitmap.push_chunk(&test_chunk(b"test"));
            bitmap.push_chunk(&test_chunk(b"test2"));
            bitmap.merkleize(&mut hasher).await.unwrap();

            let root = bitmap.root(&mut hasher).await.unwrap();

            // Confirm that root changes if we add a 1 bit, even though we won't fill a chunk.
            bitmap.push(true);
            bitmap.merkleize(&mut hasher).await.unwrap();
            let new_root = bitmap.root(&mut hasher).await.unwrap();
            assert_ne!(root, new_root);
            assert_eq!(bitmap.mmr.size(), 3); // shouldn't include the trailing bits

            // Add 0 bits to fill up entire chunk.
            for _ in 0..(SHA256_SIZE * 8 - 1) {
                bitmap.push(false);
                bitmap.merkleize(&mut hasher).await.unwrap();
                let newer_root = bitmap.root(&mut hasher).await.unwrap();
                // root will change when adding 0s within the same chunk
                assert_ne!(new_root, newer_root);
            }
            assert_eq!(bitmap.mmr.size(), 4); // chunk we filled should have been added to mmr

            // Confirm the root changes when we add the next 0 bit since it's part of a new chunk.
            bitmap.push(false);
            assert_eq!(bitmap.len(), 256 * 3 + 1);
            bitmap.merkleize(&mut hasher).await.unwrap();
            let newer_root = bitmap.root(&mut hasher).await.unwrap();
            assert_ne!(new_root, newer_root);

            // Confirm pruning everything doesn't affect the root.
            bitmap.prune_to_bit(bitmap.len()).unwrap();
            assert_eq!(bitmap.bitmap.pruned_chunks(), 3);
            assert_eq!(bitmap.len(), 256 * 3 + 1);
            assert_eq!(newer_root, bitmap.root(&mut hasher).await.unwrap());
        });
    }

    #[test_traced]
    fn test_bitmap_get_set_bits() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            // Build a test MMR with a few chunks worth of bits.
            let mut bitmap = BitMap::<_, SHA256_SIZE>::default();
            let mut hasher = StandardHasher::<Sha256>::new();
            bitmap.push_chunk(&test_chunk(b"test"));
            bitmap.push_chunk(&test_chunk(b"test2"));
            bitmap.push_chunk(&test_chunk(b"test3"));
            bitmap.push_chunk(&test_chunk(b"test4"));
            // Add a few extra bits to exercise not being on a chunk or byte boundary.
            bitmap.push_byte(0xF1);
            bitmap.push(true);
            bitmap.push(false);
            bitmap.push(true);

            bitmap.merkleize(&mut hasher).await.unwrap();
            let root = bitmap.root(&mut hasher).await.unwrap();

            // Flip each bit and confirm the root changes, then flip it back to confirm it is safely
            // restored.
            for bit_pos in (0..bitmap.len()).rev() {
                let bit = bitmap.get_bit(bit_pos);
                bitmap.set_bit(bit_pos, !bit);
                bitmap.merkleize(&mut hasher).await.unwrap();
                let new_root = bitmap.root(&mut hasher).await.unwrap();
                assert_ne!(root, new_root, "failed at bit {bit_pos}");
                // flip it back
                bitmap.set_bit(bit_pos, bit);
                bitmap.merkleize(&mut hasher).await.unwrap();
                let new_root = bitmap.root(&mut hasher).await.unwrap();
                assert_eq!(root, new_root);
            }

            // Repeat the test after pruning.
            let start_bit = (SHA256_SIZE * 8 * 2) as u64;
            bitmap.prune_to_bit(start_bit).unwrap();
            for bit_pos in (start_bit..bitmap.len()).rev() {
                let bit = bitmap.get_bit(bit_pos);
                bitmap.set_bit(bit_pos, !bit);
                bitmap.merkleize(&mut hasher).await.unwrap();
                let new_root = bitmap.root(&mut hasher).await.unwrap();
                assert_ne!(root, new_root, "failed at bit {bit_pos}");
                // flip it back
                bitmap.set_bit(bit_pos, bit);
                bitmap.merkleize(&mut hasher).await.unwrap();
                let new_root = bitmap.root(&mut hasher).await.unwrap();
                assert_eq!(root, new_root);
            }
        });
    }

    fn flip_bit<const N: usize>(bit: u64, chunk: &[u8; N]) -> [u8; N] {
        let byte = PrunableBitMap::<N>::chunk_byte_offset(bit);
        let mask = PrunableBitMap::<N>::chunk_byte_bitmask(bit);
        let mut tmp = chunk.to_vec();
        tmp[byte] ^= mask;
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
            let mut hasher = StandardHasher::<Sha256>::new();
            let mut bitmap = BitMap::<_, N>::new();
            for i in 0u32..10 {
                bitmap.push_chunk(&test_chunk(format!("test{i}").as_bytes()));
            }
            // Add a few extra bits to exercise not being on a chunk or byte boundary.
            bitmap.push_byte(0xA6);
            bitmap.push(true);
            bitmap.push(false);
            bitmap.push(true);
            bitmap.push(true);
            bitmap.push(false);

            bitmap.merkleize(&mut hasher).await.unwrap();
            let root = bitmap.root(&mut hasher).await.unwrap();

            // Make sure every bit is provable, even after pruning in intervals of 251 bits (251 is
            // the largest prime that is less than the size of one 32-byte chunk in bits).
            for prune_to_bit in (0..bitmap.len()).step_by(251) {
                assert_eq!(bitmap.root(&mut hasher).await.unwrap(), root);
                bitmap.prune_to_bit(prune_to_bit).unwrap();
                for i in prune_to_bit..bitmap.len() {
                    let (proof, chunk) = bitmap.proof(&mut hasher, i).await.unwrap();

                    // Proof should verify for the original chunk containing the bit.
                    assert!(
                        BitMap::<_, N>::verify_bit_inclusion(&mut hasher, &proof, &chunk, i, &root),
                        "failed to prove bit {i}",
                    );

                    // Flip the bit in the chunk and make sure the proof fails.
                    let corrupted = flip_bit(i, &chunk);
                    assert!(
                        !BitMap::<_, N>::verify_bit_inclusion(
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
                BitMap::<_, SHA256_SIZE>::restore_pruned(context.clone(), PARTITION, None)
                    .await
                    .unwrap();
            assert_eq!(bitmap.len(), 0);

            // Add a non-trivial amount of data.
            let mut hasher = StandardHasher::<Sha256>::new();
            for i in 0..FULL_CHUNK_COUNT {
                bitmap.push_chunk(&test_chunk(format!("test{i}").as_bytes()));
            }
            bitmap.merkleize(&mut hasher).await.unwrap();
            let chunk_aligned_root = bitmap.root(&mut hasher).await.unwrap();

            // Add a few extra bits beyond the last chunk boundary.
            bitmap.push_byte(0xA6);
            bitmap.push(true);
            bitmap.push(false);
            bitmap.push(true);
            bitmap.merkleize(&mut hasher).await.unwrap();
            let root = bitmap.root(&mut hasher).await.unwrap();

            // prune 10 chunks at a time and make sure replay will restore the bitmap every time.
            for i in (10..=FULL_CHUNK_COUNT).step_by(10) {
                bitmap
                    .prune_to_bit(
                        (i * BitMap::<sha256::Digest, SHA256_SIZE>::CHUNK_SIZE_BITS as usize)
                            as u64,
                    )
                    .unwrap();
                bitmap
                    .write_pruned(context.clone(), PARTITION)
                    .await
                    .unwrap();
                bitmap = BitMap::<_, SHA256_SIZE>::restore_pruned(context.clone(), PARTITION, None)
                    .await
                    .unwrap();
                let _ = bitmap.root(&mut hasher).await.unwrap();

                // Replay missing chunks.
                for j in i..FULL_CHUNK_COUNT {
                    bitmap.push_chunk(&test_chunk(format!("test{j}").as_bytes()));
                }
                assert_eq!(bitmap.bitmap.pruned_chunks(), i);
                assert_eq!(bitmap.len(), FULL_CHUNK_COUNT as u64 * 256);
                bitmap.merkleize(&mut hasher).await.unwrap();
                assert_eq!(bitmap.root(&mut hasher).await.unwrap(), chunk_aligned_root);

                // Replay missing partial chunk.
                bitmap.push_byte(0xA6);
                bitmap.push(true);
                bitmap.push(false);
                bitmap.push(true);
                assert_eq!(bitmap.root(&mut hasher).await.unwrap(), root);
            }
        });
    }

    #[test_traced]
    fn test_bitmap_prune_to_bit_dirty_state() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut bitmap = BitMap::<_, SHA256_SIZE>::new();
            bitmap.push_chunk(&test_chunk(b"test"));
            bitmap.push_chunk(&test_chunk(b"test2"));
            let mut hasher = StandardHasher::<Sha256>::new();
            bitmap.merkleize(&mut hasher).await.unwrap();

            // Make the bitmap dirty by modifying an existing bit
            bitmap.set_bit(0, !bitmap.get_bit(0));

            // Pruning while dirty should return error
            assert!(bitmap.is_dirty(), "Bitmap should be dirty after set_bit");
            let result = bitmap.prune_to_bit(256);
            assert!(matches!(result, Err(crate::mmr::Error::DirtyState)));

            // After syncing, pruning should work
            bitmap.merkleize(&mut hasher).await.unwrap();
            assert!(bitmap.prune_to_bit(256).is_ok());
        });
    }

    #[test_traced]
    fn test_bitmap_proof_out_of_bounds() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut bitmap = BitMap::<_, SHA256_SIZE>::new();
            bitmap.push_chunk(&test_chunk(b"test"));
            let mut hasher = StandardHasher::<Sha256>::new();
            bitmap.merkleize(&mut hasher).await.unwrap();

            // Proof for bit_offset >= bit_count should fail
            let result = bitmap.proof(&mut hasher, 256).await;
            assert!(matches!(result, Err(Error::BitOutOfBounds(offset, size))
                    if offset == 256 && size == 256));

            let result = bitmap.proof(&mut hasher, 1000).await;
            assert!(matches!(result, Err(Error::BitOutOfBounds(offset, size))
                    if offset == 1000 && size == 256));

            // Valid proof should work
            assert!(bitmap.proof(&mut hasher, 0).await.is_ok());
            assert!(bitmap.proof(&mut hasher, 255).await.is_ok());
        });
    }

    #[test_traced]
    fn test_bitmap_proof_dirty_state() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut bitmap = BitMap::<_, SHA256_SIZE>::new();
            bitmap.push_chunk(&test_chunk(b"test"));
            let mut hasher = StandardHasher::<Sha256>::new();
            bitmap.merkleize(&mut hasher).await.unwrap();

            // Make the bitmap dirty by modifying an existing bit
            bitmap.set_bit(0, !bitmap.get_bit(0));

            // Proof while dirty should return error
            assert!(bitmap.is_dirty(), "Bitmap should be dirty after set_bit");
            let result = bitmap.proof(&mut hasher, 0).await;
            assert!(matches!(result, Err(crate::mmr::Error::DirtyState)));

            // After syncing, proof should work
            bitmap.merkleize(&mut hasher).await.unwrap();
            assert!(bitmap.proof(&mut hasher, 0).await.is_ok());
        });
    }
}
