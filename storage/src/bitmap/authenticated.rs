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
        hasher::Hasher as MmrHasher,
        iterator::nodes_to_pin,
        mem::{Clean, CleanMmr, Config, Dirty, Mmr, State},
        storage::Storage,
        verification,
        Error::{self, *},
        Location, Position, Proof,
    },
};
use commonware_codec::DecodeExt;
use commonware_cryptography::{Digest, Hasher};
use commonware_parallel::ThreadPool;
use commonware_runtime::{Clock, Metrics, Storage as RStorage};
use commonware_utils::{
    bitmap::{BitMap as UtilsBitMap, Prunable as PrunableBitMap},
    sequence::prefixed_u64::U64,
};
use std::collections::HashSet;
use tracing::{debug, error, warn};

/// Returns a root digest that incorporates bits not yet part of the MMR because they
/// belong to the last (unfilled) chunk.
pub(crate) fn partial_chunk_root<H: Hasher, const N: usize>(
    hasher: &mut H,
    mmr_root: &H::Digest,
    next_bit: u64,
    last_chunk_digest: &H::Digest,
) -> H::Digest {
    assert!(next_bit > 0);
    assert!(next_bit < UtilsBitMap::<N>::CHUNK_SIZE_BITS);
    hasher.update(mmr_root);
    hasher.update(&next_bit.to_be_bytes());
    hasher.update(last_chunk_digest);
    hasher.finalize()
}

/// A bitmap in the clean state (root has been computed).
pub type CleanBitMap<E, D, const N: usize> = BitMap<E, D, N, Clean<D>>;

/// A bitmap in the dirty state (has pending updates not yet reflected in the root).
pub type DirtyBitMap<E, D, const N: usize> = BitMap<E, D, N, Dirty>;

/// A bitmap supporting inclusion proofs through Merkelization.
///
/// Merkelization of the bitmap is performed over chunks of N bytes. If the goal is to minimize
/// proof sizes, choose an N that is equal to the size or double the size of the hasher's digest.
///
/// # Type States
///
/// The bitmap uses the type-state pattern to enforce at compile-time whether the bitmap has pending
/// updates that must be merkleized before computing proofs. CleanBitMap represents a bitmap
/// whose root digest has been computed and cached. DirtyBitMap represents a bitmap with pending
/// updates. A dirty bitmap can be converted into a clean bitmap by calling [DirtyBitMap::merkleize].
///
/// # Warning
///
/// Even though we use u64 identifiers for bits, on 32-bit machines, the maximum addressable bit is
/// limited to (u32::MAX * N * 8).
pub struct BitMap<E: Clock + RStorage + Metrics, D: Digest, const N: usize, S: State<D> = Clean<D>>
{
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
    mmr: Mmr<D, S>,

    /// Chunks that have been modified but not yet merkleized. Each dirty chunk is identified by its
    /// "chunk index" (the index of the chunk in `self.bitmap`).
    ///
    /// Invariant: Indices are always in the range [0,`authenticated_len`).
    dirty_chunks: HashSet<usize>,

    /// The thread pool to use for parallelization.
    pool: Option<ThreadPool>,

    /// The cached root digest. This is always `Some` for a clean bitmap and computed during
    /// merkleization. For a dirty bitmap, this may be stale or `None`.
    cached_root: Option<D>,

    /// Metadata for persisting pruned state.
    metadata: Metadata<E, U64, Vec<u8>>,
}

/// Prefix used for the metadata key identifying node digests.
const NODE_PREFIX: u8 = 0;

/// Prefix used for the metadata key identifying the pruned_chunks value.
const PRUNED_CHUNKS_PREFIX: u8 = 1;

impl<E: Clock + RStorage + Metrics, D: Digest, const N: usize, S: State<D>> BitMap<E, D, N, S> {
    /// The size of a chunk in bits.
    pub const CHUNK_SIZE_BITS: u64 = PrunableBitMap::<N>::CHUNK_SIZE_BITS;

    /// Return the size of the bitmap in bits.
    #[inline]
    pub fn size(&self) -> Position {
        self.mmr.size()
    }

    /// Return the number of bits currently stored in the bitmap, irrespective of any pruning.
    #[inline]
    pub const fn len(&self) -> u64 {
        self.bitmap.len()
    }

    /// Returns true if the bitmap is empty.
    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Return the number of bits that have been pruned from this bitmap.
    #[inline]
    pub const fn pruned_bits(&self) -> u64 {
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

    /// Get the value of a bit.
    ///
    /// # Warning
    ///
    /// Panics if the bit doesn't exist or has been pruned.
    #[inline]
    pub fn get_bit(&self, bit: u64) -> bool {
        self.bitmap.get_bit(bit)
    }

    /// Get the value of a bit from its chunk.
    /// `bit` is an index into the entire bitmap, not just the chunk.
    #[inline]
    pub const fn get_bit_from_chunk(chunk: &[u8; N], bit: u64) -> bool {
        PrunableBitMap::<N>::get_bit_from_chunk(chunk, bit)
    }

    /// Verify whether `proof` proves that the `chunk` containing the given bit belongs to the
    /// bitmap corresponding to `root`.
    pub fn verify_bit_inclusion(
        hasher: &mut impl MmrHasher<Digest = D>,
        proof: &Proof<D>,
        chunk: &[u8; N],
        bit: u64,
        root: &D,
    ) -> bool {
        let bit_len = *proof.leaves;
        if bit >= bit_len {
            debug!(bit_len, bit, "tried to verify non-existent bit");
            return false;
        }

        // The chunk index should always be < MAX_LOCATION so we can use new_unchecked.
        let chunked_leaves =
            Location::new_unchecked(PrunableBitMap::<N>::unpruned_chunk(bit_len) as u64);
        let mut mmr_proof = Proof {
            leaves: chunked_leaves,
            digests: proof.digests.clone(),
        };

        let loc = Location::new_unchecked(PrunableBitMap::<N>::unpruned_chunk(bit) as u64);
        if bit_len.is_multiple_of(Self::CHUNK_SIZE_BITS) {
            return mmr_proof.verify_element_inclusion(hasher, chunk, loc, root);
        }

        if proof.digests.is_empty() {
            debug!("proof has no digests");
            return false;
        }
        let last_digest = mmr_proof.digests.pop().unwrap();

        if chunked_leaves == loc {
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
            let reconstructed_root = partial_chunk_root::<_, N>(
                hasher.inner(),
                &last_digest,
                next_bit,
                &last_chunk_digest,
            );
            return reconstructed_root == *root;
        };

        // For the case where the proof is over a bit in a full chunk, `last_digest` contains the
        // digest of that chunk.
        let mmr_root = match mmr_proof.reconstruct_root(hasher, &[chunk], loc) {
            Ok(root) => root,
            Err(error) => {
                debug!(error = ?error, "invalid proof input");
                return false;
            }
        };

        let next_bit = bit_len % Self::CHUNK_SIZE_BITS;
        let reconstructed_root =
            partial_chunk_root::<_, N>(hasher.inner(), &mmr_root, next_bit, &last_digest);

        reconstructed_root == *root
    }
}

impl<E: Clock + RStorage + Metrics, D: Digest, const N: usize> CleanBitMap<E, D, N> {
    /// Initialize a bitmap from the metadata in the given partition. If the partition is empty,
    /// returns an empty bitmap. Otherwise restores the pruned state (the caller must replay
    /// retained elements to restore its full state).
    ///
    /// Returns an error if the bitmap could not be restored, e.g. because of data corruption or
    /// underlying storage error.
    pub async fn init(
        context: E,
        partition: &str,
        pool: Option<ThreadPool>,
        hasher: &mut impl MmrHasher<Digest = D>,
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
            let mmr = CleanMmr::new(hasher);
            let cached_root = *mmr.root();
            return Ok(Self {
                bitmap: PrunableBitMap::new(),
                authenticated_len: 0,
                mmr,
                dirty_chunks: HashSet::new(),
                pool,
                cached_root: Some(cached_root),
                metadata,
            });
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

        let mmr = CleanMmr::init(
            Config {
                nodes: Vec::new(),
                pruned_to_pos: mmr_size,
                pinned_nodes,
            },
            hasher,
        )?;

        let bitmap = PrunableBitMap::new_with_pruned_chunks(pruned_chunks)
            .expect("pruned_chunks should never overflow");
        let cached_root = *mmr.root();
        Ok(Self {
            bitmap,
            authenticated_len: 0,
            mmr,
            dirty_chunks: HashSet::new(),
            pool,
            cached_root: Some(cached_root),
            metadata,
        })
    }

    pub fn get_node(&self, position: Position) -> Option<D> {
        self.mmr.get_node(position)
    }

    /// Write the information necessary to restore the bitmap in its fully pruned state at its last
    /// pruning boundary. Restoring the entire bitmap state is then possible by replaying the
    /// retained elements.
    pub async fn write_pruned(&mut self) -> Result<(), Error> {
        self.metadata.clear();

        // Write the number of pruned chunks.
        let key = U64::new(PRUNED_CHUNKS_PREFIX, 0);
        self.metadata
            .put(key, self.bitmap.pruned_chunks().to_be_bytes().to_vec());

        // Write the pinned nodes.
        // This will never panic because pruned_chunks is always less than MAX_LOCATION.
        let mmr_size =
            Position::try_from(Location::new_unchecked(self.bitmap.pruned_chunks() as u64))?;
        for (i, digest) in nodes_to_pin(mmr_size).enumerate() {
            let digest = self.mmr.get_node_unchecked(digest);
            let key = U64::new(NODE_PREFIX, i as u64);
            self.metadata.put(key, digest.to_vec());
        }

        self.metadata.sync().await.map_err(MetadataError)
    }

    /// Destroy the bitmap metadata from disk.
    pub async fn destroy(self) -> Result<(), Error> {
        self.metadata.destroy().await.map_err(MetadataError)
    }

    /// Prune all complete chunks before the chunk containing the given bit.
    ///
    /// The chunk containing `bit` and all subsequent chunks are retained. All chunks
    /// before it are pruned from the bitmap and the underlying MMR.
    ///
    /// If `bit` equals the bitmap length, this prunes all complete chunks while retaining
    /// the empty trailing chunk, preparing the bitmap for appending new data.
    pub fn prune_to_bit(&mut self, bit: u64) -> Result<(), Error> {
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

    /// Return the cached root digest against which inclusion proofs can be verified.
    ///
    /// # Format
    ///
    /// The root digest is simply that of the underlying MMR whenever the bit count falls on a chunk
    /// boundary. Otherwise, the root is computed as follows in order to capture the bits that are
    /// not yet part of the MMR:
    ///
    /// hash(mmr_root || next_bit as u64 be_bytes || last_chunk_digest)
    ///
    /// The root is computed during merkleization and cached, so this method is cheap to call.
    pub const fn root(&self) -> D {
        self.cached_root
            .expect("CleanBitMap should always have a cached root")
    }

    /// Return an inclusion proof for the specified bit, along with the chunk of the bitmap
    /// containing that bit. The proof can be used to prove any bit in the chunk.
    ///
    /// The bitmap proof stores the number of bits in the bitmap within the `size` field of the
    /// proof instead of MMR size since the underlying MMR's size does not reflect the number of
    /// bits in any partial chunk. The underlying MMR size can be derived from the number of
    /// bits as `leaf_num_to_pos(proof.size / BitMap<_, N>::CHUNK_SIZE_BITS)`.
    ///
    /// # Errors
    ///
    /// Returns [Error::BitOutOfBounds] if `bit` is out of bounds.
    pub async fn proof(
        &self,
        hasher: &mut impl MmrHasher<Digest = D>,
        bit: u64,
    ) -> Result<(Proof<D>, [u8; N]), Error> {
        if bit >= self.len() {
            return Err(Error::BitOutOfBounds(bit, self.len()));
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
                    leaves: Location::new_unchecked(self.len()),
                    digests: vec![*self.mmr.root()],
                },
                chunk,
            ));
        }

        let range = chunk_loc..chunk_loc + 1;
        let mut proof = verification::range_proof(&self.mmr, range).await?;
        proof.leaves = Location::new_unchecked(self.len());
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

    /// Convert this clean bitmap into a dirty bitmap without making any changes to it.
    pub fn into_dirty(self) -> DirtyBitMap<E, D, N> {
        DirtyBitMap {
            bitmap: self.bitmap,
            authenticated_len: self.authenticated_len,
            mmr: self.mmr.into_dirty(),
            dirty_chunks: self.dirty_chunks,
            pool: self.pool,
            cached_root: self.cached_root,
            metadata: self.metadata,
        }
    }
}

impl<E: Clock + RStorage + Metrics, D: Digest, const N: usize> DirtyBitMap<E, D, N> {
    /// Add a single bit to the end of the bitmap.
    ///
    /// # Warning
    ///
    /// The update will not affect the root until `merkleize` is called.
    pub fn push(&mut self, bit: bool) {
        self.bitmap.push(bit);
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
    pub async fn merkleize(
        mut self,
        hasher: &mut impl MmrHasher<Digest = D>,
    ) -> Result<CleanBitMap<E, D, N>, Error> {
        // Add newly pushed complete chunks to the MMR.
        let start = self.authenticated_len;
        let end = self.complete_chunks();
        for i in start..end {
            self.mmr.add(hasher, self.bitmap.get_chunk(i));
        }
        self.authenticated_len = end;

        // Inform the MMR of modified chunks.
        let pruned_chunks = self.bitmap.pruned_chunks();
        let updates = self
            .dirty_chunks
            .iter()
            .map(|chunk| {
                let loc = Location::new_unchecked((*chunk + pruned_chunks) as u64);
                (loc, self.bitmap.get_chunk(*chunk))
            })
            .collect::<Vec<_>>();
        self.mmr
            .update_leaf_batched(hasher, self.pool.clone(), &updates)?;
        self.dirty_chunks.clear();
        let mmr = self.mmr.merkleize(hasher, self.pool.clone());

        // Compute the bitmap root
        let mmr_root = *mmr.root();
        let cached_root = if self.bitmap.is_chunk_aligned() {
            mmr_root
        } else {
            let (last_chunk, next_bit) = self.bitmap.last_chunk();
            let last_chunk_digest = hasher.digest(last_chunk);
            partial_chunk_root::<_, N>(hasher.inner(), &mmr_root, next_bit, &last_chunk_digest)
        };

        Ok(CleanBitMap {
            bitmap: self.bitmap,
            authenticated_len: self.authenticated_len,
            mmr,
            dirty_chunks: self.dirty_chunks,
            pool: self.pool,
            cached_root: Some(cached_root),
            metadata: self.metadata,
        })
    }
}

impl<E: Clock + RStorage + Metrics, D: Digest, const N: usize> Storage<D> for CleanBitMap<E, D, N> {
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
    use commonware_runtime::{deterministic, Metrics, Runner as _};

    const SHA256_SIZE: usize = sha256::Digest::SIZE;

    type TestContext = deterministic::Context;
    type TestCleanBitMap<const N: usize> = CleanBitMap<TestContext, sha256::Digest, N>;

    impl<E: Clock + RStorage + Metrics, D: Digest, const N: usize, S: State<D>> BitMap<E, D, N, S> {
        /// Convert a bit into the position of the Merkle tree leaf it belongs to.
        pub(crate) fn leaf_pos(bit: u64) -> Position {
            let chunk = PrunableBitMap::<N>::unpruned_chunk(bit);
            let chunk = Location::new_unchecked(chunk as u64);
            Position::try_from(chunk).expect("chunk should never overflow MAX_LOCATION")
        }
    }

    impl<E: Clock + RStorage + Metrics, D: Digest, const N: usize> DirtyBitMap<E, D, N> {
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
        executor.start(|_context| async move {
            let mut hasher = StandardHasher::<Sha256>::new();
            let proof = Proof {
                leaves: Location::new_unchecked(100),
                digests: Vec::new(),
            };
            assert!(
                !TestCleanBitMap::<SHA256_SIZE>::verify_bit_inclusion(
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
        executor.start(|context| async move {
            let mut hasher = StandardHasher::<Sha256>::new();
            let mut bitmap: TestCleanBitMap<SHA256_SIZE> =
                TestCleanBitMap::init(context.with_label("bitmap"), "test", None, &mut hasher)
                    .await
                    .unwrap();
            assert_eq!(bitmap.len(), 0);
            assert_eq!(bitmap.bitmap.pruned_chunks(), 0);
            bitmap.prune_to_bit(0).unwrap();
            assert_eq!(bitmap.bitmap.pruned_chunks(), 0);

            // Add a single bit
            let root = bitmap.root();
            let mut dirty = bitmap.into_dirty();
            dirty.push(true);
            bitmap = dirty.merkleize(&mut hasher).await.unwrap();
            // Root should change
            let new_root = bitmap.root();
            assert_ne!(root, new_root);
            let root = new_root;
            bitmap.prune_to_bit(1).unwrap();
            assert_eq!(bitmap.len(), 1);
            assert_ne!(bitmap.last_chunk().0, &[0u8; SHA256_SIZE]);
            assert_eq!(bitmap.last_chunk().1, 1);
            // Pruning should be a no-op since we're not beyond a chunk boundary.
            assert_eq!(bitmap.bitmap.pruned_chunks(), 0);
            assert_eq!(root, bitmap.root());

            // Fill up a full chunk
            let mut dirty = bitmap.into_dirty();
            for i in 0..(TestCleanBitMap::<SHA256_SIZE>::CHUNK_SIZE_BITS - 1) {
                dirty.push(i % 2 != 0);
            }
            bitmap = dirty.merkleize(&mut hasher).await.unwrap();
            assert_eq!(bitmap.len(), 256);
            assert_ne!(root, bitmap.root());
            let root = bitmap.root();

            // Chunk should be provable.
            let (proof, chunk) = bitmap.proof(&mut hasher, 0).await.unwrap();
            assert!(
                TestCleanBitMap::<SHA256_SIZE>::verify_bit_inclusion(
                    &mut hasher,
                    &proof,
                    &chunk,
                    255,
                    &root
                ),
                "failed to prove bit in only chunk"
            );
            // bit outside range should not verify
            assert!(
                !TestCleanBitMap::<SHA256_SIZE>::verify_bit_inclusion(
                    &mut hasher,
                    &proof,
                    &chunk,
                    256,
                    &root
                ),
                "should not be able to prove bit outside of chunk"
            );

            // Now pruning all bits should matter.
            bitmap.prune_to_bit(256).unwrap();
            assert_eq!(bitmap.len(), 256);
            assert_eq!(bitmap.bitmap.pruned_chunks(), 1);
            assert_eq!(bitmap.bitmap.pruned_bits(), 256);
            assert_eq!(root, bitmap.root());

            // Pruning to an earlier point should be a no-op.
            bitmap.prune_to_bit(10).unwrap();
            assert_eq!(root, bitmap.root());
        });
    }

    #[test_traced]
    fn test_bitmap_building() {
        // Build the same bitmap with 2 chunks worth of bits in multiple ways and make sure they are
        // equivalent based on their roots.
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let test_chunk = test_chunk(b"test");
            let mut hasher: StandardHasher<Sha256> = StandardHasher::new();

            // Add each bit one at a time after the first chunk.
            let bitmap: TestCleanBitMap<SHA256_SIZE> =
                TestCleanBitMap::init(context.with_label("bitmap1"), "test1", None, &mut hasher)
                    .await
                    .unwrap();
            let mut dirty = bitmap.into_dirty();
            dirty.push_chunk(&test_chunk);
            for b in test_chunk {
                for j in 0..8 {
                    let mask = 1 << j;
                    let bit = (b & mask) != 0;
                    dirty.push(bit);
                }
            }
            assert_eq!(dirty.len(), 256 * 2);

            let bitmap = dirty.merkleize(&mut hasher).await.unwrap();
            let root = bitmap.root();
            let inner_root = *bitmap.mmr.root();
            assert_eq!(root, inner_root);

            {
                // Repeat the above MMR build only using push_chunk instead, and make
                // sure root digests match.
                let bitmap: TestCleanBitMap<SHA256_SIZE> = TestCleanBitMap::init(
                    context.with_label("bitmap2"),
                    "test2",
                    None,
                    &mut hasher,
                )
                .await
                .unwrap();
                let mut dirty = bitmap.into_dirty();
                dirty.push_chunk(&test_chunk);
                dirty.push_chunk(&test_chunk);
                let bitmap = dirty.merkleize(&mut hasher).await.unwrap();
                let same_root = bitmap.root();
                assert_eq!(root, same_root);
            }
            {
                // Repeat build again using push_byte this time.
                let bitmap: TestCleanBitMap<SHA256_SIZE> = TestCleanBitMap::init(
                    context.with_label("bitmap3"),
                    "test3",
                    None,
                    &mut hasher,
                )
                .await
                .unwrap();
                let mut dirty = bitmap.into_dirty();
                dirty.push_chunk(&test_chunk);
                for b in test_chunk {
                    dirty.push_byte(b);
                }
                let bitmap = dirty.merkleize(&mut hasher).await.unwrap();
                let same_root = bitmap.root();
                assert_eq!(root, same_root);
            }
        });
    }

    #[test_traced]
    #[should_panic(expected = "cannot add chunk")]
    fn test_bitmap_build_chunked_panic() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut hasher: StandardHasher<Sha256> = StandardHasher::new();
            let bitmap: TestCleanBitMap<SHA256_SIZE> =
                TestCleanBitMap::init(context.with_label("bitmap"), "test", None, &mut hasher)
                    .await
                    .unwrap();
            let mut dirty = bitmap.into_dirty();
            dirty.push_chunk(&test_chunk(b"test"));
            dirty.push(true);
            dirty.push_chunk(&test_chunk(b"panic"));
        });
    }

    #[test_traced]
    #[should_panic(expected = "cannot add byte")]
    fn test_bitmap_build_byte_panic() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut hasher: StandardHasher<Sha256> = StandardHasher::new();
            let bitmap: TestCleanBitMap<SHA256_SIZE> =
                TestCleanBitMap::init(context.with_label("bitmap"), "test", None, &mut hasher)
                    .await
                    .unwrap();
            let mut dirty = bitmap.into_dirty();
            dirty.push_chunk(&test_chunk(b"test"));
            dirty.push(true);
            dirty.push_byte(0x01);
        });
    }

    #[test_traced]
    #[should_panic(expected = "out of bounds")]
    fn test_bitmap_get_out_of_bounds_bit_panic() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut hasher: StandardHasher<Sha256> = StandardHasher::new();
            let bitmap: TestCleanBitMap<SHA256_SIZE> =
                TestCleanBitMap::init(context.with_label("bitmap"), "test", None, &mut hasher)
                    .await
                    .unwrap();
            let mut dirty = bitmap.into_dirty();
            dirty.push_chunk(&test_chunk(b"test"));
            dirty.get_bit(256);
        });
    }

    #[test_traced]
    #[should_panic(expected = "pruned")]
    fn test_bitmap_get_pruned_bit_panic() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut hasher: StandardHasher<Sha256> = StandardHasher::new();
            let bitmap: TestCleanBitMap<SHA256_SIZE> =
                TestCleanBitMap::init(context.with_label("bitmap"), "test", None, &mut hasher)
                    .await
                    .unwrap();
            let mut dirty = bitmap.into_dirty();
            dirty.push_chunk(&test_chunk(b"test"));
            dirty.push_chunk(&test_chunk(b"test2"));
            let mut bitmap = dirty.merkleize(&mut hasher).await.unwrap();

            bitmap.prune_to_bit(256).unwrap();
            bitmap.get_bit(255);
        });
    }

    #[test_traced]
    fn test_bitmap_root_boundaries() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Build a starting test MMR with two chunks worth of bits.
            let mut hasher = StandardHasher::<Sha256>::new();
            let bitmap: TestCleanBitMap<SHA256_SIZE> =
                TestCleanBitMap::init(context.with_label("bitmap"), "test", None, &mut hasher)
                    .await
                    .unwrap();
            let mut dirty = bitmap.into_dirty();
            dirty.push_chunk(&test_chunk(b"test"));
            dirty.push_chunk(&test_chunk(b"test2"));
            let mut bitmap = dirty.merkleize(&mut hasher).await.unwrap();

            let root = bitmap.root();

            // Confirm that root changes if we add a 1 bit, even though we won't fill a chunk.
            let mut dirty = bitmap.into_dirty();
            dirty.push(true);
            bitmap = dirty.merkleize(&mut hasher).await.unwrap();
            let new_root = bitmap.root();
            assert_ne!(root, new_root);
            assert_eq!(bitmap.mmr.size(), 3); // shouldn't include the trailing bits

            // Add 0 bits to fill up entire chunk.
            for _ in 0..(SHA256_SIZE * 8 - 1) {
                let mut dirty = bitmap.into_dirty();
                dirty.push(false);
                bitmap = dirty.merkleize(&mut hasher).await.unwrap();
                let newer_root = bitmap.root();
                // root will change when adding 0s within the same chunk
                assert_ne!(new_root, newer_root);
            }
            assert_eq!(bitmap.mmr.size(), 4); // chunk we filled should have been added to mmr

            // Confirm the root changes when we add the next 0 bit since it's part of a new chunk.
            let mut dirty = bitmap.into_dirty();
            dirty.push(false);
            assert_eq!(dirty.len(), 256 * 3 + 1);
            bitmap = dirty.merkleize(&mut hasher).await.unwrap();
            let newer_root = bitmap.root();
            assert_ne!(new_root, newer_root);

            // Confirm pruning everything doesn't affect the root.
            bitmap.prune_to_bit(bitmap.len()).unwrap();
            assert_eq!(bitmap.bitmap.pruned_chunks(), 3);
            assert_eq!(bitmap.len(), 256 * 3 + 1);
            assert_eq!(newer_root, bitmap.root());
        });
    }

    #[test_traced]
    fn test_bitmap_get_set_bits() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Build a test MMR with a few chunks worth of bits.
            let mut hasher = StandardHasher::<Sha256>::new();
            let bitmap: TestCleanBitMap<SHA256_SIZE> =
                TestCleanBitMap::init(context.with_label("bitmap"), "test", None, &mut hasher)
                    .await
                    .unwrap();
            let mut dirty = bitmap.into_dirty();
            dirty.push_chunk(&test_chunk(b"test"));
            dirty.push_chunk(&test_chunk(b"test2"));
            dirty.push_chunk(&test_chunk(b"test3"));
            dirty.push_chunk(&test_chunk(b"test4"));
            // Add a few extra bits to exercise not being on a chunk or byte boundary.
            dirty.push_byte(0xF1);
            dirty.push(true);
            dirty.push(false);
            dirty.push(true);

            let mut bitmap = dirty.merkleize(&mut hasher).await.unwrap();
            let root = bitmap.root();

            // Flip each bit and confirm the root changes, then flip it back to confirm it is safely
            // restored.
            for bit_pos in (0..bitmap.len()).rev() {
                let bit = bitmap.get_bit(bit_pos);
                let mut dirty = bitmap.into_dirty();
                dirty.set_bit(bit_pos, !bit);
                bitmap = dirty.merkleize(&mut hasher).await.unwrap();
                let new_root = bitmap.root();
                assert_ne!(root, new_root, "failed at bit {bit_pos}");
                // flip it back
                let mut dirty = bitmap.into_dirty();
                dirty.set_bit(bit_pos, bit);
                bitmap = dirty.merkleize(&mut hasher).await.unwrap();
                let new_root = bitmap.root();
                assert_eq!(root, new_root);
            }

            // Repeat the test after pruning.
            let start_bit = (SHA256_SIZE * 8 * 2) as u64;
            bitmap.prune_to_bit(start_bit).unwrap();
            for bit_pos in (start_bit..bitmap.len()).rev() {
                let bit = bitmap.get_bit(bit_pos);
                let mut dirty = bitmap.into_dirty();
                dirty.set_bit(bit_pos, !bit);
                bitmap = dirty.merkleize(&mut hasher).await.unwrap();
                let new_root = bitmap.root();
                assert_ne!(root, new_root, "failed at bit {bit_pos}");
                // flip it back
                let mut dirty = bitmap.into_dirty();
                dirty.set_bit(bit_pos, bit);
                bitmap = dirty.merkleize(&mut hasher).await.unwrap();
                let new_root = bitmap.root();
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
        executor.start(|context| async move {
            // Build a bitmap with 10 chunks worth of bits.
            let mut hasher = StandardHasher::<Sha256>::new();
            let bitmap: CleanBitMap<TestContext, sha256::Digest, N> =
                CleanBitMap::init(context.with_label("bitmap"), "test", None, &mut hasher)
                    .await
                    .unwrap();
            let mut dirty = bitmap.into_dirty();
            for i in 0u32..10 {
                dirty.push_chunk(&test_chunk(format!("test{i}").as_bytes()));
            }
            // Add a few extra bits to exercise not being on a chunk or byte boundary.
            dirty.push_byte(0xA6);
            dirty.push(true);
            dirty.push(false);
            dirty.push(true);
            dirty.push(true);
            dirty.push(false);

            let mut bitmap = dirty.merkleize(&mut hasher).await.unwrap();
            let root = bitmap.root();

            // Make sure every bit is provable, even after pruning in intervals of 251 bits (251 is
            // the largest prime that is less than the size of one 32-byte chunk in bits).
            for prune_to_bit in (0..bitmap.len()).step_by(251) {
                assert_eq!(bitmap.root(), root);
                bitmap.prune_to_bit(prune_to_bit).unwrap();
                for i in prune_to_bit..bitmap.len() {
                    let (proof, chunk) = bitmap.proof(&mut hasher, i).await.unwrap();

                    // Proof should verify for the original chunk containing the bit.
                    assert!(
                        CleanBitMap::<TestContext, _, N>::verify_bit_inclusion(
                            &mut hasher,
                            &proof,
                            &chunk,
                            i,
                            &root
                        ),
                        "failed to prove bit {i}",
                    );

                    // Flip the bit in the chunk and make sure the proof fails.
                    let corrupted = flip_bit(i, &chunk);
                    assert!(
                        !CleanBitMap::<TestContext, _, N>::verify_bit_inclusion(
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
            let mut hasher = StandardHasher::<Sha256>::new();
            // Initializing from an empty partition should result in an empty bitmap.
            let bitmap: TestCleanBitMap<SHA256_SIZE> =
                TestCleanBitMap::init(context.with_label("initial"), PARTITION, None, &mut hasher)
                    .await
                    .unwrap();
            assert_eq!(bitmap.len(), 0);

            // Add a non-trivial amount of data.
            let mut dirty = bitmap.into_dirty();
            for i in 0..FULL_CHUNK_COUNT {
                dirty.push_chunk(&test_chunk(format!("test{i}").as_bytes()));
            }
            let mut bitmap = dirty.merkleize(&mut hasher).await.unwrap();
            let chunk_aligned_root = bitmap.root();

            // Add a few extra bits beyond the last chunk boundary.
            let mut dirty = bitmap.into_dirty();
            dirty.push_byte(0xA6);
            dirty.push(true);
            dirty.push(false);
            dirty.push(true);
            bitmap = dirty.merkleize(&mut hasher).await.unwrap();
            let root = bitmap.root();

            // prune 10 chunks at a time and make sure replay will restore the bitmap every time.
            for i in (10..=FULL_CHUNK_COUNT).step_by(10) {
                bitmap
                    .prune_to_bit(
                        (i * TestCleanBitMap::<SHA256_SIZE>::CHUNK_SIZE_BITS as usize) as u64,
                    )
                    .unwrap();
                bitmap.write_pruned().await.unwrap();
                bitmap = TestCleanBitMap::init(
                    context.with_label(&format!("restore_{i}")),
                    PARTITION,
                    None,
                    &mut hasher,
                )
                .await
                .unwrap();
                let _ = bitmap.root();

                // Replay missing chunks.
                let mut dirty = bitmap.into_dirty();
                for j in i..FULL_CHUNK_COUNT {
                    dirty.push_chunk(&test_chunk(format!("test{j}").as_bytes()));
                }
                assert_eq!(dirty.bitmap.pruned_chunks(), i);
                assert_eq!(dirty.len(), FULL_CHUNK_COUNT as u64 * 256);
                bitmap = dirty.merkleize(&mut hasher).await.unwrap();
                assert_eq!(bitmap.root(), chunk_aligned_root);

                // Replay missing partial chunk.
                let mut dirty = bitmap.into_dirty();
                dirty.push_byte(0xA6);
                dirty.push(true);
                dirty.push(false);
                dirty.push(true);
                bitmap = dirty.merkleize(&mut hasher).await.unwrap();
                assert_eq!(bitmap.root(), root);
            }
        });
    }

    #[test_traced]
    fn test_bitmap_proof_out_of_bounds() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut hasher = StandardHasher::<Sha256>::new();
            let bitmap: TestCleanBitMap<SHA256_SIZE> =
                TestCleanBitMap::init(context.with_label("bitmap"), "test", None, &mut hasher)
                    .await
                    .unwrap();
            let mut dirty = bitmap.into_dirty();
            dirty.push_chunk(&test_chunk(b"test"));
            let bitmap = dirty.merkleize(&mut hasher).await.unwrap();

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
}
