//! An authenticated database (ADB) that provides succinct proofs of _any_ value ever associated
//! with a key, and also whether that value is the _current_ value associated with it. Its
//! implementation is based on an [Any] authenticated database combined with an authenticated
//! [Bitmap] over the activity status of each operation. The two structures are "grafted" together
//! to minimize proof sizes.

use crate::{
    adb::{
        any::fixed::{Any, Config as AConfig},
        Error,
    },
    index::Index,
    mmr::{
        bitmap::Bitmap,
        hasher::{Grafting, GraftingVerifier, Hasher, Standard},
        iterator::{leaf_num_to_pos, leaf_pos_to_num},
        storage::Grafting as GStorage,
        verification::Proof,
    },
    store::operation::Fixed,
    translator::Translator,
};
use commonware_codec::{Encode as _, FixedSize};
use commonware_cryptography::Hasher as CHasher;
use commonware_runtime::{buffer::PoolRef, Clock, Metrics, Storage as RStorage, ThreadPool};
use commonware_utils::Array;
use futures::future::try_join_all;
use tracing::{debug, warn};

/// Configuration for a [Current] authenticated db.
#[derive(Clone)]
pub struct Config<T: Translator> {
    /// The name of the [RStorage] partition used for the MMR's backing journal.
    pub mmr_journal_partition: String,

    /// The items per blob configuration value used by the MMR journal.
    pub mmr_items_per_blob: u64,

    /// The size of the write buffer to use for each blob in the MMR journal.
    pub mmr_write_buffer: usize,

    /// The name of the [RStorage] partition used for the MMR's metadata.
    pub mmr_metadata_partition: String,

    /// The name of the [RStorage] partition used to persist the (pruned) log of operations.
    pub log_journal_partition: String,

    /// The items per blob configuration value used by the log journal.
    pub log_items_per_blob: u64,

    /// The size of the write buffer to use for each blob in the log journal.
    pub log_write_buffer: usize,

    /// The name of the [RStorage] partition used for the bitmap metadata.
    pub bitmap_metadata_partition: String,

    /// The translator used by the compressed index.
    pub translator: T,

    /// An optional thread pool to use for parallelizing batch operations.
    pub thread_pool: Option<ThreadPool>,

    /// The buffer pool to use for caching data.
    pub buffer_pool: PoolRef,

    /// The number of operations to keep below the inactivity floor before pruning.
    pub pruning_delay: u64,
}

/// A key-value ADB based on an MMR over its log of operations, supporting authentication of whether
/// a key ever had a specific value, and whether the key currently has that value.
///
/// Note: The generic parameter N is not really generic, and must be manually set to double the size
/// of the hash digest being produced by the hasher. A compile-time assertion is used to prevent any
/// other setting.
pub struct Current<
    E: RStorage + Clock + Metrics,
    K: Array,
    V: Array,
    H: CHasher,
    T: Translator,
    const N: usize,
> {
    /// An [Any] authenticated database that provides the ability to prove whether a key ever had a
    /// specific value.
    pub any: Any<E, K, V, H, T>,

    /// The bitmap over the activity status of each operation. Supports augmenting [Any] proofs in
    /// order to further prove whether a key _currently_ has a specific value.
    pub status: Bitmap<H, N>,

    context: E,

    bitmap_metadata_partition: String,
}

/// The information required to verify a key value proof.
#[derive(Clone)]
pub struct KeyValueProofInfo<K, V, const N: usize> {
    /// The key whose value is being proven.
    pub key: K,

    /// The value of the key.
    pub value: V,

    /// The location of the operation that assigned this value to the key.
    pub loc: u64,

    /// The status bitmap chunk that contains the bit corresponding the operation's location.
    pub chunk: [u8; N],
}

impl<
        E: RStorage + Clock + Metrics,
        K: Array,
        V: Array,
        H: CHasher,
        T: Translator,
        const N: usize,
    > Current<E, K, V, H, T, N>
{
    // A compile-time assertion that the chunk size is some multiple of digest size. A multiple of 1 is optimal with
    // respect to proof size, but a higher multiple allows for a smaller (RAM resident) merkle tree over the structure.
    const _CHUNK_SIZE_ASSERT: () = assert!(
        N.is_multiple_of(H::Digest::SIZE),
        "chunk size must be some multiple of the digest size",
    );

    // A compile-time assertion that chunk size is a power of 2, which is necessary to allow the status bitmap tree to
    // be aligned with the underlying operations MMR.
    const _CHUNK_SIZE_IS_POW_OF_2_ASSERT: () =
        assert!(N.is_power_of_two(), "chunk size must be a power of 2");

    /// Initializes a [Current] authenticated database from the given `config`. Leverages parallel
    /// Merkleization to initialize the bitmap MMR if a thread pool is provided.
    pub async fn init(context: E, config: Config<T>) -> Result<Self, Error> {
        // Initialize the MMR journal and metadata.
        let cfg = AConfig {
            mmr_journal_partition: config.mmr_journal_partition,
            mmr_metadata_partition: config.mmr_metadata_partition,
            mmr_items_per_blob: config.mmr_items_per_blob,
            mmr_write_buffer: config.mmr_write_buffer,
            log_journal_partition: config.log_journal_partition,
            log_items_per_blob: config.log_items_per_blob,
            log_write_buffer: config.log_write_buffer,
            translator: config.translator.clone(),
            thread_pool: config.thread_pool,
            buffer_pool: config.buffer_pool,
            pruning_delay: config.pruning_delay,
        };

        let context = context.with_label("adb::current");
        let cloned_pool = cfg.thread_pool.clone();
        let mut status = Bitmap::restore_pruned(
            context.with_label("bitmap"),
            &config.bitmap_metadata_partition,
            cloned_pool,
        )
        .await?;

        // Initialize the db's mmr/log.
        let mut hasher = Standard::<H>::new();
        let (mut mmr, log) =
            Any::<_, _, _, _, T>::init_mmr_and_log(context.clone(), cfg, &mut hasher).await?;

        // Ensure consistency between the bitmap and the db's MMR.
        let mmr_pruned_pos = mmr.pruned_to_pos();
        let mut start_leaf_num = leaf_pos_to_num(mmr_pruned_pos).unwrap();
        let bit_count = status.bit_count();
        if start_leaf_num < bit_count {
            // This can happen if the commit operation failed before the mmr was pruned.
            warn!(
                start_leaf_num,
                bit_count, "mmr starting leaf precedes bitmap pruning point"
            );
            start_leaf_num = bit_count;
        }

        let pruned_bits = status.pruned_bits();
        let bitmap_pruned_pos = leaf_num_to_pos(pruned_bits);
        let mmr_pruned_leaves = leaf_pos_to_num(mmr_pruned_pos).unwrap();

        let mut grafter = Grafting::new(&mut hasher, Self::grafting_height());
        if bitmap_pruned_pos < mmr_pruned_pos {
            // The bitmap should never be behind the mmr more than one chunk's worth of bits, since
            // the mmr is always pruned after it.
            let chunk_bits = Bitmap::<H, N>::CHUNK_SIZE_BITS;
            assert!(
                mmr_pruned_leaves <= chunk_bits || pruned_bits >= mmr_pruned_leaves - chunk_bits
            );
            // Prepend the missing (inactive) bits needed to align the bitmap, which can only be
            // pruned to a chunk boundary, with the MMR's pruning boundary.
            for _ in pruned_bits..mmr_pruned_leaves {
                status.append(false);
            }
            // Load the digests of the grafting destination nodes from `mmr` into the grafting
            // hasher so the new leaf digests can be computed during sync.
            grafter
                .load_grafted_digests(&status.dirty_chunks(), &mmr)
                .await?;
            status.sync(&mut grafter).await?;
        }

        // Replay the log to generate the snapshot & populate the retained portion of the bitmap.
        let mut snapshot = Index::init(context.with_label("snapshot"), config.translator);
        let inactivity_floor_loc =
            Any::build_snapshot_from_log(start_leaf_num, &log, &mut snapshot, Some(&mut status))
                .await
                .unwrap();
        grafter
            .load_grafted_digests(&status.dirty_chunks(), &mmr)
            .await?;
        status.sync(&mut grafter).await?;
        assert!(
            pruned_bits <= inactivity_floor_loc,
            "bitmap is pruned beyond where bits should be retained"
        );

        let target_prune_loc = inactivity_floor_loc.saturating_sub(config.pruning_delay);
        if target_prune_loc > start_leaf_num {
            // Advance the pruning boundary if we failed to prune to the correct position for any reason.
            warn!(
                inactivity_floor_loc,
                target_prune_loc, start_leaf_num, "pruning MMR to correct position"
            );
            mmr.prune_to_pos(grafter.standard(), leaf_num_to_pos(target_prune_loc))
                .await?;
        }

        let any = Any {
            mmr,
            log,
            snapshot,
            inactivity_floor_loc,
            uncommitted_ops: 0,
            hasher: Standard::<H>::new(),
            pruning_delay: config.pruning_delay,
        };

        Ok(Self {
            any,
            status,
            context,
            bitmap_metadata_partition: config.bitmap_metadata_partition,
        })
    }

    /// Get the number of operations that have been applied to this db, including those that are not
    /// yet committed.
    pub fn op_count(&self) -> u64 {
        self.any.op_count()
    }

    /// Return the oldest location that remains readable & provable.
    pub fn oldest_retained_loc(&self) -> Option<u64> {
        self.any.oldest_retained_loc()
    }

    /// Get the value of `key` in the db, or None if it has no value.
    pub async fn get(&self, key: &K) -> Result<Option<V>, Error> {
        self.any.get(key).await
    }

    /// Get the level of the base MMR into which we are grafting.
    ///
    /// This value is log2 of the chunk size in bits. Since we assume the chunk size is a power of
    /// 2, we compute this from trailing_zeros.
    const fn grafting_height() -> u32 {
        Bitmap::<H, N>::CHUNK_SIZE_BITS.trailing_zeros()
    }

    /// Updates `key` to have value `value`. If the key already has this same value, then this is a
    /// no-op. The operation is reflected in the snapshot, but will be subject to rollback until the
    /// next successful `commit`.
    pub async fn update(&mut self, key: K, value: V) -> Result<(), Error> {
        let update_result = self.any.update_return_loc(key, value).await?;
        if let Some(old_loc) = update_result {
            self.status.set_bit(old_loc, false);
        }
        self.status.append(true);

        Ok(())
    }

    /// Delete `key` and its value from the db. Deleting a key that already has no value is a no-op.
    /// The operation is reflected in the snapshot, but will be subject to rollback until the next
    /// successful `commit`.
    pub async fn delete(&mut self, key: K) -> Result<(), Error> {
        let Some(old_loc) = self.any.delete(key).await? else {
            return Ok(());
        };

        self.status.append(false);
        self.status.set_bit(old_loc, false);

        Ok(())
    }

    /// Commit pending operations to the adb::any and sync it to disk. Leverages parallel
    /// Merkleization of the any-db if a thread pool is provided.
    async fn commit_ops(&mut self) -> Result<(), Error> {
        // Raise the inactivity floor by the # of uncommitted operations, plus 1 to account for the
        // commit op that will be appended.
        self.raise_inactivity_floor(self.any.uncommitted_ops + 1)
            .await?;
        self.any.uncommitted_ops = 0;
        self.any.sync().await
    }

    /// Raise the inactivity floor by exactly `max_steps` steps, followed by applying a commit
    /// operation. Each step either advances over an inactive operation, or re-applies an active
    /// operation to the tip and then advances over it. An active bit will be added to the status
    /// bitmap for any moved operation, with its old location in the bitmap flipped to false.
    ///
    /// This method does not change the state of the db's snapshot, but it always changes the root
    /// since it applies at least one operation.
    async fn raise_inactivity_floor(&mut self, max_steps: u64) -> Result<(), Error> {
        for _ in 0..max_steps {
            if self.any.inactivity_floor_loc == self.op_count() {
                break;
            }
            let op = self.any.log.read(self.any.inactivity_floor_loc).await?;
            let old_loc = self
                .any
                .move_op_if_active(op, self.any.inactivity_floor_loc)
                .await?;
            if let Some(old_loc) = old_loc {
                self.status.set_bit(old_loc, false);
                self.status.append(true);
            }
            self.any.inactivity_floor_loc += 1;
        }

        self.any
            .apply_op(Fixed::CommitFloor(self.any.inactivity_floor_loc))
            .await?;
        self.status.append(false);

        Ok(())
    }

    /// Commit any pending operations to the db, ensuring they are persisted to disk & recoverable
    /// upon return from this function. Also raises the inactivity floor according to the schedule,
    /// and prunes those operations more than `self.any.pruning_delay` below it. Leverages parallel
    /// Merkleization of the MMR structures if a thread pool is provided.
    pub async fn commit(&mut self) -> Result<(), Error> {
        // Failure recovery relies on this specific order of these three disk-based operations:
        //  (1) commit/sync the any db to disk (which raises the inactivity floor).
        //  (2) prune the bitmap to the updated pruning boundary and write its state to disk.
        //  (3) prune the any db of inactive operations.
        self.commit_ops().await?; // (1)

        let mut grafter = Grafting::new(&mut self.any.hasher, Self::grafting_height());
        grafter
            .load_grafted_digests(&self.status.dirty_chunks(), &self.any.mmr)
            .await?;
        self.status.sync(&mut grafter).await?;

        let target_prune_loc = self
            .any
            .inactivity_floor_loc
            .saturating_sub(self.any.pruning_delay);
        self.status.prune_to_bit(target_prune_loc);
        self.status
            .write_pruned(
                self.context.with_label("bitmap"),
                &self.bitmap_metadata_partition,
            )
            .await?; // (2)

        // Prune inactive elements from the any db. We do this last, because bitmap recovery could
        // require access to the hashes of these inactive nodes due to node grafting.
        self.any.prune_inactive().await?; // (3)

        Ok(())
    }

    /// Return the root of the db.
    ///
    /// # Warning
    ///
    /// Panics if there are uncommitted operations.
    pub async fn root(&self, hasher: &mut Standard<H>) -> Result<H::Digest, Error> {
        assert!(
            !self.status.is_dirty(),
            "must process updates before computing root"
        );
        let ops = &self.any.mmr;
        let height = Self::grafting_height();
        let grafted_mmr = GStorage::<'_, H, _, _>::new(&self.status, ops, height);
        let mmr_root = grafted_mmr.root(hasher).await?;

        // The digest contains all information from the base mmr, and all information from the peak
        // tree except for the partial chunk, if any.  If we are at a chunk boundary, then this is
        // all the information we need.
        let last_chunk = self.status.last_chunk();
        if last_chunk.1 == 0 {
            return Ok(mmr_root);
        }

        // There are bits in an uncommitted (partial) chunk, so we need to incorporate that
        // information into the root digest. We do so by computing a root in the same format as an
        // unaligned [Bitmap] root, which involves additionally hashing in the number of bits within
        // the last chunk and the digest of the last chunk.
        hasher.inner().update(last_chunk.0);
        let last_chunk_digest = hasher.inner().finalize();

        Ok(Bitmap::<H, N>::partial_chunk_root(
            hasher.inner(),
            &mmr_root,
            last_chunk.1,
            &last_chunk_digest,
        ))
    }

    /// Returns a proof that the specified range of operations are part of the database, along with
    /// the operations from the range. A truncated range (from hitting the max) can be detected by
    /// looking at the length of the returned operations vector. Also returns the bitmap chunks
    /// required to verify the proof.
    ///
    /// # Warning
    ///
    /// Panics if there are uncommitted operations.
    pub async fn range_proof(
        &self,
        hasher: &mut H,
        start_loc: u64,
        max_ops: u64,
    ) -> Result<(Proof<H::Digest>, Vec<Fixed<K, V>>, Vec<[u8; N]>), Error> {
        assert!(
            !self.status.is_dirty(),
            "must process updates before computing proofs"
        );
        let mmr = &self.any.mmr;
        let start_pos = leaf_num_to_pos(start_loc);
        let end_pos_last = mmr.last_leaf_pos().unwrap();
        let end_pos_max = leaf_num_to_pos(start_loc + max_ops - 1);
        let (end_pos, end_loc) = if end_pos_last < end_pos_max {
            (end_pos_last, leaf_pos_to_num(end_pos_last).unwrap())
        } else {
            (end_pos_max, start_loc + max_ops - 1)
        };
        let height = Self::grafting_height();
        let grafted_mmr = GStorage::<'_, H, _, _>::new(&self.status, mmr, height);

        let mut proof = Proof::<H::Digest>::range_proof(&grafted_mmr, start_pos, end_pos).await?;

        let mut ops = Vec::with_capacity((end_loc - start_loc + 1) as usize);
        let futures = (start_loc..=end_loc)
            .map(|i| self.any.log.read(i))
            .collect::<Vec<_>>();
        try_join_all(futures)
            .await?
            .into_iter()
            .for_each(|op| ops.push(op));

        // Gather the chunks necessary to verify the proof.
        let chunk_bits = Bitmap::<H, N>::CHUNK_SIZE_BITS;
        let start = start_loc / chunk_bits;
        let end = end_loc / chunk_bits;
        let mut chunks = Vec::with_capacity((end - start + 1) as usize);
        for i in start..=end {
            let bit_offset = i * chunk_bits;
            let chunk = *self.status.get_chunk(bit_offset);
            chunks.push(chunk);
        }

        let last_chunk = self.status.last_chunk();
        if last_chunk.1 == 0 {
            return Ok((proof, ops, chunks));
        }

        hasher.update(last_chunk.0);
        proof.digests.push(hasher.finalize());

        Ok((proof, ops, chunks))
    }

    /// Return true if the given sequence of `ops` were applied starting at location `start_loc` in
    /// the log with the provided root.
    pub fn verify_range_proof(
        hasher: &mut Standard<H>,
        proof: &Proof<H::Digest>,
        start_loc: u64,
        ops: &[Fixed<K, V>],
        chunks: &[[u8; N]],
        root: &H::Digest,
    ) -> bool {
        let op_count = leaf_pos_to_num(proof.size);
        let Some(op_count) = op_count else {
            debug!("verification failed, invalid proof size");
            return false;
        };
        let end_loc = start_loc + ops.len() as u64 - 1;
        if end_loc >= op_count {
            debug!(
                loc = end_loc,
                op_count, "proof verification failed, invalid range"
            );
            return false;
        }

        let start_pos = leaf_num_to_pos(start_loc);

        let elements = ops.iter().map(|op| op.encode()).collect::<Vec<_>>();

        let chunk_vec = chunks.iter().map(|c| c.as_ref()).collect::<Vec<_>>();
        let mut verifier = GraftingVerifier::<H>::new(
            Self::grafting_height(),
            start_loc / Bitmap::<H, N>::CHUNK_SIZE_BITS,
            chunk_vec,
        );

        if op_count % Bitmap::<H, N>::CHUNK_SIZE_BITS == 0 {
            return proof.verify_range_inclusion(&mut verifier, &elements, start_pos, root);
        }

        // The proof must contain the partial chunk digest as its last hash.
        if proof.digests.is_empty() {
            debug!("proof has no digests");
            return false;
        }
        let mut proof = proof.clone();
        let last_chunk_digest = proof.digests.pop().unwrap();

        // Reconstruct the MMR root.
        let mmr_root = match proof.reconstruct_root(&mut verifier, &elements, start_pos) {
            Ok(root) => root,
            Err(error) => {
                debug!(error = ?error, "invalid proof input");
                return false;
            }
        };

        let next_bit = op_count % Bitmap::<H, N>::CHUNK_SIZE_BITS;
        let reconstructed_root = Bitmap::<H, N>::partial_chunk_root(
            hasher.inner(),
            &mmr_root,
            next_bit,
            &last_chunk_digest,
        );

        reconstructed_root == *root
    }

    /// Generate and return a proof of the current value of `key`, along with the other
    /// [KeyValueProofInfo] required to verify the proof. Returns KeyNotFound error if the key is
    /// not currently assigned any value.
    ///
    /// # Warning
    ///
    /// Panics if there are uncommitted operations.
    pub async fn key_value_proof(
        &self,
        hasher: &mut H,
        key: K,
    ) -> Result<(Proof<H::Digest>, KeyValueProofInfo<K, V, N>), Error> {
        assert!(
            !self.status.is_dirty(),
            "must process updates before computing proofs"
        );
        let op = self.any.get_with_loc(&key).await?;
        let Some((value, loc)) = op else {
            return Err(Error::KeyNotFound);
        };
        let pos = leaf_num_to_pos(loc);
        let height = Self::grafting_height();
        let grafted_mmr = GStorage::<'_, H, _, _>::new(&self.status, &self.any.mmr, height);

        let mut proof = Proof::<H::Digest>::range_proof(&grafted_mmr, pos, pos).await?;
        let chunk = *self.status.get_chunk(loc);

        let last_chunk = self.status.last_chunk();
        if last_chunk.1 != 0 {
            hasher.update(last_chunk.0);
            proof.digests.push(hasher.finalize());
        }

        Ok((
            proof,
            KeyValueProofInfo {
                key,
                value,
                loc,
                chunk,
            },
        ))
    }

    /// Return true if the proof authenticates that `key` currently has value `value` in the db with
    /// the given root.
    pub fn verify_key_value_proof(
        hasher: &mut H,
        proof: &Proof<H::Digest>,
        info: &KeyValueProofInfo<K, V, N>,
        root: &H::Digest,
    ) -> bool {
        let Some(op_count) = leaf_pos_to_num(proof.size) else {
            debug!("verification failed, invalid proof size");
            return false;
        };

        // Make sure that the bit for the operation in the bitmap chunk is actually a 1 (indicating
        // the operation is indeed active).
        if !Bitmap::<H, N>::get_bit_from_chunk(&info.chunk, info.loc) {
            debug!(
                loc = info.loc,
                "proof verification failed, operation is inactive"
            );
            return false;
        }

        let pos = leaf_num_to_pos(info.loc);
        let num = info.loc / Bitmap::<H, N>::CHUNK_SIZE_BITS;
        let mut verifier =
            GraftingVerifier::<H>::new(Self::grafting_height(), num, vec![&info.chunk]);
        let element = Fixed::Update(info.key.clone(), info.value.clone()).encode();

        if op_count % Bitmap::<H, N>::CHUNK_SIZE_BITS == 0 {
            return proof.verify_element_inclusion(&mut verifier, &element, pos, root);
        }

        // The proof must contain the partial chunk digest as its last hash.
        if proof.digests.is_empty() {
            debug!("proof has no digests");
            return false;
        }

        let mut proof = proof.clone();
        let last_chunk_digest = proof.digests.pop().unwrap();

        // If the proof is over an operation in the partial chunk, we need to verify the last chunk
        // digest from the proof matches the digest of info.chunk, since these bits are not part of
        // the mmr.
        if info.loc / Bitmap::<H, N>::CHUNK_SIZE_BITS == op_count / Bitmap::<H, N>::CHUNK_SIZE_BITS
        {
            let expected_last_chunk_digest = verifier.digest(&info.chunk);
            if last_chunk_digest != expected_last_chunk_digest {
                debug!("last chunk digest does not match expected value");
                return false;
            }
        }

        // Reconstruct the MMR root.
        let mmr_root = match proof.reconstruct_root(&mut verifier, &[element], pos) {
            Ok(root) => root,
            Err(error) => {
                debug!(error = ?error, "invalid proof input");
                return false;
            }
        };

        let next_bit = op_count % Bitmap::<H, N>::CHUNK_SIZE_BITS;
        let reconstructed_root =
            Bitmap::<H, N>::partial_chunk_root(hasher, &mmr_root, next_bit, &last_chunk_digest);

        reconstructed_root == *root
    }

    /// Close the db. Operations that have not been committed will be lost.
    pub async fn close(self) -> Result<(), Error> {
        self.any.close().await
    }

    /// Destroy the db, removing all data from disk.
    pub async fn destroy(self) -> Result<(), Error> {
        self.any.destroy().await
    }

    #[cfg(test)]
    /// Generate an inclusion proof for any operation regardless of its activity state.
    async fn operation_inclusion_proof(
        &self,
        hasher: &mut H,
        loc: u64,
    ) -> Result<(Proof<H::Digest>, Fixed<K, V>, u64, [u8; N]), Error> {
        let op = self.any.log.read(loc).await?;

        let pos = leaf_num_to_pos(loc);
        let height = Self::grafting_height();
        let grafted_mmr = GStorage::<'_, H, _, _>::new(&self.status, &self.any.mmr, height);

        let mut proof = Proof::<H::Digest>::range_proof(&grafted_mmr, pos, pos).await?;
        let chunk = *self.status.get_chunk(loc);

        let last_chunk = self.status.last_chunk();
        if last_chunk.1 != 0 {
            hasher.update(last_chunk.0);
            proof.digests.push(hasher.finalize());
        }

        Ok((proof, op, loc, chunk))
    }

    #[cfg(test)]
    /// Simulate a crash that prevents any data from being written to disk, which involves simply
    /// consuming the db before it can be cleanly closed.
    fn simulate_commit_failure_before_any_writes(self) {
        // Don't successfully complete any of the commit operations.
    }

    #[cfg(test)]
    /// Simulate a crash that happens during commit and prevents the any db from being pruned of
    /// inactive operations, and bitmap state from being written/pruned.
    async fn simulate_commit_failure_after_any_db_commit(mut self) -> Result<(), Error> {
        // Only successfully complete operation (1) of the commit process.
        self.commit_ops().await
    }

    #[cfg(test)]
    /// Simulate a crash that happens during commit after the bitmap has been pruned & written, but
    /// before the any db is pruned of inactive elements.
    async fn simulate_commit_failure_after_bitmap_written(mut self) -> Result<(), Error> {
        // Only successfully complete operations (1) and (2) of the commit process.
        self.commit_ops().await?; // (1)

        let mut grafter = Grafting::new(&mut self.any.hasher, Self::grafting_height());
        grafter
            .load_grafted_digests(&self.status.dirty_chunks(), &self.any.mmr)
            .await?;
        self.status.sync(&mut grafter).await?;
        let target_prune_loc = self
            .any
            .inactivity_floor_loc
            .saturating_sub(self.any.pruning_delay);
        self.status.prune_to_bit(target_prune_loc);
        self.status
            .write_pruned(
                self.context.with_label("bitmap"),
                &self.bitmap_metadata_partition,
            )
            .await?; // (2)

        Ok(())
    }
}

#[cfg(test)]
pub mod test {
    use super::*;
    use crate::translator::TwoCap;
    use commonware_cryptography::{hash, sha256::Digest, Sha256};
    use commonware_macros::test_traced;
    use commonware_runtime::{deterministic, Runner as _};
    use rand::{rngs::StdRng, RngCore, SeedableRng};

    const PAGE_SIZE: usize = 88;
    const PAGE_CACHE_SIZE: usize = 8;

    fn current_db_config(partition_prefix: &str) -> Config<TwoCap> {
        Config {
            mmr_journal_partition: format!("{partition_prefix}_journal_partition"),
            mmr_metadata_partition: format!("{partition_prefix}_metadata_partition"),
            mmr_items_per_blob: 11,
            mmr_write_buffer: 1024,
            log_journal_partition: format!("{partition_prefix}_partition_prefix"),
            log_items_per_blob: 7,
            log_write_buffer: 1024,
            bitmap_metadata_partition: format!("{partition_prefix}_bitmap_metadata_partition"),
            translator: TwoCap,
            thread_pool: None,
            buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
            pruning_delay: 10,
        }
    }

    /// A type alias for the concrete [Current] type used in these unit tests.
    type CurrentTest = Current<deterministic::Context, Digest, Digest, Sha256, TwoCap, 32>;

    /// Return an [Current] database initialized with a fixed config.
    async fn open_db(context: deterministic::Context, partition_prefix: &str) -> CurrentTest {
        CurrentTest::init(context, current_db_config(partition_prefix))
            .await
            .unwrap()
    }

    /// Build a small database, then close and reopen it and ensure state is preserved.
    #[test_traced("DEBUG")]
    pub fn test_current_db_build_small_close_reopen() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut hasher = Standard::<Sha256>::new();
            let partition = "build_small";
            let mut db = open_db(context.clone(), partition).await;
            assert_eq!(db.op_count(), 0);
            assert_eq!(db.oldest_retained_loc(), None);
            let root0 = db.root(&mut hasher).await.unwrap();
            db.close().await.unwrap();
            db = open_db(context.clone(), partition).await;
            assert_eq!(db.op_count(), 0);
            assert_eq!(db.root(&mut hasher).await.unwrap(), root0);

            // Add one key.
            let k1 = hash(&0u64.to_be_bytes());
            let v1 = hash(&10u64.to_be_bytes());
            db.update(k1, v1).await.unwrap();
            assert_eq!(db.get(&k1).await.unwrap().unwrap(), v1);
            db.commit().await.unwrap();
            assert_eq!(db.op_count(), 4); // 1 update, 1 commit, 2 moves.
            let root1 = db.root(&mut hasher).await.unwrap();
            assert!(root1 != root0);
            db.close().await.unwrap();
            db = open_db(context.clone(), partition).await;
            assert_eq!(db.op_count(), 4); // 1 update, 1 commit, 2 moves.
            assert_eq!(db.root(&mut hasher).await.unwrap(), root1);

            // Delete that one key.
            db.delete(k1).await.unwrap();
            db.commit().await.unwrap();
            assert_eq!(db.op_count(), 6); // 1 update, 2 commits, 2 moves, 1 delete.
            let root2 = db.root(&mut hasher).await.unwrap();
            db.close().await.unwrap();
            db = open_db(context.clone(), partition).await;
            assert_eq!(db.op_count(), 6); // 1 update, 2 commits, 2 moves, 1 delete.
            assert_eq!(db.root(&mut hasher).await.unwrap(), root2);

            // Confirm all activity bits are false
            for i in 0..db.op_count() {
                assert!(!db.status.get_bit(i));
            }

            db.destroy().await.unwrap();
        });
    }

    /// Build a tiny database and make sure we can't convince the verifier that some old value of a
    /// key is active. We specifically test over the partial chunk case, since these bits are yet to
    /// be committed to the underlying MMR.
    #[test_traced("DEBUG")]
    pub fn test_current_db_verify_proof_over_bits_in_uncommitted_chunk() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut hasher = Standard::<Sha256>::new();
            let partition = "build_small";
            let mut db = open_db(context.clone(), partition).await;

            // Add one key.
            let k = Sha256::fill(0x01);
            let v1 = Sha256::fill(0xA1);
            db.update(k, v1).await.unwrap();
            db.commit().await.unwrap();

            let op = db.any.get_with_loc(&k).await.unwrap().unwrap();
            let proof = db
                .operation_inclusion_proof(hasher.inner(), op.1)
                .await
                .unwrap();
            let info = KeyValueProofInfo {
                key: k,
                value: v1,
                loc: op.1,
                chunk: proof.3,
            };
            let root = db.root(&mut hasher).await.unwrap();
            // Proof should be verifiable against current root.
            assert!(CurrentTest::verify_key_value_proof(
                hasher.inner(),
                &proof.0,
                &info,
                &root,
            ),);

            let v2 = Sha256::fill(0xA2);
            // Proof should not verify against a different value.
            let mut bad_info = info.clone();
            bad_info.value = v2;
            assert!(!CurrentTest::verify_key_value_proof(
                hasher.inner(),
                &proof.0,
                &bad_info,
                &root,
            ),);

            // update the key to invalidate its previous update
            db.update(k, v2).await.unwrap();
            db.commit().await.unwrap();

            // Proof should not be verifiable against the new root.
            let root = db.root(&mut hasher).await.unwrap();
            assert!(!CurrentTest::verify_key_value_proof(
                hasher.inner(),
                &proof.0,
                &info,
                &root,
            ),);

            // Create a proof of the now-inactive operation.
            let proof_inactive = db
                .operation_inclusion_proof(hasher.inner(), op.1)
                .await
                .unwrap();
            // This proof should not verify, but only because verification will see that the
            // corresponding bit in the chunk is false.
            let proof_inactive_info = KeyValueProofInfo {
                key: k,
                value: v1,
                loc: proof_inactive.2,
                chunk: proof_inactive.3,
            };
            assert!(!CurrentTest::verify_key_value_proof(
                hasher.inner(),
                &proof_inactive.0,
                &proof_inactive_info,
                &root,
            ),);

            // Attempt #1 to "fool" the verifier:  change the location to that of an active
            // operation. This should not fool the verifier if we're properly validating the
            // inclusion of the operation itself, and not just the chunk.
            let (_, active_loc) = db.any.get_with_loc(&info.key).await.unwrap().unwrap();
            // The new location should differ but still be in the same chunk.
            assert_ne!(active_loc, info.loc);
            assert_eq!(
                Bitmap::<Sha256, 32>::leaf_pos(active_loc),
                Bitmap::<Sha256, 32>::leaf_pos(info.loc)
            );
            let mut info_with_modified_loc = info.clone();
            info_with_modified_loc.loc = active_loc;
            assert!(!CurrentTest::verify_key_value_proof(
                hasher.inner(),
                &proof_inactive.0,
                &proof_inactive_info,
                &root,
            ),);

            // Attempt #2 to "fool" the verifier: Modify the chunk in the proof info to make it look
            // like the operation is active by flipping its corresponding bit to 1. This should not
            // fool the verifier if we are correctly incorporating the partial chunk information
            // into the root computation.
            let mut modified_chunk = proof_inactive.3;
            let bit_pos = proof_inactive.2;
            let byte_idx = bit_pos / 8;
            let bit_idx = bit_pos % 8;
            modified_chunk[byte_idx as usize] |= 1 << bit_idx;

            let mut info_with_modified_chunk = info.clone();
            info_with_modified_chunk.chunk = modified_chunk;
            assert!(!CurrentTest::verify_key_value_proof(
                hasher.inner(),
                &proof_inactive.0,
                &info_with_modified_chunk,
                &root,
            ),);

            db.destroy().await.unwrap();
        });
    }

    /// Apply random operations to the given db, committing them (randomly & at the end) only if
    /// `commit_changes` is true.
    async fn apply_random_ops(
        num_elements: u64,
        commit_changes: bool,
        rng_seed: u64,
        db: &mut CurrentTest,
    ) -> Result<(), Error> {
        // Log the seed with high visibility to make failures reproducible.
        warn!("rng_seed={}", rng_seed);
        let mut rng = StdRng::seed_from_u64(rng_seed);

        for i in 0u64..num_elements {
            let k = hash(&i.to_be_bytes());
            let v = hash(&rng.next_u32().to_be_bytes());
            db.update(k, v).await.unwrap();
        }

        // Randomly update / delete them. We use a delete frequency that is 1/7th of the update
        // frequency.
        for _ in 0u64..num_elements * 10 {
            let rand_key = hash(&(rng.next_u64() % num_elements).to_be_bytes());
            if rng.next_u32() % 7 == 0 {
                db.delete(rand_key).await.unwrap();
                continue;
            }
            let v = hash(&rng.next_u32().to_be_bytes());
            db.update(rand_key, v).await.unwrap();
            if commit_changes && rng.next_u32() % 20 == 0 {
                // Commit every ~20 updates.
                db.commit().await.unwrap();
            }
        }
        if commit_changes {
            db.commit().await.unwrap();
        }

        Ok(())
    }

    #[test_traced("DEBUG")]
    pub fn test_current_db_range_proofs() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            let partition = "range_proofs";
            let mut hasher = Standard::<Sha256>::new();
            let mut db = open_db(context.clone(), partition).await;
            apply_random_ops(200, true, context.next_u64(), &mut db)
                .await
                .unwrap();
            let root = db.root(&mut hasher).await.unwrap();

            // Make sure size-constrained batches of operations are provable from the oldest
            // retained op to tip.
            let max_ops = 4;
            let end_loc = db.op_count();
            let start_pos = db.any.mmr.pruned_to_pos();
            let start_loc = leaf_pos_to_num(start_pos).unwrap();

            for i in start_loc..end_loc {
                let (proof, ops, chunks) =
                    db.range_proof(hasher.inner(), i, max_ops).await.unwrap();
                assert!(
                    CurrentTest::verify_range_proof(&mut hasher, &proof, i, &ops, &chunks, &root),
                    "failed to verify range at start_loc {start_loc}",
                );
            }

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("DEBUG")]
    pub fn test_current_db_key_value_proof() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            let partition = "range_proofs";
            let mut hasher = Standard::<Sha256>::new();
            let mut db = open_db(context.clone(), partition).await;
            apply_random_ops(500, true, context.next_u64(), &mut db)
                .await
                .unwrap();
            let root = db.root(&mut hasher).await.unwrap();

            // Confirm bad keys produce the expected error.
            let bad_key = Sha256::fill(0xAA);
            let res = db.key_value_proof(hasher.inner(), bad_key).await;
            assert!(matches!(res, Err(Error::KeyNotFound)));

            let start = db.oldest_retained_loc().unwrap();
            for i in start..db.status.bit_count() {
                if !db.status.get_bit(i) {
                    continue;
                }
                // Found an active operation! Create a proof for its active current key/value.
                let op = db.any.log.read(i).await.unwrap();
                let key = op.to_key().unwrap();
                let (proof, info) = db.key_value_proof(hasher.inner(), *key).await.unwrap();
                assert_eq!(info.value, *op.to_value().unwrap());
                // Proof should validate against the current value and correct root.
                assert!(CurrentTest::verify_key_value_proof(
                    hasher.inner(),
                    &proof,
                    &info,
                    &root
                ));
                // Proof should fail against the wrong value.
                let wrong_val = Sha256::fill(0xFF);
                let mut bad_info = info.clone();
                bad_info.value = wrong_val;
                assert!(!CurrentTest::verify_key_value_proof(
                    hasher.inner(),
                    &proof,
                    &bad_info,
                    &root
                ));
                // Proof should fail against the wrong key.
                let wrong_key = Sha256::fill(0xEE);
                let mut bad_info = info.clone();
                bad_info.key = wrong_key;
                assert!(!CurrentTest::verify_key_value_proof(
                    hasher.inner(),
                    &proof,
                    &bad_info,
                    &root
                ));
                // Proof should fail against the wrong root.
                let wrong_root = Sha256::fill(0xDD);
                assert!(!CurrentTest::verify_key_value_proof(
                    hasher.inner(),
                    &proof,
                    &info,
                    &wrong_root,
                ),);
            }

            db.destroy().await.unwrap();
        });
    }

    /// This test builds a random database, and makes sure that its state is correctly restored
    /// after closing and re-opening.
    #[test_traced("WARN")]
    pub fn test_current_db_build_random_close_reopen() {
        // Number of elements to initially insert into the db.
        const ELEMENTS: u64 = 1000;

        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            let partition = "build_random";
            let rng_seed = context.next_u64();
            let mut hasher = Standard::<Sha256>::new();
            let mut db = open_db(context.clone(), partition).await;
            apply_random_ops(ELEMENTS, true, rng_seed, &mut db)
                .await
                .unwrap();

            // Close the db, then replay its operations with a bitmap.
            let root = db.root(&mut hasher).await.unwrap();
            // Create a bitmap based on the current db's pruned/inactive state.
            db.close().await.unwrap();

            let db = open_db(context, partition).await;
            assert_eq!(db.root(&mut hasher).await.unwrap(), root);

            db.destroy().await.unwrap();
        });
    }

    /// Repeatedly update the same key to a new value and ensure we can prove its current value
    /// after each update.
    #[test_traced("WARN")]
    pub fn test_current_db_proving_repeated_updates() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut hasher = Standard::<Sha256>::new();
            let partition = "build_small";
            let mut db = open_db(context.clone(), partition).await;

            // Add one key.
            let k = Sha256::fill(0x00);
            let mut old_info = KeyValueProofInfo {
                key: k,
                value: Sha256::fill(0x00),
                loc: 0,
                chunk: [0; 32],
            };
            for i in 1u8..=255 {
                let v = Sha256::fill(i);
                db.update(k, v).await.unwrap();
                assert_eq!(db.get(&k).await.unwrap().unwrap(), v);
                db.commit().await.unwrap();
                let root = db.root(&mut hasher).await.unwrap();

                // Create a proof for the current value of k.
                let (proof, info) = db.key_value_proof(hasher.inner(), k).await.unwrap();
                assert_eq!(info.value, v);
                assert!(
                    CurrentTest::verify_key_value_proof(hasher.inner(), &proof, &info, &root),
                    "proof of update {i} failed to verify"
                );
                // Ensure the proof does NOT verify if we use the previous value.
                assert!(
                    !CurrentTest::verify_key_value_proof(hasher.inner(), &proof, &old_info, &root),
                    "proof of update {i} failed to verify"
                );
                old_info = info.clone();
            }

            db.destroy().await.unwrap();
        });
    }

    /// This test builds a random database and simulates we can recover from 3 different types of
    /// failure scenarios.
    #[test_traced("WARN")]
    pub fn test_current_db_simulate_write_failures() {
        // Number of elements to initially insert into the db.
        const ELEMENTS: u64 = 1000;

        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            let partition = "build_random_fail_commit";
            let rng_seed = context.next_u64();
            let mut hasher = Standard::<Sha256>::new();
            let mut db = open_db(context.clone(), partition).await;
            apply_random_ops(ELEMENTS, true, rng_seed, &mut db)
                .await
                .unwrap();
            let committed_root = db.root(&mut hasher).await.unwrap();
            let committed_op_count = db.op_count();
            let committed_inactivity_floor = db.any.inactivity_floor_loc;
            let committed_pruning_loc = db.any.oldest_retained_loc().unwrap();

            // Verify the `pruning_delay` is correctly handled (default is 10)
            assert_eq!(
                committed_pruning_loc,
                committed_inactivity_floor.saturating_sub(10)
            );

            // Perform more random operations without committing any of them.
            apply_random_ops(ELEMENTS, false, rng_seed + 1, &mut db)
                .await
                .unwrap();

            // SCENARIO #1: Simulate a crash that happens before any writes. Upon reopening, the
            // state of the DB should be as of the last commit.
            db.simulate_commit_failure_before_any_writes();
            let mut db = open_db(context.clone(), partition).await;
            assert_eq!(db.root(&mut hasher).await.unwrap(), committed_root);
            assert_eq!(db.op_count(), committed_op_count);

            // Verify `pruning_delay` is persisted correctly.
            let recovered_pruning_loc = db.any.oldest_retained_loc().unwrap();
            assert_eq!(recovered_pruning_loc, committed_pruning_loc);
            assert_eq!(
                recovered_pruning_loc,
                db.any.inactivity_floor_loc.saturating_sub(10)
            );

            // Re-apply the exact same uncommitted operations.
            apply_random_ops(ELEMENTS, false, rng_seed + 1, &mut db)
                .await
                .unwrap();

            // SCENARIO #2: Simulate a crash that happens after the any db has been committed, but
            // before the state of the pruned bitmap can be written to disk.
            db.simulate_commit_failure_after_any_db_commit()
                .await
                .unwrap();

            // We should be able to recover, so the root should differ from the previous commit, and
            // the op count should be greater than before.
            let db = open_db(context.clone(), partition).await;
            let scenario_2_root = db.root(&mut hasher).await.unwrap();
            let scenario_2_pruning_loc = db.any.oldest_retained_loc().unwrap();
            let scenario_2_inactivity_floor = db.any.inactivity_floor_loc;

            // Verify `pruning_delay` is persisted correctly.
            assert_eq!(
                scenario_2_pruning_loc,
                scenario_2_inactivity_floor.saturating_sub(10)
            );

            // To confirm the second committed hash is correct we'll re-build the DB in a new
            // partition, but without any failures. They should have the exact same state.
            let fresh_partition = "build_random_fail_commit_fresh";
            let mut db = open_db(context.clone(), fresh_partition).await;
            apply_random_ops(ELEMENTS, true, rng_seed, &mut db)
                .await
                .unwrap();
            apply_random_ops(ELEMENTS, false, rng_seed + 1, &mut db)
                .await
                .unwrap();
            db.commit().await.unwrap();
            // State & pruning boundary from scenario #2 should match that of a successful commit.
            assert_eq!(db.root(&mut hasher).await.unwrap(), scenario_2_root);
            let successful_pruning_loc = db.any.oldest_retained_loc().unwrap();
            assert_eq!(successful_pruning_loc, scenario_2_pruning_loc);

            // Verify `pruning_delay` is persisted correctly.
            assert_eq!(
                successful_pruning_loc,
                db.any.inactivity_floor_loc.saturating_sub(10)
            );
            db.close().await.unwrap();

            // SCENARIO #3: Simulate a crash that happens after the any db has been committed and
            // the bitmap is written, but before the any db is pruned. Full state restoration should
            // remain possible, and pruning point should match a successful commit.
            let fresh_partition = "build_random_fail_commit_fresh_2";
            let mut db = open_db(context.clone(), fresh_partition).await;
            apply_random_ops(ELEMENTS, true, rng_seed, &mut db)
                .await
                .unwrap();
            apply_random_ops(ELEMENTS, false, rng_seed + 1, &mut db)
                .await
                .unwrap();
            db.simulate_commit_failure_after_bitmap_written()
                .await
                .unwrap();
            let db = open_db(context.clone(), fresh_partition).await;
            // State & pruning boundary should match that of the successful commit.
            assert_eq!(db.root(&mut hasher).await.unwrap(), scenario_2_root);
            let recovered_pruning_loc_3 = db.any.oldest_retained_loc().unwrap();
            assert_eq!(recovered_pruning_loc_3, successful_pruning_loc);

            // Verify `pruning_delay` is persisted correctly.
            assert_eq!(
                recovered_pruning_loc_3,
                db.any.inactivity_floor_loc.saturating_sub(10)
            );

            db.destroy().await.unwrap();
        });
    }

    /// Test that the `pruning_delay` works as expected.
    #[test_traced("WARN")]
    pub fn test_current_db_pruning_delay() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Create database with enough operations to trigger pruning
            let mut hasher = Standard::<Sha256>::new();
            let db_config = current_db_config("pruning_boundary_test");

            let mut db = CurrentTest::init(context.clone(), db_config.clone())
                .await
                .unwrap();

            const NUM_OPERATIONS: u64 = 500;
            for i in 0..NUM_OPERATIONS {
                let key = hash(&i.to_be_bytes());
                let value = hash(&(i * 1000).to_be_bytes());
                db.update(key, value).await.unwrap();

                // Commit periodically to advance the inactivity floor
                if i % 100 == 99 {
                    db.commit().await.unwrap();
                }
            }

            // Final commit to establish the inactivity floor
            db.commit().await.unwrap();

            // Get the root hash
            let original_root = db.root(&mut hasher).await.unwrap();

            // Verify the pruning boundary is correct
            let oldest_retained = db.oldest_retained_loc().unwrap();
            let inactivity_floor = db.any.inactivity_floor_loc;
            assert_eq!(
                oldest_retained,
                inactivity_floor.saturating_sub(db_config.pruning_delay)
            );

            // Get proof of items below inactivity floor but after pruning boundary
            let proof_start = oldest_retained;
            let proof_end = std::cmp::min(inactivity_floor, oldest_retained + 10);
            let max_ops = proof_end - proof_start;

            let (original_proof, original_ops, original_chunks) = db
                .range_proof(hasher.inner(), proof_start, max_ops)
                .await
                .unwrap();

            // Verify the proof works
            assert!(CurrentTest::verify_range_proof(
                &mut hasher,
                &original_proof,
                proof_start,
                &original_ops,
                &original_chunks,
                &original_root
            ));

            // Close and reopen the database
            db.close().await.unwrap();
            let db = CurrentTest::init(context.clone(), db_config).await.unwrap();

            // Confirm root is identical after restart
            let reopened_root = db.root(&mut hasher).await.unwrap();
            assert_eq!(original_root, reopened_root);

            // Get proof of items below inactivity floor again
            let (reopened_proof, reopened_ops, reopened_chunks) = db
                .range_proof(hasher.inner(), proof_start, max_ops)
                .await
                .unwrap();

            // Verify the proof still works and is identical
            assert_eq!(original_proof.size, reopened_proof.size);
            assert_eq!(original_proof.digests, reopened_proof.digests);
            assert_eq!(original_ops, reopened_ops);
            assert_eq!(original_chunks, reopened_chunks);

            assert!(CurrentTest::verify_range_proof(
                &mut hasher,
                &reopened_proof,
                proof_start,
                &reopened_ops,
                &reopened_chunks,
                &reopened_root
            ));

            db.destroy().await.unwrap();
        });
    }

    /// Test that databases with different `pruning_delay` values generate the same root.
    #[test_traced("WARN")]
    pub fn test_current_db_different_pruning_delays_same_root() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut hasher = Standard::<Sha256>::new();

            // Create two databases with different pruning delays
            let mut db_config_no_delay = current_db_config("no_delay_test");
            db_config_no_delay.pruning_delay = 0;

            let mut db_config_max_delay = current_db_config("max_delay_test");
            db_config_max_delay.pruning_delay = u64::MAX;

            let mut db_no_delay = CurrentTest::init(context.clone(), db_config_no_delay.clone())
                .await
                .unwrap();
            let mut db_max_delay = CurrentTest::init(context.clone(), db_config_max_delay.clone())
                .await
                .unwrap();

            // Apply identical operations to both databases
            const NUM_OPERATIONS: u64 = 1000;
            for i in 0..NUM_OPERATIONS {
                let key = hash(&i.to_be_bytes());
                let value = hash(&(i * 1000).to_be_bytes());

                db_no_delay.update(key, value).await.unwrap();
                db_max_delay.update(key, value).await.unwrap();

                // Commit periodically
                if i % 50 == 49 {
                    db_no_delay.commit().await.unwrap();
                    db_max_delay.commit().await.unwrap();
                }
            }

            // Final commit
            db_no_delay.commit().await.unwrap();
            db_max_delay.commit().await.unwrap();
            let inactivity_floor = db_no_delay.any.inactivity_floor_loc;

            // Get roots from both databases
            let root_no_delay = db_no_delay.root(&mut hasher).await.unwrap();
            let root_max_delay = db_max_delay.root(&mut hasher).await.unwrap();

            // Verify they generate the same roots
            assert_eq!(root_no_delay, root_max_delay);

            // Verify different pruning behaviors
            let oldest_no_delay = db_no_delay.oldest_retained_loc().unwrap();
            let oldest_max_delay = db_max_delay.oldest_retained_loc().unwrap();

            // With pruning_delay=0, more operations should be pruned
            // With pruning_delay=u64::MAX, no operations should be pruned (oldest retained should be 0)
            assert_eq!(oldest_no_delay, inactivity_floor);
            assert_eq!(oldest_max_delay, 0);

            // Close both databases
            db_no_delay.close().await.unwrap();
            db_max_delay.close().await.unwrap();

            // Restart both databases
            let db_no_delay = CurrentTest::init(context.clone(), db_config_no_delay)
                .await
                .unwrap();
            let db_max_delay = CurrentTest::init(context.clone(), db_config_max_delay)
                .await
                .unwrap();

            // Get roots after restart
            let root_no_delay_restart = db_no_delay.root(&mut hasher).await.unwrap();
            let root_max_delay_restart = db_max_delay.root(&mut hasher).await.unwrap();

            // Ensure roots still match after restart
            assert_eq!(root_no_delay, root_no_delay_restart);
            assert_eq!(root_max_delay, root_max_delay_restart);

            // Verify pruning boundaries are still different
            let oldest_no_delay_restart = db_no_delay.oldest_retained_loc().unwrap();
            let oldest_max_delay_restart = db_max_delay.oldest_retained_loc().unwrap();

            assert_eq!(oldest_no_delay_restart, inactivity_floor);
            assert_eq!(oldest_max_delay_restart, 0);

            db_no_delay.destroy().await.unwrap();
            db_max_delay.destroy().await.unwrap();
        });
    }
}
