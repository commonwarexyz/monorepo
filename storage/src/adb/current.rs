//! An authenticated database (ADB) that provides succinct proofs of _any_ value ever associated
//! with a key, and also whether that value is the _current_ value associated with it. Its
//! implementation is based on an [Any] authenticated database combined with an authenticated
//! [Bitmap] over the activity status of each operation.

use crate::{
    adb::{
        any::{Any, Config as AConfig, UpdateResult},
        operation::Operation,
        Error,
    },
    index::{Index, Translator},
    mmr::{
        bitmap::Bitmap,
        hasher::{Grafting, Hasher, Standard},
        iterator::{leaf_num_to_pos, leaf_pos_to_num},
        journaled::Mmr,
        verification::Proof,
        Error::*,
    },
};
use commonware_codec::FixedSize;
use commonware_cryptography::Hasher as CHasher;
use commonware_runtime::{Clock, Metrics, Storage as RStorage};
use commonware_utils::Array;
use tracing::{debug, warn};

/// Configuration for a [Current] authenticated db.
#[derive(Clone)]
pub struct Config {
    /// The name of the [RStorage] partition used for the MMR's backing journal.
    pub mmr_journal_partition: String,

    /// The items per blob configuration value used by the MMR journal.
    pub mmr_items_per_blob: u64,

    /// The name of the [RStorage] partition used for the MMR's metadata.
    pub mmr_metadata_partition: String,

    /// The name of the [RStorage] partition used to persist the (pruned) log of operations.
    pub log_journal_partition: String,

    /// The items per blob configuration value used by the log journal.
    pub log_items_per_blob: u64,

    /// The name of the [RStorage] partition used for the bitmap metadata.
    pub bitmap_metadata_partition: String,
}

/// A hasher type used with the status bitmap of the [Current] database.
type Grafter<'a, E, H> = Grafting<'a, H, Mmr<E, H>>;

/// A proof of inclusion for a range of operations in the [Current] database.
pub struct RangeProof<H: CHasher> {
    /// The proof from the underlying [Any] db.
    any_proof: Proof<H>,

    /// The root digest of the status tree.
    status_root: H::Digest,
}

/// A proof of the active value for a key in the [Current] database.
pub struct CurrentValueProof<H: CHasher, const N: usize> {
    /// The inclusion proof of the activity bit for the operation.
    status_proof: Proof<H>,

    /// The bitmap chunk containing the activity status of the operation.
    status_chunk: [u8; N],

    /// The (partial, due to grafting) inclusion proof for the operation in the MMR.
    base_mmr_proof: Proof<H>,

    /// The location of the active operation for the key in the log.
    loc: u64,
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

impl<
        E: RStorage + Clock + Metrics,
        K: Array,
        V: Array,
        H: CHasher,
        T: Translator,
        const N: usize,
    > Current<E, K, V, H, T, N>
{
    // A compile-time assertion that the chunk size is the expected multiple of digest size.
    const _MULTIPLE: usize = 2; // 2 yields the smallest possible proof sizes
    const _CHUNK_SIZE_ASSERT: () = assert!(
        N == Self::_MULTIPLE * H::Digest::SIZE,
        "chunk size must be expected multiple of the digest size",
    );
    const _CHUNK_SIZE_IS_POW_OF_2_ASSERT_: () = assert!(
        N.is_power_of_two(),
        "chunk size must be a power of 2 to allow for grafting",
    );

    /// Initializes a [Current] authenticated database from the given `config`.
    pub async fn init(context: E, config: Config, translator: T) -> Result<Self, Error> {
        // Initialize the MMR journal and metadata.
        let cfg = AConfig {
            mmr_journal_partition: config.mmr_journal_partition,
            mmr_metadata_partition: config.mmr_metadata_partition,
            mmr_items_per_blob: config.mmr_items_per_blob,
            log_journal_partition: config.log_journal_partition,
            log_items_per_blob: config.log_items_per_blob,
        };

        let context = context.with_label("adb::current");
        let mut status = Bitmap::restore_pruned(
            context.with_label("bitmap"),
            &config.bitmap_metadata_partition,
        )
        .await?;

        // Initialize the db's mmr/log.
        let mut hasher = H::new();
        let (mut mmr, log) =
            Any::<_, _, _, _, T>::init_mmr_and_log(context.clone(), &mut hasher, cfg).await?;

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
        let mut grafter = Grafter::new(&mut hasher, Self::grafting_height(), &mmr);

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
                status.append(&mut grafter, false).await?;
            }
        }

        // Replay the log to generate the snapshot & populate the retained portion of the bitmap.
        let mut snapshot = Index::init(context.with_label("snapshot"), translator);
        let inactivity_floor_loc = Any::build_snapshot_from_log(
            start_leaf_num,
            &log,
            &mut snapshot,
            Some((&mut grafter, &mut status)),
        )
        .await
        .unwrap();
        assert!(
            pruned_bits <= inactivity_floor_loc,
            "bitmap is pruned beyond where bits should be retained"
        );

        if inactivity_floor_loc > start_leaf_num {
            // Advanced the pruning boundary if we failed to prune to the inactivity floor for any reason.
            warn!(
                inactivity_floor_loc,
                "pruning any db to the current inactivity floor"
            );
            mmr.prune_to_pos(leaf_num_to_pos(inactivity_floor_loc))
                .await?;
        }

        let any = Any {
            ops: mmr,
            log,
            snapshot,
            inactivity_floor_loc,
            uncommitted_ops: 0,
            hasher,
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
    pub async fn update(&mut self, key: K, value: V) -> Result<UpdateResult, Error> {
        let update_result = self.any.update(key, value).await?;
        let mut grafter =
            Grafter::new(&mut self.any.hasher, Self::grafting_height(), &self.any.ops);
        match update_result {
            UpdateResult::NoOp => return Ok(update_result),
            UpdateResult::Inserted(_) => (),
            UpdateResult::Updated(old_loc, _) => {
                self.status.set_bit(&mut grafter, old_loc, false).await?;
            }
        }
        self.status.append(&mut grafter, true).await?;

        Ok(update_result)
    }

    /// Delete `key` and its value from the db. Deleting a key that already has no value is a no-op.
    /// The operation is reflected in the snapshot, but will be subject to rollback until the next
    /// successful `commit`.
    pub async fn delete(&mut self, key: K) -> Result<(), Error> {
        let Some(old_loc) = self.any.delete(key).await? else {
            return Ok(());
        };

        let mut grafter =
            Grafter::new(&mut self.any.hasher, Self::grafting_height(), &self.any.ops);
        self.status.append(&mut grafter, false).await?;
        self.status.set_bit(&mut grafter, old_loc, false).await?;

        Ok(())
    }

    /// Commit pending operations to the adb::any and sync it to disk.
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
                let mut grafter =
                    Grafter::new(&mut self.any.hasher, Self::grafting_height(), &self.any.ops);
                self.status.set_bit(&mut grafter, old_loc, false).await?;
                self.status.append(&mut grafter, true).await?;
            }
            self.any.inactivity_floor_loc += 1;
        }

        self.any
            .apply_op(Operation::Commit(self.any.inactivity_floor_loc))
            .await?;
        let mut grafter =
            Grafter::new(&mut self.any.hasher, Self::grafting_height(), &self.any.ops);
        self.status.append(&mut grafter, false).await?;

        Ok(())
    }

    /// Commit any pending operations to the db, ensuring they are persisted to disk & recoverable
    /// upon return from this function. Also raises the inactivity floor according to the schedule,
    /// and prunes those operations below it.
    pub async fn commit(&mut self) -> Result<(), Error> {
        // Failure recovery relies on this specific order of these three disk-based operations:
        //  (1) commit/sync the any db to disk (which raises the inactivity floor).
        //  (2) prune the bitmap to the updated inactivity floor and write its state to disk.
        //  (3) prune the any db of inactive operations.
        self.commit_ops().await?; // (1)

        self.status.prune_to_bit(self.any.inactivity_floor_loc);
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
    /// The root is computed by hashing the bitmap's root with a a filtered root of the any db's
    /// operations MMR. (Because of grafting, we only require peaks from the operations MMR that
    /// fall below the grafting height.)
    pub async fn root(&self, hasher: &mut H) -> Result<H::Digest, Error> {
        let ops = &self.any.ops;

        let grafting_height = Self::grafting_height();
        let mut grafter = Grafter::new(hasher, grafting_height, ops);
        let any_root = ops.filtered_root(grafter.standard(), grafting_height - 1);
        let bitmap_root = self.status.root(&mut grafter).await?;

        hasher.update(&any_root);
        hasher.update(&bitmap_root);

        Ok(hasher.finalize())
    }

    /// Generate and return a proof of the current value of `key`, along with the current value
    /// itself. Returns KeyNotFound error if the key is not currently assigned any value.
    pub async fn current_value_proof(
        &self,
        hasher: &mut H,
        key: &K,
    ) -> Result<(CurrentValueProof<H, N>, V), Error> {
        let op = self.any.get_with_loc(key).await?;
        let Some(op) = op else {
            return Err(Error::KeyNotFound());
        };
        let pos = leaf_num_to_pos(op.1);
        let height = Self::grafting_height();
        let mut grafter = Grafter::new(hasher, height, &self.any.ops);
        let (proof, chunk) = self.status.proof(&mut grafter, pos).await?;

        let base_mmr_proof = self.any.ops.filtered_proof(pos, height).await?;

        Ok((
            CurrentValueProof {
                status_proof: proof,
                status_chunk: chunk,
                base_mmr_proof,
                loc: op.1,
            },
            op.0,
        ))
    }

    /// Return true if the given sequence of `ops` were applied starting at location `start_loc` in
    /// the log with the provided root.
    pub async fn verify_current_value_proof(
        hasher: &mut H,
        proof: &Proof<H>,
        start_loc: u64,
        ops: &[Operation<K, V>],
        root_digest: &H::Digest,
    ) -> Result<bool, Error> {
        // TODO
        Ok(true)
    }

    /// Close the db. Operations that have not been committed will be lost.
    pub async fn close(self) -> Result<(), Error> {
        self.any.close().await
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
    /// Simulate a crash that happens during commit after the bitmap has been pruned & written, but before the any db is pruned of inactive elements.
    async fn simulate_commit_failure_after_bitmap_written(mut self) -> Result<(), Error> {
        // Only successfully complete operations (1) and (2) of the commit process.
        self.commit_ops().await?; // (1)

        self.status.prune_to_bit(self.any.inactivity_floor_loc);
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
    use crate::index::translator::TwoCap;
    use commonware_cryptography::{hash, sha256::Digest, Sha256};
    use commonware_macros::test_traced;
    use commonware_runtime::{deterministic, Runner as _};
    use rand::{rngs::StdRng, RngCore, SeedableRng};

    fn current_db_config(partition_prefix: &str) -> Config {
        Config {
            mmr_journal_partition: format!("{}_journal_partition", partition_prefix),
            mmr_metadata_partition: format!("{}_metadata_partition", partition_prefix),
            mmr_items_per_blob: 11,
            log_journal_partition: format!("{}_partition_prefix", partition_prefix),
            log_items_per_blob: 7,
            bitmap_metadata_partition: format!("{}_bitmap_metadata_partition", partition_prefix),
        }
    }

    /// Return an [Current] database initialized with a fixed config.
    async fn open_db<E: RStorage + Clock + Metrics>(
        context: E,
        partition_prefix: &str,
    ) -> Current<E, Digest, Digest, Sha256, TwoCap, 64> {
        Current::<E, Digest, Digest, Sha256, TwoCap, 64>::init(
            context,
            current_db_config(partition_prefix),
            TwoCap,
        )
        .await
        .unwrap()
    }

    /// Build a small database, then close and reopen it and ensure state is preserved.
    #[test_traced("WARN")]
    pub fn test_current_db_build_small_close_reopen() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut hasher = Sha256::new();
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
                                          // repeated update should be no-op
            assert!(matches!(
                db.update(k1, v1).await.unwrap(),
                UpdateResult::NoOp
            ));
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
        });
    }

    /// Apply random operations to the given db, committing them (randomly & at the end) only if
    /// `commit_changes` is true.
    async fn apply_random_ops<E: RStorage + Clock + Metrics>(
        num_elements: u64,
        commit_changes: bool,
        rng_seed: u64,
        db: &mut Current<E, Digest, Digest, Sha256, TwoCap, 64>,
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

    /*   #[test_traced("WARN")]
    pub fn test_current_db_range_proofs() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            let partition = "range_proofs";
            let mut hasher = Sha256::new();
            let mut db = open_db(context.clone(), partition).await;
            apply_random_ops(100, true, context.next_u64(), &mut db)
                .await
                .unwrap();
            let root = db.root(&mut hasher).await.unwrap();

            // Make sure size-constrained batches of operations are provable from the oldest
            // retained op to tip.
            let max_ops = 4;
            let end_loc = db.op_count();
            let start_pos = db.any.ops.pruned_to_pos();
            let start_loc = leaf_pos_to_num(start_pos).unwrap();

            for i in start_loc..end_loc {
                let (proof, log) = db.range_proof(&mut hasher, i, max_ops).await.unwrap();
                assert!(
                    Current::<deterministic::Context, _, _, _, TwoCap, 64>::verify_range_proof(
                        &mut hasher,
                        &proof,
                        i,
                        &log,
                        &root
                    )
                    .await
                    .unwrap()
                );
            }
        });
    }*/

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
            let mut hasher = Sha256::new();
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
            let mut hasher = Sha256::new();
            let mut db = open_db(context.clone(), partition).await;
            apply_random_ops(ELEMENTS, true, rng_seed, &mut db)
                .await
                .unwrap();
            let committed_root = db.root(&mut hasher).await.unwrap();
            let committed_op_count = db.op_count();

            // Perform more random operations without committing any of them.
            apply_random_ops(ELEMENTS, false, rng_seed + 1, &mut db)
                .await
                .unwrap();
            let uncommitted_root = db.root(&mut hasher).await.unwrap();
            assert!(uncommitted_root != committed_root);

            // SCENARIO #1: Simulate a crash that happens before any writes. Upon reopening, the
            // state of the DB should be as of the last commit.
            db.simulate_commit_failure_before_any_writes();
            let mut db = open_db(context.clone(), partition).await;
            assert_eq!(db.root(&mut hasher).await.unwrap(), committed_root);
            assert_eq!(db.op_count(), committed_op_count);

            // Re-apply the exact same uncommitted operations.
            apply_random_ops(ELEMENTS, false, rng_seed + 1, &mut db)
                .await
                .unwrap();
            assert_eq!(db.root(&mut hasher).await.unwrap(), uncommitted_root);

            // SCENARIO #2: Simulate a crash that happens after the any db has been committed, but
            // before the state of the pruned bitmap can be written to disk.
            db.simulate_commit_failure_after_any_db_commit()
                .await
                .unwrap();

            // We should be able to recover, so the root should differ from the previous commit, and
            // the op count should be greater than before.
            let db = open_db(context.clone(), partition).await;
            let scenario_2_root = db.root(&mut hasher).await.unwrap();
            assert!(scenario_2_root != uncommitted_root);
            let scenario_2_pruning_loc = db.any.oldest_retained_loc().unwrap();

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
            assert_eq!(
                db.any.oldest_retained_loc().unwrap(),
                successful_pruning_loc
            );
        });
    }
}
