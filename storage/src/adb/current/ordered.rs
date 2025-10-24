//! An _ordered_ variant of a Current-type authenticated database which additionally maintains the
//! lexicographic-next active key of each active key, allowing for exclusion proofs.

use crate::{
    adb::{
        any::fixed::{init_mmr_and_log, ordered::Any, Config as AConfig},
        current::Config,
        operation::{FixedOrdered as Operation, OrderedKeyData},
        store::{self, Db},
        Error,
    },
    index::Ordered as Index,
    mmr::{
        bitmap::BitMap,
        grafting::{Hasher as GraftingHasher, Storage as GraftingStorage},
        hasher::Hasher,
        mem::Mmr as MemMmr,
        verification, Location, Position, Proof, StandardHasher as Standard,
    },
    translator::Translator,
};
use commonware_codec::{CodecFixed, FixedSize};
use commonware_cryptography::Hasher as CHasher;
use commonware_runtime::{Clock, Metrics, Storage as RStorage};
use commonware_utils::Array;
use futures::{future::try_join_all, try_join, TryFutureExt as _};
use std::num::NonZeroU64;
use tracing::info;

/// A key-value ADB based on an MMR over its log of operations, supporting key exclusion proofs and
/// authentication of whether a currently has a specific value.
///
/// Note: The generic parameter N is not really generic, and must be manually set to double the size
/// of the hash digest being produced by the hasher. A compile-time assertion is used to prevent any
/// other setting.
pub struct Current<
    E: RStorage + Clock + Metrics,
    K: Array,
    V: CodecFixed<Cfg = ()>,
    H: CHasher,
    T: Translator,
    const N: usize,
> {
    /// An [Any] authenticated database that provides the ability to prove whether a key ever had a
    /// specific value.
    any: Any<E, K, V, H, T>,

    /// The bitmap over the activity status of each operation. Supports augmenting [Any] proofs in
    /// order to further prove whether a key _currently_ has a specific value.
    status: BitMap<H, N>,

    /// The location of the last commit operation.
    last_commit_loc: Option<Location>,

    context: E,

    bitmap_metadata_partition: String,
}

/// The information required to verify a key value proof from a Current adb.
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct KeyValueProofInfo<K: Array, V: CodecFixed<Cfg = ()>, const N: usize> {
    /// The key whose value is being proven.
    pub key: K,

    /// The value of the key.
    pub value: V,

    /// The location of the operation that assigned this value to the key.
    pub loc: Location,

    /// The next key in the key space, for ordered keyspaces.
    pub next_key: K,

    /// The status bitmap chunk that contains the bit corresponding the operation's location.
    pub chunk: [u8; N],
}

// The information required to verify an exclusion proof.
#[derive(Clone, Eq, PartialEq, Debug)]
pub enum ExclusionProofInfo<K: Array, V: CodecFixed<Cfg = ()>, const N: usize> {
    /// For the KeyValue variant, we're proving that a span over the keyspace exists in the
    /// database, allowing one to prove any key falling within that span (but not at the beginning)
    /// is excluded.
    KeyValue(KeyValueProofInfo<K, V, N>),

    /// For the Commit variant, we're proving that there exists a Commit operation in the database
    /// that establishes an inactivity floor equal to its own location. This implies there are no
    /// active keys, and therefore any key can be proven excluded against it. The wrapped values
    /// consist of the location of the commit operation and its digest.
    Commit((Location, [u8; N])),

    /// The DbEmpty variant is similar to Commit, only specifically for the case where the DB is
    /// completely empty (having no operations at all against which to prove).
    DbEmpty,
}

impl<
        E: RStorage + Clock + Metrics,
        K: Array,
        V: CodecFixed<Cfg = ()>,
        H: CHasher,
        T: Translator,
        const N: usize,
    > Current<E, K, V, H, T, N>
{
    /// Initializes a [Current] authenticated database from the given `config`. Leverages parallel
    /// Merkleization to initialize the bitmap MMR if a thread pool is provided.
    pub async fn init(context: E, config: Config<T>) -> Result<Self, Error> {
        // TODO: Re-evaluate assertion placement after `generic_const_exprs` is stable.
        const {
            // A compile-time assertion that the chunk size is some multiple of digest size. A multiple of 1 is optimal
            // with respect to proof size, but a higher multiple allows for a smaller (RAM resident) merkle tree over
            // the structure.
            assert!(
                N.is_multiple_of(H::Digest::SIZE),
                "chunk size must be some multiple of the digest size",
            );
            // A compile-time assertion that chunk size is a power of 2, which is necessary to allow the status bitmap
            // tree to be aligned with the underlying operations MMR.
            assert!(N.is_power_of_two(), "chunk size must be a power of 2");
        }

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
        };

        let context = context.with_label("adb::current");
        let cloned_pool = cfg.thread_pool.clone();
        let mut status = BitMap::restore_pruned(
            context.with_label("bitmap"),
            &config.bitmap_metadata_partition,
            cloned_pool,
        )
        .await?;

        // Initialize the db's mmr/log.
        let mut hasher = Standard::<H>::new();
        let (inactivity_floor_loc, mmr, log) =
            init_mmr_and_log::<_, Operation<K, V>, _, _>(context.clone(), cfg, &mut hasher).await?;

        // Ensure consistency between the bitmap and the db.
        let mut grafter = GraftingHasher::new(&mut hasher, Self::grafting_height());
        if status.len() < inactivity_floor_loc {
            // Prepend the missing (inactive) bits needed to align the bitmap, which can only be
            // pruned to a chunk boundary.
            while status.len() < *inactivity_floor_loc {
                status.push(false);
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
        Any::<E, K, V, H, T>::build_snapshot_from_log(
            inactivity_floor_loc,
            &log,
            &mut snapshot,
            |append: bool, old_loc: Option<Location>| {
                if let Some(old_loc) = old_loc {
                    status.set_bit(old_loc.as_u64(), false);
                }
                status.push(append);
            },
        )
        .await
        .unwrap();
        grafter
            .load_grafted_digests(&status.dirty_chunks(), &mmr)
            .await?;
        status.sync(&mut grafter).await?;
        assert_eq!(status.len(), mmr.leaves());

        let any = Any {
            mmr,
            log,
            snapshot,
            inactivity_floor_loc,
            steps: 0,
            hasher: Standard::<H>::new(),
        };

        let last_commit_loc = status.len().checked_sub(1).map(Location::new_unchecked);
        assert!(
            last_commit_loc.is_none()
                || matches!(
                    any.log.read(*last_commit_loc.unwrap()).await?,
                    Operation::CommitFloor(_)
                )
        );

        Ok(Self {
            any,
            status,
            last_commit_loc,
            context,
            bitmap_metadata_partition: config.bitmap_metadata_partition,
        })
    }

    /// Get the number of operations that have been applied to this db, including those that are not
    /// yet committed.
    pub fn op_count(&self) -> Location {
        self.any.op_count()
    }

    /// Whether the db currently has no active keys.
    pub fn is_empty(&self) -> bool {
        self.any.is_empty()
    }

    /// Return the inactivity floor location. Locations prior to this point can be safely pruned.
    pub fn inactivity_floor_loc(&self) -> Location {
        self.any.inactivity_floor_loc()
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
        BitMap::<H, N>::CHUNK_SIZE_BITS.trailing_zeros()
    }

    /// Updates `key` to have value `value`. The operation is reflected in the snapshot, but will be
    /// subject to rollback until the next successful `commit`.
    pub async fn update(&mut self, key: K, value: V) -> Result<(), Error> {
        self.any
            .update_with_callback(key, value, |loc| {
                self.status.push(true);
                if let Some(loc) = loc {
                    self.status.set_bit(*loc, false);
                }
            })
            .await
    }

    /// Delete `key` and its value from the db. Deleting a key that already has no value is a no-op.
    /// The operation is reflected in the snapshot, but will be subject to rollback until the next
    /// successful `commit`.
    pub async fn delete(&mut self, key: K) -> Result<(), Error> {
        self.any
            .delete_with_callback(key, |append, loc| {
                if let Some(loc) = loc {
                    self.status.set_bit(*loc, false);
                }
                self.status.push(append);
            })
            .await
    }

    /// Commit pending operations to the adb::any ensuring their durability upon return from this
    /// function. Leverages parallel Merkleization of the any-db if a thread pool is provided.
    async fn commit_ops(&mut self) -> Result<(), Error> {
        // Inactivate the current commit operation.
        let bit_count = self.status.len();
        if let Some(last_commit_loc) = self.last_commit_loc {
            self.status.set_bit(*last_commit_loc, false);
        }

        // Raise the inactivity floor by taking `self.steps` steps.
        let steps_to_take = self.any.steps + 1; // account for the previous commit becoming inactive.
        for _ in 0..steps_to_take {
            if self.any.is_empty() {
                self.any.inactivity_floor_loc = Location::new_unchecked(bit_count);
                info!(tip = ?self.any.inactivity_floor_loc, "db is empty, raising floor to tip");
                break;
            }
            self.raise_floor().await?;
        }
        self.any.steps = 0;

        // Apply the commit operation with the new inactivity floor.
        self.any
            .apply_op(Operation::CommitFloor(self.any.inactivity_floor_loc))
            .await?;
        self.last_commit_loc = Some(Location::new_unchecked(self.status.len()));
        self.status.push(true); // Always treat most recent commit op as active.

        // Sync the log and process the updates to the MMR in parallel.
        let mmr_fut = async {
            self.any.mmr.process_updates(&mut self.any.hasher);
            Ok::<(), Error>(())
        };
        try_join!(self.any.log.sync().map_err(Error::Journal), mmr_fut)?;

        Ok(())
    }

    /// Raise the inactivity floor by taking one _step_, which involves searching for the first
    /// active operation above the inactivity floor, moving it to tip, and then setting the
    /// inactivity floor to the location following the moved operation. This method is therefore
    /// guaranteed to raise the floor by at least one.
    ///
    /// # Panics
    ///
    /// Panics if there is not at least one active operation above the inactivity floor.
    async fn raise_floor(&mut self) -> Result<(), Error> {
        // Use the status bitmap to find the first active operation above the inactivity floor.
        while !self.status.get_bit(*self.any.inactivity_floor_loc) {
            self.any.inactivity_floor_loc += 1;
        }

        // Move the active operation to tip.
        let op = self.any.log.read(*self.any.inactivity_floor_loc).await?;
        let old_loc = self
            .any
            .move_op_if_active(op, self.any.inactivity_floor_loc)
            .await?
            .expect("op should be active based on status bitmap");
        self.status.set_bit(*old_loc, false);
        self.status.push(true);

        // Advance inactivity floor above the moved operation since we know it's inactive.
        self.any.inactivity_floor_loc += 1;

        Ok(())
    }

    /// Commit any pending operations to the db, ensuring they are persisted to disk & recoverable
    /// upon return from this function. Also raises the inactivity floor according to the schedule.
    /// Leverages parallel Merkleization of the MMR structures if a thread pool is provided.
    pub async fn commit(&mut self) -> Result<(), Error> {
        // Failure recovery relies on this specific order of these three disk-based operations:
        //  (1) commit the any db to disk (which raises the inactivity floor).
        //  (2) prune the bitmap to the updated inactivity floor and write its state to disk.
        self.commit_ops().await?; // (1)

        let mut grafter = GraftingHasher::new(&mut self.any.hasher, Self::grafting_height());
        grafter
            .load_grafted_digests(&self.status.dirty_chunks(), &self.any.mmr)
            .await?;
        self.status.sync(&mut grafter).await?;

        self.status.prune_to_bit(*self.any.inactivity_floor_loc)?;

        // Write the pruned portion of the bitmap to disk, which is required for
        // recovery. Active part is not persisted but restored by reply on restart.
        self.status
            .write_pruned(
                self.context.with_label("bitmap"),
                &self.bitmap_metadata_partition,
            )
            .await?; // (2)

        Ok(())
    }

    /// Sync data to disk, ensuring clean recovery.
    pub async fn sync(&mut self) -> Result<(), Error> {
        self.any.sync().await
    }

    /// Prune all operations prior to `target_prune_loc` from the db.
    ///
    /// # Panic
    ///
    /// Panics if `target_prune_loc` is greater than the inactivity floor.
    pub async fn prune(&mut self, target_prune_loc: Location) -> Result<(), Error> {
        self.any.prune(target_prune_loc).await
    }

    /// Return the root of the db.
    ///
    /// # Errors
    ///
    /// Returns [Error::UncommittedOperations] if there are uncommitted operations.
    pub async fn root(&self, hasher: &mut Standard<H>) -> Result<H::Digest, Error> {
        if self.status.is_dirty() {
            return Err(Error::UncommittedOperations);
        }
        let ops = &self.any.mmr;
        let height = Self::grafting_height();
        let grafted_mmr = GraftingStorage::<'_, H, _, _>::new(&self.status, ops, height);
        let mmr_root = grafted_mmr.root(hasher).await?;

        // The digest contains all information from the base mmr, and all information from the peak
        // tree except for the partial chunk, if any.  If we are at a chunk boundary, then this is
        // all the information we need.
        let (last_chunk, next_bit) = self.status.last_chunk();
        if next_bit == 0 {
            return Ok(mmr_root);
        }

        // There are bits in an uncommitted (partial) chunk, so we need to incorporate that
        // information into the root digest. We do so by computing a root in the same format as an
        // unaligned [Bitmap] root, which involves additionally hashing in the number of bits within
        // the last chunk and the digest of the last chunk.
        hasher.inner().update(last_chunk);
        let last_chunk_digest = hasher.inner().finalize();

        Ok(BitMap::<H, N>::partial_chunk_root(
            hasher.inner(),
            &mmr_root,
            next_bit,
            &last_chunk_digest,
        ))
    }

    /// Returns a proof that the specified range of operations are part of the database, along with
    /// the operations from the range. A truncated range (from hitting the max) can be detected by
    /// looking at the length of the returned operations vector. Also returns the bitmap chunks
    /// required to verify the proof.
    ///
    /// # Errors
    ///
    /// Returns [crate::mmr::Error::LocationOverflow] if `start_loc` > [crate::mmr::MAX_LOCATION].
    /// Returns [crate::mmr::Error::RangeOutOfBounds] if `start_loc` >= number of leaves in the MMR.
    /// Returns [Error::UncommittedOperations] if there are uncommitted operations.
    pub async fn range_proof(
        &self,
        hasher: &mut H,
        start_loc: Location,
        max_ops: NonZeroU64,
    ) -> Result<(Proof<H::Digest>, Vec<Operation<K, V>>, Vec<[u8; N]>), Error> {
        if self.status.is_dirty() {
            return Err(Error::UncommittedOperations);
        };

        // Compute the start and end locations & positions of the range.
        let mmr = &self.any.mmr;
        let leaves = mmr.leaves();
        if start_loc >= leaves {
            return Err(crate::mmr::Error::RangeOutOfBounds(start_loc).into());
        }
        let max_loc = start_loc.saturating_add(max_ops.get());
        let end_loc = core::cmp::min(max_loc, leaves);

        // Generate the proof from the grafted MMR.
        let height = Self::grafting_height();
        let grafted_mmr = GraftingStorage::<'_, H, _, _>::new(&self.status, mmr, height);
        let mut proof = verification::range_proof(&grafted_mmr, start_loc..end_loc).await?;

        // Collect the operations necessary to verify the proof.
        let mut ops = Vec::with_capacity((*end_loc - *start_loc) as usize);
        let futures = (*start_loc..*end_loc)
            .map(|i| self.any.log.read(i))
            .collect::<Vec<_>>();
        try_join_all(futures)
            .await?
            .into_iter()
            .for_each(|op| ops.push(op));

        // Gather the chunks necessary to verify the proof.
        let chunk_bits = BitMap::<H, N>::CHUNK_SIZE_BITS;
        let start = *start_loc / chunk_bits; // chunk that contains the very first bit.
        let end = (*end_loc - 1) / chunk_bits; // chunk that contains the very last bit.
        let mut chunks = Vec::with_capacity((end - start + 1) as usize);
        for i in start..=end {
            let bit_offset = i * chunk_bits;
            let chunk = *self.status.get_chunk_containing(bit_offset);
            chunks.push(chunk);
        }

        let (last_chunk, next_bit) = self.status.last_chunk();
        if next_bit == 0 {
            return Ok((proof, ops, chunks));
        }

        hasher.update(last_chunk);
        proof.digests.push(hasher.finalize());

        Ok((proof, ops, chunks))
    }

    /// Return true if the given sequence of `ops` were applied starting at location `start_loc` in
    /// the log with the provided root.
    pub fn verify_range_proof(
        hasher: &mut Standard<H>,
        proof: &Proof<H::Digest>,
        start_loc: Location,
        ops: &[Operation<K, V>],
        chunks: &[[u8; N]],
        root: &H::Digest,
    ) -> bool {
        super::verify_range_proof(
            hasher,
            Self::grafting_height(),
            proof,
            start_loc,
            ops,
            chunks,
            root,
        )
    }

    /// Generate and return a proof of the current value of `key`, along with the other
    /// [KeyValueProofInfo] required to verify the proof. Returns KeyNotFound error if the key is
    /// not currently assigned any value.
    ///
    /// # Errors
    ///
    /// Returns [Error::UncommittedOperations] if there are uncommitted operations.
    /// Returns [Error::KeyNotFound] if the key is not currently assigned any value.
    pub async fn key_value_proof(
        &self,
        hasher: &mut H,
        key: K,
    ) -> Result<(Proof<H::Digest>, KeyValueProofInfo<K, V, N>), Error> {
        if self.status.is_dirty() {
            return Err(Error::UncommittedOperations);
        }
        let op = self.any.get_key_loc(&key).await?;
        let Some((value, next_key, loc)) = op else {
            return Err(Error::KeyNotFound);
        };
        let height = Self::grafting_height();
        let grafted_mmr = GraftingStorage::<'_, H, _, _>::new(&self.status, &self.any.mmr, height);

        let mut proof = verification::range_proof(&grafted_mmr, loc..loc + 1).await?;
        let chunk = *self.status.get_chunk_containing(*loc);

        let (last_chunk, next_bit) = self.status.last_chunk();
        if next_bit != 0 {
            hasher.update(last_chunk);
            proof.digests.push(hasher.finalize());
        }

        Ok((
            proof,
            KeyValueProofInfo {
                key,
                value,
                next_key,
                loc,
                chunk,
            },
        ))
    }

    /// Generate and return a proof that the specified `key` does not exist in the db, along with
    /// the other [KeyValueProofInfo] required to verify the proof.
    ///
    /// # Errors
    ///
    /// Returns [Error::KeyExists] if the key exists in the db.
    /// Returns [Error::UncommittedOperations] if there are uncommitted operations.
    pub async fn exclusion_proof(
        &self,
        hasher: &mut H,
        key: &K,
    ) -> Result<(Proof<H::Digest>, ExclusionProofInfo<K, V, N>), Error> {
        if self.status.is_dirty() {
            return Err(Error::UncommittedOperations);
        }
        if self.op_count() == 0 {
            return Ok((Proof::default(), ExclusionProofInfo::DbEmpty));
        }
        let height = Self::grafting_height();
        let grafted_mmr = GraftingStorage::<'_, H, _, _>::new(&self.status, &self.any.mmr, height);
        let (last_chunk, next_bit) = self.status.last_chunk();

        let span = self.any.get_span(key).await?;
        let (loc, proof_info) = match span {
            Some((loc, key_data)) => {
                if key_data.key == *key {
                    // Cannot prove exclusion of a key that exists in the db.
                    return Err(Error::KeyExists);
                }
                let chunk = *self.status.get_chunk_containing(*loc);
                (
                    loc,
                    ExclusionProofInfo::KeyValue(KeyValueProofInfo {
                        key: key_data.key,
                        value: key_data.value,
                        next_key: key_data.next_key,
                        loc,
                        chunk,
                    }),
                )
            }
            None => {
                let loc = self
                    .op_count()
                    .checked_sub(1)
                    .expect("db shouldn't be empty");
                let chunk = *self.status.get_chunk_containing(*loc);
                (loc, ExclusionProofInfo::Commit((loc, chunk)))
            }
        };

        let mut proof = verification::range_proof(&grafted_mmr, loc..loc + 1).await?;

        if next_bit != 0 {
            hasher.update(last_chunk);
            proof.digests.push(hasher.finalize());
        }

        Ok((proof, proof_info))
    }

    /// Return true if the proof authenticates that `key` currently has value `value` in the db with
    /// the provided `root`.
    pub fn verify_key_value_proof(
        hasher: &mut H,
        proof: &Proof<H::Digest>,
        info: KeyValueProofInfo<K, V, N>,
        root: &H::Digest,
    ) -> bool {
        let element = Operation::Update(OrderedKeyData {
            key: info.key,
            value: info.value,
            next_key: info.next_key,
        });

        super::verify_key_value_proof(
            hasher,
            Self::grafting_height(),
            proof,
            info.loc,
            &info.chunk,
            root,
            element,
        )
    }

    /// Get the operation that currently defines the span whose range contains `key`, or None if the
    /// DB is empty.
    pub async fn get_span(
        &self,
        key: &K,
    ) -> Result<Option<(Location, OrderedKeyData<K, V>)>, Error> {
        self.any.get_span(key).await
    }

    /// Return true if the proof authenticates that `key` does _not_ exist in the db with the
    /// provided `root`.
    pub fn verify_exclusion_proof(
        hasher: &mut H,
        proof: &Proof<H::Digest>,
        key: &K,
        info: ExclusionProofInfo<K, V, N>,
        root: &H::Digest,
    ) -> bool {
        let (loc, chunk, element) = match info {
            ExclusionProofInfo::KeyValue(info) => {
                if info.key == *key {
                    // The provided `key` is in the DB if it matches the start of the span.
                    return false;
                }
                if !Any::<E, K, V, H, T>::span_contains(&info.key, &info.next_key, key) {
                    return false;
                }

                let element = Operation::Update(OrderedKeyData {
                    key: info.key,
                    value: info.value,
                    next_key: info.next_key,
                });

                (info.loc, info.chunk, element)
            }
            ExclusionProofInfo::Commit((loc, chunk)) => {
                // Handle the case where the proof shows the db is empty, hence any key is proven
                // excluded.
                let op = Operation::<K, V>::CommitFloor(loc);
                (loc, chunk, op)
            }
            ExclusionProofInfo::DbEmpty => {
                // Handle the case where the proof shows the db has 0 operations, hence any key is
                // proven excluded.
                let empty_root = MemMmr::empty_mmr_root(hasher);
                return proof.size == Position::new(0) && *root == empty_root;
            }
        };

        super::verify_key_value_proof(
            hasher,
            Self::grafting_height(),
            proof,
            loc,
            &chunk,
            root,
            element,
        )
    }

    /// Close the db. Operations that have not been committed will be lost.
    pub async fn close(self) -> Result<(), Error> {
        self.any.close().await
    }

    /// Destroy the db, removing all data from disk.
    pub async fn destroy(self) -> Result<(), Error> {
        // Clean up bitmap metadata partition.
        BitMap::<H, N>::destroy(self.context, &self.bitmap_metadata_partition).await?;

        // Clean up Any components (MMR and log).
        self.any.destroy().await
    }

    #[cfg(test)]
    /// Generate an inclusion proof for any operation regardless of its activity state.
    async fn operation_inclusion_proof(
        &self,
        hasher: &mut H,
        loc: Location,
    ) -> Result<(Proof<H::Digest>, Operation<K, V>, Location, [u8; N]), Error> {
        let op = self.any.log.read(*loc).await?;

        let height = Self::grafting_height();
        let grafted_mmr = GraftingStorage::<'_, H, _, _>::new(&self.status, &self.any.mmr, height);

        let mut proof = verification::range_proof(&grafted_mmr, loc..loc + 1).await?;
        let chunk = *self.status.get_chunk_containing(*loc);

        let (last_chunk, next_bit) = self.status.last_chunk();
        if next_bit != 0 {
            hasher.update(last_chunk);
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

        let mut grafter = GraftingHasher::new(&mut self.any.hasher, Self::grafting_height());
        grafter
            .load_grafted_digests(&self.status.dirty_chunks(), &self.any.mmr)
            .await?;
        self.status.sync(&mut grafter).await?;
        let target_prune_loc = self.any.inactivity_floor_loc;
        self.status.prune_to_bit(*target_prune_loc)?;
        self.status
            .write_pruned(
                self.context.with_label("bitmap"),
                &self.bitmap_metadata_partition,
            )
            .await?; // (2)

        Ok(())
    }
}

impl<
        E: RStorage + Clock + Metrics,
        K: Array,
        V: CodecFixed<Cfg = ()>,
        H: CHasher,
        T: Translator,
        const N: usize,
    > Db<E, K, V, T> for Current<E, K, V, H, T, N>
{
    fn op_count(&self) -> Location {
        self.op_count()
    }

    fn inactivity_floor_loc(&self) -> Location {
        self.inactivity_floor_loc()
    }

    async fn get(&self, key: &K) -> Result<Option<V>, store::Error> {
        self.get(key).await.map_err(Into::into)
    }

    async fn update(&mut self, key: K, value: V) -> Result<(), store::Error> {
        self.update(key, value).await.map_err(Into::into)
    }

    async fn delete(&mut self, key: K) -> Result<(), store::Error> {
        self.delete(key).await.map(|_| ()).map_err(Into::into)
    }

    async fn commit(&mut self) -> Result<(), store::Error> {
        self.commit().await.map_err(Into::into)
    }

    async fn sync(&mut self) -> Result<(), store::Error> {
        self.sync().await.map_err(Into::into)
    }

    async fn prune(&mut self, target_prune_loc: Location) -> Result<(), store::Error> {
        self.prune(target_prune_loc).await.map_err(Into::into)
    }

    async fn close(self) -> Result<(), store::Error> {
        self.close().await.map_err(Into::into)
    }

    async fn destroy(self) -> Result<(), store::Error> {
        self.destroy().await.map_err(Into::into)
    }
}

#[cfg(test)]
pub mod test {
    use super::*;
    use crate::{adb::operation::FixedOperation, mmr::mem::Mmr, translator::OneCap};
    use commonware_cryptography::{sha256::Digest, Sha256};
    use commonware_macros::test_traced;
    use commonware_runtime::{buffer::PoolRef, deterministic, Runner as _};
    use commonware_utils::{NZUsize, NZU64};
    use rand::{rngs::StdRng, RngCore, SeedableRng};
    use tracing::warn;

    const PAGE_SIZE: usize = 88;
    const PAGE_CACHE_SIZE: usize = 8;

    fn current_db_config(partition_prefix: &str) -> Config<OneCap> {
        Config {
            mmr_journal_partition: format!("{partition_prefix}_journal_partition"),
            mmr_metadata_partition: format!("{partition_prefix}_metadata_partition"),
            mmr_items_per_blob: NZU64!(11),
            mmr_write_buffer: NZUsize!(1024),
            log_journal_partition: format!("{partition_prefix}_partition_prefix"),
            log_items_per_blob: NZU64!(7),
            log_write_buffer: NZUsize!(1024),
            bitmap_metadata_partition: format!("{partition_prefix}_bitmap_metadata_partition"),
            translator: OneCap,
            thread_pool: None,
            buffer_pool: PoolRef::new(NZUsize!(PAGE_SIZE), NZUsize!(PAGE_CACHE_SIZE)),
        }
    }

    /// A type alias for the concrete [Current] type used in these unit tests.
    type CurrentTest = Current<deterministic::Context, Digest, Digest, Sha256, OneCap, 32>;

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
            assert_eq!(db.inactivity_floor_loc(), Location::new_unchecked(0));
            let root0 = db.root(&mut hasher).await.unwrap();
            db.close().await.unwrap();
            db = open_db(context.clone(), partition).await;
            assert_eq!(db.op_count(), 0);
            assert_eq!(db.root(&mut hasher).await.unwrap(), root0);
            assert_eq!(root0, Mmr::empty_mmr_root(hasher.inner()));

            // Add one key.
            let k1 = Sha256::hash(&0u64.to_be_bytes());
            let v1 = Sha256::hash(&10u64.to_be_bytes());
            db.update(k1, v1).await.unwrap();
            assert_eq!(db.get(&k1).await.unwrap().unwrap(), v1);
            db.commit().await.unwrap();
            assert_eq!(db.op_count(), 3); // 1 update, 1 commit, 1 move.
            let root1 = db.root(&mut hasher).await.unwrap();
            assert!(root1 != root0);
            db.close().await.unwrap();
            db = open_db(context.clone(), partition).await;
            assert_eq!(db.op_count(), 3);
            assert_eq!(db.root(&mut hasher).await.unwrap(), root1);

            // Delete that one key.
            db.delete(k1).await.unwrap();
            db.commit().await.unwrap();
            assert_eq!(db.op_count(), 5); // 1 update, 2 commits, 1 move, 1 delete.
            assert_eq!(db.inactivity_floor_loc(), Location::new_unchecked(4));
            let root2 = db.root(&mut hasher).await.unwrap();
            db.close().await.unwrap();
            db = open_db(context.clone(), partition).await;
            assert_eq!(db.op_count(), 5);
            assert_eq!(db.inactivity_floor_loc(), Location::new_unchecked(4));
            assert_eq!(db.root(&mut hasher).await.unwrap(), root2);

            // Confirm all activity bits except the last are false.
            for i in 0..*db.op_count() - 1 {
                assert!(!db.status.get_bit(i));
            }
            assert!(db.status.get_bit(*db.op_count() - 1));

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

            let op = db.any.get_key_loc(&k).await.unwrap().unwrap();
            let proof = db
                .operation_inclusion_proof(hasher.inner(), op.2)
                .await
                .unwrap();
            let info = KeyValueProofInfo {
                key: k,
                value: v1,
                next_key: k,
                loc: op.2,
                chunk: proof.3,
            };
            let root = db.root(&mut hasher).await.unwrap();
            // Proof should be verifiable against current root.
            assert!(CurrentTest::verify_key_value_proof(
                hasher.inner(),
                &proof.0,
                info.clone(),
                &root,
            ));

            let v2 = Sha256::fill(0xA2);
            // Proof should not verify against a different value.
            let mut bad_info = info.clone();
            bad_info.value = v2;
            assert!(!CurrentTest::verify_key_value_proof(
                hasher.inner(),
                &proof.0,
                bad_info,
                &root,
            ));

            // Proof should not be verifiable if we fail to give verification the correct next key.
            let mut bad_info = info.clone();
            bad_info.next_key = Sha256::fill(0x02);
            assert!(!CurrentTest::verify_key_value_proof(
                hasher.inner(),
                &proof.0,
                bad_info,
                &root,
            ));

            // update the key to invalidate its previous update
            db.update(k, v2).await.unwrap();
            db.commit().await.unwrap();

            // Proof should not be verifiable against the new root.
            let root = db.root(&mut hasher).await.unwrap();
            assert!(!CurrentTest::verify_key_value_proof(
                hasher.inner(),
                &proof.0,
                info.clone(),
                &root,
            ));

            // Create a proof of the now-inactive operation.
            let proof_inactive = db
                .operation_inclusion_proof(hasher.inner(), op.2)
                .await
                .unwrap();
            // This proof should not verify, but only because verification will see that the
            // corresponding bit in the chunk is false.
            let proof_inactive_info = KeyValueProofInfo {
                key: k,
                value: v1,
                next_key: k,
                loc: proof_inactive.2,
                chunk: proof_inactive.3,
            };
            assert!(!CurrentTest::verify_key_value_proof(
                hasher.inner(),
                &proof_inactive.0,
                proof_inactive_info.clone(),
                &root,
            ));

            // Attempt #1 to "fool" the verifier:  change the location to that of an active
            // operation. This should not fool the verifier if we're properly validating the
            // inclusion of the operation itself, and not just the chunk.
            let (_, _, active_loc) = db.any.get_key_loc(&info.key).await.unwrap().unwrap();
            // The new location should differ but still be in the same chunk.
            assert_ne!(active_loc, info.loc);
            assert_eq!(
                BitMap::<Sha256, 32>::leaf_pos(*active_loc),
                BitMap::<Sha256, 32>::leaf_pos(*info.loc)
            );
            let mut info_with_modified_loc = info.clone();
            info_with_modified_loc.loc = active_loc;
            assert!(!CurrentTest::verify_key_value_proof(
                hasher.inner(),
                &proof_inactive.0,
                proof_inactive_info,
                &root,
            ));

            // Attempt #2 to "fool" the verifier: Modify the chunk in the proof info to make it look
            // like the operation is active by flipping its corresponding bit to 1. This should not
            // fool the verifier if we are correctly incorporating the partial chunk information
            // into the root computation.
            let mut modified_chunk = proof_inactive.3;
            let bit_pos = *proof_inactive.2;
            let byte_idx = bit_pos / 8;
            let bit_idx = bit_pos % 8;
            modified_chunk[byte_idx as usize] |= 1 << bit_idx;

            let mut info_with_modified_chunk = info.clone();
            info_with_modified_chunk.chunk = modified_chunk;
            assert!(!CurrentTest::verify_key_value_proof(
                hasher.inner(),
                &proof_inactive.0,
                info_with_modified_chunk,
                &root,
            ));

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
            let k = Sha256::hash(&i.to_be_bytes());
            let v = Sha256::hash(&rng.next_u32().to_be_bytes());
            db.update(k, v).await.unwrap();
        }

        // Randomly update / delete them. We use a delete frequency that is 1/7th of the update
        // frequency.
        for _ in 0u64..num_elements * 10 {
            let rand_key = Sha256::hash(&(rng.next_u64() % num_elements).to_be_bytes());
            if rng.next_u32() % 7 == 0 {
                db.delete(rand_key).await.unwrap();
                continue;
            }
            let v = Sha256::hash(&rng.next_u32().to_be_bytes());
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
            let start_loc = db.any.inactivity_floor_loc();

            for loc in *start_loc..*end_loc {
                let loc = Location::new_unchecked(loc);
                let (proof, ops, chunks) = db
                    .range_proof(hasher.inner(), loc, NZU64!(max_ops))
                    .await
                    .unwrap();
                assert!(
                    CurrentTest::verify_range_proof(&mut hasher, &proof, loc, &ops, &chunks, &root),
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

            let start = *db.inactivity_floor_loc();
            for i in start..db.status.len() {
                if !db.status.get_bit(i) {
                    continue;
                }
                // Found an active operation! Create a proof for its active current key/value if
                // it's a key-updating operation.
                let op = db.any.log.read(i).await.unwrap();
                let Some(key) = op.key() else {
                    // Must be the last commit operation which doesn't update a key.
                    continue;
                };
                let (proof, info) = db.key_value_proof(hasher.inner(), *key).await.unwrap();
                assert_eq!(info.value, *op.value().unwrap());
                // Proof should validate against the current value and correct root.
                assert!(CurrentTest::verify_key_value_proof(
                    hasher.inner(),
                    &proof,
                    info.clone(),
                    &root
                ));
                // Proof should fail against the wrong value.
                let wrong_val = Sha256::fill(0xFF);
                let mut bad_info = info.clone();
                bad_info.value = wrong_val;
                assert!(!CurrentTest::verify_key_value_proof(
                    hasher.inner(),
                    &proof,
                    bad_info.clone(),
                    &root
                ));
                // Proof should fail against the wrong key.
                let wrong_key = Sha256::fill(0xEE);
                let mut bad_info = info.clone();
                bad_info.key = wrong_key;
                assert!(!CurrentTest::verify_key_value_proof(
                    hasher.inner(),
                    &proof,
                    bad_info,
                    &root
                ));
                // Proof should fail against the wrong root.
                let wrong_root = Sha256::fill(0xDD);
                assert!(!CurrentTest::verify_key_value_proof(
                    hasher.inner(),
                    &proof,
                    info,
                    &wrong_root,
                ));
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
                next_key: k,
                loc: Location::new_unchecked(0),
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
                assert_eq!(info.next_key, k);
                assert!(
                    CurrentTest::verify_key_value_proof(
                        hasher.inner(),
                        &proof,
                        info.clone(),
                        &root
                    ),
                    "proof of update {i} failed to verify"
                );
                // Ensure the proof does NOT verify if we use the previous value.
                assert!(
                    !CurrentTest::verify_key_value_proof(hasher.inner(), &proof, old_info, &root),
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
            db.prune(committed_inactivity_floor).await.unwrap();

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
            db.prune(db.any.inactivity_floor_loc()).await.unwrap();
            // State from scenario #2 should match that of a successful commit.
            assert_eq!(db.root(&mut hasher).await.unwrap(), scenario_2_root);
            db.close().await.unwrap();

            // SCENARIO #3: Simulate a crash that happens after the any db has been committed and
            // the bitmap is written. Full state restoration should remain possible.
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
            // State should match that of the successful commit.
            assert_eq!(db.root(&mut hasher).await.unwrap(), scenario_2_root);

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("WARN")]
    pub fn test_current_db_different_pruning_delays_same_root() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut hasher = Standard::<Sha256>::new();

            // Create two databases that are identical other than how they are pruned.
            let db_config_no_pruning = current_db_config("no_pruning_test");

            let db_config_pruning = current_db_config("pruning_test");

            let mut db_no_pruning =
                CurrentTest::init(context.clone(), db_config_no_pruning.clone())
                    .await
                    .unwrap();
            let mut db_pruning = CurrentTest::init(context.clone(), db_config_pruning.clone())
                .await
                .unwrap();

            // Apply identical operations to both databases, but only prune one.
            const NUM_OPERATIONS: u64 = 1000;
            for i in 0..NUM_OPERATIONS {
                let key = Sha256::hash(&i.to_be_bytes());
                let value = Sha256::hash(&(i * 1000).to_be_bytes());

                db_no_pruning.update(key, value).await.unwrap();
                db_pruning.update(key, value).await.unwrap();

                // Commit periodically
                if i % 50 == 49 {
                    db_no_pruning.commit().await.unwrap();
                    db_pruning.commit().await.unwrap();
                    db_pruning
                        .prune(db_no_pruning.any.inactivity_floor_loc())
                        .await
                        .unwrap();
                }
            }

            // Final commit
            db_no_pruning.commit().await.unwrap();
            db_pruning.commit().await.unwrap();

            // Get roots from both databases
            let root_no_pruning = db_no_pruning.root(&mut hasher).await.unwrap();
            let root_pruning = db_pruning.root(&mut hasher).await.unwrap();

            // Verify they generate the same roots
            assert_eq!(root_no_pruning, root_pruning);

            // Close both databases
            db_no_pruning.close().await.unwrap();
            db_pruning.close().await.unwrap();

            // Restart both databases
            let db_no_pruning = CurrentTest::init(context.clone(), db_config_no_pruning)
                .await
                .unwrap();
            let db_pruning = CurrentTest::init(context.clone(), db_config_pruning)
                .await
                .unwrap();
            assert_eq!(
                db_no_pruning.inactivity_floor_loc(),
                db_pruning.inactivity_floor_loc()
            );

            // Get roots after restart
            let root_no_pruning_restart = db_no_pruning.root(&mut hasher).await.unwrap();
            let root_pruning_restart = db_pruning.root(&mut hasher).await.unwrap();

            // Ensure roots still match after restart
            assert_eq!(root_no_pruning, root_no_pruning_restart);
            assert_eq!(root_pruning, root_pruning_restart);

            db_no_pruning.destroy().await.unwrap();
            db_pruning.destroy().await.unwrap();
        });
    }

    /// Build a tiny database and confirm exclusion proofs work as expected.
    #[test_traced("DEBUG")]
    pub fn test_current_db_exclusion_proofs() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut hasher = Standard::<Sha256>::new();
            let partition = "exclusion_proofs";
            let mut db = open_db(context.clone(), partition).await;

            let key_exists_1 = Sha256::fill(0x10);

            // We should be able to prove exclusion for any key against an empty db.
            let empty_root = db.root(&mut hasher).await.unwrap();
            let (empty_proof, empty_info) = db
                .exclusion_proof(hasher.inner(), &key_exists_1)
                .await
                .unwrap();
            assert!(CurrentTest::verify_exclusion_proof(
                hasher.inner(),
                &empty_proof,
                &key_exists_1,
                empty_info.clone(),
                &empty_root,
            ));

            // Add `key_exists_1` and test exclusion proving over the single-key database case.
            let v1 = Sha256::fill(0xA1);
            db.update(key_exists_1, v1).await.unwrap();
            db.commit().await.unwrap();
            let root = db.root(&mut hasher).await.unwrap();

            // We shouldn't be able to generate an exclusion proof for a key already in the db.
            let result = db.exclusion_proof(hasher.inner(), &key_exists_1).await;
            assert!(matches!(result, Err(Error::KeyExists)));

            // Generate some valid exclusion proofs for keys on either side.
            let greater_key = Sha256::fill(0xFF);
            let lesser_key = Sha256::fill(0x00);
            let (proof, info) = db
                .exclusion_proof(hasher.inner(), &greater_key)
                .await
                .unwrap();
            let (proof2, info2) = db
                .exclusion_proof(hasher.inner(), &lesser_key)
                .await
                .unwrap();

            // Since there's only one span in the DB, the two exclusion proofs should be identical,
            // and the proof should verify any key but the one that exists in the db.
            assert_eq!(proof, proof2);
            assert_eq!(info, info2);
            // Any key except the one that exists should verify against this proof.
            assert!(CurrentTest::verify_exclusion_proof(
                hasher.inner(),
                &proof,
                &greater_key,
                info.clone(),
                &root,
            ));
            assert!(CurrentTest::verify_exclusion_proof(
                hasher.inner(),
                &proof,
                &lesser_key,
                info.clone(),
                &root,
            ));
            // Exclusion should fail if we test it on a key that exists.
            assert!(!CurrentTest::verify_exclusion_proof(
                hasher.inner(),
                &proof,
                &key_exists_1,
                info.clone(),
                &root,
            ));
            // Exclusion proof should fail if we blow away the next_key setting in proof info.
            let mut corrupt_info = info.clone();
            if let ExclusionProofInfo::KeyValue(ref mut kv_info) = corrupt_info {
                kv_info.next_key = Sha256::fill(0x02);
            }
            assert!(!CurrentTest::verify_exclusion_proof(
                hasher.inner(),
                &proof,
                &key_exists_1,
                corrupt_info,
                &root,
            ));

            // Add a second key and test exclusion proving over the two-key database case.
            let key_exists_2 = Sha256::fill(0x30);
            let v2 = Sha256::fill(0xB2);

            db.update(key_exists_2, v2).await.unwrap();
            db.commit().await.unwrap();
            let root = db.root(&mut hasher).await.unwrap();

            // Use a lesser/greater key that has a translated-key conflict based
            // on our use of OneCap translator.
            let lesser_key = Sha256::fill(0x0F); // < k1=0x10
            let greater_key = Sha256::fill(0x31); // > k2=0x30
            let middle_key = Sha256::fill(0x20); // between k1=0x10 and k2=0x30
            let (proof, info) = db
                .exclusion_proof(hasher.inner(), &greater_key)
                .await
                .unwrap();
            // Test the "cycle around" span. This should prove exclusion of greater_key & lesser
            // key, but fail on middle_key.
            assert!(CurrentTest::verify_exclusion_proof(
                hasher.inner(),
                &proof,
                &greater_key,
                info.clone(),
                &root,
            ));
            assert!(CurrentTest::verify_exclusion_proof(
                hasher.inner(),
                &proof,
                &lesser_key,
                info.clone(),
                &root,
            ));
            assert!(!CurrentTest::verify_exclusion_proof(
                hasher.inner(),
                &proof,
                &middle_key,
                info.clone(),
                &root,
            ));

            // Due to the cycle, lesser & greater keys should produce the same proof.
            let (new_proof, new_info) = db
                .exclusion_proof(hasher.inner(), &lesser_key)
                .await
                .unwrap();
            assert_eq!(proof, new_proof);
            assert_eq!(info, new_info);

            // Test the inner span [k, k2).
            let (proof, info) = db
                .exclusion_proof(hasher.inner(), &middle_key)
                .await
                .unwrap();
            // `k` should fail since it's in the db.
            assert!(!CurrentTest::verify_exclusion_proof(
                hasher.inner(),
                &proof,
                &key_exists_1,
                info.clone(),
                &root,
            ));
            // `middle_key` should succeed since it's in range.
            assert!(CurrentTest::verify_exclusion_proof(
                hasher.inner(),
                &proof,
                &middle_key,
                info.clone(),
                &root,
            ));
            // `k2` should fail since it's in the db and outside its range.
            let ExclusionProofInfo::KeyValue(ref kv_info) = info else {
                panic!("expected KeyValue variant");
            };
            assert_eq!(kv_info.next_key, key_exists_2);
            assert!(!CurrentTest::verify_exclusion_proof(
                hasher.inner(),
                &proof,
                &key_exists_2,
                info.clone(),
                &root,
            ));

            let conflicting_middle_key = Sha256::fill(0x11); // between k1=0x10 and k2=0x30
            assert!(CurrentTest::verify_exclusion_proof(
                hasher.inner(),
                &proof,
                &conflicting_middle_key,
                info.clone(),
                &root,
            ));

            // Using lesser/greater keys for the middle-proof should fail.
            assert!(!CurrentTest::verify_exclusion_proof(
                hasher.inner(),
                &proof,
                &greater_key,
                info.clone(),
                &root,
            ));
            assert!(!CurrentTest::verify_exclusion_proof(
                hasher.inner(),
                &proof,
                &lesser_key,
                info,
                &root,
            ));

            // Make the DB empty again by deleting the keys and check the empty case
            // again.
            db.delete(key_exists_1).await.unwrap();
            db.delete(key_exists_2).await.unwrap();
            db.sync().await.unwrap();
            db.commit().await.unwrap();
            let root = db.root(&mut hasher).await.unwrap();
            // This root should be different than the empty root from earlier since the DB now has a
            // non-zero number of operations.
            assert!(db.is_empty());
            assert_ne!(db.op_count(), 0);
            assert_ne!(root, empty_root);

            let (proof, info) = db
                .exclusion_proof(hasher.inner(), &key_exists_1)
                .await
                .unwrap();
            assert!(CurrentTest::verify_exclusion_proof(
                hasher.inner(),
                &proof,
                &key_exists_1,
                info.clone(),
                &root,
            ));
            assert!(CurrentTest::verify_exclusion_proof(
                hasher.inner(),
                &proof,
                &key_exists_2,
                info.clone(),
                &root,
            ));

            // Try fooling the verifier with improper values.
            assert!(!CurrentTest::verify_exclusion_proof(
                hasher.inner(),
                &empty_proof, // wrong proof
                &key_exists_1,
                info.clone(),
                &root,
            ));
            assert!(!CurrentTest::verify_exclusion_proof(
                hasher.inner(),
                &proof,
                &key_exists_1,
                info,
                &empty_root, // wrong root
            ));
            assert!(!CurrentTest::verify_exclusion_proof(
                hasher.inner(),
                &proof,
                &key_exists_1,
                empty_info, // wrong info
                &root,
            ));
        });
    }
}
