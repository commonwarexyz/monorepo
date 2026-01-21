//! An _unordered_ variant of a [crate::qmdb::current] authenticated database optimized for
//! fixed-size values.
//!
//! This variant does not maintain key ordering, so it cannot generate exclusion proofs. Use
//! [super::super::ordered::fixed] if exclusion proofs are required.
//!
//! See [Db] for the main database type.

use crate::{
    bitmap::CleanBitMap,
    index::unordered::Index,
    journal::contiguous::fixed::Journal,
    kv::{self, Batchable},
    mmr::{Location, StandardHasher},
    qmdb::{
        any::{
            operation::update::Unordered as UnorderedUpdate,
            unordered::fixed::{Db as AnyDb, Operation, Update},
            FixedValue,
        },
        current::{
            self,
            db::{merkleize_grafted_bitmap, root},
            proof::OperationProof,
            FixedConfig as Config,
        },
        store::{self},
        DurabilityState, Durable, Error, MerkleizationState, Merkleized, NonDurable, Unmerkleized,
    },
    translator::Translator,
};
use commonware_codec::FixedSize;
use commonware_cryptography::{DigestOf, Hasher};
use commonware_runtime::{Clock, Metrics, Storage as RStorage};
use commonware_utils::Array;

/// Proof information for verifying a key has a particular value in the database.
pub type KeyValueProof<D, const N: usize> = OperationProof<D, N>;

/// A specialization of [current::db::Db] for unordered key spaces and fixed-size values.
pub type Db<E, K, V, H, T, const N: usize, S = Merkleized<H>, D = Durable> =
    current::db::Db<E, Journal<E, Operation<K, V>>, Index<T, Location>, H, Update<K, V>, N, S, D>;

// Functionality shared across all DB states, such as most non-mutating operations.
impl<
        E: RStorage + Clock + Metrics,
        K: Array,
        V: FixedValue,
        H: Hasher,
        T: Translator,
        const N: usize,
        M: MerkleizationState<DigestOf<H>>,
        D: DurabilityState,
    > Db<E, K, V, H, T, N, M, D>
{
    /// Get the value of `key` in the db, or None if it has no value.
    pub async fn get(&self, key: &K) -> Result<Option<V>, Error> {
        self.any.get(key).await
    }

    /// Return true if the proof authenticates that `key` currently has value `value` in the db with
    /// the provided `root`.
    pub fn verify_key_value_proof(
        hasher: &mut H,
        key: K,
        value: V,
        proof: &KeyValueProof<H::Digest, N>,
        root: &H::Digest,
    ) -> bool {
        let op = Operation::Update(UnorderedUpdate(key, value));

        proof.verify(hasher, Self::grafting_height(), op, root)
    }
}

// Functionality for the Clean state.
impl<
        E: RStorage + Clock + Metrics,
        K: Array,
        V: FixedValue,
        H: Hasher,
        T: Translator,
        const N: usize,
    > Db<E, K, V, H, T, N, Merkleized<H>, Durable>
{
    /// Initializes a [Db] authenticated database from the given `config`. Leverages parallel
    /// Merkleization to initialize the bitmap MMR if a thread pool is provided.
    pub async fn init(context: E, config: Config<T>) -> Result<Self, Error> {
        // TODO: Re-evaluate assertion placement after `generic_const_exprs` is stable.
        const {
            // A compile-time assertion that the chunk size is some multiple of digest size. A
            // multiple of 1 is optimal with respect to proof size, but a higher multiple allows for
            // a smaller (RAM resident) merkle tree over the structure.
            assert!(
                N.is_multiple_of(H::Digest::SIZE),
                "chunk size must be some multiple of the digest size",
            );
            // A compile-time assertion that chunk size is a power of 2, which is necessary to allow
            // the status bitmap tree to be aligned with the underlying operations MMR.
            assert!(N.is_power_of_two(), "chunk size must be a power of 2");
        }

        let thread_pool = config.thread_pool.clone();
        let bitmap_metadata_partition = config.bitmap_metadata_partition.clone();

        let mut hasher = StandardHasher::<H>::new();
        let mut status = CleanBitMap::init(
            context.with_label("bitmap"),
            &bitmap_metadata_partition,
            thread_pool,
            &mut hasher,
        )
        .await?
        .into_dirty();

        // Initialize the anydb with a callback that initializes the status bitmap.
        let last_known_inactivity_floor = Location::new_unchecked(status.len());
        let any = AnyDb::init_with_callback(
            context.with_label("any"),
            config.to_any_config(),
            Some(last_known_inactivity_floor),
            |append: bool, loc: Option<Location>| {
                status.push(append);
                if let Some(loc) = loc {
                    status.set_bit(*loc, false);
                }
            },
        )
        .await?;

        let status = merkleize_grafted_bitmap(&mut hasher, status, &any.log.mmr).await?;

        // Compute and cache the root
        let cached_root = Some(root(&mut hasher, &status, &any.log.mmr).await?);

        Ok(Self {
            any,
            status,
            cached_root,
        })
    }
}

// Functionality for any Merkleized state (both Durable and NonDurable).
impl<
        E: RStorage + Clock + Metrics,
        K: Array,
        V: FixedValue,
        H: Hasher,
        T: Translator,
        const N: usize,
        D: store::State,
    > Db<E, K, V, H, T, N, Merkleized<H>, D>
{
    /// Generate and return a proof of the current value of `key`, along with the other
    /// [KeyValueProof] required to verify the proof. Returns KeyNotFound error if the key is not
    /// currently assigned any value.
    ///
    /// # Errors
    ///
    /// Returns [Error::KeyNotFound] if the key is not currently assigned any value.
    pub async fn key_value_proof(
        &self,
        hasher: &mut H,
        key: K,
    ) -> Result<KeyValueProof<H::Digest, N>, Error> {
        let op_loc = self.any.get_with_loc(&key).await?;
        let Some((_, loc)) = op_loc else {
            return Err(Error::KeyNotFound);
        };
        let height = Self::grafting_height();
        let mmr = &self.any.log.mmr;

        OperationProof::<H::Digest, N>::new(hasher, &self.status, height, mmr, loc).await
    }
}

// Functionality for the Mutable state.
impl<
        E: RStorage + Clock + Metrics,
        K: Array,
        V: FixedValue,
        H: Hasher,
        T: Translator,
        const N: usize,
    > Db<E, K, V, H, T, N, Unmerkleized, NonDurable>
{
    /// Updates `key` to have value `value`. The operation is reflected in the snapshot, but will be
    /// subject to rollback until the next successful `commit`.
    pub async fn update(&mut self, key: K, value: V) -> Result<(), Error> {
        if let Some(old_loc) = self.any.update_key(key, value).await? {
            self.status.set_bit(*old_loc, false);
        }
        self.status.push(true);

        Ok(())
    }

    /// Creates a new key-value pair in the db. The operation is reflected in the snapshot, but will
    /// be subject to rollback until the next successful `commit`. Returns true if the key was
    /// created, false if it already existed.
    pub async fn create(&mut self, key: K, value: V) -> Result<bool, Error> {
        if !self.any.create(key, value).await? {
            return Ok(false);
        }
        self.status.push(true);

        Ok(true)
    }

    /// Delete `key` and its value from the db. Deleting a key that already has no value is a no-op.
    /// The operation is reflected in the snapshot, but will be subject to rollback until the next
    /// successful `commit`. Returns true if the key was deleted, false if it was already inactive.
    pub async fn delete(&mut self, key: K) -> Result<bool, Error> {
        let Some(loc) = self.any.delete_key(key).await? else {
            return Ok(false);
        };

        self.status.push(false);
        self.status.set_bit(*loc, false);

        Ok(true)
    }
}

// Store implementation for all states
impl<
        E: RStorage + Clock + Metrics,
        K: Array,
        V: FixedValue,
        H: Hasher,
        T: Translator,
        const N: usize,
        M: MerkleizationState<DigestOf<H>>,
        D: DurabilityState,
    > kv::Gettable for Db<E, K, V, H, T, N, M, D>
{
    type Key = K;
    type Value = V;
    type Error = Error;

    async fn get(&self, key: &Self::Key) -> Result<Option<Self::Value>, Self::Error> {
        self.get(key).await
    }
}

// StoreMut for (Unmerkleized,NonDurable) (aka mutable) state
impl<
        E: RStorage + Clock + Metrics,
        K: Array,
        V: FixedValue,
        H: Hasher,
        T: Translator,
        const N: usize,
    > kv::Updatable for Db<E, K, V, H, T, N, Unmerkleized, NonDurable>
{
    async fn update(&mut self, key: Self::Key, value: Self::Value) -> Result<(), Self::Error> {
        self.update(key, value).await
    }
}

// StoreDeletable for (Unmerkleized,NonDurable) (aka mutable) state
impl<
        E: RStorage + Clock + Metrics,
        K: Array,
        V: FixedValue,
        H: Hasher,
        T: Translator,
        const N: usize,
    > kv::Deletable for Db<E, K, V, H, T, N, Unmerkleized, NonDurable>
{
    async fn delete(&mut self, key: Self::Key) -> Result<bool, Self::Error> {
        self.delete(key).await
    }
}

// Batchable for (Unmerkleized,NonDurable) (aka mutable) state
impl<E, K, V, T, H, const N: usize> Batchable for Db<E, K, V, H, T, N, Unmerkleized, NonDurable>
where
    E: RStorage + Clock + Metrics,
    K: Array,
    V: FixedValue,
    T: Translator,
    H: Hasher,
{
    async fn write_batch<'a, Iter>(&'a mut self, iter: Iter) -> Result<(), Error>
    where
        Iter: Iterator<Item = (K, Option<V>)> + Send + 'a,
    {
        let status = &mut self.status;
        self.any
            .write_batch_with_callback(iter, move |append: bool, loc: Option<Location>| {
                status.push(append);
                if let Some(loc) = loc {
                    status.set_bit(*loc, false);
                }
            })
            .await
    }
}

#[cfg(test)]
pub mod test {
    use super::*;
    use crate::{
        index::Unordered as _,
        kv::tests::{assert_batchable, assert_deletable, assert_gettable, assert_send},
        mmr::{hasher::Hasher as _, Location, Proof},
        qmdb::{
            any,
            current::{proof::RangeProof, tests::apply_random_ops},
            store::{
                batch_tests,
                tests::{assert_log_store, assert_merkleized_store, assert_prunable_store},
            },
        },
        translator::TwoCap,
    };
    use commonware_cryptography::{sha256::Digest, Sha256};
    use commonware_macros::test_traced;
    use commonware_runtime::{buffer::PoolRef, deterministic, Runner as _};
    use commonware_utils::{NZUsize, NZU16, NZU64};
    use rand::RngCore;
    use std::{
        collections::HashMap,
        num::{NonZeroU16, NonZeroUsize},
    };
    use tracing::warn;

    const PAGE_SIZE: NonZeroU16 = NZU16!(88);
    const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(8);

    fn current_db_config(partition_prefix: &str) -> Config<TwoCap> {
        Config {
            mmr_journal_partition: format!("{partition_prefix}_journal_partition"),
            mmr_metadata_partition: format!("{partition_prefix}_metadata_partition"),
            mmr_items_per_blob: NZU64!(11),
            mmr_write_buffer: NZUsize!(1024),
            log_journal_partition: format!("{partition_prefix}_partition_prefix"),
            log_items_per_blob: NZU64!(7),
            log_write_buffer: NZUsize!(1024),
            bitmap_metadata_partition: format!("{partition_prefix}_bitmap_metadata_partition"),
            translator: TwoCap,
            thread_pool: None,
            buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
        }
    }

    /// A type alias for the concrete clean [Db] type used in these unit tests.
    type CleanCurrentTest = Db<deterministic::Context, Digest, Digest, Sha256, TwoCap, 32>;

    /// A type alias for the concrete mutable [Db] type used in these unit tests.
    type MutableCurrentTest =
        Db<deterministic::Context, Digest, Digest, Sha256, TwoCap, 32, Unmerkleized, NonDurable>;

    /// Return an [Db] database initialized with a fixed config.
    async fn open_db(
        context: deterministic::Context,
        partition_prefix: String,
    ) -> CleanCurrentTest {
        CleanCurrentTest::init(context, current_db_config(&partition_prefix))
            .await
            .unwrap()
    }

    /// Build a small database, then close and reopen it and ensure state is preserved.
    #[test_traced("DEBUG")]
    pub fn test_current_db_build_small_close_reopen() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let partition = "build_small".to_string();
            let db = open_db(context.with_label("first"), partition.clone()).await;
            assert_eq!(db.op_count(), 1);
            assert_eq!(db.inactivity_floor_loc(), Location::new_unchecked(0));
            assert_eq!(db.oldest_retained_loc(), Location::new_unchecked(0));
            let root0 = db.root();
            drop(db);
            let db = open_db(context.with_label("second"), partition.clone()).await;
            assert_eq!(db.op_count(), 1);
            assert!(db.get_metadata().await.unwrap().is_none());
            assert_eq!(db.root(), root0);

            // Add one key.
            let mut db = db.into_mutable();
            let k1 = Sha256::hash(&0u64.to_be_bytes());
            let v1 = Sha256::hash(&10u64.to_be_bytes());
            assert!(db.create(k1, v1).await.unwrap());
            assert_eq!(db.get(&k1).await.unwrap().unwrap(), v1);
            let (db, range) = db.commit(None).await.unwrap();
            let db = db.into_merkleized().await.unwrap();
            assert_eq!(*range.start, 1);
            assert_eq!(*range.end, 4);
            assert!(db.get_metadata().await.unwrap().is_none());
            assert_eq!(db.op_count(), 4); // 1 update, 1 commit, 1 move + 1 initial commit.
            let root1 = db.root();
            assert!(root1 != root0);
            drop(db);
            let db = open_db(context.with_label("third"), partition.clone()).await;
            assert_eq!(db.op_count(), 4); // 1 update, 1 commit, 1 moves + 1 initial commit.
            assert!(db.get_metadata().await.unwrap().is_none());
            assert_eq!(db.root(), root1);

            // Create of same key should fail.
            let mut db = db.into_mutable();
            assert!(!db.create(k1, v1).await.unwrap());

            // Delete that one key.
            assert!(db.delete(k1).await.unwrap());
            let metadata = Sha256::hash(&1u64.to_be_bytes());
            let (db, range) = db.commit(Some(metadata)).await.unwrap();
            let db = db.into_merkleized().await.unwrap();
            assert_eq!(*range.start, 4);
            assert_eq!(*range.end, 6);
            assert_eq!(db.op_count(), 6); // 1 update, 2 commits, 1 move, 1 delete.
            assert_eq!(db.get_metadata().await.unwrap().unwrap(), metadata);
            let root2 = db.root();

            // Repeated delete of same key should fail.
            let mut db = db.into_mutable();
            assert!(!db.delete(k1).await.unwrap());
            let (db, _) = db.commit(None).await.unwrap();
            let mut db = db.into_merkleized().await.unwrap();
            db.sync().await.unwrap();
            // Commit adds a commit even for no-op, so op_count increases and root changes.
            assert_eq!(db.op_count(), 7);
            let root3 = db.root();
            assert!(root3 != root2);

            // Confirm re-open preserves state.
            drop(db);
            let db = open_db(context.with_label("fourth"), partition.clone()).await;
            assert_eq!(db.op_count(), 7);
            // Last commit had no metadata (passed None to commit).
            assert!(db.get_metadata().await.unwrap().is_none());
            assert_eq!(db.root(), root3);

            // Confirm all activity bits are false except for the last commit.
            for i in 0..*db.op_count() - 1 {
                assert!(!db.status.get_bit(i));
            }
            assert!(db.status.get_bit(*db.op_count() - 1));

            // Test that we can get a non-durable root.
            let mut db = db.into_mutable();
            db.update(k1, v1).await.unwrap();
            let db = db.into_merkleized().await.unwrap();
            assert_ne!(db.root(), root3);

            let (db, _) = db.into_mutable().commit(None).await.unwrap();
            db.into_merkleized().await.unwrap().destroy().await.unwrap();
        });
    }

    #[test_traced("WARN")]
    fn test_current_db_build_big() {
        let executor = deterministic::Runner::default();
        // Build a db with 1000 keys, some of which we update and some of which we delete, and
        // confirm that the end state of the db matches that of an identically updated hashmap.
        const ELEMENTS: u64 = 1000;
        executor.start(|context| async move {
            let mut db = open_db(context.with_label("first"), "build_big".to_string())
                .await
                .into_mutable();

            let mut map = HashMap::<Digest, Digest>::default();
            for i in 0u64..ELEMENTS {
                let k = Sha256::hash(&i.to_be_bytes());
                let v = Sha256::hash(&(i * 1000).to_be_bytes());
                db.update(k, v).await.unwrap();
                map.insert(k, v);
            }

            // Update every 3rd key
            for i in 0u64..ELEMENTS {
                if i % 3 != 0 {
                    continue;
                }
                let k = Sha256::hash(&i.to_be_bytes());
                let v = Sha256::hash(&((i + 1) * 10000).to_be_bytes());
                db.update(k, v).await.unwrap();
                map.insert(k, v);
            }

            // Delete every 7th key
            for i in 0u64..ELEMENTS {
                if i % 7 != 1 {
                    continue;
                }
                let k = Sha256::hash(&i.to_be_bytes());
                db.delete(k).await.unwrap();
                map.remove(&k);
            }

            assert_eq!(db.op_count(), 1478);
            assert_eq!(db.inactivity_floor_loc(), Location::new_unchecked(0));
            assert_eq!(db.op_count(), 1478);
            assert_eq!(db.any.snapshot.items(), 857);

            // Test that commit + sync w/ pruning will raise the activity floor.
            let (db, _) = db.commit(None).await.unwrap();
            let mut db = db.into_merkleized().await.unwrap();
            db.sync().await.unwrap();
            db.prune(db.inactivity_floor_loc()).await.unwrap();
            assert_eq!(db.op_count(), 1957);
            assert_eq!(db.inactivity_floor_loc(), Location::new_unchecked(838));
            assert_eq!(db.any.snapshot.items(), 857);

            // Drop & reopen the db, making sure it has exactly the same state.
            let root = db.root();
            db.sync().await.unwrap();
            drop(db);
            let db = open_db(context.with_label("second"), "build_big".to_string()).await;
            assert_eq!(root, db.root());
            assert_eq!(db.op_count(), 1957);
            assert_eq!(db.inactivity_floor_loc(), Location::new_unchecked(838));
            assert_eq!(db.any.snapshot.items(), 857);

            // Confirm the db's state matches that of the separate map we computed independently.
            for i in 0u64..1000 {
                let k = Sha256::hash(&i.to_be_bytes());
                if let Some(map_value) = map.get(&k) {
                    let Some(db_value) = db.get(&k).await.unwrap() else {
                        panic!("key not found in db: {k}");
                    };
                    assert_eq!(*map_value, db_value);
                } else {
                    assert!(db.get(&k).await.unwrap().is_none());
                }
            }
        });
    }

    // Test that merkleization state changes don't reset `steps`.
    #[test_traced("DEBUG")]
    fn test_current_unordered_fixed_db_steps_not_reset() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let db = open_db(context, "steps_test".to_string()).await;
            any::test::test_any_db_steps_not_reset(db).await;
        });
    }

    /// Build a tiny database and make sure we can't convince the verifier that some old value of a
    /// key is active. We specifically test over the partial chunk case, since these bits are yet to
    /// be committed to the underlying MMR.
    #[test_traced("DEBUG")]
    pub fn test_current_db_verify_proof_over_bits_in_uncommitted_chunk() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut hasher = StandardHasher::<Sha256>::new();
            let partition = "build_small".to_string();
            let mut db = open_db(context.with_label("db"), partition.clone())
                .await
                .into_mutable();

            // Add one key.
            let k = Sha256::fill(0x01);
            let v1 = Sha256::fill(0xA1);
            db.update(k, v1).await.unwrap();
            let (db, _) = db.commit(None).await.unwrap();
            let db = db.into_merkleized().await.unwrap();

            let (_, op_loc) = db.any.get_with_loc(&k).await.unwrap().unwrap();
            let proof = db.key_value_proof(hasher.inner(), k).await.unwrap();

            // Proof should be verifiable against current root.
            let root = db.root();
            assert!(CleanCurrentTest::verify_key_value_proof(
                hasher.inner(),
                k,
                v1,
                &proof,
                &root
            ));

            let v2 = Sha256::fill(0xA2);
            // Proof should not verify against a different value.
            assert!(!CleanCurrentTest::verify_key_value_proof(
                hasher.inner(),
                k,
                v2,
                &proof,
                &root,
            ));

            // Update the key to a new value (v2), which inactivates the previous operation.
            let mut db = db.into_mutable();
            db.update(k, v2).await.unwrap();
            let (db, _) = db.commit(None).await.unwrap();
            let db = db.into_merkleized().await.unwrap();
            let root = db.root();

            // New value should not be verifiable against the old proof.
            assert!(!CleanCurrentTest::verify_key_value_proof(
                hasher.inner(),
                k,
                v2,
                &proof,
                &root,
            ));

            // But the new value should verify against a new proof.
            let proof = db.key_value_proof(hasher.inner(), k).await.unwrap();
            assert!(CleanCurrentTest::verify_key_value_proof(
                hasher.inner(),
                k,
                v2,
                &proof,
                &root,
            ));

            // Old value will not verify against new proof.
            assert!(!CleanCurrentTest::verify_key_value_proof(
                hasher.inner(),
                k,
                v1,
                &proof,
                &root,
            ));

            // Create a proof of the now-inactive update operation assigining v1 to k against the
            // current root.
            let (range_proof, _, chunks) = db
                .range_proof(hasher.inner(), op_loc, NZU64!(1))
                .await
                .unwrap();
            let proof_inactive = KeyValueProof {
                loc: op_loc,
                chunk: chunks[0],
                range_proof,
            };
            // This proof should verify using verify_range_proof which does not check activity
            // status.
            let op = Operation::Update(UnorderedUpdate(k, v1));
            assert!(CleanCurrentTest::verify_range_proof(
                hasher.inner(),
                &proof_inactive.range_proof,
                proof_inactive.loc,
                &[op],
                &[proof_inactive.chunk],
                &root,
            ));

            // But this proof should *not* verify as a key value proof, since verification will see
            // that the operation is inactive.
            assert!(!CleanCurrentTest::verify_key_value_proof(
                hasher.inner(),
                k,
                v1,
                &proof_inactive,
                &root,
            ));

            // Attempt #1 to "fool" the verifier:  change the location to that of an active
            // operation. This should not fool the verifier if we're properly validating the
            // inclusion of the operation itself, and not just the chunk.
            let (_, active_loc) = db.any.get_with_loc(&k).await.unwrap().unwrap();
            // The new location should differ but still be in the same chunk.
            assert_ne!(active_loc, proof_inactive.loc);
            assert_eq!(
                CleanBitMap::<deterministic::Context, Digest, 32>::leaf_pos(*active_loc),
                CleanBitMap::<deterministic::Context, Digest, 32>::leaf_pos(*proof_inactive.loc)
            );
            let mut fake_proof = proof_inactive.clone();
            fake_proof.loc = active_loc;
            assert!(!CleanCurrentTest::verify_key_value_proof(
                hasher.inner(),
                k,
                v1,
                &fake_proof,
                &root,
            ));

            // Attempt #2 to "fool" the verifier: Modify the chunk in the proof info to make it look
            // like the operation is active by flipping its corresponding bit to 1. This should not
            // fool the verifier if we are correctly incorporating the partial chunk information
            // into the root computation.
            let mut modified_chunk = proof_inactive.chunk;
            let bit_pos = *proof_inactive.loc;
            let byte_idx = bit_pos / 8;
            let bit_idx = bit_pos % 8;
            modified_chunk[byte_idx as usize] |= 1 << bit_idx;

            let mut fake_proof = proof_inactive.clone();
            fake_proof.chunk = modified_chunk;
            assert!(!CleanCurrentTest::verify_key_value_proof(
                hasher.inner(),
                k,
                v1,
                &fake_proof,
                &root,
            ));

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("DEBUG")]
    pub fn test_current_db_range_proofs() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            let partition = "range_proofs".to_string();
            let mut hasher = StandardHasher::<Sha256>::new();
            let db = open_db(context.with_label("db"), partition.clone()).await;
            let root = db.root();

            // Empty range proof should not crash or verify, since even an empty db has a single
            // commit op.
            let proof = RangeProof {
                proof: Proof::default(),
                partial_chunk_digest: None,
            };
            assert!(!CleanCurrentTest::verify_range_proof(
                hasher.inner(),
                &proof,
                Location::new_unchecked(0),
                &[],
                &[],
                &root,
            ));

            let db = apply_random_ops::<CleanCurrentTest>(
                200,
                true,
                context.next_u64(),
                db.into_mutable(),
            )
            .await
            .unwrap();
            let (db, _) = db.commit(None).await.unwrap();
            let db = db.into_merkleized().await.unwrap();
            let root = db.root();

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
                    CleanCurrentTest::verify_range_proof(
                        hasher.inner(),
                        &proof,
                        loc,
                        &ops,
                        &chunks,
                        &root
                    ),
                    "failed to verify range at start_loc {start_loc}",
                );
                // Proof should not verify if we include extra chunks.
                let mut chunks_with_extra = chunks.clone();
                chunks_with_extra.push(chunks[chunks.len() - 1]);
                assert!(!CleanCurrentTest::verify_range_proof(
                    hasher.inner(),
                    &proof,
                    loc,
                    &ops,
                    &chunks_with_extra,
                    &root,
                ));
            }

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("DEBUG")]
    pub fn test_current_db_key_value_proof() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            let partition = "range_proofs".to_string();
            let mut hasher = StandardHasher::<Sha256>::new();
            let db = open_db(context.with_label("db"), partition.clone())
                .await
                .into_mutable();
            let db = apply_random_ops::<CleanCurrentTest>(500, true, context.next_u64(), db)
                .await
                .unwrap();
            let (db, _) = db.commit(None).await.unwrap();
            let db = db.into_merkleized().await.unwrap();
            let root = db.root();

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
                let (key, value) = match db.any.log.read(Location::new_unchecked(i)).await.unwrap()
                {
                    Operation::Update(UnorderedUpdate(key, value)) => (key, value),
                    Operation::CommitFloor(_, _) => continue,
                    Operation::Delete(_) => {
                        unreachable!("location does not reference update/commit operation")
                    }
                };

                let proof = db.key_value_proof(hasher.inner(), key).await.unwrap();
                // Proof should validate against the current value and correct root.
                assert!(CleanCurrentTest::verify_key_value_proof(
                    hasher.inner(),
                    key,
                    value,
                    &proof,
                    &root
                ));
                // Proof should fail against the wrong value. Use hash instead of fill to ensure
                // the value differs from any key/value created by TestKey::from_seed (which uses
                // fill patterns).
                let wrong_val = Sha256::hash(&[0xFF]);
                assert!(!CleanCurrentTest::verify_key_value_proof(
                    hasher.inner(),
                    key,
                    wrong_val,
                    &proof,
                    &root
                ));
                // Proof should fail against the wrong key.
                let wrong_key = Sha256::hash(&[0xEE]);
                assert!(!CleanCurrentTest::verify_key_value_proof(
                    hasher.inner(),
                    wrong_key,
                    value,
                    &proof,
                    &root
                ));
                // Proof should fail against the wrong root.
                let wrong_root = Sha256::hash(&[0xDD]);
                assert!(!CleanCurrentTest::verify_key_value_proof(
                    hasher.inner(),
                    key,
                    value,
                    &proof,
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
        current::tests::test_build_random_close_reopen(open_db);
    }

    /// Test that sync() persists the bitmap pruning boundary.
    ///
    /// This test verifies that calling `sync()` persists the bitmap pruning boundary that was
    /// set during `into_merkleized()`. If `sync()` didn't call `write_pruned`, the
    /// `bitmap_pruned_bits()` count would be 0 after reopen instead of the expected value.
    #[test_traced("WARN")]
    pub fn test_current_db_sync_persists_bitmap_pruning_boundary() {
        const ELEMENTS: u64 = 500;

        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            let partition = "sync_bitmap_pruning".to_string();
            let rng_seed = context.next_u64();
            let db = open_db(context.with_label("first"), partition.clone()).await;

            // Apply random operations with commits to advance the inactivity floor.
            let db = apply_random_ops::<CleanCurrentTest>(ELEMENTS, true, rng_seed, db.into_mutable())
                .await
                .unwrap();
            let (db, _) = db.commit(None).await.unwrap();
            let mut db = db.into_merkleized().await.unwrap();

            // The bitmap should have been pruned during into_merkleized().
            let pruned_bits_before = db.bitmap_pruned_bits();
            warn!(
                "pruned_bits_before={}, inactivity_floor={}, op_count={}",
                pruned_bits_before,
                *db.inactivity_floor_loc(),
                *db.op_count()
            );

            // Verify we actually have some pruning (otherwise the test is meaningless).
            assert!(
                pruned_bits_before > 0,
                "Expected bitmap to have pruned bits after merkleization"
            );

            // Call sync() WITHOUT calling prune(). The bitmap pruning boundary was set
            // during into_merkleized(), and sync() should persist it.
            db.sync().await.unwrap();

            // Record the root before dropping.
            let root_before = db.root();
            drop(db);

            // Reopen the database.
            let db = open_db(context.with_label("second"), partition).await;

            // The pruned bits count should match. If sync() didn't persist the bitmap pruned
            // state, this would be 0.
            let pruned_bits_after = db.bitmap_pruned_bits();
            warn!("pruned_bits_after={}", pruned_bits_after);

            assert_eq!(
                pruned_bits_after, pruned_bits_before,
                "Bitmap pruned bits mismatch after reopen - sync() may not have called write_pruned()"
            );

            // Also verify the root matches.
            assert_eq!(db.root(), root_before);

            db.destroy().await.unwrap();
        });
    }

    /// Repeatedly update the same key to a new value and ensure we can prove its current value
    /// after each update.
    #[test_traced("WARN")]
    pub fn test_current_db_proving_repeated_updates() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut hasher = StandardHasher::<Sha256>::new();
            let partition = "build_small".to_string();
            let mut db = open_db(context.with_label("db"), partition.clone()).await;

            // Add one key.
            let k = Sha256::fill(0x00);
            let mut old_val = Sha256::fill(0x00);
            for i in 1u8..=255 {
                let v = Sha256::fill(i);
                let mut dirty_db = db.into_mutable();
                dirty_db.update(k, v).await.unwrap();
                assert_eq!(dirty_db.get(&k).await.unwrap().unwrap(), v);
                let (durable_db, _) = dirty_db.commit(None).await.unwrap();
                db = durable_db.into_merkleized().await.unwrap();
                let root = db.root();

                // Create a proof for the current value of k.
                let proof = db.key_value_proof(hasher.inner(), k).await.unwrap();
                assert!(
                    CleanCurrentTest::verify_key_value_proof(hasher.inner(), k, v, &proof, &root),
                    "proof of update {i} failed to verify"
                );
                // Ensure the proof does NOT verify if we use the previous value.
                assert!(
                    !CleanCurrentTest::verify_key_value_proof(
                        hasher.inner(),
                        k,
                        old_val,
                        &proof,
                        &root
                    ),
                    "proof of update {i} verified when it should not have"
                );
                old_val = v;
            }

            db.destroy().await.unwrap();
        });
    }

    /// This test builds a random database and simulates we can recover from different types of
    /// failure scenarios.
    #[test_traced("WARN")]
    pub fn test_current_db_simulate_write_failures() {
        current::tests::test_simulate_write_failures(open_db);
    }

    #[test_traced("WARN")]
    pub fn test_current_db_different_pruning_delays_same_root() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Create two databases that are identical other than how they are pruned.
            let db_config_no_pruning = current_db_config("no_pruning_test");

            let db_config_pruning = current_db_config("pruning_test");

            let mut db_no_pruning = CleanCurrentTest::init(
                context.with_label("no_pruning"),
                db_config_no_pruning.clone(),
            )
            .await
            .unwrap()
            .into_mutable();
            let mut db_pruning =
                CleanCurrentTest::init(context.with_label("pruning"), db_config_pruning.clone())
                    .await
                    .unwrap()
                    .into_mutable();

            // Apply identical operations to both databases, but only prune one.
            const NUM_OPERATIONS: u64 = 1000;
            for i in 0..NUM_OPERATIONS {
                let key = Sha256::hash(&i.to_be_bytes());
                let value = Sha256::hash(&(i * 1000).to_be_bytes());

                db_no_pruning.update(key, value).await.unwrap();
                db_pruning.update(key, value).await.unwrap();

                // Commit periodically
                if i % 50 == 49 {
                    let (db_1, _) = db_no_pruning.commit(None).await.unwrap();
                    let clean_no_pruning = db_1.into_merkleized().await.unwrap();
                    let (db_2, _) = db_pruning.commit(None).await.unwrap();
                    let mut clean_pruning = db_2.into_merkleized().await.unwrap();
                    clean_pruning
                        .prune(clean_no_pruning.any.inactivity_floor_loc())
                        .await
                        .unwrap();
                    db_no_pruning = clean_no_pruning.into_mutable();
                    db_pruning = clean_pruning.into_mutable();
                }
            }

            // Final commit
            let (db_1, _) = db_no_pruning.commit(None).await.unwrap();
            let db_no_pruning = db_1.into_merkleized().await.unwrap();
            let (db_2, _) = db_pruning.commit(None).await.unwrap();
            let db_pruning = db_2.into_merkleized().await.unwrap();

            // Get roots from both databases
            let root_no_pruning = db_no_pruning.root();
            let root_pruning = db_pruning.root();

            // Verify they generate the same roots
            assert_eq!(root_no_pruning, root_pruning);

            drop(db_no_pruning);
            drop(db_pruning);

            // Restart both databases
            let db_no_pruning = CleanCurrentTest::init(
                context.with_label("no_pruning_restart"),
                db_config_no_pruning,
            )
            .await
            .unwrap();
            let db_pruning =
                CleanCurrentTest::init(context.with_label("pruning_restart"), db_config_pruning)
                    .await
                    .unwrap();
            assert_eq!(
                db_no_pruning.inactivity_floor_loc(),
                db_pruning.inactivity_floor_loc()
            );

            // Get roots after restart
            let root_no_pruning_restart = db_no_pruning.root();
            let root_pruning_restart = db_pruning.root();

            // Ensure roots still match after restart
            assert_eq!(root_no_pruning, root_no_pruning_restart);
            assert_eq!(root_pruning, root_pruning_restart);

            db_no_pruning.destroy().await.unwrap();
            db_pruning.destroy().await.unwrap();
        });
    }

    #[test_traced("DEBUG")]
    fn test_batch() {
        batch_tests::test_batch(|mut ctx| async move {
            let seed = ctx.next_u64();
            let prefix = format!("current_unordered_batch_{seed}");
            open_db(ctx, prefix).await.into_mutable()
        });
    }

    #[allow(dead_code)]
    fn assert_clean_db_futures_are_send(db: &mut CleanCurrentTest, key: Digest, loc: Location) {
        assert_gettable(db, &key);
        assert_log_store(db);
        assert_prunable_store(db, loc);
        assert_merkleized_store(db, loc);
        assert_send(db.sync());
    }

    #[allow(dead_code)]
    fn assert_dirty_db_futures_are_send(db: &mut MutableCurrentTest, key: Digest, value: Digest) {
        assert_gettable(db, &key);
        assert_log_store(db);
        assert_send(db.update(key, value));
        assert_send(db.create(key, value));
        assert_deletable(db, key);
        assert_batchable(db, key, value);
    }

    #[allow(dead_code)]
    fn assert_mutable_db_commit_is_send(db: MutableCurrentTest) {
        assert_send(db.commit(None));
    }
}
