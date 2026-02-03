//! An _ordered_ variant of a [crate::qmdb::current] authenticated database optimized for fixed-size
//! values.
//!
//! This variant maintains the lexicographic-next active key for each active key, enabling exclusion
//! proofs (proving a key is currently inactive). Use [crate::qmdb::current::unordered::fixed] if
//! exclusion proofs are not needed.
//!
//! See [Db] for the main database type and [super::ExclusionProof] for proving key inactivity.

pub use super::db::KeyValueProof;
use crate::{
    bitmap::CleanBitMap,
    journal::contiguous::fixed::Journal,
    mmr::{Location, StandardHasher},
    qmdb::{
        any::{
            ordered::fixed::{Db as AnyDb, Operation},
            value::FixedEncoding,
            FixedValue,
        },
        current::{
            db::{merkleize_grafted_bitmap, root},
            FixedConfig as Config,
        },
        Durable, Error, Merkleized,
    },
    translator::Translator,
};
use commonware_codec::FixedSize;
use commonware_cryptography::Hasher;
use commonware_runtime::{Clock, Metrics, Storage as RStorage};
use commonware_utils::Array;

pub type Db<E, K, V, H, T, const N: usize, S = Merkleized<H>, D = Durable> =
    super::db::Db<E, Journal<E, Operation<K, V>>, K, FixedEncoding<V>, H, T, N, S, D>;

// Functionality for the Clean state - init only.
impl<
        E: RStorage + Clock + Metrics,
        K: Array,
        V: FixedValue,
        H: Hasher,
        T: Translator,
        const N: usize,
    > Db<E, K, V, H, T, N, Merkleized<H>, Durable>
{
    /// Initializes a [Db] from the given `config`. Leverages parallel Merkleization to initialize
    /// the bitmap MMR if a thread pool is provided.
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
            config.into(),
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

#[cfg(test)]
pub mod test {
    use super::*;
    use crate::{
        kv::tests::{assert_batchable, assert_deletable, assert_gettable, assert_send},
        mmr::hasher::Hasher as _,
        qmdb::{
            any::ordered::Update,
            current::{
                proof::{OperationProof, RangeProof},
                tests::{self, apply_random_ops},
            },
            store::{
                batch_tests,
                tests::{assert_log_store, assert_merkleized_store, assert_prunable_store},
                LogStore,
            },
            NonDurable, Unmerkleized,
        },
        translator::OneCap,
    };
    use commonware_cryptography::{sha256::Digest, Sha256};
    use commonware_macros::test_traced;
    use commonware_runtime::{buffer::paged::CacheRef, deterministic, Runner as _};
    use commonware_utils::{NZUsize, NZU16, NZU64};
    use rand::RngCore;
    use std::num::{NonZeroU16, NonZeroUsize};

    const PAGE_SIZE: NonZeroU16 = NZU16!(88);
    const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(8);

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
            page_cache: CacheRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
        }
    }

    /// A type alias for the concrete [Db] type used in these unit tests (Merkleized, Durable state).
    type CleanCurrentTest =
        Db<deterministic::Context, Digest, Digest, Sha256, OneCap, 32, Merkleized<Sha256>, Durable>;
    type MutableCurrentTest =
        Db<deterministic::Context, Digest, Digest, Sha256, OneCap, 32, Unmerkleized, NonDurable>;

    /// Return an [Db] database initialized with a fixed config.
    async fn open_db(
        context: deterministic::Context,
        partition_prefix: String,
    ) -> CleanCurrentTest {
        CleanCurrentTest::init(context, current_db_config(&partition_prefix))
            .await
            .unwrap()
    }

    #[test_traced("DEBUG")]
    pub fn test_current_db_build_small_close_reopen() {
        super::super::tests::test_build_small_close_reopen::<CleanCurrentTest, _, _>(open_db);
    }

    #[test_traced("WARN")]
    fn test_current_db_build_big() {
        // Expected values after commit + merkleize + prune for ordered variant.
        tests::test_current_db_build_big::<CleanCurrentTest, _, _>(open_db, 4241, 3383);
    }

    // Test that merkleization state changes don't reset `steps`.
    #[test_traced("DEBUG")]
    fn test_current_ordered_fixed_db_steps_not_reset() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let db = open_db(context, "steps_test".to_string()).await;
            crate::qmdb::any::test::test_any_db_steps_not_reset(db).await;
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
            let mut db = open_db(context, partition).await.into_mutable();

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
                &root,
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
            // Proof should not verify against a mangled next_key.
            let mut mangled_proof = proof.clone();
            mangled_proof.next_key = Sha256::fill(0xFF);
            assert!(!CleanCurrentTest::verify_key_value_proof(
                hasher.inner(),
                k,
                v1,
                &mangled_proof,
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
            let (p, _, chunks) = db
                .range_proof(hasher.inner(), op_loc, NZU64!(1))
                .await
                .unwrap();
            let proof_inactive = KeyValueProof {
                proof: OperationProof {
                    loc: op_loc,
                    chunk: chunks[0],
                    range_proof: p,
                },
                next_key: k,
            };
            // This proof should verify using verify_range_proof which does not check activity
            // status.
            let op = Operation::Update(Update {
                key: k,
                value: v1,
                next_key: k,
            });
            assert!(CleanCurrentTest::verify_range_proof(
                hasher.inner(),
                &proof_inactive.proof.range_proof,
                proof_inactive.proof.loc,
                &[op],
                &[proof_inactive.proof.chunk],
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
            assert_ne!(active_loc, proof_inactive.proof.loc);
            assert_eq!(
                CleanBitMap::<deterministic::Context, Digest, 32>::leaf_pos(*active_loc),
                CleanBitMap::<deterministic::Context, Digest, 32>::leaf_pos(
                    *proof_inactive.proof.loc
                )
            );
            let mut fake_proof = proof_inactive.clone();
            fake_proof.proof.loc = active_loc;
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
            let mut modified_chunk = proof_inactive.proof.chunk;
            let bit_pos = *proof_inactive.proof.loc;
            let byte_idx = bit_pos / 8;
            let bit_idx = bit_pos % 8;
            modified_chunk[byte_idx as usize] |= 1 << bit_idx;

            let mut fake_proof = proof_inactive.clone();
            fake_proof.proof.chunk = modified_chunk;
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
            let db = open_db(context.with_label("db"), partition).await;
            let root = db.root();

            // Empty range proof should not crash or verify, since even an empty db has a single
            // commit op.
            let proof = RangeProof {
                proof: crate::mmr::Proof::default(),
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

            let rng_seed = context.next_u64();
            let db = apply_random_ops::<CleanCurrentTest>(200, true, rng_seed, db.into_mutable())
                .await
                .unwrap();
            let (db, _) = db.commit(None).await.unwrap();
            let db = db.into_merkleized().await.unwrap();
            let root = db.root();

            // Make sure size-constrained batches of operations are provable from the oldest
            // retained op to tip.
            let max_ops = 4;
            let end_loc = db.size();
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
                let mut chunks_with_extra = chunks.to_vec();
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
                let op = db.any.log.read(Location::new_unchecked(i)).await.unwrap();
                let (key, value) = match op {
                    Operation::Update(key_data) => (key_data.key, key_data.value),
                    Operation::CommitFloor(_, _) => continue,
                    _ => unreachable!("expected update or commit floor operation"),
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
                // Proof should fail with the wrong next-key.
                let mut bad_proof = proof.clone();
                bad_proof.next_key = wrong_key;
                assert!(!CleanCurrentTest::verify_key_value_proof(
                    hasher.inner(),
                    key,
                    value,
                    &bad_proof,
                    &root,
                ));
            }

            db.destroy().await.unwrap();
        });
    }

    /// This test builds a random database, and makes sure that its state is correctly restored
    /// after closing and re-opening.
    #[test_traced("WARN")]
    pub fn test_current_db_build_random_close_reopen() {
        crate::qmdb::current::tests::test_build_random_close_reopen(open_db);
    }

    #[test_traced("WARN")]
    pub fn test_current_db_sync_persists_bitmap_pruning_boundary() {
        tests::test_sync_persists_bitmap_pruning_boundary::<CleanCurrentTest, _, _>(open_db);
    }

    /// Repeatedly update the same key to a new value and ensure we can prove its current value
    /// after each update.
    #[test_traced("WARN")]
    pub fn test_current_db_proving_repeated_updates() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut hasher = StandardHasher::<Sha256>::new();
            let partition = "build_small".to_string();
            let mut db = open_db(context, partition).await;

            // Add one key.
            let k = Sha256::fill(0x00);
            let mut old_val = Sha256::fill(0x00);
            for i in 1u8..=255 {
                let v = Sha256::fill(i);
                let mut dirty_db = db.into_mutable();
                dirty_db.update(k, v).await.unwrap();
                assert_eq!(dirty_db.get(&k).await.unwrap().unwrap(), v);
                let (dirty_db, _) = dirty_db.commit(None).await.unwrap();
                let clean_db = dirty_db.into_merkleized().await.unwrap();
                db = clean_db;
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
        crate::qmdb::current::tests::test_simulate_write_failures(open_db);
    }

    #[test_traced("WARN")]
    pub fn test_current_db_different_pruning_delays_same_root() {
        tests::test_different_pruning_delays_same_root::<CleanCurrentTest, _, _>(open_db);
    }

    /// Build a tiny database and confirm exclusion proofs work as expected.
    #[test_traced("DEBUG")]
    pub fn test_current_db_exclusion_proofs() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut hasher = StandardHasher::<Sha256>::new();
            let partition = "exclusion_proofs".to_string();
            let db = open_db(context, partition).await;

            let key_exists_1 = Sha256::fill(0x10);

            // We should be able to prove exclusion for any key against an empty db.
            let empty_root = db.root();
            let empty_proof = db
                .exclusion_proof(hasher.inner(), &key_exists_1)
                .await
                .unwrap();
            assert!(CleanCurrentTest::verify_exclusion_proof(
                hasher.inner(),
                &key_exists_1,
                &empty_proof,
                &empty_root,
            ));

            // Add `key_exists_1` and test exclusion proving over the single-key database case.
            let v1 = Sha256::fill(0xA1);
            let mut db = db.into_mutable();
            db.update(key_exists_1, v1).await.unwrap();
            let (db, _) = db.commit(None).await.unwrap();
            let db = db.into_merkleized().await.unwrap();
            let root = db.root();

            // We shouldn't be able to generate an exclusion proof for a key already in the db.
            let result = db.exclusion_proof(hasher.inner(), &key_exists_1).await;
            assert!(matches!(result, Err(Error::KeyExists)));

            // Generate some valid exclusion proofs for keys on either side.
            let greater_key = Sha256::fill(0xFF);
            let lesser_key = Sha256::fill(0x00);
            let proof = db
                .exclusion_proof(hasher.inner(), &greater_key)
                .await
                .unwrap();
            let proof2 = db
                .exclusion_proof(hasher.inner(), &lesser_key)
                .await
                .unwrap();

            // Since there's only one span in the DB, the two exclusion proofs should be identical,
            // and the proof should verify any key but the one that exists in the db.
            assert_eq!(proof, proof2);
            // Any key except the one that exists should verify against this proof.
            assert!(CleanCurrentTest::verify_exclusion_proof(
                hasher.inner(),
                &greater_key,
                &proof,
                &root,
            ));
            assert!(CleanCurrentTest::verify_exclusion_proof(
                hasher.inner(),
                &lesser_key,
                &proof,
                &root,
            ));
            // Exclusion should fail if we test it on a key that exists.
            assert!(!CleanCurrentTest::verify_exclusion_proof(
                hasher.inner(),
                &key_exists_1,
                &proof,
                &root,
            ));

            // Add a second key and test exclusion proving over the two-key database case.
            let key_exists_2 = Sha256::fill(0x30);
            let v2 = Sha256::fill(0xB2);

            let mut db = db.into_mutable();
            db.update(key_exists_2, v2).await.unwrap();
            let (db, _) = db.commit(None).await.unwrap();
            let db = db.into_merkleized().await.unwrap();
            let root = db.root();

            // Use a lesser/greater key that has a translated-key conflict based
            // on our use of OneCap translator.
            let lesser_key = Sha256::fill(0x0F); // < k1=0x10
            let greater_key = Sha256::fill(0x31); // > k2=0x30
            let middle_key = Sha256::fill(0x20); // between k1=0x10 and k2=0x30
            let proof = db
                .exclusion_proof(hasher.inner(), &greater_key)
                .await
                .unwrap();
            // Test the "cycle around" span. This should prove exclusion of greater_key & lesser
            // key, but fail on middle_key.
            assert!(CleanCurrentTest::verify_exclusion_proof(
                hasher.inner(),
                &greater_key,
                &proof,
                &root,
            ));
            assert!(CleanCurrentTest::verify_exclusion_proof(
                hasher.inner(),
                &lesser_key,
                &proof,
                &root,
            ));
            assert!(!CleanCurrentTest::verify_exclusion_proof(
                hasher.inner(),
                &middle_key,
                &proof,
                &root,
            ));

            // Due to the cycle, lesser & greater keys should produce the same proof.
            let new_proof = db
                .exclusion_proof(hasher.inner(), &lesser_key)
                .await
                .unwrap();
            assert_eq!(proof, new_proof);

            // Test the inner span [k, k2).
            let proof = db
                .exclusion_proof(hasher.inner(), &middle_key)
                .await
                .unwrap();
            // `k` should fail since it's in the db.
            assert!(!CleanCurrentTest::verify_exclusion_proof(
                hasher.inner(),
                &key_exists_1,
                &proof,
                &root,
            ));
            // `middle_key` should succeed since it's in range.
            assert!(CleanCurrentTest::verify_exclusion_proof(
                hasher.inner(),
                &middle_key,
                &proof,
                &root,
            ));
            assert!(!CleanCurrentTest::verify_exclusion_proof(
                hasher.inner(),
                &key_exists_2,
                &proof,
                &root,
            ));

            let conflicting_middle_key = Sha256::fill(0x11); // between k1=0x10 and k2=0x30
            assert!(CleanCurrentTest::verify_exclusion_proof(
                hasher.inner(),
                &conflicting_middle_key,
                &proof,
                &root,
            ));

            // Using lesser/greater keys for the middle-proof should fail.
            assert!(!CleanCurrentTest::verify_exclusion_proof(
                hasher.inner(),
                &greater_key,
                &proof,
                &root,
            ));
            assert!(!CleanCurrentTest::verify_exclusion_proof(
                hasher.inner(),
                &lesser_key,
                &proof,
                &root,
            ));

            // Make the DB empty again by deleting the keys and check the empty case
            // again.
            let mut db = db.into_mutable();
            db.delete(key_exists_1).await.unwrap();
            db.delete(key_exists_2).await.unwrap();
            let (db, _) = db.commit(None).await.unwrap();
            let mut db = db.into_merkleized().await.unwrap();
            db.sync().await.unwrap();
            let root = db.root();
            // This root should be different than the empty root from earlier since the DB now has a
            // non-zero number of operations.
            assert!(db.is_empty());
            assert_ne!(db.bounds().end, 0);
            assert_ne!(root, empty_root);

            let proof = db
                .exclusion_proof(hasher.inner(), &key_exists_1)
                .await
                .unwrap();
            assert!(CleanCurrentTest::verify_exclusion_proof(
                hasher.inner(),
                &key_exists_1,
                &proof,
                &root,
            ));
            assert!(CleanCurrentTest::verify_exclusion_proof(
                hasher.inner(),
                &key_exists_2,
                &proof,
                &root,
            ));

            // Try fooling the verifier with improper values.
            assert!(!CleanCurrentTest::verify_exclusion_proof(
                hasher.inner(),
                &key_exists_1,
                &empty_proof, // wrong proof
                &root,
            ));
            assert!(!CleanCurrentTest::verify_exclusion_proof(
                hasher.inner(),
                &key_exists_1,
                &proof,
                &empty_root, // wrong root
            ));
        });
    }

    #[test_traced("DEBUG")]
    fn test_batch() {
        batch_tests::test_batch(|mut ctx| async move {
            let seed = ctx.next_u64();
            let partition = format!("current_ordered_batch_{seed}");
            open_db(ctx, partition).await.into_mutable()
        });
    }

    #[allow(dead_code)]
    fn assert_merkleized_db_futures_are_send(
        db: &mut CleanCurrentTest,
        key: Digest,
        loc: Location,
    ) {
        assert_gettable(db, &key);
        assert_log_store(db);
        assert_prunable_store(db, loc);
        assert_merkleized_store(db, loc);
        assert_send(db.sync());
    }

    #[allow(dead_code)]
    fn assert_mutable_db_futures_are_send(db: &mut MutableCurrentTest, key: Digest, value: Digest) {
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
