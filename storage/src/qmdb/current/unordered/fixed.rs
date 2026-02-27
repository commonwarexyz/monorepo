//! An _unordered_ variant of a [crate::qmdb::current] authenticated database optimized for
//! fixed-size values.
//!
//! This variant does not maintain key ordering, so it cannot generate exclusion proofs. Use
//! [crate::qmdb::current::ordered::fixed] if exclusion proofs are required.
//!
//! See [Db] for the main database type.

pub use super::db::KeyValueProof;
use crate::{
    index::unordered::Index,
    journal::contiguous::fixed::Journal,
    mmr::Location,
    qmdb::{
        any::{unordered::fixed::Operation, value::FixedEncoding, FixedValue},
        current::FixedConfig as Config,
        Error,
    },
    translator::Translator,
};
use commonware_cryptography::Hasher;
use commonware_runtime::{Clock, Metrics, Storage as RStorage};
use commonware_utils::Array;

/// A specialization of [super::db::Db] for unordered key spaces and fixed-size values.
pub type Db<E, K, V, H, T, const N: usize> =
    super::db::Db<E, Journal<E, Operation<K, V>>, K, FixedEncoding<V>, Index<T, Location>, H, N>;

impl<
        E: RStorage + Clock + Metrics,
        K: Array,
        V: FixedValue,
        H: Hasher,
        T: Translator,
        const N: usize,
    > Db<E, K, V, H, T, N>
{
    /// Initializes a [Db] authenticated database from the given `config`. Leverages parallel
    /// Merkleization to initialize the bitmap MMR if a thread pool is provided.
    pub async fn init(context: E, config: Config<T>) -> Result<Self, Error> {
        crate::qmdb::current::init_fixed(context, config, |ctx, t| Index::new(ctx, t)).await
    }
}

pub mod partitioned {
    //! A partitioned variant of [super] that uses a partitioned index for the snapshot.
    //!
    //! See [crate::qmdb::any::unordered::fixed::partitioned] for details on partitioned indices and
    //! when to use them.

    pub use super::KeyValueProof;
    use crate::{
        index::partitioned::unordered::Index,
        journal::contiguous::fixed::Journal,
        mmr::Location,
        qmdb::{
            any::{unordered::fixed::partitioned::Operation, value::FixedEncoding, FixedValue},
            current::FixedConfig as Config,
            Error,
        },
        translator::Translator,
    };
    use commonware_cryptography::Hasher;
    use commonware_runtime::{Clock, Metrics, Storage as RStorage};
    use commonware_utils::Array;

    /// A partitioned variant of [super::Db].
    ///
    /// The const generic `P` specifies the number of prefix bytes used for partitioning:
    /// - `P = 1`: 256 partitions
    /// - `P = 2`: 65,536 partitions
    /// - `P = 3`: ~16 million partitions
    pub type Db<E, K, V, H, T, const P: usize, const N: usize> =
        crate::qmdb::current::unordered::db::Db<
            E,
            Journal<E, Operation<K, V>>,
            K,
            FixedEncoding<V>,
            Index<T, Location, P>,
            H,
            N,
        >;

    impl<
            E: RStorage + Clock + Metrics,
            K: Array,
            V: FixedValue,
            H: Hasher,
            T: Translator,
            const P: usize,
            const N: usize,
        > Db<E, K, V, H, T, P, N>
    {
        /// Initializes a [Db] authenticated database from the given `config`. Leverages parallel
        /// Merkleization to initialize the bitmap MMR if a thread pool is provided.
        pub async fn init(context: E, config: Config<T>) -> Result<Self, Error> {
            crate::qmdb::current::init_fixed(context, config, |ctx, t| Index::new(ctx, t)).await
        }
    }
}

#[cfg(test)]
pub mod test {
    use super::*;
    use crate::{
        kv::tests::{assert_batchable, assert_gettable, assert_send},
        mmr::{hasher::Hasher as _, Proof, StandardHasher},
        qmdb::{
            any::operation::update::Unordered as UnorderedUpdate,
            current::{
                proof::RangeProof,
                tests::{apply_random_ops, fixed_config},
            },
            store::{
                batch_tests,
                tests::{assert_log_store, assert_merkleized_store, assert_prunable_store},
                LogStore as _,
            },
        },
        translator::TwoCap,
    };
    use commonware_cryptography::{sha256::Digest, Digest as _, Sha256};
    use commonware_macros::test_traced;
    use commonware_runtime::{deterministic, Runner as _};
    use commonware_utils::{bitmap::Prunable as BitMap, NZU64};
    use rand::RngCore;

    /// A type alias for the concrete merkleized [Db] type used in these unit tests.
    type CleanCurrentTest = Db<deterministic::Context, Digest, Digest, Sha256, TwoCap, 32>;
    type MutableCurrentTest = CleanCurrentTest;

    /// Return an [Db] database initialized with a fixed config.
    async fn open_db(
        context: deterministic::Context,
        partition_prefix: String,
    ) -> CleanCurrentTest {
        let cfg = fixed_config::<TwoCap>(&partition_prefix, &context);
        CleanCurrentTest::init(context, cfg).await.unwrap()
    }

    /// Build a tiny database and make sure we can't convince the verifier that some old value of a
    /// key is active. We specifically test over the partial chunk case, since these bits are yet to
    /// be committed to the underlying MMR.
    #[test_traced("DEBUG")]
    pub fn test_current_db_verify_proof_over_bits_in_uncommitted_chunk() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut hasher = StandardHasher::<Sha256>::new();
            let partition = "build-small".to_string();
            let mut db = open_db(context.with_label("db"), partition.clone()).await;

            // Add one key.
            let k = Sha256::fill(0x01);
            let v1 = Sha256::fill(0xA1);
            db.write_batch([(k, Some(v1))]).await.unwrap();
            db.commit(None).await.unwrap();

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
            db.write_batch([(k, Some(v2))]).await.unwrap();
            db.commit(None).await.unwrap();
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
                BitMap::<32>::to_chunk_index(*active_loc),
                BitMap::<32>::to_chunk_index(*proof_inactive.loc)
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
            let partition = "range-proofs".to_string();
            let mut hasher = StandardHasher::<Sha256>::new();
            let db = open_db(context.with_label("db"), partition.clone()).await;
            let root = db.root();

            // Empty range proof should not crash or verify, since even an empty db has a single
            // commit op.
            let proof = RangeProof {
                proof: Proof::default(),
                partial_chunk_digest: None,
                ops_root: Digest::EMPTY,
            };
            assert!(!CleanCurrentTest::verify_range_proof(
                hasher.inner(),
                &proof,
                Location::new_unchecked(0),
                &[],
                &[],
                &root,
            ));

            let mut db = apply_random_ops::<CleanCurrentTest>(200, true, context.next_u64(), db)
                .await
                .unwrap();
            db.commit(None).await.unwrap();
            let root = db.root();

            // Make sure size-constrained batches of operations are provable from the oldest
            // retained op to tip.
            let max_ops = 4;
            let end_loc = db.size().await;
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
            let partition = "range-proofs".to_string();
            let mut hasher = StandardHasher::<Sha256>::new();
            let db = open_db(context.with_label("db"), partition.clone()).await;
            let mut db = apply_random_ops::<CleanCurrentTest>(500, true, context.next_u64(), db)
                .await
                .unwrap();
            db.commit(None).await.unwrap();
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

    /// Repeatedly update the same key to a new value and ensure we can prove its current value
    /// after each update.
    #[test_traced("WARN")]
    pub fn test_current_db_proving_repeated_updates() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut hasher = StandardHasher::<Sha256>::new();
            let partition = "build-small".to_string();
            let mut db = open_db(context.with_label("db"), partition.clone()).await;

            // Add one key.
            let k = Sha256::fill(0x00);
            let mut old_val = Sha256::fill(0x00);
            for i in 1u8..=255 {
                let v = Sha256::fill(i);
                db.write_batch([(k, Some(v))]).await.unwrap();
                assert_eq!(db.get(&k).await.unwrap().unwrap(), v);
                db.commit(None).await.unwrap();
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

    #[test_traced("DEBUG")]
    fn test_batch() {
        batch_tests::test_batch(|mut ctx| async move {
            let seed = ctx.next_u64();
            let prefix = format!("current-unordered-batch-{seed}");
            open_db(ctx, prefix).await
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
        assert_send(db.write_batch([(key, Some(value))]));
        assert_batchable(db, key, value);
    }

    #[allow(dead_code)]
    fn assert_mutable_db_commit_is_send(mut db: MutableCurrentTest) {
        assert_send(db.commit(None));
    }
}
