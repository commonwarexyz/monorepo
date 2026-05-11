//! _Unordered_ variants of a [crate::qmdb::current] authenticated database.
//!
//! These variants do not maintain key ordering, so they cannot generate exclusion proofs. Use
//! the [super::ordered] variants if exclusion proofs are required.
//!
//! Variants:
//! - [fixed]: Variant optimized for values of fixed size.
//! - [variable]: Variant for values of variable size.

pub mod db;
pub mod fixed;
#[cfg(any(test, feature = "test-traits"))]
mod test_trait_impls;
pub mod variable;

#[cfg(test)]
pub mod tests {
    //! Shared test utilities for unordered Current QMDB variants.

    use super::db;
    use crate::{
        index::unordered::Index,
        journal::{contiguous::Mutable, Error as JournalError},
        merkle::{Graftable, Location, Proof},
        qmdb::{
            any::{
                operation::update::Unordered as UnorderedUpdate,
                traits::{DbAny, UnmerkleizedBatch as _},
                unordered::Operation,
                ValueEncoding,
            },
            current::{proof::RangeProof, tests::apply_random_ops, BitmapPrunedBits},
            store::tests::{TestKey, TestValue},
            Error,
        },
        translator::TwoCap,
        Persistable,
    };
    use commonware_codec::Codec;
    use commonware_cryptography::{sha256::Digest, Digest as _, Hasher as _, Sha256};
    use commonware_runtime::{
        deterministic::{self, Context},
        Runner as _, Supervisor as _,
    };
    use commonware_utils::{
        bitmap::{Prunable as BitMap, Readable as _},
        NZU64,
    };
    use core::future::Future;
    use rand::RngCore;

    /// Concrete db type used in the shared proof tests, generic over journal (`C`) and value
    /// encoding (`V`).
    type TestDb<F, C, V> =
        db::Db<F, deterministic::Context, C, Digest, V, Index<TwoCap, Location<F>>, Sha256, 32>;

    /// Run `test_current_db_build_small_close_reopen` against an unordered database factory.
    ///
    /// This test builds a small database, performs basic operations (create, delete, commit),
    /// and verifies state is preserved across close/reopen cycles.
    pub fn test_build_small_close_reopen<F, C, Fn, Fut>(mut open_db: Fn)
    where
        F: Graftable,
        C: DbAny<F> + BitmapPrunedBits,
        C::Key: TestKey,
        <C as DbAny<F>>::Value: TestValue,
        Fn: FnMut(Context, String) -> Fut,
        Fut: Future<Output = C>,
    {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let partition = "build-small".to_string();
            let db: C = open_db(context.child("first"), partition.clone()).await;
            assert_eq!(db.inactivity_floor_loc().await, Location::<F>::new(0));
            assert_eq!(db.oldest_retained().await, 0);
            let root0 = db.root();
            drop(db);
            let mut db: C = open_db(context.child("second"), partition.clone()).await;
            assert!(db.get_metadata().await.unwrap().is_none());
            assert_eq!(db.root(), root0);

            // Add one key.
            let k1: C::Key = TestKey::from_seed(0);
            let v1: <C as DbAny<F>>::Value = TestValue::from_seed(10);
            assert!(db.get(&k1).await.unwrap().is_none());
            let merkleized = db
                .new_batch()
                .write(k1, Some(v1.clone()))
                .merkleize(&db, None)
                .await
                .unwrap();
            db.apply_batch(merkleized).await.unwrap();
            db.commit().await.unwrap();
            assert_eq!(db.get(&k1).await.unwrap().unwrap(), v1);
            assert!(db.get_metadata().await.unwrap().is_none());
            let root1 = db.root();
            assert_ne!(root1, root0);
            drop(db);
            let mut db: C = open_db(context.child("third"), partition.clone()).await;
            assert!(db.get_metadata().await.unwrap().is_none());
            assert_eq!(db.root(), root1);

            // Create of same key should fail (key already exists).
            assert!(db.get(&k1).await.unwrap().is_some());

            // Delete that one key.
            assert!(db.get(&k1).await.unwrap().is_some());
            let metadata: <C as DbAny<F>>::Value = TestValue::from_seed(1);
            let merkleized = db
                .new_batch()
                .write(k1, None)
                .merkleize(&db, Some(metadata.clone()))
                .await
                .unwrap();
            db.apply_batch(merkleized).await.unwrap();
            db.commit().await.unwrap();
            assert_eq!(db.get_metadata().await.unwrap().unwrap(), metadata);
            let root2 = db.root();

            // Repeated delete of same key should fail (key already deleted).
            assert!(db.get(&k1).await.unwrap().is_none());
            let merkleized = db.new_batch().merkleize(&db, None).await.unwrap();
            db.apply_batch(merkleized).await.unwrap();
            db.sync().await.unwrap();
            let root3 = db.root();
            assert_ne!(root3, root2);

            // Confirm re-open preserves state.
            drop(db);
            let mut db: C = open_db(context.child("fourth"), partition.clone()).await;
            // Last commit had no metadata (passed None to merkleize).
            assert!(db.get_metadata().await.unwrap().is_none());
            assert_eq!(db.root(), root3);

            // Confirm all activity bits are false except for the last commit.
            let bounds = db.bounds().await;
            for i in 0..*bounds.end - 1 {
                assert!(!db.get_bit(i));
            }
            assert!(db.get_bit(*bounds.end - 1));

            // Test that we can get a non-durable root.
            let merkleized = db
                .new_batch()
                .write(k1, Some(v1))
                .merkleize(&db, None)
                .await
                .unwrap();
            db.apply_batch(merkleized).await.unwrap();
            assert_ne!(db.root(), root3);

            db.destroy().await.unwrap();
        });
    }

    /// Build a tiny database and verify that proofs over uncommitted bitmap chunks are correct.
    ///
    /// Tests that the verifier rejects proofs for old values after updates, including attempts
    /// to forge proofs by swapping locations or flipping activity bits.
    pub(super) fn test_verify_proof_over_bits_in_uncommitted_chunk<F, C, V, Fn, Fut>(
        mut open_db: Fn,
    ) where
        F: Graftable,
        C: Mutable<Item = Operation<F, Digest, V>> + Persistable<Error = JournalError> + 'static,
        V: ValueEncoding<Value = Digest> + 'static,
        Operation<F, Digest, V>: Codec,
        TestDb<F, C, V>: DbAny<F, Key = Digest, Value = Digest, Digest = Digest> + 'static,
        Fn: FnMut(Context, String) -> Fut + 'static,
        Fut: Future<Output = TestDb<F, C, V>>,
    {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let hasher = crate::qmdb::hasher::<Sha256>();
            let partition = "build-small".to_string();
            let mut db = open_db(context.child("db"), partition.clone()).await;

            // Add one key.
            let k = Sha256::fill(0x01);
            let v1 = Sha256::fill(0xA1);
            let merkleized = db
                .new_batch()
                .write(k, Some(v1))
                .merkleize(&db, None)
                .await
                .unwrap();
            db.apply_batch(merkleized).await.unwrap();

            let (_, op_loc) = db.any.get_with_loc(&k).await.unwrap().unwrap();
            let proof = db.key_value_proof(&hasher, k).await.unwrap();

            // Proof should be verifiable against current root.
            let root = db.root();
            assert!(TestDb::<F, C, V>::verify_key_value_proof(
                &hasher, k, v1, &proof, &root
            ));

            let v2 = Sha256::fill(0xA2);
            // Proof should not verify against a different value.
            assert!(!TestDb::<F, C, V>::verify_key_value_proof(
                &hasher, k, v2, &proof, &root,
            ));

            // Update the key to a new value (v2), which inactivates the previous operation.
            let merkleized = db
                .new_batch()
                .write(k, Some(v2))
                .merkleize(&db, None)
                .await
                .unwrap();
            db.apply_batch(merkleized).await.unwrap();
            let root = db.root();

            // New value should not be verifiable against the old proof.
            assert!(!TestDb::<F, C, V>::verify_key_value_proof(
                &hasher, k, v2, &proof, &root,
            ));

            // But the new value should verify against a new proof.
            let proof = db.key_value_proof(&hasher, k).await.unwrap();
            assert!(TestDb::<F, C, V>::verify_key_value_proof(
                &hasher, k, v2, &proof, &root,
            ));

            // Old value will not verify against new proof.
            assert!(!TestDb::<F, C, V>::verify_key_value_proof(
                &hasher, k, v1, &proof, &root,
            ));

            // Create a proof of the now-inactive update operation assigning v1 to k against the
            // current root.
            let (range_proof, _, chunks) =
                db.range_proof(&hasher, op_loc, NZU64!(1)).await.unwrap();
            let proof_inactive = db::KeyValueProof {
                loc: op_loc,
                chunk: chunks[0],
                range_proof,
            };
            // This proof should verify using verify_range_proof which does not check activity
            // status.
            let op = Operation::Update(UnorderedUpdate(k, v1));
            assert!(TestDb::<F, C, V>::verify_range_proof(
                &hasher,
                &proof_inactive.range_proof,
                proof_inactive.loc,
                &[op],
                &[proof_inactive.chunk],
                &root,
            ));

            // But this proof should *not* verify as a key value proof, since verification will see
            // that the operation is inactive.
            assert!(!TestDb::<F, C, V>::verify_key_value_proof(
                &hasher,
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
            assert!(!TestDb::<F, C, V>::verify_key_value_proof(
                &hasher,
                k,
                v1,
                &fake_proof,
                &root,
            ));

            // Attempt #2 to "fool" the verifier: Modify the chunk in the proof info to make it
            // look like the operation is active by flipping its corresponding bit to 1. This
            // should not fool the verifier if we are correctly incorporating the partial chunk
            // information into the root computation.
            let mut modified_chunk = proof_inactive.chunk;
            let bit_pos = *proof_inactive.loc;
            let byte_idx = bit_pos / 8;
            let bit_idx = bit_pos % 8;
            modified_chunk[byte_idx as usize] |= 1 << bit_idx;

            let mut fake_proof = proof_inactive.clone();
            fake_proof.chunk = modified_chunk;
            assert!(!TestDb::<F, C, V>::verify_key_value_proof(
                &hasher,
                k,
                v1,
                &fake_proof,
                &root,
            ));

            db.destroy().await.unwrap();
        });
    }

    /// Verify that range proofs are correct across a database populated with random operations.
    ///
    /// Tests that every location from the inactivity floor to the tip produces a valid range
    /// proof, and that adding extra chunks causes verification to fail.
    pub(super) fn test_range_proofs<F, C, V, Fn, Fut>(mut open_db: Fn)
    where
        F: Graftable,
        C: Mutable<Item = Operation<F, Digest, V>> + Persistable<Error = JournalError> + 'static,
        V: ValueEncoding<Value = Digest> + 'static,
        Operation<F, Digest, V>: Codec,
        TestDb<F, C, V>: DbAny<F, Key = Digest, Value = Digest, Digest = Digest> + 'static,
        Fn: FnMut(Context, String) -> Fut + 'static,
        Fut: Future<Output = TestDb<F, C, V>>,
    {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            let partition = "range-proofs".to_string();
            let hasher = crate::qmdb::hasher::<Sha256>();
            let db = open_db(context.child("db"), partition.clone()).await;
            let root = db.root();

            // Empty range proof should not crash or verify, since even an empty db has a single
            // commit op.
            let proof = RangeProof {
                proof: Proof::default(),
                prefix_witnesses: vec![],
                suffix_witnesses: vec![],
                partial_chunk_digest: None,
                ops_root: Digest::EMPTY,
            };
            assert!(!TestDb::<F, C, V>::verify_range_proof(
                &hasher,
                &proof,
                Location::<F>::new(0),
                &[],
                &[],
                &root,
            ));

            let mut db = apply_random_ops::<F, TestDb<F, C, V>>(200, true, context.next_u64(), db)
                .await
                .unwrap();
            let merkleized = db.new_batch().merkleize(&db, None).await.unwrap();
            db.apply_batch(merkleized).await.unwrap();
            let root = db.root();

            // Make sure size-constrained batches of operations are provable from the oldest
            // retained op to tip.
            let max_ops = 4;
            let end_loc = db.bounds().await.end;
            let start_loc = db.any.inactivity_floor_loc();

            for loc in *start_loc..*end_loc {
                let loc = Location::<F>::new(loc);
                let (proof, ops, chunks) =
                    db.range_proof(&hasher, loc, NZU64!(max_ops)).await.unwrap();
                assert!(
                    TestDb::<F, C, V>::verify_range_proof(
                        &hasher, &proof, loc, &ops, &chunks, &root
                    ),
                    "failed to verify range at start_loc {start_loc}",
                );
                // Proof should not verify if we include extra chunks.
                let mut chunks_with_extra = chunks.clone();
                chunks_with_extra.push(chunks[chunks.len() - 1]);
                assert!(!TestDb::<F, C, V>::verify_range_proof(
                    &hasher,
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

    /// Verify key-value proofs for every active operation in a randomly-populated database.
    ///
    /// Checks that proofs validate against the correct key/value/root and fail against
    /// wrong keys, wrong values, and wrong roots.
    pub(super) fn test_key_value_proof<F, C, V, Fn, Fut>(mut open_db: Fn)
    where
        F: Graftable,
        C: Mutable<Item = Operation<F, Digest, V>> + Persistable<Error = JournalError> + 'static,
        V: ValueEncoding<Value = Digest> + 'static,
        Operation<F, Digest, V>: Codec,
        TestDb<F, C, V>: DbAny<F, Key = Digest, Value = Digest, Digest = Digest> + 'static,
        Fn: FnMut(Context, String) -> Fut + 'static,
        Fut: Future<Output = TestDb<F, C, V>>,
    {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            let partition = "range-proofs".to_string();
            let hasher = crate::qmdb::hasher::<Sha256>();
            let db = open_db(context.child("db"), partition.clone()).await;
            let mut db = apply_random_ops::<F, TestDb<F, C, V>>(500, true, context.next_u64(), db)
                .await
                .unwrap();
            let merkleized = db.new_batch().merkleize(&db, None).await.unwrap();
            db.apply_batch(merkleized).await.unwrap();
            let root = db.root();

            // Confirm bad keys produce the expected error.
            let bad_key = Sha256::fill(0xAA);
            let res = db.key_value_proof(&hasher, bad_key).await;
            assert!(matches!(res, Err(Error::KeyNotFound)));

            let start = *db.inactivity_floor_loc();
            for i in start..db.any.bitmap.len() {
                if !db.any.bitmap.get_bit(i) {
                    continue;
                }
                // Found an active operation! Create a proof for its active current key/value if
                // it's a key-updating operation.
                let (key, value) = match db.any.log.read(Location::<F>::new(i)).await.unwrap() {
                    Operation::Update(UnorderedUpdate(key, value)) => (key, value),
                    Operation::CommitFloor(_, _) => continue,
                    Operation::Delete(_) => {
                        unreachable!("location does not reference update/commit operation")
                    }
                };

                let proof = db.key_value_proof(&hasher, key).await.unwrap();
                // Proof should validate against the current value and correct root.
                assert!(TestDb::<F, C, V>::verify_key_value_proof(
                    &hasher, key, value, &proof, &root
                ));
                // Proof should fail against the wrong value. Use hash instead of fill to ensure
                // the value differs from any key/value created by TestKey::from_seed (which uses
                // fill patterns).
                let wrong_val = Sha256::hash(&[0xFF]);
                assert!(!TestDb::<F, C, V>::verify_key_value_proof(
                    &hasher, key, wrong_val, &proof, &root
                ));
                // Proof should fail against the wrong key.
                let wrong_key = Sha256::hash(&[0xEE]);
                assert!(!TestDb::<F, C, V>::verify_key_value_proof(
                    &hasher, wrong_key, value, &proof, &root
                ));
                // Proof should fail against the wrong root.
                let wrong_root = Sha256::hash(&[0xDD]);
                assert!(!TestDb::<F, C, V>::verify_key_value_proof(
                    &hasher,
                    key,
                    value,
                    &proof,
                    &wrong_root,
                ));
            }

            db.destroy().await.unwrap();
        });
    }

    /// Repeatedly update the same key and ensure the proof tracks the latest value.
    ///
    /// After each update, verifies that the new value's proof succeeds and the previous
    /// value's proof fails.
    pub(super) fn test_proving_repeated_updates<F, C, V, Fn, Fut>(mut open_db: Fn)
    where
        F: Graftable,
        C: Mutable<Item = Operation<F, Digest, V>> + Persistable<Error = JournalError> + 'static,
        V: ValueEncoding<Value = Digest> + 'static,
        Operation<F, Digest, V>: Codec,
        TestDb<F, C, V>: DbAny<F, Key = Digest, Value = Digest, Digest = Digest> + 'static,
        Fn: FnMut(Context, String) -> Fut + 'static,
        Fut: Future<Output = TestDb<F, C, V>>,
    {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let hasher = crate::qmdb::hasher::<Sha256>();
            let partition = "build-small".to_string();
            let mut db = open_db(context.child("db"), partition.clone()).await;

            // Add one key.
            let k = Sha256::fill(0x00);
            let mut old_val = Sha256::fill(0x00);
            for i in 1u8..=255 {
                let v = Sha256::fill(i);
                let merkleized = db
                    .new_batch()
                    .write(k, Some(v))
                    .merkleize(&db, None)
                    .await
                    .unwrap();
                db.apply_batch(merkleized).await.unwrap();
                assert_eq!(db.get(&k).await.unwrap().unwrap(), v);
                let root = db.root();

                // Create a proof for the current value of k.
                let proof = db.key_value_proof(&hasher, k).await.unwrap();
                assert!(
                    TestDb::<F, C, V>::verify_key_value_proof(&hasher, k, v, &proof, &root),
                    "proof of update {i} failed to verify"
                );
                // Ensure the proof does NOT verify if we use the previous value.
                assert!(
                    !TestDb::<F, C, V>::verify_key_value_proof(&hasher, k, old_val, &proof, &root,),
                    "proof of update {i} verified when it should not have"
                );
                old_val = v;
            }

            db.destroy().await.unwrap();
        });
    }
}
