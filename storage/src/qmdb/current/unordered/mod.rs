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
pub mod proof;
pub mod variable;

pub use crate::qmdb::any::unordered::{Operation, Update};

#[cfg(test)]
pub mod tests {
    //! Shared test utilities for unordered Current QMDB variants.

    use super::{
        db,
        proof::{KeyValueProof, constant, dynamic},
    };
    use crate::{
        index::unordered::Index,
        journal::contiguous::{Contiguous as _, Mutable},
        merkle::{Graftable, Location, Proof},
        qmdb::{
            Error,
            any::{
                operation::update::Unordered as UnorderedUpdate,
                traits::{DbAny, UnmerkleizedBatch as _},
                unordered::Operation,
            },
            current::{
                BitmapPrunedBits,
                proof::{RangeProof, operation},
                tests::apply_random_ops,
            },
            store::tests::{TestKey, TestValue},
            value::ValueEncoding,
        },
        translator::TwoCap,
    };
    use commonware_codec::{Codec, Decode as _, Encode as _};
    use commonware_cryptography::{Digest as _, Hasher as _, Sha256, sha256::Digest};
    use commonware_runtime::{
        Runner as _, Supervisor as _,
        deterministic::{self, Context},
    };
    use commonware_utils::{
        NZU64,
        bitmap::{Prunable as BitMap, Readable as _},
    };
    use core::future::Future;
    use rand::Rng;

    /// Concrete db type used in the shared proof tests, generic over journal (`C`) and value
    /// encoding (`V`).
    type TestDb<F, C, V> = db::Db<
        F,
        deterministic::Context,
        C,
        Digest,
        V,
        Index<TwoCap, Location<F>>,
        Sha256,
        32,
        commonware_parallel::Sequential,
    >;

    /// Run `test_current_db_build_small_close_reopen` against an unordered database factory.
    ///
    /// This test builds a small database, performs basic operations (create, delete, commit),
    /// and verifies state is preserved across close/reopen cycles.
    pub async fn test_build_small_close_reopen<F, C, Fn, Fut>(context: Context, mut open_db: Fn)
    where
        F: Graftable,
        C: DbAny<Family = F> + BitmapPrunedBits,
        C::Key: TestKey,
        C::Value: TestValue,
        Fn: FnMut(Context, String) -> Fut,
        Fut: Future<Output = C>,
    {
        let partition = "build-small".to_string();
        let db: C = open_db(context.child("first"), partition.clone()).await;
        assert_eq!(db.inactivity_floor(), Location::<F>::new(0));
        assert_eq!(db.bounds().start, Location::<F>::new(0));
        let root0 = db.root();
        drop(db);
        let db: C = open_db(context.child("second"), partition.clone()).await;
        assert!(db.get_metadata().await.unwrap().is_none());
        assert_eq!(db.root(), root0);

        // Add one key.
        let k1: C::Key = TestKey::from_seed(0);
        let v1: C::Value = TestValue::from_seed(10);
        assert!(db.get(&k1).await.unwrap().is_none());
        let merkleized = db
            .new_batch()
            .write(k1, Some(v1.clone()))
            .merkleize(&db)
            .await
            .unwrap();
        let db = db.apply_batch(merkleized).await.unwrap();
        let db = db.commit().await.unwrap();
        assert_eq!(db.get(&k1).await.unwrap().unwrap(), v1);
        assert!(db.get_metadata().await.unwrap().is_none());
        let root1 = db.root();
        assert_ne!(root1, root0);
        drop(db);
        let db: C = open_db(context.child("third"), partition.clone()).await;
        assert!(db.get_metadata().await.unwrap().is_none());
        assert_eq!(db.root(), root1);

        // Create of same key should fail (key already exists).
        assert!(db.get(&k1).await.unwrap().is_some());

        // Delete that one key.
        assert!(db.get(&k1).await.unwrap().is_some());
        let metadata: C::Value = TestValue::from_seed(1);
        let merkleized = db
            .new_batch()
            .write(k1, None)
            .with_metadata(Some(metadata.clone()))
            .merkleize(&db)
            .await
            .unwrap();
        let db = db.apply_batch(merkleized).await.unwrap();
        let db = db.commit().await.unwrap();
        assert_eq!(db.get_metadata().await.unwrap().unwrap(), metadata);
        let root2 = db.root();

        // Repeated delete of same key should fail (key already deleted).
        assert!(db.get(&k1).await.unwrap().is_none());
        let merkleized = db.new_batch().merkleize(&db).await.unwrap();
        let db = db.apply_batch(merkleized).await.unwrap();
        let db = db.sync().await.unwrap();
        let root3 = db.root();
        assert_ne!(root3, root2);

        // Confirm re-open preserves state.
        drop(db);
        let db: C = open_db(context.child("fourth"), partition.clone()).await;
        // Last commit had no metadata (passed None to merkleize).
        assert!(db.get_metadata().await.unwrap().is_none());
        assert_eq!(db.root(), root3);

        // Confirm all activity bits are false except for the last commit.
        let bounds = db.bounds();
        for i in 0..*bounds.end - 1 {
            assert!(!db.get_bit(i));
        }
        assert!(db.get_bit(*bounds.end - 1));

        // Test that we can get a non-durable root.
        let merkleized = db
            .new_batch()
            .write(k1, Some(v1))
            .merkleize(&db)
            .await
            .unwrap();
        let db = db.apply_batch(merkleized).await.unwrap();
        assert_ne!(db.root(), root3);

        db.destroy().await.unwrap();
    }

    /// Build a tiny database and verify that proofs over uncommitted bitmap chunks are correct.
    ///
    /// Tests that the verifier rejects proofs for old values after updates, including attempts
    /// to forge proofs by swapping locations or flipping activity bits.
    pub(super) fn test_verify_proof_over_bits_in_uncommitted_chunk<F, C, V, Fn, Fut>(
        mut open_db: Fn,
    ) where
        F: Graftable,
        C: Mutable<Item = Operation<F, Digest, V>>,
        V: ValueEncoding<Value = Digest>,
        Operation<F, Digest, V>: Codec,
        TestDb<F, C, V>: DbAny<Family = F, Key = Digest, Value = Digest, Digest = Digest> + 'static,
        Fn: FnMut(Context, String) -> Fut + 'static,
        Fut: Future<Output = TestDb<F, C, V>>,
    {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let partition = "build-small".to_string();
            let db = open_db(context.child("db"), partition.clone()).await;

            // Add one key.
            let k = Sha256::fill(0x01);
            let v1 = Sha256::fill(0xA1);
            let merkleized = db
                .new_batch()
                .write(k, Some(v1))
                .merkleize(&db)
                .await
                .unwrap();
            let db = db.apply_batch(merkleized).await.unwrap();

            let (_, op_loc) = db.any.get_with_loc(&k).await.unwrap().unwrap();
            let (proof, proved_value) = db.key_value_proof(&k).await.unwrap();
            assert_eq!(proved_value, v1);

            // Proof should be verifiable against current root.
            let root = db.root();
            assert!(proof.verify::<Sha256, V, _>(k, proved_value, &root));

            let v2 = Sha256::fill(0xA2);
            // Proof should not verify against a different value.
            assert!(!proof.verify::<Sha256, V, _>(k, v2, &root));

            // Update the key to a new value (v2), which inactivates the previous operation.
            let merkleized = db
                .new_batch()
                .write(k, Some(v2))
                .merkleize(&db)
                .await
                .unwrap();
            let db = db.apply_batch(merkleized).await.unwrap();
            let root = db.root();

            // New value should not be verifiable against the old proof.
            assert!(!proof.verify::<Sha256, V, _>(k, v2, &root));

            // But the new value should verify against a new proof.
            let (proof, proved_value) = db.key_value_proof(&k).await.unwrap();
            assert_eq!(proved_value, v2);
            assert!(proof.verify::<Sha256, V, _>(k, proved_value, &root));

            // Old value will not verify against new proof.
            assert!(!proof.verify::<Sha256, V, _>(k, v1, &root));

            // Create a proof of the now-inactive update operation assigning v1 to k against the
            // current root.
            let (range_proof, _, chunks) = db.range_proof(op_loc, NZU64!(1)).await.unwrap();
            let proof_inactive = constant::KeyValueProof {
                proof: operation::Proof {
                    loc: op_loc,
                    chunk: chunks[0],
                    range_proof,
                },
            };
            // This proof should verify using RangeProof::verify, which does not check activity
            // status.
            let op = Operation::Update(UnorderedUpdate(k, v1));
            assert!(proof_inactive.proof.range_proof.verify::<Sha256, _, _>(
                proof_inactive.proof.loc,
                &[op],
                &[proof_inactive.proof.chunk],
                &root,
            ));

            // But this proof should *not* verify as a key value proof, since verification will see
            // that the operation is inactive.
            assert!(!proof_inactive.verify::<Sha256, V, _>(k, v1, &root));

            // Attempt #1 to "fool" the verifier:  change the location to that of an active
            // operation. This should not fool the verifier if we're properly validating the
            // inclusion of the operation itself, and not just the chunk.
            let (_, active_loc) = db.any.get_with_loc(&k).await.unwrap().unwrap();
            // The new location should differ but still be in the same chunk.
            assert_ne!(active_loc, proof_inactive.proof.loc);
            assert_eq!(
                BitMap::<32>::to_chunk_index(*active_loc),
                BitMap::<32>::to_chunk_index(*proof_inactive.proof.loc)
            );
            let mut fake_proof = proof_inactive.clone();
            fake_proof.proof.loc = active_loc;
            assert!(!fake_proof.verify::<Sha256, V, _>(k, v1, &root));

            // Attempt #2 to "fool" the verifier: Modify the chunk in the proof info to make it
            // look like the operation is active by flipping its corresponding bit to 1. This
            // should not fool the verifier if we are correctly incorporating the partial chunk
            // information into the root computation.
            let mut modified_chunk = proof_inactive.proof.chunk;
            let bit_pos = *proof_inactive.proof.loc;
            let byte_idx = bit_pos / 8;
            let bit_idx = bit_pos % 8;
            modified_chunk[byte_idx as usize] |= 1 << bit_idx;

            let mut fake_proof = proof_inactive.clone();
            fake_proof.proof.chunk = modified_chunk;
            assert!(!fake_proof.verify::<Sha256, V, _>(k, v1, &root));

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
        C: Mutable<Item = Operation<F, Digest, V>>,
        V: ValueEncoding<Value = Digest>,
        Operation<F, Digest, V>: Codec,
        TestDb<F, C, V>: DbAny<Family = F, Key = Digest, Value = Digest, Digest = Digest> + 'static,
        Fn: FnMut(Context, String) -> Fut + 'static,
        Fut: Future<Output = TestDb<F, C, V>>,
    {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            let partition = "range-proofs".to_string();
            let db = open_db(context.child("db"), partition.clone()).await;
            let root = db.root();

            // Empty range proof should not crash or verify, since even an empty db has a single
            // commit op.
            let proof = RangeProof {
                proof: Proof::default(),
                pending_chunk_digest: None.try_into().unwrap(),
                partial_chunk_digest: None,
                ops_root: Digest::EMPTY,
            };
            assert!(!proof.verify::<Sha256, Operation<F, Digest, V>, 32>(
                Location::<F>::new(0),
                &[],
                &[],
                &root,
            ));

            let db = apply_random_ops::<F, TestDb<F, C, V>>(200, true, context.next_u64(), db)
                .await
                .unwrap();
            let merkleized = db.new_batch().merkleize(&db).await.unwrap();
            let db = db.apply_batch(merkleized).await.unwrap();
            let root = db.root();

            // Make sure size-constrained batches of operations are provable from the oldest
            // retained op to tip.
            let max_ops = 4;
            let end_loc = db.bounds().end;
            let start_loc = db.any.inactivity_floor();

            for loc in *start_loc..*end_loc {
                let loc = Location::<F>::new(loc);
                let (proof, ops, chunks) = db.range_proof(loc, NZU64!(max_ops)).await.unwrap();
                assert!(
                    proof.verify::<Sha256, _, _>(loc, &ops, &chunks, &root),
                    "failed to verify range at start_loc {start_loc}",
                );
                // Proof should not verify if we include extra chunks.
                let mut chunks_with_extra = chunks.clone();
                chunks_with_extra.push(chunks[chunks.len() - 1]);
                assert!(!proof.verify::<Sha256, _, _>(loc, &ops, &chunks_with_extra, &root));
            }

            db.destroy().await.unwrap();
        });
    }

    fn assert_key_value_proof<F, V>(
        proof: &KeyValueProof<F, Digest, impl AsRef<[u8]>>,
        key: Digest,
        value: Digest,
        root: &Digest,
    ) where
        F: Graftable,
        V: ValueEncoding<Value = Digest>,
        Operation<F, Digest, V>: Codec,
    {
        assert!(proof.verify::<Sha256, V, _>(key, value, root));

        // Seeded keys and values hash eight-byte seeds. Hash one-byte inputs here
        // to keep the negative cases distinct.
        let wrong_value = Sha256::hash(&[&[0xFF]]);
        let wrong_key = Sha256::hash(&[&[0xEE]]);
        let wrong_root = Sha256::hash(&[&[0xDD]]);
        assert!(!proof.verify::<Sha256, V, _>(key, wrong_value, root));
        assert!(!proof.verify::<Sha256, V, _>(wrong_key, value, root));
        assert!(!proof.verify::<Sha256, V, _>(key, value, &wrong_root));
    }

    /// Verify key-value proofs for every active operation in a randomly-populated database.
    ///
    /// Checks both fixed-size and runtime-sized chunks against the correct key/value/root,
    /// wrong keys, wrong values, and wrong roots.
    pub(super) fn test_key_value_proof<F, C, V, Fn, Fut>(mut open_db: Fn)
    where
        F: Graftable,
        C: Mutable<Item = Operation<F, Digest, V>>,
        V: ValueEncoding<Value = Digest>,
        Operation<F, Digest, V>: Codec,
        TestDb<F, C, V>: DbAny<Family = F, Key = Digest, Value = Digest, Digest = Digest> + 'static,
        Fn: FnMut(Context, String) -> Fut + 'static,
        Fut: Future<Output = TestDb<F, C, V>>,
    {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            let partition = "range-proofs".to_string();
            let db = open_db(context.child("db"), partition.clone()).await;
            let db = apply_random_ops::<F, TestDb<F, C, V>>(500, true, context.next_u64(), db)
                .await
                .unwrap();
            let merkleized = db.new_batch().merkleize(&db).await.unwrap();
            let db = db.apply_batch(merkleized).await.unwrap();
            let root = db.root();

            // Confirm bad keys produce the expected error.
            let bad_key = Sha256::fill(0xAA);
            let res = db.key_value_proof(&bad_key).await;
            assert!(matches!(res, Err(Error::KeyNotFound)));

            let start = *db.inactivity_floor();
            for i in start..db.any.bitmap.len() {
                if !db.any.bitmap.get_bit(i) {
                    continue;
                }
                // Found an active operation! Create a proof for its active current key/value if
                // it's a key-updating operation.
                let (key, value) = match db.any.log.read(*Location::<F>::new(i)).await.unwrap() {
                    Operation::Update(UnorderedUpdate(key, value)) => (key, value),
                    Operation::Commit(_, _) => continue,
                    Operation::Delete(_) => {
                        unreachable!("location does not reference update/commit operation")
                    }
                };

                let (proof, proved_value) = db.key_value_proof(&key).await.unwrap();
                assert_eq!(proved_value, value);
                assert_key_value_proof::<F, V>(&proof, key, proved_value, &root);

                let max_digests = proof.proof.range_proof.proof.digests.len();
                let encoded = proof.encode();
                let dynamic = dynamic::KeyValueProof::<F, Digest>::decode_cfg(
                    encoded.clone(),
                    &(proof.proof.chunk.len(), max_digests),
                )
                .unwrap();
                assert_eq!(dynamic.encode(), encoded);
                assert_key_value_proof::<F, V>(&dynamic, key, proved_value, &root);
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
        C: Mutable<Item = Operation<F, Digest, V>>,
        V: ValueEncoding<Value = Digest>,
        Operation<F, Digest, V>: Codec,
        TestDb<F, C, V>: DbAny<Family = F, Key = Digest, Value = Digest, Digest = Digest> + 'static,
        Fn: FnMut(Context, String) -> Fut + 'static,
        Fut: Future<Output = TestDb<F, C, V>>,
    {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
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
                    .merkleize(&db)
                    .await
                    .unwrap();
                db = db.apply_batch(merkleized).await.unwrap();
                assert_eq!(db.get(&k).await.unwrap().unwrap(), v);
                let root = db.root();

                // Create a proof for the current value of k.
                let (proof, proved_value) = db.key_value_proof(&k).await.unwrap();
                assert_eq!(proved_value, v);
                assert!(
                    proof.verify::<Sha256, V, _>(k, proved_value, &root),
                    "proof of update {i} failed to verify"
                );
                // Ensure the proof does NOT verify if we use the previous value.
                assert!(
                    !proof.verify::<Sha256, V, _>(k, old_val, &root),
                    "proof of update {i} verified when it should not have"
                );
                old_val = v;
            }

            db.destroy().await.unwrap();
        });
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use crate::{
            merkle::{mmb, mmr},
            qmdb::current::unordered::proof::{constant, dynamic},
        };
        use commonware_codec::conformance::CodecConformance;
        use commonware_cryptography::sha256::Digest as Sha256Digest;

        commonware_conformance::conformance_tests! {
            CodecConformance<constant::KeyValueProof<mmr::Family, Sha256Digest, 32>>,
            CodecConformance<constant::KeyValueProof<mmb::Family, Sha256Digest, 32>>,
            CodecConformance<dynamic::KeyValueProof<mmr::Family, Sha256Digest>>,
            CodecConformance<dynamic::KeyValueProof<mmb::Family, Sha256Digest>>,
        }
    }
}
