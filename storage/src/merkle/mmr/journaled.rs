//! An MMR backed by a fixed-item-length journal.
//!
//! A [crate::journal] is used to store all unpruned MMR nodes, and a [crate::metadata] store is
//! used to preserve digests required for root and proof generation that would have otherwise been
//! pruned.
//!
//! This module is a thin wrapper around the generic `Journaled` type, specialized for the
//! MMR [Family]. It re-exports [Config] and provides a [SyncConfig] type alias, and adds
//! MMR-specific async proof methods that use the [verification] module.

use crate::merkle::{
    hasher::Hasher,
    mmr::{verification, Error, Family, Location, Position, Proof},
    storage::Storage,
};
use commonware_cryptography::Digest;
use commonware_runtime::{Clock, Metrics, Storage as RStorage};
use core::ops::Range;

/// A MMR backed by a fixed-item-length journal.
pub type Mmr<E, D> = crate::merkle::journaled::Journaled<Family, E, D>;

/// Configuration for a journal-backed MMR.
pub use crate::merkle::journaled::Config;

/// Configuration for initializing a journaled MMR for synchronization.
pub type SyncConfig<D> = crate::merkle::journaled::SyncConfig<Family, D>;

/// MMR-specific extension methods on the journaled MMR.
impl<E: RStorage + Clock + Metrics, D: Digest> Mmr<E, D> {
    /// Return an inclusion proof for the element at the location `loc` against a historical MMR
    /// state with `leaves` leaves.
    ///
    /// # Errors
    ///
    /// - Returns [Error::RangeOutOfBounds] if `leaves` is greater than `self.leaves()` or if `loc`
    ///   is not provable at that historical size.
    /// - Returns [Error::LocationOverflow] if `loc` exceeds [crate::merkle::Family::MAX_LEAVES].
    /// - Returns [Error::ElementPruned] if some element needed to generate the proof has been
    ///   pruned.
    pub async fn historical_proof(
        &self,
        hasher: &impl Hasher<Family, Digest = D>,
        leaves: Location,
        loc: Location,
    ) -> Result<Proof<D>, Error> {
        if !loc.is_valid_index() {
            return Err(Error::LocationOverflow(loc));
        }
        // loc is valid so it won't overflow from + 1
        self.historical_range_proof(hasher, leaves, loc..loc + 1)
            .await
    }

    /// Return an inclusion proof for the elements in `range` against a historical MMR state with
    /// `leaves` leaves.
    ///
    /// # Errors
    ///
    /// - Returns [Error::RangeOutOfBounds] if `leaves` is greater than `self.leaves()` or if `range`
    ///   is not provable at that historical size.
    /// - Returns [Error::LocationOverflow] if any location in `range` exceeds
    ///   [crate::merkle::Family::MAX_LEAVES].
    /// - Returns [Error::ElementPruned] if some element needed to generate the proof has been
    ///   pruned.
    /// - Returns [Error::Empty] if the range is empty.
    pub async fn historical_range_proof(
        &self,
        hasher: &impl Hasher<Family, Digest = D>,
        leaves: Location,
        range: Range<Location>,
    ) -> Result<Proof<D>, Error> {
        if leaves > self.leaves() {
            return Err(Error::RangeOutOfBounds(leaves));
        }
        verification::historical_range_proof(hasher, self, leaves, range).await
    }

    /// Return an inclusion proof for the element at the location `loc` that can be verified against
    /// the current root.
    ///
    /// # Errors
    ///
    /// - Returns [Error::LocationOverflow] if `loc` exceeds [crate::merkle::Family::MAX_LEAVES].
    /// - Returns [Error::ElementPruned] if some element needed to generate the proof has been
    ///   pruned.
    /// - Returns [Error::Empty] if the range is empty.
    pub async fn proof(
        &self,
        hasher: &impl Hasher<Family, Digest = D>,
        loc: Location,
    ) -> Result<Proof<D>, Error> {
        if !loc.is_valid_index() {
            return Err(Error::LocationOverflow(loc));
        }
        // loc is valid so it won't overflow from + 1
        self.range_proof(hasher, loc..loc + 1).await
    }

    /// Return an inclusion proof for the elements within the specified location range.
    ///
    /// Locations are validated by [verification::range_proof].
    ///
    /// # Errors
    ///
    /// - Returns [Error::LocationOverflow] if any location in `range` exceeds
    ///   [crate::merkle::Family::MAX_LEAVES].
    /// - Returns [Error::ElementPruned] if some element needed to generate the proof has been
    ///   pruned.
    /// - Returns [Error::Empty] if the range is empty.
    pub async fn range_proof(
        &self,
        hasher: &impl Hasher<Family, Digest = D>,
        range: Range<Location>,
    ) -> Result<Proof<D>, Error> {
        self.historical_range_proof(hasher, self.leaves(), range)
            .await
    }
}

impl<E: RStorage + Clock + Metrics + Sync, D: Digest> Storage<Family> for Mmr<E, D> {
    type Digest = D;

    async fn size(&self) -> Position {
        self.size()
    }

    async fn get_node(&self, position: Position) -> Result<Option<D>, Error> {
        Self::get_node(self, position).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        journal::contiguous::fixed::{Config as JConfig, Journal},
        merkle::{
            conformance::build_test_mmr, mmr::iterator::nodes_to_pin, LocationRangeExt as _,
            Readable,
        },
        metadata::{Config as MConfig, Metadata},
        mmr::{mem, Location, StandardHasher as Standard},
    };
    use commonware_cryptography::{
        sha256::{self, Digest},
        Hasher, Sha256,
    };
    use commonware_macros::test_traced;
    use commonware_runtime::{
        buffer::paged::CacheRef, deterministic, Blob as _, BufferPooler, Runner,
    };
    use commonware_utils::{sequence::prefixed_u64::U64, NZUsize, NZU16, NZU64};
    use std::{
        collections::BTreeMap,
        num::{NonZeroU16, NonZeroUsize},
    };

    /// Prefix used for the key storing the pruning boundary (as a leaf index) in the metadata.
    const PRUNED_TO_PREFIX: u8 = 1;

    fn test_digest(v: usize) -> Digest {
        Sha256::hash(&v.to_be_bytes())
    }

    const PAGE_SIZE: NonZeroU16 = NZU16!(111);
    const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(5);

    fn test_config(pooler: &impl BufferPooler) -> Config {
        Config {
            journal_partition: "journal-partition".into(),
            metadata_partition: "metadata-partition".into(),
            items_per_blob: NZU64!(7),
            write_buffer: NZUsize!(1024),
            thread_pool: None,
            page_cache: CacheRef::from_pooler(pooler, PAGE_SIZE, PAGE_CACHE_SIZE),
        }
    }

    /// Test that the journaled MMR produces the same root as the in-memory reference.
    #[test]
    fn test_journaled_mmr_batched_root() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            const NUM_ELEMENTS: u64 = 199;
            let hasher: Standard<Sha256> = Standard::new();
            let test_mmr = mem::Mmr::new(&hasher);
            let test_mmr = build_test_mmr(&hasher, test_mmr, NUM_ELEMENTS);
            let expected_root = test_mmr.root();

            let mut journaled_mmr = Mmr::init(
                context.clone(),
                &Standard::<Sha256>::new(),
                test_config(&context),
            )
            .await
            .unwrap();

            let changeset = {
                let mut batch = journaled_mmr.new_batch();
                for i in 0u64..NUM_ELEMENTS {
                    let element = hasher.digest(&i.to_be_bytes());
                    batch = batch.add(&hasher, &element);
                }
                batch.merkleize(&hasher).finalize()
            };
            journaled_mmr.apply(changeset).unwrap();
            assert_eq!(journaled_mmr.root(), *expected_root);

            journaled_mmr.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_journaled_mmr_empty() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let hasher: Standard<Sha256> = Standard::new();
            let mut mmr = Mmr::init(context.with_label("first"), &hasher, test_config(&context))
                .await
                .unwrap();
            assert_eq!(mmr.size(), 0);
            assert!(mmr.get_node(Position::new(0)).await.is_err());
            let bounds = mmr.bounds();
            assert!(bounds.is_empty());
            assert!(mmr.prune_all().await.is_ok());
            assert_eq!(bounds.start, 0);
            assert!(mmr.prune(Location::new(0)).await.is_ok());
            assert!(mmr.sync().await.is_ok());
            assert!(matches!(mmr.rewind(1, &hasher).await, Err(Error::Empty)));

            let changeset = mmr
                .new_batch()
                .add(&hasher, &test_digest(0))
                .merkleize(&hasher)
                .finalize();
            mmr.apply(changeset).unwrap();
            assert_eq!(mmr.size(), 1);
            mmr.sync().await.unwrap();
            assert!(mmr.get_node(Position::new(0)).await.is_ok());
            assert!(mmr.rewind(1, &hasher).await.is_ok());
            assert_eq!(mmr.size(), 0);
            mmr.sync().await.unwrap();

            let mut mmr = Mmr::init(context.with_label("second"), &hasher, test_config(&context))
                .await
                .unwrap();
            assert_eq!(mmr.size(), 0);

            let empty_proof = Proof::default();
            let hasher: Standard<Sha256> = Standard::new();
            let root = mmr.root();
            assert!(empty_proof.verify_range_inclusion(
                &hasher,
                &[] as &[Digest],
                Location::new(0),
                &root
            ));
            assert!(empty_proof.verify_multi_inclusion(
                &hasher,
                &[] as &[(Digest, Location)],
                &root
            ));

            // Confirm empty proof no longer verifies after adding an element.
            let changeset = mmr
                .new_batch()
                .add(&hasher, &test_digest(0))
                .merkleize(&hasher)
                .finalize();
            mmr.apply(changeset).unwrap();
            let root = mmr.root();
            assert!(!empty_proof.verify_range_inclusion(
                &hasher,
                &[] as &[Digest],
                Location::new(0),
                &root
            ));
            assert!(!empty_proof.verify_multi_inclusion(
                &hasher,
                &[] as &[(Digest, Location)],
                &root
            ));

            mmr.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_journaled_prune_out_of_bounds_returns_error() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let hasher = Standard::<Sha256>::new();
            let mut mmr = Mmr::init(
                context.with_label("oob_prune"),
                &hasher,
                test_config(&context),
            )
            .await
            .unwrap();

            let changeset = mmr
                .new_batch()
                .add(&hasher, &test_digest(0))
                .merkleize(&hasher)
                .finalize();
            mmr.apply(changeset).unwrap();

            assert!(matches!(
                mmr.prune(Location::new(2)).await,
                Err(Error::LeafOutOfBounds(loc)) if loc == Location::new(2)
            ));

            mmr.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_journaled_mmr_pop() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            const NUM_ELEMENTS: u64 = 200;

            let hasher: Standard<Sha256> = Standard::new();
            let cfg = test_config(&context);
            let mut mmr = Mmr::init(context, &hasher, cfg).await.unwrap();

            let mut c_hasher = Sha256::new();
            let changeset = {
                let mut batch = mmr.new_batch();
                for i in 0u64..NUM_ELEMENTS {
                    c_hasher.update(&i.to_be_bytes());
                    let element = c_hasher.finalize();
                    batch = batch.add(&hasher, &element);
                }
                batch.merkleize(&hasher).finalize()
            };
            mmr.apply(changeset).unwrap();

            // Rewind one node at a time without syncing until empty, confirming the root matches.
            for i in (0..NUM_ELEMENTS).rev() {
                assert!(mmr.rewind(1, &hasher).await.is_ok());
                let root = mmr.root();
                let mut reference_mmr = mem::Mmr::new(&hasher);
                let changeset = {
                    let mut batch = reference_mmr.new_batch();
                    for j in 0..i {
                        c_hasher.update(&j.to_be_bytes());
                        let element = c_hasher.finalize();
                        batch = batch.add(&hasher, &element);
                    }
                    batch.merkleize(&hasher).finalize()
                };
                reference_mmr.apply(changeset).unwrap();
                assert_eq!(
                    root,
                    *reference_mmr.root(),
                    "root mismatch after rewind at {i}"
                );
            }
            assert!(matches!(mmr.rewind(1, &hasher).await, Err(Error::Empty)));
            assert!(mmr.rewind(0, &hasher).await.is_ok());

            // Repeat the test though sync part of the way to tip to test crossing the boundary from
            // cached to uncached leaves, and rewind 2 at a time instead of just 1.
            {
                let changeset = {
                    let mut batch = mmr.new_batch();
                    for i in 0u64..NUM_ELEMENTS {
                        c_hasher.update(&i.to_be_bytes());
                        let element = c_hasher.finalize();
                        batch = batch.add(&hasher, &element);
                        if i == 101 {
                            // We can't sync mid-batch, so finalize and apply the first part,
                            // sync, then start a new batch for the rest.
                            break;
                        }
                    }
                    batch.merkleize(&hasher).finalize()
                };
                mmr.apply(changeset).unwrap();
                mmr.sync().await.unwrap();
                let changeset = {
                    let mut batch = mmr.new_batch();
                    for i in 102u64..NUM_ELEMENTS {
                        c_hasher.update(&i.to_be_bytes());
                        let element = c_hasher.finalize();
                        batch = batch.add(&hasher, &element);
                    }
                    batch.merkleize(&hasher).finalize()
                };
                mmr.apply(changeset).unwrap();
            }

            for i in (0..NUM_ELEMENTS - 1).rev().step_by(2) {
                assert!(mmr.rewind(2, &hasher).await.is_ok(), "at position {i:?}");
                let root = mmr.root();
                let reference_mmr = mem::Mmr::new(&hasher);
                let reference_mmr = build_test_mmr(&hasher, reference_mmr, i);
                assert_eq!(
                    root,
                    *reference_mmr.root(),
                    "root mismatch at position {i:?}"
                );
            }
            assert!(matches!(mmr.rewind(99, &hasher).await, Err(Error::Empty)));

            // Repeat one more time only after pruning the MMR first.
            {
                let changeset = {
                    let mut batch = mmr.new_batch();
                    for i in 0u64..102 {
                        c_hasher.update(&i.to_be_bytes());
                        let element = c_hasher.finalize();
                        batch = batch.add(&hasher, &element);
                    }
                    batch.merkleize(&hasher).finalize()
                };
                mmr.apply(changeset).unwrap();
                mmr.sync().await.unwrap();
                let changeset = {
                    let mut batch = mmr.new_batch();
                    for i in 102u64..NUM_ELEMENTS {
                        c_hasher.update(&i.to_be_bytes());
                        let element = c_hasher.finalize();
                        batch = batch.add(&hasher, &element);
                    }
                    batch.merkleize(&hasher).finalize()
                };
                mmr.apply(changeset).unwrap();
            }
            let prune_loc = Location::new(50);
            let prune_pos = Position::try_from(prune_loc).unwrap();
            mmr.prune(prune_loc).await.unwrap();
            // Rewind enough nodes to cause the mem-mmr to be completely emptied, and then some.
            mmr.rewind(80, &hasher).await.unwrap();
            // Make sure the pinned node boundary is valid by generating a proof for the oldest item.
            mmr.proof(&hasher, prune_loc).await.unwrap();
            // prune all remaining leaves 1 at a time.
            while mmr.size() > prune_pos {
                assert!(mmr.rewind(1, &hasher).await.is_ok());
            }
            assert!(matches!(
                mmr.rewind(1, &hasher).await,
                Err(Error::ElementPruned(_))
            ));

            // Make sure pruning to an older location is a no-op.
            assert!(mmr.prune(prune_loc - 1).await.is_ok());
            assert_eq!(mmr.bounds().start, prune_loc);

            mmr.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_journaled_mmr_rewind_error_leaves_valid_state() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let hasher: Standard<Sha256> = Standard::new();

            // Case 1: rewind partially succeeds, then returns ElementPruned.
            let element_pruned_context = context.with_label("element_pruned_case");
            let mut mmr = Mmr::init(
                element_pruned_context.clone(),
                &hasher,
                test_config(&element_pruned_context),
            )
            .await
            .unwrap();
            let changeset = {
                let mut batch = mmr.new_batch();
                for i in 0u64..32 {
                    batch = batch.add(&hasher, &i.to_be_bytes());
                }
                batch.merkleize(&hasher).finalize()
            };
            mmr.apply(changeset).unwrap();
            mmr.prune(Location::new(8)).await.unwrap();
            let leaves_before = mmr.leaves();
            assert!(matches!(
                mmr.rewind(128, &hasher).await,
                Err(Error::ElementPruned(_))
            ));
            // After error, leaves should reflect any partial rewinds that occurred.
            assert!(mmr.leaves() <= leaves_before);
            mmr.destroy().await.unwrap();

            // Case 2: rewind partially succeeds, then returns Empty.
            let empty_context = context.with_label("empty_case");
            let cfg = test_config(&empty_context);
            let mut mmr = Mmr::init(empty_context, &hasher, cfg).await.unwrap();
            let changeset = {
                let mut batch = mmr.new_batch();
                for i in 0u64..8 {
                    batch = batch.add(&hasher, &i.to_be_bytes());
                }
                batch.merkleize(&hasher).finalize()
            };
            mmr.apply(changeset).unwrap();
            let leaves_before = mmr.leaves();
            assert!(matches!(mmr.rewind(9, &hasher).await, Err(Error::Empty)));
            // Rewind returns error without partial modification.
            assert_eq!(mmr.leaves(), leaves_before);
            mmr.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_journaled_mmr_basic() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let hasher: Standard<Sha256> = Standard::new();
            let cfg = test_config(&context);
            let mut mmr = Mmr::init(context, &hasher, cfg).await.unwrap();
            // Build a test MMR with 255 leaves
            const LEAF_COUNT: usize = 255;
            let mut leaves = Vec::with_capacity(LEAF_COUNT);
            for i in 0..LEAF_COUNT {
                leaves.push(test_digest(i));
            }
            let changeset = {
                let mut batch = mmr.new_batch();
                for leaf in &leaves {
                    batch = batch.add(&hasher, leaf);
                }
                batch.merkleize(&hasher).finalize()
            };
            mmr.apply(changeset).unwrap();
            assert_eq!(mmr.size(), Position::new(502));

            // Generate & verify proof from element that is not yet flushed to the journal.
            const TEST_ELEMENT: usize = 133;
            const TEST_ELEMENT_LOC: Location = Location::new(TEST_ELEMENT as u64);

            let proof = mmr.proof(&hasher, TEST_ELEMENT_LOC).await.unwrap();
            let root = mmr.root();
            assert!(proof.verify_element_inclusion(
                &hasher,
                &leaves[TEST_ELEMENT],
                TEST_ELEMENT_LOC,
                &root,
            ));

            // Sync the MMR, make sure it flushes the in-mem MMR as expected.
            mmr.sync().await.unwrap();

            // Now that the element is flushed from the in-mem MMR, confirm its proof is still is
            // generated correctly.
            let proof2 = mmr.proof(&hasher, TEST_ELEMENT_LOC).await.unwrap();
            assert_eq!(proof, proof2);

            // Generate & verify a proof that spans flushed elements and the last element.
            let range = Location::new(TEST_ELEMENT as u64)..Location::new(LEAF_COUNT as u64);
            let proof = mmr.range_proof(&hasher, range.clone()).await.unwrap();
            assert!(proof.verify_range_inclusion(
                &hasher,
                &leaves[range.to_usize_range()],
                TEST_ELEMENT_LOC,
                &root
            ));

            mmr.destroy().await.unwrap();
        });
    }

    /// Generates a stateful MMR, simulates various partial-write scenarios, and confirms we
    /// appropriately recover to a valid state.
    #[test_traced]
    fn test_journaled_mmr_recovery() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let hasher: Standard<Sha256> = Standard::new();
            let mut mmr = Mmr::init(context.with_label("first"), &hasher, test_config(&context))
                .await
                .unwrap();
            assert_eq!(mmr.size(), 0);

            // Build a test MMR with 252 leaves
            const LEAF_COUNT: usize = 252;
            let mut leaves = Vec::with_capacity(LEAF_COUNT);
            for i in 0..LEAF_COUNT {
                leaves.push(test_digest(i));
            }
            let changeset = {
                let mut batch = mmr.new_batch();
                for leaf in &leaves {
                    batch = batch.add(&hasher, leaf);
                }
                batch.merkleize(&hasher).finalize()
            };
            mmr.apply(changeset).unwrap();
            assert_eq!(mmr.size(), 498);
            let root = mmr.root();
            mmr.sync().await.unwrap();
            drop(mmr);

            // The very last element we added (pos=495) resulted in new parents at positions 496 &
            // 497. Simulate a partial write by corrupting the last page's checksum by truncating
            // the last blob by a single byte.
            let partition: String = "journal-partition-blobs".into();
            let (blob, len) = context
                .open(&partition, &71u64.to_be_bytes())
                .await
                .expect("Failed to open blob");
            // A full page w/ CRC should have been written on sync.
            assert_eq!(len, PAGE_SIZE.get() as u64 + 12);

            // truncate the blob by one byte to corrupt the page CRC.
            blob.resize(len - 1).await.expect("Failed to corrupt blob");
            blob.sync().await.expect("Failed to sync blob");

            let mmr = Mmr::init(context.with_label("second"), &hasher, test_config(&context))
                .await
                .unwrap();
            // Since we didn't corrupt the leaf, the MMR is able to replay the leaf and recover to
            // the previous state.
            assert_eq!(mmr.size(), 498);
            assert_eq!(mmr.root(), root);

            // Make sure dropping it and re-opening it persists the recovered state.
            drop(mmr);
            let mmr = Mmr::init(context.with_label("third"), &hasher, test_config(&context))
                .await
                .unwrap();
            assert_eq!(mmr.size(), 498);

            mmr.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_journaled_mmr_pruning() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let hasher: Standard<Sha256> = Standard::new();
            // make sure pruning doesn't break root computation, adding of new nodes, etc.
            const LEAF_COUNT: usize = 2000;
            let cfg_pruned = test_config(&context);
            let mut pruned_mmr =
                Mmr::init(context.with_label("pruned"), &hasher, cfg_pruned.clone())
                    .await
                    .unwrap();
            let cfg_unpruned = Config {
                journal_partition: "unpruned-journal-partition".into(),
                metadata_partition: "unpruned-metadata-partition".into(),
                items_per_blob: NZU64!(7),
                write_buffer: NZUsize!(1024),
                thread_pool: None,
                page_cache: cfg_pruned.page_cache.clone(),
            };
            let mut mmr = Mmr::init(context.with_label("unpruned"), &hasher, cfg_unpruned)
                .await
                .unwrap();
            let mut leaves = Vec::with_capacity(LEAF_COUNT);
            for i in 0..LEAF_COUNT {
                leaves.push(test_digest(i));
            }
            let changeset = {
                let mut batch = mmr.new_batch();
                for leaf in &leaves {
                    batch = batch.add(&hasher, leaf);
                }
                batch.merkleize(&hasher).finalize()
            };
            mmr.apply(changeset).unwrap();
            let changeset = {
                let mut batch = pruned_mmr.new_batch();
                for leaf in &leaves {
                    batch = batch.add(&hasher, leaf);
                }
                batch.merkleize(&hasher).finalize()
            };
            pruned_mmr.apply(changeset).unwrap();
            assert_eq!(mmr.size(), 3994);
            assert_eq!(pruned_mmr.size(), 3994);

            // Prune the MMR in increments of 10 making sure the journal is still able to compute
            // roots and accept new elements.
            for i in 0usize..300 {
                let prune_loc = Location::new(std::cmp::min(i as u64 * 10, *pruned_mmr.leaves()));
                pruned_mmr.prune(prune_loc).await.unwrap();
                assert_eq!(prune_loc, pruned_mmr.bounds().start);

                let digest = test_digest(LEAF_COUNT + i);
                leaves.push(digest);
                let last_leaf = leaves.last().unwrap();
                let changeset = {
                    let mut batch = pruned_mmr.new_batch();
                    batch = batch.add(&hasher, last_leaf);
                    batch.merkleize(&hasher).finalize()
                };
                pruned_mmr.apply(changeset).unwrap();
                let changeset = {
                    let mut batch = mmr.new_batch();
                    batch = batch.add(&hasher, last_leaf);
                    batch.merkleize(&hasher).finalize()
                };
                mmr.apply(changeset).unwrap();
                assert_eq!(pruned_mmr.root(), mmr.root());
            }

            // Sync the MMRs.
            pruned_mmr.sync().await.unwrap();
            assert_eq!(pruned_mmr.root(), mmr.root());

            // Sync the MMR & reopen.
            pruned_mmr.sync().await.unwrap();
            drop(pruned_mmr);
            let mut pruned_mmr = Mmr::init(
                context.with_label("pruned_reopen"),
                &hasher,
                cfg_pruned.clone(),
            )
            .await
            .unwrap();
            assert_eq!(pruned_mmr.root(), mmr.root());

            // Prune everything.
            let size = pruned_mmr.size();
            pruned_mmr.prune_all().await.unwrap();
            assert_eq!(pruned_mmr.root(), mmr.root());
            let bounds = pruned_mmr.bounds();
            assert!(bounds.is_empty());
            assert_eq!(bounds.start, Location::try_from(size).unwrap());

            // Close MMR after adding a new node without syncing and make sure state is as expected
            // on reopening.
            let changeset = mmr
                .new_batch()
                .add(&hasher, &test_digest(LEAF_COUNT))
                .merkleize(&hasher)
                .finalize();
            mmr.apply(changeset).unwrap();
            let changeset = pruned_mmr
                .new_batch()
                .add(&hasher, &test_digest(LEAF_COUNT))
                .merkleize(&hasher)
                .finalize();
            pruned_mmr.apply(changeset).unwrap();
            assert!(*pruned_mmr.size() % cfg_pruned.items_per_blob != 0);
            pruned_mmr.sync().await.unwrap();
            drop(pruned_mmr);
            let mut pruned_mmr = Mmr::init(
                context.with_label("pruned_reopen2"),
                &hasher,
                cfg_pruned.clone(),
            )
            .await
            .unwrap();
            assert_eq!(pruned_mmr.root(), mmr.root());
            let bounds = pruned_mmr.bounds();
            assert!(!bounds.is_empty());
            assert_eq!(bounds.start, Location::try_from(size).unwrap());

            // Make sure pruning to older location is a no-op.
            assert!(pruned_mmr
                .prune(Location::try_from(size).unwrap() - 1)
                .await
                .is_ok());
            assert_eq!(pruned_mmr.bounds().start, Location::try_from(size).unwrap());

            // Add nodes until we are on a blob boundary, and confirm prune_all still removes all
            // retained nodes.
            while *pruned_mmr.size() % cfg_pruned.items_per_blob != 0 {
                let changeset = {
                    let mut batch = pruned_mmr.new_batch();
                    batch = batch.add(&hasher, &test_digest(LEAF_COUNT));
                    batch.merkleize(&hasher).finalize()
                };
                pruned_mmr.apply(changeset).unwrap();
            }
            pruned_mmr.prune_all().await.unwrap();
            assert!(pruned_mmr.bounds().is_empty());

            pruned_mmr.destroy().await.unwrap();
            mmr.destroy().await.unwrap();
        });
    }

    /// Simulate partial writes after pruning, making sure we recover to a valid state.
    #[test_traced("WARN")]
    fn test_journaled_mmr_recovery_with_pruning() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Build MMR with 2000 leaves.
            let hasher: Standard<Sha256> = Standard::new();
            const LEAF_COUNT: usize = 2000;
            let mut leaves = Vec::with_capacity(LEAF_COUNT);
            let mut mmr = Mmr::init(context.with_label("init"), &hasher, test_config(&context))
                .await
                .unwrap();
            for i in 0..LEAF_COUNT {
                leaves.push(test_digest(i));
            }
            let changeset = {
                let mut batch = mmr.new_batch();
                for leaf in &leaves {
                    batch = batch.add(&hasher, leaf);
                }
                batch.merkleize(&hasher).finalize()
            };
            mmr.apply(changeset).unwrap();
            assert_eq!(mmr.size(), 3994);
            mmr.sync().await.unwrap();
            drop(mmr);

            // Prune the MMR in increments of 50, simulating a partial write after each prune.
            for i in 0usize..200 {
                let label = format!("iter_{i}");
                let mut mmr = Mmr::init(context.with_label(&label), &hasher, test_config(&context))
                    .await
                    .unwrap();
                let start_size = mmr.size();
                let start_leaves = *mmr.leaves();
                let prune_loc = Location::new(std::cmp::min(i as u64 * 50, start_leaves));
                if i % 5 == 0 {
                    mmr.simulate_pruning_failure(prune_loc).await.unwrap();
                    continue;
                }
                mmr.prune(prune_loc).await.unwrap();

                // add new elements, simulating a partial write after each.
                for j in 0..10 {
                    let digest = test_digest(100 * (i + 1) + j);
                    leaves.push(digest);
                    let changeset = {
                        let mut batch = mmr.new_batch();
                        batch = batch.add(&hasher, leaves.last().unwrap());
                        batch = batch.add(&hasher, leaves.last().unwrap());
                        batch.merkleize(&hasher).finalize()
                    };
                    mmr.apply(changeset).unwrap();
                    let digest = test_digest(LEAF_COUNT + i);
                    leaves.push(digest);
                    let changeset = {
                        let mut batch = mmr.new_batch();
                        batch = batch.add(&hasher, leaves.last().unwrap());
                        batch = batch.add(&hasher, leaves.last().unwrap());
                        batch.merkleize(&hasher).finalize()
                    };
                    mmr.apply(changeset).unwrap();
                }
                let end_size = mmr.size();
                let total_to_write = (*end_size - *start_size) as usize;
                let partial_write_limit = i % total_to_write;
                mmr.simulate_partial_sync(partial_write_limit)
                    .await
                    .unwrap();
            }

            let mmr = Mmr::init(context.with_label("final"), &hasher, test_config(&context))
                .await
                .unwrap();
            mmr.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_journaled_mmr_historical_proof_basic() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Create MMR with 10 elements
            let hasher = Standard::<Sha256>::new();
            let cfg = test_config(&context);
            let mut mmr = Mmr::init(context, &hasher, cfg).await.unwrap();
            let mut elements = Vec::new();
            for i in 0..10 {
                elements.push(test_digest(i));
            }
            let changeset = {
                let mut batch = mmr.new_batch();
                for elt in &elements {
                    batch = batch.add(&hasher, elt);
                }
                batch.merkleize(&hasher).finalize()
            };
            mmr.apply(changeset).unwrap();
            let original_leaves = mmr.leaves();

            // Historical proof should match "regular" proof when historical size == current database size
            let historical_proof = mmr
                .historical_range_proof(
                    &hasher,
                    original_leaves,
                    Location::new(2)..Location::new(6),
                )
                .await
                .unwrap();
            assert_eq!(historical_proof.leaves, original_leaves);
            let root = mmr.root();
            assert!(historical_proof.verify_range_inclusion(
                &hasher,
                &elements[2..6],
                Location::new(2),
                &root
            ));
            let regular_proof = mmr
                .range_proof(&hasher, Location::new(2)..Location::new(6))
                .await
                .unwrap();
            assert_eq!(regular_proof.leaves, historical_proof.leaves);
            assert_eq!(regular_proof.digests, historical_proof.digests);

            // Add more elements to the MMR
            for i in 10..20 {
                elements.push(test_digest(i));
            }
            let changeset = {
                let mut batch = mmr.new_batch();
                for elt in &elements[10..20] {
                    batch = batch.add(&hasher, elt);
                }
                batch.merkleize(&hasher).finalize()
            };
            mmr.apply(changeset).unwrap();
            let new_historical_proof = mmr
                .historical_range_proof(
                    &hasher,
                    original_leaves,
                    Location::new(2)..Location::new(6),
                )
                .await
                .unwrap();
            assert_eq!(new_historical_proof.leaves, historical_proof.leaves);
            assert_eq!(new_historical_proof.digests, historical_proof.digests);

            mmr.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_journaled_mmr_historical_proof_with_pruning() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let hasher = Standard::<Sha256>::new();
            let mut mmr = Mmr::init(context.with_label("main"), &hasher, test_config(&context))
                .await
                .unwrap();

            // Add many elements
            let mut elements = Vec::new();
            for i in 0..50 {
                elements.push(test_digest(i));
            }
            let changeset = {
                let mut batch = mmr.new_batch();
                for elt in &elements {
                    batch = batch.add(&hasher, elt);
                }
                batch.merkleize(&hasher).finalize()
            };
            mmr.apply(changeset).unwrap();

            // Prune to leaf 16 (position 30)
            let prune_loc = Location::new(16);
            mmr.prune(prune_loc).await.unwrap();

            // Create reference MMR for verification to get correct size
            let mut ref_mmr = Mmr::init(
                context.with_label("ref"),
                &hasher,
                Config {
                    journal_partition: "ref-journal-pruned".into(),
                    metadata_partition: "ref-metadata-pruned".into(),
                    items_per_blob: NZU64!(7),
                    write_buffer: NZUsize!(1024),
                    thread_pool: None,
                    page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
                },
            )
            .await
            .unwrap();

            let changeset = {
                let mut batch = ref_mmr.new_batch();
                for elt in elements.iter().take(41) {
                    batch = batch.add(&hasher, elt);
                }
                batch.merkleize(&hasher).finalize()
            };
            ref_mmr.apply(changeset).unwrap();
            let historical_leaves = ref_mmr.leaves();
            let historical_root = ref_mmr.root();

            // Test proof at historical position after pruning
            let historical_proof = mmr
                .historical_range_proof(
                    &hasher,
                    historical_leaves,
                    Location::new(35)..Location::new(39),
                )
                .await
                .unwrap();

            assert_eq!(historical_proof.leaves, historical_leaves);

            // Verify proof works despite pruning
            assert!(historical_proof.verify_range_inclusion(
                &hasher,
                &elements[35..39],
                Location::new(35),
                &historical_root
            ));

            ref_mmr.destroy().await.unwrap();
            mmr.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_journaled_mmr_historical_proof_large() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let hasher = Standard::<Sha256>::new();

            let mut mmr = Mmr::init(
                context.with_label("server"),
                &hasher,
                Config {
                    journal_partition: "server-journal".into(),
                    metadata_partition: "server-metadata".into(),
                    items_per_blob: NZU64!(7),
                    write_buffer: NZUsize!(1024),
                    thread_pool: None,
                    page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
                },
            )
            .await
            .unwrap();

            let mut elements = Vec::new();
            for i in 0..100 {
                elements.push(test_digest(i));
            }
            let changeset = {
                let mut batch = mmr.new_batch();
                for elt in &elements {
                    batch = batch.add(&hasher, elt);
                }
                batch.merkleize(&hasher).finalize()
            };
            mmr.apply(changeset).unwrap();

            let range = Location::new(30)..Location::new(61);

            // Only apply elements up to end_loc to the reference MMR.
            let mut ref_mmr = Mmr::init(
                context.with_label("client"),
                &hasher,
                Config {
                    journal_partition: "client-journal".into(),
                    metadata_partition: "client-metadata".into(),
                    items_per_blob: NZU64!(7),
                    write_buffer: NZUsize!(1024),
                    thread_pool: None,
                    page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
                },
            )
            .await
            .unwrap();

            // Add elements up to the end of the range to verify historical root
            let changeset = {
                let mut batch = ref_mmr.new_batch();
                for elt in elements.iter().take(*range.end as usize) {
                    batch = batch.add(&hasher, elt);
                }
                batch.merkleize(&hasher).finalize()
            };
            ref_mmr.apply(changeset).unwrap();
            let historical_leaves = ref_mmr.leaves();
            let expected_root = ref_mmr.root();

            // Generate proof from full MMR
            let proof = mmr
                .historical_range_proof(&hasher, historical_leaves, range.clone())
                .await
                .unwrap();

            assert!(proof.verify_range_inclusion(
                &hasher,
                &elements[range.to_usize_range()],
                range.start,
                &expected_root // Compare to historical (reference) root
            ));

            ref_mmr.destroy().await.unwrap();
            mmr.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_journaled_mmr_historical_proof_singleton() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let hasher = Standard::<Sha256>::new();
            let cfg = test_config(&context);
            let mut mmr = Mmr::init(context, &hasher, cfg).await.unwrap();

            let element = test_digest(0);
            let changeset = mmr
                .new_batch()
                .add(&hasher, &element)
                .merkleize(&hasher)
                .finalize();
            mmr.apply(changeset).unwrap();

            // Test single element proof at historical position
            let single_proof = mmr
                .historical_range_proof(
                    &hasher,
                    Location::new(1),
                    Location::new(0)..Location::new(1),
                )
                .await
                .unwrap();

            let root = mmr.root();
            assert!(single_proof.verify_range_inclusion(
                &hasher,
                &[element],
                Location::new(0),
                &root
            ));

            mmr.destroy().await.unwrap();
        });
    }

    // Test `init_sync` when there is no persisted data.
    #[test_traced]
    fn test_journaled_mmr_init_sync_empty() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let hasher = Standard::<Sha256>::new();

            // Test fresh start scenario with completely new MMR (no existing data)
            let sync_cfg = SyncConfig::<sha256::Digest> {
                config: test_config(&context),
                range: Location::new(0)..Location::new(52),
                pinned_nodes: None,
            };

            let mut sync_mmr = Mmr::init_sync(context.clone(), sync_cfg, &hasher)
                .await
                .unwrap();

            // Should be fresh MMR starting empty
            assert_eq!(sync_mmr.size(), 0);
            let bounds = sync_mmr.bounds();
            assert_eq!(bounds.start, 0);
            assert!(bounds.is_empty());

            // Should be able to add new elements
            let new_element = test_digest(999);
            let changeset = sync_mmr
                .new_batch()
                .add(&hasher, &new_element)
                .merkleize(&hasher)
                .finalize();
            sync_mmr.apply(changeset).unwrap();

            // Root should be computable
            let _root = sync_mmr.root();

            sync_mmr.destroy().await.unwrap();
        });
    }

    // Test `init_sync` where the persisted MMR's persisted nodes match the sync boundaries.
    #[test_traced]
    fn test_journaled_mmr_init_sync_nonempty_exact_match() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let hasher = Standard::<Sha256>::new();

            // Create initial MMR with elements.
            let mut mmr = Mmr::init(context.with_label("init"), &hasher, test_config(&context))
                .await
                .unwrap();
            let changeset = {
                let mut batch = mmr.new_batch();
                for i in 0..50 {
                    batch = batch.add(&hasher, &test_digest(i));
                }
                batch.merkleize(&hasher).finalize()
            };
            mmr.apply(changeset).unwrap();
            mmr.sync().await.unwrap();
            let original_size = mmr.size();
            let original_leaves = mmr.leaves();
            let original_root = mmr.root();

            // Sync with range.start <= existing_size <= range.end should reuse data
            let lower_bound_loc = mmr.bounds().start;
            let upper_bound_loc = mmr.leaves();
            let lower_bound_pos = Position::try_from(lower_bound_loc).unwrap();
            let upper_bound_pos = mmr.size();
            let mut expected_nodes = BTreeMap::new();
            for i in *lower_bound_pos..*upper_bound_pos {
                expected_nodes.insert(
                    Position::new(i),
                    mmr.get_node(Position::new(i)).await.unwrap().unwrap(),
                );
            }
            let sync_cfg = SyncConfig::<sha256::Digest> {
                config: test_config(&context),
                range: lower_bound_loc..upper_bound_loc,
                pinned_nodes: None,
            };

            mmr.sync().await.unwrap();
            drop(mmr);

            let sync_mmr = Mmr::init_sync(context.with_label("sync"), sync_cfg, &hasher)
                .await
                .unwrap();

            // Should have existing data in the sync range.
            assert_eq!(sync_mmr.size(), original_size);
            assert_eq!(sync_mmr.leaves(), original_leaves);
            let bounds = sync_mmr.bounds();
            assert_eq!(bounds.start, lower_bound_loc);
            assert!(!bounds.is_empty());
            assert_eq!(sync_mmr.root(), original_root);
            for pos in *lower_bound_pos..*upper_bound_pos {
                let pos = Position::new(pos);
                assert_eq!(
                    sync_mmr.get_node(pos).await.unwrap(),
                    expected_nodes.get(&pos).cloned()
                );
            }

            sync_mmr.destroy().await.unwrap();
        });
    }

    // Test `init_sync` where the persisted MMR's data partially overlaps with the sync boundaries.
    #[test_traced]
    fn test_journaled_mmr_init_sync_partial_overlap() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let hasher = Standard::<Sha256>::new();

            // Create initial MMR with elements.
            let mut mmr = Mmr::init(context.with_label("init"), &hasher, test_config(&context))
                .await
                .unwrap();
            let changeset = {
                let mut batch = mmr.new_batch();
                for i in 0..30 {
                    batch = batch.add(&hasher, &test_digest(i));
                }
                batch.merkleize(&hasher).finalize()
            };
            mmr.apply(changeset).unwrap();
            mmr.sync().await.unwrap();
            mmr.prune(Location::new(6)).await.unwrap();

            let original_size = mmr.size();
            let original_leaves = mmr.leaves();
            let original_root = mmr.root();
            let original_pruned_to = mmr.bounds().start;
            let original_pruned_to_pos = Position::try_from(original_pruned_to).unwrap();

            // Sync with boundaries that extend beyond existing data (partial overlap).
            let lower_bound_loc = original_pruned_to;
            let upper_bound_loc = original_leaves + 6; // Extend beyond existing data

            let mut expected_nodes = BTreeMap::new();
            for pos in *original_pruned_to_pos..*original_size {
                let pos = Position::new(pos);
                expected_nodes.insert(pos, mmr.get_node(pos).await.unwrap().unwrap());
            }

            let sync_cfg = SyncConfig::<sha256::Digest> {
                config: test_config(&context),
                range: lower_bound_loc..upper_bound_loc,
                pinned_nodes: None,
            };

            mmr.sync().await.unwrap();
            drop(mmr);

            let sync_mmr = Mmr::init_sync(context.with_label("sync"), sync_cfg, &hasher)
                .await
                .unwrap();

            // Should have existing data in the overlapping range.
            assert_eq!(sync_mmr.size(), original_size);
            let bounds = sync_mmr.bounds();
            assert_eq!(bounds.start, lower_bound_loc);
            assert!(!bounds.is_empty());
            assert_eq!(sync_mmr.root(), original_root);

            // Check that existing nodes are preserved in the overlapping range.
            for pos in *original_pruned_to_pos..*original_size {
                let pos = Position::new(pos);
                assert_eq!(
                    sync_mmr.get_node(pos).await.unwrap(),
                    expected_nodes.get(&pos).cloned()
                );
            }

            sync_mmr.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_journaled_mmr_init_sync_rejects_extra_pinned_nodes() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let hasher = Standard::<Sha256>::new();

            let sync_cfg = SyncConfig::<sha256::Digest> {
                config: test_config(&context),
                range: Location::new(6)..Location::new(20),
                pinned_nodes: Some(vec![test_digest(1), test_digest(2), test_digest(3)]),
            };

            let result = Mmr::init_sync(context.with_label("sync"), sync_cfg, &hasher).await;
            assert!(matches!(result, Err(Error::InvalidPinnedNodes)));
        });
    }

    // Regression test that MMR init() handles stale metadata (lower pruning boundary than journal).
    // Before the fix, this would panic with an assertion failure. After the fix, it returns a
    // MissingNode error (which is expected when metadata is corrupted and pinned nodes are lost).
    #[test_traced("WARN")]
    fn test_journaled_mmr_init_stale_metadata_returns_error() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let hasher = Standard::<Sha256>::new();

            // Create an MMR with some data and prune it
            let mut mmr = Mmr::init(context.with_label("init"), &hasher, test_config(&context))
                .await
                .unwrap();

            // Add 50 elements
            let changeset = {
                let mut batch = mmr.new_batch();
                for i in 0..50 {
                    batch = batch.add(&hasher, &test_digest(i));
                }
                batch.merkleize(&hasher).finalize()
            };
            mmr.apply(changeset).unwrap();
            mmr.sync().await.unwrap();

            // Prune enough that the journal boundary's pinned nodes span pruned blobs.
            let prune_loc = Location::new(25);
            mmr.prune(prune_loc).await.unwrap();
            drop(mmr);

            // Simulate a crash after journal prune but before metadata was updated:
            // clear all metadata and write only a stale pruning boundary of 0 (no pinned nodes).
            let meta_cfg = MConfig {
                partition: test_config(&context).metadata_partition,
                codec_config: ((0..).into(), ()),
            };
            let mut metadata =
                Metadata::<_, U64, Vec<u8>>::init(context.with_label("meta_tamper"), meta_cfg)
                    .await
                    .unwrap();
            metadata.clear();
            let key = U64::new(PRUNED_TO_PREFIX, 0);
            metadata.put(key, 0u64.to_be_bytes().to_vec());
            metadata.sync().await.unwrap();
            drop(metadata);

            // Reopen the MMR - before the fix, this would panic with assertion failure
            // After the fix, it returns MissingNode error (pinned nodes for the lower
            // boundary don't exist since they were pruned from journal and weren't
            // stored in metadata at the lower position)
            let result = Mmr::<_, Digest>::init(
                context.with_label("reopened"),
                &hasher,
                test_config(&context),
            )
            .await;

            match result {
                Err(Error::MissingNode(_)) => {} // expected
                Ok(_) => panic!("expected MissingNode error, got Ok"),
                Err(e) => panic!("expected MissingNode error, got {:?}", e),
            }
        });
    }

    // Test that MMR init() handles the case where metadata pruning boundary is ahead
    // of journal (crashed before journal prune completed). This should successfully
    // prune the journal to match metadata.
    #[test_traced("WARN")]
    fn test_journaled_mmr_init_metadata_ahead() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let hasher = Standard::<Sha256>::new();

            // Create an MMR with some data
            let mut mmr = Mmr::init(context.with_label("init"), &hasher, test_config(&context))
                .await
                .unwrap();

            // Add 50 elements
            let changeset = {
                let mut batch = mmr.new_batch();
                for i in 0..50 {
                    batch = batch.add(&hasher, &test_digest(i));
                }
                batch.merkleize(&hasher).finalize()
            };
            mmr.apply(changeset).unwrap();
            mmr.sync().await.unwrap();

            // Prune to position 30 (this stores pinned nodes and updates metadata)
            let prune_loc = Location::new(16);
            mmr.prune(prune_loc).await.unwrap();
            let expected_root = mmr.root();
            let expected_size = mmr.size();
            drop(mmr);

            // Reopen the MMR - should recover correctly with metadata ahead of
            // journal boundary (metadata says 30, journal is section-aligned to 28)
            let mmr = Mmr::init(
                context.with_label("reopened"),
                &hasher,
                test_config(&context),
            )
            .await
            .unwrap();

            assert_eq!(mmr.bounds().start, prune_loc);
            assert_eq!(mmr.size(), expected_size);
            assert_eq!(mmr.root(), expected_root);

            mmr.destroy().await.unwrap();
        });
    }

    // Regression test: init_sync must compute pinned nodes BEFORE pruning the journal. Previously,
    // init_sync would prune the journal first, then try to read pinned nodes from the pruned
    // positions, causing MissingNode errors.
    //
    // Key setup: We create an MMR with data but DON'T prune it, so the metadata has no pinned
    // nodes. Then init_sync must read pinned nodes from the journal before pruning it.
    #[test_traced]
    fn test_journaled_mmr_init_sync_computes_pinned_nodes_before_pruning() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let hasher = Standard::<Sha256>::new();

            // Use small items_per_blob to create many sections and trigger pruning.
            let cfg = Config {
                journal_partition: "mmr-journal".into(),
                metadata_partition: "mmr-metadata".into(),
                items_per_blob: NZU64!(7),
                write_buffer: NZUsize!(64),
                thread_pool: None,
                page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
            };

            // Create MMR with enough elements to span multiple sections.
            let mut mmr = Mmr::init(context.with_label("init"), &hasher, cfg.clone())
                .await
                .unwrap();
            let changeset = {
                let mut batch = mmr.new_batch();
                for i in 0..100 {
                    batch = batch.add(&hasher, &test_digest(i));
                }
                batch.merkleize(&hasher).finalize()
            };
            mmr.apply(changeset).unwrap();
            mmr.sync().await.unwrap();

            // Don't prune - this ensures metadata has no pinned nodes. init_sync will need to
            // read pinned nodes from the journal.
            let original_size = mmr.size();
            let original_root = mmr.root();
            drop(mmr);

            // Reopen via init_sync with range.start > 0. This will prune the journal, so
            // init_sync must read pinned nodes BEFORE pruning or they'll be lost.
            let prune_loc = Location::new(32);
            let sync_cfg = SyncConfig::<sha256::Digest> {
                config: cfg,
                range: prune_loc..Location::new(128),
                pinned_nodes: None, // Force init_sync to compute pinned nodes from journal
            };

            let sync_mmr = Mmr::init_sync(context.with_label("sync"), sync_cfg, &hasher)
                .await
                .unwrap();

            // Verify the MMR state is correct.
            assert_eq!(sync_mmr.size(), original_size);
            assert_eq!(sync_mmr.root(), original_root);
            assert_eq!(sync_mmr.bounds().start, prune_loc);

            sync_mmr.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_journaled_mmr_historical_proof_pruned_elements() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let hasher = Standard::<Sha256>::new();

            let mut mmr = Mmr::init(context.with_label("init"), &hasher, test_config(&context))
                .await
                .unwrap();

            let changeset = {
                let mut batch = mmr.new_batch();
                for i in 0..64 {
                    batch = batch.add(&hasher, &test_digest(i));
                }
                batch.merkleize(&hasher).finalize()
            };
            mmr.apply(changeset).unwrap();

            let prune_loc = Location::new(16);
            mmr.prune(prune_loc).await.unwrap();

            let historical_leaves = mmr.leaves();
            let mut pruned_loc = None;
            for loc_u64 in 0..*historical_leaves {
                let loc = Location::new(loc_u64);
                let result = mmr
                    .historical_range_proof(&hasher, historical_leaves, loc..loc + 1)
                    .await;
                if matches!(result, Err(Error::ElementPruned(_))) {
                    pruned_loc = Some(loc);
                    break;
                }
            }
            let pruned_loc = pruned_loc.expect("expected at least one pruned location");

            // Add more elements and verify pruned elements still return ElementPruned.
            let changeset = {
                let mut batch = mmr.new_batch();
                for i in 0..8 {
                    batch = batch.add(&hasher, &test_digest(10_000 + i));
                }
                batch.merkleize(&hasher).finalize()
            };
            mmr.apply(changeset).unwrap();

            let requested = mmr.leaves();
            let result = mmr
                .historical_range_proof(&hasher, requested, pruned_loc..pruned_loc + 1)
                .await;
            assert!(matches!(result, Err(Error::ElementPruned(_))));

            mmr.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_journaled_mmr_append_while_historical_proof_is_available() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let hasher = Standard::<Sha256>::new();
            let mut mmr = Mmr::init(context.with_label("init"), &hasher, test_config(&context))
                .await
                .unwrap();

            let changeset = {
                let mut batch = mmr.new_batch();
                for i in 0..20 {
                    batch = batch.add(&hasher, &test_digest(i));
                }
                batch.merkleize(&hasher).finalize()
            };
            mmr.apply(changeset).unwrap();

            let historical_leaves = Location::new(10);
            let range = Location::new(2)..Location::new(8);

            // Appends should remain allowed while historical proofs are available.
            let changeset = mmr
                .new_batch()
                .add(&hasher, &test_digest(100))
                .add(&hasher, &test_digest(101))
                .merkleize(&hasher)
                .finalize();
            mmr.apply(changeset).unwrap();

            let proof = mmr
                .historical_range_proof(&hasher, historical_leaves, range.clone())
                .await
                .unwrap();

            let expected = mmr
                .historical_range_proof(&hasher, historical_leaves, range)
                .await
                .unwrap();
            assert_eq!(proof, expected);

            mmr.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_journaled_mmr_historical_proof_after_sync_reads_from_journal() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let hasher = Standard::<Sha256>::new();
            let mut mmr = Mmr::init(context.with_label("init"), &hasher, test_config(&context))
                .await
                .unwrap();

            let changeset = {
                let mut batch = mmr.new_batch();
                for i in 0..64 {
                    batch = batch.add(&hasher, &test_digest(i));
                }
                batch.merkleize(&hasher).finalize()
            };
            mmr.apply(changeset).unwrap();
            mmr.sync().await.unwrap();

            let historical_leaves = Location::new(20);
            let range = Location::new(5)..Location::new(15);
            let expected = mmr
                .historical_range_proof(&hasher, historical_leaves, range.clone())
                .await
                .unwrap();

            // After sync, mem should be pruned (data lives in journal).
            let (mem_start, journal_start) = {
                let inner = mmr.inner.read();
                (
                    inner.mem.bounds().start,
                    Location::try_from(inner.pruned_to_pos).unwrap(),
                )
            };
            assert!(mem_start > journal_start);

            let actual = mmr
                .historical_range_proof(&hasher, historical_leaves, range)
                .await
                .unwrap();
            assert_eq!(actual, expected);

            mmr.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_journaled_mmr_historical_proof_after_pruning() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let hasher = Standard::<Sha256>::new();
            let mut mmr = Mmr::init(context.with_label("init"), &hasher, test_config(&context))
                .await
                .unwrap();

            let changeset = {
                let mut batch = mmr.new_batch();
                for i in 0..30 {
                    batch = batch.add(&hasher, &test_digest(i));
                }
                batch.merkleize(&hasher).finalize()
            };
            mmr.apply(changeset).unwrap();

            let prune_loc = Location::new(10);
            mmr.prune(prune_loc).await.unwrap();

            let requested = Location::new(20);
            let range = prune_loc..requested;
            let proof = mmr
                .historical_range_proof(&hasher, requested, range)
                .await
                .unwrap();
            assert!(proof.leaves > Location::new(0));

            mmr.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_journaled_mmr_historical_proof_edge_cases() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let hasher = Standard::<Sha256>::new();

            // Case 1: Empty MMR.
            let mmr = Mmr::init(context.with_label("empty"), &hasher, test_config(&context))
                .await
                .unwrap();
            let empty_end = Location::new(0);
            let empty_result = mmr
                .historical_range_proof(&hasher, empty_end, empty_end..empty_end)
                .await;
            assert!(matches!(empty_result, Err(Error::Empty)));
            let oob_result = mmr
                .historical_range_proof(&hasher, empty_end + 1, empty_end..empty_end + 1)
                .await;
            assert!(matches!(
                oob_result,
                Err(Error::RangeOutOfBounds(loc)) if loc == empty_end + 1
            ));
            mmr.destroy().await.unwrap();

            // Case 2: MMR has nodes but is fully pruned.
            let mut mmr = Mmr::init(
                context.with_label("fully_pruned"),
                &hasher,
                test_config(&context),
            )
            .await
            .unwrap();
            let changeset = {
                let mut batch = mmr.new_batch();
                for i in 0..20 {
                    batch = batch.add(&hasher, &test_digest(i));
                }
                batch.merkleize(&hasher).finalize()
            };
            mmr.apply(changeset).unwrap();
            let end = mmr.leaves();
            mmr.prune_all().await.unwrap();
            assert!(mmr.bounds().is_empty());
            let pruned_result = mmr.historical_range_proof(&hasher, end, end - 1..end).await;
            assert!(matches!(pruned_result, Err(Error::ElementPruned(_))));
            let oob_result = mmr
                .historical_range_proof(&hasher, end + 1, end - 1..end)
                .await;
            assert!(matches!(
                oob_result,
                Err(Error::RangeOutOfBounds(loc)) if loc == end + 1
            ));
            mmr.destroy().await.unwrap();

            // Case 3: All nodes but one (single leaf) are pruned.
            let mut mmr = Mmr::init(
                context.with_label("single_leaf"),
                &hasher,
                test_config(&context),
            )
            .await
            .unwrap();
            let changeset = {
                let mut batch = mmr.new_batch();
                for i in 0..11 {
                    batch = batch.add(&hasher, &test_digest(i));
                }
                batch.merkleize(&hasher).finalize()
            };
            mmr.apply(changeset).unwrap();
            let end = mmr.leaves();
            let keep_loc = end - 1;
            mmr.prune(keep_loc).await.unwrap();
            let ok_result = mmr
                .historical_range_proof(&hasher, end, keep_loc..end)
                .await;
            assert!(ok_result.is_ok());
            let pruned_end = keep_loc - 1;
            // make sure this is in a pruned range, considering blob boundaries.
            let start_loc = Location::new(1);
            let pruned_result = mmr
                .historical_range_proof(&hasher, end, start_loc..pruned_end + 1)
                .await;
            assert!(matches!(pruned_result, Err(Error::ElementPruned(_))));
            let oob_result = mmr
                .historical_range_proof(&hasher, end + 1, keep_loc..end)
                .await;
            assert!(matches!(oob_result, Err(Error::RangeOutOfBounds(_))));
            mmr.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_journaled_mmr_historical_proof_out_of_bounds() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let hasher = Standard::<Sha256>::new();
            let mut mmr = Mmr::init(context.with_label("oob"), &hasher, test_config(&context))
                .await
                .unwrap();

            let changeset = {
                let mut batch = mmr.new_batch();
                for i in 0..8 {
                    batch = batch.add(&hasher, &test_digest(i));
                }
                batch.merkleize(&hasher).finalize()
            };
            mmr.apply(changeset).unwrap();
            let requested = mmr.leaves() + 1;

            let result = mmr
                .historical_range_proof(&hasher, requested, Location::new(0)..requested)
                .await;
            assert!(matches!(
                result,
                Err(Error::RangeOutOfBounds(loc)) if loc == requested
            ));

            mmr.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_journaled_mmr_historical_proof_range_validation() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let hasher = Standard::<Sha256>::new();
            let mut mmr = Mmr::init(
                context.with_label("range_validation"),
                &hasher,
                test_config(&context),
            )
            .await
            .unwrap();

            let changeset = {
                let mut batch = mmr.new_batch();
                for i in 0..32 {
                    batch = batch.add(&hasher, &test_digest(i));
                }
                batch.merkleize(&hasher).finalize()
            };
            mmr.apply(changeset).unwrap();

            let valid_range = Location::new(0)..Location::new(1);

            // Empty range should report Empty.
            let requested = Location::new(5);
            let empty_range = requested..requested;
            let empty_result = mmr
                .historical_range_proof(&hasher, requested, empty_range)
                .await;
            assert!(matches!(empty_result, Err(Error::Empty)));

            // Requested historical size is out of bounds.
            let leaves_oob = mmr.leaves() + 1;
            let result = mmr
                .historical_range_proof(&hasher, leaves_oob, valid_range.clone())
                .await;
            assert!(matches!(
                result,
                Err(Error::RangeOutOfBounds(loc)) if loc == leaves_oob
            ));

            // Requested range end is out of bounds for the current MMR.
            let end_oob = mmr.leaves() + 1;
            let range_oob = Location::new(0)..end_oob;
            let result = mmr
                .historical_range_proof(&hasher, requested, range_oob)
                .await;
            assert!(matches!(
                result,
                Err(Error::RangeOutOfBounds(loc)) if loc == end_oob
            ));

            // Requested range end out of bounds for the requested historical size but within MMR.
            let range_end_gt_requested = requested + 1;
            let range_oob_at_requested = Location::new(0)..range_end_gt_requested;
            assert!(range_end_gt_requested <= mmr.leaves());
            let result = mmr
                .historical_range_proof(&hasher, requested, range_oob_at_requested)
                .await;
            assert!(matches!(
                result,
                Err(Error::RangeOutOfBounds(loc)) if loc == range_end_gt_requested
            ));

            // Range location overflow is caught as out-of-bounds (the bounds check
            // fires before the position conversion that would detect overflow).
            let overflow_loc = Location::new(u64::MAX);
            let overflow_range = Location::new(0)..overflow_loc;
            let result = mmr
                .historical_range_proof(&hasher, requested, overflow_range)
                .await;
            assert!(matches!(
                result,
                Err(Error::RangeOutOfBounds(loc)) if loc == overflow_loc
            ));

            mmr.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_journaled_mmr_historical_proof_non_size_prune_excludes_pruned_leaves() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let hasher = Standard::<Sha256>::new();
            let mut mmr = Mmr::init(
                context.with_label("non_size_prune"),
                &hasher,
                test_config(&context),
            )
            .await
            .unwrap();

            let changeset = {
                let mut batch = mmr.new_batch();
                for i in 0..16 {
                    batch = batch.add(&hasher, &test_digest(i));
                }
                batch.merkleize(&hasher).finalize()
            };
            mmr.apply(changeset).unwrap();

            let end = mmr.leaves();
            let mut failures = Vec::new();
            for prune_leaf in 1..*end {
                let prune_loc = Location::new(prune_leaf);
                mmr.prune(prune_loc).await.unwrap();
                for loc_u64 in 0..*end {
                    let loc = Location::new(loc_u64);
                    let range_includes_pruned_leaf = loc < prune_loc;
                    match mmr.historical_proof(&hasher, end, loc).await {
                        Ok(_) => {}
                        Err(Error::ElementPruned(_)) if range_includes_pruned_leaf => {}
                        Err(Error::ElementPruned(_)) => failures.push(format!(
                            "prune_loc={prune_loc} loc={loc} returned ElementPruned without a pruned range element"
                        )),
                        Err(err) => failures
                            .push(format!("prune_loc={prune_loc} loc={loc} err={err}")),
                    }
                }
            }

            assert!(
                failures.is_empty(),
                "historical proof generation returned unexpected errors: {failures:?}"
            );

            mmr.destroy().await.unwrap();
        });
    }

    /// Create batch A, merkleize, create batch B via `merkleized_a.new_batch()`,
    /// merkleize, flatten changeset, apply, and verify root matches a reference MMR.
    #[test_traced]
    fn test_journaled_mmr_batch_stacking() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let hasher: Standard<Sha256> = Standard::new();

            // Build base journaled MMR with 10 elements.
            let mut mmr = Mmr::init(
                context.clone(),
                &Standard::<Sha256>::new(),
                test_config(&context),
            )
            .await
            .unwrap();

            let changeset = {
                let mut batch = mmr.new_batch();
                for i in 0u64..10 {
                    let element = hasher.digest(&i.to_be_bytes());
                    batch = batch.add(&hasher, &element);
                }
                batch.merkleize(&hasher).finalize()
            };
            mmr.apply(changeset).unwrap();
            mmr.sync().await.unwrap();

            // Batch A: add 5 elements.
            let mut batch_a = mmr.new_batch();
            for i in 10u64..15 {
                let element = hasher.digest(&i.to_be_bytes());
                batch_a = batch_a.add(&hasher, &element);
            }
            let merkleized_a = batch_a.merkleize(&hasher);

            // Batch B on merkleized A: add 5 more elements.
            let mut batch_b = merkleized_a.new_batch();
            for i in 15u64..20 {
                let element = hasher.digest(&i.to_be_bytes());
                batch_b = batch_b.add(&hasher, &element);
            }
            let merkleized_b = batch_b.merkleize(&hasher);
            let expected_root = merkleized_b.root();

            // Flatten and apply.
            let changeset = merkleized_b.finalize();
            drop(merkleized_a);
            mmr.apply(changeset).unwrap();
            assert_eq!(mmr.root(), expected_root);

            // Build a reference in-memory MMR with 20 elements to verify.
            let empty = mem::Mmr::new(&hasher);
            let reference = build_test_mmr(&hasher, empty, 20);
            assert_eq!(mmr.root(), *reference.root());

            mmr.destroy().await.unwrap();
        });
    }

    /// Regression: init_sync must recover from a journal left at an invalid MMR size
    /// (e.g., a crash wrote a leaf but not its parent nodes).
    #[test_traced]
    fn test_init_sync_recovers_from_invalid_journal_size() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let hasher = Standard::<Sha256>::new();

            // Build an MMR with 3 leaves (valid size = 4), sync, and drop.
            let mut mmr = Mmr::init(context.with_label("init"), &hasher, test_config(&context))
                .await
                .unwrap();
            let changeset = {
                let mut batch = mmr.new_batch();
                for i in 0..3 {
                    batch = batch.add(&hasher, &test_digest(i));
                }
                batch.merkleize(&hasher).finalize()
            };
            mmr.apply(changeset).unwrap();
            assert_eq!(mmr.size(), 4);
            let valid_size = mmr.size();
            let valid_root = mmr.root();
            mmr.sync().await.unwrap();
            drop(mmr);

            // Append one extra digest to the journal, simulating a crash that wrote a
            // leaf (for the 4th element) but not its parent nodes. This makes the
            // journal size = 5, which is not a valid MMR size (4 is valid for 3 leaves,
            // 7 is valid for 4 leaves).
            {
                let journal: Journal<_, Digest> = Journal::init(
                    context.with_label("corrupt"),
                    JConfig {
                        partition: "journal-partition".into(),
                        items_per_blob: NZU64!(7),
                        write_buffer: NZUsize!(1024),
                        page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
                    },
                )
                .await
                .unwrap();
                assert_eq!(journal.size().await, valid_size);
                journal.append(&Sha256::hash(b"orphan")).await.unwrap();
                journal.sync().await.unwrap();
                assert_eq!(journal.size().await, valid_size + 1);
            }

            // init_sync should recover by rewinding to the last valid size.
            let sync_cfg = SyncConfig::<Digest> {
                config: test_config(&context),
                range: Location::new(0)..Location::new(100),
                pinned_nodes: None,
            };
            let sync_mmr = Mmr::init_sync(context.with_label("sync"), sync_cfg, &hasher)
                .await
                .unwrap();

            assert_eq!(sync_mmr.size(), valid_size);
            assert_eq!(sync_mmr.root(), valid_root);

            sync_mmr.destroy().await.unwrap();
        });
    }

    /// Regression: init_sync's "fresh start" path (journal data entirely before sync range)
    /// calls clear_to_size which changes the journal size, but journal_size must be re-read
    /// afterward. Without the re-read, nodes_to_pin and the mem_mmr are initialized with a
    /// stale size, causing incorrect pinned nodes or init failure.
    #[test_traced]
    fn test_init_sync_fresh_start_updates_journal_size() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let hasher = Standard::<Sha256>::new();

            // Build an MMR with 5 leaves (size 8), sync, drop.
            let mut mmr = Mmr::init(context.with_label("init"), &hasher, test_config(&context))
                .await
                .unwrap();
            let changeset = {
                let mut batch = mmr.new_batch();
                for i in 0..5 {
                    batch = batch.add(&hasher, &test_digest(i));
                }
                batch.merkleize(&hasher).finalize()
            };
            mmr.apply(changeset).unwrap();
            mmr.sync().await.unwrap();
            drop(mmr);

            // Build a reference MMR to 100 leaves to get valid pinned nodes for the
            // sync boundary.
            let ref_cfg = Config {
                journal_partition: "ref-journal".into(),
                metadata_partition: "ref-metadata".into(),
                items_per_blob: NZU64!(7),
                write_buffer: NZUsize!(1024),
                thread_pool: None,
                page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
            };
            let mut ref_mmr = Mmr::init(context.with_label("ref"), &hasher, ref_cfg)
                .await
                .unwrap();
            let changeset = {
                let mut batch = ref_mmr.new_batch();
                for i in 0..100 {
                    batch = batch.add(&hasher, &test_digest(i));
                }
                batch.merkleize(&hasher).finalize()
            };
            ref_mmr.apply(changeset).unwrap();
            let expected_size = ref_mmr.size();
            let prune_pos = Position::try_from(Location::new(100)).unwrap();
            let mut pinned = Vec::new();
            for pos in nodes_to_pin(prune_pos) {
                pinned.push(ref_mmr.get_node(pos).await.unwrap().unwrap());
            }
            ref_mmr.destroy().await.unwrap();

            // init_sync with range starting beyond the existing data triggers the
            // "fresh start" path (clear_to_size).
            let sync_cfg = SyncConfig::<Digest> {
                config: test_config(&context),
                range: Location::new(100)..Location::new(200),
                pinned_nodes: Some(pinned),
            };
            let mut sync_mmr = Mmr::init_sync(context.with_label("sync"), sync_cfg, &hasher)
                .await
                .unwrap();

            // The MMR should have size matching the prune boundary position.
            assert_eq!(sync_mmr.size(), expected_size);

            // Should be able to add new elements without panic.
            let changeset = {
                let mut batch = sync_mmr.new_batch();
                batch = batch.add(&hasher, &test_digest(999));
                batch.merkleize(&hasher).finalize()
            };
            sync_mmr.apply(changeset).unwrap();

            sync_mmr.destroy().await.unwrap();
        });
    }

    #[test]
    fn test_stale_changeset() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let hasher: Standard<Sha256> = Standard::new();
            let mut mmr = Mmr::init(
                context.clone(),
                &Standard::<Sha256>::new(),
                test_config(&context),
            )
            .await
            .unwrap();

            // Create two batches from the same base.
            let changeset_a = mmr
                .new_batch()
                .add(&hasher, b"leaf-a")
                .merkleize(&hasher)
                .finalize();
            let changeset_b = mmr
                .new_batch()
                .add(&hasher, b"leaf-b")
                .merkleize(&hasher)
                .finalize();

            // Apply A -- should succeed.
            mmr.apply(changeset_a).unwrap();

            // Apply B -- should fail (stale).
            let result = mmr.apply(changeset_b);
            assert!(
                matches!(result, Err(Error::StaleChangeset { .. })),
                "expected StaleChangeset, got {result:?}"
            );

            mmr.destroy().await.unwrap();
        });
    }

    /// Regression: update_leaf on a synced-out leaf must return ElementPruned, not panic.
    /// Before the fix, Readable::pruned_to_pos returned the journal's prune boundary
    /// (which could be 0), so the batch accepted the update. During merkleize, get_node
    /// returned None for the synced-out sibling and hit an expect panic.
    #[test_traced]
    fn test_update_leaf_after_sync_returns_pruned() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let hasher = Standard::<Sha256>::new();
            let mut mmr = Mmr::init(context.clone(), &hasher, test_config(&context))
                .await
                .unwrap();

            // Add 50 elements and sync (flushes all nodes to journal, prunes mem_mmr).
            let changeset = {
                let mut batch = mmr.new_batch();
                for i in 0..50 {
                    batch = batch.add(&hasher, &test_digest(i));
                }
                batch.merkleize(&hasher).finalize()
            };
            mmr.apply(changeset).unwrap();
            mmr.sync().await.unwrap();

            // Attempt to update leaf 0 which has been synced out of memory.
            let batch = mmr.new_batch();
            let result = batch.update_leaf(&hasher, Location::new(0), b"updated");
            assert!(matches!(result, Err(Error::ElementPruned(_))));

            mmr.destroy().await.unwrap();
        });
    }
}
