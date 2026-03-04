//! An MMR backed by a fixed-item-length journal.
//!
//! Thin wrapper around the generic [`crate::merkle::journaled`] module, fixing the Merkle family
//! to [`super::Mmr`] and the in-memory representation to [`mem::CleanMmr`].

pub use crate::merkle::journaled::Config;
use crate::{
    merkle::{self},
    mmr::{mem, storage::Storage, verification, Error, Location, Position, Proof},
};
use commonware_cryptography::Digest;
use commonware_runtime::{Clock, Metrics, Storage as RStorage};
use core::ops::Range;

/// Sync configuration for a journal-backed MMR.
pub type SyncConfig<D> = crate::merkle::journaled::SyncConfig<super::Mmr, D>;

/// A clean (merkleized) journaled MMR.
pub type CleanMmr<E, D> = merkle::journaled::Clean<super::Mmr, E, D, mem::CleanMmr<D>>;

/// A dirty (unmerkleized) journaled MMR.
pub type DirtyMmr<E, D> = merkle::journaled::Dirty<super::Mmr, E, D, mem::CleanMmr<D>>;

/// Backward-compatible alias so callers can write `Mmr::init(...)`.
pub type Mmr<E, D> = CleanMmr<E, D>;

/// Trait mapping MMR mem state types to the corresponding journaled MMR type.
///
/// This is used by [`crate::journal::authenticated::Journal`] to remain generic over the
/// Clean/Dirty state of the underlying journaled MMR.
pub trait State<D: Digest>: Send + Sync + 'static {
    /// The journaled MMR type for this state.
    type JournaledMmr<E: RStorage + Clock + Metrics>: Send + Sync;
}

impl<D: Digest> State<D> for mem::Dirty {
    type JournaledMmr<E: RStorage + Clock + Metrics> = DirtyMmr<E, D>;
}

impl<D: Digest> State<D> for mem::Clean<D> {
    type JournaledMmr<E: RStorage + Clock + Metrics> = CleanMmr<E, D>;
}

// ---------------------------------------------------------------------------
// Storage trait impls
// ---------------------------------------------------------------------------

impl<E: RStorage + Clock + Metrics + Sync, D: Digest> Storage<super::Mmr, D> for CleanMmr<E, D> {
    async fn size(&self) -> Position {
        self.size()
    }

    async fn get_node(&self, position: Position) -> Result<Option<D>, Error> {
        self.get_node(position).await
    }
}

impl<E: RStorage + Clock + Metrics + Sync, D: Digest> Storage<super::Mmr, D> for DirtyMmr<E, D> {
    async fn size(&self) -> Position {
        self.size()
    }

    async fn get_node(&self, position: Position) -> Result<Option<D>, Error> {
        // Delegate to the DirtyMmr-specific get_node which respects merkleization boundary.
        Self::get_node(self, position).await
    }
}

// ---------------------------------------------------------------------------
// CleanMmr-specific methods (proofs)
// ---------------------------------------------------------------------------

impl<E: RStorage + Clock + Metrics, D: Digest> CleanMmr<E, D> {
    /// Return an inclusion proof for the element at the location `loc` against a historical MMR
    /// state with `leaves` leaves.
    ///
    /// # Errors
    ///
    /// - Returns [Error::RangeOutOfBounds] if `leaves` is greater than `self.leaves()` or if `loc`
    ///   is not provable at that historical size.
    /// - Returns [Error::LocationOverflow] if `loc` exceeds [crate::mmr::MAX_LOCATION].
    /// - Returns [Error::ElementPruned] if some element needed to generate the proof has been
    ///   pruned.
    pub async fn historical_proof(
        &self,
        leaves: Location,
        loc: Location,
    ) -> Result<Proof<D>, Error> {
        if !loc.is_valid() {
            return Err(Error::LocationOverflow(loc));
        }
        // loc is valid so it won't overflow from + 1
        self.historical_range_proof(leaves, loc..loc + 1).await
    }

    /// Return an inclusion proof for the elements in `range` against a historical MMR state with
    /// `leaves` leaves.
    ///
    /// # Errors
    ///
    /// - Returns [Error::RangeOutOfBounds] if `leaves` is greater than `self.leaves()` or if `range`
    ///   is not provable at that historical size.
    /// - Returns [Error::LocationOverflow] if any location in `range` exceeds
    ///   [crate::mmr::MAX_LOCATION].
    /// - Returns [Error::ElementPruned] if some element needed to generate the proof has been
    ///   pruned.
    /// - Returns [Error::Empty] if the range is empty.
    pub async fn historical_range_proof(
        &self,
        leaves: Location,
        range: Range<Location>,
    ) -> Result<Proof<D>, Error> {
        if leaves > self.leaves() {
            return Err(Error::RangeOutOfBounds(leaves));
        }
        verification::historical_range_proof(self, leaves, range).await
    }

    /// Return an inclusion proof for the element at the location `loc` that can be verified against
    /// the current root.
    ///
    /// # Errors
    ///
    /// - Returns [Error::LocationOverflow] if `loc` exceeds [crate::mmr::MAX_LOCATION].
    /// - Returns [Error::ElementPruned] if some element needed to generate the proof has been
    ///   pruned.
    /// - Returns [Error::Empty] if the range is empty.
    pub async fn proof(&self, loc: Location) -> Result<Proof<D>, Error> {
        if !loc.is_valid() {
            return Err(Error::LocationOverflow(loc));
        }
        // loc is valid so it won't overflow from + 1
        self.range_proof(loc..loc + 1).await
    }

    /// Return an inclusion proof for the elements within the specified location range.
    ///
    /// Locations are validated by [verification::range_proof].
    ///
    /// # Errors
    ///
    /// - Returns [Error::LocationOverflow] if any location in `range` exceeds
    ///   [crate::mmr::MAX_LOCATION].
    /// - Returns [Error::ElementPruned] if some element needed to generate the proof has been
    ///   pruned.
    /// - Returns [Error::Empty] if the range is empty.
    pub async fn range_proof(&self, range: Range<Location>) -> Result<Proof<D>, Error> {
        self.historical_range_proof(self.leaves(), range).await
    }
}

// ---------------------------------------------------------------------------
// DirtyMmr-specific methods (proofs, get_node)
// ---------------------------------------------------------------------------

impl<E: RStorage + Clock + Metrics, D: Digest> DirtyMmr<E, D> {
    /// Return an inclusion proof for the element at the location `loc` against a historical MMR
    /// state with `leaves` leaves if the MMR is sufficiently merkleized, returning
    /// [Error::Unmerkleized] otherwise.
    ///
    /// # Errors
    ///
    /// - Returns [Error::RangeOutOfBounds] if `leaves` is greater than `self.leaves()` or if `loc`
    ///   is not provable at that historical size.
    /// - Returns [Error::Unmerkleized] if `leaves` is greater than `self.merkleized_leaves()`.
    /// - Returns [Error::LocationOverflow] if `loc` exceeds [crate::mmr::MAX_LOCATION].
    /// - Returns [Error::ElementPruned] if some element needed to generate the proof has been
    ///   pruned.
    pub async fn historical_proof(
        &self,
        leaves: Location,
        loc: Location,
    ) -> Result<Proof<D>, Error> {
        if !loc.is_valid() {
            return Err(Error::LocationOverflow(loc));
        }
        // loc is valid so it won't overflow from + 1
        self.historical_range_proof(leaves, loc..loc + 1).await
    }

    /// Return an inclusion proof for the elements in `range` against a historical MMR state with
    /// `leaves` leaves if the MMR is sufficiently merkleized, returning [Error::Unmerkleized]
    /// otherwise.
    ///
    /// # Errors
    ///
    /// - Returns [Error::RangeOutOfBounds] if `leaves` is greater than `self.leaves()` or if `range`
    ///   is not provable at that historical size.
    /// - Returns [Error::Unmerkleized] if generating the proof requires nodes at or beyond the
    ///   current merkleized frontier.
    /// - Returns [Error::LocationOverflow] if any location in `range` exceeds
    ///   [crate::mmr::MAX_LOCATION].
    /// - Returns [Error::ElementPruned] if some element needed to generate the proof has been
    ///   pruned.
    /// - Returns [Error::Empty] if the range is empty.
    pub async fn historical_range_proof(
        &self,
        leaves: Location,
        range: Range<Location>,
    ) -> Result<Proof<D>, Error> {
        // Validate requested range.  Even though historical_range_proof performs most of these
        // validations, we'd like to return the other potential errors if they hold instead of
        // [Error::Unmerkleized] to avoid a fruitless retry after merkleizing.
        let size = self.size();
        let merkleized_size = self.merkleized_size();
        let pruned_to_pos = self.pruned_to_pos();

        let requested_size = Position::try_from(leaves)?;
        let end_pos = Position::try_from(range.end)?;
        if requested_size > size {
            return Err(Error::RangeOutOfBounds(leaves));
        }
        if range.is_empty() {
            return Err(Error::Empty);
        }
        if range.end > leaves {
            return Err(Error::RangeOutOfBounds(range.end));
        }
        if end_pos > size {
            return Err(Error::RangeOutOfBounds(range.end));
        }
        let start_pos = Position::try_from(range.start)?;
        if start_pos < pruned_to_pos {
            return Err(Error::ElementPruned(start_pos));
        }

        // Finally if no other error conditions hold, check that the requested range is merkleized.
        if requested_size > merkleized_size {
            return Err(Error::Unmerkleized);
        }

        verification::historical_range_proof(self, leaves, range).await
    }

    /// Return the node digest at `position`, respecting the merkleization boundary.
    ///
    /// Nodes at or beyond the merkleized frontier return `None`. For nodes within the merkleized
    /// region, the in-memory cache is checked first, then the metadata and journal.
    pub async fn get_node(&self, position: Position) -> Result<Option<D>, Error> {
        let (merkleized_size, mem_bounds) = self.merkleized_size_and_mem_bounds();

        // Return None for unmerkleized nodes should they be requested.
        if position >= merkleized_size {
            return Ok(None);
        }

        // If the requested node is in the mem mmr, use that.
        if position >= mem_bounds.start && position < mem_bounds.end {
            return Ok(Some(self.get_node_in_mem_unchecked(position)));
        }

        // Otherwise get the node from the metadata+journal. If it's missing it must be due to
        // pruning, so we swallow MissingNode errors.
        match self.get_from_metadata_or_journal(position).await {
            Ok(digest) => Ok(Some(digest)),
            Err(Error::MissingNode(_)) => Ok(None),
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mmr::{
        conformance::build_test_mmr, hasher::Hasher as _, mem, Location, LocationRangeExt as _,
        StandardHasher as Standard,
    };
    use commonware_cryptography::{
        sha256::{self, Digest},
        Hasher, Sha256,
    };
    use commonware_macros::test_traced;
    use commonware_runtime::{
        buffer::paged::CacheRef, deterministic, Blob as _, BufferPooler, Runner,
    };
    use commonware_utils::{NZUsize, NZU16, NZU64};
    use std::num::{NonZeroU16, NonZeroUsize};

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
            let mut hasher: Standard<Sha256> = Standard::new();
            let test_mmr = mem::CleanMmr::new(&mut hasher);
            let test_mmr = build_test_mmr(&mut hasher, test_mmr, NUM_ELEMENTS);
            let expected_root = test_mmr.root();

            let journaled_mmr = Mmr::init(
                context.clone(),
                &mut Standard::<Sha256>::new(),
                test_config(&context),
            )
            .await
            .unwrap()
            .into_dirty();

            for i in 0u64..NUM_ELEMENTS {
                hasher.inner().update(&i.to_be_bytes());
                let element = hasher.inner().finalize();
                journaled_mmr.add(&mut hasher, &element).unwrap();
            }

            let journaled_mmr = journaled_mmr.merkleize(&mut hasher);
            assert_eq!(journaled_mmr.root(), *expected_root);

            journaled_mmr.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_journaled_mmr_empty() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut hasher: Standard<Sha256> = Standard::new();
            let mut mmr = Mmr::init(
                context.with_label("first"),
                &mut hasher,
                test_config(&context),
            )
            .await
            .unwrap();
            assert_eq!(mmr.size(), 0);
            assert!(mmr.get_node(Position::new(0)).await.is_err());
            let bounds = mmr.bounds();
            assert!(bounds.is_empty());
            assert!(mmr.prune_all().await.is_ok());
            assert_eq!(bounds.start, 0);
            assert!(mmr.prune_to_pos(Position::new(0)).await.is_ok());
            assert!(mmr.sync().await.is_ok());
            let mut mmr = mmr.into_dirty();
            assert!(matches!(mmr.pop(1).await, Err(Error::Empty)));

            mmr.add(&mut hasher, &test_digest(0)).unwrap();
            assert_eq!(mmr.size(), 1);
            let mmr = mmr.merkleize(&mut hasher);
            mmr.sync().await.unwrap();
            assert!(mmr.get_node(Position::new(0)).await.is_ok());
            let mut mmr = mmr.into_dirty();
            assert!(mmr.pop(1).await.is_ok());
            assert_eq!(mmr.size(), 0);
            let mmr = mmr.merkleize(&mut hasher);
            mmr.sync().await.unwrap();

            let mmr = Mmr::init(
                context.with_label("second"),
                &mut hasher,
                test_config(&context),
            )
            .await
            .unwrap();
            assert_eq!(mmr.size(), 0);

            let empty_proof = Proof::default();
            let mut hasher: Standard<Sha256> = Standard::new();
            let root = mmr.root();
            assert!(empty_proof.verify_range_inclusion(
                &mut hasher,
                &[] as &[Digest],
                Location::new(0),
                &root
            ));
            assert!(empty_proof.verify_multi_inclusion(
                &mut hasher,
                &[] as &[(Digest, Location)],
                &root
            ));

            // Confirm empty proof no longer verifies after adding an element.
            let mmr = mmr.into_dirty();
            mmr.add(&mut hasher, &test_digest(0)).unwrap();
            let mmr = mmr.merkleize(&mut hasher);
            let root = mmr.root();
            assert!(!empty_proof.verify_range_inclusion(
                &mut hasher,
                &[] as &[Digest],
                Location::new(0),
                &root
            ));
            assert!(!empty_proof.verify_multi_inclusion(
                &mut hasher,
                &[] as &[(Digest, Location)],
                &root
            ));

            mmr.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_journaled_mmr_pop() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            const NUM_ELEMENTS: u64 = 200;

            let mut hasher: Standard<Sha256> = Standard::new();
            let cfg = test_config(&context);
            let mut mmr = Mmr::init(context, &mut hasher, cfg)
                .await
                .unwrap()
                .into_dirty();

            let mut c_hasher = Sha256::new();
            for i in 0u64..NUM_ELEMENTS {
                c_hasher.update(&i.to_be_bytes());
                let element = c_hasher.finalize();
                mmr.add(&mut hasher, &element).unwrap();
            }

            // Pop off one node at a time without syncing until empty, confirming the root matches.
            for i in (0..NUM_ELEMENTS).rev() {
                assert!(mmr.pop(1).await.is_ok());
                let clean_mmr = mmr.merkleize(&mut hasher);
                let root = clean_mmr.root();
                let mut reference_mmr = mem::DirtyMmr::new();
                for j in 0..i {
                    c_hasher.update(&j.to_be_bytes());
                    let element = c_hasher.finalize();
                    reference_mmr.add(&mut hasher, &element);
                }
                let reference_mmr = reference_mmr.merkleize(&mut hasher, None);
                assert_eq!(
                    root,
                    *reference_mmr.root(),
                    "root mismatch after pop at {i}"
                );
                mmr = clean_mmr.into_dirty();
            }
            assert!(matches!(mmr.pop(1).await, Err(Error::Empty)));
            assert!(mmr.pop(0).await.is_ok());

            // Repeat the test though sync part of the way to tip to test crossing the boundary from
            // cached to uncached leaves, and pop 2 at a time instead of just 1.
            for i in 0u64..NUM_ELEMENTS {
                c_hasher.update(&i.to_be_bytes());
                let element = c_hasher.finalize();
                mmr.add(&mut hasher, &element).unwrap();
                if i == 101 {
                    let clean_mmr = mmr.merkleize(&mut hasher);
                    clean_mmr.sync().await.unwrap();
                    mmr = clean_mmr.into_dirty();
                }
            }

            for i in (0..NUM_ELEMENTS - 1).rev().step_by(2) {
                assert!(mmr.pop(2).await.is_ok(), "at position {i:?}");
                let clean_mmr = mmr.merkleize(&mut hasher);
                let root = clean_mmr.root();
                let reference_mmr = mem::CleanMmr::new(&mut hasher);
                let reference_mmr = build_test_mmr(&mut hasher, reference_mmr, i);
                assert_eq!(
                    root,
                    *reference_mmr.root(),
                    "root mismatch at position {i:?}"
                );
                mmr = clean_mmr.into_dirty();
            }
            assert!(matches!(mmr.pop(99).await, Err(Error::Empty)));

            // Repeat one more time only after pruning the MMR first.
            for i in 0u64..NUM_ELEMENTS {
                c_hasher.update(&i.to_be_bytes());
                let element = c_hasher.finalize();
                mmr.add(&mut hasher, &element).unwrap();
                if i == 101 {
                    let clean_mmr = mmr.merkleize(&mut hasher);
                    clean_mmr.sync().await.unwrap();
                    mmr = clean_mmr.into_dirty();
                }
            }
            let mut mmr = mmr.merkleize(&mut hasher);
            let leaf_pos = Position::try_from(Location::new(50)).unwrap();
            mmr.prune_to_pos(leaf_pos).await.unwrap();
            // Pop enough nodes to cause the mem-mmr to be completely emptied, and then some.
            let mut mmr = mmr.into_dirty();
            mmr.pop(80).await.unwrap();
            let mmr = mmr.merkleize(&mut hasher);
            // Make sure the pinned node boundary is valid by generating a proof for the oldest item.
            mmr.proof(Location::try_from(leaf_pos).unwrap())
                .await
                .unwrap();
            // prune all remaining leaves 1 at a time.
            let mut mmr = mmr.into_dirty();
            while mmr.size() > leaf_pos {
                assert!(mmr.pop(1).await.is_ok());
            }
            assert!(matches!(mmr.pop(1).await, Err(Error::ElementPruned(_))));

            // Make sure pruning to an older location is a no-op.
            let mut mmr = mmr.merkleize(&mut hasher);
            assert!(mmr.prune_to_pos(leaf_pos - 1).await.is_ok());
            assert_eq!(mmr.bounds().start, leaf_pos);

            mmr.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_journaled_mmr_pop_error_clamps_merkleized_size() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut hasher: Standard<Sha256> = Standard::new();

            // Case 1: pop partially succeeds, then returns ElementPruned.
            let element_pruned_context = context.with_label("element_pruned_case");
            let mmr = Mmr::init(
                element_pruned_context.clone(),
                &mut hasher,
                test_config(&element_pruned_context),
            )
            .await
            .unwrap()
            .into_dirty();
            for i in 0u64..32 {
                mmr.add(&mut hasher, &i.to_be_bytes()).unwrap();
            }
            let mut mmr = mmr.merkleize(&mut hasher);
            mmr.prune_to_pos(Position::try_from(Location::new(8)).unwrap())
                .await
                .unwrap();
            let mut mmr = mmr.into_dirty();
            assert_eq!(mmr.merkleized_leaves(), mmr.leaves());
            assert!(matches!(mmr.pop(128).await, Err(Error::ElementPruned(_))));
            assert_eq!(mmr.merkleized_leaves(), mmr.leaves());
            mmr.merkleize(&mut hasher).destroy().await.unwrap();

            // Case 2: pop partially succeeds, then returns Empty.
            let empty_context = context.with_label("empty_case");
            let cfg = test_config(&empty_context);
            let mmr = Mmr::init(empty_context, &mut hasher, cfg)
                .await
                .unwrap()
                .into_dirty();
            for i in 0u64..8 {
                mmr.add(&mut hasher, &i.to_be_bytes()).unwrap();
            }
            let mut mmr = mmr.merkleize(&mut hasher).into_dirty();
            assert_eq!(mmr.merkleized_leaves(), mmr.leaves());
            assert!(matches!(mmr.pop(9).await, Err(Error::Empty)));
            assert_eq!(mmr.leaves(), Location::new(0));
            assert_eq!(mmr.merkleized_leaves(), Location::new(0));
            mmr.merkleize(&mut hasher).destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_journaled_mmr_basic() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut hasher: Standard<Sha256> = Standard::new();
            let cfg = test_config(&context);
            let mmr = Mmr::init(context, &mut hasher, cfg).await.unwrap();
            // Build a test MMR with 255 leaves
            const LEAF_COUNT: usize = 255;
            let mut leaves = Vec::with_capacity(LEAF_COUNT);
            let mut positions = Vec::with_capacity(LEAF_COUNT);
            let mmr = mmr.into_dirty();
            for i in 0..LEAF_COUNT {
                let digest = test_digest(i);
                leaves.push(digest);
                let pos = mmr.add(&mut hasher, leaves.last().unwrap()).unwrap();
                positions.push(pos);
            }
            let mmr = mmr.merkleize(&mut hasher);
            assert_eq!(mmr.size(), Position::new(502));

            // Generate & verify proof from element that is not yet flushed to the journal.
            const TEST_ELEMENT: usize = 133;
            const TEST_ELEMENT_LOC: Location = Location::new(TEST_ELEMENT as u64);

            let proof = mmr.proof(TEST_ELEMENT_LOC).await.unwrap();
            let root = mmr.root();
            assert!(proof.verify_element_inclusion(
                &mut hasher,
                &leaves[TEST_ELEMENT],
                TEST_ELEMENT_LOC,
                &root,
            ));

            // Sync the MMR, make sure it flushes the in-mem MMR as expected.
            mmr.sync().await.unwrap();

            // Now that the element is flushed from the in-mem MMR, confirm its proof is still is
            // generated correctly.
            let proof2 = mmr.proof(TEST_ELEMENT_LOC).await.unwrap();
            assert_eq!(proof, proof2);

            // Generate & verify a proof that spans flushed elements and the last element.
            let range = Location::new(TEST_ELEMENT as u64)..Location::new(LEAF_COUNT as u64);
            let proof = mmr.range_proof(range.clone()).await.unwrap();
            assert!(proof.verify_range_inclusion(
                &mut hasher,
                &leaves[range.to_usize_range()],
                TEST_ELEMENT_LOC,
                &root
            ));

            mmr.destroy().await.unwrap();
        });
    }

    #[test_traced]
    /// Generates a stateful MMR, simulates various partial-write scenarios, and confirms we
    /// appropriately recover to a valid state.
    fn test_journaled_mmr_recovery() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut hasher: Standard<Sha256> = Standard::new();
            let mmr = Mmr::init(
                context.with_label("first"),
                &mut hasher,
                test_config(&context),
            )
            .await
            .unwrap()
            .into_dirty();
            assert_eq!(mmr.size(), 0);

            // Build a test MMR with 252 leaves
            const LEAF_COUNT: usize = 252;
            let mut leaves = Vec::with_capacity(LEAF_COUNT);
            let mut positions = Vec::with_capacity(LEAF_COUNT);
            for i in 0..LEAF_COUNT {
                let digest = test_digest(i);
                leaves.push(digest);
                let pos = mmr.add(&mut hasher, leaves.last().unwrap()).unwrap();
                positions.push(pos);
            }
            let mmr = mmr.merkleize(&mut hasher);
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

            let mmr = Mmr::init(
                context.with_label("second"),
                &mut hasher,
                test_config(&context),
            )
            .await
            .unwrap();
            // Since we didn't corrupt the leaf, the MMR is able to replay the leaf and recover to
            // the previous state.
            assert_eq!(mmr.size(), 498);
            assert_eq!(mmr.root(), root);

            // Make sure dropping it and re-opening it persists the recovered state.
            drop(mmr);
            let mmr = Mmr::init(
                context.with_label("third"),
                &mut hasher,
                test_config(&context),
            )
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
            let mut hasher: Standard<Sha256> = Standard::new();
            // make sure pruning doesn't break root computation, adding of new nodes, etc.
            const LEAF_COUNT: usize = 2000;
            let cfg_pruned = test_config(&context);
            let pruned_mmr = Mmr::init(
                context.with_label("pruned"),
                &mut hasher,
                cfg_pruned.clone(),
            )
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
            let mmr = Mmr::init(context.with_label("unpruned"), &mut hasher, cfg_unpruned)
                .await
                .unwrap()
                .into_dirty();
            let mut leaves = Vec::with_capacity(LEAF_COUNT);
            let mut positions = Vec::with_capacity(LEAF_COUNT);
            let pruned_mmr = pruned_mmr.into_dirty();
            for i in 0..LEAF_COUNT {
                let digest = test_digest(i);
                leaves.push(digest);
                let last_leaf = leaves.last().unwrap();
                let pos = mmr.add(&mut hasher, last_leaf).unwrap();
                positions.push(pos);
                pruned_mmr.add(&mut hasher, last_leaf).unwrap();
            }
            let mut mmr = mmr.merkleize(&mut hasher);
            let mut pruned_mmr = pruned_mmr.merkleize(&mut hasher);
            assert_eq!(mmr.size(), 3994);
            assert_eq!(pruned_mmr.size(), 3994);

            // Prune the MMR in increments of 10 making sure the journal is still able to compute
            // roots and accept new elements.
            for i in 0usize..300 {
                let prune_pos = i as u64 * 10;
                pruned_mmr
                    .prune_to_pos(Position::new(prune_pos))
                    .await
                    .unwrap();
                assert_eq!(prune_pos, pruned_mmr.bounds().start);

                let digest = test_digest(LEAF_COUNT + i);
                leaves.push(digest);
                let last_leaf = leaves.last().unwrap();
                let dirty_pruned_mmr = pruned_mmr.into_dirty();
                let pos = dirty_pruned_mmr.add(&mut hasher, last_leaf).unwrap();
                pruned_mmr = dirty_pruned_mmr.merkleize(&mut hasher);
                positions.push(pos);
                let dirty_mmr = mmr.into_dirty();
                dirty_mmr.add(&mut hasher, last_leaf).unwrap();
                mmr = dirty_mmr.merkleize(&mut hasher);
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
                &mut hasher,
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
            assert_eq!(bounds.start, size);

            // Close MMR after adding a new node without syncing and make sure state is as expected
            // on reopening.
            let mmr = mmr.into_dirty();
            mmr.add(&mut hasher, &test_digest(LEAF_COUNT)).unwrap();
            let mmr = mmr.merkleize(&mut hasher);
            let dirty_pruned = pruned_mmr.into_dirty();
            dirty_pruned
                .add(&mut hasher, &test_digest(LEAF_COUNT))
                .unwrap();
            let pruned_mmr = dirty_pruned.merkleize(&mut hasher);
            assert!(*pruned_mmr.size() % cfg_pruned.items_per_blob != 0);
            pruned_mmr.sync().await.unwrap();
            drop(pruned_mmr);
            let mut pruned_mmr = Mmr::init(
                context.with_label("pruned_reopen2"),
                &mut hasher,
                cfg_pruned.clone(),
            )
            .await
            .unwrap();
            assert_eq!(pruned_mmr.root(), mmr.root());
            let bounds = pruned_mmr.bounds();
            assert!(!bounds.is_empty());
            assert_eq!(bounds.start, size);

            // Make sure pruning to older location is a no-op.
            assert!(pruned_mmr.prune_to_pos(size - 1).await.is_ok());
            assert_eq!(pruned_mmr.bounds().start, size);

            // Add nodes until we are on a blob boundary, and confirm prune_all still removes all
            // retained nodes.
            while *pruned_mmr.size() % cfg_pruned.items_per_blob != 0 {
                let dirty_pruned_mmr = pruned_mmr.into_dirty();
                dirty_pruned_mmr
                    .add(&mut hasher, &test_digest(LEAF_COUNT))
                    .unwrap();
                pruned_mmr = dirty_pruned_mmr.merkleize(&mut hasher);
            }
            pruned_mmr.prune_all().await.unwrap();
            assert!(pruned_mmr.bounds().is_empty());

            pruned_mmr.destroy().await.unwrap();
            mmr.destroy().await.unwrap();
        });
    }

    #[test_traced("WARN")]
    /// Simulate partial writes after pruning, making sure we recover to a valid state.
    fn test_journaled_mmr_recovery_with_pruning() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Build MMR with 2000 leaves.
            let mut hasher: Standard<Sha256> = Standard::new();
            const LEAF_COUNT: usize = 2000;
            let mmr = Mmr::init(
                context.with_label("init"),
                &mut hasher,
                test_config(&context),
            )
            .await
            .unwrap()
            .into_dirty();
            let mut leaves = Vec::with_capacity(LEAF_COUNT);
            let mut positions = Vec::with_capacity(LEAF_COUNT);
            for i in 0..LEAF_COUNT {
                let digest = test_digest(i);
                leaves.push(digest);
                let last_leaf = leaves.last().unwrap();
                let pos = mmr.add(&mut hasher, last_leaf).unwrap();
                positions.push(pos);
            }
            let mmr = mmr.merkleize(&mut hasher);
            assert_eq!(mmr.size(), 3994);
            mmr.sync().await.unwrap();
            drop(mmr);

            // Prune the MMR in increments of 50, simulating a partial write after each prune.
            for i in 0usize..200 {
                let label = format!("iter_{i}");
                let mut mmr = Mmr::init(
                    context.with_label(&label),
                    &mut hasher,
                    test_config(&context),
                )
                .await
                .unwrap();
                let start_size = mmr.size();
                let prune_pos = std::cmp::min(i as u64 * 50, *start_size);
                let prune_pos = Position::new(prune_pos);
                if i % 5 == 0 {
                    mmr.simulate_pruning_failure(prune_pos).await.unwrap();
                    continue;
                }
                mmr.prune_to_pos(prune_pos).await.unwrap();

                // add 25 new elements, simulating a partial write after each.
                for j in 0..10 {
                    let digest = test_digest(100 * (i + 1) + j);
                    leaves.push(digest);
                    let last_leaf = leaves.last().unwrap();
                    let dirty_mmr = mmr.into_dirty();
                    let pos = dirty_mmr.add(&mut hasher, last_leaf).unwrap();
                    positions.push(pos);
                    dirty_mmr.add(&mut hasher, last_leaf).unwrap();
                    mmr = dirty_mmr.merkleize(&mut hasher);
                    let digest = test_digest(LEAF_COUNT + i);
                    leaves.push(digest);
                    let last_leaf = leaves.last().unwrap();
                    let dirty_mmr = mmr.into_dirty();
                    let pos = dirty_mmr.add(&mut hasher, last_leaf).unwrap();
                    positions.push(pos);
                    dirty_mmr.add(&mut hasher, last_leaf).unwrap();
                    mmr = dirty_mmr.merkleize(&mut hasher);
                }
                let end_size = mmr.size();
                let total_to_write = (*end_size - *start_size) as usize;
                let partial_write_limit = i % total_to_write;
                mmr.simulate_partial_sync(partial_write_limit)
                    .await
                    .unwrap();
            }

            let mmr = Mmr::init(
                context.with_label("final"),
                &mut hasher,
                test_config(&context),
            )
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
            let mut hasher = Standard::<Sha256>::new();
            let cfg = test_config(&context);
            let mmr = Mmr::init(context, &mut hasher, cfg)
                .await
                .unwrap()
                .into_dirty();
            let mut elements = Vec::new();
            let mut positions = Vec::new();
            for i in 0..10 {
                elements.push(test_digest(i));
                positions.push(mmr.add(&mut hasher, &elements[i]).unwrap());
            }
            let mmr = mmr.merkleize(&mut hasher);
            let original_leaves = mmr.leaves();

            // Historical proof should match "regular" proof when historical size == current database size
            let historical_proof = mmr
                .historical_range_proof(original_leaves, Location::new(2)..Location::new(6))
                .await
                .unwrap();
            assert_eq!(historical_proof.leaves, original_leaves);
            let root = mmr.root();
            assert!(historical_proof.verify_range_inclusion(
                &mut hasher,
                &elements[2..6],
                Location::new(2),
                &root
            ));
            let regular_proof = mmr
                .range_proof(Location::new(2)..Location::new(6))
                .await
                .unwrap();
            assert_eq!(regular_proof.leaves, historical_proof.leaves);
            assert_eq!(regular_proof.digests, historical_proof.digests);

            // Add more elements to the MMR
            let mmr = mmr.into_dirty();
            for i in 10..20 {
                elements.push(test_digest(i));
                positions.push(mmr.add(&mut hasher, &elements[i]).unwrap());
            }
            let mmr = mmr.merkleize(&mut hasher);
            let new_historical_proof = mmr
                .historical_range_proof(original_leaves, Location::new(2)..Location::new(6))
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
            let mut hasher = Standard::<Sha256>::new();
            let mmr = Mmr::init(
                context.with_label("main"),
                &mut hasher,
                test_config(&context),
            )
            .await
            .unwrap();

            // Add many elements
            let mut elements = Vec::new();
            let mut positions = Vec::new();
            let mmr = mmr.into_dirty();
            for i in 0..50 {
                elements.push(test_digest(i));
                positions.push(mmr.add(&mut hasher, &elements[i]).unwrap());
            }
            let mut mmr = mmr.merkleize(&mut hasher);

            // Prune to position 30
            let prune_pos = Position::new(30);
            mmr.prune_to_pos(prune_pos).await.unwrap();

            // Create reference MMR for verification to get correct size
            let ref_mmr = Mmr::init(
                context.with_label("ref"),
                &mut hasher,
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

            let ref_mmr = ref_mmr.into_dirty();
            for elt in elements.iter().take(41) {
                ref_mmr.add(&mut hasher, elt).unwrap();
            }
            let ref_mmr = ref_mmr.merkleize(&mut hasher);
            let historical_leaves = ref_mmr.leaves();
            let historical_root = ref_mmr.root();

            // Test proof at historical position after pruning
            let historical_proof = mmr
                .historical_range_proof(historical_leaves, Location::new(35)..Location::new(39))
                .await
                .unwrap();

            assert_eq!(historical_proof.leaves, historical_leaves);

            // Verify proof works despite pruning
            assert!(historical_proof.verify_range_inclusion(
                &mut hasher,
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
            let mut hasher = Standard::<Sha256>::new();

            let mmr = Mmr::init(
                context.with_label("server"),
                &mut hasher,
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
            let mut positions = Vec::new();
            let mmr = mmr.into_dirty();
            for i in 0..100 {
                elements.push(test_digest(i));
                positions.push(mmr.add(&mut hasher, &elements[i]).unwrap());
            }
            let mmr = mmr.merkleize(&mut hasher);

            let range = Location::new(30)..Location::new(61);

            // Only apply elements up to end_loc to the reference MMR.
            let ref_mmr = Mmr::init(
                context.with_label("client"),
                &mut hasher,
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
            let ref_mmr = ref_mmr.into_dirty();
            for elt in elements.iter().take(*range.end as usize) {
                ref_mmr.add(&mut hasher, elt).unwrap();
            }
            let ref_mmr = ref_mmr.merkleize(&mut hasher);
            let historical_leaves = ref_mmr.leaves();
            let expected_root = ref_mmr.root();

            // Generate proof from full MMR
            let proof = mmr
                .historical_range_proof(historical_leaves, range.clone())
                .await
                .unwrap();

            assert!(proof.verify_range_inclusion(
                &mut hasher,
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
            let mut hasher = Standard::<Sha256>::new();
            let cfg = test_config(&context);
            let mmr = Mmr::init(context, &mut hasher, cfg)
                .await
                .unwrap()
                .into_dirty();

            let element = test_digest(0);
            mmr.add(&mut hasher, &element).unwrap();
            let mmr = mmr.merkleize(&mut hasher);

            // Test single element proof at historical position
            let single_proof = mmr
                .historical_range_proof(Location::new(1), Location::new(0)..Location::new(1))
                .await
                .unwrap();

            let root = mmr.root();
            assert!(single_proof.verify_range_inclusion(
                &mut hasher,
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
            let mut hasher = Standard::<Sha256>::new();

            // Test fresh start scenario with completely new MMR (no existing data)
            let sync_cfg = SyncConfig::<sha256::Digest> {
                config: test_config(&context),
                range: Position::new(0)..Position::new(100),
                pinned_nodes: None,
            };

            let sync_mmr = Mmr::init_sync(context.clone(), sync_cfg, &mut hasher)
                .await
                .unwrap();

            // Should be fresh MMR starting empty
            assert_eq!(sync_mmr.size(), 0);
            let bounds = sync_mmr.bounds();
            assert_eq!(bounds.start, 0);
            assert!(bounds.is_empty());

            // Should be able to add new elements
            let new_element = test_digest(999);
            let sync_mmr = sync_mmr.into_dirty();
            sync_mmr.add(&mut hasher, &new_element).unwrap();
            let sync_mmr = sync_mmr.merkleize(&mut hasher);

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
            let mut hasher = Standard::<Sha256>::new();

            // Create initial MMR with elements.
            let mmr = Mmr::init(
                context.with_label("init"),
                &mut hasher,
                test_config(&context),
            )
            .await
            .unwrap();
            let mmr = mmr.into_dirty();
            for i in 0..50 {
                mmr.add(&mut hasher, &test_digest(i)).unwrap();
            }
            let mmr = mmr.merkleize(&mut hasher);
            mmr.sync().await.unwrap();
            let original_size = mmr.size();
            let original_leaves = mmr.leaves();
            let original_root = mmr.root();

            // Sync with range.start <= existing_size <= range.end should reuse data
            let lower_bound_pos = mmr.bounds().start;
            let upper_bound_pos = mmr.size();
            let mut expected_nodes = std::collections::BTreeMap::new();
            for i in *lower_bound_pos..*upper_bound_pos {
                expected_nodes.insert(
                    Position::new(i),
                    mmr.get_node(Position::new(i)).await.unwrap().unwrap(),
                );
            }
            let sync_cfg = SyncConfig::<sha256::Digest> {
                config: test_config(&context),
                range: lower_bound_pos..upper_bound_pos,
                pinned_nodes: None,
            };

            mmr.sync().await.unwrap();
            drop(mmr);

            let sync_mmr = Mmr::init_sync(context.with_label("sync"), sync_cfg, &mut hasher)
                .await
                .unwrap();

            // Should have existing data in the sync range.
            assert_eq!(sync_mmr.size(), original_size);
            assert_eq!(sync_mmr.leaves(), original_leaves);
            let bounds = sync_mmr.bounds();
            assert_eq!(bounds.start, lower_bound_pos);
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
            let mut hasher = Standard::<Sha256>::new();

            // Create initial MMR with elements.
            let mmr = Mmr::init(
                context.with_label("init"),
                &mut hasher,
                test_config(&context),
            )
            .await
            .unwrap();
            let mmr = mmr.into_dirty();
            for i in 0..30 {
                mmr.add(&mut hasher, &test_digest(i)).unwrap();
            }
            let mut mmr = mmr.merkleize(&mut hasher);
            mmr.sync().await.unwrap();
            mmr.prune_to_pos(Position::new(10)).await.unwrap();

            let original_size = mmr.size();
            let original_root = mmr.root();
            let original_pruned_to = mmr.bounds().start;

            // Sync with boundaries that extend beyond existing data (partial overlap).
            let lower_bound_pos = original_pruned_to;
            let upper_bound_pos = original_size + 11; // Extend beyond existing data

            let mut expected_nodes = std::collections::BTreeMap::new();
            for pos in *lower_bound_pos..*original_size {
                let pos = Position::new(pos);
                expected_nodes.insert(pos, mmr.get_node(pos).await.unwrap().unwrap());
            }

            let sync_cfg = SyncConfig::<sha256::Digest> {
                config: test_config(&context),
                range: lower_bound_pos..upper_bound_pos,
                pinned_nodes: None,
            };

            mmr.sync().await.unwrap();
            drop(mmr);

            let sync_mmr = Mmr::init_sync(context.with_label("sync"), sync_cfg, &mut hasher)
                .await
                .unwrap();

            // Should have existing data in the overlapping range.
            assert_eq!(sync_mmr.size(), original_size);
            let bounds = sync_mmr.bounds();
            assert_eq!(bounds.start, lower_bound_pos);
            assert!(!bounds.is_empty());
            assert_eq!(sync_mmr.root(), original_root);

            // Check that existing nodes are preserved in the overlapping range.
            for pos in *lower_bound_pos..*original_size {
                let pos = Position::new(pos);
                assert_eq!(
                    sync_mmr.get_node(pos).await.unwrap(),
                    expected_nodes.get(&pos).cloned()
                );
            }

            sync_mmr.destroy().await.unwrap();
        });
    }

    // Regression test that MMR init() handles stale metadata (lower pruning boundary than journal).
    // Before the fix, this would panic with an assertion failure. After the fix, it returns a
    // MissingNode error (which is expected when metadata is corrupted and pinned nodes are lost).
    #[test_traced("WARN")]
    fn test_journaled_mmr_init_stale_metadata_returns_error() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            use crate::metadata::{Config as MConfig, Metadata};
            use commonware_utils::sequence::prefixed_u64::U64;

            const PRUNE_TO_POS_PREFIX: u8 = 1;

            let mut hasher = Standard::<Sha256>::new();

            // Create an MMR with some data and prune it
            let mmr = Mmr::init(
                context.with_label("init"),
                &mut hasher,
                test_config(&context),
            )
            .await
            .unwrap();

            // Add 50 elements
            let mmr = mmr.into_dirty();
            for i in 0..50 {
                mmr.add(&mut hasher, &test_digest(i)).unwrap();
            }
            let mut mmr = mmr.merkleize(&mut hasher);
            mmr.sync().await.unwrap();

            // Prune to position 20 (this stores pinned nodes in metadata for position 20)
            let prune_pos = Position::new(20);
            mmr.prune_to_pos(prune_pos).await.unwrap();
            drop(mmr);

            // Tamper with metadata to have a stale (lower) pruning boundary
            let meta_cfg = MConfig {
                partition: test_config(&context).metadata_partition,
                codec_config: ((0..).into(), ()),
            };
            let mut metadata =
                Metadata::<_, U64, Vec<u8>>::init(context.with_label("meta_tamper"), meta_cfg)
                    .await
                    .unwrap();

            // Set pruning boundary to 0 (stale)
            let key = U64::new(PRUNE_TO_POS_PREFIX, 0);
            metadata.put(key, 0u64.to_be_bytes().to_vec());
            metadata.sync().await.unwrap();
            drop(metadata);

            // Reopen the MMR - before the fix, this would panic with assertion failure
            // After the fix, it returns MissingNode error (pinned nodes for the lower
            // boundary don't exist since they were pruned from journal and weren't
            // stored in metadata at the lower position)
            let result = CleanMmr::<_, Digest>::init(
                context.with_label("reopened"),
                &mut hasher,
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
            let mut hasher = Standard::<Sha256>::new();

            // Create an MMR with some data
            let mmr = Mmr::init(
                context.with_label("init"),
                &mut hasher,
                test_config(&context),
            )
            .await
            .unwrap()
            .into_dirty();

            // Add 50 elements
            for i in 0..50 {
                mmr.add(&mut hasher, &test_digest(i)).unwrap();
            }
            let mut mmr = mmr.merkleize(&mut hasher);
            mmr.sync().await.unwrap();

            // Prune to position 30 (this stores pinned nodes and updates metadata)
            let prune_pos = Position::new(30);
            mmr.prune_to_pos(prune_pos).await.unwrap();
            let expected_root = mmr.root();
            let expected_size = mmr.size();
            drop(mmr);

            // Reopen the MMR - should recover correctly with metadata ahead of
            // journal boundary (metadata says 30, journal is section-aligned to 28)
            let mmr = Mmr::init(
                context.with_label("reopened"),
                &mut hasher,
                test_config(&context),
            )
            .await
            .unwrap();

            assert_eq!(mmr.bounds().start, prune_pos);
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
            let mut hasher = Standard::<Sha256>::new();

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
            let mmr = Mmr::init(context.with_label("init"), &mut hasher, cfg.clone())
                .await
                .unwrap();
            let mmr = mmr.into_dirty();
            for i in 0..100 {
                mmr.add(&mut hasher, &test_digest(i)).unwrap();
            }
            let mmr = mmr.merkleize(&mut hasher);
            mmr.sync().await.unwrap();

            // Don't prune - this ensures metadata has no pinned nodes. init_sync will need to
            // read pinned nodes from the journal.
            let original_size = mmr.size();
            let original_root = mmr.root();
            drop(mmr);

            // Reopen via init_sync with range.start > 0. This will prune the journal, so
            // init_sync must read pinned nodes BEFORE pruning or they'll be lost.
            let prune_pos = Position::new(50);
            let sync_cfg = SyncConfig::<sha256::Digest> {
                config: cfg,
                range: prune_pos..Position::new(200),
                pinned_nodes: None, // Force init_sync to compute pinned nodes from journal
            };

            let sync_mmr = Mmr::init_sync(context.with_label("sync"), sync_cfg, &mut hasher)
                .await
                .unwrap();

            // Verify the MMR state is correct.
            assert_eq!(sync_mmr.size(), original_size);
            assert_eq!(sync_mmr.root(), original_root);
            assert_eq!(sync_mmr.bounds().start, prune_pos);

            sync_mmr.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_journaled_mmr_dirty_historical_proof_requires_merkleization() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut hasher = Standard::<Sha256>::new();

            let mmr = Mmr::init(
                context.with_label("init"),
                &mut hasher,
                test_config(&context),
            )
            .await
            .unwrap()
            .into_dirty();

            for i in 0..64 {
                mmr.add(&mut hasher, &test_digest(i)).unwrap();
            }

            let historical_leaves = Location::new(11);
            let range = Location::new(3)..Location::new(9);
            let result = mmr
                .historical_range_proof(historical_leaves, range.clone())
                .await;
            assert!(matches!(result, Err(Error::Unmerkleized)));

            let clean = mmr.merkleize(&mut hasher);
            let proof = clean
                .historical_range_proof(historical_leaves, range.clone())
                .await
                .unwrap();
            let expected = clean
                .historical_range_proof(historical_leaves, range)
                .await
                .unwrap();
            assert_eq!(proof, expected);

            clean.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_journaled_mmr_dirty_get_node_unmerkleized_returns_none() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut hasher = Standard::<Sha256>::new();

            let mmr = Mmr::init(
                context.with_label("init"),
                &mut hasher,
                test_config(&context),
            )
            .await
            .unwrap()
            .into_dirty();

            mmr.add(&mut hasher, &test_digest(0)).unwrap();
            let mmr = mmr.merkleize(&mut hasher).into_dirty();

            let pos = mmr.add(&mut hasher, &test_digest(1)).unwrap();
            let node = mmr.get_node(pos).await.unwrap();
            assert!(
                node.is_none(),
                "unmerkleized position should not be readable"
            );

            mmr.merkleize(&mut hasher).destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_journaled_mmr_dirty_historical_proof_pruned_precedes_unmerkleized() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut hasher = Standard::<Sha256>::new();

            let mmr = Mmr::init(
                context.with_label("init"),
                &mut hasher,
                test_config(&context),
            )
            .await
            .unwrap()
            .into_dirty();

            for i in 0..64 {
                mmr.add(&mut hasher, &test_digest(i)).unwrap();
            }

            let mut clean = mmr.merkleize(&mut hasher);
            let prune_pos = Position::try_from(Location::new(16)).unwrap();
            clean.prune_to_pos(prune_pos).await.unwrap();

            let historical_leaves = clean.leaves();
            let mut pruned_loc = None;
            for loc_u64 in 0..*historical_leaves {
                let loc = Location::new(loc_u64);
                let result = clean
                    .historical_range_proof(historical_leaves, loc..loc + 1)
                    .await;
                if matches!(result, Err(Error::ElementPruned(_))) {
                    pruned_loc = Some(loc);
                    break;
                }
            }
            let pruned_loc = pruned_loc.expect("expected at least one pruned location");

            let dirty = clean.into_dirty();
            for i in 0..8 {
                dirty.add(&mut hasher, &test_digest(10_000 + i)).unwrap();
            }

            let requested = dirty.leaves();
            let result = dirty
                .historical_range_proof(requested, pruned_loc..pruned_loc + 1)
                .await;
            assert!(matches!(result, Err(Error::ElementPruned(_))));

            dirty.merkleize(&mut hasher).destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_journaled_mmr_append_while_historical_proof_is_available() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut hasher = Standard::<Sha256>::new();
            let mmr = Mmr::init(
                context.with_label("init"),
                &mut hasher,
                test_config(&context),
            )
            .await
            .unwrap()
            .into_dirty();

            for i in 0..20 {
                mmr.add(&mut hasher, &test_digest(i)).unwrap();
            }

            let historical_leaves = Location::new(10);
            let range = Location::new(2)..Location::new(8);
            // Transition through clean and back to dirty so historical proofs are available.
            let mmr = mmr.merkleize(&mut hasher).into_dirty();

            // Appends should remain allowed while historical proofs are available.
            mmr.add(&mut hasher, &test_digest(100)).unwrap();
            mmr.add(&mut hasher, &test_digest(101)).unwrap();

            let proof = mmr
                .historical_range_proof(historical_leaves, range.clone())
                .await
                .unwrap();

            let clean = mmr.merkleize(&mut hasher);
            let expected = clean
                .historical_range_proof(historical_leaves, range)
                .await
                .unwrap();
            assert_eq!(proof, expected);

            clean.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_journaled_mmr_dirty_historical_proof_after_sync_reads_from_journal() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut hasher = Standard::<Sha256>::new();
            let mmr = Mmr::init(
                context.with_label("init"),
                &mut hasher,
                test_config(&context),
            )
            .await
            .unwrap()
            .into_dirty();

            for i in 0..64 {
                mmr.add(&mut hasher, &test_digest(i)).unwrap();
            }

            let clean = mmr.merkleize(&mut hasher);
            clean.sync().await.unwrap();

            let historical_leaves = Location::new(20);
            let range = Location::new(5)..Location::new(15);
            let expected = clean
                .historical_range_proof(historical_leaves, range.clone())
                .await
                .unwrap();

            let dirty = clean.into_dirty();

            // After sync, the in-memory cache should have been pruned, so the dirty MMR
            // must read proof nodes from the journal. Verify the proof is still correct.
            let actual = dirty
                .historical_range_proof(historical_leaves, range)
                .await
                .unwrap();
            assert_eq!(actual, expected);

            dirty.merkleize(&mut hasher).destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_journaled_mmr_historical_proof_after_pruning() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut hasher = Standard::<Sha256>::new();
            let mmr = Mmr::init(
                context.with_label("init"),
                &mut hasher,
                test_config(&context),
            )
            .await
            .unwrap()
            .into_dirty();

            for i in 0..30 {
                mmr.add(&mut hasher, &test_digest(i)).unwrap();
            }
            let mut mmr = mmr.merkleize(&mut hasher);

            let prune_loc = Location::new(10);
            let prune_pos = Position::try_from(prune_loc).unwrap();
            mmr.prune_to_pos(prune_pos).await.unwrap();

            let requested = Location::new(20);
            let range = prune_loc..requested;
            let clean_proof = mmr
                .historical_range_proof(requested, range.clone())
                .await
                .unwrap();

            let dirty = mmr.into_dirty();
            let dirty_proof = dirty
                .historical_range_proof(requested, range)
                .await
                .unwrap();
            assert_eq!(dirty_proof, clean_proof);

            dirty.merkleize(&mut hasher).destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_journaled_mmr_historical_proof_edge_cases() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut hasher = Standard::<Sha256>::new();

            // Case 1: Empty MMR.
            let mmr = Mmr::init(
                context.with_label("empty"),
                &mut hasher,
                test_config(&context),
            )
            .await
            .unwrap();
            let empty_end = Location::new(0);
            let clean_empty = mmr
                .historical_range_proof(empty_end, empty_end..empty_end)
                .await;
            assert!(matches!(clean_empty, Err(Error::Empty)));
            let clean_oob = mmr
                .historical_range_proof(empty_end + 1, empty_end..empty_end + 1)
                .await;
            assert!(matches!(
                clean_oob,
                Err(Error::RangeOutOfBounds(loc)) if loc == empty_end + 1
            ));

            let mmr = mmr.into_dirty();
            let dirty_empty = mmr
                .historical_range_proof(empty_end, empty_end..empty_end)
                .await;
            assert!(matches!(dirty_empty, Err(Error::Empty)));
            let dirty_oob = mmr
                .historical_range_proof(empty_end + 1, empty_end..empty_end + 1)
                .await;
            assert!(matches!(
                dirty_oob,
                Err(Error::RangeOutOfBounds(loc)) if loc == empty_end + 1
            ));
            mmr.merkleize(&mut hasher).destroy().await.unwrap();

            // Case 2: MMR has nodes but is fully pruned.
            let mmr = Mmr::init(
                context.with_label("fully_pruned"),
                &mut hasher,
                test_config(&context),
            )
            .await
            .unwrap()
            .into_dirty();
            for i in 0..20 {
                mmr.add(&mut hasher, &test_digest(i)).unwrap();
            }
            let mut mmr = mmr.merkleize(&mut hasher);
            let end = mmr.leaves();
            let size = mmr.size();
            mmr.prune_to_pos(size).await.unwrap();
            assert!(mmr.bounds().is_empty());
            let clean_pruned = mmr.historical_range_proof(end, end - 1..end).await;
            assert!(matches!(clean_pruned, Err(Error::ElementPruned(_))));
            let clean_oob = mmr.historical_range_proof(end + 1, end - 1..end).await;
            assert!(matches!(
                clean_oob,
                Err(Error::RangeOutOfBounds(loc)) if loc == end + 1
            ));

            let mmr = mmr.into_dirty();
            let dirty_pruned = mmr.historical_range_proof(end, end - 1..end).await;
            assert!(matches!(dirty_pruned, Err(Error::ElementPruned(_))));
            let dirty_oob = mmr.historical_range_proof(end + 1, end - 1..end).await;
            assert!(matches!(
                dirty_oob,
                Err(Error::RangeOutOfBounds(loc)) if loc == end + 1
            ));
            mmr.merkleize(&mut hasher).destroy().await.unwrap();

            // Case 3: All nodes but one (single leaf) are pruned.
            let mmr = Mmr::init(
                context.with_label("single_leaf"),
                &mut hasher,
                test_config(&context),
            )
            .await
            .unwrap()
            .into_dirty();
            for i in 0..11 {
                mmr.add(&mut hasher, &test_digest(i)).unwrap();
            }
            let mut mmr = mmr.merkleize(&mut hasher);
            let end = mmr.leaves();
            let keep_loc = end - 1;
            let prune_pos = Position::try_from(keep_loc).unwrap();
            mmr.prune_to_pos(prune_pos).await.unwrap();
            let clean_ok = mmr.historical_range_proof(end, keep_loc..end).await;
            assert!(clean_ok.is_ok());
            let pruned_end = keep_loc - 1;
            // make sure this is in a pruned range, considering blob boundaries.
            let start_loc = Location::new(1);
            let clean_pruned = mmr
                .historical_range_proof(end, start_loc..pruned_end + 1)
                .await;
            assert!(matches!(clean_pruned, Err(Error::ElementPruned(_))));
            let clean_oob = mmr.historical_range_proof(end + 1, keep_loc..end).await;
            assert!(matches!(clean_oob, Err(Error::RangeOutOfBounds(_))));

            let mmr = mmr.into_dirty();
            let dirty_ok = mmr.historical_range_proof(end, keep_loc..end).await;
            assert!(dirty_ok.is_ok());
            let dirty_pruned = mmr
                .historical_range_proof(end, start_loc..pruned_end + 1)
                .await;
            assert!(matches!(dirty_pruned, Err(Error::ElementPruned(_))));
            let dirty_oob = mmr.historical_range_proof(end + 1, keep_loc..end).await;
            assert!(matches!(dirty_oob, Err(Error::RangeOutOfBounds(_))));
            mmr.merkleize(&mut hasher).destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_journaled_mmr_historical_proof_out_of_bounds() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut hasher = Standard::<Sha256>::new();
            let mmr = Mmr::init(
                context.with_label("oob"),
                &mut hasher,
                test_config(&context),
            )
            .await
            .unwrap()
            .into_dirty();

            for i in 0..8 {
                mmr.add(&mut hasher, &test_digest(i)).unwrap();
            }
            let mmr = mmr.merkleize(&mut hasher);
            let requested = mmr.leaves() + 1;

            let clean_result = mmr
                .historical_range_proof(requested, Location::new(0)..requested)
                .await;
            assert!(matches!(
                clean_result,
                Err(Error::RangeOutOfBounds(loc)) if loc == requested
            ));

            let mmr = mmr.into_dirty();
            let dirty_result = mmr
                .historical_range_proof(requested, Location::new(0)..requested)
                .await;
            assert!(matches!(
                dirty_result,
                Err(Error::RangeOutOfBounds(loc)) if loc == requested
            ));

            mmr.merkleize(&mut hasher).destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_journaled_mmr_dirty_historical_proof_range_validation_precedes_unmerkleized() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut hasher = Standard::<Sha256>::new();
            let mmr = Mmr::init(
                context.with_label("dirty_range_validation_precedes_unmerkleized"),
                &mut hasher,
                test_config(&context),
            )
            .await
            .unwrap()
            .into_dirty();

            // Keep state dirty and unmerkleized by appending without merkleizing.
            for i in 0..32 {
                mmr.add(&mut hasher, &test_digest(i)).unwrap();
            }

            let requested_unmerkleized = Location::new(5);
            let valid_range = Location::new(0)..Location::new(1);
            let unmerkleized = mmr
                .historical_range_proof(requested_unmerkleized, valid_range.clone())
                .await;
            assert!(matches!(unmerkleized, Err(Error::Unmerkleized)));

            // Empty range should report Empty before Unmerkleized.
            let empty_range = requested_unmerkleized..requested_unmerkleized;
            let empty_result = mmr
                .historical_range_proof(requested_unmerkleized, empty_range)
                .await;
            assert!(matches!(empty_result, Err(Error::Empty)));

            // Requested historical size is out of bounds; this should win over Unmerkleized.
            let leaves_oob = mmr.leaves() + 1;
            let dirty_result = mmr
                .historical_range_proof(leaves_oob, valid_range.clone())
                .await;
            assert!(matches!(
                dirty_result,
                Err(Error::RangeOutOfBounds(loc)) if loc == leaves_oob
            ));

            // Requested range end is out of bounds for the current MMR; this should also win over
            // Unmerkleized.
            let end_oob = mmr.leaves() + 1;
            let range_oob = Location::new(0)..end_oob;
            let dirty_result = mmr
                .historical_range_proof(requested_unmerkleized, range_oob.clone())
                .await;
            assert!(matches!(
                dirty_result,
                Err(Error::RangeOutOfBounds(loc)) if loc == end_oob
            ));

            // Requested range end can also be out of bounds for the requested historical size
            // while still being within the current MMR size. This should also beat Unmerkleized.
            let range_end_gt_requested = requested_unmerkleized + 1;
            let range_oob_at_requested = Location::new(0)..range_end_gt_requested;
            assert!(range_end_gt_requested <= mmr.leaves());
            let dirty_result = mmr
                .historical_range_proof(requested_unmerkleized, range_oob_at_requested)
                .await;
            assert!(matches!(
                dirty_result,
                Err(Error::RangeOutOfBounds(loc)) if loc == range_end_gt_requested
            ));

            // Range location overflow should be returned before Unmerkleized.
            let overflow_loc = Location::new(u64::MAX);
            let overflow_range = Location::new(0)..overflow_loc;
            let dirty_result = mmr
                .historical_range_proof(requested_unmerkleized, overflow_range.clone())
                .await;
            assert!(matches!(
                dirty_result,
                Err(Error::LocationOverflow(loc)) if loc == overflow_loc
            ));

            let clean = mmr.merkleize(&mut hasher);
            let clean_result = clean.historical_range_proof(leaves_oob, valid_range).await;
            assert!(matches!(
                clean_result,
                Err(Error::RangeOutOfBounds(loc)) if loc == leaves_oob
            ));

            clean.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_journaled_mmr_historical_proof_non_size_prune_excludes_pruned_leaves() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut hasher = Standard::<Sha256>::new();
            let mmr = Mmr::init(
                context.with_label("non_size_prune"),
                &mut hasher,
                test_config(&context),
            )
            .await
            .unwrap()
            .into_dirty();

            for i in 0..16 {
                mmr.add(&mut hasher, &test_digest(i)).unwrap();
            }

            let mut mmr = mmr.merkleize(&mut hasher);
            let end = mmr.leaves();
            let size = mmr.size();
            let mut failures = Vec::new();
            for raw_pos in 1..*size {
                let prune_pos = Position::new(raw_pos);
                mmr.prune_to_pos(prune_pos).await.unwrap();
                for loc_u64 in 0..*end {
                    let loc = Location::new(loc_u64);
                    let loc_pos = Position::try_from(loc).expect("test loc should be valid");
                    let range_includes_pruned_leaf = loc_pos < prune_pos;
                    match mmr.historical_proof(end, loc).await {
                        Ok(_) => {}
                        Err(Error::ElementPruned(_)) if range_includes_pruned_leaf => {}
                        Err(Error::ElementPruned(_)) => failures.push(format!(
                            "clean prune_pos={prune_pos} loc={loc} returned ElementPruned without a pruned range element"
                        )),
                        Err(err) => failures
                            .push(format!("clean prune_pos={prune_pos} loc={loc} err={err}")),
                    }
                }

                let dirty = mmr.into_dirty();
                for loc_u64 in 0..*end {
                    let loc = Location::new(loc_u64);
                    let loc_pos = Position::try_from(loc).expect("test loc should be valid");
                    let range_includes_pruned_leaf = loc_pos < prune_pos;
                    match dirty.historical_proof(end, loc).await {
                        Ok(_) => {}
                        Err(Error::ElementPruned(_)) if range_includes_pruned_leaf => {}
                        Err(Error::ElementPruned(_)) => failures.push(format!(
                            "dirty prune_pos={prune_pos} loc={loc} returned ElementPruned without a pruned range element"
                        )),
                        Err(err) => failures
                            .push(format!("dirty prune_pos={prune_pos} loc={loc} err={err}")),
                    }
                }
                mmr = dirty.merkleize(&mut hasher);
            }

            assert!(
                failures.is_empty(),
                "historical proof generation returned unexpected errors: {failures:?}"
            );

            mmr.destroy().await.unwrap();
        });
    }
}
