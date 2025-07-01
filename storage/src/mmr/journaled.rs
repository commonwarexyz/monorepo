//! An MMR backed by a fixed-item-length journal.
//!
//! A [crate::journal] is used to store all unpruned MMR nodes, and a [crate::metadata] store is
//! used to preserve digests required for root and proof generation that would have otherwise been
//! pruned.

use crate::{
    journal::{
        fixed::{Config as JConfig, Journal},
        Error as JError,
    },
    metadata::{Config as MConfig, Metadata},
    mmr::{
        iterator::PeakIterator,
        mem::{Config as MemConfig, Mmr as MemMmr},
        verification::Proof,
        Builder, Error, Hasher,
    },
};
use commonware_codec::DecodeExt;
use commonware_cryptography::Hasher as CHasher;
use commonware_runtime::{Clock, Metrics, Storage as RStorage, ThreadPool};
use commonware_utils::array::prefixed_u64::U64;
use std::collections::HashMap;
use tracing::{debug, error, warn};

/// Configuration for a journal-backed MMR.
#[derive(Clone)]
pub struct Config {
    /// The name of the `commonware-runtime::Storage` storage partition used for the journal storing
    /// the MMR nodes.
    pub journal_partition: String,

    /// The name of the `commonware-runtime::Storage` storage partition used for the metadata
    /// containing pruned MMR nodes that are still required to calculate the root and generate
    /// proofs.
    pub metadata_partition: String,

    /// The maximum number of items to store in each blob in the backing journal.
    pub items_per_blob: u64,

    /// The size of the write buffer to use for each blob in the backing journal.
    pub write_buffer: usize,

    /// Optional thread pool to use for parallelizing batch operations.
    pub pool: Option<ThreadPool>,
}

/// A MMR backed by a fixed-item-length journal.
pub struct Mmr<E: RStorage + Clock + Metrics, H: CHasher> {
    /// A memory resident MMR used to build the MMR structure and cache updates.
    mem_mmr: MemMmr<H>,

    /// Stores all unpruned MMR nodes.
    journal: Journal<E, H::Digest>,

    /// The size of the journal irrespective of any pruned nodes or any un-synced nodes currently
    /// cached in the memory resident MMR.
    journal_size: u64,

    /// Stores all "pinned nodes" (pruned nodes required for proving & root generation) for the MMR,
    /// and the corresponding pruning boundary used to generate them. The metadata remains empty
    /// until pruning is invoked, and its contents change only when the pruning boundary moves.
    metadata: Metadata<E, U64, Vec<u8>>,

    /// The highest position for which this MMR has been pruned, or 0 if this MMR has never been
    /// pruned.
    pruned_to_pos: u64,
}

impl<E: RStorage + Clock + Metrics, H: CHasher> Builder<H> for Mmr<E, H> {
    async fn add(&mut self, hasher: &mut impl Hasher<H>, element: &[u8]) -> Result<u64, Error> {
        self.add(hasher, element).await
    }

    fn root(&self, hasher: &mut impl Hasher<H>) -> H::Digest {
        self.root(hasher)
    }
}

/// Prefix used for nodes in the metadata prefixed U8 key.
const NODE_PREFIX: u8 = 0;

/// Prefix used for the key storing the prune_to_pos position in the metadata.
const PRUNE_TO_POS_PREFIX: u8 = 1;

impl<E: RStorage + Clock + Metrics, H: CHasher> Mmr<E, H> {
    /// Initialize a new `Mmr` instance.
    pub async fn init(context: E, hasher: &mut impl Hasher<H>, cfg: Config) -> Result<Self, Error> {
        let journal_cfg = JConfig {
            partition: cfg.journal_partition,
            items_per_blob: cfg.items_per_blob,
            write_buffer: cfg.write_buffer,
        };
        let mut journal =
            Journal::<E, H::Digest>::init(context.with_label("mmr_journal"), journal_cfg).await?;
        let mut journal_size = journal.size().await?;

        let metadata_cfg = MConfig {
            partition: cfg.metadata_partition,
            codec_config: ((0..).into(), ()),
        };
        let metadata =
            Metadata::<_, U64, Vec<u8>>::init(context.with_label("mmr_metadata"), metadata_cfg)
                .await?;

        if journal_size == 0 {
            return Ok(Self {
                mem_mmr: MemMmr::init(MemConfig {
                    nodes: vec![],
                    pruned_to_pos: 0,
                    pinned_nodes: vec![],
                    pool: cfg.pool,
                }),
                journal,
                journal_size,
                metadata,
                pruned_to_pos: 0,
            });
        }

        // Make sure the journal's oldest retained node is as expected based on the last pruning
        // boundary stored in metadata. If they don't match, prune the journal to the appropriate
        // location.
        let key: U64 = U64::new(PRUNE_TO_POS_PREFIX, 0);
        let metadata_prune_pos = match metadata.get(&key) {
            Some(bytes) => u64::from_be_bytes(
                bytes
                    .as_slice()
                    .try_into()
                    .expect("metadata prune position is not 8 bytes"),
            ),
            None => 0,
        };
        let oldest_retained_pos = journal.oldest_retained_pos().await?.unwrap_or(0);
        if metadata_prune_pos != oldest_retained_pos {
            assert!(metadata_prune_pos >= oldest_retained_pos);
            // These positions may differ only due to blob boundary alignment, so this case isn't
            // unusual.
            let actual_prune_point = journal.prune(metadata_prune_pos).await?;
            if actual_prune_point != oldest_retained_pos {
                // This should only happen in the event of some failure during the last attempt to
                // prune the journal.
                warn!(
                    oldest_retained_pos,
                    metadata_prune_pos, "journal pruned to match metadata"
                );
            }
        }

        let last_valid_size = PeakIterator::to_nearest_size(journal_size);
        let mut orphaned_leaf: Option<H::Digest> = None;
        if last_valid_size != journal_size {
            warn!(
                last_valid_size,
                "encountered invalid MMR structure, recovering from last valid size"
            );
            // Check if there is an intact leaf following the last valid size, from which we can
            // recover its missing parents.
            let recovered_item = journal.read(last_valid_size).await;
            if let Ok(item) = recovered_item {
                orphaned_leaf = Some(item);
            }
            journal.rewind(last_valid_size).await?;
            journal_size = last_valid_size
        }

        // Initialize the mem_mmr in the "prune_all" state.
        let mut pinned_nodes = Vec::new();
        for pos in Proof::<H::Digest>::nodes_to_pin(journal_size) {
            let digest =
                Mmr::<E, H>::get_from_metadata_or_journal(&metadata, &journal, pos).await?;
            pinned_nodes.push(digest);
        }
        let mut mem_mmr = MemMmr::init(MemConfig {
            nodes: vec![],
            pruned_to_pos: journal_size,
            pinned_nodes,
            pool: cfg.pool,
        });

        // Compute the additional pinned nodes needed to prove all journal elements at the current
        // pruning boundary.
        let mut pinned_nodes = HashMap::new();
        for pos in Proof::<H::Digest>::nodes_to_pin(metadata_prune_pos) {
            let digest =
                Mmr::<E, H>::get_from_metadata_or_journal(&metadata, &journal, pos).await?;
            pinned_nodes.insert(pos, digest);
        }
        mem_mmr.add_pinned_nodes(pinned_nodes);

        let mut s = Self {
            mem_mmr,
            journal,
            journal_size,
            metadata,
            pruned_to_pos: metadata_prune_pos,
        };

        if let Some(leaf) = orphaned_leaf {
            // Recover the orphaned leaf and any missing parents.
            let pos = s.mem_mmr.size();
            warn!(pos, "recovering orphaned leaf");
            s.mem_mmr.add_leaf_digest(hasher, leaf);
            assert_eq!(pos, journal_size);
            s.sync(hasher).await?;
            assert_eq!(s.size(), s.journal.size().await?);
        }

        Ok(s)
    }

    /// Return the total number of nodes in the MMR, irrespective of any pruning. The next added
    /// element's position will have this value.
    pub fn size(&self) -> u64 {
        self.mem_mmr.size()
    }

    pub async fn get_node(&self, position: u64) -> Result<Option<H::Digest>, Error> {
        if let Some(node) = self.mem_mmr.get_node(position) {
            return Ok(Some(node));
        }

        match self.journal.read(position).await {
            Ok(item) => Ok(Some(item)),
            Err(JError::ItemPruned(_)) => Ok(None),
            Err(e) => Err(Error::JournalError(e)),
        }
    }

    /// Return the position of the last leaf in an MMR with this MMR's size, or None if the MMR is
    /// empty.
    pub fn last_leaf_pos(&self) -> Option<u64> {
        self.mem_mmr.last_leaf_pos()
    }

    /// Attempt to get a node from the metadata, with fallback to journal lookup if it fails.
    /// Assumes the node should exist in at least one of these sources and returns a `MissingNode`
    /// error otherwise.
    async fn get_from_metadata_or_journal(
        metadata: &Metadata<E, U64, Vec<u8>>,
        journal: &Journal<E, H::Digest>,
        pos: u64,
    ) -> Result<H::Digest, Error> {
        if let Some(bytes) = metadata.get(&U64::new(NODE_PREFIX, pos)) {
            debug!(pos, "read node from metadata");
            let digest = H::Digest::decode(bytes.as_ref());
            let Ok(digest) = digest else {
                error!(
                    pos,
                    err = %digest.err().unwrap(),
                    "could not convert node from metadata bytes to digest"
                );
                return Err(Error::MissingNode(pos));
            };
            return Ok(digest);
        }

        // If a node isn't found in the metadata, it might still be in the journal.
        debug!(pos, "reading node from journal");
        let node = journal.read(pos).await;
        match node {
            Ok(node) => Ok(node),
            Err(JError::ItemPruned(_)) => {
                error!(pos, "node is missing from metadata and journal");
                Err(Error::MissingNode(pos))
            }
            Err(e) => Err(Error::JournalError(e)),
        }
    }

    /// Add an element to the MMR and return its position in the MMR. Elements added to the MMR
    /// aren't persisted to disk until `sync` is called.
    ///
    /// # Warning
    ///
    /// Panics if there are unprocessed updates.
    pub async fn add(&mut self, h: &mut impl Hasher<H>, element: &[u8]) -> Result<u64, Error> {
        Ok(self.mem_mmr.add(h, element))
    }

    /// Add an element to the MMR, delaying the computation of ancestor digests
    /// until the next `sync`.
    pub async fn add_batched(
        &mut self,
        h: &mut impl Hasher<H>,
        element: &[u8],
    ) -> Result<u64, Error> {
        Ok(self.mem_mmr.add_batched(h, element))
    }

    /// Pop the given number of elements from the tip of the MMR assuming they exist, and otherwise
    /// return Empty or ElementPruned errors.
    ///
    /// # Warning
    ///
    /// Panics if there are unprocessed batch updates.
    pub async fn pop(&mut self, mut leaves_to_pop: usize) -> Result<(), Error> {
        // See if the elements are still cached in which case we can just pop them from the in-mem
        // MMR.
        while leaves_to_pop > 0 {
            match self.mem_mmr.pop() {
                Ok(_) => {
                    leaves_to_pop -= 1;
                }
                Err(Error::ElementPruned(_)) => break,
                Err(Error::Empty) => {
                    return Err(Error::Empty);
                }
                _ => unreachable!(),
            }
        }
        if leaves_to_pop == 0 {
            return Ok(());
        }

        let mut new_size = self.size();
        while leaves_to_pop > 0 {
            if new_size == 0 {
                return Err(Error::Empty);
            }
            new_size -= 1;
            if new_size < self.pruned_to_pos {
                return Err(Error::ElementPruned(new_size));
            }
            if PeakIterator::check_validity(new_size) {
                leaves_to_pop -= 1;
            }
        }

        self.journal.rewind(new_size).await?;
        self.journal_size = new_size;

        // Reset the mem_mmr to one of the new_size in the "prune_all" state.
        let mut pinned_nodes = Vec::new();
        for pos in Proof::<H::Digest>::nodes_to_pin(new_size) {
            let digest =
                Mmr::<E, H>::get_from_metadata_or_journal(&self.metadata, &self.journal, pos)
                    .await?;
            pinned_nodes.push(digest);
        }
        self.mem_mmr = MemMmr::init(MemConfig {
            nodes: vec![],
            pruned_to_pos: new_size,
            pinned_nodes,
            pool: self.mem_mmr.pool.take(),
        });

        Ok(())
    }

    /// Return the root of the MMR.
    ///
    /// # Warning
    ///
    /// Panics if there are unprocessed updates.
    pub fn root(&self, h: &mut impl Hasher<H>) -> H::Digest {
        self.mem_mmr.root(h)
    }

    /// Process all batched updates and sync the MMR to disk. If `pool` is non-null, then it will be
    /// used to parallelize the sync.
    pub async fn sync(&mut self, h: &mut impl Hasher<H>) -> Result<(), Error> {
        if self.size() == 0 {
            return Ok(());
        }

        // Write the nodes cached in the memory-resident MMR to the journal.
        self.mem_mmr.sync(h);

        for i in self.journal_size..self.size() {
            let node = *self.mem_mmr.get_node_unchecked(i);
            self.journal.append(node).await?;
        }
        self.journal_size = self.size();
        self.journal.sync().await?;
        assert_eq!(self.journal_size, self.journal.size().await?);

        // Recompute pinned nodes since we'll need to repopulate the cache after it is cleared by
        // pruning the mem_mmr.
        let mut pinned_nodes = HashMap::new();
        for pos in Proof::<H::Digest>::nodes_to_pin(self.pruned_to_pos) {
            let digest = self.mem_mmr.get_node_unchecked(pos);
            pinned_nodes.insert(pos, *digest);
        }

        // Now that the pinned node set has been recomputed, it's safe to prune the mem_mmr and
        // reinstate them.
        self.mem_mmr.prune_all();
        self.mem_mmr.add_pinned_nodes(pinned_nodes);

        Ok(())
    }

    /// Compute and add required nodes for the given pruning point to the metadata, and write it to
    /// disk. Return the computed set of required nodes.
    async fn update_metadata(
        &mut self,
        prune_to_pos: u64,
    ) -> Result<HashMap<u64, H::Digest>, Error> {
        let mut pinned_nodes = HashMap::new();
        for pos in Proof::<H::Digest>::nodes_to_pin(prune_to_pos) {
            let digest = self.get_node(pos).await?.unwrap();
            self.metadata
                .put(U64::new(NODE_PREFIX, pos), digest.to_vec());
            pinned_nodes.insert(pos, digest);
        }

        let key: U64 = U64::new(PRUNE_TO_POS_PREFIX, 0);
        self.metadata.put(key, prune_to_pos.to_be_bytes().into());

        self.metadata.sync().await.map_err(Error::MetadataError)?;

        Ok(pinned_nodes)
    }

    /// Return an inclusion proof for the specified element, or ElementPruned error if some element
    /// needed to generate the proof has been pruned.
    ///
    /// # Warning
    ///
    /// Panics if there are unprocessed updates.
    pub async fn proof(&self, element_pos: u64) -> Result<Proof<H::Digest>, Error> {
        self.range_proof(element_pos, element_pos).await
    }

    /// Return an inclusion proof for the specified range of elements, inclusive of both endpoints,
    /// or ElementPruned error if some element needed to generate the proof has been pruned.
    ///
    /// # Warning
    ///
    /// Panics if there are unprocessed updates.
    pub async fn range_proof(
        &self,
        start_element_pos: u64,
        end_element_pos: u64,
    ) -> Result<Proof<H::Digest>, Error> {
        assert!(!self.mem_mmr.is_dirty());
        Proof::<H::Digest>::range_proof::<Mmr<E, H>>(self, start_element_pos, end_element_pos).await
    }

    /// Prune as many nodes as possible, leaving behind at most items_per_blob nodes in the current
    /// blob.
    pub async fn prune_all(&mut self, h: &mut impl Hasher<H>) -> Result<(), Error> {
        if self.size() != 0 {
            self.prune_to_pos(h, self.size()).await?;
            return Ok(());
        }
        Ok(())
    }

    /// Prune all nodes up to but not including the given position and update the pinned nodes.
    ///
    /// This implementation ensures that no failure can leave the MMR in an unrecoverable state,
    /// requiring it sync the MMR to write any potential unprocessed updates.
    pub async fn prune_to_pos(&mut self, h: &mut impl Hasher<H>, pos: u64) -> Result<(), Error> {
        assert!(pos <= self.size());
        if self.size() == 0 {
            return Ok(());
        }

        // Flush items cached in the mem_mmr to disk to ensure the current state is recoverable.
        self.sync(h).await?;

        // Update metadata to reflect the desired pruning boundary, allowing for recovery in the
        // event of a pruning failure.
        let pinned_nodes = self.update_metadata(pos).await?;

        self.journal.prune(pos).await?;
        self.mem_mmr.add_pinned_nodes(pinned_nodes);
        self.pruned_to_pos = pos;

        Ok(())
    }

    /// The highest position for which this MMR has been pruned, or 0 if this MMR has never been
    /// pruned.
    pub fn pruned_to_pos(&self) -> u64 {
        self.pruned_to_pos
    }

    /// Return the position of the oldest retained node in the MMR, not including pinned nodes.
    pub fn oldest_retained_pos(&self) -> Option<u64> {
        if self.pruned_to_pos == self.size() {
            return None;
        }

        Some(self.pruned_to_pos)
    }

    /// Close the MMR, syncing any cached elements to disk and closing the journal.
    pub async fn close(mut self, h: &mut impl Hasher<H>) -> Result<(), Error> {
        self.sync(h).await?;
        self.journal.close().await?;
        self.metadata.close().await.map_err(Error::MetadataError)
    }

    /// Close and permanently remove any disk resources.
    pub async fn destroy(self) -> Result<(), Error> {
        self.journal.destroy().await?;
        self.metadata.destroy().await?;

        Ok(())
    }

    #[cfg(test)]
    /// Sync elements to disk until `write_limit` elements have been written, then abort to simulate
    /// a partial write for testing failure scenarios.
    pub async fn simulate_partial_sync(
        mut self,
        hasher: &mut impl Hasher<H>,
        write_limit: usize,
    ) -> Result<(), Error> {
        if write_limit == 0 {
            return Ok(());
        }

        // Write the nodes cached in the memory-resident MMR to the journal, aborting after
        // write_count nodes have been written.
        let mut written_count = 0usize;
        self.mem_mmr.sync(hasher);
        for i in self.journal_size..self.size() {
            let node = *self.mem_mmr.get_node_unchecked(i);
            self.journal.append(node).await?;
            written_count += 1;
            if written_count >= write_limit {
                break;
            }
        }
        self.journal.sync().await?;

        Ok(())
    }

    #[cfg(test)]
    pub async fn simulate_pruning_failure(
        mut self,
        h: &mut impl Hasher<H>,
        prune_to_pos: u64,
    ) -> Result<(), Error> {
        assert!(prune_to_pos <= self.size());

        // Flush items cached in the mem_mmr to disk to ensure the current state is recoverable.
        self.sync(h).await?;

        // Update metadata to reflect the desired pruning boundary, allowing for recovery in the
        // event of a pruning failure.
        self.update_metadata(prune_to_pos).await?;

        // Don't actually prune the journal to simulate failure
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mmr::{
        hasher::Standard,
        iterator::leaf_num_to_pos,
        tests::{
            build_and_check_test_roots_mmr, build_batched_and_check_test_roots_journaled, ROOTS,
        },
    };
    use commonware_cryptography::{hash, sha256::Digest, Hasher, Sha256};
    use commonware_macros::test_traced;
    use commonware_runtime::{deterministic, Blob as _, Runner};
    use commonware_utils::hex;

    fn test_digest(v: usize) -> Digest {
        hash(&v.to_be_bytes())
    }

    fn test_config() -> Config {
        Config {
            journal_partition: "journal_partition".into(),
            metadata_partition: "metadata_partition".into(),
            items_per_blob: 7,
            write_buffer: 1024,
            pool: None,
        }
    }

    /// Test that the MMR root computation remains stable.
    #[test]
    fn test_journaled_mmr_root_stability() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut mmr = Mmr::init(context.clone(), &mut Standard::new(), test_config())
                .await
                .unwrap();
            build_and_check_test_roots_mmr(&mut mmr).await;
            mmr.destroy().await.unwrap();
        });
    }

    /// Test that the MMR root computation remains stable by comparing against previously computed
    /// roots.
    #[test]
    fn test_journaled_mmr_root_stability_batched() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut std_hasher = Standard::new();
            let mut mmr = Mmr::init(context.clone(), &mut std_hasher, test_config())
                .await
                .unwrap();
            build_batched_and_check_test_roots_journaled(&mut mmr).await;
            mmr.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_journaled_mmr_empty() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut hasher: Standard<Sha256> = Standard::new();
            let mut mmr = Mmr::init(context.clone(), &mut hasher, test_config())
                .await
                .unwrap();
            assert_eq!(mmr.size(), 0);
            assert!(mmr.get_node(0).await.is_err());
            assert_eq!(mmr.oldest_retained_pos(), None);
            assert!(mmr.prune_all(&mut hasher).await.is_ok());
            assert_eq!(mmr.pruned_to_pos(), 0);
            assert!(mmr.prune_to_pos(&mut hasher, 0).await.is_ok());
            assert!(mmr.sync(&mut hasher).await.is_ok());
            assert!(matches!(mmr.pop(1).await, Err(Error::Empty)));
            mmr.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_journaled_mmr_pop() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut hasher: Standard<Sha256> = Standard::new();
            let mut mmr = Mmr::init(context.clone(), &mut hasher, test_config())
                .await
                .unwrap();

            let mut c_hasher = Sha256::new();
            for i in 0u64..199 {
                c_hasher.update(&i.to_be_bytes());
                let element = c_hasher.finalize();
                mmr.add(&mut hasher, &element).await.unwrap();
            }
            assert_eq!(ROOTS[199], hex(&mmr.root(&mut hasher)));

            // Pop off one node at a time without syncing until empty, confirming the root is still
            // is as expected.
            for i in (0..199u64).rev() {
                assert!(mmr.pop(1).await.is_ok());
                let root = mmr.root(&mut hasher);
                let expected_root = ROOTS[i as usize];
                assert_eq!(hex(&root), expected_root);
            }
            assert!(matches!(mmr.pop(1).await, Err(Error::Empty)));
            assert!(mmr.pop(0).await.is_ok());

            // Repeat the test though sync part of the way to tip to test crossing the boundary from
            // cached to uncached leaves, and pop 2 at a time instead of just 1.
            for i in 0u64..199 {
                c_hasher.update(&i.to_be_bytes());
                let element = c_hasher.finalize();
                mmr.add(&mut hasher, &element).await.unwrap();
                if i == 101 {
                    mmr.sync(&mut hasher).await.unwrap();
                }
            }
            for i in (0..198u64).rev().step_by(2) {
                assert!(mmr.pop(2).await.is_ok());
                let root = mmr.root(&mut hasher);
                let expected_root = ROOTS[i as usize];
                assert_eq!(hex(&root), expected_root);
            }
            assert_eq!(mmr.size(), 1);
            assert!(mmr.pop(1).await.is_ok()); // pop the last element
            assert!(matches!(mmr.pop(99).await, Err(Error::Empty)));

            // Repeat one more time only after pruning the MMR first.
            for i in 0u64..199 {
                c_hasher.update(&i.to_be_bytes());
                let element = c_hasher.finalize();
                mmr.add(&mut hasher, &element).await.unwrap();
            }
            let leaf_pos = leaf_num_to_pos(50);
            mmr.prune_to_pos(&mut hasher, leaf_pos).await.unwrap();
            while mmr.size() > leaf_pos {
                assert!(mmr.pop(1).await.is_ok());
            }
            assert!(matches!(mmr.pop(1).await, Err(Error::ElementPruned(_))));
            mmr.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_journaled_mmr_basic() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut hasher: Standard<Sha256> = Standard::new();
            let mut mmr = Mmr::init(context.clone(), &mut hasher, test_config())
                .await
                .unwrap();
            // Build a test MMR with 255 leaves
            const LEAF_COUNT: usize = 255;
            let mut leaves = Vec::with_capacity(LEAF_COUNT);
            let mut positions = Vec::with_capacity(LEAF_COUNT);
            for i in 0..LEAF_COUNT {
                let digest = test_digest(i);
                leaves.push(digest);
                let pos = mmr.add(&mut hasher, leaves.last().unwrap()).await.unwrap();
                positions.push(pos);
            }
            assert_eq!(mmr.size(), 502);
            assert_eq!(mmr.journal_size, 0);

            // Generate & verify proof from element that is not yet flushed to the journal.
            const TEST_ELEMENT: usize = 133;
            let test_element_pos = positions[TEST_ELEMENT];

            let proof = mmr.proof(test_element_pos).await.unwrap();
            let root = mmr.root(&mut hasher);
            assert!(proof.verify_element_inclusion(
                &mut hasher,
                &leaves[TEST_ELEMENT],
                test_element_pos,
                &root,
            ));

            // Sync the MMR, make sure it flushes the in-mem MMR as expected.
            mmr.sync(&mut hasher).await.unwrap();
            assert_eq!(mmr.journal_size, 502);
            assert_eq!(mmr.mem_mmr.oldest_retained_pos(), None);

            // Now that the element is flushed from the in-mem MMR, confirm its proof is still is
            // generated correctly.
            let proof2 = mmr.proof(test_element_pos).await.unwrap();
            assert_eq!(proof, proof2);

            // Generate & verify a proof that spans flushed elements and the last element.
            let last_element = LEAF_COUNT - 1;
            let last_element_pos = positions[last_element];
            let proof = mmr
                .range_proof(test_element_pos, last_element_pos)
                .await
                .unwrap();
            assert!(proof.verify_range_inclusion(
                &mut hasher,
                &leaves[TEST_ELEMENT..last_element + 1],
                test_element_pos,
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
            let mut mmr = Mmr::init(context.clone(), &mut hasher, test_config())
                .await
                .unwrap();
            assert_eq!(mmr.size(), 0);

            // Build a test MMR with 252 leaves
            const LEAF_COUNT: usize = 252;
            let mut leaves = Vec::with_capacity(LEAF_COUNT);
            let mut positions = Vec::with_capacity(LEAF_COUNT);
            for i in 0..LEAF_COUNT {
                let digest = test_digest(i);
                leaves.push(digest);
                let pos = mmr.add(&mut hasher, leaves.last().unwrap()).await.unwrap();
                positions.push(pos);
            }
            assert_eq!(mmr.size(), 498);
            let root = mmr.root(&mut hasher);
            mmr.close(&mut hasher).await.unwrap();

            // The very last element we added (pos=495) resulted in new parents at positions 496 &
            // 497. Simulate a partial write by corrupting the last parent's checksum by truncating
            // the last blob by a single byte.
            let partition: String = "journal_partition".into();
            let (blob, len) = context
                .open(&partition, &71u64.to_be_bytes())
                .await
                .expect("Failed to open blob");
            assert_eq!(len, 36); // N+4 = 36 bytes per node, 1 node in the last blob

            // truncate the blob by one byte to corrupt the checksum of the last parent node.
            blob.resize(len - 1).await.expect("Failed to corrupt blob");
            blob.close().await.expect("Failed to close blob");

            let mmr = Mmr::init(context.clone(), &mut hasher, test_config())
                .await
                .unwrap();
            // Since we didn't corrupt the leaf, the MMR is able to replay the leaf and recover to
            // the previous state.
            assert_eq!(mmr.size(), 498);
            assert_eq!(mmr.root(&mut hasher), root);

            // Make sure closing it and re-opening it persists the recovered state.
            mmr.close(&mut hasher).await.unwrap();
            let mmr = Mmr::init(context.clone(), &mut hasher, test_config())
                .await
                .unwrap();
            assert_eq!(mmr.size(), 498);
            mmr.close(&mut hasher).await.unwrap();

            // Repeat partial write test though this time truncate the leaf itself not just some
            // parent. The leaf is in the *previous* blob so we'll have to delete the most recent
            // blob, then appropriately truncate the previous one.
            context
                .remove(&partition, Some(&71u64.to_be_bytes()))
                .await
                .expect("Failed to remove blob");
            let (blob, len) = context
                .open(&partition, &70u64.to_be_bytes())
                .await
                .expect("Failed to open blob");
            assert_eq!(len, 36 * 7); // this blob should be full.

            // The last leaf should be in slot 5 of this blob, truncate last byte of its checksum.
            blob.resize(36 * 5 + 35)
                .await
                .expect("Failed to corrupt blob");
            blob.close().await.expect("Failed to close blob");

            let mmr = Mmr::init(context.clone(), &mut hasher, test_config())
                .await
                .unwrap();
            // Since the leaf was corrupted, it should not have been recovered, and the journal's
            // size will be the last-valid size.
            assert_eq!(mmr.size(), 495);

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
            let cfg_pruned = test_config();
            let mut pruned_mmr = Mmr::init(context.clone(), &mut hasher, cfg_pruned.clone())
                .await
                .unwrap();
            let cfg_unpruned = Config {
                journal_partition: "unpruned_journal_partition".into(),
                metadata_partition: "unpruned_metadata_partition".into(),
                items_per_blob: 7,
                write_buffer: 1024,
                pool: None,
            };
            let mut mmr = Mmr::init(context.clone(), &mut hasher, cfg_unpruned)
                .await
                .unwrap();
            let mut leaves = Vec::with_capacity(LEAF_COUNT);
            let mut positions = Vec::with_capacity(LEAF_COUNT);
            for i in 0..LEAF_COUNT {
                let digest = test_digest(i);
                leaves.push(digest);
                let last_leaf = leaves.last().unwrap();
                let pos = mmr.add(&mut hasher, last_leaf).await.unwrap();
                positions.push(pos);
                pruned_mmr.add(&mut hasher, last_leaf).await.unwrap();
            }
            assert_eq!(mmr.size(), 3994);
            assert_eq!(pruned_mmr.size(), 3994);

            // Prune the MMR in increments of 10 making sure the journal is still able to compute
            // roots and accept new elements.
            for i in 0usize..300 {
                let prune_pos = i as u64 * 10;
                pruned_mmr
                    .prune_to_pos(&mut hasher, prune_pos)
                    .await
                    .unwrap();
                assert_eq!(prune_pos, pruned_mmr.pruned_to_pos());

                let digest = test_digest(LEAF_COUNT + i);
                leaves.push(digest);
                let last_leaf = leaves.last().unwrap();
                let pos = pruned_mmr.add(&mut hasher, last_leaf).await.unwrap();
                positions.push(pos);
                mmr.add(&mut hasher, last_leaf).await.unwrap();
                assert_eq!(pruned_mmr.root(&mut hasher), mmr.root(&mut hasher));
            }

            // Sync the MMRs.
            pruned_mmr.sync(&mut hasher).await.unwrap();
            assert_eq!(pruned_mmr.root(&mut hasher), mmr.root(&mut hasher));

            // Close the MMR & reopen.
            pruned_mmr.close(&mut hasher).await.unwrap();
            let mut pruned_mmr = Mmr::init(context.clone(), &mut hasher, cfg_pruned.clone())
                .await
                .unwrap();
            assert_eq!(pruned_mmr.root(&mut hasher), mmr.root(&mut hasher));

            // Prune everything.
            let size = pruned_mmr.size();
            pruned_mmr.prune_all(&mut hasher).await.unwrap();
            assert_eq!(pruned_mmr.root(&mut hasher), mmr.root(&mut hasher));
            assert_eq!(pruned_mmr.oldest_retained_pos(), None);
            assert_eq!(pruned_mmr.pruned_to_pos(), size);

            // Close MMR after adding a new node without syncing and make sure state is as expected
            // on reopening.
            mmr.add(&mut hasher, &test_digest(LEAF_COUNT))
                .await
                .unwrap();
            pruned_mmr
                .add(&mut hasher, &test_digest(LEAF_COUNT))
                .await
                .unwrap();
            assert!(pruned_mmr.size() % cfg_pruned.items_per_blob != 0);
            pruned_mmr.close(&mut hasher).await.unwrap();
            let mut pruned_mmr = Mmr::init(context.clone(), &mut hasher, cfg_pruned.clone())
                .await
                .unwrap();
            assert_eq!(pruned_mmr.root(&mut hasher), mmr.root(&mut hasher));
            assert_eq!(pruned_mmr.oldest_retained_pos(), Some(size));
            assert_eq!(pruned_mmr.pruned_to_pos(), size);

            // Add nodes until we are on a blob boundary, and confirm prune_all still removes all
            // retained nodes.
            while pruned_mmr.size() % cfg_pruned.items_per_blob != 0 {
                pruned_mmr
                    .add(&mut hasher, &test_digest(LEAF_COUNT))
                    .await
                    .unwrap();
            }
            pruned_mmr.prune_all(&mut hasher).await.unwrap();
            assert_eq!(pruned_mmr.oldest_retained_pos(), None);

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
            let mut mmr = Mmr::init(context.clone(), &mut hasher, test_config())
                .await
                .unwrap();
            let mut leaves = Vec::with_capacity(LEAF_COUNT);
            let mut positions = Vec::with_capacity(LEAF_COUNT);
            for i in 0..LEAF_COUNT {
                let digest = test_digest(i);
                leaves.push(digest);
                let last_leaf = leaves.last().unwrap();
                let pos = mmr.add(&mut hasher, last_leaf).await.unwrap();
                positions.push(pos);
            }
            assert_eq!(mmr.size(), 3994);
            mmr.close(&mut hasher).await.unwrap();

            // Prune the MMR in increments of 50, simulating a partial write after each prune.
            for i in 0usize..200 {
                let mut mmr = Mmr::init(context.clone(), &mut hasher, test_config())
                    .await
                    .unwrap();
                let start_size = mmr.size();
                let prune_pos = std::cmp::min(i as u64 * 50, start_size);
                if i % 5 == 0 {
                    mmr.simulate_pruning_failure(&mut hasher, prune_pos)
                        .await
                        .unwrap();
                    continue;
                }
                mmr.prune_to_pos(&mut hasher, prune_pos).await.unwrap();

                // add 25 new elements, simulating a partial write after each.
                for j in 0..10 {
                    let digest = test_digest(100 * (i + 1) + j);
                    leaves.push(digest);
                    let last_leaf = leaves.last().unwrap();
                    let pos = mmr.add(&mut hasher, last_leaf).await.unwrap();
                    positions.push(pos);
                    mmr.add(&mut hasher, last_leaf).await.unwrap();
                    assert_eq!(mmr.root(&mut hasher), mmr.root(&mut hasher));
                    let digest = test_digest(LEAF_COUNT + i);
                    leaves.push(digest);
                    let last_leaf = leaves.last().unwrap();
                    let pos = mmr.add(&mut hasher, last_leaf).await.unwrap();
                    positions.push(pos);
                    mmr.add(&mut hasher, last_leaf).await.unwrap();
                }
                let end_size = mmr.size();
                let total_to_write = (end_size - start_size) as usize;
                let partial_write_limit = i % total_to_write;
                mmr.simulate_partial_sync(&mut hasher, partial_write_limit)
                    .await
                    .unwrap();
            }

            let mmr = Mmr::init(context.clone(), &mut hasher, test_config())
                .await
                .unwrap();
            mmr.destroy().await.unwrap();
        });
    }
}
