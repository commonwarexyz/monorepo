//! An MMR backed by a fixed-item-length journal.
//!
//! A [crate::journal] is used to store all unpruned MMR nodes, and a [crate::metadata] store is
//! used to preserve digests required for root and proof generation that would have otherwise been
//! pruned.

use crate::journal::{
    fixed::{Config as JConfig, Journal},
    Error as JError,
};
use crate::metadata::{Config as MConfig, Metadata};
use crate::mmr::{
    iterator::PeakIterator,
    mem::Mmr as MemMmr,
    verification::{Proof, Storage},
    Error,
};
use bytes::Bytes;
use commonware_cryptography::Hasher;
use commonware_runtime::{Blob, Clock, Metrics, Storage as RStorage};
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
}

/// A MMR backed by a fixed-item-length journal.
pub struct Mmr<B: Blob, E: RStorage<B> + Clock + Metrics, H: Hasher> {
    /// A memory resident MMR used to build the MMR structure and cache updates.
    mem_mmr: MemMmr<H>,

    /// Stores all unpruned MMR nodes.
    journal: Journal<B, E, H::Digest>,

    /// The size of the journal irrespective of any pruned nodes or any un-synced nodes currently
    /// cached in the memory resident MMR.
    journal_size: u64,

    /// Stores all "pinned nodes" (pruned nodes required for proving & root generation) for the MMR,
    /// and the corresponding pruning boundary used to generate them. The metadata remains empty
    /// until pruning is invoked, and its contents change only when the pruning boundary moves.
    metadata: Metadata<B, E, U64>,

    /// The last pruning boundary used to prune this MMR, or 0 if the MMR has never been pruned.
    pruned_to_pos: u64,
}

impl<B: Blob, E: RStorage<B> + Clock + Metrics, H: Hasher> Storage<H::Digest> for Mmr<B, E, H> {
    async fn size(&self) -> Result<u64, Error> {
        Ok(self.size())
    }

    async fn get_node(&self, position: u64) -> Result<Option<H::Digest>, Error> {
        if let Some(node) = self.mem_mmr.get_node(position) {
            return Ok(Some(node));
        }

        match self.journal.read(position).await {
            Ok(item) => Ok(Some(item)),
            Err(JError::ItemPruned(_)) => Ok(None),
            Err(e) => Err(Error::JournalError(e)),
        }
    }
}

impl<B: Blob, E: RStorage<B> + Clock + Metrics, H: Hasher> Mmr<B, E, H> {
    /// Initialize a new `Mmr` instance.
    pub async fn init(context: E, cfg: Config) -> Result<Self, Error> {
        let journal_cfg = JConfig {
            partition: cfg.journal_partition,
            items_per_blob: cfg.items_per_blob,
        };
        let mut journal =
            Journal::<B, E, H::Digest>::init(context.with_label("mmr_journal"), journal_cfg)
                .await?;
        let mut journal_size = journal.size().await?;

        let metadata_cfg = MConfig {
            partition: cfg.metadata_partition,
        };
        let metadata = Metadata::init(context.with_label("mmr_metadata"), metadata_cfg).await?;

        if journal_size == 0 {
            return Ok(Self {
                mem_mmr: MemMmr::new(),
                journal,
                journal_size,
                metadata,
                pruned_to_pos: 0,
            });
        }

        // Make sure the journal's oldest retained node is as expected based on the last pruning
        // boundary stored in metadata. If they don't match, prune the journal to the appropriate
        // location.
        let key: U64 = U64::new(Self::PRUNE_TO_POS_PREFIX, 0);
        let metadata_prune_pos = match metadata.get(&key) {
            Some(bytes) => u64::from_be_bytes(bytes.as_ref().try_into().unwrap()),
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

        let mut last_valid_size = journal_size;
        while !PeakIterator::check_validity(last_valid_size) {
            // Even this naive sequential backup must terminate in log2(n) iterations.
            // A size-0 MMR is always valid so this loop must terminate before underflow.
            last_valid_size -= 1;
        }
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
        for pos in Proof::<H>::nodes_to_pin(journal_size, journal_size) {
            let digest =
                Mmr::<B, E, H>::get_from_metadata_or_journal(&metadata, &journal, pos).await?;
            pinned_nodes.push(digest);
        }
        let mut mem_mmr = MemMmr::init(vec![], journal_size, pinned_nodes);

        // Compute the additional pinned nodes needed to prove all journal elements at the current
        // pruning boundary.
        let mut pinned_nodes = HashMap::new();
        for pos in Proof::<H>::nodes_to_pin(journal_size, metadata_prune_pos) {
            let digest =
                Mmr::<B, E, H>::get_from_metadata_or_journal(&metadata, &journal, pos).await?;
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
            let mut hasher = H::new();
            let pos = s.add(&mut hasher, &leaf);
            assert!(pos == journal_size);
            s.sync().await?;
            warn!(pos, "recovered orphaned leaf");
        }

        Ok(s)
    }

    /// Return the total number of nodes in the MMR, irrespective of any pruning. The next added
    /// element's position will have this value.
    pub fn size(&self) -> u64 {
        self.mem_mmr.size()
    }

    /// Attempt to get a node from the metadata, with fallback to journal lookup if it fails.
    /// Assumes the node should exist in at least one of these sources and returns a `MissingNode`
    /// error otherwise.
    async fn get_from_metadata_or_journal(
        metadata: &Metadata<B, E, U64>,
        journal: &Journal<B, E, H::Digest>,
        pos: u64,
    ) -> Result<H::Digest, Error> {
        if let Some(bytes) = metadata.get(&U64::new(0, pos)) {
            debug!(pos, "read node from metadata");
            let digest = H::Digest::try_from(bytes.as_ref());
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
    pub fn add(&mut self, h: &mut H, element: &H::Digest) -> u64 {
        self.mem_mmr.add(h, element)
    }

    /// Return the root hash of the MMR.
    pub fn root(&self, h: &mut H) -> H::Digest {
        self.mem_mmr.root(h)
    }

    /// Sync any new elements to disk.
    pub async fn sync(&mut self) -> Result<(), Error> {
        if self.size() == 0 {
            return Ok(());
        }

        // Write the nodes cached in the memory-resident MMR to the journal.
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
        let required_positions = Proof::<H>::nodes_to_pin(self.size(), self.pruned_to_pos);
        for pos in required_positions.into_iter() {
            let digest = self.mem_mmr.get_node_unchecked(pos);
            pinned_nodes.insert(pos, *digest);
        }

        // Now that the pinned node set has been recomputed, it's safe to prune the mem_mmr and
        // reinstate them.
        self.mem_mmr.prune_all();
        self.mem_mmr.add_pinned_nodes(pinned_nodes);

        Ok(())
    }

    /// Prefix used for nodes in the metadata prefixed U8 key.
    const NODE_PREFIX: u8 = 0;

    /// Prefix used for the key storing the prune_to_pos position in the metadata.
    const PRUNE_TO_POS_PREFIX: u8 = 1;

    /// Compute and add required nodes for the given pruning point to the metadata, and write it to
    /// disk. Return the computed set of required nodes.
    async fn update_metadata(
        &mut self,
        prune_to_pos: u64,
    ) -> Result<HashMap<u64, H::Digest>, Error> {
        let mut pinned_nodes = HashMap::new();
        let required_positions = Proof::<H>::nodes_to_pin(self.size(), prune_to_pos);
        for pos in required_positions.into_iter() {
            let digest = self.get_node(pos).await?.unwrap();
            self.metadata.put(
                U64::new(Self::NODE_PREFIX, pos),
                Bytes::copy_from_slice(digest.as_ref()),
            );
            pinned_nodes.insert(pos, digest);
        }

        let key: U64 = U64::new(Self::PRUNE_TO_POS_PREFIX, 0);
        self.metadata
            .put(key, Bytes::copy_from_slice(&prune_to_pos.to_be_bytes()));

        self.metadata.sync().await.map_err(Error::MetadataError)?;

        Ok(pinned_nodes)
    }

    /// Close the MMR, syncing any cached elements to disk and closing the journal.
    pub async fn close(mut self) -> Result<(), Error> {
        self.sync().await?;
        self.journal.close().await?;
        self.metadata.close().await.map_err(Error::MetadataError)
    }

    /// Return an inclusion proof for the specified element.
    ///
    /// Returns ElementPruned error if some element needed to generate the proof has been pruned.
    pub async fn proof(&self, element_pos: u64) -> Result<Proof<H>, Error> {
        self.range_proof(element_pos, element_pos).await
    }

    /// Return an inclusion proof for the specified range of elements, inclusive of both endpoints.
    ///
    /// Returns ElementPruned error if some element needed to generate the proof has been pruned.
    pub async fn range_proof(
        &self,
        start_element_pos: u64,
        end_element_pos: u64,
    ) -> Result<Proof<H>, Error> {
        Proof::<H>::range_proof::<Mmr<B, E, H>>(self, start_element_pos, end_element_pos).await
    }

    /// Prune as many nodes as possible, leaving behind at most items_per_blob nodes in the current
    /// blob.
    pub async fn prune_all(&mut self) -> Result<(), Error> {
        if self.size() != 0 {
            self.prune_to_pos(self.size()).await?;
            return Ok(());
        }
        Ok(())
    }

    /// Prune all nodes up to but not including the given position and update the pinned nodes.
    ///
    /// This implementation ensures that no failure can leave the MMR in an unrecoverable state.
    pub async fn prune_to_pos(&mut self, pos: u64) -> Result<(), Error> {
        assert!(pos <= self.size());
        if self.size() == 0 {
            return Ok(());
        }

        // Flush items cached in the mem_mmr to disk to ensure the current state is recoverable.
        self.sync().await?;

        // Update metadata to reflect the desired pruning boundary, allowing for recovery in the
        // event of a pruning failure.
        let pinned_nodes = self.update_metadata(pos).await?;

        self.journal.prune(pos).await?;
        self.mem_mmr.add_pinned_nodes(pinned_nodes);
        self.pruned_to_pos = pos;

        Ok(())
    }

    /// Return the position of the oldest retained node in the MMR, not including pinned nodes.
    pub fn oldest_retained_pos(&self) -> Option<u64> {
        if self.pruned_to_pos == self.size() {
            return None;
        }

        Some(self.pruned_to_pos)
    }

    #[cfg(test)]
    /// Sync elements to disk until `write_limit` elements have been written, then abort to simulate
    /// a partial write for testing failure scenarios.
    pub async fn simulate_partial_sync(mut self, write_limit: usize) -> Result<(), Error> {
        if write_limit == 0 {
            return Ok(());
        }

        // Write the nodes cached in the memory-resident MMR to the journal, aborting after
        // write_count nodes have been written.
        let mut written_count = 0usize;
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
    pub async fn simulate_pruning_failure(mut self, prune_to_pos: u64) -> Result<(), Error> {
        assert!(prune_to_pos <= self.size());

        // Flush items cached in the mem_mmr to disk to ensure the current state is recoverable.
        self.sync().await?;

        // Update metadata to reflect the desired pruning boundary, allowing for recovery in the
        // event of a pruning failure.
        self.update_metadata(prune_to_pos).await?;

        // Don't actually prune the journal to simulate failure
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{Blob, Config, Mmr, RStorage, Storage};
    use commonware_cryptography::{hash, sha256::Digest, Hasher, Sha256};
    use commonware_macros::test_traced;
    use commonware_runtime::{deterministic::Executor, Runner};

    fn test_digest(v: usize) -> Digest {
        hash(&v.to_be_bytes())
    }

    #[test_traced]
    fn test_journaled_mmr_empty() {
        let (executor, context, _) = Executor::default();
        executor.start(async move {
            let cfg = Config {
                journal_partition: "journal_partition".into(),
                metadata_partition: "metadata_partition".into(),
                items_per_blob: 7,
            };
            let mut mmr = Mmr::<_, _, Sha256>::init(context.clone(), cfg.clone())
                .await
                .unwrap();
            assert_eq!(mmr.size(), 0);
            assert!(mmr.get_node(0).await.is_err());
            assert_eq!(mmr.oldest_retained_pos(), None);
            assert!(mmr.prune_all().await.is_ok());
            assert!(mmr.prune_to_pos(0).await.is_ok());
            assert!(mmr.sync().await.is_ok());
        });
    }

    #[test_traced]
    fn test_journaled_mmr_basic() {
        let (executor, context, _) = Executor::default();
        executor.start(async move {
            let cfg = Config {
                journal_partition: "journal_partition".into(),
                metadata_partition: "metadata_partition".into(),
                items_per_blob: 7,
            };
            // Build a test MMR with 255 leaves
            let mut mmr = Mmr::<_, _, Sha256>::init(context.clone(), cfg.clone())
                .await
                .unwrap();
            const LEAF_COUNT: usize = 255;
            let mut hasher = Sha256::new();
            let mut leaves = Vec::with_capacity(LEAF_COUNT);
            let mut positions = Vec::with_capacity(LEAF_COUNT);
            for i in 0..LEAF_COUNT {
                let digest = test_digest(i);
                leaves.push(digest);
                let pos = mmr.add(&mut hasher, leaves.last().unwrap());
                positions.push(pos);
            }
            assert_eq!(mmr.size(), 502);
            assert_eq!(mmr.journal_size, 0);

            // Generate & verify proof from element that is not yet flushed to the journal.
            const TEST_ELEMENT: usize = 133;
            let test_element_pos = positions[TEST_ELEMENT];

            let proof = mmr.proof(test_element_pos).await.unwrap();
            let mut hasher = Sha256::new();
            let root = mmr.root(&mut hasher);
            assert!(proof.verify_element_inclusion(
                &mut hasher,
                &leaves[TEST_ELEMENT],
                test_element_pos,
                &root,
            ));

            // Sync the MMR, make sure it flushes the in-mem MMR as expected.
            mmr.sync().await.unwrap();
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
                last_element_pos,
                &root
            ));
        });
    }

    #[test_traced]
    /// Generates a stateful MMR, simulates various partial-write scenarios, and confirms we
    /// appropriately recover to a valid state.
    fn test_journaled_mmr_recovery() {
        let (executor, context, _) = Executor::default();
        executor.start(async move {
            let cfg = Config {
                journal_partition: "journal_partition".into(),
                metadata_partition: "metadata_partition".into(),
                items_per_blob: 7,
            };
            let mut mmr = Mmr::<_, _, Sha256>::init(context.clone(), cfg.clone())
                .await
                .unwrap();
            assert_eq!(mmr.size(), 0);

            // Build a test MMR with 252 leaves
            const LEAF_COUNT: usize = 252;
            let mut hasher = Sha256::new();
            let mut leaves = Vec::with_capacity(LEAF_COUNT);
            let mut positions = Vec::with_capacity(LEAF_COUNT);
            for i in 0..LEAF_COUNT {
                let digest = test_digest(i);
                leaves.push(digest);
                let pos = mmr.add(&mut hasher, leaves.last().unwrap());
                positions.push(pos);
            }
            assert_eq!(mmr.size(), 498);
            mmr.close().await.unwrap();

            // The very last element we added (pos=495) resulted in new parents at positions 496 &
            // 497. Simulate a partial write by corrupting the last parent's checksum by truncating
            // the last blob by a single byte.
            let partition: String = "journal_partition".into();
            let blob = context
                .open(&partition, &71u64.to_be_bytes())
                .await
                .expect("Failed to open blob");
            let len = blob.len().await.expect("Failed to get blob length");
            assert_eq!(len, 36); // N+4 = 36 bytes per node, 1 node in the last blob

            // truncate the blob by one byte to corrupt the checksum of the last parent node.
            blob.truncate(len - 1)
                .await
                .expect("Failed to corrupt blob");
            blob.close().await.expect("Failed to close blob");

            let mmr = Mmr::<_, _, Sha256>::init(context.clone(), cfg.clone())
                .await
                .unwrap();
            // Since we didn't corrupt the leaf, the MMR is able to replay the leaf and recover to
            // the previous state.
            assert_eq!(mmr.size(), 498);

            // Make sure closing it and re-opening it persists the recovered state.
            mmr.close().await.unwrap();
            let mmr = Mmr::<_, _, Sha256>::init(context.clone(), cfg.clone())
                .await
                .unwrap();
            assert_eq!(mmr.size(), 498);
            mmr.close().await.unwrap();

            // Repeat partial write test though this time truncate the leaf itself not just some
            // parent. The leaf is in the *previous* blob so we'll have to delete the most recent
            // blob, then appropriately truncate the previous one.
            context
                .remove(&partition, Some(&71u64.to_be_bytes()))
                .await
                .expect("Failed to remove blob");
            let blob = context
                .open(&partition, &70u64.to_be_bytes())
                .await
                .expect("Failed to open blob");
            let len = blob.len().await.expect("Failed to get blob length");
            assert_eq!(len, 36 * 7); // this blob should be full.

            // The last leaf should be in slot 5 of this blob, truncate last byte of its checksum.
            blob.truncate(36 * 5 + 35)
                .await
                .expect("Failed to corrupt blob");
            blob.close().await.expect("Failed to close blob");

            let mmr = Mmr::<_, _, Sha256>::init(context.clone(), cfg.clone())
                .await
                .unwrap();
            // Since the leaf was corrupted, it should not have been recovered, and the journal's
            // size will be the last-valid size.
            assert_eq!(mmr.size(), 495);
        });
    }

    #[test_traced]
    fn test_journaled_mmr_pruning() {
        let (executor, context, _) = Executor::default();
        executor.start(async move {
            let cfg = Config {
                journal_partition: "journal_partition".into(),
                metadata_partition: "metadata_partition".into(),
                items_per_blob: 7,
            };

            // Build two test MMRs with 2000 leaves, one that will be pruned and one that won't, and
            // make sure pruning doesn't break root hashing, adding of new nodes, etc.
            const LEAF_COUNT: usize = 2000;
            let mut pruned_mmr = Mmr::<_, _, Sha256>::init(context.clone(), cfg.clone())
                .await
                .unwrap();
            let cfg_unpruned = Config {
                journal_partition: "unpruned_journal_partition".into(),
                metadata_partition: "unpruned_metadata_partition".into(),
                items_per_blob: 7,
            };
            let mut mmr = Mmr::<_, _, Sha256>::init(context.clone(), cfg_unpruned)
                .await
                .unwrap();
            let mut hasher = Sha256::new();
            let mut leaves = Vec::with_capacity(LEAF_COUNT);
            let mut positions = Vec::with_capacity(LEAF_COUNT);
            for i in 0..LEAF_COUNT {
                let digest = test_digest(i);
                leaves.push(digest);
                let last_leaf = leaves.last().unwrap();
                let pos = mmr.add(&mut hasher, last_leaf);
                positions.push(pos);
                pruned_mmr.add(&mut hasher, last_leaf);
            }
            assert_eq!(mmr.size(), 3994);
            assert_eq!(pruned_mmr.size(), 3994);

            // Prune the MMR in increments of 10 making sure the journal is still able to compute
            // roots and accept new elements.
            let mut hasher = Sha256::new();
            for i in 0usize..300 {
                pruned_mmr.prune_to_pos(i as u64 * 10).await.unwrap();

                let digest = test_digest(LEAF_COUNT + i);
                leaves.push(digest);
                let last_leaf = leaves.last().unwrap();
                let pos = pruned_mmr.add(&mut hasher, last_leaf);
                positions.push(pos);
                mmr.add(&mut hasher, last_leaf);
                assert_eq!(pruned_mmr.root(&mut hasher), mmr.root(&mut hasher));
            }

            // Sync the MMRs.
            pruned_mmr.sync().await.unwrap();
            assert_eq!(pruned_mmr.root(&mut hasher), mmr.root(&mut hasher));

            // Close the MMR & reopen.
            pruned_mmr.close().await.unwrap();
            let mut pruned_mmr = Mmr::<_, _, Sha256>::init(context.clone(), cfg.clone())
                .await
                .unwrap();
            assert_eq!(pruned_mmr.root(&mut hasher), mmr.root(&mut hasher));

            // Prune everything.
            pruned_mmr.prune_all().await.unwrap();
            assert_eq!(pruned_mmr.root(&mut hasher), mmr.root(&mut hasher));
            assert_eq!(pruned_mmr.oldest_retained_pos(), None);

            // Close MMR after adding a new node without syncing and make sure state is as expected
            // on reopening.
            mmr.add(&mut hasher, &test_digest(LEAF_COUNT));
            pruned_mmr.add(&mut hasher, &test_digest(LEAF_COUNT));
            assert!(pruned_mmr.size() % cfg.items_per_blob != 0);
            pruned_mmr.close().await.unwrap();
            let mut pruned_mmr = Mmr::<_, _, Sha256>::init(context.clone(), cfg.clone())
                .await
                .unwrap();
            assert_eq!(pruned_mmr.root(&mut hasher), mmr.root(&mut hasher));

            // Add nodes until we are on a blob boundary, and confirm prune_all still removes all
            // retained nodes.
            while pruned_mmr.size() % cfg.items_per_blob != 0 {
                pruned_mmr.add(&mut hasher, &test_digest(LEAF_COUNT));
            }
            pruned_mmr.prune_all().await.unwrap();
            assert_eq!(pruned_mmr.oldest_retained_pos(), None);
        });
    }

    #[test_traced("WARN")]
    /// Simulate partial writes after pruning, making sure we recover to a valid state.
    fn test_journaled_mmr_recovery_with_pruning() {
        let (executor, context, _) = Executor::default();
        executor.start(async move {
            let cfg = Config {
                journal_partition: "journal_partition".into(),
                metadata_partition: "metadata_partition".into(),
                items_per_blob: 7,
            };

            // Build MMR with 2000 leaves.
            const LEAF_COUNT: usize = 2000;
            let mut mmr = Mmr::<_, _, Sha256>::init(context.clone(), cfg.clone())
                .await
                .unwrap();
            let mut hasher = Sha256::new();
            let mut leaves = Vec::with_capacity(LEAF_COUNT);
            let mut positions = Vec::with_capacity(LEAF_COUNT);
            for i in 0..LEAF_COUNT {
                let digest = test_digest(i);
                leaves.push(digest);
                let last_leaf = leaves.last().unwrap();
                let pos = mmr.add(&mut hasher, last_leaf);
                positions.push(pos);
            }
            assert_eq!(mmr.size(), 3994);
            mmr.close().await.unwrap();

            // Prune the MMR in increments of 50, simulating a partial write after each prune.
            let mut hasher = Sha256::new();
            for i in 0usize..200 {
                let mut mmr = Mmr::<_, _, Sha256>::init(context.clone(), cfg.clone())
                    .await
                    .unwrap();
                let start_size = mmr.size();
                let prune_pos = std::cmp::min(i as u64 * 50, start_size);
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
                    let pos = mmr.add(&mut hasher, last_leaf);
                    positions.push(pos);
                    mmr.add(&mut hasher, last_leaf);
                    assert_eq!(mmr.root(&mut hasher), mmr.root(&mut hasher));
                    let digest = test_digest(LEAF_COUNT + i);
                    leaves.push(digest);
                    let last_leaf = leaves.last().unwrap();
                    let pos = mmr.add(&mut hasher, last_leaf);
                    positions.push(pos);
                    mmr.add(&mut hasher, last_leaf);
                }
                let end_size = mmr.size();
                let total_to_write = (end_size - start_size) as usize;
                let partial_write_limit = i % total_to_write;
                mmr.simulate_partial_sync(partial_write_limit)
                    .await
                    .unwrap();
            }
        });
    }
}
