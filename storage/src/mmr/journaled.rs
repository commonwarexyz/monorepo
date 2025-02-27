//! An MMR backed by a fixed-item-length journal.
//!
//! A [crate::journal] is used to store all unpruned MMR nodes, and a [crate::metadata] store is
//! used to preserve each current peak digest in case they would otherwise have been be pruned.

use crate::journal::{
    fixed::{Config as JConfig, Journal},
    Error as JError,
};
use crate::metadata::{Config as MConfig, Metadata};
use crate::mmr::{
    iterator::{oldest_provable_pos, oldest_required_proof_pos, PeakIterator},
    mem::Mmr as MemMmr,
    verification::{Proof, Storage},
    Error,
};
use bytes::Bytes;
use commonware_cryptography::Hasher;
use commonware_runtime::{Blob, Clock, Metrics, Storage as RStorage};
use commonware_utils::array::U64;
use tracing::{error, warn};

/// Configuration for a journal-backed MMR.
#[derive(Clone)]
pub struct Config {
    /// The name of the `commonware-runtime::Storage` storage partition used for the journal storing
    /// the MMR nodes.
    pub journal_partition: String,

    /// The name of the `commonware-runtime::Storage` storage partition used for the metadata
    /// containing the MMR's current peaks.
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

    /// Stores all current peaks of the MMR.
    metadata: Metadata<B, E, U64>,
}

impl<B: Blob, E: RStorage<B> + Clock + Metrics, H: Hasher> Storage<H> for Mmr<B, E, H> {
    async fn size(&self) -> Result<u64, Error> {
        Ok(self.mem_mmr.size())
    }

    async fn get_node(&self, position: u64) -> Result<Option<H::Digest>, Error> {
        let Some(oldest_retained_pos) = self.mem_mmr.oldest_retained_pos() else {
            return Ok(None);
        };
        if position >= oldest_retained_pos {
            return self.mem_mmr.get_node(position).await;
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
            });
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

        // We bootstrap the in-mem MMR cache in the "prune_all" state where it only remembers the
        // most recent node.
        let mut bootstrap_peaks = Vec::new();
        for (peak, _) in PeakIterator::new(journal_size) {
            let bytes = metadata.get(&U64::new(peak));
            if bytes.is_none() {
                // If a peak isn't found in the metadata, it might still be in the journal. This
                // shouldn't happen unless there was a sync failure leading to a (recoverable)
                // inconsistency.
                warn!("Metadata should have had peak {}", peak);
                let node = journal.read(peak).await;
                match node {
                    Ok(node) => {
                        bootstrap_peaks.push(node);
                        continue;
                    }
                    Err(JError::ItemPruned(_)) => {
                        error!("Peak {} is missing from metadata and journal", peak);
                        return Err(Error::MissingPeak(peak));
                    }
                    Err(e) => {
                        return Err(Error::JournalError(e));
                    }
                }
            }
            let digest = H::Digest::try_from(bytes.unwrap().as_ref());
            if let Ok(digest) = digest {
                bootstrap_peaks.push(digest);
            } else {
                error!(
                    "Could not convert peak {} from metadata bytes to digest: {}",
                    peak,
                    digest.err().unwrap()
                );
                return Err(Error::MissingPeak(peak));
            }
        }

        let oldest_remembered_digest = bootstrap_peaks.pop().unwrap();
        let mem_mmr = MemMmr::init(
            vec![oldest_remembered_digest],
            journal_size - 1,
            bootstrap_peaks,
        );

        let mut s = Self {
            mem_mmr,
            journal,
            journal_size,
            metadata,
        };

        if let Some(leaf) = orphaned_leaf {
            // Recover the orphaned leaf and any missing parents.
            let mut hasher = H::new();
            let pos = s.add(&mut hasher, &leaf);
            assert!(pos == journal_size);
            s.sync().await?;
            warn!(leaf_position = pos, "recovered orphaned leaf");
        }
        Ok(s)
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
        // Write the nodes cached in the memory-resident MMR to the journal.
        for i in self.journal_size..self.mem_mmr.size() {
            let node = self.mem_mmr.get_node(i).await?.unwrap();
            self.journal.append(node).await?;
        }
        self.journal_size = self.mem_mmr.size();
        self.journal.sync().await?;
        assert_eq!(self.journal_size, self.journal.size().await?);

        // Clear out old peaks, then write the latest peaks to metadata.
        self.metadata.clear();
        let peak_iterator = self.mem_mmr.peak_iterator();
        for (peak_pos, _) in peak_iterator {
            let digest = self.mem_mmr.get_node(peak_pos).await?.unwrap();
            self.metadata
                .put(U64::new(peak_pos), Bytes::copy_from_slice(digest.as_ref()));
        }
        self.metadata.sync().await.map_err(Error::MetadataError)?;

        // Keep memory usage in check by pruning old nodes from the memory-resident MMR after
        // they've been written to disk.
        self.mem_mmr.prune_all();

        Ok(())
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

    /// Prune all but the very last node.
    ///
    /// This always leaves the MMR in a valid state since the last node is always a peak.
    pub async fn prune_all(&mut self) -> Result<(), Error> {
        if self.mem_mmr.size() != 0 {
            self.prune(self.mem_mmr.size() - 1).await?;
            return Ok(());
        }
        Ok(())
    }

    /// Prune the maximum amount of nodes possible while still allowing nodes with position `pos` or
    /// newer to be provable, returning the position of the oldest retained node. The MMR is synced
    /// in the process.
    ///
    /// Note that the guarantee that nodes in position `pos` or newer are provable does not
    /// necessarily hold after more elements are added to the MMR. This is because adding new nodes
    /// may change the peaks, and provability assumes the original peaks (that existed at the time
    /// of pruning) remain available.
    ///
    /// TODO: Consider persisting all historical peaks required to guarantee the stability of any
    /// provability guarantee provided by any call to this function.
    pub async fn prune(&mut self, provable_pos: u64) -> Result<Option<u64>, Error> {
        if self.mem_mmr.size() == 0 {
            return Ok(None);
        }
        // Flush mem-mmr items to disk and write new peaks to metadata. TODO: optimize this to avoid
        // writing any cached items which will just be immediately pruned.
        self.sync().await?;

        let oldest_required_pos =
            oldest_required_proof_pos(self.mem_mmr.peak_iterator(), provable_pos);
        self.journal.prune(oldest_required_pos).await?;

        Ok(self.journal.oldest_retained_pos().await?)
    }

    /// Return the position of the oldest retained node in the MMR, not including the peaks which
    /// are always retained.
    pub async fn oldest_retained_pos(&self) -> Result<Option<u64>, Error> {
        let Some(oldest_mem_retained_pos) = self.mem_mmr.oldest_retained_pos() else {
            return Ok(None);
        };
        let oldest_retained_pos = match self.journal.oldest_retained_pos().await? {
            Some(pos) => pos,
            None => oldest_mem_retained_pos, // happens when journal has never been synced
        };
        assert!(oldest_retained_pos <= oldest_mem_retained_pos);
        Ok(Some(oldest_retained_pos))
    }

    /// Return the oldest node position provable by this MMR.
    pub async fn oldest_provable_pos(&self) -> Result<Option<u64>, Error> {
        let Some(oldest_retained_pos) = self.oldest_retained_pos().await? else {
            return Ok(None);
        };
        let oldest_provable_pos =
            oldest_provable_pos(self.mem_mmr.peak_iterator(), oldest_retained_pos);
        Ok(Some(oldest_provable_pos))
    }

    #[cfg(test)]
    /// Sync elements to disk until `write_limit` elements have been written, then abort to simulate
    /// a partial write for testing failure scenarios.
    pub async fn simulate_partial_sync(mut self, write_limit: usize) -> Result<(), Error> {
        if write_limit == 0 {
            return Ok(());
        }
        // Write peaks to metadata without clearing out old ones to ensure we can recover to a
        // previous valid state if the later writes to the journal fail.
        let peak_iterator = self.mem_mmr.peak_iterator();
        for (peak_pos, _) in peak_iterator {
            let digest = self.mem_mmr.get_node(peak_pos).await?.unwrap();
            self.metadata
                .put(U64::new(peak_pos), Bytes::copy_from_slice(digest.as_ref()));
        }
        self.metadata.sync().await?;

        // Write the nodes cached in the memory-resident MMR to the journal, aborting after
        // write_count nodes have been written.
        let mut written_count = 0usize;
        for i in self.journal_size..self.mem_mmr.size() {
            let node = self.mem_mmr.get_node(i).await?.unwrap();
            self.journal.append(node).await?;
            written_count += 1;
            if written_count >= write_limit {
                break;
            }
        }
        self.journal.sync().await?;

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
            assert_eq!(mmr.size().await.unwrap(), 0);
            assert_eq!(mmr.get_node(0).await.unwrap(), None);
            assert_eq!(mmr.oldest_provable_pos().await.unwrap(), None);
            assert_eq!(mmr.prune(0).await.unwrap(), None);
            assert!(mmr.prune_all().await.is_ok());

            // Make sure oldest_provable_pos works on an empty journal when the cache is non-empty.
            mmr.add(&mut Sha256::new(), &test_digest(42));
            assert_eq!(mmr.size().await.unwrap(), 1);
            assert_eq!(mmr.oldest_provable_pos().await.unwrap(), Some(0));
        });
    }

    #[test_traced]
    fn test_journaled_mmr() {
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
            assert_eq!(mmr.size().await.unwrap(), 502);
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
            assert_eq!(mmr.mem_mmr.oldest_retained_pos().unwrap(), 501);

            // Now that the element is flushed from the in-mem MMR, make its proof is still is
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
            assert_eq!(mmr.size().await.unwrap(), 0);

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
            assert_eq!(mmr.size().await.unwrap(), 498);
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
            assert_eq!(mmr.size().await.unwrap(), 498);

            // Make sure closing it and re-opening it persists the recovered state.
            mmr.close().await.unwrap();
            let mmr = Mmr::<_, _, Sha256>::init(context.clone(), cfg.clone())
                .await
                .unwrap();
            assert_eq!(mmr.size().await.unwrap(), 498);
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
            assert_eq!(mmr.size().await.unwrap(), 495);
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
            assert_eq!(mmr.size().await.unwrap(), 3994);
            assert_eq!(pruned_mmr.size().await.unwrap(), 3994);

            // Prune the MMR in increments of 10 making sure the journal is still able to compute
            // roots and accept new elements.
            let mut hasher = Sha256::new();
            for i in 0usize..300 {
                pruned_mmr.prune(i as u64 * 10).await.unwrap();
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
            let oldest_retained = pruned_mmr.oldest_provable_pos().await.unwrap().unwrap();

            // Close MMR without syncing and make sure state is as expected on reopening.
            pruned_mmr.close().await.unwrap();
            let pruned_mmr = Mmr::<_, _, Sha256>::init(context.clone(), cfg.clone())
                .await
                .unwrap();
            assert_eq!(pruned_mmr.root(&mut hasher), mmr.root(&mut hasher));
            assert_eq!(
                pruned_mmr.journal.oldest_retained_pos().await.unwrap(),
                Some(oldest_retained)
            );
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
            assert_eq!(mmr.size().await.unwrap(), 3994);
            mmr.close().await.unwrap();

            // Prune the MMR in increments of 50, simulating a partial write after each prune.
            let mut hasher = Sha256::new();
            for i in 0usize..200 {
                let mut mmr = Mmr::<_, _, Sha256>::init(context.clone(), cfg.clone())
                    .await
                    .unwrap();
                let provable_pos = i as u64 * 50;
                mmr.prune(provable_pos).await.unwrap().unwrap();
                let start_size = mmr.size().await.unwrap();
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
                let end_size = mmr.size().await.unwrap();
                let total_to_write = (end_size - start_size) as usize;
                let partial_write_limit = i % total_to_write;
                mmr.simulate_partial_sync(partial_write_limit)
                    .await
                    .unwrap();
            }
        });
    }
}
