//! An MMR backed by a fixed-item-length journal.
//!
//! If the journal is pruned beyond the point of some peak, then a metadata store is used to
//! preserve its digest. When the MMR is pruned, the metadata store is updated to contain the
//! digests of the new peaks without deleting any old ones to allow for recovery in case the
//! subsequent sync of the journal fails.

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
use futures::future::try_join_all;
use tracing::{error, warn};

/// Configuration for a journal-backed MMR.
#[derive(Clone)]
pub struct Config {
    /// The prefix to use for the names of the `commonware-runtime::Storage` partitions used for the
    /// MMR metadata and backing journal.  "_metadata" and "_journal" will be appended to this
    /// prefix to form the names of the metadata and journal partitions, respectively.
    pub partition_prefix: String,

    /// The maximum number of items to store in each blob in the backing journal.
    pub items_per_blob: u64,
}

/// A MMR backed by a fixed-item-length journal.
pub struct Mmr<B: Blob, E: RStorage<B> + Clock + Metrics, H: Hasher> {
    mem_mmr: MemMmr<H>,
    journal: Journal<B, E, H::Digest>,
    journal_size: u64,
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
        let metadata_cfg = MConfig {
            partition: format!("{}{}", cfg.partition_prefix, "_metadata"),
        };
        let metadata = Metadata::init(context.with_label("mmr_metadata"), metadata_cfg).await?;

        let journal_cfg = JConfig {
            partition: format!("{}{}", cfg.partition_prefix, "_journal"),
            items_per_blob: cfg.items_per_blob,
        };
        let mut journal =
            Journal::<B, E, H::Digest>::init(context.with_label("mmr_journal"), journal_cfg)
                .await?;
        let mut journal_size = journal.size().await?;
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
        let oldest_retained_pos = journal.oldest_retained_pos().await?.unwrap();
        let mut bootstrap_peaks_futures: Vec<_> = Vec::new();
        let mut bootstrap_peaks = Vec::new();
        for (peak, _) in PeakIterator::new(journal_size) {
            if peak >= oldest_retained_pos {
                bootstrap_peaks_futures.push(journal.read(peak));
            } else {
                let bytes = metadata.get(&U64::new(peak));
                if bytes.is_none() {
                    // if a peak isn't found in the metadata the data is corrupt
                    error!("Metadata should have had peak {}", peak);
                    return Err(Error::MissingPeak(peak));
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
        }

        let resolved_peaks: Vec<H::Digest> = try_join_all(bootstrap_peaks_futures).await?;
        bootstrap_peaks.extend(resolved_peaks);
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
        // Write peaks to metadata without clearing out old ones to ensure we can recover to a
        // previous valid state if later writes fail.
        let peak_iterator = self.mem_mmr.peak_iterator();
        for (peak_pos, height) in peak_iterator {
            let bytes = height.to_be_bytes().to_vec();
            self.metadata.put(U64::new(peak_pos), Bytes::from(bytes));
        }

        println!("Syncing {} to {}", self.journal_size, self.mem_mmr.size());

        for i in self.journal_size..self.mem_mmr.size() {
            let node = self.mem_mmr.get_node(i).await?.unwrap();
            self.journal.append(node).await?;
        }
        self.journal_size = self.mem_mmr.size();
        self.mem_mmr.prune_all();
        self.journal.sync().await?;
        Ok(())
    }

    /// Close the journal
    pub async fn close(mut self) -> Result<(), Error> {
        self.sync().await?;
        self.journal.close().await?;

        // Clear peaks and repopulate to purge any old ones that are no longer needed.
        self.metadata.clear();
        let peak_iterator = self.mem_mmr.peak_iterator();
        for (peak_pos, _) in peak_iterator {
            let digest = self.mem_mmr.get_node(peak_pos).await?.unwrap();
            self.metadata
                .put(U64::new(peak_pos), Bytes::copy_from_slice(digest.as_ref()));
        }
        self.metadata.sync().await.map_err(Error::MetadataError)
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

    pub async fn prune(&mut self, provable_pos: u64) -> Result<Option<u64>, Error> {
        // Flush mem-mmr items to disk and write new peaks to metadata. TODO: optimize this to avoid
        // writing items which will just be immediately pruned.
        self.sync().await?;

        let oldest_pos = oldest_required_proof_pos(self.mem_mmr.peak_iterator(), provable_pos);
        println!(
            "Pruning to {} {} {}",
            oldest_pos, provable_pos, self.journal_size
        );
        self.journal.prune(oldest_pos).await?;

        Ok(self.journal.oldest_retained_pos().await?)
    }

    /// Return the oldest node position provable by this MMR.
    ///
    /// Will return 0 unless pruning has been invoked.
    pub async fn oldest_provable_pos(&self) -> Result<Option<u64>, Error> {
        let Some(oldest_mem_retained_pos) = self.journal.oldest_retained_pos().await? else {
            return Ok(None);
        };
        let oldest_retained_pos = match self.mem_mmr.oldest_retained_pos() {
            Some(pos) => pos,
            None => oldest_mem_retained_pos,
        };
        let oldest_provable_pos =
            oldest_provable_pos(self.mem_mmr.peak_iterator(), oldest_retained_pos);
        Ok(Some(oldest_provable_pos))
    }
}

#[cfg(test)]
mod tests {
    use super::{Blob, Config, Mmr, RStorage, Storage};
    use commonware_cryptography::{hash, sha256::Digest, Hasher, Sha256};
    use commonware_macros::test_traced;
    use commonware_runtime::{deterministic::Executor, Runner};

    fn test_digest(v: u32) -> Digest {
        hash(&v.to_be_bytes())
    }

    #[test_traced]
    fn test_journaled_mmr() {
        let (executor, context, _) = Executor::default();
        executor.start(async move {
            let cfg = Config {
                partition_prefix: "test_partition".into(),
                items_per_blob: 7,
            };
            let mut mmr = Mmr::<_, _, Sha256>::init(context.clone(), cfg.clone())
                .await
                .unwrap();
            assert_eq!(mmr.size().await.unwrap(), 0);
            assert_eq!(mmr.get_node(0).await.unwrap(), None);

            // Build a test MMR with 255 leaves
            const LEAF_COUNT: usize = 255;
            let mut hasher = Sha256::new();
            let mut leaves = Vec::with_capacity(LEAF_COUNT);
            let mut positions = Vec::with_capacity(LEAF_COUNT);
            for i in 0u32..LEAF_COUNT as u32 {
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

    /// Generates a stateful MMR, simulates various partial-write scenarios, and confirms we
    /// appropriately recover to a valid state.
    #[test_traced]
    fn test_journaled_mmr_recovery() {
        let (executor, context, _) = Executor::default();
        executor.start(async move {
            let cfg = Config {
                partition_prefix: "test_partition".into(),
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
            for i in 0u32..LEAF_COUNT as u32 {
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
            let partition = cfg.partition_prefix.clone() + "_journal";
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
                partition_prefix: "test_partition_pruned".into(),
                items_per_blob: 7,
            };
            let mut pruned_mmr = Mmr::<_, _, Sha256>::init(context.clone(), cfg.clone())
                .await
                .unwrap();
            let cfg2 = Config {
                partition_prefix: "test_partition_unpruned".into(),
                items_per_blob: 7,
            };
            let mut mmr = Mmr::<_, _, Sha256>::init(context.clone(), cfg2)
                .await
                .unwrap();

            // Build two test MMRs with 2000 leaves, one that will be pruned and one that won't.
            const LEAF_COUNT: usize = 2000;
            let mut hasher = Sha256::new();
            let mut leaves = Vec::with_capacity(LEAF_COUNT);
            let mut positions = Vec::with_capacity(LEAF_COUNT);
            for i in 0u32..LEAF_COUNT as u32 {
                let digest = test_digest(i);
                leaves.push(digest);
                let last_leaf = leaves.last().unwrap();
                let pos = mmr.add(&mut hasher, last_leaf);
                positions.push(pos);
                pruned_mmr.add(&mut hasher, last_leaf);
            }
            assert_eq!(mmr.size().await.unwrap(), 3994);
            assert_eq!(pruned_mmr.size().await.unwrap(), 3994);

            let mut hasher = Sha256::new();
            // Prune the MMR in increments of 10 making sure the journal is still able to compute
            // roots and accept new elements.
            for i in 0u32..300 {
                pruned_mmr.prune(i as u64 * 10).await.unwrap();
                let digest = test_digest(LEAF_COUNT as u32 + i);
                leaves.push(digest);
                let last_leaf = leaves.last().unwrap();
                let pos = pruned_mmr.add(&mut hasher, last_leaf);
                positions.push(pos);
                mmr.add(&mut hasher, last_leaf);
                println!(
                    "Ho ho ho {} {} {:?}",
                    i,
                    pos,
                    pruned_mmr.oldest_provable_pos().await.unwrap()
                );
                assert_eq!(pruned_mmr.root(&mut hasher), mmr.root(&mut hasher));
            }

            // Sync the MMRs.
            pruned_mmr.sync().await.unwrap();
            assert_eq!(pruned_mmr.root(&mut hasher), mmr.root(&mut hasher));

            // Close the MMR & reopen.
            pruned_mmr.close().await.unwrap();
            let pruned_mmr = Mmr::<_, _, Sha256>::init(context.clone(), cfg.clone())
                .await
                .unwrap();
            println!(
                "{} {}",
                pruned_mmr.size().await.unwrap(),
                mmr.size().await.unwrap()
            );
            assert_eq!(pruned_mmr.root(&mut hasher), mmr.root(&mut hasher));
        });
    }
}
