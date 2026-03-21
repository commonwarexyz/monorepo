//! A Merkle structure backed by a fixed-item-length journal.
//!
//! A [crate::journal] is used to store all unpruned nodes, and a [crate::metadata] store is
//! used to preserve digests required for root and proof generation that would have otherwise been
//! pruned.
//!
//! This module is generic over [`Family`], so it works for both MMR and MMB.

// All public items here will be used once `mmr::journaled` delegates to this generic module.
#![allow(dead_code)]

use crate::{
    journal::{
        contiguous::{
            fixed::{Config as JConfig, Journal},
            Reader,
        },
        Error as JError,
    },
    merkle::{
        batch::{self, ChainInfo, UnmerkleizedBatch},
        hasher::Hasher,
        mem::{Config as MemConfig, Mem},
        Error, Family, Location, Position, Proof, Readable,
    },
    metadata::{Config as MConfig, Metadata},
};
use commonware_codec::DecodeExt;
use commonware_cryptography::Digest;
use commonware_parallel::ThreadPool;
use commonware_runtime::{buffer::paged::CacheRef, Clock, Metrics, Storage as RStorage};
use commonware_utils::{
    sequence::prefixed_u64::U64,
    sync::{AsyncMutex, RwLock},
};
use std::{
    collections::BTreeMap,
    num::{NonZeroU64, NonZeroUsize},
};
use tracing::{debug, error, warn};

/// Fields of [Journaled] that are protected by an [RwLock] for interior mutability.
pub(crate) struct Inner<F: Family, D: Digest> {
    /// A memory resident Merkle structure used to build the structure and cache updates. It caches
    /// all un-synced nodes, and the pinned node set as derived from both its own pruning boundary
    /// and the journaled structure's pruning boundary.
    pub(crate) mem: Mem<F, D>,

    /// The highest position for which this structure has been pruned, or 0 if it has never been
    /// pruned.
    pub(crate) pruned_to_pos: Position<F>,
}

/// Configuration for a journal-backed Merkle structure.
#[derive(Clone)]
pub struct Config {
    /// The name of the `commonware-runtime::Storage` storage partition used for the journal storing
    /// the nodes.
    pub journal_partition: String,

    /// The name of the `commonware-runtime::Storage` storage partition used for the metadata
    /// containing pruned nodes that are still required to calculate the root and generate
    /// proofs.
    pub metadata_partition: String,

    /// The maximum number of items to store in each blob in the backing journal.
    pub items_per_blob: NonZeroU64,

    /// The size of the write buffer to use for each blob in the backing journal.
    pub write_buffer: NonZeroUsize,

    /// Optional thread pool to use for parallelizing batch operations.
    pub thread_pool: Option<ThreadPool>,

    /// The page cache to use for caching data.
    pub page_cache: CacheRef,
}

/// Configuration for initializing a journaled Merkle structure for synchronization.
///
/// Determines how to handle existing persistent data based on sync boundaries:
/// - **Fresh Start**: Existing data < range start -> discard and start fresh
/// - **Prune and Reuse**: range contains existing data -> prune and reuse
/// - **Error**: existing data > range end
pub struct SyncConfig<F: Family, D: Digest> {
    /// Base configuration (journal, metadata, etc.)
    pub config: Config,

    /// Sync range expressed as leaf-aligned bounds.
    pub range: std::ops::Range<Location<F>>,

    /// The pinned nodes the structure needs at the pruning boundary (range start), in the order
    /// specified by `Family::nodes_to_pin`. If `None`, the pinned nodes are expected to already be
    /// in the structure's metadata/journal.
    pub pinned_nodes: Option<Vec<D>>,
}

/// A Merkle structure backed by a fixed-item-length journal.
pub struct Journaled<F: Family, E: RStorage + Clock + Metrics, D: Digest> {
    /// Lock-protected mutable state.
    pub(crate) inner: RwLock<Inner<F, D>>,

    /// Stores all unpruned nodes.
    journal: Journal<E, D>,

    /// Stores all "pinned nodes" (pruned nodes required for proving & root generation), and the
    /// corresponding pruning boundary used to generate them. The metadata remains empty until
    /// pruning is invoked, and its contents change only when the pruning boundary moves.
    metadata: Metadata<E, U64, Vec<u8>>,

    /// Serializes concurrent sync calls.
    sync_lock: AsyncMutex<()>,

    /// The thread pool to use for parallelization.
    pool: Option<ThreadPool>,
}

/// Prefix used for nodes in the metadata prefixed U8 key.
const NODE_PREFIX: u8 = 0;

/// Prefix used for the key storing the pruning boundary (as a leaf index) in the metadata.
const PRUNED_TO_PREFIX: u8 = 1;

impl<F: Family, E: RStorage + Clock + Metrics, D: Digest> Journaled<F, E, D> {
    /// Return the total number of nodes in the structure, irrespective of any pruning. The next
    /// added element's position will have this value.
    pub fn size(&self) -> Position<F> {
        self.inner.read().mem.size()
    }

    /// Return the total number of leaves in the structure.
    pub fn leaves(&self) -> Location<F> {
        self.inner.read().mem.leaves()
    }

    /// Attempt to get a node from the metadata, with fallback to journal lookup if it fails.
    /// Assumes the node should exist in at least one of these sources and returns a `MissingNode`
    /// error otherwise.
    async fn get_from_metadata_or_journal(
        metadata: &Metadata<E, U64, Vec<u8>>,
        journal: &Journal<E, D>,
        pos: Position<F>,
    ) -> Result<D, Error<F>> {
        if let Some(bytes) = metadata.get(&U64::new(NODE_PREFIX, *pos)) {
            debug!(?pos, "read node from metadata");
            let digest = D::decode(bytes.as_ref());
            let Ok(digest) = digest else {
                error!(
                    ?pos,
                    err = %digest.expect_err("digest is Err in else branch"),
                    "could not convert node from metadata bytes to digest"
                );
                return Err(Error::DataCorrupted(
                    "could not read digest at requested pos",
                ));
            };
            return Ok(digest);
        }

        // If a node isn't found in the metadata, it might still be in the journal.
        debug!(?pos, "reading node from journal");
        let node = journal.reader().await.read(*pos).await;
        match node {
            Ok(node) => Ok(node),
            Err(JError::ItemPruned(_)) => {
                error!(?pos, "node is missing from metadata and journal");
                Err(Error::MissingNode(pos))
            }
            Err(e) => Err(Error::Journal(e)),
        }
    }

    /// Returns [start, end) where `start` is the oldest retained leaf and `end` is the total leaf
    /// count.
    pub fn bounds(&self) -> std::ops::Range<Location<F>> {
        let inner = self.inner.read();
        Location::try_from(inner.pruned_to_pos).expect("valid pruned_to_pos")..inner.mem.leaves()
    }

    /// Adds the pinned nodes based on `prune_pos` to `mem`.
    async fn add_extra_pinned_nodes(
        mem: &mut Mem<F, D>,
        metadata: &Metadata<E, U64, Vec<u8>>,
        journal: &Journal<E, D>,
        prune_pos: Position<F>,
    ) -> Result<(), Error<F>> {
        let size = mem.size();
        let mut pinned_nodes = BTreeMap::new();
        for pos in F::nodes_to_pin(size, prune_pos) {
            let digest = Self::get_from_metadata_or_journal(metadata, journal, pos).await?;
            pinned_nodes.insert(pos, digest);
        }
        mem.add_pinned_nodes(pinned_nodes);

        Ok(())
    }

    /// Initialize a new `Journaled` instance.
    pub async fn init(
        context: E,
        hasher: &impl Hasher<F, Digest = D>,
        cfg: Config,
    ) -> Result<Self, Error<F>> {
        let journal_cfg = JConfig {
            partition: cfg.journal_partition,
            items_per_blob: cfg.items_per_blob,
            page_cache: cfg.page_cache,
            write_buffer: cfg.write_buffer,
        };
        let journal = Journal::<E, D>::init(context.with_label("mmr_journal"), journal_cfg).await?;
        let mut journal_size = Position::<F>::new(journal.size().await);

        let metadata_cfg = MConfig {
            partition: cfg.metadata_partition,
            codec_config: ((0..).into(), ()),
        };
        let metadata =
            Metadata::<_, U64, Vec<u8>>::init(context.with_label("mmr_metadata"), metadata_cfg)
                .await?;

        if journal_size == 0 {
            let mem = Mem::init(
                MemConfig {
                    nodes: vec![],
                    pruned_to: Location::new(0),
                    pinned_nodes: vec![],
                },
                hasher,
            )?;
            return Ok(Self {
                inner: RwLock::new(Inner {
                    mem,
                    pruned_to_pos: Position::new(0),
                }),
                journal,
                metadata,
                sync_lock: AsyncMutex::new(()),
                pool: cfg.thread_pool,
            });
        }

        // Make sure the journal's oldest retained node is as expected based on the last pruning
        // boundary stored in metadata. If they don't match, prune the journal to the appropriate
        // location.
        let key: U64 = U64::new(PRUNED_TO_PREFIX, 0);
        let metadata_pruned_to = Location::<F>::new(metadata.get(&key).map_or(0, |bytes| {
            u64::from_be_bytes(
                bytes
                    .as_slice()
                    .try_into()
                    .expect("metadata pruned_to is not 8 bytes"),
            )
        }));
        let metadata_prune_pos = Position::try_from(metadata_pruned_to)?;
        let journal_bounds_start = journal.reader().await.bounds().start;
        if *metadata_prune_pos > journal_bounds_start {
            // Metadata is ahead of journal (crashed before completing journal prune).
            // Prune the journal to match metadata.
            journal.prune(*metadata_prune_pos).await?;
            if journal.reader().await.bounds().start != journal_bounds_start {
                // This should only happen in the event of some failure during the last attempt to
                // prune the journal.
                warn!(
                    journal_bounds_start,
                    ?metadata_prune_pos,
                    "journal pruned to match metadata"
                );
            }
        } else if *metadata_prune_pos < journal_bounds_start {
            // Metadata is stale (e.g., missing/corrupted while journal has valid state).
            // Use the journal's state as authoritative.
            warn!(
                ?metadata_prune_pos,
                journal_bounds_start, "metadata stale, using journal pruning boundary"
            );
        }

        // Use the more restrictive (higher) pruning boundary between metadata and journal.
        // This handles both cases: metadata ahead (crash during prune) and metadata stale.
        //
        // The journal boundary may not be leaf-aligned (it's blob-aligned), so round up to the
        // position of the first leaf after the boundary.
        let journal_boundary_pos = Position::<F>::new(journal_bounds_start);
        let journal_boundary_floor = F::to_nearest_size(journal_boundary_pos);
        let journal_boundary_leaf_aligned_pos = if journal_boundary_floor == journal_boundary_pos {
            // `to_nearest_size` rounds down, so equality means the boundary is already
            // leaf-aligned.
            journal_boundary_floor
        } else {
            // If flooring backed up over the boundary, round up to the next leaf position, which
            // is guaranteed to be above it.
            Position::try_from(Location::try_from(journal_boundary_floor)? + 1)?
        };
        let effective_prune_pos =
            std::cmp::max(metadata_prune_pos, journal_boundary_leaf_aligned_pos);

        let last_valid_size = F::to_nearest_size(journal_size);
        let mut orphaned_leaf: Option<D> = None;
        if last_valid_size != journal_size {
            warn!(
                ?last_valid_size,
                "encountered invalid structure, recovering from last valid size"
            );
            // Check if there is an intact leaf following the last valid size, from which we can
            // recover its missing parents.
            let recovered_item = journal.reader().await.read(*last_valid_size).await;
            if let Ok(item) = recovered_item {
                orphaned_leaf = Some(item);
            }
            journal.rewind(*last_valid_size).await?;
            journal.sync().await?;
            journal_size = last_valid_size
        }

        // Initialize the mem in the "prune_all" state.
        let mut pinned_nodes = Vec::new();
        for pos in F::nodes_to_pin(journal_size, journal_size) {
            let digest = Self::get_from_metadata_or_journal(&metadata, &journal, pos).await?;
            pinned_nodes.push(digest);
        }
        let mut mem = Mem::init(
            MemConfig {
                nodes: vec![],
                pruned_to: Location::try_from(journal_size)?,
                pinned_nodes,
            },
            hasher,
        )?;
        Self::add_extra_pinned_nodes(&mut mem, &metadata, &journal, effective_prune_pos).await?;

        if let Some(leaf) = orphaned_leaf {
            // Recover the orphaned leaf and any missing parents.
            let pos = mem.size();
            warn!(?pos, "recovering orphaned leaf");
            let changeset = mem
                .new_batch()
                .add_leaf_digest(leaf)
                .merkleize(hasher)
                .finalize();
            mem.apply(changeset)?;
            assert_eq!(pos, journal_size);

            // Inline sync: flush recovered nodes to journal.
            for p in journal.size().await..*mem.size() {
                let p = Position::new(p);
                let node = *mem.get_node_unchecked(p);
                journal.append(&node).await?;
            }
            journal.sync().await?;
            assert_eq!(mem.size(), journal.size().await);

            // Prune mem and reinstate pinned nodes.
            let mem_size = mem.size();
            let mut pn = BTreeMap::new();
            for p in F::nodes_to_pin(mem_size, effective_prune_pos) {
                let d = mem.get_node_unchecked(p);
                pn.insert(p, *d);
            }
            mem.prune_all();
            mem.add_pinned_nodes(pn);
        }

        Ok(Self {
            inner: RwLock::new(Inner {
                mem,
                pruned_to_pos: effective_prune_pos,
            }),
            journal,
            metadata,
            sync_lock: AsyncMutex::new(()),
            pool: cfg.thread_pool,
        })
    }

    /// Initialize a structure for synchronization, reusing existing data if possible.
    ///
    /// Handles sync scenarios based on existing journal data vs. the given sync range:
    ///
    /// 1. **Fresh Start**: existing_size <= range.start
    ///    - Deletes existing data (if any)
    ///    - Creates new [Journal] with pruning boundary and size at `range.start`
    ///
    /// 2. **Reuse**: range.start < existing_size <= range.end
    ///    - Keeps existing journal data
    ///    - Prunes the journal toward `range.start` (section-aligned)
    ///
    /// 3. **Error**: existing_size > range.end
    ///    - Returns [crate::journal::Error::ItemOutOfRange]
    pub async fn init_sync(
        context: E,
        cfg: SyncConfig<F, D>,
        hasher: &impl Hasher<F, Digest = D>,
    ) -> Result<Self, Error<F>> {
        let prune_pos = Position::try_from(cfg.range.start)?;
        let end_pos = Position::try_from(cfg.range.end)?;
        let journal_cfg = JConfig {
            partition: cfg.config.journal_partition.clone(),
            items_per_blob: cfg.config.items_per_blob,
            write_buffer: cfg.config.write_buffer,
            page_cache: cfg.config.page_cache.clone(),
        };

        // Open the journal, performing a rewind if necessary for crash recovery.
        let journal: Journal<E, D> =
            Journal::init(context.with_label("mmr_journal"), journal_cfg).await?;
        let mut journal_size = Position::<F>::new(journal.size().await);

        // If a crash left the journal at an invalid size (e.g., a leaf was written
        // but its parent nodes were not), rewind to the last valid size.
        let last_valid_size = F::to_nearest_size(journal_size);
        if last_valid_size != journal_size {
            warn!(
                ?last_valid_size,
                "init_sync: encountered invalid structure, recovering from last valid size"
            );
            journal.rewind(*last_valid_size).await?;
            journal.sync().await?;
            journal_size = last_valid_size;
        }

        // Handle existing data vs sync range.
        assert!(!cfg.range.is_empty(), "range must not be empty");
        if journal_size > *end_pos {
            return Err(crate::journal::Error::ItemOutOfRange(*journal_size).into());
        }
        if journal_size <= *prune_pos && *prune_pos != 0 {
            journal.clear_to_size(*prune_pos).await?;
            journal_size = Position::new(journal.size().await);
        }

        // Open the metadata.
        let metadata_cfg = MConfig {
            partition: cfg.config.metadata_partition,
            codec_config: ((0..).into(), ()),
        };
        let mut metadata = Metadata::init(context.with_label("mmr_metadata"), metadata_cfg).await?;

        // Write the pruning boundary.
        let pruning_boundary_key = U64::new(PRUNED_TO_PREFIX, 0);
        metadata.put(
            pruning_boundary_key,
            cfg.range.start.as_u64().to_be_bytes().into(),
        );

        // Write the required pinned nodes to metadata.
        if let Some(pinned_nodes) = cfg.pinned_nodes {
            // Use caller-provided pinned nodes.
            let nodes_to_pin_persisted = F::nodes_to_pin(journal_size, prune_pos);
            if pinned_nodes.len() != nodes_to_pin_persisted.len() {
                return Err(Error::<F>::InvalidPinnedNodes);
            }
            for (pos, digest) in nodes_to_pin_persisted.into_iter().zip(pinned_nodes.iter()) {
                metadata.put(U64::new(NODE_PREFIX, *pos), digest.to_vec());
            }
        }

        // Create the in-memory structure with the pinned nodes required for its size. This must be
        // performed *before* pruning the journal to range.start to ensure all pinned nodes are
        // present.
        let nodes_to_pin_mem = F::nodes_to_pin(journal_size, journal_size);
        let mut mem_pinned_nodes = Vec::new();
        for pos in nodes_to_pin_mem {
            let digest = Self::get_from_metadata_or_journal(&metadata, &journal, pos).await?;
            mem_pinned_nodes.push(digest);
        }
        let mut mem = Mem::init(
            MemConfig {
                nodes: vec![],
                pruned_to: Location::try_from(journal_size)?,
                pinned_nodes: mem_pinned_nodes,
            },
            hasher,
        )?;

        // Add the additional pinned nodes required for the pruning boundary, if applicable.
        // This must also be done before pruning.
        if prune_pos < journal_size {
            Self::add_extra_pinned_nodes(&mut mem, &metadata, &journal, prune_pos).await?;
        }

        // Sync metadata before pruning so pinned nodes are persisted for crash recovery.
        metadata.sync().await?;

        // Prune the journal to range.start.
        journal.prune(*prune_pos).await?;

        Ok(Self {
            inner: RwLock::new(Inner {
                mem,
                pruned_to_pos: prune_pos,
            }),
            journal,
            metadata,
            sync_lock: AsyncMutex::new(()),
            pool: cfg.config.thread_pool,
        })
    }

    /// Compute and add required nodes for the given pruning point to the metadata, and write it to
    /// disk. Return the computed set of required nodes.
    async fn update_metadata(
        &mut self,
        prune_to_pos: Position<F>,
    ) -> Result<BTreeMap<Position<F>, D>, Error<F>> {
        assert!(prune_to_pos >= self.inner.get_mut().pruned_to_pos);

        let size = self.inner.get_mut().mem.size();
        let mut pinned_nodes = BTreeMap::new();
        for pos in F::nodes_to_pin(size, prune_to_pos) {
            let digest = self.get_node(pos).await?.expect(
                "pinned node should exist if prune_to_pos is no less than self.pruned_to_pos",
            );
            self.metadata
                .put(U64::new(NODE_PREFIX, *pos), digest.to_vec());
            pinned_nodes.insert(pos, digest);
        }

        let key: U64 = U64::new(PRUNED_TO_PREFIX, 0);
        self.metadata.put(
            key,
            Location::try_from(prune_to_pos)?
                .as_u64()
                .to_be_bytes()
                .into(),
        );

        self.metadata.sync().await.map_err(Error::Metadata)?;

        Ok(pinned_nodes)
    }

    pub async fn get_node(&self, position: Position<F>) -> Result<Option<D>, Error<F>> {
        {
            let inner = self.inner.read();
            if let Some(node) = inner.mem.get_node(position) {
                return Ok(Some(node));
            }
        }

        match self.journal.reader().await.read(*position).await {
            Ok(item) => Ok(Some(item)),
            Err(JError::ItemPruned(_)) => Ok(None),
            Err(e) => Err(Error::Journal(e)),
        }
    }

    /// Sync the structure to disk.
    pub async fn sync(&self) -> Result<(), Error<F>> {
        let _sync_guard = self.sync_lock.lock().await;

        let journal_size = Position::<F>::new(self.journal.size().await);

        // Snapshot nodes in the mem that are missing from the journal, along with the pinned
        // node set for the current pruning boundary.
        let (sync_target_leaves, missing_nodes, pinned_nodes) = {
            let inner = self.inner.read();
            let size = inner.mem.size();
            let sync_target_leaves = inner.mem.leaves();

            assert!(
                journal_size <= size,
                "journal size should never exceed in-memory structure size"
            );
            if journal_size == size {
                return Ok(());
            }

            let mut missing_nodes = Vec::with_capacity((*size - *journal_size) as usize);
            for pos in *journal_size..*size {
                let node = *inner.mem.get_node_unchecked(Position::new(pos));
                missing_nodes.push(node);
            }

            // Recompute pinned nodes since we'll need to repopulate the cache after it is cleared
            // by pruning the mem.
            let mem_size = inner.mem.size();
            let mut pinned_nodes = BTreeMap::new();
            for pos in F::nodes_to_pin(mem_size, inner.pruned_to_pos) {
                let digest = inner.mem.get_node_unchecked(pos);
                pinned_nodes.insert(pos, *digest);
            }

            (sync_target_leaves, missing_nodes, pinned_nodes)
        };

        // Append missing nodes to the journal without holding the mem read lock.
        for node in missing_nodes {
            self.journal.append(&node).await?;
        }

        // Sync the journal while still holding the sync_lock to ensure durability before returning.
        self.journal.sync().await?;

        // Now that the missing nodes are in the journal, it's safe to prune them from the
        // mem. We prune to the previously captured leaf count to avoid a race with concurrent
        // appends between the read lock above and this write lock.
        {
            let mut inner = self.inner.write();
            inner
                .mem
                .prune(sync_target_leaves)
                .expect("captured leaves is in bounds");
            inner.mem.add_pinned_nodes(pinned_nodes);
        }

        Ok(())
    }

    /// Prune all nodes up to but not including the given leaf location and update the pinned nodes.
    ///
    /// This implementation ensures that no failure can leave the structure in an unrecoverable
    /// state, requiring it sync the structure to write any potential unsynced updates.
    ///
    /// Returns [Error::LocationOverflow] if `loc` exceeds [Family::MAX_LEAVES].
    /// Returns [Error::LeafOutOfBounds] if `loc` exceeds the current leaf count.
    pub async fn prune(&mut self, loc: Location<F>) -> Result<(), Error<F>> {
        let pos = Position::try_from(loc)?;
        {
            let inner = self.inner.get_mut();
            if loc > inner.mem.leaves() {
                return Err(Error::LeafOutOfBounds(loc));
            }
            if pos <= inner.pruned_to_pos {
                return Ok(());
            }
        }

        // Flush items cached in the mem to disk to ensure the current state is recoverable.
        self.sync().await?;

        // Update metadata to reflect the desired pruning boundary, allowing for recovery in the
        // event of a pruning failure.
        let pinned_nodes = self.update_metadata(pos).await?;

        self.journal.prune(*pos).await?;
        let inner = self.inner.get_mut();
        inner.mem.add_pinned_nodes(pinned_nodes);
        inner.pruned_to_pos = pos;

        Ok(())
    }

    /// Return the root of the structure.
    pub fn root(&self) -> D {
        *self.inner.read().mem.root()
    }

    /// Prune as many nodes as possible, leaving behind at most items_per_blob nodes in the current
    /// blob.
    pub async fn prune_all(&mut self) -> Result<(), Error<F>> {
        let leaves = self.inner.get_mut().mem.leaves();
        if leaves != 0 {
            self.prune(leaves).await?;
        }
        Ok(())
    }

    /// Close and permanently remove any disk resources.
    pub async fn destroy(self) -> Result<(), Error<F>> {
        self.journal.destroy().await?;
        self.metadata.destroy().await?;

        Ok(())
    }

    #[cfg(any(test, feature = "fuzzing"))]
    /// Sync elements to disk until `write_limit` elements have been written, then abort to simulate
    /// a partial write for testing failure scenarios.
    pub async fn simulate_partial_sync(&mut self, write_limit: usize) -> Result<(), Error<F>> {
        if write_limit == 0 {
            return Ok(());
        }

        let inner = self.inner.get_mut();
        let journal_size = Position::<F>::new(self.journal.size().await);

        // Write the nodes cached in the memory-resident structure to the journal, aborting after
        // write_count nodes have been written.
        let mut written_count = 0usize;
        for i in *journal_size..*inner.mem.size() {
            let node = *inner.mem.get_node_unchecked(Position::new(i));
            self.journal.append(&node).await?;
            written_count += 1;
            if written_count >= write_limit {
                break;
            }
        }
        self.journal.sync().await?;

        Ok(())
    }

    #[cfg(test)]
    pub fn get_pinned_nodes(&self) -> BTreeMap<Position<F>, D> {
        self.inner.read().mem.pinned_nodes()
    }

    #[cfg(test)]
    pub async fn simulate_pruning_failure(mut self, prune_to: Location<F>) -> Result<(), Error<F>> {
        let prune_to_pos = Position::try_from(prune_to)?;
        assert!(prune_to_pos <= self.inner.get_mut().mem.size());

        // Flush items cached in the mem to disk to ensure the current state is recoverable.
        self.sync().await?;

        // Update metadata to reflect the desired pruning boundary, allowing for recovery in the
        // event of a pruning failure.
        self.update_metadata(prune_to_pos).await?;

        // Don't actually prune the journal to simulate failure
        Ok(())
    }

    /// Apply a changeset to the structure.
    ///
    /// A changeset is only valid if the structure has not been modified since the
    /// batch that produced it was created. Multiple batches can be forked from
    /// the same parent for speculative execution, but only one may be applied.
    /// Applying a stale changeset returns [`Error::StaleChangeset`].
    pub fn apply(&mut self, changeset: batch::Changeset<F, D>) -> Result<(), Error<F>> {
        self.inner.get_mut().mem.apply(changeset)?;
        Ok(())
    }

    /// Create a new speculative batch with this structure as its parent.
    pub fn new_batch(&self) -> UnmerkleizedBatch<'_, F, D, Self> {
        UnmerkleizedBatch::new(self).with_pool(self.pool())
    }

    /// Return the thread pool, if any.
    pub fn pool(&self) -> Option<ThreadPool> {
        self.pool.clone()
    }

    /// Rewind the structure by the given number of leaves.
    ///
    /// Adds go through the batch API ([`Self::new_batch`] / [`Self::apply`]), but removing
    /// leaves requires `rewind`. After `init` or `sync`, the in-memory structure is pruned to
    /// O(log n) pinned peaks. A batch pop would expose new peaks that are not in memory, and
    /// `merkleize` cannot load them because [`Readable::get_node`] is synchronous. `rewind`
    /// performs async journal I/O to rebuild state at the target position.
    pub(crate) async fn rewind(
        &mut self,
        leaves_to_remove: usize,
        hasher: &impl Hasher<F, Digest = D>,
    ) -> Result<(), Error<F>> {
        if leaves_to_remove == 0 {
            return Ok(());
        }

        let current_leaves = *self.leaves();
        let destination_leaf = match current_leaves.checked_sub(leaves_to_remove as u64) {
            Some(dest) => dest,
            None => {
                let pruned_to_pos = self.inner.get_mut().pruned_to_pos;
                return Err(if pruned_to_pos == 0 {
                    Error::Empty
                } else {
                    Error::ElementPruned(pruned_to_pos - 1)
                });
            }
        };

        let destination_loc = Location::new(destination_leaf);
        let new_size = Position::try_from(destination_loc).expect("valid leaf");

        let pruned_to_pos = self.inner.get_mut().pruned_to_pos;
        if new_size < pruned_to_pos {
            return Err(Error::ElementPruned(new_size));
        }

        // Rewind the journal if needed.
        let journal_size = Position::<F>::new(self.journal.size().await);
        if new_size < journal_size {
            self.journal.rewind(*new_size).await?;
            self.journal.sync().await?;
        }

        // Truncate the in-memory structure to the target size and recompute the root.
        // If the in-memory structure has been pruned past the target (e.g. after sync),
        // rebuild from the journal/metadata instead.
        let inner = self.inner.get_mut();
        if new_size >= Position::try_from(inner.mem.bounds().start).expect("valid mem bounds start")
        {
            inner.mem.truncate(new_size, hasher);
        } else {
            let mut pinned_nodes = Vec::new();
            for pos in F::nodes_to_pin(new_size, new_size) {
                pinned_nodes.push(
                    Self::get_from_metadata_or_journal(&self.metadata, &self.journal, pos).await?,
                );
            }
            inner.mem = Mem::from_components(hasher, vec![], destination_loc, pinned_nodes)?;
            Self::add_extra_pinned_nodes(
                &mut inner.mem,
                &self.metadata,
                &self.journal,
                inner.pruned_to_pos,
            )
            .await?;
        }

        Ok(())
    }
}

/// The [`Readable`] implementation for the journaled structure operates only on the in-memory
/// portion. After [`Journaled::sync`], nodes that have been flushed to the journal are no longer
/// accessible through this interface. In particular, [`Readable::get_node`] returns `None` for
/// flushed positions, and [`Readable::pruned_to_pos`] reflects the in-memory boundary (which may
/// be tighter than the journal's prune boundary reported by [`Journaled::bounds`]). This means
/// batch operations like `update_leaf` will correctly reject leaves that have been synced out of
/// memory with [`Error::ElementPruned`].
impl<F: Family, E: RStorage + Clock + Metrics, D: Digest> Readable for Journaled<F, E, D> {
    type Family = F;
    type Digest = D;
    type Error = Error<F>;

    fn size(&self) -> Position<F> {
        self.size()
    }

    fn get_node(&self, pos: Position<F>) -> Option<D> {
        self.inner.read().mem.get_node(pos)
    }

    fn root(&self) -> D {
        *self.inner.read().mem.root()
    }

    fn pruned_to_pos(&self) -> Position<F> {
        self.inner.read().mem.pruned_to_pos()
    }

    fn proof(
        &self,
        hasher: &impl Hasher<F, Digest = D>,
        loc: Location<F>,
    ) -> Result<Proof<F, D>, Error<F>> {
        if !loc.is_valid_index() {
            return Err(Error::LocationOverflow(loc));
        }
        crate::merkle::proof::build_range_proof(
            hasher,
            self.leaves(),
            loc..loc + 1,
            |pos| <Self as Readable>::get_node(self, pos),
            Error::ElementPruned,
        )
        .map_err(|e| match e {
            Error::RangeOutOfBounds(_) => Error::LeafOutOfBounds(loc),
            _ => e,
        })
    }

    fn range_proof(
        &self,
        hasher: &impl Hasher<F, Digest = D>,
        range: core::ops::Range<Location<F>>,
    ) -> Result<Proof<F, D>, Error<F>> {
        crate::merkle::proof::build_range_proof(
            hasher,
            self.leaves(),
            range,
            |pos| <Self as Readable>::get_node(self, pos),
            Error::ElementPruned,
        )
    }
}

impl<F: Family, E: RStorage + Clock + Metrics + Sync, D: Digest> crate::merkle::storage::Storage<F>
    for Journaled<F, E, D>
{
    type Digest = D;

    async fn size(&self) -> Position<F> {
        self.size()
    }

    async fn get_node(&self, position: Position<F>) -> Result<Option<D>, Error<F>> {
        Self::get_node(self, position).await
    }
}

impl<F: Family, E: RStorage + Clock + Metrics, D: Digest> Journaled<F, E, D> {
    /// Return an inclusion proof for the element at the location `loc` against a historical
    /// state with `leaves` leaves.
    ///
    /// # Errors
    ///
    /// - Returns [Error::RangeOutOfBounds] if `leaves` is greater than `self.leaves()` or if `loc`
    ///   is not provable at that historical size.
    /// - Returns [Error::LocationOverflow] if `loc` exceeds [Family::MAX_LEAVES].
    /// - Returns [Error::ElementPruned] if some element needed to generate the proof has been
    ///   pruned.
    pub async fn historical_proof(
        &self,
        hasher: &impl Hasher<F, Digest = D>,
        leaves: Location<F>,
        loc: Location<F>,
    ) -> Result<Proof<F, D>, Error<F>> {
        if !loc.is_valid_index() {
            return Err(Error::LocationOverflow(loc));
        }
        // loc is valid so it won't overflow from + 1
        self.historical_range_proof(hasher, leaves, loc..loc + 1)
            .await
    }

    /// Return an inclusion proof for the elements in `range` against a historical state with
    /// `leaves` leaves.
    ///
    /// # Errors
    ///
    /// - Returns [Error::RangeOutOfBounds] if `leaves` is greater than `self.leaves()` or if
    ///   `range` is not provable at that historical size.
    /// - Returns [Error::LocationOverflow] if any location in `range` exceeds [Family::MAX_LEAVES].
    /// - Returns [Error::ElementPruned] if some element needed to generate the proof has been
    ///   pruned.
    /// - Returns [Error::Empty] if the range is empty.
    pub async fn historical_range_proof(
        &self,
        hasher: &impl Hasher<F, Digest = D>,
        leaves: Location<F>,
        range: core::ops::Range<Location<F>>,
    ) -> Result<Proof<F, D>, Error<F>> {
        if leaves > self.leaves() {
            return Err(Error::RangeOutOfBounds(leaves));
        }
        crate::merkle::verification::historical_range_proof(hasher, self, leaves, range).await
    }

    /// Return an inclusion proof for the element at the location `loc` that can be verified against
    /// the current root.
    ///
    /// This async inherent method shadows [`Readable::proof`] and can read from the backing
    /// journal for nodes that have been synced out of memory.
    ///
    /// # Errors
    ///
    /// - Returns [Error::LocationOverflow] if `loc` exceeds [Family::MAX_LEAVES].
    /// - Returns [Error::ElementPruned] if some element needed to generate the proof has been
    ///   pruned.
    /// - Returns [Error::Empty] if the range is empty.
    pub async fn proof(
        &self,
        hasher: &impl Hasher<F, Digest = D>,
        loc: Location<F>,
    ) -> Result<Proof<F, D>, Error<F>> {
        if !loc.is_valid_index() {
            return Err(Error::LocationOverflow(loc));
        }
        // loc is valid so it won't overflow from + 1
        self.range_proof(hasher, loc..loc + 1).await
    }

    /// Return an inclusion proof for the elements within the specified location range.
    ///
    /// This async inherent method shadows [`Readable::range_proof`] and can read from the backing
    /// journal for nodes that have been synced out of memory.
    ///
    /// # Errors
    ///
    /// - Returns [Error::LocationOverflow] if any location in `range` exceeds [Family::MAX_LEAVES].
    /// - Returns [Error::ElementPruned] if some element needed to generate the proof has been
    ///   pruned.
    /// - Returns [Error::Empty] if the range is empty.
    pub async fn range_proof(
        &self,
        hasher: &impl Hasher<F, Digest = D>,
        range: core::ops::Range<Location<F>>,
    ) -> Result<Proof<F, D>, Error<F>> {
        self.historical_range_proof(hasher, self.leaves(), range)
            .await
    }
}

impl<F: Family, E: RStorage + Clock + Metrics, D: Digest> ChainInfo<F> for Journaled<F, E, D> {
    type Digest = D;

    fn base_size(&self) -> Position<F> {
        self.size()
    }

    fn collect_overwrites(&self, _into: &mut BTreeMap<Position<F>, D>) {}
}
