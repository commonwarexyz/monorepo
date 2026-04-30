//! A Merkle structure backed by a fixed-item-length journal.
//!
//! A [crate::journal] is used to store all unpruned nodes, and a [crate::metadata] store is
//! used to preserve digests required for root and proof generation that would have otherwise been
//! pruned.
//!
//! This module is generic over [`Family`], so it works for both MMR and MMB.

use crate::{
    journal::{
        contiguous::{
            fixed::{Config as JConfig, Journal},
            Many, Reader,
        },
        Error as JError,
    },
    merkle::{
        batch,
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
    range::NonEmptyRange,
    sequence::prefixed_u64::U64,
    sync::{AsyncMutex, RwLock},
};
use std::{
    collections::BTreeMap,
    num::{NonZeroU64, NonZeroUsize},
    sync::Arc,
};
use tracing::{debug, error, warn};

/// Append-only wrapper around [`batch::UnmerkleizedBatch`].
///
/// The full Merkle structure's [`Merkle::sync`] only persists *appended* nodes
/// (positions in `[journal_size, state.size())`). Overwrites to existing positions are stored in
/// the in-memory layer but never flushed, so they would be silently lost on crash recovery. This
/// wrapper prevents that by exposing only append and merkleize operations, hiding `update_leaf*`
/// at compile time.
pub struct UnmerkleizedBatch<F: Family, D: Digest> {
    inner: batch::UnmerkleizedBatch<F, D>,
}

impl<F: Family, D: Digest> UnmerkleizedBatch<F, D> {
    /// Hash `element` and add it as a leaf.
    pub fn add(self, hasher: &impl Hasher<F, Digest = D>, element: &[u8]) -> Self {
        Self {
            inner: self.inner.add(hasher, element),
        }
    }

    /// Add a pre-computed leaf digest.
    pub fn add_leaf_digest(self, digest: D) -> Self {
        Self {
            inner: self.inner.add_leaf_digest(digest),
        }
    }

    /// The number of leaves visible through this batch.
    pub fn leaves(&self) -> Location<F> {
        self.inner.leaves()
    }

    /// Set a thread pool for parallel merkleization.
    #[cfg(feature = "std")]
    pub fn with_pool(self, pool: Option<ThreadPool>) -> Self {
        Self {
            inner: self.inner.with_pool(pool),
        }
    }

    /// Consume this batch and produce an immutable [`batch::MerkleizedBatch`] with computed nodes.
    /// `base` provides committed node data as fallback during hash computation.
    pub fn merkleize(
        self,
        base: &Mem<F, D>,
        hasher: &impl Hasher<F, Digest = D>,
    ) -> Arc<batch::MerkleizedBatch<F, D>> {
        self.inner.merkleize(base, hasher)
    }
}

/// Fields of [Merkle] that are protected by an [RwLock] for interior mutability.
pub(crate) struct Inner<F: Family, D: Digest> {
    /// A memory resident Merkle structure used to build the structure and cache updates. It caches
    /// all un-synced nodes, and the pinned node set as derived from both its own pruning boundary
    /// and the full structure's pruning boundary.
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

/// Configuration for initializing a full Merkle structure for synchronization.
///
/// Determines how to handle existing persistent data based on sync boundaries:
/// - **Fresh Start**: Existing data < range start -> discard and start fresh
/// - **Prune and Reuse**: range contains existing data -> prune and reuse
/// - **Error**: existing data > range end
pub struct SyncConfig<F: Family, D: Digest> {
    /// Base configuration (journal, metadata, etc.)
    pub config: Config,

    /// Sync range expressed as leaf-aligned bounds.
    pub range: NonEmptyRange<Location<F>>,

    /// The pinned nodes the structure needs at the pruning boundary (range start), in the order
    /// specified by `Family::nodes_to_pin`. If `None`, the pinned nodes are expected to already be
    /// in the structure's metadata/journal.
    pub pinned_nodes: Option<Vec<D>>,
}

/// A Merkle structure backed by a fixed-item-length journal.
pub struct Merkle<F: Family, E: RStorage + Clock + Metrics, D: Digest> {
    /// Lock-protected mutable state.
    pub(crate) inner: RwLock<Inner<F, D>>,

    /// Stores all unpruned nodes.
    pub(crate) journal: Journal<E, D>,

    /// Stores the pinned nodes for the current pruning boundary, and the corresponding pruning
    /// boundary used to generate them. The metadata remains empty until pruning is invoked, and its
    /// contents change only when the pruning boundary moves.
    pub(crate) metadata: Metadata<E, U64, Vec<u8>>,

    /// Serializes concurrent sync calls.
    pub(crate) sync_lock: AsyncMutex<()>,

    /// The thread pool to use for parallelization.
    pub(crate) pool: Option<ThreadPool>,
}

/// Prefix used for nodes in the metadata prefixed U8 key.
const NODE_PREFIX: u8 = 0;

/// Prefix used for the key storing the pruning boundary (as a leaf index) in the metadata.
pub(crate) const PRUNED_TO_PREFIX: u8 = 1;

impl<F: Family, E: RStorage + Clock + Metrics, D: Digest> Merkle<F, E, D> {
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
        let prune_loc = Location::try_from(prune_pos).expect("valid prune_pos");
        let mut pinned_nodes = BTreeMap::new();
        for pos in F::nodes_to_pin(prune_loc) {
            let digest = Self::get_from_metadata_or_journal(metadata, journal, pos).await?;
            pinned_nodes.insert(pos, digest);
        }
        mem.add_pinned_nodes(pinned_nodes);

        Ok(())
    }

    /// Read-only peek at the persisted structure's root and boundaries.
    ///
    /// The root spec must match the spec used by the caller for the persisted structure.
    ///
    /// Returns `Ok(None)` when:
    /// - Journal size is structurally invalid and would require a rewind (i.e.
    ///   a crash left the structure in an unrecoverable state for a read-only
    ///   probe).
    pub async fn peek_root(
        context: E,
        cfg: Config,
        hasher: &impl Hasher<F, Digest = D>,
        inactive_peaks: usize,
    ) -> Result<Option<(Location<F>, Location<F>, D)>, Error<F>> {
        let journal_cfg = JConfig {
            partition: cfg.journal_partition,
            items_per_blob: cfg.items_per_blob,
            write_buffer: cfg.write_buffer,
            page_cache: cfg.page_cache,
        };
        let journal: Journal<E, D> =
            Journal::init(context.with_label("merkle_journal_peek"), journal_cfg).await?;
        let journal_size = Position::<F>::new(journal.size().await);

        if journal_size == 0 {
            let mem = Mem::init(MemConfig {
                nodes: vec![],
                pruning_boundary: Location::new(0),
                pinned_nodes: vec![],
            })?;
            let empty_root = mem.root(hasher, inactive_peaks)?;
            return Ok(Some((Location::new(0), Location::new(0), empty_root)));
        }

        // Bail if the journal would require a rewind to reach a valid size.
        // Probe is read-only; the caller will handle recovery via `init`.
        let last_valid_size = F::to_nearest_size(journal_size);
        if last_valid_size != journal_size {
            return Ok(None);
        }

        let metadata_cfg = MConfig {
            partition: cfg.metadata_partition,
            codec_config: ((0..).into(), ()),
        };
        let metadata = Metadata::<_, U64, Vec<u8>>::init(
            context.with_label("merkle_metadata_peek"),
            metadata_cfg,
        )
        .await?;

        let prune_loc = metadata
            .get(&U64::new(PRUNED_TO_PREFIX, 0))
            .map(|bytes| -> Result<Location<F>, Error<F>> {
                let raw: [u8; 8] = bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| Error::DataCorrupted("metadata pruned_to is not 8 bytes"))?;
                Ok(Location::<F>::new(u64::from_be_bytes(raw)))
            })
            .transpose()?
            .unwrap_or_else(|| Location::<F>::new(0));
        let prune_pos = Position::try_from(prune_loc)?;

        let journal_leaves = Location::try_from(journal_size)?;
        let nodes_to_pin_mem = F::nodes_to_pin(journal_leaves);
        let mut mem_pinned_nodes = Vec::new();
        for pos in nodes_to_pin_mem {
            let digest = Self::get_from_metadata_or_journal(&metadata, &journal, pos).await?;
            mem_pinned_nodes.push(digest);
        }
        let mut mem = Mem::init(MemConfig {
            nodes: vec![],
            pruning_boundary: journal_leaves,
            pinned_nodes: mem_pinned_nodes,
        })?;

        if prune_pos < journal_size {
            Self::add_extra_pinned_nodes(&mut mem, &metadata, &journal, prune_pos).await?;
        }

        let root = mem.root(hasher, inactive_peaks)?;
        Ok(Some((prune_loc, journal_leaves, root)))
    }

    /// Initialize a new `Merkle` instance.
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
        let journal =
            Journal::<E, D>::init(context.with_label("merkle_journal"), journal_cfg).await?;
        let mut journal_size = Position::<F>::new(journal.size().await);

        let metadata_cfg = MConfig {
            partition: cfg.metadata_partition,
            codec_config: ((0..).into(), ()),
        };
        let metadata =
            Metadata::<_, U64, Vec<u8>>::init(context.with_label("merkle_metadata"), metadata_cfg)
                .await?;

        if journal_size == 0 {
            let mem = Mem::init(MemConfig {
                nodes: vec![],
                pruning_boundary: Location::new(0),
                pinned_nodes: vec![],
            })?;
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
        let journal_leaves = Location::try_from(journal_size)?;
        let mut pinned_nodes = Vec::new();
        for pos in F::nodes_to_pin(journal_leaves) {
            let digest = Self::get_from_metadata_or_journal(&metadata, &journal, pos).await?;
            pinned_nodes.push(digest);
        }
        let mut mem = Mem::init(MemConfig {
            nodes: vec![],
            pruning_boundary: journal_leaves,
            pinned_nodes,
        })?;
        Self::add_extra_pinned_nodes(&mut mem, &metadata, &journal, effective_prune_pos).await?;

        if let Some(leaf) = orphaned_leaf {
            // Recover the orphaned leaf and any missing parents.
            let pos = mem.size();
            warn!(?pos, "recovering orphaned leaf");
            let batch = mem
                .new_batch()
                .add_leaf_digest(leaf)
                .merkleize(&mem, hasher);
            mem.apply_batch(&batch)?;
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
            let effective_prune_loc =
                Location::try_from(effective_prune_pos).expect("valid effective_prune_pos");
            let mut pn = BTreeMap::new();
            for p in F::nodes_to_pin(effective_prune_loc) {
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
    pub async fn init_sync(context: E, cfg: SyncConfig<F, D>) -> Result<Self, Error<F>> {
        let prune_pos = Position::try_from(cfg.range.start())?;
        let end_pos = Position::try_from(cfg.range.end())?;
        let journal_cfg = JConfig {
            partition: cfg.config.journal_partition.clone(),
            items_per_blob: cfg.config.items_per_blob,
            write_buffer: cfg.config.write_buffer,
            page_cache: cfg.config.page_cache.clone(),
        };

        // Open the journal, performing a rewind if necessary for crash recovery.
        let journal: Journal<E, D> =
            Journal::init(context.with_label("merkle_journal"), journal_cfg).await?;
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
        let mut metadata =
            Metadata::init(context.with_label("merkle_metadata"), metadata_cfg).await?;

        // Write the pruning boundary.
        let pruning_boundary_key = U64::new(PRUNED_TO_PREFIX, 0);
        metadata.put(
            pruning_boundary_key,
            cfg.range.start().as_u64().to_be_bytes().into(),
        );

        // Write the required pinned nodes to metadata.
        // The set of pinned nodes depends only on the prune boundary, not on the total
        // structure size, so we validate against `nodes_to_pin(prune_loc)` alone.
        let prune_loc = Location::try_from(prune_pos)?;
        let journal_leaves = Location::try_from(journal_size)?;
        if let Some(pinned_nodes) = cfg.pinned_nodes {
            // Use caller-provided pinned nodes.
            let nodes_to_pin_persisted: Vec<_> = F::nodes_to_pin(prune_loc).collect();
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
        let nodes_to_pin_mem = F::nodes_to_pin(journal_leaves);
        let mut mem_pinned_nodes = Vec::new();
        for pos in nodes_to_pin_mem {
            let digest = Self::get_from_metadata_or_journal(&metadata, &journal, pos).await?;
            mem_pinned_nodes.push(digest);
        }
        let mut mem = Mem::init(MemConfig {
            nodes: vec![],
            pruning_boundary: Location::try_from(journal_size)?,
            pinned_nodes: mem_pinned_nodes,
        })?;

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

        let prune_loc = Location::try_from(prune_to_pos).expect("valid prune_to_pos");
        let mut pinned_nodes = BTreeMap::new();
        for pos in F::nodes_to_pin(prune_loc) {
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
            let prune_loc = Location::try_from(inner.pruned_to_pos).expect("valid pruned_to_pos");
            let mut pinned_nodes = BTreeMap::new();
            for pos in F::nodes_to_pin(prune_loc) {
                let digest = inner.mem.get_node_unchecked(pos);
                pinned_nodes.insert(pos, *digest);
            }

            (sync_target_leaves, missing_nodes, pinned_nodes)
        };

        // Append missing nodes to the journal without holding the mem read lock.
        self.journal.append_many(Many::Flat(&missing_nodes)).await?;

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

    /// Compute the root of the structure using `inactive_peaks` and the bagging carried by `hasher`.
    pub fn root(
        &self,
        hasher: &impl Hasher<F, Digest = D>,
        inactive_peaks: usize,
    ) -> Result<D, Error<F>> {
        self.inner.read().mem.root(hasher, inactive_peaks)
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
    /// Return a copy of the currently pinned nodes for recovery tests.
    pub fn get_pinned_nodes(&self) -> BTreeMap<Position<F>, D> {
        self.inner.read().mem.pinned_nodes()
    }

    #[cfg(test)]
    /// Simulate a crash after pruning metadata is written but before the journal is pruned.
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

    /// Apply a merkleized batch to the structure.
    ///
    /// A batch is valid if the structure has not been modified since the batch
    /// chain was created, or if only ancestors of this batch have been applied.
    /// Already-committed ancestors are skipped automatically.
    /// Applying a batch from a different fork returns [`Error::StaleBatch`].
    pub fn apply_batch(&mut self, batch: &batch::MerkleizedBatch<F, D>) -> Result<(), Error<F>> {
        self.inner.get_mut().mem.apply_batch(batch)?;
        Ok(())
    }

    /// Create an owned [`batch::MerkleizedBatch`] representing the current committed state.
    ///
    /// The batch has no data (the committed items are on disk, not in memory).
    /// This is the starting point for building owned batch chains.
    pub(crate) fn to_batch(&self) -> Arc<batch::MerkleizedBatch<F, D>> {
        let inner = self.inner.read();
        let mut batch = batch::MerkleizedBatch::from_mem(&inner.mem);
        #[cfg(feature = "std")]
        if let Some(pool) = &self.pool {
            Arc::get_mut(&mut batch).expect("just created").pool = Some(pool.clone());
        }
        batch
    }

    /// Borrow the committed Mem through the read lock. Holds the lock for
    /// the duration of the closure.
    pub fn with_mem<R>(&self, f: impl FnOnce(&Mem<F, D>) -> R) -> R {
        let inner = self.inner.read();
        f(&inner.mem)
    }

    /// Create a new speculative batch with this structure as its parent.
    pub fn new_batch(&self) -> UnmerkleizedBatch<F, D> {
        let inner = self.inner.read();
        let root = batch::MerkleizedBatch::from_mem(&inner.mem);
        drop(inner);
        UnmerkleizedBatch {
            inner: root.new_batch(),
        }
        .with_pool(self.pool())
    }

    /// Return the thread pool, if any.
    pub fn pool(&self) -> Option<ThreadPool> {
        self.pool.clone()
    }

    /// Rewind the structure by the given number of leaves.
    ///
    /// Adds go through the batch API ([`Self::new_batch`] / [`Self::apply_batch`]), but removing
    /// leaves requires `rewind`. After `init` or `sync`, the in-memory structure is pruned to O(log
    /// n) pinned nodes. A batch pop would expose new peaks that are not in memory, and `merkleize`
    /// cannot load them because [`Readable::get_node`] is synchronous. `rewind` performs async
    /// journal I/O to rebuild state at the target position.
    pub(crate) async fn rewind(&mut self, leaves_to_remove: usize) -> Result<(), Error<F>> {
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

        // Truncate the in-memory structure to the target size.
        // If the in-memory structure has been pruned past the target (e.g. after sync),
        // rebuild from the journal/metadata instead.
        let inner = self.inner.get_mut();
        if new_size >= Position::try_from(inner.mem.bounds().start).expect("valid mem bounds start")
        {
            inner.mem.truncate(new_size);
        } else {
            let mut pinned_nodes = Vec::new();
            for pos in F::nodes_to_pin(destination_loc) {
                pinned_nodes.push(
                    Self::get_from_metadata_or_journal(&self.metadata, &self.journal, pos).await?,
                );
            }
            inner.mem = Mem::init(MemConfig {
                nodes: vec![],
                pruning_boundary: destination_loc,
                pinned_nodes,
            })?;
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

/// The [`Readable`] implementation for the full structure operates only on the in-memory
/// portion. After [`Merkle::sync`], nodes that have been flushed to the journal are no longer
/// accessible through this interface. In particular, [`Readable::get_node`] returns `None` for
/// flushed positions, and [`Readable::pruning_boundary`] reflects the in-memory boundary (which may
/// be tighter than the journal's prune boundary reported by [`Merkle::bounds`]). This means
/// batch operations like `update_leaf` will correctly reject leaves that have been synced out of
/// memory with [`Error::ElementPruned`].
impl<F: Family, E: RStorage + Clock + Metrics, D: Digest> Readable for Merkle<F, E, D> {
    type Family = F;
    type Digest = D;
    type Error = Error<F>;

    fn size(&self) -> Position<F> {
        self.size()
    }

    fn get_node(&self, pos: Position<F>) -> Option<D> {
        self.inner.read().mem.get_node(pos)
    }

    fn pruning_boundary(&self) -> Location<F> {
        self.inner.read().mem.pruning_boundary()
    }
}

impl<F: Family, E: RStorage + Clock + Metrics + Sync, D: Digest> crate::merkle::storage::Storage<F>
    for Merkle<F, E, D>
{
    type Digest = D;

    async fn size(&self) -> Position<F> {
        self.size()
    }

    async fn get_node(&self, position: Position<F>) -> Result<Option<D>, Error<F>> {
        Self::get_node(self, position).await
    }
}

impl<F: Family, E: RStorage + Clock + Metrics, D: Digest> Merkle<F, E, D> {
    /// Return an inclusion proof for the element at the location `loc` against a historical
    /// state with `leaves` leaves, using `spec` to determine peak bagging.
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
        inactive_peaks: usize,
    ) -> Result<Proof<F, D>, Error<F>> {
        if !loc.is_valid_index() {
            return Err(Error::LocationOverflow(loc));
        }
        // loc is valid so it won't overflow from + 1
        self.historical_range_proof(hasher, leaves, loc..loc + 1, inactive_peaks)
            .await
    }

    /// Return an inclusion proof for the elements in `range` against a historical state with
    /// `leaves` leaves, using `spec` to determine peak bagging.
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
        inactive_peaks: usize,
    ) -> Result<Proof<F, D>, Error<F>> {
        if leaves > self.leaves() {
            return Err(Error::RangeOutOfBounds(leaves));
        }
        crate::merkle::verification::historical_range_proof(
            hasher,
            self,
            leaves,
            range,
            inactive_peaks,
        )
        .await
    }

    /// Return an inclusion proof for the element at the location `loc` that can be verified against
    /// the current root, using `spec` to determine peak bagging.
    ///
    /// Unlike the in-memory `Mem::proof`, this async method can read from the backing journal for
    /// nodes that have been synced out of memory.
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
        inactive_peaks: usize,
    ) -> Result<Proof<F, D>, Error<F>> {
        if !loc.is_valid_index() {
            return Err(Error::LocationOverflow(loc));
        }
        // loc is valid so it won't overflow from + 1
        self.range_proof(hasher, loc..loc + 1, inactive_peaks).await
    }

    /// Return an inclusion proof for the elements within the specified location range, using
    /// `spec` to determine peak bagging.
    ///
    /// Unlike the in-memory `Mem::range_proof`, this async method can read from the backing
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
        inactive_peaks: usize,
    ) -> Result<Proof<F, D>, Error<F>> {
        self.historical_range_proof(hasher, self.leaves(), range, inactive_peaks)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        journal::contiguous::fixed::{Config as JConfig, Journal},
        merkle::{hasher::Standard, mmb, mmr, Location, LocationRangeExt as _, Position, Proof},
        metadata::{Config as MConfig, Metadata},
    };
    use commonware_cryptography::{
        sha256::{self, Digest},
        Hasher as _, Sha256,
    };
    use commonware_macros::test_traced;
    use commonware_runtime::{buffer::paged::CacheRef, deterministic, BufferPooler, Runner};
    use commonware_utils::{non_empty_range, sequence::prefixed_u64::U64, NZUsize, NZU16, NZU64};
    use std::{
        collections::BTreeMap,
        num::{NonZeroU16, NonZeroUsize},
    };

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

    async fn full_empty_inner<F: Family>(context: deterministic::Context) {
        let hasher: Standard<Sha256> = Standard::new();
        let mut mmr = Merkle::<F, _, Digest>::init(
            context.with_label("first"),
            &hasher,
            test_config(&context),
        )
        .await
        .unwrap();
        assert_eq!(mmr.size(), 0);
        assert!(mmr.get_node(Position::<F>::new(0)).await.is_err());
        let bounds = mmr.bounds();
        assert!(bounds.is_empty());
        assert!(mmr.prune_all().await.is_ok());
        assert_eq!(bounds.start, 0);
        assert!(mmr.prune(Location::<F>::new(0)).await.is_ok());
        assert!(mmr.sync().await.is_ok());
        assert!(matches!(mmr.rewind(1).await, Err(Error::Empty)));

        let batch = mmr.new_batch().add(&hasher, &test_digest(0));
        let batch = mmr.with_mem(|mem| batch.merkleize(mem, &hasher));
        mmr.apply_batch(&batch).unwrap();
        assert_eq!(mmr.size(), 1);
        mmr.sync().await.unwrap();
        assert!(mmr.get_node(Position::<F>::new(0)).await.is_ok());
        assert!(mmr.rewind(1).await.is_ok());
        assert_eq!(mmr.size(), 0);
        mmr.sync().await.unwrap();

        let mut mmr = Merkle::<F, _, Digest>::init(
            context.with_label("second"),
            &hasher,
            test_config(&context),
        )
        .await
        .unwrap();
        assert_eq!(mmr.size(), 0);

        let empty_proof = Proof::<F, Digest>::default();
        let hasher: Standard<Sha256> = Standard::new();
        let root = mmr.root(&hasher, 0).unwrap();
        assert!(empty_proof.verify_range_inclusion(
            &hasher,
            &[] as &[Digest],
            Location::<F>::new(0),
            &root
        ));
        assert!(empty_proof.verify_multi_inclusion(
            &hasher,
            &[] as &[(Digest, Location<F>)],
            &root
        ));

        // Confirm empty proof no longer verifies after adding an element.
        let batch = mmr.new_batch().add(&hasher, &test_digest(0));
        let batch = mmr.with_mem(|mem| batch.merkleize(mem, &hasher));
        mmr.apply_batch(&batch).unwrap();
        let root = mmr.root(&hasher, 0).unwrap();
        assert!(!empty_proof.verify_range_inclusion(
            &hasher,
            &[] as &[Digest],
            Location::<F>::new(0),
            &root
        ));
        assert!(!empty_proof.verify_multi_inclusion(
            &hasher,
            &[] as &[(Digest, Location<F>)],
            &root
        ));

        mmr.destroy().await.unwrap();
    }

    #[test_traced]
    fn test_full_empty_mmr() {
        let executor = deterministic::Runner::default();
        executor.start(full_empty_inner::<mmr::Family>);
    }

    #[test_traced]
    fn test_full_empty_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(full_empty_inner::<mmb::Family>);
    }

    async fn full_prune_out_of_bounds_returns_error_inner<F: Family>(
        context: deterministic::Context,
    ) {
        let hasher = Standard::<Sha256>::new();
        let mut mmr = Merkle::<F, _, Digest>::init(
            context.with_label("oob_prune"),
            &hasher,
            test_config(&context),
        )
        .await
        .unwrap();

        let batch = mmr.new_batch().add(&hasher, &test_digest(0));
        let batch = mmr.with_mem(|mem| batch.merkleize(mem, &hasher));
        mmr.apply_batch(&batch).unwrap();

        assert!(matches!(
            mmr.prune(Location::<F>::new(2)).await,
            Err(Error::LeafOutOfBounds(loc)) if loc == Location::<F>::new(2)
        ));

        mmr.destroy().await.unwrap();
    }

    #[test_traced]
    fn test_full_prune_out_of_bounds_returns_error_mmr() {
        let executor = deterministic::Runner::default();
        executor.start(full_prune_out_of_bounds_returns_error_inner::<mmr::Family>);
    }

    #[test_traced]
    fn test_full_prune_out_of_bounds_returns_error_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(full_prune_out_of_bounds_returns_error_inner::<mmb::Family>);
    }

    async fn full_rewind_error_leaves_valid_state_inner<F: Family>(
        context: deterministic::Context,
    ) {
        let hasher: Standard<Sha256> = Standard::new();

        // Case 1: rewind partially succeeds, then returns ElementPruned.
        let element_pruned_context = context.with_label("element_pruned_case");
        let mut mmr = Merkle::<F, _, Digest>::init(
            element_pruned_context.clone(),
            &hasher,
            test_config(&element_pruned_context),
        )
        .await
        .unwrap();
        let mut batch = mmr.new_batch();
        for i in 0u64..32 {
            batch = batch.add(&hasher, &i.to_be_bytes());
        }
        let batch = mmr.with_mem(|mem| batch.merkleize(mem, &hasher));
        mmr.apply_batch(&batch).unwrap();
        mmr.prune(Location::<F>::new(8)).await.unwrap();
        let leaves_before = mmr.leaves();
        assert!(matches!(
            mmr.rewind(128).await,
            Err(Error::ElementPruned(_))
        ));
        // After error, leaves should reflect any partial rewinds that occurred.
        assert!(mmr.leaves() <= leaves_before);
        mmr.destroy().await.unwrap();

        // Case 2: rewind partially succeeds, then returns Empty.
        let empty_context = context.with_label("empty_case");
        let cfg = test_config(&empty_context);
        let mut mmr = Merkle::<F, _, Digest>::init(empty_context, &hasher, cfg)
            .await
            .unwrap();
        let mut batch = mmr.new_batch();
        for i in 0u64..8 {
            batch = batch.add(&hasher, &i.to_be_bytes());
        }
        let batch = mmr.with_mem(|mem| batch.merkleize(mem, &hasher));
        mmr.apply_batch(&batch).unwrap();
        let leaves_before = mmr.leaves();
        assert!(matches!(mmr.rewind(9).await, Err(Error::Empty)));
        // Rewind returns error without partial modification.
        assert_eq!(mmr.leaves(), leaves_before);
        mmr.destroy().await.unwrap();
    }

    #[test_traced]
    fn test_full_rewind_error_leaves_valid_state_mmr() {
        let executor = deterministic::Runner::default();
        executor.start(full_rewind_error_leaves_valid_state_inner::<mmr::Family>);
    }

    #[test_traced]
    fn test_full_rewind_error_leaves_valid_state_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(full_rewind_error_leaves_valid_state_inner::<mmb::Family>);
    }

    async fn full_basic_inner<F: Family>(context: deterministic::Context) {
        let hasher: Standard<Sha256> = Standard::new();
        let cfg = test_config(&context);
        let mut mmr = Merkle::<F, _, Digest>::init(context, &hasher, cfg)
            .await
            .unwrap();
        // Build a test structure with 255 leaves
        const LEAF_COUNT: usize = 255;
        let mut leaves = Vec::with_capacity(LEAF_COUNT);
        for i in 0..LEAF_COUNT {
            leaves.push(test_digest(i));
        }
        let mut batch = mmr.new_batch();
        for leaf in &leaves {
            batch = batch.add(&hasher, leaf);
        }
        let batch = mmr.with_mem(|mem| batch.merkleize(mem, &hasher));
        mmr.apply_batch(&batch).unwrap();
        let expected_size = Position::<F>::try_from(Location::<F>::new(LEAF_COUNT as u64)).unwrap();
        assert_eq!(mmr.size(), expected_size);

        // Generate & verify proof from element that is not yet flushed to the journal.
        const TEST_ELEMENT: usize = 133;
        let test_element_loc: Location<F> = Location::new(TEST_ELEMENT as u64);

        let proof = mmr.proof(&hasher, test_element_loc, 0).await.unwrap();
        let root = mmr.root(&hasher, 0).unwrap();
        assert!(proof.verify_element_inclusion(
            &hasher,
            &leaves[TEST_ELEMENT],
            test_element_loc,
            &root
        ));

        // Sync the structure, make sure it flushes the in-mem structure as expected.
        mmr.sync().await.unwrap();

        // Now that the element is flushed from the in-mem structure, confirm its proof is still
        // generated correctly.
        let proof2 = mmr.proof(&hasher, test_element_loc, 0).await.unwrap();
        assert_eq!(proof, proof2);

        // Generate & verify a proof that spans flushed elements and the last element.
        let range = Location::<F>::new(TEST_ELEMENT as u64)..Location::<F>::new(LEAF_COUNT as u64);
        let proof = mmr.range_proof(&hasher, range.clone(), 0).await.unwrap();
        assert!(proof.verify_range_inclusion(
            &hasher,
            &leaves[range.to_usize_range()],
            test_element_loc,
            &root
        ));

        mmr.destroy().await.unwrap();
    }

    #[test_traced]
    fn test_full_basic_mmr() {
        let executor = deterministic::Runner::default();
        executor.start(full_basic_inner::<mmr::Family>);
    }

    #[test_traced]
    fn test_full_basic_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(full_basic_inner::<mmb::Family>);
    }

    /// Generates a stateful structure, simulates a crash that wrote a leaf but not its parent
    /// nodes, and confirms we appropriately recover to a valid state.
    async fn full_recovery_inner<F: Family>(context: deterministic::Context) {
        use crate::journal::contiguous::fixed::{Config as JConfig, Journal};

        let hasher: Standard<Sha256> = Standard::new();
        let mut mmr = Merkle::<F, _, Digest>::init(
            context.with_label("first"),
            &hasher,
            test_config(&context),
        )
        .await
        .unwrap();
        assert_eq!(mmr.size(), 0);

        // Build a test structure with 252 leaves
        const LEAF_COUNT: usize = 252;
        let mut leaves = Vec::with_capacity(LEAF_COUNT);
        for i in 0..LEAF_COUNT {
            leaves.push(test_digest(i));
        }
        let mut batch = mmr.new_batch();
        for leaf in &leaves {
            batch = batch.add(&hasher, leaf);
        }
        let batch = mmr.with_mem(|mem| batch.merkleize(mem, &hasher));
        mmr.apply_batch(&batch).unwrap();
        let expected_size = Position::<F>::try_from(Location::<F>::new(LEAF_COUNT as u64)).unwrap();
        assert_eq!(mmr.size(), expected_size);
        mmr.sync().await.unwrap();
        drop(mmr);

        // Simulate a crash that wrote a leaf but not its parent nodes by appending one
        // extra digest to the journal. This creates an invalid structure size.
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
            assert_eq!(journal.size().await, expected_size);
            journal.append(&Sha256::hash(b"orphan")).await.unwrap();
            journal.sync().await.unwrap();
            assert_eq!(journal.size().await, expected_size + 1);
        }

        let mmr = Merkle::<F, _, Digest>::init(
            context.with_label("second"),
            &hasher,
            test_config(&context),
        )
        .await
        .unwrap();
        // Since the orphaned leaf is replayed, the structure recovers to the previous valid state
        // plus the new leaf.
        let recovered_size =
            Position::<F>::try_from(Location::<F>::new(LEAF_COUNT as u64 + 1)).unwrap();
        assert_eq!(mmr.size(), recovered_size);

        // Make sure dropping it and re-opening it persists the recovered state.
        drop(mmr);
        let mmr = Merkle::<F, _, Digest>::init(
            context.with_label("third"),
            &hasher,
            test_config(&context),
        )
        .await
        .unwrap();
        assert_eq!(mmr.size(), recovered_size);

        mmr.destroy().await.unwrap();
    }

    #[test_traced]
    fn test_full_recovery_mmr() {
        let executor = deterministic::Runner::default();
        executor.start(full_recovery_inner::<mmr::Family>);
    }

    #[test_traced]
    fn test_full_recovery_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(full_recovery_inner::<mmb::Family>);
    }

    async fn full_pruning_inner<F: Family>(context: deterministic::Context) {
        let hasher: Standard<Sha256> = Standard::new();
        // make sure pruning doesn't break root computation, adding of new nodes, etc.
        const LEAF_COUNT: usize = 2000;
        let cfg_pruned = test_config(&context);
        let mut pruned_mmr =
            Merkle::<F, _, Digest>::init(context.with_label("pruned"), &hasher, cfg_pruned.clone())
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
        let mut mmr =
            Merkle::<F, _, Digest>::init(context.with_label("unpruned"), &hasher, cfg_unpruned)
                .await
                .unwrap();
        let mut leaves = Vec::with_capacity(LEAF_COUNT);
        for i in 0..LEAF_COUNT {
            leaves.push(test_digest(i));
        }
        let mut batch = mmr.new_batch();
        for leaf in &leaves {
            batch = batch.add(&hasher, leaf);
        }
        let batch = mmr.with_mem(|mem| batch.merkleize(mem, &hasher));
        mmr.apply_batch(&batch).unwrap();
        let mut batch = pruned_mmr.new_batch();
        for leaf in &leaves {
            batch = batch.add(&hasher, leaf);
        }
        let batch = pruned_mmr.with_mem(|mem| batch.merkleize(mem, &hasher));
        pruned_mmr.apply_batch(&batch).unwrap();
        let expected_size = Position::<F>::try_from(Location::<F>::new(LEAF_COUNT as u64)).unwrap();
        assert_eq!(mmr.size(), expected_size);
        assert_eq!(pruned_mmr.size(), expected_size);

        // Prune the structure in increments of 10 making sure the journal is still able to compute
        // roots and accept new elements.
        for i in 0usize..300 {
            let prune_loc = Location::<F>::new(std::cmp::min(i as u64 * 10, *pruned_mmr.leaves()));
            pruned_mmr.prune(prune_loc).await.unwrap();
            assert_eq!(prune_loc, pruned_mmr.bounds().start);

            let digest = test_digest(LEAF_COUNT + i);
            leaves.push(digest);
            let last_leaf = leaves.last().unwrap();
            let batch = pruned_mmr.new_batch().add(&hasher, last_leaf);
            let batch = pruned_mmr.with_mem(|mem| batch.merkleize(mem, &hasher));
            pruned_mmr.apply_batch(&batch).unwrap();
            let batch = mmr.new_batch().add(&hasher, last_leaf);
            let batch = mmr.with_mem(|mem| batch.merkleize(mem, &hasher));
            mmr.apply_batch(&batch).unwrap();
            assert_eq!(
                pruned_mmr.root(&hasher, 0).unwrap(),
                mmr.root(&hasher, 0).unwrap()
            );
        }

        // Sync the structures.
        pruned_mmr.sync().await.unwrap();
        assert_eq!(
            pruned_mmr.root(&hasher, 0).unwrap(),
            mmr.root(&hasher, 0).unwrap()
        );

        // Sync the structure & reopen.
        pruned_mmr.sync().await.unwrap();
        drop(pruned_mmr);
        let mut pruned_mmr = Merkle::<F, _, Digest>::init(
            context.with_label("pruned_reopen"),
            &hasher,
            cfg_pruned.clone(),
        )
        .await
        .unwrap();
        assert_eq!(
            pruned_mmr.root(&hasher, 0).unwrap(),
            mmr.root(&hasher, 0).unwrap()
        );

        // Prune everything.
        let size = pruned_mmr.size();
        pruned_mmr.prune_all().await.unwrap();
        assert_eq!(
            pruned_mmr.root(&hasher, 0).unwrap(),
            mmr.root(&hasher, 0).unwrap()
        );
        let bounds = pruned_mmr.bounds();
        assert!(bounds.is_empty());
        assert_eq!(bounds.start, Location::<F>::try_from(size).unwrap());

        // Close structure after adding a new node without syncing and make sure state is as
        // expected on reopening.
        let batch = mmr.new_batch().add(&hasher, &test_digest(LEAF_COUNT));
        let batch = mmr.with_mem(|mem| batch.merkleize(mem, &hasher));
        mmr.apply_batch(&batch).unwrap();
        let batch = pruned_mmr
            .new_batch()
            .add(&hasher, &test_digest(LEAF_COUNT));
        let batch = pruned_mmr.with_mem(|mem| batch.merkleize(mem, &hasher));
        pruned_mmr.apply_batch(&batch).unwrap();
        assert!(*pruned_mmr.size() % cfg_pruned.items_per_blob != 0);
        pruned_mmr.sync().await.unwrap();
        drop(pruned_mmr);
        let mut pruned_mmr = Merkle::<F, _, Digest>::init(
            context.with_label("pruned_reopen2"),
            &hasher,
            cfg_pruned.clone(),
        )
        .await
        .unwrap();
        assert_eq!(
            pruned_mmr.root(&hasher, 0).unwrap(),
            mmr.root(&hasher, 0).unwrap()
        );
        let bounds = pruned_mmr.bounds();
        assert!(!bounds.is_empty());
        assert_eq!(bounds.start, Location::<F>::try_from(size).unwrap());

        // Make sure pruning to older location is a no-op.
        assert!(pruned_mmr
            .prune(Location::<F>::try_from(size).unwrap() - 1)
            .await
            .is_ok());
        assert_eq!(
            pruned_mmr.bounds().start,
            Location::<F>::try_from(size).unwrap()
        );

        // Add nodes until we are on a blob boundary, and confirm prune_all still removes all
        // retained nodes.
        while *pruned_mmr.size() % cfg_pruned.items_per_blob != 0 {
            let batch = pruned_mmr
                .new_batch()
                .add(&hasher, &test_digest(LEAF_COUNT));
            let batch = pruned_mmr.with_mem(|mem| batch.merkleize(mem, &hasher));
            pruned_mmr.apply_batch(&batch).unwrap();
        }
        pruned_mmr.prune_all().await.unwrap();
        assert!(pruned_mmr.bounds().is_empty());

        pruned_mmr.destroy().await.unwrap();
        mmr.destroy().await.unwrap();
    }

    #[test_traced]
    fn test_full_pruning_mmr() {
        let executor = deterministic::Runner::default();
        executor.start(full_pruning_inner::<mmr::Family>);
    }

    #[test_traced]
    fn test_full_pruning_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(full_pruning_inner::<mmb::Family>);
    }

    /// Simulate partial writes after pruning, making sure we recover to a valid state.
    async fn full_recovery_with_pruning_inner<F: Family>(context: deterministic::Context) {
        // Build structure with 2000 leaves.
        let hasher: Standard<Sha256> = Standard::new();
        const LEAF_COUNT: usize = 2000;
        let mut leaves = Vec::with_capacity(LEAF_COUNT);
        let mut mmr = Merkle::<F, _, Digest>::init(
            context.with_label("init"),
            &hasher,
            test_config(&context),
        )
        .await
        .unwrap();
        for i in 0..LEAF_COUNT {
            leaves.push(test_digest(i));
        }
        let mut batch = mmr.new_batch();
        for leaf in &leaves {
            batch = batch.add(&hasher, leaf);
        }
        let batch = mmr.with_mem(|mem| batch.merkleize(mem, &hasher));
        mmr.apply_batch(&batch).unwrap();
        let expected_size = Position::<F>::try_from(Location::<F>::new(LEAF_COUNT as u64)).unwrap();
        assert_eq!(mmr.size(), expected_size);
        mmr.sync().await.unwrap();
        drop(mmr);

        // Prune the structure in increments of 50, simulating a partial write after each prune.
        for i in 0usize..200 {
            let label = format!("iter_{i}");
            let mut mmr = Merkle::<F, _, Digest>::init(
                context.with_label(&label),
                &hasher,
                test_config(&context),
            )
            .await
            .unwrap();
            let start_size = mmr.size();
            let start_leaves = *mmr.leaves();
            let prune_loc = Location::<F>::new(std::cmp::min(i as u64 * 50, start_leaves));
            if i % 5 == 0 {
                mmr.simulate_pruning_failure(prune_loc).await.unwrap();
                continue;
            }
            mmr.prune(prune_loc).await.unwrap();

            // add new elements, simulating a partial write after each.
            for j in 0..10 {
                let digest = test_digest(100 * (i + 1) + j);
                leaves.push(digest);
                let batch = mmr
                    .new_batch()
                    .add(&hasher, leaves.last().unwrap())
                    .add(&hasher, leaves.last().unwrap());
                let batch = mmr.with_mem(|mem| batch.merkleize(mem, &hasher));
                mmr.apply_batch(&batch).unwrap();
                let digest = test_digest(LEAF_COUNT + i);
                leaves.push(digest);
                let batch = mmr
                    .new_batch()
                    .add(&hasher, leaves.last().unwrap())
                    .add(&hasher, leaves.last().unwrap());
                let batch = mmr.with_mem(|mem| batch.merkleize(mem, &hasher));
                mmr.apply_batch(&batch).unwrap();
            }
            let end_size = mmr.size();
            let total_to_write = (*end_size - *start_size) as usize;
            let partial_write_limit = i % total_to_write;
            mmr.simulate_partial_sync(partial_write_limit)
                .await
                .unwrap();
        }

        let mmr = Merkle::<F, _, Digest>::init(
            context.with_label("final"),
            &hasher,
            test_config(&context),
        )
        .await
        .unwrap();
        mmr.destroy().await.unwrap();
    }

    #[test_traced("WARN")]
    fn test_full_recovery_with_pruning_mmr() {
        let executor = deterministic::Runner::default();
        executor.start(full_recovery_with_pruning_inner::<mmr::Family>);
    }

    #[test_traced("WARN")]
    fn test_full_recovery_with_pruning_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(full_recovery_with_pruning_inner::<mmb::Family>);
    }

    async fn full_historical_proof_basic_inner<F: Family>(context: deterministic::Context) {
        // Create structure with 10 elements
        let hasher = Standard::<Sha256>::new();
        let cfg = test_config(&context);
        let mut mmr = Merkle::<F, _, Digest>::init(context, &hasher, cfg)
            .await
            .unwrap();
        let mut elements = Vec::new();
        for i in 0..10 {
            elements.push(test_digest(i));
        }
        let mut batch = mmr.new_batch();
        for elt in &elements {
            batch = batch.add(&hasher, elt);
        }
        let batch = mmr.with_mem(|mem| batch.merkleize(mem, &hasher));
        mmr.apply_batch(&batch).unwrap();
        let original_leaves = mmr.leaves();

        // Historical proof should match "regular" proof when historical size == current database size
        let historical_proof = mmr
            .historical_range_proof(
                &hasher,
                original_leaves,
                Location::<F>::new(2)..Location::<F>::new(6),
                0,
            )
            .await
            .unwrap();
        assert_eq!(historical_proof.leaves, original_leaves);
        let root = mmr.root(&hasher, 0).unwrap();
        assert!(historical_proof.verify_range_inclusion(
            &hasher,
            &elements[2..6],
            Location::<F>::new(2),
            &root
        ));
        let regular_proof = mmr
            .range_proof(&hasher, Location::<F>::new(2)..Location::<F>::new(6), 0)
            .await
            .unwrap();
        assert_eq!(regular_proof.leaves, historical_proof.leaves);
        assert_eq!(regular_proof.digests, historical_proof.digests);

        // Add more elements to the structure
        for i in 10..20 {
            elements.push(test_digest(i));
        }
        let mut batch = mmr.new_batch();
        for elt in &elements[10..20] {
            batch = batch.add(&hasher, elt);
        }
        let batch = mmr.with_mem(|mem| batch.merkleize(mem, &hasher));
        mmr.apply_batch(&batch).unwrap();
        let new_historical_proof = mmr
            .historical_range_proof(
                &hasher,
                original_leaves,
                Location::<F>::new(2)..Location::<F>::new(6),
                0,
            )
            .await
            .unwrap();
        assert_eq!(new_historical_proof.leaves, historical_proof.leaves);
        assert_eq!(new_historical_proof.digests, historical_proof.digests);

        mmr.destroy().await.unwrap();
    }

    #[test_traced]
    fn test_full_historical_proof_basic_mmr() {
        let executor = deterministic::Runner::default();
        executor.start(full_historical_proof_basic_inner::<mmr::Family>);
    }

    #[test_traced]
    fn test_full_historical_proof_basic_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(full_historical_proof_basic_inner::<mmb::Family>);
    }

    async fn full_historical_proof_with_pruning_inner<F: Family>(context: deterministic::Context) {
        let hasher = Standard::<Sha256>::new();
        let mut mmr = Merkle::<F, _, Digest>::init(
            context.with_label("main"),
            &hasher,
            test_config(&context),
        )
        .await
        .unwrap();

        // Add many elements
        let mut elements = Vec::new();
        for i in 0..50 {
            elements.push(test_digest(i));
        }
        let mut batch = mmr.new_batch();
        for elt in &elements {
            batch = batch.add(&hasher, elt);
        }
        let batch = mmr.with_mem(|mem| batch.merkleize(mem, &hasher));
        mmr.apply_batch(&batch).unwrap();

        // Prune to leaf 16 (position 30)
        let prune_loc = Location::<F>::new(16);
        mmr.prune(prune_loc).await.unwrap();

        // Create reference structure for verification to get correct size
        let mut ref_mmr = Merkle::<F, _, Digest>::init(
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

        let mut batch = ref_mmr.new_batch();
        for elt in elements.iter().take(41) {
            batch = batch.add(&hasher, elt);
        }
        let batch = ref_mmr.with_mem(|mem| batch.merkleize(mem, &hasher));
        ref_mmr.apply_batch(&batch).unwrap();
        let historical_leaves = ref_mmr.leaves();
        let historical_root = ref_mmr.root(&hasher, 0).unwrap();

        // Test proof at historical position after pruning
        let historical_proof = mmr
            .historical_range_proof(
                &hasher,
                historical_leaves,
                Location::<F>::new(35)..Location::<F>::new(39),
                0,
            )
            .await
            .unwrap();

        assert_eq!(historical_proof.leaves, historical_leaves);

        // Verify proof works despite pruning
        assert!(historical_proof.verify_range_inclusion(
            &hasher,
            &elements[35..39],
            Location::<F>::new(35),
            &historical_root
        ));

        ref_mmr.destroy().await.unwrap();
        mmr.destroy().await.unwrap();
    }

    #[test_traced]
    fn test_full_historical_proof_with_pruning_mmr() {
        let executor = deterministic::Runner::default();
        executor.start(full_historical_proof_with_pruning_inner::<mmr::Family>);
    }

    #[test_traced]
    fn test_full_historical_proof_with_pruning_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(full_historical_proof_with_pruning_inner::<mmb::Family>);
    }

    async fn full_historical_proof_large_inner<F: Family>(context: deterministic::Context) {
        let hasher = Standard::<Sha256>::new();

        let mut mmr = Merkle::<F, _, Digest>::init(
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
        let mut batch = mmr.new_batch();
        for elt in &elements {
            batch = batch.add(&hasher, elt);
        }
        let batch = mmr.with_mem(|mem| batch.merkleize(mem, &hasher));
        mmr.apply_batch(&batch).unwrap();

        let range = Location::<F>::new(30)..Location::<F>::new(61);

        // Only apply elements up to end_loc to the reference structure.
        let mut ref_mmr = Merkle::<F, _, Digest>::init(
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
        let mut batch = ref_mmr.new_batch();
        for elt in elements.iter().take(*range.end as usize) {
            batch = batch.add(&hasher, elt);
        }
        let batch = ref_mmr.with_mem(|mem| batch.merkleize(mem, &hasher));
        ref_mmr.apply_batch(&batch).unwrap();
        let historical_leaves = ref_mmr.leaves();
        let expected_root = ref_mmr.root(&hasher, 0).unwrap();

        // Generate proof from full structure
        let proof = mmr
            .historical_range_proof(&hasher, historical_leaves, range.clone(), 0)
            .await
            .unwrap();

        assert!(proof.verify_range_inclusion(
            &hasher,
            &elements[range.to_usize_range()],
            range.start,
            &expected_root, // Compare to historical (reference) root
        ));

        ref_mmr.destroy().await.unwrap();
        mmr.destroy().await.unwrap();
    }

    #[test_traced]
    fn test_full_historical_proof_large_mmr() {
        let executor = deterministic::Runner::default();
        executor.start(full_historical_proof_large_inner::<mmr::Family>);
    }

    #[test_traced]
    fn test_full_historical_proof_large_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(full_historical_proof_large_inner::<mmb::Family>);
    }

    async fn full_historical_proof_singleton_inner<F: Family>(context: deterministic::Context) {
        let hasher = Standard::<Sha256>::new();
        let cfg = test_config(&context);
        let mut mmr = Merkle::<F, _, Digest>::init(context, &hasher, cfg)
            .await
            .unwrap();

        let element = test_digest(0);
        let batch = mmr.new_batch().add(&hasher, &element);
        let batch = mmr.with_mem(|mem| batch.merkleize(mem, &hasher));
        mmr.apply_batch(&batch).unwrap();

        // Test single element proof at historical position
        let single_proof = mmr
            .historical_range_proof(
                &hasher,
                Location::<F>::new(1),
                Location::<F>::new(0)..Location::<F>::new(1),
                0,
            )
            .await
            .unwrap();

        let root = mmr.root(&hasher, 0).unwrap();
        assert!(single_proof.verify_range_inclusion(
            &hasher,
            &[element],
            Location::<F>::new(0),
            &root
        ));

        mmr.destroy().await.unwrap();
    }

    #[test_traced]
    fn test_full_historical_proof_singleton_mmr() {
        let executor = deterministic::Runner::default();
        executor.start(full_historical_proof_singleton_inner::<mmr::Family>);
    }

    #[test_traced]
    fn test_full_historical_proof_singleton_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(full_historical_proof_singleton_inner::<mmb::Family>);
    }

    // Test `init_sync` when there is no persisted data.
    async fn full_init_sync_empty_inner<F: Family>(context: deterministic::Context) {
        let hasher = Standard::<Sha256>::new();

        // Test fresh start scenario with completely new structure (no existing data)
        let sync_cfg = SyncConfig::<F, sha256::Digest> {
            config: test_config(&context),
            range: non_empty_range!(Location::<F>::new(0), Location::<F>::new(52)),
            pinned_nodes: None,
        };

        let mut sync_mmr = Merkle::<F, _, Digest>::init_sync(context.clone(), sync_cfg)
            .await
            .unwrap();

        // Should be fresh structure starting empty
        assert_eq!(sync_mmr.size(), 0);
        let bounds = sync_mmr.bounds();
        assert_eq!(bounds.start, 0);
        assert!(bounds.is_empty());

        // Should be able to add new elements
        let new_element = test_digest(999);
        let batch = sync_mmr.new_batch().add(&hasher, &new_element);
        let batch = sync_mmr.with_mem(|mem| batch.merkleize(mem, &hasher));
        sync_mmr.apply_batch(&batch).unwrap();

        // Root should be computable
        let _root = sync_mmr.root(&hasher, 0).unwrap();

        sync_mmr.destroy().await.unwrap();
    }

    #[test_traced]
    fn test_full_init_sync_empty_mmr() {
        let executor = deterministic::Runner::default();
        executor.start(full_init_sync_empty_inner::<mmr::Family>);
    }

    #[test_traced]
    fn test_full_init_sync_empty_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(full_init_sync_empty_inner::<mmb::Family>);
    }

    // Test `init_sync` where the persisted structure's persisted nodes match the sync boundaries.
    async fn full_init_sync_nonempty_exact_match_inner<F: Family>(context: deterministic::Context) {
        let hasher = Standard::<Sha256>::new();

        // Create initial structure with elements.
        let mut mmr = Merkle::<F, _, Digest>::init(
            context.with_label("init"),
            &hasher,
            test_config(&context),
        )
        .await
        .unwrap();
        let mut batch = mmr.new_batch();
        for i in 0..50 {
            batch = batch.add(&hasher, &test_digest(i));
        }
        let batch = mmr.with_mem(|mem| batch.merkleize(mem, &hasher));
        mmr.apply_batch(&batch).unwrap();
        mmr.sync().await.unwrap();
        let original_size = mmr.size();
        let original_leaves = mmr.leaves();
        let original_root = mmr.root(&hasher, 0).unwrap();

        // Sync with range.start <= existing_size <= range.end should reuse data
        let lower_bound_loc = mmr.bounds().start;
        let upper_bound_loc = mmr.leaves();
        let lower_bound_pos = Position::<F>::try_from(lower_bound_loc).unwrap();
        let upper_bound_pos = mmr.size();
        let mut expected_nodes = BTreeMap::new();
        for i in *lower_bound_pos..*upper_bound_pos {
            expected_nodes.insert(
                Position::<F>::new(i),
                mmr.get_node(Position::<F>::new(i)).await.unwrap().unwrap(),
            );
        }
        let sync_cfg = SyncConfig::<F, sha256::Digest> {
            config: test_config(&context),
            range: non_empty_range!(lower_bound_loc, upper_bound_loc),
            pinned_nodes: None,
        };

        mmr.sync().await.unwrap();
        drop(mmr);

        let sync_mmr = Merkle::<F, _, Digest>::init_sync(context.with_label("sync"), sync_cfg)
            .await
            .unwrap();

        // Should have existing data in the sync range.
        assert_eq!(sync_mmr.size(), original_size);
        assert_eq!(sync_mmr.leaves(), original_leaves);
        let bounds = sync_mmr.bounds();
        assert_eq!(bounds.start, lower_bound_loc);
        assert!(!bounds.is_empty());
        assert_eq!(sync_mmr.root(&hasher, 0).unwrap(), original_root);
        for pos in *lower_bound_pos..*upper_bound_pos {
            let pos = Position::<F>::new(pos);
            assert_eq!(
                sync_mmr.get_node(pos).await.unwrap(),
                expected_nodes.get(&pos).cloned()
            );
        }

        sync_mmr.destroy().await.unwrap();
    }

    #[test_traced]
    fn test_full_init_sync_nonempty_exact_match_mmr() {
        let executor = deterministic::Runner::default();
        executor.start(full_init_sync_nonempty_exact_match_inner::<mmr::Family>);
    }

    #[test_traced]
    fn test_full_init_sync_nonempty_exact_match_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(full_init_sync_nonempty_exact_match_inner::<mmb::Family>);
    }

    // Test `init_sync` where the persisted structure's data partially overlaps with the sync
    // boundaries.
    async fn full_init_sync_partial_overlap_inner<F: Family>(context: deterministic::Context) {
        let hasher = Standard::<Sha256>::new();

        // Create initial structure with elements.
        let mut mmr = Merkle::<F, _, Digest>::init(
            context.with_label("init"),
            &hasher,
            test_config(&context),
        )
        .await
        .unwrap();
        let mut batch = mmr.new_batch();
        for i in 0..30 {
            batch = batch.add(&hasher, &test_digest(i));
        }
        let batch = mmr.with_mem(|mem| batch.merkleize(mem, &hasher));
        mmr.apply_batch(&batch).unwrap();
        mmr.sync().await.unwrap();
        mmr.prune(Location::<F>::new(6)).await.unwrap();

        let original_size = mmr.size();
        let original_leaves = mmr.leaves();
        let original_root = mmr.root(&hasher, 0).unwrap();
        let original_pruning_boundary = mmr.bounds().start;
        let original_pruning_pos = Position::<F>::try_from(original_pruning_boundary).unwrap();

        // Sync with boundaries that extend beyond existing data (partial overlap).
        let lower_bound_loc = original_pruning_boundary;
        let upper_bound_loc = original_leaves + 6; // Extend beyond existing data

        let mut expected_nodes = BTreeMap::new();
        for i in *original_pruning_pos..*original_size {
            let pos = Position::<F>::new(i);
            expected_nodes.insert(pos, mmr.get_node(pos).await.unwrap().unwrap());
        }

        let sync_cfg = SyncConfig::<F, sha256::Digest> {
            config: test_config(&context),
            range: non_empty_range!(lower_bound_loc, upper_bound_loc),
            pinned_nodes: None,
        };

        mmr.sync().await.unwrap();
        drop(mmr);

        let sync_mmr = Merkle::<F, _, Digest>::init_sync(context.with_label("sync"), sync_cfg)
            .await
            .unwrap();

        // Should have existing data in the overlapping range.
        assert_eq!(sync_mmr.size(), original_size);
        let bounds = sync_mmr.bounds();
        assert_eq!(bounds.start, lower_bound_loc);
        assert!(!bounds.is_empty());
        assert_eq!(sync_mmr.root(&hasher, 0).unwrap(), original_root);

        // Check that existing nodes are preserved in the overlapping range.
        for i in *original_pruning_pos..*original_size {
            let pos = Position::<F>::new(i);
            assert_eq!(
                sync_mmr.get_node(pos).await.unwrap(),
                expected_nodes.get(&pos).cloned()
            );
        }

        sync_mmr.destroy().await.unwrap();
    }

    #[test_traced]
    fn test_full_init_sync_partial_overlap_mmr() {
        let executor = deterministic::Runner::default();
        executor.start(full_init_sync_partial_overlap_inner::<mmr::Family>);
    }

    #[test_traced]
    fn test_full_init_sync_partial_overlap_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(full_init_sync_partial_overlap_inner::<mmb::Family>);
    }

    async fn full_init_sync_rejects_extra_pinned_nodes_inner<F: Family>(
        context: deterministic::Context,
    ) {
        let sync_cfg = SyncConfig::<F, sha256::Digest> {
            config: test_config(&context),
            range: non_empty_range!(Location::<F>::new(6), Location::<F>::new(20)),
            pinned_nodes: Some(vec![test_digest(1), test_digest(2), test_digest(3)]),
        };

        let result = Merkle::<F, _, Digest>::init_sync(context.with_label("sync"), sync_cfg).await;
        assert!(matches!(result, Err(Error::InvalidPinnedNodes)));
    }

    #[test_traced]
    fn test_full_init_sync_rejects_extra_pinned_nodes_mmr() {
        let executor = deterministic::Runner::default();
        executor.start(full_init_sync_rejects_extra_pinned_nodes_inner::<mmr::Family>);
    }

    #[test_traced]
    fn test_full_init_sync_rejects_extra_pinned_nodes_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(full_init_sync_rejects_extra_pinned_nodes_inner::<mmb::Family>);
    }

    // Regression test that init() handles stale metadata (lower pruning boundary than journal).
    // Before the fix, this would panic with an assertion failure. After the fix, it returns a
    // MissingNode error (which is expected when metadata is corrupted and pinned nodes are lost).
    async fn full_init_stale_metadata_returns_error_inner<F: Family>(
        context: deterministic::Context,
    ) {
        let hasher = Standard::<Sha256>::new();

        // Create a structure with some data and prune it
        let mut mmr = Merkle::<F, _, Digest>::init(
            context.with_label("init"),
            &hasher,
            test_config(&context),
        )
        .await
        .unwrap();

        // Add 50 elements
        let mut batch = mmr.new_batch();
        for i in 0..50 {
            batch = batch.add(&hasher, &test_digest(i));
        }
        let batch = mmr.with_mem(|mem| batch.merkleize(mem, &hasher));
        mmr.apply_batch(&batch).unwrap();
        mmr.sync().await.unwrap();

        // Prune enough that the journal boundary's pinned nodes span pruned blobs.
        let prune_loc = Location::<F>::new(25);
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

        // Reopen the structure - before the fix, this would panic with assertion failure
        // After the fix, it returns MissingNode error (pinned nodes for the lower
        // boundary don't exist since they were pruned from journal and weren't
        // stored in metadata at the lower position)
        let result = Merkle::<F, _, Digest>::init(
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
    }

    #[test_traced("WARN")]
    fn test_full_init_stale_metadata_returns_error_mmr() {
        let executor = deterministic::Runner::default();
        executor.start(full_init_stale_metadata_returns_error_inner::<mmr::Family>);
    }

    #[test_traced("WARN")]
    fn test_full_init_stale_metadata_returns_error_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(full_init_stale_metadata_returns_error_inner::<mmb::Family>);
    }

    // Test that init() handles the case where metadata pruning boundary is ahead
    // of journal (crashed before journal prune completed). This should successfully
    // prune the journal to match metadata.
    async fn full_init_metadata_ahead_inner<F: Family>(context: deterministic::Context) {
        let hasher = Standard::<Sha256>::new();

        // Create a structure with some data
        let mut mmr = Merkle::<F, _, Digest>::init(
            context.with_label("init"),
            &hasher,
            test_config(&context),
        )
        .await
        .unwrap();

        // Add 50 elements
        let mut batch = mmr.new_batch();
        for i in 0..50 {
            batch = batch.add(&hasher, &test_digest(i));
        }
        let batch = mmr.with_mem(|mem| batch.merkleize(mem, &hasher));
        mmr.apply_batch(&batch).unwrap();
        mmr.sync().await.unwrap();

        // Prune to position 30 (this stores pinned nodes and updates metadata)
        let prune_loc = Location::<F>::new(16);
        mmr.prune(prune_loc).await.unwrap();
        let expected_root = mmr.root(&hasher, 0).unwrap();
        let expected_size = mmr.size();
        drop(mmr);

        // Reopen the structure - should recover correctly with metadata ahead of
        // journal boundary (metadata says 30, journal is section-aligned to 28)
        let mmr = Merkle::<F, _, Digest>::init(
            context.with_label("reopened"),
            &hasher,
            test_config(&context),
        )
        .await
        .unwrap();

        assert_eq!(mmr.bounds().start, prune_loc);
        assert_eq!(mmr.size(), expected_size);
        assert_eq!(mmr.root(&hasher, 0).unwrap(), expected_root);

        mmr.destroy().await.unwrap();
    }

    #[test_traced("WARN")]
    fn test_full_init_metadata_ahead_mmr() {
        let executor = deterministic::Runner::default();
        executor.start(full_init_metadata_ahead_inner::<mmr::Family>);
    }

    #[test_traced("WARN")]
    fn test_full_init_metadata_ahead_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(full_init_metadata_ahead_inner::<mmb::Family>);
    }

    // Regression test: init_sync must compute pinned nodes BEFORE pruning the journal. Previously,
    // init_sync would prune the journal first, then try to read pinned nodes from the pruned
    // positions, causing MissingNode errors.
    //
    // Key setup: We create a structure with data but DON'T prune it, so the metadata has no pinned
    // nodes. Then init_sync must read pinned nodes from the journal before pruning it.
    async fn full_init_sync_computes_pinned_nodes_before_pruning_inner<F: Family>(
        context: deterministic::Context,
    ) {
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

        // Create structure with enough elements to span multiple sections.
        let mut mmr =
            Merkle::<F, _, Digest>::init(context.with_label("init"), &hasher, cfg.clone())
                .await
                .unwrap();
        let mut batch = mmr.new_batch();
        for i in 0..100 {
            batch = batch.add(&hasher, &test_digest(i));
        }
        let batch = mmr.with_mem(|mem| batch.merkleize(mem, &hasher));
        mmr.apply_batch(&batch).unwrap();
        mmr.sync().await.unwrap();

        // Don't prune - this ensures metadata has no pinned nodes. init_sync will need to
        // read pinned nodes from the journal.
        let original_size = mmr.size();
        let original_root = mmr.root(&hasher, 0).unwrap();
        drop(mmr);

        // Reopen via init_sync with range.start > 0. This will prune the journal, so
        // init_sync must read pinned nodes BEFORE pruning or they'll be lost.
        let prune_loc = Location::<F>::new(32);
        let sync_cfg = SyncConfig::<F, sha256::Digest> {
            config: cfg,
            range: non_empty_range!(prune_loc, Location::<F>::new(128)),
            pinned_nodes: None, // Force init_sync to compute pinned nodes from journal
        };

        let sync_mmr = Merkle::<F, _, Digest>::init_sync(context.with_label("sync"), sync_cfg)
            .await
            .unwrap();

        // Verify the structure state is correct.
        assert_eq!(sync_mmr.size(), original_size);
        assert_eq!(sync_mmr.root(&hasher, 0).unwrap(), original_root);
        assert_eq!(sync_mmr.bounds().start, prune_loc);

        sync_mmr.destroy().await.unwrap();
    }

    #[test_traced]
    fn test_full_init_sync_computes_pinned_nodes_before_pruning_mmr() {
        let executor = deterministic::Runner::default();
        executor.start(full_init_sync_computes_pinned_nodes_before_pruning_inner::<mmr::Family>);
    }

    #[test_traced]
    fn test_full_init_sync_computes_pinned_nodes_before_pruning_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(full_init_sync_computes_pinned_nodes_before_pruning_inner::<mmb::Family>);
    }

    async fn full_historical_proof_pruned_elements_inner<F: Family>(
        context: deterministic::Context,
    ) {
        let hasher = Standard::<Sha256>::new();

        let mut mmr = Merkle::<F, _, Digest>::init(
            context.with_label("init"),
            &hasher,
            test_config(&context),
        )
        .await
        .unwrap();

        let mut batch = mmr.new_batch();
        for i in 0..64 {
            batch = batch.add(&hasher, &test_digest(i));
        }
        let batch = mmr.with_mem(|mem| batch.merkleize(mem, &hasher));
        mmr.apply_batch(&batch).unwrap();

        let prune_loc = Location::<F>::new(16);
        mmr.prune(prune_loc).await.unwrap();

        let historical_leaves = mmr.leaves();
        let mut pruned_loc = None;
        for loc_u64 in 0..*historical_leaves {
            let loc = Location::<F>::new(loc_u64);
            let result = mmr
                .historical_range_proof(&hasher, historical_leaves, loc..loc + 1, 0)
                .await;
            if matches!(result, Err(Error::ElementPruned(_))) {
                pruned_loc = Some(loc);
                break;
            }
        }
        let pruned_loc = pruned_loc.expect("expected at least one pruned location");

        // Add more elements and verify pruned elements still return ElementPruned.
        let mut batch = mmr.new_batch();
        for i in 0..8 {
            batch = batch.add(&hasher, &test_digest(10_000 + i));
        }
        let batch = mmr.with_mem(|mem| batch.merkleize(mem, &hasher));
        mmr.apply_batch(&batch).unwrap();

        let requested = mmr.leaves();
        let result = mmr
            .historical_range_proof(&hasher, requested, pruned_loc..pruned_loc + 1, 0)
            .await;
        assert!(matches!(result, Err(Error::ElementPruned(_))));

        mmr.destroy().await.unwrap();
    }

    #[test_traced]
    fn test_full_historical_proof_pruned_elements_mmr() {
        let executor = deterministic::Runner::default();
        executor.start(full_historical_proof_pruned_elements_inner::<mmr::Family>);
    }

    #[test_traced]
    fn test_full_historical_proof_pruned_elements_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(full_historical_proof_pruned_elements_inner::<mmb::Family>);
    }

    async fn full_append_while_historical_proof_is_available_inner<F: Family>(
        context: deterministic::Context,
    ) {
        let hasher = Standard::<Sha256>::new();
        let mut mmr = Merkle::<F, _, Digest>::init(
            context.with_label("init"),
            &hasher,
            test_config(&context),
        )
        .await
        .unwrap();

        let mut batch = mmr.new_batch();
        for i in 0..20 {
            batch = batch.add(&hasher, &test_digest(i));
        }
        let batch = mmr.with_mem(|mem| batch.merkleize(mem, &hasher));
        mmr.apply_batch(&batch).unwrap();

        let historical_leaves = Location::<F>::new(10);
        let range = Location::<F>::new(2)..Location::<F>::new(8);

        // Appends should remain allowed while historical proofs are available.
        let batch = mmr
            .new_batch()
            .add(&hasher, &test_digest(100))
            .add(&hasher, &test_digest(101));
        let batch = mmr.with_mem(|mem| batch.merkleize(mem, &hasher));
        mmr.apply_batch(&batch).unwrap();

        let proof = mmr
            .historical_range_proof(&hasher, historical_leaves, range.clone(), 0)
            .await
            .unwrap();

        let expected = mmr
            .historical_range_proof(&hasher, historical_leaves, range, 0)
            .await
            .unwrap();
        assert_eq!(proof, expected);

        mmr.destroy().await.unwrap();
    }

    #[test_traced]
    fn test_full_append_while_historical_proof_is_available_mmr() {
        let executor = deterministic::Runner::default();
        executor.start(full_append_while_historical_proof_is_available_inner::<mmr::Family>);
    }

    #[test_traced]
    fn test_full_append_while_historical_proof_is_available_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(full_append_while_historical_proof_is_available_inner::<mmb::Family>);
    }

    async fn full_historical_proof_after_sync_reads_from_journal_inner<F: Family>(
        context: deterministic::Context,
    ) {
        let hasher = Standard::<Sha256>::new();
        let mut mmr = Merkle::<F, _, Digest>::init(
            context.with_label("init"),
            &hasher,
            test_config(&context),
        )
        .await
        .unwrap();

        let mut batch = mmr.new_batch();
        for i in 0..64 {
            batch = batch.add(&hasher, &test_digest(i));
        }
        let batch = mmr.with_mem(|mem| batch.merkleize(mem, &hasher));
        mmr.apply_batch(&batch).unwrap();
        mmr.sync().await.unwrap();

        let historical_leaves = Location::<F>::new(20);
        let range = Location::<F>::new(5)..Location::<F>::new(15);
        let expected = mmr
            .historical_range_proof(&hasher, historical_leaves, range.clone(), 0)
            .await
            .unwrap();

        let actual = mmr
            .historical_range_proof(&hasher, historical_leaves, range, 0)
            .await
            .unwrap();
        assert_eq!(actual, expected);

        mmr.destroy().await.unwrap();
    }

    #[test_traced]
    fn test_full_historical_proof_after_sync_reads_from_journal_mmr() {
        let executor = deterministic::Runner::default();
        executor.start(full_historical_proof_after_sync_reads_from_journal_inner::<mmr::Family>);
    }

    #[test_traced]
    fn test_full_historical_proof_after_sync_reads_from_journal_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(full_historical_proof_after_sync_reads_from_journal_inner::<mmb::Family>);
    }

    async fn full_historical_proof_after_pruning_inner<F: Family>(context: deterministic::Context) {
        let hasher = Standard::<Sha256>::new();
        let mut mmr = Merkle::<F, _, Digest>::init(
            context.with_label("init"),
            &hasher,
            test_config(&context),
        )
        .await
        .unwrap();

        let mut batch = mmr.new_batch();
        for i in 0..30 {
            batch = batch.add(&hasher, &test_digest(i));
        }
        let batch = mmr.with_mem(|mem| batch.merkleize(mem, &hasher));
        mmr.apply_batch(&batch).unwrap();

        let prune_loc = Location::<F>::new(10);
        mmr.prune(prune_loc).await.unwrap();

        let requested = Location::<F>::new(20);
        let range = prune_loc..requested;
        let proof = mmr
            .historical_range_proof(&hasher, requested, range, 0)
            .await
            .unwrap();
        assert!(proof.leaves > Location::<F>::new(0));

        mmr.destroy().await.unwrap();
    }

    #[test_traced]
    fn test_full_historical_proof_after_pruning_mmr() {
        let executor = deterministic::Runner::default();
        executor.start(full_historical_proof_after_pruning_inner::<mmr::Family>);
    }

    #[test_traced]
    fn test_full_historical_proof_after_pruning_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(full_historical_proof_after_pruning_inner::<mmb::Family>);
    }

    async fn full_historical_proof_edge_cases_inner<F: Family>(context: deterministic::Context) {
        let hasher = Standard::<Sha256>::new();

        // Case 1: Empty structure.
        let mmr = Merkle::<F, _, Digest>::init(
            context.with_label("empty"),
            &hasher,
            test_config(&context),
        )
        .await
        .unwrap();
        let empty_end = Location::<F>::new(0);
        let empty_result = mmr
            .historical_range_proof(&hasher, empty_end, empty_end..empty_end, 0)
            .await;
        assert!(matches!(empty_result, Err(Error::Empty)));
        let oob_result = mmr
            .historical_range_proof(&hasher, empty_end + 1, empty_end..empty_end + 1, 0)
            .await;
        assert!(matches!(
            oob_result,
            Err(Error::RangeOutOfBounds(loc)) if loc == empty_end + 1
        ));
        mmr.destroy().await.unwrap();

        // Case 2: Structure has nodes but is fully pruned.
        let mut mmr = Merkle::<F, _, Digest>::init(
            context.with_label("fully_pruned"),
            &hasher,
            test_config(&context),
        )
        .await
        .unwrap();
        let mut batch = mmr.new_batch();
        for i in 0..20 {
            batch = batch.add(&hasher, &test_digest(i));
        }
        let batch = mmr.with_mem(|mem| batch.merkleize(mem, &hasher));
        mmr.apply_batch(&batch).unwrap();
        let end = mmr.leaves();
        mmr.prune_all().await.unwrap();
        assert!(mmr.bounds().is_empty());
        let pruned_result = mmr
            .historical_range_proof(&hasher, end, end - 1..end, 0)
            .await;
        assert!(matches!(pruned_result, Err(Error::ElementPruned(_))));
        let oob_result = mmr
            .historical_range_proof(&hasher, end + 1, end - 1..end, 0)
            .await;
        assert!(matches!(
            oob_result,
            Err(Error::RangeOutOfBounds(loc)) if loc == end + 1
        ));
        mmr.destroy().await.unwrap();

        // Case 3: All nodes but one (single leaf) are pruned.
        let mut mmr = Merkle::<F, _, Digest>::init(
            context.with_label("single_leaf"),
            &hasher,
            test_config(&context),
        )
        .await
        .unwrap();
        let mut batch = mmr.new_batch();
        for i in 0..11 {
            batch = batch.add(&hasher, &test_digest(i));
        }
        let batch = mmr.with_mem(|mem| batch.merkleize(mem, &hasher));
        mmr.apply_batch(&batch).unwrap();
        let end = mmr.leaves();
        let keep_loc = end - 1;
        mmr.prune(keep_loc).await.unwrap();
        let ok_result = mmr
            .historical_range_proof(&hasher, end, keep_loc..end, 0)
            .await;
        assert!(ok_result.is_ok());
        let pruned_end = keep_loc - 1;
        // make sure this is in a pruned range, considering blob boundaries.
        let start_loc = Location::<F>::new(1);
        let pruned_result = mmr
            .historical_range_proof(&hasher, end, start_loc..pruned_end + 1, 0)
            .await;
        assert!(matches!(pruned_result, Err(Error::ElementPruned(_))));
        let oob_result = mmr
            .historical_range_proof(&hasher, end + 1, keep_loc..end, 0)
            .await;
        assert!(matches!(oob_result, Err(Error::RangeOutOfBounds(_))));
        mmr.destroy().await.unwrap();
    }

    #[test_traced]
    fn test_full_historical_proof_edge_cases_mmr() {
        let executor = deterministic::Runner::default();
        executor.start(full_historical_proof_edge_cases_inner::<mmr::Family>);
    }

    #[test_traced]
    fn test_full_historical_proof_edge_cases_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(full_historical_proof_edge_cases_inner::<mmb::Family>);
    }

    async fn full_historical_proof_out_of_bounds_inner<F: Family>(context: deterministic::Context) {
        let hasher = Standard::<Sha256>::new();
        let mut mmr =
            Merkle::<F, _, Digest>::init(context.with_label("oob"), &hasher, test_config(&context))
                .await
                .unwrap();

        let mut batch = mmr.new_batch();
        for i in 0..8 {
            batch = batch.add(&hasher, &test_digest(i));
        }
        let batch = mmr.with_mem(|mem| batch.merkleize(mem, &hasher));
        mmr.apply_batch(&batch).unwrap();
        let requested = mmr.leaves() + 1;

        let result = mmr
            .historical_range_proof(&hasher, requested, Location::<F>::new(0)..requested, 0)
            .await;
        assert!(matches!(
            result,
            Err(Error::RangeOutOfBounds(loc)) if loc == requested
        ));

        mmr.destroy().await.unwrap();
    }

    #[test_traced]
    fn test_full_historical_proof_out_of_bounds_mmr() {
        let executor = deterministic::Runner::default();
        executor.start(full_historical_proof_out_of_bounds_inner::<mmr::Family>);
    }

    #[test_traced]
    fn test_full_historical_proof_out_of_bounds_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(full_historical_proof_out_of_bounds_inner::<mmb::Family>);
    }

    async fn full_historical_proof_range_validation_inner<F: Family>(
        context: deterministic::Context,
    ) {
        let hasher = Standard::<Sha256>::new();
        let mut mmr = Merkle::<F, _, Digest>::init(
            context.with_label("range_validation"),
            &hasher,
            test_config(&context),
        )
        .await
        .unwrap();

        let mut batch = mmr.new_batch();
        for i in 0..32 {
            batch = batch.add(&hasher, &test_digest(i));
        }
        let batch = mmr.with_mem(|mem| batch.merkleize(mem, &hasher));
        mmr.apply_batch(&batch).unwrap();

        let valid_range = Location::<F>::new(0)..Location::<F>::new(1);

        // Empty range should report Empty.
        let requested = Location::<F>::new(5);
        let empty_range = requested..requested;
        let empty_result = mmr
            .historical_range_proof(&hasher, requested, empty_range, 0)
            .await;
        assert!(matches!(empty_result, Err(Error::Empty)));

        // Requested historical size is out of bounds.
        let leaves_oob = mmr.leaves() + 1;
        let result = mmr
            .historical_range_proof(&hasher, leaves_oob, valid_range.clone(), 0)
            .await;
        assert!(matches!(
            result,
            Err(Error::RangeOutOfBounds(loc)) if loc == leaves_oob
        ));

        // Requested range end is out of bounds for the current structure.
        let end_oob = mmr.leaves() + 1;
        let range_oob = Location::<F>::new(0)..end_oob;
        let result = mmr
            .historical_range_proof(&hasher, requested, range_oob, 0)
            .await;
        assert!(matches!(
            result,
            Err(Error::RangeOutOfBounds(loc)) if loc == end_oob
        ));

        // Requested range end out of bounds for the requested historical size but within structure.
        let range_end_gt_requested = requested + 1;
        let range_oob_at_requested = Location::<F>::new(0)..range_end_gt_requested;
        assert!(range_end_gt_requested <= mmr.leaves());
        let result = mmr
            .historical_range_proof(&hasher, requested, range_oob_at_requested, 0)
            .await;
        assert!(matches!(
            result,
            Err(Error::RangeOutOfBounds(loc)) if loc == range_end_gt_requested
        ));

        // Range location overflow is caught as out-of-bounds (the bounds check
        // fires before the position conversion that would detect overflow).
        let overflow_loc = Location::<F>::new(u64::MAX);
        let overflow_range = Location::<F>::new(0)..overflow_loc;
        let result = mmr
            .historical_range_proof(&hasher, requested, overflow_range, 0)
            .await;
        assert!(matches!(
            result,
            Err(Error::RangeOutOfBounds(loc)) if loc == overflow_loc
        ));

        mmr.destroy().await.unwrap();
    }

    #[test_traced]
    fn test_full_historical_proof_range_validation_mmr() {
        let executor = deterministic::Runner::default();
        executor.start(full_historical_proof_range_validation_inner::<mmr::Family>);
    }

    #[test_traced]
    fn test_full_historical_proof_range_validation_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(full_historical_proof_range_validation_inner::<mmb::Family>);
    }

    async fn full_historical_proof_non_size_prune_excludes_pruned_leaves_inner<F: Family>(
        context: deterministic::Context,
    ) {
        let hasher = Standard::<Sha256>::new();
        let mut mmr = Merkle::<F, _, Digest>::init(
            context.with_label("non_size_prune"),
            &hasher,
            test_config(&context),
        )
        .await
        .unwrap();

        let mut batch = mmr.new_batch();
        for i in 0..16 {
            batch = batch.add(&hasher, &test_digest(i));
        }
        let batch = mmr.with_mem(|mem| batch.merkleize(mem, &hasher));
        mmr.apply_batch(&batch).unwrap();

        let end = mmr.leaves();
        let mut failures = Vec::new();
        for prune_leaf in 1..*end {
            let prune_loc = Location::<F>::new(prune_leaf);
            mmr.prune(prune_loc).await.unwrap();
            for loc_u64 in 0..*end {
                let loc = Location::<F>::new(loc_u64);
                let range_includes_pruned_leaf = loc < prune_loc;
                match mmr.historical_proof(&hasher, end, loc, 0).await {
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
    }

    #[test_traced]
    fn test_full_historical_proof_non_size_prune_excludes_pruned_leaves_mmr() {
        let executor = deterministic::Runner::default();
        executor.start(
            full_historical_proof_non_size_prune_excludes_pruned_leaves_inner::<mmr::Family>,
        );
    }

    #[test_traced]
    fn test_full_historical_proof_non_size_prune_excludes_pruned_leaves_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(
            full_historical_proof_non_size_prune_excludes_pruned_leaves_inner::<mmb::Family>,
        );
    }

    /// Regression: init_sync must recover from a journal left at an invalid size
    /// (e.g., a crash wrote a leaf but not its parent nodes).
    async fn full_init_sync_recovers_from_invalid_journal_size_inner<F: Family>(
        context: deterministic::Context,
    ) {
        let hasher = Standard::<Sha256>::new();

        // Build a structure with 3 leaves, sync, and drop.
        let mut mmr = Merkle::<F, _, Digest>::init(
            context.with_label("init"),
            &hasher,
            test_config(&context),
        )
        .await
        .unwrap();
        let mut batch = mmr.new_batch();
        for i in 0..3 {
            batch = batch.add(&hasher, &test_digest(i));
        }
        let batch = mmr.with_mem(|mem| batch.merkleize(mem, &hasher));
        mmr.apply_batch(&batch).unwrap();
        let valid_size = mmr.size();
        let valid_root = mmr.root(&hasher, 0).unwrap();
        mmr.sync().await.unwrap();
        drop(mmr);

        // Append one extra digest to the journal, simulating a crash that wrote a
        // leaf (for the 4th element) but not its parent nodes. This makes the
        // journal size invalid.
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
        let sync_cfg = SyncConfig::<F, Digest> {
            config: test_config(&context),
            range: non_empty_range!(Location::<F>::new(0), Location::<F>::new(100)),
            pinned_nodes: None,
        };
        let sync_mmr = Merkle::<F, _, Digest>::init_sync(context.with_label("sync"), sync_cfg)
            .await
            .unwrap();

        assert_eq!(sync_mmr.size(), valid_size);
        assert_eq!(sync_mmr.root(&hasher, 0).unwrap(), valid_root);

        sync_mmr.destroy().await.unwrap();
    }

    #[test_traced]
    fn test_init_sync_recovers_from_invalid_journal_size_mmr() {
        let executor = deterministic::Runner::default();
        executor.start(full_init_sync_recovers_from_invalid_journal_size_inner::<mmr::Family>);
    }

    #[test_traced]
    fn test_init_sync_recovers_from_invalid_journal_size_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(full_init_sync_recovers_from_invalid_journal_size_inner::<mmb::Family>);
    }

    async fn full_stale_batch_inner<F: Family>(context: deterministic::Context) {
        let hasher: Standard<Sha256> = Standard::new();
        let mut mmr = Merkle::<F, _, Digest>::init(
            context.clone(),
            &Standard::<Sha256>::new(),
            test_config(&context),
        )
        .await
        .unwrap();

        // Create two batches from the same base.
        let batch_a = mmr.new_batch().add(&hasher, b"leaf-a");
        let batch_a = mmr.with_mem(|mem| batch_a.merkleize(mem, &hasher));
        let batch_b = mmr.new_batch().add(&hasher, b"leaf-b");
        let batch_b = mmr.with_mem(|mem| batch_b.merkleize(mem, &hasher));

        // Apply A -- should succeed.
        mmr.apply_batch(&batch_a).unwrap();

        // Apply B -- should fail (stale).
        let result = mmr.apply_batch(&batch_b);
        assert!(
            matches!(result, Err(Error::StaleBatch { .. })),
            "expected StaleBatch, got {result:?}"
        );

        mmr.destroy().await.unwrap();
    }

    #[test]
    fn test_stale_batch_mmr() {
        let executor = deterministic::Runner::default();
        executor.start(full_stale_batch_inner::<mmr::Family>);
    }

    #[test]
    fn test_stale_batch_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(full_stale_batch_inner::<mmb::Family>);
    }

    /// Regression: `new_batch` must return the append-only full wrapper.
    async fn full_new_batch_returns_append_only_wrapper_inner<F: Family>(
        context: deterministic::Context,
    ) {
        let hasher = Standard::<Sha256>::new();
        let mmr = Merkle::<F, _, Digest>::init(context.clone(), &hasher, test_config(&context))
            .await
            .unwrap();

        let _batch: UnmerkleizedBatch<F, Digest> = mmr.new_batch();

        mmr.destroy().await.unwrap();
    }

    #[test_traced]
    fn test_new_batch_returns_append_only_wrapper_mmr() {
        let executor = deterministic::Runner::default();
        executor.start(full_new_batch_returns_append_only_wrapper_inner::<mmr::Family>);
    }

    #[test_traced]
    fn test_new_batch_returns_append_only_wrapper_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(full_new_batch_returns_append_only_wrapper_inner::<mmb::Family>);
    }

    /// Regression: update_leaf on a synced-out leaf must return ElementPruned, not panic.
    /// Before the fix, `Readable::pruning_boundary` returned the journal's prune boundary
    /// (which could be 0), so the batch accepted the update. During merkleize, get_node
    /// returned None for the synced-out sibling and hit an expect panic.
    async fn full_update_leaf_after_sync_returns_pruned_inner<F: Family>(
        context: deterministic::Context,
    ) {
        let hasher = Standard::<Sha256>::new();
        let mut mmr = Merkle::<F, _, Digest>::init(context.clone(), &hasher, test_config(&context))
            .await
            .unwrap();

        // Add 50 elements and sync (flushes all nodes to journal, prunes mem).
        let mut batch = mmr.new_batch();
        for i in 0..50 {
            batch = batch.add(&hasher, &test_digest(i));
        }
        let batch = mmr.with_mem(|mem| batch.merkleize(mem, &hasher));
        mmr.apply_batch(&batch).unwrap();
        mmr.sync().await.unwrap();

        // Attempt to update leaf 0 which has been synced out of memory.
        // Use the inner batch type directly since the full wrapper
        // intentionally hides update_leaf.
        let batch = mmr.to_batch().new_batch();
        let result = batch.update_leaf(&hasher, Location::<F>::new(0), b"updated");
        assert!(matches!(result, Err(Error::ElementPruned(_))));

        mmr.destroy().await.unwrap();
    }

    #[test_traced]
    fn test_update_leaf_after_sync_returns_pruned_mmr() {
        let executor = deterministic::Runner::default();
        executor.start(full_update_leaf_after_sync_returns_pruned_inner::<mmr::Family>);
    }

    #[test_traced]
    fn test_update_leaf_after_sync_returns_pruned_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(full_update_leaf_after_sync_returns_pruned_inner::<mmb::Family>);
    }
}
