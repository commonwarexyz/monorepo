//! A Merkle-family structure backed by a fixed-item-length journal.
//!
//! A [crate::journal] is used to store all unpruned nodes, and a [crate::metadata] store is
//! used to preserve digests required for root and proof generation that would have otherwise been
//! pruned.
//!
//! This module is generic over the [`MerkleFamily`] marker (MMR, MMB, etc.) and the in-memory
//! representation ([`CleanMem`] / [`DirtyMem`]).

use crate::{
    journal::{
        contiguous::{
            fixed::{Config as JConfig, Journal},
            Reader,
        },
        Error as JError,
    },
    merkle::{
        hasher::Hasher,
        mem::{CleanMem, Config as MemConfig, DirtyMem},
        storage::Storage,
        Error, Location, MerkleFamily, Position,
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

/// Fields of [`Clean`] protected by an [`RwLock`] for interior mutability.
struct CleanInner<F: MerkleFamily, D: Digest, C: CleanMem<F, D>> {
    mem: C,
    pruned_to_pos: Position<F>,
    _digest: std::marker::PhantomData<D>,
}

/// Fields of [`Dirty`] protected by an [`RwLock`] for interior mutability.
struct DirtyInner<F: MerkleFamily, D: Digest, C: CleanMem<F, D>> {
    mem: C::Dirty,
    pruned_to_pos: Position<F>,
    merkleized_size: u64,
    _digest: std::marker::PhantomData<D>,
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
/// - **Prune and Rewind**: existing data > range end -> prune and rewind to range end
pub struct SyncConfig<F: MerkleFamily, D: Digest> {
    /// Base configuration (journal, metadata, etc.)
    pub config: Config,

    /// Sync range - nodes outside this range are pruned/rewound.
    pub range: std::ops::Range<Position<F>>,

    /// The pinned nodes the structure needs at the pruning boundary (range start), in the order
    /// specified by `MerkleFamily::nodes_to_pin`. If `None`, the pinned nodes are expected to
    /// already be in the structure's metadata/journal.
    pub pinned_nodes: Option<Vec<D>>,
}

/// Prefix used for nodes in the metadata prefixed U8 key.
const NODE_PREFIX: u8 = 0;

/// Prefix used for the key storing the prune_to_pos position in the metadata.
const PRUNE_TO_POS_PREFIX: u8 = 1;

/// Compute the positions that must be pinned when pruning to `prune_pos` in a structure of
/// total `size`, returning them as `Position<F>` values.
fn nodes_to_pin_positions<F: MerkleFamily>(
    size: Position<F>,
    prune_pos: Position<F>,
) -> Vec<Position<F>> {
    F::nodes_to_pin(*size, *prune_pos)
        .into_iter()
        .map(Position::<F>::new)
        .collect()
}

/// Attempt to get a node from the metadata, with fallback to journal lookup if it fails.
/// Assumes the node should exist in at least one of these sources and returns a `MissingNode`
/// error otherwise.
pub(crate) async fn get_from_metadata_or_journal<F, E, D>(
    metadata: &Metadata<E, U64, Vec<u8>>,
    journal: &Journal<E, D>,
    pos: Position<F>,
) -> Result<D, Error<F>>
where
    F: MerkleFamily,
    E: RStorage + Clock + Metrics,
    D: Digest,
{
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

/// Collect pinned nodes for a given pruning boundary.
pub(crate) async fn collect_extra_pinned_nodes<F, E, D>(
    metadata: &Metadata<E, U64, Vec<u8>>,
    journal: &Journal<E, D>,
    size: Position<F>,
    prune_pos: Position<F>,
) -> Result<BTreeMap<Position<F>, D>, Error<F>>
where
    F: MerkleFamily,
    E: RStorage + Clock + Metrics,
    D: Digest,
{
    let mut pinned_nodes = BTreeMap::new();
    for pos in nodes_to_pin_positions::<F>(size, prune_pos) {
        let digest = get_from_metadata_or_journal(metadata, journal, pos).await?;
        pinned_nodes.insert(pos, digest);
    }
    Ok(pinned_nodes)
}

// ---------------------------------------------------------------------------
// Clean (merkleized) journaled Merkle structure
// ---------------------------------------------------------------------------

/// A clean (fully merkleized) journaled Merkle structure.
pub struct Clean<
    F: MerkleFamily,
    E: RStorage + Clock + Metrics,
    D: Digest,
    C: CleanMem<F, D>,
> {
    inner: RwLock<CleanInner<F, D, C>>,
    journal: Journal<E, D>,
    metadata: Metadata<E, U64, Vec<u8>>,
    sync_lock: AsyncMutex<()>,
    pool: Option<ThreadPool>,
}

impl<F, E, D, C> Clean<F, E, D, C>
where
    F: MerkleFamily,
    E: RStorage + Clock + Metrics,
    D: Digest,
    C: CleanMem<F, D>,
{
    /// Return the total number of nodes, irrespective of any pruning.
    pub fn size(&self) -> Position<F> {
        self.inner.read().mem.size()
    }

    /// Return the total number of leaves.
    pub fn leaves(&self) -> Location<F> {
        self.inner.read().mem.leaves()
    }

    /// Returns [start, end) where `start` and `end - 1` are the positions of the oldest and newest
    /// retained nodes respectively.
    pub fn bounds(&self) -> std::ops::Range<Position<F>> {
        let inner = self.inner.read();
        inner.pruned_to_pos..inner.mem.size()
    }

    /// Initialize a Merkle structure for synchronization, reusing existing data if possible.
    ///
    /// Handles sync scenarios based on existing journal data vs. the given sync range:
    ///
    /// 1. **Fresh Start**: existing_size <= range.start
    ///    - Deletes existing data (if any)
    ///    - Creates new journal with pruning boundary and size at `range.start`
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
        hasher: &mut impl Hasher<F, Digest = D>,
    ) -> Result<Self, Error<F>> {
        let journal_cfg = JConfig {
            partition: cfg.config.journal_partition.clone(),
            items_per_blob: cfg.config.items_per_blob,
            write_buffer: cfg.config.write_buffer,
            page_cache: cfg.config.page_cache.clone(),
        };

        // Open the journal, handling existing data vs sync range.
        assert!(!cfg.range.is_empty(), "range must not be empty");
        let journal: Journal<E, D> =
            Journal::init(context.with_label("merkle_journal"), journal_cfg).await?;
        let size = journal.size().await;

        if size > *cfg.range.end {
            return Err(Error::Journal(
                crate::journal::Error::ItemOutOfRange(size),
            ));
        }
        if size <= *cfg.range.start && *cfg.range.start != 0 {
            journal.clear_to_size(*cfg.range.start).await?;
        }

        let journal_size = Position::<F>::new(journal.size().await);

        // Open the metadata.
        let metadata_cfg = MConfig {
            partition: cfg.config.metadata_partition,
            codec_config: ((0..).into(), ()),
        };
        let mut metadata =
            Metadata::init(context.with_label("merkle_metadata"), metadata_cfg).await?;

        // Write the pruning boundary.
        let pruning_boundary_key = U64::new(PRUNE_TO_POS_PREFIX, 0);
        metadata.put(
            pruning_boundary_key,
            (*cfg.range.start).to_be_bytes().into(),
        );

        // Write the required pinned nodes to metadata.
        if let Some(pinned_nodes) = cfg.pinned_nodes {
            // Use caller-provided pinned nodes.
            let nodes_to_pin_persisted = nodes_to_pin_positions::<F>(journal_size, cfg.range.start);
            for (pos, digest) in nodes_to_pin_persisted.into_iter().zip(pinned_nodes.iter()) {
                metadata.put(U64::new(NODE_PREFIX, *pos), digest.to_vec());
            }
        }

        // Create the in-memory structure with the pinned nodes required for its size. This must be
        // performed *before* pruning the journal to range.start to ensure all pinned nodes are
        // present.
        let nodes_to_pin_mem = nodes_to_pin_positions::<F>(journal_size, journal_size);
        let mut mem_pinned_nodes = Vec::new();
        for pos in nodes_to_pin_mem {
            let digest = get_from_metadata_or_journal(&metadata, &journal, pos).await?;
            mem_pinned_nodes.push(digest);
        }
        let mut mem = C::init(
            MemConfig {
                nodes: vec![],
                pruned_to_pos: journal_size,
                pinned_nodes: mem_pinned_nodes,
            },
            hasher,
        )?;

        // Add the additional pinned nodes required for the pruning boundary, if applicable.
        // This must also be done before pruning.
        if cfg.range.start < journal_size {
            let extra = collect_extra_pinned_nodes(
                &metadata,
                &journal,
                journal_size,
                cfg.range.start,
            )
            .await?;
            mem.add_pinned_nodes(extra);
        }

        // Sync metadata before pruning so pinned nodes are persisted for crash recovery.
        metadata.sync().await.map_err(Error::Metadata)?;

        // Prune the journal to range.start.
        journal.prune(*cfg.range.start).await?;

        Ok(Self {
            inner: RwLock::new(CleanInner {
                mem,
                pruned_to_pos: cfg.range.start,
                _digest: std::marker::PhantomData,
            }),
            journal,
            metadata,
            sync_lock: AsyncMutex::new(()),
            pool: cfg.config.thread_pool,
        })
    }

    /// Initialize a new journaled Merkle instance.
    pub async fn init(
        context: E,
        hasher: &mut impl Hasher<F, Digest = D>,
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
            let mem = C::init(
                MemConfig {
                    nodes: vec![],
                    pruned_to_pos: Position::new(0),
                    pinned_nodes: vec![],
                },
                hasher,
            )?;
            return Ok(Self {
                inner: RwLock::new(CleanInner {
                    mem,
                    pruned_to_pos: Position::new(0),
                    _digest: std::marker::PhantomData,
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
        let key: U64 = U64::new(PRUNE_TO_POS_PREFIX, 0);
        let metadata_prune_pos = metadata.get(&key).map_or(0, |bytes| {
            u64::from_be_bytes(
                bytes
                    .as_slice()
                    .try_into()
                    .expect("metadata prune position is not 8 bytes"),
            )
        });
        let journal_bounds_start = journal.reader().await.bounds().start;
        if metadata_prune_pos > journal_bounds_start {
            // Metadata is ahead of journal (crashed before completing journal prune).
            // Prune the journal to match metadata.
            journal.prune(metadata_prune_pos).await?;
            if journal.reader().await.bounds().start != journal_bounds_start {
                // This should only happen in the event of some failure during the last attempt to
                // prune the journal.
                warn!(
                    journal_bounds_start,
                    metadata_prune_pos, "journal pruned to match metadata"
                );
            }
        } else if metadata_prune_pos < journal_bounds_start {
            // Metadata is stale (e.g., missing/corrupted while journal has valid state).
            // Use the journal's state as authoritative.
            warn!(
                metadata_prune_pos,
                journal_bounds_start, "metadata stale, using journal pruning boundary"
            );
        }

        // Use the more restrictive (higher) pruning boundary between metadata and journal.
        // This handles both cases: metadata ahead (crash during prune) and metadata stale.
        let effective_prune_pos = std::cmp::max(metadata_prune_pos, journal_bounds_start);

        let last_valid_size = Position::<F>::new(F::to_nearest_size(*journal_size));
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

        // Initialize the in-memory structure in the "prune_all" state.
        let mut pinned_nodes = Vec::new();
        for pos in nodes_to_pin_positions::<F>(journal_size, journal_size) {
            let digest =
                get_from_metadata_or_journal(&metadata, &journal, pos).await?;
            pinned_nodes.push(digest);
        }
        let mut mem = C::init(
            MemConfig {
                nodes: vec![],
                pruned_to_pos: journal_size,
                pinned_nodes,
            },
            hasher,
        )?;
        let prune_pos = Position::new(effective_prune_pos);
        let extra = collect_extra_pinned_nodes(&metadata, &journal, journal_size, prune_pos)
            .await?;
        mem.add_pinned_nodes(extra);

        if let Some(leaf) = orphaned_leaf {
            // Recover the orphaned leaf and any missing parents.
            let pos = mem.size();
            warn!(?pos, "recovering orphaned leaf");
            let mut dirty_mem = mem.into_dirty();
            dirty_mem.add_leaf_digest(leaf);
            mem = dirty_mem.merkleize(hasher, None);
            assert_eq!(pos, journal_size);

            // Inline sync: flush recovered nodes to journal.
            for p in journal.size().await..*mem.size() {
                let p = Position::<F>::new(p);
                let node = *mem.get_node_unchecked(p);
                journal.append(node).await?;
            }
            journal.sync().await?;
            assert_eq!(mem.size(), journal.size().await);

            // Prune mem and reinstate pinned nodes.
            let mut pn = BTreeMap::new();
            for p in nodes_to_pin_positions::<F>(mem.size(), prune_pos) {
                let d = mem.get_node_unchecked(p);
                pn.insert(p, *d);
            }
            mem.prune_all();
            mem.add_pinned_nodes(pn);
        }

        Ok(Self {
            inner: RwLock::new(CleanInner {
                mem,
                pruned_to_pos: prune_pos,
                _digest: std::marker::PhantomData,
            }),
            journal,
            metadata,
            sync_lock: AsyncMutex::new(()),
            pool: cfg.thread_pool,
        })
    }

    /// Compute and add required nodes for the given pruning point to the metadata, and write it to
    /// disk. Return the computed set of required nodes.
    async fn update_metadata(
        &mut self,
        prune_to_pos: Position<F>,
    ) -> Result<BTreeMap<Position<F>, D>, Error<F>> {
        let inner = self.inner.get_mut();
        assert!(prune_to_pos >= inner.pruned_to_pos);

        let size = inner.mem.size();
        let mut pinned_nodes = BTreeMap::new();
        for pos in nodes_to_pin_positions::<F>(size, prune_to_pos) {
            let digest = self.get_node(pos).await?.expect(
                "pinned node should exist if prune_to_pos is no less than self.pruned_to_pos",
            );
            self.metadata
                .put(U64::new(NODE_PREFIX, *pos), digest.to_vec());
            pinned_nodes.insert(pos, digest);
        }

        let key: U64 = U64::new(PRUNE_TO_POS_PREFIX, 0);
        self.metadata.put(key, (*prune_to_pos).to_be_bytes().into());

        self.metadata.sync().await.map_err(Error::Metadata)?;

        Ok(pinned_nodes)
    }

    /// Return the node digest at the given position, if available.
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

        // Snapshot nodes in the in-memory structure that are missing from the journal, along with
        // the pinned node set for the current pruning boundary.
        let (size, missing_nodes, pinned_nodes) = {
            let inner = self.inner.read();
            let size = inner.mem.size();

            assert!(
                journal_size <= size,
                "journal size should never exceed in-memory size"
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
            // by pruning the in-memory structure.
            let mut pinned_nodes = BTreeMap::new();
            for pos in nodes_to_pin_positions::<F>(size, inner.pruned_to_pos) {
                let digest = inner.mem.get_node_unchecked(pos);
                pinned_nodes.insert(pos, *digest);
            }

            (size, missing_nodes, pinned_nodes)
        };

        // Append missing nodes to the journal without holding the read lock.
        for node in missing_nodes {
            self.journal.append(node).await?;
        }

        // Sync the journal while still holding the sync_lock to ensure durability before returning.
        self.journal.sync().await?;

        // Now that the missing nodes are in the journal, it's safe to prune them from the
        // in-memory structure.
        {
            let mut inner = self.inner.write();
            inner.mem.prune_to_pos(size)?;
            inner.mem.add_pinned_nodes(pinned_nodes);
        }

        Ok(())
    }

    /// Prune all nodes up to but not including the given position and update the pinned nodes.
    ///
    /// This implementation ensures that no failure can leave the structure in an unrecoverable
    /// state, requiring it sync to write any potential unmerkleized updates.
    pub async fn prune_to_pos(&mut self, pos: Position<F>) -> Result<(), Error<F>> {
        {
            let inner = self.inner.get_mut();
            assert!(pos <= inner.mem.size());
            if pos <= inner.pruned_to_pos {
                return Ok(());
            }
        }

        // Flush items cached in the in-memory structure to disk to ensure the current state is
        // recoverable.
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

    /// Return the root digest.
    pub fn root(&self) -> D {
        *self.inner.read().mem.root()
    }

    /// Prune as many nodes as possible, leaving behind at most items_per_blob nodes in the current
    /// blob.
    pub async fn prune_all(&mut self) -> Result<(), Error<F>> {
        let size = self.inner.get_mut().mem.size();
        if size != 0 {
            self.prune_to_pos(size).await?;
        }
        Ok(())
    }

    /// Close and permanently remove any disk resources.
    pub async fn destroy(self) -> Result<(), Error<F>> {
        self.journal.destroy().await?;
        self.metadata.destroy().await?;

        Ok(())
    }

    /// Convert this structure into its dirty counterpart for batched updates.
    pub fn into_dirty(self) -> Dirty<F, E, D, C> {
        self.into()
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

        // Write the nodes cached in the in-memory structure to the journal, aborting after
        // write_count nodes have been written.
        let mut written_count = 0usize;
        for i in *journal_size..*inner.mem.size() {
            let node = *inner.mem.get_node_unchecked(Position::new(i));
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
    pub fn get_pinned_nodes(&self) -> std::collections::BTreeMap<Position<F>, D> {
        self.inner.read().mem.pinned_nodes()
    }

    #[cfg(test)]
    pub async fn simulate_pruning_failure(
        mut self,
        prune_to_pos: Position<F>,
    ) -> Result<(), Error<F>> {
        assert!(prune_to_pos <= self.inner.get_mut().mem.size());

        // Flush items cached in the in-memory structure to disk to ensure the current state is
        // recoverable.
        self.sync().await?;

        // Update metadata to reflect the desired pruning boundary, allowing for recovery in the
        // event of a pruning failure.
        self.update_metadata(prune_to_pos).await?;

        // Don't actually prune the journal to simulate failure
        Ok(())
    }
}

impl<F, E, D, C> From<Clean<F, E, D, C>> for Dirty<F, E, D, C>
where
    F: MerkleFamily,
    E: RStorage + Clock + Metrics,
    D: Digest,
    C: CleanMem<F, D>,
{
    fn from(clean: Clean<F, E, D, C>) -> Self {
        let inner = clean.inner.into_inner();
        let size = *inner.mem.size();
        Self {
            inner: RwLock::new(DirtyInner {
                mem: inner.mem.into_dirty(),
                pruned_to_pos: inner.pruned_to_pos,
                merkleized_size: size,
                _digest: std::marker::PhantomData,
            }),
            journal: clean.journal,
            metadata: clean.metadata,
            sync_lock: clean.sync_lock,
            pool: clean.pool,
        }
    }
}

// ---------------------------------------------------------------------------
// Dirty (unmerkleized) journaled Merkle structure
// ---------------------------------------------------------------------------

/// A dirty (unmerkleized) journaled Merkle structure.
pub struct Dirty<
    F: MerkleFamily,
    E: RStorage + Clock + Metrics,
    D: Digest,
    C: CleanMem<F, D>,
> {
    inner: RwLock<DirtyInner<F, D, C>>,
    journal: Journal<E, D>,
    metadata: Metadata<E, U64, Vec<u8>>,
    sync_lock: AsyncMutex<()>,
    pool: Option<ThreadPool>,
}

impl<F, E, D, C> Dirty<F, E, D, C>
where
    F: MerkleFamily,
    E: RStorage + Clock + Metrics,
    D: Digest,
    C: CleanMem<F, D>,
{
    /// Return the total number of nodes, irrespective of any pruning.
    pub fn size(&self) -> Position<F> {
        self.inner.read().mem.size()
    }

    /// Return the total number of leaves.
    pub fn leaves(&self) -> Location<F> {
        self.inner.read().mem.leaves()
    }

    /// Returns [start, end) where `start` and `end - 1` are the positions of the oldest and newest
    /// retained nodes respectively.
    pub fn bounds(&self) -> std::ops::Range<Position<F>> {
        let inner = self.inner.read();
        inner.pruned_to_pos..inner.mem.size()
    }

    /// Return the largest fully-merkleized historical size in leaves.
    pub fn merkleized_leaves(&self) -> Location<F> {
        let size = Position::<F>::new(self.inner.read().merkleized_size);
        Location::try_from(size).expect("merkleized size should be valid")
    }

    /// Return the raw merkleized size as a position.
    pub fn merkleized_size(&self) -> Position<F> {
        Position::new(self.inner.read().merkleized_size)
    }

    /// Return the pruned-to position.
    pub fn pruned_to_pos(&self) -> Position<F> {
        self.inner.read().pruned_to_pos
    }

    /// Return the merkleized size and the in-memory bounds while holding a single read lock.
    pub fn merkleized_size_and_mem_bounds(&self) -> (Position<F>, std::ops::Range<Position<F>>) {
        let inner = self.inner.read();
        let merkleized_size = Position::new(inner.merkleized_size);
        let mem_bounds = inner.mem.bounds();
        (merkleized_size, mem_bounds)
    }

    /// Read a node from the in-memory structure without bounds checking.
    pub fn get_node_in_mem_unchecked(&self, pos: Position<F>) -> D {
        *self.inner.read().mem.get_node_unchecked(pos)
    }

    /// Retrieve a node from metadata or journal.
    pub async fn get_from_metadata_or_journal(
        &self,
        pos: Position<F>,
    ) -> Result<D, Error<F>> {
        get_from_metadata_or_journal(&self.metadata, &self.journal, pos).await
    }

    /// Merkleize the structure and compute the root digest.
    pub fn merkleize(self, h: &mut impl Hasher<F, Digest = D>) -> Clean<F, E, D, C> {
        let inner = self.inner.into_inner();
        Clean {
            inner: RwLock::new(CleanInner {
                mem: inner.mem.merkleize(h, self.pool.clone()),
                pruned_to_pos: inner.pruned_to_pos,
                _digest: std::marker::PhantomData,
            }),
            journal: self.journal,
            metadata: self.metadata,
            sync_lock: self.sync_lock,
            pool: self.pool,
        }
    }

    /// Add an element and return its position.
    ///
    /// # Warnings
    ///
    /// - Added nodes are not guaranteed to be durable until the structure is merkleized and a
    ///   `sync` call succeeds.
    /// - Memory usage grows by O(log2(n)) with each node added until data is flushed to disk by
    ///   `sync`.
    pub fn add(
        &self,
        h: &mut impl Hasher<F, Digest = D>,
        element: &[u8],
    ) -> Result<Position<F>, Error<F>> {
        Ok(self.inner.write().mem.add(h, element))
    }

    /// Pop elements while staying in Dirty state. No root recomputation occurs until merkleize.
    pub async fn pop(&mut self, mut leaves_to_pop: usize) -> Result<(), Error<F>> {
        let new_size = {
            let inner = self.inner.get_mut();

            // First pop as many leaves as possible from the in-memory structure.
            while leaves_to_pop > 0 {
                match inner.mem.pop() {
                    Ok(_) => leaves_to_pop -= 1,
                    Err(Error::ElementPruned(_)) | Err(Error::Empty) => break,
                    Err(err) => return Err(err), // propagate unexpected errors
                }
            }
            if leaves_to_pop == 0 {
                inner.merkleized_size = std::cmp::min(inner.merkleized_size, *inner.mem.size());
                return Ok(());
            }

            // Compute the rewind size for the remaining leaves to pop.
            let destination_leaf = match inner.mem.leaves().checked_sub(leaves_to_pop as u64) {
                Some(destination_leaf) => destination_leaf,
                None => {
                    let pruned_to_pos = inner.pruned_to_pos;
                    inner.merkleized_size = std::cmp::min(inner.merkleized_size, *inner.mem.size());
                    return Err(if pruned_to_pos == 0 {
                        Error::Empty
                    } else {
                        Error::ElementPruned(pruned_to_pos - 1)
                    });
                }
            };
            let new_size =
                Position::try_from(destination_leaf).expect("valid leaf should convert to size");

            if new_size < inner.pruned_to_pos {
                inner.merkleized_size = std::cmp::min(inner.merkleized_size, *inner.mem.size());
                return Err(Error::ElementPruned(new_size));
            }
            new_size
        };

        self.journal.rewind(*new_size).await?;
        self.journal.sync().await?;

        let mut pinned_nodes = Vec::new();
        for pos in nodes_to_pin_positions::<F>(new_size, new_size) {
            let digest =
                get_from_metadata_or_journal(&self.metadata, &self.journal, pos).await?;
            pinned_nodes.push(digest);
        }

        let inner = self.inner.get_mut();
        inner.mem = <C::Dirty>::from_components(vec![], new_size, pinned_nodes);
        let extra = collect_extra_pinned_nodes(
            &self.metadata,
            &self.journal,
            new_size,
            inner.pruned_to_pos,
        )
        .await?;
        inner.mem.add_pinned_nodes(extra);
        inner.merkleized_size = std::cmp::min(inner.merkleized_size, *new_size);

        Ok(())
    }

    #[cfg(any(test, feature = "fuzzing"))]
    /// Sync elements to disk until `write_limit` elements have been written, then abort to simulate
    /// a partial write for testing failure scenarios.
    pub async fn simulate_partial_sync(
        self,
        hasher: &mut impl Hasher<F, Digest = D>,
        write_limit: usize,
    ) -> Result<(), Error<F>> {
        if write_limit == 0 {
            return Ok(());
        }

        // Snapshot up to `write_limit` pending nodes while holding the read lock, then release
        // it before performing async journal writes.
        let clean = self.merkleize(hasher);
        let journal_size = clean.journal.size().await;
        let pending_nodes = {
            let inner = clean.inner.read();
            let mut pending_nodes = Vec::with_capacity(write_limit);
            for i in journal_size..*inner.mem.size() {
                if pending_nodes.len() >= write_limit {
                    break;
                }
                pending_nodes.push(*inner.mem.get_node_unchecked(Position::new(i)));
            }
            pending_nodes
        };

        // Write the cached pending nodes to the journal.
        for node in pending_nodes {
            clean.journal.append(node).await?;
        }
        clean.journal.sync().await?;

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Storage trait impls (generic over MerkleFamily)
// ---------------------------------------------------------------------------

impl<F, E, D, C> Storage<F, D> for Clean<F, E, D, C>
where
    F: MerkleFamily,
    E: RStorage + Clock + Metrics + Sync,
    D: Digest,
    C: CleanMem<F, D>,
{
    async fn size(&self) -> Position<F> {
        self.size()
    }

    async fn get_node(&self, position: Position<F>) -> Result<Option<D>, Error<F>> {
        self.get_node(position).await
    }
}

impl<F, E, D, C> Storage<F, D> for Dirty<F, E, D, C>
where
    F: MerkleFamily,
    E: RStorage + Clock + Metrics + Sync,
    D: Digest,
    C: CleanMem<F, D>,
{
    async fn size(&self) -> Position<F> {
        self.size()
    }

    async fn get_node(&self, position: Position<F>) -> Result<Option<D>, Error<F>> {
        Self::get_node(self, position).await
    }
}

// ---------------------------------------------------------------------------
// Dirty: get_node with merkleization boundary + proof validation
// ---------------------------------------------------------------------------

impl<F, E, D, C> Dirty<F, E, D, C>
where
    F: MerkleFamily,
    E: RStorage + Clock + Metrics,
    D: Digest,
    C: CleanMem<F, D>,
{
    /// Return the node digest at `position`, respecting the merkleization boundary.
    ///
    /// Nodes at or beyond the merkleized frontier return `None`. For nodes within the merkleized
    /// region, the in-memory cache is checked first, then the metadata and journal.
    pub async fn get_node(&self, position: Position<F>) -> Result<Option<D>, Error<F>> {
        let (merkleized_size, mem_bounds) = self.merkleized_size_and_mem_bounds();

        if position >= merkleized_size {
            return Ok(None);
        }

        if position >= mem_bounds.start && position < mem_bounds.end {
            return Ok(Some(self.get_node_in_mem_unchecked(position)));
        }

        match self.get_from_metadata_or_journal(position).await {
            Ok(digest) => Ok(Some(digest)),
            Err(Error::MissingNode(_)) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Validate parameters for a historical range proof on a dirty (unmerkleized) structure.
    ///
    /// Checks bounds, pruning, emptiness, and merkleization status. Returns `Ok(())` if valid.
    pub fn validate_dirty_historical_range_proof(
        &self,
        leaves: Location<F>,
        range: &std::ops::Range<Location<F>>,
    ) -> Result<(), Error<F>> {
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
        if requested_size > merkleized_size {
            return Err(Error::Unmerkleized);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Clean: proof validation
// ---------------------------------------------------------------------------

impl<F, E, D, C> Clean<F, E, D, C>
where
    F: MerkleFamily,
    E: RStorage + Clock + Metrics,
    D: Digest,
    C: CleanMem<F, D>,
{
    /// Validate `leaves` for a historical range proof on a clean (merkleized) structure.
    ///
    /// Returns `Ok(())` if `leaves` does not exceed the structure's current leaf count.
    pub fn validate_historical_leaves(&self, leaves: Location<F>) -> Result<(), Error<F>> {
        if leaves > self.leaves() {
            return Err(Error::RangeOutOfBounds(leaves));
        }
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::merkle::{hasher::Hasher as MHasher, mem::CleanMem};
    use commonware_cryptography::{sha256, Hasher as _, Sha256};
    use commonware_runtime::{
        buffer::paged::CacheRef, BufferPooler, Clock, Metrics, Storage as RStorage,
    };
    use commonware_utils::{NZUsize, NZU16, NZU64};
    use std::num::{NonZeroU16, NonZeroUsize};

    pub(crate) fn test_digest(v: usize) -> sha256::Digest {
        Sha256::hash(&v.to_be_bytes())
    }

    const PAGE_SIZE: NonZeroU16 = NZU16!(111);
    const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(5);

    pub(crate) fn test_config(pooler: &impl BufferPooler) -> Config {
        Config {
            journal_partition: "journal-partition".into(),
            metadata_partition: "metadata-partition".into(),
            items_per_blob: NZU64!(7),
            write_buffer: NZUsize!(1024),
            thread_pool: None,
            page_cache: CacheRef::from_pooler(pooler, PAGE_SIZE, PAGE_CACHE_SIZE),
        }
    }

    /// Test `init_sync` when there is no persisted data.
    pub(crate) async fn test_init_sync_empty<F, E, C>(
        context: E,
        hasher: &mut impl MHasher<F, Digest = sha256::Digest>,
    ) where
        F: MerkleFamily + std::fmt::Debug,
        E: RStorage + Clock + Metrics + BufferPooler,
        C: CleanMem<F, sha256::Digest>,
    {
        let sync_cfg = SyncConfig::<F, sha256::Digest> {
            config: test_config(&context),
            range: Position::new(0)..Position::new(100),
            pinned_nodes: None,
        };

        let sync_merkle =
            Clean::<F, E, sha256::Digest, C>::init_sync(context.clone(), sync_cfg, hasher)
                .await
                .unwrap();

        assert_eq!(sync_merkle.size(), 0);
        let bounds = sync_merkle.bounds();
        assert_eq!(bounds.start, 0);
        assert!(bounds.is_empty());

        let new_element = test_digest(999);
        let sync_merkle = sync_merkle.into_dirty();
        sync_merkle.add(hasher, &new_element).unwrap();
        let sync_merkle = sync_merkle.merkleize(hasher);

        let _root = sync_merkle.root();

        sync_merkle.destroy().await.unwrap();
    }

    /// Test `init_sync` where persisted nodes match the sync boundaries exactly.
    pub(crate) async fn test_init_sync_nonempty_exact_match<F, E, C>(
        context: E,
        hasher: &mut impl MHasher<F, Digest = sha256::Digest>,
    ) where
        F: MerkleFamily + std::fmt::Debug,
        E: RStorage + Clock + Metrics + BufferPooler,
        C: CleanMem<F, sha256::Digest>,
    {
        let merkle =
            Clean::<F, E, sha256::Digest, C>::init(context.with_label("init"), hasher, test_config(&context))
                .await
                .unwrap();
        let merkle = merkle.into_dirty();
        for i in 0..50 {
            merkle.add(hasher, &test_digest(i)).unwrap();
        }
        let merkle = merkle.merkleize(hasher);
        merkle.sync().await.unwrap();
        let original_size = merkle.size();
        let original_leaves = merkle.leaves();
        let original_root = merkle.root();

        let lower_bound_pos = merkle.bounds().start;
        let upper_bound_pos = merkle.size();
        let mut expected_nodes = std::collections::BTreeMap::new();
        for i in *lower_bound_pos..*upper_bound_pos {
            expected_nodes.insert(
                Position::new(i),
                merkle.get_node(Position::new(i)).await.unwrap().unwrap(),
            );
        }
        let sync_cfg = SyncConfig::<F, sha256::Digest> {
            config: test_config(&context),
            range: lower_bound_pos..upper_bound_pos,
            pinned_nodes: None,
        };

        merkle.sync().await.unwrap();
        drop(merkle);

        let sync_merkle =
            Clean::<F, E, sha256::Digest, C>::init_sync(context.with_label("sync"), sync_cfg, hasher)
                .await
                .unwrap();

        assert_eq!(sync_merkle.size(), original_size);
        assert_eq!(sync_merkle.leaves(), original_leaves);
        let bounds = sync_merkle.bounds();
        assert_eq!(bounds.start, lower_bound_pos);
        assert!(!bounds.is_empty());
        assert_eq!(sync_merkle.root(), original_root);
        for pos in *lower_bound_pos..*upper_bound_pos {
            let pos = Position::new(pos);
            assert_eq!(
                sync_merkle.get_node(pos).await.unwrap(),
                expected_nodes.get(&pos).cloned()
            );
        }

        sync_merkle.destroy().await.unwrap();
    }

    /// Test `init_sync` where persisted data partially overlaps with the sync boundaries.
    pub(crate) async fn test_init_sync_partial_overlap<F, E, C>(
        context: E,
        hasher: &mut impl MHasher<F, Digest = sha256::Digest>,
    ) where
        F: MerkleFamily + std::fmt::Debug,
        E: RStorage + Clock + Metrics + BufferPooler,
        C: CleanMem<F, sha256::Digest>,
    {
        let merkle =
            Clean::<F, E, sha256::Digest, C>::init(context.with_label("init"), hasher, test_config(&context))
                .await
                .unwrap();
        let merkle = merkle.into_dirty();
        for i in 0..30 {
            merkle.add(hasher, &test_digest(i)).unwrap();
        }
        let mut merkle = merkle.merkleize(hasher);
        merkle.sync().await.unwrap();
        merkle.prune_to_pos(Position::new(10)).await.unwrap();

        let original_size = merkle.size();
        let original_root = merkle.root();
        let original_pruned_to = merkle.bounds().start;

        let lower_bound_pos = original_pruned_to;
        let upper_bound_pos = original_size + 11;

        let mut expected_nodes = std::collections::BTreeMap::new();
        for pos in *lower_bound_pos..*original_size {
            let pos = Position::new(pos);
            expected_nodes.insert(pos, merkle.get_node(pos).await.unwrap().unwrap());
        }

        let sync_cfg = SyncConfig::<F, sha256::Digest> {
            config: test_config(&context),
            range: lower_bound_pos..upper_bound_pos,
            pinned_nodes: None,
        };

        merkle.sync().await.unwrap();
        drop(merkle);

        let sync_merkle =
            Clean::<F, E, sha256::Digest, C>::init_sync(context.with_label("sync"), sync_cfg, hasher)
                .await
                .unwrap();

        assert_eq!(sync_merkle.size(), original_size);
        let bounds = sync_merkle.bounds();
        assert_eq!(bounds.start, lower_bound_pos);
        assert!(!bounds.is_empty());
        assert_eq!(sync_merkle.root(), original_root);

        for pos in *lower_bound_pos..*original_size {
            let pos = Position::new(pos);
            assert_eq!(
                sync_merkle.get_node(pos).await.unwrap(),
                expected_nodes.get(&pos).cloned()
            );
        }

        sync_merkle.destroy().await.unwrap();
    }

    /// Regression test: init() handles stale metadata (lower pruning boundary than journal).
    pub(crate) async fn test_init_stale_metadata_returns_error<F, E, C>(
        context: E,
        hasher: &mut impl MHasher<F, Digest = sha256::Digest>,
    ) where
        F: MerkleFamily + std::fmt::Debug,
        E: RStorage + Clock + Metrics + BufferPooler,
        C: CleanMem<F, sha256::Digest>,
    {
        use crate::metadata::{Config as MConfig, Metadata};
        use commonware_utils::sequence::prefixed_u64::U64;

        const PRUNE_TO_POS_PREFIX: u8 = 1;

        let merkle =
            Clean::<F, E, sha256::Digest, C>::init(context.with_label("init"), hasher, test_config(&context))
                .await
                .unwrap();

        let merkle = merkle.into_dirty();
        for i in 0..50 {
            merkle.add(hasher, &test_digest(i)).unwrap();
        }
        let mut merkle = merkle.merkleize(hasher);
        merkle.sync().await.unwrap();

        let prune_pos = Position::new(20);
        merkle.prune_to_pos(prune_pos).await.unwrap();
        drop(merkle);

        // Tamper with metadata to have a stale (lower) pruning boundary.
        let meta_cfg = MConfig {
            partition: test_config(&context).metadata_partition,
            codec_config: ((0..).into(), ()),
        };
        let mut metadata =
            Metadata::<_, U64, Vec<u8>>::init(context.with_label("meta_tamper"), meta_cfg)
                .await
                .unwrap();

        let key = U64::new(PRUNE_TO_POS_PREFIX, 0);
        metadata.put(key, 0u64.to_be_bytes().to_vec());
        metadata.sync().await.unwrap();
        drop(metadata);

        let result = Clean::<F, E, sha256::Digest, C>::init(
            context.with_label("reopened"),
            hasher,
            test_config(&context),
        )
        .await;

        match result {
            Err(Error::MissingNode(_)) => {}
            Ok(_) => panic!("expected MissingNode error, got Ok"),
            Err(e) => panic!("expected MissingNode error, got {:?}", e),
        }
    }

    /// Test init() handles metadata pruning boundary ahead of journal (crash during prune).
    pub(crate) async fn test_init_metadata_ahead<F, E, C>(
        context: E,
        hasher: &mut impl MHasher<F, Digest = sha256::Digest>,
    ) where
        F: MerkleFamily + std::fmt::Debug,
        E: RStorage + Clock + Metrics + BufferPooler,
        C: CleanMem<F, sha256::Digest>,
    {
        let merkle =
            Clean::<F, E, sha256::Digest, C>::init(context.with_label("init"), hasher, test_config(&context))
                .await
                .unwrap()
                .into_dirty();

        for i in 0..50 {
            merkle.add(hasher, &test_digest(i)).unwrap();
        }
        let mut merkle = merkle.merkleize(hasher);
        merkle.sync().await.unwrap();

        let prune_pos = Position::new(30);
        merkle.prune_to_pos(prune_pos).await.unwrap();
        let expected_root = merkle.root();
        let expected_size = merkle.size();
        drop(merkle);

        let merkle =
            Clean::<F, E, sha256::Digest, C>::init(context.with_label("reopened"), hasher, test_config(&context))
                .await
                .unwrap();

        assert_eq!(merkle.bounds().start, prune_pos);
        assert_eq!(merkle.size(), expected_size);
        assert_eq!(merkle.root(), expected_root);

        merkle.destroy().await.unwrap();
    }

    /// Regression test: init_sync must compute pinned nodes BEFORE pruning the journal.
    pub(crate) async fn test_init_sync_computes_pinned_nodes_before_pruning<F, E, C>(
        context: E,
        hasher: &mut impl MHasher<F, Digest = sha256::Digest>,
    ) where
        F: MerkleFamily + std::fmt::Debug,
        E: RStorage + Clock + Metrics + BufferPooler,
        C: CleanMem<F, sha256::Digest>,
    {
        let cfg = Config {
            journal_partition: "mmr-journal".into(),
            metadata_partition: "mmr-metadata".into(),
            items_per_blob: NZU64!(7),
            write_buffer: NZUsize!(64),
            thread_pool: None,
            page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
        };

        let merkle =
            Clean::<F, E, sha256::Digest, C>::init(context.with_label("init"), hasher, cfg.clone())
                .await
                .unwrap();
        let merkle = merkle.into_dirty();
        for i in 0..100 {
            merkle.add(hasher, &test_digest(i)).unwrap();
        }
        let merkle = merkle.merkleize(hasher);
        merkle.sync().await.unwrap();

        let original_size = merkle.size();
        let original_root = merkle.root();
        drop(merkle);

        let prune_pos = Position::new(50);
        let sync_cfg = SyncConfig::<F, sha256::Digest> {
            config: cfg,
            range: prune_pos..Position::new(200),
            pinned_nodes: None,
        };

        let sync_merkle =
            Clean::<F, E, sha256::Digest, C>::init_sync(context.with_label("sync"), sync_cfg, hasher)
                .await
                .unwrap();

        assert_eq!(sync_merkle.size(), original_size);
        assert_eq!(sync_merkle.root(), original_root);
        assert_eq!(sync_merkle.bounds().start, prune_pos);

        sync_merkle.destroy().await.unwrap();
    }

    /// Simulate partial writes after pruning and confirm recovery.
    pub(crate) async fn test_recovery_with_pruning<F, E, C>(
        context: E,
        hasher: &mut impl MHasher<F, Digest = sha256::Digest>,
    ) where
        F: MerkleFamily + std::fmt::Debug,
        E: RStorage + Clock + Metrics + BufferPooler,
        C: CleanMem<F, sha256::Digest>,
    {
        const LEAF_COUNT: usize = 2000;
        let merkle =
            Clean::<F, E, sha256::Digest, C>::init(context.with_label("init"), hasher, test_config(&context))
                .await
                .unwrap()
                .into_dirty();
        let mut leaves = Vec::with_capacity(LEAF_COUNT);
        for i in 0..LEAF_COUNT {
            let digest = test_digest(i);
            leaves.push(digest);
            merkle.add(hasher, leaves.last().unwrap()).unwrap();
        }
        let merkle = merkle.merkleize(hasher);
        merkle.sync().await.unwrap();
        drop(merkle);

        for i in 0usize..200 {
            let label = format!("iter_{i}");
            let mut merkle =
                Clean::<F, E, sha256::Digest, C>::init(
                    context.with_label(&label),
                    hasher,
                    test_config(&context),
                )
                .await
                .unwrap();
            let start_size = merkle.size();
            let prune_pos = std::cmp::min(i as u64 * 50, *start_size);
            let prune_pos = Position::new(prune_pos);
            if i % 5 == 0 {
                merkle.simulate_pruning_failure(prune_pos).await.unwrap();
                continue;
            }
            merkle.prune_to_pos(prune_pos).await.unwrap();

            for j in 0..10 {
                let digest = test_digest(100 * (i + 1) + j);
                leaves.push(digest);
                let dirty_merkle = merkle.into_dirty();
                dirty_merkle.add(hasher, leaves.last().unwrap()).unwrap();
                dirty_merkle.add(hasher, leaves.last().unwrap()).unwrap();
                merkle = dirty_merkle.merkleize(hasher);
                let digest = test_digest(LEAF_COUNT + i);
                leaves.push(digest);
                let dirty_merkle = merkle.into_dirty();
                dirty_merkle.add(hasher, leaves.last().unwrap()).unwrap();
                dirty_merkle.add(hasher, leaves.last().unwrap()).unwrap();
                merkle = dirty_merkle.merkleize(hasher);
            }
            let end_size = merkle.size();
            let total_to_write = (*end_size - *start_size) as usize;
            let partial_write_limit = i % total_to_write;
            merkle
                .simulate_partial_sync(partial_write_limit)
                .await
                .unwrap();
        }

        let merkle =
            Clean::<F, E, sha256::Digest, C>::init(context.with_label("final"), hasher, test_config(&context))
                .await
                .unwrap();
        merkle.destroy().await.unwrap();
    }
}
