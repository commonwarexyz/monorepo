//! An MMR backed by a fixed-item-length journal.
//!
//! A [crate::journal] is used to store all unpruned MMR nodes, and a [crate::metadata] store is
//! used to preserve digests required for root and proof generation that would have otherwise been
//! pruned.

use crate::{
    journal::{
        contiguous::fixed::{Config as JConfig, Journal},
        Error as JError,
    },
    metadata::{Config as MConfig, Metadata},
    mmr::{
        hasher::Hasher,
        iterator::{nodes_to_pin, PeakIterator},
        location::Location,
        mem::{
            Clean, CleanMmr as CleanMemMmr, Config as MemConfig, Dirty, DirtyMmr as DirtyMemMmr,
            Mmr as MemMmr, State,
        },
        position::Position,
        storage::Storage,
        verification,
        Error::{self, *},
        Proof,
    },
};
use commonware_codec::DecodeExt;
use commonware_cryptography::Digest;
use commonware_parallel::ThreadPool;
use commonware_runtime::{buffer::paged::CacheRef, Clock, Metrics, Storage as RStorage};
use commonware_utils::sequence::prefixed_u64::U64;
use core::ops::Range;
use std::{
    collections::BTreeMap,
    num::{NonZeroU64, NonZeroUsize},
};
use tracing::{debug, error, warn};

pub type DirtyMmr<E, D> = Mmr<E, D, Dirty>;
pub type CleanMmr<E, D> = Mmr<E, D, Clean<D>>;

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
    pub items_per_blob: NonZeroU64,

    /// The size of the write buffer to use for each blob in the backing journal.
    pub write_buffer: NonZeroUsize,

    /// Optional thread pool to use for parallelizing batch operations.
    pub thread_pool: Option<ThreadPool>,

    /// The page cache to use for caching data.
    pub page_cache: CacheRef,
}

/// Configuration for initializing a journaled MMR for synchronization.
///
/// Determines how to handle existing persistent data based on sync boundaries:
/// - **Fresh Start**: Existing data < range start → discard and start fresh
/// - **Prune and Reuse**: range contains existing data → prune and reuse
/// - **Prune and Rewind**: existing data > range end → prune and rewind to range end
pub struct SyncConfig<D: Digest> {
    /// Base MMR configuration (journal, metadata, etc.)
    pub config: Config,

    /// Sync range - nodes outside this range are pruned/rewound.
    pub range: std::ops::Range<Position>,

    /// The pinned nodes the MMR needs at the pruning boundary (range start), in the order
    /// specified by `nodes_to_pin`. If `None`, the pinned nodes are expected to already be in the
    /// MMR's metadata/journal.
    pub pinned_nodes: Option<Vec<D>>,
}

/// A MMR backed by a fixed-item-length journal.
pub struct Mmr<E: RStorage + Clock + Metrics, D: Digest, S: State<D> + Send + Sync = Dirty> {
    /// A memory resident MMR used to build the MMR structure and cache updates. It caches all
    /// un-synced nodes, and the pinned node set as derived from both its own pruning boundary and
    /// the journaled MMR's pruning boundary.
    mem_mmr: MemMmr<D, S>,

    /// Stores all unpruned MMR nodes.
    journal: Journal<E, D>,

    /// The size of the journal irrespective of any pruned nodes or any un-synced nodes currently
    /// cached in the memory resident MMR.
    journal_size: Position,

    /// Stores all "pinned nodes" (pruned nodes required for proving & root generation) for the MMR,
    /// and the corresponding pruning boundary used to generate them. The metadata remains empty
    /// until pruning is invoked, and its contents change only when the pruning boundary moves.
    metadata: Metadata<E, U64, Vec<u8>>,

    /// The highest position for which this MMR has been pruned, or 0 if this MMR has never been
    /// pruned.
    pruned_to_pos: Position,

    /// The thread pool to use for parallelization.
    pool: Option<ThreadPool>,
}

impl<E: RStorage + Clock + Metrics, D: Digest> From<CleanMmr<E, D>> for DirtyMmr<E, D> {
    fn from(clean: Mmr<E, D, Clean<D>>) -> Self {
        Self {
            mem_mmr: clean.mem_mmr.into(),
            journal: clean.journal,
            journal_size: clean.journal_size,
            metadata: clean.metadata,
            pruned_to_pos: clean.pruned_to_pos,
            pool: clean.pool,
        }
    }
}

/// Prefix used for nodes in the metadata prefixed U8 key.
const NODE_PREFIX: u8 = 0;

/// Prefix used for the key storing the prune_to_pos position in the metadata.
const PRUNE_TO_POS_PREFIX: u8 = 1;

impl<E: RStorage + Clock + Metrics, D: Digest, S: State<D> + Send + Sync> Mmr<E, D, S> {
    /// Return the total number of nodes in the MMR, irrespective of any pruning. The next added
    /// element's position will have this value.
    pub fn size(&self) -> Position {
        self.mem_mmr.size()
    }

    /// Return the total number of leaves in the MMR.
    pub fn leaves(&self) -> Location {
        self.mem_mmr.leaves()
    }

    /// Return the position of the last leaf in this MMR, or None if the MMR is empty.
    pub fn last_leaf_pos(&self) -> Option<Position> {
        self.mem_mmr.last_leaf_pos()
    }

    /// Attempt to get a node from the metadata, with fallback to journal lookup if it fails.
    /// Assumes the node should exist in at least one of these sources and returns a `MissingNode`
    /// error otherwise.
    async fn get_from_metadata_or_journal(
        metadata: &Metadata<E, U64, Vec<u8>>,
        journal: &Journal<E, D>,
        pos: Position,
    ) -> Result<D, Error> {
        if let Some(bytes) = metadata.get(&U64::new(NODE_PREFIX, *pos)) {
            debug!(?pos, "read node from metadata");
            let digest = D::decode(bytes.as_ref());
            let Ok(digest) = digest else {
                error!(
                    ?pos,
                    err = %digest.expect_err("digest is Err in else branch"),
                    "could not convert node from metadata bytes to digest"
                );
                return Err(Error::MissingNode(pos));
            };
            return Ok(digest);
        }

        // If a node isn't found in the metadata, it might still be in the journal.
        debug!(?pos, "reading node from journal");
        let node = journal.read(*pos).await;
        match node {
            Ok(node) => Ok(node),
            Err(JError::ItemPruned(_)) => {
                error!(?pos, "node is missing from metadata and journal");
                Err(Error::MissingNode(pos))
            }
            Err(e) => Err(Error::JournalError(e)),
        }
    }

    /// Add an element to the MMR and return its position in the MMR. Elements added to the MMR
    /// aren't persisted to disk until `sync` is called.
    pub async fn add(
        &mut self,
        h: &mut impl Hasher<Digest = D>,
        element: &[u8],
    ) -> Result<Position, Error> {
        Ok(self.mem_mmr.add(h, element))
    }

    /// Returns [start, end) where `start` and `end - 1` are the positions of the oldest and newest
    /// retained nodes respectively.
    pub fn bounds(&self) -> std::ops::Range<Position> {
        self.pruned_to_pos..self.size()
    }

    /// Adds the pinned nodes based on `prune_pos` to `mem_mmr`.
    async fn add_extra_pinned_nodes(
        mem_mmr: &mut MemMmr<D, S>,
        metadata: &Metadata<E, U64, Vec<u8>>,
        journal: &Journal<E, D>,
        prune_pos: Position,
    ) -> Result<(), Error> {
        let mut pinned_nodes = BTreeMap::new();
        for pos in nodes_to_pin(prune_pos) {
            let digest =
                Mmr::<E, D, Clean<D>>::get_from_metadata_or_journal(metadata, journal, pos).await?;
            pinned_nodes.insert(pos, digest);
        }
        mem_mmr.add_pinned_nodes(pinned_nodes);

        Ok(())
    }
}

impl<E: RStorage + Clock + Metrics, D: Digest> CleanMmr<E, D> {
    /// Initialize a new `Mmr` instance.
    pub async fn init(
        context: E,
        hasher: &mut impl Hasher<Digest = D>,
        cfg: Config,
    ) -> Result<Self, Error> {
        let journal_cfg = JConfig {
            partition: cfg.journal_partition,
            items_per_blob: cfg.items_per_blob,
            page_cache: cfg.page_cache,
            write_buffer: cfg.write_buffer,
        };
        let mut journal =
            Journal::<E, D>::init(context.with_label("mmr_journal"), journal_cfg).await?;
        let mut journal_size = Position::new(journal.bounds().end);

        let metadata_cfg = MConfig {
            partition: cfg.metadata_partition,
            codec_config: ((0..).into(), ()),
        };
        let metadata =
            Metadata::<_, U64, Vec<u8>>::init(context.with_label("mmr_metadata"), metadata_cfg)
                .await?;

        if journal_size == 0 {
            let mem_mmr = MemMmr::init(
                MemConfig {
                    nodes: vec![],
                    pruned_to_pos: Position::new(0),
                    pinned_nodes: vec![],
                },
                hasher,
            )?;
            return Ok(Self {
                mem_mmr,
                journal,
                journal_size,
                metadata,
                pruned_to_pos: Position::new(0),
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
        let journal_bounds_start = journal.bounds().start;
        if metadata_prune_pos > journal_bounds_start {
            // Metadata is ahead of journal (crashed before completing journal prune).
            // Prune the journal to match metadata.
            journal.prune(metadata_prune_pos).await?;
            if journal.bounds().start != journal_bounds_start {
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

        let last_valid_size = PeakIterator::to_nearest_size(journal_size);
        let mut orphaned_leaf: Option<D> = None;
        if last_valid_size != journal_size {
            warn!(
                ?last_valid_size,
                "encountered invalid MMR structure, recovering from last valid size"
            );
            // Check if there is an intact leaf following the last valid size, from which we can
            // recover its missing parents.
            let recovered_item = journal.read(*last_valid_size).await;
            if let Ok(item) = recovered_item {
                orphaned_leaf = Some(item);
            }
            journal.rewind(*last_valid_size).await?;
            journal.sync().await?;
            journal_size = last_valid_size
        }

        // Initialize the mem_mmr in the "prune_all" state.
        let mut pinned_nodes = Vec::new();
        for pos in nodes_to_pin(journal_size) {
            let digest =
                Mmr::<E, D>::get_from_metadata_or_journal(&metadata, &journal, pos).await?;
            pinned_nodes.push(digest);
        }
        let mut mem_mmr = MemMmr::init(
            MemConfig {
                nodes: vec![],
                pruned_to_pos: journal_size,
                pinned_nodes,
            },
            hasher,
        )?;
        let prune_pos = Position::new(effective_prune_pos);
        Self::add_extra_pinned_nodes(&mut mem_mmr, &metadata, &journal, prune_pos).await?;

        let mut s = Self {
            mem_mmr,
            journal,
            journal_size,
            metadata,
            pruned_to_pos: prune_pos,
            pool: cfg.thread_pool,
        };

        if let Some(leaf) = orphaned_leaf {
            // Recover the orphaned leaf and any missing parents.
            let pos = s.mem_mmr.size();
            warn!(?pos, "recovering orphaned leaf");
            s.mem_mmr.add_leaf_digest(hasher, leaf);
            assert_eq!(pos, journal_size);
            s.sync().await?;
            assert_eq!(s.size(), s.journal.bounds().end);
        }

        Ok(s)
    }

    /// Initialize an MMR for synchronization, reusing existing data if possible.
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
        cfg: SyncConfig<D>,
        hasher: &mut impl Hasher<Digest = D>,
    ) -> Result<Self, crate::qmdb::Error> {
        let journal_cfg = JConfig {
            partition: cfg.config.journal_partition.clone(),
            items_per_blob: cfg.config.items_per_blob,
            write_buffer: cfg.config.write_buffer,
            page_cache: cfg.config.page_cache.clone(),
        };

        // Open the journal, handling existing data vs sync range.
        assert!(!cfg.range.is_empty(), "range must not be empty");
        let mut journal: Journal<E, D> =
            Journal::init(context.with_label("mmr_journal"), journal_cfg).await?;
        let size = journal.size();

        if size > *cfg.range.end {
            return Err(crate::journal::Error::ItemOutOfRange(size).into());
        }
        if size <= *cfg.range.start && *cfg.range.start != 0 {
            journal.clear_to_size(*cfg.range.start).await?;
        }

        let journal_size = Position::new(journal.size());

        // Open the metadata.
        let metadata_cfg = MConfig {
            partition: cfg.config.metadata_partition,
            codec_config: ((0..).into(), ()),
        };
        let mut metadata = Metadata::init(context.with_label("mmr_metadata"), metadata_cfg).await?;

        // Write the pruning boundary.
        let pruning_boundary_key = U64::new(PRUNE_TO_POS_PREFIX, 0);
        metadata.put(
            pruning_boundary_key,
            (*cfg.range.start).to_be_bytes().into(),
        );

        // Write the required pinned nodes to metadata.
        if let Some(pinned_nodes) = cfg.pinned_nodes {
            // Use caller-provided pinned nodes.
            let nodes_to_pin_persisted = nodes_to_pin(cfg.range.start);
            for (pos, digest) in nodes_to_pin_persisted.zip(pinned_nodes.iter()) {
                metadata.put(U64::new(NODE_PREFIX, *pos), digest.to_vec());
            }
        }

        // Create the in-memory MMR with the pinned nodes required for its size. This must be
        // performed *before* pruning the journal to range.start to ensure all pinned nodes are
        // present.
        let nodes_to_pin_mem = nodes_to_pin(journal_size);
        let mut mem_pinned_nodes = Vec::new();
        for pos in nodes_to_pin_mem {
            let digest =
                Mmr::<E, D>::get_from_metadata_or_journal(&metadata, &journal, pos).await?;
            mem_pinned_nodes.push(digest);
        }
        let mut mem_mmr = MemMmr::init(
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
            Self::add_extra_pinned_nodes(&mut mem_mmr, &metadata, &journal, cfg.range.start)
                .await?;
        }

        // Sync metadata before pruning so pinned nodes are persisted for crash recovery.
        metadata.sync().await?;

        // Prune the journal to range.start.
        journal.prune(*cfg.range.start).await?;

        Ok(Self {
            mem_mmr,
            journal,
            journal_size,
            metadata,
            pruned_to_pos: cfg.range.start,
            pool: cfg.config.thread_pool,
        })
    }

    /// Compute and add required nodes for the given pruning point to the metadata, and write it to
    /// disk. Return the computed set of required nodes.
    async fn update_metadata(
        &mut self,
        prune_to_pos: Position,
    ) -> Result<BTreeMap<Position, D>, Error> {
        assert!(prune_to_pos >= self.pruned_to_pos);

        let mut pinned_nodes = BTreeMap::new();
        for pos in nodes_to_pin(prune_to_pos) {
            let digest = self.get_node(pos).await?.expect(
                "pinned node should exist if prune_to_pos is no less than self.pruned_to_pos",
            );
            self.metadata
                .put(U64::new(NODE_PREFIX, *pos), digest.to_vec());
            pinned_nodes.insert(pos, digest);
        }

        let key: U64 = U64::new(PRUNE_TO_POS_PREFIX, 0);
        self.metadata.put(key, (*prune_to_pos).to_be_bytes().into());

        self.metadata.sync().await.map_err(Error::MetadataError)?;

        Ok(pinned_nodes)
    }

    pub async fn get_node(&self, position: Position) -> Result<Option<D>, Error> {
        if let Some(node) = self.mem_mmr.get_node(position) {
            return Ok(Some(node));
        }

        match self.journal.read(*position).await {
            Ok(item) => Ok(Some(item)),
            Err(JError::ItemPruned(_)) => Ok(None),
            Err(e) => Err(Error::JournalError(e)),
        }
    }

    /// Sync the MMR to disk.
    pub async fn sync(&mut self) -> Result<(), Error> {
        // Write the nodes cached in the memory-resident MMR to the journal.
        for pos in *self.journal_size..*self.size() {
            let pos = Position::new(pos);
            let node = *self.mem_mmr.get_node_unchecked(pos);
            self.journal.append(node).await?;
        }
        self.journal_size = self.size();
        self.journal.sync().await?;
        assert_eq!(self.journal_size, self.journal.bounds().end);

        // Recompute pinned nodes since we'll need to repopulate the cache after it is cleared by
        // pruning the mem_mmr.
        let mut pinned_nodes = BTreeMap::new();
        for pos in nodes_to_pin(self.pruned_to_pos) {
            let digest = self.mem_mmr.get_node_unchecked(pos);
            pinned_nodes.insert(pos, *digest);
        }

        // Now that the pinned node set has been recomputed, it's safe to prune the mem_mmr and
        // reinstate them.
        self.mem_mmr.prune_all();
        self.mem_mmr.add_pinned_nodes(pinned_nodes);

        Ok(())
    }

    /// Prune all nodes up to but not including the given position and update the pinned nodes.
    ///
    /// This implementation ensures that no failure can leave the MMR in an unrecoverable state,
    /// requiring it sync the MMR to write any potential unmerkleized updates.
    pub async fn prune_to_pos(&mut self, pos: Position) -> Result<(), Error> {
        assert!(pos <= self.size());
        if pos <= self.pruned_to_pos {
            return Ok(());
        }

        // Flush items cached in the mem_mmr to disk to ensure the current state is recoverable.
        self.sync().await?;

        // Update metadata to reflect the desired pruning boundary, allowing for recovery in the
        // event of a pruning failure.
        let pinned_nodes = self.update_metadata(pos).await?;

        self.journal.prune(*pos).await?;
        self.mem_mmr.add_pinned_nodes(pinned_nodes);
        self.pruned_to_pos = pos;

        Ok(())
    }

    /// Pop the given number of elements from the tip of the MMR assuming they exist, and otherwise
    /// return Empty or ElementPruned errors. The backing journal is synced to disk before
    /// returning.
    pub async fn pop(
        &mut self,
        hasher: &mut impl Hasher<Digest = D>,
        mut leaves_to_pop: usize,
    ) -> Result<(), Error> {
        // See if the elements are still cached in which case we can just pop them from the in-mem
        // MMR.
        while leaves_to_pop > 0 {
            match self.mem_mmr.pop(hasher) {
                Ok(_) => {
                    leaves_to_pop -= 1;
                }
                Err(ElementPruned(_)) => break,
                Err(Empty) => {
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
            if new_size.is_mmr_size() {
                leaves_to_pop -= 1;
            }
        }

        self.journal.rewind(*new_size).await?;
        self.journal.sync().await?;
        self.journal_size = new_size;

        // Reset the mem_mmr to one of the new_size in the "prune_all" state.
        let mut pinned_nodes = Vec::new();
        for pos in nodes_to_pin(new_size) {
            let digest =
                Self::get_from_metadata_or_journal(&self.metadata, &self.journal, pos).await?;
            pinned_nodes.push(digest);
        }

        self.mem_mmr = CleanMemMmr::from_components(hasher, vec![], new_size, pinned_nodes);
        Self::add_extra_pinned_nodes(
            &mut self.mem_mmr,
            &self.metadata,
            &self.journal,
            self.pruned_to_pos,
        )
        .await?;

        Ok(())
    }

    /// Return the root of the MMR.
    pub const fn root(&self) -> D {
        *self.mem_mmr.root()
    }

    /// Return an inclusion proof for the element at the location `loc`.
    ///
    /// # Errors
    ///
    /// Returns [Error::LocationOverflow] if `loc` exceeds [crate::mmr::MAX_LOCATION].
    /// Returns [Error::ElementPruned] if some element needed to generate the proof has been pruned.
    /// Returns [Error::Empty] if the range is empty.
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
    /// Returns [Error::LocationOverflow] if any location in `range` exceeds [crate::mmr::MAX_LOCATION].
    /// Returns [Error::ElementPruned] if some element needed to generate the proof has been pruned.
    /// Returns [Error::Empty] if the range is empty.
    pub async fn range_proof(&self, range: Range<Location>) -> Result<Proof<D>, Error> {
        verification::range_proof(self, range).await
    }

    /// Analogous to range_proof but for a previous database state. Specifically, the state when the
    /// MMR had `leaves` leaves.
    ///
    /// Locations are validated by [verification::historical_range_proof].
    ///
    /// # Errors
    ///
    /// Returns [Error::LocationOverflow] if any location in `range` exceeds [crate::mmr::MAX_LOCATION].
    /// Returns [Error::ElementPruned] if some element needed to generate the proof has been pruned.
    /// Returns [Error::Empty] if the range is empty.
    pub async fn historical_range_proof(
        &self,
        leaves: Location,
        range: Range<Location>,
    ) -> Result<Proof<D>, Error> {
        verification::historical_range_proof(self, leaves, range).await
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

    /// Close and permanently remove any disk resources.
    pub async fn destroy(self) -> Result<(), Error> {
        self.journal.destroy().await?;
        self.metadata.destroy().await?;

        Ok(())
    }

    /// Convert this MMR into its dirty counterpart for batched updates.
    pub fn into_dirty(self) -> DirtyMmr<E, D> {
        self.into()
    }

    #[cfg(any(test, feature = "fuzzing"))]
    /// Sync elements to disk until `write_limit` elements have been written, then abort to simulate
    /// a partial write for testing failure scenarios.
    pub async fn simulate_partial_sync(&mut self, write_limit: usize) -> Result<(), Error> {
        if write_limit == 0 {
            return Ok(());
        }

        // Write the nodes cached in the memory-resident MMR to the journal, aborting after
        // write_count nodes have been written.
        let mut written_count = 0usize;
        for i in *self.journal_size..*self.size() {
            let node = *self.mem_mmr.get_node_unchecked(Position::new(i));
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
    pub fn get_pinned_nodes(&self) -> BTreeMap<Position, D> {
        self.mem_mmr.pinned_nodes()
    }

    #[cfg(test)]
    pub async fn simulate_pruning_failure(mut self, prune_to_pos: Position) -> Result<(), Error> {
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

impl<E: RStorage + Clock + Metrics, D: Digest> DirtyMmr<E, D> {
    /// Merkleize the MMR and compute the root digest.
    pub fn merkleize(self, h: &mut impl Hasher<Digest = D>) -> CleanMmr<E, D> {
        CleanMmr {
            mem_mmr: self.mem_mmr.merkleize(h, self.pool.clone()),
            journal: self.journal,
            journal_size: self.journal_size,
            metadata: self.metadata,
            pruned_to_pos: self.pruned_to_pos,
            pool: self.pool,
        }
    }

    /// Pop elements while staying in Dirty state. No root recomputation occurs until merkleize.
    pub async fn pop(&mut self, mut leaves_to_pop: usize) -> Result<(), Error> {
        while leaves_to_pop > 0 {
            match self.mem_mmr.pop() {
                Ok(_) => leaves_to_pop -= 1,
                Err(ElementPruned(_)) => break,
                Err(Empty) => return Err(Error::Empty),
                Err(e) => return Err(e),
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
            if new_size.is_mmr_size() {
                leaves_to_pop -= 1;
            }
        }

        self.journal.rewind(*new_size).await?;
        self.journal.sync().await?;
        self.journal_size = new_size;

        let mut pinned_nodes = Vec::new();
        for pos in nodes_to_pin(new_size) {
            let digest = Mmr::<E, D, Clean<D>>::get_from_metadata_or_journal(
                &self.metadata,
                &self.journal,
                pos,
            )
            .await?;
            pinned_nodes.push(digest);
        }

        self.mem_mmr = DirtyMemMmr::from_components(vec![], new_size, pinned_nodes);
        Self::add_extra_pinned_nodes(
            &mut self.mem_mmr,
            &self.metadata,
            &self.journal,
            self.pruned_to_pos,
        )
        .await?;

        Ok(())
    }

    #[cfg(any(test, feature = "fuzzing"))]
    /// Sync elements to disk until `write_limit` elements have been written, then abort to simulate
    /// a partial write for testing failure scenarios.
    pub async fn simulate_partial_sync(
        self,
        hasher: &mut impl Hasher<Digest = D>,
        write_limit: usize,
    ) -> Result<(), Error> {
        if write_limit == 0 {
            return Ok(());
        }

        let mut clean_mmr = self.merkleize(hasher);

        // Write the nodes cached in the memory-resident MMR to the journal, aborting after
        // write_count nodes have been written.
        let mut written_count = 0usize;
        for i in *clean_mmr.journal_size..*clean_mmr.size() {
            let node = *clean_mmr.mem_mmr.get_node_unchecked(Position::new(i));
            clean_mmr.journal.append(node).await?;
            written_count += 1;
            if written_count >= write_limit {
                break;
            }
        }
        clean_mmr.journal.sync().await?;

        Ok(())
    }
}

impl<E: RStorage + Clock + Metrics + Sync, D: Digest> Storage<D> for CleanMmr<E, D> {
    fn size(&self) -> Position {
        self.size()
    }

    async fn get_node(&self, position: Position) -> Result<Option<D>, Error> {
        self.get_node(position).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mmr::{
        conformance::build_test_mmr, hasher::Hasher as _, location::LocationRangeExt as _, mem,
        Location, StandardHasher as Standard,
    };
    use commonware_cryptography::{
        sha256::{self, Digest},
        Hasher, Sha256,
    };
    use commonware_macros::test_traced;
    use commonware_runtime::{buffer::paged::CacheRef, deterministic, Blob as _, Runner};
    use commonware_utils::{NZUsize, NZU16, NZU64};
    use std::num::NonZeroU16;

    fn test_digest(v: usize) -> Digest {
        Sha256::hash(&v.to_be_bytes())
    }

    const PAGE_SIZE: NonZeroU16 = NZU16!(111);
    const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(5);

    fn test_config() -> Config {
        Config {
            journal_partition: "journal_partition".into(),
            metadata_partition: "metadata_partition".into(),
            items_per_blob: NZU64!(7),
            write_buffer: NZUsize!(1024),
            thread_pool: None,
            page_cache: CacheRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
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

            let mut journaled_mmr = Mmr::init(
                context.clone(),
                &mut Standard::<Sha256>::new(),
                test_config(),
            )
            .await
            .unwrap()
            .into_dirty();

            for i in 0u64..NUM_ELEMENTS {
                hasher.inner().update(&i.to_be_bytes());
                let element = hasher.inner().finalize();
                journaled_mmr.add(&mut hasher, &element).await.unwrap();
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
            let mut mmr = Mmr::init(context.with_label("first"), &mut hasher, test_config())
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
            assert!(matches!(mmr.pop(&mut hasher, 1).await, Err(Error::Empty)));

            mmr.add(&mut hasher, &test_digest(0)).await.unwrap();
            assert_eq!(mmr.size(), 1);
            mmr.sync().await.unwrap();
            assert!(mmr.get_node(Position::new(0)).await.is_ok());
            assert!(mmr.pop(&mut hasher, 1).await.is_ok());
            assert_eq!(mmr.size(), 0);
            mmr.sync().await.unwrap();

            let mut mmr = Mmr::init(context.with_label("second"), &mut hasher, test_config())
                .await
                .unwrap();
            assert_eq!(mmr.size(), 0);

            let empty_proof = Proof::default();
            let mut hasher: Standard<Sha256> = Standard::new();
            let root = mmr.root();
            assert!(empty_proof.verify_range_inclusion(
                &mut hasher,
                &[] as &[Digest],
                Location::new_unchecked(0),
                &root
            ));
            assert!(empty_proof.verify_multi_inclusion(
                &mut hasher,
                &[] as &[(Digest, Location)],
                &root
            ));

            // Confirm empty proof no longer verifies after adding an element.
            mmr.add(&mut hasher, &test_digest(0)).await.unwrap();
            let root = mmr.root();
            assert!(!empty_proof.verify_range_inclusion(
                &mut hasher,
                &[] as &[Digest],
                Location::new_unchecked(0),
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
            let mut mmr = Mmr::init(context.clone(), &mut hasher, test_config())
                .await
                .unwrap();

            let mut c_hasher = Sha256::new();
            for i in 0u64..NUM_ELEMENTS {
                c_hasher.update(&i.to_be_bytes());
                let element = c_hasher.finalize();
                mmr.add(&mut hasher, &element).await.unwrap();
            }

            // Pop off one node at a time without syncing until empty, confirming the root matches.
            for i in (0..NUM_ELEMENTS).rev() {
                assert!(mmr.pop(&mut hasher, 1).await.is_ok());
                let root = mmr.root();
                let mut reference_mmr = mem::CleanMmr::new(&mut hasher);
                for j in 0..i {
                    c_hasher.update(&j.to_be_bytes());
                    let element = c_hasher.finalize();
                    reference_mmr.add(&mut hasher, &element);
                }
                assert_eq!(
                    root,
                    *reference_mmr.root(),
                    "root mismatch after pop at {i}"
                );
            }
            assert!(matches!(mmr.pop(&mut hasher, 1).await, Err(Error::Empty)));
            assert!(mmr.pop(&mut hasher, 0).await.is_ok());

            // Repeat the test though sync part of the way to tip to test crossing the boundary from
            // cached to uncached leaves, and pop 2 at a time instead of just 1.
            for i in 0u64..NUM_ELEMENTS {
                c_hasher.update(&i.to_be_bytes());
                let element = c_hasher.finalize();
                mmr.add(&mut hasher, &element).await.unwrap();
                if i == 101 {
                    mmr.sync().await.unwrap();
                }
            }
            for i in (0..NUM_ELEMENTS - 1).rev().step_by(2) {
                assert!(mmr.pop(&mut hasher, 2).await.is_ok(), "at position {i:?}");
                let root = mmr.root();
                let reference_mmr = mem::CleanMmr::new(&mut hasher);
                let reference_mmr = build_test_mmr(&mut hasher, reference_mmr, i);
                assert_eq!(
                    root,
                    *reference_mmr.root(),
                    "root mismatch at position {i:?}"
                );
            }
            assert!(matches!(mmr.pop(&mut hasher, 99).await, Err(Error::Empty)));

            // Repeat one more time only after pruning the MMR first.
            for i in 0u64..NUM_ELEMENTS {
                c_hasher.update(&i.to_be_bytes());
                let element = c_hasher.finalize();
                mmr.add(&mut hasher, &element).await.unwrap();
                if i == 101 {
                    mmr.sync().await.unwrap();
                }
            }
            let leaf_pos = Position::try_from(Location::new_unchecked(50)).unwrap();
            mmr.prune_to_pos(leaf_pos).await.unwrap();
            // Pop enough nodes to cause the mem-mmr to be completely emptied, and then some.
            mmr.pop(&mut hasher, 80).await.unwrap();
            // Make sure the pinned node boundary is valid by generating a proof for the oldest item.
            mmr.proof(Location::try_from(leaf_pos).unwrap())
                .await
                .unwrap();
            // prune all remaining leaves 1 at a time.
            while mmr.size() > leaf_pos {
                assert!(mmr.pop(&mut hasher, 1).await.is_ok());
            }
            assert!(matches!(
                mmr.pop(&mut hasher, 1).await,
                Err(Error::ElementPruned(_))
            ));

            // Make sure pruning to an older location is a no-op.
            assert!(mmr.prune_to_pos(leaf_pos - 1).await.is_ok());
            assert_eq!(mmr.bounds().start, leaf_pos);

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
            assert_eq!(mmr.size(), Position::new(502));
            assert_eq!(mmr.journal_size, Position::new(0));

            // Generate & verify proof from element that is not yet flushed to the journal.
            const TEST_ELEMENT: usize = 133;
            const TEST_ELEMENT_LOC: Location = Location::new_unchecked(TEST_ELEMENT as u64);

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
            assert_eq!(mmr.journal_size, Position::new(502));
            assert!(mmr.mem_mmr.bounds().is_empty());

            // Now that the element is flushed from the in-mem MMR, confirm its proof is still is
            // generated correctly.
            let proof2 = mmr.proof(TEST_ELEMENT_LOC).await.unwrap();
            assert_eq!(proof, proof2);

            // Generate & verify a proof that spans flushed elements and the last element.
            let range = Location::new_unchecked(TEST_ELEMENT as u64)
                ..Location::new_unchecked(LEAF_COUNT as u64);
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
            let mut mmr = Mmr::init(context.with_label("first"), &mut hasher, test_config())
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
            let root = mmr.root();
            mmr.sync().await.unwrap();
            drop(mmr);

            // The very last element we added (pos=495) resulted in new parents at positions 496 &
            // 497. Simulate a partial write by corrupting the last page's checksum by truncating
            // the last blob by a single byte.
            let partition: String = "journal_partition-blobs".into();
            let (blob, len) = context
                .open(&partition, &71u64.to_be_bytes())
                .await
                .expect("Failed to open blob");
            // A full page w/ CRC should have been written on sync.
            assert_eq!(len, PAGE_SIZE.get() as u64 + 12);

            // truncate the blob by one byte to corrupt the page CRC.
            blob.resize(len - 1).await.expect("Failed to corrupt blob");
            blob.sync().await.expect("Failed to sync blob");

            let mmr = Mmr::init(context.with_label("second"), &mut hasher, test_config())
                .await
                .unwrap();
            // Since we didn't corrupt the leaf, the MMR is able to replay the leaf and recover to
            // the previous state.
            assert_eq!(mmr.size(), 498);
            assert_eq!(mmr.root(), root);

            // Make sure dropping it and re-opening it persists the recovered state.
            drop(mmr);
            let mmr = Mmr::init(context.with_label("third"), &mut hasher, test_config())
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
            let cfg_pruned = test_config();
            let mut pruned_mmr = Mmr::init(
                context.with_label("pruned"),
                &mut hasher,
                cfg_pruned.clone(),
            )
            .await
            .unwrap();
            let cfg_unpruned = Config {
                journal_partition: "unpruned_journal_partition".into(),
                metadata_partition: "unpruned_metadata_partition".into(),
                items_per_blob: NZU64!(7),
                write_buffer: NZUsize!(1024),
                thread_pool: None,
                page_cache: cfg_pruned.page_cache.clone(),
            };
            let mut mmr = Mmr::init(context.with_label("unpruned"), &mut hasher, cfg_unpruned)
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
                    .prune_to_pos(Position::new(prune_pos))
                    .await
                    .unwrap();
                assert_eq!(prune_pos, pruned_mmr.bounds().start);

                let digest = test_digest(LEAF_COUNT + i);
                leaves.push(digest);
                let last_leaf = leaves.last().unwrap();
                let pos = pruned_mmr.add(&mut hasher, last_leaf).await.unwrap();
                positions.push(pos);
                mmr.add(&mut hasher, last_leaf).await.unwrap();
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
            mmr.add(&mut hasher, &test_digest(LEAF_COUNT))
                .await
                .unwrap();
            pruned_mmr
                .add(&mut hasher, &test_digest(LEAF_COUNT))
                .await
                .unwrap();
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
                pruned_mmr
                    .add(&mut hasher, &test_digest(LEAF_COUNT))
                    .await
                    .unwrap();
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
            let mut mmr = Mmr::init(context.with_label("init"), &mut hasher, test_config())
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
            mmr.sync().await.unwrap();
            drop(mmr);

            // Prune the MMR in increments of 50, simulating a partial write after each prune.
            for i in 0usize..200 {
                let label = format!("iter_{i}");
                let mut mmr = Mmr::init(context.with_label(&label), &mut hasher, test_config())
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
                    let pos = mmr.add(&mut hasher, last_leaf).await.unwrap();
                    positions.push(pos);
                    mmr.add(&mut hasher, last_leaf).await.unwrap();
                    assert_eq!(mmr.root(), mmr.root());
                    let digest = test_digest(LEAF_COUNT + i);
                    leaves.push(digest);
                    let last_leaf = leaves.last().unwrap();
                    let pos = mmr.add(&mut hasher, last_leaf).await.unwrap();
                    positions.push(pos);
                    mmr.add(&mut hasher, last_leaf).await.unwrap();
                }
                let end_size = mmr.size();
                let total_to_write = (*end_size - *start_size) as usize;
                let partial_write_limit = i % total_to_write;
                mmr.simulate_partial_sync(partial_write_limit)
                    .await
                    .unwrap();
            }

            let mmr = Mmr::init(context.with_label("final"), &mut hasher, test_config())
                .await
                .unwrap();
            mmr.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_journaled_mmr_historical_range_proof_basic() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Create MMR with 10 elements
            let mut hasher = Standard::<Sha256>::new();
            let mut mmr = Mmr::init(context.clone(), &mut hasher, test_config())
                .await
                .unwrap();
            let mut elements = Vec::new();
            let mut positions = Vec::new();
            for i in 0..10 {
                elements.push(test_digest(i));
                positions.push(mmr.add(&mut hasher, &elements[i]).await.unwrap());
            }
            let original_leaves = mmr.leaves();

            // Historical proof should match "regular" proof when historical size == current database size
            let historical_proof = mmr
                .historical_range_proof(
                    original_leaves,
                    Location::new_unchecked(2)..Location::new_unchecked(6),
                )
                .await
                .unwrap();
            assert_eq!(historical_proof.leaves, original_leaves);
            let root = mmr.root();
            assert!(historical_proof.verify_range_inclusion(
                &mut hasher,
                &elements[2..6],
                Location::new_unchecked(2),
                &root
            ));
            let regular_proof = mmr
                .range_proof(Location::new_unchecked(2)..Location::new_unchecked(6))
                .await
                .unwrap();
            assert_eq!(regular_proof.leaves, historical_proof.leaves);
            assert_eq!(regular_proof.digests, historical_proof.digests);

            // Add more elements to the MMR
            for i in 10..20 {
                elements.push(test_digest(i));
                positions.push(mmr.add(&mut hasher, &elements[i]).await.unwrap());
            }
            let new_historical_proof = mmr
                .historical_range_proof(
                    original_leaves,
                    Location::new_unchecked(2)..Location::new_unchecked(6),
                )
                .await
                .unwrap();
            assert_eq!(new_historical_proof.leaves, historical_proof.leaves);
            assert_eq!(new_historical_proof.digests, historical_proof.digests);

            mmr.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_journaled_mmr_historical_range_proof_with_pruning() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut hasher = Standard::<Sha256>::new();
            let mut mmr = Mmr::init(context.with_label("main"), &mut hasher, test_config())
                .await
                .unwrap();

            // Add many elements
            let mut elements = Vec::new();
            let mut positions = Vec::new();
            for i in 0..50 {
                elements.push(test_digest(i));
                positions.push(mmr.add(&mut hasher, &elements[i]).await.unwrap());
            }

            // Prune to position 30
            let prune_pos = Position::new(30);
            mmr.prune_to_pos(prune_pos).await.unwrap();

            // Create reference MMR for verification to get correct size
            let mut ref_mmr = Mmr::init(
                context.with_label("ref"),
                &mut hasher,
                Config {
                    journal_partition: "ref_journal_pruned".into(),
                    metadata_partition: "ref_metadata_pruned".into(),
                    items_per_blob: NZU64!(7),
                    write_buffer: NZUsize!(1024),
                    thread_pool: None,
                    page_cache: CacheRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
                },
            )
            .await
            .unwrap();

            for elt in elements.iter().take(41) {
                ref_mmr.add(&mut hasher, elt).await.unwrap();
            }
            let historical_leaves = ref_mmr.leaves();
            let historical_root = ref_mmr.root();

            // Test proof at historical position after pruning
            let historical_proof = mmr
                .historical_range_proof(
                    historical_leaves,
                    Location::new_unchecked(35)..Location::new_unchecked(39), // Start after prune point to end at historical size
                )
                .await
                .unwrap();

            assert_eq!(historical_proof.leaves, historical_leaves);

            // Verify proof works despite pruning
            assert!(historical_proof.verify_range_inclusion(
                &mut hasher,
                &elements[35..39],
                Location::new_unchecked(35),
                &historical_root
            ));

            ref_mmr.destroy().await.unwrap();
            mmr.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_journaled_mmr_historical_range_proof_large() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut hasher = Standard::<Sha256>::new();

            let mut mmr = Mmr::init(
                context.with_label("server"),
                &mut hasher,
                Config {
                    journal_partition: "server_journal".into(),
                    metadata_partition: "server_metadata".into(),
                    items_per_blob: NZU64!(7),
                    write_buffer: NZUsize!(1024),
                    thread_pool: None,
                    page_cache: CacheRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
                },
            )
            .await
            .unwrap();

            let mut elements = Vec::new();
            let mut positions = Vec::new();
            for i in 0..100 {
                elements.push(test_digest(i));
                positions.push(mmr.add(&mut hasher, &elements[i]).await.unwrap());
            }

            let range = Location::new_unchecked(30)..Location::new_unchecked(61);

            // Only apply elements up to end_loc to the reference MMR.
            let mut ref_mmr = Mmr::init(
                context.with_label("client"),
                &mut hasher,
                Config {
                    journal_partition: "client_journal".into(),
                    metadata_partition: "client_metadata".into(),
                    items_per_blob: NZU64!(7),
                    write_buffer: NZUsize!(1024),
                    thread_pool: None,
                    page_cache: CacheRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
                },
            )
            .await
            .unwrap();

            // Add elements up to the end of the range to verify historical root
            for elt in elements.iter().take(*range.end as usize) {
                ref_mmr.add(&mut hasher, elt).await.unwrap();
            }
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
    fn test_journaled_mmr_historical_range_proof_singleton() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut hasher = Standard::<Sha256>::new();
            let mut mmr = Mmr::init(context.clone(), &mut hasher, test_config())
                .await
                .unwrap();

            let element = test_digest(0);
            mmr.add(&mut hasher, &element).await.unwrap();

            // Test single element proof at historical position
            let single_proof = mmr
                .historical_range_proof(
                    Location::new_unchecked(1),
                    Location::new_unchecked(0)..Location::new_unchecked(1),
                )
                .await
                .unwrap();

            let root = mmr.root();
            assert!(single_proof.verify_range_inclusion(
                &mut hasher,
                &[element],
                Location::new_unchecked(0),
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
                config: test_config(),
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
            let mut sync_mmr = sync_mmr;
            let new_element = test_digest(999);
            sync_mmr.add(&mut hasher, &new_element).await.unwrap();

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
            let mut mmr = Mmr::init(context.with_label("init"), &mut hasher, test_config())
                .await
                .unwrap();
            for i in 0..50 {
                mmr.add(&mut hasher, &test_digest(i)).await.unwrap();
            }
            mmr.sync().await.unwrap();
            let original_size = mmr.size();
            let original_leaves = mmr.leaves();
            let original_root = mmr.root();

            // Sync with range.start <= existing_size <= range.end should reuse data
            let lower_bound_pos = mmr.bounds().start;
            let upper_bound_pos = mmr.size();
            let mut expected_nodes = BTreeMap::new();
            for i in *lower_bound_pos..*upper_bound_pos {
                expected_nodes.insert(
                    Position::new(i),
                    mmr.get_node(Position::new(i)).await.unwrap().unwrap(),
                );
            }
            let sync_cfg = SyncConfig::<sha256::Digest> {
                config: test_config(),
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
            let mut mmr = Mmr::init(context.with_label("init"), &mut hasher, test_config())
                .await
                .unwrap();
            for i in 0..30 {
                mmr.add(&mut hasher, &test_digest(i)).await.unwrap();
            }
            mmr.sync().await.unwrap();
            mmr.prune_to_pos(Position::new(10)).await.unwrap();

            let original_size = mmr.size();
            let original_root = mmr.root();
            let original_pruned_to = mmr.bounds().start;

            // Sync with boundaries that extend beyond existing data (partial overlap).
            let lower_bound_pos = original_pruned_to;
            let upper_bound_pos = original_size + 11; // Extend beyond existing data

            let mut expected_nodes = BTreeMap::new();
            for pos in *lower_bound_pos..*original_size {
                let pos = Position::new(pos);
                expected_nodes.insert(pos, mmr.get_node(pos).await.unwrap().unwrap());
            }

            let sync_cfg = SyncConfig::<sha256::Digest> {
                config: test_config(),
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
            let mut hasher = Standard::<Sha256>::new();

            // Create an MMR with some data and prune it
            let mut mmr = Mmr::init(context.with_label("init"), &mut hasher, test_config())
                .await
                .unwrap();

            // Add 50 elements
            for i in 0..50 {
                mmr.add(&mut hasher, &test_digest(i)).await.unwrap();
            }
            mmr.sync().await.unwrap();

            // Prune to position 20 (this stores pinned nodes in metadata for position 20)
            let prune_pos = Position::new(20);
            mmr.prune_to_pos(prune_pos).await.unwrap();
            drop(mmr);

            // Tamper with metadata to have a stale (lower) pruning boundary
            let meta_cfg = MConfig {
                partition: test_config().metadata_partition,
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
                test_config(),
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
            let mut mmr = Mmr::init(context.with_label("init"), &mut hasher, test_config())
                .await
                .unwrap();

            // Add 50 elements
            for i in 0..50 {
                mmr.add(&mut hasher, &test_digest(i)).await.unwrap();
            }
            mmr.sync().await.unwrap();

            // Prune to position 30 (this stores pinned nodes and updates metadata)
            let prune_pos = Position::new(30);
            mmr.prune_to_pos(prune_pos).await.unwrap();
            let expected_root = mmr.root();
            let expected_size = mmr.size();
            drop(mmr);

            // Reopen the MMR - should recover correctly with metadata ahead of
            // journal boundary (metadata says 30, journal is section-aligned to 28)
            let mmr = Mmr::init(context.with_label("reopened"), &mut hasher, test_config())
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
                journal_partition: "mmr_journal".to_string(),
                metadata_partition: "mmr_metadata".to_string(),
                items_per_blob: NZU64!(7),
                write_buffer: NZUsize!(64),
                thread_pool: None,
                page_cache: CacheRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
            };

            // Create MMR with enough elements to span multiple sections.
            let mut mmr = Mmr::init(context.with_label("init"), &mut hasher, cfg.clone())
                .await
                .unwrap();
            for i in 0..100 {
                mmr.add(&mut hasher, &test_digest(i)).await.unwrap();
            }
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
}
