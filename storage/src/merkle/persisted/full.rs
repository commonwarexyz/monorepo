//! A Merkle structure backed by a fixed-item-length journal.
//!
//! A [crate::journal] is used to store all unpruned nodes, and a [crate::metadata] store is
//! used to preserve digests required for root and proof generation that would have otherwise been
//! pruned.
//!
//! This module is generic over [`Family`], so it works for both MMR and MMB.
//!
//! # Ownership
//!
//! Mutating methods take the structure by value and return it on success. If a mutating
//! method returns an error, or its future is dropped before it finishes, the structure is
//! gone: state that was not yet durable is discarded, but everything already on disk stays
//! recoverable.

use crate::{
    Context,
    journal::{
        Error as JError,
        authenticated::{Backing as _, BackingRecovery as _, covers},
        contiguous::{
            Contiguous, Many,
            fixed::{Config as JConfig, Journal, Recovery as JournalRecovery},
        },
    },
    merkle::{
        Error, Family, Location, Position, Proof, Readable, batch,
        hasher::Hasher,
        mem::{Config as MemConfig, Mem},
    },
    metadata::{Config as MConfig, Metadata},
};
use commonware_codec::{Copying, DecodeExt, Write};
use commonware_cryptography::Digest;
use commonware_parallel::Strategy;
use commonware_runtime::{Handle, buffer::paged::CacheRef};
use commonware_utils::{range::NonEmptyRange, sequence::prefixed_u64::U64};
use std::{
    collections::{BTreeMap, BTreeSet},
    num::{NonZeroU64, NonZeroUsize},
    sync::Arc,
};

/// Append-only wrapper around [`batch::UnmerkleizedBatch`].
///
/// The full Merkle structure's [`Merkle::sync`] only persists *appended* nodes
/// (positions in `[journal_size, state.size())`). Overwrites to existing positions are stored in
/// the in-memory layer but never flushed, so they would be silently lost on crash recovery. This
/// wrapper prevents that by exposing only append and merkleize operations, hiding `update_leaf*`
/// at compile time.
pub struct UnmerkleizedBatch<F: Family, D: Digest, S: Strategy> {
    inner: batch::UnmerkleizedBatch<F, D, S>,
}

impl<F: Family, D: Digest, S: Strategy> UnmerkleizedBatch<F, D, S> {
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

    /// Encode and hash `items` across the strategy, adding their leaf digests in order.
    pub(crate) fn add_many<Item: Write + Send + Sync>(
        self,
        hasher: &impl Hasher<F, Digest = D>,
        items: &[Item],
    ) -> Self {
        Self {
            inner: self.inner.add_many(hasher, items),
        }
    }

    /// The number of leaves visible through this batch.
    pub fn leaves(&self) -> Location<F> {
        self.inner.leaves()
    }

    /// Return a reference to the batch's strategy.
    pub fn strategy(&self) -> &S {
        self.inner.strategy()
    }

    /// Consume this batch and produce an immutable [`batch::MerkleizedBatch`] with computed nodes.
    /// `base` provides committed node data as fallback during hash computation.
    pub fn merkleize(
        self,
        base: &Mem<F, D>,
        hasher: &impl Hasher<F, Digest = D>,
    ) -> Arc<batch::MerkleizedBatch<F, D, S>> {
        self.inner.merkleize(base, hasher)
    }
}

/// Configuration for a journal-backed Merkle structure.
#[derive(Clone)]
pub struct Config<S: Strategy> {
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

    /// Buffer size for sequential reads during recovery.
    pub replay_buffer: NonZeroUsize,

    /// Strategy used to parallelize batch operations.
    pub strategy: S,

    /// The page cache to use for caching data.
    pub page_cache: CacheRef,
}

/// Configuration for initializing a full Merkle structure for synchronization.
///
/// Determines how to handle existing persistent data based on sync boundaries:
/// - **Fresh Start**: Existing data < range start -> discard and start fresh
/// - **Prune and Reuse**: range contains existing data -> prune and reuse
/// - **Ahead**: retained data extends beyond range end -> truncate to range end during
///   initialization
/// - **Incompatible**: retained data starts after range start -> discard and start fresh
pub struct SyncConfig<F: Family, D: Digest, S: Strategy> {
    /// Base configuration (journal, metadata, etc.)
    pub config: Config<S>,

    /// Sync range expressed as leaf-aligned bounds.
    pub range: NonEmptyRange<Location<F>>,

    /// The pinned nodes the structure needs at the pruning boundary (range start), in the order
    /// specified by `Family::nodes_to_pin`. If `None`, the pinned nodes are expected to already be
    /// in the structure's metadata/journal.
    pub pinned_nodes: Option<Vec<D>>,
}

/// A Merkle structure backed by a fixed-item-length journal.
pub struct Merkle<F: Family, E: Context, D: Digest, S: Strategy> {
    /// A memory resident Merkle structure used to build the structure and cache updates. It caches
    /// all un-synced nodes, and the pinned node set as derived from both its own pruning boundary
    /// and the full structure's pruning boundary.
    ///
    /// Held in an [`Arc`] so [`Merkle::snapshot`] can hand a zero-copy, immutable view to jobs
    /// running off the calling task. Mutations go through [`Arc::make_mut`]: they are in-place
    /// while no snapshot is alive and copy-on-write otherwise, so a snapshot never observes
    /// later mutations.
    pub(crate) mem: Arc<Mem<F, D>>,

    /// The highest position for which this structure has been pruned, or 0 if it has never been
    /// pruned.
    pub(crate) pruned_to_pos: Position<F>,

    /// Stores all unpruned nodes.
    pub(crate) journal: Journal<E, D>,

    /// Stores the pinned nodes for the current pruning boundary, and the corresponding pruning
    /// boundary used to generate them. Pruning writes both when the boundary moves. Sync
    /// initialization replaces them with the selected boundary and its pins.
    pub(crate) metadata: Metadata<E, U64, Vec<u8>>,

    /// True while flushed nodes or a started sync still require a full journal sync.
    pub(crate) journal_dirty: bool,

    /// The strategy to use for parallelization.
    pub(crate) strategy: S,
}

/// The node journal as sync recovery finds it.
enum Nodes<E: Context, D: Digest> {
    /// Stored nodes that may serve the range or its boundary pins, opened bounded at the range end.
    Opened(Box<JournalRecovery<E, D>>),
    /// Stored nodes that cannot serve the range, left unopened until the reset.
    Unopened(E),
}

/// A validated Merkle prefix whose storage has not yet been deliberately truncated.
pub(crate) struct Recovery<F: Family, E: Context, D: Digest, S: Strategy> {
    /// Node journal that may extend beyond the greatest complete tree.
    journal: Box<JournalRecovery<E, D>>,
    /// Persisted pruning boundary and pinned nodes used to reconstruct retained history.
    metadata: Metadata<E, U64, Vec<u8>>,
    /// Complete tree reconstructed from tip pins, including any recoverable orphan leaf.
    mem: Mem<F, D>,
    /// Node count of the greatest complete prefix of the recovered journal, excluding nodes
    /// rebuilt from an orphan leaf.
    retained_size: Position<F>,
    /// Persisted leaf pruning boundary expressed as a node position.
    metadata_prune_pos: Position<F>,
    /// Stricter of the persisted pruning boundary and the journal's leaf-aligned start.
    effective_prune_pos: Position<F>,
    /// Parallelization strategy for the recovered Merkle structure.
    strategy: S,
}

impl<F: Family, E: Context, D: Digest, S: Strategy> Recovery<F, E, D, S> {
    /// Number of leaves available before operation replay.
    pub(crate) fn leaves(&self) -> Location<F> {
        self.mem.leaves()
    }

    /// Finalize a validated prefix and publish its Merkle handle.
    pub(crate) async fn finish(mut self) -> Result<Merkle<F, E, D, S>, Error<F>> {
        // Reconcile the journal with the validated complete size and durable metadata boundary.
        self.journal = self.journal.truncate(*self.retained_size).await?;
        if *self.metadata_prune_pos > self.journal.bounds().start {
            (self.journal, _) = self.journal.prune(*self.metadata_prune_pos).await?;
        }

        // Publish the selected journal prefix. The append path owns rollover synchronization for
        // any reconstructed nodes.
        let journal = (*self.journal).finish(*self.retained_size).await?;
        Merkle {
            mem: Arc::new(self.mem),
            pruned_to_pos: self.effective_prune_pos,
            journal,
            metadata: self.metadata,
            journal_dirty: false,
            strategy: self.strategy,
        }
        .sync()
        .await
    }
}

impl<F: Family, E: Context, D: Digest, S: Strategy> std::fmt::Debug for Merkle<F, E, D, S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Merkle")
            .field("size", &self.size())
            .field("leaves", &self.leaves())
            .finish_non_exhaustive()
    }
}

/// Prefix used for nodes in the metadata prefixed U8 key.
const NODE_PREFIX: u8 = 0;

/// Prefix used for the key storing the pruning boundary (as a leaf index) in the metadata.
pub(crate) const PRUNED_TO_PREFIX: u8 = 1;

impl<F: Family, E: Context, D: Digest, S: Strategy> Merkle<F, E, D, S> {
    /// Return the total number of nodes in the structure, irrespective of any pruning. The next
    /// added element's position will have this value.
    pub fn size(&self) -> Position<F> {
        self.mem.size()
    }

    /// Return the total number of leaves in the structure.
    pub fn leaves(&self) -> Location<F> {
        self.mem.leaves()
    }

    /// Returns [start, end) where `start` is the oldest retained leaf and `end` is the total leaf
    /// count.
    pub fn bounds(&self) -> std::ops::Range<Location<F>> {
        Location::try_from(self.pruned_to_pos).expect("valid pruned_to_pos")..self.mem.leaves()
    }

    /// Initialize a new `Merkle` instance.
    pub async fn init(
        context: E,
        hasher: &impl Hasher<F, Digest = D>,
        cfg: Config<S>,
    ) -> Result<Self, Error<F>> {
        Self::prepare(context, hasher, cfg, None)
            .await?
            .finish()
            .await
    }

    /// Recover at most `max_leaves` leaves and durably discard the remaining suffix.
    ///
    /// A cap above the recovered end preserves that end. The cap must permit the persisted
    /// pruning boundary.
    pub async fn init_at_most(
        context: E,
        hasher: &impl Hasher<F, Digest = D>,
        cfg: Config<S>,
        max_leaves: Location<F>,
    ) -> Result<Self, Error<F>> {
        Self::prepare(context, hasher, cfg, Some(max_leaves))
            .await?
            .finish()
            .await
    }

    /// Validate reconstruction anchors before authorizing deliberate history deletion.
    ///
    /// A persisted pruning boundary beyond the recovered journal fails with [Error::MissingNode].
    /// An interrupted [Self::init_sync] can leave this state until its retry completes the reset.
    pub(crate) async fn prepare(
        context: E,
        hasher: &impl Hasher<F, Digest = D>,
        cfg: Config<S>,
        max_leaves: Option<Location<F>>,
    ) -> Result<Recovery<F, E, D, S>, Error<F>> {
        // Metadata records a leaf pruning boundary. Reject caps that cannot retain it before
        // opening the node journal.
        let metadata = Metadata::<_, U64, Vec<u8>>::init(
            context.child("merkle_metadata"),
            MConfig {
                partition: cfg.metadata_partition,
                codec_config: ((0..).into(), ()),
            },
        )
        .await?;
        let key = U64::new(PRUNED_TO_PREFIX, 0);
        let metadata_pruned_to = match metadata.get(&key) {
            Some(bytes) => Location::<F>::new(u64::from_be_bytes(
                bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| Error::DataCorrupted("invalid Merkle pruning boundary"))?,
            )),
            None => Location::new(0),
        };
        let metadata_prune_pos = Position::try_from(metadata_pruned_to)?;
        if let Some(cap) = max_leaves
            && cap < metadata_pruned_to
        {
            return Err(Error::ElementPruned(Position::try_from(cap)?));
        }

        // Translate the leaf cap to a node ceiling. An unrepresentably large cap cannot constrain
        // any representable persisted tree.
        let node_cap = max_leaves
            .map(|leaves| Position::<F>::try_from(leaves).map_or(u64::MAX, |position| *position));
        let journal = Box::new(
            Journal::<E, D>::recover(
                context.child("merkle_journal"),
                JConfig {
                    partition: cfg.journal_partition,
                    items_per_blob: cfg.items_per_blob,
                    page_cache: cfg.page_cache,
                    write_buffer: cfg.write_buffer,
                    replay_buffer: cfg.replay_buffer,
                },
                node_cap,
            )
            .await?,
        );

        let journal_size = Position::<F>::new(journal.bounds().end);

        // Journal pruning is blob-aligned and may fall between complete trees. Round its boundary
        // up to the first leaf position, then honor the more restrictive durable boundary.
        let boundary = Position::<F>::new(journal.bounds().start);
        let boundary_floor = F::to_nearest_size(boundary);
        let aligned_boundary = if boundary_floor == boundary {
            boundary
        } else {
            Position::try_from(Location::try_from(boundary_floor)? + 1)?
        };
        let effective_prune_pos = metadata_prune_pos.max(aligned_boundary);
        let retained_size = F::to_nearest_size(journal_size);
        if effective_prune_pos > retained_size {
            return Err(Error::MissingNode(effective_prune_pos));
        }

        // Reconstruct the greatest complete tree and the anchors required by the effective
        // pruning boundary before any truncation.
        let leaves = Location::try_from(retained_size)?;
        let prune_loc = Location::try_from(effective_prune_pos)?;
        let mut mem = Self::pinned(&metadata, Some(&journal), leaves, prune_loc).await?;

        // An intact orphan leaf can reconstruct missing parents within the leaf cap.
        if retained_size != journal_size
            && max_leaves.is_none_or(|cap| leaves < cap)
            && let Ok(leaf) = journal.read(*retained_size).await
        {
            let batch = mem
                .new_batch()
                .add_leaf_digest(leaf)
                .merkleize(&mem, hasher);
            mem.apply_batch(&batch)?;
        }
        Ok(Recovery {
            journal,
            metadata,
            mem,
            retained_size,
            metadata_prune_pos,
            effective_prune_pos,
            strategy: cfg.strategy,
        })
    }

    /// Read a pinned node from metadata or initialization-owned journal storage.
    ///
    /// Returns [Error::MissingNode] when neither holds the node.
    async fn get_from_recovery(
        metadata: &Metadata<E, U64, Vec<u8>>,
        journal: Option<&JournalRecovery<E, D>>,
        pos: Position<F>,
    ) -> Result<D, Error<F>> {
        if let Some(bytes) = metadata.get(&U64::new(NODE_PREFIX, *pos)) {
            return D::decode(Copying(bytes))
                .map_err(|_| Error::DataCorrupted("could not read digest at requested pos"));
        }
        let Some(journal) = journal else {
            return Err(Error::MissingNode(pos));
        };
        match journal.read(*pos).await {
            Ok(node) => Ok(node),
            Err(JError::ItemPruned(_) | JError::ItemOutOfRange(_)) => Err(Error::MissingNode(pos)),
            Err(err) => Err(Error::Journal(err)),
        }
    }

    /// Build an empty tree of `leaves` from its tip pins, adding the pins that retain history
    /// from `prune_loc`.
    async fn pinned(
        metadata: &Metadata<E, U64, Vec<u8>>,
        journal: Option<&JournalRecovery<E, D>>,
        leaves: Location<F>,
        prune_loc: Location<F>,
    ) -> Result<Mem<F, D>, Error<F>> {
        // Reconstruct the tree of `leaves` from its tip pins.
        let mut pinned_nodes = Vec::new();
        for pos in F::nodes_to_pin(leaves) {
            pinned_nodes.push(Self::get_from_recovery(metadata, journal, pos).await?);
        }
        let mut mem = Mem::init(MemConfig {
            nodes: vec![],
            pruning_boundary: leaves,
            pinned_nodes,
        })?;

        // Add the anchors required by the pruning boundary.
        let mut extra = BTreeMap::new();
        for pos in F::nodes_to_pin(prune_loc) {
            extra.insert(pos, Self::get_from_recovery(metadata, journal, pos).await?);
        }
        mem.add_pinned_nodes(extra);
        Ok(mem)
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
    /// 3. **Ahead**: retained data covers range.start but ends after range.end
    ///    - Truncates the journal to `range.end` during initialization
    ///
    /// 4. **Incompatible**: retained data starts after range.start
    ///    - Discards existing data and creates a new [Journal] at `range.start`
    ///
    /// If interrupted, retry [Self::init_sync] with the authoritative range and pins. When the
    /// range starts outside the retained tree, ordinary [Self::init] may fail with
    /// [Error::MissingNode] until that retry completes the reset.
    pub async fn init_sync(context: E, cfg: SyncConfig<F, D, S>) -> Result<Self, Error<F>> {
        let prune_loc = cfg.range.start();
        let prune_pos = Position::try_from(prune_loc)?;
        let end_pos = Position::try_from(cfg.range.end())?;
        let journal_cfg = JConfig {
            partition: cfg.config.journal_partition.clone(),
            items_per_blob: cfg.config.items_per_blob,
            write_buffer: cfg.config.write_buffer,
            replay_buffer: cfg.config.replay_buffer,
            page_cache: cfg.config.page_cache.clone(),
        };

        // Load metadata before deciding whether to open the journal. Boundary pins missing
        // from metadata may still be recoverable from nodes before the sync range.
        let metadata_cfg = MConfig {
            partition: cfg.config.metadata_partition,
            codec_config: ((0..).into(), ()),
        };
        let mut metadata = Metadata::init(context.child("merkle_metadata"), metadata_cfg).await?;
        let nodes_to_pin_persisted: Vec<_> = F::nodes_to_pin(prune_loc).collect();

        // Without caller pins, every boundary pin missing from metadata must come from the
        // journal. Probe the highest one, since pin order need not follow position, so the journal
        // stays unopened when that pin lies past every stored blob. Otherwise the sync start
        // decides range reuse.
        let journal_probe = if cfg.pinned_nodes.is_none() {
            nodes_to_pin_persisted
                .iter()
                .filter(|&&pos| metadata.get(&U64::new(NODE_PREFIX, *pos)).is_none())
                .max()
                .copied()
                .unwrap_or(prune_pos)
        } else {
            prune_pos
        };
        let journal_context = context.child("merkle_journal");
        let span = Journal::<E, D>::span(&journal_context, &journal_cfg).await?;
        let journal = if covers(&span, *journal_probe) {
            Nodes::Opened(Box::new(
                Journal::<E, D>::recover(journal_context, journal_cfg.clone(), Some(*end_pos))
                    .await?,
            ))
        } else {
            Nodes::Unopened(journal_context)
        };
        let opened = match &journal {
            Nodes::Opened(journal) => Some(journal.as_ref()),
            Nodes::Unopened(_) => None,
        };

        // Coverage places an opened journal's start at or below the sync start, and the open caps
        // its end at the range end. A complete tree ending at or before the sync start cannot
        // serve the range, so it is reset unless the journal is already empty there.
        let bounds = opened.map_or(*prune_pos..*prune_pos, |journal| journal.bounds());
        let journal_size = F::to_nearest_size(Position::new(bounds.end)).max(prune_pos);
        let reset = journal_size == prune_pos && bounds != (*prune_pos..*prune_pos);

        // An interrupted sync can leave metadata ahead of the journal. Retain only this
        // boundary's pins so recovery cannot prefer abandoned pins over journal nodes.
        let retained_node_keys: BTreeSet<_> = nodes_to_pin_persisted
            .iter()
            .map(|pos| U64::new(NODE_PREFIX, **pos))
            .collect();
        metadata
            .retain(|key: &U64, _| key.prefix() != NODE_PREFIX || retained_node_keys.contains(key));

        // Write the pruning boundary.
        let pruning_boundary_key = U64::new(PRUNED_TO_PREFIX, 0);
        metadata.put(
            pruning_boundary_key,
            prune_loc.as_u64().to_be_bytes().into(),
        );

        // Write the required pinned nodes to metadata.
        // The set of pinned nodes depends only on the prune boundary, not on the total
        // structure size, so we validate against `nodes_to_pin(prune_loc)` alone.
        if let Some(pinned_nodes) = cfg.pinned_nodes {
            // Use caller-provided pinned nodes.
            if pinned_nodes.len() != nodes_to_pin_persisted.len() {
                return Err(Error::<F>::InvalidPinnedNodes);
            }
            for (pos, digest) in nodes_to_pin_persisted.into_iter().zip(pinned_nodes.iter()) {
                metadata.put(U64::new(NODE_PREFIX, *pos), digest.to_vec());
            }
        } else {
            // Recovery may delete the journal nodes supplying these pins. Preserve every
            // boundary pin in metadata before synchronizing it and removing its source.
            for pos in nodes_to_pin_persisted {
                let digest = Self::get_from_recovery(&metadata, opened, pos).await?;
                metadata.put(U64::new(NODE_PREFIX, *pos), digest.to_vec());
            }
        }

        // Build the in-memory structure before pruning or reset removes pin sources.
        let journal_leaves = Location::try_from(journal_size)?;
        let mem = Self::pinned(&metadata, opened, journal_leaves, prune_loc).await?;

        // Pins must be durable before reset or pruning removes their journal sources.
        let metadata = metadata.sync().await?;
        let mut journal = match journal {
            Nodes::Opened(journal) if reset => journal.clear_to_size(*prune_pos).await?,
            Nodes::Opened(journal) => journal.truncate(*journal_size).await?,
            Nodes::Unopened(journal_context) => {
                Box::new(Journal::<E, D>::clear(journal_context, journal_cfg, *prune_pos).await?)
            }
        };
        (journal, _) = journal.prune(*prune_pos).await?;
        let journal = (*journal).finish(*journal_size).await?;

        Ok(Self {
            mem: Arc::new(mem),
            pruned_to_pos: prune_pos,
            journal,
            metadata,
            journal_dirty: false,
            strategy: cfg.config.strategy,
        })
    }

    /// Compute and add required nodes for the given pruning point to the metadata, and write it to
    /// disk. Return the computed set of required nodes.
    async fn update_metadata(
        mut self,
        prune_to_pos: Position<F>,
    ) -> Result<(Self, BTreeMap<Position<F>, D>), Error<F>> {
        assert!(prune_to_pos >= self.pruned_to_pos);

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
        self.metadata = self
            .metadata
            .put_sync(
                key,
                Location::try_from(prune_to_pos)?
                    .as_u64()
                    .to_be_bytes()
                    .into(),
            )
            .await
            .map_err(Error::Metadata)?;

        Ok((self, pinned_nodes))
    }

    pub async fn get_node(&self, position: Position<F>) -> Result<Option<D>, Error<F>> {
        if let Some(node) = self.mem.get_node(position) {
            return Ok(Some(node));
        }

        match self.journal.read(*position).await {
            Ok(item) => Ok(Some(item)),
            Err(JError::ItemPruned(_)) => Ok(None),
            Err(e) => Err(Error::Journal(e)),
        }
    }

    /// Batched [`Self::get_node`]: `positions` must be strictly increasing. Memory-resident
    /// nodes are served directly; the rest go through the journal's batched read, which
    /// serves page-cache hits in bulk and fetches misses concurrently.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ElementPruned`] for the first of `positions` that falls below the
    /// journal's pruning boundary.
    pub async fn get_nodes(&self, positions: &[Position<F>]) -> Result<Vec<D>, Error<F>> {
        assert!(
            positions.is_sorted_by(|a, b| a < b),
            "positions must be strictly increasing"
        );
        let bounds = self.journal.bounds();
        let mut nodes = vec![None; positions.len()];
        let mut journal_positions = Vec::with_capacity(positions.len());
        for (slot, &position) in nodes.iter_mut().zip(positions) {
            if let Some(node) = self.mem.get_node(position) {
                *slot = Some(node);
            } else if *position >= bounds.start {
                // In-subsequence order is preserved, so this stays strictly increasing.
                journal_positions.push(*position);
            } else {
                return Err(Error::ElementPruned(position));
            }
        }

        // Within-bounds reads are guaranteed not to return `ItemPruned` (see
        // [`crate::journal::contiguous::Contiguous::read`]).
        let items = if journal_positions.is_empty() {
            Vec::new()
        } else {
            self.journal
                .read_many(&journal_positions)
                .await
                .map_err(Error::Journal)?
        };

        // The unfilled slots are exactly the journal subsequence, in the order it was built.
        let mut items = items.into_iter();
        Ok(nodes
            .into_iter()
            .map(|node| node.unwrap_or_else(|| items.next().expect("one item per journal read")))
            .collect())
    }

    /// Return the pinned nodes needed to authenticate a lower leaf boundary at `loc`.
    pub async fn pinned_nodes_at(&self, loc: Location<F>) -> Result<Vec<D>, Error<F>> {
        if !loc.is_valid() {
            return Err(Error::LocationOverflow(loc));
        }
        let futs = F::nodes_to_pin(loc)
            .map(|p| async move { self.get_node(p).await?.ok_or(Error::ElementPruned(p)) })
            .collect::<Vec<_>>();
        futures::future::try_join_all(futs).await
    }

    /// Flush all nodes cached in the in-memory structure to the journal without forcing them to
    /// disk. Flushed nodes are pruned from the in-memory structure and remain readable through the
    /// journal, but they are not guaranteed to survive a crash until [Self::sync] is called.
    pub async fn flush(self) -> Result<Self, Error<F>> {
        self.flush_internal().await
    }

    /// Flush all nodes cached in the in-memory structure to the journal and make them durable.
    pub async fn sync(mut self) -> Result<Self, Error<F>> {
        self = self.flush_internal().await?;

        // Observe pending sync failures and persist nodes from this or earlier flushes.
        if self.journal_dirty {
            self.journal = self.journal.sync().await?;
            self.journal_dirty = false;
        }

        Ok(self)
    }

    /// Flush all nodes cached in the in-memory structure to the journal and begin making them
    /// durable, returning a completion handle.
    ///
    /// The handle covers only nodes flushed so far. A later [Self::sync] still performs a full
    /// durable sync.
    pub async fn start_sync(mut self) -> Result<(Self, Handle<()>), Error<F>> {
        self = self.flush_internal().await?;
        let (journal, handle) = self.journal.start_sync().await?;
        self.journal = journal;
        self.journal_dirty = true;
        Ok((self, handle))
    }

    /// Append nodes cached in the in-memory structure that are missing from the journal, then
    /// prune them from the in-memory structure. Sets [Self::journal_dirty] when nodes are
    /// appended.
    async fn flush_internal(mut self) -> Result<Self, Error<F>> {
        let journal_size = Position::<F>::new(self.journal.size());

        // Encode the nodes missing from the journal directly to bytes and snapshot the pinned
        // node set for the current pruning boundary.
        let (sync_target_leaves, encoded, pinned_nodes) = {
            let size = self.mem.size();
            let sync_target_leaves = self.mem.leaves();

            assert!(
                journal_size <= size,
                "journal size should never exceed in-memory structure size"
            );
            if journal_size == size {
                return Ok(self);
            }

            // Encode the un-journaled tail to an owned buffer before the journal I/O below.
            let (head, tail) = self.mem.nodes_from(journal_size);
            let encoded = self.journal.prepare_append(Many::Nested(&[head, tail]));

            // Recompute pinned nodes since we'll need to repopulate the cache after it is cleared
            // by pruning the mem.
            let prune_loc = Location::try_from(self.pruned_to_pos).expect("valid pruned_to_pos");
            let mut pinned_nodes = BTreeMap::new();
            for pos in F::nodes_to_pin(prune_loc) {
                let digest = self.mem.get_node_unchecked(pos);
                pinned_nodes.insert(pos, *digest);
            }

            (sync_target_leaves, encoded, pinned_nodes)
        };

        // Append missing nodes to the journal.
        (self.journal, _) = self.journal.append_prepared(encoded).await?;
        self.journal_dirty = true;

        // Now that the missing nodes are readable from the journal, it's safe to prune them from
        // the mem. We prune to the previously captured leaf count.
        let mem = Arc::make_mut(&mut self.mem);
        mem.prune(sync_target_leaves)
            .expect("captured leaves is in bounds");
        mem.add_pinned_nodes(pinned_nodes);

        Ok(self)
    }

    /// Prune all nodes up to but not including the given leaf location and update the pinned nodes.
    ///
    /// This implementation ensures that no failure can leave the structure in an unrecoverable
    /// state, requiring it sync the structure to write any potential unsynced updates.
    ///
    /// Returns [Error::LocationOverflow] if `loc` exceeds [Family::MAX_LEAVES].
    /// Returns [Error::LeafOutOfBounds] if `loc` exceeds the current leaf count.
    pub async fn prune(mut self, loc: Location<F>) -> Result<Self, Error<F>> {
        let pos = Position::try_from(loc)?;
        if loc > self.mem.leaves() {
            return Err(Error::LeafOutOfBounds(loc));
        }
        if pos <= self.pruned_to_pos {
            return Ok(self);
        }

        // Flush items cached in the mem to disk to ensure the current state is recoverable.
        self = self.sync().await?;

        // Update metadata to reflect the desired pruning boundary, allowing for recovery in the
        // event of a pruning failure.
        let pinned_nodes;
        (self, pinned_nodes) = self.update_metadata(pos).await?;

        (self.journal, _) = self.journal.prune(*pos).await?;
        Arc::make_mut(&mut self.mem).add_pinned_nodes(pinned_nodes);
        self.pruned_to_pos = pos;

        Ok(self)
    }

    /// Compute the root of the structure using `inactive_peaks` and the bagging carried by `hasher`.
    pub fn root(
        &self,
        hasher: &impl Hasher<F, Digest = D>,
        inactive_peaks: usize,
    ) -> Result<D, Error<F>> {
        self.mem.root(hasher, inactive_peaks)
    }

    /// Prune as many nodes as possible, leaving behind at most items_per_blob nodes in the current
    /// blob.
    pub async fn prune_all(mut self) -> Result<Self, Error<F>> {
        let leaves = self.mem.leaves();
        if leaves != 0 {
            self = self.prune(leaves).await?;
        }
        Ok(self)
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
    pub async fn simulate_partial_sync(mut self, write_limit: usize) -> Result<(), Error<F>> {
        if write_limit == 0 {
            return Ok(());
        }

        let journal_size = Position::<F>::new(self.journal.size());

        // Write the nodes cached in the memory-resident structure to the journal, aborting after
        // write_count nodes have been written.
        let mut written_count = 0usize;
        for i in *journal_size..*self.mem.size() {
            let node = *self.mem.get_node_unchecked(Position::new(i));
            (self.journal, _) = self.journal.append(&node).await?;
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
        self.mem.pinned_nodes()
    }

    #[cfg(test)]
    /// Simulate a crash after pruning metadata is written but before the journal is pruned.
    pub async fn simulate_pruning_failure(mut self, prune_to: Location<F>) -> Result<(), Error<F>> {
        let prune_to_pos = Position::try_from(prune_to)?;
        assert!(prune_to_pos <= self.mem.size());

        // Flush items cached in the mem to disk to ensure the current state is recoverable.
        self = self.sync().await?;

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
    pub fn apply_batch(
        mut self,
        batch: &batch::MerkleizedBatch<F, D, S>,
    ) -> Result<Self, Error<F>> {
        Arc::make_mut(&mut self.mem).apply_batch(batch)?;
        Ok(self)
    }

    /// Create an owned [`batch::MerkleizedBatch`] representing the current committed state.
    ///
    /// The batch has no data (the committed items are on disk, not in memory).
    /// This is the starting point for building owned batch chains.
    pub(crate) fn to_batch(&self) -> Arc<batch::MerkleizedBatch<F, D, S>> {
        batch::MerkleizedBatch::from_mem_with_strategy(&self.mem, self.strategy.clone())
    }

    /// Borrow the committed Mem for the duration of the closure.
    pub fn with_mem<R>(&self, f: impl FnOnce(&Mem<F, D>) -> R) -> R {
        f(&self.mem)
    }

    /// Return a zero-copy, immutable snapshot of the committed Mem.
    ///
    /// The snapshot never observes later mutations: mutators copy-on-write while a snapshot is
    /// alive. Use this to move committed node fallback into a job running off the calling task
    /// (see [`Merkle::mem`]); prefer [`Merkle::with_mem`] when a borrow suffices.
    pub(crate) fn snapshot(&self) -> Arc<Mem<F, D>> {
        Arc::clone(&self.mem)
    }

    /// Create a new speculative batch with this structure as its parent.
    pub fn new_batch(&self) -> UnmerkleizedBatch<F, D, S> {
        UnmerkleizedBatch {
            inner: self.mem.new_batch_with_strategy(self.strategy.clone()),
        }
    }

    /// Return a reference to the merkleization strategy.
    pub const fn strategy(&self) -> &S {
        &self.strategy
    }

    /// Return an inclusion proof for the element at the location `loc` against a historical
    /// state with `leaves` leaves.
    ///
    /// The proof commits to `inactive_peaks`; peak bagging is selected by `hasher`.
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
    /// `leaves` leaves.
    ///
    /// The proof commits to `inactive_peaks`; peak bagging is selected by `hasher`.
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
    /// the current root.
    ///
    /// The proof commits to `inactive_peaks`; peak bagging is selected by `hasher`.
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

    /// Return an inclusion proof for the elements within the specified location range.
    ///
    /// The proof commits to `inactive_peaks`; peak bagging is selected by `hasher`.
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

/// The [`Readable`] implementation for the full structure operates only on the in-memory
/// portion. After [`Merkle::sync`], nodes flushed to the journal are no longer accessible
/// through this interface, even though [`Merkle::bounds`] still reports them as retained.
impl<F: Family, E: Context, D: Digest, S: Strategy> Readable for Merkle<F, E, D, S> {
    type Family = F;
    type Digest = D;

    fn size(&self) -> Position<F> {
        self.size()
    }

    fn get_node(&self, pos: Position<F>) -> Option<D> {
        self.mem.get_node(pos)
    }
}

impl<F: Family, E: Context, D: Digest, S: Strategy> crate::merkle::storage::Storage<F>
    for Merkle<F, E, D, S>
{
    type Digest = D;

    fn size(&self) -> Position<F> {
        self.size()
    }

    async fn get_node(&self, position: Position<F>) -> Result<Option<D>, Error<F>> {
        Self::get_node(self, position).await
    }

    async fn get_nodes(&self, positions: &[Position<F>]) -> Result<Vec<D>, Error<F>> {
        Self::get_nodes(self, positions).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        journal::contiguous::fixed::{Config as JConfig, Journal},
        merkle::{
            Bagging::ForwardFold, Location, LocationRangeExt as _, Position, Proof,
            hasher::Standard, mmb, mmr,
        },
        metadata::{Config as MConfig, Metadata},
    };
    use commonware_cryptography::{
        Hasher as _, Sha256,
        sha256::{self, Digest},
    };
    use commonware_macros::test_traced;
    use commonware_parallel::Sequential;
    use commonware_runtime::{
        Blob as _, BufferPooler, Runner, Storage as _, Supervisor as _,
        buffer::paged::CacheRef,
        deterministic,
        mocks::{
            DelayedSyncContext, PendingSyncs, RecordingContext, drive_pending_syncs,
            fail_pending_syncs, next_pending_sync,
        },
    };
    use commonware_utils::{NZU16, NZU64, NZUsize, non_empty_range, sequence::prefixed_u64::U64};
    use futures::FutureExt as _;
    use std::{
        collections::BTreeMap,
        future::{Future as _, poll_fn},
        num::{NonZeroU16, NonZeroUsize},
        task::Poll,
    };

    fn test_digest(v: usize) -> Digest {
        Sha256::hash(&[&v.to_be_bytes()])
    }

    const PAGE_SIZE: NonZeroU16 = NZU16!(111);
    const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(5);

    fn test_config(pooler: &impl BufferPooler) -> Config<Sequential> {
        Config {
            journal_partition: "journal-partition".into(),
            metadata_partition: "metadata-partition".into(),
            items_per_blob: NZU64!(7),
            write_buffer: NZUsize!(1024),
            replay_buffer: NZUsize!(1024),
            strategy: Sequential,
            page_cache: CacheRef::from_pooler(pooler, PAGE_SIZE, PAGE_CACHE_SIZE),
        }
    }

    async fn empty_journal_rejects_pruned_metadata<F: Family>(context: deterministic::Context) {
        let cfg = test_config(&context);
        let metadata = Metadata::<_, U64, Vec<u8>>::init(
            context.child("metadata"),
            MConfig {
                partition: cfg.metadata_partition.clone(),
                codec_config: ((0..).into(), ()),
            },
        )
        .await
        .unwrap();
        metadata
            .put_sync(U64::new(PRUNED_TO_PREFIX, 0), 1u64.to_be_bytes().to_vec())
            .await
            .unwrap();
        let hasher: Standard<Sha256> = Standard::new(ForwardFold);
        let result =
            Merkle::<F, _, Digest, Sequential>::init(context.child("open"), &hasher, cfg).await;
        assert!(matches!(result, Err(Error::MissingNode(_))));
    }

    #[test]
    fn test_empty_journal_rejects_pruned_metadata_mmr() {
        deterministic::Runner::default()
            .start(empty_journal_rejects_pruned_metadata::<mmr::Family>);
    }

    #[test]
    fn test_empty_journal_rejects_pruned_metadata_mmb() {
        deterministic::Runner::default()
            .start(empty_journal_rejects_pruned_metadata::<mmb::Family>);
    }

    async fn full_empty_inner<F: Family>(context: deterministic::Context) {
        let hasher: Standard<Sha256> = Standard::new(ForwardFold);
        let mut mmr = Merkle::<F, _, Digest, Sequential>::init(
            context.child("first"),
            &hasher,
            test_config(&context),
        )
        .await
        .unwrap();
        assert_eq!(mmr.size(), 0);
        assert!(mmr.get_node(Position::<F>::new(0)).await.is_err());
        let bounds = mmr.bounds();
        assert!(bounds.is_empty());
        mmr = mmr.prune_all().await.unwrap();
        assert_eq!(bounds.start, 0);
        mmr = mmr.prune(Location::<F>::new(0)).await.unwrap();
        mmr = mmr.sync().await.unwrap();
        drop(mmr);

        // Reopen the same partitions.
        let mut mmr = Merkle::<F, _, Digest, Sequential>::init(
            context.child("reopen"),
            &hasher,
            test_config(&context),
        )
        .await
        .unwrap();
        let batch = mmr.new_batch().add(&hasher, &test_digest(0));
        let batch = mmr.with_mem(|mem| batch.merkleize(mem, &hasher));
        mmr = mmr.apply_batch(&batch).unwrap();
        assert_eq!(mmr.size(), 1);
        mmr = mmr.sync().await.unwrap();
        assert!(mmr.get_node(Position::<F>::new(0)).await.is_ok());
        drop(mmr);
        mmr = Merkle::<F, _, Digest, Sequential>::init_at_most(
            context.child("cap_empty"),
            &hasher,
            test_config(&context),
            Location::new(0),
        )
        .await
        .unwrap();
        assert_eq!(mmr.size(), 0);
        mmr.sync().await.unwrap();

        let mut mmr = Merkle::<F, _, Digest, Sequential>::init(
            context.child("second"),
            &hasher,
            test_config(&context),
        )
        .await
        .unwrap();
        assert_eq!(mmr.size(), 0);

        let empty_proof = Proof::<F, Digest>::default();
        let hasher: Standard<Sha256> = Standard::new(ForwardFold);
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
        mmr = mmr.apply_batch(&batch).unwrap();
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
    fn test_full_sync_observes_clean_start_sync_failure() {
        deterministic::Runner::default().start(|context| async move {
            let pending = PendingSyncs::default();
            let hasher: Standard<Sha256> = Standard::new(ForwardFold);
            let cfg = test_config(&context);
            let context = DelayedSyncContext {
                inner: context,
                pending: pending.clone(),
            };
            let merkle = drive_pending_syncs(
                &pending,
                Merkle::<mmr::Family, _, Digest, Sequential>::init(
                    context.child("seed"),
                    &hasher,
                    cfg.clone(),
                ),
            )
            .await
            .unwrap();

            // Complete the data sync after the checkpoint has sampled its durable boundary.
            let batch = merkle.new_batch().add(&hasher, &test_digest(0));
            let batch = merkle.with_mem(|mem| batch.merkleize(mem, &hasher));
            let merkle = merkle.apply_batch(&batch).unwrap();
            let (merkle, handle) = merkle.start_sync().await.unwrap();
            assert!(!pending.lock().is_empty());
            drive_pending_syncs(&pending, handle).await.unwrap();
            drop(merkle);

            let merkle = drive_pending_syncs(
                &pending,
                Merkle::<mmr::Family, _, Digest, Sequential>::init(
                    context.child("reopen"),
                    &hasher,
                    cfg,
                ),
            )
            .await
            .unwrap();

            // The reopened tree has no new nodes, but a started sync can still fail.
            assert!(!merkle.journal_dirty);
            let (merkle, handle) = merkle.start_sync().await.unwrap();
            assert!(!pending.lock().is_empty());
            fail_pending_syncs(&pending);
            drop(handle);

            // Full sync must report a failure from an unobserved completion handle.
            let error = merkle.sync().await.expect_err("sync failure was lost");
            assert!(matches!(
                error,
                Error::Journal(JError::Metadata(crate::metadata::Error::Runtime(_)))
            ));
        });
    }

    /// Build a tree whose nodes are all durable while the journal's recovery watermark still
    /// lags. `start_sync` advances the watermark with the durable size sampled before its data
    /// sync completes, so a delayed first sync leaves the watermark at 0. Returns the node count.
    async fn seed_lagging_watermark(context: &deterministic::Context) -> u64 {
        let pending = PendingSyncs::default();
        let hasher: Standard<Sha256> = Standard::new(ForwardFold);
        let delayed = DelayedSyncContext {
            inner: context.child("delayed"),
            pending: pending.clone(),
        };
        let merkle = drive_pending_syncs(
            &pending,
            Merkle::<mmr::Family, _, Digest, Sequential>::init(
                delayed.child("seed"),
                &hasher,
                test_config(context),
            ),
        )
        .await
        .unwrap();
        let mut batch = merkle.new_batch();
        for i in 0..50 {
            batch = batch.add(&hasher, &test_digest(i));
        }
        let batch = merkle.with_mem(|mem| batch.merkleize(mem, &hasher));
        let merkle = merkle.apply_batch(&batch).unwrap();
        let size = *merkle.size();

        // Flush first so the appends' own blob syncs complete, then start a sync whose data
        // fsync is still in flight when the watermark samples the durable size.
        let merkle = drive_pending_syncs(&pending, merkle.flush()).await.unwrap();
        let (merkle, handle) = merkle.start_sync().await.unwrap();
        drive_pending_syncs(&pending, handle).await.unwrap();
        drop(merkle);

        let lagging = persisted_watermark(context).await.unwrap();
        assert!(
            lagging < size,
            "watermark {lagging} covers all {size} nodes"
        );
        size
    }

    /// Read the recovery watermark persisted for the test journal partition.
    async fn persisted_watermark(context: &deterministic::Context) -> Option<u64> {
        Journal::<_, Digest>::persisted_watermark(
            context.child("probe"),
            &test_config(context).journal_partition,
        )
        .await
        .unwrap()
    }

    #[test_traced]
    fn test_init_sync_publishes_watermark() {
        deterministic::Runner::default().start(|context| async move {
            let size = seed_lagging_watermark(&context).await;

            // Reusing durable nodes must publish the recovery watermark without a later data sync.
            let leaves = Location::<mmr::Family>::try_from(Position::new(size)).unwrap();
            let merkle = Merkle::<mmr::Family, _, Digest, Sequential>::init_sync(
                context.child("sync"),
                SyncConfig {
                    config: test_config(&context),
                    range: non_empty_range!(Location::new(0), leaves),
                    pinned_nodes: None,
                },
            )
            .await
            .unwrap();
            assert_eq!(*merkle.size(), size);
            drop(merkle);

            assert_eq!(persisted_watermark(&context).await, Some(size));
        });
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
        let hasher = Standard::<Sha256>::new(ForwardFold);
        let mut mmr = Merkle::<F, _, Digest, Sequential>::init(
            context.child("oob_prune"),
            &hasher,
            test_config(&context),
        )
        .await
        .unwrap();

        let batch = mmr.new_batch().add(&hasher, &test_digest(0));
        let batch = mmr.with_mem(|mem| batch.merkleize(mem, &hasher));
        mmr = mmr.apply_batch(&batch).unwrap();

        assert!(matches!(
            mmr.prune(Location::<F>::new(2)).await,
            Err(Error::LeafOutOfBounds(loc)) if loc == Location::<F>::new(2)
        ));
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

    async fn full_initialization_bounds_preserve_state_inner<F: Family>(
        context: deterministic::Context,
    ) {
        let hasher: Standard<Sha256> = Standard::new(ForwardFold);

        // A cap below the pruning boundary fails without changing the retained tree.
        let element_pruned_context = context.child("element_pruned_case");
        let mut mmr = Merkle::<F, _, Digest, Sequential>::init(
            element_pruned_context.child("element_pruned"),
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
        mmr = mmr.apply_batch(&batch).unwrap();
        let mmr = mmr.prune(Location::<F>::new(8)).await.unwrap();
        let leaves_before = mmr.leaves();
        drop(mmr);
        assert!(matches!(
            Merkle::<F, _, Digest, Sequential>::init_at_most(
                element_pruned_context.child("cap"),
                &hasher,
                test_config(&element_pruned_context),
                Location::new(7)
            )
            .await,
            Err(Error::ElementPruned(_))
        ));

        // Reopening after the rejected cap preserves the synced tree.
        let mmr = Merkle::<F, _, Digest, Sequential>::init(
            element_pruned_context.child("element_pruned_reopen"),
            &hasher,
            test_config(&element_pruned_context),
        )
        .await
        .unwrap();
        assert_eq!(mmr.leaves(), leaves_before);
        mmr.destroy().await.unwrap();

        // A bound above the end preserves the complete tree, including after another open.
        let bounded_context = context.child("overshooting_cap");
        let cfg = Config {
            journal_partition: "overshooting-journal-partition".into(),
            metadata_partition: "overshooting-metadata-partition".into(),
            ..test_config(&bounded_context)
        };
        let mut mmr = Merkle::<F, _, Digest, Sequential>::init(
            bounded_context.child("open"),
            &hasher,
            cfg.clone(),
        )
        .await
        .unwrap();
        let mut batch = mmr.new_batch();
        for i in 0u64..8 {
            batch = batch.add(&hasher, &i.to_be_bytes());
        }
        let batch = mmr.with_mem(|mem| batch.merkleize(mem, &hasher));
        mmr = mmr.apply_batch(&batch).unwrap();
        let root = mmr.root(&hasher, 0).unwrap();
        _ = mmr.sync().await.unwrap();
        let mmr = Merkle::<F, _, Digest, Sequential>::init_at_most(
            bounded_context.child("cap"),
            &hasher,
            cfg.clone(),
            Location::new(u64::MAX),
        )
        .await
        .unwrap();
        assert_eq!(mmr.leaves(), Location::new(8));
        assert_eq!(mmr.root(&hasher, 0).unwrap(), root);
        drop(mmr);
        let mmr = Merkle::<F, _, Digest, Sequential>::init(
            bounded_context.child("reopen"),
            &hasher,
            cfg.clone(),
        )
        .await
        .unwrap();
        assert_eq!(mmr.leaves(), Location::new(8));
        assert_eq!(mmr.root(&hasher, 0).unwrap(), root);
        drop(mmr);

        // A zero cap publishes and preserves an empty tree.
        let mmr = Merkle::<F, _, Digest, Sequential>::init_at_most(
            bounded_context.child("empty"),
            &hasher,
            cfg.clone(),
            Location::new(0),
        )
        .await
        .unwrap();
        assert_eq!(mmr.leaves(), Location::new(0));
        drop(mmr);
        let mmr = Merkle::<F, _, Digest, Sequential>::init(
            bounded_context.child("empty_reopen"),
            &hasher,
            cfg,
        )
        .await
        .unwrap();
        assert_eq!(mmr.leaves(), Location::new(0));
        mmr.destroy().await.unwrap();
    }

    #[test_traced]
    fn test_full_initialization_bounds_preserve_state_mmr() {
        let executor = deterministic::Runner::default();
        executor.start(full_initialization_bounds_preserve_state_inner::<mmr::Family>);
    }

    #[test_traced]
    fn test_full_initialization_bounds_preserve_state_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(full_initialization_bounds_preserve_state_inner::<mmb::Family>);
    }

    async fn full_basic_inner<F: Family>(context: deterministic::Context) {
        let hasher: Standard<Sha256> = Standard::new(ForwardFold);
        let cfg = test_config(&context);
        let mut mmr = Merkle::<F, _, Digest, Sequential>::init(context, &hasher, cfg)
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
        mmr = mmr.apply_batch(&batch).unwrap();
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
        mmr = mmr.sync().await.unwrap();

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

    /// `get_nodes` must agree with per-position `get_node` on every available position
    /// (journal-resident and memory-resident) and reject the positions `get_node` reports
    /// as absent.
    async fn full_get_nodes_matches_get_node_inner<F: Family>(context: deterministic::Context) {
        let hasher: Standard<Sha256> = Standard::new(ForwardFold);
        let cfg = test_config(&context);
        let mut mmr = Merkle::<F, _, Digest, Sequential>::init(context, &hasher, cfg)
            .await
            .unwrap();

        // Flushed leaves (journal-resident after sync), a pruned prefix, then unflushed
        // leaves on top (memory-resident).
        const LEAF_COUNT: usize = 200;
        let mut batch = mmr.new_batch();
        for i in 0..LEAF_COUNT {
            batch = batch.add(&hasher, &test_digest(i));
        }
        let batch = mmr.with_mem(|mem| batch.merkleize(mem, &hasher));
        mmr = mmr.apply_batch(&batch).unwrap();
        mmr = mmr.sync().await.unwrap();
        mmr = mmr.prune(Location::<F>::new(50)).await.unwrap();
        let mut batch = mmr.new_batch();
        for i in LEAF_COUNT..LEAF_COUNT + 10 {
            batch = batch.add(&hasher, &test_digest(i));
        }
        let batch = mmr.with_mem(|mem| batch.merkleize(mem, &hasher));
        mmr = mmr.apply_batch(&batch).unwrap();

        // Partition by what `get_node` reports, so both APIs are judged against the same
        // notion of availability.
        let all: Vec<Position<F>> = (0..*mmr.size()).map(Position::new).collect();
        let mut absent = Vec::new();
        let mut available = Vec::new();
        for &position in &all {
            match mmr.get_node(position).await.unwrap() {
                Some(node) => available.push((position, node)),
                None => absent.push(position),
            }
        }
        assert!(!absent.is_empty(), "expected some pruned positions");
        assert!(!available.is_empty(), "expected some available positions");

        // Spanning the pruning boundary is an error naming a position `get_node` calls absent.
        match mmr.get_nodes(&all).await {
            Err(Error::ElementPruned(position)) => {
                assert!(absent.contains(&position), "position {position}")
            }
            other => panic!("expected ElementPruned, got {other:?}"),
        }

        // Every available position, then a sparse subset (slot correspondence), then empty.
        let positions: Vec<Position<F>> = available.iter().map(|&(pos, _)| pos).collect();
        let batched = mmr.get_nodes(&positions).await.unwrap();
        assert_eq!(batched.len(), available.len());
        for (slot, &(position, node)) in available.iter().enumerate() {
            assert_eq!(batched[slot], node, "position {position}");
        }

        let sparse: Vec<Position<F>> = positions.iter().copied().step_by(7).collect();
        let batched = mmr.get_nodes(&sparse).await.unwrap();
        for (slot, &position) in sparse.iter().enumerate() {
            let single = mmr.get_node(position).await.unwrap().unwrap();
            assert_eq!(batched[slot], single, "position {position}");
        }

        assert!(mmr.get_nodes(&[]).await.unwrap().is_empty());
        mmr.destroy().await.unwrap();
    }

    #[test_traced]
    fn test_full_get_nodes_matches_get_node_mmr() {
        let executor = deterministic::Runner::default();
        executor.start(full_get_nodes_matches_get_node_inner::<mmr::Family>);
    }

    #[test_traced]
    fn test_full_get_nodes_matches_get_node_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(full_get_nodes_matches_get_node_inner::<mmb::Family>);
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

    /// Flush moves cached nodes into the journal and prunes them from memory, preserving reads,
    /// proofs, and the root.
    async fn full_flush_inner<F: Family>(context: deterministic::Context) {
        let hasher: Standard<Sha256> = Standard::new(ForwardFold);
        let mut mmr = Merkle::<F, _, Digest, Sequential>::init(
            context.child("first"),
            &hasher,
            test_config(&context),
        )
        .await
        .unwrap();

        const LEAF_COUNT: usize = 100;
        let mut leaves = Vec::with_capacity(LEAF_COUNT);
        for i in 0..LEAF_COUNT {
            leaves.push(test_digest(i));
        }
        let mut batch = mmr.new_batch();
        for leaf in &leaves {
            batch = batch.add(&hasher, leaf);
        }
        let batch = mmr.with_mem(|mem| batch.merkleize(mem, &hasher));
        mmr = mmr.apply_batch(&batch).unwrap();
        let expected_size = Position::<F>::try_from(Location::<F>::new(LEAF_COUNT as u64)).unwrap();
        let root = mmr.root(&hasher, 0).unwrap();

        // Flush writes all cached nodes to the journal and prunes them from the mem.
        mmr = mmr.flush().await.unwrap();
        assert_eq!(Position::<F>::new(mmr.journal.size()), expected_size);
        assert_eq!(mmr.size(), expected_size);
        assert_eq!(
            mmr.with_mem(|mem| mem.bounds().start),
            Location::<F>::new(LEAF_COUNT as u64)
        );

        // Flushing again is a no-op.
        mmr = mmr.flush().await.unwrap();
        assert_eq!(Position::<F>::new(mmr.journal.size()), expected_size);

        // Flushed nodes remain readable and provable, and the root is unchanged.
        assert_eq!(mmr.root(&hasher, 0).unwrap(), root);
        const TEST_ELEMENT: usize = 42;
        let loc: Location<F> = Location::new(TEST_ELEMENT as u64);
        let proof = mmr.proof(&hasher, loc, 0).await.unwrap();
        assert!(proof.verify_element_inclusion(&hasher, &leaves[TEST_ELEMENT], loc, &root));

        // Sync after flush succeeds (and must fsync the journal even though there is nothing
        // left to flush).
        mmr = mmr.sync().await.unwrap();

        mmr.destroy().await.unwrap();
    }

    #[test_traced]
    fn test_full_flush_mmr() {
        let executor = deterministic::Runner::default();
        executor.start(full_flush_inner::<mmr::Family>);
    }

    #[test_traced]
    fn test_full_flush_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(full_flush_inner::<mmb::Family>);
    }

    /// Flushed-but-unsynced nodes in the tail blob are lost on a crash, while synced nodes
    /// survive: the durability barrier comes from `sync`, not `flush`.
    fn full_flush_crash_inner<F: Family>() {
        let hasher: Standard<Sha256> = Standard::new(ForwardFold);

        // Phase 1: durably sync a first batch of leaves, flush (but don't sync) a second batch into
        // the tail blob, then simulate an unclean shutdown.
        let executor = deterministic::Runner::default();
        let (synced_size, checkpoint) = executor.start_and_recover(|context| async move {
            let hasher: Standard<Sha256> = Standard::new(ForwardFold);
            let mut mmr = Merkle::<F, _, Digest, Sequential>::init(
                context.child("first"),
                &hasher,
                Config {
                    // 512 items per blob keeps both batches in the tail blob: a rollover would
                    // fsync the sealed predecessor and defeat the flushed-but-unsynced scenario.
                    items_per_blob: NZU64!(512),
                    ..test_config(&context)
                },
            )
            .await
            .unwrap();

            let mut batch = mmr.new_batch();
            for i in 0..50usize {
                batch = batch.add(&hasher, &test_digest(i));
            }
            let batch = mmr.with_mem(|mem| batch.merkleize(mem, &hasher));
            mmr = mmr.apply_batch(&batch).unwrap();
            let mut mmr = mmr.sync().await.unwrap();
            let synced_size = mmr.size();

            let mut batch = mmr.new_batch();
            for i in 50..100usize {
                batch = batch.add(&hasher, &test_digest(i));
            }
            let batch = mmr.with_mem(|mem| batch.merkleize(mem, &hasher));
            mmr = mmr.apply_batch(&batch).unwrap();
            mmr = mmr.flush().await.unwrap();
            assert_eq!(Position::<F>::new(mmr.journal.size()), mmr.size());

            synced_size
        });

        // Phase 2: recover. Only the synced prefix survives.
        let executor = deterministic::Runner::from(checkpoint);
        executor.start(|context| async move {
            let mmr = Merkle::<F, _, Digest, Sequential>::init(
                context.child("second"),
                &hasher,
                Config {
                    // 512 items per blob keeps both batches in the tail blob: a rollover would
                    // fsync the sealed predecessor and defeat the flushed-but-unsynced scenario.
                    items_per_blob: NZU64!(512),
                    ..test_config(&context)
                },
            )
            .await
            .unwrap();
            assert_eq!(mmr.size(), synced_size);
        });
    }

    #[test_traced]
    fn test_full_flush_crash_recovery_mmr() {
        full_flush_crash_inner::<mmr::Family>();
    }

    #[test_traced]
    fn test_full_flush_crash_recovery_mmb() {
        full_flush_crash_inner::<mmb::Family>();
    }

    /// A sync after a flush must make the flushed nodes durable, even though the flush left
    /// nothing further to write from memory.
    fn full_flush_then_sync_crash_inner<F: Family>() {
        let hasher: Standard<Sha256> = Standard::new(ForwardFold);

        // Phase 1: flush a batch of leaves, then sync with nothing left to flush, then simulate
        // an unclean shutdown.
        let executor = deterministic::Runner::default();
        let (full_size, checkpoint) = executor.start_and_recover(|context| async move {
            let hasher: Standard<Sha256> = Standard::new(ForwardFold);
            let mut mmr = Merkle::<F, _, Digest, Sequential>::init(
                context.child("first"),
                &hasher,
                test_config(&context),
            )
            .await
            .unwrap();

            let mut batch = mmr.new_batch();
            for i in 0..100usize {
                batch = batch.add(&hasher, &test_digest(i));
            }
            let batch = mmr.with_mem(|mem| batch.merkleize(mem, &hasher));
            mmr = mmr.apply_batch(&batch).unwrap();
            mmr = mmr.flush().await.unwrap();
            let mmr = mmr.sync().await.unwrap();

            mmr.size()
        });

        // Phase 2: recover. Everything survives.
        let executor = deterministic::Runner::from(checkpoint);
        executor.start(|context| async move {
            let mmr = Merkle::<F, _, Digest, Sequential>::init(
                context.child("second"),
                &hasher,
                test_config(&context),
            )
            .await
            .unwrap();
            assert_eq!(mmr.size(), full_size);
        });
    }

    #[test_traced]
    fn test_full_flush_then_sync_crash_recovery_mmr() {
        full_flush_then_sync_crash_inner::<mmr::Family>();
    }

    #[test_traced]
    fn test_full_flush_then_sync_crash_recovery_mmb() {
        full_flush_then_sync_crash_inner::<mmb::Family>();
    }

    /// Generates a stateful structure, simulates a crash that wrote a leaf but not its parent
    /// nodes, and confirms we appropriately recover to a valid state.
    async fn full_recovery_inner<F: Family>(context: deterministic::Context) {
        use crate::journal::contiguous::fixed::{Config as JConfig, Journal};

        let hasher: Standard<Sha256> = Standard::new(ForwardFold);
        let mut mmr = Merkle::<F, _, Digest, Sequential>::init(
            context.child("first"),
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
        mmr = mmr.apply_batch(&batch).unwrap();
        let expected_size = Position::<F>::try_from(Location::<F>::new(LEAF_COUNT as u64)).unwrap();
        assert_eq!(mmr.size(), expected_size);
        let mmr = mmr.sync().await.unwrap();
        drop(mmr);

        // Simulate a crash that wrote a leaf but not its parent nodes by appending one
        // extra digest to the journal. This creates an invalid structure size.
        {
            let journal: Journal<_, Digest> = Journal::init(
                context.child("corrupt"),
                JConfig {
                    partition: "journal-partition".into(),
                    items_per_blob: NZU64!(7),
                    write_buffer: NZUsize!(1024),
                    replay_buffer: NZUsize!(1024),
                    page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
                },
            )
            .await
            .unwrap();
            assert_eq!(journal.size(), expected_size);
            let (journal, _) = journal.append(&Sha256::hash(&[b"orphan"])).await.unwrap();
            let journal = journal.sync().await.unwrap();
            assert_eq!(journal.size(), expected_size + 1);
        }

        let mmr = Merkle::<F, _, Digest, Sequential>::init(
            context.child("second"),
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
        let mmr = Merkle::<F, _, Digest, Sequential>::init(
            context.child("third"),
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
        let hasher: Standard<Sha256> = Standard::new(ForwardFold);
        // make sure pruning doesn't break root computation, adding of new nodes, etc.
        const LEAF_COUNT: usize = 2000;
        let cfg_pruned = test_config(&context);
        let mut pruned_mmr = Merkle::<F, _, Digest, Sequential>::init(
            context.child("pruned"),
            &hasher,
            cfg_pruned.clone(),
        )
        .await
        .unwrap();
        let cfg_unpruned = Config {
            journal_partition: "unpruned-journal-partition".into(),
            metadata_partition: "unpruned-metadata-partition".into(),
            items_per_blob: NZU64!(7),
            write_buffer: NZUsize!(1024),
            replay_buffer: NZUsize!(1024),
            strategy: Sequential,
            page_cache: cfg_pruned.page_cache.clone(),
        };
        let mut mmr = Merkle::<F, _, Digest, Sequential>::init(
            context.child("unpruned"),
            &hasher,
            cfg_unpruned,
        )
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
        mmr = mmr.apply_batch(&batch).unwrap();
        let mut batch = pruned_mmr.new_batch();
        for leaf in &leaves {
            batch = batch.add(&hasher, leaf);
        }
        let batch = pruned_mmr.with_mem(|mem| batch.merkleize(mem, &hasher));
        pruned_mmr = pruned_mmr.apply_batch(&batch).unwrap();
        let expected_size = Position::<F>::try_from(Location::<F>::new(LEAF_COUNT as u64)).unwrap();
        assert_eq!(mmr.size(), expected_size);
        assert_eq!(pruned_mmr.size(), expected_size);

        // Prune the structure in increments of 10 making sure the journal is still able to compute
        // roots and accept new elements.
        for i in 0usize..300 {
            let prune_loc = Location::<F>::new(std::cmp::min(i as u64 * 10, *pruned_mmr.leaves()));
            pruned_mmr = pruned_mmr.prune(prune_loc).await.unwrap();
            assert_eq!(prune_loc, pruned_mmr.bounds().start);

            let digest = test_digest(LEAF_COUNT + i);
            leaves.push(digest);
            let last_leaf = leaves.last().unwrap();
            let batch = pruned_mmr.new_batch().add(&hasher, last_leaf);
            let batch = pruned_mmr.with_mem(|mem| batch.merkleize(mem, &hasher));
            pruned_mmr = pruned_mmr.apply_batch(&batch).unwrap();
            let batch = mmr.new_batch().add(&hasher, last_leaf);
            let batch = mmr.with_mem(|mem| batch.merkleize(mem, &hasher));
            mmr = mmr.apply_batch(&batch).unwrap();
            assert_eq!(
                pruned_mmr.root(&hasher, 0).unwrap(),
                mmr.root(&hasher, 0).unwrap()
            );
        }

        // Sync the structures.
        pruned_mmr = pruned_mmr.sync().await.unwrap();
        assert_eq!(
            pruned_mmr.root(&hasher, 0).unwrap(),
            mmr.root(&hasher, 0).unwrap()
        );

        // Sync the structure & reopen.
        pruned_mmr.sync().await.unwrap();
        let mut pruned_mmr = Merkle::<F, _, Digest, Sequential>::init(
            context.child("pruned_reopen"),
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
        pruned_mmr = pruned_mmr.prune_all().await.unwrap();
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
        mmr = mmr.apply_batch(&batch).unwrap();
        let batch = pruned_mmr
            .new_batch()
            .add(&hasher, &test_digest(LEAF_COUNT));
        let batch = pruned_mmr.with_mem(|mem| batch.merkleize(mem, &hasher));
        pruned_mmr = pruned_mmr.apply_batch(&batch).unwrap();
        assert!(*pruned_mmr.size() % cfg_pruned.items_per_blob != 0);
        pruned_mmr.sync().await.unwrap();
        let mut pruned_mmr = Merkle::<F, _, Digest, Sequential>::init(
            context.child("pruned_reopen").with_attribute("index", 2),
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
        pruned_mmr = pruned_mmr
            .prune(Location::<F>::try_from(size).unwrap() - 1)
            .await
            .unwrap();
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
            pruned_mmr = pruned_mmr.apply_batch(&batch).unwrap();
        }
        pruned_mmr = pruned_mmr.prune_all().await.unwrap();
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
        let hasher: Standard<Sha256> = Standard::new(ForwardFold);
        const LEAF_COUNT: usize = 2000;
        let mut leaves = Vec::with_capacity(LEAF_COUNT);
        let mut mmr = Merkle::<F, _, Digest, Sequential>::init(
            context.child("init"),
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
        mmr = mmr.apply_batch(&batch).unwrap();
        let expected_size = Position::<F>::try_from(Location::<F>::new(LEAF_COUNT as u64)).unwrap();
        assert_eq!(mmr.size(), expected_size);
        let mmr = mmr.sync().await.unwrap();
        drop(mmr);

        // Prune the structure in increments of 50, simulating a partial write after each prune.
        for i in 0usize..200 {
            let mut mmr = Merkle::<F, _, Digest, Sequential>::init(
                context.child("iter").with_attribute("index", i),
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
            mmr = mmr.prune(prune_loc).await.unwrap();

            // add new elements, simulating a partial write after each.
            for j in 0..10 {
                let digest = test_digest(100 * (i + 1) + j);
                leaves.push(digest);
                let batch = mmr
                    .new_batch()
                    .add(&hasher, leaves.last().unwrap())
                    .add(&hasher, leaves.last().unwrap());
                let batch = mmr.with_mem(|mem| batch.merkleize(mem, &hasher));
                mmr = mmr.apply_batch(&batch).unwrap();
                let digest = test_digest(LEAF_COUNT + i);
                leaves.push(digest);
                let batch = mmr
                    .new_batch()
                    .add(&hasher, leaves.last().unwrap())
                    .add(&hasher, leaves.last().unwrap());
                let batch = mmr.with_mem(|mem| batch.merkleize(mem, &hasher));
                mmr = mmr.apply_batch(&batch).unwrap();
            }
            let end_size = mmr.size();
            let total_to_write = (*end_size - *start_size) as usize;
            let partial_write_limit = i % total_to_write;
            mmr.simulate_partial_sync(partial_write_limit)
                .await
                .unwrap();
        }

        let mmr = Merkle::<F, _, Digest, Sequential>::init(
            context.child("final"),
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
        let hasher = Standard::<Sha256>::new(ForwardFold);
        let cfg = test_config(&context);
        let mut mmr = Merkle::<F, _, Digest, Sequential>::init(context, &hasher, cfg)
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
        mmr = mmr.apply_batch(&batch).unwrap();
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
        mmr = mmr.apply_batch(&batch).unwrap();
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
        let hasher = Standard::<Sha256>::new(ForwardFold);
        let mut mmr = Merkle::<F, _, Digest, Sequential>::init(
            context.child("main"),
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
        mmr = mmr.apply_batch(&batch).unwrap();

        // Prune to leaf 16 (position 30)
        let prune_loc = Location::<F>::new(16);
        let mmr = mmr.prune(prune_loc).await.unwrap();

        // Create reference structure for verification to get correct size
        let mut ref_mmr = Merkle::<F, _, Digest, Sequential>::init(
            context.child("ref"),
            &hasher,
            Config {
                journal_partition: "ref-journal-pruned".into(),
                metadata_partition: "ref-metadata-pruned".into(),
                items_per_blob: NZU64!(7),
                write_buffer: NZUsize!(1024),
                replay_buffer: NZUsize!(1024),
                strategy: Sequential,
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
        ref_mmr = ref_mmr.apply_batch(&batch).unwrap();
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
        let hasher = Standard::<Sha256>::new(ForwardFold);

        let mut mmr = Merkle::<F, _, Digest, Sequential>::init(
            context.child("server"),
            &hasher,
            Config {
                journal_partition: "server-journal".into(),
                metadata_partition: "server-metadata".into(),
                items_per_blob: NZU64!(7),
                write_buffer: NZUsize!(1024),
                replay_buffer: NZUsize!(1024),
                strategy: Sequential,
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
        mmr = mmr.apply_batch(&batch).unwrap();

        let range = Location::<F>::new(30)..Location::<F>::new(61);

        // Only apply elements up to end_loc to the reference structure.
        let mut ref_mmr = Merkle::<F, _, Digest, Sequential>::init(
            context.child("client"),
            &hasher,
            Config {
                journal_partition: "client-journal".into(),
                metadata_partition: "client-metadata".into(),
                items_per_blob: NZU64!(7),
                write_buffer: NZUsize!(1024),
                replay_buffer: NZUsize!(1024),
                strategy: Sequential,
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
        ref_mmr = ref_mmr.apply_batch(&batch).unwrap();
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
        let hasher = Standard::<Sha256>::new(ForwardFold);
        let cfg = test_config(&context);
        let mut mmr = Merkle::<F, _, Digest, Sequential>::init(context, &hasher, cfg)
            .await
            .unwrap();

        let element = test_digest(0);
        let batch = mmr.new_batch().add(&hasher, &element);
        let batch = mmr.with_mem(|mem| batch.merkleize(mem, &hasher));
        mmr = mmr.apply_batch(&batch).unwrap();

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
        let hasher = Standard::<Sha256>::new(ForwardFold);

        // Fresh initialization must not reset or remove any journal storage.
        context.storage_fault_config().write().remove_rate =
            Some(commonware_utils::probability!(1.0));
        let sync_cfg = SyncConfig::<F, sha256::Digest, Sequential> {
            config: test_config(&context),
            range: non_empty_range!(Location::<F>::new(0), Location::<F>::new(52)),
            pinned_nodes: None,
        };

        let mut sync_mmr =
            Merkle::<F, _, Digest, Sequential>::init_sync(context.child("storage"), sync_cfg)
                .await
                .unwrap();

        context.storage_fault_config().write().remove_rate = None;

        // Should be fresh structure starting empty
        assert_eq!(sync_mmr.size(), 0);
        let bounds = sync_mmr.bounds();
        assert_eq!(bounds.start, 0);
        assert!(bounds.is_empty());

        // Should be able to add new elements
        let new_element = test_digest(999);
        let batch = sync_mmr.new_batch().add(&hasher, &new_element);
        let batch = sync_mmr.with_mem(|mem| batch.merkleize(mem, &hasher));
        sync_mmr = sync_mmr.apply_batch(&batch).unwrap();

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

    async fn init_sync_empty_at_start_keeps_journal_inner<F: Family>(
        context: deterministic::Context,
    ) {
        let hasher = Standard::<Sha256>::new(ForwardFold);
        let start = Location::<F>::new(16);
        let end = Location::<F>::new(32);
        let prune_pos = Position::try_from(start).unwrap();

        // Take the boundary pins and the expected root from a reference tree of `end` leaves.
        let mut reference_cfg = test_config(&context);
        reference_cfg.journal_partition = "reference-journal".into();
        reference_cfg.metadata_partition = "reference-metadata".into();
        let reference = seed_recovery_tree::<F>(&context, reference_cfg, *end).await;
        let root = reference.root(&hasher, 0).unwrap();
        let pins = reference.pinned_nodes_at(start).await.unwrap();
        reference.destroy().await.unwrap();

        // The first sync resets fresh storage, leaving the node journal empty at the sync start.
        let cfg = test_config(&context);
        let merkle = Merkle::<F, _, Digest, Sequential>::init_sync(
            context.child("first"),
            SyncConfig {
                config: cfg.clone(),
                range: non_empty_range!(start, end),
                pinned_nodes: Some(pins.clone()),
            },
        )
        .await
        .unwrap();
        assert_eq!(merkle.size(), prune_pos);
        drop(merkle);

        // A retry over the same range finds the journal already empty at the sync start and keeps
        // it. Any blob removal would fail.
        context.storage_fault_config().write().remove_rate =
            Some(commonware_utils::probability!(1.0));
        let mut merkle = Merkle::<F, _, Digest, Sequential>::init_sync(
            context.child("retry"),
            SyncConfig {
                config: cfg,
                range: non_empty_range!(start, end),
                pinned_nodes: Some(pins),
            },
        )
        .await
        .unwrap();
        context.storage_fault_config().write().remove_rate = None;
        assert_eq!(merkle.size(), prune_pos);

        // The kept journal extends from the boundary pins to the reference root.
        let mut batch = merkle.new_batch();
        for i in *start..*end {
            batch = batch.add(&hasher, &test_digest(i as usize));
        }
        let batch = merkle.with_mem(|mem| batch.merkleize(mem, &hasher));
        merkle = merkle.apply_batch(&batch).unwrap();
        assert_eq!(merkle.root(&hasher, 0).unwrap(), root);
        merkle.destroy().await.unwrap();
    }

    #[test_traced]
    fn test_init_sync_empty_at_start_keeps_journal_mmr() {
        deterministic::Runner::default()
            .start(init_sync_empty_at_start_keeps_journal_inner::<mmr::Family>);
    }

    #[test_traced]
    fn test_init_sync_empty_at_start_keeps_journal_mmb() {
        deterministic::Runner::default()
            .start(init_sync_empty_at_start_keeps_journal_inner::<mmb::Family>);
    }

    // Test `init_sync` where the persisted structure's persisted nodes match the sync boundaries.
    async fn full_init_sync_nonempty_exact_match_inner<F: Family>(context: deterministic::Context) {
        let hasher = Standard::<Sha256>::new(ForwardFold);

        // Create initial structure with elements.
        let mut mmr = Merkle::<F, _, Digest, Sequential>::init(
            context.child("init"),
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
        mmr = mmr.apply_batch(&batch).unwrap();
        let mmr = mmr.sync().await.unwrap();
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
        let sync_cfg = SyncConfig::<F, sha256::Digest, Sequential> {
            config: test_config(&context),
            range: non_empty_range!(lower_bound_loc, upper_bound_loc),
            pinned_nodes: None,
        };

        let mmr = mmr.sync().await.unwrap();
        drop(mmr);

        let sync_mmr =
            Merkle::<F, _, Digest, Sequential>::init_sync(context.child("sync"), sync_cfg)
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
        let hasher = Standard::<Sha256>::new(ForwardFold);

        // Create initial structure with elements.
        let mut mmr = Merkle::<F, _, Digest, Sequential>::init(
            context.child("init"),
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
        mmr = mmr.apply_batch(&batch).unwrap();
        let mmr = mmr.sync().await.unwrap();
        let mmr = mmr.prune(Location::<F>::new(6)).await.unwrap();

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

        let sync_cfg = SyncConfig::<F, sha256::Digest, Sequential> {
            config: test_config(&context),
            range: non_empty_range!(lower_bound_loc, upper_bound_loc),
            pinned_nodes: None,
        };

        let mmr = mmr.sync().await.unwrap();
        drop(mmr);

        let sync_mmr =
            Merkle::<F, _, Digest, Sequential>::init_sync(context.child("sync"), sync_cfg)
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

    /// Build and sync a complete tree for initialization recovery tests.
    async fn seed_recovery_tree<F: Family>(
        context: &deterministic::Context,
        cfg: Config<Sequential>,
        leaves: u64,
    ) -> Merkle<F, deterministic::Context, Digest, Sequential> {
        let hasher = Standard::<Sha256>::new(ForwardFold);
        let mut merkle =
            Merkle::<F, _, Digest, Sequential>::init(context.child("seed"), &hasher, cfg)
                .await
                .unwrap();
        let mut batch = merkle.new_batch();
        for i in 0..leaves {
            batch = batch.add(&hasher, &test_digest(i as usize));
        }
        let batch = merkle.with_mem(|mem| batch.merkleize(mem, &hasher));
        merkle = merkle.apply_batch(&batch).unwrap();
        merkle.sync().await.unwrap()
    }

    async fn init_sync_recovered_pins_reopen_inner<F: Family>(context: deterministic::Context) {
        let hasher = Standard::<Sha256>::new(ForwardFold);

        // Exercise reset at an exact end and reuse of a retained suffix.
        for (leaves, start, end) in [(16, 16, 32), (100, 32, 128)] {
            let context = context.child(if leaves == 16 { "reset" } else { "reuse" });
            let cfg = test_config(&context);
            let merkle = seed_recovery_tree::<F>(&context, cfg.clone(), leaves).await;
            let root = merkle.root(&hasher, 0).unwrap();
            drop(merkle);

            // Persist the synchronization boundary using pins recovered from local storage.
            let merkle = Merkle::<F, _, Digest, Sequential>::init_sync(
                context.child("sync"),
                SyncConfig {
                    config: cfg.clone(),
                    range: non_empty_range!(Location::new(start), Location::new(end)),
                    pinned_nodes: None,
                },
            )
            .await
            .unwrap();
            assert_eq!(merkle.root(&hasher, 0).unwrap(), root);
            _ = merkle.sync().await.unwrap();

            // Reopen the synchronized prefix and extend it by one leaf.
            let merkle = Merkle::<F, _, Digest, Sequential>::init(
                context.child("reopen"),
                &hasher,
                cfg.clone(),
            )
            .await
            .unwrap();
            assert_eq!(merkle.bounds(), Location::new(start)..Location::new(leaves));
            assert_eq!(merkle.root(&hasher, 0).unwrap(), root);
            let batch = merkle
                .new_batch()
                .add(&hasher, &test_digest(leaves as usize));
            let batch = merkle.with_mem(|mem| batch.merkleize(mem, &hasher));
            let merkle = merkle.apply_batch(&batch).unwrap();
            let appended_root = merkle.root(&hasher, 0).unwrap();
            _ = merkle.sync().await.unwrap();

            // A second reopen must recover the extended root.
            let merkle = Merkle::<F, _, Digest, Sequential>::init(
                context.child("after_append"),
                &hasher,
                cfg,
            )
            .await
            .unwrap();
            assert_eq!(merkle.leaves(), leaves + 1);
            assert_eq!(merkle.root(&hasher, 0).unwrap(), appended_root);
            merkle.destroy().await.unwrap();
        }
    }

    #[test]
    fn test_init_sync_recovered_pins_reopen_mmr() {
        deterministic::Runner::default()
            .start(init_sync_recovered_pins_reopen_inner::<mmr::Family>);
    }

    #[test]
    fn test_init_sync_recovered_pins_reopen_mmb() {
        deterministic::Runner::default()
            .start(init_sync_recovered_pins_reopen_inner::<mmb::Family>);
    }

    fn init_sync_metadata_ahead_of_journal_inner<F: Family>() {
        let (root, checkpoint) =
            deterministic::Runner::default().start_and_recover(|context| async move {
                let hasher = Standard::<Sha256>::new(ForwardFold);
                let mut source_cfg = test_config(&context);
                source_cfg.journal_partition = "source-journal".into();
                source_cfg.metadata_partition = "source-metadata".into();
                let source = seed_recovery_tree::<F>(&context, source_cfg, 16).await;
                let root = source.root(&hasher, 0).unwrap();
                let pins = source.pinned_nodes_at(Location::new(16)).await.unwrap();
                source.destroy().await.unwrap();

                let cfg = test_config(&context);
                drop(seed_recovery_tree::<F>(&context, cfg.clone(), 4).await);

                // Persist state at the interruption point between sync metadata and reset intent.
                let mut metadata = Metadata::<_, U64, Vec<u8>>::init(
                    context.child("metadata"),
                    MConfig {
                        partition: cfg.metadata_partition,
                        codec_config: ((0..).into(), ()),
                    },
                )
                .await
                .unwrap();
                metadata.put(U64::new(PRUNED_TO_PREFIX, 0), 16u64.to_be_bytes().to_vec());
                for (pos, pin) in F::nodes_to_pin(Location::new(16)).zip(pins) {
                    metadata.put(U64::new(NODE_PREFIX, *pos), pin.to_vec());
                }
                _ = metadata.sync().await.unwrap();
                root
            });
        deterministic::Runner::from(checkpoint).start(|context| async move {
            let hasher = Standard::<Sha256>::new(ForwardFold);
            let cfg = test_config(&context);
            assert!(matches!(
                Merkle::<F, _, Digest, Sequential>::init(
                    context.child("ordinary"),
                    &hasher,
                    cfg.clone()
                )
                .await,
                Err(Error::MissingNode(_))
            ));
            let merkle = Merkle::<F, _, Digest, Sequential>::init_sync(
                context.child("retry"),
                SyncConfig {
                    config: cfg.clone(),
                    range: non_empty_range!(Location::new(16), Location::new(32)),
                    pinned_nodes: None,
                },
            )
            .await
            .unwrap();
            assert_eq!(merkle.bounds(), Location::new(16)..Location::new(16));
            assert_eq!(merkle.root(&hasher, 0).unwrap(), root);
            drop(merkle);
            let merkle =
                Merkle::<F, _, Digest, Sequential>::init(context.child("reopen"), &hasher, cfg)
                    .await
                    .unwrap();
            assert_eq!(merkle.bounds(), Location::new(16)..Location::new(16));
            assert_eq!(merkle.root(&hasher, 0).unwrap(), root);
            merkle.destroy().await.unwrap();
        });
    }

    #[test]
    fn test_init_sync_metadata_ahead_of_journal_mmr() {
        init_sync_metadata_ahead_of_journal_inner::<mmr::Family>();
    }

    #[test]
    fn test_init_sync_metadata_ahead_of_journal_mmb() {
        init_sync_metadata_ahead_of_journal_inner::<mmb::Family>();
    }

    fn init_sync_recovered_pins_crash_inner<F: Family>() {
        for (leaves, start, end) in [(16, 16, 32), (100, 32, 128)] {
            for seed in 0..16 {
                let ((root, succeeded), checkpoint) = deterministic::Runner::seeded(seed)
                    .start_and_recover(move |context| async move {
                        let hasher = Standard::<Sha256>::new(ForwardFold);
                        let cfg = test_config(&context);
                        let merkle = seed_recovery_tree::<F>(&context, cfg.clone(), leaves).await;
                        let root = merkle.root(&hasher, 0).unwrap();
                        drop(merkle);
                        *context.storage_fault_config().write() = deterministic::FaultConfig {
                            write_rate: Some(deterministic::WriteConfig {
                                failure_rate: commonware_utils::probability!(0.2),
                                retention_rate: commonware_utils::probability!(0.5),
                                mode: deterministic::PartialWriteMode::Subset,
                            }),
                            sync_rate: Some(commonware_utils::probability!(0.2)),
                            remove_rate: Some(commonware_utils::probability!(0.2)),
                            resize_rate: Some(deterministic::ResizeConfig {
                                failure_rate: commonware_utils::probability!(0.2),
                                partial_rate: commonware_utils::probability!(0.5),
                            }),
                            ..Default::default()
                        };
                        let result = Merkle::<F, _, Digest, Sequential>::init_sync(
                            context.child("interrupted"),
                            SyncConfig {
                                config: cfg,
                                range: non_empty_range!(Location::new(start), Location::new(end)),
                                pinned_nodes: None,
                            },
                        )
                        .await;
                        let succeeded = result.is_ok();
                        drop(result);
                        (root, succeeded)
                    });
                deterministic::Runner::from(checkpoint).start(move |context| async move {
                    *context.storage_fault_config().write() = deterministic::FaultConfig::default();
                    let hasher = Standard::<Sha256>::new(ForwardFold);
                    let cfg = test_config(&context);
                    let merkle = Merkle::<F, _, Digest, Sequential>::init(
                        context.child("reopen"),
                        &hasher,
                        cfg.clone(),
                    )
                    .await
                    .unwrap_or_else(|err| {
                        panic!("seed={seed} leaves={leaves} succeeded={succeeded}: {err:?}")
                    });
                    assert_eq!(merkle.leaves(), leaves);
                    assert_eq!(merkle.root(&hasher, 0).unwrap(), root);
                    drop(merkle);
                    let merkle = Merkle::<F, _, Digest, Sequential>::init_sync(
                        context.child("retry"),
                        SyncConfig {
                            config: cfg,
                            range: non_empty_range!(Location::new(start), Location::new(end)),
                            pinned_nodes: None,
                        },
                    )
                    .await
                    .unwrap();
                    assert_eq!(merkle.bounds(), Location::new(start)..Location::new(leaves));
                    assert_eq!(merkle.root(&hasher, 0).unwrap(), root);
                });
            }
        }
    }

    #[test]
    fn test_init_sync_recovered_pins_crash_mmr() {
        init_sync_recovered_pins_crash_inner::<mmr::Family>();
    }

    #[test]
    fn test_init_sync_recovered_pins_crash_mmb() {
        init_sync_recovered_pins_crash_inner::<mmb::Family>();
    }

    async fn node_blob_names(
        context: &deterministic::Context,
        cfg: &Config<Sequential>,
    ) -> Vec<u64> {
        let mut names = context
            .scan(&format!("{}-blobs", cfg.journal_partition))
            .await
            .unwrap()
            .into_iter()
            .map(|name| u64::from_be_bytes(name.try_into().unwrap()))
            .collect::<Vec<_>>();
        names.sort_unstable();
        names
    }

    fn init_sync_after_interrupted_bounded_publication_inner<F: Family>(boundary_leaves: u64) {
        let ((root_at_boundary, root_at_end), checkpoint) = deterministic::Runner::default()
            .start_and_recover(move |context| async move {
                let hasher = Standard::<Sha256>::new(ForwardFold);
                let boundary = Location::<F>::new(boundary_leaves);
                let end = Location::<F>::new(boundary_leaves * 2);
                let boundary_pos = Position::<F>::try_from(boundary).unwrap();
                let end_pos = Position::<F>::try_from(end).unwrap();
                let mut cfg = test_config(&context);
                cfg.items_per_blob = NonZeroU64::new(*boundary_pos).unwrap();

                let mut merkle = Merkle::<F, _, Digest, Sequential>::init(
                    context.child("seed"),
                    &hasher,
                    cfg.clone(),
                )
                .await
                .unwrap();
                let mut batch = merkle.new_batch();
                for i in 0..boundary_leaves as usize {
                    batch = batch.add(&hasher, &test_digest(i));
                }
                let batch = merkle.with_mem(|mem| batch.merkleize(mem, &hasher));
                merkle = merkle.apply_batch(&batch).unwrap();
                merkle = merkle.sync().await.unwrap();
                let root_at_boundary = merkle.root(&hasher, 0).unwrap();

                let mut batch = merkle.new_batch();
                for i in boundary_leaves as usize..boundary_leaves as usize * 2 {
                    batch = batch.add(&hasher, &test_digest(i));
                }
                let batch = merkle.with_mem(|mem| batch.merkleize(mem, &hasher));
                merkle = merkle.apply_batch(&batch).unwrap();
                let root_at_end = merkle.root(&hasher, 0).unwrap();
                let mut merkle = merkle.sync().await.unwrap();

                // With 11 leaves, pruning to 10 stores some of the boundary's pins in metadata and
                // keeps the rest in the journal, so the recovering init_sync must read both. With 8
                // leaves every pin stays in the journal.
                if boundary_leaves == 11 {
                    merkle = merkle.prune(Location::new(10)).await.unwrap();
                    let pins: Vec<_> = F::nodes_to_pin(boundary).collect();
                    assert!(pins.iter().any(|pos| {
                        merkle.metadata.get(&U64::new(NODE_PREFIX, **pos)).is_some()
                    }));
                    assert!(pins.iter().any(|pos| {
                        merkle.metadata.get(&U64::new(NODE_PREFIX, **pos)).is_none()
                    }));
                } else {
                    assert!(merkle.metadata.keys().next().is_none());
                }
                assert_eq!(merkle.journal.bounds(), 0..*end_pos);
                assert_eq!(node_blob_names(&context, &cfg).await, vec![0, 1, 2]);
                drop(merkle);

                let pending = PendingSyncs::default();
                let delayed = DelayedSyncContext {
                    inner: context.child("bounded"),
                    pending: pending.clone(),
                };
                let mut bounded = Box::pin(Merkle::<F, _, Digest, Sequential>::init_at_most(
                    delayed,
                    &hasher,
                    cfg.clone(),
                    boundary,
                ));

                poll_fn(|cx| match bounded.as_mut().poll(cx) {
                    Poll::Ready(result) => {
                        panic!("init_at_most returned before its predecessor sync: {result:?}")
                    }
                    Poll::Pending if pending.lock().is_empty() => {
                        cx.waker().wake_by_ref();
                        Poll::Pending
                    }
                    Poll::Pending => Poll::Ready(()),
                })
                .await;
                let deferred = next_pending_sync(&pending);
                deferred
                    .blocked
                    .await
                    .expect("predecessor sync never reached its deferred completion");

                assert_eq!(pending.starts(), 1);
                assert_eq!(pending.entered(), 1);
                assert_eq!(pending.completions(), 0);
                assert!(
                    bounded.as_mut().now_or_never().is_none(),
                    "init_at_most must still await predecessor durability"
                );
                assert_eq!(node_blob_names(&context, &cfg).await, vec![0]);

                // Keep the predecessor sync parked while cancellation removes the unpublished
                // recovery owner. The runtime snapshot then models a crash at this point.
                drop(bounded);
                drop(deferred.release);
                (root_at_boundary, root_at_end)
            });

        let (root_at_end, checkpoint) =
            deterministic::Runner::from(checkpoint).start_and_recover(move |context| async move {
                let hasher = Standard::<Sha256>::new(ForwardFold);
                let boundary = Location::<F>::new(boundary_leaves);
                let end = Location::<F>::new(boundary_leaves * 2);
                let boundary_pos = Position::<F>::try_from(boundary).unwrap();
                let mut cfg = test_config(&context);
                cfg.items_per_blob = NonZeroU64::new(*boundary_pos).unwrap();

                assert_eq!(node_blob_names(&context, &cfg).await, vec![0]);
                assert_eq!(persisted_watermark(&context).await, Some(*boundary_pos));

                // This must be the first Merkle/journal initializer after the crash. An ordinary
                // open would publish the missing empty tail and conceal the boundary-pin path.
                let mut merkle = Merkle::<F, _, Digest, Sequential>::init_sync(
                    context.child("sync"),
                    SyncConfig {
                        config: cfg.clone(),
                        range: non_empty_range!(boundary, end),
                        pinned_nodes: None,
                    },
                )
                .await
                .unwrap();
                assert_eq!(merkle.bounds(), boundary..boundary);
                assert_eq!(merkle.root(&hasher, 0).unwrap(), root_at_boundary);

                let mut batch = merkle.new_batch();
                for i in boundary_leaves as usize..boundary_leaves as usize * 2 {
                    batch = batch.add(&hasher, &test_digest(i));
                }
                let batch = merkle.with_mem(|mem| batch.merkleize(mem, &hasher));
                merkle = merkle.apply_batch(&batch).unwrap();
                assert_eq!(merkle.root(&hasher, 0).unwrap(), root_at_end);
                _ = merkle.sync().await.unwrap();
                root_at_end
            });

        deterministic::Runner::from(checkpoint).start(move |context| async move {
            let hasher = Standard::<Sha256>::new(ForwardFold);
            let boundary = Location::<F>::new(boundary_leaves);
            let end = Location::<F>::new(boundary_leaves * 2);
            let boundary_pos = Position::<F>::try_from(boundary).unwrap();
            let mut cfg = test_config(&context);
            cfg.items_per_blob = NonZeroU64::new(*boundary_pos).unwrap();
            let merkle =
                Merkle::<F, _, Digest, Sequential>::init(context.child("reopen"), &hasher, cfg)
                    .await
                    .unwrap();
            assert_eq!(merkle.bounds(), boundary..end);
            assert_eq!(merkle.root(&hasher, 0).unwrap(), root_at_end);
            merkle.destroy().await.unwrap();
        });
    }

    #[test]
    fn test_init_sync_after_interrupted_bounded_publication_mmr() {
        for boundary in [8, 11] {
            init_sync_after_interrupted_bounded_publication_inner::<mmr::Family>(boundary);
        }
    }

    #[test]
    fn test_init_sync_after_interrupted_bounded_publication_mmb() {
        for boundary in [8, 11] {
            init_sync_after_interrupted_bounded_publication_inner::<mmb::Family>(boundary);
        }
    }

    async fn init_sync_after_interrupted_clear_inner<F: Family>(context: deterministic::Context) {
        let hasher = Standard::<Sha256>::new(ForwardFold);
        let local_start = Location::<F>::new(7);
        let local_end = Location::<F>::new(12);

        // The local tree starts mid-blob, so its journal checkpoint records that start. Staging
        // a clear leaves the record in place, and the removed cut leaves it with no blob. Blob
        // state alone would reject that record as corruption, so only the staged target can
        // describe the journal.
        let items_per_blob = test_config(&context).items_per_blob.get();
        assert_ne!(
            *Position::<F>::try_from(local_start).unwrap() % items_per_blob,
            0
        );

        // Each case restarts at `start` after a node-journal clear to `target` was staged. A start
        // equal to the target models one interrupted reset, above or below the local tree. A
        // start below the target models a retry that persisted its boundary metadata before
        // staging its own clear.
        for (start, target, end) in [(20, 20, 28), (4, 4, 12), (9, 20, 16)] {
            // Without caller pins, init_sync takes the boundary pins from the metadata written
            // below.
            for (removed, pinned) in [(false, true), (false, false), (true, true), (true, false)] {
                let context = context
                    .child("case")
                    .with_attribute("start", start)
                    .with_attribute("removed", removed)
                    .with_attribute("pinned", pinned);
                let mut cfg = test_config(&context);
                cfg.journal_partition = format!("journal-{start}-{removed}-{pinned}");
                cfg.metadata_partition = format!("metadata-{start}-{removed}-{pinned}");
                let start = Location::<F>::new(start);
                let end = Location::<F>::new(end);
                let target = Position::<F>::try_from(Location::<F>::new(target)).unwrap();

                // Take the pins and the expected root from a reference tree of `end` leaves.
                let mut reference_cfg = cfg.clone();
                reference_cfg.journal_partition.push_str("-reference");
                reference_cfg.metadata_partition.push_str("-reference");
                let reference = seed_recovery_tree::<F>(&context, reference_cfg, *end).await;
                let root = reference.root(&hasher, 0).unwrap();
                let local_pins = reference.pinned_nodes_at(local_start).await.unwrap();
                let pins = reference.pinned_nodes_at(start).await.unwrap();
                reference.destroy().await.unwrap();

                // Sync the local tree from its mid-blob start.
                let mut merkle = Merkle::<F, _, Digest, Sequential>::init_sync(
                    context.child("local"),
                    SyncConfig {
                        config: cfg.clone(),
                        range: non_empty_range!(local_start, local_end),
                        pinned_nodes: Some(local_pins),
                    },
                )
                .await
                .unwrap();
                let mut batch = merkle.new_batch();
                for i in *local_start..*local_end {
                    batch = batch.add(&hasher, &test_digest(i as usize));
                }
                let batch = merkle.with_mem(|mem| batch.merkleize(mem, &hasher));
                merkle = merkle.apply_batch(&batch).unwrap();
                _ = merkle.sync().await.unwrap();

                // Persist the boundary metadata that init_sync syncs before resetting the journal.
                let mut metadata = Metadata::<_, U64, Vec<u8>>::init(
                    context.child("metadata"),
                    MConfig {
                        partition: cfg.metadata_partition.clone(),
                        codec_config: ((0..).into(), ()),
                    },
                )
                .await
                .unwrap();
                metadata.retain(|key, _| key.prefix() != NODE_PREFIX);
                metadata.put(
                    U64::new(PRUNED_TO_PREFIX, 0),
                    start.as_u64().to_be_bytes().to_vec(),
                );
                for (pos, pin) in F::nodes_to_pin(start).zip(&pins) {
                    metadata.put(U64::new(NODE_PREFIX, *pos), pin.to_vec());
                }
                _ = metadata.sync().await.unwrap();

                // Stage the clear. The removed cut also drops the blob partition, as completing
                // the clear does before it recreates the tail.
                Journal::<_, Digest>::test_stage_clear(
                    context.child("intent"),
                    &cfg.journal_partition,
                    *target,
                )
                .await
                .unwrap();
                if removed {
                    context
                        .remove(&format!("{}-blobs", cfg.journal_partition), None)
                        .await
                        .unwrap();
                }

                // init_sync must be the first initializer after the interruption. An ordinary
                // open would complete the staged clear first.
                let mut merkle = Merkle::<F, _, Digest, Sequential>::init_sync(
                    context.child("sync"),
                    SyncConfig {
                        config: cfg.clone(),
                        range: non_empty_range!(start, end),
                        pinned_nodes: pinned.then_some(pins),
                    },
                )
                .await
                .unwrap();
                assert_eq!(merkle.size(), Position::try_from(start).unwrap());

                // Appending the range reproduces the reference root.
                let mut batch = merkle.new_batch();
                for i in *start..*end {
                    batch = batch.add(&hasher, &test_digest(i as usize));
                }
                let batch = merkle.with_mem(|mem| batch.merkleize(mem, &hasher));
                merkle = merkle.apply_batch(&batch).unwrap();
                assert_eq!(merkle.root(&hasher, 0).unwrap(), root);
                _ = merkle.sync().await.unwrap();

                // An ordinary reopen recovers the synced range.
                let merkle =
                    Merkle::<F, _, Digest, Sequential>::init(context.child("reopen"), &hasher, cfg)
                        .await
                        .unwrap();
                assert_eq!(merkle.bounds(), start..end);
                assert_eq!(merkle.root(&hasher, 0).unwrap(), root);
                merkle.destroy().await.unwrap();
            }
        }
    }

    #[test]
    fn test_init_sync_after_interrupted_clear_mmr() {
        deterministic::Runner::default()
            .start(init_sync_after_interrupted_clear_inner::<mmr::Family>);
    }

    #[test]
    fn test_init_sync_after_interrupted_clear_mmb() {
        deterministic::Runner::default()
            .start(init_sync_after_interrupted_clear_inner::<mmb::Family>);
    }

    async fn init_sync_rejects_malformed_metadata_pin_inner<F: Family>(
        context: deterministic::Context,
    ) {
        let cfg = test_config(&context);
        let boundary = Location::<F>::new(11);
        let merkle = seed_recovery_tree::<F>(&context, cfg.clone(), 22).await;
        let mut merkle = merkle.prune(Location::new(10)).await.unwrap();
        let pos = F::nodes_to_pin(boundary)
            .find(|pos| merkle.metadata.get(&U64::new(NODE_PREFIX, **pos)).is_some())
            .unwrap();
        assert!(merkle.journal.read(*pos).await.is_ok());

        // A present metadata pin remains authoritative even when the journal has its digest.
        merkle.metadata.put(U64::new(NODE_PREFIX, *pos), Vec::new());
        merkle.metadata = merkle.metadata.sync().await.unwrap();
        drop(merkle);
        let result = Merkle::<F, _, Digest, Sequential>::init_sync(
            context.child("sync"),
            SyncConfig {
                config: cfg,
                range: non_empty_range!(boundary, Location::new(22)),
                pinned_nodes: None,
            },
        )
        .await;
        assert!(matches!(result, Err(Error::DataCorrupted(_))));
    }

    #[test]
    fn test_init_sync_rejects_malformed_metadata_pin_mmr() {
        deterministic::Runner::default()
            .start(init_sync_rejects_malformed_metadata_pin_inner::<mmr::Family>);
    }

    #[test]
    fn test_init_sync_rejects_malformed_metadata_pin_mmb() {
        deterministic::Runner::default()
            .start(init_sync_rejects_malformed_metadata_pin_inner::<mmb::Family>);
    }

    async fn init_sync_rejects_missing_pin_inner<F: Family>(context: deterministic::Context) {
        let hasher = Standard::<Sha256>::new(ForwardFold);
        let start = Location::<F>::new(6);
        let end = Location::<F>::new(12);
        let pins: Vec<_> = F::nodes_to_pin(start).collect();
        let highest = *pins.iter().max().unwrap();
        assert_eq!(*highest, 9);

        // An unpruned tree keeps no pins in metadata, so init_sync probes the journal at the
        // highest pin, 9. Five leaves (size 8) occupy blobs 0 and 1, whose capacity reaches 14, so
        // the journal opens and the read at 9 lies past its recovered end. Three leaves (size 4)
        // occupy only blob 0, whose capacity ends at 7, so the journal stays unopened and the
        // first pin has no source.
        for (leaves, blobs, missing) in [(5, vec![0, 1], highest), (3, vec![0], pins[0])] {
            let context = context.child("stored").with_attribute("leaves", leaves);
            let mut cfg = test_config(&context);
            cfg.journal_partition = format!("journal-{leaves}");
            cfg.metadata_partition = format!("metadata-{leaves}");
            let merkle = seed_recovery_tree::<F>(&context, cfg.clone(), leaves).await;
            let root = merkle.root(&hasher, 0).unwrap();
            drop(merkle);
            assert_eq!(node_blob_names(&context, &cfg).await, blobs);

            // Both probe routes report the pin as a missing node.
            let result = Merkle::<F, _, Digest, Sequential>::init_sync(
                context.child("sync"),
                SyncConfig {
                    config: cfg.clone(),
                    range: non_empty_range!(start, end),
                    pinned_nodes: None,
                },
            )
            .await;
            assert!(
                matches!(&result, Err(Error::MissingNode(pos)) if *pos == missing),
                "{result:?}"
            );

            // The failure precedes any reset, so the local tree still reopens.
            let merkle =
                Merkle::<F, _, Digest, Sequential>::init(context.child("reopen"), &hasher, cfg)
                    .await
                    .unwrap();
            assert_eq!(merkle.leaves(), Location::new(leaves));
            assert_eq!(merkle.root(&hasher, 0).unwrap(), root);
            merkle.destroy().await.unwrap();
        }
    }

    #[test]
    fn test_init_sync_rejects_missing_pin_mmr() {
        deterministic::Runner::default().start(init_sync_rejects_missing_pin_inner::<mmr::Family>);
    }

    #[test]
    fn test_init_sync_rejects_missing_pin_mmb() {
        deterministic::Runner::default().start(init_sync_rejects_missing_pin_inner::<mmb::Family>);
    }

    fn init_recovery_prune_crash_inner<F: Family>() {
        let boundary = Position::try_from(Location::<F>::new(8)).unwrap();
        for per_blob in [1, 5, 7, *boundary] {
            for unbounded in [false, true] {
                let (root, checkpoint) =
                    deterministic::Runner::default().start_and_recover(move |context| async move {
                        let hasher = Standard::<Sha256>::new(ForwardFold);
                        let mut cfg = test_config(&context);
                        cfg.items_per_blob = NonZeroU64::new(per_blob).unwrap();
                        let merkle = seed_recovery_tree::<F>(&context, cfg.clone(), 16).await;

                        // Stop a prune after its boundary and pins become durable.
                        let (merkle, _) = merkle.update_metadata(boundary).await.unwrap();
                        drop(merkle);
                        let mut pending = Merkle::<F, _, Digest, Sequential>::prepare(
                            context.child("cap"),
                            &hasher,
                            cfg.clone(),
                            Some(Location::new(8)),
                        )
                        .await
                        .unwrap();
                        let root = pending.mem.root(&hasher, 0).unwrap();
                        pending.journal = pending
                            .journal
                            .truncate(*pending.retained_size)
                            .await
                            .unwrap();
                        if unbounded {
                            // An interrupted bounded open can leave no empty tail for ordinary
                            // recovery.
                            drop(pending);
                            pending = Merkle::<F, _, Digest, Sequential>::prepare(
                                context.child("ordinary"),
                                &hasher,
                                cfg,
                                None,
                            )
                            .await
                            .unwrap();
                            pending.journal = pending
                                .journal
                                .truncate(*pending.retained_size)
                                .await
                                .unwrap();
                        }
                        (pending.journal, _) = pending
                            .journal
                            .prune(*pending.metadata_prune_pos)
                            .await
                            .unwrap();

                        // Crash before publication opens the retained tail.
                        drop(pending);
                        root
                    });
                deterministic::Runner::from(checkpoint).start(move |context| async move {
                    let hasher = Standard::<Sha256>::new(ForwardFold);
                    let mut cfg = test_config(&context);
                    cfg.items_per_blob = NonZeroU64::new(per_blob).unwrap();
                    let merkle = Merkle::<F, _, Digest, Sequential>::init(
                        context.child("reopen"),
                        &hasher,
                        cfg.clone(),
                    )
                    .await
                    .unwrap_or_else(|err| {
                        panic!("per_blob={per_blob} unbounded={unbounded}: {err:?}")
                    });
                    assert_eq!(merkle.bounds(), Location::new(8)..Location::new(8));
                    assert_eq!(merkle.root(&hasher, 0).unwrap(), root);
                    drop(merkle);
                    let merkle = Merkle::<F, _, Digest, Sequential>::init_at_most(
                        context.child("retry"),
                        &hasher,
                        cfg,
                        Location::new(8),
                    )
                    .await
                    .unwrap();
                    assert_eq!(merkle.root(&hasher, 0).unwrap(), root);
                });
            }
        }
    }

    #[test]
    fn test_init_recovery_prune_crash_mmr() {
        init_recovery_prune_crash_inner::<mmr::Family>();
    }

    #[test]
    fn test_init_recovery_prune_crash_mmb() {
        init_recovery_prune_crash_inner::<mmb::Family>();
    }

    async fn full_init_sync_truncates_state_beyond_range_inner<F: Family>(
        context: deterministic::Context,
    ) {
        let hasher = Standard::<Sha256>::new(ForwardFold);
        let cfg = test_config(&context);
        let mut merkle =
            Merkle::<F, _, Digest, Sequential>::init(context.child("init"), &hasher, cfg.clone())
                .await
                .unwrap();

        let target_end = Location::<F>::new(20);
        let mut batch = merkle.new_batch();
        for i in 0..20 {
            batch = batch.add(&hasher, &test_digest(i));
        }
        let batch = merkle.with_mem(|mem| batch.merkleize(mem, &hasher));
        merkle = merkle.apply_batch(&batch).unwrap();
        let target_root = merkle.root(&hasher, 0).unwrap();
        let restart = Location::<F>::new(7);
        let pinned_nodes = merkle.pinned_nodes_at(restart).await.unwrap();

        let mut batch = merkle.new_batch();
        for i in 20..50 {
            batch = batch.add(&hasher, &test_digest(i));
        }
        let batch = merkle.with_mem(|mem| batch.merkleize(mem, &hasher));
        merkle = merkle.apply_batch(&batch).unwrap();
        let merkle = merkle.sync().await.unwrap();
        drop(merkle);

        let sync_cfg = SyncConfig::<F, sha256::Digest, Sequential> {
            config: cfg.clone(),
            range: non_empty_range!(restart, target_end),
            pinned_nodes: Some(pinned_nodes),
        };
        let merkle = Merkle::<F, _, Digest, Sequential>::init_sync(context.child("sync"), sync_cfg)
            .await
            .unwrap();

        assert_eq!(merkle.leaves(), target_end);
        assert_eq!(merkle.root(&hasher, 0).unwrap(), target_root);
        let merkle = merkle.sync().await.unwrap();
        drop(merkle);

        let merkle =
            Merkle::<F, _, Digest, Sequential>::init(context.child("reopen"), &hasher, cfg)
                .await
                .unwrap();
        assert_eq!(merkle.leaves(), target_end);
        assert_eq!(merkle.root(&hasher, 0).unwrap(), target_root);
        merkle.destroy().await.unwrap();
    }

    #[test_traced]
    fn test_full_init_sync_truncates_state_beyond_range_mmr() {
        deterministic::Runner::default()
            .start(full_init_sync_truncates_state_beyond_range_inner::<mmr::Family>);
    }

    #[test_traced]
    fn test_full_init_sync_truncates_state_beyond_range_mmb() {
        deterministic::Runner::default()
            .start(full_init_sync_truncates_state_beyond_range_inner::<mmb::Family>);
    }

    async fn full_init_sync_discards_state_pruned_past_range_inner<F: Family>(
        context: deterministic::Context,
    ) {
        let hasher = Standard::<Sha256>::new(ForwardFold);
        let cfg = test_config(&context);
        let mut merkle =
            Merkle::<F, _, Digest, Sequential>::init(context.child("init"), &hasher, cfg.clone())
                .await
                .unwrap();

        let mut batch = merkle.new_batch();
        for i in 0..50 {
            batch = batch.add(&hasher, &test_digest(i));
        }
        let batch = merkle.with_mem(|mem| batch.merkleize(mem, &hasher));
        merkle = merkle.apply_batch(&batch).unwrap();
        let target_root = merkle.root(&hasher, 0).unwrap();
        let restart = Location::<F>::new(7);
        let pinned_nodes = merkle.pinned_nodes_at(restart).await.unwrap();
        let merkle = merkle.sync().await.unwrap();
        let merkle = merkle.prune(Location::new(30)).await.unwrap();
        let merkle = merkle.sync().await.unwrap();
        assert!(merkle.bounds().start > restart);
        drop(merkle);

        let sync_cfg = SyncConfig::<F, sha256::Digest, Sequential> {
            config: cfg,
            range: non_empty_range!(restart, Location::<F>::new(60)),
            pinned_nodes: Some(pinned_nodes),
        };
        let mut merkle =
            Merkle::<F, _, Digest, Sequential>::init_sync(context.child("sync"), sync_cfg)
                .await
                .unwrap();

        assert_eq!(merkle.bounds(), restart..restart);
        let mut batch = merkle.new_batch();
        for i in 7..50 {
            batch = batch.add(&hasher, &test_digest(i));
        }
        let batch = merkle.with_mem(|mem| batch.merkleize(mem, &hasher));
        merkle = merkle.apply_batch(&batch).unwrap();
        assert_eq!(merkle.root(&hasher, 0).unwrap(), target_root);
        merkle.destroy().await.unwrap();
    }

    #[test_traced]
    fn test_full_init_sync_discards_state_pruned_past_range_mmr() {
        deterministic::Runner::default()
            .start(full_init_sync_discards_state_pruned_past_range_inner::<mmr::Family>);
    }

    #[test_traced]
    fn test_full_init_sync_discards_state_pruned_past_range_mmb() {
        deterministic::Runner::default()
            .start(full_init_sync_discards_state_pruned_past_range_inner::<mmb::Family>);
    }

    /// Tear the tail page of node blob `blob` so its next open must truncate it.
    async fn tear_node_blob(context: &deterministic::Context, cfg: &Config<Sequential>, blob: u64) {
        let (blob, len) = context
            .open(
                &format!("{}-blobs", cfg.journal_partition),
                &blob.to_be_bytes(),
            )
            .await
            .unwrap();
        blob.resize(len - 1).await.unwrap();
        blob.sync().await.unwrap();
    }

    async fn init_sync_ahead_skips_discarded_blobs_inner<F: Family>(
        context: deterministic::Context,
    ) {
        let hasher = Standard::<Sha256>::new(ForwardFold);
        let restart = Location::<F>::new(7);
        let end = Location::<F>::new(20);
        let end_pos = Position::<F>::try_from(end).unwrap();
        let stale = || U64::new(NODE_PREFIX, u64::MAX);
        let mut calls = Vec::new();
        let mut reads = Vec::new();
        for (stored_leaves, torn) in [(50, false), (80, false), (80, true)] {
            let context = context
                .child("stored")
                .with_attribute("leaves", stored_leaves)
                .with_attribute("torn", torn);
            let mut cfg = test_config(&context);
            cfg.journal_partition = format!("journal-{torn}");
            cfg.metadata_partition = format!("metadata-{torn}");
            let mut merkle = Merkle::<F, _, Digest, Sequential>::init(
                context.child("seed"),
                &hasher,
                cfg.clone(),
            )
            .await
            .unwrap();
            let mut batch = merkle.new_batch();
            for i in 0..20 {
                batch = batch.add(&hasher, &test_digest(i));
            }
            let batch = merkle.with_mem(|mem| batch.merkleize(mem, &hasher));
            merkle = merkle.apply_batch(&batch).unwrap();
            let target_root = merkle.root(&hasher, 0).unwrap();
            let pinned_nodes = merkle.pinned_nodes_at(restart).await.unwrap();
            let mut batch = merkle.new_batch();
            for i in 20..stored_leaves {
                batch = batch.add(&hasher, &test_digest(i));
            }
            let batch = merkle.with_mem(|mem| batch.merkleize(mem, &hasher));
            merkle = merkle.apply_batch(&batch).unwrap();
            let merkle = merkle.sync().await.unwrap();
            let newest = (*merkle.size() - 1) / cfg.items_per_blob.get();
            assert!(newest * cfg.items_per_blob.get() >= *end_pos);
            drop(merkle);

            // init_sync retains only the selected boundary's pins, so the stale key planted
            // here is dropped.
            let metadata_cfg = MConfig {
                partition: cfg.metadata_partition.clone(),
                codec_config: ((0..).into(), ()),
            };
            let mut metadata =
                Metadata::<_, U64, Vec<u8>>::init(context.child("stale"), metadata_cfg.clone())
                    .await
                    .unwrap();
            metadata.put(stale(), test_digest(usize::MAX).to_vec());
            _ = metadata.sync().await.unwrap();
            if torn {
                tear_node_blob(&context, &cfg, newest).await;
            }

            let pending = PendingSyncs::default();
            pending.arm();
            let (recorded, recordings) = RecordingContext::new(context.child("delayed"));
            let delayed = DelayedSyncContext {
                inner: recorded,
                pending: pending.clone(),
            };
            let merkle = drive_pending_syncs(
                &pending,
                Merkle::<F, _, Digest, Sequential>::init_sync(
                    delayed.child("sync"),
                    SyncConfig {
                        config: cfg.clone(),
                        range: non_empty_range!(restart, end),
                        pinned_nodes: Some(pinned_nodes),
                    },
                ),
            )
            .await
            .unwrap();
            assert_eq!(merkle.leaves(), end);
            assert_eq!(merkle.root(&hasher, 0).unwrap(), target_root);
            calls.push(pending.calls());
            reads.push(recordings.snapshot().reads.len());
            drop(merkle);

            let metadata = Metadata::<_, U64, Vec<u8>>::init(context.child("check"), metadata_cfg)
                .await
                .unwrap();
            assert!(metadata.get(&stale()).is_none());
            drop(metadata);
            let merkle =
                Merkle::<F, _, Digest, Sequential>::init(context.child("reopen"), &hasher, cfg)
                    .await
                    .unwrap();
            assert_eq!(merkle.leaves(), end);
            assert_eq!(merkle.root(&hasher, 0).unwrap(), target_root);
            merkle.destroy().await.unwrap();
        }

        // Node blobs wholly beyond the range are removed without being opened, so a torn tail
        // there costs no repair.
        assert_eq!(calls[0], calls[1]);
        assert_eq!(calls[1], calls[2]);
        assert_eq!(reads[0], reads[1], "reading cost grew with discarded nodes");
        assert_eq!(reads[1], reads[2]);
    }

    #[test_traced]
    fn test_init_sync_ahead_skips_discarded_blobs_mmr() {
        deterministic::Runner::default()
            .start(init_sync_ahead_skips_discarded_blobs_inner::<mmr::Family>);
    }

    #[test_traced]
    fn test_init_sync_ahead_skips_discarded_blobs_mmb() {
        deterministic::Runner::default()
            .start(init_sync_ahead_skips_discarded_blobs_inner::<mmb::Family>);
    }

    async fn init_sync_reset_leaves_retained_blobs_unopened_inner<F: Family>(
        context: deterministic::Context,
    ) {
        let hasher = Standard::<Sha256>::new(ForwardFold);
        let restart = Location::<F>::new(7);
        let end = Location::<F>::new(20);
        let mut calls = Vec::new();
        for torn in [false, true] {
            let context = context.child(if torn { "torn" } else { "clean" });
            let mut cfg = test_config(&context);
            cfg.journal_partition = format!("journal-{torn}");
            cfg.metadata_partition = format!("metadata-{torn}");
            let mut merkle = Merkle::<F, _, Digest, Sequential>::init(
                context.child("seed"),
                &hasher,
                cfg.clone(),
            )
            .await
            .unwrap();
            let mut batch = merkle.new_batch();
            for i in 0..50 {
                batch = batch.add(&hasher, &test_digest(i));
            }
            let batch = merkle.with_mem(|mem| batch.merkleize(mem, &hasher));
            merkle = merkle.apply_batch(&batch).unwrap();
            let target_root = merkle.root(&hasher, 0).unwrap();
            let pinned_nodes = merkle.pinned_nodes_at(restart).await.unwrap();
            let merkle = merkle.sync().await.unwrap();
            let merkle = merkle.prune(Location::new(30)).await.unwrap();
            let merkle = merkle.sync().await.unwrap();
            assert!(merkle.bounds().start > end);
            let newest = (*merkle.size() - 1) / cfg.items_per_blob.get();
            drop(merkle);
            if torn {
                tear_node_blob(&context, &cfg, newest).await;
            }

            let pending = PendingSyncs::default();
            pending.arm();
            let delayed = DelayedSyncContext {
                inner: context,
                pending: pending.clone(),
            };
            let mut merkle = drive_pending_syncs(
                &pending,
                Merkle::<F, _, Digest, Sequential>::init_sync(
                    delayed.child("sync"),
                    SyncConfig {
                        config: cfg,
                        range: non_empty_range!(restart, end),
                        pinned_nodes: Some(pinned_nodes),
                    },
                ),
            )
            .await
            .unwrap();
            assert_eq!(merkle.bounds(), restart..restart);
            calls.push(pending.calls());
            let mut batch = merkle.new_batch();
            for i in 7..50 {
                batch = batch.add(&hasher, &test_digest(i));
            }
            let batch = merkle.with_mem(|mem| batch.merkleize(mem, &hasher));
            merkle = merkle.apply_batch(&batch).unwrap();
            assert_eq!(merkle.root(&hasher, 0).unwrap(), target_root);
            merkle.destroy().await.unwrap();
        }

        // Every retained node lies beyond the range, so the reset must not open any blob: a
        // torn tail costs no repair.
        assert_eq!(calls[0], calls[1]);
    }

    #[test_traced]
    fn test_init_sync_reset_leaves_retained_blobs_unopened_mmr() {
        deterministic::Runner::default()
            .start(init_sync_reset_leaves_retained_blobs_unopened_inner::<mmr::Family>);
    }

    #[test_traced]
    fn test_init_sync_reset_leaves_retained_blobs_unopened_mmb() {
        deterministic::Runner::default()
            .start(init_sync_reset_leaves_retained_blobs_unopened_inner::<mmb::Family>);
    }

    async fn init_sync_invalid_pins_leave_pruned_journal_intact_inner<F: Family>(
        context: deterministic::Context,
    ) {
        let hasher = Standard::<Sha256>::new(ForwardFold);
        let restart = Location::<F>::new(7);
        let end = Location::<F>::new(20);
        let cfg = test_config(&context);
        let mut merkle =
            Merkle::<F, _, Digest, Sequential>::init(context.child("seed"), &hasher, cfg.clone())
                .await
                .unwrap();
        let mut batch = merkle.new_batch();
        for i in 0..50 {
            batch = batch.add(&hasher, &test_digest(i));
        }
        let batch = merkle.with_mem(|mem| batch.merkleize(mem, &hasher));
        merkle = merkle.apply_batch(&batch).unwrap();
        let root = merkle.root(&hasher, 0).unwrap();
        let mut pinned_nodes = merkle.pinned_nodes_at(restart).await.unwrap();
        let merkle = merkle.sync().await.unwrap();
        let merkle = merkle.prune(Location::new(30)).await.unwrap();
        let merkle = merkle.sync().await.unwrap();
        let bounds = merkle.bounds();
        assert!(bounds.start > end);
        drop(merkle);

        // Every retained node lies beyond the range, so the journal would restart at the
        // boundary. Pins of the wrong length must fail before it is reset.
        pinned_nodes.push(test_digest(usize::MAX));
        let result = Merkle::<F, _, Digest, Sequential>::init_sync(
            context.child("sync"),
            SyncConfig {
                config: cfg.clone(),
                range: non_empty_range!(restart, end),
                pinned_nodes: Some(pinned_nodes),
            },
        )
        .await;
        assert!(matches!(result, Err(Error::InvalidPinnedNodes)));

        let merkle =
            Merkle::<F, _, Digest, Sequential>::init(context.child("reopen"), &hasher, cfg)
                .await
                .unwrap();
        assert_eq!(merkle.bounds(), bounds);
        assert_eq!(merkle.root(&hasher, 0).unwrap(), root);
        merkle.destroy().await.unwrap();
    }

    #[test_traced]
    fn test_init_sync_invalid_pins_leave_pruned_journal_intact_mmr() {
        deterministic::Runner::default()
            .start(init_sync_invalid_pins_leave_pruned_journal_intact_inner::<mmr::Family>);
    }

    #[test_traced]
    fn test_init_sync_invalid_pins_leave_pruned_journal_intact_mmb() {
        deterministic::Runner::default()
            .start(init_sync_invalid_pins_leave_pruned_journal_intact_inner::<mmb::Family>);
    }

    async fn init_sync_ahead_within_end_blob_inner<F: Family>(context: deterministic::Context) {
        let hasher = Standard::<Sha256>::new(ForwardFold);
        let restart = Location::<F>::new(7);
        let end = Location::<F>::new(20);
        let end_pos = Position::<F>::try_from(end).unwrap();
        let stale = || U64::new(NODE_PREFIX, u64::MAX);
        let cfg = test_config(&context);
        let items_per_blob = cfg.items_per_blob.get();
        let mut merkle =
            Merkle::<F, _, Digest, Sequential>::init(context.child("seed"), &hasher, cfg.clone())
                .await
                .unwrap();
        let mut batch = merkle.new_batch();
        for i in 0..20 {
            batch = batch.add(&hasher, &test_digest(i));
        }
        let batch = merkle.with_mem(|mem| batch.merkleize(mem, &hasher));
        merkle = merkle.apply_batch(&batch).unwrap();
        let target_root = merkle.root(&hasher, 0).unwrap();
        let pinned_nodes = merkle.pinned_nodes_at(restart).await.unwrap();

        // Extend the tree past `end_pos` without leaving its blob, so the bound discards nodes
        // but no whole blob.
        let mut next = 20;
        while *merkle.size() <= *end_pos {
            let batch = merkle.new_batch().add(&hasher, &test_digest(next));
            let batch = merkle.with_mem(|mem| batch.merkleize(mem, &hasher));
            merkle = merkle.apply_batch(&batch).unwrap();
            next += 1;
        }
        let merkle = merkle.sync().await.unwrap();
        drop(merkle);
        let newest = context
            .scan(&format!("{}-blobs", cfg.journal_partition))
            .await
            .unwrap()
            .into_iter()
            .map(|name| u64::from_be_bytes(name.try_into().unwrap()))
            .max()
            .unwrap();
        assert_eq!(newest, *end_pos / items_per_blob);

        // init_sync retains only the selected boundary's pins, so the stale key planted here is
        // dropped.
        let metadata_cfg = MConfig {
            partition: cfg.metadata_partition.clone(),
            codec_config: ((0..).into(), ()),
        };
        let mut metadata =
            Metadata::<_, U64, Vec<u8>>::init(context.child("stale"), metadata_cfg.clone())
                .await
                .unwrap();
        metadata.put(stale(), test_digest(usize::MAX).to_vec());
        _ = metadata.sync().await.unwrap();

        let merkle = Merkle::<F, _, Digest, Sequential>::init_sync(
            context.child("sync"),
            SyncConfig {
                config: cfg.clone(),
                range: non_empty_range!(restart, end),
                pinned_nodes: Some(pinned_nodes),
            },
        )
        .await
        .unwrap();
        assert_eq!(merkle.leaves(), end);
        assert_eq!(merkle.root(&hasher, 0).unwrap(), target_root);
        drop(merkle);

        let metadata = Metadata::<_, U64, Vec<u8>>::init(context.child("check"), metadata_cfg)
            .await
            .unwrap();
        assert!(metadata.get(&stale()).is_none());
        drop(metadata);
        let merkle =
            Merkle::<F, _, Digest, Sequential>::init(context.child("reopen"), &hasher, cfg)
                .await
                .unwrap();
        assert_eq!(merkle.leaves(), end);
        assert_eq!(merkle.root(&hasher, 0).unwrap(), target_root);
        merkle.destroy().await.unwrap();
    }

    #[test_traced]
    fn test_init_sync_ahead_within_end_blob_mmr() {
        deterministic::Runner::default()
            .start(init_sync_ahead_within_end_blob_inner::<mmr::Family>);
    }

    #[test_traced]
    fn test_init_sync_ahead_within_end_blob_mmb() {
        deterministic::Runner::default()
            .start(init_sync_ahead_within_end_blob_inner::<mmb::Family>);
    }

    async fn init_sync_repairs_retained_torn_tail_inner<F: Family>(
        context: deterministic::Context,
    ) {
        let hasher = Standard::<Sha256>::new(ForwardFold);
        let restart = Location::<F>::new(7);
        let end = Location::<F>::new(22);
        let end_pos = Position::<F>::try_from(end).unwrap();
        let mut calls = Vec::new();
        for torn in [false, true] {
            let context = context.child(if torn { "torn" } else { "clean" });
            let mut cfg = test_config(&context);
            cfg.journal_partition = format!("journal-{torn}");
            cfg.metadata_partition = format!("metadata-{torn}");
            let items_per_blob = cfg.items_per_blob.get();

            // The newest blob holds more than a page of nodes, so losing its tail page leaves
            // nodes ending mid-page that recovery must rewrite rather than only shrink away.
            let nodes = (*end_pos - 1) % items_per_blob + 1;
            assert!(nodes * size_of::<Digest>() as u64 > u64::from(PAGE_SIZE.get()));

            // Seed every node durably while the recovery watermark lags behind them, so a torn
            // tail below `end_pos` is a crash shape rather than corruption.
            let pending = PendingSyncs::default();
            let delayed = DelayedSyncContext {
                inner: context.child("seed_delayed"),
                pending: pending.clone(),
            };
            let merkle = drive_pending_syncs(
                &pending,
                Merkle::<F, _, Digest, Sequential>::init(
                    delayed.child("seed"),
                    &hasher,
                    cfg.clone(),
                ),
            )
            .await
            .unwrap();
            let mut batch = merkle.new_batch();
            for i in 0..end.as_u64() as usize {
                batch = batch.add(&hasher, &test_digest(i));
            }
            let batch = merkle.with_mem(|mem| batch.merkleize(mem, &hasher));
            let merkle = merkle.apply_batch(&batch).unwrap();
            let target_root = merkle.root(&hasher, 0).unwrap();
            let pinned_nodes = merkle.pinned_nodes_at(restart).await.unwrap();
            let merkle = drive_pending_syncs(&pending, merkle.flush()).await.unwrap();
            let (merkle, handle) = merkle.start_sync().await.unwrap();
            drive_pending_syncs(&pending, handle).await.unwrap();
            assert_eq!(merkle.size(), end_pos);
            drop(merkle);
            let newest = (*end_pos - 1) / items_per_blob;
            let watermark = Journal::<_, Digest>::persisted_watermark(
                context.child("probe"),
                &cfg.journal_partition,
            )
            .await
            .unwrap()
            .unwrap();
            assert!(watermark <= newest * items_per_blob);
            if torn {
                tear_node_blob(&context, &cfg, newest).await;
            }

            let pending = PendingSyncs::default();
            pending.arm();
            let delayed = DelayedSyncContext {
                inner: context.child("sync_delayed"),
                pending: pending.clone(),
            };
            let mut merkle = drive_pending_syncs(
                &pending,
                Merkle::<F, _, Digest, Sequential>::init_sync(
                    delayed.child("sync"),
                    SyncConfig {
                        config: cfg,
                        range: non_empty_range!(restart, end),
                        pinned_nodes: Some(pinned_nodes),
                    },
                ),
            )
            .await
            .unwrap();
            calls.push(pending.calls());
            if torn {
                assert!(merkle.leaves() < end);
            } else {
                assert_eq!(merkle.leaves(), end);
            }

            // Re-adding whatever the repair dropped rebuilds the target.
            let mut batch = merkle.new_batch();
            for i in merkle.leaves().as_u64()..end.as_u64() {
                batch = batch.add(&hasher, &test_digest(i as usize));
            }
            let batch = merkle.with_mem(|mem| batch.merkleize(mem, &hasher));
            merkle = merkle.apply_batch(&batch).unwrap();
            assert_eq!(merkle.root(&hasher, 0).unwrap(), target_root);
            merkle.destroy().await.unwrap();
        }

        // A torn tail inside the range is repaired.
        assert!(calls[1] > calls[0]);
    }

    #[test_traced]
    fn test_init_sync_repairs_retained_torn_tail_mmr() {
        deterministic::Runner::default()
            .start(init_sync_repairs_retained_torn_tail_inner::<mmr::Family>);
    }

    #[test_traced]
    fn test_init_sync_repairs_retained_torn_tail_mmb() {
        deterministic::Runner::default()
            .start(init_sync_repairs_retained_torn_tail_inner::<mmb::Family>);
    }

    async fn init_sync_start_below_retained_leaves_blobs_unopened_inner<F: Family>(
        context: deterministic::Context,
    ) {
        let hasher = Standard::<Sha256>::new(ForwardFold);
        let restart = Location::<F>::new(20);
        let end = Location::<F>::new(60);
        let prune_pos = Position::<F>::try_from(restart).unwrap();
        let end_pos = Position::<F>::try_from(end).unwrap();
        let stale = || U64::new(NODE_PREFIX, u64::MAX);
        let mut calls = Vec::new();
        for torn in [false, true] {
            let context = context.child(if torn { "torn" } else { "clean" });
            let mut cfg = test_config(&context);
            cfg.journal_partition = format!("journal-{torn}");
            cfg.metadata_partition = format!("metadata-{torn}");
            let items_per_blob = cfg.items_per_blob.get();
            let pending = PendingSyncs::default();
            let delayed = DelayedSyncContext {
                inner: context.child("seed_delayed"),
                pending: pending.clone(),
            };
            let mut merkle = drive_pending_syncs(
                &pending,
                Merkle::<F, _, Digest, Sequential>::init(
                    delayed.child("seed"),
                    &hasher,
                    cfg.clone(),
                ),
            )
            .await
            .unwrap();
            let mut batch = merkle.new_batch();
            for i in 0..50 {
                batch = batch.add(&hasher, &test_digest(i));
            }
            let batch = merkle.with_mem(|mem| batch.merkleize(mem, &hasher));
            merkle = merkle.apply_batch(&batch).unwrap();
            let pinned_nodes = merkle.pinned_nodes_at(restart).await.unwrap();
            let merkle = drive_pending_syncs(&pending, merkle.sync()).await.unwrap();
            let mut merkle = drive_pending_syncs(&pending, merkle.prune(Location::new(30)))
                .await
                .unwrap();

            // The journal keeps whole blobs, so its retained start is the boundary rounded down
            // to a blob. It must lie inside the range.
            let boundary = *Position::<F>::try_from(merkle.bounds().start).unwrap();
            let retained = boundary / items_per_blob * items_per_blob;
            assert!(*prune_pos < retained && retained < *end_pos);

            // Extend the tree past the watermark the prune persisted while that watermark lags
            // behind the new nodes, so the newest blob holds only unacknowledged nodes and a
            // torn tail there is a crash shape rather than corruption. The blob starts below
            // `end_pos`, so a bounded open would take it.
            let mut batch = merkle.new_batch();
            for i in 50..60 {
                batch = batch.add(&hasher, &test_digest(i));
            }
            let batch = merkle.with_mem(|mem| batch.merkleize(mem, &hasher));
            merkle = merkle.apply_batch(&batch).unwrap();
            let target_root = merkle.root(&hasher, 0).unwrap();
            let merkle = drive_pending_syncs(&pending, merkle.flush()).await.unwrap();
            let (merkle, handle) = merkle.start_sync().await.unwrap();
            drive_pending_syncs(&pending, handle).await.unwrap();
            let newest = (*merkle.size() - 1) / items_per_blob;
            drop(merkle);
            let watermark = Journal::<_, Digest>::persisted_watermark(
                context.child("probe"),
                &cfg.journal_partition,
            )
            .await
            .unwrap()
            .unwrap();
            assert!(watermark <= newest * items_per_blob);
            assert!(newest * items_per_blob < *end_pos);

            // init_sync retains only the selected boundary's pins, so the stale key planted
            // here is dropped.
            let metadata_cfg = MConfig {
                partition: cfg.metadata_partition.clone(),
                codec_config: ((0..).into(), ()),
            };
            let mut metadata =
                Metadata::<_, U64, Vec<u8>>::init(context.child("stale"), metadata_cfg.clone())
                    .await
                    .unwrap();
            metadata.put(stale(), test_digest(usize::MAX).to_vec());
            _ = metadata.sync().await.unwrap();
            if torn {
                tear_node_blob(&context, &cfg, newest).await;
            }

            let pending = PendingSyncs::default();
            pending.arm();
            let delayed = DelayedSyncContext {
                inner: context.child("sync_delayed"),
                pending: pending.clone(),
            };
            let mut merkle = drive_pending_syncs(
                &pending,
                Merkle::<F, _, Digest, Sequential>::init_sync(
                    delayed.child("sync"),
                    SyncConfig {
                        config: cfg.clone(),
                        range: non_empty_range!(restart, end),
                        pinned_nodes: Some(pinned_nodes),
                    },
                ),
            )
            .await
            .unwrap();
            assert_eq!(merkle.bounds(), restart..restart);
            calls.push(pending.calls());
            let mut batch = merkle.new_batch();
            for i in 20..60 {
                batch = batch.add(&hasher, &test_digest(i));
            }
            let batch = merkle.with_mem(|mem| batch.merkleize(mem, &hasher));
            merkle = merkle.apply_batch(&batch).unwrap();
            assert_eq!(merkle.root(&hasher, 0).unwrap(), target_root);
            drop(merkle);

            let metadata = Metadata::<_, U64, Vec<u8>>::init(context.child("check"), metadata_cfg)
                .await
                .unwrap();
            assert!(metadata.get(&stale()).is_none());
            drop(metadata);
            let merkle =
                Merkle::<F, _, Digest, Sequential>::init(context.child("reopen"), &hasher, cfg)
                    .await
                    .unwrap();
            assert_eq!(merkle.bounds(), restart..restart);
            merkle.destroy().await.unwrap();
        }

        // The retained start lies inside the range, so the journal cannot serve it and is reset
        // without opening any blob: a torn tail costs no repair.
        assert_eq!(calls[0], calls[1]);
    }

    #[test_traced]
    fn test_init_sync_start_below_retained_leaves_blobs_unopened_mmr() {
        deterministic::Runner::default()
            .start(init_sync_start_below_retained_leaves_blobs_unopened_inner::<mmr::Family>);
    }

    #[test_traced]
    fn test_init_sync_start_below_retained_leaves_blobs_unopened_mmb() {
        deterministic::Runner::default()
            .start(init_sync_start_below_retained_leaves_blobs_unopened_inner::<mmb::Family>);
    }

    async fn init_sync_stale_below_start_leaves_blobs_unopened_inner<F: Family>(
        context: deterministic::Context,
    ) {
        let hasher = Standard::<Sha256>::new(ForwardFold);
        let restart = Location::<F>::new(30);
        let end = Location::<F>::new(50);
        let prune_pos = Position::<F>::try_from(restart).unwrap();
        let stale = || U64::new(NODE_PREFIX, u64::MAX);

        // A reference tree supplies the pins and root that the stale journal cannot.
        let mut reference_cfg = test_config(&context);
        reference_cfg.journal_partition = "journal-reference".into();
        reference_cfg.metadata_partition = "metadata-reference".into();
        let mut reference = Merkle::<F, _, Digest, Sequential>::init(
            context.child("reference"),
            &hasher,
            reference_cfg,
        )
        .await
        .unwrap();
        let mut batch = reference.new_batch();
        for i in 0..50 {
            batch = batch.add(&hasher, &test_digest(i));
        }
        let batch = reference.with_mem(|mem| batch.merkleize(mem, &hasher));
        reference = reference.apply_batch(&batch).unwrap();
        let target_root = reference.root(&hasher, 0).unwrap();
        let pinned_nodes = reference.pinned_nodes_at(restart).await.unwrap();
        reference.destroy().await.unwrap();

        let mut calls = Vec::new();
        for torn in [false, true] {
            let context = context.child(if torn { "torn" } else { "clean" });
            let mut cfg = test_config(&context);
            cfg.journal_partition = format!("journal-{torn}");
            cfg.metadata_partition = format!("metadata-{torn}");
            let items_per_blob = cfg.items_per_blob.get();

            // Seed the nodes durably while the recovery watermark lags behind them, so a torn
            // tail is a crash shape rather than corruption.
            let pending = PendingSyncs::default();
            let delayed = DelayedSyncContext {
                inner: context.child("seed_delayed"),
                pending: pending.clone(),
            };
            let mut merkle = drive_pending_syncs(
                &pending,
                Merkle::<F, _, Digest, Sequential>::init(
                    delayed.child("seed"),
                    &hasher,
                    cfg.clone(),
                ),
            )
            .await
            .unwrap();
            let mut batch = merkle.new_batch();
            for i in 0..20 {
                batch = batch.add(&hasher, &test_digest(i));
            }
            let batch = merkle.with_mem(|mem| batch.merkleize(mem, &hasher));
            merkle = merkle.apply_batch(&batch).unwrap();
            let merkle = drive_pending_syncs(&pending, merkle.flush()).await.unwrap();
            let (merkle, handle) = merkle.start_sync().await.unwrap();
            drive_pending_syncs(&pending, handle).await.unwrap();
            let newest = (*merkle.size() - 1) / items_per_blob;
            drop(merkle);
            let watermark = Journal::<_, Digest>::persisted_watermark(
                context.child("probe"),
                &cfg.journal_partition,
            )
            .await
            .unwrap()
            .unwrap_or(0);
            assert!(watermark <= newest * items_per_blob);

            // Every stored node lies below the range start, including the newest blob's
            // capacity.
            assert!((newest + 1) * items_per_blob <= *prune_pos);

            // init_sync retains only the selected boundary's pins, so the stale key planted
            // here is dropped.
            let metadata_cfg = MConfig {
                partition: cfg.metadata_partition.clone(),
                codec_config: ((0..).into(), ()),
            };
            let mut metadata =
                Metadata::<_, U64, Vec<u8>>::init(context.child("stale"), metadata_cfg.clone())
                    .await
                    .unwrap();
            metadata.put(stale(), test_digest(usize::MAX).to_vec());
            _ = metadata.sync().await.unwrap();
            if torn {
                tear_node_blob(&context, &cfg, newest).await;
            }

            let pending = PendingSyncs::default();
            pending.arm();
            let delayed = DelayedSyncContext {
                inner: context.child("sync_delayed"),
                pending: pending.clone(),
            };
            let mut merkle = drive_pending_syncs(
                &pending,
                Merkle::<F, _, Digest, Sequential>::init_sync(
                    delayed.child("sync"),
                    SyncConfig {
                        config: cfg.clone(),
                        range: non_empty_range!(restart, end),
                        pinned_nodes: Some(pinned_nodes.clone()),
                    },
                ),
            )
            .await
            .unwrap();
            assert_eq!(merkle.bounds(), restart..restart);
            calls.push(pending.calls());
            let mut batch = merkle.new_batch();
            for i in 30..50 {
                batch = batch.add(&hasher, &test_digest(i));
            }
            let batch = merkle.with_mem(|mem| batch.merkleize(mem, &hasher));
            merkle = merkle.apply_batch(&batch).unwrap();
            assert_eq!(merkle.root(&hasher, 0).unwrap(), target_root);
            drop(merkle);

            let metadata = Metadata::<_, U64, Vec<u8>>::init(context.child("check"), metadata_cfg)
                .await
                .unwrap();
            assert!(metadata.get(&stale()).is_none());
            drop(metadata);
            let merkle =
                Merkle::<F, _, Digest, Sequential>::init(context.child("reopen"), &hasher, cfg)
                    .await
                    .unwrap();
            assert_eq!(merkle.bounds(), restart..restart);
            merkle.destroy().await.unwrap();
        }

        // Every stored node lies below the range start, so the journal is reset without opening
        // any blob: a torn tail costs no repair.
        assert_eq!(calls[0], calls[1]);
    }

    #[test_traced]
    fn test_init_sync_stale_below_start_leaves_blobs_unopened_mmr() {
        deterministic::Runner::default()
            .start(init_sync_stale_below_start_leaves_blobs_unopened_inner::<mmr::Family>);
    }

    #[test_traced]
    fn test_init_sync_stale_below_start_leaves_blobs_unopened_mmb() {
        deterministic::Runner::default()
            .start(init_sync_stale_below_start_leaves_blobs_unopened_inner::<mmb::Family>);
    }

    #[test_traced]
    fn test_full_init_sync_discards_stale_pinned_metadata() {
        deterministic::Runner::default().start(|context| async move {
            type F = mmr::Family;

            let hasher = Standard::<Sha256>::new(ForwardFold);
            let cfg = test_config(&context);
            let mut merkle = Merkle::<F, _, Digest, Sequential>::init(
                context.child("old"),
                &hasher,
                cfg.clone(),
            )
            .await
            .unwrap();
            let mut batch = merkle.new_batch();
            for i in 0..40 {
                batch = batch.add(&hasher, &test_digest(i));
            }
            let batch = merkle.with_mem(|mem| batch.merkleize(mem, &hasher));
            merkle = merkle.apply_batch(&batch).unwrap();
            let merkle = merkle.sync().await.unwrap();
            let merkle = merkle.prune(Location::new(30)).await.unwrap();
            let merkle = merkle.sync().await.unwrap();
            drop(merkle);

            let mut target_cfg = test_config(&context);
            target_cfg.journal_partition = "target-journal-partition".into();
            target_cfg.metadata_partition = "target-metadata-partition".into();
            let mut target = Merkle::<F, _, Digest, Sequential>::init(
                context.child("target"),
                &hasher,
                target_cfg,
            )
            .await
            .unwrap();
            let mut batch = target.new_batch();
            for i in 0..20 {
                batch = batch.add(&hasher, &test_digest(1_000 + i));
            }
            let batch = target.with_mem(|mem| batch.merkleize(mem, &hasher));
            target = target.apply_batch(&batch).unwrap();
            let target_root = target.root(&hasher, 0).unwrap();
            let restart = Location::new(7);
            let pinned_nodes = target.pinned_nodes_at(restart).await.unwrap();
            target.destroy().await.unwrap();

            let sync_cfg = SyncConfig::<F, sha256::Digest, Sequential> {
                config: cfg.clone(),
                range: non_empty_range!(restart, Location::new(20)),
                pinned_nodes: Some(pinned_nodes),
            };
            let mut merkle =
                Merkle::<F, _, Digest, Sequential>::init_sync(context.child("sync"), sync_cfg)
                    .await
                    .unwrap();
            let mut batch = merkle.new_batch();
            for i in 7..20 {
                batch = batch.add(&hasher, &test_digest(1_000 + i));
            }
            let batch = merkle.with_mem(|mem| batch.merkleize(mem, &hasher));
            merkle = merkle.apply_batch(&batch).unwrap();
            assert_eq!(merkle.root(&hasher, 0).unwrap(), target_root);
            let merkle = merkle.sync().await.unwrap();
            drop(merkle);

            let merkle =
                Merkle::<F, _, Digest, Sequential>::init(context.child("reopen"), &hasher, cfg)
                    .await
                    .unwrap();
            assert_eq!(merkle.root(&hasher, 0).unwrap(), target_root);
            merkle.destroy().await.unwrap();
        });
    }

    async fn full_init_sync_rejects_extra_pinned_nodes_inner<F: Family>(
        context: deterministic::Context,
    ) {
        let sync_cfg = SyncConfig::<F, sha256::Digest, Sequential> {
            config: test_config(&context),
            range: non_empty_range!(Location::<F>::new(6), Location::<F>::new(20)),
            pinned_nodes: Some(vec![test_digest(1), test_digest(2), test_digest(3)]),
        };

        let result =
            Merkle::<F, _, Digest, Sequential>::init_sync(context.child("sync"), sync_cfg).await;
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
        let hasher = Standard::<Sha256>::new(ForwardFold);

        // Create a structure with some data and prune it
        let mut mmr = Merkle::<F, _, Digest, Sequential>::init(
            context.child("init"),
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
        mmr = mmr.apply_batch(&batch).unwrap();
        let mmr = mmr.sync().await.unwrap();

        // Prune enough that the journal boundary's pinned nodes span pruned blobs.
        let prune_loc = Location::<F>::new(25);
        mmr.prune(prune_loc).await.unwrap();

        // Simulate a crash after journal prune but before metadata was updated:
        // clear all metadata and write only a stale pruning boundary of 0 (no pinned nodes).
        let meta_cfg = MConfig {
            partition: test_config(&context).metadata_partition,
            codec_config: ((0..).into(), ()),
        };
        let mut metadata =
            Metadata::<_, U64, Vec<u8>>::init(context.child("meta_tamper"), meta_cfg)
                .await
                .unwrap();
        metadata.clear();
        let key = U64::new(PRUNED_TO_PREFIX, 0);
        metadata
            .put_sync(key, 0u64.to_be_bytes().to_vec())
            .await
            .unwrap();

        // Reopen the structure - before the fix, this would panic with assertion failure
        // After the fix, it returns MissingNode error (pinned nodes for the lower
        // boundary don't exist since they were pruned from journal and weren't
        // stored in metadata at the lower position)
        let result = Merkle::<F, _, Digest, Sequential>::init(
            context.child("reopened"),
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

    async fn full_init_rejects_prune_boundary_beyond_recovered_size_inner<F: Family>(
        context: deterministic::Context,
    ) {
        let hasher = Standard::<Sha256>::new(ForwardFold);
        let cfg = test_config(&context);
        let mut merkle =
            Merkle::<F, _, Digest, Sequential>::init(context.child("init"), &hasher, cfg.clone())
                .await
                .unwrap();

        let mut batch = merkle.new_batch();
        for i in 0..12 {
            batch = batch.add(&hasher, &test_digest(i));
        }
        let batch = merkle.with_mem(|mem| batch.merkleize(mem, &hasher));
        merkle = merkle.apply_batch(&batch).unwrap();
        let merkle = merkle.sync().await.unwrap();
        let merkle = merkle.prune(Location::new(12)).await.unwrap();
        let merkle = merkle.sync().await.unwrap();
        drop(merkle);

        let journal_cfg = JConfig {
            partition: cfg.journal_partition.clone(),
            items_per_blob: cfg.items_per_blob,
            page_cache: cfg.page_cache.clone(),
            write_buffer: cfg.write_buffer,
            replay_buffer: cfg.replay_buffer,
        };
        let journal =
            Journal::<_, Digest>::init(context.child("interrupted_reset"), journal_cfg.clone())
                .await
                .unwrap();
        let recovered_size = Position::<F>::try_from(Location::<F>::new(8)).unwrap();
        assert!(
            journal.bounds().start > *recovered_size,
            "test reset must discard a pruned prefix"
        );
        drop(journal);
        let journal = Journal::<_, Digest>::init_at_size(
            context.child("reset"),
            journal_cfg,
            *recovered_size,
        )
        .await
        .unwrap();
        drop(journal);

        match Merkle::<F, _, Digest, Sequential>::init(context.child("reopen"), &hasher, cfg).await
        {
            Err(Error::MissingNode(_)) => {}
            Ok(_) => panic!("pruning boundary beyond recovered size must fail closed"),
            Err(err) => panic!("expected MissingNode error, got {err:?}"),
        }
    }

    #[test_traced("WARN")]
    fn test_full_init_rejects_prune_boundary_beyond_recovered_size_mmr() {
        deterministic::Runner::default()
            .start(full_init_rejects_prune_boundary_beyond_recovered_size_inner::<mmr::Family>);
    }

    #[test_traced("WARN")]
    fn test_full_init_rejects_prune_boundary_beyond_recovered_size_mmb() {
        deterministic::Runner::default()
            .start(full_init_rejects_prune_boundary_beyond_recovered_size_inner::<mmb::Family>);
    }

    // Test that init() handles the case where metadata pruning boundary is ahead
    // of journal (crashed before journal prune completed). This should successfully
    // prune the journal to match metadata.
    async fn full_init_metadata_ahead_inner<F: Family>(context: deterministic::Context) {
        let hasher = Standard::<Sha256>::new(ForwardFold);

        // Create a structure with some data
        let mut mmr = Merkle::<F, _, Digest, Sequential>::init(
            context.child("init"),
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
        mmr = mmr.apply_batch(&batch).unwrap();
        let mmr = mmr.sync().await.unwrap();

        // Prune to position 30 (this stores pinned nodes and updates metadata)
        let prune_loc = Location::<F>::new(16);
        let mmr = mmr.prune(prune_loc).await.unwrap();
        let expected_root = mmr.root(&hasher, 0).unwrap();
        let expected_size = mmr.size();
        drop(mmr);

        // Reopen the structure - should recover correctly with metadata ahead of
        // journal boundary (metadata says 30, journal is section-aligned to 28)
        let mmr = Merkle::<F, _, Digest, Sequential>::init(
            context.child("reopened"),
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
        let hasher = Standard::<Sha256>::new(ForwardFold);

        // Use small items_per_blob to create many sections and trigger pruning.
        let cfg = Config {
            journal_partition: "mmr-journal".into(),
            metadata_partition: "mmr-metadata".into(),
            items_per_blob: NZU64!(7),
            write_buffer: NZUsize!(64),
            replay_buffer: NZUsize!(64),
            strategy: Sequential,
            page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
        };

        // Create structure with enough elements to span multiple sections.
        let mut mmr =
            Merkle::<F, _, Digest, Sequential>::init(context.child("init"), &hasher, cfg.clone())
                .await
                .unwrap();
        let mut batch = mmr.new_batch();
        for i in 0..100 {
            batch = batch.add(&hasher, &test_digest(i));
        }
        let batch = mmr.with_mem(|mem| batch.merkleize(mem, &hasher));
        mmr = mmr.apply_batch(&batch).unwrap();
        let mmr = mmr.sync().await.unwrap();

        // Don't prune - this ensures metadata has no pinned nodes. init_sync will need to
        // read pinned nodes from the journal.
        let original_size = mmr.size();
        let original_root = mmr.root(&hasher, 0).unwrap();
        drop(mmr);

        // Reopen via init_sync with range.start > 0. This will prune the journal, so
        // init_sync must read pinned nodes BEFORE pruning or they'll be lost.
        let prune_loc = Location::<F>::new(32);
        let sync_cfg = SyncConfig::<F, sha256::Digest, Sequential> {
            config: cfg,
            range: non_empty_range!(prune_loc, Location::<F>::new(128)),
            pinned_nodes: None, // Force init_sync to compute pinned nodes from journal
        };

        let sync_mmr =
            Merkle::<F, _, Digest, Sequential>::init_sync(context.child("sync"), sync_cfg)
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
        let hasher = Standard::<Sha256>::new(ForwardFold);

        let mut mmr = Merkle::<F, _, Digest, Sequential>::init(
            context.child("init"),
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
        mmr = mmr.apply_batch(&batch).unwrap();

        let prune_loc = Location::<F>::new(16);
        let mmr = mmr.prune(prune_loc).await.unwrap();

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
        let mmr = mmr.apply_batch(&batch).unwrap();

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
        let hasher = Standard::<Sha256>::new(ForwardFold);
        let mut mmr = Merkle::<F, _, Digest, Sequential>::init(
            context.child("init"),
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
        mmr = mmr.apply_batch(&batch).unwrap();

        let historical_leaves = Location::<F>::new(10);
        let range = Location::<F>::new(2)..Location::<F>::new(8);

        // Appends should remain allowed while historical proofs are available.
        let batch = mmr
            .new_batch()
            .add(&hasher, &test_digest(100))
            .add(&hasher, &test_digest(101));
        let batch = mmr.with_mem(|mem| batch.merkleize(mem, &hasher));
        mmr = mmr.apply_batch(&batch).unwrap();

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
        let hasher = Standard::<Sha256>::new(ForwardFold);
        let mut mmr = Merkle::<F, _, Digest, Sequential>::init(
            context.child("init"),
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
        mmr = mmr.apply_batch(&batch).unwrap();
        let mmr = mmr.sync().await.unwrap();

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
        let hasher = Standard::<Sha256>::new(ForwardFold);
        let mut mmr = Merkle::<F, _, Digest, Sequential>::init(
            context.child("init"),
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
        mmr = mmr.apply_batch(&batch).unwrap();

        let prune_loc = Location::<F>::new(10);
        let mmr = mmr.prune(prune_loc).await.unwrap();

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
        let hasher = Standard::<Sha256>::new(ForwardFold);

        // Case 1: Empty structure.
        let mmr = Merkle::<F, _, Digest, Sequential>::init(
            context.child("empty"),
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
        let mut mmr = Merkle::<F, _, Digest, Sequential>::init(
            context.child("fully_pruned"),
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
        mmr = mmr.apply_batch(&batch).unwrap();
        let end = mmr.leaves();
        mmr = mmr.prune_all().await.unwrap();
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
        let mut mmr = Merkle::<F, _, Digest, Sequential>::init(
            context.child("single_leaf"),
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
        mmr = mmr.apply_batch(&batch).unwrap();
        let end = mmr.leaves();
        let keep_loc = end - 1;
        mmr = mmr.prune(keep_loc).await.unwrap();
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
        let hasher = Standard::<Sha256>::new(ForwardFold);
        let mut mmr = Merkle::<F, _, Digest, Sequential>::init(
            context.child("oob"),
            &hasher,
            test_config(&context),
        )
        .await
        .unwrap();

        let mut batch = mmr.new_batch();
        for i in 0..8 {
            batch = batch.add(&hasher, &test_digest(i));
        }
        let batch = mmr.with_mem(|mem| batch.merkleize(mem, &hasher));
        mmr = mmr.apply_batch(&batch).unwrap();
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
        let hasher = Standard::<Sha256>::new(ForwardFold);
        let mut mmr = Merkle::<F, _, Digest, Sequential>::init(
            context.child("range_validation"),
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
        mmr = mmr.apply_batch(&batch).unwrap();

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
        let hasher = Standard::<Sha256>::new(ForwardFold);
        let mut mmr = Merkle::<F, _, Digest, Sequential>::init(
            context.child("non_size_prune"),
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
        mmr = mmr.apply_batch(&batch).unwrap();

        let end = mmr.leaves();
        let mut failures = Vec::new();
        for prune_leaf in 1..*end {
            let prune_loc = Location::<F>::new(prune_leaf);
            mmr = mmr.prune(prune_loc).await.unwrap();
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
        let hasher = Standard::<Sha256>::new(ForwardFold);

        // Build a structure with 3 leaves, sync, and drop.
        let mut mmr = Merkle::<F, _, Digest, Sequential>::init(
            context.child("init"),
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
        mmr = mmr.apply_batch(&batch).unwrap();
        let valid_size = mmr.size();
        let valid_root = mmr.root(&hasher, 0).unwrap();
        let mmr = mmr.sync().await.unwrap();
        drop(mmr);

        // Append one extra digest to the journal, simulating a crash that wrote a
        // leaf (for the 4th element) but not its parent nodes. This makes the
        // journal size invalid.
        {
            let journal: Journal<_, Digest> = Journal::init(
                context.child("corrupt"),
                JConfig {
                    partition: "journal-partition".into(),
                    items_per_blob: NZU64!(7),
                    write_buffer: NZUsize!(1024),
                    replay_buffer: NZUsize!(1024),
                    page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
                },
            )
            .await
            .unwrap();
            assert_eq!(journal.size(), valid_size);
            let (journal, _) = journal.append(&Sha256::hash(&[b"orphan"])).await.unwrap();
            let journal = journal.sync().await.unwrap();
            assert_eq!(journal.size(), valid_size + 1);
        }

        // Recovery truncates to the last valid size.
        let sync_cfg = SyncConfig::<F, Digest, Sequential> {
            config: test_config(&context),
            range: non_empty_range!(Location::<F>::new(0), Location::<F>::new(100)),
            pinned_nodes: None,
        };
        let sync_mmr =
            Merkle::<F, _, Digest, Sequential>::init_sync(context.child("sync"), sync_cfg)
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
        let hasher: Standard<Sha256> = Standard::new(ForwardFold);
        let mut mmr = Merkle::<F, _, Digest, Sequential>::init(
            context.child("storage"),
            &Standard::<Sha256>::new(ForwardFold),
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
        mmr = mmr.apply_batch(&batch_a).unwrap();

        // Apply B -- should fail (stale).
        assert!(matches!(
            mmr.apply_batch(&batch_b),
            Err(Error::StaleBatch { .. })
        ));
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
        let hasher = Standard::<Sha256>::new(ForwardFold);
        let mmr = Merkle::<F, _, Digest, Sequential>::init(
            context.child("storage"),
            &hasher,
            test_config(&context),
        )
        .await
        .unwrap();

        let _batch: UnmerkleizedBatch<F, Digest, Sequential> = mmr.new_batch();

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
    /// Before the fix, the batch took its pruning boundary from the journal's prune boundary
    /// (which could be 0), so the batch accepted the update. During merkleize, get_node
    /// returned None for the synced-out sibling and hit an expect panic.
    async fn full_update_leaf_after_sync_returns_pruned_inner<F: Family>(
        context: deterministic::Context,
    ) {
        let hasher = Standard::<Sha256>::new(ForwardFold);
        let mut mmr = Merkle::<F, _, Digest, Sequential>::init(
            context.child("storage"),
            &hasher,
            test_config(&context),
        )
        .await
        .unwrap();

        // Add 50 elements and sync (flushes all nodes to journal, prunes mem).
        let mut batch = mmr.new_batch();
        for i in 0..50 {
            batch = batch.add(&hasher, &test_digest(i));
        }
        let batch = mmr.with_mem(|mem| batch.merkleize(mem, &hasher));
        mmr = mmr.apply_batch(&batch).unwrap();
        let mmr = mmr.sync().await.unwrap();

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

    // A genesis sync onto a node journal that is empty at zero must drop the pins an interrupted
    // sync to a pruned range persisted, or a later init reads them ahead of the rebuilt nodes.
    async fn init_sync_genesis_drops_stale_pins_inner<F: Family>(context: deterministic::Context) {
        let hasher = Standard::<Sha256>::new(ForwardFold);
        let boundary = Location::<F>::new(16);
        let cfg = test_config(&context);

        // Model a crash after `init_sync(boundary..)` persists its boundary and pins but before
        // it resets the fresh node journal. The pins describe another history.
        let metadata_cfg = MConfig {
            partition: cfg.metadata_partition.clone(),
            codec_config: ((0..).into(), ()),
        };

        let mut metadata =
            Metadata::<_, U64, Vec<u8>>::init(context.child("metadata"), metadata_cfg)
                .await
                .unwrap();
        metadata.put(
            U64::new(PRUNED_TO_PREFIX, 0),
            boundary.as_u64().to_be_bytes().to_vec(),
        );
        for (i, pos) in F::nodes_to_pin(boundary).enumerate() {
            metadata.put(U64::new(NODE_PREFIX, *pos), test_digest(1_000 + i).to_vec());
        }
        _ = metadata.sync().await.unwrap();

        // Genesis sync, then rebuild the first leaves of the local history.
        let mut merkle = Merkle::<F, _, Digest, Sequential>::init_sync(
            context.child("sync"),
            SyncConfig {
                config: cfg.clone(),
                range: non_empty_range!(Location::<F>::new(0), boundary),
                pinned_nodes: None,
            },
        )
        .await
        .unwrap();
        assert_eq!(merkle.bounds(), Location::new(0)..Location::new(0));
        let mut batch = merkle.new_batch();
        for i in 0..16 {
            batch = batch.add(&hasher, &test_digest(i));
        }
        let batch = merkle.with_mem(|mem| batch.merkleize(mem, &hasher));
        merkle = merkle.apply_batch(&batch).unwrap();
        let root = merkle.root(&hasher, 0).unwrap();
        _ = merkle.sync().await.unwrap();

        // Reopening must recover the root of the rebuilt journal.
        let merkle =
            Merkle::<F, _, Digest, Sequential>::init(context.child("reopen"), &hasher, cfg)
                .await
                .unwrap();
        assert_eq!(merkle.root(&hasher, 0).unwrap(), root);
        merkle.destroy().await.unwrap();
    }

    #[test]
    fn test_init_sync_genesis_drops_stale_pins_mmr() {
        deterministic::Runner::default()
            .start(init_sync_genesis_drops_stale_pins_inner::<mmr::Family>);
    }

    #[test]
    fn test_init_sync_genesis_drops_stale_pins_mmb() {
        deterministic::Runner::default()
            .start(init_sync_genesis_drops_stale_pins_inner::<mmb::Family>);
    }

    // A lower-range sync can reuse the journal after a higher-range sync persisted only its
    // metadata. Reopening must authenticate any replacement suffix from journal nodes.
    async fn init_sync_lower_range_drops_future_pins_inner<F: Family>(
        context: deterministic::Context,
    ) {
        let hasher = Standard::<Sha256>::new(ForwardFold);
        let abandoned = Location::<F>::new(16);
        let lower = Location::<F>::new(2);
        let cfg = test_config(&context);

        // Keep the abandoned boundary metadata separate from the local node journal.
        let metadata_cfg = MConfig {
            partition: cfg.metadata_partition.clone(),
            codec_config: ((0..).into(), ()),
        };

        // A local tree of eight leaves.
        let mut merkle =
            Merkle::<F, _, Digest, Sequential>::init(context.child("local"), &hasher, cfg.clone())
                .await
                .unwrap();
        let mut batch = merkle.new_batch();
        for i in 0..8 {
            batch = batch.add(&hasher, &test_digest(i));
        }
        let batch = merkle.with_mem(|mem| batch.merkleize(mem, &hasher));
        merkle = merkle.apply_batch(&batch).unwrap();
        _ = merkle.sync().await.unwrap();

        // The higher boundary extends the same local history. Its pins can reach metadata
        // before an interrupted init_sync changes the local journal.
        let mut source_cfg = cfg.clone();
        source_cfg.journal_partition.push_str("-source");
        source_cfg.metadata_partition.push_str("-source");
        let source = seed_recovery_tree::<F>(&context, source_cfg, *abandoned).await;
        let pins = source.pinned_nodes_at(abandoned).await.unwrap();
        source.destroy().await.unwrap();

        let mut metadata =
            Metadata::<_, U64, Vec<u8>>::init(context.child("metadata"), metadata_cfg)
                .await
                .unwrap();
        metadata.put(
            U64::new(PRUNED_TO_PREFIX, 0),
            abandoned.as_u64().to_be_bytes().to_vec(),
        );
        for (pos, pin) in F::nodes_to_pin(abandoned).zip(pins) {
            metadata.put(U64::new(NODE_PREFIX, *pos), pin.to_vec());
        }
        _ = metadata.sync().await.unwrap();

        // Recover the lower range and append a replacement suffix through the abandoned boundary.
        let mut merkle = Merkle::<F, _, Digest, Sequential>::init_sync(
            context.child("sync"),
            SyncConfig {
                config: cfg.clone(),
                range: non_empty_range!(lower, Location::<F>::new(8)),
                pinned_nodes: None,
            },
        )
        .await
        .unwrap();
        assert_eq!(merkle.bounds(), lower..Location::new(8));
        let mut batch = merkle.new_batch();
        for i in 8..16 {
            batch = batch.add(&hasher, &test_digest(1_000 + i));
        }
        let batch = merkle.with_mem(|mem| batch.merkleize(mem, &hasher));
        merkle = merkle.apply_batch(&batch).unwrap();
        let root = merkle.root(&hasher, 0).unwrap();
        _ = merkle.sync().await.unwrap();

        // Reopening must recover the root of the replacement journal.
        let merkle =
            Merkle::<F, _, Digest, Sequential>::init(context.child("reopen"), &hasher, cfg)
                .await
                .unwrap();
        assert_eq!(merkle.root(&hasher, 0).unwrap(), root);
        merkle.destroy().await.unwrap();
    }

    #[test]
    fn test_init_sync_lower_range_drops_future_pins_mmr() {
        deterministic::Runner::default()
            .start(init_sync_lower_range_drops_future_pins_inner::<mmr::Family>);
    }

    #[test]
    fn test_init_sync_lower_range_drops_future_pins_mmb() {
        deterministic::Runner::default()
            .start(init_sync_lower_range_drops_future_pins_inner::<mmb::Family>);
    }
}
