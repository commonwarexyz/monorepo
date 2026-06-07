//! A compact Merkle structure.
//!
//! Unlike [`crate::merkle::full`], this type persists only the minimum state required to
//! recover the current root and continue appending after restart. Historical nodes are discarded
//! on sync and are not readable after reopen.
//!
//! # Why peaks are enough
//!
//! An MMR/MMB root is computed from the current peaks, and appending a new leaf only touches
//! peaks. Persisting `(leaf_count, pinned_peaks)` and rebuilding [`Mem`] on reopen with no
//! retained nodes and those peaks as pinned values reconstructs an equivalent tree: same root,
//! same future append behavior.
//!
//! # Retained bases
//!
//! Each sync appends a compact base record to a contiguous variable journal. A base contains the
//! leaf count, pinned peaks, the floor associated with the committed state, and caller-owned witness
//! bytes. Startup replays retained bases into an in-memory index and opens the journal tail as the
//! active committed state. Pruning removes bases before the requested floor, while exact rewind
//! truncates the journal back to a retained base and rebuilds [`Mem`] from that record.

use crate::{
    journal::contiguous::{
        variable::{Config as JournalConfig, Journal},
        Reader as _,
    },
    merkle::{
        batch,
        hasher::Hasher,
        mem::{Config as MemConfig, Mem},
        Error, Family, Location, Position, MAX_PINNED_NODES,
    },
    Context,
};
use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, RangeCfg, Read, Write};
use commonware_cryptography::Digest;
use commonware_parallel::Strategy;
use commonware_runtime::buffer::paged::CacheRef;
use commonware_utils::sync::{AsyncMutex, RwLock};
use std::{
    collections::BTreeMap,
    num::{NonZeroU64, NonZeroUsize},
    sync::Arc,
};

/// Append-only wrapper around [`batch::UnmerkleizedBatch`].
pub struct UnmerkleizedBatch<F: Family, D: Digest, S: Strategy> {
    inner: batch::UnmerkleizedBatch<F, D, S>,
}

impl<F: Family, D: Digest, S: Strategy> UnmerkleizedBatch<F, D, S> {
    /// Wrap an existing [`batch::UnmerkleizedBatch`] as an append-only batch.
    pub(crate) const fn wrap(inner: batch::UnmerkleizedBatch<F, D, S>) -> Self {
        Self { inner }
    }

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

    /// Consume this batch and produce an immutable [`batch::MerkleizedBatch`] with computed root.
    pub fn merkleize(
        self,
        base: &Mem<F, D>,
        hasher: &impl Hasher<F, Digest = D>,
    ) -> Arc<batch::MerkleizedBatch<F, D, S>> {
        self.inner.merkleize(base, hasher)
    }
}

/// Configuration for a compact Merkle structure.
#[derive(Clone)]
pub struct Config<S: Strategy> {
    /// Base partition used to persist compact state.
    pub partition: String,

    /// Number of retained bases to store in each log section.
    ///
    /// Once set, this value cannot be changed across restarts.
    pub items_per_section: NonZeroU64,

    /// Page cache for buffering retained-base reads.
    pub page_cache: CacheRef,

    /// Write buffer size for each retained-base section.
    pub write_buffer: NonZeroUsize,

    /// Strategy used to parallelize batch operations.
    pub strategy: S,
}

/// Codec limits for retained compact base records.
#[derive(Clone)]
pub struct BaseCfg {
    /// Allowed number of pinned frontier nodes.
    pub pinned_nodes: RangeCfg<usize>,
    /// Allowed size of the caller-owned last-commit operation bytes.
    pub last_commit_op_bytes: RangeCfg<usize>,
    /// Allowed size of the caller-owned last-commit proof bytes.
    pub last_commit_proof_bytes: RangeCfg<usize>,
}

impl Default for BaseCfg {
    fn default() -> Self {
        Self {
            pinned_nodes: (0..=MAX_PINNED_NODES).into(),
            last_commit_op_bytes: (0..).into(),
            last_commit_proof_bytes: (0..).into(),
        }
    }
}

fn base_log_config<S: Strategy>(cfg: &Config<S>) -> JournalConfig<BaseCfg> {
    JournalConfig {
        partition: format!("{}-bases", cfg.partition),
        items_per_section: cfg.items_per_section,
        compression: None,
        codec_config: BaseCfg::default(),
        page_cache: cfg.page_cache.clone(),
        write_buffer: cfg.write_buffer,
    }
}

/// Retained compact state captured at a durable sync boundary.
#[derive(Clone)]
pub(crate) struct Base<F: Family, D: Digest> {
    /// Authenticated root for this base.
    pub(crate) root: D,
    /// Total leaves committed by this base.
    pub(crate) leaf_count: Location<F>,
    /// Inactivity floor associated with this base.
    pub(crate) floor: Location<F>,
    /// Frontier nodes pinned by this base.
    pub(crate) pinned_nodes: Vec<D>,
    /// Caller-owned encoded last-commit operation bytes.
    pub(crate) last_commit_op_bytes: Vec<u8>,
    /// Caller-owned encoded last-commit proof bytes.
    pub(crate) last_commit_proof_bytes: Vec<u8>,
}

impl<F: Family, D: Digest> Write for Base<F, D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.root.write(buf);
        self.leaf_count.write(buf);
        self.floor.write(buf);
        self.pinned_nodes.write(buf);
        self.last_commit_op_bytes.write(buf);
        self.last_commit_proof_bytes.write(buf);
    }
}

impl<F: Family, D: Digest> EncodeSize for Base<F, D> {
    fn encode_size(&self) -> usize {
        self.root.encode_size()
            + self.leaf_count.encode_size()
            + self.floor.encode_size()
            + self.pinned_nodes.encode_size()
            + self.last_commit_op_bytes.encode_size()
            + self.last_commit_proof_bytes.encode_size()
    }
}

impl<F: Family, D: Digest> Read for Base<F, D> {
    type Cfg = BaseCfg;

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        let root = D::read_cfg(buf, &())?;
        let leaf_count = Location::<F>::read_cfg(buf, &())?;
        let floor = Location::<F>::read_cfg(buf, &())?;
        let pinned_nodes = Vec::<D>::read_cfg(buf, &(cfg.pinned_nodes, ()))?;
        let last_commit_op_bytes = Vec::<u8>::read_cfg(buf, &(cfg.last_commit_op_bytes, ()))?;
        let last_commit_proof_bytes = Vec::<u8>::read_cfg(buf, &(cfg.last_commit_proof_bytes, ()))?;
        Ok(Self {
            root,
            leaf_count,
            floor,
            pinned_nodes,
            last_commit_op_bytes,
            last_commit_proof_bytes,
        })
    }
}

/// A Merkle structure that persists only the state required to continue appending.
pub struct Merkle<F: Family, E: Context, D: Digest, S: Strategy> {
    inner: RwLock<Mem<F, D>>,
    base_log: Journal<E, Base<F, D>>,
    retained: RwLock<RetainedBases<F, D>>,
    sync_lock: AsyncMutex<()>,
    strategy: S,
    replace_on_next_sync: RwLock<bool>,
}

enum PersistMode {
    Write,
    Commit,
    SyncStart,
    Sync,
}

#[derive(Clone)]
struct RetainedBases<F: Family, D: Digest> {
    bases: BTreeMap<u64, Base<F, D>>,
    by_target: BTreeMap<(u64, Vec<u8>), u64>,
    current_position: Option<u64>,
}

impl<F: Family, D: Digest> Default for RetainedBases<F, D> {
    fn default() -> Self {
        Self {
            bases: BTreeMap::new(),
            by_target: BTreeMap::new(),
            current_position: None,
        }
    }
}

impl<F: Family, D: Digest> RetainedBases<F, D> {
    fn insert(&mut self, position: u64, base: Base<F, D>) {
        self.by_target
            .insert((*base.leaf_count, base.root.to_vec()), position);
        self.current_position = Some(position);
        self.bases.insert(position, base);
    }

    fn current(&self) -> Option<&Base<F, D>> {
        self.current_position
            .and_then(|position| self.bases.get(&position))
    }

    fn previous_position(&self) -> Option<u64> {
        let current = self.current_position?;
        self.bases
            .range(..current)
            .next_back()
            .map(|(position, _)| *position)
    }

    fn position_for_target(&self, leaf_count: Location<F>, root: D) -> Option<u64> {
        self.by_target.get(&(*leaf_count, root.to_vec())).copied()
    }

    fn truncate_after(&mut self, position: u64) {
        let removed = self
            .bases
            .split_off(&(position.checked_add(1).expect("position overflow")));
        for base in removed.values() {
            self.by_target
                .remove(&(*base.leaf_count, base.root.to_vec()));
        }
        self.current_position = self.bases.keys().next_back().copied();
    }

    fn clear(&mut self) {
        self.bases.clear();
        self.by_target.clear();
        self.current_position = None;
    }
}

impl<F: Family, E: Context, D: Digest, S: Strategy> Merkle<F, E, D, S> {
    const fn validate_persisted_leaves(leaves: Location<F>) -> Result<(), Error<F>> {
        if !leaves.is_valid() {
            return Err(Error::DataCorrupted("base size exceeds MAX_LEAVES"));
        }
        Ok(())
    }

    fn validate_base(base: &Base<F, D>) -> Result<(), Error<F>> {
        Self::validate_persisted_leaves(base.leaf_count)?;
        if base.pinned_nodes.len() != F::nodes_to_pin(base.leaf_count).count() {
            return Err(Error::InvalidPinnedNodes);
        }
        if base.leaf_count == 0 && base.floor != 0 {
            return Err(Error::DataCorrupted("invalid compact base floor"));
        }
        if base.leaf_count > 0 && base.floor > Location::new(*base.leaf_count - 1) {
            return Err(Error::DataCorrupted("invalid compact base floor"));
        }
        Ok(())
    }

    fn mem_from_base(base: &Base<F, D>) -> Result<Mem<F, D>, Error<F>> {
        if base.leaf_count == 0 {
            Ok(Mem::new())
        } else {
            Ok(Mem::init(MemConfig {
                nodes: vec![],
                pruning_boundary: base.leaf_count,
                pinned_nodes: base.pinned_nodes.clone(),
            })?)
        }
    }

    async fn load_retained_bases(
        base_log: &Journal<E, Base<F, D>>,
    ) -> Result<RetainedBases<F, D>, Error<F>> {
        let reader = base_log.reader().await;
        let mut retained = RetainedBases::default();
        for position in reader.bounds() {
            let base = reader.read(position).await?;
            Self::validate_base(&base)?;
            retained.insert(position, base);
        }
        Ok(retained)
    }

    /// Initialize a new `Merkle` instance, rebuilding in-memory state from the last sync.
    pub async fn init(context: E, cfg: Config<S>) -> Result<Self, Error<F>> {
        let base_log =
            Journal::<_, Base<F, D>>::init(context.child("compact_bases"), base_log_config(&cfg))
                .await?;
        let retained = Self::load_retained_bases(&base_log).await?;
        let mem = if let Some(base) = retained.current() {
            Self::mem_from_base(base)?
        } else {
            Mem::new()
        };

        Ok(Self {
            inner: RwLock::new(mem),
            base_log,
            retained: RwLock::new(retained),
            sync_lock: AsyncMutex::new(()),
            strategy: cfg.strategy,
            replace_on_next_sync: RwLock::new(false),
        })
    }

    /// Initialize from compact state without persisting it.
    ///
    /// Callers use this to reconstruct a compact tree in memory, verify that its root matches an
    /// authenticated target, and only then persist it with [`Self::sync_with_witness`].
    ///
    /// Existing retained bases are ignored in memory here; if verification fails before a later
    /// successful [`Self::sync_with_witness`], the on-disk state remains untouched. Once persistence
    /// succeeds, the previous compact history in this partition is replaced by the newly initialized
    /// state.
    /// Root verification itself happens at the QMDB layer after reconstruction, because that layer
    /// owns the typed final commit operation needed to authenticate the caller's requested target.
    pub(crate) async fn init_from_compact_state(
        context: E,
        cfg: Config<S>,
        leaves: Location<F>,
        pinned_nodes: Vec<D>,
    ) -> Result<Self, Error<F>> {
        Self::validate_persisted_leaves(leaves)?;
        if pinned_nodes.len() != F::nodes_to_pin(leaves).count() {
            return Err(Error::InvalidPinnedNodes);
        }

        let base_log =
            Journal::<_, Base<F, D>>::init(context.child("compact_bases"), base_log_config(&cfg))
                .await?;

        let mem = if leaves == 0 {
            Mem::new()
        } else {
            Mem::init(MemConfig {
                nodes: vec![],
                pruning_boundary: leaves,
                pinned_nodes,
            })?
        };

        let merkle = Self {
            inner: RwLock::new(mem),
            base_log,
            retained: RwLock::new(RetainedBases::default()),
            sync_lock: AsyncMutex::new(()),
            strategy: cfg.strategy,
            replace_on_next_sync: RwLock::new(true),
        };
        Ok(merkle)
    }

    /// Return the root digest of the current committed state.
    pub fn root(
        &self,
        hasher: &impl Hasher<F, Digest = D>,
        inactive_peaks: usize,
    ) -> Result<D, Error<F>> {
        self.inner.read().root(hasher, inactive_peaks)
    }

    /// Return the total number of nodes (MMR position count, not leaf count).
    pub fn size(&self) -> Position<F> {
        self.inner.read().size()
    }

    /// Return the number of leaves in the structure.
    pub fn leaves(&self) -> Location<F> {
        self.inner.read().leaves()
    }

    /// Return a reference to the merkleization strategy.
    pub const fn strategy(&self) -> &S {
        &self.strategy
    }

    /// Return the retained base currently holding the committed state.
    pub(crate) fn active_base(&self) -> Option<Base<F, D>> {
        self.retained.read().current().cloned()
    }

    /// Borrow the committed in-memory [`Mem`].
    pub fn with_mem<R>(&self, f: impl FnOnce(&Mem<F, D>) -> R) -> R {
        let inner = self.inner.read();
        f(&inner)
    }

    /// Create a new speculative batch with this structure as its parent.
    pub fn new_batch(&self) -> UnmerkleizedBatch<F, D, S> {
        let inner = self.inner.read();
        UnmerkleizedBatch::wrap(inner.new_batch_with_strategy(self.strategy.clone()))
    }

    /// Create an owned merkleized batch representing the current committed state.
    pub(crate) fn to_batch(&self) -> Arc<batch::MerkleizedBatch<F, D, S>> {
        let inner = self.inner.read();
        batch::MerkleizedBatch::from_mem_with_strategy(&inner, self.strategy.clone())
    }

    /// Apply a merkleized batch to the in-memory structure.
    pub fn apply_batch(&mut self, batch: &batch::MerkleizedBatch<F, D, S>) -> Result<(), Error<F>> {
        self.inner.get_mut().apply_batch(batch)
    }

    /// Persist the tree state to the retained-base log together with a caller-provided witness.
    ///
    /// This is the only safe way to durably persist state from this Merkle. The `build_witness`
    /// closure is the caller's one chance to capture anything that depends on the unpruned
    /// [`Mem`]; after this method completes, the in-memory tree is pruned to peaks only and that
    /// information is no longer recoverable locally.
    ///
    /// The `build_witness` closure runs against the unpruned [`Mem`] under `sync_lock`, making it
    /// the only safe place to capture data that would be lost by peak-only pruning. The `build_base`
    /// closure then receives the captured leaf count, pinned nodes, and witness and returns the base
    /// record to append. `build_witness` must stay fully synchronous and non-blocking: it runs while a
    /// read lock is held on the committed in-memory tree, so it must not `.await` or do unexpectedly
    /// heavy work.
    async fn persist_with_witness<W, R>(
        &self,
        mode: PersistMode,
        build_witness: impl FnOnce(&Mem<F, D>) -> Result<W, Error<F>>,
        build_base: impl FnOnce(Location<F>, Vec<D>, W) -> Result<(Base<F, D>, R), Error<F>>,
    ) -> Result<R, Error<F>> {
        let _sync_guard = self.sync_lock.lock().await;

        let (leaves, pinned_nodes, witness) = {
            let inner = self.inner.read();
            let leaves = inner.leaves();
            let pinned_nodes = F::nodes_to_pin(leaves)
                .map(|pos| *inner.get_node_unchecked(pos))
                .collect::<Vec<_>>();
            let witness = build_witness(&inner)?;
            (leaves, pinned_nodes, witness)
        };

        let (base, result) = build_base(leaves, pinned_nodes, witness)?;
        Self::validate_base(&base)?;

        let current_matches = self.retained.read().current().is_some_and(|current| {
            current.leaf_count == base.leaf_count && current.root == base.root
        });
        if current_matches {
            match mode {
                PersistMode::Write => {}
                PersistMode::Commit => self.base_log.commit().await?,
                PersistMode::SyncStart => self.base_log.sync_start().await?,
                PersistMode::Sync => self.base_log.sync().await?,
            }
            self.inner.write().prune_all();
            return Ok(result);
        }

        if *self.replace_on_next_sync.read() {
            self.base_log.clear_to_size(0).await?;
            self.retained.write().clear();
            *self.replace_on_next_sync.write() = false;
        }

        let position = self.base_log.append(&base).await?;
        match mode {
            PersistMode::Write => {}
            PersistMode::Commit => self.base_log.commit().await?,
            PersistMode::SyncStart => self.base_log.sync_start().await?,
            PersistMode::Sync => self.base_log.sync().await?,
        }
        self.retained.write().insert(position, base);

        self.inner.write().prune_all();
        Ok(result)
    }

    /// Write the tree state to the retained-base log together with a caller-provided witness.
    ///
    /// This appends pending base bytes but does not call `flush()`, `commit()`, or `sync()` on the
    /// journal.
    pub(crate) async fn write_with_witness<W, R>(
        &self,
        build_witness: impl FnOnce(&Mem<F, D>) -> Result<W, Error<F>>,
        build_base: impl FnOnce(Location<F>, Vec<D>, W) -> Result<(Base<F, D>, R), Error<F>>,
    ) -> Result<R, Error<F>> {
        self.persist_with_witness(PersistMode::Write, build_witness, build_base)
            .await
    }

    /// Commit the tree state to the retained-base log together with a caller-provided witness.
    pub(crate) async fn commit_with_witness<W, R>(
        &self,
        build_witness: impl FnOnce(&Mem<F, D>) -> Result<W, Error<F>>,
        build_base: impl FnOnce(Location<F>, Vec<D>, W) -> Result<(Base<F, D>, R), Error<F>>,
    ) -> Result<R, Error<F>> {
        self.persist_with_witness(PersistMode::Commit, build_witness, build_base)
            .await
    }

    /// Start syncing the tree state to the retained-base log together with a caller-provided witness.
    pub(crate) async fn sync_start_with_witness<W, R>(
        &self,
        build_witness: impl FnOnce(&Mem<F, D>) -> Result<W, Error<F>>,
        build_base: impl FnOnce(Location<F>, Vec<D>, W) -> Result<(Base<F, D>, R), Error<F>>,
    ) -> Result<R, Error<F>> {
        self.persist_with_witness(PersistMode::SyncStart, build_witness, build_base)
            .await
    }

    /// Sync the tree state to the retained-base log together with a caller-provided witness.
    pub(crate) async fn sync_with_witness<W, R>(
        &self,
        build_witness: impl FnOnce(&Mem<F, D>) -> Result<W, Error<F>>,
        build_base: impl FnOnce(Location<F>, Vec<D>, W) -> Result<(Base<F, D>, R), Error<F>>,
    ) -> Result<R, Error<F>> {
        self.persist_with_witness(PersistMode::Sync, build_witness, build_base)
            .await
    }

    /// Restore the state as of the sync before the most recent one.
    ///
    /// Truncates the retained-base log to the previous base and rebuilds the in-memory structure
    /// from that base. Any uncommitted `apply_batch` calls since the last `sync` are discarded.
    pub(crate) async fn rewind(&mut self) -> Result<Base<F, D>, Error<F>> {
        let _sync_guard = self.sync_lock.lock().await;
        let position = self
            .retained
            .read()
            .previous_position()
            .ok_or(Error::RewindBeyondHistory)?;
        self.rewind_to_position(position).await
    }

    /// Restore the retained base matching `leaf_count` and `root`.
    pub(crate) async fn rewind_to_base(
        &mut self,
        leaf_count: Location<F>,
        root: D,
    ) -> Result<Base<F, D>, Error<F>> {
        let _sync_guard = self.sync_lock.lock().await;
        let position = self
            .retained
            .read()
            .position_for_target(leaf_count, root)
            .ok_or(Error::RewindBeyondHistory)?;
        self.rewind_to_position(position).await
    }

    /// Start syncing the retained base matching `leaf_count` and `root`.
    pub(crate) async fn sync_start_to_base(
        &self,
        leaf_count: Location<F>,
        root: D,
    ) -> Result<(), Error<F>> {
        let _sync_guard = self.sync_lock.lock().await;
        let position = self
            .retained
            .read()
            .position_for_target(leaf_count, root)
            .ok_or(Error::RewindBeyondHistory)?;
        let end = position.checked_add(1).expect("base log position overflow");
        self.base_log.sync_start_to(end).await?;
        Ok(())
    }

    async fn rewind_to_position(&self, position: u64) -> Result<Base<F, D>, Error<F>> {
        let base = self
            .retained
            .read()
            .bases
            .get(&position)
            .cloned()
            .ok_or(Error::RewindBeyondHistory)?;
        let new_mem = Self::mem_from_base(&base)?;

        self.base_log.rewind(position + 1).await?;
        self.base_log.sync().await?;
        self.retained.write().truncate_after(position);
        *self.inner.write() = new_mem;
        Ok(base)
    }

    /// Prune retained bases before the base at `leaf_count`.
    pub(crate) async fn prune(&self, leaf_count: Location<F>, root: D) -> Result<(), Error<F>> {
        let _sync_guard = self.sync_lock.lock().await;
        let position = self
            .retained
            .read()
            .position_for_target(leaf_count, root)
            .ok_or(Error::RewindBeyondHistory)?;
        let end = position.checked_add(1).expect("base log position overflow");
        self.base_log.wait_for_sync_to(end).await?;
        self.base_log.prune(position).await?;
        self.base_log.wait_for_sync_to(end).await?;
        *self.retained.write() = Self::load_retained_bases(&self.base_log).await?;
        Ok(())
    }

    /// Durably persist the current tree state to disk.
    pub async fn sync(&self) -> Result<(), Error<F>> {
        self.sync_with_witness(
            |_| Ok(()),
            |leaf_count, pinned_nodes, ()| {
                Ok((
                    Base {
                        root: D::EMPTY,
                        leaf_count,
                        floor: Location::new(0),
                        pinned_nodes,
                        last_commit_op_bytes: Vec::new(),
                        last_commit_proof_bytes: Vec::new(),
                    },
                    (),
                ))
            },
        )
        .await
        .map(|_| ())
    }

    /// Write the current tree state to disk without waiting for durability.
    pub async fn commit(&self) -> Result<(), Error<F>> {
        self.commit_with_witness(
            |_| Ok(()),
            |leaf_count, pinned_nodes, ()| {
                Ok((
                    Base {
                        root: D::EMPTY,
                        leaf_count,
                        floor: Location::new(0),
                        pinned_nodes,
                        last_commit_op_bytes: Vec::new(),
                        last_commit_proof_bytes: Vec::new(),
                    },
                    (),
                ))
            },
        )
        .await
        .map(|_| ())
    }

    /// Destroy all persisted state associated with this structure.
    pub async fn destroy(self) -> Result<(), Error<F>> {
        self.base_log.destroy().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::{hasher::Standard as StandardHasher, mmb, mmr, Bagging::ForwardFold};
    use commonware_cryptography::Sha256;
    use commonware_parallel::Sequential;
    use commonware_runtime::{
        buffer::paged::CacheRef, deterministic, Runner as _, Supervisor as _,
    };
    use commonware_utils::{NZUsize, NZU16, NZU64};
    use std::num::{NonZeroU16, NonZeroUsize};

    const PAGE_SIZE: NonZeroU16 = NZU16!(77);
    const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(9);

    type TestMerkle<F> = Merkle<
        F,
        deterministic::Context,
        <Sha256 as commonware_cryptography::Hasher>::Digest,
        Sequential,
    >;

    fn test_config(context: &deterministic::Context, partition: &str) -> Config<Sequential> {
        let page_cache = CacheRef::from_pooler(context, PAGE_SIZE, PAGE_CACHE_SIZE);
        Config {
            partition: partition.into(),
            items_per_section: NZU64!(7),
            page_cache,
            write_buffer: NZUsize!(1024),
            strategy: Sequential,
        }
    }

    async fn open<F: Family>(context: deterministic::Context, partition: &str) -> TestMerkle<F> {
        let cfg = test_config(&context, partition);
        TestMerkle::<F>::init(context, cfg).await.unwrap()
    }

    async fn append_and_sync<F: Family>(merkle: &mut TestMerkle<F>, values: &[&[u8]]) {
        let hasher = StandardHasher::<Sha256>::new(ForwardFold);
        let batch = {
            let mut b = merkle.new_batch();
            for v in values {
                b = b.add(&hasher, v);
            }
            merkle.with_mem(|mem| b.merkleize(mem, &hasher))
        };
        merkle.apply_batch(&batch).unwrap();
        merkle.sync().await.unwrap();
    }

    async fn assert_reopen_and_continue<F: Family>(
        context: deterministic::Context,
        partition: &str,
    ) {
        let hasher = StandardHasher::<Sha256>::new(ForwardFold);
        let cfg = test_config(&context, partition);

        let mut merkle = TestMerkle::<F>::init(context.child("first"), cfg.clone())
            .await
            .unwrap();
        let batch = {
            let batch = merkle.new_batch().add(&hasher, b"a").add(&hasher, b"b");
            merkle.with_mem(|mem| batch.merkleize(mem, &hasher))
        };
        merkle.apply_batch(&batch).unwrap();
        let root_before = merkle.root(&hasher, 0).unwrap();
        let leaves_before = merkle.leaves();
        merkle.sync().await.unwrap();
        drop(merkle);

        let mut reopened = TestMerkle::<F>::init(context.child("second"), cfg)
            .await
            .unwrap();
        assert_eq!(reopened.root(&hasher, 0).unwrap(), root_before);
        assert_eq!(reopened.leaves(), leaves_before);

        let batch = {
            let batch = reopened.new_batch().add(&hasher, b"c");
            reopened.with_mem(|mem| batch.merkleize(mem, &hasher))
        };
        reopened.apply_batch(&batch).unwrap();
        reopened.sync().await.unwrap();
    }

    #[test]
    fn test_compact_reopen_and_continue_mmr() {
        deterministic::Runner::default().start(|context| async move {
            assert_reopen_and_continue::<mmr::Family>(context, "compact-mmr").await;
        });
    }

    #[test]
    fn test_compact_reopen_and_continue_mmb() {
        deterministic::Runner::default().start(|context| async move {
            assert_reopen_and_continue::<mmb::Family>(context, "compact-mmb").await;
        });
    }

    async fn assert_rewind_restores_prior_state<F: Family>(
        context: deterministic::Context,
        partition: &str,
    ) {
        let hasher = StandardHasher::<Sha256>::new(ForwardFold);
        let mut merkle = open::<F>(context, partition).await;

        append_and_sync(&mut merkle, &[b"a", b"b"]).await;
        let root_after_first = merkle.root(&hasher, 0).unwrap();
        let leaves_after_first = merkle.leaves();

        append_and_sync(&mut merkle, &[b"c"]).await;
        assert_ne!(merkle.root(&hasher, 0).unwrap(), root_after_first);

        merkle.rewind().await.unwrap();
        assert_eq!(merkle.root(&hasher, 0).unwrap(), root_after_first);
        assert_eq!(merkle.leaves(), leaves_after_first);

        merkle.destroy().await.unwrap();
    }

    #[test]
    fn test_rewind_restores_prior_state_mmr() {
        deterministic::Runner::default().start(|context| async move {
            assert_rewind_restores_prior_state::<mmr::Family>(context, "rewind-prior-mmr").await;
        });
    }

    #[test]
    fn test_rewind_restores_prior_state_mmb() {
        deterministic::Runner::default().start(|context| async move {
            assert_rewind_restores_prior_state::<mmb::Family>(context, "rewind-prior-mmb").await;
        });
    }

    #[test]
    fn test_rewind_beyond_history_errors() {
        deterministic::Runner::default().start(|context| async move {
            let mut merkle = open::<mmr::Family>(context, "rewind-beyond").await;
            // No prior sync: rewind should fail with RewindBeyondHistory.
            assert!(matches!(
                merkle.rewind().await,
                Err(Error::RewindBeyondHistory)
            ));
            // After one sync, the previous slot is still empty (nothing has been overwritten);
            // a rewind should still fail.
            append_and_sync(&mut merkle, &[b"a"]).await;
            assert!(matches!(
                merkle.rewind().await,
                Err(Error::RewindBeyondHistory)
            ));
            merkle.destroy().await.unwrap();
        });
    }

    #[test]
    fn test_rewind_discards_uncommitted() {
        deterministic::Runner::default().start(|context| async move {
            let hasher = StandardHasher::<Sha256>::new(ForwardFold);
            let mut merkle = open::<mmr::Family>(context, "rewind-uncommitted").await;

            append_and_sync(&mut merkle, &[b"a"]).await;
            append_and_sync(&mut merkle, &[b"b"]).await;
            let root_after_two = merkle.root(&hasher, 0).unwrap();
            let leaves_after_two = merkle.leaves();

            // Apply a batch but do not sync. State is ahead of the last persisted slot.
            let batch = {
                let b = merkle.new_batch().add(&hasher, b"c");
                merkle.with_mem(|mem| b.merkleize(mem, &hasher))
            };
            merkle.apply_batch(&batch).unwrap();
            assert_ne!(merkle.root(&hasher, 0).unwrap(), root_after_two);

            // Rewind reverts to the state as of the sync before the most recent sync, discarding
            // both the uncommitted append and the most recent sync.
            merkle.rewind().await.unwrap();
            assert_ne!(merkle.root(&hasher, 0).unwrap(), root_after_two);
            assert_ne!(merkle.leaves(), leaves_after_two);

            merkle.destroy().await.unwrap();
        });
    }

    #[test]
    fn test_rewind_persists_across_reopen() {
        deterministic::Runner::default().start(|context| async move {
            let hasher = StandardHasher::<Sha256>::new(ForwardFold);
            let partition = "rewind-reopen";
            let cfg = test_config(&context, partition);

            let mut merkle = open::<mmr::Family>(context.child("first"), partition).await;
            append_and_sync(&mut merkle, &[b"a"]).await;
            let root_after_first = merkle.root(&hasher, 0).unwrap();
            append_and_sync(&mut merkle, &[b"b"]).await;
            merkle.rewind().await.unwrap();
            drop(merkle);

            let reopened: TestMerkle<mmr::Family> =
                Merkle::<mmr::Family, _, _, Sequential>::init(context.child("second"), cfg)
                    .await
                    .unwrap();
            assert_eq!(reopened.root(&hasher, 0).unwrap(), root_after_first);
            reopened.destroy().await.unwrap();
        });
    }

    #[test]
    fn test_double_rewind_errors() {
        deterministic::Runner::default().start(|context| async move {
            let mut merkle = open::<mmr::Family>(context, "rewind-double").await;
            append_and_sync(&mut merkle, &[b"a"]).await;
            append_and_sync(&mut merkle, &[b"b"]).await;
            merkle.rewind().await.unwrap();
            assert!(matches!(
                merkle.rewind().await,
                Err(Error::RewindBeyondHistory)
            ));
            merkle.destroy().await.unwrap();
        });
    }

    #[test]
    fn test_rewind_then_sync_then_rewind() {
        deterministic::Runner::default().start(|context| async move {
            let hasher = StandardHasher::<Sha256>::new(ForwardFold);
            let mut merkle = open::<mmr::Family>(context, "rewind-resumable").await;

            append_and_sync(&mut merkle, &[b"a"]).await;
            let root_after_first = merkle.root(&hasher, 0).unwrap();
            append_and_sync(&mut merkle, &[b"b"]).await;
            merkle.rewind().await.unwrap();
            assert_eq!(merkle.root(&hasher, 0).unwrap(), root_after_first);

            // Now sync a different branch. Rewind should restore `root_after_first` again.
            append_and_sync(&mut merkle, &[b"c"]).await;
            let root_abc = merkle.root(&hasher, 0).unwrap();
            assert_ne!(root_abc, root_after_first);
            merkle.rewind().await.unwrap();
            assert_eq!(merkle.root(&hasher, 0).unwrap(), root_after_first);

            merkle.destroy().await.unwrap();
        });
    }

    #[test]
    fn test_reopen_rejects_invalid_base_pins() {
        deterministic::Runner::default().start(|context| async move {
            let partition = "compact-invalid-base-pins";
            let cfg = test_config(&context, partition);
            let base_log = Journal::<_, Base<mmr::Family, _>>::init(
                context.child("tamper"),
                base_log_config(&cfg),
            )
            .await
            .unwrap();
            base_log
                .append(&Base {
                    root: <<Sha256 as commonware_cryptography::Hasher>::Digest as commonware_cryptography::Digest>::EMPTY,
                    leaf_count: Location::new(2),
                    floor: Location::new(0),
                    pinned_nodes: Vec::new(),
                    last_commit_op_bytes: Vec::new(),
                    last_commit_proof_bytes: Vec::new(),
                })
                .await
                .unwrap();
            base_log.sync().await.unwrap();

            let reopened = TestMerkle::<mmr::Family>::init(context.child("second"), cfg).await;
            assert!(matches!(reopened, Err(Error::InvalidPinnedNodes)));
        });
    }
}
