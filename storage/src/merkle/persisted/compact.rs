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
//! # One-step rewind
//!
//! State is persisted into one of two slots on disk, with a generation pointer identifying the
//! active slot. Each `sync` writes the new state to the *other* slot and flips the pointer
//! atomically. The `rewind` entry point flips the pointer back and clears the now-stale slot,
//! restoring the state as of the sync before the most recent one. Rewind is one-shot until the
//! next `sync`.

use crate::{
    merkle::{
        batch,
        hasher::Hasher,
        mem::{Config as MemConfig, Mem},
        Error, Family, Location, Position,
    },
    metadata::{Config as MConfig, Metadata},
    Context,
};
use commonware_codec::DecodeExt;
use commonware_cryptography::Digest;
use commonware_parallel::ThreadPool;
use commonware_utils::{
    sequence::prefixed_u64::U64,
    sync::{AsyncMutex, RwLock},
};
use std::sync::Arc;

/// Append-only wrapper around [`batch::UnmerkleizedBatch`].
pub struct UnmerkleizedBatch<F: Family, D: Digest> {
    inner: batch::UnmerkleizedBatch<F, D>,
}

impl<F: Family, D: Digest> UnmerkleizedBatch<F, D> {
    /// Wrap an existing [`batch::UnmerkleizedBatch`] as an append-only batch.
    pub(crate) const fn wrap(inner: batch::UnmerkleizedBatch<F, D>) -> Self {
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

    /// Set a thread pool for parallel merkleization.
    pub fn with_pool(self, pool: Option<ThreadPool>) -> Self {
        Self {
            inner: self.inner.with_pool(pool),
        }
    }

    /// Consume this batch and produce an immutable [`batch::MerkleizedBatch`] with computed root.
    pub fn merkleize(
        self,
        base: &Mem<F, D>,
        hasher: &impl Hasher<F, Digest = D>,
    ) -> Arc<batch::MerkleizedBatch<F, D>> {
        self.inner.merkleize(base, hasher)
    }
}

/// Configuration for a compact Merkle structure.
#[derive(Clone)]
pub struct Config {
    /// Metadata partition used to persist the current compact state.
    pub partition: String,

    /// Optional thread pool used for batch merkleization.
    pub thread_pool: Option<ThreadPool>,
}

/// A Merkle structure that persists only the state required to continue appending.
pub struct Merkle<F: Family, E: Context, D: Digest> {
    inner: RwLock<Mem<F, D>>,
    metadata: AsyncMutex<Metadata<E, U64, Vec<u8>>>,
    sync_lock: AsyncMutex<()>,
    pool: Option<ThreadPool>,
    /// Active slot (0 or 1). Source of truth lives on disk under `GEN_PTR_PREFIX`; this is an
    /// in-memory cache refreshed on every `sync_with` and `rewind`.
    active_slot: RwLock<u8>,
}

// Metadata key prefixes. The Merkle persists into one of two slots (A=0, B=1); `GEN_PTR_PREFIX`
// records which slot is currently active. Each `sync` writes to the other slot and flips the
// pointer atomically, giving one-step rewind.
const GEN_PTR_PREFIX: u8 = 0;
const SLOT_A_SIZE_PREFIX: u8 = 1;
const SLOT_A_NODE_PREFIX: u8 = 2;
const SLOT_B_SIZE_PREFIX: u8 = 3;
const SLOT_B_NODE_PREFIX: u8 = 4;

const fn size_prefix(slot: u8) -> u8 {
    if slot == 0 {
        SLOT_A_SIZE_PREFIX
    } else {
        SLOT_B_SIZE_PREFIX
    }
}

const fn node_prefix(slot: u8) -> u8 {
    if slot == 0 {
        SLOT_A_NODE_PREFIX
    } else {
        SLOT_B_NODE_PREFIX
    }
}

impl<F: Family, E: Context, D: Digest> Merkle<F, E, D> {
    const fn validate_persisted_leaves(leaves: Location<F>) -> Result<(), Error<F>> {
        if !leaves.is_valid() {
            return Err(Error::DataCorrupted("slot size exceeds MAX_LEAVES"));
        }
        Ok(())
    }

    /// Read the active slot pointer, defaulting to 0 if absent.
    fn read_gen_ptr(metadata: &Metadata<E, U64, Vec<u8>>) -> Result<Option<u8>, Error<F>> {
        let Some(raw) = metadata.get(&U64::new(GEN_PTR_PREFIX, 0)) else {
            return Ok(None);
        };
        if raw.len() != 1 || (raw[0] != 0 && raw[0] != 1) {
            return Err(Error::DataCorrupted("invalid generation pointer"));
        }
        Ok(Some(raw[0]))
    }

    /// Read the size key for a given slot, returning `None` if the slot is unpopulated.
    fn read_slot_size(
        metadata: &Metadata<E, U64, Vec<u8>>,
        slot: u8,
    ) -> Result<Option<Location<F>>, Error<F>> {
        let Some(raw) = metadata.get(&U64::new(size_prefix(slot), 0)) else {
            return Ok(None);
        };
        let bytes: [u8; 8] = raw
            .as_slice()
            .try_into()
            .map_err(|_| Error::DataCorrupted("slot size is not 8 bytes"))?;
        let leaves = Location::new(u64::from_be_bytes(bytes));
        Self::validate_persisted_leaves(leaves)?;
        Ok(Some(leaves))
    }

    /// Remove all pin entries for a given slot.
    fn clear_slot_pins(metadata: &mut Metadata<E, U64, Vec<u8>>, slot: u8, leaves: Location<F>) {
        let pin_count = F::nodes_to_pin(leaves).count();
        for i in 0..pin_count {
            metadata.remove(&U64::new(node_prefix(slot), i as u64));
        }
    }

    /// Clear both the pins and the size key for a slot, marking it as unpopulated so that
    /// subsequent rewinds targeting it will fail with `RewindBeyondHistory`.
    fn clear_slot(metadata: &mut Metadata<E, U64, Vec<u8>>, slot: u8, leaves: Location<F>) {
        Self::clear_slot_pins(metadata, slot, leaves);
        metadata.remove(&U64::new(size_prefix(slot), 0));
    }

    fn load_slot_pins(
        metadata: &Metadata<E, U64, Vec<u8>>,
        slot: u8,
        leaves: Location<F>,
    ) -> Result<Vec<D>, Error<F>> {
        let mut pinned = Vec::new();
        for (idx, pos) in F::nodes_to_pin(leaves).enumerate() {
            let bytes = metadata
                .get(&U64::new(node_prefix(slot), idx as u64))
                .ok_or(Error::MissingNode(pos))?;
            let digest = D::decode(bytes.as_ref())
                .map_err(|_| Error::DataCorrupted("invalid pinned node"))?;
            pinned.push(digest);
        }
        Ok(pinned)
    }

    /// Initialize a new `Merkle` instance, rebuilding in-memory state from the last sync.
    pub async fn init(
        context: E,
        hasher: &impl Hasher<F, Digest = D>,
        cfg: Config,
    ) -> Result<Self, Error<F>> {
        let metadata = Metadata::<_, U64, Vec<u8>>::init(
            context.with_label("compact_metadata"),
            MConfig {
                partition: cfg.partition,
                codec_config: ((0..).into(), ()),
            },
        )
        .await?;

        let active_slot = Self::read_gen_ptr(&metadata)?.unwrap_or(0);
        let leaves = Self::read_slot_size(&metadata, active_slot)?.unwrap_or(Location::new(0));
        let mem = if leaves == 0 {
            Mem::new(hasher)
        } else {
            Mem::init(
                MemConfig {
                    nodes: vec![],
                    pruning_boundary: leaves,
                    pinned_nodes: Self::load_slot_pins(&metadata, active_slot, leaves)?,
                },
                hasher,
            )?
        };

        Ok(Self {
            inner: RwLock::new(mem),
            metadata: AsyncMutex::new(metadata),
            sync_lock: AsyncMutex::new(()),
            pool: cfg.thread_pool,
            active_slot: RwLock::new(active_slot),
        })
    }

    /// Initialize from compact state without persisting it.
    ///
    /// Callers use this to reconstruct a compact tree in memory, verify that its root
    /// matches an authenticated target, and only then persist it with [`Self::sync_with_witness`].
    /// Starting from a cleared metadata view means the first persistence populates exactly one
    /// slot, so `rewind` will return [`Error::RewindBeyondHistory`] until a later sync overwrites
    /// the alternate slot.
    ///
    /// This path is intended for a fresh or disposable compact partition. Existing metadata is
    /// cleared only in memory here; if verification fails before a later successful
    /// [`Self::sync_with_witness`], the on-disk state remains untouched. Once persistence succeeds,
    /// the previous compact history in this partition is replaced by the newly initialized state.
    /// Root verification itself happens at the QMDB layer after reconstruction, because that layer
    /// owns the typed final commit operation needed to authenticate the caller's requested target.
    pub(crate) async fn init_from_compact_state(
        context: E,
        hasher: &impl Hasher<F, Digest = D>,
        cfg: Config,
        leaves: Location<F>,
        pinned_nodes: Vec<D>,
    ) -> Result<Self, Error<F>> {
        Self::validate_persisted_leaves(leaves)?;
        if pinned_nodes.len() != F::nodes_to_pin(leaves).count() {
            return Err(Error::InvalidPinnedNodes);
        }

        let mut metadata = Metadata::<_, U64, Vec<u8>>::init(
            context.with_label("compact_metadata"),
            MConfig {
                partition: cfg.partition,
                codec_config: ((0..).into(), ()),
            },
        )
        .await?;
        metadata.clear();

        let mem = if leaves == 0 {
            Mem::new(hasher)
        } else {
            Mem::init(
                MemConfig {
                    nodes: vec![],
                    pruning_boundary: leaves,
                    pinned_nodes,
                },
                hasher,
            )?
        };

        let merkle = Self {
            inner: RwLock::new(mem),
            metadata: AsyncMutex::new(metadata),
            sync_lock: AsyncMutex::new(()),
            pool: cfg.thread_pool,
            active_slot: RwLock::new(0),
        };
        Ok(merkle)
    }

    /// Return the root digest of the current committed state.
    pub fn root(&self) -> D {
        *self.inner.read().root()
    }

    /// Return the total number of nodes (MMR position count, not leaf count).
    pub fn size(&self) -> Position<F> {
        self.inner.read().size()
    }

    /// Return the number of leaves in the structure.
    pub fn leaves(&self) -> Location<F> {
        self.inner.read().leaves()
    }

    /// Return the thread pool, if any.
    pub fn pool(&self) -> Option<ThreadPool> {
        self.pool.clone()
    }

    /// Return the index of the slot currently holding the committed state.
    pub(crate) fn active_slot(&self) -> u8 {
        *self.active_slot.read()
    }

    /// Borrow the committed in-memory [`Mem`].
    pub fn with_mem<R>(&self, f: impl FnOnce(&Mem<F, D>) -> R) -> R {
        let inner = self.inner.read();
        f(&inner)
    }

    /// Create a new speculative batch with this structure as its parent.
    pub fn new_batch(&self) -> UnmerkleizedBatch<F, D> {
        let inner = self.inner.read();
        UnmerkleizedBatch::wrap(batch::MerkleizedBatch::from_mem(&inner).new_batch())
            .with_pool(self.pool())
    }

    /// Create an owned merkleized batch representing the current committed state.
    pub(crate) fn to_batch(&self) -> Arc<batch::MerkleizedBatch<F, D>> {
        let inner = self.inner.read();
        let mut batch = batch::MerkleizedBatch::from_mem(&inner);
        if let Some(pool) = &self.pool {
            Arc::get_mut(&mut batch).expect("just created").pool = Some(pool.clone());
        }
        batch
    }

    /// Apply a merkleized batch to the in-memory structure.
    pub fn apply_batch(&mut self, batch: &batch::MerkleizedBatch<F, D>) -> Result<(), Error<F>> {
        self.inner.get_mut().apply_batch(batch)
    }

    /// Read a metadata key from the Db's "extras" keyspace for the given slot. Used by the
    /// qmdb `CompactDb` layer to read back its own per-slot state on reopen or rewind.
    pub(crate) async fn read_metadata_key(&self, key: &U64) -> Option<Vec<u8>> {
        let metadata = self.metadata.lock().await;
        metadata.get(key).cloned()
    }

    /// Persist the tree state to the inactive slot together with a caller-provided witness.
    ///
    /// This is the only safe way to durably persist state from this Merkle. The `build_witness`
    /// closure is the caller's one chance to capture anything that depends on the unpruned
    /// [`Mem`]; after this method completes, the in-memory tree is pruned to peaks only and that
    /// information is no longer recoverable locally.
    ///
    /// The `build_witness` closure runs against the unpruned [`Mem`] under `sync_lock`, making it
    /// the only safe place to capture data that would be lost by peak-only pruning. The `update`
    /// closure then receives both the mutable [`Metadata`] store and the built witness so caller
    /// metadata and the witness are written in the same atomic transaction before the generation
    /// pointer flips. `build_witness` must stay fully synchronous and non-blocking: it runs while a
    /// read lock is held on the committed in-memory tree, so it must not `.await` or do
    /// unexpectedly heavy work. In practice this closure is where callers capture a last-leaf
    /// proof or other small authenticated snapshot that would be impossible to reconstruct once the
    /// tree is pruned back to peaks.
    pub(crate) async fn sync_with_witness<W: Clone>(
        &self,
        build_witness: impl FnOnce(&Mem<F, D>) -> Result<W, Error<F>>,
        update: impl FnOnce(&mut Metadata<E, U64, Vec<u8>>, u8, W) -> Result<(), Error<F>>,
    ) -> Result<W, Error<F>> {
        let _sync_guard = self.sync_lock.lock().await;

        let current_slot = *self.active_slot.read();
        let target_slot = 1 - current_slot;

        let (leaves, pinned_nodes, witness) = {
            let inner = self.inner.read();
            let leaves = inner.leaves();
            let pinned_nodes = F::nodes_to_pin(leaves)
                .map(|pos| *inner.get_node_unchecked(pos))
                .collect::<Vec<_>>();
            let witness = build_witness(&inner)?;
            (leaves, pinned_nodes, witness)
        };

        let cached_witness = witness.clone();
        {
            let mut metadata = self.metadata.lock().await;
            let old_target_leaves =
                Self::read_slot_size(&metadata, target_slot)?.unwrap_or(Location::new(0));
            Self::clear_slot_pins(&mut metadata, target_slot, old_target_leaves);
            metadata.put(
                U64::new(size_prefix(target_slot), 0),
                leaves.as_u64().to_be_bytes().to_vec(),
            );
            for (idx, digest) in pinned_nodes.iter().enumerate() {
                metadata.put(
                    U64::new(node_prefix(target_slot), idx as u64),
                    digest.to_vec(),
                );
            }
            update(&mut metadata, target_slot, witness)?;
            metadata.put(U64::new(GEN_PTR_PREFIX, 0), vec![target_slot]);
            metadata.sync().await?;
        }

        *self.active_slot.write() = target_slot;
        self.inner.write().prune_all();
        Ok(cached_witness)
    }

    /// Restore the state as of the sync before the most recent one.
    ///
    /// Flips the generation pointer back to the previous slot and rebuilds the in-memory
    /// structure from the (size, peaks) persisted there. Any uncommitted `apply_batch` calls
    /// since the last `sync` are discarded. The pre-rewind slot is cleared, making rewind
    /// one-shot until the next `sync` (a second rewind without an intervening sync returns
    /// [`Error::RewindBeyondHistory`]).
    ///
    /// Returns the slot index now active (caller uses this to repopulate its own per-slot
    /// caches from the matching slot).
    pub(crate) async fn rewind(
        &mut self,
        hasher: &impl Hasher<F, Digest = D>,
    ) -> Result<u8, Error<F>> {
        let _sync_guard = self.sync_lock.lock().await;

        let current_slot = *self.active_slot.read();
        let target_slot = 1 - current_slot;

        let (new_leaves, pinned_nodes) = {
            let metadata = self.metadata.lock().await;
            let Some(new_leaves) = Self::read_slot_size(&metadata, target_slot)? else {
                return Err(Error::RewindBeyondHistory);
            };
            let pinned_nodes = if new_leaves == 0 {
                Vec::new()
            } else {
                Self::load_slot_pins(&metadata, target_slot, new_leaves)?
            };
            (new_leaves, pinned_nodes)
        };

        // Rebuild Mem from the rewound slot's state. This discards any uncommitted appends.
        let new_mem = if new_leaves == 0 {
            Mem::new(hasher)
        } else {
            Mem::init(
                MemConfig {
                    nodes: vec![],
                    pruning_boundary: new_leaves,
                    pinned_nodes,
                },
                hasher,
            )?
        };

        // Atomically clear this layer's state in the pre-rewind slot (size + pins) and flip the
        // generation pointer. Removing the size key is what makes the slot "no longer a valid
        // rewind target": subsequent rewinds read `None` for its size and fail with
        // `RewindBeyondHistory`. Any caller-specific extras written alongside under separate
        // prefixes remain on disk but are harmless, since the next `sync_with` into this slot
        // overwrites them before they can be read.
        {
            let mut metadata = self.metadata.lock().await;
            let old_current_leaves =
                Self::read_slot_size(&metadata, current_slot)?.unwrap_or(Location::new(0));
            Self::clear_slot(&mut metadata, current_slot, old_current_leaves);
            metadata.put(U64::new(GEN_PTR_PREFIX, 0), vec![target_slot]);
            metadata.sync().await?;
        }

        *self.inner.write() = new_mem;
        *self.active_slot.write() = target_slot;
        Ok(target_slot)
    }

    /// Durably persist the current tree state to disk.
    pub async fn sync(&self) -> Result<(), Error<F>> {
        self.sync_with_witness(|_| Ok(()), |_, _, ()| Ok(()))
            .await
            .map(|_| ())
    }

    /// Durably persist the current tree state to disk (alias for [`Self::sync`]).
    pub async fn commit(&self) -> Result<(), Error<F>> {
        self.sync().await
    }

    /// Destroy all persisted state associated with this structure.
    pub async fn destroy(self) -> Result<(), Error<F>> {
        self.metadata.into_inner().destroy().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        merkle::{hasher::Standard as StandardHasher, mmb, mmr},
        metadata::{Config as MConfig, Metadata},
    };
    use commonware_cryptography::Sha256;
    use commonware_runtime::{deterministic, Metrics, Runner as _};

    type TestMerkle<F> =
        Merkle<F, deterministic::Context, <Sha256 as commonware_cryptography::Hasher>::Digest>;

    async fn open<F: Family>(context: deterministic::Context, partition: &str) -> TestMerkle<F> {
        TestMerkle::<F>::init(
            context,
            &StandardHasher::<Sha256>::new(),
            Config {
                partition: partition.into(),
                thread_pool: None,
            },
        )
        .await
        .unwrap()
    }

    async fn append_and_sync<F: Family>(merkle: &mut TestMerkle<F>, values: &[&[u8]]) {
        let hasher = StandardHasher::<Sha256>::new();
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
        let hasher = StandardHasher::<Sha256>::new();
        let cfg = Config {
            partition: partition.into(),
            thread_pool: None,
        };

        let mut merkle = TestMerkle::<F>::init(context.with_label("first"), &hasher, cfg.clone())
            .await
            .unwrap();
        let batch = {
            let batch = merkle.new_batch().add(&hasher, b"a").add(&hasher, b"b");
            merkle.with_mem(|mem| batch.merkleize(mem, &hasher))
        };
        merkle.apply_batch(&batch).unwrap();
        let root_before = merkle.root();
        let leaves_before = merkle.leaves();
        merkle.sync().await.unwrap();
        drop(merkle);

        let mut reopened = TestMerkle::<F>::init(context.with_label("second"), &hasher, cfg)
            .await
            .unwrap();
        assert_eq!(reopened.root(), root_before);
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
        let hasher = StandardHasher::<Sha256>::new();
        let mut merkle = open::<F>(context, partition).await;

        append_and_sync(&mut merkle, &[b"a", b"b"]).await;
        let root_after_first = merkle.root();
        let leaves_after_first = merkle.leaves();

        append_and_sync(&mut merkle, &[b"c"]).await;
        assert_ne!(merkle.root(), root_after_first);

        merkle.rewind(&hasher).await.unwrap();
        assert_eq!(merkle.root(), root_after_first);
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
            let hasher = StandardHasher::<Sha256>::new();
            let mut merkle = open::<mmr::Family>(context, "rewind-beyond").await;
            // No prior sync: rewind should fail with RewindBeyondHistory.
            assert!(matches!(
                merkle.rewind(&hasher).await,
                Err(Error::RewindBeyondHistory)
            ));
            // After one sync, the previous slot is still empty (nothing has been overwritten);
            // a rewind should still fail.
            append_and_sync(&mut merkle, &[b"a"]).await;
            assert!(matches!(
                merkle.rewind(&hasher).await,
                Err(Error::RewindBeyondHistory)
            ));
            merkle.destroy().await.unwrap();
        });
    }

    #[test]
    fn test_rewind_discards_uncommitted() {
        deterministic::Runner::default().start(|context| async move {
            let hasher = StandardHasher::<Sha256>::new();
            let mut merkle = open::<mmr::Family>(context, "rewind-uncommitted").await;

            append_and_sync(&mut merkle, &[b"a"]).await;
            append_and_sync(&mut merkle, &[b"b"]).await;
            let root_after_two = merkle.root();
            let leaves_after_two = merkle.leaves();

            // Apply a batch but do not sync. State is ahead of the last persisted slot.
            let batch = {
                let b = merkle.new_batch().add(&hasher, b"c");
                merkle.with_mem(|mem| b.merkleize(mem, &hasher))
            };
            merkle.apply_batch(&batch).unwrap();
            assert_ne!(merkle.root(), root_after_two);

            // Rewind reverts to the state as of the sync before the most recent sync, discarding
            // both the uncommitted append and the most recent sync.
            merkle.rewind(&hasher).await.unwrap();
            assert_ne!(merkle.root(), root_after_two);
            assert_ne!(merkle.leaves(), leaves_after_two);

            merkle.destroy().await.unwrap();
        });
    }

    #[test]
    fn test_rewind_persists_across_reopen() {
        deterministic::Runner::default().start(|context| async move {
            let hasher = StandardHasher::<Sha256>::new();
            let partition = "rewind-reopen";
            let cfg = Config {
                partition: partition.into(),
                thread_pool: None,
            };

            let mut merkle = open::<mmr::Family>(context.with_label("first"), partition).await;
            append_and_sync(&mut merkle, &[b"a"]).await;
            let root_after_first = merkle.root();
            append_and_sync(&mut merkle, &[b"b"]).await;
            merkle.rewind(&hasher).await.unwrap();
            drop(merkle);

            let reopened: TestMerkle<mmr::Family> =
                Merkle::<mmr::Family, _, _>::init(context.with_label("second"), &hasher, cfg)
                    .await
                    .unwrap();
            assert_eq!(reopened.root(), root_after_first);
            reopened.destroy().await.unwrap();
        });
    }

    #[test]
    fn test_double_rewind_errors() {
        deterministic::Runner::default().start(|context| async move {
            let hasher = StandardHasher::<Sha256>::new();
            let mut merkle = open::<mmr::Family>(context, "rewind-double").await;
            append_and_sync(&mut merkle, &[b"a"]).await;
            append_and_sync(&mut merkle, &[b"b"]).await;
            merkle.rewind(&hasher).await.unwrap();
            assert!(matches!(
                merkle.rewind(&hasher).await,
                Err(Error::RewindBeyondHistory)
            ));
            merkle.destroy().await.unwrap();
        });
    }

    #[test]
    fn test_rewind_then_sync_then_rewind() {
        deterministic::Runner::default().start(|context| async move {
            let hasher = StandardHasher::<Sha256>::new();
            let mut merkle = open::<mmr::Family>(context, "rewind-resumable").await;

            append_and_sync(&mut merkle, &[b"a"]).await;
            let root_after_first = merkle.root();
            append_and_sync(&mut merkle, &[b"b"]).await;
            merkle.rewind(&hasher).await.unwrap();
            assert_eq!(merkle.root(), root_after_first);

            // Now sync a different branch. Rewind should restore `root_after_first` again.
            append_and_sync(&mut merkle, &[b"c"]).await;
            let root_abc = merkle.root();
            assert_ne!(root_abc, root_after_first);
            merkle.rewind(&hasher).await.unwrap();
            assert_eq!(merkle.root(), root_after_first);

            merkle.destroy().await.unwrap();
        });
    }

    #[test]
    fn test_reopen_rejects_invalid_persisted_leaf_count() {
        deterministic::Runner::default().start(|context| async move {
            let hasher = StandardHasher::<Sha256>::new();
            let partition = "compact-invalid-leaf-count";
            let cfg = Config {
                partition: partition.into(),
                thread_pool: None,
            };

            let mut merkle =
                TestMerkle::<mmr::Family>::init(context.with_label("first"), &hasher, cfg.clone())
                    .await
                    .unwrap();
            append_and_sync(&mut merkle, &[b"a"]).await;
            let slot = merkle.active_slot();
            drop(merkle);

            let mut metadata = Metadata::<_, U64, Vec<u8>>::init(
                context.with_label("tamper"),
                MConfig {
                    partition: partition.into(),
                    codec_config: ((0..).into(), ()),
                },
            )
            .await
            .unwrap();
            metadata.put(
                U64::new(size_prefix(slot), 0),
                (mmr::Family::MAX_LEAVES.as_u64() + 1)
                    .to_be_bytes()
                    .to_vec(),
            );
            metadata.sync().await.unwrap();

            let reopened =
                TestMerkle::<mmr::Family>::init(context.with_label("second"), &hasher, cfg).await;
            assert!(matches!(
                reopened,
                Err(Error::DataCorrupted("slot size exceeds MAX_LEAVES"))
            ));
        });
    }
}
