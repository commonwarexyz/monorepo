//! Authenticated journal implementation.
//!
//! An authenticated journal maintains a contiguous journal of items alongside a Merkle-family
//! structure. The item at index i in the journal corresponds to the leaf at Location i in the
//! Merkle structure. This structure enables efficient proofs that an item is included in the
//! journal at a specific location.

use crate::{
    journal::{
        contiguous::{fixed, variable, Contiguous, Many, Mutable, Reader},
        Error as JournalError,
    },
    merkle::{
        self, batch, hasher::Standard as StandardHasher, journaled::Journaled, Family, Location,
        Position, Proof, Readable,
    },
    Context, Persistable,
};
use alloc::{
    sync::{Arc, Weak},
    vec::Vec,
};
use commonware_codec::{CodecFixedShared, CodecShared, Encode, EncodeShared};
use commonware_cryptography::{Digest, Hasher};
use core::num::NonZeroU64;
use futures::{future::try_join_all, try_join, TryFutureExt as _};
use thiserror::Error;
use tracing::{debug, warn};

/// Errors that can occur when interacting with an authenticated journal.
#[derive(Error, Debug)]
pub enum Error<F: Family> {
    #[error("merkle error: {0}")]
    Merkle(#[from] merkle::Error<F>),

    #[error("journal error: {0}")]
    Journal(#[from] super::Error),
}

/// A speculative batch whose root digest has not yet been computed,
/// in contrast to [`MerkleizedBatch`].
pub struct UnmerkleizedBatch<F: Family, H: Hasher, Item: Send + Sync> {
    // The inner batch of Merkle leaf digests.
    inner: batch::UnmerkleizedBatch<F, H::Digest>,
    // The hasher to use for hashing the items.
    hasher: StandardHasher<H>,
    // The items to append from this batch.
    items: Vec<Item>,
    // This batch's parent, or None if the parent is the journal itself.
    parent: Option<Arc<MerkleizedBatch<F, H::Digest, Item>>>,
}

impl<F: Family, H: Hasher, Item: Encode + Send + Sync> UnmerkleizedBatch<F, H, Item> {
    /// Add an item to the batch.
    #[allow(clippy::should_implement_trait)]
    pub fn add(mut self, item: Item) -> Self {
        let encoded = item.encode();
        self.inner = self.inner.add(&self.hasher, &encoded);
        self.items.push(item);
        self
    }

    /// Collect ancestor items from the parent chain before downgrading.
    fn collect_ancestor_items(
        parent: &Option<Arc<MerkleizedBatch<F, H::Digest, Item>>>,
    ) -> Vec<Arc<Vec<Item>>> {
        let Some(parent) = parent else {
            return Vec::new();
        };
        let mut items = Vec::new();
        if !parent.items.is_empty() {
            items.push(Arc::clone(&parent.items));
        }
        let mut current = parent.parent.as_ref().and_then(Weak::upgrade);
        while let Some(batch) = current {
            if !batch.items.is_empty() {
                items.push(Arc::clone(&batch.items));
            }
            current = batch.parent.as_ref().and_then(Weak::upgrade);
        }
        items.reverse();
        items
    }

    /// Merkleize the batch, computing the root digest.
    /// `base` provides committed node data as fallback during hash computation.
    pub fn merkleize(
        self,
        base: &merkle::mem::Mem<F, H::Digest>,
    ) -> Arc<MerkleizedBatch<F, H::Digest, Item>> {
        let merkle = self.inner.merkleize(base, &self.hasher);
        let ancestor_items = Self::collect_ancestor_items(&self.parent);
        Arc::new(MerkleizedBatch {
            inner: merkle,
            items: Arc::new(self.items),
            parent: self.parent.as_ref().map(Arc::downgrade),
            ancestor_items,
        })
    }

    /// Like [`merkleize`](Self::merkleize), but the caller supplies the items instead of
    /// accumulating them with [`add`](Self::add). The two approaches must not be mixed: do
    /// not call [`add`](Self::add) before this method.
    ///
    /// The items are encoded and hashed into the Merkle structure, and the `Arc` is stored
    /// directly in the resulting [`MerkleizedBatch`] without copying.
    ///
    /// # Panics
    ///
    /// Panics if items were previously added via [`add`](Self::add).
    pub(crate) fn merkleize_with(
        mut self,
        base: &merkle::mem::Mem<F, H::Digest>,
        items: Arc<Vec<Item>>,
    ) -> Arc<MerkleizedBatch<F, H::Digest, Item>> {
        assert!(
            self.items.is_empty(),
            "merkleize_with expects no items added via add"
        );
        for item in &*items {
            let encoded = item.encode();
            self.inner = self.inner.add(&self.hasher, &encoded);
        }
        let merkle = self.inner.merkleize(base, &self.hasher);
        let ancestor_items = Self::collect_ancestor_items(&self.parent);
        Arc::new(MerkleizedBatch {
            inner: merkle,
            items,
            parent: self.parent.as_ref().map(Arc::downgrade),
            ancestor_items,
        })
    }
}

/// A speculative batch whose root digest has been computed, in contrast to [`UnmerkleizedBatch`].
#[derive(Clone, Debug)]
pub struct MerkleizedBatch<F: Family, D: Digest, Item: Send + Sync> {
    /// The inner batch of Merkle leaf digests.
    pub(crate) inner: Arc<batch::MerkleizedBatch<F, D>>,
    /// The items to append from this batch.
    items: Arc<Vec<Item>>,
    /// This batch's parent, or None if the parent is the journal itself.
    parent: Option<Weak<Self>>,
    /// Ancestor item batches collected at merkleize time (root-to-tip order).
    pub(crate) ancestor_items: Vec<Arc<Vec<Item>>>,
}

impl<F: Family, D: Digest, Item: Send + Sync> MerkleizedBatch<F, D, Item> {
    /// Return the root digest of the authenticated journal after this batch is applied.
    pub fn root(&self) -> D {
        self.inner.root()
    }

    /// The number of items visible through this batch, including ancestors.
    pub(crate) fn size(&self) -> u64 {
        *self.inner.leaves()
    }

    /// The items added in this batch.
    pub(crate) const fn items(&self) -> &Arc<Vec<Item>> {
        &self.items
    }

    /// Create a new speculative batch of operations with this batch as its parent.
    ///
    /// All uncommitted ancestors in the chain must be kept alive until the child (or any
    /// descendant) is merkleized. Dropping an uncommitted ancestor causes data
    /// loss detected at `apply_batch` time.
    pub fn new_batch<H: Hasher<Digest = D>>(self: &Arc<Self>) -> UnmerkleizedBatch<F, H, Item>
    where
        Item: Encode,
    {
        UnmerkleizedBatch {
            inner: self.inner.new_batch(),
            hasher: StandardHasher::new(),
            items: Vec::new(),
            parent: Some(Arc::clone(self)),
        }
    }
}

impl<F: Family, D: Digest, Item: Send + Sync> Readable for MerkleizedBatch<F, D, Item> {
    type Family = F;
    type Digest = D;
    type Error = merkle::Error<F>;

    fn size(&self) -> Position<F> {
        self.inner.size()
    }

    fn get_node(&self, pos: Position<F>) -> Option<D> {
        self.inner.get_node(pos)
    }

    fn root(&self) -> D {
        self.inner.root()
    }

    fn pruning_boundary(&self) -> Location<F> {
        self.inner.pruning_boundary()
    }

    fn proof(
        &self,
        hasher: &impl crate::merkle::hasher::Hasher<F, Digest = D>,
        loc: Location<F>,
    ) -> Result<Proof<F, D>, merkle::Error<F>> {
        self.inner.proof(hasher, loc)
    }

    fn range_proof(
        &self,
        hasher: &impl crate::merkle::hasher::Hasher<F, Digest = D>,
        range: core::ops::Range<Location<F>>,
    ) -> Result<Proof<F, D>, merkle::Error<F>> {
        self.inner.range_proof(hasher, range)
    }
}

/// An append-only data structure that maintains a sequential journal of items alongside a
/// Merkle-family structure. The item at index i in the journal corresponds to the leaf at Location
/// i in the Merkle structure. This structure enables efficient proofs that an item is included in
/// the journal at a specific location.
pub struct Journal<F, E, C, H>
where
    F: Family,
    E: Context,
    C: Contiguous<Item: EncodeShared>,
    H: Hasher,
{
    /// Merkle structure where each leaf is an item digest.
    /// Invariant: leaf i corresponds to item i in the journal.
    pub(crate) merkle: Journaled<F, E, H::Digest>,

    /// Journal of items.
    /// Invariant: item i corresponds to leaf i in the Merkle structure.
    pub(crate) journal: C,

    pub(crate) hasher: StandardHasher<H>,
}

impl<F, E, C, H> Journal<F, E, C, H>
where
    F: Family,
    E: Context,
    C: Contiguous<Item: EncodeShared>,
    H: Hasher,
{
    /// Returns the Location of the next item appended to the journal.
    pub async fn size(&self) -> Location<F> {
        Location::new(self.journal.size().await)
    }

    /// Return the root of the Merkle structure.
    pub fn root(&self) -> H::Digest {
        self.merkle.root()
    }

    /// Create a speculative batch atop this journal.
    pub fn new_batch(&self) -> UnmerkleizedBatch<F, H, C::Item>
    where
        C::Item: Encode,
    {
        let root = self.merkle.to_batch();
        UnmerkleizedBatch {
            inner: root.new_batch(),
            hasher: StandardHasher::new(),
            items: Vec::new(),
            parent: None,
        }
    }

    /// Borrow the committed Mem through the read lock.
    pub(crate) fn with_mem<R>(&self, f: impl FnOnce(&merkle::mem::Mem<F, H::Digest>) -> R) -> R {
        self.merkle.with_mem(f)
    }

    /// Create an owned [`MerkleizedBatch`] representing the current committed state.
    ///
    /// The batch has no items (the committed items are on disk, not in memory).
    /// This is the starting point for building owned batch chains.
    pub(crate) fn to_merkleized_batch(&self) -> Arc<MerkleizedBatch<F, H::Digest, C::Item>> {
        Arc::new(MerkleizedBatch {
            inner: self.merkle.to_batch(),
            items: Arc::new(Vec::new()),
            parent: None,
            ancestor_items: Vec::new(),
        })
    }
}

impl<F, E, C, H> Journal<F, E, C, H>
where
    F: Family,
    E: Context,
    C: Contiguous<Item: EncodeShared> + Persistable<Error = JournalError>,
    H: Hasher,
{
    /// Durably persist the journal. This is faster than `sync()` but does not persist the Merkle
    /// structure, meaning recovery will be required on startup if we crash before `sync()`.
    pub async fn commit(&self) -> Result<(), Error<F>> {
        self.journal.commit().await.map_err(Error::Journal)
    }
}

impl<F, E, C, H> Journal<F, E, C, H>
where
    F: Family,
    E: Context,
    C: Mutable<Item: EncodeShared>,
    H: Hasher,
{
    /// Create a new [Journal] from the given components after aligning the Merkle structure with
    /// the journal.
    pub async fn from_components(
        mut merkle: Journaled<F, E, H::Digest>,
        journal: C,
        hasher: StandardHasher<H>,
        apply_batch_size: u64,
    ) -> Result<Self, Error<F>> {
        Self::align(&mut merkle, &journal, &hasher, apply_batch_size).await?;

        // Sync the Merkle structure to disk to avoid having to repeat any recovery that may have
        // been performed on next startup.
        merkle.sync().await?;

        Ok(Self {
            merkle,
            journal,
            hasher,
        })
    }

    /// Align the Merkle structure to be consistent with the journal. Any items in the structure
    /// that are not in the journal are popped, and any items in the journal that are not in the
    /// structure are added. Items are added in batches of size `apply_batch_size` to avoid memory
    /// bloat.
    async fn align(
        merkle: &mut Journaled<F, E, H::Digest>,
        journal: &C,
        hasher: &StandardHasher<H>,
        apply_batch_size: u64,
    ) -> Result<(), Error<F>> {
        // Rewind Merkle structure elements that are ahead of the journal.
        let journal_size = journal.size().await;
        let mut merkle_leaves = merkle.leaves();
        if merkle_leaves > journal_size {
            let rewind_count = merkle_leaves - journal_size;
            warn!(
                journal_size,
                ?rewind_count,
                "rewinding Merkle structure to match journal"
            );
            merkle.rewind(*rewind_count as usize, hasher).await?;
            merkle_leaves = Location::new(journal_size);
        }

        // If the Merkle structure is behind, replay journal items to catch up.
        if merkle_leaves < journal_size {
            let replay_count = journal_size - *merkle_leaves;
            warn!(
                ?journal_size,
                replay_count, "Merkle structure lags behind journal, replaying journal to catch up"
            );

            let reader = journal.reader().await;
            while merkle_leaves < journal_size {
                let batch = {
                    let mut batch = merkle.new_batch();
                    let mut count = 0u64;
                    while count < apply_batch_size && merkle_leaves < journal_size {
                        let op = reader.read(*merkle_leaves).await?;
                        batch = batch.add(hasher, &op.encode());
                        merkle_leaves += 1;
                        count += 1;
                    }
                    batch
                };
                let batch = merkle.with_mem(|mem| batch.merkleize(mem, hasher));
                merkle.apply_batch(&batch)?;
            }
            return Ok(());
        }

        // At this point the Merkle structure and journal should be consistent.
        assert_eq!(journal.size().await, *merkle.leaves());

        Ok(())
    }

    /// Append an item to the journal and update the Merkle structure.
    pub async fn append(&mut self, item: &C::Item) -> Result<Location<F>, Error<F>> {
        let encoded_item = item.encode();

        // Append item to the journal, then update the Merkle structure state.
        let loc = self.journal.append(item).await?;
        let unmerkleized_batch = self.merkle.new_batch().add(&self.hasher, &encoded_item);
        let batch = self
            .merkle
            .with_mem(|mem| unmerkleized_batch.merkleize(mem, &self.hasher));
        self.merkle.apply_batch(&batch)?;

        Ok(Location::new(loc))
    }

    /// Apply a batch to the journal.
    ///
    /// A batch is valid if the journal has not been modified since the batch
    /// chain was created, or if only ancestors of this batch have been applied.
    /// Already-committed ancestors are skipped automatically.
    /// Applying a batch from a different fork returns an error.
    pub async fn apply_batch(
        &mut self,
        batch: &MerkleizedBatch<F, H::Digest, C::Item>,
    ) -> Result<(), Error<F>> {
        let merkle_size = self.merkle.size();
        let base_size = batch.inner.base_size();

        // Determine whether ancestors have already been committed.
        // `base_size` is the merkle size when the batch chain was forked.
        // If the merkle has advanced past the fork point, ancestors are
        // already on disk; check that the current size is reachable from
        // the batch chain before skipping them.
        let skip_ancestors = if merkle_size == base_size {
            false
        } else if merkle_size > base_size && merkle_size < batch.inner.size() {
            true
        } else {
            // Merkle is at an incompatible position (a sibling or unrelated
            // fork was committed). Eagerly reject to avoid mutating the journal.
            return Err(merkle::Error::StaleBatch {
                expected: base_size,
                actual: merkle_size,
            }
            .into());
        };

        // Apply ancestor items in root-to-tip order. Already-committed
        // batches are skipped by tracking cumulative leaf count.
        // Batches are collected into a single append_many call to acquire the
        // journal's write lock once instead of per-batch.
        let committed_leaves = self.journal.size().await;
        let mut leaf_end = *Location::<F>::try_from(base_size)?;
        let mut batches: Vec<&[C::Item]> = Vec::with_capacity(batch.ancestor_items.len() + 1);
        for ancestor_items in &batch.ancestor_items {
            leaf_end += ancestor_items.len() as u64;
            if skip_ancestors && leaf_end <= committed_leaves {
                continue;
            }
            batches.push(ancestor_items);
        }
        if !batch.items.is_empty() {
            batches.push(&batch.items);
        }
        if !batches.is_empty() {
            self.journal.append_many(Many::Nested(&batches)).await?;
        }

        self.merkle.apply_batch(&batch.inner)?;
        assert_eq!(*self.merkle.leaves(), self.journal.size().await);
        Ok(())
    }

    /// Prune both the Merkle structure and journal to the given location.
    ///
    /// # Returns
    /// The new pruning boundary, which may be less than the requested `prune_loc`.
    pub async fn prune(&mut self, prune_loc: Location<F>) -> Result<Location<F>, Error<F>> {
        if self.merkle.size() == 0 {
            // DB is empty, nothing to prune.
            return Ok(Location::new(self.reader().await.bounds().start));
        }

        // Sync the Merkle structure before pruning the journal, otherwise its last element could
        // end up behind the journal's first element after a crash, and there would be no way to
        // replay the items between the structure's last element and the journal's first element.
        self.merkle.sync().await?;

        // Prune the journal and check if anything was actually pruned
        if !self.journal.prune(*prune_loc).await? {
            return Ok(Location::new(self.reader().await.bounds().start));
        }

        let bounds = self.reader().await.bounds();
        debug!(size = ?bounds.end, ?prune_loc, boundary = ?bounds.start, "pruned inactive ops");

        // Prune Merkle structure to match the journal's actual boundary
        self.merkle.prune(Location::from(bounds.start)).await?;

        Ok(Location::new(bounds.start))
    }
}

impl<F, E, C, H> Journal<F, E, C, H>
where
    F: Family,
    E: Context,
    C: Contiguous<Item: EncodeShared>,
    H: Hasher,
{
    /// Generate a proof of inclusion for items starting at `start_loc`.
    ///
    /// Returns a proof and the items corresponding to the leaves in the range `start_loc..end_loc`,
    /// where `end_loc` is the minimum of the current item count and `start_loc + max_ops`.
    ///
    /// # Errors
    ///
    /// - Returns [Error::Merkle] with [merkle::Error::LocationOverflow] if `start_loc` >
    ///   [Family::MAX_LEAVES].
    /// - Returns [Error::Merkle] with [merkle::Error::RangeOutOfBounds] if `start_loc` >= current
    ///   item count.
    /// - Returns [Error::Journal] with [crate::journal::Error::ItemPruned] if `start_loc` has been
    ///   pruned.
    pub async fn proof(
        &self,
        start_loc: Location<F>,
        max_ops: NonZeroU64,
    ) -> Result<(Proof<F, H::Digest>, Vec<C::Item>), Error<F>> {
        self.historical_proof(self.size().await, start_loc, max_ops)
            .await
    }

    /// Generate a historical proof with respect to the state of the Merkle structure when it had
    /// `historical_leaves` leaves.
    ///
    /// Returns a proof and the items corresponding to the leaves in the range `start_loc..end_loc`,
    /// where `end_loc` is the minimum of `historical_leaves` and `start_loc + max_ops`.
    ///
    /// # Errors
    ///
    /// - Returns [Error::Merkle] with [merkle::Error::RangeOutOfBounds] if `start_loc` >=
    ///   `historical_leaves` or `historical_leaves` > number of items in the journal.
    /// - Returns [Error::Journal] with [crate::journal::Error::ItemPruned] if `start_loc` has been
    ///   pruned.
    pub async fn historical_proof(
        &self,
        historical_leaves: Location<F>,
        start_loc: Location<F>,
        max_ops: NonZeroU64,
    ) -> Result<(Proof<F, H::Digest>, Vec<C::Item>), Error<F>> {
        // Acquire a reader guard to prevent pruning from advancing while we read.
        let reader = self.journal.reader().await;
        let bounds = reader.bounds();

        if *historical_leaves > bounds.end {
            return Err(merkle::Error::RangeOutOfBounds(Location::new(bounds.end)).into());
        }
        if start_loc >= historical_leaves {
            return Err(merkle::Error::RangeOutOfBounds(start_loc).into());
        }

        let end_loc = std::cmp::min(historical_leaves, start_loc.saturating_add(max_ops.get()));

        let hasher = self.hasher.clone();
        let proof = self
            .merkle
            .historical_range_proof(&hasher, historical_leaves, start_loc..end_loc)
            .await?;

        let mut ops = Vec::with_capacity((*end_loc - *start_loc) as usize);
        let futures = (*start_loc..*end_loc)
            .map(|i| reader.read(i))
            .collect::<Vec<_>>();
        try_join_all(futures)
            .await?
            .into_iter()
            .for_each(|op| ops.push(op));

        Ok((proof, ops))
    }
}

impl<F, E, C, H> Journal<F, E, C, H>
where
    F: Family,
    E: Context,
    C: Contiguous<Item: EncodeShared> + Persistable<Error = JournalError>,
    H: Hasher,
{
    /// Destroy the authenticated journal, removing all data from disk.
    pub async fn destroy(self) -> Result<(), Error<F>> {
        try_join!(
            self.journal.destroy().map_err(Error::Journal),
            self.merkle.destroy().map_err(Error::Merkle),
        )?;

        Ok(())
    }

    /// Durably persist the journal, ensuring no recovery is required on startup.
    pub async fn sync(&self) -> Result<(), Error<F>> {
        try_join!(
            self.journal.sync().map_err(Error::Journal),
            self.merkle.sync().map_err(Error::Merkle)
        )?;

        Ok(())
    }
}

/// The number of items to apply to the Merkle structure in a single batch.
const APPLY_BATCH_SIZE: u64 = 1 << 16;

/// Generate a `new()` constructor for an authenticated journal backed by a specific contiguous
/// journal type.
macro_rules! impl_journal_new {
    ($journal_mod:ident, $cfg_ty:ty, $codec_bound:path) => {
        impl<F, E, O, H> Journal<F, E, $journal_mod::Journal<E, O>, H>
        where
            F: Family,
            E: Context,
            O: $codec_bound,
            H: Hasher,
        {
            /// Create a new authenticated [Journal].
            ///
            /// The inner journal will be rewound to the last item matching `rewind_predicate`,
            /// and the merkle structure will be aligned to match.
            pub async fn new(
                context: E,
                merkle_cfg: merkle::journaled::Config,
                journal_cfg: $cfg_ty,
                rewind_predicate: fn(&O) -> bool,
            ) -> Result<Self, Error<F>> {
                let mut journal =
                    $journal_mod::Journal::init(context.with_label("journal"), journal_cfg).await?;
                journal.rewind_to(rewind_predicate).await?;

                let hasher = StandardHasher::<H>::new();
                let mut merkle =
                    Journaled::init(context.with_label("merkle"), &hasher, merkle_cfg).await?;
                Self::align(&mut merkle, &journal, &hasher, APPLY_BATCH_SIZE).await?;

                journal.sync().await?;
                merkle.sync().await?;

                Ok(Self {
                    merkle,
                    journal,
                    hasher,
                })
            }
        }
    };
}

impl_journal_new!(fixed, fixed::Config, CodecFixedShared);
impl_journal_new!(variable, variable::Config<O::Cfg>, CodecShared);

impl<F, E, C, H> Contiguous for Journal<F, E, C, H>
where
    F: Family,
    E: Context,
    C: Contiguous<Item: EncodeShared>,
    H: Hasher,
{
    type Item = C::Item;

    async fn reader(&self) -> impl Reader<Item = C::Item> + '_ {
        self.journal.reader().await
    }

    async fn size(&self) -> u64 {
        self.journal.size().await
    }
}

impl<F, E, C, H> Mutable for Journal<F, E, C, H>
where
    F: Family,
    E: Context,
    C: Mutable<Item: EncodeShared>,
    H: Hasher,
{
    async fn append(&mut self, item: &Self::Item) -> Result<u64, JournalError> {
        let res = self.append(item).await.map_err(|e| match e {
            Error::Journal(inner) => inner,
            Error::Merkle(inner) => JournalError::Merkle(anyhow::Error::from(inner)),
        })?;

        Ok(*res)
    }

    async fn prune(&mut self, min_position: u64) -> Result<bool, JournalError> {
        self.journal.prune(min_position).await
    }

    async fn rewind(&mut self, size: u64) -> Result<(), JournalError> {
        self.journal.rewind(size).await?;

        let leaves = *self.merkle.leaves();
        if leaves > size {
            self.merkle
                .rewind((leaves - size) as usize, &self.hasher)
                .await
                .map_err(|error| JournalError::Merkle(anyhow::Error::from(error)))?;
        }

        Ok(())
    }
}

/// A [Mutable] journal that can serve as the inner journal of an authenticated [Journal].
pub trait Inner<E: Context>: Mutable + Persistable<Error = JournalError> {
    /// The configuration needed to initialize this journal.
    type Config: Clone + Send;

    /// Initialize an authenticated [Journal] backed by this journal type.
    fn init<F: Family, H: Hasher>(
        context: E,
        merkle_cfg: merkle::journaled::Config,
        journal_cfg: Self::Config,
        rewind_predicate: fn(&Self::Item) -> bool,
    ) -> impl core::future::Future<Output = Result<Journal<F, E, Self, H>, Error<F>>> + Send
    where
        Self: Sized,
        Self::Item: EncodeShared;
}

impl<F, E, C, H> Persistable for Journal<F, E, C, H>
where
    F: Family,
    E: Context,
    C: Contiguous<Item: EncodeShared> + Persistable<Error = JournalError>,
    H: Hasher,
{
    type Error = JournalError;

    async fn commit(&self) -> Result<(), JournalError> {
        self.commit().await.map_err(|e| match e {
            Error::Journal(inner) => inner,
            Error::Merkle(inner) => JournalError::Merkle(anyhow::Error::from(inner)),
        })
    }

    async fn sync(&self) -> Result<(), JournalError> {
        self.sync().await.map_err(|e| match e {
            Error::Journal(inner) => inner,
            Error::Merkle(inner) => JournalError::Merkle(anyhow::Error::from(inner)),
        })
    }

    async fn destroy(self) -> Result<(), JournalError> {
        self.destroy().await.map_err(|e| match e {
            Error::Journal(inner) => inner,
            Error::Merkle(inner) => JournalError::Merkle(anyhow::Error::from(inner)),
        })
    }
}

#[cfg(test)]
impl<F, E, C, H> Journal<F, E, C, H>
where
    F: Family,
    E: Context,
    C: Contiguous<Item: EncodeShared>,
    H: Hasher,
{
    /// Test helper: Read the item at the given location.
    pub(crate) async fn read(&self, loc: Location<F>) -> Result<C::Item, Error<F>> {
        self.journal
            .reader()
            .await
            .read(*loc)
            .await
            .map_err(Error::Journal)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        journal::contiguous::fixed::{Config as JConfig, Journal as ContiguousJournal},
        merkle::{
            journaled::{Config as MerkleConfig, Journaled},
            mmb, mmr,
        },
        qmdb::{
            any::{
                operation::{update::Unordered as Update, Unordered as Op},
                value::FixedEncoding,
            },
            operation::Committable,
        },
    };
    use commonware_codec::Encode;
    use commonware_cryptography::{sha256::Digest, Sha256};
    use commonware_macros::test_traced;
    use commonware_runtime::{
        buffer::paged::CacheRef,
        deterministic::{self, Context},
        BufferPooler, Metrics, Runner as _,
    };
    use commonware_utils::{NZUsize, NZU16, NZU64};
    use futures::StreamExt as _;
    use std::num::{NonZeroU16, NonZeroUsize};

    const PAGE_SIZE: NonZeroU16 = NZU16!(101);
    const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(11);

    /// Generic operation type for testing, parameterized by Merkle family.
    type TestOp<F> = Op<F, Digest, FixedEncoding<Digest>>;

    /// Generic authenticated journal type for testing, parameterized by Merkle family.
    type TestJournal<F> = Journal<
        F,
        deterministic::Context,
        ContiguousJournal<deterministic::Context, TestOp<F>>,
        Sha256,
    >;

    /// Create Merkle configuration for tests.
    fn merkle_config(suffix: &str, pooler: &impl BufferPooler) -> MerkleConfig {
        MerkleConfig {
            journal_partition: format!("mmr-journal-{suffix}"),
            metadata_partition: format!("mmr-metadata-{suffix}"),
            items_per_blob: NZU64!(11),
            write_buffer: NZUsize!(1024),
            thread_pool: None,
            page_cache: CacheRef::from_pooler(pooler, PAGE_SIZE, PAGE_CACHE_SIZE),
        }
    }

    /// Create journal configuration for tests.
    fn journal_config(suffix: &str, pooler: &impl BufferPooler) -> JConfig {
        JConfig {
            partition: format!("journal-{suffix}"),
            items_per_blob: NZU64!(7),
            write_buffer: NZUsize!(1024),
            page_cache: CacheRef::from_pooler(pooler, PAGE_SIZE, PAGE_CACHE_SIZE),
        }
    }

    /// Create a new empty authenticated journal.
    async fn create_empty_journal<F: Family + PartialEq>(
        context: Context,
        suffix: &str,
    ) -> TestJournal<F> {
        let merkle_cfg = merkle_config(suffix, &context);
        let journal_cfg = journal_config(suffix, &context);
        TestJournal::<F>::new(context, merkle_cfg, journal_cfg, |op: &TestOp<F>| {
            op.is_commit()
        })
        .await
        .unwrap()
    }

    /// Create a test operation with predictable values based on index.
    fn create_operation<F: Family + PartialEq>(index: u8) -> TestOp<F> {
        TestOp::<F>::Update(Update(
            Sha256::fill(index),
            Sha256::fill(index.wrapping_add(1)),
        ))
    }

    /// Create an authenticated journal with N committed operations.
    ///
    /// Operations are added and then synced to ensure they are committed.
    async fn create_journal_with_ops<F: Family + PartialEq>(
        context: Context,
        suffix: &str,
        count: usize,
    ) -> TestJournal<F> {
        let mut journal = create_empty_journal::<F>(context, suffix).await;

        for i in 0..count {
            let op = create_operation::<F>(i as u8);
            let loc = journal.append(&op).await.unwrap();
            assert_eq!(loc, Location::<F>::new(i as u64));
        }

        journal.sync().await.unwrap();
        journal
    }

    /// Create separate Merkle and journal components for testing alignment.
    ///
    /// These components are created independently and can be manipulated separately to test
    /// scenarios where the Merkle structure and journal are out of sync (e.g., one ahead of the
    /// other).
    async fn create_components<F: Family + PartialEq>(
        context: Context,
        suffix: &str,
    ) -> (
        Journaled<F, deterministic::Context, Digest>,
        ContiguousJournal<deterministic::Context, TestOp<F>>,
        StandardHasher<Sha256>,
    ) {
        let hasher = StandardHasher::new();
        let merkle = Journaled::<F, _, Digest>::init(
            context.with_label("mmr"),
            &hasher,
            merkle_config(suffix, &context),
        )
        .await
        .unwrap();
        let journal = ContiguousJournal::init(
            context.with_label("journal"),
            journal_config(suffix, &context),
        )
        .await
        .unwrap();
        (merkle, journal, hasher)
    }

    /// Verify that a proof correctly proves the given operations are included in the Merkle
    /// structure.
    fn verify_proof<F: Family + PartialEq>(
        proof: &Proof<F, <Sha256 as commonware_cryptography::Hasher>::Digest>,
        operations: &[TestOp<F>],
        start_loc: Location<F>,
        root: &<Sha256 as commonware_cryptography::Hasher>::Digest,
        hasher: &StandardHasher<Sha256>,
    ) -> bool {
        let encoded_ops: Vec<_> = operations.iter().map(|op| op.encode()).collect();
        proof.verify_range_inclusion(hasher, &encoded_ops, start_loc, root)
    }

    /// Verify that new() creates an empty authenticated journal.
    async fn test_new_creates_empty_journal_inner<F: Family + PartialEq>(context: Context) {
        let journal = create_empty_journal::<F>(context, "new-empty").await;

        let bounds = journal.reader().await.bounds();
        assert_eq!(bounds.end, 0);
        assert_eq!(bounds.start, 0);
        assert!(bounds.is_empty());
    }

    #[test_traced("INFO")]
    fn test_new_creates_empty_journal_mmr() {
        let executor = deterministic::Runner::default();
        executor.start(test_new_creates_empty_journal_inner::<mmr::Family>);
    }

    #[test_traced("INFO")]
    fn test_new_creates_empty_journal_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(test_new_creates_empty_journal_inner::<mmb::Family>);
    }

    /// Verify that align() correctly handles empty Merkle and journal components.
    async fn test_align_with_empty_mmr_and_journal_inner<F: Family + PartialEq>(context: Context) {
        let (mut merkle, journal, hasher) = create_components::<F>(context, "align-empty").await;

        TestJournal::<F>::align(&mut merkle, &journal, &hasher, APPLY_BATCH_SIZE)
            .await
            .unwrap();

        assert_eq!(merkle.leaves(), Location::<F>::new(0));
        assert_eq!(journal.size().await, 0);
    }

    #[test_traced("INFO")]
    fn test_align_with_empty_mmr_and_journal_mmr() {
        let executor = deterministic::Runner::default();
        executor.start(test_align_with_empty_mmr_and_journal_inner::<mmr::Family>);
    }

    #[test_traced("INFO")]
    fn test_align_with_empty_mmr_and_journal_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(test_align_with_empty_mmr_and_journal_inner::<mmb::Family>);
    }

    /// Verify that align() pops Merkle elements when Merkle is ahead of the journal.
    async fn test_align_when_mmr_ahead_inner<F: Family + PartialEq>(context: Context) {
        let (mut merkle, journal, hasher) = create_components::<F>(context, "mmr-ahead").await;

        // Add 20 operations to both Merkle and journal
        {
            let batch = {
                let mut batch = merkle.new_batch();
                for i in 0..20 {
                    let op = create_operation::<F>(i as u8);
                    let encoded = op.encode();
                    batch = batch.add(&hasher, &encoded);
                    journal.append(&op).await.unwrap();
                }
                batch
            };
            let batch = merkle.with_mem(|mem| batch.merkleize(mem, &hasher));
            merkle.apply_batch(&batch).unwrap();
        }

        // Add commit operation to journal only (making journal ahead)
        let commit_op = TestOp::<F>::CommitFloor(None, Location::<F>::new(0));
        journal.append(&commit_op).await.unwrap();
        journal.sync().await.unwrap();

        // Merkle has 20 leaves, journal has 21 operations (20 ops + 1 commit)
        TestJournal::<F>::align(&mut merkle, &journal, &hasher, APPLY_BATCH_SIZE)
            .await
            .unwrap();

        // Merkle should have been aligned to match journal
        assert_eq!(merkle.leaves(), Location::<F>::new(21));
        assert_eq!(journal.size().await, 21);
    }

    #[test_traced("WARN")]
    fn test_align_when_mmr_ahead_mmr() {
        let executor = deterministic::Runner::default();
        executor.start(test_align_when_mmr_ahead_inner::<mmr::Family>);
    }

    #[test_traced("WARN")]
    fn test_align_when_mmr_ahead_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(test_align_when_mmr_ahead_inner::<mmb::Family>);
    }

    /// Verify that align() replays journal operations when journal is ahead of Merkle.
    async fn test_align_when_journal_ahead_inner<F: Family + PartialEq>(context: Context) {
        let (mut merkle, journal, hasher) = create_components::<F>(context, "journal-ahead").await;

        // Add 20 operations to journal only
        for i in 0..20 {
            let op = create_operation::<F>(i as u8);
            journal.append(&op).await.unwrap();
        }

        // Add commit
        let commit_op = TestOp::<F>::CommitFloor(None, Location::<F>::new(0));
        journal.append(&commit_op).await.unwrap();
        journal.sync().await.unwrap();

        // Journal has 21 operations, Merkle has 0 leaves
        TestJournal::<F>::align(&mut merkle, &journal, &hasher, APPLY_BATCH_SIZE)
            .await
            .unwrap();

        // Merkle should have been replayed to match journal
        assert_eq!(merkle.leaves(), Location::<F>::new(21));
        assert_eq!(journal.size().await, 21);
    }

    #[test_traced("WARN")]
    fn test_align_when_journal_ahead_mmr() {
        let executor = deterministic::Runner::default();
        executor.start(test_align_when_journal_ahead_inner::<mmr::Family>);
    }

    #[test_traced("WARN")]
    fn test_align_when_journal_ahead_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(test_align_when_journal_ahead_inner::<mmb::Family>);
    }

    /// Verify that align() discards uncommitted operations.
    async fn test_align_with_mismatched_committed_ops_inner<F: Family + PartialEq>(
        context: Context,
    ) {
        let mut journal =
            create_empty_journal::<F>(context.with_label("first"), "mismatched").await;

        // Add 20 uncommitted operations
        for i in 0..20 {
            let loc = journal
                .append(&create_operation::<F>(i as u8))
                .await
                .unwrap();
            assert_eq!(loc, Location::<F>::new(i as u64));
        }

        // Don't sync - these are uncommitted
        // After alignment, they should be discarded
        let size_before = journal.size().await;
        assert_eq!(size_before, 20);

        // Drop and recreate to simulate restart (which calls align internally)
        journal.sync().await.unwrap();
        drop(journal);
        let journal = create_empty_journal::<F>(context.with_label("second"), "mismatched").await;

        // Uncommitted operations should be gone
        assert_eq!(journal.size().await, 0);
    }

    #[test_traced("INFO")]
    fn test_align_with_mismatched_committed_ops_mmr() {
        let executor = deterministic::Runner::default();
        executor.start(|context| {
            test_align_with_mismatched_committed_ops_inner::<mmr::Family>(context)
        });
    }

    #[test_traced("INFO")]
    fn test_align_with_mismatched_committed_ops_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(|context| {
            test_align_with_mismatched_committed_ops_inner::<mmb::Family>(context)
        });
    }

    async fn test_rewind_inner<F: Family + PartialEq>(context: Context) {
        // Test 1: Matching operation is kept
        {
            let mut journal = ContiguousJournal::init(
                context.with_label("rewind_match"),
                journal_config("rewind-match", &context),
            )
            .await
            .unwrap();

            // Add operations where operation 3 is a commit
            for i in 0..3 {
                journal.append(&create_operation::<F>(i)).await.unwrap();
            }
            journal
                .append(&TestOp::<F>::CommitFloor(None, Location::<F>::new(0)))
                .await
                .unwrap();
            for i in 4..7 {
                journal.append(&create_operation::<F>(i)).await.unwrap();
            }

            // Rewind to last commit
            let final_size = journal.rewind_to(|op| op.is_commit()).await.unwrap();
            assert_eq!(final_size, 4);
            assert_eq!(journal.size().await, 4);

            // Verify the commit operation is still there
            let op = journal.read(3).await.unwrap();
            assert!(op.is_commit());
        }

        // Test 2: Last matching operation is chosen when multiple match
        {
            let mut journal = ContiguousJournal::init(
                context.with_label("rewind_multiple"),
                journal_config("rewind-multiple", &context),
            )
            .await
            .unwrap();

            // Add multiple commits
            journal.append(&create_operation::<F>(0)).await.unwrap();
            journal
                .append(&TestOp::<F>::CommitFloor(None, Location::<F>::new(0)))
                .await
                .unwrap(); // pos 1
            journal.append(&create_operation::<F>(2)).await.unwrap();
            journal
                .append(&TestOp::<F>::CommitFloor(None, Location::<F>::new(1)))
                .await
                .unwrap(); // pos 3
            journal.append(&create_operation::<F>(4)).await.unwrap();

            // Should rewind to last commit (pos 3)
            let final_size = journal.rewind_to(|op| op.is_commit()).await.unwrap();
            assert_eq!(final_size, 4);

            // Verify the last commit is still there
            let op = journal.read(3).await.unwrap();
            assert!(op.is_commit());

            // Verify we can't read pos 4
            assert!(journal.read(4).await.is_err());
        }

        // Test 3: Rewind to pruning boundary when no match
        {
            let mut journal = ContiguousJournal::init(
                context.with_label("rewind_no_match"),
                journal_config("rewind-no-match", &context),
            )
            .await
            .unwrap();

            // Add operations with no commits
            for i in 0..10 {
                journal.append(&create_operation::<F>(i)).await.unwrap();
            }

            // Rewind should go to pruning boundary (0 for unpruned)
            let final_size = journal.rewind_to(|op| op.is_commit()).await.unwrap();
            assert_eq!(final_size, 0, "Should rewind to pruning boundary (0)");
            assert_eq!(journal.size().await, 0);
        }

        // Test 4: Rewind with existing pruning boundary
        {
            let mut journal = ContiguousJournal::init(
                context.with_label("rewind_with_pruning"),
                journal_config("rewind-with-pruning", &context),
            )
            .await
            .unwrap();

            // Add operations and a commit at position 10 (past first section boundary of 7)
            for i in 0..10 {
                journal.append(&create_operation::<F>(i)).await.unwrap();
            }
            journal
                .append(&TestOp::<F>::CommitFloor(None, Location::<F>::new(0)))
                .await
                .unwrap(); // pos 10
            for i in 11..15 {
                journal.append(&create_operation::<F>(i)).await.unwrap();
            }
            journal.sync().await.unwrap();

            // Prune up to position 8 (this will prune section 0, items 0-6, keeping 7+)
            journal.prune(8).await.unwrap();
            assert_eq!(journal.reader().await.bounds().start, 7);

            // Add more uncommitted operations
            for i in 15..20 {
                journal.append(&create_operation::<F>(i)).await.unwrap();
            }

            // Rewind should keep the commit at position 10
            let final_size = journal.rewind_to(|op| op.is_commit()).await.unwrap();
            assert_eq!(final_size, 11);

            // Verify commit is still there
            let op = journal.read(10).await.unwrap();
            assert!(op.is_commit());
        }

        // Test 5: Rewind with no matches after pruning boundary
        {
            let mut journal = ContiguousJournal::init(
                context.with_label("rewind_no_match_pruned"),
                journal_config("rewind-no-match-pruned", &context),
            )
            .await
            .unwrap();

            // Add operations with a commit at position 5 (in section 0: 0-6)
            for i in 0..5 {
                journal.append(&create_operation::<F>(i)).await.unwrap();
            }
            journal
                .append(&TestOp::<F>::CommitFloor(None, Location::<F>::new(0)))
                .await
                .unwrap(); // pos 5
            for i in 6..10 {
                journal.append(&create_operation::<F>(i)).await.unwrap();
            }
            journal.sync().await.unwrap();

            // Prune up to position 8 (this prunes section 0, including the commit at pos 5)
            // Pruning boundary will be at position 7 (start of section 1)
            journal.prune(8).await.unwrap();
            assert_eq!(journal.reader().await.bounds().start, 7);

            // Add uncommitted operations with no commits (in section 1: 7-13)
            for i in 10..14 {
                journal.append(&create_operation::<F>(i)).await.unwrap();
            }

            // Rewind with no matching commits after the pruning boundary
            // Should rewind to the pruning boundary at position 7
            let final_size = journal.rewind_to(|op| op.is_commit()).await.unwrap();
            assert_eq!(final_size, 7);
        }

        // Test 6: Empty journal
        {
            let mut journal = ContiguousJournal::init(
                context.with_label("rewind_empty"),
                journal_config("rewind-empty", &context),
            )
            .await
            .unwrap();

            // Rewind empty journal should be no-op
            let final_size = journal
                .rewind_to(|op: &TestOp<F>| op.is_commit())
                .await
                .unwrap();
            assert_eq!(final_size, 0);
            assert_eq!(journal.size().await, 0);
        }

        // Test 7: Position based authenticated journal rewind.
        {
            let merkle_cfg = merkle_config("rewind", &context);
            let journal_cfg = journal_config("rewind", &context);
            let mut journal =
                TestJournal::<F>::new(context, merkle_cfg, journal_cfg, |op| op.is_commit())
                    .await
                    .unwrap();

            // Add operations with a commit at position 5 (in section 0: 0-6)
            for i in 0..5 {
                journal.append(&create_operation::<F>(i)).await.unwrap();
            }
            journal
                .append(&TestOp::<F>::CommitFloor(None, Location::<F>::new(0)))
                .await
                .unwrap(); // pos 5
            for i in 6..10 {
                journal.append(&create_operation::<F>(i)).await.unwrap();
            }
            assert_eq!(journal.size().await, 10);

            journal.rewind(2).await.unwrap();
            assert_eq!(journal.size().await, 2);
            assert_eq!(journal.merkle.leaves(), 2);
            assert_eq!(journal.merkle.size(), 3);
            let bounds = journal.reader().await.bounds();
            assert_eq!(bounds.start, 0);
            assert!(!bounds.is_empty());

            assert!(matches!(
                journal.rewind(3).await,
                Err(JournalError::InvalidRewind(_))
            ));

            journal.rewind(0).await.unwrap();
            assert_eq!(journal.size().await, 0);
            assert_eq!(journal.merkle.leaves(), 0);
            assert_eq!(journal.merkle.size(), 0);
            let bounds = journal.reader().await.bounds();
            assert_eq!(bounds.start, 0);
            assert!(bounds.is_empty());

            // Test rewinding after pruning.
            for i in 0..255 {
                journal.append(&create_operation::<F>(i)).await.unwrap();
            }
            journal.prune(Location::<F>::new(100)).await.unwrap();
            assert_eq!(journal.reader().await.bounds().start, 98);
            let res = journal.rewind(97).await;
            assert!(matches!(res, Err(JournalError::InvalidRewind(97))));
            journal.rewind(98).await.unwrap();
            let bounds = journal.reader().await.bounds();
            assert_eq!(bounds.end, 98);
            assert_eq!(journal.merkle.leaves(), 98);
            assert_eq!(bounds.start, 98);
            assert!(bounds.is_empty());
        }
    }

    #[test_traced("INFO")]
    fn test_rewind_mmr() {
        let executor = deterministic::Runner::default();
        executor.start(test_rewind_inner::<mmr::Family>);
    }

    #[test_traced("INFO")]
    fn test_rewind_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(test_rewind_inner::<mmb::Family>);
    }

    /// Verify that append() increments the operation count, returns correct locations, and
    /// operations can be read back correctly.
    async fn test_apply_op_and_read_operations_inner<F: Family + PartialEq>(context: Context) {
        let mut journal = create_empty_journal::<F>(context, "apply_op").await;

        assert_eq!(journal.size().await, 0);

        // Add 50 operations
        let expected_ops: Vec<_> = (0..50).map(|i| create_operation::<F>(i as u8)).collect();
        for (i, op) in expected_ops.iter().enumerate() {
            let loc = journal.append(op).await.unwrap();
            assert_eq!(loc, Location::<F>::new(i as u64));
            assert_eq!(journal.size().await, (i + 1) as u64);
        }

        assert_eq!(journal.size().await, 50);

        // Verify all operations can be read back correctly
        journal.sync().await.unwrap();
        for (i, expected_op) in expected_ops.iter().enumerate() {
            let read_op = journal.read(Location::<F>::new(i as u64)).await.unwrap();
            assert_eq!(read_op, *expected_op);
        }
    }

    #[test_traced("INFO")]
    fn test_apply_op_and_read_operations_mmr() {
        let executor = deterministic::Runner::default();
        executor.start(test_apply_op_and_read_operations_inner::<mmr::Family>);
    }

    #[test_traced("INFO")]
    fn test_apply_op_and_read_operations_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(test_apply_op_and_read_operations_inner::<mmb::Family>);
    }

    /// Verify that read() returns correct operations at various positions.
    async fn test_read_operations_at_various_positions_inner<F: Family + PartialEq>(
        context: Context,
    ) {
        let journal = create_journal_with_ops::<F>(context, "read", 50).await;

        // Verify reading first operation
        let first_op = journal.read(Location::<F>::new(0)).await.unwrap();
        assert_eq!(first_op, create_operation::<F>(0));

        // Verify reading middle operation
        let middle_op = journal.read(Location::<F>::new(25)).await.unwrap();
        assert_eq!(middle_op, create_operation::<F>(25));

        // Verify reading last operation
        let last_op = journal.read(Location::<F>::new(49)).await.unwrap();
        assert_eq!(last_op, create_operation::<F>(49));

        // Verify all operations match expected values
        for i in 0..50 {
            let op = journal.read(Location::<F>::new(i)).await.unwrap();
            assert_eq!(op, create_operation::<F>(i as u8));
        }
    }

    #[test_traced("INFO")]
    fn test_read_operations_at_various_positions_mmr() {
        let executor = deterministic::Runner::default();
        executor.start(|context| {
            test_read_operations_at_various_positions_inner::<mmr::Family>(context)
        });
    }

    #[test_traced("INFO")]
    fn test_read_operations_at_various_positions_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(|context| {
            test_read_operations_at_various_positions_inner::<mmb::Family>(context)
        });
    }

    /// Verify that read() returns an error for pruned operations.
    async fn test_read_pruned_operation_returns_error_inner<F: Family + PartialEq>(
        context: Context,
    ) {
        let mut journal = create_journal_with_ops::<F>(context, "read_pruned", 100).await;

        // Add commit and prune
        journal
            .append(&TestOp::<F>::CommitFloor(None, Location::<F>::new(50)))
            .await
            .unwrap();
        journal.sync().await.unwrap();
        let pruned_boundary = journal.prune(Location::<F>::new(50)).await.unwrap();

        // Try to read an operation before the pruned boundary
        let read_loc = Location::<F>::new(0);
        if read_loc < pruned_boundary {
            let result = journal.read(read_loc).await;
            assert!(matches!(
                result,
                Err(Error::Journal(crate::journal::Error::ItemPruned(_)))
            ));
        }
    }

    #[test_traced("INFO")]
    fn test_read_pruned_operation_returns_error_mmr() {
        let executor = deterministic::Runner::default();
        executor.start(|context| {
            test_read_pruned_operation_returns_error_inner::<mmr::Family>(context)
        });
    }

    #[test_traced("INFO")]
    fn test_read_pruned_operation_returns_error_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(|context| {
            test_read_pruned_operation_returns_error_inner::<mmb::Family>(context)
        });
    }

    /// Verify that read() returns an error for out-of-range locations.
    async fn test_read_out_of_range_returns_error_inner<F: Family + PartialEq>(context: Context) {
        let journal = create_journal_with_ops::<F>(context, "read_oob", 3).await;

        // Try to read beyond the end
        let result = journal.read(Location::<F>::new(10)).await;
        assert!(matches!(
            result,
            Err(Error::Journal(crate::journal::Error::ItemOutOfRange(_)))
        ));
    }

    #[test_traced("INFO")]
    fn test_read_out_of_range_returns_error_mmr() {
        let executor = deterministic::Runner::default();
        executor.start(test_read_out_of_range_returns_error_inner::<mmr::Family>);
    }

    #[test_traced("INFO")]
    fn test_read_out_of_range_returns_error_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(test_read_out_of_range_returns_error_inner::<mmb::Family>);
    }

    /// Verify that we can read all operations back correctly.
    async fn test_read_all_operations_back_correctly_inner<F: Family + PartialEq>(
        context: Context,
    ) {
        let journal = create_journal_with_ops::<F>(context, "read_all", 50).await;

        assert_eq!(journal.size().await, 50);

        // Verify all operations can be read back and match expected values
        for i in 0..50 {
            let op = journal.read(Location::<F>::new(i)).await.unwrap();
            assert_eq!(op, create_operation::<F>(i as u8));
        }
    }

    #[test_traced("INFO")]
    fn test_read_all_operations_back_correctly_mmr() {
        let executor = deterministic::Runner::default();
        executor.start(test_read_all_operations_back_correctly_inner::<mmr::Family>);
    }

    #[test_traced("INFO")]
    fn test_read_all_operations_back_correctly_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(test_read_all_operations_back_correctly_inner::<mmb::Family>);
    }

    /// Verify that sync() persists operations.
    async fn test_sync_inner<F: Family + PartialEq>(context: Context) {
        let mut journal =
            create_empty_journal::<F>(context.with_label("first"), "close_pending").await;

        // Add 20 operations
        let expected_ops: Vec<_> = (0..20).map(|i| create_operation::<F>(i as u8)).collect();
        for (i, op) in expected_ops.iter().enumerate() {
            let loc = journal.append(op).await.unwrap();
            assert_eq!(loc, Location::<F>::new(i as u64),);
        }

        // Add commit operation to commit the operations
        let commit_loc = journal
            .append(&TestOp::<F>::CommitFloor(None, Location::<F>::new(0)))
            .await
            .unwrap();
        assert_eq!(
            commit_loc,
            Location::<F>::new(20),
            "commit should be at location 20"
        );
        journal.sync().await.unwrap();

        // Reopen and verify the operations persisted
        drop(journal);
        let journal =
            create_empty_journal::<F>(context.with_label("second"), "close_pending").await;
        assert_eq!(journal.size().await, 21);

        // Verify all operations can be read back
        for (i, expected_op) in expected_ops.iter().enumerate() {
            let read_op = journal.read(Location::<F>::new(i as u64)).await.unwrap();
            assert_eq!(read_op, *expected_op);
        }
    }

    #[test_traced("INFO")]
    fn test_sync_mmr() {
        let executor = deterministic::Runner::default();
        executor.start(test_sync_inner::<mmr::Family>);
    }

    #[test_traced("INFO")]
    fn test_sync_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(test_sync_inner::<mmb::Family>);
    }

    /// Verify that pruning an empty journal returns the boundary.
    async fn test_prune_empty_journal_inner<F: Family + PartialEq>(context: Context) {
        let mut journal = create_empty_journal::<F>(context, "prune_empty").await;

        let boundary = journal.prune(Location::<F>::new(0)).await.unwrap();

        assert_eq!(boundary, Location::<F>::new(0));
    }

    #[test_traced("INFO")]
    fn test_prune_empty_journal_mmr() {
        let executor = deterministic::Runner::default();
        executor.start(test_prune_empty_journal_inner::<mmr::Family>);
    }

    #[test_traced("INFO")]
    fn test_prune_empty_journal_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(test_prune_empty_journal_inner::<mmb::Family>);
    }

    /// Verify that pruning to a specific location works correctly.
    async fn test_prune_to_location_inner<F: Family + PartialEq>(context: Context) {
        let mut journal = create_journal_with_ops::<F>(context, "prune_to", 100).await;

        // Add commit at position 50
        journal
            .append(&TestOp::<F>::CommitFloor(None, Location::<F>::new(50)))
            .await
            .unwrap();
        journal.sync().await.unwrap();

        let boundary = journal.prune(Location::<F>::new(50)).await.unwrap();

        // Boundary should be <= requested location (may align to section boundary)
        assert!(boundary <= Location::<F>::new(50));
    }

    #[test_traced("INFO")]
    fn test_prune_to_location_mmr() {
        let executor = deterministic::Runner::default();
        executor.start(test_prune_to_location_inner::<mmr::Family>);
    }

    #[test_traced("INFO")]
    fn test_prune_to_location_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(test_prune_to_location_inner::<mmb::Family>);
    }

    /// Verify that prune() returns the actual boundary (which may differ from requested).
    async fn test_prune_returns_actual_boundary_inner<F: Family + PartialEq>(context: Context) {
        let mut journal = create_journal_with_ops::<F>(context, "prune_boundary", 100).await;

        journal
            .append(&TestOp::<F>::CommitFloor(None, Location::<F>::new(50)))
            .await
            .unwrap();
        journal.sync().await.unwrap();

        let requested = Location::<F>::new(50);
        let actual = journal.prune(requested).await.unwrap();

        // Actual boundary should match bounds.start
        let bounds = journal.reader().await.bounds();
        assert!(!bounds.is_empty());
        assert_eq!(actual, bounds.start);

        // Actual may be <= requested due to section alignment
        assert!(actual <= requested);
    }

    #[test_traced("INFO")]
    fn test_prune_returns_actual_boundary_mmr() {
        let executor = deterministic::Runner::default();
        executor.start(test_prune_returns_actual_boundary_inner::<mmr::Family>);
    }

    #[test_traced("INFO")]
    fn test_prune_returns_actual_boundary_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(test_prune_returns_actual_boundary_inner::<mmb::Family>);
    }

    /// Verify that pruning doesn't change the operation count.
    async fn test_prune_preserves_operation_count_inner<F: Family + PartialEq>(context: Context) {
        let mut journal = create_journal_with_ops::<F>(context, "prune_count", 100).await;

        journal
            .append(&TestOp::<F>::CommitFloor(None, Location::<F>::new(50)))
            .await
            .unwrap();
        journal.sync().await.unwrap();

        let count_before = journal.size().await;
        journal.prune(Location::<F>::new(50)).await.unwrap();
        let count_after = journal.size().await;

        assert_eq!(count_before, count_after);
    }

    #[test_traced("INFO")]
    fn test_prune_preserves_operation_count_mmr() {
        let executor = deterministic::Runner::default();
        executor.start(test_prune_preserves_operation_count_inner::<mmr::Family>);
    }

    #[test_traced("INFO")]
    fn test_prune_preserves_operation_count_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(test_prune_preserves_operation_count_inner::<mmb::Family>);
    }

    /// Verify bounds() for empty journal, no pruning, and after pruning.
    async fn test_bounds_empty_and_pruned_inner<F: Family + PartialEq>(context: Context) {
        // Test empty journal
        let journal = create_empty_journal::<F>(context.with_label("empty"), "oldest").await;
        assert!(journal.reader().await.bounds().is_empty());
        journal.destroy().await.unwrap();

        // Test no pruning
        let journal =
            create_journal_with_ops::<F>(context.with_label("no_prune"), "oldest", 100).await;
        let bounds = journal.reader().await.bounds();
        assert!(!bounds.is_empty());
        assert_eq!(bounds.start, 0);
        journal.destroy().await.unwrap();

        // Test after pruning
        let mut journal =
            create_journal_with_ops::<F>(context.with_label("pruned"), "oldest", 100).await;
        journal
            .append(&TestOp::<F>::CommitFloor(None, Location::<F>::new(50)))
            .await
            .unwrap();
        journal.sync().await.unwrap();

        let pruned_boundary = journal.prune(Location::<F>::new(50)).await.unwrap();

        // Should match the pruned boundary (may be <= 50 due to section alignment)
        let bounds = journal.reader().await.bounds();
        assert!(!bounds.is_empty());
        assert_eq!(bounds.start, pruned_boundary);
        // Should be <= requested location (50)
        assert!(pruned_boundary <= 50);
        journal.destroy().await.unwrap();
    }

    #[test_traced("INFO")]
    fn test_bounds_empty_and_pruned_mmr() {
        let executor = deterministic::Runner::default();
        executor.start(test_bounds_empty_and_pruned_inner::<mmr::Family>);
    }

    #[test_traced("INFO")]
    fn test_bounds_empty_and_pruned_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(test_bounds_empty_and_pruned_inner::<mmb::Family>);
    }

    /// Verify bounds().start for empty journal, no pruning, and after pruning.
    async fn test_bounds_start_after_prune_inner<F: Family + PartialEq>(context: Context) {
        // Test empty journal
        let journal = create_empty_journal::<F>(context.with_label("empty"), "boundary").await;
        assert_eq!(journal.reader().await.bounds().start, 0);

        // Test no pruning
        let journal =
            create_journal_with_ops::<F>(context.with_label("no_prune"), "boundary", 100).await;
        assert_eq!(journal.reader().await.bounds().start, 0);

        // Test after pruning
        let mut journal =
            create_journal_with_ops::<F>(context.with_label("pruned"), "boundary", 100).await;
        journal
            .append(&TestOp::<F>::CommitFloor(None, Location::<F>::new(50)))
            .await
            .unwrap();
        journal.sync().await.unwrap();

        let pruned_boundary = journal.prune(Location::<F>::new(50)).await.unwrap();

        assert_eq!(journal.reader().await.bounds().start, pruned_boundary);
    }

    #[test_traced("INFO")]
    fn test_bounds_start_after_prune_mmr() {
        let executor = deterministic::Runner::default();
        executor.start(test_bounds_start_after_prune_inner::<mmr::Family>);
    }

    #[test_traced("INFO")]
    fn test_bounds_start_after_prune_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(test_bounds_start_after_prune_inner::<mmb::Family>);
    }

    /// Verify that Merkle prunes to the journal's actual boundary, not the requested location.
    async fn test_mmr_prunes_to_journal_boundary_inner<F: Family + PartialEq>(context: Context) {
        let mut journal = create_journal_with_ops::<F>(context, "mmr_boundary", 50).await;

        journal
            .append(&TestOp::<F>::CommitFloor(None, Location::<F>::new(25)))
            .await
            .unwrap();
        journal.sync().await.unwrap();

        let pruned_boundary = journal.prune(Location::<F>::new(25)).await.unwrap();

        // Verify Merkle and journal remain in sync
        let bounds = journal.reader().await.bounds();
        assert!(!bounds.is_empty());
        assert_eq!(pruned_boundary, bounds.start);

        // Verify boundary is at or before requested (due to section alignment)
        assert!(pruned_boundary <= Location::<F>::new(25));

        // Verify operation count is unchanged
        assert_eq!(journal.size().await, 51);
    }

    #[test_traced("INFO")]
    fn test_mmr_prunes_to_journal_boundary_mmr() {
        let executor = deterministic::Runner::default();
        executor.start(test_mmr_prunes_to_journal_boundary_inner::<mmr::Family>);
    }

    #[test_traced("INFO")]
    fn test_mmr_prunes_to_journal_boundary_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(test_mmr_prunes_to_journal_boundary_inner::<mmb::Family>);
    }

    /// Verify proof() for multiple operations.
    async fn test_proof_multiple_operations_inner<F: Family + PartialEq>(context: Context) {
        let journal = create_journal_with_ops::<F>(context, "proof_multi", 50).await;

        let (proof, ops) = journal
            .proof(Location::<F>::new(0), NZU64!(50))
            .await
            .unwrap();

        assert_eq!(ops.len(), 50);
        for (i, op) in ops.iter().enumerate() {
            assert_eq!(*op, create_operation::<F>(i as u8));
        }

        // Verify the proof is valid
        let hasher = StandardHasher::new();
        let root = journal.root();
        assert!(verify_proof(
            &proof,
            &ops,
            Location::<F>::new(0),
            &root,
            &hasher
        ));
    }

    #[test_traced("INFO")]
    fn test_proof_multiple_operations_mmr() {
        let executor = deterministic::Runner::default();
        executor.start(test_proof_multiple_operations_inner::<mmr::Family>);
    }

    #[test_traced("INFO")]
    fn test_proof_multiple_operations_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(test_proof_multiple_operations_inner::<mmb::Family>);
    }

    /// Verify that historical_proof() respects the max_ops limit.
    async fn test_historical_proof_limited_by_max_ops_inner<F: Family + PartialEq>(
        context: Context,
    ) {
        let journal = create_journal_with_ops::<F>(context, "proof_limit", 50).await;

        let size = journal.size().await;
        let (proof, ops) = journal
            .historical_proof(size, Location::<F>::new(0), NZU64!(20))
            .await
            .unwrap();

        // Should return only 20 operations despite 50 being available
        assert_eq!(ops.len(), 20);
        for (i, op) in ops.iter().enumerate() {
            assert_eq!(*op, create_operation::<F>(i as u8));
        }

        // Verify the proof is valid
        let hasher = StandardHasher::new();
        let root = journal.root();
        assert!(verify_proof(
            &proof,
            &ops,
            Location::<F>::new(0),
            &root,
            &hasher
        ));
    }

    #[test_traced("INFO")]
    fn test_historical_proof_limited_by_max_ops_mmr() {
        let executor = deterministic::Runner::default();
        executor.start(|context| {
            test_historical_proof_limited_by_max_ops_inner::<mmr::Family>(context)
        });
    }

    #[test_traced("INFO")]
    fn test_historical_proof_limited_by_max_ops_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(|context| {
            test_historical_proof_limited_by_max_ops_inner::<mmb::Family>(context)
        });
    }

    /// Verify historical_proof() at the end of the journal.
    async fn test_historical_proof_at_end_of_journal_inner<F: Family + PartialEq>(
        context: Context,
    ) {
        let journal = create_journal_with_ops::<F>(context, "proof_end", 50).await;

        let size = journal.size().await;
        // Request proof starting near the end
        let (proof, ops) = journal
            .historical_proof(size, Location::<F>::new(40), NZU64!(20))
            .await
            .unwrap();

        // Should return only 10 operations (positions 40-49)
        assert_eq!(ops.len(), 10);
        for (i, op) in ops.iter().enumerate() {
            assert_eq!(*op, create_operation::<F>((40 + i) as u8));
        }

        // Verify the proof is valid
        let hasher = StandardHasher::new();
        let root = journal.root();
        assert!(verify_proof(
            &proof,
            &ops,
            Location::<F>::new(40),
            &root,
            &hasher
        ));
    }

    #[test_traced("INFO")]
    fn test_historical_proof_at_end_of_journal_mmr() {
        let executor = deterministic::Runner::default();
        executor.start(test_historical_proof_at_end_of_journal_inner::<mmr::Family>);
    }

    #[test_traced("INFO")]
    fn test_historical_proof_at_end_of_journal_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(test_historical_proof_at_end_of_journal_inner::<mmb::Family>);
    }

    /// Verify that historical_proof() returns an error for invalid size.
    async fn test_historical_proof_out_of_range_returns_error_inner<F: Family + PartialEq>(
        context: Context,
    ) {
        let journal = create_journal_with_ops::<F>(context, "proof_oob", 5).await;

        // Request proof with size > actual journal size
        let result = journal
            .historical_proof(Location::<F>::new(10), Location::<F>::new(0), NZU64!(1))
            .await;

        assert!(matches!(
            result,
            Err(Error::Merkle(merkle::Error::RangeOutOfBounds(_)))
        ));
    }

    #[test_traced("INFO")]
    fn test_historical_proof_out_of_range_returns_error_mmr() {
        let executor = deterministic::Runner::default();
        executor.start(|context| {
            test_historical_proof_out_of_range_returns_error_inner::<mmr::Family>(context)
        });
    }

    #[test_traced("INFO")]
    fn test_historical_proof_out_of_range_returns_error_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(|context| {
            test_historical_proof_out_of_range_returns_error_inner::<mmb::Family>(context)
        });
    }

    /// Verify that historical_proof() returns an error when start_loc >= size.
    async fn test_historical_proof_start_too_large_returns_error_inner<F: Family + PartialEq>(
        context: Context,
    ) {
        let journal = create_journal_with_ops::<F>(context, "proof_start_oob", 5).await;

        let size = journal.size().await;
        // Request proof starting at size (should fail)
        let result = journal.historical_proof(size, size, NZU64!(1)).await;

        assert!(matches!(
            result,
            Err(Error::Merkle(merkle::Error::RangeOutOfBounds(_)))
        ));
    }

    #[test_traced("INFO")]
    fn test_historical_proof_start_too_large_returns_error_mmr() {
        let executor = deterministic::Runner::default();
        executor.start(|context| {
            test_historical_proof_start_too_large_returns_error_inner::<mmr::Family>(context)
        });
    }

    #[test_traced("INFO")]
    fn test_historical_proof_start_too_large_returns_error_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(|context| {
            test_historical_proof_start_too_large_returns_error_inner::<mmb::Family>(context)
        });
    }

    /// Verify historical_proof() for a truly historical state (before more operations added).
    async fn test_historical_proof_truly_historical_inner<F: Family + PartialEq>(context: Context) {
        // Create journal with initial operations
        let mut journal = create_journal_with_ops::<F>(context, "proof_historical", 50).await;

        // Capture root at historical state
        let hasher = StandardHasher::new();
        let historical_root = journal.root();
        let historical_size = journal.size().await;

        // Add more operations after the historical state
        for i in 50..100 {
            journal
                .append(&create_operation::<F>(i as u8))
                .await
                .unwrap();
        }
        journal.sync().await.unwrap();

        // Generate proof for the historical state
        let (proof, ops) = journal
            .historical_proof(historical_size, Location::<F>::new(0), NZU64!(50))
            .await
            .unwrap();

        // Verify operations match expected historical operations
        assert_eq!(ops.len(), 50);
        for (i, op) in ops.iter().enumerate() {
            assert_eq!(*op, create_operation::<F>(i as u8));
        }

        // Verify the proof is valid against the historical root
        assert!(verify_proof(
            &proof,
            &ops,
            Location::<F>::new(0),
            &historical_root,
            &hasher
        ));
    }

    #[test_traced("INFO")]
    fn test_historical_proof_truly_historical_mmr() {
        let executor = deterministic::Runner::default();
        executor.start(test_historical_proof_truly_historical_inner::<mmr::Family>);
    }

    #[test_traced("INFO")]
    fn test_historical_proof_truly_historical_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(test_historical_proof_truly_historical_inner::<mmb::Family>);
    }

    /// Verify that historical_proof() returns an error when start_loc is pruned.
    async fn test_historical_proof_pruned_location_returns_error_inner<F: Family + PartialEq>(
        context: Context,
    ) {
        let mut journal = create_journal_with_ops::<F>(context, "proof_pruned", 50).await;

        journal
            .append(&TestOp::<F>::CommitFloor(None, Location::<F>::new(25)))
            .await
            .unwrap();
        journal.sync().await.unwrap();
        let pruned_boundary = journal.prune(Location::<F>::new(25)).await.unwrap();

        // Try to get proof starting at a location before the pruned boundary
        let size = journal.size().await;
        let start_loc = Location::<F>::new(0);
        if start_loc < pruned_boundary {
            let result = journal.historical_proof(size, start_loc, NZU64!(1)).await;

            // Should fail when trying to read pruned operations
            assert!(result.is_err());
        }
    }

    #[test_traced("INFO")]
    fn test_historical_proof_pruned_location_returns_error_mmr() {
        let executor = deterministic::Runner::default();
        executor.start(|context| {
            test_historical_proof_pruned_location_returns_error_inner::<mmr::Family>(context)
        });
    }

    #[test_traced("INFO")]
    fn test_historical_proof_pruned_location_returns_error_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(|context| {
            test_historical_proof_pruned_location_returns_error_inner::<mmb::Family>(context)
        });
    }

    /// Verify replay() with empty journal and multiple operations.
    async fn test_replay_operations_inner<F: Family + PartialEq>(context: Context) {
        // Test empty journal
        let journal = create_empty_journal::<F>(context.with_label("empty"), "replay").await;
        let reader = journal.reader().await;
        let stream = reader.replay(NZUsize!(10), 0).await.unwrap();
        futures::pin_mut!(stream);
        assert!(stream.next().await.is_none());

        // Test replaying all operations
        let journal =
            create_journal_with_ops::<F>(context.with_label("with_ops"), "replay", 50).await;
        let reader = journal.reader().await;
        let stream = reader.replay(NZUsize!(100), 0).await.unwrap();
        futures::pin_mut!(stream);

        for i in 0..50 {
            let (pos, op) = stream.next().await.unwrap().unwrap();
            assert_eq!(pos, i);
            assert_eq!(op, create_operation::<F>(i as u8));
        }

        assert!(stream.next().await.is_none());
    }

    #[test_traced("INFO")]
    fn test_replay_operations_mmr() {
        let executor = deterministic::Runner::default();
        executor.start(test_replay_operations_inner::<mmr::Family>);
    }

    #[test_traced("INFO")]
    fn test_replay_operations_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(test_replay_operations_inner::<mmb::Family>);
    }

    /// Verify replay() starting from a middle location.
    async fn test_replay_from_middle_inner<F: Family + PartialEq>(context: Context) {
        let journal = create_journal_with_ops::<F>(context, "replay_middle", 50).await;
        let reader = journal.reader().await;
        let stream = reader.replay(NZUsize!(100), 25).await.unwrap();
        futures::pin_mut!(stream);

        let mut count = 0;
        while let Some(result) = stream.next().await {
            let (pos, op) = result.unwrap();
            assert_eq!(pos, 25 + count);
            assert_eq!(op, create_operation::<F>((25 + count) as u8));
            count += 1;
        }

        // Should have replayed positions 25-49 (25 operations)
        assert_eq!(count, 25);
    }

    #[test_traced("INFO")]
    fn test_replay_from_middle_mmr() {
        let executor = deterministic::Runner::default();
        executor.start(test_replay_from_middle_inner::<mmr::Family>);
    }

    #[test_traced("INFO")]
    fn test_replay_from_middle_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(test_replay_from_middle_inner::<mmb::Family>);
    }

    /// Verify the speculative batch API: fork two batches, verify independent roots, apply one.
    async fn test_speculative_batch_inner<F: Family + PartialEq>(context: Context) {
        let mut journal = create_journal_with_ops::<F>(context, "speculative_batch", 10).await;
        let original_root = journal.root();

        // Fork two independent speculative batches.
        let b1 = journal.new_batch();
        let b2 = journal.new_batch();

        // Add different items to each batch.
        let op_a = create_operation::<F>(100);
        let op_b = create_operation::<F>(200);
        let b1 = b1.add(op_a.clone());
        let b2 = b2.add(op_b);

        // Merkleize and verify independent roots.
        let m1 = journal.merkle.with_mem(|mem| b1.merkleize(mem));
        let m2 = journal.merkle.with_mem(|mem| b2.merkleize(mem));
        assert_ne!(m1.root(), m2.root());
        assert_ne!(m1.root(), original_root);
        assert_ne!(m2.root(), original_root);

        // Journal root should be unchanged (batches are speculative).
        assert_eq!(journal.root(), original_root);

        // Apply batch 1.
        let expected_root = m1.root();
        journal.apply_batch(&m1).await.unwrap();

        // Journal should now match the applied batch's root.
        assert_eq!(journal.root(), expected_root);
        assert_eq!(*journal.size().await, 11);
    }

    #[test_traced("INFO")]
    fn test_speculative_batch_mmr() {
        let executor = deterministic::Runner::default();
        executor.start(test_speculative_batch_inner::<mmr::Family>);
    }

    #[test_traced("INFO")]
    fn test_speculative_batch_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(test_speculative_batch_inner::<mmb::Family>);
    }

    /// Verify stacking: create batch A, merkleize, create batch B from merkleized A,
    /// merkleize, and apply. Verify root and items.
    async fn test_speculative_batch_stacking_inner<F: Family + PartialEq>(context: Context) {
        let mut journal = create_journal_with_ops::<F>(context, "batch_stacking", 10).await;

        let op_a = create_operation::<F>(100);
        let op_b = create_operation::<F>(200);

        let merkleized_b = {
            let batch_a = journal.new_batch().add(op_a.clone());
            let merkleized_a = journal.merkle.with_mem(|mem| batch_a.merkleize(mem));

            let batch_b = merkleized_a.new_batch::<Sha256>().add(op_b.clone());
            journal.merkle.with_mem(|mem| batch_b.merkleize(mem))
        };

        let expected_root = merkleized_b.root();
        journal.apply_batch(&merkleized_b).await.unwrap();

        assert_eq!(journal.root(), expected_root);
        assert_eq!(*journal.size().await, 12);

        // Verify both items were appended correctly.
        let read_a = journal.read(Location::<F>::new(10)).await.unwrap();
        assert_eq!(read_a, op_a);
        let read_b = journal.read(Location::<F>::new(11)).await.unwrap();
        assert_eq!(read_b, op_b);
    }

    #[test_traced("INFO")]
    fn test_speculative_batch_stacking_mmr() {
        let executor = deterministic::Runner::default();
        executor.start(test_speculative_batch_stacking_inner::<mmr::Family>);
    }

    #[test_traced("INFO")]
    fn test_speculative_batch_stacking_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(test_speculative_batch_stacking_inner::<mmb::Family>);
    }

    /// Verify sequential batch application: apply batch A, then build and apply batch B
    /// from the committed state. Verify root and items.
    async fn test_speculative_batch_sequential_inner<F: Family + PartialEq>(context: Context) {
        let mut journal = create_journal_with_ops::<F>(context, "batch_sequential", 10).await;

        let op_a = create_operation::<F>(100);
        let op_b = create_operation::<F>(200);

        // Apply batch A.
        let batch_a = journal.new_batch().add(op_a.clone());
        let merkleized_a = journal.merkle.with_mem(|mem| batch_a.merkleize(mem));
        journal.apply_batch(&merkleized_a).await.unwrap();
        assert_eq!(*journal.size().await, 11);

        // Apply batch B (built on top of the committed A).
        let batch_b = journal.new_batch().add(op_b.clone());
        let merkleized_b = journal.merkle.with_mem(|mem| batch_b.merkleize(mem));
        let expected_root = merkleized_b.root();
        journal.apply_batch(&merkleized_b).await.unwrap();

        assert_eq!(journal.root(), expected_root);
        assert_eq!(*journal.size().await, 12);

        // Verify both items were appended correctly.
        let read_a = journal.read(Location::<F>::new(10)).await.unwrap();
        assert_eq!(read_a, op_a);
        let read_b = journal.read(Location::<F>::new(11)).await.unwrap();
        assert_eq!(read_b, op_b);
    }

    #[test_traced("INFO")]
    fn test_speculative_batch_sequential_mmr() {
        let executor = deterministic::Runner::default();
        executor.start(test_speculative_batch_sequential_inner::<mmr::Family>);
    }

    #[test_traced("INFO")]
    fn test_speculative_batch_sequential_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(test_speculative_batch_sequential_inner::<mmb::Family>);
    }

    async fn test_stale_batch_sibling_inner<F: Family + PartialEq>(context: Context) {
        let mut journal = create_empty_journal::<F>(context, "stale-sibling").await;
        let op_a = create_operation::<F>(1);
        let op_b = create_operation::<F>(2);

        // Create two batches from the same base.
        let batch_a = journal.new_batch().add(op_a.clone());
        let merkleized_a = journal.merkle.with_mem(|mem| batch_a.merkleize(mem));
        let batch_b = journal.new_batch().add(op_b);
        let merkleized_b = journal.merkle.with_mem(|mem| batch_b.merkleize(mem));

        // Apply A -- should succeed.
        journal.apply_batch(&merkleized_a).await.unwrap();
        let expected_root = journal.root();
        let expected_size = journal.size().await;

        // Apply B -- should fail (stale).
        let result = journal.apply_batch(&merkleized_b).await;
        assert!(
            matches!(
                result,
                Err(super::Error::Merkle(merkle::Error::StaleBatch { .. }))
            ),
            "expected StaleBatch, got {result:?}"
        );

        // The stale batch must not mutate the journal or desync it from the Merkle.
        assert_eq!(journal.root(), expected_root);
        assert_eq!(journal.size().await, expected_size);
        let (_, ops) = journal
            .proof(Location::<F>::new(0), NZU64!(1))
            .await
            .unwrap();
        assert_eq!(ops, vec![op_a]);
    }

    #[test_traced("INFO")]
    fn test_stale_batch_sibling_mmr() {
        let executor = deterministic::Runner::default();
        executor.start(test_stale_batch_sibling_inner::<mmr::Family>);
    }

    #[test_traced("INFO")]
    fn test_stale_batch_sibling_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(test_stale_batch_sibling_inner::<mmb::Family>);
    }

    async fn test_stale_batch_chained_inner<F: Family + PartialEq>(context: Context) {
        let mut journal = create_journal_with_ops::<F>(context, "stale-chained", 5).await;

        // Parent batch, then fork two children.
        let parent_batch = journal.new_batch().add(create_operation::<F>(10));
        let parent = journal.merkle.with_mem(|mem| parent_batch.merkleize(mem));
        let batch_a = parent.new_batch::<Sha256>().add(create_operation::<F>(20));
        let child_a = journal.merkle.with_mem(|mem| batch_a.merkleize(mem));
        let batch_b = parent.new_batch::<Sha256>().add(create_operation::<F>(30));
        let child_b = journal.merkle.with_mem(|mem| batch_b.merkleize(mem));
        drop(parent);

        // Apply child_a, then child_b should be stale.
        journal.apply_batch(&child_a).await.unwrap();
        let result = journal.apply_batch(&child_b).await;
        assert!(
            matches!(
                result,
                Err(super::Error::Merkle(merkle::Error::StaleBatch { .. }))
            ),
            "expected StaleBatch for sibling, got {result:?}"
        );
    }

    #[test_traced("INFO")]
    fn test_stale_batch_chained_mmr() {
        let executor = deterministic::Runner::default();
        executor.start(test_stale_batch_chained_inner::<mmr::Family>);
    }

    #[test_traced("INFO")]
    fn test_stale_batch_chained_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(test_stale_batch_chained_inner::<mmb::Family>);
    }

    async fn test_stale_batch_parent_before_child_inner<F: Family + PartialEq>(context: Context) {
        let mut journal = create_empty_journal::<F>(context, "stale-parent-first").await;

        // Create parent, then child.
        let parent_batch = journal.new_batch().add(create_operation::<F>(1));
        let parent = journal.merkle.with_mem(|mem| parent_batch.merkleize(mem));
        let child_batch = parent.new_batch::<Sha256>().add(create_operation::<F>(2));
        let child = journal.merkle.with_mem(|mem| child_batch.merkleize(mem));

        let expected_root = child.root();

        // Apply parent, then child (sequential commit).
        journal.apply_batch(&parent).await.unwrap();
        journal.apply_batch(&child).await.unwrap();

        assert_eq!(journal.root(), expected_root);
        assert_eq!(*journal.size().await, 2);
    }

    #[test_traced("INFO")]
    fn test_stale_batch_parent_before_child_mmr() {
        let executor = deterministic::Runner::default();
        executor.start(test_stale_batch_parent_before_child_inner::<mmr::Family>);
    }

    #[test_traced("INFO")]
    fn test_stale_batch_parent_before_child_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(test_stale_batch_parent_before_child_inner::<mmb::Family>);
    }

    async fn test_stale_batch_child_before_parent_inner<F: Family + PartialEq>(context: Context) {
        let mut journal = create_empty_journal::<F>(context, "stale-child-first").await;

        // Create parent, then child.
        let parent_batch = journal.new_batch().add(create_operation::<F>(1));
        let parent = journal.merkle.with_mem(|mem| parent_batch.merkleize(mem));
        let child_batch = parent.new_batch::<Sha256>().add(create_operation::<F>(2));
        let child = journal.merkle.with_mem(|mem| child_batch.merkleize(mem));

        // Apply child first (full chain) -- parent should now be stale.
        journal.apply_batch(&child).await.unwrap();
        let result = journal.apply_batch(&parent).await;
        assert!(
            matches!(
                result,
                Err(super::Error::Merkle(merkle::Error::StaleBatch { .. }))
            ),
            "expected StaleBatch for parent after child applied, got {result:?}"
        );
    }

    #[test_traced("INFO")]
    fn test_stale_batch_child_before_parent_mmr() {
        let executor = deterministic::Runner::default();
        executor.start(test_stale_batch_child_before_parent_inner::<mmr::Family>);
    }

    #[test_traced("INFO")]
    fn test_stale_batch_child_before_parent_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(test_stale_batch_child_before_parent_inner::<mmb::Family>);
    }

    /// Apply parent then child: child skips already-committed ancestor items.
    async fn test_apply_batch_skip_ancestor_items_inner<F: Family + PartialEq>(context: Context) {
        let mut journal = create_journal_with_ops::<F>(context, "rp-skip", 3).await;

        // Parent: 2 items.
        let parent_batch = journal
            .new_batch()
            .add(create_operation::<F>(10))
            .add(create_operation::<F>(11));
        let parent = journal.merkle.with_mem(|mem| parent_batch.merkleize(mem));

        // Child: 3 more items.
        let child_batch = parent
            .new_batch::<Sha256>()
            .add(create_operation::<F>(20))
            .add(create_operation::<F>(21))
            .add(create_operation::<F>(22));
        let child = journal.merkle.with_mem(|mem| child_batch.merkleize(mem));

        // Apply parent.
        journal.apply_batch(&parent).await.unwrap();

        // Apply child (ancestor items already committed, skipped automatically).
        journal.apply_batch(&child).await.unwrap();

        // Verify all items are present.
        let (_, ops) = journal
            .proof(Location::<F>::new(3), NZU64!(5))
            .await
            .unwrap();
        assert_eq!(ops.len(), 5);
    }

    #[test_traced("INFO")]
    fn test_apply_batch_skip_ancestor_items_mmr() {
        let executor = deterministic::Runner::default();
        executor.start(test_apply_batch_skip_ancestor_items_inner::<mmr::Family>);
    }

    #[test_traced("INFO")]
    fn test_apply_batch_skip_ancestor_items_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(test_apply_batch_skip_ancestor_items_inner::<mmb::Family>);
    }

    /// `apply_batch` works correctly across a 3-level chain.
    async fn test_apply_batch_cross_segment_inner<F: Family + PartialEq>(context: Context) {
        let mut journal = create_journal_with_ops::<F>(context, "rp-cross", 2).await;

        // Grandparent: 3 items.
        let grandparent_batch = journal
            .new_batch()
            .add(create_operation::<F>(3))
            .add(create_operation::<F>(4))
            .add(create_operation::<F>(5));
        let grandparent = journal
            .merkle
            .with_mem(|mem| grandparent_batch.merkleize(mem));

        // Parent: 2 items.
        let parent_batch = grandparent
            .new_batch::<Sha256>()
            .add(create_operation::<F>(6))
            .add(create_operation::<F>(7));
        let parent = journal.merkle.with_mem(|mem| parent_batch.merkleize(mem));

        // Child: 1 item.
        let child_batch = parent.new_batch::<Sha256>().add(create_operation::<F>(8));
        let child = journal.merkle.with_mem(|mem| child_batch.merkleize(mem));

        // Apply grandparent, then parent, then child sequentially.
        journal.apply_batch(&grandparent).await.unwrap();

        // Apply parent (ancestor items already committed, skipped automatically).
        journal.apply_batch(&parent).await.unwrap();

        // Apply child (ancestor items already committed, skipped automatically).
        journal.apply_batch(&child).await.unwrap();

        // All 8 items (2 base + 3 + 2 + 1) should be present.
        assert_eq!(*journal.size().await, 8);

        // Verify the actual items at each location.
        let (_, ops) = journal
            .proof(Location::<F>::new(2), NZU64!(6))
            .await
            .unwrap();
        for (i, op) in ops.iter().enumerate() {
            assert_eq!(*op, create_operation::<F>((i + 3) as u8));
        }
    }

    #[test_traced("INFO")]
    fn test_apply_batch_cross_segment_mmr() {
        let executor = deterministic::Runner::default();
        executor.start(test_apply_batch_cross_segment_inner::<mmr::Family>);
    }

    #[test_traced("INFO")]
    fn test_apply_batch_cross_segment_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(test_apply_batch_cross_segment_inner::<mmb::Family>);
    }

    /// merkleize_with produces the same root as add + merkleize.
    async fn test_merkleize_with_matches_add_inner<F: Family + PartialEq>(context: Context) {
        let journal = create_journal_with_ops::<F>(context, "mw-matches", 5).await;

        let ops = vec![
            create_operation::<F>(10),
            create_operation::<F>(11),
            create_operation::<F>(12),
        ];

        // add + merkleize
        let mut batch = journal.new_batch();
        for op in &ops {
            batch = batch.add(op.clone());
        }
        let expected = journal.merkle.with_mem(|mem| batch.merkleize(mem));

        // merkleize_with
        let batch = journal.new_batch();
        let actual = journal
            .merkle
            .with_mem(|mem| batch.merkleize_with(mem, Arc::new(ops)));

        assert_eq!(actual.root(), expected.root());
    }

    #[test_traced("INFO")]
    fn test_merkleize_with_matches_add_mmr() {
        let executor = deterministic::Runner::default();
        executor.start(test_merkleize_with_matches_add_inner::<mmr::Family>);
    }

    #[test_traced("INFO")]
    fn test_merkleize_with_matches_add_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(test_merkleize_with_matches_add_inner::<mmb::Family>);
    }

    /// merkleize_with items are readable after apply.
    async fn test_merkleize_with_apply_inner<F: Family + PartialEq>(context: Context) {
        let mut journal = create_journal_with_ops::<F>(context, "mw-apply", 5).await;

        let ops = vec![create_operation::<F>(10), create_operation::<F>(11)];
        let batch = journal.new_batch();
        let merkleized = journal
            .merkle
            .with_mem(|mem| batch.merkleize_with(mem, Arc::new(ops.clone())));

        let expected_root = merkleized.root();
        journal.apply_batch(&merkleized).await.unwrap();

        assert_eq!(journal.root(), expected_root);
        assert_eq!(*journal.size().await, 7);

        let reader = journal.reader().await;
        assert_eq!(reader.read(5).await.unwrap(), ops[0]);
        assert_eq!(reader.read(6).await.unwrap(), ops[1]);
    }

    #[test_traced("INFO")]
    fn test_merkleize_with_apply_mmr() {
        let executor = deterministic::Runner::default();
        executor.start(test_merkleize_with_apply_inner::<mmr::Family>);
    }

    #[test_traced("INFO")]
    fn test_merkleize_with_apply_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(test_merkleize_with_apply_inner::<mmb::Family>);
    }

    /// merkleize_with shares the Arc: the caller's clone and the batch's
    /// internal segment point to the same allocation.
    async fn test_merkleize_with_shares_arc_inner<F: Family + PartialEq>(context: Context) {
        let journal = create_journal_with_ops::<F>(context, "mw-arc", 3).await;

        let ops = Arc::new(vec![create_operation::<F>(20), create_operation::<F>(21)]);
        let ops_clone = Arc::clone(&ops);
        let batch = journal.new_batch();
        let merkleized = journal
            .merkle
            .with_mem(|mem| batch.merkleize_with(mem, ops_clone));

        // The batch should hold the same Arc allocation, not a copy.
        assert!(Arc::ptr_eq(&merkleized.items, &ops));
    }

    #[test_traced("INFO")]
    fn test_merkleize_with_shares_arc_mmr() {
        let executor = deterministic::Runner::default();
        executor.start(test_merkleize_with_shares_arc_inner::<mmr::Family>);
    }

    #[test_traced("INFO")]
    fn test_merkleize_with_shares_arc_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(test_merkleize_with_shares_arc_inner::<mmb::Family>);
    }

    /// Apply C (grandchild of A) after only A is committed. B's journal items
    /// must still be applied -- skip only A's items.
    async fn test_apply_batch_skips_only_committed_ancestor_items_inner<F: Family + PartialEq>(
        context: Context,
    ) {
        let mut journal = create_empty_journal::<F>(context.clone(), "skip-partial").await;

        // Build chain: A -> B -> C
        let a_batch = journal.new_batch().add(create_operation::<F>(1));
        let a = journal.merkle.with_mem(|mem| a_batch.merkleize(mem));
        let b_batch = a.new_batch::<Sha256>().add(create_operation::<F>(2));
        let b = journal.merkle.with_mem(|mem| b_batch.merkleize(mem));
        let c_batch = b.new_batch::<Sha256>().add(create_operation::<F>(3));
        let c = journal.merkle.with_mem(|mem| c_batch.merkleize(mem));

        // Apply A, then apply C directly (skipping B's apply_batch).
        journal.apply_batch(&a).await.unwrap();
        journal.apply_batch(&c).await.unwrap();

        // All 3 items should be in the journal.
        assert_eq!(*journal.size().await, 3);

        // Build a reference that applies all three sequentially.
        let mut reference =
            create_empty_journal::<F>(context.with_label("ref"), "skip-partial-ref").await;
        for i in 1..=3u8 {
            reference.append(&create_operation::<F>(i)).await.unwrap();
        }
        assert_eq!(journal.root(), reference.root());
    }

    #[test_traced("INFO")]
    fn test_apply_batch_skips_only_committed_ancestor_items_mmr() {
        let executor = deterministic::Runner::default();
        executor.start(test_apply_batch_skips_only_committed_ancestor_items_inner::<mmr::Family>);
    }

    #[test_traced("INFO")]
    fn test_apply_batch_skips_only_committed_ancestor_items_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(test_apply_batch_skips_only_committed_ancestor_items_inner::<mmb::Family>);
    }
}
